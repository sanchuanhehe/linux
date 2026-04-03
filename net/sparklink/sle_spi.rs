// SPDX-License-Identifier: GPL-2.0

//! SparkLink SPI transport for SLE DLI controllers.
//!
//! Implements DLI packet framing over SPI following T/XS 10003-2025
//! SPI transport binding. The SPI transport uses a register-based
//! command/response model suitable for embedded SLE radio chips that
//! expose a 4-wire SPI slave interface.
//!
//! SPI transport protocol:
//!
//! The host drives the SPI clock (SCLK). Communication is
//! half-duplex, initiated by the host. The controller asserts a
//! dedicated IRQ line (active low) when it has data for the host.
//!
//! Command transfer (Host -> Controller):
//!   Phase 1 (Write): Host writes a command header register.
//!     [0]     Register address = 0x01 (CMD_REG)
//!     [1]     Packet type (DliPacketType)
//!     [2..3]  Opcode (little-endian)
//!     [4]     Parameter length
//!   Phase 2 (Write): Host writes parameter data to the data FIFO.
//!     [0]     Register address = 0x02 (DATA_REG)
//!     [1..N]  Parameter bytes
//!
//! Event read (Controller -> Host, triggered by IRQ):
//!   Phase 1 (Read): Host reads the status register.
//!     [0]     Register address = 0x00 (STATUS_REG) + read flag
//!     Response: [0] = available bytes in RX FIFO
//!   Phase 2 (Read): Host reads the RX FIFO.
//!     [0]     Register address = 0x03 (RX_REG) + read flag
//!     Response: [0] = packet type, [1..N] = frame bytes
//!
//! Data transfer uses the same DATA_REG / RX_REG registers.
//!
//! SPI configuration:
//!   Mode:       CPOL=0, CPHA=0 (SPI mode 0)
//!   Bit order:  MSB first
//!   Word size:  8 bits
//!   Max clock:  20 MHz (typical: 8 MHz)

#![allow(dead_code, unreachable_pub)]

use core::cell::Cell;
use core::cell::RefCell;
use kernel::alloc::KVec;
use kernel::prelude::*;

use super::sle_dli::{
    DliPacketType, SleBus, SleController, SleControllerInfo, SleEvent, SleFeature, SleOpcode,
    SleStatus, SLE_MEAS_RSSI, SLE_SEC_AES_CCM, SLE_TRANSPORT_UNRELIABLE,
};

// =========================================================================
// SPI register map
// =========================================================================

/// Status register address (read).
pub const REG_STATUS: u8 = 0x00;

/// Command header register address (write).
pub const REG_CMD: u8 = 0x01;

/// Data FIFO register address (write).
pub const REG_DATA_TX: u8 = 0x02;

/// RX FIFO register address (read).
pub const REG_DATA_RX: u8 = 0x03;

/// Configuration register address (read/write).
pub const REG_CONFIG: u8 = 0x04;

/// Interrupt status register address (read, clears on read).
pub const REG_INT_STATUS: u8 = 0x05;

/// Read flag: ORed with register address for read operations.
pub const SPI_READ_FLAG: u8 = 0x80;

// =========================================================================
// SPI transport constants
// =========================================================================

/// Default SPI clock frequency in Hz.
pub const DEFAULT_SPI_FREQ: u32 = 8_000_000;

/// Maximum SPI clock frequency in Hz.
pub const MAX_SPI_FREQ: u32 = 20_000_000;

/// Maximum single SPI transfer size (register address + data).
pub const MAX_SPI_TRANSFER: usize = 260;

/// Command header size on SPI: type(1) + opcode(2) + len(1) = 4.
const SPI_CMD_HEADER_SIZE: usize = 4;

// =========================================================================
// Interrupt status bits
// =========================================================================

/// RX data available in the receive FIFO.
pub const INT_RX_READY: u8 = 0x01;

/// TX FIFO has space for new data.
pub const INT_TX_READY: u8 = 0x02;

/// Command complete status available.
pub const INT_CMD_COMPLETE: u8 = 0x04;

/// Controller error condition.
pub const INT_ERROR: u8 = 0x80;

// =========================================================================
// SPI message builder
// =========================================================================

/// Build a SPI write transfer for a command header.
///
/// Returns number of bytes written to `buf`.
pub fn encode_spi_command(opcode: u16, param_len: u8, buf: &mut [u8]) -> usize {
    if buf.len() < 5 {
        return 0;
    }
    buf[0] = REG_CMD;
    buf[1] = DliPacketType::Command as u8;
    let op_bytes = opcode.to_le_bytes();
    buf[2] = op_bytes[0];
    buf[3] = op_bytes[1];
    buf[4] = param_len;
    5
}

/// Build a SPI write transfer for data payload.
///
/// Prepends the DATA_TX register address.
/// Returns number of bytes written to `buf`.
pub fn encode_spi_data_write(data: &[u8], buf: &mut [u8]) -> usize {
    let total = 1 + data.len();
    if buf.len() < total || data.len() > 255 {
        return 0;
    }
    buf[0] = REG_DATA_TX;
    buf[1..total].copy_from_slice(data);
    total
}

/// Build a SPI read transfer request for the status register.
///
/// Returns the 2-byte transfer: [register | READ_FLAG, 0x00(dummy)].
pub fn encode_spi_status_read(buf: &mut [u8]) -> usize {
    if buf.len() < 2 {
        return 0;
    }
    buf[0] = REG_STATUS | SPI_READ_FLAG;
    buf[1] = 0x00; // dummy byte, controller responds here
    2
}

/// Build a SPI read transfer request for the RX FIFO.
///
/// `len` is the number of bytes to read (from status register).
/// Returns the total transfer size.
pub fn encode_spi_rx_read(len: usize, buf: &mut [u8]) -> usize {
    let total = 1 + len;
    if buf.len() < total {
        return 0;
    }
    buf[0] = REG_DATA_RX | SPI_READ_FLAG;
    // Remaining bytes are dummy (controller fills them)
    for b in &mut buf[1..total] {
        *b = 0x00;
    }
    total
}

// =========================================================================
// SPI RX frame parser
// =========================================================================

/// Parse a received SPI RX FIFO buffer into a frame.
///
/// The buffer starts with the packet type byte followed by the
/// type-specific header and payload (same encoding as UART).
pub fn parse_spi_rx_frame(data: &[u8]) -> Option<SpiFrame> {
    if data.is_empty() {
        return None;
    }
    let pkt_type = match data[0] {
        0xA2 => DliPacketType::Event,
        0xA3 => DliPacketType::AsyncUnicast,
        0xA4 => DliPacketType::SyncUnicast,
        0xA5 => DliPacketType::AsyncMulticast,
        _ => return None,
    };

    match pkt_type {
        DliPacketType::Event => {
            if data.len() < 5 {
                return None;
            }
            let event_code = u16::from_le_bytes([data[1], data[2]]);
            let param_len = u16::from_le_bytes([data[3], data[4]]) as usize;
            if data.len() < 5 + param_len {
                return None;
            }
            let mut params = KVec::new();
            for &b in &data[5..5 + param_len] {
                let _ = params.push(b, GFP_KERNEL);
            }
            Some(SpiFrame::Event { event_code, params })
        }
        _ => {
            // Data frame
            if data.len() < 5 {
                return None;
            }
            let raw_handle = u16::from_le_bytes([data[1], data[2]]);
            let handle = raw_handle & 0x0FFF;
            let flags = (raw_handle >> 12) as u8;
            let data_len = u16::from_le_bytes([data[3], data[4]]) as usize;
            if data.len() < 5 + data_len {
                return None;
            }
            let mut payload = KVec::new();
            for &b in &data[5..5 + data_len] {
                let _ = payload.push(b, GFP_KERNEL);
            }
            Some(SpiFrame::Data {
                pkt_type,
                handle,
                flags,
                payload,
            })
        }
    }
}

/// Parsed frame from the SPI RX FIFO.
pub enum SpiFrame {
    /// Event frame from the controller.
    Event { event_code: u16, params: KVec<u8> },
    /// Data frame from the controller.
    Data {
        pkt_type: DliPacketType,
        handle: u16,
        flags: u8,
        payload: KVec<u8>,
    },
}

// =========================================================================
// SPI controller (DLI over SPI)
// =========================================================================

/// SPI transport configuration.
#[derive(Copy, Clone, Debug)]
pub struct SpiConfig {
    /// SPI clock frequency in Hz.
    pub freq_hz: u32,
    /// SPI mode (0-3). Default: mode 0 (CPOL=0, CPHA=0).
    pub mode: u8,
    /// Chip select pin is active low.
    pub cs_active_low: bool,
}

impl Default for SpiConfig {
    fn default() -> Self {
        Self {
            freq_hz: DEFAULT_SPI_FREQ,
            mode: 0,
            cs_active_low: true,
        }
    }
}

/// SPI-based SLE controller.
///
/// In a real driver, this would hold a reference to a `spi_device`
/// from the kernel SPI subsystem. For now, provides the DLI-over-SPI
/// protocol framing logic.
pub struct SpiController {
    addr: [u8; 6],
    config: SpiConfig,
    opened: Cell<bool>,
    pending_events: RefCell<[Option<SleEvent>; super::sle_dli::CTRL_EVENT_RING_SIZE]>,
    event_head: Cell<usize>,
    event_tail: Cell<usize>,
}

// SAFETY: SpiController is stored inside Mutex<ControllerBackend> in
// SparkLinkCtl.  Mutex provides exclusive access, making Cell/RefCell sound.
unsafe impl Send for SpiController {}
// SAFETY: SpiController is stored inside Mutex<ControllerBackend> in
// SparkLinkCtl.  Mutex provides exclusive access, making Cell/RefCell sound.
unsafe impl Sync for SpiController {}

impl SpiController {
    /// Create a new SPI controller.
    pub fn new(addr: [u8; 6], config: SpiConfig) -> Self {
        Self {
            addr,
            config,
            opened: Cell::new(false),
            pending_events: RefCell::new([const { None }; super::sle_dli::CTRL_EVENT_RING_SIZE]),
            event_head: Cell::new(0),
            event_tail: Cell::new(0),
        }
    }

    fn enqueue_event(&self, ev: SleEvent) {
        let tail = self.event_tail.get();
        let next = (tail + 1) % super::sle_dli::CTRL_EVENT_RING_SIZE;
        if next == self.event_head.get() {
            pr_warn!("sparklink-spi: controller event ring full, dropping event\n");
            return;
        }
        self.pending_events.borrow_mut()[tail] = Some(ev);
        self.event_tail.set(next);
    }

    /// Get the current SPI configuration.
    pub fn config(&self) -> &SpiConfig {
        &self.config
    }

    /// Set the SPI clock frequency.
    pub fn set_freq(&mut self, freq_hz: u32) -> Result {
        if freq_hz == 0 || freq_hz > MAX_SPI_FREQ {
            return Err(EINVAL);
        }
        self.config.freq_hz = freq_hz;
        Ok(())
    }

    /// Prepare a command for SPI transmission.
    ///
    /// Returns two transfer buffers: header and optional data.
    /// Caller performs the actual SPI transfers.
    pub fn prepare_command(
        &self,
        opcode: u16,
        params: &[u8],
        hdr_buf: &mut [u8],
        data_buf: &mut [u8],
    ) -> (usize, usize) {
        let hdr_len = encode_spi_command(opcode, params.len() as u8, hdr_buf);
        let data_len = if params.is_empty() {
            0
        } else {
            encode_spi_data_write(params, data_buf)
        };
        (hdr_len, data_len)
    }

    /// Prepare a data frame for SPI transmission.
    pub fn prepare_data(
        &self,
        handle: u16,
        payload: &[u8],
        hdr_buf: &mut [u8],
        data_buf: &mut [u8],
    ) -> (usize, usize) {
        // Header: reg(1) + type(1) + handle(2) + len(2) = 6 bytes
        if hdr_buf.len() < 6 {
            return (0, 0);
        }
        hdr_buf[0] = REG_CMD;
        hdr_buf[1] = DliPacketType::AsyncUnicast as u8;
        let hb = (handle & 0x0FFF).to_le_bytes();
        hdr_buf[2] = hb[0];
        hdr_buf[3] = hb[1];
        let lb = (payload.len() as u16).to_le_bytes();
        hdr_buf[4] = lb[0];
        hdr_buf[5] = lb[1];

        let data_len = encode_spi_data_write(payload, data_buf);
        (6, data_len)
    }
}

impl SleController for SpiController {
    fn info(&self) -> SleControllerInfo {
        let mut info = SleControllerInfo::default();
        let name = b"sparklink-spi";
        info.name[..name.len()].copy_from_slice(name);
        info.bus = SleBus::Spi;
        info.addr = self.addr;
        info.fw_version = 0x0001_0000;
        info.features = (SleFeature::Encryption as u64)
            | (SleFeature::Mcs4 as u64)
            | (SleFeature::Pilot8to1 as u64)
            | (SleFeature::Crc32 as u64);
        info.max_pdu_payload = 255;
        info.max_connections = 2;
        info.max_mtu = 247;
        info.max_mps = 247;
        info.transport_modes = SLE_TRANSPORT_UNRELIABLE;
        info.measurement_cap = SLE_MEAS_RSSI;
        info.security_cap = SLE_SEC_AES_CCM;
        info
    }

    fn open(&self) -> Result {
        if self.opened.get() {
            return Err(EBUSY);
        }
        self.opened.set(true);
        pr_info!(
            "sparklink-spi: open freq={}Hz mode={}\n",
            self.config.freq_hz,
            self.config.mode
        );
        Ok(())
    }

    fn close(&self) {
        self.opened.set(false);
        pr_info!("sparklink-spi: close\n");
    }

    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result {
        let mut hdr_buf = [0u8; 8];
        let mut data_buf = [0u8; 260];
        let (hdr_len, data_len) =
            self.prepare_command(opcode as u16, params, &mut hdr_buf, &mut data_buf);
        if hdr_len == 0 {
            return Err(EINVAL);
        }
        pr_debug!(
            "sparklink-spi: cmd 0x{:04x} hdr={} data={}\n",
            opcode as u16,
            hdr_len,
            data_len
        );
        self.enqueue_event(SleEvent::CommandComplete {
            opcode,
            status: SleStatus::Success,
            data: KVec::new(),
        });
        Ok(())
    }

    fn send_data(&self, handle: u16, data: &[u8]) -> Result {
        let mut hdr_buf = [0u8; 8];
        let mut data_buf = [0u8; 260];
        let (hdr_len, data_len) = self.prepare_data(handle, data, &mut hdr_buf, &mut data_buf);
        if hdr_len == 0 {
            return Err(EINVAL);
        }
        pr_debug!(
            "sparklink-spi: data handle={} hdr={} payload={}\n",
            handle,
            hdr_len,
            data_len
        );
        Ok(())
    }

    fn poll_event(&self) -> Option<SleEvent> {
        let head = self.event_head.get();
        if head == self.event_tail.get() {
            return None;
        }
        let ev = self.pending_events.borrow_mut()[head].take();
        self.event_head
            .set((head + 1) % super::sle_dli::CTRL_EVENT_RING_SIZE);
        ev
    }

    fn reset(&self) -> Result {
        pr_info!("sparklink-spi: reset\n");
        Ok(())
    }
}
