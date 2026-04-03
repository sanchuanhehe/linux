// SPDX-License-Identifier: GPL-2.0

//! SparkLink UART transport for SLE DLI controllers.
//!
//! Implements DLI packet framing over UART following T/XS 10003-2025
//! UART transport binding. The framing is similar to the Bluetooth HCI
//! H4 protocol: a one-byte packet type indicator followed by a
//! type-specific header and payload.
//!
//! UART transport frame format:
//!   [0]     Packet type indicator (DliPacketType)
//!   [1..N]  Type-specific header (opcode/handle + length)
//!   [N..]   Payload data
//!
//! Command frame (Host -> Controller):
//!   [0]     0xA1 (Command)
//!   [1..2]  Opcode (little-endian)
//!   [3]     Parameter length
//!   [4..]   Parameters
//!
//! Event frame (Controller -> Host):
//!   [0]     0xA2 (Event)
//!   [1..2]  Event code (little-endian)
//!   [3]     Parameter length
//!   [4..]   Parameters
//!
//! Data frame (bidirectional):
//!   [0]     0xA3/0xA4/0xA5 (Async/Sync/Multicast)
//!   [1..2]  Handle (little-endian, lower 12 bits) + flags (upper 4 bits)
//!   [3..4]  Data length (little-endian)
//!   [5..]   Payload
//!
//! Default UART configuration:
//!   Baud rate: 115200 (configurable up to 3000000)
//!   Data bits: 8
//!   Stop bits: 1
//!   Parity:    None
//!   Flow ctrl: Hardware (RTS/CTS) recommended

#![allow(dead_code, unreachable_pub)]

use core::cell::Cell;
use core::cell::RefCell;
use kernel::alloc::KVec;
use kernel::prelude::*;

use super::sle_dli::{
    DliPacketType, SleBus, SleController, SleControllerInfo, SleEvent, SleFeature, SleOpcode,
    SleStatus, SLE_MEAS_RSSI, SLE_SEC_AES_CCM, SLE_SEC_ECDH_P256, SLE_TRANSPORT_RELIABLE,
    SLE_TRANSPORT_UNRELIABLE,
};

// =========================================================================
// UART transport constants
// =========================================================================

/// Default baud rate for SLE UART transport.
pub const DEFAULT_BAUD_RATE: u32 = 115200;

/// Maximum supported baud rate.
pub const MAX_BAUD_RATE: u32 = 3_000_000;

/// Command frame header size: type(1) + opcode(2) + len(1) = 4.
pub const CMD_HEADER_SIZE: usize = 4;

/// Event frame header size: type(1) + event_code(2) + len(2) = 5.
pub const EVENT_HEADER_SIZE: usize = 5;

/// Data frame header size: type(1) + handle(2) + len(2) = 5.
pub const DATA_HEADER_SIZE: usize = 5;

/// Maximum parameter/payload length in a single UART frame.
pub const MAX_PAYLOAD_LEN: usize = 255;

/// Size of the UART receive ring buffer.
const RX_BUF_SIZE: usize = 4096;

/// Size of the UART transmit buffer.
const TX_BUF_SIZE: usize = 512;

// =========================================================================
// UART receiver state machine
// =========================================================================

/// Parser states for the DLI UART byte stream.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
enum RxState {
    /// Waiting for a packet type indicator byte.
    #[default]
    WaitType,
    /// Reading the type-specific header bytes.
    ReadHeader {
        pkt_type: DliPacketType,
        /// Number of header bytes collected so far.
        count: usize,
        /// Total header bytes expected (not including the type byte).
        expected: usize,
    },
    /// Reading the payload/parameter bytes.
    ReadPayload {
        pkt_type: DliPacketType,
        /// Number of payload bytes collected so far.
        count: usize,
        /// Total payload bytes expected.
        expected: usize,
    },
}

/// Parsed DLI frame from the UART stream.
pub enum UartFrame {
    /// Command frame (host to controller, but also used for parsing).
    Command { opcode: u16, params: KVec<u8> },
    /// Event frame from the controller.
    Event { event_code: u16, params: KVec<u8> },
    /// Data frame (async unicast, sync unicast, or multicast).
    Data {
        pkt_type: DliPacketType,
        handle: u16,
        flags: u8,
        payload: KVec<u8>,
    },
}

/// UART frame parser.
///
/// Feeds bytes from the UART receiver one at a time (or in chunks)
/// and produces complete frames when enough data is accumulated.
pub struct UartParser {
    state: RxState,
    /// Partial header accumulator (max 4 bytes).
    header: [u8; 4],
    /// Payload accumulator.
    payload: KVec<u8>,
}

impl UartParser {
    /// Create a new parser in the idle state.
    pub fn new() -> Self {
        Self {
            state: RxState::WaitType,
            header: [0u8; 4],
            payload: KVec::new(),
        }
    }

    /// Reset the parser to the initial state.
    pub fn reset(&mut self) {
        self.state = RxState::WaitType;
        self.payload.clear();
    }

    /// Feed a single byte into the parser.
    ///
    /// Returns `Some(UartFrame)` when a complete frame is assembled.
    /// Returns `None` if more bytes are needed.
    /// On protocol errors, the parser resets and returns `None`.
    pub fn feed(&mut self, byte: u8) -> Option<UartFrame> {
        match self.state {
            RxState::WaitType => {
                let pkt_type = match byte {
                    0xA1 => DliPacketType::Command,
                    0xA2 => DliPacketType::Event,
                    0xA3 => DliPacketType::AsyncUnicast,
                    0xA4 => DliPacketType::SyncUnicast,
                    0xA5 => DliPacketType::AsyncMulticast,
                    _ => return None, // skip unknown bytes
                };
                // Header size depends on type
                let hdr_size = match pkt_type {
                    DliPacketType::Command => 3,
                    _ => 4, // Event: event_code(2)+len(2); Data: handle(2)+len(2)
                };
                self.state = RxState::ReadHeader {
                    pkt_type,
                    count: 0,
                    expected: hdr_size,
                };
                None
            }
            RxState::ReadHeader {
                pkt_type,
                count,
                expected,
            } => {
                self.header[count] = byte;
                let new_count = count + 1;
                if new_count < expected {
                    self.state = RxState::ReadHeader {
                        pkt_type,
                        count: new_count,
                        expected,
                    };
                    return None;
                }
                // Header complete, determine payload length
                let payload_len = match pkt_type {
                    DliPacketType::Command => self.header[2] as usize,
                    _ => u16::from_le_bytes([self.header[2], self.header[3]]) as usize,
                };
                if payload_len == 0 {
                    let frame = self.build_frame(pkt_type);
                    self.reset();
                    return frame;
                }
                if payload_len > MAX_PAYLOAD_LEN {
                    // Protocol error: payload too large
                    self.reset();
                    return None;
                }
                self.payload.clear();
                self.state = RxState::ReadPayload {
                    pkt_type,
                    count: 0,
                    expected: payload_len,
                };
                None
            }
            RxState::ReadPayload {
                pkt_type,
                count,
                expected,
            } => {
                if self.payload.push(byte, GFP_KERNEL).is_err() {
                    // OOM: discard partial frame
                    self.reset();
                    return None;
                }
                let new_count = count + 1;
                if new_count < expected {
                    self.state = RxState::ReadPayload {
                        pkt_type,
                        count: new_count,
                        expected,
                    };
                    return None;
                }
                // Payload complete
                let frame = self.build_frame(pkt_type);
                self.reset();
                frame
            }
        }
    }

    /// Feed a byte slice and collect all completed frames.
    pub fn feed_bytes(&mut self, data: &[u8], out: &mut KVec<UartFrame>) {
        for &b in data {
            if let Some(frame) = self.feed(b) {
                let _ = out.push(frame, GFP_KERNEL);
            }
        }
    }

    /// Build a frame from the accumulated header and payload.
    fn build_frame(&mut self, pkt_type: DliPacketType) -> Option<UartFrame> {
        match pkt_type {
            DliPacketType::Command => {
                let opcode = u16::from_le_bytes([self.header[0], self.header[1]]);
                let mut params = KVec::new();
                core::mem::swap(&mut params, &mut self.payload);
                Some(UartFrame::Command { opcode, params })
            }
            DliPacketType::Event => {
                let event_code = u16::from_le_bytes([self.header[0], self.header[1]]);
                let mut params = KVec::new();
                core::mem::swap(&mut params, &mut self.payload);
                Some(UartFrame::Event { event_code, params })
            }
            _ => {
                let raw_handle = u16::from_le_bytes([self.header[0], self.header[1]]);
                let handle = raw_handle & 0x0FFF;
                let flags = (raw_handle >> 12) as u8;
                let mut payload = KVec::new();
                core::mem::swap(&mut payload, &mut self.payload);
                Some(UartFrame::Data {
                    pkt_type,
                    handle,
                    flags,
                    payload,
                })
            }
        }
    }
}

// =========================================================================
// UART frame encoder
// =========================================================================

/// Encode a DLI command into a UART frame.
///
/// Returns the number of bytes written to `buf`.
/// Returns 0 if `buf` is too small.
pub fn encode_command(opcode: u16, params: &[u8], buf: &mut [u8]) -> usize {
    let total = CMD_HEADER_SIZE + params.len();
    if buf.len() < total || params.len() > MAX_PAYLOAD_LEN {
        return 0;
    }
    buf[0] = DliPacketType::Command as u8;
    let op_bytes = opcode.to_le_bytes();
    buf[1] = op_bytes[0];
    buf[2] = op_bytes[1];
    buf[3] = params.len() as u8;
    buf[4..total].copy_from_slice(params);
    total
}

/// Encode a DLI event into a UART frame.
pub fn encode_event(event_code: u16, params: &[u8], buf: &mut [u8]) -> usize {
    let total = EVENT_HEADER_SIZE + params.len();
    if buf.len() < total || params.len() > MAX_PAYLOAD_LEN {
        return 0;
    }
    buf[0] = DliPacketType::Event as u8;
    let ec_bytes = event_code.to_le_bytes();
    buf[1] = ec_bytes[0];
    buf[2] = ec_bytes[1];
    let plen_bytes = (params.len() as u16).to_le_bytes();
    buf[3] = plen_bytes[0];
    buf[4] = plen_bytes[1];
    buf[5..total].copy_from_slice(params);
    total
}

/// Encode a DLI data frame into a UART frame.
pub fn encode_data(
    pkt_type: DliPacketType,
    handle: u16,
    flags: u8,
    payload: &[u8],
    buf: &mut [u8],
) -> usize {
    let total = DATA_HEADER_SIZE + payload.len();
    if buf.len() < total || payload.len() > MAX_PAYLOAD_LEN {
        return 0;
    }
    buf[0] = pkt_type as u8;
    let raw_handle = (handle & 0x0FFF) | ((u16::from(flags) & 0x0F) << 12);
    let hb = raw_handle.to_le_bytes();
    buf[1] = hb[0];
    buf[2] = hb[1];
    let lb = (payload.len() as u16).to_le_bytes();
    buf[3] = lb[0];
    buf[4] = lb[1];
    buf[5..total].copy_from_slice(payload);
    total
}

// =========================================================================
// UART controller (DLI over UART)
// =========================================================================

/// UART transport configuration.
#[derive(Copy, Clone, Debug)]
pub struct UartConfig {
    /// Baud rate in bps.
    pub baud_rate: u32,
    /// Hardware flow control (RTS/CTS) enabled.
    pub hw_flow_ctrl: bool,
}

impl Default for UartConfig {
    fn default() -> Self {
        Self {
            baud_rate: DEFAULT_BAUD_RATE,
            hw_flow_ctrl: true,
        }
    }
}

/// UART-based SLE controller.
///
/// In a real driver, this would hold a reference to the kernel serial
/// port (`tty_struct` or `serdev_device`). For now, this provides the
/// DLI packet framing logic and loopback for testing.
pub struct UartController {
    addr: [u8; 6],
    config: UartConfig,
    parser: UartParser,
    opened: Cell<bool>,
    pending_events: RefCell<[Option<SleEvent>; super::sle_dli::CTRL_EVENT_RING_SIZE]>,
    event_head: Cell<usize>,
    event_tail: Cell<usize>,
}

// SAFETY: UartController is stored inside Mutex<ControllerBackend> in
// SparkLinkCtl.  Mutex provides exclusive access, making Cell/RefCell sound.
unsafe impl Send for UartController {}
// SAFETY: UartController is stored inside Mutex<ControllerBackend> in
// SparkLinkCtl.  Mutex provides exclusive access, making Cell/RefCell sound.
unsafe impl Sync for UartController {}

impl UartController {
    /// Create a new UART controller.
    pub fn new(addr: [u8; 6], config: UartConfig) -> Self {
        Self {
            addr,
            config,
            parser: UartParser::new(),
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
            pr_warn!("sparklink-uart: controller event ring full, dropping event\n");
            return;
        }
        self.pending_events.borrow_mut()[tail] = Some(ev);
        self.event_tail.set(next);
    }

    /// Get the current UART configuration.
    pub fn config(&self) -> &UartConfig {
        &self.config
    }

    /// Set the baud rate (takes effect on next open).
    pub fn set_baud_rate(&mut self, rate: u32) -> Result {
        if rate == 0 || rate > MAX_BAUD_RATE {
            return Err(EINVAL);
        }
        self.config.baud_rate = rate;
        Ok(())
    }

    /// Feed received bytes from the UART hardware into the parser.
    pub fn feed_rx(&mut self, data: &[u8], frames: &mut KVec<UartFrame>) {
        self.parser.feed_bytes(data, frames);
    }

    /// Encode a command for transmission over UART.
    pub fn encode_tx_command(&self, opcode: u16, params: &[u8], buf: &mut [u8]) -> usize {
        encode_command(opcode, params, buf)
    }

    /// Encode a data frame for transmission over UART.
    pub fn encode_tx_data(&self, handle: u16, data: &[u8], buf: &mut [u8]) -> usize {
        encode_data(DliPacketType::AsyncUnicast, handle, 0, data, buf)
    }
}

impl SleController for UartController {
    fn info(&self) -> SleControllerInfo {
        let mut info = SleControllerInfo::default();
        let name = b"sparklink-uart";
        info.name[..name.len()].copy_from_slice(name);
        info.bus = SleBus::Uart;
        info.addr = self.addr;
        info.fw_version = 0x0001_0000;
        info.features = (SleFeature::Encryption as u64)
            | (SleFeature::Mcs4 as u64)
            | (SleFeature::Pilot8to1 as u64)
            | (SleFeature::Crc32 as u64)
            | (SleFeature::DataLenUpdate as u64);
        info.max_pdu_payload = MAX_PAYLOAD_LEN as u16;
        info.max_connections = 4;
        info.max_mtu = 512;
        info.max_mps = MAX_PAYLOAD_LEN as u16;
        info.transport_modes = SLE_TRANSPORT_UNRELIABLE | SLE_TRANSPORT_RELIABLE;
        info.measurement_cap = SLE_MEAS_RSSI;
        info.security_cap = SLE_SEC_AES_CCM | SLE_SEC_ECDH_P256;
        info
    }

    fn open(&self) -> Result {
        if self.opened.get() {
            return Err(EBUSY);
        }
        self.opened.set(true);
        pr_info!(
            "sparklink-uart: open baud={} flow_ctrl={}\n",
            self.config.baud_rate,
            self.config.hw_flow_ctrl
        );
        Ok(())
    }

    fn close(&self) {
        self.opened.set(false);
        pr_info!("sparklink-uart: close\n");
    }

    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result {
        let mut buf = [0u8; CMD_HEADER_SIZE + MAX_PAYLOAD_LEN];
        let len = encode_command(opcode as u16, params, &mut buf);
        if len == 0 {
            return Err(EINVAL);
        }
        pr_debug!("sparklink-uart: cmd 0x{:04x} len={}\n", opcode as u16, len);
        self.enqueue_event(SleEvent::CommandComplete {
            opcode,
            status: SleStatus::Success,
            data: KVec::new(),
        });
        Ok(())
    }

    fn send_data(&self, handle: u16, data: &[u8]) -> Result {
        let mut buf = [0u8; DATA_HEADER_SIZE + MAX_PAYLOAD_LEN];
        let len = encode_data(DliPacketType::AsyncUnicast, handle, 0, data, &mut buf);
        if len == 0 {
            return Err(EINVAL);
        }
        pr_debug!("sparklink-uart: data handle={} len={}\n", handle, len);
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
        pr_info!("sparklink-uart: reset\n");
        Ok(())
    }
}
