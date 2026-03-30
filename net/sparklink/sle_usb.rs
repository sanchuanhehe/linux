// SPDX-License-Identifier: GPL-2.0

//! SparkLink USB transport for SLE DLI controllers.
//!
//! Implements DLI packet framing over USB and provides [`UsbController`]
//! which implements the [`SleController`] trait for USB-attached
//! SparkLink radio controllers.
//!
//! Protocol follows T/XS 10003-2025 USB transport binding:
//!
//! USB interface descriptor:
//!   bInterfaceClass     = 0xE0   Wireless Controller
//!   bInterfaceSubClass  = 0x01   RF Controller
//!   bInterfaceProtocol  = 0x05   SparkLink DLI
//!
//! Endpoint mapping (host perspective):
//!   EP0  Control           Setup requests for DLI instructions
//!   EP1  Interrupt IN 0x81 DLI events from controller (16B, 4 ms)
//!   EP2  Bulk IN      0x82 Async/sync data from controller
//!   EP3  Bulk OUT     0x03 Commands and TX data to controller

#![allow(dead_code, unreachable_pub)]

use kernel::prelude::*;
use kernel::alloc::KVec;

use super::sle_dli::{
    DliPacketType, SleBus, SleController, SleControllerInfo, SleEvent, SleFeature,
    SleOpcode, SleStatus,
};

// ---------------------------------------------------------------------------
// USB descriptor class / subclass / protocol
// ---------------------------------------------------------------------------

/// USB interface class for SLE wireless controllers.
pub const SLE_USB_CLASS: u8 = 0xE0;
/// USB interface subclass: RF controller.
pub const SLE_USB_SUBCLASS: u8 = 0x01;
/// USB interface protocol: SparkLink DLI.
pub const SLE_USB_PROTOCOL: u8 = 0x05;

// ---------------------------------------------------------------------------
// Endpoint addresses and sizes (host perspective)
// ---------------------------------------------------------------------------

/// Interrupt IN endpoint for DLI events (controller-to-host).
pub const EP_EVENT_IN: u8 = 0x81;
/// Bulk IN endpoint for async/sync data reception.
pub const EP_DATA_IN: u8 = 0x82;
/// Bulk OUT endpoint for commands and TX data.
pub const EP_CMD_DATA_OUT: u8 = 0x03;

/// Interrupt endpoint max packet size.
pub const EP_EVENT_MAX_PKT: usize = 16;
/// Bulk endpoint max packet size (full-speed).
pub const EP_BULK_FS_MAX_PKT: usize = 64;
/// Bulk endpoint max packet size (high-speed).
pub const EP_BULK_HS_MAX_PKT: usize = 512;

/// USB class request type for DLI control transfers.
pub const SLE_USB_REQ_TYPE: u8 = 0x20;

// ---------------------------------------------------------------------------
// Timeouts (milliseconds)
// ---------------------------------------------------------------------------

/// Timeout for DLI command responses.
pub const CMD_TIMEOUT_MS: u32 = 5000;
/// Timeout for bulk data transfers.
pub const DATA_TIMEOUT_MS: u32 = 1000;
/// Interval for polling the event interrupt endpoint.
pub const EVENT_POLL_INTERVAL_MS: u32 = 4;

// ---------------------------------------------------------------------------
// DLI packet size limits
// ---------------------------------------------------------------------------

/// Maximum parameter length in a DLI command or event packet.
pub const DLI_PARAM_MAX: usize = 255;

/// Maximum async data payload (9-bit length field).
pub const DLI_DATA_PAYLOAD_MAX: usize = 511;

// ---------------------------------------------------------------------------
// DLI USB packet builders
// ---------------------------------------------------------------------------

/// Build a DLI command packet for USB bulk OUT transmission.
///
/// Wire format (all multi-byte values little-endian):
///
///     Byte 0:      0xA1 (DliPacketType::Command)
///     Bytes 1-2:   opcode (LE16)
///     Byte 3:      parameter length
///     Bytes 4..N:  parameters
pub fn build_command_packet(opcode: SleOpcode, params: &[u8]) -> Result<KVec<u8>> {
    let param_len = params.len().min(DLI_PARAM_MAX);
    let total = 4 + param_len;
    let mut buf = KVec::with_capacity(total, GFP_KERNEL)?;

    buf.push(DliPacketType::Command as u8, GFP_KERNEL)?;
    let op = opcode as u16;
    buf.push(op as u8, GFP_KERNEL)?;
    buf.push((op >> 8) as u8, GFP_KERNEL)?;
    buf.push(param_len as u8, GFP_KERNEL)?;
    for &b in &params[..param_len] {
        buf.push(b, GFP_KERNEL)?;
    }
    Ok(buf)
}

/// Build a DLI async unicast data packet for USB bulk OUT.
///
/// Wire format:
///
///     Byte 0:      0xA3 (DliPacketType::AsyncUnicast)
///     Bytes 1-2:   link_id_seg field (LE16)
///                  [15:4] = link_id (12 bits)
///                  [3:2]  = segmentation (2 bits)
///                  [1]    = reserved
///                  [0]    = priority
///     Bytes 3-4:   data_len field (LE16)
///                  [8:0]  = payload length (9 bits)
///                  [15:9] = reserved
///     Bytes 5..N:  payload
pub fn build_async_data_packet(
    link_id: u16,
    seg: u8,
    priority: bool,
    data: &[u8],
) -> Result<KVec<u8>> {
    let payload_len = data.len().min(DLI_DATA_PAYLOAD_MAX);
    let total = 5 + payload_len;
    let mut buf = KVec::with_capacity(total, GFP_KERNEL)?;

    buf.push(DliPacketType::AsyncUnicast as u8, GFP_KERNEL)?;

    let link_id_seg: u16 = ((link_id & 0x0FFF) << 4)
        | (((seg & 0x03) as u16) << 2)
        | (priority as u16);
    buf.push(link_id_seg as u8, GFP_KERNEL)?;
    buf.push((link_id_seg >> 8) as u8, GFP_KERNEL)?;

    let data_len_field: u16 = (payload_len as u16) & 0x01FF;
    buf.push(data_len_field as u8, GFP_KERNEL)?;
    buf.push((data_len_field >> 8) as u8, GFP_KERNEL)?;

    for &b in &data[..payload_len] {
        buf.push(b, GFP_KERNEL)?;
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// DLI USB packet parsers
// ---------------------------------------------------------------------------

/// Parsed DLI event from the interrupt IN endpoint.
pub struct DliUsbEvent {
    /// Raw event code (T/XS 10003-2025).
    pub event_code: u16,
    /// Event parameters.
    pub params: KVec<u8>,
}

/// Parse a raw DLI event received on the interrupt IN endpoint.
///
/// Wire format (no packet type byte — implicit from endpoint):
///
///     Bytes 0-1:   event_code (LE16)
///     Byte 2:      parameter length
///     Bytes 3..N:  parameters
pub fn parse_event_packet(data: &[u8]) -> Result<DliUsbEvent> {
    if data.len() < 3 {
        return Err(EINVAL);
    }
    let event_code = u16::from_le_bytes([data[0], data[1]]);
    let param_len = data[2] as usize;

    if data.len() < 3 + param_len {
        return Err(EINVAL);
    }

    let mut params = KVec::with_capacity(param_len, GFP_KERNEL)?;
    for &b in &data[3..3 + param_len] {
        params.push(b, GFP_KERNEL)?;
    }

    Ok(DliUsbEvent { event_code, params })
}

/// Parsed async data header.
pub struct DliAsyncHeader {
    /// 12-bit link identifier.
    pub link_id: u16,
    /// 2-bit segmentation indicator (0=complete, 1=first, 2=cont, 3=last).
    pub seg: u8,
    /// Priority flag.
    pub priority: bool,
    /// Payload length (9 bits).
    pub data_len: u16,
}

/// Parse the async/sync data header from a bulk IN packet.
///
/// Expects the raw packet starting with the type byte already stripped
/// (or starting at byte 1 of the full packet).
pub fn parse_async_data_header(data: &[u8]) -> Result<DliAsyncHeader> {
    if data.len() < 4 {
        return Err(EINVAL);
    }

    let link_id_seg = u16::from_le_bytes([data[0], data[1]]);
    let data_len_field = u16::from_le_bytes([data[2], data[3]]);

    Ok(DliAsyncHeader {
        link_id: (link_id_seg >> 4) & 0x0FFF,
        seg: ((link_id_seg >> 2) & 0x03) as u8,
        priority: (link_id_seg & 1) != 0,
        data_len: data_len_field & 0x01FF,
    })
}

/// Convert a raw event code and parameters into an [`SleEvent`].
pub fn event_to_sle(evt: &DliUsbEvent) -> Option<SleEvent> {
    match evt.event_code {
        // CmdComplete (0x0002): [opcode:2] [status:1] [return_params:N]
        0x0002 => {
            if evt.params.len() < 3 {
                return None;
            }
            let opcode_raw = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let status_raw = evt.params[2];
            let data = if evt.params.len() > 3 {
                let mut v = KVec::new();
                for &b in &evt.params[3..] {
                    let _ = v.push(b, GFP_KERNEL);
                }
                v
            } else {
                KVec::new()
            };
            // Reinterpret opcode — if unknown, use VendorBase as fallback
            let opcode = raw_to_opcode(opcode_raw);
            let status = raw_to_status(status_raw);
            Some(SleEvent::CommandComplete {
                opcode,
                status,
                data,
            })
        }
        // CmdStatus (0x0001): [status:1] [opcode:2]
        0x0001 => {
            if evt.params.len() < 3 {
                return None;
            }
            let status_raw = evt.params[0];
            let opcode_raw = u16::from_le_bytes([evt.params[1], evt.params[2]]);
            Some(SleEvent::CommandStatus {
                opcode: raw_to_opcode(opcode_raw),
                status: raw_to_status(status_raw),
            })
        }
        // ConnEstablished (0x0015): [status:1] [handle:2] [addr:6]
        0x0015 => {
            if evt.params.len() < 9 {
                return None;
            }
            let status_raw = evt.params[0];
            let handle = u16::from_le_bytes([evt.params[1], evt.params[2]]);
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&evt.params[3..9]);
            Some(SleEvent::ConnComplete {
                handle,
                addr,
                status: raw_to_status(status_raw),
            })
        }
        // DisconnectDone (0x0005): [handle:2] [reason:1]
        0x0005 => {
            if evt.params.len() < 3 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            let reason = evt.params[2];
            Some(SleEvent::Disconnected { handle, reason })
        }
        // BroadcastReport (0x001A): [addr:6] [rssi:1] [data_len:1] [data:N]
        0x001A => {
            if evt.params.len() < 8 {
                return None;
            }
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&evt.params[..6]);
            let rssi = evt.params[6] as i8;
            let data_len = evt.params[7] as usize;
            let data_end = (8 + data_len).min(evt.params.len());
            let mut data = KVec::new();
            for &b in &evt.params[8..data_end] {
                let _ = data.push(b, GFP_KERNEL);
            }
            Some(SleEvent::AdvReport { addr, rssi, data })
        }
        // HwError (0x000A): [code:1]
        0x000A => {
            if evt.params.is_empty() {
                return None;
            }
            Some(SleEvent::HardwareError {
                code: evt.params[0],
            })
        }
        // EncStatusChange (0x0011): [handle:2] [enabled:1]
        0x0011 => {
            if evt.params.len() < 3 {
                return None;
            }
            let handle = u16::from_le_bytes([evt.params[0], evt.params[1]]);
            Some(SleEvent::EncryptionChanged {
                handle,
                enabled: evt.params[2] != 0,
            })
        }
        // PairRequest (0x001D): [addr:6] [method:1]
        0x001D => {
            if evt.params.len() < 7 {
                return None;
            }
            let mut addr = [0u8; 6];
            addr.copy_from_slice(&evt.params[..6]);
            Some(SleEvent::PairRequest {
                addr,
                method: evt.params[6],
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Raw value conversion helpers
// ---------------------------------------------------------------------------

fn raw_to_opcode(raw: u16) -> SleOpcode {
    // Return the opcode if it matches a known variant, otherwise VendorBase
    match raw {
        0x0401 => SleOpcode::Reset,
        0x0402 => SleOpcode::ReadLocalVersion,
        0x0403 => SleOpcode::ReadLocalFeatures,
        0x0404 => SleOpcode::ReadLocalAddr,
        0x0405 => SleOpcode::SetMacAddr,
        0x0406 => SleOpcode::ReadBufferSize,
        0x0407 => SleOpcode::SetEventMask,
        0x0C01 => SleOpcode::SetBroadcastParam,
        0x0C02 => SleOpcode::SetBroadcastData,
        0x0C03 => SleOpcode::SetBroadcastScanRsp,
        0x0C04 => SleOpcode::EnableBroadcast,
        0x1001 => SleOpcode::SetScanParam,
        0x1002 => SleOpcode::EnableScan,
        0x1401 => SleOpcode::CreateConnection,
        0x1402 => SleOpcode::Disconnect,
        0x1403 => SleOpcode::SetConnParam,
        0x1404 => SleOpcode::ReadConnParam,
        0x1405 => SleOpcode::ConnParamReqReply,
        0x1406 => SleOpcode::ReadFeatures,
        0x1407 => SleOpcode::ReadVersion,
        0x1408 => SleOpcode::ReadRssi,
        0x1801 => SleOpcode::SetPhyParam,
        0x1802 => SleOpcode::ReadPhyParam,
        0x1803 => SleOpcode::SetTxPower,
        0x1804 => SleOpcode::ReadTxPower,
        0x1805 => SleOpcode::SetMaxDataLen,
        0x1806 => SleOpcode::ReadMaxDataLen,
        0x1C01 => SleOpcode::RequestPair,
        0x1C02 => SleOpcode::PairResponse,
        0x1C03 => SleOpcode::PairPublicKey,
        0x1C04 => SleOpcode::PairDhCheck,
        0x1C05 => SleOpcode::SetPairPsk,
        0x1C06 => SleOpcode::SetPairSk,
        0x1C07 => SleOpcode::SetPairPassword,
        0x1C08 => SleOpcode::StartEncrypt,
        0x1C0D => SleOpcode::PairPasskey,
        0x1C0E => SleOpcode::PairRandom,
        0x1C0F => SleOpcode::PairConfirm,
        0x1C10 => SleOpcode::DhkeyVerify,
        0x1C11 => SleOpcode::PairFail,
        0x1C12 => SleOpcode::AddRalDevice,
        0x1C14 => SleOpcode::ClearRal,
        0x1C15 => SleOpcode::ReadRalSize,
        0x1C18 => SleOpcode::SetRpaEnable,
        0x1C19 => SleOpcode::SetRpaTimeout,
        0x2001 => SleOpcode::ReadLocalMeasCap,
        0x2003 => SleOpcode::SetMeasLinkParam,
        0x2005 => SleOpcode::MeasAction,
        0x200B => SleOpcode::EnableMeas,
        0x2801 => SleOpcode::SyncUcastParam,
        0x2803 => SleOpcode::SyncUcastCreate,
        0x2804 => SleOpcode::SyncUcastRemove,
        0xF801 => SleOpcode::TestModeEnable,
        0xF802 => SleOpcode::TestRx,
        0xF803 => SleOpcode::TestTx,
        0xF804 => SleOpcode::TestRxResult,
        _ => SleOpcode::VendorBase,
    }
}

fn raw_to_status(raw: u8) -> SleStatus {
    match raw {
        0x00 => SleStatus::Success,
        0x01 => SleStatus::UnknownCommand,
        0x02 => SleStatus::InvalidParameters,
        0x03 => SleStatus::HardwareFailure,
        0x04 => SleStatus::ResourceExhausted,
        0x05 => SleStatus::NotConnected,
        0x06 => SleStatus::AlreadyActive,
        0x07 => SleStatus::PermissionDenied,
        0x08 => SleStatus::Timeout,
        _ => SleStatus::HardwareFailure,
    }
}

// ---------------------------------------------------------------------------
// USB controller (SleController implementation)
// ---------------------------------------------------------------------------

/// USB-attached SLE controller state.
///
/// Constructed during USB probe when a matching device is detected.
/// Uses bulk and interrupt transfers to communicate with the radio
/// controller firmware over the DLI protocol.
///
/// Integration with the USB subsystem requires a separate kernel module
/// (`sparklink_usb`) that implements `usb::Driver` and creates an
/// instance of `UsbController` per interface. The current implementation
/// provides the SleController trait and packet framing — actual USB I/O
/// is deferred until hardware integration.
pub struct UsbController {
    addr: [u8; 6],
    opened: bool,
}

impl UsbController {
    /// Create a new USB controller handle.
    ///
    /// `addr` is the 6-byte SLE MAC address read from the controller
    /// during probe via the ReadLocalAddr (0x0404) command.
    pub fn new(addr: [u8; 6]) -> Self {
        Self {
            addr,
            opened: false,
        }
    }
}

impl SleController for UsbController {
    fn info(&self) -> SleControllerInfo {
        let mut info = SleControllerInfo::default();
        let name = b"sparklink-usb";
        info.name[..name.len()].copy_from_slice(name);
        info.bus = SleBus::Usb;
        info.addr = self.addr;
        info.fw_version = 0; // read from device during open
        info.features = (SleFeature::Encryption as u64)
            | (SleFeature::DataLenUpdate as u64)
            | (SleFeature::Mcs4 as u64)
            | (SleFeature::Bw2m as u64)
            | (SleFeature::Pilot8to1 as u64)
            | (SleFeature::Crc32 as u64);
        info.max_pdu_payload = 255;
        info.max_connections = 8;
        info
    }

    fn open(&self) -> Result {
        // Real implementation: send Reset (0x0401) command via bulk OUT,
        // wait for CommandComplete event on interrupt IN, then read
        // firmware version and features.
        //
        // Requires: usb_bulk_msg() for EP3 write, usb_interrupt_msg()
        //           for EP1 read.
        pr_info!("sparklink-usb: open (no hardware attached)\n");
        Err(ENODEV)
    }

    fn close(&self) {
        pr_info!("sparklink-usb: close\n");
    }

    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result {
        let pkt = build_command_packet(opcode, params)?;
        // Real implementation: usb_bulk_msg(udev, pipe_out, pkt,
        //                                   pkt.len(), &actual, timeout)
        pr_debug!(
            "sparklink-usb: cmd 0x{:04x} ({} bytes)\n",
            opcode as u16,
            pkt.len()
        );
        Err(ENODEV)
    }

    fn send_data(&self, handle: u16, data: &[u8]) -> Result {
        let pkt = build_async_data_packet(handle, 0, false, data)?;
        // Real implementation: usb_bulk_msg(udev, pipe_out, pkt,
        //                                   pkt.len(), &actual, timeout)
        pr_debug!(
            "sparklink-usb: data tx handle={} ({} bytes)\n",
            handle,
            pkt.len()
        );
        Err(ENODEV)
    }

    fn poll_event(&self) -> Option<SleEvent> {
        // Real implementation: usb_interrupt_msg(udev, pipe_in, buf,
        //                                        EP_EVENT_MAX_PKT,
        //                                        &actual, timeout)
        // then parse_event_packet() + event_to_sle()
        None
    }

    fn reset(&self) -> Result {
        self.send_command(SleOpcode::Reset, &[])
    }
}
