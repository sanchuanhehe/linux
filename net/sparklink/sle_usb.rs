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
use kernel::device;
use kernel::usb;

use core::sync::atomic::{AtomicU32, Ordering};

use super::sle_dli::{
    ControllerEventRing, DliPacketType, SleBus, SleController, SleControllerInfo,
    SleEvent, SleFeature, SleOpcode, SleStatus,
    SLE_TRANSPORT_UNRELIABLE, SLE_TRANSPORT_RELIABLE, SLE_TRANSPORT_FRAGMENTED,
    SLE_MEAS_RSSI, SLE_MEAS_PATH_LOSS,
    SLE_SEC_AES_CCM, SLE_SEC_ECDH_P256, SLE_SEC_SC,
};
use super::sle_transport::{SleAttachInfo, SleProtoId};

// ---------------------------------------------------------------------------
// Global USB event ring — receives events from C completion callbacks
// ---------------------------------------------------------------------------

kernel::sync::global_lock! {
    // SAFETY: Initialized once in module_init via init_usb_event_ring().
    unsafe(uninit) static USB_EVENT_RING: Mutex<Option<ControllerEventRing>> = None;
}

/// Initialize the global USB event ring.
///
/// # Safety
///
/// Must be called exactly once during module init.
pub(crate) unsafe fn init_usb_event_ring() {
    unsafe { USB_EVENT_RING.init() };
    *USB_EVENT_RING.lock() = Some(ControllerEventRing::new());
}

// ---------------------------------------------------------------------------
// USB FFI — C wrapper functions from sle_usb_ffi.c
// ---------------------------------------------------------------------------

/// Opaque handle returned by `sle_usb_alloc_ctx()`.
///
/// The real struct lives in C (`struct sle_urb_ctx`). Rust only holds
/// a pointer and never dereferences it directly.
#[repr(C)]
pub struct SleUrbCtxOpaque {
    _opaque: [u8; 0],
}

extern "C" {
    fn sle_usb_alloc_ctx(buf_size: i32) -> *mut SleUrbCtxOpaque;
    fn sle_usb_free_ctx(ctx: *mut SleUrbCtxOpaque);
    fn sle_usb_submit_bulk_out(
        ctx: *mut SleUrbCtxOpaque,
        udev: *mut core::ffi::c_void,
        ep: u8,
        data: *const u8,
        len: i32,
        rust_ctx: *mut core::ffi::c_void,
        timeout_ms: i32,
    ) -> i32;
    fn sle_usb_submit_bulk_in(
        ctx: *mut SleUrbCtxOpaque,
        udev: *mut core::ffi::c_void,
        ep: u8,
        rust_ctx: *mut core::ffi::c_void,
    ) -> i32;
    fn sle_usb_submit_intr_in(
        ctx: *mut SleUrbCtxOpaque,
        udev: *mut core::ffi::c_void,
        ep: u8,
        rust_ctx: *mut core::ffi::c_void,
        interval: i32,
    ) -> i32;
    fn sle_usb_kill_ctx(ctx: *mut SleUrbCtxOpaque);
    fn sle_usb_sync_bulk_out(
        udev: *mut core::ffi::c_void,
        ep: u8,
        data: *const u8,
        len: i32,
        timeout_ms: i32,
    ) -> i32;
    fn sle_usb_sync_bulk_in(
        udev: *mut core::ffi::c_void,
        ep: u8,
        buf: *mut u8,
        size: i32,
        timeout_ms: i32,
    ) -> i32;

    // Per-device USB state table: high-level send functions
    fn sle_usb_dev_register(dev_id: i32, intf_ptr: *mut core::ffi::c_void) -> i32;
    fn sle_usb_dev_unregister(dev_id: i32);
    fn sle_usb_dev_send_cmd(
        dev_id: i32,
        opcode: u16,
        params: *const u8,
        plen: i32,
    ) -> i32;
    fn sle_usb_dev_send_data(
        dev_id: i32,
        handle: u16,
        data: *const u8,
        len: i32,
    ) -> i32;
    fn sle_usb_dev_start_evt(dev_id: i32) -> i32;
    fn sle_usb_dev_stop_evt(dev_id: i32);
    fn sle_usb_dev_init_controller(dev_id: i32) -> i32;
    fn sle_usb_dev_get_fw_version(dev_id: i32) -> u32;
    fn sle_usb_dev_get_mac(dev_id: i32, mac: *mut u8) -> i32;
    fn sle_usb_dev_suspend(dev_id: i32) -> i32;
    fn sle_usb_dev_resume(dev_id: i32) -> i32;
}

// ---------------------------------------------------------------------------
// URB context: safe Rust wrapper
// ---------------------------------------------------------------------------

/// Safe wrapper around the C-side URB context.
///
/// Owns the allocation and frees it on drop. Provides methods for
/// submitting and cancelling transfers without exposing raw pointers.
pub(crate) struct SleUrbCtx {
    inner: *mut SleUrbCtxOpaque,
}

// SAFETY: The C-side sle_urb_ctx is heap-allocated and has no thread
// affinity. USB core completion callbacks are synchronized via
// usb_kill_urb before free.
unsafe impl Send for SleUrbCtx {}
unsafe impl Sync for SleUrbCtx {}

impl SleUrbCtx {
    /// Allocate a new URB context with the given buffer size.
    pub(crate) fn new(buf_size: usize) -> Result<Self> {
        // SAFETY: sle_usb_alloc_ctx handles all internal allocation.
        let ptr = unsafe { sle_usb_alloc_ctx(buf_size as i32) };
        if ptr.is_null() {
            return Err(ENOMEM);
        }
        Ok(Self { inner: ptr })
    }

    /// Submit a bulk OUT (TX) transfer asynchronously.
    ///
    /// `udev_ptr` is the raw `struct usb_device *` from the kernel.
    /// Completion will invoke `sparklink_usb_complete` with `rust_ctx`.
    pub(crate) fn submit_bulk_out(
        &self,
        udev_ptr: *mut core::ffi::c_void,
        ep: u8,
        data: &[u8],
        rust_ctx: *mut core::ffi::c_void,
    ) -> Result {
        // SAFETY: inner is valid (checked in new), data pointer and len
        // are consistent, udev_ptr must be valid by caller contract.
        let ret = unsafe {
            sle_usb_submit_bulk_out(
                self.inner,
                udev_ptr,
                ep,
                data.as_ptr(),
                data.len() as i32,
                rust_ctx,
                0,
            )
        };
        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(())
        }
    }

    /// Submit a bulk IN (RX) transfer asynchronously.
    pub(crate) fn submit_bulk_in(
        &self,
        udev_ptr: *mut core::ffi::c_void,
        ep: u8,
        rust_ctx: *mut core::ffi::c_void,
    ) -> Result {
        // SAFETY: inner/udev_ptr valid by caller contract.
        let ret = unsafe {
            sle_usb_submit_bulk_in(self.inner, udev_ptr, ep, rust_ctx)
        };
        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(())
        }
    }

    /// Submit an interrupt IN transfer (auto-resubmitting).
    pub(crate) fn submit_intr_in(
        &self,
        udev_ptr: *mut core::ffi::c_void,
        ep: u8,
        rust_ctx: *mut core::ffi::c_void,
        interval: i32,
    ) -> Result {
        // SAFETY: inner/udev_ptr valid by caller contract.
        let ret = unsafe {
            sle_usb_submit_intr_in(self.inner, udev_ptr, ep, rust_ctx, interval)
        };
        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(())
        }
    }

    /// Cancel a pending transfer.
    pub(crate) fn kill(&self) {
        // SAFETY: inner is valid.
        unsafe { sle_usb_kill_ctx(self.inner) };
    }
}

impl Drop for SleUrbCtx {
    fn drop(&mut self) {
        // SAFETY: inner was allocated by sle_usb_alloc_ctx.
        unsafe { sle_usb_free_ctx(self.inner) };
    }
}

// ---------------------------------------------------------------------------
// Synchronous bulk transfer helpers
// ---------------------------------------------------------------------------

/// Blocking bulk OUT transfer — sends `data` and waits for completion.
///
/// Returns the number of bytes actually transferred.
pub(crate) fn sync_bulk_out(
    udev_ptr: *mut core::ffi::c_void,
    ep: u8,
    data: &[u8],
    timeout_ms: i32,
) -> Result<usize> {
    // SAFETY: udev_ptr must be a valid struct usb_device pointer.
    let ret = unsafe {
        sle_usb_sync_bulk_out(udev_ptr, ep, data.as_ptr(), data.len() as i32, timeout_ms)
    };
    if ret < 0 {
        Err(Error::from_errno(ret))
    } else {
        Ok(ret as usize)
    }
}

/// Blocking bulk IN transfer — waits for data from the device.
///
/// Returns slice length of received data in the provided buffer.
pub(crate) fn sync_bulk_in(
    udev_ptr: *mut core::ffi::c_void,
    ep: u8,
    buf: &mut [u8],
    timeout_ms: i32,
) -> Result<usize> {
    // SAFETY: udev_ptr valid, buf pointer and size consistent.
    let ret = unsafe {
        sle_usb_sync_bulk_in(udev_ptr, ep, buf.as_mut_ptr(), buf.len() as i32, timeout_ms)
    };
    if ret < 0 {
        Err(Error::from_errno(ret))
    } else {
        Ok(ret as usize)
    }
}

// ---------------------------------------------------------------------------
// Completion callback from C — receives URB completion events
// ---------------------------------------------------------------------------

/// Called from C (`sle_usb_bulk_cb` / `sle_usb_intr_cb`) when a USB
/// transfer completes. The `ctx` pointer identifies which Rust-side
/// operation completed.
///
/// Currently logs the completion and feeds events into the subsystem.
/// A full implementation would match `ctx` to a pending command or
/// data transfer and wake the corresponding waiter.
#[no_mangle]
pub(crate) extern "C" fn sparklink_usb_complete(
    _ctx: *mut core::ffi::c_void,
    data: *const u8,
    length: i32,
    status: i32,
) {
    if status != 0 {
        pr_debug!("sparklink-usb: URB completed with status {}\n", status);
        return;
    }

    if length <= 0 || data.is_null() {
        return;
    }

    let len = length as usize;
    // SAFETY: data points to the URB transfer buffer which is valid
    // during the completion callback. length is the actual bytes
    // transferred, guaranteed <= buffer size by USB core.
    let slice = unsafe { core::slice::from_raw_parts(data, len) };

    // Try to parse as a DLI event packet
    if let Ok(evt) = parse_event_packet(slice) {
        if let Some(sle_evt) = event_to_sle(&evt) {
            pr_debug!(
                "sparklink-usb: event code=0x{:04x} parsed\n",
                evt.event_code
            );
            if let Some(ref mut ring) = *USB_EVENT_RING.lock() {
                ring.push(sle_evt);
            }
        }
    }
}

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

/// Extract discovery_level from raw advertising TLV data.
///
/// Scans the TLV entries (type 0x01 = discovery level per T/XS 20001)
/// and returns the 3-bit discovery level value. Returns 0 if not found.
fn extract_discovery_level(data: &[u8]) -> u8 {
    let mut i = 0;
    while i + 1 < data.len() {
        let len = data[i] as usize;
        if len == 0 || i + 1 + len > data.len() {
            break;
        }
        let typ = data[i + 1];
        if typ == 0x01 && len >= 2 {
            return data[i + 2] & 0x07;
        }
        i += 1 + len;
    }
    0
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
            let discovery_level = extract_discovery_level(data.as_slice());
            Some(SleEvent::AdvReport { addr, rssi, discovery_level, data })
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
        // Group 1: Basic (0x04xx)
        0x0401 => SleOpcode::ReadCmdLen,
        0x0402 => SleOpcode::ReadCtrlBuffer,
        0x0403 => SleOpcode::ReadLocalFeatures,
        0x0404 => SleOpcode::ReadLocalVersion,
        0x0405 => SleOpcode::SetMacAddr,
        0x0406 => SleOpcode::ReadMacAddr,
        0x0407 => SleOpcode::SetNonUniqueMac,
        0x0408 => SleOpcode::Reset,
        0x0409 => SleOpcode::AvailChannelInd,
        0x040A => SleOpcode::ReadWhitelistSize,
        0x040B => SleOpcode::ClearWhitelist,
        0x040C => SleOpcode::AddWhitelist,
        0x040D => SleOpcode::DeleteWhitelist,
        0x040E => SleOpcode::SetSlbNodeRole,
        0x040F => SleOpcode::ReadSlbNodeRole,
        0x0410 => SleOpcode::SetSlbWorkChannel,
        0x0411 => SleOpcode::ReadSlbWorkChannel,
        0x0412 => SleOpcode::ReadSlbCtrlBuffer,
        0x0413 => SleOpcode::ConfigFisaChannels,
        0x0414 => SleOpcode::EnableFisa,
        0x0415 => SleOpcode::ConfigSlbSyncSignal,
        0x0416 => SleOpcode::ReadSlbSyncSignal,
        0x0417 => SleOpcode::ReadSlbLocalPower,
        0x0418 => SleOpcode::EnableSlbCtrl,
        0x0419 => SleOpcode::IndicateTimeSync,
        0x041A => SleOpcode::TimeSyncRequest,
        0x041B => SleOpcode::TimeSyncResponse,
        0x0420 => SleOpcode::AddWhitelistExt,
        // Group 3: Broadcast (0x0Cxx)
        0x0C02 => SleOpcode::SetBroadcastParam,
        0x0C03 => SleOpcode::SetBroadcastData,
        0x0C04 => SleOpcode::SetBroadcastScanRsp,
        0x0C05 => SleOpcode::EnableBroadcast,
        0x0C06 => SleOpcode::ReadMaxBcastDataLen,
        0x0C07 => SleOpcode::ReadBcastSetSize,
        0x0C08 => SleOpcode::DeleteBcastSet,
        0x0C09 => SleOpcode::ConfigSlbDomainName,
        0x0C0A => SleOpcode::ReadSlbDomainName,
        0x0C0B => SleOpcode::ConfigSlbBcastParam,
        0x0C0C => SleOpcode::ReadSlbBcastParam,
        // Group 4: Scan (0x10xx)
        0x1001 => SleOpcode::SetScanParam,
        0x1002 => SleOpcode::EnableScan,
        0x1003 => SleOpcode::SetScanReqData,
        0x1004 => SleOpcode::SetSlbScanParam,
        // Group 5: Connection (0x14xx)
        0x1401 => SleOpcode::CreateConnection,
        0x1402 => SleOpcode::CancelConnection,
        0x1403 => SleOpcode::Disconnect,
        0x1404 => SleOpcode::SlbCreateConnection,
        // Group 6: Link control (0x18xx)
        0x1801 => SleOpcode::ReadFeatures,
        0x1802 => SleOpcode::ReadVersion,
        0x1804 => SleOpcode::SetMaxDataLen,
        0x1805 => SleOpcode::ReadPhyParam,
        0x1806 => SleOpcode::SetPhyParam,
        0x1807 => SleOpcode::ConnParamUpdate,
        0x1808 => SleOpcode::ConnParamReqReply,
        0x1809 => SleOpcode::ReadAvailChannels,
        0x180A => SleOpcode::SetCodingModulation,
        0x180C => SleOpcode::ReadRssi,
        0x180D => SleOpcode::SetTxPower,
        0x180E => SleOpcode::ReadTxPower,
        0x180F => SleOpcode::ReadPeerTxPower,
        0x1810 => SleOpcode::ConfigPowerReport,
        0x1812 => SleOpcode::SetCtrlSignalData,
        0x1813 => SleOpcode::EnableRssiPowerCtrl,
        0x1814 => SleOpcode::SetSlbCodingMod,
        0x1815 => SleOpcode::ReadSlbCodingMod,
        // Group 7: Security (0x1Cxx)
        0x1C01 => SleOpcode::HashCompute,
        0x1C02 => SleOpcode::GenSecureRandom,
        0x1C03 => SleOpcode::StartEncrypt,
        0x1C04 => SleOpcode::RequestPair,
        0x1C05 => SleOpcode::ReplyEncParamReq,
        0x1C06 => SleOpcode::RejectEncParamReq,
        0x1C07 => SleOpcode::ReadLocalEncAlgo,
        0x1C08 => SleOpcode::StartPairing,
        0x1C09 => SleOpcode::PairInfoExchange,
        0x1C0A => SleOpcode::PairOptionConfirm,
        0x1C0B => SleOpcode::PairOptionAccept,
        0x1C0C => SleOpcode::PairExtData,
        0x1C0D => SleOpcode::PairPasskey,
        0x1C0E => SleOpcode::PairRandom,
        0x1C0F => SleOpcode::PairConfirm,
        0x1C10 => SleOpcode::DhkeyVerify,
        0x1C11 => SleOpcode::PairFail,
        0x1C12 => SleOpcode::AddRalDevice,
        0x1C13 => SleOpcode::RemoveRalDevice,
        0x1C14 => SleOpcode::ClearRal,
        0x1C15 => SleOpcode::ReadRalSize,
        0x1C16 => SleOpcode::ReadRemoteRpa,
        0x1C17 => SleOpcode::ReadLocalRpa,
        0x1C18 => SleOpcode::SetRpaEnable,
        0x1C19 => SleOpcode::SetRpaTimeout,
        0x1C1A => SleOpcode::ConfigSlbAuthPsk,
        0x1C1B => SleOpcode::DeleteSlbAuthPsk,
        0x1C1C => SleOpcode::ConfigSlbAuthPwd,
        0x1C1D => SleOpcode::DeleteSlbAuthPwd,
        0x1C1E => SleOpcode::ConfigSlbCipherAlgo,
        0x1C1F => SleOpcode::ReadSlbCipherAlgo,
        0x1C20 => SleOpcode::ConfigSlbSecAssoc,
        0x1C21 => SleOpcode::ReadSlbSecAssoc,
        0x1C22 => SleOpcode::ConfigSlbSecTimeout,
        0x1C23 => SleOpcode::ReadSlbSecTimeout,
        // Group 8: Measurement (0x20xx)
        0x2001 => SleOpcode::ReadLocalMeasCap,
        0x2003 => SleOpcode::SetMeasLinkParam,
        0x2005 => SleOpcode::MeasAction,
        0x200B => SleOpcode::EnableMeas,
        // Group 9: SLB Logical Channel (0x24xx)
        0x2401 => SleOpcode::SlbCreateLogChannel,
        0x2402 => SleOpcode::SlbUpdateLogChannel,
        0x2403 => SleOpcode::SlbDeleteLogChannel,
        // Group 10: Sync link (0x28xx)
        0x2801 => SleOpcode::SyncUcastParam,
        0x2803 => SleOpcode::SyncUcastCreate,
        0x2804 => SleOpcode::SyncUcastRemove,
        0x2805 => SleOpcode::SyncUcastAccept,
        0x2806 => SleOpcode::SyncUcastReject,
        0x2807 => SleOpcode::SyncMcastParam,
        0x2808 => SleOpcode::SyncMcastInfo,
        0x2809 => SleOpcode::SyncMcastCreate,
        0x280A => SleOpcode::SyncMcastRemove,
        0x280B => SleOpcode::SyncMcastAccept,
        0x280C => SleOpcode::SyncMcastReject,
        0x280D => SleOpcode::SyncDataPathConfig,
        0x280E => SleOpcode::SyncDataPathRemove,
        // Group 62: Test (0xF8xx)
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
/// Actual USB I/O is delegated to the C FFI layer which maintains a
/// per-device table mapping `dev_id` to `usb_device` and URB contexts.
pub struct UsbController {
    addr: [u8; 6],
    opened: bool,
    /// Device ID in the sle_dev registry. Used to index the C-side
    /// USB device table for actual I/O.
    dev_id: u16,
}

impl UsbController {
    /// Create a new USB controller handle.
    ///
    /// `addr` is the 6-byte SLE MAC address read from the controller
    /// during probe via the ReadLocalAddr (0x0404) command.
    /// `dev_id` is the device ID returned by `sle_attach_device`.
    pub fn new(addr: [u8; 6], dev_id: u16) -> Self {
        Self {
            addr,
            opened: false,
            dev_id,
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
        info.max_mtu = 512;
        info.max_mps = 255;
        info.transport_modes = SLE_TRANSPORT_UNRELIABLE
            | SLE_TRANSPORT_RELIABLE
            | SLE_TRANSPORT_FRAGMENTED;
        info.measurement_cap = SLE_MEAS_RSSI | SLE_MEAS_PATH_LOSS;
        info.security_cap = SLE_SEC_AES_CCM | SLE_SEC_ECDH_P256 | SLE_SEC_SC;
        info
    }

    fn open(&self) -> Result {
        // Register event listener via the C device table.
        // SAFETY: dev_id was validated during probe.
        let ret = unsafe { sle_usb_dev_start_evt(self.dev_id as i32) };
        if ret < 0 {
            pr_warn!("sparklink-usb: event listener start failed: {}\n", ret);
            // Non-fatal: controller can still send commands.
        }
        pr_info!("sparklink-usb: open dev_id={}\n", self.dev_id);
        Ok(())
    }

    fn close(&self) {
        unsafe { sle_usb_dev_stop_evt(self.dev_id as i32) };
        pr_info!("sparklink-usb: close dev_id={}\n", self.dev_id);
    }

    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result {
        let pkt = build_command_packet(opcode, params)?;
        // Use the C device table for actual USB bulk OUT.
        // dev_send_cmd builds the DLI packet internally, but we
        // already have the raw opcode — pass it directly.
        let ret = unsafe {
            sle_usb_dev_send_cmd(
                self.dev_id as i32,
                opcode as u16,
                params.as_ptr(),
                params.len() as i32,
            )
        };
        if ret < 0 {
            pr_debug!(
                "sparklink-usb: cmd 0x{:04x} failed: {}\n",
                opcode as u16,
                ret
            );
            return Err(Error::from_errno(ret));
        }
        pr_debug!(
            "sparklink-usb: cmd 0x{:04x} sent ({} bytes)\n",
            opcode as u16,
            pkt.len()
        );
        Ok(())
    }

    fn send_data(&self, handle: u16, data: &[u8]) -> Result {
        let ret = unsafe {
            sle_usb_dev_send_data(
                self.dev_id as i32,
                handle,
                data.as_ptr(),
                data.len() as i32,
            )
        };
        if ret < 0 {
            pr_debug!(
                "sparklink-usb: data tx handle={} failed: {}\n",
                handle,
                ret
            );
            return Err(Error::from_errno(ret));
        }
        pr_debug!(
            "sparklink-usb: data tx handle={} ({} bytes)\n",
            handle,
            data.len()
        );
        Ok(())
    }

    fn poll_event(&self) -> Option<SleEvent> {
        if let Some(ref mut ring) = *USB_EVENT_RING.lock() {
            ring.pop()
        } else {
            None
        }
    }

    fn reset(&self) -> Result {
        self.send_command(SleOpcode::Reset, &[])
    }
}

// ---------------------------------------------------------------------------
// USB driver integration — hardware discovery
// ---------------------------------------------------------------------------

/// Counter for discovered USB SLE devices.
static USB_DEV_COUNT: AtomicU32 = AtomicU32::new(0);

/// Returns the number of currently attached USB SLE controllers.
pub fn usb_device_count() -> u32 {
    USB_DEV_COUNT.load(Ordering::Relaxed)
}

kernel::usb_device_table!(
    SLE_USB_IDS,
    MODULE_SLE_USB_TABLE,
    <SleUsbDriver as usb::Driver>::IdInfo,
    [
        // Match by interface class/subclass/protocol:
        //   Wireless Controller (0xE0) / RF Controller (0x01) / SparkLink DLI (0x05)
        (
            usb::DeviceId::from_interface_info(
                SLE_USB_CLASS,
                SLE_USB_SUBCLASS,
                SLE_USB_PROTOCOL,
            ),
            (),
        ),
    ]
);

/// Per-device state stored as driver data during probe.
#[pin_data]
pub(crate) struct SleUsbDriver {
    /// Allocated device id from the SleDev registry (u16::MAX = not attached).
    dev_id: u16,
}

impl usb::Driver for SleUsbDriver {
    type IdInfo = ();
    const ID_TABLE: usb::IdTable<Self::IdInfo> = &SLE_USB_IDS;

    fn probe(
        interface: &usb::Interface<device::Core>,
        _id: &usb::DeviceId,
        _info: &Self::IdInfo,
    ) -> impl PinInit<Self, Error> {
        pr_info!("sparklink-usb: SLE controller discovered\n");
        USB_DEV_COUNT.fetch_add(1, Ordering::Relaxed);

        // Build attach info for the transport framework.
        // In a real driver this would read the MAC address and firmware
        // version from the device via control transfers.
        let count = USB_DEV_COUNT.load(Ordering::Relaxed);
        let mut addr = [0x5E, 0x00, 0x00, 0x00, 0x01, count as u8];
        let attach = SleAttachInfo::new(SleProtoId::UsbBulk, addr);

        let dev_id = super::sle_attach_device(&attach).unwrap_or(u16::MAX);
        let mut fw_version: u32 = 0;
        if dev_id != u16::MAX {
            pr_info!("sparklink-usb: attached as sle{}\n", dev_id);

            // Register the USB interface in the C-side device table so
            // send_command / send_data can perform actual I/O.
            //
            // SAFETY: Interface is #[repr(transparent)] over
            // Opaque<bindings::usb_interface>. The pointer cast yields
            // the underlying C struct which the C code casts back to
            // struct usb_interface *. The interface survives as long as
            // the driver is bound (guaranteed by USB core).
            let intf_ptr = interface as *const usb::Interface<device::Core>
                as *mut core::ffi::c_void;
            let reg_ret = unsafe { sle_usb_dev_register(dev_id as i32, intf_ptr) };
            if reg_ret < 0 {
                pr_warn!(
                    "sparklink-usb: C device table register failed: {}\n",
                    reg_ret
                );
            } else {
                // Run the init sequence: Reset → ReadLocalVersion → ReadMacAddr.
                // Failures are non-fatal: the driver continues with placeholder
                // values from sle_attach_device.
                let init_ret = unsafe { sle_usb_dev_init_controller(dev_id as i32) };
                if init_ret == 0 {
                    // Read back real MAC address and firmware version
                    // from the C device table and update the device info.
                    let mut real_mac = [0u8; 6];
                    let mac_ret = unsafe {
                        sle_usb_dev_get_mac(dev_id as i32, real_mac.as_mut_ptr())
                    };
                    if mac_ret == 0 && real_mac != [0u8; 6] {
                        // Use real MAC from controller
                        addr = real_mac;
                    }
                    fw_version = unsafe {
                        sle_usb_dev_get_fw_version(dev_id as i32)
                    };
                    pr_info!(
                        "sparklink-usb: init OK fw=0x{:08x} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                        fw_version,
                        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
                    );

                    // Attempt firmware download (non-fatal if firmware
                    // blob is absent or already programmed).
                    let fw_name = kernel::c_str!("sparklink/sle_usb_v1.bin");
                    let kern_dev: &kernel::device::Device<kernel::device::Core> = interface.as_ref();
                    match super::sle_fw::load_usb_firmware(dev_id, fw_name, kern_dev) {
                        Ok(r) => pr_info!(
                            "sparklink-usb: firmware loaded ({} bytes)\n",
                            r.size
                        ),
                        Err(_) => pr_debug!(
                            "sparklink-usb: firmware load skipped\n"
                        ),
                    }
                }
            }

            // Switch the subsystem controller backend to USB and sync
            // the device registry with real hardware info.
            super::sle_switch_controller_usb(dev_id, addr, fw_version);
        }

        try_pin_init!(Self { dev_id })
    }

    fn disconnect(_interface: &usb::Interface<device::Core>, data: Pin<&Self>) {
        pr_info!("sparklink-usb: SLE controller removed\n");
        USB_DEV_COUNT.fetch_sub(1, Ordering::Relaxed);

        let dev_id = data.dev_id;
        if dev_id != u16::MAX {
            // Stop URBs and unregister from C device table.
            unsafe { sle_usb_dev_unregister(dev_id as i32) };
            super::sle_detach_device(dev_id);
            pr_info!("sparklink-usb: detached sle{}\n", dev_id);
        }
    }

    fn suspend(
        _interface: &usb::Interface<device::Core>,
        data: Pin<&Self>,
        _event: kernel::ffi::c_int,
    ) -> Result {
        let dev_id = data.dev_id;
        if dev_id == u16::MAX {
            return Ok(());
        }
        let ret = unsafe { sle_usb_dev_suspend(dev_id as i32) };
        if ret < 0 {
            pr_err!("sparklink-usb: suspend sle{} failed: {}\n", dev_id, ret);
            return Err(Error::from_errno(ret));
        }
        super::sle_suspend_device(dev_id);
        pr_info!("sparklink-usb: sle{} suspended\n", dev_id);
        Ok(())
    }

    fn resume(
        _interface: &usb::Interface<device::Core>,
        data: Pin<&Self>,
    ) -> Result {
        let dev_id = data.dev_id;
        if dev_id == u16::MAX {
            return Ok(());
        }
        let ret = unsafe { sle_usb_dev_resume(dev_id as i32) };
        if ret < 0 {
            pr_err!("sparklink-usb: resume sle{} failed: {}\n", dev_id, ret);
            return Err(Error::from_errno(ret));
        }
        super::sle_resume_device(dev_id);
        pr_info!("sparklink-usb: sle{} resumed\n", dev_id);
        Ok(())
    }
}

/// Type alias for USB driver registration used by the core module.
pub(crate) type UsbRegistration = kernel::driver::Registration<usb::Adapter<SleUsbDriver>>;
