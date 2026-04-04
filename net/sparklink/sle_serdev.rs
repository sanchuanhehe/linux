// SPDX-License-Identifier: GPL-2.0

//! SparkLink UART serial device (serdev) driver skeleton.
//!
//! This module provides the hardware-binding layer for UART-attached
//! SparkLink controllers. It follows the same pattern as the Bluetooth
//! `hci_serdev.c` / `hci_ldisc.c` drivers:
//!
//!   Device tree / ACPI → serdev match → probe → sle_attach_device
//!
//! The actual serdev API is not yet available as Rust bindings in the
//! kernel. This file defines the attach/detach skeleton and documents
//! the intended integration points. When Rust serdev bindings land,
//! the probe function will be called by the serdev core and the
//! `SleSerdevData` struct will gain a reference to `serdev_device`.
//!
//! UART transport flow:
//!
//! ```text
//!   serdev_device_ops::receive_buf() → UartParser::feed_bytes()
//!                                    → SleEvent queue
//!                                    → EventPump picks up via poll_event()
//!
//!   send_command() → encode_command() → serdev_device_write_buf()
//! ```
//!
//! Device tree binding example:
//!
//! ```dts
//!   &uart2 {
//!       sparklink {
//!           compatible = "sparklink,sle-h4";
//!           max-speed = <1000000>;
//!       };
//!   };
//! ```

#![allow(dead_code)]

use kernel::prelude::*;

use super::sle_dli::{
    ControllerEventRing, SleBus, SleController, SleControllerInfo, SleEvent, SleFeature, SleOpcode,
    SLE_MEAS_RSSI, SLE_SEC_AES_CCM, SLE_SEC_ECDH_P256, SLE_TRANSPORT_RELIABLE,
    SLE_TRANSPORT_UNRELIABLE,
};
use super::sle_transport::{SleAttachInfo, SleProtoId};
use super::sle_uart::{UartFrame, UartParser, MAX_PAYLOAD_LEN};
use super::sle_usb::{event_to_sle, DliUsbEvent};

// =========================================================================
// Serdev FFI — C wrapper functions from sle_serdev_ffi.c
// =========================================================================

/// Opaque handle for C-side `struct sle_serdev_data`.
#[repr(C)]
pub(crate) struct SleSerdevDataOpaque {
    _opaque: [u8; 0],
}

extern "C" {
    fn sle_serdev_alloc(
        serdev: *mut core::ffi::c_void,
        rust_ctx: *mut core::ffi::c_void,
    ) -> *mut SleSerdevDataOpaque;
    fn sle_serdev_open_dev(sd: *mut SleSerdevDataOpaque) -> i32;
    fn sle_serdev_close_dev(sd: *mut SleSerdevDataOpaque);
    fn sle_serdev_set_baudrate(sd: *mut SleSerdevDataOpaque, baud: u32) -> u32;
    fn sle_serdev_set_flow_control(sd: *mut SleSerdevDataOpaque, enable: bool);
    fn sle_serdev_write(
        sd: *mut SleSerdevDataOpaque,
        data: *const u8,
        len: i32,
        timeout_ms: i32,
    ) -> i32;
    fn sle_serdev_write_buf(sd: *mut SleSerdevDataOpaque, data: *const u8, len: i32) -> i32;
    fn sle_serdev_dev_register(dev_id: i32, sd: *mut SleSerdevDataOpaque) -> i32;
    fn sle_serdev_dev_unregister(dev_id: i32);
    fn sle_serdev_dev_send_cmd(dev_id: i32, opcode: u16, params: *const u8, plen: i32) -> i32;
    fn sle_serdev_dev_send_data(dev_id: i32, handle: u16, data: *const u8, len: i32) -> i32;
    fn sle_serdev_dev_send_cmd_sync(
        dev_id: i32,
        opcode: u16,
        resp: *mut u8,
        resp_size: i32,
        resp_len: *mut i32,
    ) -> i32;
    fn sle_serdev_dev_init_controller(dev_id: i32) -> i32;
    fn sle_serdev_dev_get_fw_version(dev_id: i32) -> u32;
    fn sle_serdev_dev_get_mac(dev_id: i32, mac: *mut u8) -> i32;
    fn sle_serdev_dev_feed_event(dev_id: i32, event_code: u16, params: *const u8, plen: i32);
}

// =========================================================================
// Completion callbacks from C — serdev receive path
// =========================================================================

/// Global parser state for the serdev receive path.
///
/// Protected by a spinlock since `receive_buf` can be called from softirq
/// context. Feeds incoming bytes through a `UartParser` to reconstruct DLI
/// frames, then forwards parsed events to the C-side sync command waiter.
struct SerdevParserState {
    parser: UartParser,
    dev_id: Option<u16>,
    events: ControllerEventRing,
}

impl SerdevParserState {
    fn new() -> Self {
        Self {
            parser: UartParser::new(),
            dev_id: None,
            events: ControllerEventRing::new(),
        }
    }

    fn set_dev_id(&mut self, dev_id: u16) {
        self.dev_id = Some(dev_id);
    }

    fn feed_rx(&mut self, data: &[u8]) {
        let mut frames = kernel::alloc::KVec::new();
        self.parser.feed_bytes(data, &mut frames);

        let dev_id = match self.dev_id {
            Some(id) => i32::from(id),
            None => return,
        };

        for frame in frames.iter() {
            match frame {
                UartFrame::Event { event_code, params } => {
                    // SAFETY: dev_id is valid, params pointer and length are consistent.
                    unsafe {
                        sle_serdev_dev_feed_event(
                            dev_id,
                            *event_code,
                            params.as_ptr(),
                            params.len() as i32,
                        );
                    }
                    // Convert to SleEvent and push into event ring for
                    // EventPump to pick up via poll_event().
                    let mut p = kernel::alloc::KVec::new();
                    if p.extend_from_slice(params.as_slice(), kernel::alloc::flags::GFP_KERNEL)
                        .is_err()
                    {
                        pr_warn!("sparklink-serdev: event alloc failed, dropping\n");
                        continue;
                    }
                    let raw_evt = DliUsbEvent {
                        event_code: *event_code,
                        params: p,
                    };
                    if let Some(sle_evt) = event_to_sle(&raw_evt) {
                        self.events.push(sle_evt);
                    }
                }
                _ => {
                    pr_debug!("sparklink-serdev: rx non-event frame\n");
                }
            }
        }
    }
}

kernel::sync::global_lock! {
    // SAFETY: Initialized in module_init before any serdev probe.
    unsafe(uninit) static SERDEV_PARSER: Mutex<Option<SerdevParserState>> = None;
}

/// Initialize the global serdev parser lock.
///
/// # Safety
///
/// Must be called exactly once during module init.
pub(crate) unsafe fn init_serdev_parser() {
    // SAFETY: Caller guarantees this is called exactly once during module init.
    unsafe { SERDEV_PARSER.init() };
}

/// Called from C when the serdev core delivers received bytes.
///
/// Feeds incoming data through the global UART parser which reconstructs
/// complete DLI packets, then forwards parsed events to the C-side sync
/// command waiter and the subsystem event pipeline.
#[no_mangle]
pub(crate) extern "C" fn sparklink_serdev_receive(
    _ctx: *mut core::ffi::c_void,
    data: *const u8,
    len: i32,
) {
    if data.is_null() || len <= 0 {
        return;
    }
    // SAFETY: data is non-null and len > 0, checked above; the C caller
    // guarantees the buffer is valid for len bytes.
    let slice = unsafe { core::slice::from_raw_parts(data, len as usize) };
    if let Some(ref mut state) = *SERDEV_PARSER.lock() {
        state.feed_rx(slice);
    }
}

/// Called from C when the serial port becomes writable again.
#[no_mangle]
pub(crate) extern "C" fn sparklink_serdev_write_wakeup(_ctx: *mut core::ffi::c_void) {
    pr_debug!("sparklink-serdev: write wakeup\n");
}

// =========================================================================
// Safe Rust wrapper for serdev FFI
// =========================================================================

/// Safe wrapper around the C-side serdev driver data.
pub(crate) struct SleSerdevHandle {
    inner: *mut SleSerdevDataOpaque,
}

// SAFETY: SleSerdevHandle wraps a C pointer to serdev device data which
// is heap-allocated and has no thread affinity; access is synchronized
// by the serdev core serialization guarantees.
unsafe impl Send for SleSerdevHandle {}
// SAFETY: All operations on the inner pointer call synchronized C
// functions; concurrent access is safe.
unsafe impl Sync for SleSerdevHandle {}

// =========================================================================
// SerdevController — real I/O over UART
// =========================================================================

/// UART-attached SLE controller using serdev for actual I/O.
///
/// Commands and data are sent via the C-side serdev device table which
/// encodes H4 frames and writes them to the serial port. Events arrive
/// asynchronously through the serdev receive callback, get parsed by
/// `UartParser`, and fed to the C-side sync waiter or subsystem event ring.
pub(crate) struct SerdevController {
    addr: [u8; 6],
    dev_id: u16,
    opened: bool,
}

impl SerdevController {
    pub(crate) fn new(addr: [u8; 6], dev_id: u16) -> Self {
        Self {
            addr,
            opened: false,
            dev_id,
        }
    }
}

impl SleController for SerdevController {
    fn info(&self) -> SleControllerInfo {
        let mut info = SleControllerInfo::default();
        let name = b"sparklink-serdev";
        let n = core::cmp::min(name.len(), info.name.len());
        info.name[..n].copy_from_slice(&name[..n]);
        info.bus = SleBus::Uart;
        info.addr = self.addr;
        // SAFETY: dev_id is valid.
        info.fw_version = unsafe { sle_serdev_dev_get_fw_version(i32::from(self.dev_id)) };
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
        pr_info!("sparklink-serdev: open dev_id={}\n", self.dev_id);
        Ok(())
    }

    fn close(&self) {
        pr_info!("sparklink-serdev: close dev_id={}\n", self.dev_id);
    }

    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result {
        // SAFETY: dev_id is valid, opcode and params pointer/length are consistent.
        let ret = unsafe {
            sle_serdev_dev_send_cmd(
                i32::from(self.dev_id),
                opcode as u16,
                params.as_ptr(),
                params.len() as i32,
            )
        };
        if ret < 0 {
            return Err(Error::from_errno(ret));
        }
        Ok(())
    }

    fn send_data(&self, handle: u16, data: &[u8]) -> Result {
        // SAFETY: dev_id is valid, data pointer and length are from a valid slice.
        let ret = unsafe {
            sle_serdev_dev_send_data(
                i32::from(self.dev_id),
                handle,
                data.as_ptr(),
                data.len() as i32,
            )
        };
        if ret < 0 {
            return Err(Error::from_errno(ret));
        }
        Ok(())
    }

    fn poll_event(&self) -> Option<SleEvent> {
        if let Some(ref mut state) = *SERDEV_PARSER.lock() {
            state.events.pop()
        } else {
            None
        }
    }

    fn reset(&self) -> Result {
        self.send_command(SleOpcode::Reset, &[])
    }
}

impl SleSerdevHandle {
    /// Wrap a raw pointer returned by `sle_serdev_alloc`.
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid pointer from `sle_serdev_alloc`.
    pub(crate) unsafe fn from_raw(ptr: *mut SleSerdevDataOpaque) -> Result<Self> {
        if ptr.is_null() {
            return Err(ENOMEM);
        }
        Ok(Self { inner: ptr })
    }

    /// Open the serial port.
    pub(crate) fn open(&self) -> Result {
        // SAFETY: self.inner is a valid pointer obtained during probe.
        let ret = unsafe { sle_serdev_open_dev(self.inner) };
        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(())
        }
    }

    /// Close the serial port.
    pub(crate) fn close(&self) {
        // SAFETY: self.inner is a valid pointer obtained during probe.
        unsafe { sle_serdev_close_dev(self.inner) };
    }

    /// Set the baud rate. Returns the actual rate configured.
    pub(crate) fn set_baudrate(&self, baud: u32) -> u32 {
        // SAFETY: self.inner is a valid pointer obtained during probe.
        unsafe { sle_serdev_set_baudrate(self.inner, baud) }
    }

    /// Enable or disable hardware flow control.
    pub(crate) fn set_flow_control(&self, enable: bool) {
        // SAFETY: self.inner is a valid pointer obtained during probe.
        unsafe { sle_serdev_set_flow_control(self.inner, enable) };
    }

    /// Write data, blocking until sent or timeout.
    pub(crate) fn write(&self, data: &[u8], timeout_ms: i32) -> Result<usize> {
        // SAFETY: self.inner is valid, data pointer and length are consistent.
        let ret =
            unsafe { sle_serdev_write(self.inner, data.as_ptr(), data.len() as i32, timeout_ms) };
        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(ret as usize)
        }
    }

    /// Non-blocking write. Returns number of bytes accepted.
    pub(crate) fn write_buf(&self, data: &[u8]) -> Result<usize> {
        // SAFETY: self.inner is valid, data pointer and length are consistent.
        let ret = unsafe { sle_serdev_write_buf(self.inner, data.as_ptr(), data.len() as i32) };
        if ret < 0 {
            Err(Error::from_errno(ret))
        } else {
            Ok(ret as usize)
        }
    }
}

// =========================================================================
// Constants
// =========================================================================

/// Default initial baud rate for UART attached controllers.
pub(crate) const DEFAULT_INIT_SPEED: u32 = 115_200;

/// Operational baud rate after firmware handshake (speed change).
pub(crate) const DEFAULT_OPER_SPEED: u32 = 1_000_000;

/// Compatible string for device tree matching.
pub(crate) const DT_COMPATIBLE: &str = "sparklink,sle-h4";

// =========================================================================
// Serdev driver data
// =========================================================================

/// Per-device state for a serdev-attached SLE controller.
///
/// Constructed during serdev probe and stored as driver data on the
/// `serdev_device`. When Rust serdev bindings become available, this
/// struct will hold `Arc<serdev_device>` for write-back.
pub(crate) struct SleSerdevData {
    /// Device id assigned by `sle_attach_device()`.
    dev_id: u16,
    /// Initial baud rate used during probe.
    init_speed: u32,
    /// Operational baud rate after speed change.
    oper_speed: u32,
}

impl SleSerdevData {
    /// Create a new serdev data record.
    fn new(dev_id: u16, init_speed: u32, oper_speed: u32) -> Self {
        Self {
            dev_id,
            init_speed,
            oper_speed,
        }
    }

    /// Device id in the SleDevRegistry.
    pub(crate) fn dev_id(&self) -> u16 {
        self.dev_id
    }
}

// =========================================================================
// Probe / remove
// =========================================================================

/// Probe callback for a UART-attached SLE controller.
///
/// 1. Attach device to subsystem to obtain `dev_id`.
/// 2. Register with C-side serdev device table for command I/O.
/// 3. Run controller init sequence (Reset, ReadVersion, ReadMAC).
/// 4. Read back MAC/version and switch subsystem controller to serdev.
///
/// The `sd_handle` parameter is the raw serdev data pointer from the C
/// side (from `sle_serdev_alloc`). If `None`, the function falls back to
/// a stub mode without hardware I/O (useful for integration tests).
pub(crate) fn serdev_probe(
    sd_handle: Option<*mut SleSerdevDataOpaque>,
    addr: [u8; 6],
    init_speed: u32,
    oper_speed: u32,
) -> Result<SleSerdevData> {
    pr_info!(
        "sparklink-serdev: probe init_speed={} oper_speed={}\n",
        init_speed,
        oper_speed,
    );

    let mut attach = SleAttachInfo::new(SleProtoId::H4Uart, addr);
    attach.fw_version = 0;
    attach.features = 0;

    let dev_id = super::sle_attach_device(&attach)?;
    pr_info!("sparklink-serdev: attached as sle{}\n", dev_id);

    if let Some(sd) = sd_handle {
        // Register with C-side serdev device table for command I/O.
        // SAFETY: dev_id is valid; sd pointer is valid for driver lifetime.
        let ret = unsafe { sle_serdev_dev_register(i32::from(dev_id), sd) };
        if ret < 0 {
            super::sle_detach_device(dev_id);
            return Err(Error::from_errno(ret));
        }

        // Set up the global parser to route events to this device.
        {
            let mut guard = SERDEV_PARSER.lock();
            if guard.is_none() {
                *guard = Some(SerdevParserState::new());
            }
            if let Some(ref mut state) = *guard {
                state.set_dev_id(dev_id);
            }
        }

        // Run controller init sequence (reset, read version, read MAC).
        // SAFETY: dev_id is valid.
        let init_ret = unsafe { sle_serdev_dev_init_controller(i32::from(dev_id)) };
        if init_ret < 0 {
            pr_warn!(
                "sparklink-serdev: init failed ({}), continuing with defaults\n",
                init_ret
            );
        }

        // Read back MAC address and firmware version from controller.
        let mut real_addr = addr;
        let mut mac_buf = [0u8; 6];
        // SAFETY: dev_id is valid, mac_buf is a valid 6-byte buffer.
        if unsafe { sle_serdev_dev_get_mac(i32::from(dev_id), mac_buf.as_mut_ptr()) } == 0
            && mac_buf != [0u8; 6]
        {
            real_addr = mac_buf;
            pr_info!(
                "sparklink-serdev: controller MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                real_addr[0],
                real_addr[1],
                real_addr[2],
                real_addr[3],
                real_addr[4],
                real_addr[5]
            );
        }
        // SAFETY: dev_id is valid.
        let fw_version = unsafe { sle_serdev_dev_get_fw_version(i32::from(dev_id)) };

        // Switch subsystem controller to serdev backend and sync
        // the device registry with real hardware info.
        super::sle_switch_controller_serdev(dev_id, real_addr, fw_version);
    }

    Ok(SleSerdevData::new(dev_id, init_speed, oper_speed))
}

/// Remove callback for a UART-attached SLE controller.
///
/// Unregisters the device from the C-side serdev device table and detaches
/// it from the subsystem.
pub(crate) fn serdev_remove(data: &SleSerdevData) {
    pr_info!("sparklink-serdev: remove sle{}\n", data.dev_id);
    // SAFETY: dev_id is valid; unregister is safe and idempotent.
    unsafe { sle_serdev_dev_unregister(i32::from(data.dev_id)) };
    super::sle_detach_device(data.dev_id);
}
