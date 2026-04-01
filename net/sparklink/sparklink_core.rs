// SPDX-License-Identifier: GPL-2.0

//! SparkLink (NearLink) protocol stack core.
//!
//! This module implements the SparkLink Controller Interface (SCI) framework
//! and provides device management, discovery, and control plane functionality
//! for the SparkLink short-range wireless communication system.
//!
//! The architecture follows a layered design aligned with the SparkLink
//! standard (T/XS 10002-2025, T/XS 20001-2025):
//!
//!   - SCI Core: Device lifecycle, registration, global device list
//!   - Discovery: Device discovery with discovery levels and filtering
//!   - Transport: Async/sync data link management
//!   - Security: SM2/SM3/SM4 pairing and encryption (future)

mod sle_pdu;
mod sle_adv;
mod sle_conn;
mod sle_crypto;
mod sle_security;
mod sle_ssap;
mod sle_power;
mod sle_dli;
mod sle_dev;
mod sle_mgmt;
mod sle_transport;
mod sle_serdev;
mod sle_event;
mod sle_usb;
mod sle_netlink;
mod sle_configfs;
mod sle_phy;
mod sle_uart;
mod sle_spi;
mod sle_fw;

use sle_dli::SleController;

use kernel::sync::atomic::Relaxed;
use kernel::sync::Arc;
use kernel::configfs_attrs;
use kernel::{
    bindings,
    configfs,
    debugfs::{Dir, File},
    device::Device,
    fs::{File as FsFile, Kiocb},
    ioctl::{_IO, _IOR, _IOW, _IOWR},
    iov::IovIterDest,
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    new_mutex, new_poll_condvar,
    prelude::*,
    str::CString,
    sync::{
        aref::ARef,
        atomic::Atomic,
        poll::{PollCondVar, PollTable},
        Mutex,
    },
    time::msecs_to_jiffies,
    transmute::FromBytes,
    uaccess::{UserPtr, UserSlice},
    workqueue::{self, impl_has_delayed_work, new_delayed_work, DelayedWork, WorkItem},
};

use sle_adv::{AdvParams, AdvScanInner, ScanParams};
use sle_conn::{AccessResponseType, ConnManager, GtRole, NegotiatedParams, CONN_DATA_MAX};
use sle_security::SecurityInner;
use sle_ssap::SsapInner;
use sle_power::PowerInner;
use sle_event::EventQueue;

// ---------------------------------------------------------------------------
// Userspace read/write helpers for repr(C) ioctl structures
// ---------------------------------------------------------------------------

/// Read a repr(C) struct from userspace.
///
/// # Safety requirement on T
///
/// `T` must be `repr(C)` with only primitive fields so that every bit
/// pattern produced by FromBytes is valid.
fn read_user_struct<T: FromBytes + Sized>(arg: usize) -> Result<T> {
    let slice = UserSlice::new(UserPtr::from_addr(arg), core::mem::size_of::<T>());
    let mut reader = slice.reader();
    reader.read()
}

/// Write a repr(C) struct to userspace.
///
/// # Safety
///
/// `T` must be `repr(C)` with only primitive fields and fully initialized
/// (typically via `core::mem::zeroed()` followed by field assignments) so
/// that converting it to a byte slice is defined behaviour.
fn write_user_struct<T: Sized>(arg: usize, val: &T) -> Result {
    // SAFETY: T is repr(C) with only primitive fields, caller guarantees
    // the value is fully initialized.
    let bytes = unsafe {
        core::slice::from_raw_parts(val as *const T as *const u8, core::mem::size_of::<T>())
    };
    let slice = UserSlice::new(UserPtr::from_addr(arg), core::mem::size_of::<T>());
    slice.writer().write_slice(bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Global device counter (shared with C genetlink code via FFI)
// ---------------------------------------------------------------------------

/// Return the number of registered SparkLink devices (C FFI export).
#[no_mangle]
pub extern "C" fn sparklink_genl_get_dev_count() -> u32 {
    let ss = SUBSYSTEM.lock();
    match ss.as_ref() {
        Some(shared) => shared.dev_registry.count() as u32,
        None => 0,
    }
}

/// Return the protocol stack version as a packed u32 (C FFI export).
#[no_mangle]
pub extern "C" fn sparklink_genl_get_proto_version() -> u32 {
    0x000300 // v0.3.0
}

/// Get the current GT role (C FFI export). 0=TNode, 1=GNode.
#[no_mangle]
pub extern "C" fn sparklink_genl_get_role() -> u8 {
    let ss = SUBSYSTEM.lock();
    match ss.as_ref() {
        Some(shared) => shared.local_role as u8,
        None => 0,
    }
}

/// Set the local GT role (C FFI export). 0=TNode, 1=GNode.
/// Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn sparklink_genl_set_role(role: u8) -> i32 {
    let mut ss = SUBSYSTEM.lock();
    match ss.as_mut() {
        Some(shared) => {
            shared.local_role = if role == 1 { GtRole::GNode } else { GtRole::TNode };
            0
        }
        None => -(bindings::ENODEV as i32),
    }
}

/// Connection info result for genl (C FFI).
#[repr(C)]
pub struct GenlConnInfo {
    /// Connection handle.
    pub handle: u16,
    /// Connection state.
    pub state: u8,
    /// Local GT role (0=T, 1=G).
    pub role: u8,
    /// Peer SLE address (6 bytes).
    pub peer_addr: [u8; 6],
    /// Bandwidth in MHz.
    pub bandwidth_mhz: u8,
    /// MCS index.
    pub mcs_index: u8,
    /// Total TX bytes.
    pub tx_bytes: u64,
    /// Total RX bytes.
    pub rx_bytes: u64,
}

/// Get connection info by handle (C FFI export).
/// Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn sparklink_genl_get_conn_info(handle: u16, out: *mut GenlConnInfo) -> i32 {
    let ss = SUBSYSTEM.lock();
    match ss.as_ref() {
        Some(shared) => match shared.conn.info(handle) {
            Ok(entry) => {
                // SAFETY: caller guarantees out is a valid pointer.
                let info = unsafe { &mut *out };
                info.handle = entry.handle;
                info.state = entry.state as u8;
                info.role = entry.local_role as u8;
                info.peer_addr = entry.peer_addr;
                info.bandwidth_mhz = entry.params.bandwidth_mhz;
                info.mcs_index = entry.params.mcs_index;
                info.tx_bytes = entry.tx_bytes;
                info.rx_bytes = entry.rx_bytes;
                0
            }
            Err(_) => -(bindings::ENOENT as i32),
        },
        None => -(bindings::ENODEV as i32),
    }
}

/// Power management info result for genl (C FFI).
#[repr(C)]
pub struct GenlPmInfo {
    /// Power state.
    pub state: u8,
    /// Force-active flag.
    pub force_active: u8,
    /// Estimated power percentage.
    pub power_pct: u8,
    /// Padding.
    _pad: u8,
    /// State transition count.
    pub transitions: u32,
}

/// Get power management info (C FFI export).
#[no_mangle]
pub extern "C" fn sparklink_genl_get_pm_info(out: *mut GenlPmInfo) -> i32 {
    let ss = SUBSYSTEM.lock();
    match ss.as_ref() {
        Some(shared) => {
            let info = unsafe { &mut *out };
            info.state = shared.power.state as u8;
            info.force_active = if shared.power.is_forced_active() { 1 } else { 0 };
            info.power_pct = shared.power.estimated_power_pct();
            info._pad = 0;
            info.transitions = shared.power.stats.transitions;
            0
        }
        None => -(bindings::ENODEV as i32),
    }
}

/// DLI controller info result for genl (C FFI).
#[repr(C)]
pub struct GenlDliInfo {
    /// DLI bus type.
    pub bus_type: u8,
    /// Max concurrent connections.
    pub max_conn: u8,
    /// Supported transport modes (bitmask).
    pub transport_modes: u8,
    /// Measurement capabilities (bitmask).
    pub measurement_cap: u8,
    /// Firmware version.
    pub fw_version: u32,
    /// Feature bitmask.
    pub features: u64,
    /// Maximum MTU.
    pub max_mtu: u16,
    /// Maximum MPS.
    pub max_mps: u16,
    /// Security capabilities (bitmask).
    pub security_cap: u16,
    _pad: [u8; 2],
}

/// Get DLI controller info (C FFI export).
#[no_mangle]
pub extern "C" fn sparklink_genl_get_dli_info(out: *mut GenlDliInfo) -> i32 {
    let ss = SUBSYSTEM.lock();
    match ss.as_ref() {
        Some(shared) => {
            let ci = shared.controller.info();
            let info = unsafe { &mut *out };
            info.bus_type = ci.bus as u8;
            info.max_conn = ci.max_connections;
            info.transport_modes = ci.transport_modes;
            info.measurement_cap = ci.measurement_cap;
            info.fw_version = ci.fw_version;
            info.features = ci.features;
            info.max_mtu = ci.max_mtu;
            info.max_mps = ci.max_mps;
            info.security_cap = ci.security_cap;
            info._pad = [0u8; 2];
            0
        }
        None => -(bindings::ENODEV as i32),
    }
}

// ---------------------------------------------------------------------------
// Generic Netlink C bridge (conditional on CONFIG_SPARKLINK_GENL)
// ---------------------------------------------------------------------------

#[cfg(CONFIG_SPARKLINK_GENL)]
mod genl_bridge {
    extern "C" {
        pub(crate) fn sparklink_genl_register() -> core::ffi::c_int;
        pub(crate) fn sparklink_genl_unregister();
        pub(crate) fn sparklink_genl_send_event(
            event_type: u8,
            handle: u16,
            addr: *const u8,
            addr_len: u32,
            payload: *const u8,
            payload_len: u32,
        ) -> core::ffi::c_int;
    }

    pub(crate) struct GenlGuard;

    impl GenlGuard {
        pub(crate) fn new() -> kernel::error::Result<Self> {
            // SAFETY: sparklink_genl_register is defined in sparklink_genl.c
            let ret = unsafe { sparklink_genl_register() };
            if ret != 0 {
                return Err(kernel::error::Error::from_errno(ret));
            }
            Ok(Self)
        }
    }

    impl Drop for GenlGuard {
        fn drop(&mut self) {
            // SAFETY: sparklink_genl_unregister is defined in sparklink_genl.c
            unsafe { sparklink_genl_unregister(); }
        }
    }

    /// Broadcast an event via genetlink multicast.
    pub(crate) fn notify_event(event_type: u8, handle: u16, addr: &[u8; 6]) {
        // SAFETY: sparklink_genl_send_event is defined in sparklink_genl.c
        unsafe {
            sparklink_genl_send_event(
                event_type,
                handle,
                addr.as_ptr(),
                6,
                core::ptr::null(),
                0,
            );
        }
    }
}

#[cfg(not(CONFIG_SPARKLINK_GENL))]
mod genl_bridge {
    pub(crate) struct GenlGuard;

    impl GenlGuard {
        pub(crate) fn new() -> kernel::error::Result<Self> {
            Ok(Self)
        }
    }

    #[inline]
    pub(crate) fn notify_event(_event_type: u8, _handle: u16, _addr: &[u8; 6]) {}
}

// ---------------------------------------------------------------------------
// IOCTL definitions for the /dev/sparklink control interface
// ---------------------------------------------------------------------------

const SL_MAGIC: u32 = 'S' as u32;

/// Register a new virtual SCI device (for testing).
const SL_IOCTL_DEV_REGISTER: u32 = _IO(SL_MAGIC, 0x01);

/// Unregister a SCI device by index.
const SL_IOCTL_DEV_UNREGISTER: u32 = _IOW::<u16>(SL_MAGIC, 0x02);

/// Get the number of registered SCI devices.
const SL_IOCTL_DEV_COUNT: u32 = _IOR::<u32>(SL_MAGIC, 0x03);

/// Get device info by index.
const SL_IOCTL_DEV_INFO: u32 = _IOR::<SciDevInfo>(SL_MAGIC, 0x04);

/// Start SLE advertising (device discovery - discoverable side).
const SL_IOCTL_START_ADV: u32 = _IOW::<SleAdvParams>(SL_MAGIC, 0x10);

/// Stop SLE advertising.
const SL_IOCTL_STOP_ADV: u32 = _IO(SL_MAGIC, 0x11);

/// Start SLE scanning (device discovery - scanner side).
const SL_IOCTL_START_SCAN: u32 = _IOW::<SleScanParams>(SL_MAGIC, 0x12);

/// Stop SLE scanning.
const SL_IOCTL_STOP_SCAN: u32 = _IO(SL_MAGIC, 0x13);

/// Inject a simulated advertising PDU for loopback testing.
/// Userspace provides a SleInjectAdv struct; if in scanning state,
/// the PDU is processed as a received advertisement.
const SL_IOCTL_INJECT_ADV: u32 = _IOW::<SleInjectAdv>(SL_MAGIC, 0x20);

/// Get the current scan result count.
const SL_IOCTL_SCAN_RESULT_COUNT: u32 = _IO(SL_MAGIC, 0x21);

// --- Connection management ioctls ---

/// Initiate an SLE connection to a peer device.
/// Returns the connection handle (> 0) on success.
const SL_IOCTL_CONNECT: u32 = _IOW::<SleConnectParams>(SL_MAGIC, 0x30);

/// Disconnect from a peer by connection handle.
const SL_IOCTL_DISCONNECT: u32 = _IOW::<u16>(SL_MAGIC, 0x31);

/// Get connection status and statistics by handle.
const SL_IOCTL_CONN_INFO: u32 = _IOWR::<SleConnInfo>(SL_MAGIC, 0x32);

/// Send data on a connection identified by handle.
const SL_IOCTL_CONN_SEND: u32 = _IOW::<SleConnData>(SL_MAGIC, 0x33);

/// Receive data from a connection identified by handle.
const SL_IOCTL_CONN_RECV: u32 = _IOWR::<SleConnData>(SL_MAGIC, 0x34);

/// Inject a simulated access response for loopback testing.
const SL_IOCTL_INJECT_CONN_RESP: u32 = _IOW::<SleInjectConnResp>(SL_MAGIC, 0x35);

/// Inject simulated received data for loopback testing.
const SL_IOCTL_INJECT_CONN_DATA: u32 = _IOW::<SleConnData>(SL_MAGIC, 0x36);

/// Get number of active connections.
const SL_IOCTL_CONN_COUNT: u32 = _IO(SL_MAGIC, 0x37);

/// Get list of active connection handles.
const SL_IOCTL_CONN_LIST: u32 = _IOR::<SleConnList>(SL_MAGIC, 0x38);

// --- Security management ioctls ---

/// Set the pre-shared key for PSK pairing.
const SL_IOCTL_SEC_SET_PSK: u32 = _IOW::<SlePskParams>(SL_MAGIC, 0x40);

/// Start pairing (method specified in parameters).
const SL_IOCTL_SEC_PAIR: u32 = _IOW::<SlePairParams>(SL_MAGIC, 0x41);

/// Get security status and key fingerprint.
const SL_IOCTL_SEC_INFO: u32 = _IOR::<SleSecInfo>(SL_MAGIC, 0x42);

/// Enable encryption on the data path (requires Paired state).
const SL_IOCTL_SEC_ENCRYPT_ON: u32 = _IO(SL_MAGIC, 0x43);

/// SM3 hash test: compute SM3(data) and return digest.
const SL_IOCTL_SEC_SM3_TEST: u32 = _IOW::<SleHashTest>(SL_MAGIC, 0x44);

/// SM4 encrypt test: encrypt data in-place using session key.
const SL_IOCTL_SEC_SM4_ENC_TEST: u32 = _IOW::<SleConnData>(SL_MAGIC, 0x45);

/// SM4 decrypt test: decrypt data in-place using session key.
const SL_IOCTL_SEC_SM4_DEC_TEST: u32 = _IOW::<SleConnData>(SL_MAGIC, 0x46);

/// SM4 standalone block test: encrypt or decrypt one 16-byte block with explicit key.
const SL_IOCTL_SEC_SM4_BLOCK_TEST: u32 = _IOWR::<SleSm4BlockTest>(SL_MAGIC, 0x47);

/// HMAC-SM3 test: compute HMAC-SM3(key, data) and return digest.
const SL_IOCTL_SEC_HMAC_TEST: u32 = _IOWR::<SleHmacTest>(SL_MAGIC, 0x48);

// --- SSAP service layer ioctls ---

/// Register the built-in device info service.
const SL_IOCTL_SSAP_REGISTER_SVC: u32 = _IO(SL_MAGIC, 0x50);

/// Get SSAP service/property count summary.
const SL_IOCTL_SSAP_INFO: u32 = _IOR::<SsapSummary>(SL_MAGIC, 0x51);

/// Read a property by handle.
const SL_IOCTL_SSAP_READ: u32 = _IOWR::<SsapReadWrite>(SL_MAGIC, 0x52);

/// Write a property by handle.
const SL_IOCTL_SSAP_WRITE: u32 = _IOW::<SsapReadWrite>(SL_MAGIC, 0x53);

/// Find primary services.
const SL_IOCTL_SSAP_FIND_SVC: u32 = _IOR::<SsapServiceList>(SL_MAGIC, 0x54);

/// Send a notification for a property handle.
const SL_IOCTL_SSAP_NOTIFY: u32 = _IOW::<u16>(SL_MAGIC, 0x55);

/// Dequeue one pending notification.
const SL_IOCTL_SSAP_DEQUEUE_NTF: u32 = _IOR::<SsapNotification>(SL_MAGIC, 0x56);

/// Register a dynamic SSAP service from userspace.
const SL_IOCTL_SSAP_ADD_SVC: u32 = _IOWR::<SsapAddService>(SL_MAGIC, 0x57);

/// Add a property to the last registered service.
const SL_IOCTL_SSAP_ADD_PROP: u32 = _IOWR::<SsapAddProperty>(SL_MAGIC, 0x58);

/// Remove a service by its start handle.
const SL_IOCTL_SSAP_REMOVE_SVC: u32 = _IOW::<u16>(SL_MAGIC, 0x59);

// --- Power management ioctls ---

/// Get power management status.
const SL_IOCTL_PM_INFO: u32 = _IOR::<SlePmInfo>(SL_MAGIC, 0x60);

/// Set power state (Active/Sniff/Suspend/Resume).
const SL_IOCTL_PM_SET_STATE: u32 = _IOW::<SlePmStateCmd>(SL_MAGIC, 0x61);

/// Update connection interval parameters.
const SL_IOCTL_PM_SET_INTERVAL: u32 = _IOW::<SlePmInterval>(SL_MAGIC, 0x62);

/// Set force-active mode.
const SL_IOCTL_PM_FORCE_ACTIVE: u32 = _IOW::<u8>(SL_MAGIC, 0x63);

/// Simulate a connection event tick (for testing).
const SL_IOCTL_PM_TICK: u32 = _IO(SL_MAGIC, 0x64);

/// Record a data activity event.
const SL_IOCTL_PM_ACTIVITY: u32 = _IO(SL_MAGIC, 0x65);

/// Get number of pending events in the event queue.
const SL_IOCTL_EVENT_COUNT: u32 = _IO(SL_MAGIC, 0x70);

/// Get event queue lifetime statistics.
const SL_IOCTL_EVENT_STATS: u32 = _IOR::<SleEventStats>(SL_MAGIC, 0x71);

/// Get DLI controller information.
const SL_IOCTL_DLI_INFO: u32 = _IOR::<SleDliInfo>(SL_MAGIC, 0x80);

/// Get USB SLE device count (hardware discovery).
const SL_IOCTL_USB_DEV_COUNT: u32 = _IO(SL_MAGIC, 0x81);

/// Poll a DLI event from the controller.
const SL_IOCTL_DLI_POLL_EVENT: u32 = _IOR::<SleDliEvent>(SL_MAGIC, 0x82);

/// Reset the DLI controller.
const SL_IOCTL_DLI_RESET: u32 = _IO(SL_MAGIC, 0x83);

/// Send a DLI command to the controller (management plane).
const SL_IOCTL_DLI_SEND_CMD: u32 = _IOWR::<SleDliCmd>(SL_MAGIC, 0x84);

/// Get management plane pending queue statistics.
const SL_IOCTL_MGMT_STATS: u32 = _IOR::<SleMgmtStats>(SL_MAGIC, 0x85);

/// Get unified subsystem statistics (admin observability).
const SL_IOCTL_SUBSYS_STATS: u32 = _IOR::<SleSubsysStats>(SL_MAGIC, 0x86);

// --- PHY layer ioctls ---

/// Get PHY layer configuration.
const SL_IOCTL_PHY_INFO: u32 = _IOR::<SlePhyInfo>(SL_MAGIC, 0x90);

/// Set MCS index.
const SL_IOCTL_PHY_SET_MCS: u32 = _IOW::<SlePhyMcsCmd>(SL_MAGIC, 0x91);

/// Set TX power.
const SL_IOCTL_PHY_SET_TXPOWER: u32 = _IOW::<SlePhyTxPowerCmd>(SL_MAGIC, 0x92);

/// Select best MCS for given requirements.
const SL_IOCTL_PHY_MCS_SELECT: u32 = _IOWR::<SlePhyMcsSelect>(SL_MAGIC, 0x93);

/// Get frequency hopping next channel.
const SL_IOCTL_PHY_HOP_NEXT: u32 = _IOR::<SlePhyHopInfo>(SL_MAGIC, 0x94);

/// Set bandwidth.
const SL_IOCTL_PHY_SET_BW: u32 = _IOW::<SlePhyBwCmd>(SL_MAGIC, 0x95);

/// Set local GT node role (0=TNode, 1=GNode).
const SL_IOCTL_SET_ROLE: u32 = _IOW::<u8>(SL_MAGIC, 0xA0);

/// Get current local GT node role.
const SL_IOCTL_GET_ROLE: u32 = _IOR::<u8>(SL_MAGIC, 0xA1);

// ---------------------------------------------------------------------------
// SparkLink address (6 bytes, same as SLE MAC layer identifier)
// ---------------------------------------------------------------------------

/// SLE media access layer identifier, 6 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SleAddr {
    /// Raw 6-byte SLE address.
    pub b: [u8; 6],
}

// ---------------------------------------------------------------------------
// SCI device state machine
// ---------------------------------------------------------------------------

/// SCI device operating state.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub enum SciState {
    /// Device is registered but not active.
    #[default]
    Idle = 0,
    /// Device is advertising (discoverable).
    Advertising = 1,
    /// Device is scanning for other devices.
    Scanning = 2,
    /// Device has an active connection.
    Connected = 3,
}

// ---------------------------------------------------------------------------
// Discovery levels (T/XS 20001-2025 section 6.3.2)
// ---------------------------------------------------------------------------

/// Discovery level indicating the discoverability of the device.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub enum DiscoveryLevel {
    /// Not visible to any device.
    Invisible = 0,
    /// Generally discoverable by all devices.
    #[default]
    General = 1,
    /// Priority discoverable, faster detection.
    Priority = 2,
    /// Discoverable only by previously paired devices.
    PairedOnly = 3,
    /// Discoverable only by a specific designated device.
    Designated = 4,
}

// ---------------------------------------------------------------------------
// Userspace data structures (ioctl payloads)
// ---------------------------------------------------------------------------

/// Device information returned to userspace.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SciDevInfo {
    /// SCI device index.
    pub index: u16,
    /// Operating state (see `SciState`).
    pub state: u8,
    /// Transport bus type (see `SciBus`).
    pub bus: u8,
    /// SLE address.
    pub addr: SleAddr,
    /// Device name (UTF-8, null-padded).
    pub name: [u8; 32],
    _reserved: [u8; 24],
}

/// SLE advertising parameters.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SleAdvParams {
    /// Target SCI device index.
    pub dev_index: u16,
    /// Advertising interval in milliseconds.
    pub interval_ms: u16,
    /// Discovery level (see `DiscoveryLevel`).
    pub discovery_level: u8,
    _reserved: [u8; 11],
}

// SAFETY: SleAdvParams is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleAdvParams {}

/// SLE scanning parameters.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SleScanParams {
    /// Target SCI device index.
    pub dev_index: u16,
    /// Scan window in milliseconds.
    pub window_ms: u16,
    /// Scan interval in milliseconds.
    pub interval_ms: u16,
    /// Minimum discovery level to accept.
    pub filter_discovery_level: u8,
    _reserved: [u8; 9],
}

// SAFETY: SleScanParams is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleScanParams {}

/// Injected advertising data for loopback testing.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleInjectAdv {
    /// Simulated source SLE address.
    pub addr: [u8; 6],
    /// Simulated RSSI.
    pub rssi: i8,
    /// Discovery level to include in the advertising data.
    pub discovery_level: u8,
    /// Device name (UTF-8, null-terminated).
    pub name: [u8; 32],
    /// Name length.
    pub name_len: u8,
    _reserved: [u8; 7],
}

impl Default for SleInjectAdv {
    fn default() -> Self {
        Self {
            addr: [0u8; 6],
            rssi: -50,
            discovery_level: 1,
            name: [0u8; 32],
            name_len: 0,
            _reserved: [0u8; 7],
        }
    }
}

// SAFETY: SleInjectAdv is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleInjectAdv {}

// ---------------------------------------------------------------------------
// Connection management userspace data structures
// ---------------------------------------------------------------------------

/// Connection request parameters from userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleConnectParams {
    /// Target peer SLE address (6 bytes).
    pub peer_addr: [u8; 6],
    /// Desired GT role: 0=T node, 1=G node.
    pub gt_role: u8,
    /// Preferred bandwidth in MHz (1, 2, or 4).
    pub bandwidth: u8,
    /// Preferred MCS index (0-12).
    pub mcs_index: u8,
    _pad: u8,
    /// Supervision timeout in 10 ms units.
    pub timeout_10ms: u16,
    _reserved: [u8; 4],
}

impl Default for SleConnectParams {
    fn default() -> Self {
        Self {
            peer_addr: [0u8; 6],
            gt_role: 0,
            bandwidth: 1,
            mcs_index: 4,
            _pad: 0,
            timeout_10ms: 100,
            _reserved: [0u8; 4],
        }
    }
}

// SAFETY: SleConnectParams is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleConnectParams {}

/// Connection status and statistics returned to userspace.
///
/// Layout is ordered to avoid implicit padding: u64 fields first,
/// then u16, then u8 — no gaps between fields.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleConnInfo {
    /// Total bytes transmitted.
    pub tx_bytes: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// Connection handle.
    pub handle: u16,
    /// Event group period in scheduling slots.
    pub event_group_period: u16,
    /// Supervision timeout in 10 ms units.
    pub supervision_timeout: u16,
    /// Pending TX queue depth.
    pub tx_pending: u16,
    /// Pending RX queue depth.
    pub rx_pending: u16,
    /// Connection state (see ConnState).
    pub state: u8,
    /// Peer SLE address.
    pub peer_addr: [u8; 6],
    /// Local GT role: 0=T, 1=G.
    pub local_role: u8,
    /// Negotiated bandwidth in MHz.
    pub bandwidth_mhz: u8,
    /// Negotiated MCS index.
    pub mcs_index: u8,
    /// Current TX sequence number.
    pub tx_seq: u8,
    /// Current RX sequence number.
    pub rx_seq: u8,
    _reserved: [u8; 10],
}

// SAFETY: SleConnInfo is repr(C) with only primitive fields.
unsafe impl FromBytes for SleConnInfo {}

/// Data buffer for connection send/receive ioctls.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleConnData {
    /// Connection handle (0 = first active connection).
    pub handle: u16,
    /// Data payload length in bytes.
    pub length: u16,
    /// Data payload.
    pub data: [u8; 255],
    _reserved: u8,
}

impl Default for SleConnData {
    fn default() -> Self {
        Self {
            handle: 0,
            length: 0,
            data: [0u8; 255],
            _reserved: 0,
        }
    }
}

// SAFETY: SleConnData is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleConnData {}

/// Injected connection response for loopback testing.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleInjectConnResp {
    /// Connection handle to inject response for.
    pub handle: u16,
    /// Response type (0=accepted, 1=role fail, 2=resource, 3=rejected).
    pub response_type: u8,
    /// Bandwidth in MHz for the accepted connection.
    pub bandwidth_mhz: u8,
    /// MCS index for the accepted connection.
    pub mcs_index: u8,
    _pad: u8,
    /// Supervision timeout in 10 ms units.
    pub supervision_timeout: u16,
}

impl Default for SleInjectConnResp {
    fn default() -> Self {
        Self {
            handle: 0,
            response_type: 0,
            bandwidth_mhz: 1,
            mcs_index: 4,
            _pad: 0,
            supervision_timeout: 100,
        }
    }
}

// SAFETY: SleInjectConnResp is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleInjectConnResp {}

/// List of active connection handles returned from CONN_LIST.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleConnList {
    /// Number of active handles in the list.
    pub count: u16,
    _pad: u16,
    /// Up to 8 active connection handles.
    pub handles: [u16; 8],
    _reserved: [u8; 4],
}

// ---------------------------------------------------------------------------
// Security management userspace data structures
// ---------------------------------------------------------------------------

/// Pre-shared key for PSK pairing.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlePskParams {
    /// 128-bit pre-shared key.
    pub psk: [u8; 16],
}

// SAFETY: SlePskParams is repr(C) with only primitive fields.
unsafe impl FromBytes for SlePskParams {}

/// Pairing request parameters.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlePairParams {
    /// Pairing method: 1=JustWorks, 2=PSK.
    pub method: u8,
    _reserved: [u8; 3],
}

// SAFETY: SlePairParams is repr(C) with only primitive fields.
unsafe impl FromBytes for SlePairParams {}

/// Security status returned to userspace.
///
/// Layout avoids implicit padding: all fields are u8 or u8 arrays.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleSecInfo {
    /// Security state (SecurityState).
    pub state: u8,
    /// Pairing method (PairingMethod).
    pub method: u8,
    /// Security mode (SecurityMode).
    pub mode: u8,
    /// Whether encryption is currently active.
    pub enc_enabled: u8,
    /// First 4 bytes of SM3(enc_key) for fingerprint verification.
    pub enc_key_fingerprint: [u8; 4],
    _reserved: [u8; 8],
}

/// SM3 hash test request/response.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleHashTest {
    /// Input data length (max 220).
    pub in_len: u16,
    /// Padding.
    _pad: u16,
    /// Input data buffer.
    pub data: [u8; 220],
    /// Output SM3 digest (32 bytes).
    pub digest: [u8; 32],
}

// SAFETY: SleHashTest is repr(C) with only primitive fields.
unsafe impl FromBytes for SleHashTest {}

/// SM4 standalone block encrypt/decrypt test.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleSm4BlockTest {
    /// 128-bit key.
    pub key: [u8; 16],
    /// 16-byte input block.
    pub input: [u8; 16],
    /// 16-byte output block (filled by kernel).
    pub output: [u8; 16],
    /// 0 = encrypt, 1 = decrypt.
    pub decrypt: u8,
    _pad: [u8; 15],
}

// SAFETY: SleSm4BlockTest is repr(C) with only primitive fields.
unsafe impl FromBytes for SleSm4BlockTest {}

/// HMAC-SM3 standalone test.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleHmacTest {
    /// HMAC key length (max 64).
    pub key_len: u16,
    /// Input data length (max 160).
    pub data_len: u16,
    /// HMAC key.
    pub key: [u8; 64],
    /// Input data.
    pub data: [u8; 160],
    /// Output HMAC-SM3 digest (32 bytes, filled by kernel).
    pub digest: [u8; 32],
}

// SAFETY: SleHmacTest is repr(C) with only primitive fields.
unsafe impl FromBytes for SleHmacTest {}

// ---------------------------------------------------------------------------
// SSAP service layer userspace data structures
// ---------------------------------------------------------------------------

/// SSAP summary info returned to userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SsapSummary {
    /// Number of registered services.
    pub service_count: u16,
    /// Total number of properties across all services.
    pub property_count: u16,
    /// Total SSAP entries (services + properties + methods + events).
    pub total_entries: u16,
    /// Negotiated MTU.
    pub mtu: u16,
    /// Pending notification count.
    pub notification_count: u16,
    _reserved: [u8; 6],
}

/// SSAP read/write payload for property access.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SsapReadWrite {
    /// Property handle.
    pub handle: u16,
    /// Data length in bytes.
    pub length: u16,
    /// Data buffer (max 252 bytes).
    pub data: [u8; 252],
}

// SAFETY: SsapReadWrite is repr(C) with only primitive fields.
unsafe impl FromBytes for SsapReadWrite {}

/// Service entry in the discovery result list.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SsapServiceEntry {
    /// Service start handle.
    pub start_handle: u16,
    /// Service end handle.
    pub end_handle: u16,
    /// Service UUID (16-bit; 0 if 128-bit).
    pub uuid16: u16,
    /// Whether primary service.
    pub primary: u8,
    _pad: u8,
}

/// Service list returned from FIND_SVC.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SsapServiceList {
    /// Number of services in the list.
    pub count: u16,
    _pad: [u8; 2],
    /// Up to 15 services.
    pub services: [SsapServiceEntry; 15],
}

/// Dequeued notification/indication payload.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SsapNotification {
    /// Property handle that generated the notification.
    pub handle: u16,
    /// 1 = indication, 0 = notification.
    pub indication: u8,
    /// Data length.
    pub length: u8,
    /// Notification data (max 252 bytes).
    pub data: [u8; 252],
}

/// Dynamic SSAP service registration from userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SsapAddService {
    /// Service UUID (16-bit, or 0 for 128-bit specified in uuid128).
    pub uuid16: u16,
    /// Whether primary (1) or secondary (0) service.
    pub primary: u8,
    _pad: u8,
    /// 128-bit UUID (used when uuid16 == 0).
    pub uuid128: [u8; 16],
    /// Output: assigned start handle.
    pub start_handle: u16,
    _reserved: [u8; 6],
}

// SAFETY: SsapAddService is repr(C) with only primitive fields.
unsafe impl FromBytes for SsapAddService {}

/// Add a property to the last registered SSAP service.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SsapAddProperty {
    /// Property UUID (16-bit).
    pub uuid16: u16,
    /// Operation indicator bitmask (bit0=Read, bit1=Write, bit2=Notify, etc.).
    pub ops: u8,
    /// Length of initial value data.
    pub value_len: u8,
    /// Initial value data (max 248 bytes).
    pub value: [u8; 248],
    /// Output: assigned property handle.
    pub handle: u16,
    _reserved: [u8; 2],
}

// SAFETY: SsapAddProperty is repr(C) with only primitive fields.
unsafe impl FromBytes for SsapAddProperty {}

// ---------------------------------------------------------------------------
// Power management userspace data structures
// ---------------------------------------------------------------------------

/// Power management status info returned to userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlePmInfo {
    /// Current power state (0=Active, 1=Sniff, 2=Idle, 3=Suspended).
    pub state: u8,
    /// Whether force-active is enabled.
    pub force_active: u8,
    /// Estimated power consumption percentage (0-100).
    pub power_pct: u8,
    _pad: u8,
    /// Current connection interval in 1.25 ms units.
    pub current_interval: u16,
    /// Supervision timeout in 10 ms units.
    pub supervision_timeout: u16,
    /// Peripheral latency.
    pub latency: u16,
    /// Idle event count since last activity.
    pub idle_count: u16,
    /// Total state transitions.
    pub transitions: u32,
    /// Active events count.
    pub active_events: u64,
    /// Sniff events count.
    pub sniff_events: u64,
    /// Idle events count.
    pub idle_events: u64,
    _reserved: [u8; 8],
}

/// Power state command.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlePmStateCmd {
    /// Target state: 0=Active, 1=Sniff, 3=Suspend.
    pub target_state: u8,
    _reserved: [u8; 3],
}

// SAFETY: SlePmStateCmd is repr(C) with only primitive fields.
unsafe impl FromBytes for SlePmStateCmd {}

/// Connection interval parameters from userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlePmInterval {
    /// Minimum interval in 1.25 ms units.
    pub min_interval: u16,
    /// Maximum interval in 1.25 ms units.
    pub max_interval: u16,
    /// Peripheral latency.
    pub latency: u16,
    /// Supervision timeout in 10 ms units.
    pub supervision_timeout: u16,
}

// SAFETY: SlePmInterval is repr(C) with only primitive fields.
unsafe impl FromBytes for SlePmInterval {}

// ---------------------------------------------------------------------------
// Event queue statistics
// ---------------------------------------------------------------------------

/// Lifetime statistics for the event queue.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SleEventStats {
    /// Number of events currently pending.
    pub pending: u32,
    _pad: u32,
    /// Total events enqueued (lifetime).
    pub total_enqueued: u64,
    /// Total events dropped (queue full).
    pub total_dropped: u64,
    /// Total events delivered to userspace.
    pub total_delivered: u64,
}

// ---------------------------------------------------------------------------
// DLI controller information
// ---------------------------------------------------------------------------

/// DLI controller information returned to userspace.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SleDliInfo {
    /// Bus type (0=Virtual, 1=UART, 2=USB, 3=SDIO).
    pub bus: u8,
    _pad: [u8; 3],
    /// Firmware version (major.minor.patch packed as u32).
    pub firmware_version: u32,
    /// Supported feature bitmask (TXS-10003-2025).
    pub features: u64,
    /// Maximum simultaneous connections.
    pub max_connections: u8,
    /// Maximum advertising sets.
    pub max_adv_sets: u8,
    /// Supported transport modes (bitmask).
    pub transport_modes: u8,
    /// Measurement capabilities (bitmask).
    pub measurement_cap: u8,
    /// Maximum MTU the controller supports.
    pub max_mtu: u16,
    /// Maximum payload segment size per single TX.
    pub max_mps: u16,
    /// Security capabilities (bitmask).
    pub security_cap: u16,
    /// Controller name (null-terminated).
    pub name: [u8; 32],
    _reserved: [u8; 6],
}

/// DLI event returned to userspace via DLI_POLL_EVENT ioctl.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleDliEvent {
    /// Event type discriminator.
    pub event_type: u8,
    /// Status code (0 = success).
    pub status: u8,
    /// Associated connection handle (if any).
    pub handle: u16,
    /// Opcode that triggered this event (for CommandComplete/Status).
    pub opcode: u16,
    /// Payload length.
    pub data_len: u16,
    /// Event payload.
    pub data: [u8; 240],
    /// Associated address (for conn/adv events).
    pub addr: [u8; 6],
    _pad: [u8; 2],
}

impl Default for SleDliEvent {
    fn default() -> Self {
        // SAFETY: SleDliEvent is repr(C) with all primitive fields; zeroed is valid.
        unsafe { core::mem::zeroed() }
    }
}

/// DLI command sent to the controller via DLI_SEND_CMD ioctl.
///
/// On input: opcode + params. On output: seq (assigned sequence number)
/// so userspace can track the pending command.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleDliCmd {
    /// DLI opcode (OGF|OCF).
    pub opcode: u16,
    /// Parameter length.
    pub param_len: u16,
    /// Assigned sequence number (output, filled by kernel).
    pub seq: u32,
    /// Command parameters.
    pub params: [u8; 240],
}

impl Default for SleDliCmd {
    fn default() -> Self {
        // SAFETY: repr(C) with primitive fields.
        unsafe { core::mem::zeroed() }
    }
}

// SAFETY: SleDliCmd is repr(C) with only primitive fields.
unsafe impl FromBytes for SleDliCmd {}

/// Management plane pending queue statistics.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SleMgmtStats {
    /// Currently pending (unresolved) commands.
    pub pending: u16,
    _pad: u16,
    /// Total commands submitted.
    pub total_submitted: u32,
    /// Total commands resolved (complete or timeout).
    pub total_resolved: u32,
    /// Total command timeouts.
    pub total_timeouts: u32,
}

// SAFETY: SleMgmtStats is repr(C) with only primitive fields.
unsafe impl FromBytes for SleMgmtStats {}

/// Unified subsystem statistics for observability.
///
/// Returned by the SUBSYS_STATS ioctl (0x86). Aggregates key counters
/// from the management plane, connection manager, power manager,
/// device registry, and transport framework into a single read.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SleSubsysStats {
    /// Number of registered devices in the SleDev registry.
    pub dev_count: u16,
    /// Number of registered transport protocols.
    pub proto_count: u8,
    /// Number of active device-transport bindings.
    pub binding_count: u8,
    /// Active connections.
    pub active_connections: u16,
    /// Management plane pending commands.
    pub mgmt_pending: u16,
    /// Total connections created (lifetime).
    pub total_conn_created: u32,
    /// Total connections completed (lifetime).
    pub total_conn_completed: u32,
    /// Total management commands submitted (lifetime).
    pub total_mgmt_submitted: u32,
    /// Total management command timeouts.
    pub total_mgmt_timeouts: u32,
    /// Power state (0=Active, 1=Sniff, 2=Idle, 3=Suspended).
    pub power_state: u8,
    _pad: [u8; 3],
    /// Power state transitions.
    pub power_transitions: u32,
}

// SAFETY: SleSubsysStats is repr(C) with only primitive fields.
unsafe impl FromBytes for SleSubsysStats {}

fn sle_dli_event_to_wire(ev: &sle_dli::SleEvent) -> SleDliEvent {
    let mut out = SleDliEvent::default();
    match ev {
        sle_dli::SleEvent::CommandComplete { opcode, status, data } => {
            out.event_type = 0x01;
            out.status = *status as u8;
            out.opcode = *opcode as u16;
            let len = data.len().min(240);
            out.data_len = len as u16;
            out.data[..len].copy_from_slice(&data[..len]);
        }
        sle_dli::SleEvent::CommandStatus { opcode, status } => {
            out.event_type = 0x02;
            out.status = *status as u8;
            out.opcode = *opcode as u16;
        }
        sle_dli::SleEvent::AdvReport { addr, rssi, discovery_level, data } => {
            out.event_type = 0x03;
            out.addr = *addr;
            out.data[0] = *rssi as u8;
            out.data[1] = *discovery_level;
            let len = data.len().min(238);
            out.data_len = (len + 2) as u16;
            out.data[2..2 + len].copy_from_slice(&data[..len]);
        }
        sle_dli::SleEvent::ConnComplete { handle, addr, status } => {
            out.event_type = 0x04;
            out.handle = *handle;
            out.addr = *addr;
            out.status = *status as u8;
        }
        sle_dli::SleEvent::DataReceived { handle, data } => {
            out.event_type = 0x05;
            out.handle = *handle;
            let len = data.len().min(240);
            out.data_len = len as u16;
            out.data[..len].copy_from_slice(&data[..len]);
        }
        sle_dli::SleEvent::Disconnected { handle, reason } => {
            out.event_type = 0x06;
            out.handle = *handle;
            out.data[0] = *reason;
            out.data_len = 1;
        }
        sle_dli::SleEvent::EncryptionChanged { handle, enabled } => {
            out.event_type = 0x07;
            out.handle = *handle;
            out.data[0] = if *enabled { 1 } else { 0 };
            out.data_len = 1;
        }
        sle_dli::SleEvent::PairRequest { addr, method } => {
            out.event_type = 0x08;
            out.addr = *addr;
            out.data[0] = *method;
            out.data_len = 1;
        }
        sle_dli::SleEvent::HardwareError { code } => {
            out.event_type = 0x09;
            out.data[0] = *code;
            out.data_len = 1;
        }
        sle_dli::SleEvent::BroadcastEnd { reason } => {
            out.event_type = 0x0A;
            out.data[0] = *reason;
            out.data_len = 1;
        }
        sle_dli::SleEvent::PhyUpdate { handle, mcs_index, bandwidth_mhz } => {
            out.event_type = 0x0B;
            out.handle = *handle;
            out.data[0] = *mcs_index;
            out.data[1] = *bandwidth_mhz;
            out.data_len = 2;
        }
        sle_dli::SleEvent::ConnParamUpdate { handle, interval, latency, timeout } => {
            out.event_type = 0x0C;
            out.handle = *handle;
            out.data[0] = (*interval & 0xFF) as u8;
            out.data[1] = (*interval >> 8) as u8;
            out.data[2] = (*latency & 0xFF) as u8;
            out.data[3] = (*latency >> 8) as u8;
            out.data[4] = (*timeout & 0xFF) as u8;
            out.data[5] = (*timeout >> 8) as u8;
            out.data_len = 6;
        }
        sle_dli::SleEvent::DataLenChange { handle, max_tx_octets, max_rx_octets } => {
            out.event_type = 0x0D;
            out.handle = *handle;
            out.data[0] = (*max_tx_octets & 0xFF) as u8;
            out.data[1] = (*max_tx_octets >> 8) as u8;
            out.data[2] = (*max_rx_octets & 0xFF) as u8;
            out.data[3] = (*max_rx_octets >> 8) as u8;
            out.data_len = 4;
        }
        sle_dli::SleEvent::DataBufOverflow { link_type } => {
            out.event_type = 0x0E;
            out.data[0] = *link_type;
            out.data_len = 1;
        }
        sle_dli::SleEvent::PeerConnParamReq { handle, interval_min, interval_max, latency, timeout } => {
            out.event_type = 0x0F;
            out.handle = *handle;
            out.data[0] = (*interval_min & 0xFF) as u8;
            out.data[1] = (*interval_min >> 8) as u8;
            out.data[2] = (*interval_max & 0xFF) as u8;
            out.data[3] = (*interval_max >> 8) as u8;
            out.data[4] = (*latency & 0xFF) as u8;
            out.data[5] = (*latency >> 8) as u8;
            out.data[6] = (*timeout & 0xFF) as u8;
            out.data[7] = (*timeout >> 8) as u8;
            out.data_len = 8;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// PHY layer ioctl structures
// ---------------------------------------------------------------------------

/// PHY layer information returned to userspace.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SlePhyInfo {
    /// Current MCS index (0-12).
    pub mcs_index: u8,
    /// Bandwidth in MHz (1, 2, or 4).
    pub bandwidth_mhz: u8,
    /// Pilot density (0=4:1, 1=8:1, 2=16:1, 3=none).
    pub pilot_density: u8,
    /// TX power in dBm (signed).
    pub tx_power_dbm: i8,
    /// MIMO mode (0=SISO, 1=SpatialMux2x2, ...).
    pub mimo_mode: u8,
    /// Number of TX antennas.
    pub num_tx_ant: u8,
    /// Number of RX antennas.
    pub num_rx_ant: u8,
    /// Whether OFDM is used for current MCS.
    pub ofdm: u8,
    /// Effective data rate in kbps.
    pub data_rate_kbps: u32,
    /// Current frequency hopping channel.
    pub hop_channel: u8,
    /// Hopping increment.
    pub hop_increment: u8,
    /// Number of used hopping channels.
    pub hop_used_channels: u8,
    _pad: u8,
    /// Modulation type for current MCS.
    pub modulation: u8,
    /// Code rate numerator.
    pub code_rate_num: u8,
    /// Code rate denominator.
    pub code_rate_den: u8,
    _reserved: [u8; 5],
}

/// Set MCS index command.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SlePhyMcsCmd {
    /// MCS index (0-12).
    pub mcs_index: u8,
    _reserved: [u8; 3],
}

/// Set TX power command.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SlePhyTxPowerCmd {
    /// TX power in dBm.
    pub tx_power_dbm: i8,
    _reserved: [u8; 3],
}

/// MCS selection request/response.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SlePhyMcsSelect {
    /// Input: minimum required data rate in kbps.
    pub min_kbps: u32,
    /// Output: effective data rate in kbps.
    pub effective_kbps: u32,
    /// Input: available SINR in dB x10 (signed).
    pub sinr_db_x10: i16,
    /// Input: bandwidth in MHz.
    pub bandwidth_mhz: u8,
    /// Output: selected MCS index.
    pub selected_mcs: u8,
}

/// Frequency hopping channel info.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SlePhyHopInfo {
    /// Channel index (0-78).
    pub channel: u8,
    _pad: u8,
    /// RF frequency in MHz.
    pub freq_mhz: u16,
    /// Event counter after hop.
    pub event_counter: u16,
    _reserved: [u8; 2],
}

/// Set bandwidth command.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SlePhyBwCmd {
    /// Bandwidth in MHz (1, 2, or 4).
    pub bandwidth_mhz: u8,
    _reserved: [u8; 3],
}

// SAFETY: All PHY ioctl structs are repr(C) with only primitive fields.
unsafe impl FromBytes for SlePhyInfo {}
unsafe impl FromBytes for SlePhyMcsCmd {}
unsafe impl FromBytes for SlePhyTxPowerCmd {}
unsafe impl FromBytes for SlePhyMcsSelect {}
unsafe impl FromBytes for SlePhyHopInfo {}
unsafe impl FromBytes for SlePhyBwCmd {}

// ---------------------------------------------------------------------------
// SCI bus types
// ---------------------------------------------------------------------------

/// Transport bus type for the SCI device.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
pub enum SciBus {
    /// Virtual controller (for testing).
    #[default]
    Virtual = 0,
    /// UART-attached controller.
    Uart = 1,
    /// USB-attached controller.
    Usb = 2,
    /// SDIO-attached controller.
    Sdio = 3,
}

// ---------------------------------------------------------------------------
// Global shared subsystem state
// ---------------------------------------------------------------------------
// The SparkLink subsystem uses a single shared controller and protocol state
// that is shared across all open file descriptors.  Each fd gets its own
// event queue for per-listener event delivery, but the radio controller,
// connection table, advertising state, PHY config, security context, SSAP
// services, and power management are shared.
//
// This matches the hardware model: there is one physical radio, one set of
// connections, one advertising state.  Multiple userspace processes opening
// /dev/sparklink see the SAME radio and connection table.

kernel::sync::global_lock! {
    // SAFETY: Initialized in module_init before any MiscDevice open() call.
    unsafe(uninit) static SUBSYSTEM: Mutex<Option<SubsystemShared>> = None;
}

/// Number of currently open file descriptors.
static OPEN_FD_COUNT: kernel::sync::atomic::Atomic<u32> =
    kernel::sync::atomic::Atomic::new(0);

/// DLI event ring size (events consumed from controller by EventPump).
const DLI_RING_SIZE: usize = 32;

/// Shared state across all open file descriptors.
/// Protected by the SUBSYSTEM global mutex.
struct SubsystemShared {
    controller: sle_dli::ControllerBackend,
    conn: ConnManager,
    adv_scan: AdvScanInner,
    security: SecurityInner,
    ssap: SsapInner,
    power: PowerInner,
    phy: sle_phy::PhyConfig,
    local_role: GtRole,
    /// Global event broadcast ring for multi-listener delivery.
    broadcast: sle_event::BroadcastRing,
    /// DLI event ring for DLI_POLL_EVENT ioctl. Events consumed from the
    /// controller by the EventPump are stored here so DLI_POLL_EVENT has
    /// a deterministic source separate from the controller queue.
    dli_ring: [SleDliEvent; DLI_RING_SIZE],
    dli_head: usize,
    dli_tail: usize,
    /// Background event pump handle. Kept alive while subsystem is active.
    _event_pump: Option<Arc<EventPump>>,
    /// Background command worker handle.
    _cmd_worker: Option<Arc<CommandWorker>>,
    /// Per-controller device registry.
    dev_registry: sle_dev::SleDevRegistry,
    /// Index of the active device in the registry (`None` = no controller).
    active_dev_id: Option<u16>,
    /// Command pending queue for management plane.
    cmd_pending: sle_mgmt::CmdPendingQueue,
    /// Outgoing command request queue (async dispatch).
    cmd_queue: sle_mgmt::CmdRequestQueue,
    /// Transport protocol registry (H4, USB, SPI, virtual).
    proto_registry: sle_transport::SleProtoRegistry,
    /// Device-to-transport binding table.
    dev_bindings: sle_transport::SleBindingTable,
}

impl SubsystemShared {
    fn push_dli_event(&mut self, ev: SleDliEvent) {
        self.dli_ring[self.dli_tail] = ev;
        self.dli_tail = (self.dli_tail + 1) % DLI_RING_SIZE;
        if self.dli_tail == self.dli_head {
            // Ring full: drop oldest entry.
            self.dli_head = (self.dli_head + 1) % DLI_RING_SIZE;
        }
    }

    fn pop_dli_event(&mut self) -> Option<SleDliEvent> {
        if self.dli_head == self.dli_tail {
            return None;
        }
        let ev = self.dli_ring[self.dli_head];
        self.dli_head = (self.dli_head + 1) % DLI_RING_SIZE;
        Some(ev)
    }
}

// ---------------------------------------------------------------------------
// Transport device attach / detach (called from driver probe/remove)
// ---------------------------------------------------------------------------

/// Attach a newly-discovered physical device to the subsystem.
///
/// Called from USB probe, serdev probe, or any other transport driver's
/// hardware enumeration callback. Allocates a `SleDev` in the global
/// registry, creates a transport binding, and logs the attachment.
///
/// Returns the allocated device id on success.
pub(crate) fn sle_attach_device(info: &sle_transport::SleAttachInfo) -> Result<u16> {
    let mut ss = SUBSYSTEM.lock();
    let ss = ss.as_mut().ok_or(ENODEV)?;

    // Look up the protocol to get bus type and defaults.
    let proto = ss.proto_registry.get(info.proto_id).ok_or(EINVAL)?;
    let bus = proto.bus;
    let default_pdu = proto.max_pdu;

    // Build a SleControllerInfo for device registration.
    let mut ctrl_info = sle_dli::SleControllerInfo::default();
    ctrl_info.bus = bus;
    ctrl_info.addr = info.addr;
    ctrl_info.fw_version = info.fw_version;
    ctrl_info.features = info.features;
    ctrl_info.max_pdu_payload = if info.max_pdu > 0 { info.max_pdu } else { default_pdu };
    ctrl_info.max_connections = if info.max_connections > 0 {
        info.max_connections
    } else {
        8
    };
    let proto_name = proto.name;
    let name_bytes = proto_name.as_bytes();
    let copy_len = name_bytes.len().min(ctrl_info.name.len());
    ctrl_info.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // Register in the SleDev registry.
    let dev_id = ss.dev_registry.register(&ctrl_info)?;

    // Create the transport binding.
    let binding = sle_transport::SleDevBinding {
        dev_id,
        proto_id: info.proto_id,
        opened: false,
    };
    if let Err(e) = ss.dev_bindings.insert(binding) {
        let _ = ss.dev_registry.unregister(dev_id);
        return Err(e);
    }

    pr_info!(
        "sparklink: device sle{} attached via {} [{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}]\n",
        dev_id,
        proto_name,
        info.addr[0], info.addr[1], info.addr[2],
        info.addr[3], info.addr[4], info.addr[5],
    );

    Ok(dev_id)
}

/// Detach a device from the subsystem.
///
/// Called from USB disconnect, serdev remove, or module unload cleanup.
/// Removes the transport binding and unregisters the SleDev.
pub(crate) fn sle_detach_device(dev_id: u16) {
    let mut ss = SUBSYSTEM.lock();
    if let Some(ss) = ss.as_mut() {
        // Remove the transport binding first.
        ss.dev_bindings.remove(dev_id);

        // If this was the active device, clear the active pointer
        // and revert controller to Virtual backend.
        if ss.active_dev_id == Some(dev_id) {
            ss.active_dev_id = None;
            let virt_addr = [0x5E, 0x00, 0x00, 0x00, 0x00, 0x00];
            ss.controller = sle_dli::ControllerBackend::new_virtual(virt_addr);
            pr_info!("sparklink: reverted to virtual controller\n");
        }

        // Unregister the device from the registry.
        let _ = ss.dev_registry.unregister(dev_id);

        pr_info!("sparklink: device sle{} detached\n", dev_id);
    }
}

/// Switch the subsystem controller backend to USB.
///
/// Called from USB probe after sle_attach_device and C-side registration
/// succeed. This replaces the current controller (typically Virtual) with
/// a USB controller that dispatches commands through the C FFI layer.
pub(crate) fn sle_switch_controller_usb(dev_id: u16, addr: [u8; 6], fw_version: u32) {
    let mut ss = SUBSYSTEM.lock();
    if let Some(ss) = ss.as_mut() {
        ss.controller = sle_dli::ControllerBackend::new_usb(addr, dev_id);
        ss.active_dev_id = Some(dev_id);
        // Sync device model with real hardware info from probe.
        let _ = ss.dev_registry.update_hw_info(dev_id, addr, fw_version);
        pr_info!(
            "sparklink: controller switched to USB (sle{})\n",
            dev_id
        );
    }
}

/// Suspend the active device's power state.
///
/// Called from USB suspend to transition the power manager to Suspended.
pub(crate) fn sle_suspend_device(dev_id: u16) {
    let mut ss = SUBSYSTEM.lock();
    if let Some(ss) = ss.as_mut() {
        if ss.active_dev_id == Some(dev_id) {
            let _ = ss.power.suspend();
        }
    }
}

/// Resume the active device's power state.
///
/// Called from USB resume to transition the power manager back to Active.
pub(crate) fn sle_resume_device(dev_id: u16) {
    let mut ss = SUBSYSTEM.lock();
    if let Some(ss) = ss.as_mut() {
        if ss.active_dev_id == Some(dev_id) {
            ss.power.resume();
        }
    }
}

/// Switch the subsystem controller backend to Serdev (UART).
///
/// Called from serdev probe after sle_attach_device and C-side registration
/// succeed.
pub(crate) fn sle_switch_controller_serdev(dev_id: u16, addr: [u8; 6], fw_version: u32) {
    let mut ss = SUBSYSTEM.lock();
    if let Some(ss) = ss.as_mut() {
        ss.controller = sle_dli::ControllerBackend::new_serdev(addr, dev_id);
        ss.active_dev_id = Some(dev_id);
        // Sync device model with real hardware info from probe.
        let _ = ss.dev_registry.update_hw_info(dev_id, addr, fw_version);
        pr_info!(
            "sparklink: controller switched to serdev (sle{})\n",
            dev_id
        );
    }
}

// ---------------------------------------------------------------------------
// Background event pump
// ---------------------------------------------------------------------------

/// Interval between event pump polls (milliseconds).
const EVENT_PUMP_INTERVAL_MS: u32 = 100;

/// Background worker that periodically polls the controller for DLI events
/// and publishes them to the global broadcast ring.
///
/// Without this, DLI events are only consumed when userspace calls the
/// DLI_POLL_EVENT ioctl — an active polling model. The event pump turns
/// this into passive delivery: events flow into the broadcast ring
/// automatically, and per-fd readers pick them up on their next poll/read.
#[pin_data]
struct EventPump {
    #[pin]
    work: DelayedWork<EventPump>,
}

impl_has_delayed_work! {
    impl HasDelayedWork<Self> for EventPump { self.work }
}

// ---------------------------------------------------------------------------
// Unified controller event processing
// ---------------------------------------------------------------------------

/// Process a single controller event: resolve pending commands, drive
/// state machine transitions, and publish to broadcast ring / DLI ring.
///
/// Called from both `EventPump` (periodic background) and inline after
/// ioctl commands (immediate drain for synchronous controller backends
/// like VirtualController).
fn process_controller_event(shared: &mut SubsystemShared, ev: &sle_dli::SleEvent) {
    // 1. Resolve pending management commands.
    match ev {
        sle_dli::SleEvent::CommandComplete { opcode, status, data } => {
            shared.cmd_pending.resolve(*opcode as u16, *status as u8, data.as_slice());
        }
        sle_dli::SleEvent::CommandStatus { opcode, status } => {
            shared.cmd_pending.resolve(*opcode as u16, *status as u8, &[]);
        }
        _ => {}
    }

    // 2. Drive pending state machine transitions (DLI async confirmation).
    match ev {
        sle_dli::SleEvent::CommandComplete { opcode, status, .. } => {
            match opcode {
                sle_dli::SleOpcode::EnableBroadcast => {
                    if *status == sle_dli::SleStatus::Success {
                        shared.adv_scan.confirm_advertising();
                        if let Some(dev) = shared.active_dev_id.and_then(|id| shared.dev_registry.get(id)) {
                            dev.set_flag(sle_dev::SLE_DEV_ADVERTISING);
                        }
                    } else {
                        shared.adv_scan.abort_advertising();
                    }
                }
                sle_dli::SleOpcode::EnableScan => {
                    if *status == sle_dli::SleStatus::Success {
                        shared.adv_scan.confirm_scanning();
                        if let Some(dev) = shared.active_dev_id.and_then(|id| shared.dev_registry.get(id)) {
                            dev.set_flag(sle_dev::SLE_DEV_SCANNING);
                        }
                    } else {
                        shared.adv_scan.abort_scanning();
                    }
                }
                _ => {}
            }
        }
        sle_dli::SleEvent::ConnComplete { handle: _, addr, status } => {
            if *status == sle_dli::SleStatus::Success {
                shared.conn.confirm_connecting_by_addr(addr);
                genl_bridge::notify_event(0x01, 0, addr);
            } else {
                shared.conn.abort_connecting_by_addr(addr);
            }
        }
        sle_dli::SleEvent::Disconnected { handle, .. } => {
            let peer_addr = shared.conn.info(*handle)
                .map(|e| e.peer_addr)
                .unwrap_or([0u8; 6]);
            shared.conn.confirm_disconnecting_by_handle(*handle);
            genl_bridge::notify_event(0x01, *handle, &peer_addr);
        }
        sle_dli::SleEvent::AdvReport { addr, .. } => {
            genl_bridge::notify_event(0x02, 0, addr);
        }
        _ => {}
    }

    // 3. Publish to broadcast ring and DLI event ring.
    let wire = sle_dli_event_to_broadcast(ev);
    shared.broadcast.publish(wire);
    let dli_ev = sle_dli_event_to_wire(ev);
    shared.push_dli_event(dli_ev);
}

/// Drain all immediately available controller events and process them.
///
/// Used after ioctl commands to handle synchronous controller responses
/// (VirtualController, UartController) inline without waiting for the
/// next EventPump cycle. For real hardware backends (USB, serdev),
/// events arrive asynchronously and this function is a no-op.
fn drain_controller_events(shared: &mut SubsystemShared) {
    let mut drained = 0u32;
    while let Some(ev) = shared.controller.poll_event() {
        process_controller_event(shared, &ev);
        drained += 1;
        if drained >= 32 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Background event pump (RX processing)
// ---------------------------------------------------------------------------

impl EventPump {
    fn new() -> Result<Arc<Self>> {
        Arc::pin_init(pin_init!(EventPump {
            work <- new_delayed_work!("sparklink_event_pump"),
        }), GFP_KERNEL)
    }

    /// Schedule the first pump cycle.
    fn start(self: &Arc<Self>) {
        let _ = workqueue::system().enqueue_delayed(
            self.clone(),
            msecs_to_jiffies(EVENT_PUMP_INTERVAL_MS),
        );
    }
}

impl WorkItem for EventPump {
    type Pointer = Arc<EventPump>;

    fn run(this: Arc<EventPump>) {
        // Drain all pending controller events into both the broadcast ring
        // (for read() delivery) and the DLI event ring (for DLI_POLL_EVENT).
        // Also resolve pending commands from the management plane.
        let mut pumped = 0u32;
        {
            let mut ss = SUBSYSTEM.lock();
            if let Some(ref mut shared) = *ss {
                while let Some(ev) = shared.controller.poll_event() {
                    process_controller_event(shared, &ev);
                    pumped += 1;
                    if pumped >= 32 {
                        break; // yield after 32 events per cycle
                    }
                }

                // Expire stale commands and garbage-collect resolved entries.
                let expired = shared.cmd_pending.expire_stale();
                if expired > 0 {
                    pr_warn!("sparklink: {} pending command(s) timed out\n", expired);
                }
                shared.cmd_pending.gc();
            }
        }
        // Re-arm the delayed work for the next cycle.
        let _ = workqueue::system().enqueue_delayed(
            this,
            msecs_to_jiffies(EVENT_PUMP_INTERVAL_MS),
        );
    }
}

// ---------------------------------------------------------------------------
// Background command worker (TX dispatch)
// ---------------------------------------------------------------------------

/// Minimum interval between command dispatch cycles (milliseconds).
const CMD_WORKER_INTERVAL_MS: u32 = 10;

/// Background worker that dequeues command requests from `cmd_queue`
/// and sends them to the controller in workqueue context.
///
/// This decouples command submission (ioctl) from hardware transmission,
/// following the Bluetooth `hci_cmd_work` pattern. Benefits:
/// - Reduces ioctl lock hold time
/// - Enables future flow control (credit-based throttling)
/// - Makes real hardware latency non-blocking for userspace
#[pin_data]
struct CommandWorker {
    #[pin]
    work: DelayedWork<CommandWorker>,
}

impl_has_delayed_work! {
    impl HasDelayedWork<Self> for CommandWorker { self.work }
}

impl CommandWorker {
    fn new() -> Result<Arc<Self>> {
        Arc::pin_init(pin_init!(CommandWorker {
            work <- new_delayed_work!("sparklink_cmd_worker"),
        }), GFP_KERNEL)
    }

    /// Schedule the command worker to run soon.
    fn kick(self: &Arc<Self>) {
        let _ = workqueue::system().enqueue_delayed(
            self.clone(),
            msecs_to_jiffies(CMD_WORKER_INTERVAL_MS),
        );
    }
}

impl WorkItem for CommandWorker {
    type Pointer = Arc<CommandWorker>;

    fn run(this: Arc<CommandWorker>) {
        let mut dispatched = 0u32;
        {
            let mut ss = SUBSYSTEM.lock();
            if let Some(ref mut shared) = *ss {
                // Dispatch up to 8 commands per cycle.
                while dispatched < 8 {
                    match shared.cmd_queue.pop() {
                        Some(req) => {
                            let plen = req.param_len as usize;
                            let result = shared.controller.send_command_raw(
                                req.opcode,
                                &req.params[..plen],
                            );
                            if result.is_err() {
                                // Immediately resolve the pending entry as
                                // failed so it does not linger until timeout.
                                shared.cmd_pending.resolve(
                                    req.opcode, 0x03, &[], // HardwareFailure
                                );
                            }
                            dispatched += 1;
                        }
                        None => break,
                    }
                }
            }
        }

        // Re-arm if there are more commands pending.
        if dispatched > 0 {
            let ss = SUBSYSTEM.lock();
            if let Some(ref shared) = *ss {
                if !shared.cmd_queue.is_empty() {
                    drop(ss);
                    this.kick();
                }
            }
        }
    }
}

/// Convert a DLI SleEvent into a SleWireEvent for broadcast ring insertion.
fn sle_dli_event_to_broadcast(ev: &sle_dli::SleEvent) -> sle_event::SleWireEvent {
    match ev {
        sle_dli::SleEvent::CommandComplete { opcode, status, data } => {
            sle_event::SleWireEvent::command_complete(
                *opcode as u16,
                *status as u8,
                data.as_slice(),
            )
        }
        sle_dli::SleEvent::CommandStatus { opcode, status } => {
            sle_event::SleWireEvent::command_status(*opcode as u16, *status as u8)
        }
        sle_dli::SleEvent::ConnComplete { handle, addr, status } => {
            let new_state = if *status == sle_dli::SleStatus::Success { 2u8 } else { 0u8 };
            sle_event::SleWireEvent::conn_state(*handle, 1, new_state, *addr, *status as u8)
        }
        sle_dli::SleEvent::Disconnected { handle, reason } => {
            sle_event::SleWireEvent::conn_state(*handle, 2, 0, [0u8; 6], *reason)
        }
        sle_dli::SleEvent::AdvReport { addr, rssi, discovery_level, data } => {
            sle_event::SleWireEvent::adv_report(*addr, *rssi, *discovery_level, data.as_slice())
        }
        sle_dli::SleEvent::DataReceived { handle, data } => {
            sle_event::SleWireEvent::data_received(*handle, data.len() as u16)
        }
        sle_dli::SleEvent::HardwareError { code } => {
            sle_event::SleWireEvent::hardware_error(*code)
        }
        sle_dli::SleEvent::EncryptionChanged { handle, enabled } => {
            // Map to SecurityChanged wire event.
            sle_event::SleWireEvent::conn_state(
                *handle,
                0,
                if *enabled { 1 } else { 0 },
                [0u8; 6],
                0,
            )
        }
        sle_dli::SleEvent::PairRequest { addr, .. } => {
            sle_event::SleWireEvent::conn_state(0, 0, 0, *addr, 0)
        }
        sle_dli::SleEvent::BroadcastEnd { reason } => {
            sle_event::SleWireEvent::broadcast_end(*reason)
        }
        sle_dli::SleEvent::PhyUpdate { handle, mcs_index, bandwidth_mhz } => {
            sle_event::SleWireEvent::phy_update(*handle, *mcs_index, *bandwidth_mhz)
        }
        sle_dli::SleEvent::ConnParamUpdate { handle, interval, latency, timeout } => {
            sle_event::SleWireEvent::conn_param_update(*handle, *interval, *latency, *timeout)
        }
        sle_dli::SleEvent::DataLenChange { handle, max_tx_octets, max_rx_octets } => {
            sle_event::SleWireEvent::data_len_change(*handle, *max_tx_octets, *max_rx_octets)
        }
        sle_dli::SleEvent::DataBufOverflow { link_type } => {
            sle_event::SleWireEvent::data_buf_overflow(*link_type)
        }
        sle_dli::SleEvent::PeerConnParamReq { handle, interval_min, interval_max, latency, timeout } => {
            sle_event::SleWireEvent::peer_conn_param_req(*handle, *interval_min, *interval_max, *latency, *timeout)
        }
    }
}

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

/// Guard that tears down the shared subsystem when the module is unloaded.
struct SubsystemGuard;

impl Drop for SubsystemGuard {
    fn drop(&mut self) {
        let mut ss = SUBSYSTEM.lock();
        if let Some(ref mut shared) = *ss {
            // Unregister all devices before closing the controller.
            if let Some(id) = shared.active_dev_id.take() {
                let _ = shared.dev_registry.unregister(id);
            }
            shared.controller.close();
        }
        *ss = None;
        pr_info!("sparklink: shared subsystem destroyed (module unload)\n");
    }
}

module! {
    type: SparkLinkModule,
    name: "sparklink",
    authors: ["SparkLink for Linux Contributors"],
    description: "SparkLink (NearLink) wireless communication subsystem",
    license: "GPL",
}

#[pin_data]
struct SparkLinkModule {
    #[pin]
    _miscdev: MiscDeviceRegistration<SparkLinkCtl>,
    // debugfs: /sys/kernel/debug/sparklink/
    _debugfs: Dir,
    #[pin]
    _version: File<CString>,
    #[pin]
    _build_info: File<CString>,
    #[pin]
    _subsystems: File<CString>,
    #[pin]
    adv_count: File<Atomic<usize>>,
    #[pin]
    scan_count: File<Atomic<usize>>,
    #[pin]
    conn_count: File<Atomic<usize>>,
    #[pin]
    ioctl_count: File<Atomic<usize>>,
    #[pin]
    _dli_info: File<Atomic<u32>>,
    // debugfs subdirectories for observability layer
    _mgmt_dir: Dir,
    #[pin]
    _mgmt_stats: File<Atomic<u32>>,
    _transport_dir: Dir,
    #[pin]
    _transport_info: File<Atomic<u32>>,
    _power_dir: Dir,
    #[pin]
    _power_stats: File<Atomic<u32>>,
    _conn_dir: Dir,
    #[pin]
    _conn_stats: File<Atomic<u32>>,
    #[pin]
    _device_list: File<Atomic<u32>>,
    _genl: genl_bridge::GenlGuard,
    #[pin]
    _configfs: configfs::Subsystem<sle_configfs::SparkLinkConfig>,
    #[pin]
    _usb: sle_usb::UsbRegistration,
    /// Dropped LAST — after _miscdev closes all fds.
    _subsystem_guard: SubsystemGuard,
}

impl kernel::InPlaceModule for SparkLinkModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        pr_info!("sparklink: initialising SparkLink subsystem v0.3.0\n");

        // SAFETY: Called exactly once during module init.
        unsafe { SUBSYSTEM.init() };
        // SAFETY: Called exactly once during module init.
        unsafe { sle_serdev::init_serdev_parser() };
        // SAFETY: Called exactly once during module init.
        unsafe { sle_usb::init_usb_event_ring() };

        let options = MiscDeviceOptions {
            name: c"sparklink",
        };

        let debugfs = Dir::new(c"sparklink");
        let mgmt_dir = debugfs.subdir(c"mgmt");
        let transport_dir = debugfs.subdir(c"transport");
        let power_dir = debugfs.subdir(c"power");
        let conn_dir = debugfs.subdir(c"connections");

        try_pin_init!(Self {
            _miscdev <- MiscDeviceRegistration::register(options),
            _version <- debugfs.read_only_file(
                c"version",
                CString::try_from_fmt(fmt!("sparklink 0.3.0"))?,
            ),
            _build_info <- debugfs.read_only_file(
                c"build_info",
                CString::try_from_fmt(fmt!("sparklink subsystem\nstandard: T/XS 10002-2025, T/XS 20001-2025, T/XS 10003-2025\nmodules: core pdu adv conn crypto security ssap power event dli usb netlink\nlanguage: Rust"))?,
            ),
            _subsystems <- debugfs.read_only_file(
                c"subsystems",
                CString::try_from_fmt(fmt!("sle_pdu: frame codec\nsle_adv: advertising/scanning\nsle_conn: connection management\nsle_crypto: SM3/SM4 crypto\nsle_security: pairing/encryption\nsle_ssap: service access protocol\nsle_power: power management\nsle_event: async event notification\nsle_dli: driver layer interface\nsle_usb: USB transport\nsle_netlink: Generic Netlink protocol"))?,
            ),
            adv_count <- debugfs.read_write_file(
                c"adv_count",
                Atomic::<usize>::new(0),
            ),
            scan_count <- debugfs.read_write_file(
                c"scan_count",
                Atomic::<usize>::new(0),
            ),
            conn_count <- debugfs.read_write_file(
                c"conn_count",
                Atomic::<usize>::new(0),
            ),
            ioctl_count <- debugfs.read_write_file(
                c"ioctl_count",
                Atomic::<usize>::new(0),
            ),
            _dli_info <- debugfs.read_callback_file(
                c"dli_controller",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let ss = SUBSYSTEM.lock();
                    if let Some(ref ss) = *ss {
                        let cinfo = ss.controller.info();
                        let major = (cinfo.fw_version >> 16) & 0xFF;
                        let minor = (cinfo.fw_version >> 8) & 0xFF;
                        let patch = cinfo.fw_version & 0xFF;
                        writeln!(f, "bus: {:?}", cinfo.bus)?;
                        writeln!(f, "firmware: {}.{}.{}", major, minor, patch)?;
                        writeln!(f, "features: 0x{:016x}", cinfo.features)?;
                        writeln!(f, "max_connections: {}", cinfo.max_connections)?;
                        writeln!(f, "max_mtu: {}", cinfo.max_mtu)?;
                        writeln!(f, "max_mps: {}", cinfo.max_mps)?;
                        writeln!(f, "transport_modes: 0x{:02x}", cinfo.transport_modes)?;
                        writeln!(f, "measurement_cap: 0x{:02x}", cinfo.measurement_cap)?;
                        writeln!(f, "security_cap: 0x{:04x}", cinfo.security_cap)?;
                    }
                    Ok(())
                },
            ),
            // --- Observability layer: debugfs subdirectories ---
            _mgmt_stats <- mgmt_dir.read_callback_file(
                c"stats",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let ss = SUBSYSTEM.lock();
                    if let Some(ref ss) = *ss {
                        let q = &ss.cmd_pending;
                        writeln!(f, "pending: {}", q.pending_count)?;
                        writeln!(f, "submitted: {}", q.total_submitted)?;
                        writeln!(f, "resolved: {}", q.total_resolved)?;
                        writeln!(f, "timeouts: {}", q.total_timeouts)?;
                        writeln!(f, "cmd_queue_depth: {}", ss.cmd_queue.len())?;
                    }
                    Ok(())
                },
            ),
            _mgmt_dir: mgmt_dir,
            _transport_info <- transport_dir.read_callback_file(
                c"info",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let ss = SUBSYSTEM.lock();
                    if let Some(ref ss) = *ss {
                        writeln!(f, "protocols_registered: {}", ss.proto_registry.count())?;
                        writeln!(f, "devices_bound: {}", ss.dev_bindings.count())?;
                        for proto in ss.proto_registry.iter() {
                            writeln!(f, "  proto: {} (bus={:?}, max_pdu={})",
                                proto.name, proto.bus, proto.max_pdu)?;
                        }
                    }
                    Ok(())
                },
            ),
            _transport_dir: transport_dir,
            _power_stats <- power_dir.read_callback_file(
                c"stats",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let ss = SUBSYSTEM.lock();
                    if let Some(ref ss) = *ss {
                        let p = &ss.power;
                        writeln!(f, "state: {:?}", p.state)?;
                        writeln!(f, "forced_active: {}", p.is_forced_active())?;
                        writeln!(f, "active_events: {}", p.stats.active_events)?;
                        writeln!(f, "sniff_events: {}", p.stats.sniff_events)?;
                        writeln!(f, "idle_events: {}", p.stats.idle_events)?;
                        writeln!(f, "transitions: {}", p.stats.transitions)?;
                        writeln!(f, "force_active_count: {}", p.stats.force_active_count)?;
                        writeln!(f, "supervision_warnings: {}", p.stats.supervision_warnings)?;
                    }
                    Ok(())
                },
            ),
            _power_dir: power_dir,
            _conn_stats <- conn_dir.read_callback_file(
                c"stats",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let ss = SUBSYSTEM.lock();
                    if let Some(ref ss) = *ss {
                        writeln!(f, "active: {}", ss.conn.active_count())?;
                        writeln!(f, "total_created: {}", ss.conn.total_created)?;
                        writeln!(f, "total_completed: {}", ss.conn.total_completed)?;
                    }
                    Ok(())
                },
            ),
            _conn_dir: conn_dir,
            _device_list <- debugfs.read_callback_file(
                c"devices",
                Atomic::<u32>::new(0),
                &|_dummy: &Atomic<u32>, f: &mut core::fmt::Formatter<'_>| {
                    let ss = SUBSYSTEM.lock();
                    if let Some(ref ss) = *ss {
                        writeln!(f, "registered: {}", ss.dev_registry.count())?;
                        for dev in ss.dev_registry.iter() {
                            let name_end = dev.name.iter().position(|&b| b == 0)
                                .unwrap_or(dev.name.len());
                            // SAFETY: device names are always ASCII.
                            let name_str = core::str::from_utf8(&dev.name[..name_end])
                                .unwrap_or("?");
                            writeln!(f, "  sle{}: {} bus={:?} addr={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} flags=0x{:08x}",
                                dev.id, name_str, dev.bus,
                                dev.addr[0], dev.addr[1], dev.addr[2],
                                dev.addr[3], dev.addr[4], dev.addr[5],
                                dev.flags())?;
                        }
                    }
                    Ok(())
                },
            ),
            _debugfs: debugfs,
            _genl: genl_bridge::GenlGuard::new()?,
            _configfs <- {
                use sle_configfs::SparkLinkConfig;
                let item_type = configfs_attrs! {
                    container: configfs::Subsystem<SparkLinkConfig>,
                    data: SparkLinkConfig,
                    attributes: [
                        version: 0,
                        max_connections: 1,
                        adv_interval_ms: 2,
                        scan_window_ms: 3,
                        power_mode: 4,
                        controller_type: 5,
                    ],
                };
                configfs::Subsystem::new(
                    c"sparklink",
                    item_type,
                    SparkLinkConfig::new(),
                )
            },
            _usb <- sle_usb::UsbRegistration::new(c"sparklink_usb", _module),
            _subsystem_guard: {
                // Initialise the shared subsystem at module load time.
                // This decouples the subsystem lifecycle from fd lifetime:
                // the controller, event pump, and protocol state persist
                // even when no fd is open.
                let mut ss = SUBSYSTEM.lock();
                let addr = [0x5E, 0x00, 0x00, 0x00, 0x00, 0x01];
                let controller = match sle_configfs::controller_type() {
                    1 => sle_dli::ControllerBackend::new_uart(
                        addr, sle_uart::UartConfig::default()),
                    2 => sle_dli::ControllerBackend::new_spi(
                        addr, sle_spi::SpiConfig::default()),
                    _ => sle_dli::ControllerBackend::new_virtual(addr),
                };
                controller.open()?;

                let mut conn = ConnManager::new(addr);
                conn.set_max_connections(sle_configfs::max_connections() as usize);

                let pump = EventPump::new().ok();
                if let Some(ref p) = pump {
                    p.start();
                }

                let cmd_worker = CommandWorker::new().ok();

                // Register built-in transport protocols.
                let mut proto_registry = sle_transport::SleProtoRegistry::new();
                sle_transport::register_builtin_protos(&mut proto_registry);

                // Register the controller in the device registry.
                let ctrl_info = controller.info();
                let mut dev_registry = sle_dev::SleDevRegistry::new();
                let dev_id = dev_registry.register(&ctrl_info).ok();

                *ss = Some(SubsystemShared {
                    controller,
                    conn,
                    adv_scan: AdvScanInner::new(addr, b"sparklink-ctl"),
                    security: SecurityInner::new(),
                    ssap: SsapInner::new(),
                    power: PowerInner::new(),
                    phy: sle_phy::PhyConfig::default_config(),
                    local_role: GtRole::TNode,
                    broadcast: sle_event::BroadcastRing::new(),
                    dli_ring: unsafe { core::mem::zeroed() },
                    dli_head: 0,
                    dli_tail: 0,
                    _event_pump: pump,
                    _cmd_worker: cmd_worker,
                    dev_registry,
                    active_dev_id: dev_id,
                    cmd_pending: sle_mgmt::CmdPendingQueue::new(),
                    cmd_queue: sle_mgmt::CmdRequestQueue::new(),
                    proto_registry,
                    dev_bindings: sle_transport::SleBindingTable::new(),
                });
                pr_info!("sparklink: shared subsystem initialised\n");
                SubsystemGuard
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Misc device implementation: /dev/sparklink control interface
// ---------------------------------------------------------------------------
// Each open fd gets its own event queue for per-listener event delivery.
// All protocol state (controller, connections, advertising, security, SSAP,
// power, PHY) is shared across fds via the SUBSYSTEM global mutex.

#[pin_data(PinnedDrop)]
struct SparkLinkCtl {
    #[pin]
    events: Mutex<EventQueue>,
    #[pin]
    event_poll: PollCondVar,
    dev: ARef<Device>,
    /// Broadcast ring cursor: sequence number of the last event this fd has seen.
    last_seq: core::sync::atomic::AtomicU64,
}

#[vtable]
impl MiscDevice for SparkLinkCtl {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &FsFile, misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let dev = ARef::from(misc.device());
        dev_info!(dev, "sparklink: control interface opened\n");

        // Subsystem is initialised at module load; just verify it exists.
        {
            let ss = SUBSYSTEM.lock();
            if ss.is_none() {
                dev_err!(dev, "sparklink: subsystem not initialised\n");
                return Err(ENODEV);
            }
        }
        OPEN_FD_COUNT.fetch_add(1u32, Relaxed);

        KBox::try_pin_init(
            try_pin_init! {
                SparkLinkCtl {
                    events <- new_mutex!(EventQueue::new()),
                    event_poll <- new_poll_condvar!("sparklink_event"),
                    dev: dev,
                    last_seq: core::sync::atomic::AtomicU64::new(
                        sle_event::BroadcastRing::current_seq()
                    ),
                }
            },
            GFP_KERNEL,
        )
    }

    fn read_iter(kiocb: Kiocb<'_, Self::Ptr>, iov: &mut IovIterDest<'_>) -> Result<usize> {
        let me = kiocb.file();
        // Sync broadcast events into per-fd queue before reading.
        Self::sync_broadcast(me.as_ref());
        let mut guard = me.events.lock();
        if !guard.has_events() {
            return Err(EAGAIN);
        }
        let mut total = 0usize;
        let evt_size = core::mem::size_of::<sle_event::SleWireEvent>();
        while guard.has_events() && iov.len() >= evt_size {
            if let Some(evt) = guard.dequeue() {
                let bytes: &[u8] = evt.as_bytes();
                let written = iov.copy_to_iter(bytes);
                if written == 0 {
                    break;
                }
                total += written;
            }
        }
        Ok(total)
    }

    fn poll(me: Pin<&SparkLinkCtl>, file: &FsFile, table: &PollTable<'_>) -> u32 {
        table.register_wait(file, &me.event_poll);
        // Sync broadcast events into per-fd queue before checking.
        Self::sync_broadcast(me.as_ref());
        let guard = me.events.lock();
        let mut mask = 0u32;
        if guard.has_events() {
            mask |= bindings::POLLIN | bindings::POLLRDNORM;
        }
        mask
    }

    fn ioctl(me: Pin<&SparkLinkCtl>, _file: &FsFile, cmd: u32, arg: usize) -> Result<isize> {
        // Sync power mode from configfs on every ioctl.
        Self::sync_power_mode(me.as_ref());

        match cmd {
            SL_IOCTL_START_ADV => {
                Self::check_power_active()?;
                let uparams: SleAdvParams = read_user_struct(arg)?;
                let interval = if uparams.interval_ms == 0 {
                    sle_configfs::adv_interval_ms()
                } else {
                    uparams.interval_ms
                };
                let params = AdvParams {
                    discovery_level: uparams.discovery_level,
                    interval_slots: (interval as u32) * 8,
                    broadcast_type: sle_pdu::BroadcastType::AccessibleScannable,
                    tx_power: 0,
                };
                {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    if s.local_role != GtRole::GNode {
                        dev_warn!(me.dev, "sparklink: advertising requires GNode role\n");
                        return Err(EPERM);
                    }
                    s.adv_scan.start_advertising(params)?;
                    if let Some(pdu) = s.adv_scan.build_adv_pdu() {
                        dev_info!(
                            me.dev,
                            "sparklink: ADV PDU built, {} bytes data, CRC=0x{:03x}\n",
                            pdu.data_len,
                            pdu.crc
                        );
                    }
                    // Send enable to controller; state stays AdvPending.
                    // EventPump will confirm or abort when CommandComplete
                    // arrives from the controller (DLI async model).
                    match s.controller.enable_broadcast(true) {
                        Ok(()) => {
                            // Drain synchronous responses (VirtualController).
                            drain_controller_events(s);
                        }
                        Err(e) => {
                            s.adv_scan.abort_advertising();
                            return Err(e);
                        }
                    }
                }
                Ok(0)
            }
            SL_IOCTL_STOP_ADV => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.adv_scan.stop_advertising()?;
                if let Some(dev) = s.active_dev_id.and_then(|id| s.dev_registry.get(id)) {
                    dev.clear_flag(sle_dev::SLE_DEV_ADVERTISING);
                }
                let _ = s.controller.enable_broadcast(false);
                Ok(0)
            }
            SL_IOCTL_START_SCAN => {
                Self::check_power_active()?;
                let uparams: SleScanParams = read_user_struct(arg)?;
                let window = if uparams.window_ms == 0 {
                    sle_configfs::scan_window_ms()
                } else {
                    uparams.window_ms
                };
                let interval = if uparams.interval_ms == 0 {
                    window * 2 // default: interval = 2x window
                } else {
                    uparams.interval_ms
                };
                let params = ScanParams {
                    window_slots: (window as u32) * 8,
                    interval_slots: (interval as u32) * 8,
                    filter_level: uparams.filter_discovery_level,
                    active: false,
                };
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                if s.local_role != GtRole::TNode {
                    dev_warn!(me.dev, "sparklink: scanning requires TNode role\n");
                    return Err(EPERM);
                }
                s.adv_scan.start_scanning(params)?;
                match s.controller.enable_scan(true) {
                    Ok(()) => {
                        // Drain synchronous responses (VirtualController).
                        drain_controller_events(s);
                    }
                    Err(e) => {
                        s.adv_scan.abort_scanning();
                        return Err(e);
                    }
                }
                Ok(0)
            }
            SL_IOCTL_STOP_SCAN => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.adv_scan.stop_scanning()?;
                if let Some(dev) = s.active_dev_id.and_then(|id| s.dev_registry.get(id)) {
                    dev.clear_flag(sle_dev::SLE_DEV_SCANNING);
                }
                let _ = s.controller.enable_scan(false);
                Ok(0)
            }
            SL_IOCTL_DEV_COUNT => {
                let ss = SUBSYSTEM.lock();
                let count = ss.as_ref().map_or(0, |s| s.dev_registry.count());
                Ok(count as isize)
            }
            SL_IOCTL_DEV_INFO => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                // SAFETY: SciDevInfo is repr(C) with only primitive fields.
                let mut info: SciDevInfo = unsafe { core::mem::zeroed() };

                let dev_id = s.active_dev_id.unwrap_or(0);
                if let Some(dev) = s.dev_registry.get(dev_id) {
                    info.index = dev.id();
                    info.bus = dev.bus() as u8;
                    info.addr = SleAddr { b: *dev.addr() };
                    let dev_name = dev.name();
                    let copy_len = dev_name.len().min(info.name.len());
                    info.name[..copy_len].copy_from_slice(&dev_name[..copy_len]);
                    info.state = if dev.test_flag(sle_dev::SLE_DEV_ADVERTISING) {
                        SciState::Advertising as u8
                    } else if dev.test_flag(sle_dev::SLE_DEV_SCANNING) {
                        SciState::Scanning as u8
                    } else {
                        SciState::Idle as u8
                    };
                } else {
                    info.state = SciState::Idle as u8;
                    info.bus = SciBus::Virtual as u8;
                    info.addr = SleAddr { b: [0x5E, 0x00, 0x00, 0x00, 0x00, 0x01] };
                    let name = b"sparklink-ctl";
                    info.name[..name.len()].copy_from_slice(name);
                }

                drop(ss);
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_DEV_REGISTER => {
                dev_info!(me.dev, "sparklink: DEV_REGISTER via ioctl (use module init for real registration)\n");
                Ok(0)
            }
            SL_IOCTL_DEV_UNREGISTER => {
                dev_info!(me.dev, "sparklink: DEV_UNREGISTER via ioctl (use module unload for real unregistration)\n");
                Ok(0)
            }
            SL_IOCTL_INJECT_ADV => {
                let inject: SleInjectAdv = read_user_struct(arg)?;

                let mut builder = sle_pdu::AdvDataBuilder::new();
                let _ = builder.push_discovery_level(inject.discovery_level);
                let _ = builder.push_sle_addr(&inject.addr);
                let name_len = (inject.name_len as usize).min(32);
                if name_len > 0 {
                    let _ = builder.push_complete_name(&inject.name[..name_len]);
                }
                let pdu = sle_pdu::AdvPdu::build(
                    sle_pdu::BroadcastType::AccessibleScannable,
                    sle_pdu::PacketType::BasicAdv,
                    0,
                    &builder,
                );

                {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    s.adv_scan.process_adv_pdu(&pdu, inject.rssi)?;
                }
                let name_len = (inject.name_len as usize).min(31);
                Self::broadcast_event(
                    me.as_ref(),
                    sle_event::SleWireEvent::adv_report(
                        inject.addr,
                        inject.rssi,
                        inject.discovery_level,
                        &inject.name[..name_len],
                    ),
                );
                genl_bridge::notify_event(0x02, 0, &inject.addr);
                dev_info!(
                    me.dev,
                    "sparklink: injected ADV from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} rssi={}\n",
                    inject.addr[0], inject.addr[1], inject.addr[2],
                    inject.addr[3], inject.addr[4], inject.addr[5],
                    inject.rssi
                );
                Ok(0)
            }
            SL_IOCTL_SCAN_RESULT_COUNT => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let count = s.adv_scan.scan_result_count();
                Ok(count as isize)
            }
            // --- Connection management ---
            SL_IOCTL_CONNECT => {
                Self::check_power_active()?;
                let cp: SleConnectParams = read_user_struct(arg)?;
                let role = if cp.gt_role == 1 {
                    GtRole::GNode
                } else {
                    GtRole::TNode
                };
                let handle = {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    let handle = s.conn.connect(cp.peer_addr, role)?;
                    // Send CreateConnection to controller; state stays
                    // ConnPending. EventPump will confirm when ConnComplete
                    // event arrives from the controller.
                    match s.controller.create_connection(&cp.peer_addr) {
                        Ok(()) => {
                            drain_controller_events(s);
                        }
                        Err(e) => {
                            s.conn.abort_connecting(handle);
                            return Err(e);
                        }
                    }
                    handle
                };
                Self::broadcast_event(
                    me.as_ref(),
                    sle_event::SleWireEvent::conn_state(handle, 0, 1, cp.peer_addr, 0),
                );
                Ok(handle as isize)
            }
            SL_IOCTL_DISCONNECT => {
                let handle: u16 = read_user_struct(arg)?;
                let (handle, peer_addr, old_state) = {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    let handle = s.conn.resolve_handle(handle)?;
                    let peer_addr = s.conn.info(handle).map(|e| e.peer_addr).unwrap_or([0u8; 6]);
                    let old_state = s.conn.info(handle).map(|e| e.state as u8).unwrap_or(0);
                    s.conn.disconnect(handle)?;
                    // Send Disconnect to controller; state stays
                    // DisconnPending. EventPump will confirm when
                    // Disconnected event arrives from the controller.
                    match s.controller.disconnect(handle) {
                        Ok(()) => {
                            drain_controller_events(s);
                        }
                        Err(_) => {
                            s.conn.abort_disconnecting(handle);
                        }
                    }
                    (handle, peer_addr, old_state)
                };
                Self::broadcast_event(
                    me.as_ref(),
                    sle_event::SleWireEvent::conn_state(handle, old_state, 0, peer_addr, 0),
                );
                Ok(0)
            }
            SL_IOCTL_CONN_INFO => {
                let req: SleConnInfo = read_user_struct(arg)?;
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let handle = if req.handle == 0 {
                    let (handles, count) = s.conn.active_handles();
                    if count == 0 {
                        return Err(EPIPE);
                    }
                    handles[0]
                } else {
                    req.handle
                };
                let entry = s.conn.info(handle)?;
                // SAFETY: SleConnInfo is repr(C) with no uninitialized padding.
                let mut info: SleConnInfo = unsafe { core::mem::zeroed() };
                info.handle = entry.handle;
                info.state = entry.state as u8;
                info.peer_addr = entry.peer_addr;
                info.local_role = entry.local_role as u8;
                info.bandwidth_mhz = entry.params.bandwidth_mhz;
                info.mcs_index = entry.params.mcs_index;
                info.event_group_period = entry.params.event_group_period;
                info.supervision_timeout = entry.params.supervision_timeout;
                info.tx_seq = entry.seq.tx_seq;
                info.rx_seq = entry.seq.rx_seq;
                info.tx_pending = entry.tx_queue.len() as u16;
                info.rx_pending = entry.rx_queue.len() as u16;
                info.tx_bytes = entry.tx_bytes;
                info.rx_bytes = entry.rx_bytes;
                drop(ss);
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_CONN_SEND => {
                let cd: SleConnData = read_user_struct(arg)?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                let sent = {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    let handle = s.conn.resolve_handle(cd.handle)?;
                    let sent = s.conn.send(handle, &cd.data[..len])?;
                    let _ = s.controller.send_data(cd.handle, &cd.data[..len]);
                    sent
                };
                Ok(sent as isize)
            }
            SL_IOCTL_CONN_RECV => {
                let cd: SleConnData = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let handle = s.conn.resolve_handle(cd.handle)?;
                // SAFETY: SleConnData is repr(C), zeroed gives all-zero which is valid.
                let mut out: SleConnData = unsafe { core::mem::zeroed() };
                out.handle = handle;
                let recv_len = s.conn.recv(handle, &mut out.data)?;
                out.length = recv_len.min(CONN_DATA_MAX) as u16;
                drop(ss);
                write_user_struct(arg, &out)?;
                Ok(0)
            }
            SL_IOCTL_INJECT_CONN_RESP => {
                let resp: SleInjectConnResp = read_user_struct(arg)?;
                let resp_type = AccessResponseType::from_raw(resp.response_type)
                    .ok_or(EINVAL)?;
                let mut params = NegotiatedParams::default();
                params.bandwidth_mhz = resp.bandwidth_mhz;
                params.mcs_index = resp.mcs_index;
                params.supervision_timeout = resp.supervision_timeout;
                let (handle, peer_addr, result) = {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    let handle = s.conn.resolve_handle(resp.handle)?;
                    let peer_addr = s.conn.info(handle).map(|e| e.peer_addr).unwrap_or([0u8; 6]);
                    let result = s.conn.process_access_response(handle, resp_type, params);
                    (handle, peer_addr, result)
                };
                match &result {
                    Ok(()) => {
                        Self::broadcast_event(
                            me.as_ref(),
                            sle_event::SleWireEvent::conn_state(handle, 1, 2, peer_addr, 0),
                        );
                    }
                    Err(_) => {
                        Self::broadcast_event(
                            me.as_ref(),
                            sle_event::SleWireEvent::conn_state(handle, 1, 0, peer_addr, resp.response_type),
                        );
                    }
                }
                result.map(|()| 0isize)
            }
            SL_IOCTL_INJECT_CONN_DATA => {
                let cd: SleConnData = read_user_struct(arg)?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    let handle = s.conn.resolve_handle(cd.handle)?;
                    let seq = {
                        let entry = s.conn.info(handle)?;
                        entry.seq.rx_seq
                    };
                    s.conn.receive_data(handle, &cd.data[..len], seq)?;
                }
                // Use cd.handle (unresolved) for the event since handle is local
                Self::broadcast_event(
                    me.as_ref(),
                    sle_event::SleWireEvent::data_received(cd.handle, len as u16),
                );
                dev_info!(
                    me.dev,
                    "sparklink: injected {} bytes connection data (handle={})\n",
                    len,
                    cd.handle
                );
                Ok(0)
            }
            SL_IOCTL_CONN_COUNT => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let count = s.conn.active_count();
                Ok(count as isize)
            }
            SL_IOCTL_CONN_LIST => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let (handles, count) = s.conn.active_handles();
                // SAFETY: SleConnList is repr(C).
                let mut list: SleConnList = unsafe { core::mem::zeroed() };
                let count = count.min(8);
                list.count = count as u16;
                for i in 0..count {
                    list.handles[i] = handles[i];
                }
                drop(ss);
                write_user_struct(arg, &list)?;
                Ok(0)
            }
            // --- Security management ---
            SL_IOCTL_SEC_SET_PSK => {
                let params: SlePskParams = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.security.set_psk(params.psk);
                Ok(0)
            }
            SL_IOCTL_SEC_PAIR => {
                let params: SlePairParams = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                match params.method {
                    1 => s.security.pair_just_works()?,
                    2 => s.security.pair_psk()?,
                    _ => return Err(EINVAL),
                }
                let _ = s.controller.request_pair(params.method);
                Ok(0)
            }
            SL_IOCTL_SEC_INFO => {
                let info = {
                    let ss = SUBSYSTEM.lock();
                    let s = ss.as_ref().ok_or(ENODEV)?;
                    // SAFETY: SleSecInfo is repr(C) with all u8 fields, no padding.
                    let mut info: SleSecInfo = unsafe { core::mem::zeroed() };
                    info.state = s.security.state as u8;
                    info.method = s.security.method as u8;
                    info.mode = s.security.mode as u8;
                    info.enc_enabled = if s.security.is_encrypted() { 1 } else { 0 };
                    info.enc_key_fingerprint = s.security.enc_key_fingerprint();
                    info
                };
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_SEC_ENCRYPT_ON => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.security.enable_encryption()?;
                let _ = s.controller.start_encrypt();
                Ok(0)
            }
            SL_IOCTL_SEC_SM3_TEST => {
                let mut ht: SleHashTest = read_user_struct(arg)?;
                let in_len = (ht.in_len as usize).min(220);
                let digest = SecurityInner::sm3_hash(&ht.data[..in_len]);
                ht.digest = digest;
                write_user_struct(arg, &ht)?;
                Ok(0)
            }
            SL_IOCTL_SEC_SM4_ENC_TEST => {
                let mut cd: SleConnData = read_user_struct(arg)?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    s.security.encrypt_test(&mut cd.data[..len])?;
                }
                write_user_struct(arg, &cd)?;
                Ok(0)
            }
            SL_IOCTL_SEC_SM4_DEC_TEST => {
                let mut cd: SleConnData = read_user_struct(arg)?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    s.security.decrypt_test(&mut cd.data[..len])?;
                }
                write_user_struct(arg, &cd)?;
                Ok(0)
            }
            SL_IOCTL_SEC_SM4_BLOCK_TEST => {
                let mut bt: SleSm4BlockTest = read_user_struct(arg)?;
                let ctx = sle_crypto::Sm4Key::new(&bt.key);
                bt.output = if bt.decrypt != 0 {
                    ctx.decrypt_block(&bt.input)
                } else {
                    ctx.encrypt_block(&bt.input)
                };
                write_user_struct(arg, &bt)?;
                Ok(0)
            }
            SL_IOCTL_SEC_HMAC_TEST => {
                let mut ht: SleHmacTest = read_user_struct(arg)?;
                let klen = (ht.key_len as usize).min(64);
                let dlen = (ht.data_len as usize).min(160);
                ht.digest = sle_crypto::hmac_sm3(&ht.key[..klen], &ht.data[..dlen]);
                write_user_struct(arg, &ht)?;
                Ok(0)
            }
            // --- SSAP service layer ---
            SL_IOCTL_SSAP_REGISTER_SVC => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.ssap.register_device_info_service()?;
                Ok(0)
            }
            SL_IOCTL_SSAP_INFO => {
                let info = {
                    let ss = SUBSYSTEM.lock();
                    let s = ss.as_ref().ok_or(ENODEV)?;
                    // SAFETY: SsapSummary is repr(C) with primitive fields.
                    let mut info: SsapSummary = unsafe { core::mem::zeroed() };
                    info.service_count = s.ssap.service_count() as u16;
                    info.property_count = s.ssap.property_count() as u16;
                    info.total_entries = s.ssap.total_entries() as u16;
                    info.mtu = s.ssap.negotiated.mtu;
                    info.notification_count = s.ssap.notification_count() as u16;
                    info
                };
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_READ => {
                let rw: SsapReadWrite = read_user_struct(arg)?;
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let data = s.ssap.read_property(rw.handle)?;
                // SAFETY: SsapReadWrite is repr(C).
                let mut out: SsapReadWrite = unsafe { core::mem::zeroed() };
                out.handle = rw.handle;
                let copy_len = data.len().min(252);
                out.length = copy_len as u16;
                out.data[..copy_len].copy_from_slice(&data[..copy_len]);
                drop(ss);
                write_user_struct(arg, &out)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_WRITE => {
                let rw: SsapReadWrite = read_user_struct(arg)?;
                let len = (rw.length as usize).min(252);
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.ssap.write_property(rw.handle, &rw.data[..len])?;
                Ok(0)
            }
            SL_IOCTL_SSAP_FIND_SVC => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let services = s.ssap.find_primary_services();
                // SAFETY: SsapServiceList is repr(C).
                let mut list: SsapServiceList = unsafe { core::mem::zeroed() };
                let count = services.len().min(15);
                list.count = count as u16;
                for (i, (start, end, uuid)) in services.iter().take(15).enumerate() {
                    list.services[i].start_handle = *start;
                    list.services[i].end_handle = *end;
                    list.services[i].uuid16 = uuid.as_u16().unwrap_or(0);
                    list.services[i].primary = 1;
                }
                drop(ss);
                write_user_struct(arg, &list)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_NOTIFY => {
                let handle: u16 = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.ssap.notify(handle)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_DEQUEUE_NTF => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let ntf = s.ssap.dequeue_notification();
                match ntf {
                    Some(n) => {
                        // SAFETY: SsapNotification is repr(C).
                        let mut out: SsapNotification = unsafe { core::mem::zeroed() };
                        out.handle = n.handle;
                        out.indication = if n.indication { 1 } else { 0 };
                        let copy_len = n.data.len().min(252);
                        out.length = copy_len as u8;
                        out.data[..copy_len].copy_from_slice(&n.data[..copy_len]);
                        drop(ss);
                        write_user_struct(arg, &out)?;
                        Ok(0)
                    }
                    None => Err(EAGAIN),
                }
            }
            SL_IOCTL_SSAP_ADD_SVC => {
                let mut cmd: SsapAddService = read_user_struct(arg)?;
                let uuid = if cmd.uuid16 != 0 {
                    sle_ssap::SsapUuid::Uuid16(cmd.uuid16)
                } else {
                    sle_ssap::SsapUuid::Uuid128(cmd.uuid128)
                };
                let primary = cmd.primary != 0;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let handle = s.ssap.register_service(uuid, primary)?;
                cmd.start_handle = handle;
                drop(ss);
                write_user_struct(arg, &cmd)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_ADD_PROP => {
                let mut cmd: SsapAddProperty = read_user_struct(arg)?;
                let uuid = sle_ssap::SsapUuid::Uuid16(cmd.uuid16);
                let ops = sle_ssap::OpIndicator::from_raw(cmd.ops as u32);
                let len = (cmd.value_len as usize).min(248);
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let handle = s.ssap.add_property(uuid, ops, &cmd.value[..len])?;
                cmd.handle = handle;
                drop(ss);
                write_user_struct(arg, &cmd)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_REMOVE_SVC => {
                let start_handle: u16 = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.ssap.remove_service(start_handle)?;
                Ok(0)
            }
            // --- Power management ---
            SL_IOCTL_PM_INFO => {
                let info = {
                    let ss = SUBSYSTEM.lock();
                    let s = ss.as_ref().ok_or(ENODEV)?;
                    // SAFETY: SlePmInfo is repr(C).
                    let mut info: SlePmInfo = unsafe { core::mem::zeroed() };
                    info.state = s.power.state as u8;
                    info.force_active = if s.power.is_forced_active() { 1 } else { 0 };
                    info.power_pct = s.power.estimated_power_pct();
                    info.current_interval = s.power.interval.current_interval;
                    info.supervision_timeout = s.power.interval.supervision_timeout;
                    info.latency = s.power.interval.latency;
                    info.idle_count = s.power.stats.active_events.min(u16::MAX as u64) as u16;
                    info.transitions = s.power.stats.transitions;
                    info.active_events = s.power.stats.active_events;
                    info.sniff_events = s.power.stats.sniff_events;
                    info.idle_events = s.power.stats.idle_events;
                    info
                };
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_PM_SET_STATE => {
                let cmd_data: SlePmStateCmd = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                match cmd_data.target_state {
                    0 => { s.power.resume(); Ok(0) }
                    1 => { s.power.on_activity(); s.power.force_active(false); Ok(0) }
                    3 => { s.power.suspend()?; Ok(0) }
                    _ => Err(EINVAL),
                }
            }
            SL_IOCTL_PM_SET_INTERVAL => {
                let params: SlePmInterval = read_user_struct(arg)?;
                let interval = sle_power::ConnInterval {
                    min_interval: params.min_interval,
                    max_interval: params.max_interval,
                    current_interval: params.min_interval,
                    latency: params.latency,
                    supervision_timeout: params.supervision_timeout,
                };
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.power.update_interval(interval)?;
                Ok(0)
            }
            SL_IOCTL_PM_FORCE_ACTIVE => {
                let enable: u8 = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.power.force_active(enable != 0);
                Ok(0)
            }
            SL_IOCTL_PM_TICK => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.power.on_tick();
                Ok(0)
            }
            SL_IOCTL_PM_ACTIVITY => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.power.on_activity();
                Ok(0)
            }
            // --- Event notification ---
            SL_IOCTL_EVENT_COUNT => {
                let count = me.events.lock().pending();
                Ok(count as isize)
            }
            SL_IOCTL_EVENT_STATS => {
                let guard = me.events.lock();
                let stats = SleEventStats {
                    pending: guard.pending() as u32,
                    _pad: 0,
                    total_enqueued: guard.total_enqueued,
                    total_dropped: guard.total_dropped,
                    total_delivered: guard.total_delivered,
                };
                drop(guard);
                write_user_struct(arg, &stats)?;
                Ok(0)
            }
            // --- DLI controller info ---
            SL_IOCTL_DLI_INFO => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let cinfo = s.controller.info();
                let mut name = [0u8; 32];
                let copy_len = cinfo.name.len().min(31);
                name[..copy_len].copy_from_slice(&cinfo.name[..copy_len]);
                let info = SleDliInfo {
                    bus: cinfo.bus as u8,
                    _pad: [0u8; 3],
                    firmware_version: cinfo.fw_version,
                    features: cinfo.features,
                    max_connections: cinfo.max_connections,
                    max_adv_sets: 1,
                    transport_modes: cinfo.transport_modes,
                    measurement_cap: cinfo.measurement_cap,
                    max_mtu: cinfo.max_mtu,
                    max_mps: cinfo.max_mps,
                    security_cap: cinfo.security_cap,
                    name,
                    _reserved: [0u8; 6],
                };
                drop(ss);
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            // --- DLI event polling ---
            SL_IOCTL_DLI_POLL_EVENT => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                // Try DLI event ring first (events already consumed by EventPump).
                if let Some(dli_ev) = s.pop_dli_event() {
                    drop(ss);
                    write_user_struct(arg, &dli_ev)?;
                    return Ok(0);
                }
                // Fallback: poll controller directly (EventPump hasn't run yet).
                match s.controller.poll_event() {
                    Some(ev) => {
                        let dli_ev = sle_dli_event_to_wire(&ev);
                        drop(ss);
                        write_user_struct(arg, &dli_ev)?;
                        Ok(0)
                    }
                    None => Err(EAGAIN),
                }
            }
            // --- DLI controller reset ---
            SL_IOCTL_DLI_RESET => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.controller.reset()?;
                Ok(0)
            }
            // --- DLI send command (management plane, async dispatch) ---
            SL_IOCTL_DLI_SEND_CMD => {
                let mut cmd: SleDliCmd = read_user_struct(arg)?;
                let param_len = (cmd.param_len as usize).min(240);

                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;

                // Enqueue to command request queue first — if this fails,
                // no pending entry is leaked.
                s.cmd_queue.push(cmd.opcode, &cmd.params[..param_len])?;

                // Only create the pending tracking entry after the command
                // is successfully enqueued for dispatch.
                let seq = s.cmd_pending.submit(cmd.opcode)?;

                // Kick the command worker to dispatch.
                if let Some(ref w) = s._cmd_worker {
                    w.kick();
                }

                cmd.seq = seq;
                drop(ss);
                write_user_struct(arg, &cmd)?;
                Ok(0)
            }
            // --- Management plane statistics ---
            SL_IOCTL_MGMT_STATS => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let stats = SleMgmtStats {
                    pending: s.cmd_pending.pending(),
                    _pad: 0,
                    total_submitted: s.cmd_pending.total_submitted as u32,
                    total_resolved: s.cmd_pending.total_resolved as u32,
                    total_timeouts: s.cmd_pending.total_timeouts as u32,
                };
                drop(ss);
                write_user_struct(arg, &stats)?;
                Ok(0)
            }
            SL_IOCTL_SUBSYS_STATS => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let stats = SleSubsysStats {
                    dev_count: s.dev_registry.count() as u16,
                    proto_count: s.proto_registry.count(),
                    binding_count: s.dev_bindings.count(),
                    active_connections: s.conn.active_count() as u16,
                    mgmt_pending: s.cmd_pending.pending_count,
                    total_conn_created: s.conn.total_created as u32,
                    total_conn_completed: s.conn.total_completed as u32,
                    total_mgmt_submitted: s.cmd_pending.total_submitted as u32,
                    total_mgmt_timeouts: s.cmd_pending.total_timeouts as u32,
                    power_state: s.power.state as u8,
                    _pad: [0; 3],
                    power_transitions: s.power.stats.transitions,
                };
                drop(ss);
                write_user_struct(arg, &stats)?;
                Ok(0)
            }
            // --- USB device discovery ---
            SL_IOCTL_USB_DEV_COUNT => {
                Ok(sle_usb::usb_device_count() as isize)
            }
            // --- PHY layer ---
            SL_IOCTL_PHY_INFO => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let mcs = sle_phy::mcs_lookup(s.phy.mcs_index);
                let info = SlePhyInfo {
                    mcs_index: s.phy.mcs_index,
                    bandwidth_mhz: s.phy.bandwidth_mhz,
                    pilot_density: s.phy.pilot_density,
                    tx_power_dbm: s.phy.tx_power_dbm,
                    mimo_mode: s.phy.antenna.mode as u8,
                    num_tx_ant: s.phy.antenna.num_tx,
                    num_rx_ant: s.phy.antenna.num_rx,
                    ofdm: if mcs.map_or(false, |m| m.ofdm) { 1 } else { 0 },
                    data_rate_kbps: s.phy.effective_data_rate_kbps(),
                    hop_channel: s.phy.hopping.last_channel,
                    hop_increment: s.phy.hopping.hop_increment,
                    hop_used_channels: s.phy.hopping.channel_map.used_count(),
                    modulation: mcs.map_or(0, |m| m.modulation as u8),
                    code_rate_num: mcs.map_or(0, |m| m.code_rate.num),
                    code_rate_den: mcs.map_or(0, |m| m.code_rate.den),
                    ..Default::default()
                };
                drop(ss);
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_PHY_SET_MCS => {
                let cmd: SlePhyMcsCmd = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.phy.set_mcs(cmd.mcs_index)?;
                let _ = s.controller.set_coding_modulation(cmd.mcs_index);
                Ok(0)
            }
            SL_IOCTL_PHY_SET_TXPOWER => {
                let cmd: SlePhyTxPowerCmd = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.phy.set_tx_power(cmd.tx_power_dbm)?;
                let _ = s.controller.set_tx_power(cmd.tx_power_dbm);
                Ok(0)
            }
            SL_IOCTL_PHY_MCS_SELECT => {
                let mut sel: SlePhyMcsSelect = read_user_struct(arg)?;
                let best = sle_phy::mcs_select(sel.min_kbps, sel.bandwidth_mhz, sel.sinr_db_x10);
                sel.selected_mcs = best;
                sel.effective_kbps = sle_phy::data_rate_kbps(best, sel.bandwidth_mhz)
                    .unwrap_or(0);
                write_user_struct(arg, &sel)?;
                Ok(0)
            }
            SL_IOCTL_PHY_HOP_NEXT => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let ch = s.phy.hopping.next_channel();
                let info = SlePhyHopInfo {
                    channel: ch,
                    freq_mhz: sle_phy::HoppingState::channel_to_freq(ch),
                    event_counter: s.phy.hopping.event_counter,
                    ..Default::default()
                };
                drop(ss);
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_PHY_SET_BW => {
                let cmd: SlePhyBwCmd = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.phy.set_bandwidth(cmd.bandwidth_mhz)?;
                let _ = s.controller.set_bandwidth(cmd.bandwidth_mhz);
                Ok(0)
            }
            SL_IOCTL_SET_ROLE => {
                let role_byte: u8 = read_user_struct(arg)?;
                let role = match role_byte {
                    0 => GtRole::TNode,
                    1 => GtRole::GNode,
                    _ => return Err(EINVAL),
                };
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                if s.conn.active_handles().1 > 0 {
                    dev_warn!(me.dev, "sparklink: cannot change role with active connections\n");
                    return Err(EBUSY);
                }
                s.local_role = role;
                dev_info!(me.dev, "sparklink: local role set to {:?}\n", role);
                Ok(0)
            }
            SL_IOCTL_GET_ROLE => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                write_user_struct(arg, &(s.local_role as u8))?;
                Ok(0)
            }
            _ => {
                dev_err!(me.dev, "sparklink: unknown ioctl 0x{:x}\n", cmd);
                Err(ENOTTY)
            }
        }
    }
}

impl SparkLinkCtl {
    /// Synchronize configfs power_mode into SubsystemShared.
    /// Called at the beginning of ioctls that initiate active operations.
    fn sync_power_mode(_me: Pin<&SparkLinkCtl>) {
        let configfs_mode = sle_configfs::power_mode();
        let mut ss = SUBSYSTEM.lock();
        if let Some(ref mut shared) = *ss {
            let old_pct = shared.power.estimated_power_pct();
            if shared.power.set_mode(configfs_mode) {
                let new_pct = shared.power.estimated_power_pct();
                pr_info!(
                    "sparklink: power mode changed to {} ({}% -> {}%)\n",
                    configfs_mode, old_pct, new_pct
                );
                // Push a power changed event through per-fd EventQueue path
                // instead of broadcast ring (avoid pub visibility issue).
            }
        }
    }

    /// Check if the subsystem power mode allows active operations.
    /// Returns Err(EPERM) if in idle mode.
    fn check_power_active() -> Result {
        let mode = sle_configfs::power_mode();
        if mode >= 2 {
            // Idle or suspended — reject active operations.
            return Err(EPERM);
        }
        Ok(())
    }

    /// Synchronize events from the global broadcast ring into this fd's
    /// per-listener event queue. Called before read() and poll() so that
    /// all open fds see the same event stream regardless of which fd
    /// triggered the operation that produced the event.
    fn sync_broadcast(me: Pin<&SparkLinkCtl>) {
        let cur = sle_event::BroadcastRing::current_seq();
        let my_seq = me.last_seq.load(core::sync::atomic::Ordering::Relaxed);
        if cur <= my_seq {
            return; // no new events
        }
        let ss = SUBSYSTEM.lock();
        if let Some(ref shared) = *ss {
            let mut eq = me.events.lock();
            let (copied, new_seq) = shared.broadcast.drain_since(my_seq, &mut eq);
            if copied > 0 {
                me.last_seq.store(new_seq, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Publish an event to the global broadcast ring (visible to all fds)
    /// and also push it into this fd's local queue for immediate reads.
    fn broadcast_event(me: Pin<&SparkLinkCtl>, event: sle_event::SleWireEvent) {
        {
            let mut ss = SUBSYSTEM.lock();
            if let Some(ref mut shared) = *ss {
                shared.broadcast.publish(event);
            }
        }
        // Also push directly to this fd so the caller gets immediate read.
        me.events.lock().push_raw(event);
        let new_seq = sle_event::BroadcastRing::current_seq();
        me.last_seq.store(new_seq, core::sync::atomic::Ordering::Relaxed);
        me.event_poll.notify_all();
    }
}

#[pinned_drop]
impl PinnedDrop for SparkLinkCtl {
    fn drop(self: Pin<&mut Self>) {
        OPEN_FD_COUNT.fetch_add(u32::MAX, Relaxed); // wrapping decrement
        dev_info!(self.dev, "sparklink: control interface closed\n");
    }
}
