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
mod sle_event;
mod sle_usb;
mod sle_netlink;

use sle_dli::SleController;

use kernel::{
    bindings,
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
        Arc, Mutex,
    },
    transmute::FromBytes,
    uaccess::{UserPtr, UserSlice},
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
    /// Discovery level (see `DiscoveryLevel`).
    pub discovery_level: u8,
    /// Advertising interval in milliseconds.
    pub interval_ms: u16,
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
    /// Controller name (null-terminated).
    pub name: [u8; 32],
    _reserved: [u8; 14],
}

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
// Global device registry (placeholder for future multi-device support)
// ---------------------------------------------------------------------------

/// Global state: placeholder for future multi-device support.
/// Multi-device registry will be integrated when the kernel MiscDevice API
/// supports passing user data from module init to the open() callback.
struct SparkLinkState {
    #[allow(dead_code)]
    next_index: u16,
}

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

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
    #[pin]
    state: Arc<Mutex<SparkLinkState>>,
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
    _dli_info: File<CString>,
}

impl kernel::InPlaceModule for SparkLinkModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        pr_info!("sparklink: initialising SparkLink subsystem v0.3.0\n");

        let state = Arc::pin_init(
            new_mutex!(SparkLinkState {
                next_index: 0,
            }),
            GFP_KERNEL,
        );

        let options = MiscDeviceOptions {
            name: c"sparklink",
        };

        let debugfs = Dir::new(c"sparklink");

        try_pin_init!(Self {
            _miscdev <- MiscDeviceRegistration::register(options),
            state <- state,
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
            _dli_info <- {
                let ctrl = sle_dli::VirtualController::new([0x5E, 0, 0, 0, 0, 1]);
                let cinfo = ctrl.info();
                let major = (cinfo.fw_version >> 16) & 0xFF;
                let minor = (cinfo.fw_version >> 8) & 0xFF;
                let patch = cinfo.fw_version & 0xFF;
                debugfs.read_only_file(
                    c"dli_controller",
                    CString::try_from_fmt(fmt!(
                        "bus: {:?}\nfirmware: {}.{}.{}\nfeatures: 0x{:016x}\nmax_connections: {}",
                        cinfo.bus, major, minor, patch,
                        cinfo.features, cinfo.max_connections
                    ))?,
                )
            },
            _debugfs: debugfs,
        })
    }
}

// ---------------------------------------------------------------------------
// Global state accessor — store a clone of the Arc in each open file handle
// ---------------------------------------------------------------------------
// The MiscDevice trait doesn't give us access to SparkLinkModule directly,
// so we store the global state Arc inside each SparkLinkCtl instance.
// For now, since MiscDeviceRegistration doesn't carry user data to open(),
// we use a simpler approach: each SparkLinkCtl gets its own per-fd state.
// Full global registry integration will follow when the kernel API supports
// registering user data on MiscDeviceRegistration.

// ---------------------------------------------------------------------------
// Misc device implementation: /dev/sparklink control interface
// ---------------------------------------------------------------------------

#[pin_data(PinnedDrop)]
struct SparkLinkCtl {
    #[pin]
    adv_scan: Mutex<AdvScanInner>,
    #[pin]
    conn: Mutex<ConnManager>,
    #[pin]
    security: Mutex<SecurityInner>,
    #[pin]
    ssap: Mutex<SsapInner>,
    #[pin]
    power: Mutex<PowerInner>,
    #[pin]
    events: Mutex<EventQueue>,
    #[pin]
    event_poll: PollCondVar,
    dev: ARef<Device>,
}

#[vtable]
impl MiscDevice for SparkLinkCtl {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &FsFile, misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let dev = ARef::from(misc.device());
        dev_info!(dev, "sparklink: control interface opened\n");

        let addr = [0x5E, 0x00, 0x00, 0x00, 0x00, 0x01];
        let name = b"sparklink-ctl";

        KBox::try_pin_init(
            try_pin_init! {
                SparkLinkCtl {
                    adv_scan <- new_mutex!(AdvScanInner::new(addr, name)),
                    conn <- new_mutex!(ConnManager::new(addr)),
                    security <- new_mutex!(SecurityInner::new()),
                    ssap <- new_mutex!(SsapInner::new()),
                    power <- new_mutex!(PowerInner::new()),
                    events <- new_mutex!(EventQueue::new()),
                    event_poll <- new_poll_condvar!("sparklink_event"),
                    dev: dev,
                }
            },
            GFP_KERNEL,
        )
    }

    fn read_iter(kiocb: Kiocb<'_, Self::Ptr>, iov: &mut IovIterDest<'_>) -> Result<usize> {
        let me = kiocb.file();
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
        let guard = me.events.lock();
        let mut mask = 0u32;
        if guard.has_events() {
            mask |= bindings::POLLIN | bindings::POLLRDNORM;
        }
        mask
    }

    fn ioctl(me: Pin<&SparkLinkCtl>, _file: &FsFile, cmd: u32, arg: usize) -> Result<isize> {
        match cmd {
            SL_IOCTL_START_ADV => {
                let uparams: SleAdvParams = read_user_struct(arg)?;
                let params = AdvParams {
                    discovery_level: uparams.discovery_level,
                    interval_slots: (uparams.interval_ms as u32) * 8, // ms to 125us slots
                    broadcast_type: sle_pdu::BroadcastType::AccessibleScannable,
                    tx_power: 0,
                };
                let mut guard = me.adv_scan.lock();
                guard.start_advertising(params)?;
                // Build and log the first PDU as a sanity check
                if let Some(pdu) = guard.build_adv_pdu() {
                    dev_info!(
                        me.dev,
                        "sparklink: ADV PDU built, {} bytes data, CRC=0x{:03x}\n",
                        pdu.data_len,
                        pdu.crc
                    );
                }
                Ok(0)
            }
            SL_IOCTL_STOP_ADV => {
                me.adv_scan.lock().stop_advertising()?;
                Ok(0)
            }
            SL_IOCTL_START_SCAN => {
                let uparams: SleScanParams = read_user_struct(arg)?;
                let params = ScanParams {
                    window_slots: (uparams.window_ms as u32) * 8,
                    interval_slots: (uparams.interval_ms as u32) * 8,
                    filter_level: uparams.filter_discovery_level,
                    active: false,
                };
                me.adv_scan.lock().start_scanning(params)?;
                Ok(0)
            }
            SL_IOCTL_STOP_SCAN => {
                me.adv_scan.lock().stop_scanning()?;
                Ok(0)
            }
            SL_IOCTL_DEV_COUNT => {
                // Per-fd design: each open fd has exactly one virtual controller.
                Ok(1)
            }
            SL_IOCTL_DEV_INFO => {
                let guard = me.adv_scan.lock();
                // SAFETY: SciDevInfo is repr(C) with only primitive fields.
                let mut info: SciDevInfo = unsafe { core::mem::zeroed() };
                info.index = 0;
                info.state = match (guard.is_advertising(), guard.is_scanning()) {
                    (true, _) => SciState::Advertising as u8,
                    (_, true) => SciState::Scanning as u8,
                    _ => SciState::Idle as u8,
                };
                info.bus = SciBus::Virtual as u8;
                info.addr = SleAddr { b: [0x5E, 0x00, 0x00, 0x00, 0x00, 0x01] };
                let name = b"sparklink-ctl";
                info.name[..name.len()].copy_from_slice(name);
                drop(guard);
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_DEV_REGISTER => {
                dev_info!(me.dev, "sparklink: DEV_REGISTER (stub)\n");
                Ok(0)
            }
            SL_IOCTL_DEV_UNREGISTER => {
                dev_info!(me.dev, "sparklink: DEV_UNREGISTER (stub)\n");
                Ok(0)
            }
            SL_IOCTL_INJECT_ADV => {
                let inject: SleInjectAdv = read_user_struct(arg)?;

                // Build a fake AdvPdu from the injected data
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

                let mut guard = me.adv_scan.lock();
                guard.process_adv_pdu(&pdu, inject.rssi)?;
                drop(guard);
                let name_len = (inject.name_len as usize).min(31);
                me.events.lock().push_adv_report(
                    inject.addr,
                    inject.rssi,
                    inject.discovery_level,
                    &inject.name[..name_len],
                );
                me.event_poll.notify_all();
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
                let count = me.adv_scan.lock().scan_result_count();
                Ok(count as isize)
            }
            // --- Connection management ---
            SL_IOCTL_CONNECT => {
                let cp: SleConnectParams = read_user_struct(arg)?;
                let role = if cp.gt_role == 1 {
                    GtRole::GNode
                } else {
                    GtRole::TNode
                };
                let handle = me.conn.lock().connect(cp.peer_addr, role)?;
                me.events.lock().push_conn_state(handle, 0, 1, cp.peer_addr, 0);
                me.event_poll.notify_all();
                Ok(handle as isize)
            }
            SL_IOCTL_DISCONNECT => {
                let handle: u16 = read_user_struct(arg)?;
                let mut guard = me.conn.lock();
                let handle = guard.resolve_handle(handle)?;
                let peer_addr = guard.info(handle).map(|e| e.peer_addr).unwrap_or([0u8; 6]);
                let old_state = guard.info(handle).map(|e| e.state as u8).unwrap_or(0);
                guard.disconnect(handle)?;
                drop(guard);
                me.events.lock().push_conn_state(handle, old_state, 0, peer_addr, 0);
                me.event_poll.notify_all();
                Ok(0)
            }
            SL_IOCTL_CONN_INFO => {
                let req: SleConnInfo = read_user_struct(arg)?;
                let guard = me.conn.lock();
                let handle = if req.handle == 0 {
                    // Legacy: find first active
                    let handles = guard.active_handles();
                    if handles.is_empty() {
                        return Err(EPIPE);
                    }
                    handles[0]
                } else {
                    req.handle
                };
                let entry = guard.info(handle)?;
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
                drop(guard);
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_CONN_SEND => {
                let cd: SleConnData = read_user_struct(arg)?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                let mut guard = me.conn.lock();
                let handle = guard.resolve_handle(cd.handle)?;
                let sent = guard.send(handle, &cd.data[..len])?;
                Ok(sent as isize)
            }
            SL_IOCTL_CONN_RECV => {
                let cd: SleConnData = read_user_struct(arg)?;
                let mut guard = me.conn.lock();
                let handle = guard.resolve_handle(cd.handle)?;
                let data_vec = guard.recv(handle)?;
                // Build SleConnData response
                // SAFETY: SleConnData is repr(C), zeroed gives all-zero which is valid.
                let mut out: SleConnData = unsafe { core::mem::zeroed() };
                out.handle = handle;
                let copy_len = data_vec.len().min(CONN_DATA_MAX);
                out.length = copy_len as u16;
                out.data[..copy_len].copy_from_slice(&data_vec[..copy_len]);
                drop(guard);
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
                let mut guard = me.conn.lock();
                let handle = guard.resolve_handle(resp.handle)?;
                let peer_addr = guard.info(handle).map(|e| e.peer_addr).unwrap_or([0u8; 6]);
                let result = guard.process_access_response(handle, resp_type, params);
                drop(guard);
                match &result {
                    Ok(()) => {
                        me.events.lock().push_conn_state(handle, 1, 2, peer_addr, 0);
                        me.event_poll.notify_all();
                    }
                    Err(_) => {
                        me.events.lock().push_conn_state(handle, 1, 0, peer_addr, resp.response_type);
                        me.event_poll.notify_all();
                    }
                }
                result.map(|()| 0isize)
            }
            SL_IOCTL_INJECT_CONN_DATA => {
                let cd: SleConnData = read_user_struct(arg)?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                let mut guard = me.conn.lock();
                let handle = guard.resolve_handle(cd.handle)?;
                let seq = {
                    let entry = guard.info(handle)?;
                    entry.seq.rx_seq
                };
                guard.receive_data(handle, &cd.data[..len], seq)?;
                drop(guard);
                me.events.lock().push_data_received(handle, len as u16);
                me.event_poll.notify_all();
                dev_info!(
                    me.dev,
                    "sparklink: injected {} bytes connection data (handle={})\n",
                    len,
                    handle
                );
                Ok(0)
            }
            SL_IOCTL_CONN_COUNT => {
                let count = me.conn.lock().active_count();
                Ok(count as isize)
            }
            SL_IOCTL_CONN_LIST => {
                let guard = me.conn.lock();
                let handles = guard.active_handles();
                // SAFETY: SleConnList is repr(C).
                let mut list: SleConnList = unsafe { core::mem::zeroed() };
                let count = handles.len().min(8);
                list.count = count as u16;
                for (i, &h) in handles.iter().take(8).enumerate() {
                    list.handles[i] = h;
                }
                drop(guard);
                write_user_struct(arg, &list)?;
                Ok(0)
            }
            // --- Security management ---
            SL_IOCTL_SEC_SET_PSK => {
                let params: SlePskParams = read_user_struct(arg)?;
                me.security.lock().set_psk(params.psk);
                Ok(0)
            }
            SL_IOCTL_SEC_PAIR => {
                let params: SlePairParams = read_user_struct(arg)?;
                let mut guard = me.security.lock();
                match params.method {
                    1 => guard.pair_just_works()?,
                    2 => guard.pair_psk()?,
                    _ => return Err(EINVAL),
                }
                Ok(0)
            }
            SL_IOCTL_SEC_INFO => {
                let info = {
                    let guard = me.security.lock();
                    // SAFETY: SleSecInfo is repr(C) with all u8 fields, no padding.
                    let mut info: SleSecInfo = unsafe { core::mem::zeroed() };
                    info.state = guard.state as u8;
                    info.method = guard.method as u8;
                    info.mode = guard.mode as u8;
                    info.enc_enabled = if guard.is_encrypted() { 1 } else { 0 };
                    info.enc_key_fingerprint = guard.enc_key_fingerprint();
                    info
                };
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_SEC_ENCRYPT_ON => {
                me.security.lock().enable_encryption()?;
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
                me.security.lock().encrypt_test(&mut cd.data[..len])?;
                write_user_struct(arg, &cd)?;
                Ok(0)
            }
            SL_IOCTL_SEC_SM4_DEC_TEST => {
                let mut cd: SleConnData = read_user_struct(arg)?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                me.security.lock().decrypt_test(&mut cd.data[..len])?;
                write_user_struct(arg, &cd)?;
                Ok(0)
            }
            // --- SSAP service layer ---
            SL_IOCTL_SSAP_REGISTER_SVC => {
                me.ssap.lock().register_device_info_service()?;
                Ok(0)
            }
            SL_IOCTL_SSAP_INFO => {
                let info = {
                    let guard = me.ssap.lock();
                    // SAFETY: SsapSummary is repr(C) with primitive fields.
                    let mut info: SsapSummary = unsafe { core::mem::zeroed() };
                    info.service_count = guard.service_count() as u16;
                    info.property_count = guard.property_count() as u16;
                    info.total_entries = guard.total_entries() as u16;
                    info.mtu = guard.negotiated.mtu;
                    info.notification_count = guard.notification_count() as u16;
                    info
                };
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_READ => {
                let rw: SsapReadWrite = read_user_struct(arg)?;
                let data = me.ssap.lock().read_property(rw.handle)?;

                // SAFETY: SsapReadWrite is repr(C).
                let mut out: SsapReadWrite = unsafe { core::mem::zeroed() };
                out.handle = rw.handle;
                let copy_len = data.len().min(252);
                out.length = copy_len as u16;
                out.data[..copy_len].copy_from_slice(&data[..copy_len]);
                write_user_struct(arg, &out)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_WRITE => {
                let rw: SsapReadWrite = read_user_struct(arg)?;
                let len = (rw.length as usize).min(252);
                me.ssap.lock().write_property(rw.handle, &rw.data[..len])?;
                Ok(0)
            }
            SL_IOCTL_SSAP_FIND_SVC => {
                let services = me.ssap.lock().find_primary_services();

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

                write_user_struct(arg, &list)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_NOTIFY => {
                let handle: u16 = read_user_struct(arg)?;
                me.ssap.lock().notify(handle)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_DEQUEUE_NTF => {
                let ntf = me.ssap.lock().dequeue_notification();
                match ntf {
                    Some(n) => {
                        // SAFETY: SsapNotification is repr(C).
                        let mut out: SsapNotification = unsafe { core::mem::zeroed() };
                        out.handle = n.handle;
                        out.indication = if n.indication { 1 } else { 0 };
                        let copy_len = n.data.len().min(252);
                        out.length = copy_len as u8;
                        out.data[..copy_len].copy_from_slice(&n.data[..copy_len]);
                        write_user_struct(arg, &out)?;
                        Ok(0)
                    }
                    None => Err(EAGAIN),
                }
            }
            // --- Power management ---
            SL_IOCTL_PM_INFO => {
                let info = {
                    let guard = me.power.lock();
                    // SAFETY: SlePmInfo is repr(C).
                    let mut info: SlePmInfo = unsafe { core::mem::zeroed() };
                    info.state = guard.state as u8;
                    info.force_active = if guard.is_forced_active() { 1 } else { 0 };
                    info.power_pct = guard.estimated_power_pct();
                    info.current_interval = guard.interval.current_interval;
                    info.supervision_timeout = guard.interval.supervision_timeout;
                    info.latency = guard.interval.latency;
                    info.idle_count = guard.stats.active_events.min(u16::MAX as u64) as u16;
                    info.transitions = guard.stats.transitions;
                    info.active_events = guard.stats.active_events;
                    info.sniff_events = guard.stats.sniff_events;
                    info.idle_events = guard.stats.idle_events;
                    info
                };
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_PM_SET_STATE => {
                let cmd_data: SlePmStateCmd = read_user_struct(arg)?;
                let mut guard = me.power.lock();
                match cmd_data.target_state {
                    0 => { guard.resume(); Ok(0) }
                    1 => { guard.on_activity(); guard.force_active(false); Ok(0) }
                    3 => { guard.suspend()?; Ok(0) }
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
                me.power.lock().update_interval(interval)?;
                Ok(0)
            }
            SL_IOCTL_PM_FORCE_ACTIVE => {
                let enable: u8 = read_user_struct(arg)?;
                me.power.lock().force_active(enable != 0);
                Ok(0)
            }
            SL_IOCTL_PM_TICK => {
                me.power.lock().on_tick();
                Ok(0)
            }
            SL_IOCTL_PM_ACTIVITY => {
                me.power.lock().on_activity();
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
                let ctrl = sle_dli::VirtualController::new([0x5E, 0, 0, 0, 0, 1]);
                let cinfo = ctrl.info();
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
                    name,
                    _reserved: [0u8; 14],
                };
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            _ => {
                dev_err!(me.dev, "sparklink: unknown ioctl 0x{:x}\n", cmd);
                Err(ENOTTY)
            }
        }
    }
}

#[pinned_drop]
impl PinnedDrop for SparkLinkCtl {
    fn drop(self: Pin<&mut Self>) {
        dev_info!(self.dev, "sparklink: control interface closed\n");
    }
}
