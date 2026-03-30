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

use kernel::{
    debugfs::{Dir, File},
    device::Device,
    fs::File as FsFile,
    ioctl::{_IO, _IOR, _IOW},
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    new_mutex,
    prelude::*,
    str::CString,
    sync::{
        aref::ARef,
        atomic::Atomic,
        Arc, Mutex,
    },
    transmute::FromBytes,
    uaccess::{UserPtr, UserSlice},
};

use sle_adv::{AdvParams, AdvScanInner, ScanParams};
use sle_conn::{AccessResponseType, ConnInner, GtRole, NegotiatedParams, CONN_DATA_MAX};
use sle_security::SecurityInner;
use sle_ssap::SsapInner;

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
#[allow(dead_code)]
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
const SL_IOCTL_CONNECT: u32 = _IOW::<SleConnectParams>(SL_MAGIC, 0x30);

/// Disconnect from the currently connected peer.
const SL_IOCTL_DISCONNECT: u32 = _IO(SL_MAGIC, 0x31);

/// Get connection status and statistics.
const SL_IOCTL_CONN_INFO: u32 = _IOR::<SleConnInfo>(SL_MAGIC, 0x32);

/// Send data on an established connection.
const SL_IOCTL_CONN_SEND: u32 = _IOW::<SleConnData>(SL_MAGIC, 0x33);

/// Receive data from an established connection.
const SL_IOCTL_CONN_RECV: u32 = _IOR::<SleConnData>(SL_MAGIC, 0x34);

/// Inject a simulated access response for loopback testing.
const SL_IOCTL_INJECT_CONN_RESP: u32 = _IOW::<SleInjectConnResp>(SL_MAGIC, 0x35);

/// Inject simulated received data for loopback testing.
const SL_IOCTL_INJECT_CONN_DATA: u32 = _IOW::<SleConnData>(SL_MAGIC, 0x36);

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
const SL_IOCTL_SSAP_READ: u32 = _IOW::<SsapReadWrite>(SL_MAGIC, 0x52);

/// Write a property by handle.
const SL_IOCTL_SSAP_WRITE: u32 = _IOW::<SsapReadWrite>(SL_MAGIC, 0x53);

/// Find primary services.
const SL_IOCTL_SSAP_FIND_SVC: u32 = _IOR::<SsapServiceList>(SL_MAGIC, 0x54);

/// Send a notification for a property handle.
const SL_IOCTL_SSAP_NOTIFY: u32 = _IOW::<u16>(SL_MAGIC, 0x55);

/// Dequeue one pending notification.
const SL_IOCTL_SSAP_DEQUEUE_NTF: u32 = _IOR::<SsapNotification>(SL_MAGIC, 0x56);

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
    _reserved: [u8; 12],
}

/// Data buffer for connection send/receive ioctls.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleConnData {
    /// Data payload length in bytes.
    pub length: u16,
    /// Data payload.
    pub data: [u8; 255],
    _reserved: u8,
}

impl Default for SleConnData {
    fn default() -> Self {
        Self {
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
    /// Response type (0=accepted, 1=role fail, 2=resource, 3=rejected).
    pub response_type: u8,
    /// Bandwidth in MHz for the accepted connection.
    pub bandwidth_mhz: u8,
    /// MCS index for the accepted connection.
    pub mcs_index: u8,
    _pad: u8,
    /// Supervision timeout in 10 ms units.
    pub supervision_timeout: u16,
    _reserved: [u8; 2],
}

impl Default for SleInjectConnResp {
    fn default() -> Self {
        Self {
            response_type: 0,
            bandwidth_mhz: 1,
            mcs_index: 4,
            _pad: 0,
            supervision_timeout: 100,
            _reserved: [0u8; 2],
        }
    }
}

// SAFETY: SleInjectConnResp is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleInjectConnResp {}

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
// SCI device: the core representation of a SparkLink controller
// ---------------------------------------------------------------------------

/// Internal mutable state of an SCI device.
#[allow(dead_code)]
struct SciDevInner {
    state: SciState,
    adv_scan: AdvScanInner,
}

/// An SCI device represents a single SparkLink controller.
#[allow(dead_code)]
#[pin_data]
pub struct SciDevEntry {
    /// SCI device index.
    pub index: u16,
    /// Transport bus type.
    pub bus: SciBus,
    /// SLE address.
    pub addr: SleAddr,
    /// Device name (UTF-8, null-padded).
    pub name: [u8; 32],
    #[pin]
    inner: Mutex<SciDevInner>,
}

impl SciDevEntry {
    /// Create a new SCI device entry.
    #[allow(dead_code)]
    fn new(index: u16, bus: SciBus, addr: SleAddr, name: [u8; 32]) -> impl PinInit<Self, Error> {
        let adv_scan = AdvScanInner::new(addr.b, &name);
        try_pin_init!(Self {
            index,
            bus,
            addr,
            name,
            inner <- new_mutex!(SciDevInner {
                state: SciState::Idle,
                adv_scan,
            }),
        })
    }
}

// ---------------------------------------------------------------------------
// Global device registry
// ---------------------------------------------------------------------------

/// Global state: the list of all registered SCI devices.
#[allow(dead_code)]
struct SparkLinkState {
    devices: KVec<Pin<KBox<SciDevEntry>>>,
    next_index: u16,
}

#[allow(dead_code)]
impl SparkLinkState {
    /// Register a new virtual SCI device for testing.
    fn register_virtual_device(&mut self) -> Result<u16> {
        let idx = self.next_index;
        let addr = SleAddr {
            b: [0x5E, 0x00, 0x00, 0x00, (idx >> 8) as u8, idx as u8],
        };
        let mut name = [0u8; 32];
        // "sparklink0", "sparklink1", ...
        let prefix = b"sparklink";
        name[..prefix.len()].copy_from_slice(prefix);
        // Append index digit(s) — simple single-digit for now
        let digit = b'0' + (idx % 10) as u8;
        name[prefix.len()] = digit;

        let dev = KBox::try_pin_init(
            SciDevEntry::new(idx, SciBus::Virtual, addr, name),
            GFP_KERNEL,
        )?;
        self.devices.push(dev, GFP_KERNEL)?;
        self.next_index = idx.checked_add(1).ok_or(EOVERFLOW)?;
        pr_info!("sparklink: registered device sci{}\n", idx);
        Ok(idx)
    }

    /// Unregister a device by index.
    fn unregister_device(&mut self, index: u16) -> Result {
        let pos = self
            .devices
            .iter()
            .position(|d| d.index == index)
            .ok_or(ENODEV)?;
        let _ = self.devices.remove(pos);
        pr_info!("sparklink: unregistered device sci{}\n", index);
        Ok(())
    }

    /// Find device by index.
    fn find_device(&self, index: u16) -> Option<&Pin<KBox<SciDevEntry>>> {
        self.devices.iter().find(|d| d.index == index)
    }
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
    adv_count: File<Atomic<usize>>,
    #[pin]
    scan_count: File<Atomic<usize>>,
}

impl kernel::InPlaceModule for SparkLinkModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        pr_info!("sparklink: initialising SparkLink subsystem v0.2.0\n");

        let state = Arc::pin_init(
            new_mutex!(SparkLinkState {
                devices: KVec::new(),
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
                CString::try_from_fmt(fmt!("sparklink 0.2.0"))?,
            ),
            adv_count <- debugfs.read_write_file(
                c"adv_count",
                Atomic::<usize>::new(0),
            ),
            scan_count <- debugfs.read_write_file(
                c"scan_count",
                Atomic::<usize>::new(0),
            ),
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
    conn: Mutex<ConnInner>,
    #[pin]
    security: Mutex<SecurityInner>,
    #[pin]
    ssap: Mutex<SsapInner>,
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
                    conn <- new_mutex!(ConnInner::new(addr)),
                    security <- new_mutex!(SecurityInner::new()),
                    ssap <- new_mutex!(SsapInner::new()),
                    dev: dev,
                }
            },
            GFP_KERNEL,
        )
    }

    fn ioctl(me: Pin<&SparkLinkCtl>, _file: &FsFile, cmd: u32, arg: usize) -> Result<isize> {
        match cmd {
            SL_IOCTL_START_ADV => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleAdvParams>(),
                );
                let mut reader = slice.reader();
                let uparams: SleAdvParams = reader.read()?;
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
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleScanParams>(),
                );
                let mut reader = slice.reader();
                let uparams: SleScanParams = reader.read()?;
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
                // Return scan result count when scanning, 0 otherwise
                let count = me.adv_scan.lock().scan_result_count();
                Ok(count as isize)
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
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleInjectAdv>(),
                );
                let mut reader = slice.reader();
                let inject: SleInjectAdv = reader.read()?;

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
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleConnectParams>(),
                );
                let mut reader = slice.reader();
                let cp: SleConnectParams = reader.read()?;
                let role = if cp.gt_role == 1 {
                    GtRole::GNode
                } else {
                    GtRole::TNode
                };
                me.conn.lock().connect(cp.peer_addr, role)?;
                Ok(0)
            }
            SL_IOCTL_DISCONNECT => {
                me.conn.lock().disconnect()?;
                Ok(0)
            }
            SL_IOCTL_CONN_INFO => {
                // Gather connection info while holding the lock
                let info = {
                    let guard = me.conn.lock();
                    // SAFETY: SleConnInfo is repr(C) with no implicit padding
                    // (fields ordered largest-first), zeroed ensures all bytes defined.
                    let mut info: SleConnInfo = unsafe { core::mem::zeroed() };
                    info.state = guard.state as u8;
                    info.peer_addr = guard.peer_addr;
                    info.local_role = guard.local_role as u8;
                    info.bandwidth_mhz = guard.params.bandwidth_mhz;
                    info.mcs_index = guard.params.mcs_index;
                    info.event_group_period = guard.params.event_group_period;
                    info.supervision_timeout = guard.params.supervision_timeout;
                    info.tx_seq = guard.seq.tx_seq;
                    info.rx_seq = guard.seq.rx_seq;
                    info.tx_pending = guard.tx_pending() as u16;
                    info.rx_pending = guard.rx_pending() as u16;
                    info.tx_bytes = guard.tx_bytes;
                    info.rx_bytes = guard.rx_bytes;
                    info
                };
                // Write back to userspace (lock released)
                // SAFETY: SleConnInfo is repr(C) and fully initialized via zeroed().
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        &info as *const SleConnInfo as *const u8,
                        core::mem::size_of::<SleConnInfo>(),
                    )
                };
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleConnInfo>(),
                );
                let mut writer = slice.writer();
                writer.write_slice(bytes)?;
                Ok(0)
            }
            SL_IOCTL_CONN_SEND => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleConnData>(),
                );
                let mut reader = slice.reader();
                let cd: SleConnData = reader.read()?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                let sent = me.conn.lock().send(&cd.data[..len])?;
                Ok(sent as isize)
            }
            SL_IOCTL_CONN_RECV => {
                let data_vec = me.conn.lock().recv()?;
                // Build SleConnData response
                // SAFETY: SleConnData is repr(C), zeroed gives all-zero which is valid.
                let mut cd: SleConnData = unsafe { core::mem::zeroed() };
                let copy_len = data_vec.len().min(CONN_DATA_MAX);
                cd.length = copy_len as u16;
                cd.data[..copy_len].copy_from_slice(&data_vec[..copy_len]);
                // Write to userspace
                // SAFETY: SleConnData is repr(C) and fully initialized via zeroed().
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        &cd as *const SleConnData as *const u8,
                        core::mem::size_of::<SleConnData>(),
                    )
                };
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleConnData>(),
                );
                let mut writer = slice.writer();
                writer.write_slice(bytes)?;
                Ok(0)
            }
            SL_IOCTL_INJECT_CONN_RESP => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleInjectConnResp>(),
                );
                let mut reader = slice.reader();
                let resp: SleInjectConnResp = reader.read()?;
                let resp_type = AccessResponseType::from_raw(resp.response_type)
                    .ok_or(EINVAL)?;
                let mut params = NegotiatedParams::default();
                params.bandwidth_mhz = resp.bandwidth_mhz;
                params.mcs_index = resp.mcs_index;
                params.supervision_timeout = resp.supervision_timeout;
                me.conn.lock().process_access_response(resp_type, params)?;
                Ok(0)
            }
            SL_IOCTL_INJECT_CONN_DATA => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleConnData>(),
                );
                let mut reader = slice.reader();
                let cd: SleConnData = reader.read()?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                let mut guard = me.conn.lock();
                let seq = guard.seq.rx_seq; // Use expected seq for loopback
                guard.receive_data(&cd.data[..len], seq)?;
                dev_info!(
                    me.dev,
                    "sparklink: injected {} bytes connection data\n",
                    len
                );
                Ok(0)
            }
            // --- Security management ---
            SL_IOCTL_SEC_SET_PSK => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SlePskParams>(),
                );
                let mut reader = slice.reader();
                let params: SlePskParams = reader.read()?;
                me.security.lock().set_psk(params.psk);
                Ok(0)
            }
            SL_IOCTL_SEC_PAIR => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SlePairParams>(),
                );
                let mut reader = slice.reader();
                let params: SlePairParams = reader.read()?;
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
                // SAFETY: SleSecInfo is repr(C) and fully initialized via zeroed().
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        &info as *const SleSecInfo as *const u8,
                        core::mem::size_of::<SleSecInfo>(),
                    )
                };
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleSecInfo>(),
                );
                let mut writer = slice.writer();
                writer.write_slice(bytes)?;
                Ok(0)
            }
            SL_IOCTL_SEC_ENCRYPT_ON => {
                me.security.lock().enable_encryption()?;
                Ok(0)
            }
            SL_IOCTL_SEC_SM3_TEST => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleHashTest>(),
                );
                let mut reader = slice.reader();
                let mut ht: SleHashTest = reader.read()?;
                let in_len = (ht.in_len as usize).min(220);
                let digest = SecurityInner::sm3_hash(&ht.data[..in_len]);
                ht.digest = digest;
                // Write back with digest filled in
                // SAFETY: SleHashTest is repr(C) and fully initialized.
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        &ht as *const SleHashTest as *const u8,
                        core::mem::size_of::<SleHashTest>(),
                    )
                };
                let out = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleHashTest>(),
                );
                let mut writer = out.writer();
                writer.write_slice(bytes)?;
                Ok(0)
            }
            SL_IOCTL_SEC_SM4_ENC_TEST => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleConnData>(),
                );
                let mut reader = slice.reader();
                let mut cd: SleConnData = reader.read()?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                me.security.lock().encrypt_test(&mut cd.data[..len])?;
                // Write the encrypted data back
                // SAFETY: SleConnData is repr(C) and fully initialized.
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        &cd as *const SleConnData as *const u8,
                        core::mem::size_of::<SleConnData>(),
                    )
                };
                let out = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleConnData>(),
                );
                let mut writer = out.writer();
                writer.write_slice(bytes)?;
                Ok(0)
            }
            SL_IOCTL_SEC_SM4_DEC_TEST => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleConnData>(),
                );
                let mut reader = slice.reader();
                let mut cd: SleConnData = reader.read()?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                me.security.lock().decrypt_test(&mut cd.data[..len])?;
                // SAFETY: SleConnData is repr(C) and fully initialized.
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        &cd as *const SleConnData as *const u8,
                        core::mem::size_of::<SleConnData>(),
                    )
                };
                let out = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SleConnData>(),
                );
                let mut writer = out.writer();
                writer.write_slice(bytes)?;
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
                // SAFETY: SsapSummary is repr(C) and fully initialized.
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        &info as *const SsapSummary as *const u8,
                        core::mem::size_of::<SsapSummary>(),
                    )
                };
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SsapSummary>(),
                );
                let mut writer = slice.writer();
                writer.write_slice(bytes)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_READ => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SsapReadWrite>(),
                );
                let mut reader = slice.reader();
                let rw: SsapReadWrite = reader.read()?;

                let data = me.ssap.lock().read_property(rw.handle)?;

                // SAFETY: SsapReadWrite is repr(C).
                let mut out: SsapReadWrite = unsafe { core::mem::zeroed() };
                out.handle = rw.handle;
                let copy_len = data.len().min(252);
                out.length = copy_len as u16;
                out.data[..copy_len].copy_from_slice(&data[..copy_len]);

                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        &out as *const SsapReadWrite as *const u8,
                        core::mem::size_of::<SsapReadWrite>(),
                    )
                };
                let wslice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SsapReadWrite>(),
                );
                let mut writer = wslice.writer();
                writer.write_slice(bytes)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_WRITE => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SsapReadWrite>(),
                );
                let mut reader = slice.reader();
                let rw: SsapReadWrite = reader.read()?;
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

                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        &list as *const SsapServiceList as *const u8,
                        core::mem::size_of::<SsapServiceList>(),
                    )
                };
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<SsapServiceList>(),
                );
                let mut writer = slice.writer();
                writer.write_slice(bytes)?;
                Ok(0)
            }
            SL_IOCTL_SSAP_NOTIFY => {
                let slice = UserSlice::new(
                    UserPtr::from_addr(arg),
                    core::mem::size_of::<u16>(),
                );
                let mut reader = slice.reader();
                let handle: u16 = reader.read()?;
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

                        let bytes = unsafe {
                            core::slice::from_raw_parts(
                                &out as *const SsapNotification as *const u8,
                                core::mem::size_of::<SsapNotification>(),
                            )
                        };
                        let slice = UserSlice::new(
                            UserPtr::from_addr(arg),
                            core::mem::size_of::<SsapNotification>(),
                        );
                        let mut writer = slice.writer();
                        writer.write_slice(bytes)?;
                        Ok(0)
                    }
                    None => Err(EAGAIN),
                }
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
