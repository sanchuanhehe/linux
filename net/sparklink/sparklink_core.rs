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

use kernel::{
    device::Device,
    fs::File,
    ioctl::{_IO, _IOR, _IOW},
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    new_mutex,
    prelude::*,
    sync::{aref::ARef, Arc, Mutex},
    transmute::FromBytes,
    uaccess::{UserPtr, UserSlice},
};

use sle_adv::{AdvParams, AdvScanInner, ScanParams};

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

        try_pin_init!(Self {
            _miscdev <- MiscDeviceRegistration::register(options),
            state <- state,
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
    dev: ARef<Device>,
}

#[vtable]
impl MiscDevice for SparkLinkCtl {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &File, misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let dev = ARef::from(misc.device());
        dev_info!(dev, "sparklink: control interface opened\n");

        let addr = [0x5E, 0x00, 0x00, 0x00, 0x00, 0x01];
        let name = b"sparklink-ctl";

        KBox::try_pin_init(
            try_pin_init! {
                SparkLinkCtl {
                    adv_scan <- new_mutex!(AdvScanInner::new(addr, name)),
                    dev: dev,
                }
            },
            GFP_KERNEL,
        )
    }

    fn ioctl(me: Pin<&SparkLinkCtl>, _file: &File, cmd: u32, arg: usize) -> Result<isize> {
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
