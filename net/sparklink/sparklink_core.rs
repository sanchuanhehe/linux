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

use kernel::{
    device::Device,
    fs::File,
    ioctl::{_IO, _IOC_SIZE, _IOR, _IOW},
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    new_mutex,
    prelude::*,
    sync::{aref::ARef, Arc, Mutex},
};

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
    adv_params: Option<SleAdvParams>,
    scan_params: Option<SleScanParams>,
}

/// An SCI device represents a single SparkLink controller.
#[allow(dead_code)]
pub struct SciDevEntry {
    /// SCI device index.
    pub index: u16,
    /// Transport bus type.
    pub bus: SciBus,
    /// SLE address.
    pub addr: SleAddr,
    /// Device name (UTF-8, null-padded).
    pub name: [u8; 32],
    inner: Mutex<SciDevInner>,
}

// ---------------------------------------------------------------------------
// Global device registry
// ---------------------------------------------------------------------------

/// Global state: the list of all registered SCI devices.
#[allow(dead_code)]
struct SparkLinkState {
    devices: KVec<Arc<SciDevEntry>>,
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
}

impl kernel::InPlaceModule for SparkLinkModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        pr_info!("sparklink: initialising SparkLink subsystem v0.1.0\n");

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
// Misc device implementation: /dev/sparklink control interface
// ---------------------------------------------------------------------------

#[pin_data(PinnedDrop)]
struct SparkLinkCtl {
    #[pin]
    inner: Mutex<SparkLinkCtlInner>,
    dev: ARef<Device>,
}

struct SparkLinkCtlInner {
    _placeholder: u32,
}

#[vtable]
impl MiscDevice for SparkLinkCtl {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &File, misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let dev = ARef::from(misc.device());
        dev_info!(dev, "sparklink: control interface opened\n");

        KBox::try_pin_init(
            try_pin_init! {
                SparkLinkCtl {
                    inner <- new_mutex!(SparkLinkCtlInner {
                        _placeholder: 0,
                    }),
                    dev: dev,
                }
            },
            GFP_KERNEL,
        )
    }

    fn ioctl(me: Pin<&SparkLinkCtl>, _file: &File, cmd: u32, _arg: usize) -> Result<isize> {
        let _size = _IOC_SIZE(cmd);

        match cmd {
            SL_IOCTL_DEV_COUNT => {
                dev_info!(me.dev, "sparklink: DEV_COUNT query\n");
                // Placeholder: return 0 devices
                Ok(0)
            }
            SL_IOCTL_DEV_REGISTER => {
                dev_info!(me.dev, "sparklink: DEV_REGISTER\n");
                Ok(0)
            }
            SL_IOCTL_DEV_UNREGISTER => {
                dev_info!(me.dev, "sparklink: DEV_UNREGISTER\n");
                Ok(0)
            }
            SL_IOCTL_START_ADV => {
                dev_info!(me.dev, "sparklink: START_ADV\n");
                Ok(0)
            }
            SL_IOCTL_STOP_ADV => {
                dev_info!(me.dev, "sparklink: STOP_ADV\n");
                Ok(0)
            }
            SL_IOCTL_START_SCAN => {
                dev_info!(me.dev, "sparklink: START_SCAN\n");
                Ok(0)
            }
            SL_IOCTL_STOP_SCAN => {
                dev_info!(me.dev, "sparklink: STOP_SCAN\n");
                Ok(0)
            }
            _ => {
                dev_err!(me.dev, "sparklink: unknown ioctl {}\n", cmd);
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
