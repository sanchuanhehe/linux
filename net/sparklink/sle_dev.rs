// SPDX-License-Identifier: GPL-2.0

//! SparkLink device model (per-controller kernel object).
//!
//! Provides the `SleDev` struct — the SparkLink equivalent of Bluetooth's
//! `hci_dev`.  Each registered `SleDev` represents a single SLE controller
//! attached via a transport bus (UART, USB, SPI, SDIO, or virtual loopback).
//!
//! The global `SLE_DEV_REGISTRY` tracks all registered devices and provides
//! index-based lookup.  Device lifecycle is modelled as a set of atomic
//! flags that gate operations like advertising, scanning, and connecting.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};
use kernel::prelude::*;

use crate::sle_dli::{SleBus, SleControllerInfo};

// ---------------------------------------------------------------------------
// Device state flags (bitfield, similar to HCI_* flags in bluetooth)
// ---------------------------------------------------------------------------

/// Device has been inserted into the global registry.
pub(crate) const SLE_DEV_REGISTERED: u32 = 1 << 0;
/// Device is up and ready for operations.
pub(crate) const SLE_DEV_UP: u32 = 1 << 1;
/// Device is performing initial setup / firmware handshake.
pub(crate) const SLE_DEV_SETUP: u32 = 1 << 2;
/// Device is being torn down (unregister in progress).
pub(crate) const SLE_DEV_UNREGISTERING: u32 = 1 << 3;
/// Device is actively advertising.
pub(crate) const SLE_DEV_ADVERTISING: u32 = 1 << 4;
/// Device is actively scanning.
pub(crate) const SLE_DEV_SCANNING: u32 = 1 << 5;
/// Device has at least one active connection.
pub(crate) const SLE_DEV_CONNECTED: u32 = 1 << 6;
/// Device radio is suspended (low-power state).
pub(crate) const SLE_DEV_SUSPENDED: u32 = 1 << 7;

// ---------------------------------------------------------------------------
// Per-device statistics
// ---------------------------------------------------------------------------

/// Cumulative statistics for a single SleDev.
#[derive(Default)]
pub(crate) struct SleDevStats {
    /// Total commands sent to controller.
    pub(crate) cmd_tx: u64,
    /// Total events received from controller.
    pub(crate) evt_rx: u64,
    /// Total data bytes sent.
    pub(crate) data_tx_bytes: u64,
    /// Total data bytes received.
    pub(crate) data_rx_bytes: u64,
    /// Count of hardware errors reported.
    pub(crate) hw_errors: u32,
    /// Count of command timeouts.
    pub(crate) cmd_timeouts: u32,
}

// ---------------------------------------------------------------------------
// SleDev — per-controller device object
// ---------------------------------------------------------------------------

/// Maximum device name length (including NUL terminator).
const SLE_DEV_NAME_LEN: usize = 16;

/// Per-controller device object, analogous to Bluetooth's `hci_dev`.
///
/// Tracks device identity (index, name, address, bus type), lifecycle
/// state (atomic flags), controller capabilities, and runtime statistics.
///
/// The actual protocol state (connections, advertising, security, etc.)
/// remains in `SubsystemShared`.  `SleDev` provides the device-model
/// layer that was previously missing — identity, lifecycle gating, and
/// multi-controller awareness.
pub(crate) struct SleDev {
    /// Unique device index (0-based), allocated from `SleDevRegistry`.
    pub(crate) id: u16,
    /// Device name, e.g. `"sle0"`, NUL-terminated.
    pub(crate) name: [u8; SLE_DEV_NAME_LEN],
    /// Transport bus type.
    pub(crate) bus: SleBus,
    /// 6-byte SLE MAC address.
    pub(crate) addr: [u8; 6],
    /// Lifecycle and operational state flags (see `SLE_DEV_*` constants).
    flags: AtomicU32,
    /// Firmware version (packed major.minor.patch).
    fw_version: u32,
    /// Feature bitmask from controller info.
    features: u64,
    /// Maximum concurrent connections.
    max_connections: u8,
    /// Cumulative device statistics.
    pub(crate) stats: SleDevStats,
}

impl SleDev {
    /// Create a new `SleDev` from controller info. The device starts in
    /// the `SETUP` state with no flags set until `setup_complete()` is called.
    pub(crate) fn new(id: u16, info: &SleControllerInfo) -> Self {
        let mut name = [0u8; SLE_DEV_NAME_LEN];
        // Format name as "sleN\0".
        let prefix = b"sle";
        name[..prefix.len()].copy_from_slice(prefix);
        // Simple itoa for small ids (0..999).
        let id_val = id as usize;
        if id_val < 10 {
            name[3] = b'0' + id_val as u8;
        } else if id_val < 100 {
            name[3] = b'0' + (id_val / 10) as u8;
            name[4] = b'0' + (id_val % 10) as u8;
        } else {
            name[3] = b'0' + (id_val / 100) as u8;
            name[4] = b'0' + ((id_val / 10) % 10) as u8;
            name[5] = b'0' + (id_val % 10) as u8;
        }

        Self {
            id,
            name,
            bus: info.bus,
            addr: info.addr,
            flags: AtomicU32::new(SLE_DEV_SETUP),
            fw_version: info.fw_version,
            features: info.features,
            max_connections: info.max_connections,
            stats: SleDevStats::default(),
        }
    }

    // -- Identity accessors ------------------------------------------------

    /// Device index.
    pub(crate) fn id(&self) -> u16 {
        self.id
    }

    /// Device name as a byte slice (without trailing NUL bytes).
    pub(crate) fn name(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(SLE_DEV_NAME_LEN);
        &self.name[..end]
    }

    /// Transport bus type.
    pub(crate) fn bus(&self) -> SleBus {
        self.bus
    }

    /// 6-byte SLE MAC address.
    pub(crate) fn addr(&self) -> &[u8; 6] {
        &self.addr
    }

    /// Firmware version.
    pub(crate) fn fw_version(&self) -> u32 {
        self.fw_version
    }

    /// Feature bitmask.
    pub(crate) fn features(&self) -> u64 {
        self.features
    }

    /// Maximum connections the controller supports.
    pub(crate) fn max_connections(&self) -> u8 {
        self.max_connections
    }

    /// Update hardware info read back during probe (MAC, firmware version).
    pub(crate) fn update_hw_info(&mut self, addr: [u8; 6], fw_version: u32) {
        self.addr = addr;
        self.fw_version = fw_version;
    }

    // -- Flag operations ---------------------------------------------------

    /// Test whether a flag is set.
    pub(crate) fn test_flag(&self, flag: u32) -> bool {
        self.flags.load(Ordering::Acquire) & flag != 0
    }

    /// Set a flag. Returns the previous flag state.
    pub(crate) fn set_flag(&self, flag: u32) -> u32 {
        self.flags.fetch_or(flag, Ordering::AcqRel)
    }

    /// Clear a flag. Returns the previous flag state.
    pub(crate) fn clear_flag(&self, flag: u32) -> u32 {
        self.flags.fetch_and(!flag, Ordering::AcqRel)
    }

    /// Return the raw flags word.
    pub(crate) fn flags(&self) -> u32 {
        self.flags.load(Ordering::Acquire)
    }

    // -- Lifecycle transitions ---------------------------------------------

    /// Mark setup as complete. Transitions from `SETUP` to `UP | REGISTERED`.
    pub(crate) fn setup_complete(&self) {
        self.flags.fetch_and(!SLE_DEV_SETUP, Ordering::AcqRel);
        self.flags
            .fetch_or(SLE_DEV_UP | SLE_DEV_REGISTERED, Ordering::AcqRel);
    }

    /// Check whether the device is operational (UP and not UNREGISTERING/SUSPENDED).
    pub(crate) fn is_up(&self) -> bool {
        let f = self.flags.load(Ordering::Acquire);
        (f & SLE_DEV_UP != 0) && (f & (SLE_DEV_UNREGISTERING | SLE_DEV_SUSPENDED) == 0)
    }

    /// Begin teardown. Sets `UNREGISTERING`, clears `UP`.
    pub(crate) fn begin_unregister(&self) {
        self.flags.fetch_or(SLE_DEV_UNREGISTERING, Ordering::AcqRel);
        self.flags.fetch_and(!SLE_DEV_UP, Ordering::AcqRel);
    }
}

// ---------------------------------------------------------------------------
// Global device registry
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously registered SparkLink controllers.
pub(crate) const SLE_DEV_MAX: usize = 16;

/// Global device registry. Access must be serialized by the caller
/// (currently the SUBSYSTEM Mutex already provides this guarantee).
pub(crate) struct SleDevRegistry {
    /// Slots for registered devices. `None` = slot free.
    slots: [Option<SleDev>; SLE_DEV_MAX],
    /// Bitmask of allocated IDs (bit N = 1 means slot N is occupied).
    allocated: u16,
}

impl SleDevRegistry {
    /// Create an empty registry.
    pub(crate) const fn new() -> Self {
        const NONE: Option<SleDev> = None;
        Self {
            slots: [NONE; SLE_DEV_MAX],
            allocated: 0,
        }
    }

    /// Register a new device from controller info. Returns the allocated
    /// device index on success, or `ENOSPC` if the registry is full.
    pub(crate) fn register(&mut self, info: &SleControllerInfo) -> Result<u16> {
        // Find first free bit.
        let free = (!self.allocated).trailing_zeros();
        if free as usize >= SLE_DEV_MAX {
            return Err(ENOSPC);
        }
        let id = free as u16;
        self.allocated |= 1 << id;

        let dev = SleDev::new(id, info);
        dev.setup_complete();
        self.slots[id as usize] = Some(dev);

        pr_info!("sparklink: registered device sle{} (bus={:?}, addr={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})\n",
            id,
            info.bus,
            info.addr[0], info.addr[1], info.addr[2],
            info.addr[3], info.addr[4], info.addr[5]);

        Ok(id)
    }

    /// Unregister a device by index. Returns `ENODEV` if not registered.
    pub(crate) fn unregister(&mut self, id: u16) -> Result {
        let idx = id as usize;
        if idx >= SLE_DEV_MAX || self.slots[idx].is_none() {
            return Err(ENODEV);
        }

        if let Some(ref dev) = self.slots[idx] {
            dev.begin_unregister();
            pr_info!("sparklink: unregistered device sle{}\n", id);
        }

        self.slots[idx] = None;
        self.allocated &= !(1 << id);
        Ok(())
    }

    /// Look up a device by index (immutable reference).
    pub(crate) fn get(&self, id: u16) -> Option<&SleDev> {
        self.slots.get(id as usize).and_then(|s| s.as_ref())
    }

    /// Look up a device by index (mutable reference).
    pub(crate) fn get_mut(&mut self, id: u16) -> Option<&mut SleDev> {
        self.slots.get_mut(id as usize).and_then(|s| s.as_mut())
    }

    /// Return the number of currently registered devices.
    pub(crate) fn count(&self) -> usize {
        self.allocated.count_ones() as usize
    }

    /// Iterate over all registered devices.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &SleDev> {
        self.slots.iter().filter_map(|s| s.as_ref())
    }

    /// Update hardware-read metadata for a registered device.
    ///
    /// Called after USB/serdev probe reads the real MAC and firmware version
    /// from the controller, so that the registry reflects actual hardware state.
    pub(crate) fn update_hw_info(&mut self, id: u16, addr: [u8; 6], fw_version: u32) {
        if let Some(dev) = self.get_mut(id) {
            dev.update_hw_info(addr, fw_version);
        }
    }

    /// Return the ID allocation bitmask.
    pub(crate) fn allocated_mask(&self) -> u16 {
        self.allocated
    }
}
