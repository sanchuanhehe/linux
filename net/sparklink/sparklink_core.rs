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

mod sle_adv;
mod sle_configfs;
mod sle_conn;
mod sle_crypto;
mod sle_dev;
mod sle_dli;
mod sle_event;
mod sle_fw;
mod sle_mgmt;
mod sle_netlink;
mod sle_pdu;
mod sle_phy;
mod sle_power;
mod sle_security;
mod sle_serdev;
mod sle_spi;
mod sle_ssap;
mod sle_transport;
mod sle_uapi;
mod sle_uart;
mod sle_usb;
mod sle_workers;

use sle_dli::SleController;
use sle_uapi::*;
use sle_workers::{drain_controller_events, send_credit_grant, CommandWorker, EventPump};

use kernel::configfs_attrs;
use kernel::sync::atomic::Relaxed;
use kernel::sync::Arc;
use kernel::{
    bindings, configfs,
    debugfs::{Dir, File},
    device::Device,
    fs::{File as FsFile, Kiocb},
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
    transmute::FromBytes,
    uaccess::{UserPtr, UserSlice},
};

use sle_adv::{AdvParams, AdvScanInner, ScanParams};
use sle_conn::{
    AccessResponseType, ConnManager, ConnState, GtRole, NegotiatedParams, CONN_DATA_MAX,
};
use sle_event::EventQueue;
use sle_power::PowerInner;
use sle_security::{RalEntry, RpaManager, SecurityInner};
use sle_ssap::SsapInner;

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
/// `T` must be `repr(C)` with only primitive fields and fully initialized
/// (typically via `core::mem::zeroed()` followed by field assignments) so
/// that converting it to a byte slice is defined behaviour.
fn write_user_struct<T: Sized>(arg: usize, val: &T) -> Result {
    // SAFETY: T is repr(C) with only primitive fields, caller guarantees
    // the value is fully initialized.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            core::ptr::from_ref::<T>(val).cast::<u8>(),
            core::mem::size_of::<T>(),
        )
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
            shared.local_role = if role == 1 {
                GtRole::GNode
            } else {
                GtRole::TNode
            };
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
    /// Data channel MTU.
    pub data_mtu: u16,
    /// Data channel MPS.
    pub data_mps: u16,
    /// Service management channel MTU.
    pub svc_mtu: u16,
    /// Data channel transport mode (0=unreliable, 1=reliable).
    pub data_mode: u8,
    /// Padding.
    pub _pad: [u8; 1],
}

/// Get connection info by handle (C FFI export).
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
///
/// `out` must be a valid, aligned pointer to a `GenlConnInfo` struct.
#[no_mangle]
pub unsafe extern "C" fn sparklink_genl_get_conn_info(handle: u16, out: *mut GenlConnInfo) -> i32 {
    let ss = SUBSYSTEM.lock();
    match ss.as_ref() {
        Some(shared) => match shared.conn.info(handle) {
            Ok(entry) => {
                // SAFETY: caller guarantees out is a valid, aligned pointer.
                let info = unsafe { &mut *out };
                info.handle = entry.handle;
                info.state = entry.state as u8;
                info.role = entry.local_role as u8;
                info.peer_addr = entry.peer_addr;
                info.bandwidth_mhz = entry.params.bandwidth_mhz;
                info.mcs_index = entry.params.mcs_index;
                info.tx_bytes = entry.tx_bytes;
                info.rx_bytes = entry.rx_bytes;
                info.data_mtu = entry.channels.data.mtu;
                info.data_mps = entry.channels.data.mps;
                info.data_mode = entry.channels.data.mode as u8;
                info.svc_mtu = entry.channels.svc_mgmt.mtu;
                info._pad = [0];
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
///
/// # Safety
///
/// `out` must be a valid, aligned pointer to a `GenlPmInfo` struct.
#[no_mangle]
pub unsafe extern "C" fn sparklink_genl_get_pm_info(out: *mut GenlPmInfo) -> i32 {
    let ss = SUBSYSTEM.lock();
    match ss.as_ref() {
        Some(shared) => {
            // SAFETY: caller guarantees out is a valid, aligned pointer.
            let info = unsafe { &mut *out };
            info.state = shared.power.state as u8;
            info.force_active = if shared.power.is_forced_active() {
                1
            } else {
                0
            };
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
    /// Extended feature bits 64-72.
    pub features_ext: u16,
}

/// Get DLI controller info (C FFI export).
///
/// # Safety
///
/// `out` must be a valid, aligned pointer to a `GenlDliInfo` struct.
#[no_mangle]
pub unsafe extern "C" fn sparklink_genl_get_dli_info(out: *mut GenlDliInfo) -> i32 {
    let ss = SUBSYSTEM.lock();
    match ss.as_ref() {
        Some(shared) => {
            let ci = shared.controller.info();
            // SAFETY: caller guarantees out is a valid, aligned pointer.
            let info = unsafe { &mut *out };
            info.bus_type = ci.bus as u8;
            info.max_conn = ci.max_connections;
            info.transport_modes = ci.transport_modes;
            info.measurement_cap = ci.measurement_cap;
            info.fw_version = ci.fw_version;
            info.features = ci.features;
            info.features_ext = ci.features_ext;
            info.max_mtu = ci.max_mtu;
            info.max_mps = ci.max_mps;
            info.security_cap = ci.security_cap;
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
            unsafe {
                sparklink_genl_unregister();
            }
        }
    }

    /// Broadcast an event via genetlink multicast.
    pub(crate) fn notify_event(event_type: u8, handle: u16, addr: &[u8; 6]) {
        // SAFETY: sparklink_genl_send_event is defined in sparklink_genl.c
        unsafe {
            sparklink_genl_send_event(event_type, handle, addr.as_ptr(), 6, core::ptr::null(), 0);
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
// Global shared subsystem state
// ---------------------------------------------------------------------------
// The SparkLink subsystem supports multiple controllers (up to SLE_DEV_MAX).
// Each controller has its own protocol state (connections, advertising,
// security, SSAP, power, PHY).  At any time one controller is "active"
// and its state is stored directly in the SubsystemShared fields for
// zero-cost access by the 100+ call sites that reference them.
//
// When the active device switches, the current state is saved into
// `saved_states[old_id]` and the new device's state is restored from
// `saved_states[new_id]` (swap-on-switch pattern).  This means that
// multiple USB controllers can coexist without destroying each other's
// state.
//
// Each open fd gets its own event queue for per-listener event delivery.
// Protocol state (controller, connections, advertising, security, SSAP,
// power, PHY) is per-device and shared across fds via the SUBSYSTEM mutex.

kernel::sync::global_lock! {
    // SAFETY: Initialized in module_init before any MiscDevice open() call.
    pub(crate) unsafe(uninit) static SUBSYSTEM: Mutex<Option<SubsystemShared>> = None;
}

/// Number of currently open file descriptors.
static OPEN_FD_COUNT: kernel::sync::atomic::Atomic<u32> = kernel::sync::atomic::Atomic::new(0);

/// DLI event ring size (events consumed from controller by EventPump).
pub(crate) const DLI_RING_SIZE: usize = 32;

/// Saved per-device protocol state.
///
/// When the active device switches, its live state (controller, conn,
/// adv_scan, security, ssap, power, phy) is packed into this struct
/// and stored in `SubsystemShared::saved_states[dev_id]`.  When the
/// device becomes active again, the state is unpacked back into the
/// live fields.
pub(crate) struct PerDeviceState {
    pub(crate) controller: sle_dli::ControllerBackend,
    pub(crate) conn: ConnManager,
    pub(crate) adv_scan: AdvScanInner,
    pub(crate) security: SecurityInner,
    pub(crate) ssap: SsapInner,
    pub(crate) power: PowerInner,
    pub(crate) phy: sle_phy::PhyConfig,
    pub(crate) local_role: GtRole,
}

impl PerDeviceState {
    /// Create fresh state for a newly activated device.
    pub(crate) fn new_for_device(addr: [u8; 6], backend: sle_dli::ControllerBackend) -> Self {
        Self {
            controller: backend,
            conn: ConnManager::new(addr),
            adv_scan: AdvScanInner::new(addr, b"sparklink"),
            security: SecurityInner::new(),
            ssap: SsapInner::new(),
            power: PowerInner::new(),
            phy: sle_phy::PhyConfig::default_config(),
            local_role: GtRole::TNode,
        }
    }

    /// Save the live state from SubsystemShared into this container.
    pub(crate) fn take_from(ss: &mut SubsystemShared) -> Self {
        let placeholder = [0u8; 6];
        Self {
            controller: core::mem::replace(
                &mut ss.controller,
                sle_dli::ControllerBackend::new_virtual(placeholder),
            ),
            conn: core::mem::replace(&mut ss.conn, ConnManager::new(placeholder)),
            adv_scan: core::mem::replace(&mut ss.adv_scan, AdvScanInner::new(placeholder, b"")),
            security: core::mem::replace(&mut ss.security, SecurityInner::new()),
            ssap: core::mem::replace(&mut ss.ssap, SsapInner::new()),
            power: core::mem::replace(&mut ss.power, PowerInner::new()),
            phy: core::mem::replace(&mut ss.phy, sle_phy::PhyConfig::default_config()),
            local_role: core::mem::replace(&mut ss.local_role, GtRole::TNode),
        }
    }

    /// Restore this container's state into the live SubsystemShared fields.
    pub(crate) fn restore_into(self, ss: &mut SubsystemShared) {
        ss.controller = self.controller;
        ss.conn = self.conn;
        ss.adv_scan = self.adv_scan;
        ss.security = self.security;
        ss.ssap = self.ssap;
        ss.power = self.power;
        ss.phy = self.phy;
        ss.local_role = self.local_role;
    }
}

/// Shared state across all open file descriptors.
/// Protected by the SUBSYSTEM global mutex.
pub(crate) struct SubsystemShared {
    pub(crate) controller: sle_dli::ControllerBackend,
    pub(crate) conn: ConnManager,
    pub(crate) adv_scan: AdvScanInner,
    pub(crate) security: SecurityInner,
    pub(crate) rpa: RpaManager,
    pub(crate) ssap: SsapInner,
    pub(crate) power: PowerInner,
    pub(crate) phy: sle_phy::PhyConfig,
    pub(crate) local_role: GtRole,
    /// Global event broadcast ring for multi-listener delivery.
    pub(crate) broadcast: sle_event::BroadcastRing,
    /// DLI event ring for DLI_POLL_EVENT ioctl. Events consumed from the
    /// controller by the EventPump are stored here so DLI_POLL_EVENT has
    /// a deterministic source separate from the controller queue.
    pub(crate) dli_ring: [SleDliEvent; DLI_RING_SIZE],
    pub(crate) dli_head: usize,
    pub(crate) dli_tail: usize,
    /// Background event pump handle. Kept alive while subsystem is active.
    pub(crate) _event_pump: Option<Arc<EventPump>>,
    /// Background command worker handle.
    pub(crate) _cmd_worker: Option<Arc<CommandWorker>>,
    /// Per-controller device registry.
    pub(crate) dev_registry: sle_dev::SleDevRegistry,
    /// Index of the active device in the registry (`None` = no controller).
    pub(crate) active_dev_id: Option<u16>,
    /// Command pending queue for management plane.
    pub(crate) cmd_pending: sle_mgmt::CmdPendingQueue,
    /// Outgoing command request queue (async dispatch).
    pub(crate) cmd_queue: sle_mgmt::CmdRequestQueue,
    /// Transport protocol registry (H4, USB, SPI, virtual).
    pub(crate) proto_registry: sle_transport::SleProtoRegistry,
    /// Device-to-transport binding table.
    pub(crate) dev_bindings: sle_transport::SleBindingTable,
    /// Saved per-device states for inactive devices (heap-allocated).
    /// Stored as (dev_id, state) pairs. When the active device switches,
    /// its state is saved here. Typically holds at most N-1 entries for N
    /// registered controllers.
    pub(crate) saved_states: KVec<(u16, PerDeviceState)>,
}

impl SubsystemShared {
    pub(crate) fn push_dli_event(&mut self, ev: SleDliEvent) {
        self.dli_ring[self.dli_tail] = ev;
        self.dli_tail = (self.dli_tail + 1) % DLI_RING_SIZE;
        if self.dli_tail == self.dli_head {
            // Ring full: drop oldest entry.
            self.dli_head = (self.dli_head + 1) % DLI_RING_SIZE;
        }
    }

    pub(crate) fn pop_dli_event(&mut self) -> Option<SleDliEvent> {
        if self.dli_head == self.dli_tail {
            return None;
        }
        let ev = self.dli_ring[self.dli_head];
        self.dli_head = (self.dli_head + 1) % DLI_RING_SIZE;
        Some(ev)
    }

    /// Look up and remove a saved state by device ID.
    fn take_saved_state(&mut self, dev_id: u16) -> Option<PerDeviceState> {
        if let Some(pos) = self.saved_states.iter().position(|(id, _)| *id == dev_id) {
            // Swap the found element with the last, then truncate.
            let last = self.saved_states.len() - 1;
            if pos != last {
                self.saved_states.swap(pos, last);
            }
            self.saved_states.pop().map(|(_, state)| state)
        } else {
            None
        }
    }

    /// Save a state for a device ID. Replaces any existing entry.
    fn save_state(&mut self, dev_id: u16, state: PerDeviceState) {
        // Remove existing entry for this dev_id, if any.
        if let Some(pos) = self.saved_states.iter().position(|(id, _)| *id == dev_id) {
            let last = self.saved_states.len() - 1;
            if pos != last {
                self.saved_states.swap(pos, last);
            }
            self.saved_states.pop();
        }
        // Best-effort push; if allocation fails the state is dropped.
        let _ = self.saved_states.push((dev_id, state), GFP_KERNEL);
    }

    /// Discard saved state for a device (on detach).
    fn discard_saved_state(&mut self, dev_id: u16) {
        if let Some(pos) = self.saved_states.iter().position(|(id, _)| *id == dev_id) {
            let last = self.saved_states.len() - 1;
            if pos != last {
                self.saved_states.swap(pos, last);
            }
            self.saved_states.pop();
        }
    }

    /// Switch the active device.
    ///
    /// Saves the current active device's protocol state, then restores
    /// (or creates) the state for `new_id`.  All live field accessors
    /// (`self.controller`, `self.conn`, etc.) transparently refer to
    /// the new device after this call.
    pub(crate) fn switch_active_device(
        &mut self,
        new_id: u16,
        new_state: Option<PerDeviceState>,
    ) -> Result {
        if new_id as usize >= sle_dev::SLE_DEV_MAX {
            return Err(EINVAL);
        }
        // Save current live state for the old active device.
        if let Some(old_id) = self.active_dev_id {
            if old_id == new_id {
                // Already active; if caller provided new_state, apply it.
                if let Some(state) = new_state {
                    state.restore_into(self);
                }
                return Ok(());
            }
            let saved = PerDeviceState::take_from(self);
            self.save_state(old_id, saved);
        }
        // Restore saved state for the new device, or use the caller-
        // supplied state for first activation.
        let state = if let Some(saved) = self.take_saved_state(new_id) {
            // Prefer saved state (preserves prior connections etc.).
            saved
        } else if let Some(fresh) = new_state {
            fresh
        } else {
            return Err(ENODEV);
        };
        state.restore_into(self);
        self.active_dev_id = Some(new_id);
        Ok(())
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
    let proto_name = proto.name;
    let name_bytes = proto_name.as_bytes();
    let mut name_buf = [0u8; 32];
    let copy_len = name_bytes.len().min(name_buf.len());
    name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let ctrl_info = sle_dli::SleControllerInfo {
        name: name_buf,
        bus,
        addr: info.addr,
        fw_version: info.fw_version,
        features: info.features,
        features_ext: info.features_ext,
        max_pdu_payload: if info.max_pdu > 0 {
            info.max_pdu
        } else {
            default_pdu
        },
        max_connections: if info.max_connections > 0 {
            info.max_connections
        } else {
            8
        },
        ..Default::default()
    };

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
        info.addr[0],
        info.addr[1],
        info.addr[2],
        info.addr[3],
        info.addr[4],
        info.addr[5],
    );

    Ok(dev_id)
}

/// Detach a device from the subsystem.
///
/// Called from USB disconnect, serdev remove, or module unload cleanup.
/// Removes the transport binding and unregisters the SleDev.  If the
/// device was the active one, reverts to the virtual backend.  If it
/// was inactive, its saved state is discarded.
pub(crate) fn sle_detach_device(dev_id: u16) {
    let mut ss = SUBSYSTEM.lock();
    if let Some(ss) = ss.as_mut() {
        // Remove the transport binding first.
        ss.dev_bindings.remove(dev_id);

        if ss.active_dev_id == Some(dev_id) {
            // Active device detached: revert to virtual controller.
            let virt_addr = [0x5E, 0x00, 0x00, 0x00, 0x00, 0x00];
            let backend = sle_dli::ControllerBackend::new_virtual(virt_addr);
            let virt_state = PerDeviceState::new_for_device(virt_addr, backend);
            // Don't save the detaching device's state.
            ss.active_dev_id = None;
            virt_state.restore_into(ss);
            // active_dev_id stays None (no registered virtual device).
            pr_info!("sparklink: reverted to virtual controller\n");
        } else {
            // Inactive device: discard its saved state.
            ss.discard_saved_state(dev_id);
        }

        // Unregister the device from the registry.
        let _ = ss.dev_registry.unregister(dev_id);

        pr_info!("sparklink: device sle{} detached\n", dev_id);
    }
}

// ---------------------------------------------------------------------------
// Unified control plane operations (shared by ioctl + genetlink)
// ---------------------------------------------------------------------------

/// Start advertising / broadcast with the given interval.
fn do_start_adv(interval_ms: u32, discovery_level: u8) -> Result<i32> {
    let mode = sle_configfs::power_mode();
    if mode >= 2 {
        return Err(EPERM);
    }
    let interval = if interval_ms == 0 {
        u32::from(sle_configfs::adv_interval_ms())
    } else {
        interval_ms
    };
    let params = AdvParams {
        discovery_level,
        interval_slots: interval * 8,
        broadcast_type: sle_pdu::BroadcastType::AccessibleScannable,
        tx_power: 0,
    };
    let mut ss = SUBSYSTEM.lock();
    let s = ss.as_mut().ok_or(ENODEV)?;
    if s.local_role != GtRole::GNode {
        return Err(EPERM);
    }
    s.adv_scan.start_advertising(params)?;
    let _ = s.adv_scan.build_adv_pdu();
    match s.controller.enable_broadcast(true) {
        Ok(()) => {
            drain_controller_events(s);
        }
        Err(e) => {
            s.adv_scan.abort_advertising();
            return Err(e);
        }
    }
    Ok(0)
}

/// Stop advertising / broadcast.
fn do_stop_adv() -> Result<i32> {
    let mut ss = SUBSYSTEM.lock();
    let s = ss.as_mut().ok_or(ENODEV)?;
    s.adv_scan.stop_advertising()?;
    if let Some(dev) = s.active_dev_id.and_then(|id| s.dev_registry.get(id)) {
        dev.clear_flag(sle_dev::SLE_DEV_ADVERTISING);
    }
    let _ = s.controller.enable_broadcast(false);
    Ok(0)
}

/// Start scanning with the given window and interval.
fn do_start_scan(window_ms: u32, interval_ms: u32, filter_level: u8) -> Result<i32> {
    let mode = sle_configfs::power_mode();
    if mode >= 2 {
        return Err(EPERM);
    }
    let window = if window_ms == 0 {
        u32::from(sle_configfs::scan_window_ms())
    } else {
        window_ms
    };
    let interval = if interval_ms == 0 {
        window * 2
    } else {
        interval_ms
    };
    let params = ScanParams {
        window_slots: window * 8,
        interval_slots: interval * 8,
        filter_level,
        active: false,
    };
    let mut ss = SUBSYSTEM.lock();
    let s = ss.as_mut().ok_or(ENODEV)?;
    if s.local_role != GtRole::TNode {
        return Err(EPERM);
    }
    s.adv_scan.start_scanning(params)?;
    match s.controller.enable_scan(true) {
        Ok(()) => {
            drain_controller_events(s);
        }
        Err(e) => {
            s.adv_scan.abort_scanning();
            return Err(e);
        }
    }
    Ok(0)
}

/// Stop scanning.
fn do_stop_scan() -> Result<i32> {
    let mut ss = SUBSYSTEM.lock();
    let s = ss.as_mut().ok_or(ENODEV)?;
    s.adv_scan.stop_scanning()?;
    if let Some(dev) = s.active_dev_id.and_then(|id| s.dev_registry.get(id)) {
        dev.clear_flag(sle_dev::SLE_DEV_SCANNING);
    }
    let _ = s.controller.enable_scan(false);
    Ok(0)
}

// ---------------------------------------------------------------------------
// C FFI exports for genetlink action commands
// ---------------------------------------------------------------------------

/// Start advertising (C FFI). Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn sparklink_do_start_adv(interval_ms: u32, discovery_level: u8) -> i32 {
    match do_start_adv(interval_ms, discovery_level) {
        Ok(v) => v,
        Err(e) => e.to_errno(),
    }
}

/// Stop advertising (C FFI). Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn sparklink_do_stop_adv() -> i32 {
    match do_stop_adv() {
        Ok(v) => v,
        Err(e) => e.to_errno(),
    }
}

/// Start scanning (C FFI). Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn sparklink_do_start_scan(
    window_ms: u32,
    interval_ms: u32,
    filter_level: u8,
) -> i32 {
    match do_start_scan(window_ms, interval_ms, filter_level) {
        Ok(v) => v,
        Err(e) => e.to_errno(),
    }
}

/// Stop scanning (C FFI). Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn sparklink_do_stop_scan() -> i32 {
    match do_stop_scan() {
        Ok(v) => v,
        Err(e) => e.to_errno(),
    }
}

/// Switch the subsystem controller backend to USB.
///
/// Called from USB probe after sle_attach_device and C-side registration
/// succeed. Creates per-device protocol state and switches the active
/// device using swap-on-switch.  The previous active device's state is
/// preserved in `saved_states` and can be restored later.
pub(crate) fn sle_switch_controller_usb(dev_id: u16, addr: [u8; 6], fw_version: u32) {
    let mut ss = SUBSYSTEM.lock();
    if let Some(ss) = ss.as_mut() {
        let backend = sle_dli::ControllerBackend::new_usb(addr, dev_id);
        let new_state = PerDeviceState::new_for_device(addr, backend);
        if let Err(e) = ss.switch_active_device(dev_id, Some(new_state)) {
            pr_err!(
                "sparklink: failed to switch to USB sle{}: {:?}\n",
                dev_id,
                e
            );
            return;
        }
        // Open the controller (starts event URB listener).
        if let Err(e) = ss.controller.open() {
            pr_warn!(
                "sparklink: controller open failed for sle{}: {:?}\n",
                dev_id,
                e
            );
        }
        // Sync device model with real hardware info from probe.
        ss.dev_registry.update_hw_info(dev_id, addr, fw_version);
        pr_info!("sparklink: controller switched to USB (sle{})\n", dev_id);
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
        ss.dev_registry.update_hw_info(dev_id, addr, fw_version);
        pr_info!("sparklink: controller switched to serdev (sle{})\n", dev_id);
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

        let options = MiscDeviceOptions { name: c"sparklink" };

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
                        writeln!(f, "features_ext: 0x{:04x}", cinfo.features_ext)?;
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
                            // Device names are always ASCII.
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
                    rpa: RpaManager::new(),
                    ssap: SsapInner::new(),
                    power: PowerInner::new(),
                    phy: sle_phy::PhyConfig::default_config(),
                    local_role: GtRole::TNode,
                    broadcast: sle_event::BroadcastRing::new(),
                    // SAFETY: DliTraceRing is repr(C) with all-zero as valid initial state.
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
                    saved_states: KVec::new(),
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

/// Handle SEC_SET_OOB ioctl in a separate stack frame to avoid
/// bloating the main ioctl function's stack usage.
#[inline(never)]
fn ioctl_set_oob(arg: usize) -> Result {
    let params: SleOobData = read_user_struct(arg)?;
    let mut ss = SUBSYSTEM.lock();
    let s = ss.as_mut().ok_or(ENODEV)?;
    s.security.set_oob_data(&params.data);
    Ok(())
}

/// Handle RAL_ADD ioctl in a separate stack frame (SleRalAddParams is 44 bytes).
#[inline(never)]
fn ioctl_ral_add(arg: usize) -> Result {
    let params: SleRalAddParams = read_user_struct(arg)?;
    let entry = RalEntry {
        peer_id_type: params.peer_id_type,
        resolve_algo: params.resolve_algo,
        peer_irkid: params.peer_irkid,
        local_irkid: params.local_irkid,
        peer_id: params.peer_id,
        peer_irk: params.peer_irk,
        local_irk: params.local_irk,
    };
    let mut ss = SUBSYSTEM.lock();
    let s = ss.as_mut().ok_or(ENODEV)?;
    s.rpa.ral_add(entry)
}

/// Handle RAL_READ_PEER_RPA / RAL_READ_LOCAL_RPA ioctls.
#[inline(never)]
fn ioctl_ral_read_rpa(arg: usize, is_local: bool) -> Result {
    let mut params: SleRalQueryParams = read_user_struct(arg)?;
    let rpa = {
        let ss = SUBSYSTEM.lock();
        let s = ss.as_ref().ok_or(ENODEV)?;
        if is_local {
            s.rpa.read_local_rpa(params.id_type, &params.id)?
        } else {
            s.rpa.read_peer_rpa(params.id_type, &params.id)?
        }
    };
    params.rpa = rpa;
    write_user_struct(arg, &params)
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
                let uparams: SleAdvParams = read_user_struct(arg)?;
                do_start_adv(u32::from(uparams.interval_ms), uparams.discovery_level)?;
                Ok(0)
            }
            SL_IOCTL_STOP_ADV => {
                do_stop_adv()?;
                Ok(0)
            }
            SL_IOCTL_START_SCAN => {
                let uparams: SleScanParams = read_user_struct(arg)?;
                do_start_scan(
                    u32::from(uparams.window_ms),
                    u32::from(uparams.interval_ms),
                    uparams.filter_discovery_level,
                )?;
                Ok(0)
            }
            SL_IOCTL_STOP_SCAN => {
                do_stop_scan()?;
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
                    info.addr = SleAddr {
                        b: [0x5E, 0x00, 0x00, 0x00, 0x00, 0x01],
                    };
                    let name = b"sparklink-ctl";
                    info.name[..name.len()].copy_from_slice(name);
                }

                drop(ss);
                write_user_struct(arg, &info)?;
                Ok(0)
            }
            SL_IOCTL_DEV_REGISTER => {
                dev_info!(
                    me.dev,
                    "sparklink: DEV_REGISTER via ioctl (use module init for real registration)\n"
                );
                Ok(0)
            }
            SL_IOCTL_DEV_UNREGISTER => {
                dev_info!(me.dev, "sparklink: DEV_UNREGISTER via ioctl (use module unload for real unregistration)\n");
                Ok(0)
            }
            SL_IOCTL_DEV_SWITCH => {
                let target_id: u16 = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                // Verify the target device exists in the registry.
                if s.dev_registry.get(target_id).is_none() {
                    return Err(ENODEV);
                }
                s.switch_active_device(target_id, None)?;
                pr_info!("sparklink: switched active device to sle{}\n", target_id);
                Ok(0)
            }
            SL_IOCTL_DEV_LIST => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let mask = s.dev_registry.allocated_mask();
                drop(ss);
                write_user_struct(arg, &mask)?;
                Ok(0)
            }
            // --- Extended advertising ---
            SL_IOCTL_EXT_ADV_CONFIGURE => {
                let cfg: SleExtAdvConfig = read_user_struct(arg)?;
                let primary_phy = sle_adv::ExtAdvPhy::from_raw(cfg.primary_phy).ok_or(EINVAL)?;
                let secondary_phy =
                    sle_adv::ExtAdvPhy::from_raw(cfg.secondary_phy).ok_or(EINVAL)?;
                let bcast = sle_pdu::BroadcastType::from_raw(cfg.broadcast_type).ok_or(EINVAL)?;
                let params = sle_adv::ExtAdvParams {
                    discovery_level: cfg.discovery_level,
                    interval_slots: u32::from(cfg.interval_ms) * 8, // ms to 125us slots
                    broadcast_type: bcast,
                    tx_power: cfg.tx_power_dbm,
                    primary_phy,
                    secondary_phy,
                    sid: cfg.sid,
                    include_tx_power: cfg.include_tx_power != 0,
                    extended_adv_timing: cfg.ext_adv_timing,
                };
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.adv_scan.ext_adv_configure(cfg.handle, params)?;
                Ok(0)
            }
            SL_IOCTL_EXT_ADV_SET_DATA => {
                let d: SleExtAdvData = read_user_struct(arg)?;
                let len = (d.data_len as usize).min(252);
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.adv_scan.ext_adv_set_data(d.handle, &d.data[..len])?;
                Ok(0)
            }
            SL_IOCTL_EXT_ADV_ENABLE => {
                let handle: u8 = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.adv_scan.ext_adv_enable(handle)?;
                Ok(0)
            }
            SL_IOCTL_EXT_ADV_DISABLE => {
                let handle: u8 = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.adv_scan.ext_adv_disable(handle)?;
                Ok(0)
            }
            SL_IOCTL_EXT_ADV_REMOVE => {
                let handle: u8 = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.adv_scan.ext_adv_remove(handle)?;
                Ok(0)
            }
            SL_IOCTL_EXT_ADV_INFO => {
                let params: SleExtAdvInfo = read_user_struct(arg)?;
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let (state, sid, phy, data_len, tx_count, timing, max_ev, ev_sent) =
                    s.adv_scan.ext_adv_info(params.handle)?;
                drop(ss);
                let out = SleExtAdvInfo {
                    handle: params.handle,
                    state: match state {
                        sle_adv::ExtAdvState::Idle => 0,
                        sle_adv::ExtAdvState::Configured => 1,
                        sle_adv::ExtAdvState::Active => 2,
                    },
                    sid,
                    primary_phy: phy,
                    data_len: data_len as u16,
                    ext_adv_timing: timing,
                    max_adv_events: max_ev,
                    tx_count,
                    events_sent: ev_sent,
                    _pad: [0u8; 4],
                };
                write_user_struct(arg, &out)?;
                Ok(0)
            }
            SL_IOCTL_EXT_ADV_ENABLE_EX => {
                let p: SleExtAdvEnableParams = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.adv_scan
                    .ext_adv_enable_ex(p.handle, p.duration_10ms, p.max_adv_events)?;
                Ok(0)
            }
            SL_IOCTL_EXT_ADV_TICK => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let disabled = s.adv_scan.ext_adv_tick();
                Ok(disabled as c_long)
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
            SL_IOCTL_INJECT_RAW_ADV => {
                let inject: SleInjectRawAdv = read_user_struct(arg)?;
                let len = inject.pdu_len as usize;
                if !(6..=264).contains(&len) {
                    return Err(EINVAL);
                }
                let pdu = sle_pdu::AdvPdu::deserialize(&inject.pdu_data[..len]).ok_or(EINVAL)?;
                {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    s.adv_scan.process_adv_pdu(&pdu, inject.rssi)?;
                }
                Ok(0)
            }
            SL_IOCTL_SCAN_RESULT_COUNT => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                drain_controller_events(s);
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
                            // If ConnComplete event hasn't arrived yet,
                            // force-confirm since the USB command succeeded.
                            s.conn.confirm_connecting_by_addr(&cp.peer_addr);
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
                            // If event hasn't arrived yet, force-confirm.
                            // The USB command succeeded so the controller
                            // already tore down the link.
                            if s.conn
                                .info(handle)
                                .map(|e| e.state == ConnState::DisconnectPending)
                                .unwrap_or(false)
                            {
                                s.conn.confirm_disconnecting(handle);
                            }
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
                info.data_mtu = entry.channels.data.mtu;
                info.data_mps = entry.channels.data.mps;
                info.data_mode = entry.channels.data.mode as u8;
                info.svc_mtu = entry.channels.svc_mgmt.mtu;
                if let Some(session) = &entry.ssap_session {
                    info.ssap_mtu = session.mtu;
                    info.ssap_info_exchanged = if session.info_exchanged { 1 } else { 0 };
                }
                // Credit state for reliable transport channels.
                info.smtc_tx_credits = entry.channels.svc_mgmt.tx_credits;
                info.smtc_rx_credits = entry.channels.svc_mgmt.rx_credits;
                info.dudtc_tx_credits = entry.channels.data.tx_credits;
                info.dudtc_rx_credits = entry.channels.data.rx_credits;
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
                    // Prepend TCID for the default unicast data channel.
                    let mut tx_buf = [0u8; 1 + CONN_DATA_MAX];
                    tx_buf[0] = sle_conn::tcid::DEFAULT_DATA as u8;
                    tx_buf[1..1 + len].copy_from_slice(&cd.data[..len]);
                    let _ = s.controller.send_data(cd.handle, &tx_buf[..1 + len]);
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
                let resp_type = AccessResponseType::from_raw(resp.response_type).ok_or(EINVAL)?;
                let params = NegotiatedParams {
                    bandwidth_mhz: resp.bandwidth_mhz,
                    mcs_index: resp.mcs_index,
                    supervision_timeout: resp.supervision_timeout,
                    ..Default::default()
                };
                let (handle, peer_addr, result) = {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    let handle = s.conn.resolve_handle(resp.handle)?;
                    let peer_addr = s.conn.info(handle).map(|e| e.peer_addr).unwrap_or([0u8; 6]);
                    let result = s.conn.process_access_response(handle, resp_type, params);
                    // Apply per-connection MTU/MPS if specified.
                    if result.is_ok() && resp.data_mtu > 0 {
                        let mps = if resp.data_mps > 0 {
                            Some(resp.data_mps)
                        } else {
                            None
                        };
                        let _ = s.conn.set_data_mtu(handle, resp.data_mtu, mps);
                    }
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
                            sle_event::SleWireEvent::conn_state(
                                handle,
                                1,
                                0,
                                peer_addr,
                                resp.response_type,
                            ),
                        );
                    }
                }
                result.map(|()| 0isize)
            }
            SL_IOCTL_INJECT_CONN_DATA => {
                let cd: SleConnData = read_user_struct(arg)?;
                let len = (cd.length as usize).min(CONN_DATA_MAX);
                let raw = &cd.data[..len];
                {
                    let mut ss = SUBSYSTEM.lock();
                    let s = ss.as_mut().ok_or(ENODEV)?;
                    let handle = s.conn.resolve_handle(cd.handle)?;
                    if !raw.is_empty()
                        && u16::from(raw[0]) == sle_conn::tcid::MANAGEMENT
                        && raw.len() >= 5
                        && raw[1] == sle_conn::CREDIT_GRANT_PDU_TYPE
                    {
                        // Credit grant PDU injection.
                        let target_tcid = u16::from(raw[2]);
                        let credits = u16::from_le_bytes([raw[3], raw[4]]);
                        let _ = s.conn.receive_credits(handle, target_tcid, credits);
                    } else if !raw.is_empty()
                        && u16::from(raw[0]) == sle_conn::tcid::SERVICE_MGMT
                        && raw.len() > 1
                    {
                        // SSAP PDU injection — route through SSAP processing.
                        let needs_grant = s
                            .conn
                            .consume_rx_credit(handle, sle_conn::tcid::SERVICE_MGMT);
                        let pdu_data = &raw[1..];
                        let mut resp_buf = [0u8; sle_ssap::SSAP_PDU_MAX];
                        let resp_len = s
                            .conn
                            .process_ssap_pdu(handle, pdu_data, &mut s.ssap, &mut resp_buf)
                            .unwrap_or(0);
                        if resp_len > 0
                            && s.conn
                                .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)
                                .is_ok()
                        {
                            let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                            tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                            tx_buf[1..1 + resp_len].copy_from_slice(&resp_buf[..resp_len]);
                            let _ = s.controller.send_data(handle, &tx_buf[..1 + resp_len]);
                        }
                        // Drain notifications triggered by the write.
                        while let Some(n) = s.ssap.dequeue_notification() {
                            if s.conn
                                .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)
                                .is_err()
                            {
                                break;
                            }
                            let pdu = if n.indication {
                                sle_ssap::SsapPdu::ValueInd {
                                    handle: n.handle,
                                    data: n.data,
                                }
                            } else {
                                sle_ssap::SsapPdu::ValueNtf {
                                    handle: n.handle,
                                    data: n.data,
                                }
                            };
                            let mut ntf_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                            ntf_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                            if let Ok(pdu_len) = pdu.encode(&mut ntf_buf[1..]) {
                                if pdu_len > 0 {
                                    let _ = s.controller.send_data(handle, &ntf_buf[..1 + pdu_len]);
                                }
                            }
                        }
                        // Send credit grant if RX credits are low.
                        if needs_grant {
                            if let Ok(granted) =
                                s.conn.grant_credits(handle, sle_conn::tcid::SERVICE_MGMT)
                            {
                                send_credit_grant(
                                    &s.controller,
                                    handle,
                                    sle_conn::tcid::SERVICE_MGMT,
                                    granted,
                                );
                            }
                        }
                    } else {
                        // Regular data injection — strip TCID if present.
                        let payload = if !raw.is_empty()
                            && u16::from(raw[0]) == sle_conn::tcid::DEFAULT_DATA
                            && raw.len() > 1
                        {
                            let _ = s
                                .conn
                                .consume_rx_credit(handle, sle_conn::tcid::DEFAULT_DATA);
                            &raw[1..]
                        } else {
                            raw
                        };
                        let seq = {
                            let entry = s.conn.info(handle)?;
                            entry.seq.rx_seq
                        };
                        s.conn.receive_data(handle, payload, seq)?;
                    }
                }
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
                list.handles[..count].copy_from_slice(&handles[..count]);
                drop(ss);
                write_user_struct(arg, &list)?;
                Ok(0)
            }
            SL_IOCTL_SET_CONN_MTU => {
                let params: SleConnMtuParams = read_user_struct(arg)?;
                let mps = if params.mps > 0 {
                    Some(params.mps)
                } else {
                    None
                };
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let handle = s.conn.resolve_handle(params.handle)?;
                s.conn.set_data_mtu(handle, params.mtu, mps)?;
                Ok(0)
            }
            // --- AFH (Adaptive Frequency Hopping) ---
            SL_IOCTL_AFH_SET_MAP => {
                let params: SleAfhMapParams = read_user_struct(arg)?;
                let map = sle_phy::ChannelMap::from_raw(params.map);
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let handle = s.conn.resolve_handle(params.handle)?;
                let min_ch = if params.min_channels > 0 {
                    params.min_channels
                } else {
                    2
                };
                s.conn.set_channel_map(handle, map, min_ch)?;
                Ok(0)
            }
            SL_IOCTL_AFH_GET_MAP => {
                let params: SleAfhMapParams = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let handle = s.conn.resolve_handle(params.handle)?;
                let map = s.conn.get_channel_map(handle)?;
                drop(ss);
                let out = SleAfhMapParams {
                    handle,
                    min_channels: 0,
                    _pad: 0,
                    map: map.map,
                    used_count: map.used_count(),
                    _pad2: 0,
                };
                write_user_struct(arg, &out)?;
                Ok(0)
            }
            SL_IOCTL_AFH_REPORT_RSSI => {
                let rpt: SleAfhRssiReport = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let handle = s.conn.resolve_handle(rpt.handle)?;
                s.conn.report_rssi(handle, rpt.channel, rpt.rssi_dbm)?;
                Ok(0)
            }
            SL_IOCTL_AFH_CLASSIFY => {
                let params: SleAfhClassifyParams = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let handle = s.conn.resolve_handle(params.handle)?;
                let min_ch = if params.min_channels > 0 {
                    params.min_channels
                } else {
                    2
                };
                let map = s
                    .conn
                    .classify_channels(handle, params.threshold_dbm, min_ch)?;
                drop(ss);
                let out = SleAfhClassifyParams {
                    handle,
                    threshold_dbm: params.threshold_dbm,
                    min_channels: min_ch,
                    map_out: map.map,
                    used_count: map.used_count(),
                    _pad: 0,
                };
                write_user_struct(arg, &out)?;
                Ok(0)
            }
            SL_IOCTL_AFH_HOP_NEXT => {
                let params: SleAfhHopInfo = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let handle = s.conn.resolve_handle(params.handle)?;
                let (ch, freq, ec) = s.conn.hop_next(handle)?;
                drop(ss);
                let out = SleAfhHopInfo {
                    handle,
                    channel: ch,
                    _pad: 0,
                    freq_mhz: freq,
                    event_counter: ec,
                };
                write_user_struct(arg, &out)?;
                Ok(0)
            }
            SL_IOCTL_AFH_REPORT_RETX => {
                let rpt: SleAfhRetxReport = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let handle = s.conn.resolve_handle(rpt.handle)?;
                s.conn
                    .report_retx(handle, rpt.channel, rpt.retransmitted != 0)?;
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
                    3 => s.security.pair_numeric_comparison()?,
                    4 => s.security.pair_passkey_entry()?,
                    5 => s.security.pair_oob()?,
                    6 => s.security.pair_password()?,
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
            SL_IOCTL_SEC_RESET => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.security.reset();
                Ok(0)
            }
            SL_IOCTL_SEC_GET_PASSKEY => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let passkey = s.security.get_passkey()?;
                drop(ss);
                write_user_struct(arg, &passkey)?;
                Ok(0)
            }
            SL_IOCTL_SEC_CONFIRM_PASSKEY => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.security.confirm_passkey()?;
                Ok(0)
            }
            SL_IOCTL_SEC_REJECT_PASSKEY => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.security.reject_passkey();
                Ok(0)
            }
            SL_IOCTL_SEC_SET_OOB => {
                ioctl_set_oob(arg)?;
                Ok(0)
            }
            SL_IOCTL_SEC_INPUT_PASSKEY => {
                let params: SlePasskeyInput = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.security.input_passkey(params.passkey)?;
                Ok(0)
            }
            SL_IOCTL_SEC_SET_PASSWORD => {
                let params: SlePasswordParams = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.security.set_password(&params.data, params.len)?;
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
                let ops = sle_ssap::OpIndicator::from_raw(u32::from(cmd.ops));
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
                    info.idle_count = s.power.stats.active_events.min(u64::from(u16::MAX)) as u16;
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
                    0 => {
                        s.power.resume();
                        Ok(0)
                    }
                    1 => {
                        s.power.on_activity();
                        s.power.force_active(false);
                        Ok(0)
                    }
                    3 => {
                        s.power.suspend()?;
                        Ok(0)
                    }
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
            // --- Sync link management ---
            SL_IOCTL_SYNC_UCAST_PARAM => {
                let mut cfg = read_user_struct::<SleSyncCigConfig>(arg)?;
                let params = sle_conn::SyncCigParams {
                    cig_id: cfg.cig_id,
                    sdu_interval_g2t: cfg.sdu_interval_g2t,
                    sdu_interval_t2g: cfg.sdu_interval_t2g,
                    max_sdu_g2t: cfg.max_sdu_g2t,
                    max_sdu_t2g: cfg.max_sdu_t2g,
                    retransmit_g2t: cfg.retransmit_g2t,
                    retransmit_t2g: cfg.retransmit_t2g,
                    max_latency_g2t: cfg.max_latency_g2t,
                    max_latency_t2g: cfg.max_latency_t2g,
                    adapt_mode: cfg.adapt_mode,
                    link_count: cfg.link_count,
                };
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let result = s.conn.sync_ucast_configure(&params)?;
                cfg.cig_id = result.cig_id;
                cfg.link_count = result.link_count;
                cfg.handles_out = result.handles;
                drop(ss);
                write_user_struct(arg, &cfg)?;
                Ok(0)
            }
            SL_IOCTL_SYNC_UCAST_CREATE => {
                let cmd = read_user_struct::<SleSyncCreateCmd>(arg)?;
                let count = cmd.link_count.min(8) as usize;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let created = s
                    .conn
                    .sync_ucast_create(cmd.group_id, &cmd.acl_handles[..count])?;
                Ok(created as isize)
            }
            SL_IOCTL_SYNC_UCAST_REMOVE => {
                let cig_id = read_user_struct::<u8>(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.conn.sync_ucast_remove(cig_id)?;
                Ok(0)
            }
            SL_IOCTL_SYNC_MCAST_PARAM => {
                let mut cfg = read_user_struct::<SleSyncBigConfig>(arg)?;
                let params = sle_conn::SyncBigParams {
                    big_id: cfg.big_id,
                    sdu_interval_g2t: cfg.sdu_interval_g2t,
                    sdu_interval_t2g: cfg.sdu_interval_t2g,
                    max_sdu_g2t: cfg.max_sdu_g2t,
                    max_sdu_t2g: cfg.max_sdu_t2g,
                    retransmit_g2t: cfg.retransmit_g2t,
                    retransmit_t2g: cfg.retransmit_t2g,
                    max_latency_g2t: cfg.max_latency_g2t,
                    max_latency_t2g: cfg.max_latency_t2g,
                    adapt_mode: cfg.adapt_mode,
                    link_count: cfg.link_count,
                };
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let result = s.conn.sync_mcast_configure(&params)?;
                cfg.big_id = result.big_id;
                cfg.link_count = result.link_count;
                cfg.handles_out = result.handles;
                drop(ss);
                write_user_struct(arg, &cfg)?;
                Ok(0)
            }
            SL_IOCTL_SYNC_MCAST_CREATE => {
                let cmd = read_user_struct::<SleSyncCreateCmd>(arg)?;
                let count = cmd.link_count.min(8) as usize;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                let created = s
                    .conn
                    .sync_mcast_create(cmd.group_id, &cmd.acl_handles[..count])?;
                Ok(created as isize)
            }
            SL_IOCTL_SYNC_MCAST_REMOVE => {
                let big_id = read_user_struct::<u8>(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.conn.sync_mcast_remove(big_id)?;
                Ok(0)
            }
            SL_IOCTL_SYNC_DATAPATH_CFG => {
                let cmd = read_user_struct::<SleSyncDatapathCmd>(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.conn.sync_datapath_config(
                    cmd.sync_handle,
                    cmd.direction,
                    cmd.path_id,
                    cmd.codec_id,
                )?;
                Ok(0)
            }
            SL_IOCTL_SYNC_DATAPATH_REMOVE => {
                let sync_handle = read_user_struct::<u16>(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.conn.sync_datapath_remove(sync_handle)?;
                Ok(0)
            }
            SL_IOCTL_SYNC_INFO => {
                let mut info = read_user_struct::<SleSyncLinkInfo>(arg)?;
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let link = s.conn.sync_link_info(info.sync_handle)?;
                info.acl_handle = link.acl_handle;
                info.group_id = link.cig_id;
                info.stream_id = link.cis_id;
                info.link_type = link.link_type as u8;
                info.state = link.state as u8;
                info.sdu_interval_g2t = link.sdu_interval_g2t;
                info.sdu_interval_t2g = link.sdu_interval_t2g;
                info.max_sdu_g2t = link.max_sdu_g2t;
                info.max_sdu_t2g = link.max_sdu_t2g;
                info.datapath_configured = if link.datapath_configured { 1 } else { 0 };
                drop(ss);
                write_user_struct(arg, &info)?;
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
                    max_adv_sets: sle_adv::EXT_ADV_MAX_SETS as u8,
                    transport_modes: cinfo.transport_modes,
                    measurement_cap: cinfo.measurement_cap,
                    max_mtu: cinfo.max_mtu,
                    max_mps: cinfo.max_mps,
                    security_cap: cinfo.security_cap,
                    features_ext: cinfo.features_ext,
                    name,
                    _reserved: [0u8; 4],
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

                // Validate opcode early — reject unknown opcodes at the
                // ioctl boundary instead of only in the async worker.
                if sle_dli::sle_opcode_from_u16(cmd.opcode).is_none() {
                    return Err(EINVAL);
                }

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
                    crc_errors: sle_pdu::crc_error_count(),
                };
                drop(ss);
                write_user_struct(arg, &stats)?;
                Ok(0)
            }
            // --- USB device discovery ---
            SL_IOCTL_USB_DEV_COUNT => Ok(sle_usb::usb_device_count() as isize),
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
                    ofdm: if mcs.is_some_and(|m| m.ofdm) { 1 } else { 0 },
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
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let best = sle_phy::mcs_select_with_thresholds(
                    sel.min_kbps,
                    sel.bandwidth_mhz,
                    sel.sinr_db_x10,
                    &s.phy.sinr_thresholds,
                );
                sel.selected_mcs = best;
                sel.effective_kbps = sle_phy::data_rate_kbps(best, sel.bandwidth_mhz).unwrap_or(0);
                drop(ss);
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
            SL_IOCTL_PHY_GET_SINR => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let out = SleSinrThresholds {
                    thresholds: s.phy.sinr_thresholds,
                    _pad: [0; 2],
                };
                drop(ss);
                write_user_struct(arg, &out)?;
                Ok(0)
            }
            SL_IOCTL_PHY_SET_SINR => {
                let cmd: SleSinrThresholds = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.phy.sinr_thresholds = cmd.thresholds;
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
                    dev_warn!(
                        me.dev,
                        "sparklink: cannot change role with active connections\n"
                    );
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
            // --- RAL / RPA management ---
            SL_IOCTL_RAL_ADD => {
                ioctl_ral_add(arg)?;
                Ok(0)
            }
            SL_IOCTL_RAL_REMOVE => {
                let params: SleRalRemoveParams = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.rpa.ral_remove(params.peer_id_type, &params.peer_id)?;
                Ok(0)
            }
            SL_IOCTL_RAL_CLEAR => {
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.rpa.ral_clear()?;
                Ok(0)
            }
            SL_IOCTL_RAL_SIZE => {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
                let count = s.rpa.ral_size();
                write_user_struct(arg, &count)?;
                Ok(0)
            }
            SL_IOCTL_RAL_READ_PEER_RPA => {
                ioctl_ral_read_rpa(arg, false)?;
                Ok(0)
            }
            SL_IOCTL_RAL_READ_LOCAL_RPA => {
                ioctl_ral_read_rpa(arg, true)?;
                Ok(0)
            }
            SL_IOCTL_RPA_ENABLE => {
                let enable: u8 = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.rpa.set_enabled(enable != 0);
                Ok(0)
            }
            SL_IOCTL_RPA_SET_TIMEOUT => {
                let secs: u16 = read_user_struct(arg)?;
                let mut ss = SUBSYSTEM.lock();
                let s = ss.as_mut().ok_or(ENODEV)?;
                s.rpa.set_timeout(secs);
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
                    configfs_mode,
                    old_pct,
                    new_pct
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
                me.last_seq
                    .store(new_seq, core::sync::atomic::Ordering::Relaxed);
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
        me.last_seq
            .store(new_seq, core::sync::atomic::Ordering::Relaxed);
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
