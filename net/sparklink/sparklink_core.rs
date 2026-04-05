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
///
/// All padding/reserved fields are checked for zero per kernel UAPI
/// guidelines (Documentation/process/botching-up-ioctls.rst).
fn read_user_struct<T: FromBytes + Sized + CheckReserved>(arg: usize) -> Result<T> {
    let slice = UserSlice::new(UserPtr::from_addr(arg), core::mem::size_of::<T>());
    let mut reader = slice.reader();
    let val: T = reader.read()?;
    val.check_reserved()?;
    Ok(val)
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
///
/// Field order and explicit padding ensure identical layout on 32-bit
/// and 64-bit ABIs.  All u64 fields are placed at 8-byte aligned
/// offsets and explicit `_pad` fields replace compiler-inserted gaps.
#[repr(C)]
pub struct GenlConnInfo {
    /// Total TX bytes (offset 0, 8-byte aligned).
    pub tx_bytes: u64,
    /// Total RX bytes (offset 8).
    pub rx_bytes: u64,
    /// Connection handle (offset 16).
    pub handle: u16,
    /// Data channel MTU (offset 18).
    pub data_mtu: u16,
    /// Data channel MPS (offset 20).
    pub data_mps: u16,
    /// Service management channel MTU (offset 22).
    pub svc_mtu: u16,
    /// Peer SLE address (6 bytes, offset 24).
    pub peer_addr: [u8; 6],
    /// Connection state (offset 30).
    pub state: u8,
    /// Local GT role (0=T, 1=G) (offset 31).
    pub role: u8,
    /// Bandwidth in MHz (offset 32).
    pub bandwidth_mhz: u8,
    /// MCS index (offset 33).
    pub mcs_index: u8,
    /// Data channel transport mode (0=unreliable, 1=reliable) (offset 34).
    pub data_mode: u8,
    /// Explicit padding to 4-byte boundary (offset 35).
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
    pub(crate) unsafe(uninit) static SUBSYSTEM: Mutex<Option<KBox<SubsystemShared>>> = None;
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
    /// Heap-allocate fresh state for a newly activated device.
    ///
    /// Uses `KBox::init` + `init!` to construct each field directly on
    /// the heap, avoiding a ~13 KB `PerDeviceState` value on the kernel
    /// stack.  This is critical for call paths with limited remaining
    /// stack (USB hub workqueue, serdev probe, etc.).
    #[inline(never)]
    pub(crate) fn new_boxed(
        addr: [u8; 6],
        backend: sle_dli::ControllerBackend,
    ) -> Result<KBox<Self>> {
        KBox::init(
            init!(PerDeviceState {
                controller: backend,
                conn: ConnManager::new(addr),
                adv_scan: AdvScanInner::new(addr, b"sparklink"),
                security: SecurityInner::new(),
                ssap: SsapInner::new(),
                power: PowerInner::new(),
                phy: sle_phy::PhyConfig::default_config(),
                local_role: GtRole::TNode,
            }),
            GFP_KERNEL,
        )
    }

    /// Restore state from a heap-allocated box into the live fields.
    ///
    /// Swaps each field individually so the old live values end up in
    /// the box and are dropped with it — no full `PerDeviceState` ever
    /// lands on the stack.
    pub(crate) fn restore_box_into(mut state: KBox<Self>, ss: &mut SubsystemShared) {
        core::mem::swap(&mut ss.controller, &mut state.controller);
        core::mem::swap(&mut ss.conn, &mut state.conn);
        core::mem::swap(&mut ss.adv_scan, &mut state.adv_scan);
        core::mem::swap(&mut ss.security, &mut state.security);
        core::mem::swap(&mut ss.ssap, &mut state.ssap);
        core::mem::swap(&mut ss.power, &mut state.power);
        core::mem::swap(&mut ss.phy, &mut state.phy);
        core::mem::swap(&mut ss.local_role, &mut state.local_role);
        // `state` drops here, deallocating the old live values.
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
    /// Transport protocol registry (H4, USB, SPI).
    pub(crate) proto_registry: sle_transport::SleProtoRegistry,
    /// Device-to-transport binding table.
    pub(crate) dev_bindings: sle_transport::SleBindingTable,
    /// Saved per-device states for inactive devices (heap-allocated).
    /// Stored as (dev_id, state) pairs. When the active device switches,
    /// its state is saved here. Typically holds at most N-1 entries for N
    /// registered controllers.
    pub(crate) saved_states: KVec<(u16, KBox<PerDeviceState>)>,
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

    /// Save the current active device's live state into saved_states.
    ///
    /// Allocates a placeholder `PerDeviceState` on the **heap** via
    /// `KBox::init` + `init!`, then swaps each field between `self` and
    /// the heap entry.  This keeps the stack frame small (~200 B) so
    /// the function is safe to call from USB hub workqueue or serdev
    /// probe contexts where remaining kernel stack is limited.
    #[inline(never)]
    fn save_current_device(&mut self, old_id: u16) {
        // Remove any existing entry for old_id.
        self.discard_saved_state(old_id);

        // Allocate a placeholder PerDeviceState on the heap.
        let placeholder = [0u8; 6];
        let boxed = match PerDeviceState::new_boxed(
            placeholder,
            sle_dli::ControllerBackend::new_none(),
        ) {
            Ok(b) => b,
            Err(_) => {
                pr_err!("sparklink: save_current_device: OOM\n");
                return;
            }
        };

        // Extract saved_states temporarily so we can borrow self fields.
        let mut states = core::mem::take(&mut self.saved_states);
        let _ = states.push((old_id, boxed), GFP_KERNEL);

        // Swap each field between self and the newly pushed entry.
        // After swapping, the entry holds the old live data and
        // self holds the placeholder defaults.
        if let Some(entry) = states.last_mut() {
            core::mem::swap(&mut self.controller, &mut entry.1.controller);
            core::mem::swap(&mut self.conn, &mut entry.1.conn);
            core::mem::swap(&mut self.adv_scan, &mut entry.1.adv_scan);
            core::mem::swap(&mut self.security, &mut entry.1.security);
            core::mem::swap(&mut self.ssap, &mut entry.1.ssap);
            core::mem::swap(&mut self.power, &mut entry.1.power);
            core::mem::swap(&mut self.phy, &mut entry.1.phy);
            core::mem::swap(&mut self.local_role, &mut entry.1.local_role);
        }
        self.saved_states = states;
    }

    /// Restore a previously saved device state from saved_states.
    ///
    /// Uses field-by-field swap to avoid placing a full PerDeviceState
    /// on the stack.
    #[inline(never)]
    fn restore_saved_device(&mut self, new_id: u16) -> Result {
        let pos = self
            .saved_states
            .iter()
            .position(|(id, _)| *id == new_id)
            .ok_or(ENODEV)?;
        let last = self.saved_states.len() - 1;
        if pos != last {
            self.saved_states.swap(pos, last);
        }
        // Extract saved_states so we can borrow self fields for swapping.
        let mut states = core::mem::take(&mut self.saved_states);
        if let Some(entry) = states.last_mut() {
            core::mem::swap(&mut self.controller, &mut entry.1.controller);
            core::mem::swap(&mut self.conn, &mut entry.1.conn);
            core::mem::swap(&mut self.adv_scan, &mut entry.1.adv_scan);
            core::mem::swap(&mut self.security, &mut entry.1.security);
            core::mem::swap(&mut self.ssap, &mut entry.1.ssap);
            core::mem::swap(&mut self.power, &mut entry.1.power);
            core::mem::swap(&mut self.phy, &mut entry.1.phy);
            core::mem::swap(&mut self.local_role, &mut entry.1.local_role);
        }
        // Pop the now-stale entry (holds old live state which is dropped).
        states.pop();
        self.saved_states = states;
        self.active_dev_id = Some(new_id);
        Ok(())
    }

    /// Switch to a device that already has saved state.
    pub(crate) fn switch_to_device(&mut self, new_id: u16) -> Result {
        if new_id as usize >= sle_dev::SLE_DEV_MAX {
            return Err(EINVAL);
        }
        if let Some(old_id) = self.active_dev_id {
            if old_id == new_id {
                return Ok(());
            }
            self.save_current_device(old_id);
        }
        self.restore_saved_device(new_id)
    }

    /// Activate a device with fresh state (first-time or re-init).
    ///
    /// Takes a heap-allocated `KBox<PerDeviceState>` to avoid placing
    /// the ~13 KB struct on the kernel stack.
    #[inline(never)]
    pub(crate) fn activate_new_device(&mut self, new_id: u16, new_state: KBox<PerDeviceState>) -> Result {
        if new_id as usize >= sle_dev::SLE_DEV_MAX {
            return Err(EINVAL);
        }
        if let Some(old_id) = self.active_dev_id {
            if old_id == new_id {
                PerDeviceState::restore_box_into(new_state, self);
                return Ok(());
            }
            self.save_current_device(old_id);
        }
        // Prefer saved state over provided state (preserves prior connections).
        let has_saved = self.saved_states.iter().any(|(id, _)| *id == new_id);
        if has_saved {
            drop(new_state);
            self.restore_saved_device(new_id)
        } else {
            PerDeviceState::restore_box_into(new_state, self);
            self.active_dev_id = Some(new_id);
            Ok(())
        }
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
/// device was the active one, reverts to the no-controller state.  If it
/// was inactive, its saved state is discarded.
pub(crate) fn sle_detach_device(dev_id: u16) {
    let mut ss = SUBSYSTEM.lock();
    if let Some(ss) = ss.as_mut() {
        // Remove the transport binding first.
        ss.dev_bindings.remove(dev_id);

        if ss.active_dev_id == Some(dev_id) {
            // Active device detached: revert to no-controller state.
            let addr = [0x5E, 0x00, 0x00, 0x00, 0x00, 0x00];
            let backend = sle_dli::ControllerBackend::new_none();
            match PerDeviceState::new_boxed(addr, backend) {
                Ok(empty_state) => {
                    // Don't save the detaching device's state.
                    ss.active_dev_id = None;
                    PerDeviceState::restore_box_into(empty_state, ss);
                    pr_info!("sparklink: reverted to no-controller state\n");
                }
                Err(_) => {
                    pr_err!("sparklink: OOM reverting controller state\n");
                }
            }
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
    // Collect registered SSAP service UUIDs for advertising payload
    let mut std_uuids = [0u16; 32];
    let std_count = s.ssap.collect_std_uuids(&mut std_uuids);
    let mut custom_uuids = [[0u8; 16]; 8];
    let custom_count = s.ssap.collect_custom_uuids(&mut custom_uuids);
    let _ = s.adv_scan.build_adv_pdu(
        &std_uuids[..std_count],
        &custom_uuids[..custom_count],
    );
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
        let new_state = match PerDeviceState::new_boxed(addr, backend) {
            Ok(b) => b,
            Err(e) => {
                pr_err!(
                    "sparklink: failed to allocate state for USB sle{}: {:?}\n",
                    dev_id,
                    e
                );
                return;
            }
        };
        if let Err(e) = ss.activate_new_device(dev_id, new_state) {
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

// ---------------------------------------------------------------------------
// debugfs observability layer — heap-allocated to avoid kernel stack overflow
// ---------------------------------------------------------------------------
#[pin_data]
struct DebugfsHolder {
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
}

#[pin_data]
struct SparkLinkModule {
    #[pin]
    _miscdev: MiscDeviceRegistration<SparkLinkCtl>,
    _debugfs_holder: Pin<KBox<DebugfsHolder>>,
    _genl: genl_bridge::GenlGuard,
    #[pin]
    _configfs: configfs::Subsystem<sle_configfs::SparkLinkConfig>,
    #[pin]
    _usb: sle_usb::UsbRegistration,
    /// Dropped LAST — after _miscdev closes all fds.
    _subsystem_guard: SubsystemGuard,
}

#[inline(never)]
fn init_version_string() -> Result<CString> {
    CString::try_from_fmt(fmt!("sparklink 0.3.0"))
}

#[inline(never)]
fn init_build_string() -> Result<CString> {
    CString::try_from_fmt(fmt!("sparklink subsystem\nstandard: T/XS 10002-2025, T/XS 20001-2025, T/XS 10003-2025\nmodules: core pdu adv conn crypto security ssap power event dli usb netlink\nlanguage: Rust"))
}

#[inline(never)]
fn init_subsys_string() -> Result<CString> {
    CString::try_from_fmt(fmt!("sle_pdu: frame codec\nsle_adv: advertising/scanning\nsle_conn: connection management\nsle_crypto: SM3/SM4 crypto\nsle_security: pairing/encryption\nsle_ssap: service access protocol\nsle_power: power management\nsle_event: async event notification\nsle_dli: driver layer interface\nsle_usb: USB transport\nsle_netlink: Generic Netlink protocol"))
}

#[inline(never)]
fn init_debugfs() -> Result<Pin<KBox<DebugfsHolder>>> {
    let ver = init_version_string()?;
    let build = init_build_string()?;
    let subsys = init_subsys_string()?;

    let debugfs = Dir::new(c"sparklink");
    let mgmt_dir = debugfs.subdir(c"mgmt");
    let transport_dir = debugfs.subdir(c"transport");
    let power_dir = debugfs.subdir(c"power");
    let conn_dir = debugfs.subdir(c"connections");

    KBox::pin_init(
        pin_init!(DebugfsHolder {
            _version <- debugfs.read_only_file(c"version", ver),
            _build_info <- debugfs.read_only_file(c"build_info", build),
            _subsystems <- debugfs.read_only_file(c"subsystems", subsys),
            adv_count <- debugfs.read_write_file(c"adv_count", Atomic::<usize>::new(0)),
            scan_count <- debugfs.read_write_file(c"scan_count", Atomic::<usize>::new(0)),
            conn_count <- debugfs.read_write_file(c"conn_count", Atomic::<usize>::new(0)),
            ioctl_count <- debugfs.read_write_file(c"ioctl_count", Atomic::<usize>::new(0)),
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
        }),
        GFP_KERNEL,
    )
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

        try_pin_init!(Self {
            _miscdev <- MiscDeviceRegistration::register(options),
            _debugfs_holder: init_debugfs()?,
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
            _subsystem_guard: init_subsystem()?,
        })
    }
}

#[inline(never)]
fn init_subsystem() -> Result<SubsystemGuard> {
    let mut ss = SUBSYSTEM.lock();
    let addr = [0x5E, 0x00, 0x00, 0x00, 0x00, 0x01];
    let controller = match sle_configfs::controller_type() {
        1 => sle_dli::ControllerBackend::new_uart(addr, sle_uart::UartConfig::default()),
        2 => sle_dli::ControllerBackend::new_spi(addr, sle_spi::SpiConfig::default()),
        _ => sle_dli::ControllerBackend::new_none(),
    };
    // Only open if a real backend was configured; None is deferred
    // until a USB/serdev device attaches.
    let _ = controller.open();

    let mut conn = ConnManager::new(addr);
    conn.set_max_connections(sle_configfs::max_connections() as usize);

    sle_workers::init_event_pump_ref();

    let pump = match EventPump::new() {
        Ok(p) => {
            p.start();
            Some(p)
        }
        Err(_) => {
            pr_warn!("sparklink: EventPump allocation failed, running without async events\n");
            None
        }
    };

    let cmd_worker = match CommandWorker::new() {
        Ok(w) => Some(w),
        Err(_) => {
            pr_warn!("sparklink: CommandWorker allocation failed, commands run synchronously\n");
            None
        }
    };

    let mut proto_registry = sle_transport::SleProtoRegistry::new();
    sle_transport::register_builtin_protos(&mut proto_registry);

    let mut dev_registry = sle_dev::SleDevRegistry::new();
    // Only register a device at init if a real controller backend is
    // configured (UART/SPI via configfs).  For None (the default),
    // the first device is registered when a USB/serdev driver probes.
    let dev_id = if !controller.is_none() {
        let ctrl_info = controller.info();
        dev_registry.register(&ctrl_info).ok()
    } else {
        None
    };

    *ss = Some(KBox::init(
        init!(SubsystemShared {
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
        }),
        GFP_KERNEL,
    )?);
    pr_info!("sparklink: shared subsystem initialised\n");
    Ok(SubsystemGuard)
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
    /// Per-fd device affinity.  -1 means "follow the global active_dev_id".
    /// A non-negative value means this fd is bound to a specific controller
    /// (auto-switch on ioctl entry).
    target_dev_id: core::sync::atomic::AtomicI32,
}

/// Advertising, scanning, device management ioctl sub-dispatcher.
#[inline(never)]
fn ioctl_dispatch_adv(me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_START_ADV
        | SL_IOCTL_STOP_ADV
        | SL_IOCTL_START_SCAN
        | SL_IOCTL_STOP_SCAN
        | SL_IOCTL_DEV_COUNT
        | SL_IOCTL_DEV_INFO
        | SL_IOCTL_DEV_REGISTER
        | SL_IOCTL_DEV_UNREGISTER
        | SL_IOCTL_DEV_SWITCH
        | SL_IOCTL_DEV_LIST
        | SL_IOCTL_SCAN_RESULT_COUNT
        | SL_IOCTL_SET_SCAN_FILTER
        | SL_IOCTL_CLEAR_SCAN_FILTER => ioctl_dispatch_adv_basic(me, cmd, arg),
        SL_IOCTL_EXT_ADV_CONFIGURE
        | SL_IOCTL_EXT_ADV_SET_DATA
        | SL_IOCTL_EXT_ADV_ENABLE
        | SL_IOCTL_EXT_ADV_DISABLE
        | SL_IOCTL_EXT_ADV_REMOVE
        | SL_IOCTL_EXT_ADV_INFO
        | SL_IOCTL_EXT_ADV_ENABLE_EX
        | SL_IOCTL_EXT_ADV_TICK => ioctl_dispatch_ext_adv(cmd, arg),
        SL_IOCTL_INJECT_ADV => ioctl_inject_adv(me, arg),
        SL_IOCTL_INJECT_RAW_ADV => ioctl_inject_raw_adv(arg),
        _ => Err(EINVAL),
    }
}

/// DEV_SWITCH ioctl — isolated to avoid PerDeviceState stack inflation.
#[inline(never)]
fn ioctl_dev_switch(arg: usize) -> Result<isize> {
    let target_id: u16 = read_user_struct(arg)?;
    let mut ss = SUBSYSTEM.lock();
    let s = ss.as_mut().ok_or(ENODEV)?;
    if s.dev_registry.get(target_id).is_none() {
        return Err(ENODEV);
    }
    s.switch_to_device(target_id)?;
    pr_info!("sparklink: switched active device to sle{}\n", target_id);
    Ok(0)
}

/// DEV_SELECT ioctl — per-fd device affinity.
///
/// Sets which controller this fd targets.  -1 means follow the global
/// active_dev_id; ≥0 binds the fd to that specific controller.  On each
/// subsequent ioctl the handler will auto-switch if needed.
#[inline(never)]
fn ioctl_dev_select(me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let val: i16 = read_user_struct(arg)?;
    if val >= 0 {
        let target = val as u16;
        let ss = SUBSYSTEM.lock();
        let s = ss.as_ref().ok_or(ENODEV)?;
        if s.dev_registry.get(target).is_none() {
            return Err(ENODEV);
        }
        me.target_dev_id.store(val as i32, core::sync::atomic::Ordering::Release);
    } else {
        me.target_dev_id.store(val as i32, core::sync::atomic::Ordering::Release);
    }
    Ok(0)
}

/// DEV_GET_ACTIVE ioctl — return the effective device for this fd.
#[inline(never)]
fn ioctl_dev_get_active(me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let fd_target = me.target_dev_id.load(core::sync::atomic::Ordering::Relaxed);
    let effective: u16 = if fd_target >= 0 {
        fd_target as u16
    } else {
        let ss = SUBSYSTEM.lock();
        let s = ss.as_ref().ok_or(ENODEV)?;
        s.active_dev_id.unwrap_or(0xFFFF)
    };
    write_user_struct(arg, &effective)?;
    Ok(0)
}

/// Basic adv/scan/dev ioctl sub-dispatcher.
#[inline(never)]
fn ioctl_dispatch_adv_basic(me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
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
                info.bus = SciBus::None as u8; // 0 = no controller
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
            dev_info!(
                me.dev,
                "sparklink: DEV_UNREGISTER via ioctl (use module unload for real unregistration)\n"
            );
            Ok(0)
        }
        SL_IOCTL_DEV_SWITCH => ioctl_dev_switch(arg),
        SL_IOCTL_DEV_LIST => {
            let ss = SUBSYSTEM.lock();
            let s = ss.as_ref().ok_or(ENODEV)?;
            let mask = s.dev_registry.allocated_mask();
            drop(ss);
            write_user_struct(arg, &mask)?;
            Ok(0)
        }
        SL_IOCTL_SCAN_RESULT_COUNT => {
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            drain_controller_events(s);
            let count = s.adv_scan.scan_result_count();
            Ok(count as isize)
        }
        SL_IOCTL_SET_SCAN_FILTER => {
            let params: SleScanFilter = read_user_struct(arg)?;
            let count = (params.uuid_count as usize).min(sle_adv::SCAN_FILTER_MAX_UUIDS);
            let mut filter = sle_adv::ScanFilter::default();
            filter.uuid_count = count as u8;
            filter.uuids[..count].copy_from_slice(&params.uuids[..count]);
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.adv_scan.set_scan_filter(filter);
            Ok(0)
        }
        SL_IOCTL_CLEAR_SCAN_FILTER => {
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.adv_scan.clear_scan_filter();
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// Extended advertising ioctl sub-dispatcher.
#[inline(never)]
fn ioctl_dispatch_ext_adv(cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_EXT_ADV_CONFIGURE => {
            let cfg: SleExtAdvConfig = read_user_struct(arg)?;
            let primary_phy = sle_adv::ExtAdvPhy::from_raw(cfg.primary_phy).ok_or(EINVAL)?;
            let secondary_phy = sle_adv::ExtAdvPhy::from_raw(cfg.secondary_phy).ok_or(EINVAL)?;
            let bcast = sle_pdu::BroadcastType::from_raw(cfg.broadcast_type).ok_or(EINVAL)?;
            let params = sle_adv::ExtAdvParams {
                discovery_level: cfg.discovery_level,
                interval_slots: u32::from(cfg.interval_ms) * 8,
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
            let len = (d.data_len as usize).min(ADV_DATA_MAX);
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
        _ => Err(EINVAL),
    }
}

/// INJECT_ADV — large structs (AdvDataBuilder, AdvPdu), isolated for stack safety.
#[inline(never)]
fn ioctl_inject_adv(me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let inject: SleInjectAdv = read_user_struct(arg)?;
    let mut builder = sle_pdu::AdvDataBuilder::new();
    let _ = builder.push_discovery_level(inject.discovery_level);
    let _ = builder.push_sle_addr(&inject.addr);
    let name_len = (inject.name_len as usize).min(ADV_NAME_MAX);
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
    SparkLinkCtl::broadcast_event(
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
        inject.addr[0],
        inject.addr[1],
        inject.addr[2],
        inject.addr[3],
        inject.addr[4],
        inject.addr[5],
        inject.rssi
    );
    Ok(0)
}

/// INJECT_RAW_ADV — large SleInjectRawAdv struct, isolated for stack safety.
#[inline(never)]
fn ioctl_inject_raw_adv(arg: usize) -> Result<isize> {
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

/// Connection data send — isolated for stack safety (SleConnData = 260B + tx_buf = 256B).
#[inline(never)]
fn ioctl_conn_send(arg: usize) -> Result<isize> {
    let cd: SleConnData = read_user_struct(arg)?;
    let len = (cd.length as usize).min(CONN_DATA_MAX);
    let mut ss = SUBSYSTEM.lock();
    let s = ss.as_mut().ok_or(ENODEV)?;
    let handle = s.conn.resolve_handle(cd.handle)?;
    let sent = s.conn.send(handle, &cd.data[..len])?;
    let mut tx_buf = [0u8; 1 + CONN_DATA_MAX];
    tx_buf[0] = sle_conn::tcid::DEFAULT_DATA as u8;
    tx_buf[1..1 + len].copy_from_slice(&cd.data[..len]);
    s.controller.send_data(cd.handle, &tx_buf[..1 + len])?;
    Ok(sent as isize)
}

/// Connection data receive — isolated for stack safety (2x SleConnData = 520B).
#[inline(never)]
fn ioctl_conn_recv(arg: usize) -> Result<isize> {
    let cd: SleConnData = read_user_struct(arg)?;
    let mut ss = SUBSYSTEM.lock();
    let s = ss.as_mut().ok_or(ENODEV)?;
    let handle = s.conn.resolve_handle(cd.handle)?;
    let mut out: SleConnData = unsafe { core::mem::zeroed() };
    out.handle = handle;
    let recv_len = s.conn.recv(handle, &mut out.data)?;
    out.length = recv_len.min(CONN_DATA_MAX) as u16;
    drop(ss);
    write_user_struct(arg, &out)?;
    Ok(0)
}

fn ioctl_dispatch_conn(me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_CONNECT => {
            SparkLinkCtl::check_power_active()?;
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
                match s.controller.create_connection(&cp.peer_addr) {
                    Ok(()) => {
                        drain_controller_events(s);
                        s.conn.confirm_connecting_by_addr(&cp.peer_addr);
                    }
                    Err(e) => {
                        s.conn.abort_connecting(handle);
                        return Err(e);
                    }
                }
                handle
            };
            SparkLinkCtl::broadcast_event(
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
                match s.controller.disconnect(handle) {
                    Ok(()) => {
                        drain_controller_events(s);
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
            SparkLinkCtl::broadcast_event(
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
                info.ssap_reliable_mode = if session.reliable_mode { 1 } else { 0 };
                info.ssap_version_major = session.version.0;
            }
            info.smtc_tx_credits = entry.channels.svc_mgmt.tx_credits;
            info.smtc_rx_credits = entry.channels.svc_mgmt.rx_credits;
            info.dudtc_tx_credits = entry.channels.data.tx_credits;
            info.dudtc_rx_credits = entry.channels.data.rx_credits;
            drop(ss);
            write_user_struct(arg, &info)?;
            Ok(0)
        }
        SL_IOCTL_CONN_SEND => ioctl_conn_send(arg),
        SL_IOCTL_CONN_RECV => ioctl_conn_recv(arg),
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
                    SparkLinkCtl::broadcast_event(
                        me.as_ref(),
                        sle_event::SleWireEvent::conn_state(handle, 1, 2, peer_addr, 0),
                    );
                }
                Err(_) => {
                    SparkLinkCtl::broadcast_event(
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
        SL_IOCTL_INJECT_CONN_DATA => ioctl_inject_conn_data(me, arg),
        SL_IOCTL_CONN_COUNT => {
            let ss = SUBSYSTEM.lock();
            let s = ss.as_ref().ok_or(ENODEV)?;
            Ok(s.conn.active_count() as isize)
        }
        SL_IOCTL_CONN_LIST => {
            let ss = SUBSYSTEM.lock();
            let s = ss.as_ref().ok_or(ENODEV)?;
            let (handles, count) = s.conn.active_handles();
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
        SL_IOCTL_CONN_READ_PEER_FEATURES => {
            let req: SleConnPeerCap = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(req.handle)?;
            let entry = s.conn.info(handle)?;
            if !entry.peer_cap.features_valid {
                let hb = handle.to_le_bytes();
                s.controller
                    .send_command(sle_dli::SleOpcode::ReadFeatures, &hb)?;
                drain_controller_events(s);
            }
            let entry = s.conn.info(handle)?;
            let mut out: SleConnPeerCap = unsafe { core::mem::zeroed() };
            out.handle = handle;
            out.features = entry.peer_cap.features;
            out.features_valid = if entry.peer_cap.features_valid { 1 } else { 0 };
            out.version = entry.peer_cap.version;
            out.manufacturer = entry.peer_cap.manufacturer;
            out.subversion = entry.peer_cap.subversion;
            out.version_valid = if entry.peer_cap.version_valid { 1 } else { 0 };
            drop(ss);
            write_user_struct(arg, &out)?;
            Ok(0)
        }
        SL_IOCTL_CONN_READ_PEER_VERSION => {
            let req: SleConnPeerCap = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(req.handle)?;
            let entry = s.conn.info(handle)?;
            if !entry.peer_cap.version_valid {
                let hb = handle.to_le_bytes();
                s.controller
                    .send_command(sle_dli::SleOpcode::ReadVersion, &hb)?;
                drain_controller_events(s);
            }
            let entry = s.conn.info(handle)?;
            let mut out: SleConnPeerCap = unsafe { core::mem::zeroed() };
            out.handle = handle;
            out.features = entry.peer_cap.features;
            out.features_valid = if entry.peer_cap.features_valid { 1 } else { 0 };
            out.version = entry.peer_cap.version;
            out.manufacturer = entry.peer_cap.manufacturer;
            out.subversion = entry.peer_cap.subversion;
            out.version_valid = if entry.peer_cap.version_valid { 1 } else { 0 };
            drop(ss);
            write_user_struct(arg, &out)?;
            Ok(0)
        }
        SL_IOCTL_CONN_UPDATE_PARAMS => {
            let up: SleConnParamUpdate = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(up.handle)?;
            let interval = if up.interval_max > 0 {
                up.interval_max
            } else {
                up.interval_min
            };
            s.conn
                .update_conn_params(handle, interval, up.latency, up.supervision_timeout)?;
            let mut params = [0u8; 10];
            params[0..2].copy_from_slice(&handle.to_le_bytes());
            params[2..4].copy_from_slice(&up.interval_min.to_le_bytes());
            params[4..6].copy_from_slice(&up.interval_max.to_le_bytes());
            params[6..8].copy_from_slice(&up.latency.to_le_bytes());
            params[8..10].copy_from_slice(&up.supervision_timeout.to_le_bytes());
            s.controller
                .send_command(sle_dli::SleOpcode::ConnParamUpdate, &params)?;
            Ok(0)
        }
        SL_IOCTL_CONN_PHY_UPDATE => {
            let pu: SleConnPhyUpdate = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(pu.handle)?;
            let mcs = if pu.mcs_index != 0xFF {
                pu.mcs_index
            } else {
                s.conn.info(handle)?.params.mcs_index
            };
            let bw = if pu.bandwidth_mhz != 0 {
                pu.bandwidth_mhz
            } else {
                s.conn.info(handle)?.params.bandwidth_mhz
            };
            s.conn.update_phy_params(handle, mcs, bw)?;
            let mut params = [0u8; 4];
            params[0..2].copy_from_slice(&handle.to_le_bytes());
            params[2] = mcs;
            params[3] = bw;
            s.controller
                .send_command(sle_dli::SleOpcode::SetPhyParam, &params)?;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// INJECT_CONN_DATA — largest single ioctl, isolated for stack safety.
#[inline(never)]
fn ioctl_inject_conn_data(me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let cd: SleConnData = read_user_struct(arg)?;
    let len = (cd.length as usize).min(CONN_DATA_MAX);
    let raw = &cd.data[..len];
    {
        let mut ss = SUBSYSTEM.lock();
        let s = ss.as_mut().ok_or(ENODEV)?;
        let s = &mut **s;
        let handle = s.conn.resolve_handle(cd.handle)?;
        if !raw.is_empty()
            && u16::from(raw[0]) == sle_conn::tcid::MANAGEMENT
            && raw.len() >= sle_conn::CREDIT_GRANT_PDU_SIZE
            && raw[1] == sle_conn::CREDIT_GRANT_PDU_TYPE
        {
            // Credit grant signaling (T/XS 20002-2025 §7.3.3):
            // [TCID 0x02] [code 0xFC] [identifier] [length LE16] [target_tcid] [credits LE16]
            let target_tcid = u16::from(raw[5]);
            let credits = u16::from_le_bytes([raw[6], raw[7]]);
            let _ = s.conn.receive_credits(handle, target_tcid, credits);
        } else if !raw.is_empty()
            && u16::from(raw[0]) == sle_conn::tcid::MANAGEMENT
            && raw.len() >= 5
            && raw[1] != sle_conn::CREDIT_GRANT_PDU_TYPE
        {
            // Transport control signaling (T/XS 20002-2025 §7.3.4).
            let sig_data = &raw[1..];
            let mut resp_buf = [0u8; 32];
            let resp_len = s
                .conn
                .handle_transport_signaling(handle, sig_data, &mut resp_buf)
                .unwrap_or(0);
            if resp_len > 0 {
                let _ = s.controller.send_data(handle, &resp_buf[..resp_len]);
            }
        } else if !raw.is_empty()
            && u16::from(raw[0]) == sle_conn::tcid::SERVICE_MGMT
            && raw.len() > 1
        {
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
            // Drain at most 8 queued notifications to bound lock hold time.
            for _ in 0..8 {
                let n = match s.ssap.dequeue_notification() {
                    Some(n) => n,
                    None => break,
                };
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
            if needs_grant {
                if let Ok((granted, id)) = s.conn.grant_credits(handle, sle_conn::tcid::SERVICE_MGMT) {
                    send_credit_grant(&s.controller, handle, sle_conn::tcid::SERVICE_MGMT, granted, id);
                }
            }
            // After ExchangeInfo negotiation: if reliable mode is agreed
            // but the reliable channel is not yet created, initiate TCID_Connect_Req.
            let needs_connect = s
                .conn
                .get_ssap_session(handle)
                .map(|sess| sess.reliable_mode && sess.reliable_tcid.is_none())
                .unwrap_or(false);
            if needs_connect {
                let cfg = sle_conn::ReliableModeConfig::default();
                let mut sig_buf = [0u8; 24];
                if let Ok(sig_len) =
                    s.conn.build_tcid_connect_req(handle, &cfg, &mut sig_buf)
                {
                    let _ = s.controller.send_data(handle, &sig_buf[..sig_len]);
                }
            }
        } else {
            // Check if this is an SSAP PDU on the dynamic reliable channel.
            let first_byte_tcid = u16::from(raw[0]);
            let is_ssap_reliable = raw.len() > 1
                && s.conn
                    .ssap_reliable_tcid(handle)
                    .map(|t| t == first_byte_tcid)
                    .unwrap_or(false);
            if is_ssap_reliable {
                let needs_grant = s.conn.consume_rx_credit(handle, first_byte_tcid);
                let pdu_data = &raw[1..];
                let mut resp_buf = [0u8; sle_ssap::SSAP_PDU_MAX];
                let resp_len = s
                    .conn
                    .process_ssap_pdu(handle, pdu_data, &mut s.ssap, &mut resp_buf)
                    .unwrap_or(0);
                if resp_len > 0
                    && s.conn.consume_tx_credit(handle, first_byte_tcid).is_ok()
                {
                    let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                    tx_buf[0] = first_byte_tcid as u8;
                    tx_buf[1..1 + resp_len].copy_from_slice(&resp_buf[..resp_len]);
                    let _ = s.controller.send_data(handle, &tx_buf[..1 + resp_len]);
                }
                if needs_grant {
                    if let Ok((granted, id)) = s.conn.grant_credits(handle, first_byte_tcid) {
                        send_credit_grant(&s.controller, handle, first_byte_tcid, granted, id);
                    }
                }
            } else {
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
    }
    SparkLinkCtl::broadcast_event(
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

/// AFH ioctl sub-dispatcher (channel map, RSSI, hopping).
#[inline(never)]
fn ioctl_afh(cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
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
        _ => Err(EINVAL),
    }
}

/// Security ioctl sub-dispatcher (pairing, encryption, crypto tests).
#[inline(never)]
fn ioctl_security(cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
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
            let handle = s.conn.first_active_handle().unwrap_or(0);
            let auth_req: u8 = if params.method == 3 { 0x04 } else { 0x00 };
            s.controller.request_pair(handle, auth_req, params.method)?;
            drain_controller_events(s);
            Ok(0)
        }
        SL_IOCTL_SEC_INFO => {
            let info = {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
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
            s.controller.start_encrypt()?;
            Ok(0)
        }
        SL_IOCTL_SEC_SM3_TEST => {
            let mut ht: SleHashTest = read_user_struct(arg)?;
            let in_len = (ht.in_len as usize).min(HASH_INPUT_MAX);
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
            let klen = (ht.key_len as usize).min(HMAC_KEY_MAX);
            let dlen = (ht.data_len as usize).min(HMAC_DATA_MAX);
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
        _ => Err(EINVAL),
    }
}

/// Local SSAP ioctl sub-dispatcher (service DB, property R/W).
#[inline(never)]
fn ioctl_ssap_local(cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
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
            let mut out: SsapReadWrite = unsafe { core::mem::zeroed() };
            out.handle = rw.handle;
            let copy_len = data.len().min(SSAP_DATA_MAX);
            out.length = copy_len as u16;
            out.data[..copy_len].copy_from_slice(&data[..copy_len]);
            drop(ss);
            write_user_struct(arg, &out)?;
            Ok(0)
        }
        SL_IOCTL_SSAP_WRITE => {
            let rw: SsapReadWrite = read_user_struct(arg)?;
            let len = (rw.length as usize).min(SSAP_DATA_MAX);
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.ssap.write_property(rw.handle, &rw.data[..len])?;
            Ok(0)
        }
        SL_IOCTL_SSAP_FIND_SVC => {
            let ss = SUBSYSTEM.lock();
            let s = ss.as_ref().ok_or(ENODEV)?;
            let services = s.ssap.find_primary_services();
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
                    let mut out: SsapNotification = unsafe { core::mem::zeroed() };
                    out.handle = n.handle;
                    out.indication = if n.indication { 1 } else { 0 };
                    let copy_len = n.data.len().min(SSAP_DATA_MAX);
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
            let mut cmd_data: SsapAddService = read_user_struct(arg)?;
            let uuid = if cmd_data.uuid16 != 0 {
                sle_ssap::SsapUuid::Uuid16(cmd_data.uuid16)
            } else {
                sle_ssap::SsapUuid::Uuid128(cmd_data.uuid128)
            };
            let primary = cmd_data.primary != 0;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.ssap.register_service(uuid, primary)?;
            cmd_data.start_handle = handle;
            drop(ss);
            write_user_struct(arg, &cmd_data)?;
            Ok(0)
        }
        SL_IOCTL_SSAP_ADD_PROP => {
            let mut cmd_data: SsapAddProperty = read_user_struct(arg)?;
            let uuid = sle_ssap::SsapUuid::Uuid16(cmd_data.uuid16);
            let ops = sle_ssap::OpIndicator::from_raw(u32::from(cmd_data.ops));
            let len = (cmd_data.value_len as usize).min(SSAP_VALUE_MAX);
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.ssap.add_property(uuid, ops, &cmd_data.value[..len])?;
            cmd_data.handle = handle;
            drop(ss);
            write_user_struct(arg, &cmd_data)?;
            Ok(0)
        }
        SL_IOCTL_SSAP_REMOVE_SVC => {
            let start_handle: u16 = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.ssap.remove_service(start_handle)?;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// AFH, security, SSAP ioctl router — delegates to domain-specific handlers.
#[inline(never)]
fn ioctl_dispatch_sec_ssap(cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_AFH_SET_MAP
        | SL_IOCTL_AFH_GET_MAP
        | SL_IOCTL_AFH_REPORT_RSSI
        | SL_IOCTL_AFH_CLASSIFY
        | SL_IOCTL_AFH_HOP_NEXT
        | SL_IOCTL_AFH_REPORT_RETX => ioctl_afh(cmd, arg),

        SL_IOCTL_SEC_SET_PSK
        | SL_IOCTL_SEC_PAIR
        | SL_IOCTL_SEC_INFO
        | SL_IOCTL_SEC_ENCRYPT_ON
        | SL_IOCTL_SEC_SM3_TEST
        | SL_IOCTL_SEC_SM4_ENC_TEST
        | SL_IOCTL_SEC_SM4_DEC_TEST
        | SL_IOCTL_SEC_SM4_BLOCK_TEST
        | SL_IOCTL_SEC_HMAC_TEST
        | SL_IOCTL_SEC_RESET
        | SL_IOCTL_SEC_GET_PASSKEY
        | SL_IOCTL_SEC_CONFIRM_PASSKEY
        | SL_IOCTL_SEC_REJECT_PASSKEY
        | SL_IOCTL_SEC_SET_OOB
        | SL_IOCTL_SEC_INPUT_PASSKEY
        | SL_IOCTL_SEC_SET_PASSWORD => ioctl_security(cmd, arg),

        SL_IOCTL_SSAP_REGISTER_SVC
        | SL_IOCTL_SSAP_INFO
        | SL_IOCTL_SSAP_READ
        | SL_IOCTL_SSAP_WRITE
        | SL_IOCTL_SSAP_FIND_SVC
        | SL_IOCTL_SSAP_NOTIFY
        | SL_IOCTL_SSAP_DEQUEUE_NTF
        | SL_IOCTL_SSAP_ADD_SVC
        | SL_IOCTL_SSAP_ADD_PROP
        | SL_IOCTL_SSAP_REMOVE_SVC => ioctl_ssap_local(cmd, arg),

        SL_IOCTL_SSAP_EXCHANGE_INFO
        | SL_IOCTL_SSAP_REMOTE_DISCOVER
        | SL_IOCTL_SSAP_REMOTE_READ
        | SL_IOCTL_SSAP_REMOTE_WRITE
        | SL_IOCTL_SSAP_REMOTE_EVENT
        | SL_IOCTL_SSAP_CALL_METHOD
        | SL_IOCTL_SSAP_FIND_BY_UUID
        | SL_IOCTL_SSAP_READ_BY_UUID => ioctl_ssap_remote(cmd, arg),

        _ => Err(EINVAL),
    }
}

/// Remote SSAP client-side ioctl sub-dispatcher.
///
/// Sends SSAP request PDUs to connected remote peers via the SMTC
/// service management channel. Responses arrive asynchronously through
/// the normal PDU receive path and are cached in `remote_db`.
#[inline(never)]
fn ioctl_ssap_remote(cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_SSAP_EXCHANGE_INFO => {
            let params: SsapRemoteCmd = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_exchange_info_req(247, &mut buf)?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        SL_IOCTL_SSAP_REMOTE_DISCOVER => {
            let mut params: SsapRemoteDiscover = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_find_structure_req(
                params.start_handle,
                params.end_handle,
                &mut buf,
            )?;
            // Return current remote_db entry count before sending
            params.count = session.remote_db.entry_count() as u16;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            drop(ss);
            write_user_struct(arg, &params)?;
            Ok(0)
        }
        SL_IOCTL_SSAP_REMOTE_READ => {
            let params: SsapRemoteReadWrite = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_read_req(params.handle, &mut buf)?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        SL_IOCTL_SSAP_REMOTE_WRITE => {
            let params: SsapRemoteReadWrite = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let data_len = (params.length as usize).min(params.data.len());
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_write_req(
                params.handle,
                &params.data[..data_len],
                &mut buf,
            )?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        SL_IOCTL_SSAP_REMOTE_EVENT => {
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            // Pop remote event from the first connection that has one
            let evt = s.conn.pop_any_remote_event();
            match evt {
                Some((conn_handle, re)) => {
                    let mut out: SsapNotification = unsafe { core::mem::zeroed() };
                    out.handle = re.handle;
                    out.indication = re.indication as u8;
                    let copy_len = re.data.len().min(out.data.len());
                    out.data[..copy_len].copy_from_slice(&re.data[..copy_len]);
                    out.length = copy_len as u8;
                    // Encode conn_handle in unused notification_count area
                    let _ = conn_handle;
                    drop(ss);
                    write_user_struct(arg, &out)?;
                    Ok(0)
                }
                None => Err(EAGAIN),
            }
        }
        SL_IOCTL_SSAP_CALL_METHOD => {
            let params: SsapRemoteReadWrite = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let data_len = (params.length as usize).min(params.data.len());
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_call_method_req(
                params.handle,
                &params.data[..data_len],
                &mut buf,
            )?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        SL_IOCTL_SSAP_FIND_BY_UUID => {
            let params: SsapUuidOp = read_user_struct(arg)?;
            let uuid = if params.uuid16 != 0 {
                sle_ssap::SsapUuid::Uuid16(params.uuid16)
            } else {
                sle_ssap::SsapUuid::Uuid128(params.uuid128)
            };
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_find_by_uuid_req(&uuid, &mut buf)?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        SL_IOCTL_SSAP_READ_BY_UUID => {
            let params: SsapUuidOp = read_user_struct(arg)?;
            let uuid = if params.uuid16 != 0 {
                sle_ssap::SsapUuid::Uuid16(params.uuid16)
            } else {
                sle_ssap::SsapUuid::Uuid128(params.uuid128)
            };
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let handle = s.conn.resolve_handle(params.conn_handle)?;
            let mut buf = [0u8; sle_ssap::SSAP_PDU_MAX];
            let session = s.conn.get_ssap_session(handle).ok_or(ENOENT)?;
            let pdu_len = session.build_read_by_uuid_req(&uuid, &mut buf)?;
            if pdu_len > 0 {
                s.conn
                    .consume_tx_credit(handle, sle_conn::tcid::SERVICE_MGMT)?;
                let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                tx_buf[1..1 + pdu_len].copy_from_slice(&buf[..pdu_len]);
                s.controller.send_data(handle, &tx_buf[..1 + pdu_len])?;
            }
            Ok(0)
        }
        _ => Err(EINVAL),
    }
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

/// Sync link ioctl sub-dispatcher (separate stack frame for large structs).
#[inline(never)]
fn ioctl_sync_link(cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
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
            let (links, cnt) = s.conn.sync_links_for_group(
                result.cig_id, sle_conn::SyncLinkType::Unicast);
            let (buf, len) = sle_conn::encode_sync_param_cmd(
                result.cig_id,
                params.sdu_interval_g2t, params.sdu_interval_t2g,
                params.adapt_mode,
                params.max_latency_g2t, params.max_latency_t2g,
                cnt, &links[..cnt as usize],
            );
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncUcastParam, &buf[..len]);
            drop(ss);
            write_user_struct(arg, &cfg)?;
            Ok(0)
        }
        SL_IOCTL_SYNC_UCAST_CREATE => {
            let cmd_data = read_user_struct::<SleSyncCreateCmd>(arg)?;
            let count = cmd_data.link_count.min(8) as usize;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let created = s
                .conn
                .sync_ucast_create(cmd_data.group_id, &cmd_data.acl_handles[..count])?;
            let (links, cnt) = s.conn.sync_links_for_group(
                cmd_data.group_id, sle_conn::SyncLinkType::Unicast);
            let (buf, len) = sle_conn::encode_sync_create_cmd(
                cmd_data.group_id, &links[..cnt as usize]);
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncUcastCreate, &buf[..len]);
            Ok(created as isize)
        }
        SL_IOCTL_SYNC_UCAST_REMOVE => {
            let cig_id = read_user_struct::<u8>(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.conn.sync_ucast_remove(cig_id)?;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncUcastRemove, &[cig_id]);
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
            let (links, cnt) = s.conn.sync_links_for_group(
                result.big_id, sle_conn::SyncLinkType::Multicast);
            let (buf, len) = sle_conn::encode_sync_param_cmd(
                result.big_id,
                params.sdu_interval_g2t, params.sdu_interval_t2g,
                params.adapt_mode,
                params.max_latency_g2t, params.max_latency_t2g,
                cnt, &links[..cnt as usize],
            );
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncMcastParam, &buf[..len]);
            drop(ss);
            write_user_struct(arg, &cfg)?;
            Ok(0)
        }
        SL_IOCTL_SYNC_MCAST_CREATE => {
            let cmd_data = read_user_struct::<SleSyncCreateCmd>(arg)?;
            let count = cmd_data.link_count.min(8) as usize;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            let created = s
                .conn
                .sync_mcast_create(cmd_data.group_id, &cmd_data.acl_handles[..count])?;
            let (links, cnt) = s.conn.sync_links_for_group(
                cmd_data.group_id, sle_conn::SyncLinkType::Multicast);
            let (buf, len) = sle_conn::encode_sync_create_cmd(
                cmd_data.group_id, &links[..cnt as usize]);
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncMcastCreate, &buf[..len]);
            Ok(created as isize)
        }
        SL_IOCTL_SYNC_MCAST_REMOVE => {
            let big_id = read_user_struct::<u8>(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.conn.sync_mcast_remove(big_id)?;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncMcastRemove, &[big_id]);
            Ok(0)
        }
        SL_IOCTL_SYNC_DATAPATH_CFG => {
            let cmd_data = read_user_struct::<SleSyncDatapathCmd>(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.conn.sync_datapath_config(
                cmd_data.sync_handle,
                cmd_data.direction,
                cmd_data.path_id,
                cmd_data.codec_id,
            )?;
            let (buf, len) = sle_conn::encode_sync_datapath_cmd(
                cmd_data.sync_handle, cmd_data.direction,
                cmd_data.path_id, cmd_data.codec_id);
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncDataPathConfig, &buf[..len]);
            Ok(0)
        }
        SL_IOCTL_SYNC_DATAPATH_REMOVE => {
            let sync_handle = read_user_struct::<u16>(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.conn.sync_datapath_remove(sync_handle)?;
            let mut buf = [0u8; 3];
            buf[0..2].copy_from_slice(&sync_handle.to_le_bytes());
            buf[2] = 0xFF;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncDataPathRemove, &buf);
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
        SL_IOCTL_SYNC_UCAST_ACCEPT => {
            let sync_handle = read_user_struct::<u16>(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.conn.sync_ucast_accept(sync_handle)?;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncUcastAccept,
                &sync_handle.to_le_bytes());
            Ok(0)
        }
        SL_IOCTL_SYNC_UCAST_REJECT => {
            let cmd = read_user_struct::<SleSyncRejectCmd>(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.conn.sync_ucast_reject(cmd.sync_handle, cmd.reason)?;
            let mut buf = [0u8; 3];
            buf[0..2].copy_from_slice(&cmd.sync_handle.to_le_bytes());
            buf[2] = cmd.reason;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncUcastReject, &buf);
            Ok(0)
        }
        SL_IOCTL_SYNC_MCAST_ACCEPT => {
            let sync_handle = read_user_struct::<u16>(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.conn.sync_mcast_accept(sync_handle)?;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncMcastAccept,
                &sync_handle.to_le_bytes());
            Ok(0)
        }
        SL_IOCTL_SYNC_MCAST_REJECT => {
            let cmd = read_user_struct::<SleSyncRejectCmd>(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.conn.sync_mcast_reject(cmd.sync_handle, cmd.reason)?;
            let mut buf = [0u8; 3];
            buf[0..2].copy_from_slice(&cmd.sync_handle.to_le_bytes());
            buf[2] = cmd.reason;
            let _ = s.controller.send_command(
                sle_dli::SleOpcode::SyncMcastReject, &buf);
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// Sync data send ioctl — isolated for stack safety (256+251 byte locals).
#[inline(never)]
fn ioctl_sync_data_send(arg: usize) -> Result<isize> {
    let cmd = read_user_struct::<SleSyncDataCmd>(arg)?;
    let len = (cmd.len as usize).min(247);
    let ss = SUBSYSTEM.lock();
    let s = ss.as_ref().ok_or(ENODEV)?;
    let link = s.conn.sync_link_info(cmd.sync_handle)?;
    if link.state != sle_conn::SyncLinkState::Active {
        return Err(EPIPE);
    }
    if !link.datapath_configured {
        return Err(EINVAL);
    }
    let seg = match cmd.segment {
        0 => sle_conn::SyncSegment::Complete,
        1 => sle_conn::SyncSegment::First,
        2 => sle_conn::SyncSegment::Middle,
        _ => sle_conn::SyncSegment::Last,
    };
    let hdr = sle_conn::encode_sync_data_header(
        cmd.sync_handle, seg, false, cmd.priority != 0,
        len as u16);
    let mut tx_buf = [0u8; 4 + 247];
    tx_buf[..4].copy_from_slice(&hdr);
    tx_buf[4..4 + len].copy_from_slice(&cmd.data[..len]);
    s.controller.send_data(cmd.sync_handle, &tx_buf[..4 + len])?;
    Ok(len as isize)
}

/// DLI command ioctl — isolated for stack safety (SleDliCmd = 248 bytes).
#[inline(never)]
fn ioctl_dli_send_cmd(arg: usize) -> Result<isize> {
    let mut cmd_data: SleDliCmd = read_user_struct(arg)?;
    let param_len = (cmd_data.param_len as usize).min(DLI_PARAM_MAX);
    if sle_dli::sle_opcode_from_u16(cmd_data.opcode).is_none() {
        return Err(EINVAL);
    }
    let worker;
    {
        let mut ss = SUBSYSTEM.lock();
        let s = ss.as_mut().ok_or(ENODEV)?;
        s.cmd_queue
            .push(cmd_data.opcode, &cmd_data.params[..param_len])?;
        cmd_data.seq = s.cmd_pending.submit(cmd_data.opcode)?;
        worker = s._cmd_worker.clone();
    }
    if let Some(ref w) = worker {
        w.kick();
    }
    write_user_struct(arg, &cmd_data)?;
    Ok(0)
}

/// Infrastructure ioctl sub-dispatcher: PM, sync, DLI, events, PHY, role, RAL/RPA.
#[inline(never)]
fn ioctl_dispatch_infra(me: Pin<&SparkLinkCtl>, cmd: u32, arg: usize) -> Result<isize> {
    match cmd {
        SL_IOCTL_PM_INFO => {
            let info = {
                let ss = SUBSYSTEM.lock();
                let s = ss.as_ref().ok_or(ENODEV)?;
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
        SL_IOCTL_SYNC_UCAST_PARAM
        | SL_IOCTL_SYNC_UCAST_CREATE
        | SL_IOCTL_SYNC_UCAST_REMOVE
        | SL_IOCTL_SYNC_MCAST_PARAM
        | SL_IOCTL_SYNC_MCAST_CREATE
        | SL_IOCTL_SYNC_MCAST_REMOVE
        | SL_IOCTL_SYNC_DATAPATH_CFG
        | SL_IOCTL_SYNC_DATAPATH_REMOVE
        | SL_IOCTL_SYNC_INFO
        | SL_IOCTL_SYNC_UCAST_ACCEPT
        | SL_IOCTL_SYNC_UCAST_REJECT
        | SL_IOCTL_SYNC_MCAST_ACCEPT
        | SL_IOCTL_SYNC_MCAST_REJECT => ioctl_sync_link(cmd, arg),
        SL_IOCTL_SYNC_DATA_SEND => ioctl_sync_data_send(arg),
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
        SL_IOCTL_DLI_POLL_EVENT => {
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            if let Some(dli_ev) = s.pop_dli_event() {
                drop(ss);
                write_user_struct(arg, &dli_ev)?;
                return Ok(0);
            }
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
        SL_IOCTL_DLI_RESET => {
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.controller.reset()?;
            Ok(0)
        }
        SL_IOCTL_DLI_SEND_CMD => ioctl_dli_send_cmd(arg),
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
        SL_IOCTL_USB_DEV_COUNT => Ok(sle_usb::usb_device_count() as isize),
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
            let cmd_data: SlePhyMcsCmd = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.phy.set_mcs(cmd_data.mcs_index)?;
            s.controller.set_coding_modulation(cmd_data.mcs_index)?;
            Ok(0)
        }
        SL_IOCTL_PHY_SET_TXPOWER => {
            let cmd_data: SlePhyTxPowerCmd = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.phy.set_tx_power(cmd_data.tx_power_dbm)?;
            s.controller.set_tx_power(cmd_data.tx_power_dbm)?;
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
            let cmd_data: SlePhyBwCmd = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.phy.set_bandwidth(cmd_data.bandwidth_mhz)?;
            s.controller.set_bandwidth(cmd_data.bandwidth_mhz)?;
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
            let cmd_data: SleSinrThresholds = read_user_struct(arg)?;
            let mut ss = SUBSYSTEM.lock();
            let s = ss.as_mut().ok_or(ENODEV)?;
            s.phy.sinr_thresholds = cmd_data.thresholds;
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
        // -- Narrowband AFH measurement (T/XS 10003-2025 §8.7) --
        SL_IOCTL_MEAS_READ_CAP => {
            let ss = SUBSYSTEM.lock();
            let s = ss.as_ref().ok_or(ENODEV)?;
            let cinfo = s.controller.info();
            let cap = SleMeasCap {
                meas_types: cinfo.measurement_cap,
                max_instances: 1,
                antenna_count: 1,
                _reserved: 0,
            };
            drop(ss);
            write_user_struct(arg, &cap)?;
            Ok(0)
        }
        SL_IOCTL_MEAS_SET_LINK_PARAM => {
            let params: SleMeasLinkParam = read_user_struct(arg)?;
            let mut buf = [0u8; 8];
            buf[0..2].copy_from_slice(&params.handle.to_le_bytes());
            buf[2] = params.meas_type;
            buf[3] = params.config_index;
            buf[4..6].copy_from_slice(&params.interval.to_le_bytes());
            buf[6..8].copy_from_slice(&params.duration.to_le_bytes());
            let ss = SUBSYSTEM.lock();
            let s = ss.as_ref().ok_or(ENODEV)?;
            s.controller.send_command(sle_dli::SleOpcode::SetMeasLinkParam, &buf)?;
            Ok(0)
        }
        SL_IOCTL_MEAS_ACTION => {
            let action: SleMeasAction = read_user_struct(arg)?;
            let buf = [
                action.handle.to_le_bytes()[0],
                action.handle.to_le_bytes()[1],
                action.action,
                action.config_index,
            ];
            let ss = SUBSYSTEM.lock();
            let s = ss.as_ref().ok_or(ENODEV)?;
            s.controller.send_command(sle_dli::SleOpcode::MeasAction, &buf)?;
            Ok(0)
        }
        SL_IOCTL_MEAS_ENABLE => {
            let enable: u8 = read_user_struct(arg)?;
            let ss = SUBSYSTEM.lock();
            let s = ss.as_ref().ok_or(ENODEV)?;
            s.controller.send_command(sle_dli::SleOpcode::EnableMeas, &[enable])?;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
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
                    target_dev_id: core::sync::atomic::AtomicI32::new(-1),
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

        // Per-fd device routing: DEV_SELECT and DEV_GET_ACTIVE are handled
        // before auto-switch so they can query/set the affinity itself.
        match cmd {
            SL_IOCTL_DEV_SELECT => return ioctl_dev_select(me, arg),
            SL_IOCTL_DEV_GET_ACTIVE => return ioctl_dev_get_active(me, arg),
            _ => {}
        }

        // Auto-switch to this fd's target device if bound via DEV_SELECT.
        // Skipped for DEV_SWITCH (which sets the global active device).
        if cmd != SL_IOCTL_DEV_SWITCH {
            Self::ensure_target_device(me.as_ref())?;
        }

        match cmd {
            // --- Advertising, scanning, device management ---
            SL_IOCTL_START_ADV
            | SL_IOCTL_STOP_ADV
            | SL_IOCTL_START_SCAN
            | SL_IOCTL_STOP_SCAN
            | SL_IOCTL_DEV_COUNT
            | SL_IOCTL_DEV_INFO
            | SL_IOCTL_DEV_REGISTER
            | SL_IOCTL_DEV_UNREGISTER
            | SL_IOCTL_DEV_SWITCH
            | SL_IOCTL_DEV_LIST
            | SL_IOCTL_EXT_ADV_CONFIGURE
            | SL_IOCTL_EXT_ADV_SET_DATA
            | SL_IOCTL_EXT_ADV_ENABLE
            | SL_IOCTL_EXT_ADV_DISABLE
            | SL_IOCTL_EXT_ADV_REMOVE
            | SL_IOCTL_EXT_ADV_INFO
            | SL_IOCTL_EXT_ADV_ENABLE_EX
            | SL_IOCTL_EXT_ADV_TICK
            | SL_IOCTL_INJECT_ADV
            | SL_IOCTL_INJECT_RAW_ADV
            | SL_IOCTL_SCAN_RESULT_COUNT
            | SL_IOCTL_SET_SCAN_FILTER
            | SL_IOCTL_CLEAR_SCAN_FILTER => ioctl_dispatch_adv(me, cmd, arg),
            // --- Connection management ---
            SL_IOCTL_CONNECT
            | SL_IOCTL_DISCONNECT
            | SL_IOCTL_CONN_INFO
            | SL_IOCTL_CONN_SEND
            | SL_IOCTL_CONN_RECV
            | SL_IOCTL_INJECT_CONN_RESP
            | SL_IOCTL_INJECT_CONN_DATA
            | SL_IOCTL_CONN_COUNT
            | SL_IOCTL_CONN_LIST
            | SL_IOCTL_SET_CONN_MTU
            | SL_IOCTL_CONN_READ_PEER_FEATURES
            | SL_IOCTL_CONN_READ_PEER_VERSION
            | SL_IOCTL_CONN_UPDATE_PARAMS
            | SL_IOCTL_CONN_PHY_UPDATE => ioctl_dispatch_conn(me, cmd, arg),
            // --- AFH, security, SSAP ---
            SL_IOCTL_AFH_SET_MAP
            | SL_IOCTL_AFH_GET_MAP
            | SL_IOCTL_AFH_REPORT_RSSI
            | SL_IOCTL_AFH_CLASSIFY
            | SL_IOCTL_AFH_HOP_NEXT
            | SL_IOCTL_AFH_REPORT_RETX
            | SL_IOCTL_SEC_SET_PSK
            | SL_IOCTL_SEC_PAIR
            | SL_IOCTL_SEC_INFO
            | SL_IOCTL_SEC_ENCRYPT_ON
            | SL_IOCTL_SEC_SM3_TEST
            | SL_IOCTL_SEC_SM4_ENC_TEST
            | SL_IOCTL_SEC_SM4_DEC_TEST
            | SL_IOCTL_SEC_SM4_BLOCK_TEST
            | SL_IOCTL_SEC_HMAC_TEST
            | SL_IOCTL_SEC_RESET
            | SL_IOCTL_SEC_GET_PASSKEY
            | SL_IOCTL_SEC_CONFIRM_PASSKEY
            | SL_IOCTL_SEC_REJECT_PASSKEY
            | SL_IOCTL_SEC_SET_OOB
            | SL_IOCTL_SEC_INPUT_PASSKEY
            | SL_IOCTL_SEC_SET_PASSWORD
            | SL_IOCTL_SSAP_REGISTER_SVC
            | SL_IOCTL_SSAP_INFO
            | SL_IOCTL_SSAP_READ
            | SL_IOCTL_SSAP_WRITE
            | SL_IOCTL_SSAP_FIND_SVC
            | SL_IOCTL_SSAP_NOTIFY
            | SL_IOCTL_SSAP_DEQUEUE_NTF
            | SL_IOCTL_SSAP_ADD_SVC
            | SL_IOCTL_SSAP_ADD_PROP
            | SL_IOCTL_SSAP_REMOVE_SVC
            | SL_IOCTL_SSAP_EXCHANGE_INFO
            | SL_IOCTL_SSAP_REMOTE_DISCOVER
            | SL_IOCTL_SSAP_REMOTE_READ
            | SL_IOCTL_SSAP_REMOTE_WRITE
            | SL_IOCTL_SSAP_REMOTE_EVENT => ioctl_dispatch_sec_ssap(cmd, arg),
            // --- Infrastructure: PM, sync, DLI, events, PHY, role, RAL/RPA ---
            SL_IOCTL_PM_INFO
            | SL_IOCTL_PM_SET_STATE
            | SL_IOCTL_PM_SET_INTERVAL
            | SL_IOCTL_PM_FORCE_ACTIVE
            | SL_IOCTL_PM_TICK
            | SL_IOCTL_PM_ACTIVITY
            | SL_IOCTL_SYNC_UCAST_PARAM
            | SL_IOCTL_SYNC_UCAST_CREATE
            | SL_IOCTL_SYNC_UCAST_REMOVE
            | SL_IOCTL_SYNC_MCAST_PARAM
            | SL_IOCTL_SYNC_MCAST_CREATE
            | SL_IOCTL_SYNC_MCAST_REMOVE
            | SL_IOCTL_SYNC_DATAPATH_CFG
            | SL_IOCTL_SYNC_DATAPATH_REMOVE
            | SL_IOCTL_SYNC_INFO
            | SL_IOCTL_SYNC_UCAST_ACCEPT
            | SL_IOCTL_SYNC_UCAST_REJECT
            | SL_IOCTL_SYNC_MCAST_ACCEPT
            | SL_IOCTL_SYNC_MCAST_REJECT
            | SL_IOCTL_SYNC_DATA_SEND
            | SL_IOCTL_EVENT_COUNT
            | SL_IOCTL_EVENT_STATS
            | SL_IOCTL_DLI_INFO
            | SL_IOCTL_DLI_POLL_EVENT
            | SL_IOCTL_DLI_RESET
            | SL_IOCTL_DLI_SEND_CMD
            | SL_IOCTL_MGMT_STATS
            | SL_IOCTL_SUBSYS_STATS
            | SL_IOCTL_USB_DEV_COUNT
            | SL_IOCTL_PHY_INFO
            | SL_IOCTL_PHY_SET_MCS
            | SL_IOCTL_PHY_SET_TXPOWER
            | SL_IOCTL_PHY_MCS_SELECT
            | SL_IOCTL_PHY_HOP_NEXT
            | SL_IOCTL_PHY_SET_BW
            | SL_IOCTL_PHY_GET_SINR
            | SL_IOCTL_PHY_SET_SINR
            | SL_IOCTL_SET_ROLE
            | SL_IOCTL_GET_ROLE
            | SL_IOCTL_RAL_ADD
            | SL_IOCTL_RAL_REMOVE
            | SL_IOCTL_RAL_CLEAR
            | SL_IOCTL_RAL_SIZE
            | SL_IOCTL_RAL_READ_PEER_RPA
            | SL_IOCTL_RAL_READ_LOCAL_RPA
            | SL_IOCTL_RPA_ENABLE
            | SL_IOCTL_RPA_SET_TIMEOUT
            | SL_IOCTL_MEAS_READ_CAP
            | SL_IOCTL_MEAS_SET_LINK_PARAM
            | SL_IOCTL_MEAS_ACTION
            | SL_IOCTL_MEAS_ENABLE => ioctl_dispatch_infra(me, cmd, arg),
            _ => {
                dev_err!(me.dev, "sparklink: unknown ioctl 0x{:x}\n", cmd);
                Err(ENOTTY)
            }
        }
    }
}

impl SparkLinkCtl {
    /// If this fd has a per-fd device affinity (`target_dev_id >= 0`),
    /// ensure the global active controller is switched to that device.
    /// Called at the top of `ioctl()` so all subsequent operations in
    /// the call see the correct per-device state.
    ///
    /// Returns `Ok(())` if:
    /// - The fd follows the global active device (`target_dev_id == -1`).
    /// - The target device is already active (no switch needed).
    /// - The switch completed successfully.
    ///
    /// Returns `Err(ENODEV)` if the target device is no longer registered.
    fn ensure_target_device(me: Pin<&Self>) -> Result {
        let target = me.target_dev_id.load(core::sync::atomic::Ordering::Relaxed);
        if target < 0 {
            return Ok(()); // follow global
        }
        let target_id = target as u16;
        let mut ss = SUBSYSTEM.lock();
        let s = ss.as_mut().ok_or(ENODEV)?;
        // Already active?
        if s.active_dev_id == Some(target_id) {
            return Ok(());
        }
        // Target still registered?
        if s.dev_registry.get(target_id).is_none() {
            // Device gone: reset affinity to global.
            me.target_dev_id.store(-1, core::sync::atomic::Ordering::Relaxed);
            return Err(ENODEV);
        }
        s.switch_to_device(target_id)
    }

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
