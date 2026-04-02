// SPDX-License-Identifier: GPL-2.0

//! Background workers for SparkLink subsystem.
//!
//! Contains the EventPump (periodic DLI event polling) and CommandWorker
//! (async command dispatch) extracted from sparklink_core.rs.

use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::time::msecs_to_jiffies;
use kernel::workqueue::{self, impl_has_delayed_work, new_delayed_work, DelayedWork, WorkItem};

use super::genl_bridge;
use super::sle_conn;
use super::sle_dev;
use super::sle_dli;
use super::sle_dli::SleController;
use super::sle_event;
use super::sle_ssap;
use super::sle_uapi::*;
use super::sle_usb;
use super::SubsystemShared;
use super::SUBSYSTEM;

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
pub(crate) struct EventPump {
    #[pin]
    work: DelayedWork<EventPump>,
}

impl_has_delayed_work! {
    impl HasDelayedWork<Self> for EventPump { self.work }
}

// ---------------------------------------------------------------------------
// Unified controller event processing
// ---------------------------------------------------------------------------

/// Send a credit grant PDU on the management channel (CMTC).
///
/// Format: `[TCID_CMTC] [CREDIT_GRANT_PDU_TYPE] [target_tcid] [credits LE16]`
pub(crate) fn send_credit_grant(
    ctrl: &sle_dli::ControllerBackend,
    handle: u16,
    target_tcid: u16,
    credits: u16,
) {
    let mut buf = [0u8; 5];
    buf[0] = sle_conn::tcid::MANAGEMENT as u8;
    buf[1] = sle_conn::CREDIT_GRANT_PDU_TYPE;
    buf[2] = target_tcid as u8;
    let c = credits.to_le_bytes();
    buf[3] = c[0];
    buf[4] = c[1];
    let _ = ctrl.send_data(handle, &buf);
}

/// Process a single controller event: resolve pending commands, drive
/// state machine transitions, and publish to broadcast ring / DLI ring.
///
/// Called from both `EventPump` (periodic background) and inline after
/// ioctl commands (immediate drain for synchronous controller backends
/// like VirtualController).
pub(crate) fn process_controller_event(shared: &mut SubsystemShared, ev: &sle_dli::SleEvent) {
    // 1. Resolve pending management commands.
    match ev {
        sle_dli::SleEvent::CommandComplete {
            opcode,
            status,
            data,
        } => {
            shared
                .cmd_pending
                .resolve(*opcode as u16, *status as u8, data.as_slice());
        }
        sle_dli::SleEvent::CommandStatus { opcode, status } => {
            shared
                .cmd_pending
                .resolve(*opcode as u16, *status as u8, &[]);
        }
        _ => {}
    }

    // 2. Drive pending state machine transitions (DLI async confirmation).
    match ev {
        sle_dli::SleEvent::CommandComplete { opcode, status, .. } => match opcode {
            sle_dli::SleOpcode::EnableBroadcast => {
                if *status == sle_dli::SleStatus::Success {
                    shared.adv_scan.confirm_advertising();
                    if let Some(dev) = shared
                        .active_dev_id
                        .and_then(|id| shared.dev_registry.get(id))
                    {
                        dev.set_flag(sle_dev::SLE_DEV_ADVERTISING);
                    }
                } else {
                    shared.adv_scan.abort_advertising();
                }
            }
            sle_dli::SleOpcode::EnableScan => {
                if *status == sle_dli::SleStatus::Success {
                    shared.adv_scan.confirm_scanning();
                    if let Some(dev) = shared
                        .active_dev_id
                        .and_then(|id| shared.dev_registry.get(id))
                    {
                        dev.set_flag(sle_dev::SLE_DEV_SCANNING);
                    }
                } else {
                    shared.adv_scan.abort_scanning();
                }
            }
            _ => {}
        },
        sle_dli::SleEvent::ConnComplete {
            handle: evt_handle,
            addr,
            status,
        } => {
            if *status == sle_dli::SleStatus::Success {
                if shared.conn.confirm_connecting_by_addr(addr).is_none() {
                    // Incoming connection — no prior ConnectPending entry.
                    // Auto-create a Connected entry for the acceptor side.
                    let _ = shared.conn.accept_incoming(*evt_handle, addr);
                }
                genl_bridge::notify_event(0x01, 0, addr);
            } else {
                shared.conn.abort_connecting_by_addr(addr);
            }
        }
        sle_dli::SleEvent::Disconnected { handle, .. } => {
            let peer_addr = shared
                .conn
                .info(*handle)
                .map(|e| e.peer_addr)
                .unwrap_or([0u8; 6]);
            shared.conn.confirm_disconnecting_by_handle(*handle);
            genl_bridge::notify_event(0x01, *handle, &peer_addr);
        }
        sle_dli::SleEvent::AdvReport {
            addr,
            rssi,
            discovery_level,
            data,
        } => {
            let _ =
                shared
                    .adv_scan
                    .process_adv_report(addr, *rssi, *discovery_level, data.as_slice());
            genl_bridge::notify_event(0x02, 0, addr);
        }
        sle_dli::SleEvent::DataReceived { handle, data } => {
            let raw = data.as_slice();
            if raw.is_empty() {
                // Empty payload, nothing to route.
            } else if u16::from(raw[0]) == sle_conn::tcid::MANAGEMENT
                && raw.len() >= 5
                && raw[1] == sle_conn::CREDIT_GRANT_PDU_TYPE
            {
                // Credit grant PDU on management channel.
                // Format: [TCID 0x02] [0xFC] [target_tcid u8] [credits LE16]
                let target_tcid = u16::from(raw[2]);
                let credits = u16::from_le_bytes([raw[3], raw[4]]);
                let _ = shared.conn.receive_credits(*handle, target_tcid, credits);
            } else if u16::from(raw[0]) == sle_conn::tcid::SERVICE_MGMT && raw.len() > 1 {
                // SSAP PDU on service management channel (TCID 0x0A).
                // Track RX credit for the reliable SMTC channel.
                let needs_grant = shared
                    .conn
                    .consume_rx_credit(*handle, sle_conn::tcid::SERVICE_MGMT);
                let pdu_data = &raw[1..];
                let mut resp_buf = [0u8; sle_ssap::SSAP_PDU_MAX];
                let resp_len = shared
                    .conn
                    .process_ssap_pdu(*handle, pdu_data, &mut shared.ssap, &mut resp_buf)
                    .unwrap_or(0);
                // Send response PDU back with TCID prefix, consuming TX credit.
                if resp_len > 0
                    && shared
                        .conn
                        .consume_tx_credit(*handle, sle_conn::tcid::SERVICE_MGMT)
                        .is_ok()
                {
                    let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                    tx_buf[0] = sle_conn::tcid::SERVICE_MGMT as u8;
                    tx_buf[1..1 + resp_len].copy_from_slice(&resp_buf[..resp_len]);
                    let _ = shared
                        .controller
                        .send_data(*handle, &tx_buf[..1 + resp_len]);
                }
                // Drain pending notifications/indications triggered by the PDU.
                while let Some(n) = shared.ssap.dequeue_notification() {
                    if shared
                        .conn
                        .consume_tx_credit(*handle, sle_conn::tcid::SERVICE_MGMT)
                        .is_err()
                    {
                        break; // No credits remaining for notifications.
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
                            let _ = shared
                                .controller
                                .send_data(*handle, &ntf_buf[..1 + pdu_len]);
                        }
                    }
                }
                // Send credit grant if RX credits are low.
                if needs_grant {
                    if let Ok(granted) = shared
                        .conn
                        .grant_credits(*handle, sle_conn::tcid::SERVICE_MGMT)
                    {
                        send_credit_grant(
                            &shared.controller,
                            *handle,
                            sle_conn::tcid::SERVICE_MGMT,
                            granted,
                        );
                    }
                }
            } else {
                // User data — strip TCID prefix if present, enqueue to rx_queue.
                let tcid = if u16::from(raw[0]) == sle_conn::tcid::DEFAULT_DATA && raw.len() > 1 {
                    let _ = shared
                        .conn
                        .consume_rx_credit(*handle, sle_conn::tcid::DEFAULT_DATA);
                    sle_conn::tcid::DEFAULT_DATA
                } else {
                    0 // Legacy data without TCID prefix.
                };
                let payload = if tcid != 0 { &raw[1..] } else { raw };
                let seq = shared.conn.info(*handle).map(|e| e.seq.rx_seq).unwrap_or(0);
                let _ = shared.conn.receive_data(*handle, payload, seq);
            }
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
pub(crate) fn drain_controller_events(shared: &mut SubsystemShared) {
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
    pub(crate) fn new() -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(EventPump {
                work <- new_delayed_work!("sparklink_event_pump"),
            }),
            GFP_KERNEL,
        )
    }

    /// Schedule the first pump cycle.
    pub(crate) fn start(self: &Arc<Self>) {
        let _ = workqueue::system()
            .enqueue_delayed(self.clone(), msecs_to_jiffies(EVENT_PUMP_INTERVAL_MS));
    }
}

impl WorkItem for EventPump {
    type Pointer = Arc<EventPump>;

    fn run(this: Arc<EventPump>) {
        // Drain all pending controller events into both the broadcast ring
        // (for read() delivery) and the DLI event ring (for DLI_POLL_EVENT).
        // Also resolve pending commands from the management plane.
        let mut _pumped = 0u32;

        // Collect tagged events from USB event ring first (minimal lock hold).
        let mut tagged_events: [(Option<u16>, Option<sle_dli::SleEvent>); 32] =
            [const { (None, None) }; 32];
        let tagged_count = sle_usb::drain_usb_events(&mut tagged_events);

        {
            let mut ss = SUBSYSTEM.lock();
            if let Some(ref mut shared) = *ss {
                // Process VirtualController events (untagged, always active device).
                while let Some(ev) = shared.controller.poll_event() {
                    process_controller_event(shared, &ev);
                    _pumped += 1;
                    if _pumped >= 32 {
                        break;
                    }
                }

                // Process tagged USB events, routing to correct device.
                for item in tagged_events.iter_mut().take(tagged_count) {
                    let (dev_id, ev_opt) = core::mem::take(item);
                    if let Some(ev) = ev_opt {
                        let active = shared.active_dev_id;
                        if dev_id.is_none() || dev_id == active {
                            // Event belongs to active device: process directly.
                            process_controller_event(shared, &ev);
                        } else if let Some(target_id) = dev_id {
                            // Event belongs to a non-active device.
                            // Temporarily swap to the target device, process,
                            // then swap back.
                            if shared.switch_active_device(target_id, None).is_ok() {
                                process_controller_event(shared, &ev);
                                if let Some(orig_id) = active {
                                    let _ = shared.switch_active_device(orig_id, None);
                                }
                            }
                        }
                        _pumped += 1;
                    }
                }

                // Expire stale commands and garbage-collect resolved entries.
                let expired = shared.cmd_pending.expire_stale();
                if expired > 0 {
                    pr_warn!("sparklink: {} pending command(s) timed out\n", expired);
                }
                shared.cmd_pending.gc();

                // Check supervision timeouts on all connected entries.
                let timed_out = shared.conn.check_supervision_timeouts();
                for &h in timed_out.iter() {
                    if let Ok(peer) = shared.conn.timeout_disconnect(h) {
                        shared
                            .broadcast
                            .publish(sle_event::SleWireEvent::conn_state(
                                h,
                                sle_conn::ConnState::Connected as u8,
                                sle_conn::ConnState::Idle as u8,
                                peer,
                                0x08, // supervision timeout
                            ));
                    }
                }
            }
        }
        // Re-arm the delayed work for the next cycle.
        let _ = workqueue::system().enqueue_delayed(this, msecs_to_jiffies(EVENT_PUMP_INTERVAL_MS));
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
pub(crate) struct CommandWorker {
    #[pin]
    work: DelayedWork<CommandWorker>,
}

impl_has_delayed_work! {
    impl HasDelayedWork<Self> for CommandWorker { self.work }
}

impl CommandWorker {
    pub(crate) fn new() -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(CommandWorker {
                work <- new_delayed_work!("sparklink_cmd_worker"),
            }),
            GFP_KERNEL,
        )
    }

    /// Schedule the command worker to run soon.
    pub(crate) fn kick(self: &Arc<Self>) {
        let _ = workqueue::system()
            .enqueue_delayed(self.clone(), msecs_to_jiffies(CMD_WORKER_INTERVAL_MS));
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
                            let result = shared
                                .controller
                                .send_command_raw(req.opcode, &req.params[..plen]);
                            if result.is_err() {
                                // Immediately resolve the pending entry as
                                // failed so it does not linger until timeout.
                                shared.cmd_pending.resolve(
                                    req.opcode,
                                    0x03,
                                    &[], // HardwareFailure
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
        sle_dli::SleEvent::CommandComplete {
            opcode,
            status,
            data,
        } => sle_event::SleWireEvent::command_complete(
            *opcode as u16,
            *status as u8,
            data.as_slice(),
        ),
        sle_dli::SleEvent::CommandStatus { opcode, status } => {
            sle_event::SleWireEvent::command_status(*opcode as u16, *status as u8)
        }
        sle_dli::SleEvent::ConnComplete {
            handle,
            addr,
            status,
        } => {
            let new_state = if *status == sle_dli::SleStatus::Success {
                2u8
            } else {
                0u8
            };
            sle_event::SleWireEvent::conn_state(*handle, 1, new_state, *addr, *status as u8)
        }
        sle_dli::SleEvent::Disconnected { handle, reason } => {
            sle_event::SleWireEvent::conn_state(*handle, 2, 0, [0u8; 6], *reason)
        }
        sle_dli::SleEvent::AdvReport {
            addr,
            rssi,
            discovery_level,
            data,
        } => sle_event::SleWireEvent::adv_report(*addr, *rssi, *discovery_level, data.as_slice()),
        sle_dli::SleEvent::DataReceived { handle, data } => {
            sle_event::SleWireEvent::data_received(*handle, data.len() as u16)
        }
        sle_dli::SleEvent::HardwareError { code } => sle_event::SleWireEvent::hardware_error(*code),
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
        sle_dli::SleEvent::PhyUpdate {
            handle,
            mcs_index,
            bandwidth_mhz,
        } => sle_event::SleWireEvent::phy_update(*handle, *mcs_index, *bandwidth_mhz),
        sle_dli::SleEvent::ConnParamUpdate {
            handle,
            interval,
            latency,
            timeout,
        } => sle_event::SleWireEvent::conn_param_update(*handle, *interval, *latency, *timeout),
        sle_dli::SleEvent::DataLenChange {
            handle,
            max_tx_octets,
            max_rx_octets,
        } => sle_event::SleWireEvent::data_len_change(*handle, *max_tx_octets, *max_rx_octets),
        sle_dli::SleEvent::DataBufOverflow { link_type } => {
            sle_event::SleWireEvent::data_buf_overflow(*link_type)
        }
        sle_dli::SleEvent::PeerConnParamReq {
            handle,
            interval_min,
            interval_max,
            latency,
            timeout,
        } => sle_event::SleWireEvent::peer_conn_param_req(
            *handle,
            *interval_min,
            *interval_max,
            *latency,
            *timeout,
        ),
    }
}
