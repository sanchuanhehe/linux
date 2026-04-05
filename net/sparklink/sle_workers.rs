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
// Global EventPump reference for interrupt-driven wakeup
// ---------------------------------------------------------------------------

kernel::sync::global_lock! {
    /// Global reference to the EventPump Arc, set during initialisation.
    /// Accessed from USB completion callbacks (soft IRQ context) via
    /// `kick_event_pump()` to schedule immediate event processing.
    unsafe(uninit) static EVENT_PUMP_REF: Mutex<Option<Arc<EventPump>>> = None;
}

/// Initialise the global EVENT_PUMP_REF lock. Must be called once
/// during module init before any kick_event_pump() call.
pub(crate) fn init_event_pump_ref() {
    // SAFETY: called once from module_init, single-threaded.
    unsafe { EVENT_PUMP_REF.init() };
    *EVENT_PUMP_REF.lock() = None;
}

/// Store a reference to the EventPump in the global slot.
fn set_event_pump_ref(pump: &Arc<EventPump>) {
    *EVENT_PUMP_REF.lock() = Some(pump.clone());
}

/// Schedule the EventPump for immediate execution.
///
/// Safe to call from any context including USB soft-IRQ completion
/// callbacks.  If no EventPump is registered yet, this is a no-op.
///
/// Uses an atomic flag to avoid redundant Mutex acquisitions when
/// multiple producers (USB completions) kick in rapid succession.
pub(crate) fn kick_event_pump() {
    // Fast path: if already scheduled, skip the lock entirely.
    if KICK_SCHEDULED.swap(true, core::sync::atomic::Ordering::AcqRel) {
        return;
    }
    if let Some(ref pump) = *EVENT_PUMP_REF.lock() {
        let _ = workqueue::system().enqueue_delayed(pump.clone(), 0);
    }
}

/// Atomic flag to avoid redundant EVENT_PUMP_REF lock acquisitions.
/// Set by `kick_event_pump()`, cleared by `EventPump::run()`.
static KICK_SCHEDULED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Fast-poll countdown. When events are processed, this is set to a
/// positive value. Each subsequent run() that finds no events decrements
/// it. While non-zero, EventPump rearms at 1 jiffy instead of heartbeat,
/// giving USB round-trips time to complete during multi-step flows.
static FAST_POLL_REMAINING: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Background event pump
// ---------------------------------------------------------------------------

/// Heartbeat interval for supervision timeouts and cleanup (ms).
/// The pump no longer self-schedules at this interval for event
/// processing — it is kicked immediately by producers.  The heartbeat
/// ensures periodic maintenance even when no events arrive.
const EVENT_PUMP_HEARTBEAT_MS: u32 = 500;

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
/// Format per T/XS 20002-2025 §7.3.3 control signaling:
/// `[TCID_CMTC] [code=0xFC] [identifier] [length LE16=0x0003] [target_tcid] [credits LE16]`
pub(crate) fn send_credit_grant(
    ctrl: &sle_dli::ControllerBackend,
    handle: u16,
    target_tcid: u16,
    credits: u16,
    identifier: u8,
) {
    let mut buf = [0u8; sle_conn::CREDIT_GRANT_PDU_SIZE];
    buf[0] = sle_conn::tcid::MANAGEMENT as u8;
    buf[1] = sle_conn::CREDIT_GRANT_PDU_TYPE;
    buf[2] = identifier;
    buf[3] = 0x03; // length LE16 low byte: target_tcid(1) + credits(2)
    buf[4] = 0x00; // length LE16 high byte
    buf[5] = target_tcid as u8;
    let c = credits.to_le_bytes();
    buf[6] = c[0];
    buf[7] = c[1];
    let _ = ctrl.send_data(handle, &buf);
}

/// Process a single controller event: resolve pending commands, drive
/// state machine transitions, and publish to broadcast ring / DLI ring.
///
/// Called from both `EventPump` (periodic background) and inline after
/// ioctl commands (immediate drain for synchronous controller backends).
#[inline(never)]
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
                if shared.conn.confirm_connecting_by_addr(addr).is_none()
                    && !shared.conn.has_addr(addr)
                {
                    // Incoming connection — no prior ConnectPending entry
                    // and no existing entry for this address.
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
                && raw.len() >= sle_conn::CREDIT_GRANT_PDU_SIZE
                && raw[1] == sle_conn::CREDIT_GRANT_PDU_TYPE
            {
                // Credit grant signaling on management channel (T/XS 20002-2025 §7.3.3).
                // Format: [TCID 0x02] [code 0xFC] [identifier] [length LE16] [target_tcid] [credits LE16]
                let target_tcid = u16::from(raw[5]);
                let credits = u16::from_le_bytes([raw[6], raw[7]]);
                let _ = shared.conn.receive_credits(*handle, target_tcid, credits);
            } else if u16::from(raw[0]) == sle_conn::tcid::MANAGEMENT
                && raw.len() >= 5
                && raw[1] != sle_conn::CREDIT_GRANT_PDU_TYPE
            {
                // Transport control signaling on management channel (T/XS 20002-2025 §7.3.4).
                let sig_data = &raw[1..];
                let mut resp_buf = [0u8; 32];
                let resp_len = shared
                    .conn
                    .handle_transport_signaling(*handle, sig_data, &mut resp_buf)
                    .unwrap_or(0);
                if resp_len > 0 {
                    let _ = shared
                        .controller
                        .send_data(*handle, &resp_buf[..resp_len]);
                }
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
                    if let Ok((granted, id)) = shared
                        .conn
                        .grant_credits(*handle, sle_conn::tcid::SERVICE_MGMT)
                    {
                        send_credit_grant(
                            &shared.controller,
                            *handle,
                            sle_conn::tcid::SERVICE_MGMT,
                            granted,
                            id,
                        );
                    }
                }
                // After ExchangeInfo negotiation: if reliable mode is agreed
                // but the reliable channel is not yet created, initiate
                // TCID_Connect_Req on the management channel.
                let needs_connect = shared
                    .conn
                    .get_ssap_session(*handle)
                    .map(|sess| sess.reliable_mode && sess.reliable_tcid.is_none())
                    .unwrap_or(false);
                if needs_connect {
                    let cfg = sle_conn::ReliableModeConfig::default();
                    let mut sig_buf = [0u8; 24];
                    if let Ok(sig_len) =
                        shared.conn.build_tcid_connect_req(*handle, &cfg, &mut sig_buf)
                    {
                        let _ = shared.controller.send_data(*handle, &sig_buf[..sig_len]);
                    }
                }
            } else {
                // Check if this is an SSAP PDU on the dynamic reliable channel.
                let first_byte_tcid = u16::from(raw[0]);
                let is_ssap_reliable = raw.len() > 1
                    && shared
                        .conn
                        .ssap_reliable_tcid(*handle)
                        .map(|t| t == first_byte_tcid)
                        .unwrap_or(false);
                if is_ssap_reliable {
                    // SSAP PDU on reliable transport channel.
                    let needs_grant = shared
                        .conn
                        .consume_rx_credit(*handle, first_byte_tcid);
                    let pdu_data = &raw[1..];
                    let mut resp_buf = [0u8; sle_ssap::SSAP_PDU_MAX];
                    let resp_len = shared
                        .conn
                        .process_ssap_pdu(*handle, pdu_data, &mut shared.ssap, &mut resp_buf)
                        .unwrap_or(0);
                    if resp_len > 0
                        && shared
                            .conn
                            .consume_tx_credit(*handle, first_byte_tcid)
                            .is_ok()
                    {
                        let mut tx_buf = [0u8; 1 + sle_ssap::SSAP_PDU_MAX];
                        tx_buf[0] = first_byte_tcid as u8;
                        tx_buf[1..1 + resp_len].copy_from_slice(&resp_buf[..resp_len]);
                        let _ = shared
                            .controller
                            .send_data(*handle, &tx_buf[..1 + resp_len]);
                    }
                    if needs_grant {
                        if let Ok((granted, id)) = shared
                            .conn
                            .grant_credits(*handle, first_byte_tcid)
                        {
                            send_credit_grant(
                                &shared.controller,
                                *handle,
                                first_byte_tcid,
                                granted,
                                id,
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
        }
        // -----------------------------------------------------------------
        // Pairing events — drive the security state machine and
        // send response commands back to the controller.
        // -----------------------------------------------------------------
        sle_dli::SleEvent::PairInfoExchange {
            handle,
            io_cap,
            oob_flag,
            auth_req,
            max_key_len,
            sec_dist,
            psk_ind,
            crypto_cap,
        } => {
            if let Ok(reply) = shared.security.on_pair_info_exchange(
                *handle, *io_cap, *oob_flag, *auth_req,
                *max_key_len, *sec_dist, *psk_ind, crypto_cap,
            ) {
                let _ = shared.controller.pair_info_exchange_reply(&reply);
            }
        }
        sle_dli::SleEvent::PairOptionReport {
            handle,
            key_len,
            auth_method,
            crypto_alg,
            public_key,
        } => {
            if let Ok(accept) = shared.security.on_pair_option_report(
                *handle, *key_len, *auth_method, crypto_alg, public_key.as_slice(),
            ) {
                let _ = shared.controller.pair_option_accept(&accept);
            }
        }
        sle_dli::SleEvent::PairRandom { handle, random } => {
            if let Ok(resp) = shared.security.on_pair_random(*handle, random) {
                let _ = shared.controller.pair_random(&resp);
            }
        }
        sle_dli::SleEvent::PairConfirm { handle, confirm } => {
            if let Ok(resp) = shared.security.on_pair_confirm(*handle, confirm) {
                let _ = shared.controller.pair_confirm(&resp);
            }
        }
        sle_dli::SleEvent::DHKeyCheck { handle, dhkey_check } => {
            if let Ok(resp) = shared.security.on_dhkey_verify(*handle, dhkey_check) {
                let _ = shared.controller.dhkey_verify(&resp);
            }
        }
        sle_dli::SleEvent::PairFailure { handle, reason } => {
            shared.security.on_pair_failure(*handle, *reason);
        }
        // -----------------------------------------------------------------
        // Sync link setup events — update ConnManager state machine.
        // -----------------------------------------------------------------
        sle_dli::SleEvent::SyncUcastSetupRequest {
            async_handle,
            sync_handle,
            event_group_set_id,
            event_group_id,
        } => {
            let _ = shared.conn.handle_sync_ucast_setup_request(
                *async_handle, *sync_handle, *event_group_set_id, *event_group_id);
        }
        sle_dli::SleEvent::SyncUcastSetupComplete {
            sync_handle,
            status,
            ..
        } => {
            let _ = shared.conn.handle_sync_ucast_setup_complete(*sync_handle, *status);
        }
        sle_dli::SleEvent::SyncMcastSetupRequest {
            async_handle,
            sync_handle,
        } => {
            let _ = shared.conn.handle_sync_mcast_setup_request(*async_handle, *sync_handle);
        }
        sle_dli::SleEvent::SyncMcastSetupComplete {
            sync_handle,
            status,
            ..
        } => {
            let _ = shared.conn.handle_sync_mcast_setup_complete(*sync_handle, *status);
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
/// (UartController, SpiController) inline without waiting for the
/// next EventPump cycle. Also drains USB event ring entries so that
/// multi-step protocol exchanges (e.g. pairing) can complete within
/// a single ioctl call.
pub(crate) fn drain_controller_events(shared: &mut SubsystemShared) {
    // Multiple rounds: each round may generate new DLI commands whose
    // responses arrive in a subsequent round. Limit total iterations
    // to bound lock hold time on the ioctl path.
    let mut total = 0u32;
    for _round in 0..4 {
        let mut drained_this_round = 0u32;

        // 1. Inline controller events (UART/SPI synchronous responses)
        while let Some(ev) = shared.controller.poll_event() {
            process_controller_event(shared, &ev);
            drained_this_round += 1;
            total += 1;
            if total >= 32 {
                return;
            }
        }

        // 2. USB event ring entries (with device-ID filtering)
        let mut tagged: [(Option<u16>, Option<sle_dli::SleEvent>); 64] =
            [const { (None, None) }; 64];
        let count = sle_usb::drain_usb_events(&mut tagged);
        let active = shared.active_dev_id;
        for item in tagged.iter_mut().take(count) {
            let (dev_id, ev_opt) = core::mem::take(item);
            if let Some(ev) = ev_opt {
                if dev_id.is_none() || dev_id == active {
                    process_controller_event(shared, &ev);
                } else {
                    let is_conn_lifecycle = matches!(
                        ev,
                        sle_dli::SleEvent::ConnComplete { .. }
                            | sle_dli::SleEvent::Disconnected { .. }
                    );
                    if is_conn_lifecycle {
                        drained_this_round += 1;
                        total += 1;
                        continue;
                    }
                    process_controller_event(shared, &ev);
                }
                drained_this_round += 1;
                total += 1;
                if total >= 32 {
                    return;
                }
            }
        }

        if drained_this_round == 0 {
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

    /// Schedule the first pump cycle and register the global reference
    /// so that interrupt-context producers can kick the pump.
    pub(crate) fn start(self: &Arc<Self>) {
        set_event_pump_ref(self);
        let _ = workqueue::system()
            .enqueue_delayed(self.clone(), msecs_to_jiffies(EVENT_PUMP_HEARTBEAT_MS));
    }
}

impl WorkItem for EventPump {
    type Pointer = Arc<EventPump>;

    fn run(this: Arc<EventPump>) {
        // Drain all pending controller events into both the broadcast ring
        // (for read() delivery) and the DLI event ring (for DLI_POLL_EVENT).
        // Also resolve pending commands from the management plane.
        //
        // The outer loop retries after processing events because
        // process_controller_event() may send new DLI commands whose
        // USB responses arrive while we still hold the SUBSYSTEM lock.
        // Without retrying, those responses would wait until the next
        // heartbeat (up to 500ms) — too slow for multi-step sequences
        // like pairing which need sub-millisecond round-trips.
        let mut _pumped = 0u32;
        let mut rearm_jiffies = msecs_to_jiffies(EVENT_PUMP_HEARTBEAT_MS) as u64;

        // Log USB event ring overflow if any events were dropped.
        {
            let usb_dropped = sle_usb::take_dropped_count();
            if usb_dropped > 0 {
                pr_warn!(
                    "sparklink: USB event ring overflow: {} event(s) dropped\n",
                    usb_dropped
                );
            }
        }

        // Outer retry loop: keep draining until no new events arrive.
        // Limit iterations to avoid hogging the CPU if events keep arriving.
        for _pass in 0..16u32 {
            let mut tagged_events: [(Option<u16>, Option<sle_dli::SleEvent>); 64] =
                [const { (None, None) }; 64];
            let tagged_count = sle_usb::drain_usb_events(&mut tagged_events);
            let mut drained_this_pass = 0u32;

            {
                let mut ss = SUBSYSTEM.lock();
                if let Some(ref mut shared) = *ss {
                    // Process inline controller events (untagged, always active device).
                    while let Some(ev) = shared.controller.poll_event() {
                        process_controller_event(shared, &ev);
                        _pumped += 1;
                        drained_this_pass += 1;
                        if _pumped >= 256 {
                            break;
                        }
                    }

                    // Process tagged USB events, routing to correct device.
                    for item in tagged_events.iter_mut().take(tagged_count) {
                        let (dev_id, ev_opt) = core::mem::take(item);
                        if let Some(ev) = ev_opt {
                            let active = shared.active_dev_id;
                            if dev_id.is_none() || dev_id == active {
                                process_controller_event(shared, &ev);
                            } else if let Some(target_id) = dev_id {
                                // Events from non-active USB devices: skip
                                // connection lifecycle events (ConnComplete /
                                // Disconnected) because those are the
                                // acceptor-side mirrors of connections already
                                // tracked on the active device.  Processing
                                // them would create duplicate entries in the
                                // shared ConnManager.
                                let is_conn_lifecycle = matches!(
                                    ev,
                                    sle_dli::SleEvent::ConnComplete { .. }
                                        | sle_dli::SleEvent::Disconnected { .. }
                                );
                                if is_conn_lifecycle {
                                    _pumped += 1;
                                    drained_this_pass += 1;
                                    continue;
                                }
                                if shared.switch_to_device(target_id).is_ok() {
                                    process_controller_event(shared, &ev);
                                    if let Some(orig_id) = active {
                                        let _ = shared.switch_to_device(orig_id);
                                    }
                                } else {
                                    pr_warn!(
                                        "sparklink: dropped event for device {} (switch failed)\n",
                                        target_id
                                    );
                                }
                            }
                            _pumped += 1;
                            drained_this_pass += 1;
                        }
                    }

                    // Only perform maintenance on the final pass.
                    if drained_this_pass == 0 || _pumped >= 256 {
                        let expired = shared.cmd_pending.expire_stale();
                        if expired > 0 {
                            pr_warn!("sparklink: {} pending command(s) timed out\n", expired);
                        }
                        shared.cmd_pending.gc();

                        let mut timeout_buf = [0u16; sle_conn::MAX_CONNECTIONS];
                        let n = shared.conn.check_supervision_timeouts(&mut timeout_buf);
                        for &h in &timeout_buf[..n] {
                            if let Ok(peer) = shared.conn.timeout_disconnect(h) {
                                shared
                                    .broadcast
                                    .publish(sle_event::SleWireEvent::conn_state(
                                        h,
                                        sle_conn::ConnState::Connected as u8,
                                        sle_conn::ConnState::Idle as u8,
                                        peer,
                                        0x08,
                                    ));
                            }
                        }

                        let heartbeat = msecs_to_jiffies(EVENT_PUMP_HEARTBEAT_MS) as u64;
                        rearm_jiffies = match shared.conn.next_supervision_jiffies() {
                            Some(j) if j < heartbeat => j,
                            _ => heartbeat,
                        };
                    }
                }
            }

            if drained_this_pass == 0 || _pumped >= 256 {
                break;
            }
        }
        // Re-arm: if events were processed this cycle, new USB responses
        // may be in-flight (e.g. pairing multi-step flow).  Set a fast-poll
        // countdown so subsequent empty runs still rearm at 1 jiffy,
        // giving USB round-trips (~1-8ms) time to deliver responses.
        if _pumped > 0 {
            // Reset countdown: stay in fast-poll for up to 64 more runs.
            FAST_POLL_REMAINING.store(64, core::sync::atomic::Ordering::Relaxed);
            rearm_jiffies = 1;
        } else {
            let remaining = FAST_POLL_REMAINING.load(core::sync::atomic::Ordering::Relaxed);
            if remaining > 0 {
                FAST_POLL_REMAINING.store(remaining - 1, core::sync::atomic::Ordering::Relaxed);
                rearm_jiffies = 1;
            }
        }
        // Clear the kick-scheduled flag so new producers can kick again.
        KICK_SCHEDULED.store(false, core::sync::atomic::Ordering::Release);
        let _ = workqueue::system()
            .enqueue_delayed(this, rearm_jiffies as kernel::time::Jiffies);
    }
}

// ---------------------------------------------------------------------------
// Background command worker (TX dispatch)
// ---------------------------------------------------------------------------

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

    /// Schedule the command worker to run immediately.
    pub(crate) fn kick(self: &Arc<Self>) {
        let _ = workqueue::system()
            .enqueue_delayed(self.clone(), 0);
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
#[inline(never)]
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

        // --- HIGH priority events ---
        sle_dli::SleEvent::PowerChangeReport {
            handle,
            reason,
            frame_type,
            bandwidth,
            pilot_density,
            tx_power,
            power_level,
            offset,
        } => sle_event::SleWireEvent::power_change_report(
            *handle,
            *reason,
            *frame_type,
            *bandwidth,
            *pilot_density,
            *tx_power,
            *power_level,
            *offset,
        ),
        sle_dli::SleEvent::NumCompletedPackets {
            handle,
            num_completed,
        } => sle_event::SleWireEvent::num_completed_packets(*handle, *num_completed),
        sle_dli::SleEvent::EncryptionParamReq { handle } => {
            sle_event::SleWireEvent::encryption_param_req(*handle)
        }

        // --- MEDIUM — Peer Info events ---
        sle_dli::SleEvent::ControllerSignalData {
            handle,
            signal_id,
            data,
        } => {
            let mut evt = sle_event::ControllerSignalDataEvent {
                handle: *handle,
                signal_id: *signal_id,
                data_len: data.len().min(32) as u8,
                _pad: 0,
                data: [0u8; 32],
            };
            let len = data.len().min(32);
            evt.data[..len].copy_from_slice(&data[..len]);
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::ControllerSignalData,
                &evt,
            )
        }
        sle_dli::SleEvent::ReadPeerFeatures {
            handle,
            status,
            features,
        } => {
            let evt = sle_event::ReadPeerFeaturesEvent {
                handle: *handle,
                status: *status,
                _pad: 0,
                features: *features,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::ReadPeerFeatures,
                &evt,
            )
        }
        sle_dli::SleEvent::ReadPeerVersion {
            handle,
            status,
            version,
            manufacturer,
            subversion,
        } => {
            let evt = sle_event::ReadPeerVersionEvent {
                handle: *handle,
                manufacturer: *manufacturer,
                subversion: *subversion,
                status: *status,
                version: *version,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::ReadPeerVersion,
                &evt,
            )
        }
        sle_dli::SleEvent::ReadPeerPower {
            handle,
            status,
            frame_type,
            bandwidth,
            pilot_density,
            tx_power,
            power_level,
        } => {
            let evt = sle_event::ReadPeerPowerEvent {
                handle: *handle,
                status: *status,
                frame_type: *frame_type,
                bandwidth: *bandwidth,
                pilot_density: *pilot_density,
                tx_power: *tx_power,
                power_level: *power_level,
            };
            sle_event::SleWireEvent::from_payload_pub(sle_event::SleEventType::ReadPeerPower, &evt)
        }
        sle_dli::SleEvent::InquiryRequestReport {
            adv_handle,
            addr_type,
            addr,
            rssi,
            ..
        } => {
            let evt = sle_event::InquiryRequestReportEvent {
                addr: *addr,
                addr_type: *addr_type,
                adv_handle: *adv_handle,
                rssi: *rssi,
                data_len: 0,
                _pad: [0u8; 2],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::InquiryRequestReport,
                &evt,
            )
        }

        // --- MEDIUM — Pairing events ---
        sle_dli::SleEvent::PairInfoExchange {
            handle,
            io_cap,
            oob_flag,
            auth_req,
            max_key_len,
            sec_dist,
            psk_ind,
            crypto_cap,
        } => {
            let evt = sle_event::PairInfoEvent {
                handle: *handle,
                io_cap: *io_cap,
                oob_flag: *oob_flag,
                auth_req: *auth_req,
                max_key_len: *max_key_len,
                sec_dist: *sec_dist,
                psk_ind: *psk_ind,
                crypto_cap: *crypto_cap,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairInfoExchangeReq,
                &evt,
            )
        }
        sle_dli::SleEvent::PairInfoReport {
            handle,
            io_cap,
            oob_flag,
            auth_req,
            max_key_len,
            sec_dist,
            psk_ind,
            crypto_cap,
        } => {
            let evt = sle_event::PairInfoEvent {
                handle: *handle,
                io_cap: *io_cap,
                oob_flag: *oob_flag,
                auth_req: *auth_req,
                max_key_len: *max_key_len,
                sec_dist: *sec_dist,
                psk_ind: *psk_ind,
                crypto_cap: *crypto_cap,
            };
            sle_event::SleWireEvent::from_payload_pub(sle_event::SleEventType::PairInfoReport, &evt)
        }
        sle_dli::SleEvent::PairOptionReport {
            handle,
            key_len,
            auth_method,
            crypto_alg,
            public_key,
        } => {
            let mut evt = sle_event::PairOptionReportEvent {
                handle: *handle,
                key_len: *key_len,
                auth_method: *auth_method,
                crypto_alg: *crypto_alg,
                public_key: [0u8; 32],
            };
            let len = public_key.len().min(32);
            evt.public_key[..len].copy_from_slice(&public_key[..len]);
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairOptionReport,
                &evt,
            )
        }
        sle_dli::SleEvent::PeerPublicKey { handle, public_key } => {
            let mut evt = sle_event::PeerPublicKeyReportEvent {
                handle: *handle,
                _pad: [0u8; 2],
                public_key: [0u8; 32],
            };
            let len = public_key.len().min(32);
            evt.public_key[..len].copy_from_slice(&public_key[..len]);
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PeerPublicKeyReport,
                &evt,
            )
        }
        sle_dli::SleEvent::PairExtData {
            handle,
            ext_pubkey_x,
            ..
        } => {
            let mut evt = sle_event::PairExtDataReportEvent {
                handle: *handle,
                _pad: [0u8; 2],
                ext_key_data: [0u8; 36],
            };
            let len = ext_pubkey_x.len().min(32);
            evt.ext_key_data[..len].copy_from_slice(&ext_pubkey_x[..len]);
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairExtDataReport,
                &evt,
            )
        }
        sle_dli::SleEvent::KeypressNotify { handle, action } => {
            let evt = sle_event::KeypressNotificationEvent {
                handle: *handle,
                _pad: [0u8; 2],
                action: *action,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::KeypressNotification,
                &evt,
            )
        }
        sle_dli::SleEvent::PairRandom { handle, random } => {
            let evt = sle_event::PairRandomReportEvent {
                handle: *handle,
                _pad: [0u8; 2],
                random: *random,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairRandomReport,
                &evt,
            )
        }
        sle_dli::SleEvent::PairConfirm { handle, confirm } => {
            let evt = sle_event::PairConfirmReportEvent {
                handle: *handle,
                _pad: [0u8; 2],
                confirm: *confirm,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairConfirmReport,
                &evt,
            )
        }
        sle_dli::SleEvent::DHKeyCheck {
            handle,
            dhkey_check,
        } => {
            let evt = sle_event::DHKeyCheckReportEvent {
                handle: *handle,
                _pad: [0u8; 2],
                dhkey_check: *dhkey_check,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::DHKeyCheckReport,
                &evt,
            )
        }
        sle_dli::SleEvent::PairFailure { handle, reason } => {
            let evt = sle_event::PairFailureReportEvent {
                handle: *handle,
                reason: *reason,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PairFailureReport,
                &evt,
            )
        }

        // --- LOW — Measurement events ---
        sle_dli::SleEvent::NarrowbandMeasInfo {
            handle,
            meas_type,
            status,
            config_index,
        } => {
            let evt = sle_event::NarrowbandMeasInfoEvent {
                handle: *handle,
                meas_type: *meas_type,
                status: *status,
                config_index: *config_index,
                _pad: [0u8; 2],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::NarrowbandMeasInfo,
                &evt,
            )
        }
        sle_dli::SleEvent::NarrowbandMeasStateChange {
            status,
            config_index,
            meas_state,
        } => {
            let evt = sle_event::NarrowbandMeasStateChangeEvent {
                status: *status,
                config_index: *config_index,
                meas_state: *meas_state,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::NarrowbandMeasStateChange,
                &evt,
            )
        }
        sle_dli::SleEvent::NarrowbandMeasParamReport {
            handle,
            status,
            config_index,
        } => {
            let evt = sle_event::NarrowbandMeasParamReportEvent {
                handle: *handle,
                status: *status,
                config_index: *config_index,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::NarrowbandMeasParamReport,
                &evt,
            )
        }
        sle_dli::SleEvent::LocalNarrowbandMeasCap {
            status,
            antenna_count,
            signal_cap,
            report_cap,
        } => {
            let evt = sle_event::LocalNarrowbandMeasCapEvent {
                status: *status,
                antenna_count: *antenna_count,
                signal_cap: *signal_cap,
                report_cap: *report_cap,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::LocalNarrowbandMeasCap,
                &evt,
            )
        }
        sle_dli::SleEvent::PeerNarrowbandMeasCap {
            handle,
            status,
            antenna_count,
            signal_cap,
            report_cap,
        } => {
            let evt = sle_event::PeerNarrowbandMeasCapEvent {
                handle: *handle,
                status: *status,
                antenna_count: *antenna_count,
                signal_cap: *signal_cap,
                report_cap: *report_cap,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::PeerNarrowbandMeasCap,
                &evt,
            )
        }
        sle_dli::SleEvent::MeasStateChange {
            source,
            status,
            instance_handle,
            instance_state,
        } => {
            let evt = sle_event::MeasStateChangeEvent {
                source: *source,
                status: *status,
                instance_handle: *instance_handle,
                instance_state: *instance_state,
                _pad: [0u8; 3],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::MeasStateChange,
                &evt,
            )
        }
        sle_dli::SleEvent::MeasQuantityReport {
            source,
            meas_source,
            seq,
            instance_handle,
            meas_count,
        } => {
            let evt = sle_event::MeasQuantityReportEvent {
                source: *source,
                meas_source: *meas_source,
                seq: *seq,
                instance_handle: *instance_handle,
                meas_count: *meas_count,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::MeasQuantityReport,
                &evt,
            )
        }

        // --- LOW — SLB events ---
        sle_dli::SleEvent::SlbAdvReport {
            mac_addr,
            channel,
            bandwidth,
            rssi,
            ..
        } => {
            let evt = sle_event::SlbAdvReportEvent {
                mac_addr: *mac_addr,
                channel: *channel,
                bandwidth: *bandwidth,
                rssi: *rssi,
                data_len: 0,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(sle_event::SleEventType::SlbAdvReport, &evt)
        }
        sle_dli::SleEvent::SlbConnComplete {
            handle,
            status,
            peer_addr,
        } => {
            let evt = sle_event::SlbConnCompleteEvent {
                handle: *handle,
                status: *status,
                _pad: 0,
                peer_addr: *peer_addr,
                _pad2: [0u8; 2],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SlbConnComplete,
                &evt,
            )
        }
        sle_dli::SleEvent::SlbUcastChannelComplete {
            channel_handle,
            conn_handle,
            status,
            max_pkt_len,
            max_pkt_count,
        } => {
            let evt = sle_event::SlbUcastChannelCompleteEvent {
                channel_handle: *channel_handle,
                conn_handle: *conn_handle,
                max_pkt_len: *max_pkt_len,
                max_pkt_count: *max_pkt_count,
                status: *status,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SlbUcastChannelComplete,
                &evt,
            )
        }
        sle_dli::SleEvent::SlbUcastChannelUpdate {
            channel_handle,
            status,
            max_pkt_len,
            max_pkt_count,
        } => {
            let evt = sle_event::SlbUcastChannelUpdateEvent {
                channel_handle: *channel_handle,
                max_pkt_len: *max_pkt_len,
                max_pkt_count: *max_pkt_count,
                status: *status,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SlbUcastChannelUpdate,
                &evt,
            )
        }
        sle_dli::SleEvent::SlbChannelDelete {
            channel_handle,
            status,
        } => {
            let evt = sle_event::SlbChannelDeleteEvent {
                channel_handle: *channel_handle,
                status: *status,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SlbChannelDelete,
                &evt,
            )
        }
        sle_dli::SleEvent::SlbNumCompletedPackets {
            channel_handle,
            num_completed,
        } => {
            let evt = sle_event::SlbNumCompletedPacketsEvent {
                channel_handle: *channel_handle,
                num_completed: *num_completed,
                _pad: 0,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SlbNumCompletedPackets,
                &evt,
            )
        }

        // --- LOW — Sync Link events ---
        sle_dli::SleEvent::TimeSyncStatusUpdate {
            sync_status,
            clock_source,
            accuracy,
        } => {
            let evt = sle_event::TimeSyncStatusUpdateEvent {
                accuracy: *accuracy,
                sync_status: *sync_status,
                clock_source: *clock_source,
                _pad: [0u8; 2],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::TimeSyncStatusUpdate,
                &evt,
            )
        }
        sle_dli::SleEvent::TimeSyncRequest {
            time_seq,
            send_time,
        } => {
            let evt = sle_event::TimeSyncRequestEvent {
                time_seq: *time_seq,
                send_time: *send_time,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::TimeSyncRequest,
                &evt,
            )
        }
        sle_dli::SleEvent::SyncUcastSetupRequest {
            async_handle,
            sync_handle,
            event_group_set_id,
            event_group_id,
        } => {
            let evt = sle_event::SyncUcastSetupRequestEvent {
                async_handle: *async_handle,
                sync_handle: *sync_handle,
                event_group_set_id: *event_group_set_id,
                event_group_id: *event_group_id,
                _pad: [0u8; 2],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SyncUcastSetupRequest,
                &evt,
            )
        }
        sle_dli::SleEvent::SyncUcastSetupComplete {
            async_handle,
            sync_handle,
            status,
        } => {
            let evt = sle_event::SyncUcastSetupCompleteEvent {
                async_handle: *async_handle,
                sync_handle: *sync_handle,
                status: *status,
                _pad: [0u8; 3],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SyncUcastSetupComplete,
                &evt,
            )
        }
        sle_dli::SleEvent::SyncMcastSetupRequest {
            async_handle,
            sync_handle,
        } => {
            let evt = sle_event::SyncMcastSetupRequestEvent {
                async_handle: *async_handle,
                sync_handle: *sync_handle,
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SyncMcastSetupRequest,
                &evt,
            )
        }
        sle_dli::SleEvent::SyncMcastSetupComplete {
            async_handle,
            sync_handle,
            status,
        } => {
            let evt = sle_event::SyncMcastSetupCompleteEvent {
                async_handle: *async_handle,
                sync_handle: *sync_handle,
                status: *status,
                _pad: [0u8; 3],
            };
            sle_event::SleWireEvent::from_payload_pub(
                sle_event::SleEventType::SyncMcastSetupComplete,
                &evt,
            )
        }
    }
}
