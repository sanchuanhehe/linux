// SPDX-License-Identifier: GPL-2.0

#![allow(dead_code, unreachable_pub)]

//! SparkLink event notification subsystem.
//!
//! Provides a typed event queue that enables userspace to receive
//! asynchronous notifications from the SparkLink subsystem. Events
//! are serialized into a fixed-size wire format and delivered through
//! the `read()` system call on `/dev/sparklink`.
//!
//! Supported event types:
//!   - Connection state changes (connected, disconnected, rejected)
//!   - Advertising reports (scan results)
//!   - Data received indication
//!   - Security state changes
//!   - Power state changes
//!   - Hardware errors

use kernel::prelude::*;
use core::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Event type codes
// ---------------------------------------------------------------------------

/// Event type identifier in the wire header.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SleEventType {
    /// Connection state changed (new, connected, disconnected, rejected).
    ConnStateChanged = 0x01,
    /// Advertising report received during scanning.
    AdvReport = 0x02,
    /// Data received on a connection.
    DataReceived = 0x03,
    /// Security state changed (pairing started, completed, failed).
    SecurityChanged = 0x04,
    /// Power state changed.
    PowerChanged = 0x05,
    /// Hardware or controller error.
    HardwareError = 0x06,
    /// DLI command completed (opcode + status).
    CommandComplete = 0x07,
    /// DLI command status (async command accepted/rejected).
    CommandStatus = 0x08,
    /// Broadcast / advertising terminated.
    BroadcastEnd = 0x09,
    /// PHY parameters updated (MCS, bandwidth, etc.).
    PhyUpdate = 0x0A,
    /// Connection parameters updated.
    ConnParamUpdate = 0x0B,
    /// Data length changed on a connection.
    DataLenChange = 0x0C,
    /// Controller data buffer overflow.
    DataBufOverflow = 0x0D,
    /// Remote peer requests connection parameter change.
    PeerConnParamReq = 0x0E,
}

// ---------------------------------------------------------------------------
// Event payloads
// ---------------------------------------------------------------------------

/// Connection state change event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnStateEvent {
    /// Connection handle.
    pub handle: u16,
    /// New state (0=Idle/removed, 1=Connecting, 2=Connected, 3=Disconnecting).
    pub new_state: u8,
    /// Previous state.
    pub old_state: u8,
    /// Peer address.
    pub peer_addr: [u8; 6],
    /// Reason code (0=normal, others TBD).
    pub reason: u8,
    _pad: u8,
}

/// Advertising report event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AdvReportEvent {
    /// Advertiser address.
    pub addr: [u8; 6],
    /// RSSI in dBm.
    pub rssi: i8,
    /// Discovery level.
    pub discovery_level: u8,
    /// Device name length.
    pub name_len: u8,
    /// Device name (truncated to 31 bytes).
    pub name: [u8; 31],
}

/// Data received indication event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DataReceivedEvent {
    /// Connection handle.
    pub handle: u16,
    /// Number of bytes available in the RX queue.
    pub rx_bytes: u16,
}

/// Security state change event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SecurityEvent {
    /// New security state.
    pub state: u8,
    /// Pairing method (0=none, 1=JustWorks, 2=PSK).
    pub method: u8,
    /// Whether encryption is active.
    pub encrypted: u8,
    _pad: u8,
}

/// Power state change event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PowerEvent {
    /// New power state (0=Active, 1=Sniff, 2=Idle, 3=Suspended).
    pub state: u8,
    /// Estimated power consumption percentage.
    pub power_pct: u8,
    _pad: [u8; 2],
}

/// Hardware error event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HardwareErrorEvent {
    /// Error code.
    pub error_code: u8,
    _pad: [u8; 3],
}

/// DLI command completed event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CommandCompleteEvent {
    /// Opcode of the completed command.
    pub opcode: u16,
    /// Status code (0 = success).
    pub status: u8,
    /// Return data length.
    pub data_len: u8,
    /// Return data (up to 32 bytes).
    pub data: [u8; 32],
}

/// DLI command status event (async command accepted/rejected).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CommandStatusEvent {
    /// Opcode of the command.
    pub opcode: u16,
    /// Status code (0 = pending/accepted).
    pub status: u8,
    _pad: u8,
}

/// Broadcast terminated event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct BroadcastEndEvent {
    /// Reason code for termination.
    pub reason: u8,
    _pad: [u8; 3],
}

/// PHY parameters updated event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PhyUpdateEvent {
    /// Connection handle (0xFFFF = local).
    pub handle: u16,
    /// New MCS index.
    pub mcs_index: u8,
    /// New bandwidth in MHz.
    pub bandwidth_mhz: u8,
}

/// Connection parameters updated event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ConnParamUpdateEvent {
    /// Connection handle.
    pub handle: u16,
    /// New interval (in 1.25ms units).
    pub interval: u16,
    /// New latency (number of events).
    pub latency: u16,
    /// New supervision timeout (in 10ms units).
    pub timeout: u16,
}

/// Data length changed event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DataLenChangeEvent {
    /// Connection handle.
    pub handle: u16,
    /// Max TX octets.
    pub max_tx_octets: u16,
    /// Max RX octets.
    pub max_rx_octets: u16,
    _pad: u16,
}

/// Data buffer overflow event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DataBufOverflowEvent {
    /// Link type (0=async, 1=sync).
    pub link_type: u8,
    _pad: [u8; 3],
}

/// Peer connection parameter request event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PeerConnParamReqEvent {
    /// Connection handle.
    pub handle: u16,
    /// Requested minimum interval.
    pub interval_min: u16,
    /// Requested maximum interval.
    pub interval_max: u16,
    /// Requested latency.
    pub latency: u16,
    /// Requested supervision timeout.
    pub timeout: u16,
    _pad: u16,
}

// ---------------------------------------------------------------------------
// Wire format: [type: u8] [length: u8] [payload: ...] [pad to 4-byte align]
// ---------------------------------------------------------------------------

/// Maximum payload size for any event.
pub const EVENT_PAYLOAD_MAX: usize = 40;

/// Wire-format event header + payload.
///
/// On-wire layout (packed):
///   byte 0:      event type (SleEventType)
///   byte 1:      payload length
///   byte 2..N:   payload data
///   pad to 4-byte boundary
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SleWireEvent {
    /// Event type.
    pub event_type: u8,
    /// Payload length in bytes.
    pub payload_len: u8,
    /// Payload data (up to EVENT_PAYLOAD_MAX bytes).
    pub payload: [u8; EVENT_PAYLOAD_MAX],
    /// Padding for alignment.
    _pad: [u8; 2],
}

impl SleWireEvent {
    /// Total wire size of this event (header + payload, 4-byte aligned).
    pub fn wire_size(&self) -> usize {
        // 2 (header) + payload_len, rounded up to 4
        let raw = 2 + self.payload_len as usize;
        (raw + 3) & !3
    }

    /// Serialize the entire struct as bytes for copy_to_iter.
    pub fn as_bytes(&self) -> &[u8] {
        let size = core::mem::size_of::<Self>();
        // SAFETY: SleWireEvent is repr(C) with only primitive fields.
        unsafe { core::slice::from_raw_parts(core::ptr::from_ref(self).cast::<u8>(), size) }
    }

    /// Build a wire event from a typed payload.
    fn from_payload<T: Sized>(event_type: SleEventType, payload: &T) -> Self {
        let payload_size = core::mem::size_of::<T>();
        let copy_len = payload_size.min(EVENT_PAYLOAD_MAX);
        // SAFETY: T is repr(C) with only primitive fields.
        let payload_bytes = unsafe {
            core::slice::from_raw_parts(core::ptr::from_ref(payload).cast::<u8>(), copy_len)
        };
        let mut wire = SleWireEvent {
            event_type: event_type as u8,
            payload_len: copy_len as u8,
            payload: [0u8; EVENT_PAYLOAD_MAX],
            _pad: [0u8; 2],
        };
        wire.payload[..copy_len].copy_from_slice(payload_bytes);
        wire
    }

    /// Build a connection state change wire event.
    pub fn conn_state(
        handle: u16,
        old_state: u8,
        new_state: u8,
        peer_addr: [u8; 6],
        reason: u8,
    ) -> Self {
        let payload = ConnStateEvent {
            handle,
            new_state,
            old_state,
            peer_addr,
            reason,
            _pad: 0,
        };
        Self::from_payload(SleEventType::ConnStateChanged, &payload)
    }

    /// Build an advertising report wire event.
    pub fn adv_report(
        addr: [u8; 6],
        rssi: i8,
        discovery_level: u8,
        name: &[u8],
    ) -> Self {
        let mut evt = AdvReportEvent {
            addr,
            rssi,
            discovery_level,
            name_len: name.len().min(31) as u8,
            name: [0u8; 31],
        };
        let copy_len = name.len().min(31);
        evt.name[..copy_len].copy_from_slice(&name[..copy_len]);
        Self::from_payload(SleEventType::AdvReport, &evt)
    }

    /// Build a data received indication wire event.
    pub fn data_received(handle: u16, rx_bytes: u16) -> Self {
        let payload = DataReceivedEvent { handle, rx_bytes };
        Self::from_payload(SleEventType::DataReceived, &payload)
    }

    /// Build a hardware error wire event.
    pub fn hardware_error(error_code: u8) -> Self {
        let payload = HardwareErrorEvent {
            error_code,
            _pad: [0u8; 3],
        };
        Self::from_payload(SleEventType::HardwareError, &payload)
    }

    /// Build a command complete wire event.
    pub fn command_complete(opcode: u16, status: u8, data: &[u8]) -> Self {
        let mut evt = CommandCompleteEvent {
            opcode,
            status,
            data_len: data.len().min(32) as u8,
            data: [0u8; 32],
        };
        let len = data.len().min(32);
        evt.data[..len].copy_from_slice(&data[..len]);
        Self::from_payload(SleEventType::CommandComplete, &evt)
    }

    /// Build a command status wire event.
    pub fn command_status(opcode: u16, status: u8) -> Self {
        let payload = CommandStatusEvent {
            opcode,
            status,
            _pad: 0,
        };
        Self::from_payload(SleEventType::CommandStatus, &payload)
    }

    /// Build a broadcast end wire event.
    pub fn broadcast_end(reason: u8) -> Self {
        let payload = BroadcastEndEvent {
            reason,
            _pad: [0u8; 3],
        };
        Self::from_payload(SleEventType::BroadcastEnd, &payload)
    }

    /// Build a PHY update wire event.
    pub fn phy_update(handle: u16, mcs_index: u8, bandwidth_mhz: u8) -> Self {
        let payload = PhyUpdateEvent {
            handle,
            mcs_index,
            bandwidth_mhz,
        };
        Self::from_payload(SleEventType::PhyUpdate, &payload)
    }

    /// Build a connection parameter update wire event.
    pub fn conn_param_update(handle: u16, interval: u16, latency: u16, timeout: u16) -> Self {
        let payload = ConnParamUpdateEvent {
            handle,
            interval,
            latency,
            timeout,
        };
        Self::from_payload(SleEventType::ConnParamUpdate, &payload)
    }

    /// Build a data length change wire event.
    pub fn data_len_change(handle: u16, max_tx: u16, max_rx: u16) -> Self {
        let payload = DataLenChangeEvent {
            handle,
            max_tx_octets: max_tx,
            max_rx_octets: max_rx,
            _pad: 0,
        };
        Self::from_payload(SleEventType::DataLenChange, &payload)
    }

    /// Build a data buffer overflow wire event.
    pub fn data_buf_overflow(link_type: u8) -> Self {
        let payload = DataBufOverflowEvent {
            link_type,
            _pad: [0u8; 3],
        };
        Self::from_payload(SleEventType::DataBufOverflow, &payload)
    }

    /// Build a peer connection parameter request wire event.
    pub fn peer_conn_param_req(
        handle: u16,
        interval_min: u16,
        interval_max: u16,
        latency: u16,
        timeout: u16,
    ) -> Self {
        let payload = PeerConnParamReqEvent {
            handle,
            interval_min,
            interval_max,
            latency,
            timeout,
            _pad: 0,
        };
        Self::from_payload(SleEventType::PeerConnParamReq, &payload)
    }
}

// ---------------------------------------------------------------------------
// Event queue
// ---------------------------------------------------------------------------

/// Maximum number of queued events before oldest are dropped.
const EVENT_QUEUE_MAX: usize = 64;

/// Event queue for delivering asynchronous notifications to userspace.
///
/// Uses a fixed-size ring buffer for O(1) enqueue and dequeue, avoiding
/// the O(n) element shift of the previous KVec-based implementation and
/// eliminating per-event heap allocation.
///
/// Events are enqueued by kernel-side subsystems and dequeued by
/// userspace via `read()` on the /dev/sparklink file descriptor.
pub struct EventQueue {
    /// Fixed-size ring buffer (pre-allocated, no per-event allocation).
    buf: [SleWireEvent; EVENT_QUEUE_MAX],
    /// Index of the oldest pending event (read position).
    head: usize,
    /// Number of events currently in the buffer.
    count: usize,
    /// Total events enqueued (lifetime counter).
    pub total_enqueued: u64,
    /// Total events dropped due to queue full.
    pub total_dropped: u64,
    /// Total events delivered to userspace.
    pub total_delivered: u64,
}

impl EventQueue {
    /// Create an empty event queue with pre-allocated ring buffer.
    pub fn new() -> Self {
        Self {
            // SAFETY: SleWireEvent is repr(C) with only primitive fields;
            // all-zero is a valid bit pattern.
            buf: unsafe { core::mem::zeroed() },
            head: 0,
            count: 0,
            total_enqueued: 0,
            total_dropped: 0,
            total_delivered: 0,
        }
    }

    /// Number of pending events.
    pub fn pending(&self) -> usize {
        self.count
    }

    /// Whether the queue has any pending events.
    pub fn has_events(&self) -> bool {
        self.count > 0
    }

    /// Enqueue a connection state change event.
    pub fn push_conn_state(
        &mut self,
        handle: u16,
        old_state: u8,
        new_state: u8,
        peer_addr: [u8; 6],
        reason: u8,
    ) {
        let payload = ConnStateEvent {
            handle,
            new_state,
            old_state,
            peer_addr,
            reason,
            _pad: 0,
        };
        self.enqueue(SleEventType::ConnStateChanged, &payload);
    }

    /// Enqueue an advertising report event.
    pub fn push_adv_report(
        &mut self,
        addr: [u8; 6],
        rssi: i8,
        discovery_level: u8,
        name: &[u8],
    ) {
        let mut evt = AdvReportEvent {
            addr,
            rssi,
            discovery_level,
            name_len: name.len().min(31) as u8,
            name: [0u8; 31],
        };
        let copy_len = name.len().min(31);
        evt.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.enqueue(SleEventType::AdvReport, &evt);
    }

    /// Enqueue a data received indication.
    pub fn push_data_received(&mut self, handle: u16, rx_bytes: u16) {
        let payload = DataReceivedEvent { handle, rx_bytes };
        self.enqueue(SleEventType::DataReceived, &payload);
    }

    /// Enqueue a security state change event.
    pub fn push_security_changed(&mut self, state: u8, method: u8, encrypted: u8) {
        let payload = SecurityEvent {
            state,
            method,
            encrypted,
            _pad: 0,
        };
        self.enqueue(SleEventType::SecurityChanged, &payload);
    }

    /// Enqueue a power state change event.
    pub fn push_power_changed(&mut self, state: u8, power_pct: u8) {
        let payload = PowerEvent {
            state,
            power_pct,
            _pad: [0u8; 2],
        };
        self.enqueue(SleEventType::PowerChanged, &payload);
    }

    /// Enqueue a hardware error event.
    pub fn push_hardware_error(&mut self, error_code: u8) {
        let payload = HardwareErrorEvent {
            error_code,
            _pad: [0u8; 3],
        };
        self.enqueue(SleEventType::HardwareError, &payload);
    }

    /// Dequeue the oldest event. Returns None if the queue is empty.
    ///
    /// O(1) — advances the ring buffer head pointer.
    pub fn dequeue(&mut self) -> Option<SleWireEvent> {
        if self.count == 0 {
            return None;
        }
        let evt = self.buf[self.head];
        self.head = (self.head + 1) % EVENT_QUEUE_MAX;
        self.count -= 1;
        self.total_delivered += 1;
        Some(evt)
    }

    /// Drain as many events as fit into the given buffer size.
    /// Returns the total bytes written.
    pub fn drain_to_buf(&mut self, buf: &mut [u8]) -> usize {
        let evt_size = core::mem::size_of::<SleWireEvent>();
        let mut offset = 0;
        while self.count > 0 {
            if offset + evt_size > buf.len() {
                break;
            }
            if let Some(evt) = self.dequeue() {
                let bytes = evt.as_bytes();
                buf[offset..offset + evt_size].copy_from_slice(bytes);
                offset += evt_size;
            }
        }
        offset
    }

    /// Insert a pre-built wire event directly into the queue.
    /// Used by the broadcast ring to copy events into per-fd queues.
    pub fn push_raw(&mut self, wire: SleWireEvent) {
        if self.count >= EVENT_QUEUE_MAX {
            self.head = (self.head + 1) % EVENT_QUEUE_MAX;
            self.count -= 1;
            self.total_dropped += 1;
        }
        let tail = (self.head + self.count) % EVENT_QUEUE_MAX;
        self.buf[tail] = wire;
        self.count += 1;
        self.total_enqueued += 1;
    }

    // --- Internal ---

    /// O(1) ring buffer insertion. Drops oldest event if full.
    fn enqueue<T: Sized>(&mut self, event_type: SleEventType, payload: &T) {
        let payload_size = core::mem::size_of::<T>();
        let copy_len = payload_size.min(EVENT_PAYLOAD_MAX);

        // SAFETY: T is repr(C) with only primitive fields.
        let payload_bytes = unsafe {
            core::slice::from_raw_parts(core::ptr::from_ref(payload).cast::<u8>(), copy_len)
        };

        let mut wire = SleWireEvent {
            event_type: event_type as u8,
            payload_len: copy_len as u8,
            payload: [0u8; EVENT_PAYLOAD_MAX],
            _pad: [0u8; 2],
        };
        wire.payload[..copy_len].copy_from_slice(payload_bytes);

        // Drop oldest if queue is full
        if self.count >= EVENT_QUEUE_MAX {
            self.head = (self.head + 1) % EVENT_QUEUE_MAX;
            self.count -= 1;
            self.total_dropped += 1;
            pr_warn!("sparklink: event queue full, dropped oldest event\n");
        }

        let tail = (self.head + self.count) % EVENT_QUEUE_MAX;
        self.buf[tail] = wire;
        self.count += 1;
        self.total_enqueued += 1;
    }
}

// ---------------------------------------------------------------------------
// Global broadcast ring: multi-listener event delivery
// ---------------------------------------------------------------------------

/// Size of the global broadcast ring (power of 2 for fast modulo).
const BROADCAST_RING_SIZE: usize = 128;

/// Monotonically increasing sequence counter for global events.
///
/// Each event written to the broadcast ring gets a unique sequence number.
/// Per-fd readers track their own cursor (last_seq) and catch up on poll/read.
static BROADCAST_SEQ: AtomicU64 = AtomicU64::new(0);

/// Entry in the broadcast ring: event + sequence number.
#[derive(Copy, Clone)]
pub struct BroadcastEntry {
    pub seq: u64,
    pub event: SleWireEvent,
}

/// Global broadcast ring buffer for multi-listener event delivery.
///
/// Design rationale: instead of maintaining a global list of per-fd event
/// queue references (which would require Arc<PollCondVar> and complex
/// lifetime management), we use a `/dev/kmsg`-style model:
///
/// - One shared ring buffer holds the most recent BROADCAST_RING_SIZE events.
/// - Each event gets a monotonically increasing sequence number.
/// - Each fd tracks its own `last_seq` cursor.
/// - On poll/read, the fd copies events with seq > last_seq into its local
///   EventQueue, then reads from the local queue as before.
///
/// This decouples event production from fd lifetime and naturally supports
/// any number of concurrent readers without a global fd registry.
pub struct BroadcastRing {
    buf: [BroadcastEntry; BROADCAST_RING_SIZE],
    /// Write position (next slot to write).
    write_pos: usize,
    /// Number of valid entries (min of total written and BROADCAST_RING_SIZE).
    count: usize,
}

impl BroadcastRing {
    /// Create an empty broadcast ring.
    pub fn new() -> Self {
        Self {
            // SAFETY: BroadcastEntry is Copy with repr(C) primitives.
            buf: unsafe { core::mem::zeroed() },
            write_pos: 0,
            count: 0,
        }
    }

    /// Publish an event to the broadcast ring. Returns the assigned sequence.
    pub fn publish(&mut self, event: SleWireEvent) -> u64 {
        let seq = BROADCAST_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
        self.buf[self.write_pos] = BroadcastEntry { seq, event };
        self.write_pos = (self.write_pos + 1) % BROADCAST_RING_SIZE;
        if self.count < BROADCAST_RING_SIZE {
            self.count += 1;
        }
        seq
    }

    /// Get the current (latest) sequence number.
    pub fn current_seq() -> u64 {
        BROADCAST_SEQ.load(Ordering::Relaxed)
    }

    /// Drain events newer than `after_seq` into the given per-fd EventQueue.
    /// Returns the number of events copied and the new cursor position.
    pub fn drain_since(&self, after_seq: u64, dst: &mut EventQueue) -> (usize, u64) {
        if self.count == 0 {
            return (0, after_seq);
        }

        let mut copied = 0usize;
        let mut new_seq = after_seq;

        // Scan the ring for entries with seq > after_seq.
        // Since the ring is small (128) and we only scan once per poll,
        // a linear scan is acceptable.
        let start = if self.count < BROADCAST_RING_SIZE {
            0
        } else {
            self.write_pos // oldest entry
        };

        for i in 0..self.count {
            let idx = (start + i) % BROADCAST_RING_SIZE;
            let entry = &self.buf[idx];
            if entry.seq > after_seq {
                // Copy event into per-fd queue.
                dst.push_raw(entry.event);
                copied += 1;
                if entry.seq > new_seq {
                    new_seq = entry.seq;
                }
            }
        }

        (copied, new_seq)
    }
}
