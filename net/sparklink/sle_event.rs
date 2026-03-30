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
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size) }
    }
}

// ---------------------------------------------------------------------------
// Event queue
// ---------------------------------------------------------------------------

/// Maximum number of queued events before oldest are dropped.
const EVENT_QUEUE_MAX: usize = 64;

/// Event queue for delivering asynchronous notifications to userspace.
///
/// Events are enqueued by kernel-side subsystems and dequeued by
/// userspace via `read()` on the /dev/sparklink file descriptor.
pub struct EventQueue {
    /// Circular buffer of serialized events.
    events: KVec<SleWireEvent>,
    /// Total events enqueued (lifetime counter).
    pub total_enqueued: u64,
    /// Total events dropped due to queue full.
    pub total_dropped: u64,
    /// Total events delivered to userspace.
    pub total_delivered: u64,
}

impl EventQueue {
    /// Create an empty event queue.
    pub fn new() -> Self {
        Self {
            events: KVec::new(),
            total_enqueued: 0,
            total_dropped: 0,
            total_delivered: 0,
        }
    }

    /// Number of pending events.
    pub fn pending(&self) -> usize {
        self.events.len()
    }

    /// Whether the queue has any pending events.
    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
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
    pub fn dequeue(&mut self) -> Option<SleWireEvent> {
        if self.events.is_empty() {
            return None;
        }
        match self.events.remove(0) {
            Ok(evt) => {
                self.total_delivered += 1;
                Some(evt)
            }
            Err(_) => None,
        }
    }

    /// Drain as many events as fit into the given buffer size.
    /// Returns the total bytes written.
    pub fn drain_to_buf(&mut self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        while !self.events.is_empty() {
            let evt_size = core::mem::size_of::<SleWireEvent>();
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

    // --- Internal ---

    fn enqueue<T: Sized>(&mut self, event_type: SleEventType, payload: &T) {
        let payload_size = core::mem::size_of::<T>();
        let copy_len = payload_size.min(EVENT_PAYLOAD_MAX);

        // SAFETY: T is repr(C) with only primitive fields.
        let payload_bytes = unsafe {
            core::slice::from_raw_parts(payload as *const T as *const u8, copy_len)
        };

        let mut wire = SleWireEvent {
            event_type: event_type as u8,
            payload_len: copy_len as u8,
            payload: [0u8; EVENT_PAYLOAD_MAX],
            _pad: [0u8; 2],
        };
        wire.payload[..copy_len].copy_from_slice(payload_bytes);

        // Drop oldest if queue is full
        if self.events.len() >= EVENT_QUEUE_MAX {
            let _ = self.events.remove(0);
            self.total_dropped += 1;
            pr_warn!("sparklink: event queue full, dropped oldest event\n");
        }

        if self.events.push(wire, GFP_KERNEL).is_ok() {
            self.total_enqueued += 1;
        }
    }
}
