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

use core::sync::atomic::{AtomicU64, Ordering};
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

    // --- HIGH priority (TXS-10003-2025 §9.1.7, §9.1.8, §9.1.11) ---
    /// TX power change report (§9.1.7).
    PowerChangeReport = 0x0F,
    /// Number of successfully transmitted packets (§9.1.8).
    NumCompletedPackets = 0x10,
    /// Link encryption parameter request (§9.1.11).
    EncryptionParamReq = 0x11,

    // --- MEDIUM — Peer Info (§9.1.13, §9.1.15–§9.1.16, §9.1.20–§9.1.21) ---
    /// Controller control signaling data (§9.1.13).
    ControllerSignalData = 0x12,
    /// Read peer features complete (§9.1.15).
    ReadPeerFeatures = 0x13,
    /// Read peer version info complete (§9.1.16).
    ReadPeerVersion = 0x14,
    /// Read peer TX power complete (§9.1.20).
    ReadPeerPower = 0x15,
    /// Inquiry (scan) request report (§9.1.21).
    InquiryRequestReport = 0x16,

    // --- MEDIUM — Pairing (§9.1.22–§9.1.32) ---
    /// Pairing request from remote peer (§9.1.22).
    PairRequest = 0x17,
    /// Pairing information exchange request (§9.1.23).
    PairInfoExchangeReq = 0x18,
    /// Pairing information report (§9.1.24).
    PairInfoReport = 0x19,
    /// Pairing option report (§9.1.25).
    PairOptionReport = 0x1A,
    /// Peer public key report (§9.1.26).
    PeerPublicKeyReport = 0x1B,
    /// Pairing extended data report (§9.1.27).
    PairExtDataReport = 0x1C,
    /// Keypress notification (§9.1.28).
    KeypressNotification = 0x1D,
    /// Pairing random number report (§9.1.29).
    PairRandomReport = 0x1E,
    /// Pairing confirm code report (§9.1.30).
    PairConfirmReport = 0x1F,
    /// DH key check report (§9.1.31).
    DHKeyCheckReport = 0x20,
    /// Pairing failure report (§9.1.32).
    PairFailureReport = 0x21,

    // --- LOW — Narrowband Measurement (§9.1.33–§9.1.39) ---
    /// Narrowband frequency-hopping measurement info (§9.1.33).
    NarrowbandMeasInfo = 0x22,
    /// Narrowband measurement state change (§9.1.34).
    NarrowbandMeasStateChange = 0x23,
    /// Narrowband measurement parameter report (§9.1.35).
    NarrowbandMeasParamReport = 0x24,
    /// Local narrowband measurement capabilities (§9.1.36).
    LocalNarrowbandMeasCap = 0x25,
    /// Peer narrowband measurement capabilities (§9.1.37).
    PeerNarrowbandMeasCap = 0x26,
    /// Measurement state change (§9.1.38).
    MeasStateChange = 0x27,
    /// Measurement quantity report (§9.1.39).
    MeasQuantityReport = 0x28,

    // --- LOW — SLB (§9.1.40–§9.1.45) ---
    /// SLB advertising report (§9.1.40).
    SlbAdvReport = 0x29,
    /// SLB connection established (§9.1.41).
    SlbConnComplete = 0x2A,
    /// SLB unicast logical channel established (§9.1.42).
    SlbUcastChannelComplete = 0x2B,
    /// SLB unicast logical channel updated (§9.1.43).
    SlbUcastChannelUpdate = 0x2C,
    /// SLB logical channel deleted (§9.1.44).
    SlbChannelDelete = 0x2D,
    /// SLB logical channel completed packets count (§9.1.45).
    SlbNumCompletedPackets = 0x2E,

    // --- LOW — Sync Link (§9.1.46–§9.1.51) ---
    /// Time synchronization status update (§9.1.46).
    TimeSyncStatusUpdate = 0x2F,
    /// Time synchronization request from controller (§9.1.47).
    TimeSyncRequest = 0x30,
    /// Synchronous unicast link setup request (§9.1.48).
    SyncUcastSetupRequest = 0x31,
    /// Synchronous unicast link setup complete (§9.1.49).
    SyncUcastSetupComplete = 0x32,
    /// Synchronous multicast link setup request (§9.1.50).
    SyncMcastSetupRequest = 0x33,
    /// Synchronous multicast link setup complete (§9.1.51).
    SyncMcastSetupComplete = 0x34,
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
// New event payload structs (TXS-10003-2025 §9.1.7–§9.1.51)
// ---------------------------------------------------------------------------

/// TX power change report event (§9.1.7).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PowerChangeReportEvent {
    pub handle: u16,
    pub reason: u8,
    pub frame_type: u8,
    pub bandwidth: u8,
    pub pilot_density: u8,
    pub tx_power: i8,
    pub power_level: u8,
    pub offset: i8,
    pub _pad: u8,
}

/// Number of completed packets event (§9.1.8).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct NumCompletedPacketsEvent {
    pub handle: u16,
    pub num_completed: u8,
    pub _pad: u8,
}

/// Encryption parameter request event (§9.1.11).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct EncryptionParamReqEvent {
    pub handle: u16,
    pub _pad: [u8; 2],
}

/// Controller signaling data event (§9.1.13).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ControllerSignalDataEvent {
    pub handle: u16,
    pub signal_id: u16,
    pub data_len: u8,
    pub _pad: u8,
    pub data: [u8; 32],
}

/// Read peer features complete event (§9.1.15).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ReadPeerFeaturesEvent {
    pub handle: u16,
    pub status: u8,
    pub _pad: u8,
    pub features: [u8; 10],
}

/// Read peer version complete event (§9.1.16).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ReadPeerVersionEvent {
    pub handle: u16,
    pub manufacturer: u16,
    pub subversion: u16,
    pub status: u8,
    pub version: u8,
}

/// Read peer TX power event (§9.1.20).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ReadPeerPowerEvent {
    pub handle: u16,
    pub status: u8,
    pub frame_type: u8,
    pub bandwidth: u8,
    pub pilot_density: u8,
    pub tx_power: i8,
    pub power_level: u8,
}

/// Inquiry request report event (§9.1.21).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct InquiryRequestReportEvent {
    pub addr: [u8; 6],
    pub addr_type: u8,
    pub adv_handle: u8,
    pub rssi: i8,
    pub data_len: u8,
    pub _pad: [u8; 2],
}

/// Pairing request event (§9.1.22).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PairRequestEvent {
    pub handle: u16,
    pub auth_req: u8,
    pub _pad: u8,
}

/// Pairing info exchange / report event (§9.1.23, §9.1.24).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PairInfoEvent {
    pub handle: u16,
    pub io_cap: u8,
    pub oob_flag: u8,
    pub auth_req: u8,
    pub max_key_len: u8,
    pub sec_dist: u8,
    pub psk_ind: u8,
    pub crypto_cap: [u8; 4],
}

/// Pairing option report event (§9.1.25).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PairOptionReportEvent {
    pub handle: u16,
    pub key_len: u8,
    pub auth_method: u8,
    pub crypto_alg: [u8; 4],
    pub public_key: [u8; 32],
}

/// Peer public key report event (§9.1.26).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PeerPublicKeyReportEvent {
    pub handle: u16,
    pub _pad: [u8; 2],
    pub public_key: [u8; 32],
}

/// Pairing extended data report event (§9.1.27).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PairExtDataReportEvent {
    pub handle: u16,
    pub _pad: [u8; 2],
    pub ext_key_data: [u8; 36],
}

/// Keypress notification event (§9.1.28).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct KeypressNotificationEvent {
    pub handle: u16,
    pub _pad: [u8; 2],
    pub action: [u8; 4],
}

/// Pairing random number report event (§9.1.29).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PairRandomReportEvent {
    pub handle: u16,
    pub _pad: [u8; 2],
    pub random: [u8; 16],
}

/// Pairing confirm code report event (§9.1.30).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PairConfirmReportEvent {
    pub handle: u16,
    pub _pad: [u8; 2],
    pub confirm: [u8; 16],
}

/// DH key check report event (§9.1.31).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DHKeyCheckReportEvent {
    pub handle: u16,
    pub _pad: [u8; 2],
    pub dhkey_check: [u8; 16],
}

/// Pairing failure report event (§9.1.32).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PairFailureReportEvent {
    pub handle: u16,
    pub reason: u8,
    pub _pad: u8,
}

/// Narrowband measurement info event (§9.1.33).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct NarrowbandMeasInfoEvent {
    pub handle: u16,
    pub meas_type: u16,
    pub status: u8,
    pub config_index: u8,
    pub _pad: [u8; 2],
}

/// Narrowband measurement state change event (§9.1.34).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct NarrowbandMeasStateChangeEvent {
    pub status: u8,
    pub config_index: u8,
    pub meas_state: u8,
    pub _pad: u8,
}

/// Narrowband measurement parameter report event (§9.1.35).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct NarrowbandMeasParamReportEvent {
    pub handle: u16,
    pub status: u8,
    pub config_index: u8,
}

/// Local narrowband measurement capabilities event (§9.1.36).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LocalNarrowbandMeasCapEvent {
    pub status: u8,
    pub antenna_count: u8,
    pub signal_cap: [u8; 4],
    pub report_cap: [u8; 4],
}

/// Peer narrowband measurement capabilities event (§9.1.37).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PeerNarrowbandMeasCapEvent {
    pub handle: u16,
    pub status: u8,
    pub antenna_count: u8,
    pub signal_cap: [u8; 4],
    pub report_cap: [u8; 4],
}

/// Measurement state change event (§9.1.38).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MeasStateChangeEvent {
    pub source: u16,
    pub status: u8,
    pub instance_handle: u8,
    pub instance_state: u8,
    pub _pad: [u8; 3],
}

/// Measurement quantity report event (§9.1.39).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MeasQuantityReportEvent {
    pub source: u16,
    pub meas_source: u16,
    pub seq: u16,
    pub instance_handle: u8,
    pub meas_count: u8,
}

/// SLB advertising report event (§9.1.40).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlbAdvReportEvent {
    pub mac_addr: [u8; 6],
    pub channel: u16,
    pub bandwidth: u8,
    pub rssi: i8,
    pub data_len: u8,
    pub _pad: u8,
}

/// SLB connection complete event (§9.1.41).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlbConnCompleteEvent {
    pub handle: u16,
    pub status: u8,
    pub _pad: u8,
    pub peer_addr: [u8; 6],
    pub _pad2: [u8; 2],
}

/// SLB unicast channel complete event (§9.1.42).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlbUcastChannelCompleteEvent {
    pub channel_handle: u16,
    pub conn_handle: u16,
    pub max_pkt_len: u16,
    pub max_pkt_count: u16,
    pub status: u8,
    pub _pad: u8,
}

/// SLB unicast channel update event (§9.1.43).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlbUcastChannelUpdateEvent {
    pub channel_handle: u16,
    pub max_pkt_len: u16,
    pub max_pkt_count: u16,
    pub status: u8,
    pub _pad: u8,
}

/// SLB channel delete event (§9.1.44).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlbChannelDeleteEvent {
    pub channel_handle: u16,
    pub status: u8,
    pub _pad: u8,
}

/// SLB completed packets event (§9.1.45).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SlbNumCompletedPacketsEvent {
    pub channel_handle: u16,
    pub num_completed: u8,
    pub _pad: u8,
}

/// Time sync status update event (§9.1.46).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TimeSyncStatusUpdateEvent {
    pub accuracy: u32,
    pub sync_status: u8,
    pub clock_source: u8,
    pub _pad: [u8; 2],
}

/// Time sync request event (§9.1.47).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TimeSyncRequestEvent {
    pub time_seq: u32,
    pub send_time: [u8; 8],
}

/// Sync unicast setup request event (§9.1.48).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SyncUcastSetupRequestEvent {
    pub async_handle: u16,
    pub sync_handle: u16,
    pub event_group_set_id: u8,
    pub event_group_id: u8,
    pub _pad: [u8; 2],
}

/// Sync unicast setup complete event (§9.1.49).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SyncUcastSetupCompleteEvent {
    pub async_handle: u16,
    pub sync_handle: u16,
    pub status: u8,
    pub _pad: [u8; 3],
}

/// Sync multicast setup request event (§9.1.50).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SyncMcastSetupRequestEvent {
    pub async_handle: u16,
    pub sync_handle: u16,
}

/// Sync multicast setup complete event (§9.1.51).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SyncMcastSetupCompleteEvent {
    pub async_handle: u16,
    pub sync_handle: u16,
    pub status: u8,
    pub _pad: [u8; 3],
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

    /// Build a wire event from a typed payload (public, for cross-module use).
    pub fn from_payload_pub<T: Sized>(event_type: SleEventType, payload: &T) -> Self {
        Self::from_payload(event_type, payload)
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
    pub fn adv_report(addr: [u8; 6], rssi: i8, discovery_level: u8, name: &[u8]) -> Self {
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

    /// Build a TX power change report wire event (§9.1.7).
    pub fn power_change_report(
        handle: u16,
        reason: u8,
        frame_type: u8,
        bandwidth: u8,
        pilot_density: u8,
        tx_power: i8,
        power_level: u8,
        offset: i8,
    ) -> Self {
        let payload = PowerChangeReportEvent {
            handle,
            reason,
            frame_type,
            bandwidth,
            pilot_density,
            tx_power,
            power_level,
            offset,
            _pad: 0,
        };
        Self::from_payload(SleEventType::PowerChangeReport, &payload)
    }

    /// Build a number-of-completed-packets wire event (§9.1.8).
    pub fn num_completed_packets(handle: u16, num_completed: u8) -> Self {
        let payload = NumCompletedPacketsEvent {
            handle,
            num_completed,
            _pad: 0,
        };
        Self::from_payload(SleEventType::NumCompletedPackets, &payload)
    }

    /// Build an encryption parameter request wire event (§9.1.11).
    pub fn encryption_param_req(handle: u16) -> Self {
        let payload = EncryptionParamReqEvent {
            handle,
            _pad: [0u8; 2],
        };
        Self::from_payload(SleEventType::EncryptionParamReq, &payload)
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
    pub fn push_adv_report(&mut self, addr: [u8; 6], rssi: i8, discovery_level: u8, name: &[u8]) {
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

    /// Enqueue a number-of-completed-packets event (§9.1.8).
    pub fn push_num_completed_packets(&mut self, handle: u16, num_completed: u8) {
        let payload = NumCompletedPacketsEvent {
            handle,
            num_completed,
            _pad: 0,
        };
        self.enqueue(SleEventType::NumCompletedPackets, &payload);
    }

    /// Enqueue a TX power change report event (§9.1.7).
    pub fn push_power_change_report(
        &mut self,
        handle: u16,
        reason: u8,
        frame_type: u8,
        bandwidth: u8,
        pilot_density: u8,
        tx_power: i8,
        power_level: u8,
        offset: i8,
    ) {
        let payload = PowerChangeReportEvent {
            handle,
            reason,
            frame_type,
            bandwidth,
            pilot_density,
            tx_power,
            power_level,
            offset,
            _pad: 0,
        };
        self.enqueue(SleEventType::PowerChangeReport, &payload);
    }

    /// Enqueue an encryption parameter request event (§9.1.11).
    pub fn push_encryption_param_req(&mut self, handle: u16) {
        let payload = EncryptionParamReqEvent {
            handle,
            _pad: [0u8; 2],
        };
        self.enqueue(SleEventType::EncryptionParamReq, &payload);
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
