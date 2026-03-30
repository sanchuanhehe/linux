// SPDX-License-Identifier: GPL-2.0

//! SLE connection management state machine.
//!
//! Implements connection establishment, parameter negotiation, data
//! exchange, and disconnection for SLE asynchronous connections as
//! defined in T/XS 10002-2025.
//!
//! The connection lifecycle follows: Idle → Connecting (access request
//! sent) → Connected (access response accepted) → Idle (disconnected).
//! During the Connected state, data PDUs can be exchanged with 1-bit
//! ARQ sequence numbering for the async link.

#![allow(dead_code, unreachable_pub)]

use kernel::alloc::KVec;
use kernel::prelude::*;

// ---------------------------------------------------------------------------
// GT role definitions (T/XS 10002-2025 table 32, GT角色标志)
// ---------------------------------------------------------------------------

/// GT node role in an SLE connection.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum GtRole {
    /// T node (terminal/slave).
    #[default]
    TNode = 0,
    /// G node (gateway/master).
    GNode = 1,
}

/// GT role preference for connection requests.
#[derive(Copy, Clone, Debug)]
pub struct GtRolePreference {
    /// Preferred role.
    pub preferred: GtRole,
    /// Whether the role is negotiable.
    pub negotiable: bool,
}

impl Default for GtRolePreference {
    fn default() -> Self {
        Self {
            preferred: GtRole::TNode,
            negotiable: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Access request capability (T/XS 10002-2025 table 32)
// ---------------------------------------------------------------------------

/// Device capabilities advertised in an access request.
#[derive(Copy, Clone, Debug)]
pub struct AccessCapability {
    /// GT role preference.
    pub gt_role: GtRolePreference,
    /// Supported frame types (bitmask, bits 0-3 for type 1-4).
    pub frame_types: u8,
    /// Supported bandwidths (bit0=1MHz, bit1=2MHz, bit2=4MHz).
    pub bandwidth: u8,
    /// Supported MCS indices (bitmask, bits 0-12).
    pub mcs_support: u16,
    /// Supported pilot densities (bit0=4:1, bit1=8:1, bit2=16:1, bit3=none).
    pub pilot: u8,
    /// Supported scheduling slots (bit0=25us, ..., bit4=125us).
    pub schedule_slots: u8,
    /// TX/RX switch delay index (0-15).
    pub switch_delay: u8,
    /// Supported CRC types (bit0=CRC24, bit1=CRC32).
    pub crc_type: u8,
}

impl Default for AccessCapability {
    fn default() -> Self {
        Self {
            gt_role: GtRolePreference::default(),
            frame_types: 0x01,    // frame type 1 only
            bandwidth: 0x01,      // 1 MHz only
            mcs_support: 0x0010,  // MCS 4 (QPSK 1/2)
            pilot: 0x02,          // 8:1 pilot
            schedule_slots: 0x10, // 125 us (bit 4)
            switch_delay: 2,
            crc_type: 0x01,       // CRC24
        }
    }
}

// ---------------------------------------------------------------------------
// Access response type (T/XS 10002-2025 table 34)
// ---------------------------------------------------------------------------

/// Access response result code.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AccessResponseType {
    /// Connection accepted.
    Accepted = 0,
    /// GT role negotiation failed.
    RoleNegotiationFailed = 1,
    /// Peer resource limited.
    ResourceLimited = 2,
    /// User rejected.
    UserRejected = 3,
}

impl AccessResponseType {
    /// Decode from raw byte. Returns `None` for reserved values.
    pub fn from_raw(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Accepted),
            1 => Some(Self::RoleNegotiationFailed),
            2 => Some(Self::ResourceLimited),
            3 => Some(Self::UserRejected),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Negotiated connection parameters
// ---------------------------------------------------------------------------

/// Parameters agreed upon after access request/response exchange.
#[derive(Copy, Clone, Debug)]
pub struct NegotiatedParams {
    /// Bandwidth in MHz (1, 2, or 4).
    pub bandwidth_mhz: u8,
    /// MCS index (0-12).
    pub mcs_index: u8,
    /// Pilot density (0=4:1, 1=8:1, 2=16:1, 3=none).
    pub pilot_density: u8,
    /// Scheduling slot duration in microseconds (25, 50, 75, 100, 125).
    pub schedule_slot_us: u8,
    /// CRC type (0=CRC24, 1=CRC32).
    pub crc_type: u8,
    /// Event group period in scheduling slots.
    pub event_group_period: u16,
    /// Event period in scheduling slots.
    pub event_period: u16,
    /// Intra-event interval in microseconds.
    pub intra_event_interval: u16,
    /// Supervision timeout in 10 ms units.
    pub supervision_timeout: u16,
    /// Latency period in event group period multiples.
    pub latency_period: u16,
    /// Maximum PDU size in bytes for the forward link.
    pub max_pdu_size: u16,
}

impl Default for NegotiatedParams {
    fn default() -> Self {
        Self {
            bandwidth_mhz: 1,
            mcs_index: 4,           // QPSK 1/2
            pilot_density: 1,       // 8:1
            schedule_slot_us: 125,
            crc_type: 0,            // CRC24
            event_group_period: 40, // 40 * 125 us = 5 ms
            event_period: 2,
            intra_event_interval: 150,
            supervision_timeout: 100, // 100 * 10 ms = 1 s
            latency_period: 0,
            max_pdu_size: 255,
        }
    }
}

// ---------------------------------------------------------------------------
// Async data link control header (T/XS 10002-2025 table 3, A2)
// ---------------------------------------------------------------------------

/// Control header for the async data link (Frame Type 1, 32-bit).
///
/// Used during the Connected state for data exchange between G and T nodes.
#[derive(Copy, Clone, Debug, Default)]
pub struct DataCtrlHeader {
    /// MCS index for the data payload (4 bits).
    pub mcs_index: u8,
    /// Packet type (2 bits): 0=no time offset, 1=with time offset,
    /// 2=control+data, 3=control plane only.
    pub packet_type: u8,
    /// Empty packet indicator: true if no data payload.
    pub empty: bool,
    /// Transmit sequence number (1 bit for async links).
    pub tx_seq: u8,
    /// Receive sequence number (1 bit for async links).
    pub rx_seq: u8,
    /// Flow control: true if sender has more data pending.
    pub flow_ctrl: bool,
    /// Data length in bytes (11 bits, max 2047).
    pub data_length: u16,
}

// ---------------------------------------------------------------------------
// Connection state machine
// ---------------------------------------------------------------------------

/// Connection state.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum ConnState {
    /// No active connection.
    #[default]
    Idle = 0,
    /// Access request sent, waiting for response.
    Connecting = 1,
    /// Connection established, data exchange active.
    Connected = 2,
    /// Disconnection in progress.
    Disconnecting = 3,
}

/// Async data link sequence number tracker.
///
/// The async link uses 1-bit sequence numbers (0 or 1) for simple
/// stop-and-wait ARQ. The sync link variant uses 5-bit (0-31) for
/// a larger transmit window, but we default to async mode.
#[derive(Copy, Clone, Debug, Default)]
pub struct SeqTracker {
    /// Next transmit sequence number.
    pub tx_seq: u8,
    /// Expected receive sequence number.
    pub rx_seq: u8,
    /// Sequence number modulus (2 for async, 32 for sync).
    pub modulus: u8,
}

impl SeqTracker {
    /// Create a new tracker for async links (1-bit sequence numbers).
    pub fn new_async() -> Self {
        Self {
            tx_seq: 0,
            rx_seq: 0,
            modulus: 2,
        }
    }

    /// Advance the TX sequence number (new data sent).
    pub fn advance_tx(&mut self) {
        self.tx_seq = (self.tx_seq + 1) % self.modulus;
    }

    /// Advance the RX sequence number (data received and accepted).
    pub fn advance_rx(&mut self) {
        self.rx_seq = (self.rx_seq + 1) % self.modulus;
    }

    /// Check if a received sequence number matches the expected.
    pub fn check_rx(&self, seq: u8) -> bool {
        (seq % self.modulus) == self.rx_seq
    }
}

/// Maximum data payload per connection ioctl call.
pub const CONN_DATA_MAX: usize = 255;

// ---------------------------------------------------------------------------
// Connection manager
// ---------------------------------------------------------------------------

/// Connection manager for a single SLE connection.
///
/// Each open fd on /dev/sparklink gets its own ConnInner instance.
/// It manages the full connection lifecycle: Idle → Connecting →
/// Connected → Idle, along with data transmit/receive queues.
pub struct ConnInner {
    /// Current connection state.
    pub state: ConnState,
    /// Peer SLE address.
    pub peer_addr: [u8; 6],
    /// Local SLE address.
    pub local_addr: [u8; 6],
    /// Local GT role in this connection.
    pub local_role: GtRole,
    /// Local device capabilities.
    pub local_cap: AccessCapability,
    /// Negotiated connection parameters.
    pub params: NegotiatedParams,
    /// Sequence number tracker.
    pub seq: SeqTracker,
    /// Transmit data queue (userspace → peer).
    pub tx_queue: KVec<KVec<u8>>,
    /// Receive data queue (peer → userspace).
    pub rx_queue: KVec<KVec<u8>>,
    /// Maximum queue depth.
    pub queue_max: usize,
    /// Total bytes sent.
    pub tx_bytes: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
}

impl ConnInner {
    /// Create a new idle connection manager.
    pub fn new(local_addr: [u8; 6]) -> Self {
        Self {
            state: ConnState::Idle,
            peer_addr: [0u8; 6],
            local_addr,
            local_role: GtRole::TNode,
            local_cap: AccessCapability::default(),
            params: NegotiatedParams::default(),
            seq: SeqTracker::new_async(),
            tx_queue: KVec::new(),
            rx_queue: KVec::new(),
            queue_max: 64,
            tx_bytes: 0,
            rx_bytes: 0,
        }
    }

    /// Initiate a connection to the given peer address.
    ///
    /// Transitions Idle → Connecting. In real hardware this would
    /// trigger transmission of an Access Request PDU on the advertising
    /// channel.
    ///
    /// # Errors
    ///
    /// Returns `EBUSY` if not in Idle state.
    pub fn connect(&mut self, peer_addr: [u8; 6], role: GtRole) -> Result {
        if self.state != ConnState::Idle {
            pr_err!("sparklink: cannot connect in state {:?}\n", self.state);
            return Err(EBUSY);
        }
        self.peer_addr = peer_addr;
        self.local_role = role;
        self.seq = SeqTracker::new_async();
        self.tx_queue = KVec::new();
        self.rx_queue = KVec::new();
        self.tx_bytes = 0;
        self.rx_bytes = 0;
        self.state = ConnState::Connecting;
        pr_info!(
            "sparklink: connecting to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} as {:?}\n",
            peer_addr[0],
            peer_addr[1],
            peer_addr[2],
            peer_addr[3],
            peer_addr[4],
            peer_addr[5],
            self.local_role
        );
        Ok(())
    }

    /// Process a received access response.
    ///
    /// If accepted, transitions Connecting → Connected with the negotiated
    /// parameters. If rejected, transitions back to Idle.
    pub fn process_access_response(
        &mut self,
        response_type: AccessResponseType,
        params: NegotiatedParams,
    ) -> Result {
        if self.state != ConnState::Connecting {
            return Err(EBUSY);
        }
        match response_type {
            AccessResponseType::Accepted => {
                self.params = params;
                self.state = ConnState::Connected;
                pr_info!(
                    "sparklink: connected (bw={}MHz mcs={} timeout={}0ms)\n",
                    params.bandwidth_mhz,
                    params.mcs_index,
                    params.supervision_timeout
                );
                Ok(())
            }
            other => {
                self.state = ConnState::Idle;
                pr_warn!("sparklink: connection rejected: {:?}\n", other);
                // EACCES used in place of ECONNREFUSED (not declared in kernel Rust)
                Err(EACCES)
            }
        }
    }

    /// Disconnect from the peer.
    ///
    /// Valid from Connected or Connecting states. Resets all connection
    /// state and returns to Idle.
    ///
    /// # Errors
    ///
    /// Returns `EPIPE` if not currently connected or connecting.
    pub fn disconnect(&mut self) -> Result {
        match self.state {
            ConnState::Connected | ConnState::Connecting => {
                let old_state = self.state;
                self.state = ConnState::Idle;
                pr_info!(
                    "sparklink: disconnected from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (was {:?})\n",
                    self.peer_addr[0],
                    self.peer_addr[1],
                    self.peer_addr[2],
                    self.peer_addr[3],
                    self.peer_addr[4],
                    self.peer_addr[5],
                    old_state
                );
                Ok(())
            }
            // EPIPE used in place of ENOTCONN (not declared in kernel Rust)
            _ => Err(EPIPE),
        }
    }

    /// Queue data for transmission. Returns the number of bytes queued.
    ///
    /// Data is placed in the TX queue and will be transmitted as async
    /// data PDUs by the radio driver. Sequence numbers are advanced
    /// per the 1-bit ARQ scheme.
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        if self.state != ConnState::Connected {
            return Err(EPIPE);
        }
        if data.is_empty() || data.len() > CONN_DATA_MAX {
            return Err(EINVAL);
        }
        if self.tx_queue.len() >= self.queue_max {
            return Err(EAGAIN);
        }
        let mut buf = KVec::new();
        buf.extend_from_slice(data, GFP_KERNEL)?;
        self.tx_queue.push(buf, GFP_KERNEL)?;
        self.seq.advance_tx();
        self.tx_bytes += data.len() as u64;
        Ok(data.len())
    }

    /// Process received data from the peer (or loopback injection).
    ///
    /// The data is validated against the expected sequence number and
    /// placed in the RX queue. Duplicate or out-of-order packets are
    /// silently dropped (simplified ARQ).
    pub fn receive_data(&mut self, data: &[u8], seq: u8) -> Result {
        if self.state != ConnState::Connected {
            return Err(EPIPE);
        }
        if !self.seq.check_rx(seq) {
            // Duplicate or out-of-order — drop silently
            return Ok(());
        }
        if self.rx_queue.len() >= self.queue_max {
            // Evict oldest entry
            let _ = self.rx_queue.remove(0);
        }
        let mut buf = KVec::new();
        buf.extend_from_slice(data, GFP_KERNEL)?;
        self.rx_queue.push(buf, GFP_KERNEL)?;
        self.seq.advance_rx();
        self.rx_bytes += data.len() as u64;
        Ok(())
    }

    /// Read received data from the RX queue.
    ///
    /// Returns the oldest buffered data or `EAGAIN` if the queue is empty.
    pub fn recv(&mut self) -> Result<KVec<u8>> {
        if self.state != ConnState::Connected {
            return Err(EPIPE);
        }
        if self.rx_queue.is_empty() {
            return Err(EAGAIN);
        }
        self.rx_queue.remove(0).map_err(|_| EINVAL)
    }

    /// Get the number of pending receive buffers.
    pub fn rx_pending(&self) -> usize {
        self.rx_queue.len()
    }

    /// Get the number of pending transmit buffers.
    pub fn tx_pending(&self) -> usize {
        self.tx_queue.len()
    }
}
