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
//!
//! Each connection carries a set of transport channels (T/XS 20002-2025):
//! a management channel (SLE-CMTC, TCID 0x02), a service management channel
//! (SLE-SMTC, TCID 0x0A), and a default unicast data channel (SLE-DUDTC,
//! TCID 0x1F).

#![allow(dead_code, unreachable_pub)]

use kernel::alloc::KVec;
use kernel::prelude::*;

use super::sle_ssap::SsapSession;

// ---------------------------------------------------------------------------
// Transport Channel abstraction (T/XS 20002-2025)
//
// Each SLE connection carries a fixed set of logical transport channels,
// identified by a Transport Channel Identifier (TCID). This provides the
// minimal abstraction needed for standard compliance without implementing
// the full SLB logical channel framework.
// ---------------------------------------------------------------------------

/// Transport Channel Identifier (TCID) — fixed channel assignments per
/// T/XS 00001-2025 and T/XS 20002-2025 Table 1.
pub mod tcid {
    /// SLE Common Management Transport Channel (SLE-CMTC).
    pub const MANAGEMENT: u16 = 0x02;
    /// SLE Service Management Transport Channel (SLE-SMTC).
    pub const SERVICE_MGMT: u16 = 0x0A;
    /// SLE Default Unicast Data Transport Channel (SLE-DUDTC).
    pub const DEFAULT_DATA: u16 = 0x1F;
}

/// Transport mode for a channel (T/XS 20002-2025).
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum TransportMode {
    /// Unreliable delivery (no retransmission).
    #[default]
    Unreliable = 0,
    /// Reliable delivery (credit-based flow control).
    Reliable = 1,
}

/// State of a transport channel.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum ChannelState {
    /// Channel not yet configured.
    #[default]
    Closed = 0,
    /// Channel ready for data transfer.
    Open = 1,
}

/// A single logical transport channel within a connection.
#[derive(Copy, Clone, Debug)]
pub struct TransportChannel {
    /// Channel identifier.
    pub tcid: u16,
    /// Channel state.
    pub state: ChannelState,
    /// Transport mode (reliable/unreliable).
    pub mode: TransportMode,
    /// Maximum Transmission Unit negotiated for this channel.
    pub mtu: u16,
    /// Maximum PDU Segment size.
    pub mps: u16,
    /// TX credit count (for reliable mode flow control).
    pub tx_credits: u16,
    /// RX credit count.
    pub rx_credits: u16,
}

impl TransportChannel {
    /// Create a channel with standard defaults.
    const fn new(tcid: u16, mode: TransportMode, mtu: u16) -> Self {
        Self {
            tcid,
            state: ChannelState::Closed,
            mode,
            mtu,
            mps: 247,
            tx_credits: 0,
            rx_credits: 0,
        }
    }
}

/// Fixed set of transport channels per connection.
///
/// Each connection has exactly three channels: management, service management,
/// and default data. Additional dynamic channels are not supported in this
/// minimal implementation.
#[derive(Copy, Clone, Debug)]
pub struct ChannelSet {
    /// SLE-CMTC management channel (TCID 0x02): reliable, small MTU.
    pub mgmt: TransportChannel,
    /// SLE-SMTC service management channel (TCID 0x0A): reliable, used by SSAP.
    pub svc_mgmt: TransportChannel,
    /// SLE-DUDTC default unicast data channel (TCID 0x1F): mode from caps.
    pub data: TransportChannel,
}

impl Default for ChannelSet {
    fn default() -> Self {
        Self {
            mgmt: TransportChannel::new(tcid::MANAGEMENT, TransportMode::Reliable, 48),
            svc_mgmt: TransportChannel::new(tcid::SERVICE_MGMT, TransportMode::Reliable, 247),
            data: TransportChannel::new(tcid::DEFAULT_DATA, TransportMode::Unreliable, 247),
        }
    }
}

impl ChannelSet {
    /// Open all channels (called when connection transitions to Connected).
    pub fn open_all(&mut self) {
        self.mgmt.state = ChannelState::Open;
        self.svc_mgmt.state = ChannelState::Open;
        self.data.state = ChannelState::Open;
    }

    /// Close all channels (called on disconnection).
    pub fn close_all(&mut self) {
        self.mgmt.state = ChannelState::Closed;
        self.svc_mgmt.state = ChannelState::Closed;
        self.data.state = ChannelState::Closed;
    }

    /// Update data channel MTU/MPS based on negotiated connection parameters.
    pub fn negotiate(&mut self, max_pdu_size: u16, controller_mtu: u16) {
        let effective_mtu = max_pdu_size.min(controller_mtu);
        self.data.mtu = effective_mtu;
        self.data.mps = effective_mtu;
        // Service management inherits the same MTU ceiling.
        self.svc_mgmt.mtu = effective_mtu.min(self.svc_mgmt.mtu.max(effective_mtu));
    }

    /// Find channel by TCID, returning mutable reference.
    pub fn by_tcid_mut(&mut self, tcid: u16) -> Option<&mut TransportChannel> {
        match tcid {
            self::tcid::MANAGEMENT => Some(&mut self.mgmt),
            self::tcid::SERVICE_MGMT => Some(&mut self.svc_mgmt),
            self::tcid::DEFAULT_DATA => Some(&mut self.data),
            _ => None,
        }
    }

    /// Find channel by TCID, returning immutable reference.
    pub fn by_tcid(&self, tcid: u16) -> Option<&TransportChannel> {
        match tcid {
            self::tcid::MANAGEMENT => Some(&self.mgmt),
            self::tcid::SERVICE_MGMT => Some(&self.svc_mgmt),
            self::tcid::DEFAULT_DATA => Some(&self.data),
            _ => None,
        }
    }
}

/// Maximum number of messages in a connection data queue.
const QUEUE_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// Pre-allocated ring buffer for connection data queues
//
// Replaces KVec<KVec<u8>> to eliminate per-message heap allocation.
// Uses a single heap-allocated KVec<u8> as backing storage and a
// fixed-size metadata array for message boundaries.
// ---------------------------------------------------------------------------

/// Slot metadata: offset into backing buffer and message length.
#[derive(Copy, Clone, Default)]
struct SlotMeta {
    offset: u32,
    length: u16,
}

/// Fixed-capacity ring buffer for connection TX/RX data.
///
/// Backing storage is a single heap allocation. Message boundaries
/// are tracked in a small fixed-size metadata array.
/// Enqueue/dequeue are O(1) with no per-message allocation.
pub struct DataRingBuffer {
    /// Backing storage for all messages (heap-allocated).
    storage: KVec<u8>,
    /// Per-slot metadata.
    meta: [SlotMeta; QUEUE_DEPTH],
    /// Read cursor.
    head: usize,
    /// Number of valid entries.
    count: usize,
    /// Write offset into storage.
    write_off: u32,
    /// Total capacity of storage.
    capacity: u32,
}

impl DataRingBuffer {
    fn try_new() -> Result<Self> {
        let cap = QUEUE_DEPTH * CONN_DATA_MAX; // 16320 bytes
        let mut storage = KVec::with_capacity(cap, GFP_KERNEL)?;
        // Pre-fill to set length = capacity so we can index safely
        for _ in 0..cap {
            storage.push(0u8, GFP_KERNEL)?;
        }
        Ok(Self {
            storage,
            meta: [SlotMeta::default(); QUEUE_DEPTH],
            head: 0,
            count: 0,
            write_off: 0,
            capacity: cap as u32,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.count
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Enqueue data into the ring buffer. Returns EAGAIN if full.
    fn enqueue(&mut self, data: &[u8]) -> Result {
        if self.count >= QUEUE_DEPTH {
            return Err(EAGAIN);
        }
        let len = data.len().min(CONN_DATA_MAX);
        let tail = (self.head + self.count) % QUEUE_DEPTH;
        let off = (tail * CONN_DATA_MAX) as u32;
        self.storage[off as usize..off as usize + len].copy_from_slice(&data[..len]);
        self.meta[tail] = SlotMeta { offset: off, length: len as u16 };
        self.count += 1;
        Ok(())
    }

    /// Dequeue into a caller-provided buffer. Returns the number of bytes
    /// in the dequeued message, or EAGAIN if empty.
    fn dequeue_into(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.count == 0 {
            return Err(EAGAIN);
        }
        let m = self.meta[self.head];
        let len = m.length as usize;
        let off = m.offset as usize;
        let copy_len = len.min(buf.len());
        buf[..copy_len].copy_from_slice(&self.storage[off..off + copy_len]);
        self.head = (self.head + 1) % QUEUE_DEPTH;
        self.count -= 1;
        Ok(len)
    }

    /// Drop the oldest entry. Used for overflow handling.
    fn drop_oldest(&mut self) {
        if self.count > 0 {
            self.head = (self.head + 1) % QUEUE_DEPTH;
            self.count -= 1;
        }
    }
}

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
    /// CreateConnection command sent to controller, awaiting acceptance.
    ConnectPending = 4,
    /// Disconnect command sent to controller, awaiting acceptance.
    DisconnectPending = 5,
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

/// Maximum number of concurrent connections per controller.
pub const MAX_CONNECTIONS: usize = 8;

/// Invalid connection handle sentinel.
pub const INVALID_HANDLE: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Per-connection state
// ---------------------------------------------------------------------------

/// State for a single SLE connection, identified by a handle.
pub struct ConnEntry {
    /// Connection handle (assigned by ConnManager).
    pub handle: u16,
    /// Current connection state.
    pub state: ConnState,
    /// Peer SLE address.
    pub peer_addr: [u8; 6],
    /// Local GT role in this connection.
    pub local_role: GtRole,
    /// Local device capabilities.
    pub local_cap: AccessCapability,
    /// Negotiated connection parameters.
    pub params: NegotiatedParams,
    /// Transport channels (management, service management, data).
    pub channels: ChannelSet,
    /// SSAP session for service management (created on connection).
    pub ssap_session: Option<SsapSession>,
    /// Sequence number tracker.
    pub seq: SeqTracker,
    /// Transmit data queue (userspace -> peer).
    pub tx_queue: DataRingBuffer,
    /// Receive data queue (peer -> userspace).
    pub rx_queue: DataRingBuffer,
    /// Maximum queue depth.
    pub queue_max: usize,
    /// Total bytes sent.
    pub tx_bytes: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
}

impl ConnEntry {
    fn try_new(handle: u16) -> Result<Self> {
        Ok(Self {
            handle,
            state: ConnState::Idle,
            peer_addr: [0u8; 6],
            local_role: GtRole::TNode,
            local_cap: AccessCapability::default(),
            params: NegotiatedParams::default(),
            channels: ChannelSet::default(),
            ssap_session: None,
            seq: SeqTracker::new_async(),
            tx_queue: DataRingBuffer::try_new()?,
            rx_queue: DataRingBuffer::try_new()?,
            queue_max: QUEUE_DEPTH,
            tx_bytes: 0,
            rx_bytes: 0,
        })
    }
}

// ---------------------------------------------------------------------------
// Multi-connection manager
// ---------------------------------------------------------------------------

/// Manager for multiple concurrent SLE connections.
///
/// Each connection is identified by a unique 16-bit handle. The manager
/// tracks up to MAX_CONNECTIONS simultaneous links and provides
/// handle-based access to individual connection state machines.
pub struct ConnManager {
    /// Local SLE address shared by all connections.
    pub local_addr: [u8; 6],
    /// Active connections indexed by slot position.
    connections: KVec<ConnEntry>,
    /// Next handle to allocate.
    next_handle: u16,
    /// Runtime connection limit (from configfs or default).
    max_connections: usize,
    /// Total connections created (lifetime counter).
    pub total_created: u64,
    /// Total connections completed (lifetime counter).
    pub total_completed: u64,
}

impl ConnManager {
    /// Create a new multi-connection manager.
    pub fn new(local_addr: [u8; 6]) -> Self {
        Self {
            local_addr,
            connections: KVec::new(),
            next_handle: 1,
            max_connections: MAX_CONNECTIONS,
            total_created: 0,
            total_completed: 0,
        }
    }

    /// Set the maximum number of concurrent connections (from configfs).
    pub fn set_max_connections(&mut self, max: usize) {
        self.max_connections = max.min(MAX_CONNECTIONS);
    }

    /// Allocate a handle and return it.
    fn alloc_handle(&mut self) -> u16 {
        let mut h = self.next_handle;
        if h == INVALID_HANDLE {
            h = 1;
        }
        self.next_handle = h.wrapping_add(1);
        if self.next_handle == INVALID_HANDLE {
            self.next_handle = 1;
        }
        h
    }

    /// Find a connection by handle, return mutable reference.
    fn find_mut(&mut self, handle: u16) -> Result<&mut ConnEntry> {
        for entry in self.connections.iter_mut() {
            if entry.handle == handle {
                return Ok(entry);
            }
        }
        Err(ENOENT)
    }

    /// Find a connection by handle, return immutable reference.
    fn find(&self, handle: u16) -> Result<&ConnEntry> {
        for entry in self.connections.iter() {
            if entry.handle == handle {
                return Ok(entry);
            }
        }
        Err(ENOENT)
    }

    /// Get current number of active connections (not Idle).
    pub fn active_count(&self) -> usize {
        self.connections
            .iter()
            .filter(|c| c.state != ConnState::Idle)
            .count()
    }

    /// Get total number of connection slots in use (including Idle but not yet removed).
    pub fn slot_count(&self) -> usize {
        self.connections.len()
    }

    /// Initiate a new connection to the given peer address.
    ///
    /// Allocates a new connection handle and transitions to Connecting.
    /// Returns the assigned handle on success.
    pub fn connect(&mut self, peer_addr: [u8; 6], role: GtRole) -> Result<u16> {
        if self.connections.len() >= self.max_connections {
            pr_err!("sparklink: max connections ({}) reached\n", self.max_connections);
            return Err(EBUSY);
        }
        // Check for duplicate peer address among active connections
        for entry in self.connections.iter() {
            if entry.peer_addr == peer_addr && entry.state != ConnState::Idle {
                pr_err!("sparklink: already connected/connecting to this peer\n");
                return Err(EEXIST);
            }
        }
        let handle = self.alloc_handle();
        let mut entry = ConnEntry::try_new(handle)?;
        entry.peer_addr = peer_addr;
        entry.local_role = role;
        entry.seq = SeqTracker::new_async();
        entry.state = ConnState::ConnectPending;
        self.connections.push(entry, GFP_KERNEL)?;
        self.total_created += 1;
        pr_info!(
            "sparklink: connecting to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} as {:?} (handle={})\n",
            peer_addr[0],
            peer_addr[1],
            peer_addr[2],
            peer_addr[3],
            peer_addr[4],
            peer_addr[5],
            role,
            handle
        );
        Ok(handle)
    }

    /// Confirm that the controller accepted the CreateConnection command.
    /// Transitions ConnectPending → Connecting.
    pub fn confirm_connecting(&mut self, handle: u16) {
        if let Ok(entry) = self.find_mut(handle) {
            if entry.state == ConnState::ConnectPending {
                entry.state = ConnState::Connecting;
            }
        }
    }

    /// The controller rejected the CreateConnection command.
    /// Removes the ConnectPending entry.
    pub fn abort_connecting(&mut self, handle: u16) {
        let mut idx = None;
        for (i, entry) in self.connections.iter().enumerate() {
            if entry.handle == handle && entry.state == ConnState::ConnectPending {
                idx = Some(i);
                break;
            }
        }
        if let Some(i) = idx {
            let _ = self.connections.remove(i);
        }
    }

    /// Confirm a pending connection by peer address (for DLI ConnComplete events
    /// where the controller-side handle may differ from the host-assigned handle).
    pub fn confirm_connecting_by_addr(&mut self, addr: &[u8; 6]) -> Option<u16> {
        for entry in self.connections.iter_mut() {
            if entry.peer_addr == *addr && entry.state == ConnState::ConnectPending {
                entry.state = ConnState::Connecting;
                return Some(entry.handle);
            }
        }
        None
    }

    /// Accept an incoming connection from a remote peer.
    /// Creates a Connected entry using the controller-provided handle.
    pub fn accept_incoming(&mut self, handle: u16, addr: &[u8; 6]) -> Result {
        if self.connections.len() >= self.max_connections {
            return Err(EBUSY);
        }
        for entry in self.connections.iter() {
            if entry.handle == handle {
                return Ok(());
            }
        }
        let mut entry = ConnEntry::try_new(handle)?;
        entry.peer_addr = *addr;
        entry.state = ConnState::Connected;
        self.connections.push(entry, GFP_KERNEL)?;
        self.total_created += 1;
        pr_info!(
            "sparklink: accepted incoming connection from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (handle={})\n",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], handle
        );
        Ok(())
    }

    /// Abort the first pending connection matching a peer address.
    pub fn abort_connecting_by_addr(&mut self, addr: &[u8; 6]) {
        let mut idx = None;
        for (i, entry) in self.connections.iter().enumerate() {
            if entry.peer_addr == *addr && entry.state == ConnState::ConnectPending {
                idx = Some(i);
                break;
            }
        }
        if let Some(i) = idx {
            let _ = self.connections.remove(i);
        }
    }

    /// Confirm a disconnect by handle, removing the entry.
    /// Returns true if a matching entry was found and removed.
    pub fn confirm_disconnecting_by_handle(&mut self, handle: u16) -> bool {
        let mut idx = None;
        for (i, entry) in self.connections.iter().enumerate() {
            if entry.handle == handle
                && (entry.state == ConnState::DisconnectPending
                    || entry.state == ConnState::Connected
                    || entry.state == ConnState::Connecting)
            {
                idx = Some(i);
                break;
            }
        }
        if let Some(i) = idx {
            let _ = self.connections.remove(i);
            self.total_completed += 1;
            true
        } else {
            false
        }
    }

    /// Process a received access response for a given handle.
    pub fn process_access_response(
        &mut self,
        handle: u16,
        response_type: AccessResponseType,
        params: NegotiatedParams,
    ) -> Result {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connecting {
            return Err(EBUSY);
        }
        match response_type {
            AccessResponseType::Accepted => {
                entry.params = params;
                entry.channels.negotiate(params.max_pdu_size, 512);
                entry.channels.open_all();
                entry.ssap_session = Some(SsapSession::new(handle));
                entry.state = ConnState::Connected;
                pr_info!(
                    "sparklink: handle {} connected (bw={}MHz mcs={} timeout={}0ms)\n",
                    handle,
                    params.bandwidth_mhz,
                    params.mcs_index,
                    params.supervision_timeout
                );
                Ok(())
            }
            other => {
                entry.state = ConnState::Idle;
                pr_warn!("sparklink: handle {} connection rejected: {:?}\n", handle, other);
                Err(EACCES)
            }
        }
    }

    /// Start disconnecting a connection by handle.
    ///
    /// Sets DisconnectPending state; call confirm_disconnecting() after
    /// the controller accepts the command.
    pub fn disconnect(&mut self, handle: u16) -> Result {
        let entry = self.find_mut(handle)?;
        match entry.state {
            ConnState::Connected | ConnState::Connecting | ConnState::ConnectPending => {
                pr_info!(
                    "sparklink: disconnecting handle {} from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                    handle,
                    entry.peer_addr[0],
                    entry.peer_addr[1],
                    entry.peer_addr[2],
                    entry.peer_addr[3],
                    entry.peer_addr[4],
                    entry.peer_addr[5]
                );
                entry.state = ConnState::DisconnectPending;
                Ok(())
            }
            _ => Err(EPIPE),
        }
    }

    /// Confirm that the controller accepted the Disconnect command.
    /// Removes the entry from the connection table.
    pub fn confirm_disconnecting(&mut self, handle: u16) {
        let mut idx = None;
        for (i, entry) in self.connections.iter().enumerate() {
            if entry.handle == handle && entry.state == ConnState::DisconnectPending {
                idx = Some(i);
                break;
            }
        }
        if let Some(i) = idx {
            let _ = self.connections.remove(i);
            self.total_completed += 1;
        }
    }

    /// The controller rejected the Disconnect command.
    /// Revert DisconnectPending back to Connected.
    pub fn abort_disconnecting(&mut self, handle: u16) {
        if let Ok(entry) = self.find_mut(handle) {
            if entry.state == ConnState::DisconnectPending {
                entry.state = ConnState::Connected;
            }
        }
    }

    /// Send data on a connection identified by handle.
    pub fn send(&mut self, handle: u16, data: &[u8]) -> Result<usize> {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        if data.is_empty() || data.len() > CONN_DATA_MAX {
            return Err(EINVAL);
        }
        entry.tx_queue.enqueue(data)?;
        entry.seq.advance_tx();
        entry.tx_bytes += data.len() as u64;
        Ok(data.len())
    }

    /// Process received data for a connection by handle.
    pub fn receive_data(&mut self, handle: u16, data: &[u8], seq: u8) -> Result {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        if !entry.seq.check_rx(seq) {
            return Ok(());
        }
        if entry.rx_queue.len() >= entry.queue_max {
            entry.rx_queue.drop_oldest();
        }
        entry.rx_queue.enqueue(data)?;
        entry.seq.advance_rx();
        entry.rx_bytes += data.len() as u64;
        Ok(())
    }

    /// Receive data from a connection by handle into the provided buffer.
    /// Returns the number of bytes in the dequeued message.
    pub fn recv(&mut self, handle: u16, buf: &mut [u8]) -> Result<usize> {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        entry.rx_queue.dequeue_into(buf)
    }

    /// Get connection info by handle.
    pub fn info(&self, handle: u16) -> Result<&ConnEntry> {
        let entry = self.find(handle)?;
        if entry.state == ConnState::Idle {
            return Err(EPIPE);
        }
        Ok(entry)
    }

    /// Get a list of active connection handles (stack-allocated).
    /// Returns (array, count).
    pub fn active_handles(&self) -> ([u16; MAX_CONNECTIONS], usize) {
        let mut handles = [0u16; MAX_CONNECTIONS];
        let mut count = 0;
        for entry in self.connections.iter() {
            if entry.state != ConnState::Idle && count < MAX_CONNECTIONS {
                handles[count] = entry.handle;
                count += 1;
            }
        }
        (handles, count)
    }

    // --- Legacy single-connection compatibility layer ---
    // These methods operate on the most recently created connection
    // for backward compatibility with handle=0 (auto-select).

    /// Find the first connected (not merely connecting) entry.
    fn find_first_connected_mut(&mut self) -> Result<&mut ConnEntry> {
        for entry in self.connections.iter_mut() {
            if entry.state == ConnState::Connected {
                return Ok(entry);
            }
        }
        Err(EPIPE)
    }

    /// Resolve a handle: 0 means "first connected connection".
    pub fn resolve_handle(&mut self, handle: u16) -> Result<u16> {
        if handle == 0 {
            let entry = self.find_first_connected_mut()?;
            Ok(entry.handle)
        } else {
            // Verify handle exists
            let _ = self.find(handle)?;
            Ok(handle)
        }
    }

    /// Process a received SSAP PDU on a connection's service management channel.
    ///
    /// Routes the raw PDU through the per-connection SSAP session, which
    /// handles service discovery, property read/write, and notifications.
    /// Returns the response PDU length written to `resp_buf` (0 if none).
    pub fn process_ssap_pdu(
        &mut self,
        handle: u16,
        pdu_data: &[u8],
        ssap: &mut super::sle_ssap::SsapInner,
        resp_buf: &mut [u8],
    ) -> Result<usize> {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        let session = entry.ssap_session.as_mut().ok_or(ENODEV)?;
        session.process_incoming(ssap, pdu_data, resp_buf)
    }

    /// Query SSAP session state for a connection.
    /// Returns (mtu, info_exchanged) on success.
    pub fn ssap_session_info(&self, handle: u16) -> Option<(u16, bool)> {
        let entry = self.find(handle).ok()?;
        entry.ssap_session.as_ref().map(|s| (s.mtu, s.info_exchanged))
    }
}
