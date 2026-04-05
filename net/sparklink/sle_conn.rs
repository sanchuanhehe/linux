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
use kernel::time::msecs_to_jiffies;

use super::sle_phy::{ChannelMap, HoppingState};
use super::sle_ssap::SsapSession;

/// Read the current kernel jiffies counter.
pub fn jiffies_now() -> u64 {
    // SAFETY: reading jiffies_64 is always safe.
    unsafe { kernel::bindings::jiffies_64 }
}

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
    /// Sliding window sequence state for reliable/flow modes.
    /// Inactive (zeroed) when mode is Unreliable.
    pub seq: SeqState,
}

/// Initial credit window for reliable transport channels.
pub const INITIAL_CREDITS: u16 = 16;
/// When rx_credits drops below this threshold, send a credit grant.
const CREDIT_LOW_WATERMARK: u16 = 4;
/// Number of credits to grant at a time.
const CREDIT_GRANT_SIZE: u16 = 16;
/// PDU type for credit grant on the management channel.
/// Uses RFU code space (0x47~0xFF) per T/XS 20002-2025 Table 59.
pub const CREDIT_GRANT_PDU_TYPE: u8 = 0xFC;
/// Credit grant signaling PDU header+data length (per T/XS 20002-2025 §7.3.3):
/// code(1) + identifier(1) + length(2) + data(3) = 7 bytes after TCID;
/// total wire size = 8 bytes (TCID prefix + signaling).
pub const CREDIT_GRANT_PDU_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Sliding window sequence tracker (TXS-20002-2025 section 3.4)
// ---------------------------------------------------------------------------

/// Maximum sequence number space (14-bit, 0..16383).
const SEQ_MODULUS: u16 = 1 << 14;
/// Mask for 14-bit sequence arithmetic.
const SEQ_MASK: u16 = SEQ_MODULUS - 1;

/// Wrapping 14-bit sequence distance: `a - b` in [0, SEQ_MODULUS).
#[inline]
fn seq_distance(a: u16, b: u16) -> u16 {
    (a.wrapping_sub(b)) & SEQ_MASK
}

/// Sliding window state for reliable/flow mode transport channels.
///
/// Implements the TX/RX state machines defined in TXS-20002-2025 section 3.4:
/// - **TX side**: NextTxSeq, ExpectedAckSeq, ReTxSeq with bounded window
/// - **RX side**: ExpectedTxSeq tracking with gap detection
///
/// This struct is only active when the channel's `TransportMode` is `Reliable`.
/// `Unreliable` channels bypass all sequence logic.
#[derive(Copy, Clone, Debug)]
pub struct SeqState {
    // --- TX side ---
    /// Next sequence number to assign to a new outgoing PDU.
    pub next_tx_seq: u16,
    /// Oldest unacknowledged sequence number (peer has not ACKed up to here).
    pub expected_ack_seq: u16,
    /// Next sequence in the retransmission queue. When `retx_seq == next_tx_seq`,
    /// there is nothing to retransmit.
    pub retx_seq: u16,
    /// Maximum number of unacknowledged PDUs allowed (negotiated).
    pub tx_window: u16,

    // --- RX side ---
    /// Next expected in-order incoming sequence number.
    pub expected_rx_seq: u16,
    /// Tracks the highest sequence number buffered (for gap detection).
    pub buffer_seq: u16,

    // --- Counters ---
    /// Number of successfully transmitted PDUs.
    pub tx_count: u32,
    /// Number of retransmitted PDUs.
    pub retx_count: u32,
    /// Number of received in-order PDUs.
    pub rx_count: u32,
    /// Number of out-of-order / duplicate PDUs dropped.
    pub rx_drop_count: u32,
}

impl Default for SeqState {
    fn default() -> Self {
        Self {
            next_tx_seq: 0,
            expected_ack_seq: 0,
            retx_seq: 0,
            tx_window: INITIAL_CREDITS,
            expected_rx_seq: 0,
            buffer_seq: 0,
            tx_count: 0,
            retx_count: 0,
            rx_count: 0,
            rx_drop_count: 0,
        }
    }
}

/// Result of a TX window check.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TxAction {
    /// Send a new PDU with the given sequence number.
    SendNew(u16),
    /// Retransmit the PDU with the given sequence number.
    Retransmit(u16),
    /// TX window is full, cannot send.
    WindowFull,
}

/// Result of receiving a PDU with a particular sequence number.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxAction {
    /// PDU is in-order, deliver to upper layer.
    Accept,
    /// PDU fills a gap, buffer for reordering.
    Buffer,
    /// PDU is a duplicate or outside the window, discard.
    Drop,
}

impl SeqState {
    /// Determine the next TX action according to TXS-20002-2025 section 3.4.2.
    ///
    /// **TX rules**:
    /// - If `ReTxSeq == NextTxSeq` (nothing to retransmit):
    ///     - If window allows, assign `NextTxSeq` and advance.
    /// - If `ReTxSeq < NextTxSeq`:
    ///     - Retransmit the PDU at `ReTxSeq`, advance `ReTxSeq`.
    pub fn next_tx_action(&mut self) -> TxAction {
        if self.retx_seq == self.next_tx_seq {
            // No pending retransmissions — try to send new.
            let outstanding = seq_distance(self.next_tx_seq, self.expected_ack_seq);
            if outstanding < self.tx_window {
                let seq = self.next_tx_seq;
                self.next_tx_seq = (self.next_tx_seq + 1) & SEQ_MASK;
                self.retx_seq = self.next_tx_seq;
                self.tx_count += 1;
                TxAction::SendNew(seq)
            } else {
                TxAction::WindowFull
            }
        } else {
            // Retransmission pending.
            let seq = self.retx_seq;
            self.retx_seq = (self.retx_seq + 1) & SEQ_MASK;
            self.retx_count += 1;
            TxAction::Retransmit(seq)
        }
    }

    /// Process an incoming ACK (ReqSeq) from the peer.
    ///
    /// Advances `expected_ack_seq` to `ack_seq`, freeing window slots.
    /// Returns the number of PDUs acknowledged.
    pub fn process_ack(&mut self, ack_seq: u16) -> u16 {
        let ack = ack_seq & SEQ_MASK;
        let acked = seq_distance(ack, self.expected_ack_seq);
        if acked > 0 && acked <= self.tx_window {
            self.expected_ack_seq = ack;
        }
        acked
    }

    /// Trigger a full retransmission from `expected_ack_seq`.
    ///
    /// Sets `ReTxSeq = ExpectedAckSeq`, so subsequent `next_tx_action()`
    /// calls will retransmit all unacknowledged PDUs before sending new ones.
    pub fn trigger_retransmit(&mut self) {
        self.retx_seq = self.expected_ack_seq;
    }

    /// Classify an incoming PDU by its TxSeq per TXS-20002-2025 section 3.4.4.
    ///
    /// **RX rules**:
    /// - `TxSeq == ExpectedTxSeq`: in-order, accept, advance ExpectedTxSeq.
    /// - `0 < distance(TxSeq, ExpectedTxSeq) < TxWindow`: within window, buffer.
    /// - Otherwise: duplicate or outside window, drop.
    pub fn classify_rx(&mut self, tx_seq: u16) -> RxAction {
        let seq = tx_seq & SEQ_MASK;
        if seq == self.expected_rx_seq {
            // In-order delivery.
            self.expected_rx_seq = (self.expected_rx_seq + 1) & SEQ_MASK;
            self.buffer_seq = self.expected_rx_seq;
            self.rx_count += 1;
            RxAction::Accept
        } else {
            let dist_from_expected = seq_distance(seq, self.expected_rx_seq);
            if dist_from_expected > 0 && dist_from_expected < self.tx_window {
                // Within the window — buffer it (handles both new gaps and
                // gap-filling PDUs that arrive after higher-numbered ones).
                let new_end = (seq + 1) & SEQ_MASK;
                let new_dist = seq_distance(new_end, self.expected_rx_seq);
                let cur_dist = seq_distance(self.buffer_seq, self.expected_rx_seq);
                if new_dist > cur_dist && new_dist < self.tx_window {
                    self.buffer_seq = new_end;
                }
                self.rx_count += 1;
                RxAction::Buffer
            } else {
                // Duplicate or outside window.
                self.rx_drop_count += 1;
                RxAction::Drop
            }
        }
    }
}

impl TransportChannel {
    /// Create a channel with standard defaults.
    /// MPS is clamped to MTU per T/XS 20002-2025.
    const fn new(tcid: u16, mode: TransportMode, mtu: u16) -> Self {
        Self {
            tcid,
            state: ChannelState::Closed,
            mode,
            mtu,
            mps: mtu,
            tx_credits: 0,
            rx_credits: 0,
            seq: SeqState {
                next_tx_seq: 0,
                expected_ack_seq: 0,
                retx_seq: 0,
                tx_window: INITIAL_CREDITS,
                expected_rx_seq: 0,
                buffer_seq: 0,
                tx_count: 0,
                retx_count: 0,
                rx_count: 0,
                rx_drop_count: 0,
            },
        }
    }

    /// Try to consume a TX credit before sending. For Unreliable channels,
    /// always succeeds. Returns EAGAIN when no credits remain.
    pub fn try_consume_tx_credit(&mut self) -> Result {
        if self.mode == TransportMode::Unreliable {
            return Ok(());
        }
        if self.tx_credits == 0 {
            return Err(EAGAIN);
        }
        self.tx_credits -= 1;
        Ok(())
    }

    /// Record a received PDU. Returns true if rx_credits fell below the
    /// watermark and a credit grant should be sent to the peer.
    /// For Unreliable channels, always returns false.
    pub fn consume_rx_credit(&mut self) -> bool {
        if self.mode == TransportMode::Unreliable {
            return false;
        }
        self.rx_credits = self.rx_credits.saturating_sub(1);
        self.rx_credits < CREDIT_LOW_WATERMARK
    }

    /// Replenish rx_credits and return the number of credits granted.
    pub fn grant_rx_credits(&mut self) -> u16 {
        self.rx_credits = self.rx_credits.saturating_add(CREDIT_GRANT_SIZE);
        CREDIT_GRANT_SIZE
    }

    /// Apply a credit grant received from the peer.
    pub fn receive_tx_credits(&mut self, credits: u16) {
        self.tx_credits = self.tx_credits.saturating_add(credits);
    }
}

/// Fixed set of transport channels per connection.
///
/// Each connection has three fixed channels (management, service management,
/// default data) and an optional dynamic reliable channel for SSAP.
#[derive(Copy, Clone, Debug)]
pub struct ChannelSet {
    /// SLE-CMTC management channel (TCID 0x02): reliable, small MTU.
    pub mgmt: TransportChannel,
    /// SLE-SMTC service management channel (TCID 0x0A): reliable, used by SSAP.
    pub svc_mgmt: TransportChannel,
    /// SLE-DUDTC default unicast data channel (TCID 0x1F): mode from caps.
    pub data: TransportChannel,
    /// Dynamic reliable channel for SSAP (created after ExchangeInfo negotiation).
    pub ssap_reliable: Option<TransportChannel>,
    /// Monotonic identifier for credit grant signaling (T/XS 20002-2025 §7.3.3).
    pub credit_grant_id: u8,
    /// Monotonic identifier for transport control signaling (§7.3.3).
    pub sig_identifier: u8,
    /// Next dynamic TCID to allocate (0x80..=0xBF range).
    pub next_dynamic_tcid: u8,
}

impl Default for ChannelSet {
    fn default() -> Self {
        Self {
            mgmt: TransportChannel::new(tcid::MANAGEMENT, TransportMode::Reliable, 48),
            svc_mgmt: TransportChannel::new(tcid::SERVICE_MGMT, TransportMode::Reliable, 247),
            data: TransportChannel::new(tcid::DEFAULT_DATA, TransportMode::Unreliable, 247),
            ssap_reliable: None,
            credit_grant_id: 0,
            sig_identifier: 0,
            next_dynamic_tcid: 0x80,
        }
    }
}

impl ChannelSet {
    /// Open all channels (called when connection transitions to Connected).
    pub fn open_all(&mut self) {
        self.mgmt.state = ChannelState::Open;
        self.svc_mgmt.state = ChannelState::Open;
        self.data.state = ChannelState::Open;
        // Initialize credits for Reliable channels.
        for ch in [&mut self.mgmt, &mut self.svc_mgmt, &mut self.data] {
            if ch.mode == TransportMode::Reliable {
                ch.tx_credits = INITIAL_CREDITS;
                ch.rx_credits = INITIAL_CREDITS;
            }
        }
    }

    /// Close all channels (called on disconnection).
    pub fn close_all(&mut self) {
        self.mgmt.state = ChannelState::Closed;
        self.svc_mgmt.state = ChannelState::Closed;
        self.data.state = ChannelState::Closed;
        for ch in [&mut self.mgmt, &mut self.svc_mgmt, &mut self.data] {
            ch.tx_credits = 0;
            ch.rx_credits = 0;
        }
        self.ssap_reliable = None;
    }

    /// Get next credit grant identifier and advance counter (wraps at 255).
    pub fn next_credit_grant_id(&mut self) -> u8 {
        let id = self.credit_grant_id;
        self.credit_grant_id = self.credit_grant_id.wrapping_add(1);
        id
    }

    /// Get next signaling identifier and advance counter (wraps at 255).
    pub fn next_sig_id(&mut self) -> u8 {
        let id = self.sig_identifier;
        self.sig_identifier = self.sig_identifier.wrapping_add(1);
        id
    }

    /// Allocate a dynamic TCID from the unicast range (0x80..=0xBF).
    /// Returns None if the range is exhausted.
    pub fn alloc_dynamic_tcid(&mut self) -> Option<u8> {
        if self.next_dynamic_tcid > 0xBF {
            return None;
        }
        let tcid = self.next_dynamic_tcid;
        self.next_dynamic_tcid = self.next_dynamic_tcid.wrapping_add(1);
        Some(tcid)
    }

    /// Create and open the SSAP reliable transport channel with negotiated params.
    pub fn create_ssap_reliable(&mut self, tcid: u16, cfg: &ReliableModeConfig) {
        let mut ch = TransportChannel::new(tcid, TransportMode::Reliable, cfg.mtu);
        ch.mps = cfg.mps;
        ch.seq.tx_window = cfg.tx_window as u16;
        ch.state = ChannelState::Open;
        ch.tx_credits = INITIAL_CREDITS;
        ch.rx_credits = INITIAL_CREDITS;
        self.ssap_reliable = Some(ch);
    }

    /// Update data channel MTU/MPS based on negotiated connection parameters.
    pub fn negotiate(&mut self, max_pdu_size: u16, controller_mtu: u16) {
        let effective_mtu = max_pdu_size.min(controller_mtu);
        self.data.mtu = effective_mtu;
        self.data.mps = effective_mtu;
        // Service management inherits the same MTU ceiling.
        self.svc_mgmt.mtu = effective_mtu;
        self.svc_mgmt.mps = self.svc_mgmt.mps.min(self.svc_mgmt.mtu);
    }

    /// Find channel by TCID, returning mutable reference.
    pub fn by_tcid_mut(&mut self, tcid: u16) -> Option<&mut TransportChannel> {
        match tcid {
            self::tcid::MANAGEMENT => Some(&mut self.mgmt),
            self::tcid::SERVICE_MGMT => Some(&mut self.svc_mgmt),
            self::tcid::DEFAULT_DATA => Some(&mut self.data),
            _ => self
                .ssap_reliable
                .as_mut()
                .filter(|ch| ch.tcid == tcid),
        }
    }

    /// Find channel by TCID, returning immutable reference.
    pub fn by_tcid(&self, tcid: u16) -> Option<&TransportChannel> {
        match tcid {
            self::tcid::MANAGEMENT => Some(&self.mgmt),
            self::tcid::SERVICE_MGMT => Some(&self.svc_mgmt),
            self::tcid::DEFAULT_DATA => Some(&self.data),
            _ => self.ssap_reliable.as_ref().filter(|ch| ch.tcid == tcid),
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
        self.meta[tail] = SlotMeta {
            offset: off,
            length: len as u16,
        };
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
            crc_type: 0x01, // CRC24
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
// Peer capability storage (post-connect feature/version exchange)
// ---------------------------------------------------------------------------

/// Peer device capabilities learned via ReadFeatures / ReadVersion after
/// connection establishment.
#[derive(Copy, Clone, Debug, Default)]
pub struct PeerCapability {
    /// Feature bitmap (10 bytes, TXS-10003-2025 section 10).
    pub features: [u8; 10],
    /// Protocol version (TXS-10003 8.1.4).
    pub version: u8,
    /// Manufacturer identifier.
    pub manufacturer: u16,
    /// Sub-version number.
    pub subversion: u16,
    /// Whether feature exchange has been completed.
    pub features_valid: bool,
    /// Whether version exchange has been completed.
    pub version_valid: bool,
}

impl PeerCapability {
    /// Store features received from ReadPeerFeatures event.
    pub fn set_features(&mut self, features: [u8; 10]) {
        self.features = features;
        self.features_valid = true;
    }

    /// Store version info received from ReadPeerVersion event.
    pub fn set_version(&mut self, version: u8, manufacturer: u16, subversion: u16) {
        self.version = version;
        self.manufacturer = manufacturer;
        self.subversion = subversion;
        self.version_valid = true;
    }

    /// Check if a specific feature bit is set (bit index 0..79).
    pub fn has_feature(&self, bit: u8) -> bool {
        if bit >= 80 {
            return false;
        }
        let byte_idx = (bit / 8) as usize;
        let bit_idx = bit % 8;
        (self.features[byte_idx] & (1 << bit_idx)) != 0
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
            mcs_index: 4,     // QPSK 1/2
            pilot_density: 1, // 8:1
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

/// Maximum sync links per CIG/BIG group (per T/XS 10003-2025 8.10.1: 0x01-0x1F).
pub const MAX_SYNC_LINKS_PER_CIG: usize = 8;

// ---------------------------------------------------------------------------
// Sync link types and state (T/XS 10003-2025 section 8.10)
// ---------------------------------------------------------------------------

/// Whether a sync link is unicast (CIS) or multicast (BIS).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SyncLinkType {
    Unicast = 0,
    Multicast = 1,
}

/// Lifecycle state for a sync link.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SyncLinkState {
    /// Parameters configured but link not yet created.
    Configured = 0,
    /// Link creation in progress.
    Creating = 1,
    /// Link is active and carrying data.
    Active = 2,
}

/// Per-sync-link entry managed by ConnManager.
#[derive(Copy, Clone, Debug)]
pub struct SyncLinkEntry {
    /// Sync link connection handle.
    pub handle: u16,
    /// Unicast or multicast.
    pub link_type: SyncLinkType,
    /// Current state.
    pub state: SyncLinkState,
    /// Associated async connection handle.
    pub acl_handle: u16,
    /// CIG/BIG group identifier (0x00-0xEF).
    pub cig_id: u8,
    /// CIS/BIS identifier within the group.
    pub cis_id: u8,
    /// G→T SDU interval in microseconds.
    pub sdu_interval_g2t: u32,
    /// T→G SDU interval in microseconds.
    pub sdu_interval_t2g: u32,
    /// Max SDU payload size G→T (bytes).
    pub max_sdu_g2t: u16,
    /// Max SDU payload size T→G (bytes).
    pub max_sdu_t2g: u16,
    /// PDU retransmit count G→T.
    pub retransmit_g2t: u8,
    /// PDU retransmit count T→G.
    pub retransmit_t2g: u8,
    /// Max transport delay G→T (ms).
    pub max_latency_g2t: u16,
    /// Max transport delay T→G (ms).
    pub max_latency_t2g: u16,
    /// Adaptation mode: 0=periodic, 1=aperiodic.
    pub adapt_mode: u8,
    /// Data path direction (0=input, 1=output, 2=both).
    pub datapath_direction: u8,
    /// Data path identifier.
    pub datapath_id: u8,
    /// Codec identifier.
    pub codec_id: u8,
    /// Whether data path has been configured.
    pub datapath_configured: bool,
}

/// Parameters for configuring a sync unicast CIG group.
pub struct SyncCigParams {
    pub cig_id: u8,
    pub sdu_interval_g2t: u32,
    pub sdu_interval_t2g: u32,
    pub max_sdu_g2t: u16,
    pub max_sdu_t2g: u16,
    pub retransmit_g2t: u8,
    pub retransmit_t2g: u8,
    pub max_latency_g2t: u16,
    pub max_latency_t2g: u16,
    pub adapt_mode: u8,
    pub link_count: u8,
}

/// Result of CIG configuration.
pub struct SyncCigResult {
    pub cig_id: u8,
    pub link_count: u8,
    pub handles: [u16; MAX_SYNC_LINKS_PER_CIG],
}

/// Parameters for configuring a sync multicast BIG group.
pub struct SyncBigParams {
    pub big_id: u8,
    pub sdu_interval_g2t: u32,
    pub sdu_interval_t2g: u32,
    pub max_sdu_g2t: u16,
    pub max_sdu_t2g: u16,
    pub retransmit_g2t: u8,
    pub retransmit_t2g: u8,
    pub max_latency_g2t: u16,
    pub max_latency_t2g: u16,
    pub adapt_mode: u8,
    pub link_count: u8,
}

/// Result of BIG configuration.
pub struct SyncBigResult {
    pub big_id: u8,
    pub link_count: u8,
    pub handles: [u16; MAX_SYNC_LINKS_PER_CIG],
}

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
    /// Peer device capabilities (populated via post-connect exchange).
    pub peer_cap: PeerCapability,
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
    /// Jiffies timestamp of most recent data activity (RX or TX).
    pub last_activity: u64,
    /// Per-connection hopping state (independent from global PhyConfig).
    pub afh_hopping: HoppingState,
    /// Accumulated RSSI per channel (dBm x10, for averaging).
    pub afh_rssi_acc: [i32; 79],
    /// Number of RSSI samples per channel.
    pub afh_samples: [u16; 79],
    /// Retransmission quality score per channel (0=good, higher=worse).
    /// Incremented on retx, decremented on success; clamped to [0, 255].
    pub afh_retx_score: [u8; 79],
    /// Auto-classify trigger: number of reports before auto-classify.
    pub afh_auto_classify_threshold: u16,
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
            peer_cap: PeerCapability::default(),
            channels: ChannelSet::default(),
            ssap_session: None,
            seq: SeqTracker::new_async(),
            tx_queue: DataRingBuffer::try_new()?,
            rx_queue: DataRingBuffer::try_new()?,
            queue_max: QUEUE_DEPTH,
            tx_bytes: 0,
            rx_bytes: 0,
            last_activity: 0,
            afh_hopping: HoppingState::new(7, ChannelMap::all_used()),
            afh_rssi_acc: [0i32; 79],
            afh_samples: [0u16; 79],
            afh_retx_score: [0u8; 79],
            afh_auto_classify_threshold: 0,
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
    /// Sync link entries (CIS/BIS).
    sync_links: KVec<SyncLinkEntry>,
    /// Next sync handle to allocate.
    next_sync_handle: u16,
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
            sync_links: KVec::new(),
            next_sync_handle: 1,
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
            pr_err!(
                "sparklink: max connections ({}) reached\n",
                self.max_connections
            );
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

    /// Check if any connection entry (in any state) references this peer address.
    pub fn has_addr(&self, addr: &[u8; 6]) -> bool {
        self.connections.iter().any(|e| e.peer_addr == *addr)
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
        entry.last_activity = jiffies_now();
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
                entry.last_activity = jiffies_now();
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
                pr_warn!(
                    "sparklink: handle {} connection rejected: {:?}\n",
                    handle,
                    other
                );
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
        let mtu = entry.channels.data.mtu as usize;
        if data.len() > mtu {
            return Err(EFBIG);
        }
        entry.tx_queue.enqueue(data)?;
        entry.seq.advance_tx();
        entry.tx_bytes += data.len() as u64;
        entry.last_activity = jiffies_now();
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
        entry.last_activity = jiffies_now();
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

    /// Store peer features received from a ReadPeerFeatures event.
    pub fn store_peer_features(&mut self, handle: u16, features: [u8; 10]) -> Result {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        entry.peer_cap.set_features(features);
        Ok(())
    }

    /// Store peer version info received from a ReadPeerVersion event.
    pub fn store_peer_version(
        &mut self,
        handle: u16,
        version: u8,
        manufacturer: u16,
        subversion: u16,
    ) -> Result {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        entry.peer_cap.set_version(version, manufacturer, subversion);
        Ok(())
    }

    /// Update connection parameters after a ConnParamUpdate event.
    pub fn update_conn_params(
        &mut self,
        handle: u16,
        interval: u16,
        latency: u16,
        timeout: u16,
    ) -> Result {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        if interval > 0 {
            entry.params.event_group_period = interval;
        }
        if latency > 0 {
            entry.params.latency_period = latency;
        }
        if timeout > 0 {
            entry.params.supervision_timeout = timeout;
        }
        entry.last_activity = jiffies_now();
        Ok(())
    }

    /// Update PHY parameters after a PhyUpdate event.
    pub fn update_phy_params(
        &mut self,
        handle: u16,
        mcs_index: u8,
        bandwidth_mhz: u8,
    ) -> Result {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        if mcs_index <= 12 {
            entry.params.mcs_index = mcs_index;
        }
        if bandwidth_mhz == 1 || bandwidth_mhz == 2 || bandwidth_mhz == 4 {
            entry.params.bandwidth_mhz = bandwidth_mhz;
        }
        entry.last_activity = jiffies_now();
        Ok(())
    }

    /// Update maximum data length after a DataLenChange event.
    pub fn update_data_length(
        &mut self,
        handle: u16,
        max_tx_octets: u16,
        max_rx_octets: u16,
    ) -> Result {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        let effective = max_tx_octets.min(max_rx_octets);
        if effective > 0 {
            entry.params.max_pdu_size = effective;
            entry.channels.negotiate(effective, effective);
        }
        Ok(())
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

    /// Return the handle of the first connected connection, if any.
    pub fn first_active_handle(&self) -> Option<u16> {
        self.connections.iter()
            .find(|e| e.state == ConnState::Connected)
            .map(|e| e.handle)
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

    /// Build a TCID_Connect_Req PDU for reliable-mode channel creation.
    ///
    /// Allocates a local dynamic TCID, encodes the signaling PDU with a
    /// TCID 0x02 prefix for sending on the management channel, and records
    /// the allocated TCID in the SSAP session's `reliable_tcid`.
    ///
    /// Returns the total wire length written to `buf` (including TCID prefix).
    pub fn build_tcid_connect_req(
        &mut self,
        handle: u16,
        cfg: &ReliableModeConfig,
        buf: &mut [u8],
    ) -> Result<usize> {
        let entry = self.find_mut(handle)?;
        let local_tcid = entry
            .channels
            .alloc_dynamic_tcid()
            .ok_or(ENOMEM)?;
        let sig_id = entry.channels.next_sig_id();
        // Wire: [TCID_prefix=0x02][signaling PDU...]
        if buf.is_empty() {
            return Err(ENOMEM);
        }
        buf[0] = tcid::MANAGEMENT as u8;
        let sig_len = TransportSignaling::encode_connect_req(
            sig_id,
            local_tcid,
            cfg,
            &mut buf[1..],
        )?;
        // Record the local TCID so we can match the ConnectRsp.
        if let Some(session) = &mut entry.ssap_session {
            session.reliable_tcid = Some(local_tcid as u16);
        }
        Ok(1 + sig_len)
    }

    /// Handle an incoming transport control signaling PDU (on TCID 0x02).
    ///
    /// Decodes the signaling, and for ConnectReq allocates a local TCID,
    /// creates the reliable channel, and writes a ConnectRsp to `resp_buf`.
    /// Returns the response length (including TCID prefix), or 0 if no
    /// response is needed (e.g. for ConnectRsp which is terminal).
    pub fn handle_transport_signaling(
        &mut self,
        handle: u16,
        raw: &[u8],
        resp_buf: &mut [u8],
    ) -> Result<usize> {
        let sig = TransportSignaling::decode(raw)?;
        match sig {
            TransportSignaling::ConnectReq {
                identifier,
                src_tcid,
                config,
            } => {
                let entry = self.find_mut(handle)?;
                // Allocate a local TCID for this channel.
                let local_tcid = match entry.channels.alloc_dynamic_tcid() {
                    Some(t) => t,
                    None => {
                        // No resources — send failure response.
                        if resp_buf.len() < 9 {
                            return Err(ENOMEM);
                        }
                        resp_buf[0] = tcid::MANAGEMENT as u8;
                        let rsp_len = TransportSignaling::encode_connect_rsp(
                            identifier,
                            src_tcid,
                            0,
                            TcidConnectResult::NoResources,
                            &mut resp_buf[1..],
                        )?;
                        return Ok(1 + rsp_len);
                    }
                };
                // Create the reliable channel with negotiated params.
                entry
                    .channels
                    .create_ssap_reliable(local_tcid as u16, &config);
                // Record the peer's TCID so SSAP can route through it.
                if let Some(session) = &mut entry.ssap_session {
                    session.reliable_tcid = Some(local_tcid as u16);
                    session.reliable_mode = true;
                }
                pr_info!(
                    "sparklink: TCID_Connect_Req accepted: local={:#04x} peer={:#04x} mtu={}\n",
                    local_tcid,
                    src_tcid,
                    config.mtu
                );
                // Send success response.
                if resp_buf.len() < 9 {
                    return Err(ENOMEM);
                }
                resp_buf[0] = tcid::MANAGEMENT as u8;
                let rsp_len = TransportSignaling::encode_connect_rsp(
                    identifier,
                    src_tcid,
                    local_tcid,
                    TcidConnectResult::Success,
                    &mut resp_buf[1..],
                )?;
                Ok(1 + rsp_len)
            }
            TransportSignaling::ConnectRsp {
                src_tcid,
                dst_tcid,
                result,
                ..
            } => {
                let entry = self.find_mut(handle)?;
                if result == TcidConnectResult::Success {
                    // The peer accepted — create the channel locally using
                    // the src_tcid we proposed. The dst_tcid is the peer's
                    // local TCID (we don't need to store it separately since
                    // routing is done by our local TCID).
                    let cfg = ReliableModeConfig::default();
                    entry
                        .channels
                        .create_ssap_reliable(src_tcid as u16, &cfg);
                    if let Some(session) = &mut entry.ssap_session {
                        session.reliable_tcid = Some(src_tcid as u16);
                        session.reliable_mode = true;
                    }
                    pr_info!(
                        "sparklink: TCID_Connect_Rsp success: local={:#04x} peer={:#04x}\n",
                        src_tcid,
                        dst_tcid
                    );
                } else {
                    pr_info!(
                        "sparklink: TCID_Connect_Rsp failed: result={}\n",
                        result as u8
                    );
                    // Clear any pending reliable TCID.
                    if let Some(session) = &mut entry.ssap_session {
                        session.reliable_tcid = None;
                    }
                }
                Ok(0) // No further response for a ConnectRsp.
            }
            TransportSignaling::DisconnectReq {
                identifier,
                src_tcid,
                dst_tcid,
            } => {
                let entry = self.find_mut(handle)?;
                // Tear down the reliable channel if it matches.
                if let Some(ch) = &entry.channels.ssap_reliable {
                    if ch.tcid == dst_tcid as u16 {
                        entry.channels.ssap_reliable = None;
                        if let Some(session) = &mut entry.ssap_session {
                            session.reliable_tcid = None;
                        }
                    }
                }
                // Send DisconnectRsp.
                if resp_buf.len() < 8 {
                    return Err(ENOMEM);
                }
                resp_buf[0] = tcid::MANAGEMENT as u8;
                resp_buf[1] = sig_code::TCID_DISCONNECT_RSP;
                resp_buf[2] = identifier;
                let dlen: u16 = 3;
                let dl = dlen.to_le_bytes();
                resp_buf[3] = dl[0];
                resp_buf[4] = dl[1];
                resp_buf[5] = src_tcid;
                resp_buf[6] = dst_tcid;
                resp_buf[7] = 0; // result = success
                Ok(8)
            }
            TransportSignaling::DisconnectRsp { .. } => {
                Ok(0) // Terminal — no response.
            }
        }
    }

    /// Query SSAP session state for a connection.
    /// Returns (mtu, info_exchanged) on success.
    pub fn ssap_session_info(&self, handle: u16) -> Option<(u16, bool)> {
        let entry = self.find(handle).ok()?;
        entry
            .ssap_session
            .as_ref()
            .map(|s| (s.mtu, s.info_exchanged))
    }

    /// Return the SSAP reliable TCID for a connection, if one exists.
    pub fn ssap_reliable_tcid(&self, handle: u16) -> Option<u16> {
        let entry = self.find(handle).ok()?;
        entry.ssap_session.as_ref()?.reliable_tcid
    }

    /// Get a mutable reference to the SSAP session for a connection.
    pub fn get_ssap_session(
        &mut self,
        handle: u16,
    ) -> Option<&mut super::sle_ssap::SsapSession> {
        let entry = self.find_mut(handle).ok()?;
        entry.ssap_session.as_mut()
    }

    /// Pop the first available remote event from any connected peer's SSAP session.
    /// Returns (conn_handle, RemoteEvent) if any peer has a queued event.
    pub fn pop_any_remote_event(
        &mut self,
    ) -> Option<(u16, super::sle_ssap::RemoteEvent)> {
        for entry in self.connections.iter_mut() {
            if let Some(session) = &mut entry.ssap_session {
                if let Some(evt) = session.remote_db.pop_remote_event() {
                    return Some((entry.handle, evt));
                }
            }
        }
        None
    }

    /// Consume a TX credit on the specified channel before sending a PDU.
    pub fn consume_tx_credit(&mut self, handle: u16, tcid: u16) -> Result {
        let entry = self.find_mut(handle)?;
        let ch = entry.channels.by_tcid_mut(tcid).ok_or(EINVAL)?;
        ch.try_consume_tx_credit()
    }

    /// Record a received PDU on a channel and return whether credits need
    /// refilling (rx_credits fell below the watermark).
    pub fn consume_rx_credit(&mut self, handle: u16, tcid: u16) -> bool {
        self.find_mut(handle)
            .ok()
            .map(|e| {
                e.last_activity = jiffies_now();
                e.channels
                    .by_tcid_mut(tcid)
                    .map(|ch| ch.consume_rx_credit())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// Grant more credits for a channel, returning the number granted.
    pub fn grant_credits(&mut self, handle: u16, tcid: u16) -> Result<(u16, u8)> {
        let entry = self.find_mut(handle)?;
        let id = entry.channels.next_credit_grant_id();
        let ch = entry.channels.by_tcid_mut(tcid).ok_or(EINVAL)?;
        Ok((ch.grant_rx_credits(), id))
    }

    /// Apply credits received from the peer for a specific channel.
    pub fn receive_credits(&mut self, handle: u16, tcid: u16, credits: u16) -> Result {
        let entry = self.find_mut(handle)?;
        let ch = entry.channels.by_tcid_mut(tcid).ok_or(EINVAL)?;
        ch.receive_tx_credits(credits);
        Ok(())
    }

    /// Get credit state for a specific channel. Returns (tx_credits, rx_credits).
    pub fn channel_credits(&self, handle: u16, tcid: u16) -> Option<(u16, u16)> {
        let entry = self.find(handle).ok()?;
        entry
            .channels
            .by_tcid(tcid)
            .map(|ch| (ch.tx_credits, ch.rx_credits))
    }

    /// Set per-connection MTU for the data channel.
    ///
    /// Bounds: 23 <= mtu <= max_pdu_size (from negotiated params).
    /// MPS is clamped to the new MTU value if it would exceed MTU.
    /// If `mps` is Some and > 0, also set MPS (clamped to mtu).
    pub fn set_data_mtu(&mut self, handle: u16, mtu: u16, mps: Option<u16>) -> Result {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        let max = entry.params.max_pdu_size;
        if mtu < 23 || mtu > max {
            return Err(EINVAL);
        }
        entry.channels.data.mtu = mtu;
        if let Some(m) = mps {
            if m > 0 {
                entry.channels.data.mps = m.min(mtu);
            }
        }
        if entry.channels.data.mps > mtu {
            entry.channels.data.mps = mtu;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Adaptive Frequency Hopping (AFH)
    // -----------------------------------------------------------------------

    /// Set the channel map for a connection's hopping state.
    ///
    /// The map must have at least `min_channels` usable channels (minimum 2).
    pub fn set_channel_map(&mut self, handle: u16, map: ChannelMap, min_channels: u8) -> Result {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        let min_ch = if min_channels < 2 { 2 } else { min_channels };
        if map.used_count() < min_ch {
            return Err(EINVAL);
        }
        entry.afh_hopping.update_map(map);
        Ok(())
    }

    /// Get the current channel map for a connection.
    pub fn get_channel_map(&self, handle: u16) -> Result<ChannelMap> {
        let entry = self.find(handle)?;
        Ok(entry.afh_hopping.channel_map)
    }

    /// Advance the per-connection hopping state and return the next channel.
    ///
    /// Returns (channel_index, freq_mhz, event_counter).
    pub fn hop_next(&mut self, handle: u16) -> Result<(u8, u16, u16)> {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        let ch = entry.afh_hopping.next_channel();
        let freq = HoppingState::channel_to_freq(ch);
        let ec = entry.afh_hopping.event_counter;
        Ok((ch, freq, ec))
    }

    /// Record an RSSI measurement for a specific channel on a connection.
    pub fn report_rssi(&mut self, handle: u16, channel: u8, rssi_dbm: i8) -> Result {
        let entry = self.find_mut(handle)?;
        if channel >= 79 {
            return Err(EINVAL);
        }
        let idx = channel as usize;
        entry.afh_rssi_acc[idx] += i32::from(rssi_dbm);
        entry.afh_samples[idx] = entry.afh_samples[idx].saturating_add(1);
        Ok(())
    }

    /// Report a per-channel TX attempt and optional retransmission.
    /// Uses a quality score: retx increments by 3, success decrements by 1.
    pub fn report_retx(&mut self, handle: u16, channel: u8, retransmitted: bool) -> Result {
        let entry = self.find_mut(handle)?;
        if channel >= 79 {
            return Err(EINVAL);
        }
        let idx = channel as usize;
        if retransmitted {
            entry.afh_retx_score[idx] = entry.afh_retx_score[idx].saturating_add(3);
        } else {
            entry.afh_retx_score[idx] = entry.afh_retx_score[idx].saturating_sub(1);
        }

        // Auto-classify if threshold is set and enough total samples collected.
        if entry.afh_auto_classify_threshold > 0 {
            let total: u32 = entry.afh_samples.iter().map(|&s| u32::from(s)).sum();
            if total >= u32::from(entry.afh_auto_classify_threshold) {
                let _ = Self::do_classify(entry, -70, 2);
            }
        }
        Ok(())
    }

    /// Set the auto-classify threshold for a connection.
    /// When total RSSI samples + TX attempts exceed this threshold,
    /// classification is triggered automatically.
    /// Set to 0 to disable auto-classify.
    pub fn set_auto_classify(&mut self, handle: u16, threshold: u16) -> Result {
        let entry = self.find_mut(handle)?;
        entry.afh_auto_classify_threshold = threshold;
        Ok(())
    }

    /// Classify channels based on accumulated RSSI measurements.
    ///
    /// Channels with average RSSI below `threshold_dbm` are marked bad.
    /// Channels with no measurements are kept as-is (assumed good).
    /// Ensures at least `min_channels` remain usable (minimum 2).
    ///
    /// Returns the new channel map and applies it to the connection.
    pub fn classify_channels(
        &mut self,
        handle: u16,
        threshold_dbm: i8,
        min_channels: u8,
    ) -> Result<ChannelMap> {
        let entry = self.find_mut(handle)?;
        if entry.state != ConnState::Connected {
            return Err(EPIPE);
        }
        Self::do_classify(entry, threshold_dbm, min_channels)
    }

    /// Internal classification logic operating on a ConnEntry directly.
    fn do_classify(
        entry: &mut ConnEntry,
        threshold_dbm: i8,
        min_channels: u8,
    ) -> Result<ChannelMap> {
        let min_ch = if min_channels < 2 { 2 } else { min_channels };
        let threshold = i32::from(threshold_dbm);

        // Build classification starting from the current map.
        // Channels with no measurements keep their current state.
        let mut new_map = entry.afh_hopping.channel_map;
        let mut bad_channels: [(u8, i32); 79] = [(0, 0); 79];
        let mut bad_count = 0usize;

        for ch in 0u8..79 {
            let idx = ch as usize;
            let mut is_bad = false;
            // RSSI-based classification.
            if entry.afh_samples[idx] > 0 {
                let avg = entry.afh_rssi_acc[idx] / i32::from(entry.afh_samples[idx]);
                if avg < threshold {
                    is_bad = true;
                }
            }
            // Retransmission score classification: score >= 5 marks bad.
            if entry.afh_retx_score[idx] >= 5 {
                is_bad = true;
            }
            if is_bad {
                new_map.set_used(ch, false);
                let quality = if entry.afh_samples[idx] > 0 {
                    entry.afh_rssi_acc[idx] / i32::from(entry.afh_samples[idx])
                } else {
                    i32::MIN / 2
                };
                bad_channels[bad_count] = (ch, quality);
                bad_count += 1;
            }
        }

        // If too many channels removed, re-enable the least-bad ones.
        if new_map.used_count() < min_ch {
            // Sort bad channels by RSSI descending (least bad first).
            let bad_slice = &mut bad_channels[..bad_count];
            // Simple insertion sort (at most 79 elements).
            for i in 1..bad_slice.len() {
                let mut j = i;
                while j > 0 && bad_slice[j].1 > bad_slice[j - 1].1 {
                    bad_slice.swap(j, j - 1);
                    j -= 1;
                }
            }
            for &(ch, _) in bad_slice.iter() {
                if new_map.used_count() >= min_ch {
                    break;
                }
                new_map.set_used(ch, true);
            }
        }

        entry.afh_hopping.update_map(new_map);
        // Clear measurement accumulators after classification.
        entry.afh_rssi_acc = [0i32; 79];
        entry.afh_samples = [0u16; 79];
        entry.afh_retx_score = [0u8; 79];
        Ok(new_map)
    }

    /// Check all Connected entries for supervision timeout expiry.
    ///
    /// Returns a vector of handles whose `last_activity` jiffies exceed the
    /// negotiated supervision timeout. The caller should disconnect these.
    ///
    /// Uses a caller-provided stack buffer to avoid heap allocation in
    /// the hot path. Returns the number of timed-out handles written.
    pub fn check_supervision_timeouts(&self, out: &mut [u16; MAX_CONNECTIONS]) -> usize {
        let now = jiffies_now();
        let mut count = 0usize;
        for entry in self.connections.iter() {
            if entry.state != ConnState::Connected {
                continue;
            }
            if entry.last_activity == 0 {
                continue;
            }
            let timeout_ms = u64::from(entry.params.supervision_timeout) * 10;
            if timeout_ms == 0 {
                continue;
            }
            let timeout_jiffies = msecs_to_jiffies(timeout_ms as u32) as u64;
            let elapsed = now.wrapping_sub(entry.last_activity);
            if elapsed > timeout_jiffies && count < MAX_CONNECTIONS {
                out[count] = entry.handle;
                count += 1;
            }
        }
        count
    }

    /// Return the number of jiffies until the next supervision
    /// timeout fires, or `None` if no connected entry has a timeout.
    pub fn next_supervision_jiffies(&self) -> Option<u64> {
        let now = jiffies_now();
        let mut earliest: Option<u64> = None;
        for entry in self.connections.iter() {
            if entry.state != ConnState::Connected {
                continue;
            }
            if entry.last_activity == 0 {
                continue;
            }
            let timeout_ms = u64::from(entry.params.supervision_timeout) * 10;
            if timeout_ms == 0 {
                continue;
            }
            let timeout_jiffies = msecs_to_jiffies(timeout_ms as u32) as u64;
            let elapsed = now.wrapping_sub(entry.last_activity);
            if elapsed < timeout_jiffies {
                let remaining = timeout_jiffies - elapsed;
                match earliest {
                    Some(e) if remaining < e => earliest = Some(remaining),
                    None => earliest = Some(remaining),
                    _ => {}
                }
            }
        }
        earliest
    }

    /// Force-disconnect a connection due to supervision timeout.
    ///
    /// Closes channels, resets state, and returns the peer address for
    /// event notification purposes.
    pub fn timeout_disconnect(&mut self, handle: u16) -> Result<[u8; 6]> {
        let entry = self.find_mut(handle)?;
        let peer = entry.peer_addr;
        entry.channels.close_all();
        entry.state = ConnState::Idle;
        entry.ssap_session = None;
        pr_warn!(
            "sparklink: handle {} supervision timeout (peer {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})\n",
            handle, peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]
        );
        Ok(peer)
    }

    // -----------------------------------------------------------------------
    // Sync link management (T/XS 10003-2025 section 8.10)
    // -----------------------------------------------------------------------

    /// Configure a sync unicast event group set (CIG) per 8.10.1.
    ///
    /// Associates SDU interval, latency, and per-link parameters with
    /// a CIG ID. Returns the allocated link handles.
    pub fn sync_ucast_configure(&mut self, params: &SyncCigParams) -> Result<SyncCigResult> {
        if params.cig_id > 0xEF {
            return Err(EINVAL);
        }
        if params.link_count == 0 || params.link_count as usize > MAX_SYNC_LINKS_PER_CIG {
            return Err(EINVAL);
        }
        // Remove existing CIG if reconfiguring.
        self.sync_links.retain(|l| l.cig_id != params.cig_id);

        let mut handles = [0u16; MAX_SYNC_LINKS_PER_CIG];
        for (i, h) in handles
            .iter_mut()
            .enumerate()
            .take(params.link_count as usize)
        {
            let handle = self.alloc_sync_handle();
            let link = SyncLinkEntry {
                handle,
                link_type: SyncLinkType::Unicast,
                state: SyncLinkState::Configured,
                acl_handle: 0,
                cig_id: params.cig_id,
                cis_id: i as u8,
                sdu_interval_g2t: params.sdu_interval_g2t,
                sdu_interval_t2g: params.sdu_interval_t2g,
                max_sdu_g2t: params.max_sdu_g2t,
                max_sdu_t2g: params.max_sdu_t2g,
                retransmit_g2t: params.retransmit_g2t,
                retransmit_t2g: params.retransmit_t2g,
                max_latency_g2t: params.max_latency_g2t,
                max_latency_t2g: params.max_latency_t2g,
                adapt_mode: params.adapt_mode,
                datapath_direction: 0,
                datapath_id: 0,
                codec_id: 0,
                datapath_configured: false,
            };
            *h = handle;
            self.sync_links.push(link, GFP_KERNEL)?;
        }
        Ok(SyncCigResult {
            cig_id: params.cig_id,
            link_count: params.link_count,
            handles,
        })
    }

    /// Create (activate) sync unicast links within a configured CIG per 8.10.3.
    ///
    /// Each link is bound to an existing async connection via `acl_handles`.
    pub fn sync_ucast_create(&mut self, cig_id: u8, acl_handles: &[u16]) -> Result<u8> {
        // Verify async connections exist.
        for &ah in acl_handles {
            let entry = self.find(ah)?;
            if entry.state != ConnState::Connected {
                return Err(EPIPE);
            }
        }
        let mut count = 0u8;
        for link in self.sync_links.iter_mut() {
            if link.cig_id != cig_id {
                continue;
            }
            if link.state != SyncLinkState::Configured {
                continue;
            }
            let idx = count as usize;
            if idx < acl_handles.len() {
                link.acl_handle = acl_handles[idx];
                link.state = SyncLinkState::Active;
                count += 1;
            }
        }
        if count == 0 {
            return Err(ENOENT);
        }
        Ok(count)
    }

    /// Remove all sync links belonging to a CIG per 8.10.4.
    pub fn sync_ucast_remove(&mut self, cig_id: u8) -> Result {
        // Cannot remove a CIG with active links.
        for link in self.sync_links.iter() {
            if link.cig_id == cig_id && link.state == SyncLinkState::Active {
                return Err(EBUSY);
            }
        }
        let before = self.sync_links.len();
        self.sync_links.retain(|l| l.cig_id != cig_id);
        if self.sync_links.len() == before {
            return Err(ENOENT);
        }
        Ok(())
    }

    /// Configure a sync multicast event group set (BIG) per 8.10.7.
    pub fn sync_mcast_configure(&mut self, params: &SyncBigParams) -> Result<SyncBigResult> {
        if params.big_id > 0xEF {
            return Err(EINVAL);
        }
        if params.link_count == 0 || params.link_count as usize > MAX_SYNC_LINKS_PER_CIG {
            return Err(EINVAL);
        }
        self.sync_links
            .retain(|l| !(l.cig_id == params.big_id && l.link_type == SyncLinkType::Multicast));

        let mut handles = [0u16; MAX_SYNC_LINKS_PER_CIG];
        for (i, h) in handles
            .iter_mut()
            .enumerate()
            .take(params.link_count as usize)
        {
            let handle = self.alloc_sync_handle();
            let link = SyncLinkEntry {
                handle,
                link_type: SyncLinkType::Multicast,
                state: SyncLinkState::Configured,
                acl_handle: 0,
                cig_id: params.big_id,
                cis_id: i as u8,
                sdu_interval_g2t: params.sdu_interval_g2t,
                sdu_interval_t2g: params.sdu_interval_t2g,
                max_sdu_g2t: params.max_sdu_g2t,
                max_sdu_t2g: params.max_sdu_t2g,
                retransmit_g2t: params.retransmit_g2t,
                retransmit_t2g: params.retransmit_t2g,
                max_latency_g2t: params.max_latency_g2t,
                max_latency_t2g: params.max_latency_t2g,
                adapt_mode: params.adapt_mode,
                datapath_direction: 0,
                datapath_id: 0,
                codec_id: 0,
                datapath_configured: false,
            };
            *h = handle;
            self.sync_links.push(link, GFP_KERNEL)?;
        }
        Ok(SyncBigResult {
            big_id: params.big_id,
            link_count: params.link_count,
            handles,
        })
    }

    /// Create (activate) sync multicast links per 8.10.9.
    pub fn sync_mcast_create(&mut self, big_id: u8, acl_handles: &[u16]) -> Result<u8> {
        for &ah in acl_handles {
            let entry = self.find(ah)?;
            if entry.state != ConnState::Connected {
                return Err(EPIPE);
            }
        }
        let mut count = 0u8;
        for link in self.sync_links.iter_mut() {
            if link.cig_id != big_id || link.link_type != SyncLinkType::Multicast {
                continue;
            }
            if link.state != SyncLinkState::Configured {
                continue;
            }
            let idx = count as usize;
            if idx < acl_handles.len() {
                link.acl_handle = acl_handles[idx];
                link.state = SyncLinkState::Active;
                count += 1;
            }
        }
        if count == 0 {
            return Err(ENOENT);
        }
        Ok(count)
    }

    /// Remove all sync multicast links belonging to a BIG per 8.10.10.
    pub fn sync_mcast_remove(&mut self, big_id: u8) -> Result {
        for link in self.sync_links.iter() {
            if link.cig_id == big_id
                && link.link_type == SyncLinkType::Multicast
                && link.state == SyncLinkState::Active
            {
                return Err(EBUSY);
            }
        }
        let before = self.sync_links.len();
        self.sync_links
            .retain(|l| !(l.cig_id == big_id && l.link_type == SyncLinkType::Multicast));
        if self.sync_links.len() == before {
            return Err(ENOENT);
        }
        Ok(())
    }

    /// Configure the data path for a sync link per 8.10.13.
    pub fn sync_datapath_config(
        &mut self,
        sync_handle: u16,
        direction: u8,
        path_id: u8,
        codec_id: u8,
    ) -> Result {
        let link = self.find_sync_mut(sync_handle)?;
        if link.state != SyncLinkState::Active {
            return Err(EINVAL);
        }
        link.datapath_direction = direction;
        link.datapath_id = path_id;
        link.codec_id = codec_id;
        link.datapath_configured = true;
        Ok(())
    }

    /// Remove the data path for a sync link per 8.10.14.
    pub fn sync_datapath_remove(&mut self, sync_handle: u16) -> Result {
        let link = self.find_sync_mut(sync_handle)?;
        if !link.datapath_configured {
            return Err(EINVAL);
        }
        link.datapath_configured = false;
        link.datapath_direction = 0;
        link.datapath_id = 0;
        link.codec_id = 0;
        Ok(())
    }

    /// Get information about a sync link by handle.
    pub fn sync_link_info(&self, sync_handle: u16) -> Result<&SyncLinkEntry> {
        self.find_sync(sync_handle)
    }

    /// Allocate a sync link handle.
    fn alloc_sync_handle(&mut self) -> u16 {
        let h = self.next_sync_handle;
        self.next_sync_handle = h.wrapping_add(1);
        if self.next_sync_handle == 0 {
            self.next_sync_handle = 1;
        }
        h
    }

    /// Find a sync link by handle (mutable).
    fn find_sync_mut(&mut self, handle: u16) -> Result<&mut SyncLinkEntry> {
        for link in self.sync_links.iter_mut() {
            if link.handle == handle {
                return Ok(link);
            }
        }
        Err(ENOENT)
    }

    /// Find a sync link by handle (immutable).
    fn find_sync(&self, handle: u16) -> Result<&SyncLinkEntry> {
        for link in self.sync_links.iter() {
            if link.handle == handle {
                return Ok(link);
            }
        }
        Err(ENOENT)
    }

    // -----------------------------------------------------------------------
    // Sync link accept / reject (T/XS 10003-2025 §8.10.5/6, §8.10.11/12)
    // -----------------------------------------------------------------------

    /// Accept a sync unicast setup request. Transitions the link to Active.
    pub fn sync_ucast_accept(&mut self, sync_handle: u16) -> Result {
        let link = self.find_sync_mut(sync_handle)?;
        if link.link_type != SyncLinkType::Unicast {
            return Err(EINVAL);
        }
        if link.state != SyncLinkState::Creating {
            return Err(EINVAL);
        }
        link.state = SyncLinkState::Active;
        Ok(())
    }

    /// Reject a sync unicast setup request. Removes the link entry.
    pub fn sync_ucast_reject(&mut self, sync_handle: u16, _reason: u8) -> Result {
        let found = self.sync_links.iter().any(|l| {
            l.handle == sync_handle
                && l.link_type == SyncLinkType::Unicast
                && l.state == SyncLinkState::Creating
        });
        if !found {
            return Err(ENOENT);
        }
        self.sync_links.retain(|l| l.handle != sync_handle);
        Ok(())
    }

    /// Accept a sync multicast setup request. Transitions the link to Active.
    pub fn sync_mcast_accept(&mut self, sync_handle: u16) -> Result {
        let link = self.find_sync_mut(sync_handle)?;
        if link.link_type != SyncLinkType::Multicast {
            return Err(EINVAL);
        }
        if link.state != SyncLinkState::Creating {
            return Err(EINVAL);
        }
        link.state = SyncLinkState::Active;
        Ok(())
    }

    /// Reject a sync multicast setup request. Removes the link entry.
    pub fn sync_mcast_reject(&mut self, sync_handle: u16, _reason: u8) -> Result {
        let found = self.sync_links.iter().any(|l| {
            l.handle == sync_handle
                && l.link_type == SyncLinkType::Multicast
                && l.state == SyncLinkState::Creating
        });
        if !found {
            return Err(ENOENT);
        }
        self.sync_links.retain(|l| l.handle != sync_handle);
        Ok(())
    }

    /// Handle an incoming SyncUcastSetupRequest event from the controller.
    /// Creates a link entry in Creating state for the host to accept/reject.
    pub fn handle_sync_ucast_setup_request(
        &mut self,
        async_handle: u16,
        sync_handle: u16,
        group_set_id: u8,
        group_id: u8,
    ) -> Result {
        let link = SyncLinkEntry {
            handle: sync_handle,
            link_type: SyncLinkType::Unicast,
            state: SyncLinkState::Creating,
            acl_handle: async_handle,
            cig_id: group_set_id,
            cis_id: group_id,
            sdu_interval_g2t: 0,
            sdu_interval_t2g: 0,
            max_sdu_g2t: 0,
            max_sdu_t2g: 0,
            retransmit_g2t: 0,
            retransmit_t2g: 0,
            max_latency_g2t: 0,
            max_latency_t2g: 0,
            adapt_mode: 0,
            datapath_direction: 0,
            datapath_id: 0,
            codec_id: 0,
            datapath_configured: false,
        };
        self.sync_links.push(link, GFP_KERNEL)?;
        Ok(())
    }

    /// Handle SyncUcastSetupComplete — transition to Active or remove on error.
    pub fn handle_sync_ucast_setup_complete(
        &mut self,
        sync_handle: u16,
        status: u8,
    ) -> Result {
        if status == 0 {
            let link = self.find_sync_mut(sync_handle)?;
            link.state = SyncLinkState::Active;
        } else {
            self.sync_links.retain(|l| l.handle != sync_handle);
        }
        Ok(())
    }

    /// Handle an incoming SyncMcastSetupRequest event from the controller.
    pub fn handle_sync_mcast_setup_request(
        &mut self,
        async_handle: u16,
        sync_handle: u16,
    ) -> Result {
        let link = SyncLinkEntry {
            handle: sync_handle,
            link_type: SyncLinkType::Multicast,
            state: SyncLinkState::Creating,
            acl_handle: async_handle,
            cig_id: 0,
            cis_id: 0,
            sdu_interval_g2t: 0,
            sdu_interval_t2g: 0,
            max_sdu_g2t: 0,
            max_sdu_t2g: 0,
            retransmit_g2t: 0,
            retransmit_t2g: 0,
            max_latency_g2t: 0,
            max_latency_t2g: 0,
            adapt_mode: 0,
            datapath_direction: 0,
            datapath_id: 0,
            codec_id: 0,
            datapath_configured: false,
        };
        self.sync_links.push(link, GFP_KERNEL)?;
        Ok(())
    }

    /// Handle SyncMcastSetupComplete — transition to Active or remove on error.
    pub fn handle_sync_mcast_setup_complete(
        &mut self,
        sync_handle: u16,
        status: u8,
    ) -> Result {
        if status == 0 {
            let link = self.find_sync_mut(sync_handle)?;
            link.state = SyncLinkState::Active;
        } else {
            self.sync_links.retain(|l| l.handle != sync_handle);
        }
        Ok(())
    }

    /// Look up the async ACL handle associated with a sync link.
    pub fn sync_acl_handle(&self, sync_handle: u16) -> Result<u16> {
        let link = self.find_sync(sync_handle)?;
        Ok(link.acl_handle)
    }

    /// Collect sync links belonging to a given CIG/BIG group.
    /// Returns a temporary array and count for DLI command encoding.
    pub fn sync_links_for_group(
        &self,
        group_id: u8,
        link_type: SyncLinkType,
    ) -> ([SyncLinkEntry; MAX_SYNC_LINKS_PER_CIG], u8) {
        let empty = SyncLinkEntry {
            handle: 0, link_type: SyncLinkType::Unicast,
            state: SyncLinkState::Configured, acl_handle: 0,
            cig_id: 0, cis_id: 0,
            sdu_interval_g2t: 0, sdu_interval_t2g: 0,
            max_sdu_g2t: 0, max_sdu_t2g: 0,
            retransmit_g2t: 0, retransmit_t2g: 0,
            max_latency_g2t: 0, max_latency_t2g: 0,
            adapt_mode: 0, datapath_direction: 0,
            datapath_id: 0, codec_id: 0, datapath_configured: false,
        };
        let mut arr = [empty; MAX_SYNC_LINKS_PER_CIG];
        let mut count = 0u8;
        for link in self.sync_links.iter() {
            if link.cig_id == group_id && link.link_type == link_type {
                if (count as usize) < MAX_SYNC_LINKS_PER_CIG {
                    arr[count as usize] = link.clone();
                    count += 1;
                }
            }
        }
        (arr, count)
    }
}

// ---------------------------------------------------------------------------
// DLI parameter encoding helpers for sync commands (T/XS 10003-2025 §8.10)
// ---------------------------------------------------------------------------

/// Encode SyncUcastParam (0x2801) / SyncMcastParam (0x2807) DLI command params.
///
/// Wire format (§8.10.1 / §8.10.7):
///   [group_id:1][sdu_interval_g2t:3][sdu_interval_t2g:3][sca:1][rsvd:1]
///   [adapt_mode:1][max_latency_g2t:2][max_latency_t2g:2][link_count:1]
///   followed by per-link: [stream_id:1][max_sdu_g2t:2][max_sdu_t2g:2]
///                         [retransmit_g2t:1][retransmit_t2g:1]
pub fn encode_sync_param_cmd(
    group_id: u8,
    sdu_interval_g2t: u32,
    sdu_interval_t2g: u32,
    adapt_mode: u8,
    max_latency_g2t: u16,
    max_latency_t2g: u16,
    link_count: u8,
    links: &[SyncLinkEntry],
) -> ([u8; 64], usize) {
    let mut buf = [0u8; 64];
    let mut off = 0usize;

    buf[off] = group_id;
    off += 1;
    // SDU intervals are 3 bytes LE
    let g2t = sdu_interval_g2t.to_le_bytes();
    buf[off..off + 3].copy_from_slice(&g2t[..3]);
    off += 3;
    let t2g = sdu_interval_t2g.to_le_bytes();
    buf[off..off + 3].copy_from_slice(&t2g[..3]);
    off += 3;
    buf[off] = 0x07; // SCA: best accuracy (0-20ppm)
    off += 1;
    buf[off] = 0; // reserved
    off += 1;
    buf[off] = adapt_mode;
    off += 1;
    buf[off..off + 2].copy_from_slice(&max_latency_g2t.to_le_bytes());
    off += 2;
    buf[off..off + 2].copy_from_slice(&max_latency_t2g.to_le_bytes());
    off += 2;
    buf[off] = link_count;
    off += 1;

    for link in links.iter().take(link_count as usize) {
        buf[off] = link.cis_id;
        off += 1;
        buf[off..off + 2].copy_from_slice(&link.max_sdu_g2t.to_le_bytes());
        off += 2;
        buf[off..off + 2].copy_from_slice(&link.max_sdu_t2g.to_le_bytes());
        off += 2;
        buf[off] = link.retransmit_g2t;
        off += 1;
        buf[off] = link.retransmit_t2g;
        off += 1;
    }

    (buf, off)
}

/// Encode SyncUcastCreate (0x2803) / SyncMcastCreate (0x2809) command params.
///
/// Wire format (§8.10.3 / §8.10.9):
///   [group_id:1][link_count:1]
///   per-link: [sync_handle:2][acl_handle:2]
pub fn encode_sync_create_cmd(
    group_id: u8,
    links: &[SyncLinkEntry],
) -> ([u8; 40], usize) {
    let mut buf = [0u8; 40];
    buf[0] = group_id;
    buf[1] = links.len() as u8;
    let mut off = 2usize;
    for link in links.iter() {
        buf[off..off + 2].copy_from_slice(&link.handle.to_le_bytes());
        off += 2;
        buf[off..off + 2].copy_from_slice(&link.acl_handle.to_le_bytes());
        off += 2;
    }
    (buf, off)
}

/// Encode SyncDataPathConfig (0x280D) command params.
///
/// Wire format (§8.10.13):
///   [sync_handle:2][direction:1][path_id:1][codec_id:1]
///   [controller_delay:3][codec_cfg_len:1][codec_cfg:var]
pub fn encode_sync_datapath_cmd(
    sync_handle: u16,
    direction: u8,
    path_id: u8,
    codec_id: u8,
) -> ([u8; 8], usize) {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&sync_handle.to_le_bytes());
    buf[2] = direction;
    buf[3] = path_id;
    buf[4] = codec_id;
    buf[5] = 0; buf[6] = 0; buf[7] = 0; // controller_delay = 0
    (buf, 8)
}

// ---------------------------------------------------------------------------
// Sync link isochronous data encapsulation (T/XS 10003-2025 §7.5)
// ---------------------------------------------------------------------------

/// Segmentation indicator for sync link SDU fragments.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SyncSegment {
    Complete = 0,
    First = 1,
    Middle = 2,
    Last = 3,
}

/// Encode a sync link data header (§7.5) for TX.
///
/// Header layout (4 bytes):
///   bits [0..11]:   link handle (12 bits)
///   bits [12..13]:  segmentation indicator (2 bits)
///   bit  [14]:      timestamp present (1 bit)
///   bit  [15]:      priority (1 bit)
///   bits [16..24]:  DLI data length (lower 8 bits)
///   bits [24..25]:  DLI data length (upper 1 bit, 9 bits total)
///   bits [25..31]:  reserved
///
/// Returns the 4-byte header.
pub fn encode_sync_data_header(
    handle: u16,
    segment: SyncSegment,
    has_timestamp: bool,
    priority: bool,
    payload_len: u16,
) -> [u8; 4] {
    let mut hdr = [0u8; 4];
    // byte 0: handle bits [0..7]
    hdr[0] = (handle & 0xFF) as u8;
    // byte 1: handle bits [8..11] | segment [12..13] | ts [14] | prio [15]
    hdr[1] = ((handle >> 8) & 0x0F) as u8
        | ((segment as u8) << 4)
        | (if has_timestamp { 1 << 6 } else { 0 })
        | (if priority { 1 << 7 } else { 0 });
    // byte 2-3: DLI data length (9 bits LE + reserved)
    hdr[2] = (payload_len & 0xFF) as u8;
    hdr[3] = ((payload_len >> 8) & 0x01) as u8;
    hdr
}

/// Decode a sync link data header (§7.5).
///
/// Returns (handle, segment, has_timestamp, priority, payload_len).
pub fn decode_sync_data_header(hdr: &[u8; 4]) -> (u16, SyncSegment, bool, bool, u16) {
    let handle = (hdr[0] as u16) | (((hdr[1] & 0x0F) as u16) << 8);
    let seg = match (hdr[1] >> 4) & 0x03 {
        0 => SyncSegment::Complete,
        1 => SyncSegment::First,
        2 => SyncSegment::Middle,
        _ => SyncSegment::Last,
    };
    let ts = (hdr[1] & 0x40) != 0;
    let prio = (hdr[1] & 0x80) != 0;
    let len = (hdr[2] as u16) | (((hdr[3] & 0x01) as u16) << 8);
    (handle, seg, ts, prio, len)
}

// ---------------------------------------------------------------------------
// Transport control signaling codec (T/XS 20002-2025 §7.3.3, §7.3.4)
//
// Signaling PDUs are exchanged on the management channel (TCID 0x02) using
// a common envelope: [code:1][identifier:1][length:2 LE][data:variable].
// ---------------------------------------------------------------------------

/// Transport control signaling codes (T/XS 20002-2025 Table 59).
pub mod sig_code {
    pub const ERROR_RSP: u8 = 0x00;
    pub const TCID_CONNECT_REQ: u8 = 0x10;
    pub const TCID_CONNECT_RSP: u8 = 0x11;
    pub const TCID_DISCONNECT_REQ: u8 = 0x12;
    pub const TCID_DISCONNECT_RSP: u8 = 0x13;
}

/// First dynamic unicast TCID we allocate (range 0x80..=0xBF per standard).
const DYNAMIC_TCID_BASE: u16 = 0x80;

/// Reliable-mode channel configuration (T/XS 20002-2025 §7.3.4.1).
#[derive(Copy, Clone, Debug)]
pub struct ReliableModeConfig {
    pub mtu: u16,
    pub mps: u16,
    pub tx_window: u8,
    pub max_tx_threshold: u8,
    pub retransmission_timeout: u16,
    pub response_timeout: u16,
    pub reorder_timeout: u16,
    pub crc_init: u16,
}

impl Default for ReliableModeConfig {
    fn default() -> Self {
        Self {
            mtu: 247,
            mps: 247,
            tx_window: 16,
            max_tx_threshold: 4,
            retransmission_timeout: 2000,
            response_timeout: 2000,
            reorder_timeout: 2000,
            crc_init: 0,
        }
    }
}

/// Result codes for TCID_Connect_Rsp (T/XS 20002-2025 Table 60).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcidConnectResult {
    Success = 0,
    NoResources = 1,
    MtuUnsupported = 2,
    MpsUnsupported = 3,
    SrcTcidUnexpected = 4,
}

impl TcidConnectResult {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::NoResources,
            2 => Self::MtuUnsupported,
            3 => Self::MpsUnsupported,
            4 => Self::SrcTcidUnexpected,
            _ => Self::NoResources,
        }
    }
}

/// Transport control signaling PDU (decoded form).
pub enum TransportSignaling {
    /// TCID_Connect_Req (code 0x10).
    ConnectReq {
        identifier: u8,
        src_tcid: u8,
        config: ReliableModeConfig,
    },
    /// TCID_Connect_Rsp (code 0x11).
    ConnectRsp {
        identifier: u8,
        src_tcid: u8,
        dst_tcid: u8,
        result: TcidConnectResult,
    },
    /// TCID_Disconnect_Req (code 0x12).
    DisconnectReq {
        identifier: u8,
        src_tcid: u8,
        dst_tcid: u8,
    },
    /// TCID_Disconnect_Rsp (code 0x13).
    DisconnectRsp {
        identifier: u8,
        src_tcid: u8,
        dst_tcid: u8,
        result: u8,
    },
}

impl TransportSignaling {
    /// Encode a TCID_Connect_Req for reliable-mode channel creation.
    ///
    /// Wire format (after TCID prefix byte):
    /// `[code=0x10][identifier][length LE16=18][srcTCID][optionOffset=0]`
    /// `[E=0|M_EN=0|RFU=0][modeConfig(15 bytes)]`
    pub fn encode_connect_req(
        identifier: u8,
        src_tcid: u8,
        cfg: &ReliableModeConfig,
        buf: &mut [u8],
    ) -> Result<usize> {
        // modeConfig for reliable: mode(1)+mtu(2)+mps(2)+txWin(1)+maxTx(1)
        //   +retxTimeout(2)+rspTimeout(2)+reorderTimeout(2)+crcInit(2) = 15
        // data: srcTCID(1)+optionOffset(1)+flags(1)+modeConfig(15) = 18
        const DATA_LEN: u16 = 18;
        const TOTAL: usize = 4 + DATA_LEN as usize; // 22
        if buf.len() < TOTAL {
            return Err(ENOMEM);
        }
        buf[0] = sig_code::TCID_CONNECT_REQ;
        buf[1] = identifier;
        let len_bytes = DATA_LEN.to_le_bytes();
        buf[2] = len_bytes[0];
        buf[3] = len_bytes[1];
        buf[4] = src_tcid;
        buf[5] = 0; // optionOffset = 0 (no extensions)
        buf[6] = 0; // E=0, M_EN=0, RFU=0
        // modeConfig: transportMode=3 in upper nibble, RFU=0 in lower
        buf[7] = 0x30;
        let mtu = cfg.mtu.to_le_bytes();
        buf[8] = mtu[0];
        buf[9] = mtu[1];
        let mps = cfg.mps.to_le_bytes();
        buf[10] = mps[0];
        buf[11] = mps[1];
        buf[12] = cfg.tx_window;
        buf[13] = cfg.max_tx_threshold;
        let retx = cfg.retransmission_timeout.to_le_bytes();
        buf[14] = retx[0];
        buf[15] = retx[1];
        let rsp = cfg.response_timeout.to_le_bytes();
        buf[16] = rsp[0];
        buf[17] = rsp[1];
        let reorder = cfg.reorder_timeout.to_le_bytes();
        buf[18] = reorder[0];
        buf[19] = reorder[1];
        let crc = cfg.crc_init.to_le_bytes();
        buf[20] = crc[0];
        buf[21] = crc[1];
        Ok(TOTAL)
    }

    /// Encode a TCID_Connect_Rsp.
    ///
    /// Wire format: `[code=0x11][identifier][length LE16=4][srcTCID][dstTCID][result][LC=0|RFU]`
    pub fn encode_connect_rsp(
        identifier: u8,
        src_tcid: u8,
        dst_tcid: u8,
        result: TcidConnectResult,
        buf: &mut [u8],
    ) -> Result<usize> {
        const DATA_LEN: u16 = 4;
        const TOTAL: usize = 4 + DATA_LEN as usize; // 8
        if buf.len() < TOTAL {
            return Err(ENOMEM);
        }
        buf[0] = sig_code::TCID_CONNECT_RSP;
        buf[1] = identifier;
        let len_bytes = DATA_LEN.to_le_bytes();
        buf[2] = len_bytes[0];
        buf[3] = len_bytes[1];
        buf[4] = src_tcid;
        buf[5] = dst_tcid;
        buf[6] = result as u8;
        buf[7] = 0; // LC=0, RFU=0 (no lcConfig extension)
        Ok(TOTAL)
    }

    /// Decode a transport control signaling PDU from raw data (after TCID byte).
    ///
    /// Input: `[code][identifier][length LE16][data...]`
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() < 4 {
            return Err(EINVAL);
        }
        let code = raw[0];
        let identifier = raw[1];
        let data_len = u16::from_le_bytes([raw[2], raw[3]]) as usize;
        if raw.len() < 4 + data_len {
            return Err(EINVAL);
        }
        let data = &raw[4..4 + data_len];

        match code {
            sig_code::TCID_CONNECT_REQ => {
                // data: srcTCID(1) + optionOffset(1) + flags(1) + modeConfig(>=15)
                if data.len() < 18 {
                    return Err(EINVAL);
                }
                let src_tcid = data[0];
                // data[1] = optionOffset (ignored for now)
                // data[2] = flags (E, M_EN, RFU — ignored for now)
                // modeConfig starts at data[3]
                let transport_mode = data[3] >> 4;
                if transport_mode != 3 {
                    // Only reliable mode supported for dynamic channels.
                    return Err(ENOTSUPP);
                }
                let mtu = u16::from_le_bytes([data[4], data[5]]);
                let mps = u16::from_le_bytes([data[6], data[7]]);
                let tx_window = data[8];
                let max_tx_threshold = data[9];
                let retransmission_timeout = u16::from_le_bytes([data[10], data[11]]);
                let response_timeout = u16::from_le_bytes([data[12], data[13]]);
                let reorder_timeout = u16::from_le_bytes([data[14], data[15]]);
                let crc_init = u16::from_le_bytes([data[16], data[17]]);
                Ok(Self::ConnectReq {
                    identifier,
                    src_tcid,
                    config: ReliableModeConfig {
                        mtu,
                        mps,
                        tx_window,
                        max_tx_threshold,
                        retransmission_timeout,
                        response_timeout,
                        reorder_timeout,
                        crc_init,
                    },
                })
            }
            sig_code::TCID_CONNECT_RSP => {
                // data: srcTCID(1) + dstTCID(1) + result(1) + LC_flags(1)
                if data.len() < 4 {
                    return Err(EINVAL);
                }
                Ok(Self::ConnectRsp {
                    identifier,
                    src_tcid: data[0],
                    dst_tcid: data[1],
                    result: TcidConnectResult::from_u8(data[2]),
                })
            }
            sig_code::TCID_DISCONNECT_REQ => {
                if data.len() < 2 {
                    return Err(EINVAL);
                }
                Ok(Self::DisconnectReq {
                    identifier,
                    src_tcid: data[0],
                    dst_tcid: data[1],
                })
            }
            sig_code::TCID_DISCONNECT_RSP => {
                if data.len() < 3 {
                    return Err(EINVAL);
                }
                Ok(Self::DisconnectRsp {
                    identifier,
                    src_tcid: data[0],
                    dst_tcid: data[1],
                    result: data[2],
                })
            }
            _ => Err(ENOTSUPP),
        }
    }
}
