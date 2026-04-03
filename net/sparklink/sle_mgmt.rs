// SPDX-License-Identifier: GPL-2.0

//! SparkLink management plane — command pending queue with timeout.
//!
//! Provides a fixed-size ring of `CmdPendingEntry` objects that track
//! in-flight commands sent to the DLI controller.  The `EventPump`
//! resolves entries when `CommandComplete` / `CommandStatus` events
//! arrive; stale entries are expired based on a jiffies deadline.
//!
//! This replaces the previous fire-and-forget `send_command` model and
//! mirrors the Bluetooth `hci_sent_cmd` / `req_wait_q` mechanism in a
//! simplified form suitable for the kernel Rust crate.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};
use kernel::prelude::*;
use kernel::time::msecs_to_jiffies;

// ---------------------------------------------------------------------------
// Pending entry
// ---------------------------------------------------------------------------

/// Marker value for a pending (unresolved) command.
pub(crate) const CMD_STATUS_PENDING: u32 = u32::MAX;

/// Maximum response data bytes stored per entry.
const CMD_DATA_MAX: usize = 64;

/// Default command timeout in milliseconds.
pub(crate) const CMD_TIMEOUT_MS: u32 = 5000;

/// A single in-flight command awaiting a response from the controller.
pub(crate) struct CmdPendingEntry {
    /// DLI opcode (OGF|OCF) that was sent.
    pub(crate) opcode: u16,
    /// Monotonically increasing sequence number (for dedup).
    pub(crate) seq: u32,
    /// Resolution status.
    ///
    /// - `CMD_STATUS_PENDING` — not yet resolved.
    /// - `0x8000_0000 | (status & 0xFF)` — resolved with DLI status.
    /// - `0x8000_0000 | 0x100` — resolved as timeout (ETIMEDOUT).
    pub(crate) status: AtomicU32,
    /// Response payload (valid only after resolution).
    pub(crate) data: [u8; CMD_DATA_MAX],
    /// Length of valid data.
    pub(crate) data_len: u16,
    /// Deadline (jiffies) after which this entry is considered timed out.
    pub(crate) deadline: u64,
}

/// Bit set in `status` to indicate the entry is resolved.
pub(crate) const CMD_RESOLVED_BIT: u32 = 0x8000_0000;
/// Pseudo-status value for timeout.
pub(crate) const CMD_TIMEOUT_STATUS: u32 = CMD_RESOLVED_BIT | 0x100;

impl CmdPendingEntry {
    /// Create a new pending entry.
    pub(crate) fn new(opcode: u16, seq: u32, timeout_ms: u32) -> Self {
        let deadline = Self::jiffies_now().wrapping_add(msecs_to_jiffies(timeout_ms) as u64);
        Self {
            opcode,
            seq,
            status: AtomicU32::new(CMD_STATUS_PENDING),
            data: [0u8; CMD_DATA_MAX],
            data_len: 0,
            deadline,
        }
    }

    /// Check whether this entry is still pending.
    pub(crate) fn is_pending(&self) -> bool {
        self.status.load(Ordering::Acquire) == CMD_STATUS_PENDING
    }

    /// Check whether this entry has been resolved (complete or timeout).
    pub(crate) fn is_resolved(&self) -> bool {
        self.status.load(Ordering::Acquire) & CMD_RESOLVED_BIT != 0
    }

    /// Resolve this entry with a CommandComplete result.
    ///
    /// Stores the status and up to `CMD_DATA_MAX` bytes of response data.
    pub(crate) fn resolve(&mut self, dli_status: u8, response: &[u8]) {
        let copy_len = response.len().min(CMD_DATA_MAX);
        self.data[..copy_len].copy_from_slice(&response[..copy_len]);
        self.data_len = copy_len as u16;
        self.status.store(
            CMD_RESOLVED_BIT | (u32::from(dli_status)),
            Ordering::Release,
        );
    }

    /// Mark this entry as timed out.
    pub(crate) fn timeout(&mut self) {
        self.status.store(CMD_TIMEOUT_STATUS, Ordering::Release);
    }

    /// Extract the DLI status from a resolved entry.
    /// Returns `None` if still pending.
    pub(crate) fn result_status(&self) -> Option<u8> {
        let v = self.status.load(Ordering::Acquire);
        if v & CMD_RESOLVED_BIT != 0 {
            if v == CMD_TIMEOUT_STATUS {
                None // timeout — no DLI status
            } else {
                Some((v & 0xFF) as u8)
            }
        } else {
            None
        }
    }

    /// Read the current jiffies counter.
    fn jiffies_now() -> u64 {
        // SAFETY: reading jiffies_64 is always safe.
        unsafe { kernel::bindings::jiffies_64 }
    }

    /// Check whether this entry's deadline has passed.
    pub(crate) fn is_expired(&self) -> bool {
        Self::jiffies_now() >= self.deadline
    }
}

// ---------------------------------------------------------------------------
// Pending queue
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously pending commands.
const CMD_QUEUE_DEPTH: usize = 16;

/// Fixed-size ring buffer of pending commands.
///
/// Access is serialized by the caller (the SUBSYSTEM mutex).
pub(crate) struct CmdPendingQueue {
    /// Circular buffer of entries.
    entries: [Option<CmdPendingEntry>; CMD_QUEUE_DEPTH],
    /// Next write position.
    tail: usize,
    /// Next sequence number.
    next_seq: u32,
    /// Count of pending (unresolved) entries.
    pub(crate) pending_count: u16,
    /// Cumulative count of commands submitted.
    pub(crate) total_submitted: u64,
    /// Cumulative count of commands resolved (complete or timeout).
    pub(crate) total_resolved: u64,
    /// Cumulative count of timeouts.
    pub(crate) total_timeouts: u64,
}

impl CmdPendingQueue {
    /// Create an empty queue.
    pub(crate) const fn new() -> Self {
        const NONE: Option<CmdPendingEntry> = None;
        Self {
            entries: [NONE; CMD_QUEUE_DEPTH],
            tail: 0,
            next_seq: 1,
            pending_count: 0,
            total_submitted: 0,
            total_resolved: 0,
            total_timeouts: 0,
        }
    }

    /// Submit a new command. Returns the sequence number on success,
    /// or `EBUSY` if the queue is full.
    pub(crate) fn submit(&mut self, opcode: u16) -> Result<u32> {
        self.submit_with_timeout(opcode, CMD_TIMEOUT_MS)
    }

    /// Submit a new command with a custom timeout.
    pub(crate) fn submit_with_timeout(&mut self, opcode: u16, timeout_ms: u32) -> Result<u32> {
        if self.pending_count as usize >= CMD_QUEUE_DEPTH {
            return Err(EBUSY);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        let entry = CmdPendingEntry::new(opcode, seq, timeout_ms);
        self.entries[self.tail] = Some(entry);
        self.tail = (self.tail + 1) % CMD_QUEUE_DEPTH;
        self.pending_count += 1;
        self.total_submitted += 1;
        Ok(seq)
    }

    /// Find the oldest pending entry matching `opcode` and resolve it.
    ///
    /// Returns `true` if a matching entry was found and resolved.
    pub(crate) fn resolve(&mut self, opcode: u16, status: u8, data: &[u8]) -> bool {
        for entry in self.entries.iter_mut().flatten() {
            if entry.opcode == opcode && entry.is_pending() {
                entry.resolve(status, data);
                self.pending_count = self.pending_count.saturating_sub(1);
                self.total_resolved += 1;
                return true;
            }
        }
        false
    }

    /// Expire all entries whose deadline has passed.
    ///
    /// Returns the number of entries that were timed out.
    pub(crate) fn expire_stale(&mut self) -> u32 {
        let mut expired = 0u32;
        for entry in self.entries.iter_mut().flatten() {
            if entry.is_pending() && entry.is_expired() {
                entry.timeout();
                self.pending_count = self.pending_count.saturating_sub(1);
                self.total_resolved += 1;
                self.total_timeouts += 1;
                expired += 1;
            }
        }
        expired
    }

    /// Remove resolved entries from the ring (garbage collection).
    ///
    /// Call periodically to free slots for new commands.
    pub(crate) fn gc(&mut self) {
        for slot in self.entries.iter_mut() {
            if let Some(ref entry) = slot {
                if entry.is_resolved() {
                    *slot = None;
                }
            }
        }
    }

    /// Number of currently pending (unresolved) commands.
    pub(crate) fn pending(&self) -> u16 {
        self.pending_count
    }

    /// Look up a pending entry by sequence number.
    pub(crate) fn find_by_seq(&self, seq: u32) -> Option<&CmdPendingEntry> {
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.seq == seq)
    }
}

// ---------------------------------------------------------------------------
// Command request queue (outgoing command buffer)
// ---------------------------------------------------------------------------

/// Maximum parameter length per command request.
const CMD_REQ_PARAM_MAX: usize = 240;

/// Command request to be sent to the controller asynchronously.
pub(crate) struct CmdRequest {
    /// DLI opcode (raw u16).
    pub(crate) opcode: u16,
    /// Parameter data.
    pub(crate) params: [u8; CMD_REQ_PARAM_MAX],
    /// Valid parameter length.
    pub(crate) param_len: u16,
}

/// Maximum depth of the command request queue.
const CMD_REQ_QUEUE_DEPTH: usize = 64;

/// Fixed-size ring buffer for outgoing command requests.
///
/// Commands are enqueued from the ioctl path and dequeued by the
/// `CommandWorker` running in workqueue context.
pub(crate) struct CmdRequestQueue {
    entries: [Option<CmdRequest>; CMD_REQ_QUEUE_DEPTH],
    head: usize,
    tail: usize,
    count: u16,
}

impl CmdRequestQueue {
    /// Create an empty queue.
    pub(crate) const fn new() -> Self {
        const NONE: Option<CmdRequest> = None;
        Self {
            entries: [NONE; CMD_REQ_QUEUE_DEPTH],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Enqueue a command request. Returns `EBUSY` if the queue is full.
    pub(crate) fn push(&mut self, opcode: u16, params: &[u8]) -> Result {
        if self.count as usize >= CMD_REQ_QUEUE_DEPTH {
            return Err(EBUSY);
        }
        let mut req = CmdRequest {
            opcode,
            params: [0u8; CMD_REQ_PARAM_MAX],
            param_len: params.len().min(CMD_REQ_PARAM_MAX) as u16,
        };
        let copy_len = req.param_len as usize;
        req.params[..copy_len].copy_from_slice(&params[..copy_len]);
        self.entries[self.tail] = Some(req);
        self.tail = (self.tail + 1) % CMD_REQ_QUEUE_DEPTH;
        self.count += 1;
        Ok(())
    }

    /// Dequeue the next command request. Returns `None` if empty.
    pub(crate) fn pop(&mut self) -> Option<CmdRequest> {
        if self.count == 0 {
            return None;
        }
        let req = self.entries[self.head].take();
        self.head = (self.head + 1) % CMD_REQ_QUEUE_DEPTH;
        if req.is_some() {
            self.count -= 1;
        }
        req
    }

    /// Number of queued requests.
    pub(crate) fn len(&self) -> u16 {
        self.count
    }

    /// Whether the queue is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }
}
