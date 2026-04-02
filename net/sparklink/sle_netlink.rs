// SPDX-License-Identifier: GPL-2.0

//! SparkLink Generic Netlink protocol types.
//!
//! Defines the command and attribute enumerations for the SparkLink
//! Generic Netlink family ("sparklink"), mirroring the UAPI header
//! `include/uapi/linux/sparklink.h`.
//!
//! This module provides:
//!  - Command and attribute enumerations
//!  - Netlink attribute TLV builder/parser helpers
//!  - Attribute policy definitions for validation
//!
//! The actual genetlink family registration requires C genetlink
//! bindings (`genl_register_family`) which are not yet available in
//! the kernel Rust framework. A C shim or binding addition will be
//! needed to complete the integration.
//!
//! Multicast group "events" delivers async events to subscribed
//! userspace listeners via `SPARKLINK_CMD_EVENT` messages.

#![allow(dead_code, unreachable_pub)]

use kernel::alloc::KVec;
use kernel::prelude::*;

// ---------------------------------------------------------------------------
// Family identification
// ---------------------------------------------------------------------------

/// Generic Netlink family name.
pub const GENL_FAMILY_NAME: &[u8] = b"sparklink\0";
/// Generic Netlink family version.
pub const GENL_VERSION: u8 = 1;
/// Multicast group for event delivery.
pub const MCGRP_EVENTS: &[u8] = b"events\0";

// ---------------------------------------------------------------------------
// Commands (mirrors SPARKLINK_CMD_* in UAPI header)
// ---------------------------------------------------------------------------

/// SparkLink Generic Netlink commands.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NlCmd {
    Unspec = 0,
    GetDevInfo = 1,
    DevRegister = 2,
    DevUnregister = 3,
    StartAdv = 4,
    StopAdv = 5,
    StartScan = 6,
    StopScan = 7,
    InjectAdv = 8,
    Connect = 9,
    Disconnect = 10,
    GetConnInfo = 11,
    ConnSend = 12,
    ConnRecv = 13,
    GetConnList = 14,
    SetPsk = 15,
    Pair = 16,
    GetSecInfo = 17,
    EncryptOn = 18,
    SsapRegister = 19,
    GetSsapInfo = 20,
    SsapRead = 21,
    SsapWrite = 22,
    GetPmInfo = 23,
    SetPmState = 24,
    SetPmInterval = 25,
    Event = 26,
    GetDliInfo = 27,
}

impl NlCmd {
    /// Total number of defined commands (for policy array sizing).
    pub const COUNT: usize = 28;
}

// ---------------------------------------------------------------------------
// Attributes (mirrors SPARKLINK_ATTR_* in UAPI header)
// ---------------------------------------------------------------------------

/// SparkLink Generic Netlink attributes.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NlAttr {
    Unspec = 0,
    // Device
    DevIndex = 1,
    DevState = 2,
    DevName = 3,
    DevBus = 4,
    DevCount = 5,
    // Address
    Addr = 6,
    PeerAddr = 7,
    // Connection
    Handle = 8,
    ConnState = 9,
    GtRole = 10,
    Bandwidth = 11,
    McsIndex = 12,
    TxBytes = 13,
    RxBytes = 14,
    Timeout10ms = 15,
    // Adv/scan
    DiscoveryLevel = 16,
    IntervalMs = 17,
    WindowMs = 18,
    Rssi = 19,
    ScanResults = 20,
    // Data
    Data = 21,
    DataLen = 22,
    // Security
    Psk = 23,
    PairMethod = 24,
    SecState = 25,
    SecMode = 26,
    Encrypted = 27,
    KeyFingerprint = 28,
    // SSAP
    SvcCount = 29,
    PropCount = 30,
    PropHandle = 31,
    Mtu = 32,
    // Power
    PmState = 33,
    ForceActive = 34,
    PowerPct = 35,
    PmIntervalMin = 36,
    PmIntervalMax = 37,
    PmLatency = 38,
    // Events
    EventType = 39,
    EventPayload = 40,
    EventPending = 41,
    EventTotal = 42,
    EventDropped = 43,
    // DLI
    DliBus = 44,
    DliFwVer = 45,
    DliFeatures = 46,
    DliMaxConn = 47,
}

impl NlAttr {
    /// Total number of attribute types.
    pub const COUNT: usize = 48;
}

// ---------------------------------------------------------------------------
// Netlink attribute TLV builder
// ---------------------------------------------------------------------------

/// Netlink attribute TLV alignment (NLA_ALIGNTO = 4).
const NLA_ALIGNTO: usize = 4;

/// Align a length to NLA_ALIGNTO boundary.
const fn nla_align(len: usize) -> usize {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

/// Netlink attribute header size (type: u16 + len: u16 = 4).
const NLA_HDRLEN: usize = 4;

/// Builder for constructing netlink attribute TLV sequences.
///
/// Produces a byte buffer of NLA-formatted attributes suitable
/// for inclusion in a Generic Netlink message payload.
pub struct NlAttrBuilder {
    buf: KVec<u8>,
}

impl NlAttrBuilder {
    /// Create a new empty attribute builder.
    pub fn new() -> Self {
        Self { buf: KVec::new() }
    }

    /// Add a u8 attribute.
    pub fn put_u8(&mut self, attr: NlAttr, val: u8) -> Result {
        self.put_raw(attr, &[val])
    }

    /// Add a u16 attribute (little-endian).
    pub fn put_u16(&mut self, attr: NlAttr, val: u16) -> Result {
        self.put_raw(attr, &val.to_le_bytes())
    }

    /// Add a u32 attribute (little-endian).
    pub fn put_u32(&mut self, attr: NlAttr, val: u32) -> Result {
        self.put_raw(attr, &val.to_le_bytes())
    }

    /// Add a u64 attribute (little-endian).
    pub fn put_u64(&mut self, attr: NlAttr, val: u64) -> Result {
        self.put_raw(attr, &val.to_le_bytes())
    }

    /// Add a signed i8 attribute.
    pub fn put_s8(&mut self, attr: NlAttr, val: i8) -> Result {
        self.put_raw(attr, &[val as u8])
    }

    /// Add a binary attribute.
    pub fn put_binary(&mut self, attr: NlAttr, data: &[u8]) -> Result {
        self.put_raw(attr, data)
    }

    /// Add a NUL-terminated string attribute.
    pub fn put_string(&mut self, attr: NlAttr, s: &[u8]) -> Result {
        // Include NUL terminator
        let mut data = KVec::with_capacity(s.len() + 1, GFP_KERNEL)?;
        for &b in s {
            if b == 0 {
                break;
            }
            data.push(b, GFP_KERNEL)?;
        }
        data.push(0, GFP_KERNEL)?;
        self.put_raw(attr, &data)
    }

    /// Return the built attribute buffer.
    pub fn finish(self) -> KVec<u8> {
        self.buf
    }

    /// Total byte length of the built attributes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    fn put_raw(&mut self, attr: NlAttr, payload: &[u8]) -> Result {
        let nla_len = NLA_HDRLEN + payload.len();
        let padded = nla_align(nla_len);

        // Attribute header: [len:u16-LE] [type:u16-LE]
        let len_bytes = (nla_len as u16).to_le_bytes();
        let type_bytes = (attr as u16).to_le_bytes();
        self.buf.push(len_bytes[0], GFP_KERNEL)?;
        self.buf.push(len_bytes[1], GFP_KERNEL)?;
        self.buf.push(type_bytes[0], GFP_KERNEL)?;
        self.buf.push(type_bytes[1], GFP_KERNEL)?;

        // Payload
        for &b in payload {
            self.buf.push(b, GFP_KERNEL)?;
        }

        // Padding
        let pad = padded - nla_len;
        for _ in 0..pad {
            self.buf.push(0, GFP_KERNEL)?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Netlink attribute TLV parser
// ---------------------------------------------------------------------------

/// A parsed netlink attribute.
pub struct ParsedAttr<'a> {
    /// Attribute type.
    pub attr_type: u16,
    /// Payload bytes (without header or padding).
    pub payload: &'a [u8],
}

/// Iterate over netlink attributes in a buffer.
///
/// The buffer should contain a sequence of NLA-formatted attributes
/// (typically from a Generic Netlink message payload).
pub fn parse_attrs(buf: &[u8]) -> NlAttrIter<'_> {
    NlAttrIter { buf, offset: 0 }
}

/// Iterator over netlink attributes in a byte buffer.
pub struct NlAttrIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for NlAttrIter<'a> {
    type Item = ParsedAttr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + NLA_HDRLEN > self.buf.len() {
            return None;
        }

        let nla_len =
            u16::from_le_bytes([self.buf[self.offset], self.buf[self.offset + 1]]) as usize;
        let nla_type = u16::from_le_bytes([self.buf[self.offset + 2], self.buf[self.offset + 3]]);

        if nla_len < NLA_HDRLEN || self.offset + nla_len > self.buf.len() {
            return None;
        }

        let payload_start = self.offset + NLA_HDRLEN;
        let payload_end = self.offset + nla_len;
        let payload = &self.buf[payload_start..payload_end];

        // Advance past padded attribute
        self.offset += nla_align(nla_len);

        Some(ParsedAttr {
            attr_type: nla_type,
            payload,
        })
    }
}

/// Extract a u8 from an attribute payload.
pub fn attr_get_u8(attr: &ParsedAttr<'_>) -> Option<u8> {
    attr.payload.first().copied()
}

/// Extract a u16 (LE) from an attribute payload.
pub fn attr_get_u16(attr: &ParsedAttr<'_>) -> Option<u16> {
    if attr.payload.len() >= 2 {
        Some(u16::from_le_bytes([attr.payload[0], attr.payload[1]]))
    } else {
        None
    }
}

/// Extract a u32 (LE) from an attribute payload.
pub fn attr_get_u32(attr: &ParsedAttr<'_>) -> Option<u32> {
    if attr.payload.len() >= 4 {
        Some(u32::from_le_bytes([
            attr.payload[0],
            attr.payload[1],
            attr.payload[2],
            attr.payload[3],
        ]))
    } else {
        None
    }
}

/// Extract a u64 (LE) from an attribute payload.
pub fn attr_get_u64(attr: &ParsedAttr<'_>) -> Option<u64> {
    if attr.payload.len() >= 8 {
        Some(u64::from_le_bytes([
            attr.payload[0],
            attr.payload[1],
            attr.payload[2],
            attr.payload[3],
            attr.payload[4],
            attr.payload[5],
            attr.payload[6],
            attr.payload[7],
        ]))
    } else {
        None
    }
}
