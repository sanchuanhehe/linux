// SPDX-License-Identifier: GPL-2.0

//! SLE PDU frame definitions and codec.
//!
//! Implements the SparkLink Low Energy (SLE) protocol data unit structures
//! as defined in T/XS 10002-2025. This module handles the logical PDU layer
//! above the PHY — it does not deal with modulation, synchronization word
//! generation, or radio-level encoding.
//!
//! The advertising channel uses Frame Type 1 (GFSK) with a 32-bit control
//! header and variable-length TLV advertising data.

#![allow(dead_code, unreachable_pub)]

use core::sync::atomic::{AtomicU32, Ordering};
use kernel::prelude::*;

// ---------------------------------------------------------------------------
// CRC error counter
// ---------------------------------------------------------------------------

/// Global counter for CRC-12 verification failures.
static CRC_ERRORS: AtomicU32 = AtomicU32::new(0);

/// Return the current CRC error count.
pub fn crc_error_count() -> u32 {
    CRC_ERRORS.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Frame Type 1 sync word (for advertising channel).
pub const SLE_SYNC_WORD_ADV: u32 = 0x5A2B_DA62;

/// CRC-12 generator polynomial: D^12 + D^11 + D^10 + D^8 + D^5 + D^4 + D^2 + 1.
const CRC12_POLY: u16 = 0x0D25;

/// Maximum advertising PDU data payload (bytes).
pub const SLE_ADV_DATA_MAX: usize = 255;

// ---------------------------------------------------------------------------
// Broadcast type (3 bits in PHY control info)
// ---------------------------------------------------------------------------

/// Broadcast access/scan mode of the advertising PDU.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum BroadcastType {
    /// Not accessible, not scannable.
    #[default]
    NoAccessNoScan = 0,
    /// Accessible, not scannable.
    AccessibleNoScan = 1,
    /// Not accessible, scannable.
    NoAccessScannable = 2,
    /// Accessible and scannable.
    AccessibleScannable = 3,
}

impl BroadcastType {
    /// Decode from 3-bit field. Returns `None` for reserved values.
    pub fn from_raw(v: u8) -> Option<Self> {
        match v & 0x07 {
            0 => Some(Self::NoAccessNoScan),
            1 => Some(Self::AccessibleNoScan),
            2 => Some(Self::NoAccessScannable),
            3 => Some(Self::AccessibleScannable),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Packet type (3 bits in PHY control info)
// ---------------------------------------------------------------------------

/// PDU packet type on the advertising channel.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum PacketType {
    /// Basic advertising PDU.
    #[default]
    BasicAdv = 0,
    /// Extended advertising PDU.
    ExtendedAdv = 1,
    /// Active scan request.
    ScanRequest = 2,
    /// Active scan response.
    ScanResponse = 3,
    /// Connection/access request.
    AccessRequest = 4,
    /// Connection/access response.
    AccessResponse = 5,
}

impl PacketType {
    /// Decode from 3-bit field. Returns `None` for reserved values.
    pub fn from_raw(v: u8) -> Option<Self> {
        match v & 0x07 {
            0 => Some(Self::BasicAdv),
            1 => Some(Self::ExtendedAdv),
            2 => Some(Self::ScanRequest),
            3 => Some(Self::ScanResponse),
            4 => Some(Self::AccessRequest),
            5 => Some(Self::AccessResponse),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// PHY control header for advertising channel (Frame Type 1)
//
// Layout (32 bits, MSB-first wire order):
//   [7:0]   link_quality
//   [10:8]  broadcast_type
//   [13:11] packet_type
//   [19:14] reserved
//   [27:20] data_length (bytes)
//   [31:28] CRC-12 high nibble  ← actually CRC is bits [31:20]
//
// The standard defines:
//   bits 0-7:   link quality indicator
//   bits 8-10:  broadcast type (3 bits)
//   bits 11-13: packet type (3 bits)
//   bits 14-19: reserved (6 bits)
//   bits 20-27: data length in bytes (8 bits, max 255)
//   bits 28-39: CRC-12 (12 bits, but within the 32-bit control word
//               the top 12 bits [31:20] are protected — see standard)
//
// For the software PDU representation we store the logical fields and
// compute/verify CRC separately.
// ---------------------------------------------------------------------------

/// Advertising channel PHY control header (logical representation).
#[derive(Copy, Clone, Debug, Default)]
pub struct AdvPduHeader {
    /// Link quality indicator (0-255).
    pub link_quality: u8,
    /// Broadcast type.
    pub broadcast_type: BroadcastType,
    /// Packet type.
    pub packet_type: PacketType,
    /// Payload data length in bytes.
    pub data_length: u8,
}

impl AdvPduHeader {
    /// Encode the header into a 4-byte wire-format buffer (without CRC-12).
    /// The caller must append CRC-12 over the first 20 bits if needed.
    pub fn encode(&self) -> [u8; 4] {
        let mut w: u32 = 0;
        w |= u32::from(self.link_quality) & 0xFF;
        w |= (self.broadcast_type as u32 & 0x07) << 8;
        w |= (self.packet_type as u32 & 0x07) << 11;
        // bits 14-19 reserved = 0
        w |= (u32::from(self.data_length) & 0xFF) << 20;
        // bits 28-31 will be filled by CRC-12 (only top 4 bits fit here)
        w.to_le_bytes()
    }

    /// Decode a 4-byte wire-format header. Does NOT verify CRC-12.
    pub fn decode(buf: &[u8; 4]) -> Option<Self> {
        let w = u32::from_le_bytes(*buf);
        let lq = (w & 0xFF) as u8;
        let bt = BroadcastType::from_raw(((w >> 8) & 0x07) as u8)?;
        let pt = PacketType::from_raw(((w >> 11) & 0x07) as u8)?;
        let dl = ((w >> 20) & 0xFF) as u8;
        Some(Self {
            link_quality: lq,
            broadcast_type: bt,
            packet_type: pt,
            data_length: dl,
        })
    }
}

// ---------------------------------------------------------------------------
// Advertising data TLV (Type-Length-Value)
//
// Each element:
//   [0]   type   (1 byte)
//   [1]   length (1 byte, length of value field only)
//   [2..] value  (variable)
// ---------------------------------------------------------------------------

/// Well-known advertising data type codes (T/XS 20001-2025).
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AdvDataType {
    /// Discovery level (1 byte, bits 0-2).
    DiscoveryLevel = 0x01,
    /// SLE access layer capability.
    AccessCapability = 0x02,
    /// Standard service data (16-bit UUID + data).
    StdServiceData = 0x03,
    /// Custom service data (128-bit UUID + data).
    CustomServiceData = 0x04,
    /// Complete standard service list.
    FullStdServiceList = 0x05,
    /// Complete custom service list.
    FullCustomServiceList = 0x06,
    /// Partial standard service list.
    PartialStdServiceList = 0x07,
    /// Partial custom service list.
    PartialCustomServiceList = 0x08,
    /// Service structure hash (16 bytes SHA-256 truncated).
    ServiceHash = 0x09,
    /// Shortened local name (UTF-8).
    ShortName = 0x0A,
    /// Complete local name (UTF-8).
    CompleteName = 0x0B,
    /// TX power level (1 byte, -127..127 dBm).
    TxPower = 0x0C,
    /// SLB communication domain name (1-128 bytes).
    SlbDomainName = 0x0D,
    /// SLB MAC address (6 bytes).
    SlbMacAddr = 0x0E,
    /// SLE MAC address (6 bytes).
    SleMacAddr = 0x0F,
    /// Multi-hop networking info.
    MultiHop = 0x10,
    /// Manufacturer-specific data (2-byte vendor ID + data).
    ManufacturerSpecific = 0xFF,
}

impl AdvDataType {
    /// Convert from raw byte.
    pub fn from_raw(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::DiscoveryLevel),
            0x02 => Some(Self::AccessCapability),
            0x03 => Some(Self::StdServiceData),
            0x04 => Some(Self::CustomServiceData),
            0x05 => Some(Self::FullStdServiceList),
            0x06 => Some(Self::FullCustomServiceList),
            0x07 => Some(Self::PartialStdServiceList),
            0x08 => Some(Self::PartialCustomServiceList),
            0x09 => Some(Self::ServiceHash),
            0x0A => Some(Self::ShortName),
            0x0B => Some(Self::CompleteName),
            0x0C => Some(Self::TxPower),
            0x0D => Some(Self::SlbDomainName),
            0x0E => Some(Self::SlbMacAddr),
            0x0F => Some(Self::SleMacAddr),
            0x10 => Some(Self::MultiHop),
            0xFF => Some(Self::ManufacturerSpecific),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Advertising data builder — accumulates TLV entries into a flat buffer
// ---------------------------------------------------------------------------

/// Builder for advertising data payload (sequence of TLV entries).
///
/// Backed by a fixed-size buffer; no heap allocation required.
pub struct AdvDataBuilder {
    buf: [u8; SLE_ADV_DATA_MAX],
    len: usize,
}

impl AdvDataBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self {
            buf: [0u8; SLE_ADV_DATA_MAX],
            len: 0,
        }
    }

    /// Remaining capacity in bytes.
    pub fn remaining(&self) -> usize {
        SLE_ADV_DATA_MAX - self.len
    }

    /// Current payload length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Append a raw TLV entry. Returns `ENOMEM` if the buffer is full.
    pub fn push_tlv(&mut self, typ: u8, value: &[u8]) -> Result {
        let entry_len = 2 + value.len(); // type(1) + length(1) + value
        if entry_len > self.remaining() {
            return Err(ENOMEM);
        }
        self.buf[self.len] = typ;
        self.buf[self.len + 1] = value.len() as u8;
        self.buf[self.len + 2..self.len + 2 + value.len()].copy_from_slice(value);
        self.len += entry_len;
        Ok(())
    }

    /// Append a discovery level TLV.
    pub fn push_discovery_level(&mut self, level: u8) -> Result {
        self.push_tlv(AdvDataType::DiscoveryLevel as u8, &[level & 0x07])
    }

    /// Append a complete local name TLV.
    pub fn push_complete_name(&mut self, name: &[u8]) -> Result {
        self.push_tlv(AdvDataType::CompleteName as u8, name)
    }

    /// Append a shortened local name TLV.
    pub fn push_short_name(&mut self, name: &[u8]) -> Result {
        self.push_tlv(AdvDataType::ShortName as u8, name)
    }

    /// Append a TX power level TLV.
    pub fn push_tx_power(&mut self, dbm: i8) -> Result {
        self.push_tlv(AdvDataType::TxPower as u8, &[dbm as u8])
    }

    /// Append an SLE MAC address TLV.
    pub fn push_sle_addr(&mut self, addr: &[u8; 6]) -> Result {
        self.push_tlv(AdvDataType::SleMacAddr as u8, addr)
    }

    /// Append a complete standard service list TLV (type 0x05).
    ///
    /// Each UUID is encoded as 2 bytes little-endian per T/XS 20001-2025 §6.3.
    pub fn push_std_service_list(&mut self, uuids: &[u16]) -> Result {
        if uuids.is_empty() {
            return Ok(());
        }
        let value_len = uuids.len() * 2;
        let entry_len = 2 + value_len;
        if entry_len > self.remaining() {
            return Err(ENOMEM);
        }
        self.buf[self.len] = AdvDataType::FullStdServiceList as u8;
        self.buf[self.len + 1] = value_len as u8;
        let mut offset = self.len + 2;
        for &uuid in uuids {
            let le = uuid.to_le_bytes();
            self.buf[offset] = le[0];
            self.buf[offset + 1] = le[1];
            offset += 2;
        }
        self.len += entry_len;
        Ok(())
    }

    /// Append a complete custom (128-bit) service list TLV (type 0x06).
    pub fn push_custom_service_list(&mut self, uuids: &[[u8; 16]]) -> Result {
        if uuids.is_empty() {
            return Ok(());
        }
        let value_len = uuids.len() * 16;
        let entry_len = 2 + value_len;
        if entry_len > self.remaining() {
            return Err(ENOMEM);
        }
        self.buf[self.len] = AdvDataType::FullCustomServiceList as u8;
        self.buf[self.len + 1] = value_len as u8;
        let mut offset = self.len + 2;
        for uuid in uuids {
            self.buf[offset..offset + 16].copy_from_slice(uuid);
            offset += 16;
        }
        self.len += entry_len;
        Ok(())
    }

    /// Append a standard service data TLV (type 0x03): 16-bit UUID + data.
    pub fn push_std_service_data(&mut self, uuid: u16, data: &[u8]) -> Result {
        let value_len = 2 + data.len();
        let entry_len = 2 + value_len;
        if entry_len > self.remaining() {
            return Err(ENOMEM);
        }
        self.buf[self.len] = AdvDataType::StdServiceData as u8;
        self.buf[self.len + 1] = value_len as u8;
        let le = uuid.to_le_bytes();
        self.buf[self.len + 2] = le[0];
        self.buf[self.len + 3] = le[1];
        if !data.is_empty() {
            self.buf[self.len + 4..self.len + 4 + data.len()].copy_from_slice(data);
        }
        self.len += entry_len;
        Ok(())
    }

    /// Append a service structure hash TLV (type 0x09, 16 bytes).
    pub fn push_service_hash(&mut self, hash: &[u8; 16]) -> Result {
        self.push_tlv(AdvDataType::ServiceHash as u8, hash)
    }

    /// Append an access capability TLV (type 0x02, 1 byte).
    pub fn push_access_capability(&mut self, cap: u8) -> Result {
        self.push_tlv(AdvDataType::AccessCapability as u8, &[cap])
    }

    /// Append a manufacturer-specific data TLV (type 0xFF): 2-byte vendor ID + data.
    pub fn push_manufacturer_specific(&mut self, vendor_id: u16, data: &[u8]) -> Result {
        let value_len = 2 + data.len();
        let entry_len = 2 + value_len;
        if entry_len > self.remaining() {
            return Err(ENOMEM);
        }
        self.buf[self.len] = AdvDataType::ManufacturerSpecific as u8;
        self.buf[self.len + 1] = value_len as u8;
        let le = vendor_id.to_le_bytes();
        self.buf[self.len + 2] = le[0];
        self.buf[self.len + 3] = le[1];
        if !data.is_empty() {
            self.buf[self.len + 4..self.len + 4 + data.len()].copy_from_slice(data);
        }
        self.len += entry_len;
        Ok(())
    }

    /// Append raw bytes directly to the payload (not TLV-wrapped).
    pub fn push_raw(&mut self, data: &[u8]) -> Result {
        if data.len() > self.remaining() {
            return Err(ENOMEM);
        }
        self.buf[self.len..self.len + data.len()].copy_from_slice(data);
        self.len += data.len();
        Ok(())
    }

    /// Get a reference to the built payload.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

// ---------------------------------------------------------------------------
// Advertising data parser — iterates over TLV entries in a byte slice
// ---------------------------------------------------------------------------

/// A single parsed TLV entry (borrowed from the underlying buffer).
#[derive(Copy, Clone)]
pub struct AdvDataEntry<'a> {
    /// Type code.
    pub typ: u8,
    /// Value bytes (not including type and length fields).
    pub value: &'a [u8],
}

/// Iterator over TLV entries in an advertising data payload.
pub struct AdvDataIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> AdvDataIter<'a> {
    /// Create a new iterator over the given advertising data bytes.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> Iterator for AdvDataIter<'a> {
    type Item = AdvDataEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 2 > self.data.len() {
            return None;
        }
        let typ = self.data[self.pos];
        let vlen = self.data[self.pos + 1] as usize;
        let vstart = self.pos + 2;
        let vend = vstart + vlen;
        if vend > self.data.len() {
            return None;
        }
        let entry = AdvDataEntry {
            typ,
            value: &self.data[vstart..vend],
        };
        self.pos = vend;
        Some(entry)
    }
}

// ---------------------------------------------------------------------------
// CRC-12 calculation (table-driven)
//
// Generator polynomial: g(D) = D^12+D^11+D^10+D^8+D^5+D^4+D^2+1
// Seed: lower 12 bits of the sync word
// Input bit order: LSB first
//
// Uses 256-entry lookup table (512 bytes) to process one byte per
// iteration instead of 8 bit operations.
// ---------------------------------------------------------------------------

/// CRC-12 lookup table for polynomial 0x0D25, LSB-first processing.
/// table[i] = CRC-12 of single byte i with seed 0.
#[rustfmt::skip]
const CRC12_TABLE: [u16; 256] = [
    0x000, 0xA54, 0xEE3, 0x4B7, 0x78D, 0xDD9, 0x96E, 0x33A,
    0xF1A, 0x54E, 0x1F9, 0xBAD, 0x897, 0x2C3, 0x674, 0xC20,
    0x47F, 0xE2B, 0xA9C, 0x0C8, 0x3F2, 0x9A6, 0xD11, 0x745,
    0xB65, 0x131, 0x586, 0xFD2, 0xCE8, 0x6BC, 0x20B, 0x85F,
    0x8FE, 0x2AA, 0x61D, 0xC49, 0xF73, 0x527, 0x190, 0xBC4,
    0x7E4, 0xDB0, 0x907, 0x353, 0x069, 0xA3D, 0xE8A, 0x4DE,
    0xC81, 0x6D5, 0x262, 0x836, 0xB0C, 0x158, 0x5EF, 0xFBB,
    0x39B, 0x9CF, 0xD78, 0x72C, 0x416, 0xE42, 0xAF5, 0x0A1,
    0xBB7, 0x1E3, 0x554, 0xF00, 0xC3A, 0x66E, 0x2D9, 0x88D,
    0x4AD, 0xEF9, 0xA4E, 0x01A, 0x320, 0x974, 0xDC3, 0x797,
    0xFC8, 0x59C, 0x12B, 0xB7F, 0x845, 0x211, 0x6A6, 0xCF2,
    0x0D2, 0xA86, 0xE31, 0x465, 0x75F, 0xD0B, 0x9BC, 0x3E8,
    0x349, 0x91D, 0xDAA, 0x7FE, 0x4C4, 0xE90, 0xA27, 0x073,
    0xC53, 0x607, 0x2B0, 0x8E4, 0xBDE, 0x18A, 0x53D, 0xF69,
    0x736, 0xD62, 0x9D5, 0x381, 0x0BB, 0xAEF, 0xE58, 0x40C,
    0x82C, 0x278, 0x6CF, 0xC9B, 0xFA1, 0x5F5, 0x142, 0xB16,
    0xD25, 0x771, 0x3C6, 0x992, 0xAA8, 0x0FC, 0x44B, 0xE1F,
    0x23F, 0x86B, 0xCDC, 0x688, 0x5B2, 0xFE6, 0xB51, 0x105,
    0x95A, 0x30E, 0x7B9, 0xDED, 0xED7, 0x483, 0x034, 0xA60,
    0x640, 0xC14, 0x8A3, 0x2F7, 0x1CD, 0xB99, 0xF2E, 0x57A,
    0x5DB, 0xF8F, 0xB38, 0x16C, 0x256, 0x802, 0xCB5, 0x6E1,
    0xAC1, 0x095, 0x422, 0xE76, 0xD4C, 0x718, 0x3AF, 0x9FB,
    0x1A4, 0xBF0, 0xF47, 0x513, 0x629, 0xC7D, 0x8CA, 0x29E,
    0xEBE, 0x4EA, 0x05D, 0xA09, 0x933, 0x367, 0x7D0, 0xD84,
    0x692, 0xCC6, 0x871, 0x225, 0x11F, 0xB4B, 0xFFC, 0x5A8,
    0x988, 0x3DC, 0x76B, 0xD3F, 0xE05, 0x451, 0x0E6, 0xAB2,
    0x2ED, 0x8B9, 0xC0E, 0x65A, 0x560, 0xF34, 0xB83, 0x1D7,
    0xDF7, 0x7A3, 0x314, 0x940, 0xA7A, 0x02E, 0x499, 0xECD,
    0xE6C, 0x438, 0x08F, 0xADB, 0x9E1, 0x3B5, 0x702, 0xD56,
    0x176, 0xB22, 0xF95, 0x5C1, 0x6FB, 0xCAF, 0x818, 0x24C,
    0xA13, 0x047, 0x4F0, 0xEA4, 0xD9E, 0x7CA, 0x37D, 0x929,
    0x509, 0xF5D, 0xBEA, 0x1BE, 0x284, 0x8D0, 0xC67, 0x633,
];

/// Compute CRC-12 over `data` with the given initial seed.
///
/// Table-driven: processes one byte per iteration (vs 8 bit ops
/// per byte in the naive approach).
#[inline]
pub fn crc12(seed: u16, data: &[u8]) -> u16 {
    let mut crc = seed & 0x0FFF;
    for &byte in data {
        let idx = ((crc as u8) ^ byte) as usize;
        crc = (crc >> 8) ^ CRC12_TABLE[idx];
    }
    crc & 0x0FFF
}

/// Default CRC-12 seed derived from the advertising sync word.
pub fn crc12_adv_seed() -> u16 {
    (SLE_SYNC_WORD_ADV & 0x0FFF) as u16
}

// ---------------------------------------------------------------------------
// CRC-16 for transport layer data frames (TXS-20002-2025 section 3.6)
//
// Polynomial: G(x) = x^16 + x^15 + x^2 + 1  (0x8005, reflected 0xA001)
// Default seed: 0x5555 (negotiable per standard)
// Scope: entire packet (header + payload)
// ---------------------------------------------------------------------------

/// CRC-16 lookup table for polynomial 0x8005, LSB-first processing.
#[rustfmt::skip]
const CRC16_TABLE: [u16; 256] = [
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
];

/// Default CRC-16 seed for transport layer data frames.
pub const CRC16_DEFAULT_SEED: u16 = 0x5555;

/// Compute CRC-16 over `data` with the given initial seed.
///
/// Uses polynomial 0x8005 (G(x) = x^16 + x^15 + x^2 + 1) in reflected
/// (LSB-first) form. Table-driven: one byte per iteration.
#[inline]
pub fn crc16(seed: u16, data: &[u8]) -> u16 {
    let mut crc = seed;
    for &byte in data {
        let idx = ((crc as u8) ^ byte) as usize;
        crc = (crc >> 8) ^ CRC16_TABLE[idx];
    }
    crc
}

/// Verify CRC-16 of a packet: header+payload followed by 2-byte CRC (LE).
///
/// Returns `true` if the CRC matches.
#[inline]
pub fn crc16_verify(seed: u16, packet: &[u8]) -> bool {
    if packet.len() < 2 {
        return false;
    }
    let data_len = packet.len() - 2;
    let computed = crc16(seed, &packet[..data_len]);
    let stored = u16::from_le_bytes([packet[data_len], packet[data_len + 1]]);
    computed == stored
}

/// Append CRC-16 (LE) to a mutable buffer at `data_len` offset.
///
/// The caller must ensure `buf.len() >= data_len + 2`.
#[inline]
pub fn crc16_append(seed: u16, buf: &mut [u8], data_len: usize) {
    let crc = crc16(seed, &buf[..data_len]);
    let bytes = crc.to_le_bytes();
    buf[data_len] = bytes[0];
    buf[data_len + 1] = bytes[1];
}

// ---------------------------------------------------------------------------
// Full advertising PDU (header + data payload + CRC)
// ---------------------------------------------------------------------------

/// A complete advertising channel PDU ready for transmission.
///
/// This is the logical representation; the PHY layer wraps it with
/// preamble and synchronization word before over-the-air transmission.
pub struct AdvPdu {
    /// PDU header.
    pub header: AdvPduHeader,
    /// TLV advertising data payload.
    pub data: [u8; SLE_ADV_DATA_MAX],
    /// Actual number of valid bytes in `data`.
    pub data_len: usize,
    /// CRC-12 computed over the data payload.
    pub crc: u16,
}

impl AdvPdu {
    /// Build an advertising PDU from header fields and a data builder.
    pub fn build(
        broadcast_type: BroadcastType,
        packet_type: PacketType,
        link_quality: u8,
        adv_data: &AdvDataBuilder,
    ) -> Self {
        let header = AdvPduHeader {
            link_quality,
            broadcast_type,
            packet_type,
            data_length: adv_data.len() as u8,
        };
        let mut data = [0u8; SLE_ADV_DATA_MAX];
        data[..adv_data.len()].copy_from_slice(adv_data.as_bytes());
        let crc = crc12(crc12_adv_seed(), &data[..adv_data.len()]);
        Self {
            header,
            data,
            data_len: adv_data.len(),
            crc,
        }
    }

    /// Serialize the PDU into a byte buffer.
    /// Returns the number of bytes written, or `ENOMEM` if the buffer
    /// is too small.
    ///
    /// Wire format: [header 4 bytes] [data N bytes] [CRC-12 2 bytes]
    pub fn serialize(&self, out: &mut [u8]) -> Result<usize> {
        let total = 4 + self.data_len + 2;
        if out.len() < total {
            return Err(ENOMEM);
        }
        let hdr_bytes = self.header.encode();
        out[..4].copy_from_slice(&hdr_bytes);
        out[4..4 + self.data_len].copy_from_slice(&self.data[..self.data_len]);
        let crc_bytes = self.crc.to_le_bytes();
        out[4 + self.data_len] = crc_bytes[0];
        out[4 + self.data_len + 1] = crc_bytes[1];
        Ok(total)
    }

    /// Deserialize a PDU from a byte buffer.
    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 6 {
            // minimum: 4 header + 0 data + 2 CRC
            return None;
        }
        let hdr_bytes: [u8; 4] = buf[..4].try_into().ok()?;
        let header = AdvPduHeader::decode(&hdr_bytes)?;
        let data_len = header.data_length as usize;
        if buf.len() < 4 + data_len + 2 {
            return None;
        }
        let mut data = [0u8; SLE_ADV_DATA_MAX];
        data[..data_len].copy_from_slice(&buf[4..4 + data_len]);
        let crc = u16::from_le_bytes([buf[4 + data_len], buf[4 + data_len + 1]]);
        // Verify CRC
        let expected = crc12(crc12_adv_seed(), &data[..data_len]);
        if crc != expected {
            CRC_ERRORS.fetch_add(1, Ordering::Relaxed);
            pr_debug!(
                "sparklink: adv PDU CRC-12 mismatch: received {:#05x}, expected {:#05x} (len={})\n",
                crc,
                expected,
                data_len
            );
            return None;
        }
        Some(Self {
            header,
            data,
            data_len,
            crc,
        })
    }

    /// Iterate over TLV entries in the data payload.
    pub fn iter_adv_data(&self) -> AdvDataIter<'_> {
        AdvDataIter::new(&self.data[..self.data_len])
    }
}

// ---------------------------------------------------------------------------
// Transport layer frame format (TXS-20002-2025 section 3.3)
//
// Basic frame:
//   TCID(8) | FrameType(4)=0000 | O(1)=0 | C(1) | RFU(2)
//   | Length(16 LE) | PI(8) | Data(N) | [CRC-16(2) if C=1]
//
// Enhanced frame (reliable/flow):
//   TCID(8) | FrameType(4)!=0000 | O(1) | C(1)=1 | P(1) | RFU(1)
//   | Length(16 LE) | PI(8) | TxSeq(14) | RFU(2) | Data(N) | CRC-16(2)
// ---------------------------------------------------------------------------

/// Transport frame types defined by TXS-20002-2025.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TransportFrameType {
    /// Basic frame — no sequence, optional CRC.
    Basic = 0x00,
    /// Aggregated frame.
    Aggregated = 0x01,
    /// Segmented frame.
    Segmented = 0x02,
    /// Bidirectional frame (type 3).
    Bidi3 = 0x03,
    /// Bidirectional frame (type 4).
    Bidi4 = 0x04,
    /// ACK / supervisory frame.
    Ack = 0x05,
}

/// Header of a parsed transport frame.
#[derive(Copy, Clone, Debug)]
pub struct TransportHeader {
    /// Transport Channel ID.
    pub tcid: u8,
    /// Frame type.
    pub frame_type: u8,
    /// Outgoing indicator (O bit).
    pub outgoing: bool,
    /// Checksum present (C bit).
    pub checksum: bool,
    /// Poll/priority (P bit, enhanced only).
    pub poll: bool,
    /// Payload length (from the Length field).
    pub length: u16,
    /// Protocol information byte.
    pub pi: u8,
    /// TX sequence number (14-bit, enhanced frames only; 0 for basic).
    pub tx_seq: u16,
    /// Request sequence / ACK number (14-bit, ACK frames only; 0 otherwise).
    pub req_seq: u16,
}

/// Minimum header size for a basic frame (TCID + flags + length + PI).
pub const TRANSPORT_BASIC_HDR_LEN: usize = 5;
/// Additional bytes for enhanced frame header (TxSeq field).
pub const TRANSPORT_ENH_HDR_EXTRA: usize = 2;
/// Total enhanced frame header length.
pub const TRANSPORT_ENH_HDR_LEN: usize = TRANSPORT_BASIC_HDR_LEN + TRANSPORT_ENH_HDR_EXTRA;
/// CRC-16 trailer size.
pub const TRANSPORT_CRC_LEN: usize = 2;

/// Encode a basic-mode transport frame header into `buf`.
///
/// Returns the number of header bytes written (5).
/// Caller appends data after the header, then optionally CRC-16.
#[allow(dead_code)]
pub fn encode_basic_header(buf: &mut [u8], tcid: u8, pi: u8, data_len: u16, crc: bool) -> usize {
    // Byte 0: TCID
    buf[0] = tcid;
    // Byte 1: FrameType(4)=0000 | O(1)=0 | C(1) | RFU(2)=00
    buf[1] = if crc { 0x04 } else { 0x00 }; // C bit at position 2
    // Bytes 2-3: Length (LE16)
    let len_bytes = data_len.to_le_bytes();
    buf[2] = len_bytes[0];
    buf[3] = len_bytes[1];
    // Byte 4: PI
    buf[4] = pi;
    TRANSPORT_BASIC_HDR_LEN
}

/// Encode an enhanced-mode transport frame header into `buf`.
///
/// Returns the number of header bytes written (7).
#[allow(dead_code)]
pub fn encode_enhanced_header(
    buf: &mut [u8],
    tcid: u8,
    frame_type: u8,
    pi: u8,
    tx_seq: u16,
    data_len: u16,
    poll: bool,
) -> usize {
    // Byte 0: TCID
    buf[0] = tcid;
    // Byte 1: FrameType(4) | O(1)=0 | C(1)=1 | P(1) | RFU(1)=0
    let ft = (frame_type & 0x0F) << 4;
    let c_bit = 0x04; // C=1 always for enhanced
    let p_bit = if poll { 0x02 } else { 0x00 };
    buf[1] = ft | c_bit | p_bit;
    // Bytes 2-3: Length (LE16)
    let len_bytes = data_len.to_le_bytes();
    buf[2] = len_bytes[0];
    buf[3] = len_bytes[1];
    // Byte 4: PI
    buf[4] = pi;
    // Bytes 5-6: TxSeq(14) | RFU(2)=00, LE16
    let seq_field = (tx_seq & 0x3FFF).to_le_bytes();
    buf[5] = seq_field[0];
    buf[6] = seq_field[1];
    TRANSPORT_ENH_HDR_LEN
}

/// Parse a transport frame header from raw bytes.
///
/// Returns `None` if the buffer is too short for the detected frame type.
#[allow(dead_code)]
pub fn parse_transport_header(data: &[u8]) -> Option<TransportHeader> {
    if data.len() < TRANSPORT_BASIC_HDR_LEN {
        return None;
    }
    let tcid = data[0];
    let flags = data[1];
    let frame_type = (flags >> 4) & 0x0F;
    let outgoing = (flags & 0x08) != 0;
    let checksum = (flags & 0x04) != 0;
    let poll = (flags & 0x02) != 0;
    let length = u16::from_le_bytes([data[2], data[3]]);
    let pi = data[4];

    let (tx_seq, req_seq) = if frame_type != 0 {
        // Enhanced frame — need 2 more bytes for TxSeq.
        if data.len() < TRANSPORT_ENH_HDR_LEN {
            return None;
        }
        let raw_seq = u16::from_le_bytes([data[5], data[6]]);
        (raw_seq & 0x3FFF, 0u16)
    } else {
        (0, 0)
    };

    Some(TransportHeader {
        tcid,
        frame_type,
        outgoing,
        checksum,
        poll,
        length,
        pi,
        tx_seq,
        req_seq,
    })
}
