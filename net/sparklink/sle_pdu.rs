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

use kernel::prelude::*;

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
        w |= (self.link_quality as u32) & 0xFF;
        w |= ((self.broadcast_type as u32) & 0x07) << 8;
        w |= ((self.packet_type as u32) & 0x07) << 11;
        // bits 14-19 reserved = 0
        w |= ((self.data_length as u32) & 0xFF) << 20;
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
// CRC-12 calculation
//
// Generator polynomial: g(D) = D^12+D^11+D^10+D^8+D^5+D^4+D^2+1
// Seed: lower 12 bits of the sync word
// Input bit order: LSB first
// ---------------------------------------------------------------------------

/// Compute CRC-12 over `data` with the given initial seed.
pub fn crc12(seed: u16, data: &[u8]) -> u16 {
    let mut crc = seed & 0x0FFF;
    for &byte in data {
        for i in 0..8 {
            let bit = ((byte >> i) & 1) as u16;
            let fb = (crc ^ bit) & 1;
            crc >>= 1;
            if fb != 0 {
                crc ^= CRC12_POLY;
            }
        }
    }
    crc & 0x0FFF
}

/// Default CRC-12 seed derived from the advertising sync word.
pub fn crc12_adv_seed() -> u16 {
    (SLE_SYNC_WORD_ADV & 0x0FFF) as u16
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
