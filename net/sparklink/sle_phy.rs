// SPDX-License-Identifier: GPL-2.0

//! SLE PHY layer parameters and algorithms.
//!
//! Implements the physical layer characteristics defined in
//! T/XS 10002-2025 including MCS (modulation and coding scheme)
//! parameter tables, frequency hopping sequence generation, and
//! MIMO antenna configuration.

#![allow(dead_code, unreachable_pub)]

use kernel::prelude::*;

// =========================================================================
// MCS definitions (T/XS 10002-2025 table 11)
//
// SLE defines 13 MCS indices (0-12) covering modulation types from
// BPSK to 256QAM, paired with forward error correction (FEC) code
// rates from 1/4 to 5/6.
// =========================================================================

/// Modulation type used by a given MCS index.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Modulation {
    Bpsk   = 0,
    Qpsk   = 1,
    Qam16  = 2,
    Qam64  = 3,
    Qam256 = 4,
}

impl Modulation {
    /// Number of bits per symbol for this modulation type.
    pub const fn bits_per_symbol(self) -> u8 {
        match self {
            Self::Bpsk   => 1,
            Self::Qpsk   => 2,
            Self::Qam16  => 4,
            Self::Qam64  => 6,
            Self::Qam256 => 8,
        }
    }

    /// Decode from raw byte.
    pub fn from_raw(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Bpsk),
            1 => Some(Self::Qpsk),
            2 => Some(Self::Qam16),
            3 => Some(Self::Qam64),
            4 => Some(Self::Qam256),
            _ => None,
        }
    }
}

/// FEC code rate as a fraction (numerator, denominator).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CodeRate {
    pub num: u8,
    pub den: u8,
}

impl CodeRate {
    const fn new(num: u8, den: u8) -> Self {
        Self { num, den }
    }

    /// Effective coding efficiency as fixed-point (x1000).
    pub const fn efficiency_x1000(self) -> u32 {
        (self.num as u32) * 1000 / (self.den as u32)
    }
}

/// MCS parameter entry combining modulation and code rate.
#[derive(Copy, Clone, Debug)]
pub struct McsParams {
    /// MCS index (0-12).
    pub index: u8,
    /// Modulation type.
    pub modulation: Modulation,
    /// FEC code rate.
    pub code_rate: CodeRate,
    /// Data rate in kbps at 1 MHz bandwidth.
    pub data_rate_1m_kbps: u16,
    /// Whether OFDM (multi-carrier) is used (MCS 7-12).
    pub ofdm: bool,
}

/// Complete MCS parameter table per T/XS 10002-2025 table 11.
///
/// MCS 0-6: single-carrier (GFSK/PSK/QAM)
/// MCS 7-12: OFDM multi-carrier
pub const MCS_TABLE: [McsParams; 13] = [
    McsParams { index: 0,  modulation: Modulation::Bpsk,   code_rate: CodeRate::new(1, 4), data_rate_1m_kbps: 125,  ofdm: false },
    McsParams { index: 1,  modulation: Modulation::Bpsk,   code_rate: CodeRate::new(1, 2), data_rate_1m_kbps: 250,  ofdm: false },
    McsParams { index: 2,  modulation: Modulation::Bpsk,   code_rate: CodeRate::new(3, 4), data_rate_1m_kbps: 375,  ofdm: false },
    McsParams { index: 3,  modulation: Modulation::Qpsk,   code_rate: CodeRate::new(1, 4), data_rate_1m_kbps: 250,  ofdm: false },
    McsParams { index: 4,  modulation: Modulation::Qpsk,   code_rate: CodeRate::new(1, 2), data_rate_1m_kbps: 500,  ofdm: false },
    McsParams { index: 5,  modulation: Modulation::Qpsk,   code_rate: CodeRate::new(3, 4), data_rate_1m_kbps: 750,  ofdm: false },
    McsParams { index: 6,  modulation: Modulation::Qam16,  code_rate: CodeRate::new(1, 2), data_rate_1m_kbps: 1000, ofdm: false },
    McsParams { index: 7,  modulation: Modulation::Qpsk,   code_rate: CodeRate::new(1, 2), data_rate_1m_kbps: 500,  ofdm: true  },
    McsParams { index: 8,  modulation: Modulation::Qpsk,   code_rate: CodeRate::new(3, 4), data_rate_1m_kbps: 750,  ofdm: true  },
    McsParams { index: 9,  modulation: Modulation::Qam16,  code_rate: CodeRate::new(1, 2), data_rate_1m_kbps: 1000, ofdm: true  },
    McsParams { index: 10, modulation: Modulation::Qam16,  code_rate: CodeRate::new(3, 4), data_rate_1m_kbps: 1500, ofdm: true  },
    McsParams { index: 11, modulation: Modulation::Qam64,  code_rate: CodeRate::new(3, 4), data_rate_1m_kbps: 2250, ofdm: true  },
    McsParams { index: 12, modulation: Modulation::Qam256, code_rate: CodeRate::new(5, 6), data_rate_1m_kbps: 3333, ofdm: true  },
];

/// Look up MCS parameters by index. Returns `None` for invalid indices.
pub fn mcs_lookup(index: u8) -> Option<&'static McsParams> {
    MCS_TABLE.get(index as usize)
}

/// Compute the effective data rate in kbps for a given MCS index and
/// bandwidth in MHz (1, 2, or 4).
pub fn data_rate_kbps(mcs_index: u8, bandwidth_mhz: u8) -> Option<u32> {
    let params = mcs_lookup(mcs_index)?;
    Some(u32::from(params.data_rate_1m_kbps) * u32::from(bandwidth_mhz))
}

/// Select the best MCS index that satisfies the given minimum data rate
/// (kbps) at the specified bandwidth and SINR threshold.
///
/// Returns the highest-rate MCS with data_rate >= min_kbps and
/// required SINR <= available sinr_db. If no MCS qualifies, returns
/// the lowest MCS.
///
/// sinr_thresholds: approximate minimum SINR (dB, x10) required for
/// each MCS index at BER=1e-5.
pub fn mcs_select(min_kbps: u32, bandwidth_mhz: u8, sinr_db_x10: i16) -> u8 {
    // Approximate SINR thresholds (dB x10) per MCS index
    const SINR_THRESH: [i16; 13] = [
        -20, // MCS 0: BPSK 1/4
         10, // MCS 1: BPSK 1/2
         40, // MCS 2: BPSK 3/4
         20, // MCS 3: QPSK 1/4
         50, // MCS 4: QPSK 1/2
         80, // MCS 5: QPSK 3/4
        100, // MCS 6: 16QAM 1/2
         60, // MCS 7: QPSK 1/2 OFDM
         90, // MCS 8: QPSK 3/4 OFDM
        120, // MCS 9: 16QAM 1/2 OFDM
        150, // MCS 10: 16QAM 3/4 OFDM
        190, // MCS 11: 64QAM 3/4 OFDM
        230, // MCS 12: 256QAM 5/6 OFDM
    ];

    let mut best = 0u8;
    for i in 0..13u8 {
        let rate = u32::from(MCS_TABLE[i as usize].data_rate_1m_kbps) * u32::from(bandwidth_mhz);
        if rate >= min_kbps && SINR_THRESH[i as usize] <= sinr_db_x10 {
            best = i;
        }
    }
    best
}

// =========================================================================
// Frequency hopping (T/XS 10002-2025 section 5.3)
//
// SLE uses adaptive frequency hopping (AFH) across the 2.4 GHz ISM
// band. The channel map has 79 channels (0-78), each 1 MHz wide,
// starting at 2402 MHz (channel 0).
//
// The hopping sequence is generated using a permutation-based algorithm
// that maps (connection_event_counter, hop_increment, channel_map) to
// a used channel index, avoiding channels marked as bad in the map.
// =========================================================================

/// Total number of frequency channels in the SLE band (2402-2480 MHz).
pub const NUM_CHANNELS: u8 = 79;

/// Channel map: bitmask of usable channels (79 bits).
/// Bit N set = channel N is usable.
#[derive(Copy, Clone, Debug)]
pub struct ChannelMap {
    /// 10-byte bitmask (80 bits, only bits 0-78 used).
    pub map: [u8; 10],
    /// Number of used channels (cached).
    used_count: u8,
}

impl ChannelMap {
    /// Create a channel map where all 79 channels are usable.
    pub fn all_used() -> Self {
        let mut map = [0xFFu8; 10];
        // Clear bit 79 (not a valid channel)
        map[9] &= 0x7F;
        Self { map, used_count: NUM_CHANNELS }
    }

    /// Create a channel map from a raw 10-byte bitmask.
    pub fn from_raw(raw: [u8; 10]) -> Self {
        let mut s = Self { map: raw, used_count: 0 };
        s.map[9] &= 0x7F; // mask off bit 79
        s.recount();
        s
    }

    /// Recalculate the used channel count.
    fn recount(&mut self) {
        let mut count = 0u8;
        for ch in 0..NUM_CHANNELS {
            if self.is_used(ch) {
                count += 1;
            }
        }
        self.used_count = count;
    }

    /// Check if a channel is marked as usable.
    pub fn is_used(&self, channel: u8) -> bool {
        if channel >= NUM_CHANNELS { return false; }
        let byte_idx = (channel / 8) as usize;
        let bit_idx = channel % 8;
        (self.map[byte_idx] >> bit_idx) & 1 != 0
    }

    /// Mark a channel as used or unused.
    pub fn set_used(&mut self, channel: u8, used: bool) {
        if channel >= NUM_CHANNELS { return; }
        let byte_idx = (channel / 8) as usize;
        let bit_idx = channel % 8;
        if used {
            self.map[byte_idx] |= 1 << bit_idx;
        } else {
            self.map[byte_idx] &= !(1 << bit_idx);
        }
        self.recount();
    }

    /// Number of usable channels.
    pub fn used_count(&self) -> u8 {
        self.used_count
    }

    /// Get the Nth used channel (0-indexed among used channels).
    /// Returns `None` if n >= used_count.
    pub fn nth_used(&self, n: u8) -> Option<u8> {
        let mut count = 0u8;
        for ch in 0..NUM_CHANNELS {
            if self.is_used(ch) {
                if count == n {
                    return Some(ch);
                }
                count += 1;
            }
        }
        None
    }
}

/// Frequency hopping state for a connection.
#[derive(Clone, Debug)]
pub struct HoppingState {
    /// Hop increment (1-78), derived from connection parameters.
    pub hop_increment: u8,
    /// Current channel map.
    pub channel_map: ChannelMap,
    /// Connection event counter (wraps at u16::MAX).
    pub event_counter: u16,
    /// Last selected channel.
    pub last_channel: u8,
}

impl HoppingState {
    /// Create a new hopping state with given increment and channel map.
    pub fn new(hop_increment: u8, channel_map: ChannelMap) -> Self {
        let hop = if hop_increment == 0 || hop_increment >= NUM_CHANNELS {
            7 // default to 7 if invalid
        } else {
            hop_increment
        };
        Self {
            hop_increment: hop,
            channel_map,
            event_counter: 0,
            last_channel: 0,
        }
    }

    /// Compute the next channel for the current event counter and advance.
    ///
    /// Algorithm per T/XS 10002-2025 section 5.3:
    /// 1. unmapped_channel = (last_channel + hop_increment) mod 79
    /// 2. If unmapped_channel is in the channel map, use it directly
    /// 3. Otherwise, remap: used_channel[unmapped_channel mod used_count]
    pub fn next_channel(&mut self) -> u8 {
        let unmapped = (u16::from(self.last_channel) + u16::from(self.hop_increment))
            % u16::from(NUM_CHANNELS);
        let unmapped = unmapped as u8;

        let channel = if self.channel_map.is_used(unmapped) {
            unmapped
        } else {
            let used = self.channel_map.used_count();
            if used == 0 {
                0 // degenerate case: no channels available
            } else {
                let remap_idx = unmapped % used;
                self.channel_map.nth_used(remap_idx).unwrap_or(0)
            }
        };

        self.last_channel = channel;
        self.event_counter = self.event_counter.wrapping_add(1);
        channel
    }

    /// Get the RF frequency in MHz for a channel index.
    /// Channel 0 = 2402 MHz, Channel 78 = 2480 MHz.
    pub fn channel_to_freq(channel: u8) -> u16 {
        2402 + u16::from(channel)
    }

    /// Update the channel map (e.g., after AFH classification).
    pub fn update_map(&mut self, new_map: ChannelMap) {
        self.channel_map = new_map;
    }
}

// =========================================================================
// MIMO antenna configuration (T/XS 10002-2025 section 5.5)
//
// SLE supports spatial multiplexing and beamforming for devices with
// multiple antennas. The MIMO mode is negotiated during connection
// establishment based on device capabilities.
// =========================================================================

/// MIMO mode for an SLE link.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum MimoMode {
    /// Single antenna (no MIMO).
    #[default]
    Siso = 0,
    /// 2x2 spatial multiplexing (doubles throughput).
    SpatialMux2x2 = 1,
    /// 2x1 transmit diversity (improved reliability).
    TxDiversity2x1 = 2,
    /// 1x2 receive diversity (improved sensitivity).
    RxDiversity1x2 = 3,
    /// 2x2 beamforming (improved range).
    Beamforming2x2 = 4,
}

impl MimoMode {
    pub fn from_raw(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Siso),
            1 => Some(Self::SpatialMux2x2),
            2 => Some(Self::TxDiversity2x1),
            3 => Some(Self::RxDiversity1x2),
            4 => Some(Self::Beamforming2x2),
            _ => None,
        }
    }

    /// Number of spatial streams for this MIMO mode.
    pub fn num_streams(self) -> u8 {
        match self {
            Self::Siso | Self::TxDiversity2x1 | Self::RxDiversity1x2 => 1,
            Self::SpatialMux2x2 | Self::Beamforming2x2 => 2,
        }
    }

    /// Throughput multiplier (x100) compared to SISO.
    pub fn throughput_factor(self) -> u8 {
        match self {
            Self::Siso => 100,
            Self::SpatialMux2x2 => 200,
            Self::TxDiversity2x1 => 100, // same throughput, better reliability
            Self::RxDiversity1x2 => 100,
            Self::Beamforming2x2 => 150, // range gain, moderate throughput
        }
    }
}

/// Antenna configuration for a device.
#[derive(Copy, Clone, Debug)]
pub struct AntennaConfig {
    /// Number of transmit antennas.
    pub num_tx: u8,
    /// Number of receive antennas.
    pub num_rx: u8,
    /// Active MIMO mode.
    pub mode: MimoMode,
    /// Antenna calibration state.
    pub calibrated: bool,
}

impl Default for AntennaConfig {
    fn default() -> Self {
        Self {
            num_tx: 1,
            num_rx: 1,
            mode: MimoMode::Siso,
            calibrated: false,
        }
    }
}

impl AntennaConfig {
    /// Determine the best MIMO mode based on antenna counts.
    pub fn negotiate_mode(local: &Self, remote: &Self) -> MimoMode {
        let tx = local.num_tx.min(remote.num_rx);
        let rx = local.num_rx.min(remote.num_tx);

        if tx >= 2 && rx >= 2 {
            MimoMode::SpatialMux2x2
        } else if tx >= 2 && rx == 1 {
            MimoMode::TxDiversity2x1
        } else if tx == 1 && rx >= 2 {
            MimoMode::RxDiversity1x2
        } else {
            MimoMode::Siso
        }
    }
}

// =========================================================================
// PHY link configuration (combines all PHY parameters)
// =========================================================================

/// Complete PHY layer configuration for an SLE connection.
#[derive(Clone, Debug)]
pub struct PhyConfig {
    /// Active MCS index (0-12).
    pub mcs_index: u8,
    /// Bandwidth in MHz (1, 2, or 4).
    pub bandwidth_mhz: u8,
    /// Pilot density (0=4:1, 1=8:1, 2=16:1, 3=none).
    pub pilot_density: u8,
    /// TX power in dBm.
    pub tx_power_dbm: i8,
    /// Frequency hopping state.
    pub hopping: HoppingState,
    /// Antenna configuration.
    pub antenna: AntennaConfig,
}

impl PhyConfig {
    /// Create a default PHY configuration (MCS 4, 1 MHz, SISO).
    pub fn default_config() -> Self {
        Self {
            mcs_index: 4,
            bandwidth_mhz: 1,
            pilot_density: 1,
            tx_power_dbm: 10,
            hopping: HoppingState::new(7, ChannelMap::all_used()),
            antenna: AntennaConfig::default(),
        }
    }

    /// Compute the current effective data rate in kbps.
    pub fn effective_data_rate_kbps(&self) -> u32 {
        let base = data_rate_kbps(self.mcs_index, self.bandwidth_mhz)
            .unwrap_or(500);
        let mimo_factor = u32::from(self.antenna.mode.throughput_factor());
        base * mimo_factor / 100
    }

    /// Set MCS index with bounds validation.
    pub fn set_mcs(&mut self, index: u8) -> Result {
        if index > 12 {
            return Err(EINVAL);
        }
        self.mcs_index = index;
        Ok(())
    }

    /// Set bandwidth with validation.
    pub fn set_bandwidth(&mut self, bw_mhz: u8) -> Result {
        match bw_mhz {
            1 | 2 | 4 => {
                self.bandwidth_mhz = bw_mhz;
                Ok(())
            }
            _ => Err(EINVAL),
        }
    }

    /// Set TX power with range validation (-20 to +20 dBm).
    pub fn set_tx_power(&mut self, power_dbm: i8) -> Result {
        if !(-20..=20).contains(&power_dbm) {
            return Err(EINVAL);
        }
        self.tx_power_dbm = power_dbm;
        Ok(())
    }

    /// Encode PHY parameters for DLI ReadPhyParam response.
    ///
    /// Format (T/XS 10003-2025 ReadPhyParam response):
    ///   [0]    = MCS index
    ///   [1]    = bandwidth (0=1MHz, 1=2MHz, 2=4MHz)
    ///   [2]    = pilot density
    ///   [3]    = TX power (signed i8)
    ///   [4]    = MIMO mode
    ///   [5]    = num_tx antennas
    ///   [6]    = num_rx antennas
    pub fn encode_dli_params(&self, buf: &mut [u8]) -> usize {
        if buf.len() < 7 {
            return 0;
        }
        buf[0] = self.mcs_index;
        buf[1] = match self.bandwidth_mhz {
            1 => 0,
            2 => 1,
            4 => 2,
            _ => 0,
        };
        buf[2] = self.pilot_density;
        buf[3] = self.tx_power_dbm as u8;
        buf[4] = self.antenna.mode as u8;
        buf[5] = self.antenna.num_tx;
        buf[6] = self.antenna.num_rx;
        7
    }

    /// Decode PHY parameters from DLI SetPhyParam command payload.
    ///
    /// Accepts the same format as encode_dli_params produces.
    /// Returns Ok(()) on success, Err(EINVAL) if parameters are invalid.
    pub fn decode_dli_params(&mut self, buf: &[u8]) -> Result {
        if buf.len() < 7 {
            return Err(EINVAL);
        }
        self.set_mcs(buf[0])?;
        let bw = match buf[1] {
            0 => 1u8,
            1 => 2,
            2 => 4,
            _ => return Err(EINVAL),
        };
        self.set_bandwidth(bw)?;
        if buf[2] > 3 {
            return Err(EINVAL);
        }
        self.pilot_density = buf[2];
        self.set_tx_power(buf[3] as i8)?;
        match MimoMode::from_raw(buf[4]) {
            Some(m) => self.antenna.mode = m,
            None => return Err(EINVAL),
        }
        self.antenna.num_tx = buf[5];
        self.antenna.num_rx = buf[6];
        Ok(())
    }

    /// Build feature bitmask from current PHY config.
    ///
    /// Maps MCS index, bandwidth, and pilot density to the
    /// SleFeature bits defined in sle_dli.rs.
    pub fn to_feature_bits(&self) -> u64 {
        let mut bits = 0u64;
        // MCS feature bits (SleFeature::Mcs0 = 1<<14, ..Mcs12 = 1<<26)
        if self.mcs_index <= 12 {
            bits |= 1u64 << (14 + u32::from(self.mcs_index));
        }
        // Bandwidth
        if self.bandwidth_mhz >= 2 {
            bits |= 1u64 << 8; // Bw2m
        }
        if self.bandwidth_mhz >= 4 {
            bits |= 1u64 << 9; // Bw4m
        }
        // Pilot density
        match self.pilot_density {
            0 => bits |= 1u64 << 10, // Pilot4to1
            1 => bits |= 1u64 << 11, // Pilot8to1
            2 => bits |= 1u64 << 12, // Pilot16to1
            _ => {}
        }
        bits
    }
}
