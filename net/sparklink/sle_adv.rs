// SPDX-License-Identifier: GPL-2.0

//! SLE advertising and scanning state machine.
//!
//! Manages the lifecycle of advertising (discoverable/connectable
//! broadcasting) and scanning (observer) operations on an SCI device.
//! The state machine enforces mutual exclusion between advertising and
//! scanning on a single controller, following the SLE air-interface
//! specification T/XS 10002-2025.

#![allow(dead_code, unreachable_pub)]

use kernel::prelude::*;
use kernel::alloc::KVec;
use crate::sle_pdu::{
    AdvDataBuilder, AdvPdu, BroadcastType, PacketType, SLE_ADV_DATA_MAX,
};

// ---------------------------------------------------------------------------
// Advertising parameters
// ---------------------------------------------------------------------------

/// Advertising parameters controlling how the device broadcasts.
#[derive(Copy, Clone, Debug)]
pub struct AdvParams {
    /// Discovery level (0-4, maps to DiscoveryLevel).
    pub discovery_level: u8,
    /// Advertising interval in units of 125us system slots.
    pub interval_slots: u32,
    /// Broadcast type to use in the PDU header.
    pub broadcast_type: BroadcastType,
    /// TX power in dBm.
    pub tx_power: i8,
}

impl Default for AdvParams {
    fn default() -> Self {
        Self {
            discovery_level: 1, // General discoverable
            interval_slots: 800, // 100ms = 800 * 125us
            broadcast_type: BroadcastType::AccessibleScannable,
            tx_power: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Scanning parameters
// ---------------------------------------------------------------------------

/// Scanning parameters controlling how the device listens for advertisements.
#[derive(Copy, Clone, Debug)]
pub struct ScanParams {
    /// Scan window in units of 125us system slots.
    pub window_slots: u32,
    /// Scan interval in units of 125us system slots.
    pub interval_slots: u32,
    /// Minimum discovery level to accept (filter).
    pub filter_level: u8,
    /// Whether to send scan requests (active scan).
    pub active: bool,
}

impl Default for ScanParams {
    fn default() -> Self {
        Self {
            window_slots: 400, // 50ms
            interval_slots: 800, // 100ms
            filter_level: 0,   // accept all levels
            active: false,     // passive scan
        }
    }
}

// ---------------------------------------------------------------------------
// Scan result entry
// ---------------------------------------------------------------------------

/// A single advertising report received during scanning.
#[derive(Clone)]
pub struct ScanResult {
    /// Source SLE address (6 bytes).
    pub addr: [u8; 6],
    /// Received signal strength indicator.
    pub rssi: i8,
    /// Discovery level extracted from the advertising data.
    pub discovery_level: u8,
    /// Device name extracted from advertising data (UTF-8, truncated).
    pub name: [u8; 32],
    /// Actual length of the name.
    pub name_len: usize,
    /// Raw advertising data.
    pub adv_data: [u8; SLE_ADV_DATA_MAX],
    /// Length of advertising data.
    pub adv_data_len: usize,
}

impl Default for ScanResult {
    fn default() -> Self {
        Self {
            addr: [0u8; 6],
            rssi: -127,
            discovery_level: 0,
            name: [0u8; 32],
            name_len: 0,
            adv_data: [0u8; SLE_ADV_DATA_MAX],
            adv_data_len: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Operating state of the advertising/scanning state machine.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum AdvScanState {
    /// Idle — neither advertising nor scanning.
    #[default]
    Idle,
    /// Advertising — broadcasting PDUs.
    Advertising,
    /// Scanning — listening for PDUs.
    Scanning,
}

/// Internal mutable state for the advertising/scanning engine.
pub struct AdvScanInner {
    /// Current operating state.
    pub state: AdvScanState,
    /// Active advertising parameters (valid when state == Advertising).
    pub adv_params: AdvParams,
    /// Active scanning parameters (valid when state == Scanning).
    pub scan_params: ScanParams,
    /// Device name for advertising (UTF-8, null-padded).
    pub local_name: [u8; 32],
    /// Actual length of the local name.
    pub local_name_len: usize,
    /// SLE address of this device.
    pub addr: [u8; 6],
    /// Collected scan results (ring buffer of last N results).
    pub scan_results: KVec<ScanResult>,
    /// Maximum number of scan results to retain.
    pub scan_results_max: usize,
}

impl AdvScanInner {
    /// Create a new idle state machine.
    pub fn new(addr: [u8; 6], name: &[u8]) -> Self {
        let mut local_name = [0u8; 32];
        let copy_len = name.len().min(32);
        local_name[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            state: AdvScanState::Idle,
            adv_params: AdvParams::default(),
            scan_params: ScanParams::default(),
            local_name,
            local_name_len: copy_len,
            addr,
            scan_results: KVec::new(),
            scan_results_max: 64,
        }
    }

    /// Start advertising. Fails if already advertising or scanning.
    pub fn start_advertising(&mut self, params: AdvParams) -> Result {
        if self.state != AdvScanState::Idle {
            pr_err!("sparklink: cannot start adv in state {:?}\n", self.state);
            return Err(EBUSY);
        }
        self.adv_params = params;
        self.state = AdvScanState::Advertising;
        pr_info!(
            "sparklink: advertising started (level={}, interval={})\n",
            params.discovery_level,
            params.interval_slots
        );
        Ok(())
    }

    /// Stop advertising.
    pub fn stop_advertising(&mut self) -> Result {
        if self.state != AdvScanState::Advertising {
            return Err(EBUSY);
        }
        self.state = AdvScanState::Idle;
        pr_info!("sparklink: advertising stopped\n");
        Ok(())
    }

    /// Start scanning. Fails if already advertising or scanning.
    pub fn start_scanning(&mut self, params: ScanParams) -> Result {
        if self.state != AdvScanState::Idle {
            pr_err!("sparklink: cannot start scan in state {:?}\n", self.state);
            return Err(EBUSY);
        }
        self.scan_params = params;
        self.scan_results = KVec::new();
        self.state = AdvScanState::Scanning;
        pr_info!(
            "sparklink: scanning started (window={}, interval={}, filter={})\n",
            params.window_slots,
            params.interval_slots,
            params.filter_level
        );
        Ok(())
    }

    /// Stop scanning.
    pub fn stop_scanning(&mut self) -> Result {
        if self.state != AdvScanState::Scanning {
            return Err(EBUSY);
        }
        self.state = AdvScanState::Idle;
        pr_info!("sparklink: scanning stopped ({} results)\n", self.scan_results.len());
        Ok(())
    }

    /// Build the advertising PDU for the current configuration.
    ///
    /// Called by the driver/timer to generate the next advertising frame.
    pub fn build_adv_pdu(&self) -> Option<AdvPdu> {
        if self.state != AdvScanState::Advertising {
            return None;
        }
        let mut builder = AdvDataBuilder::new();
        // Discovery level TLV
        let _ = builder.push_discovery_level(self.adv_params.discovery_level);
        // TX power TLV
        let _ = builder.push_tx_power(self.adv_params.tx_power);
        // SLE address TLV
        let _ = builder.push_sle_addr(&self.addr);
        // Device name TLV
        if self.local_name_len > 0 {
            let _ = builder.push_complete_name(&self.local_name[..self.local_name_len]);
        }

        Some(AdvPdu::build(
            self.adv_params.broadcast_type,
            PacketType::BasicAdv,
            0, // link quality filled by PHY
            &builder,
        ))
    }

    /// Process a received advertising PDU (called during scanning).
    ///
    /// Extracts device info from the PDU and adds it to the scan results
    /// if it passes the discovery level filter.
    pub fn process_adv_pdu(&mut self, pdu: &AdvPdu, rssi: i8) -> Result {
        if self.state != AdvScanState::Scanning {
            return Err(EPERM);
        }

        let mut result = ScanResult::default();
        result.rssi = rssi;

        // Copy raw advertising data
        let dlen = pdu.data_len.min(SLE_ADV_DATA_MAX);
        result.adv_data[..dlen].copy_from_slice(&pdu.data[..dlen]);
        result.adv_data_len = dlen;

        // Parse TLV entries
        for entry in pdu.iter_adv_data() {
            match entry.typ {
                0x01 if !entry.value.is_empty() => {
                    result.discovery_level = entry.value[0] & 0x07;
                }
                0x0B | 0x0A => {
                    let copy_len = entry.value.len().min(32);
                    result.name[..copy_len].copy_from_slice(&entry.value[..copy_len]);
                    result.name_len = copy_len;
                }
                0x0F if entry.value.len() == 6 => {
                    result.addr.copy_from_slice(entry.value);
                }
                _ => {}
            }
        }

        // Apply discovery level filter
        if result.discovery_level < self.scan_params.filter_level {
            return Ok(());
        }

        // Add to results (evict oldest if full)
        if self.scan_results.len() >= self.scan_results_max {
            let _ = self.scan_results.remove(0);
        }
        self.scan_results.push(result, GFP_KERNEL)?;
        Ok(())
    }

    /// Get the number of available scan results.
    pub fn scan_result_count(&self) -> usize {
        self.scan_results.len()
    }
}
