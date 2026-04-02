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
// Extended advertising (T/XS 10002-2025 section 6.8)
// ---------------------------------------------------------------------------

/// Maximum number of concurrent extended advertising sets.
pub const EXT_ADV_MAX_SETS: usize = 4;

/// Maximum extended advertising data length.
/// Primary channel: 251 bytes. Auxiliary channel: up to 1650 bytes.
pub const EXT_ADV_DATA_MAX: usize = 1650;

/// Extended advertising PHY selection.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum ExtAdvPhy {
    /// 1 MHz bandwidth (default).
    #[default]
    Phy1M = 0,
    /// 2 MHz bandwidth.
    Phy2M = 1,
    /// 4 MHz bandwidth (coded PHY).
    PhyCoded = 2,
}

impl ExtAdvPhy {
    pub fn from_raw(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Phy1M),
            1 => Some(Self::Phy2M),
            2 => Some(Self::PhyCoded),
            _ => None,
        }
    }
}

/// Extended advertising set parameters.
#[derive(Clone, Debug)]
pub struct ExtAdvParams {
    /// Discovery level (0-4).
    pub discovery_level: u8,
    /// Advertising interval in 125us slots.
    pub interval_slots: u32,
    /// Broadcast type for the PDU header.
    pub broadcast_type: BroadcastType,
    /// TX power in dBm.
    pub tx_power: i8,
    /// Primary advertising PHY.
    pub primary_phy: ExtAdvPhy,
    /// Secondary advertising PHY (for auxiliary channel).
    pub secondary_phy: ExtAdvPhy,
    /// Advertising SID (set identifier, 0-15).
    pub sid: u8,
    /// Whether to include TX power in the extended header.
    pub include_tx_power: bool,
    /// Extended advertising send timing (per §8.2.1).
    /// 0x00 = send before next base advertising,
    /// 0x01..0xFF = max base advs to skip before sending extended adv.
    pub extended_adv_timing: u8,
}

impl Default for ExtAdvParams {
    fn default() -> Self {
        Self {
            discovery_level: 1,
            interval_slots: 800,
            broadcast_type: BroadcastType::AccessibleScannable,
            tx_power: 0,
            primary_phy: ExtAdvPhy::Phy1M,
            secondary_phy: ExtAdvPhy::Phy1M,
            sid: 0,
            include_tx_power: true,
            extended_adv_timing: 0,
        }
    }
}

/// State of a single extended advertising set.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum ExtAdvState {
    #[default]
    Idle,
    Configured,
    Active,
}

/// A single extended advertising set.
pub struct ExtAdvSet {
    /// Set handle (0..EXT_ADV_MAX_SETS-1).
    pub handle: u8,
    /// Current state.
    pub state: ExtAdvState,
    /// Advertising parameters.
    pub params: ExtAdvParams,
    /// Advertising data (primary + auxiliary combined).
    pub data: [u8; EXT_ADV_DATA_MAX],
    /// Length of valid data.
    pub data_len: usize,
    /// Number of PDUs sent since enabled.
    pub tx_count: u64,
    /// Advertising duration in 10ms units (0 = infinite).
    pub duration_10ms: u16,
    /// Maximum advertising events (0 = unlimited).
    pub max_events: u8,
    /// Number of advertising events sent since enabled.
    pub events_sent: u32,
    /// Elapsed ticks (each tick = 10ms) since enabled.
    pub elapsed_ticks: u32,
}

impl ExtAdvSet {
    fn new(handle: u8) -> Self {
        Self {
            handle,
            state: ExtAdvState::Idle,
            params: ExtAdvParams::default(),
            data: [0u8; EXT_ADV_DATA_MAX],
            data_len: 0,
            tx_count: 0,
            duration_10ms: 0,
            max_events: 0,
            events_sent: 0,
            elapsed_ticks: 0,
        }
    }

    /// Build an extended advertising PDU.
    /// For data <= 251 bytes, uses a single primary PDU.
    /// For larger data, the primary PDU carries 251 bytes and signals
    /// auxiliary data via the PacketType field.
    pub fn build_pdu(&self, addr: &[u8; 6], name: &[u8]) -> Option<AdvPdu> {
        if self.state != ExtAdvState::Active {
            return None;
        }
        let mut builder = AdvDataBuilder::new();
        let _ = builder.push_discovery_level(self.params.discovery_level);
        if self.params.include_tx_power {
            let _ = builder.push_tx_power(self.params.tx_power);
        }
        let _ = builder.push_sle_addr(addr);
        if !name.is_empty() {
            let _ = builder.push_complete_name(name);
        }
        // Append custom advertising data.
        if self.data_len > 0 {
            let _ = builder.push_raw(&self.data[..self.data_len]);
        }

        Some(AdvPdu::build(
            self.params.broadcast_type,
            PacketType::ExtendedAdv,
            0,
            &builder,
        ))
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
    /// Advertising command sent to controller, awaiting confirmation.
    AdvPending,
    /// Advertising confirmed by controller — broadcasting PDUs.
    Advertising,
    /// Scan command sent to controller, awaiting confirmation.
    ScanPending,
    /// Scanning confirmed by controller — listening for PDUs.
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
    /// Extended advertising sets.
    pub ext_adv_sets: [Option<ExtAdvSet>; EXT_ADV_MAX_SETS],
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
            ext_adv_sets: [None, None, None, None],
        }
    }

    /// Start advertising. Fails if already advertising or scanning.
    /// Sets state to AdvPending; call confirm_advertising() after
    /// controller sends CommandComplete with success.
    pub fn start_advertising(&mut self, params: AdvParams) -> Result {
        if self.state != AdvScanState::Idle {
            pr_err!("sparklink: cannot start adv in state {:?}\n", self.state);
            return Err(EBUSY);
        }
        self.adv_params = params;
        self.state = AdvScanState::AdvPending;
        pr_info!(
            "sparklink: advertising pending (level={}, interval={})\n",
            params.discovery_level,
            params.interval_slots
        );
        Ok(())
    }

    /// Confirm advertising after controller reports success.
    pub fn confirm_advertising(&mut self) {
        if self.state == AdvScanState::AdvPending {
            self.state = AdvScanState::Advertising;
            pr_info!("sparklink: advertising confirmed\n");
        }
    }

    /// Abort a pending advertising request (controller reported failure).
    pub fn abort_advertising(&mut self) {
        if self.state == AdvScanState::AdvPending {
            self.state = AdvScanState::Idle;
            pr_info!("sparklink: advertising aborted (controller rejected)\n");
        }
    }

    /// Stop advertising.
    pub fn stop_advertising(&mut self) -> Result {
        if self.state != AdvScanState::Advertising && self.state != AdvScanState::AdvPending {
            return Err(EBUSY);
        }
        self.state = AdvScanState::Idle;
        pr_info!("sparklink: advertising stopped\n");
        Ok(())
    }

    /// Start scanning. Fails if already advertising or scanning.
    /// Sets state to ScanPending; call confirm_scanning() after
    /// controller sends CommandComplete with success.
    pub fn start_scanning(&mut self, params: ScanParams) -> Result {
        if self.state != AdvScanState::Idle {
            pr_err!("sparklink: cannot start scan in state {:?}\n", self.state);
            return Err(EBUSY);
        }
        self.scan_params = params;
        self.scan_results = KVec::new();
        self.state = AdvScanState::ScanPending;
        pr_info!(
            "sparklink: scanning pending (window={}, interval={}, filter={})\n",
            params.window_slots,
            params.interval_slots,
            params.filter_level
        );
        Ok(())
    }

    /// Confirm scanning after controller reports success.
    pub fn confirm_scanning(&mut self) {
        if self.state == AdvScanState::ScanPending {
            self.state = AdvScanState::Scanning;
            pr_info!("sparklink: scanning confirmed\n");
        }
    }

    /// Abort a pending scan request (controller reported failure).
    pub fn abort_scanning(&mut self) {
        if self.state == AdvScanState::ScanPending {
            self.state = AdvScanState::Idle;
            pr_info!("sparklink: scanning aborted (controller rejected)\n");
        }
    }

    /// Stop scanning.
    pub fn stop_scanning(&mut self) -> Result {
        if self.state != AdvScanState::Scanning && self.state != AdvScanState::ScanPending {
            return Err(EBUSY);
        }
        self.state = AdvScanState::Idle;
        pr_info!("sparklink: scanning stopped ({} results)\n", self.scan_results.len());
        Ok(())
    }

    /// Check if currently advertising (confirmed or pending).
    pub fn is_advertising(&self) -> bool {
        self.state == AdvScanState::Advertising || self.state == AdvScanState::AdvPending
    }

    /// Check if currently scanning (confirmed or pending).
    pub fn is_scanning(&self) -> bool {
        self.state == AdvScanState::Scanning || self.state == AdvScanState::ScanPending
    }

    /// Build the advertising PDU for the current configuration.
    ///
    /// Called by the driver/timer to generate the next advertising frame.
    pub fn build_adv_pdu(&self) -> Option<AdvPdu> {
        if self.state != AdvScanState::Advertising && self.state != AdvScanState::AdvPending {
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
        if self.state != AdvScanState::Scanning && self.state != AdvScanState::ScanPending {
            return Err(EPERM);
        }

        let mut result = ScanResult {
            rssi,
            ..Default::default()
        };

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

    /// Process an advertising report event from a controller.
    ///
    /// Unlike `process_adv_pdu`, this takes pre-parsed fields from
    /// the controller event (addr, rssi, discovery_level, raw adv data)
    /// and adds a scan result directly.
    pub fn process_adv_report(
        &mut self,
        addr: &[u8; 6],
        rssi: i8,
        discovery_level: u8,
        data: &[u8],
    ) -> Result {
        if self.state != AdvScanState::Scanning && self.state != AdvScanState::ScanPending {
            return Ok(());
        }
        if discovery_level < self.scan_params.filter_level {
            return Ok(());
        }
        let mut result = ScanResult {
            addr: *addr,
            rssi,
            discovery_level,
            ..Default::default()
        };
        let dlen = data.len().min(SLE_ADV_DATA_MAX);
        result.adv_data[..dlen].copy_from_slice(&data[..dlen]);
        result.adv_data_len = dlen;

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

    // -----------------------------------------------------------------------
    // Extended advertising set management
    // -----------------------------------------------------------------------

    /// Configure an extended advertising set.
    ///
    /// Creates or updates the set at `handle` (0..EXT_ADV_MAX_SETS-1).
    pub fn ext_adv_configure(&mut self, handle: u8, params: ExtAdvParams) -> Result {
        let idx = handle as usize;
        if idx >= EXT_ADV_MAX_SETS {
            return Err(EINVAL);
        }
        if params.sid > 15 {
            return Err(EINVAL);
        }
        match &mut self.ext_adv_sets[idx] {
            Some(set) => {
                if set.state == ExtAdvState::Active {
                    return Err(EBUSY);
                }
                set.params = params;
                set.state = ExtAdvState::Configured;
            }
            slot => {
                let mut set = ExtAdvSet::new(handle);
                set.params = params;
                set.state = ExtAdvState::Configured;
                *slot = Some(set);
            }
        }
        Ok(())
    }

    /// Set advertising data for an extended advertising set.
    pub fn ext_adv_set_data(&mut self, handle: u8, data: &[u8]) -> Result {
        let idx = handle as usize;
        if idx >= EXT_ADV_MAX_SETS {
            return Err(EINVAL);
        }
        let set = self.ext_adv_sets[idx].as_mut().ok_or(ENOENT)?;
        if set.state == ExtAdvState::Idle {
            return Err(EINVAL);
        }
        let len = data.len().min(EXT_ADV_DATA_MAX);
        set.data[..len].copy_from_slice(&data[..len]);
        set.data_len = len;
        Ok(())
    }

    /// Enable an extended advertising set.
    pub fn ext_adv_enable(&mut self, handle: u8) -> Result {
        self.ext_adv_enable_ex(handle, 0, 0)
    }

    /// Enable an extended advertising set with periodic parameters.
    ///
    /// `duration_10ms`: advertising duration in 10ms units (0 = infinite).
    /// `max_events`: max advertising events before auto-disable (0 = unlimited).
    pub fn ext_adv_enable_ex(
        &mut self,
        handle: u8,
        duration_10ms: u16,
        max_events: u8,
    ) -> Result {
        let idx = handle as usize;
        if idx >= EXT_ADV_MAX_SETS {
            return Err(EINVAL);
        }
        let set = self.ext_adv_sets[idx].as_mut().ok_or(ENOENT)?;
        if set.state == ExtAdvState::Idle {
            return Err(EINVAL);
        }
        set.state = ExtAdvState::Active;
        set.tx_count = 0;
        set.duration_10ms = duration_10ms;
        set.max_events = max_events;
        set.events_sent = 0;
        set.elapsed_ticks = 0;
        Ok(())
    }

    /// Disable an extended advertising set.
    pub fn ext_adv_disable(&mut self, handle: u8) -> Result {
        let idx = handle as usize;
        if idx >= EXT_ADV_MAX_SETS {
            return Err(EINVAL);
        }
        let set = self.ext_adv_sets[idx].as_mut().ok_or(ENOENT)?;
        if set.state != ExtAdvState::Active {
            return Err(EINVAL);
        }
        set.state = ExtAdvState::Configured;
        Ok(())
    }

    /// Remove an extended advertising set.
    pub fn ext_adv_remove(&mut self, handle: u8) -> Result {
        let idx = handle as usize;
        if idx >= EXT_ADV_MAX_SETS {
            return Err(EINVAL);
        }
        let set = self.ext_adv_sets[idx].as_ref().ok_or(ENOENT)?;
        if set.state == ExtAdvState::Active {
            return Err(EBUSY);
        }
        self.ext_adv_sets[idx] = None;
        Ok(())
    }

    /// Get info about an extended advertising set.
    pub fn ext_adv_info(
        &self,
        handle: u8,
    ) -> Result<(ExtAdvState, u8, u8, usize, u64, u8, u8, u32)> {
        let idx = handle as usize;
        if idx >= EXT_ADV_MAX_SETS {
            return Err(EINVAL);
        }
        let set = self.ext_adv_sets[idx].as_ref().ok_or(ENOENT)?;
        Ok((
            set.state,
            set.params.sid,
            set.params.primary_phy as u8,
            set.data_len,
            set.tx_count,
            set.params.extended_adv_timing,
            set.max_events,
            set.events_sent,
        ))
    }

    /// Build extended advertising PDU for the given set.
    pub fn build_ext_adv_pdu(&self, handle: u8) -> Option<AdvPdu> {
        let idx = handle as usize;
        if idx >= EXT_ADV_MAX_SETS {
            return None;
        }
        let set = self.ext_adv_sets[idx].as_ref()?;
        let name = if self.local_name_len > 0 {
            &self.local_name[..self.local_name_len]
        } else {
            &[]
        };
        set.build_pdu(&self.addr, name)
    }

    /// Count active extended advertising sets.
    pub fn ext_adv_active_count(&self) -> u8 {
        let mut count = 0u8;
        for slot in &self.ext_adv_sets {
            if let Some(set) = slot {
                if set.state == ExtAdvState::Active {
                    count += 1;
                }
            }
        }
        count
    }

    /// Simulate one advertising tick (10ms) for all active extended sets.
    ///
    /// Each tick: increments elapsed time, sends one event per active set,
    /// and auto-disables sets that exceed their duration or event limit.
    /// Returns the number of sets that were auto-disabled this tick.
    pub fn ext_adv_tick(&mut self) -> u8 {
        let mut disabled = 0u8;
        for slot in &mut self.ext_adv_sets {
            let set = match slot.as_mut() {
                Some(s) if s.state == ExtAdvState::Active => s,
                _ => continue,
            };
            set.elapsed_ticks += 1;
            set.events_sent += 1;
            set.tx_count += 1;

            let duration_expired = set.duration_10ms > 0
                && set.elapsed_ticks >= u32::from(set.duration_10ms);
            let events_exhausted =
                set.max_events > 0 && set.events_sent >= u32::from(set.max_events);

            if duration_expired || events_exhausted {
                set.state = ExtAdvState::Configured;
                disabled += 1;
            }
        }
        disabled
    }
}
