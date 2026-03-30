// SPDX-License-Identifier: GPL-2.0

//! SLE power management state machine.
//!
//! Manages low-power states for SLE connections following a model
//! similar to BLE connection parameter management:
//!
//!   - Active: normal operation, all events processed
//!   - Sniff: reduced duty-cycle, periodic wake windows
//!   - Idle: minimal activity, only supervisory keepalives
//!   - Suspended: device-level suspend, no radio activity
//!
//! Connection interval and supervision timeout are tracked per-link.
//! Force-active override allows upper layers (e.g., security handshake)
//! to prevent power saving during critical operations.

#![allow(dead_code, unreachable_pub)]

use kernel::prelude::*;

// ---------------------------------------------------------------------------
// Power states
// ---------------------------------------------------------------------------

/// Power management states for an SLE link.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum PowerState {
    /// Normal operation; all connection events processed.
    #[default]
    Active = 0,
    /// Reduced duty-cycle; periodic wake windows for data exchange.
    Sniff = 1,
    /// Minimal activity; only supervisory keepalives.
    Idle = 2,
    /// Device-level suspend; no radio activity.
    Suspended = 3,
}

// ---------------------------------------------------------------------------
// Connection interval parameters
// ---------------------------------------------------------------------------

/// Connection timing parameters (units: 1.25 ms slots, matching SLE spec).
#[derive(Copy, Clone, Debug)]
pub struct ConnInterval {
    /// Minimum connection interval in 1.25 ms units (6..3200 → 7.5 ms..4 s).
    pub min_interval: u16,
    /// Maximum connection interval in 1.25 ms units.
    pub max_interval: u16,
    /// Current connection interval.
    pub current_interval: u16,
    /// Peripheral latency: number of consecutive connection events
    /// the peripheral may skip.
    pub latency: u16,
    /// Supervision timeout in 10 ms units (10..3200 → 100 ms..32 s).
    pub supervision_timeout: u16,
}

impl Default for ConnInterval {
    fn default() -> Self {
        Self {
            min_interval: 24,   // 30 ms
            max_interval: 40,   // 50 ms
            current_interval: 32, // 40 ms
            latency: 0,
            supervision_timeout: 200, // 2 s
        }
    }
}

impl ConnInterval {
    /// Validate that proposed parameters are within SLE specification limits.
    pub fn validate(&self) -> Result {
        // Min interval: 6 (7.5 ms) to 3200 (4 s)
        if self.min_interval < 6 || self.min_interval > 3200 {
            return Err(EINVAL);
        }
        if self.max_interval < self.min_interval || self.max_interval > 3200 {
            return Err(EINVAL);
        }
        // Supervision timeout must be > (1 + latency) * max_interval * 2
        let min_timeout = ((1 + self.latency as u32) * self.max_interval as u32 * 2) / 8;
        if (self.supervision_timeout as u32) < min_timeout {
            return Err(EINVAL);
        }
        if self.supervision_timeout < 10 || self.supervision_timeout > 3200 {
            return Err(EINVAL);
        }
        Ok(())
    }

    /// Get the current interval in milliseconds.
    pub fn current_ms(&self) -> u32 {
        (self.current_interval as u32) * 125 / 100 // 1.25 ms per unit
    }

    /// Get the supervision timeout in milliseconds.
    pub fn supervision_timeout_ms(&self) -> u32 {
        self.supervision_timeout as u32 * 10
    }
}

// ---------------------------------------------------------------------------
// Sniff mode parameters
// ---------------------------------------------------------------------------

/// Sniff mode timing parameters.
#[derive(Copy, Clone, Debug)]
pub struct SniffParams {
    /// Sniff interval in 1.25 ms units: how often the device wakes.
    pub sniff_interval: u16,
    /// Sniff window in 1.25 ms units: how long the device stays awake.
    pub sniff_window: u16,
    /// Maximum number of sniff attempts before giving up.
    pub sniff_attempt: u16,
    /// Sniff timeout: time to wait for data before returning to sniff.
    pub sniff_timeout: u16,
}

impl Default for SniffParams {
    fn default() -> Self {
        Self {
            sniff_interval: 800,  // 1 s
            sniff_window: 16,     // 20 ms
            sniff_attempt: 4,
            sniff_timeout: 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Power management statistics
// ---------------------------------------------------------------------------

/// Power management statistics for monitoring and tuning.
#[derive(Copy, Clone, Debug, Default)]
pub struct PowerStats {
    /// Total time in Active state (in connection-event counts).
    pub active_events: u64,
    /// Total time in Sniff state.
    pub sniff_events: u64,
    /// Total time in Idle state.
    pub idle_events: u64,
    /// Number of state transitions.
    pub transitions: u32,
    /// Number of forced active activations.
    pub force_active_count: u32,
    /// Number of supervision timeout warnings.
    pub supervision_warnings: u32,
}

// ---------------------------------------------------------------------------
// Power management inner state
// ---------------------------------------------------------------------------

/// Per-connection power management state.
pub struct PowerInner {
    /// Current power state.
    pub state: PowerState,
    /// Connection interval parameters.
    pub interval: ConnInterval,
    /// Sniff mode parameters (used when state == Sniff).
    pub sniff: SniffParams,
    /// Force-active flag: prevents entering power-saving modes.
    force_active: bool,
    /// Number of connection events since last data exchange.
    idle_count: u32,
    /// Threshold: enter sniff after this many idle events.
    sniff_threshold: u32,
    /// Threshold: enter idle after this many sniff intervals with no data.
    idle_threshold: u32,
    /// Power statistics.
    pub stats: PowerStats,
}

impl PowerInner {
    /// Create power management state with default parameters.
    pub fn new() -> Self {
        Self {
            state: PowerState::Active,
            interval: ConnInterval::default(),
            sniff: SniffParams::default(),
            force_active: false,
            idle_count: 0,
            sniff_threshold: 50,   // enter sniff after ~50 idle events
            idle_threshold: 200,   // enter idle after ~200 sniff intervals
            stats: PowerStats::default(),
        }
    }

    /// Update connection interval parameters.
    pub fn update_interval(&mut self, params: ConnInterval) -> Result {
        params.validate()?;
        self.interval = params;
        self.interval.current_interval = params.min_interval;
        Ok(())
    }

    /// Set sniff mode parameters.
    pub fn set_sniff_params(&mut self, params: SniffParams) {
        self.sniff = params;
    }

    /// Force active mode (prevents power saving).
    pub fn force_active(&mut self, enable: bool) {
        self.force_active = enable;
        if enable {
            self.stats.force_active_count += 1;
            if self.state != PowerState::Active {
                self.transition_to(PowerState::Active);
            }
        }
    }

    /// Check if force-active is currently set.
    pub fn is_forced_active(&self) -> bool {
        self.force_active
    }

    /// Record a data activity event — resets the idle counter
    /// and may transition back to Active from a low-power state.
    pub fn on_activity(&mut self) {
        self.idle_count = 0;
        if self.state != PowerState::Active && !self.force_active {
            self.transition_to(PowerState::Active);
        }
        self.stats.active_events += 1;
    }

    /// Called on each connection event tick to advance power state machine.
    /// Should be called once per connection interval by the link layer.
    pub fn on_tick(&mut self) {
        if self.state == PowerState::Suspended {
            return;
        }

        self.idle_count += 1;

        match self.state {
            PowerState::Active => {
                self.stats.active_events += 1;
                if !self.force_active && self.idle_count >= self.sniff_threshold {
                    self.transition_to(PowerState::Sniff);
                }
            }
            PowerState::Sniff => {
                self.stats.sniff_events += 1;
                if self.idle_count >= self.sniff_threshold + self.idle_threshold {
                    self.transition_to(PowerState::Idle);
                }
            }
            PowerState::Idle => {
                self.stats.idle_events += 1;
                // Stay in idle; only activity or explicit resume can exit
            }
            PowerState::Suspended => {}
        }
    }

    /// Suspend the device (enter deep sleep).
    pub fn suspend(&mut self) -> Result {
        if self.force_active {
            return Err(EBUSY);
        }
        self.transition_to(PowerState::Suspended);
        Ok(())
    }

    /// Resume from suspend.
    pub fn resume(&mut self) {
        self.transition_to(PowerState::Active);
        self.idle_count = 0;
    }

    /// Get estimated power consumption ratio (0-100).
    /// Active=100, Sniff=30, Idle=5, Suspended=0.
    pub fn estimated_power_pct(&self) -> u8 {
        match self.state {
            PowerState::Active => 100,
            PowerState::Sniff => {
                // Duty cycle based on window/interval ratio
                let duty = (self.sniff.sniff_window as u32 * 100)
                    / self.sniff.sniff_interval.max(1) as u32;
                duty.min(100) as u8
            }
            PowerState::Idle => 5,
            PowerState::Suspended => 0,
        }
    }

    fn transition_to(&mut self, new_state: PowerState) {
        if self.state != new_state {
            self.state = new_state;
            self.stats.transitions += 1;
        }
    }
}
