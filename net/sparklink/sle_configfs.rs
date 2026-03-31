// SPDX-License-Identifier: GPL-2.0

//! SparkLink configfs interface.
//!
//! Exposes runtime-configurable parameters under
//! `/sys/kernel/config/sparklink/`:
//!
//! - `version` (read-only): protocol stack version string
//! - `max_connections` (read/write): maximum simultaneous connections (1..8)
//! - `adv_interval_ms` (read/write): default advertising interval
//! - `scan_window_ms` (read/write): default scan window
//! - `power_mode` (read/write): power management mode (active/sniff/idle)

use kernel::configfs;
use kernel::new_mutex;
use kernel::page::PAGE_SIZE;
use kernel::prelude::*;
use kernel::sync::Mutex;

use core::sync::atomic::{AtomicU8, AtomicU16, Ordering};

const VERSION_STR: &[u8] = b"0.3.0\n";

static MAX_CONNECTIONS: AtomicU8 = AtomicU8::new(8);
static ADV_INTERVAL_MS: AtomicU16 = AtomicU16::new(100);
static SCAN_WINDOW_MS: AtomicU16 = AtomicU16::new(200);
static POWER_MODE: AtomicU8 = AtomicU8::new(0);
static CONTROLLER_TYPE: AtomicU8 = AtomicU8::new(0);

/// Get the configured controller type.
/// 0 = Virtual, 1 = UART, 2 = SPI.
pub(crate) fn controller_type() -> u8 {
    CONTROLLER_TYPE.load(Ordering::Relaxed)
}

/// Get the configured maximum number of connections (1..8).
pub(crate) fn max_connections() -> u8 {
    MAX_CONNECTIONS.load(Ordering::Relaxed)
}

/// Get the configured default advertising interval in milliseconds.
#[allow(dead_code)]
pub(crate) fn adv_interval_ms() -> u16 {
    ADV_INTERVAL_MS.load(Ordering::Relaxed)
}

/// Get the configured default scan window in milliseconds.
#[allow(dead_code)]
pub(crate) fn scan_window_ms() -> u16 {
    SCAN_WINDOW_MS.load(Ordering::Relaxed)
}

#[pin_data]
pub(crate) struct SparkLinkConfig {
    #[pin]
    _dummy: Mutex<()>,
}

impl SparkLinkConfig {
    pub(crate) fn new() -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            _dummy <- new_mutex!(()),
        })
    }
}

/// Format a u32 into a decimal string followed by newline.
/// Returns the number of bytes written.
fn int_to_page(val: u32, page: &mut [u8; PAGE_SIZE]) -> usize {
    if val == 0 {
        page[0] = b'0';
        page[1] = b'\n';
        return 2;
    }
    let mut tmp = [0u8; 12];
    let mut n = val;
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        page[j] = tmp[i - 1 - j];
    }
    page[i] = b'\n';
    i + 1
}

// Attribute 0: version (read-only)
#[vtable]
impl configfs::AttributeOperations<0> for SparkLinkConfig {
    type Data = SparkLinkConfig;

    fn show(_data: &SparkLinkConfig, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        page[..VERSION_STR.len()].copy_from_slice(VERSION_STR);
        Ok(VERSION_STR.len())
    }
}

// Attribute 1: max_connections (read/write, 1..8)
#[vtable]
impl configfs::AttributeOperations<1> for SparkLinkConfig {
    type Data = SparkLinkConfig;

    fn show(_data: &SparkLinkConfig, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let val = MAX_CONNECTIONS.load(Ordering::Relaxed);
        Ok(int_to_page(val as u32, page))
    }

    fn store(_data: &SparkLinkConfig, page: &[u8]) -> Result {
        let s = core::str::from_utf8(page).map_err(|_| EINVAL)?;
        let val: u8 = s.trim().parse().map_err(|_| EINVAL)?;
        if val == 0 || val > 8 {
            return Err(EINVAL);
        }
        MAX_CONNECTIONS.store(val, Ordering::Relaxed);
        Ok(())
    }
}

// Attribute 2: adv_interval_ms (read/write, 20..10240)
#[vtable]
impl configfs::AttributeOperations<2> for SparkLinkConfig {
    type Data = SparkLinkConfig;

    fn show(_data: &SparkLinkConfig, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let val = ADV_INTERVAL_MS.load(Ordering::Relaxed);
        Ok(int_to_page(val as u32, page))
    }

    fn store(_data: &SparkLinkConfig, page: &[u8]) -> Result {
        let s = core::str::from_utf8(page).map_err(|_| EINVAL)?;
        let val: u16 = s.trim().parse().map_err(|_| EINVAL)?;
        if val < 20 || val > 10240 {
            return Err(EINVAL);
        }
        ADV_INTERVAL_MS.store(val, Ordering::Relaxed);
        Ok(())
    }
}

// Attribute 3: scan_window_ms (read/write, 10..10240)
#[vtable]
impl configfs::AttributeOperations<3> for SparkLinkConfig {
    type Data = SparkLinkConfig;

    fn show(_data: &SparkLinkConfig, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let val = SCAN_WINDOW_MS.load(Ordering::Relaxed);
        Ok(int_to_page(val as u32, page))
    }

    fn store(_data: &SparkLinkConfig, page: &[u8]) -> Result {
        let s = core::str::from_utf8(page).map_err(|_| EINVAL)?;
        let val: u16 = s.trim().parse().map_err(|_| EINVAL)?;
        if val < 10 || val > 10240 {
            return Err(EINVAL);
        }
        SCAN_WINDOW_MS.store(val, Ordering::Relaxed);
        Ok(())
    }
}

// Attribute 4: power_mode (read/write, 0=active, 1=sniff, 2=idle)
#[vtable]
impl configfs::AttributeOperations<4> for SparkLinkConfig {
    type Data = SparkLinkConfig;

    fn show(_data: &SparkLinkConfig, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let mode = POWER_MODE.load(Ordering::Relaxed);
        let label = match mode {
            0 => b"active\n" as &[u8],
            1 => b"sniff\n",
            2 => b"idle\n",
            _ => b"unknown\n",
        };
        page[..label.len()].copy_from_slice(label);
        Ok(label.len())
    }

    fn store(_data: &SparkLinkConfig, page: &[u8]) -> Result {
        let s = core::str::from_utf8(page).map_err(|_| EINVAL)?;
        let val = match s.trim() {
            "active" | "0" => 0u8,
            "sniff" | "1" => 1u8,
            "idle" | "2" => 2u8,
            _ => return Err(EINVAL),
        };
        POWER_MODE.store(val, Ordering::Relaxed);
        Ok(())
    }
}

// Attribute 5: controller_type (read/write, 0=virtual, 1=uart, 2=spi)
#[vtable]
impl configfs::AttributeOperations<5> for SparkLinkConfig {
    type Data = SparkLinkConfig;

    fn show(_data: &SparkLinkConfig, page: &mut [u8; PAGE_SIZE]) -> Result<usize> {
        let ct = CONTROLLER_TYPE.load(Ordering::Relaxed);
        let label = match ct {
            0 => b"virtual\n" as &[u8],
            1 => b"uart\n",
            2 => b"spi\n",
            _ => b"unknown\n",
        };
        page[..label.len()].copy_from_slice(label);
        Ok(label.len())
    }

    fn store(_data: &SparkLinkConfig, page: &[u8]) -> Result {
        let s = core::str::from_utf8(page).map_err(|_| EINVAL)?;
        let val = match s.trim() {
            "virtual" | "0" => 0u8,
            "uart" | "1" => 1u8,
            "spi" | "2" => 2u8,
            _ => return Err(EINVAL),
        };
        CONTROLLER_TYPE.store(val, Ordering::Relaxed);
        pr_info!("sparklink: controller_type set to {}\n", val);
        Ok(())
    }
}
