// SPDX-License-Identifier: GPL-2.0

//! SparkLink UART serial device (serdev) driver skeleton.
//!
//! This module provides the hardware-binding layer for UART-attached
//! SparkLink controllers. It follows the same pattern as the Bluetooth
//! `hci_serdev.c` / `hci_ldisc.c` drivers:
//!
//!   Device tree / ACPI → serdev match → probe → sle_attach_device
//!
//! The actual serdev API is not yet available as Rust bindings in the
//! kernel. This file defines the attach/detach skeleton and documents
//! the intended integration points. When Rust serdev bindings land,
//! the probe function will be called by the serdev core and the
//! `SleSerdevData` struct will gain a reference to `serdev_device`.
//!
//! UART transport flow:
//!
//! ```text
//!   serdev_device_ops::receive_buf() → UartParser::feed_bytes()
//!                                    → SleEvent queue
//!                                    → EventPump picks up via poll_event()
//!
//!   send_command() → encode_command() → serdev_device_write_buf()
//! ```
//!
//! Device tree binding example:
//!
//! ```dts
//!   &uart2 {
//!       sparklink {
//!           compatible = "sparklink,sle-h4";
//!           max-speed = <1000000>;
//!       };
//!   };
//! ```

#![allow(dead_code)]

use kernel::prelude::*;

use super::sle_transport::{SleAttachInfo, SleProtoId};

// =========================================================================
// Constants
// =========================================================================

/// Default initial baud rate for UART attached controllers.
pub(crate) const DEFAULT_INIT_SPEED: u32 = 115_200;

/// Operational baud rate after firmware handshake (speed change).
pub(crate) const DEFAULT_OPER_SPEED: u32 = 1_000_000;

/// Compatible string for device tree matching.
pub(crate) const DT_COMPATIBLE: &str = "sparklink,sle-h4";

// =========================================================================
// Serdev driver data
// =========================================================================

/// Per-device state for a serdev-attached SLE controller.
///
/// Constructed during serdev probe and stored as driver data on the
/// `serdev_device`. When Rust serdev bindings become available, this
/// struct will hold `Arc<serdev_device>` for write-back.
pub(crate) struct SleSerdevData {
    /// Device id assigned by `sle_attach_device()`.
    dev_id: u16,
    /// Initial baud rate used during probe.
    init_speed: u32,
    /// Operational baud rate after speed change.
    oper_speed: u32,
}

impl SleSerdevData {
    /// Create a new serdev data record.
    fn new(dev_id: u16, init_speed: u32, oper_speed: u32) -> Self {
        Self {
            dev_id,
            init_speed,
            oper_speed,
        }
    }

    /// Device id in the SleDevRegistry.
    pub(crate) fn dev_id(&self) -> u16 {
        self.dev_id
    }
}

// =========================================================================
// Probe / remove stubs
// =========================================================================
//
// These functions implement the serdev_device_driver .probe and .remove
// callbacks. In a real build they will be called by the serdev core
// when a matching device tree node or ACPI entry is found.
//
// Until Rust serdev bindings exist, these are invoked by the integration
// test helper or from module parameters for development.

/// Probe callback for a UART-attached SLE controller.
///
/// Steps (matching hci_uart_register_dev / hci_serdev_register):
/// 1. Open the serial port at `init_speed`.
/// 2. Read the controller MAC address (ReadMacAddr, opcode 0x0406).
/// 3. Optionally negotiate higher baud rate (`oper_speed`).
/// 4. Call `sle_attach_device()` to register in the subsystem.
///
/// Returns the allocated device id on success.
pub(crate) fn serdev_probe(
    addr: [u8; 6],
    init_speed: u32,
    oper_speed: u32,
) -> Result<SleSerdevData> {
    pr_info!(
        "sparklink-serdev: probe init_speed={} oper_speed={}\n",
        init_speed,
        oper_speed,
    );

    let mut attach = SleAttachInfo::new(SleProtoId::H4Uart, addr);
    // Real driver would read these from the controller after reset.
    attach.fw_version = 0;
    attach.features = 0;

    let dev_id = super::sle_attach_device(&attach)?;
    pr_info!("sparklink-serdev: attached as sle{}\n", dev_id);

    Ok(SleSerdevData::new(dev_id, init_speed, oper_speed))
}

/// Remove callback for a UART-attached SLE controller.
pub(crate) fn serdev_remove(data: &SleSerdevData) {
    pr_info!("sparklink-serdev: remove sle{}\n", data.dev_id);
    super::sle_detach_device(data.dev_id);
}
