// SPDX-License-Identifier: GPL-2.0

//! Virtual SparkLink controller driver for testing.
//!
//! This driver registers a virtual SCI device that can be used to test the
//! SparkLink protocol stack without real hardware. It emulates a SparkLink
//! SLE controller, responding to SCI commands with simulated behavior.

use kernel::prelude::*;

module! {
    type: SparkLinkVirtual,
    name: "sparklink_virtual",
    authors: ["SparkLink for Linux Contributors"],
    description: "Virtual SparkLink controller driver",
    license: "GPL",
}

struct SparkLinkVirtual;

impl kernel::Module for SparkLinkVirtual {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("sparklink_virtual: virtual controller loaded\n");
        Ok(SparkLinkVirtual)
    }
}

impl Drop for SparkLinkVirtual {
    fn drop(&mut self) {
        pr_info!("sparklink_virtual: virtual controller unloaded\n");
    }
}
