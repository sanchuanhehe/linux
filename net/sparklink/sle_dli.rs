// SPDX-License-Identifier: GPL-2.0

//! SparkLink Driver Layer Interface (DLI).
//!
//! This module defines the abstract interface between the SparkLink protocol
//! stack core and hardware controller drivers.  Every SLE radio chip driver
//! implements the [`SleController`] trait; the core dispatches operations
//! through this trait without knowing the underlying transport (UART, SPI,
//! USB, platform MMIO, or virtual loopback).
//!
//! The design mirrors how Bluetooth HCI separates the host stack from the
//! controller driver: `SleController` is the SLE equivalent of
//! `struct hci_dev`.

#![allow(dead_code, unreachable_pub)]

use kernel::prelude::*;
use kernel::alloc::KVec;

// ---------------------------------------------------------------------------
// Controller capabilities
// ---------------------------------------------------------------------------

/// Transport bus type between the host and the SLE controller.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleBus {
    Virtual = 0,
    Uart    = 1,
    Spi     = 2,
    Sdio    = 3,
    Usb     = 4,
    Mmio    = 5,
}

/// Feature flags advertised by a controller.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleFeature {
    /// Controller supports SLE advertising.
    Advertising  = 1 << 0,
    /// Controller supports SLE scanning.
    Scanning     = 1 << 1,
    /// Controller supports SLE connections.
    Connection   = 1 << 2,
    /// Controller supports hardware SM4 encryption.
    HwCrypto     = 1 << 3,
    /// Controller supports low-power sniff mode.
    Sniff        = 1 << 4,
    /// Controller supports multiple simultaneous connections.
    MultiLink    = 1 << 5,
}

/// Static information about a controller.
pub struct SleControllerInfo {
    /// Human-readable name (e.g. "WS63-SLE").
    pub name: [u8; 32],
    /// Transport bus type.
    pub bus: SleBus,
    /// 6-byte SLE MAC address burned into the chip.
    pub addr: [u8; 6],
    /// Firmware version as a packed u32 (major.minor.patch).
    pub fw_version: u32,
    /// Bitmask of supported features (see [`SleFeature`]).
    pub features: u32,
    /// Maximum PDU payload size in bytes.
    pub max_pdu_payload: u16,
    /// Maximum number of concurrent connections (0 = unlimited).
    pub max_connections: u8,
}

impl Default for SleControllerInfo {
    fn default() -> Self {
        Self {
            name: [0u8; 32],
            bus: SleBus::Virtual,
            addr: [0u8; 6],
            fw_version: 0,
            features: 0,
            max_pdu_payload: 255,
            max_connections: 1,
        }
    }
}

impl SleControllerInfo {
    /// Check whether a feature is supported.
    pub fn has_feature(&self, f: SleFeature) -> bool {
        self.features & (f as u32) != 0
    }
}

// ---------------------------------------------------------------------------
// HCI-like command/event model
// ---------------------------------------------------------------------------

/// Opcode for commands sent from host to controller.
///
/// Loosely mirrors the SparkLink standard command groups.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleOpcode {
    // --- Link layer control ---
    Reset          = 0x0001,
    SetAddr        = 0x0002,
    ReadAddr       = 0x0003,

    // --- Advertising ---
    SetAdvParams   = 0x0101,
    SetAdvData     = 0x0102,
    AdvEnable      = 0x0103,
    AdvDisable     = 0x0104,

    // --- Scanning ---
    SetScanParams  = 0x0201,
    ScanEnable     = 0x0202,
    ScanDisable    = 0x0203,

    // --- Connection ---
    CreateConn     = 0x0301,
    Disconnect     = 0x0302,
    SendData       = 0x0303,
    SetConnParams  = 0x0304,

    // --- Security ---
    SetPsk         = 0x0401,
    StartPairing   = 0x0402,
    EncryptEnable  = 0x0403,

    // --- Power ---
    SetPowerMode   = 0x0501,
    Suspend        = 0x0502,
    Resume         = 0x0503,

    // --- Vendor-specific (0xF000–0xFFFF) ---
    VendorBase     = 0xF000,
}

/// Completion status for a command.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleStatus {
    Success             = 0x00,
    UnknownCommand      = 0x01,
    InvalidParameters   = 0x02,
    HardwareFailure     = 0x03,
    ResourceExhausted   = 0x04,
    NotConnected        = 0x05,
    AlreadyActive       = 0x06,
    PermissionDenied    = 0x07,
    Timeout             = 0x08,
}

/// An event from the controller to the host.
pub enum SleEvent {
    /// Command completed with status.
    CommandComplete {
        opcode: SleOpcode,
        status: SleStatus,
        data: KVec<u8>,
    },
    /// An advertising report was received during scanning.
    AdvReport {
        addr: [u8; 6],
        rssi: i8,
        data: KVec<u8>,
    },
    /// A connection request was received.
    ConnRequest {
        addr: [u8; 6],
        role: u8,
    },
    /// Connection established.
    ConnComplete {
        handle: u16,
        addr: [u8; 6],
        status: SleStatus,
    },
    /// Data received on a connection.
    DataReceived {
        handle: u16,
        data: KVec<u8>,
    },
    /// Connection lost.
    Disconnected {
        handle: u16,
        reason: u8,
    },
    /// Controller error requiring attention.
    HardwareError {
        code: u8,
    },
}

// ---------------------------------------------------------------------------
// Controller trait — the DLI
// ---------------------------------------------------------------------------

/// The SparkLink Driver Layer Interface.
///
/// Each SLE controller driver (UART, SPI, virtual, etc.) implements this
/// trait.  The protocol stack core holds a reference to the active controller
/// and calls these methods to drive the radio.
///
/// All methods are synchronous from the caller's perspective; the driver is
/// responsible for internal buffering and IRQ handling.
pub trait SleController: Send + Sync {
    /// Return static controller info (name, bus, address, capabilities).
    fn info(&self) -> SleControllerInfo;

    /// Open the controller.  Called once when the first userspace fd opens
    /// `/dev/sparklink`.  Drivers should power on the radio and perform
    /// initial firmware handshake.
    fn open(&self) -> Result;

    /// Close the controller.  Called when the last userspace fd closes.
    fn close(&self);

    /// Send a host-to-controller command.
    ///
    /// `opcode` identifies the command.  `params` carries opcode-specific
    /// payload bytes.  The driver should return `Ok(())` once the command
    /// is accepted; asynchronous results are delivered via
    /// [`SleController::poll_event`].
    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result;

    /// Send raw data on a connection.
    ///
    /// `handle` identifies the connection.  The driver queues the data for
    /// transmission and returns immediately.
    fn send_data(&self, handle: u16, data: &[u8]) -> Result;

    /// Poll for the next pending event from the controller.
    ///
    /// Returns `None` if no event is available.  The core calls this from a
    /// workqueue context or in response to an IRQ notification.
    fn poll_event(&self) -> Option<SleEvent>;

    /// Reset the controller to a known-good state.
    fn reset(&self) -> Result;
}

// ---------------------------------------------------------------------------
// Virtual controller (built-in to the DLI module for testing)
// ---------------------------------------------------------------------------

/// A purely software-based SLE controller for testing.
///
/// All operations are loopback: advertising data is immediately available
/// as scan results, connections are looped back locally, etc.
pub struct VirtualController {
    addr: [u8; 6],
    opened: bool,
}

impl VirtualController {
    /// Create a new virtual controller with the given address.
    pub fn new(addr: [u8; 6]) -> Self {
        Self { addr, opened: false }
    }
}

impl SleController for VirtualController {
    fn info(&self) -> SleControllerInfo {
        let mut info = SleControllerInfo::default();
        let name = b"sparklink-virtual";
        info.name[..name.len()].copy_from_slice(name);
        info.bus = SleBus::Virtual;
        info.addr = self.addr;
        info.fw_version = 0x0001_0000; // 1.0.0
        info.features = (SleFeature::Advertising as u32)
            | (SleFeature::Scanning as u32)
            | (SleFeature::Connection as u32);
        info.max_pdu_payload = 255;
        info.max_connections = 1;
        info
    }

    fn open(&self) -> Result {
        if self.opened {
            return Err(EBUSY);
        }
        pr_info!("sparklink-virtual: controller opened\n");
        Ok(())
    }

    fn close(&self) {
        pr_info!("sparklink-virtual: controller closed\n");
    }

    fn send_command(&self, opcode: SleOpcode, _params: &[u8]) -> Result {
        pr_debug!("sparklink-virtual: cmd {:?}\n", opcode);
        Ok(())
    }

    fn send_data(&self, handle: u16, data: &[u8]) -> Result {
        pr_debug!("sparklink-virtual: data tx handle={} len={}\n", handle, data.len());
        Ok(())
    }

    fn poll_event(&self) -> Option<SleEvent> {
        None
    }

    fn reset(&self) -> Result {
        pr_info!("sparklink-virtual: controller reset\n");
        Ok(())
    }
}
