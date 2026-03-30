// SPDX-License-Identifier: GPL-2.0

//! SparkLink Driver Layer Interface (DLI).
//!
//! Defines the abstract interface between the SparkLink host protocol
//! stack and hardware controller drivers, following T/XS 10003-2025.
//! Every SLE radio chip driver implements the [`SleController`] trait;
//! the core dispatches operations through this trait without knowing
//! the underlying transport (USB, UART, SPI, SDIO, or virtual loopback).
//!
//! The DLI packet model uses typed channels identical to the standard:
//!   - Command (Host → Controller): opcode + parameters
//!   - Event   (Controller → Host): event code + parameters
//!   - Async unicast data: link_id + payload
//!   - Sync unicast data:  link_id + payload
//!   - Async multicast data
//!
//! Opcode encoding follows TXS-10003-2025: upper 6 bits = command
//! group (OGF), lower 10 bits = command within the group (OCF).

#![allow(dead_code, unreachable_pub)]

use kernel::prelude::*;
use kernel::alloc::KVec;
use core::cell::Cell;

// ---------------------------------------------------------------------------
// DLI packet type indicators (T/XS 10003-2025 section 5.1)
// ---------------------------------------------------------------------------

/// DLI packet type byte on the transport layer.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DliPacketType {
    /// Host-to-controller command.
    Command       = 0xA1,
    /// Controller-to-host event.
    Event         = 0xA2,
    /// Asynchronous unicast data.
    AsyncUnicast  = 0xA3,
    /// Synchronous unicast data.
    SyncUnicast   = 0xA4,
    /// Asynchronous multicast data.
    AsyncMulticast = 0xA5,
}

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

/// Feature bits from the 10-byte (80-bit) feature set (T/XS 10003-2025).
///
/// Stored as a bitmask in `SleControllerInfo::features`.
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleFeature {
    Encryption       = 1 << 0,
    DataLenUpdate    = 1 << 1,
    Ping             = 1 << 2,
    FilterPolicy     = 1 << 3,
    Privacy          = 1 << 4,
    FrameType2       = 1 << 5,
    FrameType3       = 1 << 6,
    FrameType4       = 1 << 7,
    Bw2m             = 1 << 8,
    Bw4m             = 1 << 9,
    Pilot4to1        = 1 << 10,
    Pilot8to1        = 1 << 11,
    Pilot16to1       = 1 << 12,
    Crc32            = 1 << 13,
    Mcs0             = 1 << 14,
    Mcs1             = 1 << 15,
    Mcs2             = 1 << 16,
    Mcs3             = 1 << 17,
    Mcs4             = 1 << 18,
    Mcs5             = 1 << 19,
    Mcs6             = 1 << 20,
    Mcs7             = 1 << 21,
    Mcs8             = 1 << 22,
    Mcs9             = 1 << 23,
    Mcs10            = 1 << 24,
    Mcs11            = 1 << 25,
    Mcs12            = 1 << 26,
    TxRxGap25us      = 1 << 27,
    TxRxGap50us      = 1 << 28,
    TxRxGap75us      = 1 << 29,
    TxRxGap100us     = 1 << 30,
}

/// Static information about a controller.
pub struct SleControllerInfo {
    /// Human-readable name (e.g. "WS63-SLE").
    pub name: [u8; 32],
    /// Transport bus type.
    pub bus: SleBus,
    /// 6-byte SLE MAC address.
    pub addr: [u8; 6],
    /// Firmware version as a packed u32 (major.minor.patch).
    pub fw_version: u32,
    /// Bitmask of supported features (see [`SleFeature`]).
    pub features: u64,
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
        self.features & (f as u64) != 0
    }
}

// ---------------------------------------------------------------------------
// DLI command opcode encoding (T/XS 10003-2025)
//
// Format:  [15:10] = OGF (command group)  [9:0] = OCF (command index)
// ---------------------------------------------------------------------------

/// Command group identifiers (OGF, upper 6 bits of opcode).
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DliOgf {
    /// Group 1: Basic commands (0x04xx) — reset, address, features.
    Basic           = 0x01,
    /// Group 3: Broadcast / advertising (0x0Cxx).
    Broadcast       = 0x03,
    /// Group 4: Scan (0x10xx).
    Scan            = 0x04,
    /// Group 5: Connection (0x14xx).
    Connection      = 0x05,
    /// Group 6: Link control / PHY (0x18xx).
    LinkControl     = 0x06,
    /// Group 7: Security (0x1Cxx).
    Security        = 0x07,
    /// Group 8: Measurement (0x20xx).
    Measurement     = 0x08,
    /// Group 10: Sync link (0x28xx).
    SyncLink        = 0x0A,
    /// Group 62: Test / vendor (0xF8xx).
    Test            = 0x3E,
}

/// Build a DLI opcode from OGF and OCF.
pub const fn dli_opcode(ogf: u16, ocf: u16) -> u16 {
    (ogf << 10) | (ocf & 0x03FF)
}

/// Extract OGF from a DLI opcode.
pub const fn dli_ogf(opcode: u16) -> u16 {
    opcode >> 10
}

/// Extract OCF from a DLI opcode.
pub const fn dli_ocf(opcode: u16) -> u16 {
    opcode & 0x03FF
}

/// Well-known DLI command opcodes from T/XS 10003-2025.
///
/// Encoded as `(OGF << 10) | OCF` following the standard.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleOpcode {
    // --- Group 1: Basic (OGF=0x01, wire prefix 0x04xx) ---
    Reset               = 0x0401,
    ReadLocalVersion     = 0x0402,
    ReadLocalFeatures    = 0x0403,
    ReadLocalAddr        = 0x0404,
    SetMacAddr           = 0x0405,
    ReadBufferSize       = 0x0406,
    SetEventMask         = 0x0407,

    // --- Group 3: Broadcast (OGF=0x03, wire prefix 0x0Cxx) ---
    SetBroadcastParam    = 0x0C01,
    SetBroadcastData     = 0x0C02,
    SetBroadcastScanRsp  = 0x0C03,
    EnableBroadcast      = 0x0C04,

    // --- Group 4: Scan (OGF=0x04, wire prefix 0x10xx) ---
    SetScanParam         = 0x1001,
    EnableScan           = 0x1002,

    // --- Group 5: Connection (OGF=0x05, wire prefix 0x14xx) ---
    CreateConnection     = 0x1401,
    Disconnect           = 0x1402,
    SetConnParam         = 0x1403,
    ReadConnParam        = 0x1404,
    ConnParamReqReply    = 0x1405,
    ReadFeatures         = 0x1406,
    ReadVersion          = 0x1407,
    ReadRssi             = 0x1408,

    // --- Group 6: Link control (OGF=0x06, wire prefix 0x18xx) ---
    SetPhyParam          = 0x1801,
    ReadPhyParam         = 0x1802,
    SetTxPower           = 0x1803,
    ReadTxPower          = 0x1804,
    SetMaxDataLen        = 0x1805,
    ReadMaxDataLen       = 0x1806,

    // --- Group 7: Security (OGF=0x07, wire prefix 0x1Cxx) ---
    RequestPair          = 0x1C01,
    PairResponse         = 0x1C02,
    PairPublicKey        = 0x1C03,
    PairDhCheck          = 0x1C04,
    SetPairPsk           = 0x1C05,
    SetPairSk            = 0x1C06,
    SetPairPassword      = 0x1C07,
    PairPasskey          = 0x1C0D,
    PairRandom           = 0x1C0E,
    PairConfirm          = 0x1C0F,
    DhkeyVerify          = 0x1C10,
    PairFail             = 0x1C11,
    StartEncrypt         = 0x1C08,
    AddRalDevice         = 0x1C12,
    ClearRal             = 0x1C14,
    ReadRalSize          = 0x1C15,
    SetRpaEnable         = 0x1C18,
    SetRpaTimeout        = 0x1C19,

    // --- Group 8: Measurement (OGF=0x08, wire prefix 0x20xx) ---
    ReadLocalMeasCap     = 0x2001,
    SetMeasLinkParam     = 0x2003,
    MeasAction           = 0x2005,
    EnableMeas           = 0x200B,

    // --- Group 10: Sync link (OGF=0x0A, wire prefix 0x28xx) ---
    SyncUcastParam       = 0x2801,
    SyncUcastCreate      = 0x2803,
    SyncUcastRemove      = 0x2804,

    // --- Group 62: Test / vendor (OGF=0x3E, wire prefix 0xF8xx) ---
    TestModeEnable       = 0xF801,
    TestRx               = 0xF802,
    TestTx               = 0xF803,
    TestRxResult         = 0xF804,

    // --- Vendor extension (0xFC00–0xFFFF) ---
    VendorBase           = 0xFC00,
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

// ---------------------------------------------------------------------------
// DLI event codes (Controller → Host, T/XS 10003-2025)
// ---------------------------------------------------------------------------

/// Event codes from the controller.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DliEventCode {
    /// Async command status (Pending).
    CmdStatus           = 0x0001,
    /// Command complete with return parameters.
    CmdComplete         = 0x0002,
    /// RX data length change.
    DataLenChange       = 0x0003,
    /// Broadcast terminated.
    BroadcastEnd        = 0x0004,
    /// Link disconnected.
    DisconnectDone      = 0x0005,
    /// Peer connection parameter update request.
    PeerConnParamReq    = 0x0007,
    /// TX power changed.
    PowerChange         = 0x0008,
    /// TX packet count.
    TxPktCount          = 0x0009,
    /// Hardware error.
    HwError             = 0x000A,
    /// Data buffer overflow.
    DataBufOverflow     = 0x000B,
    /// Encryption parameter request.
    EncParamReq         = 0x000E,
    /// Encryption status changed.
    EncStatusChange     = 0x0011,
    /// Connection established.
    ConnEstablished     = 0x0015,
    /// Peer features received.
    PeerFeatures        = 0x0016,
    /// Peer version received.
    PeerVersion         = 0x0017,
    /// PHY parameter updated.
    PhyParamUpdate      = 0x0018,
    /// Connection parameter updated.
    ConnParamUpdate     = 0x0019,
    /// Broadcast/advertising report.
    BroadcastReport     = 0x001A,
    /// Scan result report.
    ScanReport          = 0x001C,
    /// Pairing request from peer.
    PairRequest         = 0x001D,
    /// Pairing response.
    PairResponse        = 0x001E,
    /// Pairing public key received.
    PairPublicKey       = 0x001F,
    /// Pairing DH check result.
    PairDhCheck         = 0x0020,
    /// Measurement report.
    MeasReport          = 0x002E,
    /// Sync link established.
    SyncUcastDone       = 0x0339,
}

/// An event from the controller to the host.
pub enum SleEvent {
    /// Command completed with status and optional return data.
    CommandComplete {
        opcode: SleOpcode,
        status: SleStatus,
        data: KVec<u8>,
    },
    /// Command pending (asynchronous processing started).
    CommandStatus {
        opcode: SleOpcode,
        status: SleStatus,
    },
    /// Advertising / broadcast report received during scanning.
    AdvReport {
        addr: [u8; 6],
        rssi: i8,
        data: KVec<u8>,
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
    /// Encryption status changed on a connection.
    EncryptionChanged {
        handle: u16,
        enabled: bool,
    },
    /// Pairing request from a remote peer.
    PairRequest {
        addr: [u8; 6],
        method: u8,
    },
    /// Controller hardware error.
    HardwareError {
        code: u8,
    },
}

// ---------------------------------------------------------------------------
// Controller trait — the DLI (T/XS 10003-2025)
// ---------------------------------------------------------------------------

/// The SparkLink Driver Layer Interface.
///
/// Each SLE controller driver (USB, UART, SPI, virtual, etc.) implements
/// this trait. The host protocol stack holds a reference to the active
/// controller and calls these methods to drive the radio.
///
/// The command/event model follows TXS-10003-2025:
///   - Commands use opcodes encoded as (OGF << 10) | OCF.
///   - Synchronous commands return a CommandComplete event immediately.
///   - Asynchronous commands return CommandStatus first, then later a
///     domain-specific completion event (ConnEstablished, etc.).
pub trait SleController: Send + Sync {
    /// Return static controller info (name, bus, address, capabilities).
    fn info(&self) -> SleControllerInfo;

    /// Open the controller. Called once when the first userspace fd opens
    /// `/dev/sparklink`. Drivers should power on the radio and perform
    /// initial firmware handshake.
    fn open(&self) -> Result;

    /// Close the controller. Called when the last userspace fd closes.
    fn close(&self);

    /// Send a DLI command to the controller.
    ///
    /// `opcode` uses the TXS-10003-2025 encoding. `params` carries the
    /// command-specific payload bytes. Returns `Ok(())` once the command
    /// is accepted; results arrive via [`SleController::poll_event`].
    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result;

    /// Send asynchronous unicast data on a connection.
    ///
    /// `handle` identifies the connection. The driver queues the data
    /// for transmission and returns immediately.
    fn send_data(&self, handle: u16, data: &[u8]) -> Result;

    /// Poll for the next pending event from the controller.
    ///
    /// Returns `None` if no event is available. The core calls this from
    /// a workqueue context or in response to an IRQ notification.
    fn poll_event(&self) -> Option<SleEvent>;

    /// Reset the controller to a known-good state.
    fn reset(&self) -> Result;
}

// ---------------------------------------------------------------------------
// Virtual controller (built-in loopback for testing)
// ---------------------------------------------------------------------------

/// A purely software-based SLE controller for testing.
///
/// All operations are loopback: advertising data is immediately available
/// as scan results, connections are looped back locally, etc.
pub struct VirtualController {
    addr: [u8; 6],
    opened: Cell<bool>,
}

// SAFETY: VirtualController is always accessed behind a Mutex, so Cell<bool>
// interior mutability is safe. The Mutex provides the necessary synchronization.
unsafe impl Send for VirtualController {}
unsafe impl Sync for VirtualController {}

impl VirtualController {
    /// Create a new virtual controller with the given address.
    pub fn new(addr: [u8; 6]) -> Self {
        Self { addr, opened: Cell::new(false) }
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
        info.features = (SleFeature::Encryption as u64)
            | (SleFeature::Mcs4 as u64)
            | (SleFeature::Pilot8to1 as u64)
            | (SleFeature::Crc32 as u64);
        info.max_pdu_payload = 255;
        info.max_connections = 8;
        info
    }

    fn open(&self) -> Result {
        if self.opened.get() {
            return Err(EBUSY);
        }
        self.opened.set(true);
        pr_info!("sparklink-virtual: controller opened\n");
        Ok(())
    }

    fn close(&self) {
        self.opened.set(false);
        pr_info!("sparklink-virtual: controller closed\n");
    }

    fn send_command(&self, opcode: SleOpcode, _params: &[u8]) -> Result {
        pr_debug!("sparklink-virtual: cmd {:?} (0x{:04x})\n", opcode, opcode as u16);
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
