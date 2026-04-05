// SPDX-License-Identifier: GPL-2.0

//! SparkLink userspace API (UAPI) definitions.
//!
//! IOCTL command codes and all associated repr(C) data structures
//! exchanged between the `/dev/sparklink` char device and userspace.

use kernel::ioctl::{_IO, _IOR, _IOW, _IOWR};
use kernel::prelude::*;
use kernel::transmute::FromBytes;

use super::sle_dli;
use super::sle_phy;

// ---------------------------------------------------------------------------
// Padding / reserved field validation (per botching-up-ioctls.rst)
// ---------------------------------------------------------------------------

/// Helper trait: is a padding field all-zero?
pub(crate) trait IsZeroPad {
    fn is_zero(&self) -> bool;
}

impl IsZeroPad for u8 {
    fn is_zero(&self) -> bool { *self == 0 }
}
impl IsZeroPad for u16 {
    fn is_zero(&self) -> bool { *self == 0 }
}
impl IsZeroPad for u32 {
    fn is_zero(&self) -> bool { *self == 0 }
}
impl<const N: usize> IsZeroPad for [u8; N] {
    fn is_zero(&self) -> bool { self.iter().all(|&b| b == 0) }
}

/// Rejects non-zero padding/reserved fields from userspace, preventing
/// forward-compatibility issues when these fields gain meaning later.
pub(crate) trait CheckReserved {
    fn check_reserved(&self) -> Result<()> {
        Ok(())
    }
}

/// Generate `CheckReserved` impl that rejects non-zero padding fields.
/// Use the no-argument form for structs without padding.
macro_rules! impl_check_reserved {
    ($ty:ty, [ $($field:ident),+ $(,)? ]) => {
        impl CheckReserved for $ty {
            fn check_reserved(&self) -> Result<()> {
                $(
                    if !IsZeroPad::is_zero(&self.$field) {
                        return Err(EINVAL);
                    }
                )+
                Ok(())
            }
        }
    };
    ($ty:ty) => {
        impl CheckReserved for $ty {}
    };
}

// Scalar types passed to read_user_struct — no padding to check.
impl CheckReserved for u8 {}
impl CheckReserved for u16 {}
impl CheckReserved for i16 {}

// ---------------------------------------------------------------------------
// Buffer size constants (used by IOCTL handlers for bounds clamping)
// ---------------------------------------------------------------------------

/// Maximum name length in SleInjectAdv / SleAdvParams.
pub(crate) const ADV_NAME_MAX: usize = 32;
/// Maximum advertising/scan data payload.
pub(crate) const ADV_DATA_MAX: usize = 252;
/// Maximum SM3 hash input length.
pub(crate) const HASH_INPUT_MAX: usize = 220;
/// Maximum HMAC key length.
pub(crate) const HMAC_KEY_MAX: usize = 64;
/// Maximum HMAC data length.
pub(crate) const HMAC_DATA_MAX: usize = 160;
/// Maximum SSAP read/write/notification data length.
pub(crate) const SSAP_DATA_MAX: usize = 252;
/// Maximum SSAP property value length.
pub(crate) const SSAP_VALUE_MAX: usize = 248;
/// Maximum DLI command parameter length.
pub(crate) const DLI_PARAM_MAX: usize = 240;

// ---------------------------------------------------------------------------
// IOCTL definitions for the /dev/sparklink control interface
// ---------------------------------------------------------------------------

pub(crate) const SL_MAGIC: u32 = 'S' as u32;

/// Register a new SCI device (for testing).
pub(crate) const SL_IOCTL_DEV_REGISTER: u32 = _IO(SL_MAGIC, 0x01);

/// Unregister a SCI device by index.
pub(crate) const SL_IOCTL_DEV_UNREGISTER: u32 = _IOW::<u16>(SL_MAGIC, 0x02);

/// Get the number of registered SCI devices.
pub(crate) const SL_IOCTL_DEV_COUNT: u32 = _IOR::<u32>(SL_MAGIC, 0x03);

/// Get device info by index.
pub(crate) const SL_IOCTL_DEV_INFO: u32 = _IOR::<SciDevInfo>(SL_MAGIC, 0x04);

/// Switch the active controller device by index (u16).
///
/// Saves the current active device's protocol state and restores
/// the target device's state (swap-on-switch).  Returns ENODEV if
/// the target device is not registered or has no saved state.
pub(crate) const SL_IOCTL_DEV_SWITCH: u32 = _IOW::<u16>(SL_MAGIC, 0x05);

/// List all registered device IDs (returns bitmask u16).
pub(crate) const SL_IOCTL_DEV_LIST: u32 = _IOR::<u16>(SL_MAGIC, 0x06);

/// Select per-fd device affinity (i16: -1 = follow global, ≥0 = bind to device).
///
/// Unlike DEV_SWITCH (which changes the global active controller),
/// DEV_SELECT only affects the calling fd.  On each subsequent ioctl,
/// the handler auto-switches to the fd's target device if needed.
pub(crate) const SL_IOCTL_DEV_SELECT: u32 = _IOW::<i16>(SL_MAGIC, 0x07);

/// Query the effective device for this fd (returns u16).
/// If the fd has a per-fd affinity, returns that; otherwise returns
/// the global active_dev_id (or 0xFFFF if no device is active).
pub(crate) const SL_IOCTL_DEV_GET_ACTIVE: u32 = _IOR::<u16>(SL_MAGIC, 0x08);

/// Start SLE advertising (device discovery - discoverable side).
pub(crate) const SL_IOCTL_START_ADV: u32 = _IOW::<SleAdvParams>(SL_MAGIC, 0x10);

/// Stop SLE advertising.
pub(crate) const SL_IOCTL_STOP_ADV: u32 = _IO(SL_MAGIC, 0x11);

/// Start SLE scanning (device discovery - scanner side).
pub(crate) const SL_IOCTL_START_SCAN: u32 = _IOW::<SleScanParams>(SL_MAGIC, 0x12);

/// Stop SLE scanning.
pub(crate) const SL_IOCTL_STOP_SCAN: u32 = _IO(SL_MAGIC, 0x13);

// --- Extended advertising ioctls ---

/// Configure an extended advertising set.
pub(crate) const SL_IOCTL_EXT_ADV_CONFIGURE: u32 = _IOW::<SleExtAdvConfig>(SL_MAGIC, 0x14);

/// Set data for an extended advertising set.
pub(crate) const SL_IOCTL_EXT_ADV_SET_DATA: u32 = _IOW::<SleExtAdvData>(SL_MAGIC, 0x15);

/// Enable an extended advertising set.
pub(crate) const SL_IOCTL_EXT_ADV_ENABLE: u32 = _IOW::<u8>(SL_MAGIC, 0x16);

/// Disable an extended advertising set.
pub(crate) const SL_IOCTL_EXT_ADV_DISABLE: u32 = _IOW::<u8>(SL_MAGIC, 0x17);

/// Remove an extended advertising set.
pub(crate) const SL_IOCTL_EXT_ADV_REMOVE: u32 = _IOW::<u8>(SL_MAGIC, 0x18);

/// Get info about an extended advertising set.
pub(crate) const SL_IOCTL_EXT_ADV_INFO: u32 = _IOWR::<SleExtAdvInfo>(SL_MAGIC, 0x19);

/// Enable with periodic parameters (duration + max events).
pub(crate) const SL_IOCTL_EXT_ADV_ENABLE_EX: u32 = _IOW::<SleExtAdvEnableParams>(SL_MAGIC, 0x1A);

/// Simulate one 10ms advertising tick for active sets.
/// Returns the number of sets auto-disabled this tick.
pub(crate) const SL_IOCTL_EXT_ADV_TICK: u32 = _IO(SL_MAGIC, 0x1B);

/// Inject a simulated advertising PDU for loopback testing.
/// Userspace provides a SleInjectAdv struct; if in scanning state,
/// the PDU is processed as a received advertisement.
pub(crate) const SL_IOCTL_INJECT_ADV: u32 = _IOW::<SleInjectAdv>(SL_MAGIC, 0x20);

/// Get the current scan result count.
pub(crate) const SL_IOCTL_SCAN_RESULT_COUNT: u32 = _IO(SL_MAGIC, 0x21);

/// Inject a raw advertising PDU (header + data + CRC-12) for CRC
/// verification testing. The PDU goes through `AdvPdu::deserialize()`
/// and is rejected with EINVAL if CRC-12 does not match.
pub(crate) const SL_IOCTL_INJECT_RAW_ADV: u32 = _IOW::<SleInjectRawAdv>(SL_MAGIC, 0x22);

/// Set extended scan filter (service UUID matching, T/XS 20001-2025 §6.4).
pub(crate) const SL_IOCTL_SET_SCAN_FILTER: u32 = _IOW::<SleScanFilter>(SL_MAGIC, 0x23);

/// Clear extended scan filter (accept all matching discovery level).
pub(crate) const SL_IOCTL_CLEAR_SCAN_FILTER: u32 = _IO(SL_MAGIC, 0x24);

// --- Connection management ioctls ---

/// Initiate an SLE connection to a peer device.
/// Returns the connection handle (> 0) on success.
pub(crate) const SL_IOCTL_CONNECT: u32 = _IOW::<SleConnectParams>(SL_MAGIC, 0x30);

/// Disconnect from a peer by connection handle.
pub(crate) const SL_IOCTL_DISCONNECT: u32 = _IOW::<u16>(SL_MAGIC, 0x31);

/// Get connection status and statistics by handle.
pub(crate) const SL_IOCTL_CONN_INFO: u32 = _IOWR::<SleConnInfo>(SL_MAGIC, 0x32);

/// Send data on a connection identified by handle.
pub(crate) const SL_IOCTL_CONN_SEND: u32 = _IOW::<SleConnData>(SL_MAGIC, 0x33);

/// Receive data from a connection identified by handle.
pub(crate) const SL_IOCTL_CONN_RECV: u32 = _IOWR::<SleConnData>(SL_MAGIC, 0x34);

/// Inject a simulated access response for loopback testing.
pub(crate) const SL_IOCTL_INJECT_CONN_RESP: u32 = _IOW::<SleInjectConnResp>(SL_MAGIC, 0x35);

/// Inject simulated received data for loopback testing.
pub(crate) const SL_IOCTL_INJECT_CONN_DATA: u32 = _IOW::<SleConnData>(SL_MAGIC, 0x36);

/// Get number of active connections.
pub(crate) const SL_IOCTL_CONN_COUNT: u32 = _IO(SL_MAGIC, 0x37);

/// Get list of active connection handles.
pub(crate) const SL_IOCTL_CONN_LIST: u32 = _IOR::<SleConnList>(SL_MAGIC, 0x38);

/// Set per-connection data channel MTU and MPS.
pub(crate) const SL_IOCTL_SET_CONN_MTU: u32 = _IOW::<SleConnMtuParams>(SL_MAGIC, 0x39);

// --- AFH (Adaptive Frequency Hopping) ioctls ---

/// Set the channel map for a connection.
pub(crate) const SL_IOCTL_AFH_SET_MAP: u32 = _IOW::<SleAfhMapParams>(SL_MAGIC, 0x3A);

/// Get the channel map for a connection.
pub(crate) const SL_IOCTL_AFH_GET_MAP: u32 = _IOWR::<SleAfhMapParams>(SL_MAGIC, 0x3B);

/// Report RSSI measurement for a channel on a connection.
pub(crate) const SL_IOCTL_AFH_REPORT_RSSI: u32 = _IOW::<SleAfhRssiReport>(SL_MAGIC, 0x3C);

/// Classify channels based on RSSI measurements and update the map.
pub(crate) const SL_IOCTL_AFH_CLASSIFY: u32 = _IOWR::<SleAfhClassifyParams>(SL_MAGIC, 0x3D);

/// Get the next hop channel for a connection.
pub(crate) const SL_IOCTL_AFH_HOP_NEXT: u32 = _IOWR::<SleAfhHopInfo>(SL_MAGIC, 0x3E);

/// Report a per-channel retransmission event.
pub(crate) const SL_IOCTL_AFH_REPORT_RETX: u32 = _IOW::<SleAfhRetxReport>(SL_MAGIC, 0x3F);

// --- Security management ioctls ---

/// Set the pre-shared key for PSK pairing.
pub(crate) const SL_IOCTL_SEC_SET_PSK: u32 = _IOW::<SlePskParams>(SL_MAGIC, 0x40);

/// Start pairing (method specified in parameters).
pub(crate) const SL_IOCTL_SEC_PAIR: u32 = _IOW::<SlePairParams>(SL_MAGIC, 0x41);

/// Get security status and key fingerprint.
pub(crate) const SL_IOCTL_SEC_INFO: u32 = _IOR::<SleSecInfo>(SL_MAGIC, 0x42);

/// Enable encryption on the data path (requires Paired state).
pub(crate) const SL_IOCTL_SEC_ENCRYPT_ON: u32 = _IO(SL_MAGIC, 0x43);

/// SM3 hash test: compute SM3(data) and return digest.
pub(crate) const SL_IOCTL_SEC_SM3_TEST: u32 = _IOW::<SleHashTest>(SL_MAGIC, 0x44);

/// SM4 encrypt test: encrypt data in-place using session key.
pub(crate) const SL_IOCTL_SEC_SM4_ENC_TEST: u32 = _IOW::<SleConnData>(SL_MAGIC, 0x45);

/// SM4 decrypt test: decrypt data in-place using session key.
pub(crate) const SL_IOCTL_SEC_SM4_DEC_TEST: u32 = _IOW::<SleConnData>(SL_MAGIC, 0x46);

/// SM4 standalone block test: encrypt or decrypt one 16-byte block with explicit key.
pub(crate) const SL_IOCTL_SEC_SM4_BLOCK_TEST: u32 = _IOWR::<SleSm4BlockTest>(SL_MAGIC, 0x47);

/// HMAC-SM3 test: compute HMAC-SM3(key, data) and return digest.
pub(crate) const SL_IOCTL_SEC_HMAC_TEST: u32 = _IOWR::<SleHmacTest>(SL_MAGIC, 0x48);

/// Reset security state to Idle (e.g. on disconnect or re-pairing).
pub(crate) const SL_IOCTL_SEC_RESET: u32 = _IO(SL_MAGIC, 0x49);

/// Get 6-digit passkey for numeric comparison pairing.
pub(crate) const SL_IOCTL_SEC_GET_PASSKEY: u32 = _IOR::<u32>(SL_MAGIC, 0x4A);

/// Confirm numeric comparison passkey match — completes pairing.
pub(crate) const SL_IOCTL_SEC_CONFIRM_PASSKEY: u32 = _IO(SL_MAGIC, 0x4B);

/// Reject numeric comparison passkey — returns to Idle.
pub(crate) const SL_IOCTL_SEC_REJECT_PASSKEY: u32 = _IO(SL_MAGIC, 0x4C);

/// Set OOB data (remote public key X+Y, 64 bytes) for OOB pairing.
pub(crate) const SL_IOCTL_SEC_SET_OOB: u32 = _IOW::<SleOobData>(SL_MAGIC, 0x4D);

/// Input 6-digit passkey for passkey entry pairing.
pub(crate) const SL_IOCTL_SEC_INPUT_PASSKEY: u32 = _IOW::<SlePasskeyInput>(SL_MAGIC, 0x4E);

/// Set password (1..32 bytes) for password-based pairing.
pub(crate) const SL_IOCTL_SEC_SET_PASSWORD: u32 = _IOW::<SlePasswordParams>(SL_MAGIC, 0x4F);

// --- SSAP service layer ioctls ---

/// Register the built-in device info service.
pub(crate) const SL_IOCTL_SSAP_REGISTER_SVC: u32 = _IO(SL_MAGIC, 0x50);

/// Get SSAP service/property count summary.
pub(crate) const SL_IOCTL_SSAP_INFO: u32 = _IOR::<SsapSummary>(SL_MAGIC, 0x51);

/// Read a property by handle.
pub(crate) const SL_IOCTL_SSAP_READ: u32 = _IOWR::<SsapReadWrite>(SL_MAGIC, 0x52);

/// Write a property by handle.
pub(crate) const SL_IOCTL_SSAP_WRITE: u32 = _IOW::<SsapReadWrite>(SL_MAGIC, 0x53);

/// Find primary services.
pub(crate) const SL_IOCTL_SSAP_FIND_SVC: u32 = _IOR::<SsapServiceList>(SL_MAGIC, 0x54);

/// Send a notification for a property handle.
pub(crate) const SL_IOCTL_SSAP_NOTIFY: u32 = _IOW::<u16>(SL_MAGIC, 0x55);

/// Dequeue one pending notification.
pub(crate) const SL_IOCTL_SSAP_DEQUEUE_NTF: u32 = _IOR::<SsapNotification>(SL_MAGIC, 0x56);

/// Register a dynamic SSAP service from userspace.
pub(crate) const SL_IOCTL_SSAP_ADD_SVC: u32 = _IOWR::<SsapAddService>(SL_MAGIC, 0x57);

/// Add a property to the last registered service.
pub(crate) const SL_IOCTL_SSAP_ADD_PROP: u32 = _IOWR::<SsapAddProperty>(SL_MAGIC, 0x58);

/// Remove a service by its start handle.
pub(crate) const SL_IOCTL_SSAP_REMOVE_SVC: u32 = _IOW::<u16>(SL_MAGIC, 0x59);

// --- Remote SSAP client-side ioctls ---

/// Initiate SSAP ExchangeInfo (MTU negotiation) with connected peer.
pub(crate) const SL_IOCTL_SSAP_EXCHANGE_INFO: u32 = _IOW::<SsapRemoteCmd>(SL_MAGIC, 0x5A);

/// Discover remote services via FindStructure.
pub(crate) const SL_IOCTL_SSAP_REMOTE_DISCOVER: u32 = _IOWR::<SsapRemoteDiscover>(SL_MAGIC, 0x5B);

/// Read a remote property by handle.
pub(crate) const SL_IOCTL_SSAP_REMOTE_READ: u32 = _IOWR::<SsapRemoteReadWrite>(SL_MAGIC, 0x5C);

/// Write a remote property by handle.
pub(crate) const SL_IOCTL_SSAP_REMOTE_WRITE: u32 = _IOW::<SsapRemoteReadWrite>(SL_MAGIC, 0x5D);

/// Dequeue one inbound remote notification/indication.
pub(crate) const SL_IOCTL_SSAP_REMOTE_EVENT: u32 = _IOR::<SsapNotification>(SL_MAGIC, 0x5E);

/// Invoke a method on a remote peer's SSAP service.
pub(crate) const SL_IOCTL_SSAP_CALL_METHOD: u32 = _IOWR::<SsapRemoteReadWrite>(SL_MAGIC, 0x5F);

/// Find service/property by UUID on a remote peer.
pub(crate) const SL_IOCTL_SSAP_FIND_BY_UUID: u32 = _IOWR::<SsapUuidOp>(SL_MAGIC, 0x6F);

/// Read a property by UUID on a remote peer.
pub(crate) const SL_IOCTL_SSAP_READ_BY_UUID: u32 = _IOWR::<SsapUuidOp>(SL_MAGIC, 0x72);

// --- Power management ioctls ---

/// Get power management status.
pub(crate) const SL_IOCTL_PM_INFO: u32 = _IOR::<SlePmInfo>(SL_MAGIC, 0x60);

/// Set power state (Active/Sniff/Suspend/Resume).
pub(crate) const SL_IOCTL_PM_SET_STATE: u32 = _IOW::<SlePmStateCmd>(SL_MAGIC, 0x61);

/// Update connection interval parameters.
pub(crate) const SL_IOCTL_PM_SET_INTERVAL: u32 = _IOW::<SlePmInterval>(SL_MAGIC, 0x62);

/// Set force-active mode.
pub(crate) const SL_IOCTL_PM_FORCE_ACTIVE: u32 = _IOW::<u8>(SL_MAGIC, 0x63);

/// Simulate a connection event tick (for testing).
pub(crate) const SL_IOCTL_PM_TICK: u32 = _IO(SL_MAGIC, 0x64);

/// Record a data activity event.
pub(crate) const SL_IOCTL_PM_ACTIVITY: u32 = _IO(SL_MAGIC, 0x65);

// --- Sync link management ioctls (T/XS 10003-2025 section 8.10) ---

/// Configure sync unicast CIG group parameters.
pub(crate) const SL_IOCTL_SYNC_UCAST_PARAM: u32 = _IOWR::<SleSyncCigConfig>(SL_MAGIC, 0x66);

/// Create (activate) sync unicast links within a CIG.
pub(crate) const SL_IOCTL_SYNC_UCAST_CREATE: u32 = _IOW::<SleSyncCreateCmd>(SL_MAGIC, 0x67);

/// Remove a sync unicast CIG group.
pub(crate) const SL_IOCTL_SYNC_UCAST_REMOVE: u32 = _IOW::<u8>(SL_MAGIC, 0x68);

/// Configure sync multicast BIG group parameters.
pub(crate) const SL_IOCTL_SYNC_MCAST_PARAM: u32 = _IOWR::<SleSyncBigConfig>(SL_MAGIC, 0x69);

/// Create (activate) sync multicast links within a BIG.
pub(crate) const SL_IOCTL_SYNC_MCAST_CREATE: u32 = _IOW::<SleSyncCreateCmd>(SL_MAGIC, 0x6A);

/// Remove a sync multicast BIG group.
pub(crate) const SL_IOCTL_SYNC_MCAST_REMOVE: u32 = _IOW::<u8>(SL_MAGIC, 0x6B);

/// Configure data path for a sync link (codec).
pub(crate) const SL_IOCTL_SYNC_DATAPATH_CFG: u32 = _IOW::<SleSyncDatapathCmd>(SL_MAGIC, 0x6C);

/// Remove data path for a sync link.
pub(crate) const SL_IOCTL_SYNC_DATAPATH_REMOVE: u32 = _IOW::<u16>(SL_MAGIC, 0x6D);

/// Get sync link information.
pub(crate) const SL_IOCTL_SYNC_INFO: u32 = _IOWR::<SleSyncLinkInfo>(SL_MAGIC, 0x6E);

/// Accept a sync unicast setup request (§8.10.5).
pub(crate) const SL_IOCTL_SYNC_UCAST_ACCEPT: u32 = _IOW::<u16>(SL_MAGIC, 0x73);

/// Reject a sync unicast setup request (§8.10.6).
pub(crate) const SL_IOCTL_SYNC_UCAST_REJECT: u32 = _IOW::<SleSyncRejectCmd>(SL_MAGIC, 0x74);

/// Accept a sync multicast setup request (§8.10.11).
pub(crate) const SL_IOCTL_SYNC_MCAST_ACCEPT: u32 = _IOW::<u16>(SL_MAGIC, 0x75);

/// Reject a sync multicast setup request (§8.10.12).
pub(crate) const SL_IOCTL_SYNC_MCAST_REJECT: u32 = _IOW::<SleSyncRejectCmd>(SL_MAGIC, 0x76);

/// Send isochronous data on a sync link (§7.5).
pub(crate) const SL_IOCTL_SYNC_DATA_SEND: u32 = _IOW::<SleSyncDataCmd>(SL_MAGIC, 0x77);

/// Get number of pending events in the event queue.
pub(crate) const SL_IOCTL_EVENT_COUNT: u32 = _IO(SL_MAGIC, 0x70);

/// Get event queue lifetime statistics.
pub(crate) const SL_IOCTL_EVENT_STATS: u32 = _IOR::<SleEventStats>(SL_MAGIC, 0x71);

/// Get DLI controller information.
pub(crate) const SL_IOCTL_DLI_INFO: u32 = _IOR::<SleDliInfo>(SL_MAGIC, 0x80);

/// Get USB SLE device count (hardware discovery).
pub(crate) const SL_IOCTL_USB_DEV_COUNT: u32 = _IO(SL_MAGIC, 0x81);

/// Poll a DLI event from the controller.
pub(crate) const SL_IOCTL_DLI_POLL_EVENT: u32 = _IOR::<SleDliEvent>(SL_MAGIC, 0x82);

/// Reset the DLI controller.
pub(crate) const SL_IOCTL_DLI_RESET: u32 = _IO(SL_MAGIC, 0x83);

/// Send a DLI command to the controller (management plane).
pub(crate) const SL_IOCTL_DLI_SEND_CMD: u32 = _IOWR::<SleDliCmd>(SL_MAGIC, 0x84);

/// Get management plane pending queue statistics.
pub(crate) const SL_IOCTL_MGMT_STATS: u32 = _IOR::<SleMgmtStats>(SL_MAGIC, 0x85);

/// Get unified subsystem statistics (admin observability).
pub(crate) const SL_IOCTL_SUBSYS_STATS: u32 = _IOR::<SleSubsysStats>(SL_MAGIC, 0x86);

// --- PHY layer ioctls ---

/// Get PHY layer configuration.
pub(crate) const SL_IOCTL_PHY_INFO: u32 = _IOR::<SlePhyInfo>(SL_MAGIC, 0x90);

/// Set MCS index.
pub(crate) const SL_IOCTL_PHY_SET_MCS: u32 = _IOW::<SlePhyMcsCmd>(SL_MAGIC, 0x91);

/// Set TX power.
pub(crate) const SL_IOCTL_PHY_SET_TXPOWER: u32 = _IOW::<SlePhyTxPowerCmd>(SL_MAGIC, 0x92);

/// Select best MCS for given requirements.
pub(crate) const SL_IOCTL_PHY_MCS_SELECT: u32 = _IOWR::<SlePhyMcsSelect>(SL_MAGIC, 0x93);

/// Get frequency hopping next channel.
pub(crate) const SL_IOCTL_PHY_HOP_NEXT: u32 = _IOR::<SlePhyHopInfo>(SL_MAGIC, 0x94);

/// Set bandwidth.
pub(crate) const SL_IOCTL_PHY_SET_BW: u32 = _IOW::<SlePhyBwCmd>(SL_MAGIC, 0x95);

/// Get SINR thresholds (dB x10, 13 entries for MCS 0-12).
pub(crate) const SL_IOCTL_PHY_GET_SINR: u32 = _IOR::<SleSinrThresholds>(SL_MAGIC, 0x96);

/// Set SINR thresholds (dB x10, 13 entries for MCS 0-12).
pub(crate) const SL_IOCTL_PHY_SET_SINR: u32 = _IOW::<SleSinrThresholds>(SL_MAGIC, 0x97);

// --- Capability / channel negotiation ioctls ---

/// Trigger or query peer feature exchange for a connection.
pub(crate) const SL_IOCTL_CONN_READ_PEER_FEATURES: u32 =
    _IOWR::<SleConnPeerCap>(SL_MAGIC, 0x98);

/// Trigger or query peer version exchange for a connection.
pub(crate) const SL_IOCTL_CONN_READ_PEER_VERSION: u32 =
    _IOWR::<SleConnPeerCap>(SL_MAGIC, 0x99);

/// Request connection parameter update for a specific handle.
pub(crate) const SL_IOCTL_CONN_UPDATE_PARAMS: u32 =
    _IOW::<SleConnParamUpdate>(SL_MAGIC, 0x9A);

/// Request PHY parameter update (MCS / bandwidth) for a connection.
pub(crate) const SL_IOCTL_CONN_PHY_UPDATE: u32 =
    _IOW::<SleConnPhyUpdate>(SL_MAGIC, 0x9B);

/// Set local GT node role (0=TNode, 1=GNode).
pub(crate) const SL_IOCTL_SET_ROLE: u32 = _IOW::<u8>(SL_MAGIC, 0xA0);

/// Get current local GT node role.
pub(crate) const SL_IOCTL_GET_ROLE: u32 = _IOR::<u8>(SL_MAGIC, 0xA1);

// --- RAL / RPA management ioctls (T/XS 10003-2025 §8.6.18-§8.6.25) ---

/// Add a device to the Resolving Address List.
pub(crate) const SL_IOCTL_RAL_ADD: u32 = _IOW::<SleRalAddParams>(SL_MAGIC, 0xB0);

/// Remove a device from the RAL by peer identity.
pub(crate) const SL_IOCTL_RAL_REMOVE: u32 = _IOW::<SleRalRemoveParams>(SL_MAGIC, 0xB1);

/// Clear all RAL entries.
pub(crate) const SL_IOCTL_RAL_CLEAR: u32 = _IO(SL_MAGIC, 0xB2);

/// Read current RAL entry count.
pub(crate) const SL_IOCTL_RAL_SIZE: u32 = _IOR::<u8>(SL_MAGIC, 0xB3);

/// Read peer RPA for a given identity.
pub(crate) const SL_IOCTL_RAL_READ_PEER_RPA: u32 = _IOWR::<SleRalQueryParams>(SL_MAGIC, 0xB4);

/// Read local RPA for a given identity.
pub(crate) const SL_IOCTL_RAL_READ_LOCAL_RPA: u32 = _IOWR::<SleRalQueryParams>(SL_MAGIC, 0xB5);

/// Enable or disable RPA resolution.
pub(crate) const SL_IOCTL_RPA_ENABLE: u32 = _IOW::<u8>(SL_MAGIC, 0xB6);

/// Set RPA timeout in seconds.
pub(crate) const SL_IOCTL_RPA_SET_TIMEOUT: u32 = _IOW::<u16>(SL_MAGIC, 0xB7);

// --- Narrowband AFH measurement ioctls (T/XS 10003-2025 §8.7) ---

/// Read local measurement capabilities (DLI opcode 0x2001).
pub(crate) const SL_IOCTL_MEAS_READ_CAP: u32 = _IOR::<SleMeasCap>(SL_MAGIC, 0xC0);

/// Set measurement link parameters (DLI opcode 0x2003).
pub(crate) const SL_IOCTL_MEAS_SET_LINK_PARAM: u32 = _IOW::<SleMeasLinkParam>(SL_MAGIC, 0xC1);

/// Start or stop a measurement action (DLI opcode 0x2005).
pub(crate) const SL_IOCTL_MEAS_ACTION: u32 = _IOW::<SleMeasAction>(SL_MAGIC, 0xC2);

/// Enable or disable measurement reporting (DLI opcode 0x200B).
pub(crate) const SL_IOCTL_MEAS_ENABLE: u32 = _IOW::<u8>(SL_MAGIC, 0xC3);

// ---------------------------------------------------------------------------
// SparkLink address (6 bytes, same as SLE MAC layer identifier)
// ---------------------------------------------------------------------------

/// SLE media access layer identifier, 6 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleAddr {
    /// Raw 6-byte SLE address.
    pub b: [u8; 6],
}

// ---------------------------------------------------------------------------
// SCI device state machine
// ---------------------------------------------------------------------------

/// SCI device operating state.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub(crate) enum SciState {
    /// Device is registered but not active.
    #[default]
    Idle = 0,
    /// Device is advertising (discoverable).
    Advertising = 1,
    /// Device is scanning for other devices.
    Scanning = 2,
    /// Device has an active connection.
    Connected = 3,
}

// ---------------------------------------------------------------------------
// Discovery levels (T/XS 20001-2025 section 6.3.2)
// ---------------------------------------------------------------------------

/// Discovery level indicating the discoverability of the device.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub(crate) enum DiscoveryLevel {
    /// Not visible to any device.
    Invisible = 0,
    /// Generally discoverable by all devices.
    #[default]
    General = 1,
    /// Priority discoverable, faster detection.
    Priority = 2,
    /// Discoverable only by previously paired devices.
    PairedOnly = 3,
    /// Discoverable only by a specific designated device.
    Designated = 4,
}

// ---------------------------------------------------------------------------
// Userspace data structures (ioctl payloads)
// ---------------------------------------------------------------------------

/// Device information returned to userspace.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SciDevInfo {
    /// SCI device index.
    pub index: u16,
    /// Operating state (see `SciState`).
    pub state: u8,
    /// Transport bus type (see `SciBus`).
    pub bus: u8,
    /// SLE address.
    pub addr: SleAddr,
    /// Device name (UTF-8, null-padded).
    pub name: [u8; 32],
    pub(crate) _reserved: [u8; 24],
}

/// SLE advertising parameters.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleAdvParams {
    /// Target SCI device index.
    pub dev_index: u16,
    /// Advertising interval in milliseconds.
    pub interval_ms: u16,
    /// Discovery level (see `DiscoveryLevel`).
    pub discovery_level: u8,
    pub(crate) _reserved: [u8; 11],
}

// SAFETY: SleAdvParams is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleAdvParams {}

/// SLE scanning parameters.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleScanParams {
    /// Target SCI device index.
    pub dev_index: u16,
    /// Scan window in milliseconds.
    pub window_ms: u16,
    /// Scan interval in milliseconds.
    pub interval_ms: u16,
    /// Minimum discovery level to accept.
    pub filter_discovery_level: u8,
    pub(crate) _reserved: [u8; 9],
}

// SAFETY: SleScanParams is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleScanParams {}

// ---------------------------------------------------------------------------
// Extended advertising userspace data structures
// ---------------------------------------------------------------------------

/// Extended advertising set configuration.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleExtAdvConfig {
    /// Set handle (0..3).
    pub handle: u8,
    /// Discovery level (0-4).
    pub discovery_level: u8,
    /// Advertising SID (0-15).
    pub sid: u8,
    /// Broadcast type (0-3).
    pub broadcast_type: u8,
    /// Primary PHY (0=1M, 1=2M, 2=Coded).
    pub primary_phy: u8,
    /// Secondary PHY (0=1M, 1=2M, 2=Coded).
    pub secondary_phy: u8,
    /// TX power in dBm.
    pub tx_power_dbm: i8,
    /// Include TX power in extended header.
    pub include_tx_power: u8,
    /// Advertising interval in milliseconds.
    pub interval_ms: u16,
    /// Extended advertising send timing (§8.2.1).
    /// 0x00 = send before next base adv,
    /// 0x01..0xFF = max base advs to skip.
    pub ext_adv_timing: u8,
    pub(crate) _reserved: [u8; 5],
}

/// Extended advertising data payload.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleExtAdvData {
    /// Set handle (0..3).
    pub handle: u8,
    pub(crate) _pad: u8,
    /// Length of data in bytes.
    pub data_len: u16,
    /// Raw advertising data.
    pub data: [u8; 252],
}

impl Default for SleExtAdvData {
    fn default() -> Self {
        Self {
            handle: 0,
            _pad: 0,
            data_len: 0,
            data: [0u8; 252],
        }
    }
}

/// Extended advertising set info (output).
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleExtAdvInfo {
    /// Set handle (input).
    pub handle: u8,
    /// State: 0=Idle, 1=Configured, 2=Active.
    pub state: u8,
    /// Advertising SID.
    pub sid: u8,
    /// Primary PHY.
    pub primary_phy: u8,
    /// Data length.
    pub data_len: u16,
    /// Extended advertising send timing.
    pub ext_adv_timing: u8,
    /// Max advertising events (0 = unlimited).
    pub max_adv_events: u8,
    /// PDUs sent.
    pub tx_count: u64,
    /// Events sent since last enable.
    pub events_sent: u32,
    pub(crate) _pad: [u8; 4],
}

// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleExtAdvConfig {}
// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleExtAdvData {}
// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleExtAdvInfo {}

/// Extended advertising enable with periodic parameters.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleExtAdvEnableParams {
    /// Set handle (0..3).
    pub handle: u8,
    /// Max advertising events (0 = unlimited).
    pub max_adv_events: u8,
    /// Duration in 10ms units (0 = infinite).
    pub duration_10ms: u16,
    pub(crate) _reserved: [u8; 4],
}

// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleExtAdvEnableParams {}

/// Injected advertising data for loopback testing.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleInjectAdv {
    /// Simulated source SLE address.
    pub addr: [u8; 6],
    /// Simulated RSSI.
    pub rssi: i8,
    /// Discovery level to include in the advertising data.
    pub discovery_level: u8,
    /// Device name (UTF-8, null-terminated).
    pub name: [u8; 32],
    /// Name length.
    pub name_len: u8,
    pub(crate) _reserved: [u8; 7],
}

impl Default for SleInjectAdv {
    fn default() -> Self {
        Self {
            addr: [0u8; 6],
            rssi: -50,
            discovery_level: 1,
            name: [0u8; 32],
            name_len: 0,
            _reserved: [0u8; 7],
        }
    }
}

// SAFETY: SleInjectAdv is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleInjectAdv {}

/// Raw advertising PDU for CRC-12 verification testing.
///
/// Wire format: [header 4B][data NB][CRC-12 2B], total up to 264 bytes.
/// The RSSI field is external metadata, not part of the PDU.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleInjectRawAdv {
    /// RSSI to associate with this PDU.
    pub rssi: i8,
    pub(crate) _pad: u8,
    /// Number of valid bytes in `pdu_data` (header + data + CRC).
    pub pdu_len: u16,
    /// Raw PDU bytes.
    pub pdu_data: [u8; 264],
}

impl Default for SleInjectRawAdv {
    fn default() -> Self {
        Self {
            rssi: -50,
            _pad: 0,
            pdu_len: 0,
            pdu_data: [0u8; 264],
        }
    }
}

// SAFETY: SleInjectRawAdv is repr(C) with only primitive fields.
unsafe impl FromBytes for SleInjectRawAdv {}

// ---------------------------------------------------------------------------
// Connection management userspace data structures
// ---------------------------------------------------------------------------

/// Connection request parameters from userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleConnectParams {
    /// Target peer SLE address (6 bytes).
    pub peer_addr: [u8; 6],
    /// Desired GT role: 0=T node, 1=G node.
    pub gt_role: u8,
    /// Preferred bandwidth in MHz (1, 2, or 4).
    pub bandwidth: u8,
    /// Preferred MCS index (0-12).
    pub mcs_index: u8,
    pub(crate) _pad: u8,
    /// Supervision timeout in 10 ms units.
    pub timeout_10ms: u16,
    pub(crate) _reserved: [u8; 4],
}

impl Default for SleConnectParams {
    fn default() -> Self {
        Self {
            peer_addr: [0u8; 6],
            gt_role: 0,
            bandwidth: 1,
            mcs_index: 4,
            _pad: 0,
            timeout_10ms: 100,
            _reserved: [0u8; 4],
        }
    }
}

// SAFETY: SleConnectParams is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleConnectParams {}

/// Connection status and statistics returned to userspace.
///
/// Layout is ordered to avoid implicit padding: u64 fields first,
/// then u16, then u8 — no gaps between fields.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleConnInfo {
    /// Total bytes transmitted.
    pub tx_bytes: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// Connection handle.
    pub handle: u16,
    /// Event group period in scheduling slots.
    pub event_group_period: u16,
    /// Supervision timeout in 10 ms units.
    pub supervision_timeout: u16,
    /// Pending TX queue depth.
    pub tx_pending: u16,
    /// Pending RX queue depth.
    pub rx_pending: u16,
    /// Connection state (see ConnState).
    pub state: u8,
    /// Peer SLE address.
    pub peer_addr: [u8; 6],
    /// Local GT role: 0=T, 1=G.
    pub local_role: u8,
    /// Negotiated bandwidth in MHz.
    pub bandwidth_mhz: u8,
    /// Negotiated MCS index.
    pub mcs_index: u8,
    /// Current TX sequence number.
    pub tx_seq: u8,
    /// Current RX sequence number.
    pub rx_seq: u8,
    /// Data channel MTU.
    pub data_mtu: u16,
    /// Data channel MPS.
    pub data_mps: u16,
    /// Service management channel MTU.
    pub svc_mtu: u16,
    /// Data channel transport mode (0=unreliable, 1=reliable).
    pub data_mode: u8,
    /// SSAP ExchangeInfo completed flag (1=yes, 0=no).
    pub ssap_info_exchanged: u8,
    /// SSAP session negotiated MTU (0 if no session bound).
    pub ssap_mtu: u16,
    /// SSAP reliable mode negotiated (1=yes, 0=no).
    pub ssap_reliable_mode: u8,
    /// SSAP negotiated protocol major version.
    pub ssap_version_major: u8,
    /// SMTC TX credits remaining (Reliable channel).
    pub smtc_tx_credits: u16,
    /// SMTC RX credits remaining (Reliable channel).
    pub smtc_rx_credits: u16,
    /// DUDTC TX credits remaining (0 if Unreliable).
    pub dudtc_tx_credits: u16,
    /// DUDTC RX credits remaining (0 if Unreliable).
    pub dudtc_rx_credits: u16,
}

// SAFETY: SleConnInfo is repr(C) with only primitive fields.
unsafe impl FromBytes for SleConnInfo {}

/// Data buffer for connection send/receive ioctls.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleConnData {
    /// Connection handle (0 = first active connection).
    pub handle: u16,
    /// Data payload length in bytes.
    pub length: u16,
    /// Data payload.
    pub data: [u8; 255],
    pub(crate) _reserved: u8,
}

impl Default for SleConnData {
    fn default() -> Self {
        Self {
            handle: 0,
            length: 0,
            data: [0u8; 255],
            _reserved: 0,
        }
    }
}

// SAFETY: SleConnData is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleConnData {}

/// Injected connection response for loopback testing.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleInjectConnResp {
    /// Connection handle to inject response for.
    pub handle: u16,
    /// Response type (0=accepted, 1=role fail, 2=resource, 3=rejected).
    pub response_type: u8,
    /// Bandwidth in MHz for the accepted connection.
    pub bandwidth_mhz: u8,
    /// MCS index for the accepted connection.
    pub mcs_index: u8,
    pub(crate) _pad: u8,
    /// Supervision timeout in 10 ms units.
    pub supervision_timeout: u16,
    /// Data channel MTU (0 = use default 247).
    pub data_mtu: u16,
    /// Data channel MPS (0 = use MTU value).
    pub data_mps: u16,
}

impl Default for SleInjectConnResp {
    fn default() -> Self {
        Self {
            handle: 0,
            response_type: 0,
            bandwidth_mhz: 1,
            mcs_index: 4,
            _pad: 0,
            supervision_timeout: 100,
            data_mtu: 0,
            data_mps: 0,
        }
    }
}

// SAFETY: SleInjectConnResp is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleInjectConnResp {}

/// List of active connection handles returned from CONN_LIST.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleConnList {
    /// Number of active handles in the list.
    pub count: u16,
    pub(crate) _pad: u16,
    /// Up to 8 active connection handles.
    pub handles: [u16; 8],
    pub(crate) _reserved: [u8; 4],
}

/// Per-connection MTU/MPS update parameters.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleConnMtuParams {
    /// Connection handle.
    pub handle: u16,
    /// New data channel MTU (23..=max_pdu_size).
    pub mtu: u16,
    /// New data channel MPS (0 = keep current, clamped to MTU).
    pub mps: u16,
    pub(crate) _pad: u16,
}

// SAFETY: SleConnMtuParams is repr(C) with only primitive fields.
unsafe impl FromBytes for SleConnMtuParams {}

// ---------------------------------------------------------------------------
// AFH (Adaptive Frequency Hopping) userspace data structures
// ---------------------------------------------------------------------------

/// Channel map set/get parameters for a connection.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleAfhMapParams {
    /// Connection handle.
    pub handle: u16,
    /// Minimum number of usable channels (at least 2).
    pub min_channels: u8,
    pub(crate) _pad: u8,
    /// 10-byte channel map bitmask (bit N = channel N usable).
    pub map: [u8; 10],
    /// Number of usable channels (output on GET).
    pub used_count: u8,
    pub(crate) _pad2: u8,
}

/// RSSI measurement report for AFH classification.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleAfhRssiReport {
    /// Connection handle.
    pub handle: u16,
    /// Channel index (0-78).
    pub channel: u8,
    /// RSSI in dBm (signed).
    pub rssi_dbm: i8,
}

/// AFH auto-classification parameters and result.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleAfhClassifyParams {
    /// Connection handle.
    pub handle: u16,
    /// RSSI threshold in dBm — channels below this are classified bad.
    pub threshold_dbm: i8,
    /// Minimum channels to keep usable (at least 2).
    pub min_channels: u8,
    /// Output: resulting channel map after classification.
    pub map_out: [u8; 10],
    /// Output: number of usable channels.
    pub used_count: u8,
    pub(crate) _pad: u8,
}

/// Per-connection hop info (next channel + frequency + event counter).
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleAfhHopInfo {
    /// Connection handle (input).
    pub handle: u16,
    /// Channel index (0-78, output).
    pub channel: u8,
    pub(crate) _pad: u8,
    /// RF frequency in MHz (output).
    pub freq_mhz: u16,
    /// Event counter after hop (output).
    pub event_counter: u16,
}

/// AFH retransmission report for dynamic channel classification.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleAfhRetxReport {
    /// Connection handle.
    pub handle: u16,
    /// Channel index (0-78).
    pub channel: u8,
    /// 1 = retransmission occurred, 0 = first-time success.
    pub retransmitted: u8,
}

// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleAfhMapParams {}
// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleAfhRssiReport {}
// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleAfhClassifyParams {}
// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleAfhHopInfo {}
// SAFETY: repr(C), all fields are primitives.
unsafe impl FromBytes for SleAfhRetxReport {}

// ---------------------------------------------------------------------------
// Sync link management userspace data structures (T/XS 10003-2025 §8.10)
// ---------------------------------------------------------------------------

/// Configuration parameters for a sync unicast CIG group.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleSyncCigConfig {
    /// CIG identifier (0x00-0xEF).
    pub cig_id: u8,
    /// Number of sync links to create (1-8).
    pub link_count: u8,
    /// Adaptation mode: 0=periodic, 1=aperiodic.
    pub adapt_mode: u8,
    pub(crate) _pad: u8,
    /// G→T SDU interval in microseconds.
    pub sdu_interval_g2t: u32,
    /// T→G SDU interval in microseconds.
    pub sdu_interval_t2g: u32,
    /// Max SDU payload G→T (bytes).
    pub max_sdu_g2t: u16,
    /// Max SDU payload T→G (bytes).
    pub max_sdu_t2g: u16,
    /// Max transport delay G→T (ms).
    pub max_latency_g2t: u16,
    /// Max transport delay T→G (ms).
    pub max_latency_t2g: u16,
    /// PDU retransmit count G→T.
    pub retransmit_g2t: u8,
    /// PDU retransmit count T→G.
    pub retransmit_t2g: u8,
    /// Output: allocated sync link handles.
    pub handles_out: [u16; 8],
}

// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleSyncCigConfig {}

/// Configuration parameters for a sync multicast BIG group.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleSyncBigConfig {
    /// BIG identifier (0x00-0xEF).
    pub big_id: u8,
    /// Number of sync links to create (1-8).
    pub link_count: u8,
    /// Adaptation mode: 0=periodic, 1=aperiodic.
    pub adapt_mode: u8,
    pub(crate) _pad: u8,
    /// G→T SDU interval in microseconds.
    pub sdu_interval_g2t: u32,
    /// T→G SDU interval in microseconds.
    pub sdu_interval_t2g: u32,
    /// Max SDU payload G→T (bytes).
    pub max_sdu_g2t: u16,
    /// Max SDU payload T→G (bytes).
    pub max_sdu_t2g: u16,
    /// Max transport delay G→T (ms).
    pub max_latency_g2t: u16,
    /// Max transport delay T→G (ms).
    pub max_latency_t2g: u16,
    /// PDU retransmit count G→T.
    pub retransmit_g2t: u8,
    /// PDU retransmit count T→G.
    pub retransmit_t2g: u8,
    /// Output: allocated sync link handles.
    pub handles_out: [u16; 8],
}

// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleSyncBigConfig {}

/// Create (activate) sync links — binds CIG/BIG links to async connections.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleSyncCreateCmd {
    /// CIG or BIG identifier.
    pub group_id: u8,
    /// Number of links to create.
    pub link_count: u8,
    pub(crate) _pad: [u8; 2],
    /// ACL connection handles to bind (one per link).
    pub acl_handles: [u16; 8],
}

// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleSyncCreateCmd {}

/// Sync link data path configuration.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleSyncDatapathCmd {
    /// Sync link handle.
    pub sync_handle: u16,
    /// Direction: 0=input, 1=output, 2=both.
    pub direction: u8,
    /// Data path identifier.
    pub path_id: u8,
    /// Codec identifier.
    pub codec_id: u8,
    pub(crate) _pad: [u8; 3],
}

// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleSyncDatapathCmd {}

/// Sync link information query/response.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleSyncLinkInfo {
    /// Sync link handle (input).
    pub sync_handle: u16,
    /// Associated ACL handle (output).
    pub acl_handle: u16,
    /// CIG/BIG ID (output).
    pub group_id: u8,
    /// CIS/BIS ID within group (output).
    pub stream_id: u8,
    /// Link type: 0=unicast, 1=multicast (output).
    pub link_type: u8,
    /// State: 0=configured, 1=creating, 2=active (output).
    pub state: u8,
    /// G→T SDU interval µs (output).
    pub sdu_interval_g2t: u32,
    /// T→G SDU interval µs (output).
    pub sdu_interval_t2g: u32,
    /// Max SDU G→T (output).
    pub max_sdu_g2t: u16,
    /// Max SDU T→G (output).
    pub max_sdu_t2g: u16,
    /// Data path configured (output).
    pub datapath_configured: u8,
    pub(crate) _pad2: [u8; 3],
}

// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleSyncLinkInfo {}

/// Sync link reject command (§8.10.6, §8.10.12).
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleSyncRejectCmd {
    /// Sync link handle.
    pub sync_handle: u16,
    /// Rejection reason code.
    pub reason: u8,
    pub(crate) _pad: u8,
}

// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleSyncRejectCmd {}

/// Sync data send command (§7.5).
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleSyncDataCmd {
    /// Sync link handle.
    pub sync_handle: u16,
    /// Segmentation: 0=complete, 1=first, 2=middle, 3=last.
    pub segment: u8,
    /// Priority: 0=low, 1=high.
    pub priority: u8,
    /// Payload length.
    pub len: u16,
    pub(crate) _pad: [u8; 2],
    /// SDU payload data.
    pub data: [u8; 247],
    pub(crate) _pad2: u8,
}

// SAFETY: repr(C) with only primitive fields.
unsafe impl FromBytes for SleSyncDataCmd {}

impl Default for SleSyncDataCmd {
    fn default() -> Self {
        // SAFETY: all-zeros is a valid representation for this repr(C) struct.
        unsafe { core::mem::zeroed() }
    }
}

// ---------------------------------------------------------------------------
// Security management userspace data structures
// ---------------------------------------------------------------------------

/// Pre-shared key for PSK pairing.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SlePskParams {
    /// 128-bit pre-shared key.
    pub psk: [u8; 16],
}

// SAFETY: SlePskParams is repr(C) with only primitive fields.
unsafe impl FromBytes for SlePskParams {}

/// Pairing request parameters.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SlePairParams {
    /// Pairing method: 1=JustWorks, 2=PSK, 3=NC, 4=PasskeyEntry, 5=OOB, 6=Password.
    pub method: u8,
    pub(crate) _reserved: [u8; 3],
}

// SAFETY: SlePairParams is repr(C) with only primitive fields.
unsafe impl FromBytes for SlePairParams {}

/// OOB data: remote public key X[32] + Y[32] exchanged out-of-band.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleOobData {
    /// 64 bytes of OOB key material (X[32] || Y[32]).
    pub data: [u8; 64],
}

// SAFETY: SleOobData is repr(C) with only primitive fields.
unsafe impl FromBytes for SleOobData {}

/// Password parameters for password-based pairing.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SlePasswordParams {
    /// Password length (1..32).
    pub len: u8,
    pub(crate) _reserved: [u8; 3],
    /// Password data (up to 32 bytes).
    pub data: [u8; 32],
}

// SAFETY: SlePasswordParams is repr(C) with only primitive fields.
unsafe impl FromBytes for SlePasswordParams {}

/// Passkey input for passkey entry pairing.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SlePasskeyInput {
    /// 6-digit passkey value (0..999999).
    pub passkey: u32,
}

// SAFETY: SlePasskeyInput is repr(C) with only primitive fields.
unsafe impl FromBytes for SlePasskeyInput {}

/// Parameters for adding a device to the RAL.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleRalAddParams {
    /// Resolution algorithm bits (bit0=local, bit1=peer; 0=AES-CMAC, 1=HMAC-SM3).
    pub resolve_algo: u8,
    /// Peer identity address type.
    pub peer_id_type: u8,
    /// Peer IRKID.
    pub peer_irkid: u8,
    /// Local IRKID.
    pub local_irkid: u8,
    /// Peer identity address (6 bytes).
    pub peer_id: [u8; 6],
    pub(crate) _reserved: [u8; 2],
    /// Peer Identity Resolving Key (16 bytes).
    pub peer_irk: [u8; 16],
    /// Local Identity Resolving Key (16 bytes).
    pub local_irk: [u8; 16],
}

// SAFETY: SleRalAddParams is repr(C) with only primitive fields.
unsafe impl FromBytes for SleRalAddParams {}

/// Parameters for removing a device from the RAL.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleRalRemoveParams {
    /// Peer identity address type.
    pub peer_id_type: u8,
    pub(crate) _reserved: u8,
    /// Peer identity address (6 bytes).
    pub peer_id: [u8; 6],
}

// SAFETY: SleRalRemoveParams is repr(C) with only primitive fields.
unsafe impl FromBytes for SleRalRemoveParams {}

/// Query/result for reading a peer or local RPA.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleRalQueryParams {
    /// Identity address type.
    pub id_type: u8,
    pub(crate) _reserved: u8,
    /// Identity address (6 bytes).
    pub id: [u8; 6],
    /// Output: resolved RPA (6 bytes), filled by kernel.
    pub rpa: [u8; 6],
    pub(crate) _pad: [u8; 2],
}

// SAFETY: SleRalQueryParams is repr(C) with only primitive fields.
unsafe impl FromBytes for SleRalQueryParams {}

/// Security status returned to userspace.
///
/// Layout avoids implicit padding: all fields are u8 or u8 arrays.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleSecInfo {
    /// Security state (SecurityState).
    pub state: u8,
    /// Pairing method (PairingMethod).
    pub method: u8,
    /// Security mode (SecurityMode).
    pub mode: u8,
    /// Whether encryption is currently active.
    pub enc_enabled: u8,
    /// First 4 bytes of SM3(enc_key) for fingerprint verification.
    pub enc_key_fingerprint: [u8; 4],
    pub(crate) _reserved: [u8; 8],
}

/// SM3 hash test request/response.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleHashTest {
    /// Input data length (max 220).
    pub in_len: u16,
    /// Padding.
    pub(crate) _pad: u16,
    /// Input data buffer.
    pub data: [u8; 220],
    /// Output SM3 digest (32 bytes).
    pub digest: [u8; 32],
}

// SAFETY: SleHashTest is repr(C) with only primitive fields.
unsafe impl FromBytes for SleHashTest {}

/// SM4 standalone block encrypt/decrypt test.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleSm4BlockTest {
    /// 128-bit key.
    pub key: [u8; 16],
    /// 16-byte input block.
    pub input: [u8; 16],
    /// 16-byte output block (filled by kernel).
    pub output: [u8; 16],
    /// 0 = encrypt, 1 = decrypt.
    pub decrypt: u8,
    pub(crate) _pad: [u8; 15],
}

// SAFETY: SleSm4BlockTest is repr(C) with only primitive fields.
unsafe impl FromBytes for SleSm4BlockTest {}

/// HMAC-SM3 standalone test.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleHmacTest {
    /// HMAC key length (max 64).
    pub key_len: u16,
    /// Input data length (max 160).
    pub data_len: u16,
    /// HMAC key.
    pub key: [u8; 64],
    /// Input data.
    pub data: [u8; 160],
    /// Output HMAC-SM3 digest (32 bytes, filled by kernel).
    pub digest: [u8; 32],
}

// SAFETY: SleHmacTest is repr(C) with only primitive fields.
unsafe impl FromBytes for SleHmacTest {}

// ---------------------------------------------------------------------------
// SSAP service layer userspace data structures
// ---------------------------------------------------------------------------

/// SSAP summary info returned to userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SsapSummary {
    /// Number of registered services.
    pub service_count: u16,
    /// Total number of properties across all services.
    pub property_count: u16,
    /// Total SSAP entries (services + properties + methods + events).
    pub total_entries: u16,
    /// Negotiated MTU.
    pub mtu: u16,
    /// Pending notification count.
    pub notification_count: u16,
    pub(crate) _reserved: [u8; 6],
}

/// SSAP read/write payload for property access.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SsapReadWrite {
    /// Property handle.
    pub handle: u16,
    /// Data length in bytes.
    pub length: u16,
    /// Data buffer (max 252 bytes).
    pub data: [u8; 252],
}

// SAFETY: SsapReadWrite is repr(C) with only primitive fields.
unsafe impl FromBytes for SsapReadWrite {}

/// Service entry in the discovery result list.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SsapServiceEntry {
    /// Service start handle.
    pub start_handle: u16,
    /// Service end handle.
    pub end_handle: u16,
    /// Service UUID (16-bit; 0 if 128-bit).
    pub uuid16: u16,
    /// Whether primary service.
    pub primary: u8,
    pub(crate) _pad: u8,
}

/// Service list returned from FIND_SVC.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SsapServiceList {
    /// Number of services in the list.
    pub count: u16,
    pub(crate) _pad: [u8; 2],
    /// Up to 15 services.
    pub services: [SsapServiceEntry; 15],
}

/// Dequeued notification/indication payload.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SsapNotification {
    /// Property handle that generated the notification.
    pub handle: u16,
    /// 1 = indication, 0 = notification.
    pub indication: u8,
    /// Data length.
    pub length: u8,
    /// Notification data (max 252 bytes).
    pub data: [u8; 252],
}

/// Dynamic SSAP service registration from userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SsapAddService {
    /// Service UUID (16-bit, or 0 for 128-bit specified in uuid128).
    pub uuid16: u16,
    /// Whether primary (1) or secondary (0) service.
    pub primary: u8,
    pub(crate) _pad: u8,
    /// 128-bit UUID (used when uuid16 == 0).
    pub uuid128: [u8; 16],
    /// Output: assigned start handle.
    pub start_handle: u16,
    pub(crate) _reserved: [u8; 6],
}

// SAFETY: SsapAddService is repr(C) with only primitive fields.
unsafe impl FromBytes for SsapAddService {}

/// Add a property to the last registered SSAP service.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SsapAddProperty {
    /// Property UUID (16-bit).
    pub uuid16: u16,
    /// Operation indicator bitmask (bit0=Read, bit1=Write, bit2=Notify, etc.).
    pub ops: u8,
    /// Length of initial value data.
    pub value_len: u8,
    /// Initial value data (max 248 bytes).
    pub value: [u8; 248],
    /// Output: assigned property handle.
    pub handle: u16,
    pub(crate) _reserved: [u8; 2],
}

// SAFETY: SsapAddProperty is repr(C) with only primitive fields.
unsafe impl FromBytes for SsapAddProperty {}

/// Remote SSAP command targeting a specific connection handle.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SsapRemoteCmd {
    /// Connection handle of the remote peer.
    pub conn_handle: u16,
    pub(crate) _reserved: [u8; 2],
}

// SAFETY: SsapRemoteCmd is repr(C) with only primitive fields.
unsafe impl FromBytes for SsapRemoteCmd {}

/// Remote service discovery via FindStructure.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SsapRemoteDiscover {
    /// Connection handle of the remote peer.
    pub conn_handle: u16,
    /// Start handle of the range to discover (input).
    pub start_handle: u16,
    /// End handle of the range to discover (input).
    pub end_handle: u16,
    /// Number of discovered entries returned (output).
    pub count: u16,
}

// SAFETY: SsapRemoteDiscover is repr(C) with only primitive fields.
unsafe impl FromBytes for SsapRemoteDiscover {}

/// Remote SSAP read/write targeting a specific connection.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SsapRemoteReadWrite {
    /// Connection handle of the remote peer.
    pub conn_handle: u16,
    /// Property handle on the remote device.
    pub handle: u16,
    /// Data length in bytes.
    pub length: u16,
    pub(crate) _pad: [u8; 2],
    /// Data buffer (max 248 bytes).
    pub data: [u8; 248],
}

// SAFETY: SsapRemoteReadWrite is repr(C) with only primitive fields.
unsafe impl FromBytes for SsapRemoteReadWrite {}

/// UUID-based SSAP operation (find-by-uuid, read-by-uuid).
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SsapUuidOp {
    /// Connection handle of the remote peer.
    pub conn_handle: u16,
    /// 16-bit UUID (0 when using uuid128).
    pub uuid16: u16,
    /// 128-bit UUID (ignored when uuid16 != 0).
    pub uuid128: [u8; 16],
    /// Output: matched handle.
    pub handle: u16,
    /// Output: data length.
    pub length: u16,
    /// Output: read data (READ_BY_UUID only).
    pub data: [u8; 232],
}

// SAFETY: SsapUuidOp is repr(C) with only primitive fields.
unsafe impl FromBytes for SsapUuidOp {}

// ---------------------------------------------------------------------------
// Power management userspace data structures
// ---------------------------------------------------------------------------

/// Power management status info returned to userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SlePmInfo {
    /// Current power state (0=Active, 1=Sniff, 2=Idle, 3=Suspended).
    pub state: u8,
    /// Whether force-active is enabled.
    pub force_active: u8,
    /// Estimated power consumption percentage (0-100).
    pub power_pct: u8,
    pub(crate) _pad: u8,
    /// Current connection interval in 1.25 ms units.
    pub current_interval: u16,
    /// Supervision timeout in 10 ms units.
    pub supervision_timeout: u16,
    /// Peripheral latency.
    pub latency: u16,
    /// Idle event count since last activity.
    pub idle_count: u16,
    /// Total state transitions.
    pub transitions: u32,
    /// Active events count.
    pub active_events: u64,
    /// Sniff events count.
    pub sniff_events: u64,
    /// Idle events count.
    pub idle_events: u64,
    pub(crate) _reserved: [u8; 8],
}

/// Power state command.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SlePmStateCmd {
    /// Target state: 0=Active, 1=Sniff, 3=Suspend.
    pub target_state: u8,
    pub(crate) _reserved: [u8; 3],
}

// SAFETY: SlePmStateCmd is repr(C) with only primitive fields.
unsafe impl FromBytes for SlePmStateCmd {}

/// Connection interval parameters from userspace.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SlePmInterval {
    /// Minimum interval in 1.25 ms units.
    pub min_interval: u16,
    /// Maximum interval in 1.25 ms units.
    pub max_interval: u16,
    /// Peripheral latency.
    pub latency: u16,
    /// Supervision timeout in 10 ms units.
    pub supervision_timeout: u16,
}

// SAFETY: SlePmInterval is repr(C) with only primitive fields.
unsafe impl FromBytes for SlePmInterval {}

// ---------------------------------------------------------------------------
// Event queue statistics
// ---------------------------------------------------------------------------

/// Lifetime statistics for the event queue.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleEventStats {
    /// Number of events currently pending.
    pub pending: u32,
    pub(crate) _pad: u32,
    /// Total events enqueued (lifetime).
    pub total_enqueued: u64,
    /// Total events dropped (queue full).
    pub total_dropped: u64,
    /// Total events delivered to userspace.
    pub total_delivered: u64,
}

// ---------------------------------------------------------------------------
// DLI controller information
// ---------------------------------------------------------------------------

/// DLI controller information returned to userspace.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleDliInfo {
    /// Bus type (0=None, 1=UART, 2=USB, 3=SDIO).
    pub bus: u8,
    pub(crate) _pad: [u8; 3],
    /// Firmware version (major.minor.patch packed as u32).
    pub firmware_version: u32,
    /// Supported feature bitmask (TXS-10003-2025).
    pub features: u64,
    /// Maximum simultaneous connections.
    pub max_connections: u8,
    /// Maximum advertising sets.
    pub max_adv_sets: u8,
    /// Supported transport modes (bitmask).
    pub transport_modes: u8,
    /// Measurement capabilities (bitmask).
    pub measurement_cap: u8,
    /// Maximum MTU the controller supports.
    pub max_mtu: u16,
    /// Maximum payload segment size per single TX.
    pub max_mps: u16,
    /// Security capabilities (bitmask).
    pub security_cap: u16,
    /// Extended feature bits 64-72.
    pub features_ext: u16,
    /// Controller name (null-terminated).
    pub name: [u8; 32],
    pub(crate) _reserved: [u8; 4],
}

/// DLI event returned to userspace via DLI_POLL_EVENT ioctl.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleDliEvent {
    /// Event type discriminator.
    pub event_type: u8,
    /// Status code (0 = success).
    pub status: u8,
    /// Associated connection handle (if any).
    pub handle: u16,
    /// Opcode that triggered this event (for CommandComplete/Status).
    pub opcode: u16,
    /// Payload length.
    pub data_len: u16,
    /// Event payload.
    pub data: [u8; 240],
    /// Associated address (for conn/adv events).
    pub addr: [u8; 6],
    pub(crate) _pad: [u8; 2],
}

impl Default for SleDliEvent {
    fn default() -> Self {
        // SAFETY: SleDliEvent is repr(C) with all primitive fields; zeroed is valid.
        unsafe { core::mem::zeroed() }
    }
}

/// DLI command sent to the controller via DLI_SEND_CMD ioctl.
///
/// On input: opcode + params. On output: seq (assigned sequence number)
/// so userspace can track the pending command.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleDliCmd {
    /// DLI opcode (OGF|OCF).
    pub opcode: u16,
    /// Parameter length.
    pub param_len: u16,
    /// Assigned sequence number (output, filled by kernel).
    pub seq: u32,
    /// Command parameters.
    pub params: [u8; 240],
}

impl Default for SleDliCmd {
    fn default() -> Self {
        // SAFETY: repr(C) with primitive fields.
        unsafe { core::mem::zeroed() }
    }
}

// SAFETY: SleDliCmd is repr(C) with only primitive fields.
unsafe impl FromBytes for SleDliCmd {}

/// Management plane pending queue statistics.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleMgmtStats {
    /// Currently pending (unresolved) commands.
    pub pending: u16,
    pub(crate) _pad: u16,
    /// Total commands submitted.
    pub total_submitted: u32,
    /// Total commands resolved (complete or timeout).
    pub total_resolved: u32,
    /// Total command timeouts.
    pub total_timeouts: u32,
}

// SAFETY: SleMgmtStats is repr(C) with only primitive fields.
unsafe impl FromBytes for SleMgmtStats {}

/// Unified subsystem statistics for observability.
///
/// Returned by the SUBSYS_STATS ioctl (0x86). Aggregates key counters
/// from the management plane, connection manager, power manager,
/// device registry, and transport framework into a single read.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleSubsysStats {
    /// Number of registered devices in the SleDev registry.
    pub dev_count: u16,
    /// Number of registered transport protocols.
    pub proto_count: u8,
    /// Number of active device-transport bindings.
    pub binding_count: u8,
    /// Active connections.
    pub active_connections: u16,
    /// Management plane pending commands.
    pub mgmt_pending: u16,
    /// Total connections created (lifetime).
    pub total_conn_created: u32,
    /// Total connections completed (lifetime).
    pub total_conn_completed: u32,
    /// Total management commands submitted (lifetime).
    pub total_mgmt_submitted: u32,
    /// Total management command timeouts.
    pub total_mgmt_timeouts: u32,
    /// Power state (0=Active, 1=Sniff, 2=Idle, 3=Suspended).
    pub power_state: u8,
    pub(crate) _pad: [u8; 3],
    /// Power state transitions.
    pub power_transitions: u32,
    /// CRC-12 verification failures (advertising PDUs).
    pub crc_errors: u32,
}

// SAFETY: SleSubsysStats is repr(C) with only primitive fields.
unsafe impl FromBytes for SleSubsysStats {}

#[inline(never)]
pub(crate) fn sle_dli_event_to_wire(ev: &sle_dli::SleEvent) -> SleDliEvent {
    let mut out = SleDliEvent::default();
    match ev {
        sle_dli::SleEvent::CommandComplete {
            opcode,
            status,
            data,
        } => {
            out.event_type = 0x01;
            out.status = *status as u8;
            out.opcode = *opcode as u16;
            let len = data.len().min(240);
            out.data_len = len as u16;
            out.data[..len].copy_from_slice(&data[..len]);
        }
        sle_dli::SleEvent::CommandStatus { opcode, status } => {
            out.event_type = 0x02;
            out.status = *status as u8;
            out.opcode = *opcode as u16;
        }
        sle_dli::SleEvent::AdvReport {
            addr,
            rssi,
            discovery_level,
            data,
        } => {
            out.event_type = 0x03;
            out.addr = *addr;
            out.data[0] = *rssi as u8;
            out.data[1] = *discovery_level;
            let len = data.len().min(238);
            out.data_len = (len + 2) as u16;
            out.data[2..2 + len].copy_from_slice(&data[..len]);
        }
        sle_dli::SleEvent::ConnComplete {
            handle,
            addr,
            status,
        } => {
            out.event_type = 0x04;
            out.handle = *handle;
            out.addr = *addr;
            out.status = *status as u8;
        }
        sle_dli::SleEvent::DataReceived { handle, data } => {
            out.event_type = 0x05;
            out.handle = *handle;
            let len = data.len().min(240);
            out.data_len = len as u16;
            out.data[..len].copy_from_slice(&data[..len]);
        }
        sle_dli::SleEvent::Disconnected { handle, reason } => {
            out.event_type = 0x06;
            out.handle = *handle;
            out.data[0] = *reason;
            out.data_len = 1;
        }
        sle_dli::SleEvent::EncryptionChanged { handle, enabled } => {
            out.event_type = 0x07;
            out.handle = *handle;
            out.data[0] = if *enabled { 1 } else { 0 };
            out.data_len = 1;
        }
        sle_dli::SleEvent::PairRequest { addr, method } => {
            out.event_type = 0x08;
            out.addr = *addr;
            out.data[0] = *method;
            out.data_len = 1;
        }
        sle_dli::SleEvent::HardwareError { code } => {
            out.event_type = 0x09;
            out.data[0] = *code;
            out.data_len = 1;
        }
        sle_dli::SleEvent::BroadcastEnd { reason } => {
            out.event_type = 0x0A;
            out.data[0] = *reason;
            out.data_len = 1;
        }
        sle_dli::SleEvent::PhyUpdate {
            handle,
            mcs_index,
            bandwidth_mhz,
        } => {
            out.event_type = 0x0B;
            out.handle = *handle;
            out.data[0] = *mcs_index;
            out.data[1] = *bandwidth_mhz;
            out.data_len = 2;
        }
        sle_dli::SleEvent::ConnParamUpdate {
            handle,
            interval,
            latency,
            timeout,
        } => {
            out.event_type = 0x0C;
            out.handle = *handle;
            out.data[0] = (*interval & 0xFF) as u8;
            out.data[1] = (*interval >> 8) as u8;
            out.data[2] = (*latency & 0xFF) as u8;
            out.data[3] = (*latency >> 8) as u8;
            out.data[4] = (*timeout & 0xFF) as u8;
            out.data[5] = (*timeout >> 8) as u8;
            out.data_len = 6;
        }
        sle_dli::SleEvent::DataLenChange {
            handle,
            max_tx_octets,
            max_rx_octets,
        } => {
            out.event_type = 0x0D;
            out.handle = *handle;
            out.data[0] = (*max_tx_octets & 0xFF) as u8;
            out.data[1] = (*max_tx_octets >> 8) as u8;
            out.data[2] = (*max_rx_octets & 0xFF) as u8;
            out.data[3] = (*max_rx_octets >> 8) as u8;
            out.data_len = 4;
        }
        sle_dli::SleEvent::DataBufOverflow { link_type } => {
            out.event_type = 0x0E;
            out.data[0] = *link_type;
            out.data_len = 1;
        }
        sle_dli::SleEvent::PeerConnParamReq {
            handle,
            interval_min,
            interval_max,
            latency,
            timeout,
        } => {
            out.event_type = 0x0F;
            out.handle = *handle;
            out.data[0] = (*interval_min & 0xFF) as u8;
            out.data[1] = (*interval_min >> 8) as u8;
            out.data[2] = (*interval_max & 0xFF) as u8;
            out.data[3] = (*interval_max >> 8) as u8;
            out.data[4] = (*latency & 0xFF) as u8;
            out.data[5] = (*latency >> 8) as u8;
            out.data[6] = (*timeout & 0xFF) as u8;
            out.data[7] = (*timeout >> 8) as u8;
            out.data_len = 8;
        }

        // --- HIGH priority events ---
        sle_dli::SleEvent::PowerChangeReport {
            handle,
            reason,
            frame_type,
            bandwidth,
            pilot_density,
            tx_power,
            power_level,
            offset,
        } => {
            out.event_type = 0x10;
            out.handle = *handle;
            out.data[0] = *reason;
            out.data[1] = *frame_type;
            out.data[2] = *bandwidth;
            out.data[3] = *pilot_density;
            out.data[4] = *tx_power as u8;
            out.data[5] = *power_level;
            out.data[6] = *offset as u8;
            out.data_len = 7;
        }
        sle_dli::SleEvent::NumCompletedPackets {
            handle,
            num_completed,
        } => {
            out.event_type = 0x11;
            out.handle = *handle;
            out.data[0] = *num_completed;
            out.data_len = 1;
        }
        sle_dli::SleEvent::EncryptionParamReq { handle } => {
            out.event_type = 0x12;
            out.handle = *handle;
        }

        // --- MEDIUM — Peer Info events ---
        sle_dli::SleEvent::ControllerSignalData {
            handle,
            signal_id,
            data,
        } => {
            out.event_type = 0x13;
            out.handle = *handle;
            out.opcode = *signal_id;
            let len = data.len().min(240);
            out.data_len = len as u16;
            out.data[..len].copy_from_slice(&data[..len]);
        }
        sle_dli::SleEvent::ReadPeerFeatures {
            handle,
            status,
            features,
        } => {
            out.event_type = 0x14;
            out.handle = *handle;
            out.status = *status;
            out.data[..10].copy_from_slice(features);
            out.data_len = 10;
        }
        sle_dli::SleEvent::ReadPeerVersion {
            handle,
            status,
            version,
            manufacturer,
            subversion,
        } => {
            out.event_type = 0x15;
            out.handle = *handle;
            out.status = *status;
            out.data[0] = *version;
            out.data[1] = (*manufacturer & 0xFF) as u8;
            out.data[2] = (*manufacturer >> 8) as u8;
            out.data[3] = (*subversion & 0xFF) as u8;
            out.data[4] = (*subversion >> 8) as u8;
            out.data_len = 5;
        }
        sle_dli::SleEvent::ReadPeerPower {
            handle,
            status,
            frame_type,
            bandwidth,
            pilot_density,
            tx_power,
            power_level,
        } => {
            out.event_type = 0x16;
            out.handle = *handle;
            out.status = *status;
            out.data[0] = *frame_type;
            out.data[1] = *bandwidth;
            out.data[2] = *pilot_density;
            out.data[3] = *tx_power as u8;
            out.data[4] = *power_level;
            out.data_len = 5;
        }
        sle_dli::SleEvent::InquiryRequestReport {
            adv_handle,
            addr_type,
            addr,
            rssi,
            data,
        } => {
            out.event_type = 0x17;
            out.addr = *addr;
            out.data[0] = *adv_handle;
            out.data[1] = *addr_type;
            out.data[2] = *rssi as u8;
            let len = data.len().min(237);
            out.data[3..3 + len].copy_from_slice(&data[..len]);
            out.data_len = (3 + len) as u16;
        }

        // --- MEDIUM — Pairing events ---
        sle_dli::SleEvent::PairInfoExchange {
            handle,
            io_cap,
            oob_flag,
            auth_req,
            max_key_len,
            sec_dist,
            psk_ind,
            crypto_cap,
        } => {
            out.event_type = 0x18;
            out.handle = *handle;
            out.data[0] = *io_cap;
            out.data[1] = *oob_flag;
            out.data[2] = *auth_req;
            out.data[3] = *max_key_len;
            out.data[4] = *sec_dist;
            out.data[5] = *psk_ind;
            out.data[6..10].copy_from_slice(crypto_cap);
            out.data_len = 10;
        }
        sle_dli::SleEvent::PairInfoReport {
            handle,
            io_cap,
            oob_flag,
            auth_req,
            max_key_len,
            sec_dist,
            psk_ind,
            crypto_cap,
        } => {
            out.event_type = 0x19;
            out.handle = *handle;
            out.data[0] = *io_cap;
            out.data[1] = *oob_flag;
            out.data[2] = *auth_req;
            out.data[3] = *max_key_len;
            out.data[4] = *sec_dist;
            out.data[5] = *psk_ind;
            out.data[6..10].copy_from_slice(crypto_cap);
            out.data_len = 10;
        }
        sle_dli::SleEvent::PairOptionReport {
            handle,
            key_len,
            auth_method,
            crypto_alg,
            public_key,
        } => {
            out.event_type = 0x1A;
            out.handle = *handle;
            out.data[0] = *key_len;
            out.data[1] = *auth_method;
            out.data[2..6].copy_from_slice(crypto_alg);
            let len = public_key.len().min(32);
            out.data[6..6 + len].copy_from_slice(&public_key[..len]);
            out.data_len = (6 + len) as u16;
        }
        sle_dli::SleEvent::PeerPublicKey { handle, public_key } => {
            out.event_type = 0x1B;
            out.handle = *handle;
            let len = public_key.len().min(32);
            out.data[..len].copy_from_slice(&public_key[..len]);
            out.data_len = len as u16;
        }
        sle_dli::SleEvent::PairExtData {
            handle,
            ext_pubkey_x,
            ext_pubkey_y,
        } => {
            out.event_type = 0x1C;
            out.handle = *handle;
            let lx = ext_pubkey_x.len().min(32);
            out.data[..lx].copy_from_slice(&ext_pubkey_x[..lx]);
            let ly = ext_pubkey_y.len().min(32);
            out.data[32..32 + ly].copy_from_slice(&ext_pubkey_y[..ly]);
            out.data_len = (32 + ly) as u16;
        }
        sle_dli::SleEvent::KeypressNotify { handle, action } => {
            out.event_type = 0x1D;
            out.handle = *handle;
            out.data[..4].copy_from_slice(action);
            out.data_len = 4;
        }
        sle_dli::SleEvent::PairRandom { handle, random } => {
            out.event_type = 0x1E;
            out.handle = *handle;
            out.data[..16].copy_from_slice(random);
            out.data_len = 16;
        }
        sle_dli::SleEvent::PairConfirm { handle, confirm } => {
            out.event_type = 0x1F;
            out.handle = *handle;
            out.data[..16].copy_from_slice(confirm);
            out.data_len = 16;
        }
        sle_dli::SleEvent::DHKeyCheck {
            handle,
            dhkey_check,
        } => {
            out.event_type = 0x20;
            out.handle = *handle;
            out.data[..16].copy_from_slice(dhkey_check);
            out.data_len = 16;
        }
        sle_dli::SleEvent::PairFailure { handle, reason } => {
            out.event_type = 0x21;
            out.handle = *handle;
            out.data[0] = *reason;
            out.data_len = 1;
        }

        // --- LOW — Measurement events ---
        sle_dli::SleEvent::NarrowbandMeasInfo {
            handle,
            meas_type,
            status,
            config_index,
        } => {
            out.event_type = 0x22;
            out.handle = *handle;
            out.status = *status;
            out.data[0] = (*meas_type & 0xFF) as u8;
            out.data[1] = (*meas_type >> 8) as u8;
            out.data[2] = *config_index;
            out.data_len = 3;
        }
        sle_dli::SleEvent::NarrowbandMeasStateChange {
            status,
            config_index,
            meas_state,
        } => {
            out.event_type = 0x23;
            out.status = *status;
            out.data[0] = *config_index;
            out.data[1] = *meas_state;
            out.data_len = 2;
        }
        sle_dli::SleEvent::NarrowbandMeasParamReport {
            handle,
            status,
            config_index,
        } => {
            out.event_type = 0x24;
            out.handle = *handle;
            out.status = *status;
            out.data[0] = *config_index;
            out.data_len = 1;
        }
        sle_dli::SleEvent::LocalNarrowbandMeasCap {
            status,
            antenna_count,
            signal_cap,
            report_cap,
        } => {
            out.event_type = 0x25;
            out.status = *status;
            out.data[0] = *antenna_count;
            out.data[1..5].copy_from_slice(signal_cap);
            out.data[5..9].copy_from_slice(report_cap);
            out.data_len = 9;
        }
        sle_dli::SleEvent::PeerNarrowbandMeasCap {
            handle,
            status,
            antenna_count,
            signal_cap,
            report_cap,
        } => {
            out.event_type = 0x26;
            out.handle = *handle;
            out.status = *status;
            out.data[0] = *antenna_count;
            out.data[1..5].copy_from_slice(signal_cap);
            out.data[5..9].copy_from_slice(report_cap);
            out.data_len = 9;
        }
        sle_dli::SleEvent::MeasStateChange {
            source,
            status,
            instance_handle,
            instance_state,
        } => {
            out.event_type = 0x27;
            out.status = *status;
            out.data[0] = (*source & 0xFF) as u8;
            out.data[1] = (*source >> 8) as u8;
            out.data[2] = *instance_handle;
            out.data[3] = *instance_state;
            out.data_len = 4;
        }
        sle_dli::SleEvent::MeasQuantityReport {
            source,
            meas_source,
            seq,
            instance_handle,
            meas_count,
        } => {
            out.event_type = 0x28;
            out.data[0] = (*source & 0xFF) as u8;
            out.data[1] = (*source >> 8) as u8;
            out.data[2] = (*meas_source & 0xFF) as u8;
            out.data[3] = (*meas_source >> 8) as u8;
            out.data[4] = (*seq & 0xFF) as u8;
            out.data[5] = (*seq >> 8) as u8;
            out.data[6] = *instance_handle;
            out.data[7] = *meas_count;
            out.data_len = 8;
        }

        // --- LOW — SLB events ---
        sle_dli::SleEvent::SlbAdvReport {
            mac_addr,
            channel,
            bandwidth,
            rssi,
            data,
        } => {
            out.event_type = 0x29;
            out.addr = *mac_addr;
            out.data[0] = (*channel & 0xFF) as u8;
            out.data[1] = (*channel >> 8) as u8;
            out.data[2] = *bandwidth;
            out.data[3] = *rssi as u8;
            let len = data.len().min(236);
            out.data[4..4 + len].copy_from_slice(&data[..len]);
            out.data_len = (4 + len) as u16;
        }
        sle_dli::SleEvent::SlbConnComplete {
            handle,
            status,
            peer_addr,
        } => {
            out.event_type = 0x2A;
            out.handle = *handle;
            out.status = *status;
            out.addr = *peer_addr;
        }
        sle_dli::SleEvent::SlbUcastChannelComplete {
            channel_handle,
            conn_handle,
            status,
            max_pkt_len,
            max_pkt_count,
        } => {
            out.event_type = 0x2B;
            out.handle = *channel_handle;
            out.status = *status;
            out.data[0] = (*conn_handle & 0xFF) as u8;
            out.data[1] = (*conn_handle >> 8) as u8;
            out.data[2] = (*max_pkt_len & 0xFF) as u8;
            out.data[3] = (*max_pkt_len >> 8) as u8;
            out.data[4] = (*max_pkt_count & 0xFF) as u8;
            out.data[5] = (*max_pkt_count >> 8) as u8;
            out.data_len = 6;
        }
        sle_dli::SleEvent::SlbUcastChannelUpdate {
            channel_handle,
            status,
            max_pkt_len,
            max_pkt_count,
        } => {
            out.event_type = 0x2C;
            out.handle = *channel_handle;
            out.status = *status;
            out.data[0] = (*max_pkt_len & 0xFF) as u8;
            out.data[1] = (*max_pkt_len >> 8) as u8;
            out.data[2] = (*max_pkt_count & 0xFF) as u8;
            out.data[3] = (*max_pkt_count >> 8) as u8;
            out.data_len = 4;
        }
        sle_dli::SleEvent::SlbChannelDelete {
            channel_handle,
            status,
        } => {
            out.event_type = 0x2D;
            out.handle = *channel_handle;
            out.status = *status;
        }
        sle_dli::SleEvent::SlbNumCompletedPackets {
            channel_handle,
            num_completed,
        } => {
            out.event_type = 0x2E;
            out.handle = *channel_handle;
            out.data[0] = *num_completed;
            out.data_len = 1;
        }

        // --- LOW — Sync Link events ---
        sle_dli::SleEvent::TimeSyncStatusUpdate {
            sync_status,
            clock_source,
            accuracy,
        } => {
            out.event_type = 0x2F;
            out.data[0] = *sync_status;
            out.data[1] = *clock_source;
            out.data[2] = (*accuracy & 0xFF) as u8;
            out.data[3] = ((*accuracy >> 8) & 0xFF) as u8;
            out.data[4] = ((*accuracy >> 16) & 0xFF) as u8;
            out.data[5] = ((*accuracy >> 24) & 0xFF) as u8;
            out.data_len = 6;
        }
        sle_dli::SleEvent::TimeSyncRequest {
            time_seq,
            send_time,
        } => {
            out.event_type = 0x30;
            out.data[0] = (*time_seq & 0xFF) as u8;
            out.data[1] = ((*time_seq >> 8) & 0xFF) as u8;
            out.data[2] = ((*time_seq >> 16) & 0xFF) as u8;
            out.data[3] = ((*time_seq >> 24) & 0xFF) as u8;
            out.data[4..12].copy_from_slice(send_time);
            out.data_len = 12;
        }
        sle_dli::SleEvent::SyncUcastSetupRequest {
            async_handle,
            sync_handle,
            event_group_set_id,
            event_group_id,
        } => {
            out.event_type = 0x31;
            out.handle = *async_handle;
            out.data[0] = (*sync_handle & 0xFF) as u8;
            out.data[1] = (*sync_handle >> 8) as u8;
            out.data[2] = *event_group_set_id;
            out.data[3] = *event_group_id;
            out.data_len = 4;
        }
        sle_dli::SleEvent::SyncUcastSetupComplete {
            async_handle,
            sync_handle,
            status,
        } => {
            out.event_type = 0x32;
            out.handle = *async_handle;
            out.status = *status;
            out.data[0] = (*sync_handle & 0xFF) as u8;
            out.data[1] = (*sync_handle >> 8) as u8;
            out.data_len = 2;
        }
        sle_dli::SleEvent::SyncMcastSetupRequest {
            async_handle,
            sync_handle,
        } => {
            out.event_type = 0x33;
            out.handle = *async_handle;
            out.data[0] = (*sync_handle & 0xFF) as u8;
            out.data[1] = (*sync_handle >> 8) as u8;
            out.data_len = 2;
        }
        sle_dli::SleEvent::SyncMcastSetupComplete {
            async_handle,
            sync_handle,
            status,
        } => {
            out.event_type = 0x34;
            out.handle = *async_handle;
            out.status = *status;
            out.data[0] = (*sync_handle & 0xFF) as u8;
            out.data[1] = (*sync_handle >> 8) as u8;
            out.data_len = 2;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// PHY layer ioctl structures
// ---------------------------------------------------------------------------

/// PHY layer information returned to userspace.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SlePhyInfo {
    /// Current MCS index (0-12).
    pub mcs_index: u8,
    /// Bandwidth in MHz (1, 2, or 4).
    pub bandwidth_mhz: u8,
    /// Pilot density (0=4:1, 1=8:1, 2=16:1, 3=none).
    pub pilot_density: u8,
    /// TX power in dBm (signed).
    pub tx_power_dbm: i8,
    /// MIMO mode (0=SISO, 1=SpatialMux2x2, ...).
    pub mimo_mode: u8,
    /// Number of TX antennas.
    pub num_tx_ant: u8,
    /// Number of RX antennas.
    pub num_rx_ant: u8,
    /// Whether OFDM is used for current MCS.
    pub ofdm: u8,
    /// Effective data rate in kbps.
    pub data_rate_kbps: u32,
    /// Current frequency hopping channel.
    pub hop_channel: u8,
    /// Hopping increment.
    pub hop_increment: u8,
    /// Number of used hopping channels.
    pub hop_used_channels: u8,
    pub(crate) _pad: u8,
    /// Modulation type for current MCS.
    pub modulation: u8,
    /// Code rate numerator.
    pub code_rate_num: u8,
    /// Code rate denominator.
    pub code_rate_den: u8,
    pub(crate) _reserved: [u8; 5],
}

/// Set MCS index command.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SlePhyMcsCmd {
    /// MCS index (0-12).
    pub mcs_index: u8,
    pub(crate) _reserved: [u8; 3],
}

/// Set TX power command.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SlePhyTxPowerCmd {
    /// TX power in dBm.
    pub tx_power_dbm: i8,
    pub(crate) _reserved: [u8; 3],
}

/// MCS selection request/response.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SlePhyMcsSelect {
    /// Input: minimum required data rate in kbps.
    pub min_kbps: u32,
    /// Output: effective data rate in kbps.
    pub effective_kbps: u32,
    /// Input: available SINR in dB x10 (signed).
    pub sinr_db_x10: i16,
    /// Input: bandwidth in MHz.
    pub bandwidth_mhz: u8,
    /// Output: selected MCS index.
    pub selected_mcs: u8,
}

/// Frequency hopping channel info.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SlePhyHopInfo {
    /// Channel index (0-78).
    pub channel: u8,
    pub(crate) _pad: u8,
    /// RF frequency in MHz.
    pub freq_mhz: u16,
    /// Event counter after hop.
    pub event_counter: u16,
    pub(crate) _reserved: [u8; 2],
}

/// Set bandwidth command.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SlePhyBwCmd {
    /// Bandwidth in MHz (1, 2, or 4).
    pub bandwidth_mhz: u8,
    pub(crate) _reserved: [u8; 3],
}

/// SINR thresholds per MCS index (dB x10).
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct SleSinrThresholds {
    /// 13 threshold values for MCS 0-12 (unit: dB x10).
    pub thresholds: [i16; 13],
    pub(crate) _pad: [u8; 2],
}

impl Default for SleSinrThresholds {
    fn default() -> Self {
        Self {
            thresholds: sle_phy::DEFAULT_SINR_THRESHOLDS,
            _pad: [0; 2],
        }
    }
}

// SAFETY: All PHY ioctl structs are repr(C) with only primitive fields.
unsafe impl FromBytes for SlePhyInfo {}
// SAFETY: repr(C), all fields are primitives.
unsafe impl FromBytes for SlePhyMcsCmd {}
// SAFETY: repr(C), all fields are primitives.
unsafe impl FromBytes for SlePhyTxPowerCmd {}
// SAFETY: repr(C), all fields are primitives.
unsafe impl FromBytes for SlePhyMcsSelect {}
// SAFETY: repr(C), all fields are primitives.
unsafe impl FromBytes for SlePhyHopInfo {}
// SAFETY: repr(C), all fields are primitives.
unsafe impl FromBytes for SlePhyBwCmd {}
// SAFETY: repr(C), all fields are primitives.
unsafe impl FromBytes for SleSinrThresholds {}

// ---------------------------------------------------------------------------
// Capability / channel negotiation (T/XS 10003-2025 §8.5)
// ---------------------------------------------------------------------------

/// Peer capability query/response for READ_PEER_FEATURES and READ_PEER_VERSION.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleConnPeerCap {
    /// Connection handle.
    pub handle: u16,
    /// Feature bitmap (10 bytes, §10 feature bits).
    pub features: [u8; 10],
    /// Whether features have been exchanged.
    pub features_valid: u8,
    /// Protocol version.
    pub version: u8,
    /// Manufacturer identifier.
    pub manufacturer: u16,
    /// Sub-version number.
    pub subversion: u16,
    /// Whether version has been exchanged.
    pub version_valid: u8,
    pub(crate) _reserved: [u8; 3],
}

/// Connection parameter update request.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleConnParamUpdate {
    /// Connection handle.
    pub handle: u16,
    /// Minimum connection interval (in event group periods).
    pub interval_min: u16,
    /// Maximum connection interval (in event group periods).
    pub interval_max: u16,
    /// Latency period (in event group period multiples).
    pub latency: u16,
    /// Supervision timeout (in 10 ms units).
    pub supervision_timeout: u16,
    pub(crate) _reserved: [u8; 2],
}

/// PHY parameter update request.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleConnPhyUpdate {
    /// Connection handle.
    pub handle: u16,
    /// Desired MCS index (0-12, 0xFF = no change).
    pub mcs_index: u8,
    /// Desired bandwidth in MHz (1/2/4, 0 = no change).
    pub bandwidth_mhz: u8,
}

// SAFETY: repr(C), all fields are primitives.
unsafe impl FromBytes for SleConnPeerCap {}
// SAFETY: repr(C), all fields are primitives.
unsafe impl FromBytes for SleConnParamUpdate {}
// SAFETY: repr(C), all fields are primitives.
unsafe impl FromBytes for SleConnPhyUpdate {}

// ---------------------------------------------------------------------------
// Extended scan filter (T/XS 20001-2025 §6.4)
// ---------------------------------------------------------------------------

/// Maximum number of service UUIDs in a single scan filter.
pub(crate) const SCAN_FILTER_MAX_UUIDS: usize = 4;

/// Extended scan filter for device discovery.
///
/// Allows filtering scan results by 16-bit standard service UUIDs
/// found in advertising data TLV types 0x05-0x08 (service lists).
/// A result passes the filter if its advertising data contains at
/// least one of the specified UUIDs.  An empty list (count == 0)
/// disables UUID filtering.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleScanFilter {
    /// Number of valid UUIDs in the list (0..4).
    pub uuid_count: u8,
    pub _reserved: [u8; 3],
    /// Target 16-bit standard service UUIDs to match.
    pub uuids: [u16; SCAN_FILTER_MAX_UUIDS],
}

// SAFETY: SleScanFilter is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleScanFilter {}

// ---------------------------------------------------------------------------
// Narrowband AFH measurement (T/XS 10003-2025 §8.7)
// ---------------------------------------------------------------------------

/// Local measurement capabilities returned by MEAS_READ_CAP.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleMeasCap {
    /// Supported measurement types bitmask.
    pub meas_types: u8,
    /// Maximum concurrent measurement instances.
    pub max_instances: u8,
    /// Antenna count available for measurements.
    pub antenna_count: u8,
    pub _reserved: u8,
}

// SAFETY: SleMeasCap is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleMeasCap {}

/// Measurement link parameter configuration.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleMeasLinkParam {
    /// Connection handle for the measurement link.
    pub handle: u16,
    /// Measurement type to configure.
    pub meas_type: u8,
    /// Configuration index (0-based).
    pub config_index: u8,
    /// Measurement interval in 10 ms units.
    pub interval: u16,
    /// Duration in 10 ms units (0 = continuous).
    pub duration: u16,
}

// SAFETY: SleMeasLinkParam is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleMeasLinkParam {}

/// Measurement action command (start/stop).
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct SleMeasAction {
    /// Connection handle.
    pub handle: u16,
    /// Action: 0 = stop, 1 = start.
    pub action: u8,
    /// Configuration index.
    pub config_index: u8,
}

// SAFETY: SleMeasAction is repr(C) with only primitive fields, all bit patterns valid.
unsafe impl FromBytes for SleMeasAction {}

// ---------------------------------------------------------------------------
// SCI bus types
// ---------------------------------------------------------------------------

/// Transport bus type for the SCI device.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub(crate) enum SciBus {
    /// No controller attached.
    #[default]
    None = 0,
    /// UART-attached controller.
    Uart = 1,
    /// SPI-attached controller.
    Spi = 2,
    /// SDIO-attached controller.
    Sdio = 3,
    /// USB-attached controller.
    Usb = 4,
    /// MMIO-attached controller.
    Mmio = 5,
}

// ---------------------------------------------------------------------------
// CheckReserved implementations — reject non-zero padding from userspace
// ---------------------------------------------------------------------------

impl_check_reserved!(SciDevInfo, [_reserved]);
impl_check_reserved!(SleAdvParams, [_reserved]);
impl_check_reserved!(SleScanParams, [_reserved]);
impl_check_reserved!(SleScanFilter, [_reserved]);
impl_check_reserved!(SleExtAdvConfig, [_reserved]);
impl_check_reserved!(SleExtAdvData, [_pad]);
impl_check_reserved!(SleExtAdvInfo, [_pad]);
impl_check_reserved!(SleExtAdvEnableParams, [_reserved]);
impl_check_reserved!(SleInjectAdv, [_reserved]);
impl_check_reserved!(SleInjectRawAdv, [_pad]);
impl_check_reserved!(SleConnectParams, [_pad, _reserved]);
impl_check_reserved!(SleConnData, [_reserved]);
impl_check_reserved!(SleInjectConnResp, [_pad]);
impl_check_reserved!(SleConnList, [_pad, _reserved]);
impl_check_reserved!(SleConnMtuParams, [_pad]);
impl_check_reserved!(SleAfhMapParams, [_pad, _pad2]);
impl_check_reserved!(SleAfhClassifyParams, [_pad]);
impl_check_reserved!(SleAfhHopInfo, [_pad]);
impl_check_reserved!(SleSyncCigConfig, [_pad]);
impl_check_reserved!(SleSyncBigConfig, [_pad]);
impl_check_reserved!(SleSyncCreateCmd, [_pad]);
impl_check_reserved!(SleSyncDatapathCmd, [_pad]);
impl_check_reserved!(SleSyncLinkInfo, [_pad2]);
impl_check_reserved!(SleSyncRejectCmd, [_pad]);
impl_check_reserved!(SleSyncDataCmd, [_pad, _pad2]);
impl_check_reserved!(SlePairParams, [_reserved]);
impl_check_reserved!(SlePasswordParams, [_reserved]);
impl_check_reserved!(SleRalAddParams, [_reserved]);
impl_check_reserved!(SleRalRemoveParams, [_reserved]);
impl_check_reserved!(SleRalQueryParams, [_reserved, _pad]);
impl_check_reserved!(SleSecInfo, [_reserved]);
impl_check_reserved!(SleHashTest, [_pad]);
impl_check_reserved!(SleSm4BlockTest, [_pad]);
impl_check_reserved!(SsapSummary, [_reserved]);
impl_check_reserved!(SsapServiceEntry, [_pad]);
impl_check_reserved!(SsapServiceList, [_pad]);
impl_check_reserved!(SsapAddService, [_pad, _reserved]);
impl_check_reserved!(SsapAddProperty, [_reserved]);
impl_check_reserved!(SsapRemoteCmd, [_reserved]);
impl_check_reserved!(SsapRemoteReadWrite, [_pad]);
impl_check_reserved!(SlePmInfo, [_pad, _reserved]);
impl_check_reserved!(SlePmStateCmd, [_reserved]);
impl_check_reserved!(SleEventStats, [_pad]);
impl_check_reserved!(SleDliInfo, [_pad, _reserved]);
impl_check_reserved!(SleDliEvent, [_pad]);
impl_check_reserved!(SleMgmtStats, [_pad]);
impl_check_reserved!(SleSubsysStats, [_pad]);
impl_check_reserved!(SlePhyInfo, [_pad, _reserved]);
impl_check_reserved!(SlePhyMcsCmd, [_reserved]);
impl_check_reserved!(SlePhyTxPowerCmd, [_reserved]);
impl_check_reserved!(SlePhyHopInfo, [_pad, _reserved]);
impl_check_reserved!(SlePhyBwCmd, [_reserved]);
impl_check_reserved!(SleSinrThresholds, [_pad]);
impl_check_reserved!(SleConnPeerCap, [_reserved]);
impl_check_reserved!(SleConnParamUpdate, [_reserved]);
impl_check_reserved!(SleMeasCap, [_reserved]);

// Structs without padding fields — no-op validation.
impl_check_reserved!(SlePskParams);
impl_check_reserved!(SleHmacTest);
impl_check_reserved!(SsapReadWrite);
impl_check_reserved!(SsapNotification);
impl_check_reserved!(SsapRemoteDiscover);
impl_check_reserved!(SleOobData);
impl_check_reserved!(SlePasskeyInput);
impl_check_reserved!(SlePmInterval);
impl_check_reserved!(SleDliCmd);
impl_check_reserved!(SlePhyMcsSelect);
impl_check_reserved!(SsapUuidOp);
impl_check_reserved!(SleMeasLinkParam);
impl_check_reserved!(SleMeasAction);
impl_check_reserved!(SleConnPhyUpdate);
impl_check_reserved!(SleAfhRssiReport);
impl_check_reserved!(SleAfhRetxReport);
impl_check_reserved!(SleConnInfo);
