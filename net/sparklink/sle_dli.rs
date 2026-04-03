// SPDX-License-Identifier: GPL-2.0

//! SparkLink Driver Layer Interface (DLI).
//!
//! Defines the abstract interface between the SparkLink host protocol
//! stack and hardware controller drivers, following T/XS 10003-2025.
//! Every SLE radio chip driver implements the [`SleController`] trait;
//! the core dispatches operations through this trait without knowing
//! the underlying transport (USB, UART, SPI, or SDIO).
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

use kernel::alloc::KVec;
use kernel::prelude::*;

// ---------------------------------------------------------------------------
// Controller backend event ring capacity
// ---------------------------------------------------------------------------

/// Number of slots in each controller backend's event ring buffer.
/// Must be a power of two for efficient modular arithmetic.
pub(crate) const CTRL_EVENT_RING_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Shared event ring for hardware controller backends
// ---------------------------------------------------------------------------

/// Thread-safe event ring buffer used by USB and serdev controllers to
/// buffer asynchronous events received from hardware completion callbacks
/// until `EventPump` polls them via `SleController::poll_event()`.
pub(crate) struct ControllerEventRing {
    events: [(Option<u16>, Option<SleEvent>); CTRL_EVENT_RING_SIZE],
    head: usize,
    tail: usize,
    /// Cumulative count of events dropped due to ring overflow.
    pub(crate) dropped: u32,
}

impl ControllerEventRing {
    pub(crate) fn new() -> Self {
        Self {
            events: [const { (None, None) }; CTRL_EVENT_RING_SIZE],
            head: 0,
            tail: 0,
            dropped: 0,
        }
    }

    /// Push an event with an optional source device id.
    /// Returns `true` if the event was stored, `false` if dropped (ring full).
    pub(crate) fn push_tagged(&mut self, dev_id: Option<u16>, ev: SleEvent) -> bool {
        let next = (self.tail + 1) % CTRL_EVENT_RING_SIZE;
        if next == self.head {
            self.dropped = self.dropped.wrapping_add(1);
            return false;
        }
        self.events[self.tail] = (dev_id, Some(ev));
        self.tail = next;
        true
    }

    /// Push an event without device routing (processed on active device).
    pub(crate) fn push(&mut self, ev: SleEvent) {
        self.push_tagged(None, ev);
    }

    /// Pop the next event along with its source device id.
    pub(crate) fn pop_tagged(&mut self) -> Option<(Option<u16>, SleEvent)> {
        if self.head == self.tail {
            return None;
        }
        let (dev_id, ev) = core::mem::take(&mut self.events[self.head]);
        self.head = (self.head + 1) % CTRL_EVENT_RING_SIZE;
        ev.map(|e| (dev_id, e))
    }

    pub(crate) fn pop(&mut self) -> Option<SleEvent> {
        self.pop_tagged().map(|(_, ev)| ev)
    }
}

// ---------------------------------------------------------------------------
// DLI packet type indicators (T/XS 10003-2025 section 5.1)
// ---------------------------------------------------------------------------

/// DLI packet type byte on the transport layer.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DliPacketType {
    /// Host-to-controller command.
    Command = 0xA1,
    /// Controller-to-host event.
    Event = 0xA2,
    /// Asynchronous unicast data.
    AsyncUnicast = 0xA3,
    /// Synchronous unicast data.
    SyncUnicast = 0xA4,
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
    None = 0,
    Uart = 1,
    Spi = 2,
    Sdio = 3,
    Usb = 4,
    Mmio = 5,
}

/// Feature bits from the 10-byte (80-bit) feature set (T/XS 10003-2025 Table 9).
///
/// Stored as a bitmask in `SleControllerInfo::features`.
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleFeature {
    /// Bit 0: 加密
    Encryption = 1 << 0,
    /// Bit 1: 数据长度更新
    DataLenUpdate = 1 << 1,
    /// Bit 2: PING流程
    Ping = 1 << 2,
    /// Bit 3: 过滤策略
    FilterPolicy = 1 << 3,
    /// Bit 4: 隐私管理
    Privacy = 1 << 4,
    /// Bit 5: 无线帧类型2
    FrameType2 = 1 << 5,
    /// Bit 6: 无线帧类型3
    FrameType3 = 1 << 6,
    /// Bit 7: 无线帧类型4
    FrameType4 = 1 << 7,
    /// Bit 8: 2M带宽
    Bw2m = 1 << 8,
    /// Bit 9: 4M带宽
    Bw4m = 1 << 9,
    /// Bit 10: 导频密度4:1
    Pilot4to1 = 1 << 10,
    /// Bit 11: 导频密度8:1
    Pilot8to1 = 1 << 11,
    /// Bit 12: 导频密度16:1
    Pilot16to1 = 1 << 12,
    /// Bit 13: CRC32类型
    Crc32 = 1 << 13,
    /// Bit 14: MCS0
    Mcs0 = 1 << 14,
    /// Bit 15: MCS1
    Mcs1 = 1 << 15,
    /// Bit 16: MCS2
    Mcs2 = 1 << 16,
    /// Bit 17: MCS3
    Mcs3 = 1 << 17,
    /// Bit 18: MCS4
    Mcs4 = 1 << 18,
    /// Bit 19: MCS5
    Mcs5 = 1 << 19,
    /// Bit 20: MCS6
    Mcs6 = 1 << 20,
    /// Bit 21: MCS7
    Mcs7 = 1 << 21,
    /// Bit 22: MCS8
    Mcs8 = 1 << 22,
    /// Bit 23: MCS9
    Mcs9 = 1 << 23,
    /// Bit 24: MCS10
    Mcs10 = 1 << 24,
    /// Bit 25: MCS11
    Mcs11 = 1 << 25,
    /// Bit 26: MCS12
    Mcs12 = 1 << 26,
    /// Bit 27: 收发间隔25us
    TxRxGap25us = 1 << 27,
    /// Bit 28: 收发间隔50us
    TxRxGap50us = 1 << 28,
    /// Bit 29: 收发间隔75us
    TxRxGap75us = 1 << 29,
    /// Bit 30: 收发间隔100us
    TxRxGap100us = 1 << 30,
    /// Bit 31: 系统管理帧控制
    SysMgmtFrame = 1 << 31,
    /// Bit 32: 系统管理帧跳频算法
    SysMgmtHopping = 1 << 32,
    /// Bit 33: 最小可用信道流程
    MinAvailChannel = 1 << 33,
    /// Bit 34: 睡眠时钟精度更新
    SleepClkAccuracy = 1 << 34,
    /// Bit 35: 远程公钥验证
    RemotePkVerify = 1 << 35,
    /// Bit 36: 功率控制更新
    PowerControl = 1 << 36,
    /// Bit 37: 信道质量估计
    ChannelQuality = 1 << 37,
    /// Bit 38: 5GHz频段
    Band5ghz = 1 << 38,
    /// Bit 39: 角色切换
    RoleSwitch = 1 << 39,
    /// Bit 40: 异步数据组播-G节点
    AsyncDataMcastG = 1 << 40,
    /// Bit 41: 异步数据组播-T节点
    AsyncDataMcastT = 1 << 41,
    /// Bit 42: 异步双向组播-G节点
    AsyncBidiMcastG = 1 << 42,
    /// Bit 43: 异步双向组播-T节点
    AsyncBidiMcastT = 1 << 43,
    /// Bit 44: 异步反馈组播-G节点
    AsyncFbMcastG = 1 << 44,
    /// Bit 45: 异步反馈组播-T节点
    AsyncFbMcastT = 1 << 45,
    /// Bit 46: 异步链接态广播-G节点
    AsyncLinkBcastG = 1 << 46,
    /// Bit 47: 异步链接态广播-T节点
    AsyncLinkBcastT = 1 << 47,
    /// Bit 48: 同步数据组播-G节点
    SyncDataMcastG = 1 << 48,
    /// Bit 49: 同步数据组播-T节点
    SyncDataMcastT = 1 << 49,
    /// Bit 50: 同步双向组播-G节点
    SyncBidiMcastG = 1 << 50,
    /// Bit 51: 同步双向组播-T节点
    SyncBidiMcastT = 1 << 51,
    /// Bit 52: 同步反馈组播-G节点
    SyncFbMcastG = 1 << 52,
    /// Bit 53: 同步反馈组播-T节点
    SyncFbMcastT = 1 << 53,
    /// Bit 54: 同步链接态广播-G节点
    SyncLinkBcastG = 1 << 54,
    /// Bit 55: 同步链接态广播-T节点
    SyncLinkBcastT = 1 << 55,
    /// Bit 56: 异步单播链路参数更新
    AsyncUcastParamUpd = 1 << 56,
    /// Bit 57: 异步组播链路参数更新
    AsyncMcastParamUpd = 1 << 57,
    /// Bit 58: 同步链路参数更新
    SyncParamUpd = 1 << 58,
    /// Bit 59: 链接态广播链路参数更新
    LinkBcastParamUpd = 1 << 59,
    /// Bit 60: 先发后发TG模式
    TgMode = 1 << 60,
    /// Bit 61: 128比特NTP时间
    Ntp128 = 1 << 61,
    /// Bit 62: 64比特NTP时间
    Ntp64 = 1 << 62,
    /// Bit 63: 32比特NTP时间
    Ntp32 = 1u64 << 63,
}

/// Extended feature bits 64-72 (T/XS 10003-2025 Table 9, continued).
/// Stored in a separate `features_ext: u16` field.
pub const SLE_FEAT_EXT_CBG_FB_TYPE3: u16 = 1 << 0; // Bit 64
pub const SLE_FEAT_EXT_CBG_FB_TYPE4: u16 = 1 << 1; // Bit 65
pub const SLE_FEAT_EXT_NB_RANGING: u16 = 1 << 2; // Bit 66
pub const SLE_FEAT_EXT_UWB_RANGING: u16 = 1 << 3; // Bit 67
pub const SLE_FEAT_EXT_UWB_SENSING: u16 = 1 << 4; // Bit 68
pub const SLE_FEAT_EXT_NB_SENSING: u16 = 1 << 5; // Bit 69
pub const SLE_FEAT_EXT_SYNC_UCAST_G: u16 = 1 << 6; // Bit 70
pub const SLE_FEAT_EXT_SYNC_UCAST_T: u16 = 1 << 7; // Bit 71
pub const SLE_FEAT_EXT_VERIFY_BCAST: u16 = 1 << 8; // Bit 72

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
    /// Extended feature bits 64-72 (see `SLE_FEAT_EXT_*`).
    pub features_ext: u16,
    /// Maximum PDU payload size in bytes.
    pub max_pdu_payload: u16,
    /// Maximum number of concurrent connections (0 = unlimited).
    pub max_connections: u8,
    /// Maximum MTU (SSAP message size) the controller supports.
    pub max_mtu: u16,
    /// Maximum payload segment size per single TX.
    pub max_mps: u16,
    /// Supported transport modes (bitmask, see `SLE_TRANSPORT_*`).
    pub transport_modes: u8,
    /// Measurement capabilities (bitmask, see `SLE_MEAS_*`).
    pub measurement_cap: u8,
    /// Security capabilities (bitmask, see `SLE_SEC_*`).
    pub security_cap: u16,
}

// Transport mode bitmask constants.
pub const SLE_TRANSPORT_UNRELIABLE: u8 = 1 << 0;
pub const SLE_TRANSPORT_RELIABLE: u8 = 1 << 1;
pub const SLE_TRANSPORT_FRAGMENTED: u8 = 1 << 2;

// Measurement capability bitmask constants.
pub const SLE_MEAS_RSSI: u8 = 1 << 0;
pub const SLE_MEAS_PATH_LOSS: u8 = 1 << 1;
pub const SLE_MEAS_POWER_MONITOR: u8 = 1 << 2;
pub const SLE_MEAS_CHANNEL_MAP: u8 = 1 << 3;

// Security capability bitmask constants.
pub const SLE_SEC_AES_CCM: u16 = 1 << 0;
pub const SLE_SEC_SM4: u16 = 1 << 1;
pub const SLE_SEC_OOB_AUTH: u16 = 1 << 2;
pub const SLE_SEC_ECDH_P256: u16 = 1 << 3;
pub const SLE_SEC_SC: u16 = 1 << 4;

impl Default for SleControllerInfo {
    fn default() -> Self {
        Self {
            name: [0u8; 32],
            bus: SleBus::None,
            addr: [0u8; 6],
            fw_version: 0,
            features: 0,
            features_ext: 0,
            max_pdu_payload: 255,
            max_connections: 1,
            max_mtu: 247,
            max_mps: 247,
            transport_modes: SLE_TRANSPORT_UNRELIABLE,
            measurement_cap: 0,
            security_cap: 0,
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
    Basic = 0x01,
    /// Group 3: Broadcast / advertising (0x0Cxx).
    Broadcast = 0x03,
    /// Group 4: Scan (0x10xx).
    Scan = 0x04,
    /// Group 5: Connection (0x14xx).
    Connection = 0x05,
    /// Group 6: Link control / PHY (0x18xx).
    LinkControl = 0x06,
    /// Group 7: Security (0x1Cxx).
    Security = 0x07,
    /// Group 8: Measurement (0x20xx).
    Measurement = 0x08,
    /// Group 9: SLB logical channel (0x24xx).
    SlbLogChannel = 0x09,
    /// Group 10: Sync link (0x28xx).
    SyncLink = 0x0A,
    /// Group 62: Test / vendor (0xF8xx).
    Test = 0x3E,
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
/// Group numbers in comments follow the standard document sections.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleOpcode {
    // --- Group 1: Basic (OGF=0x01, wire 0x04xx, section 8.1) ---
    /// 读控制器指令长度 (8.1.1)
    ReadCmdLen = 0x0401,
    /// 读控制器缓存 (8.1.2)
    ReadCtrlBuffer = 0x0402,
    /// 读本地特性 (8.1.3)
    ReadLocalFeatures = 0x0403,
    /// 读本地版本信息 (8.1.4)
    ReadLocalVersion = 0x0404,
    /// 设置媒体接入层唯一标识 (8.1.5)
    SetMacAddr = 0x0405,
    /// 读媒体接入层标识 (8.1.6)
    ReadMacAddr = 0x0406,
    /// 设置媒体接入层非唯一标识 (8.1.7)
    SetNonUniqueMac = 0x0407,
    /// 控制器复位 (8.1.8)
    Reset = 0x0408,
    /// 可用信道指示 (8.1.9)
    AvailChannelInd = 0x0409,
    /// 读白名单大小 (8.1.10)
    ReadWhitelistSize = 0x040A,
    /// 清空白名单 (8.1.11)
    ClearWhitelist = 0x040B,
    /// 添加白名单设备 (8.1.12)
    AddWhitelist = 0x040C,
    /// 删除白名单设备 (8.1.13)
    DeleteWhitelist = 0x040D,
    /// 设置SLB节点角色 (8.1.14)
    SetSlbNodeRole = 0x040E,
    /// 读SLB节点角色 (8.1.15)
    ReadSlbNodeRole = 0x040F,
    /// 设置SLB工作信道 (8.1.16)
    SetSlbWorkChannel = 0x0410,
    /// 读SLB工作信道 (8.1.17)
    ReadSlbWorkChannel = 0x0411,
    /// 读SLB控制器缓存 (8.1.18)
    ReadSlbCtrlBuffer = 0x0412,
    /// 配置FISA信道列表 (8.1.19)
    ConfigFisaChannels = 0x0413,
    /// 使能FISA (8.1.20)
    EnableFisa = 0x0414,
    /// 配置SLB同步信号 (8.1.21)
    ConfigSlbSyncSignal = 0x0415,
    /// 读SLB同步信号配置 (8.1.22)
    ReadSlbSyncSignal = 0x0416,
    /// 读SLB本地功率 (8.1.23)
    ReadSlbLocalPower = 0x0417,
    /// 使能SLB控制器 (8.1.24)
    EnableSlbCtrl = 0x0418,
    /// 指示时间同步状态 (8.1.25)
    IndicateTimeSync = 0x0419,
    /// 时间同步请求 (8.1.26)
    TimeSyncRequest = 0x041A,
    /// 时间同步响应 (8.1.27)
    TimeSyncResponse = 0x041B,
    /// 添加白名单设备扩展 (8.1.28)
    AddWhitelistExt = 0x0420,

    // --- Group 3: Broadcast (OGF=0x03, wire 0x0Cxx, section 8.2) ---
    /// 配置广播参数 (8.2.1)
    SetBroadcastParam = 0x0C02,
    /// 配置广播数据 (8.2.2)
    SetBroadcastData = 0x0C03,
    /// 配置查询回复数据 (8.2.3)
    SetBroadcastScanRsp = 0x0C04,
    /// 使能广播 (8.2.4)
    EnableBroadcast = 0x0C05,
    /// 读最大广播数据长度 (8.2.5)
    ReadMaxBcastDataLen = 0x0C06,
    /// 读广播集合大小 (8.2.6)
    ReadBcastSetSize = 0x0C07,
    /// 删除广播集合 (8.2.7)
    DeleteBcastSet = 0x0C08,
    /// 配置SLB通信域域名 (8.2.8)
    ConfigSlbDomainName = 0x0C09,
    /// 读SLB通信域域名 (8.2.9)
    ReadSlbDomainName = 0x0C0A,
    /// 配置SLB广播参数 (8.2.10)
    ConfigSlbBcastParam = 0x0C0B,
    /// 读SLB广播参数 (8.2.11)
    ReadSlbBcastParam = 0x0C0C,

    // --- Group 4: Scan/Query (OGF=0x04, wire 0x10xx, section 8.3) ---
    /// 设置查询参数 (8.3.1)
    SetScanParam = 0x1001,
    /// 使能查询 (8.3.2)
    EnableScan = 0x1002,
    /// 设置查询请求数据 (8.3.3)
    SetScanReqData = 0x1003,
    /// 设置SLB查询参数 (8.3.4)
    SetSlbScanParam = 0x1004,

    // --- Group 5: Connection (OGF=0x05, wire 0x14xx, section 8.4) ---
    /// 创建异步链路 (8.4.1)
    CreateConnection = 0x1401,
    /// 取消异步链路建立 (8.4.2)
    CancelConnection = 0x1402,
    /// 断开连接 (8.4.3)
    Disconnect = 0x1403,
    /// SLB创建连接 (8.4.4)
    SlbCreateConnection = 0x1404,

    // --- Group 6: Link control (OGF=0x06, wire 0x18xx, section 8.5) ---
    /// 读取对端特性 (8.5.1)
    ReadFeatures = 0x1801,
    /// 读取对端版本信息 (8.5.2)
    ReadVersion = 0x1802,
    /// 设置数据长度 (8.5.3)
    SetMaxDataLen = 0x1804,
    /// 读取物理层参数 (8.5.4)
    ReadPhyParam = 0x1805,
    /// 设置物理层参数 (8.5.5)
    SetPhyParam = 0x1806,
    /// 连接参数更新 (8.5.6)
    ConnParamUpdate = 0x1807,
    /// 设置对端连接参数更新请求的响应 (8.5.7)
    ConnParamReqReply = 0x1808,
    /// 读取可用信道 (8.5.8)
    ReadAvailChannels = 0x1809,
    /// 设置编码调制参数 (8.5.9)
    SetCodingModulation = 0x180A,
    /// 读取RSSI (8.5.10)
    ReadRssi = 0x180C,
    /// 设置本端功率 (8.5.11)
    SetTxPower = 0x180D,
    /// 读取本端功率 (8.5.12)
    ReadTxPower = 0x180E,
    /// 读取对端功率 (8.5.13)
    ReadPeerTxPower = 0x180F,
    /// 功率变化报告配置 (8.5.14)
    ConfigPowerReport = 0x1810,
    /// 设置控制器控制信令数据 (8.5.15)
    SetCtrlSignalData = 0x1812,
    /// 开启RSSI功率控制 (8.5.16)
    EnableRssiPowerCtrl = 0x1813,
    /// 设置SLB编码调制参数 (8.5.17)
    SetSlbCodingMod = 0x1814,
    /// 读取SLB编码调制参数 (8.5.18)
    ReadSlbCodingMod = 0x1815,

    // --- Group 7: Security (OGF=0x07, wire 0x1Cxx, section 8.6) ---
    /// 散列计算 (8.6.1)
    HashCompute = 0x1C01,
    /// 生成安全随机数 (8.6.2)
    GenSecureRandom = 0x1C02,
    /// 启动链路加密 (8.6.3)
    StartEncrypt = 0x1C03,
    /// 请求配对 (8.6.4)
    RequestPair = 0x1C04,
    /// 回复链路加密参数请求 (8.6.5)
    ReplyEncParamReq = 0x1C05,
    /// 拒绝链路加密参数请求 (8.6.6)
    RejectEncParamReq = 0x1C06,
    /// 读取本端加密算法 (8.6.7)
    ReadLocalEncAlgo = 0x1C07,
    /// 启动配对 (8.6.8)
    StartPairing = 0x1C08,
    /// 配对信息交换回复 (8.6.9)
    PairInfoExchange = 0x1C09,
    /// 配对选项确认 (8.6.10)
    PairOptionConfirm = 0x1C0A,
    /// 配对选项接受 (8.6.11)
    PairOptionAccept = 0x1C0B,
    /// 配对扩展数据 (8.6.12)
    PairExtData = 0x1C0C,
    /// 用户通行码按键 (8.6.13)
    PairPasskey = 0x1C0D,
    /// 配对随机数 (8.6.14)
    PairRandom = 0x1C0E,
    /// 配对确认码 (8.6.15)
    PairConfirm = 0x1C0F,
    /// DHKey验证 (8.6.16)
    DhkeyVerify = 0x1C10,
    /// 配对失败 (8.6.17)
    PairFail = 0x1C11,
    /// 添加设备至RAL (8.6.18)
    AddRalDevice = 0x1C12,
    /// 从RAL删除设备 (8.6.19)
    RemoveRalDevice = 0x1C13,
    /// 清空RAL (8.6.20)
    ClearRal = 0x1C14,
    /// 读取RAL大小 (8.6.21)
    ReadRalSize = 0x1C15,
    /// 读对端可解析随机标识 (8.6.22)
    ReadRemoteRpa = 0x1C16,
    /// 读本端可解析随机标识 (8.6.23)
    ReadLocalRpa = 0x1C17,
    /// 设置RPA使能 (8.6.24)
    SetRpaEnable = 0x1C18,
    /// 设置RPA超时时间 (8.6.25)
    SetRpaTimeout = 0x1C19,
    /// 配置SLB认证PSK (8.6.26)
    ConfigSlbAuthPsk = 0x1C1A,
    /// 删除SLB认证PSK (8.6.27)
    DeleteSlbAuthPsk = 0x1C1B,
    /// 配置SLB认证口令 (8.6.28)
    ConfigSlbAuthPwd = 0x1C1C,
    /// 删除SLB认证口令 (8.6.29)
    DeleteSlbAuthPwd = 0x1C1D,
    /// 配置SLB密码算法 (8.6.30)
    ConfigSlbCipherAlgo = 0x1C1E,
    /// 读取SLB密码算法 (8.6.31)
    ReadSlbCipherAlgo = 0x1C1F,
    /// 配置SLB安全关联数量 (8.6.32)
    ConfigSlbSecAssoc = 0x1C20,
    /// 读取SLB安全关联数量 (8.6.33)
    ReadSlbSecAssoc = 0x1C21,
    /// 配置SLB安全绑定过期时间 (8.6.34)
    ConfigSlbSecTimeout = 0x1C22,
    /// 读取SLB安全绑定过期时间 (8.6.35)
    ReadSlbSecTimeout = 0x1C23,

    // --- Group 8: Measurement (OGF=0x08, wire 0x20xx, section 8.7) ---
    /// 读取本地测量能力 (8.7.1)
    ReadLocalMeasCap = 0x2001,
    /// 设置测量链路参数 (8.7.2)
    SetMeasLinkParam = 0x2003,
    /// 测量动作 (8.7.3)
    MeasAction = 0x2005,
    /// 使能测量 (8.7.4)
    EnableMeas = 0x200B,

    // --- Group 9: SLB Logical Channel (OGF=0x09, wire 0x24xx, section 8.8) ---
    /// 创建SLB单播逻辑信道 (8.8.1)
    SlbCreateLogChannel = 0x2401,
    /// 更新SLB单播逻辑信道 (8.8.2)
    SlbUpdateLogChannel = 0x2402,
    /// 删除SLB逻辑信道 (8.8.3)
    SlbDeleteLogChannel = 0x2403,

    // --- Group 10: Sync link (OGF=0x0A, wire 0x28xx, section 8.10) ---
    /// 同步单播链路配置 (8.10.1)
    SyncUcastParam = 0x2801,
    /// 同步单播链路创建 (8.10.3)
    SyncUcastCreate = 0x2803,
    /// 同步单播链路移除 (8.10.4)
    SyncUcastRemove = 0x2804,
    /// 接受同步单播建链 (8.10.5)
    SyncUcastAccept = 0x2805,
    /// 拒绝同步单播建链 (8.10.6)
    SyncUcastReject = 0x2806,
    /// 设置同步组播参数 (8.10.7)
    SyncMcastParam = 0x2807,
    /// 设置同步组播链路信息 (8.10.8)
    SyncMcastInfo = 0x2808,
    /// 创建同步组播链路 (8.10.9)
    SyncMcastCreate = 0x2809,
    /// 同步组播链路信息移除 (8.10.10)
    SyncMcastRemove = 0x280A,
    /// 接受同步组播链路建链 (8.10.11)
    SyncMcastAccept = 0x280B,
    /// 拒绝同步组播链路建链 (8.10.12)
    SyncMcastReject = 0x280C,
    /// 同步链路数据路径配置 (8.10.13)
    SyncDataPathConfig = 0x280D,
    /// 同步链路数据路径删除 (8.10.14)
    SyncDataPathRemove = 0x280E,

    // --- Group 62: Test (OGF=0x3E, wire 0xF8xx, section 8.9) ---
    /// 测试模式使能 (8.9.1)
    TestModeEnable = 0xF801,
    /// 测试接收 (8.9.2)
    TestRx = 0xF802,
    /// 测试发送 (8.9.3)
    TestTx = 0xF803,
    /// 测试接收结果 (8.9.4)
    TestRxResult = 0xF804,

    // --- Vendor extension (OGF=0x3F, wire 0xFCxx-0xFFFF) ---
    /// 厂商自定义指令基址
    VendorBase = 0xFC00,
}

/// Completion status for a command.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleStatus {
    Success = 0x00,
    UnknownCommand = 0x01,
    InvalidParameters = 0x02,
    HardwareFailure = 0x03,
    ResourceExhausted = 0x04,
    NotConnected = 0x05,
    AlreadyActive = 0x06,
    PermissionDenied = 0x07,
    Timeout = 0x08,
}

// ---------------------------------------------------------------------------
// DLI event codes (Controller → Host, T/XS 10003-2025)
// ---------------------------------------------------------------------------

/// Event codes from the controller (T/XS 10003-2025 section 9).
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DliEventCode {
    /// 指令执行状态 (9.1)
    CmdStatus = 0x0001,
    /// 指令执行完成 (9.2)
    CmdComplete = 0x0002,
    /// 数据长度变更 (9.3)
    DataLenChange = 0x0003,
    /// 广播终止 (9.4)
    BroadcastEnd = 0x0004,
    /// 连接断开完成 (9.5)
    DisconnectDone = 0x0005,
    /// 对端连接参数请求 (9.6)
    PeerConnParamReq = 0x0007,
    /// 功率变化上报 (9.7)
    PowerChange = 0x0008,
    /// 成功发送的数据包数量 (9.8)
    TxPktCount = 0x0009,
    /// 硬件错误 (9.9)
    HwError = 0x000A,
    /// 数据缓存溢出 (9.10)
    DataBufOverflow = 0x000B,
    /// 链路加密参数请求 (9.11)
    EncParamReq = 0x000E,
    /// 链路加密状态变更 (9.12)
    EncStatusChange = 0x0011,
    /// 控制器控制信令数据 (9.13)
    CtrlSignalData = 0x0014,
    /// 异步链路建立完成 (9.14)
    ConnEstablished = 0x0015,
    /// 读取对端特性 (9.15)
    PeerFeatures = 0x0016,
    /// 读取对端版本信息 (9.16)
    PeerVersion = 0x0017,
    /// 物理层参数更新 (9.17)
    PhyParamUpdate = 0x0018,
    /// 连接参数更新 (9.18)
    ConnParamUpdate = 0x0019,
    /// 广播信息上报 (9.19)
    BroadcastReport = 0x001A,
    /// 读取对端功率 (9.20)
    ReadRemotePower = 0x001B,
    /// 查询请求上报 (9.21)
    ScanReport = 0x001C,
    /// 配对请求 (9.22)
    PairRequest = 0x001D,
    /// 配对信息交换请求 (9.23)
    PairInfoExchange = 0x001E,
    /// 配对信息上报 (9.24)
    PairInfoReport = 0x001F,
    /// 配对选项上报 (9.25)
    PairOptionReport = 0x0020,
    /// 对端公钥上报 (9.26)
    RemotePublicKey = 0x0021,
    /// 配对扩展数据上报 (9.27)
    PairExtDataReport = 0x0022,
    /// 按键提示通知 (9.28)
    PasskeyNotify = 0x0023,
    /// 配对随机数上报 (9.29)
    PairRandomReport = 0x0024,
    /// 配对确认码上报 (9.30)
    PairConfirmReport = 0x0025,
    /// DHkey验证码上报 (9.31)
    DhkeyVerifyReport = 0x0026,
    /// 配对失败上报 (9.32)
    PairFailReport = 0x0027,
    /// 窄带跳频测量信息上报 (9.33)
    NbfhMeasInfo = 0x0028,
    /// 窄带跳频测量状态改变 (9.34)
    NbfhMeasStateChange = 0x0029,
    /// 窄带跳频测量参数上报 (9.35)
    NbfhMeasParams = 0x002A,
    /// 本端窄带跳频测量能力上报 (9.36)
    LocalNbfhMeasCap = 0x002B,
    /// 对端窄带跳频测量能力上报 (9.37)
    RemoteNbfhMeasCap = 0x002C,
    /// 测量状态变更 (9.38)
    MeasStateChange = 0x002D,
    /// 测量量上报 (9.39)
    MeasReport = 0x002E,
    /// SLB广播信息上报 (9.40)
    SlbBroadcastReport = 0x002F,
    /// SLB连接建立完成 (9.41)
    SlbConnEstablished = 0x0030,
    /// SLB单播逻辑信道建立完成 (9.42)
    SlbLogChannelDone = 0x0031,
    /// SLB单播逻辑信道更新完成 (9.43)
    SlbLogChannelUpdate = 0x0032,
    /// SLB逻辑信道删除完成 (9.44)
    SlbLogChannelDelete = 0x0033,
    /// SLB逻辑信道成功发送数据包数量 (9.45)
    SlbLogChannelTxPkt = 0x0034,
    /// 时间同步状态更新 (9.46)
    TimeSyncUpdate = 0x0035,
    /// 时间同步请求 (9.47)
    TimeSyncRequest = 0x0036,
    /// 同步单播建链请求 (9.48)
    SyncUcastRequest = 0x0038,
    /// 同步单播建链完成 (9.49)
    SyncUcastDone = 0x0039,
    /// 同步组播建链请求 (9.50)
    SyncMcastRequest = 0x003A,
    /// 同步组播建链完成 (9.51)
    SyncMcastDone = 0x003B,
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
        discovery_level: u8,
        data: KVec<u8>,
    },
    /// Connection established.
    ConnComplete {
        handle: u16,
        addr: [u8; 6],
        status: SleStatus,
    },
    /// Data received on a connection.
    DataReceived { handle: u16, data: KVec<u8> },
    /// Connection lost.
    Disconnected { handle: u16, reason: u8 },
    /// Encryption status changed on a connection.
    EncryptionChanged { handle: u16, enabled: bool },
    /// Pairing request from a remote peer.
    PairRequest { addr: [u8; 6], method: u8 },
    /// Controller hardware error.
    HardwareError { code: u8 },
    /// Broadcast / advertising terminated by the controller.
    BroadcastEnd { reason: u8 },
    /// PHY parameters updated on a connection.
    PhyUpdate {
        handle: u16,
        mcs_index: u8,
        bandwidth_mhz: u8,
    },
    /// Connection parameters updated.
    ConnParamUpdate {
        handle: u16,
        interval: u16,
        latency: u16,
        timeout: u16,
    },
    /// Data length changed on a connection.
    DataLenChange {
        handle: u16,
        max_tx_octets: u16,
        max_rx_octets: u16,
    },
    /// Controller data buffer overflow.
    DataBufOverflow { link_type: u8 },
    /// Remote peer requests connection parameter change.
    PeerConnParamReq {
        handle: u16,
        interval_min: u16,
        interval_max: u16,
        latency: u16,
        timeout: u16,
    },

    // --- HIGH priority (§9.1.7, §9.1.8, §9.1.11) ---
    /// TX power change report (§9.1.7).
    PowerChangeReport {
        handle: u16,
        reason: u8,
        frame_type: u8,
        bandwidth: u8,
        pilot_density: u8,
        tx_power: i8,
        power_level: u8,
        offset: i8,
    },
    /// Number of completed packets (§9.1.8).
    NumCompletedPackets { handle: u16, num_completed: u8 },
    /// Link encryption parameter request (§9.1.11).
    EncryptionParamReq { handle: u16 },

    // --- MEDIUM — Peer Info (§9.1.13, §9.1.15–§9.1.16, §9.1.20–§9.1.21) ---
    /// Controller control signaling data (§9.1.13).
    ControllerSignalData {
        handle: u16,
        signal_id: u16,
        data: KVec<u8>,
    },
    /// Read peer features complete (§9.1.15).
    ReadPeerFeatures {
        handle: u16,
        status: u8,
        features: [u8; 10],
    },
    /// Read peer version info complete (§9.1.16).
    ReadPeerVersion {
        handle: u16,
        status: u8,
        version: u8,
        manufacturer: u16,
        subversion: u16,
    },
    /// Read peer TX power complete (§9.1.20).
    ReadPeerPower {
        handle: u16,
        status: u8,
        frame_type: u8,
        bandwidth: u8,
        pilot_density: u8,
        tx_power: i8,
        power_level: u8,
    },
    /// Inquiry (scan) request report (§9.1.21).
    InquiryRequestReport {
        adv_handle: u8,
        addr_type: u8,
        addr: [u8; 6],
        rssi: i8,
        data: KVec<u8>,
    },

    // --- MEDIUM — Pairing (§9.1.23–§9.1.32) ---
    // NOTE: PairRequest (§9.1.22) already exists above.
    /// Pairing information exchange request (§9.1.23).
    PairInfoExchange {
        handle: u16,
        io_cap: u8,
        oob_flag: u8,
        auth_req: u8,
        max_key_len: u8,
        sec_dist: u8,
        psk_ind: u8,
        crypto_cap: [u8; 4],
    },
    /// Pairing information report (§9.1.24).
    PairInfoReport {
        handle: u16,
        io_cap: u8,
        oob_flag: u8,
        auth_req: u8,
        max_key_len: u8,
        sec_dist: u8,
        psk_ind: u8,
        crypto_cap: [u8; 4],
    },
    /// Pairing option report (§9.1.25).
    PairOptionReport {
        handle: u16,
        key_len: u8,
        auth_method: u8,
        crypto_alg: [u8; 4],
        public_key: KVec<u8>,
    },
    /// Peer public key report (§9.1.26).
    PeerPublicKey { handle: u16, public_key: KVec<u8> },
    /// Pairing extended data report (§9.1.27).
    PairExtData {
        handle: u16,
        ext_pubkey_x: KVec<u8>,
        ext_pubkey_y: KVec<u8>,
    },
    /// Keypress notification (§9.1.28).
    KeypressNotify { handle: u16, action: [u8; 4] },
    /// Pairing random number report (§9.1.29).
    PairRandom { handle: u16, random: [u8; 16] },
    /// Pairing confirm code report (§9.1.30).
    PairConfirm { handle: u16, confirm: [u8; 16] },
    /// DH key check report (§9.1.31).
    DHKeyCheck { handle: u16, dhkey_check: [u8; 16] },
    /// Pairing failure report (§9.1.32).
    PairFailure { handle: u16, reason: u8 },

    // --- LOW — Narrowband Measurement (§9.1.33–§9.1.39) ---
    /// Narrowband measurement info (§9.1.33).
    NarrowbandMeasInfo {
        handle: u16,
        status: u8,
        config_index: u8,
    },
    /// Narrowband measurement state change (§9.1.34).
    NarrowbandMeasStateChange {
        status: u8,
        config_index: u8,
        meas_state: u8,
    },
    /// Narrowband measurement parameter report (§9.1.35).
    NarrowbandMeasParamReport {
        handle: u16,
        status: u8,
        config_index: u8,
    },
    /// Local narrowband measurement capabilities (§9.1.36).
    LocalNarrowbandMeasCap { status: u8 },
    /// Peer narrowband measurement capabilities (§9.1.37).
    PeerNarrowbandMeasCap { handle: u16, status: u8 },
    /// Measurement state change (§9.1.38).
    MeasStateChange {
        source: u16,
        status: u8,
        instance_handle: u8,
        instance_state: u8,
    },
    /// Measurement quantity report (§9.1.39).
    MeasQuantityReport {
        source: u16,
        instance_handle: u8,
        meas_count: u8,
    },

    // --- LOW — SLB (§9.1.40–§9.1.45) ---
    /// SLB advertising report (§9.1.40).
    SlbAdvReport {
        mac_addr: [u8; 6],
        channel: u16,
        bandwidth: u8,
        rssi: i8,
        data: KVec<u8>,
    },
    /// SLB connection established (§9.1.41).
    SlbConnComplete {
        handle: u16,
        status: u8,
        peer_addr: [u8; 6],
    },
    /// SLB unicast logical channel established (§9.1.42).
    SlbUcastChannelComplete {
        channel_handle: u16,
        conn_handle: u16,
        status: u8,
        max_pkt_len: u16,
        max_pkt_count: u16,
    },
    /// SLB unicast logical channel updated (§9.1.43).
    SlbUcastChannelUpdate {
        channel_handle: u16,
        status: u8,
        max_pkt_len: u16,
        max_pkt_count: u16,
    },
    /// SLB logical channel deleted (§9.1.44).
    SlbChannelDelete { channel_handle: u16, status: u8 },
    /// SLB completed packets count (§9.1.45).
    SlbNumCompletedPackets {
        channel_handle: u16,
        num_completed: u8,
    },

    // --- LOW — Sync Link (§9.1.46–§9.1.51) ---
    /// Time synchronization status update (§9.1.46).
    TimeSyncStatusUpdate {
        sync_status: u8,
        clock_source: u8,
        accuracy: u32,
    },
    /// Time synchronization request (§9.1.47).
    TimeSyncRequest { time_seq: u32, send_time: [u8; 8] },
    /// Synchronous unicast link setup request (§9.1.48).
    SyncUcastSetupRequest {
        async_handle: u16,
        sync_handle: u16,
        event_group_set_id: u8,
        event_group_id: u8,
    },
    /// Synchronous unicast link setup complete (§9.1.49).
    SyncUcastSetupComplete {
        async_handle: u16,
        sync_handle: u16,
        status: u8,
    },
    /// Synchronous multicast link setup request (§9.1.50).
    SyncMcastSetupRequest { async_handle: u16, sync_handle: u16 },
    /// Synchronous multicast link setup complete (§9.1.51).
    SyncMcastSetupComplete {
        async_handle: u16,
        sync_handle: u16,
        status: u8,
    },
}

// ---------------------------------------------------------------------------
// Controller trait — the DLI (T/XS 10003-2025)
// ---------------------------------------------------------------------------

/// The SparkLink Driver Layer Interface.
///
/// Each SLE controller driver (USB, UART, SPI, etc.) implements
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
// Controller dispatch enum (avoids trait objects)
// ---------------------------------------------------------------------------

/// Concrete controller selector used by the core module.
///
/// This enum wraps all supported controller backends, allowing static
/// dispatch without heap-allocated trait objects.
pub enum ControllerBackend {
    /// No controller attached. All operations return `ENODEV`.
    None,
    Uart(super::sle_uart::UartController),
    Spi(super::sle_spi::SpiController),
    Usb(super::sle_usb::UsbController),
    Serdev(super::sle_serdev::SerdevController),
}

// SAFETY: ControllerBackend is always stored inside Mutex<ControllerBackend>
// in SparkLinkCtl.  The Mutex provides exclusive access, so Cell/RefCell
// interior mutability in the contained controllers is sound.
unsafe impl Send for ControllerBackend {}
// SAFETY: ControllerBackend is always stored inside Mutex<ControllerBackend>
// in SparkLinkCtl.  The Mutex provides exclusive access, so Cell/RefCell
// interior mutability in the contained controllers is sound.
unsafe impl Sync for ControllerBackend {}

impl ControllerBackend {
    /// Create a placeholder backend with no hardware attached.
    pub fn new_none() -> Self {
        Self::None
    }

    /// Returns `true` if no controller hardware is attached.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn new_uart(addr: [u8; 6], config: super::sle_uart::UartConfig) -> Self {
        Self::Uart(super::sle_uart::UartController::new(addr, config))
    }

    pub fn new_spi(addr: [u8; 6], config: super::sle_spi::SpiConfig) -> Self {
        Self::Spi(super::sle_spi::SpiController::new(addr, config))
    }

    pub fn new_usb(addr: [u8; 6], dev_id: u16) -> Self {
        Self::Usb(super::sle_usb::UsbController::new(addr, dev_id))
    }

    pub fn new_serdev(addr: [u8; 6], dev_id: u16) -> Self {
        Self::Serdev(super::sle_serdev::SerdevController::new(addr, dev_id))
    }
}

// -- High-level convenience wrappers ----------------------------------------
// These encapsulate DLI parameter encoding so the core layer never builds
// transport-level byte arrays directly (T/XS 10003-2025 section 8).

/// Convert a raw u16 to SleOpcode, returning None for unknown values.
pub fn sle_opcode_from_u16(v: u16) -> Option<SleOpcode> {
    match v {
        0x0401 => Some(SleOpcode::ReadCmdLen),
        0x0402 => Some(SleOpcode::ReadCtrlBuffer),
        0x0403 => Some(SleOpcode::ReadLocalFeatures),
        0x0404 => Some(SleOpcode::ReadLocalVersion),
        0x0405 => Some(SleOpcode::SetMacAddr),
        0x0406 => Some(SleOpcode::ReadMacAddr),
        0x0407 => Some(SleOpcode::SetNonUniqueMac),
        0x0408 => Some(SleOpcode::Reset),
        0x0409 => Some(SleOpcode::AvailChannelInd),
        0x040A => Some(SleOpcode::ReadWhitelistSize),
        0x040B => Some(SleOpcode::ClearWhitelist),
        0x040C => Some(SleOpcode::AddWhitelist),
        0x040D => Some(SleOpcode::DeleteWhitelist),
        0x040E => Some(SleOpcode::SetSlbNodeRole),
        0x040F => Some(SleOpcode::ReadSlbNodeRole),
        0x0410 => Some(SleOpcode::SetSlbWorkChannel),
        0x0411 => Some(SleOpcode::ReadSlbWorkChannel),
        0x0412 => Some(SleOpcode::ReadSlbCtrlBuffer),
        0x0413 => Some(SleOpcode::ConfigFisaChannels),
        0x0414 => Some(SleOpcode::EnableFisa),
        0x0415 => Some(SleOpcode::ConfigSlbSyncSignal),
        0x0416 => Some(SleOpcode::ReadSlbSyncSignal),
        0x0417 => Some(SleOpcode::ReadSlbLocalPower),
        0x0418 => Some(SleOpcode::EnableSlbCtrl),
        0x0419 => Some(SleOpcode::IndicateTimeSync),
        0x041A => Some(SleOpcode::TimeSyncRequest),
        0x041B => Some(SleOpcode::TimeSyncResponse),
        0x0420 => Some(SleOpcode::AddWhitelistExt),
        0x0C02 => Some(SleOpcode::SetBroadcastParam),
        0x0C03 => Some(SleOpcode::SetBroadcastData),
        0x0C04 => Some(SleOpcode::SetBroadcastScanRsp),
        0x0C05 => Some(SleOpcode::EnableBroadcast),
        0x0C06 => Some(SleOpcode::ReadMaxBcastDataLen),
        0x0C07 => Some(SleOpcode::ReadBcastSetSize),
        0x0C08 => Some(SleOpcode::DeleteBcastSet),
        0x0C09 => Some(SleOpcode::ConfigSlbDomainName),
        0x0C0A => Some(SleOpcode::ReadSlbDomainName),
        0x0C0B => Some(SleOpcode::ConfigSlbBcastParam),
        0x0C0C => Some(SleOpcode::ReadSlbBcastParam),
        0x1001 => Some(SleOpcode::SetScanParam),
        0x1002 => Some(SleOpcode::EnableScan),
        0x1003 => Some(SleOpcode::SetScanReqData),
        0x1004 => Some(SleOpcode::SetSlbScanParam),
        0x1401 => Some(SleOpcode::CreateConnection),
        0x1402 => Some(SleOpcode::CancelConnection),
        0x1403 => Some(SleOpcode::Disconnect),
        0x1404 => Some(SleOpcode::SlbCreateConnection),
        0x1801 => Some(SleOpcode::ReadFeatures),
        0x1802 => Some(SleOpcode::ReadVersion),
        0x1804 => Some(SleOpcode::SetMaxDataLen),
        0x1805 => Some(SleOpcode::ReadPhyParam),
        0x1806 => Some(SleOpcode::SetPhyParam),
        0x1807 => Some(SleOpcode::ConnParamUpdate),
        0x1808 => Some(SleOpcode::ConnParamReqReply),
        0x1809 => Some(SleOpcode::ReadAvailChannels),
        0x180A => Some(SleOpcode::SetCodingModulation),
        0x180C => Some(SleOpcode::ReadRssi),
        0x180D => Some(SleOpcode::SetTxPower),
        0x180E => Some(SleOpcode::ReadTxPower),
        0x180F => Some(SleOpcode::ReadPeerTxPower),
        0x1810 => Some(SleOpcode::ConfigPowerReport),
        0x1812 => Some(SleOpcode::SetCtrlSignalData),
        0x1813 => Some(SleOpcode::EnableRssiPowerCtrl),
        0x1814 => Some(SleOpcode::SetSlbCodingMod),
        0x1815 => Some(SleOpcode::ReadSlbCodingMod),
        0x1C01 => Some(SleOpcode::HashCompute),
        0x1C02 => Some(SleOpcode::GenSecureRandom),
        0x1C03 => Some(SleOpcode::StartEncrypt),
        0x1C04 => Some(SleOpcode::RequestPair),
        0x1C05 => Some(SleOpcode::ReplyEncParamReq),
        0x1C06 => Some(SleOpcode::RejectEncParamReq),
        0x1C07 => Some(SleOpcode::ReadLocalEncAlgo),
        0x1C08 => Some(SleOpcode::StartPairing),
        0x1C09 => Some(SleOpcode::PairInfoExchange),
        0x1C0A => Some(SleOpcode::PairOptionConfirm),
        0x1C0B => Some(SleOpcode::PairOptionAccept),
        0x1C0C => Some(SleOpcode::PairExtData),
        0x1C0D => Some(SleOpcode::PairPasskey),
        0x1C0E => Some(SleOpcode::PairRandom),
        0x1C0F => Some(SleOpcode::PairConfirm),
        0x1C10 => Some(SleOpcode::DhkeyVerify),
        0x1C11 => Some(SleOpcode::PairFail),
        0x1C12 => Some(SleOpcode::AddRalDevice),
        0x1C13 => Some(SleOpcode::RemoveRalDevice),
        0x1C14 => Some(SleOpcode::ClearRal),
        0x1C15 => Some(SleOpcode::ReadRalSize),
        0x1C16 => Some(SleOpcode::ReadRemoteRpa),
        0x1C17 => Some(SleOpcode::ReadLocalRpa),
        0x1C18 => Some(SleOpcode::SetRpaEnable),
        0x1C19 => Some(SleOpcode::SetRpaTimeout),
        0x1C1A => Some(SleOpcode::ConfigSlbAuthPsk),
        0x1C1B => Some(SleOpcode::DeleteSlbAuthPsk),
        0x1C1C => Some(SleOpcode::ConfigSlbAuthPwd),
        0x1C1D => Some(SleOpcode::DeleteSlbAuthPwd),
        0x1C1E => Some(SleOpcode::ConfigSlbCipherAlgo),
        0x1C1F => Some(SleOpcode::ReadSlbCipherAlgo),
        0x1C20 => Some(SleOpcode::ConfigSlbSecAssoc),
        0x1C21 => Some(SleOpcode::ReadSlbSecAssoc),
        0x1C22 => Some(SleOpcode::ConfigSlbSecTimeout),
        0x1C23 => Some(SleOpcode::ReadSlbSecTimeout),
        0x2001 => Some(SleOpcode::ReadLocalMeasCap),
        0x2003 => Some(SleOpcode::SetMeasLinkParam),
        0x2005 => Some(SleOpcode::MeasAction),
        0x200B => Some(SleOpcode::EnableMeas),
        0x2401 => Some(SleOpcode::SlbCreateLogChannel),
        0x2402 => Some(SleOpcode::SlbUpdateLogChannel),
        0x2403 => Some(SleOpcode::SlbDeleteLogChannel),
        0x2801 => Some(SleOpcode::SyncUcastParam),
        0x2803 => Some(SleOpcode::SyncUcastCreate),
        0x2804 => Some(SleOpcode::SyncUcastRemove),
        0x2805 => Some(SleOpcode::SyncUcastAccept),
        0x2806 => Some(SleOpcode::SyncUcastReject),
        0x2807 => Some(SleOpcode::SyncMcastParam),
        0x2808 => Some(SleOpcode::SyncMcastInfo),
        0x2809 => Some(SleOpcode::SyncMcastCreate),
        0x280A => Some(SleOpcode::SyncMcastRemove),
        0x280B => Some(SleOpcode::SyncMcastAccept),
        0x280C => Some(SleOpcode::SyncMcastReject),
        0x280D => Some(SleOpcode::SyncDataPathConfig),
        0x280E => Some(SleOpcode::SyncDataPathRemove),
        0xF801 => Some(SleOpcode::TestModeEnable),
        0xF802 => Some(SleOpcode::TestRx),
        0xF803 => Some(SleOpcode::TestTx),
        0xF804 => Some(SleOpcode::TestRxResult),
        0xFC00 => Some(SleOpcode::VendorBase),
        _ => None,
    }
}

impl ControllerBackend {
    /// Send a command using a raw opcode value (u16).
    ///
    /// Used by the management plane DLI_SEND_CMD ioctl where the opcode
    /// comes from userspace as a raw u16.
    pub fn send_command_raw(&self, raw_opcode: u16, params: &[u8]) -> Result {
        // Validate that raw_opcode is a known SleOpcode discriminant.
        // We cannot use transmute on arbitrary u16 values as that is UB.
        let opcode = sle_opcode_from_u16(raw_opcode).ok_or(EINVAL)?;
        self.send_command(opcode, params)
    }

    /// Enable or disable broadcasting (section 8.2.4).
    pub fn enable_broadcast(&self, enable: bool) -> Result {
        self.send_command(SleOpcode::EnableBroadcast, &[u8::from(enable)])
    }

    /// Enable or disable scanning (section 8.3.3).
    pub fn enable_scan(&self, enable: bool) -> Result {
        self.send_command(SleOpcode::EnableScan, &[u8::from(enable)])
    }

    /// Set the coding & modulation scheme (MCS index, section 8.5.3).
    pub fn set_coding_modulation(&self, mcs_index: u8) -> Result {
        self.send_command(SleOpcode::SetCodingModulation, &[mcs_index])
    }

    /// Set transmit power in dBm (section 8.5.5, sub-type 0x01).
    pub fn set_tx_power(&self, dbm: i8) -> Result {
        let p = [0x01, dbm as u8];
        self.send_command(SleOpcode::SetPhyParam, &p)
    }

    /// Set channel bandwidth in MHz (section 8.5.5, sub-type 0x02).
    pub fn set_bandwidth(&self, mhz: u8) -> Result {
        let p = [0x02, mhz];
        self.send_command(SleOpcode::SetPhyParam, &p)
    }

    /// Initiate a connection to a peer (section 8.4.1).
    pub fn create_connection(&self, peer_addr: &[u8; 6]) -> Result {
        self.send_command(SleOpcode::CreateConnection, peer_addr)
    }

    /// Disconnect a link identified by `handle` (section 8.4.2).
    pub fn disconnect(&self, handle: u16) -> Result {
        let h = handle.to_le_bytes();
        self.send_command(SleOpcode::Disconnect, &h)
    }

    /// Request pairing with the given method byte (§8.6.4).
    ///
    /// Standard format: [handle:2(LE16)][auth_req:1]
    /// The handle is the connection handle; auth_req encodes security
    /// attribute (bits 0-1), MITM flag (bit 2), and keyboard hint (bit 3).
    pub fn request_pair(&self, handle: u16, auth_req: u8, method_hint: u8) -> Result {
        let h = handle.to_le_bytes();
        self.send_command(SleOpcode::RequestPair, &[h[0], h[1], auth_req, method_hint])
    }

    /// Send PairInfoExchangeReply command (§8.6.9, opcode 0x1C09).
    pub fn pair_info_exchange_reply(&self, params: &[u8]) -> Result {
        self.send_command(SleOpcode::PairInfoExchange, params)
    }

    /// Send PairOptionAccept command (§8.6.11, opcode 0x1C0B).
    pub fn pair_option_accept(&self, params: &[u8]) -> Result {
        self.send_command(SleOpcode::PairOptionAccept, params)
    }

    /// Send PairRandom command (§8.6.14, opcode 0x1C0E).
    pub fn pair_random(&self, params: &[u8]) -> Result {
        self.send_command(SleOpcode::PairRandom, params)
    }

    /// Send PairConfirm command (§8.6.15, opcode 0x1C0F).
    pub fn pair_confirm(&self, params: &[u8]) -> Result {
        self.send_command(SleOpcode::PairConfirm, params)
    }

    /// Send DHKeyVerify command (§8.6.16, opcode 0x1C10).
    pub fn dhkey_verify(&self, params: &[u8]) -> Result {
        self.send_command(SleOpcode::DhkeyVerify, params)
    }

    /// Start link encryption (§8.6.3).
    pub fn start_encrypt(&self) -> Result {
        self.send_command(SleOpcode::StartEncrypt, &[])
    }
}

impl SleController for ControllerBackend {
    fn info(&self) -> SleControllerInfo {
        match self {
            Self::None => SleControllerInfo::default(),
            Self::Uart(c) => c.info(),
            Self::Spi(c) => c.info(),
            Self::Usb(c) => c.info(),
            Self::Serdev(c) => c.info(),
        }
    }

    fn open(&self) -> Result {
        match self {
            Self::None => Err(ENODEV),
            Self::Uart(c) => c.open(),
            Self::Spi(c) => c.open(),
            Self::Usb(c) => c.open(),
            Self::Serdev(c) => c.open(),
        }
    }

    fn close(&self) {
        match self {
            Self::None => {},
            Self::Uart(c) => c.close(),
            Self::Spi(c) => c.close(),
            Self::Usb(c) => c.close(),
            Self::Serdev(c) => c.close(),
        }
    }

    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result {
        match self {
            Self::None => Err(ENODEV),
            Self::Uart(c) => c.send_command(opcode, params),
            Self::Spi(c) => c.send_command(opcode, params),
            Self::Usb(c) => c.send_command(opcode, params),
            Self::Serdev(c) => c.send_command(opcode, params),
        }
    }

    fn send_data(&self, handle: u16, data: &[u8]) -> Result {
        match self {
            Self::None => Err(ENODEV),
            Self::Uart(c) => c.send_data(handle, data),
            Self::Spi(c) => c.send_data(handle, data),
            Self::Usb(c) => c.send_data(handle, data),
            Self::Serdev(c) => c.send_data(handle, data),
        }
    }

    fn poll_event(&self) -> Option<SleEvent> {
        match self {
            Self::None => None,
            Self::Uart(c) => c.poll_event(),
            Self::Spi(c) => c.poll_event(),
            Self::Usb(c) => c.poll_event(),
            Self::Serdev(c) => c.poll_event(),
        }
    }

    fn reset(&self) -> Result {
        match self {
            Self::None => Err(ENODEV),
            Self::Uart(c) => c.reset(),
            Self::Spi(c) => c.reset(),
            Self::Usb(c) => c.reset(),
            Self::Serdev(c) => c.reset(),
        }
    }
}
