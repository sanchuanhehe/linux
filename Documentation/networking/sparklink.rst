.. SPDX-License-Identifier: GPL-2.0

========================
Linux SparkLink subsystem
========================

SparkLink（星闪）是一种短距无线通信技术，面向智能终端、智能家居、智能汽车
和智能制造等场景，提供低时延、高可靠的无线连接。本子系统实现了 SparkLink
SLE（SparkLink Low Energy）协议栈，遵循 T/XS 10002-2025（SLE 空口技术规范）
和 T/XS 20001-2025（设备发现与服务管理技术规范）两项标准。

整个协议栈使用 Rust 编写，运行在内核态，通过 ``/dev/sparklink`` 字符设备
向用户空间暴露 ioctl 控制接口。

Architecture overview
=====================

子系统按协议层次划分为以下模块：

.. code-block:: none

    +------------------------------------------------------+
    |                    USER SPACE                         |
    |   sparklink_ctl / sparklink_test / custom app         |
    +------------------------------------------------------+
                         |  ioctl
                         v
    +------------------------------------------------------+
    |              sparklink_core (SCI)                     |
    |   misc device · ioctl dispatch · debugfs · module     |
    +------+------+------+------+------+------+------+-----+
           |      |      |      |      |      |      |
           v      v      v      v      v      v      v
        sle_pdu sle_adv sle_conn sle_crypto sle_sec sle_ssap sle_power
         帧编解码 广播扫描  连接管理   国密算法  安全配对  服务属性   功耗管理
    +------------------------------------------------------+
    |          sparklink_virtual (virtual controller)       |
    +------------------------------------------------------+

各模块职责：

**sparklink_core** (``net/sparklink/sparklink_core.rs``, 1513 行)
  SCI（SparkLink Controller Interface）核心。注册 ``/dev/sparklink`` misc
  设备，管理虚拟控制器的生命周期，分发全部 ioctl 命令，维护 debugfs 信息节点。

**sle_pdu** (``net/sparklink/sle_pdu.rs``, 490 行)
  帧编解码器。按照 T/XS 10002-2025 第 6 章定义的 PDU 格式实现帧的序列化与
  反序列化，覆盖 Preamble、Access Address、PDU Header、Payload、CRC24 等字段。

**sle_adv** (``net/sparklink/sle_adv.rs``, 299 行)
  广播与扫描状态机。管理 SLE 的 Advertising 和 Scanning 两种模式，支持
  参数配置、互斥检查、广播报文的注入与扫描结果的收集。

**sle_conn** (``net/sparklink/sle_conn.rs``, 484 行)
  连接管理模块。实现三态状态机（Idle → Connecting → Connected），支持
  GT 角色协商、连接参数谈判、1-bit ARQ 序列号跟踪、数据收发和回环。

**sle_crypto** (``net/sparklink/sle_crypto.rs``, 466 行)
  国密算法库。纯 Rust 实现 SM3 哈希（GB/T 32905-2016）、SM4 分组密码
  （GB/T 32907-2016）、HMAC-SM3 和 SM4-CTR 模式，用于安全层的密钥派生与
  数据加解密。

**sle_security** (``net/sparklink/sle_security.rs``, 282 行)
  安全层状态机。支持 JustWorks 和 PSK 两种配对方式，管理安全状态
  （Unpaired → Pairing → Paired → Encrypted），提供 SM4-CTR 数据加密、
  密钥派生和指纹计算。

**sle_ssap** (``net/sparklink/sle_ssap.rs``, 845 行)
  SSAP（SLE Service Access Profile）层，功能等价于蓝牙 GATT。按照
  T/XS 20001-2025 第 7.4 节实现服务注册、属性读写、方法调用、事件通知和
  服务发现。内置 Device Information Service（UUID 0x0001）。

**sle_power** (``net/sparklink/sle_power.rs``, 298 行)
  功耗管理模块。维护连接间隔、Sniff 参数和功耗统计，实现基于空闲计数的
  自动状态转换（Active → Sniff → Idle），支持挂起/恢复和强制激活。

**sparklink_virtual** (``drivers/sparklink/sparklink_virtual.rs``, 32 行)
  虚拟控制器驱动。在无物理硬件时提供测试用的虚拟 SCI 设备。

Source code layout
==================

.. code-block:: none

    net/sparklink/
    ├── Kconfig                  # 子系统 Kconfig
    ├── Makefile                 # 构建规则
    ├── sparklink_core.rs        # 核心模块
    ├── sle_pdu.rs               # 帧编解码
    ├── sle_adv.rs               # 广播扫描
    ├── sle_conn.rs              # 连接管理
    ├── sle_crypto.rs            # 国密算法
    ├── sle_security.rs          # 安全配对
    ├── sle_ssap.rs              # 服务属性
    └── sle_power.rs             # 功耗管理

    drivers/sparklink/
    ├── Kconfig
    ├── Makefile
    └── sparklink_virtual.rs     # 虚拟控制器

    tools/testing/selftests/sparklink/
    ├── Makefile
    ├── sparklink_test.c         # ioctl 自测程序 (1058 行)
    └── sparklink_ctl.c          # CLI 控制工具 (553 行)

Kernel configuration
====================

启用 SparkLink 子系统需要以下配置：

.. code-block:: none

    CONFIG_RUST=y                  # Rust 支持
    CONFIG_SPARKLINK=y             # SparkLink 核心协议栈
    CONFIG_SPARKLINK_DRIVERS=y     # SparkLink 驱动框架
    CONFIG_SPARKLINK_VIRTUAL=y     # 虚拟控制器（测试用）

可通过 ``make menuconfig`` 在以下路径找到相关选项::

    Networking support → SparkLink short-range wireless subsystem
    Device Drivers → SparkLink Controller drivers → Virtual SparkLink Controller

Building
========

确保内核已启用 Rust 支持（参见 ``Documentation/rust/``），然后按常规方式
编译内核：

.. code-block:: shell

    make O=build menuconfig      # 启用上述 CONFIG 项
    make O=build -j$(nproc)

编译结果中 SparkLink 模块代码链入 vmlinux 或作为模块加载。

ioctl interface
===============

SparkLink 子系统通过 ``/dev/sparklink`` 字符设备提供 ioctl 接口。
ioctl magic number 为 ``'S'`` (0x53)。所有结构体定义见
``net/sparklink/sparklink_core.rs``。

Device management (0x01 – 0x04)
-------------------------------

.. list-table::
   :widths: 10 20 30 40
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x01
     - ``SL_IOCTL_DEV_REGISTER``
     - None
     - 注册一个虚拟 SCI 设备，返回设备索引
   * - 0x02
     - ``SL_IOCTL_DEV_UNREGISTER``
     - Write (u16)
     - 按索引注销 SCI 设备
   * - 0x03
     - ``SL_IOCTL_DEV_COUNT``
     - Read (u32)
     - 读取当前已注册设备数
   * - 0x04
     - ``SL_IOCTL_DEV_INFO``
     - Read (SciDevInfo)
     - 读取设备基本信息

Advertising & Scanning (0x10 – 0x13)
-------------------------------------

.. list-table::
   :widths: 10 20 30 40
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x10
     - ``SL_IOCTL_START_ADV``
     - Write (SleAdvParams)
     - 开始广播，设置间隔和发射功率
   * - 0x11
     - ``SL_IOCTL_STOP_ADV``
     - None
     - 停止广播
   * - 0x12
     - ``SL_IOCTL_START_SCAN``
     - Write (SleScanParams)
     - 开始扫描，设置窗口和扫描类型
   * - 0x13
     - ``SL_IOCTL_STOP_SCAN``
     - None
     - 停止扫描

Loopback injection (0x20 – 0x21)
---------------------------------

.. list-table::
   :widths: 10 20 30 40
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x20
     - ``SL_IOCTL_INJECT_ADV``
     - Write (SleInjectAdv)
     - 向扫描结果队列注入一条虚拟广播报文
   * - 0x21
     - ``SL_IOCTL_SCAN_RESULT_COUNT``
     - None
     - 返回当前扫描结果队列中的报文数量

Connection management (0x30 – 0x36)
------------------------------------

.. list-table::
   :widths: 10 20 30 40
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x30
     - ``SL_IOCTL_CONNECT``
     - Write (SleConnectParams)
     - 发起到目标地址的连接请求
   * - 0x31
     - ``SL_IOCTL_DISCONNECT``
     - None
     - 断开当前连接
   * - 0x32
     - ``SL_IOCTL_CONN_INFO``
     - Read (SleConnInfo)
     - 读取连接状态和参数
   * - 0x33
     - ``SL_IOCTL_CONN_SEND``
     - Write (SleConnData)
     - 发送连接数据
   * - 0x34
     - ``SL_IOCTL_CONN_RECV``
     - Read (SleConnData)
     - 接收连接数据
   * - 0x35
     - ``SL_IOCTL_INJECT_CONN_RESP``
     - Write (SleInjectConnResp)
     - 注入连接响应（回环测试）
   * - 0x36
     - ``SL_IOCTL_INJECT_CONN_DATA``
     - Write (SleConnData)
     - 注入连接数据（回环测试）

Security (0x40 – 0x46)
-----------------------

.. list-table::
   :widths: 10 20 30 40
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x40
     - ``SL_IOCTL_SEC_SET_PSK``
     - Write (SlePskParams)
     - 设置预共享密钥
   * - 0x41
     - ``SL_IOCTL_SEC_PAIR``
     - Write (SlePairParams)
     - 发起配对流程（JustWorks 或 PSK）
   * - 0x42
     - ``SL_IOCTL_SEC_INFO``
     - Read (SleSecInfo)
     - 读取安全状态
   * - 0x43
     - ``SL_IOCTL_SEC_ENCRYPT_ON``
     - None
     - 启用数据加密
   * - 0x44
     - ``SL_IOCTL_SEC_SM3_TEST``
     - Write (SleHashTest)
     - SM3 哈希测试接口
   * - 0x45
     - ``SL_IOCTL_SEC_SM4_ENC_TEST``
     - Write (SleConnData)
     - SM4-CTR 加密测试接口
   * - 0x46
     - ``SL_IOCTL_SEC_SM4_DEC_TEST``
     - Write (SleConnData)
     - SM4-CTR 解密测试接口

SSAP service layer (0x50 – 0x56)
---------------------------------

.. list-table::
   :widths: 10 20 30 40
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x50
     - ``SL_IOCTL_SSAP_REGISTER_SVC``
     - None
     - 注册内置 Device Information Service
   * - 0x51
     - ``SL_IOCTL_SSAP_INFO``
     - Read (SsapSummary)
     - 读取 SSAP 摘要信息（服务数、属性数等）
   * - 0x52
     - ``SL_IOCTL_SSAP_READ``
     - Write/Read (SsapReadWrite)
     - 按 handle 读取属性值
   * - 0x53
     - ``SL_IOCTL_SSAP_WRITE``
     - Write (SsapReadWrite)
     - 按 handle 写入属性值
   * - 0x54
     - ``SL_IOCTL_SSAP_FIND_SVC``
     - Read (SsapServiceList)
     - 服务发现，返回已注册服务列表
   * - 0x55
     - ``SL_IOCTL_SSAP_NOTIFY``
     - Write (u16)
     - 对指定属性触发通知
   * - 0x56
     - ``SL_IOCTL_SSAP_DEQUEUE_NTF``
     - Read (SsapNotification)
     - 取出一条排队的通知

Power management (0x60 – 0x65)
-------------------------------

.. list-table::
   :widths: 10 20 30 40
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x60
     - ``SL_IOCTL_PM_INFO``
     - Read (SlePmInfo)
     - 读取功耗管理状态和统计
   * - 0x61
     - ``SL_IOCTL_PM_SET_STATE``
     - Write (SlePmStateCmd)
     - 设置功耗状态（Active/Sniff/Idle/Suspended）
   * - 0x62
     - ``SL_IOCTL_PM_SET_INTERVAL``
     - Write (SlePmInterval)
     - 设置连接间隔参数
   * - 0x63
     - ``SL_IOCTL_PM_FORCE_ACTIVE``
     - Write (u8)
     - 强制保持 Active 状态（1）或解除（0）
   * - 0x64
     - ``SL_IOCTL_PM_TICK``
     - None
     - 触发一次功耗管理时钟 tick
   * - 0x65
     - ``SL_IOCTL_PM_ACTIVITY``
     - None
     - 上报一次活动事件，重置空闲计数器

debugfs interface
=================

加载 SparkLink 模块后，以下 debugfs 节点在 ``/sys/kernel/debug/sparklink/``
目录下可用：

.. code-block:: none

    /sys/kernel/debug/sparklink/
    ├── version          # 协议栈版本号
    ├── build_info       # 构建信息（内核版本、编译器、标准号）
    ├── subsystems       # 已启用子系统列表
    ├── adv_count        # 广播操作累计次数
    ├── scan_count       # 扫描操作累计次数
    ├── conn_count       # 连接操作累计次数
    └── ioctl_count      # ioctl 调用总次数

所有节点均为只读。

Userspace tools
===============

sparklink_test
--------------

位于 ``tools/testing/selftests/sparklink/sparklink_test.c``，集成测试程序，
覆盖全部子系统的 ioctl 接口。包含 15 个测试用例：

- 设备管理：计数、注册
- 广播扫描：启动/停止广播、启动/停止扫描、互斥检查
- 回环测试：注入广播报文、结果计数、RSSI 过滤
- 连接管理：发起连接、拒绝响应、数据回环
- 安全层：SM3 哈希验证、JustWorks 配对
- SSAP：服务注册与属性读取
- 功耗管理：状态查询与转换
- 错误处理：未知 ioctl

编译和运行：

.. code-block:: shell

    gcc -Wall -Wextra -O2 -o sparklink_test \
        tools/testing/selftests/sparklink/sparklink_test.c
    sudo ./sparklink_test

sparklink_ctl
--------------

位于 ``tools/testing/selftests/sparklink/sparklink_ctl.c``，命令行控制工具，
在缺少 Generic Netlink Rust 绑定的情况下作为主要的用户空间管理接口。

用法：

.. code-block:: shell

    sparklink_ctl <command> [args...]

    # 查看子系统信息
    sparklink_ctl info

    # 广播管理
    sparklink_ctl adv start [interval_ms] [tx_power_dbm]
    sparklink_ctl adv stop

    # 扫描管理
    sparklink_ctl scan start [window_ms] [type]
    sparklink_ctl scan stop
    sparklink_ctl scan count

    # 连接管理
    sparklink_ctl conn connect <addr_hex>
    sparklink_ctl conn info
    sparklink_ctl conn disconnect
    sparklink_ctl conn send <data_hex>

    # 安全管理
    sparklink_ctl sec psk <key_hex>
    sparklink_ctl sec pair <method: 0=JustWorks, 1=PSK>
    sparklink_ctl sec info
    sparklink_ctl sec encrypt

    # SSAP 服务层
    sparklink_ctl ssap register
    sparklink_ctl ssap info
    sparklink_ctl ssap read <handle>
    sparklink_ctl ssap write <handle> <data_hex>

    # 功耗管理
    sparklink_ctl pm info
    sparklink_ctl pm suspend
    sparklink_ctl pm resume

编译：

.. code-block:: shell

    gcc -Wall -Wextra -O2 -o sparklink_ctl \
        tools/testing/selftests/sparklink/sparklink_ctl.c

Protocol overview
=================

SLE 空口帧格式
--------------

按照 T/XS 10002-2025 第 6 章，SLE 空口 PDU 的帧格式如下：

.. code-block:: none

    +----------+----------------+-----------+---------+---------+
    | Preamble | Access Address | PDU Header| Payload | CRC-24  |
    | (1-2 B)  |    (4 B)       |  (2 B)    | (var)   | (3 B)   |
    +----------+----------------+-----------+---------+---------+

    PDU Header 字段：
    +---------+---------+-------+----------+---------+
    | PDU Type| RFU     | TxAdd | Payload  | SN/NESN |
    | (4 bit) | (1 bit) | (1b)  | Len (8b) | (2 bit) |
    +---------+---------+-------+----------+---------+

PDU 类型包括：

- ``AdvInd`` (0x0): 可连接非定向广播
- ``AdvDirectInd`` (0x1): 可连接定向广播
- ``AdvNonconnInd`` (0x2): 不可连接非定向广播
- ``ScanReq`` (0x3): 扫描请求
- ``ScanRsp`` (0x4): 扫描响应
- ``ConnReq`` (0x5): 连接请求
- ``Data`` (0x6): 数据 PDU
- ``Ack`` (0x7): 确认 PDU

SSAP 服务模型
-------------

SSAP（SLE Service Access Profile）遵循 T/XS 20001-2025 第 7.4 节，采用与
蓝牙 GATT 类似的分层模型：

.. code-block:: none

    Service (UUID, handle range)
    ├── Property (类似 Characteristic)
    │   ├── handle
    │   ├── permissions (read/write/notify)
    │   └── value (max 244 bytes)
    ├── Method (可调用操作)
    │   ├── handle
    │   └── permissions
    └── Event (通知/指示)
        ├── handle
        └── permissions

UUID 支持 16 位短格式和 128 位长格式。操作指示器（OpIndicator）以位掩码
编码读、写、通知三种权限。

安全体系
--------

安全层基于国密算法，提供以下机制：

1. **配对** — JustWorks（无需用户交互）或 PSK（预共享密钥）
2. **密钥派生** — 使用 HMAC-SM3 从配对结果和双方随机数派生会话链路密钥
3. **数据加密** — SM4-CTR 模式，128 位密钥，96 位 IV
4. **完整性** — 链路密钥指纹通过 SM3 哈希计算

功耗管理状态机
--------------

.. code-block:: none

    ┌────────┐  idle timeout  ┌───────┐  idle timeout  ┌──────┐
    │ Active │ ─────────────> │ Sniff │ ─────────────> │ Idle │
    └────────┘                └───────┘                └──────┘
         ^                        |                       |
         |     activity event     |    activity event     |
         +────────────────────────+───────────────────────+

                    suspend
         ──────────────────────────> ┌───────────┐
                                     │ Suspended │
                    resume           └───────────┘
         <──────────────────────────

Limitations and future work
============================

当前实现的主要限制：

1. **无物理硬件支持** — 仅有虚拟控制器，所有测试在回环模式下进行
2. **无 Generic Netlink 接口** — 内核 Rust 尚未提供正式的 Generic Netlink
   绑定，暂以 ioctl + CLI 工具替代
3. **国密算法为纯 Rust 实现** — 未对接内核 crypto 子系统的硬件加速路径
4. **单连接** — 连接管理目前仅支持一条活跃连接
5. **SSAP 通知为轮询模式** — 缺少 epoll/异步通知机制

后续计划：

- 对接物理 SLE 射频芯片驱动
- 在 Generic Netlink Rust 绑定就绪后迁移控制面
- 集成内核 crypto API 的 SM3/SM4 实现
- 支持多连接管理
- 添加 sysfs/configfs 运行时配置接口
- 实现基于 poll/epoll 的异步事件通知

References
==========

- T/XS 10002-2025: SparkLink SLE 空口技术规范
- T/XS 20001-2025: SparkLink 设备发现与服务管理技术规范
- GB/T 32905-2016: SM3 密码杂凑算法
- GB/T 32907-2016: SM4 分组密码算法
- ``Documentation/rust/``: Linux 内核 Rust 支持文档
