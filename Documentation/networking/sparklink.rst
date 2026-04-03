.. SPDX-License-Identifier: GPL-2.0

=========================
Linux SparkLink subsystem
=========================

SparkLink (NearLink) is a short-range wireless communication technology
targeting smart terminals, smart home, automotive, and industrial
scenarios, providing low-latency, high-reliability wireless connectivity.

This subsystem implements the SparkLink SLE (SparkLink Low Energy) protocol
stack in the Linux kernel, following these standards:

- T/XS 10002-2025: SLE air interface specification
- T/XS 20001-2025: device discovery and service management
- T/XS 10003-2025: driver layer interface (DLI)

The entire protocol stack is written in Rust and runs in kernel space.
It exposes a character device ``/dev/sparklink`` to userspace for ioctl
control and asynchronous event delivery via ``read()``.

Architecture overview
=====================

The subsystem is organized in a layered architecture:

.. code-block:: none

    +-------------------------------------------------------+
    |                    USER SPACE                         |
    |   sparklink_ctl / sparklink_test / custom app         |
    +-------------------------------------------------------+
            |  ioctl + read()  |  Generic Netlink  |  configfs
            v                  v                   v
    +-------------------------------------------------------+
    |              sparklink_core (SCI)                     |
    |  misc device - ioctl dispatch - event queue - debugfs |
    |  sparklink_genl.c (genetlink) - sle_configfs (config) |
    +--+------+------+------+------+------+------+------+---+
       |      |      |      |      |      |      |      |
       v      v      v      v      v      v      v      v
    sle_pdu sle_adv sle_conn sle_crypto sle_sec sle_ssap sle_power sle_event
    codec   adv/scan  multi    SM3/SM4  pairing   SSAP     PM     event queue
                     conn
    +-------------------------------------------------------+
    |               sle_phy (PHY layer)                     |
    |   MCS table - freq hopping - MIMO - power control     |
    +-------------------------------------------------------+
    |                  sle_dli (DLI)                        |
    |  SleController trait - opcode/event model (10003)     |
    +------+------------------+------------------+----------+
           |                  |                  |
    VirtualController    sle_uart (UART)    sle_spi (SPI)
       (loopback)        H4 framing        register-based
                              |                  |
                         sle_usb (USB)     sle_serdev (serial)
                        hardware discovery  serdev framework

Module descriptions:

**sparklink_core** (``net/sparklink/sparklink_core.rs``)
  SCI (SparkLink Controller Interface) core. Registers the ``/dev/sparklink``
  misc device, dispatches all ioctl commands, delivers events through
  ``read()``, and maintains debugfs information nodes.

**sle_pdu** (``net/sparklink/sle_pdu.rs``)
  Frame codec implementing the PDU format defined in T/XS 10002-2025
  chapter 6, including Preamble, Access Address, PDU Header, Payload,
  and CRC-12.

**sle_adv** (``net/sparklink/sle_adv.rs``)
  Advertising and scanning state machine. Manages broadcast and scan
  modes with parameter configuration and mutual exclusion.

**sle_conn** (``net/sparklink/sle_conn.rs``)
  Multi-connection manager supporting up to 8 simultaneous connections.
  Each connection is identified by a 16-bit handle and follows the
  state machine: Idle -> Connecting -> Connected -> Disconnecting.
  Supports GT role negotiation, parameter negotiation, 1-bit ARQ
  sequence tracking, and per-connection data queues.

**sle_crypto** (``net/sparklink/sle_crypto.rs``)
  Safe Rust wrapper for SparkLink cryptographic flows. Core SM3/SM4/
  HMAC/CTR/ECB operations are delegated to Linux kernel crypto API
  providers through ``sle_crypto_ffi.c``.

**sle_security** (``net/sparklink/sle_security.rs``)
  Security state machine supporting JustWorks and PSK pairing methods.
  Manages security states (Unpaired -> Pairing -> Paired -> Encrypted)
  and provides SM4-CTR data encryption.

**sle_ssap** (``net/sparklink/sle_ssap.rs``)
  SSAP (SLE Service Access Profile) layer, functionally equivalent to
  Bluetooth GATT. Implements property read/write, notifications, and
  service discovery per T/XS 20001-2025 section 7.4.  Supports both
  the built-in Device Information Service and dynamic service
  registration from userspace via ``SSAP_ADD_SVC``, ``SSAP_ADD_PROP``,
  and ``SSAP_REMOVE_SVC`` ioctls.

**sle_power** (``net/sparklink/sle_power.rs``)
  Power management module with automatic state transitions
  (Active -> Sniff -> Idle) based on idle count, plus suspend/resume
  and force-active mode.

**sle_event** (``net/sparklink/sle_event.rs``)
  Asynchronous event notification subsystem. Delivers typed events
  (connection state, advertising reports, data received, security
  changes, power changes, hardware errors) to userspace via ``read()``
  on the device file descriptor.

**sle_configfs** (``net/sparklink/sle_configfs.rs``)
  Configfs-based runtime configuration interface. Registers the
  ``sparklink`` subsystem under ``/sys/kernel/config/`` and exposes
  tunable parameters (max connections, advertising interval, scan
  window, power mode) as configfs attributes.

**sle_dli** (``net/sparklink/sle_dli.rs``)
  Driver Layer Interface following T/XS 10003-2025. Defines the
  ``SleController`` trait that hardware drivers implement, with
  standard DLI opcode encoding (OGF/OCF), event codes, and feature
  bits from the 80-bit feature set.  ``ControllerBackend`` dispatches
  to transport-specific implementations via enum match, and provides
  convenience methods (``enable_broadcast``, ``set_tx_power``,
  ``create_connection``, etc.) that encapsulate byte-level parameter
  encoding so the core layer never constructs DLI payloads directly.

**sle_phy** (``net/sparklink/sle_phy.rs``)
  PHY layer parameter management following T/XS 10002-2025. Includes
  13-entry MCS table (BPSK to 256QAM), adaptive MCS selection based on
  SINR thresholds, 79-channel frequency hopping with configurable hop
  increment, bandwidth configuration (1/2/4 MHz), TX power control
  (-20 to +10 dBm), and MIMO mode support (SISO, 2x2 spatial
  multiplexing, transmit/receive diversity, beamforming).

**sle_uart** (``net/sparklink/sle_uart.rs``)
  UART DLI transport following T/XS 10003-2025. Implements H4-like
  byte-stream framing with packet type indicator, byte-by-byte state
  machine parsing (WaitType -> ReadHeader -> ReadPayload), and
  ``UartController`` implementing the ``SleController`` trait.
  Supports configurable baud rate and hardware flow control.

**sle_spi** (``net/sparklink/sle_spi.rs``)
  SPI DLI transport following T/XS 10003-2025. Implements register-based
  command/response protocol with 6 register addresses (STATUS, CMD,
  DATA_TX, DATA_RX, CONFIG, INT_STATUS). Provides SPI message builders
  for command, data write, status read, and RX read operations.
  ``SpiController`` implements the ``SleController`` trait with
  configurable frequency, SPI mode, and CS polarity.

**sle_usb** (``net/sparklink/sle_usb.rs``)
  USB transport implementation for SLE DLI controllers. Provides DLI
  packet framing (command/event/data), ``UsbController`` implementing
  the ``SleController`` trait, and a USB driver (``usb::Driver``) for
  automatic hardware discovery of devices matching interface class
  0xE0/0x01/0x05.

**sparklink_virtual** (``drivers/sparklink/sparklink_virtual.rs``)
  Virtual controller driver for testing without physical hardware.

**sle_mgmt** (``net/sparklink/sle_mgmt.rs``)
  Management plane command pending queue with timeout.  Tracks in-flight
  DLI commands and resolves entries when CommandComplete/CommandStatus
  events arrive; stale entries are expired based on a jiffies deadline.

**sle_transport** (``net/sparklink/sle_transport.rs``)
  Transport protocol registration and driver attach framework.  Provides
  infrastructure for controller drivers to register transport protocols
  and attach physical devices at probe time.

**sle_fw** (``net/sparklink/sle_fw.rs``)
  Firmware loading framework for SLE controllers.  Loads firmware from
  ``/lib/firmware/`` via the kernel firmware API and sends it to the
  controller in chunks via the USB bulk OUT endpoint.

Source code layout
==================

.. code-block:: none

    net/sparklink/
    ├── Kconfig                  # Subsystem Kconfig
    ├── Makefile                 # Build rules
    ├── sparklink_core.rs        # Core module
    ├── sle_uapi.rs              # UAPI ioctl constants and repr(C) data types
    ├── sparklink_genl.c         # Generic Netlink C bridge
    ├── sle_pdu.rs               # Frame codec
    ├── sle_adv.rs               # Advertising/scanning
    ├── sle_conn.rs              # Multi-connection manager
    ├── sle_crypto.rs            # Crypto API Rust wrapper
    ├── sle_crypto_ffi.c         # Kernel crypto API bridge (C FFI)
    ├── sle_security.rs          # Security/pairing
    ├── sle_ssap.rs              # Service access protocol
    ├── sle_power.rs             # Power management
    ├── sle_event.rs             # Event notification
    ├── sle_netlink.rs           # Netlink protocol types
    ├── sle_configfs.rs          # Configfs runtime configuration
    ├── sle_dli.rs               # Driver layer interface
    ├── sle_phy.rs               # PHY layer parameters
    ├── sle_uart.rs              # UART DLI transport
    ├── sle_spi.rs               # SPI DLI transport
    ├── sle_usb.rs               # USB transport + hardware discovery
    ├── sle_usb_ffi.c            # USB C FFI bridge
    ├── sle_serdev.rs            # serdev transport
    ├── sle_serdev_ffi.c         # serdev C FFI bridge
    ├── sle_mgmt.rs              # Management plane command queue
    ├── sle_transport.rs         # Transport registration framework
    └── sle_fw.rs                # Firmware loading framework

    drivers/sparklink/
    ├── Kconfig
    ├── Makefile
    └── sparklink_virtual.rs     # Virtual controller

    tools/testing/selftests/sparklink/
    ├── Makefile
    ├── sparklink_test.c         # Integration test program
    └── sparklink_ctl.c          # CLI control utility

Kernel configuration
====================

The following options must be enabled:

.. code-block:: none

    CONFIG_RUST=y                  # Rust language support
    CONFIG_SPARKLINK=y             # SparkLink core protocol stack
    CONFIG_SPARKLINK_SLE=y         # SLE air interface support (default y)
    CONFIG_SPARKLINK_GENL=y        # Generic Netlink control plane
    CONFIG_SPARKLINK_DEBUGFS=y     # debugfs information nodes (default y)
    CONFIG_SPARKLINK_DRIVERS=y     # SparkLink driver framework
    CONFIG_SPARKLINK_VIRTUAL=y     # Virtual controller (testing)
    CONFIG_CONFIGFS_FS=y           # configfs filesystem (runtime config)

The ``SPARKLINK`` menuconfig automatically selects required kernel
crypto API modules (``CRYPTO_SM3_GENERIC``, ``CRYPTO_SM4_GENERIC``,
``CRYPTO_ECB``, ``CRYPTO_CTR``, ``CRYPTO_HMAC``).

Find these options in ``make menuconfig`` at::

    Networking support -> SparkLink short-range wireless subsystem
    Device Drivers -> SparkLink Controller drivers -> Virtual SparkLink Controller

Building
========

Ensure kernel Rust support is enabled (see ``Documentation/rust/``),
then build:

.. code-block:: shell

    make O=build menuconfig      # Enable CONFIG options above
    make O=build -j$(nproc)

ioctl interface
===============

The SparkLink subsystem exposes its control plane through ioctl on
``/dev/sparklink``. The ioctl magic number is ``'S'`` (0x53). All
structure definitions are in ``net/sparklink/sparklink_core.rs``.

Device management (0x01 -- 0x08)
--------------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x01
     - ``DEV_REGISTER``
     - None
     - Register a virtual SCI device (stub)
   * - 0x02
     - ``DEV_UNREGISTER``
     - Write (u16)
     - Unregister a SCI device by index (stub)
   * - 0x03
     - ``DEV_COUNT``
     - Read (u32)
     - Get number of registered devices
   * - 0x04
     - ``DEV_INFO``
     - Read (SciDevInfo)
     - Get device information (state, address, name)
   * - 0x05
     - ``DEV_SWITCH``
     - Write (u16)
     - Switch the active controller device by index (swap-on-switch)
   * - 0x06
     - ``DEV_LIST``
     - Read (u16)
     - List all registered device IDs (returns bitmask)
   * - 0x07
     - ``DEV_SELECT``
     - Write (i16)
     - Bind this fd to a specific device (-1 = follow global active)
   * - 0x08
     - ``DEV_GET_ACTIVE``
     - Read (u16)
     - Get the currently active device ID

Advertising and scanning (0x10 -- 0x13)
---------------------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x10
     - ``START_ADV``
     - Write (SleAdvParams)
     - Start advertising with interval and discovery level
   * - 0x11
     - ``STOP_ADV``
     - None
     - Stop advertising
   * - 0x12
     - ``START_SCAN``
     - Write (SleScanParams)
     - Start scanning with window, interval, and filter
   * - 0x13
     - ``STOP_SCAN``
     - None
     - Stop scanning

Loopback injection (0x20 -- 0x21)
---------------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x20
     - ``INJECT_ADV``
     - Write (SleInjectAdv)
     - Inject a simulated advertising PDU into the scan result queue
   * - 0x21
     - ``SCAN_RESULT_COUNT``
     - None (retval)
     - Return number of pending scan results

Scan filtering (0x22 -- 0x24)
-----------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x22
     - ``INJECT_RAW_ADV``
     - Write (SleInjectRawAdv)
     - Inject raw advertising PDU for testing
   * - 0x23
     - ``SET_SCAN_FILTER``
     - Write (SleScanFilter)
     - Set scan filter (discovery level threshold and/or UUID whitelist)
   * - 0x24
     - ``CLEAR_SCAN_FILTER``
     - None
     - Clear all scan filters

Connection management (0x30 -- 0x38)
------------------------------------

All connection ioctls use handle-based addressing. A handle is returned
by ``CONNECT`` and must be passed to subsequent connection operations.
Handle ``0`` is a legacy shortcut that resolves to the first active
connection.

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x30
     - ``CONNECT``
     - Write (SleConnectParams)
     - Initiate connection; returns handle (> 0) on success
   * - 0x31
     - ``DISCONNECT``
     - Write (u16)
     - Disconnect by handle; removes the connection entry
   * - 0x32
     - ``CONN_INFO``
     - Write/Read (SleConnInfo)
     - Get connection state, parameters, and statistics by handle
   * - 0x33
     - ``CONN_SEND``
     - Write (SleConnData)
     - Send data on a connection by handle
   * - 0x34
     - ``CONN_RECV``
     - Write/Read (SleConnData)
     - Receive data from a connection by handle
   * - 0x35
     - ``INJECT_CONN_RESP``
     - Write (SleInjectConnResp)
     - Inject connection response for loopback testing
   * - 0x36
     - ``INJECT_CONN_DATA``
     - Write (SleConnData)
     - Inject received data for loopback testing
   * - 0x37
     - ``CONN_COUNT``
     - None (retval)
     - Return number of active connections
   * - 0x38
     - ``CONN_LIST``
     - Read (SleConnList)
     - Return list of active connection handles (up to 8)

Security (0x40 -- 0x48)
-----------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x40
     - ``SEC_SET_PSK``
     - Write (SlePskParams)
     - Set 128-bit pre-shared key
   * - 0x41
     - ``SEC_PAIR``
     - Write (SlePairParams)
     - Initiate pairing (method=1 JustWorks, method=2 PSK)
   * - 0x42
     - ``SEC_INFO``
     - Read (SleSecInfo)
     - Get security state, method, and key fingerprint
   * - 0x43
     - ``SEC_ENCRYPT_ON``
     - None
     - Enable data path encryption (requires Paired state)
   * - 0x44
     - ``SEC_SM3_TEST``
     - Write (SleHashTest)
     - Compute SM3 hash of input data
   * - 0x45
     - ``SEC_SM4_ENC_TEST``
     - Write (SleConnData)
     - Encrypt data in-place with SM4-CTR
   * - 0x46
     - ``SEC_SM4_DEC_TEST``
     - Write (SleConnData)
     - Decrypt data in-place with SM4-CTR
   * - 0x47
     - ``SEC_SM4_BLOCK_TEST``
     - Write/Read (SleSm4BlockTest)
     - Single-block SM4 encrypt/decrypt test (GB/T 32907-2016 A.1)
   * - 0x48
     - ``SEC_HMAC_TEST``
     - Write/Read (SleHmacTest)
     - HMAC-SM3 computation and verification

SSAP service layer (0x50 -- 0x59)
---------------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x50
     - ``SSAP_REGISTER_SVC``
     - None
     - Register built-in Device Information Service
   * - 0x51
     - ``SSAP_INFO``
     - Read (SsapSummary)
     - Get SSAP summary (service count, MTU, etc.)
   * - 0x52
     - ``SSAP_READ``
     - Write/Read (SsapReadWrite)
     - Read property value by handle
   * - 0x53
     - ``SSAP_WRITE``
     - Write (SsapReadWrite)
     - Write property value by handle
   * - 0x54
     - ``SSAP_FIND_SVC``
     - Read (SsapServiceList)
     - Discover registered services
   * - 0x55
     - ``SSAP_NOTIFY``
     - Write (u16)
     - Trigger notification on a property handle
   * - 0x56
     - ``SSAP_DEQUEUE_NTF``
     - Read (SsapNotification)
     - Dequeue one pending notification
   * - 0x57
     - ``SSAP_ADD_SVC``
     - Write/Read (SsapAddService)
     - Register a custom service (16-bit or 128-bit UUID), returns start_handle
   * - 0x58
     - ``SSAP_ADD_PROP``
     - Write/Read (SsapAddProperty)
     - Add property to current service with operation mask and initial value
   * - 0x59
     - ``SSAP_REMOVE_SVC``
     - Write (u16)
     - Remove a service by its start_handle

SSAP remote operations (0x5A -- 0x5E)
-------------------------------------

Client-side SSAP operations for querying remote services over an
established connection. PDUs are sent via the SERVICE_MGMT TCID.

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x5A
     - ``SSAP_EXCHANGE_INFO``
     - Write (SsapRemoteCmd)
     - Send ExchangeInfo request to negotiate MTU with peer
   * - 0x5B
     - ``SSAP_REMOTE_DISCOVER``
     - Read/Write (SsapRemoteDiscover)
     - Discover remote services, returns cached entry count
   * - 0x5C
     - ``SSAP_REMOTE_READ``
     - Read/Write (SsapRemoteReadWrite)
     - Read a remote property value by handle
   * - 0x5D
     - ``SSAP_REMOTE_WRITE``
     - Write (SsapRemoteReadWrite)
     - Write to a remote property value by handle
   * - 0x5E
     - ``SSAP_REMOTE_EVENT``
     - Read (SsapNotification)
     - Dequeue a remote notification/indication event

Power management (0x60 -- 0x65)
-------------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x60
     - ``PM_INFO``
     - Read (SlePmInfo)
     - Get power state, statistics, and interval parameters
   * - 0x61
     - ``PM_SET_STATE``
     - Write (SlePmStateCmd)
     - Set power state (0=Active, 1=Sniff, 3=Suspend)
   * - 0x62
     - ``PM_SET_INTERVAL``
     - Write (SlePmInterval)
     - Update connection interval parameters
   * - 0x63
     - ``PM_FORCE_ACTIVE``
     - Write (u8)
     - Enable (1) or disable (0) force-active mode
   * - 0x64
     - ``PM_TICK``
     - None
     - Simulate a power management clock tick
   * - 0x65
     - ``PM_ACTIVITY``
     - None
     - Record a data activity event, reset idle counter

Event notification (0x70-0x71)
------------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x70
     - ``EVENT_COUNT``
     - None (retval)
     - Return number of pending events in the queue
   * - 0x71
     - ``EVENT_STATS``
     - Read
     - Return event queue lifetime statistics (SleEventStats)

``SleEventStats`` structure:

.. code-block:: c

    struct sle_event_stats {
        uint32_t pending;          /* current pending count */
        uint32_t _pad;
        uint64_t total_enqueued;   /* lifetime enqueued */
        uint64_t total_dropped;    /* dropped due to queue full */
        uint64_t total_delivered;  /* delivered to userspace */
    };

PHY layer (0x90 -- 0x95)
------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x90
     - ``PHY_INFO``
     - Read (SlePhyInfo)
     - Get current PHY configuration (MCS, bandwidth, TX power, MIMO mode)
   * - 0x91
     - ``PHY_SET_MCS``
     - Write (SlePhyMcsCmd)
     - Set MCS index (0--12) for modulation and coding rate selection
   * - 0x92
     - ``PHY_SET_TXPOWER``
     - Write (SlePhyTxPowerCmd)
     - Set TX power in dBm (range: -20 to +10)
   * - 0x93
     - ``PHY_MCS_SELECT``
     - Write/Read (SlePhyMcsSelect)
     - Adaptive MCS selection: given SINR and bandwidth, selects optimal
       MCS index and returns effective data rate in kbps
   * - 0x94
     - ``PHY_HOP_NEXT``
     - Read (SlePhyHopInfo)
     - Advance the frequency hopping state machine by one event and return
       current channel index, hop increment, and event counter
   * - 0x95
     - ``PHY_SET_BW``
     - Write (SlePhyBwCmd)
     - Set channel bandwidth (1, 2, or 4 MHz)

DLI controller (0x80 -- 0x86)
-----------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x80
     - ``DLI_INFO``
     - Read
     - Return DLI controller information (SleDliInfo)
   * - 0x81
     - ``USB_DEV_COUNT``
     - None (retval)
     - Return number of currently attached USB SLE controllers
   * - 0x82
     - ``DLI_POLL_EVENT``
     - Read (SleDliEvent)
     - Dequeue next pending event from the controller
   * - 0x83
     - ``DLI_RESET``
     - None
     - Reset the DLI controller to a known-good state
   * - 0x84
     - ``DLI_SEND_CMD``
     - Write/Read (SleDliCmd)
     - Send a DLI command to the controller (management plane)
   * - 0x85
     - ``MGMT_STATS``
     - Read (SleMgmtStats)
     - Get management plane pending queue statistics
   * - 0x86
     - ``SUBSYS_STATS``
     - Read (SleSubsysStats)
     - Get unified subsystem statistics (admin observability)

``SleDliInfo`` structure:

.. code-block:: c

    struct sle_dli_info {
        uint8_t  bus;               /* 0=Virtual, 1=UART, 2=SPI, 3=SDIO, 4=USB, 5=MMIO */
        uint8_t  _pad[3];
        uint32_t firmware_version;  /* major.minor.patch packed */
        uint64_t features;          /* feature bitmask (TXS-10003-2025) */
        uint8_t  max_connections;
        uint8_t  max_adv_sets;
        uint8_t  name[32];          /* null-terminated controller name */
        uint8_t  _reserved[14];
    };

Role management (0xA0 -- 0xA1)
------------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0xA0
     - ``SET_ROLE``
     - Write (u8)
     - Set local GT node role (0=T-Node, 1=G-Node)
   * - 0xA1
     - ``GET_ROLE``
     - Read (u8)
     - Get current local GT node role

Extended advertising (0x14 -- 0x1B, 0x22)
-----------------------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x14
     - ``EXT_ADV_CONFIGURE``
     - Write (SleExtAdvConfig)
     - Configure extended advertising set
   * - 0x15
     - ``EXT_ADV_SET_DATA``
     - Write (SleExtAdvData)
     - Set advertising data for a set
   * - 0x16
     - ``EXT_ADV_ENABLE``
     - Write (u8)
     - Enable advertising set by handle
   * - 0x17
     - ``EXT_ADV_DISABLE``
     - Write (u8)
     - Disable advertising set by handle
   * - 0x18
     - ``EXT_ADV_REMOVE``
     - Write (u8)
     - Remove advertising set by handle
   * - 0x19
     - ``EXT_ADV_INFO``
     - Read/Write (SleExtAdvInfo)
     - Query advertising set state
   * - 0x1A
     - ``EXT_ADV_ENABLE_EX``
     - Write (SleExtAdvEnableParams)
     - Enable with max events/duration
   * - 0x1B
     - ``EXT_ADV_TICK``
     - None
     - Advance advertising timer by one event period
   * - 0x22
     - ``INJECT_RAW_ADV``
     - Write (SleInjectRawAdv)
     - Inject raw advertising PDU for testing

AFH and connection extensions (0x39 -- 0x3F)
---------------------------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x39
     - ``SET_CONN_MTU``
     - Write (SleConnMtuParams)
     - Set per-connection MTU/MPS
   * - 0x3A
     - ``AFH_SET_MAP``
     - Write (SleAfhMapParams)
     - Set channel map for a connection
   * - 0x3B
     - ``AFH_GET_MAP``
     - Read/Write (SleAfhMapParams)
     - Get current channel map
   * - 0x3C
     - ``AFH_REPORT_RSSI``
     - Write (SleAfhRssiReport)
     - Report measured RSSI for a channel
   * - 0x3D
     - ``AFH_CLASSIFY``
     - Read/Write (SleAfhClassifyParams)
     - Classify channels by RSSI threshold
   * - 0x3E
     - ``AFH_HOP_NEXT``
     - Read/Write (SleAfhHopInfo)
     - Advance hopping sequence
   * - 0x3F
     - ``AFH_REPORT_RETX``
     - Write (SleAfhRetxReport)
     - Report retransmission on a channel

Security extensions (0x49 -- 0x4F)
----------------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x49
     - ``SEC_RESET``
     - None
     - Reset security state to unpaired
   * - 0x4A
     - ``SEC_GET_PASSKEY``
     - Read (u32)
     - Get generated numeric comparison passkey
   * - 0x4B
     - ``SEC_CONFIRM_PASSKEY``
     - None
     - Confirm numeric comparison
   * - 0x4C
     - ``SEC_REJECT_PASSKEY``
     - None
     - Reject numeric comparison
   * - 0x4D
     - ``SEC_SET_OOB``
     - Write (SleOobData)
     - Set OOB pairing data
   * - 0x4E
     - ``SEC_INPUT_PASSKEY``
     - Write (SlePasskeyInput)
     - Input passkey for passkey entry
   * - 0x4F
     - ``SEC_SET_PASSWORD``
     - Write (SlePasswordParams)
     - Set PIN/password for pairing

Sync link management (0x66 -- 0x6E)
------------------------------------

Isochronous (sync) links for time-sensitive data, supporting unicast
CIG and multicast BIG groups per T/XS 10002-2025 chapter 8.10.

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x66
     - ``SYNC_UCAST_PARAM``
     - Read/Write (SleSyncCigConfig)
     - Configure CIG parameters
   * - 0x67
     - ``SYNC_UCAST_CREATE``
     - Write (SleSyncCreateCmd)
     - Create/activate CIG links
   * - 0x68
     - ``SYNC_UCAST_REMOVE``
     - Write (u8)
     - Remove CIG by ID
   * - 0x69
     - ``SYNC_MCAST_PARAM``
     - Read/Write (SleSyncBigConfig)
     - Configure BIG parameters
   * - 0x6A
     - ``SYNC_MCAST_CREATE``
     - Write (SleSyncCreateCmd)
     - Create/activate BIG links
   * - 0x6B
     - ``SYNC_MCAST_REMOVE``
     - Write (u8)
     - Remove BIG by ID (fails with EBUSY if active)
   * - 0x6C
     - ``SYNC_DATAPATH_CFG``
     - Write (SleSyncDatapathCmd)
     - Configure datapath for sync link
   * - 0x6D
     - ``SYNC_DATAPATH_REMOVE``
     - Write (u16)
     - Remove datapath from sync link
   * - 0x6E
     - ``SYNC_INFO``
     - Read/Write (SleSyncLinkInfo)
     - Query sync link state

PHY extensions (0x96 -- 0x97)
-----------------------------

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x96
     - ``PHY_GET_SINR``
     - Read (SleSinrThresholds)
     - Get SINR threshold table
   * - 0x97
     - ``PHY_SET_SINR``
     - Write (SleSinrThresholds)
     - Set SINR threshold table

RAL/RPA management (0xB0 -- 0xB7)
----------------------------------

Resolving Address List and Resolvable Private Address management
per T/XS 10003-2025 sections 8.6.18--8.6.25.

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0xB0
     - ``RAL_ADD``
     - Write (SleRalAddParams)
     - Add entry to resolving address list
   * - 0xB1
     - ``RAL_REMOVE``
     - Write (SleRalRemoveParams)
     - Remove RAL entry by peer identity
   * - 0xB2
     - ``RAL_CLEAR``
     - None
     - Clear entire resolving address list
   * - 0xB3
     - ``RAL_SIZE``
     - Read (u8)
     - Get number of RAL entries
   * - 0xB4
     - ``RAL_READ_PEER_RPA``
     - Read/Write (SleRalQueryParams)
     - Read peer's RPA
   * - 0xB5
     - ``RAL_READ_LOCAL_RPA``
     - Read/Write (SleRalQueryParams)
     - Read local RPA
   * - 0xB6
     - ``RPA_ENABLE``
     - Write (u8)
     - Enable/disable RPA generation
   * - 0xB7
     - ``RPA_SET_TIMEOUT``
     - Write (u16)
     - Set RPA rotation timeout in seconds

Capability negotiation (0x98 -- 0x9B)
-------------------------------------

Per-connection feature/version exchange and parameter update.

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0x98
     - ``CONN_READ_PEER_FEATURES``
     - Read/Write (SleConnPeerCap)
     - Trigger or query peer feature exchange; sends ReadFeatures DLI
       command if not yet cached
   * - 0x99
     - ``CONN_READ_PEER_VERSION``
     - Read/Write (SleConnPeerCap)
     - Trigger or query peer version exchange; sends ReadVersion DLI
       command if not yet cached
   * - 0x9A
     - ``CONN_UPDATE_PARAMS``
     - Write (SleConnParamUpdate)
     - Request connection parameter update (interval, latency, timeout)
   * - 0x9B
     - ``CONN_PHY_UPDATE``
     - Write (SleConnPhyUpdate)
     - Request PHY parameter update (MCS index, bandwidth) per connection

Narrowband AFH measurement (0xC0 -- 0xC3)
------------------------------------------

Narrowband measurement support per T/XS 10003-2025 section 8.7.

.. list-table::
   :widths: 8 25 15 52
   :header-rows: 1

   * - Nr
     - Name
     - Direction
     - Description
   * - 0xC0
     - ``MEAS_READ_CAP``
     - Read (SleMeasCap)
     - Read local measurement capabilities (DLI opcode 0x2001)
   * - 0xC1
     - ``MEAS_SET_LINK_PARAM``
     - Write (SleMeasLinkParam)
     - Set measurement link parameters (DLI opcode 0x2003)
   * - 0xC2
     - ``MEAS_ACTION``
     - Write (SleMeasAction)
     - Start or stop a measurement action (DLI opcode 0x2005)
   * - 0xC3
     - ``MEAS_ENABLE``
     - Write (u8)
     - Enable or disable measurement reporting (DLI opcode 0x200B)

Error codes
-----------

Common ``errno`` values returned by sparklink ioctls:

.. list-table::
   :widths: 12 88
   :header-rows: 1

   * - Error
     - Meaning
   * - ``ENODEV``
     - No active controller or subsystem not initialized
   * - ``EBUSY``
     - Operation blocked by active connection, scan, or advertisement
   * - ``EINVAL``
     - Invalid parameter, enum value, or MCS/bandwidth out of range
   * - ``ENOENT``
     - Connection handle not found or SSAP session missing
   * - ``EAGAIN``
     - No data, event, or notification available (non-blocking)
   * - ``ENOMEM``
     - Kernel memory allocation failure
   * - ``EACCES``
     - Operation rejected (e.g., connection response rejection)
   * - ``EIO``
     - DLI controller communication failure

Event delivery via read()
=========================

Asynchronous events are delivered to userspace through the standard
``read()`` system call on ``/dev/sparklink``. Each event is serialized
as a fixed-size ``SleWireEvent`` structure (44 bytes):

.. code-block:: none

    Offset  Size  Field
    ------  ----  -----
    0       1     event_type (SleEventType)
    1       1     payload_len
    2       40    payload (type-specific, padded with zeros)
    42      2     _pad (alignment)

Event types:

.. list-table::
   :widths: 10 25 65
   :header-rows: 1

   * - Code
     - Type
     - Description
   * - 0x01
     - ConnStateChanged
     - Connection state transition (handle, old/new state, peer addr, reason)
   * - 0x02
     - AdvReport
     - Advertising report (address, RSSI, discovery level, name)
   * - 0x03
     - DataReceived
     - Data available on a connection (handle, rx_bytes count)
   * - 0x04
     - SecurityChanged
     - Security state transition (state, method, encrypted flag)
   * - 0x05
     - PowerChanged
     - Power state transition (state, power percentage)
   * - 0x06
     - HardwareError
     - Controller hardware error (error code)

The event queue uses a fixed-size ring buffer (64 slots, O(1) enqueue
and dequeue) with no per-event heap allocation. When full, the oldest
event is dropped (LRU eviction). ``read()`` returns ``EAGAIN`` when no
events are pending. Callers can use ``poll()``/``epoll()`` to wait for
events with ``POLLIN | POLLRDNORM`` readiness indication.

Multiple events are returned in a single ``read()`` call if the
userspace buffer is large enough.

Driver Layer Interface (DLI)
============================

The DLI module (``sle_dli.rs``) defines the ``SleController`` trait
that hardware controller drivers implement, following T/XS 10003-2025.

Opcode encoding
---------------

DLI command opcodes use a 16-bit format:

.. code-block:: none

    Bits [15:10]  OGF (Opcode Group Field, 6 bits)
    Bits [9:0]    OCF (Opcode Command Field, 10 bits)

Command groups:

.. list-table::
   :widths: 8 15 20 57
   :header-rows: 1

   * - OGF
     - Wire prefix
     - Group
     - Key commands
   * - 0x01
     - 0x04xx
     - Basic
     - ReadCmdLen, ReadCtrlBuffer, ReadLocalFeatures, ReadLocalVersion, SetMacAddr, ReadMacAddr, Reset, ...
   * - 0x03
     - 0x0Cxx
     - Broadcast
     - SetBroadcastParam, SetBroadcastData, EnableBroadcast
   * - 0x04
     - 0x10xx
     - Scan
     - SetScanParam, EnableScan
   * - 0x05
     - 0x14xx
     - Connection
     - CreateConnection, CancelConnection, Disconnect, SlbCreateConnection
   * - 0x06
     - 0x18xx
     - Link control
     - SetPhyParam, SetTxPower, SetMaxDataLen
   * - 0x07
     - 0x1Cxx
     - Security
     - RequestPair, SetPairPsk, StartEncrypt, SetRpaEnable
   * - 0x08
     - 0x20xx
     - Measurement
     - ReadLocalMeasCap, MeasAction, EnableMeas
   * - 0x0A
     - 0x28xx
     - Sync link
     - SyncUcastCreate, SyncUcastRemove
   * - 0x3E
     - 0xF8xx
     - Test
     - TestModeEnable, TestRx, TestTx

DLI transport
-------------

The standard defines five DLI packet types on the transport layer:

.. list-table::
   :widths: 10 25 65
   :header-rows: 1

   * - ID
     - Type
     - Description
   * - 0xA1
     - Command
     - Host to controller: opcode (2B) + param_len (1B) + params
   * - 0xA2
     - Event
     - Controller to host: event_code (2B) + param_len (1B) + params
   * - 0xA3
     - Async unicast
     - Asynchronous connection data: link_id (2B) + data_len (2B) + data
   * - 0xA4
     - Sync unicast
     - Synchronous connection data
   * - 0xA5
     - Async multicast
     - Multicast data distribution

For USB controllers, the transport maps to four endpoints:

- EP0 (Control): DLI commands (Class request)
- EP1 (Interrupt IN, max packet size per descriptor): DLI events
- EP2 (Bulk OUT): Async TX data
- EP3 (Bulk IN): Async RX data

USB device class: 0xE0 (Wireless Controller), subclass 0x01,
protocol 0x05.

SleController trait
-------------------

Hardware drivers implement the ``SleController`` trait::

    trait SleController: Send + Sync {
        fn info(&self) -> SleControllerInfo;
        fn open(&self) -> Result;
        fn close(&self);
        fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result;
        fn send_data(&self, handle: u16, data: &[u8]) -> Result;
        fn poll_event(&self) -> Option<SleEvent>;
        fn reset(&self) -> Result;
    }

The built-in ``VirtualController`` implements this trait for loopback
testing without physical hardware.

Ioctl-to-DLI routing
--------------------

The ioctl dispatcher in ``sparklink_core.rs`` routes all hardware-facing
operations through the active ``SleController``. Each ``SparkLinkCtl``
instance holds a controller reference; on ``open()`` the controller is
powered on, and on ``close()`` (PinnedDrop) it is shut down.

The mapping from SCI ioctls to DLI opcodes:

.. list-table::
   :widths: 25 25 50
   :header-rows: 1

   * - SCI ioctl
     - DLI opcode
     - Description
   * - ``START_ADV``
     - ``EnableBroadcast(1)``
     - Enable broadcast with parameters
   * - ``STOP_ADV``
     - ``EnableBroadcast(0)``
     - Disable broadcast
   * - ``START_SCAN``
     - ``EnableScan(1)``
     - Enable discovery scanning
   * - ``STOP_SCAN``
     - ``EnableScan(0)``
     - Disable scanning
   * - ``CONNECT``
     - ``CreateConnection``
     - Initiate connection to peer address
   * - ``DISCONNECT``
     - ``Disconnect``
     - Terminate connection by handle
   * - ``CONN_SEND``
     - ``send_data()``
     - Async unicast data transmission
   * - ``SEC_PAIR``
     - ``RequestPair``
     - Initiate pairing with method
   * - ``SEC_ENCRYPT_ON``
     - ``StartEncrypt``
     - Enable link-layer encryption
   * - ``PHY_SET_MCS``
     - ``SetCodingModulation``
     - Change MCS index
   * - ``PHY_SET_TXPOWER``
     - ``SetPhyParam(0x01)``
     - Set TX power level
   * - ``PHY_SET_BW``
     - ``SetPhyParam(0x02)``
     - Set channel bandwidth

Dual-path architecture: the ioctl handler first updates local host-side
state (AdvScanInner, ConnManager, etc.), then issues the corresponding
DLI command. This ensures the host protocol stack tracks state even if
the controller is virtual or disconnected.

DLI event polling
-----------------

The ``DLI_POLL_EVENT`` ioctl (0x82) dequeues the next pending event from
the controller. Returns ``EAGAIN`` when no events are available.

The ``VirtualController`` generates ``CommandComplete`` events for each
``send_command()`` call, enabling full loopback testing of the event
pipeline without hardware.

.. code-block:: c

    struct sle_dli_event {
        uint8_t  event_type;    /* 1=CmdComplete, 2=CmdStatus, 3=AdvReport, ... */
        uint8_t  status;        /* 0=Success */
        uint16_t handle;
        uint16_t opcode;
        uint16_t data_len;
        uint8_t  data[240];
        uint8_t  addr[6];
        uint8_t  _pad[2];
    };

The ``DLI_RESET`` ioctl (0x83) resets the controller to a known-good
state.

The ``DLI_SEND_CMD`` ioctl (0x84) sends a raw DLI command to the
controller, specified by opcode and parameter bytes.  The ioctl
validates the opcode against the known DLI opcode set before queuing.
On success the matching ``CommandComplete`` event can be retrieved via
``DLI_POLL_EVENT``.

USB transport module
--------------------

The ``sle_usb.rs`` module implements DLI packet framing for
USB-attached controllers and provides ``UsbController`` implementing
the ``SleController`` trait.

USB wire format for DLI command packets (sent on EP0, Class request):

.. code-block:: none

    Byte 0:       0xA1 (Command type)
    Bytes 1-2:    opcode (LE16)
    Byte 3:       parameter length
    Bytes 4..N:   parameters

Async unicast data header (bulk EP2/EP3):

.. code-block:: none

    Byte 0:       0xA3 (AsyncUnicast type)
    Bytes 1-2:    link_id_seg (LE16)
                  [15:4] = link_id (12 bits)
                  [3:2]  = segmentation (0=complete, 1=first, 2=cont, 3=last)
                  [1]    = reserved
                  [0]    = priority
    Bytes 3-4:    data_len (LE16, 9-bit effective)
    Bytes 5..N:   payload

USB transport support is integrated in ``sle_usb.rs`` and registered
alongside the subsystem. Runtime behavior depends on the attached
controller implementation (virtual model or physical device).

USB hardware discovery
----------------------

The ``sle_usb.rs`` module registers a USB driver that automatically
detects SLE controllers when plugged in. The driver matches USB
interfaces with the following descriptor:

.. code-block:: none

    bInterfaceClass    = 0xE0  (Wireless Controller)
    bInterfaceSubClass = 0x01  (RF Controller)
    bInterfaceProtocol = 0x05  (SparkLink DLI)

When a matching interface is found, the driver's ``probe()`` callback
increments an atomic device counter. On ``disconnect()``, the counter
is decremented. Userspace can query the current count via the
``SL_IOCTL_USB_DEV_COUNT`` (0x81) ioctl.

The USB driver is registered at module init time along with the main
SparkLink subsystem. No separate module loading is required.

Example:

.. code-block:: shell

    # Check if any USB SLE controllers are attached
    sparklink_ctl dli usb-count
    # Or via ioctl (returns count as ioctl retval)
    #   ioctl(fd, SL_IOCTL_USB_DEV_COUNT)

UART transport module
---------------------

The ``sle_uart.rs`` module implements H4-like byte-stream framing for
UART-attached SLE controllers, following T/XS 10003-2025.

Wire format:

.. code-block:: none

    Byte 0:       Packet type indicator
                  0xA1 = Command, 0xA2 = Event, 0xA3 = Data
    Bytes 1-2:    Opcode (Command/Event) or Handle (Data), LE16
    Byte 3:       Parameter length (Command/Event, 1 byte)
    Bytes 3-4:    Data length (Data packets, LE16, 2 bytes)
    Bytes N..:    Payload

The ``UartParser`` is a byte-by-byte state machine with three states:

1. **WaitType** -- Waiting for the packet type indicator byte
2. **ReadHeader** -- Collecting the 2-byte opcode/handle and length field(s)
3. **ReadPayload** -- Collecting the payload bytes

On allocation failure during payload collection, the parser resets to
WaitType to maintain frame synchronization.

``UartConfig`` supports baud rate (default 115200) and hardware flow
control (RTS/CTS).

SPI transport module
--------------------

The ``sle_spi.rs`` module implements register-based SPI transport for
SLE controllers, following T/XS 10003-2025.

Register map:

.. list-table::
   :widths: 10 20 70
   :header-rows: 1

   * - Addr
     - Name
     - Description
   * - 0x00
     - STATUS
     - Controller status (read-only)
   * - 0x01
     - CMD
     - Command register (write: send DLI command)
   * - 0x02
     - DATA_TX
     - TX data FIFO (write: queue outbound data)
   * - 0x03
     - DATA_RX
     - RX data FIFO (read: retrieve inbound data)
   * - 0x04
     - CONFIG
     - Configuration register (read/write)
   * - 0x05
     - INT_STATUS
     - Interrupt status (read to check, write to clear)

SPI read operations set bit 7 of the register address (``0x80``).

Interrupt status bits:

- Bit 0: ``RX_READY`` -- Data available in RX FIFO
- Bit 1: ``TX_READY`` -- TX FIFO can accept data
- Bit 2: ``CMD_COMPLETE`` -- Command execution completed
- Bit 3: ``ERROR`` -- Controller error

Data frame format (DATA_TX/DATA_RX):

.. code-block:: none

    Byte 0:       Register address (DATA_TX=0x02 or DATA_RX=0x83)
    Byte 1:       Packet type (0xA1/0xA2/0xA3)
    Bytes 2-3:    Opcode/Handle (LE16)
    Bytes 4-5:    Payload length (LE16)
    Bytes 6..N:   Payload

``SpiConfig`` supports SPI clock frequency (default 8 MHz), SPI mode
(0--3), and chip-select active-low polarity.

PHY layer
=========

The PHY layer module (``sle_phy.rs``) manages physical layer parameters
as specified in T/XS 10002-2025.

MCS table
---------

The SLE air interface defines 13 MCS (Modulation and Coding Scheme)
indices:

.. list-table::
   :widths: 8 15 12 15 50
   :header-rows: 1

   * - MCS
     - Modulation
     - Code rate
     - Bits/symbol
     - Notes
   * - 0
     - BPSK
     - 1/2
     - 1
     - Minimum rate, maximum range
   * - 1
     - BPSK
     - 3/4
     - 1
     -
   * - 2
     - QPSK
     - 1/2
     - 2
     -
   * - 3
     - QPSK
     - 3/4
     - 2
     -
   * - 4
     - 16QAM
     - 1/2
     - 4
     - Default MCS
   * - 5
     - 16QAM
     - 3/4
     - 4
     -
   * - 6
     - 64QAM
     - 1/2
     - 6
     -
   * - 7
     - 64QAM
     - 2/3
     - 6
     -
   * - 8
     - 64QAM
     - 3/4
     - 6
     -
   * - 9
     - 64QAM
     - 5/6
     - 6
     -
   * - 10
     - 256QAM
     - 1/2
     - 8
     -
   * - 11
     - 256QAM
     - 3/4
     - 8
     -
   * - 12
     - 256QAM
     - 5/6
     - 8
     - Maximum rate, requires high SINR

Adaptive MCS selection chooses the highest feasible MCS index for the
reported SINR (in 0.1 dB units) and channel bandwidth, returning the
effective data rate in kbps.

Frequency hopping
-----------------

SLE uses a 79-channel frequency hopping scheme. The hopping algorithm
computes each channel as:

.. code-block:: none

    next_channel = (current_channel + hop_increment) mod num_used_channels
    mapped_channel = channel_map.nth_used(next_channel)

``hop_increment`` is negotiated during connection setup (valid range:
5--16). The channel map is an 80-bit bitmask where each bit represents
one of 79 usable channels. ``nth_used()`` remaps the logical channel
index to the actual RF channel, skipping channels marked as bad.

MIMO modes
----------

The PHY layer supports five antenna configurations:

- **SISO** -- Single input, single output (1 stream)
- **SpatialMux2x2** -- 2x2 spatial multiplexing (2 streams)
- **TxDiversity2x1** -- Transmit diversity, 2 TX / 1 RX
- **RxDiversity1x2** -- Receive diversity, 1 TX / 2 RX
- **Beamforming2x2** -- 2x2 beamforming (1 logical stream)

MIMO mode negotiation uses a min-capability model: both sides report
their maximum supported mode, and the lesser mode is selected.

DLI parameter encoding
----------------------

PHY parameters are encoded in a 7-byte format for DLI ReadPhyParam
and SetPhyParam commands:

.. code-block:: none

    Byte 0:    MCS index (0--12)
    Byte 1:    Bandwidth (1, 2, or 4 MHz)
    Byte 2:    Pilot pattern
    Byte 3:    TX power (signed, dBm)
    Byte 4:    MIMO mode
    Bytes 5-6: Reserved

configfs runtime configuration
==============================

The SparkLink subsystem registers a configfs subsystem at
``/sys/kernel/config/sparklink/`` for runtime parameter tuning.
This requires ``CONFIG_CONFIGFS_FS=y``.

Mounting configfs (if not already mounted):

.. code-block:: shell

    mount -t configfs none /sys/kernel/config

Attributes
----------

.. list-table::
   :widths: 20 10 15 55
   :header-rows: 1

   * - Name
     - Mode
     - Default
     - Description
   * - ``version``
     - RO
     - ``0.3.0``
     - Protocol stack version string
   * - ``max_connections``
     - RW
     - ``8``
     - Maximum simultaneous SLE connections (valid range: 1--8)
   * - ``adv_interval_ms``
     - RW
     - ``100``
     - Default advertising interval in milliseconds (valid range: 20--10240).
       When ``START_ADV`` ioctl receives ``interval_ms=0``, this value is used.
   * - ``scan_window_ms``
     - RW
     - ``200``
     - Default scan window in milliseconds (valid range: 10--10240).
       When ``START_SCAN`` ioctl receives ``window_ms=0``, this value is used.
   * - ``power_mode``
     - RW
     - ``active``
     - Power management mode: ``active``, ``sniff``, or ``idle``
       (also accepts numeric: 0, 1, 2)

Usage:

.. code-block:: shell

    # Read current max connections
    cat /sys/kernel/config/sparklink/max_connections
    # Set advertising interval to 200ms
    echo 200 > /sys/kernel/config/sparklink/adv_interval_ms
    # Set power mode
    echo sniff > /sys/kernel/config/sparklink/power_mode

Implementation notes: configuration values are stored in module-level
``AtomicU8``/``AtomicU16`` variables rather than per-subsystem instance
data, due to a known address calculation issue in the kernel configfs
Rust framework's ``get_group_data()`` for root group subsystems. This
workaround is functionally equivalent and thread-safe.

Generic Netlink interface
=========================

The SparkLink subsystem registers a Generic Netlink family
``"sparklink"`` (version 1) for structured kernel-userspace
communication as an alternative to the ioctl interface.

This is implemented via a C bridge (``sparklink_genl.c``) because
the kernel Rust subsystem does not yet provide genetlink bindings.
The C code handles family registration, command dispatch, and event
multicast, while calling ``#[no_mangle]`` Rust FFI exports for data
queries. Rust calls back into C for event broadcasting and
registration lifecycle management via an RAII ``GenlGuard`` wrapper.

Enable with ``CONFIG_SPARKLINK_GENL=y``.

Protocol definitions are in ``include/uapi/linux/sparklink.h``.

Commands
--------

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Command
     - Description
   * - ``SPARKLINK_CMD_GET_DEV_INFO``
     - Returns the number of currently registered SparkLink devices
       via the ``SPARKLINK_ATTR_DEV_COUNT`` attribute.
   * - ``SPARKLINK_CMD_GET_VERSION``
     - Returns the protocol stack version (``SPARKLINK_ATTR_PROTO_VERSION``)
       and the genetlink interface version (``SPARKLINK_ATTR_GENL_VERSION``).
   * - ``SPARKLINK_CMD_SET_ROLE``
     - Set the local GT node role (T-Node/G-Node) via
       ``SPARKLINK_ATTR_GT_ROLE``.
   * - ``SPARKLINK_CMD_GET_ROLE``
     - Returns the current GT role via ``SPARKLINK_ATTR_GT_ROLE``.
   * - ``SPARKLINK_CMD_GET_CONN_INFO``
     - Returns connection information for the handle specified in
       ``SPARKLINK_ATTR_HANDLE``, including state, role, bandwidth,
       MCS index, and TX/RX byte counters.
   * - ``SPARKLINK_CMD_GET_PM_INFO``
     - Returns power management status via ``SPARKLINK_ATTR_PM_STATE``,
       ``SPARKLINK_ATTR_FORCE_ACTIVE``, and ``SPARKLINK_ATTR_POWER_PCT``.
   * - ``SPARKLINK_CMD_GET_DLI_INFO``
     - Returns DLI controller information (bus type, firmware version,
       feature bitmask, max connections, max MTU/MPS, transport modes,
       measurement and security capabilities).
   * - ``SPARKLINK_CMD_START_ADV``
     - Start advertising with interval and discovery level from
       ``SPARKLINK_ATTR_INTERVAL_MS`` and ``SPARKLINK_ATTR_DISCOVERY_LEVEL``.
   * - ``SPARKLINK_CMD_STOP_ADV``
     - Stop advertising.
   * - ``SPARKLINK_CMD_START_SCAN``
     - Start scanning with parameters from ``SPARKLINK_ATTR_WINDOW_MS``
       and ``SPARKLINK_ATTR_INTERVAL_MS``.
   * - ``SPARKLINK_CMD_STOP_SCAN``
     - Stop scanning.
   * - ``SPARKLINK_CMD_EVENT``
     - Multicast event notification sent to the ``"events"`` group
       carrying ``SPARKLINK_ATTR_EVENT_TYPE``, optional
       ``SPARKLINK_ATTR_HANDLE``, ``SPARKLINK_ATTR_ADDR``, and
       ``SPARKLINK_ATTR_EVENT_PAYLOAD``.

Multicast groups
----------------

The ``"events"`` multicast group delivers async event notifications
to subscribed userspace listeners (connection state changes,
advertising reports, security events, etc.).

Attributes
----------

The full attribute enumeration is defined in
``include/uapi/linux/sparklink.h`` (``enum SPARKLINK_ATTR_*``).
Key attribute groups include device info, addressing, connection
parameters, advertising/scanning, security, SSAP service layer,
power management, event delivery, DLI controller capabilities,
and data channel configuration.

Rust integration
----------------

The ``sle_netlink.rs`` module provides complementary protocol types:

- Command/attribute enumerations (``NlCmd``, ``NlAttr``)
- Attribute TLV builder (``NlAttrBuilder``) for constructing messages
- Attribute TLV parser (``parse_attrs()``) with type-safe extractors

debugfs interface
=================

After loading the SparkLink module, the following debugfs nodes are
available under ``/sys/kernel/debug/sparklink/``:

.. code-block:: none

    /sys/kernel/debug/sparklink/
    ├── version          # Protocol stack version
    ├── build_info       # Build info (standards, language)
    ├── subsystems       # Enabled subsystem list
    ├── adv_count        # Advertising operation count
    ├── scan_count       # Scanning operation count
    ├── conn_count       # Connection operation count
    ├── ioctl_count      # Total ioctl call count
    └── dli_controller   # DLI controller info (bus, firmware, features)

Userspace tools
===============

sparklink_test
--------------

Integration test program at
``tools/testing/selftests/sparklink/sparklink_test.c``.
Covers all subsystem ioctl interfaces with a continuously expanded
selftest matrix, including:

- Device management: count, info, register
- Advertising: start/stop, duplicate detection
- Scanning: start/stop, result count
- Mutual exclusion: advertising blocks scanning
- Role management: SET_ROLE/GET_ROLE, role-gate ADV/SCAN
- Loopback: inject advertising PDU, filter by discovery level
- Multi-connection: connect to multiple peers, CONN_COUNT, CONN_LIST
- Connection rejection: handle-based access response
- Data loopback: send/inject/recv, statistics, disconnect cleanup
- Event notification: read events after connect/inject
- Event statistics: EVENT_STATS ioctl verification
- DLI controller info: DLI_INFO ioctl verification
- DLI event polling: event drain, CommandComplete verification
- poll/epoll: poll readiness with event trigger and drain
- Ring buffer stress: overflow handling with 80 events in 64-slot buffer
- SM3 hash: test vector verification
- Security: PSK pairing, encryption, SM4 roundtrip
- SSAP: service registration, property read/write, notifications
- SSAP dynamic registration: ADD_SVC (16/128-bit UUID), ADD_PROP, REMOVE_SVC
- Power management: state transitions, intervals, force-active
- Configfs: mount, default readback, write/readback, boundary validation
- Configfs-ioctl integration: interval_ms=0 / window_ms=0 fallback
- Performance benchmarks: ioctl throughput (10k iterations), ADV cycle latency
- USB hardware discovery: device count query
- Generic Netlink: family lookup, GET_DEV_INFO, GET_VERSION
- PHY layer: MCS set/get, bandwidth, TX power, adaptive MCS selection,
  frequency hopping, invalid parameter rejection
- Error handling: unknown ioctl

Build and run:

.. code-block:: shell

    gcc -Wall -Wextra -O2 -o sparklink_test \
        tools/testing/selftests/sparklink/sparklink_test.c
    sudo ./sparklink_test

run_qemu_test.sh
----------------

QEMU integration test runner at
``tools/testing/selftests/sparklink/run_qemu_test.sh``.
Boots the kernel in a QEMU VM with a minimal initramfs, runs the full
sparklink_test suite against the real kernel module, and reports results.

Prerequisites:

- ``qemu-system-x86_64``
- ``busybox`` (statically linked)
- Built kernel at ``build/`` (or set ``KBUILD``)

.. code-block:: shell

    cd tools/testing/selftests/sparklink
    ./run_qemu_test.sh              # Normal run
    ./run_qemu_test.sh --verbose    # Show full console output

The script:

1. Builds ``sparklink_test`` as a static binary
2. Creates a minimal initramfs with busybox and the test binary
3. Boots the kernel in QEMU with KVM (if available)
4. Waits for ``/dev/sparklink`` and runs the full test suite
5. Parses console output for OK/FAIL/WARN counts and overall result

sparklink_ctl
-------------

CLI control tool at ``tools/testing/selftests/sparklink/sparklink_ctl.c``.

.. code-block:: shell

    sparklink_ctl <command> [args...]

    info                              Show subsystem information

    adv start                         Start advertising
    adv stop                          Stop advertising

    scan start                        Start scanning
    scan stop                         Stop scanning
    scan results                      Show scan result count

    conn <addr_hex>                   Connect to peer
    conn info [handle]                Show connection info
    conn disconnect <handle>          Disconnect by handle
    conn count                        Show active connection count
    conn list                         List active connection handles
    conn send <handle> <data>         Send data on connection

    sec psk <key_hex>                 Set pre-shared key
    sec pair <method>                 Start pairing (1=JustWorks, 2=PSK)
    sec info                          Show security info
    sec encrypt                       Enable encryption

    ssap register                     Register device info service
    ssap info                         Show SSAP summary
    ssap read <handle>                Read property
    ssap write <handle> <data>        Write property

    pm info                           Show power management info
    pm suspend                        Suspend
    pm resume                         Resume

    event count                       Show pending event count
    event read                        Read and display pending events
    event wait [ms]                   Wait for events with poll (default 5000ms)

    dli info                          Show DLI controller information
    dli stats                         Show event queue statistics

    phy info                          Show PHY configuration (MCS, BW, power)
    phy mcs <index>                   Set MCS index (0-12)
    phy bw <1|2|4>                    Set channel bandwidth (MHz)
    phy power <dBm>                   Set TX power (-20 to +10)
    phy select <sinr_x10> <bw>        Adaptive MCS selection
    phy hop                           Advance frequency hopping

Build:

.. code-block:: shell

    gcc -Wall -Wextra -O2 -o sparklink_ctl \
        tools/testing/selftests/sparklink/sparklink_ctl.c

Protocol overview
=================

SLE air interface frame format
------------------------------

Per T/XS 10002-2025 chapter 6, the SLE over-the-air PDU is:

.. code-block:: none

    +----------+----------------+-----------+---------+---------+
    | Preamble | Access Address | PDU Header| Payload | CRC-12  |
    | (1-2 B)  |    (4 B)       |  (2 B)    | (var)   | (2 B)   |
    +----------+----------------+-----------+---------+---------+

    PDU Header fields:
    +---------+---------+-------+----------+---------+
    | PDU Type| RFU     | TxAdd | Payload  | SN/NESN |
    | (4 bit) | (1 bit) | (1b)  | Len (8b) | (2 bit) |
    +---------+---------+-------+----------+---------+

PDU types:

- ``AdvInd`` (0x0): Connectable undirected advertising
- ``AdvDirectInd`` (0x1): Connectable directed advertising
- ``AdvNonconnInd`` (0x2): Non-connectable undirected advertising
- ``ScanReq`` (0x3): Scan request
- ``ScanRsp`` (0x4): Scan response
- ``ConnReq`` (0x5): Connection request
- ``Data`` (0x6): Data PDU
- ``Ack`` (0x7): Acknowledgment PDU

SSAP service model
------------------

SSAP (SLE Service Access Profile) follows T/XS 20001-2025 section 7.4,
using a hierarchical model similar to Bluetooth GATT:

.. code-block:: none

    Service (UUID, handle range)
    ├── Property (similar to Characteristic)
    │   ├── handle
    │   ├── permissions (read/write/notify)
    │   └── value (max 244 bytes)
    ├── Method (invocable operation)
    │   ├── handle
    │   └── permissions
    └── Event (notification/indication)
        ├── handle
        └── permissions

UUIDs support both 16-bit short and 128-bit long formats. The
OpIndicator bitmask encodes read, write, and notify permissions.

Security model
--------------

The security layer uses Chinese national cryptographic algorithms:

1. **Pairing** -- JustWorks (no user interaction) or PSK (pre-shared key)
2. **Key derivation** -- HMAC-SM3 from pairing result and nonces
3. **Data encryption** -- SM4-CTR mode, 128-bit key, 96-bit IV
4. **Integrity** -- Link key fingerprint via SM3 hash

Power management state machine
------------------------------

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

Multi-connection model
----------------------

The connection manager supports up to 8 concurrent connections.
Each connection has:

- A unique 16-bit handle (assigned sequentially starting from 1)
- Independent state machine per connection
- Per-connection TX/RX queues (max 64 entries each)
- Per-connection sequence tracking (1-bit ARQ for async links)
- Per-connection statistics (tx_bytes, rx_bytes)

Duplicate peer address detection prevents connecting to the same
device twice. The handle ``0`` serves as a legacy shortcut that
resolves to the first active connection.

Limitations and future work
===========================

Current limitations:

1. **No physical hardware validation** -- USB, UART, SPI, and serdev
   transport frameworks are complete with full framing and protocol
   support, and have been integration-tested with a custom QEMU
   virtual SLE controller (``usb-sle-dli``). Actual silicon validation
   awaits availability of conformant SLE radio hardware.

2. **C bridge for genetlink** -- The Generic Netlink family is
   registered via a C bridge (``sparklink_genl.c``) because upstream
   Rust genetlink bindings are not yet available. When they mature,
   the bridge can be replaced with pure Rust registration.

3. **configfs framework workaround** -- The configfs Rust framework
   has a ``container_of`` address calculation issue for root group
   subsystems. Configuration parameters use module-level atomics
   instead of per-instance data as a workaround.

Recent additions:

- Extended advertising (0x14--0x1B, 0x22) with multi-set management
  and duration/max-event control
- Adaptive frequency hopping (AFH, 0x3A--0x3F) with RSSI-based channel
  classification and retransmission tracking
- Per-connection MTU/MPS negotiation (0x39)
- Numeric comparison, OOB, and PIN/password pairing methods
  (0x49--0x4F), supplementing the existing JustWorks and PSK methods
- RAL/RPA management (0xB0--0xB7) for resolvable private address
  generation and resolution per T/XS 10003-2025
- Sync link management (0x66--0x6E) for isochronous CIG/BIG data paths
- PHY SINR threshold management (0x96--0x97)

Planned work:

- Physical SLE radio hardware bring-up and conformance testing
- UART/SPI/serdev bus driver binding for embedded SLE radio modules
- Pure Rust genetlink registration when upstream Rust bindings mature

Architecture design review
==========================

Module dependency graph
-----------------------

.. code-block:: none

    sparklink_core.rs (SCI entry, ioctl dispatch, MiscDevice)
      ├── sle_dli.rs        SleController trait, opcodes, ControllerBackend
      │     ├── sle_uart.rs     UartController (H4 framing)
      │     ├── sle_spi.rs      SpiController (register I/O)
      │     ├── sle_usb.rs      UsbController (USB bulk/interrupt)
      │     │     └── sle_usb_ffi.c   USB driver C FFI bridge
      │     └── sle_serdev.rs   SerdevController (serial device)
      │           └── sle_serdev_ffi.c  serdev C FFI bridge
      ├── sle_adv.rs        AdvScanInner, PDU advertising/scanning
      ├── sle_conn.rs       ConnManager, DataRingBuffer, ARQ
      ├── sle_crypto.rs     Rust wrapper over kernel crypto API
      │     └── sle_crypto_ffi.c   SM3/SM4/HMAC C FFI bridge
      ├── sle_security.rs   SecurityInner, pairing state machine
      ├── sle_ssap.rs       Service framework (property/method/event)
      ├── sle_power.rs      PowerInner, PM state machine
      ├── sle_event.rs      EventQueue, typed events for userspace
      ├── sle_phy.rs        MCS lookup, frequency hopping, MIMO
      ├── sle_pdu.rs        PDU codec, CRC-12, advertising builder
      ├── sle_netlink.rs    TLV encoding for Generic Netlink
      ├── sle_configfs.rs   Runtime parameters via /sys/kernel/config/
      ├── sle_mgmt.rs       Management plane, DLI command queue
      ├── sle_transport.rs  Transport abstraction layer
      ├── sle_fw.rs         Firmware version parsing
      ├── sle_uapi.rs       UAPI ioctl consts + repr(C) data types
      └── sparklink_genl.c  C genetlink family (FFI bridge)

Design decisions
----------------

**Static dispatch via enum instead of trait objects.**
``ControllerBackend`` enumerates all transport backends (Virtual, UART,
SPI) and dispatches ``SleController`` methods through ``match``.  This
avoids heap-allocated ``dyn SleController`` and keeps the code compatible
with kernel contexts where dynamic allocation is expensive or forbidden.
The trade-off is that every new transport requires adding a variant to
this enum, but transport types change infrequently.

**Global shared subsystem with ``global_lock!``.**
All mutable protocol state (``ControllerBackend``, ``ConnManager``,
``AdvScanInner``, ``SecurityInner``, ``SsapInner``, ``PowerInner``,
``PhyConfig``) is held in a single ``SubsystemShared`` struct behind a
global ``Mutex`` created via the kernel's ``global_lock!`` macro.
The first ``open()`` lazily initialises this shared state; the last
``close()`` tears it down.  A global ``Atomic<u32>`` tracks open fd
count.  Per-fd state is limited to ``EventQueue`` and ``event_poll``.
This avoids isolated per-fd protocol stacks and ensures all fds share
the same radio controller, connection table, and security context.
The per-backend ``Cell``/``RefCell`` fields (event ring buffer, opened
flag) are sound because the enclosing global Mutex serialises access.

**Three-way control plane.**
Ioctl is the primary interface, mapping 1:1 to protocol operations.
Generic Netlink provides attribute-based access for structured tools and
multicast event delivery.  ConfigFS allows persistent runtime tuning
without opening the device node.  All three are optional in different
build configurations.

**Zero-copy connection buffer.**
``DataRingBuffer`` in ``sle_conn.rs`` pre-allocates a single ``KVec``
backing store with fixed slot metadata (64 slots, 255 bytes per message
max).  This avoids per-message heap allocation under high data
throughput and prevents kernel memory fragmentation.

**Kernel crypto API delegation.**
SM3 and SM4 operations are delegated to kernel crypto API providers
(``CRYPTO_SM3_GENERIC``, ``CRYPTO_SM4_GENERIC``, ``CRYPTO_HMAC``,
``CRYPTO_ECB``, ``CRYPTO_CTR``) through a C FFI bridge
(``sle_crypto_ffi.c``).  ``sle_crypto.rs`` is a thin safe Rust wrapper
that provides the typed interface (``Sm3::hash``, ``Sm4Ecb::encrypt``,
``HmacSm3::mac``, etc.) without reimplementing cryptographic primitives.
This keeps the module aligned with the kernel's audited crypto
infrastructure and enables hardware acceleration on platforms that
provide SM3/SM4 accelerators.  Test vectors validate conformance to
GB/T 32905-2016 and GB/T 32907-2016.

**Bounded resource limits.**
Connections are capped at ``MAX_CONNECTIONS`` (default 8, overridable
via configfs ``max_connections``).  Event queue depth is finite with
oldest-event eviction.  Scan results are capped at 64 with FIFO
replacement.  No data structure in the module grows without bound.

Identified risks and mitigations
--------------------------------

1. **configfs static atomics.**  Because the kernel ``configfs.rs``
   binding does not yet support ``container_of!()`` for data retrieval,
   configfs attributes use global ``AtomicU8``/``AtomicU32`` statics.
   When multiple SparkLink instances exist, they would share the same
   configfs values.  Mitigation: awaiting upstream configfs API
   improvement; current usage is single-instance.

2. **Event ring buffer size.**  The 32-slot ring in each controller
   backend can overflow under burst command traffic, silently dropping
   events.  For the virtual loopback test path this is acceptable.
   Real hardware drivers should implement flow control or larger
   buffers.

3. **No runtime transport hot-swap.**  The controller backend is
   selected at ``open()`` based on the configfs ``controller_type``
   value.  Changing the type while a file descriptor is open takes
   effect only on the next ``open()``.  This is intentional to avoid
   mid-session transport disruption.

4. **SSAP service handle namespace.**  Dynamically registered services
   share the same handle namespace with the built-in Device Information
   Service.  When services are removed and re-added, handle recycling
   may confuse clients that cache stale handle values.  Mitigation:
   clients should re-discover services after receiving a service-changed
   event.

Code statistics
---------------

.. code-block:: none

    Component                  Lines
    ─────────────────────────  ─────
    sparklink_core.rs           ~3517
    sle_uapi.rs                 ~1890
    sle_conn.rs                 ~1784
    sle_ssap.rs                 ~1494
    sle_dli.rs                  ~1380
    sle_usb.rs                  ~1186
    sle_usb_ffi.c               ~1011
    sle_security.rs              ~908
    sle_event.rs                 ~750
    sle_adv.rs                   ~729
    sle_phy.rs                   ~684
    sparklink_genl.c             ~655
    sle_serdev_ffi.c             ~597
    sle_pdu.rs                   ~559
    sle_serdev.rs                ~544
    sle_uart.rs                  ~527
    sle_spi.rs                   ~472
    sle_crypto_ffi.c             ~419
    sle_netlink.rs               ~364
    sle_transport.rs             ~350
    sle_mgmt.rs                  ~333
    sle_dev.rs                   ~326
    sle_power.rs                 ~314
    sle_crypto.rs                ~267
    sle_configfs.rs              ~227
    sle_fw.rs                    ~173
    ─────────────────────────  ─────
    Kernel total               ~21460
    Test + tools               ~10360
    UAPI headers                ~1019
    Documentation               ~2089
    Grand total                ~34930

References
==========

- T/XS 10002-2025: SparkLink SLE air interface specification
- T/XS 20001-2025: SparkLink device discovery and service management
- T/XS 10003-2025: SparkLink driver layer interface (DLI)
- GB/T 32905-2016: SM3 cryptographic hash algorithm
- GB/T 32907-2016: SM4 block cipher algorithm
- ``Documentation/rust/``: Linux kernel Rust support
