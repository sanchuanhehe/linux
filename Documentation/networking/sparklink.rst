.. SPDX-License-Identifier: GPL-2.0

========================
Linux SparkLink subsystem
========================

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

    +------------------------------------------------------+
    |                    USER SPACE                         |
    |   sparklink_ctl / sparklink_test / custom app         |
    +------------------------------------------------------+
            |  ioctl + read()         |  Generic Netlink
            v                         v
    +------------------------------------------------------+
    |              sparklink_core (SCI)                     |
    |  misc device - ioctl dispatch - event queue - debugfs |
    |                    sparklink_genl.c (genetlink family) |
    +--+------+------+------+------+------+------+------+--+
       |      |      |      |      |      |      |      |
       v      v      v      v      v      v      v      v
    sle_pdu sle_adv sle_conn sle_crypto sle_sec sle_ssap sle_power sle_event
    codec   adv/scan  multi    SM3/SM4  pairing   SSAP     PM     event queue
                     conn
    +------------------------------------------------------+
    |                  sle_dli (DLI)                        |
    |  SleController trait - opcode/event model (10003)     |
    +------+-----------------------+-----------------------+
           |                       |
    VirtualController        USB / UART / SPI driver
       (loopback)              (future hardware)

Module descriptions:

**sparklink_core** (``net/sparklink/sparklink_core.rs``)
  SCI (SparkLink Controller Interface) core. Registers the ``/dev/sparklink``
  misc device, dispatches all ioctl commands, delivers events through
  ``read()``, and maintains debugfs information nodes.

**sle_pdu** (``net/sparklink/sle_pdu.rs``)
  Frame codec implementing the PDU format defined in T/XS 10002-2025
  chapter 6, including Preamble, Access Address, PDU Header, Payload,
  and CRC-24.

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
  Pure Rust implementation of SM3 hash (GB/T 32905-2016), SM4 block
  cipher (GB/T 32907-2016), HMAC-SM3, and SM4-CTR mode for key
  derivation and data encryption.

**sle_security** (``net/sparklink/sle_security.rs``)
  Security state machine supporting JustWorks and PSK pairing methods.
  Manages security states (Unpaired -> Pairing -> Paired -> Encrypted)
  and provides SM4-CTR data encryption.

**sle_ssap** (``net/sparklink/sle_ssap.rs``)
  SSAP (SLE Service Access Profile) layer, functionally equivalent to
  Bluetooth GATT. Implements service registration, property read/write,
  notifications, and service discovery per T/XS 20001-2025 section 7.4.

**sle_power** (``net/sparklink/sle_power.rs``)
  Power management module with automatic state transitions
  (Active -> Sniff -> Idle) based on idle count, plus suspend/resume
  and force-active mode.

**sle_event** (``net/sparklink/sle_event.rs``)
  Asynchronous event notification subsystem. Delivers typed events
  (connection state, advertising reports, data received, security
  changes, power changes, hardware errors) to userspace via ``read()``
  on the device file descriptor.

**sle_dli** (``net/sparklink/sle_dli.rs``)
  Driver Layer Interface following T/XS 10003-2025. Defines the
  ``SleController`` trait that hardware drivers implement, with
  standard DLI opcode encoding (OGF/OCF), event codes, and feature
  bits from the 80-bit feature set.

**sparklink_virtual** (``drivers/sparklink/sparklink_virtual.rs``)
  Virtual controller driver for testing without physical hardware.

Source code layout
==================

.. code-block:: none

    net/sparklink/
    ├── Kconfig                  # Subsystem Kconfig
    ├── Makefile                 # Build rules
    ├── sparklink_core.rs        # Core module
    ├── sparklink_genl.c         # Generic Netlink C bridge
    ├── sle_pdu.rs               # Frame codec
    ├── sle_adv.rs               # Advertising/scanning
    ├── sle_conn.rs              # Multi-connection manager
    ├── sle_crypto.rs            # SM3/SM4 crypto
    ├── sle_security.rs          # Security/pairing
    ├── sle_ssap.rs              # Service access protocol
    ├── sle_power.rs             # Power management
    ├── sle_event.rs             # Event notification
    ├── sle_netlink.rs           # Netlink protocol types
    └── sle_dli.rs               # Driver layer interface

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
    CONFIG_SPARKLINK_GENL=y        # Generic Netlink control plane
    CONFIG_SPARKLINK_DRIVERS=y     # SparkLink driver framework
    CONFIG_SPARKLINK_VIRTUAL=y     # Virtual controller (testing)

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

Device management (0x01 -- 0x04)
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

Security (0x40 -- 0x46)
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
     - Write/Read (SleHashTest)
     - Compute SM3 hash of input data
   * - 0x45
     - ``SEC_SM4_ENC_TEST``
     - Write/Read (SleConnData)
     - Encrypt data in-place with SM4-CTR
   * - 0x46
     - ``SEC_SM4_DEC_TEST``
     - Write/Read (SleConnData)
     - Decrypt data in-place with SM4-CTR
   * - 0x47
     - ``SEC_SM4_BLOCK_TEST``
     - Write/Read (SleSm4BlockTest)
     - Single-block SM4 encrypt/decrypt test (GB/T 32907-2016 A.1)
   * - 0x48
     - ``SEC_HMAC_TEST``
     - Write/Read (SleHmacTest)
     - HMAC-SM3 computation and verification

SSAP service layer (0x50 -- 0x56)
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

DLI controller info (0x80)
--------------------------

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

``SleDliInfo`` structure:

.. code-block:: c

    struct sle_dli_info {
        uint8_t  bus;               /* 0=Virtual, 1=UART, 2=USB, 3=SDIO */
        uint8_t  _pad[3];
        uint32_t firmware_version;  /* major.minor.patch packed */
        uint64_t features;          /* feature bitmask (TXS-10003-2025) */
        uint8_t  max_connections;
        uint8_t  max_adv_sets;
        uint8_t  name[32];          /* null-terminated controller name */
        uint8_t  _reserved[14];
    };

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
     - Reset, ReadLocalVersion, ReadLocalFeatures, SetMacAddr
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
     - CreateConnection, Disconnect, SetConnParam, ReadRssi
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
- EP1 (Interrupt IN, 16B max): DLI events
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

USB transport module
--------------------

The ``sle_usb.rs`` module implements DLI packet framing for
USB-attached controllers and provides ``UsbController`` implementing
the ``SleController`` trait.

USB wire format for DLI command packets (sent on bulk OUT EP3):

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

Currently the USB controller returns ``ENODEV`` on ``open()`` as no
hardware drivers are registered. A separate ``sparklink_usb`` kernel
module implementing ``usb::Driver`` will register the USB transport
when hardware is available.

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
Covers all subsystem ioctl interfaces with 21 test cases:

- Device management: count, info, register
- Advertising: start/stop, duplicate detection
- Scanning: start/stop, result count
- Mutual exclusion: advertising blocks scanning
- Loopback: inject advertising PDU, filter by discovery level
- Multi-connection: connect to multiple peers, CONN_COUNT, CONN_LIST
- Connection rejection: handle-based access response
- Data loopback: send/inject/recv, statistics, disconnect cleanup
- Event notification: read events after connect/inject
- Event statistics: EVENT_STATS ioctl verification
- DLI controller info: DLI_INFO ioctl verification
- poll/epoll: poll readiness with event trigger and drain
- Ring buffer stress: overflow handling with 80 events in 64-slot buffer
- SM3 hash: test vector verification
- Security: PSK pairing, encryption, SM4 roundtrip
- SSAP: service registration, property read/write, notifications
- Power management: state transitions, intervals, force-active
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
4. Waits for ``/dev/sparklink`` and runs all 21 test cases
5. Parses console output for OK/FAIL/WARN counts and overall result

sparklink_ctl
--------------

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
    | Preamble | Access Address | PDU Header| Payload | CRC-24  |
    | (1-2 B)  |    (4 B)       |  (2 B)    | (var)   | (3 B)   |
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
-------------------------------

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
============================

Current limitations:

1. **No physical hardware driver** -- Only the virtual loopback
   controller is available; all testing is done in loopback mode.

2. **C bridge for genetlink** -- The Generic Netlink family is
   registered via a C bridge (``sparklink_genl.c``) because upstream
   Rust genetlink bindings are not yet available. When they mature,
   the bridge can be replaced with pure Rust registration.

3. **Pure Rust crypto** -- SM3/SM4 are implemented in pure Rust
   without kernel crypto API hardware acceleration.

Planned work:

- USB DLI driver for physical SLE radio controllers
- Pure Rust genetlink registration when upstream Rust bindings mature
- Kernel crypto API integration for hardware-accelerated SM3/SM4
- sysfs/configfs runtime configuration interface

References
==========

- T/XS 10002-2025: SparkLink SLE air interface specification
- T/XS 20001-2025: SparkLink device discovery and service management
- T/XS 10003-2025: SparkLink driver layer interface (DLI)
- GB/T 32905-2016: SM3 cryptographic hash algorithm
- GB/T 32907-2016: SM4 block cipher algorithm
- ``Documentation/rust/``: Linux kernel Rust support
