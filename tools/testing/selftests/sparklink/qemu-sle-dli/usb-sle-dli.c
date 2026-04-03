// SPDX-License-Identifier: GPL-2.0
/*
 * QEMU USB SparkLink SLE DLI Controller Device
 *
 * Emulates a minimal SparkLink SLE DLI USB controller per T/XS 10003-2025
 * for Linux kernel driver testing. Not a full protocol emulator; provides
 * deterministic command/event handling for the guest USB backend in
 * net/sparklink/sle_usb.rs and net/sparklink/sle_usb_ffi.c.
 *
 * USB descriptor layout (T/XS 10003-2025 Table 3):
 *   EP0       Control         DLI instructions (standards path)
 *   0x91      Interrupt IN    DLI events (max 16 bytes)
 *   0x92      Bulk IN         Async data + compat command responses
 *   0x12      Bulk OUT        Async data + compat commands
 *
 * USB class codes (T/XS 10003-2025 Table 6):
 *   bInterfaceClass    = 0xE0  Wireless Controller
 *   bInterfaceSubClass = 0x01  RF Controller
 *   bInterfaceProtocol = 0x05  SparkLink DLI
 *
 * Supported command set (v1):
 *   0x0401  ReadCmdLen
 *   0x0402  ReadCtrlBuffer
 *   0x0403  ReadLocalFeatures
 *   0x0404  ReadLocalVersion
 *   0x0406  ReadMacAddr
 *   0x0408  Reset
 *   0x0C05  EnableBroadcast
 *   0x1002  EnableScan
 *   0x1401  CreateConnection
 *   0x1403  Disconnect
 *   0xF810  FwDownloadStart
 *   0xF811  FwDownloadDone
 */

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "hw/qdev-properties.h"
#include "hw/usb.h"
#include "hw/usb/desc.h"
#include "qapi/error.h"
#include "qom/object.h"

/* --------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------- */

#define TYPE_USB_SLE_DLI  "usb-sle-dli"

/* DLI packet type indicators (T/XS 10003-2025 Table 1) */
#define DLI_PKT_COMMAND     0xA1
#define DLI_PKT_EVENT       0xA2
#define DLI_PKT_ASYNC_DATA  0xA3
#define DLI_PKT_SYNC_DATA   0xA4
#define DLI_PKT_MCAST_DATA  0xA5

/* DLI command opcodes */
#define DLI_OP_READ_CMD_LEN       0x0401
#define DLI_OP_READ_CTRL_BUFFER   0x0402
#define DLI_OP_READ_FEATURES      0x0403
#define DLI_OP_READ_VERSION       0x0404
#define DLI_OP_SET_MAC            0x0405
#define DLI_OP_READ_MAC           0x0406
#define DLI_OP_RESET              0x0408
#define DLI_OP_ENABLE_BROADCAST   0x0C05
#define DLI_OP_ENABLE_SCAN        0x1002
#define DLI_OP_CREATE_CONN        0x1401
#define DLI_OP_DISCONNECT         0x1403
#define DLI_OP_FW_DL_START        0xF810
#define DLI_OP_FW_DL_DONE         0xF811

/* Broadcast configuration opcodes (§8.2) */
#define DLI_OP_SET_BCAST_PARAM    0x0C02
#define DLI_OP_SET_BCAST_DATA     0x0C03
#define DLI_OP_SET_BCAST_SCAN_RSP 0x0C04
#define DLI_OP_READ_MAX_BCAST_LEN 0x0C06
#define DLI_OP_READ_BCAST_SET_SZ  0x0C07
#define DLI_OP_DELETE_BCAST_SET   0x0C08

/* Scan opcodes (§8.3) */
#define DLI_OP_SET_SCAN_PARAM     0x1001
#define DLI_OP_SET_SCAN_REQ_DATA  0x1003

/* Connection opcodes (§8.4) */
#define DLI_OP_CANCEL_CONN        0x1402

/* Link control opcodes (§8.5) */
#define DLI_OP_READ_PEER_FEATURES 0x1801
#define DLI_OP_READ_PEER_VERSION  0x1802
#define DLI_OP_SET_DATA_LENGTH    0x1804
#define DLI_OP_READ_PHY_PARAM     0x1805
#define DLI_OP_SET_PHY_PARAM      0x1806
#define DLI_OP_CONN_PARAM_UPDATE  0x1807
#define DLI_OP_READ_RSSI          0x180C
#define DLI_OP_SET_CODING_MOD     0x180A
#define DLI_OP_CONN_PARAM_REQ_RPL 0x1808
#define DLI_OP_READ_AVAIL_CHAN    0x1809
#define DLI_OP_SET_TX_POWER       0x180D
#define DLI_OP_READ_TX_POWER      0x180E
#define DLI_OP_READ_PEER_TX_POWER 0x180F
#define DLI_OP_CONFIG_POWER_RPT   0x1810
#define DLI_OP_SET_CTRL_SIGNAL    0x1812
#define DLI_OP_ENABLE_RSSI_CTRL   0x1813

/* Security opcodes (§8.6) */
#define DLI_OP_HASH_COMPUTE       0x1C01
#define DLI_OP_GEN_SECURE_RANDOM  0x1C02
#define DLI_OP_START_ENCRYPT      0x1C03
#define DLI_OP_REQUEST_PAIR       0x1C04
#define DLI_OP_REPLY_ENC_PARAM    0x1C05
#define DLI_OP_REJECT_ENC_PARAM   0x1C06
#define DLI_OP_READ_ENC_ALGO      0x1C07
#define DLI_OP_START_PAIRING      0x1C08
#define DLI_OP_PAIR_INFO_EXCH_RPL 0x1C09
#define DLI_OP_PAIR_OPT_CONFIRM  0x1C0A
#define DLI_OP_PAIR_OPT_ACCEPT   0x1C0B
#define DLI_OP_PAIR_EXT_DATA     0x1C0C
#define DLI_OP_PAIR_PASSKEY_KEY  0x1C0D
#define DLI_OP_PAIR_RANDOM       0x1C0E
#define DLI_OP_PAIR_CONFIRM      0x1C0F
#define DLI_OP_DHKEY_VERIFY      0x1C10
#define DLI_OP_PAIR_FAIL         0x1C11
#define DLI_OP_RAL_ADD           0x1C12
#define DLI_OP_RAL_REMOVE        0x1C13
#define DLI_OP_RAL_CLEAR         0x1C14
#define DLI_OP_RAL_READ_SIZE     0x1C15
#define DLI_OP_RAL_READ_PEER_RPA 0x1C16
#define DLI_OP_RAL_READ_LOCAL_RPA 0x1C17
#define DLI_OP_RPA_SET_ENABLE    0x1C18
#define DLI_OP_RPA_SET_TIMEOUT   0x1C19
#define DLI_OP_SLB_CFG_AUTH_PSK  0x1C1A
#define DLI_OP_SLB_DEL_AUTH_PSK  0x1C1B
#define DLI_OP_SLB_CFG_AUTH_PWD  0x1C1C
#define DLI_OP_SLB_DEL_AUTH_PWD  0x1C1D
#define DLI_OP_SLB_CFG_CIPHER   0x1C1E
#define DLI_OP_SLB_READ_CIPHER  0x1C1F

/* DLI event codes */
#define DLI_EVT_CMD_STATUS        0x0001
#define DLI_EVT_CMD_COMPLETE      0x0002
#define DLI_EVT_DISCONNECTED      0x0005
#define DLI_EVT_HW_ERROR          0x000A
#define DLI_EVT_ENC_CHANGED       0x0011
#define DLI_EVT_CONN_ESTABLISHED  0x0015
#define DLI_EVT_BROADCAST_REPORT  0x001A
#define DLI_EVT_PAIR_REQUEST      0x001D

/* Link control events (§9.1.15–§9.1.18) */
#define DLI_EVT_DATA_LEN_CHANGE   0x0003
#define DLI_EVT_BROADCAST_END     0x0004
#define DLI_EVT_PEER_CONN_PARAM   0x0007
#define DLI_EVT_POWER_CHANGE      0x0008
#define DLI_EVT_NUM_COMPLETED_PKT 0x0009
#define DLI_EVT_DATA_BUF_OVERFLOW 0x000B
#define DLI_EVT_ENC_PARAM_REQ     0x000E
#define DLI_EVT_PEER_FEATURES     0x0016
#define DLI_EVT_PEER_VERSION      0x0017
#define DLI_EVT_PHY_PARAM_UPDATE  0x0018
#define DLI_EVT_CONN_PARAM_UPDATE 0x0019
#define DLI_EVT_READ_PEER_POWER   0x001B

/* Pairing events (§9.1.22–§9.1.32) */
#define DLI_EVT_PAIR_INFO_EXCH    0x001E
#define DLI_EVT_PAIR_INFO_REPORT  0x001F
#define DLI_EVT_PAIR_OPT_REPORT  0x0020
#define DLI_EVT_REMOTE_PUBKEY    0x0021
#define DLI_EVT_PAIR_EXT_DATA    0x0022
#define DLI_EVT_PASSKEY_NOTIFY   0x0023
#define DLI_EVT_PAIR_RANDOM      0x0024
#define DLI_EVT_PAIR_CONFIRM     0x0025
#define DLI_EVT_DHKEY_VERIFY     0x0026
#define DLI_EVT_PAIR_FAIL        0x0027

/* Controller limits */
#define MAX_CONNECTIONS   8
#define MAX_EVENT_QUEUE   64
#define MAX_DATA_QUEUE    16
#define MAX_EVENT_SIZE    64
#define MAX_RAL_ENTRIES   16
#define MAX_DATA_SIZE     520
#define MAX_PEERS         4

/* Endpoint addresses per T/XS 10003-2025 Table 3 */
#define EP_EVENT_IN_ADDR  0x91
#define EP_DATA_IN_ADDR   0x92
#define EP_DATA_OUT_ADDR  0x12

/* USB class codes */
#define SLE_USB_CLASS     0xE0
#define SLE_USB_SUBCLASS  0x01
#define SLE_USB_PROTOCOL  0x05

/* USB descriptor string indices */
enum {
    STR_MANUFACTURER = 1,
    STR_PRODUCT,
    STR_SERIAL,
};

/* --------------------------------------------------------------------
 * Data structures
 * -------------------------------------------------------------------- */

OBJECT_DECLARE_SIMPLE_TYPE(USBSleDliState, USB_SLE_DLI)

/* Queued event packet */
typedef struct SleDliEvent {
    uint8_t data[MAX_EVENT_SIZE];
    int     len;
} SleDliEvent;

/* Queued async data packet */
typedef struct SleDliDataPkt {
    uint8_t data[MAX_DATA_SIZE];
    int     len;
} SleDliDataPkt;

/* Simulated peer for discovery/connection */
typedef struct SleDliPeer {
    bool    active;
    uint8_t addr[6];
    int8_t  rssi;
    uint8_t name[32];
    int     name_len;
    uint8_t discovery_level;
} SleDliPeer;

/* Resolving Address List entry */
typedef struct SleDliRalEntry {
    bool    used;
    uint8_t resolve_algo;
    uint8_t peer_id_type;
    uint8_t peer_id[6];
    uint8_t peer_irkid;
    uint8_t local_irkid;
    uint8_t peer_irk[16];
    uint8_t local_irk[16];
} SleDliRalEntry;

/* Per-connection state in the controller */
/* Pairing state machine phases (T/XS 10003-2025 §8.6) */
enum {
    PAIR_IDLE = 0,
    PAIR_REQUESTED,        /* T-node sent RequestPair, awaiting G-node response */
    PAIR_INFO_EXCHANGED,   /* Info exchange complete, awaiting option decision */
    PAIR_OPTION_DECIDED,   /* G-node chose method, awaiting T-node accept */
    PAIR_PUBKEY_EXCHANGED, /* Public keys exchanged */
    PAIR_RANDOM_SENT,      /* Random nonces exchanged */
    PAIR_CONFIRM_SENT,     /* Confirm values exchanged */
    PAIR_DHKEY_VERIFIED,   /* DHKey verification done */
    PAIR_COMPLETE,         /* Pairing complete, link key derived */
};

typedef struct SleDliConn {
    bool     active;
    uint16_t handle;
    uint8_t  peer_addr[6];
    /* Link to the remote device's connection slot for data relay */
    struct USBSleDliState *remote_dev;
    int      remote_slot;
    /* PHY parameters */
    uint8_t  mcs_index;
    uint8_t  bandwidth_mhz;
    /* Connection parameters */
    uint16_t interval;
    uint16_t latency;
    uint16_t timeout;
    /* Data length */
    uint16_t max_tx_octets;
    uint16_t max_rx_octets;
    /* Security state */
    bool     encrypted;
    /* Power management */
    int8_t   tx_power;       /* dBm, default 0 */
    bool     power_report;   /* auto power reporting enabled */
    /* Pairing state machine */
    int      pair_state;
    uint8_t  pair_method;    /* authentication method (0x00-0x05) */
    uint8_t  pair_auth_req;  /* authentication request field */
    uint8_t  local_pubkey[32];  /* simulated local public key */
    uint8_t  peer_pubkey[32];   /* received peer public key */
    uint8_t  local_random[16];  /* local random nonce */
    uint8_t  peer_random[16];   /* peer random nonce */
    uint8_t  local_confirm[16]; /* local confirm value */
    uint8_t  peer_confirm[16];  /* peer confirm value */
    uint8_t  dhkey_check[16];   /* DHKey verification value */
    uint8_t  link_key[16];      /* derived link key */
} SleDliConn;

struct USBSleDliState {
    USBDevice dev;

    /* Controller identity */
    uint8_t  mac_addr[6];
    uint32_t fw_version;
    uint8_t  protocol_version;
    uint16_t company_id;
    uint16_t sub_version;

    /* Controller state */
    bool     broadcasting;
    bool     scanning;
    bool     suspended;
    bool     fw_downloading;
    uint32_t fw_total_size;
    uint32_t fw_received;

    /* Broadcast configuration */
    uint8_t  bcast_data[251];
    int      bcast_data_len;
    uint8_t  bcast_scan_rsp[251];
    int      bcast_scan_rsp_len;

    /* Connections */
    SleDliConn connections[MAX_CONNECTIONS];
    uint16_t   next_handle;

    /* Simulated peers */
    SleDliPeer peers[MAX_PEERS];

    /* Resolving Address List */
    SleDliRalEntry ral[MAX_RAL_ENTRIES];
    int            ral_count;
    bool           rpa_enabled;
    uint16_t       rpa_timeout;   /* seconds */

    /* SLB cipher algorithm config */
    uint8_t  slb_cipher_algo_type;
    uint8_t  slb_cipher_comm_type;
    uint8_t  slb_cipher_priority[8];

    /* Event queue (interrupt IN + compat bulk IN) */
    SleDliEvent event_queue[MAX_EVENT_QUEUE];
    int         evt_head;
    int         evt_tail;
    int         evt_count;

    /* Async data queue (bulk IN) */
    SleDliDataPkt data_queue[MAX_DATA_QUEUE];
    int           data_head;
    int           data_tail;
    int           data_count;

    /* Properties */
    char     *cmd_path;  /* "dual", "bulk-compat", "control-only" */
    char     *fw_mode;   /* "accept", "missing", "fail" */

    /* Interrupt endpoint for wakeup signaling */
    USBEndpoint *intr;

    /* Deferred wakeup timer: schedule INT endpoint wakeup outside
     * the current USB transaction processing context so that xHCI
     * can actually complete the pending INT transfer. */
    QEMUTimer *deferred_wakeup;

    /* Inter-device air medium link */
    QTAILQ_ENTRY(USBSleDliState) air_link;
};

/* Forward declarations for functions used by air medium logic */
static void sle_dli_disconnected(USBSleDliState *s, uint16_t handle,
                                 uint8_t reason);
static void sle_dli_broadcast_report(USBSleDliState *s,
                                     const SleDliPeer *peer);
static void sle_dli_queue_data(USBSleDliState *s,
                               const uint8_t *buf, int len);
static void sle_dli_conn_complete(USBSleDliState *s, uint8_t status,
                                  uint16_t handle, const uint8_t *peer_addr);

/* --------------------------------------------------------------------
 * Global air medium: shared registry of all usb-sle-dli instances
 * -------------------------------------------------------------------- */

static QTAILQ_HEAD(, USBSleDliState) sle_air_devices =
    QTAILQ_HEAD_INITIALIZER(sle_air_devices);

/* Find a peer device on the air medium by MAC address */
static USBSleDliState *sle_air_find_by_addr(const uint8_t *addr)
{
    USBSleDliState *dev;
    QTAILQ_FOREACH(dev, &sle_air_devices, air_link) {
        if (memcmp(dev->mac_addr, addr, 6) == 0) {
            return dev;
        }
    }
    return NULL;
}

/* Register a device on the air medium */
static void sle_air_register(USBSleDliState *s)
{
    QTAILQ_INSERT_TAIL(&sle_air_devices, s, air_link);
}

/* Unregister a device from the air medium */
static void sle_air_unregister(USBSleDliState *s)
{
    QTAILQ_REMOVE(&sle_air_devices, s, air_link);
}

/* Forward declaration for event queuing (defined later) */
static void sle_dli_queue_event(USBSleDliState *s,
                                const uint8_t *data, int len);

/*
 * Deferred INT endpoint wakeup timer callback.
 *
 * When a cross-device operation (e.g. sle_air_connect) queues events
 * on another controller's event queue, calling usb_wakeup() directly
 * from within the source device's USB transaction handler may not take
 * effect because xHCI is still processing the source transfer.  By
 * deferring the wakeup to a 0-delay timer, we ensure it fires in the
 * next event loop iteration when xHCI is idle.
 */
static void sle_dli_deferred_wakeup_cb(void *opaque)
{
    USBSleDliState *s = opaque;
    if (s->evt_count > 0 && s->intr) {
        usb_wakeup(s->intr, 0);
    }
}

/*
 * Schedule a deferred INT endpoint wakeup.  Safe to call from within
 * another device's USB transaction handler.
 */
static void sle_dli_schedule_wakeup(USBSleDliState *s)
{
    if (s->deferred_wakeup) {
        timer_mod(s->deferred_wakeup,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    }
}

/* Notify all scanning devices about a broadcasting device */
static void sle_air_broadcast_notify(USBSleDliState *broadcaster)
{
    USBSleDliState *dev;
    SleDliPeer fake_peer;

    memset(&fake_peer, 0, sizeof(fake_peer));
    fake_peer.active = true;
    memcpy(fake_peer.addr, broadcaster->mac_addr, 6);
    fake_peer.rssi = -30;  /* close proximity simulated */
    fake_peer.discovery_level = 2;
    /* Copy device name from serial string */
    const char *name = "SLE-Device";
    fake_peer.name_len = strlen(name);
    memcpy(fake_peer.name, name, fake_peer.name_len);

    QTAILQ_FOREACH(dev, &sle_air_devices, air_link) {
        if (dev == broadcaster) {
            continue;
        }
        if (dev->scanning) {
            sle_dli_broadcast_report(dev, &fake_peer);
            sle_dli_schedule_wakeup(dev);
        }
    }
}

/* Create a bidirectional connection between two devices */
static bool sle_air_connect(USBSleDliState *initiator,
                            const uint8_t *peer_addr,
                            int initiator_slot)
{
    USBSleDliState *acceptor = sle_air_find_by_addr(peer_addr);
    if (!acceptor || acceptor == initiator) {
        return false;
    }

    /* Find a free slot on the acceptor side */
    int acceptor_slot = -1;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!acceptor->connections[i].active) {
            acceptor_slot = i;
            break;
        }
    }
    if (acceptor_slot < 0) {
        return false;
    }

    /* Set up the acceptor's connection */
    acceptor->connections[acceptor_slot].active = true;
    acceptor->connections[acceptor_slot].handle = acceptor->next_handle++;
    memcpy(acceptor->connections[acceptor_slot].peer_addr,
           initiator->mac_addr, 6);
    acceptor->connections[acceptor_slot].remote_dev = initiator;
    acceptor->connections[acceptor_slot].remote_slot = initiator_slot;

    /* Link the initiator back to the acceptor */
    initiator->connections[initiator_slot].remote_dev = acceptor;
    initiator->connections[initiator_slot].remote_slot = acceptor_slot;

    /* Generate ConnEstablished event on the acceptor */
    sle_dli_conn_complete(acceptor, 0x00,
                          acceptor->connections[acceptor_slot].handle,
                          initiator->mac_addr);
    sle_dli_schedule_wakeup(acceptor);

    return true;
}

/* Relay data from one connected device to its peer via Bulk IN (standard path) */
static void sle_air_relay_data(USBSleDliState *sender,
                               int conn_slot,
                               const uint8_t *data, int len)
{
    SleDliConn *conn = &sender->connections[conn_slot];
    if (!conn->active || !conn->remote_dev) {
        return;
    }

    USBSleDliState *receiver = conn->remote_dev;
    int remote_slot = conn->remote_slot;
    if (remote_slot < 0 || remote_slot >= MAX_CONNECTIONS ||
        !receiver->connections[remote_slot].active) {
        return;
    }

    /*
     * Extract payload from the DLI async data packet:
     *   [0]    = 0xA3 (DLI_PKT_ASYNC_DATA)
     *   [1..2] = link_id_seg (sender handle encoded)
     *   [3..4] = payload length (LE16)
     *   [5..N] = payload
     */
    const uint8_t *payload = data;
    int payload_len = len;
    if (len >= 5 && data[0] == DLI_PKT_ASYNC_DATA) {
        payload = &data[5];
        payload_len = len - 5;
    }

    /*
     * Rebuild a standard 0xA3 async data packet with the receiver's handle
     * and queue it to the data queue for delivery via Bulk IN (0x92).
     */
    uint16_t recv_handle = receiver->connections[remote_slot].handle;
    uint16_t link_id_seg = (recv_handle & 0x0FFF) << 4;
    uint8_t buf[MAX_DATA_SIZE];
    int total = 5 + payload_len;
    if (total > MAX_DATA_SIZE) {
        payload_len = MAX_DATA_SIZE - 5;
        total = MAX_DATA_SIZE;
    }
    buf[0] = DLI_PKT_ASYNC_DATA;  /* 0xA3 */
    buf[1] = link_id_seg & 0xFF;
    buf[2] = (link_id_seg >> 8) & 0xFF;
    buf[3] = payload_len & 0xFF;
    buf[4] = (payload_len >> 8) & 0xFF;
    if (payload_len > 0) {
        memcpy(&buf[5], payload, payload_len);
    }
    sle_dli_queue_data(receiver, buf, total);
    sle_dli_schedule_wakeup(receiver);
}

/* Disconnect and notify the remote side */
static void sle_air_disconnect(USBSleDliState *local, int slot,
                               uint8_t reason)
{
    SleDliConn *conn = &local->connections[slot];
    if (!conn->remote_dev) {
        return;
    }

    USBSleDliState *remote = conn->remote_dev;
    int remote_slot = conn->remote_slot;

    /* Clean up this side's link */
    conn->remote_dev = NULL;
    conn->remote_slot = -1;

    /* Disconnect the remote side */
    if (remote_slot >= 0 && remote_slot < MAX_CONNECTIONS &&
        remote->connections[remote_slot].active) {
        uint16_t remote_handle = remote->connections[remote_slot].handle;
        remote->connections[remote_slot].active = false;
        remote->connections[remote_slot].remote_dev = NULL;
        remote->connections[remote_slot].remote_slot = -1;
        sle_dli_disconnected(remote, remote_handle, reason);
        sle_dli_schedule_wakeup(remote);
    }
}

/* --------------------------------------------------------------------
 * USB descriptors
 * -------------------------------------------------------------------- */

static const USBDescStrings desc_strings = {
    [STR_MANUFACTURER] = "SparkLink Alliance",
    [STR_PRODUCT]      = "SLE DLI Controller (QEMU)",
    [STR_SERIAL]       = "QEMU-SLE-DLI-001",
};

static const USBDescIface desc_iface_sle_dli = {
    .bInterfaceNumber   = 0,
    .bAlternateSetting  = 0,
    .bNumEndpoints      = 3,
    .bInterfaceClass    = SLE_USB_CLASS,
    .bInterfaceSubClass = SLE_USB_SUBCLASS,
    .bInterfaceProtocol = SLE_USB_PROTOCOL,
    .eps = (USBDescEndpoint[]) {
        {
            .bEndpointAddress = USB_DIR_IN | 0x11,  /* 0x91: interrupt IN (events) */
            .bmAttributes     = USB_ENDPOINT_XFER_INT,
            .wMaxPacketSize   = 64,
            .bInterval        = 4,
        },
        {
            .bEndpointAddress = USB_DIR_IN | 0x12,  /* 0x92: bulk IN (data) */
            .bmAttributes     = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize   = 64,
        },
        {
            .bEndpointAddress = USB_DIR_OUT | 0x12, /* 0x12: bulk OUT (commands) */
            .bmAttributes     = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize   = 64,
        },
    },
};

static const USBDescDevice desc_device_sle_dli = {
    .bcdUSB         = 0x0200,
    .bDeviceClass   = SLE_USB_CLASS,
    .bDeviceSubClass = SLE_USB_SUBCLASS,
    .bDeviceProtocol = SLE_USB_PROTOCOL,
    .bMaxPacketSize0 = 64,
    .bNumConfigurations = 1,
    .confs = (USBDescConfig[]) {
        {
            .bNumInterfaces    = 1,
            .bConfigurationValue = 1,
            .bmAttributes      = USB_CFG_ATT_ONE | USB_CFG_ATT_SELFPOWER,
            .bMaxPower         = 50, /* 100 mA */
            .nif = 1,
            .ifs = &desc_iface_sle_dli,
        },
    },
};

static const USBDesc desc_sle_dli = {
    .id = {
        .idVendor  = 0x1234,  /* test vendor */
        .idProduct = 0x5678,  /* test product */
        .bcdDevice = 0x0100,
        .iManufacturer = STR_MANUFACTURER,
        .iProduct      = STR_PRODUCT,
        .iSerialNumber = STR_SERIAL,
    },
    .full  = &desc_device_sle_dli,
    .high  = &desc_device_sle_dli,
    .str   = desc_strings,
};

/* --------------------------------------------------------------------
 * Event queue helpers
 * -------------------------------------------------------------------- */

static void sle_dli_queue_event(USBSleDliState *s,
                                const uint8_t *data, int len)
{
    if (s->evt_count >= MAX_EVENT_QUEUE) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "usb-sle-dli: event queue full, dropping\n");
        return;
    }
    SleDliEvent *e = &s->event_queue[s->evt_tail];
    int copy_len = MIN(len, MAX_EVENT_SIZE);
    memcpy(e->data, data, copy_len);
    e->len = copy_len;
    s->evt_tail = (s->evt_tail + 1) % MAX_EVENT_QUEUE;
    s->evt_count++;
}

static int sle_dli_dequeue_event(USBSleDliState *s,
                                 uint8_t *buf, int buf_size)
{
    if (s->evt_count == 0) {
        return 0;
    }
    SleDliEvent *e = &s->event_queue[s->evt_head];
    int copy_len = MIN(e->len, buf_size);
    memcpy(buf, e->data, copy_len);
    s->evt_head = (s->evt_head + 1) % MAX_EVENT_QUEUE;
    s->evt_count--;
    return copy_len;
}

/* Queue async data for bulk IN */
static void sle_dli_queue_data(USBSleDliState *s,
                               const uint8_t *data, int len)
{
    if (s->data_count >= MAX_DATA_QUEUE) {
        return;
    }
    SleDliDataPkt *p = &s->data_queue[s->data_tail];
    int copy_len = MIN(len, MAX_DATA_SIZE);
    memcpy(p->data, data, copy_len);
    p->len = copy_len;
    s->data_tail = (s->data_tail + 1) % MAX_DATA_QUEUE;
    s->data_count++;
}

static int sle_dli_dequeue_data(USBSleDliState *s,
                                uint8_t *buf, int buf_size)
{
    if (s->data_count == 0) {
        return 0;
    }
    SleDliDataPkt *p = &s->data_queue[s->data_head];
    int copy_len = MIN(p->len, buf_size);
    memcpy(buf, p->data, copy_len);
    s->data_head = (s->data_head + 1) % MAX_DATA_QUEUE;
    s->data_count--;
    return copy_len;
}

/* --------------------------------------------------------------------
 * Event builders
 * -------------------------------------------------------------------- */

/*
 * Build a CommandComplete event packet.
 *
 * Wire format (T/XS 10003-2025 §7.3):
 *   [0..1] event_code = 0x0002 (LE16)
 *   [2..3] total_param_len (LE16)
 *   [4..5] opcode (LE16)
 *   [6]    status
 *   [7..N] return params
 */
static void sle_dli_cmd_complete(USBSleDliState *s, uint16_t opcode,
                                 uint8_t status,
                                 const uint8_t *params, int plen)
{
    uint8_t buf[MAX_EVENT_SIZE];
    int total_plen = 3 + plen; /* opcode(2) + status(1) + return_params */

    buf[0] = DLI_EVT_CMD_COMPLETE & 0xFF;
    buf[1] = (DLI_EVT_CMD_COMPLETE >> 8) & 0xFF;
    buf[2] = (uint8_t)(total_plen & 0xFF);
    buf[3] = (uint8_t)(total_plen >> 8);
    buf[4] = opcode & 0xFF;
    buf[5] = (opcode >> 8) & 0xFF;
    buf[6] = status;
    if (plen > 0 && params) {
        memcpy(&buf[7], params, MIN(plen, MAX_EVENT_SIZE - 7));
    }
    sle_dli_queue_event(s, buf, 7 + plen);
}

/*
 * Build a CommandStatus event packet.
 *
 * Wire format (T/XS 10003-2025 §7.3):
 *   [0..1] event_code = 0x0001 (LE16)
 *   [2..3] param_len = 3 (LE16)
 *   [4]    status
 *   [5..6] opcode (LE16)
 */
static void sle_dli_cmd_status(USBSleDliState *s, uint16_t opcode,
                               uint8_t status)
{
    uint8_t buf[7];
    buf[0] = DLI_EVT_CMD_STATUS & 0xFF;
    buf[1] = (DLI_EVT_CMD_STATUS >> 8) & 0xFF;
    buf[2] = 3;
    buf[3] = 0;
    buf[4] = status;
    buf[5] = opcode & 0xFF;
    buf[6] = (opcode >> 8) & 0xFF;
    sle_dli_queue_event(s, buf, 7);
}

/*
 * Build a ConnectionEstablished event.
 *
 * Wire format (T/XS 10003-2025 §7.3):
 *   [0..1] event_code = 0x0015 (LE16)
 *   [2..3] param_len = 9 (LE16)
 *   [4]    status
 *   [5..6] handle (LE16)
 *   [7..12] peer addr (6 bytes)
 */
static void sle_dli_conn_complete(USBSleDliState *s, uint8_t status,
                                  uint16_t handle,
                                  const uint8_t *addr)
{
    uint8_t buf[13];
    buf[0]  = DLI_EVT_CONN_ESTABLISHED & 0xFF;
    buf[1]  = (DLI_EVT_CONN_ESTABLISHED >> 8) & 0xFF;
    buf[2]  = 9;
    buf[3]  = 0;
    buf[4]  = status;
    buf[5]  = handle & 0xFF;
    buf[6]  = (handle >> 8) & 0xFF;
    memcpy(&buf[7], addr, 6);
    sle_dli_queue_event(s, buf, 13);
}

/*
 * Build a Disconnected event.
 *
 * Wire format (T/XS 10003-2025 §7.3):
 *   [0..1] event_code = 0x0005 (LE16)
 *   [2..3] param_len = 3 (LE16)
 *   [4..5] handle (LE16)
 *   [6]    reason
 */
static void sle_dli_disconnected(USBSleDliState *s, uint16_t handle,
                                 uint8_t reason)
{
    uint8_t buf[7];
    buf[0] = DLI_EVT_DISCONNECTED & 0xFF;
    buf[1] = (DLI_EVT_DISCONNECTED >> 8) & 0xFF;
    buf[2] = 3;
    buf[3] = 0;
    buf[4] = handle & 0xFF;
    buf[5] = (handle >> 8) & 0xFF;
    buf[6] = reason;
    sle_dli_queue_event(s, buf, 7);
}

/*
 * Build a BroadcastReport event.
 *
 * Wire format (T/XS 10003-2025 §7.3):
 *   [0..1] event_code = 0x001A (LE16)
 *   [2..3] param_len (LE16)
 *   [4..9] addr (6 bytes)
 *   [10]   rssi
 *   [11]   data_len
 *   [12..N] advertising data (TLV)
 */
static void sle_dli_broadcast_report(USBSleDliState *s,
                                     const SleDliPeer *peer)
{
    uint8_t buf[MAX_EVENT_SIZE];
    int adv_len = 0;
    uint8_t adv_data[32];

    /* Build minimal advertising TLV: discovery level */
    adv_data[0] = 2;  /* length */
    adv_data[1] = 0x01; /* type: discovery level */
    adv_data[2] = peer->discovery_level;
    adv_len = 3;

    /* Add local name TLV if present */
    if (peer->name_len > 0) {
        adv_data[adv_len] = (uint8_t)(1 + peer->name_len);
        adv_data[adv_len + 1] = 0x09; /* complete local name */
        memcpy(&adv_data[adv_len + 2], peer->name, peer->name_len);
        adv_len += 2 + peer->name_len;
    }

    int plen = 6 + 1 + 1 + adv_len; /* addr + rssi + data_len + data */
    buf[0]  = DLI_EVT_BROADCAST_REPORT & 0xFF;
    buf[1]  = (DLI_EVT_BROADCAST_REPORT >> 8) & 0xFF;
    buf[2]  = (uint8_t)(plen & 0xFF);
    buf[3]  = (uint8_t)(plen >> 8);
    memcpy(&buf[4], peer->addr, 6);
    buf[10] = (uint8_t)peer->rssi;
    buf[11] = (uint8_t)adv_len;
    memcpy(&buf[12], adv_data, adv_len);
    sle_dli_queue_event(s, buf, 12 + adv_len);
}

/*
 * Build a HardwareError event.
 *
 * Wire format (T/XS 10003-2025 §7.3):
 *   [0..1] event_code = 0x000A (LE16)
 *   [2..3] param_len = 1 (LE16)
 *   [4]    error code
 */
static void sle_dli_hw_error(USBSleDliState *s, uint8_t code)
{
    uint8_t buf[5];
    buf[0] = DLI_EVT_HW_ERROR & 0xFF;
    buf[1] = (DLI_EVT_HW_ERROR >> 8) & 0xFF;
    buf[2] = 1;
    buf[3] = 0;
    buf[4] = code;
    sle_dli_queue_event(s, buf, 5);
}

/* Find an active connection by handle. Returns NULL if not found. */
static SleDliConn *sle_dli_find_conn(USBSleDliState *s, uint16_t handle)
{
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (s->connections[i].active && s->connections[i].handle == handle) {
            return &s->connections[i];
        }
    }
    return NULL;
}

/*
 * Build a PeerFeatures event (0x0016).
 *   [0..1] event_code (LE16)
 *   [2..3] param_len = 13 (LE16)
 *   [4..5] handle (LE16)
 *   [6]    status
 *   [7]    pad
 *   [8..17] features (10 bytes)
 */
static void sle_dli_peer_features_evt(USBSleDliState *s, uint16_t handle,
                                      uint8_t status,
                                      const uint8_t *features)
{
    uint8_t buf[18];
    buf[0] = DLI_EVT_PEER_FEATURES & 0xFF;
    buf[1] = (DLI_EVT_PEER_FEATURES >> 8) & 0xFF;
    buf[2] = 14; /* param_len */
    buf[3] = 0;
    buf[4] = handle & 0xFF;
    buf[5] = (handle >> 8) & 0xFF;
    buf[6] = status;
    buf[7] = 0; /* pad */
    if (features) {
        memcpy(&buf[8], features, 10);
    } else {
        memset(&buf[8], 0, 10);
    }
    sle_dli_queue_event(s, buf, 18);
}

/*
 * Build a PeerVersion event (0x0017).
 *   [0..1] event_code (LE16)
 *   [2..3] param_len = 8 (LE16)
 *   [4..5] handle (LE16)
 *   [6]    status
 *   [7]    version
 *   [8..9] manufacturer (LE16)
 *   [10..11] subversion (LE16)
 */
static void sle_dli_peer_version_evt(USBSleDliState *s, uint16_t handle,
                                     uint8_t status, uint8_t version,
                                     uint16_t manufacturer, uint16_t subversion)
{
    uint8_t buf[12];
    buf[0]  = DLI_EVT_PEER_VERSION & 0xFF;
    buf[1]  = (DLI_EVT_PEER_VERSION >> 8) & 0xFF;
    buf[2]  = 8;
    buf[3]  = 0;
    buf[4]  = handle & 0xFF;
    buf[5]  = (handle >> 8) & 0xFF;
    buf[6]  = status;
    buf[7]  = version;
    buf[8]  = manufacturer & 0xFF;
    buf[9]  = (manufacturer >> 8) & 0xFF;
    buf[10] = subversion & 0xFF;
    buf[11] = (subversion >> 8) & 0xFF;
    sle_dli_queue_event(s, buf, 12);
}

/*
 * Build a PhyParamUpdate event (0x0018).
 *   [0..1] event_code (LE16)
 *   [2..3] param_len = 4 (LE16)
 *   [4..5] handle (LE16)
 *   [6]    mcs_index
 *   [7]    bandwidth_mhz
 */
static void sle_dli_phy_update_evt(USBSleDliState *s, uint16_t handle,
                                   uint8_t mcs_index, uint8_t bandwidth_mhz)
{
    uint8_t buf[8];
    buf[0] = DLI_EVT_PHY_PARAM_UPDATE & 0xFF;
    buf[1] = (DLI_EVT_PHY_PARAM_UPDATE >> 8) & 0xFF;
    buf[2] = 4;
    buf[3] = 0;
    buf[4] = handle & 0xFF;
    buf[5] = (handle >> 8) & 0xFF;
    buf[6] = mcs_index;
    buf[7] = bandwidth_mhz;
    sle_dli_queue_event(s, buf, 8);
}

/*
 * Build a ConnParamUpdate event (0x0019).
 *   [0..1] event_code (LE16)
 *   [2..3] param_len = 8 (LE16)
 *   [4..5] handle (LE16)
 *   [6..7] interval (LE16)
 *   [8..9] latency (LE16)
 *   [10..11] timeout (LE16)
 */
static void sle_dli_conn_param_update_evt(USBSleDliState *s, uint16_t handle,
                                          uint16_t interval, uint16_t latency,
                                          uint16_t timeout)
{
    uint8_t buf[12];
    buf[0]  = DLI_EVT_CONN_PARAM_UPDATE & 0xFF;
    buf[1]  = (DLI_EVT_CONN_PARAM_UPDATE >> 8) & 0xFF;
    buf[2]  = 8;
    buf[3]  = 0;
    buf[4]  = handle & 0xFF;
    buf[5]  = (handle >> 8) & 0xFF;
    buf[6]  = interval & 0xFF;
    buf[7]  = (interval >> 8) & 0xFF;
    buf[8]  = latency & 0xFF;
    buf[9]  = (latency >> 8) & 0xFF;
    buf[10] = timeout & 0xFF;
    buf[11] = (timeout >> 8) & 0xFF;
    sle_dli_queue_event(s, buf, 12);
}

/* --------------------------------------------------------------------
 * Command engine
 * -------------------------------------------------------------------- */

static void sle_dli_process_command(USBSleDliState *s,
                                    uint16_t opcode,
                                    const uint8_t *params, int plen)
{
    switch (opcode) {
    case DLI_OP_RESET:
        /* Reset controller to initial state */
        s->broadcasting = false;
        s->scanning = false;
        s->fw_downloading = false;
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (s->connections[i].active) {
                sle_dli_disconnected(s, s->connections[i].handle, 0x13);
                s->connections[i].active = false;
            }
        }
        s->next_handle = 0x0001;
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;

    case DLI_OP_READ_CMD_LEN: {
        /* Return max command parameter length (2 bytes LE16) */
        uint8_t rp[2];
        rp[0] = 0xFF; /* 255 bytes */
        rp[1] = 0x00;
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 2);
        break;
    }

    case DLI_OP_READ_CTRL_BUFFER: {
        /*
         * Return buffer sizes:
         *   async_max_len(2) + async_max_num(2) +
         *   sync_max_len(2) + sync_max_num(2)
         */
        uint8_t rp[8];
        rp[0] = 0x00; rp[1] = 0x02; /* async max len = 512 */
        rp[2] = 0x08; rp[3] = 0x00; /* async max num = 8 */
        rp[4] = 0x40; rp[5] = 0x00; /* sync max len = 64 */
        rp[6] = 0x04; rp[7] = 0x00; /* sync max num = 4 */
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 8);
        break;
    }

    case DLI_OP_READ_FEATURES: {
        /* Return 8 bytes of feature bits (all zeros = minimal) */
        uint8_t rp[8] = {0};
        rp[0] = 0x01; /* bit 0: basic feature supported */
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 8);
        break;
    }

    case DLI_OP_READ_VERSION: {
        /*
         * Return:
         *   version(1) + company_id(2) + sub_version(2)
         *
         * The guest parses this as a 4-byte fw_version at offset [7..10]
         * in the raw event response. Since the event is:
         *   [0..1] evt_code  [2..3] plen  [4..5] opcode
         *   [6] status  [7] version  [8..9] company_id  [10..11] sub_version
         * The guest reads le32 from offset 7, which spans
         * version(1) + company_id(2) + sub_version[0](1).
         */
        uint8_t rp[5];
        rp[0] = s->protocol_version;
        rp[1] = s->company_id & 0xFF;
        rp[2] = (s->company_id >> 8) & 0xFF;
        rp[3] = s->sub_version & 0xFF;
        rp[4] = (s->sub_version >> 8) & 0xFF;
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 5);
        break;
    }

    case DLI_OP_READ_MAC: {
        /* Return 6-byte MAC address */
        sle_dli_cmd_complete(s, opcode, 0x00, s->mac_addr, 6);
        break;
    }

    case DLI_OP_SET_MAC:
        if (plen >= 6) {
            memcpy(s->mac_addr, params, 6);
        }
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;

    /* ----------------------------------------------------------------
     * Broadcast configuration commands (§8.2)
     * ---------------------------------------------------------------- */

    case DLI_OP_SET_BCAST_PARAM:
        /* params: [adv_handle:1] [mode:1] [gt_role:1] ... (variable)
         * Accept any params, return CmdComplete with tx_power */
        {
            uint8_t rp[1] = { 0 }; /* selected tx_power = 0 dBm */
            sle_dli_cmd_complete(s, opcode, 0x00, rp, 1);
        }
        break;

    case DLI_OP_SET_BCAST_DATA:
        /* params: [adv_handle:1] [frag_op:1] [frag_sel:1]
         *         [data_len:1] [data:N] */
        if (plen >= 4) {
            int data_len = params[3];
            if (data_len > 0 && plen >= 4 + data_len &&
                data_len <= (int)sizeof(s->bcast_data)) {
                memcpy(s->bcast_data, &params[4], data_len);
                s->bcast_data_len = data_len;
            }
        }
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;

    case DLI_OP_SET_BCAST_SCAN_RSP:
        /* params: [adv_handle:1] [frag_op:1] [frag_sel:1]
         *         [data_len:1] [data:N] */
        if (plen >= 4) {
            int data_len = params[3];
            if (data_len > 0 && plen >= 4 + data_len &&
                data_len <= (int)sizeof(s->bcast_scan_rsp)) {
                memcpy(s->bcast_scan_rsp, &params[4], data_len);
                s->bcast_scan_rsp_len = data_len;
            }
        }
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;

    case DLI_OP_ENABLE_BROADCAST: {
        bool enable = (plen >= 1) ? (params[0] != 0) : true;
        s->broadcasting = enable;
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        if (enable) {
            /* Notify all scanning devices on the air medium */
            sle_air_broadcast_notify(s);
        }
        break;
    }

    case DLI_OP_READ_MAX_BCAST_LEN: {
        /* no params → CmdComplete with [max_len:2] */
        uint8_t rp[2];
        rp[0] = 251 & 0xFF; /* 251 bytes */
        rp[1] = 0;
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 2);
        break;
    }

    case DLI_OP_READ_BCAST_SET_SZ: {
        /* no params → CmdComplete with [num_sets:1] */
        uint8_t rp[1] = { 4 }; /* Support 4 broadcast sets */
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 1);
        break;
    }

    case DLI_OP_DELETE_BCAST_SET:
        /* params: [set_id:1] → CmdComplete */
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;

    /* ----------------------------------------------------------------
     * Scan commands (§8.3)
     * ---------------------------------------------------------------- */

    case DLI_OP_SET_SCAN_PARAM:
        /* Accept any scan parameters, return success */
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;

    case DLI_OP_ENABLE_SCAN: {
        bool enable = (plen >= 1) ? (params[0] != 0) : true;
        s->scanning = enable;
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        if (enable) {
            /* Generate broadcast reports for built-in static peers */
            for (int i = 0; i < MAX_PEERS; i++) {
                if (s->peers[i].active) {
                    sle_dli_broadcast_report(s, &s->peers[i]);
                }
            }
            /* Also discover broadcasting devices on the air medium */
            USBSleDliState *air_dev;
            QTAILQ_FOREACH(air_dev, &sle_air_devices, air_link) {
                if (air_dev == s || !air_dev->broadcasting) {
                    continue;
                }
                SleDliPeer air_peer;
                memset(&air_peer, 0, sizeof(air_peer));
                air_peer.active = true;
                memcpy(air_peer.addr, air_dev->mac_addr, 6);
                air_peer.rssi = -30;
                air_peer.discovery_level = 2;
                const char *name = "SLE-Air";
                air_peer.name_len = strlen(name);
                memcpy(air_peer.name, name, air_peer.name_len);
                sle_dli_broadcast_report(s, &air_peer);
            }
        }
        break;
    }

    case DLI_OP_SET_SCAN_REQ_DATA:
        /* Accept scan request payload, return success */
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;

    /* ----------------------------------------------------------------
     * Connection commands (§8.4)
     * ---------------------------------------------------------------- */

    case DLI_OP_CANCEL_CONN:
        /* Cancel pending connection → CmdComplete */
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;

    case DLI_OP_CREATE_CONN: {
        /* params: [addr:6] (kernel sends 6-byte MAC address directly) */
        if (plen < 6) {
            sle_dli_cmd_status(s, opcode, 0x12); /* invalid params */
            break;
        }
        /* Find free connection slot */
        int slot = -1;
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (!s->connections[i].active) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            sle_dli_cmd_status(s, opcode, 0x07); /* max connections */
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        /* Create connection on this side */
        s->connections[slot].active = true;
        s->connections[slot].handle = s->next_handle++;
        memcpy(s->connections[slot].peer_addr, &params[0], 6);
        s->connections[slot].remote_dev = NULL;
        s->connections[slot].remote_slot = -1;
        /* Default PHY/connection parameters */
        s->connections[slot].mcs_index = 4;     /* QPSK 1/2 */
        s->connections[slot].bandwidth_mhz = 2; /* 2 MHz */
        s->connections[slot].interval = 20;     /* 20 units */
        s->connections[slot].latency = 0;
        s->connections[slot].timeout = 500;     /* 500 units */
        s->connections[slot].max_tx_octets = 251;
        s->connections[slot].max_rx_octets = 251;

        /* Try to create a bidirectional link via the air medium */
        sle_air_connect(s, &params[0], slot);

        /* Generate ConnEstablished event on this side */
        sle_dli_conn_complete(s, 0x00,
                              s->connections[slot].handle,
                              s->connections[slot].peer_addr);
        break;
    }

    case DLI_OP_DISCONNECT: {
        /* params: [handle:2] [reason:1(optional)] */
        if (plen < 2) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        uint8_t reason = (plen >= 3) ? params[2] : 0x13; /* default: remote terminate */
        bool found = false;
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (s->connections[i].active &&
                s->connections[i].handle == handle) {
                /* Notify remote device via air medium */
                sle_air_disconnect(s, i, reason);
                s->connections[i].active = false;
                s->connections[i].remote_dev = NULL;
                s->connections[i].remote_slot = -1;
                found = true;
                break;
            }
        }
        if (found) {
            sle_dli_cmd_status(s, opcode, 0x00);
            sle_dli_disconnected(s, handle, reason);
        } else {
            sle_dli_cmd_status(s, opcode, 0x02); /* unknown handle */
        }
        break;
    }

    case DLI_OP_FW_DL_START:
        if (s->fw_mode && strcmp(s->fw_mode, "missing") == 0) {
            sle_dli_cmd_complete(s, opcode, 0x01, NULL, 0);
        } else if (s->fw_mode && strcmp(s->fw_mode, "fail") == 0) {
            sle_dli_cmd_complete(s, opcode, 0x01, NULL, 0);
        } else {
            /* Accept firmware download */
            s->fw_downloading = true;
            if (plen >= 4) {
                s->fw_total_size = params[0] |
                    ((uint32_t)params[1] << 8) |
                    ((uint32_t)params[2] << 16) |
                    ((uint32_t)params[3] << 24);
            }
            s->fw_received = 0;
            sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        }
        break;

    case DLI_OP_FW_DL_DONE:
        if (!s->fw_downloading) {
            sle_dli_cmd_complete(s, opcode, 0x01, NULL, 0);
        } else if (s->fw_mode && strcmp(s->fw_mode, "fail") == 0) {
            s->fw_downloading = false;
            sle_dli_cmd_complete(s, opcode, 0x01, NULL, 0);
        } else {
            s->fw_downloading = false;
            /* Update fw_version to indicate new firmware loaded */
            s->fw_version += 1;
            sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        }
        break;

    /* ----------------------------------------------------------------
     * Link control commands (§8.5)
     * ---------------------------------------------------------------- */

    case DLI_OP_READ_PEER_FEATURES: {
        /* params: [handle:2] → CmdStatus + PeerFeatures event */
        if (plen < 2) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02); /* unknown connection */
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        /* Return remote device features if linked, else zeros */
        uint8_t features[10] = {0};
        if (conn->remote_dev) {
            /* Simulate: copy features from local (peers share features) */
            features[0] = 0xFF;
            features[1] = 0x03;
        }
        sle_dli_peer_features_evt(s, handle, 0x00, features);
        break;
    }

    case DLI_OP_READ_PEER_VERSION: {
        /* params: [handle:2] → CmdStatus + PeerVersion event */
        if (plen < 2) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        uint8_t ver = s->protocol_version;
        uint16_t mfr = s->company_id;
        uint16_t sub = s->sub_version;
        if (conn->remote_dev) {
            ver = conn->remote_dev->protocol_version;
            mfr = conn->remote_dev->company_id;
            sub = conn->remote_dev->sub_version;
        }
        sle_dli_peer_version_evt(s, handle, 0x00, ver, mfr, sub);
        break;
    }

    case DLI_OP_SET_DATA_LENGTH: {
        /* params: [handle:2] [max_tx:2] → CmdComplete */
        if (plen < 4) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        uint16_t max_tx = params[2] | ((uint16_t)params[3] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_complete(s, opcode, 0x02, NULL, 0);
            break;
        }
        conn->max_tx_octets = max_tx;
        if (plen >= 6) {
            conn->max_rx_octets = params[4] | ((uint16_t)params[5] << 8);
        }
        uint8_t rp[3];
        rp[0] = handle & 0xFF;
        rp[1] = (handle >> 8) & 0xFF;
        rp[2] = 0x00;
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 3);
        break;
    }

    case DLI_OP_READ_PHY_PARAM: {
        /* params: [handle:2] → CmdComplete with PHY params */
        if (plen < 2) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_complete(s, opcode, 0x02, NULL, 0);
            break;
        }
        uint8_t rp[11];
        rp[0] = handle & 0xFF;
        rp[1] = (handle >> 8) & 0xFF;
        rp[2] = 0x00; /* status */
        rp[3] = 0;    /* tx_frame_type */
        rp[4] = 0;    /* rx_frame_type */
        rp[5] = conn->bandwidth_mhz; /* tx_bandwidth */
        rp[6] = conn->bandwidth_mhz; /* rx_bandwidth */
        rp[7] = 0;    /* tx_pilot_density */
        rp[8] = 0;    /* rx_pilot_density */
        rp[9] = 0;    /* tx_feedback_type */
        rp[10] = 0;   /* rx_feedback_type */
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 11);
        break;
    }

    case DLI_OP_SET_PHY_PARAM: {
        /* params: [handle:2] [tx_frame:1] [rx_frame:1] [tx_bw:1] [rx_bw:1]
         *         [tx_pilot:1] [rx_pilot:1] [tx_fb:1] [rx_fb:1]
         * → CmdStatus + PhyParamUpdate event */
        if (plen < 4) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        /* Apply bandwidth if present */
        if (plen >= 6) {
            conn->bandwidth_mhz = params[4];
        }
        sle_dli_phy_update_evt(s, handle, conn->mcs_index,
                               conn->bandwidth_mhz);
        break;
    }

    case DLI_OP_CONN_PARAM_UPDATE: {
        /* params: [handle:2] [interval_min:2] [interval_max:2]
         *         [latency:2] [timeout:2] → CmdStatus + ConnParamUpdate evt */
        if (plen < 10) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        uint16_t imin   = params[2] | ((uint16_t)params[3] << 8);
        uint16_t imax   = params[4] | ((uint16_t)params[5] << 8);
        uint16_t lat    = params[6] | ((uint16_t)params[7] << 8);
        uint16_t tmo    = params[8] | ((uint16_t)params[9] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        /* Pick midpoint of interval range */
        conn->interval = (imin + imax) / 2;
        conn->latency = lat;
        conn->timeout = tmo;
        sle_dli_conn_param_update_evt(s, handle, conn->interval,
                                      conn->latency, conn->timeout);
        break;
    }

    case DLI_OP_READ_RSSI: {
        /* params: [handle:2] → CmdComplete with RSSI */
        if (plen < 2) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_complete(s, opcode, 0x02, NULL, 0);
            break;
        }
        uint8_t rp[4];
        rp[0] = handle & 0xFF;
        rp[1] = (handle >> 8) & 0xFF;
        rp[2] = 0x00;         /* status */
        rp[3] = (uint8_t)-50; /* RSSI: -50 dBm */
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 4);
        break;
    }

    case DLI_OP_SET_CODING_MOD: {
        /* params: [mcs_index:1] → CmdComplete
         * The driver sends this when selecting a global MCS/coding mode.
         * We just accept it and return success. */
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    case DLI_OP_CONN_PARAM_REQ_RPL: {
        /* params: [handle:2] [accept:1] [interval:2] [latency:2] [timeout:2]
         * Reply to a PeerConnParamReq event. Accept and apply. */
        if (plen < 3) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_complete(s, opcode, 0x02, NULL, 0);
            break;
        }
        bool accept = params[2] != 0;
        if (accept && plen >= 9) {
            conn->interval = params[3] | ((uint16_t)params[4] << 8);
            conn->latency  = params[5] | ((uint16_t)params[6] << 8);
            conn->timeout  = params[7] | ((uint16_t)params[8] << 8);
        }
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    case DLI_OP_READ_AVAIL_CHAN: {
        /* no params → CmdComplete with [num_chan:1] [chan_map:10] */
        uint8_t rp[11];
        memset(rp, 0, sizeof(rp));
        rp[0] = 79; /* 79 channels available */
        memset(&rp[1], 0xFF, 10); /* all channels marked available */
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 11);
        break;
    }

    case DLI_OP_SET_TX_POWER: {
        /* params: [handle:2] [tx_power:1 signed] → CmdComplete */
        if (plen < 3) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_complete(s, opcode, 0x02, NULL, 0);
            break;
        }
        conn->tx_power = (int8_t)params[2];
        uint8_t rp[3];
        rp[0] = handle & 0xFF;
        rp[1] = (handle >> 8) & 0xFF;
        rp[2] = params[2]; /* echo back actual power */
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 3);
        break;
    }

    case DLI_OP_READ_TX_POWER: {
        /* params: [handle:2] → CmdComplete with tx_power */
        if (plen < 2) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_complete(s, opcode, 0x02, NULL, 0);
            break;
        }
        uint8_t rp[4];
        rp[0] = handle & 0xFF;
        rp[1] = (handle >> 8) & 0xFF;
        rp[2] = 0x00; /* status */
        rp[3] = (uint8_t)conn->tx_power;
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 4);
        break;
    }

    case DLI_OP_READ_PEER_TX_POWER: {
        /* params: [handle:2] → CmdStatus + ReadPeerPower event */
        if (plen < 2) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        /* Generate ReadPeerPower event (0x001B) */
        uint8_t ev[16];
        ev[0]  = DLI_EVT_READ_PEER_POWER & 0xFF;
        ev[1]  = (DLI_EVT_READ_PEER_POWER >> 8) & 0xFF;
        ev[2]  = 12;   /* param_len */
        ev[3]  = 0;
        ev[4]  = handle & 0xFF;
        ev[5]  = (handle >> 8) & 0xFF;
        ev[6]  = 0x00; /* status */
        ev[7]  = 0;    /* frame_type */
        ev[8]  = conn->bandwidth_mhz; /* bandwidth */
        ev[9]  = 0;    /* pilot_density */
        ev[10] = (uint8_t)conn->tx_power; /* tx_power (simulated peer) */
        ev[11] = 0x02; /* power_level: optimal */
        ev[12] = 0;    /* offset:4 bytes LE */
        ev[13] = 0;
        ev[14] = 0;
        ev[15] = 0;
        sle_dli_queue_event(s, ev, 16);
        break;
    }

    case DLI_OP_CONFIG_POWER_RPT: {
        /* params: [handle:2] [enable:1] → CmdComplete */
        if (plen < 3) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_complete(s, opcode, 0x02, NULL, 0);
            break;
        }
        conn->power_report = (params[2] != 0);
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    case DLI_OP_SET_CTRL_SIGNAL: {
        /* params: [handle:2] [signal_id:1] [data_len:1] [data:N]
         * Accept and return success */
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    case DLI_OP_ENABLE_RSSI_CTRL: {
        /* params: [handle:2] [enable:1] [rssi_threshold:1]
         * Accept and return success */
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    /* ----------------------------------------------------------------
     * Security commands (§8.6)
     * ---------------------------------------------------------------- */

    case DLI_OP_HASH_COMPUTE: {
        /* params: [key:16] [plaintext:16] [algo:1] → CmdComplete with hash */
        if (plen < 33) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        /* Simulated hash: XOR key with plaintext (not cryptographic!) */
        uint8_t rp[17];
        rp[0] = 0x00; /* status */
        for (int i = 0; i < 16; i++) {
            rp[1 + i] = params[i] ^ params[16 + i];
        }
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 17);
        break;
    }

    case DLI_OP_GEN_SECURE_RANDOM: {
        /* no params → CmdComplete with 16-byte random */
        uint8_t rp[17];
        rp[0] = 0x00; /* status */
        /* Deterministic "random" for reproducible test results */
        for (int i = 0; i < 16; i++) {
            rp[1 + i] = (uint8_t)(0x42 + i * 7 + s->mac_addr[5]);
        }
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 17);
        break;
    }

    case DLI_OP_START_ENCRYPT: {
        /* Standard: [handle:2][key:16][algo:1][kdf:1][integrity:1]
         * Driver sends: no params (handle inferred from first active conn)
         * Accept both. */
        uint16_t handle;
        SleDliConn *conn = NULL;
        if (plen >= 2) {
            handle = params[0] | ((uint16_t)params[1] << 8);
            conn = sle_dli_find_conn(s, handle);
        } else {
            /* Find first active connection */
            for (int i = 0; i < MAX_CONNECTIONS; i++) {
                if (s->connections[i].active) {
                    conn = &s->connections[i];
                    handle = conn->handle;
                    break;
                }
            }
        }
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        conn->encrypted = true;
        /* Queue EncStatusChange event (0x0011): [handle:2][enabled:1] */
        {
            uint8_t buf[7];
            buf[0] = DLI_EVT_ENC_CHANGED & 0xFF;
            buf[1] = (DLI_EVT_ENC_CHANGED >> 8) & 0xFF;
            buf[2] = 3;
            buf[3] = 0;
            buf[4] = handle & 0xFF;
            buf[5] = (handle >> 8) & 0xFF;
            buf[6] = 1; /* enabled */
            sle_dli_queue_event(s, buf, 7);
        }
        break;
    }

    case DLI_OP_REQUEST_PAIR: {
        /* T-node host requests pairing (§8.6.4).
         * Standard params: [handle:2][auth_req:1]
         * Legacy params:   [method:1]
         * Controller ACKs, then simulates G-node response by queuing
         * PairInfoExchange event (0x001E) back to T-node host. */
        sle_dli_cmd_status(s, opcode, 0x00);

        /* Find the connection (use handle from params or first active) */
        uint16_t handle = 0;
        uint8_t auth_req = 0;
        SleDliConn *conn = NULL;
        if (plen >= 3) {
            /* Standard format: [handle:2][auth_req:1] */
            handle = params[0] | ((uint16_t)params[1] << 8);
            auth_req = params[2];
            conn = sle_dli_find_conn(s, handle);
        } else {
            /* Legacy: [method:1] or no params — use first active conn */
            for (int i = 0; i < MAX_CONNECTIONS; i++) {
                if (s->connections[i].active) {
                    conn = &s->connections[i];
                    handle = conn->handle;
                    break;
                }
            }
        }

        if (conn) {
            conn->pair_state = PAIR_REQUESTED;
            conn->pair_auth_req = auth_req;

            /* Simulate G-node response: send PairInfoExchange event
             * (0x001E) to T-node host with G-node's capabilities.
             * Format: [handle:2][io_cap:1][oob:1][auth_req:1]
             *         [max_key:1][sec_dist:1][crypto_cap:4][psk:1] */
            uint8_t buf[4 + 12];
            buf[0] = DLI_EVT_PAIR_INFO_EXCH & 0xFF;
            buf[1] = (DLI_EVT_PAIR_INFO_EXCH >> 8) & 0xFF;
            buf[2] = 12;  /* param length */
            buf[3] = 0;
            /* handle */
            buf[4] = handle & 0xFF;
            buf[5] = (handle >> 8) & 0xFF;
            /* G-node I/O capability: 0x01 = Display+YesNo */
            buf[6] = 0x01;
            /* OOB data flag: 0x00 = no OOB */
            buf[7] = 0x00;
            /* Auth request: mirror T-node's request */
            buf[8] = auth_req;
            /* Max encryption key length: 16 */
            buf[9] = 16;
            /* Security info distribution: 0x03 = IRK+identity */
            buf[10] = 0x03;
            /* Crypto algorithm capability: AC1+AC2 enc, AC1+AC2 int,
             * HA1 KDF, KE2(ECDH P256) key exchange */
            buf[11] = 0x03; /* enc: AC1|AC2 */
            buf[12] = 0x03; /* int: AC1|AC2 */
            buf[13] = 0x01; /* kdf: HA1 */
            buf[14] = 0x02; /* kex: KE2 */
            /* PSK indicator: 0x00 = no PSK */
            buf[15] = 0x00;
            sle_dli_queue_event(s, buf, 16);
        }
        break;
    }

    case DLI_OP_REPLY_ENC_PARAM: {
        /* params: [handle:2][key:16][algo:1][kdf:1] → CmdComplete */
        if (plen < 2) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        uint8_t rp[3];
        rp[0] = handle & 0xFF;
        rp[1] = (handle >> 8) & 0xFF;
        rp[2] = 0x00;
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 3);
        break;
    }

    case DLI_OP_REJECT_ENC_PARAM: {
        /* params: [handle:2] → CmdComplete */
        if (plen < 2) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        uint8_t rp[3];
        rp[0] = handle & 0xFF;
        rp[1] = (handle >> 8) & 0xFF;
        rp[2] = 0x00;
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 3);
        break;
    }

    case DLI_OP_READ_ENC_ALGO: {
        /* no params → CmdComplete with algo_bitmap(4) */
        uint8_t rp[5];
        rp[0] = 0x00; /* status */
        /* Support AC1(SM4-CCM) + AC2(AES-CCM) = bits 0,1 */
        rp[1] = 0x03;
        rp[2] = 0x00;
        rp[3] = 0x00;
        rp[4] = 0x00;
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 5);
        break;
    }

    case DLI_OP_START_PAIRING: {
        /* G-node: start pairing with its capabilities (§8.6.8).
         * params: [handle:2][io_cap:1][oob:1][auth:1][max_key:1]
         *         [sec_dist:1][crypto:4][psk:1] → CmdStatus
         * Just ACK — the pairing sequence is driven by the
         * REQUEST_PAIR → INFO_EXCH → OPT → random/confirm/DHKey flow. */
        if (plen < 3) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        break;
    }

    /* ----------------------------------------------------------------
     * Pairing exchange commands (§8.6.9–§8.6.17)
     *
     * The QEMU controller acts as a simulated G-node, automatically
     * driving the pairing sequence back to the T-node host:
     *
     *   Host 0x1C04 (RequestPair) → Controller sends evt 0x001E
     *   Host 0x1C09 (InfoExchReply) → Controller sends evt 0x0020 + pubkey
     *   Host 0x1C0B (OptAccept+pubkey) → Controller sends evt 0x0024 (random)
     *   Host 0x1C0E (Random) → Controller sends evt 0x0025 (confirm)
     *   Host 0x1C0F (Confirm) → Controller sends evt 0x0026 (DHKey)
     *   Host 0x1C10 (DHKeyVerify) → pair_state = COMPLETE
     * ---------------------------------------------------------------- */

    case DLI_OP_PAIR_INFO_EXCH_RPL: {
        /* T-node host replies with its I/O capabilities (§8.6.9).
         * params: [handle:2][io_cap:1][oob:1][auth_req:1][max_key:1]
         *         [sec_dist:1][cipher_cap:4][psk:1]
         * Controller (as G-node) decides pairing method and sends
         * PairOptionReport (0x0020) with chosen method + simulated pubkey. */
        if (plen < 3) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);

        conn->pair_state = PAIR_INFO_EXCHANGED;

        /* Decide pairing method based on capabilities:
         * Default: JustWorks (0x01). If MITM requested, use
         * NumericComparison (0x00). If PSK available, use PSK (0x05). */
        uint8_t auth_req = (plen >= 5) ? params[4] : 0;
        uint8_t psk_ind = (plen >= 12) ? params[11] : 0;
        uint8_t method = 0x01; /* JustWorks */
        if (psk_ind != 0) {
            method = 0x05; /* PSK */
        } else if (auth_req & 0x04) {
            method = 0x00; /* NumericComparison (MITM required) */
        }
        conn->pair_method = method;

        /* Generate simulated G-node public key (deterministic for test) */
        for (int i = 0; i < 32; i++) {
            conn->local_pubkey[i] = (uint8_t)((handle * 7 + i * 13 + 0xA5) & 0xFF);
        }

        /* Send PairOptionReport (0x0020) to T-node host:
         * [handle:2][key_len:1][auth_method:1][crypto_alg:4][pubkey:32] */
        uint8_t buf[4 + 40];
        buf[0] = DLI_EVT_PAIR_OPT_REPORT & 0xFF;
        buf[1] = (DLI_EVT_PAIR_OPT_REPORT >> 8) & 0xFF;
        buf[2] = 40; /* param len */
        buf[3] = 0;
        buf[4] = handle & 0xFF;
        buf[5] = (handle >> 8) & 0xFF;
        buf[6] = 16;     /* key length */
        buf[7] = method;  /* auth method */
        /* Selected algorithms: AC1 enc, AC1 int, HA1 kdf, KE2 kex */
        buf[8] = 0x00;
        buf[9] = 0x00;
        buf[10] = 0x00;
        buf[11] = 0x01;
        /* G-node's public key */
        memcpy(&buf[12], conn->local_pubkey, 32);
        sle_dli_queue_event(s, buf, 44);

        conn->pair_state = PAIR_OPTION_DECIDED;
        break;
    }

    case DLI_OP_PAIR_OPT_CONFIRM: {
        /* G-node side command — not used in T-node flow.
         * Just ACK it. */
        if (plen < 4) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        break;
    }

    case DLI_OP_PAIR_OPT_ACCEPT: {
        /* T-node accepts pairing option and provides its public key (§8.6.11).
         * params: [handle:2][pubkey:32]
         * Controller stores T-node's pubkey, then sends back a simulated
         * G-node random nonce via PairRandom event (0x0024). */
        if (plen < 2) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);

        /* Store T-node public key */
        if (plen >= 34) {
            memcpy(conn->peer_pubkey, &params[2], 32);
        }
        conn->pair_state = PAIR_PUBKEY_EXCHANGED;

        /* Generate simulated G-node random nonce (deterministic) */
        for (int i = 0; i < 16; i++) {
            conn->local_random[i] = (uint8_t)((handle * 11 + i * 17 + 0x3C) & 0xFF);
        }

        /* Send PairRandom event (0x0024): [handle:2][random:16] */
        {
            uint8_t buf[4 + 18];
            buf[0] = DLI_EVT_PAIR_RANDOM & 0xFF;
            buf[1] = (DLI_EVT_PAIR_RANDOM >> 8) & 0xFF;
            buf[2] = 18;
            buf[3] = 0;
            buf[4] = handle & 0xFF;
            buf[5] = (handle >> 8) & 0xFF;
            memcpy(&buf[6], conn->local_random, 16);
            sle_dli_queue_event(s, buf, 22);
        }
        break;
    }

    case DLI_OP_PAIR_EXT_DATA: {
        /* SM2-2 extended public key data (§8.6.12). ACK only. */
        if (plen < 2) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        break;
    }

    case DLI_OP_PAIR_PASSKEY_KEY: {
        /* Passkey digit action (§8.6.13). ACK only. */
        if (plen < 3) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        break;
    }

    case DLI_OP_PAIR_RANDOM: {
        /* T-node sends its random nonce (§8.6.14).
         * params: [handle:2][random:16]
         * Controller stores it, then responds with simulated G-node
         * confirm value via PairConfirm event (0x0025). */
        if (plen < 18) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);

        /* Store T-node's random */
        memcpy(conn->peer_random, &params[2], 16);
        conn->pair_state = PAIR_RANDOM_SENT;

        /* Generate simulated G-node confirm value (deterministic).
         * In real hardware this would be:
         * Confirm = f4(PKb, PKa, Nb, 0) using the negotiated KDF. */
        for (int i = 0; i < 16; i++) {
            conn->local_confirm[i] = conn->local_random[i] ^
                                     conn->local_pubkey[i] ^ 0x55;
        }

        /* Send PairConfirm event (0x0025): [handle:2][confirm:16] */
        {
            uint8_t buf[4 + 18];
            buf[0] = DLI_EVT_PAIR_CONFIRM & 0xFF;
            buf[1] = (DLI_EVT_PAIR_CONFIRM >> 8) & 0xFF;
            buf[2] = 18;
            buf[3] = 0;
            buf[4] = handle & 0xFF;
            buf[5] = (handle >> 8) & 0xFF;
            memcpy(&buf[6], conn->local_confirm, 16);
            sle_dli_queue_event(s, buf, 22);
        }
        break;
    }

    case DLI_OP_PAIR_CONFIRM: {
        /* T-node sends its confirm value (§8.6.15).
         * params: [handle:2][confirm:16]
         * Controller stores it, then responds with simulated G-node
         * DHKey verify via DHKeyVerify event (0x0026). */
        if (plen < 18) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);

        /* Store T-node's confirm */
        memcpy(conn->peer_confirm, &params[2], 16);
        conn->pair_state = PAIR_CONFIRM_SENT;

        /* Generate simulated G-node DHKey check (deterministic).
         * In real hardware: f6(W, N1, N2, r, IOcap, A1, A2). */
        for (int i = 0; i < 16; i++) {
            conn->dhkey_check[i] = conn->local_random[i] ^
                                   conn->peer_random[i] ^ 0xAA;
        }

        /* Send DHKeyVerify event (0x0026): [handle:2][dhkey_check:16] */
        {
            uint8_t buf[4 + 18];
            buf[0] = DLI_EVT_DHKEY_VERIFY & 0xFF;
            buf[1] = (DLI_EVT_DHKEY_VERIFY >> 8) & 0xFF;
            buf[2] = 18;
            buf[3] = 0;
            buf[4] = handle & 0xFF;
            buf[5] = (handle >> 8) & 0xFF;
            memcpy(&buf[6], conn->dhkey_check, 16);
            sle_dli_queue_event(s, buf, 22);
        }
        break;
    }

    case DLI_OP_DHKEY_VERIFY: {
        /* T-node sends DHKey verification (§8.6.16).
         * params: [handle:2][dhkey_check:16]
         * Controller verifies (always accepts in simulation) and
         * marks pairing as complete. Sends EncryptionChanged event
         * to confirm link encryption is enabled. */
        if (plen < 18) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);

        conn->pair_state = PAIR_COMPLETE;

        /* Derive simulated link key from exchanged material */
        for (int i = 0; i < 16; i++) {
            conn->link_key[i] = conn->local_random[i] ^
                                conn->peer_random[i] ^
                                conn->local_pubkey[i] ^ 0xCC;
        }
        break;
    }

    case DLI_OP_PAIR_FAIL: {
        /* Pairing failure notification (§8.6.17).
         * params: [handle:2][reason:1]
         * Reset pairing state on the connection. */
        if (plen < 3) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        SleDliConn *conn = sle_dli_find_conn(s, handle);
        if (!conn) {
            sle_dli_cmd_status(s, opcode, 0x02);
            break;
        }
        sle_dli_cmd_status(s, opcode, 0x00);
        conn->pair_state = PAIR_IDLE;
        break;
    }

    /* ----------------------------------------------------------------
     * RAL management commands (§8.6.18–§8.6.25)
     * ---------------------------------------------------------------- */

    case DLI_OP_RAL_ADD: {
        /* params: [resolve_algo:1][peer_id_type:1][peer_id:6]
         *         [peer_irkid:1][local_irkid:1][peer_irk:16][local_irk:16]
         * → CmdComplete */
        if (plen < 42) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        if (s->ral_count >= MAX_RAL_ENTRIES) {
            sle_dli_cmd_complete(s, opcode, 0x07, NULL, 0); /* memory full */
            break;
        }
        /* Check for duplicate */
        for (int i = 0; i < MAX_RAL_ENTRIES; i++) {
            if (s->ral[i].used &&
                s->ral[i].peer_id_type == params[1] &&
                memcmp(s->ral[i].peer_id, &params[2], 6) == 0) {
                sle_dli_cmd_complete(s, opcode, 0x11, NULL, 0); /* exists */
                goto done;
            }
        }
        /* Find empty slot */
        for (int i = 0; i < MAX_RAL_ENTRIES; i++) {
            if (!s->ral[i].used) {
                s->ral[i].used = true;
                s->ral[i].resolve_algo = params[0];
                s->ral[i].peer_id_type = params[1];
                memcpy(s->ral[i].peer_id, &params[2], 6);
                s->ral[i].peer_irkid = params[8];
                s->ral[i].local_irkid = params[9];
                memcpy(s->ral[i].peer_irk, &params[10], 16);
                memcpy(s->ral[i].local_irk, &params[26], 16);
                s->ral_count++;
                break;
            }
        }
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
    done:
        break;
    }

    case DLI_OP_RAL_REMOVE: {
        /* params: [peer_id_type:1][peer_id:6] → CmdComplete */
        if (plen < 7) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        bool found = false;
        for (int i = 0; i < MAX_RAL_ENTRIES; i++) {
            if (s->ral[i].used &&
                s->ral[i].peer_id_type == params[0] &&
                memcmp(s->ral[i].peer_id, &params[1], 6) == 0) {
                memset(&s->ral[i], 0, sizeof(s->ral[i]));
                s->ral_count--;
                found = true;
                break;
            }
        }
        sle_dli_cmd_complete(s, opcode, found ? 0x00 : 0x02, NULL, 0);
        break;
    }

    case DLI_OP_RAL_CLEAR: {
        /* no params → CmdComplete */
        memset(s->ral, 0, sizeof(s->ral));
        s->ral_count = 0;
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    case DLI_OP_RAL_READ_SIZE: {
        /* no params → CmdComplete with [size:1] */
        uint8_t rp[1];
        rp[0] = (uint8_t)s->ral_count;
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 1);
        break;
    }

    case DLI_OP_RAL_READ_PEER_RPA: {
        /* params: [peer_id_type:1][peer_id:6] → CmdComplete with [rpa:6] */
        if (plen < 7) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        /* Find the RAL entry and generate a simulated RPA */
        uint8_t rpa[6] = {0};
        uint8_t status = 0x02; /* not found */
        for (int i = 0; i < MAX_RAL_ENTRIES; i++) {
            if (s->ral[i].used &&
                s->ral[i].peer_id_type == params[0] &&
                memcmp(s->ral[i].peer_id, &params[1], 6) == 0) {
                /* Generate deterministic RPA from peer_irk */
                for (int j = 0; j < 6; j++)
                    rpa[j] = s->ral[i].peer_irk[j] ^ s->ral[i].peer_id[j];
                rpa[3] = (rpa[3] & 0x3F) | 0x40; /* resolvable marker */
                status = 0x00;
                break;
            }
        }
        sle_dli_cmd_complete(s, opcode, status, rpa, 6);
        break;
    }

    case DLI_OP_RAL_READ_LOCAL_RPA: {
        /* params: [local_id_type:1][local_id:6] → CmdComplete with [rpa:6] */
        if (plen < 7) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        uint8_t rpa[6] = {0};
        uint8_t status = 0x02; /* not found */
        for (int i = 0; i < MAX_RAL_ENTRIES; i++) {
            if (s->ral[i].used &&
                s->ral[i].peer_id_type == params[0] &&
                memcmp(s->ral[i].peer_id, &params[1], 6) == 0) {
                /* Generate deterministic RPA from local_irk */
                for (int j = 0; j < 6; j++)
                    rpa[j] = s->ral[i].local_irk[j] ^ s->ral[i].peer_id[j];
                rpa[3] = (rpa[3] & 0x3F) | 0x40; /* resolvable marker */
                status = 0x00;
                break;
            }
        }
        sle_dli_cmd_complete(s, opcode, status, rpa, 6);
        break;
    }

    case DLI_OP_RPA_SET_ENABLE: {
        /* params: [enable:1] → CmdComplete */
        if (plen < 1) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        s->rpa_enabled = (params[0] != 0);
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    case DLI_OP_RPA_SET_TIMEOUT: {
        /* params: [timeout:2] → CmdComplete */
        if (plen < 2) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        s->rpa_timeout = params[0] | ((uint16_t)params[1] << 8);
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    /* ----------------------------------------------------------------
     * SLB security commands (§8.6.26–§8.6.31)
     * ---------------------------------------------------------------- */

    case DLI_OP_SLB_CFG_AUTH_PSK: {
        /* params: [remote_id:6][psk_len:1][psk:N] → CmdComplete */
        if (plen < 7) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        /* Accept and ACK (simulation only stores nothing) */
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    case DLI_OP_SLB_DEL_AUTH_PSK: {
        /* params: [remote_id:6] → CmdComplete */
        if (plen < 6) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    case DLI_OP_SLB_CFG_AUTH_PWD: {
        /* params: [remote_id:6][pwd_len:1][pwd:N] → CmdComplete */
        if (plen < 7) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    case DLI_OP_SLB_DEL_AUTH_PWD: {
        /* params: [remote_id:6] → CmdComplete */
        if (plen < 6) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    case DLI_OP_SLB_CFG_CIPHER: {
        /* params: [algo_type:1][comm_type:1][priority:8] → CmdComplete */
        if (plen < 10) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        s->slb_cipher_algo_type = params[0];
        s->slb_cipher_comm_type = params[1];
        memcpy(s->slb_cipher_priority, &params[2], 8);
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;
    }

    case DLI_OP_SLB_READ_CIPHER: {
        /* params: [algo_type:1][comm_type:1]
         * → CmdComplete with [algo_type:1][comm_type:1][priority:8] */
        if (plen < 2) {
            sle_dli_cmd_complete(s, opcode, 0x12, NULL, 0);
            break;
        }
        uint8_t rp[10];
        rp[0] = s->slb_cipher_algo_type;
        rp[1] = s->slb_cipher_comm_type;
        memcpy(&rp[2], s->slb_cipher_priority, 8);
        sle_dli_cmd_complete(s, opcode, 0x00, rp, 10);
        break;
    }

    default:
        /* Unknown command — return error */
        qemu_log_mask(LOG_GUEST_ERROR,
                      "usb-sle-dli: unknown opcode 0x%04x\n", opcode);
        sle_dli_cmd_complete(s, opcode, 0x01, NULL, 0);
        break;
    }
}

/* Parse a received DLI command from bulk OUT */
static void sle_dli_handle_bulk_out_command(USBSleDliState *s,
                                            const uint8_t *data, int len)
{
    if (len < 4) {
        return;
    }
    if (data[0] != DLI_PKT_COMMAND) {
        /* Check for async data — relay to connected peer */
        if (data[0] == DLI_PKT_ASYNC_DATA && len >= 5) {
            /*
             * Async data format (DLI wire):
             *   [0]    = 0xA3 (DLI_PKT_ASYNC_DATA)
             *   [1..2] = link_id_segment (LE16): (handle & 0xFFF) << 4
             *   [3..4] = payload length (LE16, 9 bits)
             *   [5..N] = payload
             */
            uint16_t link_id_seg = data[1] | ((uint16_t)data[2] << 8);
            uint16_t handle = (link_id_seg >> 4) & 0x0FFF;
            for (int i = 0; i < MAX_CONNECTIONS; i++) {
                if (s->connections[i].active &&
                    s->connections[i].handle == handle) {
                    sle_air_relay_data(s, i, data, len);
                    break;
                }
            }
            return;
        }
        /* Check for firmware data chunk */
        if (data[0] == DLI_PKT_MCAST_DATA && s->fw_downloading) {
            /* FW chunk: [0]=0xA5 [1..4]=offset [5..6]=chunk_len [7..N]=data */
            if (len >= 7) {
                uint16_t chunk_len = data[5] | ((uint16_t)data[6] << 8);
                s->fw_received += chunk_len;
            }
            return;
        }
        return;
    }
    uint16_t opcode = data[1] | ((uint16_t)data[2] << 8);
    uint16_t param_len = data[3] | ((uint16_t)data[4] << 8);
    const uint8_t *params = (len > 5) ? &data[5] : NULL;
    int actual_plen = MIN(param_len, len - 5);

    sle_dli_process_command(s, opcode, params, actual_plen);
}

/* --------------------------------------------------------------------
 * USBDevice callbacks
 * -------------------------------------------------------------------- */

static uint8_t sle_dli_instance_counter;

static void usb_sle_dli_realize(USBDevice *dev, Error **errp)
{
    USBSleDliState *s = USB_SLE_DLI(dev);

    usb_desc_create_serial(dev);
    usb_desc_init(dev);

    /* Default controller state — each instance gets a unique MAC */
    if (s->mac_addr[0] == 0 && s->mac_addr[1] == 0 &&
        s->mac_addr[2] == 0 && s->mac_addr[3] == 0 &&
        s->mac_addr[4] == 0 && s->mac_addr[5] == 0) {
        uint8_t id = ++sle_dli_instance_counter;
        s->mac_addr[0] = 0xDE;
        s->mac_addr[1] = 0xAD;
        s->mac_addr[2] = 0xBE;
        s->mac_addr[3] = 0xEF;
        s->mac_addr[4] = 0x00;
        s->mac_addr[5] = id;
    }
    if (s->fw_version == 0) {
        s->fw_version = 0x01020300; /* 1.2.3.0 */
    }
    s->protocol_version = 0x02; /* Release 2 */
    s->company_id = 0x0001;
    s->sub_version = 0x0100;
    s->next_handle = 0x0001;

    /* Add one default peer for discovery testing */
    s->peers[0].active = true;
    s->peers[0].addr[0] = 0xAA;
    s->peers[0].addr[1] = 0xBB;
    s->peers[0].addr[2] = 0xCC;
    s->peers[0].addr[3] = 0xDD;
    s->peers[0].addr[4] = 0x00;
    s->peers[0].addr[5] = 0x01;
    s->peers[0].rssi = -45;
    memcpy(s->peers[0].name, "SLE-Peer-1", 10);
    s->peers[0].name_len = 10;
    s->peers[0].discovery_level = 2;

    /* Initialize connection remote links */
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        s->connections[i].remote_dev = NULL;
        s->connections[i].remote_slot = -1;
    }

    /* Cache interrupt endpoint for wakeup signaling */
    s->intr = usb_ep_get(dev, USB_TOKEN_IN, 1);

    /* Create deferred wakeup timer for cross-device event delivery */
    s->deferred_wakeup = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                      sle_dli_deferred_wakeup_cb, s);

    /* Register on the virtual air medium */
    sle_air_register(s);
}

static void usb_sle_dli_handle_reset(USBDevice *dev)
{
    USBSleDliState *s = USB_SLE_DLI(dev);

    /* Unregister from air medium before resetting state */
    sle_air_unregister(s);

    /* Cancel any pending deferred wakeup */
    if (s->deferred_wakeup) {
        timer_del(s->deferred_wakeup);
    }

    s->evt_head = s->evt_tail = s->evt_count = 0;
    s->data_head = s->data_tail = s->data_count = 0;
    s->broadcasting = false;
    s->scanning = false;
    s->suspended = false;

    /* Clear connection remote links */
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        s->connections[i].active = false;
        s->connections[i].remote_dev = NULL;
        s->connections[i].remote_slot = -1;
    }

    /* Re-register on air medium */
    sle_air_register(s);
}

static void usb_sle_dli_handle_control(USBDevice *dev, USBPacket *p,
                                       int request, int value,
                                       int index, int length,
                                       uint8_t *data)
{
    USBSleDliState *s = USB_SLE_DLI(dev);
    int ret;

    ret = usb_desc_handle_control(dev, p, request, value, index,
                                  length, data);
    if (ret >= 0) {
        return;
    }

    /*
     * EP0 control path for DLI commands (standards path).
     * T/XS 10003-2025 §6.2.2:
     *   0x20 = single-function device (target: device)
     *   0x21 = multi-function device (target: interface)
     */
    if ((request >> 8) == 0x20 || (request >> 8) == 0x21) {
        /* data contains a DLI command payload */
        if (length >= 4) {
            uint16_t opcode = data[0] | ((uint16_t)data[1] << 8);
            uint16_t param_len = data[2] | ((uint16_t)data[3] << 8);
            const uint8_t *params = (length > 4) ? &data[4] : NULL;
            int actual_plen = MIN(param_len, length - 4);
            sle_dli_process_command(s, opcode, params, actual_plen);
            p->status = USB_RET_SUCCESS;
        } else {
            p->status = USB_RET_STALL;
        }
        return;
    }

    p->status = USB_RET_STALL;
}

static void usb_sle_dli_handle_data(USBDevice *dev, USBPacket *p)
{
    USBSleDliState *s = USB_SLE_DLI(dev);
    uint8_t buf[MAX_DATA_SIZE];
    int len;

    switch (p->pid) {
    case USB_TOKEN_IN:
        if (p->ep->nr == 1) {
            /* Interrupt IN (0x81) — deliver events */
            len = sle_dli_dequeue_event(s, buf, sizeof(buf));
            if (len > 0) {
                if (len > (int)p->iov.size) {
                    len = (int)p->iov.size;
                }
                usb_packet_copy(p, buf, len);
                /* If more events pending, schedule a wakeup to drain them
                 * promptly instead of waiting for the next interval poll. */
                if (s->evt_count > 0 && s->intr) {
                    sle_dli_schedule_wakeup(s);
                }
            } else {
                p->status = USB_RET_NAK;
            }
        } else if (p->ep->nr == 2) {
            /* Bulk IN (0x82) — deliver compat command responses or data */
            /* In dual/bulk-compat mode, events are also available here */
            len = sle_dli_dequeue_event(s, buf, sizeof(buf));
            if (len > 0) {
                usb_packet_copy(p, buf, len);
            } else {
                len = sle_dli_dequeue_data(s, buf, sizeof(buf));
                if (len > 0) {
                    usb_packet_copy(p, buf, len);
                } else {
                    p->status = USB_RET_NAK;
                }
            }
        } else {
            p->status = USB_RET_STALL;
        }
        break;

    case USB_TOKEN_OUT:
        if (p->ep->nr == 2) {
            /* Bulk OUT (0x02) — receive commands and data */
            len = MIN(p->iov.size, sizeof(buf));
            usb_packet_copy(p, buf, len);
            sle_dli_handle_bulk_out_command(s, buf, len);
            /* Wake INT endpoint so host polls queued events */
            if (s->evt_count > 0 && s->intr) {
                usb_wakeup(s->intr, 0);
            }
        } else {
            p->status = USB_RET_STALL;
        }
        break;

    default:
        p->status = USB_RET_STALL;
        break;
    }
}

/* --------------------------------------------------------------------
 * Properties and registration
 * -------------------------------------------------------------------- */

static Property usb_sle_dli_properties[] = {
    DEFINE_PROP_STRING("cmd-path", USBSleDliState, cmd_path),
    DEFINE_PROP_STRING("fw-mode", USBSleDliState, fw_mode),
    DEFINE_PROP_END_OF_LIST(),
};

static void usb_sle_dli_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    USBDeviceClass *uc = USB_DEVICE_CLASS(klass);

    uc->realize        = usb_sle_dli_realize;
    uc->product_desc   = "SparkLink SLE DLI Controller (QEMU)";
    uc->usb_desc       = &desc_sle_dli;
    uc->handle_reset   = usb_sle_dli_handle_reset;
    uc->handle_control = usb_sle_dli_handle_control;
    uc->handle_data    = usb_sle_dli_handle_data;

    dc->desc = "SparkLink SLE DLI USB controller for testing";
    device_class_set_props(dc, usb_sle_dli_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo usb_sle_dli_type_info = {
    .name          = TYPE_USB_SLE_DLI,
    .parent        = TYPE_USB_DEVICE,
    .instance_size = sizeof(USBSleDliState),
    .class_init    = usb_sle_dli_class_init,
};

static void usb_sle_dli_register_types(void)
{
    type_register_static(&usb_sle_dli_type_info);
}

type_init(usb_sle_dli_register_types);
