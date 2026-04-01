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
#define DLI_OP_DISABLE_BROADCAST  0x0C06
#define DLI_OP_ENABLE_SCAN        0x1002
#define DLI_OP_DISABLE_SCAN       0x1003
#define DLI_OP_CREATE_CONN        0x1401
#define DLI_OP_DISCONNECT         0x1403
#define DLI_OP_FW_DL_START        0xF810
#define DLI_OP_FW_DL_DONE         0xF811

/* DLI event codes */
#define DLI_EVT_CMD_STATUS        0x0001
#define DLI_EVT_CMD_COMPLETE      0x0002
#define DLI_EVT_DISCONNECTED      0x0005
#define DLI_EVT_HW_ERROR          0x000A
#define DLI_EVT_ENC_CHANGED       0x0011
#define DLI_EVT_CONN_ESTABLISHED  0x0015
#define DLI_EVT_BROADCAST_REPORT  0x001A
#define DLI_EVT_PAIR_REQUEST      0x001D

/* Controller limits */
#define MAX_CONNECTIONS   8
#define MAX_EVENT_QUEUE   64
#define MAX_DATA_QUEUE    16
#define MAX_EVENT_SIZE    64
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

/* Per-connection state in the controller */
typedef struct SleDliConn {
    bool     active;
    uint16_t handle;
    uint8_t  peer_addr[6];
    /* Link to the remote device's connection slot for data relay */
    struct USBSleDliState *remote_dev;
    int      remote_slot;
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

    /* Connections */
    SleDliConn connections[MAX_CONNECTIONS];
    uint16_t   next_handle;

    /* Simulated peers */
    SleDliPeer peers[MAX_PEERS];

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

    return true;
}

/* Relay data from one connected device to its peer */
static void sle_air_relay_data(USBSleDliState *sender,
                               int conn_slot,
                               const uint8_t *data, int len)
{
    SleDliConn *conn = &sender->connections[conn_slot];
    if (!conn->active || !conn->remote_dev) {
        return;
    }

    USBSleDliState *receiver = conn->remote_dev;
    /* Queue the data as an async data packet on the receiver */
    sle_dli_queue_data(receiver, data, len);
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
            .bEndpointAddress = USB_DIR_IN | 0x01,  /* 0x81: interrupt IN (events) */
            .bmAttributes     = USB_ENDPOINT_XFER_INT,
            .wMaxPacketSize   = 16,
            .bInterval        = 4,
        },
        {
            .bEndpointAddress = USB_DIR_IN | 0x02,  /* 0x82: bulk IN (data) */
            .bmAttributes     = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize   = 512,
        },
        {
            .bEndpointAddress = USB_DIR_OUT | 0x02, /* 0x02: bulk OUT (commands) */
            .bmAttributes     = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize   = 512,
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
 * Wire format:
 *   [0..1] event_code = 0x0002 (LE16)
 *   [2]    total_param_len
 *   [3..4] opcode (LE16)
 *   [5]    status
 *   [6..N] return params
 */
static void sle_dli_cmd_complete(USBSleDliState *s, uint16_t opcode,
                                 uint8_t status,
                                 const uint8_t *params, int plen)
{
    uint8_t buf[MAX_EVENT_SIZE];
    int total_plen = 3 + plen; /* opcode(2) + status(1) + return_params */

    buf[0] = DLI_EVT_CMD_COMPLETE & 0xFF;
    buf[1] = (DLI_EVT_CMD_COMPLETE >> 8) & 0xFF;
    buf[2] = (uint8_t)total_plen;
    buf[3] = opcode & 0xFF;
    buf[4] = (opcode >> 8) & 0xFF;
    buf[5] = status;
    if (plen > 0 && params) {
        memcpy(&buf[6], params, MIN(plen, MAX_EVENT_SIZE - 6));
    }
    sle_dli_queue_event(s, buf, 6 + plen);
}

/*
 * Build a CommandStatus event packet.
 *
 * Wire format:
 *   [0..1] event_code = 0x0001 (LE16)
 *   [2]    param_len = 3
 *   [3]    status
 *   [4..5] opcode (LE16)
 */
static void sle_dli_cmd_status(USBSleDliState *s, uint16_t opcode,
                               uint8_t status)
{
    uint8_t buf[6];
    buf[0] = DLI_EVT_CMD_STATUS & 0xFF;
    buf[1] = (DLI_EVT_CMD_STATUS >> 8) & 0xFF;
    buf[2] = 3;
    buf[3] = status;
    buf[4] = opcode & 0xFF;
    buf[5] = (opcode >> 8) & 0xFF;
    sle_dli_queue_event(s, buf, 6);
}

/*
 * Build a ConnectionEstablished event.
 *
 * Wire format:
 *   [0..1] event_code = 0x0015 (LE16)
 *   [2]    param_len = 9
 *   [3]    status
 *   [4..5] handle (LE16)
 *   [6..11] peer addr (6 bytes)
 */
static void sle_dli_conn_complete(USBSleDliState *s, uint8_t status,
                                  uint16_t handle,
                                  const uint8_t *addr)
{
    uint8_t buf[12];
    buf[0]  = DLI_EVT_CONN_ESTABLISHED & 0xFF;
    buf[1]  = (DLI_EVT_CONN_ESTABLISHED >> 8) & 0xFF;
    buf[2]  = 9;
    buf[3]  = status;
    buf[4]  = handle & 0xFF;
    buf[5]  = (handle >> 8) & 0xFF;
    memcpy(&buf[6], addr, 6);
    sle_dli_queue_event(s, buf, 12);
}

/*
 * Build a Disconnected event.
 *
 * Wire format:
 *   [0..1] event_code = 0x0005 (LE16)
 *   [2]    param_len = 3
 *   [3..4] handle (LE16)
 *   [5]    reason
 */
static void sle_dli_disconnected(USBSleDliState *s, uint16_t handle,
                                 uint8_t reason)
{
    uint8_t buf[6];
    buf[0] = DLI_EVT_DISCONNECTED & 0xFF;
    buf[1] = (DLI_EVT_DISCONNECTED >> 8) & 0xFF;
    buf[2] = 3;
    buf[3] = handle & 0xFF;
    buf[4] = (handle >> 8) & 0xFF;
    buf[5] = reason;
    sle_dli_queue_event(s, buf, 6);
}

/*
 * Build a BroadcastReport event.
 *
 * Wire format:
 *   [0..1] event_code = 0x001A (LE16)
 *   [2]    param_len
 *   [3..8] addr (6 bytes)
 *   [9]    rssi
 *   [10]   data_len
 *   [11..N] advertising data (TLV)
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
    buf[2]  = (uint8_t)plen;
    memcpy(&buf[3], peer->addr, 6);
    buf[9]  = (uint8_t)peer->rssi;
    buf[10] = (uint8_t)adv_len;
    memcpy(&buf[11], adv_data, adv_len);
    sle_dli_queue_event(s, buf, 11 + adv_len);
}

/*
 * Build a HardwareError event.
 */
static void sle_dli_hw_error(USBSleDliState *s, uint8_t code)
{
    uint8_t buf[4];
    buf[0] = DLI_EVT_HW_ERROR & 0xFF;
    buf[1] = (DLI_EVT_HW_ERROR >> 8) & 0xFF;
    buf[2] = 1;
    buf[3] = code;
    sle_dli_queue_event(s, buf, 4);
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
         * The guest parses this as a 4-byte fw_version at offset [6..9]
         * in the raw event response. Since the event is:
         *   [0..1] evt_code  [2] plen  [3..4] opcode
         *   [5] status  [6] version  [7..8] company_id  [9..10] sub_version
         * The guest reads le32 from offset 6, which spans
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

    case DLI_OP_ENABLE_BROADCAST:
        s->broadcasting = true;
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        /* Notify all scanning devices on the air medium */
        sle_air_broadcast_notify(s);
        break;

    case DLI_OP_DISABLE_BROADCAST:
        s->broadcasting = false;
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;

    case DLI_OP_ENABLE_SCAN:
        s->scanning = true;
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        /* Generate broadcast reports for built-in static peers */
        for (int i = 0; i < MAX_PEERS; i++) {
            if (s->peers[i].active) {
                sle_dli_broadcast_report(s, &s->peers[i]);
            }
        }
        /* Also discover broadcasting devices on the air medium */
        {
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

    case DLI_OP_DISABLE_SCAN:
        s->scanning = false;
        sle_dli_cmd_complete(s, opcode, 0x00, NULL, 0);
        break;

    case DLI_OP_CREATE_CONN: {
        /* params: [addr_type:1] [addr:6] ... */
        if (plen < 7) {
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
        memcpy(s->connections[slot].peer_addr, &params[1], 6);
        s->connections[slot].remote_dev = NULL;
        s->connections[slot].remote_slot = -1;

        /* Try to create a bidirectional link via the air medium */
        sle_air_connect(s, &params[1], slot);

        /* Generate ConnEstablished event on this side */
        sle_dli_conn_complete(s, 0x00,
                              s->connections[slot].handle,
                              s->connections[slot].peer_addr);
        break;
    }

    case DLI_OP_DISCONNECT: {
        /* params: [handle:2] [reason:1] */
        if (plen < 3) {
            sle_dli_cmd_status(s, opcode, 0x12);
            break;
        }
        uint16_t handle = params[0] | ((uint16_t)params[1] << 8);
        uint8_t reason = params[2];
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
             * Async data format:
             *   [0]    = 0xA3 (DLI_PKT_ASYNC_DATA)
             *   [1..2] = handle (LE16)
             *   [3..4] = payload length (LE16)
             *   [5..N] = payload
             */
            uint16_t handle = data[1] | ((uint16_t)data[2] << 8);
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
    uint8_t param_len = data[3];
    const uint8_t *params = (len > 4) ? &data[4] : NULL;
    int actual_plen = MIN(param_len, len - 4);

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

    /* Register on the virtual air medium */
    sle_air_register(s);
}

static void usb_sle_dli_handle_reset(USBDevice *dev)
{
    USBSleDliState *s = USB_SLE_DLI(dev);

    /* Unregister from air medium before resetting state */
    sle_air_unregister(s);

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
     * Class-specific requests: bmRequestType = 0x21 (host-to-device, class,
     * interface), bRequest = 0x00 (DLI command).
     */
    if ((request >> 8) == 0x21) {
        /* data contains a DLI command payload */
        if (length >= 3) {
            uint16_t opcode = data[0] | ((uint16_t)data[1] << 8);
            uint8_t param_len = data[2];
            const uint8_t *params = (length > 3) ? &data[3] : NULL;
            sle_dli_process_command(s, opcode, params, param_len);
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
        if (p->ep->nr == 0x01) {
            /* Interrupt IN (0x81) — deliver events */
            len = sle_dli_dequeue_event(s, buf, sizeof(buf));
            if (len > 0) {
                usb_packet_copy(p, buf, len);
            } else {
                p->status = USB_RET_NAK;
            }
        } else if (p->ep->nr == 0x02) {
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
        if (p->ep->nr == 0x02) {
            /* Bulk OUT (0x02) — receive commands and data */
            len = MIN(p->iov.size, sizeof(buf));
            usb_packet_copy(p, buf, len);
            sle_dli_handle_bulk_out_command(s, buf, len);
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
