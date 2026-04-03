/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * SparkLink (NearLink) Generic Netlink protocol definitions.
 *
 * Family: "sparklink"
 * Version: 1
 *
 * This header defines the stable userspace ABI for the SparkLink
 * Generic Netlink interface. It parallels the ioctl interface on
 * /dev/sparklink and provides structured attribute-based messaging.
 *
 * Copyright (C) 2025 SparkLink for Linux Contributors
 */
#ifndef _UAPI_LINUX_SPARKLINK_H
#define _UAPI_LINUX_SPARKLINK_H

#include <linux/types.h>

/* Generic Netlink family name */
#define SPARKLINK_GENL_NAME		"sparklink"
#define SPARKLINK_GENL_VERSION		1

/* Multicast group for async event delivery */
#define SPARKLINK_MCGRP_EVENTS		"events"

/* ---------------------------------------------------------------------------
 * Generic Netlink commands
 * ---------------------------------------------------------------------------
 */

enum {
	/* Device management */
	SPARKLINK_CMD_UNSPEC,
	SPARKLINK_CMD_GET_DEV_INFO,	/* Get device information */
	SPARKLINK_CMD_DEV_REGISTER,	/* Register virtual device */
	SPARKLINK_CMD_DEV_UNREGISTER,	/* Unregister virtual device */

	/* Advertising / scanning */
	SPARKLINK_CMD_START_ADV,	/* Start advertising */
	SPARKLINK_CMD_STOP_ADV,		/* Stop advertising */
	SPARKLINK_CMD_START_SCAN,	/* Start scanning */
	SPARKLINK_CMD_STOP_SCAN,	/* Stop scanning */
	SPARKLINK_CMD_INJECT_ADV,	/* Inject advertising PDU (test) */

	/* Connection management */
	SPARKLINK_CMD_CONNECT,		/* Initiate connection */
	SPARKLINK_CMD_DISCONNECT,	/* Disconnect */
	SPARKLINK_CMD_GET_CONN_INFO,	/* Get connection info */
	SPARKLINK_CMD_CONN_SEND,	/* Send data */
	SPARKLINK_CMD_CONN_RECV,	/* Receive data */
	SPARKLINK_CMD_GET_CONN_LIST,	/* List active connections */

	/* Security */
	SPARKLINK_CMD_SET_PSK,		/* Set pre-shared key */
	SPARKLINK_CMD_PAIR,		/* Start pairing */
	SPARKLINK_CMD_GET_SEC_INFO,	/* Get security status */
	SPARKLINK_CMD_ENCRYPT_ON,	/* Enable encryption */

	/* SSAP service layer */
	SPARKLINK_CMD_SSAP_REGISTER,	/* Register services */
	SPARKLINK_CMD_GET_SSAP_INFO,	/* Get SSAP summary */
	SPARKLINK_CMD_SSAP_READ,	/* Read property */
	SPARKLINK_CMD_SSAP_WRITE,	/* Write property */

	/* Power management */
	SPARKLINK_CMD_GET_PM_INFO,	/* Get PM status */
	SPARKLINK_CMD_SET_PM_STATE,	/* Set power state */
	SPARKLINK_CMD_SET_PM_INTERVAL,	/* Set connection interval */

	/* Events (multicast only) */
	SPARKLINK_CMD_EVENT,		/* Async event notification */

	/* DLI controller */
	SPARKLINK_CMD_GET_DLI_INFO,	/* Get DLI controller info */

	/* Version query */
	SPARKLINK_CMD_GET_VERSION,	/* Get protocol version info */

	/* Role management */
	SPARKLINK_CMD_SET_ROLE,		/* Set local GT role (T/G) */
	SPARKLINK_CMD_GET_ROLE,		/* Get current GT role */

	/* Dynamic SSAP service registration */
	SPARKLINK_CMD_SSAP_ADD_SVC,	/* Add SSAP service */
	SPARKLINK_CMD_SSAP_ADD_PROP,	/* Add property to service */
	SPARKLINK_CMD_SSAP_REMOVE_SVC,	/* Remove SSAP service */

	__SPARKLINK_CMD_MAX,
};
#define SPARKLINK_CMD_MAX (__SPARKLINK_CMD_MAX - 1)

/* ---------------------------------------------------------------------------
 * Generic Netlink attributes
 * ---------------------------------------------------------------------------
 */

enum {
	SPARKLINK_ATTR_UNSPEC,

	/* Device attributes */
	SPARKLINK_ATTR_DEV_INDEX,	/* u16: SCI device index */
	SPARKLINK_ATTR_DEV_STATE,	/* u8: operating state */
	SPARKLINK_ATTR_DEV_NAME,	/* NUL string: device name */
	SPARKLINK_ATTR_DEV_BUS,		/* u8: transport bus type */
	SPARKLINK_ATTR_DEV_COUNT,	/* u32: device count */

	/* Version info */
	SPARKLINK_ATTR_PROTO_VERSION,	/* u32: protocol stack version */
	SPARKLINK_ATTR_GENL_VERSION,	/* u32: genetlink interface version */

	/* Address */
	SPARKLINK_ATTR_ADDR,		/* binary(6): local SLE address */
	SPARKLINK_ATTR_PEER_ADDR,	/* binary(6): peer SLE address */

	/* Connection */
	SPARKLINK_ATTR_HANDLE,		/* u16: connection handle */
	SPARKLINK_ATTR_CONN_STATE,	/* u8: connection state */
	SPARKLINK_ATTR_GT_ROLE,		/* u8: GT role (0=T, 1=G) */
	SPARKLINK_ATTR_BANDWIDTH,	/* u8: bandwidth in MHz */
	SPARKLINK_ATTR_MCS_INDEX,	/* u8: MCS index */
	SPARKLINK_ATTR_TX_BYTES,	/* u64: total TX bytes */
	SPARKLINK_ATTR_RX_BYTES,	/* u64: total RX bytes */
	SPARKLINK_ATTR_TIMEOUT_10MS,	/* u16: supervision timeout */

	/* Advertising / scanning */
	SPARKLINK_ATTR_DISCOVERY_LEVEL,	/* u8: discovery level */
	SPARKLINK_ATTR_INTERVAL_MS,	/* u16: interval in ms */
	SPARKLINK_ATTR_WINDOW_MS,	/* u16: window in ms */
	SPARKLINK_ATTR_RSSI,		/* s8: signal strength */
	SPARKLINK_ATTR_SCAN_RESULTS,	/* u32: scan result count */

	/* Data */
	SPARKLINK_ATTR_DATA,		/* binary: payload data */
	SPARKLINK_ATTR_DATA_LEN,	/* u16: data length */

	/* Security */
	SPARKLINK_ATTR_PSK,		/* binary(16): pre-shared key */
	SPARKLINK_ATTR_PAIR_METHOD,	/* u8: pairing method */
	SPARKLINK_ATTR_SEC_STATE,	/* u8: security state */
	SPARKLINK_ATTR_SEC_MODE,	/* u8: security mode */
	SPARKLINK_ATTR_ENCRYPTED,	/* u8: encryption active */
	SPARKLINK_ATTR_KEY_FP,		/* binary(4): key fingerprint */

	/* SSAP */
	SPARKLINK_ATTR_SVC_COUNT,	/* u16: service count */
	SPARKLINK_ATTR_PROP_COUNT,	/* u16: property count */
	SPARKLINK_ATTR_PROP_HANDLE,	/* u16: property handle */
	SPARKLINK_ATTR_MTU,		/* u16: negotiated MTU */

	/* Power management */
	SPARKLINK_ATTR_PM_STATE,	/* u8: power state */
	SPARKLINK_ATTR_FORCE_ACTIVE,	/* u8: force-active flag */
	SPARKLINK_ATTR_POWER_PCT,	/* u8: estimated power % */
	SPARKLINK_ATTR_PM_INTERVAL_MIN,	/* u16: min interval */
	SPARKLINK_ATTR_PM_INTERVAL_MAX,	/* u16: max interval */
	SPARKLINK_ATTR_PM_LATENCY,	/* u16: peripheral latency */

	/* Events (multicast) */
	SPARKLINK_ATTR_EVENT_TYPE,	/* u8: event type code */
	SPARKLINK_ATTR_EVENT_PAYLOAD,	/* binary: event payload */
	SPARKLINK_ATTR_EVENT_PENDING,	/* u32: pending event count */
	SPARKLINK_ATTR_EVENT_TOTAL,	/* u64: total enqueued */
	SPARKLINK_ATTR_EVENT_DROPPED,	/* u64: total dropped */

	/* DLI */
	SPARKLINK_ATTR_DLI_BUS,			/* u8: DLI bus type */
	SPARKLINK_ATTR_DLI_FW_VER,		/* u32: firmware version */
	SPARKLINK_ATTR_DLI_FEATURES,		/* u64: feature bitmask */
	SPARKLINK_ATTR_DLI_MAX_CONN,		/* u8: max connections */
	SPARKLINK_ATTR_DLI_MAX_MTU,		/* u16: max MTU */
	SPARKLINK_ATTR_DLI_MAX_MPS,		/* u16: max MPS */
	SPARKLINK_ATTR_DLI_TRANSPORT_MODES,	/* u8: transport mode bitmask */
	SPARKLINK_ATTR_DLI_MEASUREMENT_CAP,	/* u8: measurement capability bitmask */
	SPARKLINK_ATTR_DLI_SECURITY_CAP,	/* u16: security capability bitmask */

	/* Transport channel (per-connection) */
	SPARKLINK_ATTR_DATA_MTU,	/* u16: data channel MTU */
	SPARKLINK_ATTR_DATA_MPS,	/* u16: data channel MPS */
	SPARKLINK_ATTR_DATA_MODE,	/* u8: data channel transport mode */
	SPARKLINK_ATTR_SVC_MTU,		/* u16: service mgmt channel MTU */

	__SPARKLINK_ATTR_MAX,
};
#define SPARKLINK_ATTR_MAX (__SPARKLINK_ATTR_MAX - 1)

/* ---------------------------------------------------------------------------
 * Event types (same as sle_event.rs)
 * ---------------------------------------------------------------------------
 */

enum sparklink_event_type {
	/* Core events */
	SPARKLINK_EVT_CONN_STATE	= 0x01,
	SPARKLINK_EVT_ADV_REPORT	= 0x02,
	SPARKLINK_EVT_DATA_RECEIVED	= 0x03,
	SPARKLINK_EVT_SECURITY_CHANGED	= 0x04,
	SPARKLINK_EVT_POWER_CHANGED	= 0x05,
	SPARKLINK_EVT_HARDWARE_ERROR	= 0x06,
	SPARKLINK_EVT_CMD_COMPLETE	= 0x07,
	SPARKLINK_EVT_CMD_STATUS	= 0x08,
	SPARKLINK_EVT_BROADCAST_END	= 0x09,
	SPARKLINK_EVT_PHY_UPDATE	= 0x0A,
	SPARKLINK_EVT_CONN_PARAM_UPDATE	= 0x0B,
	SPARKLINK_EVT_DATA_LEN_CHANGE	= 0x0C,
	SPARKLINK_EVT_DATA_BUF_OVERFLOW	= 0x0D,
	SPARKLINK_EVT_PEER_CONN_PARAM_REQ = 0x0E,

	/* T/XS 10003-2025 §9.1.7-§9.1.11 */
	SPARKLINK_EVT_POWER_CHANGE_REPORT = 0x0F,
	SPARKLINK_EVT_NUM_COMPLETED_PKTS  = 0x10,
	SPARKLINK_EVT_ENCRYPT_PARAM_REQ	  = 0x11,

	/* T/XS 10003-2025 §9.1.13-§9.1.21 */
	SPARKLINK_EVT_CTRL_SIGNAL_DATA	= 0x12,
	SPARKLINK_EVT_READ_PEER_FEATURES = 0x13,
	SPARKLINK_EVT_READ_PEER_VERSION	= 0x14,
	SPARKLINK_EVT_READ_PEER_POWER	= 0x15,
	SPARKLINK_EVT_INQUIRY_REQ_REPORT = 0x16,

	/* T/XS 10003-2025 §9.1.22-§9.1.32 (pairing) */
	SPARKLINK_EVT_PAIR_REQUEST	= 0x17,
	SPARKLINK_EVT_PAIR_INFO_EXCH_REQ = 0x18,
	SPARKLINK_EVT_PAIR_INFO_REPORT	= 0x19,
	SPARKLINK_EVT_PAIR_OPTION_REPORT = 0x1A,
	SPARKLINK_EVT_PEER_PUBKEY_REPORT = 0x1B,
	SPARKLINK_EVT_PAIR_EXT_DATA	= 0x1C,
	SPARKLINK_EVT_KEYPRESS_NOTIFY	= 0x1D,
	SPARKLINK_EVT_PAIR_RANDOM_REPORT = 0x1E,
	SPARKLINK_EVT_PAIR_CONFIRM_REPORT = 0x1F,
	SPARKLINK_EVT_DH_KEY_CHECK_REPORT = 0x20,
	SPARKLINK_EVT_PAIR_FAILURE_REPORT = 0x21,

	/* T/XS 10003-2025 §9.1.33-§9.1.39 (narrowband measurement) */
	SPARKLINK_EVT_NB_MEAS_INFO	= 0x22,
	SPARKLINK_EVT_NB_MEAS_STATE_CHG = 0x23,
	SPARKLINK_EVT_NB_MEAS_PARAM	= 0x24,
	SPARKLINK_EVT_LOCAL_NB_MEAS_CAP = 0x25,
	SPARKLINK_EVT_PEER_NB_MEAS_CAP = 0x26,
	SPARKLINK_EVT_MEAS_STATE_CHG	= 0x27,
	SPARKLINK_EVT_MEAS_QUANTITY	= 0x28,

	/* T/XS 10003-2025 §9.1.40-§9.1.45 (SLB) */
	SPARKLINK_EVT_SLB_ADV_REPORT	= 0x29,
	SPARKLINK_EVT_SLB_CONN_COMPLETE	= 0x2A,
	SPARKLINK_EVT_SLB_UCAST_CH_DONE = 0x2B,
	SPARKLINK_EVT_SLB_UCAST_CH_UPD	= 0x2C,
	SPARKLINK_EVT_SLB_CH_DELETE	= 0x2D,
	SPARKLINK_EVT_SLB_NUM_COMP_PKTS	= 0x2E,

	/* T/XS 10003-2025 §9.1.46-§9.1.51 (sync link) */
	SPARKLINK_EVT_TIME_SYNC_STATUS	= 0x2F,
	SPARKLINK_EVT_TIME_SYNC_REQUEST	= 0x30,
	SPARKLINK_EVT_SYNC_UCAST_SETUP_REQ  = 0x31,
	SPARKLINK_EVT_SYNC_UCAST_SETUP_DONE = 0x32,
	SPARKLINK_EVT_SYNC_MCAST_SETUP_REQ  = 0x33,
	SPARKLINK_EVT_SYNC_MCAST_SETUP_DONE = 0x34,
};

/* ---------------------------------------------------------------------------
 * Connection states
 * ---------------------------------------------------------------------------
 */

enum sparklink_conn_state {
	SPARKLINK_CONN_IDLE		= 0,
	SPARKLINK_CONN_CONNECTING	= 1,
	SPARKLINK_CONN_CONNECTED	= 2,
	SPARKLINK_CONN_DISCONNECTING	= 3,
};

/* ---------------------------------------------------------------------------
 * Power states
 * ---------------------------------------------------------------------------
 */

enum sparklink_pm_state {
	SPARKLINK_PM_ACTIVE		= 0,
	SPARKLINK_PM_SNIFF		= 1,
	SPARKLINK_PM_IDLE		= 2,
	SPARKLINK_PM_SUSPENDED		= 3,
};

/* ---------------------------------------------------------------------------
 * Security states
 * ---------------------------------------------------------------------------
 */

enum sparklink_sec_state {
	SPARKLINK_SEC_NONE		= 0,
	SPARKLINK_SEC_PAIRING		= 1,
	SPARKLINK_SEC_PAIRED		= 2,
	SPARKLINK_SEC_ENCRYPTED		= 3,
};

/* ---------------------------------------------------------------------------
 * Pairing methods
 * ---------------------------------------------------------------------------
 */

enum sparklink_pair_method {
	SPARKLINK_PAIR_NONE		= 0,
	SPARKLINK_PAIR_JUST_WORKS	= 1,
	SPARKLINK_PAIR_PSK		= 2,
};

/* ---------------------------------------------------------------------------
 * Discovery levels (T/XS 20001-2025)
 * ---------------------------------------------------------------------------
 */

enum sparklink_discovery_level {
	SPARKLINK_DISC_INVISIBLE	= 0,
	SPARKLINK_DISC_GENERAL		= 1,
	SPARKLINK_DISC_PRIORITY		= 2,
	SPARKLINK_DISC_PAIRED_ONLY	= 3,
	SPARKLINK_DISC_DESIGNATED	= 4,
};

/* ---------------------------------------------------------------------------
 * DLI transport bus types
 * ---------------------------------------------------------------------------
 */

enum sparklink_dli_bus {
	SPARKLINK_BUS_VIRTUAL		= 0,
	SPARKLINK_BUS_UART		= 1,
	SPARKLINK_BUS_SPI		= 2,
	SPARKLINK_BUS_SDIO		= 3,
	SPARKLINK_BUS_USB		= 4,
	SPARKLINK_BUS_MMIO		= 5,
};

/* ---------------------------------------------------------------------------
 * DLI packet type indicators (T/XS 10003-2025 Table 1)
 * ---------------------------------------------------------------------------
 */

enum sparklink_dli_pkt_type {
	SPARKLINK_DLI_PKT_COMMAND	= 0xA1,
	SPARKLINK_DLI_PKT_EVENT		= 0xA2,
	SPARKLINK_DLI_PKT_ASYNC_UCAST	= 0xA3,
	SPARKLINK_DLI_PKT_SYNC_UCAST	= 0xA4,
	SPARKLINK_DLI_PKT_ASYNC_MCAST	= 0xA5,
};

/* ---------------------------------------------------------------------------
 * DLI event codes (T/XS 10003-2025 §9.1)
 *
 * These are the 2-byte event identifiers in the DLI wire protocol,
 * distinct from the sparklink_event_type values used in the kernel
 * event subsystem.
 * ---------------------------------------------------------------------------
 */

enum sparklink_dli_event_code {
	SPARKLINK_DLI_EVT_CMD_STATUS		= 0x0001, /* 9.1.1 */
	SPARKLINK_DLI_EVT_CMD_COMPLETE		= 0x0002, /* 9.1.2 */
	SPARKLINK_DLI_EVT_DATA_LEN_CHANGE	= 0x0003, /* 9.1.3 */
	SPARKLINK_DLI_EVT_BROADCAST_END		= 0x0004, /* 9.1.4 */
	SPARKLINK_DLI_EVT_DISCONNECTED		= 0x0005, /* 9.1.5 */
	SPARKLINK_DLI_EVT_PEER_CONN_PARAM_REQ	= 0x0007, /* 9.1.6 */
	SPARKLINK_DLI_EVT_TX_POWER_CHANGE	= 0x0008, /* 9.1.7 */
	SPARKLINK_DLI_EVT_NUM_COMPLETED_PKTS	= 0x0009, /* 9.1.8 */
	SPARKLINK_DLI_EVT_HW_ERROR		= 0x000A, /* 9.1.9 */
	SPARKLINK_DLI_EVT_DATA_BUF_OVERFLOW	= 0x000B, /* 9.1.10 */
	SPARKLINK_DLI_EVT_ENCRYPT_PARAM_REQ	= 0x000E, /* 9.1.11 */
	SPARKLINK_DLI_EVT_ENCRYPT_STATE_CHANGE	= 0x0011, /* 9.1.12 */
	SPARKLINK_DLI_EVT_CTRL_SIGNAL_DATA	= 0x0014, /* 9.1.13 */
	SPARKLINK_DLI_EVT_CONN_ESTABLISHED	= 0x0015, /* 9.1.14 */
	SPARKLINK_DLI_EVT_READ_PEER_FEATURES	= 0x0016, /* 9.1.15 */
	SPARKLINK_DLI_EVT_READ_PEER_VERSION	= 0x0017, /* 9.1.16 */
	SPARKLINK_DLI_EVT_PHY_PARAM_UPDATE	= 0x0018, /* 9.1.17 */
	SPARKLINK_DLI_EVT_CONN_PARAM_UPDATE	= 0x0019, /* 9.1.18 */
	SPARKLINK_DLI_EVT_BROADCAST_REPORT	= 0x001A, /* 9.1.19 */
	SPARKLINK_DLI_EVT_READ_PEER_TX_POWER	= 0x001B, /* 9.1.20 */
	SPARKLINK_DLI_EVT_INQUIRY_REQ_REPORT	= 0x001C, /* 9.1.21 */
	SPARKLINK_DLI_EVT_PAIR_REQUEST		= 0x001D, /* 9.1.22 */
	SPARKLINK_DLI_EVT_PAIR_INFO_EXCHANGE	= 0x001E, /* 9.1.23 */
	SPARKLINK_DLI_EVT_PAIR_INFO_REPORT	= 0x001F, /* 9.1.24 */
	SPARKLINK_DLI_EVT_PAIR_OPTION_REPORT	= 0x0020, /* 9.1.25 */
	SPARKLINK_DLI_EVT_REMOTE_PUBLIC_KEY	= 0x0021, /* 9.1.26 */
	SPARKLINK_DLI_EVT_PAIR_EXT_DATA		= 0x0022, /* 9.1.27 */
	SPARKLINK_DLI_EVT_KEY_NOTIFY		= 0x0023, /* 9.1.28 */
	SPARKLINK_DLI_EVT_PAIR_RANDOM		= 0x0024, /* 9.1.29 */
	SPARKLINK_DLI_EVT_PAIR_CONFIRM		= 0x0025, /* 9.1.30 */
	SPARKLINK_DLI_EVT_DHKEY_CHECK		= 0x0026, /* 9.1.31 */
	SPARKLINK_DLI_EVT_PAIR_FAILED		= 0x0027, /* 9.1.32 */
	SPARKLINK_DLI_EVT_NB_FH_MEAS_INFO	= 0x0028, /* 9.1.33 */
	SPARKLINK_DLI_EVT_NB_FH_MEAS_STATE	= 0x0029, /* 9.1.34 */
	SPARKLINK_DLI_EVT_NB_FH_MEAS_PARAM	= 0x002A, /* 9.1.35 */
	SPARKLINK_DLI_EVT_LOCAL_NB_FH_CAP	= 0x002B, /* 9.1.36 */
	SPARKLINK_DLI_EVT_PEER_NB_FH_CAP	= 0x002C, /* 9.1.37 */
	SPARKLINK_DLI_EVT_MEAS_STATE_CHANGE	= 0x002D, /* 9.1.38 */
	SPARKLINK_DLI_EVT_MEAS_REPORT		= 0x002E, /* 9.1.39 */
	SPARKLINK_DLI_EVT_SLB_BROADCAST_REPORT	= 0x002F, /* 9.1.40 */
	SPARKLINK_DLI_EVT_SLB_CONN_ESTABLISHED	= 0x0030, /* 9.1.41 */
	SPARKLINK_DLI_EVT_SLB_UC_CH_ESTABLISHED = 0x0031, /* 9.1.42 */
	SPARKLINK_DLI_EVT_SLB_UC_CH_UPDATED	= 0x0032, /* 9.1.43 */
	SPARKLINK_DLI_EVT_SLB_CH_DELETED	= 0x0033, /* 9.1.44 */
	SPARKLINK_DLI_EVT_SLB_NUM_COMPLETED	= 0x0034, /* 9.1.45 */
	SPARKLINK_DLI_EVT_TIME_SYNC_UPDATE	= 0x0035, /* 9.1.46 */
	SPARKLINK_DLI_EVT_TIME_SYNC_REQUEST	= 0x0036, /* 9.1.47 */
	SPARKLINK_DLI_EVT_SYNC_UC_CONN_REQ	= 0x0038, /* 9.1.48 */
	SPARKLINK_DLI_EVT_SYNC_UC_CONN_DONE	= 0x0039, /* 9.1.49 */
	SPARKLINK_DLI_EVT_SYNC_MC_CONN_REQ	= 0x003A, /* 9.1.50 */
	SPARKLINK_DLI_EVT_SYNC_MC_CONN_DONE	= 0x003B, /* 9.1.51 */
};

#endif /* _UAPI_LINUX_SPARKLINK_H */
