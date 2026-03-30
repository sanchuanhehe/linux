// SPDX-License-Identifier: GPL-2.0
/*
 * sparklink_ctl.c - SparkLink userspace control utility
 *
 * Provides a command-line interface for managing SparkLink devices
 * through the /dev/sparklink ioctl interface. Designed to complement
 * a future Generic Netlink interface when Rust genetlink bindings
 * become available upstream.
 *
 * Usage:
 *   sparklink_ctl info          - Show subsystem version and module list
 *   sparklink_ctl adv start     - Start advertising
 *   sparklink_ctl adv stop      - Stop advertising
 *   sparklink_ctl scan start    - Start scanning
 *   sparklink_ctl scan stop     - Stop scanning
 *   sparklink_ctl scan results  - Show scan result count
 *   sparklink_ctl conn <addr>   - Connect to a peer
 *   sparklink_ctl conn info     - Show connection info
 *   sparklink_ctl conn send <d> - Send data
 *   sparklink_ctl sec psk <key> - Set pre-shared key
 *   sparklink_ctl sec pair <m>  - Start pairing
 *   sparklink_ctl sec info      - Show security info
 *   sparklink_ctl sec encrypt   - Enable encryption
 *   sparklink_ctl ssap register - Register device info service
 *   sparklink_ctl ssap info     - Show SSAP summary
 *   sparklink_ctl ssap read <h> - Read property by handle
 *   sparklink_ctl ssap write <h> <v> - Write property by handle
 *   sparklink_ctl pm info       - Show power management info
 *   sparklink_ctl pm suspend    - Suspend
 *   sparklink_ctl pm resume     - Resume
 *
 * Build:
 *   gcc -Wall -O2 -o sparklink_ctl sparklink_ctl.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define SL_MAGIC 'S'
#define DEVICE "/dev/sparklink"

/* ioctl definitions */
#define SL_IOCTL_DEV_INFO        _IOR(SL_MAGIC, 0x04, struct sci_dev_info)
#define SL_IOCTL_START_ADV       _IOW(SL_MAGIC, 0x10, struct sle_adv_params)
#define SL_IOCTL_STOP_ADV        _IO(SL_MAGIC, 0x11)
#define SL_IOCTL_START_SCAN      _IOW(SL_MAGIC, 0x12, struct sle_scan_params)
#define SL_IOCTL_STOP_SCAN       _IO(SL_MAGIC, 0x13)
#define SL_IOCTL_SCAN_RESULT_COUNT _IO(SL_MAGIC, 0x21)
#define SL_IOCTL_CONNECT         _IOW(SL_MAGIC, 0x30, struct sle_connect_params)
#define SL_IOCTL_DISCONNECT      _IOW(SL_MAGIC, 0x31, uint16_t)
#define SL_IOCTL_CONN_INFO       _IOWR(SL_MAGIC, 0x32, struct sle_conn_info)
#define SL_IOCTL_CONN_SEND       _IOW(SL_MAGIC, 0x33, struct sle_conn_data)
#define SL_IOCTL_CONN_COUNT      _IO(SL_MAGIC, 0x37)
#define SL_IOCTL_CONN_LIST       _IOR(SL_MAGIC, 0x38, struct sle_conn_list)
#define SL_IOCTL_SEC_SET_PSK     _IOW(SL_MAGIC, 0x40, struct sle_psk_params)
#define SL_IOCTL_SEC_PAIR        _IOW(SL_MAGIC, 0x41, struct sle_pair_params)
#define SL_IOCTL_SEC_INFO        _IOR(SL_MAGIC, 0x42, struct sle_sec_info)
#define SL_IOCTL_SEC_ENCRYPT_ON  _IO(SL_MAGIC, 0x43)
#define SL_IOCTL_SSAP_REGISTER_SVC _IO(SL_MAGIC, 0x50)
#define SL_IOCTL_SSAP_INFO       _IOR(SL_MAGIC, 0x51, struct ssap_summary)
#define SL_IOCTL_SSAP_READ       _IOWR(SL_MAGIC, 0x52, struct ssap_read_write)
#define SL_IOCTL_SSAP_WRITE      _IOW(SL_MAGIC, 0x53, struct ssap_read_write)
#define SL_IOCTL_PM_INFO         _IOR(SL_MAGIC, 0x60, struct sle_pm_info)
#define SL_IOCTL_PM_SET_STATE    _IOW(SL_MAGIC, 0x61, struct sle_pm_state_cmd)

/* Event notification */
#define SL_IOCTL_EVENT_COUNT     _IO(SL_MAGIC, 0x70)
#define SL_IOCTL_EVENT_STATS     _IOR(SL_MAGIC, 0x71, struct sle_event_stats)

/* DLI controller info */
#define SL_IOCTL_DLI_INFO        _IOR(SL_MAGIC, 0x80, struct sle_dli_info)

/* Data structures */
struct sci_dev_info {
	uint16_t index;
	uint8_t  state;
	uint8_t  bus;
	uint8_t  addr[6];
	uint8_t  name[32];
	uint8_t  _reserved[24];
} __attribute__((packed));

struct sle_adv_params {
	uint16_t dev_index;
	uint8_t  discovery_level;
	uint16_t interval_ms;
	uint8_t  _reserved[11];
} __attribute__((packed));

struct sle_scan_params {
	uint16_t dev_index;
	uint16_t window_ms;
	uint16_t interval_ms;
	uint8_t  filter_discovery_level;
	uint8_t  _reserved[9];
} __attribute__((packed));

struct sle_connect_params {
	uint8_t  peer_addr[6];
	uint8_t  gt_role;
	uint8_t  bandwidth;
	uint8_t  mcs_index;
	uint8_t  _pad;
	uint16_t timeout_10ms;
	uint8_t  _reserved[4];
} __attribute__((packed));

struct sle_conn_info {
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint16_t handle;
	uint16_t event_group_period;
	uint16_t supervision_timeout;
	uint16_t tx_pending;
	uint16_t rx_pending;
	uint8_t  state;
	uint8_t  peer_addr[6];
	uint8_t  local_role;
	uint8_t  bandwidth_mhz;
	uint8_t  mcs_index;
	uint8_t  tx_seq;
	uint8_t  rx_seq;
	uint8_t  _reserved[10];
} __attribute__((packed));

struct sle_conn_data {
	uint16_t handle;
	uint16_t length;
	uint8_t  data[255];
	uint8_t  _reserved;
} __attribute__((packed));

struct sle_conn_list {
	uint16_t count;
	uint16_t _pad;
	uint16_t handles[8];
	uint8_t  _reserved[4];
} __attribute__((packed));

struct sle_psk_params {
	uint8_t psk[16];
} __attribute__((packed));

struct sle_pair_params {
	uint8_t method;
	uint8_t _reserved[3];
} __attribute__((packed));

struct sle_sec_info {
	uint8_t state;
	uint8_t method;
	uint8_t mode;
	uint8_t enc_enabled;
	uint8_t enc_key_fingerprint[4];
	uint8_t _reserved[8];
} __attribute__((packed));

struct ssap_summary {
	uint16_t service_count;
	uint16_t property_count;
	uint16_t total_entries;
	uint16_t mtu;
	uint16_t notification_count;
	uint8_t  _reserved[6];
} __attribute__((packed));

struct ssap_read_write {
	uint16_t handle;
	uint16_t length;
	uint8_t  data[252];
} __attribute__((packed));

struct sle_pm_info {
	uint8_t  state;
	uint8_t  force_active;
	uint8_t  power_pct;
	uint8_t  _pad;
	uint16_t current_interval;
	uint16_t supervision_timeout;
	uint16_t latency;
	uint16_t idle_count;
	uint32_t transitions;
	uint64_t active_events;
	uint64_t sniff_events;
	uint64_t idle_events;
	uint8_t  _reserved[8];
} __attribute__((packed));

struct sle_pm_state_cmd {
	uint8_t target_state;
	uint8_t _reserved[3];
} __attribute__((packed));

/* Event wire format — must match SleWireEvent in sle_event.rs */
struct sle_wire_event {
	uint8_t  event_type;
	uint8_t  payload_len;
	uint8_t  payload[40];
	uint8_t  _pad[2];
} __attribute__((packed));

/* Event queue statistics */
struct sle_event_stats {
	uint32_t pending;
	uint32_t _pad;
	uint64_t total_enqueued;
	uint64_t total_dropped;
	uint64_t total_delivered;
};

/* DLI controller information */
struct sle_dli_info {
	uint8_t  bus;
	uint8_t  _pad[3];
	uint32_t firmware_version;
	uint64_t features;
	uint8_t  max_connections;
	uint8_t  max_adv_sets;
	uint8_t  name[32];
	uint8_t  _reserved[14];
} __attribute__((packed));

static const char *bus_type_str(uint8_t b)
{
	switch (b) {
	case 0: return "Virtual";
	case 1: return "UART";
	case 2: return "USB";
	case 3: return "SDIO";
	default: return "Unknown";
	}
}

static const char *power_state_str(uint8_t s)
{
	switch (s) {
	case 0: return "Active";
	case 1: return "Sniff";
	case 2: return "Idle";
	case 3: return "Suspended";
	default: return "Unknown";
	}
}

static const char *conn_state_str(uint8_t s)
{
	switch (s) {
	case 0: return "Idle";
	case 1: return "Connecting";
	case 2: return "Connected";
	default: return "Unknown";
	}
}

static const char *sec_state_str(uint8_t s)
{
	switch (s) {
	case 0: return "Idle";
	case 1: return "Pairing";
	case 2: return "Paired";
	case 3: return "Encrypted";
	default: return "Unknown";
	}
}

static int parse_hex(const char *str, uint8_t *out, int max_len)
{
	int len = 0;
	while (*str && len < max_len) {
		unsigned int byte;
		if (sscanf(str, "%2x", &byte) != 1)
			break;
		out[len++] = (uint8_t)byte;
		str += 2;
		if (*str == ':') str++;
	}
	return len;
}

static void cmd_info(int fd)
{
	static const char *state_names[] = {"idle", "advertising", "scanning", "connected"};
	static const char *bus_names[]   = {"virtual", "uart", "spi", "sdio", "usb"};

	printf("SparkLink Control Utility\n");
	printf("Device: %s\n", DEVICE);
	printf("Standard: T/XS 10002-2025, T/XS 20001-2025\n");
	printf("Modules: core pdu adv conn crypto security ssap power\n");

	struct sci_dev_info info;
	memset(&info, 0, sizeof(info));
	if (ioctl(fd, SL_IOCTL_DEV_INFO, &info) == 0) {
		const char *state = info.state < 4 ? state_names[info.state] : "unknown";
		const char *bus   = info.bus < 5 ? bus_names[info.bus] : "unknown";
		printf("Controller #%u: state=%s bus=%s addr=%02x:%02x:%02x:%02x:%02x:%02x name=%.32s\n",
		       info.index, state, bus,
		       info.addr[0], info.addr[1], info.addr[2],
		       info.addr[3], info.addr[4], info.addr[5],
		       info.name);
	} else {
		printf("Interface: ioctl (DEV_INFO unavailable)\n");
	}
}

static void cmd_adv(int fd, int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "Usage: sparklink_ctl adv <start|stop>\n");
		return;
	}
	if (strcmp(argv[0], "start") == 0) {
		struct sle_adv_params p;
		memset(&p, 0, sizeof(p));
		p.discovery_level = 1;
		p.interval_ms = 100;
		if (ioctl(fd, SL_IOCTL_START_ADV, &p) < 0)
			perror("START_ADV");
		else
			printf("Advertising started (interval=100ms, level=general)\n");
	} else if (strcmp(argv[0], "stop") == 0) {
		if (ioctl(fd, SL_IOCTL_STOP_ADV, NULL) < 0)
			perror("STOP_ADV");
		else
			printf("Advertising stopped\n");
	} else {
		fprintf(stderr, "Unknown adv command: %s\n", argv[0]);
	}
}

static void cmd_scan(int fd, int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "Usage: sparklink_ctl scan <start|stop|results>\n");
		return;
	}
	if (strcmp(argv[0], "start") == 0) {
		struct sle_scan_params p;
		memset(&p, 0, sizeof(p));
		p.window_ms = 30;
		p.interval_ms = 60;
		p.filter_discovery_level = 0;
		if (ioctl(fd, SL_IOCTL_START_SCAN, &p) < 0)
			perror("START_SCAN");
		else
			printf("Scanning started (window=30ms, interval=60ms)\n");
	} else if (strcmp(argv[0], "stop") == 0) {
		if (ioctl(fd, SL_IOCTL_STOP_SCAN, NULL) < 0)
			perror("STOP_SCAN");
		else
			printf("Scanning stopped\n");
	} else if (strcmp(argv[0], "results") == 0) {
		int ret = ioctl(fd, SL_IOCTL_SCAN_RESULT_COUNT, NULL);
		if (ret < 0)
			perror("SCAN_RESULT_COUNT");
		else
			printf("Scan results: %d\n", ret);
	} else {
		fprintf(stderr, "Unknown scan command: %s\n", argv[0]);
	}
}

static void cmd_conn(int fd, int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "Usage: sparklink_ctl conn <info [handle]|disconnect <handle>|list|count|<addr>|send <handle> <data>>\n");
		return;
	}
	if (strcmp(argv[0], "info") == 0) {
		struct sle_conn_info ci;
		memset(&ci, 0, sizeof(ci));
		if (argc >= 2)
			ci.handle = (uint16_t)atoi(argv[1]);
		if (ioctl(fd, SL_IOCTL_CONN_INFO, &ci) < 0) {
			perror("CONN_INFO");
			return;
		}
		printf("Connection Info (handle=%u):\n", ci.handle);
		printf("  State:      %s (%u)\n", conn_state_str(ci.state), ci.state);
		printf("  Peer:       %02x:%02x:%02x:%02x:%02x:%02x\n",
		       ci.peer_addr[0], ci.peer_addr[1], ci.peer_addr[2],
		       ci.peer_addr[3], ci.peer_addr[4], ci.peer_addr[5]);
		printf("  Role:       %s\n", ci.local_role == 0 ? "T-node" : "G-node");
		printf("  BW:         %u MHz\n", ci.bandwidth_mhz);
		printf("  MCS:        %u\n", ci.mcs_index);
		printf("  TX/RX:      %lu / %lu bytes\n",
		       (unsigned long)ci.tx_bytes, (unsigned long)ci.rx_bytes);
		printf("  Pending:    TX=%u RX=%u\n", ci.tx_pending, ci.rx_pending);
	} else if (strcmp(argv[0], "disconnect") == 0) {
		uint16_t handle = 0;
		if (argc >= 2)
			handle = (uint16_t)atoi(argv[1]);
		if (ioctl(fd, SL_IOCTL_DISCONNECT, &handle) < 0)
			perror("DISCONNECT");
		else
			printf("Disconnected handle=%u\n", handle);
	} else if (strcmp(argv[0], "count") == 0) {
		int ret = ioctl(fd, SL_IOCTL_CONN_COUNT, NULL);
		if (ret < 0)
			perror("CONN_COUNT");
		else
			printf("Active connections: %d\n", ret);
	} else if (strcmp(argv[0], "list") == 0) {
		struct sle_conn_list list;
		memset(&list, 0, sizeof(list));
		if (ioctl(fd, SL_IOCTL_CONN_LIST, &list) < 0) {
			perror("CONN_LIST");
			return;
		}
		printf("Active connections (%u):\n", list.count);
		for (int i = 0; i < list.count && i < 8; i++)
			printf("  handle=%u\n", list.handles[i]);
	} else if (strcmp(argv[0], "send") == 0 && argc >= 3) {
		struct sle_conn_data cd;
		memset(&cd, 0, sizeof(cd));
		cd.handle = (uint16_t)atoi(argv[1]);
		size_t len = strlen(argv[2]);
		if (len > 255) len = 255;
		cd.length = (uint16_t)len;
		memcpy(cd.data, argv[2], len);
		if (ioctl(fd, SL_IOCTL_CONN_SEND, &cd) < 0)
			perror("CONN_SEND");
		else
			printf("Sent %u bytes on handle=%u\n", cd.length, cd.handle);
	} else {
		/* Treat as address to connect to */
		struct sle_connect_params cp;
		memset(&cp, 0, sizeof(cp));
		parse_hex(argv[0], cp.peer_addr, 6);
		cp.bandwidth = 1;
		cp.mcs_index = 4;
		cp.timeout_10ms = 100;
		int ret = ioctl(fd, SL_IOCTL_CONNECT, &cp);
		if (ret < 0)
			perror("CONNECT");
		else
			printf("Connection handle=%d to %02x:%02x:%02x:%02x:%02x:%02x\n",
			       ret,
			       cp.peer_addr[0], cp.peer_addr[1], cp.peer_addr[2],
			       cp.peer_addr[3], cp.peer_addr[4], cp.peer_addr[5]);
	}
}

static void cmd_sec(int fd, int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "Usage: sparklink_ctl sec <psk <key>|pair <method>|info|encrypt>\n");
		return;
	}
	if (strcmp(argv[0], "psk") == 0 && argc >= 2) {
		struct sle_psk_params p;
		memset(&p, 0, sizeof(p));
		parse_hex(argv[1], p.psk, 16);
		if (ioctl(fd, SL_IOCTL_SEC_SET_PSK, &p) < 0)
			perror("SEC_SET_PSK");
		else
			printf("PSK set\n");
	} else if (strcmp(argv[0], "pair") == 0 && argc >= 2) {
		struct sle_pair_params p;
		memset(&p, 0, sizeof(p));
		p.method = (uint8_t)atoi(argv[1]);
		if (ioctl(fd, SL_IOCTL_SEC_PAIR, &p) < 0)
			perror("SEC_PAIR");
		else
			printf("Pairing initiated (method=%u)\n", p.method);
	} else if (strcmp(argv[0], "info") == 0) {
		struct sle_sec_info si;
		memset(&si, 0, sizeof(si));
		if (ioctl(fd, SL_IOCTL_SEC_INFO, &si) < 0) {
			perror("SEC_INFO");
			return;
		}
		printf("Security Info:\n");
		printf("  State:       %s (%u)\n", sec_state_str(si.state), si.state);
		printf("  Method:      %u\n", si.method);
		printf("  Mode:        %u\n", si.mode);
		printf("  Encrypted:   %s\n", si.enc_enabled ? "yes" : "no");
		printf("  Fingerprint: %02x%02x%02x%02x\n",
		       si.enc_key_fingerprint[0], si.enc_key_fingerprint[1],
		       si.enc_key_fingerprint[2], si.enc_key_fingerprint[3]);
	} else if (strcmp(argv[0], "encrypt") == 0) {
		if (ioctl(fd, SL_IOCTL_SEC_ENCRYPT_ON, NULL) < 0)
			perror("SEC_ENCRYPT_ON");
		else
			printf("Encryption enabled\n");
	} else {
		fprintf(stderr, "Unknown sec command: %s\n", argv[0]);
	}
}

static void cmd_ssap(int fd, int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "Usage: sparklink_ctl ssap <register|info|read <handle>|write <handle> <value>>\n");
		return;
	}
	if (strcmp(argv[0], "register") == 0) {
		if (ioctl(fd, SL_IOCTL_SSAP_REGISTER_SVC, NULL) < 0)
			perror("SSAP_REGISTER_SVC");
		else
			printf("Device info service registered\n");
	} else if (strcmp(argv[0], "info") == 0) {
		struct ssap_summary ss;
		memset(&ss, 0, sizeof(ss));
		if (ioctl(fd, SL_IOCTL_SSAP_INFO, &ss) < 0) {
			perror("SSAP_INFO");
			return;
		}
		printf("SSAP Info:\n");
		printf("  Services:      %u\n", ss.service_count);
		printf("  Properties:    %u\n", ss.property_count);
		printf("  Total entries: %u\n", ss.total_entries);
		printf("  MTU:           %u\n", ss.mtu);
		printf("  Notifications: %u pending\n", ss.notification_count);
	} else if (strcmp(argv[0], "read") == 0 && argc >= 2) {
		struct ssap_read_write rw;
		memset(&rw, 0, sizeof(rw));
		rw.handle = (uint16_t)strtoul(argv[1], NULL, 0);
		if (ioctl(fd, SL_IOCTL_SSAP_READ, &rw) < 0) {
			perror("SSAP_READ");
			return;
		}
		printf("Handle 0x%04x [%u bytes]: ", rw.handle, rw.length);
		/* Try printing as text if all printable */
		int printable = 1;
		for (int i = 0; i < rw.length; i++) {
			if (rw.data[i] < 0x20 || rw.data[i] > 0x7e) {
				printable = 0;
				break;
			}
		}
		if (printable && rw.length > 0)
			printf("\"%.*s\"\n", rw.length, rw.data);
		else {
			for (int i = 0; i < rw.length; i++)
				printf("%02x ", rw.data[i]);
			printf("\n");
		}
	} else if (strcmp(argv[0], "write") == 0 && argc >= 3) {
		struct ssap_read_write rw;
		memset(&rw, 0, sizeof(rw));
		rw.handle = (uint16_t)strtoul(argv[1], NULL, 0);
		size_t len = strlen(argv[2]);
		if (len > 252) len = 252;
		rw.length = (uint16_t)len;
		memcpy(rw.data, argv[2], len);
		if (ioctl(fd, SL_IOCTL_SSAP_WRITE, &rw) < 0)
			perror("SSAP_WRITE");
		else
			printf("Written %u bytes to handle 0x%04x\n", rw.length, rw.handle);
	} else {
		fprintf(stderr, "Unknown ssap command: %s\n", argv[0]);
	}
}

static void cmd_pm(int fd, int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "Usage: sparklink_ctl pm <info|suspend|resume>\n");
		return;
	}
	if (strcmp(argv[0], "info") == 0) {
		struct sle_pm_info pm;
		memset(&pm, 0, sizeof(pm));
		if (ioctl(fd, SL_IOCTL_PM_INFO, &pm) < 0) {
			perror("PM_INFO");
			return;
		}
		printf("Power Management:\n");
		printf("  State:        %s (%u)\n", power_state_str(pm.state), pm.state);
		printf("  Force active: %s\n", pm.force_active ? "yes" : "no");
		printf("  Power:        %u%%\n", pm.power_pct);
		printf("  Interval:     %u (%.1f ms)\n",
		       pm.current_interval, pm.current_interval * 1.25);
		printf("  SV timeout:   %u (%u ms)\n",
		       pm.supervision_timeout, pm.supervision_timeout * 10);
		printf("  Latency:      %u\n", pm.latency);
		printf("  Transitions:  %u\n", pm.transitions);
		printf("  Events:       active=%lu sniff=%lu idle=%lu\n",
		       (unsigned long)pm.active_events,
		       (unsigned long)pm.sniff_events,
		       (unsigned long)pm.idle_events);
	} else if (strcmp(argv[0], "suspend") == 0) {
		struct sle_pm_state_cmd c = { .target_state = 3 };
		if (ioctl(fd, SL_IOCTL_PM_SET_STATE, &c) < 0)
			perror("PM_SET_STATE(suspend)");
		else
			printf("Suspended\n");
	} else if (strcmp(argv[0], "resume") == 0) {
		struct sle_pm_state_cmd c = { .target_state = 0 };
		if (ioctl(fd, SL_IOCTL_PM_SET_STATE, &c) < 0)
			perror("PM_SET_STATE(resume)");
		else
			printf("Resumed\n");
	} else {
		fprintf(stderr, "Unknown pm command: %s\n", argv[0]);
	}
}

static const char *event_type_str(uint8_t t)
{
	switch (t) {
	case 0x01: return "ConnStateChanged";
	case 0x02: return "AdvReport";
	case 0x03: return "DataReceived";
	case 0x04: return "SecurityChanged";
	case 0x05: return "PowerChanged";
	case 0x06: return "HardwareError";
	default:   return "Unknown";
	}
}

static void cmd_event(int fd, int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "Usage: sparklink_ctl event <count|read>\n");
		return;
	}
	if (strcmp(argv[0], "count") == 0) {
		int ret = ioctl(fd, SL_IOCTL_EVENT_COUNT, NULL);
		if (ret < 0)
			perror("EVENT_COUNT");
		else
			printf("Pending events: %d\n", ret);
	} else if (strcmp(argv[0], "read") == 0) {
		int total = 0;
		while (total < 64) {
			struct sle_wire_event evt;
			memset(&evt, 0, sizeof(evt));
			ssize_t n = read(fd, &evt, sizeof(evt));
			if (n < 0) {
				if (errno == EAGAIN)
					break;
				perror("read");
				break;
			}
			if (n == 0)
				break;
			total++;
			printf("  [%d] %s (type=0x%02x, payload_len=%u): ",
			       total, event_type_str(evt.event_type),
			       evt.event_type, evt.payload_len);
			for (int i = 0; i < evt.payload_len && i < 16; i++)
				printf("%02x ", evt.payload[i]);
			printf("\n");
		}
		if (total == 0)
			printf("No pending events\n");
		else
			printf("Total: %d event(s)\n", total);
	} else {
		fprintf(stderr, "Unknown event command: %s\n", argv[0]);
	}
}

static void cmd_dli(int fd, int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "Usage: sparklink_ctl dli <info|stats>\n");
		return;
	}
	if (strcmp(argv[0], "info") == 0) {
		struct sle_dli_info dli;
		memset(&dli, 0, sizeof(dli));
		if (ioctl(fd, SL_IOCTL_DLI_INFO, &dli) < 0) {
			perror("DLI_INFO");
			return;
		}
		unsigned major = (dli.firmware_version >> 16) & 0xFF;
		unsigned minor = (dli.firmware_version >> 8) & 0xFF;
		unsigned patch = dli.firmware_version & 0xFF;
		printf("DLI Controller:\n");
		printf("  Name:             %.32s\n", dli.name);
		printf("  Bus:              %s (%u)\n", bus_type_str(dli.bus), dli.bus);
		printf("  Firmware:         %u.%u.%u\n", major, minor, patch);
		printf("  Features:         0x%016lx\n", (unsigned long)dli.features);
		printf("  Max connections:  %u\n", dli.max_connections);
		printf("  Max adv sets:     %u\n", dli.max_adv_sets);
	} else if (strcmp(argv[0], "stats") == 0) {
		struct sle_event_stats stats;
		memset(&stats, 0, sizeof(stats));
		if (ioctl(fd, SL_IOCTL_EVENT_STATS, &stats) < 0) {
			perror("EVENT_STATS");
			return;
		}
		printf("Event Queue Statistics:\n");
		printf("  Pending:    %u\n", stats.pending);
		printf("  Enqueued:   %lu\n", (unsigned long)stats.total_enqueued);
		printf("  Dropped:    %lu\n", (unsigned long)stats.total_dropped);
		printf("  Delivered:  %lu\n", (unsigned long)stats.total_delivered);
	} else {
		fprintf(stderr, "Unknown dli command: %s\n", argv[0]);
	}
}

static void usage(void)
{
	fprintf(stderr, "sparklink_ctl - SparkLink control utility\n\n");
	fprintf(stderr, "Usage: sparklink_ctl <command> [args...]\n\n");
	fprintf(stderr, "Commands:\n");
	fprintf(stderr, "  info                       Show subsystem information\n");
	fprintf(stderr, "  adv  <start|stop>          Advertising control\n");
	fprintf(stderr, "  scan <start|stop|results>  Scanning control\n");
	fprintf(stderr, "  conn <addr|info|disconnect|send <data>>\n");
	fprintf(stderr, "                             Connection management\n");
	fprintf(stderr, "  sec  <psk <key>|pair <m>|info|encrypt>\n");
	fprintf(stderr, "                             Security management\n");
	fprintf(stderr, "  ssap <register|info|read <h>|write <h> <v>>\n");
	fprintf(stderr, "                             SSAP service layer\n");
	fprintf(stderr, "  pm   <info|suspend|resume> Power management\n");
	fprintf(stderr, "  event <count|read>         Event notification\n");
	fprintf(stderr, "  dli  <info|stats>          DLI controller / stats\n");
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 1;
	}

	int fd = open(DEVICE, O_RDWR);
	if (fd < 0) {
		perror("open " DEVICE);
		return 1;
	}

	if (strcmp(argv[1], "info") == 0)
		cmd_info(fd);
	else if (strcmp(argv[1], "adv") == 0)
		cmd_adv(fd, argc - 2, argv + 2);
	else if (strcmp(argv[1], "scan") == 0)
		cmd_scan(fd, argc - 2, argv + 2);
	else if (strcmp(argv[1], "conn") == 0)
		cmd_conn(fd, argc - 2, argv + 2);
	else if (strcmp(argv[1], "sec") == 0)
		cmd_sec(fd, argc - 2, argv + 2);
	else if (strcmp(argv[1], "ssap") == 0)
		cmd_ssap(fd, argc - 2, argv + 2);
	else if (strcmp(argv[1], "pm") == 0)
		cmd_pm(fd, argc - 2, argv + 2);
	else if (strcmp(argv[1], "event") == 0)
		cmd_event(fd, argc - 2, argv + 2);
	else if (strcmp(argv[1], "dli") == 0)
		cmd_dli(fd, argc - 2, argv + 2);
	else {
		fprintf(stderr, "Unknown command: %s\n", argv[1]);
		usage();
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}
