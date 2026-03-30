// SPDX-License-Identifier: GPL-2.0
/*
 * sparklink_test.c - Userspace test program for /dev/sparklink
 *
 * Exercises the SparkLink SCI control interface ioctl commands:
 *   - DEV_COUNT: query registered device count
 *   - DEV_REGISTER / DEV_UNREGISTER: stub registration
 *   - START_ADV / STOP_ADV: advertising lifecycle
 *   - START_SCAN / STOP_SCAN: scanning lifecycle
 *
 * Build:
 *   gcc -Wall -O2 -o sparklink_test sparklink_test.c
 *
 * Run (requires root or appropriate device permissions):
 *   sudo ./sparklink_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <poll.h>

/* ------------------------------------------------------------------ */
/* IOCTL definitions — must match sparklink_core.rs                   */
/* ------------------------------------------------------------------ */

#define SL_MAGIC 'S'

/* _IO / _IOW / _IOR are defined in <sys/ioctl.h> via <asm/ioctl.h> */
#define SL_IOCTL_DEV_REGISTER    _IO(SL_MAGIC, 0x01)
#define SL_IOCTL_DEV_UNREGISTER  _IOW(SL_MAGIC, 0x02, uint16_t)
#define SL_IOCTL_DEV_COUNT       _IOR(SL_MAGIC, 0x03, uint32_t)
#define SL_IOCTL_DEV_INFO        _IOR(SL_MAGIC, 0x04, struct sci_dev_info)

#define SL_IOCTL_START_ADV       _IOW(SL_MAGIC, 0x10, struct sle_adv_params)
#define SL_IOCTL_STOP_ADV        _IO(SL_MAGIC, 0x11)
#define SL_IOCTL_START_SCAN      _IOW(SL_MAGIC, 0x12, struct sle_scan_params)
#define SL_IOCTL_STOP_SCAN       _IO(SL_MAGIC, 0x13)

#define SL_IOCTL_INJECT_ADV      _IOW(SL_MAGIC, 0x20, struct sle_inject_adv)
#define SL_IOCTL_SCAN_RESULT_COUNT _IO(SL_MAGIC, 0x21)

/* Connection management */
#define SL_IOCTL_CONNECT         _IOW(SL_MAGIC, 0x30, struct sle_connect_params)
#define SL_IOCTL_DISCONNECT      _IOW(SL_MAGIC, 0x31, uint16_t)
#define SL_IOCTL_CONN_INFO       _IOWR(SL_MAGIC, 0x32, struct sle_conn_info)
#define SL_IOCTL_CONN_SEND       _IOW(SL_MAGIC, 0x33, struct sle_conn_data)
#define SL_IOCTL_CONN_RECV       _IOWR(SL_MAGIC, 0x34, struct sle_conn_data)
#define SL_IOCTL_INJECT_CONN_RESP _IOW(SL_MAGIC, 0x35, struct sle_inject_conn_resp)
#define SL_IOCTL_INJECT_CONN_DATA _IOW(SL_MAGIC, 0x36, struct sle_conn_data)
#define SL_IOCTL_CONN_COUNT      _IO(SL_MAGIC, 0x37)
#define SL_IOCTL_CONN_LIST       _IOR(SL_MAGIC, 0x38, struct sle_conn_list)

/* Security management */
#define SL_IOCTL_SEC_SET_PSK     _IOW(SL_MAGIC, 0x40, struct sle_psk_params)
#define SL_IOCTL_SEC_PAIR        _IOW(SL_MAGIC, 0x41, struct sle_pair_params)
#define SL_IOCTL_SEC_INFO        _IOR(SL_MAGIC, 0x42, struct sle_sec_info)
#define SL_IOCTL_SEC_ENCRYPT_ON  _IO(SL_MAGIC, 0x43)
#define SL_IOCTL_SEC_SM3_TEST    _IOW(SL_MAGIC, 0x44, struct sle_hash_test)
#define SL_IOCTL_SEC_SM4_ENC_TEST _IOW(SL_MAGIC, 0x45, struct sle_conn_data)
#define SL_IOCTL_SEC_SM4_DEC_TEST _IOW(SL_MAGIC, 0x46, struct sle_conn_data)

/* SSAP service layer */
#define SL_IOCTL_SSAP_REGISTER_SVC _IO(SL_MAGIC, 0x50)
#define SL_IOCTL_SSAP_INFO        _IOR(SL_MAGIC, 0x51, struct ssap_summary)
#define SL_IOCTL_SSAP_READ        _IOWR(SL_MAGIC, 0x52, struct ssap_read_write)
#define SL_IOCTL_SSAP_WRITE       _IOW(SL_MAGIC, 0x53, struct ssap_read_write)
#define SL_IOCTL_SSAP_FIND_SVC    _IOR(SL_MAGIC, 0x54, struct ssap_service_list)
#define SL_IOCTL_SSAP_NOTIFY      _IOW(SL_MAGIC, 0x55, uint16_t)
#define SL_IOCTL_SSAP_DEQUEUE_NTF _IOR(SL_MAGIC, 0x56, struct ssap_notification)

/* Power management */
#define SL_IOCTL_PM_INFO         _IOR(SL_MAGIC, 0x60, struct sle_pm_info)
#define SL_IOCTL_PM_SET_STATE    _IOW(SL_MAGIC, 0x61, struct sle_pm_state_cmd)
#define SL_IOCTL_PM_SET_INTERVAL _IOW(SL_MAGIC, 0x62, struct sle_pm_interval)
#define SL_IOCTL_PM_FORCE_ACTIVE _IOW(SL_MAGIC, 0x63, uint8_t)
#define SL_IOCTL_PM_TICK         _IO(SL_MAGIC, 0x64)
#define SL_IOCTL_PM_ACTIVITY     _IO(SL_MAGIC, 0x65)

/* Event notification */
#define SL_IOCTL_EVENT_COUNT     _IO(SL_MAGIC, 0x70)
#define SL_IOCTL_EVENT_STATS     _IOR(SL_MAGIC, 0x71, struct sle_event_stats)

/* DLI controller info */
#define SL_IOCTL_DLI_INFO        _IOR(SL_MAGIC, 0x80, struct sle_dli_info)

/* ------------------------------------------------------------------ */
/* Userspace data structures — must match repr(C) in sparklink_core   */
/* ------------------------------------------------------------------ */

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

struct sle_inject_adv {
	uint8_t  addr[6];
	int8_t   rssi;
	uint8_t  discovery_level;
	uint8_t  name[32];
	uint8_t  name_len;
	uint8_t  _reserved[7];
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

struct sle_inject_conn_resp {
	uint16_t handle;
	uint8_t  response_type;
	uint8_t  bandwidth_mhz;
	uint8_t  mcs_index;
	uint8_t  _pad;
	uint16_t supervision_timeout;
} __attribute__((packed));

struct sle_conn_list {
	uint16_t count;
	uint16_t _pad;
	uint16_t handles[8];
	uint8_t  _reserved[4];
} __attribute__((packed));

/* Security */
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

struct sle_hash_test {
	uint16_t in_len;
	uint16_t _pad;
	uint8_t  data[220];
	uint8_t  digest[32];
} __attribute__((packed));

/* SSAP */
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

struct ssap_service_entry {
	uint16_t start_handle;
	uint16_t end_handle;
	uint16_t uuid16;
	uint8_t  primary;
	uint8_t  _pad;
} __attribute__((packed));

struct ssap_service_list {
	uint16_t count;
	uint8_t  _pad[2];
	struct ssap_service_entry services[15];
} __attribute__((packed));

struct ssap_notification {
	uint16_t handle;
	uint8_t  indication;
	uint8_t  length;
	uint8_t  data[252];
} __attribute__((packed));

/* Power management */
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

struct sle_pm_interval {
	uint16_t min_interval;
	uint16_t max_interval;
	uint16_t latency;
	uint16_t supervision_timeout;
} __attribute__((packed));

/* Event wire format — must match SleWireEvent in sle_event.rs */
struct sle_wire_event {
	uint8_t  event_type;
	uint8_t  payload_len;
	uint8_t  payload[40];
	uint8_t  _pad[2];
} __attribute__((packed));

#define SLE_EVT_CONN_STATE   0x01
#define SLE_EVT_ADV_REPORT   0x02
#define SLE_EVT_DATA_RECV    0x03
#define SLE_EVT_SEC_CHANGED  0x04
#define SLE_EVT_PWR_CHANGED  0x05
#define SLE_EVT_HW_ERROR     0x06

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

/* ------------------------------------------------------------------ */
/* Test helpers                                                        */
/* ------------------------------------------------------------------ */

static const char *DEVICE = "/dev/sparklink";

static void test_header(const char *name)
{
	printf("\n--- %s ---\n", name);
}

static int check(const char *op, int ret)
{
	if (ret < 0) {
		printf("  FAIL: %s: %s (errno=%d)\n", op, strerror(errno), errno);
		return -1;
	}
	printf("  OK:   %s: ret=%d\n", op, ret);
	return ret;
}

/* ------------------------------------------------------------------ */
/* Test cases                                                         */
/* ------------------------------------------------------------------ */

static void test_dev_count(int fd)
{
	test_header("DEV_COUNT");
	int ret = ioctl(fd, SL_IOCTL_DEV_COUNT, NULL);
	if (ret == 1) {
		printf("  OK:   DEV_COUNT: %d device(s)\n", ret);
	} else {
		printf("  WARN: DEV_COUNT: expected 1, got %d\n", ret);
	}
}

static void test_dev_info(int fd)
{
	test_header("DEV_INFO");
	struct sci_dev_info info;
	memset(&info, 0, sizeof(info));
	int ret = ioctl(fd, SL_IOCTL_DEV_INFO, &info);
	check("DEV_INFO", ret);
	if (ret == 0) {
		printf("  INFO: index=%u state=%u bus=%u addr=%02x:%02x:%02x:%02x:%02x:%02x name=%.32s\n",
		       info.index, info.state, info.bus,
		       info.addr[0], info.addr[1], info.addr[2],
		       info.addr[3], info.addr[4], info.addr[5],
		       info.name);
	}
}

static void test_dev_register(int fd)
{
	test_header("DEV_REGISTER / DEV_UNREGISTER");
	int ret = ioctl(fd, SL_IOCTL_DEV_REGISTER, NULL);
	check("DEV_REGISTER", ret);

	ret = ioctl(fd, SL_IOCTL_DEV_UNREGISTER, NULL);
	check("DEV_UNREGISTER", ret);
}

static void test_advertising(int fd)
{
	test_header("START_ADV / STOP_ADV");

	struct sle_adv_params params;
	memset(&params, 0, sizeof(params));
	params.dev_index = 0;
	params.discovery_level = 1;  /* General discoverable */
	params.interval_ms = 100;

	int ret = ioctl(fd, SL_IOCTL_START_ADV, &params);
	check("START_ADV (general, 100ms)", ret);

	/* Try starting again — should fail with EBUSY */
	ret = ioctl(fd, SL_IOCTL_START_ADV, &params);
	if (ret < 0 && errno == EBUSY) {
		printf("  OK:   START_ADV (duplicate): correctly rejected (EBUSY)\n");
	} else {
		printf("  WARN: START_ADV (duplicate): expected EBUSY, got ret=%d errno=%d\n",
		       ret, errno);
	}

	ret = ioctl(fd, SL_IOCTL_STOP_ADV, NULL);
	check("STOP_ADV", ret);

	/* Try stopping again — should fail */
	ret = ioctl(fd, SL_IOCTL_STOP_ADV, NULL);
	if (ret < 0) {
		printf("  OK:   STOP_ADV (duplicate): correctly rejected (errno=%d)\n", errno);
	} else {
		printf("  WARN: STOP_ADV (duplicate): expected error, got ret=%d\n", ret);
	}
}

static void test_scanning(int fd)
{
	test_header("START_SCAN / STOP_SCAN");

	struct sle_scan_params params;
	memset(&params, 0, sizeof(params));
	params.dev_index = 0;
	params.window_ms = 50;
	params.interval_ms = 100;
	params.filter_discovery_level = 0;  /* Accept all */

	int ret = ioctl(fd, SL_IOCTL_START_SCAN, &params);
	check("START_SCAN (passive, 50/100ms)", ret);

	/* Query scan result count via DEV_COUNT */
	ret = ioctl(fd, SL_IOCTL_DEV_COUNT, NULL);
	check("DEV_COUNT (scan results)", ret);

	ret = ioctl(fd, SL_IOCTL_STOP_SCAN, NULL);
	check("STOP_SCAN", ret);
}

static void test_mutual_exclusion(int fd)
{
	test_header("Mutual exclusion: ADV then SCAN");

	struct sle_adv_params adv;
	memset(&adv, 0, sizeof(adv));
	adv.discovery_level = 2;  /* Priority */
	adv.interval_ms = 200;

	struct sle_scan_params scan;
	memset(&scan, 0, sizeof(scan));
	scan.window_ms = 30;
	scan.interval_ms = 60;

	/* Start advertising */
	int ret = ioctl(fd, SL_IOCTL_START_ADV, &adv);
	check("START_ADV", ret);

	/* Try scanning while advertising — should fail */
	ret = ioctl(fd, SL_IOCTL_START_SCAN, &scan);
	if (ret < 0 && errno == EBUSY) {
		printf("  OK:   START_SCAN (while adv): correctly rejected (EBUSY)\n");
	} else {
		printf("  WARN: START_SCAN (while adv): expected EBUSY, got ret=%d errno=%d\n",
		       ret, errno);
	}

	ret = ioctl(fd, SL_IOCTL_STOP_ADV, NULL);
	check("STOP_ADV", ret);
}

static void test_unknown_ioctl(int fd)
{
	test_header("Unknown IOCTL");
	int ret = ioctl(fd, _IO(SL_MAGIC, 0xFF), NULL);
	if (ret < 0 && errno == ENOTTY) {
		printf("  OK:   Unknown ioctl: correctly rejected (ENOTTY)\n");
	} else {
		printf("  WARN: Unknown ioctl: expected ENOTTY, got ret=%d errno=%d\n",
		       ret, errno);
	}
}

static void test_loopback(int fd)
{
	test_header("Loopback: SCAN + INJECT_ADV");

	/* Start scanning */
	struct sle_scan_params scan;
	memset(&scan, 0, sizeof(scan));
	scan.window_ms = 50;
	scan.interval_ms = 100;
	scan.filter_discovery_level = 0;

	int ret = ioctl(fd, SL_IOCTL_START_SCAN, &scan);
	check("START_SCAN", ret);

	/* Verify no results yet */
	ret = ioctl(fd, SL_IOCTL_SCAN_RESULT_COUNT, NULL);
	check("SCAN_RESULT_COUNT (initial)", ret);
	if (ret != 0)
		printf("  WARN: expected 0 results, got %d\n", ret);

	/* Inject 3 simulated advertisements */
	struct sle_inject_adv inject;

	memset(&inject, 0, sizeof(inject));
	inject.addr[0] = 0xAA; inject.addr[1] = 0xBB; inject.addr[5] = 0x01;
	inject.rssi = -40;
	inject.discovery_level = 1;
	memcpy(inject.name, "dev-alpha", 9);
	inject.name_len = 9;
	ret = ioctl(fd, SL_IOCTL_INJECT_ADV, &inject);
	check("INJECT_ADV #1 (dev-alpha)", ret);

	memset(&inject, 0, sizeof(inject));
	inject.addr[0] = 0xCC; inject.addr[1] = 0xDD; inject.addr[5] = 0x02;
	inject.rssi = -65;
	inject.discovery_level = 2;
	memcpy(inject.name, "dev-beta", 8);
	inject.name_len = 8;
	ret = ioctl(fd, SL_IOCTL_INJECT_ADV, &inject);
	check("INJECT_ADV #2 (dev-beta)", ret);

	memset(&inject, 0, sizeof(inject));
	inject.addr[0] = 0xEE; inject.addr[1] = 0xFF; inject.addr[5] = 0x03;
	inject.rssi = -80;
	inject.discovery_level = 0;  /* Invisible — should still pass filter=0 */
	memcpy(inject.name, "dev-gamma", 9);
	inject.name_len = 9;
	ret = ioctl(fd, SL_IOCTL_INJECT_ADV, &inject);
	check("INJECT_ADV #3 (dev-gamma)", ret);

	/* Verify 3 results */
	ret = ioctl(fd, SL_IOCTL_SCAN_RESULT_COUNT, NULL);
	check("SCAN_RESULT_COUNT (after inject)", ret);
	if (ret == 3) {
		printf("  OK:   Got expected 3 scan results\n");
	} else {
		printf("  WARN: expected 3 results, got %d\n", ret);
	}

	ret = ioctl(fd, SL_IOCTL_STOP_SCAN, NULL);
	check("STOP_SCAN", ret);
}

static void test_loopback_filter(int fd)
{
	test_header("Loopback with discovery level filter");

	struct sle_scan_params scan;
	memset(&scan, 0, sizeof(scan));
	scan.window_ms = 50;
	scan.interval_ms = 100;
	scan.filter_discovery_level = 2;  /* Accept level >= 2 only */

	int ret = ioctl(fd, SL_IOCTL_START_SCAN, &scan);
	check("START_SCAN (filter>=2)", ret);

	/* Inject level=1 — should be filtered */
	struct sle_inject_adv inject;
	memset(&inject, 0, sizeof(inject));
	inject.addr[5] = 0x10;
	inject.rssi = -30;
	inject.discovery_level = 1;
	memcpy(inject.name, "filtered", 8);
	inject.name_len = 8;
	ret = ioctl(fd, SL_IOCTL_INJECT_ADV, &inject);
	check("INJECT_ADV (level=1, should filter)", ret);

	/* Inject level=2 — should pass */
	memset(&inject, 0, sizeof(inject));
	inject.addr[5] = 0x20;
	inject.rssi = -45;
	inject.discovery_level = 2;
	memcpy(inject.name, "accepted", 8);
	inject.name_len = 8;
	ret = ioctl(fd, SL_IOCTL_INJECT_ADV, &inject);
	check("INJECT_ADV (level=2, should pass)", ret);

	ret = ioctl(fd, SL_IOCTL_SCAN_RESULT_COUNT, NULL);
	check("SCAN_RESULT_COUNT", ret);
	if (ret == 1) {
		printf("  OK:   Filter working: 1 result (level=1 filtered out)\n");
	} else {
		printf("  WARN: expected 1 result, got %d\n", ret);
	}

	ret = ioctl(fd, SL_IOCTL_STOP_SCAN, NULL);
	check("STOP_SCAN", ret);
}

static void test_connect(int fd)
{
	test_header("CONNECT / DISCONNECT (multi-connection)");

	struct sle_connect_params cp;
	memset(&cp, 0, sizeof(cp));
	cp.peer_addr[0] = 0xAA;
	cp.peer_addr[1] = 0xBB;
	cp.peer_addr[5] = 0x01;
	cp.gt_role = 0;  /* T node */
	cp.bandwidth = 1;
	cp.mcs_index = 4;
	cp.timeout_10ms = 100;

	/* Connect — should return handle > 0 */
	int ret = ioctl(fd, SL_IOCTL_CONNECT, &cp);
	if (ret <= 0) {
		printf("  FAIL: CONNECT: expected handle > 0, got %d\n", ret);
		return;
	}
	uint16_t handle = (uint16_t)ret;
	printf("  OK:   CONNECT: handle=%u\n", handle);

	/* Verify state via CONN_INFO */
	struct sle_conn_info info;
	memset(&info, 0, sizeof(info));
	info.handle = handle;
	ret = ioctl(fd, SL_IOCTL_CONN_INFO, &info);
	check("CONN_INFO (connecting)", ret);
	if (ret == 0 && info.state == 1) {
		printf("  OK:   state=Connecting (1) handle=%u\n", info.handle);
	} else {
		printf("  WARN: expected state=1, got state=%u\n", info.state);
	}

	/* Connect to same peer again — should fail EEXIST */
	ret = ioctl(fd, SL_IOCTL_CONNECT, &cp);
	if (ret < 0 && errno == EEXIST) {
		printf("  OK:   CONNECT (duplicate): correctly rejected (EEXIST)\n");
	} else {
		printf("  WARN: CONNECT (duplicate): expected EEXIST, got ret=%d errno=%d\n",
		       ret, errno);
	}

	/* Connect to different peer — should succeed (multi-conn) */
	struct sle_connect_params cp2;
	memset(&cp2, 0, sizeof(cp2));
	cp2.peer_addr[0] = 0x11;
	cp2.peer_addr[5] = 0x02;
	cp2.gt_role = 1;  /* G node */
	ret = ioctl(fd, SL_IOCTL_CONNECT, &cp2);
	if (ret > 0) {
		uint16_t handle2 = (uint16_t)ret;
		printf("  OK:   CONNECT (2nd peer): handle=%u\n", handle2);

		/* Check CONN_COUNT */
		ret = ioctl(fd, SL_IOCTL_CONN_COUNT, NULL);
		printf("  OK:   CONN_COUNT: %d active connections\n", ret);

		/* Check CONN_LIST */
		struct sle_conn_list list;
		memset(&list, 0, sizeof(list));
		ret = ioctl(fd, SL_IOCTL_CONN_LIST, &list);
		if (ret == 0) {
			printf("  OK:   CONN_LIST: %u handles:", list.count);
			for (int i = 0; i < list.count; i++)
				printf(" %u", list.handles[i]);
			printf("\n");
		}

		/* Disconnect 2nd handle */
		ret = ioctl(fd, SL_IOCTL_DISCONNECT, &handle2);
		check("DISCONNECT (2nd handle)", ret);
	} else {
		printf("  WARN: CONNECT (2nd peer): expected handle>0, got ret=%d\n", ret);
	}

	/* Disconnect first handle */
	ret = ioctl(fd, SL_IOCTL_DISCONNECT, &handle);
	check("DISCONNECT", ret);

	/* Verify all disconnected */
	ret = ioctl(fd, SL_IOCTL_CONN_COUNT, NULL);
	if (ret == 0) {
		printf("  OK:   CONN_COUNT=0 after all disconnected\n");
	} else {
		printf("  WARN: expected CONN_COUNT=0, got %d\n", ret);
	}
}

static void test_conn_reject(int fd)
{
	test_header("Connection rejection");

	struct sle_connect_params cp;
	memset(&cp, 0, sizeof(cp));
	cp.peer_addr[0] = 0xCC;
	cp.peer_addr[5] = 0x02;
	cp.gt_role = 1;  /* G node */

	int ret = ioctl(fd, SL_IOCTL_CONNECT, &cp);
	if (ret <= 0) {
		printf("  FAIL: CONNECT: expected handle > 0, got %d\n", ret);
		return;
	}
	uint16_t handle = (uint16_t)ret;
	printf("  OK:   CONNECT: handle=%u\n", handle);

	/* Inject rejection response */
	struct sle_inject_conn_resp resp;
	memset(&resp, 0, sizeof(resp));
	resp.handle = handle;
	resp.response_type = 3;  /* UserRejected */

	ret = ioctl(fd, SL_IOCTL_INJECT_CONN_RESP, &resp);
	if (ret < 0 && errno == EACCES) {
		printf("  OK:   INJECT_CONN_RESP (rejected): got EACCES\n");
	} else {
		printf("  WARN: expected EACCES, got ret=%d errno=%d\n",
		       ret, errno);
	}

	/* Connection entry should be removed after rejection.
	 * CONN_COUNT should be 0. */
	ret = ioctl(fd, SL_IOCTL_CONN_COUNT, NULL);
	if (ret == 0) {
		printf("  OK:   CONN_COUNT=0 after rejection\n");
	} else {
		printf("  WARN: expected CONN_COUNT=0, got %d\n", ret);
	}
}

static void test_conn_data_loopback(int fd)
{
	test_header("Connection data loopback");

	/* Step 1: Connect */
	struct sle_connect_params cp;
	memset(&cp, 0, sizeof(cp));
	cp.peer_addr[0] = 0xDD;
	cp.peer_addr[5] = 0x03;
	cp.gt_role = 0;

	int ret = ioctl(fd, SL_IOCTL_CONNECT, &cp);
	if (ret <= 0) {
		printf("  FAIL: CONNECT: expected handle > 0, got %d\n", ret);
		return;
	}
	uint16_t handle = (uint16_t)ret;
	printf("  OK:   CONNECT: handle=%u\n", handle);

	/* Step 2: Accept connection via injected response */
	struct sle_inject_conn_resp resp;
	memset(&resp, 0, sizeof(resp));
	resp.handle = handle;
	resp.response_type = 0;  /* Accepted */
	resp.bandwidth_mhz = 2;
	resp.mcs_index = 6;
	resp.supervision_timeout = 200;

	ret = ioctl(fd, SL_IOCTL_INJECT_CONN_RESP, &resp);
	check("INJECT_CONN_RESP (accepted)", ret);

	/* Step 3: Verify Connected state and negotiated params */
	struct sle_conn_info info;
	memset(&info, 0, sizeof(info));
	info.handle = handle;
	ret = ioctl(fd, SL_IOCTL_CONN_INFO, &info);
	check("CONN_INFO (connected)", ret);
	if (ret == 0) {
		printf("  handle=%u state=%u role=%u bw=%u mcs=%u timeout=%u\n",
		       info.handle, info.state, info.local_role, info.bandwidth_mhz,
		       info.mcs_index, info.supervision_timeout);
		if (info.state != 2)
			printf("  WARN: expected state=2 (Connected)\n");
		if (info.bandwidth_mhz != 2)
			printf("  WARN: expected bw=2\n");
		if (info.mcs_index != 6)
			printf("  WARN: expected mcs=6\n");
	}

	/* Step 4: Send data */
	struct sle_conn_data sd;
	memset(&sd, 0, sizeof(sd));
	sd.handle = handle;
	const char *msg = "Hello SparkLink!";
	sd.length = strlen(msg);
	memcpy(sd.data, msg, sd.length);
	ret = ioctl(fd, SL_IOCTL_CONN_SEND, &sd);
	check("CONN_SEND", ret);

	/* Step 5: Inject received data (simulating peer sending back) */
	struct sle_conn_data rd;
	memset(&rd, 0, sizeof(rd));
	rd.handle = handle;
	const char *reply = "ACK from peer";
	rd.length = strlen(reply);
	memcpy(rd.data, reply, rd.length);
	ret = ioctl(fd, SL_IOCTL_INJECT_CONN_DATA, &rd);
	check("INJECT_CONN_DATA", ret);

	/* Step 6: Receive the injected data */
	struct sle_conn_data recv_buf;
	memset(&recv_buf, 0, sizeof(recv_buf));
	recv_buf.handle = handle;
	ret = ioctl(fd, SL_IOCTL_CONN_RECV, &recv_buf);
	check("CONN_RECV", ret);
	if (ret == 0 && recv_buf.length == strlen(reply) &&
	    memcmp(recv_buf.data, reply, recv_buf.length) == 0) {
		printf("  OK:   Received data matches: \"%.*s\"\n",
		       recv_buf.length, recv_buf.data);
	} else {
		printf("  WARN: data mismatch: len=%u\n", recv_buf.length);
	}

	/* Step 7: Try to receive again — should fail EAGAIN */
	memset(&recv_buf, 0, sizeof(recv_buf));
	recv_buf.handle = handle;
	ret = ioctl(fd, SL_IOCTL_CONN_RECV, &recv_buf);
	if (ret < 0 && errno == EAGAIN) {
		printf("  OK:   CONN_RECV (empty): correctly got EAGAIN\n");
	} else {
		printf("  WARN: expected EAGAIN, got ret=%d errno=%d\n", ret, errno);
	}

	/* Step 8: Check stats */
	memset(&info, 0, sizeof(info));
	info.handle = handle;
	ret = ioctl(fd, SL_IOCTL_CONN_INFO, &info);
	if (ret == 0) {
		printf("  stats: tx_bytes=%lu rx_bytes=%lu tx_pend=%u rx_pend=%u\n",
		       (unsigned long)info.tx_bytes, (unsigned long)info.rx_bytes,
		       info.tx_pending, info.rx_pending);
	}

	/* Step 9: Disconnect */
	ret = ioctl(fd, SL_IOCTL_DISCONNECT, &handle);
	check("DISCONNECT", ret);

	/* Step 10: Try to send after disconnect — should fail ENOENT (handle gone) */
	memset(&sd, 0, sizeof(sd));
	sd.handle = handle;
	sd.length = 5;
	memcpy(sd.data, "bad", 3);
	ret = ioctl(fd, SL_IOCTL_CONN_SEND, &sd);
	if (ret < 0 && errno == ENOENT) {
		printf("  OK:   CONN_SEND (disconnected): correctly got ENOENT\n");
	} else {
		printf("  WARN: expected ENOENT, got ret=%d errno=%d\n", ret, errno);
	}
}

static void test_sm3_hash(int fd)
{
	test_header("SM3 hash test");

	/* SM3("abc") test vector from GB/T 32905-2016 A.1 */
	struct sle_hash_test ht;
	memset(&ht, 0, sizeof(ht));
	memcpy(ht.data, "abc", 3);
	ht.in_len = 3;

	int ret = ioctl(fd, SL_IOCTL_SEC_SM3_TEST, &ht);
	check("SEC_SM3_TEST", ret);

	if (ret == 0) {
		printf("  SM3(\"abc\") = ");
		for (int i = 0; i < 32; i++)
			printf("%02x", ht.digest[i]);
		printf("\n");

		/* Expected: 66c7f0f4 62eeedd9 d1f2d46b dc10e4e2
		 *           4167c487 5cf2f7a2 297da02b 8f4ba8e0 */
		const uint8_t expected[32] = {
			0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
			0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
			0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
			0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
		};
		if (memcmp(ht.digest, expected, 32) == 0) {
			printf("  OK:   SM3 test vector matches\n");
		} else {
			printf("  FAIL: SM3 test vector mismatch!\n");
		}
	}
}

static void test_security_pairing(int fd)
{
	test_header("Security: PSK pairing and encryption");

	/* Step 1: Set PSK */
	struct sle_psk_params psk;
	memset(&psk, 0, sizeof(psk));
	for (int i = 0; i < 16; i++)
		psk.psk[i] = (uint8_t)i;

	int ret = ioctl(fd, SL_IOCTL_SEC_SET_PSK, &psk);
	check("SEC_SET_PSK", ret);

	/* Step 2: Pair using PSK */
	struct sle_pair_params pair;
	memset(&pair, 0, sizeof(pair));
	pair.method = 2;  /* PSK */

	ret = ioctl(fd, SL_IOCTL_SEC_PAIR, &pair);
	check("SEC_PAIR (PSK)", ret);

	/* Step 3: Check security info */
	struct sle_sec_info sec;
	memset(&sec, 0, sizeof(sec));
	ret = ioctl(fd, SL_IOCTL_SEC_INFO, &sec);
	check("SEC_INFO", ret);
	if (ret == 0) {
		printf("  state=%u method=%u mode=%u enc=%u fingerprint=%02x%02x%02x%02x\n",
		       sec.state, sec.method, sec.mode, sec.enc_enabled,
		       sec.enc_key_fingerprint[0], sec.enc_key_fingerprint[1],
		       sec.enc_key_fingerprint[2], sec.enc_key_fingerprint[3]);
		if (sec.state != 2)
			printf("  WARN: expected state=2 (Paired)\n");
		if (sec.method != 2)
			printf("  WARN: expected method=2 (PSK)\n");
	}

	/* Step 4: Enable encryption */
	ret = ioctl(fd, SL_IOCTL_SEC_ENCRYPT_ON, NULL);
	check("SEC_ENCRYPT_ON", ret);

	/* Step 5: Verify encrypted state */
	memset(&sec, 0, sizeof(sec));
	ret = ioctl(fd, SL_IOCTL_SEC_INFO, &sec);
	if (ret == 0 && sec.enc_enabled == 1) {
		printf("  OK:   Encryption enabled (state=%u)\n", sec.state);
	} else {
		printf("  WARN: expected enc_enabled=1\n");
	}

	/* Step 6: SM4 encrypt-decrypt roundtrip */
	struct sle_conn_data enc_data;
	memset(&enc_data, 0, sizeof(enc_data));
	const char *plaintext = "SLE test data 123";
	enc_data.length = strlen(plaintext);
	memcpy(enc_data.data, plaintext, enc_data.length);

	uint8_t original[255];
	memcpy(original, enc_data.data, enc_data.length);

	ret = ioctl(fd, SL_IOCTL_SEC_SM4_ENC_TEST, &enc_data);
	check("SEC_SM4_ENC_TEST", ret);

	if (ret == 0) {
		if (memcmp(enc_data.data, original, enc_data.length) != 0) {
			printf("  OK:   Data encrypted (differs from original)\n");
		} else {
			printf("  WARN: encrypted data same as original!\n");
		}

		ret = ioctl(fd, SL_IOCTL_SEC_SM4_DEC_TEST, &enc_data);
		check("SEC_SM4_DEC_TEST", ret);

		if (ret == 0 && memcmp(enc_data.data, original, enc_data.length) == 0) {
			printf("  OK:   Decrypt roundtrip matches: \"%.*s\"\n",
			       enc_data.length, enc_data.data);
		} else {
			printf("  FAIL: decrypt roundtrip mismatch!\n");
		}
	}
}

static void test_ssap_service(int fd)
{
	test_header("SSAP: service registration and property access");

	/* Step 1: Register built-in device info service */
	int ret = ioctl(fd, SL_IOCTL_SSAP_REGISTER_SVC, NULL);
	check("SSAP_REGISTER_SVC", ret);

	/* Step 2: Get SSAP summary info */
	struct ssap_summary info;
	memset(&info, 0, sizeof(info));
	ret = ioctl(fd, SL_IOCTL_SSAP_INFO, &info);
	check("SSAP_INFO", ret);
	if (ret == 0) {
		printf("  services=%u properties=%u total_entries=%u mtu=%u notifications=%u\n",
		       info.service_count, info.property_count, info.total_entries,
		       info.mtu, info.notification_count);
		if (info.service_count != 1)
			printf("  WARN: expected 1 service\n");
		if (info.property_count != 3)
			printf("  WARN: expected 3 properties\n");
	}

	/* Step 3: Find primary services */
	struct ssap_service_list slist;
	memset(&slist, 0, sizeof(slist));
	ret = ioctl(fd, SL_IOCTL_SSAP_FIND_SVC, &slist);
	check("SSAP_FIND_SVC", ret);
	if (ret == 0) {
		printf("  found %u primary services\n", slist.count);
		for (int i = 0; i < slist.count && i < 15; i++) {
			printf("    svc[%d]: handle=%u-%u uuid=0x%04x primary=%u\n",
			       i, slist.services[i].start_handle,
			       slist.services[i].end_handle,
			       slist.services[i].uuid16,
			       slist.services[i].primary);
		}
	}

	/* Step 4: Read device name property (handle 0x0011) */
	struct ssap_read_write rw;
	memset(&rw, 0, sizeof(rw));
	rw.handle = 0x0011;
	ret = ioctl(fd, SL_IOCTL_SSAP_READ, &rw);
	check("SSAP_READ (device_name)", ret);
	if (ret == 0) {
		printf("  device_name[%u]: \"%.*s\"\n", rw.length, rw.length, rw.data);
	}

	/* Step 5: Read firmware version (handle 0x0012) */
	memset(&rw, 0, sizeof(rw));
	rw.handle = 0x0012;
	ret = ioctl(fd, SL_IOCTL_SSAP_READ, &rw);
	check("SSAP_READ (fw_version)", ret);
	if (ret == 0) {
		printf("  fw_version[%u]: \"%.*s\"\n", rw.length, rw.length, rw.data);
	}

	/* Step 6: Write status property (handle 0x0013) */
	memset(&rw, 0, sizeof(rw));
	rw.handle = 0x0013;
	rw.length = 1;
	rw.data[0] = 0x42;
	ret = ioctl(fd, SL_IOCTL_SSAP_WRITE, &rw);
	check("SSAP_WRITE (status)", ret);

	/* Step 7: Read back the written value */
	memset(&rw, 0, sizeof(rw));
	rw.handle = 0x0013;
	ret = ioctl(fd, SL_IOCTL_SSAP_READ, &rw);
	check("SSAP_READ (status readback)", ret);
	if (ret == 0 && rw.length == 1 && rw.data[0] == 0x42) {
		printf("  OK:   Status readback matches: 0x%02x\n", rw.data[0]);
	} else if (ret == 0) {
		printf("  FAIL: Status readback mismatch: len=%u data[0]=0x%02x\n",
		       rw.length, rw.data[0]);
	}

	/* Step 8: Check notification was generated from the write */
	struct ssap_summary info2;
	memset(&info2, 0, sizeof(info2));
	ret = ioctl(fd, SL_IOCTL_SSAP_INFO, &info2);
	if (ret == 0 && info2.notification_count > 0) {
		printf("  OK:   %u notification(s) pending after write\n",
		       info2.notification_count);

		/* Dequeue the notification */
		struct ssap_notification ntf;
		memset(&ntf, 0, sizeof(ntf));
		ret = ioctl(fd, SL_IOCTL_SSAP_DEQUEUE_NTF, &ntf);
		check("SSAP_DEQUEUE_NTF", ret);
		if (ret == 0) {
			printf("  notification: handle=0x%04x ind=%u len=%u data[0]=0x%02x\n",
			       ntf.handle, ntf.indication, ntf.length,
			       ntf.length > 0 ? ntf.data[0] : 0);
		}
	} else {
		printf("  INFO: no notifications pending\n");
	}

	/* Step 9: Try reading non-existent handle */
	memset(&rw, 0, sizeof(rw));
	rw.handle = 0xFFFF;
	ret = ioctl(fd, SL_IOCTL_SSAP_READ, &rw);
	if (ret < 0) {
		printf("  OK:   Read invalid handle: correctly rejected (errno=%d)\n", errno);
	} else {
		printf("  WARN: expected error for invalid handle\n");
	}
}

static void test_power_management(int fd)
{
	test_header("Power management: state transitions and intervals");

	/* Step 1: Get initial PM info */
	struct sle_pm_info pm;
	memset(&pm, 0, sizeof(pm));
	int ret = ioctl(fd, SL_IOCTL_PM_INFO, &pm);
	check("PM_INFO (initial)", ret);
	if (ret == 0) {
		printf("  state=%u force_active=%u power=%u%% interval=%u timeout=%u\n",
		       pm.state, pm.force_active, pm.power_pct,
		       pm.current_interval, pm.supervision_timeout);
		if (pm.state != 0)
			printf("  WARN: expected state=0 (Active)\n");
	}

	/* Step 2: Update connection interval */
	struct sle_pm_interval intv = {
		.min_interval = 16,   /* 20 ms */
		.max_interval = 80,   /* 100 ms */
		.latency = 2,
		.supervision_timeout = 400,  /* 4 s */
	};
	ret = ioctl(fd, SL_IOCTL_PM_SET_INTERVAL, &intv);
	check("PM_SET_INTERVAL", ret);

	/* Step 3: Verify updated interval */
	memset(&pm, 0, sizeof(pm));
	ret = ioctl(fd, SL_IOCTL_PM_INFO, &pm);
	if (ret == 0 && pm.current_interval == 16) {
		printf("  OK:   Interval updated to %u (%.1f ms)\n",
		       pm.current_interval, pm.current_interval * 1.25);
	} else if (ret == 0) {
		printf("  WARN: expected interval=16, got %u\n", pm.current_interval);
	}

	/* Step 4: Simulate ticks to trigger sniff transition */
	for (int i = 0; i < 55; i++)
		ioctl(fd, SL_IOCTL_PM_TICK, NULL);

	memset(&pm, 0, sizeof(pm));
	ret = ioctl(fd, SL_IOCTL_PM_INFO, &pm);
	if (ret == 0) {
		printf("  After 55 ticks: state=%u power=%u%% transitions=%u\n",
		       pm.state, pm.power_pct, pm.transitions);
		if (pm.state == 1)
			printf("  OK:   Entered Sniff mode\n");
	}

	/* Step 5: Record activity — should return to Active */
	ret = ioctl(fd, SL_IOCTL_PM_ACTIVITY, NULL);
	check("PM_ACTIVITY", ret);

	memset(&pm, 0, sizeof(pm));
	ret = ioctl(fd, SL_IOCTL_PM_INFO, &pm);
	if (ret == 0 && pm.state == 0) {
		printf("  OK:   Returned to Active after activity\n");
	}

	/* Step 6: Force active, then try suspend — should fail */
	uint8_t fa = 1;
	ret = ioctl(fd, SL_IOCTL_PM_FORCE_ACTIVE, &fa);
	check("PM_FORCE_ACTIVE(1)", ret);

	struct sle_pm_state_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.target_state = 3; /* Suspend */
	ret = ioctl(fd, SL_IOCTL_PM_SET_STATE, &cmd);
	if (ret < 0 && errno == EBUSY) {
		printf("  OK:   Suspend rejected during force-active (EBUSY)\n");
	} else {
		printf("  WARN: expected EBUSY, got ret=%d errno=%d\n", ret, errno);
	}

	/* Step 7: Clear force-active and suspend */
	fa = 0;
	ioctl(fd, SL_IOCTL_PM_FORCE_ACTIVE, &fa);

	cmd.target_state = 3;
	ret = ioctl(fd, SL_IOCTL_PM_SET_STATE, &cmd);
	check("PM_SET_STATE (suspend)", ret);

	memset(&pm, 0, sizeof(pm));
	ret = ioctl(fd, SL_IOCTL_PM_INFO, &pm);
	if (ret == 0 && pm.state == 3) {
		printf("  OK:   Suspended (power=%u%%)\n", pm.power_pct);
	}

	/* Step 8: Resume */
	cmd.target_state = 0;
	ret = ioctl(fd, SL_IOCTL_PM_SET_STATE, &cmd);
	check("PM_SET_STATE (resume)", ret);

	memset(&pm, 0, sizeof(pm));
	ret = ioctl(fd, SL_IOCTL_PM_INFO, &pm);
	if (ret == 0 && pm.state == 0) {
		printf("  OK:   Resumed to Active (transitions=%u)\n", pm.transitions);
	}
}

static void test_event_notification(int fd)
{
	test_header("Event notification: read() and EVENT_COUNT");

	/* Step 1: Verify empty event queue */
	int ret = ioctl(fd, SL_IOCTL_EVENT_COUNT, NULL);
	if (ret == 0) {
		printf("  OK:   EVENT_COUNT=0 (initial)\n");
	} else {
		printf("  WARN: expected EVENT_COUNT=0, got %d\n", ret);
	}

	/* Step 2: read() on empty queue should return EAGAIN */
	struct sle_wire_event evt;
	ssize_t n = read(fd, &evt, sizeof(evt));
	if (n < 0 && errno == EAGAIN) {
		printf("  OK:   read() empty queue: EAGAIN\n");
	} else {
		printf("  WARN: expected EAGAIN, got n=%zd errno=%d\n", n, errno);
	}

	/* Step 3: Trigger events via connect + inject adv */
	struct sle_connect_params cp;
	memset(&cp, 0, sizeof(cp));
	cp.peer_addr[0] = 0xEE;
	cp.peer_addr[5] = 0xAA;
	cp.gt_role = 0;
	cp.bandwidth = 1;
	cp.mcs_index = 4;
	cp.timeout_10ms = 100;
	ret = ioctl(fd, SL_IOCTL_CONNECT, &cp);
	uint16_t handle = 0;
	if (ret > 0) {
		handle = (uint16_t)ret;
		printf("  OK:   CONNECT generated event (handle=%u)\n", handle);
	} else {
		printf("  FAIL: CONNECT failed\n");
		return;
	}

	/* Start scanning and inject an adv to generate AdvReport event */
	struct sle_scan_params scan;
	memset(&scan, 0, sizeof(scan));
	scan.window_ms = 50;
	scan.interval_ms = 100;
	ioctl(fd, SL_IOCTL_START_SCAN, &scan);

	struct sle_inject_adv inject;
	memset(&inject, 0, sizeof(inject));
	inject.addr[0] = 0xBB;
	inject.addr[5] = 0xCC;
	inject.rssi = -55;
	inject.discovery_level = 1;
	memcpy(inject.name, "evt-test", 8);
	inject.name_len = 8;
	ioctl(fd, SL_IOCTL_INJECT_ADV, &inject);

	ioctl(fd, SL_IOCTL_STOP_SCAN, NULL);

	/* Step 4: Check event count (should have >= 2: ConnState + AdvReport) */
	ret = ioctl(fd, SL_IOCTL_EVENT_COUNT, NULL);
	printf("  OK:   EVENT_COUNT=%d after connect+inject_adv\n", ret);
	if (ret < 2) {
		printf("  WARN: expected >= 2 events\n");
	}

	/* Step 5: Read events via read() */
	int total_read = 0;
	int got_conn = 0, got_adv = 0;
	while (total_read < 10) {
		memset(&evt, 0, sizeof(evt));
		n = read(fd, &evt, sizeof(evt));
		if (n < 0) {
			if (errno == EAGAIN)
				break;
			printf("  FAIL: read() error: %s\n", strerror(errno));
			break;
		}
		if (n == 0)
			break;
		total_read++;
		switch (evt.event_type) {
		case SLE_EVT_CONN_STATE:
			got_conn = 1;
			printf("  event: ConnStateChanged (payload_len=%u)\n",
			       evt.payload_len);
			break;
		case SLE_EVT_ADV_REPORT:
			got_adv = 1;
			printf("  event: AdvReport (payload_len=%u)\n",
			       evt.payload_len);
			break;
		default:
			printf("  event: type=0x%02x (payload_len=%u)\n",
			       evt.event_type, evt.payload_len);
			break;
		}
	}

	if (got_conn)
		printf("  OK:   Got ConnStateChanged event\n");
	else
		printf("  WARN: Missing ConnStateChanged event\n");

	if (got_adv)
		printf("  OK:   Got AdvReport event\n");
	else
		printf("  WARN: Missing AdvReport event\n");

	/* Step 6: Verify queue is now empty */
	ret = ioctl(fd, SL_IOCTL_EVENT_COUNT, NULL);
	if (ret == 0) {
		printf("  OK:   EVENT_COUNT=0 after draining\n");
	} else {
		printf("  WARN: expected EVENT_COUNT=0 after drain, got %d\n", ret);
	}

	/* Cleanup: disconnect */
	ioctl(fd, SL_IOCTL_DISCONNECT, &handle);
}

static void test_event_stats(int fd)
{
	test_header("Event Queue Statistics");

	struct sle_event_stats stats;
	memset(&stats, 0, sizeof(stats));
	int ret = ioctl(fd, SL_IOCTL_EVENT_STATS, &stats);
	if (ret != 0) {
		printf("  FAIL: EVENT_STATS ioctl: %s\n", strerror(errno));
		return;
	}
	printf("  Pending:   %u\n", stats.pending);
	printf("  Enqueued:  %lu\n", (unsigned long)stats.total_enqueued);
	printf("  Dropped:   %lu\n", (unsigned long)stats.total_dropped);
	printf("  Delivered: %lu\n", (unsigned long)stats.total_delivered);
	printf("  OK:   EVENT_STATS returned successfully\n");
}

static void test_dli_info(int fd)
{
	test_header("DLI Controller Info");

	struct sle_dli_info dli;
	memset(&dli, 0, sizeof(dli));
	int ret = ioctl(fd, SL_IOCTL_DLI_INFO, &dli);
	if (ret != 0) {
		printf("  FAIL: DLI_INFO ioctl: %s\n", strerror(errno));
		return;
	}
	printf("  Name:         %.32s\n", dli.name);
	printf("  Bus:          %u\n", dli.bus);

	unsigned major = (dli.firmware_version >> 16) & 0xFF;
	unsigned minor = (dli.firmware_version >> 8) & 0xFF;
	unsigned patch = dli.firmware_version & 0xFF;
	printf("  Firmware:     %u.%u.%u\n", major, minor, patch);
	printf("  Features:     0x%016lx\n", (unsigned long)dli.features);
	printf("  Max conns:    %u\n", dli.max_connections);

	/* Virtual controller should be bus=0 */
	if (dli.bus == 0)
		printf("  OK:   bus=Virtual\n");
	else
		printf("  WARN: unexpected bus %u\n", dli.bus);

	/* Features should be non-zero */
	if (dli.features != 0)
		printf("  OK:   features=0x%lx\n", (unsigned long)dli.features);
	else
		printf("  WARN: features=0\n");

	/* Max connections should be > 0 */
	if (dli.max_connections > 0)
		printf("  OK:   max_connections=%u\n", dli.max_connections);
	else
		printf("  FAIL: max_connections=0\n");
}

static void test_poll_epoll(int fd)
{
	test_header("poll/epoll event notification");

	/* Step 1: poll on empty queue — should timeout immediately */
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int ret = poll(&pfd, 1, 0);
	if (ret == 0) {
		printf("  OK:   poll() returns 0 on empty queue\n");
	} else {
		printf("  WARN: poll() returned %d on empty queue (expected 0)\n", ret);
	}

	/* Step 2: Trigger an event (connect) */
	struct sle_connect_params cp;
	memset(&cp, 0, sizeof(cp));
	cp.peer_addr[0] = 0xBB;
	cp.peer_addr[5] = 0xBB;
	uint16_t handle = 0;
	ret = ioctl(fd, SL_IOCTL_CONNECT, &cp);
	if (ret > 0) {
		handle = (uint16_t)ret;
		printf("  OK:   connected handle=%u\n", handle);
	} else {
		printf("  FAIL: connect failed (%d)\n", ret);
		return;
	}

	/* Step 3: poll should now return POLLIN */
	pfd.revents = 0;
	ret = poll(&pfd, 1, 0);
	if (ret == 1 && (pfd.revents & POLLIN)) {
		printf("  OK:   poll() returns POLLIN after event\n");
	} else {
		printf("  WARN: poll() returned %d, revents=0x%x\n", ret, pfd.revents);
	}

	/* Step 4: Drain events via read() */
	struct sle_wire_event evt;
	while (read(fd, &evt, sizeof(evt)) > 0)
		;

	/* Step 5: poll should return 0 after drain */
	pfd.revents = 0;
	ret = poll(&pfd, 1, 0);
	if (ret == 0) {
		printf("  OK:   poll() returns 0 after drain\n");
	} else {
		printf("  WARN: poll() returned %d after drain\n", ret);
	}

	/* Cleanup */
	ioctl(fd, SL_IOCTL_DISCONNECT, &handle);
}

/* ------------------------------------------------------------------ */
/* Test 21: Ring buffer stress test                                    */
/* ------------------------------------------------------------------ */

static void test_ring_buffer_stress(int fd)
{
	test_header("Ring buffer: stress fill and drain");
	int i, ret;
	struct sle_wire_event evt;
	ssize_t n;

	/* Step 1: drain any leftover events */
	while (read(fd, &evt, sizeof(evt)) > 0)
		;

	ret = ioctl(fd, SL_IOCTL_EVENT_COUNT, NULL);
	if (ret != 0) {
		printf("  WARN: queue not empty before stress, count=%d\n", ret);
		return;
	}

	/* Step 2: start scanning so we can inject advs to generate events */
	struct sle_scan_params scan;
	memset(&scan, 0, sizeof(scan));
	scan.window_ms = 50;
	scan.interval_ms = 100;
	ioctl(fd, SL_IOCTL_START_SCAN, &scan);

	/* Step 3: inject 80 events (exceeds 64-slot ring buffer) */
	for (i = 0; i < 80; i++) {
		struct sle_inject_adv inject;
		memset(&inject, 0, sizeof(inject));
		inject.addr[0] = 0xA0 + (i & 0x0F);
		inject.addr[5] = (uint8_t)(i >> 4);
		inject.rssi = -40 - (i % 20);
		inject.discovery_level = 1;
		inject.name_len = 4;
		memcpy(inject.name, "ring", 4);
		ioctl(fd, SL_IOCTL_INJECT_ADV, &inject);
	}

	ioctl(fd, SL_IOCTL_STOP_SCAN, NULL);

	/* Step 4: count should be capped at 64 */
	ret = ioctl(fd, SL_IOCTL_EVENT_COUNT, NULL);
	if (ret == 64) {
		printf("  OK:   pending=%d (capped at ring buffer size)\n", ret);
	} else {
		printf("  WARN: expected pending=64, got %d\n", ret);
	}

	/* Step 5: check stats — should show 80 enqueued, 16 dropped */
	struct sle_event_stats stats;
	memset(&stats, 0, sizeof(stats));
	ioctl(fd, SL_IOCTL_EVENT_STATS, &stats);
	printf("  stats: enqueued=%lu dropped=%lu delivered=%lu\n",
	       (unsigned long)stats.total_enqueued,
	       (unsigned long)stats.total_dropped,
	       (unsigned long)stats.total_delivered);
	if (stats.total_dropped >= 16) {
		printf("  OK:   dropped >= 16 (oldest events evicted)\n");
	} else {
		printf("  WARN: expected >= 16 drops, got %lu\n",
		       (unsigned long)stats.total_dropped);
	}

	/* Step 6: drain all events, verify we get exactly 64 */
	int drained = 0;
	while (drained < 100) {
		n = read(fd, &evt, sizeof(evt));
		if (n < 0) {
			if (errno == EAGAIN)
				break;
			printf("  FAIL: read error: %s\n", strerror(errno));
			break;
		}
		if (n == 0)
			break;
		drained++;
	}
	if (drained == 64) {
		printf("  OK:   drained=%d events (full ring buffer)\n", drained);
	} else {
		printf("  WARN: expected 64 drained, got %d\n", drained);
	}

	/* Step 7: queue must be empty now */
	ret = ioctl(fd, SL_IOCTL_EVENT_COUNT, NULL);
	if (ret == 0) {
		printf("  OK:   queue empty after full drain\n");
	} else {
		printf("  WARN: expected 0, got %d\n", ret);
	}
}

static void test_multi_conn_concurrent(int fd)
{
	test_header("Multi-connection: concurrent data exchange");

	uint16_t handles[3];
	int i;

	/* Step 1: Create 3 connections to different peers */
	for (i = 0; i < 3; i++) {
		struct sle_connect_params cp;
		memset(&cp, 0, sizeof(cp));
		cp.peer_addr[0] = 0xF0 + i;
		cp.peer_addr[5] = 0x10 + i;
		cp.gt_role = 0;
		cp.bandwidth = 1;
		cp.mcs_index = 4;
		cp.timeout_10ms = 100;

		int ret = ioctl(fd, SL_IOCTL_CONNECT, &cp);
		if (ret <= 0) {
			printf("  FAIL: CONNECT #%d: ret=%d\n", i, ret);
			goto cleanup;
		}
		handles[i] = (uint16_t)ret;
		printf("  OK:   CONNECT #%d: handle=%u\n", i, handles[i]);
	}

	/* Step 2: Accept all connections */
	for (i = 0; i < 3; i++) {
		struct sle_inject_conn_resp resp;
		memset(&resp, 0, sizeof(resp));
		resp.handle = handles[i];
		resp.response_type = 0;
		resp.bandwidth_mhz = 2;
		resp.mcs_index = 4 + i;
		resp.supervision_timeout = 100;

		int ret = ioctl(fd, SL_IOCTL_INJECT_CONN_RESP, &resp);
		check("INJECT_CONN_RESP", ret);
	}

	/* Step 3: Verify CONN_COUNT */
	int ret = ioctl(fd, SL_IOCTL_CONN_COUNT, NULL);
	if (ret == 3) {
		printf("  OK:   CONN_COUNT=3\n");
	} else {
		printf("  WARN: expected CONN_COUNT=3, got %d\n", ret);
	}

	/* Step 4: Send unique data on each connection */
	for (i = 0; i < 3; i++) {
		struct sle_conn_data sd;
		memset(&sd, 0, sizeof(sd));
		sd.handle = handles[i];
		char msg[32];
		int len = snprintf(msg, sizeof(msg), "data-conn-%d", i);
		sd.length = len;
		memcpy(sd.data, msg, len);

		ret = ioctl(fd, SL_IOCTL_CONN_SEND, &sd);
		if (ret < 0)
			printf("  FAIL: CONN_SEND handle=%u: %s\n",
			       handles[i], strerror(errno));
	}

	/* Step 5: Inject receive data on each connection */
	for (i = 0; i < 3; i++) {
		struct sle_conn_data rd;
		memset(&rd, 0, sizeof(rd));
		rd.handle = handles[i];
		char msg[32];
		int len = snprintf(msg, sizeof(msg), "reply-%d", i);
		rd.length = len;
		memcpy(rd.data, msg, len);

		ioctl(fd, SL_IOCTL_INJECT_CONN_DATA, &rd);
	}

	/* Step 6: Receive and verify data on each connection */
	int match_count = 0;
	for (i = 0; i < 3; i++) {
		struct sle_conn_data recv_buf;
		memset(&recv_buf, 0, sizeof(recv_buf));
		recv_buf.handle = handles[i];

		ret = ioctl(fd, SL_IOCTL_CONN_RECV, &recv_buf);
		if (ret == 0) {
			char expected[32];
			int exp_len = snprintf(expected, sizeof(expected),
					       "reply-%d", i);
			if (recv_buf.length == (uint16_t)exp_len &&
			    memcmp(recv_buf.data, expected, exp_len) == 0) {
				match_count++;
			} else {
				printf("  WARN: handle=%u data mismatch\n",
				       handles[i]);
			}
		} else {
			printf("  FAIL: CONN_RECV handle=%u: %s\n",
			       handles[i], strerror(errno));
		}
	}
	printf("  OK:   %d/3 connections data matched\n", match_count);

	/* Step 7: Check per-connection stats */
	for (i = 0; i < 3; i++) {
		struct sle_conn_info info;
		memset(&info, 0, sizeof(info));
		info.handle = handles[i];
		ret = ioctl(fd, SL_IOCTL_CONN_INFO, &info);
		if (ret == 0) {
			printf("  handle=%u: tx=%lu rx=%lu mcs=%u\n",
			       info.handle,
			       (unsigned long)info.tx_bytes,
			       (unsigned long)info.rx_bytes,
			       info.mcs_index);
		}
	}

cleanup:
	/* Step 8: Disconnect all */
	for (i = 0; i < 3; i++)
		ioctl(fd, SL_IOCTL_DISCONNECT, &handles[i]);

	ret = ioctl(fd, SL_IOCTL_CONN_COUNT, NULL);
	if (ret == 0) {
		printf("  OK:   All connections cleaned up\n");
	} else {
		printf("  WARN: CONN_COUNT=%d after cleanup\n", ret);
	}
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
	printf("SparkLink userspace test program\n");
	printf("Device: %s\n", DEVICE);

	int fd = open(DEVICE, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n", DEVICE, strerror(errno));
		fprintf(stderr, "Make sure the sparklink module is loaded and "
			"you have appropriate permissions.\n");
		return 1;
	}
	printf("Opened %s (fd=%d)\n", DEVICE, fd);

	test_dev_count(fd);
	test_dev_info(fd);
	test_dev_register(fd);
	test_advertising(fd);
	test_scanning(fd);
	test_mutual_exclusion(fd);
	test_loopback(fd);
	test_loopback_filter(fd);
	test_connect(fd);
	test_conn_reject(fd);
	test_conn_data_loopback(fd);
	test_sm3_hash(fd);
	test_security_pairing(fd);
	test_ssap_service(fd);
	test_power_management(fd);
	test_unknown_ioctl(fd);
	test_event_notification(fd);
	test_event_stats(fd);
	test_dli_info(fd);
	test_poll_epoll(fd);
	test_ring_buffer_stress(fd);
	test_multi_conn_concurrent(fd);

	printf("\n=== All tests completed ===\n");

	close(fd);
	return 0;
}
