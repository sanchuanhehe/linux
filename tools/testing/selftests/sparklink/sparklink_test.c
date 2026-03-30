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

/* ------------------------------------------------------------------ */
/* IOCTL definitions — must match sparklink_core.rs                   */
/* ------------------------------------------------------------------ */

#define SL_MAGIC 'S'

/* _IO / _IOW / _IOR are defined in <sys/ioctl.h> via <asm/ioctl.h> */
#define SL_IOCTL_DEV_REGISTER    _IO(SL_MAGIC, 0x01)
#define SL_IOCTL_DEV_UNREGISTER  _IOW(SL_MAGIC, 0x02, uint16_t)
#define SL_IOCTL_DEV_COUNT       _IOR(SL_MAGIC, 0x03, uint32_t)

#define SL_IOCTL_START_ADV       _IOW(SL_MAGIC, 0x10, struct sle_adv_params)
#define SL_IOCTL_STOP_ADV        _IO(SL_MAGIC, 0x11)
#define SL_IOCTL_START_SCAN      _IOW(SL_MAGIC, 0x12, struct sle_scan_params)
#define SL_IOCTL_STOP_SCAN       _IO(SL_MAGIC, 0x13)

#define SL_IOCTL_INJECT_ADV      _IOW(SL_MAGIC, 0x20, struct sle_inject_adv)
#define SL_IOCTL_SCAN_RESULT_COUNT _IO(SL_MAGIC, 0x21)

/* Connection management */
#define SL_IOCTL_CONNECT         _IOW(SL_MAGIC, 0x30, struct sle_connect_params)
#define SL_IOCTL_DISCONNECT      _IO(SL_MAGIC, 0x31)
#define SL_IOCTL_CONN_INFO       _IOR(SL_MAGIC, 0x32, struct sle_conn_info)
#define SL_IOCTL_CONN_SEND       _IOW(SL_MAGIC, 0x33, struct sle_conn_data)
#define SL_IOCTL_CONN_RECV       _IOR(SL_MAGIC, 0x34, struct sle_conn_data)
#define SL_IOCTL_INJECT_CONN_RESP _IOW(SL_MAGIC, 0x35, struct sle_inject_conn_resp)
#define SL_IOCTL_INJECT_CONN_DATA _IOW(SL_MAGIC, 0x36, struct sle_conn_data)

/* Security management */
#define SL_IOCTL_SEC_SET_PSK     _IOW(SL_MAGIC, 0x40, struct sle_psk_params)
#define SL_IOCTL_SEC_PAIR        _IOW(SL_MAGIC, 0x41, struct sle_pair_params)
#define SL_IOCTL_SEC_INFO        _IOR(SL_MAGIC, 0x42, struct sle_sec_info)
#define SL_IOCTL_SEC_ENCRYPT_ON  _IO(SL_MAGIC, 0x43)
#define SL_IOCTL_SEC_SM3_TEST    _IOW(SL_MAGIC, 0x44, struct sle_hash_test)
#define SL_IOCTL_SEC_SM4_ENC_TEST _IOW(SL_MAGIC, 0x45, struct sle_conn_data)
#define SL_IOCTL_SEC_SM4_DEC_TEST _IOW(SL_MAGIC, 0x46, struct sle_conn_data)

/* ------------------------------------------------------------------ */
/* Userspace data structures — must match repr(C) in sparklink_core   */
/* ------------------------------------------------------------------ */

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
	uint8_t  _reserved[12];
} __attribute__((packed));

struct sle_conn_data {
	uint16_t length;
	uint8_t  data[255];
	uint8_t  _reserved;
} __attribute__((packed));

struct sle_inject_conn_resp {
	uint8_t  response_type;
	uint8_t  bandwidth_mhz;
	uint8_t  mcs_index;
	uint8_t  _pad;
	uint16_t supervision_timeout;
	uint8_t  _reserved[2];
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
	check("DEV_COUNT", ret);
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
	test_header("CONNECT / DISCONNECT");

	struct sle_connect_params cp;
	memset(&cp, 0, sizeof(cp));
	cp.peer_addr[0] = 0xAA;
	cp.peer_addr[1] = 0xBB;
	cp.peer_addr[5] = 0x01;
	cp.gt_role = 0;  /* T node */
	cp.bandwidth = 1;
	cp.mcs_index = 4;
	cp.timeout_10ms = 100;

	/* Connect — should transition to Connecting */
	int ret = ioctl(fd, SL_IOCTL_CONNECT, &cp);
	check("CONNECT", ret);

	/* Verify state via CONN_INFO */
	struct sle_conn_info info;
	memset(&info, 0, sizeof(info));
	ret = ioctl(fd, SL_IOCTL_CONN_INFO, &info);
	check("CONN_INFO (connecting)", ret);
	if (ret == 0 && info.state == 1) {
		printf("  OK:   state=Connecting (1)\n");
	} else {
		printf("  WARN: expected state=1, got state=%u\n", info.state);
	}

	/* Connect again while connecting — should fail EBUSY */
	ret = ioctl(fd, SL_IOCTL_CONNECT, &cp);
	if (ret < 0 && errno == EBUSY) {
		printf("  OK:   CONNECT (duplicate): correctly rejected (EBUSY)\n");
	} else {
		printf("  WARN: CONNECT (duplicate): expected EBUSY, got ret=%d errno=%d\n",
		       ret, errno);
	}

	/* Disconnect from Connecting state */
	ret = ioctl(fd, SL_IOCTL_DISCONNECT, NULL);
	check("DISCONNECT", ret);

	/* Verify state is Idle */
	memset(&info, 0, sizeof(info));
	ret = ioctl(fd, SL_IOCTL_CONN_INFO, &info);
	check("CONN_INFO (idle)", ret);
	if (ret == 0 && info.state == 0) {
		printf("  OK:   state=Idle (0)\n");
	} else {
		printf("  WARN: expected state=0, got state=%u\n", info.state);
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
	check("CONNECT", ret);

	/* Inject rejection response */
	struct sle_inject_conn_resp resp;
	memset(&resp, 0, sizeof(resp));
	resp.response_type = 3;  /* UserRejected */

	ret = ioctl(fd, SL_IOCTL_INJECT_CONN_RESP, &resp);
	if (ret < 0 && errno == EACCES) {
		printf("  OK:   INJECT_CONN_RESP (rejected): got EACCES\n");
	} else {
		printf("  WARN: expected EACCES, got ret=%d errno=%d\n",
		       ret, errno);
	}

	/* Verify state is back to Idle */
	struct sle_conn_info info;
	memset(&info, 0, sizeof(info));
	ret = ioctl(fd, SL_IOCTL_CONN_INFO, &info);
	check("CONN_INFO (after reject)", ret);
	if (ret == 0 && info.state == 0) {
		printf("  OK:   state=Idle after rejection\n");
	} else {
		printf("  WARN: expected state=0, got state=%u\n", info.state);
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
	check("CONNECT", ret);

	/* Step 2: Accept connection via injected response */
	struct sle_inject_conn_resp resp;
	memset(&resp, 0, sizeof(resp));
	resp.response_type = 0;  /* Accepted */
	resp.bandwidth_mhz = 2;
	resp.mcs_index = 6;
	resp.supervision_timeout = 200;

	ret = ioctl(fd, SL_IOCTL_INJECT_CONN_RESP, &resp);
	check("INJECT_CONN_RESP (accepted)", ret);

	/* Step 3: Verify Connected state and negotiated params */
	struct sle_conn_info info;
	memset(&info, 0, sizeof(info));
	ret = ioctl(fd, SL_IOCTL_CONN_INFO, &info);
	check("CONN_INFO (connected)", ret);
	if (ret == 0) {
		printf("  state=%u role=%u bw=%u mcs=%u timeout=%u\n",
		       info.state, info.local_role, info.bandwidth_mhz,
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
	const char *msg = "Hello SparkLink!";
	sd.length = strlen(msg);
	memcpy(sd.data, msg, sd.length);
	ret = ioctl(fd, SL_IOCTL_CONN_SEND, &sd);
	check("CONN_SEND", ret);

	/* Step 5: Inject received data (simulating peer sending back) */
	struct sle_conn_data rd;
	memset(&rd, 0, sizeof(rd));
	const char *reply = "ACK from peer";
	rd.length = strlen(reply);
	memcpy(rd.data, reply, rd.length);
	ret = ioctl(fd, SL_IOCTL_INJECT_CONN_DATA, &rd);
	check("INJECT_CONN_DATA", ret);

	/* Step 6: Receive the injected data */
	struct sle_conn_data recv_buf;
	memset(&recv_buf, 0, sizeof(recv_buf));
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
	ret = ioctl(fd, SL_IOCTL_CONN_RECV, &recv_buf);
	if (ret < 0 && errno == EAGAIN) {
		printf("  OK:   CONN_RECV (empty): correctly got EAGAIN\n");
	} else {
		printf("  WARN: expected EAGAIN, got ret=%d errno=%d\n", ret, errno);
	}

	/* Step 8: Check stats */
	memset(&info, 0, sizeof(info));
	ret = ioctl(fd, SL_IOCTL_CONN_INFO, &info);
	if (ret == 0) {
		printf("  stats: tx_bytes=%lu rx_bytes=%lu tx_pend=%u rx_pend=%u\n",
		       (unsigned long)info.tx_bytes, (unsigned long)info.rx_bytes,
		       info.tx_pending, info.rx_pending);
	}

	/* Step 9: Disconnect */
	ret = ioctl(fd, SL_IOCTL_DISCONNECT, NULL);
	check("DISCONNECT", ret);

	/* Step 10: Try to send after disconnect — should fail EPIPE */
	memset(&sd, 0, sizeof(sd));
	sd.length = 5;
	memcpy(sd.data, "bad", 3);
	ret = ioctl(fd, SL_IOCTL_CONN_SEND, &sd);
	if (ret < 0 && errno == EPIPE) {
		printf("  OK:   CONN_SEND (disconnected): correctly got EPIPE\n");
	} else {
		printf("  WARN: expected EPIPE, got ret=%d errno=%d\n", ret, errno);
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
	test_unknown_ioctl(fd);

	printf("\n=== All tests completed ===\n");

	close(fd);
	return 0;
}
