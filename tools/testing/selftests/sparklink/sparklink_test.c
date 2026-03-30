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
	test_unknown_ioctl(fd);

	printf("\n=== All tests completed ===\n");

	close(fd);
	return 0;
}
