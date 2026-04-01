// SPDX-License-Identifier: GPL-2.0
/*
 * SparkLink serial device (serdev) transport FFI helpers.
 *
 * Provides C wrappers around the serdev subsystem API so that the
 * Rust sle_serdev module can register a serial driver, configure baud
 * rate / flow control, and send/receive data over a UART-attached
 * SparkLink controller.
 *
 * Architecture:
 *
 *   Rust (sle_serdev.rs)        C (sle_serdev_ffi.c)      kernel serdev
 *   ────────────────────        ────────────────────       ─────────────
 *   sle_serdev_open()      ──► sle_serdev_open_dev() ──► serdev_device_open()
 *   sle_serdev_write()     ──► sle_serdev_write()    ──► serdev_device_write_buf()
 *   sle_serdev_close()     ──► sle_serdev_close_dev()──► serdev_device_close()
 *   sle_serdev_set_baud()  ──► sle_serdev_set_baud() ──► serdev_device_set_baudrate()
 *
 *   <rx callback>          ◄── sle_serdev_receive_cb()◄── serdev core
 *   <write wakeup>         ◄── sle_serdev_wakeup_cb() ◄── serdev core
 */

#include <linux/serdev.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/mod_devicetable.h>

/* -----------------------------------------------------------------------
 * Rust completion callbacks
 * -----------------------------------------------------------------------
 */
extern void sparklink_serdev_receive(void *ctx, const u8 *data, int len);
extern void sparklink_serdev_write_wakeup(void *ctx);

/* Forward declarations for exported FFI functions */
struct sle_serdev_data;
struct sle_serdev_data *sle_serdev_alloc(struct serdev_device *serdev,
					 void *rust_ctx);
int sle_serdev_open_dev(struct sle_serdev_data *sd);
void sle_serdev_close_dev(struct sle_serdev_data *sd);
unsigned int sle_serdev_set_baudrate(struct sle_serdev_data *sd,
				     unsigned int baud);
void sle_serdev_set_flow_control(struct sle_serdev_data *sd, bool enable);
int sle_serdev_write(struct sle_serdev_data *sd, const u8 *data,
		     int len, int timeout_ms);
int sle_serdev_write_buf(struct sle_serdev_data *sd, const u8 *data,
			 int len);

/* -----------------------------------------------------------------------
 * Per-device driver data
 * -----------------------------------------------------------------------
 */
struct sle_serdev_data {
	struct serdev_device *serdev;
	void *rust_ctx;
};

/* -----------------------------------------------------------------------
 * serdev callbacks
 * -----------------------------------------------------------------------
 */
static size_t sle_serdev_receive_cb(struct serdev_device *serdev,
				    const u8 *data, size_t count)
{
	struct sle_serdev_data *sd = serdev_device_get_drvdata(serdev);

	if (sd && sd->rust_ctx)
		sparklink_serdev_receive(sd->rust_ctx, data, (int)count);

	return count;
}

static void sle_serdev_wakeup_cb(struct serdev_device *serdev)
{
	struct sle_serdev_data *sd = serdev_device_get_drvdata(serdev);

	if (sd && sd->rust_ctx)
		sparklink_serdev_write_wakeup(sd->rust_ctx);
}

static const struct serdev_device_ops sle_serdev_ops = {
	.receive_buf = sle_serdev_receive_cb,
	.write_wakeup = sle_serdev_wakeup_cb,
};

/* -----------------------------------------------------------------------
 * Exported FFI functions
 * -----------------------------------------------------------------------
 */

/**
 * sle_serdev_alloc - Allocate per-device data and install serdev callbacks.
 * @serdev:   serdev_device from probe
 * @rust_ctx: opaque Rust context pointer
 *
 * Returns an opaque handle or NULL on failure.
 */
struct sle_serdev_data *sle_serdev_alloc(struct serdev_device *serdev,
					 void *rust_ctx)
{
	struct sle_serdev_data *sd;

	sd = devm_kzalloc(&serdev->dev, sizeof(*sd), GFP_KERNEL);
	if (!sd)
		return NULL;

	sd->serdev = serdev;
	sd->rust_ctx = rust_ctx;

	serdev_device_set_drvdata(serdev, sd);
	serdev_device_set_client_ops(serdev, &sle_serdev_ops);

	return sd;
}

/**
 * sle_serdev_open_dev - Open the serial port.
 * @sd: driver data from sle_serdev_alloc
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_serdev_open_dev(struct sle_serdev_data *sd)
{
	if (!sd || !sd->serdev)
		return -EINVAL;
	return serdev_device_open(sd->serdev);
}

/**
 * sle_serdev_close_dev - Close the serial port.
 * @sd: driver data
 */
void sle_serdev_close_dev(struct sle_serdev_data *sd)
{
	if (sd && sd->serdev)
		serdev_device_close(sd->serdev);
}

/**
 * sle_serdev_set_baudrate - Set the UART baud rate.
 * @sd:   driver data
 * @baud: desired baud rate
 *
 * Returns the actual baud rate set (may differ from requested).
 */
unsigned int sle_serdev_set_baudrate(struct sle_serdev_data *sd,
				     unsigned int baud)
{
	if (!sd || !sd->serdev)
		return 0;
	return serdev_device_set_baudrate(sd->serdev, baud);
}

/**
 * sle_serdev_set_flow_control - Enable or disable hardware flow control.
 * @sd:     driver data
 * @enable: true to enable RTS/CTS
 */
void sle_serdev_set_flow_control(struct sle_serdev_data *sd, bool enable)
{
	if (sd && sd->serdev)
		serdev_device_set_flow_control(sd->serdev, enable);
}

/**
 * sle_serdev_write - Write data to the serial port (blocking).
 * @sd:        driver data
 * @data:      data buffer
 * @len:       number of bytes to write
 * @timeout_ms: timeout in ms (0 = default)
 *
 * Returns the number of bytes written, or negative errno.
 */
int sle_serdev_write(struct sle_serdev_data *sd, const u8 *data,
		     int len, int timeout_ms)
{
	unsigned long timeout_jiffies;

	if (!sd || !sd->serdev || !data || len <= 0)
		return -EINVAL;

	if (timeout_ms > 0)
		timeout_jiffies = msecs_to_jiffies(timeout_ms);
	else
		timeout_jiffies = HZ; /* default 1 second */

	return serdev_device_write(sd->serdev, data, len, timeout_jiffies);
}

/**
 * sle_serdev_write_buf - Write data to the serial port (non-blocking).
 * @sd:   driver data
 * @data: data buffer
 * @len:  number of bytes to write
 *
 * Returns the number of bytes accepted, or negative errno.
 */
int sle_serdev_write_buf(struct sle_serdev_data *sd, const u8 *data,
			 int len)
{
	if (!sd || !sd->serdev || !data || len <= 0)
		return -EINVAL;
	return serdev_device_write_buf(sd->serdev, data, len);
}
