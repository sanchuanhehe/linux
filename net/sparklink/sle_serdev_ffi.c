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
#include <linux/completion.h>
#include <linux/spinlock.h>

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
 * Per-device command I/O table
 *
 * Mirrors the USB device table pattern. Stores per-device serdev state
 * and provides synchronous command/response via a completion variable.
 * The receive callback feeds into cmd_resp when a command is pending.
 * -----------------------------------------------------------------------
 */
#define SLE_SERDEV_MAX_DEVS     4
#define SLE_SERDEV_CMD_TIMEOUT  3000   /* ms */
#define SLE_SERDEV_CMD_BUF      260    /* 4-byte header + 255 params + 1 spare */

/* DLI packet type bytes */
#define SLE_H4_COMMAND   0xA1
#define SLE_H4_EVENT     0xA2
#define SLE_H4_ASYNC     0xA3

/* DLI event: CommandComplete */
#define SLE_SERDEV_EVT_CMD_COMPLETE 0x0002

/* DLI init opcodes */
#define SLE_SERDEV_OP_READ_VER  0x0404
#define SLE_SERDEV_OP_READ_MAC  0x0406
#define SLE_SERDEV_OP_RESET     0x0408

struct sle_serdev_dev {
	bool active;
	bool cmd_pending;
	struct sle_serdev_data *sd;
	struct completion cmd_done;
	u8 cmd_resp[SLE_SERDEV_CMD_BUF];
	int cmd_resp_len;
	u16 cmd_pending_opcode;
	spinlock_t lock;
	/* Read-back from controller during init */
	u8 mac_addr[6];
	u32 fw_version;
};

static struct sle_serdev_dev serdev_dev_table[SLE_SERDEV_MAX_DEVS];

/* Forward declarations for device table functions */
int sle_serdev_dev_register(int dev_id, struct sle_serdev_data *sd);
void sle_serdev_dev_unregister(int dev_id);
int sle_serdev_dev_send_cmd(int dev_id, u16 opcode,
			    const u8 *params, int plen);
int sle_serdev_dev_send_data(int dev_id, u16 handle,
			     const u8 *data, int len);
int sle_serdev_dev_send_cmd_sync(int dev_id, u16 opcode,
				 u8 *resp, int resp_size, int *resp_len);
int sle_serdev_dev_init_controller(int dev_id);
u32 sle_serdev_dev_get_fw_version(int dev_id);
int sle_serdev_dev_get_mac(int dev_id, u8 *mac);
void sle_serdev_dev_feed_event(int dev_id, u16 event_code,
			       const u8 *params, int plen);

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

/* -----------------------------------------------------------------------
 * Per-device serdev command I/O
 * -----------------------------------------------------------------------
 */

/**
 * sle_serdev_dev_register - Register a serdev device for command I/O.
 * @dev_id: device id from sle_attach_device
 * @sd:     serdev driver data (from sle_serdev_alloc)
 */
int sle_serdev_dev_register(int dev_id, struct sle_serdev_data *sd)
{
	struct sle_serdev_dev *d;

	if (dev_id < 0 || dev_id >= SLE_SERDEV_MAX_DEVS || !sd)
		return -EINVAL;

	d = &serdev_dev_table[dev_id];
	if (d->active)
		return -EBUSY;

	spin_lock_init(&d->lock);
	init_completion(&d->cmd_done);
	d->sd = sd;
	d->cmd_pending = false;
	d->cmd_resp_len = 0;
	d->cmd_pending_opcode = 0;
	memset(d->mac_addr, 0, 6);
	d->fw_version = 0;
	d->active = true;

	pr_info("sparklink-serdev: dev %d registered\n", dev_id);
	return 0;
}

/**
 * sle_serdev_dev_unregister - Unregister a serdev device.
 * @dev_id: device id
 */
void sle_serdev_dev_unregister(int dev_id)
{
	struct sle_serdev_dev *d;

	if (dev_id < 0 || dev_id >= SLE_SERDEV_MAX_DEVS)
		return;

	d = &serdev_dev_table[dev_id];
	if (!d->active)
		return;

	/* Wake up any pending sync command */
	if (d->cmd_pending) {
		d->cmd_pending = false;
		complete(&d->cmd_done);
	}

	d->active = false;
	d->sd = NULL;
	pr_info("sparklink-serdev: dev %d unregistered\n", dev_id);
}

/**
 * sle_serdev_dev_send_cmd - Send a DLI command (fire-and-forget).
 * @dev_id: device id
 * @opcode: DLI opcode
 * @params: parameter buffer (may be NULL if plen==0)
 * @plen:   parameter length
 *
 * Encodes an H4 command frame and writes it to the serial port.
 */
int sle_serdev_dev_send_cmd(int dev_id, u16 opcode,
			    const u8 *params, int plen)
{
	struct sle_serdev_dev *d;
	u8 buf[SLE_SERDEV_CMD_BUF];
	int total;

	if (dev_id < 0 || dev_id >= SLE_SERDEV_MAX_DEVS)
		return -EINVAL;

	d = &serdev_dev_table[dev_id];
	if (!d->active || !d->sd)
		return -ENODEV;

	if (plen < 0 || plen > 255)
		return -EINVAL;

	/* Encode H4 command frame */
	total = 4 + plen; /* type(1) + opcode(2) + len(1) + params */
	buf[0] = SLE_H4_COMMAND;
	buf[1] = (u8)(opcode & 0xFF);
	buf[2] = (u8)((opcode >> 8) & 0xFF);
	buf[3] = (u8)plen;
	if (plen > 0 && params)
		memcpy(&buf[4], params, plen);

	return sle_serdev_write(d->sd, buf, total, SLE_SERDEV_CMD_TIMEOUT);
}

/**
 * sle_serdev_dev_send_data - Send a DLI async data frame.
 * @dev_id: device id
 * @handle: connection handle
 * @data:   payload
 * @len:    payload length
 */
int sle_serdev_dev_send_data(int dev_id, u16 handle,
			     const u8 *data, int len)
{
	struct sle_serdev_dev *d;
	u8 buf[SLE_SERDEV_CMD_BUF];
	int total;

	if (dev_id < 0 || dev_id >= SLE_SERDEV_MAX_DEVS)
		return -EINVAL;

	d = &serdev_dev_table[dev_id];
	if (!d->active || !d->sd)
		return -ENODEV;

	if (len < 0 || len > 255)
		return -EINVAL;

	/* Encode H4 async data frame */
	total = 5 + len; /* type(1) + handle(2) + len(2) + payload */
	buf[0] = SLE_H4_ASYNC;
	buf[1] = (u8)(handle & 0xFF);
	buf[2] = (u8)((handle >> 8) & 0xFF);
	buf[3] = (u8)(len & 0xFF);
	buf[4] = (u8)((len >> 8) & 0xFF);
	if (len > 0 && data)
		memcpy(&buf[5], data, len);

	return sle_serdev_write(d->sd, buf, total, SLE_SERDEV_CMD_TIMEOUT);
}

/**
 * sle_serdev_dev_feed_event - Feed a parsed event to sync command waiter.
 * @dev_id:     device id
 * @event_code: DLI event code
 * @params:     event parameters
 * @plen:       parameter length
 *
 * Called from Rust receive callback after H4 parsing. If a synchronous
 * command is pending and the event carries a matching CommandComplete,
 * the response is stored and the completion is signalled.
 */
void sle_serdev_dev_feed_event(int dev_id, u16 event_code,
			       const u8 *params, int plen)
{
	struct sle_serdev_dev *d;
	unsigned long flags;

	if (dev_id < 0 || dev_id >= SLE_SERDEV_MAX_DEVS)
		return;

	if (plen > 0 && !params)
		return;

	d = &serdev_dev_table[dev_id];
	if (!d->active)
		return;

	spin_lock_irqsave(&d->lock, flags);

	if (d->cmd_pending && event_code == SLE_SERDEV_EVT_CMD_COMPLETE) {
		/* Check opcode match: params[0..1] = opcode LE16 */
		if (plen >= 2) {
			u16 resp_op = (u16)params[0] | ((u16)params[1] << 8);

			if (resp_op == d->cmd_pending_opcode) {
				int copy = min(plen, (int)sizeof(d->cmd_resp));

				memcpy(d->cmd_resp, params, copy);
				d->cmd_resp_len = copy;
				d->cmd_pending = false;
				spin_unlock_irqrestore(&d->lock, flags);
				complete(&d->cmd_done);
				return;
			}
		}
	}

	spin_unlock_irqrestore(&d->lock, flags);
}

/**
 * sle_serdev_dev_send_cmd_sync - Send command and wait for response.
 * @dev_id:    device id
 * @opcode:    DLI opcode
 * @resp:      response buffer
 * @resp_size: response buffer size
 * @resp_len:  actual response length (output)
 */
int sle_serdev_dev_send_cmd_sync(int dev_id, u16 opcode,
				 u8 *resp, int resp_size, int *resp_len)
{
	struct sle_serdev_dev *d;
	unsigned long flags;
	int ret;
	unsigned long timeout;

	if (dev_id < 0 || dev_id >= SLE_SERDEV_MAX_DEVS)
		return -EINVAL;

	d = &serdev_dev_table[dev_id];
	if (!d->active || !d->sd)
		return -ENODEV;

	/* Set up pending command */
	spin_lock_irqsave(&d->lock, flags);
	reinit_completion(&d->cmd_done);
	d->cmd_pending = true;
	d->cmd_pending_opcode = opcode;
	d->cmd_resp_len = 0;
	spin_unlock_irqrestore(&d->lock, flags);

	/* Send the command */
	ret = sle_serdev_dev_send_cmd(dev_id, opcode, NULL, 0);
	if (ret < 0) {
		spin_lock_irqsave(&d->lock, flags);
		d->cmd_pending = false;
		spin_unlock_irqrestore(&d->lock, flags);
		return ret;
	}

	/* Wait for response */
	timeout = msecs_to_jiffies(SLE_SERDEV_CMD_TIMEOUT);
	ret = wait_for_completion_interruptible_timeout(&d->cmd_done, timeout);
	if (ret == 0) {
		spin_lock_irqsave(&d->lock, flags);
		d->cmd_pending = false;
		spin_unlock_irqrestore(&d->lock, flags);
		pr_err("sparklink-serdev: cmd 0x%04x timeout\n", opcode);
		return -ETIMEDOUT;
	}
	if (ret < 0) {
		spin_lock_irqsave(&d->lock, flags);
		d->cmd_pending = false;
		spin_unlock_irqrestore(&d->lock, flags);
		return ret;
	}

	/* Copy response */
	if (resp && resp_size > 0) {
		int copy = min(d->cmd_resp_len, resp_size);

		memcpy(resp, d->cmd_resp, copy);
		if (resp_len)
			*resp_len = copy;
	}

	return 0;
}

/**
 * sle_serdev_dev_init_controller - Run controller init sequence over UART.
 * @dev_id: device id
 *
 * Sends Reset, ReadLocalVersion, ReadMacAddr synchronously.
 */
int sle_serdev_dev_init_controller(int dev_id)
{
	struct sle_serdev_dev *d;
	u8 resp[64];
	int resp_len = 0;
	int ret;

	if (dev_id < 0 || dev_id >= SLE_SERDEV_MAX_DEVS)
		return -EINVAL;

	d = &serdev_dev_table[dev_id];
	if (!d->active || !d->sd)
		return -ENODEV;

	/* Step 1: Reset */
	ret = sle_serdev_dev_send_cmd_sync(dev_id, SLE_SERDEV_OP_RESET,
					   resp, sizeof(resp), &resp_len);
	if (ret) {
		pr_err("sparklink-serdev: reset failed: %d\n", ret);
		return ret;
	}
	pr_info("sparklink-serdev: controller reset OK\n");

	/* Step 2: ReadLocalVersion */
	ret = sle_serdev_dev_send_cmd_sync(dev_id, SLE_SERDEV_OP_READ_VER,
					   resp, sizeof(resp), &resp_len);
	if (ret) {
		pr_warn("sparklink-serdev: read version failed: %d\n", ret);
	} else if (resp_len >= 7) {
		/* resp: opcode(2) + status(1) + version(4) */
		d->fw_version = (u32)resp[3] | ((u32)resp[4] << 8) |
				((u32)resp[5] << 16) | ((u32)resp[6] << 24);
		pr_info("sparklink-serdev: fw version 0x%08x\n", d->fw_version);
	}

	/* Step 3: ReadMacAddr */
	ret = sle_serdev_dev_send_cmd_sync(dev_id, SLE_SERDEV_OP_READ_MAC,
					   resp, sizeof(resp), &resp_len);
	if (ret) {
		pr_warn("sparklink-serdev: read MAC failed: %d\n", ret);
	} else if (resp_len >= 9) {
		/* resp: opcode(2) + status(1) + mac(6) */
		memcpy(d->mac_addr, &resp[3], 6);
		pr_info("sparklink-serdev: MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			d->mac_addr[0], d->mac_addr[1], d->mac_addr[2],
			d->mac_addr[3], d->mac_addr[4], d->mac_addr[5]);
	}

	return 0;
}

/**
 * sle_serdev_dev_get_fw_version - Get cached firmware version.
 * @dev_id: device id
 */
u32 sle_serdev_dev_get_fw_version(int dev_id)
{
	if (dev_id < 0 || dev_id >= SLE_SERDEV_MAX_DEVS)
		return 0;
	return serdev_dev_table[dev_id].fw_version;
}

/**
 * sle_serdev_dev_get_mac - Get cached MAC address.
 * @dev_id: device id
 * @mac:    output buffer (6 bytes)
 */
int sle_serdev_dev_get_mac(int dev_id, u8 *mac)
{
	if (dev_id < 0 || dev_id >= SLE_SERDEV_MAX_DEVS || !mac)
		return -EINVAL;
	if (!serdev_dev_table[dev_id].active)
		return -ENODEV;
	memcpy(mac, serdev_dev_table[dev_id].mac_addr, 6);
	return 0;
}
