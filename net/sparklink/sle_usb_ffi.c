// SPDX-License-Identifier: GPL-2.0
/*
 * SparkLink USB transport FFI helpers.
 *
 * Provides thin C wrappers around the kernel USB URB API for consumption
 * by the Rust sle_usb module. The wrappers handle the unsafe parts of
 * URB lifecycle management (allocation, fill, submit, complete) and
 * expose a minimal, type-safe surface to Rust.
 *
 * Architecture:
 *
 *   Rust (sle_usb.rs)         C (sle_usb_ffi.c)        kernel USB core
 *   ─────────────────         ─────────────────         ──────────────
 *   sle_usb_alloc()      ──► sle_usb_alloc_urb()  ──► usb_alloc_urb()
 *   sle_usb_submit_bulk()──► sle_usb_submit_bulk()──► usb_fill_bulk_urb()
 *                                                  ──► usb_submit_urb()
 *   <completion callback> ◄── sle_usb_bulk_cb()   ◄── USB core IRQ
 *   sle_usb_kill()        ──► sle_usb_kill_urb()  ──► usb_kill_urb()
 *   sle_usb_free()        ──► sle_usb_free_urb()  ──► usb_free_urb()
 */

#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/module.h>

/* -----------------------------------------------------------------------
 * Rust-side completion callback declaration
 * -----------------------------------------------------------------------
 * Rust provides this function via #[no_mangle]. It receives:
 *   ctx      — opaque pointer passed during submit (Rust uses this to
 *              identify which URB completed)
 *   data     — pointer to the transfer buffer
 *   length   — actual number of bytes transferred
 *   status   — URB completion status (0 = success, negative = error)
 */
extern void sparklink_usb_complete(void *ctx, const u8 *data,
				   int length, int status);

/* Forward declarations for exported FFI functions */
struct sle_urb_ctx *sle_usb_alloc_ctx(int buf_size);
void sle_usb_free_ctx(struct sle_urb_ctx *ctx);
int sle_usb_submit_bulk_out(struct sle_urb_ctx *ctx,
			    struct usb_device *udev, u8 ep,
			    const u8 *data, int len,
			    void *rust_ctx, int timeout_ms);
int sle_usb_submit_bulk_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep,
			   void *rust_ctx);
int sle_usb_submit_intr_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep,
			   void *rust_ctx, int interval);
void sle_usb_kill_ctx(struct sle_urb_ctx *ctx);
int sle_usb_sync_bulk_out(struct usb_device *udev, u8 ep,
			  const u8 *data, int len, int timeout_ms);
int sle_usb_sync_bulk_in(struct usb_device *udev, u8 ep,
			 u8 *buf, int size, int timeout_ms);

/* -----------------------------------------------------------------------
 * URB context: bookkeeping for in-flight transfers
 * -----------------------------------------------------------------------
 */
struct sle_urb_ctx {
	struct urb *urb;
	u8 *buf;
	int buf_size;
	void *rust_ctx;  /* opaque pointer handed back to Rust on completion */
};

/* -----------------------------------------------------------------------
 * Completion handler: called by USB core when transfer finishes
 * -----------------------------------------------------------------------
 */
static void sle_usb_bulk_cb(struct urb *urb)
{
	struct sle_urb_ctx *ctx = urb->context;

	sparklink_usb_complete(ctx->rust_ctx, ctx->buf,
			       urb->actual_length, urb->status);
}

static void sle_usb_intr_cb(struct urb *urb)
{
	struct sle_urb_ctx *ctx = urb->context;

	sparklink_usb_complete(ctx->rust_ctx, ctx->buf,
			       urb->actual_length, urb->status);

	/* For interrupt IN endpoints: auto-resubmit unless cancelled */
	if (urb->status == 0 || urb->status == -EOVERFLOW) {
		int ret = usb_submit_urb(urb, GFP_ATOMIC);
		if (ret)
			pr_err("sparklink-usb: intr resubmit failed: %d\n",
			       ret);
	}
}

/* -----------------------------------------------------------------------
 * Exported FFI functions
 * -----------------------------------------------------------------------
 */

/**
 * sle_usb_alloc_ctx - Allocate a URB context for SparkLink transfers.
 * @buf_size: size of the transfer buffer
 *
 * Returns NULL on allocation failure.
 */
struct sle_urb_ctx *sle_usb_alloc_ctx(int buf_size)
{
	struct sle_urb_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!ctx->urb) {
		kfree(ctx);
		return NULL;
	}

	ctx->buf = kmalloc(buf_size, GFP_KERNEL);
	if (!ctx->buf) {
		usb_free_urb(ctx->urb);
		kfree(ctx);
		return NULL;
	}

	ctx->buf_size = buf_size;
	ctx->rust_ctx = NULL;
	return ctx;
}

/**
 * sle_usb_free_ctx - Free a URB context and its resources.
 * @ctx: context allocated by sle_usb_alloc_ctx
 */
void sle_usb_free_ctx(struct sle_urb_ctx *ctx)
{
	if (!ctx)
		return;
	usb_free_urb(ctx->urb);
	kfree(ctx->buf);
	kfree(ctx);
}

/**
 * sle_usb_submit_bulk_out - Submit a bulk OUT transfer (host to device).
 * @ctx:       URB context
 * @udev:      USB device
 * @ep:        endpoint address (e.g. 0x03)
 * @data:      payload to send
 * @len:       payload length
 * @rust_ctx:  opaque pointer passed to completion callback
 * @timeout_ms: 0 for async, > 0 for synchronous timeout
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_usb_submit_bulk_out(struct sle_urb_ctx *ctx,
			    struct usb_device *udev, u8 ep,
			    const u8 *data, int len,
			    void *rust_ctx, int timeout_ms)
{
	unsigned int pipe;
	int actual_len;

	if (!ctx || !udev || len > ctx->buf_size)
		return -EINVAL;

	if (timeout_ms > 0) {
		/* Synchronous: use usb_bulk_msg */
		memcpy(ctx->buf, data, len);
		pipe = usb_sndbulkpipe(udev, ep);
		return usb_bulk_msg(udev, pipe, ctx->buf, len,
				    &actual_len, timeout_ms);
	}

	/* Asynchronous: fill and submit URB */
	memcpy(ctx->buf, data, len);
	ctx->rust_ctx = rust_ctx;
	pipe = usb_sndbulkpipe(udev, ep);

	usb_fill_bulk_urb(ctx->urb, udev, pipe,
			  ctx->buf, len,
			  sle_usb_bulk_cb, ctx);

	return usb_submit_urb(ctx->urb, GFP_KERNEL);
}

/**
 * sle_usb_submit_bulk_in - Submit a bulk IN transfer (device to host).
 * @ctx:       URB context
 * @udev:      USB device
 * @ep:        endpoint address (e.g. 0x82)
 * @rust_ctx:  opaque pointer passed to completion callback
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_usb_submit_bulk_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep,
			   void *rust_ctx)
{
	unsigned int pipe;

	if (!ctx || !udev)
		return -EINVAL;

	ctx->rust_ctx = rust_ctx;
	pipe = usb_rcvbulkpipe(udev, ep);

	usb_fill_bulk_urb(ctx->urb, udev, pipe,
			  ctx->buf, ctx->buf_size,
			  sle_usb_bulk_cb, ctx);

	return usb_submit_urb(ctx->urb, GFP_KERNEL);
}

/**
 * sle_usb_submit_intr_in - Submit an interrupt IN transfer (events).
 * @ctx:       URB context
 * @udev:      USB device
 * @ep:        endpoint address (e.g. 0x81)
 * @rust_ctx:  opaque pointer passed to completion callback
 * @interval:  polling interval (from endpoint descriptor)
 *
 * Returns 0 on success, negative errno on failure.
 * The URB auto-resubmits on successful completion.
 */
int sle_usb_submit_intr_in(struct sle_urb_ctx *ctx,
			   struct usb_device *udev, u8 ep,
			   void *rust_ctx, int interval)
{
	unsigned int pipe;

	if (!ctx || !udev)
		return -EINVAL;

	ctx->rust_ctx = rust_ctx;
	pipe = usb_rcvintpipe(udev, ep);

	usb_fill_int_urb(ctx->urb, udev, pipe,
			 ctx->buf, ctx->buf_size,
			 sle_usb_intr_cb, ctx, interval);

	return usb_submit_urb(ctx->urb, GFP_KERNEL);
}

/**
 * sle_usb_kill_ctx - Cancel a pending URB.
 * @ctx: URB context
 */
void sle_usb_kill_ctx(struct sle_urb_ctx *ctx)
{
	if (ctx && ctx->urb)
		usb_kill_urb(ctx->urb);
}

/**
 * sle_usb_sync_bulk_out - Blocking bulk OUT transfer.
 * @udev:      USB device
 * @ep:        endpoint address
 * @data:      payload
 * @len:       payload length
 * @timeout_ms: timeout in milliseconds
 *
 * Returns actual bytes transferred on success, negative errno on failure.
 */
int sle_usb_sync_bulk_out(struct usb_device *udev, u8 ep,
			  const u8 *data, int len, int timeout_ms)
{
	int actual_len = 0;
	int ret;
	unsigned int pipe = usb_sndbulkpipe(udev, ep);

	ret = usb_bulk_msg(udev, pipe, (void *)data, len,
			   &actual_len, timeout_ms);
	return ret ? ret : actual_len;
}

/**
 * sle_usb_sync_bulk_in - Blocking bulk IN transfer.
 * @udev:  USB device
 * @ep:    endpoint address
 * @buf:   receive buffer
 * @size:  buffer capacity
 * @timeout_ms: timeout in milliseconds
 *
 * Returns actual bytes received on success, negative errno on failure.
 */
int sle_usb_sync_bulk_in(struct usb_device *udev, u8 ep,
			 u8 *buf, int size, int timeout_ms)
{
	int actual_len = 0;
	int ret;
	unsigned int pipe = usb_rcvbulkpipe(udev, ep);

	ret = usb_bulk_msg(udev, pipe, buf, size,
			   &actual_len, timeout_ms);
	return ret ? ret : actual_len;
}

/* =======================================================================
 * Per-device USB state table
 *
 * Maps dev_id (from sle_attach_device) to USB resources. This allows
 * Rust code to send commands/data by dev_id without dealing with
 * raw USB device pointers.
 * ======================================================================= */

#define SLE_USB_MAX_DEVS 16

/* DLI packet type bytes (T/XS 10003-2025 section 5.2) */
#define DLI_PKT_COMMAND    0xA1
#define DLI_PKT_ASYNC_DATA 0xA3

/* Endpoint addresses (host perspective) */
#define SLE_EP_EVENT_IN   0x81
#define SLE_EP_DATA_IN    0x82
#define SLE_EP_CMD_OUT    0x03

/* Transfer buffer sizes */
#define SLE_CMD_BUF_SIZE  260  /* 4-byte header + 255 params + 1 spare */
#define SLE_DATA_BUF_SIZE 520  /* 5-byte header + 511 payload + 4 spare */
#define SLE_EVENT_BUF_SIZE 64
#define SLE_RX_BUF_SIZE   520

/* Timeout for synchronous command transfers (ms) */
#define SLE_CMD_TIMEOUT_MS 5000

/* Forward declarations for device table functions */
int sle_usb_dev_register(int dev_id, void *intf_ptr);
void sle_usb_dev_unregister(int dev_id);
int sle_usb_dev_send_cmd(int dev_id, u16 opcode, const u8 *params, int plen);
int sle_usb_dev_send_data(int dev_id, u16 handle, const u8 *data, int len);
int sle_usb_dev_start_evt(int dev_id);
void sle_usb_dev_stop_evt(int dev_id);

struct sle_usb_dev {
	bool active;
	struct usb_interface *intf;
	struct usb_device *udev;
	struct sle_urb_ctx *evt_urb;  /* interrupt IN for events */
	struct sle_urb_ctx *rx_urb;   /* bulk IN for data */
	spinlock_t lock;
};

static struct sle_usb_dev usb_dev_table[SLE_USB_MAX_DEVS];

/**
 * sle_usb_dev_register - Register a USB device for I/O by dev_id.
 * @dev_id:   device id from sle_attach_device
 * @intf_ptr: raw struct usb_interface pointer (from Rust probe)
 *
 * Extracts the usb_device, allocates URB contexts for event and data
 * reception. Returns 0 on success.
 */
int sle_usb_dev_register(int dev_id, void *intf_ptr)
{
	struct sle_usb_dev *d;
	struct usb_interface *intf;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS || !intf_ptr)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (d->active)
		return -EBUSY;

	intf = (struct usb_interface *)intf_ptr;

	spin_lock_init(&d->lock);
	d->intf = intf;
	d->udev = interface_to_usbdev(intf);

	d->evt_urb = sle_usb_alloc_ctx(SLE_EVENT_BUF_SIZE);
	if (!d->evt_urb)
		return -ENOMEM;

	d->rx_urb = sle_usb_alloc_ctx(SLE_RX_BUF_SIZE);
	if (!d->rx_urb) {
		sle_usb_free_ctx(d->evt_urb);
		d->evt_urb = NULL;
		return -ENOMEM;
	}

	d->active = true;
	return 0;
}

/**
 * sle_usb_dev_unregister - Remove a device from the USB I/O table.
 * @dev_id: device id
 *
 * Cancels pending URBs and frees resources.
 */
void sle_usb_dev_unregister(int dev_id)
{
	struct sle_usb_dev *d;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return;

	d = &usb_dev_table[dev_id];
	if (!d->active)
		return;

	d->active = false;

	if (d->evt_urb) {
		sle_usb_kill_ctx(d->evt_urb);
		sle_usb_free_ctx(d->evt_urb);
		d->evt_urb = NULL;
	}
	if (d->rx_urb) {
		sle_usb_kill_ctx(d->rx_urb);
		sle_usb_free_ctx(d->rx_urb);
		d->rx_urb = NULL;
	}

	d->intf = NULL;
	d->udev = NULL;
}

/**
 * sle_usb_dev_send_cmd - Send a DLI command via USB bulk OUT.
 * @dev_id: device id
 * @opcode: DLI opcode (host byte order)
 * @params: parameter bytes
 * @plen:   parameter length
 *
 * Builds a DLI command packet and sends synchronously.
 * Returns 0 on success, negative errno on failure.
 */
int sle_usb_dev_send_cmd(int dev_id, u16 opcode, const u8 *params, int plen)
{
	struct sle_usb_dev *d;
	u8 pkt[SLE_CMD_BUF_SIZE];
	int total;
	int actual_len;
	unsigned int pipe;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (!d->active || !d->udev)
		return -ENODEV;

	if (plen > 255)
		plen = 255;

	/* Build DLI command packet */
	pkt[0] = DLI_PKT_COMMAND;
	pkt[1] = (u8)(opcode & 0xFF);
	pkt[2] = (u8)(opcode >> 8);
	pkt[3] = (u8)plen;
	if (plen > 0 && params)
		memcpy(&pkt[4], params, plen);
	total = 4 + plen;

	pipe = usb_sndbulkpipe(d->udev, SLE_EP_CMD_OUT);
	return usb_bulk_msg(d->udev, pipe, pkt, total,
			    &actual_len, SLE_CMD_TIMEOUT_MS);
}

/**
 * sle_usb_dev_send_data - Send a DLI async data packet via USB bulk OUT.
 * @dev_id: device id
 * @handle: link handle
 * @data:   payload bytes
 * @len:    payload length
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_usb_dev_send_data(int dev_id, u16 handle, const u8 *data, int len)
{
	struct sle_usb_dev *d;
	u8 pkt[SLE_DATA_BUF_SIZE];
	int total;
	int actual_len;
	unsigned int pipe;
	u16 link_id_seg;
	u16 data_len_field;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (!d->active || !d->udev)
		return -ENODEV;

	if (len > 511)
		len = 511;

	/* Build DLI async unicast data packet */
	link_id_seg = ((handle & 0x0FFF) << 4);
	data_len_field = (u16)(len & 0x01FF);

	pkt[0] = DLI_PKT_ASYNC_DATA;
	pkt[1] = (u8)(link_id_seg & 0xFF);
	pkt[2] = (u8)(link_id_seg >> 8);
	pkt[3] = (u8)(data_len_field & 0xFF);
	pkt[4] = (u8)(data_len_field >> 8);
	if (len > 0 && data)
		memcpy(&pkt[5], data, len);
	total = 5 + len;

	pipe = usb_sndbulkpipe(d->udev, SLE_EP_CMD_OUT);
	return usb_bulk_msg(d->udev, pipe, pkt, total,
			    &actual_len, SLE_CMD_TIMEOUT_MS);
}

/**
 * sle_usb_dev_start_evt - Start listening for events on interrupt IN.
 * @dev_id: device id
 *
 * Submits the event interrupt URB which auto-resubmits on completion.
 */
int sle_usb_dev_start_evt(int dev_id)
{
	struct sle_usb_dev *d;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (!d->active || !d->udev || !d->evt_urb)
		return -ENODEV;

	return sle_usb_submit_intr_in(d->evt_urb, d->udev,
				      SLE_EP_EVENT_IN, NULL, 4);
}

/**
 * sle_usb_dev_stop_evt - Stop listening for events.
 * @dev_id: device id
 */
void sle_usb_dev_stop_evt(int dev_id)
{
	struct sle_usb_dev *d;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return;

	d = &usb_dev_table[dev_id];
	if (d->evt_urb)
		sle_usb_kill_ctx(d->evt_urb);
}
