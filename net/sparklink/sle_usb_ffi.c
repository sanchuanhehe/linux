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
