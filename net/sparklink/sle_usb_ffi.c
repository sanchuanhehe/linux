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
 * @ep:        endpoint address (e.g. 0x12)
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
 * @ep:        endpoint address (e.g. 0x92)
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
 * @ep:        endpoint address (e.g. 0x91)
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
 * Uses a kmalloc'd bounce buffer to avoid DMA from stack memory.
 * Returns actual bytes transferred on success, negative errno on failure.
 */
int sle_usb_sync_bulk_out(struct usb_device *udev, u8 ep,
			  const u8 *data, int len, int timeout_ms)
{
	int actual_len = 0;
	int ret;
	unsigned int pipe = usb_sndbulkpipe(udev, ep);
	u8 *bounce;

	bounce = kmalloc(len, GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;
	memcpy(bounce, data, len);

	ret = usb_bulk_msg(udev, pipe, bounce, len,
			   &actual_len, timeout_ms);
	kfree(bounce);
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
 * Uses a kmalloc'd bounce buffer to avoid DMA from stack memory.
 * Returns actual bytes received on success, negative errno on failure.
 */
int sle_usb_sync_bulk_in(struct usb_device *udev, u8 ep,
			 u8 *buf, int size, int timeout_ms)
{
	int actual_len = 0;
	int ret;
	unsigned int pipe = usb_rcvbulkpipe(udev, ep);
	u8 *bounce;

	bounce = kmalloc(size, GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;

	ret = usb_bulk_msg(udev, pipe, bounce, size,
			   &actual_len, timeout_ms);
	if (!ret)
		memcpy(buf, bounce, actual_len);
	kfree(bounce);
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

/* Endpoint addresses (host perspective, T/XS 10003-2025 Table 3) */
#define SLE_EP_EVENT_IN   0x81
#define SLE_EP_DATA_IN    0x82
#define SLE_EP_CMD_OUT    0x02

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
int sle_usb_dev_init_controller(int dev_id);
u32 sle_usb_dev_get_fw_version(int dev_id);
int sle_usb_dev_get_mac(int dev_id, u8 *mac);
int sle_usb_dev_download_fw(int dev_id, const u8 *data, int size,
			    int chunk_size);
int sle_usb_dev_suspend(int dev_id);
int sle_usb_dev_resume(int dev_id);

struct sle_usb_dev {
	bool active;
	bool suspended;
	struct usb_interface *intf;
	struct usb_device *udev;
	struct sle_urb_ctx *evt_urb;  /* interrupt IN for events */
	struct sle_urb_ctx *rx_urb;   /* bulk IN for data */
	spinlock_t lock;
	/* Discovered endpoint addresses (from endpoint descriptors) */
	u8 ep_bulk_in;                /* 0x92 per T/XS 10003 */
	u8 ep_bulk_out;               /* 0x12 per T/XS 10003 */
	u8 ep_intr_in;                /* 0x91 per T/XS 10003 */
	u16 ep_bulk_in_size;          /* wMaxPacketSize */
	u16 ep_intr_in_size;
	u8 ep_intr_in_interval;       /* bInterval */
	bool endpoints_valid;
	/* Read-back from controller during init */
	u8 mac_addr[6];
	u32 fw_version;
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
	struct usb_endpoint_descriptor *bulk_in, *bulk_out, *int_in;
	int ret;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS || !intf_ptr)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (d->active)
		return -EBUSY;

	intf = (struct usb_interface *)intf_ptr;

	spin_lock_init(&d->lock);
	d->intf = intf;
	d->udev = interface_to_usbdev(intf);

	/* Discover endpoints from the interface descriptor */
	ret = usb_find_common_endpoints(intf->cur_altsetting,
					&bulk_in, &bulk_out, &int_in, NULL);
	if (ret) {
		/* Endpoints not found — use hard-coded defaults (test mode) */
		d->ep_bulk_in  = SLE_EP_DATA_IN;
		d->ep_bulk_out = SLE_EP_CMD_OUT;
		d->ep_intr_in  = SLE_EP_EVENT_IN;
		d->ep_bulk_in_size  = 64;
		d->ep_intr_in_size  = 16;
		d->ep_intr_in_interval = 4;
		d->endpoints_valid = false;
		pr_warn("sparklink-usb: endpoints not found in descriptors, using defaults\n");
	} else {
		d->ep_bulk_in  = bulk_in->bEndpointAddress;
		d->ep_bulk_out = bulk_out->bEndpointAddress;
		d->ep_intr_in  = int_in->bEndpointAddress;
		d->ep_bulk_in_size  = usb_endpoint_maxp(bulk_in);
		d->ep_intr_in_size  = usb_endpoint_maxp(int_in);
		d->ep_intr_in_interval = int_in->bInterval;
		d->endpoints_valid = true;
		pr_info("sparklink-usb: endpoints: bulk_in=0x%02x(%d) "
			"bulk_out=0x%02x int_in=0x%02x(%d,ivl=%d)\n",
			d->ep_bulk_in, d->ep_bulk_in_size,
			d->ep_bulk_out,
			d->ep_intr_in, d->ep_intr_in_size,
			d->ep_intr_in_interval);
	}

	d->evt_urb = sle_usb_alloc_ctx(d->ep_intr_in_size > 0 ?
					d->ep_intr_in_size : SLE_EVENT_BUF_SIZE);
	if (!d->evt_urb)
		return -ENOMEM;

	d->rx_urb = sle_usb_alloc_ctx(d->ep_bulk_in_size > 0 ?
				       d->ep_bulk_in_size : SLE_RX_BUF_SIZE);
	if (!d->rx_urb) {
		sle_usb_free_ctx(d->evt_urb);
		d->evt_urb = NULL;
		return -ENOMEM;
	}

	memset(d->mac_addr, 0, 6);
	d->fw_version = 0;
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
	u8 *pkt;
	int total;
	int actual_len;
	unsigned int pipe;
	int ret;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (!d->active || !d->udev)
		return -ENODEV;

	if (plen > 255)
		plen = 255;

	total = 4 + plen;
	pkt = kmalloc(total, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	/* Build DLI command packet */
	pkt[0] = DLI_PKT_COMMAND;
	pkt[1] = (u8)(opcode & 0xFF);
	pkt[2] = (u8)(opcode >> 8);
	pkt[3] = (u8)plen;
	if (plen > 0 && params)
		memcpy(&pkt[4], params, plen);

	pipe = usb_sndbulkpipe(d->udev, d->ep_bulk_out);
	ret = usb_bulk_msg(d->udev, pipe, pkt, total,
			   &actual_len, SLE_CMD_TIMEOUT_MS);
	kfree(pkt);
	return ret;
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
	u8 *pkt;
	int total;
	int actual_len;
	unsigned int pipe;
	u16 link_id_seg;
	u16 data_len_field;
	int ret;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (!d->active || !d->udev)
		return -ENODEV;

	if (len > 511)
		len = 511;

	total = 5 + len;
	pkt = kmalloc(total, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

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

	pipe = usb_sndbulkpipe(d->udev, d->ep_bulk_out);
	ret = usb_bulk_msg(d->udev, pipe, pkt, total,
			   &actual_len, SLE_CMD_TIMEOUT_MS);
	kfree(pkt);
	return ret;
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
	int ret;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (!d->active || !d->udev || !d->evt_urb)
		return -ENODEV;

	ret = sle_usb_submit_intr_in(d->evt_urb, d->udev,
				      d->ep_intr_in,
				      (void *)(uintptr_t)(dev_id + 1),
				      d->ep_intr_in_interval);
	return ret;
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

/* -----------------------------------------------------------------------
 * Device initialisation sequence
 *
 * Performs the standard SLE controller bring-up over USB:
 *   1. Send Reset command (opcode 0x0408)
 *   2. Send ReadLocalVersion (opcode 0x0404) → extract fw_version
 *   3. Send ReadMacAddr (opcode 0x0406) → extract MAC address
 *
 * The responses are received synchronously via the bulk IN endpoint.
 * On success, fw_version and mac_addr fields of the device table entry
 * are populated.
 *
 * DLI command packet format (T/XS 10003-2025):
 *   [0]    = 0xA1 (Command)
 *   [1..2] = opcode (LE16)
 *   [3]    = param_len
 *   [4..N] = params
 *
 * DLI event packet format:
 *   [0..1] = event_code (LE16) — expect CmdComplete 0x0002
 *   [2]    = param_len
 *   [3..4] = opcode echo (LE16)
 *   [5]    = status (0 = success)
 *   [6..N] = return params
 * ----------------------------------------------------------------------- */

/* DLI opcodes from T/XS 10003-2025 */
#define SLE_OP_READ_LOCAL_VERSION 0x0404
#define SLE_OP_READ_MAC_ADDR      0x0406
#define SLE_OP_RESET              0x0408

/* DLI event: CommandComplete */
#define SLE_EVT_CMD_COMPLETE      0x0002

/* How long to wait for a command response (ms) */
#define SLE_INIT_TIMEOUT_MS       3000

static int sle_usb_send_cmd_sync(struct sle_usb_dev *d, u16 opcode,
				 u8 *resp, int resp_size, int *resp_len)
{
	u8 *cmd;
	u8 *rbuf;
	int actual_len;
	unsigned int pipe_out, pipe_in;
	int ret;

	cmd = kmalloc(4, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd[0] = DLI_PKT_COMMAND;
	cmd[1] = (u8)(opcode & 0xFF);
	cmd[2] = (u8)(opcode >> 8);
	cmd[3] = 0; /* no parameters */

	pipe_out = usb_sndbulkpipe(d->udev, d->ep_bulk_out);
	ret = usb_bulk_msg(d->udev, pipe_out, cmd, 4,
			   &actual_len, SLE_INIT_TIMEOUT_MS);
	kfree(cmd);
	if (ret)
		return ret;

	/* Read response from bulk IN using heap buffer */
	rbuf = kmalloc(resp_size, GFP_KERNEL);
	if (!rbuf)
		return -ENOMEM;

	pipe_in = usb_rcvbulkpipe(d->udev, d->ep_bulk_in);
	ret = usb_bulk_msg(d->udev, pipe_in, rbuf, resp_size,
			   resp_len, SLE_INIT_TIMEOUT_MS);
	if (!ret && *resp_len > 0)
		memcpy(resp, rbuf, *resp_len);
	kfree(rbuf);
	return ret;
}

/**
 * sle_usb_dev_init_controller - Run the SLE controller init sequence.
 * @dev_id: device id (must be registered)
 *
 * Sends Reset, ReadLocalVersion, ReadMacAddr commands and stores the
 * results in the per-device state. If the device does not respond (e.g.
 * no real hardware attached), returns -ENODEV without failing the probe
 * — the driver remains functional in degraded mode with placeholder
 * values from sle_attach_device.
 *
 * Returns 0 on full success. Negative errno if any command fails.
 * Partial success is allowed: fw_version and mac_addr are updated
 * independently.
 */
int sle_usb_dev_init_controller(int dev_id)
{
	struct sle_usb_dev *d;
	u8 resp[64];
	int resp_len = 0;
	int ret;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (!d->active || !d->udev)
		return -ENODEV;

	/* Step 1: Reset controller */
	ret = sle_usb_send_cmd_sync(d, SLE_OP_RESET, resp, sizeof(resp),
				    &resp_len);
	if (ret) {
		pr_info("sparklink-usb: init reset failed (%d), "
			"continuing with defaults\n", ret);
		return ret;
	}
	pr_info("sparklink-usb: controller reset OK\n");

	/* Step 2: ReadLocalVersion → fw_version at resp[6..9] */
	ret = sle_usb_send_cmd_sync(d, SLE_OP_READ_LOCAL_VERSION,
				    resp, sizeof(resp), &resp_len);
	if (!ret && resp_len >= 10) {
		/* Response: [evt_code:2][plen:1][opcode:2][status:1][version:4] */
		if (resp[5] == 0) {
			d->fw_version = le32_to_cpup((__le32 *)&resp[6]);
			pr_info("sparklink-usb: fw_version=0x%08x\n",
				d->fw_version);
		}
	}

	/* Step 3: ReadMacAddr → 6-byte MAC at resp[6..11] */
	ret = sle_usb_send_cmd_sync(d, SLE_OP_READ_MAC_ADDR,
				    resp, sizeof(resp), &resp_len);
	if (!ret && resp_len >= 12) {
		if (resp[5] == 0) {
			memcpy(d->mac_addr, &resp[6], 6);
			pr_info("sparklink-usb: mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
				d->mac_addr[0], d->mac_addr[1],
				d->mac_addr[2], d->mac_addr[3],
				d->mac_addr[4], d->mac_addr[5]);
		}
	}

	return 0;
}

/**
 * sle_usb_dev_get_fw_version - Read back the firmware version.
 * @dev_id: device id
 *
 * Returns the firmware version obtained during init, or 0.
 */
u32 sle_usb_dev_get_fw_version(int dev_id)
{
	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return 0;
	if (!usb_dev_table[dev_id].active)
		return 0;
	return usb_dev_table[dev_id].fw_version;
}

/**
 * sle_usb_dev_get_mac - Read back the MAC address.
 * @dev_id: device id
 * @mac:    output buffer (6 bytes)
 *
 * Returns 0 on success.
 */
int sle_usb_dev_get_mac(int dev_id, u8 *mac)
{
	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS || !mac)
		return -EINVAL;
	if (!usb_dev_table[dev_id].active)
		return -ENODEV;
	memcpy(mac, usb_dev_table[dev_id].mac_addr, 6);
	return 0;
}

/* -----------------------------------------------------------------------
 * Firmware download over USB bulk OUT
 *
 * Protocol (modeled after BT HCI firmware download):
 *   1. Host sends FW_DOWNLOAD_START command (opcode 0xF810, param = total size)
 *   2. Host sends firmware data in chunks via bulk OUT, prefixed with
 *      a FW_DATA header byte 0xA5
 *   3. After all chunks: host sends FW_DOWNLOAD_DONE (opcode 0xF811)
 *   4. Controller ACKs with CommandComplete
 *
 * Chunk wire format:
 *   [0]      0xA5 (FW_DATA marker)
 *   [1..4]   offset (LE32)
 *   [5..6]   chunk_len (LE16)
 *   [7..N]   firmware data
 * ----------------------------------------------------------------------- */

#define SLE_FW_DATA_MARKER   0xA5
#define SLE_FW_CHUNK_HDR     7     /* marker + offset(4) + len(2) */
#define SLE_OP_FW_DL_START   0xF810
#define SLE_OP_FW_DL_DONE    0xF811
#define SLE_FW_DEFAULT_CHUNK 240   /* safe for full-speed USB (64B MTU) */
#define SLE_FW_DL_TIMEOUT_MS 10000

/**
 * sle_usb_dev_download_fw - Download firmware to controller in chunks.
 * @dev_id:     device id
 * @data:       firmware blob from request_firmware()
 * @size:       firmware size in bytes
 * @chunk_size: max payload per transfer (0 = auto from endpoint size)
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_usb_dev_download_fw(int dev_id, const u8 *data, int size,
			    int chunk_size)
{
	struct sle_usb_dev *d;
	unsigned int pipe;
	int offset = 0;
	int actual_len;
	int ret;
	u8 *pkt;
	int pkt_size;
	u8 start_params[4];
	u8 resp[32];
	int resp_len;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return -EINVAL;
	if (!data || size <= 0)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (!d->active || !d->udev)
		return -ENODEV;

	if (chunk_size <= 0)
		chunk_size = d->ep_bulk_in_size > SLE_FW_CHUNK_HDR ?
			     d->ep_bulk_in_size - SLE_FW_CHUNK_HDR :
			     SLE_FW_DEFAULT_CHUNK;

	pkt_size = SLE_FW_CHUNK_HDR + chunk_size;
	pkt = kmalloc(pkt_size, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	/* Step 1: Send FW_DOWNLOAD_START with total size */
	start_params[0] = (u8)(size & 0xFF);
	start_params[1] = (u8)((size >> 8) & 0xFF);
	start_params[2] = (u8)((size >> 16) & 0xFF);
	start_params[3] = (u8)((size >> 24) & 0xFF);

	ret = sle_usb_dev_send_cmd(dev_id, SLE_OP_FW_DL_START,
				   start_params, 4);
	if (ret) {
		pr_err("sparklink-usb: fw download start failed: %d\n", ret);
		goto out;
	}

	/* Step 2: Send firmware in chunks via bulk OUT */
	pipe = usb_sndbulkpipe(d->udev, d->ep_bulk_out);

	while (offset < size) {
		int chunk = min(chunk_size, size - offset);
		int total = SLE_FW_CHUNK_HDR + chunk;

		pkt[0] = SLE_FW_DATA_MARKER;
		pkt[1] = (u8)(offset & 0xFF);
		pkt[2] = (u8)((offset >> 8) & 0xFF);
		pkt[3] = (u8)((offset >> 16) & 0xFF);
		pkt[4] = (u8)((offset >> 24) & 0xFF);
		pkt[5] = (u8)(chunk & 0xFF);
		pkt[6] = (u8)((chunk >> 8) & 0xFF);
		memcpy(&pkt[SLE_FW_CHUNK_HDR], data + offset, chunk);

		ret = usb_bulk_msg(d->udev, pipe, pkt, total,
				   &actual_len, SLE_FW_DL_TIMEOUT_MS);
		if (ret) {
			pr_err("sparklink-usb: fw chunk at offset %d failed: %d\n",
			       offset, ret);
			goto out;
		}

		offset += chunk;
	}

	/* Step 3: Send FW_DOWNLOAD_DONE and wait for ACK */
	ret = sle_usb_send_cmd_sync(d, SLE_OP_FW_DL_DONE,
				    resp, sizeof(resp), &resp_len);
	if (ret)
		pr_err("sparklink-usb: fw download done cmd failed: %d\n", ret);
	else
		pr_info("sparklink-usb: firmware downloaded (%d bytes)\n", size);

out:
	kfree(pkt);
	return ret;
}

/* -----------------------------------------------------------------------
 * Power management: suspend / resume
 *
 * suspend: Kill all in-flight URBs so the host controller can power down.
 * resume:  Re-submit the event interrupt URB and optionally re-init the
 *          controller if the device was reset during suspend.
 * ----------------------------------------------------------------------- */

/**
 * sle_usb_dev_suspend - Quiesce the device for system/runtime suspend.
 * @dev_id: device table slot
 *
 * Kills the event (interrupt IN) and data (bulk IN) URBs so no further
 * transfers are pending when the host controller suspends.
 */
int sle_usb_dev_suspend(int dev_id)
{
	struct sle_usb_dev *d;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (!d->active)
		return -ENODEV;

	if (d->suspended)
		return 0;

	/* Kill outstanding URBs */
	if (d->evt_urb)
		sle_usb_kill_ctx(d->evt_urb);
	if (d->rx_urb)
		sle_usb_kill_ctx(d->rx_urb);

	d->suspended = true;
	pr_debug("sparklink-usb: dev %d suspended\n", dev_id);
	return 0;
}

/**
 * sle_usb_dev_resume - Re-activate the device after suspend.
 * @dev_id: device table slot
 *
 * Re-submits the event interrupt URB so the driver resumes receiving
 * asynchronous events from the controller.
 */
int sle_usb_dev_resume(int dev_id)
{
	struct sle_usb_dev *d;
	int ret;

	if (dev_id < 0 || dev_id >= SLE_USB_MAX_DEVS)
		return -EINVAL;

	d = &usb_dev_table[dev_id];
	if (!d->active)
		return -ENODEV;

	if (!d->suspended)
		return 0;

	d->suspended = false;

	/* Re-submit event URB */
	if (d->evt_urb && d->udev) {
		ret = sle_usb_submit_intr_in(d->evt_urb, d->udev,
					     d->ep_intr_in,
					     (void *)(uintptr_t)(dev_id + 1),
					     d->ep_intr_in_interval);
		if (ret) {
			pr_err("sparklink-usb: dev %d resume evt URB failed: %d\n",
			       dev_id, ret);
			return ret;
		}
	}

	pr_debug("sparklink-usb: dev %d resumed\n", dev_id);
	return 0;
}
