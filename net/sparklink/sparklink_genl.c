// SPDX-License-Identifier: GPL-2.0
/*
 * SparkLink Generic Netlink interface
 *
 * Registers the "sparklink" genetlink family and provides attribute-based
 * messaging as an alternative to the /dev/sparklink ioctl interface.
 * Event multicasting allows multiple userspace listeners to subscribe
 * via the "events" multicast group.
 *
 * This file is compiled as part of the sparklink.ko module alongside
 * the Rust sparklink_core.o.  It calls #[no_mangle] Rust functions
 * for data queries and is called by Rust for event broadcasting.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <net/genetlink.h>
#include <uapi/linux/sparklink.h>

/* -----------------------------------------------------------------------
 * Rust FFI: functions exported by sparklink_core.rs (#[no_mangle])
 * -----------------------------------------------------------------------
 */
extern u32  sparklink_genl_get_dev_count(void);
extern u32  sparklink_genl_get_proto_version(void);

/* Forward declarations (also used externally from Rust via FFI) */
int sparklink_genl_register(void);
void sparklink_genl_unregister(void);
int sparklink_genl_send_event(u8 event_type, u16 handle,
			      const u8 *addr, u32 addr_len,
			      const u8 *payload, u32 payload_len);

/* -----------------------------------------------------------------------
 * Multicast groups
 * -----------------------------------------------------------------------
 */
static const struct genl_multicast_group sparklink_mcgrps[] = {
	{ .name = SPARKLINK_MCGRP_EVENTS },
};

/* -----------------------------------------------------------------------
 * Attribute policy (validation rules)
 * -----------------------------------------------------------------------
 */
static const struct nla_policy sparklink_genl_policy[SPARKLINK_ATTR_MAX + 1] = {
	[SPARKLINK_ATTR_DEV_INDEX]	= { .type = NLA_U16 },
	[SPARKLINK_ATTR_DEV_STATE]	= { .type = NLA_U8 },
	[SPARKLINK_ATTR_DEV_NAME]	= { .type = NLA_NUL_STRING,
					    .len = 32 },
	[SPARKLINK_ATTR_DEV_BUS]	= { .type = NLA_U8 },
	[SPARKLINK_ATTR_DEV_COUNT]	= { .type = NLA_U32 },
	[SPARKLINK_ATTR_PROTO_VERSION]	= { .type = NLA_U32 },
	[SPARKLINK_ATTR_EVENT_TYPE]	= { .type = NLA_U8 },
	[SPARKLINK_ATTR_EVENT_PAYLOAD]	= { .type = NLA_BINARY,
					    .len = 256 },
	[SPARKLINK_ATTR_HANDLE]		= { .type = NLA_U16 },
	[SPARKLINK_ATTR_ADDR]		= NLA_POLICY_EXACT_LEN(6),
	[SPARKLINK_ATTR_PEER_ADDR]	= NLA_POLICY_EXACT_LEN(6),
};

/* -----------------------------------------------------------------------
 * Command operations
 * -----------------------------------------------------------------------
 */
static int sparklink_genl_get_dev_info(struct sk_buff *skb,
				       struct genl_info *info);
static int sparklink_genl_get_version(struct sk_buff *skb,
				      struct genl_info *info);

static const struct genl_small_ops sparklink_genl_ops[] = {
	{
		.cmd	= SPARKLINK_CMD_GET_DEV_INFO,
		.doit	= sparklink_genl_get_dev_info,
	},
	{
		.cmd	= SPARKLINK_CMD_GET_VERSION,
		.doit	= sparklink_genl_get_version,
	},
};

/* -----------------------------------------------------------------------
 * Family definition
 * -----------------------------------------------------------------------
 */
static struct genl_family sparklink_genl_family __ro_after_init = {
	.name		= SPARKLINK_GENL_NAME,
	.version	= SPARKLINK_GENL_VERSION,
	.maxattr	= SPARKLINK_ATTR_MAX,
	.policy		= sparklink_genl_policy,
	.module		= THIS_MODULE,
	.small_ops	= sparklink_genl_ops,
	.n_small_ops	= ARRAY_SIZE(sparklink_genl_ops),
	.mcgrps		= sparklink_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(sparklink_mcgrps),
	.parallel_ops	= true,
};

/* -----------------------------------------------------------------------
 * GET_DEV_INFO handler
 *
 * Returns the number of registered SparkLink devices.
 * -----------------------------------------------------------------------
 */
static int sparklink_genl_get_dev_info(struct sk_buff *skb,
				       struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	u32 count;

	msg = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &sparklink_genl_family, 0,
			  SPARKLINK_CMD_GET_DEV_INFO);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	count = sparklink_genl_get_dev_count();
	if (nla_put_u32(msg, SPARKLINK_ATTR_DEV_COUNT, count))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	nlmsg_free(msg);
	return -EMSGSIZE;
}

/* -----------------------------------------------------------------------
 * GET_VERSION handler
 *
 * Returns protocol stack and genetlink interface versions.
 * -----------------------------------------------------------------------
 */
static int sparklink_genl_get_version(struct sk_buff *skb,
				      struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;

	msg = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &sparklink_genl_family, 0,
			  SPARKLINK_CMD_GET_VERSION);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	if (nla_put_u32(msg, SPARKLINK_ATTR_PROTO_VERSION,
			sparklink_genl_get_proto_version()))
		goto nla_put_failure;
	if (nla_put_u32(msg, SPARKLINK_ATTR_GENL_VERSION,
			SPARKLINK_GENL_VERSION))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	nlmsg_free(msg);
	return -EMSGSIZE;
}

/* -----------------------------------------------------------------------
 * Event multicast (called from Rust via FFI)
 *
 * Broadcasts a SPARKLINK_CMD_EVENT message to all listeners subscribed
 * to the "events" multicast group.
 * -----------------------------------------------------------------------
 */
int sparklink_genl_send_event(u8 event_type, u16 handle,
			      const u8 *addr, u32 addr_len,
			      const u8 *payload, u32 payload_len)
{
	struct sk_buff *msg;
	void *hdr;

	msg = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &sparklink_genl_family, 0,
			  SPARKLINK_CMD_EVENT);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	if (nla_put_u8(msg, SPARKLINK_ATTR_EVENT_TYPE, event_type))
		goto nla_put_failure;

	if (handle != 0) {
		if (nla_put_u16(msg, SPARKLINK_ATTR_HANDLE, handle))
			goto nla_put_failure;
	}

	if (addr && addr_len == 6) {
		if (nla_put(msg, SPARKLINK_ATTR_ADDR, 6, addr))
			goto nla_put_failure;
	}

	if (payload && payload_len > 0) {
		if (nla_put(msg, SPARKLINK_ATTR_EVENT_PAYLOAD,
			    payload_len, payload))
			goto nla_put_failure;
	}

	genlmsg_end(msg, hdr);

	return genlmsg_multicast(&sparklink_genl_family, msg, 0, 0,
				 GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	nlmsg_free(msg);
	return -EMSGSIZE;
}

/* -----------------------------------------------------------------------
 * Init / Exit (called from the Rust module init/drop)
 * -----------------------------------------------------------------------
 */
int sparklink_genl_register(void)
{
	int ret;

	ret = genl_register_family(&sparklink_genl_family);
	if (ret)
		pr_err("sparklink: failed to register genetlink family: %d\n",
		       ret);
	else
		pr_info("sparklink: genetlink family \"%s\" v%d registered\n",
			SPARKLINK_GENL_NAME, SPARKLINK_GENL_VERSION);

	return ret;
}

void sparklink_genl_unregister(void)
{
	genl_unregister_family(&sparklink_genl_family);
	pr_info("sparklink: genetlink family unregistered\n");
}
