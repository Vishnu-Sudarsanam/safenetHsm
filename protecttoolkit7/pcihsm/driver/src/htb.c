/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * htb.c
 */
#include "headers.h"

struct k7_req *k7_find_req_from_dt (struct k7_channel *channel, u64 daddr, unsigned int ioc_flags, struct k7_dt **dt_p, const char *prefix)
{
	struct k7_dev *dev = channel->dev;
	struct k7_req *req;
	struct k7_dt  *dt;

	SPIN_LOCK_REQUIRED(&dev->lock);
	if (list_empty(&channel->busylist)) {
		kwarn(channel->name, "%s: busylist is empty", prefix);
	} else {
		int failsafe2, failsafe1 = channel->active_count;
		list_for_each_entry(req, &channel->busylist, list) {
			if ((req->ioc->flags & ioc_flags) == ioc_flags && !list_empty(&req->hrb_dtc)) {
				failsafe2 = (K7_MAX_HRB_LEN + 2 * PAGE_SIZE) / PAGE_SIZE;
				list_for_each_entry(dt, &req->hrb_dtc, list) {
					if (dt->daddr == daddr) {
						if (dt_p)
							*dt_p = dt;
						kdebug(channel->name, "%s: daddr=%016llx req=%p", prefix, daddr, req);
						return req;
					}
					if (--failsafe2 < 0) {
						kderr(channel->name, "too many DTs in HRB chain");
						k7_dev_failure_locked(dev, channel->name, "too many DTs in HRB chain");
						break;
					}
				}
			}
			if (--failsafe1 < 0) {
				kderr(channel->name, "too many reqs on busylist, active_count=%d", channel->active_count);
				k7_dev_failure_locked(dev, channel->name, "too many REQs in busylist");
				break;
			}
		}
		kwarn(channel->name, "%s: no match for daddr=%016llx", prefix, daddr);
	}
	return NULL;  /* DT not found */
}

/*
 * Handle a NOTIFY_RX notification for a daddr from the HTB.
 * It will usually (but not always) match the head of busylist here.
 * Note that NOTIFY_RX is not normally used/relied upon for anything,
 * other than for special "K7_DMA_FLAG_NO_REPLY" requests.
 */
static int k7_handle_notify_rx (struct k7_channel *channel, u64 daddr)
{
	struct k7_req *req;
	struct k7_dt  *dt;
	int ret = 0;

	SPIN_LOCK(&channel->dev->lock);
	req = k7_find_req_from_dt(channel, daddr, K7_DMA_FLAG_NO_REPLY, &dt, "NOTIFY_RX");
	if (!req || !dt) {
		ret = -EINVAL;
	} else {
		kdebug(channel->name, "NO_REPLY completed");
		if (k7_remove_req_from_busylist(channel, req))
			k7_complete_req(channel, req, K7_REQ_COMPLETED, 1);
	}
	SPIN_UNLOCK(&channel->dev->lock);
	return ret;
}

/*
 * External completion requests are kept in the busylist
 * for the channel they were sent to, which means the MCPU.
 * So if we see rqaction==1 here, we redirect handling to the MCPU side.
 *
 * Sample HSM Bypass "Abort Request" hdr from DD2: 0x3212030000080008
 *
 * Note that host can set rqaction bits in the outgoing request,
 * and the hardware just echos them back to us.. so we can
 * see strange self-inflicted values here too.  Tough.
 */
static struct k7_channel *k7_decode_htb_htype (struct k7_dev *dev, unsigned int htype, unsigned int rqstr, unsigned int rqaction, int *is_notify_rx)
{
	struct k7_channel *channel = NULL;

	//kdebug2(dev->name, "htype=0x%02x rqstr=%u", htype, rqstr);
	/* Everything in the HTB should be an IV */
	if (!(htype & 0x02)) {
		kerr(dev->name, "non-IV: htype=0x%02x rqstr=%u", htype, rqstr);
	} else if (rqaction == 3) {
		kerr(dev->name, "rqaction=%u: htype=0x%02x rqstr=%u", rqaction, htype, rqstr);
	} else switch (htype) {
		case K7_HTYPE_PK2H_A_IV:
		case K7_HTYPE_PK2H_B_IV:
			if (rqstr == 3) { /* MCPU: external completion */
				if (rqaction != 1) {
					kerr(dev->name, "bad rqaction=%u for htype=0x%02x", rqaction, htype);
					break;
				}
				channel = &dev->channels[K7_DMA_TARGET_MCPU];
			} else
				channel = &dev->channels[K7_DMA_TARGET_PKU];
			break;
		case K7_HTYPE_SK2H_A_IV:  /* fastpath only */
			channel = &dev->channels[K7_DMA_TARGET_SKU];
			break;
		case K7_HTYPE_SK2H_B_IV:  /* mix of fastpath and external completions */
			if (rqstr == 3) {  /* MCPU: external completion */
				if (rqaction != 0) {
					kerr(dev->name, "bad rqaction=%u for htype=0x%02x", rqaction, htype);
					break;
				}
				channel = &dev->channels[K7_DMA_TARGET_MCPU];
			} else
				channel = &dev->channels[K7_DMA_TARGET_SKU];
			break;
		case K7_HTYPE_M2H_IV:
			if (rqaction == 0)  /* normal request? */
				channel = &dev->channels[K7_DMA_TARGET_MCPU];
			else
				kerr(dev->name, "bad rqaction=%u for htype=0x%02x", rqaction, htype);
			break;
		case K7_HTYPE_H2PK_IV:
			*is_notify_rx = 1;
			channel = &dev->channels[K7_DMA_TARGET_PKU];
			break;
		case K7_HTYPE_H2SK_IV:
			*is_notify_rx = 1;
			channel = &dev->channels[K7_DMA_TARGET_SKU];
			break;
		case K7_HTYPE_H2M_IV:
			*is_notify_rx = 1;
			channel = &dev->channels[K7_DMA_TARGET_MCPU];
			break;
	}
	if (channel == NULL)
		kerr(dev->name, "FAILED htype=0x%02x rqaction=%u", htype, rqaction);
	return channel;
}

static int k7_service_hra_daddr (struct k7_channel *channel, u64 daddr)
{
	struct k7_dev *dev = channel->dev;
	struct k7_req *req;

	SPIN_LOCK(&dev->lock);
	if (!list_empty(&channel->busylist)) {
		list_for_each_entry(req, &channel->busylist, list) {
			if (daddr == req->hra_daddr)
				goto found_req;
		}
	}
	SPIN_UNLOCK(&dev->lock);
	return -EINVAL;
found_req:
	if (k7_remove_req_from_busylist(channel, req)) {
		if (channel->target == K7_DMA_TARGET_MCPU) {
			if (req->ioc->flags & K7_DMA_FLAG_KEK_KEY) {
				/*
				 * Handle reply from KEK_KEY inline here,
				 * to preserve sequence of operations
				 * with other fastpath management commands.
				 */
				SPIN_UNLOCK(&dev->lock);
				req->kek_key_ret = k7_handle_hra(dev, req);
				SPIN_LOCK(&dev->lock);
			}
		}
		k7_complete_req(channel, req, K7_REQ_COMPLETED, 1);
	} else {
		/* Somebody beat us to it; NOT an error! */
	}
	SPIN_UNLOCK(&dev->lock);
	return 0;  /* success: found and serviced req */
}

static void k7_dump_htb (struct k7_dev *dev)
{
	u64          *data = dev->htb_area.vaddr;
	unsigned int  len  = dev->htb_area.len;
	unsigned int offset;

	kinfo(dev->name, "Dumping full HTB vaddr=%p len=0x%x");
	len /= 16;
	for (offset = 0; offset < len; offset++) {
		unsigned int index = offset * 2;
		u64 w0 = be64_to_cpu(data[index    ]);
		u64 w1 = be64_to_cpu(data[index + 1]);
		kinfo(dev->name, "%04x: %016llx %016llx", offset * 16, w0, w1);
	}
	kinfo(dev->name, "----");
}

/*
 * The unsolicited message type values here are shared with the MCPU.
 * A non-zero value indicates an "unsolicited" message, so zero cannot be a message type.
 */
typedef enum {
	k7_unsolicited_logmsg		= 1,
	k7_unsolicited_debug		= 2,
	k7_unsolicited_trace		= 3,
	k7_unsolicited_hsm_state	= 4,
	k7_unsolicited_protocol_version = 5,
	k7_unsolicited_mrbinfo		= 6,
	k7_unsolicited_fastpath_mgmt	= 7,
	k7_unsolicited_callback_info	= 8,
	k7_unsolicited_type9		= 9,
	k7_unsolicited_type10		= 10,
	k7_unsolicited_type11		= 11,
	k7_unsolicited_type12		= 12,
	k7_unsolicited_type13		= 13,
	k7_unsolicited_type14		= 14,
	k7_unsolicited_mcpu_protocol_level = 15
} k7_umsg_type;

static void k7_handle_mrbinfo_msg (struct k7_channel *channel, const u8 *msg, int len)
{
	struct k7_dev *dev  = channel->dev;
	const u32   *data   = (void *)msg;
	u32          word0  = be32_to_cpu(data[0]);
	unsigned int mrb_id = word0 &  1;
	unsigned int size   = word0 & ~1;
	unsigned int flags  = be32_to_cpu(data[1]);

	kdebug(channel->name, "len=%u mrb_id=%u size=%u flags=0x%x", len, mrb_id, size, flags);
	if (len != 8) {
		kwarn(channel->name, "bad umsg len: %u", len);
		return;
	}
	if (channel->mrb_size[mrb_id] != 0)  // Paranoia
		kerr(channel->name, "BUG: mrb_size[%u] already set: old=0x%x new=0x%x", mrb_id, channel->mrb_size[mrb_id], size);
	channel->mrb_size  [mrb_id] = size;
	channel->mrb_offset[mrb_id] = 0;
	if (mrb_id == 0) {
		dev->mcpu_protocol_level = !!(flags & K7_MRB_OFFSET_FLAG_USES_HTYPES);
		kdinfo(dev->name, "mcpu_protocol_level=%u", dev->mcpu_protocol_level);
	} else {
		channel->enabled = 1;  /* only enable channel after the second MRB has reported */
		if (dev->mcpu_protocol_level != 0) {
			kdebug(dev->name, "Sending host_protocol_level=%u to mcpu", K7_HOST_PROTOCOL_LEVEL);
			k7_async_send_to_mcpu(dev, "protocol_level",
				K7_HRB_TYPE_PROTOCOL_LEVEL | (K7_HOST_PROTOCOL_LEVEL << 8),
				K7_DMA_FLAG_MRB1 | K7_DMA_FLAG_NO_REPLY, NULL, 0);
		}
	}
	if (dev->hsm_state < K7_HSM_STATE_DMA_READY)
		k7_update_hsm_state(dev, K7_HSM_STATE_DMA_READY);

	kdebug1(channel->name, "mrb: id=%u size=0x%05x flags=0x%x", mrb_id, size, flags);
}

static void k7_handle_mcpu_protocol_level_msg (struct k7_channel *channel, const u8 *msg, int len)
{
	struct k7_dev *dev = channel->dev;
	const u32   *data  = (void *)msg;
	u32          mcpu_protocol_level = be32_to_cpu(data[0]);
	u32          word1 = be32_to_cpu(data[1]);  /* reserved for future use */

	kdebug(channel->name, "len=%u mcpu_protocol_level=0x%x word1=0x%x", len, mcpu_protocol_level, word1);
	if (len != 8) {
		kwarn(channel->name, "bad umsg len: %u", len);
		return;
	}
	if (mcpu_protocol_level == 0)
		kerr(channel->name, "BUG: mcpu_protocol_level=%u not valid here", mcpu_protocol_level);
	else
		dev->mcpu_protocol_level = mcpu_protocol_level;
	k7_trigger_send_cbhras_to_mcpu(dev);
	kdinfo(dev->name, "mcpu_protocol_level=%u", dev->mcpu_protocol_level);
}

static void k7_handle_logmsg_msg (struct k7_channel *channel, u8 *msg, unsigned int len)
{
	if (len && msg[len - 1] == '\n')
		msg[--len] = '\0';
	if (len) {
		struct k7_dev *dev = channel->dev;  /* for kdlog() */
		kdlog(dev->name, "[HSM] %s", msg);
	}
}

static u32 k7_get_le32 (void *data)
{
	unsigned char *d = data;
	u32 val = d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24);
	return le32_to_cpu(val);
}

/*
 * These fastpath_mgmt subcommand constants are shared with HSM firmware.
 */
typedef enum {
	K7_FP_ENABLE		= 0,
	K7_FP_DISABLE		= 1,
	K7_FP_STOP_KEK_GROUP	= 2,
	K7_FP_REPLACE_KEK_ID	= 3,
	K7_FP_ACTIVATE_KEK_ID	= 4,
	K7_FP_DELETE_KEY_HANDLE	= 5,
	K7_FP_DELETE_SESSION_ID	= 6,
	K7_FP_UPDATE_MINIMUM_KEK_ID = 7,
} k7_fp_subcommand;

static void k7_handle_fastpath_mgmt (struct k7_dev *dev)
{
	struct k7_channel *channel = &dev->channels[K7_DMA_TARGET_SKU];
	u32 group_id, kek_id, pending_kek_id, minimum_kek_id, key_handle, *umsg = (u32 *)(dev->umsg);
	unsigned int active_count, nwords = dev->umsgx / sizeof(u32);
	k7_fp_subcommand subcommand;

	if (!nwords) {
		kerr(dev->name, "bad fastpath_mgmt msg: length=%u", dev->umsgx);
		return;
	}
	subcommand = k7_get_le32(umsg++);
	kdebug(dev->name, "subcommand=0x%x nwords=%u", subcommand, nwords);
	switch (subcommand) {
	case K7_FP_ENABLE:
		if (nwords != 1)
			break;
		SPIN_LOCK(&dev->lock);
		channel->enabled = 1;
		SPIN_UNLOCK(&dev->lock);
		kinfo(channel->name, "fastpath enabled by MCPU");
		return;
	case K7_FP_DISABLE:
		if (nwords != 1)
			break;
		SPIN_LOCK(&dev->lock);
		channel->enabled = 0;
		SPIN_UNLOCK(&dev->lock);
		/* MCPU should have stopped all KEK groups before killing the DMA channel: */
		active_count = channel->active_count;
		if (active_count)
			kerr(channel->name, "fastpath disabled by MCPU while active_count=%u", active_count);
		else
			kinfo(channel->name, "fastpath disabled by MCPU");
		k7_keycache_depopulate(dev);
		return;
	case K7_FP_STOP_KEK_GROUP:
		if (nwords != 2)
			break;
		group_id = k7_get_le32(umsg++);
		kdebug(channel->name, "group_id=%u stopped by MCPU", group_id);
		k7_keycache_stop_kek_group(dev, group_id);
		return;
	case K7_FP_REPLACE_KEK_ID:
		if (nwords != 5)
			break;
		group_id       = k7_get_le32(umsg++);
		kek_id         = k7_get_le32(umsg++);
		pending_kek_id = k7_get_le32(umsg++);
		minimum_kek_id = k7_get_le32(umsg++);
		kdebug(channel->name, "KEK replacement: group_id=%u kek_id=%08x pending_kek_id=%08x minimum_kek_id=%08x",
						group_id, kek_id, pending_kek_id, minimum_kek_id);
		k7_keycache_replace_kek_id(dev, group_id, kek_id, pending_kek_id, minimum_kek_id);
		return;
	case K7_FP_ACTIVATE_KEK_ID:
		if (nwords != 4)
			break;
		group_id        = k7_get_le32(umsg++);
		kek_id          = k7_get_le32(umsg++);
		minimum_kek_id  = k7_get_le32(umsg++);
		kdebug(channel->name, "KEK activate: group_id=%u kek_id=%08x minimum_kek_id=%08x", group_id, kek_id, minimum_kek_id);
		k7_keycache_activate_kek_id(dev, group_id, kek_id, minimum_kek_id);
		return;
	case K7_FP_DELETE_KEY_HANDLE:
		if (nwords != 2)
			break;
		key_handle = k7_get_le32(umsg++);
		kdebug(channel->name, "key_handle=%08x deleted by MCPU", key_handle);
		k7_keycache_delete_key(dev, key_handle, NULL);
		return;
	case K7_FP_DELETE_SESSION_ID:
	{
		u32 session_id;
		if (nwords != 2)
			break;
		session_id = k7_get_le32(umsg++);
		k7_delete_session(dev, session_id);
		return;
	}
	case K7_FP_UPDATE_MINIMUM_KEK_ID:
		if (nwords != 3)
			break;
		group_id = k7_get_le32(umsg++);
		minimum_kek_id = k7_get_le32(umsg++);
		kdebug(channel->name, "Updating minimum_kek_id: group_id=%u minimum_kek_id=%u", group_id, minimum_kek_id);
		k7_keycache_update_minimum_kek_id(dev, group_id, minimum_kek_id);
		return;
	default:
		break;
	}
	kerr(dev->name, "bad fastpath_mgmt msg: subcommand=0x%x length=%u", subcommand, dev->umsgx);
}

static void k7_handle_umsg (struct k7_channel *channel, u8 msg_type)
{
	static const char *sc[] = {"unknown", "LOG", "DEBUG", "TRACE", "HSM_STATE", "CALLBACK", "DRIVER"};
	struct k7_dev *dev = channel->dev;

	kdebug(channel->name, "%s: len=%u", sc[(msg_type < 7) ? msg_type : 0], dev->umsgx);
	switch (msg_type) {
	case k7_unsolicited_logmsg:
		k7_handle_logmsg_msg(channel, dev->umsg, dev->umsgx);
		break;
	case k7_unsolicited_debug:		/* FIXME: implement this */
		goto badmsg;
	case k7_unsolicited_trace:		/* FIXME: implement this */
		goto badmsg;
	case k7_unsolicited_hsm_state:
		if (dev->umsgx == sizeof(u32)) {
			SPIN_LOCK(&dev->lock);
			k7_update_hsm_state(dev, k7_get_le32(dev->umsg));
			SPIN_UNLOCK(&dev->lock);
			break;
		}
		goto badmsg;
	case k7_unsolicited_protocol_version:  /* HSM protocol version for ICD commands etc. */
		if (dev->umsgx == (1 * sizeof(u32))) {
			dev->hsm_protocol_version = k7_get_le32(dev->umsg);
			break;
		}
		goto badmsg;
	case k7_unsolicited_fastpath_mgmt:
		k7_handle_fastpath_mgmt(dev);
		break;
	case k7_unsolicited_callback_info:
		if (dev->umsgx == (2 * sizeof(u32))) {
			SPIN_LOCK(&dev->lock);
			dev->callback_io_version = k7_get_le32(dev->umsg);
			dev->callback_version = k7_get_le32(dev->umsg + sizeof(u32));
			SPIN_UNLOCK(&dev->lock);
			break;
		}
		goto badmsg;
	case k7_unsolicited_mrbinfo:
		SPIN_LOCK(&dev->lock);
		k7_handle_mrbinfo_msg(channel, dev->umsg, dev->umsgx);
		SPIN_UNLOCK(&dev->lock);
		break;
	case k7_unsolicited_mcpu_protocol_level:
		SPIN_LOCK(&dev->lock);
		k7_handle_mcpu_protocol_level_msg(channel, dev->umsg, dev->umsgx);
		SPIN_UNLOCK(&dev->lock);
		break;
	default:
		kwarn(channel->name, "unknown umsg type: %u -- IGNORED", msg_type);
	}
	return;
badmsg:
	kwarn(channel->name, "unimplemented umsg=%u(%s) umsgx=%d -- IGNORED", msg_type, sc[msg_type], dev->umsgx);
}

static int k7_handle_unsolicited_iv (struct k7_dev *dev, u8 user_byte, u64 data)
{
	struct k7_channel *channel = &dev->channels[K7_DMA_TARGET_MCPU];
	u8 eof   = (user_byte >> 3) & 1;
	u8 len   = (user_byte & 7) ? (user_byte & 7) : 8;
	u8 *umsg = dev->umsg;
	u8 *d    = (void *)&data;

	while (len--) {
		if (dev->umsgx >= K7_UMSG_MAX_LEN) {
			kwarn(dev->name, "max length (%u) exceeded, discarding remaining data", K7_UMSG_MAX_LEN);
			break;
		}
		umsg[dev->umsgx++] = *d++;
	}
	if (eof) {
		u8 msg_type = (user_byte >> 4); /* msg_type is only taken from the final (eof=1) msg of the sequence */
		umsg[dev->umsgx] = 0;  /* Zero-termination for strings; space is allocated in the buffer for this */
		k7_handle_umsg(channel, msg_type);
		dev->umsgx = 0;
	}
	return 0;
}

static int k7_service_htb_entry (struct k7_dev *dev, u64 *htbe)
{
	struct k7_channel *channel = NULL;
	u64          flags    = be64_to_cpu(htbe[0]);
	u64          daddr    = be64_to_cpu(htbe[1]);
	unsigned int htype    = extract64(flags, K7_DMAHDR_HTYPE);
	unsigned int rqstr    = extract64(flags, K7_DMAHDR_RQSTR);
	unsigned int rqaction = extract64(flags, K7_DMAHDR_RQACTION);
	unsigned int len      = extract64(flags, K7_DMAHDR_IVLEN);
	unsigned int vfid     = extract64(flags, K7_DMAHDR_VFID);
	unsigned int is_notify_rx = 0;
	int          ret = -EIO;
	u8           user_byte;

	kdebug1(dev->name, "flags=0x%llx daddr=%016llx", flags, daddr);
	if (len != 0x08) {
		kerr(dev->name, "%bad LEN=%u flags=0x%llx", len, flags);
		k7_dev_failure(dev, "bad htb entry", "len/flags");
	} else if (htype == K7_HTYPE_M2H_IV && (user_byte = extract64(flags, K7_DMAHDR_USER)) != 0) {
		ret = k7_handle_unsolicited_iv(dev, user_byte, htbe[1]);
	} else if (daddr & 7) {
		kerr(dev->name, "bad daddr=%016llx flags=0x%llx", daddr, flags);
		k7_dev_failure(dev, "bad htb entry", "daddr");
	} else {
		/* Validate the DMA htype field: */
		channel = k7_decode_htb_htype(dev, htype, rqstr, rqaction, &is_notify_rx);
		if (!channel) {
			if (k7_debug)
				k7_dump_htb(dev);
			k7_dev_failure(dev, "bad htb entry", "htype");
		} else {
			/* Validate vfid, but only for debugging.. might not be valid inside a VM */
			if (vfid != dev->vfid)
				kwarn(dev->name, "bad vfid=%u(expected %u) flags=0x%llx", vfid, dev->vfid, flags);
			if (is_notify_rx) {
				if (rqstr == 1) {  /* rqstr should always be 1 ("host") for notify_rx */
					ret = k7_handle_notify_rx(channel, daddr);
				} else {
					kerr(dev->name, "notify_rx bad rqstr=%u(expected 1) flags=0x%llx", rqstr, flags);
					k7_dev_failure(dev, "bad htb entry", "notify_rx bad rqstr");
				}
			} else if (k7_service_hra_daddr(channel, daddr) && k7_cb_service_daddr(dev, daddr)) {
				kerr(channel->name, "HRA not found, flags=0x%llx daddr=%016llx (%p)", flags, daddr, htbe);
				k7_dev_failure(dev, "bad htb entry", "HRA not found");
			} else {
				ret = 0;
			}
		}
	}
	return ret;
}

/* Called from (re-)initialization code */
void k7_reinit_htb (struct k7_dev *dev)
{
	if (k7_zeromem)
		memset(dev->htb_area.vaddr, 0, dev->htb_area.len);	/* paranoia */
	dev->last_wa = dev->htb_area.daddr;
	wmb();
	K7_WRITE64(K7_HTBWA, dev->htb_area.daddr);
	K7_WRITE64(K7_HTBTC, dev->htb_area.len);
	mb();
}

/*
 * Called from HTB interrupt thread.
 */
void k7_service_htb (struct k7_dev *dev)
{
	u64 last_wa, htb_wa;
	void *htbe;
	int err, htb_enabled;

	mutex_lock(&dev->htb_mutex);
	while (1) {
		SPIN_LOCK(&dev->lock);
		htb_enabled = dev->htb_enabled;
		htb_wa = K7_READ64(K7_HTBWA);	/* reading this also clears the associated interrupt */
		if (htb_wa == ~0ull)
			k7_poll_pcie_link_failed(dev);
		SPIN_UNLOCK(&dev->lock);
		if (!htb_enabled)
			break;
		htb_wa &= ~(u64)(K7_HTB_ENTRY_BYTES - 1);  /* ignore partially filled HTB entries */

		/* Ensure we got a valid value back from hardware (reads zero after a reset): */
		if (htb_wa < dev->htb_area.daddr || htb_wa > (dev->htb_area.daddr + K7_HTB_SIZE)) {
			kerr(dev->name, "bad HTBWA: %016llx: htb_daddr=%p", htb_wa, dev->htb_area.daddr);
			k7_dev_failure(dev, "bad HTBWA", "not an HTB address");
			break;
		}

		last_wa = dev->last_wa;
		if (last_wa == htb_wa)
			break;  /* All caught up. */
		htbe = dev->htb_area.vaddr + (last_wa - dev->htb_area.daddr);
		rmb();
		do {
			err = k7_service_htb_entry(dev, htbe);
			htbe    += K7_HTB_ENTRY_BYTES;
			last_wa += K7_HTB_ENTRY_BYTES;
		} while (last_wa != htb_wa && !err);
		if (err) {
			kerr(dev->name, "bad HTBWA: %016llx: htb_daddr=%p", htb_wa, dev->htb_area.daddr);
			k7_dev_failure(dev, "bad HTBWA", "not an HTB address");
			break;
		}
		dev->last_wa = last_wa;
		if (last_wa == (((unsigned long)(dev->htb_area.daddr)) + dev->htb_area.len))
			k7_reinit_htb(dev);
		break;  /* Do only one pass at a time, to avoid appearing to be a "soft lockup". */
	}
	mutex_unlock(&dev->htb_mutex);
}
