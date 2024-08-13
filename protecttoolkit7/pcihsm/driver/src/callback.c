/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * callback.c
 *
 * Implementation for host side of HSM callback mechanism.
 */
#include "headers.h"
#include "proc.h"

enum {
	K7_CB_STATE_DISABLED    = 0,
	K7_CB_STATE_ENABLING    = 1,
	K7_CB_STATE_ENABLED     = 2,
	K7_CB_STATE_DISABLING   = 3
};

static int k7_auto_cancel_callbacks = 1;	/* change to 0 if pedClient is updated to cancel cb_id's on its own */

static void k7_cbhra_free (struct k7_dev *dev, struct k7_cbhra *cbhra);
static void k7_cb_free_cbhra_donelist (struct k7_dev *dev);

static unsigned int k7_extract_cb_id (struct k7_dev *dev, u64 *hdr)
{
	u64 hdr3 = be64_to_cpu(hdr[3]);
	return extract64(hdr3, BE64MSK(8,15));
}

static void k7_remove_free_cb_ids_from_donelist (struct k7_dev *dev)
{
	struct k7_cbhra *cbhra, *next;

	SPIN_LOCK_REQUIRED(&dev->lock);
	list_for_each_entry_safe(cbhra, next, &dev->cbhra_donelist, list) {
		struct k7_dt *first_dt = list_first_entry(&cbhra->hra_dtc, struct k7_dt, list);
		unsigned int cb_id = k7_extract_cb_id(dev, first_dt->data.vaddr);
		if (dev->cb_id_state[cb_id] == K7_CB_ID_STATE_FREE) {
			list_del_init(&cbhra->list);
			k7_cbhra_free(dev, cbhra);
		}
	}
}

static void k7_free_cb_id (struct k7_dev *dev, unsigned int cb_id)
{
	SPIN_LOCK_REQUIRED(&dev->lock);
	if (dev->cb_id_state[cb_id] != K7_CB_ID_STATE_FREE) {
		dev->cb_id_state[cb_id] = K7_CB_ID_STATE_FREE;
		k7_remove_free_cb_ids_from_donelist(dev);
		wake_up(&dev->cbhra_wq);
	}
}

static void k7_async_send_cb_cancel (struct k7_dev *dev, const char *debug_label, unsigned int cb_id)
{
	if (k7_cbdebug)
		kinfo(dev->name, "sending %s: cb_id=%u", debug_label, cb_id);
	k7_async_send_to_mcpu(dev, debug_label, K7_HRB_TYPE_CB_CANCEL | (cb_id << 16),
		K7_DMA_FLAG_NO_REPLY | K7_DMA_FLAG_MRB1 | K7_DMA_FLAG_CBHRA, NULL, 0);
}

static void k7_handle_cbhra (struct k7_dev *dev, struct k7_cbhra *cbhra, struct k7_dt *first_dt)
{
	void *vaddr = first_dt->data.vaddr;
	u64 tmp, *hdr = vaddr;
	unsigned int rlen, signature, data_len, min_len = K7_HRA_HDR_LEN_MCPU - sizeof(u64);
	unsigned int hra_type, cb_id;

	SPIN_LOCK_REQUIRED(&dev->lock);

	/* hdr[0]: 64-bit word: DMA header with rlen */
	tmp  = be64_to_cpu(hdr[0]);
	rlen = extract64(tmp, K7_DMAHDR_RLEN);
	if (rlen > (K7_CBHRA_SIZE - sizeof(u64))) {
		kerr(dev->name, "bad rlen: rlen=%u max=%u", rlen, K7_CBHRA_SIZE - sizeof(u64));
		goto free_it;
	}

	/* hdr[1]: first dt_addr of HRA; should match the bus addr of the HRA */
	tmp = be64_to_cpu(hdr[1]);
	if (tmp != first_dt->daddr) {
		kderr(dev->name, "hra_p(0x%llx) != daddr(0x%llx)", tmp, (u64)first_dt->daddr);
		goto free_it;
	}

	/* hdr[2]: signature and hardware dependent field (HDF) */
	tmp = be64_to_cpu(hdr[2]);
	signature = extract64(tmp, K7_HRA_SIGNATURE_MASK);
	if (signature != 0x524d) {
		kderr(dev->name, "bad signature 0x%04x", signature);
		goto free_it;
	}

	/* hdr[3]: software defined: hra_type, parameters, data_len, various flags */
	tmp      = be64_to_cpu(hdr[3]);
	hra_type = dev->mcpu_protocol_level ? extract64(tmp, K7_HRx_TYPE_BITMSK) : K7_HRA_TYPE_CB_CMD;
	data_len = extract64(tmp, BE64MSK(40,63));
	if (rlen < min_len || data_len > (rlen - min_len)) {  /* Note: data_len can be less than rlen.. */
		cbhra->hra_len = 0;  /* should never happen */
		kerr(dev->name, "bad len: rlen=%u data_len=%u", rlen, data_len);
		goto free_it;
	}
	cbhra->hra_len = data_len;
	cbhra->offset  = K7_HRA_HDR_LEN_MCPU;
	INIT_LIST_HEAD(&cbhra->list);
	switch (hra_type) {
		case K7_HRA_TYPE_CB_CMD:
			cb_id = k7_extract_cb_id(dev, vaddr);
			cbdebug(dev->name, "rlen=%u data_len=%u hra_type=%u hra_len=%u cb_id=%u",
				rlen, data_len, hra_type, cbhra->hra_len, cb_id);
			if (cb_id != 0 && dev->cb_state == K7_CB_STATE_ENABLED) {
				switch (dev->cb_id_state[cb_id]) {
				case K7_CB_ID_STATE_FREE:
					dev->cb_id_state[cb_id] = K7_CB_ID_STATE_UNCLAIMED;
					/* fall thru */
				case K7_CB_ID_STATE_UNCLAIMED:
				case K7_CB_ID_STATE_CLAIMED:
					list_add_tail(&cbhra->list, &dev->cbhra_donelist);
					wake_up(&dev->cbhra_wq);
					return;
				case K7_CB_ID_STATE_HSM_CANCELLED:
					kerr(dev->name, "Unexpected data for cb_id=%u after HSM_CANCELLED", cb_id);
					break;
				case K7_CB_ID_STATE_HOST_CANCELLED:
					break;
				}
			}
			break;
		case K7_HRA_TYPE_CB_CANCEL:
			cb_id = k7_extract_cb_id(dev, vaddr);
			cbdebug(dev->name, "CB_CANCEL: rlen=%u data_len=%u hra_type=%u hra_len=%u cb_id=%u",
				rlen, data_len, hra_type, cbhra->hra_len, cb_id);
			if (cb_id != 0) {
				switch (dev->cb_id_state[cb_id]) {
				case K7_CB_ID_STATE_FREE:
				case K7_CB_ID_STATE_HSM_CANCELLED:
					kerr(dev->name, "unexpected CB_CANCEL from HSM, cb_id=%u state=%u", cb_id, dev->cb_id_state[cb_id]);
					k7_async_send_cb_cancel(dev, "-CB_CANCEL0", cb_id);
					break;
				case K7_CB_ID_STATE_HOST_CANCELLED:
					k7_free_cb_id(dev, cb_id);
					break;
				case K7_CB_ID_STATE_UNCLAIMED:
					dev->cb_id_state[cb_id] = K7_CB_ID_STATE_FREE;
					k7_async_send_cb_cancel(dev, "-CB_CANCEL1", cb_id);
					break;
				case K7_CB_ID_STATE_CLAIMED:
					dev->cb_id_state[cb_id] = K7_CB_ID_STATE_HSM_CANCELLED;
					break;
				}
			}
			break;
		case K7_HRA_TYPE_LOGMSG:
		{
			const unsigned int max_logmsg = K7_CBHRA_SIZE - K7_HRA_HDR_LEN_MCPU - 1;
			char *msg = (char *)vaddr + K7_HRA_HDR_LEN_MCPU;
			if (data_len && msg[data_len - 1] == '\n')
				data_len--;
			if (data_len >= max_logmsg)  /* Ensure there's room to insert the '\0' */
				data_len = max_logmsg;
			msg[data_len] = '\0';
			if (data_len)
				kdlog(dev->name, "[HSM] %s", msg);
			break;
		}
		case K7_HRA_TYPE_ETHERNET:
			if (k7eth_rx_ethernet(dev, vaddr) == 0)
				break;
			kerr(dev->name, "bad hra_type=%u", hra_type);
			break;
		default:
			kerr(dev->name, "bad hra_type=%u", hra_type);
	}
free_it:
	if (dev->mcpu_protocol_level != 0)
		k7_trigger_send_cbhras_to_mcpu(dev);
	k7_cbhra_free(dev, cbhra);
}

/* This is called from the HTB interrupt thread in htb.c */
int k7_cb_service_daddr (struct k7_dev *dev, u64 daddr)
{
	struct k7_cbhra *cbhra;
	int ret = -EINVAL;

	SPIN_LOCK(&dev->lock);
	if (!list_empty(&dev->cbhra_busylist)) {
		list_for_each_entry(cbhra, &dev->cbhra_busylist, list) {
			struct k7_dt *first_dt = list_first_entry(&cbhra->hra_dtc, struct k7_dt, list);
			if (daddr == first_dt->daddr) {
				list_del_init(&cbhra->list);
				k7_dma_unmap_dtc(dev, &cbhra->hra_dtc, DMA_FROM_DEVICE);
				if (--dev->cbhra_count < 0) {
					kerr(dev->name, "cbhra_count was %d", dev->cbhra_count);
					dev->cbhra_count = 0;
				}
				k7_handle_cbhra(dev, cbhra, first_dt);
				ret = 0;  /* success: found and serviced cbhra */
				break;
			}
		}
	}
	SPIN_UNLOCK(&dev->lock);
	return ret;
}

/*
 * This is called from main.c for requests tagged with K7_DMA_FLAG_CBHRA,
 * to move the associated hra buffer (if any) onto cbhra_busylist afterward.
 */
int k7_cb_submit (struct k7_dev *dev, struct k7_channel *channel, struct k7_req *req)
{
	struct k7_cbhra *cbhra = NULL;
	int ret;

	if (req->ioc->outbuf_size) {
		cbhra = kzalloc(sizeof(*cbhra), GFP_KERNEL);
		if (!cbhra)
			return -ENOMEM;
	}
	SPIN_LOCK(&dev->lock);
	ret = k7_submit_req(channel, req);
	if (cbhra) {
		if (ret) {
			kfree(cbhra);
		} else {
			/* Move hra_dtc from req to cbhra_busylist */
			INIT_LIST_HEAD(&cbhra->hra_dtc);
			list_splice_init(&req->hra_dtc, &cbhra->hra_dtc);  /* aka. "move_list(from,to)" */
			INIT_LIST_HEAD(&cbhra->list);
			list_add_tail(&cbhra->list, &dev->cbhra_busylist);
			dev->cbhra_count++;
		}
	}
	SPIN_UNLOCK(&dev->lock);
	return ret;
}

static int k7_cb_enqueue_hras (struct k7_dev *dev)
{
	static int babble;
	struct k7_dma_ioctl *ioc;
	int ret = 0;

	if (dev->cbhra_count >= K7_CBHRA_MIN_COUNT)
		return 0;
	ioc = kzalloc(sizeof(*ioc), GFP_KERNEL);
	if (!ioc)
		return -ENOMEM;
	ioc->target        = K7_DMA_TARGET_MCPU;
	ioc->flags         = K7_DMA_FLAG_NO_REPLY | K7_DMA_FLAG_MRB1 | K7_DMA_FLAG_CBHRA;
	ioc->timeout_msecs = K7_CBHRA_MAX_WAIT;   /* Timeout for sending to MCPU only */
	ioc->outbuf_size   = K7_CBHRA_SIZE;

	while (dev->cbhra_count < K7_CBHRA_MIN_COUNT) {
		if (dev->mcpu_protocol_level == 0 && dev->cb_state != K7_CB_STATE_ENABLED)
			break;
		ret = k7_do_dma_ioctl(dev, ioc, K7_HRB_TYPE_DEFAULT);
		if (ret || ++babble < K7_CBHRA_MIN_COUNT)
			cbdebug(dev->name, "k7_do_dma_ioctl() ret=%d", ret);
		if (ret)
			break;
	}
	kfree(ioc);
	return ret;
}

static int k7_cb_send_enable_to_mcpu (struct k7_dev *dev)
{
	struct k7_dma_ioctl *ioc;
	int ret = 0;

	if (dev->mcpu_protocol_level != 0) {
		/* Send the enable message first, to avoid confusing new firmware on MCPU */
		ioc = kzalloc(sizeof(*ioc), GFP_KERNEL);
		if (!ioc)
			return -ENOMEM;
		ioc->target        = K7_DMA_TARGET_MCPU;
		ioc->flags         = K7_DMA_FLAG_NO_REPLY | K7_DMA_FLAG_MRB1 | K7_DMA_FLAG_CBHRA;
		ioc->timeout_msecs = K7_CBHRA_MAX_WAIT;
		ret = k7_do_dma_ioctl(dev, ioc, K7_HRB_TYPE_CB_ENABLE);
		cbdebug(dev->name, "k7_do_dma_ioctl() ret=%d", ret);
		kfree(ioc);
	}
	k7_trigger_send_cbhras_to_mcpu(dev);
	return 0;
}

static int k7_cb_send_disable_to_mcpu (struct k7_dev *dev)
{
	struct k7_dma_ioctl *ioc;
	int ret;

	ioc = kzalloc(sizeof(*ioc), GFP_KERNEL);
	if (!ioc)
		return -ENOMEM;
	ioc->target        = K7_DMA_TARGET_MCPU;
	ioc->flags         = K7_DMA_FLAG_NO_REPLY | K7_DMA_FLAG_MRB1;
	ioc->timeout_msecs = K7_CBHRA_MAX_WAIT;   /* Timeout for sending to MCPU only */
	ret = k7_do_dma_ioctl(dev, ioc, K7_HRB_TYPE_CB_DISABLE);
	kfree(ioc);
	return ret;
}

static void k7_cbhra_free (struct k7_dev *dev, struct k7_cbhra *cbhra)
{
	struct k7_channel *channel = &dev->channels[K7_DMA_TARGET_MCPU];

	k7_free_dtc(channel, &cbhra->hra_dtc, 0);
	memset(cbhra, 0, sizeof(*cbhra));
	kfree(cbhra);
}

static void k7_cb_force_free_cbhra_busylist (struct k7_dev *dev)
{
	struct k7_cbhra *cbhra;

	while (NULL != (cbhra = list_first_entry_or_null(&dev->cbhra_busylist, struct k7_cbhra, list))) {
		cbdebug(dev->name, "from busylist: cbhra=%p", cbhra);
		list_del_init(&cbhra->list);
		dev->cbhra_count--;
		k7_dma_unmap_dtc(dev, &cbhra->hra_dtc, DMA_FROM_DEVICE);
		k7_cbhra_free(dev, cbhra);
	}
	if (dev->cbhra_count != 0) {
		kerr(dev->name, "cbhra_count was %d", dev->cbhra_count);
		dev->cbhra_count = 0;
	}
}

static void k7_cb_free_cbhra_donelist (struct k7_dev *dev)
{
	struct k7_cbhra *cbhra;

	/* Free all of the HRAs from donelist */
	SPIN_LOCK_REQUIRED(&dev->lock);
	while (NULL != (cbhra = list_first_entry_or_null(&dev->cbhra_donelist, struct k7_cbhra, list))) {
		cbdebug(dev->name, "from donelist: cbhra=%p", cbhra);
		list_del_init(&cbhra->list);
		k7_cbhra_free(dev, cbhra);
	}
}

static int k7_cb_disable_at_mcpu (struct k7_dev *dev)
{
	int ret;

	/* Tell the MCPU we are disabling callback, causing it to cancel/return HRAs to us */
	ret = k7_cb_send_disable_to_mcpu(dev);
	if (ret < 0) {
		/* ECONNREFUSED is normal here if the HSM has been freshly reset */
		if (ret != -ECONNREFUSED || k7_debug)
			kerr(dev->name, "k7_cb_send_disable_to_mcpu() failed, err=%d", ret);
	}
	return ret;
}

static void k7_free_all_cb_ids (struct k7_dev *dev)
{
	unsigned int cb_id;

	SPIN_LOCK_REQUIRED(&dev->lock);
	for (cb_id = 0; cb_id <= K7_MAX_CB_ID; cb_id++)
		k7_free_cb_id(dev, cb_id);
}

static int k7_do_cb_disable (struct k7_dev *dev)
{
	pid_t cpid = current->tgid;
	int ret, do_disable = 0;

	cbdebug(dev->name, "current_pid=%llu cb_pid=%llu cb_state=%u",
		(u64)cpid, (u64)dev->cb_pid, dev->cb_state);
	SPIN_LOCK(&dev->lock);
	switch (dev->cb_state) {
		case K7_CB_STATE_DISABLED:
		case K7_CB_STATE_DISABLING:
			dev->cb_pid = 0;
			ret = 0;
			break;
		case K7_CB_STATE_ENABLED:
		case K7_CB_STATE_ENABLING:
			if (dev->cb_pid != cpid) {
				kwarn(dev->name, "wrong pid: %llu vs %llu", (u64)dev->cb_pid, (u64)cpid);
				ret = -EBUSY;
			} else {
				if (dev->cb_state == K7_CB_STATE_ENABLING) {
					dev->cb_state = K7_CB_STATE_DISABLED;
				} else {
					dev->cb_state = K7_CB_STATE_DISABLING;
					do_disable = 1;
				}
				dev->cb_pid = 0;
				k7_free_all_cb_ids(dev);
				k7_cb_free_cbhra_donelist(dev);
				kfinfo(dev->name, "%s[%llu] stopped listening", current->comm, (u64)cpid);
				ret = 0;
			}
			break;
		default:
			ret = -EINVAL;
	}
	SPIN_UNLOCK(&dev->lock);
	if (do_disable) {
		(void) k7_cb_disable_at_mcpu(dev);  /* don't care if this fails */
		SPIN_LOCK(&dev->lock);
		dev->cb_state = K7_CB_STATE_DISABLED;
		SPIN_UNLOCK(&dev->lock);
	}
	return ret;
}

static int k7_cb_start_listening (struct k7_dev *dev)
{
	pid_t cpid = current->tgid;
	int ret, do_enable = 0;

	do {
		SPIN_LOCK(&dev->lock);
		if (dev->hsm_state != K7_HSM_STATE_READY) {
			cbdebug(dev->name, "ret=-EAGAIN");
			ret = -EAGAIN;
		} else switch (dev->cb_state) {
			case K7_CB_STATE_DISABLED:
				dev->cb_state = K7_CB_STATE_ENABLING;
				dev->cb_pid   = cpid;
				ret = 0;  /* keep compiler happy */
				do_enable = 1;
				cbdebug(dev->name, "new cb_state=%u ret=%d", dev->cb_state, ret);
				break;
			case K7_CB_STATE_ENABLED:
				ret = (dev->cb_pid == cpid) ? 0 : -EBUSY;
				cbdebug(dev->name, "new cb_state=%u ret=%d", dev->cb_state, ret);
				break;
			case K7_CB_STATE_ENABLING:	/* can happen if two threads call in simultaneously */
				ret = signal_pending(current) ? -EINTR : -EEXIST;
				break;
			default:
				cbdebug(dev->name, "cb_state=%u ret=-EINVAL", dev->cb_state);
				ret = -EINVAL;
				break;
		}
		SPIN_UNLOCK(&dev->lock);
	} while (ret == -EEXIST);
	if (do_enable) {
		ret = k7_cb_send_enable_to_mcpu(dev);
		if (ret) {
			k7_do_cb_disable(dev);
		} else {
			SPIN_LOCK(&dev->lock);
			dev->cb_state = K7_CB_STATE_ENABLED;
			SPIN_UNLOCK(&dev->lock);
			kfinfo(dev->name, "%s[%llu] listening", current->comm, (u64)cpid);
		}
		cbdebug(dev->name, "new cb_state=%u ret=%d", dev->cb_state, ret);
	}
	return ret;
}

static int k7_cb_id_has_activity (struct k7_dev *dev, unsigned int cb_id)
{
	int ret = 0;  /* default: do NOT wake caller */

	SPIN_LOCK(&dev->lock);
	if (cb_id && dev->cb_id_state[cb_id] != K7_CB_ID_STATE_CLAIMED) {
		ret = 1;  /* wake caller */
	} else {
		struct k7_cbhra	*cbhra, *next;
		/* Scan donelist for a suitable match for cb_id */
		list_for_each_entry_safe(cbhra, next, &dev->cbhra_donelist, list) {
			struct k7_dt *first_dt = list_first_entry(&cbhra->hra_dtc, struct k7_dt, list);
			unsigned int this_cb_id = k7_extract_cb_id(dev, first_dt->data.vaddr);
			if (cb_id == 0) {
				if (dev->cb_id_state[this_cb_id] == K7_CB_ID_STATE_UNCLAIMED) {
					ret = 1;  /* wake caller */
					break;
				}
			} else if (cb_id == this_cb_id) {
				ret = 1;  /* wake caller */
				break;
			}
		}
	}
	SPIN_UNLOCK(&dev->lock);
	return ret;
}

static int k7_wait_on_cb_id (struct k7_dev *dev, unsigned int cb_id, unsigned long timeout)
{
	long ret = wait_event_interruptible_timeout
			(dev->cbhra_wq, !dev->icd_enabled || dev->failed || k7_cb_id_has_activity(dev, cb_id), timeout);
	if (ret == 0)
		return -ETIMEDOUT;
	if (ret == -ERESTARTSYS)
		return -EINTR;
	if (!dev->icd_enabled || dev->failed)
		return -EIO;
	return 0;
}

static int k7_cb_io_read_data (struct k7_dev *dev, void *buf, unsigned int bufsize, unsigned int *cb_id_p)
{
	struct k7_cbhra	*cbhra, *next;
	unsigned int	cb_id = *cb_id_p;

	SPIN_LOCK_REQUIRED(&dev->lock);
	if (cb_id && dev->cb_id_state[cb_id] != K7_CB_ID_STATE_CLAIMED) {
		kwarn(dev->name, "want_cb_id=%u not claimed (state=%u)", cb_id, dev->cb_id_state[cb_id]);
		return -ENODATA;
	}
	list_for_each_entry_safe(cbhra, next, &dev->cbhra_donelist, list) {
		struct k7_dt *first_dt = list_first_entry(&cbhra->hra_dtc, struct k7_dt, list);
		unsigned int len = cbhra->hra_len;
		if (len) {
			unsigned int this_cb_id = k7_extract_cb_id(dev, first_dt->data.vaddr);
			u8 *data;
			if (!cb_id) {
				if (dev->cb_id_state[this_cb_id] != K7_CB_ID_STATE_UNCLAIMED)
					continue;
				dev->cb_id_state[this_cb_id] = K7_CB_ID_STATE_CLAIMED;
				*cb_id_p = this_cb_id;
			} else if (cb_id != this_cb_id) {
				continue;
			}
			data = (u8 *)first_dt->data.vaddr + cbhra->offset;
			if (len > bufsize)
				len = bufsize;
			memcpy(buf, data, len);
			if (k7_cbdebug)
				k7_dumpmem(NULL, dev->name, NULL, "CB_READ", data, 0, len);
			cbhra->offset  += len;
			cbhra->hra_len -= len;
		}
		if (cbhra->hra_len == 0) {
			list_del_init(&cbhra->list);	/* remove from donelist */
			k7_cbhra_free(dev, cbhra);
		}
		if (len)
			return len;
	}
	return 0;
}

static int k7_cb_io_read_internal (struct k7_dev *dev, struct uhd_cb_rw_args *args, unsigned int *cb_id_p)
{
	unsigned long timeout;
	int ret;

	if (!args->in.buf || !args->in.size) {
		kerr(dev->name, "outbuf=%p outbuf_size=%u", args->in.buf, args->in.size);
		return -EINVAL;
	}
	if (dev->hsm_state != K7_HSM_STATE_READY)
		return -ECONNREFUSED;
	timeout = msecs_to_jiffies(args->in.timeout);
	if (!dev->icd_enabled) {
		ret = -EIO;
	} else {
		void *buf = NULL;
		ret = k7_cb_start_listening(dev);
		if (ret == 0) {
			buf = kmalloc(args->in.size, GFP_KERNEL);
			if (!buf)
				ret = -ENOMEM;
		}
		while (ret == 0) {
			unsigned int cb_id = *cb_id_p;
			if (cb_id && dev->cb_id_state[cb_id] != K7_CB_ID_STATE_CLAIMED) {
				kwarn(dev->name, "want_cb_id=%u not claimed (state=%u)", cb_id, dev->cb_id_state[cb_id]);
				ret = -ENODATA;
				break;
			}
			k7_trigger_send_cbhras_to_mcpu(dev);
			ret = k7_wait_on_cb_id(dev, cb_id, timeout);
			if (ret)
				break;
			SPIN_LOCK(&dev->lock);
			ret = k7_cb_io_read_data(dev, buf, args->in.size, cb_id_p);
			SPIN_UNLOCK(&dev->lock);
			if (ret > 0 && copy_to_user((void *)(long)(args->in.buf), buf, ret)) {
				kerr(dev->name, "copy_to_user(outbuf=0x%llx) failed", args->in.buf);
				ret = -EFAULT;
			}
		}
		if (buf)
			kfree(buf);
	}
	return ret;
}

static int k7_cb_io_write_internal (struct k7_dev *dev, struct k7_dma_ioctl *ioc, unsigned int cb_id)
{
	int ret;

	if (!ioc->inbuf || !ioc->inbuf_size) {
		kerr(dev->name, "inbuf=%p inbuf_size=%u", ioc->inbuf, ioc->inbuf_size);
		return -EINVAL;
	}
	if (dev->hsm_state != K7_HSM_STATE_READY || !dev->icd_enabled)
		return -ECONNREFUSED;
	if (dev->cb_state != K7_CB_STATE_ENABLED) {
		kerr(dev->name, "cb_state=%u", dev->cb_state);
		return -EINVAL;
	}
	if (dev->cb_pid != current->tgid) {
		kerr(dev->name, "cb_pid=%u current_pid=%u", dev->cb_pid, current->tgid);
		return -EBUSY;
	}
	if (k7_cbdebug) {
		kfinfo(dev->name, "cb_id=%u", cb_id);
		k7_dumpmem(NULL, dev->name, NULL, "CB_WRITE", (void *)(long)ioc->inbuf, 0, ioc->inbuf_size);
	}
	ret = k7_do_dma_ioctl(dev, ioc, ((cb_id & 0xff) << 16) | K7_HRB_TYPE_CB_REPLY);
	if (ret)
		kerr(dev->name, "k7_do_dma_ioctl() ret=%d", ret);
	return ret;
}

/*
 * This is called from k7_release() when pedClient closes the device.
 */
int k7_cb_disable (struct k7_dev *dev)
{
	return k7_do_cb_disable(dev);
}

/*************************************** UHD/VKD compatibility *****************************************/

#define OS_LINUX 1
#include "fwcbrc.h"

static int uhd_errno_to_cb_ret (int *err)
{
	int cb_err;

	switch (*err) {
		case 0:			cb_err = CB_RET_OK;			break;
		case -EINVAL:		cb_err = LUNA_RET_CB_PARAM_INVALID;	break;
		case -ENOMEM:		cb_err = CB_RET_NO_MEMORY;		break;
		case -ETIME:		  *err = -ETIMEDOUT; /* fall-thru */
		case -ETIMEDOUT:	cb_err = CB_RET_TIMEOUT;		break;
		case -ENODATA:		cb_err = CB_RET_HIOS_HANDLE_INVALID;	break;
		case -EINTR:		cb_err = CB_RET_SYS_ERROR;		break;
		case -ERESTARTSYS:	cb_err = CB_RET_OK;			break;
		case -EIO:		cb_err = CB_RET_HIOS_IO_ERROR;		break;
		case -EFAULT:		cb_err = CB_RET_SYS_ERROR;		break;
		default:		cb_err = CB_RET_SYS_ERROR;		break;
	}
	/* if not a "system error", then set original errno to 0 and let user access the cb_err instead */
	if (cb_err != CB_RET_SYS_ERROR)
		*err = 0;
	return cb_err;
}

static unsigned int uhd_elapsed_msecs (unsigned long started)
{
	unsigned long now     = jiffies;
	unsigned long elapsed = now - started;

	if (started > now) {
		elapsed += ~0UL;
		elapsed +=  1UL;
	}
	return jiffies_to_msecs(elapsed);
}

static unsigned int uhd_remaining_msecs (unsigned int timeout_msecs, unsigned long started)
{
	unsigned int elapsed = uhd_elapsed_msecs(started);
	return (elapsed >= timeout_msecs) ? 0 : (timeout_msecs - elapsed);
}

static int uhd_cb_rw_exit (struct k7_dev *dev, struct uhd_cb_rw_args *args, unsigned long started, int ret)
{
	args->out.timeout = uhd_remaining_msecs(args->in.timeout, started);
	args->out.cb_ret  = uhd_errno_to_cb_ret(&ret);
	if (copy_to_user((void *)(long)args->param.out, &args->out, sizeof(args->out))) {
		kerr(dev->name, "copy_to_user(param.out=0x%llx) failed", args->param.out);
		ret = -EFAULT;
	}
	return ret;
}

static int uhd_cb_rw_entry (struct k7_dev *dev, struct uhd_cb_rw_args *args, void __user *uargp,
				int compat, unsigned long started)
{
	memset(args, 0, sizeof(*args));
	if (copy_from_user(&args->param, uargp, sizeof(args->param))) {
		kerr(dev->name, "copy_from_user(param=%p) failed", uargp);
		return -EFAULT;
	}
#ifdef CONFIG_COMPAT
	if (compat) {
		args->param.in  = (u64)compat_ptr(args->param.in);
		args->param.out = (u64)compat_ptr(args->param.out);
	}
#endif
	if (!args->in.timeout)
		args->in.timeout = K7_CB_IO_READ_TIMEOUT;
	if (copy_from_user(&args->in, (void *)(long)args->param.in, sizeof(args->in))) {
		kerr(dev->name, "copy_from_user(param.in=0x%llx) failed", args->param.in);
		return -EFAULT;
	}
#ifdef CONFIG_COMPAT
	if (compat)
		args->in.buf = (u64)compat_ptr(args->in.buf);
#endif
	if (!args->in.buf || !args->in.size || args->in.hios_id > 0xff) {
		kerr(dev->name, "buf=0x%llx len=%u hios_id=%u", args->in.buf, args->in.size, args->in.hios_id);
		return uhd_cb_rw_exit(dev, args, started, -EINVAL);
	}
	return 0;
}

static int uhd_cb_io_write (struct k7_dev *dev, void __user *uargp, int compat)
{
	struct k7_dma_ioctl *ioc;
	struct uhd_cb_rw_args args;
	unsigned long started = jiffies;
	int ret;

	ioc = kzalloc(sizeof(*ioc), GFP_KERNEL);
	if (!ioc) {
		cbdebug(dev->name, "ret=-ENOMEM");
		return -ENOMEM;
	}
	ret = uhd_cb_rw_entry(dev, &args, uargp, compat, started);
	if (ret == 0) {
		cbdebug(dev->name, "current_pid=%u cb_pid=%u cb_state=%u cb_id=%u",
			(unsigned int)(current->tgid), (unsigned int)(dev->cb_pid), dev->cb_state, args.in.hios_id);
		ioc->inbuf         = args.in.buf;
		ioc->inbuf_size    = args.in.size;
		ioc->timeout_msecs = (args.in.timeout < K7_CBHRA_MAX_WAIT) ? K7_CBHRA_MAX_WAIT : args.in.timeout;
		ioc->target        = K7_DMA_TARGET_MCPU;
		ioc->flags         = K7_DMA_FLAG_NO_REPLY | K7_DMA_FLAG_MRB1;
		if (dev->cbhra_count < K7_CBHRA_MIN_COUNT) {
			ioc->flags |= K7_DMA_FLAG_CBHRA;
			ioc->outbuf_size = K7_CBHRA_SIZE;
		}
		if (k7_cbdebug)
			k7_dumpmem(NULL, dev->name, NULL, "CB_WRITE", (void *)(long)ioc->inbuf, 0, ioc->inbuf_size);
		ret = k7_cb_io_write_internal(dev, ioc, args.in.hios_id);
		if (ret >= 0) {
			args.out.transmitted = args.in.size;
			ret = 0;
		}
		args.out.hios_id = args.in.hios_id;
		ret = uhd_cb_rw_exit(dev, &args, started, ret);
	}
	kfree(ioc);
	cbdebug(dev->name, "ret=%d", ret);
	return ret;
}

static int k7_cb_io_cancel_cb_id (struct k7_dev *dev, unsigned int cb_id)
{
	int ret = 0;

	cbdebug(dev->name, "cb_id=%u", cb_id);
	if (cb_id > 0xff) {
		kerr(dev->name, "bad hios_id: %u", cb_id);
		return -EINVAL;
	}
	if (cb_id == 0)
		return k7_do_cb_disable(dev);
	SPIN_LOCK(&dev->lock);
	switch (dev->cb_id_state[cb_id]) {
	case K7_CB_ID_STATE_FREE:
		break;
	case K7_CB_ID_STATE_HSM_CANCELLED:
		k7_free_cb_id(dev, cb_id);
		if (dev->mcpu_protocol_level >= 3)
			k7_async_send_cb_cancel(dev, "-CB_CANCEL2", cb_id);
		break;
	case K7_CB_ID_STATE_HOST_CANCELLED:
		kwarn(dev->name, "cb_id=%u was already cancelled", cb_id);
		break;
	case K7_CB_ID_STATE_UNCLAIMED:
	case K7_CB_ID_STATE_CLAIMED:
		if (dev->mcpu_protocol_level < 3) {
			k7_free_cb_id(dev, cb_id);
		} else {
			dev->cb_id_state[cb_id] = K7_CB_ID_STATE_HOST_CANCELLED;
			k7_async_send_cb_cancel(dev, "-CB_CANCEL3", cb_id);
		}
	}
	SPIN_UNLOCK(&dev->lock);
	return ret;
}

static int uhd_cb_io_read (struct k7_dev *dev, void __user *uargp, int compat)
{
	struct uhd_cb_rw_args args;
	unsigned long started = jiffies;
	unsigned int cb_id;
	int ret;

	ret = uhd_cb_rw_entry(dev, &args, uargp, compat, started);
	if (ret == 0) {
		cbdebug(dev->name, "current_pid=%u cb_pid=%u cb_state=%u cb_id=%u",
			(unsigned int)(current->tgid), (unsigned int)(dev->cb_pid), dev->cb_state, args.in.hios_id);
		cb_id = args.in.hios_id;
		if (k7_auto_cancel_callbacks) {
			if (!cb_id && dev->active_cb_id != 0) {
				k7_cb_io_cancel_cb_id(dev, dev->active_cb_id);
				dev->active_cb_id = 0;
			}
		}
		ret = k7_cb_io_read_internal(dev, &args, &cb_id);
		if (ret >= 0) {
			args.out.transmitted = ret;
			args.out.hios_id     = cb_id;
			ret = 0;
			cbdebug(dev->name, "cb_id=%u len=%u", args.out.hios_id, args.out.transmitted);
		}
		if (k7_auto_cancel_callbacks) {
			if (ret >= 0 && cb_id)
				dev->active_cb_id = (u8)cb_id;
		}
		ret = uhd_cb_rw_exit(dev, &args, started, ret);
	}
	cbdebug(dev->name, "ret=%d", ret);
	return ret;
}

static int uhd_cb_io_cancel (struct k7_dev *dev, void __user *uargp, int compat)
{
	struct uhd_ioctl_cb_cancel_in_param_s parms;
	unsigned int cb_id;

	if (copy_from_user(&parms, uargp, sizeof(parms)))
		return -EFAULT;
	cb_id = parms.hios_id;
	if (cb_id && k7_auto_cancel_callbacks) {
		kfinfo(dev->name, "setting k7_auto_cancel_callbacks=0");
		k7_auto_cancel_callbacks = 0;
	}
	return k7_cb_io_cancel_cb_id(dev, cb_id);
}

static int uhd_cb_io_query (struct k7_dev *dev, void __user *uargp, int compat)
{
	struct uhd_ioctl_cb_query_param_s     param;
	struct uhd_ioctl_cb_query_in_param_s  in;
	struct uhd_ioctl_cb_query_out_param_s out;

	cbdebug(dev->name, "current_pid=%u cb_pid=%u cb_state=%u",
		(unsigned int)(current->tgid), (unsigned int)(dev->cb_pid), dev->cb_state);
	if (dev->hsm_state != K7_HSM_STATE_READY) {
		cbdebug(dev->name, "hsm not ready");
		return -ECONNREFUSED;
	}
	if (copy_from_user(&param, uargp, sizeof(param))) {
		kerr(dev->name, "copy_from_user(param=%p) failed", uargp);
		return -EFAULT;
	}
#ifdef CONFIG_COMPAT
	if (compat) {
		param.in  = (u64)compat_ptr(param.in);
		param.out = (u64)compat_ptr(param.out);
	}
#endif
	if (copy_from_user(&in, (void *)(long)param.in, sizeof(in))) {
		kerr(dev->name, "copy_from_user(param.in=0x%llx) failed", param.in);
		return -EFAULT;
	}
	if (in.what != CB_QUERY_INFO) {
		kerr(dev->name, "in.what(%u) != CB_QUERY_INFO(%u)", in.what, CB_QUERY_INFO);
		return -EINVAL;
	}

	memset(&out, 0, sizeof(out));
	out.cb_support_level    = CB_QUERY_CALLBACK_IO_SUPPORTED;
	out.cb_io_version       = dev->callback_io_version;    /* layer 2 (driver)  protocol */
	out.cb_protocol_version = dev->callback_version;
	if (copy_to_user((void *)(long)param.out, &out, sizeof(out))) {
		kerr(dev->name, "copy_to_user(param.out=0x%llx) failed", param.out);
		return -EFAULT;
	}
	cbdebug(dev->name, "ret=0");
	return 0;
}

/* This is called from k7_unlocked_ioctl() in main.c */
int k7_cb_ioctl (struct k7_dev *dev, unsigned int cmd, void __user *uargp, int compat)
{
	switch (cmd) {
	case UHD_IOCTL_CB_IO_READ:
		return uhd_cb_io_read(dev, uargp, compat);
	case UHD_IOCTL_CB_IO_WRITE:
		return uhd_cb_io_write(dev, uargp, compat);
	case UHD_IOCTL_CB_IO_CANCEL:
		return uhd_cb_io_cancel(dev, uargp, compat);
	case UHD_IOCTL_CB_IO_QUERY:
		return uhd_cb_io_query(dev, uargp, compat);
	default:
		return -ENOTTY;
	}
}

static void k7_cbhra_worker (struct work_struct *work)
{
	struct k7_dev *dev = container_of(work, struct k7_dev, cbhra_work);
	k7_cb_enqueue_hras(dev);
}

void k7_trigger_send_cbhras_to_mcpu (struct k7_dev *dev)
{
	schedule_work(&dev->cbhra_work);
}

void k7_cb_reinit_for_reset (struct k7_dev *dev, int force_free_busylist)
{
	SPIN_LOCK_REQUIRED(&dev->lock);
	dev->active_cb_id = 0;
	k7_free_all_cb_ids(dev);
	k7_cb_free_cbhra_donelist(dev);
	if (force_free_busylist)
		k7_cb_force_free_cbhra_busylist(dev);
	wake_up(&dev->cbhra_wq);
}

void k7_cb_init (struct k7_dev *dev)
{
	INIT_WORK(&dev->cbhra_work, k7_cbhra_worker);
	INIT_LIST_HEAD(&dev->cbhra_busylist);
	INIT_LIST_HEAD(&dev->cbhra_donelist);
	init_waitqueue_head(&dev->cbhra_wq);
}
