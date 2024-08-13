/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * req.c
 */
#include "headers.h"

#define OS_LINUX 1
#include "fwrc.h"

static int k7_dma_map (struct k7_dev *dev, struct k7_mem *data, enum dma_data_direction direction)
{
	int err;
	if (data->type != K7_MEM_PG_NONCACHED) {
		data->daddr = pci_map_single(dev->pdev, data->vaddr, data->len, direction);
		err = pci_dma_mapping_error(dev->pdev, data->daddr);
		if (err) {
			data->daddr = 0;
			kerr(dev->name, "pci_map_single() failed, err=%d", err);
			return -EIO;
		}
		kdebug2(dev->name, "vaddr=%p daddr=%016llx len=%u dir=%u",
			data->vaddr, (u64)data->daddr, data->len, direction);
	}
	return 0;
}

static void k7_dma_unmap (struct k7_dev *dev, struct k7_mem *data, enum dma_data_direction direction)
{
	if (data->type != K7_MEM_PG_NONCACHED) {
		u64 daddr = data->daddr;
		data->daddr = 0;
		pci_unmap_single(dev->pdev, daddr, data->len, direction);
		kdebug2(dev->name, "daddr=%016llx len=%u dir=%u", daddr, data->len, direction);
	}
}

static void k7_reinit_dt (struct k7_dt *dt)
{
	struct k7_hwdt *hwdt;

	INIT_LIST_HEAD(&dt->list);
	dt->dma_mapped = 0;
	dt->req_done   = 0;
	dt->next_done  = 0;
	hwdt = dt->hwdt;
	if (hwdt) {
		if (hwdt->pad64 != 0) {  //FIXME testing
			kwarn(DRV_NAME, "hwdt->pad64=0x%llx", hwdt->pad64);
			hwdt->pad64 = 0ull;
		}
		memset(hwdt, 0, 24 /*sizeof(struct k7_hwdt)*/);
	}
}

int k7_alloc_special_dt (struct k7_dev *dev)
{
	struct k7_mem special_dt;
	int err = 0;

	memset(&special_dt, 0, sizeof(special_dt));
	k7_mem_zalloc(dev, &special_dt, PAGE_SIZE, K7_MEM_PG_NONCACHED);  /* s/w + h/w: non-cacheable */
	SPIN_LOCK(&dev->dt_freelist_lock);
	if (dev->special_dt.vaddr)
		err = -EBUSY;
	else if (!special_dt.vaddr)
		err = -ENOMEM;
	else
		memcpy(&dev->special_dt, &special_dt, sizeof(special_dt));
	SPIN_UNLOCK(&dev->dt_freelist_lock);
	if (err)
		k7_mem_free(dev, &special_dt);
	return err;
}

void k7_put_dt (struct k7_dev *dev, struct k7_dt *dt)
{
	if (dt) {
		k7_reinit_dt(dt);
		SPIN_LOCK(&dev->dt_freelist_lock);
		if (dt == dev->special_dt.vaddr) {  /* special dt used for error-injection */
			k7_mem_free(dev, &dev->special_dt);
		} else {
			if (K7_FREE_TO_LIST_HEAD)
				list_add(&dt->list, &dev->dt_freelist);
			else
				list_add_tail(&dt->list, &dev->dt_freelist);
			dev->dt_freelist_count++;
		}
		SPIN_UNLOCK(&dev->dt_freelist_lock);
	}
}

static int k7_get_dt (struct k7_dev *dev, struct k7_dt **dt_p)
{
	struct k7_dt *dt = NULL;

	SPIN_LOCK(&dev->dt_freelist_lock);
	if (!list_empty(&dev->dt_freelist)) {
		dev->dt_freelist_count--;
		dt = list_first_entry(&dev->dt_freelist, struct k7_dt, list);
		list_del_init(&dt->list);  /* unlink from dt_freelist */
	} else if (!dev->dt_freelist_complained) {
		dev->dt_freelist_complained = 1;
		kwarn(dev->name, "dt_freelist was empty");
	}
	SPIN_UNLOCK(&dev->dt_freelist_lock);
	if (dt) {
		*dt_p = dt;
		return 0;
	}
	return -ENOMEM;
}

void k7_free_all_dt_databufs (struct k7_dev *dev)
{
	if (K7_PERMANENT_DATABUFS) {
		struct k7_dt *dt;
		dev->dt_freelist_complained = 1;
		while (0 == k7_get_dt(dev, &dt)) {
			k7_mem_free(dev, &dt->data);
		}
	}
}

static void k7_free_dt_data (struct k7_dev *dev, struct k7_dt *dt)
{
	if (!K7_PERMANENT_DATABUFS && dt->data.vaddr) {
		k7_mem_free(dev, &dt->data);
		dt->data.vaddr = NULL;
	}
}

void k7_free_dt (struct k7_channel *channel, struct k7_dt *dt)
{
	struct k7_dev *dev = channel->dev;

	if (dt == channel->eoc) {
		channel->eoc = NULL;
		kderr(dev->name, "BUG: freeing EOC dt");
	}
	k7_free_dt_data(dev, dt);
	k7_put_dt(dev, dt);
}

static void k7_dma_unmap_dt (struct k7_dev *dev, struct k7_dt *dt, enum dma_data_direction direction)
{
	struct k7_mem *data = &dt->data;
	if (data && data->vaddr)
		k7_dma_unmap(dev, data, direction);
	else if (!data)
		kderr(dev->name, "dt=%p, dt->data is NULL??", dt);
}

void k7_dma_unmap_dtc (struct k7_dev *dev, struct list_head *dtc, enum dma_data_direction direction)
{
	struct k7_dt *dt;

	rmb();
	if (!list_empty(dtc)) {
		list_for_each_entry(dt, dtc, list) {
			if (dt->dma_mapped) {
				dt->dma_mapped = 0;
				k7_dma_unmap_dt(dev, dt, direction);
			}
		}
	}
}

int k7_dma_map_dtc (struct k7_dev *dev, struct list_head *dtc, enum dma_data_direction direction)
{
	struct k7_dt *dt;

	if (!list_empty(dtc)) {
		list_for_each_entry(dt, dtc, list) {
			struct k7_mem *data = &dt->data;
			if (!dt->dma_mapped) {
				int err = k7_dma_map(dev, data, direction);
				if (err) {
					k7_dma_unmap_dtc(dev, dtc, direction);
					return err;
				}
				dt->dma_mapped = 1;
				dt->hwdt->data_daddr = cpu_to_be64(data->daddr);
			}
		}
	}
	if (!K7_USE_CACHEABLE_RAM)
		wmb();  /* needed for NONCACHED memory */
	return 0;
}

static void k7_prep_dt (struct k7_dt *dt)
{
	u64 control = K7_DT_SIGNATURE_VAL | BE64VAL(4,23,dt->data.len);

	dt->hwdt->control    = cpu_to_be64(control);
	dt->hwdt->data_daddr = cpu_to_be64(dt->data.daddr);
	dt->hwdt->next_daddr = 0ull;
}

static void k7_free_final_dt (struct k7_channel *channel, struct k7_dt *dt)
{
	SPIN_LOCK(&channel->dt_done_lock);
	if (dt->req_done)
		k7_free_dt(channel, dt);
	else
		dt->next_done = 1;
	SPIN_UNLOCK(&channel->dt_done_lock);
}

void k7_free_channel_eoc (struct k7_channel *channel)
{
	struct k7_dt *dt = channel->eoc;

	SPIN_LOCK_REQUIRED(&channel->dev->lock);
	if (dt) {
		channel->eoc = NULL;
		k7_free_final_dt(channel, dt);
	}
}

void k7_free_dtc (struct k7_channel *channel, struct list_head *dtc, int was_submitted)
{
	if (dtc && !list_empty(dtc)) {
		struct k7_dev *dev = channel->dev;
		struct k7_dt  *dt  = NULL;
		int            final_dt;
		do {
			dt = list_first_entry(dtc, struct k7_dt, list);
			list_del_init(&dt->list);  /* unlink from dtc */
			final_dt = list_empty(dtc);
			if (!final_dt || !was_submitted) {
				k7_free_dt(channel, dt);
			} else {
				SPIN_LOCK(&channel->dt_done_lock);
				if (dt->next_done) {
					k7_free_dt(channel, dt);
				} else {
					k7_free_dt_data(dev, dt);
					dt->req_done = 1;
				}
				SPIN_UNLOCK(&channel->dt_done_lock);
				break;
			}
		} while (!final_dt);
	}
}

/*
 * Allocate a DT chain with associated data buffers, totalling "size" bytes.
 */
int k7_alloc_dtc (struct k7_channel *channel, struct list_head *dtc,
			unsigned int size, enum dma_data_direction direction)
{
	struct k7_dev *dev = channel->dev;
	struct k7_dt  *prev = NULL, *dt = NULL;
	unsigned int offset;
	int err = 0;

	for (offset = 0; offset < size;) {
		unsigned int len = size - offset;
		prev = dt;
		err = k7_get_dt(dev, &dt);
		if (err)
			break;
		if (prev)
			prev->hwdt->next_daddr = cpu_to_be64(dt->daddr);
		list_add_tail(&dt->list, dtc);
		if (len > K7_MAX_BYTES_PER_DT)
			len = K7_MAX_BYTES_PER_DT;
		offset += len;
		if (K7_PERMANENT_DATABUFS) {
			dt->data.len = len;
			if (k7_zeromem)
				memset(dt->data.vaddr, 0, len);
		} else {
			k7_mem_zalloc(dev, &dt->data, len, K7_MEM_DATABUF);
			if (!dt->data.vaddr) {
				err = -ENOMEM;
				break;
			}
		}
		k7_prep_dt(dt);
	}
	if (err) {
		if (k7_debug || err != -ENOMEM)
			kderr(channel->name, "failed, err=%d", err);
		k7_free_dtc(channel, dtc, 0);
	} else if (dt) {
		dt->hwdt->control |= cpu_to_be64(K7_DT_EOC);  // set EOC bit
		/*
		 * HW288860:
		 * Chip has a bug where bytecount < 8 in final DT of HRB chain will
		 * trigger a DMA error.  The workaround is to fill in the supposedly
		 * ignored HRB_LENGTH field in the final DT with 0xffff8 (-1).
		 * But only if there's more than one DT (first DT gets real hrb_len).
		 * First dt always has (len > 8) so no need to test that explicitly here.
		 */
		if (dt->data.len < 8 && direction == DMA_TO_DEVICE)
			dt->hwdt->control |= cpu_to_be64(BE64VAL(28,47,0xffff8));
	}
	return err;
}

void k7_free_req (struct k7_channel *channel, struct k7_req *req, int was_submitted)
{
	struct k7_dt *dt;

	k7_free_dtc(channel, &req->hrb_dtc, was_submitted);
	k7_free_dtc(channel, &req->hra_dtc, 0);

	if (was_submitted) {
		dt = req->prev_eoc;
		if (dt)
			k7_free_final_dt(channel, dt);
	}
	k7_fp_put_req_keys(channel->dev, req);
	if (k7_zeromem)
		memset(req, 0, sizeof(*req));
	kfree(req);
}

u32 k7_dma_hra_hdr_len (unsigned int target)
{
	switch (target) {
		case K7_DMA_TARGET_MCPU: return K7_HRA_HDR_LEN_MCPU;
		case K7_DMA_TARGET_PKU:
		case K7_DMA_TARGET_SKU:  return K7_HRA_HDR_LEN_FASTPATH;
		default:                 return 0;  /* BUG */
	}
}

static void k7_assemble_hrb_hdr_fastpath (struct k7_dev *dev, u64 *hdr,
					struct k7_req *req, u64 htype, u64 hrb_sig)
{
	u64 control, hra_daddr = req->hra_daddr;

	control = htype | K7_DMAHDR_ACTION_IV_IRQ;  /* Send IV+IRQ to target after DMA */
	hdr[0]  = cpu_to_be64(control);    /* DMA header */
	control = hrb_sig;                 /* Signature */
	hdr[1]  = cpu_to_be64(control);    /* Signature / HDF */
	hdr[2]  = cpu_to_be64(hra_daddr);  /* Request ID / user field */
	hdr[3]  = cpu_to_be64(hra_daddr);  /* HRA: Host Return Address */
}

static void k7_assemble_hrb_hdr_mcpu (struct k7_dev *dev, u64 *hdr, struct k7_req *req)
{
	u64 flags_size, control, hra_daddr = req->hra_daddr;
	u32 hrb_flags;
	unsigned short ioc_flags = req->ioc->flags;

	control = BE64VAL(0,7,K7_HTYPE_H2M);
	if (ioc_flags & K7_DMA_FLAG_MRB1)
		control |= K7_DMAHDR_MRB1;  /* select MRB1 instead of MRB0 */
	if (ioc_flags & K7_DMA_FLAG_NOTX)
		control |= K7_DMAHDR_NOTX;  /* Interrupt MCPU instead of auto-DMAing */
	else
		control |= K7_DMAHDR_ACTION_IRQ;  /* Send IRQ to MCPU after DMA */
	hdr[0]      = cpu_to_be64(control);  /* DMA header */
	control     = BE64VAL(0,15,K7_HRB_SIGNATURE_1234);
	hdr[1]      = cpu_to_be64(control);     /* Signature / HDF */
	hrb_flags   = req->post_padding << 24;  /* 8-bits for post-padding, 24-bits for hrb_flags */
	hrb_flags  |= req->hrb_type;            /* Note: this value is ((parameters << 8) | hrb_type) */
	if (dev->mcpu_protocol_level == 0) {
		switch (K7_REQ_HRB_TYPE(req)) {
			case K7_HRB_TYPE_DEFAULT:
			case K7_HRB_TYPE_ICD_CMD:
			case K7_HRB_TYPE_CB_DISABLE:
			case K7_HRB_TYPE_ABORT_HRA:
				break;  /* These correspond to the old HRB_FLAG values */
			case K7_HRB_TYPE_CB_REPLY:
				break;  /* This has no bits in common with the old HRB_FLAG values */
			default:
				/* Anything else should not be used when dev->mcpu_protocol_level==0 */
				kerr(dev->name, "hrb_type=%u not supported by MCPU", K7_REQ_HRB_TYPE(req));
		}
	}
	flags_size  = ((u64)hrb_flags) << 32;  /* software-defined HRB "flags" */
	flags_size |= req->hra_size;           /* max size of HRA data area for the reply */
	hdr[2]      = cpu_to_be64(flags_size);
	hdr[3]      = cpu_to_be64(hra_daddr);  /* HRA: Host Return Address */
}

static void k7_assemble_hrb_hdr (struct k7_dev *dev, int target, void *hdr, struct k7_req *req)
{
	switch (target) {
	case K7_DMA_TARGET_MCPU:
		k7_assemble_hrb_hdr_mcpu(dev, hdr, req);
		break;
	case K7_DMA_TARGET_PKU:
		k7_assemble_hrb_hdr_fastpath (dev, hdr, req,
			BE64VAL(0,7,K7_HTYPE_H2PK), BE64VAL(0,15,K7_HRB_SIGNATURE_1234));
		break;
	case K7_DMA_TARGET_SKU:
		k7_assemble_hrb_hdr_fastpath (dev, hdr, req,
			BE64VAL(0,7,K7_HTYPE_H2SK), BE64VAL(0,15,K7_HRB_SIGNATURE_A5A5));
		break;
	default:  /* not possible here */
		kerr(dev->name, "bad dma target (%u)", target);
	}
}

static void k7_dump_inbuf (struct k7_dev *dev, struct k7_dma_ioctl *ioc)
{
	static u8 *buf;

	buf = kmalloc(ioc->inbuf_size, GFP_KERNEL);
	if (!buf) {
		kerr(dev->name, "kmalloc(%u) failed", ioc->inbuf_size);
	} else {
		if (copy_from_user(buf, (void __user *)(unsigned long)ioc->inbuf, ioc->inbuf_size))
			kerr(dev->name, "copy_from_user() failed");
		else
			k7_dumpmem(NULL, dev->name, NULL, "inbuf", buf, 0, ioc->inbuf_size);  /* FIXME: CLOG ? */
		kfree(buf);
	}
}

/*
 * ICD command from the library is not in the exact format wanted by MCPU.
 * So parse the header info, and strip away what we don't need.
 * The incoming command header (hdr) is always in little-endian.
 *
 * All ICD commands begin with a header, which is a sequence of (u32) words:
 *
 *
 *     Word   0     Return size.
 *     Word   1     Timeout.
 *     Word   2     flags.
 *     Word   3     unused for padding (value 0xC0CAC01A).
 *     Word   4     cmdCode.
 *     Words  5-11  (8-words) STC Info (K7_STC_INFO_WORDS).
 *     Word  12     Cmd code (potentially different from Word 4 IF STC is enabled).
 *     Words 13-20  (8-words) protocol/futureproofing header (K7_ICD_PROTO_FUTURE_WORDS).
 *     Word  21     Command parameters/data start here.  Session ID is first, if present (flags & 0x02).
 *
 * We have to strip out the first four words, and pass the rest through to the MCPU.
 */
static int k7_reformat_icd_cmd (struct k7_channel *channel, struct k7_req *req)
{
	struct k7_dev       *dev = channel->dev;  /* needed by expansion of K7_ICD_PARAMS_OFFSET_WORDS */
	struct k7_dma_ioctl *ioc = req->ioc;
	u32 return_size, timeout_msecs, hdr[5], cmd_id;
	const int params_offset = (K7_ICD_LIBRARY_PREFIX_WORDS + K7_ICD_PARAMS_OFFSET_WORDS) * sizeof(u32);

	if (k7_dump_icd_inbuf)
		k7_dump_inbuf(dev, ioc);

	/* Ensure there is room for at least a response_hdr */
	if (!ioc->outbuf || ioc->outbuf_size < sizeof(struct k7_icd_response_hdr)) {
		kerr(channel->name, "No room for response header %p %u", ioc->outbuf, ioc->outbuf_size);
		return -EINVAL;
	}

	/* Enforce minimum command size (full header) */
	if (ioc->inbuf_size < params_offset) {
		kwarn(channel->name, "inbuf_size(%u) too small for ICD header", ioc->inbuf_size);
		return -EINVAL;
	}
	if (copy_from_user(hdr, (void __user *)(unsigned long)(ioc->inbuf), sizeof(hdr))) {
		kerr(channel->name, "copy_from_user(%u) failed", sizeof(hdr));
		return -EFAULT;
	}

	return_size = le32_to_cpu(hdr[0]);
	if (return_size > ioc->outbuf_size) {
		kwarn(channel->name, "return_size(%u) larger than outbuf_size(%u)",
				return_size, ioc->outbuf_size);
		return -EINVAL;
	}

	timeout_msecs = le32_to_cpu(hdr[1]);
	if (timeout_msecs && timeout_msecs != ~0u)
		ioc->timeout_msecs = timeout_msecs;

	cmd_id = le32_to_cpu(hdr[4]);
	if (cmd_id == LUNA_KEK_KEY_ICD)
		return k7_intercept_kek_key_cmd(dev, req);
	return 0;
}

int k7_copy_udata (struct k7_dev *dev, unsigned int ioc_flags, struct list_head *dtc,
			k7_copy_inout inout, void *uaddr,
			unsigned int udata_len, unsigned int data_offset)
{
	struct k7_dt *dt;
	unsigned int dtc_offset = 0, dt_offset = 0;
	int err = 0;

	kdebug2(dev->name, "(%s): uaddr=%p udata_len=%u data_offset=%u",
			inout ? "out" : "in", uaddr, udata_len, data_offset);
	if (!udata_len)
		return 0;
	if (list_empty(dtc)) {
		kerr(dev->name, "empty dtc");
		return -EINVAL;
	}
	/* Handle data_offset, if any */
	list_for_each_entry(dt, dtc, list) {
		unsigned int dt_len;
		if (dtc_offset >= data_offset)
			break;
		dt_len = dt->data.len;
		if ((dtc_offset + dt_len) > data_offset) {
			dt_offset = data_offset - dtc_offset;
			break;
		}
		dtc_offset += dt_len;
		kdebug2(dev->name, "(%s): skipped dt: dt_len=%u dtc_offset=%u data_offset=%u",
			inout ? "out" : "in", dt_len, dtc_offset, data_offset);
	}
	/* Now copy udata_len bytes in/out as requested */
	list_for_each_entry_from(dt, dtc, list) {
		u8          *kaddr = dt->data.vaddr + dt_offset;
		unsigned int len   = dt->data.len   - dt_offset;
		if (len > udata_len) {
			/* Zero-pad tail of HRB buffers: MCPU needs this, possibly crypto units too */
			if (inout == K7_COPYIN) {
				kdebug(dev->name, "zero-pad %u bytes", len - udata_len);
				memset(kaddr + udata_len, 0, len - udata_len);
			}
			len = udata_len;
		}
		if (len) {
			kdebug2(dev->name, "(%s): copying: uaddr=%p kaddr=%p len=%u dt_offset=%u",
				inout ? "out" : "in", uaddr, kaddr, len, dt_offset);
			if (ioc_flags & K7_DMA_FLAG_KBUF) {
				if (inout == K7_COPYIN)
					memcpy(kaddr, uaddr, len);
				else
					memcpy(uaddr, kaddr, len);
				err = 0;
			} else {
				if (inout == K7_COPYIN)
					err = copy_from_user(kaddr, uaddr, len);
				else
					err = copy_to_user(uaddr, kaddr, len);
			}
			if (err) {
				kerr(dev->name, "(%s): failed err=%d (bad uaddr?: %p:%u)", inout ? "out" : "in", err, uaddr, len);
				return err;
			}
			uaddr     += len;
			udata_len -= len;
		}
		dt_offset = 0;
		if (inout != K7_COPYIN && !udata_len)
			break;
	}
	if (udata_len) {
		kerr(dev->name, "(%s): udata_len exceeded dtc len, %u bytes not copied",
						inout ? "out" : "in", udata_len);
		return -ENOSPC;
	}
	kdebug2(dev->name, "done");
	return 0;
}

static int k7_build_hrb (struct k7_channel *channel, unsigned int hrb_len, struct k7_req *req, unsigned int icd_adjust)
{
	struct k7_dev *dev = channel->dev;
	int err;

	if (hrb_len > dev->max_hrb_len && !K7_ERR_TYPE_EQ(K7_DEV_ERR_TYPE(dev), K7EI_EXCEED_MAX_HRB)) {
		kerr(channel->name, "hrb_len (%d) exceeds device limit (%d)", hrb_len, dev->max_hrb_len);
		err = -EINVAL;
	} else {
		struct k7_dma_ioctl *ioc = req->ioc;
		err = k7_alloc_dtc(channel, &req->hrb_dtc, hrb_len, DMA_TO_DEVICE);
		if (!err) {
			struct k7_dt *dt;
			unsigned int data_offset = K7_HRB_HDR_LEN;
			if (ioc->flags & K7_DMA_FLAG_NO_REPLY) {
				dt = list_tail_entry(&req->hrb_dtc, struct k7_dt, list);
				dt->hwdt->control |= cpu_to_be64(K7_DT_NOTIFY_RX | K7_DT_RMRI);
			}
			dt = list_first_entry(&req->hrb_dtc, struct k7_dt, list);
			k7_assemble_hrb_hdr(dev, ioc->target, dt->data.vaddr, req);
			req->hrb_len = hrb_len;  /* used only for mrb/rxbuf alignment tracking */
			k7_set_hrb_len(dt, hrb_len);
			if (ioc->flags & K7_DMA_FLAG_KEK_FASTPATH)
				return data_offset;
			err = k7_copy_udata(dev, ioc->flags, &req->hrb_dtc, K7_COPYIN,
				(void __user *)(unsigned long)(ioc->inbuf + icd_adjust),
				ioc->inbuf_size - icd_adjust, data_offset);
			if (err)
				kerr(channel->name, "k7_copy_udata() failed");
			else if (dev->clog.enabled)
				k7_clog_dump_dtc(channel, "HRB", &req->hrb_dtc, -1);
		}
	}
	return err;
}

static int k7_build_req (struct k7_channel *channel, unsigned int hrb_len, struct k7_req *req)
{
	struct k7_dma_ioctl *ioc = req->ioc;
	int icd_adjust = 0;

	hrb_len += K7_HRB_HDR_LEN;
	if (ioc->target == K7_DMA_TARGET_MCPU) {
		unsigned int residual;
		if (K7_REQ_HRB_TYPE(req) == K7_HRB_TYPE_ICD_CMD && !(ioc->flags & K7_DMA_FLAG_KBUF)) {
			int err;
			err = k7_reformat_icd_cmd(channel, req);
			if (err)  /* Check for non-zero, not just negative; it could be a KEK_KEY bytecount */
				return err;
			icd_adjust = sizeof(u32) * K7_ICD_LIBRARY_PREFIX_WORDS;
			hrb_len -= icd_adjust;
		}
		/* MCPU requests are required to be built/sent as multiples of K7_HRB_MCPU_ALIGNMENT */
		residual = (hrb_len + K7_HRB_FOOTER_BYTES) % K7_HRB_MCPU_ALIGNMENT;
		if (residual) {
			unsigned int padding = K7_HRB_MCPU_ALIGNMENT - residual;
			req->post_padding = padding;
			hrb_len += padding;
		}
	}
	if (ioc->outbuf_size) {
		int err;
		/*
		 * The HRA hdr_len for external completion uses MCPU size,
		 * which is larger than the actual header from SKU/PKU
		 */
		req->hra_size = k7_dma_hra_hdr_len(ioc->target) + ioc->outbuf_size;
		err = k7_alloc_dtc(channel, &req->hra_dtc, req->hra_size, DMA_FROM_DEVICE);
		if (err)
			return err;
		req->hra_daddr = list_first_entry(&req->hra_dtc, struct k7_dt, list)->daddr;
	}
	return k7_build_hrb(channel, hrb_len, req, icd_adjust);
}

int k7_prepare_req (struct k7_channel *channel, unsigned int hrb_len, struct k7_dma_ioctl *ioc,
			unsigned int hrb_type, struct k7_req **req_r)
{
	struct k7_req *req;
	int err = 0;
	unsigned int mrb_id = (ioc->flags & K7_DMA_FLAG_MRB1) ? 1 : 0;

	if (hrb_len > K7_MCPU_MAX_HRB_LEN && channel->mrb_size[mrb_id] && !K7_ERR_TYPE_EQ(K7_DEV_ERR_TYPE(channel->dev), K7EI_EXCEED_MAX_HRB)) {
		kerr(channel->name, "bad hrb_len=%d, limit=%u", hrb_len, K7_MCPU_MAX_HRB_LEN);
		return -EINVAL;
	}
	req = kzalloc(sizeof(struct k7_req), GFP_KERNEL);
	if (!req) {
		kdebug1(channel->name, "kzalloc(req) failed");
		return -ENOMEM;
	}
	init_completion(&req->wait);
	INIT_LIST_HEAD(&req->hrb_dtc);
	INIT_LIST_HEAD(&req->hra_dtc);
	INIT_LIST_HEAD(&req->list);
	req->channel     = channel;
	req->status      = K7_REQ_IDLE;
	req->ioc         = ioc;
	req->hrb_type    = hrb_type;
	err = k7_build_req(channel, hrb_len, req);  /* returns data_offset, or error */
	/*
	 * When a KEK_KEY command is satisfied from the keycache,
	 * it will return a non-zero bytecount along with K7_REQ_COMPLETED.
	 * Our caller (k7_attempt_dma_ioctl) will exit without further action.
	 */
	if (err >= 0 && req->status != K7_REQ_COMPLETED) {
		req->timeout = msecs_to_jiffies(ioc->timeout_msecs);
		*req_r = req;
		return err;
	}
	k7_free_req(channel, req, 0);
	return err;
}

int k7_remove_req_from_busylist (struct k7_channel *channel, struct k7_req *req)
{
	struct k7_dev *dev = channel->dev;
	int was_first;

	SPIN_LOCK_REQUIRED(&dev->lock);
	if (req->status != K7_REQ_SUBMITTED)
		return 0;  /* failed */
	req->status = K7_REQ_COMPLETING;
	was_first = (req == list_first_entry(&channel->busylist, struct k7_req, list));
	list_del_init(&req->list);  /* unlink from busylist */
	if (was_first)
		k7_restart_busylist_timer(channel);
	/*
	 * As much as we'd like to defer DMA unmapping to a non IRQ/spinlock place,
	 * it simply is not possible.  Any time we do a device reset, the kernel just
	 * zeros the DMA mapping tables, and if we have a slow task that eventually
	 * comes in later to do its own unmap, it will Ooops.  So we MUST do it here!
	 */
	k7_dma_unmap_req(dev, req);
	return 1;  /* succeeded */
}

void k7_complete_req (struct k7_channel *channel, struct k7_req *req, int new_status, int do_wakeup)
{
	SPIN_LOCK_REQUIRED(&channel->dev->lock);
	if (req->status == K7_REQ_COMPLETING) {
		req->status = new_status;
		if (do_wakeup)
			complete(&req->wait);
	}
}

static const char * k7_get_sku_error_meaning (struct k7_channel *channel, u16 error_status)
{
	static struct k7_sku_error_s {
		u16 code;
		const char *meaning;
	} k7_sku_errors[] = {
		{0x0000, ""},
		{0x0001, ",Invalid_opcode"},
		{0x0002, ",Invalid_data_length"},
		{0x0003, ",Zero_length_aes_gcm_iv"},
		{0x0004, ",Invalid_chain_operation"},
		{0x0005, ",Invalid_chain_length"},
		{0x0006, ",Invalid_opcode_mode"},
		{0x0007, ",Invalid_key_length"},
		{0x0008, ",Control_bit_mismatch"},
		{0x000d, ",Invalid_aggreate_digest_feedback_value"},
		{0x000e, ",Invalid_hash_length_on_resumed_hash_operation"},
		{0x000f, ",Unexpected_end_of_packet"},
		{0x0010, ",Incorrect_aggregate_op_output_length"},
		{0x0011, ",Invalid_aggregate_op"},
		{0x0012, ",Disabled_aggregate_op"},
		{0x0000, NULL}
	}, *e;

	for (e = k7_sku_errors; (e->meaning != NULL); ++e) {
		if (e->code == error_status)
			return e->meaning;
	}
	return ",Unknown_error";
}

static int k7_check_sku_return_code (struct k7_channel *channel, void *uaddr)
{
	struct k7_dev *dev;
	u8 rc[3];

	/* Read the SKCH return code bytes back from ioc->outbuf */
	if (copy_from_user(rc, uaddr, sizeof(rc)))
		return -EFAULT;
	if ((rc[0] & 0x80) == 0)
		return 0;  /* no errors */
	dev = channel->dev;  /* needed for kdwarn() */
	kdwarn(channel->name, "Error: Return_Code=0x%02x%02x%02x%s%s%s%s%s",
		rc[0], rc[1], rc[2],
		(rc[0] & 0x40) ? ",Invalid_Header_Type"    : "",
		(rc[0] & 0x20) ? ",Invalid_Footer"         : "",
		(rc[0] & 0x10) ? ",Invalid_Minimum_Length" : "",
		(rc[0] & 0x08) ? ",Early_Return_Code"      : "",
		k7_get_sku_error_meaning(channel, ((u16)(rc[1]) << 8) | rc[2]));
	return -EIO;
}

static int k7_copy_hra_to_user (struct k7_dev *dev, struct k7_req *req, int data_len,
						int hdr_len, unsigned int truncated)
{
	int err;
	struct k7_dma_ioctl *ioc = req->ioc;

	if (data_len > ioc->outbuf_size) {
		kwarn(dev->name, "data_len(%u) larger than outbuf_size(%u)", data_len, ioc->outbuf_size);
		data_len  = ioc->outbuf_size;
		truncated = 1;
	}
	if (data_len == 0)
		return 0;
	err = 0;
	if (!(ioc->flags & K7_DMA_FLAG_NO_RESULT_DATA)) {
		void __user *uaddr = (void __user *)(unsigned long)(ioc->outbuf);
		/* Copy results back to userspace */
		err = k7_copy_udata(dev, ioc->flags, &req->hra_dtc, K7_COPYOUT, uaddr, data_len, hdr_len);
		if (!err) {
			err = data_len;
			if (truncated) {
				err |= K7_DMA_OUTPUT_TRUNCATED;
			} else if (data_len >= 8 && ioc->target == K7_DMA_TARGET_SKU) {
				struct k7_channel *channel = req->channel;
				int err2 = k7_check_sku_return_code(channel, uaddr + data_len - 8);
				if (err2) {
					err = err2;
					if (err == -EIO) {
						struct k7_dma_fastpath *ioc = (void *)req->ioc;
						if (req->kk)
							k7_keycache_delete_key(dev, ioc->key_handle, req->kk);
						if (req->xk)
							k7_keycache_delete_key(dev, ioc->xts_tweak_handle, req->xk);
					}
					if (k7_debug)
						k7_dump_dtc(NULL, channel->name, "err-HRB", &req->hrb_dtc, 48);
				}
			}
		}
	}
	return err;
}

static int k7_handle_hra_fastpath (struct k7_dev *dev, struct k7_req *req, struct k7_dt *first_dt)
{
	u64 dra, rqid, *hdr = first_dt->data.vaddr, hdr0 = be64_to_cpu(hdr[0]);
	unsigned int hdr_len = K7_HRA_HDR_LEN_FASTPATH;
	unsigned int rlen, min_len = hdr_len - sizeof(u64);
	unsigned int htype = extract64(hdr0, K7_DMAHDR_HTYPE);

	if (htype & 0x02) {
		kderr(dev->name, "unexpected IV, hdr0=0x%016x", hdr0);
		return -EIO;
	}

	/* Ensure we have at least enough response data to include the entire header */
	rlen = extract64(hdr0, K7_DMAHDR_RLEN);
	if (rlen < min_len) {
		kderr(dev->name, "rlen(%u) too small (min %u)", rlen, min_len);
		return -EIO;
	}
	/* Response hdr includes DRA/DDRA and "Request ID", both of which should match HRA address */
	dra = be64_to_cpu(hdr[1]);  /* should match the bus addr of the HRA */
	if (dra != first_dt->daddr) {
		kderr(dev->name, "dra(0x%llx) != daddr(0x%llx)", dra, first_dt->daddr);
		return -EIO;
	}
	rqid = be64_to_cpu(hdr[2]);  /* should match the bus addr of the HRA (same as "dra") */
	if (rqid != dra) {
		kderr(dev->name, "rqid(0x%llx) != daddr(0x%llx)", rqid, dra);
		return -EIO;
	}
	return k7_copy_hra_to_user(dev, req, rlen - min_len, hdr_len, 0);
}

static int k7_handle_hra_mcpu (struct k7_dev *dev, struct k7_req *req, struct k7_dt *first_dt)
{
	u64  tmp, *hdr = first_dt->data.vaddr;
	unsigned int rqtype, rqstr, signature, truncated, aborted, hra_type, hrb_type, data_len;
	unsigned int hdr_len = K7_HRA_HDR_LEN_MCPU;
	unsigned int rlen, min_len = hdr_len - sizeof(u64);

	/* hdr[0]: 64-bit word: DMA header with rlen */
	tmp = be64_to_cpu(hdr[0]);

	/* Check for external completion: sent to MCPU, but response is from PKU/SKU */
	rqtype = extract64(tmp, K7_DMAHDR_RQACTION);
	if (rqtype == 1)
		return -EAGAIN; /* external completion from PKA */
	rqstr = extract64(tmp, K7_DMAHDR_RQSTR);
	if (rqstr  == 3)
		return -EAGAIN; /* external completion from SKU */

	/* Now that we know it's really from MCPU, we can check for minimum rlen */
	rlen = extract64(tmp, K7_DMAHDR_RLEN);
	if (rlen < min_len) {
		kderr(dev->name, "rlen(%u) too small (min %u)", rlen, min_len);
		return -EIO;
	}

	/* hdr[1]: first dt_addr of HRA; should match the bus addr of the HRA */
	tmp = be64_to_cpu(hdr[1]);
	if (tmp != first_dt->daddr) {
		kderr(dev->name, "hra_p(0x%llx) != daddr(0x%llx)", tmp, (u64)first_dt->daddr);
		return -EIO;
	}

	/* hdr[2]: signature and hardware dependent field (HDF) */
	tmp = be64_to_cpu(hdr[2]);
	signature = extract64(tmp, K7_HRA_SIGNATURE_MASK);
	if (signature != 0x524d) {
		kderr(dev->name, "bad signature 0x%04x", signature);
		return -EIO;
	}

	/* hdr[3]: software defined: hra_type, parameters, data_len, various flags */
	tmp       = be64_to_cpu(hdr[3]);
	truncated = extract64(tmp, BE64MSK(32,32));
	aborted   = extract64(tmp, BE64MSK(33,33));
	data_len  = extract64(tmp, BE64MSK(40,63));  /* reply data length */
	hrb_type  = K7_REQ_HRB_TYPE(req);
	if (dev->mcpu_protocol_level != 0) {
		hra_type = extract64(tmp, K7_HRx_TYPE_BITMSK);

		/* CB_CMD and ETHERNET don't come through this path */
		switch (hra_type) {
			case K7_HRA_TYPE_DEFAULT:
				if (hrb_type != K7_HRB_TYPE_DEFAULT)
					goto bad_hra_type;
				break;
			case K7_HRA_TYPE_ICD_REPLY:
				if (hrb_type != K7_HRB_TYPE_ICD_CMD)
					goto bad_hra_type;
				break;
			default:
				goto bad_hra_type;
		}
	}
	if (aborted) {
		kdebug(dev->name, "transaction aborted at MCPU");
		return -ECANCELED;
	}
	if (rlen != (ROUND8(data_len) + min_len)) {
		kderr(dev->name, "rlen(%u) != (ROUND8(data_len)(%u,%u) + min_len(%u))",
				rlen, data_len, ROUND8(data_len), min_len);
		return -EIO;
	}

	if (req->ioc->flags & K7_DMA_FLAG_KEK_KEY) {
		k7_handle_kek_key_reply(dev, req, &hdr[4], rlen - min_len, truncated);
		return 0;
	}
	return k7_copy_hra_to_user(dev, req, rlen - min_len, hdr_len, truncated);
bad_hra_type:
	kderr(dev->name, "Unexpected hra_type=%u (hrb_type=%u)", hra_type, hrb_type);
	return -EIO;
}

int k7_handle_hra (struct k7_dev *dev, struct k7_req *req)
{
	struct k7_dt *first_dt;
	int err;

	/* The first_dt must be large enough to hold the entire header: */
	first_dt = list_first_entry(&req->hra_dtc, struct k7_dt, list);
	if (k7_debug > 2) {
		unsigned int hdr_len = k7_dma_hra_hdr_len(req->ioc->target);
		k7_dumpmem(NULL, dev->name, NULL, "HRA-header", first_dt->data.vaddr, first_dt->data.daddr, hdr_len);
	}
	if (first_dt->data.len < sizeof(u64)) {
		kderr(dev->name, "BUG: initial HRA:dt too small(%u) for DMA header(%u)", first_dt->data.len, sizeof(u64));
		return -EIO;
	}
	switch (req->ioc->target) {
	case K7_DMA_TARGET_MCPU:
		err = k7_handle_hra_mcpu(dev, req, first_dt);
		if (err != -EAGAIN) /* not an external completion response? */
			return err;
		return k7_handle_hra_fastpath(dev, req, first_dt);
	case K7_DMA_TARGET_PKU:
	case K7_DMA_TARGET_SKU:
		return k7_handle_hra_fastpath(dev, req, first_dt);
	default:  /* not possible here */
		kderr(dev->name, "bad dma target (%u)", req->ioc->target);
		return -EINVAL;
	}
}

static void k7_dump_failed_req (struct k7_channel *channel, struct k7_req *req)
{
	struct k7_dev *dev = channel->dev;

	/* Don't dump more than a few failed HRB/HRAs, to avoid overflowing the logs */
	if (req->busylist_index > 2)  { /* first index is 0 */
		kdebug(channel->name, "busylist_index=%u not dumped", req->busylist_index);
		return;
	}
	kinfo(channel->name, "failed busylist_index=%u HRB=%p HRA=%p", req->busylist_index, &req->hrb_dtc, &req->hra_dtc);

	/* Guarantee that we dump at least minimally useful information for the likely culprit */
	if (req->busylist_index == 0) {
		if (K7_REQ_HRB_TYPE(req) == K7_HRB_TYPE_ICD_CMD) {
			struct k7_dt *dt  = list_first_entry(&req->hrb_dtc, struct k7_dt, list);
			u32          *hdr = dt->data.vaddr + K7_HRB_HDR_LEN;
			kinfo(channel->name, "busy_list_index=%u ICD timed-out cmd_id=0x%x timeout_msecs=%u",
				req->busylist_index, le32_to_cpu(hdr[0]), req->ioc->timeout_msecs);
		} else {
			kinfo(channel->name, "busy_list_index=%u hrb_type=%u timed-out timeout_msecs=%u",
				req->busylist_index, K7_REQ_HRB_TYPE(req), req->ioc->timeout_msecs);
		}
		if (!dev->clog.enabled && !k7_dump_failed)
			k7_dump_dtc(NULL, channel->name, "timedout-HRB", &req->hrb_dtc, 64);
	}
	if (dev->clog.enabled) {
		k7_clog_dump_dtc(channel, "failed-HRA", &req->hra_dtc, 64);
	} else if (k7_dump_failed) {
		if (req->ioc->flags & K7_DMA_FLAG_KEK_FASTPATH) {
			struct k7_dma_fastpath *ioc = (struct k7_dma_fastpath *)req->ioc;
			kinfo(dev->name, "HRB=%p: session_id=%08x key_handle=%08x xts_handle=%08x kk=%p xk=%p",
				&req->hrb_dtc, ioc->session_id, ioc->key_handle, ioc->xts_tweak_handle, req->kk, req->xk);
		}
		k7_dump_dtc(NULL, channel->name, "failed-HRB", &req->hrb_dtc, 256);
		k7_dump_dtc(NULL, channel->name, "failed-HRA", &req->hra_dtc, 64);
	}
}

static int k7_handle_req_status (struct k7_channel *channel, struct k7_req *req, int die_on_EINTR)
{
	struct k7_dev *dev = channel->dev;
	struct k7_dt  *dt;
	int err;

	while (req->status == K7_REQ_COMPLETING) {
		msleep(1);
	}
	SPIN_LOCK(&dev->lock);
	switch (req->status) {
	case K7_REQ_COMPLETED:
		err = 0;
		break;
	case K7_REQ_SUBMITTED:
		if (signal_pending(current)) {
			if (die_on_EINTR) {
				if (k7_remove_req_from_busylist(channel, req))
					k7_complete_req(channel, req, K7_REQ_IOERROR, 0);
				k7_dev_failure_locked(dev, channel->name, "User abort (EINTR)");
			}
			err = -EINTR;
		} else {
			if (req->ioc->flags & K7_DMA_FLAG_NO_REPLY) {
				dt = list_tail_entry(&req->hrb_dtc, struct k7_dt, list);
				kderr(channel->name, "TIMEOUT NOTIFY_RX req=%p daddr=%016llx", req, dt->daddr);
			} else {
				kderr(channel->name, "TIMEOUT HRA req=%p daddr=%016llx", req, req->hra_daddr);
			}
			if (k7_remove_req_from_busylist(channel, req))
				k7_complete_req(channel, req, K7_REQ_TIMEDOUT, 0);
			k7_dump_failed_req(channel, req);
			if (!dev->alarm_count)
				kdalarm(dev, "ALM0017: Request Timed Out");
			k7_dev_failure_locked(dev, channel->name, "req timed out");
			err = -ETIMEDOUT;
		}
		break;
	case K7_REQ_TIMEDOUT:
		err = -ETIMEDOUT;
		k7_dump_failed_req(channel, req);
		break;
	case K7_REQ_IOERROR:
	default:
		err = -EIO;
		k7_dump_failed_req(channel, req);
	}
	SPIN_UNLOCK(&dev->lock);
	return err;
}

static void k7_mcpu_abort_hra (struct k7_dev *dev, struct k7_req *req)
{
	u64 hra_daddr = cpu_to_be64(req->hra_daddr);
	int err;

	if (!hra_daddr)
		return;  /* nothing to do */
	/* Cannot use MRB1 for this: leads to race conditions on re-use of hra_daddr. */
	kdebug(dev->name, "req=%p hra_daddr=0x%llx", req, hra_daddr);
	err = k7_send_to_mcpu(dev, &hra_daddr, sizeof(hra_daddr), NULL, 0, K7_DMA_FLAG_NO_REPLY, K7_HRB_TYPE_ABORT_HRA);
	if (err < 0) {
		/*
		 * This can happen if low on resources (will get -EINTR here).
		 * Don't compound the problem by attempting to retry it.
		 */
		if (err != -EINTR)
			kdwarn(dev->name, "send ABORT_HRA failed, err=%d", err);
	}
}

int k7_wait_for_req (struct k7_channel *channel, struct k7_req *req)
{
	int err;

	if (wait_for_completion_interruptible(&req->wait) != -ERESTARTSYS) {
		if (req->status == K7_REQ_COMPLETED)
			return 0;  /* fast exit for the normal case */
		err = k7_handle_req_status(channel, req, 0);
		if (err != -EINTR)
			return err;
	}
	/* Caught a signal: try and abort the command at the MCPU: */
	if (channel->target == K7_DMA_TARGET_MCPU)
		k7_mcpu_abort_hra(channel->dev, req);  /* Don't care if it fails */
	/* Give req a chance to complete gracefully: */
	wait_for_completion_timeout(&req->wait, 15*HZ);
	return k7_handle_req_status(channel, req, 1);
}

int k7_send_to_mcpu (struct k7_dev *dev, const void *inbuf, int inbuf_size, void *outbuf, int outbuf_size, unsigned int flags, unsigned int hrb_type)
{
	struct k7_dma_ioctl *ioc;
	void *buf = NULL;
	int err;

	if (flags & K7_DMA_FLAG_NO_REPLY)
		outbuf_size = 0;
	if (outbuf_size && !outbuf)
		outbuf = buf = kzalloc(outbuf_size,  GFP_KERNEL);
	ioc = kzalloc(sizeof(*ioc), GFP_KERNEL);
	if (!ioc || (outbuf_size && !outbuf)) {
		kerr(dev->name, "kzalloc() failed");
		err = -ENOMEM;
	} else {
		ioc->inbuf         = K7_PTR_TO_U64(inbuf);
		ioc->outbuf        = K7_PTR_TO_U64(outbuf);
		ioc->inbuf_size    = inbuf_size;
		ioc->outbuf_size   = outbuf_size;
		ioc->target        = K7_DMA_TARGET_MCPU;
		ioc->flags         = flags | K7_DMA_FLAG_KBUF;
		if (!outbuf_size)
			ioc->flags |= K7_DMA_FLAG_NO_RESULT_DATA;
		ioc->timeout_msecs = 20 * 1000;  /* 20 seconds */
		err = k7_do_dma_ioctl(dev, ioc, hrb_type);
		if (k7_debug && err >= 0 && outbuf) {
			kfinfo(dev->name, "err=%d", err);
			k7_dumpmem(NULL, dev->name, NULL, "MCPU outbuf", outbuf, 0, outbuf_size);
		}
	}
	if (ioc)
		kfree(ioc);
	if (buf) {
		memset(buf, 0, outbuf_size);
		kfree(buf);
	}
	return err;
}

struct k7_async_send_work {
	struct work_struct	work;
	struct k7_dev		*dev;
	char			msg_type[32];
	unsigned int		hrb_type;
	unsigned int		dma_flags;
	unsigned int		inbuf_size;
	u8			inbuf[64];
};

static void k7_async_send_worker (struct work_struct *work)
{
	struct k7_async_send_work *w = container_of(work, struct k7_async_send_work, work);
	struct k7_dev *dev = w->dev;
	int err;

	if (w->msg_type[0] && w->msg_type[0] != '-')
		kdlog(dev->name, "Sending %s", w->msg_type);
	err = k7_send_to_mcpu(dev, w->inbuf, w->inbuf_size, NULL, 128, w->dma_flags, w->hrb_type);
	if (err < 0) {
		kderr(dev->name, "%s failed, err=%d", w->msg_type, err);
		k7_dev_failure(dev, w->msg_type, "failed");
	}
	memset(w, 0, sizeof(*w));
	kfree(w);
}

void k7_async_send_to_mcpu (struct k7_dev *dev, const char *msg_type, unsigned int hrb_type,
				unsigned int dma_flags, void *inbuf, unsigned int inbuf_size)
{
	struct k7_async_send_work *w;
	/*
	 * We are being invoked from the IRQ handler,
	 * so we cannot just send a message to the MCPU from this context.
	 * Instead, pass it off onto a workqueue.
	 */
	w = kzalloc(sizeof(*w), GFP_ATOMIC);
	if (!w) {
		kderr(dev->name, "%s failed, err=%d", msg_type, -ENOMEM);
		k7_dev_failure_locked(dev, msg_type, "failed");
		return;
	}
	INIT_WORK(&w->work, k7_async_send_worker);
	w->dev = dev;
	strncpy(w->msg_type, msg_type, sizeof(w->msg_type) - 1);
	w->msg_type[sizeof(w->msg_type) - 1] = '\0';
	w->hrb_type = hrb_type;
	w->dma_flags = dma_flags;
	if (inbuf && inbuf_size) {
		if (inbuf_size > sizeof(w->inbuf))
			inbuf_size = sizeof(w->inbuf);
		w->inbuf_size = inbuf_size;
		memcpy(w->inbuf, inbuf, inbuf_size);
	}
	schedule_work(&w->work);
}
