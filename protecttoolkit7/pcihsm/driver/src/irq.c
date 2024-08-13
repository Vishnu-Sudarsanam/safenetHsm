/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * irq.c
 */
#include "headers.h"

static int k7_pci_enable_msix(struct k7_dev *dev)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0))
	return pci_enable_msix(dev->pdev, dev->irqs, dev->num_vectors);
#else
	int ret, i, nvec = dev->num_vectors;

	ret = pci_alloc_irq_vectors(dev->pdev, nvec, nvec, PCI_IRQ_MSIX);
	if (ret >= 0) {
		for (i = 0; i < nvec; i++)
			dev->irqs[i].vector = pci_irq_vector(dev->pdev, i);
		ret = 0;
	}
	return ret;
#endif
}

/*
 * Update the Interrupt-Enable register, keeping a cached copy for use by k7_irq().
 */
void k7_write_hier (struct k7_dev *dev, u32 hier)
{
	dev->hier = hier;
	if (dev->mmio)
		K7_FLUSH32(K7_HIER, hier);
}

/*
 * Disable (mask) all on-chip interrupts.
 */
void k7_disable_all_irqs (struct k7_dev *dev)
{
	k7_write_hier(dev, 0);  /* disable all interrupts */
}

/*
 * Disable (mask) all DMA-related on-chip interrupts.
 */
void k7_disable_dma_irqs (struct k7_dev *dev)
{
	k7_write_hier(dev, dev->hier & ~K7_DMA_IRQS);
}

int k7_poll_pcie_link_failed (struct k7_dev *dev)
{
	SPIN_LOCK_REQUIRED(&dev->lock);
	if (dev->pcie_link_poll_enabled) {
		dev->pcie_link_poll_enabled = 0;
		if (dev->pcie_link_failed && dev->pci_saved_state)
			k7_restore_pci_state(dev);
		if (K7_READ64(K7_VF_MAX_HRB_LEN) != ~0ull) {
			if (dev->pcie_link_failed) {
				dev->pcie_link_failed = 0;
				kdlog(dev->name, "PCIe Link is alive again");
			}
		} else if (!dev->pcie_link_failed) {
			dev->pcie_link_failed = 1;
			kdalarm(dev, "ALM0015: PCIe Link Failure");
			k7_dev_failure_locked(dev, "ERROR", "PCIe Link Failure");
		}
		dev->pcie_link_poll_enabled = 1;
	}
	return dev->pcie_link_failed;
}

static int k7_decode_hw_chid (unsigned int chid, char *name)
{
	int target;

	switch (chid) {
	case  0: strcpy(name, "H2MM")  ; target = K7_DMA_TARGET_PKU;   break;
	case  1: strcpy(name, "H2SKA") ; target = K7_DMA_TARGET_SKU;   break;
	case  2: strcpy(name, "H2SKB") ; target = K7_DMA_TARGET_SKU;   break;
	case  3: strcpy(name, "H2M")   ; target = K7_DMA_TARGET_MCPU;  break;
	case  4: strcpy(name, "H2S")   ; target = -EINVAL;             break;
	case  5: strcpy(name, "H2FA")  ; target = -EINVAL;             break;
	case  6: strcpy(name, "H2FB")  ; target = -EINVAL;             break;
	case  8: strcpy(name, "MM2H")  ; target = K7_DMA_TARGET_PKU;   break;
	case  9: strcpy(name, "SKA2H") ; target = K7_DMA_TARGET_SKU;   break;
	case 10: strcpy(name, "SKB2H") ; target = K7_DMA_TARGET_SKU;   break;
	case 11: strcpy(name, "M2H")   ; target = K7_DMA_TARGET_MCPU;  break;
	case 12: strcpy(name, "S2H")   ; target = -EINVAL;             break;
	case 13: strcpy(name, "FA2H")  ; target = -EINVAL;             break;
	case 14: strcpy(name, "FB2H")  ; target = -EINVAL;             break;
	default:
		sprintf(name, "(%u?)", chid);
		target = -EINVAL;
	}
	return target;
}

static u64 k7_dump_channel_regs (struct k7_channel *channel, unsigned int chid)
{
	struct k7_dev *dev = channel->dev;
	const char *name;
	unsigned int dma_base;

	u64 tcp, rcs, rbp, rdc, rdt, wcs, wlh, wbp, wdc, wdt, wdo;

	if (!dev->is_pf)
		return 0;
	switch (channel->target) {
	case K7_DMA_TARGET_MCPU:
		name     = "H2M";
		dma_base = K7_MCPU_DMA_BASE;
		break;
	case K7_DMA_TARGET_PKU:
		name     = "H2P";
		dma_base = K7_PKU_DMA_BASE;
		break;
	case K7_DMA_TARGET_SKU:
		if (chid == 2) {
			name     = "H2SKB";
			dma_base = K7_SKUB_DMA_BASE;
		} else {
			name     = "H2SKA";
			dma_base = K7_SKU_DMA_BASE;
		}
		break;
	default:
		return 0;
	}

	SPIN_LOCK_REQUIRED(&channel->dev->lock);
	tcp = (chid == 2) ? 0 : K7_READ64(dma_base + K7_H2X_TCP);
	rcs = K7_READ64(dma_base + K7_H2X_CH_STATUS);
	rbp = K7_READ64(dma_base + K7_H2X_BUFF_PTR);
	rdc = K7_READ64(dma_base + K7_H2X_DT_CTRL);
	rdt = K7_READ64(dma_base + K7_H2X_LAST_DT_PTR);
	wcs = K7_READ64(dma_base + K7_X2H_CH_STATUS);
	wlh = K7_READ64(dma_base + K7_X2H_LAST_HEADER);
	wbp = K7_READ64(dma_base + K7_X2H_BUFF_PTR);
	wdc = K7_READ64(dma_base + K7_X2H_DT_CTRL);
	wdt = K7_READ64(dma_base + K7_X2H_DT_PTR);
	wdo = K7_READ64(dma_base + K7_X2H_FIFO_AUX_DOUT);
	kinfo(channel->name, "%s-regs: tcp=0x%llx rcs=0x%llx rbp=0x%llx rdc=0x%llx rdt=0x%llx",
					name, tcp, rcs, rbp, rdc, rdt);
	kinfo(channel->name, "%s-regs: wcs=0x%llx wlh=0x%llx wbp=0x%llx wdc=0x%llx wdt=0x%llx wdo=0x%llx",
					name, wcs, wlh, wbp, wdc, wdt, wdo);
	return tcp;
}

#if 0 // FIXME this function is a work-in-progress; disabled for now.
static void k7_recover_dma (struct k7_dev *dev, unsigned int target, unsigned int chid)
{
	struct k7_channel *channel = &dev->channels[target];

	/*
	 * Problem:  with SKU (at least), TCP is unreliable because of dual-pipes.
	 */
	u64 daddr = K7_READ64(channel->base + K7_H2X_TCP);
	struct k7_req *req;

	if (!daddr) {
		k7_dev_failure_locked(dev, channel->name, "DMA error: NULL daddr");
		return;
	}
	/*
	 * For _VF_ errors, the HRA will _not_ appear in HTB later,
	 * because the hardware DMA channel flushes those through by itself.
	 * So fail the request directly here, and then reenable channels.
	 * EDIT: for DD2 at least, this is not always true of PKU requests;
	 * EDIT: those will sometimes give an IRQ _and_ an HTB entry.
	 *
	 * For a _PF_ RD_CH error, the HRA _will_ appear in HTB
	 * automatically as soon as we re-enable the channel.
	 * So just flag the request as failed (IOERROR),
	 * and let it complete naturally.
	 *
	 * For a _PF_ WR_CH error, things are more complex.
	 * The TCP register points at the most recently *sent* request,
	 * which could be later than the one that actually failed.
	 * So for single threaded operation, it usually works same as RD_CH above,
	 * but when multiple things are queued up, we could get mass confusion.
	 *
	 * And don't even mention how complex "external completion" makes things.
	 */
	req = k7_find_req_from_dt(channel, daddr, 0, NULL, "RECOV_DMA_ERR");
	if (!req) {
		k7_dev_failure_locked(dev, channel->name, "DMA error: req not found");
	} else {
		if (dev->is_pf) {
			req->status = K7_REQ_IOERROR;
		} else {
			if (k7_remove_req_from_busylist(channel, req))
				k7_complete_req(channel, req, K7_REQ_IOERROR, 1);
		}
		// k7_enable_dma_channel(channel, 0);
		k7_reinit_dma_channel(channel, K7_NOT_RESET);
		if (channel->eoc != NULL)
			k7_trigger_channel_initial_fetch(channel);
	}
}
#endif

static void k7_dump_hderr (struct k7_dev *dev, int target, u32 hderr)
{
	if (target >= 0) {
		struct k7_channel *channel = &dev->channels[target];
		unsigned int hderr_count = ++channel->hderr_count;
		char label[32];
		sprintf(label, "%s HDERR-%u", channel->name, hderr_count);
		k7_dumpreg(dev, label, hderr, k7_hderr_regbits);
	}
}

static void k7_vf_mbx_handler (struct k7_dev *dev, u64 mbx)
{
	if (dev->minor == -1) {
		/* the last byte of mbx should be our device minor number */
		u8 minor = (u8)extract64(mbx, BE64MSK(56,63));
		u8 vfid  = minor % K7_MINORS_PER_CARD;
		if (minor && vfid) {
			/* Make sure the mbx VF bit matches vfid of the minor number */
			unsigned int offset = --vfid * 2;
			unsigned int bits = extract64(mbx, BE64MSK(offset, offset + 1));
			if (bits == 3) {
				dev->minor = minor;
				mb();
				kdebug(dev->name, " mbx   0x%016llx vfid %u minor %u", mbx, vfid, minor);
				kdebug(dev->name, "writing mbx=0x%016llx (done)", 0);
				K7_WRITE64(K7_PF2VF_MBX, 0);
			}
		}
	}
}

static void k7_pf_mbx_handler (struct k7_dev *dev, u64 mbx)
{
	const u32 all_wren = 0x55555555;
	u64 reply = ((u64)all_wren) << 32;
	u32 vf, ctrl = mbx >> 32;

	/*
	 * If mbx is all zeros, this is a final "ACK" from a VF.
	 * So we can now re-enable writes (interrupts) from all VFs.
	 */
	if (ctrl) {
		kdebug(dev->name, "mbx   0x%016llx", mbx);
		/*
		 * Okay, at least one VF tried to interrupt us.
		 * Identify the first one by looking for a zeroed Write-Enable bit,
		 * and reply with its device minor number.
		 *
		 * Be wary of a potential bug here (actually happened). For example:
		 * 1. PF reads  0x4555555500000000
		 * 2. PF writes 0x3000000000000002,
		 * 3. VF simultaneously times out and writes zeros again without reading mbx.
		 * 4. PF reads  0x2000000000000000, indicating VF hasn't read prior message.
		 * Need to be careful in handling this!
		 */
		for (vf = 0; vf < dev->num_vf; ++vf) {
			u32 vf_full = 0x80000000 >> (vf * 2);  /* MBX-Full     */
			u32 vf_wren = 0x40000000 >> (vf * 2);  /* Write-Enable */
			if (ctrl == (all_wren & ~vf_wren)	/* Normal case: VF asking for "identify me" */
			 || ctrl == vf_full)			/* Collision: VF timed-out/retried just as we replied */
			{
				u32 msg = (u32)mbx;  /* bottom 32-bits */
				if (msg == 0) {  /* an "identify me" request */
					u8 minor = (u8)(dev->minor + 1 + vf);
					/*
					 * Reply to this VF, and reenable reception from it.
					 */
					reply  = (((u64)(vf_full | vf_wren)) << 32) | minor;
					kdebug(dev->name, "reply 0x%016llx vfid %u minor %u", reply, vf, minor);
					/*
					 * Start timer in case the VF doesn't ACK again with all-zeros.
					 */
					mod_timer(&dev->pf2vf_timer, jiffies + HZ);
					break;  /* Can only message to a single VF at a time */
				}
			}
		}
	}
	kdebug(dev->name, "writing mbx=0x%016llx", reply);
	K7_WRITE64(K7_PF2VF_MBX, reply);
}

/* pf2vf_timer function */
void k7_pf2vf_timer_expiry (K7_KERNEL_TIMER_ARG_T arg)
{
	void *timer_p = (struct timer_list *)arg;
	struct k7_dev *dev = container_of(timer_p, struct k7_dev, pf2vf_timer);
	unsigned long flags;

	SPIN_LOCK_IRQSAVE(&dev->pf2vf_lock, flags);
	k7_pf_mbx_handler(dev, 0);
	SPIN_UNLOCK_IRQRESTORE(&dev->pf2vf_lock, flags);
}

static void k7_dump_sm_regs (struct k7_dev *dev, void *sm_regs)
{
	const int bufsize = 64;
	char *buf = kmalloc(bufsize, GFP_ATOMIC);
	u8 *regs = (u8 *)sm_regs;
	int n = 0, addr;

	if (!buf) {
		kderr(dev->name, "%s: no memory", __func__);
		return;
	}
	for (addr = 0; addr < K7_SM_REG_COUNT; addr++) {
		int pos = addr % 16;
		if (pos == 0)
			n += scnprintf(buf+n, bufsize-n, "%04x:", addr);
		n += scnprintf(buf+n, bufsize-n, " %02x", regs[addr]);
		if (pos == 15 || addr == K7_SM_REG_COUNT) {
			kdlog(dev->name, "%s: %s\n", __func__, buf);
			n = 0;
		}
	}
	kfree(buf);
}

/*
 * Read a set of four registers from SM chip.
 * Time required is about 151usec per I2C register read.
 */
static int k7_read_sm_reg_locked (struct k7_dev *dev, unsigned int addr, u32 *val_r)
{
	unsigned int loops;

	SPIN_LOCK_REQUIRED(&dev->lock);
	K7_WRITE32(K7_HTS_AP, insert32(0, K7_HTS_AP_HTS_ADDR, addr));
	for (loops = 0; loops < 400; ++loops) {
		u32 ap;
		udelay(1);
		ap = K7_READ32(K7_HTS_AP);
		if (ap != ~0u && ap & K7_HTS_AP_HTS_DONE) {
			*val_r = cpu_to_be32(K7_READ32(K7_HTS_DP));  /* Callers expect big-endian */
			return 0;
		}
		if (ap & K7_HTS_AP_HTS_ERR) {
			kdlog(dev->name, "%s(%04x): error (loops=%u)", __func__, addr, loops);
			return -EIO;
		}
	}
	kdlog(dev->name, "%s(%04x): timeout", __func__, addr);
	return -ETIMEDOUT;
}

static int k7_read_sm_reg (struct k7_dev *dev, unsigned int addr, int locked, u32 *val_r)
{
	int err;

	if (!locked)
		SPIN_LOCK(&dev->lock);
	err = k7_read_sm_reg_locked(dev, addr, val_r);
	if (!locked)
		SPIN_UNLOCK(&dev->lock);
	return err;
}

/*
 * Read registers from Security Management chip.
 */
int k7_read_sm_regs (struct k7_dev *dev, void *sm_regs, int locked, int *count_r)
{
	u32 *regs = (u32 *)sm_regs;
	int addr, err;

	for (addr = 0; addr < K7_SM_REG_COUNT; addr += sizeof(u32)) {
		u32 val = 0;
		err = k7_read_sm_reg(dev, addr, locked, &val);
		if (err)
			break;
		*regs++ = val;
	}
	*count_r = addr;
	return err;
}

/*
 * Get current temperature reading from PKA power management.
 */
static void k7_read_pkapm_temperature (struct k7_dev *dev, int *temperature_r)
{
	int t;
	u64 val = K7_READ64(K7_HCSR);
	val = extract64(val, K7_HCSR_PM_CURR_TEMP);
	t = val & 0x000000ff;
	if (t >= 0x80)
		t -= 256;
	*temperature_r = t;
}

static void k7_report_dma_error (struct k7_dev *dev, unsigned int target, unsigned int chid)
{
	struct k7_channel *channel = &dev->channels[target];
	u64 daddr;

	daddr = k7_dump_channel_regs(channel, chid);
	k7_minimal_dump_busylist(channel);
	if (daddr) {
		struct k7_req *req = k7_find_req_from_dt(channel, daddr, 0, NULL, __func__);
		if (req) {
			kinfo(channel->name, "Failed req=%p", req);
			k7_dump_dtc(NULL, channel->name, "DMA_ERR failed-HRB", &req->hrb_dtc, 256);
			if (k7_remove_req_from_busylist(channel, req))
				k7_complete_req(channel, req, K7_REQ_IOERROR, 1);
		}
	}
}

static void k7_handle_dma_error (struct k7_dev *dev, const char *err_msg)
{
	char name[16];
	int rd_target = -1, wr_target = -1;
	u32 rchid, wchid, hderr = K7_READ32(K7_HDERR);

	dev->last_hderr = hderr;
	rchid = extract32(hderr, K7_HDERR_RD_CH_ID);
	if (rchid != 0xf) {
		K7_WRITE16(K7_HDERR, 0); // clear the RD half of the error register
		// Easy: the channel's TCP reg points at a hwdt from failed request.
		rd_target = k7_decode_hw_chid(rchid, name);
		kdlog(dev->name, "%s interrupt, RD_CH=%s chid=%u", err_msg, name, rchid);
		k7_dump_hderr(dev, rd_target, hderr);
	}
	wchid = extract32(hderr, K7_HDERR_WR_CH_ID);
	if (wchid != 0xf) {
		K7_WRITE16(K7_HDERR + 2, 0); // clear the WR half of the error register
		// Hard: the channel's TCP reg *might not* point at a DT from failed request.
		// There's a 4KB outgoing FIFO.. so channel could have read several requests
		// and fed them to SKU/PKA before a failed response arrives.
		wr_target = k7_decode_hw_chid(wchid, name);
		kdlog(dev->name, "%s interrupt, WR_CH=%s", err_msg, name);
		k7_dump_hderr(dev, wr_target, hderr);
	}
	if (rd_target == -1 && wr_target == -1)
		k7_dumpreg(dev, NULL, hderr, k7_hderr_regbits);
	if (rd_target >= 0 && rd_target != wr_target)
		k7_report_dma_error(dev, rd_target, rchid);
	if (wr_target >= 0 && !dev->failed)
		k7_report_dma_error(dev, wr_target, wchid);
	k7_dev_failure_locked(dev, "ERROR", err_msg);
}

static u32 k7_handle_tamper (struct k7_dev *dev, u32 hisr_bits)
{
	u64 hcsr;
	u32 hrcsr;
	int sm_count = 0;
	u8 *sm_regs;

	if (dev->is_pf)
		k7_force_stop_all_dma_immediately(dev);  /* Errata HW288377 wants us to do this as early as possible */
	hrcsr = K7_READ32(K7_HRCSR);
	hcsr  = K7_READ64(K7_HCSR);
	if (hisr_bits & K7_HISR_SOFT_TAMPER) {
		int old = dev->alarm_count;
		hisr_bits &= ~K7_HISR_SOFT_TAMPER;
		if (hcsr != ~0ull) {
			if (hrcsr & K7_HRCSR_VST)
				kdalarm(dev, "ALM0001: Soft tamper - over voltage");
			if (hrcsr & K7_HRCSR_TST)
				kdalarm(dev, "ALM0002: Soft tamper - temperature (%dC)",
						extract64(hcsr, K7_HCSR_PM_TAMPER_TEMP));
		}
		if (dev->alarm_count == old)
			kdalarm(dev, "ALM0003: Soft tamper - indeterminate cause");
	}
	sm_regs = kzalloc(K7_SM_REG_COUNT, GFP_ATOMIC);
	if (sm_regs)
		k7_read_sm_regs(dev, sm_regs, 1/*locked*/, &sm_count);
	else
		kerr(dev->name, "kzalloc(sm_regs) failed");
	if (hisr_bits & K7_HISR_HARD_TAMPER) {
		int old = dev->alarm_count;
		hisr_bits &= ~K7_HISR_HARD_TAMPER;
		if (sm_count >= 3) {  /* managed to read the Tamper Latch info? */
			if (sm_regs[3] & BIT(2))
				kdalarm(dev, "ALM0004: Hard tamper - high temperature");
			if (sm_regs[3] & BIT(1))
				kdalarm(dev, "ALM0005: Hard tamper - low temperature");
			if (sm_regs[2] & BIT(5) || sm_regs[1] & BIT(3))
				kdalarm(dev, "ALM0006: Hard tamper - over voltage");
			if (sm_regs[3] & BIT(6))
				kdalarm(dev, "ALM0007: Hard tamper - internal data corruption");
			if (sm_regs[1] & (BIT(2)|BIT(1)| BIT(0)) || sm_regs[2] & (BIT(3)|BIT(2)|BIT(1)|BIT(0)))
				kdalarm(dev, "ALM0008: Hard tamper - enclosure penetration");
			if (sm_regs[3] & BIT(3))
				kdalarm(dev, "ALM0009: Hard tamper - oscillator failure");
			if (sm_regs[1] & BIT(4))
				kdalarm(dev, "ALM0010: Hard tamper - Decommission signal triggered");
		}
		if (dev->alarm_count == old)
			kdalarm(dev, "ALM0011: Hard tamper - indeterminate cause");
	}
	if (sm_regs) {
		k7_dump_sm_regs(dev, sm_regs);
		kfree(sm_regs);
	}
	k7_dumpreg(dev, NULL, hrcsr, k7_hrcsr_regbits);
	k7_dumpreg(dev, NULL, hcsr,  k7_hcsr_regbits);
	if (K7_READ32(K7_HIER) == 0) {
		kderr(dev->name, "HIER got cleared!");
		/*
		 * No point in restoring it here,
		 * the problem is with VFs/PF that don't get the tamper irq
		 * because their HIER got cleared too quickly..
		 * Cannot help that here, and lots of other host regs also get reset (ugh).
		 */
	}
	k7_update_hsm_state(dev, K7_HSM_STATE_TAMPER_RESET);
	k7_dev_failure_locked(dev, "ERROR", "TAMPER");
	return hisr_bits;
}

/*
 * Handle the less frequently occurring interrupts.
 */
static void k7_service_misc_irqs (struct k7_dev *dev, u32 hisr_bits)
{
	if (hisr_bits & K7_HISR_HW_ERR) {
		hisr_bits &= ~K7_HISR_HW_ERR;
		K7_WRITE32(K7_HISR, K7_HISR_HW_ERR);  /* clear the interrupt, but reset also needed */
		kdalarm(dev, "ALM0012: Hardware Error");
		k7_dev_failure_locked(dev, "ERROR", "HW_ERR");
	}
	if (hisr_bits & K7_HISR_ACCESS_ERR) {
		/* self-clearing */
		hisr_bits &= ~K7_HISR_ACCESS_ERR;
		k7_dev_failure_locked(dev, "ERROR", "ACCESS_ERR");
	}
	if (hisr_bits & K7_HISR_RECOV_DMA_ERR) {
		hisr_bits &= ~K7_HISR_RECOV_DMA_ERR;
		k7_handle_dma_error(dev, "RECOV_DMA_ERR");
	}
	if (hisr_bits & K7_HISR_UNRECOV_DMA_ERR) {
		hisr_bits &= ~K7_HISR_UNRECOV_DMA_ERR;
		K7_WRITE32(K7_HISR, K7_HISR_UNRECOV_DMA_ERR);  // clear the interrupt
		k7_handle_dma_error(dev, "UNRECOV_DMA_ERR");
	}
	if (hisr_bits & (K7_HISR_SOFT_TAMPER | K7_HISR_HARD_TAMPER)) {
		hisr_bits = k7_handle_tamper(dev, hisr_bits);
	}
	if (hisr_bits & K7_HISR_H2M) {
		hisr_bits &= ~K7_HISR_H2M;
		kdebug(dev->name, "H2M mailbox");
	}
	if (hisr_bits & K7_HISR_M2H) {
		u64 mbx = k7_read_m2h_mbx(dev);
		hisr_bits &= ~K7_HISR_M2H;
		kdebug(dev->name, "M2H mailbox: %016llx", mbx);
		k7_handle_m2h_mbx(dev, mbx);
	}
	if (hisr_bits & K7_HISR_H2S) {
		hisr_bits &= ~K7_HISR_H2S;
		kdlog(dev->name, "H2S mailbox");
	}
	if (hisr_bits & K7_HISR_S2H) {
		u64 mbx = K7_READ64(K7_S2H_MBX);
		hisr_bits &= ~K7_HISR_S2H;
		kdlog(dev->name, "S2H mailbox: %016llx", mbx);
	}
	if (hisr_bits & K7_HISR_H_TEMP_WRNG) {
		int temperature;
		hisr_bits &= ~K7_HISR_H_TEMP_WRNG;
		k7_read_pkapm_temperature(dev, &temperature);
		kdlog(dev->name, "ALM0013: High Temperature - %dC", temperature);  /* non-fatal alarms use kdlog() */
	}
	if (hisr_bits & K7_HISR_LOWBAT) {
		hisr_bits &= ~K7_HISR_LOWBAT;
		kdlog(dev->name, "ALM0014: Low Battery");  /* non-fatal alarms use kdlog() */
	}
	if (hisr_bits & K7_HISR_PF2VF_MBX) {
		u64 mbx;
		hisr_bits &= ~K7_HISR_PF2VF_MBX;
		if (dev->is_pf) {
			SPIN_LOCK_IRQ(&dev->pf2vf_lock);
			mbx = K7_READ64(K7_PF2VF_MBX);
			kdebug(dev->name, "PF2VF mailbox: %016llx", mbx);
			if (dev->num_vf)
				k7_pf_mbx_handler(dev, mbx);
			SPIN_UNLOCK_IRQ(&dev->pf2vf_lock);
		} else {
			mbx = K7_READ64(K7_PF2VF_MBX);
			kdebug(dev->name, "PF2VF mailbox: %016llx", mbx);
			k7_vf_mbx_handler(dev, mbx);
		}
	}
	if (hisr_bits & K7_HISR_SRM_ATT)
		k7_dev_failure_locked(dev, "ERROR", "SRM_ATT");
	if (hisr_bits & K7_HISR_MRM_ATT)
		k7_dev_failure_locked(dev, "ERROR", "MRM_ATT");
	if (hisr_bits) {
		k7_dumpreg(dev, "hisr_unhandled", hisr_bits, k7_hisr_regbits);
		k7_dumpreg(dev, "HIER", dev->hier, k7_hisr_regbits);
		k7_disable_all_irqs(dev);
		k7_dev_failure_locked(dev, "ERROR", "unexpected_IRQ");
	}
}

static u32 k7_lookup_hisr_bits (struct k7_dev *dev, int irq)
{
	unsigned int i;

	for (i = 0; i < dev->num_vectors; ++i) {
		if (dev->irqs[i].vector == irq)
			return dev->hisr_bits[i];
	}
	kderr(dev->name, "BUG: irq=%d not found in vectors", irq);
	return K7_HISR_READ_NEEDED;  /* examine all HISR bits */
}

static u32 k7_read_and_mask_hisr_bits (struct k7_dev *dev, u32 enabled_irqs)
{
	u32 hisr_bits = K7_READ32(K7_HISR);
	if (hisr_bits == ~0u) {
		k7_poll_pcie_link_failed(dev);
		enabled_irqs = 0;  /* Prevents further processing */
	}
	hisr_bits &= enabled_irqs;
	return hisr_bits;
}

/*
 * Interrupt thread for the single-vector case.
 */
static irqreturn_t k7_generic_irq_thread (int irq, void *devp)
{
	struct k7_dev *dev = devp;
	u32 hisr_bits, htb_bits;

	SPIN_LOCK(&dev->lock);
	hisr_bits = k7_lookup_hisr_bits(dev, irq);
	if (hisr_bits == K7_HISR_READ_NEEDED)
		hisr_bits = k7_read_and_mask_hisr_bits(dev, dev->hier);
	htb_bits   = hisr_bits & (K7_HISR_HTB_INT | K7_HISR_HTB_BF);
	hisr_bits ^= htb_bits;
	if (hisr_bits)
		k7_service_misc_irqs(dev, hisr_bits);
	SPIN_UNLOCK(&dev->lock);
	if (htb_bits)
		k7_service_htb(dev);
	return IRQ_HANDLED;
}

/*
 * Interrupt thread for HTB interrupts.
 */
static irqreturn_t k7_htb_irq_thread (int irq, void *devp)
{
	struct k7_dev *dev = devp;

	k7_service_htb(dev);
	return IRQ_HANDLED;
}

/*
 * This can be called from within the driver to poll for existing (missed edge) IRQs at startup.
 * No need to look for HTB interrupts here.
 */
void k7_poll_hisr (struct k7_dev *dev, u32 enabled_irqs)
{
	u32 hisr_bits;

	hisr_bits = k7_read_and_mask_hisr_bits(dev, enabled_irqs);
	if (hisr_bits)
		k7_service_misc_irqs(dev, hisr_bits);
}

static void k7_bind_hisr_bits (struct k7_dev *dev, int index, u32 hisr_bits, const char *irq_name)
{
	dev->hisr_bits[index] = hisr_bits;
	snprintf(dev->irq_names[index], sizeof(dev->irq_names[index]), "%s-%s", dev->name, irq_name);
}

static void k7_prep_for_1_msi_vector (struct k7_dev *dev)
{
	K7_FLUSH32(K7_HMVMC, K7_HMVMC_MSIX_1_VEC);  /* paranoia */
	dev->num_vectors = 1;
	dev->irqs[0].vector = dev->pdev->irq;
	k7_bind_hisr_bits(dev, 0, K7_HISR_READ_NEEDED, "ALL");	/* HISR bits 0-31 */
}

static void k7_prep_for_2_msi_vectors (struct k7_dev *dev)
{
	K7_FLUSH32(K7_HMVMC, K7_HMVMC_MSIX_2_VEC);  /* paranoia */
	dev->num_vectors = 2;
	dev->irqs[0].vector = dev->pdev->irq;
	dev->irqs[1].vector = dev->pdev->irq + 1;
	k7_bind_hisr_bits(dev, 0, K7_HISR_READ_NEEDED, "LOW");	/* HISR bits 0-7  */
	k7_bind_hisr_bits(dev, 1, K7_HISR_READ_NEEDED, "HIGH");	/* HISR bits 8-31 */
}

static void k7_prep_msix_entries (struct k7_dev *dev, unsigned int num_vectors)
{
	unsigned int i;

	dev->num_vectors = num_vectors;
	for (i = 0; i < num_vectors; ++i) {
		dev->irqs[i].vector = 0;	/* irq number filled-in by pci_enable_msix() */
		dev->irqs[i].entry  = i;	/* index into MSI-X table */
	}
}

static void k7_prep_for_1_msix_vector (struct k7_dev *dev)
{
	k7_prep_msix_entries(dev, 1);
	K7_FLUSH32(K7_HMVMC, K7_HMVMC_MSIX_1_VEC);
	k7_bind_hisr_bits(dev, 0, K7_HISR_READ_NEEDED, "ALL");	/* HISR bits 0-31 */
}

static void k7_prep_for_2_msix_vectors (struct k7_dev *dev)
{
	k7_prep_msix_entries(dev, 2);
	K7_FLUSH32(K7_HMVMC, K7_HMVMC_MSIX_2_VEC);
	k7_bind_hisr_bits(dev, 0, K7_HISR_READ_NEEDED, "LOW");	/* HISR bits 0-7  */
	k7_bind_hisr_bits(dev, 1, K7_HISR_READ_NEEDED, "HIGH");	/* HISR bits 8-31 */
}

static void k7_prep_for_4_msix_vectors (struct k7_dev *dev)
{
	k7_prep_msix_entries(dev, 4);
	K7_FLUSH32(K7_HMVMC, K7_HMVMC_MSIX_4_VEC);
	k7_bind_hisr_bits(dev, 0, K7_HISR_READ_NEEDED, "LOW");	/* HISR bits 0-7  */
	k7_bind_hisr_bits(dev, 1, K7_HISR_READ_NEEDED, "HIGH");	/* HISR bits 8-29 */
	k7_bind_hisr_bits(dev, 2, K7_HISR_READ_NEEDED, "HTBF");	/* HISR bit 30 */
	k7_bind_hisr_bits(dev, 3, K7_HISR_HTB_INT,     "HTB");	/* HISR bit 31 */
}

static void k7_prep_for_8_msix_vectors (struct k7_dev *dev)
{
	k7_prep_msix_entries(dev, 8);
	K7_FLUSH32(K7_HMVMC, K7_HMVMC_MSIX_8_VEC);
	k7_bind_hisr_bits(dev, 0, K7_HISR_READ_NEEDED, "LOW");	/* HISR bits  0-7  */
	k7_bind_hisr_bits(dev, 1, K7_HISR_READ_NEEDED, "HIGH");	/* HISR bits 12-29 */
	k7_bind_hisr_bits(dev, 2, K7_HISR_READ_NEEDED, "H2M");	/* HISR bit   8 */
	k7_bind_hisr_bits(dev, 3, K7_HISR_M2H,         "M2H");	/* HISR bit   9 */
	k7_bind_hisr_bits(dev, 4, K7_HISR_READ_NEEDED, "H2S");	/* HISR bit  10 */
	k7_bind_hisr_bits(dev, 5, K7_HISR_S2H,         "S2H");	/* HISR bit  11 */
	k7_bind_hisr_bits(dev, 6, K7_HISR_READ_NEEDED, "HTBF");	/* HISR bit  30 */
	k7_bind_hisr_bits(dev, 7, K7_HISR_HTB_INT,     "HTB");	/* HISR bit  31 */
}

static void k7_prep_for_16_msix_vectors (struct k7_dev *dev)
{
	k7_prep_msix_entries(dev, 16);
	K7_FLUSH32(K7_HMVMC, K7_HMVMC_MSIX_16_VEC);
	k7_bind_hisr_bits(dev,  0, K7_HISR_HW_ERR,          "HWERR");	/* HISR bit  0 */
	k7_bind_hisr_bits(dev,  1, K7_HISR_READ_NEEDED,      "ACCERR");	/* HISR bit  3 */
	k7_bind_hisr_bits(dev,  2, K7_HISR_READ_NEEDED,      "RECOV");	/* HISR bit  4 */
	k7_bind_hisr_bits(dev,  3, K7_HISR_UNRECOV_DMA_ERR, "UNRECOV");	/* HISR bit  5 */
	k7_bind_hisr_bits(dev,  4, K7_HISR_READ_NEEDED,     "STAMPER");	/* HISR bit  6 */
	k7_bind_hisr_bits(dev,  5, K7_HISR_READ_NEEDED,     "HTAMPER");	/* HISR bit  7 */
	k7_bind_hisr_bits(dev,  6, K7_HISR_READ_NEEDED,     "H2M");	/* HISR bit  8 */
	k7_bind_hisr_bits(dev,  7, K7_HISR_M2H,             "M2H");	/* HISR bit  9 */
	k7_bind_hisr_bits(dev,  8, K7_HISR_READ_NEEDED,     "H2S");	/* HISR bit 10 */
	k7_bind_hisr_bits(dev,  9, K7_HISR_READ_NEEDED,     "S2HP2V");	/* HISR bits 11,27 */
	k7_bind_hisr_bits(dev, 10, K7_HISR_READ_NEEDED,     "HTEMP");	/* HISR bit 24 */
	k7_bind_hisr_bits(dev, 11, K7_HISR_READ_NEEDED,     "LBAT");	/* HISR bit 26 */
	k7_bind_hisr_bits(dev, 12, K7_HISR_READ_NEEDED,     "SRM");	/* HISR bit 28 */
	k7_bind_hisr_bits(dev, 13, K7_HISR_READ_NEEDED,     "MRM");	/* HISR bit 29 */
	k7_bind_hisr_bits(dev, 14, K7_HISR_READ_NEEDED,     "HTBF");	/* HISR bit 30 */
	k7_bind_hisr_bits(dev, 15, K7_HISR_HTB_INT,         "HTB");	/* HISR bit 31 */
}

/*
 * This gets called from main.c
 */
void k7_free_irqs (struct k7_dev *dev)
{
	int i;

	del_timer_sync(&dev->pf2vf_timer);
	k7_disable_all_irqs(dev);
	if (dev->num_vectors) {
		/* Unbind interrupt handler from each vector */
		for (i = 0; i < dev->num_vectors; ++i) {
			if (dev->irq_bound[i]) {
				dev->irq_bound[i] = false;
				free_irq(dev->irqs[i].vector, dev);
			}
		}
		dev->num_vectors = 0;
	}
	switch (dev->irqtype) {
		case K7_IRQTYPE_MSIX:
			PCI_DISABLE_MSIX(dev->pdev);
			break;
		case K7_IRQTYPE_MSI:
			PCI_DISABLE_MSI(dev->pdev);
			break;
		case K7_IRQTYPE_PIN:
		default:
			break;
	}
	dev->irqtype = K7_IRQTYPE_PIN;
}

static int k7_request_irqs (struct k7_dev *dev)
{
	static const char *irqtypes[] = {"IRQ", "MSI", "MSI-X"};
	int i, err, htb_int;

	/* Bind interrupt handler to each vector that was allocated */
	for (i = 0; i < dev->num_vectors; ++i) {
		if (!K7_USE_HTB_BF && dev->hisr_bits[i] == K7_HISR_HTB_BF)
			continue;
		htb_int = (dev->hisr_bits[i] == K7_HISR_HTB_INT);
		err = request_threaded_irq(dev->irqs[i].vector, NULL,
				htb_int ? k7_htb_irq_thread : k7_generic_irq_thread,
				IRQF_ONESHOT, dev->irq_names[i], dev);
		if (err) {
			k7_free_irqs(dev);
			kderr(dev->name, "request_threaded_irq() failed, err=%d", err);
			return err;
		}
		dev->irq_bound[i] = true;
	}
	kdebug(dev->name, "allocated %d %s vector%s",
			dev->num_vectors, irqtypes[dev->irqtype],
			dev->num_vectors > 1 ? "s" : "");
	return 0;
}

static int k7_alloc_msix_irqs (struct k7_dev *dev, int nvec)
{
	k7_disable_all_irqs(dev);
	do {
		if (nvec < 2)
			k7_prep_for_1_msix_vector(dev);
		else if (nvec < 4)
			k7_prep_for_2_msix_vectors(dev);
		else if (nvec < 8)
			k7_prep_for_4_msix_vectors(dev);
		else if (nvec < 16)
			k7_prep_for_8_msix_vectors(dev);
		else
			k7_prep_for_16_msix_vectors(dev);
		PCI_DISABLE_MSIX(dev->pdev);  /* otherwise pci_enable_msix() may complain */
		nvec = k7_pci_enable_msix(dev);
	} while (nvec > 0);

	if (nvec) {
		kderr(dev->name, "pci_enable_msix() failed, err=%d", nvec);
		dev->num_vectors = 0;
		return nvec;
	}
	return 0;	/* success */
}

/*
 * This gets called from main.c to set up interrupt handling.
 *
 * We first try MSI-X in the 16, 8, 4, 2, and then 1 vector configurations.
 * Failing all of those, we try MSI in the 2 and 1 vector configurations.
 */
int k7_alloc_irqs (struct k7_dev *dev, int num_irqs)
{
	int err;

	if (dev->num_vectors)
		k7_free_irqs(dev);
	if (dev->is_pf) {
		unsigned long flags;
		SPIN_LOCK_IRQSAVE(&dev->pf2vf_lock, flags);
		k7_pf_mbx_handler(dev, 0);
		SPIN_UNLOCK_IRQRESTORE(&dev->pf2vf_lock, flags);
	}

	dev->hier = K7_READ32(K7_HIER);

	/* Try MSI-X first */
	if (num_irqs && k7_alloc_msix_irqs(dev, num_irqs) == 0) {
		dev->irqtype = K7_IRQTYPE_MSIX;
	} else {
		/* Try regular MSI: these update dev->pdev->irq on success: */
		if (num_irqs > 1 && PCI_ENABLE_MSI_EXACT(dev->pdev, 2) == 0) {
			k7_prep_for_2_msi_vectors(dev);
			dev->irqtype = K7_IRQTYPE_MSI;
		} else {
			PCI_DISABLE_MSI(dev->pdev);
			if (pci_enable_msi(dev->pdev) == 0) {
				k7_prep_for_1_msi_vector(dev);
				dev->irqtype = K7_IRQTYPE_MSI;
			} else {
				PCI_DISABLE_MSI(dev->pdev);
				kderr(dev->name, "pci_enable_msi() failed");
				kerr(dev->name, "failed to setup irqs");
				return -EIO;
			}
		}
	}
	/* Bind interrupt handler to each allocated vector */
	err = k7_request_irqs(dev);
	if (dev->irqtype == K7_IRQTYPE_MSI) {
		/*
		 * Workaround for DD1 HW229255:
		 *
		 * Root cause of this problem is that interrupt controllers are not reset when a
		 * FW host reset or PF FLR is requested. As the DMA logic gets reset, HTB TC
		 * register goes to zero which triggers an HTB full interrupt and an MSI is sent.
		 * Since sim code never reads HISR, interrupt controller stops sending MSIs to
		 * avoid flooding the host. After reset is removed, normal operation resumes and
		 * HTB done interrupt bit gets set but since HISR was never read, interrupt
		 * controller does not send an MSI.
		 */
		K7_READ32(K7_HISR);
	}
	return err;
}
