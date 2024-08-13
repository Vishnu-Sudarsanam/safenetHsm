/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * main.c
 *
 * Host driver for K7 cards.
 *
 * 2013/05/14: MSI-X vectors vs HOST_RESET:
 * The MSI/MSI-X vectors do NOT survive HOST_RESET.
 * They need to be freed prior to doing a reset,
 * and then reacquired again after the reset.
 *
 * 2013/05/22: VF_MAX_HRB_LEN register:
 * 1. Is actually a 64-bit register (spec says 32-bits).
 * 2. All bits can be written/read, but only bits 4:23 matter.
 *
 * 2013/05/28: HIER not effective with MSI-X:
 * Nihad mentioned this in chat: interrupt masking with HIER may not work
 * when using MSI-X vectors.  Disable the MSI-X vector instead.
 *
 * 2013/09/20: when restarting a DMA channel after recoverable error, chip resumes with current TCP
 *  immediately after DMA is (re-)enabled.  And chip then wants REFETCH instead of FETCH afterward.
 *
 * 2014/04/04:
 * Can deadlock the entire board beyond recovery
 * if accessing the mailbox register at same time
 * as MCPU is accessing anything in 0xCC08_xxxx (eg. LEM1).
 * So the MCPU reset code must use the mailbox interrupt
 * instead of accessing those registers itself.
 *
 * 2014/04/04:
 * When VF locks up, it cannot read the DMA debug registers (not available).
 * But it could message to the PF (PF2VF mailbox) to get the PF to read/return regs.
 *
 * 2014/04/07:
 * MMIO space quirks/restrictions:
 *	-- Most of MMIO is big-endian.
 *	-- 0x9xxx is all PCIe CPE stuff, equivalent to 0xcc08xxxx on MCPU.
 *	-- 0x9000-0x97ff is a mirror of PCIe config space,
 *	    therefore little-endian, and requires 4-byte accesses.
 *	-- 0x9800-ox9fff holds other CPE registers,
 *	    is big-endian, and requires 4-byte/8-byte accesses.
 *
 * 2014/05/02:
 * Interrupt delivery issue: (workaround in PORSM c052: 1-second delay on reset, but still need polling!).
 * During tamper interrupt testing, which sends an interrupt to each function simultaneously,
 * it was discovered that MSI maxes out at four interrupts (vf0,vf1,vf2,vf3), and other PCI
 * functions including the PF do not receive the interrupt.
 * Similarly, MSI-X maxes out at eight interrupts.
 * In all cases, the HISR does show the (lost) interrupt bits though,
 * so it could be possible to work around this issue with a failsafe timer/thread
 * that polls the HISR after a reasonable period of inactivity (no IRQs on the function).
 * This issue likely applies to any situation where the chip sends 4 MSI or 8 MSI-X interrupts
 * to the host (any functions) in very quick succession, so a polling workaround will always be necessary.
 *
 * 2014/05/14: HW288860
 * Chip has an issue where bytecount < 8 in final DT of HRB chain will
 * trigger a DMA error.  The workaround is to fill in the supposedly
 * ignored HRB_LENGTH field in the final DT with 0xffff8 (-1).
 * See workaround in the req.c file.
 * When bug happens, it looks like this:
 *	k7vf13: RECOV_DMA_ERR interrupt, RD_CH=H2SKA
 *	k7vf13: k7vf13: SKU HDERR-1: 1052f000 { RD_CH_ID=H2SKA WR_CH_ID=(nil) RD_HRB RD_DT_BC RD_DT_EOC }
 *	k7vf13: SKU: k7_channel_failure: DMA error
 * Nihad says "No reset is needed. I know that's your normal operation
 *             but in this case you really just have to enable the channel
 *             and update TCP.  No actual data is ever fetched."
 */

#include "headers.h"
#include "proc.h"

/*
 * Module parameter: k7_num_irqs:
 *	0 means use a single MSI interrupt.
 *	1 means try to use a single MSI-X interrupt.
 *	2,4,8,16 means try to use that number of MSI-X interrupts.
 * There is no way to force use of two MSI interrupts; Linux doesn't support it regardless.
 */
static int k7_num_irqs = 4;
module_param(k7_num_irqs, int, 0444);
MODULE_PARM_DESC(k7_num_irqs, "Number of MSI/MSI-X vectors; 0 selects one MSI vector, 1,4,8,16 selects MSI-X");

/*
 * Module parameter: k7_num_vf:
 *	Number of virtual functions (up to 16) to create per physical function.
 */
int k7_num_vf = 0;
module_param(k7_num_vf, int, 0444);
MODULE_PARM_DESC(k7_num_vf, "Number of Virtual Functions per Physical Function (0..16)");

/*
 * Module parameter: k7_debug:
 *	1 == Trace important events to kernel log.
 *	2 == Trace more stuff.
 *	3 == Trace even more stuff.
 *	4 == Trace a lot more stuff.
 */
int k7_debug = 0;
module_param(k7_debug, int, 0644);
MODULE_PARM_DESC(k7_debug, "Debug level (0..5)");

/*
 * Module parameter: k7_cbdebug:
 *	1 == Trace callback activity to kernel log.
 */
int k7_cbdebug = 0;
module_param(k7_cbdebug, int, 0644);
MODULE_PARM_DESC(k7_cbdebug, "Debug level (0..1)");

/*
 * Module parameter: k7_zeromem:
 *	1 == always zero buffers before/after use for easier debugging.
 *	0 == don't zero buffers on alloc/free unless necessary.
 */
int k7_zeromem = 0;
module_param(k7_zeromem, int, 0644);
MODULE_PARM_DESC(k7_zeromem, "zero memory buffers");

/*
 * Module parameter: k7_dump_failed:
 *	0 == no.
 *	1 == dump DTCs for HRB/HRA on failure.
 */
int k7_dump_failed = 0;
module_param(k7_dump_failed, int, 0644);
MODULE_PARM_DESC(k7_dump_failed, "Dump failed HRB/HRA on error (0==no, 1==yes)");

/*
 * Module parameter: k7_traceio:
 *	1 == Trace all register reads/writes to kernel log.
 */
int k7_traceio = 0;
module_param(k7_traceio, int, 0644);
MODULE_PARM_DESC(k7_traceio, "1=log all register reads/writes");

/*
 * Module parameter: k7_notify_rx:
 *	1 == Request hardware ACKs ("NOTIFY_RX") for each/every DT sent from Host.
 */
int k7_notify_rx = 0;
module_param(k7_notify_rx, int, 0444);
MODULE_PARM_DESC(k7_notify_rx, "1=turn on NOTIFY_RX|RMRI bits in outbound DTs");

/*
 * Module parameter: k7_autoboot:
 *	1 == Boot the firmware.
 */
int k7_autoboot = 1;
module_param(k7_autoboot, int, 0444);
MODULE_PARM_DESC(k7_autoboot, "1=Boot the firmware");

/*
 * Module parameter: k7_procfs:
 *	0 == no /proc/k7/ heirarchy.
 *	1 == create /proc/k7/ heirarchy for debug purposes.
 */
int k7_procfs = 0;
module_param(k7_procfs, int, 0444);
MODULE_PARM_DESC(k7_procfs, "0=off; 1=create /proc/k7/ heirarchy for debug purposes");

#define K7_MCPU_INTERNAL_HRB_LIMIT 64
/*
 * Module parameter: k7_mcpu_hrb_limit:
 *	0 == no limits.
 *	Otherwise, specifies max number of HRBs allowed in-flight for MCPU.
 *	To be able to abort commands, at least one empty "slot" in the MCPU HRB FIFO is needed.
 */
int k7_mcpu_hrb_limit = K7_MCPU_INTERNAL_HRB_LIMIT - 1;  /* one slot reserved for fast abort HRB */
module_param(k7_mcpu_hrb_limit, int, 0444);
MODULE_PARM_DESC(k7_mcpu_hrb_limit, "0=no_limit");

/*
 * Module parameter: k7_rootonly_reset:
 *	0 == allow any user with access permissions to perform device resets and similar actions.
 *	1 == only users with CAP_SYS_ADMIN (eg. "root") can perform device resets and similar actions.
 */
int k7_rootonly_reset = 0;
module_param(k7_rootonly_reset, int, 0644);
MODULE_PARM_DESC(k7_rootonly_reset, "1=allow only superuser to perform card resets");

/*
 * Module parameter: k7_dump_icd_inbuf:
 *	0 == off.
 *	1 == dump raw inbuf of ICD commands to syslog.
 */
int k7_dump_icd_inbuf = 0;
module_param(k7_dump_icd_inbuf, int, 0644);
MODULE_PARM_DESC(k7_dump_icd_inbuf, "1=dump raw inbuf of ICD commands to syslog");

/* Minor number & naming controls */
K7_DECLARE_SPINLOCK(k7_global_lock);
static struct k7_dev	*k7_minors[K7_MAX_MINORS] = {NULL,};

/* These are initialized in k7_init() at module load time */
static struct class	*k7_class;	/* from class_create() */
static dev_t		k7_chrdev;	/* from alloc_chrdev_region() */
static int		k7_major;	/* extracted from k7_chrdev */

static int k7_start_irqs (struct k7_dev *dev);
static void k7_start_dma (struct k7_dev *dev);
static void k7_stop_dma (struct k7_dev *dev);

unsigned long k7_lock_global (void)
{
	unsigned long flags;

	SPIN_LOCK_IRQSAVE(&k7_global_lock, flags);
	return flags;
}

void k7_unlock_global (unsigned long flags)
{
	SPIN_UNLOCK_IRQRESTORE(&k7_global_lock, flags);
}

static const char * k7_target_name (int target)
{
	switch (target) {
	case K7_DMA_TARGET_MCPU:	return "MCPU";
	case K7_DMA_TARGET_PKU:		return "PKU";
	case K7_DMA_TARGET_SKU:		return "SKU";
	default:			return "???";
	}
}

/*
 * Dump memory contents in hex.
 */
void k7_dumpmem (struct k7_dev *clog_dev, const char *name, const char *prefix,
		const char *msg, const void *addr, dma_addr_t dma_addr, int len)
{
	const unsigned char *data = addr;
	unsigned char hex[54], ascii[17], odata[16];
	unsigned int offset, count = 0, skipping = 0;

	if (!prefix)
		prefix = "";
	if (clog_dev)
		k7_clog(clog_dev, name, "%s%s: (%p) %016llx:%04x", prefix, msg, addr, (u64)dma_addr, len);
	else
		kinfo(name, "%s%s: (%p) %016llx:%04x", prefix, msg, addr, (u64)dma_addr, len);
	for (offset = 0; offset < len; ) {
		unsigned int mod16 = offset % 16;
		unsigned char c;
		if (mod16 == 0) {
			count = sprintf(hex, "%04x:", offset);
			if ((len - offset) > 16) {
				if (offset && 0 == memcmp(odata, data + offset, 16)) {
					if (!skipping) {
						skipping = 1;
						if (clog_dev)
							k7_clog(clog_dev, name, "%s%s: ....", prefix, msg);
						else
							kinfo(name, "%s%s: ....", prefix, msg);
					}
					offset += 16;
					continue;
				}
				skipping = 0;
				memcpy(odata, data + offset, 16);
			}
		}
		c = data[offset];
		count += sprintf(hex + count, " %02x", c);
		ascii[mod16] = (c >= ' ' && c < 0x7f) ? c : '.';
		if (++offset == len || mod16 == 15) {
			ascii[mod16 + 1] = '\0';
			if (clog_dev)
				k7_clog(clog_dev, name, "%s%s: %-53s", prefix, msg, hex);  /* no ascii */
			else
				kinfo(name, "%s%s: %-53s %s", prefix, msg, hex, ascii);
		}
	}
}

static void k7_clear_busylist (struct k7_channel *channel)
{
	unsigned int index = 1;  /* "0" is for the failed request; all others count from "1" */

	SPIN_LOCK_REQUIRED(&channel->dev->lock);
	kdebug(channel->name, "");
	channel->enabled = 0;
	while (!list_empty(&channel->busylist)) {
		struct k7_req *req = list_first_entry(&channel->busylist, struct k7_req, list);
		kdebug(channel->name, "req=%p hra=%016llx", req, req->hra_daddr);
		/* Mark the requests's busylist position, for with k7_dump_failed */
		req->busylist_index = index;
		/* Don't allow index to wrap around beyond the capacity of busylist_index */
		if (index < ((1 << (8 * sizeof(req->busylist_index))) - 1))
			++index;
		if (k7_remove_req_from_busylist(channel, req))
			k7_complete_req(channel, req, K7_REQ_IOERROR, 1);
	}
}

static void k7_dev_disable_channels (struct k7_dev *dev)
{
	unsigned int target;

	dev->icd_enabled = 0;
	K7_FOREACH_DMA_TARGET(target) {
		struct k7_channel *channel = &dev->channels[target];
		channel->enabled = 0;
	}
}

/*
 * Caller must hold dev->lock
 */
void k7_dev_failure_locked (struct k7_dev *dev, const char *name, const char *reason)
{
	/*
	 * DMA communications are now out of whack due to a soft failure.
	 * We need a reset to recover.
	 */
	SPIN_LOCK_REQUIRED(&dev->lock);
	if (name && reason && !dev->alarm_count)
		kdalarm(dev, "ALM0016: Device Error");
	dev->failed = 1;
	k7_poll_pcie_link_failed(dev);  /* Do this AFTER setting dev->failed=1 */
	k7_keycache_wake_all(dev);
	if (name && reason)
		kderr(dev->name, "%s: %s", name, reason);
	k7_stop_dma(dev);  /* undoes all DMA mappings, clears busylists */
}

void k7_dev_failure (struct k7_dev *dev, const char *name, const char *reason)
{
	SPIN_LOCK(&dev->lock);
	k7_dev_failure_locked(dev, name, reason);
	SPIN_UNLOCK(&dev->lock);
}

static void k7_sleep_one_tick (void)
{
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(1);
}

static void k7_free_channel_eocs (struct k7_dev *dev)
{
	unsigned int target;

	K7_FOREACH_DMA_TARGET(target) {
		struct k7_channel *channel = &dev->channels[target];
		k7_free_channel_eoc(channel);
	}
}

static unsigned int k7_round_up_to_power_of_2 (unsigned int val)
{
	unsigned int rounded = 32;
	while (rounded < val)
		rounded *= 2;
	return rounded;
}

static void k7_free_dma_descriptors (struct k7_dev *dev)
{
	if (dev->htb_area.vaddr)
		k7_mem_free(dev, &dev->htb_area);
	if (dev->dt_areas) {
		struct k7_mem *mem;
		k7_free_all_dt_databufs(dev);
		for (mem = dev->dt_areas; mem->vaddr; ++mem) {
			k7_mem_free(dev, mem);
		}
		kfree(dev->dt_areas);
		dev->dt_areas = NULL;
	}
}

static int k7_alloc_dma_descriptors (struct k7_dev *dev, unsigned int wanted)
{
	struct k7_mem		*dt_area  = NULL, *hwdt_area   = NULL;
	unsigned int		dt_offset = 0,    hwdt_offset = 0;
	const unsigned int	area_size = PAGE_SIZE;
	unsigned int		per_area, num_areas, area_count = 0, dt_count;
	unsigned int		b512_gap;

	unsigned int dt_stride   = k7_round_up_to_power_of_2(sizeof(struct k7_dt));
	unsigned int hwdt_stride = sizeof(struct k7_hwdt);
	/*
	 * First, figure out how many "areas" we will be allocating,
	 * so that we can first allocate a table to keep track of them all.
	 *
	 * The k7_hwdt struct is not permitted to cross 512-byte boundaries
	 * (hardware restriction). So the math here is somewhat messy:
	 */
	per_area  = (area_size / 512) * (512 / hwdt_stride);
	num_areas = (wanted + (per_area - 1)) / per_area;  /* rounding up */
	/*
	 * For regular k7_dt structs, this is a simpler calculation:
	 */
	per_area   = area_size / dt_stride;
	num_areas += (wanted + (per_area - 1)) / per_area;  /* rounding up */

	/*
	 * Allocate a table for keeping track of subsequent "area" allocations,
	 * so they can later be freed on device/module removal.
	 */
	num_areas += 1;	 /* one extra, so list is always zero-terminated when later freeing */
	dev->dt_areas = kzalloc(num_areas * sizeof(struct k7_mem), GFP_KERNEL);
	if (!dev->dt_areas) {
		kerr(dev->name, "kzalloc(%u) failed, wanted=%u", num_areas * sizeof(struct k7_mem), wanted);
		return -ENOMEM;
	}

	/*
	 * Now allocate large areas and assign memory from them to the much smaller dt/hwdt structures.
	 */
	for (dt_count = 0; dt_count < wanted; ++dt_count) {
		struct k7_dt	*dt;
		if (!dt_area) {
			if (area_count == num_areas)
				goto miscalculated;
			dt_area = &dev->dt_areas[area_count++];
			k7_mem_zalloc(dev, dt_area, area_size, K7_MEM_PG_CACHED);  /* s/w only: cacheable */
			dt_offset = 0;
		}
		if (!hwdt_area) {
			if (area_count == num_areas)
				goto miscalculated;
			hwdt_area = &dev->dt_areas[area_count++];
			k7_mem_zalloc(dev, hwdt_area, area_size, K7_MEM_PG_NONCACHED);  /* s/w + h/w: non-cacheable */
			hwdt_offset = 0;
		}
		if (!dt_area->vaddr || !hwdt_area->vaddr) {
			kerr(dev->name, "FAILED at dt_count=%u/%u", dt_count, wanted);
			return -ENOMEM;
		}

		/*
		 * Now build up a dt/hwdt from the available areas and add it to our internal free list.
		 */
		dt        = dt_area->vaddr   + dt_offset;
		dt->hwdt  = hwdt_area->vaddr + hwdt_offset;
		dt->daddr = hwdt_area->daddr + hwdt_offset;
		if (K7_PERMANENT_DATABUFS) {
			k7_mem_zalloc(dev, &dt->data, K7_MAX_BYTES_PER_DT, K7_MEM_DATABUF);
			if (!dt->data.vaddr) {
				kerr(dev->name, "FAILED(data), returning dt_count=%u", dt_count);
				return -ENOMEM;
			}
		}
		k7_put_dt(dev, dt);

		/* Adjust dt_offset */
		dt_offset += dt_stride;
		if ((dt_offset + dt_stride) > area_size)
			dt_area = NULL;

		/* Adjust hwdt_offset, ensuring next hwdt doesn't cross a 512-byte boundary */
		hwdt_offset += hwdt_stride;
		b512_gap = 512 - (hwdt_offset % 512);
		if (b512_gap && b512_gap < hwdt_stride)
			hwdt_offset += b512_gap;
		if ((hwdt_offset + hwdt_stride) > area_size)
			hwdt_area = NULL;
	}
	/*
	 * We also need memory for the HTB:
	 */
	k7_mem_zalloc(dev, &dev->htb_area, K7_HTB_SIZE, K7_MEM_PG_NONCACHED);
	if (!dev->htb_area.vaddr) {
		kerr(dev->name, "DMA HTB-area alloc failure");
		return -ENOMEM;
	}
	return 0;
miscalculated:
	kerr(dev->name, "FAILED, dt_count=%u/%u area_size=%u num_areas=%u area_count=%u stride=%u/%u",
		dt_count, wanted, area_size, num_areas, area_count, dt_stride, hwdt_stride);
	return -ENOMEM;
}

u64 k7_read_m2h_mbx (struct k7_dev *dev)
{
	u64 mbx;

	SPIN_LOCK_REQUIRED(&dev->lock);
	mbx = K7_READ64(K7_M2H_MBX);
	dev->last_m2h_mbx = mbx;
	return mbx;
}

static int k7_wait_for_reset_complete (struct k7_dev *dev)
{
	if (!dev->is_pf) {
		kerr(dev->name, "Huh? this function is for PF only");
		return -EINVAL;
	}
	/* Wait for M2H mailbox interrupt signalling that MCPU is alive */
	wait_event_interruptible_timeout(dev->reset_wq, dev->mcpu_reset_completed, K7_RESET_TIMEOUT_SECS * HZ);
	if (!dev->mcpu_reset_completed) {
		kderr(dev->name, "timed out, last_m2h_mbx=0x%016llx", dev->last_m2h_mbx);
		return -ETIMEDOUT;
	}
	return 0;
}

static int k7_wait_for_mmio_okay (struct k7_dev *dev)
{
	u64 test_pattern = 0x0000000012345678ull;
	unsigned long started = jiffies;
	unsigned long timeout = started + (HZ * 3 / 4);
	do {
		K7_WRITE64(K7_PF2VF_MBX, test_pattern);
		mb();
		if (K7_READ64(K7_PF2VF_MBX) == test_pattern) {
			kdebug(dev->name, "mmio okay after %lu jiffies", jiffies - started);
			return 0;
		}
	} while (time_before(jiffies, timeout));
	kderr(dev->name, "mmio timed out");
	return -EIO;
}

static void k7_tell_mcpu_to_reset_itself (struct k7_dev *dev)
{
	u64 hcsr;
	unsigned long failsafe = jiffies + (2 * HZ);

	kdebug(dev->name, "writing mbx");
	K7_WRITE64(K7_H2M_MBX, cpu_to_be64(K7_MCPU_RESET_CODE));
	do {
		hcsr = K7_READ64(K7_HCSR);
		if ((hcsr & K7_HCSR_H2M_EMPTY)) {
			kdebug(dev->name, "mbx now empty");
			msleep(100);  /* Allow time for MCPU to handle the message */
			return;
		}
	} while (time_before(jiffies, failsafe));
	kwarn(dev->name, "timed-out");
}

/*
 * Resets everything except the PCIe interface.
 */
static int k7_host_reset (struct k7_dev *dev)
{
	int err;

	kdfinfo(dev->name, "");
	if (!dev->is_pf) {
		kerr(dev->name, "called from VF??");
		err = -EINVAL;
	} else {
		k7_tell_mcpu_to_reset_itself(dev);
		pci_disable_sriov(dev->pdev);
		SPIN_LOCK_IRQ(&dev->lock);
		dev->pcie_link_poll_enabled = 0;
		k7_modify32(dev, K7_HRCSR, 0, K7_HRCSR_HOST_RESET);	/* reset everything except PCIe interface */
		k7_modify32(dev, K7_HBMCR, K7_HBMCR_ARB_SINGLE_STEP, 0);
		dev->icd_enabled = 0;  /* Stop accepting new requests during the reset */
		dev->hsm_state = 0;  /* So we can detect when it changes back to something expected */
		dev->last_m2h_mbx = 0;
		dev->mcpu_reset_completed = 0;
		K7_CLEAR_SET_ERR_INJECT(&dev->err);
		wmb();
		SPIN_UNLOCK_IRQ(&dev->lock);
		msleep(20);
		k7_modify32(dev, K7_HRCSR, K7_HRCSR_HOST_RESET, 0);	/* clear the reset bit */
		if (k7_wait_for_mmio_okay(dev)) /* ~500msec for older uboot, ~1msec for newer uboot */
			err = -EIO;
		else
			err = 0;
		dev->pcie_link_poll_enabled = 1;
	}
	return err;
}

/* Wait for PF2VF mailbox IRQ to obtain minor/vfid from PF */
static int k7_get_vf_minor_from_pf (struct k7_dev *dev)
{
	unsigned long timeout = jiffies + (10 * HZ);

	if (dev->is_pf)
		return -EINVAL;
	if (dev->minor != -1)
		return 0;  /* already have it from before */

	/* The protocol used here requires retries to manage VF "collisions" */
	do {
		unsigned long flags;
		/* Attempt to send an "identify me" request to PF */
		kdebug(dev->name, "writing mbx=0x%016llx", 0);
		K7_WRITE64(K7_PF2VF_MBX, 0);
		k7_sleep_one_tick();
		SPIN_LOCK_IRQSAVE(&dev->pf2vf_lock, flags);
		k7_poll_hisr(dev, K7_HISR_PF2VF_MBX);
		SPIN_UNLOCK_IRQRESTORE(&dev->pf2vf_lock, flags);
		if (dev->minor != -1)
			return 0;
	} while (time_before(jiffies, timeout));
	kderr(dev->name, "timed-out waiting for PF2VF");
	return -ETIMEDOUT;
}

static void k7_set_vf_dma_enables (struct k7_dev *dev)
{
	u64 enables, e16;

	/* enable all channels for all configured VFs */
	e16 = (0xffff << (16 - dev->num_vf)) & 0xffff;
	enables = e16 << 32;	/* H2SK */
	if (0) enables |= e16 << 48;	/* H2MM */
	k7_write64(dev, K7_VF_DMA_MASTER_EN, enables);

	/* Give all functions strictly equal round-robin priorities */
	k7_modify64(dev, K7_H2SKA_DMA_VF_ARB_CRD, 0xffffffffc0000000ull, 0x5555555540000000ull);

	/* Set max HRB length */
	k7_write64(dev, K7_VF_MAX_HRB_LEN, ((u64)(dev->max_hrb_len)) << 40);
}

static void k7_enable_sriov (struct k7_dev *dev)
{
	int err;

	dev->num_vf = (k7_num_vf > 7 && !dev->ari_enabled) ? 7 : k7_num_vf;
	k7_set_vf_dma_enables(dev);
	if (dev->num_vf) {
		err = pci_enable_sriov(dev->pdev, dev->num_vf);
		if (err) {
			kderr(dev->name, "pci_enable_sriov(%d) failed, err=%d", dev->num_vf, err);
			dev->num_vf = 0;
			k7_set_vf_dma_enables(dev);
		}
	}
}

/*
 * PCIe Function-Level-Reset (FLR)
 */
static int k7_flr_reset_pdev (struct k7_dev *dev, struct pci_dev *pdev)
{
	u16 control;
	int pos = pci_pcie_cap(pdev);

	kdfinfo(dev->name, "");
	if (!pos) {
		kerr(dev->name, "pci_pcie_cap() failed");
		return -ENOTTY;
	}
	pci_read_config_word(pdev,  pos + PCI_EXP_DEVCTL, &control);
	control |= PCI_EXP_DEVCTL_BCR_FLR;
	dev->hsm_state = 0;  /* So we can detect when it changes back to something expected */
	dev->last_m2h_mbx = 0;
	pci_write_config_word(pdev, pos + PCI_EXP_DEVCTL, control);
	msleep(20);
	return 0;
}

void k7_restore_pci_state (struct k7_dev *dev)
{
	struct pci_dev *pdev = dev->pdev;

	if (dev->pci_saved_state) {
		kdebug(dev->name, "doing pci_load_saved_state");
		PCI_LOAD_SAVED_STATE(pdev, dev->pci_saved_state);
		pci_restore_state(pdev);  /* originally saved in k7_probe() */
	} else {
		kdebug(dev->name, "doing pci_{restore,save}_state");
		pci_restore_state(pdev);  /* originally saved in k7_probe() */
		pci_save_state(pdev);     /* restore() wipes it, so save again now */
	}
}

/*
 * Device reset: either HOST_RESET or FLR:
 */
static int k7_dev_reset (struct k7_dev *dev, int do_host_reset)
{
	struct pci_dev *pdev = dev->pdev;
	int err;

	kdebug(dev->name, "");
	if (!k7_device_trylock(&pdev->dev))  {
		kerr(dev->name, "device already locked");
		err = -EINVAL;
	} else {
		k7_restore_pci_state(dev);
		if (dev->is_pf)
			pci_disable_sriov(dev->pdev);
		if (dev->is_pf && do_host_reset)
			err = k7_host_reset(dev);
		else
			err = k7_flr_reset_pdev(dev, pdev);
		k7_restore_pci_state(dev);
		k7_device_unlock(&pdev->dev);
	}
	kdebug(dev->name, "exit, err=%d", err);
	return err;
}

static int k7_wait_for_active_count_zero (struct k7_dev *dev)
{
	unsigned long timeout = jiffies + (3 * HZ);
	int busy;

	/* Wait for all outstanding requests to complete */
	do {
		unsigned int target;
		k7_sleep_one_tick();
		SPIN_LOCK(&dev->lock);
		busy = 0;
		K7_FOREACH_DMA_TARGET(target) {
			struct k7_channel *channel = &dev->channels[target];
			if (channel->active_count) {
				busy++;
				break;
			}
		}
		SPIN_UNLOCK(&dev->lock);
	} while (busy && time_before(jiffies, timeout));
	return busy;
}

static void k7_stop_busylist_timers (struct k7_dev *dev)
{
	unsigned int target;

	K7_FOREACH_DMA_TARGET(target) {
		struct k7_channel *channel = &dev->channels[target];
		del_timer_sync(&channel->busylist_timer);
		cancel_work_sync(&channel->work);
	}
}

static void k7_pci_disable_device (struct k7_dev *dev);
static int k7_init_device_from_scratch (struct k7_dev *dev);

static int k7_shutdown_for_reset_or_remove (struct k7_dev *dev)
{
	int busy;

	SPIN_LOCK(&dev->lock);
	if (dev->reset_ioctl_in_progress) {
		busy = 1;
	} else {
		dev->reset_ioctl_in_progress = 1;
		dev->failed = 1;	/* prevent new requests from being submitted */
		k7_dev_disable_channels(dev);
		busy = 0;
	}
	SPIN_UNLOCK(&dev->lock);
	if (busy)
		return -EBUSY;  /* only one caller permitted at a time */

	/* Give time for outstanding requests to complete gracefully */
	k7eth_deinit(dev);
	if (k7_wait_for_active_count_zero(dev))
		kderr(dev->name, "still busy, forcing reset now.");
	else
		kdinfo(dev->name, "device stopped");
	k7_dev_failure(dev, NULL, NULL);
	k7_stop_busylist_timers(dev);
	k7_free_irqs(dev);
	return 0;
}

static int k7_ioctl_flr_reset (struct k7_dev *dev, unsigned int cmd)
{
	int err;

	if (k7_rootonly_reset && !capable(CAP_SYS_ADMIN))
		return -EPERM;
	err = k7_shutdown_for_reset_or_remove(dev);
	if (err)
		return err;
	kdfinfo(dev->name, "initiating %s RESET", (cmd == K7_HOST_RESET) ? "HOST" : "FLR");
	/*
	 * At this point, all DMA mappings must have been undone,
	 * because the kernel will clear them as part of device reset,
	 * causing a subsequent Ooops if we then try to clear them ourselves.
	 */
	err = k7_dev_reset(dev, cmd == K7_HOST_RESET);
	if (!err) {
		err = k7_start_irqs(dev);
		if (!err) {
			k7_start_dma(dev);  /* on PF, this re-probes each VF */
			if (dev->is_pf)
				err = k7_wait_for_reset_complete(dev);
			if (!err)
				err = k7_wait_for_hsm_ready(dev, K7_HSM_READY_TIMEOUT_SECS);
		}
	}
	k7eth_init(dev);
	kdfinfo(dev->name, "completed %s RESET", (cmd == K7_HOST_RESET) ? "HOST" : "FLR");
	dev->reset_ioctl_in_progress = 0;
	return err;
}

static void k7_trigger_channel_refetch (struct k7_channel *channel)
{
	struct k7_dev *dev = channel->dev;
	u32 bit;

	SPIN_LOCK_REQUIRED(&dev->lock);
	kdebug2(channel->name, "");
	switch (channel->target) {
		case K7_DMA_TARGET_MCPU:	bit = K7_HCR_RF_H2M_DT; break;
		case K7_DMA_TARGET_PKU:		bit = K7_HCR_RF_PK_DT;  break;
		case K7_DMA_TARGET_SKU:		bit = K7_HCR_RF_SK_DT;  break;
		default:
			kerr(channel->name, "BUG");
			return;
	}
	K7_WRITE32(K7_HCR, bit);
}

static void k7_trigger_channel_fetch (struct k7_channel *channel)
{
	struct k7_dev *dev = channel->dev;
	u32 bit;

	SPIN_LOCK_REQUIRED(&dev->lock);
	kdebug2(channel->name, "");
	switch (channel->target) {
		case K7_DMA_TARGET_MCPU:	bit = K7_HCR_F_H2M_DT; break;
		case K7_DMA_TARGET_PKU:		bit = K7_HCR_F_PK_DT;  break;
		case K7_DMA_TARGET_SKU:		bit = K7_HCR_F_SK_DT;  break;
		default:
			kerr(channel->name, "BUG");
			return;
	}
	K7_FLUSH32(K7_HCR, bit);
}

static u32 k7_hbmcr_sriov_enable_bits (struct k7_channel *channel)
{
	unsigned int target = channel->target;

	switch (target) {
		case K7_DMA_TARGET_MCPU:	return K7_HBMCR_H2M_SRIOV_ON;
		case K7_DMA_TARGET_PKU:		return K7_HBMCR_H2PK_SRIOV_ON;
		case K7_DMA_TARGET_SKU:		return K7_HBMCR_H2SK_SRIOV_ON;
		default:
			kerr(channel->name, "BUG: target=%u", target);
			return 0;
	}
}

static u32 k7_hbmcr_dma_enable_bits (struct k7_channel *channel)
{
	unsigned int target = channel->target;
	u32 bits;

	switch (target) {
		case K7_DMA_TARGET_MCPU:	bits = K7_HBMCR_M2H_BMEN  | K7_HBMCR_H2M_BMEN;  break;
		case K7_DMA_TARGET_PKU:		bits = K7_HBMCR_PK2H_BMEN | K7_HBMCR_H2PK_BMEN; break;
		case K7_DMA_TARGET_SKU:		bits = K7_HBMCR_SK2H_BMEN | K7_HBMCR_H2SK_BMEN; break;
		default:
			kerr(channel->name, "BUG: target=%u", target);
			return 0;
	}
	if (channel->dev->num_vf)
		bits |= K7_HBMCR_RD_CH_INT_EN;
	return bits;
}

static int k7_dma_is_ready (struct k7_channel *channel)
{
	struct k7_dev *dev = channel->dev;
	unsigned int target = channel->target;
	u64 bit, hbmsr;

	switch (target) {
		case K7_DMA_TARGET_MCPU:	bit = K7_HBMSR_H2M_TCPR;  break;
		case K7_DMA_TARGET_PKU:		bit = K7_HBMSR_H2PK_TCPR; break;
		case K7_DMA_TARGET_SKU:		bit = K7_HBMSR_H2SK_TCPR; break;
		default:
			kerr(channel->name, "BUG: target=%u", target);
			return 0;
	}

	hbmsr = K7_READ64(K7_HBMSR);
	if (k7_debug > 1)
		k7_dumpreg(dev, NULL, hbmsr, k7_hbmsr_regbits);
	kdebug2(channel->name, "hbmsr=0x%llx bit=0x%llx result=%d", hbmsr, bit, (hbmsr & bit) ? 1 : 0);
	if (hbmsr == ~0ull)
		return 0;	/* dead, definitely not ready! */
	return (hbmsr & bit) ? 1 : 0;
}

void k7_reinit_dma_channel (struct k7_channel *channel, k7_was_reset_t was_reset)
{
	struct k7_dev *dev = channel->dev;

	kdebug(channel->name, "enabled=%d", channel->enabled);
	SPIN_LOCK_REQUIRED(&dev->lock);
	kdebug2(channel->name, "");
	k7_modify32(dev, K7_HBMCR, 0, k7_hbmcr_dma_enable_bits(channel) | K7_HBMCR_HTB_BMEN);
	if (channel->dev->num_vf)
		k7_modify32(dev, K7_HBMCR, 0, k7_hbmcr_sriov_enable_bits(channel));
	channel->hderr_count = 0;
	channel->enabled     = 0;
	if (was_reset == K7_WAS_RESET)
		channel->did_fetch = 0;
}

static void k7_clear_busylists_locked (struct k7_dev *dev)
{
	unsigned int target;

	k7_cb_reinit_for_reset(dev, 1);
	/* Disable all DMA channels */
	K7_FOREACH_DMA_TARGET(target) {
		struct k7_channel *channel = &dev->channels[target];
	        k7_clear_busylist(channel);
	}
}

static void k7_keycache_reset_worker (struct work_struct *work)
{
	struct k7_dev *dev = container_of(work, struct k7_dev, keycache_reset_work);

	k7_keycache_reset(dev, 0);
}

void k7_reinit_mcpu_channel_after_reset (struct k7_dev *dev)
{
	struct k7_channel *mcpu = &dev->channels[K7_DMA_TARGET_MCPU];

	SPIN_LOCK_REQUIRED(&dev->lock);
	dev->icd_enabled     = 0;
	if (dev->is_pf)
		dev->mcpu_protocol_level = 0;
	mcpu->enabled        = 0;
	mcpu->mrb_size   [1] = mcpu->mrb_size   [0] = 0;
	mcpu->mrb_offset [1] = mcpu->mrb_offset [0] = 0;
	k7_clear_busylists_locked(dev);
	schedule_work(&dev->keycache_reset_work);  /* dev->lock precludes direct call of k7_keycache_reset() here */
	k7_reinit_dma_channel(mcpu, K7_WAS_RESET);
	mcpu->enabled = 1;
}

static void k7_reinit_channels (struct k7_dev *dev)
{
	unsigned int  target;

	SPIN_LOCK(&dev->lock);
	K7_FOREACH_DMA_TARGET(target) {
		struct k7_channel *channel = &dev->channels[target];
		sprintf(channel->name, "%s: %s", dev->name, k7_target_name(target));
		if (channel->target != K7_DMA_TARGET_MCPU)
			k7_reinit_dma_channel(channel, K7_WAS_RESET);
	}
	SPIN_UNLOCK(&dev->lock);
}

static int k7_wait_on_dma_ready (struct k7_channel *channel, unsigned int max_msecs, int wanted_state)
{
	const int loop_delay = 125;	/* micro-seconds per iteration */
	int max_loops = max_msecs * (1000 / loop_delay);

	while (k7_dma_is_ready(channel) != wanted_state) {
		if (!max_loops--)
			return -ETIMEDOUT;
		udelay(loop_delay);
	}
	return 0;
}

static void k7_disable_dma_channel (struct k7_channel *channel)
{
	struct k7_dev *dev = channel->dev;
	int err;

	SPIN_LOCK_REQUIRED(&dev->lock);
	kdebug2(channel->name, "");
	k7_modify32(dev, K7_HBMCR, k7_hbmcr_dma_enable_bits(channel), 0);
	err = k7_wait_on_dma_ready(channel, 500 /*msecs*/, 0 /*notready*/);

	if (err)
		kderr(channel->name, "DMA channel still Ready after stopping??");
	K7_WRITE64(channel->base + K7_H2X_TCP, 0);  /* Null out the hwdt list head in hardware */
}

static void k7_disable_channels (struct k7_dev *dev)
{
	unsigned int target;

	SPIN_LOCK_REQUIRED(&dev->lock);
	K7_FOREACH_DMA_TARGET(target) {
		struct k7_channel *channel = &dev->channels[target];
		k7_disable_dma_channel(channel);
	}
}

static void k7_send_initial_dtc (struct k7_channel *channel, u64 daddr)
{
	struct k7_dev *dev = channel->dev;
	int err;

	SPIN_LOCK_REQUIRED(&dev->lock);
	kdebug(channel->name, "setting TCP=0x%llx", daddr);
	K7_FLUSH64(channel->base + K7_H2X_TCP, daddr);
	k7_reinit_dma_channel(channel, K7_NOT_RESET);
	channel->enabled = 1;

	err = k7_wait_on_dma_ready(channel, 500 /*msecs*/, 1 /*ready*/);
	if (err)
		kderr(channel->name, "DMA channel not ready");
	/*
	 * The only time we do a pure "fetch" is on a freshly-reset channel.
	 * After k7_recover_channel(), did_fetch==1 is still true here,
	 * so do a re-fetch instead.
	 */
	if (channel->did_fetch)
		k7_trigger_channel_refetch(channel);
	else
		k7_trigger_channel_fetch(channel);
	channel->did_fetch = 1;
}

/*
 * datamax says how much of the associated data buffers (total over all DTs) to dump out.
 * A value of 0 says "don't dump any data", and -1 means "dump all of the data".
 */
void k7_dump_dtc (struct k7_dev *clog_dev, const char *name, const char *prefix, struct list_head *dtc, int datamax)
{
	struct k7_dt *dt;
	void *first = NULL;
	int count = 0;

	if (clog_dev)
		k7_clog(clog_dev, name, "%s-dtc: %p", prefix, dtc);
	else
		kinfo(name, "%s-dtc: %p", prefix, dtc);
	if (!list_empty(dtc)) {
		list_for_each_entry(dt, dtc, list) {
			char msg[16];
			if (!first) {
				first = dt;
			} else if (dt == first) {
				kerr(name, "DT list wrapped unexpectedly, aborting.");
				break;
			}
			sprintf(msg, "-dt%02u", count++);
			k7_dumpmem(clog_dev, name, prefix, msg, dt->hwdt, dt->daddr, sizeof(struct k7_hwdt));
			if (datamax && dt->data.vaddr) {
				unsigned int len = dt->data.len;
				if (datamax != -1 && len > datamax)
					len = datamax;
				if (len < dt->data.len) {
					if (clog_dev)
						k7_clog(clog_dev, name, "%s-data: dumping %u/%u bytes", prefix, len, dt->data.len);
					else
						kinfo(name, "%s-data: dumping %u/%u bytes", prefix, len, dt->data.len);
				}
				k7_dumpmem(clog_dev, name, prefix, "-data", dt->data.vaddr, dt->data.daddr, len);
				if (datamax != -1) {
					datamax -= len;
					if (datamax == 0 && dt->list.next != first) {
						if (clog_dev)
							k7_clog(clog_dev, name, "remaining DTs skipped.");
						else
							kinfo(name, name, "remaining DTs skipped.");
						break;
					}
				}
			}
			if (count > 256) {
				if (clog_dev)
					k7_clog(clog_dev, name, "too many DTs in chain, aborting.");
				else
					kinfo(name, "too many DTs in chain, aborting.");
				break;
			}
		}
	}
}

void k7_clog_dump_dtc (struct k7_channel *channel, const char *prefix, struct list_head *dtc, int datamax)
{
	/* Point beyond the dev->name prefix inside channel->name (to save space in CLOG buffer) */
	const char *label = strchr(channel->name, ':');
	label = label ? label + 2 : channel->name;

	if (datamax == -1 || datamax > 1024)
		datamax = 1024;
	k7_dump_dtc(channel->dev, label, prefix, dtc, datamax);
}

static int k7_increment_active_count (struct k7_channel *channel)
{
	struct k7_dev *dev = channel->dev;
	int ch_enabled;

	SPIN_LOCK(&dev->lock);
	ch_enabled = k7_error_injection ? 1 : channel->enabled;
	if (ch_enabled)
		channel->active_count++;
	SPIN_UNLOCK(&dev->lock);
	return ch_enabled;
}

static void k7_decrement_active_count (struct k7_channel *channel)
{
	struct k7_dev *dev = channel->dev;

	SPIN_LOCK(&dev->lock);
	if (channel->active_count-- <= 0) {
		kderr(channel->name, "active_count=%d ??", channel->active_count);
		channel->active_count = 0;
	}
	SPIN_UNLOCK(&dev->lock);
}

void k7_minimal_dump_busylist (struct k7_channel *channel)
{
	struct k7_req *req;
	unsigned int index = 0;

	SPIN_LOCK_REQUIRED(&channel->dev->lock);
	if (list_empty(&channel->busylist))
		kwarn(channel->name, "huh? busylist was empty");
	else
		list_for_each_entry(req, &channel->busylist, list) {
			char busyname[16];
			snprintf(busyname, sizeof(busyname), "busyHRB-%u%s", index, req->prepadded ? "+" : "");
			k7_dump_dtc(NULL, channel->name, busyname, &req->hrb_dtc, 64);
			if (req->prepadded) {
				snprintf(busyname, sizeof(busyname), "busyHRB-%u", index);
				k7_dump_dtc(NULL, channel->name, busyname, &req->original_hrb, 64);
			}
			/* Avoid flooding logs with more than three requests */
			if (++index > 2)
				break;
		}
}

static void k7_busylist_expiry_worker (struct work_struct *work)
{
	struct k7_channel *channel = container_of(work, struct k7_channel, work);
	struct k7_dev     *dev     = channel->dev;

	SPIN_LOCK(&dev->lock);
	if (channel->busylist_timer_armed) {
		channel->busylist_timer_armed = 0;
		kderr(channel->name, "");
		if (k7_debug)
			k7_minimal_dump_busylist(channel);
		if (!list_empty(&channel->busylist)) {
			struct k7_req *req = list_first_entry(&channel->busylist, struct k7_req, list);
			if (!dev->alarm_count)
				kdalarm(dev, "ALM0017: Request Timed Out");
			if (k7_remove_req_from_busylist(channel, req))
				k7_complete_req(channel, req, K7_REQ_TIMEDOUT, 1);
			k7_dev_failure_locked(dev, channel->name, "timeout");
		}
	}
	SPIN_UNLOCK(&dev->lock);
}

static void k7_busylist_timer_expiry (K7_KERNEL_TIMER_ARG_T arg)
{
	void *timer_p = (struct timer_list *)arg;
	struct k7_channel *channel = container_of(timer_p, struct k7_channel, busylist_timer);

	schedule_work(&channel->work);
}

void k7_restart_busylist_timer (struct k7_channel *channel)
{
	struct k7_req *req;
	SPIN_LOCK_REQUIRED(&channel->dev->lock);

	req = list_first_entry_or_null(&channel->busylist, struct k7_req, list);
	if (!req || !req->timeout || (channel->dev->failed && !k7_error_injection)) {
		channel->busylist_timer_armed = 0;
		del_timer(&channel->busylist_timer);
	} else {
		channel->busylist_timer_armed = 1;
		mod_timer(&channel->busylist_timer, jiffies + req->timeout);
	}
}

static void k7_pcie_link_poll_worker (struct work_struct *work)
{
	struct k7_dev *dev = container_of(work, struct k7_dev, pcie_link_poll_work.work);

	if (dev->pcie_link_poll_enabled) {
		SPIN_LOCK(&dev->lock);
		k7_poll_pcie_link_failed(dev);
		SPIN_UNLOCK(&dev->lock);
	}
	schedule_delayed_work(&dev->pcie_link_poll_work, K7_PCIE_LINK_POLL_SECS * HZ);
}

static int k7_check_ready (struct k7_channel *channel, struct k7_req *req)
{
	if (channel->enabled || k7_error_injection) {
		if (channel->target != K7_DMA_TARGET_MCPU)
			return 1;  /* ready */
		if (channel->dev->icd_enabled)
			return 1;
		switch (K7_REQ_HRB_TYPE(req)) {
			case K7_HRB_TYPE_DEFAULT:
				return 1;
			case K7_HRB_TYPE_ICD_CMD:
			case K7_HRB_TYPE_CB_ENABLE:
			case K7_HRB_TYPE_CB_DISABLE:
			case K7_HRB_TYPE_CB_REPLY:
				break;  /* not ready */
			case K7_HRB_TYPE_ETHERNET:
				if (channel->dev->hsm_state >= K7_HSM_STATE_DMA_READY)
					return 1;
				break;  /* not ready */
			default:
				return 1;  /* ready */
		}
	}
	kdebug(channel->name, "enabled=%d icd_enabled=%d flags=0x%08x hrb_type=%u",
		channel->enabled, channel->dev->icd_enabled, req->ioc->flags, K7_REQ_HRB_TYPE(req));
	return 0;  /* not ready */
}

/*
 * This code is the innermost "hot path".
 */
int k7_submit_req (struct k7_channel *channel, struct k7_req *req)
{
	struct k7_dev	*dev = channel->dev;
	struct k7_dt	*old_eoc, *new_eoc;
	struct k7_hwdt	*old_eoc_hwdt;
	u64		hrb_daddr;
	int		list_was_empty;

	SPIN_LOCK_REQUIRED(&dev->lock);
	if (!k7_check_ready(channel, req))
		return -ECONNREFUSED;
	kdebug(channel->name, "submitting %p", req);
	if (req->ioc->flags & K7_DMA_FLAG_FTE_RELOAD)
		dev->last_m2h_mbx = 0;  /* Possibly racy, but good enough */
	new_eoc     = list_tail_entry(&req->hrb_dtc, struct k7_dt, list);
	hrb_daddr   = list_first_entry(&req->hrb_dtc, struct k7_dt, list)->daddr;
	req->status = K7_REQ_SUBMITTED;
	list_was_empty = list_empty(&channel->busylist);
	list_add_tail(&req->list, &channel->busylist);
	wmb();  /* Ensure it is on busylist before linking into DT chain */
	if (list_was_empty)
		k7_restart_busylist_timer(channel);
	old_eoc      = channel->eoc;
	channel->eoc = new_eoc;

	if (old_eoc) {
		req->prev_eoc = old_eoc;
		old_eoc_hwdt  = old_eoc->hwdt;
		old_eoc_hwdt->next_daddr = cpu_to_be64(hrb_daddr);
		wmb();  /* necessary */
		old_eoc_hwdt->control &= ~cpu_to_be64(K7_DT_EOC);
		wmb();  /* necessary */
		k7_trigger_channel_refetch(channel);
	} else {
		wmb();  /* necessary */
		k7_send_initial_dtc(channel, hrb_daddr);
	}
	return 0;
}

int k7_dma_map_req (struct k7_dev *dev, struct k7_req *req)
{
	if (k7_dma_map_dtc(dev, &req->hrb_dtc, DMA_TO_DEVICE) == 0) {
		if (k7_dma_map_dtc(dev, &req->hra_dtc, DMA_FROM_DEVICE) == 0) {
			req->mapped = 1;
			return 0;  /* Success */
		}
		k7_dma_unmap_dtc(dev, &req->hrb_dtc, DMA_TO_DEVICE);
	}
	return -ENOMEM;  /* upper layer will retry -ENOMEM for us */
}

void k7_dma_unmap_req (struct k7_dev *dev, struct k7_req *req)
{
	if (req->mapped) {
		req->mapped = 0;
		k7_dma_unmap_dtc(dev, &req->hrb_dtc, DMA_TO_DEVICE);
		k7_dma_unmap_dtc(dev, &req->hra_dtc, DMA_FROM_DEVICE);
	}
}

/*
 * There are (at least) two ways to pre-pad an HRB:
 *  (1) we can pre-pend a completely separate HRB, or
 *  (2) we can pre-pad the current HRB with a duplicate hrb header.
 *
 * Here, we try the second method, which appears to be slightly simpler,
 * because it does not introduce a second DMA footer (appended by hardware).
 */
int k7_insert_hrb_prepadding (struct k7_channel *channel, struct k7_req *req, unsigned int prepadding)
{
	struct list_head	dtc;
	struct k7_dt		*new_first_dt, *new_last_dt, *old_first_dt;
	u64			*new_hdr, *old_hdr;
	int			err;

	/* Allocate DT chain and buffers for the padding */
	INIT_LIST_HEAD(&dtc);
	err = k7_alloc_dtc(channel, &dtc, prepadding, DMA_TO_DEVICE);
	if (err)
		return err;

	/* Clear end-of-request flags from the new dtc */
	new_last_dt = list_tail_entry(&dtc, struct k7_dt, list);
	new_last_dt->hwdt->control &= ~cpu_to_be64(K7_DT_NOTIFY_RX | K7_DT_RMRI | K7_DT_EOC);

	req->original_hrb = req->hrb_dtc;
	req->prepadded = 1;

	/* Fill in the new HRB header */
	old_first_dt = list_first_entry(&req->hrb_dtc, struct k7_dt, list);
	new_first_dt = list_first_entry(&dtc, struct k7_dt, list);
	old_hdr      = old_first_dt->data.vaddr;
	new_hdr      = new_first_dt->data.vaddr;
	new_hdr[0]   = old_hdr[0];
	new_hdr[1]   = old_hdr[1];
	new_hdr[3]   = cpu_to_be64(prepadding); /* pass the amount of prepadding to MCPU */
	new_hdr[2]   = cpu_to_be64(((u64)K7_HRB_TYPE_PREPADDING) << 32);

	/* Append original hrb_dtc to the new dtc */
	new_last_dt->hwdt->next_daddr = cpu_to_be64(old_first_dt->daddr);
	list_splice(&dtc, &req->hrb_dtc);

	kdebug1(channel->name, "hrb_len(%u) + prepadding(%u) = new hrb_len(%u)",
			req->hrb_len, prepadding, req->hrb_len + prepadding);
	req->hrb_len += prepadding;
	k7_set_hrb_len(new_first_dt, req->hrb_len);
	return 0;
}

/*
 * This driver tracks RXBUF usage for the MCPU internal-DMA side.
 * Note that this can only work if using separate MRBs for VFs,
 * rather than a single combined MRB pair for all functions,
 * as selected by the MCPU DMA driver.
 *
 * The hardware requires hrb_len >= 0x20 (Hardware Spec, section 3.5.2.2).
 * This means 8-byte DMA hdr, 8-byte sig/HDF word, and at least 16-bytes data,
 * to which the DMA hardware will also append an 8-byte footer at the MRB end.
 * So the mininum we can send across for a complete HRB is 40 bytes.
 *
 * Whenever an HRB ends up split across two RXBUFs in MCPU RAM,
 * it results in complexity when the MCPU tries to parse/handle such requests.
 * Since we are MUCH faster than the MCPU, it might be worth taking extra
 * cycles here to save the MCPU for pure crypto processing.
 *
 * When an HRB would otherwise cross an RXBUF boundary, we pad the beginning
 * of it with "prepadding" bytes of dummy data, including a dummy HRB header
 * which informs the MCPU of the prepadding.  This simplifies HRB handling
 * at the (slower) MCPU side.
 *
 * We have also have "post_padding" in req.c, whereby all MCPU requests are
 * padded out such that they end up in MCPU RAM as a multiple of 32-bytes
 * (size of an HRB header), after accounting for the 8-byte footer that is
 * appended by the hardware.  Doing this guarantees that any HRB header
 * (including the dummy padding HRB) will not be split across RXBUFs.
 *
 * If the RXBUF size is not much larger than the max-size, then the overhead is enormous.
 * If we ensure RXBUF is _MUCH_ larger (like, 15-20X) than max-size, it might be fine.
 *
 * Making RXBUF size very large has its own pitfalls, though, in that an RXBUF cannot
 * be recycled until _all_ requests therein have completed.  A very slow keygen could
 * tie up an RXBUF for a very long time --> perhaps the HSM could be "aware" of this,
 * and copy/free the HRB(RXBUF) before launching very long requests for processing.
 *
 * On exit, this function returns "new_offset", which the caller uses
 * to update channel->mrb_offset[mrb_id] after successfully completing submit_req().
 */
static int k7_prepad_hrb_for_mrb_alignment (struct k7_channel *channel, struct k7_req *req, int err_type)
{
	unsigned int mrb_id          = (req->ioc->flags & K7_DMA_FLAG_MRB1) ? 1 : 0;
	unsigned int mrb_offset      = channel->mrb_offset[mrb_id];
	unsigned int hrb_plus_footer = req->hrb_len + K7_HRB_FOOTER_BYTES;
	unsigned int new_offset      = mrb_offset + hrb_plus_footer;
	unsigned int mrb_size        = channel->mrb_size[mrb_id];
	unsigned int prepadding;
	int err;

	if (!mrb_size || new_offset < mrb_size)
		return new_offset;
	if (new_offset == mrb_size)
		return 0;
	if (hrb_plus_footer > mrb_size) {
		if (K7_ERR_TYPE_EQ(err_type, K7EI_EXCEED_MAX_HRB))
			return 0;
		kerr(channel->name, "BUG: packet too large for MCPU: hrb_len=0x%x + footer(8)", req->hrb_len);
		return -EINVAL;
	}
	/*
	 * When we get here, we have determined that the current HRB would span
	 * across two RXBUFs (MRB segments) when transfered to MCPU memory.
	 * To prevent this, We now pre-pad the HRB with a dummy header+data
	 * totalling "prepadding" bytes in size, before the real header+data.
	 * Note that this is all guaranteed to be an even multiple of 32-bytes in size.
	 */
	prepadding = mrb_size - mrb_offset;
	kdebug1(channel->name, "HRB (len=%u) spans RXBUFs: mrb_size=0x%05x, mrb_offset=0x%05x new_offset=0x%05x pre_pad=0x%05x",
		req->hrb_len, mrb_size, mrb_offset, new_offset, prepadding);
	if (err_type) {
		err = k7_do_error_injection_prepadding(channel, req, prepadding, err_type);
		if (err != -ENOMSG)  /* -ENOMSG here indicates "no error-injection here; proceed normally" */
			return err;  /* Returns either "new_offset", or a negative errno value */
	}
	err = k7_insert_hrb_prepadding(channel, req, prepadding);
	if (err)
		return err;
	/*
	 * With prepadding, this HRB is now guaranteed to be placed at offset 0 in an RXBUF,
	 * so the new_offset after transmission is simply the HRB size, plus DMA footer.
	 */
	return hrb_plus_footer;
}

int k7_dma_submit_and_wait (struct k7_dev *dev, struct k7_req *req, struct k7_dma_ioctl *ioc)
{
	struct k7_channel	*channel = &dev->channels[ioc->target];
	int			err = 0, was_submitted = 0;
	int			for_mcpu, err_type, new_mrb_offset = 0;

	/*
	 * "active_count" protects against reset happening under our feet,
	 * which can trigger an Ooops if we managed to create a DMA mapping
	 * before the reset.
	 */
	if (!k7_increment_active_count(channel)) {
		err = -ECONNREFUSED;
		goto done;
	}
	/*
	 * "mcpu_submit_mutex" enables us to calculate/insert HRB prepadding
	 * in an atomic fashion when needed.
	 */
	for_mcpu = (ioc->target == K7_DMA_TARGET_MCPU);
	if (for_mcpu) {
		err = mutex_lock_interruptible(&dev->mcpu_submit_mutex);
		if (err)
			goto done_decr;
		err_type = k7_check_for_error_injection(dev, req, ioc);
		new_mrb_offset = k7_prepad_hrb_for_mrb_alignment(channel, req, err_type);
		if (new_mrb_offset < 0)
			err = new_mrb_offset;
	} else {
		err_type = k7_check_for_error_injection(dev, req, ioc);
	}
	if (!err) {
		if (err_type)
			err = k7_do_error_injection(dev, req, ioc, err_type, &new_mrb_offset);
		else
			err = k7_dma_map_req(dev, req);
		if (!err) {
			if (ioc->flags & K7_DMA_FLAG_CBHRA) {
				err = k7_cb_submit(dev, channel, req);
			} else {
				SPIN_LOCK(&dev->lock);
				err = k7_submit_req(channel, req);
				SPIN_UNLOCK(&dev->lock);
			}
		}
	}
	if (for_mcpu) {
		if (!err) {
			/* Update mrb_offset with retval from k7_prepad_hrb_for_mrb_alignment() */
			unsigned int mrb_id = (ioc->flags & K7_DMA_FLAG_MRB1) ? 1 : 0;
			channel->mrb_offset[mrb_id] = new_mrb_offset;
		}
		mutex_unlock(&dev->mcpu_submit_mutex);
	}
	if (err) {
		k7_dma_unmap_req(dev, req);
	} else {
		err = k7_wait_for_req(channel, req);
		was_submitted = 1;
	}
	if (!err) {
		if (ioc->flags & K7_DMA_FLAG_NO_REPLY) {
			SPIN_LOCK(&dev->stats_lock);
			dev->bytes_sent += req->hrb_len - K7_HRB_HDR_LEN - req->post_padding;
			dev->completed_requests++;
			SPIN_UNLOCK(&dev->stats_lock);
		} else {
			if (ioc->flags & K7_DMA_FLAG_KEK_KEY) {
				/*
				 * To prevent kek_key replies from being handled out of sequence
				 * with respect to key deletions, we handle both of those activities
				 * directly from the HTB interrupt handler.
				 *
				 * The kek_key return value from there gets saved in req->kek_key_ret,
				 * so here we just need to retrieve/return it, nothing else.
				 */
				err = req->kek_key_ret;  /* courtesy of the HTB IRQ handler */
				if (err >= 0) {
					err = k7_fp_return_lkrc(dev, req, req->lkrc, req->raw_key_bytes, req->kk->kek_id);
				}
			} else {
				err = k7_handle_hra(dev, req);
			}
			if (err >= 0) {
				SPIN_LOCK(&dev->stats_lock);
				dev->bytes_received += err & ~K7_DMA_OUTPUT_TRUNCATED;
				dev->completed_requests++;
				dev->bytes_sent += req->hrb_len - K7_HRB_HDR_LEN - req->post_padding;
				SPIN_UNLOCK(&dev->stats_lock);
				if (dev->clog.enabled && !(ioc->flags & K7_DMA_FLAG_NO_REPLY)) {
					unsigned int hdr_len = k7_dma_hra_hdr_len(ioc->target);
					k7_clog_dump_dtc(channel, "HRA", &req->hra_dtc, hdr_len + err);
				}
			}
		}
	}
done_decr:
	k7_decrement_active_count(channel);
done:
	k7_free_req(channel, req, was_submitted);
	return err;
}

int k7_attempt_dma_ioctl (struct k7_dev *dev, struct k7_dma_ioctl *ioc, unsigned int hrb_type)
{
	struct k7_req		*req;
	int			err;
	unsigned int		using_hrb_sem = 0, target = ioc->target;

	if (target == K7_DMA_TARGET_MCPU && k7_mcpu_hrb_limit) {
		if ((ioc->flags & K7_DMA_FLAG_MRB1) == 0 && hrb_type != K7_HRB_TYPE_ABORT_HRA) {
			err = down_interruptible(&dev->mcpu_hrb_sem);
			if (err)
				return err;
			using_hrb_sem = 1;
		}
	}
	err = k7_prepare_req(&dev->channels[target], ioc->inbuf_size, ioc, hrb_type, &req);
	if (!err)  /* Check for non-zero, not just negative; it could be a KEK_KEY bytecount */
		err = k7_dma_submit_and_wait(dev, req, ioc);
	if (using_hrb_sem)
		up(&dev->mcpu_hrb_sem);
	return err;
}

u8 k7_get_random_byte (void)
{
	u8 r;

	get_random_bytes(&r, sizeof(r));
	return r;
}

/*
 * There are a few ways we could be low on resources for an instant,
 * causing an allocation or mapping attempt to temporarily fail.
 * We deal with this (-ENOMEM), by wrapping k7_attempt_dma_ioctl() in a retry loop.
 */
int k7_do_dma_ioctl (struct k7_dev *dev, struct k7_dma_ioctl *ioc, unsigned int hrb_type)
{
	unsigned int retry_delay_msecs = 1;
	int err;

	while (1) {
		err = k7_attempt_dma_ioctl(dev, ioc, hrb_type);
		if (err != -ENOMEM)
			return err;
		if (signal_pending(current))
			return -EINTR;
		if (dev->failed)
			return -ECONNREFUSED;
		/* Give time for resources to become available */
		if (retry_delay_msecs == 1)
			kdebug(dev->name, "temporarily out of resources, retrying");
		msleep(retry_delay_msecs);
		retry_delay_msecs = (k7_get_random_byte() % 64) + 25;
	}
}

static int k7_do_dma_ioctl_precheck (struct k7_dev *dev, struct k7_dma_ioctl *ioc, unsigned int hrb_type)
{
	unsigned int inbuf_size;

	if (!ioc) {
		kerr(dev->name, "bad ioc ptr");
		return -EINVAL;
	}
	switch (ioc->target) {
	case K7_DMA_TARGET_MCPU:
		if (dev->icd_enabled && hrb_type != K7_HRB_TYPE_ICD_CMD && !k7_error_injection) {
			kerr(dev->name, "non-ICD command attempted while HSM is active");
			return -EINVAL;
		}
	case K7_DMA_TARGET_PKU:
	case K7_DMA_TARGET_SKU:
		break;
	default:
		kerr(dev->name, "bad dma target (%u)", ioc->target);
		return -EINVAL;
	}
	if (ioc->flags & ~K7_DMA_FLAG_MASK) {
		kerr(dev->name, "bad flags: 0x%x", ioc->flags);
		return -EINVAL;
	}
	if (!ioc->inbuf) {
		kerr(dev->name, "bad inbuf addr (NULL)");
		return -EINVAL;
	}
	inbuf_size = ioc->inbuf_size;
	/*
	 * This restriction (multiple of 8) is not strictly necessary here,
	 * because we don't DMA directly to/from the user buffers.
	 * But enforcing it here keeps things less bug-prone elsewhere.
	 */
	if (!inbuf_size || (inbuf_size & 7)) {
		kerr(dev->name, "bad inbuf_size=%d", inbuf_size);
		return -EINVAL;
	}
	if (!ioc->outbuf) {
		if (ioc->outbuf_size || !(ioc->flags & K7_DMA_FLAG_NO_REPLY)) {
			kerr(dev->name, "bad outbuf addr (NULL)");
			return -EINVAL;
		}
	} else if (!ioc->outbuf_size) {
		kerr(dev->name, "bad outbuf_size=%d", ioc->outbuf_size);
		return -EINVAL;
	}
	/*
	 * This restriction (multiple of 8) is not strictly necessary here,
	 * because we don't DMA directly to/from the user buffers.
	 * But enforcing it here keeps things less bug-prone elsewhere.
	 */
	if ((ioc->outbuf_size & 7)) {
		kerr(dev->name, "outbuf_size=%d not multiple of 8", ioc->outbuf_size);
		return -EINVAL;
	}
	return 0;
}

static int k7_wait_for_fte_reload (struct k7_dev *dev)
{
	unsigned long timeout = jiffies + (K7_RESET_TIMEOUT_SECS * HZ);

	kdinfo(dev->name, "waiting for FTE_RELOAD");
	while (1) {
		if (dev->last_m2h_mbx == K7_FTE_RESET_DONE) {
			kdinfo(dev->name, "FTE_RELOAD completed");
			return 0;
		}
		if (signal_pending(current))
			return -EINTR;
		if (time_after(jiffies, timeout))
			return -ETIMEDOUT;
		msleep(10);
	}
}

static int k7_ioctl_dma_ioctl (struct k7_dev *dev, void __user *uargp, int compat)
{
	struct k7_dma_ioctl *ioc;
	int err;

	ioc = kmalloc(sizeof(*ioc), GFP_KERNEL);
	if (!ioc)
		return -ENOMEM;
	if (copy_from_user(ioc, uargp, sizeof(*ioc))) {
		err = -EFAULT;
	} else {
		unsigned int hrb_type = (ioc->flags & K7_DMA_FLAG_ICD_CMD) ? K7_HRB_TYPE_ICD_CMD : K7_HRB_TYPE_DEFAULT;
#ifdef CONFIG_COMPAT
		if (compat) {
			ioc->inbuf  = (unsigned long)compat_ptr(ioc->inbuf);
			ioc->outbuf = (unsigned long)compat_ptr(ioc->outbuf);
		}
#endif
		err = k7_do_dma_ioctl_precheck(dev, ioc, hrb_type);
		if (!err) {
			err = k7_do_dma_ioctl(dev, ioc, hrb_type);
			if (err >= 0 && (ioc->flags & K7_DMA_FLAG_FTE_RELOAD))
				err = k7_wait_for_fte_reload(dev);
		}
	}
	kfree(ioc);
	return err;
}

static int k7_ioctl_mbx_write (struct k7_dev *dev, void __user *uargp)
{
	struct k7_mbx_ioctl m;
	int ret;

	if (copy_from_user(&m, uargp, sizeof(m)))
		return -EFAULT;
	if (m.target != K7_DMA_TARGET_MCPU)
		return -EINVAL;
	SPIN_LOCK(&dev->lock);
	/* Avoid clashing over mailbox with the reset code */
	if (dev->reset_ioctl_in_progress) {
		ret = -EBUSY;
	} else if (k7_rootonly_reset && !capable(CAP_SYS_ADMIN) && (be64_to_cpu(m.data) & 0xff) == K7_MCPU_RESET_CODE) {
		ret = -EPERM;
	} else {
		K7_WRITE64(K7_H2M_MBX, m.data);
		ret = 0;
	}
	SPIN_UNLOCK(&dev->lock);
	return ret;
}

static int k7_ioctl_mbx_read (struct k7_dev *dev, void __user *uargp)
{
	struct k7_mbx_ioctl m;
	int ret;

	if (copy_from_user(&m, uargp, sizeof(m)))
		return -EFAULT;
	if (m.target != K7_DMA_TARGET_MCPU)
		return -EINVAL;
	SPIN_LOCK(&dev->lock);
	if (dev->reset_ioctl_in_progress) {
		ret = -EBUSY;
	} else {
		int rx_flag = dev->m2h_mbx_rx_flag;
		if (rx_flag) {
			dev->m2h_mbx_rx_flag = 0;
			m.data = k7_read_m2h_mbx(dev);
			ret = 0;
		} else {
			ret = -ENODATA;
		}
	}
	SPIN_UNLOCK(&dev->lock);
	if (ret == 0 && copy_to_user(uargp, &m, sizeof(m)))
		return -EFAULT;
	return ret;
}

/* Read hcsr and return H2M/M2H mailbox status */
static int k7_ioctl_mbx_status (struct k7_dev *dev, void __user *uargp)
{
	struct k7_mbx_ioctl m;
	int ret;

	if (copy_from_user(&m, uargp, sizeof(m)))
		return -EFAULT;
	if (m.target != K7_DMA_TARGET_MCPU)
		return -EINVAL;
	SPIN_LOCK(&dev->lock);
	/* Avoid clashing over mailbox with the reset code */
	if (dev->reset_ioctl_in_progress) {
		ret = -EBUSY;
	} else {
		u64 hcsr = K7_READ64(K7_HCSR);
		ret = 0;
		if ((hcsr & K7_HCSR_H2M_EMPTY) == 0)
			ret |= K7_H2X_MBX_FULL;
		if ((hcsr & K7_HCSR_M2H_FULL) != 0)
			ret |= K7_X2H_MBX_FULL;
	}
	SPIN_UNLOCK(&dev->lock);
	return ret;
}

static int k7_ioctl_hif_reg_read (struct k7_dev *dev, void __user *uargp, int compat)
{
	struct k7_hif_reg_ioctl ioc;

	if (copy_from_user(&ioc, uargp, sizeof(ioc)))
		return -EFAULT;

	/* Ensure the offset is less than 13 bits long */
	if (ioc.offset > 0xfff)
		return -EINVAL;
#ifdef CONFIG_COMPAT
	if (compat)
		ioc.buf = (unsigned long)compat_ptr((compat_uptr_t)ioc.buf);
#endif
	switch (ioc.len) {
		case sizeof(u32):
		{
			u32 val;
			val = K7_READ32(ioc.offset);
			if (copy_to_user((void *)(unsigned long)ioc.buf, &val, ioc.len))
				return -EFAULT;
			break;
		}
		case sizeof(u64):
		{
			u64 val;
			val = K7_READ64(ioc.offset);
			if (copy_to_user((void *)(unsigned long)ioc.buf, &val, ioc.len))
				return -EFAULT;
			break;
		}
		default:
			return -EINVAL;
	}
	return 0;
}

static int k7_ioctl_tamper_regs_read(struct k7_dev *dev, void __user *uargp)
{
	int err, count;
	void *buf = kzalloc(K7_SM_REG_COUNT, GFP_KERNEL);

	if (!buf)
		return -ENOMEM;
	err = k7_read_sm_regs(dev, buf, 0/*not-locked*/, &count);
	if (!err && copy_to_user(uargp, buf, K7_SM_REG_COUNT))
		err = -EFAULT;
	kfree(buf);
	return err;
}

static int k7_ioctl_return_u32 (struct k7_dev *dev, void __user *uaddr, u32 *kaddr)
{
	if (copy_to_user(uaddr, kaddr, sizeof(u32)))
		return -EFAULT;
	return 0;
}

static int k7_ioctl_return_u32_fail (struct k7_dev *dev, void __user *uargp, u32 *val_p)
{
	return dev->failed ? -EIO : k7_ioctl_return_u32(dev, uargp, val_p);
}

#ifdef K7_DUMP_KEYCACHE
static int k7_dump_keycache_ioctl (struct k7_dev *dev, void __user *uargp, int compat)
{
	struct k7_dump_keycache_parms p;
	void __user *ubuf;
	u8 *kbuf;
	int result;

	if (copy_from_user(&p, uargp, sizeof(p)))
		return -EFAULT;
#ifdef CONFIG_COMPAT
	if (compat)
		p.outbuf = K7_PTR_TO_U64(compat_ptr(p.outbuf));
#endif
	ubuf = (void __user *)(unsigned long)p.outbuf;
	if (!ubuf || p.outbuf_size < 1024 || p.outbuf_size > (4 * 1024 * 1024))
		return -EINVAL;
	kbuf = vmalloc(p.outbuf_size);
	if (!kbuf)
		return -ENOMEM;
	result = k7_do_dump_keycache (dev, kbuf, p.outbuf_size - 1);
	kbuf[result++] = '\0';  /* Zero-terminate the result */
	if (copy_to_user(ubuf, kbuf, result))
		result = -EFAULT;
	vfree(kbuf);
	return result;
}
#endif /* K7_DUMP_KEYCACHE */

static long k7_ioctl (struct file *file, unsigned int cmd, unsigned long arg, int compat)
{
	struct k7_dev		*dev = file->private_data;
	void __user		*uargp = (void __user *)arg;
	int			err;

	switch (cmd) {
	case K7_DMA_FASTPATH:
		err = k7_ioctl_dma_fastpath(dev, uargp, compat);
		break;
	case K7_DMA_IOCTL:
		err = k7_ioctl_dma_ioctl(dev, uargp, compat);
		break;
#ifdef K7EI
	case K7_SET_ERR_INJECT:
		err = k7_ioctl_set_err_inject(dev, uargp, compat);
		break;
#endif
	case K7_MBX_WRITE:
		err = k7_ioctl_mbx_write(dev, uargp);
		break;
	case K7_MBX_READ:
		err = k7_ioctl_mbx_read(dev, uargp);
		break;
	case K7_MBX_STATUS:
		err = k7_ioctl_mbx_status(dev, uargp);
		break;
	case K7_GET_HSM_STATE:
		err = k7_ioctl_return_u32_fail(dev, uargp, &dev->hsm_state);
		break;
	case K7_GET_INSERTION_COUNT:
		err = k7_ioctl_return_u32(dev, uargp, &dev->insertion_count);
		break;
	case K7_GET_PROTOCOL_VERSION:
		err = k7_ioctl_return_u32_fail(dev, uargp, &dev->hsm_protocol_version);
		break;
	case K7_GET_TAMPER_REGS:
		err = k7_ioctl_tamper_regs_read(dev, uargp);
		break;
	case K7_HIF_REG_READ:
		err = k7_ioctl_hif_reg_read(dev, uargp, compat);
		break;
	case K7_HOST_RESET:
		if (!dev->is_pf)
			return -EINVAL;
		/* fall thru */
	case K7_FLR_RESET:
		err = k7_ioctl_flr_reset(dev, cmd);
		break;
	case UHD_IOCTL_RESET_DEVICE:
		err = k7_ioctl_flr_reset(dev, dev->is_pf ? K7_HOST_RESET : K7_FLR_RESET);
		break;
	case K7_SET_AUTOBOOT:
		if (k7_rootonly_reset && !capable(CAP_SYS_ADMIN))
			return -EPERM;
		dev->disable_autoboot = (arg == 0);
		err = 0;
		break;
	case K7_CLOG_READ:
		err = k7_ioctl_log(dev, &dev->clog, uargp, compat);
		break;
	case K7_DLOG_READ:
		err = k7_ioctl_log(dev, &dev->dlog, uargp, compat);
		break;
#ifdef K7_DUMP_KEYCACHE
	case K7_DUMP_KEYCACHE:
		err = k7_dump_keycache_ioctl(dev, uargp, compat);
		break;
#endif
	default:
		err = k7_cb_ioctl(dev, cmd, uargp, compat);
		if (err == -ENOTTY)
			printk_ratelimited(KERN_INFO "%s: %s: %s[%u]: cmd=0x%x uargp=%p",
				dev->name, __func__, current->comm, current->pid, cmd, uargp);
	}
	return err;
}

static long k7_unlocked_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
	return k7_ioctl(file, cmd, arg, 0);
}

#ifdef CONFIG_COMPAT
static long k7_compat_ioctl (struct file *filp, unsigned int cmd, unsigned long arg)
{
	return k7_ioctl(filp, cmd, (unsigned long)compat_ptr(arg), 1);
}
#endif

/*
 * This is for use from /proc/k7, to deal with races on
 * the "dev" pointer that is embedded in the /proc/ entries.
 */
struct k7_dev *k7_get_dev_kref (struct k7_dev *dev)
{
	unsigned long flags;
	unsigned int minor;

	flags = k7_lock_global();
	for (minor = 0; minor < K7_MAX_MINORS; minor++) {
		if (dev == k7_minors[minor]) {
			kref_get(&dev->kref);
			goto done;
		}
	}
	dev = NULL;
done:
	k7_unlock_global(flags);
	return dev;
}

static struct k7_dev *k7_get_dev_from_minor (unsigned int minor)
{
	struct k7_dev *dev;
	unsigned long flags;

	if (minor >= K7_MAX_MINORS)
		return NULL;
	flags = k7_lock_global();
	dev = k7_minors[minor];
	if (dev)
		kref_get(&dev->kref);
	k7_unlock_global(flags);
	return dev;
}

static int k7_open (struct inode *inode, struct file *file)
{
	struct k7_dev *dev;

	dev = k7_get_dev_from_minor(iminor(inode));
	if (!dev)
		return -ENODEV;
	file->private_data = dev;
	kdebug(dev->name, "dev=%p", __func__);
	return 0;
}

static void k7_free_minor (struct k7_dev *dev)
{
	SPIN_LOCK_REQUIRED(&k7_global_lock);
	if (dev->minor != -1) {
		if (dev->minor < K7_MAX_MINORS && k7_minors[dev->minor] == dev)
			k7_minors[dev->minor] = NULL;
		dev->minor = -1;
	}
}

void k7_free_dev (struct kref *kref)
{
	struct k7_dev *dev = container_of(kref, struct k7_dev, kref);
	unsigned long flags;

	kdebug(dev->name, "%s:", __func__);
	k7_mem_free(dev, &dev->special_dt);
	k7_keycache_free(dev);
	k7_free_dma_descriptors(dev);
	flags = k7_lock_global();
	k7_free_minor(dev);
	memset(dev, 0, sizeof(*dev));
	kfree(dev);
	k7_unlock_global(flags);
	/*
	 * Bit of a race here:  the minor number was freed internally in this function (above),
	 * but the kernel's calling function doesn't free it until some time after we return.
	 * So if a hotplug event happens in between here and there, something may get confused.
	 */
}

static int k7_release (struct inode *inode, struct file *file)
{
	struct k7_dev *dev = file->private_data;

	kdebug(dev->name, "%s: %s[%lu]", __func__, current->comm, (long)current->tgid);
	if (dev->cb_pid == current->tgid)
		k7_cb_disable(dev);
	file->private_data = NULL;
	kref_put(&dev->kref, k7_free_dev);
	return 0;
}

int k7_mmap (struct file *file, struct vm_area_struct *vma)
{
	struct k7_dev *dev	= file->private_data;
	unsigned long phys_pfn	= (pci_resource_start(dev->pdev, 0) >> PAGE_SHIFT) + vma->vm_pgoff;
	unsigned long bytecount	= vma->vm_end - vma->vm_start;
	u64 end = (vma->vm_pgoff << PAGE_SHIFT) + bytecount;
	int err;

	if (bytecount % PAGE_SIZE || end > pci_resource_len(dev->pdev, 0)) {
		kerr(dev->name, "bad offset(0x%llx) or bytecount(%lu)", (u64)vma->vm_pgoff, bytecount);
		return -EINVAL;
	}
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_flags |= VM_IO;

	err = io_remap_pfn_range(vma, vma->vm_start, phys_pfn, bytecount, vma->vm_page_prot);
	if (err) {
		kerr(dev->name, "io_remap_pfn_range() failed, err=%d", err);
		return -EAGAIN;
	}
	return 0;
}

static const struct file_operations k7_fops = {
	.open			= k7_open,
	.release		= k7_release,
	.mmap			= k7_mmap,
	.unlocked_ioctl		= k7_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= k7_compat_ioctl,
#endif
};

static int k7_alloc_pf_minor (struct k7_dev *dev)
{
	unsigned long flags;
	int err = -ENOSPC, minor;

	if (!dev->is_pf) {
		kerr(NULL, "called from VF??");
		return -EINVAL;
	}
	flags = k7_lock_global();
	for (minor = 0; minor < K7_MAX_MINORS; minor += K7_MINORS_PER_CARD) {
		struct k7_dev *mdev = k7_minors[minor];
		if (mdev == NULL || mdev == dev) {
			k7_minors[minor] = dev;
			dev->minor = minor;
			sprintf(dev->name, DRV_NAME "pf%u", minor / K7_MINORS_PER_CARD);
			err = 0;
			goto done;
		}
	}
	kerr(NULL, "failed, err=%d", err);
done:
	k7_unlock_global(flags);
	return err;
}

static int k7_alloc_vf_minor (struct k7_dev *dev)
{
	unsigned long flags;
	int err = -ENOSPC;

	if (dev->is_pf || dev->minor == -1) {
		kerr(NULL, "is_pf=%u minor=%d", dev->is_pf, dev->minor);
		return -EINVAL;
	}

	flags = k7_lock_global();
	if (dev->minor >= K7_MAX_MINORS) {
		kerr(NULL, "minor=0x%x (limit=0x%x)", dev->minor, K7_MAX_MINORS - 1);
		err = -EINVAL;
	} else if (k7_minors[dev->minor] && k7_minors[dev->minor] != dev) {
		kerr(NULL, "minor number (0x%x) already assigned", dev->minor);
		err = -ENOSPC;
	} else {
		unsigned int pfid = dev->minor / K7_MINORS_PER_CARD;
		unsigned int vfid = dev->minor % K7_MINORS_PER_CARD;
		if (vfid == 0) {
			kerr(NULL, "is_pf=0 yet minor=0x%u (PF?)", dev->minor);
			err = -EINVAL;
		} else {
			k7_minors[dev->minor] = dev;
			dev->vfid = --vfid | 0x10;
			sprintf(dev->name, DRV_NAME "vf%u", vfid + (pfid * (K7_MINORS_PER_CARD - 1)));
			err = 0;
		}
	}
	k7_unlock_global(flags);
	return err;
}

static int k7_get_vf_minor (struct k7_dev *dev)
{
	int err;

	err = k7_get_vf_minor_from_pf(dev);
	if (!err)
		err = k7_alloc_vf_minor(dev);
	return err;
}

static int k7_set_dma_masks (struct k7_dev *dev)
{
	struct pci_dev	*pdev = dev->pdev;
	u64		dma_mask = DMA_BIT_MASK(64);
	int		err;
	/*
	 * This first mask is for "streaming" DMA: random mappings of kmalloc'd memory.
	 * This is for data buffers, user pages, etc..
	 */
	err = pci_set_dma_mask(pdev, dma_mask);
	if (err) {
		dma_mask = DMA_BIT_MASK(32);
		err = pci_set_dma_mask(pdev, dma_mask);
		if (err) {
			kerr(dev->name, "pci_set_dma_mask() failed, err=%d", err);
			return err;
		}
	}
	/*
	 * This second mask is for "coherent" DMA: non-cacheable RAM from the DMA APIs.
	 * This is normally used for ring-buffers, descriptors, and other device-specific structures.
	 * The mask setting is guaranteed to work at sizes up to that set above,
	 * but we check/handle the return value here regardless.
	 */
	err = pci_set_consistent_dma_mask(pdev, dma_mask);
	if (err) {	/* guaranteed not to fail, but handle it anyway */
		dma_mask = DMA_BIT_MASK(32);
		err = pci_set_consistent_dma_mask(pdev, dma_mask);
		if (err)
			kerr(dev->name, "pci_set_consistent_dma_mask() failed, err=%d", err);
	}
	return err;
}

static int k7_parent_bridge_ari_enabled (struct k7_dev *dev)
{
	struct pci_dev *bridge;
	int pos;
	u32 cap;
	u16 flags, ctrl;

	if (!dev->pdev->bus) {
		kerr(dev->name, "dev->pdev->bus is NULL");
		return -EIO;	/* cannot access bridge capabilities */
	}
	bridge = dev->pdev->bus->self;
	if (!bridge) {
		kerr(dev->name, "dev->pdev->bus->self is NULL");
		return -EIO;	/* cannot access bridge capabilities */
	}

	pos = pci_pcie_cap(bridge);
	if (!pos) {
		kdebug(dev->name, "no PCIe capabilities listed");
		return 0;  /* no PCIe capabilities listed */
	}
	pci_read_config_word(bridge, pos + PCI_EXP_FLAGS, &flags);
	if ((flags & PCI_EXP_FLAGS_VERS) < 2) {
		kdebug(dev->name, "too old for ARI");
		return 0;  /* too old to support ARI */
	}
	pci_read_config_dword(bridge, pos + PCI_EXP_DEVCAP2, &cap);
	if (!(cap & PCI_EXP_DEVCAP2_ARI)) {
		kdebug(dev->name, "not capable of ARI");
		return 0;  /* not capable of ARI */
	}
	pci_read_config_word(bridge, pos + PCI_EXP_DEVCTL2, &ctrl);
	if (!(ctrl & PCI_EXP_DEVCTL2_ARI)) {
		kdebug(dev->name, "ARI is not enabled");
		return 0;  /* ARI not enabled */
	}
	kdebug(dev->name, "ARI is enabled");
	return 1;  /* ARI is enabled */
}

static const char *k7_asic_rev (struct k7_dev *dev)
{
	switch (dev->asic_rev) {
		case 0x10:	return "DD1";
		case 0x20:	return "DD2";
		default:	return "Unknown";
	}
}

static void k7_log_connection_type (struct k7_dev *dev, int ari_enabled)
{
	char *speed = "(?)", width[8], *ari = "";
	int pos, w;
        u16 link_status;

	pos = pci_pcie_cap(dev->pdev);
        if (!pos) {
		strcpy(width, "(?)");
	} else {
		unsigned slot_speed, card_speed;
		if (ari_enabled)
			ari = ", ARI enabled";
		pci_read_config_word(dev->pdev, pos + PCI_EXP_LNKSTA, &link_status);
		slot_speed = link_status & PCI_EXP_LNKSTA_CLS;
		dev->pcie_gen = slot_speed;
                switch (slot_speed) {
                case PCI_EXP_LNKSTA_CLS_2_5GB:
                        speed = "2.5GT/s";
                        break;
                case PCI_EXP_LNKSTA_CLS_5_0GB:
                        speed = "5GT/s";
                        break;
                case PCI_EXP_LNKSTA_CLS_8_0GB:
                        speed = "8GT/s";
                        break;
                default:
                        break;
                }
		card_speed = extract64(K7_READ64(0x9b40), BE64MSK(36,39));  // CPE_PCIE_DLP_TCR
		if (card_speed != slot_speed)
			kderr(dev->name, "Speed reporting ERROR: slot=%u card=%u", slot_speed, card_speed);
                w = (link_status & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;  /* 6-bits */
		if (w && w != (PCI_EXP_LNKSTA_NLW >> PCI_EXP_LNKSTA_NLW_SHIFT))
			sprintf(width, "x%u", w);
		else
			strcpy(width, "(?)");
        }
	kdinfo(dev->name, "PCIe connection speed %s width %s%s asic_rev %s", speed, width, ari, k7_asic_rev(dev));
}

static void k7_pci_disable_device (struct k7_dev *dev)
{
	if (dev->is_pf)
		pci_disable_sriov(dev->pdev);
	k7_free_irqs(dev);
	if (dev->mmio) {
		pci_iounmap(dev->pdev, dev->mmio);
		dev->mmio = NULL;
	}
	pci_release_regions(dev->pdev);
	pci_disable_device(dev->pdev);
}

static int k7_enable_device (struct k7_dev *dev)
{
	struct pci_dev *pdev = dev->pdev;
	int err;

	err = pci_enable_device(pdev);
	if (err) {
		kerr(dev->name, "pci_enable_device() failed, err=%d", err);
		return err;
	}
	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		kerr(dev->name, "pci_request_regions() failed, err=%d", err);
		goto err_exit;
	}
	err = k7_set_dma_masks(dev);
	if (err)
		goto err_exit;

	dev->mmio = pci_iomap(pdev, 0, 0);
	if (!dev->mmio) {
		kerr(dev->name, "pci_iomap(mmio) failed");
		err = -ENOMEM;
		goto err_exit;
	}
	dev->asic_rev = extract64(K7_READ64(K7_HCSR), K7_HCSR_ASIC_REV_ID);
	if (dev->asic_rev == K7_ASIC_REV_DD1) {
		kwarn(dev->name, "ASIC_REV=DD1 not supported");
		err = -ENODEV;
		goto err_exit;
	}
	/*
	 * Some one-time setup for PF only:
	 *
	 * Set FLR auto-timer to the same delay we use with HOST_RESET (20msecs).
	 * And for DD2, turn on the "chicken switches":
	 *   Bit-19: enable logic to prevent lockups when multiple MMIO reads (PF/VFs) collide.
	 *   Bit-18: enables parity checks/errors for DMA to host.
	 *     Any resulting parity errors should be treated as "fatal, replace hardware".
	 */
	if (dev->is_pf) {
		u64 hcfgr1 = K7_READ64(K7_HCFGR1);
		hcfgr1  = insert64(hcfgr1, K7_HCFGR1_PF_FLR_TIMER_VALUE, 20000);  /* 20 msecs */
		hcfgr1 |= K7_HCFGR1_AIB_TXDAT_ERR_EN | K7_HCFGR1_AIB_RXCH_FIX_EN;
		K7_WRITE64(K7_HCFGR1, hcfgr1);
	}

	/* We only need to know about ARI for the PF when it has VFs */
	if (dev->is_pf && k7_num_vf) {
		kdebug(dev->name, "ARI test: is_pf=%d num_vf=%d/%d rev=0x%x",
			dev->is_pf, dev->num_vf, k7_num_vf, dev->asic_rev);
		err = k7_parent_bridge_ari_enabled(dev);
		if (err < 0)
			goto err_exit;
		dev->ari_enabled = err;
		err = 0;
	} else {
		kdebug(dev->name, "ARI test skipped: is_pf=%d num_vf=%d/%d rev=0x%x",
			dev->is_pf, dev->num_vf, k7_num_vf, dev->asic_rev);
	}
	if (dev->is_pf) {
		err = k7_alloc_pf_minor(dev);
		if (err)
			goto err_exit;
		k7_log_connection_type(dev, dev->ari_enabled);
		err = k7_host_reset(dev);
		if (err)
			goto err_exit;
	}
	return 0;

err_exit:
	if (dev->mmio) {
		pci_iounmap(dev->pdev, dev->mmio);
		dev->mmio = NULL;
	}
	k7_pci_disable_device(dev);
	return err;
}

static int k7_init_device_from_scratch (struct k7_dev *dev)
{
	int err = k7_enable_device(dev);
	if (err) {
		kerr(dev->name, "k7_enable_device() failed, err=%d", err);
		return err;
	}
	/*
	 * Ugly:  we need irqs enabled on PF for the M2H mailbox protocol to work,
	 * as well as for the PF2VF minor/vfid exchanges.
	 * Ideally, we would like to also enable irqs for VFs in the same place,
	 * but the problem is we don't yet know the "names" of the VFs,
	 * and our interrupts like to have nice names assigned to them. (ugh, ugh!!).
	 */
	if (dev->is_pf) {
		err = k7_start_irqs(dev);
		if (err)
			return err;
		err = k7_wait_for_reset_complete(dev);
	} else {
		dev->mcpu_reset_completed = 0;
		err = k7_get_vf_minor(dev);
		if (!err) {
			SPIN_LOCK(&dev->lock);
			k7_mcpu_reset_completed(dev);
			SPIN_UNLOCK(&dev->lock);
			err = k7_start_irqs(dev);
		}
	}
	if (err)
		return err;

/*
 * KB: Kernel 5.6.19 online uses pci_cleanup_aer_uncorrect_error_status()
 *     while kernel 5.7.19 uses pci_aer_clear_nonfatal_status().
 *     However, RHEL 8.3+ shows the old kernel version (4.18) but uses
 *     the new API, so we need to check if we are in RHEL as well
*/
#if defined(RHEL_RELEASE_CODE)
#define USE_NEW_PCI_API RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8,3)
#else
#define USE_NEW_PCI_API 0
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0) || USE_NEW_PCI_API
	pci_aer_clear_nonfatal_status(dev->pdev);
#else
	pci_cleanup_aer_uncorrect_error_status(dev->pdev);
#endif

	err = pci_enable_pcie_error_reporting(dev->pdev);
	if (err)
		kwarn(dev->name, "pci_enable_pcie_error_reporting() failed, err=%d", err);
	kdebug(dev->name, "mmio at %p asic_rev %s", dev->mmio, k7_asic_rev(dev));
	k7_start_dma(dev);	/* On PF, this also calls probe() for each VF, one at a time */
	return 0;
}

static int k7_probe (struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct k7_dev *dev;
	int target, err;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		kerr(NULL, "kzalloc(%u) failed", sizeof(*dev));
		return -ENOMEM;
	}
	kref_init(&dev->kref);
	if (k7_keycache_alloc(dev)) {
		kerr(NULL, "k7_alloc_keycache() failed");
		kref_put(&dev->kref, k7_free_dev);
		return -ENOMEM;
	}
	dev->minor = -1;
	dev->pdev = pdev;
	dev->traceio = k7_traceio;
	dev->disable_autoboot = !k7_autoboot;
	pci_set_drvdata(pdev, dev);
	dev->is_pf = (pdev->device == K7_PCI_PF_DEVICE_ID);
	dev->max_hrb_len = K7_MAX_HRB_LEN;
	INIT_LIST_HEAD(&dev->dt_freelist);
	init_waitqueue_head(&dev->reset_wq);
	SPIN_LOCK_INIT(&dev->lock);
	SPIN_LOCK_INIT(&dev->pf2vf_lock);
	SPIN_LOCK_INIT(&dev->dt_freelist_lock);
	SPIN_LOCK_INIT(&dev->stats_lock);
	INIT_DEFERRABLE_WORK(&dev->pcie_link_poll_work, k7_pcie_link_poll_worker);

	sema_init(&dev->mcpu_hrb_sem, k7_mcpu_hrb_limit);
	mutex_init(&dev->htb_mutex);
	mutex_init(&dev->mcpu_submit_mutex);
	INIT_WORK(&dev->keycache_reset_work, k7_keycache_reset_worker);
	k7_timer_setup(&dev->pf2vf_timer, k7_pf2vf_timer_expiry, 0);
	K7_CLEAR_SET_ERR_INJECT(&dev->err);
	k7_cb_init(dev);

	if (dev->is_pf) {
		err = k7_alloc_pf_minor(dev); /* initializes dev->minor, dev->name */
		if (err) {
			kerr(dev->name, "k7_alloc_pf_minor() failed, err=%d", err);
			goto err_out_kfree;
		}
	} else {
		strcpy(dev->name, DRV_NAME "vf");  /* temporary, until k7_enable_device() is run */
	}

	err = k7_log_init(dev);
	if (err)
		goto err_out_kfree;

	K7_FOREACH_DMA_TARGET(target) {
		struct k7_channel *channel = &dev->channels[target];
		channel->dev	= dev;
		channel->base	= k7_dma_base(dev, target);
		channel->target	= target;
		sprintf(channel->name, "%s: %s", dev->name, k7_target_name(target));
		INIT_LIST_HEAD(&channel->busylist);
		SPIN_LOCK_INIT(&channel->dt_done_lock);
		k7_timer_setup(&channel->busylist_timer, k7_busylist_timer_expiry, 0);
		INIT_WORK(&channel->work, k7_busylist_expiry_worker);
	}

	err = k7_alloc_dma_descriptors(dev, K7_NUM_DMA_DESCRIPTORS);
	if (err) {
		kerr(dev->name, "k7_alloc_dma_descriptors(%u) failed, err=%d", K7_NUM_DMA_DESCRIPTORS, err);
		goto err_out_kfree;
	}
	dev->reset_ioctl_in_progress = 1;
	err = k7_init_device_from_scratch(dev);
	if (err)
		goto err_out_kfree;
	dev->reset_ioctl_in_progress = 0;
	dev->cdev = cdev_alloc();
	if (!dev->cdev) {
		kerr(dev->name, "cdev_alloc() failed");
		goto err_out_kfree;
	}
	cdev_init(dev->cdev, &k7_fops);
	dev->cdev->owner = THIS_MODULE;
	dev->devt = MKDEV(k7_major, dev->minor);
	err = cdev_add(dev->cdev, dev->devt, 1);
	if (err) {
		kerr(dev->name, "cdev_add() failed, err=%d", err);
		goto err_out_disable_operations;
	}
	dev->device = device_create(k7_class, &dev->pdev->dev, dev->devt, dev, dev->name);
	if (IS_ERR(dev->device)) {
		err = PTR_ERR(dev->device);
		goto err_out_disable_operations;
	}

	pci_save_state(pdev);  /* Enables recovery from later PCIe link loss */
	dev->pci_saved_state = PCI_STORE_SAVED_STATE(pdev);

	schedule_delayed_work(&dev->pcie_link_poll_work, K7_PCIE_LINK_POLL_SECS * HZ);

	kdebug(dev->name, "registered chrdev %d:%d", k7_major, dev->minor);

	k7_proc_create_dev(dev);  /* don't care about failure for this */
	k7eth_init(dev);

	k7_wait_for_hsm_ready(dev, K7_HSM_READY_TIMEOUT_SECS);  /* ignore result */
	return 0;

err_out_disable_operations:
	k7_disable_all_irqs(dev);
	SPIN_LOCK(&dev->lock);
	k7_disable_channels(dev);
	SPIN_UNLOCK(&dev->lock);
err_out_kfree:
	k7_pci_disable_device(dev);
	if (dev->cdev) {
		cdev_del(dev->cdev);
		dev->cdev = NULL;
	}
	k7_log_deinit(dev);
	pci_set_drvdata(pdev, NULL);
	kref_put(&dev->kref, k7_free_dev);
	return err;
}

/*
 * Prepare / enable use of IRQs on this function.
 */
static int k7_start_irqs (struct k7_dev *dev)
{
	int err;

	kdebug(dev->name, "entry");
	k7_reinit_htb(dev);
	err = k7_alloc_irqs(dev, k7_num_irqs);
	if (!err) {
		kinfo(dev->name, "allocated %d interrupt vectors", dev->num_vectors);
		K7_READ32(K7_HISR);	/* clear leftover IRQ bits (eg. HTB_BF, TAMPER, ..) */
		k7_write_hier(dev, K7_IRQS_ENABLED);	/* unmask interrupts */
		pci_set_master(dev->pdev);
		SPIN_LOCK(&dev->lock);
		k7_poll_hisr(dev, dev->hier);	/* check for pre-existing IRQs, which we'd otherwise miss (edge-triggers!) */
		SPIN_UNLOCK(&dev->lock);
	}
	if (err || k7_debug)
		kerr(dev->name, "exit, err=%d", err);
	return err;
}

/*
 * Prepare / enable use of DMA channels on this function.
 */
static void k7_start_dma (struct k7_dev *dev)
{
	kdebug(dev->name, "entry");
	dev->htb_enabled = 1;
	if (dev->is_pf)
		k7_enable_sriov(dev);	/* must *preceed* k7_reinit_channels() below */
	k7_reinit_channels(dev);
	dev->alarm_count = 0;
	dev->failed = 0;
}

static void k7_stop_dma (struct k7_dev *dev)
{
	SPIN_LOCK_REQUIRED(&dev->lock);
	dev->htb_enabled = 0;
	k7_disable_dma_irqs(dev);
	if (dev->is_pf)
		k7_force_stop_all_dma_immediately(dev);
	k7_disable_channels(dev);
	k7_clear_busylists_locked(dev);
	k7_free_channel_eocs(dev);
}

static void k7_remove (struct pci_dev *pdev)
{
	struct k7_dev *dev = pci_get_drvdata(pdev);
	int err;

	/*
	 * The "virsh nodedev-detach" command can result in k7_remove() being invoked
	 * while the device is still quite active.  This is a major design flaw,
	 * but we have to deal with it here.  Note that remove() functions cannot return errors,
	 * so the system just expects it to always "succeed".  This means that we cannot return
	 * to caller until the device is completely idle and detached.
	 */
	if (!dev) {
		kerr(DRV_NAME, "BUG: no drvdata");
		return;
	}
	kfinfo(dev->name, "detaching chrdev %d:%d", k7_major, dev->minor);

	/* Stop PCIe link monitoring: */
	cancel_delayed_work_sync(&dev->pcie_link_poll_work);
	pci_disable_pcie_error_reporting(pdev);

	/* Remove all possible ways for userspace to open() the device: */
	k7eth_deinit(dev);
	k7_proc_destroy_dev(dev);
	device_destroy(k7_class, dev->devt);
	cdev_del(dev->cdev);
	dev->cdev = NULL;

	/* Wakeup anyone stuck on "logread -t": */
	k7_log_deinit(dev);

	/* Shut down all operations in progress: */
	do {
		cancel_work_sync(&dev->keycache_reset_work);
		err = k7_shutdown_for_reset_or_remove(dev);
		if (err)
			msleep(100);
	} while (err);

	/* Clean up PCI state: */
	if (dev->pci_saved_state) {
		PCI_LOAD_SAVED_STATE(pdev, dev->pci_saved_state);
		kfree(dev->pci_saved_state);
		dev->pci_saved_state = NULL;
	}
	pci_restore_state(pdev);  /* originally saved in k7_probe() */
	k7_pci_disable_device(dev);
	pci_set_drvdata(pdev, NULL);

	/* The actual k7_dev struct won't be freed until after all tasks close() the device: */
	kref_put(&dev->kref, k7_free_dev);
	kdebug(NULL, "exit");
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0))
static pci_ers_result_t k7_pcieh_error_detected (struct pci_dev *pdev, pci_channel_state_t state)
#else
static pci_ers_result_t k7_pcieh_error_detected (struct pci_dev *pdev, enum pci_channel_state state)
#endif
{
	struct k7_dev *dev = pci_get_drvdata(pdev);

	/*
	 * Step 1: Notification, mmio disabled.
	 * Device is dead: driver can cleanup here in preparation
	 * for recovery actions, but DO NOT TOUCH THE DEVICE !!
	 */
	kderr(dev->name, "pcieh_state=%u", state);
	dev->pcieh_state = state;
	return PCI_ERS_RESULT_CAN_RECOVER;  /* do nothing, just progress to next step: k7_pcieh_mmio_enabled() */
}

static pci_ers_result_t k7_pcieh_mmio_enabled (struct pci_dev *pdev)
{
	struct k7_dev *dev = pci_get_drvdata(pdev);
	/*
	 * Step 2: MMIO re-enabled.
	 * "Early Recovery" callback, before external recovery is attempted.
	 * Probably not called if "error_detected" returned "NEED_RESET".
	 *
	 * Driver can access mmio space, but NO DMA.  Try to recover/reset stuff,
	 * and report back whether further action needed or not.
	 */
	switch (dev->pcieh_state) {
	case pci_channel_io_normal:  /* everything is in a normal state */
		k7_dev_failure_locked(dev, __func__, "pci_channel_io_normal (non-fatal error), requesting resume");
		kdinfo(dev->name, "PCIe non-fatal error logged");
		return PCI_ERS_RESULT_RECOVERED;
	case pci_channel_io_frozen:
		k7_dev_failure_locked(dev, __func__, "pci_channel_io_frozen, requesting link_reset");
		return PCI_ERS_RESULT_NEED_RESET;
	case pci_channel_io_perm_failure:  /* permanently dead card */
		k7_dev_failure_locked(dev, __func__, "pci_channel_io_perm_failure, requesting disconnect");
		return PCI_ERS_RESULT_DISCONNECT;
	default:
		k7_dev_failure_locked(dev, __func__, "unknown state, requesting link_reset");
		return PCI_ERS_RESULT_NEED_RESET;
	}
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0))  /* FIXME: update to newer API? */
static pci_ers_result_t k7_pcieh_link_reset (struct pci_dev *pdev)
{
	struct k7_dev *dev = pci_get_drvdata(pdev);
	/*
	 * Step 3: PCIe Link has been reset.
	 *
	 * Driver should check whether device is responding or not.
	 */
	kderr(dev->name, "");
	return PCI_ERS_RESULT_NEED_RESET;
}
#endif

static pci_ers_result_t k7_pcieh_slot_reset (struct pci_dev *pdev)
{
	struct k7_dev *dev = pci_get_drvdata(pdev);
	int err;
	/*
	 * Step 4: Slot has been reset.
	 *
	 * Driver should check whether device is responding or not.
	 * Reinitialize a few things, and report back.
	 */
	kderr(dev->name, "");
	err = k7_init_device_from_scratch(dev); //FIXME
	if (err) {
		kderr(dev->name, "k7_init_device_from_scratch() failed");
		return PCI_ERS_RESULT_DISCONNECT;
	}
	return PCI_ERS_RESULT_RECOVERED;
}

static void k7_pcieh_resume (struct pci_dev *pdev)
{
	struct k7_dev *dev = pci_get_drvdata(pdev);
	/*
	 * Step 5: Device is functional: restart everything, including DMA.
	 */
	kderr(dev->name, "clearing pcieh_state");
	dev->pcieh_state = 0;
}

struct pci_error_handlers k7_pcieh = {
	.error_detected	= k7_pcieh_error_detected,
	.mmio_enabled	= k7_pcieh_mmio_enabled,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0))  /* FIXME: update to newer API? */
	.link_reset	= k7_pcieh_link_reset,
#endif
	.slot_reset	= k7_pcieh_slot_reset,
	.resume		= k7_pcieh_resume,
};

static const struct pci_device_id k7_pci_tbl[] = {
	{ 0xcafe, K7_PCI_PF_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID, 0, 0, },	// K7 physical function (pf)
	{ 0xcafe, 0x2143, PCI_ANY_ID, PCI_ANY_ID, 0, 0, },	// K7 virtual  function (vf) L3
	{ 0xcafe, 0x2144, PCI_ANY_ID, PCI_ANY_ID, 0, 0, },	// K7 virtual  function (vf) L4
	{ }	/* terminate list */
};
MODULE_DEVICE_TABLE(pci, k7_pci_tbl);

static struct pci_driver k7_driver = {
	.name		= DRV_NAME,
	.id_table	= k7_pci_tbl,
	.probe		= k7_probe,
	.remove		= k7_remove,
	.err_handler	= &k7_pcieh,
};

static int __init k7_init (void)
{
	int	err;

	kinfo(NULL, "Loading " DRV_NAME " Host Driver version " DRV_VERSION);

	/* Self-test */
	if (sizeof(struct k7_kek_key) != 64) {
		kerr(NULL, "sizeof(k7_kek_key)=%u, should be 64", sizeof(struct k7_kek_key));
		return -ENOMEM;
	}
	if (sizeof(struct k7_session_group) != PAGE_SIZE) {
		kerr(NULL, "sizeof(k7_session_group)=%u, should be PAGE_SIZE(%u)",
			sizeof(struct k7_session_group), PAGE_SIZE);
		return -ENOMEM;
	}

	/* Clean up module parameters */
	if (k7_num_vf > 16)
		k7_num_vf = 16;
	else if (k7_num_vf < 0)
		k7_num_vf = 0;
	if (k7_num_irqs > 16)
		k7_num_irqs = 16;
	else if (k7_num_irqs < 0)
		k7_num_irqs = 0;

	k7_class = class_create(THIS_MODULE, DRV_NAME);
	if (IS_ERR(k7_class)) {
		err = PTR_ERR(k7_class);
		kerr(NULL, "class_create() failed, err=%d", err);
		return err;
	}
	SPIN_LOCK_INIT(&k7_global_lock);
	err = alloc_chrdev_region(&k7_chrdev, 0, K7_MAX_MINORS, DRV_NAME);
	if (err) {
		kerr(NULL, "alloc_chrdev_region() failed, err=%d", err);
		goto err_out_class_destroy;
	}
	k7_proc_create();
	k7_major = MAJOR(k7_chrdev);
	err = pci_register_driver(&k7_driver);
	if (err) {
		kerr(NULL, "pci_register_driver() failed, err=%d", err);
		goto err_out_unregister_chrdev_region;
	}
	return 0;

err_out_unregister_chrdev_region:
	unregister_chrdev_region(k7_chrdev, K7_MAX_MINORS);
err_out_class_destroy:
	class_destroy(k7_class);
	k7_proc_destroy();
	return err;
}

static void __exit k7_exit(void)
{
	pci_unregister_driver(&k7_driver);
	unregister_chrdev_region(k7_chrdev, K7_MAX_MINORS);
	class_destroy(k7_class);
	k7_proc_destroy();
	kinfo(NULL, "removing driver version " DRV_VERSION);
}

module_init(k7_init);
module_exit(k7_exit);

MODULE_AUTHOR("Thales Group");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(DRV_NAME " PCIe driver");
MODULE_VERSION(DRV_VERSION);
