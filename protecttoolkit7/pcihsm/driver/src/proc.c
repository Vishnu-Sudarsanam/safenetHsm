/*
 * Copyright (c) 2013-2021 Thales Group.  All rights reserved.
 *
 * proc.c
 */
#include "headers.h"
#include "proc.h"

#if defined(K7_HAVE_PROC_FS) || defined(K7_DUMP_KEYCACHE)

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0))
#define kstrtoul(a,b,c) -ENOTSUP
#define kstrtol(a,b,c)  -ENOTSUP
#endif

static const char *kg_status[4] = {"idle", "stop", "actv", "repl"};

static char *fmt_ops (char *buf, u16 ops)
{
	buf[4] = (ops & (1 << OPER_DIGEST )) ? 'G' : '-';
	buf[3] = (ops & (1 << OPER_VERIFY )) ? 'V' : '-';
	buf[2] = (ops & (1 << OPER_SIGN   )) ? 'S' : '-';
	buf[1] = (ops & (1 << OPER_DECRYPT)) ? 'D' : '-';
	buf[0] = (ops & (1 << OPER_ENCRYPT)) ? 'E' : '-';
	buf[5] = '\0';
	return buf;
}
#endif

#ifdef K7_DUMP_KEYCACHE
/*
 * Mimic output/layout of /proc/k7/../keycache for use by the test team.
 */
unsigned int k7_do_dump_keycache (struct k7_dev *dev, u8 *kbuf, unsigned int n)
{
	unsigned int x = 0;
	unsigned int index1, index2;

	x += scnprintf(kbuf+x, n-x, "GP activkek pendgkek minkekid stat kref kyhandle kygenern -kek_id- algorthm K opers vmech imech rsize ksize\n");
	for (index1 = 0; index1 <= dev->keycache_level1_max; ++index1) {
		struct k7_keycache_level2 *level2 = dev->keycache->level2[index1];
		if (!level2)
			continue;
		for (index2 = 0; index2 < K7_KEYCACHE_LEVEL2_WIDTH; ++index2) {
			struct k7_kek_key *kk;
			SPIN_LOCK(&dev->keycache_lock);
			kk = k7_kk_null_if_empty(level2->slot[index2].kk);
			if (kk) {
				u32 key_handle = (index1 * K7_KEYCACHE_LEVEL2_WIDTH) + index2;
				struct k7_kek_group *kg = &dev->kek_group[kk->group_id];
				char buf[8];
				if (!kg) {
					x += scnprintf(kbuf+x, n-x, "-- -------- -------- -------- ----");
				} else {
					x += scnprintf(kbuf+x, n-x, "%2u %08x %08x %08x %4s", kg->group_id, kg->active_kek_id,
							kg->pending_kek_id, kg->minimum_kek_id, kg_status[kg->status & 3]);
				}
				x += scnprintf(kbuf+x, n-x, " %4u %08x %08x %08x %08x %c %s %5u %5u %5u %5u ",
					k7_kref_read(&kk->kref), key_handle, kk->generation,
					kk->kek_id, kk->kek_algorithm, kk->cannot_be_keked ? 'N' : 'Y',
					fmt_ops(buf, kk->valid_ops), kk->valid_mechs, kk->invalid_mechs,
					kk->raw_key_words * (int)sizeof(u64), kk->key_words * (int)sizeof(u64));
				x += scnprintf(kbuf+x, n-x, "\n");
			}
			SPIN_UNLOCK(&dev->keycache_lock);
		}
	}
	return x;
}
#endif /* K7_DUMP_KEYCACHE */

#ifndef K7_HAVE_PROC_FS

#warning "/proc/k7 not enabled for this kernel"

void k7_proc_create_dev (struct k7_dev *dev) {}
void k7_proc_destroy_dev (struct k7_dev *dev) {}
void k7_proc_create (void) {}
void k7_proc_destroy (void) {}

#else

/*
 * Pointer to the top level /proc/k7/ directory
 */
static struct proc_dir_entry *k7_proc_topdir;

static int k7_proc_write_stats (struct k7_proc_desc *d, const char *kbuf)
{
	struct k7_dev *dev = d->dev;

	SPIN_LOCK(&dev->stats_lock);
	dev->completed_requests = 0;
	dev->bytes_sent = 0;
	dev->bytes_received = 0;
	SPIN_UNLOCK(&dev->stats_lock);
	return 0;
}

static int k7_proc_write_htbmask (struct k7_proc_desc *d, const char *kbuf)
{
	struct k7_dev *dev = d->dev;
	int htbmask;
	u32 hier;

	if (0 == strcmp(kbuf, "0"))
		htbmask = 0;
	else if (0 == strcmp(kbuf, "1"))
		htbmask = 1;
	else
		return -EINVAL;
	SPIN_LOCK(&dev->lock);
	hier = dev->hier;
	if (htbmask)
		hier &= ~K7_HISR_HTB_INT;
	else
		hier |= K7_HISR_HTB_INT;
	k7_write_hier(dev, hier);
	SPIN_UNLOCK(&dev->lock);
	return 0;
}

static int k7_proc_write_r32 (struct k7_proc_desc *d, const char *kbuf)
{
	struct k7_dev *dev = d->dev;
	unsigned long val, min = d->min, max = d->max;
	int err = kstrtoul(kbuf, 0, &val);

	if (err)
		return err;
	if ((min != max) && (val < min || val > max))
		return -ERANGE;
	K7_WRITE32((unsigned long)(d->val_p), val);
	return 0;
}

static int k7_proc_write_din (struct k7_proc_desc *d, const char *kbuf)
{
	struct k7_dev *dev = d->dev;
	unsigned long val, min = d->min, max = d->max;
	int err = kstrtoul(kbuf, 0, &val);

	if (err)
		return err;
	if ((min != max) && (val < min || val > max))
		return -ERANGE;
	K7_WRITE32((unsigned long)(d->val_p) + K7_H2X_FIFO_DIN, val);
	return 0;
}

static int k7_proc_write_u32 (struct k7_proc_desc *d, const char *kbuf)
{
	unsigned long val, min = d->min, max = d->max;
	int err = kstrtoul(kbuf, 0, &val);

	if (err)
		return err;
	if ((min != max) && (val < min || val > max))
		return -ERANGE;
	*(u32 *)(d->val_p) = val;
	mb();
	return 0;
}

static int k7_proc_write_hsm_state (struct k7_proc_desc *d, const char *kbuf)
{
	struct k7_dev *dev = d->dev;
	unsigned long val;
	int err = kstrtoul(kbuf, 0, &val);

	if (err)
		return err;
	SPIN_LOCK(&dev->lock);
	k7_update_hsm_state(dev, val);
	SPIN_UNLOCK(&dev->lock);
	return 0;
}

#if 0  // Not used
static int k7_proc_write_s32 (struct k7_proc_desc *d, const char *kbuf)
{
	long val, min = d->min, max = d->max;
	int err = kstrtol(kbuf, 0, &val);

	if (err)
		return err;
	if ((min != max) && (val < min || val > max))
		return -ERANGE;
	*(s32 *)(d->val_p) = val;
	mb();
	return 0;
}

static int k7_proc_write_str (struct k7_proc_desc *d, const char *kbuf)
{
	if (strlen(kbuf) > d->max)
		return -ENOSPC;
	strcpy((char *)(d->val_p), kbuf);
	return 0;
}
#endif

/*
 * k7_proc_write() is called whenever somebody writes to "/proc/k7/xxx".
 * We can do anything we like here, so long as we return "count" to the caller.
 */
static ssize_t k7_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct k7_proc_desc *d = k7_pde_data(file_inode(file));
	char *kbuf;
	int ret;

	if (!d->writefunc)
		return -EPERM;
	if (!count)
		return 0;
	if (ppos && *ppos)
		return -EINVAL;
	kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;
	if (copy_from_user(kbuf, buf, count)) {
		ret = -EFAULT;
	} else {
		if (kbuf[count - 1] == '\n')
			kbuf[count - 1] = '\0';
		else
			kbuf[count] = '\0';
		ret = d->writefunc(d, kbuf);
		kfree(kbuf);
	}
	if (ret)
		return ret;
	if (ppos)
		*ppos += count;
	return count;
}

static void k7_proc_read_stats (struct seq_file *seq, struct k7_proc_desc *d)
{
	struct k7_dev *dev = d->dev;
	u64 completed_requests, bytes_sent, bytes_received;

	SPIN_LOCK(&dev->stats_lock);
	completed_requests = dev->completed_requests;
	bytes_sent         = dev->bytes_sent;
	bytes_received     = dev->bytes_received;
	SPIN_UNLOCK(&dev->stats_lock);

	seq_printf(seq, "completed_requests %llu\n", completed_requests);
	seq_printf(seq, "bytes_sent         %llu\n", bytes_sent);
	seq_printf(seq, "bytes_received     %llu\n", bytes_received);
	seq_printf(seq, "dt_freelist_count  %u\n",   dev->dt_freelist_count);
}

static void k7_proc_read_last_hderr (struct seq_file *seq, struct k7_proc_desc *d)
{
	struct k7_dev *dev = d->dev;

	k7_dumpreg_seq(seq, NULL, dev->last_hderr,  k7_hderr_regbits);
}

static void k7_proc_read_regs (struct seq_file *seq, struct k7_proc_desc *d)
{
	struct k7_dev *dev = d->dev;
	u64 hbmsr, hcsr, hmvmc, htbtc;
	u64 h2mldt = 0, h2mdtc = 0, m2hcs = 0, h2mcs = 0, vfdme = 0, hcfgr1 = 0, hrbmax = 0;
	u32 hcr, hbmcr, hier, hrcsr;
	u32 hderr = 0;

	SPIN_LOCK(&dev->lock);
	hcr	= K7_READ32(K7_HCR);
	hbmcr	= K7_READ32(K7_HBMCR);
	hbmsr	= K7_READ64(K7_HBMSR);
	hier	= K7_READ32(K7_HIER);
	hrcsr	= K7_READ32(K7_HRCSR);
	hcsr	= K7_READ64(K7_HCSR);
	hmvmc	= K7_READ64(K7_HMVMC);
	htbtc	= K7_READ64(K7_HTBTC);
	hderr	= K7_READ32(K7_HDERR);
	hrbmax	= K7_READ64(K7_VF_MAX_HRB_LEN);
	if (dev->is_pf) {
		h2mldt	= K7_READ64(K7_H2MLDT);
		h2mdtc	= K7_READ64(K7_H2MDTC);
		m2hcs	= K7_READ64(K7_H2MCS);
		h2mcs	= K7_READ64(K7_H2MCS);
		vfdme	= K7_READ64(K7_VF_DMA_MASTER_EN);
		hcfgr1	= K7_READ64(K7_HCFGR1);
	}
	SPIN_UNLOCK(&dev->lock);

	k7_dumpreg_seq(seq, NULL, hcr,    k7_hcr_regbits);
	k7_dumpreg_seq(seq, NULL, hbmcr,  k7_hbmcr_regbits);
	k7_dumpreg_seq(seq, "HIER", hier, k7_hisr_regbits);
	k7_dumpreg_seq(seq, NULL, hderr,  k7_hderr_regbits);
	k7_dumpreg_seq(seq, NULL, hmvmc,  k7_hmvmc_regbits);
	k7_dumpreg_seq(seq, NULL, hrcsr,  k7_hrcsr_regbits);
	k7_dumpreg_seq(seq, NULL, hbmsr,  k7_hbmsr_regbits);
	k7_dumpreg_seq(seq, NULL, hcsr,   k7_hcsr_regbits);
	k7_dumpreg_seq(seq, NULL, htbtc,  k7_htbtc_regbits);
	k7_dumpreg_seq(seq, "HRBMAX", hrbmax, k7_64bits);
	if (dev->is_pf) {
		k7_dumpreg_seq(seq, "H2MLDT", h2mldt, k7_64bits);
		k7_dumpreg_seq(seq, NULL, h2mdtc, k7_h2mdtc_regbits);
		k7_dumpreg_seq(seq, NULL, m2hcs,  k7_m2hcs_regbits);
		k7_dumpreg_seq(seq, NULL, h2mcs,  k7_h2mcs_regbits);
		k7_dumpreg_seq(seq, "VFDME", vfdme, k7_64bits);
		k7_dumpreg_seq(seq, NULL, hcfgr1, k7_hcfgr1_regbits);
	}
}

static void k7_proc_read_htb (struct seq_file *seq, struct k7_proc_desc *d)
{
	struct k7_dev *dev = d->dev;
	unsigned int htb_len = dev->htb_area.len;
	unsigned offset;
	u64 last_wa;
	u64 *htb;

	htb = kmalloc(htb_len, GFP_KERNEL);
	if (htb) {
		SPIN_LOCK(&dev->lock);
		memcpy(htb, dev->htb_area.vaddr, htb_len);
		last_wa = dev->last_wa;
		SPIN_UNLOCK(&dev->lock);
		seq_printf(seq, "(%p) %016llx:%04x last_wa=%016llx\n",
				dev->htb_area.vaddr, (u64)dev->htb_area.daddr, htb_len, last_wa);
		htb_len /= 16;
		for (offset = 0; offset < htb_len; offset++) {
			unsigned int index = offset * 2;
			u64 w0 = be64_to_cpu(htb[index    ]);
			u64 w1 = be64_to_cpu(htb[index + 1]);
			seq_printf(seq, "%04x: %016llx %016llx\n", offset * 16, w0, w1);
		}
		kfree(htb);
	}
}

static char *k7_x2x (char *x2x_buf, const char *fmt, const char *s1, const char *s2)
{
        sprintf(x2x_buf, fmt, s1, s2);
        return x2x_buf;
}

#define H2X(regname)  k7_x2x(x2x_buf,"H2%s_%s",prefix,regname)
#define X2H(regname)  k7_x2x(x2x_buf,"%s2H_%s",prefix,regname)

static void k7_proc_read_dma_debug (struct seq_file *seq, struct k7_proc_desc *d)
{
	struct k7_dev *dev = d->dev;
	unsigned int dma_base;
	unsigned char *prefix = d->val_p;

	u64 tcp = 0, rcs = 0, rbp = 0, rdc = 0, rdt = 0, wcs = 0, wlh = 0, wbp = 0, wdc = 0, wdt = 0, wdo = 0;
	char x2x_buf[16];

	if (0 == strcmp(prefix, "MM"))
		dma_base = K7_PKU_DMA_BASE;
	else if (0 == strcmp(prefix, "SK"))
		dma_base = K7_SKU_DMA_BASE;
	else if (0 == strcmp(prefix, "M"))
		dma_base = K7_MCPU_DMA_BASE;
	else if (0 == strcmp(prefix, "SKB")) {
		prefix = "SK";
		dma_base = K7_SKUB_DMA_BASE;
	} else
		return;	/* BUG */

	SPIN_LOCK(&dev->lock);
	if (dma_base != K7_SKUB_DMA_BASE)
		tcp = K7_READ64(dma_base + K7_H2X_TCP);
	if (dev->is_pf) {
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
	}
	SPIN_UNLOCK(&dev->lock);

	if (dma_base != K7_SKUB_DMA_BASE)
		k7_dumpreg_seq(seq, H2X("TCP"), tcp, k7_64bits);
	if (dev->is_pf) {
		k7_dumpreg_seq(seq, H2X("CS"),  rcs, k7_h2xcs_regbits);
		k7_dumpreg_seq(seq, H2X("BP"),  rbp, k7_64bits);
		k7_dumpreg_seq(seq, H2X("DTC"), rdc, k7_64bits);
		k7_dumpreg_seq(seq, H2X("LDT"), rdt, k7_64bits);
		k7_dumpreg_seq(seq, X2H("CS"),  wcs, k7_x2hcs_regbits);
		k7_dumpreg_seq(seq, X2H("LH"),  wlh, k7_64bits);
		k7_dumpreg_seq(seq, X2H("BP"),  wbp, k7_64bits);
		k7_dumpreg_seq(seq, X2H("DTC"), wdc, k7_64bits);
		k7_dumpreg_seq(seq, X2H("DT"),  wdt, k7_64bits);
		k7_dumpreg_seq(seq, X2H("ADO"), wdo, k7_64bits);
	}
}

static void k7_proc_read_r64 (struct seq_file *seq, struct k7_proc_desc *d)
{
	struct k7_dev *dev = d->dev;
	u64 reg = K7_READ64((unsigned long)(d->val_p));
	k7_dumpreg_seq(seq, d->name, reg, d->regbits);
}

static void k7_proc_read_r32 (struct seq_file *seq, struct k7_proc_desc *d)
{
	struct k7_dev *dev = d->dev;
	u32 reg = K7_READ32((unsigned long)(d->val_p));
	k7_dumpreg_seq(seq, d->name, reg, d->regbits);
}

static void k7_proc_read_dout (struct seq_file *seq, struct k7_proc_desc *d)
{
	struct k7_dev *dev = d->dev;
	u32 reg = K7_READ32((unsigned long)(d->val_p) + K7_X2H_FIFO_DOUT);
	seq_printf(seq, "0x%08x\n", reg);
}

static void k7_proc_print_mechs (struct seq_file *seq, struct k7_dev *dev, u8 *mechs)
{
	char buf[8];
	u8 mech;

	for (mech = *mechs++; mech; mech = *mechs++) {
		u32 mechanism = dev->mechanisms[mech];
		u16 valid_ops = dev->mech_ops[mech];
		fmt_ops(buf, valid_ops);
		seq_printf(seq, " %08x:%s", mechanism, buf);
	}
	seq_printf(seq, "\n");
}

static void k7_proc_print_mechlists (struct seq_file *seq, struct k7_dev *dev, const char *name, struct k7_mechlist *mechlists)
{
	int mechlist;

	for (mechlist = 0; mechlist < K7_MAX_MECHLISTS; ++mechlist) {
		struct k7_mechlist *list = &mechlists[mechlist];
		if (list->mechs) {
			seq_printf(seq, "%s[%u] %08x: ", name, mechlist, list->hash);
			k7_proc_print_mechs(seq, dev, list->mechs);
		}
	}
}

static void k7_proc_read_vmechlists (struct seq_file *seq, struct k7_proc_desc *d)
{
	k7_proc_print_mechlists(seq, d->dev, "valid_mechlists", d->dev->valid_mechlists);
}

static void k7_proc_read_imechlists (struct seq_file *seq, struct k7_proc_desc *d)
{
	k7_proc_print_mechlists(seq, d->dev, "invalid_mechlists", d->dev->invalid_mechlists);
}

static void k7_proc_print_kk (struct seq_file *seq, struct k7_dev *dev, u32 key_handle, struct k7_kek_key *kk)
{
	struct k7_kek_group *kg = &dev->kek_group[kk->group_id];
	char buf[8];
	unsigned int i;

	if (!kg) {
		seq_printf(seq, "-- -------- -------- -------- ----");
	} else {
		seq_printf(seq, "%2u %08x %08x %08x %4s", kg->group_id, kg->active_kek_id,
				kg->pending_kek_id, kg->minimum_kek_id, kg_status[kg->status & 3]);
	}
	seq_printf(seq, " %4u %08x %08x %08x %08x %c %s %5u %5u %5u %5u ",
		k7_kref_read(&kk->kref), key_handle, kk->generation,
		kk->kek_id, kk->kek_algorithm, kk->cannot_be_keked ? 'N' : 'Y',
		fmt_ops(buf, kk->valid_ops), kk->valid_mechs, kk->invalid_mechs,
		kk->raw_key_words * (int)sizeof(u64), kk->key_words * (int)sizeof(u64));
	if (0 && kk->key_words) {
		for (i = 0; i < (kk->key_words * sizeof(u64)); ++i)
			seq_printf(seq, "%02x", *(u8 *)(kk->key_data + i));
	}
	seq_printf(seq, "\n");
}

static void k7_proc_read_keycache (struct seq_file *seq, struct k7_proc_desc *d)
{
	struct k7_dev	*dev = d->dev;
	unsigned int	index1, index2;

	seq_printf(seq, "GP activkek pendgkek minkekid stat kref kyhandle kygenern -kek_id- algorthm K opers vmech imech rsize ksize\n");
	for (index1 = 0; index1 <= dev->keycache_level1_max; ++index1) {
		struct k7_keycache_level2 *level2 = dev->keycache->level2[index1];
		if (!level2)
			continue;
		for (index2 = 0; index2 < K7_KEYCACHE_LEVEL2_WIDTH; ++index2) {
			struct k7_kek_key *kk;
			SPIN_LOCK(&dev->keycache_lock);
			kk = k7_kk_null_if_empty(level2->slot[index2].kk);
			if (kk) {
				u32 key_handle = (index1 * K7_KEYCACHE_LEVEL2_WIDTH) + index2;
				k7_proc_print_kk(seq, dev, key_handle, kk);
			}
			SPIN_UNLOCK(&dev->keycache_lock);
		}
	}
}

static void k7_proc_read_kek_groups (struct seq_file *seq, struct k7_proc_desc *d)
{
	struct k7_dev	*dev = d->dev;
	unsigned int	group_id;

	seq_printf(seq, "GP activkek pendgkek minkekid stat actcount NZ\n");
	for (group_id = 0; group_id < K7_KEYCACHE_GROUPS; ++group_id) {
		struct k7_kek_group *kg = &dev->kek_group[group_id];
		SPIN_LOCK(&kg->lock);
			seq_printf(seq, "%2u %08x %08x %08x %4s %8u  %c\n",
				group_id, kg->active_kek_id, kg->pending_kek_id, kg->minimum_kek_id, kg_status[kg->status & 3], kg->active_count,
				kg->notify_hsm_when_zero ? 'Y' : 'N');
		SPIN_UNLOCK(&kg->lock);
	}
}

static int k7_proc_write_keycache (struct k7_proc_desc *d, const char *kbuf)
{
	long val;
	int err = kstrtol(kbuf, 0, &val);
	if (err)
		return err;
	if (val <= 0 || val >= K7_KEYCACHE_MAX_HANDLES)
		return -ERANGE;
	k7_keycache_delete_key(d->dev, val, NULL);
	return 0;
}

static void k7_proc_dump_keylist (struct seq_file *seq, struct k7_session_keylist *keylist)
{
	struct k7_key_id *keys        = keylist->keys;
	struct k7_key_id *end_of_list = keys + K7_SESSION_KEYLIST_ENTRIES;

	do {
		if (keys->id)
			seq_printf(seq, " %08x:%u", keys->key_handle, keys->generation);
	} while (++keys != end_of_list);
}

static void k7_proc_read_sessions (struct seq_file *seq, struct k7_proc_desc *d)
{
	struct k7_dev *dev = d->dev;
	unsigned int group_id, groupx;

	for (group_id = 0; group_id < K7_SESSION_GROUPS; ++group_id) {
		struct k7_session_group *group = dev->session_groups[group_id];
		if (group) {
			for (groupx = 0; groupx < K7_SESSIONS_PER_GROUP; ++groupx) {
				struct k7_session_keylist *keylist;
				u32 session_id = 0;
				SPIN_LOCK(&dev->sessions_lock);
				for (keylist = group->keylists[groupx]; keylist; keylist = keylist->next) {
					if (keylist->num_keys) {
						if (!session_id) {
							session_id = (group_id * K7_SESSIONS_PER_GROUP) + groupx;
							seq_printf(seq, "%08x: ", session_id);
						}
						k7_proc_dump_keylist(seq, keylist);
					}
				}
				SPIN_UNLOCK(&dev->sessions_lock);
				if (session_id)
					seq_printf(seq, "\n");
			}
		}
	}
}

static void k7_proc_read_x64 (struct seq_file *seq, struct k7_proc_desc *d)
{
	seq_printf(seq, "0x%016llx\n", *(u64 *)(d->val_p));
}

#if 0  // not used
static void k7_proc_read_x32 (struct seq_file *seq, struct k7_proc_desc *d)
{
	seq_printf(seq, "0x%08x\n", *(u32 *)(d->val_p));
}

static void k7_proc_read_s32 (struct seq_file *seq, struct k7_proc_desc *d)
{
	seq_printf(seq, "%d\n", *(s32 *)(d->val_p));
}

static void k7_proc_read_u64 (struct seq_file *seq, struct k7_proc_desc *d)
{
	seq_printf(seq, "%llu\n", *(u64 *)(d->val_p));
}

static void k7_proc_read_str (struct seq_file *seq, struct k7_proc_desc *d)
{
	seq_printf(seq, "%s\n", (char *)(d->val_p));
}
#endif

static void k7_proc_read_u32 (struct seq_file *seq, struct k7_proc_desc *d)
{
	seq_printf(seq, "%u\n", *(u32 *)(d->val_p));
}

static void k7_proc_read_u8 (struct seq_file *seq, struct k7_proc_desc *d)
{
	seq_printf(seq, "%u\n", (unsigned int)*(u8 *)(d->val_p));
}

static void k7_proc_read_x32 (struct seq_file *seq, struct k7_proc_desc *d)
{
	seq_printf(seq, "%08x\n", *(u32 *)(d->val_p));
}

static void k7_proc_read_atomic (struct seq_file *seq, struct k7_proc_desc *d)
{
	seq_printf(seq, "%lu\n", (unsigned long)atomic_read(d->val_p));
}

static int k7_proc_write_atomic (struct k7_proc_desc *d, const char *kbuf)
{
	unsigned long val, min = d->min, max = d->max;
	int err = kstrtoul(kbuf, 0, &val);

	if (err)
		return err;
	if ((min != max) && (val < min || val > max))
		return -ERANGE;
	atomic_set((atomic_t *)(d->val_p), val);
	return 0;
}

/*
 * k7_proc_read() is called whenever somebody reads from "/proc/k7/xxx".
 * the "seq_printf()" function takes care of most of the complexity involved.
 */
static int k7_proc_read(struct seq_file *seq, void *offset)
{
	struct k7_proc_desc *d = seq->private;

	if (!d->readfunc)
		return -EPERM;
	d->readfunc(seq, d);
	return 0;
}

static void k7_fill_desc (struct k7_proc_desc *d, struct k7_dev *dev, const char *name,
				volatile void *val_p, const struct k7_regbits *regbits, void *readfunc, void *writefunc)
{
	const char *devname = dev->name + 2;  /* skip over the "k7" prefix portion */

	d->dev = dev;
	if (!name) {
		snprintf(d->name, sizeof(d->name), "%s", devname);
	} else {
		snprintf(d->name, sizeof(d->name), "%s/%s", devname, name);
		d->val_p     = (void *)val_p;
		d->regbits   = regbits;
		d->readfunc  = readfunc;
		d->writefunc = writefunc;
	}
}

static int k7_proc_release (struct inode *inode, struct file *file)
{
	struct k7_proc_desc *d = k7_pde_data(file_inode(file));

	if (d->dev)
		kref_put(&d->dev->kref, k7_free_dev);
	return single_release(inode, file);
}

/*
 * k7_proc_proc_open() is called each time open() is invoked on "/proc/k7/xxx"
 * we provide it here so we can hook into the seq_printf() infrastructure.
 */
static int k7_proc_open(struct inode *inode, struct file *file)
{
	struct k7_proc_desc *d = k7_pde_data(file_inode(file));
	struct k7_dev *dev;

	if (!d->dev)
		return single_open(file, k7_proc_read, d);
	dev = k7_get_dev_kref(d->dev);
	return dev ? single_open(file, k7_proc_read, d) : -ESTALE;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0))
static const struct proc_ops k7_proc_ro_fops = {
        .proc_open           = k7_proc_open,
        .proc_lseek         = seq_lseek,
        .proc_read           = seq_read,
        .proc_release        = k7_proc_release,
};

static const struct proc_ops k7_proc_wo_fops = {
        .proc_open           = k7_proc_open,
        .proc_lseek         = seq_lseek,
        .proc_write          = k7_proc_write,
        .proc_release        = k7_proc_release,
};

static const struct proc_ops k7_proc_rw_fops = {
        .proc_open           = k7_proc_open,
        .proc_lseek         = seq_lseek,
        .proc_read           = seq_read,
        .proc_write          = k7_proc_write,
        .proc_release        = k7_proc_release,
};
#else
static const struct file_operations k7_proc_ro_fops = {
	.owner		= THIS_MODULE,
	.open		= k7_proc_open,
	.llseek		= seq_lseek,
	.read		= seq_read,
	.release	= k7_proc_release,
};

static const struct file_operations k7_proc_wo_fops = {
	.owner		= THIS_MODULE,
	.open		= k7_proc_open,
	.llseek		= seq_lseek,
	.write		= k7_proc_write,
	.release	= k7_proc_release,
};

static const struct file_operations k7_proc_rw_fops = {
	.owner		= THIS_MODULE,
	.open		= k7_proc_open,
	.llseek		= seq_lseek,
	.read		= seq_read,
	.write		= k7_proc_write,
	.release	= k7_proc_release,
};
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0))
static const struct proc_ops *k7_proc_fops(umode_t mode)
#else
static const struct file_operations *k7_proc_fops(umode_t mode)
#endif
{
	if ((mode & S_IWUGO) && (mode & S_IRUGO))
		return &k7_proc_rw_fops;
	if (mode & S_IWUGO)
		return &k7_proc_wo_fops;
	return &k7_proc_ro_fops;
}

static int k7_proc_add_entries (struct k7_proc_desc *d)
{
	struct proc_dir_entry *ent;

	for (; d->name[0]; ++d) {
		umode_t mode = 0;
		if (d->readfunc)
			mode |= S_IFREG|S_IRUGO;
		if (d->writefunc)
			mode |= S_IFREG|S_IWUSR;
		if (mode)
			ent = proc_create_data(d->name, mode, k7_proc_topdir, k7_proc_fops(mode), d);
		else
			ent = proc_mkdir(d->name, k7_proc_topdir);
		if (!ent) {
			printk(KERN_ERR "%s: proc_create(\"%s\") failed\n", __func__, d->name);
			break;
		}
	}
	return 0;
}

static void k7_proc_del_entries (struct k7_proc_desc *d)
{
	/*
	 * Remove entries in reverse order of creation, to correctly handle any subdirectories.
	 */
	if (!k7_proc_topdir)
		return;
	if (d && d->name[0]) {
		struct k7_proc_desc *first = d;
		while (d->name[0])
			++d;
		while (d-- != first)
			remove_proc_entry(d->name, k7_proc_topdir);
	}
}

void k7_proc_create_dev (struct k7_dev *dev)
{
	const int max_entries = 50;
	struct k7_proc_desc *pd, *d;

	if (!k7_proc_topdir)
		return;
	pd = kzalloc(sizeof(struct k7_proc_desc) * max_entries, GFP_KERNEL);
	if (!pd) {
		printk(KERN_ERR "%s: kzalloc() failed\n", __func__);
		return;
	}
	dev->proc_desc = d = pd;
	k7_fill_desc(d++, dev, NULL,		NULL,			NULL,			NULL,			NULL);
	k7_fill_desc(d++, dev, "alarm_count",	&dev->alarm_count,	NULL,			k7_proc_read_u32,	NULL);
	k7_fill_desc(d++, dev, "cb_state",	&dev->cb_state,		NULL,			k7_proc_read_u8,	NULL);
	k7_fill_desc(d++, dev, "cbhra_count",	&dev->cbhra_count,	NULL,			k7_proc_read_u32,	NULL);
	if (dev->is_pf)
		k7_fill_desc(d++, dev, "disable_autoboot", &dev->disable_autoboot, NULL,	k7_proc_read_u32,	k7_proc_write_u32);
	k7_fill_desc(d++, dev, "hisr",		(void *)K7_HISR,	k7_hisr_regbits,	k7_proc_read_r32,	k7_proc_write_r32);
	k7_fill_desc(d++, dev, "hsm_state",	&dev->hsm_state,	NULL,			k7_proc_read_x32,	k7_proc_write_hsm_state);
	k7_fill_desc(d++, dev, "htb",		NULL,			NULL,			k7_proc_read_htb,	NULL);
	k7_fill_desc(d++, dev, "htbmask",	NULL,			NULL,			NULL,			k7_proc_write_htbmask);
	k7_fill_desc(d++, dev, "htbwa",		(void *)K7_HTBWA,	k7_64bits,		k7_proc_read_r64,	NULL);
	k7_fill_desc(d++, dev, "failed",	&dev->failed,		NULL,			k7_proc_read_u8,	NULL);
	k7_fill_desc(d++, dev, "icd_enabled",	&dev->icd_enabled,	NULL,			k7_proc_read_u8,	NULL);
	k7_fill_desc(d++, dev, "insertion_count", &dev->insertion_count,NULL,			k7_proc_read_u32,	k7_proc_write_u32);
	k7_fill_desc(d++, dev, "kek_groups",	NULL,			NULL,			k7_proc_read_kek_groups,NULL);
	k7_fill_desc(d++, dev, "keycache",	NULL,			NULL,			k7_proc_read_keycache,	k7_proc_write_keycache);
	k7_fill_desc(d++, dev, "last_hderr",	&dev->last_hderr,	NULL,			k7_proc_read_last_hderr, k7_proc_write_u32);
	if (dev->is_pf)
		k7_fill_desc(d++, dev, "m2hmbx", &dev->last_m2h_mbx,	NULL,			k7_proc_read_x64,	NULL);
	k7_fill_desc(d++, dev, "mcpu_reset_completed",	&dev->mcpu_reset_completed, NULL,	k7_proc_read_u8,	NULL);
	k7_fill_desc(d++, dev, "mdebug",	"M",			NULL,			k7_proc_read_dma_debug,	NULL);
	if (dev->is_pf)
		k7_fill_desc(d++, dev, "mdin",	(void *)K7_MCPU_DMA_BASE, NULL,			NULL,			k7_proc_write_din);
	k7_fill_desc(d++, dev, "mmdebug",	"MM",			NULL,			k7_proc_read_dma_debug,	NULL);
	if (dev->is_pf) {
		k7_fill_desc(d++, dev, "mmdin",	(void *)K7_PKU_DMA_BASE, NULL,			NULL,			k7_proc_write_din);
		k7_fill_desc(d++, dev, "mmdout", (void *)K7_PKU_DMA_BASE, NULL,			k7_proc_read_dout,	NULL);
		k7_fill_desc(d++, dev, "pcie_gen", &dev->pcie_gen,	NULL,			k7_proc_read_u32,	NULL);
	}
	k7_fill_desc(d++, dev, "regs",		NULL,			NULL,			k7_proc_read_regs,	NULL);
	k7_fill_desc(d++, dev, "rekek_count",	&dev->rekek_count,	NULL,			k7_proc_read_atomic,	k7_proc_write_atomic);
	k7_fill_desc(d++, dev, "sessions",	NULL,			NULL,			k7_proc_read_sessions,	NULL);
	if (dev->is_pf)
		k7_fill_desc(d++, dev, "skadebug","SK",			NULL,			k7_proc_read_dma_debug,	NULL);
	if (dev->is_pf) {
		k7_fill_desc(d++, dev, "skadin", (void *)K7_SKU_DMA_BASE, NULL,			NULL,			k7_proc_write_din);
		k7_fill_desc(d++, dev, "skadout", (void *)K7_SKU_DMA_BASE, NULL,		k7_proc_read_dout,	NULL);
		k7_fill_desc(d++, dev, "skbdebug", "SKB",		NULL,			k7_proc_read_dma_debug,	NULL);
		k7_fill_desc(d++, dev, "skbdin", (void *)K7_SKUB_DMA_BASE, NULL,		NULL,			k7_proc_write_din);
		k7_fill_desc(d++, dev, "skbdout", (void *)K7_SKUB_DMA_BASE, NULL,		k7_proc_read_dout,	NULL);
	}
	k7_fill_desc(d++, dev, "stats",		NULL,			NULL,			k7_proc_read_stats,	k7_proc_write_stats);
	k7_fill_desc(d++, dev, "traceio",	&dev->traceio,		NULL,			k7_proc_read_u32,	k7_proc_write_u32);
	k7_fill_desc(d++, dev, "valid_mechlists", NULL,			NULL,			k7_proc_read_vmechlists,NULL);
	k7_fill_desc(d++, dev, "invalid_mechlists", NULL,		NULL,			k7_proc_read_imechlists,NULL);

	k7_proc_add_entries(pd);
}

void k7_proc_destroy_dev (struct k7_dev *dev)
{
	struct k7_proc_desc *pd = dev->proc_desc;

	if (pd) {
		dev->proc_desc = NULL;
		k7_proc_del_entries(pd);
		kfree(pd);
	}
}

static struct k7_proc_desc k7_proc_main_entries[] =
/*	  name			dev   val_p		min	max	regbits		readfunc		writefunc */
{/*	  ====================	====  ===========	=====	====	=======		========		========= */
	{ "kek_key_structs",	NULL, &k7_kek_key_struct_count,	0, 0,	NULL,	k7_proc_read_atomic,	NULL},
	{ "",			NULL, NULL,		0,	0,	NULL,	NULL,			NULL}
};

void k7_proc_create (void)
{
	if (!k7_procfs)
		return;
	k7_proc_topdir = proc_mkdir(DEV_BASENAME, NULL);
	if (!k7_proc_topdir)
		printk(KERN_ERR "%s: proc_mkdir(\"%s\") failed\n", __func__, DEV_BASENAME);
	else
		k7_proc_add_entries(k7_proc_main_entries);
}

void k7_proc_destroy (void)
{
	if (k7_proc_topdir) {
		k7_proc_del_entries(k7_proc_main_entries);
		k7_proc_topdir = NULL;
		remove_proc_entry(DEV_BASENAME, NULL);
	}
}
#endif /* K7_HAVE_PROC_FS */
