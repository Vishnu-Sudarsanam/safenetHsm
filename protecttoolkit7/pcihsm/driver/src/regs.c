/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * regs.c -- register definitions etc.. for debugging.
 */
#include "headers.h"
#include "proc.h"

static const char *k7_hderr_ch_id[16] = {
	"H2MM",
	"H2SKA",
	"H2SKB",
	"H2M",
	"H2S",
	"H2FA",
	"H2FB",
	"(Ch.7)",
	"MM2H",
	"SKA2H",
	"SKB2H",
	"M2H",
	"S2H",
	"FA2H",
	"FB2H",
	NULL
};

unsigned int k7_dma_base (struct k7_dev *dev, unsigned int target)
{
	switch (target) {
		case K7_DMA_TARGET_MCPU:	return K7_MCPU_DMA_BASE;
		case K7_DMA_TARGET_PKU:		return K7_PKU_DMA_BASE;
		case K7_DMA_TARGET_SKU:		return K7_SKU_DMA_BASE;
		default:			return 0;  /* BUG */
	}
}

void k7_write16 (struct k7_dev *dev, unsigned int offset, u16 data)
{
	void __iomem *addr;

	if (!dev->mmio) {
		dump_stack();
		return;
	}
	addr = dev->mmio + offset;
	if (dev->traceio)
		kinfo(dev->name, "write16(%p): 0x%04x", addr, data);
	data = cpu_to_be16(data);
	writew(data, addr);
}

u32 k7_read32 (struct k7_dev *dev, unsigned int offset)
{
	void __iomem *addr;
	u32 data;

	if (!dev->mmio) {
		dump_stack();
		return ~0;
	}
	addr = dev->mmio + offset;
	data = readl(addr);
	data = be32_to_cpu(data);
	if (dev->traceio)
		kinfo(dev->name, "read32 (%p): %08x", addr, data);
	return data;
}

void k7_write32 (struct k7_dev *dev, unsigned int offset, u32 data)
{
	void __iomem *addr;

	if (!dev->mmio) {
		dump_stack();
		return;
	}
	addr = dev->mmio + offset;
	if (dev->traceio)
		kinfo(dev->name, "write32(%p): %08x", addr, data);
	data = cpu_to_be32(data);
	writel(data, addr);
}

u32 k7_flush32 (struct k7_dev *dev, unsigned int offset, u32 data)
{
	k7_write32(dev, offset, data);
	return k7_read32(dev, offset);
}

u64 k7_read64 (struct k7_dev *dev, unsigned int offset)
{
	void __iomem *addr;
	u64 data;

	if (!dev->mmio) {
		dump_stack();
		return ~0ull;
	}
	addr = dev->mmio + offset;
#ifdef readq
	data = readq(addr);
#else
	mb();
	data = *(const volatile u64 __force *)addr;
	rmb();
#endif
	data = be64_to_cpu(data);
	if (dev->traceio)
		kinfo(dev->name, "read64 (%p): %016llx", addr, data);
	return data;
}

void k7_write64 (struct k7_dev *dev, unsigned int offset, u64 data)
{
	void __iomem *addr;

	if (!dev->mmio) {
		dump_stack();
		return;
	}
	addr = dev->mmio + offset;
	if (dev->traceio)
		kinfo(dev->name, "write64(%p): %016llx", addr, data);
	data = cpu_to_be64(data);
#ifdef writeq
	writeq(data, addr);
#else
	mb();
	*(volatile u64 __force *)addr = data;
	wmb();
#endif
}

u64 k7_flush64 (struct k7_dev *dev, unsigned int offset, u64 data)
{
	k7_write64(dev, offset, data);
	return k7_read64(dev, offset);
}

void k7_modify64 (struct k7_dev *dev, unsigned int offset, u64 clear_bits, u64 set_bits)
{
	u64	old, new;

	if (!dev->mmio) {
		dump_stack();
		return;
	}
	old = K7_READ64(offset);
	new = (old & ~clear_bits) | set_bits;
	if (old != new)
		K7_WRITE64(offset, new);
}

void k7_modify32 (struct k7_dev *dev, unsigned int offset, u32 clear_bits, u32 set_bits)
{
	u32	old, new;

	if (!dev->mmio) {
		dump_stack();
		return;
	}
	old = K7_READ32(offset);
	new = (old & ~clear_bits) | set_bits;
	if (old != new || offset == K7_HCR)
		K7_WRITE32(offset, new);
}

/*
 * ffs64: "find first set" bit in a u64.
 *
 * Return bit-count [1..64] of first "1" bit, searching from lsb to msb.
 * Returns 0 if all bits are zero.
 * Most users of this function will need to subtract one from the result
 * in order to obtain the bit-index [0..63].
 *
 * On Intel CPUs, ffs() _should_ use the (fast) machine instruction 'bsf1'.
 */
static int ffs64 (u64 data)
{
	u32 d32;

	if (!data)
		return 0;
	d32 = data;
	if (d32)
		return ffs(d32);
	d32 = data >> 32;
	return ffs(d32) + 32;
}

/*
 * Extract and right-align a bitfield from a 32-bit CPU-endian value.
 */
unsigned int extract32 (u32 data, u32 mask)
{
	return (data & mask) >> (ffs(mask) - 1);
}

/*
 * Extract and right-align a bitfield from a 64-bit CPU-endian value.
 */
unsigned int extract64 (u64 data, u64 mask)
{
	return (data & mask) >> (ffs64(mask) - 1);
}

/*
 * Align and insert a bitfield into a 32-bit CPU-endian value.
 */
u32 insert32 (u32 data, u32 mask, unsigned int val)
{
	u32 bits = ((u32)val) << (ffs(mask) - 1);
	return (data & ~mask) | (bits & mask);
}

/*
 * Align and insert a bitfield into a 64-bit CPU-endian value.
 */
u64 insert64 (u64 data, u64 mask, unsigned int val)
{
	u64 bits = ((u64)val) << (ffs64(mask) - 1);
	return (data & ~mask) | (bits & mask);
}

/*
 * Count number of bits set in a u32.
 */
int count_bits32 (u32 data)
{
	data = data - ((data >> 1) & 0x55555555);
	data = (data & 0x33333333) + ((data >> 2) & 0x33333333);
	return (((data + (data >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

/*
 * Count number of bits set in a u64.
 */
int count_bits64 (u64 data)
{
	return count_bits32(data) + count_bits32(data >> 32);
}

/*
 * Dump out a register value for /proc/, showing what the individual bit-fields mean.
 */
void k7_dumpreg_seq (struct seq_file *seq, const char *label, u64 reg, const struct k7_regbits *regbits)
{
#ifdef CONFIG_PROC_FS
	if (!regbits) {
		if (!label || !*label)
			label = "?????";
		seq_printf(seq, "%8s: 0x%llx", label, reg);
	} else {
		const struct k7_regbits	*header = regbits++;
		const struct k7_regbits	*r;
		if (!label || !*label)
			label = header->name;
		if (header->mask == 64)
			seq_printf(seq, "%8s: %016llx", label, reg);
		else
			seq_printf(seq, "%8s: %08x", label, (u32)reg);
		if (regbits->mask) {
			seq_printf(seq, " {");
			for (r = regbits; r->mask; ++r) {
				//u64 data = (reg & r->mask) >> (ffs64(r->mask) - 1);
				u64 data = extract64(reg, r->mask);
				if (r->name[0] == '=' || (data && r->name[0] == '+'))
					seq_printf(seq, " %s=%llu", r->name + 1, data);
				else if (r->name[0] == '@') {
					const char *ch_id = k7_hderr_ch_id[data & 15];
					if (ch_id)
						seq_printf(seq, " %s=%s", r->name + 1, ch_id);
				}
				else if (data && count_bits64(r->mask) > 1)
					seq_printf(seq, " %s=0x%llx", r->name, data);
				else if (data != 0)
					seq_printf(seq, " %s", r->name);
			}
			seq_printf(seq, " }");
		}
	}
	seq_printf(seq, "\n");
#endif
}

/*
 * Dump out a register value, showing what the individual bit-fields mean.
 */
static int k7_dumpreg_buf (const char *label, u64 reg, const struct k7_regbits *regbits, char *buf, int blen)
{
	int n = 0;

	buf[--blen] = '\0';
	if (!regbits) {
		if (!label || !*label)
			label = "?????";
		n += scnprintf(buf+n, blen-n, "%8s: 0x%llx", label, reg);
	} else {
		const struct k7_regbits	*header = regbits++;
		const struct k7_regbits	*r;
		if (!label || !*label)
			label = header->name;
		if (header->mask == 64)
			n += scnprintf(buf+n, blen-n, "%8s: %016llx", label, reg);
		else
			n += scnprintf(buf+n, blen-n, "%8s: %08x", label, (u32)reg);
		if (regbits->mask) {
			n += scnprintf(buf+n, blen-n, " {");
			for (r = regbits; r->mask; ++r) {
				//u64 data = (reg & r->mask) >> (ffs64(r->mask) - 1);
				u64 data = extract64(reg, r->mask);
				if (r->name[0] == '=' || (data && r->name[0] == '+'))
					n += scnprintf(buf+n, blen-n, " %s=%llu", r->name + 1, data);
				else if (r->name[0] == '~' || (data && r->name[0] == '-')) {
					// Shift the data into the sign bit and back so that
					// it becomes properly sign extended for a 64 bit int.
					s64 val = (s64)data;
					val <<= 64 - count_bits64(r->mask);
					val >>= 64 - count_bits64(r->mask);
					n += scnprintf(buf+n, blen-n, " %s=%lld", r->name + 1, val);
				}
				else if (r->name[0] == '@') {
					const char *ch_id = k7_hderr_ch_id[data & 15];
					if (ch_id)
						n += scnprintf(buf+n, blen-n, " %s=%s", r->name + 1, ch_id);
				}
				else if (data && count_bits64(r->mask) > 1)
					n += scnprintf(buf+n, blen-n, " %s=0x%llx", r->name, data);
				else if (data != 0)
					n += scnprintf(buf+n, blen-n, " %s", r->name);
			}
			n += scnprintf(buf+n, blen-n, " }");
		}
	}
	return n;
}

void k7_dumpreg (struct k7_dev *dev, const char *label, u64 reg, const struct k7_regbits *regbits)
{
	unsigned long page = __get_free_page(GFP_ATOMIC);	/* overkill */
	if (!page) {
		kerr(dev->name, "__gfp() failed");
	} else {
		char *buf = (void *)page;
		k7_dumpreg_buf(label, reg, regbits, buf, PAGE_SIZE);
		kdlog(dev->name, "%s", buf);
		free_page(page);
	}
}

const struct k7_regbits k7_32bits[] = {
	{32, /* 32-bit register */	"32bits" /* register name */ },
	{0,				NULL		}
};

const struct k7_regbits k7_64bits[] = {
	{64, /* 64-bit register */	"64bits" /* register name */ },
	{0,				NULL		}
};

const struct k7_regbits k7_hisr_regbits[] = {
	{32, /* 32-bit register */	"HISR" /* register name */ },
	{K7_HISR_HW_ERR,		"HW_ERR"	},
	{K7_HISR_RESERVED1,		"RESERVED1"	},
	{K7_HISR_ACCESS_ERR,		"ACCESS_ERR"	},
	{K7_HISR_RECOV_DMA_ERR,		"RECOV_DMA_ERR"	},
	{K7_HISR_UNRECOV_DMA_ERR,	"UNRECOV_DMA_ERR" },
	{K7_HISR_SOFT_TAMPER,		"SOFT_TAMPER"	},
	{K7_HISR_HARD_TAMPER,		"HARD_TAMPER"	},
	{K7_HISR_H2M,			"H2M"		},
	{K7_HISR_M2H,			"M2H"		},
	{K7_HISR_H2S,			"H2S"		},
	{K7_HISR_S2H,			"S2H"		},
	{K7_HISR_RESERVED12,		"RESERVED12"	},
	{K7_HISR_H_TEMP_WRNG,		"H_TEMP_WRNG"	},
	{K7_HISR_RESERVED25,		"RESERVED25"	},
	{K7_HISR_LOWBAT,		"LOWBAT"	},
	{K7_HISR_PF2VF_MBX,		"PF2VF_MBX"	},
	{K7_HISR_SRM_ATT,		"SRM_ATT"	},
	{K7_HISR_MRM_ATT,		"MRM_ATT"	},
	{K7_HISR_HTB_BF,		"HTB_BF"	},
	{K7_HISR_HTB_INT,		"HTB_INT"	},
	{0,				NULL		}
};

const struct k7_regbits	k7_hbmsr_regbits[] = {
	{64, /* 64-bit register */	"HBMSR" /* register name */ },
	{K7_HBMSR_H2PK_DE,		"H2PK_DE"		},
	{K7_HBMSR_PK2H_DE,		"PK2H_DE"		},
	{K7_HBMSR_H2SK_DE,		"H2SK_DE"		},
	{K7_HBMSR_SK2H_DE,		"SK2H_DE"		},
	{K7_HBMSR_H2M_DE,		"H2M_DE"		},
	{K7_HBMSR_M2H_DE,		"M2H_DE"		},
	{K7_HBMSR_H2S_DE,		"H2S_DE"		},
	{K7_HBMSR_S2H_DE,		"S2H_DE"		},
	{K7_HBMSR_H2FA_DE,		"H2FA_DE"		},
	{K7_HBMSR_FA2H_DE,		"FA2H_DE"		},
	{K7_HBMSR_H2FB_DE,		"H2FB_DE"		},
	{K7_HBMSR_FB2H_DE,		"FB2H_DE"		},
	{K7_HBMSR_H2MM_MEN,		"H2MM_MEN"		},
	{K7_HBMSR_H2SK_MEN,		"H2SK_MEN"		},
	{K7_HBMSR_H2FA_MEN,		"H2FA_MEN"		},
	{K7_HBMSR_H2FB_MEN,		"H2FB_MEN"		},
	{K7_HBMSR_H2PK_TCPR,		"H2PK_TCPR"		},
	{K7_HBMSR_H2SK_TCPR,		"H2SK_TCPR"		},
	{K7_HBMSR_H2M_TCPR,		"H2M_TCPR"		},
	{K7_HBMSR_H2S_TCPR,		"H2S_TCPR"		},
	{K7_HBMSR_H2FA_TCPR,		"H2FA_TCPR"		},
	{K7_HBMSR_H2FB_TCPR,		"H2FB_TCPR"		},
	{K7_HBMSR_RESERVED22,		"RESERVED22"		},
	{K7_HBMSR_HTB_FULL,		"HTB_FULL"		},
	{K7_HBMSR_H2MM_BUSY,		"H2MM_BUSY"		},
	{K7_HBMSR_H2SK_BUSY,		"H2SK_BUSY"		},
	{K7_HBMSR_H2M_BUSY,		"H2M_BUSY"		},
	{K7_HBMSR_H2S_BUSY,		"H2S_BUSY"		},
	{K7_HBMSR_H2FS_BUSY,		"H2FS_BUSY"		},
	{K7_HBMSR_H2FB_BUSY,		"H2FB_BUSY"		},
	{K7_HBMSR_RESERVED30,		"RESERVED30"		},
	{K7_HBMSR_DMA_ARB_SM,		"DMA_ARB_SM"		},
	{K7_HBMSR_DMA_ARB_WR,		"DMA_ARB_WR"		},
	{K7_HBMSR_DMA_ARB_IV,		"DMA_ARB_IV"		},
	{K7_HBMSR_DMA_ARB_RD,		"DMA_ARB_RD"		},
	{K7_HBMSR_DMA_ARB_DT,		"DMA_ARB_DT"		},
	{K7_HBMSR_DMA_LAST_BM,		"DMA_LAST_BM"		},
	{K7_HBMSR_DMA_LAST_WR,		"DMA_LAST_WR"		},
	{K7_HBMSR_DMA_LAST_IV,		"DMA_LAST_IV"		},
	{K7_HBMSR_DMA_LAST_RD,		"DMA_LAST_RD"		},
	{K7_HBMSR_DMA_LAST_DT,		"DMA_LAST_DT"		},
	{K7_HBMSR_RESERVED48,		"RESERVED48"		},
	{K7_HBMSR_H2MM_FF,		"H2MM_FF"		},
	{K7_HBMSR_MM2H_FE,		"MM2H_FE"		},
	{K7_HBMSR_H2SKA_FF,		"H2SKA_FF"		},
	{K7_HBMSR_SKA2H_FE,		"SKA2H_FE"		},
	{K7_HBMSR_H2SKB_FF,		"H2SKB_FF"		},
	{K7_HBMSR_SKB2H_FE,		"SKB2H_FE"		},
	{K7_HBMSR_H2M_FF,		"H2M_FF"		},
	{K7_HBMSR_M2H_FE,		"M2H_FE"		},
	{K7_HBMSR_H2S_FF,		"H2S_FF"		},
	{K7_HBMSR_S2H_FE,		"S2H_FE"		},
	{K7_HBMSR_H2FA_FF,		"H2FA_FF"		},
	{K7_HBMSR_FA2H_FE,		"FA2H_FE"		},
	{K7_HBMSR_H2FB_FF,		"H2FB_FF"		},
	{K7_HBMSR_FB2H_FE,		"FB2H_FE"		},
	{0,				NULL			}
};

const struct k7_regbits k7_hcr_regbits[] = {
	{32, /* 32-bit register */	"HCR" /* register name */ },
	{K7_HCR_RESERVED0,		"RESERVED0"		},
	{K7_HCR_RESUME_SRM,		"RESUME_SRM"		},
	{K7_HCR_RESUME_MRM,		"RESUME_MRM"		},
	{K7_HCR_RESERVED10,		"RESERVED10"		},
	{K7_HCR_RESERVED20,		"RESERVED20"		},
	{K7_HCR_RF_H2S_DT,		"RF_H2S_DT"		},
	{K7_HCR_F_H2S_DT,		"F_H2S_DT"		},
	{K7_HCR_RF_H2M_DT,		"RF_H2M_DT"		},
	{K7_HCR_F_H2M_DT,		"F_H2M_DT"		},
	{K7_HCR_RF_SK_DT,		"RF_SK_DT"		},
	{K7_HCR_F_SK_DT,		"F_SK_DT"		},
	{K7_HCR_RF_PK_DT,		"RF_PK_DT"		},
	{K7_HCR_F_PK_DT,		"F_PK_DT"		},
	{0,				NULL			}
};

const struct k7_regbits k7_hbmcr_regbits[] = {
	{32, /* 32-bit register */	"HBMCR" /* register name */ },
	{K7_HBMCR_MAX_BURST,		"MAX_BURST"		},
	{K7_HBMCR_RESERVED2,		"RESERVED2"		},
	{K7_HBMCR_ARB_SINGLE_STEP,	"ARB_SINGLE_STEP"	},
	{K7_HBMCR_ARB_COUNT,		"ARB_COUNT"		},
	{K7_HBMCR_H2PK_SRIOV_ON,	"H2PK_SRIOV_ON"		},
	{K7_HBMCR_H2SK_SRIOV_ON,	"H2SK_SRIOV_ON"	},
	{K7_HBMCR_RESERVED10,		"RESERVED10"		},
	{K7_HBMCR_H2M_SRIOV_ON,		"H2M_SRIOV_ON"		},
	{K7_HBMCR_RESERVED12,		"RESERVED12"		},
	{K7_HBMCR_RESERVED14,		"RESERVED14"		},
	{K7_HBMCR_RD_CH_INT_EN,		"RD_CH_INT_EN"		},
	{K7_HBMCR_HTB_BMEN,		"HTB_BMEN"		},
	{K7_HBMCR_S2H_BMEN,		"S2H_BMEN"		},
	{K7_HBMCR_H2S_BMEN,		"H2S_BMEN"		},
	{K7_HBMCR_M2H_BMEN,		"M2H_BMEN"		},
	{K7_HBMCR_H2M_BMEN,		"H2M_BMEN"		},
	{K7_HBMCR_SK2H_BMEN,		"SK2H_BMEN"		},
	{K7_HBMCR_H2SK_BMEN,		"H2SK_BMEN"		},
	{K7_HBMCR_PK2H_BMEN,		"PK2H_BMEN"		},
	{K7_HBMCR_H2PK_BMEN,		"H2PK_BMEN"		},
	{0,				NULL			}
};

void k7_force_stop_all_dma_immediately (struct k7_dev *dev)
{
	k7_modify32(dev, K7_HBMCR, K7_HBMCR_ARB_COUNT, K7_HBMCR_ARB_SINGLE_STEP);
}

const struct k7_regbits k7_hrcsr_regbits[] = {
	{32, /* 32-bit register */	"HRCSR" /* register name */ },
	{K7_HRCSR_RRAT,			"RRAT"			},
	{K7_HRCSR_RRAST,		"RRAST"			},
	{K7_HRCSR_FRAT,			"FRAT"			},
	{K7_HRCSR_FRAST,		"FRAST"			},
	{K7_HRCSR_PCT,			"PCT"			},
	{K7_HRCSR_VST,			"VST"			},
	{K7_HRCSR_TST,			"TST"			},
	{K7_HRCSR_INJ_ST,		"INJ_ST"		},
	{K7_HRCSR_TRST,			"TRST"			},
	{K7_HRCSR_STRST,		"STRST"			},
	{K7_HRCSR_MWRMBOOT,		"MWRMBOOT"		},
	{K7_HRCSR_SWRMBOOT,		"SWRMBOOT"		},
	{K7_HRCSR_POST2_COMPL,		"POST2_COMPL"		},
	{K7_HRCSR_SEG2_STARTED,		"SEG2_STARTED"		},
	{K7_HRCSR_SEG3_STARTED,		"SEG3_STARTED"		},
	{K7_HRCSR_SEG3_COMPL,		"SEG3_COMPL"		},
	{K7_HRCSR_HOST_RESET,		"HOST_RESET"		},
	{K7_HRCSR_S2M_RSTS,		"S2M_RSTS"		},
	{K7_HRCSR_M_RSTS,		"M_RSTS"		},
	{K7_HRCSR_RESERVED19,		"RESERVED19"		},
	{K7_HRCSR_MCPU_WUE,		"MCPU_WUE"		},
	{K7_HRCSR_ERROR_WUE,		"ERROR_WUE"		},
	{K7_HRCSR_TMPR_WUE,		"TMPR_WUE"		},
	{K7_HRCSR_H2S_WUE,		"H2S_WUE"		},
	{K7_HRCSR_SSP_RSTS,		"SSP_RSTS"		},
	{K7_HRCSR_SSP_HPRST,		"SSP_HPRST"		},
	{K7_HRCSR_H2S_WURQSTS,		"H2S_WURQSTS"		},
	{K7_HRCSR_H2S_WURQST,		"H2S_WURQST"		},
	{0,				NULL			}
};

const struct k7_regbits k7_hcsr_regbits[] = {
	{64, /* 64-bit register */	"HCSR" /* register name */ },
	{K7_HCSR_RESERVED0,		"RESERVED0"		},
	{K7_HCSR_H2S_EMPTY,		"H2S_EMPTY"		},
	{K7_HCSR_S2H_FULL,		"S2H_FULL"		},
	{K7_HCSR_H2M_EMPTY,		"H2M_EMPTY"		},
	{K7_HCSR_M2H_FULL,		"M2H_FULL"		},
	{K7_HCSR_RESERVED8,		"RESERVED8"		},
	{K7_HCSR_LOWBAT,		"LOWBAT"		},
	{K7_HCSR_RESERVED10,		"RESERVED10"		},
	{K7_HCSR_PM_CURR_TEMP,		"~PM_CURR_TEMP"		},
	{K7_HCSR_PM_TAMPER_TEMP,	"-PM_TAMPER_TEMP"	},
	{K7_HCSR_RESERVED32,		"RESERVED32"		},
	{K7_HCSR_ASIC_REV_ID,		"=ASIC_REV_ID"		},
	{K7_HCSR_CARD_REV_ID,		"=CARD_REV_ID"		},
	{0,				NULL			}
};

const struct k7_regbits k7_hmvmc_regbits[] = {
	{32, /* 32-bit register */	"HMVMC" /* register name */ },
	{K7_HMVMC_MSIX_1_VEC,		"MSIX_1_VEC"		},
	{K7_HMVMC_MSIX_2_VEC,		"MSIX_2_VEC"		},
	{K7_HMVMC_RESERVED2,		"RESERVED2"		},
	{K7_HMVMC_MSIX_4_VEC,		"MSIX_4_VEC"		},
	{K7_HMVMC_RESERVED4,		"RESERVED4"		},
	{K7_HMVMC_MSIX_8_VEC,		"MSIX_8_VEC"		},
	{K7_HMVMC_RESERVED8,		"RESERVED8"		},
	{K7_HMVMC_MSIX_16_VEC,		"MSIX_16_VEC"		},
	{K7_HMVMC_RESERVED16,		"RESERVED16"		},
	{0,				NULL			}
};

const struct k7_regbits k7_hcfgr1_regbits[] = {
	{64, /* 64-bit register */	"HCFGR1" /* register name */ },
	{K7_HCFGR1_AIB_TMR_VAL,		"AIB_TMR_VAL"		},
	{K7_HCFGR1_WR_FIFO_MODE_SEL,	"WR_FIFO_MODE_SEL"	},
	{K7_HCFGR1_TRC_DMA,		"TRC_DMA"		},
	{K7_HCFGR1_TRC_REG,		"TRC_REG"		},
	{K7_HCFGR1_TRC_CPE,		"TRC_CPE"		},
	{K7_HCFGR1_AIB_ECC_INJ_SEL,	"AIB_ECC_INJ_SEL"	},
	{K7_HCFGR1_AIB_ECC_INJ_VAL,	"AIB_ECC_INJ_VAL"	},
	{K7_HCFGR1_AIB_RX_FENCE_INJ,	"AIB_RX_FENCE_INJ"	},
	{K7_HCFGR1_AIB_RX_FENCE_EN,	"AIB_RX_FENCE_EN"	},
	{K7_HCFGR1_AIB_TXDAT_ERR_EN,	"AIB_TXDAT_ERR_EN",	},
	{K7_HCFGR1_AIB_RXCH_FIX_EN,	"AIB_RXCH_FIX_EN",	},
	{K7_HCFGR1_RESERVED20,		"RESERVED20"		},
	{K7_HCFGR1_MSIX_ECC_INJ_SEL,	"MSIX_ECC_INJ_SEL"	},
	{K7_HCFGR1_MSIX_ECC_INJ_VAL,	"MSIX_ECC_INJ_VAL"	},
	{K7_HCFGR1_RESERVED32,		"RESERVED32"		},
	{K7_HCFGR1_PF_FLR_TIMER_VALUE,	"=PF_FLR_TIMER_VALUE"	},
	{0,				NULL			}
};

const struct k7_regbits k7_m2hcs_regbits[] = {
	{64, /* 64-bit register */	"M2HCS" /* register name */ },
	{K7_M2HCS_STATE,		"STATE"			},
	{K7_M2HCS_RESERVED16,		"RESERVED16"		},
	{K7_M2HCS_TX_SIZE,		"TX_SIZE"		},
	{K7_M2HCS_RESERVED28,		"RESERVED28"		},
	{K7_M2HCS_FLUSH,		"FLUSH"			},
	{K7_M2HCS_RESERVED32,		"RESERVED32"		},
	{K7_M2HCS_VFID,			"VFID"			},
	{K7_M2HCS_RESERVED40,		"RESERVED40"		},
	{K7_M2HCS_AVAIL_COUNT,		"+AVAIL_COUNT"		},
	{0,				NULL			}
};

const struct k7_regbits k7_h2mcs_regbits[] = {
	{64, /* 64-bit register */	"H2MCS" /* register name */ },
	{K7_H2MCS_STATE,		"STATE"			},
	{K7_H2MCS_RESERVED24,		"RESERVED24"		},
	{K7_H2MCS_VFID,			"VFID"			},
	{K7_H2MCS_RESERVED32,		"RESERVED32"		},
	{K7_H2MCS_RD_PENDING,		"RD_PENDING"		},
	{K7_H2MCS_RESERVED48,		"RESERVED48"		},
	{K7_H2MCS_AVAIL_COUNT,		"+AVAIL_COUNT"		},
	{0,				NULL			}
};

const struct k7_regbits k7_h2mdtc_regbits[] = {
	{64, /* 64-bit register */	"H2MDTC" /* register name */ },
	{K7_H2MDTC_CTRL,		"CTRL"			},
	{K7_H2MDTC_BUF_BC,		"BUF_BC"		},
	{K7_H2MDTC_RSVD,		"RSVD"			},
	{K7_H2MDTC_HRB_BC,		"HRB_BC"		},
	{K7_H2MDTC_SIGN,		"SIGN"			},
	{0,				NULL			}
};

const struct k7_regbits k7_htbtc_regbits[] = {
	{64, /* 64-bit register */	"HTBTC" /* register name */ },
	{K7_HTBTC_RESERVED0,		"RESERVED0"		},
	{K7_HTBTC_TC,			"=TC"			},
	{K7_HTBTC_MBZ,			"MBZ"			},
	{0,				NULL			}
};

const struct k7_regbits k7_hderr_regbits[] = {
	{32, /* 32-bit register */	"HDERR" /* register name */ },
	{K7_HDERR_RD_CH_ID,		"@RD_CH_ID"		},
	{K7_HDERR_WR_CH_ID,		"@WR_CH_ID"		},
	{K7_HDERR_RESERVED4,		"RESERVED4"		},
	{K7_HDERR_RD_DT_SIG,		"RD_DT_SIG"		},
	{K7_HDERR_RD_HRB,		"RD_HRB"		},
	{K7_HDERR_RD_DT_MAX,		"RD_DT_MAX"		},
	{K7_HDERR_RD_DT_BC,		"RD_DT_BC"		},
	{K7_HDERR_RD_DT_ALIGN,		"RD_DT_ALIGN"		},
	{K7_HDERR_RD_DT_512,		"RD_DT_512"		},
	{K7_HDERR_RD_DT_EOC,		"RD_DT_EOC"		},
	{K7_HDERR_RD_HRB_SIG,		"RD_HRB_SIG"		},
	{K7_HDERR_RESERVED20,		"RESERVED20"		},
	{K7_HDERR_WR_DT_SIG,		"WR_DT_SIG"		},
	{K7_HDERR_RESERVED25,		"RESERVED25"		},
	{K7_HDERR_WR_VF_FLUSHED,	"WR_VF_FLUSHED"		},
	{K7_HDERR_RESERVED25,		"RESERVED25"		},
	{K7_HDERR_WR_DT_BC,		"WR_DT_BC"		},
	{K7_HDERR_WR_DT_ALIGN,		"WR_DT_ALIGN"		},
	{K7_HDERR_WR_DT_512,		"WR_DT_512"		},
	{K7_HDERR_WR_DT_EOC,		"WR_DT_EOC"		},
	{K7_HDERR_WR_HRB_SIG,		"WR_HRB_SIG"		},
	{0,				NULL			}
};

const struct k7_regbits k7_h2xcs_regbits[] = {
	{64, /* 64-bit register */	"H2XCS" /* register name */ },
	{K7_H2XCS_CURR_STATE,		"CURR_STATE"		},
	{K7_H2XCS_RESERVED24,		"RESERVED24"		},
	{K7_H2XCS_VFID,			"VFID"			},
	{K7_H2XCS_RESERVED32,		"RESERVED32"		},
	{K7_H2XCS_RD_PENDING,		"RD_PENDING"		},
	{K7_H2XCS_RESERVED48,		"RESERVED48"		},
	{K7_H2XCS_AVAIL_COUNT,		"AVAIL_COUNT"		},
	{0,				NULL			}
};

const struct k7_regbits k7_x2hcs_regbits[] = {
	{64, /* 64-bit register */	"X2HCS" /* register name */ },
	{K7_X2HCS_CURR_STATE,		"CURR_STATE"		},
	{K7_X2HCS_RESERVED16,		"RESERVED16"		},
	{K7_X2HCS_TX_SIZE,		"TX_SIZE"		},
	{K7_X2HCS_RESERVED28,		"RESERVED28"		},
	{K7_X2HCS_FLUSH,		"FLUSH"			},
	{K7_X2HCS_RESERVED32,		"RESERVED32"		},
	{K7_X2HCS_VFID,			"VFID"			},
	{K7_X2HCS_RESERVED48,		"RESERVED48"		},
	{K7_X2HCS_AVAIL_COUNT,		"AVAIL_COUNT"		},
	{0,				NULL			}
};

const struct k7_regbits k7_pf2vf_regbits[] = {
	{64, /* 64-bit register */	"PF2VF" /* register name */ },
	{K7_PF2VF_VF0_FULL,		"VF0_FULL"		},
	{K7_PF2VF_VF0_WE,		"VF0_WE"		},
	{K7_PF2VF_VF1_FULL,		"VF1_FULL"		},
	{K7_PF2VF_VF1_WE,		"VF1_WE"		},
	{K7_PF2VF_VF2_FULL,		"VF2_FULL"		},
	{K7_PF2VF_VF2_WE,		"VF2_WE"		},
	{K7_PF2VF_VF3_FULL,		"VF3_FULL"		},
	{K7_PF2VF_VF3_WE,		"VF3_WE"		},
	{K7_PF2VF_VF4_FULL,		"VF4_FULL"		},
	{K7_PF2VF_VF4_WE,		"VF4_WE"		},
	{K7_PF2VF_VF5_FULL,		"VF5_FULL"		},
	{K7_PF2VF_VF5_WE,		"VF5_WE"		},
	{K7_PF2VF_VF6_FULL,		"VF6_FULL"		},
	{K7_PF2VF_VF6_WE,		"VF6_WE"		},
	{K7_PF2VF_VF7_FULL,		"VF7_FULL"		},
	{K7_PF2VF_VF7_WE,		"VF7_WE"		},
	{K7_PF2VF_VF8_FULL,		"VF8_FULL"		},
	{K7_PF2VF_VF8_WE,		"VF8_WE"		},
	{K7_PF2VF_VF9_FULL,		"VF9_FULL"		},
	{K7_PF2VF_VF9_WE,		"VF9_WE"		},
	{K7_PF2VF_VF10_FULL,		"VF10_FULL"		},
	{K7_PF2VF_VF10_WE,		"VF10_WE"		},
	{K7_PF2VF_VF11_FULL,		"VF11_FULL"		},
	{K7_PF2VF_VF11_WE,		"VF11_WE"		},
	{K7_PF2VF_VF12_FULL,		"VF12_FULL"		},
	{K7_PF2VF_VF12_WE,		"VF12_WE"		},
	{K7_PF2VF_VF13_FULL,		"VF13_FULL"		},
	{K7_PF2VF_VF13_WE,		"VF13_WE"		},
	{K7_PF2VF_VF14_FULL,		"VF14_FULL"		},
	{K7_PF2VF_VF14_WE,		"VF14_WE"		},
	{K7_PF2VF_VF15_FULL,		"VF15_FULL"		},
	{K7_PF2VF_VF15_WE,		"VF15_WE"		},
	{K7_PF2VF_MSG,			"MSG"			},
	{0,				NULL			}
};
