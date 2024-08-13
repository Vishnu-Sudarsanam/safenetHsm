/*
 * Copyright (c) 2013-2017 Safenet.  All rights reserved.
 *
 * regs.h -- register definitions etc.. for debugging.
 */
#ifndef __K7_REGS_H__
#define __K7_REGS_H__

struct k7_regbits {
	const u64		mask;
	const char *		name;
};

void k7_dumpreg (struct k7_dev *dev, const char *label, u64 reg, const struct k7_regbits *regbits);

u32  k7_read32   (struct k7_dev *dev, unsigned int offset);
u64  k7_read64   (struct k7_dev *dev, unsigned int offset);
void k7_write16  (struct k7_dev *dev, unsigned int offset, u16 data);
void k7_write32  (struct k7_dev *dev, unsigned int offset, u32 data);
void k7_write64  (struct k7_dev *dev, unsigned int offset, u64 data);
u32  k7_flush32  (struct k7_dev *dev, unsigned int offset, u32 data);
u64  k7_flush64  (struct k7_dev *dev, unsigned int offset, u64 data);
void k7_modify64 (struct k7_dev *dev, unsigned int offset, u64 clear_bits, u64 set_bits);
void k7_modify32 (struct k7_dev *dev, unsigned int offset, u32 clear_bits, u32 set_bits);

unsigned int k7_dma_base (struct k7_dev *dev, unsigned int target);

#define K7_READ32(offset)       k7_read32 (dev, offset)
#define K7_READ64(offset)       k7_read64 (dev, offset)
#define K7_WRITE16(offset,data) k7_write16(dev, offset, data)
#define K7_WRITE32(offset,data) k7_write32(dev, offset, data)
#define K7_WRITE64(offset,data) k7_write64(dev, offset, data)
#define K7_FLUSH32(offset,data) k7_flush32(dev, offset, data)
#define K7_FLUSH64(offset,data) k7_flush64(dev, offset, data)

#define K7_MAX_HRB_LEN	 0xfffe8	/* Max bytecount for any HRB */

/*
 * Register offsets
 */
enum {
	K7_H2M_MBX			= 0x0000,		/* Host-to-MCPU Mailbox (64-bit) */
	K7_M2H_MBX			= 0x0008,		/* MCPU-to-Host Mailbox (64-bit) */
	K7_H2S_MBX			= 0x0010,		/* Host-to-SSP Mailbox (64-bit) */
	K7_S2H_MBX			= 0x0018,		/* SSP-to-Host Mailbox (64-bit) */
	K7_PF2VF_MBX			= 0x0af0,		/* PF2VF / VF2PF Mailbox (64-bit) */
	K7_H2SKA_DMA_VF_ARB_CRD		= 0x0a48,		/* Host to SKCH DMA VF Arbiter Credit Register */
	K7_HTBWA			= 0x0bc0,		/* HTB Write Address (64-bit) */

	/*
	 * Base offsets for 2-way blocks of DMA registers:
	 */
	K7_PKU_DMA_BASE			= 0x0800,		/* PKA/ModularMath dma regs base offset */
	K7_SKU_DMA_BASE			= 0x0880,		/* SKU A dma regs base offset */
	K7_SKUB_DMA_BASE		= 0x08c0,		/* SKU B dma regs base offset */
	K7_MCPU_DMA_BASE		= 0x0900,		/* MCPU  dma regs base offset */
	K7_SSP_DMA_BASE			= 0x09c0,		/* SSP   dma regs base offset */

	K7_VF_MAX_HRB_LEN		= 0x0a00,		/* PF-only, 64-bit, use bits 4..23 */
	K7_VF_DMA_MASTER_EN		= 0x0a08,		/* PF-only */

	/*
	 * DMA register offsets from *_DMA_BASE offsets:
	 * eg. TCP registers are typically 0x.....890
	 */
	K7_H2X_CH_STATUS		= 0x0000,		/* Host-to-xxx channel status (64-bit) */
	K7_H2X_TCP			= 0x0010,		/* Host-to-xxx Transfer Command Port register (64-bit) */
	K7_H2X_BUFF_PTR			= 0x0018,		/* Host-to-xxx channel buffer pointer (64-bit) */
	K7_H2X_DT_CTRL			= 0x0020,		/* Host-to-xxx channel DT controls (64-bit) */
	K7_H2X_LAST_DT_PTR		= 0x0028,		/* Host-to-xxx channel last DT pointer (64-bit) */
	K7_H2X_FIFO_DIN			= 0x0030,		/* Host-to-xxx FIFO write port (64-bit) */

	K7_X2H_CH_STATUS		= 0x0400,		/* xxx-to_Host channel status (64-bit) */
	K7_X2H_LAST_HEADER		= 0x0410,		/* xxx-to_Host last reply hdr processed by state machine (64-bit) */
	K7_X2H_BUFF_PTR			= 0x0418,		/* xxx-to-Host channel buffer pointer (64-bit) */
	K7_X2H_DT_CTRL			= 0x0420,		/* xxx-to-Host channel DT controls (64-bit) */
	K7_X2H_DT_PTR			= 0x0428,		/* xxx-to-Host channel current pointer (64-bit) */
	K7_X2H_FIFO_DOUT		= 0x0430,		/* xxx-to-Host FIFO read port (64-bit) */
	K7_X2H_FIFO_AUX_DOUT		= 0x0438,		/* xxx-to-Host FIFO Aux read port (64-bit) */

	K7_H2MLDT			= K7_MCPU_DMA_BASE + K7_H2X_LAST_DT_PTR,  /* debug (PF only) */
};

/*
 * Host Interrupt Status/Enable Registers
 */
enum {
	K7_HISR				= 0x00a0,		/* Host Interrupt Status register (32-bit) */
	K7_HIER				= 0x00a8,		/* Host Interrupt Enable register (32-bit) */
	K7_HISR_HW_ERR			= BE32BIT( 0),		/* Hardware error */
	K7_HISR_RESERVED1		= BE32MSK( 1, 2),	/* (2-bits) */
	K7_HISR_ACCESS_ERR		= BE32BIT( 3),		/* Access error: host attempted r/w of bad reg addr */
	K7_HISR_RECOV_DMA_ERR		= BE32BIT( 4),		/* Recoverable DMA error */
	K7_HISR_UNRECOV_DMA_ERR		= BE32BIT( 5),		/* Un-recoverable DMA error */
	K7_HISR_SOFT_TAMPER		= BE32BIT( 6),		/* Soft Tamper */
	K7_HISR_HARD_TAMPER		= BE32BIT( 7),		/* Hard Tamper */
	K7_HISR_H2M			= BE32BIT( 8),		/* mailbox: Host to MCPU */
	K7_HISR_M2H			= BE32BIT( 9),		/* mailbox: MCPU to Host */
	K7_HISR_H2S			= BE32BIT(10),		/* mailbox: Host to SSP */
	K7_HISR_S2H			= BE32BIT(11),		/* mailbox: SSP to Host */
	K7_HISR_RESERVED12		= BE32MSK(12, 23),	/* (12-bits) */
	K7_HISR_H_TEMP_WRNG		= BE32BIT(24),		/* High Temperature Warning */
	K7_HISR_RESERVED25		= BE32BIT(25),		/* (1-bit) */
	K7_HISR_LOWBAT			= BE32BIT(26),		/* Low Battery */
	K7_HISR_PF2VF_MBX		= BE32BIT(27),		/* PF to VF mailbox full */
	K7_HISR_SRM_ATT			= BE32BIT(28),		/* SSP Reply Message Attention */
	K7_HISR_MRM_ATT			= BE32BIT(29),		/* Host Message Reply */
	K7_HISR_HTB_BF			= BE32BIT(30),		/* HTB Buffer Full */
	K7_HISR_HTB_INT			= BE32BIT(31),		/* Host Transfer Completed */
};
extern const struct k7_regbits k7_hisr_regbits[];

#define K7_DMA_IRQS	(	K7_HISR_RECOV_DMA_ERR | K7_HISR_UNRECOV_DMA_ERR  |\
				K7_HISR_MRM_ATT | K7_HISR_HTB_INT |\
				(K7_HISR_HTB_BF * K7_USE_HTB_BF) )

#define K7_IRQS_ENABLED (	K7_DMA_IRQS | K7_HISR_HW_ERR | K7_HISR_ACCESS_ERR |\
				K7_HISR_SOFT_TAMPER | K7_HISR_HARD_TAMPER |\
				K7_HISR_H2M | K7_HISR_M2H |\
				K7_HISR_H_TEMP_WRNG | K7_HISR_LOWBAT |\
				K7_HISR_PF2VF_MBX )

/*
 * Host Bus-Master Status Register
 */
enum {
	K7_HBMSR			= 0x0b88,		/* Host Bus-Master Status register (64-bit) */
	K7_HBMSR_H2PK_DE		= BE64BIT( 0),		/* Host-to-PKA   disabled by error */
	K7_HBMSR_PK2H_DE		= BE64BIT( 1),		/* PKA-to-Host   disabled by error */
	K7_HBMSR_H2SK_DE		= BE64BIT( 2),		/* Host-to-SKU   disabled by error */  /* both A and B */
	K7_HBMSR_SK2H_DE		= BE64BIT( 3),		/* SKU-to-Host   disabled by error */  /* both A and B */
	K7_HBMSR_H2M_DE			= BE64BIT( 4),		/* Host-to-MCPU  disabled by error */
	K7_HBMSR_M2H_DE			= BE64BIT( 5),		/* MCPU-to-Host  disabled by error */
	K7_HBMSR_H2S_DE			= BE64BIT( 6),		/* Host-to-SSP   disabled by error */
	K7_HBMSR_S2H_DE			= BE64BIT( 7),		/* SSP-to-Host   disabled by error */
	K7_HBMSR_H2FA_DE		= BE64BIT( 8),		/* Host-to-FPGAA disabled by error */
	K7_HBMSR_FA2H_DE		= BE64BIT( 9),		/* FPGAA-to-Host disabled by error */
	K7_HBMSR_H2FB_DE		= BE64BIT(10),		/* Host-to-FPGAB disabled by error */
	K7_HBMSR_FB2H_DE		= BE64BIT(11),		/* FPGAB-to-Host disabled by error */
	K7_HBMSR_H2MM_MEN		= BE64BIT(12),		/* Host-to-MM    enabled by MCPU */
	K7_HBMSR_H2SK_MEN		= BE64BIT(13),		/* Host-to-SKCH  enabled by MCPU */
	K7_HBMSR_H2FA_MEN		= BE64BIT(14),		/* Host-to-FPGAA enabled by MCPU */
	K7_HBMSR_H2FB_MEN		= BE64BIT(15),		/* Host-to-FPGAB enabled by MCPU */
	K7_HBMSR_H2PK_TCPR		= BE64BIT(16),		/* Host-to-PKA   idle, safe to update TCP */
	K7_HBMSR_H2SK_TCPR		= BE64BIT(17),		/* Host-to-SKU   idle, safe to update TCP */  /* both A and B */
	K7_HBMSR_H2M_TCPR		= BE64BIT(18),		/* Host-to-MCPU  idle, safe to update TCP */
	K7_HBMSR_H2S_TCPR		= BE64BIT(19),		/* Host-to-SSP   idle, safe to update TCP */
	K7_HBMSR_H2FA_TCPR		= BE64BIT(20),		/* Host-to-FPGAA idle, safe to update TCP */
	K7_HBMSR_H2FB_TCPR		= BE64BIT(21),		/* Host-to-FPGAB idle, safe to update TCP */
	K7_HBMSR_RESERVED22		= BE64BIT(22),		/* (1-bit) */
	K7_HBMSR_HTB_FULL		= BE64BIT(23),		/* HTB buffer is full or not-initialized */
	K7_HBMSR_H2MM_BUSY		= BE64BIT(24),		/* H2MM channel currently processing a request */
	K7_HBMSR_H2SK_BUSY		= BE64BIT(25),		/* H2SK channel currently processing a request */
	K7_HBMSR_H2M_BUSY		= BE64BIT(26),		/* H2M  channel currently processing a request */
	K7_HBMSR_H2S_BUSY		= BE64BIT(27),		/* H2S  channel currently processing a request */
	K7_HBMSR_H2FS_BUSY		= BE64BIT(28),		/* H2FA channel currently processing a request */
	K7_HBMSR_H2FB_BUSY		= BE64BIT(29),		/* H2FB channel currently processing a request */
	K7_HBMSR_RESERVED30		= BE64MSK(30,32),	/* (3-bits) */
	K7_HBMSR_DMA_ARB_SM		= BE64MSK(33,35),	/* current state of the DMA ch arbiter (3-bits) */
	K7_HBMSR_DMA_ARB_WR		= BE64BIT(36),		/* DMA ch arbiter current op is data-write */
	K7_HBMSR_DMA_ARB_IV		= BE64BIT(37),		/* DMA ch arbiter current op is IV-write */
	K7_HBMSR_DMA_ARB_RD		= BE64BIT(38),		/* DMA ch arbiter current op is data-read */
	K7_HBMSR_DMA_ARB_DT		= BE64BIT(39),		/* DMA ch arbiter current op is DT-fetch */
	K7_HBMSR_DMA_LAST_BM		= BE64MSK(40,43),	/* Last DMA ch active (0xf is dummy post-reset val) (4-bits) */
	K7_HBMSR_DMA_LAST_WR		= BE64BIT(44),		/* Last DMA op was data-write to host mem */
	K7_HBMSR_DMA_LAST_IV		= BE64BIT(45),		/* Last DMA op was IV-write to host HTB */
	K7_HBMSR_DMA_LAST_RD		= BE64BIT(46),		/* Last DMA op was data-read from host mem */
	K7_HBMSR_DMA_LAST_DT		= BE64BIT(47),		/* Last DMA op was DT-fetch from host mem */
	K7_HBMSR_RESERVED48		= BE64MSK(48,49),	/* (2-bits) */
	K7_HBMSR_H2MM_FF		= BE64BIT(50),		/* Host-to-PKA FIFO is full */
	K7_HBMSR_MM2H_FE		= BE64BIT(51),		/* PKA-to-Host FIFO is empty */
	K7_HBMSR_H2SKA_FF		= BE64BIT(52),		/* Host-to-SKCHA FIFO is full */
	K7_HBMSR_SKA2H_FE		= BE64BIT(53),		/* SKCHA-to-Host FIFO is empty */
	K7_HBMSR_H2SKB_FF		= BE64BIT(54),		/* Host-to-SKCHB FIFO is full */
	K7_HBMSR_SKB2H_FE		= BE64BIT(55),		/* SKCHB-to-Host FIFO is empty */
	K7_HBMSR_H2M_FF			= BE64BIT(56),		/* Host-to-MCPU  FIFO is full */
	K7_HBMSR_M2H_FE			= BE64BIT(57),		/* MCPU-to-Host  FIFO is empty */
	K7_HBMSR_H2S_FF			= BE64BIT(58),		/* Host-to-SSP   FIFO is full */
	K7_HBMSR_S2H_FE			= BE64BIT(59),		/* SSP-to-Host   FIFO is empty */
	K7_HBMSR_H2FA_FF		= BE64BIT(60),		/* Host-to-FPGAA FIFO is full */
	K7_HBMSR_FA2H_FE		= BE64BIT(61),		/* FPGAA-to-Host FIFO is empty */
	K7_HBMSR_H2FB_FF		= BE64BIT(62),		/* Host-to-FPGAB FIFO is full */
	K7_HBMSR_FB2H_FE		= BE64BIT(63),		/* FPGAB-to-Host FIFO is empty */
};
extern const struct k7_regbits k7_hbmsr_regbits[];

/*
 * Host Control Register
 */
enum {
	K7_HCR				= 0x0b90,		/* Host Control register (32-bit) */
	K7_HCR_RESERVED0		= BE32MSK( 0, 7),	/* (8-bits) */
	K7_HCR_RESUME_SRM		= BE32BIT( 8),		/* Resume with next SSP Reply message transfer */
	K7_HCR_RESUME_MRM		= BE32BIT( 9),		/* Resume with next MCPU Reply message transfer */
	K7_HCR_RESERVED10		= BE32MSK(10,19),	/* (10-bits) */
	K7_HCR_RESERVED20		= BE32MSK(20,23),	/* (4-bits) formerly for FPGA */
	K7_HCR_RF_H2S_DT		= BE32BIT(24),		/* Re-Fetch Host-to-SSP EOC DT */
	K7_HCR_F_H2S_DT			= BE32BIT(25),		/* Fetch Host-to-SSP first DT */
	K7_HCR_RF_H2M_DT		= BE32BIT(26),		/* Re-Fetch Host-to-MCPU EOC DT */
	K7_HCR_F_H2M_DT			= BE32BIT(27),		/* Fetch Host-to-MCPU first DT */
	K7_HCR_RF_SK_DT			= BE32BIT(28),		/* Re-Fetch Host-to-SKU EOC DT */
	K7_HCR_F_SK_DT			= BE32BIT(29),		/* Fetch Host-to-SKU first DT */
	K7_HCR_RF_PK_DT			= BE32BIT(30),		/* Re-Fetch Host-to-PKA EOC DT */
	K7_HCR_F_PK_DT			= BE32BIT(31),		/* Fetch Host-to-PKA first DT */
};
extern const struct k7_regbits k7_hcr_regbits[];

/*
 * Host Bus-Master Control Register
 */
enum {
	K7_HBMCR			= 0x0b80,		/* Host Bus-Master Control register (32-bit) */
	K7_HBMCR_MAX_BURST		= BE32MSK( 0,1),	/* Max burst size for PCIe transactions */
	K7_HBMCR_RESERVED2		= BE32BIT( 2),		/* (1-bit) */
	K7_HBMCR_ARB_SINGLE_STEP	= BE32BIT( 3),		/* Enable channel arbiter single-step debug mode */
	K7_HBMCR_ARB_COUNT		= BE32MSK( 4, 7),	/* (4-bits) Number of AIB transactions to grant before waiting */
	K7_HBMCR_H2PK_SRIOV_ON		= BE32BIT( 8),		/* Enable Host-to-PKA  virtual function arbiter */
	K7_HBMCR_H2SK_SRIOV_ON		= BE32BIT( 9),		/* Enable Host-to-SKCH virtual function arbiter */
	K7_HBMCR_RESERVED10		= BE32BIT(10),		/* Enable Host-to-MCPU virtual function arbiter */
	K7_HBMCR_H2M_SRIOV_ON		= BE32BIT(11),		/* Enable Host-to-MCPU virtual function arbiter */
	K7_HBMCR_RESERVED12		= BE32MSK(12,13),	/* (2-bits) formerly for FPGA */
	K7_HBMCR_RESERVED14		= BE32BIT(14),		/* (1-bit) */
	K7_HBMCR_RD_CH_INT_EN		= BE32BIT(15),		/* 1 == VF read channel interrupts (RX_NOTIFY) enabled */
	K7_HBMCR_RESERVED16		= BE32MSK(16,18),	/* (3-bits) */
	K7_HBMCR_RESERVED19		= BE32MSK(19,22),	/* (4-bits) formerly for FPGA */
	K7_HBMCR_HTB_BMEN		= BE32BIT(23),		/* Enable IV-to-HTB DMA (from all channels) */
	K7_HBMCR_S2H_BMEN		= BE32BIT(24),		/* Enable SSP-to-Host DMA */
	K7_HBMCR_H2S_BMEN		= BE32BIT(25),		/* Enable Host-to-SSP DMA */
	K7_HBMCR_M2H_BMEN		= BE32BIT(26),		/* Enable MCPU-to-Host DMA */
	K7_HBMCR_H2M_BMEN		= BE32BIT(27),		/* Enable Host-to-MCPU DMA */
	K7_HBMCR_SK2H_BMEN		= BE32BIT(28),		/* Enable SKU-to-Host DMA */
	K7_HBMCR_H2SK_BMEN		= BE32BIT(29),		/* Enable Host-to-SKU DMA */
	K7_HBMCR_PK2H_BMEN		= BE32BIT(30),		/* Enable PKA-to-Host DMA */
	K7_HBMCR_H2PK_BMEN		= BE32BIT(31),		/* Enable Host-to-PKA DMA */
};
extern const struct k7_regbits k7_hbmcr_regbits[];

/*
 * Host Reset Control Status Register
 */
enum {
	K7_HRCSR			= 0x0608,		/* Host Reset Control Status register (32-bit) */
	K7_HRCSR_RRAT			= BE32BIT( 0),		/* Reset Required After Tamper */
	K7_HRCSR_RRAST			= BE32BIT( 1),		/* Reset Required After Soft Tamper */
	K7_HRCSR_FRAT			= BE32BIT( 2),		/* First Reset After Tamper */
	K7_HRCSR_FRAST			= BE32BIT( 3),		/* First Reset After Soft Tamper */
	K7_HRCSR_PCT			= BE32BIT( 4),		/* Permanent Card Tamper */
	K7_HRCSR_VST			= BE32BIT( 5),		/* Voltage Soft Tamper */
	K7_HRCSR_TST			= BE32BIT( 6),		/* Temperature Soft Tamper */
	K7_HRCSR_INJ_ST			= BE32BIT( 7),		/* Soft Tamper Injection */
	K7_HRCSR_TRST			= BE32BIT( 8),		/* Chip is held under hard tamper reset */
	K7_HRCSR_STRST			= BE32BIT( 9),		/* Chip is held under soft tamper reset */
	K7_HRCSR_MWRMBOOT		= BE32BIT(10),		/* MCPU Warm Boot */
	K7_HRCSR_SWRMBOOT		= BE32BIT(11),		/* SSP Warm Boot */
	K7_HRCSR_POST2_COMPL		= BE32BIT(12),		/* POST2 Complete */
	K7_HRCSR_SEG2_STARTED		= BE32BIT(13),		/* Segment 2 Started */
	K7_HRCSR_SEG3_STARTED		= BE32BIT(14),		/* Segment 3 Started */
	K7_HRCSR_SEG3_COMPL		= BE32BIT(15),		/* Segment 3 Complete */
	K7_HRCSR_HOST_RESET		= BE32BIT(16),		/* Resets the chip without PCIe reset (hold for 10msec) */
	K7_HRCSR_S2M_RSTS		= BE32BIT(17),		/* SSP to MCPU Reset Control Status */
	K7_HRCSR_M_RSTS			= BE32BIT(18),		/* MCPU Reset Status */
	K7_HRCSR_RESERVED19		= BE32MSK(19,20),	/* (2-bits) */
	K7_HRCSR_MCPU_WUE		= BE32BIT(21),		/* MCPU Wake-Up Event */
	K7_HRCSR_ERROR_WUE		= BE32BIT(22),		/* Error Wake-Up Event */
	K7_HRCSR_TMPR_WUE		= BE32BIT(23),		/* Tamper Wake-Up Event */
	K7_HRCSR_H2S_WUE		= BE32MSK(24,27),	/* (4-bits) Host to SSP Wake-Up Event/Reason */
	K7_HRCSR_SSP_RSTS		= BE32BIT(28),		/* SSP Reset Status */
	K7_HRCSR_SSP_HPRST		= BE32BIT(29),		/* SSP High Priority Reset */
	K7_HRCSR_H2S_WURQSTS		= BE32BIT(30),		/* Host to SSP Wake-Up Request Status */
	K7_HRCSR_H2S_WURQST		= BE32BIT(31),		/* Host to SSP Wake-Up Request */
};
extern const struct k7_regbits k7_hrcsr_regbits[];

/*
 * Host Control Status Register
 */
enum {
	K7_HCSR				= 0x0610,		/* Host Control Status register (64-bit) */
	K7_HCSR_RESERVED0		= BE64MSK( 0, 3),	/* (4-bits) */
	K7_HCSR_H2S_EMPTY		= BE64BIT( 4),		/* H2S mailbox empty */
	K7_HCSR_S2H_FULL		= BE64BIT( 5),		/* S2H mailbox full */
	K7_HCSR_H2M_EMPTY		= BE64BIT( 6),		/* H2M mailbox empty */
	K7_HCSR_M2H_FULL		= BE64BIT( 7),		/* M2H mailbox full */
	K7_HCSR_RESERVED8		= BE64BIT( 8),		/* (1-bits) */
	K7_HCSR_LOWBAT			= BE64BIT( 9),		/* Low Battery indication */
	K7_HCSR_RESERVED10		= BE64MSK(10,15),	/* (6-bits) */
	K7_HCSR_PM_CURR_TEMP		= BE64MSK(16,23),	/* Current temperature (C) */
	K7_HCSR_PM_TAMPER_TEMP		= BE64MSK(24,31),	/* Temperature (C) that triggered soft tamper */
	K7_HCSR_RESERVED32		= BE64MSK(32,47),	/* (16-bits) */
	K7_HCSR_ASIC_REV_ID		= BE64MSK(48,55),	/* ASIC revision ID */
	K7_HCSR_CARD_REV_ID		= BE64MSK(56,63),	/* Card revision ID */
};
extern const struct k7_regbits k7_hcsr_regbits[];

/*
 * Host MSX-X Vector Mapping Control Register
 */
enum {
	K7_HMVMC			= 0x00B0,		/* Host MSX-X Vector Mapping Control Register (32-bit) */
	K7_HMVMC_MSIX_1_VEC		= BE32BIT( 0),		/* 1 vector: HISR 0-31 */
	K7_HMVMC_MSIX_2_VEC		= BE32BIT( 1),		/* 2 vectors: HISR 0-7,8-31 */
	K7_HMVMC_RESERVED2		= BE32BIT( 2),		/*  */
	K7_HMVMC_MSIX_4_VEC		= BE32BIT( 3),		/* 4 vectors: HISR 0-7,8-29,30,31 (preferred) */
	K7_HMVMC_RESERVED4		= BE32MSK( 4, 6),	/*  */
	K7_HMVMC_MSIX_8_VEC		= BE32BIT( 7),		/* 8 vectors: HISR 0-7,12-29,8,9,10,11,30,31 */
	K7_HMVMC_RESERVED8		= BE32MSK( 8,14),	/*  */
	K7_HMVMC_MSIX_16_VEC		= BE32BIT(15),		/* 16 vectors: HISR 0,3,4,5,6,7,8,9,10,11/27,24,26,28,29,30,31 */
	K7_HMVMC_RESERVED16		= BE32MSK(16,31),	/* (4-bits) */
};
extern const struct k7_regbits k7_hmvmc_regbits[];

/*
 * Host Configuration Register 1
 */
enum {
	K7_HCFGR1			= 0x0600,		/* Host Configuration Register 1 (64-bit) */
	K7_HCFGR1_AIB_TMR_VAL		= BE64MSK( 0, 3),	/* (4-bits) AIB reg access timer value */
	K7_HCFGR1_WR_FIFO_MODE_SEL	= BE64BIT( 4),		/* DMA WR FIFO mode select: 0=0BAD; 1=last_data */
	K7_HCFGR1_TRC_DMA		= BE64BIT( 5),		/* Trace control: DMA */
	K7_HCFGR1_TRC_REG		= BE64BIT( 6),		/* Trace control: REG */
	K7_HCFGR1_TRC_CPE		= BE64BIT( 7),		/* Trace control: CPE */
	K7_HCFGR1_AIB_ECC_INJ_SEL	= BE64BIT( 8),		/* ECC error inject select for AIB bus back to CPE */
	K7_HCFGR1_AIB_ECC_INJ_VAL	= BE64MSK( 9,15),	/* (7-bits) ECC error inject mask value */
	K7_HCFGR1_AIB_RX_FENCE_INJ	= BE64BIT(16),		/* Inject TX fence on AIB interface */
	K7_HCFGR1_AIB_RX_FENCE_EN	= BE64BIT(17),		/* Enable TX fence on AIB interface */

	/* bits 18-19: see Nihad's email 13-March-2014: */
	K7_HCFGR1_AIB_TXDAT_ERR_EN	= BE64BIT(18),		/* DD2: enable AI_TX_DAT_ERR reporting on AIB */
	K7_HCFGR1_AIB_RXCH_FIX_EN	= BE64BIT(19),		/* DD2: enable RX channel fix in AIB */

	K7_HCFGR1_RESERVED20		= BE64MSK(20,23),	/* (4-bits) */
	K7_HCFGR1_MSIX_ECC_INJ_SEL	= BE64BIT(24),		/* ECC error inject select for MSIx RAM input data */
	K7_HCFGR1_MSIX_ECC_INJ_VAL	= BE64MSK(25,31),	/* ECC error inject mask value */
	K7_HCFGR1_RESERVED32		= BE64MSK(32,39),	/* (8-bits) */
	K7_HCFGR1_PF_FLR_TIMER_VALUE	= BE64MSK(40,63),	/* Number of usecs PF timer counts before "reset done" to CPE */
};
extern const struct k7_regbits k7_hcfgr1_regbits[];

/*
 * (debug) MCPU to Host Channel Status (PF only)
 */
enum {
	K7_M2HCS			= 0x0d00,		/* Host to MCPU Channel Status debug register (64-bit) */
	K7_M2HCS_STATE			= BE64MSK( 0,15),	/* M2H current state */
	K7_M2HCS_RESERVED16		= BE64MSK(16,17),	/* (2-bits) */
	K7_M2HCS_TX_SIZE		= BE64MSK(18,27),	/* last burst size written by the state machine */
	K7_M2HCS_RESERVED28		= BE64MSK(28,30),	/* (8-bits) */
	K7_M2HCS_FLUSH			= BE64BIT(31),		/* indicates state machine in process of flushing reply msg */
	K7_M2HCS_RESERVED32		= BE64MSK(32,34),	/* (3-bits) */
	K7_M2HCS_VFID			= BE64MSK(35,39),	/* most recently serviced VFID */
	K7_M2HCS_RESERVED40		= BE64MSK(40,50),	/* (8-bits) */
	K7_M2HCS_AVAIL_COUNT		= BE64MSK(51,63),	/* available bytes in DMA write buffer */
};
extern const struct k7_regbits k7_m2hcs_regbits[];

/*
 * (debug) Host to MCPU Channel Status (PF only)
 */
enum {
	K7_H2MCS			= 0x0900,		/* Host to MCPU Channel Status debug register (64-bit) */
	K7_H2MCS_STATE			= BE64MSK( 0,23),	/* H2M current state */
	K7_H2MCS_RESERVED24		= BE64MSK(24,26),	/* (3-bits) */
	K7_H2MCS_VFID			= BE64MSK(27,31),	/* most recently serviced VFID */
	K7_H2MCS_RESERVED32		= BE64MSK(32,39),	/* (8-bits) */
	K7_H2MCS_RD_PENDING		= BE64MSK(40,47),	/* current status of read channel tags */
	K7_H2MCS_RESERVED48		= BE64MSK(48,50),	/* (3-bits) */
	K7_H2MCS_AVAIL_COUNT		= BE64MSK(51,63),	/* available bytes in DMA read buffer */
};
extern const struct k7_regbits k7_h2mcs_regbits[];

/*
 * (debug) Host to MCPU Channel DT controls (PF only)
 */
enum {
	K7_H2MDTC			= 0x0920,		/* Host to MCPU channel DT controls register (64-bit) */
	K7_H2MDTC_CTRL			= BE64MSK( 0, 3),	/* control field of last DT fetched */
	K7_H2MDTC_BUF_BC		= BE64MSK( 4,23),	/* remaining DT bytecount to be fetched */
	K7_H2MDTC_RSVD			= BE64MSK(24,27),	/* DT reserved field from last DT fetched */
	K7_H2MDTC_HRB_BC		= BE64MSK(28,47),	/* remaining HRB bytecount to be fetched */
	K7_H2MDTC_SIGN			= BE64MSK(48,63),	/* DT signature field from last DT fetched */
};
extern const struct k7_regbits k7_h2mdtc_regbits[];

/*
 * (debug) Host DMA error (PF only)
 * Contents frozen (two independent halves) after error; write anything to clear.
 *
 * The CH_ID values are interpeted as follows:
 * 0 - MM read channel
 * 1 - SKCH read channel A
 * 2 - SKCH read channel B
 * 3 - MCPU read channel
 * 4 - SSP  read channel
 * 5 - FPGA read channel A
 * 6 - FPGA read channel B
 * 7 - Reserved
 * 8 - MM   write channel
 * 9 - SKCH write channel A
 * A - SKCH write channel B
 * B - MCPU write channel
 * C - SSP  write channel
 * D - FPGA write channel A
 * E - FPGA write channel B
 * F - Reserved
 */
enum {
	K7_HDERR			= 0x0ba0,		/* Host DMA error debug register (32-bit) */
	K7_HDERR_RD_CH_ID		= BE32MSK( 0, 3),	/* */
	K7_HDERR_RESERVED4		= BE32MSK( 4, 7),	/* */
	K7_HDERR_RD_DT_SIG		= BE32BIT( 8),		/* */
	K7_HDERR_RD_HRB			= BE32BIT( 9),		/* */
	K7_HDERR_RD_DT_MAX		= BE32BIT(10),		/* */
	K7_HDERR_RD_DT_BC		= BE32BIT(11),		/* */
	K7_HDERR_RD_DT_ALIGN		= BE32BIT(12),		/* */
	K7_HDERR_RD_DT_512		= BE32BIT(13),		/* */
	K7_HDERR_RD_DT_EOC		= BE32BIT(14),		/* */
	K7_HDERR_RD_HRB_SIG		= BE32BIT(15),		/* */
	K7_HDERR_WR_CH_ID		= BE32MSK(16,19),	/* */
	K7_HDERR_RESERVED20		= BE32MSK(20,23),	/* */
	K7_HDERR_WR_DT_SIG		= BE32BIT(24),		/* */
	K7_HDERR_RESERVED25		= BE32BIT(25),		/* */
	K7_HDERR_WR_VF_FLUSHED		= BE32BIT(26),		/* VF-only: reply arrived when DMA disabled; flushed */
	K7_HDERR_WR_DT_BC		= BE32BIT(27),		/* */
	K7_HDERR_WR_DT_ALIGN		= BE32BIT(28),		/* */
	K7_HDERR_WR_DT_512		= BE32BIT(29),		/* */
	K7_HDERR_WR_DT_EOC		= BE32BIT(30),		/* */
	K7_HDERR_WR_HRB_SIG		= BE32BIT(31),		/* */
};
extern const struct k7_regbits k7_hderr_regbits[];

/*
 * HTB Transfer Count
 */
enum {
	K7_HTBTC			= 0x0bc8,		/* HTB Transfer Count (64-bit) */
	K7_HTBTC_RESERVED0		= BE64MSK( 0,39),	/* (40-bits) */
	K7_HTBTC_TC			= BE64MSK(40,59),	/* (16-bits) */
	K7_HTBTC_MBZ			= BE64MSK(60,63),	/* (4-bits) */
};
extern const struct k7_regbits k7_htbtc_regbits[];

/*
 * Host Tamper Subsystem (HTS) registers:
 */
enum {
	K7_HTS_DP			= 0x0218,		/* HTS Data Port */
	K7_HTS_AP			= 0x0210,		/* HTS Address Port */
	K7_HTS_AP_HTS_DONE		= BE32BIT(0),		/* "Last request complete" bit */
	K7_HTS_AP_HTS_ERR		= BE32BIT(1),		/* "Last request failed" bit */
	K7_HTS_AP_RESERVED2		= BE32MSK(2,24),	/* */
	K7_HTS_AP_HTS_ADDR		= BE32MSK(25,31),	/* I2C register address field */
	K7_SM_REG_COUNT			= 0x38,			/* Number of I2C registers for host access inside SM chip */
};

/*
 * K7_H2X_CH_STATUS (debug) Host to XX channel status (PF only)
 */
enum {
	K7_H2XCS_CURR_STATE		= BE64MSK( 0,23),	/* */
	K7_H2XCS_RESERVED24		= BE64MSK(24,26),	/* */
	K7_H2XCS_VFID			= BE64MSK(27,31),	/* */
	K7_H2XCS_RESERVED32		= BE64MSK(32,39),	/* */
	K7_H2XCS_RD_PENDING		= BE64MSK(40,47),	/* tags pending bitmap */
	K7_H2XCS_RESERVED48		= BE64MSK(48,50),	/* */
	K7_H2XCS_AVAIL_COUNT		= BE64MSK(51,63),	/* */
};
extern const struct k7_regbits k7_h2xcs_regbits[];

/*
 * K7_X2H_CH_STATUS (debug) XX to Host XX channel status (PF only)
 */
enum {
	K7_X2HCS_CURR_STATE		= BE64MSK( 0,15),	/* */
	K7_X2HCS_RESERVED16		= BE64MSK(16,17),	/* */
	K7_X2HCS_TX_SIZE		= BE64MSK(18,27),	/* */
	K7_X2HCS_RESERVED28		= BE64MSK(28,30),	/* */
	K7_X2HCS_FLUSH			= BE64BIT(31),		/* */
	K7_X2HCS_RESERVED32		= BE64MSK(32,34),	/* */
	K7_X2HCS_VFID			= BE64MSK(35,39),	/* */
	K7_X2HCS_RESERVED48		= BE64MSK(40,50),	/* */
	K7_X2HCS_AVAIL_COUNT		= BE64MSK(51,63),	/* */
};
extern const struct k7_regbits k7_x2hcs_regbits[];

/*
 * K7_X2H_CH_STATUS (debug) XX to Host XX channel status (PF only)
 */
enum {
	K7_PF2VF_VF0_FULL		= BE64BIT( 0),		/* vf0 mailbox full */
	K7_PF2VF_VF0_WE			= BE64BIT( 1),		/* vf0_to_pf write-enable */
	K7_PF2VF_VF1_FULL		= BE64BIT( 2),		/* vf1 mailbox full */
	K7_PF2VF_VF1_WE			= BE64BIT( 3),		/* vf1_to_pf write-enable */
	K7_PF2VF_VF2_FULL		= BE64BIT( 4),		/* vf2 mailbox full */
	K7_PF2VF_VF2_WE			= BE64BIT( 5),		/* vf2_to_pf write-enable */
	K7_PF2VF_VF3_FULL		= BE64BIT( 6),		/* vf3 mailbox full */
	K7_PF2VF_VF3_WE			= BE64BIT( 7),		/* vf3_to_pf write-enable */
	K7_PF2VF_VF4_FULL		= BE64BIT( 8),		/* vf4 mailbox full */
	K7_PF2VF_VF4_WE			= BE64BIT( 9),		/* vf4_to_pf write-enable */
	K7_PF2VF_VF5_FULL		= BE64BIT(10),		/* vf5 mailbox full */
	K7_PF2VF_VF5_WE			= BE64BIT(11),		/* vf5_to_pf write-enable */
	K7_PF2VF_VF6_FULL		= BE64BIT(12),		/* vf6 mailbox full */
	K7_PF2VF_VF6_WE			= BE64BIT(13),		/* vf6_to_pf write-enable */
	K7_PF2VF_VF7_FULL		= BE64BIT(14),		/* vf7 mailbox full */
	K7_PF2VF_VF7_WE			= BE64BIT(15),		/* vf7_to_pf write-enable */
	K7_PF2VF_VF8_FULL		= BE64BIT(16),		/* vf8 mailbox full */
	K7_PF2VF_VF8_WE			= BE64BIT(17),		/* vf8_to_pf write-enable */
	K7_PF2VF_VF9_FULL		= BE64BIT(18),		/* vf9 mailbox full */
	K7_PF2VF_VF9_WE			= BE64BIT(19),		/* vf9_to_pf write-enable */
	K7_PF2VF_VF10_FULL		= BE64BIT(20),		/* vf10 mailbox full */
	K7_PF2VF_VF10_WE		= BE64BIT(21),		/* vf10_to_pf write-enable */
	K7_PF2VF_VF11_FULL		= BE64BIT(22),		/* vf11 mailbox full */
	K7_PF2VF_VF11_WE		= BE64BIT(23),		/* vf11_to_pf write-enable */
	K7_PF2VF_VF12_FULL		= BE64BIT(24),		/* vf12 mailbox full */
	K7_PF2VF_VF12_WE		= BE64BIT(25),		/* vf12_to_pf write-enable */
	K7_PF2VF_VF13_FULL		= BE64BIT(26),		/* vf13 mailbox full */
	K7_PF2VF_VF13_WE		= BE64BIT(27),		/* vf13_to_pf write-enable */
	K7_PF2VF_VF14_FULL		= BE64BIT(28),		/* vf14 mailbox full */
	K7_PF2VF_VF14_WE		= BE64BIT(29),		/* vf14_to_pf write-enable */
	K7_PF2VF_VF15_FULL		= BE64BIT(30),		/* vf15 mailbox full */
	K7_PF2VF_VF15_WE		= BE64BIT(31),		/* vf15_to_pf write-enable */
	K7_PF2VF_MSG			= BE64MSK(32,63),	/* message data */
};
extern const struct k7_regbits k7_pf2vf_regbits[];

extern const struct k7_regbits k7_32bits[];
extern const struct k7_regbits k7_64bits[];

#endif /* __K7_REGS_H__ */
