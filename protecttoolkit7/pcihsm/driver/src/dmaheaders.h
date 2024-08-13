/*
 * Copyright (c) 2013-2017 Safenet.  All rights reserved.
 *
 * dmaheaders.h -- Generic DMA header for K7,
 */
#ifndef __K7_DMAHEADERS_H__
#define __K7_DMAHEADERS_H__

enum {
	K7_DMAHDR_HTYPE			= BE64MSK( 0, 7),	/* Header Type */
	K7_DMAHDR_RESERVED8		= BE64BIT( 8),		/* (1-bit) */
	K7_DMAHDR_RQSTR			= BE64MSK( 9,11),	/* Requester ID (who sent this block) */
	K7_DMAHDR_RESERVED12		= BE64BIT(12),		/* (1-bit) */
	K7_DMAHDR_ADDR_TYPE		= BE64BIT(13),		/* Address type: 0=DTC; 1=Direct */
	K7_DMAHDR_RQACTION		= BE64MSK(14,15),	/* Request type: 0=normal,1=extcompl,2=abort,3=rsvd */
	K7_DMAHDR_NOTX			= BE64BIT(16),		/* 0=normal-DMA; 1=interrupt-instead-of-DMA (at MCPU) */
	K7_DMAHDR_RESERVED17		= BE64MSK(17,19),	/* (3-bits) */
	K7_DMAHDR_MRB0			= BE64VAL(20,21,0),	/* HRB-only: select MRB0 */
	K7_DMAHDR_MRB1			= BE64VAL(20,21,1),	/* HRB-only: select MRB1 */
	K7_DMAHDR_ACTION_IV		= BE64VAL(22,23,1),	/* Generate target IV on receipt */
	K7_DMAHDR_ACTION_IRQ		= BE64VAL(22,23,2),	/* Interrupt target on receipt */
	K7_DMAHDR_ACTION_IV_IRQ		= K7_DMAHDR_ACTION_IV | K7_DMAHDR_ACTION_IRQ,
	K7_DMAHDR_USER			= BE64MSK(24,31),	/* User-defined operation-ID (8-bits) */
	K7_DMAHDR_VFID			= BE64MSK(32,39),	/* Virtual Function ID: 0=phys, {32..47}=VF (8-bits) */
	K7_DMAHDR_RESERVED40		= BE64MSK(40,43),	/* (4-bits) */
	K7_DMAHDR_RLEN			= BE64MSK(44,63),	/* Request/Reply bytecount (multiple of 8) (20-bits) */
	K7_DMAHDR_IVLEN			= BE64MSK(56,63),	/* IV bytecount (8-bits) */
	/*
	 * IV header has these fields instead of the normal 20-bit K7_DMAHDR_RLEN field:
	 */
	K7_DMAHDR_IV_RC			= BE64MSK(44,47),	/* IV simple return code  (4-bits) */
	K7_DMAHDR_IV_RESERVED48		= BE64MSK(48,55),	/* IV reserved area       (8-bits) */
	K7_DMAHDR_IV_RLEN		= BE64MSK(56,63),	/* IV Length, always 0x08 (8-bits) */

	K7_HRA_SIGNATURE_MASK		= BE64MSK( 0,15),	/* for extracting sig from hra->sig_hdf word */

	K7_HRB_SIGNATURE_1234		= 0x1234,		/* HRB signature for MCPU & PKU */
	K7_HRB_SIGNATURE_A5A5		= 0xa5a5,		/* HRB signature for SKU */
};

enum {
	/*
	 * Breakdown of DT control word:
	 */
	K7_DT_EOC			= BE64BIT( 0),		/* End-Of-Chain */
	K7_DT_RESERVED1			= BE64BIT( 1),		/* (1-bit) */
	K7_DT_NOTIFY_RX			= BE64BIT( 2),		/* (read ch) Generate IV on completion of this DT */
	K7_DT_RMRI			= BE64BIT( 3),		/* (read ch) Interrupt host with NOTIFY_RX */
	K7_DT_BYTECOUNT			= BE64MSK( 4,23),	/* Size of data area for this DT */
	K7_DT_RESERVED24		= BE64MSK(24,27),	/* (4-bits) */
	K7_DT_HRB_LENGTH		= BE64MSK(28,47),	/* (read ch) Total message size (first DT of dtc) */
	K7_DT_SIGNATURE_MASK		= BE64MSK(48,63),	/* Signature, always 0xd64d */
	K7_DT_SIGNATURE_VAL		= BE64VAL(48,63,0xd64d),/* Signature, always 0xd64d */
};

enum {
	/*
	 * HTYPE values for outbound DMA headers.
	 */
	K7_HTYPE_H2PK		= 0x00,		/* Host-to-PKU */
	K7_HTYPE_H2PK_IV	= 0x02,		/* Host-to-PKU IV */
	K7_HTYPE_H2SK		= 0x20,		/* Host-to-SKU */
	K7_HTYPE_H2SK_IV	= 0x22,		/* Host-to-SKU IV */
	K7_HTYPE_H2M		= 0x40,		/* Host-to-MCPU */
	K7_HTYPE_H2M_IV		= 0x42,		/* Host-to-MCPU */
	K7_HTYPE_M2H		= 0x50,		/* MCPU-to-Host */
	/*
	 * HTYPE values for inbound HTB IV entries.
	 *
	 * For "read"  channels, this is followed by an 8-byte DT address.
	 * For "write" channels, the second 8-bytes vary in meaning,
	 * but should normally be (user-defined) the HRA address.
	 *
	 * The PKU and SKU each have A/B subchannels; dunno if host ever sees "B",
	 * but just in case we define HTYPE for both A/B and allow either in the code.
	 */
	K7_HTYPE_PK2H_A_IV	= 0x12,		/* PKU-to-MCPU A */
	K7_HTYPE_PK2H_B_IV	= 0x1a,		/* PKU-to-MCPU B */
	K7_HTYPE_SK2H_A		= 0x30,		/* SKU-to-Host A */
	K7_HTYPE_SK2H_B		= 0x38,		/* SKU-to-Host B */
	K7_HTYPE_SK2H_A_IV	= 0x32,		/* SKU-to-Host A IV */
	K7_HTYPE_SK2H_B_IV	= 0x3a,		/* SKU-to-Host B IV */
	K7_HTYPE_M2H_IV		= 0x52,		/* MCPU-to-Host (really!) */
};

#endif /* __K7_DMAHEADERS_H__ */
