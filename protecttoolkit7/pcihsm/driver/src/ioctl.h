/*
 * Copyright (c) 2013-2017 Safenet.  All rights reserved.
 *
 * ioctl.h -- ioctl definitions for use by apps.
 */
#ifndef __K7_IOCTL_H__
#define __K7_IOCTL_H__

#include <linux/types.h>

#ifndef PACK
#if defined(__GNUC__)
        #define PACK( __Struct__ ) __Struct__ __attribute__((__packed__))     /* GCC struct packing */
#elif defined(K7_WIN) || defined(OS_WIN32) || defined(OS_WIN64)
        #define PACK( __Struct__ ) __pragma( pack(push, 1) ) __Struct__ __pragma( pack(pop) )  /* for MS-Studio */
#elif defined(OS_SOLARIS)
        #define PACK( __Struct__ ) __Struct__ /* for solaris */
#else
	#error "Need to define a PACK() macro for this compiler"
#endif
#endif

/*
 * Possible values for the "target" field of the k7_dma_ioctl struct:
 */
enum K7DMA {
	/*
	 * DMA target codes.
	 */
	K7_DMA_TARGET_MCPU	= 0,	/* DMA target is MCPU */
	K7_DMA_TARGET_PKU	= 1,	/* DMA target is ModularMath */
	K7_DMA_TARGET_SKU	= 2,	/* DMA target is SymmetricKey */
	K7_DMA_TARGET_MAX	= K7_DMA_TARGET_SKU,

	/*
	 * Bits for the "flags" field in struct k7_dma_ioctl.
	 * These can be OR'd together when/where appropriate.
	 */
	K7_DMA_FLAG_MRB0		= 0x0000,	/* select MCPU MRB0 (default) */
	K7_DMA_FLAG_MRB1		= 0x0001,	/* select MCPU MRB1 */
	K7_DMA_FLAG_NOTX		= 0x0002,	/* select MCPU "NO_TX" HRB action */
	K7_DMA_FLAG_FTE_RELOAD		= 0x0004,	/* this transaction (re)loads the FTE on MCPU */
	K7_DMA_FLAG_NO_RESULT_DATA	= 0x0008,	/* don't return the result data (for perf testing) */
	K7_DMA_FLAG_NO_REPLY		= 0x0010,	/* no response expected from target */
	K7_DMA_FLAG_ICD_CMD		= 0x0400,	/* ICD request being sent via MCPU, MRB0 only */
	K7_DMA_FLAG_MASK		= (K7_DMA_FLAG_MRB0           | K7_DMA_FLAG_MRB1
					 | K7_DMA_FLAG_NOTX           | K7_DMA_FLAG_FTE_RELOAD
					 | K7_DMA_FLAG_NO_RESULT_DATA | K7_DMA_FLAG_NO_REPLY
					 | K7_DMA_FLAG_ICD_CMD ),

	K7_HSM_STATE_NULL		= 0x00000000,	/* Never a valid/used state */
	K7_HSM_STATE_BL_STARTED		= 0x00000001,	/* BL accepting commands, token has been erased */
	K7_HSM_STATE_BL_COMMANDS	= 0x00000002,	/* BL accepting commands, token has been erased */
	K7_HSM_STATE_BL_READY		= 0x00000003,	/* firmware validated, can be started with GOFW */
	K7_HSM_STATE_BL_ERASING		= 0x00000004,	/* Token is being erased */
	K7_HSM_STATE_BL1_FATAL		= 0x00000005,	/* Fatal error in BL1 */
	K7_HSM_STATE_BL2_FATAL		= 0x00000006,	/* Fatal error in BL2 */
	K7_HSM_STATE_TAMPER_RESET	= 0x00000007,	/* Card in reset due to tamper. */
	K7_HSM_STATE_BOOTING		= 0x0000000f,	/* (driver) GOFW command was issued */
	K7_HSM_STATE_DMA_READY		= 0x00000010,	/* firmware DMA driver initialized */
	K7_HSM_STATE_CONFIGURE		= 0x00000020,
	K7_HSM_STATE_READY		= 0x00000040,
	K7_HSM_STATE_HW_ERROR		= 0x00000081,
};

/*
 * Input struct for the K7_DMA_IOCTL ioctl() call.
 *
 * Userspace passes in this struct.
 * DMA is sent, response is received, size of response is returned from ioctl.
 *
 * The driver waits up to "timeout_msecs" for the response,
 * and fails the operation if not completed within that time allotment.
 * This also causes the DMA engines to be shut down requiring a reset to recover.
 *
 * If outbuf_size was too small, then (outbuf_size|K7_DMA_OUTPUT_TRUNCATED) is returned.
 * If any other error occurs, a negative errno is returned inside the kernel,
 * which userspace will see as "-1" with the actual (positive) errno in "errno".
 *
 * For MCPU ICD commands (K7_DMA_FLAG_ICD_CMD),
 * the ioctl tries to format/return LUNA_RET_* codes
 * into a standard response header in outbuf[] when possible.
 */
#define K7_DMA_OUTPUT_TRUNCATED	(1<<30)		/* or'd with bytecount return value when outbuf_size was too small */
PACK(struct k7_dma_ioctl {
	unsigned long long	inbuf;		/* address of input data buffer  */
	unsigned long long	outbuf;		/* address of output data buffer */
	unsigned int		inbuf_size;	/* size of inbuf */
	unsigned int		outbuf_size;	/* size of outbuf */
	unsigned int		timeout_msecs;	/* transaction timeout in milli-seconds */
	unsigned char		target;		/* target device for DMA: mcpu, pkcu, skcu, or ssp */
	unsigned char		reserved;	/* not used */
	unsigned short		flags;		/* flags for special behaviour/options */
});

/*
 * Input struct for the K7_DMA_FASTPATH ioctl() call.
 *
 * Note about return codes:
 *   -EKEYEXPIRED  is returned for LUNA_RET_KEY_NOT_KEKED.
 *   -EKEYREJECTED is returned for LUNA_RET_KEY_CANNOT_BE_KEKED.
 */
#define K7_FP_MAX_SEGMENTS	4
PACK(struct k7_data_segment {
	unsigned long long	buf;				/* userspace buffer pointer */
	unsigned int		bytecount;			/* Transfer size of buffer */
	unsigned int		padding;			/* for alignment and future use */
});

PACK(struct k7_dma_fastpath {
	struct k7_dma_ioctl	d;
	struct k7_data_segment	payload [K7_FP_MAX_SEGMENTS];	/* extra input fields */
	unsigned int		key_handle;			/* key_handle for data */
	unsigned int		session_id;			/* NOTE: 1-based (session_handle + 1) */
	unsigned int		operation;			/* SKU operation type */
	unsigned int		mechanism;
	unsigned int		xts_tweak_vector[4];		/* extra data for AES-XTS */
	unsigned int		xts_tweak_handle;		/* extra key_handle for AES-XTS */
});

PACK(struct k7_mbx_ioctl {
	unsigned long long	data;		/* passes data in to MBX_WRITE; passes data out from MBX_READ */
	unsigned int		target;		/* input: one of K7_DMA_TARGET_{MCPU,SSP} */
	unsigned int		spare;		/* reserved (padding) */
});

/* IO_MCPU_MBX_STATUS returns an OR of these values */
enum K7MBX {
	K7_H2X_MBX_FULL		= 0x00000001,
	K7_X2H_MBX_FULL		= 0x00000002,
};

/*
 * K7_LOG_READ ioctl:
 *
 * This ioctl reads the next buffered "unsolicited log" message received from the board.
 * Returns bytecount for the data returned, zero means "no messages".
 */
PACK(struct k7_log_ioctl {
	unsigned long long	outbuf;		/* address of output data buffer (DMA channel writes to this buffer) */
	unsigned int		outbuf_size;	/* size of outbuf */
	unsigned int		target;		/* K7_DMA_TARGET_MCPU */
});

/*
 * K7_HIF_REG_READ ioctl:
 *
 * This ioctl reads the host interface register
 */
struct k7_hif_reg_ioctl {
	unsigned int		offset;	/* register offset */
	unsigned int		len;	/* byte length of the register e.g 4 or 8 bytes */
	unsigned long long	buf;	/* address of buf[len] for the content of the register */
};

#define K7_DMA_IOCTL		_IOR('d', 0x11, struct k7_dma_ioctl)
#define K7_DMA_FASTPATH		_IOR('d', 0x15, struct k7_dma_fastpath)
#define K7_MBX_WRITE		_IOR('d', 0x21, struct k7_mbx_ioctl)
#define K7_MBX_READ		_IOW('d', 0x22, struct k7_mbx_ioctl)
#define K7_MBX_STATUS		_IOR('d', 0x23, struct k7_mbx_ioctl)
#define K7_LOG_READ		_IOR('d', 0x31, struct k7_log_ioctl)

#define K7_GET_INSERTION_COUNT	_IOR('d', 0x33, unsigned int)
#define K7_GET_HSM_STATE	_IOR('d', 0x34, unsigned int)
#define K7_GET_PROTOCOL_VERSION	_IOR('d', 0x35, unsigned int)
#define K7_GET_TAMPER_REGS	_IO( 'd', 0x36)
#define K7_HIF_REG_READ		_IOR('d', 0x37, struct k7_hif_reg_ioctl)

#define K7_FLR_RESET		_IO( 'd', 0x43)
#define K7_HOST_RESET		_IO( 'd', 0x44)
#define K7_SET_AUTOBOOT		_IO( 'd', 0x46)

#if 1  /* FIXME: this is for test/debug only; not needed by the actual product */
struct k7_dump_keycache_parms {
	unsigned long long	outbuf;
	unsigned int		outbuf_size;
};
#define K7_DUMP_KEYCACHE	_IOR( 'd', 0x66, struct k7_dump_keycache_parms)
#endif

#endif /* __K7_IOCTL_H__ */
