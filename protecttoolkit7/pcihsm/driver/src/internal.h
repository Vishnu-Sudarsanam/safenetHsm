/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * internal.h -- internal driver stuff.
 */
#ifndef __K7_INTERNAL_H__
#define __K7_INTERNAL_H__

#define DRV_NAME		"k7"
#define DEV_BASENAME	        DRV_NAME	/* used as first few chars of /dev/ and /proc/k7/ names */
#define DRV_VERSION		"1.37"
#define K7_HOST_PROTOCOL_LEVEL	3
#define K7_DEBUG_ENABLED	1		/* 1==compile with debug logic (runtime switchable); 0==omit all debug stuff */

/*
 * A partial glossary of terms used throughout this driver for variable and data structure names.
 * Knowing these definitions makes it somewhat easier to understand the code.
 *
 * be32,BE32        Big-Endian 32-bit (used by the K7 card and documentation).
 * be64,BE64        Big-Endian 64-bit (used by the K7 card and documentation).
 * busylist         A linked-list of in-flight DMA requests.
 * cb,CB            abbreviation for the HSM "callback" mechanism.
 * cbhra            Callback HRA: preallocated HRA for receipt of an unsolicited message from the MCPU (no associated HRB).
 * cb_id            identifies a series of related callback requests (commands) and responses.
 * daddr            DMA physical address, from point of view of the K7 hardware.
 * databuf          A data buffer used as source/destination of DMA to/from a card.
 * dev              pointer to a per-device structure.
 * DRV              short form of "device driver".
 * dt,DT            Descriptor Table entry: describes a DMA scatter/gather segment.
 * dtc              DT Chain: a software/hardware linked-list of DTs.
 * fp,fastpath      Fastpath: direct crypto between host and SKU, bypassing the MCPU.
 * fte,FTE          Functional Test Exerciser: a software test harness used to validate the hardware.
 * hderr            abbreviation for "Hardware DMA Error".
 * hdr              abbreviation for "header".
 * hier             Host Interrupt Enable Register
 * hisr             Host Interrupt Status Register
 * host             The computer/operating-system on which this driver runs.
 * hra,HRA          Host Return Address: designated memory to receive DMA data, usually in response to an HRB.
 * hra_type         a software field used to categorize the content of a received HRA.
 * hrb              Host Request Block: hardware structure defining a request layout.
 * hrb_type         a software field used to categorize the content of an outbound HRB.
 * htb,HTB          Host Transfer-complete Buffer: receives "DMA completed" notifications.
 * HSM              Hardware Security Module, but here it mainly refers to the crypto firmware inside the K7.
 * hwdt             DT structure as fetched/used by the hardware.
 * icd,ICD          A host library crypto command targeting the MCPU.
 * io,ioc           abbreviation for "ioctl", or "ioctl parameters".
 * irq              interrupt request number: identifies a specific interrupt source/handler.
 * k7,K7            The Gemalto internal name for the PCIe HSM card to which this device driver interfaces.
 * kek              Key Encryption Key: internal to the K7, used to encrypt other keys.
 * kek_group        Identifies a group of kek_keys associated with a specific kek_id.
 * kek_id           Identifies a specific kek.
 * kek_key          Key data which has been pre-encrypted with a kek, used for fastpath operations.
 * keycache         a cache of kek_key values maintained at the host (for performance) by this driver.
 * kk,xk            abbreviation for "pointer to a kek'd key structure".
 * len              abbreviation for "length" (normally a bytecount).
 * lkrc             Luna Result Code: what the HSM and host libraries use for crypto result codes.
 * m2h,M2H          denotes data transfers from MCPU to Host.
 * h2m,H2M          denotes data transfers from Host to MCPU.
 * mbx              hardware mailbox mechanism for communications between host and MCPU.
 * mcpu,MCPU        The microprocessor inside the K7 which runs the HSM firmware.
 * mech             abbreviation for "mechanism": a usage scenario for a crypto key.
 * mechlist         a list (array) of mech values.
 * mrb,MRB          MCPU Receive Buffer: refers to DMA destination memory inside the K7.
 * PCIe             Peripheral Component Interconnect (PCI) Express bus.
 * pf,PF            PCIe "physical function": the primary/controlling interface to a card.
 * proto            short for "protocol".
 * rekek            The process of REplacing a KEK value with a new one.
 * rxbuf,RXBUF      A scatter-gather block within an MRB.
 * req              A software structure for tracking a DMA request (aka. a DMA transaction).
 * sig              a hardware-checked signature value.
 * sku,SKU          Symmetric Crypto Unit (crypto engine) on the K7 card.
 * vaddr            CPU virtual address.
 * vf,VF            PCIe "virtual function": an alternate register set for accessing a card.
 */

#define K7_PCI_PF_DEVICE_ID	0x0008		/* PCI DEVICE_ID for Physical Function (pf) */

#define ROUND8(v)	(((v) + 7) & ~7)

#define K7_MRB_OFFSET_FLAG_USES_HTYPES	0x80000000  /* shared with the MCPU */

/* These 8-bit HRB hrb_type values are shared with the MCPU */
enum {
	/*
	* These six HRB_TYPEs have carefully chosen values for backward compatibility
	* with the old HRB_FLAG values. DO NOT CHANGE THESE VALUES.  EVER!
	*/
	K7_HRB_TYPE_DEFAULT	=  0, /* bootloader, fastpath */
	K7_HRB_TYPE_PROTOCOL_LEVEL = 1, /* tell MCPU the host protocol level */
	K7_HRB_TYPE_PREPADDING	=  4, /* fake HRB inserted for alignment */
	K7_HRB_TYPE_CB_DISABLE	=  8, /* tell MCPU that callback is no longer operational */
	K7_HRB_TYPE_ICD_CMD	= 16, /* standard crypto request for HSM */
	K7_HRB_TYPE_ABORT_HRA	= 32, /* ask MCPU to return empty HRA before ICD_CMD finishes */

	/* This one must NOT have any bits in common with the old HRB_FLAG values above */
	K7_HRB_TYPE_CB_REPLY	= 64, /* reply to MCPU for a CB_CMD */

	/* Other HRB_TYPEs can be any 8-bit values that agree with the MCPU's definitions */
	K7_HRB_TYPE_CB_ENABLE	=  6, /* tell MCPU that callback (pedClient) is operational */
	K7_HRB_TYPE_ETHERNET	= 14, /* ethernet frame (0xE) */
	K7_HRB_TYPE_CB_CANCEL	= 129, /* deactivate a cb_id */
};

/* These 8-bit HRA hra_type values are shared with the MCPU */
enum {
	/* For simplicity, use the same values as for HRB_TYPE (where applicable). */
	K7_HRA_TYPE_DEFAULT	=  K7_HRB_TYPE_DEFAULT,  /* fastpath, bootloader: must be zero */
	K7_HRA_TYPE_ICD_REPLY	=  K7_HRB_TYPE_ICD_CMD,  /* response from host for an ICD_CMD */
	K7_HRA_TYPE_CB_CMD	=  K7_HRB_TYPE_CB_REPLY, /* a callback request to the host */
	K7_HRA_TYPE_ETHERNET	=  K7_HRB_TYPE_ETHERNET, /* ethernet frame */
	K7_HRA_TYPE_LOGMSG	= 128,                   /* k7_unsolicited_logmsg */
	K7_HRA_TYPE_CB_CANCEL	= 129,                   /* deactivate a cb_id */
};

#define K7_REQ_HRB_TYPE(req)		((req)->hrb_type & 0xff)
#define K7_REQ_CB_ID(req)		(((req)->hrb_type >> 16) & 0xff)
#define K7_HRx_TYPE_BITMSK		BE64MSK(24,31)

#define K7_ICD_LIBRARY_PREFIX_WORDS	 4  /* number of u32 words prefixed to ICD command by library */
#define K7_ICD_STC_WORDS		10  /* number of u32 words used for STC info (whether ICD command is STC or not). */
#define K7_ICD_PROTO_FUTURE_WORDS	 8  /* number of u32 words for protocol-version, future-proofing etc.. */
#define K7_ICD_PARAMS_OFFSET_WORDS	(1 + K7_ICD_STC_WORDS + K7_ICD_PROTO_FUTURE_WORDS)    /* number of u32 words */

#define LUNA_PS_MULTI     0x200

#define PS_MULTI_INIT     1
#define PS_MULTI_UPDATE   2
#define PS_MULTI_FINAL    3
#define PS_MULTI_FETCH    4

/* Addendum to the more public DMA_FLAGS in ioctl.h: */
enum {
	K7_DMA_FLAG_KBUF		= 0x0100,	/* inbuf/outbuf are in kernel space */
	K7_DMA_FLAG_KEK_FASTPATH	= 0x0800,	/* identifies SKU fastpath requests within the driver */
	K7_DMA_FLAG_CBHRA		= 0x1000,	/* provide an HRA buffer for MCPU to keep for later needs */
	K7_DMA_FLAG_KEK_KEY		= 0x8000,	/* identifies KEY_KEY commands for special handling */
};

#define K7_FOREACH_DMA_TARGET(target)	for (target = K7_DMA_TARGET_MCPU; target <= K7_DMA_TARGET_MAX; target++)

extern int k7_num_vf;				/* number of virtual functions desired per K7 card */
extern int k7_debug;				/* debug level: log various levels of info */
extern int k7_cbdebug;				/* debug flag for callback (only) */
extern int k7_zeromem;				/* debug flag: 1=zero buffers even when not necessary */
extern int k7_dump_failed;			/* debug flag: 1=dump HRB/HRA DTCs for failed requests */
extern int k7_procfs;				/* debug flag: 0=off; 1=enable /proc/k7/ heirarchy */
extern int k7_dump_icd_inbuf;			/* debug flag: 0=off; 1=dump raw inbuf of ICD commands to syslog */

#define K7_HISR_READ_NEEDED	((u32)0)

enum {
	/*
	 * Compile-time configuration flags:
	 */
	K7_FREE_TO_LIST_HEAD	= 0,		/* 1==return freed DTs to list head; 0==return freed DTs to list tail */
	K7_USE_HTB_BF		= 0,		/* 1==use HTB_BF irqs, 0==don't use them (we don't really need them) */
	K7_USE_CACHEABLE_RAM	= 1,		/* 1==use cacheable data buffers, 0==use only non-cacheable RAM */
	K7_PERMANENT_DATABUFS	= 1,		/* 1==permanently allocate data buffers at startup; 0==alloc/free on the fly */
	K7_MAX_BYTES_PER_DT	= PAGE_SIZE,	/* normally PAGE_SIZE; larger multiples often work, but are not guaranteed to */
	K7_MCPU_MAX_HRB_BYTES	= 65 * 1024,	/* shared with the MCPU; limit on total HRB+footer size in MCPU MRB */
	K7_HSM_READY_TIMEOUT_SECS = 5 * 60,	/* allow up to five minutes for HSM_READY after RESET */
	K7_PCIE_LINK_POLL_SECS	= 2,		/* polling frequency for checking for PCIe link loss */

	/*
	 * Other useful driver constants:
	 */
	K7_HRB_HDR_LEN		= 4 * sizeof(u64),
	K7_HRB_MCPU_ALIGNMENT	= K7_HRB_HDR_LEN,
	K7_HRB_FOOTER_BYTES	= sizeof(u64),	/* bytecount of extra DMA header appended by h/w in MRB */
	K7_CBHRA_SIZE		= K7_MAX_BYTES_PER_DT - K7_HRB_HDR_LEN,

	K7_MAX_CARDS		= 8,
	K7_MAX_VFS_PER_CARD	= 16,
	K7_MINORS_PER_CARD	= K7_MAX_VFS_PER_CARD + 1,
	K7_MAX_MINORS		= K7_MAX_CARDS * K7_MINORS_PER_CARD,

	K7_HTB_SIZE		= 0x2000,	/* size (bytes) of area to receive IVs on DMA completions */
	K7_NUM_DMA_DESCRIPTORS	= 4096,		/* number of preallocated DTs for all outgoing/incoming DMA uses */

	K7_HTB_ENTRY_BYTES	= (2 * sizeof(u64)),

	/* Request status (software) */
	K7_REQ_IDLE		= 0,
	K7_REQ_SUBMITTED	= 1,
	K7_REQ_COMPLETING	= 2,
	K7_REQ_COMPLETED	= 3,
	K7_REQ_TIMEDOUT		= 4,
	K7_REQ_IOERROR		= 5,

	K7_RESET_TIMEOUT_SECS	= 10,
	K7_FP_TIMEOUT_SECS	= 30,

	/* dev->asic_rev values from HCSR */
	K7_ASIC_REV_DD1		= 16,
	K7_ASIC_REV_DD2		= 32,

	K7_CBHRA_MIN_COUNT	= 32,	/* Number of HRAs to pre-enqueue to MCPU for callback use */
	K7_CBHRA_MAX_WAIT	= 10000, /* Transmission (notify_rx) timeout for callback */
	K7_CB_IO_READ_TIMEOUT	= 1000, /* Default callback read timeout (milliseconds) */

	K7_MCPU_RESET_CODE	= 0x52,		/* H2M mailbox opcode: 'R' (0x52) is for "Reset" */
};

typedef enum {
	K7_MEM_PG_CACHED,			/* page-sized contiguous cacheable RAM */
	K7_MEM_PG_NONCACHED,			/* page-sized contiguous non-cacheable RAM */
	K7_MEM_DATABUF = K7_USE_CACHEABLE_RAM ? K7_MEM_PG_CACHED : K7_MEM_PG_NONCACHED,
} k7_mem_t;

#define K7_UBOOT_RESET_DONE	0x0123456789abcdefull
#define K7_FTE_RESET_DONE	0xfedcba9876543210ull

#define K7_HRA_HDR_LEN_MCPU	(4 * sizeof(u64))
#define K7_HRA_HDR_LEN_FASTPATH	(3 * sizeof(u64))

typedef enum {
	K7_IRQTYPE_PIN,
	K7_IRQTYPE_MSI,
	K7_IRQTYPE_MSIX,
} k7_irqtype_t;

/*
 * Tracking structure for internal memory allocations.
 */
struct k7_mem {
	void			*vaddr;
	dma_addr_t		daddr;
	unsigned int		len;
	k7_mem_t		type;
};

/*
 * Hardware DMA descriptor table entry (hwdt).
 * This is an 8-byte aligned 24-bit structure
 * which is not allowed to cross a 512-byte boundary.
 *
 * Weird DMA failures occur if not padded out to 32-bytes (March/2016).
 */
struct k7_hwdt {
	u64			data_daddr;	/* DMA address pointing at hrb_control field */
	u64			control;	/* bytecount, control, and signature bits */
	u64			next_daddr;	/* DMA address of next hwdt in the chain */
	u64			pad64;		/* Pad out to power-of-two (32 bytes) */
} __attribute__((packed));

/*
 * Software DMA-Table descriptor (dt):
 * points at a hardware DMA table descriptor (hwdt) and it's associated data block.
 */
struct k7_dt {
	struct list_head	list;		/* used to string DTs together into a (software) chain */
	struct k7_hwdt		*hwdt;		/* pointer to (real) hardware DT, in non-cachable RAM */
	u64			daddr;		/* DMA address of the hardware DT (hwdt) */
	struct k7_mem		data;		/* The data buffer associated with this DT */
	u8			dma_mapped;	/* bool for "data" buffer: 1==mapped, 0==not_mapped */
	/*
	 * We need to track state for the EOC DT from each hrb_dtc.
	 * Before we can safely free/re-use an EOC DT, we must ensure
	 * that both this req and the following req have been completed.
	 *
	 * Until both conditions are satisfied, the EOC DT cannot be freed
	 * without reading/comparing TCP.  Because of dual pipes on the SKU,
	 * this "simple" check is far more difficult than it ought to be.
	 */
	u8			req_done;	/* bool: original request has completed */
	u8			next_done;	/* bool: following request has completed */
} __attribute__((packed));

struct k7_cbhra {
	struct list_head	list;		/* used to maintain lists of callback HRAs */
	struct list_head	hra_dtc;	/* DT chain for this HRA; only ever contains a single DT! */
	unsigned int		hra_len;	/* number of bytes received in this HRA */
	unsigned int		offset;		/* current byte offset (for CB_IO_READ) within this HRA */
};

struct k7_req {
	struct list_head	list;
	u64			hra_daddr;	/* same as "list_first_entry(&req->hra_dtc, struct k7_dt, list)->daddr" */
	struct k7_channel	*channel;
	struct k7_dt		*prev_eoc;
	struct k7_dma_ioctl	*ioc;		/* for inbuf/outbuf parameters from user */
	struct list_head	hrb_dtc;
	struct list_head	hra_dtc;
	struct completion	wait;
	unsigned long		timeout;	/* period in jiffies */
	u8			mapped;		/* bool: non-zero means DMA mappings are in-place */
	u8			status;
	u16			post_padding;	/* amount of extra padding at end of HRB for alignment */
	unsigned int		hrb_len;	/* total HRB length over entire dtc */
	unsigned int		hra_size;	/* total HRA size over entire dtc */

	struct k7_kek_key	*kk;		/* fastpath: primary key structure */
	struct k7_kek_key	*xk;		/* fastpath: secondary key structure (optional) */
	struct list_head	original_hrb;	/* for debugging prepadding: points at original HRB */  //FIXME
	u32			session_id;	/* for fastpath requests */
	u32			key_handle;	/* for fastpath kek keys */
	int			kek_key_ret;	/* fastpath: linux return code for kek_key */
	u32			raw_key_bytes;	/* from HTB IRQ back to original context */
	u32			lkrc;		/* from HTB IRQ back to original context */
	u32			hrb_type;	/* type of HRB request (8-bits), possibly OR'd with 8-bit (cb_id << 16) */
	u16			key_op;		/* for fastpath kek keys */
	u16			kek_algorithm;	/* for fastpath kek keys */
	u16			busylist_index;	/* used on channel failure to determine which commands to dump */
	u8			key_mech;	/* for fastpath kek keys */
	u8			prepadded;	/* bool: for debugging prepadding */
	u8			have_mutex;	/* bool: request has locked the key_handle's rekek_mutex */
} __attribute__((packed));

struct k7_channel {
	/* Hardware DMA channel data structures protected by "dev->lock" */
	struct k7_dev		*dev;		/* parent pointer, for convenience */
	struct list_head	busylist;	/* list of active req's */
	struct timer_list	busylist_timer;	/* for request timeouts on busylist */
	int			busylist_timer_armed; /* for request timeouts on busylist */
	struct k7_dt		*eoc;		/* current end-of-chain for submitted DTs */
	unsigned int		mrb_size  [2];	/* used for tracking RXBUF usage of MCPU side */
	unsigned int		mrb_offset[2];	/* used for tracking RXBUF usage of MCPU side */
	unsigned int		base;		/* mmio base offset for DMA registers */
	unsigned char		enabled;	/* bool: 0 = channel not enabled yet */
	unsigned char		did_fetch;	/* 0 = TCP not initialized yet; 1 = use ReFetch */
	unsigned char		target;		/* K7_DMA_TARGET_* identifier for this DMA target */
	char			name[16];	/* channel name for use with debug logs */
	int			active_count;
	volatile unsigned int	hderr_count;	/* cleared whenever channel reenabled */
	struct work_struct	work;		/* handler for busylist_timer timeouts */

	/* This protects access to all dt req_done/next_done fields in busylist */
	K7_DECLARE_SPINLOCK(dt_done_lock);
};

#define K7_UMSG_MAX_LEN		(PAGE_SIZE - 1)

#define K7_MCPU_MAX_HRB_LEN (K7_MCPU_MAX_HRB_BYTES - K7_HRB_HDR_LEN - K7_HRB_FOOTER_BYTES)

/*
 * Response header (little-endian) returned to userspace on ICD command completion.
 */
struct k7_icd_response_hdr {
	u32	flags;
	u32	total_size;
	u32	data_size;
	u32	padding;
	u32	unused[K7_ICD_STC_WORDS]; /* Extra header info present in K7 that the driver will ignore */
	u32	response_code;
} __attribute__((packed));

enum {
	LUNA_RET_KEY_CANNOT_BE_KEKED		= 0x80000905,
	LUNA_RET_KEY_NOT_KEKED			= 0x80000906, /* FIXME: use this in fastpath ioctl */
	LUNA_RET_MECHANISM_INVALID_FOR_FP	= 0x80000907,
	LUNA_RET_OPERATION_INVALID_FOR_FP	= 0x80000908,

	LUNA_KEK_KEY_ICD			= 0xf5,   /* From Library to Driver (possibly forwarded to MCPU) */
	LUNA_REPLACE_KEK_ICD			= 0xf6,   /* From Library to MCPU (driver doesn't need to intercept) */
	LUNA_FAST_PATH_TRANSACTIONS_COMPLETE_ICD = 0xf7,  /* From Driver to MCPU (no reply) */
};

/*
 * Shared with libary and HSM firmware.
 * These define the value of the "(u32)operation" field,
 * as well as the bit index into the valid_ops bitmask.
 */
typedef enum {
	OPER_ENCRYPT,
	OPER_DECRYPT,
	OPER_SIGN,
	OPER_VERIFY,
	OPER_DIGEST,
} SKCH_OPER_TYPE;

typedef enum {idle, stopped, active, in_replacement} k7_kek_group_status;

/*
 * Keycache for fastpath KEK'd keys:
 *
 * This cache stores encrypted keys received from the HSM, for direct use
 * by SKU fastpath requests.  These keys are decrypted at point of use in the SKU,
 * with one of sixteen Key Encryption Keys (KEKs) stored in registers inside the HSM.
 * The group of all keys encrypted by a given KEK is known as a "KEK group",
 * identified by the group_id (0..15).
 *
 * Keys are referenced using a key_handle, which is a sequentially assigned value
 * from 1..whatever, used as an index into the HSM's own internal database.
 * Deleted slots are re-used when possible, keeping the "whatever" limit no larger
 * than need be.  The host driver's keycache is designed to hold more keys than
 * the current HSM can possibly hold, using the key_handle as the index
 * into a direct 1:1 table of key data (the keycache itself).
 *
 * For storage efficiency, the keycache is laid out as a two level segmented table,
 * indexed in two parts by key_handle.
 *
 * The first (level1) is a table of pointers to (level2) sub-tables of key_slots.
 * This (relatively small) level1 table is fully allocated at driver start up.
 *
 * The level2 sub-tables are allocated on-demand, but never freed until driver unload.
 * Each level2 sub-table is a table of key slots, one per key_handle.
 * Each slot has a small amount of book-keeping overhead,
 * plus a pointer to a k7_kek_key (kk) struct.
 *
 * Originally, the level2 structs were allocated in PAGE_SIZE increments using GFP_KERNEL.
 * But as the book-keeping overhead has increased, this became less efficient and larger
 * PAGE_SIZE multiples are now used, falling back to vmalloc if higher-order pages are unavailable.
 * A book-keeping flag (used_vmalloc) tracks this for when memory is eventually freed.
 *
 * The kk structs are allocated and freed on-the-fly as needed.
 * Whenever a kk struct is to be updated, a new copy is created/copied from
 * the original one, the update is peformed on the new copy, and then this
 * replaces the original struct in the slot->kk pointer.  A kref counter is used
 * to determine when the original copy can later be safely freed, after all outstanding
 * fastpath operations involving it are completed.
 *
 * For purposes of session_id accounting, a generation counter is maintained for
 * each key_handle.  When a kk struct exists in slot->kk, the generation count is
 * held in a field within the kk struct.  But when slot->kk becomes empty (NULL),
 * the most recent generation count is encoded back into the NULL pointer value,
 * using the otherwise-invalid lsb of the pointer to indicate such.
 *
 * Managing key_handles (above) turns out to be the "simple" part.
 * We must also manage lists of valid/invalid mechanisms per-key,
 * along with globally tracking valid operations for each mechanism.
 *
 * Mechanisms are global: a given mechanism has a global valid_ops bitmask.
 * In practice, there are not likely to be more than a few dozen mechanisms in all.
 * Each key will have a small list/set of (perhaps) 5-6 permitted mechanisms,
 * and many keys will very likely have the exact same mechanism lists.
 *
 * To keep storage requirements small, we convert external u32 mechanism values
 * into internal u8 mech indexes, which are then strung together into mechlists
 * (lists of mechanisms) identifying valid/invalid mechanisms per key_handle.
 * The mechlists themselves are also kept in global arrays, so each key_handle
 * need only store a small mechlist array index for each of its valid/invalid
 * lists, rather than the entire lists themselves.  Each mechlist is likely
 * to be shared among a substantial number of key_handles of the same type,
 * so this scheme saves quite a bit of RAM.
 *
 * Each mechlist is kept in sorted order by mech index, making searches easy
 * and avoiding having multiple lists with identical contents but in different orders.
 *
 * All of this is in consideration of keeping the RAM requirements as small as possible.
 *
 * Notes:
 *    Zero is NEVER a valid "mech" value; we use it for list-termination.
 *    Each mechlist is kept in sorted ascending order by mech, and zero-terminated.
 *    Both valid_mechlists[0] and invalid_mechlists[0] are always empty lists.
 *    When adding/deleting a mech on a mechlist, we always create a new list and keep the original.
 */
struct k7_kek_group {
	K7_DECLARE_SPINLOCK(lock);			/* protects active_count */
	k7_kek_group_status	status;
	u32			group_id;		/* table index: 0..15 */
	u32			active_kek_id;		/* valid only when status==active */
	u32			pending_kek_id;		/* valid only when status==in_replacement */
	u32			minimum_kek_id;		/* lowest valid kek ID for keys cached as not-kekable */
	unsigned int		active_count;		/* Number of in-flight references to active_kek_id */
	int			notify_hsm_when_zero;	/* notify HSM when active_count goes to zero */
	wait_queue_head_t	wq;			/* waitqueue for kek replacements */
};

struct k7_kek_key {
	struct kref		kref;			/* usage counter (32-bits) */
	u32			generation;		/* generation count, incremented each time key_handle is recycled */
	u32			kek_id;			/* the kek_id this key was kek'd with */
	unsigned		group_id:4;		/* 0..15 hardware slot number / kek_group[] index */
	unsigned		kek_algorithm:2;	/* 2-bits for injection into fastpath reqs. */
	unsigned		cannot_be_keked:1;	/* bool */
	unsigned		has_been_keked:1;	/* bool */
	u8			raw_key_words;		/* number of u64 words for the key */
	u16			valid_ops;		/* bitmap */
	u16			valid_mechs;		/* index into dev->valid_mechlists[] */
	u16			invalid_mechs;		/* index into dev->invalid_mechlists[] */
	u8			key_words;		/* number of u64 words for key_data */
	/* 13-bytes for everything above */
	u8			padding[3];		/* for alignment of key_data[] below */
	u8			key_data[40];		/* actual KEK'd key data (must be 8-byte aligned) */
} __attribute__((packed));  /* 64-bytes in total, including key_data[] */

/*
 * Keycache info for a single key_handle: 48-bytes.
 */
struct k7_key_slot {
	struct k7_kek_key		*kk;		/* points at kek_key struct with key details */
	struct mutex			rekek_mutex;	/* mutex for one-at-a-time KEK_KEY */
} __attribute__((packed));

#define K7_MAX_MECHLISTS		1024	/* Maximum possible number of mechlists of each type (valid,invalid) */
#define K7_MAX_MECHS			256	/* Maximum possible number of mechanisms (global); 8-bits max */
#define K7_KEYCACHE_GROUPS		16	/* Number of keycache groups: hardware limit for K7 */
#define K7_KEYCACHE_MAX_HANDLES		(2 * 1024 * 1024)		/* Somewhat arbitrary */
#define K7_KEYCACHE_LEVEL2_ALLOC_BYTES	(64 * PAGE_SIZE)
#define K7_KEYCACHE_LEVEL2_WIDTH	((K7_KEYCACHE_LEVEL2_ALLOC_BYTES - sizeof(unsigned int)) / sizeof(struct k7_key_slot))
#define K7_KEYCACHE_LEVEL1_WIDTH	((K7_KEYCACHE_MAX_HANDLES + K7_KEYCACHE_LEVEL2_WIDTH - 1) / K7_KEYCACHE_LEVEL2_WIDTH)

/*
 * k7_keycache_level2: a sub-table of key_slots.
 */
struct k7_keycache_level2 {
	struct k7_key_slot		slot[K7_KEYCACHE_LEVEL2_WIDTH];
	unsigned int			used_vmalloc;	/* bool: allocated with vmalloc() rather than get_free_pages() */
} __attribute__((packed));

/*
 * k7_keycache_level1: a table of pointers to tables of key_slots.
 */
struct k7_keycache_level1 {
	struct k7_keycache_level2	*level2[K7_KEYCACHE_LEVEL1_WIDTH];
} __attribute__((packed));

struct k7_mechlist {
	u8		*mechs;
	u32		hash;
};

/*
 * Common log FIFO structure/functions used for both DLOG (device log) and CLOG (command/response logging).
 */
struct k7_log_fifo {
	wait_queue_head_t	wq;		/* waitqueue, and spinlock to protect all dlog* fields */
	unsigned int		rx;		/* Read index: byte offset of next unread message */
	unsigned int		wx;		/* Write index: byte offset where next message will be written */
	char			*buf;		/* The circular buffer for device/debug logs */
	unsigned int		size;		/* Size of dlog_buf[] in bytes */
	volatile unsigned int	activity;	/* A counter that changes value whenever dlog is written to */
	char			enabled;	/* bool: 0 == this log is completely disabled */
	char			no_syslog;	/* bool: 1 == do NOT copy messages to syslog (printk) */
	char			buf_vmalloc;	/* 0==used-kmalloc; 1==used-vmalloc */
	char			tmpbuf[32];	/* temporary buffer used for formatting timestamps */
};

/*
 * Need to track which key_handles are valid for each active session_id,
 * so that the driver can reject confused usage of keys that are not
 * valid for a given session_id.
 *
 * Each k7_dev has a 2-level segmented table, indexed by 16-bit session_id.
 * Each entry points to a list of valid keys for that session_id.
 * Each list is stored as a linked list of small, unordered arrays of k7_key_id structs.
 *
 * Presently, no list compaction is performed on key deletions,
 * because the amount of storage is small and likely to be needed again.
 * Each list is completely freed on session close.
 *
 * We support 65535 sessions.  session_id=0 (or 65535 when 1-based) is not permitted.
 */
enum {
	K7_MAX_SESSIONS			= 65536,	/* K7 uses u16 for session_ids. session_id=0 is reserved */
	K7_SESSIONS_PER_GROUP		= ((PAGE_SIZE) / sizeof(struct k7_session_group *)),
	K7_SESSION_GROUPS		= ((K7_MAX_SESSIONS + K7_SESSIONS_PER_GROUP - 1) / K7_SESSIONS_PER_GROUP),
	K7_SESSION_KEYLIST_BYTES	= 128,
	K7_SESSION_KEYLIST_ENTRIES	= ((K7_SESSION_KEYLIST_BYTES - sizeof(u32) - sizeof(struct k7_session_keylist *)) / sizeof(u32)),
};

struct k7_key_id {
	union {
		struct {
			u32		key_handle;
			u32		generation;
		};
		u64			id;
	};
} __attribute__((packed));

struct k7_session_keylist {
	struct k7_session_keylist	*next;
	unsigned long			num_keys;
	struct k7_key_id		keys[K7_SESSION_KEYLIST_ENTRIES];
} __attribute__((packed));

struct k7_session_group {
	struct k7_session_keylist *keylists[K7_SESSIONS_PER_GROUP];
};

#define K7_MAX_CB_ID		255	/* cb_id's are 1.255, with 0 being invalid */

typedef enum {
	K7_CB_ID_STATE_FREE           = 0,	/* cb_id not in use */
	K7_CB_ID_STATE_HSM_CANCELLED  = 1,	/* cb_id has been cancelled by HSM */
	K7_CB_ID_STATE_HOST_CANCELLED = 2,	/* cb_id has been cancelled by host (pedClient) */
	K7_CB_ID_STATE_UNCLAIMED      = 3,	/* data for cb_id received from MCPU, but cb_id not yet claimed by pedClient */
	K7_CB_ID_STATE_CLAIMED        = 4	/* cb_id has been claimed by pedClient */
} k7_cb_id_state_t;

#ifdef K7EI
#include "errinj.h"
#else
#define k7_error_injection   (0)
#define K7_DEV_ERR_TYPE(dev) (0)
#define K7_ERR_TYPE_EQ(err_type, ERRTYPE) (0)
#define K7_CLEAR_SET_ERR_INJECT(err) do {} while (0)
static inline int k7_do_error_injection_prepadding (struct k7_channel *channel, struct k7_req *req, int prepadding, int err_type) {return -ENODEV;}
static inline int k7_check_for_error_injection (struct k7_dev *dev, struct k7_req *req, struct k7_dma_ioctl *ioc) {return 0;}
static inline int k7_do_error_injection (struct k7_dev *dev, struct k7_req *req, struct k7_dma_ioctl *ioc, int err_type, unsigned int *new_mrb_offset) {return -ENODEV;}
struct k7_set_err_inject {};
#endif /* K7EI */

/*
 * Main device state structure: one per PF/VF device.
 */
struct k7_dev {
	struct kref		kref;			/* reference counter for freeing this struct */
	struct mutex		htb_mutex;		/* interlock for HTB interrupt threads */
	void __iomem		*mmio;
	int			minor;
	unsigned char		is_pf;
	unsigned char		failed;
	unsigned char		ari_enabled;
	unsigned char		mcpu_reset_completed;
	unsigned char		icd_enabled;
	unsigned char		num_vf;
	unsigned char		dt_freelist_complained;
	unsigned char		cb_state;
	unsigned char		active_cb_id;		/* for use only when k7_auto_cancel_callbacks==1 */
	unsigned char		reset_ioctl_in_progress;
	unsigned char		pcie_link_failed;
	unsigned char		pcie_link_poll_enabled;
	unsigned char		mcpu_protocol_level;  /* if 0, MCPU does NOT understand hrb_type/hra_type values */
	struct semaphore	mcpu_hrb_sem;
	struct mutex		mcpu_submit_mutex;
	unsigned int		disable_autoboot;  /* accessed as u32 from /proc */
	unsigned int		asic_rev;
	int			traceio;
	dev_t			devt;
	struct k7_set_err_inject err;
	struct device		*device;
	struct cdev		*cdev;
	struct pci_dev		*pdev;

	/* Hardware (mostly) DMA data structures protected by "lock" */
	K7_DECLARE_SPINLOCK(lock);
	int			htb_enabled;		/* 0==HTB not functional */
	u64			last_wa;
	u64			last_m2h_mbx;
	int			m2h_mbx_rx_flag;	/* bool: 1 == new data available for K7_MBX_READ */
	struct k7_channel	channels[K7_DMA_TARGET_MAX + 1];
	struct k7_mem		htb_area;
	struct k7_mem		*dt_areas;
	u32			hier;			/* cached value of most recently written interrupt enables */
	u8			vfid;			/* virtual-function identifier: 0x10..0x1f */
	unsigned int		max_hrb_len;		/* normally 0xfffe8 bytes */
	char			umsg[K7_UMSG_MAX_LEN + 1];  /* buffer to accumulate an unsolicited msg from IVs */
	unsigned int		umsgx;			/* index into umsg[] for next umsg byte */
	int			cbhra_count;		/* callback: number of cbhra struct's available to MCPU */
	struct list_head	cbhra_busylist;		/* callback: HRAs submitted to MCPU */
	struct list_head	cbhra_donelist;		/* callback: HRAs received back from MCPU */
	wait_queue_head_t	cbhra_wq;		/* callback: used to sleep/wake for cbhra_donelist */
	struct work_struct	cbhra_work;		/* callback: worker to re-enqueue CBHRAs */
	pid_t			cb_pid;			/* callback: current owner process */
	unsigned char		mbx_buffer[256];	/* for log messages arriving via mailboxes */
	unsigned int		mbx_bufferx;		/* for log messages arriving via mailboxes */
	unsigned int		alarm_count;		/* alarm count since last reset */

	struct delayed_work	pcie_link_poll_work;	/* used to poll for link-loss condition */

	K7_DECLARE_SPINLOCK(keycache_lock);		/* protects keycache accesses */
	unsigned int		keycache_level1_max;	/* high-water mark for level1 index, speeds up table loops */
	struct k7_keycache_level1 *keycache;
	struct k7_kek_group	kek_group[K7_KEYCACHE_GROUPS]; /* corresponds to a KEK RAM[n] entries on HSM */
	u16			mech_ops  [K7_MAX_MECHS]; /* per-mech bitmap: indexed by mech index */
	struct k7_mechlist	*valid_mechlists;	/* indexed by 10-bit mechlist index */
	struct k7_mechlist	*invalid_mechlists;	/* indexed by 10-bit mechlist index */
	atomic_t		rekek_count;		/* for test/debug */
	struct mutex		level2_alloc_mutex;	/* protects alloc/dealloc of level2 sub-tables */
	struct work_struct	keycache_reset_work;	/* handler for wiping keycache after mcpu reset */

	K7_DECLARE_SPINLOCK(mechanisms_lock);		/* protects mechanisms[] updates */
	u32			mechanisms[K7_MAX_MECHS]; /* convert from u32 mechanism into internal mech index */

	K7_DECLARE_SPINLOCK(sessions_lock);		/* protects session_groups[] accesses */
	struct k7_session_group	*session_groups[K7_SESSION_GROUPS];
	u32			max_session_id;		/* high-water mark */

	/* HSM state / configuration variables */
	u32			hsm_state;		/* received from HSM via unsolicited message */
	u32			hsm_protocol_version;	/* received from HSM via unsolicited message */
	u32			callback_io_version;	/* received from HSM via unsolicited message */
	u32			callback_version;	/* received from HSM via unsolicited message */
	u32			insertion_count;	/* incremented each time we see a backwards hsm_state transition */

	struct k7_log_fifo	dlog;			/* Device log FIFO (DLOG) */
	struct k7_log_fifo	clog;			/* Command/response log FIFO (CLOG) */

	K7_DECLARE_SPINLOCK(dt_freelist_lock);	/* protects dt_freelist */
	struct list_head	dt_freelist;
	unsigned int		dt_freelist_count;

	k7_cb_id_state_t	cb_id_state[K7_MAX_CB_ID+1];	/* Callback identifier (cb_id) state; uses dev->lock */

	/* MSI-X interrupt mappings */
	k7_irqtype_t		irqtype;		/* pin, msx, or msi-x */
	unsigned int		num_vectors;		/* number of interrupt vectors allocated */
	struct msix_entry	irqs[16];		/* mapping table from vectors to IRQs */
	u32			hisr_bits[16];		/* which HISR bit corresponds to each IRQ; 0=all */
	bool			irq_bound[16];		/* true if handler was bound to this irq via request_irq() */

	wait_queue_head_t	reset_wq;		/* used to wait for device reset completions */

	struct k7_proc_desc	*proc_desc;		/* /proc/k7/<minor> subdirectory for this device */
	char			name[16];		/* formatted device name for /dev/ */

	/* Some counters, protected by "stats_lock" */
	K7_DECLARE_SPINLOCK(stats_lock);
	u64			completed_requests;
	u64			bytes_sent;
	u64			bytes_received;

	/* IRQ names for /proc/interrupts */
	char			irq_names[16][16];
	int			pcie_gen;		/* PCIe link speed, as generation number 1,2,3 */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0))
	pci_channel_state_t     pcieh_state;            /* PCIe error recovery state, normally zero */
#else
	enum pci_channel_state  pcieh_state;            /* PCIe error recovery state, normally zero */
#endif

	K7_DECLARE_SPINLOCK(pf2vf_lock);
	struct timer_list	pf2vf_timer;		/* for pf2vf mailbox communications; PF only */

	void			*pci_saved_state;	/* for save/restore of initial PCIe state */
	u32			last_hderr;		/* value of hderr register from most recent DMA error */
	struct k7_mem		special_dt;		/* used for error injection */
#ifdef K7ETH
	struct net_device	*netdev;
#endif
};

/*
 * Chip documentation is all in "big endian", where "bit-0" is the msb rather than the lsb.
 * Driver software is normally written assuming the opposite (bit-0 is _always_ the lsb).
 * Define macros to translate from the documentation bit numbering to software bit numbering,
 * to minimize the coding errors that would otherwise happen.
 */
#define __MASK(nbits,size)		((((u##size)1) << (nbits)) - 1)
#define __MSK(msb,lsb,size)		((__MASK(1 + (lsb) - (msb), size)        ) << (size - 1 - (lsb)))
#define __VAL(msb,lsb,val,size)		((__MASK(1 + (lsb) - (msb), size) & (val)) << (size - 1 - (lsb)))

/* Bitmask for a single big-endian bit */
#define BE32BIT(bit)			__MSK(bit,bit,32)		/* 32-bit single bit */
#define BE64BIT(bit)			__MSK(bit,bit,64)		/* 64-bit single bit */

/* Bitmask for a big-endian bitfield */
#define BE32MSK(msb,lsb)		__MSK(msb,lsb,32)		/* 32-bit bitfield */
#define BE64MSK(msb,lsb)		__MSK(msb,lsb,64)		/* 64-bit bitfield */

/*
 * Align a bitfield value for insertion into a 32/64 bit value.
 * This is similar to insert32()/insert64() below, but much more efficient.
 */
#define BE32VAL(msb,lsb,val)		__VAL(msb,lsb,(u32)(val),32)	/* 32-bit subfield */
#define BE64VAL(msb,lsb,val)		__VAL(msb,lsb,(u64)(val),64)	/* 64-bit subfield */

/*
 * Log functions
 */
void k7_clog (struct k7_dev *dev, const char *prefix, const char *fmt, ...);
void k7_log (struct k7_dev *dev, const char *_name, const char *fn, const char *level, const char *fmt, ...);

#define kinfo(_name,...)	k7_log(NULL, _name,   NULL,   KERN_INFO,    __VA_ARGS__)
#define kfinfo(_name,...)	k7_log(NULL, _name, __func__, KERN_INFO,    __VA_ARGS__)
#define kwarn(_name,...)	k7_log(NULL, _name, __func__, KERN_WARNING, __VA_ARGS__)
#define kerr(_name,...)		k7_log(NULL, _name, __func__, KERN_ERR,     __VA_ARGS__)
#define kdlog(_name,...)	k7_log(dev,  _name,   NULL,   KERN_INFO,    __VA_ARGS__)
#define kdinfo(_name,...)	k7_log(dev,  _name,   NULL,   KERN_INFO,    __VA_ARGS__)
#define kdfinfo(_name,...)	k7_log(dev,  _name, __func__, KERN_INFO,    __VA_ARGS__)
#define kdwarn(_name,...)	k7_log(dev,  _name, __func__, KERN_WARNING, __VA_ARGS__)
#define kderr(_name,...)	k7_log(dev,  _name, __func__, KERN_ERR,     __VA_ARGS__)
#define kdalarm(_dev,...)	do { (_dev)->alarm_count++; k7_log(_dev, (_dev)->name, NULL, KERN_INFO, __VA_ARGS__); } while (0)

#if K7_DEBUG_ENABLED
#define kdebugn(dbglevel,_name,...) do { if (k7_debug >= dbglevel) k7_log(NULL, _name, __func__, KERN_INFO, __VA_ARGS__); } while (0)
#define cbdebug(_name,...) do { if (k7_cbdebug) k7_log(NULL, _name, __func__, KERN_INFO, __VA_ARGS__); } while (0)
#else
#define kdebugn(...) do { } while (0)
#endif

#define kdebug3(_name,...) kdebugn(3,_name, __VA_ARGS__)
#define kdebug2(_name,...) kdebugn(2,_name, __VA_ARGS__)
#define kdebug1(_name,...) kdebugn(1,_name, __VA_ARGS__)
#define kdebug(_name,...)  kdebugn(1,_name, __VA_ARGS__)

/*
 * Align and insert a bitfield into a 32-bit value.
 */
u32 insert32(u32 data, u32 mask, unsigned int val);

/*
 * Align and insert a bitfield into a 64-bit value.
 */
u64 insert64(u64 data, u64 mask, unsigned int val);

/*
 * Extract and right-align a bitfield from a 32-bit value.
 */
unsigned int extract32(u32 data, u32 mask);

/*
 * Extract and right-align a bitfield from a 64-bit value.
 */
unsigned int extract64(u64 data, u64 mask);

/*
 * Fill in HRB bytecount, less DMA header size, into first DT.
 */
static inline void k7_set_hrb_len (struct k7_dt *dt, unsigned int hrb_len)
{
	u64 control;

	hrb_len -= sizeof(u64);
	control = be64_to_cpu(dt->hwdt->control);
	control |= BE64VAL(28,47,hrb_len);
	dt->hwdt->control = cpu_to_be64(control);
}

void   k7_mem_zalloc (struct k7_dev *dev, struct k7_mem *mem, unsigned int len, k7_mem_t type);
void   k7_mem_free  (struct k7_dev *dev, struct k7_mem *mem);
void k7_reinit_htb (struct k7_dev *dev);
void k7_service_htb (struct k7_dev *dev);
void k7_write_hier (struct k7_dev *dev, u32 hier);
void k7_dev_failure_locked (struct k7_dev *dev, const char *name, const char *reason);
void k7_dev_failure (struct k7_dev *dev, const char *name, const char *reason);
int k7_alloc_irqs (struct k7_dev *dev, int num_irqs);
void k7_free_irqs (struct k7_dev *dev);
void k7_disable_all_irqs (struct k7_dev *dev);
void k7_disable_dma_irqs (struct k7_dev *dev);
int  k7_dma_map_dtc (struct k7_dev *dev, struct list_head *dtc, enum dma_data_direction direction);
void k7_dma_unmap_dtc (struct k7_dev *dev, struct list_head *dtc, enum dma_data_direction direction);
int k7_dma_map_req (struct k7_dev *dev, struct k7_req *req);
void k7_dma_unmap_req (struct k7_dev *dev, struct k7_req *req);
typedef enum {K7_NOT_RESET = 0, K7_WAS_RESET = 1} k7_was_reset_t;
void k7_reinit_dma_channel (struct k7_channel *channel, k7_was_reset_t was_reset);

void k7_dumpmem (struct k7_dev *clog_dev, const char *name, const char *prefix,
		const char *msg, const void *addr, dma_addr_t dma_addr, int len);
void k7_dump_dtc (struct k7_dev *clog_dev, const char *name, const char *msg, struct list_head *dtc, int datamax);
void k7_clog_dump_dtc (struct k7_channel *channel, const char *prefix, struct list_head *dtc, int datamax);

void k7_put_dt (struct k7_dev *dev, struct k7_dt *dt);
void k7_modify_dt_control (struct k7_hwdt *hwdt, u64 clear_bits, u64 set_bits);
struct k7_req *k7_find_req_from_dt (struct k7_channel *channel, u64 daddr, unsigned int ioc_flags, struct k7_dt **dt_p, const char *prefix);
u64 k7_read_m2h_mbx (struct k7_dev *dev);
void k7_free_channel_eoc (struct k7_channel *channel);
void k7_stop_htb_thread (struct k7_dev *dev);
int k7_start_htb_thread (struct k7_dev *dev);

typedef enum { K7_COPYIN, K7_COPYOUT } k7_copy_inout;
int k7_copy_udata (struct k7_dev *dev, unsigned int ioc_flags, struct list_head *dtc,
			k7_copy_inout inout, void __user *uaddr,
			unsigned int udata_len, unsigned int data_offset);

void k7_free_req (struct k7_channel *channel, struct k7_req *req, int was_submitted);
int k7_prepare_req (struct k7_channel *channel, unsigned int hrb_len, struct k7_dma_ioctl *ioc, unsigned int hra_type, struct k7_req **req_r);
int k7_handle_hra (struct k7_dev *dev, struct k7_req *req);
int k7_remove_req_from_busylist (struct k7_channel *channel, struct k7_req *req);
void k7_complete_req (struct k7_channel *channel, struct k7_req *req, int new_status, int do_wakeup);
int k7_wait_for_req (struct k7_channel *channel, struct k7_req *req);
void k7_poll_hisr (struct k7_dev *dev, u32 mask);
u32 k7_dma_hra_hdr_len (unsigned int target);
int k7_alloc_dtc (struct k7_channel *channel, struct list_head *dtc,
			unsigned int size, enum dma_data_direction direction);
void k7_free_all_dt_databufs (struct k7_dev *dev);
void k7_restart_busylist_timer (struct k7_channel *channel);
extern int k7_alloc_special_dt (struct k7_dev *dev);
void k7_free_dt (struct k7_channel *channel, struct k7_dt *dt);
void k7_free_dtc (struct k7_channel *channel, struct list_head *dtc, int was_submitted);
int k7_cb_ioctl (struct k7_dev *dev, unsigned int cmd, void __user *uargp, int compat);
int k7_do_dma_ioctl (struct k7_dev *dev, struct k7_dma_ioctl *ioc, unsigned int hrb_type);
int k7_attempt_dma_ioctl (struct k7_dev *dev, struct k7_dma_ioctl *ioc, unsigned int hrb_type);
int k7_submit_req (struct k7_channel *channel, struct k7_req *req);

int k7_cb_disable (struct k7_dev *dev);
int k7_cb_service_daddr (struct k7_dev *dev, u64 daddr);
int k7_cb_submit (struct k7_dev *dev, struct k7_channel *channel, struct k7_req *req);
void k7_cb_reinit_for_reset (struct k7_dev *dev, int force_free_busylist);
void k7_cb_init (struct k7_dev *dev);
void k7_update_hsm_state (struct k7_dev *dev, u32 new_state);
int k7_ioctl_dma_fastpath (struct k7_dev *dev, void __user *uargp, int compat);
int k7_ioctl_dma_kek_fastpath (struct k7_dev *dev, void __user *uargp, int compat);
int k7_dma_submit_and_wait (struct k7_dev *dev, struct k7_req *req, struct k7_dma_ioctl *ioc);
int k7_intercept_kek_key_cmd (struct k7_dev *dev, struct k7_req *req);
void k7_handle_kek_key_reply (struct k7_dev *dev, struct k7_req *req, void *data, unsigned int response_len, int truncated);
void k7_keycache_delete_key (struct k7_dev *dev, u32 key_handle, struct k7_kek_key *expected_kk);
void k7_put_key (struct k7_dev *dev, struct k7_kek_key *kk);
void k7_keycache_free (struct k7_dev *dev);
int k7_keycache_alloc (struct k7_dev *dev);
void k7_keycache_depopulate (struct k7_dev *dev);
void k7_keycache_reset (struct k7_dev *dev, int free_level2);
void k7_keycache_wake_all (struct k7_dev *dev);
void k7_fp_put_req_keys (struct k7_dev *dev, struct k7_req *req);
extern atomic_t k7_kek_key_struct_count;  /* global counter for debug */
void k7_keycache_stop_kek_group (struct k7_dev *dev, unsigned int group_id);
void k7_keycache_replace_kek_id (struct k7_dev *dev, u32 group_id, u32 kek_id, u32 pending_kek_id, u32 minimum_kek_id);
void k7_keycache_activate_kek_id (struct k7_dev *dev, u32 group_id, u32 kek_id, u32 minimum_kek_id);
void k7_keycache_update_minimum_kek_id (struct  k7_dev *dev, u32 group_id, u32 kek_id);
int k7_fp_return_lkrc (struct k7_dev *dev, struct k7_req *req, u32 lkrc, u32 raw_key_bytes, u32 kek_id);
int k7_handle_m2h_mbx (struct k7_dev *dev, u64 cmd);
int k7_send_to_mcpu (struct k7_dev *dev, const void *inbuf, int inbuf_size, void *outbuf, int outbuf_size, unsigned int flags, unsigned int hrb_type);
void k7_async_send_to_mcpu (struct k7_dev *dev, const char *msg_type, unsigned int hrb_type, unsigned int dma_flags, void *inbuf, unsigned int inbuf_size);
void k7_reinit_mcpu_channel_after_reset (struct k7_dev *dev);
int k7_wait_for_hsm_ready (struct k7_dev *dev, unsigned int timeout_secs);
int k7_read_sm_regs (struct k7_dev *dev, void *sm_regs, int locked, int *count_r);
int k7_ioctl_log (struct k7_dev *dev, struct k7_log_fifo *log, void __user *uargp, int compat);
void k7_log_deinit (struct k7_dev *dev);
int k7_log_init (struct k7_dev *dev);
u8 k7_get_random_byte (void);
void k7_minimal_dump_busylist (struct k7_channel *channel);
void k7_force_stop_all_dma_immediately (struct k7_dev *dev);
int k7_poll_pcie_link_failed (struct k7_dev *dev);
void k7_free_dev (struct kref *kref);
void k7_trigger_send_cbhras_to_mcpu (struct k7_dev *dev);
struct k7_dev *k7_get_dev_kref (struct k7_dev *dev);
void k7_restore_pci_state (struct k7_dev *dev);

unsigned long k7_lock_global (void);
void k7_unlock_global (unsigned long flags);
void k7_mcpu_reset_completed (struct k7_dev *dev);

void k7_free_session_groups (struct k7_dev *dev);
int k7_add_key_to_session (struct k7_dev *dev, u32 session_id, u32 key_handle, u32 generation);
void k7_delete_key_from_all_sessions (struct k7_dev *dev, u32 key_handle, u32 generation);
int k7_validate_key_for_session (struct k7_dev *dev, u32 session_id, u32 key_handle, u32 generation);
int k7_delete_session (struct k7_dev *dev, u32 session_id);
int k7_insert_hrb_prepadding (struct k7_channel *channel, struct k7_req *req, unsigned int prepadding);
void k7_pf2vf_timer_expiry (K7_KERNEL_TIMER_ARG_T arg);

#ifdef K7ETH
void k7eth_init       (struct k7_dev *dev);
void k7eth_deinit     (struct k7_dev *dev);
int k7eth_rx_ethernet (struct k7_dev *dev, void *vaddr);
#else
static inline void k7eth_init        (struct k7_dev *dev) {}
static inline void k7eth_deinit      (struct k7_dev *dev) {}
static inline int  k7eth_rx_ethernet (struct k7_dev *dev, void *vaddr) {return -EIO;}
#endif

#define K7_KEY_SLOT_EMPTY_FLAG	(1ul)
static inline struct k7_kek_key *k7_kk_null_if_empty (struct k7_kek_key *kk)
{
	unsigned long generation = (unsigned long)kk;

	if (generation & K7_KEY_SLOT_EMPTY_FLAG)
		kk = NULL;
	return kk;
}

static inline int k7_session_id_okay (u32 session_id)
{
	return session_id && session_id < K7_MAX_SESSIONS;
}

#define HD_MBX_PASS			0xb1          /* Ignore/passthru M2H mailbox value */
#define HD_MBX_MESSAGE			0xb2          /* Print a message in the DLOG */
#define HD_MBX_READ			0xb3          /* Read register on behalf of bootloader */
#define HD_MBX_WRITE			0xb4          /* Write register on behalf of bootloader */

#define HD_MBX_BL_STATE			0xbb
#define HD_MBX_FTE_STATE		0xfe

#define MBX_BL1_STATE_STARTED		0x11122334455666ull
#define MBX_BL1_STATE_READY             0x1123456789abcdull
#define MBX_BL1_STATE_CRIT_ERROR        0x10000011111111ull
#define MBX_BL1_STATE_FATAL_ERROR       0x10000022222222ull
#define MBX_BL1_STATE_COMMANDS          0x10000033333333ull
#define MBX_BL2_STATE_READY             0x2223456789abcdull
#define MBX_BL2_STATE_CRIT_ERROR        0x20000011111111ull
#define MBX_BL2_STATE_FATAL_ERROR       0x20000022222222ull
#define MBX_BL2_STATE_COMMANDS          0x20000033333333ull
#define MBX_BL2_STATE_ERASING           0x200000eeeeeeeeull
#define MBX_FTE_STATE_READY             0xdcba9876543210ull
#define MBX_FTE_STATE_CRIT_ERROR        0x00000011111111ull
#define MBX_FTE_STATE_FATAL_ERROR       0x00000022222222ull

#define K7_PTR_TO_U64(p)		((u64)(unsigned long)(p))

#ifdef K7_DUMP_KEYCACHE
unsigned int k7_do_dump_keycache (struct k7_dev *dev, u8 *kbuf, unsigned int n);
#endif /* K7_DUMP_KEYCACHE */

#endif /* __K7_INTERNAL_H__ */
