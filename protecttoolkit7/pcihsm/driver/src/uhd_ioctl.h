/*
 * Copyright (c) 2013-2017 Safenet.  All rights reserved.
 *
 * uhd_ioctl.h
 */
#ifndef UHD_IOCTL_H
#define UHD_IOCTL_H

/*
 * Callback ioctls, binary compatible with G5/K6 host drivers.
 */
#define UHD_IOCTL_RESET_DEVICE	_IO('L', 0x02)  /* for backward compatibility: autoselects HOST/FLR reset */
#define UHD_IOCTL_CB_IO_READ	_IO('L', 0x10)
#define UHD_IOCTL_CB_IO_WRITE	_IO('L', 0x11)
#define UHD_IOCTL_CB_IO_CANCEL	_IO('L', 0x12)
#define UHD_IOCTL_CB_IO_QUERY	_IO('L', 0x13)

typedef struct uhd_ioctl_cb_rw_in_param_s {
   __u32    hios_id;                /* A valid HIOS ID or HIOS_ID_NULL for "listen" requests */
   __u32    timeout;                /* Timeout, ms */
   __u64    buf;                    /* in for writes, out for reads */
   __u32    size;                   /* data size for writes, how much to read for reads */
} uhd_ioctl_cb_rw_in_param_t;


typedef struct uhd_ioctl_cb_rw_out_param_s {
   __u32    hios_id;                /* The same or new hios_id (for listen requests */
   __u32    cb_ret;                 /* Result code */
   __u32    timeout;                /* How much left of timeout */
   __u32    transmitted;            /* Number of bytes actually transmitted */
} uhd_ioctl_cb_rw_out_param_t;


typedef struct uhd_ioctl_cb_rw_param_s {
   __u64    in;                     /* pointer to the input parameters */
   __u64    out;                    /* pointer to the output parameters */
} uhd_ioctl_cb_rw_param_t;

typedef uhd_ioctl_cb_rw_in_param_t     uhd_ioctl_cb_read_in_param_t;
typedef uhd_ioctl_cb_rw_out_param_t    uhd_ioctl_cb_read_out_param_t;

typedef uhd_ioctl_cb_rw_in_param_t     uhd_ioctl_cb_write_in_param_t;
typedef uhd_ioctl_cb_rw_out_param_t    uhd_ioctl_cb_write_out_param_t;


typedef struct uhd_ioctl_cb_cancel_in_param_s {
   __u32    hios_id;
} uhd_ioctl_cb_cancel_in_param_t;

#define CB_QUERY_INFO                                    0
#define CB_QUERY_CALLBACK_IO_NOT_SUPPORTED_BY_HSM        0
#define CB_QUERY_CALLBACK_IO_NOT_SUPPORTED_BY_DRIVER     1
#define CB_QUERY_CALLBACK_IO_SUPPORTED                   2

typedef struct uhd_ioctl_cb_query_in_param_s {
   __u32    what;                      /* Set to CB_QUERY_IS_SUPPORTED to query if CB is supported */
} uhd_ioctl_cb_query_in_param_t;

typedef struct uhd_ioctl_cb_query_out_param_s {
   __u32    cb_support_level;          /* Result of the query */
   __u32    cb_io_version;
   __u32    cb_protocol_version;
} uhd_ioctl_cb_query_out_param_t;

typedef struct uhd_ioctl_cb_query_param_s {
   __u64    in;                        /* Pointer to the uhd_ioctl_cb_query_in_param_t */
   __u64    out;                       /* Pointer to the uhd_ioctl_cb_query_out_param_t */
} uhd_ioctl_cb_query_param_t;

struct uhd_cb_rw_args {
        struct uhd_ioctl_cb_rw_param_s     param;
        struct uhd_ioctl_cb_rw_in_param_s  in;
        struct uhd_ioctl_cb_rw_out_param_s out;
};

typedef struct vip_ioctl64_buffer_s
{
   __u64	addr;
   __u32	len;
} vip_ioctl64_buffer_t;

#define K7_DLOG_FIFO_BYTES	( 32 * 1024)	/* Max size of driver's internal DLOG FIFO */
#define K7_CLOG_FIFO_BYTES	(512 * 1024)	/* Max size of driver's internal CLOG FIFO */

/*
 * VIP_IOCTL_HSM_DLOG_READ ioctl parameters.
 *
 * - buf.len/buf.addr: user space buffer to put HSM debug messages from
 *   the dlog to.
 *
 * - flags: turn printing of the HSM debug messages to syslog On/Off and/or
 *   enable/disable dlog overrun. Can be set to 0, or any 'or' combination
 *   of *ON/OFF constants defined above.
 *
 * buf.len != 0 && buf.addr == 0 or buf.len == 0 && flags == 0 are invalid
 * settings.
 */
typedef struct vip_ioctl64_dlog_parms_s
{
	__u32			flags;	/* in        */
	vip_ioctl64_buffer_t	buf;	/* in (*out) */
} vip_ioctl64_dlog_parms_t;

#define VIP_IOCTL_HSM_DLOG_READ        _IO('L', 0x8a)
#define K7_DLOG_READ                   VIP_IOCTL_HSM_DLOG_READ
#define K7_CLOG_READ                   _IO('L', 0x9a)

/*
 * Parameters for VIP_IOCTL_HSM_DLOG_READ.
 * HSM_DLOG stands for HSM debug messages log
 */

/* Blocking or non-blocking call */
#define VIP_HSM_DLOG_WAIT                 (1 << 0)
#define K7_LOG_FLAG_WAIT                  VIP_HSM_DLOG_WAIT

/*
 * By default the driver prints the HSM debug messages to the syslog (on
 * supported platforms, see below). Printing can be enabled and disabled
 * using different methods, including using 'flags' field in the parameters
 * of the VIP_IOCTL_HSM_DLOG_READ ioctl. Ioctl parameters are defined in
 * the struct vip_ioctl*_dlog_parms_s.
 *
 * Bit telling the driver to turn printing of the HSM debug messages to the
 * syslog on or off. ON/OFF value is provided by the accompaning bit, below.
 *
 * Note. So far does not print to syslog on Windows. Windows driver uses
 * KdPrint(), which prints to kernel debug log buffer, rather than to syslog.
 *
 * Don't use this bit directly. Use VIP_HSM_DLOG_PRINT_TO_SYSLOG_ON/OFF
 * constants (below).
 */
#define VIP_HSM_DLOG_PRINT_TO_SYSLOG_SET  (1 << 1)
#define K7_LOG_FLAG_SYSLOG_SET            VIP_HSM_DLOG_PRINT_TO_SYSLOG_SET

/*
 * Value to set: 1 (on) or 0 (off). Ignored by the driver if
 * VIP_HSM_DLOG_PRINT_TO_SYSLOG_SET bit is zero. When printing switch changes
 * from off to on, the driver starts printing _new_ HSM debug messages, The
 * ones that have been already read and stored in dlog are noto printed out.
 *
 * Don't use this bit directly. Use VIP_HSM_DLOG_PRINT_TO_SYSLOG_ON/OFF
 * constants (below).
 */
#define VIP_HSM_DLOG_PRINT_TO_SYSLOG_VAL  (1 << 2)
#define K7_LOG_FLAG_SYSLOG_VAL            VIP_HSM_DLOG_PRINT_TO_SYSLOG_VAL

/*
 * To control printing of the HSM debug messages to the syslog, applications
 * should use in the ::flags field of the vip_ioctl(64)_dlog_parms_t the
 * constants defined below.
 */
#define VIP_HSM_DLOG_PRINT_TO_SYSLOG_ON   \
   (VIP_HSM_DLOG_PRINT_TO_SYSLOG_SET | VIP_HSM_DLOG_PRINT_TO_SYSLOG_VAL)
#define K7_LOG_FLAGS_SYSLOG_ON  VIP_HSM_DLOG_PRINT_TO_SYSLOG_ON

#define VIP_HSM_DLOG_PRINT_TO_SYSLOG_OFF  \
   (VIP_HSM_DLOG_PRINT_TO_SYSLOG_SET | 0)
#define K7_LOG_FLAGS_SYSLOG_OFF  VIP_HSM_DLOG_PRINT_TO_SYSLOG_OFF

/*
 * Bit telling the driver to turn dlog overrun on or off.
 * IGNORED and NOT IMPLEMENTED on K7!!
 */
#define VIP_HSM_DLOG_DONT_OVERRUN_SET     (1 << 3)
#define VIP_HSM_DLOG_DONT_OVERRUN_VAL     (1 << 4)

/*
 * To control dlog overrun, applications should use in the ::flags field of
 * the vip_ioctl(64)_dlog_parms_t the constants defined below.
 * IGNORED and NOT IMPLEMENTED on K7!!
 */
#define VIP_HSM_DLOG_DONT_OVERRUN_ON   \
   (VIP_HSM_DLOG_DONT_OVERRUN_SET | VIP_HSM_DLOG_DONT_OVERRUN_VAL)

#define VIP_HSM_DLOG_DONT_OVERRUN_OFF  \
   (VIP_HSM_DLOG_DONT_OVERRUN_SET | 0)

/*
 * By default the driver erases DLOG entries as they are read.
 * But for test/debug with lunadiag, it is desireable to be able
 * to read the DLOG without erasing it.
 * This flag is NOT permitted in combination with VIP_HSM_DLOG_WAIT.
 * This is a K7-only feature.
 */
#define K7_LOG_FLAG_NO_ERASE_ON_READ	(1 << 11)

/*
 * Turn logging on/off (both to FIFO, and to syslog if enabled).
 */
#define K7_LOG_FLAG_ENABLE		(1 << 12)  /* enable logging */
#define K7_LOG_FLAG_DISABLE		(1 << 13)  /* disable logging  */

/*
 * K7 uses very similar handling for a Command/response log (CLOG).
 * The storage for this log fifo is not allocated by default,
 * and so there are these two ioctl() calls to alloc/free it.
 * These also work for the DLOG fifo, though probably shouldn't be used.
 */
#define K7_LOG_FLAG_ALLOC		(1 << 14)  /* allocate log FIFO if not already allocated */
#define K7_LOG_FLAG_FREE		(1 << 15)  /* free log FIFO if not already freed */

#endif /* UHD_IOCTL_H */
