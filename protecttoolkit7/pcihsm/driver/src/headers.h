/*
 * Copyright (c) 2013-2017 Safenet.  All rights reserved.
 */
#ifndef __K7_HEADERS_H__
#define __K7_HEADERS_H__
/*
 * headers.h -- pulls in all needed header files in a correct sequence.
 * Copyright 2016, Safenet Inc.
 */
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/blkdev.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/kref.h>
#include <linux/interrupt.h>
#include <linux/compiler.h>
#include <linux/workqueue.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/mutex.h>
#include <linux/dma-mapping.h>
#include <linux/cdev.h>
#include <linux/completion.h>
#include <linux/compat.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <linux/ratelimit.h>
#include <linux/aer.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/msr.h>

#include "compat.h"
#include "spinlock.h"
#include "ioctl.h"
#include "uhd_ioctl.h"  /* for G5/K6 compatible ioctls */
#include "internal.h"
#include "regs.h"

#include "dmaheaders.h"

#ifndef list_tail_entry
#define list_tail_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)
#endif

#ifndef ENOTSUP
#define ENOTSUP (ENOTSUPP)	/* Linux kernel misspells this */
#endif

#endif /* __K7_HEADERS_H__ */
