/*
 * Copyright (c) 2013-2017 Safenet.  All rights reserved.
 *
 * proc.h
 */
#ifndef __K7_PROC_H__
#define __K7_PROC_H__

#ifdef CONFIG_PROC_FS
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32))	//FIXME: figure out exactly which kernels we support
#define K7_HAVE_PROC_FS

#include "headers.h"
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

struct k7_proc_desc {
	char		name[32]; /* name of the /proc/k7/ entry */
	struct k7_dev	*dev;	/* device, or NULL for simply "k7" */
	void		*val_p;	/* pointer to the data (or offset for a register) */
	long		min;	/* minimum value when writing (ignored if same as max) */
	long		max;	/* maximum value when writing (ignored if same as min) */
	const struct k7_regbits	*regbits;
	void		(*readfunc)(struct seq_file *, struct k7_proc_desc *);	/* function for reading the value */
	int		(*writefunc)(struct k7_proc_desc *, const char *);	/* function for storing a new value */
};

/* This is from regs.c */
void k7_dumpreg_seq (struct seq_file *seq, const char *label, u64 reg, const struct k7_regbits *regbits);

#endif  /* CONFIG_PROC_FS */
#endif  /* LINUX_VERSION_CODE */

/* Setup/teardown functions */
void k7_proc_create_dev (struct k7_dev *dev);
void k7_proc_destroy_dev (struct k7_dev *dev);
void k7_proc_create (void);
void k7_proc_destroy (void);

#endif /* __K7_PROC_H__ */
