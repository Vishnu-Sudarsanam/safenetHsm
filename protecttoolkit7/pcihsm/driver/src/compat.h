/*
 * Copyright (c) 2013-2017 Safenet.  All rights reserved.
 *
 * compat.h -- compatibility for older Linux kernels
 */
#ifndef __K7_COMPAT_H__
#define __K7_COMPAT_H__

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define K7_KERNEL_TIMER_ARG_T unsigned long
static inline void k7_timer_setup(struct timer_list *timer_p, void *callback, unsigned long flags)
{
	init_timer(timer_p);
	timer_p->function = callback;
	timer_p->data = (long)timer_p;
}
#else
#define k7_timer_setup(timer_p, callback, flags)  timer_setup(timer_p, callback, flags)
#define K7_KERNEL_TIMER_ARG_T struct timer_list *
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
#include <linux/sched/signal.h>  /* for signal_pending() */
#endif

#if 0
/*
 * Older kernels may lack support for pci_enable_sriov().
 */
#ifndef CONFIG_PCI_IOV
static inline int  pci_enable_sriov (struct pci_dev *pdev, int num_vf) { return -ENODEV; }
static inline void pci_disable_sriov(struct pci_dev *pdev) { }
#endif
#endif

static inline void *k7_pde_data(const struct inode *inode)
{
/*
 * Kernel 5.17 renamed PDE_DATA to pde_data,
 * RHEL 9.1 backported this while keeping the kernel version 5.14
*/
#if defined(RHEL_RELEASE_CODE)
#define USE_NEW_PDE_DATA (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9,1))
#else
#define USE_NEW_PDE_DATA 0
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)) || USE_NEW_PDE_DATA
	return pde_data(inode);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0))
	return PDE(inode)->data;
#else
	return PDE_DATA(inode);
#endif
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0))
static inline struct inode *file_inode(struct file *f)
{
	return f->f_path.dentry->d_inode;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0))
/*
 * Older kernels lack pci_pcie_cap(), so do it the slow way instead.
 */
#define pci_pcie_cap(pdev)	pci_find_capability(pdev, PCI_CAP_ID_EXP)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0))

#define PCI_DISABLE_MSI		pci_disable_msi
#define PCI_DISABLE_MSIX	pci_disable_msix

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0))
#define PCI_ENABLE_MSI_EXACT(pdev,nvec)	pci_enable_msi_block(pdev,nvec)
#else
#define PCI_ENABLE_MSI_EXACT	pci_enable_msi_exact
#endif

#else

#define PCI_DISABLE_MSI		pci_free_irq_vectors
#define PCI_DISABLE_MSIX	pci_free_irq_vectors

static inline int PCI_ENABLE_MSI_EXACT(struct pci_dev *pdev, int nvec)
{
	return (pci_alloc_irq_vectors(pdev, nvec, nvec, PCI_IRQ_MSI) >= 0) ? 0 : -ENODEV;
}

#endif

static inline unsigned int k7_kref_read (struct kref *kref)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0))
	return (unsigned int)atomic_read(&kref->refcount);
#else
	return kref_read(kref);
#endif
}

/*
 * Older kernels lack pci_enable_msi_block().
 * Kernels that have it, redefine pci_enable_msi() as macro instead of a function.
 */
#ifndef pci_enable_msi
static inline int pci_enable_msi_block (struct pci_dev *pdev, int num_msi) { return -ENODEV; }
#endif

/*
 * printk() "CONTinuation" header:
 */
#ifndef KERN_CONT
#define KERN_CONT
#endif

/*
 * Older kernels may be missing some of these PCIe defines.
 */
#ifndef PCI_EXP_LNKSTA
#define PCI_EXP_LNKSTA 18
#endif
#ifndef PCI_EXP_LNKSTA_CLS
#define PCI_EXP_LNKSTA_CLS 0x000f
#endif
#ifndef PCI_EXP_LNKSTA_CLS_2_5GB
#define PCI_EXP_LNKSTA_CLS_2_5GB 1
#endif
#ifndef PCI_EXP_LNKSTA_CLS_5_0GB
#define PCI_EXP_LNKSTA_CLS_5_0GB 2
#endif
#ifndef PCI_EXP_LNKSTA_CLS_8_0GB
#define PCI_EXP_LNKSTA_CLS_8_0GB 3
#endif
#ifndef PCI_EXP_LNKSTA_NLW
#define PCI_EXP_LNKSTA_NLW 0x03f0
#endif
#ifndef PCI_EXP_LNKSTA_NLW_SHIFT
#define PCI_EXP_LNKSTA_NLW_SHIFT 4
#endif
#ifndef PCI_EXP_DEVCAP2
#define PCI_EXP_DEVCAP2 36
#endif
#ifndef PCI_EXP_DEVCAP2_ARI
#define PCI_EXP_DEVCAP2_ARI 0x20
#endif
#ifndef PCI_EXP_DEVCTL2
#define PCI_EXP_DEVCTL2 40
#endif
#ifndef PCI_EXP_DEVCTL2_ARI
#define PCI_EXP_DEVCTL2_ARI 0x20
#endif

#ifndef IRQF_DISABLED  /* obsolete: has been a "no-op" for ages now */
#define IRQF_DISABLED 0
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32))   //FIXME not sure which version to use here
	#define request_threaded_irq(irq, flh, thread, flags, name, dev) \
		request_irq(irq, thread, IRQF_DISABLED, name, dev)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36))   //FIXME not sure which version to use here
	#define k7_device_trylock(dev)	(1)
	#define k7_device_unlock(dev)	do {} while (0)
#else
	#define k7_device_trylock	device_trylock
	#define k7_device_unlock	device_unlock
#endif

#ifndef list_first_entry_or_null
#define list_first_entry_or_null(ptr, type, member) \
        (!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32))
#include <linux/atomic.h>
#endif

#ifndef printk_ratelimited
#define printk_ratelimited printk
#endif

#ifndef INIT_DEFERRABLE_WORK
#define INIT_DEFERRABLE_WORK INIT_DELAYED_WORK
#endif

/*
 * Official kernel.org kernels >= 3.0.0 have these functions.
 * But not some Redhat kernels that claim to be 3.10.0, possibly others too.
 * So, just blacklist everything older than 4.0.0.
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0))
static inline void *PCI_STORE_SAVED_STATE (struct pci_dev *pdev) {return NULL;}
static inline void  PCI_LOAD_SAVED_STATE  (struct pci_dev *pdev, void *saved_state) {}
#else
#define PCI_STORE_SAVED_STATE pci_store_saved_state
#define PCI_LOAD_SAVED_STATE  pci_load_saved_state
#endif

#endif /* __K7_COMPAT_H__ */
