/*
 * Copyright (c) 2013-2017 Safenet.  All rights reserved.
 *
 * spinlock.h -- wrapper for debugging spinlocks
 */
#ifndef __K7_SPINLOCK_H__
#define __K7_SPINLOCK_H__

#define K7_SPINLOCK_VERIFY	1	/* 1==debug-on, 0==debug-off */

#if !K7_SPINLOCK_VERIFY
/*
 * Use the native spinlock stuff directly.
 */

#define SPIN_LOCK_REQUIRED(lock)		do {} while (0)
#define K7_DECLARE_SPINLOCK(lock)		spinlock_t lock
#define SPIN_LOCK_IRQSAVE(lock,flags)		spin_lock_irqsave(lock,flags)
#define SPIN_LOCK_IRQ(lock)			spin_lock_irq(lock)
#define SPIN_LOCK(lock)				spin_lock(lock)
#define SPIN_UNLOCK_IRQRESTORE(lock,flags)	spin_unlock_irqrestore(lock,flags)
#define SPIN_UNLOCK_IRQ(lock)			spin_unlock_irq(lock)
#define SPIN_UNLOCK(lock)			spin_unlock(lock)
#define SPIN_LOCK_INIT(lock)			spin_lock_init(lock)

#define SPIN_LOCK_TIMEOUT(lock,max_wait,ret,errno)			\
	do {								\
		unsigned long timeout = jiffies + (max_wait);		\
		while (!spin_trylock(lock)) {				\
			if (time_after(jiffies, timeout)) {		\
				ret = errno;				\
				break;					\
			}						\
		}							\
	} while (0)

#else
/*
 * Wrap native spinlock stuff with a layer of error/deadlock detection.
 */
#include <asm/hardirq.h>  // for in_interrupt()

#define K7_DECLARE_SPINLOCK(lock)		spinlock_t lock ; void *lock##_holder ; int lock##_dumped
#define SPINLOCK_MAX_COMPLAIN	2

#define SPIN_LOCK_GET_HOLDER_CURTASK(lock)				\
	void **holder = lock##_holder;					\
	void *curtask = in_interrupt() ? (void *)-1l : current;

#define SPIN_LOCK_INIT(lock)						\
	do {								\
		spin_lock_init(lock);					\
		*(lock##_holder) = NULL;				\
		*(lock##_dumped) = 0;					\
	} while (0)

#define SPIN_LOCK_REQUIRED(lock)					\
	do {								\
		SPIN_LOCK_GET_HOLDER_CURTASK(lock)			\
		if (*holder != curtask) {				\
			if (*(lock##_dumped) < SPINLOCK_MAX_COMPLAIN) {	\
				kerr(DRV_NAME, "spinlock: not held");	\
				*(lock##_dumped) += 1;			\
				dump_stack();				\
			}						\
		}							\
	} while (0)

#define SPIN_LOCK_CHECK_HOLDER(lock)					\
	if (*holder == curtask) {					\
		if (*(lock##_dumped) < SPINLOCK_MAX_COMPLAIN) {		\
			panic("spinlock already held by current task");	/*FIXME*/\
			kerr(DRV_NAME, "spin_lock: already held");	\
			*(lock##_dumped) += 1;				\
			dump_stack();					\
		}							\
	}

#define SPIN_UNLOCK_CHECK_HOLDER(lock)					\
	SPIN_LOCK_GET_HOLDER_CURTASK(lock)				\
	if (*holder == curtask) {					\
		*holder = NULL;						\
	} else {							\
		if (*(lock##_dumped) < SPINLOCK_MAX_COMPLAIN) {		\
			kerr(DRV_NAME, "spin_unlock: not owner, curtask=%p, holder=%p", curtask, holder); \
			*(lock##_dumped) += 1;				\
			dump_stack();					\
		}							\
	}

#define SPIN_LOCK_IRQSAVE(lock,flags)					\
	do {								\
		SPIN_LOCK_GET_HOLDER_CURTASK(lock)			\
		if (!spin_trylock_irqsave(lock, flags)) {		\
			SPIN_LOCK_CHECK_HOLDER(lock)			\
			spin_lock_irqsave(lock, flags);			\
		}							\
		*holder = curtask;					\
	} while (0)

#define SPIN_LOCK_IRQ(lock)						\
	do {								\
		SPIN_LOCK_GET_HOLDER_CURTASK(lock)			\
		if (!spin_trylock_irq(lock)) {				\
			SPIN_LOCK_CHECK_HOLDER(lock)			\
			spin_lock_irq(lock);				\
		}							\
		*holder = curtask;					\
	} while (0)

#define SPIN_LOCK(lock)							\
	do {								\
		SPIN_LOCK_GET_HOLDER_CURTASK(lock)			\
		if (!spin_trylock(lock)) {				\
			SPIN_LOCK_CHECK_HOLDER(lock)			\
			spin_lock(lock);				\
		}							\
		*holder = curtask;					\
	} while (0)

#define SPIN_UNLOCK_IRQRESTORE(lock,flags)				\
	do {								\
		SPIN_UNLOCK_CHECK_HOLDER(lock)				\
		spin_unlock_irqrestore(lock, flags);			\
	} while (0)

#define SPIN_UNLOCK_IRQ(lock)						\
	do {								\
		SPIN_UNLOCK_CHECK_HOLDER(lock)				\
		spin_unlock_irq(lock);					\
	} while (0)

#define SPIN_UNLOCK(lock)						\
	do {								\
		SPIN_UNLOCK_CHECK_HOLDER(lock)				\
		spin_unlock(lock);					\
	} while (0)

#define SPIN_LOCK_TIMEOUT(lock,max_wait,ret,errno)			\
	do {								\
		SPIN_LOCK_GET_HOLDER_CURTASK(lock)			\
		if (!spin_trylock(lock)) {				\
			unsigned long timeout = jiffies + (max_wait);	\
			SPIN_LOCK_CHECK_HOLDER(lock)			\
			while (!spin_trylock(lock)) {			\
				if (time_after(jiffies, timeout)) {	\
					ret = errno;			\
					break;				\
				}					\
			}						\
		}							\
		if (ret != errno)					\
			*holder = curtask;				\
	} while (0)

#endif /* K7_SPINLOCK_VERIFY */
#endif /* __K7_SPINLOCK_H__ */
