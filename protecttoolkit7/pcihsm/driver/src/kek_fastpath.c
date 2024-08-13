/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * kek_fastpath.c
 */
#include "headers.h"

#define OS_LINUX 1
#include "fwrc.h"

#define KEKDEBUG kdebug		/* Use kfinfo for testing, or kdebug for normal operation */

/*
 * Fastpath SKU keycache for KEK'd keys:
 */

atomic_t k7_kek_key_struct_count;  /* global counter for debug */

/*
 * Hash a u32 HSM "mechanism" value into a u8 table index.
 */
static u8 k7_hash_mechanism_to_u8 (u32 mechanism)
{
	u8  m[4];

	*(u32 *)m = mechanism;
	return m[0] ^ m[1] ^ m[2] ^ m[3];
}

/*
 * Convert a 32-bit external library/HSM "mechanism" value to an
 * internal 8-bit "mech" index, as part of KEK_KEY command processing.
 * To speed things up, we use a hash(mechanism) index for starters.
 * This should work well enough for a sparse table, with few mechanisms.
 */
static int k7_mechanism_to_mech (struct k7_dev *dev, u32 mechanism)
{
	u32 *mechanisms = dev->mechanisms;
	u8 hash = k7_hash_mechanism_to_u8(mechanism), mech = hash;

	do {
		if (mech) {  /* zero is never a valid mech index */
			u32 this_mechanism = mechanisms[mech];
			if (mechanism == this_mechanism)
				return mech;  /* found it */
			if (!this_mechanism) {
				/* Guard against races by checking again, with spinlock */
				SPIN_LOCK(&dev->mechanisms_lock);
				if (!mechanisms[mech]) {
					dev->mech_ops[mech] = 0;
					mechanisms[mech] = mechanism;
				}
				SPIN_UNLOCK(&dev->mechanisms_lock);
				if (mechanism == mechanisms[mech])
					return mech;  /* new entry */
			}
		}
	} while (++mech != hash);  /* u8 mech wraps automatically here */
	kerr(dev->name, "BUG: mechanism table is full");
	return -EIO;
}

/*
 * sdbm hash function from http://www.cse.yorku.ca/~oz/hash.html:
 * The code below is an optimized version of this:
 *	hash(i) = hash(i - 1) * 65599 + list[i];
 */
static u32 k7_hash_mechs (u8 *mechs)
{
	u32 hash = 0;
	u8 mech;

	if (mechs) {
		while (0 != (mech = *mechs++))
			hash = mech + (hash << 6) + (hash << 16) - hash;
	}
	return hash;
}

/*
 * Save "mechs" into a free slot in "mechlists[]", but only after first
 * searching for an existing list with identical contents.
 * The mechlist index of the saved (or pre-existing) list is returned to caller.
 *
 * Each list within mechlists[] is maintained in increasing order by mech.
 * But mechlists[] itself is not maintained in any particular order,
 * other than that empty slots are always contiguous at the end.
 */
static int k7_save_mechlist (struct k7_dev *dev, u8 *mechs, struct k7_mechlist mechlists[])
{
	int mechlist;
	u32 mechs_hash = k7_hash_mechs(mechs);

	/* Search mechlists for an identical mechs[] list, or first empty slot */
	for (mechlist = 1; mechlist < K7_MAX_MECHLISTS; ++mechlist) {  /* mechlists[0] is always an empty list */
		struct k7_mechlist *list = &mechlists[mechlist];
		if (!list->mechs) {  /* Empty slot? */
			/* spinlock not needed because only HTB-IRQ thread ever modifies _mechlists[] */
			list->mechs = mechs;      /* save new mechs list */
			list->hash  = mechs_hash; /* along with accompanying hash */
			return mechlist;  /* list index of where it was saved */
		}
		if (list->hash == mechs_hash && 0 == strcmp(list->mechs, mechs)) {  /* Found an existing identical list? */
			kfree(mechs);  /* mechs list is not needed, so free it */
			return mechlist;  /* list index for existing identical list */
		}
	}
	kerr(dev->name, "BUG: mechlist table is full");
	kfree(mechs);  /* mechs list not saved, so free it */
	return -EIO;
}

/*
 * Create a clone of "mechlist" with "mech" removed from the clone.
 * Then save the clone in mechlists[], but only after first searching
 * for an existing list with identical contents.
 * The list index of the saved (or pre-existing) list is returned to caller.
 */
static int k7_del_from_mechlist (struct k7_dev *dev, u16 mechlist, u8 mech, struct k7_mechlist mechlists[])
{
	u8 *new, *mechs = mechlists[mechlist].mechs;
	unsigned int i;

	if (!mechs)
		return mechlist;  /* mechs was empty, so mech not there */
	for (i = 0; mech < mechs[i]; ++i);  /* Note: ordered list, zero-terminated */
	if (mech != mechs[i])
		return mechlist;  /* mech not in mechlist, so return the same list */
	if (i == 0 && !mechs[1])
		return 0;  /* return mechindex for empty list */

	/* Remove mech from a new[] clone of mechs[] */
	new = kzalloc(K7_MAX_MECHS, GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	if (i > 0)
		memcpy(new, mechs, i);
	strcpy(new + i, mechs + i + 1);
	return k7_save_mechlist(dev, new, mechlists);
}

/*
 * Create a clone of "mechlist" with "mech" inserted into the clone.
 * Then save the clone in mechlists[], but only after first searching
 * for an existing list with identical contents.
 * The list index of the saved (or pre-existing) list is returned to caller.
 */
static int k7_add_to_mechlist (struct k7_dev *dev, u16 mechlist, u8 mech, struct k7_mechlist mechlists[])
{
	unsigned int i = 0;
	u8 *new, *mechs = mechlists[mechlist].mechs;

	if (mechs) {
		for (; mech < mechs[i]; ++i);  /* Note: ordered mechs, zero-terminated */
		if (mech == mechs[i])
			return mechlist;  /* already in mechs */
		if (i >= (K7_MAX_MECHS - 1)) {	/* Mathematically impossible */
			kerr(dev->name, "BUG: mechlists[%u] is full", mechlist);
			return -EIO;
		}
	}

	/* Insert mech into a new[] clone of mechs[] */
	new = kzalloc(K7_MAX_MECHS, GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	if (mechs && i > 0)
		memcpy(new, mechs, i - 1);
	new[i] = mech;
	if (mechs)
		strcpy(new + i + 1, mechs + i);
	return k7_save_mechlist(dev, new, mechlists);
}

/*
 * Search "mechlist" for "mech", returning 0 if mech is not present.
 */
static int k7_match_mechlist (struct k7_dev *dev, u8 *list, u8 mech)
{
	unsigned int i;

	if (list) {
		/* spinlock not needed because we never modify an existing mechlist[] in-place */
		for (i = 0; mech < list[i]; ++i);  /* Note: ordered list, zero-terminated */
		if (mech == list[i])
			return mech;  /* matched */
	}
	return 0;  /* no match */
}

static void k7_kk_free (struct kref *kref)
{
	struct k7_kek_key *kk = container_of(kref, struct k7_kek_key, kref);

	memset(kk, 0, sizeof(*kk));  /* wipe kk->key_data[] */
	kfree(kk);
	atomic_dec(&k7_kek_key_struct_count);  /* global counter for debug */
}

static u32 k7_slot_generation (struct k7_kek_key *kk)
{
	unsigned long generation = (unsigned long)kk;

	if (!generation || generation & K7_KEY_SLOT_EMPTY_FLAG)
		return (u32)(generation >> 1);
	return kk->generation;
}

static inline struct k7_kek_key *k7_empty_key_slot_value (u32 generation)
{
	unsigned long kk = (((unsigned long)generation) << 1) | K7_KEY_SLOT_EMPTY_FLAG;
	return (struct k7_kek_key *)kk;
}

static inline void k7_delete_kk_from_slot (struct k7_key_slot *slot, struct k7_kek_key *kk)
{
	//SPIN_LOCK_REQUIRED(&dev->keycache_lock);
	slot->kk = k7_empty_key_slot_value(kk->generation);
	kref_put(&kk->kref, k7_kk_free);  /* keycache's reference */
}

static struct k7_kek_key *k7_kk_zalloc (void)
{
	struct k7_kek_key *kk = kzalloc(sizeof(*kk), GFP_KERNEL);

	if (kk) {
		kref_init(&kk->kref);  /* initial reference */
		atomic_inc(&k7_kek_key_struct_count);  /* global counter for debug */
	}
	return kk;
}

static void k7_keycache_free_level2 (struct k7_dev *dev, struct k7_keycache_level2 *level2)
{
	if (level2) {
		int used_vmalloc = level2->used_vmalloc;
		memset(level2, 0, K7_KEYCACHE_LEVEL2_ALLOC_BYTES);
		if (used_vmalloc)
			vfree(level2);
		else
			free_pages((unsigned long)level2, get_order(K7_KEYCACHE_LEVEL2_ALLOC_BYTES));
	}
}

static void k7_keycache_init_level2 (struct k7_keycache_level2 *level2, unsigned int used_vmalloc)
{
	int i;

	memset(level2, 0, K7_KEYCACHE_LEVEL2_ALLOC_BYTES);
	level2->used_vmalloc = used_vmalloc;
	for (i = 0; i < K7_KEYCACHE_LEVEL2_WIDTH; ++i)
		mutex_init(&level2->slot[i].rekek_mutex);
}

static struct k7_keycache_level2 *k7_keycache_alloc_level2 (struct k7_dev *dev,
					struct k7_keycache_level2 **level2_p, unsigned int index1)
{
	struct k7_keycache_level2 *level2;
	int used_vmalloc = 0;

	if (mutex_lock_interruptible(&dev->level2_alloc_mutex))
		return NULL;
	rmb();  /* Synchronize with wmb() in k7_keycache_alloc_level2() */
	level2 = *level2_p;
	if (!level2) {
		level2 = (void *)__get_free_pages(GFP_KERNEL, get_order(K7_KEYCACHE_LEVEL2_ALLOC_BYTES));
		if (!level2) {
			kdebug(dev->name, "vmalloc(%u)", K7_KEYCACHE_LEVEL2_ALLOC_BYTES);
			level2 = vmalloc(K7_KEYCACHE_LEVEL2_ALLOC_BYTES);
			if (!level2)
				kerr(dev->name, "allocation failed");
			else
				used_vmalloc = 1;
		}
		if (level2) {
			k7_keycache_init_level2(level2, used_vmalloc);
			wmb();  /* Synchronize with rmb() in k7_keycache_get_slot() */
			SPIN_LOCK(&dev->keycache_lock);
			*level2_p = level2;
			if (index1 > dev->keycache_level1_max)
				dev->keycache_level1_max = index1;  /* high-water mark */
			SPIN_UNLOCK(&dev->keycache_lock);
		}
	}
	mutex_unlock(&dev->level2_alloc_mutex);
	return level2;
}

static struct k7_key_slot *k7_keycache_get_slot (struct k7_dev *dev, u32 key_handle)
{
	if (!key_handle || key_handle >= K7_KEYCACHE_MAX_HANDLES) {
		kwarn(dev->name, "bad key_handle: 0x%08x", key_handle);
		return NULL;
	} else {
		unsigned int index1 = key_handle / K7_KEYCACHE_LEVEL2_WIDTH;
		unsigned int index2 = key_handle % K7_KEYCACHE_LEVEL2_WIDTH;
		struct k7_keycache_level2 **level2_p = &dev->keycache->level2[index1];
		struct k7_keycache_level2 *level2;
		rmb();  /* Synchronize with wmb() in k7_keycache_alloc_level2() */
		level2 = *level2_p;
		if (!level2) {
			level2 = k7_keycache_alloc_level2(dev, level2_p, index1);
			if (!level2)
				return NULL;
		}
		return &level2->slot[index2];
	}
}

static inline struct mutex *k7_rekek_get_mutex (struct k7_dev *dev, u32 key_handle)
{
	struct k7_key_slot *slot = k7_keycache_get_slot(dev, key_handle);
	return slot ? &(slot->rekek_mutex) : NULL;
}

static int k7_rekek_lock (struct k7_dev *dev, u32 key_handle)
{
	struct mutex *mutex = k7_rekek_get_mutex(dev, key_handle);
	if (!mutex)
		return -ENOMEM;
	return mutex_lock_interruptible(mutex);
}

static void k7_rekek_unlock (struct k7_dev *dev, u32 key_handle)
{
	struct mutex *mutex = k7_rekek_get_mutex(dev, key_handle);
	if (mutex)
		mutex_unlock(mutex);
	else
		kerr(dev->name, "BUG: key_handle=%08x no mutex", key_handle);
}

static struct k7_kek_key *k7_keycache_lookup (struct k7_dev *dev, u32 key_handle)
{
	struct k7_key_slot *slot;
	struct k7_kek_key  *kk;

	slot = k7_keycache_get_slot(dev, key_handle);
	if (!slot)
		return NULL;
	SPIN_LOCK(&dev->keycache_lock);
	kk = k7_kk_null_if_empty(slot->kk);
	if (kk)
		kref_get(&kk->kref);  /* caller's reference */
	SPIN_UNLOCK(&dev->keycache_lock);
	return kk;
}

void k7_keycache_delete_key (struct k7_dev *dev, u32 key_handle, struct k7_kek_key *expected_kk)
{
	struct k7_key_slot *slot;
	struct k7_kek_key  *kk;

	slot = k7_keycache_get_slot(dev, key_handle);
	if (slot) {
		u32 generation = 0;
		int do_delete  = 1;
		SPIN_LOCK(&dev->keycache_lock);
		kk = slot->kk;
		if (k7_kk_null_if_empty(kk) != NULL) {
			if (!expected_kk || kk == expected_kk) {
				generation = kk->generation;
				k7_delete_kk_from_slot(slot, kk);
			} else {
				do_delete = 0;
			}
		} else {
			generation = expected_kk ? expected_kk->generation : k7_slot_generation(kk);
		}
		SPIN_UNLOCK(&dev->keycache_lock);
		if (do_delete)
			k7_delete_key_from_all_sessions(dev, key_handle, generation);
	}
}

static void k7_copy_old_mechlists (struct k7_dev *dev, struct k7_key_slot *slot, struct k7_kek_key *new_kk)
{
	struct k7_kek_key *kk;
	/*
	 * This spinlock should not be necessary here because all keycache updates
	 * happen from a single thread, and that same thread is the caller of this function.
	 * But for safety/future-proofing, the spinlock is still used here.
	 */
	SPIN_LOCK(&dev->keycache_lock);
	kk = k7_kk_null_if_empty(slot->kk);
	if (kk) {
		new_kk->valid_mechs   = kk->valid_mechs;
		new_kk->invalid_mechs = kk->invalid_mechs;
	}
	SPIN_UNLOCK(&dev->keycache_lock);
}

static int k7_update_kk_mechlists (struct k7_dev *dev, struct k7_kek_key *kk, int good_mech, int bad_mech)
{
	if (bad_mech) {
		int ret = k7_del_from_mechlist(dev, kk->valid_mechs, (u8)bad_mech, dev->valid_mechlists);
		if (ret < 0)
			return ret;
		kk->valid_mechs = (u16)ret;
		ret = k7_add_to_mechlist(dev, kk->invalid_mechs, (u8)bad_mech, dev->invalid_mechlists);
		if (ret < 0)
			return ret;
		kk->invalid_mechs = (u16)ret;
	}
	if (good_mech) {
		int ret = k7_add_to_mechlist(dev, kk->valid_mechs, (u8)good_mech, dev->valid_mechlists);
		if (ret < 0)
			return ret;
		kk->valid_mechs = (u16)ret;
		ret = k7_del_from_mechlist(dev, kk->invalid_mechs, (u8)good_mech, dev->invalid_mechlists);
		if (ret < 0)
			return ret;
		kk->invalid_mechs = (u16)ret;
	}
	return 0;
}

static void k7_keycache_replace_kek_key (struct k7_dev *dev, struct k7_key_slot *slot,
					struct k7_kek_key *new, int good_mech, int bad_mech)
{
	struct k7_kek_key *old;

	SPIN_LOCK(&dev->keycache_lock);
	old = slot->kk;
	if (k7_kk_null_if_empty(old) == NULL) {
		new->generation = k7_slot_generation(old) + 1;
		old = NULL;
	} else if (old->kek_id != new->kek_id || old->group_id != new->group_id) {
		new->generation = old->generation + 1;
	} else {
		new->generation = old->generation;
		if (old->has_been_keked && !new->cannot_be_keked) {
			new->valid_ops |= old->valid_ops;
			if (!new->has_been_keked) {
				new->has_been_keked = 1;
				new->key_words      = old->key_words;
				new->raw_key_words  = old->raw_key_words;
				new->kek_algorithm  = old->kek_algorithm;
				memcpy(new->key_data, old->key_data, old->key_words * sizeof(u64));
			}
		}
	}
	kref_get(&new->kref);  /* get keycache's reference; the initial ref gets eaten later by k7_free_req() */
	slot->kk = new;  /* update the keycache */
	SPIN_UNLOCK(&dev->keycache_lock);
	if (old)
		kref_put(&old->kref, k7_kk_free);  /* keycache's reference */
}

static void k7_send_fp_transactions_complete (struct k7_dev *dev, u32 group_id, u32 kek_id)
{
	u32 *inbuf;
	const int inbuf_size  = (K7_ICD_PARAMS_OFFSET_WORDS + 2) * sizeof(u32);
	const int outbuf_size = 256;
	unsigned int dma_flags = K7_DMA_FLAG_MRB1;

	inbuf = kzalloc(inbuf_size, GFP_KERNEL);
	if (!inbuf) {
		kerr(dev->name, "kzalloc(%u) failed", K7_ICD_PARAMS_OFFSET_WORDS + 2);
		return;
	}
	inbuf[ 0] = cpu_to_le32(LUNA_FAST_PATH_TRANSACTIONS_COMPLETE_ICD);
	inbuf[K7_ICD_PARAMS_OFFSET_WORDS + 0] = cpu_to_le32(group_id);
	inbuf[K7_ICD_PARAMS_OFFSET_WORDS + 1] = cpu_to_le32(kek_id);
	(void)k7_send_to_mcpu(dev, inbuf, inbuf_size, NULL, outbuf_size, dma_flags, K7_HRB_TYPE_ICD_CMD);
	kfree(inbuf);
}

struct k7_notify_hsm_work {
	struct work_struct	work;
	struct k7_dev		*dev;
	u32			group_id;
	u32			kek_id;
};

static void k7_fp_transactions_complete_worker (struct work_struct *work)
{
	struct k7_notify_hsm_work *notify = container_of(work, struct k7_notify_hsm_work, work);
	kdebug(notify->dev->name, "Handling %p, send_to_mcpu: group_id=%u kek_id=%08x", notify, notify->group_id, notify->kek_id);
	k7_send_fp_transactions_complete(notify->dev, notify->group_id, notify->kek_id);
	memset(notify, 0, sizeof(*notify));
	kfree(notify);
}

static void k7_enqueue_fp_transactions_complete (struct k7_dev *dev, u32 group_id, u32 kek_id)
{
	struct k7_notify_hsm_work *notify;
	/*
	 * Pass it off to a workqueue, to avoid holding up further HTB processing.
	 */
	notify = kzalloc(sizeof(*notify), GFP_KERNEL);
	if (!notify) {
		kerr(dev->name, "kzalloc(%u, GFP_KERNEL) failed", sizeof(*notify));
		return;
	}
	INIT_WORK(&notify->work, k7_fp_transactions_complete_worker);
	notify->dev      = dev;
	notify->group_id = group_id;
	notify->kek_id   = kek_id;
	kdebug(dev->name, "Sending %p to notify worker, group_id=%u kek_id=%08x", notify, group_id, kek_id);
	schedule_work(&notify->work);
}

void k7_put_key (struct k7_dev *dev, struct k7_kek_key *kk)
{
	struct k7_kek_group  *kg = &dev->kek_group[kk->group_id];
	u32 kek_id;
	int notify_hsm = 0;

	kek_id = kk->kek_id;
	kref_put(&kk->kref, k7_kk_free);  /* caller's reference */
	SPIN_LOCK(&kg->lock);
	if (kek_id == kg->active_kek_id) {
		if (!kg->active_count) {
			kerr(dev->name, "BUG: active_count was already zero");
		} else {
			kg->active_count--;
			if (kg->active_count == 0 && kg->notify_hsm_when_zero) {
				kg->notify_hsm_when_zero = 0;
				notify_hsm = 1;
			}
		}
	}
	SPIN_UNLOCK(&kg->lock);
	if (notify_hsm)
		k7_enqueue_fp_transactions_complete(dev, kg->group_id, kek_id);
}

static int k7_check_key_against_request (struct k7_dev *dev, struct k7_dma_fastpath *ioc, u32 key_handle, struct k7_kek_key *kk)
{
	int mech;
	unsigned int this_op;

	this_op = ioc->operation;
	if (this_op >= ((sizeof(u16) * 8)))
		return -EINVAL;  /* operation must be in range 0..15 */
	this_op = 1 << this_op;
	if (!(kk->valid_ops & this_op))
		return -EKEYEXPIRED;  /* operation not (yet) valid for this key */
	mech = k7_mechanism_to_mech(dev, ioc->mechanism);
	if (mech < 0)
		return mech;
	if (!(dev->mech_ops[mech] & this_op))
		return  -EKEYEXPIRED;  /* operation not (yet) valid for this mechanism */
	if (!k7_match_mechlist(dev, dev->valid_mechlists[kk->valid_mechs].mechs, (u8)mech)) {
		if (k7_match_mechlist(dev, dev->invalid_mechlists[kk->invalid_mechs].mechs, (u8)mech))
			return -EINVAL;  /* Mech was found on the "invalid" list */
		return -EKEYEXPIRED;  /* Mech not found on either valid or invalid lists */
	}
	return 0;
}

static int k7_get_key (struct k7_dev *dev, u32 key_handle, u32 session_id,
			struct k7_kek_key **kk_r, struct k7_kek_group **kg_r)
{
	struct k7_kek_key *kk;
	int err;

	kk = k7_keycache_lookup(dev, key_handle);
	if (!kk) {
		KEKDEBUG(dev->name, "not found: LUNA_RET_KEY_NOT_KEKED");
		err = -EKEYEXPIRED;	/* LUNA_RET_KEY_NOT_KEKED */
	} else {
		if (kk->cannot_be_keked) {
			struct k7_kek_group *kg = &dev->kek_group[kk->group_id];
			if (kk->kek_id < kg->minimum_kek_id) {
				k7_keycache_delete_key(dev, key_handle, kk); /* expired kek_id: nuke it */
				KEKDEBUG(dev->name, "cannot_be_keked has expired: LUNA_RET_KEY_NOT_KEKED");
				err = -EKEYEXPIRED;	/* LUNA_RET_KEY_NOT_KEKED */
			} else {
				KEKDEBUG(dev->name, "cannot_be_keked: LUNA_RET_KEY_CANNOT_BE_KEKED");
				err = -EKEYREJECTED;	/* LUNA_RET_KEY_CANNOT_BE_KEKED */
			}
		} else if (!kk->has_been_keked) {
			KEKDEBUG(dev->name, "not has_been_keked: LUNA_RET_KEY_NOT_KEKED");
			err = -EKEYEXPIRED;	/* LUNA_RET_KEY_NOT_KEKED */
		} else if (!(err = k7_validate_key_for_session(dev, session_id, key_handle, kk->generation))) {
			struct k7_kek_group *kg = &dev->kek_group[kk->group_id];
			SPIN_LOCK(&kg->lock);
			if (kg->status == active && kk->kek_id == kg->active_kek_id) {
				kg->active_count++;
				*kk_r = kk;
				err = 0;
			} else if (kg->status == in_replacement && kk->kek_id == kg->pending_kek_id) {
				*kg_r = kg;	/* Return kek_group to caller so they can wait on it */
				err = -EAGAIN;	/* Wait for kek replacement to complete */
			} else {
				KEKDEBUG(dev->name, "status=%u kek_id=%08x active=%08x pending=%08x, LUNA_RET_KEY_NOT_KEKED",
					kg->status, kk->kek_id, kg->active_kek_id, kg->pending_kek_id);
				err = -EKEYEXPIRED;	/* LUNA_RET_KEY_NOT_KEKED */
			}
			SPIN_UNLOCK(&kg->lock);
		}
		if (err)
			kref_put(&kk->kref, k7_kk_free);
	}
	return err;
}

static int k7_check_kek_id (struct k7_dev *dev, struct k7_kek_key *kk, u32 lkrc)
{
	u32 kek_id, group_id = kk->group_id;
	struct k7_kek_group *kg = &dev->kek_group[group_id];
	int err = 0;

	SPIN_LOCK(&kg->lock);
	kek_id = kk->kek_id;
	switch (kg->status) {
	case idle:
	case stopped:
	default:
		if (lkrc == LUNA_RET_OK && kek_id != kg->active_kek_id) {
			kwarn(dev->name, "group_id=%08x kek_id=%08x active_kek_id=%08x status=%u",
				group_id, kek_id, kg->active_kek_id,kg->status);
			err = -EINVAL;
		}
		break;
	case active:
		if (kek_id != kg->active_kek_id) {
			kwarn(dev->name, "group_id=%08x kek_id=%08x active_kek_id=%08x",
				group_id, kek_id, kg->active_kek_id);
			err = -EINVAL;
		}
		break;
	case in_replacement:
		if (kek_id != kg->active_kek_id && kek_id != kg->pending_kek_id) {
			kwarn(dev->name, "group_id=%08x kek_id=%08x active_kek_id=%08x pending_kek_id=%08x",
				group_id, kek_id, kg->active_kek_id, kg->pending_kek_id);
			err = -EINVAL;
		}
		break;
	}
	SPIN_UNLOCK(&kg->lock);
	return err;
}

static int k7_update_keycache (struct k7_dev *dev, u32 key_handle, struct k7_kek_key *kk, int good_mech, int bad_mech)
{
	struct k7_key_slot *slot;
	int err;
	/*
	 * One might expect these steps to all be done together under
	 * overall spinlock protection.  But that is not necessary here,
	 * because only HTB-IRQ thread ever runs this code,
	 * and nothing else can modify kk values.
	 */
	slot = k7_keycache_get_slot(dev, key_handle);
	if (!slot)
		return -ENOMEM;
	k7_copy_old_mechlists(dev, slot, kk);
	err = k7_update_kk_mechlists(dev, kk, good_mech, bad_mech);
	if (err)
		return err;
	k7_keycache_replace_kek_key(dev, slot, kk, good_mech, bad_mech);
	return 0;
}

static int k7_save_kek_key (struct k7_dev *dev, struct k7_req *req, u32 *data, unsigned int data_len, u32 *raw_key_bytes_r)
{
	struct k7_kek_key	*kk = req->kk;
	u32			lkrc, valid_ops, this_op;
	unsigned int		min_bytes, good_mech = 0, bad_mech = 0, key_bytes = 0;

	/* get/validate the group_id */
	kk->group_id = le32_to_cpu(data[0]);
	if (kk->group_id >= K7_KEYCACHE_GROUPS) {
		kerr(dev->name, "bad kek group_id=%08x", kk->group_id);
		return LUNA_RET_GENERAL_ERROR;
	}

	/* get kek_id/lkrc and validate against current KEK Group settings */
	kk->kek_id = le32_to_cpu(data[1]);
	lkrc       = le32_to_cpu(data[2]);
	if (k7_check_kek_id(dev, kk, lkrc))
		return LUNA_RET_GENERAL_ERROR;

	/* validate secondary lkrc, and data_len for LUNA_RET_OK case */
	switch (lkrc) {
	case LUNA_RET_OK:
		min_bytes = 6 * sizeof(u32);
		if (data_len < min_bytes) {
			kerr(dev->name, "not enough data(%u) for full response", data_len);
			return LUNA_RET_GENERAL_ERROR;
		}
		key_bytes = le32_to_cpu(data[4]);
		if (key_bytes & (sizeof(u64) - 1)) {
			kerr(dev->name, "raw_key_bytes not multiple of u64: %u", key_bytes);
			return LUNA_RET_GENERAL_ERROR;
		}
		*raw_key_bytes_r  = key_bytes;
		kk->raw_key_words = key_bytes / sizeof(u64);
		key_bytes = le32_to_cpu(data[5]);
		if (!key_bytes || key_bytes & (sizeof(u64) - 1) || key_bytes > sizeof(kk->key_data)) {
			kerr(dev->name, "invalid key_bytes: %u", key_bytes);
			return LUNA_RET_GENERAL_ERROR;
		}
		kk->key_words = key_bytes / sizeof(u64);
		min_bytes += key_bytes;
		if (min_bytes > data_len) {
			kerr(dev->name, "not enough data(%u) for key_data(%u)", data_len, key_bytes);
			return LUNA_RET_GENERAL_ERROR;
		}
		memcpy(kk->key_data, &data[6], key_bytes);
		kk->kek_algorithm         = req->kek_algorithm;
		this_op                   = 1 << req->key_op;
		valid_ops                 = le32_to_cpu(data[3]);
		kk->valid_ops            |= (valid_ops & 0x0000ffff) | this_op;
		good_mech                 = req->key_mech;
		/* No locking required for next line, as here (IRQ) is the only place it is updated from */
		dev->mech_ops[good_mech] |= (valid_ops >> 16) | this_op;
		kk->has_been_keked        = 1;
		break;
	case LUNA_RET_KEY_CANNOT_BE_KEKED:
		kk->cannot_be_keked = 1;
		break;
	case LUNA_RET_MECHANISM_INVALID_FOR_FP:
		bad_mech = req->key_mech;
		break;
	default:
		kwarn(dev->name, "lkrc=%08x", lkrc);
		return lkrc;
	}
	if (k7_update_keycache(dev, req->key_handle, kk, good_mech, bad_mech)) {
		kwarn(dev->name, "k7_update_keycache() failed");
		lkrc = LUNA_RET_GENERAL_ERROR;
	}
	return lkrc;
}

int k7_fp_return_lkrc (struct k7_dev *dev, struct k7_req *req, u32 lkrc, u32 raw_key_bytes, u32 kek_id)
{
	unsigned int rsize;
	struct {
		struct k7_icd_response_hdr	hdr;
		u32				data[2];
	} response;

	req->status = K7_REQ_COMPLETED;
	if (lkrc == LUNA_RET_OK && raw_key_bytes) {
		response.data[0] = cpu_to_le32(raw_key_bytes);
		response.data[1] = cpu_to_le32(kek_id);
		rsize = sizeof(response);
	} else {
		if (lkrc == LUNA_RET_OK)
			lkrc = LUNA_RET_GENERAL_ERROR;
		rsize = sizeof(response.hdr);
	}
	response.hdr.response_code = cpu_to_le32(lkrc);
	response.hdr.flags         = 0;
	response.hdr.total_size    = cpu_to_le32(rsize);
	response.hdr.data_size     = cpu_to_le32(rsize - sizeof(response.hdr));
	if (copy_to_user((void *)(long)(req->ioc->outbuf), &response, rsize)) {
		kerr(dev->name, "copy_to_user(outbuf=0x%llx:%u, 0x%x, %u) failed", req->ioc->outbuf, &response, rsize);
		return -EFAULT;
	}
	return rsize;
}

static int k7_copyin_kek_key_params (struct k7_dev *dev, struct k7_req *req)
{
	struct k7_dma_ioctl *ioc = req->ioc;
	u32 params[5];
	enum {sessionx, mechanismx, keyhandlex, operationx, algorithmx};  /* params[] indicies */
	int mech, params_offset = (K7_ICD_LIBRARY_PREFIX_WORDS + K7_ICD_PARAMS_OFFSET_WORDS) * sizeof(u32);

	/* outbuf must be at least large enough for a response header, plus (u32)raw_key_bytes, plus (u32)kek_id */
	if (ioc->outbuf_size < (sizeof(struct k7_icd_response_hdr) + (2 * sizeof(u32)))) {
		kwarn(dev->name, "outbuf_size=%u too small", ioc->outbuf_size);
		return -EINVAL;
	}
	if (ioc->inbuf_size < (params_offset + sizeof(params))) {
		kwarn(dev->name, "inbuf_size=%u too small", ioc->inbuf_size);
		return -EINVAL;
	}
	if (copy_from_user(params, (void *)(long)(ioc->inbuf + params_offset), sizeof(params))) {
		kwarn(dev->name, "copy_from_user(inbuf) failed");
		return -EFAULT;
	}
	req->session_id = le32_to_cpu(params[sessionx]);
	if (!k7_session_id_okay(req->session_id)) {
		kwarn(dev->name, "bad session_id: 0x%08x", req->session_id);
		return k7_fp_return_lkrc(dev, req, LUNA_RET_DATA_INVALID, 0, 0);
	}
	mech = k7_mechanism_to_mech(dev, le32_to_cpu(params[mechanismx]));
	if (mech < 0)
		return k7_fp_return_lkrc(dev, req, LUNA_RET_GENERAL_ERROR, 0, 0);
	req->key_mech   = (u8)mech;
	req->key_handle = le32_to_cpu(params[keyhandlex]);
	req->key_op     = (u16)le32_to_cpu(params[operationx]);
	if (req->key_op >= (sizeof(u16) * 8)) {
		kwarn(dev->name, "invalid key_op: %08x", req->key_op);
		return k7_fp_return_lkrc(dev, req, LUNA_RET_DATA_INVALID, 0, 0);
	}
	req->kek_algorithm = (u16)le32_to_cpu(params[algorithmx]);
	if (req->kek_algorithm & ~0x00000003) {
		kwarn(dev->name, "invalid kek_algorithm: %08x", req->kek_algorithm);
		return k7_fp_return_lkrc(dev, req, LUNA_RET_DATA_INVALID, 0, 0);
	}
	return 0;
}

static u64 k7_fp_build_hsmb (struct k7_dma_fastpath *ioc, struct k7_kek_key *kk, struct k7_kek_key *xk)
{
	u64 hsmb;
	unsigned int tmp;

	hsmb  = BE64VAL( 0, 7,0x28);			/* signature */
	tmp   = (u16)(ioc->session_id - 1);
	hsmb |= BE64VAL( 8,23,tmp);			/* session ID */
	hsmb |= BE64VAL(24,27,kk->group_id);		/* SLOT ID */
	hsmb |= BE64VAL(28,29,kk->kek_algorithm);	/* Type */
	if (xk) {
		tmp   = xk->key_words;
		hsmb |= BE64VAL(32,39,tmp);		/* Primary key size */
		tmp  += 1 + (sizeof(ioc->xts_tweak_vector) / sizeof(u64));
		hsmb |= BE64VAL(48,55,tmp);		/* Secondary key offset */
		hsmb |= BE64VAL(40,47,kk->key_words);	/* Secondary key size */
		if(xk->raw_key_words & 1) {
			hsmb |= BE64BIT(56);		/* PDT=1 for non-exact multiples */
			hsmb |= BE64BIT(57);		/* SDT=1 for non-exact multiples */
		}
	} else {
		if (kk->raw_key_words & 1)		/* PDT=0 for exact multiples of 128 bits */
			hsmb |= BE64BIT(56);		/* PDT=1 for non-exact multiples */
		hsmb |= BE64VAL(32,39,kk->key_words);	/* Primary key size */
	}
	return cpu_to_be64(hsmb);
}

static int k7_fp_build_sku_hdr (struct k7_dev *dev, struct k7_req *req, struct k7_dma_fastpath *ioc,
					struct k7_kek_key *kk, struct k7_kek_key *xk, unsigned int data_offset)
{
	struct k7_dt *first_dt = list_first_entry(&req->hrb_dtc, struct k7_dt, list);
	u8 *key_len, *vaddr = (u8 *)first_dt->data.vaddr, *out = vaddr + data_offset;
	u64 hsmb = k7_fp_build_hsmb(ioc, kk, xk);
	unsigned int key_bytes;

	/* copy SKU request header */
	if (copy_from_user(out, (void __user *)(unsigned long)ioc->d.inbuf, sizeof(u64)))
		return -EFAULT;
	key_len = out;
	switch(kk->raw_key_words)
	{
	case 1:
	case 2:
		*key_len |= 0x1;
		break;
	case 3:
		*key_len |= 0x2;
		break;
	case 4:
		*key_len |= 0x4;
		break;
	}
	out += sizeof(u64);
	memcpy(out, &hsmb, sizeof(hsmb));
	out += sizeof(u64);
	if (xk) {
		key_bytes = xk->key_words * sizeof(u64);
		memcpy(out, xk->key_data, key_bytes);
		out += key_bytes;
		memcpy(out, ioc->xts_tweak_vector, sizeof(ioc->xts_tweak_vector));
		out += sizeof(ioc->xts_tweak_vector);
	}
	key_bytes = kk->key_words * sizeof(u64);
	memcpy(out, kk->key_data, key_bytes);
	out += key_bytes;
	return (int)(out - vaddr);
}

static int k7_wait_for_kek_replacement (struct k7_dev *dev, struct k7_kek_group *kg)
{
	int ret = -EAGAIN;

	if (wait_event_interruptible(kg->wq, (kg->status != in_replacement) || dev->failed))
		ret = -EINTR;
	return dev->failed ? -ECONNREFUSED : ret;
}

static int k7_fp_build_req (struct k7_dev *dev, struct k7_dma_fastpath *ioc,
				unsigned int request_size, struct k7_req **req_r)
{
	/* Validate keys and calculate total request size */
	struct k7_kek_key *kk, *xk = NULL;
	struct k7_kek_group *kg = NULL;
	int err;

	err = k7_get_key(dev, ioc->key_handle, ioc->session_id, &kk, &kg);
	if (err)
		goto err_exit;
	request_size += sizeof(u64) + (kk->key_words * sizeof(u64));  /* hsmb_word + key_bytes */
	if (ioc->xts_tweak_handle) {
		err = k7_get_key(dev, ioc->xts_tweak_handle, ioc->session_id, &xk, &kg);
		if (!err) {
			if (xk->kek_id != kk->kek_id) {
				kwarn(dev->name, "mismatched kek_id: %08x vs %08x, LUNA_RET_KEY_NOT_KEKED", xk->kek_id, kk->kek_id);
				err = -EKEYEXPIRED;	/* LUNA_RET_KEY_NOT_KEKED */
			} else {
				request_size += (xk->key_words * sizeof(u64)) + sizeof(ioc->xts_tweak_vector);
				/* The two keys are not permitted to be identical */
				if (kk->key_words != xk->key_words) {
					err = -EINVAL;
				} else if (0 == memcmp(kk->key_data, xk->key_data, kk->key_words * sizeof(u64))) {
					err = -EINVAL;
				}
			}
		}
	}
	if (!err)
		err = k7_check_key_against_request(dev, ioc, ioc->key_handle, kk);
	if (!err && xk)
		err = k7_check_key_against_request(dev, ioc, ioc->xts_tweak_handle, xk);
	if (!err) {
		struct k7_channel *channel = &dev->channels[K7_DMA_TARGET_SKU];
		struct k7_req *req;
		int data_offset = k7_prepare_req(channel, request_size, &ioc->d, K7_HRB_TYPE_DEFAULT, &req);
		if (data_offset >= 0) {
			data_offset = k7_fp_build_sku_hdr(dev, req, ioc, kk, xk, data_offset);
			if (data_offset >= 0) {
				/* Save keys in req, so we can do k7_put_key() on them after req is completed */
				req->kk = kk;
				req->xk = xk;
				*req_r  = req;
				return data_offset;  /* Success */
			}
			k7_free_req(channel, req, 0);
		}
		*req_r = NULL;
		err = data_offset;
	}
	k7_put_key(dev, kk);
	if (xk)
		k7_put_key(dev, xk);
err_exit:
	if (err == -EAGAIN && kg)
		err = k7_wait_for_kek_replacement(dev, kg);
	return err;
}

void k7_fp_put_req_keys (struct k7_dev *dev, struct k7_req *req)
{
	if (req->have_mutex) {
		req->have_mutex = 0;
		k7_rekek_unlock(dev, req->key_handle);
	}
	if (req->kk) {
		if (req->ioc->flags & K7_DMA_FLAG_KEK_KEY) {
			kref_put(&req->kk->kref, k7_kk_free);
		} else {
			k7_put_key(dev, req->kk);
			if (req->xk)
				k7_put_key(dev, req->xk);
		}
	}
}

static int k7_fp_prepare (struct k7_dev *dev, struct k7_dma_fastpath *ioc, unsigned int request_size, struct k7_req **req_r)
{
	struct k7_req *req = NULL;
	struct k7_data_segment *seg;
	unsigned int inbuf_size = ioc->d.inbuf_size;
	int err, data_offset;

	/* Ensure the SKU request header is entirely within the first inbuf */
	if (inbuf_size < sizeof(u64)) {
		kerr(dev->name, "inbuf_size(%u) < %u", inbuf_size, (int)sizeof(u64));
		return -EINVAL;
	}

	if (ioc->session_id >= K7_MAX_SESSIONS) {
		kerr(dev->name, "bad session_id: 0x%08x", ioc->session_id);
		return -EINVAL;
	}

	data_offset = k7_fp_build_req(dev, ioc, request_size, &req);
	if (data_offset < 0)
		return data_offset;

	/* If inbuf also contained payload data, now is the time to append it */
	inbuf_size -= sizeof(u64);
	if (inbuf_size) {
		err = k7_copy_udata(dev, ioc->d.flags, &req->hrb_dtc, K7_COPYIN,
			(void __user *)(unsigned long)(ioc->d.inbuf + sizeof(u64)),
			inbuf_size, data_offset);
		if (err)
			goto err_free_req;
		data_offset += inbuf_size;
	}

	/* Append any remaining payload data to the request */
	for (seg = ioc->payload; seg->buf != 0; ++seg) {
		err = k7_copy_udata(dev, ioc->d.flags, &req->hrb_dtc, K7_COPYIN,
			(void __user *)(unsigned long)(seg->buf),
			seg->bytecount, data_offset);
		if (err)
			goto err_free_req;
		data_offset += seg->bytecount;
	}
	if (dev->clog.enabled) {
		struct k7_channel *channel = &dev->channels[K7_DMA_TARGET_SKU];
		k7_clog_dump_dtc(channel, "HRB", &req->hrb_dtc, -1);
	}
	*req_r = req;
	return 0;
err_free_req:
	k7_free_req(&dev->channels[K7_DMA_TARGET_SKU], req, 0);
	return err;
}

static int k7_do_kek_fastpath (struct k7_dev *dev, struct k7_dma_fastpath *ioc, unsigned int request_size)
{
	unsigned long failsafe = jiffies + (HZ * K7_FP_TIMEOUT_SECS);
	unsigned int retry_delay_msecs = 1;
	int err;

	while (1) {
		struct k7_req *req = NULL;
		err = k7_fp_prepare(dev, ioc, request_size, &req);
		if (err == -EAGAIN)
			continue;  /* kek replacement completed, try again */
		if (err == 0)
			err = k7_dma_submit_and_wait(dev, req, &ioc->d);  /* Frees req */
		if (err != -ENOMEM)
			return err;
		if (signal_pending(current))
			return -EINTR;
		if (time_after(jiffies, failsafe)) {
			kwarn(dev->name, "timed-out");
			return -ETIMEDOUT;
		}
		/* Give time for resources to become available */
		if (retry_delay_msecs == 1)
			kdebug(dev->name, "temporarily out of resources, retrying");
		msleep(retry_delay_msecs);
		retry_delay_msecs = (k7_get_random_byte() % 64) + 25;  /* k7_get_random_int() may return zero */
	}
}

static int k7_fp_get_bytecount (struct k7_data_segment segments[], int compat)
{
	unsigned int i, bytecount = 0;

	for (i = 0; i < K7_FP_MAX_SEGMENTS; ++i) {
		struct k7_data_segment *seg = &segments[i];
#ifdef CONFIG_COMPAT
		if (compat)
			seg->buf = (unsigned long)compat_ptr(seg->buf);
#endif
		if (!seg->buf)
			break;
		bytecount += seg->bytecount;
	}
	return bytecount;
}

static int k7_do_dma_fastpath (struct k7_dev *dev, struct k7_dma_fastpath *ioc, int compat)
{
	unsigned int request_size;
	int err;
#ifdef CONFIG_COMPAT
	if (compat) {
		ioc->d.inbuf  = (unsigned long)compat_ptr(ioc->d.inbuf);
		ioc->d.outbuf = (unsigned long)compat_ptr(ioc->d.outbuf);
	}
#endif
	ioc->d.target = K7_DMA_TARGET_SKU;
	if (!ioc->d.inbuf || !ioc->d.inbuf_size || !ioc->d.outbuf || !ioc->d.outbuf_size) {
		kerr(dev->name, "inbuf=%p:%u outbuf=%p:%u",
			(void *)(long)ioc->d.inbuf, ioc->d.inbuf_size, (void *)(long)ioc->d.outbuf, ioc->d.outbuf_size);
		err = -EINVAL;
	} else {
		if (!ioc->key_handle || ioc->key_handle >= K7_KEYCACHE_MAX_HANDLES) {
			kwarn(dev->name, "bad key_handle: 0x%08x", ioc->key_handle);
			return -EINVAL;;
		}
		if (ioc->xts_tweak_handle >= K7_KEYCACHE_MAX_HANDLES) {
			kwarn(dev->name, "bad xts_tweak_handle: 0x%08x", ioc->xts_tweak_handle);
			return -EINVAL;;
		}
		request_size  = k7_fp_get_bytecount(ioc->payload, compat)  + ioc->d.inbuf_size;
		if (!request_size) {
			kerr(dev->name, "request_size=%u", request_size);
			err = -EINVAL;
		} else {
			err = k7_do_kek_fastpath(dev, ioc, request_size);
		}
	}
	return err;
}

int k7_ioctl_dma_fastpath (struct k7_dev *dev, void __user *uargp, int compat)
{
	struct k7_dma_fastpath *ioc;
	int err;

	ioc = kmalloc(sizeof(*ioc), GFP_KERNEL);
	if (!ioc) {
		err = -ENOMEM;
	} else {
		if (copy_from_user(ioc, uargp, sizeof(*ioc))) {
			err = -EFAULT;
		} else {
			ioc->d.flags = K7_DMA_FLAG_KEK_FASTPATH;
			err = k7_do_dma_fastpath(dev, ioc, compat);
		}
		kfree(ioc);
	}
	return err;
}

/*
 * Look up key in local cache and validate usage scenario.
 * Returns +bytecount to tell caller to short-circuit ICD command and immediately return response.
 * Returns 0 to continue with ICD command to MCPU;
 * Anything else is an internal failure of some sort.
 */
int k7_intercept_kek_key_cmd (struct k7_dev *dev, struct k7_req *req)
{
	struct k7_dma_ioctl *ioc = req->ioc;
	struct k7_kek_key   *kk;
	struct k7_kek_group *kg;
	u32 lkrc, kek_id = 0, raw_key_bytes = 0;
	int err;
	u16 this_op;
	u8 mech;

	err = k7_copyin_kek_key_params(dev, req);
	if (err)
		return err;
	req->have_mutex = 0;
	if (k7_rekek_lock(dev, req->key_handle))
		return -ENOMEM;
	req->have_mutex = 1;
	kk = k7_keycache_lookup(dev, req->key_handle);
	if (!kk)
		goto forward_to_mcpu;
	kg = &dev->kek_group[kk->group_id];
	kek_id = kk->kek_id;
	if (kk->cannot_be_keked) {
		if (kek_id < kg->minimum_kek_id) {
			k7_keycache_delete_key(dev, req->key_handle, kk); /* expired kek_id: nuke it */
			goto forward_to_mcpu;
		}
		kdebug(dev->name, "key_handle=%08x cannot be keked", req->key_handle);
		lkrc = LUNA_RET_KEY_CANNOT_BE_KEKED;
		goto return_lkrc;
	}
	err = k7_validate_key_for_session(dev, req->session_id, req->key_handle, kk->generation);
	if (err) {
		if (err == -EPERM)
			goto forward_to_mcpu;
		lkrc = LUNA_RET_GENERAL_ERROR;
		goto return_lkrc;
	}
	mech = req->key_mech;
	if (!k7_match_mechlist(dev, dev->valid_mechlists[kk->valid_mechs].mechs, mech)) {
		if (!k7_match_mechlist(dev, dev->invalid_mechlists[kk->invalid_mechs].mechs, mech))
			goto forward_to_mcpu;
		kwarn(dev->name, "mechanism=%08x: invalid_for_fp", dev->mechanisms[mech]);
		lkrc = LUNA_RET_MECHANISM_INVALID_FOR_FP;
		goto return_lkrc;
	}
	this_op = 1 << req->key_op;
	if (!(dev->mech_ops[mech] & this_op)) {
		kwarn(dev->name, "invalid operation (%08x) for mech %08x", req->key_op, dev->mechanisms[mech]);
		lkrc = LUNA_RET_OPERATION_INVALID_FOR_FP;
		goto return_lkrc;
	}
	if (!kk->has_been_keked)
		goto forward_to_mcpu;
	if (kk->kek_algorithm != req->kek_algorithm) {
		kwarn(dev->name, "kek_algorithm mismatch %u:%u", kk->kek_algorithm, req->kek_algorithm);
		lkrc = LUNA_RET_DATA_INVALID;
		goto return_lkrc;
	}
	if (!(kk->valid_ops & this_op)) {
		kwarn(dev->name, "invalid operation (0x%08x) for key", req->key_op);
		lkrc = LUNA_RET_KEY_TYPE_INCONSISTENT;
		goto return_lkrc;
	}
	/*
	 * spinlocks not required here, because:
	 * 1) We don't modify *kk when updating keycache, instead we replace the entire entry with a new kk.
	 * 2) We can race against KEK replacement, but that will just result in the
	 *    subsequent fastpath operations being told to re-kek the key at time of use.
	 */
	if (kek_id != kg->active_kek_id && kek_id != kg->pending_kek_id) {
		k7_keycache_delete_key(dev, req->key_handle, kk); /* unrecognized kek_id: nuke it */
	} else {
		switch (kg->status) {
		case active:
			if (kek_id == kg->active_kek_id) {
				raw_key_bytes = kk->raw_key_words * sizeof(u64);
				lkrc = LUNA_RET_OK;
				goto return_lkrc;
			}
			k7_keycache_delete_key(dev, req->key_handle, kk); /* unrecognized kek_id: nuke it */
			break;
		case in_replacement:
			if (kek_id == kg->pending_kek_id) {
				raw_key_bytes = kk->raw_key_words * sizeof(u64);
				lkrc = LUNA_RET_OK;
				goto return_lkrc;
			}
			k7_keycache_delete_key(dev, req->key_handle, kk); /* unrecognized kek_id: nuke it */
			KEKDEBUG(dev->name, "in_repl: forward to MCPU");
			break;
		case idle:
		case stopped:
		default:
			kerr(dev->name, "kek_id=%08x/%08x/%08x kek_group=%08x status=%u",
				kek_id, kg->active_kek_id, kg->pending_kek_id, kg->group_id, kg->status);
			break;
		}
	}
forward_to_mcpu:
	ioc->flags |= K7_DMA_FLAG_KEK_KEY | K7_DMA_FLAG_MRB1;
	kdebug(dev->name, "forwarding to mcpu");
	if (kk)
		kref_put(&kk->kref, k7_kk_free);  /* undo kref_get() from k7_keycache_lookup() */
	/* Pre-allocate a kek_key struct for use by the IRQ handler for MCPU reply */
	kk = k7_kk_zalloc();
	if (kk) {
		req->kk = kk;
		atomic_inc(&dev->rekek_count);
		return 0;  /* forward this icd command to mcpu, and intercept response afterward */
	}
	kerr(dev->name, "kzalloc(kk) failed");
	lkrc = LUNA_RET_GENERAL_ERROR;
return_lkrc:
	if (req->have_mutex) {
		req->have_mutex = 0;
		k7_rekek_unlock(dev, req->key_handle);
	}
	if (kk)
		kref_put(&kk->kref, k7_kk_free);  /* undo kref_get() from k7_keycache_lookup() */
	if (lkrc == LUNA_RET_OK && !dev->icd_enabled)
		return -ECONNREFUSED;  /* Don't return cached key if MCPU itself wouldn't accept KEK_KEY command */
	return k7_fp_return_lkrc(dev, req, lkrc, raw_key_bytes, kek_id);
}

void k7_handle_kek_key_reply (struct k7_dev *dev, struct k7_req *req, void *data,
				unsigned int response_len, int truncated)
{
	u32 lkrc;

	kdebug(dev->name, "");
	if (truncated || response_len < sizeof(struct k7_icd_response_hdr)) {
		kwarn(dev->name, "response_len=%u too small", response_len);
		lkrc = LUNA_RET_BUFFER_TOO_SMALL;
	} else {
		struct k7_icd_response_hdr *hdr = data;
		lkrc = le32_to_cpu(hdr->response_code);
		if (lkrc != LUNA_RET_OK) {
			KEKDEBUG(dev->name, "failed, lkrc=%08x", lkrc);
		} else if (response_len < (sizeof(struct k7_icd_response_hdr) + (3 * sizeof(u32)))) {
			kwarn(dev->name, "response_len=%u too small", response_len);
			lkrc = LUNA_RET_BUFFER_TOO_SMALL;
		} else {
			unsigned int data_len = response_len - sizeof(struct k7_icd_response_hdr);
			data += sizeof(struct k7_icd_response_hdr);
			lkrc = k7_save_kek_key(dev, req, data, data_len, &req->raw_key_bytes);
			if (lkrc == LUNA_RET_OK) {
				if (k7_add_key_to_session(dev, req->session_id, req->key_handle, req->kk->generation))
					lkrc = LUNA_RET_GENERAL_ERROR;
			}
		}
	}
	req->lkrc = lkrc;
}

static void k7_keycache_free_keys (struct k7_dev *dev, int free_level2)
{
	struct k7_keycache_level1 *keycache = dev->keycache;
	int index1, index2;

	if (free_level2)
		mutex_lock(&dev->level2_alloc_mutex);
	for (index1 = dev->keycache_level1_max; index1 >= 0; --index1) {
		struct k7_keycache_level2 *level2;
		SPIN_LOCK(&dev->keycache_lock);
		rmb();  /* Synchronize with wmb() in k7_keycache_alloc_level2() */
		level2 = keycache->level2[index1];
		if (level2) {
			if (free_level2)
				keycache->level2[index1] = NULL;
			wmb();
			for (index2 = 0; index2 < K7_KEYCACHE_LEVEL2_WIDTH; ++index2) {
				struct k7_key_slot *slot = &level2->slot[index2];
				struct k7_kek_key  *kk = k7_kk_null_if_empty(slot->kk);
				if (kk)
					k7_delete_kk_from_slot(slot, kk);
			}
			if (free_level2)
				k7_keycache_free_level2(dev, level2);
		}
		if (index1 > 0 && index1 == dev->keycache_level1_max)
			dev->keycache_level1_max--;
		SPIN_UNLOCK(&dev->keycache_lock);
	}
	if (free_level2)
		mutex_unlock(&dev->level2_alloc_mutex);
}

static void k7_free_mechlists (struct k7_mechlist *mechlists)
{
	if (mechlists) {
		int mechlist;
		for (mechlist = 0; mechlist < K7_MAX_MECHLISTS; ++mechlist) {
			struct k7_mechlist *list = &mechlists[mechlist];
			if (list->mechs) {
				kfree(list->mechs);
				list->mechs = NULL;
			}
		}
	}
}

/*
 * This can be used after a failure, to wake up all tasks waiting on keycache events.
 */
void k7_keycache_wake_all (struct k7_dev *dev)
{
	unsigned int group_id;

	for (group_id = 0; group_id < K7_KEYCACHE_GROUPS; ++group_id) {
		struct k7_kek_group *kg = &dev->kek_group[group_id];
		wake_up(&kg->wq);
	}
}

static void k7_kek_group_reinit (struct k7_dev *dev)
{
	unsigned int group_id;

	for (group_id = 0; group_id < K7_KEYCACHE_GROUPS; ++group_id) {
		struct k7_kek_group *kg = &dev->kek_group[group_id];
		SPIN_LOCK(&kg->lock);
		kg->status               = idle;
		kg->group_id             = group_id;
		kg->active_kek_id        = 0;
		kg->pending_kek_id       = 0;
		kg->minimum_kek_id       = 0;
		kg->active_count         = 0;
		kg->notify_hsm_when_zero = 0;
		SPIN_UNLOCK(&kg->lock);
	}
	k7_keycache_wake_all(dev);
}

/*
 * Safely remove keys from keycache, and reinitialize kek_groups, in response to FP_DISABLE.
 */
void k7_keycache_depopulate (struct k7_dev *dev)
{
	if (dev->keycache)
		k7_keycache_free_keys(dev, 0);
	k7_kek_group_reinit(dev);
}

/*
 * Brute-force reinitialization of keycache data structures, for device reset.
 */
void k7_keycache_reset (struct k7_dev *dev, int free_level2)
{
	if (dev->keycache)
		k7_keycache_free_keys(dev, free_level2);
	if (dev->valid_mechlists)
		k7_free_mechlists(dev->valid_mechlists);
	if (dev->invalid_mechlists)
		k7_free_mechlists(dev->invalid_mechlists);
	memset(dev->mechanisms, 0, sizeof(dev->mechanisms));
	memset(dev->mech_ops,   0, sizeof(dev->mech_ops));
	k7_kek_group_reinit(dev);
	k7_free_session_groups(dev);
}

void k7_keycache_free (struct k7_dev *dev)
{
	k7_keycache_reset(dev, 1);
	if (dev->valid_mechlists)
		kfree(dev->valid_mechlists);
	if (dev->invalid_mechlists)
		kfree(dev->invalid_mechlists);
	if (dev->keycache) {
		memset(dev->keycache, 0, sizeof(*(dev->keycache)));
		kfree(dev->keycache);
	}
}

int k7_keycache_alloc (struct k7_dev *dev)
{
	unsigned int group_id;

	SPIN_LOCK_INIT(&dev->keycache_lock);
	SPIN_LOCK_INIT(&dev->mechanisms_lock);
	SPIN_LOCK_INIT(&dev->sessions_lock);
	mutex_init(&dev->level2_alloc_mutex);
	for (group_id = 0; group_id < K7_KEYCACHE_GROUPS; ++group_id) {
		struct k7_kek_group *kg = &dev->kek_group[group_id];
		SPIN_LOCK_INIT(&kg->lock);
		init_waitqueue_head(&kg->wq);
	}
	dev->valid_mechlists   = kzalloc(K7_MAX_MECHLISTS * sizeof(*(dev->valid_mechlists)), GFP_KERNEL);
	if (!dev->valid_mechlists)
		return -ENOMEM;
	dev->invalid_mechlists = kzalloc(K7_MAX_MECHLISTS * sizeof(*(dev->invalid_mechlists)), GFP_KERNEL);
	if (!dev->invalid_mechlists)
		return -ENOMEM;
	dev->keycache = kzalloc(sizeof(*(dev->keycache)), GFP_KERNEL);
	if (!dev->keycache)
		return -ENOMEM;
	k7_kek_group_reinit(dev);
	return 0;  /* success */
}

/*
 * k7_notify_hsm_when_active_count_is_zero():
 *
 * Returns 1 if caller should notify HSM immediately,
 * Returns 0 if notification has been deferred to when active_count later becomes zero.
 */
static u32 k7_notify_hsm_when_active_count_is_zero (struct k7_kek_group *kg)
{
	SPIN_LOCK_REQUIRED(&kg->lock);
	if (!kg->notify_hsm_when_zero) {
		if (kg->active_count == 0)
			return kg->active_kek_id;  /* Caller should notify HSM immediately */
		kg->notify_hsm_when_zero = 1;
	}
	return 0;  /* Caller should not notify HSM; it will happen when active_count goes zero */
}

static void k7_nuke_kek_group_keys (struct k7_dev *dev, unsigned int group_id, u32 kek_id)
{
	/* Needed for session_id tracking. */
	/* Nuke all keys matching group_id which have (kk->kek_id <= kek_id). */

	unsigned int index1, index2;

	/* Iterate over entire keycache: */
	for (index1 = 0; index1 <= dev->keycache_level1_max; ++index1) {
		struct k7_keycache_level2 *level2;
		rmb();  /* Synchronize with wmb() in k7_keycache_alloc_level2() */
		level2 = dev->keycache->level2[index1];
		if (level2) {
			for (index2 = 0; index2 < K7_KEYCACHE_LEVEL2_WIDTH; ++index2) {
				struct k7_key_slot *slot = &level2->slot[index2];
				struct k7_kek_key  *kk = k7_kk_null_if_empty(slot->kk);
				if (kk) {
					u32 generation = 0;
					int do_delete  = 0;
					SPIN_LOCK(&dev->keycache_lock);
					kk = k7_kk_null_if_empty(slot->kk);
					if (kk && kk->group_id == group_id) {
						if (kk->kek_id <= kek_id) {
							generation = kk->generation;
							k7_delete_kk_from_slot(slot, kk);
							do_delete = 1;
						}
					}
					SPIN_UNLOCK(&dev->keycache_lock);
					if (do_delete) {
						unsigned int key_handle = (index1 * K7_KEYCACHE_LEVEL2_WIDTH) + index2;
						k7_delete_key_from_all_sessions(dev, key_handle, generation);
					}
				}
			}
		}
	}
}

static void k7_nuke_outdated_keys (struct k7_dev *dev, u32 group_id, u32 kek_id, u32 minimum_kek_id)
{
	/* Needed by session_id tracking. */
	/* Nuke all "cannot_be_keked" keys matching group_id with (kk->kek_id < minimum_kek_id) */
	/* Nuke all "keked" keys matching group_id with (kk->kek_id <= kek_id) */

	unsigned int index1, index2;

	/* Iterate over entire keycache: */
	for (index1 = 0; index1 <= dev->keycache_level1_max; ++index1) {
		struct k7_keycache_level2 *level2;
		rmb();  /* Synchronize with wmb() in k7_keycache_alloc_level2() */
		level2 = dev->keycache->level2[index1];
		if (level2) {
			for (index2 = 1; index2 < K7_KEYCACHE_LEVEL2_WIDTH; ++index2) {
				struct k7_key_slot *slot = &level2->slot[index2];
				struct k7_kek_key  *kk = k7_kk_null_if_empty(slot->kk);
				if (kk) {
					u32 generation = 0;
					int do_delete  = 0;
					SPIN_LOCK(&dev->keycache_lock);
					kk = k7_kk_null_if_empty(slot->kk);
					if (kk && kk->group_id == group_id) {
						if (kk->kek_id < minimum_kek_id || (!kk->cannot_be_keked && kk->kek_id <= kek_id)) {
							generation = kk->generation;
							k7_delete_kk_from_slot(slot, kk);
							do_delete = 1;
						}
					}
					SPIN_UNLOCK(&dev->keycache_lock);
					if (do_delete) {
						unsigned int key_handle = (index1 * K7_KEYCACHE_LEVEL2_WIDTH) + index2;
						k7_delete_key_from_all_sessions(dev, key_handle, generation);
					}
				}
			}
		}
	}
}

void k7_keycache_stop_kek_group (struct k7_dev *dev, unsigned int group_id)
{
	struct k7_kek_group *kg = &dev->kek_group[group_id];
	u32 kek_id;

	KEKDEBUG(dev->name, "group_id=%u", group_id);
	SPIN_LOCK(&kg->lock);
	if (kg->status != stopped) {
		kg->status = stopped;
		kdebug(dev->name, "stopped group_id=%08x", group_id);
	}
	kek_id = k7_notify_hsm_when_active_count_is_zero(kg);
	SPIN_UNLOCK(&kg->lock);
	k7_nuke_kek_group_keys(dev, group_id, kek_id);
	if (kek_id)
		k7_enqueue_fp_transactions_complete(dev, group_id, kek_id);
}

void k7_keycache_replace_kek_id (struct k7_dev *dev, u32 group_id, u32 kek_id, u32 pending_kek_id, u32 minimum_kek_id)
{
	struct k7_kek_group *kg = &dev->kek_group[group_id];

	KEKDEBUG(dev->name, "group_id=%u kek_id=%08x pending_kek_id=%08x, minimum_kek_id=%08x",
				group_id, kek_id, pending_kek_id, minimum_kek_id);
	SPIN_LOCK(&kg->lock);
	if (kek_id != kg->active_kek_id) {
		kwarn(dev->name, "kek_id=%08x active_kek_id=%08x", kek_id, kg->active_kek_id);
		kg->active_kek_id  = kek_id;
	}
	kg->pending_kek_id = pending_kek_id;
	kg->minimum_kek_id = minimum_kek_id;
	kg->status         = in_replacement;
	kek_id             = k7_notify_hsm_when_active_count_is_zero(kg);
	SPIN_UNLOCK(&kg->lock);
	k7_nuke_outdated_keys(dev, group_id, kek_id, minimum_kek_id);
	if (kek_id)
		k7_enqueue_fp_transactions_complete(dev, group_id, kek_id);
}

void k7_keycache_activate_kek_id (struct k7_dev *dev, u32 group_id, u32 kek_id, u32 minimum_kek_id)
{
	struct k7_kek_group *kg = &dev->kek_group[group_id];

	SPIN_LOCK(&kg->lock);
	KEKDEBUG(dev->name, "group_id=%08x kek_id=%08x", group_id, kek_id);
	if (kg->status == active || kg->active_count || (kg->status == in_replacement && kek_id != kg->pending_kek_id)) {
		kwarn(dev->name, "group_id=%08x kek_id=%08x pending_kek_id=%08x minimum_kek_id=%08x status=%u active_count=%d",
				group_id, kek_id, kg->pending_kek_id, kg->minimum_kek_id, kg->status, kg->active_count);
	}
	kg->active_kek_id  = kek_id;
	kg->pending_kek_id = 0;
	kg->minimum_kek_id = minimum_kek_id;
	kg->status         = active;
	SPIN_UNLOCK(&kg->lock);
	wake_up(&kg->wq);
}

void k7_keycache_update_minimum_kek_id (struct  k7_dev *dev, u32 group_id, u32 kek_id)
{
	struct k7_kek_group *kg = &dev->kek_group[group_id];

	SPIN_LOCK(&kg->lock);
	KEKDEBUG(dev->name, "group_id=%08x kek_id=%08x", group_id, kek_id);
	kg->minimum_kek_id = kek_id;
	SPIN_UNLOCK(&kg->lock);
}
