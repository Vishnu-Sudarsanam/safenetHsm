/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * sessions.c
 */
#include "headers.h"

/*
 * key_handles get re-used, frequently.
 *    We maintain a per-key_handle "generation" count(u32) in the key_key struct.
 *    For empty keycache slots, we encode the generation count into the NULL slot pointer,
 *      in place of the usual NULL, shifted and OR'd with a 1 so that we can distinguish it
 *      from a valid kk pointer.  This works well and doesn't affect management of kk structs.
 *    When adding a new kk entry, we grab/increment the generation count from the slot,
 *      and save it into the kk struct.  Copy it unchanged to new kk struct each time a kk is updated.
 *    On key deletion, it gets stuffed back into the keycache slot instead of a NULL pointer.
 *    The session_id keylists store BOTH the key_handle and the generation count.
 *
 * K7_FP_DELETE_KEY_HANDLE::k7_delete_key_from_all_sessions():
 *    If performance/CPU becomes an issue here, then we could also maintain lists
 *      of session_ids to each kk struct, enabling fast two-way lookups at the
 *      expense of added overhead and using double the RAM for storing keys.
 */

static inline int is_older_generation (u32 generation, u32 new_generation)
{
	u64 new64 = new_generation;

	if (new_generation < generation)
		new64 += 0x100000000ull;
	return (new64 - (u64)generation) < 0x3fffffffull;
}

static int k7_add_key_to_keylist (struct k7_dev *dev, struct k7_session_keylist *keylist, struct k7_key_id key)
{
	if (keylist->num_keys < K7_SESSION_KEYLIST_ENTRIES) {
		struct k7_key_id *this_key    = keylist->keys;
		struct k7_key_id *end_of_list = this_key + K7_SESSION_KEYLIST_ENTRIES;
		do {
			if (!this_key->id) {
				*this_key = key;
				keylist->num_keys++;
				kdebug(dev->name, "id(%016llx) added", key.id);
				return 0;
			}
			if (this_key->key_handle == key.key_handle) {
				if (is_older_generation(this_key->generation, key.generation)) {
					/* Not supposed to be possible, because older generations are deleted beforehand. */
					this_key->generation = key.generation;  /* Replace older with newer */
					kdebug(dev->name, "id(%016llx) updated", key.id);
					return 0;
				}
				return 0;  /* keylist already has same/newer generation of key */
			}
		} while (++this_key != end_of_list);  /* Paranoia */
		kerr(dev->name, "Bug: num_keys=%d/%d", keylist->num_keys, K7_SESSION_KEYLIST_ENTRIES);
		keylist->num_keys = K7_SESSION_KEYLIST_ENTRIES;
	}
	return -ENOENT;
}

static int k7_delete_key_from_keylist (struct k7_dev *dev, struct k7_session_keylist *keylist, struct k7_key_id key)
{
	int count = 0;

	/* Delete all same/older generations of key from keylist */
	if (keylist->num_keys) {
		struct k7_key_id *this_key    = keylist->keys;
		struct k7_key_id *end_of_list = this_key + K7_SESSION_KEYLIST_ENTRIES;
		do {
			if (this_key->key_handle == key.key_handle) {
				if (this_key->generation == key.generation
				 || is_older_generation(this_key->generation, key.generation)) {
					this_key->id = 0ull;  /* delete this key from list */
					++count;
					if (!--keylist->num_keys)
						break;
				}
			}
		} while (++this_key != end_of_list);  /* Paranoia */
	}
	return count;
}

static void k7_delete_key_from_session_group (struct k7_dev *dev, struct k7_session_group *group, unsigned int groupx, struct k7_key_id key)
{
	struct k7_session_keylist *keylist = group->keylists[groupx];
	struct k7_session_keylist **prev   = NULL;
	int count = 0;

	if (!keylist)
		return;
	do {
		struct k7_session_keylist *next;
		count += k7_delete_key_from_keylist(dev, keylist, key);
		/*
		 * Keep at least one keylist around while the session remains open,
		 * to avoid free/alloc repetitions on rekek operations.
		 * If this keylist is now empty and it is not the first keylist for this session,
		 * it can be removed/freed here now.
		 */
		next = keylist->next;
		if (!prev || keylist->num_keys) {
			prev = &keylist->next;
		} else {
			*prev = next;  /* unlink keylist from the chain */
			memset(keylist, 0, sizeof(*keylist));
			kfree(keylist);
		}
		keylist = next;
	} while (keylist);
	if (count > 1)
		kwarn(dev->name, "count=%d", count);
	keylist = group->keylists[groupx];
	if (!keylist->num_keys && keylist->next) {
		/* First keylist is empty and there is at least one more keylist in the chain */
		group->keylists[groupx] = keylist->next;
		memset(keylist, 0, sizeof(*keylist));
		kfree(keylist);
	}
	/*
	 * This can still finish up with a chain of very sparsely filled keylists here.
	 * If that is an issue, code can be added to detect this and compress the chain here.
	 */
}

static int k7_find_key_in_keylist (struct k7_session_keylist *keylist, struct k7_key_id key)
{
	if (keylist->num_keys) {
		struct k7_key_id *this_key    = keylist->keys;
		struct k7_key_id *end_of_list = this_key + K7_SESSION_KEYLIST_ENTRIES;
		do {
			if (this_key->id == key.id)
				return 0;
		} while (++this_key != end_of_list);
	}
	return -ENOENT;
}

static void k7_free_session_keylist (struct k7_dev *dev, struct k7_session_keylist *keylist)
{
	while (keylist) {
		struct k7_session_keylist *next = keylist->next;
		memset(keylist, 0, sizeof(*keylist));
		kfree(keylist);
		keylist = next;
	}
}

void k7_free_session_groups (struct k7_dev *dev)
{
	unsigned int group_id, groupx;

	dev->max_session_id = 0;
	for (group_id = 0; group_id < K7_SESSION_GROUPS; ++group_id) {
		struct k7_session_group *group;
		SPIN_LOCK(&dev->sessions_lock);
		group = dev->session_groups[group_id];
		dev->session_groups[group_id] = NULL;
		SPIN_UNLOCK(&dev->sessions_lock);
		if (group) {
			for (groupx = 0; groupx < K7_SESSIONS_PER_GROUP; ++groupx) {
				struct k7_session_keylist *keylist = group->keylists[groupx];
				if (keylist) {
					group->keylists[groupx] = NULL;
					k7_free_session_keylist(dev, keylist);
				}
			}
			free_page((long)group);
		}
	}
}

static int k7_valid_session_id (struct k7_dev *dev, u32 session_id)
{
	int valid = k7_session_id_okay(session_id);
	if (!valid)
		kwarn(dev->name, "session_id=%08x not valid", session_id);
	return valid;
}

int k7_add_key_to_session (struct k7_dev *dev, u32 session_id, u32 key_handle, u32 generation)
{
	struct k7_session_group   *group;
	struct k7_session_keylist *keylist, *new_keylist;
	struct k7_key_id           key;
	unsigned long page = 0;
	unsigned int group_id, groupx;
	int err = -ENOMEM;

	key.key_handle = key_handle;
	key.generation = generation;
	kdebug(dev->name, "id(%016llx) session_id=%08x", key.id, session_id);
	if (!k7_valid_session_id(dev, session_id))
		return -EINVAL;
	group_id = session_id / K7_SESSIONS_PER_GROUP;
	groupx   = session_id % K7_SESSIONS_PER_GROUP;

	/*
	 * Perform group allocation (if needed) before we grab spinlock.
	 * This can race against other tasks, but we catch that later.
	 */
	if (!dev->session_groups[group_id]) {
		page = __get_free_page(GFP_KERNEL);
		if (!page) {
			kerr(dev->name, "__get_free_page() failed");
			return -ENOMEM;
		}
		memset((void *)page, 0, PAGE_SIZE);
	}

	/* Pre-allocate a new keylist struct in case we need it while spinlock'd below */
	new_keylist = kzalloc(sizeof(*keylist), GFP_KERNEL);

	SPIN_LOCK(&dev->sessions_lock);
	if (session_id > dev->max_session_id)
		dev->max_session_id = session_id;  /* high-water mark */
	group = dev->session_groups[group_id];
	if (group) {
		free_page(page);  /* Another task won the race */
		k7_delete_key_from_session_group(dev, group, groupx, key);
	} else {
		group = (void *)page;
		dev->session_groups[group_id] = group;
	}
	keylist = group->keylists[groupx];
	if (!keylist) {
		keylist = new_keylist;
		new_keylist = NULL;
		if (!keylist)
			goto err_exit;
		group->keylists[groupx] = keylist;
	}
	while (k7_add_key_to_keylist(dev, keylist, key)) {
		if (!keylist->next) {
			keylist->next = new_keylist;
			new_keylist = NULL;
			keylist = keylist->next;
			if (!keylist)
				goto err_exit;
		}
	}
	err = 0;
	kdebug(dev->name, "Added %08x:%08x to session %08x", key.key_handle, key.generation, session_id);
err_exit:
	SPIN_UNLOCK(&dev->sessions_lock);
	if (err)
		kerr(dev->name, "%08x:%08x session_id=%08x err=%d", key.key_handle, key.generation, session_id, err);
	if (new_keylist)
		kfree(new_keylist);
	return err;
}

static void k7_delete_key_from_session (struct k7_dev *dev, u32 session_id, u32 key_handle, u32 generation)
{
	struct k7_session_group    *group;
	struct k7_key_id            key;
	unsigned int group_id, groupx;

	if (!dev->max_session_id)
		return;
	key.key_handle = key_handle;
	key.generation = generation;
	kdebug(dev->name, "id(%016llx) session_id=%08x", key.id, session_id);
	if (!k7_valid_session_id(dev, session_id))
		return;
	group_id = session_id / K7_SESSIONS_PER_GROUP;
	groupx   = session_id % K7_SESSIONS_PER_GROUP;

	SPIN_LOCK(&dev->sessions_lock);
	group = dev->session_groups[group_id];
	if (group)
		k7_delete_key_from_session_group(dev, group, groupx, key);
	SPIN_UNLOCK(&dev->sessions_lock);
}

void k7_delete_key_from_all_sessions (struct k7_dev *dev, u32 key_handle, u32 generation)
{
	u32 session_id;

	kdebug(dev->name, "%08x:%08x", key_handle, generation);
	for (session_id = 1; session_id <= dev->max_session_id; ++session_id)
		k7_delete_key_from_session(dev, session_id, key_handle, generation);
}

int k7_validate_key_for_session (struct k7_dev *dev, u32 session_id, u32 key_handle, u32 generation)
{
	struct k7_session_group    *group;
	struct k7_key_id            key;
	unsigned int group_id, groupx;
	int err = -EPERM;

	key.key_handle = key_handle;
	key.generation = generation;
	if (!k7_valid_session_id(dev, session_id))
		return -EINVAL;
	group_id = session_id / K7_SESSIONS_PER_GROUP;
	groupx   = session_id % K7_SESSIONS_PER_GROUP;

	SPIN_LOCK(&dev->sessions_lock);
	group = dev->session_groups[group_id];
	if (group) {
		struct k7_session_keylist *keylist = group->keylists[groupx];
		while (keylist) {
			if (0 == k7_find_key_in_keylist(keylist, key)) {
				err = 0;
				break;
			}
			keylist = keylist->next;
		}
	}
	SPIN_UNLOCK(&dev->sessions_lock);
	kdebug(dev->name, "session_id=%08x  err=%d", session_id, err);
	return err;
}

int k7_delete_session (struct k7_dev *dev, u32 session_id)
{
	struct k7_session_group   *group;
	struct k7_session_keylist *keylist = NULL;
	unsigned int group_id, groupx;

	if (!dev->max_session_id)
		return 0;
	kdebug(dev->name, "session_id=%08x", session_id);
	if (!k7_valid_session_id(dev, session_id))
		return -EINVAL;
	group_id = session_id / K7_SESSIONS_PER_GROUP;
	groupx   = session_id % K7_SESSIONS_PER_GROUP;
	SPIN_LOCK(&dev->sessions_lock);
	group    = dev->session_groups[group_id];
	if (group) {
		keylist = group->keylists[groupx];
		group->keylists[groupx] = NULL;
	}
	SPIN_UNLOCK(&dev->sessions_lock);
	if (keylist)
		k7_free_session_keylist(dev, keylist);
	return 0;
}
