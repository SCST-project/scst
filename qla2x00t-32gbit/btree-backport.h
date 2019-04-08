#ifndef _BTREE_BACKPORT_H_
#define _BTREE_BACKPORT_H_

struct btree_head32 {
	struct list_head	head;
};

struct btree_node32 {
	struct list_head	entry;
	u32			key;
	void			*val;
};

struct btree_head64 {
	struct list_head	head;
};

struct btree_node64 {
	struct list_head	entry;
	u64			key;
	void			*val;
};

/**
 * btree_init - initialise a btree
 *
 * @head: the btree head to initialise
 *
 * This function allocates the memory pool that the
 * btree needs. Returns zero or a negative error code
 * (-%ENOMEM) when memory allocation fails.
 */
static inline int __must_check btree_init32(struct btree_head32 *head)
{
	INIT_LIST_HEAD(&head->head);
	return 0;
}

static inline int __must_check btree_init64(struct btree_head64 *head)
{
	INIT_LIST_HEAD(&head->head);
	return 0;
}

/**
 * btree_destroy - destroy mempool
 *
 * @head: the btree head to destroy
 *
 * This function destroys the internal memory pool, use only
 * when using btree_init(), not with btree_init_mempool().
 */
static inline void btree_destroy32(struct btree_head32 *head)
{
}

static inline void btree_destroy64(struct btree_head64 *head)
{
}

/**
 * btree_lookup - look up a key in the btree
 *
 * @head: the btree to look in
 * @geo: the btree geometry
 * @key: the key to look up
 *
 * This function returns the value for the given key, or %NULL.
 */
static inline void *btree_lookup32(struct btree_head32 *head, u32 key)
{
	struct btree_node32 *n;

	list_for_each_entry(n, &head->head, entry) {
		if (n->key == key)
			return n->val;
	}
	return NULL;
}

static inline void *btree_lookup64(struct btree_head64 *head, u64 key)
{
	struct btree_node64 *n;

	list_for_each_entry(n, &head->head, entry) {
		if (n->key == key)
			return n->val;
	}
	return NULL;
}

/**
 * btree_insert - insert an entry into the btree
 *
 * @head: the btree to add to
 * @geo: the btree geometry
 * @key: the key to add (must not already be present)
 * @val: the value to add (must not be %NULL)
 * @gfp: allocation flags for node allocations
 *
 * This function returns 0 if the item could be added, or an
 * error code if it failed (may fail due to memory pressure).
 */
static inline int __must_check btree_insert32(struct btree_head32 *head,
				u32 key, void *val, gfp_t gfp)
{
	struct btree_node32 *n, *p;

	n = kmalloc(sizeof(*n), gfp);
	if (IS_ERR(n))
		return PTR_ERR(n);
	n->key = key;
	n->val = val;
	list_for_each_entry(p, &head->head, entry) {
		if (p->key > key)
			break;
	}
	list_add(&n->entry, p->entry.prev);
	return 0;
}

static inline int __must_check btree_insert64(struct btree_head64 *head,
				u64 key, void *val, gfp_t gfp)
{
	struct btree_node64 *n, *p;

	n = kmalloc(sizeof(*n), gfp);
	if (IS_ERR(n))
		return PTR_ERR(n);
	n->key = key;
	n->val = val;
	list_for_each_entry(p, &head->head, entry) {
		if (p->key > key)
			break;
	}
	list_add(&n->entry, p->entry.prev);
	return 0;
}

/**
 * btree_update - update an entry in the btree
 *
 * @head: the btree to update
 * @geo: the btree geometry
 * @key: the key to update
 * @val: the value to change it to (must not be %NULL)
 *
 * This function returns 0 if the update was successful, or
 * -%ENOENT if the key could not be found.
 */
static inline int btree_update32(struct btree_head32 *head, u32 key, void *val)
{
	struct btree_node32 *p;

	list_for_each_entry(p, &head->head, entry) {
		if (p->key == key) {
			p->val = val;
			return 0;
		}
	}
	return -ENOENT;
}

/**
 * btree_remove - remove an entry from the btree
 *
 * @head: the btree to update
 * @geo: the btree geometry
 * @key: the key to remove
 *
 * This function returns the removed entry, or %NULL if the key
 * could not be found.
 */
static inline void *btree_remove32(struct btree_head32 *head, u32 key)
{
	struct btree_node32 *p;
	void *val;

	list_for_each_entry(p, &head->head, entry) {
		if (p->key == key) {
			val = p->val;
			list_del(&p->entry);
			kfree(p);
			return val;
		}
	}
	return NULL;
}

static inline void *btree_remove64(struct btree_head64 *head, u64 key)
{
	struct btree_node64 *p;
	void *val;

	list_for_each_entry(p, &head->head, entry) {
		if (p->key == key) {
			val = p->val;
			list_del(&p->entry);
			kfree(p);
			return val;
		}
	}
	return NULL;
}

/**
 * btree_last - get last entry in btree
 *
 * @head: btree head
 * @geo: btree geometry
 * @key: last key
 *
 * Returns the last entry in the btree, and sets @key to the key
 * of that entry; returns NULL if the tree is empty, in that case
 * key is not changed.
 */
static inline void *btree_last32(struct btree_head32 *head, u32 *key)
{
	struct btree_node32 *p;

	if (list_empty(&head->head))
		return NULL;
	p = list_last_entry(&head->head, typeof(*p), entry);
	*key = p->key;
	return p->val;
}

static inline void *btree_last64(struct btree_head64 *head, u64 *key)
{
	struct btree_node64 *p;

	if (list_empty(&head->head))
		return NULL;
	p = list_last_entry(&head->head, typeof(*p), entry);
	*key = p->key;
	return p->val;
}

/**
 * btree_get_prev - get previous entry
 *
 * @head: btree head
 * @geo: btree geometry
 * @key: pointer to key
 *
 * The function returns the next item right before the value pointed to by
 * @key, and updates @key with its key, or returns %NULL when there is no
 * entry with a key smaller than the given key.
 */
static inline void *btree_get_prev32(struct btree_head32 *head, u32 *key)
{
	struct btree_node32 *p;

	list_for_each_entry_reverse(p, &head->head, entry) {
		if (p->key < *key) {
			*key = p->key;
			return p->val;
		}
	}
	return NULL;
}

static inline void *btree_get_prev64(struct btree_head64 *head, u64 *key)
{
	struct btree_node64 *p;

	list_for_each_entry_reverse(p, &head->head, entry) {
		if (p->key < *key) {
			*key = p->key;
			return p->val;
		}
	}
	return NULL;
}

#define btree_for_each_safe32(head, key, val)	\
	for (val = btree_last32(head, &key);	\
	     val;				\
	     val = btree_get_prev32(head, &key))

#define btree_for_each_safe64(head, key, val)	\
	for (val = btree_last64(head, &key);	\
	     val;				\
	     val = btree_get_prev64(head, &key))

#endif /* _BTREE_BACKPORT_H_ */
