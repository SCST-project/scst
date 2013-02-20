/*
 *  Copyright (C) 2007 - 2013 Vladislav Bolkhovitin
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *  Copyright (C) 2010 - 2013 SCST Ltd.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation, version 2
 *  of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#ifndef MISC_H
#define MISC_H

struct __qelem {
	struct __qelem *q_forw;
	struct __qelem *q_back;
};

/* stolen list stuff from Linux kernel */

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) \
	struct __qelem name = LIST_HEAD_INIT(name)

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->q_forw = (ptr); (ptr)->q_back = (ptr); \
} while (0)

static inline int list_empty(const struct __qelem *head)
{
	return head->q_forw == head;
}

static inline int list_length_is_one(const struct __qelem *head)
{
        return (!list_empty(head) && head->q_forw == head->q_back);
}

#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->q_forw, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = list_entry(pos->member.q_forw, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->q_forw, typeof(*pos), member),	\
		n = list_entry(pos->member.q_forw, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.q_forw, typeof(*n), member))

#define list_del(elem) remque(elem)

#define list_del_init(elem) do {		\
		remque(elem);			\
		INIT_LIST_HEAD(elem);		\
	} while (0)

#define list_add(new, head) insque (new, head)

#define list_add_tail(new, head) insque(new, (head)->q_back)

/* min()/max() that do strict type-checking. Lifted from the kernel. */
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

/* ... and their non-checking counterparts, also taken from the kernel. */
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1: __max2; })

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY	26
#endif

extern void set_non_blocking(int fd);
extern void sock_set_keepalive(int sock, int timeout);

#endif
