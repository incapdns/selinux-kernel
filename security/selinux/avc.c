// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implementation of the kernel access vector cache (AVC).
 *
 * Authors:  Stephen Smalley, <stephen.smalley.work@gmail.com>
 *	     James Morris <jmorris@redhat.com>
 *
 * Update:   KaiGai, Kohei <kaigai@ak.jp.nec.com>
 *	Replaced the avc_lock spinlock by RCU.
 *
 * Copyright (C) 2003 Red Hat, Inc., James Morris <jmorris@redhat.com>
 */
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <linux/list.h>
#include <net/sock.h>
#include <linux/un.h>
#include <net/af_unix.h>
#include <linux/ip.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include "avc.h"
#include "avc_ss.h"
#include "classmap.h"
#include "hash.h"
#include "resource.h"
#ifdef CONFIG_SECURITY_SELINUX_NS
#include "label_view.h"
#include "namespace.h"
#include "pathless.h"
#endif

#define CREATE_TRACE_POINTS
#include <trace/events/avc.h>

#define AVC_CACHE_SLOTS		(1 << CONFIG_SECURITY_SELINUX_AVC_HASH_BITS)
#define AVC_DEF_CACHE_THRESHOLD	AVC_CACHE_SLOTS
#define AVC_CACHE_RECLAIM	16

#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
#define avc_cache_stats_incr(field)	this_cpu_inc(avc_cache_stats.field)
#else
#define avc_cache_stats_incr(field)	do {} while (0)
#endif

struct avc_entry {
	u32			ssid;
	u32			tsid;
	u16			tclass;
	struct av_decision	avd;
	struct avc_xperms_node	*xp_node;
};

struct avc_node {
	struct avc_entry	ae;
	struct selinux_resource_account *resources;
	struct hlist_node	list; /* anchored in avc_cache->slots[i] */
	struct rcu_head		rhead;
};

struct avc_xperms_decision_node {
	struct extended_perms_decision xpd;
	struct selinux_resource_account *resources;
	size_t charged_bytes;
	struct list_head xpd_list; /* list of extended_perms_decision */
};

struct avc_xperms_node {
	struct extended_perms xp;
	struct selinux_resource_account *resources;
	struct list_head xpd_head; /* list head of extended_perms_decision */
};

struct avc_cache {
	struct hlist_head	slots[AVC_CACHE_SLOTS]; /* head for avc_node->list */
	spinlock_t		slots_lock[AVC_CACHE_SLOTS]; /* lock for writes */
	atomic_t		lru_hint;	/* LRU hint for reclaim scan */
	atomic_t		active_nodes;
	u32			latest_notif;	/* latest revocation notification */
};

struct avc_callback_node {
	selinux_avc_callback_t callback;
	u32 events;
	struct avc_callback_node *next;
};

#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
DEFINE_PER_CPU(struct avc_cache_stats, avc_cache_stats) = { 0 };
#endif

struct selinux_avc {
	unsigned int avc_cache_threshold;
	struct selinux_resource_account *resources;
	struct avc_cache avc_cache;
};

int selinux_avc_create(struct selinux_resource_account *resources,
		       struct selinux_avc **avc)
{
	struct selinux_avc *newavc;
	int i, rc;

	if (!resources)
		return -EINVAL;
	rc = selinux_resource_reserve(resources, SELINUX_RESOURCE_AVC, 1,
				      sizeof(*newavc));
	if (rc)
		return rc;

	newavc = kzalloc(sizeof(*newavc), GFP_KERNEL);
	if (!newavc) {
		selinux_resource_release(resources, SELINUX_RESOURCE_AVC, 1,
					 sizeof(*newavc));
		return -ENOMEM;
	}

	newavc->avc_cache_threshold = AVC_DEF_CACHE_THRESHOLD;
	newavc->resources = selinux_resource_account_get(resources);

	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		INIT_HLIST_HEAD(&newavc->avc_cache.slots[i]);
		spin_lock_init(&newavc->avc_cache.slots_lock[i]);
	}
	atomic_set(&newavc->avc_cache.active_nodes, 0);
	atomic_set(&newavc->avc_cache.lru_hint, 0);

	*avc = newavc;
	return 0;
}

static void avc_flush(struct selinux_avc *avc);

void selinux_avc_free(struct selinux_avc *avc)
{
	avc_flush(avc);
	selinux_resource_release(avc->resources, SELINUX_RESOURCE_AVC, 1,
				 sizeof(*avc));
	selinux_resource_account_put(avc->resources);
	kfree(avc);
}

unsigned int avc_get_cache_threshold(struct selinux_avc *avc)
{
	return READ_ONCE(avc->avc_cache_threshold);
}

int avc_set_cache_threshold(struct selinux_avc *avc,
			    unsigned int cache_threshold)
{
	if (!cache_threshold ||
	    cache_threshold > CONFIG_SECURITY_SELINUX_AVC_MAX_NODES_PER_STATE)
		return -ERANGE;
	WRITE_ONCE(avc->avc_cache_threshold, cache_threshold);
	return 0;
}

static struct avc_callback_node *avc_callbacks __ro_after_init;
static struct kmem_cache *avc_node_cachep __ro_after_init;
static struct kmem_cache *avc_xperms_data_cachep __ro_after_init;
static struct kmem_cache *avc_xperms_decision_cachep __ro_after_init;
static struct kmem_cache *avc_xperms_cachep __ro_after_init;

static inline u32 avc_hash(u32 ssid, u32 tsid, u16 tclass)
{
	return av_hash(ssid, tsid, (u32)tclass, (u32)(AVC_CACHE_SLOTS - 1));
}

/**
 * avc_init - Initialize the AVC.
 *
 * Initialize the access vector cache.
 */
void __init avc_init(void)
{
	avc_node_cachep = KMEM_CACHE(avc_node, SLAB_PANIC);
	avc_xperms_cachep = KMEM_CACHE(avc_xperms_node, SLAB_PANIC);
	avc_xperms_decision_cachep = KMEM_CACHE(avc_xperms_decision_node, SLAB_PANIC);
	avc_xperms_data_cachep = KMEM_CACHE(extended_perms_data, SLAB_PANIC);
}

int avc_get_hash_stats(struct selinux_avc *avc, char *page)
{
	int i, chain_len, max_chain_len, slots_used;
	struct avc_node *node;
	struct hlist_head *head;

	rcu_read_lock();

	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		head = &avc->avc_cache.slots[i];
		if (!hlist_empty(head)) {
			slots_used++;
			chain_len = 0;
			hlist_for_each_entry_rcu(node, head, list)
				chain_len++;
			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
		}
	}

	rcu_read_unlock();

	return scnprintf(page, PAGE_SIZE, "entries: %d\nbuckets used: %d/%d\n"
			 "longest chain: %d\n",
			 atomic_read(&avc->avc_cache.active_nodes),
			 slots_used, AVC_CACHE_SLOTS, max_chain_len);
}

/*
 * using a linked list for extended_perms_decision lookup because the list is
 * always small. i.e. less than 5, typically 1
 */
static struct extended_perms_decision *
avc_xperms_decision_lookup(u8 driver, u8 base_perm,
			   struct avc_xperms_node *xp_node)
{
	struct avc_xperms_decision_node *xpd_node;

	list_for_each_entry(xpd_node, &xp_node->xpd_head, xpd_list) {
		if (xpd_node->xpd.driver == driver &&
		    xpd_node->xpd.base_perm == base_perm)
			return &xpd_node->xpd;
	}
	return NULL;
}

static inline unsigned int
avc_xperms_has_perm(struct extended_perms_decision *xpd,
					u8 perm, u8 which)
{
	unsigned int rc = 0;

	if ((which == XPERMS_ALLOWED) &&
			(xpd->used & XPERMS_ALLOWED))
		rc = security_xperm_test(xpd->allowed->p, perm);
	else if ((which == XPERMS_AUDITALLOW) &&
			(xpd->used & XPERMS_AUDITALLOW))
		rc = security_xperm_test(xpd->auditallow->p, perm);
	else if ((which == XPERMS_DONTAUDIT) &&
			(xpd->used & XPERMS_DONTAUDIT))
		rc = security_xperm_test(xpd->dontaudit->p, perm);
	return rc;
}

static void avc_xperms_allow_perm(struct avc_xperms_node *xp_node,
				  u8 driver, u8 base_perm, u8 perm)
{
	struct extended_perms_decision *xpd;
	security_xperm_set(xp_node->xp.drivers.p, driver);
	xp_node->xp.base_perms |= base_perm;
	xpd = avc_xperms_decision_lookup(driver, base_perm, xp_node);
	if (xpd && xpd->allowed)
		security_xperm_set(xpd->allowed->p, perm);
}

static void avc_xperms_decision_free(struct avc_xperms_decision_node *xpd_node)
{
	struct extended_perms_decision *xpd;
	struct selinux_resource_account *resources;
	size_t charged_bytes;

	xpd = &xpd_node->xpd;
	resources = xpd_node->resources;
	charged_bytes = xpd_node->charged_bytes;
	if (xpd->allowed)
		kmem_cache_free(avc_xperms_data_cachep, xpd->allowed);
	if (xpd->auditallow)
		kmem_cache_free(avc_xperms_data_cachep, xpd->auditallow);
	if (xpd->dontaudit)
		kmem_cache_free(avc_xperms_data_cachep, xpd->dontaudit);
	kmem_cache_free(avc_xperms_decision_cachep, xpd_node);
	selinux_resource_release(resources, SELINUX_RESOURCE_AVC, 1,
				 charged_bytes);
}

static void avc_xperms_free(struct avc_xperms_node *xp_node)
{
	struct avc_xperms_decision_node *xpd_node, *tmp;
	struct selinux_resource_account *resources;

	if (!xp_node)
		return;
	resources = xp_node->resources;

	list_for_each_entry_safe(xpd_node, tmp, &xp_node->xpd_head, xpd_list) {
		list_del(&xpd_node->xpd_list);
		avc_xperms_decision_free(xpd_node);
	}
	kmem_cache_free(avc_xperms_cachep, xp_node);
	selinux_resource_release(resources, SELINUX_RESOURCE_AVC, 1,
				 sizeof(*xp_node));
}

static void avc_copy_xperms_decision(struct extended_perms_decision *dest,
					struct extended_perms_decision *src)
{
	dest->base_perm = src->base_perm;
	dest->driver = src->driver;
	dest->used = src->used;
	if (dest->used & XPERMS_ALLOWED)
		memcpy(dest->allowed->p, src->allowed->p,
				sizeof(src->allowed->p));
	if (dest->used & XPERMS_AUDITALLOW)
		memcpy(dest->auditallow->p, src->auditallow->p,
				sizeof(src->auditallow->p));
	if (dest->used & XPERMS_DONTAUDIT)
		memcpy(dest->dontaudit->p, src->dontaudit->p,
				sizeof(src->dontaudit->p));
}

/*
 * similar to avc_copy_xperms_decision, but only copy decision
 * information relevant to this perm
 */
static inline void avc_quick_copy_xperms_decision(u8 perm,
			struct extended_perms_decision *dest,
			struct extended_perms_decision *src)
{
	/*
	 * compute index of the u32 of the 256 bits (8 u32s) that contain this
	 * command permission
	 */
	u8 i = perm >> 5;

	dest->base_perm = src->base_perm;
	dest->used = src->used;
	if (dest->used & XPERMS_ALLOWED)
		dest->allowed->p[i] = src->allowed->p[i];
	if (dest->used & XPERMS_AUDITALLOW)
		dest->auditallow->p[i] = src->auditallow->p[i];
	if (dest->used & XPERMS_DONTAUDIT)
		dest->dontaudit->p[i] = src->dontaudit->p[i];
}

static struct avc_xperms_decision_node *
avc_xperms_decision_alloc(struct selinux_resource_account *resources, u8 which)
{
	struct avc_xperms_decision_node *xpd_node;
	struct extended_perms_decision *xpd;
	size_t charged_bytes = sizeof(*xpd_node);
	int rc;

	charged_bytes += hweight8(which & (XPERMS_ALLOWED |
					 XPERMS_AUDITALLOW |
					 XPERMS_DONTAUDIT)) *
			 sizeof(struct extended_perms_data);
	rc = selinux_resource_reserve(resources, SELINUX_RESOURCE_AVC, 1,
				      charged_bytes);
	if (rc)
		return NULL;

	xpd_node = kmem_cache_zalloc(avc_xperms_decision_cachep, GFP_NOWAIT);
	if (!xpd_node) {
		selinux_resource_release(resources, SELINUX_RESOURCE_AVC, 1,
					 charged_bytes);
		return NULL;
	}

	xpd_node->resources = resources;
	xpd_node->charged_bytes = charged_bytes;
	xpd = &xpd_node->xpd;
	if (which & XPERMS_ALLOWED) {
		xpd->allowed = kmem_cache_zalloc(avc_xperms_data_cachep,
						 GFP_NOWAIT);
		if (!xpd->allowed)
			goto error;
	}
	if (which & XPERMS_AUDITALLOW) {
		xpd->auditallow = kmem_cache_zalloc(avc_xperms_data_cachep,
						    GFP_NOWAIT);
		if (!xpd->auditallow)
			goto error;
	}
	if (which & XPERMS_DONTAUDIT) {
		xpd->dontaudit = kmem_cache_zalloc(avc_xperms_data_cachep,
						   GFP_NOWAIT);
		if (!xpd->dontaudit)
			goto error;
	}
	return xpd_node;
error:
	avc_xperms_decision_free(xpd_node);
	return NULL;
}

static int avc_add_xperms_decision(struct avc_node *node,
			struct extended_perms_decision *src)
{
	struct avc_xperms_decision_node *dest_xpd;

	dest_xpd = avc_xperms_decision_alloc(node->resources, src->used);
	if (!dest_xpd)
		return -ENOMEM;
	avc_copy_xperms_decision(&dest_xpd->xpd, src);
	list_add(&dest_xpd->xpd_list, &node->ae.xp_node->xpd_head);
	node->ae.xp_node->xp.len++;
	return 0;
}

static struct avc_xperms_node *
avc_xperms_alloc(struct selinux_resource_account *resources)
{
	struct avc_xperms_node *xp_node;
	int rc;

	rc = selinux_resource_reserve(resources, SELINUX_RESOURCE_AVC, 1,
				      sizeof(*xp_node));
	if (rc)
		return NULL;

	xp_node = kmem_cache_zalloc(avc_xperms_cachep, GFP_NOWAIT);
	if (!xp_node) {
		selinux_resource_release(resources, SELINUX_RESOURCE_AVC, 1,
					 sizeof(*xp_node));
		return NULL;
	}
	xp_node->resources = resources;
	INIT_LIST_HEAD(&xp_node->xpd_head);
	return xp_node;
}

static int avc_xperms_populate(struct avc_node *node,
				struct avc_xperms_node *src)
{
	struct avc_xperms_node *dest;
	struct avc_xperms_decision_node *dest_xpd;
	struct avc_xperms_decision_node *src_xpd;

	if (src->xp.len == 0)
		return 0;
	dest = avc_xperms_alloc(node->resources);
	if (!dest)
		return -ENOMEM;

	memcpy(dest->xp.drivers.p, src->xp.drivers.p, sizeof(dest->xp.drivers.p));
	dest->xp.len = src->xp.len;
	dest->xp.base_perms = src->xp.base_perms;

	/* for each source xpd allocate a destination xpd and copy */
	list_for_each_entry(src_xpd, &src->xpd_head, xpd_list) {
		dest_xpd = avc_xperms_decision_alloc(node->resources,
						 src_xpd->xpd.used);
		if (!dest_xpd)
			goto error;
		avc_copy_xperms_decision(&dest_xpd->xpd, &src_xpd->xpd);
		list_add(&dest_xpd->xpd_list, &dest->xpd_head);
	}
	node->ae.xp_node = dest;
	return 0;
error:
	avc_xperms_free(dest);
	return -ENOMEM;

}

static inline u32 avc_xperms_audit_required(u32 requested,
					struct av_decision *avd,
					struct extended_perms_decision *xpd,
					u8 perm,
					int result,
					u32 *deniedp)
{
	u32 denied, audited;

	denied = requested & ~avd->allowed;
	if (unlikely(denied)) {
		audited = denied & avd->auditdeny;
		if (audited && xpd) {
			if (avc_xperms_has_perm(xpd, perm, XPERMS_DONTAUDIT))
				audited = 0;
		}
	} else if (result) {
		audited = denied = requested;
	} else {
		audited = requested & avd->auditallow;
		if (audited && xpd) {
			if (!avc_xperms_has_perm(xpd, perm, XPERMS_AUDITALLOW))
				audited = 0;
		}
	}

	*deniedp = denied;
	return audited;
}

struct avc_xperms_audit_decision {
	u32 audited;
	u32 denied;
	int result;
};

static int avc_xperms_audit_decision(
	struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
	u32 requested, const struct avc_xperms_audit_decision *decision,
	struct common_audit_data *ad)
{
	if (likely(!decision->audited))
		return 0;
	return slow_avc_audit(state, ssid, tsid, tclass, requested,
			      decision->audited, decision->denied,
			      decision->result, ad);
}

static void avc_node_free(struct rcu_head *rhead)
{
	struct avc_node *node = container_of(rhead, struct avc_node, rhead);
	struct selinux_resource_account *resources = node->resources;

	avc_xperms_free(node->ae.xp_node);
	kmem_cache_free(avc_node_cachep, node);
	selinux_resource_release(resources, SELINUX_RESOURCE_AVC, 1,
				 sizeof(*node));
	selinux_resource_account_put(resources);
	avc_cache_stats_incr(frees);
}

static void avc_node_delete(struct selinux_avc *avc, struct avc_node *node)
{
	hlist_del_rcu(&node->list);
	call_rcu(&node->rhead, avc_node_free);
	atomic_dec(&avc->avc_cache.active_nodes);
}

static void avc_node_kill(struct selinux_avc *avc, struct avc_node *node)
{
	struct selinux_resource_account *resources = node->resources;

	avc_xperms_free(node->ae.xp_node);
	kmem_cache_free(avc_node_cachep, node);
	selinux_resource_release(resources, SELINUX_RESOURCE_AVC, 1,
				 sizeof(*node));
	selinux_resource_account_put(resources);
	avc_cache_stats_incr(frees);
	atomic_dec(&avc->avc_cache.active_nodes);
}

static void avc_node_replace(struct selinux_avc *avc,
			     struct avc_node *new, struct avc_node *old)
{
	hlist_replace_rcu(&old->list, &new->list);
	call_rcu(&old->rhead, avc_node_free);
	atomic_dec(&avc->avc_cache.active_nodes);
}

static inline int avc_reclaim_node(struct selinux_avc *avc)
{
	struct avc_node *node;
	int hvalue, try, ecx;
	unsigned long flags;
	struct hlist_head *head;
	spinlock_t *lock;

	for (try = 0, ecx = 0; try < AVC_CACHE_SLOTS; try++) {
		hvalue = atomic_inc_return(&avc->avc_cache.lru_hint) &
			(AVC_CACHE_SLOTS - 1);
		head = &avc->avc_cache.slots[hvalue];
		lock = &avc->avc_cache.slots_lock[hvalue];

		if (!spin_trylock_irqsave(lock, flags))
			continue;

		rcu_read_lock();
		hlist_for_each_entry(node, head, list) {
			avc_node_delete(avc, node);
			avc_cache_stats_incr(reclaims);
			ecx++;
			if (ecx >= AVC_CACHE_RECLAIM) {
				rcu_read_unlock();
				spin_unlock_irqrestore(lock, flags);
				goto out;
			}
		}
		rcu_read_unlock();
		spin_unlock_irqrestore(lock, flags);
	}
out:
	return ecx;
}

static struct avc_node *avc_alloc_node(struct selinux_avc *avc)
{
	struct avc_node *node;
	unsigned int limit;
	int active, rc;

	limit = min_t(unsigned int, READ_ONCE(avc->avc_cache_threshold),
		      CONFIG_SECURITY_SELINUX_AVC_MAX_NODES_PER_STATE);
	if (atomic_read(&avc->avc_cache.active_nodes) >= limit)
		avc_reclaim_node(avc);
	active = atomic_read(&avc->avc_cache.active_nodes);
	for (;;) {
		if (active >= limit)
			return NULL;
		if (atomic_try_cmpxchg(&avc->avc_cache.active_nodes, &active,
				       active + 1))
			break;
	}
	rc = selinux_resource_reserve(avc->resources, SELINUX_RESOURCE_AVC, 1,
				      sizeof(*node));
	if (rc)
		goto err_active;
	node = kmem_cache_zalloc(avc_node_cachep, GFP_NOWAIT);
	if (!node)
		goto err_charge;

	INIT_HLIST_NODE(&node->list);
	node->resources = selinux_resource_account_get(avc->resources);
	avc_cache_stats_incr(allocations);
	return node;

err_charge:
	selinux_resource_release(avc->resources, SELINUX_RESOURCE_AVC, 1,
				 sizeof(*node));
err_active:
	atomic_dec(&avc->avc_cache.active_nodes);
	return NULL;
}

static void avc_node_populate(struct avc_node *node, u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
	node->ae.ssid = ssid;
	node->ae.tsid = tsid;
	node->ae.tclass = tclass;
	memcpy(&node->ae.avd, avd, sizeof(node->ae.avd));
}

static inline struct avc_node *avc_search_node(struct selinux_avc *avc,
					       u32 ssid, u32 tsid, u16 tclass)
{
	struct avc_node *node, *ret = NULL;
	u32 hvalue;
	struct hlist_head *head;

	hvalue = avc_hash(ssid, tsid, tclass);
	head = &avc->avc_cache.slots[hvalue];
	hlist_for_each_entry_rcu(node, head, list) {
		if (ssid == node->ae.ssid &&
		    tclass == node->ae.tclass &&
		    tsid == node->ae.tsid) {
			ret = node;
			break;
		}
	}

	return ret;
}

/**
 * avc_lookup - Look up an AVC entry.
 * @avc: the access vector cache
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 *
 * Look up an AVC entry that is valid for the
 * (@ssid, @tsid), interpreting the permissions
 * based on @tclass.  If a valid AVC entry exists,
 * then this function returns the avc_node.
 * Otherwise, this function returns NULL.
 */
static struct avc_node *avc_lookup(struct selinux_avc *avc,
				   u32 ssid, u32 tsid, u16 tclass)
{
	struct avc_node *node;

	avc_cache_stats_incr(lookups);
	node = avc_search_node(avc, ssid, tsid, tclass);

	if (node)
		return node;

	avc_cache_stats_incr(misses);
	return NULL;
}

static int avc_latest_notif_update(struct selinux_avc *avc,
				   u32 seqno, int is_insert)
{
	int ret = 0;
	static DEFINE_SPINLOCK(notif_lock);
	unsigned long flag;

	spin_lock_irqsave(&notif_lock, flag);
	if (is_insert) {
		if (seqno < avc->avc_cache.latest_notif) {
			pr_warn("SELinux: avc:  seqno %d < latest_notif %d\n",
			       seqno, avc->avc_cache.latest_notif);
			ret = -EAGAIN;
		}
	} else {
		if (seqno > avc->avc_cache.latest_notif)
			avc->avc_cache.latest_notif = seqno;
	}
	spin_unlock_irqrestore(&notif_lock, flag);

	return ret;
}

/**
 * avc_insert - Insert an AVC entry.
 * @avc: the access vector cache
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @avd: resulting av decision
 * @xp_node: resulting extended permissions
 *
 * Insert an AVC entry for the SID pair
 * (@ssid, @tsid) and class @tclass.
 * The access vectors and the sequence number are
 * normally provided by the security server in
 * response to a security_compute_av() call.  If the
 * sequence number @avd->seqno is not less than the latest
 * revocation notification, then the function copies
 * the access vectors into a cache entry.
 */
static void avc_insert(struct selinux_avc *avc, u32 ssid, u32 tsid, u16 tclass,
		       struct av_decision *avd, struct avc_xperms_node *xp_node)
{
	struct avc_node *pos, *node = NULL;
	u32 hvalue;
	unsigned long flag;
	spinlock_t *lock;
	struct hlist_head *head;

	if (avc_latest_notif_update(avc, avd->seqno, 1))
		return;

	node = avc_alloc_node(avc);
	if (!node)
		return;

	avc_node_populate(node, ssid, tsid, tclass, avd);
	if (avc_xperms_populate(node, xp_node)) {
		avc_node_kill(avc, node);
		return;
	}

	hvalue = avc_hash(ssid, tsid, tclass);
	head = &avc->avc_cache.slots[hvalue];
	lock = &avc->avc_cache.slots_lock[hvalue];
	spin_lock_irqsave(lock, flag);
	hlist_for_each_entry(pos, head, list) {
		if (pos->ae.ssid == ssid &&
			pos->ae.tsid == tsid &&
			pos->ae.tclass == tclass) {
			avc_node_replace(avc, node, pos);
			goto found;
		}
	}
	hlist_add_head_rcu(&node->list, head);
found:
	spin_unlock_irqrestore(lock, flag);
}

/**
 * avc_audit_pre_callback - SELinux specific information
 * will be called by generic audit code
 * @ab: the audit buffer
 * @a: audit_data
 */
static void avc_audit_pre_callback(struct audit_buffer *ab, void *a)
{
	struct common_audit_data *ad = a;
	struct selinux_audit_data *sad = ad->selinux_audit_data;
	u32 av = sad->audited, perm;
	const char *const *perms;
	u32 i;

	audit_log_format(ab, "avc:  %s ", sad->denied ? "denied" : "granted");

	if (av == 0) {
		audit_log_format(ab, " null");
		return;
	}

	perms = secclass_map[sad->tclass-1].perms;

	audit_log_format(ab, " {");
	i = 0;
	perm = 1;
	while (i < (sizeof(av) * 8)) {
		if ((perm & av) && perms[i]) {
			audit_log_format(ab, " %s", perms[i]);
			av &= ~perm;
		}
		i++;
		perm <<= 1;
	}

	if (av)
		audit_log_format(ab, " 0x%x", av);

	audit_log_format(ab, " } for ");
}

/**
 * avc_audit_post_callback - SELinux specific information
 * will be called by generic audit code
 * @ab: the audit buffer
 * @a: audit_data
 */
static void avc_audit_post_callback(struct audit_buffer *ab, void *a)
{
	struct common_audit_data *ad = a;
	struct selinux_audit_data *sad = ad->selinux_audit_data;
	const char *scontext = NULL;
	const char *tcontext = NULL;
	const char *tclass = NULL;
	u32 scontext_len;
	u32 tcontext_len;
	int rc;

	rcu_read_lock();
	rc = security_sid_to_context(sad->state, sad->ssid, &scontext,
				     &scontext_len);
	if (rc)
		audit_log_format(ab, " ssid=%d", sad->ssid);
	else
		audit_log_format(ab, " scontext=%s", scontext);

	rc = security_sid_to_context(sad->state, sad->tsid, &tcontext,
				     &tcontext_len);
	if (rc)
		audit_log_format(ab, " tsid=%d", sad->tsid);
	else
		audit_log_format(ab, " tcontext=%s", tcontext);

	tclass = secclass_map[sad->tclass-1].name;
	audit_log_format(ab, " tclass=%s", tclass);

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (sad->state && sad->state->label_domain)
		audit_log_format(ab,
				 " selinux_domain=%llu selinux_depth=%u policy_seqno=%u chain_epoch=%llu",
				 sad->state->label_domain->id,
				 sad->state->label_domain->depth,
				 avc_policy_seqno(sad->state),
				 selinux_chain_epoch_read(sad->state));
#endif

	if (sad->denied)
		audit_log_format(ab, " permissive=%u", sad->result ? 0 : 1);

	trace_selinux_audited(sad, scontext, tcontext, tclass);

	/* in case of invalid context report also the actual context string */
	rc = security_sid_to_context_inval(sad->state, sad->ssid, &scontext,
					   &scontext_len);
	if (!rc && scontext) {
		if (scontext_len && scontext[scontext_len - 1] == '\0')
			scontext_len--;
		audit_log_format(ab, " srawcon=");
		audit_log_n_untrustedstring(ab, scontext, scontext_len);
	}

	rc = security_sid_to_context_inval(sad->state, sad->tsid, &scontext,
					   &scontext_len);
	if (!rc && scontext) {
		if (scontext_len && scontext[scontext_len - 1] == '\0')
			scontext_len--;
		audit_log_format(ab, " trawcon=");
		audit_log_n_untrustedstring(ab, scontext, scontext_len);
	}
	rcu_read_unlock();
}

/*
 * This is the slow part of avc audit with big stack footprint.
 * Note that it is non-blocking and can be called from under
 * rcu_read_lock().
 */
noinline int slow_avc_audit(struct selinux_state *state,
			    u32 ssid, u32 tsid, u16 tclass,
			    u32 requested, u32 audited, u32 denied, int result,
			    struct common_audit_data *a)
{
	struct common_audit_data stack_data;
	struct selinux_audit_data sad;

	if (WARN_ON(!tclass || tclass >= ARRAY_SIZE(secclass_map)))
		return -EINVAL;

	if (!a) {
		a = &stack_data;
		a->type = LSM_AUDIT_DATA_NONE;
	}

	sad.tclass = tclass;
	sad.requested = requested;
	sad.ssid = ssid;
	sad.tsid = tsid;
	sad.audited = audited;
	sad.denied = denied;
	sad.result = result;
	sad.state = state;

	a->selinux_audit_data = &sad;

	return common_lsm_audit_status(a, avc_audit_pre_callback,
				       avc_audit_post_callback);
}

/**
 * avc_add_callback - Register a callback for security events.
 * @callback: callback function
 * @events: security events
 *
 * Register a callback function for events in the set @events.
 * Returns %0 on success or -%ENOMEM if insufficient memory
 * exists to add the callback.
 */
int __init avc_add_callback(selinux_avc_callback_t callback, u32 events)
{
	struct avc_callback_node *c;
	int rc = 0;

	c = kmalloc_obj(*c);
	if (!c) {
		rc = -ENOMEM;
		goto out;
	}

	c->callback = callback;
	c->events = events;
	c->next = avc_callbacks;
	avc_callbacks = c;
out:
	return rc;
}

/**
 * avc_update_node - Update an AVC entry
 * @avc: the access vector cache
 * @event : Updating event
 * @perms : Permission mask bits
 * @driver: xperm driver information
 * @base_perm: the base permission associated with the extended permission
 * @xperm: xperm permissions
 * @ssid: AVC entry source sid
 * @tsid: AVC entry target sid
 * @tclass : AVC entry target object class
 * @seqno : sequence number when decision was made
 * @xpd: extended_perms_decision to be added to the node
 * @flags: the AVC_* flags, e.g. AVC_EXTENDED_PERMS, or 0.
 *
 * if a valid AVC entry doesn't exist,this function returns -ENOENT.
 * if kmalloc() called internal returns NULL, this function returns -ENOMEM.
 * otherwise, this function updates the AVC entry. The original AVC-entry object
 * will release later by RCU.
 */
static int avc_update_node(struct selinux_avc *avc,
			   u32 event, u32 perms, u8 driver, u8 base_perm,
			   u8 xperm, u32 ssid,
			   u32 tsid, u16 tclass, u32 seqno,
			   struct extended_perms_decision *xpd,
			   u32 flags)
{
	u32 hvalue;
	int rc = 0;
	unsigned long flag;
	struct avc_node *pos, *node, *orig = NULL;
	struct hlist_head *head;
	spinlock_t *lock;

	node = avc_alloc_node(avc);
	if (!node) {
		rc = -ENOMEM;
		goto out;
	}

	/* Lock the target slot */
	hvalue = avc_hash(ssid, tsid, tclass);

	head = &avc->avc_cache.slots[hvalue];
	lock = &avc->avc_cache.slots_lock[hvalue];

	spin_lock_irqsave(lock, flag);

	hlist_for_each_entry(pos, head, list) {
		if (ssid == pos->ae.ssid &&
		    tsid == pos->ae.tsid &&
		    tclass == pos->ae.tclass &&
		    seqno == pos->ae.avd.seqno){
			orig = pos;
			break;
		}
	}

	if (!orig) {
		rc = -ENOENT;
		avc_node_kill(avc, node);
		goto out_unlock;
	}

	/*
	 * Copy and replace original node.
	 */

	avc_node_populate(node, ssid, tsid, tclass, &orig->ae.avd);

	if (orig->ae.xp_node) {
		rc = avc_xperms_populate(node, orig->ae.xp_node);
		if (rc) {
			avc_node_kill(avc, node);
			goto out_unlock;
		}
	}

	switch (event) {
	case AVC_CALLBACK_GRANT:
		node->ae.avd.allowed |= perms;
		if (node->ae.xp_node && (flags & AVC_EXTENDED_PERMS))
			avc_xperms_allow_perm(node->ae.xp_node, driver, base_perm, xperm);
		break;
	case AVC_CALLBACK_TRY_REVOKE:
	case AVC_CALLBACK_REVOKE:
		node->ae.avd.allowed &= ~perms;
		break;
	case AVC_CALLBACK_AUDITALLOW_ENABLE:
		node->ae.avd.auditallow |= perms;
		break;
	case AVC_CALLBACK_AUDITALLOW_DISABLE:
		node->ae.avd.auditallow &= ~perms;
		break;
	case AVC_CALLBACK_AUDITDENY_ENABLE:
		node->ae.avd.auditdeny |= perms;
		break;
	case AVC_CALLBACK_AUDITDENY_DISABLE:
		node->ae.avd.auditdeny &= ~perms;
		break;
	case AVC_CALLBACK_ADD_XPERMS:
		rc = avc_add_xperms_decision(node, xpd);
		if (rc) {
			avc_node_kill(avc, node);
			goto out_unlock;
		}
		break;
	}
	avc_node_replace(avc, node, orig);
out_unlock:
	spin_unlock_irqrestore(lock, flag);
out:
	return rc;
}

/**
 * avc_flush - Flush the cache
 * @avc: the access vector cache
 */
static void avc_flush(struct selinux_avc *avc)
{
	struct hlist_head *head;
	struct avc_node *node;
	spinlock_t *lock;
	unsigned long flag;
	int i;

	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		head = &avc->avc_cache.slots[i];
		lock = &avc->avc_cache.slots_lock[i];

		spin_lock_irqsave(lock, flag);
		/*
		 * With preemptible RCU, the outer spinlock does not
		 * prevent RCU grace periods from ending.
		 */
		rcu_read_lock();
		hlist_for_each_entry(node, head, list)
			avc_node_delete(avc, node);
		rcu_read_unlock();
		spin_unlock_irqrestore(lock, flag);
	}
}

/**
 * avc_ss_reset - Flush the cache and revalidate migrated permissions.
 * @avc: the access vector cache
 * @seqno: policy sequence number
 */
int avc_ss_reset(struct selinux_avc *avc, u32 seqno)
{
	struct avc_callback_node *c;
	int rc = 0, tmprc;

	avc_flush(avc);

	for (c = avc_callbacks; c; c = c->next) {
		if (c->events & AVC_CALLBACK_RESET) {
			tmprc = c->callback(avc, AVC_CALLBACK_RESET);
			/* save the first error encountered for the return
			   value and continue processing the callbacks */
			if (!rc)
				rc = tmprc;
		}
	}

	avc_latest_notif_update(avc, seqno, 0);
	return rc;
}

/**
 * avc_compute_av - Add an entry to the AVC based on the security policy
 * @state: SELinux state pointer
 * @ssid: subject
 * @tsid: object/target
 * @tclass: object class
 * @avd: access vector decision
 * @xp_node: AVC extended permissions node
 *
 * Slow-path helper function for avc_has_perm_noaudit, when the avc_node lookup
 * fails.  Don't inline this, since it's the slow-path and just results in a
 * bigger stack frame.
 */
static noinline void avc_compute_av(struct selinux_state *state, u32 ssid,
				    u32 tsid, u16 tclass,
				    struct av_decision *avd,
				    struct avc_xperms_node *xp_node)
{
	INIT_LIST_HEAD(&xp_node->xpd_head);
	security_compute_av(state, ssid, tsid, tclass, avd, &xp_node->xp);
	avc_insert(state->avc, ssid, tsid, tclass, avd, xp_node);
}

static noinline int avc_denied(struct selinux_state *state,
			       u32 ssid, u32 tsid,
			       u16 tclass, u32 requested,
			       u8 driver, u8 base_perm, u8 xperm,
			       unsigned int flags,
			       struct av_decision *avd)
{
	if (flags & AVC_STRICT)
		return -EACCES;

	if (enforcing_enabled(state) &&
	    !(avd->flags & AVD_FLAGS_PERMISSIVE))
		return -EACCES;

	avc_update_node(state->avc, AVC_CALLBACK_GRANT, requested, driver,
			base_perm, xperm, ssid, tsid, tclass, avd->seqno,
			NULL, flags);
	return 0;
}

/*
 * The avc extended permissions logic adds an additional 256 bits of
 * permissions to an avc node when extended permissions for that node are
 * specified in the avtab. If the additional 256 permissions is not adequate,
 * as-is the case with ioctls, then multiple may be chained together and the
 * driver field is used to specify which set contains the permission.
 */
static int avc_has_extended_perms_noaudit_internal(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot,
	u32 ssid, u32 tsid, u16 tclass, u32 requested,
	u8 driver, u8 base_perm, u8 xperm,
	struct avc_xperms_audit_decision *audit)
{
	struct avc_node *node;
	struct av_decision avd;
	u32 denied;
	struct extended_perms_decision local_xpd;
	struct extended_perms_decision *xpd = NULL;
	struct extended_perms_data allowed;
	struct extended_perms_data auditallow;
	struct extended_perms_data dontaudit;
	struct avc_xperms_node local_xp_node;
	struct avc_xperms_node *xp_node;
	int rc = 0;

	xp_node = &local_xp_node;
	if (WARN_ON(!requested))
		return -EACCES;
	if (snapshot && !selinux_policy_snapshot_valid(state, snapshot))
		return -ESTALE;

	rcu_read_lock();

	node = avc_lookup(state->avc, ssid, tsid, tclass);
	if (unlikely(!node)) {
		avc_compute_av(state, ssid, tsid, tclass, &avd, xp_node);
	} else {
		memcpy(&avd, &node->ae.avd, sizeof(avd));
		xp_node = node->ae.xp_node;
	}
	/* if extended permissions are not defined, only consider av_decision */
	if (!xp_node || !xp_node->xp.len)
		goto decision;

	local_xpd.allowed = &allowed;
	local_xpd.auditallow = &auditallow;
	local_xpd.dontaudit = &dontaudit;

	xpd = avc_xperms_decision_lookup(driver, base_perm, xp_node);
	if (unlikely(!xpd)) {
		/*
		 * Compute the extended_perms_decision only if the driver
		 * is flagged and the base permission is known.
		 */
		if (!security_xperm_test(xp_node->xp.drivers.p, driver) ||
		    !(xp_node->xp.base_perms & base_perm)) {
			avd.allowed &= ~requested;
			goto decision;
		}
		rcu_read_unlock();
		security_compute_xperms_decision(state, ssid, tsid, tclass,
						 driver, base_perm,
						 &local_xpd);
		rcu_read_lock();
		avc_update_node(state->avc, AVC_CALLBACK_ADD_XPERMS, requested,
				driver, base_perm, xperm, ssid, tsid, tclass,
				avd.seqno, &local_xpd, 0);
	} else {
		avc_quick_copy_xperms_decision(xperm, &local_xpd, xpd);
	}
	xpd = &local_xpd;

	if (!avc_xperms_has_perm(xpd, xperm, XPERMS_ALLOWED))
		avd.allowed &= ~requested;

decision:
	/*
	 * A policycap may have selected this extended-permission ABI.  Match
	 * both the policy identity and the decision generation before allowing
	 * the operation.  A caller seeing -ESTALE must reacquire the snapshot,
	 * rederive the ABI/requested permissions, and retry the whole check.
	 */
	if (snapshot &&
	    (avd.seqno != snapshot->seqno ||
	     !selinux_policy_snapshot_valid(state, snapshot))) {
		rcu_read_unlock();
		return -ESTALE;
	}

	denied = requested & ~(avd.allowed);
	if (unlikely(denied))
		rc = avc_denied(state, ssid, tsid, tclass, requested,
				driver, base_perm, xperm, AVC_EXTENDED_PERMS,
				&avd);
	if (audit) {
		audit->audited = avc_xperms_audit_required(
			requested, &avd, xpd, xperm, rc, &audit->denied);
		audit->result = rc;
	}

	rcu_read_unlock();
	return rc;
}

static int avc_has_extended_perms_internal(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot,
	u32 ssid, u32 tsid, u16 tclass, u32 requested,
	u8 driver, u8 base_perm, u8 xperm, struct common_audit_data *ad)
{
	struct avc_xperms_audit_decision decision = {};
	int rc, audit_rc;

	rc = avc_has_extended_perms_noaudit_internal(
		state, snapshot, ssid, tsid, tclass, requested, driver,
		base_perm, xperm, &decision);
	if (rc == -ESTALE)
		return rc;
	audit_rc = avc_xperms_audit_decision(state, ssid, tsid, tclass,
					       requested, &decision, ad);
	return audit_rc ? audit_rc : rc;
}

int avc_has_extended_perms(struct selinux_state *state,
			   u32 ssid, u32 tsid, u16 tclass, u32 requested,
			   u8 driver, u8 base_perm, u8 xperm,
			   struct common_audit_data *ad)
{
	return avc_has_extended_perms_internal(state, NULL, ssid, tsid, tclass,
					       requested, driver, base_perm,
					       xperm, ad);
}

int avc_has_extended_perms_snapshot(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot,
	u32 ssid, u32 tsid, u16 tclass, u32 requested,
	u8 driver, u8 base_perm, u8 xperm, struct common_audit_data *ad)
{
	if (WARN_ON_ONCE(!snapshot))
		return -EINVAL;
	return avc_has_extended_perms_internal(state, snapshot, ssid, tsid,
					       tclass, requested, driver,
					       base_perm, xperm, ad);
}

/**
 * avc_perm_nonode - Add an entry to the AVC
 * @state: SELinux state pointer
 * @ssid: subject
 * @tsid: object/target
 * @tclass: object class
 * @requested: requested permissions
 * @flags: AVC flags
 * @avd: access vector decision
 *
 * This is the "we have no node" part of avc_has_perm_noaudit(), which is
 * unlikely and needs extra stack space for the new node that we generate, so
 * don't inline it.
 */
static noinline int avc_perm_nonode(struct selinux_state *state,
				    u32 ssid, u32 tsid, u16 tclass,
				    u32 requested, unsigned int flags,
				    struct av_decision *avd)
{
	u32 denied;
	struct avc_xperms_node xp_node;

	avc_compute_av(state, ssid, tsid, tclass, avd, &xp_node);
	denied = requested & ~(avd->allowed);
	if (unlikely(denied))
		return avc_denied(state, ssid, tsid, tclass, requested, 0, 0,
				  0, flags, avd);
	return 0;
}

/**
 * avc_has_perm_noaudit - Check permissions but perform no auditing.
 * @state: SELinux state
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @flags:  AVC_STRICT or 0
 * @avd: access vector decisions
 *
 * Check the AVC to determine whether the @requested permissions are granted
 * for the SID pair (@ssid, @tsid), interpreting the permissions
 * based on @tclass, and call the security server on a cache miss to obtain
 * a new decision and add it to the cache.  Return a copy of the decisions
 * in @avd.  Return %0 if all @requested permissions are granted,
 * -%EACCES if any permissions are denied, or another -errno upon
 * other errors.  This function is typically called by avc_has_perm(),
 * but may also be called directly to separate permission checking from
 * auditing, e.g. in cases where a lock must be held for the check but
 * should be released for the auditing.
 */
inline int avc_has_perm_noaudit(struct selinux_state *state,
				u32 ssid, u32 tsid,
				u16 tclass, u32 requested,
				unsigned int flags,
				struct av_decision *avd)
{
	u32 denied;
	struct avc_node *node;

	if (WARN_ON(!requested))
		return -EACCES;

	rcu_read_lock();
	node = avc_lookup(state->avc, ssid, tsid, tclass);
	if (unlikely(!node)) {
		rcu_read_unlock();
		return avc_perm_nonode(state, ssid, tsid, tclass, requested,
				       flags, avd);
	}
	denied = requested & ~node->ae.avd.allowed;
	memcpy(avd, &node->ae.avd, sizeof(*avd));
	rcu_read_unlock();

	if (unlikely(denied))
		return avc_denied(state, ssid, tsid, tclass, requested, 0, 0,
				  0, flags, avd);
	return 0;
}

/**
 * avc_has_perm - Check permissions and perform any appropriate auditing.
 * @state: SELinux state
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @auditdata: auxiliary audit data
 *
 * Check the AVC to determine whether the @requested permissions are granted
 * for the SID pair (@ssid, @tsid), interpreting the permissions
 * based on @tclass, and call the security server on a cache miss to obtain
 * a new decision and add it to the cache.  Audit the granting or denial of
 * permissions in accordance with the policy.  Return %0 if all @requested
 * permissions are granted, -%EACCES if any permissions are denied, or
 * another -errno upon other errors.
 */
int avc_has_perm(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
		 u32 requested, struct common_audit_data *auditdata)
{
	struct av_decision avd;
	int rc, rc2;

	rc = avc_has_perm_noaudit(state, ssid, tsid, tclass, requested, 0,
				  &avd);

	rc2 = avc_audit(state, ssid, tsid, tclass, requested, &avd, rc,
			auditdata);
	if (rc2)
		return rc2;
	return rc;
}

/**
 * avc_has_perm_snapshot - Check permissions against a policycap snapshot
 * @state: SELinux state
 * @snapshot: policy identity, capability bitmap, and generation
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class selected from @snapshot
 * @requested: permissions selected from @snapshot
 * @auditdata: auxiliary audit data
 *
 * Return -ESTALE without authorizing if policy publication raced capability,
 * class, or permission selection.  The caller must reacquire a snapshot,
 * rederive all policycap-dependent inputs, and retry the whole operation.
 * A non--ESTALE result is linearizable because the decision seqno and the
 * RCU-published policy identity were both equal to @snapshot after the AVC
 * lookup/computation and before auditing/returning the decision.
 */
int avc_has_perm_snapshot(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot,
	u32 ssid, u32 tsid, u16 tclass, u32 requested,
	struct common_audit_data *auditdata)
{
	struct av_decision avd;
	int rc, rc2;

	if (WARN_ON_ONCE(!snapshot))
		return -EINVAL;
	if (WARN_ON(!requested))
		return -EACCES;
	if (!selinux_policy_snapshot_valid(state, snapshot))
		return -ESTALE;

	rc = avc_has_perm_noaudit(state, ssid, tsid, tclass, requested, 0,
				  &avd);
	if (avd.seqno != snapshot->seqno ||
	    !selinux_policy_snapshot_valid(state, snapshot))
		return -ESTALE;

	rc2 = avc_audit(state, ssid, tsid, tclass, requested, &avd, rc,
			auditdata);
	if (rc2)
		return rc2;
	return rc;
}

#ifndef CONFIG_SECURITY_SELINUX_NS
static u32 task_sid_obj_for_state(const struct task_struct *p,
				  const struct selinux_state *state)
{
	const struct cred_security_struct *crsec;
	u32 sid;

	rcu_read_lock();
	crsec = selinux_cred(__task_cred(p));
	while (crsec->state != state && crsec->parent_cred)
		crsec = selinux_cred(crsec->parent_cred);
	if (crsec->state == state)
		sid = crsec->sid;
	else
		sid = SECINITSID_UNLABELED;
	rcu_read_unlock();
	return sid;
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
#define SELINUX_AVC_CHAIN_RETRIES 3

enum selinux_avc_audit_check_kind {
	SELINUX_AVC_AUDIT_CHECK_AVC = 1,
	SELINUX_AVC_AUDIT_CHECK_VALIDATETRANS,
};

enum selinux_avc_transaction_allocation_stage {
	SELINUX_AVC_TRANSACTION_ALLOC_NONE,
	SELINUX_AVC_TRANSACTION_ALLOC_AVC_WORK,
	SELINUX_AVC_TRANSACTION_ALLOC_VALIDATETRANS_WORK,
	SELINUX_AVC_TRANSACTION_ALLOC_AGGREGATE,
};

struct selinux_avc_audit_level {
	u64 namespace_id;
	u64 domain_id;
	u64 policy_seqno;
	u64 chain_epoch;
	u64 canonical_label_id;
	u64 canonical_domain_id;
	u64 view_id;
	u64 view_generation;
	u64 map_generation;
	union {
		struct {
			u32 ssid;
			u32 tsid;
			u32 requested;
			u32 denied;
			u16 tclass;
			u8 decision_kind;
			u8 driver;
			u8 base_perm;
			u8 xperm;
		} avc;
		struct {
			u32 oldsid;
			u32 newsid;
			u32 tasksid;
			u16 tclass;
			u8 enforcing;
		} validatetrans;
	};
	u8 kind;
	u8 source;
};

struct selinux_avc_aggregate_audit {
	u16 count;
	struct selinux_avc_audit_level level[];
};

struct selinux_avc_audit_work {
	struct selinux_avc_level levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct selinux_avc_provenance
		provenance[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct selinux_policy_snapshot
		snapshots[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct av_decision decisions[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct avc_xperms_audit_decision
		xdecisions[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	int results[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
};

struct selinux_avc_transaction_workspace {
	u16 capacity;
	struct selinux_avc_level *effective;
	struct av_decision *decisions;
	struct avc_xperms_audit_decision *xdecisions;
	int *results;
	enum selinux_validatetrans_decision *validatetrans_decisions;
	u8 data[] __aligned(__alignof__(struct selinux_avc_level));
};

static int selinux_avc_xperm_decide(
	struct selinux_avc_level *level,
	const struct selinux_policy_snapshot *snapshot, u16 index, u8 driver,
	u8 base_perm, u8 xperm, struct avc_xperms_audit_decision *decision);
static int selinux_avc_xperm_audit(
	struct selinux_avc_level *level,
	const struct avc_xperms_audit_decision *decision,
	struct common_audit_data *ad);

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
static bool selinux_kunit_avc_workspace_alloc_fail(void);
#endif

static bool selinux_avc_workspace_add_size(size_t *bytes, size_t count,
					   size_t element_size,
					   size_t alignment)
{
	size_t part;

	*bytes = ALIGN(*bytes, alignment);
	return check_mul_overflow(count, element_size, &part) ||
	       check_add_overflow(*bytes, part, bytes);
}

struct selinux_avc_transaction_workspace *
selinux_avc_transaction_workspace_alloc(u16 capacity, gfp_t gfp)
{
	struct selinux_avc_transaction_workspace *workspace;
	size_t bytes = sizeof(*workspace);
	u8 *cursor;

	if (!capacity)
		return NULL;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_avc_workspace_alloc_fail()))
		return NULL;
#endif
	if (selinux_avc_workspace_add_size(
		    &bytes, capacity, sizeof(struct selinux_avc_level),
		    __alignof__(struct selinux_avc_level)) ||
	    selinux_avc_workspace_add_size(
		    &bytes, capacity, sizeof(struct av_decision),
		    __alignof__(struct av_decision)) ||
	    selinux_avc_workspace_add_size(
		    &bytes, capacity, sizeof(struct avc_xperms_audit_decision),
		    __alignof__(struct avc_xperms_audit_decision)) ||
	    selinux_avc_workspace_add_size(&bytes, capacity, sizeof(int),
					   __alignof__(int)) ||
	    selinux_avc_workspace_add_size(
		    &bytes, capacity,
		    sizeof(enum selinux_validatetrans_decision),
		    __alignof__(enum selinux_validatetrans_decision)))
		return NULL;

	workspace = kvzalloc(bytes, gfp);
	if (!workspace)
		return NULL;
	workspace->capacity = capacity;
	cursor = workspace->data;
#define SELINUX_AVC_WORKSPACE_SET(_member, _type)                     \
	do {                                                           \
		cursor = PTR_ALIGN(cursor, __alignof__(_type));           \
		workspace->_member = (_type *)cursor;                     \
		cursor += array_size((size_t)capacity, sizeof(_type));     \
	} while (0)
	SELINUX_AVC_WORKSPACE_SET(effective, struct selinux_avc_level);
	SELINUX_AVC_WORKSPACE_SET(decisions, struct av_decision);
	SELINUX_AVC_WORKSPACE_SET(xdecisions,
				  struct avc_xperms_audit_decision);
	SELINUX_AVC_WORKSPACE_SET(results, int);
	SELINUX_AVC_WORKSPACE_SET(validatetrans_decisions,
				  enum selinux_validatetrans_decision);
#undef SELINUX_AVC_WORKSPACE_SET
	return workspace;
}

void selinux_avc_transaction_workspace_free(
	struct selinux_avc_transaction_workspace *workspace)
{
	kvfree(workspace);
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
static int selinux_kunit_host_audit_rc;
static u16 selinux_kunit_host_audit_denials;
static u64 selinux_kunit_host_audit_namespace_id;

#define SELINUX_KUNIT_XPERM_LEVELS 3
#define SELINUX_KUNIT_AVC_FAULT_LEVELS SELINUX_AVC_TRANSACTION_MAX_CHECKS
struct selinux_kunit_xperm_fault {
	struct task_struct *owner;
	unsigned long policycaps[SELINUX_KUNIT_AVC_FAULT_LEVELS];
	u16 evaluations[SELINUX_KUNIT_AVC_FAULT_LEVELS];
	u16 attempts;
	u16 ordinary_audits;
	u16 aggregate_calls;
	u16 aggregate_denials;
	u16 aggregate_avc_denials;
	u16 aggregate_validatetrans_denials;
	u16 aggregate_permissive_validatetrans_denials;
	u16 ordinary_evaluations;
	u16 xperm_evaluations;
	u16 workspace_allocations;
	u8 aggregate_decision_kind;
	u8 aggregate_driver;
	u8 aggregate_base_perm;
	u8 aggregate_xperm;
	u16 validatetrans_evaluations[
		SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS];
	u32 aggregate_validatetrans_oldsids[
		SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS];
	u32 first_validatetrans_oldsid;
	u32 first_validatetrans_newsid;
	u32 first_validatetrans_tasksid;
	u16 first_validatetrans_tclass;
	DECLARE_BITMAP(deny_levels, SELINUX_KUNIT_AVC_FAULT_LEVELS);
	DECLARE_BITMAP(validatetrans_enforcing_levels,
		       SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS);
	DECLARE_BITMAP(validatetrans_permissive_levels,
		       SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS);
	s16 stale_level;
	s16 stale_validatetrans_level;
	int aggregate_rc;
	u8 allocation_fail_stage;
	bool stale_injected;
	bool stale_validatetrans_injected;
	bool active;
};

static struct selinux_kunit_xperm_fault selinux_kunit_xperm_fault;
static DEFINE_MUTEX(selinux_kunit_xperm_lock);

static bool selinux_kunit_xperm_fault_active(void)
{
	return READ_ONCE(selinux_kunit_xperm_fault.active) &&
	       READ_ONCE(selinux_kunit_xperm_fault.owner) == current;
}

static bool selinux_kunit_avc_workspace_alloc_fail(void)
{
	u8 stage;

	if (!selinux_kunit_xperm_fault_active())
		return false;
	selinux_kunit_xperm_fault.workspace_allocations++;
	stage = READ_ONCE(selinux_kunit_xperm_fault.allocation_fail_stage);
	if (stage != SELINUX_AVC_TRANSACTION_ALLOC_AVC_WORK &&
	    stage != SELINUX_AVC_TRANSACTION_ALLOC_VALIDATETRANS_WORK)
		return false;
	WRITE_ONCE(selinux_kunit_xperm_fault.allocation_fail_stage,
		   SELINUX_AVC_TRANSACTION_ALLOC_NONE);
	return true;
}

static int selinux_kunit_host_audit_emit(
	struct common_audit_data *ad,
	void (*pre_audit)(struct audit_buffer *, void *),
	void (*post_audit)(struct audit_buffer *, void *))
{
	struct selinux_avc_aggregate_audit *aggregate =
		(void *)ad->selinux_audit_data;

	selinux_kunit_host_audit_denials = aggregate->count;
	selinux_kunit_host_audit_namespace_id = aggregate->level[0].namespace_id;
	return selinux_kunit_host_audit_rc;
}
#endif

static int selinux_avc_host_audit_emit(
	struct common_audit_data *ad,
	void (*pre_audit)(struct audit_buffer *, void *),
	void (*post_audit)(struct audit_buffer *, void *))
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_xperm_fault_active())) {
		struct selinux_avc_aggregate_audit *aggregate =
			(void *)ad->selinux_audit_data;
		u16 i, validatetrans_index;

		selinux_kunit_xperm_fault.aggregate_calls++;
		selinux_kunit_xperm_fault.aggregate_denials = aggregate->count;
		for (i = 0; i < aggregate->count; i++) {
			const struct selinux_avc_audit_level *level =
				&aggregate->level[i];

			if (level->kind == SELINUX_AVC_AUDIT_CHECK_AVC) {
				selinux_kunit_xperm_fault.aggregate_avc_denials++;
				if (!selinux_kunit_xperm_fault.aggregate_decision_kind) {
					selinux_kunit_xperm_fault
						.aggregate_decision_kind =
						level->avc.decision_kind;
					selinux_kunit_xperm_fault.aggregate_driver =
						level->avc.driver;
					selinux_kunit_xperm_fault.aggregate_base_perm =
						level->avc.base_perm;
					selinux_kunit_xperm_fault.aggregate_xperm =
						level->avc.xperm;
				}
				continue;
			}
			if (level->kind !=
			    SELINUX_AVC_AUDIT_CHECK_VALIDATETRANS)
				continue;
			validatetrans_index = selinux_kunit_xperm_fault
						      .aggregate_validatetrans_denials;
			if (validatetrans_index <
			    SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS)
				selinux_kunit_xperm_fault
					.aggregate_validatetrans_oldsids[
						validatetrans_index] =
					level->validatetrans.oldsid;
			selinux_kunit_xperm_fault.aggregate_validatetrans_denials++;
			if (!level->validatetrans.enforcing)
				selinux_kunit_xperm_fault
					.aggregate_permissive_validatetrans_denials++;
			if (selinux_kunit_xperm_fault.first_validatetrans_tclass)
				continue;
			selinux_kunit_xperm_fault.first_validatetrans_oldsid =
				level->validatetrans.oldsid;
			selinux_kunit_xperm_fault.first_validatetrans_newsid =
				level->validatetrans.newsid;
			selinux_kunit_xperm_fault.first_validatetrans_tasksid =
				level->validatetrans.tasksid;
			selinux_kunit_xperm_fault.first_validatetrans_tclass =
				level->validatetrans.tclass;
		}
		return selinux_kunit_xperm_fault.aggregate_rc;
	}
	if (unlikely(READ_ONCE(selinux_kunit_host_audit_rc)))
		return selinux_kunit_host_audit_emit(ad, pre_audit, post_audit);
#endif
	return common_lsm_audit_status(ad, pre_audit, post_audit);
}

static void selinux_avc_aggregate_pre(struct audit_buffer *ab, void *data)
{
	struct common_audit_data *ad = data;
	struct selinux_avc_aggregate_audit *aggregate =
		(void *)ad->selinux_audit_data;
	u16 i;

	audit_log_format(ab, "avc: denied host_aggregate=1 denials=%u for ",
			 aggregate->count);
	for (i = 0; i < aggregate->count; i++) {
		const struct selinux_avc_audit_level *level =
			&aggregate->level[i];

		audit_log_format(ab,
			 " level=%u ns=%llu domain=%llu policy_seqno=%llu chain_epoch=%llu",
			 i, level->namespace_id, level->domain_id,
			 level->policy_seqno, level->chain_epoch);
		if (level->kind == SELINUX_AVC_AUDIT_CHECK_AVC)
			audit_log_format(
				ab,
				" kind=avc ssid=%u tsid=%u tclass=%u requested=0x%x denied=0x%x decision=%u driver=%u base_perm=0x%x xperm=%u",
				level->avc.ssid, level->avc.tsid,
				level->avc.tclass, level->avc.requested,
				level->avc.denied, level->avc.decision_kind,
				level->avc.driver, level->avc.base_perm,
				level->avc.xperm);
		else
			audit_log_format(
				ab,
				" kind=validatetrans oldsid=%u newsid=%u tasksid=%u tclass=%u enforcing=%u",
				level->validatetrans.oldsid,
				level->validatetrans.newsid,
				level->validatetrans.tasksid,
				level->validatetrans.tclass,
				level->validatetrans.enforcing);
		audit_log_format(ab,
			 " canonical_label=%llu canonical_domain=%llu source=%u view=%llu view_generation=%llu map_generation=%llu",
			 level->canonical_label_id,
			 level->canonical_domain_id, level->source,
			 level->view_id, level->view_generation,
			 level->map_generation);
	}
}

static void *selinux_avc_transaction_calloc(size_t count, size_t size,
					    u8 allocation_stage)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_xperm_fault_active()) &&
	    READ_ONCE(selinux_kunit_xperm_fault.allocation_fail_stage) ==
		    allocation_stage) {
		WRITE_ONCE(selinux_kunit_xperm_fault.allocation_fail_stage,
			   SELINUX_AVC_TRANSACTION_ALLOC_NONE);
		return NULL;
	}
#endif
	return kcalloc(count, size, GFP_ATOMIC | __GFP_NOWARN);
}

static void selinux_avc_audit_level_identity(
	struct selinux_avc_audit_level *audit_level,
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot,
	const struct selinux_avc_provenance *provenance)
{
	u16 depth;

	if (state->ns_control)
		audit_level->namespace_id = state->ns_control->ns.ns_id;
	audit_level->domain_id = state->label_domain->id;
	audit_level->policy_seqno = snapshot->seqno;
	audit_level->chain_epoch = snapshot->chain_epoch;
	if (!provenance || !provenance->label || !provenance->view)
		return;
	audit_level->canonical_label_id = provenance->label->id;
	audit_level->canonical_domain_id = provenance->label->domain->id;
	audit_level->source = provenance->source;
	audit_level->view_id = provenance->view->id;
	audit_level->view_generation = provenance->view->generation;
	if (provenance->map_generation) {
		audit_level->map_generation = provenance->map_generation;
		return;
	}
	depth = state->label_domain->depth;
	if (depth && depth <= provenance->view->map_count &&
	    provenance->view->maps[depth - 1])
		audit_level->map_generation =
			provenance->view->maps[depth - 1]->generation;
}

static int selinux_avc_host_aggregate_composite(
	const struct selinux_avc_level *levels,
	const struct selinux_policy_snapshot *snapshots,
	const struct av_decision *decisions, u16 count,
	const struct selinux_validatetrans_level *validatetrans,
	const struct selinux_policy_snapshot *validatetrans_snapshots,
	const enum selinux_validatetrans_decision *validatetrans_decisions,
	u16 validatetrans_count,
	struct common_audit_data *ad)
{
	struct selinux_avc_aggregate_audit *aggregate;
	struct selinux_audit_reservation reservation = {};
	struct common_audit_data stack_ad = { .type = LSM_AUDIT_DATA_NONE };
	struct selinux_state *host_state;
	struct selinux_audit_data *saved_selinux_data;
	size_t bytes;
	u16 avc_denial_count = 0, validatetrans_denial_count = 0;
	u16 denial_count, i, out = 0;
	int rc;

	for (i = 0; i < count; i++)
		if (levels[i].requested & ~decisions[i].allowed)
			avc_denial_count++;
	for (i = 0; i < validatetrans_count; i++)
		if (selinux_validatetrans_denied(validatetrans_decisions[i]))
			validatetrans_denial_count++;
	if (check_add_overflow(avc_denial_count, validatetrans_denial_count,
			       &denial_count))
		return -EOVERFLOW;
	if (!denial_count)
		return 0;
	host_state = validatetrans_count ?
		validatetrans[validatetrans_count - 1].state :
		levels[count - 1].state;
	if (!host_state || !host_state->label_domain ||
	    !host_state->label_domain->resources)
		return -EOPNOTSUPP;
	bytes = struct_size(aggregate, level, denial_count);
	if (bytes == SIZE_MAX)
		return -EOVERFLOW;
	rc = selinux_audit_reserve(host_state->label_domain->resources, bytes,
				   &reservation);
	if (rc)
		return rc;
	aggregate = selinux_avc_transaction_calloc(
		1, bytes, SELINUX_AVC_TRANSACTION_ALLOC_AGGREGATE);
	if (!aggregate) {
		rc = -ENOMEM;
		goto out_release;
	}
	aggregate->count = denial_count;
	for (i = 0; i < count; i++) {
		struct selinux_state *state = levels[i].state;
		struct selinux_avc_audit_level *audit_level;
		const struct selinux_avc_provenance *provenance =
			levels[i].provenance;
		u32 denied = levels[i].requested & ~decisions[i].allowed;

		if (!denied)
			continue;
		audit_level = &aggregate->level[out++];
		audit_level->kind = SELINUX_AVC_AUDIT_CHECK_AVC;
		audit_level->avc.ssid = levels[i].ssid;
		audit_level->avc.tsid = levels[i].tsid;
		audit_level->avc.tclass = levels[i].tclass;
		audit_level->avc.requested = levels[i].requested;
		audit_level->avc.denied = denied;
		audit_level->avc.decision_kind = levels[i].decision_kind;
		audit_level->avc.driver = levels[i].driver;
		audit_level->avc.base_perm = levels[i].base_perm;
		audit_level->avc.xperm = levels[i].xperm;
		selinux_avc_audit_level_identity(audit_level, state, &snapshots[i],
					       provenance);
	}
	for (i = 0; i < validatetrans_count; i++) {
		const struct selinux_validatetrans_level *level =
			&validatetrans[i];
		struct selinux_avc_audit_level *audit_level;

		if (!selinux_validatetrans_denied(validatetrans_decisions[i]))
			continue;
		audit_level = &aggregate->level[out++];
		audit_level->kind = SELINUX_AVC_AUDIT_CHECK_VALIDATETRANS;
		audit_level->validatetrans.oldsid = level->oldsid;
		audit_level->validatetrans.newsid = level->newsid;
		audit_level->validatetrans.tasksid = level->tasksid;
		audit_level->validatetrans.tclass = level->tclass;
		audit_level->validatetrans.enforcing =
			validatetrans_decisions[i] ==
			SELINUX_VALIDATETRANS_DENIED_ENFORCING;
		selinux_avc_audit_level_identity(
			audit_level, level->state, &validatetrans_snapshots[i],
			level->provenance);
	}
	if (!ad)
		ad = &stack_ad;
	saved_selinux_data = ad->selinux_audit_data;
	ad->selinux_audit_data = (void *)aggregate;
	rc = selinux_avc_host_audit_emit(ad, selinux_avc_aggregate_pre, NULL);
	ad->selinux_audit_data = saved_selinux_data;
	kfree(aggregate);
out_release:
	selinux_audit_release(&reservation);
	return rc;
}

static int selinux_avc_host_aggregate(
	const struct selinux_avc_level *levels,
	const struct selinux_policy_snapshot *snapshots,
	const struct av_decision *decisions, u16 count,
	struct common_audit_data *ad)
{
	return selinux_avc_host_aggregate_composite(
		levels, snapshots, decisions, count, NULL, NULL, NULL, 0, ad);
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
int selinux_kunit_avc_host_aggregate(bool child_dontaudit, int emit_rc,
				     u16 *denial_count, u64 *namespace_id)
{
	struct selinux_avc_level levels[2] = {};
	struct selinux_policy_snapshot snapshots[2] = {};
	struct av_decision decisions[2] = {};
	int rc;

	if (!current_selinux_state || !current_selinux_state->label_domain ||
	    !denial_count || !namespace_id)
		return -EINVAL;
	levels[0].state = current_selinux_state;
	levels[0].ssid = SECINITSID_KERNEL;
	levels[0].tsid = SECINITSID_UNLABELED;
	levels[0].tclass = SECCLASS_FILE;
	levels[0].requested = FILE__READ;
	levels[1] = levels[0];
	snapshots[0].seqno = 11;
	snapshots[0].chain_epoch = 21;
	snapshots[1].seqno = 12;
	snapshots[1].chain_epoch = 22;
	decisions[0].allowed = 0;
	decisions[0].auditdeny = child_dontaudit ? 0 : FILE__READ;
	decisions[1].allowed = FILE__READ;
	selinux_kunit_host_audit_denials = 0;
	selinux_kunit_host_audit_namespace_id = 0;
	selinux_kunit_host_audit_rc = emit_rc ? emit_rc : -ECANCELED;
	rc = selinux_avc_host_aggregate(levels, snapshots, decisions,
					2, NULL);
	*denial_count = selinux_kunit_host_audit_denials;
	*namespace_id = selinux_kunit_host_audit_namespace_id;
	selinux_kunit_host_audit_rc = 0;
	if (!emit_rc && rc == -ECANCELED)
		rc = 0;
	return rc;
}
#endif

static void selinux_avc_level_set_provenance(
	struct selinux_avc_level *level, struct selinux_avc_provenance *provenance,
	const struct selinux_label_ref *label,
	const struct selinux_label_view *view, u8 source)
{
	if (!label || !view)
		return;
	provenance->label = label;
	provenance->view = view;
	provenance->source = source;
	level->provenance = provenance;
}

static bool selinux_avc_levels_denied(const struct selinux_avc_level *levels,
				      const struct av_decision *decisions,
				      u16 count)
{
	u16 i;

	for (i = 0; i < count; i++)
		if (levels[i].requested & ~decisions[i].allowed)
			return true;
	return false;
}

static u32 selinux_avc_level_effective_requested(
	const struct selinux_avc_level *level,
	const struct selinux_policy_snapshot *snapshot)
{
	u32 requested = level->requested;

	if (level->skip_policycap &&
	    selinux_policy_snapshot_has_cap(snapshot, level->skip_policycap))
		return 0;
	if (level->policycap_requested &&
	    selinux_policy_snapshot_has_cap(snapshot, level->policycap))
		requested |= level->policycap_requested;
	return requested;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
u32 selinux_kunit_avc_effective_requested(
	unsigned long policycaps, u32 requested, u32 policycap_requested,
	u16 policycap, u16 skip_policycap)
{
	struct selinux_policy_snapshot snapshot = { .policycaps = policycaps };
	struct selinux_avc_level level = {
		.requested = requested,
		.policycap_requested = policycap_requested,
		.policycap = policycap,
		.skip_policycap = skip_policycap,
	};

	return selinux_avc_level_effective_requested(&level, &snapshot);
}
#endif

static int selinux_avc_perm_snapshot_read(
	struct selinux_state *state, struct selinux_policy_snapshot *snapshot,
	u16 level)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_xperm_fault_active())) {
		memset(snapshot, 0, sizeof(*snapshot));
		if (!level)
			selinux_kunit_xperm_fault.attempts++;
		snapshot->seqno = 100 + selinux_kunit_xperm_fault.attempts;
		snapshot->chain_epoch = 200;
		return 0;
	}
#endif
	return selinux_policy_snapshot_read(state, snapshot);
}

static bool selinux_avc_perm_snapshot_valid(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_xperm_fault_active()))
		return true;
#endif
	return selinux_policy_snapshot_valid(state, snapshot);
}

static int selinux_avc_perm_decide(
	struct selinux_avc_level *level,
	const struct selinux_policy_snapshot *snapshot, u16 index,
	struct av_decision *decision)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_xperm_fault_active())) {
		memset(decision, 0, sizeof(*decision));
		selinux_kunit_xperm_fault.evaluations[index]++;
		selinux_kunit_xperm_fault.ordinary_evaluations++;
		if (!selinux_kunit_xperm_fault.stale_injected &&
		    selinux_kunit_xperm_fault.stale_level == index) {
			selinux_kunit_xperm_fault.stale_injected = true;
			return -ESTALE;
		}
		decision->seqno = snapshot->seqno;
		if (test_bit(index, selinux_kunit_xperm_fault.deny_levels)) {
			decision->auditdeny = level->requested;
			return -EACCES;
		}
		decision->allowed = level->requested;
		decision->auditallow = level->requested;
		return 0;
	}
#endif
	return avc_has_perm_noaudit(level->state, level->ssid, level->tsid,
				    level->tclass, level->requested, 0,
				    decision);
}

static int selinux_avc_perm_audit(
	struct selinux_avc_level *level, const struct av_decision *decision,
	int result, struct common_audit_data *ad)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_xperm_fault_active())) {
		selinux_kunit_xperm_fault.ordinary_audits++;
		return 0;
	}
#endif
	return avc_audit(level->state, level->ssid, level->tsid, level->tclass,
			 level->requested, decision, result, ad);
}

static int selinux_validatetrans_decide(
	const struct selinux_validatetrans_level *level,
	const struct selinux_policy_snapshot *snapshot, u16 index,
	enum selinux_validatetrans_decision *decision)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_xperm_fault_active())) {
		selinux_kunit_xperm_fault.validatetrans_evaluations[index]++;
		if (!selinux_kunit_xperm_fault.stale_validatetrans_injected &&
		    selinux_kunit_xperm_fault.stale_validatetrans_level == index) {
			selinux_kunit_xperm_fault.stale_validatetrans_injected = true;
			return -ESTALE;
		}
		if (test_bit(index, selinux_kunit_xperm_fault
					    .validatetrans_enforcing_levels))
			*decision = SELINUX_VALIDATETRANS_DENIED_ENFORCING;
		else if (test_bit(index, selinux_kunit_xperm_fault
						 .validatetrans_permissive_levels))
			*decision = SELINUX_VALIDATETRANS_DENIED_PERMISSIVE;
		else
			*decision = SELINUX_VALIDATETRANS_ALLOWED;
		return 0;
	}
#endif
	return security_validate_transition_snapshot_noaudit(
		level->state, snapshot, level->oldsid, level->newsid,
		level->tasksid, level->tclass, decision);
}

/*
 * Preflight an already-snapshotted AVC vector without emitting audit records.
 * A permissive denial returns success, matching avc_has_perm_noaudit(); an
 * enforcing denial may be translated to the caller-selected denial_errno.
 */
int selinux_avc_transaction_has_perm_noaudit(
	const struct selinux_avc_level *levels,
	const struct selinux_policy_snapshot *snapshots, u16 count)
{
	int first_rc = 0;
	u16 i;

	if (!levels || !snapshots || !count ||
	    count > SELINUX_AVC_TRANSACTION_MAX_CHECKS)
		return -EINVAL;
	for (i = 0; i < count; i++) {
		struct selinux_avc_level effective = levels[i];
		struct av_decision decision = {};
		int rc;

		if (!effective.state || effective.denial_errno > 0)
			return -EINVAL;
		if (!effective.state->label_domain)
			return -EOPNOTSUPP;
		if (!selinux_avc_perm_snapshot_valid(effective.state,
						    &snapshots[i]))
			return -ESTALE;
		effective.requested = selinux_avc_level_effective_requested(
			&effective, &snapshots[i]);
		if (!effective.requested)
			continue;
		rc = selinux_avc_perm_decide(&effective, &snapshots[i], i,
					     &decision);
		if (rc == -ESTALE || decision.seqno != snapshots[i].seqno ||
		    !selinux_avc_perm_snapshot_valid(effective.state,
						    &snapshots[i]))
			return -ESTALE;
		if (rc && rc != -EACCES)
			return rc;
		if (rc == -EACCES && effective.denial_errno)
			rc = effective.denial_errno;
		if (rc && !first_rc)
			first_rc = rc;
	}
	for (i = 0; i < count; i++)
		if (!selinux_avc_perm_snapshot_valid(levels[i].state,
						     &snapshots[i]))
			return -ESTALE;
	return first_rc;
}

static bool selinux_validatetrans_levels_denied(
	const enum selinux_validatetrans_decision *decisions, u16 count)
{
	u16 i;

	for (i = 0; i < count; i++)
		if (selinux_validatetrans_denied(decisions[i]))
			return true;
	return false;
}

/*
 * Evaluate one already-snapshotted composite authorization transaction.  The
 * caller owns retry and must rebuild every policy-derived input after
 * -ESTALE.  No audit is emitted until every decision and every supplied
 * snapshot has been validated, so a denial at a deeper policy cannot suppress
 * a host denial.
 */
noinline int selinux_avc_transaction_has_perm_composite_guarded_workspace(
	const struct selinux_avc_level *levels,
	const struct selinux_policy_snapshot *snapshots, u16 count,
	const struct selinux_validatetrans_level *validatetrans,
	const struct selinux_policy_snapshot *validatetrans_snapshots,
	u16 validatetrans_count, int guard_result, struct common_audit_data *ad,
	struct selinux_avc_transaction_workspace *workspace)
{
	struct selinux_avc_level *effective;
	struct av_decision *decisions;
	struct avc_xperms_audit_decision *xdecisions;
	enum selinux_validatetrans_decision *validatetrans_decisions;
	int *results;
	u16 total_count;
	/* Typed guards/translated denials deterministically outrank -EACCES. */
	int access_rc = 0, typed_rc = 0;
	u16 i;

	if (guard_result > 0 || (!count && !validatetrans_count) ||
	    (count && (!levels || !snapshots)) ||
	    (validatetrans_count &&
	     (!validatetrans || !validatetrans_snapshots)))
		return -EINVAL;
	if (validatetrans_count > SELINUX_AVC_TRANSACTION_MAX_CHECKS ||
	    check_add_overflow(count, validatetrans_count, &total_count) ||
	    !workspace || total_count > workspace->capacity)
		return -E2BIG;
	for (i = 0; i < count; i++) {
		if (!levels[i].state)
			return -EINVAL;
		if (levels[i].denial_errno > 0)
			return -EINVAL;
		if (levels[i].decision_kind > SELINUX_AVC_DECISION_GUARD ||
		    levels[i].guard_result > 0 ||
		    (levels[i].decision_kind == SELINUX_AVC_DECISION_GUARD &&
		     (levels[i].requested || levels[i].denial_errno)))
			return -EINVAL;
		if (!levels[i].state->label_domain)
			return -EOPNOTSUPP;
		if (!selinux_avc_perm_snapshot_valid(levels[i].state,
						    &snapshots[i]))
			return -ESTALE;
	}
	for (i = 0; i < validatetrans_count; i++) {
		if (!validatetrans[i].state)
			return -EINVAL;
		if (!validatetrans[i].state->label_domain)
			return -EOPNOTSUPP;
		if (!selinux_avc_perm_snapshot_valid(
			    validatetrans[i].state,
			    &validatetrans_snapshots[i]))
			return -ESTALE;
	}
	effective = workspace->effective;
	decisions = workspace->decisions;
	xdecisions = workspace->xdecisions;
	results = workspace->results;
	validatetrans_decisions = workspace->validatetrans_decisions + count;
	memset(effective, 0, array_size(count, sizeof(*effective)));
	memset(decisions, 0, array_size(count, sizeof(*decisions)));
	memset(xdecisions, 0, array_size(count, sizeof(*xdecisions)));
	memset(results, 0, array_size(count, sizeof(*results)));
	memset(validatetrans_decisions, 0,
	       array_size(validatetrans_count,
			  sizeof(*validatetrans_decisions)));
	for (i = 0; i < count; i++) {
		int effective_rc;
		int rc;

		effective[i] = levels[i];
		if (effective[i].decision_kind == SELINUX_AVC_DECISION_GUARD) {
			if (effective[i].guard_result && !typed_rc)
				typed_rc = effective[i].guard_result;
			continue;
		}
		effective[i].requested =
			selinux_avc_level_effective_requested(
				&effective[i], &snapshots[i]);
		if (!effective[i].requested)
			continue;
		if (effective[i].decision_kind == SELINUX_AVC_DECISION_XPERM) {
			rc = selinux_avc_xperm_decide(
				&effective[i], &snapshots[i], i,
				effective[i].driver, effective[i].base_perm,
				effective[i].xperm, &xdecisions[i]);
			decisions[i].allowed = effective[i].requested &
					       ~xdecisions[i].denied;
		} else {
			rc = selinux_avc_perm_decide(
				&effective[i], &snapshots[i], i, &decisions[i]);
		}
		results[i] = rc;
		if (rc == -ESTALE ||
		    (effective[i].decision_kind == SELINUX_AVC_DECISION_AVC &&
		     decisions[i].seqno != snapshots[i].seqno) ||
		    !selinux_avc_perm_snapshot_valid(levels[i].state,
						     &snapshots[i]))
			return -ESTALE;
		effective_rc = rc;
		if (rc == -EACCES && effective[i].denial_errno) {
			effective_rc = effective[i].denial_errno;
			if (!typed_rc)
				typed_rc = effective_rc;
		} else if (effective_rc == -EACCES && !access_rc) {
			access_rc = effective_rc;
		}
		if (rc && rc != -EACCES)
			return rc;
	}
	for (i = 0; i < validatetrans_count; i++) {
		int decision_rc;
		int rc;

		rc = selinux_validatetrans_decide(
			&validatetrans[i], &validatetrans_snapshots[i], i,
			&validatetrans_decisions[i]);
		if (rc == -ESTALE ||
		    !selinux_avc_perm_snapshot_valid(
			    validatetrans[i].state,
			    &validatetrans_snapshots[i]))
			return -ESTALE;
		if (rc)
			return rc;
		decision_rc =
			selinux_validatetrans_apply(validatetrans_decisions[i]);
		if (decision_rc && decision_rc != -EPERM)
			return decision_rc;
		if (decision_rc && !access_rc)
			access_rc = decision_rc;
	}
	for (i = 0; i < count; i++)
		if (!selinux_avc_perm_snapshot_valid(levels[i].state,
						     &snapshots[i]))
			return -ESTALE;
	for (i = 0; i < validatetrans_count; i++)
		if (!selinux_avc_perm_snapshot_valid(
			    validatetrans[i].state,
			    &validatetrans_snapshots[i]))
			return -ESTALE;

	if ((count && selinux_avc_levels_denied(effective, decisions, count)) ||
	    selinux_validatetrans_levels_denied(validatetrans_decisions,
						 validatetrans_count)) {
		int audit_rc = selinux_avc_host_aggregate_composite(
			effective, snapshots, decisions, count, validatetrans,
			validatetrans_snapshots, validatetrans_decisions,
			validatetrans_count, ad);

		return audit_rc ? audit_rc :
			(guard_result ?: (typed_rc ?: access_rc));
	}
	/* A NOAUDIT non-SELinux guard denied the composed operation. */
	if (guard_result)
		return guard_result;
	/* A typed guard denial suppresses allow audits for the denied operation. */
	if (typed_rc)
		return typed_rc;
	for (i = count; i-- > 0;) {
		int audit_rc;

		if (!effective[i].requested ||
		    effective[i].decision_kind == SELINUX_AVC_DECISION_GUARD)
			continue;
		if (ad && ad->type == LSM_AUDIT_DATA_NLMSGTYPE)
			ad->u.nlmsg_type =
				((u16)effective[i].driver << 8) |
				effective[i].xperm;
		if (effective[i].decision_kind == SELINUX_AVC_DECISION_XPERM)
			audit_rc = selinux_avc_xperm_audit(
				&effective[i], &xdecisions[i], ad);
		else
			audit_rc = selinux_avc_perm_audit(
				&effective[i], &decisions[i], results[i], ad);
		if (audit_rc)
			return audit_rc;
	}
	return typed_rc ?: access_rc;
}

int selinux_avc_transaction_has_perm_workspace(
	const struct selinux_avc_level *levels,
	const struct selinux_policy_snapshot *snapshots, u16 count,
	struct common_audit_data *ad,
	struct selinux_avc_transaction_workspace *workspace)
{
	if (!levels || !snapshots || !count || !workspace ||
	    count > workspace->capacity)
		return -E2BIG;
	return selinux_avc_transaction_has_perm_composite_guarded_workspace(
		levels, snapshots, count, NULL, NULL, 0, 0, ad, workspace);
}

noinline int
selinux_avc_levels_has_perm(struct selinux_avc_level *levels, u16 count,
			    struct common_audit_data *ad)
{
	struct selinux_avc_audit_work *work __free(kfree) = NULL;
	unsigned int retry;

	if (!count || count > SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1)
		return -E2BIG;
	work = kzalloc_obj(*work, GFP_ATOMIC | __GFP_NOWARN);
	if (!work)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		bool retry_chain = false;
		int first_rc = 0;
		u16 i;

		for (i = 0; i < count; i++) {
			int rc = selinux_avc_perm_snapshot_read(
				levels[i].state, &work->snapshots[i], i);

			if (rc == -EAGAIN || rc == -ESTALE) {
				retry_chain = true;
				break;
			}
			if (rc)
				return rc;
		}
		if (retry_chain)
			continue;

		for (i = 0; i < count; i++) {
			struct av_decision decision;
			struct selinux_avc_level *level = &work->levels[i];
			int decision_rc;

			*level = levels[i];
			level->requested = selinux_avc_level_effective_requested(
				level, &work->snapshots[i]);
			if (!level->requested) {
				work->results[i] = 0;
				continue;
			}
			decision_rc = selinux_avc_perm_decide(
				level, &work->snapshots[i], i, &decision);
			work->decisions[i] = decision;
			work->results[i] = decision_rc;
			if (decision_rc == -ESTALE) {
				retry_chain = true;
				break;
			}
			if (decision.seqno != work->snapshots[i].seqno ||
			    !selinux_avc_perm_snapshot_valid(
				levels[i].state, &work->snapshots[i])) {
				retry_chain = true;
				break;
			}
			if (decision_rc && !first_rc)
				first_rc = decision_rc;
			if (decision_rc && decision_rc != -EACCES)
				return decision_rc;
		}
		if (retry_chain)
			continue;
		for (i = 0; i < count; i++)
			if (!selinux_avc_perm_snapshot_valid(
				levels[i].state, &work->snapshots[i])) {
				retry_chain = true;
				break;
			}
		if (retry_chain)
			continue;

		if (selinux_avc_levels_denied(work->levels, work->decisions, count)) {
			int audit_rc = selinux_avc_host_aggregate(
				work->levels, work->snapshots, work->decisions,
				count, ad);

			if (audit_rc)
				return audit_rc;
			return first_rc;
		}
		for (i = count; i-- > 0;) {
			struct selinux_avc_level *level = &work->levels[i];
			int audit_rc;

			if (!level->requested)
				continue;
			audit_rc = selinux_avc_perm_audit(
				level, &work->decisions[i], work->results[i], ad);

			if (audit_rc)
				return audit_rc;
		}
		return first_rc;
	}
	return -ESTALE;
}

static int selinux_avc_xperm_snapshot_read(
	struct selinux_state *state, struct selinux_policy_snapshot *snapshot,
	u16 level)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_xperm_fault_active())) {
		memset(snapshot, 0, sizeof(*snapshot));
		if (!level)
			selinux_kunit_xperm_fault.attempts++;
		snapshot->policycaps =
			selinux_kunit_xperm_fault.policycaps[level];
		snapshot->seqno = 100 + selinux_kunit_xperm_fault.attempts;
		snapshot->chain_epoch = 200;
		return 0;
	}
#endif
	return selinux_policy_snapshot_read(state, snapshot);
}

static bool selinux_avc_xperm_snapshot_valid(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_xperm_fault_active()))
		return true;
#endif
	return selinux_policy_snapshot_valid(state, snapshot);
}

static int selinux_avc_xperm_decide(
	struct selinux_avc_level *level,
	const struct selinux_policy_snapshot *snapshot, u16 index, u8 driver,
	u8 base_perm, u8 xperm, struct avc_xperms_audit_decision *decision)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_xperm_fault_active())) {
		selinux_kunit_xperm_fault.evaluations[index]++;
		selinux_kunit_xperm_fault.xperm_evaluations++;
		if (!selinux_kunit_xperm_fault.stale_injected &&
		    selinux_kunit_xperm_fault.stale_level == index) {
			selinux_kunit_xperm_fault.stale_injected = true;
			return -ESTALE;
		}
		if (test_bit(index, selinux_kunit_xperm_fault.deny_levels)) {
			decision->audited = level->requested;
			decision->denied = level->requested;
			decision->result = -EACCES;
			return -EACCES;
		}
		return 0;
	}
#endif
	return avc_has_extended_perms_noaudit_internal(
		level->state, snapshot, level->ssid, level->tsid, level->tclass,
		level->requested, driver, base_perm, xperm, decision);
}

static int selinux_avc_xperm_audit(
	struct selinux_avc_level *level,
	const struct avc_xperms_audit_decision *decision,
	struct common_audit_data *ad)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (unlikely(selinux_kunit_xperm_fault_active())) {
		selinux_kunit_xperm_fault.ordinary_audits++;
		return 0;
	}
#endif
	return avc_xperms_audit_decision(
		level->state, level->ssid, level->tsid, level->tclass,
		level->requested, decision, ad);
}

static int selinux_avc_transaction_has_extended_perm_work(
	const struct selinux_avc_level *levels,
	const struct selinux_policy_snapshot *snapshots, u16 count, u8 driver,
	u8 base_perm, u8 xperm, struct common_audit_data *ad,
	struct selinux_avc_audit_work *work)
{
	int first_rc = 0;
	u16 i;

	if (!levels || !snapshots || !count)
		return -EINVAL;
	if (count > SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1)
		return -E2BIG;
	if (!work)
		return -EINVAL;
	memset(work->levels, 0, sizeof(work->levels));
	memset(work->decisions, 0, sizeof(work->decisions));
	memset(work->xdecisions, 0, sizeof(work->xdecisions));
	memset(work->results, 0, sizeof(work->results));
	for (i = 0; i < count; i++) {
		if (!levels[i].state)
			return -EINVAL;
		if (!levels[i].state->label_domain)
			return -EOPNOTSUPP;
		if (!selinux_avc_xperm_snapshot_valid(levels[i].state,
						       &snapshots[i]))
			return -ESTALE;
	}
	for (i = 0; i < count; i++) {
		struct selinux_avc_level *level = &work->levels[i];
		struct avc_xperms_audit_decision *xdecision =
			&work->xdecisions[i];
		int decision_rc;

		*level = levels[i];
		level->requested = selinux_avc_level_effective_requested(
			level, &snapshots[i]);
		if (!level->requested)
			continue;
		decision_rc = selinux_avc_xperm_decide(
			level, &snapshots[i], i, driver, base_perm, xperm,
			xdecision);
		work->decisions[i].allowed =
			level->requested & ~xdecision->denied;
		work->results[i] = decision_rc;
		if (decision_rc == -ESTALE ||
		    !selinux_avc_xperm_snapshot_valid(levels[i].state,
						       &snapshots[i]))
			return -ESTALE;
		if (decision_rc && !first_rc)
			first_rc = decision_rc;
		if (decision_rc && decision_rc != -EACCES)
			return decision_rc;
	}
	for (i = 0; i < count; i++)
		if (!selinux_avc_xperm_snapshot_valid(levels[i].state,
						       &snapshots[i]))
			return -ESTALE;
	if (selinux_avc_levels_denied(work->levels, work->decisions, count)) {
		int audit_rc = selinux_avc_host_aggregate(
			work->levels, snapshots, work->decisions, count, ad);

		return audit_rc ? audit_rc : first_rc;
	}
	for (i = count; i-- > 0;) {
		struct selinux_avc_level *level = &work->levels[i];
		int audit_rc;

		if (!level->requested)
			continue;
		audit_rc = selinux_avc_xperm_audit(
			level, &work->xdecisions[i], ad);
		if (audit_rc)
			return audit_rc;
	}
	return first_rc;
}

noinline int selinux_avc_levels_has_extended_perm(
	struct selinux_avc_level *levels, u16 count, u8 driver, u8 base_perm,
	u8 xperm, struct common_audit_data *ad)
{
	struct selinux_avc_audit_work *work __free(kfree) = NULL;
	unsigned int retry;

	if (!levels || !count || count > SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1)
		return -E2BIG;
	work = kzalloc_obj(*work, GFP_ATOMIC | __GFP_NOWARN);
	if (!work)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		bool stale = false;
		u16 i;

		for (i = 0; i < count; i++) {
			int rc = selinux_avc_xperm_snapshot_read(
				levels[i].state, &work->snapshots[i], i);

			if (rc == -EAGAIN || rc == -ESTALE) {
				stale = true;
				break;
			}
			if (rc)
				return rc;
		}
		if (stale)
			continue;
		{
			int rc = selinux_avc_transaction_has_extended_perm_work(
				levels, work->snapshots, count, driver, base_perm, xperm,
				ad, work);

			if (rc == -ESTALE)
				continue;
			return rc;
		}
	}
	return -ESTALE;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
int selinux_kunit_avc_xperm_vector(
	const unsigned long policycaps[SELINUX_KUNIT_XPERM_LEVELS],
	int deny_level, int stale_level, int aggregate_rc,
	struct selinux_kunit_xperm_result *result)
{
	struct selinux_avc_level levels[SELINUX_KUNIT_XPERM_LEVELS] = {};
	struct selinux_kunit_xperm_fault *fault = &selinux_kunit_xperm_fault;
	int rc;
	u16 i;

	if (!policycaps || !result || deny_level < -1 ||
	    deny_level >= SELINUX_KUNIT_XPERM_LEVELS || stale_level < -1 ||
	    stale_level >= SELINUX_KUNIT_XPERM_LEVELS ||
	    !current_selinux_state || !current_selinux_state->label_domain)
		return -EINVAL;
	mutex_lock(&selinux_kunit_xperm_lock);
	memset(fault, 0, sizeof(*fault));
	fault->owner = current;
	if (deny_level >= 0)
		set_bit(deny_level, fault->deny_levels);
	fault->stale_level = stale_level;
	fault->aggregate_rc = aggregate_rc;
	for (i = 0; i < ARRAY_SIZE(levels); i++) {
		fault->policycaps[i] = policycaps[i];
		levels[i] = (struct selinux_avc_level) {
			.state = current_selinux_state,
			.ssid = SECINITSID_KERNEL,
			.tsid = SECINITSID_UNLABELED,
			.requested = FILE__IOCTL,
			.tclass = SECCLASS_FILE,
			.skip_policycap = POLICYDB_CAP_IOCTL_SKIP_CLOEXEC,
		};
	}
	WRITE_ONCE(fault->active, true);
	rc = selinux_avc_levels_has_extended_perm(
		levels, ARRAY_SIZE(levels), 0, AVC_EXT_IOCTL, 0, NULL);
	memcpy(result->evaluations, fault->evaluations,
	       sizeof(result->evaluations));
	result->attempts = fault->attempts;
	result->ordinary_audits = fault->ordinary_audits;
	result->aggregate_calls = fault->aggregate_calls;
	result->aggregate_denials = fault->aggregate_denials;
	WRITE_ONCE(fault->active, false);
	WRITE_ONCE(fault->owner, NULL);
	mutex_unlock(&selinux_kunit_xperm_lock);
	return rc;
}

int selinux_kunit_avc_perm_vector(
	int deny_level, int stale_level, int aggregate_rc,
	struct selinux_kunit_xperm_result *result)
{
	struct selinux_avc_level levels[SELINUX_KUNIT_XPERM_LEVELS] = {};
	struct selinux_kunit_xperm_fault *fault = &selinux_kunit_xperm_fault;
	int rc;
	u16 i;

	if (!result || deny_level < -1 ||
	    deny_level >= SELINUX_KUNIT_XPERM_LEVELS || stale_level < -1 ||
	    stale_level >= SELINUX_KUNIT_XPERM_LEVELS ||
	    !current_selinux_state || !current_selinux_state->label_domain)
		return -EINVAL;
	mutex_lock(&selinux_kunit_xperm_lock);
	memset(fault, 0, sizeof(*fault));
	fault->owner = current;
	if (deny_level >= 0)
		set_bit(deny_level, fault->deny_levels);
	fault->stale_level = stale_level;
	fault->aggregate_rc = aggregate_rc;
	for (i = 0; i < ARRAY_SIZE(levels); i++)
		levels[i] = (struct selinux_avc_level) {
			.state = current_selinux_state,
			.ssid = SECINITSID_KERNEL,
			.tsid = SECINITSID_UNLABELED,
			.requested = PACKET__RELABELTO,
			.tclass = SECCLASS_PACKET,
		};
	WRITE_ONCE(fault->active, true);
	rc = selinux_avc_levels_has_perm(levels, ARRAY_SIZE(levels), NULL);
	memcpy(result->evaluations, fault->evaluations,
	       sizeof(result->evaluations));
	result->attempts = fault->attempts;
	result->ordinary_audits = fault->ordinary_audits;
	result->aggregate_calls = fault->aggregate_calls;
	result->aggregate_denials = fault->aggregate_denials;
	WRITE_ONCE(fault->active, false);
	WRITE_ONCE(fault->owner, NULL);
	mutex_unlock(&selinux_kunit_xperm_lock);
	return rc;
}

int selinux_kunit_avc_mixed_transaction(
	bool ordinary_denied, bool xperm_denied, int guard_result,
	int stale_level, struct selinux_kunit_xperm_result *result)
{
	struct selinux_avc_level levels[SELINUX_KUNIT_XPERM_LEVELS] = {};
	struct selinux_policy_snapshot snapshots[SELINUX_KUNIT_XPERM_LEVELS] = {};
	struct selinux_avc_transaction_workspace *workspace;
	struct selinux_kunit_xperm_fault *fault = &selinux_kunit_xperm_fault;
	unsigned int retry;
	int rc = -ESTALE;
	u16 i;

	if (!result || guard_result > 0 || stale_level < -1 ||
	    stale_level >= SELINUX_KUNIT_XPERM_LEVELS ||
	    !current_selinux_state || !current_selinux_state->label_domain)
		return -EINVAL;
	mutex_lock(&selinux_kunit_xperm_lock);
	memset(fault, 0, sizeof(*fault));
	fault->owner = current;
	fault->stale_level = stale_level;
	if (ordinary_denied)
		set_bit(0, fault->deny_levels);
	if (xperm_denied)
		set_bit(1, fault->deny_levels);
	levels[0] = (struct selinux_avc_level) {
		.state = current_selinux_state,
		.ssid = SECINITSID_KERNEL,
		.tsid = SECINITSID_UNLABELED,
		.requested = PACKET__RELABELTO,
		.tclass = SECCLASS_PACKET,
		.driver = 7,
		.base_perm = AVC_EXT_NLMSG,
		.xperm = 23,
	};
	levels[1] = levels[0];
	levels[1].decision_kind = SELINUX_AVC_DECISION_XPERM;
	levels[2] = (struct selinux_avc_level) {
		.state = current_selinux_state,
		.decision_kind = SELINUX_AVC_DECISION_GUARD,
		.guard_result = guard_result,
	};
	WRITE_ONCE(fault->active, true);
	workspace = selinux_avc_transaction_workspace_alloc(
		ARRAY_SIZE(levels), GFP_KERNEL);
	if (!workspace) {
		rc = -ENOMEM;
		goto out_result;
	}
	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		fault->attempts++;
		for (i = 0; i < ARRAY_SIZE(snapshots); i++)
			snapshots[i].seqno = 100 + fault->attempts;
		rc = selinux_avc_transaction_has_perm_workspace(
			levels, snapshots, ARRAY_SIZE(levels), NULL, workspace);
		if (rc != -ESTALE)
			break;
	}
	selinux_avc_transaction_workspace_free(workspace);
out_result:
	memcpy(result->evaluations, fault->evaluations,
	       sizeof(result->evaluations));
	result->attempts = fault->attempts;
	result->ordinary_audits = fault->ordinary_audits;
	result->aggregate_calls = fault->aggregate_calls;
	result->aggregate_denials = fault->aggregate_denials;
	result->ordinary_evaluations = fault->ordinary_evaluations;
	result->xperm_evaluations = fault->xperm_evaluations;
	result->workspace_allocations = fault->workspace_allocations;
	result->aggregate_decision_kind = fault->aggregate_decision_kind;
	result->aggregate_driver = fault->aggregate_driver;
	result->aggregate_base_perm = fault->aggregate_base_perm;
	result->aggregate_xperm = fault->aggregate_xperm;
	WRITE_ONCE(fault->active, false);
	WRITE_ONCE(fault->owner, NULL);
	mutex_unlock(&selinux_kunit_xperm_lock);
	return rc;
}

int selinux_kunit_avc_noaudit_precheck(
	int deny_level, int stale_level, int denial_errno,
	struct selinux_kunit_xperm_result *result)
{
	struct selinux_avc_level levels[SELINUX_KUNIT_XPERM_LEVELS] = {};
	struct selinux_policy_snapshot
		snapshots[SELINUX_KUNIT_XPERM_LEVELS] = {};
	struct selinux_kunit_xperm_fault *fault = &selinux_kunit_xperm_fault;
	int rc;
	u16 i;

	if (!result || deny_level < -1 ||
	    deny_level >= SELINUX_KUNIT_XPERM_LEVELS || stale_level < -1 ||
	    stale_level >= SELINUX_KUNIT_XPERM_LEVELS || denial_errno > 0 ||
	    !current_selinux_state || !current_selinux_state->label_domain)
		return -EINVAL;
	mutex_lock(&selinux_kunit_xperm_lock);
	memset(fault, 0, sizeof(*fault));
	fault->owner = current;
	fault->stale_level = stale_level;
	if (deny_level >= 0)
		set_bit(deny_level, fault->deny_levels);
	for (i = 0; i < ARRAY_SIZE(levels); i++) {
		levels[i] = (struct selinux_avc_level) {
			.state = current_selinux_state,
			.ssid = SECINITSID_KERNEL,
			.tsid = SECINITSID_KERNEL,
			.requested = CAP_TO_MASK(CAP_MAC_ADMIN),
			.tclass = SECCLASS_CAPABILITY2,
			.denial_errno = denial_errno,
		};
		snapshots[i].seqno = 100;
	}
	WRITE_ONCE(fault->active, true);
	rc = selinux_avc_transaction_has_perm_noaudit(
		levels, snapshots, ARRAY_SIZE(levels));
	memcpy(result->evaluations, fault->evaluations,
	       sizeof(result->evaluations));
	result->ordinary_audits = fault->ordinary_audits;
	result->aggregate_calls = fault->aggregate_calls;
	result->aggregate_denials = fault->aggregate_denials;
	WRITE_ONCE(fault->active, false);
	WRITE_ONCE(fault->owner, NULL);
	mutex_unlock(&selinux_kunit_xperm_lock);
	return rc;
}

int selinux_kunit_avc_mount_transaction(
	u16 denial_mask, int stale_level, bool stale_every_attempt,
	int aggregate_rc, struct selinux_kunit_mount_transaction_result *result)
{
	struct selinux_avc_level
		levels[SELINUX_KUNIT_MOUNT_TRANSACTION_CHECKS] = {};
	struct selinux_policy_snapshot
		snapshots[SELINUX_KUNIT_MOUNT_TRANSACTION_CHECKS] = {};
	struct selinux_kunit_xperm_fault *fault = &selinux_kunit_xperm_fault;
	struct selinux_avc_transaction_workspace *workspace;
	unsigned int retry;
	int rc = -ESTALE;
	u16 i;

	if (!result || stale_level < -1 ||
	    stale_level >= SELINUX_KUNIT_MOUNT_TRANSACTION_CHECKS ||
	    denial_mask >> SELINUX_KUNIT_MOUNT_TRANSACTION_CHECKS ||
	    !current_selinux_state || !current_selinux_state->label_domain)
		return -EINVAL;
	/*
	 * Synthetic two-level mount vector: guard, two child checks, then
	 * mount/selection/capability for the leaf parent and host respectively.
	 */
	mutex_lock(&selinux_kunit_xperm_lock);
	memset(fault, 0, sizeof(*fault));
	fault->owner = current;
	fault->stale_level = stale_level;
	fault->aggregate_rc = aggregate_rc;
	for (i = 0; i < ARRAY_SIZE(levels); i++) {
		levels[i] = (struct selinux_avc_level) {
			.state = current_selinux_state,
			.ssid = SECINITSID_KERNEL,
			.tsid = SECINITSID_UNLABELED,
			.requested = i ? PACKET__RELABELTO : 0,
			.tclass = SECCLASS_PACKET,
		};
		if (denial_mask & BIT(i))
			set_bit(i, fault->deny_levels);
	}
	WRITE_ONCE(fault->active, true);
	workspace = selinux_avc_transaction_workspace_alloc(
		ARRAY_SIZE(levels), GFP_KERNEL);
	if (!workspace) {
		rc = -ENOMEM;
		goto out_result;
	}
	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		fault->attempts++;
		if (stale_every_attempt)
			fault->stale_injected = false;
		for (i = 0; i < ARRAY_SIZE(snapshots); i++)
			snapshots[i].seqno = 100 + fault->attempts;
		rc = selinux_avc_transaction_has_perm_workspace(
			levels, snapshots, ARRAY_SIZE(levels), NULL, workspace);
		if (rc != -ESTALE)
			break;
	}
	selinux_avc_transaction_workspace_free(workspace);
out_result:
	memcpy(result->evaluations, fault->evaluations,
	       sizeof(result->evaluations));
	result->attempts = fault->attempts;
	result->ordinary_audits = fault->ordinary_audits;
	result->aggregate_calls = fault->aggregate_calls;
	result->aggregate_denials = fault->aggregate_denials;
	WRITE_ONCE(fault->active, false);
	WRITE_ONCE(fault->owner, NULL);
	mutex_unlock(&selinux_kunit_xperm_lock);
	return rc;
}

int selinux_kunit_avc_validatetrans_transaction(
	u16 avc_denial_mask, u8 validatetrans_enforcing_mask,
	u8 validatetrans_permissive_mask, int stale_validatetrans_level,
	u8 allocation_fail_stage, int aggregate_rc,
	struct selinux_kunit_composite_transaction_result *result)
{
	struct selinux_avc_level
		levels[SELINUX_KUNIT_COMPOSITE_AVC_CHECKS] = {};
	struct selinux_policy_snapshot
		snapshots[SELINUX_KUNIT_COMPOSITE_AVC_CHECKS] = {};
	struct selinux_validatetrans_level validatetrans[
		SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS] = {};
	struct selinux_policy_snapshot validatetrans_snapshots[
		SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS] = {};
	struct selinux_kunit_xperm_fault *fault = &selinux_kunit_xperm_fault;
	struct selinux_avc_transaction_workspace *workspace;
	unsigned int retry;
	int rc = -ESTALE;
	u16 i;

	if (!result ||
	    avc_denial_mask >> SELINUX_KUNIT_COMPOSITE_AVC_CHECKS ||
	    validatetrans_enforcing_mask >>
		    SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS ||
	    validatetrans_permissive_mask >>
		    SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS ||
	    (validatetrans_enforcing_mask & validatetrans_permissive_mask) ||
	    stale_validatetrans_level < -1 ||
	    stale_validatetrans_level >=
		    SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS ||
	    allocation_fail_stage > SELINUX_KUNIT_COMPOSITE_ALLOC_AGGREGATE ||
	    !current_selinux_state || !current_selinux_state->label_domain)
		return -EINVAL;

	mutex_lock(&selinux_kunit_xperm_lock);
	memset(fault, 0, sizeof(*fault));
	fault->owner = current;
	fault->stale_level = -1;
	fault->stale_validatetrans_level = stale_validatetrans_level;
	fault->allocation_fail_stage = allocation_fail_stage;
	fault->aggregate_rc = aggregate_rc;
	for (i = 0; i < ARRAY_SIZE(levels); i++) {
		levels[i] = (struct selinux_avc_level) {
			.state = current_selinux_state,
			.ssid = SECINITSID_KERNEL,
			.tsid = SECINITSID_UNLABELED,
			.requested = FILE__RELABELTO,
			.tclass = SECCLASS_FILE,
		};
		if (avc_denial_mask & BIT(i))
			set_bit(i, fault->deny_levels);
	}
	for (i = 0; i < ARRAY_SIZE(validatetrans); i++) {
		validatetrans[i] = (struct selinux_validatetrans_level) {
			.state = current_selinux_state,
			.oldsid = 1000 + i,
			.newsid = 2000 + i,
			.tasksid = 3000 + i,
			.tclass = SECCLASS_FILE,
		};
		if (validatetrans_enforcing_mask & BIT(i))
			set_bit(i, fault->validatetrans_enforcing_levels);
		if (validatetrans_permissive_mask & BIT(i))
			set_bit(i, fault->validatetrans_permissive_levels);
	}
	WRITE_ONCE(fault->active, true);
	workspace = selinux_avc_transaction_workspace_alloc(
		ARRAY_SIZE(levels) + ARRAY_SIZE(validatetrans), GFP_KERNEL);
	if (!workspace) {
		rc = -ENOMEM;
		goto out_result;
	}
	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		fault->attempts++;
		for (i = 0; i < ARRAY_SIZE(snapshots); i++)
			snapshots[i].seqno = 100 + fault->attempts;
		for (i = 0; i < ARRAY_SIZE(validatetrans_snapshots); i++)
			validatetrans_snapshots[i].seqno =
				200 + fault->attempts;
		rc = selinux_avc_transaction_has_perm_composite_guarded_workspace(
			levels, snapshots, ARRAY_SIZE(levels), validatetrans,
			validatetrans_snapshots, ARRAY_SIZE(validatetrans), 0, NULL,
			workspace);
		if (rc != -ESTALE)
			break;
	}
	selinux_avc_transaction_workspace_free(workspace);
out_result:
	memcpy(result->avc_evaluations, fault->evaluations,
	       sizeof(result->avc_evaluations));
	memcpy(result->validatetrans_evaluations,
	       fault->validatetrans_evaluations,
	       sizeof(result->validatetrans_evaluations));
	result->attempts = fault->attempts;
	result->ordinary_audits = fault->ordinary_audits;
	result->aggregate_calls = fault->aggregate_calls;
	result->aggregate_denials = fault->aggregate_denials;
	result->aggregate_avc_denials = fault->aggregate_avc_denials;
	result->aggregate_validatetrans_denials =
		fault->aggregate_validatetrans_denials;
	result->aggregate_permissive_validatetrans_denials =
		fault->aggregate_permissive_validatetrans_denials;
	memcpy(result->aggregate_validatetrans_oldsids,
	       fault->aggregate_validatetrans_oldsids,
	       sizeof(result->aggregate_validatetrans_oldsids));
	result->first_validatetrans_oldsid = fault->first_validatetrans_oldsid;
	result->first_validatetrans_newsid = fault->first_validatetrans_newsid;
	result->first_validatetrans_tasksid =
		fault->first_validatetrans_tasksid;
	result->first_validatetrans_tclass =
		fault->first_validatetrans_tclass;
	WRITE_ONCE(fault->active, false);
	WRITE_ONCE(fault->owner, NULL);
	mutex_unlock(&selinux_kunit_xperm_lock);
	return rc;
}
#endif

static int selinux_avc_resolution_levels(
	struct selinux_state *state,
	const struct selinux_label_resolution *source,
	const struct selinux_label_resolution *target, u16 tclass, u32 requested,
	struct selinux_avc_level *levels,
	const struct selinux_avc_provenance *provenance, u16 *countp)
{
	u16 count = 0;

	if (!state || !source || !target || !levels || !countp || !tclass ||
	    !requested)
		return -EINVAL;
	while (state) {
		u16 depth;

		if (!state->label_domain)
			return -EOPNOTSUPP;
		if (count >= SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1)
			return -E2BIG;
		depth = state->label_domain->depth;
		if (depth > source->max_depth || depth > target->max_depth ||
		    source->domain_id[depth] != state->label_domain->id ||
		    target->domain_id[depth] != state->label_domain->id ||
		    !source->sid[depth] || !target->sid[depth])
			return -EXDEV;
		levels[count].state = state;
		levels[count].ssid = source->sid[depth];
		levels[count].tsid = target->sid[depth];
		levels[count].tclass = tclass;
		levels[count].requested = requested;
		levels[count].provenance = provenance;
		count++;
		state = state->parent;
	}
	*countp = count;
	return count ? 0 : -EINVAL;
}

int selinux_state_resolutions_has_perm(
	struct selinux_state *state,
	const struct selinux_label_resolution *source,
	const struct selinux_label_resolution *target, u16 tclass, u32 requested,
	const struct selinux_label_ref *canonical_target,
	const struct selinux_label_view *view, u8 assertion_source,
	struct common_audit_data *ad)
{
	struct selinux_avc_level levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	struct selinux_avc_provenance provenance = {
		.label = canonical_target,
		.view = view,
		.source = assertion_source,
	};
	u16 count;
	int rc;

	if (!canonical_target || !view)
		return -EOPNOTSUPP;
	rc = selinux_avc_resolution_levels(state, source, target, tclass,
					   requested, levels, &provenance, &count);
	if (rc)
		return rc;
	return selinux_avc_levels_has_perm(levels, count, ad);
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
int selinux_kunit_resolution_levels(
	struct selinux_state *state,
	const struct selinux_label_resolution *source,
	const struct selinux_label_resolution *target, u16 *count)
{
	struct selinux_avc_level levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};

	return selinux_avc_resolution_levels(
		state, source, target, SECCLASS_ASSOCIATION,
		ASSOCIATION__POLMATCH, levels, NULL, count);
}
#endif
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_cred_chain_advance(const struct cred **cursor)
{
	const struct cred_security_struct *current_sec, *parent;
	const struct cred *next;

	if (!cursor || !*cursor)
		return -EINVAL;
	current_sec = selinux_cred(*cursor);
	if (!current_sec->state || !current_sec->state->label_domain ||
	    current_sec->state->depth != current_sec->state->label_domain->depth)
		return -EXDEV;
	next = current_sec->parent_cred;
	if (!next) {
		if (current_sec->state->parent ||
		    current_sec->state->label_domain->parent ||
		    current_sec->state->depth)
			return -EXDEV;
		*cursor = NULL;
		return 0;
	}
	parent = selinux_cred(next);
	if (!parent->state || !parent->state->label_domain ||
	    current_sec->state->parent != parent->state ||
	    current_sec->state->label_domain->parent !=
		    parent->state->label_domain ||
	    current_sec->state->depth != parent->state->depth + 1 ||
	    current_sec->state->label_domain->depth !=
		    parent->state->label_domain->depth + 1)
		return -EXDEV;
	*cursor = next;
	return 0;
}

/*
 * Resolve one monotonically descending credential chain against @state.
 * The cursor never rewinds, so resolving every level of another chain is
 * Theta(left depth + right depth), rather than Theta(depth squared).
 */
static int selinux_cred_chain_sid_for_state(const struct cred **cursor,
					    const struct selinux_state *state,
					    u32 *sid)
{
	if (!cursor || !state || !state->label_domain || !sid ||
	    state->depth != state->label_domain->depth)
		return -EXDEV;

	while (*cursor) {
		const struct cred_security_struct *crsec = selinux_cred(*cursor);
		int rc;

		if (!crsec->state || !crsec->state->label_domain ||
		    crsec->state->depth != crsec->state->label_domain->depth)
			return -EXDEV;
		if (crsec->state != state &&
		    crsec->state->label_domain == state->label_domain)
			return -EXDEV;
		if (crsec->state == state) {
			*sid = crsec->sid;
			return selinux_cred_chain_advance(cursor);
		}
		if (crsec->state->depth <= state->depth)
			break;
		rc = selinux_cred_chain_advance(cursor);
		if (rc)
			return rc;
	}
	*sid = SECINITSID_UNLABELED;
	return 0;
}

static int selinux_cred_pair_levels(
	const struct cred *policy_cred, const struct cred *subject,
	const struct cred *target, u16 tclass, u32 requested,
	struct selinux_avc_level *levels, u16 capacity, u16 *countp)
{
	const struct cred *subject_cursor = subject;
	const struct cred *target_cursor = target;
	u16 count = 0;

	if (!policy_cred || !subject || !target || !tclass || !requested ||
	    !levels || !capacity || !countp)
		return -EINVAL;
	while (policy_cred) {
		const struct cred_security_struct *policy =
			selinux_cred(policy_cred);
		int rc;

		if (count >= capacity)
			return -E2BIG;
		if (!policy->state || !policy->state->label_domain)
			return -EXDEV;
		rc = selinux_cred_chain_sid_for_state(
			&subject_cursor, policy->state, &levels[count].ssid);
		if (rc)
			return rc;
		rc = selinux_cred_chain_sid_for_state(
			&target_cursor, policy->state, &levels[count].tsid);
		if (rc)
			return rc;
		levels[count].state = policy->state;
		levels[count].tclass = tclass;
		levels[count].requested = requested;
		count++;
		rc = selinux_cred_chain_advance(&policy_cred);
		if (rc)
			return rc;
	}
	if (subject_cursor || target_cursor)
		return -EXDEV;
	*countp = count;
	return count ? 0 : -EINVAL;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
int selinux_kunit_cred_pair_levels(
	const struct cred *policy_cred, const struct cred *subject,
	const struct cred *target, struct selinux_state **states, u32 *ssids,
	u32 *tsids, u16 capacity, u16 *countp)
{
	struct selinux_avc_level *levels;
	u16 count, i;
	int rc;

	if (!states || !ssids || !tsids || !capacity || !countp)
		return -EINVAL;
	levels = kcalloc(capacity, sizeof(*levels), GFP_KERNEL);
	if (!levels)
		return -ENOMEM;
	rc = selinux_cred_pair_levels(policy_cred, subject, target,
				      SECCLASS_PROCESS, PROCESS__PTRACE,
				      levels, capacity, &count);
	if (!rc) {
		for (i = 0; i < count; i++) {
			states[i] = levels[i].state;
			ssids[i] = levels[i].ssid;
			tsids[i] = levels[i].tsid;
		}
		*countp = count;
	}
	kfree(levels);
	return rc;
}
#endif
#endif

/**
 * cred_task_has_perm - Check and audit permissions on a (cred, task) pair
 * @cred: subject credentials
 * @p: target task
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @ad: auxiliary audit data
 *
 * Check permissions between a cred @cred and a task @p for @cred's namespace
 * and all ancestors to determine whether the @requested permissions are
 * granted.
 * Audit the granting or denial of permissions in accordance with the policy.
 * Return %0 if all @requested permissions are granted, -%EACCES if any
 * permissions are denied, or another -errno upon other errors.
 */
int cred_task_has_perm(const struct cred *cred, const struct task_struct *p,
		       u16 tclass, u32 requested,
		       struct common_audit_data *ad)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_level levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	const struct cred *target = get_task_cred((struct task_struct *)p);
	u16 count;
	int rc;

	rc = selinux_cred_pair_levels(cred, cred, target, tclass, requested,
				      levels, ARRAY_SIZE(levels), &count);
	put_cred(target);
	return rc ?: selinux_avc_levels_has_perm(levels, count, ad);
#else
	struct cred_security_struct *crsec;
	struct selinux_state *state;
	u32 ssid;
	u32 tsid;
	int rc;

	do {
		crsec = selinux_cred(cred);
		ssid = crsec->sid;
		state = crsec->state;
		tsid = task_sid_obj_for_state(p, state);

		rc = avc_has_perm(state, ssid, tsid, tclass, requested, ad);
		if (rc)
			return rc;

		cred = crsec->parent_cred;
	} while (cred);

	return 0;
#endif
}

#ifndef CONFIG_SECURITY_SELINUX_NS
static const struct cred_security_struct *task_cred_security(
	const struct task_struct *p)
{
	const struct cred_security_struct *crsec;

	crsec = selinux_cred(__task_cred(p));
	while (crsec->state != current_selinux_state && crsec->parent_cred)
		crsec = selinux_cred(crsec->parent_cred);
	if (crsec->state != current_selinux_state)
		return NULL;
	return crsec;
}
#endif

/**
 * task_obj_has_perm - Check and audit permissions on a (task, other-task) pair
 * @s: source task
 * @t: target task
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @ad: auxiliary audit data
 *
 * Check permissions between a task @s and a task @t for the current namespace
 * and all ancestors to determine whether the @requested permissions are
 * granted.
 * Audit the granting or denial of permissions in accordance with the policy.
 * Return %0 if all @requested permissions are granted, -%EACCES if any
 * permissions are denied, or another -errno upon other errors.
 * DO NOT USE when @s is current; use cred_task_has_perm() instead.
 */
int task_obj_has_perm(const struct task_struct *s,
		      const struct task_struct *t,
		      u16 tclass, u32 requested,
		      struct common_audit_data *ad)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_level levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	const struct cred *source = get_task_cred((struct task_struct *)s);
	const struct cred *target = get_task_cred((struct task_struct *)t);
	u16 count;
	int rc;

	/* The traced task's policy chain protects the traced object. */
	rc = selinux_cred_pair_levels(target, source, target, tclass, requested,
				      levels, ARRAY_SIZE(levels), &count);
	if (!rc)
		rc = selinux_avc_levels_has_perm(levels, count, ad);
	put_cred(target);
	put_cred(source);
	return rc;
#else
	const struct cred *cred;
	const struct cred_security_struct *crsec;
	struct selinux_state *state;
	u32 ssid;
	u32 tsid;
	int rc;

	state = current_selinux_state;
	rcu_read_lock();
	crsec = task_cred_security(s);
	if (crsec)
		ssid = crsec->sid;
	else
		ssid = SECINITSID_UNLABELED;

	do {
		tsid = task_sid_obj_for_state(t, state);

		rc = avc_has_perm(state, ssid, tsid, tclass, requested, ad);
		if (rc)
			break;

		if (!crsec)
			break;

		cred = crsec->parent_cred;
		if (!cred)
			break;

		crsec = selinux_cred(cred);
		ssid = crsec->sid;
		state = crsec->state;
	} while (cred);

	rcu_read_unlock();
	return rc;
#endif
}

/**
 * cred_has_extended_perms - Check and audit extended permissions on a (cred, tsid) pair
 * @cred: subject credentials
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @driver: driver value
 * @base_perm: the base permission associated with the extended permission
 * @xperm: extended permission value
 * @ad: auxiliary audit data
 *
 * Check extended permissions between a cred @cred and a target
 * security identifier @tsid for @cred's namespace and all ancestors
 * to determine whether the @requested permissions are granted for the
 * specified (@driver, @xperm) pair.
 * Audit the granting or denial of permissions in accordance with the policy.
 * Return %0 if the @requested permissions are granted, -%EACCES if any
 * permissions are denied, or another -errno upon other errors.
 */
int cred_has_extended_perms(const struct cred *cred, u32 tsid, u16 tclass,
			    u32 requested, u8 driver, u8 base_perm, u8 xperm,
			    struct common_audit_data *ad)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_audit_work *work __free(kfree) = NULL;
	struct selinux_avc_level *levels;
	struct selinux_policy_snapshot *snapshots;
	struct av_decision *decisions;
	struct avc_xperms_audit_decision *xdecisions;
	unsigned int retry;
	u16 count = 0, i;

	work = kzalloc(sizeof(*work), GFP_ATOMIC | __GFP_NOWARN);
	if (!work)
		return -ENOMEM;
	levels = work->levels;
	snapshots = work->snapshots;
	decisions = work->decisions;
	xdecisions = work->xdecisions;
	while (cred) {
		struct cred_security_struct *crsec = selinux_cred(cred);

		if (count >= SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1)
			return -E2BIG;
		levels[count].state = crsec->state;
		levels[count].ssid = crsec->sid;
		levels[count].tsid = tsid;
		levels[count].tclass = tclass;
		levels[count].requested = requested;
		count++;
		cred = crsec->parent_cred;
	}
	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		int first_rc = 0;
		bool stale = false;

		for (i = 0; i < count; i++) {
			int rc = selinux_policy_snapshot_read(levels[i].state,
						      &snapshots[i]);

			if (rc == -EAGAIN || rc == -ESTALE) {
				stale = true;
				break;
			}
			if (rc)
				return rc;
		}
		if (stale)
			continue;
		for (i = 0; i < count; i++) {
			int rc = avc_has_extended_perms_noaudit_internal(
				levels[i].state, &snapshots[i], levels[i].ssid,
				levels[i].tsid, tclass, requested, driver, base_perm,
				xperm, &xdecisions[i]);

			decisions[i].allowed = requested & ~xdecisions[i].denied;
			if (rc && !first_rc)
				first_rc = rc;
			if (rc == -ESTALE) {
				stale = true;
				break;
			}
			if (rc && rc != -EACCES)
				return rc;
		}
		if (stale)
			continue;
		for (i = 0; i < count; i++)
			if (!selinux_policy_snapshot_valid(levels[i].state,
						   &snapshots[i])) {
				stale = true;
				break;
			}
		if (stale)
			continue;
		if (selinux_avc_levels_denied(levels, decisions, count)) {
			int audit_rc = selinux_avc_host_aggregate(
				levels, snapshots, decisions, count, ad);

			return audit_rc ? audit_rc : first_rc;
		}
		for (i = count; i-- > 0;) {
			int audit_rc = avc_xperms_audit_decision(
				levels[i].state, levels[i].ssid, levels[i].tsid,
				tclass, requested, &xdecisions[i], ad);

			if (audit_rc)
				return audit_rc;
		}
		return first_rc;
	}
	return -ESTALE;
#else
	struct cred_security_struct *crsec;
	struct selinux_state *state;
	u32 ssid;
	int rc, first_rc = 0;

	do {
		crsec = selinux_cred(cred);
		ssid = crsec->sid;
		state = crsec->state;

		rc = avc_has_extended_perms(state, ssid, tsid, tclass,
					    requested, driver, base_perm,
					    xperm, ad);
		if (rc && !first_rc)
			first_rc = rc;
		if (rc && rc != -EACCES)
			return rc;

		cred = crsec->parent_cred;
	} while (cred);

	return first_rc;
#endif
}

/**
 * cred_self_has_perm - Check and audit permissions on a (cred, self) pair
 * @cred: subject credentials
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @ad: auxiliary audit data
 *
 * Check permissions between a cred @cred and itself for @cred's namespace
 * and all ancestors to determine whether the @requested permissions are
 * granted.
 * Audit the granting or denial of permissions in accordance with the policy.
 * Return %0 if all @requested permissions are granted, -%EACCES if any
 * permissions are denied, or another -errno upon other errors.
 */
int cred_self_has_perm(const struct cred *cred, u16 tclass, u32 requested,
		       struct common_audit_data *ad)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_level levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	u16 count = 0;

	if (!selinux_initialized(selinux_cred(cred)->state) &&
	    selinux_cred_chain_uninitialized(cred))
		return 0;

	while (cred) {
		struct cred_security_struct *crsec = selinux_cred(cred);

		if (count >= ARRAY_SIZE(levels))
			return -E2BIG;
		levels[count].state = crsec->state;
		levels[count].ssid = crsec->sid;
		levels[count].tsid = crsec->sid;
		levels[count].tclass = tclass;
		levels[count].requested = requested;
		count++;
		cred = crsec->parent_cred;
	}
	return selinux_avc_levels_has_perm(levels, count, ad);
#else
	struct cred_security_struct *crsec;
	struct selinux_state *state;
	u32 ssid;
	int rc;

	do {
		crsec = selinux_cred(cred);
		ssid = crsec->sid;
		state = crsec->state;
		rc = avc_has_perm(state, ssid, ssid, tclass, requested, ad);
		if (rc)
			return rc;

		cred = crsec->parent_cred;
	} while (cred);

	return 0;
#endif
}

/**
 * cred_self_has_perm_noaudit - Check permissions on a (cred, self) pair, no audit
 * @cred: subject credentials
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 *
 * Check permissions between a cred @cred and itself for @cred's namespace
 * and all ancestors to determine whether the @requested permissions are
 * granted.
 * Return %0 if all @requested permissions are granted, -%EACCES if any
 * permissions are denied, or another -errno upon other errors.
 */
int cred_self_has_perm_noaudit(const struct cred *cred, u16 tclass,
			       u32 requested)
{
	struct cred_security_struct *crsec;
	struct selinux_state *state;
	u32 ssid;
	struct av_decision avd;
	int rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!selinux_initialized(selinux_cred(cred)->state) &&
	    selinux_cred_chain_uninitialized(cred))
		return 0;
#endif

	do {
		crsec = selinux_cred(cred);
		ssid = crsec->sid;
		state = crsec->state;

		rc = avc_has_perm_noaudit(state, ssid, ssid, tclass,
					  requested, 0, &avd);
		if (rc)
			return rc;

		cred = crsec->parent_cred;
	} while (cred);

	return 0;
}


/**
 * cred_tsid_has_perm - Check and audit permissions on a (cred, tsid) pair
 * @cred: subject credentials
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @ad: auxiliary audit data
 *
 * Check permissions between a cred @cred and a target SID @tsid for
 * @cred's namespace and all ancestors to determine whether the
 * @requested permissions are granted, interpreting the permissions based
 * on @tclass.
 * Audit the granting or denial of permissions in accordance with the policy.
 * Return %0 if all @requested permissions are granted, -%EACCES if any
 * permissions are denied, or another -errno upon other errors.
 * DO NOT USE when checking permissions between two creds (or tasks);
 * use cred_other_has_perm() or cred_task_has_perm() instead.
 */
int cred_tsid_has_perm(const struct cred *cred, u32 tsid, u16 tclass,
		       u32 requested, struct common_audit_data *ad)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_level levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	u16 count = 0;

	while (cred) {
		struct cred_security_struct *crsec = selinux_cred(cred);

		if (count >= ARRAY_SIZE(levels))
			return -E2BIG;
		levels[count].state = crsec->state;
		levels[count].ssid = crsec->sid;
		levels[count].tsid = tsid;
		levels[count].tclass = tclass;
		levels[count].requested = requested;
		count++;
		cred = crsec->parent_cred;
	}
	return selinux_avc_levels_has_perm(levels, count, ad);
#else
	struct cred_security_struct *crsec;
	struct selinux_state *state;
	u32 ssid;
	int rc;

	do {
		crsec = selinux_cred(cred);
		ssid = crsec->sid;
		state = crsec->state;
		rc = avc_has_perm(state, ssid, tsid, tclass, requested, ad);
		if (rc)
			return rc;

		cred = crsec->parent_cred;
	} while (cred);

	return 0;
#endif
}

/**
 * cred_tsid_has_perm_noaudit - Check permissions on a (cred, tsid) pair, no audit
 * @cred: subject credentials
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @avd: access vector decisions
 *
 * Check permissions between a cred @cred and a target SID @tsid for
 * @cred's namespace and all ancestors to determine whether the
 * @requested permissions are granted.
 * Return %0 if all @requested permissions are granted, -%EACCES if any
 * permissions are denied, or another -errno upon other errors.
 * DO NOT USE when checking permissions between two creds (or tasks);
 * use cred_other_has_perm() or cred_task_has_perm() instead.
 */
int cred_tsid_has_perm_noaudit(const struct cred *cred, u32 tsid, u16 tclass,
			       u32 requested, struct av_decision *avd)
{
	struct cred_security_struct *crsec;
	struct selinux_state *state;
	struct av_decision tmp_avd;
	u32 ssid;
	int rc;

	crsec = selinux_cred(cred);
	ssid = crsec->sid;
	state = crsec->state;

	rc = avc_has_perm_noaudit(state, ssid, tsid, tclass,
				requested, 0, avd);
	if (rc)
		return rc;

	cred = crsec->parent_cred;
	while (cred) {
		crsec = selinux_cred(cred);
		ssid = crsec->sid;
		state = crsec->state;

		rc = avc_has_perm_noaudit(state, ssid, tsid, tclass,
					  requested, 0, &tmp_avd);

		avd->allowed &= tmp_avd.allowed;
		avd->auditallow |= tmp_avd.auditallow;
		avd->auditdeny |= tmp_avd.auditdeny;
		avd->flags &= tmp_avd.flags;

		if (rc)
			return rc;

		cred = crsec->parent_cred;
	}

	return 0;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static void av_decision_fail_closed(struct av_decision *avd)
{
	avd->allowed = 0;
	avd->auditallow = 0;
	avd->auditdeny = ~0U;
	avd->seqno = 0;
	avd->flags = 0;
}

struct selinux_avc_chain_snapshot {
	const struct cred *cred[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct selinux_policy_snapshot *policy;
	u16 count;
};

DEFINE_FREE(selinux_pathless_chain_resolution_put,
	struct selinux_pathless_chain_resolution,
	selinux_pathless_chain_resolution_put(&_T))

static void selinux_pathless_chain_resolution_ptr_free(
	struct selinux_pathless_chain_resolution *resolution)
{
	if (!resolution)
		return;
	selinux_pathless_chain_resolution_put(resolution);
	kfree(resolution);
}

DEFINE_FREE(selinux_pathless_chain_resolution_ptr_put,
	struct selinux_pathless_chain_resolution *,
	if (_T)
		selinux_pathless_chain_resolution_ptr_free(_T))

static void selinux_label_operation_resolution_ptr_free(
	struct selinux_label_operation_resolution *resolution)
{
	if (!resolution)
		return;
	selinux_label_operation_resolution_put(resolution);
	kfree(resolution);
}

DEFINE_FREE(selinux_label_operation_resolution_ptr_put,
	struct selinux_label_operation_resolution *,
	if (_T)
		selinux_label_operation_resolution_ptr_free(_T))

static bool selinux_avc_chain_snapshot_valid(
	const struct selinux_avc_chain_snapshot *chain)
{
	u16 i;

	if (!chain || !chain->count)
		return false;
	for (i = 0; i < chain->count; i++) {
		const struct cred_security_struct *crsec =
			selinux_cred(chain->cred[i]);
		const struct cred_security_struct *parent =
			i + 1 < chain->count ?
				selinux_cred(chain->cred[i + 1]) : NULL;
		struct selinux_state *state = crsec->state;

		if (!state || !state->label_domain ||
		    state->depth != state->label_domain->depth ||
		    state->depth != chain->count - i - 1 ||
		    (parent && (crsec->parent_cred != chain->cred[i + 1] ||
				state->parent != parent->state ||
				state->label_domain->parent !=
					parent->state->label_domain)) ||
		    (!parent && (crsec->parent_cred || state->parent ||
				 state->label_domain->parent)) ||
		    !selinux_policy_snapshot_valid(state, &chain->policy[i]))
			return false;
	}
	return true;
}

static int selinux_avc_chain_snapshot_read(
	const struct cred *cred, struct selinux_avc_chain_snapshot *chain)
{
	u16 count = 0;
	int rc;

	if (!chain->policy)
		return -EINVAL;
	while (cred) {
		const struct cred_security_struct *crsec = selinux_cred(cred);

		if (count >= ARRAY_SIZE(chain->cred))
			return -E2BIG;
		if (!crsec->state || !crsec->state->label_domain)
			return -EXDEV;
		chain->cred[count] = cred;
		rc = selinux_policy_snapshot_read(crsec->state,
						  &chain->policy[count]);
		if (rc)
			return rc;
		count++;
		cred = crsec->parent_cred;
	}
	chain->count = count;
	return selinux_avc_chain_snapshot_valid(chain) ? 0 : -ESTALE;
}

int cred_label_has_perm(const struct cred *cred, u32 tsid,
			struct selinux_label_ref *label,
			const struct selinux_label_view *view, u16 tclass,
			u32 requested, struct common_audit_data *ad)
{
	struct selinux_avc_transaction_workspace *workspace;
	struct selinux_avc_chain_snapshot chain;
	struct selinux_avc_audit_work *work __free(kfree) = NULL;
	unsigned int retry;
	int rc = -ESTALE;

	if (!label || !view)
		return -EOPNOTSUPP;
	work = kzalloc_obj(*work, GFP_ATOMIC | __GFP_NOWARN);
	if (!work)
		return -ENOMEM;
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1,
		GFP_ATOMIC | __GFP_NOWARN);
	if (!workspace)
		return -ENOMEM;
	chain.policy = work->snapshots;
	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		struct selinux_label_operation_resolution *operation
			__free(selinux_label_operation_resolution_ptr_put) =
			kzalloc_obj(*operation, GFP_ATOMIC | __GFP_NOWARN);
		u16 i;

		if (!operation) {
			rc = -ENOMEM;
			break;
		}
		rc = selinux_avc_chain_snapshot_read(cred, &chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_label_view_resolve_operation(
			view, label, tsid,
			selinux_cred(chain.cred[0])->state->label_domain, operation);
		if (rc)
			break;
		for (i = 0; i < chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain.cred[i]);
			u16 depth = crsec->state->label_domain->depth;

			if (operation->labels.domain_id[depth] !=
				    crsec->state->label_domain->id ||
			    !operation->labels.sid[depth]) {
				rc = -EOPNOTSUPP;
				break;
			}
			work->provenance[i] = (struct selinux_avc_provenance) {
				.label = label,
				.view = view,
				.map_generation = operation->map_generation[depth],
				.source = SELINUX_LABEL_SOURCE_UNSPECIFIED,
			};
			work->levels[i] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = operation->labels.sid[depth],
				.tclass = tclass,
				.requested = requested,
				.provenance = &work->provenance[i],
			};
		}
		if (rc)
			break;
		rc = selinux_avc_transaction_has_perm_workspace(
			work->levels, chain.policy, chain.count, ad, workspace);
		if (rc == -ESTALE || !selinux_avc_chain_snapshot_valid(&chain)) {
			rc = -ESTALE;
			continue;
		}
		break;
	}
	selinux_avc_transaction_workspace_free(workspace);
	return rc;
}

int cred_label_has_perm_noaudit(const struct cred *cred, u32 tsid,
				struct selinux_label_ref *label,
				const struct selinux_label_view *view, u16 tclass,
				u32 requested, struct av_decision *avd)
{
	struct selinux_avc_chain_snapshot chain;
	struct selinux_policy_snapshot *snapshots __free(kfree) = NULL;
	unsigned int retry;
	int rc = -ESTALE;

	if (!label || !view) {
		av_decision_fail_closed(avd);
		return -EOPNOTSUPP;
	}
	snapshots = kcalloc(SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1,
			    sizeof(*snapshots), GFP_ATOMIC | __GFP_NOWARN);
	if (!snapshots) {
		av_decision_fail_closed(avd);
		return -ENOMEM;
	}
	chain.policy = snapshots;

	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		struct selinux_label_operation_resolution *operation
			__free(selinux_label_operation_resolution_ptr_put) =
			kzalloc_obj(*operation, GFP_ATOMIC | __GFP_NOWARN);
		bool first = true;
		u16 i;

		if (!operation) {
			rc = -ENOMEM;
			break;
		}
		rc = selinux_avc_chain_snapshot_read(cred, &chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_label_view_resolve_operation(
			view, label, tsid,
			selinux_cred(chain.cred[0])->state->label_domain, operation);
		if (rc)
			break;
		for (i = 0; i < chain.count; i++) {
			struct cred_security_struct *crsec =
				selinux_cred(chain.cred[i]);
			struct selinux_state *state = crsec->state;
			struct av_decision tmp_avd;
			u16 depth = state->label_domain->depth;

			if (depth > operation->labels.max_depth ||
			    operation->labels.domain_id[depth] !=
				    state->label_domain->id ||
			    !operation->labels.sid[depth]) {
				rc = -EOPNOTSUPP;
				break;
			}
			rc = avc_has_perm_noaudit(
				state, crsec->sid, operation->labels.sid[depth], tclass,
				requested, 0, &tmp_avd);
			if (tmp_avd.seqno != chain.policy[i].seqno ||
			    !selinux_policy_snapshot_valid(state,
							   &chain.policy[i])) {
				rc = -ESTALE;
				break;
			}
			if (first) {
				*avd = tmp_avd;
				first = false;
			} else {
				avd->allowed &= tmp_avd.allowed;
				avd->auditallow |= tmp_avd.auditallow;
				avd->auditdeny |= tmp_avd.auditdeny;
				avd->flags &= tmp_avd.flags;
			}
			if (rc)
				break;
		}
		if (rc == -ESTALE ||
		    !selinux_avc_chain_snapshot_valid(&chain))
			continue;
		if (!first)
			return rc;
		rc = -EINVAL;
		break;
	}
	av_decision_fail_closed(avd);
	return rc;
}

int cred_label_has_extended_perms(const struct cred *cred, u32 tsid,
				  struct selinux_label_ref *label,
				  const struct selinux_label_view *view,
				  u16 tclass, u32 requested, u8 driver,
				  u8 base_perm, u8 xperm,
				  struct common_audit_data *ad)
{
	struct selinux_avc_chain_snapshot chain;
	struct selinux_avc_audit_work *work __free(kfree) = NULL;
	unsigned int retry;
	int rc = -ESTALE;

	if (!label || !view)
		return -EOPNOTSUPP;
	work = kzalloc(sizeof(*work), GFP_ATOMIC | __GFP_NOWARN);
	if (!work)
		return -ENOMEM;
	chain.policy = work->snapshots;

	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		struct selinux_label_operation_resolution *operation
			__free(selinux_label_operation_resolution_ptr_put) =
			kzalloc_obj(*operation, GFP_ATOMIC | __GFP_NOWARN);
		struct selinux_avc_level *levels = work->levels;
		struct av_decision *decisions = work->decisions;
		struct avc_xperms_audit_decision *xdecisions = work->xdecisions;
		int first_rc = 0;
		u16 i;

		if (!operation)
			return -ENOMEM;
		rc = selinux_avc_chain_snapshot_read(cred, &chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = selinux_label_view_resolve_operation(
			view, label, tsid,
			selinux_cred(chain.cred[0])->state->label_domain, operation);
		if (rc)
			return rc;
		for (i = 0; i < chain.count; i++) {
			struct cred_security_struct *crsec =
				selinux_cred(chain.cred[i]);
			struct selinux_state *state = crsec->state;
			u16 depth = state->label_domain->depth;

			if (depth > operation->labels.max_depth ||
			    operation->labels.domain_id[depth] !=
				    state->label_domain->id ||
			    !operation->labels.sid[depth]) {
				rc = -EOPNOTSUPP;
				break;
			}
			rc = avc_has_extended_perms_noaudit_internal(
				state, &chain.policy[i], crsec->sid,
				operation->labels.sid[depth], tclass, requested, driver,
				base_perm, xperm, &xdecisions[i]);
			levels[i].state = state;
			levels[i].ssid = crsec->sid;
			levels[i].tsid = operation->labels.sid[depth];
			levels[i].tclass = tclass;
			levels[i].requested = requested;
			selinux_avc_level_set_provenance(&levels[i],
						       &work->provenance[i], label, view,
						       SELINUX_LABEL_SOURCE_UNSPECIFIED);
			work->provenance[i].map_generation =
				operation->map_generation[depth];
			decisions[i].allowed = requested & ~xdecisions[i].denied;
			if (rc && !first_rc)
				first_rc = rc;
			if (rc && rc != -EACCES)
				break;
		}
		if (rc == -ESTALE ||
		    !selinux_avc_chain_snapshot_valid(&chain))
			continue;
		if (i != chain.count)
			return rc;
		if (selinux_avc_levels_denied(levels, decisions, chain.count)) {
			int audit_rc = selinux_avc_host_aggregate(
				levels, chain.policy, decisions, chain.count, ad);

			return audit_rc ? audit_rc : first_rc;
		}
		for (i = chain.count; i-- > 0;) {
			struct cred_security_struct *crsec =
				selinux_cred(chain.cred[i]);
			u16 depth = crsec->state->label_domain->depth;
			int audit_rc;

			audit_rc = avc_xperms_audit_decision(
				crsec->state, crsec->sid, operation->labels.sid[depth],
				tclass, requested, &xdecisions[i], ad);
			if (audit_rc && !first_rc)
				first_rc = audit_rc;
		}
		return first_rc;
	}
	return -ESTALE;
}

static int __cred_pathless_has_perm(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection, u16 tclass,
	u32 requested, struct common_audit_data *ad)
{
	struct selinux_avc_chain_snapshot chain;
	struct selinux_avc_audit_work *work __free(kfree) = NULL;
	unsigned int retry;
	int rc = -ESTALE;

	if (!projection)
		return -EOPNOTSUPP;
	work = kzalloc(sizeof(*work), GFP_ATOMIC | __GFP_NOWARN);
	if (!work)
		return -ENOMEM;
	chain.policy = work->snapshots;
	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		struct selinux_pathless_chain_resolution *line
			__free(selinux_pathless_chain_resolution_ptr_put) =
			kzalloc_obj(*line, GFP_ATOMIC | __GFP_NOWARN);
		struct selinux_avc_level *levels = work->levels;
		struct av_decision *decisions = work->decisions;
		int first_rc = 0;
		u16 i;

		if (!line)
			return -ENOMEM;

		rc = selinux_avc_chain_snapshot_read(cred, &chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = selinux_pathless_projection_resolve_cred_chain(
			projection, chain.cred, chain.policy, chain.count, line);
		if (rc)
			return rc;
		for (i = 0; i < chain.count; i++) {
			struct cred_security_struct *crsec =
				selinux_cred(chain.cred[i]);
			struct selinux_pathless_resolution resolved;
			struct av_decision decision;
			int decision_rc;

			resolved = line->level[crsec->state->label_domain->depth];
			decision_rc = avc_has_perm_noaudit(
				crsec->state, crsec->sid, resolved.sid,
				tclass ? tclass : resolved.sclass, requested, 0,
				&decision);
			levels[i].state = crsec->state;
			levels[i].ssid = crsec->sid;
			levels[i].tsid = resolved.sid;
			levels[i].tclass = tclass ? tclass : resolved.sclass;
			levels[i].requested = requested;
			selinux_avc_level_set_provenance(
				&levels[i], &work->provenance[i], projection->label,
				projection->view, projection->source);
			work->provenance[i].map_generation = resolved.map_generation;
			decisions[i] = decision;
			if (decision.seqno != chain.policy[i].seqno ||
			    !selinux_policy_snapshot_valid(crsec->state,
						   &chain.policy[i])) {
				rc = -ESTALE;
				break;
			}
			if (decision_rc && !first_rc)
				first_rc = decision_rc;
			if (decision_rc && decision_rc != -EACCES) {
				rc = decision_rc;
				break;
			}
		}
		if (rc == -ESTALE ||
		    !selinux_avc_chain_snapshot_valid(&chain))
			continue;
		if (i != chain.count)
			return rc;
		if (selinux_avc_levels_denied(levels, decisions, chain.count)) {
			int audit_rc = selinux_avc_host_aggregate(
				levels, chain.policy, decisions, chain.count, ad);

			return audit_rc ? audit_rc : first_rc;
		}
		for (i = chain.count; i-- > 0;) {
			struct cred_security_struct *crsec =
				selinux_cred(chain.cred[i]);
			struct selinux_pathless_resolution resolved;
			struct av_decision decision;
			int decision_rc;
			int audit_rc;

			resolved = line->level[crsec->state->label_domain->depth];
			decision_rc = avc_has_perm_noaudit(
				crsec->state, crsec->sid, resolved.sid,
				tclass ? tclass : resolved.sclass, requested, 0,
				&decision);
			if (decision.seqno != chain.policy[i].seqno ||
			    !selinux_policy_snapshot_valid(crsec->state,
						   &chain.policy[i]))
				return -ESTALE;
			if (decision_rc && decision_rc != -EACCES)
				return decision_rc;
			audit_rc = avc_audit(
				crsec->state, crsec->sid, resolved.sid,
				tclass ? tclass : resolved.sclass, requested,
				&decision, decision_rc, ad);
			if (audit_rc && !first_rc)
				first_rc = audit_rc;
		}
		return first_rc;
	}
	return -ESTALE;
}

int cred_pathless_has_perm(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection, u32 requested,
	struct common_audit_data *ad)
{
	return __cred_pathless_has_perm(cred, projection, 0, requested, ad);
}

int cred_pathless_has_perm_class(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection, u16 tclass,
	u32 requested, struct common_audit_data *ad)
{
	if (!tclass)
		return -EINVAL;
	return __cred_pathless_has_perm(cred, projection, tclass, requested, ad);
}

int cred_pathless_relation_has_perm(
	const struct cred *cred,
	const struct selinux_pathless_projection *source,
	const struct selinux_pathless_projection *target, u16 source_tclass,
	u16 tclass,
	u32 requested, struct common_audit_data *ad)
{
	struct selinux_avc_chain_snapshot chain;
	struct selinux_avc_audit_work *work __free(kfree) = NULL;
	unsigned int retry;
	int rc = -ESTALE;

	if (!source || !target || !source_tclass || !tclass)
		return -EOPNOTSUPP;
	work = kzalloc(sizeof(*work), GFP_ATOMIC | __GFP_NOWARN);
	if (!work)
		return -ENOMEM;
	chain.policy = work->snapshots;
	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		struct selinux_pathless_chain_resolution *source_line
			__free(selinux_pathless_chain_resolution_ptr_put) =
			kzalloc_obj(*source_line, GFP_ATOMIC | __GFP_NOWARN);
		struct selinux_pathless_chain_resolution *target_line
			__free(selinux_pathless_chain_resolution_ptr_put) =
			kzalloc_obj(*target_line, GFP_ATOMIC | __GFP_NOWARN);
		struct selinux_avc_level *levels = work->levels;
		struct av_decision *decisions = work->decisions;
		int first_rc = 0;
		u16 i;

		if (!source_line || !target_line)
			return -ENOMEM;
		rc = selinux_avc_chain_snapshot_read(cred, &chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = selinux_pathless_projection_resolve_cred_chain(
			source, chain.cred, chain.policy, chain.count, source_line);
		if (rc)
			return rc;
		rc = selinux_pathless_projection_resolve_cred_chain(
			target, chain.cred, chain.policy, chain.count, target_line);
		if (rc)
			return rc;
		for (i = 0; i < chain.count; i++) {
			struct cred_security_struct *crsec =
				selinux_cred(chain.cred[i]);
			struct selinux_pathless_resolution source_resolved;
			struct selinux_pathless_resolution target_resolved;
			struct av_decision decision;
			int decision_rc;

			source_resolved = source_line->level[
				crsec->state->label_domain->depth];
			target_resolved = target_line->level[
				crsec->state->label_domain->depth];
			if (source_resolved.sclass != source_tclass ||
			    target_resolved.sclass != tclass) {
				rc = -EOPNOTSUPP;
				break;
			}
			decision_rc = avc_has_perm_noaudit(
				crsec->state, source_resolved.sid,
				target_resolved.sid, tclass, requested, 0,
				&decision);
			levels[i].state = crsec->state;
			levels[i].ssid = source_resolved.sid;
			levels[i].tsid = target_resolved.sid;
			levels[i].tclass = tclass;
			levels[i].requested = requested;
			selinux_avc_level_set_provenance(
				&levels[i], &work->provenance[i], target->label,
				target->view, target->source);
			work->provenance[i].map_generation =
				target_resolved.map_generation;
			decisions[i] = decision;
			if (decision.seqno != chain.policy[i].seqno ||
			    !selinux_policy_snapshot_valid(crsec->state,
						   &chain.policy[i])) {
				rc = -ESTALE;
				break;
			}
			if (decision_rc && !first_rc)
				first_rc = decision_rc;
			if (decision_rc && decision_rc != -EACCES) {
				rc = decision_rc;
				break;
			}
		}
		if (rc == -ESTALE ||
		    !selinux_avc_chain_snapshot_valid(&chain))
			continue;
		if (i != chain.count)
			return rc;
		if (selinux_avc_levels_denied(levels, decisions, chain.count)) {
			int audit_rc = selinux_avc_host_aggregate(
				levels, chain.policy, decisions, chain.count, ad);

			return audit_rc ? audit_rc : first_rc;
		}
		for (i = chain.count; i-- > 0;) {
			struct cred_security_struct *crsec =
				selinux_cred(chain.cred[i]);
			struct selinux_pathless_resolution source_resolved;
			struct selinux_pathless_resolution target_resolved;
			struct av_decision decision;
			int decision_rc;
			int audit_rc;

			source_resolved = source_line->level[
				crsec->state->label_domain->depth];
			target_resolved = target_line->level[
				crsec->state->label_domain->depth];
			if (source_resolved.sclass != source_tclass ||
			    target_resolved.sclass != tclass)
				return -EOPNOTSUPP;
			decision_rc = avc_has_perm_noaudit(
				crsec->state, source_resolved.sid,
				target_resolved.sid, tclass, requested, 0,
				&decision);
			if (decision.seqno != chain.policy[i].seqno ||
			    !selinux_policy_snapshot_valid(crsec->state,
						   &chain.policy[i]))
				return -ESTALE;
			if (decision_rc && decision_rc != -EACCES)
				return decision_rc;
			audit_rc = avc_audit(
				crsec->state, source_resolved.sid,
				target_resolved.sid, tclass, requested,
				&decision, decision_rc, ad);
			if (audit_rc && !first_rc)
				first_rc = audit_rc;
		}
		return first_rc;
	}
	return -ESTALE;
}

int cred_pathless_has_perm_noaudit(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection, u32 requested,
	struct av_decision *avd)
{
	struct selinux_avc_chain_snapshot chain;
	struct selinux_policy_snapshot *snapshots __free(kfree) = NULL;
	unsigned int retry;
	int rc = -ESTALE;

	if (!projection) {
		av_decision_fail_closed(avd);
		return -EOPNOTSUPP;
	}
	snapshots = kcalloc(SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1,
			    sizeof(*snapshots), GFP_ATOMIC | __GFP_NOWARN);
	if (!snapshots) {
		av_decision_fail_closed(avd);
		return -ENOMEM;
	}
	chain.policy = snapshots;
	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		struct selinux_pathless_chain_resolution *line
			__free(selinux_pathless_chain_resolution_ptr_put) =
			kzalloc_obj(*line, GFP_ATOMIC | __GFP_NOWARN);
		bool first = true;
		u16 i;

		if (!line) {
			rc = -ENOMEM;
			break;
		}
		rc = selinux_avc_chain_snapshot_read(cred, &chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_pathless_projection_resolve_cred_chain(
			projection, chain.cred, chain.policy, chain.count, line);
		if (rc)
			break;
		for (i = 0; i < chain.count; i++) {
			struct cred_security_struct *crsec =
				selinux_cred(chain.cred[i]);
			struct selinux_pathless_resolution resolved;
			struct av_decision tmp_avd;

			resolved = line->level[crsec->state->label_domain->depth];
			rc = avc_has_perm_noaudit(
				crsec->state, crsec->sid, resolved.sid,
				resolved.sclass, requested, 0, &tmp_avd);
			if (tmp_avd.seqno != chain.policy[i].seqno ||
			    !selinux_policy_snapshot_valid(crsec->state,
							   &chain.policy[i])) {
				rc = -ESTALE;
				break;
			}
			if (first) {
				*avd = tmp_avd;
				first = false;
			} else {
				avd->allowed &= tmp_avd.allowed;
				avd->auditallow |= tmp_avd.auditallow;
				avd->auditdeny |= tmp_avd.auditdeny;
				avd->flags &= tmp_avd.flags;
			}
			if (rc)
				break;
		}
		if (rc == -ESTALE ||
		    !selinux_avc_chain_snapshot_valid(&chain))
			continue;
		if (!first)
			return rc;
		rc = -EINVAL;
		break;
	}
	av_decision_fail_closed(avd);
	return rc;
}

int cred_pathless_has_extended_perms(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection, u32 requested,
	u8 driver, u8 base_perm, u8 xperm, struct common_audit_data *ad)
{
	struct selinux_avc_chain_snapshot chain;
	struct selinux_avc_audit_work *work __free(kfree) = NULL;
	unsigned int retry;
	int rc = -ESTALE;

	if (!projection)
		return -EOPNOTSUPP;
	work = kzalloc(sizeof(*work), GFP_ATOMIC | __GFP_NOWARN);
	if (!work)
		return -ENOMEM;
	chain.policy = work->snapshots;
	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		struct selinux_pathless_chain_resolution *line
			__free(selinux_pathless_chain_resolution_ptr_put) =
			kzalloc_obj(*line, GFP_ATOMIC | __GFP_NOWARN);
		struct selinux_avc_level *levels = work->levels;
		struct av_decision *decisions = work->decisions;
		struct avc_xperms_audit_decision *xdecisions = work->xdecisions;
		int first_rc = 0;
		u16 i;

		if (!line)
			return -ENOMEM;
		rc = selinux_avc_chain_snapshot_read(cred, &chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = selinux_pathless_projection_resolve_cred_chain(
			projection, chain.cred, chain.policy, chain.count, line);
		if (rc)
			return rc;
		for (i = 0; i < chain.count; i++) {
			struct cred_security_struct *crsec =
				selinux_cred(chain.cred[i]);
			struct selinux_pathless_resolution resolved;

			resolved = line->level[crsec->state->label_domain->depth];
			rc = avc_has_extended_perms_noaudit_internal(
				crsec->state, &chain.policy[i], crsec->sid,
				resolved.sid, resolved.sclass, requested, driver,
				base_perm, xperm, &xdecisions[i]);
			levels[i].state = crsec->state;
			levels[i].ssid = crsec->sid;
			levels[i].tsid = resolved.sid;
			levels[i].tclass = resolved.sclass;
			levels[i].requested = requested;
			selinux_avc_level_set_provenance(
				&levels[i], &work->provenance[i], projection->label,
				projection->view,
				projection->source);
			work->provenance[i].map_generation = resolved.map_generation;
			decisions[i].allowed = requested & ~xdecisions[i].denied;
			if (rc && !first_rc)
				first_rc = rc;
			if (rc && rc != -EACCES)
				break;
		}
		if (rc == -ESTALE ||
		    !selinux_avc_chain_snapshot_valid(&chain))
			continue;
		if (i != chain.count)
			return rc;
		if (selinux_avc_levels_denied(levels, decisions, chain.count)) {
			int audit_rc = selinux_avc_host_aggregate(
				levels, chain.policy, decisions, chain.count, ad);

			return audit_rc ? audit_rc : first_rc;
		}
		for (i = chain.count; i-- > 0;) {
			struct cred_security_struct *crsec =
				selinux_cred(chain.cred[i]);
			struct selinux_pathless_resolution resolved;
			int audit_rc;

			resolved = line->level[crsec->state->label_domain->depth];
			audit_rc = avc_xperms_audit_decision(
				crsec->state, crsec->sid, resolved.sid,
				resolved.sclass, requested, &xdecisions[i], ad);
			if (audit_rc && !first_rc)
				first_rc = audit_rc;
		}
		return first_rc;
	}
	return -ESTALE;
}
#endif

/**
 * cred_obj_has_perm - Check and audit permissions on a (ssid, tsid) pair
 * @cred: subject credentials
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @ad: auxiliary audit data
 *
 * Check permissions between a source SID @ssid and a target SID @tsid for
 * @cred's namespace and all ancestors to determine whether the
 * @requested permissions are granted.
 * Audit the granting or denial of permissions in accordance with the policy.
 * Return %0 if all @requested permissions are granted, -%EACCES if any
 * permissions are denied, or another -errno upon other errors.
 * DO NOT USE when checking permissions involving cred/task SIDs; this
 * helper is only for object-to-object checks.
 */
int cred_obj_has_perm(const struct cred *cred, u32 ssid, u32 tsid,
		      u16 tclass, u32 requested,
		      struct common_audit_data *ad)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_level levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	u16 count = 0;

	while (cred) {
		struct cred_security_struct *crsec = selinux_cred(cred);

		if (count >= ARRAY_SIZE(levels))
			return -E2BIG;
		levels[count].state = crsec->state;
		levels[count].ssid = ssid;
		levels[count].tsid = tsid;
		levels[count].tclass = tclass;
		levels[count].requested = requested;
		count++;
		cred = crsec->parent_cred;
	}
	return selinux_avc_levels_has_perm(levels, count, ad);
#else
	struct cred_security_struct *crsec;
	struct selinux_state *state;
	int rc;

	do {
		crsec = selinux_cred(cred);
		state = crsec->state;
		rc = avc_has_perm(state, ssid, tsid, tclass, requested, ad);
		if (rc)
			return rc;

		cred = crsec->parent_cred;
	} while (cred);

	return 0;
#endif
}

/**
 * cred_ssid_has_perm - Check and audit permissions on a (ssid, tsid) pair
 * @cred: subject credentials
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @ad: auxiliary audit data
 *
 * Check permissions between a source SID @ssid and a target SID @tsid for
 * @cred's namespace and check between the parent cred's SID and %tsid
 * for all ancestors to determine whether the @requested permissions are
 * granted.
 * Audit the granting or denial of permissions in accordance with the policy.
 * Return %0 if all @requested permissions are granted, -%EACCES if any
 * permissions are denied, or another -errno upon other errors.
 * DO NOT USE when checking permissions involving cred/task SIDs; this
 * helper is only for socket and IPC checks.
 */
int cred_ssid_has_perm(const struct cred *cred, u32 ssid, u32 tsid, u16 tclass,
		       u32 requested, struct common_audit_data *ad)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_level levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	u16 count = 0;
	bool leaf = true;

	while (cred) {
		struct cred_security_struct *crsec = selinux_cred(cred);

		if (count >= ARRAY_SIZE(levels))
			return -E2BIG;
		levels[count].state = crsec->state;
		levels[count].ssid = leaf ? ssid : crsec->sid;
		levels[count].tsid = tsid;
		levels[count].tclass = tclass;
		levels[count].requested = requested;
		count++;
		leaf = false;
		cred = crsec->parent_cred;
	}
	return selinux_avc_levels_has_perm(levels, count, ad);
#else
	struct cred_security_struct *crsec;
	struct selinux_state *state;
	int rc;

	/* Check using the provided ssid in the current namespace. */
	crsec = selinux_cred(cred);
	state = crsec->state;
	rc = avc_has_perm(state, ssid, tsid, tclass, requested, ad);
	if (rc)
		return rc;

	cred = crsec->parent_cred;
	while (cred) {
		/*
		 * In all ancestor namespaces, use the task SID from
		 * the corresponding credential as the subject SID.
		 */
		crsec = selinux_cred(cred);
		state = crsec->state;
		ssid = crsec->sid;
		rc = avc_has_perm(state, ssid, tsid, tclass, requested, ad);
		if (rc)
			return rc;

		cred = crsec->parent_cred;
	}

	return 0;
#endif
}

#ifndef CONFIG_SECURITY_SELINUX_NS
static u32 cred_sid_for_state(const struct cred *cred,
			      const struct selinux_state *state)
{
	const struct cred_security_struct *crsec;
	u32 sid;

	crsec = selinux_cred(cred);
	while (crsec->state != state && crsec->parent_cred)
		crsec = selinux_cred(crsec->parent_cred);
	if (crsec->state == state)
		sid = crsec->sid;
	else
		sid = SECINITSID_UNLABELED;
	return sid;
}
#endif

/**
 * cred_sid_chain_equal - Compare complete policy/SID credential chains
 * @left: first credential
 * @right: second credential
 *
 * Return: true only when both credentials carry the same state and SID at
 * every depth and both chains end together.
 */
bool cred_sid_chain_equal(const struct cred *left, const struct cred *right)
{
	while (left && right) {
		const struct cred_security_struct *left_sec = selinux_cred(left);
		const struct cred_security_struct *right_sec = selinux_cred(right);

		if (left_sec->state != right_sec->state ||
		    left_sec->sid != right_sec->sid)
			return false;
		left = left_sec->parent_cred;
		right = right_sec->parent_cred;
	}

	return !left && !right;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
/*
 * Binder transaction authorization is one policy transaction: an optional
 * actor -> sender impersonate edge followed by the sender -> receiver call
 * edge.  Keeping both edges in one vector prevents a policy reload from
 * assembling an allow out of decisions made in different generations.
 */
int cred_binder_transaction_has_perm(const struct cred *actor,
				     const struct cred *from,
				     const struct cred *to)
{
	const u16 capacity = 2 * (SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1);
	struct selinux_avc_transaction_workspace *workspace;
	struct selinux_policy_snapshot *snapshots;
	struct selinux_avc_level *levels;
	unsigned int retry;
	u16 count, edge_count, i;
	int rc = -ESTALE;

	if (!actor || !from || !to)
		return -EINVAL;
	levels = kcalloc(capacity, sizeof(*levels),
			 GFP_ATOMIC | __GFP_NOWARN);
	if (!levels)
		return -ENOMEM;
	snapshots = kcalloc(capacity, sizeof(*snapshots),
			    GFP_ATOMIC | __GFP_NOWARN);
	if (!snapshots) {
		rc = -ENOMEM;
		goto out_levels;
	}
	workspace = selinux_avc_transaction_workspace_alloc(
		capacity, GFP_ATOMIC | __GFP_NOWARN);
	if (!workspace) {
		rc = -ENOMEM;
		goto out_snapshots;
	}

	count = 0;
	if (!cred_sid_chain_equal(actor, from)) {
		rc = selinux_cred_pair_levels(
			actor, actor, from, SECCLASS_BINDER,
			BINDER__IMPERSONATE, levels, capacity, &edge_count);
		if (rc)
			goto out_workspace;
		count = edge_count;
	}
	rc = selinux_cred_pair_levels(from, from, to, SECCLASS_BINDER,
				      BINDER__CALL, levels + count,
				      capacity - count, &edge_count);
	if (rc)
		goto out_workspace;
	count += edge_count;

	for (retry = 0; retry < SELINUX_AVC_CHAIN_RETRIES; retry++) {
		bool stale = false;

		for (i = 0; i < count; i++) {
			rc = selinux_avc_perm_snapshot_read(
				levels[i].state, &snapshots[i], i);
			if (rc == -EAGAIN || rc == -ESTALE) {
				stale = true;
				break;
			}
			if (rc)
				goto out_workspace;
		}
		if (stale)
			continue;
		rc = selinux_avc_transaction_has_perm_workspace(
			levels, snapshots, count, NULL, workspace);
		if (rc != -ESTALE)
			break;
	}

out_workspace:
	selinux_avc_transaction_workspace_free(workspace);
out_snapshots:
	kfree(snapshots);
out_levels:
	kfree(levels);
	return rc;
}
#endif

/**
 * cred_other_has_perm - Check and audit permissions on a (cred, other-cred) pair
 * @cred: subject credentials
 * @other: other credentials
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @ad: auxiliary audit data
 *
 * Check permissions between a cred @cred and a task @p for @cred's namespace
 * and all ancestors to determine whether the @requested permissions are
 * granted.
 * Audit the granting or denial of permissions in accordance with the policy.
 * Return %0 if all @requested permissions are granted, -%EACCES if any
 * permissions are denied, or another -errno upon other errors.
 */
int cred_other_has_perm(const struct cred *cred, const struct cred *other,
			u16 tclass, u32 requested,
			struct common_audit_data *ad)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_level levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	u16 count;
	int rc;

	rc = selinux_cred_pair_levels(cred, cred, other, tclass, requested,
				      levels, ARRAY_SIZE(levels), &count);
	return rc ?: selinux_avc_levels_has_perm(levels, count, ad);
#else
	struct cred_security_struct *crsec;
	struct selinux_state *state;
	u32 ssid;
	u32 tsid;
	int rc;

	do {
		crsec = selinux_cred(cred);
		ssid = crsec->sid;
		state = crsec->state;
		tsid = cred_sid_for_state(other, state);

		rc = avc_has_perm(state, ssid, tsid, tclass, requested, ad);
		if (rc)
			return rc;

		cred = crsec->parent_cred;
	} while (cred);

	return 0;
#endif
}

/**
 * selinux_state_has_perm - Check and audit permissions on a (ssid, tsid) pair
 * @state: SELinux state
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @ad: auxiliary audit data
 *
 * Check permissions between a source SID @ssid and a target SID @tsid for
 * @state and all ancestors to determine whether the @requested permissions
 * are granted, interpreting the permissions based on @tclass.
 * For the ancestor checks, use the SID of the creator of the namespace
 * as the source SID of the check.
 * Audit the granting or denial of permissions in accordance with the policy.
 * Return %0 if all @requested permissions are granted, -%EACCES if any
 * permissions are denied, or another -errno upon other errors.
 * DO NOT USE when a cred is available; use cred_*_has_perm() instead.
 */
int selinux_state_has_perm(struct selinux_state *state, u32 ssid, u32 tsid,
			   u16 tclass, u32 requested,
			   struct common_audit_data *ad)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_level levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	u16 count = 0;

	while (state) {
		if (count >= ARRAY_SIZE(levels))
			return -E2BIG;
		levels[count].state = state;
		levels[count].ssid = ssid;
		levels[count].tsid = tsid;
		levels[count].tclass = tclass;
		levels[count].requested = requested;
		count++;
		ssid = state->creator_sid;
		state = state->parent;
	}
	return selinux_avc_levels_has_perm(levels, count, ad);
#else
	int rc;

	do {
		rc = avc_has_perm(state, ssid, tsid, tclass, requested, ad);
		if (rc)
			return rc;

		ssid = state->creator_sid;
		state = state->parent;
	} while (state);

	return 0;
#endif
}

u32 avc_policy_seqno(struct selinux_state *state)
{
	return state->avc->avc_cache.latest_notif;
}
