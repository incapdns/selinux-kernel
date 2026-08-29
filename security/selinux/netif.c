// SPDX-License-Identifier: GPL-2.0-only
/*
 * Network interface table.
 *
 * Network interfaces (devices) do not have a security field, so we
 * maintain a table associating each interface with a SID.
 *
 * Author: James Morris <jmorris@redhat.com>
 *
 * Copyright (C) 2003 Red Hat, Inc., James Morris <jmorris@redhat.com>
 * Copyright (C) 2007 Hewlett-Packard Development Company, L.P.
 *		      Paul Moore <paul@paul-moore.com>
 */
#include <linux/init.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <net/net_namespace.h>

#include "initcalls.h"
#include "global_sidtab.h"
#include "security.h"
#include "objsec.h"
#include "netif.h"

#define SEL_NETIF_HASH_SIZE	64
#define SEL_NETIF_HASH_MAX	1024

struct sel_netif {
	struct list_head list;
	struct list_head lru;
	struct netif_security_struct nsec;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *sid_handle;
#endif
	struct rcu_head rcu_head;
};

static u32 sel_netif_total;
static DEFINE_SPINLOCK(sel_netif_lock);
static struct list_head sel_netif_hash[SEL_NETIF_HASH_SIZE];
static LIST_HEAD(sel_netif_lru);

/**
 * sel_netif_hashfn - Hashing function for the interface table
 * @ns: the network namespace
 * @ifindex: the network interface
 *
 * Description:
 * This is the hashing function for the network interface table, it returns the
 * bucket number for the given interface.
 *
 */
static inline u32 sel_netif_hashfn(const struct net *ns, int ifindex)
{
	return (((uintptr_t)ns + ifindex) & (SEL_NETIF_HASH_SIZE - 1));
}

/**
 * sel_netif_find - Search for an interface record
 * @domain_id: stable SELinux label-domain identity
 * @snapshot: immutable policy generation
 * @ns: the network namespace
 * @ifindex: the network interface
 *
 * Description:
 * Search the network interface table and return the record matching @ifindex.
 * If an entry can not be found in the table return NULL.
 *
 */
static inline struct sel_netif *sel_netif_find(
	u64 domain_id,
	const struct selinux_policy_snapshot *snapshot, const struct net *ns,
	int ifindex)
{
	u32 idx = sel_netif_hashfn(ns, ifindex);
	struct sel_netif *netif;

	list_for_each_entry_rcu(netif, &sel_netif_hash[idx], list)
		if (net_eq(netif->nsec.ns, ns) &&
		    netif->nsec.ifindex == ifindex &&
#ifdef CONFIG_SECURITY_SELINUX_NS
		    netif->sid_handle &&
		    global_sid_handle_sid(netif->sid_handle) == netif->nsec.sid &&
#endif
		    selinux_policy_cache_key_matches(&netif->nsec.policy,
						     domain_id, snapshot))
			return netif;

	return NULL;
}

/**
 * sel_netif_free - Free an interface record after its RCU grace period
 * @rcu: embedded RCU head
 *
 * Description:
 * Release an interface record after readers can no longer observe it.
 *
 */
static void sel_netif_free(struct rcu_head *rcu)
{
	struct sel_netif *netif = container_of(rcu, struct sel_netif, rcu_head);

#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(netif->sid_handle);
#endif
	kfree(netif);
}

static void sel_netif_destroy(struct sel_netif *netif)
{
	list_del_rcu(&netif->list);
	list_del(&netif->lru);
	sel_netif_total--;
	call_rcu(&netif->rcu_head, sel_netif_free);
}

/**
 * sel_netif_insert - Insert a new interface into the table
 * @netif: the new interface record
 *
 * Description:
 * Add a new interface record to the network interface hash table, evicting
 * the oldest record in O(1) when the global bound has been reached.
 */
static void sel_netif_insert(struct sel_netif *netif)
{
	u32 idx;

	if (sel_netif_total >= SEL_NETIF_HASH_MAX) {
		struct sel_netif *victim;

		victim = list_last_entry(&sel_netif_lru, struct sel_netif, lru);
		sel_netif_destroy(victim);
	}

	idx = sel_netif_hashfn(netif->nsec.ns, netif->nsec.ifindex);
	list_add_rcu(&netif->list, &sel_netif_hash[idx]);
	list_add(&netif->lru, &sel_netif_lru);
	sel_netif_total++;
}

/**
 * sel_netif_sid_slow - Lookup the SID of a network interface using the policy
 * @state: the SELinux state
 * @snapshot: immutable policy generation
 * @ns: the network namespace
 * @ifindex: the network interface
 * @sid: interface SID
 * @out_handle: strong handle paired with @sid
 *
 * Description:
 * This function determines the SID of a network interface by querying the
 * security policy.  The result is added to the network interface table to
 * speedup future queries.  Returns zero on success, negative values on
 * failure.
 *
 */
static int sel_netif_sid_slow(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, struct net *ns,
	int ifindex, u32 *sid,
	struct selinux_global_sid_handle **out_handle)
{
	int ret = 0;
	u64 domain_id = state->label_domain->id;
	struct sel_netif *netif;
	struct sel_netif *new;
	struct net_device *dev;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *sid_handle = NULL;
	struct selinux_global_sid_handle *cache_handle;
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!out_handle)
		return -EINVAL;
	*out_handle = NULL;
#else
	(void)out_handle;
#endif

	/* NOTE: we always use init's network namespace since we don't
	 * currently support containers */

	dev = dev_get_by_index(ns, ifindex);
	if (unlikely(dev == NULL)) {
		pr_warn("SELinux: failure in %s(), invalid network interface (%d)\n",
			__func__, ifindex);
		return -ENOENT;
	}

	spin_lock_bh(&sel_netif_lock);
	netif = sel_netif_find(domain_id, snapshot, ns, ifindex);
	if (netif != NULL) {
		*sid = netif->nsec.sid;
#ifdef CONFIG_SECURITY_SELINUX_NS
		sid_handle = global_sid_handle_dup(netif->sid_handle);
		if (IS_ERR(sid_handle)) {
			ret = PTR_ERR(sid_handle);
			sid_handle = NULL;
		}
#endif
		goto out;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	sid_handle = security_netif_sid_handle(state, dev->name, sid);
	if (IS_ERR(sid_handle)) {
		ret = PTR_ERR(sid_handle);
		sid_handle = NULL;
	} else if (!*sid || global_sid_handle_sid(sid_handle) != *sid) {
		ret = -ESTALE;
	}
#else
	ret = security_netif_sid(state, dev->name, sid);
#endif
	if (ret != 0)
		goto out;
	if (!selinux_policy_snapshot_valid(state, snapshot)) {
		ret = -ESTALE;
		goto out;
	}

	/* If this memory allocation fails still return 0. The SID
	 * is valid, it just won't be added to the cache.
	 */
	new = kmalloc_obj(*new, GFP_ATOMIC);
	if (new) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		cache_handle = global_sid_handle_dup(sid_handle);
		if (IS_ERR(cache_handle)) {
			kfree(new);
			new = NULL;
		}
#endif
	}
	if (new) {
		new->nsec.ns = ns;
		new->nsec.ifindex = ifindex;
		new->nsec.sid = *sid;
		selinux_policy_cache_key_init(&new->nsec.policy, domain_id,
					      snapshot);
#ifdef CONFIG_SECURITY_SELINUX_NS
		new->sid_handle = cache_handle;
#endif
		sel_netif_insert(new);
	}

out:
	spin_unlock_bh(&sel_netif_lock);
	dev_put(dev);
	if (!ret && !selinux_policy_snapshot_valid(state, snapshot))
		ret = -ESTALE;
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!ret && (!sid_handle || !*sid ||
		     global_sid_handle_sid(sid_handle) != *sid))
		ret = -ESTALE;
	if (!ret) {
		*out_handle = sid_handle;
		sid_handle = NULL;
	}
	global_sid_handle_put(sid_handle);
#endif
	if (unlikely(ret && ret != -ESTALE))
		pr_warn("SELinux: failure in %s(), unable to determine network interface label (%d)\n",
			__func__, ifindex);
	return ret;
}

/**
 * sel_netif_sid_snapshot_handle - Lookup the SID of a network interface
 * @state: the SELinux state
 * @snapshot: immutable policy generation
 * @ns: the network namespace
 * @ifindex: the network interface
 * @sid: interface SID
 *
 * Description:
 * This function determines the SID of a network interface using the fastest
 * method possible.  First the interface table is queried, but if an entry
 * can't be found then the policy is queried and the result is added to the
 * table to speedup future queries.  Returns zero on success, negative values
 * on failure.
 *
 */
#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_global_sid_handle *
sel_netif_sid_snapshot_handle(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, struct net *ns,
	int ifindex, u32 *sid)
{
	struct selinux_global_sid_handle *handle;
	struct sel_netif *netif;
	bool valid;
	int rc;

	if (!state || !state->label_domain || !snapshot || !sid ||
	    !snapshot->chain_epoch)
		return ERR_PTR(-EINVAL);

	rcu_read_lock();
	netif = sel_netif_find(state->label_domain->id, snapshot, ns, ifindex);
	if (likely(netif != NULL)) {
		*sid = netif->nsec.sid;
		handle = global_sid_handle_dup(netif->sid_handle);
		valid = selinux_policy_snapshot_valid(state, snapshot);
		rcu_read_unlock();
		if (IS_ERR(handle))
			return handle;
		if (!valid || !*sid || global_sid_handle_sid(handle) != *sid) {
			global_sid_handle_put(handle);
			return ERR_PTR(-ESTALE);
		}
		return handle;
	}
	rcu_read_unlock();

	rc = sel_netif_sid_slow(state, snapshot, ns, ifindex, sid, &handle);
	return rc ? ERR_PTR(rc) : handle;
}

struct selinux_global_sid_handle *
sel_netif_sid_handle(struct selinux_state *state, struct net *ns, int ifindex,
		     u32 *sid)
{
	struct selinux_global_sid_handle *handle;
	struct selinux_policy_snapshot snapshot;
	unsigned int retry;
	int rc;

	for (retry = 0; retry < 3; retry++) {
		rc = selinux_policy_snapshot_read(state, &snapshot);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return ERR_PTR(rc);
		handle = sel_netif_sid_snapshot_handle(
			state, &snapshot, ns, ifindex, sid);
		if (!IS_ERR(handle) || PTR_ERR(handle) != -ESTALE)
			return handle;
	}
	return ERR_PTR(-ESTALE);
}
#endif

int sel_netif_sid_snapshot(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, struct net *ns,
	int ifindex, u32 *sid)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;

	handle = sel_netif_sid_snapshot_handle(state, snapshot, ns, ifindex,
						 sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
#else
	struct sel_netif *netif;
	bool valid;

	if (!state || !state->label_domain || !snapshot ||
	    !snapshot->chain_epoch)
		return -EINVAL;
	rcu_read_lock();
	netif = sel_netif_find(state->label_domain->id, snapshot, ns, ifindex);
	if (likely(netif != NULL)) {
		*sid = netif->nsec.sid;
		valid = selinux_policy_snapshot_valid(state, snapshot);
		rcu_read_unlock();
		return valid ? 0 : -ESTALE;
	}
	rcu_read_unlock();
	return sel_netif_sid_slow(state, snapshot, ns, ifindex, sid, NULL);
#endif
}

int sel_netif_sid(struct selinux_state *state, struct net *ns, int ifindex,
		  u32 *sid)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;

	handle = sel_netif_sid_handle(state, ns, ifindex, sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
#else
	struct selinux_policy_snapshot snapshot;
	unsigned int retry;
	int rc;

	for (retry = 0; retry < 3; retry++) {
		rc = selinux_policy_snapshot_read(state, &snapshot);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = sel_netif_sid_snapshot(state, &snapshot, ns, ifindex, sid);
		if (rc != -ESTALE)
			return rc;
	}
	return -ESTALE;
#endif
}

/**
 * sel_netif_kill - Remove an entry from the network interface table
 * @ns: the network namespace
 * @ifindex: the network interface
 *
 * Description:
 * This function removes the entry matching @ifindex from the network interface
 * table if it exists.
 *
 */
static void sel_netif_kill(const struct net *ns, int ifindex)
{
	struct sel_netif *netif, *tmp;
	u32 idx = sel_netif_hashfn(ns, ifindex);

	spin_lock_bh(&sel_netif_lock);
	list_for_each_entry_safe(netif, tmp, &sel_netif_hash[idx], list)
		if (net_eq(netif->nsec.ns, ns) &&
		    netif->nsec.ifindex == ifindex)
			sel_netif_destroy(netif);
	spin_unlock_bh(&sel_netif_lock);
}

/**
 * sel_netif_flush - Flush the entire network interface table
 *
 * Description:
 * Remove all entries from the network interface table.
 *
 */
void sel_netif_flush(void)
{
	int idx;
	struct sel_netif *netif, *tmp;

	spin_lock_bh(&sel_netif_lock);
	for (idx = 0; idx < SEL_NETIF_HASH_SIZE; idx++)
		list_for_each_entry_safe(netif, tmp, &sel_netif_hash[idx], list)
			sel_netif_destroy(netif);
	spin_unlock_bh(&sel_netif_lock);
}

static int sel_netif_netdev_notifier_handler(struct notifier_block *this,
					     unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event == NETDEV_DOWN || event == NETDEV_UNREGISTER ||
	    event == NETDEV_CHANGENAME)
		sel_netif_kill(dev_net(dev), dev->ifindex);

	return NOTIFY_DONE;
}

static struct notifier_block sel_netif_netdev_notifier = {
	.notifier_call = sel_netif_netdev_notifier_handler,
};

int __init sel_netif_init(void)
{
	int i;

	if (!selinux_enabled_boot)
		return 0;

	for (i = 0; i < SEL_NETIF_HASH_SIZE; i++)
		INIT_LIST_HEAD(&sel_netif_hash[i]);

	register_netdevice_notifier(&sel_netif_netdev_notifier);

	return 0;
}
