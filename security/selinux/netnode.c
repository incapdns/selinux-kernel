// SPDX-License-Identifier: GPL-2.0-only
/*
 * Network node table
 *
 * SELinux must keep a mapping of network nodes to labels/SIDs.  This
 * mapping is maintained as part of the normal policy but a fast cache is
 * needed to reduce the lookup overhead since most of these queries happen on
 * a per-packet basis.
 *
 * Author: Paul Moore <paul@paul-moore.com>
 *
 * This code is heavily based on the "netif" concept originally developed by
 * James Morris <jmorris@redhat.com>
 *   (see security/selinux/netif.c for more information)
 */

/*
 * (c) Copyright Hewlett-Packard Development Company, L.P., 2007
 */

#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "initcalls.h"
#include "global_sidtab.h"
#include "netnode.h"
#include "objsec.h"

#define SEL_NETNODE_HASH_SIZE       256
#define SEL_NETNODE_HASH_BKT_LIMIT   16

struct sel_netnode_bkt {
	unsigned int size;
	struct list_head list;
};

struct sel_netnode {
	struct netnode_security_struct nsec;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *sid_handle;
#endif

	struct list_head list;
	struct rcu_head rcu;
};

/* NOTE: we are using a combined hash table for both IPv4 and IPv6, the reason
 * for this is that I suspect most users will not make heavy use of both
 * address families at the same time so one table will usually end up wasted,
 * if this becomes a problem we can always add a hash table for each address
 * family later */

static DEFINE_SPINLOCK(sel_netnode_lock);
static struct sel_netnode_bkt sel_netnode_hash[SEL_NETNODE_HASH_SIZE];

static void sel_netnode_free(struct rcu_head *rcu)
{
	struct sel_netnode *node = container_of(rcu, struct sel_netnode, rcu);

#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(node->sid_handle);
#endif
	kfree(node);
}

/**
 * sel_netnode_hashfn_ipv4 - IPv4 hashing function for the node table
 * @addr: IPv4 address
 *
 * Description:
 * This is the IPv4 hashing function for the node interface table, it returns
 * the bucket number for the given IP address.
 *
 */
static unsigned int sel_netnode_hashfn_ipv4(__be32 addr)
{
	/* at some point we should determine if the mismatch in byte order
	 * affects the hash function dramatically */
	return (addr & (SEL_NETNODE_HASH_SIZE - 1));
}

/**
 * sel_netnode_hashfn_ipv6 - IPv6 hashing function for the node table
 * @addr: IPv6 address
 *
 * Description:
 * This is the IPv6 hashing function for the node interface table, it returns
 * the bucket number for the given IP address.
 *
 */
static unsigned int sel_netnode_hashfn_ipv6(const struct in6_addr *addr)
{
	/* just hash the least significant 32 bits to keep things fast (they
	 * are the most likely to be different anyway), we can revisit this
	 * later if needed */
	return (addr->s6_addr32[3] & (SEL_NETNODE_HASH_SIZE - 1));
}

/**
 * sel_netnode_find - Search for a node record
 * @domain_id: stable SELinux label-domain identity
 * @snapshot: immutable policy generation
 * @addr: IP address
 * @family: address family
 *
 * Description:
 * Search the network node table and return the record matching @addr.  If an
 * entry can not be found in the table return NULL.
 *
 */
static struct sel_netnode *sel_netnode_find(
	u64 domain_id,
	const struct selinux_policy_snapshot *snapshot, const void *addr,
	u16 family)
{
	unsigned int idx;
	struct sel_netnode *node;

	switch (family) {
	case PF_INET:
		idx = sel_netnode_hashfn_ipv4(*(const __be32 *)addr);
		break;
	case PF_INET6:
		idx = sel_netnode_hashfn_ipv6(addr);
		break;
	default:
		BUG();
		return NULL;
	}

	list_for_each_entry_rcu(node, &sel_netnode_hash[idx].list, list) {
		if (node->nsec.family != family ||
		    !selinux_policy_cache_key_matches(&node->nsec.policy,
						      domain_id, snapshot))
			continue;
#ifdef CONFIG_SECURITY_SELINUX_NS
		if (!node->sid_handle ||
		    global_sid_handle_sid(node->sid_handle) != node->nsec.sid)
			continue;
#endif
		switch (family) {
		case PF_INET:
			if (node->nsec.addr.ipv4 == *(const __be32 *)addr)
				return node;
			break;
		case PF_INET6:
			if (ipv6_addr_equal(&node->nsec.addr.ipv6, addr))
				return node;
			break;
		}
	}

	return NULL;
}

/**
 * sel_netnode_insert - Insert a new node into the table
 * @node: the new node record
 *
 * Description:
 * Add a new node record to the network address hash table.
 *
 */
static void sel_netnode_insert(struct sel_netnode *node)
{
	unsigned int idx;

	switch (node->nsec.family) {
	case PF_INET:
		idx = sel_netnode_hashfn_ipv4(node->nsec.addr.ipv4);
		break;
	case PF_INET6:
		idx = sel_netnode_hashfn_ipv6(&node->nsec.addr.ipv6);
		break;
	default:
		BUG();
		return;
	}

	/* we need to impose a limit on the growth of the hash table so check
	 * this bucket to make sure it is within the specified bounds */
	list_add_rcu(&node->list, &sel_netnode_hash[idx].list);
	if (sel_netnode_hash[idx].size == SEL_NETNODE_HASH_BKT_LIMIT) {
		struct sel_netnode *tail;
		tail = list_entry(
			rcu_dereference_protected(
				list_tail_rcu(&sel_netnode_hash[idx].list),
				lockdep_is_held(&sel_netnode_lock)),
			struct sel_netnode, list);
		list_del_rcu(&tail->list);
		call_rcu(&tail->rcu, sel_netnode_free);
	} else
		sel_netnode_hash[idx].size++;
}

/**
 * sel_netnode_sid_slow - Lookup the SID of a network address using the policy
 * @state: the SELinux state
 * @snapshot: immutable policy generation
 * @addr: the IP address
 * @family: the address family
 * @sid: node SID
 * @out_handle: strong handle paired with @sid
 *
 * Description:
 * This function determines the SID of a network address by querying the
 * security policy.  The result is added to the network address table to
 * speedup future queries.  Returns zero on success, negative values on
 * failure.
 *
 */
static int sel_netnode_sid_slow(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, const void *addr,
	u16 family, u32 *sid,
	struct selinux_global_sid_handle **out_handle)
{
	int ret = 0;
	u64 domain_id = state->label_domain->id;
	struct sel_netnode *node;
	struct sel_netnode *new;
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

	spin_lock_bh(&sel_netnode_lock);
	node = sel_netnode_find(domain_id, snapshot, addr, family);
	if (node != NULL) {
		*sid = node->nsec.sid;
#ifdef CONFIG_SECURITY_SELINUX_NS
		sid_handle = global_sid_handle_dup(node->sid_handle);
		if (IS_ERR(sid_handle)) {
			ret = PTR_ERR(sid_handle);
			sid_handle = NULL;
		}
#endif
		goto out;
	}

	/* If this memory allocation fails still return 0. The SID
	 * is valid, it just won't be added to the cache.
	 */
	new = kmalloc_obj(*new, GFP_ATOMIC);
	switch (family) {
	case PF_INET:
#ifdef CONFIG_SECURITY_SELINUX_NS
		sid_handle = security_node_sid_handle(
			state, PF_INET, addr, sizeof(struct in_addr), sid);
		ret = IS_ERR(sid_handle) ? PTR_ERR(sid_handle) : 0;
		if (IS_ERR(sid_handle))
			sid_handle = NULL;
#else
		ret = security_node_sid(state, PF_INET,
					addr, sizeof(struct in_addr), sid);
#endif
		if (new)
			new->nsec.addr.ipv4 = *(const __be32 *)addr;
		break;
	case PF_INET6:
#ifdef CONFIG_SECURITY_SELINUX_NS
		sid_handle = security_node_sid_handle(
			state, PF_INET6, addr, sizeof(struct in6_addr), sid);
		ret = IS_ERR(sid_handle) ? PTR_ERR(sid_handle) : 0;
		if (IS_ERR(sid_handle))
			sid_handle = NULL;
#else
		ret = security_node_sid(state, PF_INET6,
					addr, sizeof(struct in6_addr), sid);
#endif
		if (new)
			new->nsec.addr.ipv6 = *(const struct in6_addr *)addr;
		break;
	default:
		BUG();
		ret = -EINVAL;
	}
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!ret && (!*sid || global_sid_handle_sid(sid_handle) != *sid))
		ret = -ESTALE;
#endif
	if (!ret && !selinux_policy_snapshot_valid(state, snapshot))
		ret = -ESTALE;
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!ret && new) {
		cache_handle = global_sid_handle_dup(sid_handle);
		if (IS_ERR(cache_handle)) {
			kfree(new);
			new = NULL;
		}
	}
#endif
	if (ret == 0 && new) {
		new->nsec.family = family;
		new->nsec.sid = *sid;
		selinux_policy_cache_key_init(&new->nsec.policy, domain_id,
					      snapshot);
#ifdef CONFIG_SECURITY_SELINUX_NS
		new->sid_handle = cache_handle;
#endif
		sel_netnode_insert(new);
	} else
		kfree(new);

out:
	spin_unlock_bh(&sel_netnode_lock);
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
		pr_warn("SELinux: failure in %s(), unable to determine network node label\n",
			__func__);
	return ret;
}

/**
 * sel_netnode_sid_snapshot_handle - Lookup the SID of a network address
 * @state: the SELinux state
 * @snapshot: immutable policy generation
 * @addr: the IP address
 * @family: the address family
 * @sid: node SID
 *
 * Description:
 * This function determines the SID of a network address using the fastest
 * method possible.  First the address table is queried, but if an entry
 * can't be found then the policy is queried and the result is added to the
 * table to speedup future queries.  Returns zero on success, negative values
 * on failure.
 *
 */
#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_global_sid_handle *
sel_netnode_sid_snapshot_handle(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, const void *addr,
	u16 family, u32 *sid)
{
	struct selinux_global_sid_handle *handle;
	struct sel_netnode *node;
	bool valid;
	int rc;

	if (!state || !state->label_domain || !snapshot || !sid ||
	    !snapshot->chain_epoch)
		return ERR_PTR(-EINVAL);

	rcu_read_lock();
	node = sel_netnode_find(state->label_domain->id, snapshot, addr, family);
	if (likely(node != NULL)) {
		*sid = node->nsec.sid;
		handle = global_sid_handle_dup(node->sid_handle);
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

	rc = sel_netnode_sid_slow(state, snapshot, addr, family, sid, &handle);
	return rc ? ERR_PTR(rc) : handle;
}

struct selinux_global_sid_handle *
sel_netnode_sid_handle(struct selinux_state *state, const void *addr,
		      u16 family, u32 *sid)
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
		handle = sel_netnode_sid_snapshot_handle(
			state, &snapshot, addr, family, sid);
		if (!IS_ERR(handle) || PTR_ERR(handle) != -ESTALE)
			return handle;
	}
	return ERR_PTR(-ESTALE);
}
#endif

int sel_netnode_sid_snapshot(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, const void *addr,
	u16 family, u32 *sid)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;

	handle = sel_netnode_sid_snapshot_handle(state, snapshot, addr, family,
						 sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
#else
	struct sel_netnode *node;
	bool valid;

	if (!state || !state->label_domain || !snapshot ||
	    !snapshot->chain_epoch)
		return -EINVAL;
	rcu_read_lock();
	node = sel_netnode_find(state->label_domain->id, snapshot, addr, family);
	if (likely(node != NULL)) {
		*sid = node->nsec.sid;
		valid = selinux_policy_snapshot_valid(state, snapshot);
		rcu_read_unlock();
		return valid ? 0 : -ESTALE;
	}
	rcu_read_unlock();
	return sel_netnode_sid_slow(state, snapshot, addr, family, sid, NULL);
#endif
}

int sel_netnode_sid(struct selinux_state *state, const void *addr, u16 family,
		    u32 *sid)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;

	handle = sel_netnode_sid_handle(state, addr, family, sid);
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
		rc = sel_netnode_sid_snapshot(state, &snapshot, addr, family,
					       sid);
		if (rc != -ESTALE)
			return rc;
	}
	return -ESTALE;
#endif
}

/**
 * sel_netnode_flush - Flush the entire network address table
 *
 * Description:
 * Remove all entries from the network address table.
 *
 */
void sel_netnode_flush(void)
{
	unsigned int idx;
	struct sel_netnode *node, *node_tmp;

	spin_lock_bh(&sel_netnode_lock);
	for (idx = 0; idx < SEL_NETNODE_HASH_SIZE; idx++) {
		list_for_each_entry_safe(node, node_tmp,
					 &sel_netnode_hash[idx].list, list) {
				list_del_rcu(&node->list);
				call_rcu(&node->rcu, sel_netnode_free);
		}
		sel_netnode_hash[idx].size = 0;
	}
	spin_unlock_bh(&sel_netnode_lock);
}

int __init sel_netnode_init(void)
{
	int iter;

	if (!selinux_enabled_boot)
		return 0;

	for (iter = 0; iter < SEL_NETNODE_HASH_SIZE; iter++) {
		INIT_LIST_HEAD(&sel_netnode_hash[iter].list);
		sel_netnode_hash[iter].size = 0;
	}

	return 0;
}
