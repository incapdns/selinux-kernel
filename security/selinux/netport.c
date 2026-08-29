// SPDX-License-Identifier: GPL-2.0-only
/*
 * Network port table
 *
 * SELinux must keep a mapping of network ports to labels/SIDs.  This
 * mapping is maintained as part of the normal policy but a fast cache is
 * needed to reduce the lookup overhead.
 *
 * Author: Paul Moore <paul@paul-moore.com>
 *
 * This code is heavily based on the "netif" concept originally developed by
 * James Morris <jmorris@redhat.com>
 *   (see security/selinux/netif.c for more information)
 */

/*
 * (c) Copyright Hewlett-Packard Development Company, L.P., 2008
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
#include <linux/hash.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "initcalls.h"
#include "global_sidtab.h"
#include "netport.h"
#include "objsec.h"

#define SEL_NETPORT_HASH_SIZE       256
#define SEL_NETPORT_HASH_BKT_LIMIT   16

struct sel_netport_bkt {
	int size;
	struct list_head list;
};

struct sel_netport {
	struct netport_security_struct psec;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *sid_handle;
#endif

	struct list_head list;
	struct rcu_head rcu;
};

static DEFINE_SPINLOCK(sel_netport_lock);
static struct sel_netport_bkt sel_netport_hash[SEL_NETPORT_HASH_SIZE];

static void sel_netport_free(struct rcu_head *rcu)
{
	struct sel_netport *port = container_of(rcu, struct sel_netport, rcu);

#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(port->sid_handle);
#endif
	kfree(port);
}

/**
 * sel_netport_hashfn - Hashing function for the port table
 * @domain_id: stable SELinux label-domain identity
 * @protocol: transport protocol
 * @pnum: port number
 *
 * Description:
 * This is the hashing function for the port table, it returns the bucket
 * number for the given port.
 *
 */
static unsigned int sel_netport_hashfn(u64 domain_id, u8 protocol, u16 pnum)
{
	return hash_64(domain_id ^ ((u64)protocol << 16) ^ pnum, 8);
}

static bool sel_netport_match(const struct netport_security_struct *psec,
			      u64 domain_id,
			      const struct selinux_policy_snapshot *snapshot,
			      u8 protocol, u16 pnum)
{
	return psec->port == pnum &&
	       psec->protocol == protocol &&
	       selinux_policy_cache_key_matches(&psec->policy, domain_id,
						snapshot);
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
bool selinux_kunit_netport_key_matches(
	u64 stored_domain_id,
	const struct selinux_policy_snapshot *stored_snapshot,
	u8 stored_protocol, u16 stored_port,
	u64 query_domain_id,
	const struct selinux_policy_snapshot *query_snapshot,
	u8 query_protocol, u16 query_port)
{
	const struct netport_security_struct psec = {
		.protocol = stored_protocol,
		.port = stored_port,
	};
	struct netport_security_struct key = psec;

	selinux_policy_cache_key_init(&key.policy, stored_domain_id,
				      stored_snapshot);

	return sel_netport_match(&key, query_domain_id, query_snapshot, query_protocol,
				 query_port);
}
#endif

/**
 * sel_netport_find - Search for a port record
 * @domain_id: stable SELinux label-domain identity
 * @snapshot: immutable policy generation
 * @protocol: protocol
 * @pnum: port
 *
 * Description:
 * Search the network port table and return the matching record.  If an entry
 * can not be found in the table return NULL.
 *
 */
static struct sel_netport *sel_netport_find(
	u64 domain_id,
	const struct selinux_policy_snapshot *snapshot, u8 protocol, u16 pnum)
{
	unsigned int idx;
	struct sel_netport *port;

	idx = sel_netport_hashfn(domain_id, protocol, pnum);
	list_for_each_entry_rcu(port, &sel_netport_hash[idx].list, list)
		if (sel_netport_match(&port->psec, domain_id, snapshot, protocol,
				      pnum)
#ifdef CONFIG_SECURITY_SELINUX_NS
		    && port->sid_handle &&
		    global_sid_handle_sid(port->sid_handle) == port->psec.sid
#endif
		   )
			return port;

	return NULL;
}

/**
 * sel_netport_insert - Insert a new port into the table
 * @port: the new port record
 *
 * Description:
 * Add a new port record to the network address hash table.
 *
 */
static void sel_netport_insert(struct sel_netport *port)
{
	unsigned int idx;

	/* we need to impose a limit on the growth of the hash table so check
	 * this bucket to make sure it is within the specified bounds */
	idx = sel_netport_hashfn(port->psec.policy.domain_id, port->psec.protocol,
				 port->psec.port);
	list_add_rcu(&port->list, &sel_netport_hash[idx].list);
	if (sel_netport_hash[idx].size == SEL_NETPORT_HASH_BKT_LIMIT) {
		struct sel_netport *tail;
		tail = list_entry(
			rcu_dereference_protected(
				list_tail_rcu(&sel_netport_hash[idx].list),
				lockdep_is_held(&sel_netport_lock)),
			struct sel_netport, list);
		list_del_rcu(&tail->list);
		call_rcu(&tail->rcu, sel_netport_free);
	} else
		sel_netport_hash[idx].size++;
}

/**
 * sel_netport_sid_slow - Lookup the SID of a network address using the policy
 * @state: the SELinux state
 * @snapshot: immutable policy generation
 * @protocol: protocol
 * @pnum: port
 * @sid: port SID
 * @out_handle: strong handle paired with @sid
 *
 * Description:
 * This function determines the SID of a network port by querying the security
 * policy.  The result is added to the network port table to speedup future
 * queries.  Returns zero on success, negative values on failure.
 *
 */
static int sel_netport_sid_slow(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, u8 protocol, u16 pnum,
	u32 *sid, struct selinux_global_sid_handle **out_handle)
{
	int ret = 0;
	u64 domain_id = state->label_domain->id;
	struct sel_netport *port;
	struct sel_netport *new;
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

	spin_lock_bh(&sel_netport_lock);
	port = sel_netport_find(domain_id, snapshot, protocol, pnum);
	if (port != NULL) {
		*sid = port->psec.sid;
#ifdef CONFIG_SECURITY_SELINUX_NS
		sid_handle = global_sid_handle_dup(port->sid_handle);
		if (IS_ERR(sid_handle)) {
			ret = PTR_ERR(sid_handle);
			sid_handle = NULL;
		}
#endif
		goto out;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	sid_handle = security_port_sid_handle(state, protocol, pnum, sid);
	if (IS_ERR(sid_handle)) {
		ret = PTR_ERR(sid_handle);
		sid_handle = NULL;
	} else if (!*sid || global_sid_handle_sid(sid_handle) != *sid) {
		ret = -ESTALE;
	}
#else
	ret = security_port_sid(state, protocol, pnum, sid);
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
		new->psec.port = pnum;
		new->psec.protocol = protocol;
		new->psec.sid = *sid;
		selinux_policy_cache_key_init(&new->psec.policy, domain_id,
					      snapshot);
#ifdef CONFIG_SECURITY_SELINUX_NS
		new->sid_handle = cache_handle;
#endif
		sel_netport_insert(new);
	}

out:
	spin_unlock_bh(&sel_netport_lock);
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
		pr_warn("SELinux: failure in %s(), unable to determine network port label\n",
			__func__);
	return ret;
}

/**
 * sel_netport_sid_snapshot_handle - Lookup the SID of a network port
 * @state: the SELinux state
 * @snapshot: immutable policy generation
 * @protocol: protocol
 * @pnum: port
 * @sid: port SID
 *
 * Description:
 * This function determines the SID of a network port using the fastest method
 * possible.  First the port table is queried, but if an entry can't be found
 * then the policy is queried and the result is added to the table to speedup
 * future queries.  Returns zero on success, negative values on failure.
 *
 */
#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_global_sid_handle *
sel_netport_sid_snapshot_handle(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, u8 protocol, u16 pnum,
	u32 *sid)
{
	struct selinux_global_sid_handle *handle;
	struct sel_netport *port;
	bool valid;
	int rc;

	if (!state || !state->label_domain || !snapshot || !sid ||
	    !snapshot->chain_epoch)
		return ERR_PTR(-EINVAL);

	rcu_read_lock();
	port = sel_netport_find(state->label_domain->id, snapshot, protocol,
				pnum);
	if (likely(port != NULL)) {
		*sid = port->psec.sid;
		handle = global_sid_handle_dup(port->sid_handle);
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

	rc = sel_netport_sid_slow(state, snapshot, protocol, pnum, sid,
				  &handle);
	return rc ? ERR_PTR(rc) : handle;
}

struct selinux_global_sid_handle *
sel_netport_sid_handle(struct selinux_state *state, u8 protocol, u16 pnum,
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
		handle = sel_netport_sid_snapshot_handle(
			state, &snapshot, protocol, pnum, sid);
		if (!IS_ERR(handle) || PTR_ERR(handle) != -ESTALE)
			return handle;
	}
	return ERR_PTR(-ESTALE);
}
#endif

int sel_netport_sid_snapshot(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, u8 protocol, u16 pnum,
	u32 *sid)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;

	handle = sel_netport_sid_snapshot_handle(state, snapshot, protocol,
						 pnum, sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
#else
	struct sel_netport *port;
	bool valid;

	if (!state || !state->label_domain || !snapshot ||
	    !snapshot->chain_epoch)
		return -EINVAL;
	rcu_read_lock();
	port = sel_netport_find(state->label_domain->id, snapshot, protocol,
				pnum);
	if (likely(port != NULL)) {
		*sid = port->psec.sid;
		valid = selinux_policy_snapshot_valid(state, snapshot);
		rcu_read_unlock();
		return valid ? 0 : -ESTALE;
	}
	rcu_read_unlock();
	return sel_netport_sid_slow(state, snapshot, protocol, pnum, sid, NULL);
#endif
}

int sel_netport_sid(struct selinux_state *state, u8 protocol, u16 pnum,
		    u32 *sid)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;

	handle = sel_netport_sid_handle(state, protocol, pnum, sid);
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
		rc = sel_netport_sid_snapshot(state, &snapshot, protocol, pnum,
					      sid);
		if (rc != -ESTALE)
			return rc;
	}
	return -ESTALE;
#endif
}

/**
 * sel_netport_flush - Flush the entire network port table
 *
 * Description:
 * Remove all entries from the network address table.
 *
 */
void sel_netport_flush(void)
{
	unsigned int idx;
	struct sel_netport *port, *port_tmp;

	spin_lock_bh(&sel_netport_lock);
	for (idx = 0; idx < SEL_NETPORT_HASH_SIZE; idx++) {
		list_for_each_entry_safe(port, port_tmp,
					 &sel_netport_hash[idx].list, list) {
			list_del_rcu(&port->list);
			call_rcu(&port->rcu, sel_netport_free);
		}
		sel_netport_hash[idx].size = 0;
	}
	spin_unlock_bh(&sel_netport_lock);
}

int __init sel_netport_init(void)
{
	int iter;

	if (!selinux_enabled_boot)
		return 0;

	for (iter = 0; iter < SEL_NETPORT_HASH_SIZE; iter++) {
		INIT_LIST_HEAD(&sel_netport_hash[iter].list);
		sel_netport_hash[iter].size = 0;
	}

	return 0;
}
