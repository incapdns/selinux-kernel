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
#include "security.h"
#include "objsec.h"
#include "netif.h"
#include "namespace.h"
#include "object_label.h"

#define SEL_NETIF_HASH_SIZE	64
#define SEL_NETIF_HASH_MAX	1024

struct sel_netif {
	struct list_head list;
	struct netif_security_struct nsec;
	struct rcu_head rcu_head;
};

static u32 sel_netif_total;
static DEFINE_SPINLOCK(sel_netif_lock);
static struct list_head sel_netif_hash[SEL_NETIF_HASH_SIZE];

static void sel_netif_free(struct rcu_head *rcu);

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
 * @ns: the network namespace
 * @ifindex: the network interface
 *
 * Description:
 * Search the network interface table and return the record matching @ifindex.
 * If an entry can not be found in the table return NULL.
 *
 */
static inline struct sel_netif *sel_netif_find(const struct net *ns,
					       int ifindex)
{
	u32 idx = sel_netif_hashfn(ns, ifindex);
	struct sel_netif *netif;

	list_for_each_entry_rcu(netif, &sel_netif_hash[idx], list)
		if (net_eq(netif->nsec.ns, ns) &&
		    netif->nsec.ifindex == ifindex)
			return netif;

	return NULL;
}

/**
 * sel_netif_insert - Insert a new interface into the table
 * @netif: the new interface record
 *
 * Description:
 * Add a new interface record to the network interface hash table.  Returns
 * zero on success, negative values on failure.
 *
 */
static int sel_netif_insert(struct sel_netif *netif)
{
	u32 idx;

	if (sel_netif_total >= SEL_NETIF_HASH_MAX)
		return -ENOSPC;

	idx = sel_netif_hashfn(netif->nsec.ns, netif->nsec.ifindex);
	list_add_rcu(&netif->list, &sel_netif_hash[idx]);
	sel_netif_total++;

	return 0;
}

/**
 * sel_netif_destroy - Remove an interface record from the table
 * @netif: the existing interface record
 *
 * Description:
 * Remove an existing interface record from the network interface table.
 *
 */
static void sel_netif_destroy(struct sel_netif *netif)
{
	list_del_rcu(&netif->list);
	sel_netif_total--;
	call_rcu(&netif->rcu_head, sel_netif_free);
}

static void sel_netif_free(struct rcu_head *rcu)
{
	struct sel_netif *netif = container_of(rcu, struct sel_netif, rcu_head);

	selinux_object_identity_put(netif->nsec.object);
	kfree(netif);
}

static int sel_netif_populate_labels(
	const struct cred *cred,
	const struct net_device *dev,
	struct selinux_object_identity *object)
{
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	const struct cred *level_cred = cred;
	struct selinux_state *state = cred_selinux_state(cred);
	u16 count = 0;
	int rc;

	while (state) {
		const struct cred_security_struct *security;

		if (!level_cred || count >= ARRAY_SIZE(states))
			return -ESTALE;
		security = selinux_cred(level_cred);
		if (security->state != state)
			return -ESTALE;
		states[count] = state;
		rc = security_netif_sid(state, dev->name, &values[count].sid);
		if (rc)
			return rc;
		values[count].sclass = SECCLASS_NETIF;
		values[count].source = SELINUX_LABEL_SOURCE_NETWORK;
		count++;
		level_cred = security->parent_cred;
		state = state->parent;
	}
	if (level_cred)
		return -ESTALE;
	return selinux_object_labels_set_chain(
		object, states, values, count, GFP_ATOMIC);
}

/**
 * sel_netif_object_slow - Resolve a network interface identity for the chain
 * @ns: the network namespace
 * @ifindex: the network interface
 * @sid: interface SID
 *
 * Description:
 * This function determines the SID of a network interface by querying the
 * security policy.  The result is added to the network interface table to
 * speedup future queries.  Returns zero on success, negative values on
 * failure.
 *
 */
static int sel_netif_object_slow(
	const struct cred *cred,
	struct net *ns,
	int ifindex,
	struct selinux_object_identity **object)
{
	int ret = 0;
	struct sel_netif *netif;
	struct sel_netif *new;
	struct net_device *dev;

	/* NOTE: we always use init's network namespace since we don't
	 * currently support containers */

	dev = dev_get_by_index(ns, ifindex);
	if (unlikely(dev == NULL)) {
		pr_warn("SELinux: failure in %s(), invalid network interface (%d)\n",
			__func__, ifindex);
		return -ENOENT;
	}

	spin_lock_bh(&sel_netif_lock);
	netif = sel_netif_find(ns, ifindex);
	if (netif != NULL) {
		struct selinux_object_label_value value;

		if (selinux_object_label_get(
			    cred_selinux_state(cred), netif->nsec.object, &value)) {
			ret = sel_netif_populate_labels(
				cred, dev, netif->nsec.object);
			if (ret)
				goto out;
		}
		*object = selinux_object_identity_get(netif->nsec.object);
		goto out;
	}

	new = kmalloc_obj(*new, GFP_ATOMIC);
	if (!new) {
		ret = -ENOMEM;
		goto out;
	}
	new->nsec.object = selinux_object_identity_alloc(
		init_selinux_state, GFP_ATOMIC);
	if (IS_ERR(new->nsec.object)) {
		ret = PTR_ERR(new->nsec.object);
		kfree(new);
		goto out;
	}
	ret = sel_netif_populate_labels(cred, dev, new->nsec.object);
	if (ret) {
		selinux_object_identity_put(new->nsec.object);
		kfree(new);
		goto out;
	}

	new->nsec.ns = ns;
	new->nsec.ifindex = ifindex;
	ret = sel_netif_insert(new);
	if (ret) {
		selinux_object_identity_put(new->nsec.object);
		kfree(new);
		goto out;
	}
	*object = selinux_object_identity_get(new->nsec.object);

out:
	spin_unlock_bh(&sel_netif_lock);
	dev_put(dev);
	if (unlikely(ret))
		pr_warn("SELinux: failure in %s(), unable to determine network interface label (%d)\n",
			__func__, ifindex);
	return ret;
}

/**
 * sel_netif_object - Lookup the stable identity of a network interface
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
int sel_netif_object(const struct cred *cred, struct net *ns, int ifindex,
		     struct selinux_object_identity **object)
{
	struct sel_netif *netif;
	struct selinux_object_label_value value;

	if (!cred || !object)
		return -EINVAL;
	*object = NULL;

	rcu_read_lock();
	netif = sel_netif_find(ns, ifindex);
	if (likely(netif != NULL) &&
	    !selinux_object_label_get(
		    cred_selinux_state(cred), netif->nsec.object, &value)) {
		*object = selinux_object_identity_get(netif->nsec.object);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	return sel_netif_object_slow(cred, ns, ifindex, object);
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
	struct sel_netif *netif;

	rcu_read_lock();
	spin_lock_bh(&sel_netif_lock);
	netif = sel_netif_find(ns, ifindex);
	if (netif)
		sel_netif_destroy(netif);
	spin_unlock_bh(&sel_netif_lock);
	rcu_read_unlock();
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
	struct sel_netif *netif;

	spin_lock_bh(&sel_netif_lock);
	for (idx = 0; idx < SEL_NETIF_HASH_SIZE; idx++)
		list_for_each_entry(netif, &sel_netif_hash[idx], list)
			sel_netif_destroy(netif);
	spin_unlock_bh(&sel_netif_lock);
}

static int sel_netif_netdev_notifier_handler(struct notifier_block *this,
					     unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event == NETDEV_DOWN)
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
