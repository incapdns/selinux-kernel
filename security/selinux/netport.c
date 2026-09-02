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
#include <net/ip.h>
#include <net/ipv6.h>

#include "initcalls.h"
#include "netport.h"
#include "objsec.h"
#include "namespace.h"
#include "object_label.h"
#include "security.h"

#define SEL_NETPORT_HASH_SIZE       256
#define SEL_NETPORT_HASH_BKT_LIMIT   16

struct sel_netport_bkt {
	int size;
	struct list_head list;
};

struct sel_netport {
	struct netport_security_struct psec;

	struct list_head list;
	struct rcu_head rcu;
};

static DEFINE_SPINLOCK(sel_netport_lock);
static struct sel_netport_bkt sel_netport_hash[SEL_NETPORT_HASH_SIZE];

static void sel_netport_free(struct rcu_head *rcu)
{
	struct sel_netport *port = container_of(rcu, struct sel_netport, rcu);

	selinux_object_identity_put(port->psec.object);
	kfree(port);
}

static int sel_netport_populate_labels(
	const struct cred *cred,
	u8 protocol,
	u16 pnum,
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
		rc = security_port_sid(
			state, protocol, pnum, &values[count].sid);
		if (rc)
			return rc;
		/* The caller supplies the protocol-specific socket class. */
		values[count].sclass = SECCLASS_NULL;
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
 * sel_netport_hashfn - Hashing function for the port table
 * @pnum: port number
 *
 * Description:
 * This is the hashing function for the port table, it returns the bucket
 * number for the given port.
 *
 */
static unsigned int sel_netport_hashfn(u16 pnum)
{
	return (pnum & (SEL_NETPORT_HASH_SIZE - 1));
}

/**
 * sel_netport_find - Search for a port record
 * @protocol: protocol
 * @pnum: port
 *
 * Description:
 * Search the network port table and return the matching record.  If an entry
 * can not be found in the table return NULL.
 *
 */
static struct sel_netport *sel_netport_find(u8 protocol, u16 pnum)
{
	unsigned int idx;
	struct sel_netport *port;

	idx = sel_netport_hashfn(pnum);
	list_for_each_entry_rcu(port, &sel_netport_hash[idx].list, list)
		if (port->psec.port == pnum && port->psec.protocol == protocol)
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
	idx = sel_netport_hashfn(port->psec.port);
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
 * sel_netport_object_slow - Resolve a network-port identity for the chain
 * @protocol: protocol
 * @pnum: port
 * @sid: port SID
 *
 * Description:
 * This function determines the SID of a network port by querying the security
 * policy.  The result is added to the network port table to speedup future
 * queries.  Returns zero on success, negative values on failure.
 *
 */
static int sel_netport_object_slow(
	const struct cred *cred,
	u8 protocol,
	u16 pnum,
	struct selinux_object_identity **object)
{
	int ret = 0;
	struct sel_netport *port;
	struct sel_netport *new;

	spin_lock_bh(&sel_netport_lock);
	port = sel_netport_find(protocol, pnum);
	if (port != NULL) {
		struct selinux_object_label_value value;

		if (selinux_object_label_get(
			    cred_selinux_state(cred), port->psec.object, &value)) {
			ret = sel_netport_populate_labels(
				cred, protocol, pnum, port->psec.object);
			if (ret)
				goto out;
		}
		*object = selinux_object_identity_get(port->psec.object);
		goto out;
	}

	new = kmalloc_obj(*new, GFP_ATOMIC);
	if (!new) {
		ret = -ENOMEM;
		goto out;
	}
	new->psec.object = selinux_object_identity_alloc(
		init_selinux_state, GFP_ATOMIC);
	if (IS_ERR(new->psec.object)) {
		ret = PTR_ERR(new->psec.object);
		kfree(new);
		goto out;
	}
	ret = sel_netport_populate_labels(
		cred, protocol, pnum, new->psec.object);
	if (ret) {
		selinux_object_identity_put(new->psec.object);
		kfree(new);
		goto out;
	}
	new->psec.port = pnum;
	new->psec.protocol = protocol;
	sel_netport_insert(new);
	*object = selinux_object_identity_get(new->psec.object);

out:
	spin_unlock_bh(&sel_netport_lock);
	if (unlikely(ret))
		pr_warn("SELinux: failure in %s(), unable to determine network port label\n",
			__func__);
	return ret;
}

/**
 * sel_netport_object - Lookup the stable identity of a network port
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
int sel_netport_object(const struct cred *cred, u8 protocol, u16 pnum,
		       struct selinux_object_identity **object)
{
	struct sel_netport *port;
	struct selinux_object_label_value value;

	if (!cred || !object)
		return -EINVAL;
	*object = NULL;

	rcu_read_lock();
	port = sel_netport_find(protocol, pnum);
	if (likely(port != NULL) &&
	    !selinux_object_label_get(
		    cred_selinux_state(cred), port->psec.object, &value)) {
		*object = selinux_object_identity_get(port->psec.object);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	return sel_netport_object_slow(cred, protocol, pnum, object);
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
