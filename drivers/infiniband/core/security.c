/*
 * Copyright (c) 2016 Mellanox Technologies Ltd.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/security.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/rbtree.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_cache.h>
#include "core_priv.h"
#include "mad_priv.h"

static LIST_HEAD(mad_agent_list);
/* Lock to protect mad_agent_list */
static DEFINE_SPINLOCK(mad_agent_list_lock);

#define IB_POLICY_SCOPE_MAX_DEPTH 64

enum ib_policy_scope_kind {
	IB_POLICY_SCOPE_QP,
	IB_POLICY_SCOPE_MAD,
};

enum ib_policy_error_state {
	IB_POLICY_ERROR_IDLE,
	IB_POLICY_ERROR_IN_PROGRESS,
	IB_POLICY_ERROR_REVOKED,
};

struct ib_policy_scope_watch;
struct ib_policy_scope_bucket {
	struct rb_node node;
	struct hlist_head watches;
	struct completion pre_done;
	refcount_t refs;
	u64 id;
	u32 updates;
	int pre_rc;
	bool pre_in_progress;
};

struct ib_policy_scope_entry {
	struct hlist_node node;
	struct ib_policy_scope_bucket *bucket;
	struct ib_policy_scope_watch *watch;
	bool update_pending;
};

struct ib_policy_scope_watch {
	struct work_struct work;
	refcount_t refs;
	struct completion refs_done;
	atomic64_t change_seq;
	atomic_t qp_pending;
	bool dead;
	bool seq_overflow;
	enum ib_policy_scope_kind kind;
	void *owner;
	u16 scope_pending;
	u16 count;
	struct ib_policy_scope_entry entry[];
};

struct ib_policy_pre_target {
	struct list_head list;
	struct ib_policy_scope_watch *watch;
};

static struct rb_root ib_policy_scope_root = RB_ROOT;
static DEFINE_SPINLOCK(ib_policy_scope_lock);

static void ib_policy_scope_revalidate(struct work_struct *work);

static void ib_policy_scope_bucket_put(struct ib_policy_scope_bucket *bucket)
{
	if (refcount_dec_and_test(&bucket->refs))
		kfree(bucket);
}

static struct ib_policy_scope_bucket *
ib_policy_scope_bucket_find(u64 id)
{
	struct rb_node *node = ib_policy_scope_root.rb_node;

	while (node) {
		struct ib_policy_scope_bucket *bucket =
			rb_entry(node, struct ib_policy_scope_bucket, node);

		if (id < bucket->id)
			node = node->rb_left;
		else if (id > bucket->id)
			node = node->rb_right;
		else
			return bucket;
	}
	return NULL;
}

static struct ib_policy_scope_bucket *
ib_policy_scope_bucket_insert(struct ib_policy_scope_bucket *candidate)
{
	struct rb_node **link = &ib_policy_scope_root.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		struct ib_policy_scope_bucket *bucket =
			rb_entry(*link, struct ib_policy_scope_bucket, node);

		parent = *link;
		if (candidate->id < bucket->id)
			link = &(*link)->rb_left;
		else if (candidate->id > bucket->id)
			link = &(*link)->rb_right;
		else
			return bucket;
	}
	rb_link_node(&candidate->node, parent, link);
	rb_insert_color(&candidate->node, &ib_policy_scope_root);
	return candidate;
}

static int ib_policy_scope_watch_register(void *security, void *owner,
					  enum ib_policy_scope_kind kind,
					  struct ib_policy_scope_watch **watchp)
{
	u64 ids[IB_POLICY_SCOPE_MAX_DEPTH];
	struct ib_policy_scope_bucket *candidates[IB_POLICY_SCOPE_MAX_DEPTH] = {};
	struct ib_policy_scope_watch *watch;
	int count, i;

	*watchp = NULL;
	count = security_ib_policy_scopes(security, ids, ARRAY_SIZE(ids));
	if (count <= 0)
		return count;
	if (count > ARRAY_SIZE(ids))
		return -E2BIG;
	watch = kzalloc(struct_size(watch, entry, count), GFP_ATOMIC);
	if (!watch)
		return -ENOMEM;
	for (i = 0; i < count; i++) {
		candidates[i] = kzalloc_obj(*candidates[i], GFP_ATOMIC);
		if (!candidates[i])
			goto out_free_candidates;
		candidates[i]->id = ids[i];
		INIT_HLIST_HEAD(&candidates[i]->watches);
		init_completion(&candidates[i]->pre_done);
		refcount_set(&candidates[i]->refs, 1);
	}
	INIT_WORK(&watch->work, ib_policy_scope_revalidate);
	refcount_set(&watch->refs, 1);
	init_completion(&watch->refs_done);
	atomic64_set(&watch->change_seq, 0);
	atomic_set(&watch->qp_pending, 0);
	watch->kind = kind;
	watch->owner = owner;
	watch->count = count;
	spin_lock(&ib_policy_scope_lock);
	for (i = 0; i < count; i++) {
		struct ib_policy_scope_bucket *bucket =
			ib_policy_scope_bucket_find(ids[i]);

		if (bucket && bucket->updates) {
			spin_unlock(&ib_policy_scope_lock);
			for (i = 0; i < count; i++)
				kfree(candidates[i]);
			kfree(watch);
			return -EAGAIN;
		}
	}
	for (i = 0; i < count; i++) {
		struct ib_policy_scope_bucket *bucket =
			ib_policy_scope_bucket_insert(candidates[i]);

		if (bucket == candidates[i])
			candidates[i] = NULL;
		watch->entry[i].bucket = bucket;
		watch->entry[i].watch = watch;
		hlist_add_head(&watch->entry[i].node, &bucket->watches);
	}
	spin_unlock(&ib_policy_scope_lock);
	for (i = 0; i < count; i++)
		kfree(candidates[i]);
	*watchp = watch;
	return 0;

out_free_candidates:
	while (i--)
		kfree(candidates[i]);
	kfree(watch);
	return -ENOMEM;
}

/* Caller holds ib_policy_scope_lock. */
static void ib_policy_scope_qp_pending_complete(
	struct ib_policy_scope_watch *watch, bool revoke)
{
	struct ib_qp_security *sec;
	struct ib_qp_security *real;
	int pending;

	if (watch->kind != IB_POLICY_SCOPE_QP ||
	    !atomic_xchg(&watch->qp_pending, 0))
		return;
	sec = watch->owner;
	real = sec->qp->real_qp->qp_sec;
	if (revoke) {
		atomic_set(&real->policy_revoked, 1);
		atomic_set(&real->policy_blocked, 1);
	}
	pending = atomic_dec_return(&real->policy_pending);
	if (WARN_ON_ONCE(pending < 0)) {
		atomic_set(&real->policy_pending, 0);
		return;
	}
	if (!pending && !atomic_read(&real->policy_revoked))
		atomic_set(&real->policy_blocked, 0);
}

static void ib_policy_scope_watch_unregister(struct ib_policy_scope_watch *watch)
{
	struct ib_policy_scope_bucket *empty[IB_POLICY_SCOPE_MAX_DEPTH] = {};
	u16 i;

	if (!watch)
		return;
	spin_lock(&ib_policy_scope_lock);
	watch->dead = true;
	ib_policy_scope_qp_pending_complete(watch, false);
	for (i = 0; i < watch->count; i++) {
		struct ib_policy_scope_bucket *bucket = watch->entry[i].bucket;

		hlist_del(&watch->entry[i].node);
		if (hlist_empty(&bucket->watches) && !bucket->updates) {
			rb_erase(&bucket->node, &ib_policy_scope_root);
			empty[i] = bucket;
		}
	}
	spin_unlock(&ib_policy_scope_lock);
	cancel_work_sync(&watch->work);
	if (!refcount_dec_and_test(&watch->refs))
		wait_for_completion(&watch->refs_done);
	for (i = 0; i < watch->count; i++)
		if (empty[i])
			ib_policy_scope_bucket_put(empty[i]);
	kfree(watch);
}

static struct pkey_index_qp_list *get_pkey_idx_qp_list(struct ib_port_pkey *pp)
{
	struct pkey_index_qp_list *pkey = NULL;
	struct pkey_index_qp_list *tmp_pkey;
	struct ib_device *dev = pp->sec->dev;

	spin_lock(&dev->port_data[pp->port_num].pkey_list_lock);
	list_for_each_entry (tmp_pkey, &dev->port_data[pp->port_num].pkey_list,
			     pkey_index_list) {
		if (tmp_pkey->pkey_index == pp->pkey_index) {
			pkey = tmp_pkey;
			break;
		}
	}
	spin_unlock(&dev->port_data[pp->port_num].pkey_list_lock);
	return pkey;
}

static int get_pkey_and_subnet_prefix(struct ib_port_pkey *pp,
				      u16 *pkey,
				      u64 *subnet_prefix)
{
	struct ib_device *dev = pp->sec->dev;
	int ret;

	ret = ib_get_cached_pkey(dev, pp->port_num, pp->pkey_index, pkey);
	if (ret)
		return ret;

	ib_get_cached_subnet_prefix(dev, pp->port_num, subnet_prefix);

	return ret;
}

static int enforce_qp_pkey_security(u16 pkey,
				    u64 subnet_prefix,
				    struct ib_qp_security *qp_sec)
{
	struct ib_qp_security *shared_qp_sec;
	int ret;

	ret = security_ib_pkey_access(qp_sec->security, subnet_prefix, pkey);
	if (ret)
		return ret;

	list_for_each_entry(shared_qp_sec,
			    &qp_sec->shared_qp_list,
			    shared_qp_list) {
		ret = security_ib_pkey_access(shared_qp_sec->security,
					      subnet_prefix,
					      pkey);
		if (ret)
			return ret;
	}
	return 0;
}

/* The caller of this function must hold the QP security
 * mutex of the QP of the security structure in *pps.
 *
 * It takes separate ports_pkeys and security structure
 * because in some cases the pps will be for a new settings
 * or the pps will be for the real QP and security structure
 * will be for a shared QP.
 */
static int check_qp_port_pkey_settings(struct ib_ports_pkeys *pps,
				       struct ib_qp_security *sec)
{
	u64 subnet_prefix;
	u16 pkey;
	int ret = 0;

	if (!pps)
		return 0;

	if (pps->main.state != IB_PORT_PKEY_NOT_VALID) {
		ret = get_pkey_and_subnet_prefix(&pps->main,
						 &pkey,
						 &subnet_prefix);
		if (ret)
			return ret;

		ret = enforce_qp_pkey_security(pkey,
					       subnet_prefix,
					       sec);
		if (ret)
			return ret;
	}

	if (pps->alt.state != IB_PORT_PKEY_NOT_VALID) {
		ret = get_pkey_and_subnet_prefix(&pps->alt,
						 &pkey,
						 &subnet_prefix);
		if (ret)
			return ret;

		ret = enforce_qp_pkey_security(pkey,
					       subnet_prefix,
					       sec);
	}

	return ret;
}

/* Revalidate only the principal represented by @sec, never its siblings. */
static int check_qp_port_pkey_settings_single(struct ib_ports_pkeys *pps,
					      struct ib_qp_security *sec)
{
	struct ib_port_pkey *pp[2];
	u64 subnet_prefix;
	u16 pkey;
	int i, ret;

	if (!pps)
		return 0;
	pp[0] = &pps->main;
	pp[1] = &pps->alt;
	for (i = 0; i < ARRAY_SIZE(pp); i++) {
		if (pp[i]->state == IB_PORT_PKEY_NOT_VALID)
			continue;
		ret = get_pkey_and_subnet_prefix(pp[i], &pkey, &subnet_prefix);
		if (ret)
			return ret;
		ret = security_ib_pkey_access(sec->security, subnet_prefix, pkey);
		if (ret)
			return ret;
	}
	return 0;
}

/* The caller of this function must hold the QP security
 * mutex.
 */
static int qp_to_error(struct ib_qp_security *sec)
{
	struct ib_qp_security *shared_qp_sec;
	struct ib_qp_attr attr = {
		.qp_state = IB_QPS_ERR
	};
	struct ib_event event = {
		.event = IB_EVENT_QP_FATAL
	};

	/* If the QP is in the process of being destroyed
	 * the qp pointer in the security structure is
	 * undefined.  It cannot be modified now.
	 */
	if (sec->destroying)
		return -EBUSY;
	atomic_set(&sec->policy_revoked, 1);
	atomic_set(&sec->policy_blocked, 1);
	if (atomic_cmpxchg(&sec->policy_error, IB_POLICY_ERROR_IDLE,
			   IB_POLICY_ERROR_IN_PROGRESS) != IB_POLICY_ERROR_IDLE)
		return atomic_read(&sec->policy_error) == IB_POLICY_ERROR_REVOKED ?
			0 : -EAGAIN;

	/*
	 * The caller holds @sec->mutex.  Bypass ib_security_modify_qp() here:
	 * all external modifies take the same mutex and recheck policy_blocked,
	 * while this fail-closed transition is the sole internal exception.
	 */
	if (sec->qp->device->ops.modify_qp(sec->qp, &attr, IB_QP_STATE, NULL)) {
		atomic_set(&sec->policy_error, IB_POLICY_ERROR_IDLE);
		return -EIO;
	}
	atomic_set(&sec->policy_error, IB_POLICY_ERROR_REVOKED);

	if (sec->qp->event_handler && sec->qp->qp_context) {
		event.element.qp = sec->qp;
		sec->qp->event_handler(&event,
				       sec->qp->qp_context);
	}

	list_for_each_entry(shared_qp_sec,
			    &sec->shared_qp_list,
			    shared_qp_list) {
		struct ib_qp *qp = shared_qp_sec->qp;

		if (qp->event_handler && qp->qp_context) {
			event.element.qp = qp;
			event.device = qp->device;
			qp->event_handler(&event,
					  qp->qp_context);
		}
	}
	return 0;
}

static void ib_policy_scope_revalidate(struct work_struct *work)
{
	struct ib_policy_scope_watch *watch =
		container_of(work, struct ib_policy_scope_watch, work);

	if (watch->kind == IB_POLICY_SCOPE_QP) {
		struct ib_qp_security *sec = watch->owner;
		struct ib_qp_security *real = sec->qp->real_qp->qp_sec;
		u64 change_seq = atomic64_read(&watch->change_seq);
		bool complete = false;
		bool revoke = false;
		bool withdrawn;
		int rc = 0;

		mutex_lock(&real->mutex);
		withdrawn = sec->destroying || real->destroying;
		if (!withdrawn)
			rc = check_qp_port_pkey_settings_single(
				real->ports_pkeys, sec);
		spin_lock(&ib_policy_scope_lock);
		if (!watch->dead && !watch->scope_pending &&
		    !watch->seq_overflow &&
		    atomic_read(&watch->qp_pending) &&
		    change_seq == atomic64_read(&watch->change_seq)) {
			revoke = !withdrawn && rc;
			ib_policy_scope_qp_pending_complete(watch, revoke);
			complete = true;
		}
		spin_unlock(&ib_policy_scope_lock);
		if (complete && (revoke || atomic_read(&real->policy_revoked)))
			qp_to_error(real);
		mutex_unlock(&real->mutex);
	} else {
		struct ib_mad_agent *agent = watch->owner;
		u64 change_seq = atomic64_read(&watch->change_seq);
		bool allowed;

		allowed = !security_ib_endport_manage_subnet(
			agent->security, dev_name(&agent->device->dev),
			agent->port_num);
		spin_lock(&ib_policy_scope_lock);
		if (!watch->dead && !watch->scope_pending &&
		    !watch->seq_overflow && allowed &&
		    change_seq == atomic64_read(&watch->change_seq))
			WRITE_ONCE(agent->smp_allowed, true);
		spin_unlock(&ib_policy_scope_lock);
	}
}

static void ib_policy_scope_watch_put(struct ib_policy_scope_watch *watch)
{
	if (refcount_dec_and_test(&watch->refs))
		complete(&watch->refs_done);
}

static void ib_policy_scope_gate_watch(struct ib_policy_scope_watch *watch)
{
	if (atomic64_read(&watch->change_seq) >= S64_MAX - 1) {
		atomic64_set(&watch->change_seq, S64_MAX);
		watch->seq_overflow = true;
	} else {
		atomic64_inc(&watch->change_seq);
	}
	if (watch->kind == IB_POLICY_SCOPE_MAD) {
		struct ib_mad_agent *agent = watch->owner;

		WRITE_ONCE(agent->smp_allowed, false);
	} else {
		struct ib_qp_security *sec = watch->owner;
		struct ib_qp_security *real = sec->qp->real_qp->qp_sec;

		atomic_set(&real->policy_blocked, 1);
		if (atomic_cmpxchg(&watch->qp_pending, 0, 1) == 0)
			atomic_inc(&real->policy_pending);
	}
}

static int ib_policy_scope_security_pre(u64 scope_id)
{
	LIST_HEAD(targets);
	struct ib_policy_pre_target *target, *tmp;
	struct ib_policy_scope_entry *entry;
	struct ib_policy_scope_bucket *bucket;
	struct ib_policy_scope_bucket *leader = NULL;
	struct ib_policy_scope_bucket *waiter = NULL;
	int rc = 0;

	spin_lock(&ib_policy_scope_lock);
	bucket = ib_policy_scope_bucket_find(scope_id);
	if (!bucket)
		goto unlock;
	if (bucket->updates >= U32_MAX - 1) {
		bucket->updates = U32_MAX;
		rc = -EOVERFLOW;
		goto unlock;
	}
	if (bucket->updates++) {
		if (bucket->pre_in_progress) {
			refcount_inc(&bucket->refs);
			waiter = bucket;
		} else {
			rc = bucket->pre_rc;
		}
		goto unlock;
	}
	reinit_completion(&bucket->pre_done);
	bucket->pre_rc = 0;
	bucket->pre_in_progress = true;
	refcount_inc(&bucket->refs);
	leader = bucket;
	hlist_for_each_entry(entry, &bucket->watches, node) {
		struct ib_policy_scope_watch *watch = entry->watch;

		if (watch->dead || entry->update_pending)
			continue;
		entry->update_pending = true;
		watch->scope_pending++;
		ib_policy_scope_gate_watch(watch);
		if (watch->kind != IB_POLICY_SCOPE_QP)
			continue;
		target = kzalloc_obj(*target, GFP_ATOMIC | __GFP_NOWARN);
		if (!target) {
			rc = -ENOMEM;
			continue;
		}
		if (!refcount_inc_not_zero(&watch->refs)) {
			kfree(target);
			rc = -ESTALE;
			continue;
		}
		target->watch = watch;
		list_add_tail(&target->list, &targets);
	}
unlock:
	spin_unlock(&ib_policy_scope_lock);
	if (waiter) {
		/* The same-scope leader owns the physical gate and its result. */
		wait_for_completion(&waiter->pre_done);
		rc = READ_ONCE(waiter->pre_rc);
		ib_policy_scope_bucket_put(waiter);
		return rc;
	}

	list_for_each_entry(target, &targets, list) {
		struct ib_qp_security *sec = target->watch->owner;
		struct ib_qp_security *real = sec->qp->real_qp->qp_sec;
		int err;

		mutex_lock(&real->mutex);
		err = qp_to_error(real);
		mutex_unlock(&real->mutex);
		if (err && !rc)
			rc = err;
	}
	list_for_each_entry_safe(target, tmp, &targets, list) {
		list_del(&target->list);
		ib_policy_scope_watch_put(target->watch);
		kfree(target);
	}
	if (leader) {
		/* Publish the result before releasing every coalesced PRE. */
		spin_lock(&ib_policy_scope_lock);
		leader->pre_rc = rc;
		leader->pre_in_progress = false;
		spin_unlock(&ib_policy_scope_lock);
		complete_all(&leader->pre_done);
		ib_policy_scope_bucket_put(leader);
	}
	return rc;
}

static int ib_policy_scope_security_post(u64 scope_id)
{
	struct ib_policy_scope_entry *entry;
	struct ib_policy_scope_bucket *bucket;
	struct ib_policy_scope_bucket *empty = NULL;

	spin_lock(&ib_policy_scope_lock);
	bucket = ib_policy_scope_bucket_find(scope_id);
	if (!bucket)
		goto unlock;
	if (!bucket->updates)
		goto unlock;
	if (bucket->updates == U32_MAX)
		goto unlock;
	if (--bucket->updates)
		goto unlock;
	hlist_for_each_entry(entry, &bucket->watches, node) {
		struct ib_policy_scope_watch *watch = entry->watch;

		if (!entry->update_pending)
			continue;
		entry->update_pending = false;
		if (WARN_ON_ONCE(!watch->scope_pending))
			continue;
		watch->scope_pending--;
		if (!watch->dead && !watch->scope_pending && !watch->seq_overflow)
			schedule_work(&watch->work);
	}
	if (hlist_empty(&bucket->watches)) {
		rb_erase(&bucket->node, &ib_policy_scope_root);
		empty = bucket;
	}
unlock:
	spin_unlock(&ib_policy_scope_lock);
	if (empty)
		ib_policy_scope_bucket_put(empty);
	return 0;
}

int ib_policy_scope_security_change(u64 scope_id, bool pre)
{
	return pre ? ib_policy_scope_security_pre(scope_id) :
		ib_policy_scope_security_post(scope_id);
}

static inline void check_pkey_qps(struct pkey_index_qp_list *pkey,
				  struct ib_device *device,
				  u32 port_num,
				  u64 subnet_prefix)
{
	struct ib_port_pkey *pp, *tmp_pp;
	bool comp;
	LIST_HEAD(to_error_list);
	u16 pkey_val;

	if (!ib_get_cached_pkey(device,
				port_num,
				pkey->pkey_index,
				&pkey_val)) {
		spin_lock(&pkey->qp_list_lock);
		list_for_each_entry(pp, &pkey->qp_list, qp_list) {
			if (atomic_read(&pp->sec->error_list_count))
				continue;

			if (enforce_qp_pkey_security(pkey_val,
						     subnet_prefix,
						     pp->sec)) {
				atomic_inc(&pp->sec->error_list_count);
				list_add(&pp->to_error_list,
					 &to_error_list);
			}
		}
		spin_unlock(&pkey->qp_list_lock);
	}

	list_for_each_entry_safe(pp,
				 tmp_pp,
				 &to_error_list,
				 to_error_list) {
		mutex_lock(&pp->sec->mutex);
		qp_to_error(pp->sec);
		list_del(&pp->to_error_list);
		atomic_dec(&pp->sec->error_list_count);
		comp = pp->sec->destroying;
		mutex_unlock(&pp->sec->mutex);

		if (comp)
			complete(&pp->sec->error_complete);
	}
}

/* The caller of this function must hold the QP security
 * mutex.
 */
static int port_pkey_list_insert(struct ib_port_pkey *pp)
{
	struct pkey_index_qp_list *tmp_pkey;
	struct pkey_index_qp_list *pkey;
	struct ib_device *dev;
	u32 port_num = pp->port_num;
	int ret = 0;

	if (pp->state != IB_PORT_PKEY_VALID)
		return 0;

	dev = pp->sec->dev;

	pkey = get_pkey_idx_qp_list(pp);

	if (!pkey) {
		bool found = false;

		pkey = kzalloc_obj(*pkey);
		if (!pkey)
			return -ENOMEM;

		spin_lock(&dev->port_data[port_num].pkey_list_lock);
		/* Check for the PKey again.  A racing process may
		 * have created it.
		 */
		list_for_each_entry(tmp_pkey,
				    &dev->port_data[port_num].pkey_list,
				    pkey_index_list) {
			if (tmp_pkey->pkey_index == pp->pkey_index) {
				kfree(pkey);
				pkey = tmp_pkey;
				found = true;
				break;
			}
		}

		if (!found) {
			pkey->pkey_index = pp->pkey_index;
			spin_lock_init(&pkey->qp_list_lock);
			INIT_LIST_HEAD(&pkey->qp_list);
			list_add(&pkey->pkey_index_list,
				 &dev->port_data[port_num].pkey_list);
		}
		spin_unlock(&dev->port_data[port_num].pkey_list_lock);
	}

	spin_lock(&pkey->qp_list_lock);
	list_add(&pp->qp_list, &pkey->qp_list);
	spin_unlock(&pkey->qp_list_lock);

	pp->state = IB_PORT_PKEY_LISTED;

	return ret;
}

/* The caller of this function must hold the QP security
 * mutex.
 */
static void port_pkey_list_remove(struct ib_port_pkey *pp)
{
	struct pkey_index_qp_list *pkey;

	if (pp->state != IB_PORT_PKEY_LISTED)
		return;

	pkey = get_pkey_idx_qp_list(pp);

	spin_lock(&pkey->qp_list_lock);
	list_del(&pp->qp_list);
	spin_unlock(&pkey->qp_list_lock);

	/* The setting may still be valid, i.e. after
	 * a destroy has failed for example.
	 */
	pp->state = IB_PORT_PKEY_VALID;
}

static void destroy_qp_security(struct ib_qp_security *sec)
{
	ib_policy_scope_watch_unregister(sec->policy_scope_watch);
	security_ib_free_security(sec->security);
	kfree(sec->ports_pkeys);
	kfree(sec);
}

/* The caller of this function must hold the QP security
 * mutex.
 */
static struct ib_ports_pkeys *get_new_pps(const struct ib_qp *qp,
					  const struct ib_qp_attr *qp_attr,
					  int qp_attr_mask)
{
	struct ib_ports_pkeys *new_pps;
	struct ib_ports_pkeys *qp_pps = qp->qp_sec->ports_pkeys;

	new_pps = kzalloc_obj(*new_pps);
	if (!new_pps)
		return NULL;

	if (qp_attr_mask & IB_QP_PORT)
		new_pps->main.port_num = qp_attr->port_num;
	else if (qp_pps)
		new_pps->main.port_num = qp_pps->main.port_num;

	if (qp_attr_mask & IB_QP_PKEY_INDEX)
		new_pps->main.pkey_index = qp_attr->pkey_index;
	else if (qp_pps)
		new_pps->main.pkey_index = qp_pps->main.pkey_index;

	if (((qp_attr_mask & IB_QP_PKEY_INDEX) &&
	     (qp_attr_mask & IB_QP_PORT)) ||
	    (qp_pps && qp_pps->main.state != IB_PORT_PKEY_NOT_VALID))
		new_pps->main.state = IB_PORT_PKEY_VALID;

	if (qp_attr_mask & IB_QP_ALT_PATH) {
		new_pps->alt.port_num = qp_attr->alt_port_num;
		new_pps->alt.pkey_index = qp_attr->alt_pkey_index;
		new_pps->alt.state = IB_PORT_PKEY_VALID;
	} else if (qp_pps) {
		new_pps->alt.port_num = qp_pps->alt.port_num;
		new_pps->alt.pkey_index = qp_pps->alt.pkey_index;
		if (qp_pps->alt.state != IB_PORT_PKEY_NOT_VALID)
			new_pps->alt.state = IB_PORT_PKEY_VALID;
	}

	new_pps->main.sec = qp->qp_sec;
	new_pps->alt.sec = qp->qp_sec;
	return new_pps;
}

int ib_open_shared_qp_security(struct ib_qp *qp, struct ib_device *dev)
{
	struct ib_qp *real_qp = qp->real_qp;
	int ret;

	ret = ib_create_qp_security(qp, dev);

	if (ret)
		return ret;

	if (!qp->qp_sec)
		return 0;

	mutex_lock(&real_qp->qp_sec->mutex);
	ret = check_qp_port_pkey_settings(real_qp->qp_sec->ports_pkeys,
					  qp->qp_sec);

	if (ret)
		goto ret;

	if (qp != real_qp) {
		list_add(&qp->qp_sec->shared_qp_list,
			 &real_qp->qp_sec->shared_qp_list);
		ret = ib_policy_scope_watch_register(
			qp->qp_sec->security, qp->qp_sec, IB_POLICY_SCOPE_QP,
			&qp->qp_sec->policy_scope_watch);
		if (ret)
			goto rollback_list;
		/* Close the authorize-before-index race with one indexed recheck. */
		ret = check_qp_port_pkey_settings_single(
			real_qp->qp_sec->ports_pkeys, qp->qp_sec);
		if (ret)
			goto rollback_list;
	}
	goto ret;

rollback_list:
	list_del_init(&qp->qp_sec->shared_qp_list);
	qp->qp_sec->destroying = true;
ret:
	mutex_unlock(&real_qp->qp_sec->mutex);
	if (ret)
		destroy_qp_security(qp->qp_sec);

	return ret;
}

void ib_close_shared_qp_security(struct ib_qp_security *sec)
{
	struct ib_qp *real_qp = sec->qp->real_qp;

	mutex_lock(&real_qp->qp_sec->mutex);
	sec->destroying = true;
	list_del_init(&sec->shared_qp_list);
	mutex_unlock(&real_qp->qp_sec->mutex);

	destroy_qp_security(sec);
}

int ib_create_qp_security(struct ib_qp *qp, struct ib_device *dev)
{
	unsigned int i;
	bool is_ib = false;
	int ret;

	rdma_for_each_port (dev, i) {
		is_ib = rdma_protocol_ib(dev, i);
		if (is_ib)
			break;
	}

	/* If this isn't an IB device don't create the security context */
	if (!is_ib)
		return 0;

	qp->qp_sec = kzalloc_obj(*qp->qp_sec);
	if (!qp->qp_sec)
		return -ENOMEM;

	qp->qp_sec->qp = qp;
	qp->qp_sec->dev = dev;
	mutex_init(&qp->qp_sec->mutex);
	INIT_LIST_HEAD(&qp->qp_sec->shared_qp_list);
	atomic_set(&qp->qp_sec->policy_blocked, 0);
	atomic_set(&qp->qp_sec->policy_pending, 0);
	atomic_set(&qp->qp_sec->policy_revoked, 0);
	atomic_set(&qp->qp_sec->policy_error, IB_POLICY_ERROR_IDLE);
	atomic_set(&qp->qp_sec->error_list_count, 0);
	init_completion(&qp->qp_sec->error_complete);
	ret = security_ib_alloc_security(&qp->qp_sec->security);
	if (ret) {
		kfree(qp->qp_sec);
		qp->qp_sec = NULL;
	} else if (qp->real_qp == qp) {
		ret = ib_policy_scope_watch_register(
			qp->qp_sec->security, qp->qp_sec, IB_POLICY_SCOPE_QP,
			&qp->qp_sec->policy_scope_watch);
		if (ret) {
			security_ib_free_security(qp->qp_sec->security);
			kfree(qp->qp_sec);
			qp->qp_sec = NULL;
		}
	}

	return ret;
}
EXPORT_SYMBOL(ib_create_qp_security);

void ib_destroy_qp_security_begin(struct ib_qp_security *sec)
{
	/* Return if not IB */
	if (!sec)
		return;

	mutex_lock(&sec->mutex);

	/* Remove the QP from the lists so it won't get added to
	 * a to_error_list during the destroy process.
	 */
	if (sec->ports_pkeys) {
		port_pkey_list_remove(&sec->ports_pkeys->main);
		port_pkey_list_remove(&sec->ports_pkeys->alt);
	}

	/* If the QP is already in one or more of those lists
	 * the destroying flag will ensure the to error flow
	 * doesn't operate on an undefined QP.
	 */
	sec->destroying = true;

	/* Record the error list count to know how many completions
	 * to wait for.
	 */
	sec->error_comps_pending = atomic_read(&sec->error_list_count);

	mutex_unlock(&sec->mutex);
}

void ib_destroy_qp_security_abort(struct ib_qp_security *sec)
{
	int ret;
	int i;

	/* Return if not IB */
	if (!sec)
		return;

	/* If a concurrent cache update is in progress this
	 * QP security could be marked for an error state
	 * transition.  Wait for this to complete.
	 */
	for (i = 0; i < sec->error_comps_pending; i++)
		wait_for_completion(&sec->error_complete);

	mutex_lock(&sec->mutex);
	sec->destroying = false;

	/* Restore the position in the lists and verify
	 * access is still allowed in case a cache update
	 * occurred while attempting to destroy.
	 *
	 * Because these setting were listed already
	 * and removed during ib_destroy_qp_security_begin
	 * we know the pkey_index_qp_list for the PKey
	 * already exists so port_pkey_list_insert won't fail.
	 */
	if (sec->ports_pkeys) {
		port_pkey_list_insert(&sec->ports_pkeys->main);
		port_pkey_list_insert(&sec->ports_pkeys->alt);
	}

	ret = check_qp_port_pkey_settings(sec->ports_pkeys, sec);
	if (ret)
		qp_to_error(sec);

	mutex_unlock(&sec->mutex);
}

void ib_destroy_qp_security_end(struct ib_qp_security *sec)
{
	int i;

	/* Return if not IB */
	if (!sec)
		return;

	/* If a concurrent cache update is occurring we must
	 * wait until this QP security structure is processed
	 * in the QP to error flow before destroying it because
	 * the to_error_list is in use.
	 */
	for (i = 0; i < sec->error_comps_pending; i++)
		wait_for_completion(&sec->error_complete);

	destroy_qp_security(sec);
}

void ib_security_cache_change(struct ib_device *device,
			      u32 port_num,
			      u64 subnet_prefix)
{
	struct pkey_index_qp_list *pkey;

	list_for_each_entry (pkey, &device->port_data[port_num].pkey_list,
			     pkey_index_list) {
		check_pkey_qps(pkey,
			       device,
			       port_num,
			       subnet_prefix);
	}
}

void ib_security_release_port_pkey_list(struct ib_device *device)
{
	struct pkey_index_qp_list *pkey, *tmp_pkey;
	unsigned int i;

	rdma_for_each_port (device, i) {
		list_for_each_entry_safe(pkey,
					 tmp_pkey,
					 &device->port_data[i].pkey_list,
					 pkey_index_list) {
			list_del(&pkey->pkey_index_list);
			kfree(pkey);
		}
	}
}

int ib_security_modify_qp(struct ib_qp *qp,
			  struct ib_qp_attr *qp_attr,
			  int qp_attr_mask,
			  struct ib_udata *udata)
{
	int ret = 0;
	struct ib_ports_pkeys *tmp_pps;
	struct ib_ports_pkeys *new_pps = NULL;
	struct ib_qp *real_qp = qp->real_qp;
	struct ib_qp_security *real_sec = real_qp->qp_sec;
	bool special_qp = (real_qp->qp_type == IB_QPT_SMI ||
			   real_qp->qp_type == IB_QPT_GSI ||
			   real_qp->qp_type >= IB_QPT_RESERVED1);
	bool pps_change = ((qp_attr_mask & (IB_QP_PKEY_INDEX | IB_QP_PORT)) ||
			   (qp_attr_mask & IB_QP_ALT_PATH));

	WARN_ONCE((qp_attr_mask & IB_QP_PORT &&
		   rdma_protocol_ib(real_qp->device, qp_attr->port_num) &&
		   !real_sec),
		   "%s: QP security is not initialized for IB QP: %u\n",
		   __func__, real_qp->qp_num);
	if (real_sec) {
		/* Serialize the gate recheck and every driver modify with PRE/ERR. */
		mutex_lock(&real_sec->mutex);
		if (atomic_read(&real_sec->policy_blocked)) {
			ret = -EACCES;
			goto out_unlock;
		}
	}

	/* The port/pkey settings are maintained only for the real QP. Open
	 * handles on the real QP will be in the shared_qp_list. When
	 * enforcing security on the real QP all the shared QPs will be
	 * checked as well.
	 */

	if (pps_change && !special_qp && real_sec) {
		new_pps = get_new_pps(real_qp,
				      qp_attr,
				      qp_attr_mask);
		if (!new_pps) {
			ret = -ENOMEM;
			goto out_unlock;
		}
		/* Add this QP to the lists for the new port
		 * and pkey settings before checking for permission
		 * in case there is a concurrent cache update
		 * occurring.  Walking the list for a cache change
		 * doesn't acquire the security mutex unless it's
		 * sending the QP to error.
		 */
		ret = port_pkey_list_insert(&new_pps->main);

		if (!ret)
			ret = port_pkey_list_insert(&new_pps->alt);

		if (!ret)
			ret = check_qp_port_pkey_settings(new_pps,
							  real_sec);
	}

	if (!ret)
		ret = real_qp->device->ops.modify_qp(real_qp,
						     qp_attr,
						     qp_attr_mask,
						     udata);

	if (new_pps) {
		/* Clean up the lists and free the appropriate
		 * ports_pkeys structure.
		 */
		if (ret) {
			tmp_pps = new_pps;
		} else {
			tmp_pps = real_sec->ports_pkeys;
			real_sec->ports_pkeys = new_pps;
		}

		if (tmp_pps) {
			port_pkey_list_remove(&tmp_pps->main);
			port_pkey_list_remove(&tmp_pps->alt);
		}
		kfree(tmp_pps);
	}
out_unlock:
	if (real_sec)
		mutex_unlock(&real_sec->mutex);
	return ret;
}

static int ib_security_pkey_access(struct ib_device *dev,
				   u32 port_num,
				   u16 pkey_index,
				   void *sec)
{
	u64 subnet_prefix;
	u16 pkey;
	int ret;

	if (!rdma_protocol_ib(dev, port_num))
		return 0;

	ret = ib_get_cached_pkey(dev, port_num, pkey_index, &pkey);
	if (ret)
		return ret;

	ib_get_cached_subnet_prefix(dev, port_num, &subnet_prefix);

	return security_ib_pkey_access(sec, subnet_prefix, pkey);
}

void ib_mad_agent_security_change(void)
{
	struct ib_mad_agent *ag;

	spin_lock(&mad_agent_list_lock);
	list_for_each_entry(ag,
			    &mad_agent_list,
			    mad_agent_sec_list)
		WRITE_ONCE(ag->smp_allowed,
			   !security_ib_endport_manage_subnet(ag->security,
				dev_name(&ag->device->dev), ag->port_num));
	spin_unlock(&mad_agent_list_lock);
}

int ib_mad_agent_security_setup(struct ib_mad_agent *agent,
				enum ib_qp_type qp_type)
{
	int ret;

	if (!rdma_protocol_ib(agent->device, agent->port_num))
		return 0;

	INIT_LIST_HEAD(&agent->mad_agent_sec_list);

	ret = security_ib_alloc_security(&agent->security);
	if (ret)
		return ret;

	if (qp_type != IB_QPT_SMI)
		return 0;

	spin_lock(&mad_agent_list_lock);
	ret = security_ib_endport_manage_subnet(agent->security,
						dev_name(&agent->device->dev),
						agent->port_num);
	if (ret)
		goto free_security;

	WRITE_ONCE(agent->smp_allowed, true);
	ret = ib_policy_scope_watch_register(
		agent->security, agent, IB_POLICY_SCOPE_MAD,
		&agent->policy_scope_watch);
	if (ret)
		goto free_security;
	/* Close the authorize-before-index race without reopening the gate. */
	ret = security_ib_endport_manage_subnet(agent->security,
						dev_name(&agent->device->dev),
						agent->port_num);
	if (ret)
		goto unregister_security;
	list_add(&agent->mad_agent_sec_list, &mad_agent_list);
	spin_unlock(&mad_agent_list_lock);
	return 0;

unregister_security:
	WRITE_ONCE(agent->smp_allowed, false);
	spin_unlock(&mad_agent_list_lock);
	ib_policy_scope_watch_unregister(agent->policy_scope_watch);
	agent->policy_scope_watch = NULL;
	security_ib_free_security(agent->security);
	return ret;
free_security:
	spin_unlock(&mad_agent_list_lock);
	security_ib_free_security(agent->security);
	return ret;
}

void ib_mad_agent_security_cleanup(struct ib_mad_agent *agent)
{
	if (!rdma_protocol_ib(agent->device, agent->port_num))
		return;

	if (agent->qp->qp_type == IB_QPT_SMI) {
		ib_policy_scope_watch_unregister(agent->policy_scope_watch);
		agent->policy_scope_watch = NULL;
		spin_lock(&mad_agent_list_lock);
		list_del(&agent->mad_agent_sec_list);
		spin_unlock(&mad_agent_list_lock);
	}

	security_ib_free_security(agent->security);
}

int ib_mad_enforce_security(struct ib_mad_agent_private *map, u16 pkey_index)
{
	if (!rdma_protocol_ib(map->agent.device, map->agent.port_num))
		return 0;

	if (map->agent.qp->qp_type == IB_QPT_SMI) {
		if (!READ_ONCE(map->agent.smp_allowed))
			return -EACCES;
		return 0;
	}

	return ib_security_pkey_access(map->agent.device,
				       map->agent.port_num,
				       pkey_index,
				       map->agent.security);
}
