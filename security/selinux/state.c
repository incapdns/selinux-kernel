// SPDX-License-Identifier: GPL-2.0-only
/* SELinux policy-state tree and namespace lifetime management. */

#include <linux/err.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include "chain.h"
#include "namespace.h"
#include "object_label.h"
#include "resource.h"
#include "security.h"

unsigned int selinux_maxns = CONFIG_SECURITY_SELINUX_MAXNS;
unsigned int selinux_maxnsdepth = CONFIG_SECURITY_SELINUX_MAXNSDEPTH;

struct selinux_state *init_selinux_state;

static atomic_t selinux_nsnum = ATOMIC_INIT(0);
static atomic64_t selinux_state_id = ATOMIC64_INIT(0);
static DEFINE_MUTEX(selinux_state_tree_mutex);

static void selinux_state_free(struct work_struct *work);

int selinux_state_policy_mutation_allowed(
	struct selinux_state *target,
	const struct cred *cred,
	u32 permission,
	bool allow_dormant_parent)
{
	const struct cred_security_struct *credsec;
	bool parent_constructing;
	int rc;

	if (!target || !cred || !permission)
		return -EINVAL;

	credsec = selinux_cred(cred);
	parent_constructing = allow_dormant_parent &&
		!selinux_state_active(target) && target->parent == credsec->state;
	if (!parent_constructing && credsec->state != target)
		return -EPERM;

	rc = security_capable(
		cred,
		target->owner_userns,
		CAP_MAC_ADMIN,
		CAP_OPT_NONE);
	if (rc)
		return rc;

	return selinux_chain_has_initial_perm(
		cred,
		SECINITSID_SECURITY,
		SECCLASS_SECURITY,
		permission,
		NULL);
}

int selinux_state_set_maxns(unsigned int value)
{
	int rc = 0;

	if (!value || value > SELINUX_MAX_NAMESPACES_LIMIT)
		return -EINVAL;

	mutex_lock(&selinux_state_tree_mutex);
	if (value < atomic_read(&selinux_nsnum))
		rc = -EBUSY;
	else
		WRITE_ONCE(selinux_maxns, value);
	mutex_unlock(&selinux_state_tree_mutex);
	return rc;
}

int selinux_state_set_maxnsdepth(unsigned int value)
{
	if (value > SELINUX_NS_MAX_DEPTH)
		return -EINVAL;

	mutex_lock(&selinux_state_tree_mutex);
	WRITE_ONCE(selinux_maxnsdepth, value);
	mutex_unlock(&selinux_state_tree_mutex);
	return 0;
}

u64 selinux_chain_epoch_read(const struct selinux_state *state)
{
	u64 epoch;

	if (unlikely(atomic_read_acquire(&state->chain_updates)))
		return 0;

	epoch = atomic64_read(&state->chain_epoch);
	smp_rmb();
	if (unlikely(atomic_read(&state->chain_updates)))
		return 0;
	return epoch;
}

bool selinux_chain_update_active(const struct selinux_state *state)
{
	return atomic_read_acquire(&state->chain_updates) != 0;
}

static void selinux_chain_epoch_advance_one(struct selinux_state *state)
{
	s64 epoch = atomic64_read(&state->chain_epoch);

	if (epoch > 0 && epoch < S64_MAX)
		atomic64_inc(&state->chain_epoch);
	else
		atomic64_set(&state->chain_epoch, 0);
}

static void selinux_chain_epoch_bump_locked(struct selinux_state *state)
{
	struct selinux_state *child;

	selinux_chain_epoch_advance_one(state);
	list_for_each_entry(child, &state->children, sibling)
		selinux_chain_epoch_bump_locked(child);
}

static void selinux_chain_update_begin_locked(struct selinux_state *state)
{
	struct selinux_state *child;

	if (atomic_read(&state->chain_updates) != INT_MAX)
		atomic_inc_return(&state->chain_updates);
	selinux_chain_epoch_advance_one(state);
	list_for_each_entry(child, &state->children, sibling)
		selinux_chain_update_begin_locked(child);
}

static void selinux_chain_update_release_one(struct selinux_state *state)
{
	int updates = atomic_read(&state->chain_updates);

	if (updates == INT_MAX)
		return;
	if (WARN_ON_ONCE(updates <= 0))
		atomic_set_release(&state->chain_updates, 0);
	else
		atomic_dec_return_release(&state->chain_updates);
}

static void selinux_chain_update_end_locked(struct selinux_state *state)
{
	struct selinux_state *child;

	selinux_chain_epoch_advance_one(state);
	selinux_chain_update_release_one(state);
	list_for_each_entry(child, &state->children, sibling)
		selinux_chain_update_end_locked(child);
}

void selinux_chain_epoch_bump(struct selinux_state *state)
{
	mutex_lock(&selinux_state_tree_mutex);
	selinux_chain_epoch_bump_locked(state);
	mutex_unlock(&selinux_state_tree_mutex);
}

int selinux_chain_update_begin(struct selinux_state *state)
{
	mutex_lock(&selinux_state_tree_mutex);
	selinux_chain_update_begin_locked(state);
	mutex_unlock(&selinux_state_tree_mutex);
	return 0;
}

int selinux_chain_update_prepare(struct selinux_state *state)
{
	return state ? 0 : -EINVAL;
}

void selinux_chain_update_end(struct selinux_state *state)
{
	mutex_lock(&selinux_state_tree_mutex);
	selinux_chain_update_end_locked(state);
	mutex_unlock(&selinux_state_tree_mutex);
}

void selinux_chain_update_abort(struct selinux_state *state)
{
}

void selinux_chain_update_complete(struct selinux_state *state)
{
	if (state)
		call_blocking_lsm_notifier(LSM_POLICY_CHANGE, NULL);
}

static struct selinux_state *selinux_state_alloc(
	const struct cred *cred,
	bool active)
{
	const struct cred_security_struct *credsec = selinux_cred(cred);
	struct selinux_state *parent = credsec->state;
	struct selinux_state *state;
	u64 state_id;
	bool namespace_counted = false;
	int rc;

	mutex_lock(&selinux_state_tree_mutex);
	if (atomic_read(&selinux_nsnum) >= READ_ONCE(selinux_maxns) ||
	    (parent && parent->depth >= READ_ONCE(selinux_maxnsdepth))) {
		mutex_unlock(&selinux_state_tree_mutex);
		return ERR_PTR(-ENOSPC);
	}
	atomic_inc(&selinux_nsnum);
	namespace_counted = true;
	mutex_unlock(&selinux_state_tree_mutex);

	state_id = atomic64_inc_return(&selinux_state_id);
	if (!state_id || state_id > S64_MAX) {
		rc = -EOVERFLOW;
		goto err_count;
	}

	state = kzalloc_obj(*state, GFP_KERNEL_ACCOUNT);
	if (!state) {
		rc = -ENOMEM;
		goto err_count;
	}

	state->id = state_id;
	WRITE_ONCE(state->active, active);
	INIT_LIST_HEAD(&state->children);
	INIT_LIST_HEAD(&state->sibling);
	atomic64_set(&state->chain_epoch, 1);
	atomic_set(&state->chain_updates, 0);
	refcount_set(&state->count, 1);
	INIT_WORK(&state->work, selinux_state_free);
	mutex_init(&state->status_lock);
	mutex_init(&state->policy_mutex);
	atomic64_set(&state->policy_snapshot_bytes, 0);

	if (parent) {
		state->parent = get_selinux_state(parent);
		state->depth = parent->depth + 1;
	}

	state->owner_userns = get_user_ns(cred->user_ns);
	state->resources = selinux_resource_account_get_owner(
		state->owner_userns);
	if (IS_ERR(state->resources)) {
		rc = PTR_ERR(state->resources);
		state->resources = NULL;
		goto err_parent;
	}

	rc = selinux_object_label_table_init(state);
	if (rc)
		goto err_resources;

	rc = selinux_ns_control_state_init(state, active);
	if (rc)
		goto err_labels;

	rc = selinux_avc_create(state->resources, &state->avc);
	if (rc)
		goto err_control;

	if (parent) {
		mutex_lock(&selinux_state_tree_mutex);
		atomic_set(&state->chain_updates,
			   atomic_read(&parent->chain_updates));
		list_add_tail(&state->sibling, &parent->children);
		mutex_unlock(&selinux_state_tree_mutex);
	}
	return state;

err_control:
	selinux_ns_control_state_destroy(state);
err_labels:
	selinux_object_label_table_destroy(state);
err_resources:
	selinux_resource_account_put(state->resources);
	put_user_ns(state->owner_userns);
err_parent:
	put_selinux_state(state->parent);
	kfree(state);
err_count:
	if (namespace_counted) {
		mutex_lock(&selinux_state_tree_mutex);
		atomic_dec(&selinux_nsnum);
		mutex_unlock(&selinux_state_tree_mutex);
	}
	return ERR_PTR(rc);
}

struct selinux_state *selinux_state_create_dormant(const struct cred *cred)
{
	return selinux_state_alloc(cred, false);
}

int selinux_state_init_initial(const struct cred *cred, bool enforcing)
{
	struct selinux_state *state;

	if (!cred || init_selinux_state)
		return -EINVAL;

	state = selinux_state_alloc(cred, true);
	if (IS_ERR(state))
		return PTR_ERR(state);

	enforcing_set(state, enforcing);
	init_selinux_state = state;
	return 0;
}

static void selinux_state_free(struct work_struct *work)
{
	struct selinux_state *state = container_of(
		work, struct selinux_state, work);

	for (;;) {
		struct selinux_state *parent = state->parent;

		mutex_lock(&selinux_state_tree_mutex);
		WARN_ON(!list_empty(&state->children));
		if (parent)
			list_del_init(&state->sibling);
		atomic_dec(&selinux_nsnum);
		mutex_unlock(&selinux_state_tree_mutex);

		if (state->status_page)
			__free_page(state->status_page);
		WARN_ON(atomic64_read(&state->policy_snapshot_bytes));
		selinux_state_policy_free(state);
		selinux_avc_free(state->avc);
		selinux_ns_control_state_destroy(state);
		selinux_object_label_table_destroy(state);
		selinux_resource_account_put(state->resources);
		put_user_ns(state->owner_userns);
		kfree(state);

		if (!parent || !refcount_dec_and_test(&parent->count))
			break;
		state = parent;
	}
}

void __put_selinux_state(struct selinux_state *state)
{
	schedule_work(&state->work);
}
