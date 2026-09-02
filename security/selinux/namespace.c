// SPDX-License-Identifier: GPL-2.0-only
/* SELinux policy namespace lifecycle and nsfs integration. */

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/nsfs.h>
#include <linux/nstree.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/vmalloc.h>
#include <linux/selinux_ns.h>
#include <crypto/sha2.h>

#include "chain.h"
#include "av_permissions.h"
#include "namespace.h"
#include "resource.h"
#include "security.h"

static struct ns_tree_root selinux_ns_tree = {
	.ns_rb = RB_ROOT,
	.ns_list_head = LIST_HEAD_INIT(selinux_ns_tree.ns_list_head),
};

static struct selinux_ns_control *selinux_ns_from_common(struct ns_common *ns)
{
	return container_of(ns, struct selinux_ns_control, ns);
}

static u64 selinux_ns_parent_id(const struct selinux_state *state)
{
	return state->parent ? state->parent->id : 0;
}

static long selinux_ns_control_load_policy(
	struct selinux_ns_control *control,
	unsigned long arg)
{
	struct selinux_ns_policy request;
	struct selinux_load_state load_state;
	void *policy = NULL;
	int rc;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.flags || !request.data || !request.size ||
	    request.size > CONFIG_SECURITY_SELINUX_POLICY_MAX_BYTES)
		return -EINVAL;

	rc = selinux_state_policy_mutation_allowed(
		control->state,
		current_cred(),
		SECURITY__LOAD_POLICY,
		true);
	if (rc)
		return rc;

	policy = vmalloc(request.size);
	if (!policy)
		return -ENOMEM;
	if (copy_from_user(policy, u64_to_user_ptr(request.data), request.size)) {
		rc = -EFAULT;
		goto out;
	}

	mutex_lock(&control->lock);
	mutex_lock(&control->state->policy_mutex);
	rc = security_load_policy(
		control->state,
		policy,
		request.size,
		&load_state);
	if (rc)
		goto out_unlock;

	rc = selinux_chain_update_prepare(control->state);
	if (rc)
		goto out_cancel;
	rc = selinux_chain_update_begin(control->state);
	if (rc) {
		selinux_chain_update_abort(control->state);
		goto out_cancel;
	}

	sha256(policy, request.size, control->state->policy_digest);
	selinux_policy_commit(control->state, &load_state);
	selinux_chain_update_end(control->state);
	selinux_chain_update_complete(control->state);
	goto out_unlock;

out_cancel:
	selinux_policy_cancel(control->state, &load_state);
out_unlock:
	mutex_unlock(&control->state->policy_mutex);
	mutex_unlock(&control->lock);
out:
	vfree(policy);
	return rc;
}

static long selinux_ns_control_join(struct selinux_ns_control *control)
{
	struct cred *prepared;
	int rc;

	rc = selinux_ns_control_prepare_join(control, &prepared);
	if (rc)
		return rc;
	rc = commit_creds(prepared);
	security_task_setns_cred_for_children(current_cred());
	return rc;
}

static long selinux_ns_control_get_info(
	const struct selinux_ns_control *control,
	unsigned long arg)
{
	struct selinux_ns_info info = {
		.id = control->state->id,
		.parent_id = selinux_ns_parent_id(control->state),
		.depth = control->state->depth,
	};

	if (selinux_initialized(control->state))
		info.flags |= SELINUX_NS_INFO_INITIALIZED;
	if (selinux_state_active(control->state))
		info.flags |= SELINUX_NS_INFO_ACTIVE;
	return copy_to_user((void __user *)arg, &info, sizeof(info)) ?
		-EFAULT : 0;
}

static long selinux_ns_control_get_metadata(
	const struct selinux_ns_control *control,
	unsigned long arg)
{
	struct selinux_ns_metadata metadata = {
		.size = sizeof(metadata),
		.id = control->state->id,
		.parent_id = selinux_ns_parent_id(control->state),
		.domain_id = control->state->id,
		.parent_domain_id = selinux_ns_parent_id(control->state),
		.depth = control->state->depth,
		.policy_seqno = READ_ONCE(control->state->policy_seqno),
	};

	memcpy(
		metadata.policy_digest,
		control->state->policy_digest,
		sizeof(metadata.policy_digest));
	return copy_to_user((void __user *)arg, &metadata, sizeof(metadata)) ?
		-EFAULT : 0;
}

long selinux_ns_control_ioctl(
	struct selinux_ns_control *control,
	unsigned int cmd,
	unsigned long arg)
{
	int rc;

	if (!control)
		return -EINVAL;

	switch (cmd) {
	case SELINUX_NS_IOC_LOAD_POLICY:
		return selinux_ns_control_load_policy(control, arg);
	case SELINUX_NS_IOC_ACTIVATE:
		if (arg)
			return -EINVAL;
		rc = selinux_ns_control_authorize_parent(
			control,
			current_cred());
		if (rc)
			return rc;
		return selinux_ns_control_activate(
			control,
			cred_selinux_state(current_cred()));
	case SELINUX_NS_IOC_JOIN:
		if (arg)
			return -EINVAL;
		return selinux_ns_control_join(control);
	case SELINUX_NS_IOC_GET_INFO:
		return selinux_ns_control_get_info(control, arg);
	case SELINUX_NS_IOC_GET_METADATA:
		return selinux_ns_control_get_metadata(control, arg);
	default:
		return -ENOTTY;
	}
}

int selinux_ns_control_state_init(struct selinux_state *state, bool active)
{
	struct selinux_ns_control *control;
	u64 bytes = sizeof(*state) + sizeof(*control);
	int rc;

	if (!state || !state->resources || state->ns_control)
		return -EINVAL;

	rc = selinux_namespace_reserve(
		state->resources,
		bytes,
		READ_ONCE(selinux_maxns));
	if (rc)
		return rc;

	control = kzalloc_obj(*control, GFP_KERNEL_ACCOUNT);
	if (!control) {
		rc = -ENOMEM;
		goto err_charge;
	}

	mutex_init(&control->lock);
	control->state = state;
	control->resources = selinux_resource_account_get(state->resources);
	control->resource_bytes = bytes;
	rc = __ns_common_init(&control->ns, 0, &selinuxns_operations, 0);
	if (rc)
		goto err_control;

	/*
	 * Assign the namespace identity before publishing the control object or
	 * taking any additional references to it.  The generic namespace helpers
	 * reserve the low IDs for initial namespaces; leaving ns_id at zero would
	 * therefore make __ns_ref_inc() treat a dormant control as an initial
	 * namespace and skip the increment.
	 */
	if (!__ns_tree_gen_id(&control->ns, 0)) {
		rc = -EOVERFLOW;
		goto err_common;
	}

	state->ns_control = control;
	if (active) {
		__ns_tree_add_raw(&control->ns, &selinux_ns_tree);
		control->tree_published = true;
		__ns_ref_active_get(&control->ns);
	}
	return 0;

err_common:
	__ns_common_free(&control->ns);
err_control:
	selinux_resource_account_put(control->resources);
	kfree(control);
err_charge:
	selinux_namespace_release(state->resources, bytes);
	return rc;
}

void selinux_ns_control_state_destroy(struct selinux_state *state)
{
	struct selinux_ns_control *control;

	if (!state)
		return;
	control = state->ns_control;
	if (!control)
		return;

	if (selinux_state_active(state))
		__ns_ref_active_put(&control->ns);
	if (control->tree_published)
		__ns_tree_remove(&control->ns, &selinux_ns_tree);
	WARN_ON_ONCE(!__ns_ref_put(&control->ns));
	__ns_common_free(&control->ns);
	selinux_namespace_release(
		control->resources,
		control->resource_bytes);
	selinux_resource_account_put(control->resources);
	kfree(control);
	state->ns_control = NULL;
}

struct selinux_ns_control *selinux_ns_control_alloc_unassigned(
	const struct cred *cred)
{
	struct selinux_state *state;
	struct selinux_ns_control *control;

	state = selinux_state_create_dormant(cred);
	if (IS_ERR(state))
		return ERR_CAST(state);

	control = selinux_ns_control_get(state->ns_control);
	put_selinux_state(state);
	return control;
}

struct selinux_ns_control *selinux_ns_control_alloc(const struct cred *cred)
{
	return selinux_ns_control_alloc_unassigned(cred);
}

struct selinux_ns_control *selinux_ns_control_get(
	struct selinux_ns_control *control)
{
	if (!control)
		return NULL;
	__ns_ref_inc(&control->ns);
	get_selinux_state(control->state);
	return control;
}

void selinux_ns_control_put(struct selinux_ns_control *control)
{
	if (!control)
		return;
	WARN_ON_ONCE(__ns_ref_put(&control->ns));
	put_selinux_state(control->state);
}

struct selinux_ns_control *selinux_ns_control_get_from_file(
	const struct file *file)
{
	struct ns_common *ns;

	if (!file || !proc_ns_file(file))
		return ERR_PTR(-EINVAL);
	ns = get_proc_ns(file_inode(file));
	if (!ns || ns->ops != &selinuxns_operations)
		return ERR_PTR(-EINVAL);
	return selinux_ns_control_get(selinux_ns_from_common(ns));
}

bool selinux_ns_control_parent(
	const struct selinux_ns_control *control,
	const struct selinux_state *actor)
{
	return control && actor && control->state->parent == actor;
}

int selinux_ns_control_authorize_parent(
	struct selinux_ns_control *control,
	const struct cred *cred)
{
	if (!control || !cred)
		return -EINVAL;
	if (!selinux_ns_control_parent(control, cred_selinux_state(cred)))
		return -EPERM;
	if (security_capable(
		cred,
		control->state->owner_userns,
		CAP_MAC_ADMIN,
		CAP_OPT_NONE))
		return -EPERM;
	return selinux_chain_has_self_perm(
		cred,
		SECCLASS_PROCESS2,
		PROCESS2__UNSHARE_SELINUXNS,
		NULL);
}

int selinux_ns_control_authorize_direct_child(
	struct selinux_ns_control *control,
	const struct cred *cred)
{
	int rc;

	rc = selinux_ns_control_authorize_parent(control, cred);
	if (rc)
		return rc;
	if (!selinux_state_active(control->state))
		return -EAGAIN;
	return selinux_state_has_initial_perm(
		control->state,
		SECINITSID_INIT,
		SECINITSID_INIT,
		SECCLASS_PROCESS2,
		PROCESS2__UNSHARE_SELINUXNS,
		NULL);
}

static int selinux_ns_control_activate_locked(
	struct selinux_ns_control *control)
{
	int rc;

	lockdep_assert_held(&control->lock);
	if (selinux_state_active(control->state))
		return -EALREADY;
	if (!selinux_initialized(control->state))
		return -EAGAIN;

	rc = selinux_chain_update_prepare(control->state);
	if (rc)
		return rc;
	rc = selinux_chain_update_begin(control->state);
	if (rc) {
		selinux_chain_update_abort(control->state);
		return rc;
	}

	__ns_tree_add_raw(&control->ns, &selinux_ns_tree);
	control->tree_published = true;
	__ns_ref_active_get(&control->ns);
	selinux_state_mark_active(control->state);
	selinux_chain_update_end(control->state);
	selinux_chain_update_complete(control->state);
	return 0;
}

int selinux_ns_control_activate(
	struct selinux_ns_control *control,
	const struct selinux_state *actor)
{
	int rc;

	if (!selinux_ns_control_parent(control, actor))
		return -EPERM;
	mutex_lock(&control->lock);
	rc = selinux_ns_control_activate_locked(control);
	mutex_unlock(&control->lock);
	return rc;
}

struct selinux_state *selinux_ns_control_state_get(
	struct selinux_ns_control *control)
{
	return control ? get_selinux_state(control->state) : NULL;
}

static int selinux_ns_prepare_cred(
	struct selinux_ns_control *control,
	const struct cred *actor,
	struct cred *prepared)
{
	struct cred_security_struct *security = selinux_cred(prepared);
	int rc;

	rc = selinux_ns_control_authorize_direct_child(control, actor);
	if (rc)
		return rc;

	put_selinux_state(security->state);
	put_cred(security->parent_cred);
	security->state = get_selinux_state(control->state);
	security->parent_cred = get_cred(actor);
	security->osid = SECINITSID_INIT;
	security->sid = SECINITSID_INIT;
	security->exec_sid = SECSID_NULL;
	security->create_sid = SECSID_NULL;
	security->keycreate_sid = SECSID_NULL;
	security->sockcreate_sid = SECSID_NULL;
	return 0;
}

int selinux_ns_control_prepare_join(
	struct selinux_ns_control *control,
	struct cred **prepared)
{
	struct cred *new;
	int rc;

	if (!prepared)
		return -EINVAL;
	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	rc = selinux_ns_prepare_cred(control, current_cred(), new);
	if (rc) {
		abort_creds(new);
		return rc;
	}
	*prepared = new;
	return 0;
}

static int selinux_ns_prepare_cred_for_children(
	struct selinux_ns_control *control,
	const struct cred *actor,
	struct cred **prepared)
{
	const struct cred *ancestor;
	struct cred *new;
	int rc;

	if (!control || !actor || !prepared)
		return -EINVAL;
	if (!selinux_state_active(control->state))
		return -EAGAIN;

	if (control->state->parent == cred_selinux_state(actor)) {
		new = prepare_creds();
		if (!new)
			return -ENOMEM;
		rc = selinux_ns_prepare_cred(control, actor, new);
		if (rc) {
			abort_creds(new);
			return rc;
		}
		*prepared = new;
		return 0;
	}

	ancestor = selinux_chain_cred_for_state(actor, control->state);
	if (!ancestor)
		return -EXDEV;
	if (security_capable(
		actor,
		control->state->owner_userns,
		CAP_MAC_ADMIN,
		CAP_OPT_NONE))
		return -EPERM;
	rc = selinux_chain_has_self_perm(
		actor,
		SECCLASS_PROCESS2,
		PROCESS2__UNSHARE_SELINUXNS,
		NULL);
	if (rc)
		return rc;
	*prepared = (struct cred *)get_cred(ancestor);
	return 0;
}

static struct ns_common *selinuxns_get(struct task_struct *task)
{
	const struct cred *cred = get_task_cred(task);
	struct selinux_ns_control *control =
		selinux_cred(cred)->state->ns_control;

	selinux_ns_control_get(control);
	put_cred(cred);
	return &control->ns;
}

static void selinuxns_put(struct ns_common *ns)
{
	selinux_ns_control_put(selinux_ns_from_common(ns));
}

static int selinuxns_install(struct nsset *nsset, struct ns_common *ns)
{
	struct selinux_ns_control *control = selinux_ns_from_common(ns);
	struct cred *prepared;
	int rc;

	rc = selinux_ns_prepare_cred_for_children(
		control,
		current_cred(),
		&prepared);
	if (rc)
		return rc;
	rc = nsset_install_security_cred_for_children(nsset, prepared);
	if (rc)
		put_cred(prepared);
	return rc;
}

static struct user_namespace *selinuxns_owner(struct ns_common *ns)
{
	return selinux_ns_from_common(ns)->state->owner_userns;
}

static struct ns_common *selinuxns_get_parent(struct ns_common *ns)
{
	struct selinux_state *parent =
		selinux_ns_from_common(ns)->state->parent;

	if (!parent)
		return ERR_PTR(-EPERM);
	selinux_ns_control_get(parent->ns_control);
	return &parent->ns_control->ns;
}

static long selinuxns_ioctl(
	struct ns_common *ns,
	unsigned int cmd,
	unsigned long arg)
{
	return selinux_ns_control_ioctl(
		selinux_ns_from_common(ns),
		cmd,
		arg);
}

const struct proc_ns_operations selinuxns_operations = {
	.name = "selinux",
	.get = selinuxns_get,
	.put = selinuxns_put,
	.install = selinuxns_install,
	.owner = selinuxns_owner,
	.get_parent = selinuxns_get_parent,
	.ioctl = selinuxns_ioctl,
};
