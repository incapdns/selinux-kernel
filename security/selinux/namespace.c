// SPDX-License-Identifier: GPL-2.0-only
/* Parent-owned, two-phase SELinux namespace construction. */

#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kconfig.h>
#include <linux/ipc_namespace.h>
#include <linux/nsproxy.h>
#include <linux/nstree.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>

#include "avc.h"
#include "global_sidtab.h"
#include "namespace.h"
#include "resource.h"
#include "security.h"
#include "ss/services.h"

/* Type zero is reserved here for direct nsfs/setns(fd, 0) integration. */
static struct ns_tree_root selinux_ns_tree = {
	.ns_rb = RB_ROOT,
	.ns_list_head = LIST_HEAD_INIT(selinux_ns_tree.ns_list_head),
};

static const char selinux_ns_map_digest_domain[] =
	"SELinux namespace map transcript v1\0";

static struct selinux_ns_control *selinux_ns_from_common(struct ns_common *ns)
{
	return container_of(ns, struct selinux_ns_control, ns);
}

int selinux_ns_control_state_init(struct selinux_state *state, bool active)
{
	struct selinux_ns_control *control;
	struct selinux_resource_account *resources;
	u64 resource_bytes = sizeof(*state) + sizeof(*control);
	int rc;

	resources = selinux_resource_account_get(state->label_domain->resources);
	if (!resources)
		return -EOPNOTSUPP;
	rc = selinux_namespace_reserve(resources, resource_bytes,
				       READ_ONCE(selinux_maxns));
	if (rc)
		goto err_resources;
	control = kzalloc_obj(*control, GFP_KERNEL_ACCOUNT);
	if (!control) {
		rc = -ENOMEM;
		goto err_charge;
	}
	mutex_init(&control->lock);
	control->state = state;
	control->resources = resources;
	control->resource_bytes = resource_bytes;
	sha256_init(&control->map_digest_ctx);
	sha256_update(&control->map_digest_ctx, selinux_ns_map_digest_domain,
		      sizeof(selinux_ns_map_digest_domain));
	rc = __ns_common_init(&control->ns, 0, &selinuxns_operations, 0);
	if (rc)
		goto err_control;
	if (active) {
		rc = __ns_tree_gen_id(&control->ns, 0) ? 0 : -EOVERFLOW;
		if (rc)
			goto err_common;
	}
	if (state->parent) {
		control->map = selinux_label_map_alloc(
			state->parent->label_domain, state->label_domain);
		if (IS_ERR(control->map)) {
			rc = PTR_ERR(control->map);
			control->map = NULL;
			goto err_common;
		}
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
	kfree(control);
err_charge:
	selinux_namespace_release(resources, resource_bytes);
err_resources:
	selinux_resource_account_put(resources);
	return rc;
}

void selinux_ns_control_state_destroy(struct selinux_state *state)
{
	struct selinux_ns_control *control = state->ns_control;

	if (!control)
		return;
	if (selinux_state_active(state))
		__ns_ref_active_put(&control->ns);
	if (control->tree_published)
		__ns_tree_remove(&control->ns, &selinux_ns_tree);
	selinux_label_map_put(control->map);
	WARN_ON_ONCE(!__ns_ref_put(&control->ns));
	__ns_common_free(&control->ns);
	selinux_namespace_release(control->resources, control->resource_bytes);
	selinux_resource_account_put(control->resources);
	kfree(control);
	state->ns_control = NULL;
}

struct selinux_ns_control *selinux_ns_control_alloc_unassigned(
	const struct cred *cred)
{
	struct selinux_state *state;

	state = selinux_state_create_dormant(cred);
	if (IS_ERR(state))
		return ERR_CAST(state);
	/* Convert the state constructor's reference into a control reference. */
	selinux_ns_control_get(state->ns_control);
	put_selinux_state(state);
	return state->ns_control;
}

struct selinux_ns_control *selinux_ns_control_alloc(const struct cred *cred)
{
	struct selinux_ns_control *control;

	control = selinux_ns_control_alloc_unassigned(cred);
	if (IS_ERR(control))
		return control;
	if (!__ns_tree_gen_id(&control->ns, 0)) {
		selinux_ns_control_put(control);
		return ERR_PTR(-EOVERFLOW);
	}
	return control;
}

int selinux_ns_control_reserve_id(struct selinux_ns_control *control,
				  u64 expected_id)
{
	if (!control || control->ns.ns_id)
		return -EINVAL;
	return __ns_tree_reserve_id(&control->ns, expected_id);
}

int selinux_ns_restore_parent_validate(const struct selinux_state *parent,
				       u64 expected_parent_id)
{
	if (!parent || !parent->ns_control ||
	    parent->ns_control->ns.ns_id != expected_parent_id)
		return -ESTALE;
	return 0;
}

struct selinux_ns_control *
selinux_ns_control_get(struct selinux_ns_control *control)
{
	if (control)
		__ns_ref_inc(&control->ns);
	if (control)
		get_selinux_state(control->state);
	return control;
}

void selinux_ns_control_put(struct selinux_ns_control *control)
{
	if (control) {
		WARN_ON_ONCE(__ns_ref_put(&control->ns));
		put_selinux_state(control->state);
	}
}

/**
 * selinux_ns_control_get_from_file - Acquire a SELinux namespace control
 * @file: referenced namespace file
 *
 * Return: a referenced control, whether dormant or active, or an error
 * pointer. The caller must release a successful result with
 * selinux_ns_control_put(). Activation is checked by the operation which
 * requires it, not by nsfs type validation.
 */
struct selinux_ns_control *
selinux_ns_control_get_from_file(const struct file *file)
{
	struct ns_common *ns;

	if (!file || !proc_ns_file(file))
		return ERR_PTR(-EINVAL);
	ns = get_proc_ns(file_inode(file));
	if (!ns || ns->ops != &selinuxns_operations)
		return ERR_PTR(-EINVAL);
	return selinux_ns_control_get(selinux_ns_from_common(ns));
}

/**
 * selinux_ns_control_authorize_parent - Authorize the constructing parent
 * @control: dormant or active target SELinux namespace
 * @cred: credentials selecting or constructing the target
 *
 * Require @cred to belong to the target's direct parent, hold CAP_SYS_ADMIN
 * in the target label domain's owner user namespace, and have the SELinux
 * unshare_selinuxns permission in its parent policy chain. All checks use
 * @cred rather than ambient current credentials.
 *
 * Return: 0 if the parent is authorized, or a negative error code.
 */
int selinux_ns_control_authorize_parent(
	struct selinux_ns_control *control, const struct cred *cred)
{
	const struct cred_security_struct *credsec;
	int rc;

	if (!control || !cred)
		return -EINVAL;
	credsec = selinux_cred(cred);
	if (!selinux_ns_control_parent(control, credsec->state))
		return -EPERM;
	rc = security_capable(cred, control->state->label_domain->owner_userns,
			      CAP_SYS_ADMIN, CAP_OPT_NONE);
	if (rc)
		return rc;
	return cred_self_has_perm(cred, SECCLASS_PROCESS2,
				  PROCESS2__UNSHARE_SELINUXNS, NULL);
}

/**
 * selinux_ns_control_authorize_direct_child - Authorize direct selection
 * @control: active target SELinux namespace
 * @cred: credentials selecting the target
 *
 * Require @cred to belong to the target's direct parent, hold CAP_SYS_ADMIN
 * in the target label domain's owner user namespace, and have the SELinux
 * unshare_selinuxns permission.  All checks use @cred rather than ambient
 * current credentials.
 *
 * Return: 0 if selection is authorized, or a negative error code.
 */
int selinux_ns_control_authorize_direct_child(
	struct selinux_ns_control *control, const struct cred *cred)
{
	const struct cred_security_struct *credsec;
	u32 target_sid;
	int rc;

	rc = selinux_ns_control_authorize_parent(control, cred);
	if (rc)
		return rc;
	if (!selinux_state_active(control->state))
		return -EAGAIN;
	credsec = selinux_cred(cred);

	/* The selected child independently authorizes the parent actor. */
	mutex_lock(&credsec->state->policy_mutex);
	mutex_lock_nested(&control->state->policy_mutex, SINGLE_DEPTH_NESTING);
	rc = selinux_ns_control_resolve_join(
		control, credsec->state, credsec->sid, &target_sid);
	if (!rc)
		rc = avc_has_perm(control->state, target_sid, target_sid,
				  SECCLASS_PROCESS2,
				  PROCESS2__UNSHARE_SELINUXNS, NULL);
	mutex_unlock(&control->state->policy_mutex);
	mutex_unlock(&credsec->state->policy_mutex);
	return rc;
}

bool selinux_ns_control_parent(const struct selinux_ns_control *control,
			       const struct selinux_state *actor)
{
	return control && actor && control->state->parent == actor;
}

int selinux_ns_control_add_map(struct selinux_ns_control *control,
			       const struct selinux_state *actor,
			       enum selinux_label_map_direction direction,
			       const char *source_context, u32 source_len,
			       const char *target_context, u32 target_len)
{
	struct {
		__le32 direction;
		__le32 source_len;
		__le32 target_len;
	} transcript;
	struct selinux_global_sid_handle *source_handle = NULL;
	struct selinux_global_sid_handle *target_handle = NULL;
	struct selinux_state *source_state, *target_state;
	u32 source_sid, target_sid;
	int rc;

	if (!selinux_ns_control_parent(control, actor))
		return -EPERM;
	if (direction >= SELINUX_LABEL_MAP_DIRECTIONS || !source_context ||
	    !target_context || !source_len || !target_len)
		return -EINVAL;

	mutex_lock(&control->lock);
	if (selinux_state_active(control->state)) {
		rc = -EBUSY;
	} else if (!selinux_initialized(control->state)) {
		rc = -EAGAIN;
	} else {
		if (direction == SELINUX_LABEL_MAP_PARENT_TO_CHILD) {
			source_state = control->state->parent;
			target_state = control->state;
		} else {
			source_state = control->state;
			target_state = control->state->parent;
		}
		/* Policy identities and the map epoch form one transaction. */
		mutex_lock(&control->state->parent->policy_mutex);
		mutex_lock_nested(&control->state->policy_mutex,
				  SINGLE_DEPTH_NESTING);
		if (control->parent_chain_epoch &&
		    (control->parent_chain_epoch !=
			     selinux_chain_epoch_read(actor) ||
		     control->child_chain_epoch !=
			     selinux_chain_epoch_read(control->state)))
			rc = -ESTALE;
		else {
			source_handle = security_context_to_global_handle(
				source_state, source_context, source_len,
				&source_sid, GFP_KERNEL);
			if (IS_ERR(source_handle)) {
				rc = PTR_ERR(source_handle);
				source_handle = NULL;
			}
		}
		if (!rc) {
			target_handle = security_context_to_global_handle(
				target_state, target_context, target_len,
				&target_sid, GFP_KERNEL);
			if (IS_ERR(target_handle)) {
				rc = PTR_ERR(target_handle);
				target_handle = NULL;
			}
		}
		if (!rc)
			rc = selinux_label_map_add(control->map, direction,
						   source_handle,
						   target_handle);
		if (!rc) {
			transcript.direction = cpu_to_le32(direction);
			transcript.source_len = cpu_to_le32(source_len);
			transcript.target_len = cpu_to_le32(target_len);
			sha256_update(&control->map_digest_ctx,
				      (const u8 *)&transcript,
				      sizeof(transcript));
			sha256_update(&control->map_digest_ctx, source_context,
				      source_len);
			sha256_update(&control->map_digest_ctx, target_context,
				      target_len);
			control->map_entries[direction]++;
		}
		if (!rc && !control->parent_chain_epoch) {
			control->parent_chain_epoch =
				selinux_chain_epoch_read(actor);
			control->child_chain_epoch =
				selinux_chain_epoch_read(control->state);
		}
		global_sid_handle_put(target_handle);
		global_sid_handle_put(source_handle);
		mutex_unlock(&control->state->policy_mutex);
		mutex_unlock(&control->state->parent->policy_mutex);
	}
	mutex_unlock(&control->lock);
	return rc;
}

static int selinux_ns_control_activate_locked(
	struct selinux_ns_control *control, const struct selinux_state *actor)
{
	struct selinux_label_map *published;
	int rc;

	lockdep_assert_held(&control->lock);
	lockdep_assert_held(&control->state->parent->policy_mutex);
	lockdep_assert_held(&control->state->policy_mutex);
	if (selinux_state_active(control->state)) {
		rc = -EALREADY;
		goto done;
	}
	if (!selinux_initialized(control->state)) {
		rc = -EAGAIN;
		goto done;
	}
	if (!control->parent_chain_epoch ||
	    control->parent_chain_epoch != selinux_chain_epoch_read(actor) ||
	    control->child_chain_epoch !=
		selinux_chain_epoch_read(control->state)) {
		rc = -ESTALE;
		goto done;
	}
	if (!selinux_label_map_complete(control->map)) {
		rc = -ENODATA;
		goto done;
	}

	rc = selinux_label_map_seal(control->map, actor->label_domain);
	if (rc && rc != -EALREADY)
		goto done;

	rc = selinux_label_domain_publish_map(control->state->label_domain,
					      control->map,
					      actor->label_domain);
	if (rc == -EALREADY) {
		published = selinux_label_domain_get_map(control->state->label_domain);
		if (published == control->map)
			rc = 0;
		selinux_label_map_put(published);
	}
	if (!rc) {
		struct sha256_ctx digest = control->map_digest_ctx;

		sha256_final(&digest, control->map_digest);
		control->map_digest_valid = true;
		selinux_chain_epoch_bump(control->state);
		control->child_chain_epoch =
			selinux_chain_epoch_read(control->state);
		__ns_tree_add_raw(&control->ns, &selinux_ns_tree);
		control->tree_published = true;
		__ns_ref_active_get(&control->ns);
		selinux_state_mark_active(control->state);
	}
done:
	return rc;
}

int selinux_ns_control_activate(struct selinux_ns_control *control,
				const struct selinux_state *actor)
{
	int rc;

	if (!selinux_ns_control_parent(control, actor))
		return -EPERM;
	mutex_lock(&control->lock);
	mutex_lock(&control->state->parent->policy_mutex);
	mutex_lock_nested(&control->state->policy_mutex, SINGLE_DEPTH_NESTING);
	rc = selinux_ns_control_activate_locked(control, actor);
	mutex_unlock(&control->state->policy_mutex);
	mutex_unlock(&control->state->parent->policy_mutex);
	mutex_unlock(&control->lock);
	return rc;
}

int selinux_ns_control_activate_restore(
	struct selinux_ns_control *control, const struct selinux_state *actor,
	u64 expected_id, u64 expected_parent_id, u64 expected_map_generation,
	u32 expected_policy_seqno, const u8 policy_digest[SHA256_DIGEST_SIZE],
	const u8 map_digest[SHA256_DIGEST_SIZE])
{
	struct selinux_policy_snapshot snapshot;
	struct sha256_ctx digest_ctx;
	u8 digest[SHA256_DIGEST_SIZE];
	int rc;

	if (!selinux_ns_control_parent(control, actor))
		return -EPERM;
	mutex_lock(&control->lock);
	mutex_lock(&control->state->parent->policy_mutex);
	mutex_lock_nested(&control->state->policy_mutex, SINGLE_DEPTH_NESTING);
	if (selinux_state_active(control->state)) {
		rc = -EALREADY;
		goto out;
	}
	rc = selinux_policy_snapshot_read(control->state, &snapshot);
	if (rc)
		goto out;
	digest_ctx = control->map_digest_ctx;
	sha256_final(&digest_ctx, digest);
	if (control->ns.ns_id != expected_id ||
	    control->state->parent->ns_control->ns.ns_id != expected_parent_id ||
	    expected_map_generation != 1 ||
	    snapshot.seqno != expected_policy_seqno ||
	    memcmp(snapshot.effective_digest, policy_digest,
		   SHA256_DIGEST_SIZE) ||
	    memcmp(digest, map_digest, SHA256_DIGEST_SIZE))
		rc = -ESTALE;
	if (!rc)
		rc = selinux_ns_control_activate_locked(control, actor);
out:
	mutex_unlock(&control->state->policy_mutex);
	mutex_unlock(&control->state->parent->policy_mutex);
	mutex_unlock(&control->lock);
	return rc;
}

int selinux_ns_control_resolve_join(struct selinux_ns_control *control,
				    const struct selinux_state *actor,
				    u32 actor_sid, u32 *target_sid)
{
	struct selinux_label_ref *source, *target = NULL;
	int rc;

	if (!target_sid)
		return -EINVAL;
	if (!selinux_ns_control_parent(control, actor))
		return -EPERM;
	if (!selinux_state_active(control->state))
		return -EAGAIN;
	lockdep_assert_held(&actor->policy_mutex);
	lockdep_assert_held(&control->state->policy_mutex);

	source = global_sid_to_label_ref(actor_sid);
	if (IS_ERR(source))
		return PTR_ERR(source);
	rc = selinux_label_map_resolve(control->map,
				       SELINUX_LABEL_MAP_PARENT_TO_CHILD,
				       source, actor_sid, target_sid, &target);
	/*
	 * The sealed map entry owns target_handle for the map lifetime, and an
	 * installed credential retains the target state and its published map.
	 * Keep that global identity across reload; per-policy SID resolution is
	 * generation-aware and must not mint an unowned replacement here.
	 */
	selinux_label_ref_put(target);
	selinux_label_ref_put(source);
	return rc;
}

struct selinux_state *
selinux_ns_control_state_get(struct selinux_ns_control *control)
{
	return control ? get_selinux_state(control->state) : NULL;
}

static struct ns_common *selinuxns_get(struct task_struct *task)
{
	const struct cred *cred;
	struct selinux_state *state;

	cred = get_task_cred(task);
	state = selinux_cred(cred)->state;
	selinux_ns_control_get(state->ns_control);
	put_cred(cred);
	return &state->ns_control->ns;
}

static void selinuxns_put(struct ns_common *ns)
{
	selinux_ns_control_put(selinux_ns_from_common(ns));
}

static bool selinuxns_get_lifetime(struct ns_common *ns)
{
	struct selinux_ns_control *control = selinux_ns_from_common(ns);

	return refcount_inc_not_zero(&control->state->count);
}

static bool selinuxns_is_current(struct ns_common *ns)
{
	return current_selinux_state->ns_control == selinux_ns_from_common(ns);
}

static int selinuxns_install(struct nsset *nsset, struct ns_common *ns)
{
	struct selinux_ns_control *control = selinux_ns_from_common(ns);
	struct cred *prepared = nsset_cred(nsset) ?: nsset->security_cred;
	bool installed = prepared;
	int rc;

	if (prepared)
		rc = selinux_ns_control_apply_join(
			control, current_cred(), prepared);
	else
		rc = selinux_ns_control_prepare_join(control, &prepared);
	if (rc)
		return rc;
#if defined(CONFIG_SYSVIPC) || defined(CONFIG_POSIX_MQUEUE)
	if (nsset->nsproxy->ipc_ns != &init_ipc_ns) {
		/* Anchor the final IPC target to the final prepared credential. */
		security_ipc_namespace_reanchor_abort(
			&nsset->ipc_security_txn);
		rc = security_ipc_namespace_reanchor_prepare(
			&nsset->ipc_security_txn, nsset->nsproxy->ipc_ns,
			prepared, NULL, NULL);
		if (rc) {
			if (!installed)
				abort_creds(prepared);
			return rc;
		}
	}
#endif /* CONFIG_SYSVIPC || CONFIG_POSIX_MQUEUE */
	if (installed)
		return 0;
	rc = nsset_install_security_cred(nsset, prepared);
	if (rc) {
		security_ipc_namespace_reanchor_abort(
			&nsset->ipc_security_txn);
		abort_creds(prepared);
	}
	return rc;
}

static struct user_namespace *selinuxns_owner(struct ns_common *ns)
{
	return selinux_ns_from_common(ns)->state->label_domain->owner_userns;
}

static struct ns_common *selinuxns_get_parent(struct ns_common *ns)
{
	struct selinux_state *parent = selinux_ns_from_common(ns)->state->parent;

	if (!parent)
		return ERR_PTR(-EPERM);
	selinux_ns_control_get(parent->ns_control);
	return &parent->ns_control->ns;
}

static long selinuxns_ioctl(struct ns_common *ns, unsigned int cmd,
			    unsigned long arg)
{
	return selinux_ns_control_ioctl(selinux_ns_from_common(ns), cmd, arg);
}

const struct proc_ns_operations selinuxns_operations = {
	.name = "selinux",
	.get_lifetime = selinuxns_get_lifetime,
	.is_current = selinuxns_is_current,
	.get = selinuxns_get,
	.put = selinuxns_put,
	.install = selinuxns_install,
	.owner = selinuxns_owner,
	.get_parent = selinuxns_get_parent,
	.ioctl = selinuxns_ioctl,
};
