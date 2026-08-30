// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/audit.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/kconfig.h>
#include <linux/nsfs.h>
#include <linux/proc_ns.h>
#include <linux/user_namespace.h>

#include "global_sidtab.h"
#include "label.h"
#include "label_map.h"
#include "label_view.h"
#include "namespace.h"
#include "objsec.h"
#include "pathless.h"
#include "resource.h"
#include "security.h"
#include "ss/services.h"
#include "avc.h"

static void selinux_test_ns_control_put(void *data)
{
	selinux_ns_control_put(data);
}

static struct selinux_ns_control *
selinux_test_ns_control_alloc_cred(struct kunit *test, const struct cred *cred)
{
	struct selinux_ns_control *control;
	int rc;

	control = selinux_ns_control_alloc(cred);
	if (IS_ERR(control)) {
		KUNIT_FAIL(test, "control allocation failed: %ld",
			   PTR_ERR(control));
		return NULL;
	}
	rc = kunit_add_action_or_reset(test, selinux_test_ns_control_put,
				       control);
	if (rc) {
		KUNIT_FAIL(test, "control cleanup registration failed: %d", rc);
		return NULL;
	}
	return control;
}

static struct selinux_ns_control *
selinux_test_ns_control_alloc(struct kunit *test)
{
	return selinux_test_ns_control_alloc_cred(test, current_cred());
}

static void selinux_test_abort_creds(void *data)
{
	abort_creds(data);
}

static void selinux_test_fput(void *data)
{
	fput(data);
}

static struct cred *
selinux_test_cred_for_state(struct kunit *test, struct selinux_state *state)
{
	struct cred_security_struct *credsec;
	struct selinux_state *old;
	struct cred *cred;
	int rc;

	cred = prepare_creds();
	if (!cred) {
		KUNIT_FAIL(test, "credential allocation failed");
		return NULL;
	}
	rc = kunit_add_action_or_reset(test, selinux_test_abort_creds, cred);
	if (rc) {
		KUNIT_FAIL(test, "credential cleanup registration failed: %d", rc);
		return NULL;
	}
	credsec = selinux_cred(cred);
	old = credsec->state;
	credsec->state = get_selinux_state(state);
	put_selinux_state(old);
	return cred;
}

static struct selinux_global_sid_handle *
selinux_test_ns_handle(struct kunit *test, struct selinux_label_domain *domain,
		       const char *context, u32 *sid)
{
	struct selinux_state state = {
		.label_domain = domain,
	};
	struct selinux_global_sid_handle *handle;

	handle = global_context_to_handle(&state, context, strlen(context) + 1,
					  0, sid, GFP_KERNEL);
	if (IS_ERR(handle)) {
		KUNIT_FAIL(test, "handle allocation failed: %ld",
			   PTR_ERR(handle));
		return NULL;
	}
	return handle;
}

static int selinux_test_ns_control_activate(struct kunit *test,
					    struct selinux_ns_control *control)
{
	struct selinux_state *parent = control->state->parent;
	struct selinux_global_sid_handle *parent_handle, *child_handle;
	u32 parent_sid, child_sid;
	int rc;

	parent_handle = selinux_test_ns_handle(
		test, parent->label_domain, "u:r:test_parent_t:s0", &parent_sid);
	if (!parent_handle)
		return -ENOMEM;
	child_handle = selinux_test_ns_handle(
		test, control->state->label_domain, "u:r:test_child_t:s0",
		&child_sid);
	if (!child_handle) {
		rc = -ENOMEM;
		goto out_parent;
	}
	rc = selinux_label_map_add(
		control->map, SELINUX_LABEL_MAP_PARENT_TO_CHILD,
		parent_handle, child_handle);
	if (rc)
		goto out_handles;
	rc = selinux_label_map_add(
		control->map, SELINUX_LABEL_MAP_CHILD_TO_PARENT,
		child_handle, parent_handle);
	if (rc)
		goto out_handles;
	control->map_entries[SELINUX_LABEL_MAP_PARENT_TO_CHILD] = 1;
	control->map_entries[SELINUX_LABEL_MAP_CHILD_TO_PARENT] = 1;
	selinux_mark_initialized(control->state);
	control->parent_chain_epoch = selinux_chain_epoch_read(parent);
	control->child_chain_epoch = selinux_chain_epoch_read(control->state);
	rc = selinux_ns_control_activate(control, parent);

out_handles:
	global_sid_handle_put(child_handle);
out_parent:
	global_sid_handle_put(parent_handle);
	return rc;
}

static void selinux_ns_control_activation_test(struct kunit *test)
{
	struct selinux_state *parent = current_selinux_state;
	struct selinux_ns_control *control;
	struct selinux_label_map *published;
	struct selinux_global_sid_handle *parent_handle, *child_handle;
	enum selinux_label_map_direction direction;
	u32 parent_sid, child_sid;
	bool parent_matches;
	int rc;

	control = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, control);
	KUNIT_EXPECT_FALSE(test, selinux_state_active(control->state));
	KUNIT_EXPECT_TRUE(test, selinux_ns_control_parent(control, parent));
	parent_matches = selinux_ns_control_parent(control, control->state);
	KUNIT_EXPECT_FALSE(test, parent_matches);
	published = selinux_label_domain_get_map(control->state->label_domain);
	KUNIT_EXPECT_PTR_EQ(test, published, NULL);
	selinux_label_map_put(published);

	parent_handle = selinux_test_ns_handle(
		test, parent->label_domain, "u:r:parent_t:s0", &parent_sid);
	KUNIT_ASSERT_NOT_NULL(test, parent_handle);
	child_handle = selinux_test_ns_handle(
		test, control->state->label_domain, "u:r:child_t:s0",
		&child_sid);
	if (!child_handle) {
		global_sid_handle_put(parent_handle);
		return;
	}
	direction = SELINUX_LABEL_MAP_PARENT_TO_CHILD;
	rc = selinux_label_map_add(control->map, direction, parent_handle,
				   child_handle);
	KUNIT_ASSERT_EQ(test, rc, 0);
	direction = SELINUX_LABEL_MAP_CHILD_TO_PARENT;
	rc = selinux_label_map_add(control->map, direction, child_handle,
				   parent_handle);
	KUNIT_ASSERT_EQ(test, rc, 0);
	control->map_entries[SELINUX_LABEL_MAP_PARENT_TO_CHILD] = 1;
	control->map_entries[SELINUX_LABEL_MAP_CHILD_TO_PARENT] = 1;
	global_sid_handle_put(child_handle);
	global_sid_handle_put(parent_handle);

	selinux_mark_initialized(control->state);
	control->parent_chain_epoch = selinux_chain_epoch_read(parent);
	control->child_chain_epoch = selinux_chain_epoch_read(control->state);
	rc = selinux_ns_control_activate(control, parent);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_TRUE(test, selinux_state_active(control->state));
	published = selinux_label_domain_get_map(control->state->label_domain);
	KUNIT_EXPECT_PTR_EQ(test, published, control->map);
	selinux_label_map_put(published);

	rc = selinux_ns_control_add_map(control, parent,
					SELINUX_LABEL_MAP_PARENT_TO_CHILD,
					"parent", 6, "child", 5);
	KUNIT_EXPECT_EQ(test, rc, -EBUSY);
	KUNIT_EXPECT_EQ(test, selinux_ns_control_activate(control, parent),
			-EALREADY);
}

static void selinux_ns_control_no_partial_publish_test(struct kunit *test)
{
	struct selinux_ns_control *control;
	struct selinux_label_map *published;
	int rc;

	control = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, control);
	selinux_mark_initialized(control->state);
	rc = selinux_ns_control_activate(control, current_selinux_state);
	KUNIT_EXPECT_EQ(test, rc, -ESTALE);
	KUNIT_EXPECT_FALSE(test, selinux_state_active(control->state));
	published = selinux_label_domain_get_map(control->state->label_domain);
	KUNIT_EXPECT_PTR_EQ(test, published, NULL);
	selinux_label_map_put(published);
}

static void selinux_ns_control_requires_bidirectional_map_test(struct kunit *test)
{
	struct selinux_state *parent = current_selinux_state;
	struct selinux_ns_control *control;
	struct selinux_label_map *published;
	struct selinux_global_sid_handle *parent_handle, *child_handle;
	enum selinux_label_map_direction direction;
	u32 parent_sid, child_sid;
	int rc;

	control = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, control);
	parent_handle = selinux_test_ns_handle(
		test, parent->label_domain, "u:r:parent_one_way_t:s0",
		&parent_sid);
	KUNIT_ASSERT_NOT_NULL(test, parent_handle);
	child_handle = selinux_test_ns_handle(
		test, control->state->label_domain, "u:r:child_one_way_t:s0",
		&child_sid);
	if (!child_handle) {
		global_sid_handle_put(parent_handle);
		return;
	}
	direction = SELINUX_LABEL_MAP_PARENT_TO_CHILD;
	rc = selinux_label_map_add(control->map, direction, parent_handle,
				   child_handle);
	control->map_entries[SELINUX_LABEL_MAP_PARENT_TO_CHILD] = 1;
	global_sid_handle_put(child_handle);
	global_sid_handle_put(parent_handle);
	KUNIT_ASSERT_EQ(test, rc, 0);

	selinux_mark_initialized(control->state);
	control->parent_chain_epoch = selinux_chain_epoch_read(parent);
	control->child_chain_epoch = selinux_chain_epoch_read(control->state);
	KUNIT_EXPECT_EQ(test, selinux_ns_control_activate(control, parent),
			-ENODATA);
	KUNIT_EXPECT_FALSE(test, selinux_state_active(control->state));
	published = selinux_label_domain_get_map(control->state->label_domain);
	KUNIT_EXPECT_PTR_EQ(test, published, NULL);
	selinux_label_map_put(published);
}

static void selinux_ns_nsfs_type_zero_handle_test(struct kunit *test)
{
	struct selinux_ns_control *other;

	/* Current nsfs handle: SELinux deliberately uses namespace type zero. */
	KUNIT_EXPECT_TRUE(test, nsfs_kunit_handle_fields_valid(42, 314, 0));
	/* Legacy id-only handles remain valid. */
	KUNIT_EXPECT_TRUE(test, nsfs_kunit_handle_fields_valid(42, 0, 0));
	/* Existing typed namespaces still require an inode number. */
	KUNIT_EXPECT_FALSE(test,
			   nsfs_kunit_handle_fields_valid(42, 0,
						  CLONE_NEWUSER));
	KUNIT_EXPECT_FALSE(test, nsfs_kunit_handle_fields_valid(0, 314, 0));
	KUNIT_EXPECT_TRUE(test, selinuxns_operations.is_current(
		&current_selinux_state->ns_control->ns));
	other = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, other);
	KUNIT_EXPECT_FALSE(test, selinuxns_operations.is_current(&other->ns));
}

static void selinux_ns_direct_child_dormant_rejected_test(struct kunit *test)
{
	struct selinux_ns_control *control;
	int parent_rc, child_rc;

	control = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, control);
	KUNIT_ASSERT_FALSE(test, selinux_state_active(control->state));
	parent_rc = selinux_ns_control_authorize_parent(control,
							current_cred());
	child_rc = selinux_ns_control_authorize_direct_child(control,
							     current_cred());
	if (parent_rc)
		KUNIT_EXPECT_EQ(test, child_rc, parent_rc);
	else
		KUNIT_EXPECT_EQ(test, child_rc, -EAGAIN);
}

static void selinux_ns_direct_child_relationship_test(struct kunit *test)
{
	struct selinux_ns_control *target, *sibling, *grandchild;
	struct cred *self_cred, *sibling_cred, *grandchild_cred;
	int rc;

	target = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, target);
	rc = selinux_test_ns_control_activate(test, target);
	KUNIT_ASSERT_EQ(test, rc, 0);

	sibling = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, sibling);
	rc = selinux_test_ns_control_activate(test, sibling);
	KUNIT_ASSERT_EQ(test, rc, 0);
	sibling_cred = selinux_test_cred_for_state(test, sibling->state);
	KUNIT_ASSERT_NOT_NULL(test, sibling_cred);
	KUNIT_EXPECT_EQ(test,
		selinux_ns_control_authorize_direct_child(target, sibling_cred),
		-EPERM);

	self_cred = selinux_test_cred_for_state(test, target->state);
	KUNIT_ASSERT_NOT_NULL(test, self_cred);
	KUNIT_EXPECT_EQ(test,
		selinux_ns_control_authorize_direct_child(target, self_cred),
		-EPERM);

	grandchild = selinux_test_ns_control_alloc_cred(test, self_cred);
	KUNIT_ASSERT_NOT_NULL(test, grandchild);
	rc = selinux_test_ns_control_activate(test, grandchild);
	KUNIT_ASSERT_EQ(test, rc, 0);
	grandchild_cred = selinux_test_cred_for_state(test, grandchild->state);
	KUNIT_ASSERT_NOT_NULL(test, grandchild_cred);
	KUNIT_EXPECT_EQ(test,
		selinux_ns_control_authorize_direct_child(target,
						  grandchild_cred),
		-EPERM);

	/*
	 * The direct-parent success path deliberately reaches the live
	 * capability and AVC policy.  This suite has no policy-loading or static
	 * stub seam for those checks, so its allow/deny result is host-policy
	 * dependent and is not asserted here.
	 */
}

static void selinux_ns_control_from_file_ref_test(struct kunit *test)
{
	struct selinux_ns_control *control, *acquired;
	struct file *nsfile;
	int ns_refs, state_refs;
	int rc;

	control = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, control);
	KUNIT_ASSERT_FALSE(test, selinux_state_active(control->state));

	/* open_namespace_file() consumes this complete control reference. */
	selinux_ns_control_get(control);
	nsfile = open_namespace_file(&control->ns);
	KUNIT_ASSERT_FALSE(test, IS_ERR(nsfile));
	rc = kunit_add_action_or_reset(test, selinux_test_fput, nsfile);
	KUNIT_ASSERT_EQ(test, rc, 0);

	ns_refs = __ns_ref_read(&control->ns);
	state_refs = refcount_read(&control->state->count);
	acquired = selinux_ns_control_get_from_file(nsfile);
	KUNIT_ASSERT_FALSE(test, IS_ERR(acquired));
	KUNIT_EXPECT_PTR_EQ(test, acquired, control);
	KUNIT_EXPECT_EQ(test, __ns_ref_read(&control->ns), ns_refs + 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&control->state->count),
			state_refs + 1);
	selinux_ns_control_put(acquired);
	KUNIT_EXPECT_EQ(test, __ns_ref_read(&control->ns), ns_refs);
	KUNIT_EXPECT_EQ(test, refcount_read(&control->state->count), state_refs);
}

static void selinux_ns_control_nsfs_security_unwind_test(struct kunit *test)
{
	struct selinux_ns_control *control, *other;
	struct file *nsfile;
	int ns_refs, state_refs;

	control = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, control);
	ns_refs = __ns_ref_read(&control->ns);
	state_refs = refcount_read(&control->state->count);

	/* A different nsfs materialization must not consume this scoped fault. */
	other = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, other);
	nsfs_kunit_fail_security_init_once(&control->ns, -ENOMEM);
	selinux_ns_control_get(other);
	nsfile = open_namespace_file(&other->ns);
	if (IS_ERR(nsfile)) {
		nsfs_kunit_fail_security_init_once(NULL, 0);
		KUNIT_FAIL(test, "unrelated nsfs open failed: %ld",
			   PTR_ERR(nsfile));
		return;
	}
	fput(nsfile);

	/* open_namespace_file() consumes the complete reference on failure too. */
	selinux_ns_control_get(control);
	nsfile = open_namespace_file(&control->ns);
	if (!IS_ERR(nsfile)) {
		fput(nsfile);
		KUNIT_FAIL(test, "targeted nsfs open unexpectedly succeeded");
		return;
	}
	KUNIT_EXPECT_EQ(test, PTR_ERR(nsfile), -ENOMEM);
	KUNIT_EXPECT_EQ(test, __ns_ref_read(&control->ns), ns_refs);
	KUNIT_EXPECT_EQ(test, refcount_read(&control->state->count), state_refs);
}

static void selinux_ns_generic_nsfs_projection_test(struct kunit *test)
{
	struct selinux_pathless_projection *projection, *reopened_projection;
	struct cred *cred;
	struct user_namespace *user_ns;
	struct file *nsfile, *reopened;
	int rc;

	/* A new userns is controlled here and has no previously stashed dentry. */
	cred = prepare_creds();
	KUNIT_ASSERT_NOT_NULL(test, cred);
	rc = kunit_add_action_or_reset(test, selinux_test_abort_creds, cred);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = create_user_ns(cred);
	KUNIT_ASSERT_EQ(test, rc, 0);
	/* userns_operations is intentionally unrelated to selinuxns_operations. */
	user_ns = get_user_ns(cred->user_ns);
	nsfile = open_namespace_file(&user_ns->ns);
	KUNIT_ASSERT_FALSE(test, IS_ERR(nsfile));
	rc = kunit_add_action_or_reset(test, selinux_test_fput, nsfile);
	KUNIT_ASSERT_EQ(test, rc, 0);
	projection = selinux_file(nsfile)->pathless;
	KUNIT_ASSERT_NOT_NULL(test, projection);
	KUNIT_EXPECT_EQ(test, projection->kind,
			SELINUX_PATHLESS_KIND_NSFS);
	KUNIT_EXPECT_EQ(test, projection->source,
			SELINUX_LABEL_SOURCE_KERNEL_INITIAL);
	KUNIT_EXPECT_EQ(test, projection->seal_count, (u16)1);
	KUNIT_EXPECT_PTR_EQ(test, projection->view,
			 selinux_file(nsfile)->view);

	/* Reopening the stashed dentry must not rematerialize its nsfs inode. */
	user_ns = get_user_ns(cred->user_ns);
	reopened = open_namespace_file(&user_ns->ns);
	KUNIT_ASSERT_FALSE(test, IS_ERR(reopened));
	rc = kunit_add_action_or_reset(test, selinux_test_fput, reopened);
	KUNIT_ASSERT_EQ(test, rc, 0);
	reopened_projection = selinux_file(reopened)->pathless;
	KUNIT_ASSERT_NOT_NULL(test, reopened_projection);
	KUNIT_EXPECT_PTR_EQ(test, file_inode(reopened), file_inode(nsfile));
	KUNIT_EXPECT_PTR_EQ(test, reopened_projection, projection);
}

static void selinux_ns_restore_mismatch_is_not_published_test(struct kunit *test)
{
	struct selinux_ns_control *control;
	struct selinux_policy_snapshot snapshot;
	struct sha256_ctx digest_ctx;
	u8 map_digest[SHA256_DIGEST_SIZE];
	int rc;

	control = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, control);
	selinux_mark_initialized(control->state);
	control->parent_chain_epoch =
		selinux_chain_epoch_read(current_selinux_state);
	control->child_chain_epoch = selinux_chain_epoch_read(control->state);
	mutex_lock(&control->lock);
	digest_ctx = control->map_digest_ctx;
	sha256_final(&digest_ctx, map_digest);
	mutex_unlock(&control->lock);
	rc = selinux_policy_snapshot_read(control->state, &snapshot);
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = selinux_ns_control_activate_restore(
		control, current_selinux_state, control->ns.ns_id + 1,
		current_selinux_state->ns_control->ns.ns_id, 1, snapshot.seqno,
		snapshot.effective_digest, map_digest);
	KUNIT_EXPECT_EQ(test, rc, -ESTALE);
	KUNIT_EXPECT_FALSE(test, selinux_state_active(control->state));
	KUNIT_EXPECT_FALSE(test, smp_load_acquire(&control->map->sealed));
	KUNIT_EXPECT_FALSE(test, control->tree_published);
}

static void selinux_policy_effective_digest_generation_test(struct kunit *test)
{
	struct cond_bool_datum boolean = {};
	struct cond_bool_datum *boolean_index[] = { &boolean };
	struct selinux_policy policy = {
		.policydb = {
			.bool_val_to_struct = boolean_index,
		},
	};
	u8 initial[SHA256_DIGEST_SIZE];
	u8 boolean_changed[SHA256_DIGEST_SIZE];

	policy.policydb.p_bools.nprim = 1;
	memset(policy.binary_digest, 0x5a, sizeof(policy.binary_digest));
	selinux_kunit_policy_effective_digest(&policy);
	memcpy(initial, policy.effective_digest, sizeof(initial));
	boolean.state = 1;
	selinux_kunit_policy_effective_digest(&policy);
	memcpy(boolean_changed, policy.effective_digest,
	       sizeof(boolean_changed));
	KUNIT_EXPECT_MEMNEQ(test, initial, boolean_changed, sizeof(initial));

	policy.binary_digest[0] ^= 0xff;
	selinux_kunit_policy_effective_digest(&policy);
	KUNIT_EXPECT_MEMNEQ(test, boolean_changed, policy.effective_digest,
			   sizeof(boolean_changed));
}

static void selinux_policy_snapshot_digest_generation_test(struct kunit *test)
{
	struct selinux_policy_snapshot snapshot;
	const struct selinux_policy *policy;
	u32 seqno;
	u8 digest[SHA256_DIGEST_SIZE];
	bool same_policy;
	int rc;

	rc = selinux_policy_snapshot_read(current_selinux_state, &snapshot);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rcu_read_lock();
	policy = rcu_dereference(current_selinux_state->policy);
	same_policy = policy == snapshot.policy_cookie;
	seqno = policy ? policy->latest_granting : 0;
	if (policy)
		memcpy(digest, policy->effective_digest, sizeof(digest));
	else
		memset(digest, 0, sizeof(digest));
	rcu_read_unlock();
	KUNIT_ASSERT_TRUE(test, same_policy);
	KUNIT_EXPECT_EQ(test, seqno, snapshot.seqno);
	KUNIT_EXPECT_MEMEQ(test, digest, snapshot.effective_digest,
			  sizeof(digest));
}

static void selinux_ns_restore_id_reservation_test(struct kunit *test)
{
	struct selinux_ns_control *base, *restored, *next;
	struct selinux_ns_control *stale;
	u64 gap_id;

	base = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, base);
	gap_id = base->ns.ns_id + 100;
	restored = selinux_ns_control_alloc_unassigned(current_cred());
	KUNIT_ASSERT_FALSE(test, IS_ERR(restored));
	KUNIT_ASSERT_EQ(test, selinux_ns_control_reserve_id(restored, gap_id), 0);
	KUNIT_EXPECT_EQ(test, restored->ns.ns_id, gap_id);
	selinux_ns_control_put(restored);

	/* Collision/out-of-order failure must not advance the high-water mark. */
	stale = selinux_ns_control_alloc_unassigned(current_cred());
	KUNIT_ASSERT_FALSE(test, IS_ERR(stale));
	KUNIT_EXPECT_EQ(test, stale->ns.ns_id, 0);
	KUNIT_EXPECT_FALSE(test, is_ns_init_id(&stale->ns));
	KUNIT_EXPECT_EQ(test, selinux_ns_control_reserve_id(stale, gap_id),
			-ESTALE);
	selinux_ns_control_put(stale);
	next = selinux_ns_control_alloc_unassigned(current_cred());
	KUNIT_ASSERT_FALSE(test, IS_ERR(next));
	KUNIT_ASSERT_EQ(test, selinux_ns_control_reserve_id(next, gap_id + 1), 0);
	KUNIT_EXPECT_EQ(test, next->ns.ns_id, gap_id + 1);
	selinux_ns_control_put(next);

	stale = selinux_ns_control_alloc_unassigned(current_cred());
	KUNIT_ASSERT_FALSE(test, IS_ERR(stale));
	KUNIT_EXPECT_EQ(test, selinux_ns_control_reserve_id(stale, 0), -EINVAL);
	KUNIT_EXPECT_EQ(test, selinux_ns_control_reserve_id(
		stale, (u64)S64_MAX + 1), -EINVAL);
	selinux_ns_control_put(stale);
	KUNIT_EXPECT_EQ(test, selinux_ns_restore_parent_validate(
		current_selinux_state,
		current_selinux_state->ns_control->ns.ns_id), 0);
	KUNIT_EXPECT_EQ(test, selinux_ns_restore_parent_validate(
		current_selinux_state,
		current_selinux_state->ns_control->ns.ns_id + 1), -ESTALE);
}

static void selinux_policy_resource_accounting_test(struct kunit *test)
{
	struct selinux_ns_control *control;
	struct selinux_policy old_policy = {};
	struct selinux_policy new_policy;
	struct selinux_resource_account *resources;
	u64 baseline, bytes_baseline;
	int rc;

	control = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, control);
	resources = control->state->label_domain->resources;
	baseline = selinux_kunit_resource_objects(resources,
						  SELINUX_RESOURCE_POLICY);
	bytes_baseline = selinux_kunit_resource_bytes(resources,
						      SELINUX_RESOURCE_POLICY);
	rc = selinux_kunit_policy_resource_reserve(control->state, &old_policy);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(resources, SELINUX_RESOURCE_POLICY),
		baseline + 1);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_bytes(resources, SELINUX_RESOURCE_POLICY),
		bytes_baseline + (u64)CONFIG_SECURITY_SELINUX_POLICY_MAX_BYTES);
	new_policy = old_policy;
	selinux_kunit_policy_resource_transfer(&old_policy, &new_policy);
	selinux_kunit_policy_resource_release(&old_policy);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(resources, SELINUX_RESOURCE_POLICY),
		baseline + 1);
	selinux_kunit_policy_resource_release(&new_policy);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(resources, SELINUX_RESOURCE_POLICY),
		baseline);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_bytes(resources, SELINUX_RESOURCE_POLICY),
		bytes_baseline);
}

static void selinux_namespace_resource_accounting_test(struct kunit *test)
{
	struct selinux_resource_account *resources;
	u64 bytes_before, global_before, objects_before, owner_before;
	const u64 charge = 768;
	int rc;

	resources = current_selinux_state->label_domain->resources;
	objects_before = selinux_kunit_resource_objects(
		resources, SELINUX_RESOURCE_NAMESPACE);
	bytes_before = selinux_kunit_resource_bytes(
		resources, SELINUX_RESOURCE_NAMESPACE);
	owner_before = selinux_kunit_namespace_owner_count(resources);
	global_before = selinux_kunit_namespace_global_count();

	rc = selinux_kunit_namespace_reserve(resources, charge,
					     owner_before + 1, S64_MAX);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, selinux_kunit_namespace_owner_count(resources),
			owner_before + 1);
	KUNIT_EXPECT_EQ(test, selinux_kunit_namespace_global_count(),
			global_before + 1);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_objects(
		resources, SELINUX_RESOURCE_NAMESPACE), objects_before + 1);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_bytes(
		resources, SELINUX_RESOURCE_NAMESPACE), bytes_before + charge);

	/* Owner exhaustion rolls back the transient global reservation. */
	rc = selinux_kunit_namespace_reserve(resources, charge,
					     owner_before + 1, S64_MAX);
	KUNIT_EXPECT_EQ(test, rc, -EDQUOT);
	KUNIT_EXPECT_EQ(test, selinux_kunit_namespace_global_count(),
			global_before + 1);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_objects(
		resources, SELINUX_RESOURCE_NAMESPACE), objects_before + 1);

	/* Global exhaustion does not touch the owner or aggregate counters. */
	rc = selinux_kunit_namespace_reserve(resources, charge, S64_MAX,
					     global_before + 1);
	KUNIT_EXPECT_EQ(test, rc, -EDQUOT);
	KUNIT_EXPECT_EQ(test, selinux_kunit_namespace_owner_count(resources),
			owner_before + 1);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_bytes(
		resources, SELINUX_RESOURCE_NAMESPACE), bytes_before + charge);

	selinux_namespace_release(resources, charge);
	KUNIT_EXPECT_EQ(test, selinux_kunit_namespace_owner_count(resources),
			owner_before);
	KUNIT_EXPECT_EQ(test, selinux_kunit_namespace_global_count(),
			global_before);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_objects(
		resources, SELINUX_RESOURCE_NAMESPACE), objects_before);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_bytes(
		resources, SELINUX_RESOURCE_NAMESPACE), bytes_before);
}

static void selinux_namespace_limit_validation_test(struct kunit *test)
{
	u32 maxns = READ_ONCE(selinux_maxns);
	u32 depth = READ_ONCE(selinux_maxnsdepth);

	KUNIT_EXPECT_EQ(test, selinux_state_set_maxns(maxns), 0);
	KUNIT_EXPECT_EQ(test, selinux_state_set_maxns(0), -EINVAL);
	KUNIT_EXPECT_EQ(test,
			selinux_state_set_maxns(SELINUX_MAX_NAMESPACES_LIMIT + 1),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, READ_ONCE(selinux_maxns), maxns);
	KUNIT_EXPECT_EQ(test, selinux_state_set_maxnsdepth(depth), 0);
	KUNIT_EXPECT_EQ(test, selinux_state_set_maxnsdepth(
		SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1), -EINVAL);
	KUNIT_EXPECT_EQ(test, READ_ONCE(selinux_maxnsdepth), depth);
}

static void selinux_audit_host_reserve_lifetime_test(struct kunit *test)
{
	struct selinux_ns_control *control;
	struct selinux_resource_account *resources;
	struct selinux_audit_reservation reservation = {};
	u64 baseline, bytes_baseline, host_before;
	int rc;

	control = selinux_test_ns_control_alloc(test);
	KUNIT_ASSERT_NOT_NULL(test, control);
	resources = control->state->label_domain->resources;
	baseline = selinux_kunit_resource_objects(resources,
						  SELINUX_RESOURCE_AUDIT);
	bytes_baseline = selinux_kunit_resource_bytes(resources,
						      SELINUX_RESOURCE_AUDIT);
	selinux_kunit_audit_buckets_reset();
	host_before = selinux_kunit_audit_host_tokens();
	rc = selinux_kunit_audit_reserve_channel(resources, false, 128,
						 &reservation);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, selinux_kunit_audit_host_tokens(), host_before);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(resources, SELINUX_RESOURCE_AUDIT),
		baseline + 1);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_bytes(resources, SELINUX_RESOURCE_AUDIT),
		bytes_baseline + 128 + SELINUX_AUDIT_RECORD_OVERHEAD);
	selinux_audit_release(&reservation);
	KUNIT_EXPECT_PTR_EQ(test, reservation.account, NULL);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(resources, SELINUX_RESOURCE_AUDIT),
		baseline);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_bytes(resources, SELINUX_RESOURCE_AUDIT),
		bytes_baseline);
}

static void selinux_audit_dontaudit_host_aggregate_test(struct kunit *test)
{
	u64 child_before, host_before;
	u64 namespace_id = 0;
	u16 count = 0;

	selinux_kunit_audit_buckets_reset();
	selinux_kunit_audit_child_tokens_set(0);
	child_before = selinux_kunit_audit_child_tokens();
	host_before = selinux_kunit_audit_host_tokens();
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_avc_host_aggregate(true, 0, &count, &namespace_id), 0);
	KUNIT_EXPECT_EQ(test, count, (u16)1);
	KUNIT_EXPECT_EQ(test, selinux_kunit_audit_child_tokens(), child_before);
	KUNIT_EXPECT_EQ(test, selinux_kunit_audit_host_tokens(), host_before - 1);
	KUNIT_ASSERT_NOT_NULL(test, current_selinux_state->ns_control);
	KUNIT_EXPECT_EQ(test, namespace_id,
			current_selinux_state->ns_control->ns.ns_id);
}

static void selinux_audit_allocation_failure_test(struct kunit *test)
{
	u16 count = 0;
	u64 namespace_id = 0;

	selinux_kunit_audit_buckets_reset();
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_avc_host_aggregate(true, -ENOMEM, &count,
						 &namespace_id),
		-ENOMEM);
	KUNIT_EXPECT_EQ(test, count, (u16)1);
}

static void selinux_audit_format_expansion_failure_test(struct kunit *test)
{
	struct audit_kunit_format_fault_result result;
	int rc;

	rc = audit_kunit_format_expand_failure(&result);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, result.failure_rc, -ENOMEM);
	KUNIT_EXPECT_EQ(test, result.expansion_failures, (u16)1);
	KUNIT_EXPECT_EQ(test, result.failure_enqueues, (u16)0);
	KUNIT_EXPECT_EQ(test, result.retry_rc, 0);
	KUNIT_EXPECT_EQ(test, result.retry_enqueues, (u16)2);
}

static void selinux_audit_refill_saturation_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_audit_refill_amount(U64_MAX, 4096), (u64)4096);
	KUNIT_EXPECT_LE(test,
		selinux_kunit_audit_refill_amount(1, 4096), (u64)4096);
}

static struct kunit_case selinux_namespace_control_test_cases[] = {
	KUNIT_CASE(selinux_ns_control_activation_test),
	KUNIT_CASE(selinux_ns_control_no_partial_publish_test),
	KUNIT_CASE(selinux_ns_control_requires_bidirectional_map_test),
	KUNIT_CASE(selinux_ns_nsfs_type_zero_handle_test),
	KUNIT_CASE(selinux_ns_direct_child_dormant_rejected_test),
	KUNIT_CASE(selinux_ns_direct_child_relationship_test),
	KUNIT_CASE(selinux_ns_control_from_file_ref_test),
	KUNIT_CASE(selinux_ns_control_nsfs_security_unwind_test),
	KUNIT_CASE(selinux_ns_generic_nsfs_projection_test),
	KUNIT_CASE(selinux_ns_restore_mismatch_is_not_published_test),
	KUNIT_CASE(selinux_policy_effective_digest_generation_test),
	KUNIT_CASE(selinux_policy_snapshot_digest_generation_test),
	KUNIT_CASE(selinux_ns_restore_id_reservation_test),
	KUNIT_CASE(selinux_policy_resource_accounting_test),
	KUNIT_CASE(selinux_namespace_resource_accounting_test),
	KUNIT_CASE(selinux_namespace_limit_validation_test),
	KUNIT_CASE(selinux_audit_host_reserve_lifetime_test),
	KUNIT_CASE(selinux_audit_dontaudit_host_aggregate_test),
	KUNIT_CASE(selinux_audit_allocation_failure_test),
	KUNIT_CASE(selinux_audit_format_expansion_failure_test),
	KUNIT_CASE(selinux_audit_refill_saturation_test),
	{}
};

static struct kunit_suite selinux_namespace_control_test_suite = {
	.name = "selinux-namespace-control",
	.test_cases = selinux_namespace_control_test_cases,
};

kunit_test_suite(selinux_namespace_control_test_suite);

MODULE_DESCRIPTION("KUnit tests for SELinux namespace control FDs");
MODULE_LICENSE("GPL");
