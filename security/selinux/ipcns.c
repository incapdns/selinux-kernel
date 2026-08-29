// SPDX-License-Identifier: GPL-2.0-only
/* Immutable SELinux policy/view anchors for IPC namespaces. */

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/ipc_namespace.h>
#include <linux/refcount.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#endif

#include "avc.h"
#include "flask.h"
#include "ipcns.h"
#include "label.h"
#include "label_view.h"
#include "namespace.h"
#include "objsec.h"
#include "resource.h"
#include "security.h"

struct selinux_ipcns_anchor {
	refcount_t refs;
	u64 id;
	u64 generation;
	struct selinux_state *state;
	struct selinux_label_domain *domain;
	const struct selinux_label_view *view;
	struct selinux_resource_account *resources;
	u64 charged_bytes;
};

static atomic64_t selinux_ipcns_sequence = ATOMIC64_INIT(0);
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
static atomic_t selinux_ipcns_fail_anchor_alloc = ATOMIC_INIT(0);
#endif

static struct selinux_ipcns_security *selinux_ipcns(struct ipc_namespace *ns)
{
	if (!ns || !ns->security)
		return NULL;
	return ns->security + selinux_blob_sizes.lbs_ipc_namespace;
}

static u64 selinux_ipcns_next_id(void)
{
	s64 old = atomic64_read(&selinux_ipcns_sequence);

	for (;;) {
		if (unlikely(old == S64_MAX))
			return 0;
		if (atomic64_try_cmpxchg(&selinux_ipcns_sequence, &old, old + 1))
			return (u64)old + 1;
	}
}

static struct selinux_ipcns_anchor *
selinux_ipcns_anchor_alloc(struct ipc_namespace *ns,
			   struct selinux_state *state)
{
	struct selinux_ipcns_anchor *anchor;
	const struct selinux_label_view *view;
	struct selinux_resource_account *resources;
	u64 id;
	int rc;

	if (!ns || !ns->user_ns || !state || !state->label_domain ||
	    !init_selinux_state || !init_selinux_state->label_domain)
		return ERR_PTR(-EACCES);
	id = selinux_ipcns_next_id();
	if (!id)
		return ERR_PTR(-EOVERFLOW);
	view = selinux_identity_view_alloc(ns->user_ns, state->label_domain,
					  init_selinux_state->label_domain);
	if (IS_ERR(view))
		return ERR_CAST(view);
	resources = selinux_resource_account_get(state->label_domain->resources);
	if (!resources) {
		selinux_label_view_put(view);
		return ERR_PTR(-EOPNOTSUPP);
	}
	rc = selinux_resource_reserve(resources, SELINUX_RESOURCE_IPC_ANCHOR,
				      1, sizeof(*anchor));
	if (rc) {
		selinux_resource_account_put(resources);
		selinux_label_view_put(view);
		return ERR_PTR(rc);
	}
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (atomic_xchg(&selinux_ipcns_fail_anchor_alloc, 0)) {
		selinux_resource_release(resources,
					 SELINUX_RESOURCE_IPC_ANCHOR, 1,
					 sizeof(*anchor));
		selinux_resource_account_put(resources);
		selinux_label_view_put(view);
		return ERR_PTR(-ENOMEM);
	}
#endif
	anchor = kzalloc_obj(*anchor, GFP_KERNEL_ACCOUNT);
	if (!anchor) {
		selinux_resource_release(resources,
					 SELINUX_RESOURCE_IPC_ANCHOR, 1,
					 sizeof(*anchor));
		selinux_resource_account_put(resources);
		selinux_label_view_put(view);
		return ERR_PTR(-ENOMEM);
	}
	refcount_set(&anchor->refs, 1);
	anchor->id = id;
	anchor->generation = id;
	anchor->state = get_selinux_state(state);
	anchor->domain = selinux_label_domain_get(state->label_domain);
	anchor->view = view;
	anchor->resources = resources;
	anchor->charged_bytes = sizeof(*anchor);
	return anchor;
}

void selinux_ipcns_anchor_put(struct selinux_ipcns_anchor *anchor)
{
	if (!anchor || !refcount_dec_and_test(&anchor->refs))
		return;
	selinux_label_view_put(anchor->view);
	selinux_label_domain_put(anchor->domain);
	put_selinux_state(anchor->state);
	selinux_resource_release(anchor->resources,
				 SELINUX_RESOURCE_IPC_ANCHOR, 1,
				 anchor->charged_bytes);
	selinux_resource_account_put(anchor->resources);
	kfree(anchor);
}

static struct selinux_ipcns_anchor *
selinux_ipcns_anchor_get_locked(struct selinux_ipcns_anchor *anchor)
{
	if (anchor && refcount_inc_not_zero(&anchor->refs))
		return anchor;
	return NULL;
}

const struct selinux_label_view *
selinux_ipcns_anchor_view(const struct selinux_ipcns_anchor *anchor)
{
	return anchor ? anchor->view : NULL;
}

struct selinux_ipcns_anchor *
selinux_ipcns_anchor_get(struct ipc_namespace *ns, const struct cred *cred)
{
	struct selinux_ipcns_security *sec = selinux_ipcns(ns);
	struct selinux_ipcns_anchor *anchor = NULL;
	struct selinux_state *state;

	if (!sec || !READ_ONCE(sec->initialized) || !cred)
		return ERR_PTR(-EACCES);
	state = selinux_cred(cred)->state;
	spin_lock(&sec->lock);
	if (!sec->pending && sec->anchor && sec->anchor->state == state)
		anchor = selinux_ipcns_anchor_get_locked(sec->anchor);
	spin_unlock(&sec->lock);
	return anchor ?: ERR_PTR(-EACCES);
}

bool selinux_ipcns_anchor_valid(struct ipc_namespace *ns,
			       const struct cred *cred,
			       const struct selinux_ipcns_anchor *anchor)
{
	struct selinux_ipcns_security *sec = selinux_ipcns(ns);
	bool valid = false;

	if (!sec || !READ_ONCE(sec->initialized) || !cred || !anchor)
		return false;
	spin_lock(&sec->lock);
	valid = !sec->pending && sec->anchor == anchor &&
		sec->anchor->state == selinux_cred(cred)->state;
	spin_unlock(&sec->lock);
	return valid;
}

static int selinux_ipc_namespace_alloc_security(
	struct ipc_namespace *ns, const struct ipc_namespace *old_ns,
	const struct cred *cred, bool initial)
{
	struct selinux_ipcns_security *sec = selinux_ipcns(ns);
	struct selinux_ipcns_anchor *anchor;
	struct selinux_state *state;

	(void)old_ns;
	if (!sec)
		return -EACCES;
	spin_lock_init(&sec->lock);
	WRITE_ONCE(sec->initialized, true);
	if (!cred)
		return -EACCES;
	state = selinux_cred(cred)->state;
	if (initial) {
#if defined(CONFIG_SYSVIPC) || defined(CONFIG_POSIX_MQUEUE)
		if (ns != &init_ipc_ns || state != init_selinux_state)
			return -EXDEV;
#else
		return -EOPNOTSUPP;
#endif
	}
	anchor = selinux_ipcns_anchor_alloc(ns, state);
	if (IS_ERR(anchor))
		return PTR_ERR(anchor);
	sec->anchor = anchor;
	sec->generation = anchor->generation;
	sec->initial = initial;
	return 0;
}

static void selinux_ipc_namespace_free_security(struct ipc_namespace *ns)
{
	struct selinux_ipcns_security *sec = selinux_ipcns(ns);
	struct selinux_ipcns_anchor *anchor, *pending;

	if (!sec || !READ_ONCE(sec->initialized))
		return;
	spin_lock(&sec->lock);
	anchor = sec->anchor;
	pending = sec->pending;
	sec->anchor = NULL;
	sec->pending = NULL;
	sec->pending_token = 0;
	WRITE_ONCE(sec->initialized, false);
	spin_unlock(&sec->lock);
	selinux_ipcns_anchor_put(pending);
	selinux_ipcns_anchor_put(anchor);
}

static void selinux_ipcns_ids_write_lock(struct ipc_namespace *ns)
{
#ifdef CONFIG_SYSVIPC
	down_write(&ns->ids[IPC_SEM_IDS].rwsem);
	down_write(&ns->ids[IPC_MSG_IDS].rwsem);
	down_write(&ns->ids[IPC_SHM_IDS].rwsem);
#else
	(void)ns;
#endif
}

static void selinux_ipcns_ids_write_unlock(struct ipc_namespace *ns)
{
#ifdef CONFIG_SYSVIPC
	up_write(&ns->ids[IPC_SHM_IDS].rwsem);
	up_write(&ns->ids[IPC_MSG_IDS].rwsem);
	up_write(&ns->ids[IPC_SEM_IDS].rwsem);
#else
	(void)ns;
#endif
}

static bool selinux_ipcns_empty_locked(const struct ipc_namespace *ns)
{
#ifdef CONFIG_SYSVIPC
	if (ns->ids[IPC_SEM_IDS].in_use ||
	    ns->ids[IPC_MSG_IDS].in_use ||
	    ns->ids[IPC_SHM_IDS].in_use)
		return false;
#endif
	return !ns->mq_queues_count;
}

static int selinux_ipcns_pending_try(
	struct selinux_ipcns_security *sec, struct selinux_ipcns_anchor *old,
	u64 generation, struct selinux_ipcns_anchor *candidate, u64 token)
{
	int rc = 0;

	spin_lock(&sec->lock);
	if (sec->anchor != old || sec->generation != generation ||
	    sec->pending || sec->initial || sec->reanchored ||
	    sec->ever_published)
		rc = -ESTALE;
	else {
		sec->pending = candidate;
		sec->pending_token = token;
	}
	spin_unlock(&sec->lock);
	return rc;
}

enum selinux_ipcns_join_relation {
	SELINUX_IPCNS_JOIN_SAME,
	SELINUX_IPCNS_JOIN_SELINUX_FIRST,
	SELINUX_IPCNS_JOIN_IPC_FIRST,
	SELINUX_IPCNS_JOIN_INVALID,
};

static enum selinux_ipcns_join_relation selinux_ipcns_join_relation(
	const struct selinux_state *anchor, const struct selinux_state *target)
{
	if (!anchor || !target)
		return SELINUX_IPCNS_JOIN_INVALID;
	if (anchor == target)
		return SELINUX_IPCNS_JOIN_SAME;
	if (target->parent == anchor)
		return SELINUX_IPCNS_JOIN_SELINUX_FIRST;
	if (anchor->parent == target)
		return SELINUX_IPCNS_JOIN_IPC_FIRST;
	return SELINUX_IPCNS_JOIN_INVALID;
}

static int selinux_ipc_namespace_reanchor_prepare(
	struct ipc_namespace *ns, const struct cred *cred, u64 token,
	struct cred *mutable_cred, struct cred **replacement_cred)
{
	struct selinux_ipcns_security *sec = selinux_ipcns(ns);
	struct selinux_ipcns_anchor *old, *candidate = NULL;
	struct cred *joined = NULL;
	struct selinux_state *target;
	enum selinux_ipcns_join_relation relation;
	u64 generation;
	int rc;

	if (!sec || !READ_ONCE(sec->initialized) || !cred || !token)
		return -EINVAL;
	if (replacement_cred && *replacement_cred)
		return -EBUSY;
	spin_lock(&sec->lock);
	old = selinux_ipcns_anchor_get_locked(sec->anchor);
	generation = sec->generation;
	if (!old || sec->pending) {
		spin_unlock(&sec->lock);
		selinux_ipcns_anchor_put(old);
		return -EBUSY;
	}
	target = selinux_cred(cred)->state;
	relation = selinux_ipcns_join_relation(old->state, target);
	if (relation == SELINUX_IPCNS_JOIN_SAME) {
		spin_unlock(&sec->lock);
		selinux_ipcns_anchor_put(old);
		return 0;
	}
	spin_unlock(&sec->lock);

	/*
	 * IPC-first join: the target IPC namespace is already anchored in the
	 * direct child of the caller.  Prepare that child credential through the
	 * normal parent-authorized SELinux namespace join path; never let a host
	 * credential operate transiently against a child anchor.
	 */
	if (relation == SELINUX_IPCNS_JOIN_IPC_FIRST) {
		if ((replacement_cred && *replacement_cred) ||
		    !old->state->ns_control ||
		    (!mutable_cred && !replacement_cred)) {
			rc = -EOPNOTSUPP;
			goto out;
		}
		if (mutable_cred)
			rc = selinux_ns_control_apply_join(
				old->state->ns_control, current_cred(), mutable_cred);
		else
			rc = selinux_ns_control_prepare_join(old->state->ns_control,
						     &joined);
		if (rc)
			goto out;
		if (selinux_cred(mutable_cred ?: joined)->state != old->state) {
			rc = -ESTALE;
			goto out;
		}
		spin_lock(&sec->lock);
		rc = sec->anchor == old && sec->generation == generation &&
			     !sec->pending ? 0 : -ESTALE;
		spin_unlock(&sec->lock);
		if (rc)
			goto out;
		if (joined) {
			*replacement_cred = joined;
			joined = NULL;
		}
		goto out;
	}
	if (relation != SELINUX_IPCNS_JOIN_SELINUX_FIRST) {
		rc = -EXDEV;
		goto out;
	}
	spin_lock(&sec->lock);
	if (sec->initial || sec->reanchored || sec->ever_published) {
		spin_unlock(&sec->lock);
		rc = -EXDEV;
		goto out;
	}
	spin_unlock(&sec->lock);
	if (!target || !selinux_state_active(target) ||
	    target->parent != old->state || !target->label_domain ||
	    target->label_domain->parent != old->domain ||
	    target->label_domain->owner_userns != ns->user_ns) {
		rc = -EXDEV;
		goto out;
	}
	rc = cred_self_has_perm(cred, SECCLASS_PROCESS2,
				PROCESS2__UNSHARE_SELINUXNS, NULL);
	if (rc)
		goto out;
	candidate = selinux_ipcns_anchor_alloc(ns, target);
	if (IS_ERR(candidate)) {
		rc = PTR_ERR(candidate);
		candidate = NULL;
		goto out;
	}

	selinux_ipcns_ids_write_lock(ns);
#if defined(CONFIG_SYSVIPC) || defined(CONFIG_POSIX_MQUEUE)
	spin_lock(&mq_lock);
	if (!selinux_ipcns_empty_locked(ns)) {
		rc = -EBUSY;
	} else {
		rc = selinux_ipcns_pending_try(sec, old, generation, candidate,
					       token);
		if (!rc)
			candidate = NULL;
	}
	spin_unlock(&mq_lock);
#else
	rc = -EOPNOTSUPP;
#endif
	selinux_ipcns_ids_write_unlock(ns);
out:
	if (joined)
		abort_creds(joined);
	selinux_ipcns_anchor_put(candidate);
	selinux_ipcns_anchor_put(old);
	return rc;
}

static void selinux_ipc_namespace_reanchor_commit(struct ipc_namespace *ns,
						  u64 token)
{
	struct selinux_ipcns_security *sec = selinux_ipcns(ns);
	struct selinux_ipcns_anchor *old = NULL;

	if (!sec || !READ_ONCE(sec->initialized) || !token)
		return;
	spin_lock(&sec->lock);
	if (sec->pending && sec->pending_token == token) {
		old = sec->anchor;
		sec->anchor = sec->pending;
		sec->pending = NULL;
		sec->pending_token = 0;
		sec->generation = sec->anchor->generation;
		sec->reanchored = true;
	}
	spin_unlock(&sec->lock);
	selinux_ipcns_anchor_put(old);
}

static void selinux_ipc_namespace_reanchor_abort(struct ipc_namespace *ns,
						 u64 token)
{
	struct selinux_ipcns_security *sec = selinux_ipcns(ns);
	struct selinux_ipcns_anchor *pending = NULL;

	if (!sec || !READ_ONCE(sec->initialized) || !token)
		return;
	spin_lock(&sec->lock);
	if (sec->pending && sec->pending_token == token) {
		pending = sec->pending;
		sec->pending = NULL;
		sec->pending_token = 0;
	}
	spin_unlock(&sec->lock);
	selinux_ipcns_anchor_put(pending);
}

/* Atomic hook: caller holds an ids writer lock or mq_lock. */
static int selinux_ipc_namespace_create_gate(struct ipc_namespace *ns,
					      const struct cred *cred)
{
	struct selinux_ipcns_security *sec = selinux_ipcns(ns);
	int rc = -EACCES;

	if (!sec || !READ_ONCE(sec->initialized) || !cred)
		return rc;
	spin_lock(&sec->lock);
	if (sec->pending)
		rc = -EBUSY;
	else if (sec->anchor && sec->anchor->state == selinux_cred(cred)->state)
		rc = 0;
	spin_unlock(&sec->lock);
	return rc;
}

/* Atomic hook: publication is serialized by the corresponding IPC lock. */
static void selinux_ipc_namespace_object_published(struct ipc_namespace *ns)
{
	struct selinux_ipcns_security *sec = selinux_ipcns(ns);

	if (!sec || !READ_ONCE(sec->initialized))
		return;
	spin_lock(&sec->lock);
	sec->ever_published = true;
	spin_unlock(&sec->lock);
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
struct selinux_ipcns_test_ctx {
	struct ipc_namespace ns;
	struct selinux_ipcns_security *sec;
	struct selinux_resource_account *resources;
};

static int selinux_ipcns_test_init(struct kunit *test,
				   struct selinux_ipcns_test_ctx *ctx)
{
	size_t bytes = selinux_blob_sizes.lbs_ipc_namespace +
		       sizeof(struct selinux_ipcns_security);

	memset(ctx, 0, sizeof(*ctx));
	ctx->ns.user_ns = &init_user_ns;
	ctx->ns.security = kunit_kzalloc(test, bytes, GFP_KERNEL);
	if (!ctx->ns.security)
		return -ENOMEM;
	ctx->sec = selinux_ipcns(&ctx->ns);
	ctx->resources = selinux_cred(current_cred())->state->label_domain->resources;
	return selinux_ipc_namespace_alloc_security(
		&ctx->ns, NULL, current_cred(), false);
}

#if defined(CONFIG_SYSVIPC) || defined(CONFIG_POSIX_MQUEUE)
static void selinux_ipcns_initial_anchor_test(struct kunit *test)
{
	struct selinux_ipcns_security *sec = selinux_ipcns(&init_ipc_ns);

	KUNIT_ASSERT_NOT_NULL(test, sec);
	KUNIT_EXPECT_TRUE(test, READ_ONCE(sec->initialized));
	KUNIT_EXPECT_TRUE(test, READ_ONCE(sec->initial));
	KUNIT_ASSERT_NOT_NULL(test, READ_ONCE(sec->anchor));
	KUNIT_EXPECT_PTR_EQ(test, READ_ONCE(sec->anchor)->state,
			    init_selinux_state);
}
#endif

static void selinux_ipcns_lifetime_accounting_test(struct kunit *test)
{
	struct selinux_ipcns_test_ctx *ctx;
	struct selinux_ipcns_anchor *held;
	u64 before;
	int rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	before = selinux_kunit_resource_objects(
		selinux_cred(current_cred())->state->label_domain->resources,
		SELINUX_RESOURCE_IPC_ANCHOR);
	rc = selinux_ipcns_test_init(test, ctx);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(
			ctx->resources, SELINUX_RESOURCE_IPC_ANCHOR),
		before + 1);
	held = selinux_ipcns_anchor_get(&ctx->ns, current_cred());
	KUNIT_ASSERT_FALSE(test, IS_ERR(held));
	selinux_ipc_namespace_free_security(&ctx->ns);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(
			ctx->resources, SELINUX_RESOURCE_IPC_ANCHOR),
		before + 1);
	selinux_ipcns_anchor_put(held);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(
			ctx->resources, SELINUX_RESOURCE_IPC_ANCHOR),
		before);
}

static void selinux_ipcns_rollback_test(struct kunit *test)
{
	struct selinux_ipcns_test_ctx *ctx;
	struct selinux_ipcns_anchor *candidate, *old;
	u64 before, generation;
	int rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	rc = selinux_ipcns_test_init(test, ctx);
	KUNIT_ASSERT_EQ(test, rc, 0);
	before = selinux_kunit_resource_objects(
		ctx->resources, SELINUX_RESOURCE_IPC_ANCHOR);
	old = ctx->sec->anchor;
	generation = ctx->sec->generation;
	candidate = selinux_ipcns_anchor_alloc(
		&ctx->ns, selinux_cred(current_cred())->state);
	KUNIT_ASSERT_FALSE(test, IS_ERR(candidate));
	rc = selinux_ipcns_pending_try(ctx->sec, old, generation, candidate, 11);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test,
		selinux_ipc_namespace_create_gate(&ctx->ns, current_cred()),
		-EBUSY);
	selinux_ipc_namespace_reanchor_abort(&ctx->ns, 12);
	KUNIT_EXPECT_PTR_EQ(test, ctx->sec->pending, candidate);
	selinux_ipc_namespace_reanchor_abort(&ctx->ns, 11);
	KUNIT_EXPECT_PTR_EQ(test, ctx->sec->anchor, old);
	KUNIT_EXPECT_PTR_EQ(test, ctx->sec->pending, NULL);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(
			ctx->resources, SELINUX_RESOURCE_IPC_ANCHOR),
		before);
	selinux_ipc_namespace_free_security(&ctx->ns);
}

static void selinux_ipcns_empty_bookkeeping_test(struct kunit *test)
{
	struct ipc_namespace ns = {};
#ifdef CONFIG_SYSVIPC
	int i;
#endif

	KUNIT_EXPECT_TRUE(test, selinux_ipcns_empty_locked(&ns));
#ifdef CONFIG_SYSVIPC
	for (i = 0; i < IPC_IDS_COUNT; i++) {
		ns.ids[i].in_use = 1;
		KUNIT_EXPECT_FALSE(test, selinux_ipcns_empty_locked(&ns));
		ns.ids[i].in_use = 0;
	}
#endif
	ns.mq_queues_count = 1;
	KUNIT_EXPECT_FALSE(test, selinux_ipcns_empty_locked(&ns));
}

static void selinux_ipcns_join_order_test(struct kunit *test)
{
	struct selinux_state host = {};
	struct selinux_state child = { .parent = &host };
	struct selinux_state sibling = { .parent = &host };
	struct selinux_state grandchild = { .parent = &child };

	KUNIT_EXPECT_EQ(test, selinux_ipcns_join_relation(&host, &child),
			SELINUX_IPCNS_JOIN_SELINUX_FIRST);
	KUNIT_EXPECT_EQ(test, selinux_ipcns_join_relation(&child, &host),
			SELINUX_IPCNS_JOIN_IPC_FIRST);
	KUNIT_EXPECT_EQ(test, selinux_ipcns_join_relation(&child, &child),
			SELINUX_IPCNS_JOIN_SAME);
	KUNIT_EXPECT_EQ(test, selinux_ipcns_join_relation(&child, &sibling),
			SELINUX_IPCNS_JOIN_INVALID);
	KUNIT_EXPECT_EQ(test, selinux_ipcns_join_relation(&host, &grandchild),
			SELINUX_IPCNS_JOIN_INVALID);
}

static void selinux_ipcns_userns_single_cred_test(struct kunit *test)
{
	struct nsset set = {
		.flags = CLONE_NEWUSER,
		.cred = current_cred(),
	};

	KUNIT_EXPECT_PTR_EQ(test, nsset_cred(&set), current_cred());
	KUNIT_EXPECT_EQ(test,
		nsset_install_security_cred(&set, (struct cred *)current_cred()),
		-EBUSY);
	KUNIT_EXPECT_PTR_EQ(test, set.security_cred, NULL);
}

static void selinux_ipcns_publish_second_reanchor_test(struct kunit *test)
{
	struct selinux_ipcns_test_ctx *ctx;
	struct selinux_ipcns_anchor *candidate, *second, *old;
	u64 generation;
	int rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	rc = selinux_ipcns_test_init(test, ctx);
	KUNIT_ASSERT_EQ(test, rc, 0);
	old = ctx->sec->anchor;
	generation = ctx->sec->generation;
	candidate = selinux_ipcns_anchor_alloc(
		&ctx->ns, selinux_cred(current_cred())->state);
	KUNIT_ASSERT_FALSE(test, IS_ERR(candidate));
	rc = selinux_ipcns_pending_try(ctx->sec, old, generation, candidate, 21);
	KUNIT_ASSERT_EQ(test, rc, 0);
	selinux_ipc_namespace_reanchor_commit(&ctx->ns, 21);
	KUNIT_EXPECT_TRUE(test, ctx->sec->reanchored);
	KUNIT_EXPECT_PTR_NE(test, ctx->sec->anchor, old);
	selinux_ipc_namespace_object_published(&ctx->ns);
	KUNIT_EXPECT_TRUE(test, ctx->sec->ever_published);
	/* SysV and POSIX mqueue share the same idempotent publication seal. */
	selinux_ipc_namespace_object_published(&ctx->ns);
	KUNIT_EXPECT_TRUE(test, ctx->sec->ever_published);

	second = selinux_ipcns_anchor_alloc(
		&ctx->ns, selinux_cred(current_cred())->state);
	KUNIT_ASSERT_FALSE(test, IS_ERR(second));
	rc = selinux_ipcns_pending_try(ctx->sec, ctx->sec->anchor,
				       ctx->sec->generation, second, 22);
	KUNIT_EXPECT_EQ(test, rc, -ESTALE);
	selinux_ipcns_anchor_put(second);
	selinux_ipc_namespace_free_security(&ctx->ns);
}

static void selinux_ipcns_fault_rollback_test(struct kunit *test)
{
	struct selinux_ipcns_test_ctx *ctx;
	struct selinux_resource_account *resources;
	size_t bytes = selinux_blob_sizes.lbs_ipc_namespace +
		       sizeof(struct selinux_ipcns_security);
	u64 before;
	int rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	resources = selinux_cred(current_cred())->state->label_domain->resources;
	before = selinux_kunit_resource_objects(
		resources, SELINUX_RESOURCE_IPC_ANCHOR);
	ctx->ns.user_ns = &init_user_ns;
	ctx->ns.security = kunit_kzalloc(test, bytes, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->ns.security);
	atomic_set(&selinux_ipcns_fail_anchor_alloc, 1);
	rc = selinux_ipc_namespace_alloc_security(
		&ctx->ns, NULL, current_cred(), false);
	KUNIT_EXPECT_EQ(test, rc, -ENOMEM);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(
			resources, SELINUX_RESOURCE_IPC_ANCHOR),
		before);
}

struct selinux_ipcns_race {
	struct selinux_ipcns_security *sec;
	struct selinux_ipcns_anchor *old;
	struct selinux_ipcns_anchor *candidate;
	u64 generation;
	u64 token;
	struct completion ready;
	struct completion go;
	struct completion done;
	int rc;
};

static int selinux_ipcns_race_worker(void *data)
{
	struct selinux_ipcns_race *race = data;

	complete(&race->ready);
	wait_for_completion(&race->go);
	race->rc = selinux_ipcns_pending_try(
		race->sec, race->old, race->generation, race->candidate,
		race->token);
	complete(&race->done);
	/* Keep task_struct alive until the owning test performs kthread_stop(). */
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

static void selinux_ipcns_concurrent_pending_test(struct kunit *test)
{
	struct selinux_ipcns_test_ctx *ctx;
	struct selinux_ipcns_race race[2] = {};
	struct task_struct *task[2];
	int i, rc, winners;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	rc = selinux_ipcns_test_init(test, ctx);
	KUNIT_ASSERT_EQ(test, rc, 0);
	for (i = 0; i < 2; i++) {
		race[i].sec = ctx->sec;
		race[i].old = ctx->sec->anchor;
		race[i].generation = ctx->sec->generation;
		race[i].token = 30 + i;
		race[i].candidate = selinux_ipcns_anchor_alloc(
			&ctx->ns, selinux_cred(current_cred())->state);
		if (IS_ERR(race[i].candidate)) {
			rc = PTR_ERR(race[i].candidate);
			race[i].candidate = NULL;
			KUNIT_FAIL(test, "candidate allocation failed: %d", rc);
			goto out_candidates;
		}
		init_completion(&race[i].ready);
		init_completion(&race[i].go);
		init_completion(&race[i].done);
	}
	for (i = 0; i < 2; i++) {
		task[i] = kthread_run(selinux_ipcns_race_worker, &race[i],
				      "selinux-ipcns-race/%d", i);
		if (IS_ERR(task[i])) {
			rc = PTR_ERR(task[i]);
			KUNIT_FAIL(test, "worker creation failed: %d", rc);
			while (i--) {
				complete(&race[i].go);
				wait_for_completion(&race[i].done);
				kthread_stop(task[i]);
			}
			goto out_candidates;
		}
	}
	for (i = 0; i < 2; i++)
		wait_for_completion(&race[i].ready);
	for (i = 0; i < 2; i++)
		complete(&race[i].go);
	for (i = 0; i < 2; i++) {
		wait_for_completion(&race[i].done);
		kthread_stop(task[i]);
	}
	winners = (race[0].rc == 0) + (race[1].rc == 0);
	KUNIT_EXPECT_EQ(test, winners, 1);
	for (i = 0; i < 2; i++)
		if (race[i].rc)
			selinux_ipcns_anchor_put(race[i].candidate);
	selinux_ipc_namespace_reanchor_abort(
		&ctx->ns, ctx->sec->pending_token);
	goto out_free;
out_candidates:
	for (i = 0; i < 2; i++) {
		if (ctx->sec->pending == race[i].candidate)
			selinux_ipc_namespace_reanchor_abort(
				&ctx->ns, ctx->sec->pending_token);
		else
			selinux_ipcns_anchor_put(race[i].candidate);
	}
out_free:
	selinux_ipc_namespace_free_security(&ctx->ns);
}

static struct kunit_case selinux_ipcns_test_cases[] = {
#if defined(CONFIG_SYSVIPC) || defined(CONFIG_POSIX_MQUEUE)
	KUNIT_CASE(selinux_ipcns_initial_anchor_test),
#endif
	KUNIT_CASE(selinux_ipcns_lifetime_accounting_test),
	KUNIT_CASE(selinux_ipcns_rollback_test),
	KUNIT_CASE(selinux_ipcns_empty_bookkeeping_test),
	KUNIT_CASE(selinux_ipcns_join_order_test),
	KUNIT_CASE(selinux_ipcns_userns_single_cred_test),
	KUNIT_CASE(selinux_ipcns_publish_second_reanchor_test),
	KUNIT_CASE(selinux_ipcns_fault_rollback_test),
	KUNIT_CASE(selinux_ipcns_concurrent_pending_test),
	{},
};

static struct kunit_suite selinux_ipcns_test_suite = {
	.name = "selinux-ipcns-anchor",
	.test_cases = selinux_ipcns_test_cases,
};

kunit_test_suite(selinux_ipcns_test_suite);
#endif /* CONFIG_SECURITY_SELINUX_KUNIT_TEST */

static struct security_hook_list selinux_ipcns_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(ipc_namespace_alloc_security,
		      selinux_ipc_namespace_alloc_security),
	LSM_HOOK_INIT(ipc_namespace_free_security,
		      selinux_ipc_namespace_free_security),
	LSM_HOOK_INIT(ipc_namespace_reanchor_prepare,
		      selinux_ipc_namespace_reanchor_prepare),
	LSM_HOOK_INIT(ipc_namespace_reanchor_commit,
		      selinux_ipc_namespace_reanchor_commit),
	LSM_HOOK_INIT(ipc_namespace_reanchor_abort,
		      selinux_ipc_namespace_reanchor_abort),
	LSM_HOOK_INIT(ipc_namespace_create_gate,
		      selinux_ipc_namespace_create_gate),
	LSM_HOOK_INIT(ipc_namespace_object_published,
		      selinux_ipc_namespace_object_published),
};

void __init selinux_ipcns_add_hooks(const struct lsm_id *lsmid)
{
	security_add_hooks(selinux_ipcns_hooks, ARRAY_SIZE(selinux_ipcns_hooks),
			   lsmid);
}
