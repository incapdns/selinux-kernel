// SPDX-License-Identifier: GPL-2.0-only
/* Immutable provenance for SELinux-labeled objects without a stable path. */

#include <linux/err.h>
#include <linux/limits.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
#include <linux/mutex.h>
#include <linux/sched.h>
#endif

#include "global_sidtab.h"
#include "label_view.h"
#include "pathless.h"
#include "security.h"
#include "resource.h"

static atomic64_t selinux_pathless_projection_id = ATOMIC64_INIT(0);

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
struct selinux_pathless_kunit_fault_state {
	struct task_struct *owner;
	enum selinux_pathless_kunit_fault point;
	unsigned int occurrence;
	bool active;
};

static DEFINE_MUTEX(selinux_pathless_kunit_fault_lock);
static struct selinux_pathless_kunit_fault_state selinux_pathless_kunit_fault;

int selinux_pathless_kunit_fault_arm(
	enum selinux_pathless_kunit_fault point, unsigned int occurrence)
{
	if (point <= SELINUX_PATHLESS_KUNIT_FAULT_NONE ||
	    point >= SELINUX_PATHLESS_KUNIT_FAULT_MAX || !occurrence)
		return -EINVAL;

	mutex_lock(&selinux_pathless_kunit_fault_lock);
	WRITE_ONCE(selinux_pathless_kunit_fault.owner, current);
	WRITE_ONCE(selinux_pathless_kunit_fault.point, point);
	WRITE_ONCE(selinux_pathless_kunit_fault.occurrence, occurrence);
	/* Publish the selector before exposing this task-scoped fault. */
	smp_store_release(&selinux_pathless_kunit_fault.active, true);
	return 0;
}

void selinux_pathless_kunit_fault_disarm(void)
{
	if (WARN_ON_ONCE(READ_ONCE(selinux_pathless_kunit_fault.owner) != current))
		return;
	WRITE_ONCE(selinux_pathless_kunit_fault.active, false);
	WRITE_ONCE(selinux_pathless_kunit_fault.owner, NULL);
	WRITE_ONCE(selinux_pathless_kunit_fault.point,
		   SELINUX_PATHLESS_KUNIT_FAULT_NONE);
	WRITE_ONCE(selinux_pathless_kunit_fault.occurrence, 0);
	mutex_unlock(&selinux_pathless_kunit_fault_lock);
}

static bool selinux_pathless_kunit_should_fail(
	enum selinux_pathless_kunit_fault point, unsigned int occurrence)
{
	/* Pairs with arm's release before reading the fault selector. */
	if (!smp_load_acquire(&selinux_pathless_kunit_fault.active) ||
	    READ_ONCE(selinux_pathless_kunit_fault.owner) != current ||
	    READ_ONCE(selinux_pathless_kunit_fault.point) != point ||
	    READ_ONCE(selinux_pathless_kunit_fault.occurrence) != occurrence)
		return false;

	WRITE_ONCE(selinux_pathless_kunit_fault.active, false);
	return true;
}
#else
static inline bool selinux_pathless_kunit_should_fail(
	unsigned int point, unsigned int occurrence)
{
	(void)point;
	(void)occurrence;
	return false;
}
#endif

static u64 selinux_pathless_projection_next_id(void)
{
	s64 old = atomic64_read(&selinux_pathless_projection_id);

	for (;;) {
		/* Reusing an ID could validate stale pathless-object provenance. */
		if (unlikely(old == S64_MAX))
			return 0;
		if (atomic64_try_cmpxchg(&selinux_pathless_projection_id, &old,
					 old + 1))
			return old + 1;
	}
}

static bool selinux_pathless_kind_valid(enum selinux_pathless_kind kind)
{
	return kind > SELINUX_PATHLESS_KIND_INVALID &&
	       kind < SELINUX_PATHLESS_KIND_MAX;
}

static bool selinux_pathless_source_valid(enum selinux_label_source source)
{
	return source > SELINUX_LABEL_SOURCE_UNSPECIFIED &&
	       source <= SELINUX_LABEL_SOURCE_SOCKET;
}

static bool selinux_pathless_model_valid(enum selinux_pathless_model model)
{
	return model > SELINUX_PATHLESS_MODEL_INVALID &&
	       model < SELINUX_PATHLESS_MODEL_MAX;
}

static int selinux_pathless_projection_validate_label(
	struct selinux_label_ref *label, u32 sid,
	const struct selinux_label_view *view,
	struct selinux_label_resolution *resolution)
{
	struct selinux_label_ref *canonical;
	int rc;

	/* A numeric SID is never accepted without its exact canonical identity. */
	canonical = global_sid_to_label_ref(sid);
	if (IS_ERR(canonical))
		return PTR_ERR(canonical);
	if (canonical != label) {
		rc = -EINVAL;
		goto out;
	}

	rc = selinux_label_view_resolve_chain(view, label, sid, resolution);
out:
	selinux_label_ref_put(canonical);
	return rc;
}

static struct selinux_global_sid_handle *
selinux_pathless_sid_handle_get(u32 sid,
			       const struct selinux_label_ref *expected_label)
{
	struct selinux_global_sid_handle *handle;
	struct selinux_label_ref *canonical = NULL;
	int rc = 0;

	handle = global_sid_handle_get(sid);
	if (IS_ERR(handle))
		return handle;
	if (global_sid_handle_sid(handle) != sid) {
		rc = -ESTALE;
		goto out;
	}
	if (!expected_label)
		return handle;

	canonical = global_sid_handle_label_get(handle);
	if (!canonical)
		rc = -ESTALE;
	else if (canonical != expected_label)
		rc = -EINVAL;
out:
	selinux_label_ref_put(canonical);
	if (rc) {
		global_sid_handle_put(handle);
		return ERR_PTR(rc);
	}
	return handle;
}

static struct selinux_pathless_projection *
selinux_pathless_projection_alloc_validated(
	enum selinux_pathless_kind kind, enum selinux_label_source source,
	struct selinux_label_ref *label, u32 sid,
	const struct selinux_label_view *view, size_t alloc_size, gfp_t gfp)
{
	struct selinux_pathless_projection *projection;
	struct selinux_global_sid_handle *sid_handle;
	struct selinux_resource_account *resources;
	u64 id;

	sid_handle = selinux_pathless_sid_handle_get(sid, label);
	if (IS_ERR(sid_handle))
		return ERR_CAST(sid_handle);
	id = selinux_pathless_projection_next_id();
	if (!id) {
		projection = ERR_PTR(-EOVERFLOW);
		goto out_handle;
	}
	resources = selinux_resource_account_get(view->resources);
	if (!resources) {
		projection = ERR_PTR(-EINVAL);
		goto out_handle;
	}
	if (unlikely(selinux_pathless_kunit_should_fail(
		SELINUX_PATHLESS_KUNIT_FAULT_RESERVE, 1)) ||
	    selinux_resource_reserve(resources, SELINUX_RESOURCE_PROJECTION, 1,
				     alloc_size)) {
		selinux_resource_account_put(resources);
		projection = ERR_PTR(-EDQUOT);
		goto out_handle;
	}
	if (unlikely(selinux_pathless_kunit_should_fail(
		SELINUX_PATHLESS_KUNIT_FAULT_ALLOC, 1)))
		projection = NULL;
	else
		projection = kzalloc(alloc_size, gfp);
	if (!projection) {
		selinux_resource_release(resources, SELINUX_RESOURCE_PROJECTION,
					 1, alloc_size);
		selinux_resource_account_put(resources);
		projection = ERR_PTR(-ENOMEM);
		goto out_handle;
	}

	refcount_set(&projection->refs, 1);
	projection->id = id;
	projection->label = selinux_label_ref_get(label);
	projection->view = selinux_label_view_get(view);
	projection->sid_handle = sid_handle;
	projection->resources = resources;
	projection->charged_bytes = alloc_size;
	projection->sid = sid;
	projection->kind = kind;
	projection->source = source;
	return projection;

out_handle:
	global_sid_handle_put(sid_handle);
	return projection;
}

static void selinux_pathless_projection_release(
	struct selinux_pathless_projection *projection)
{
	u16 i;

	for (i = 0; i < projection->seal_count; i++)
		global_sid_handle_put(projection->seals[i].sid_handle);
	global_sid_handle_put(projection->sid_handle);
	selinux_label_view_put(projection->view);
	selinux_label_ref_put(projection->label);
	selinux_resource_release(projection->resources,
				 SELINUX_RESOURCE_PROJECTION, 1,
				 projection->charged_bytes);
	selinux_resource_account_put(projection->resources);
	kfree(projection);
}

struct selinux_pathless_projection *
selinux_pathless_projection_alloc(enum selinux_pathless_kind kind,
				  enum selinux_label_source source,
				  struct selinux_label_ref *label, u32 sid,
				  const struct selinux_label_view *view,
				  gfp_t gfp)
{
	struct selinux_pathless_projection *projection;
	struct selinux_label_resolution resolution;
	int rc;

	if (!selinux_pathless_kind_valid(kind) ||
	    !selinux_pathless_source_valid(source) || !label || !sid || !view ||
	    !view->origin_domain)
		return ERR_PTR(-EINVAL);
	if (!(label->domain->flags & SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) &&
	    label->domain != view->origin_domain)
		return ERR_PTR(-EINVAL);

	/* Validate the complete retained map chain before publication. */
	rc = selinux_pathless_projection_validate_label(label, sid, view,
							 &resolution);
	if (rc)
		return ERR_PTR(rc);

	projection = selinux_pathless_projection_alloc_validated(
		kind, source, label, sid, view, sizeof(*projection), gfp);
	return projection;
}

struct selinux_pathless_projection *
selinux_pathless_projection_alloc_sealed(
	enum selinux_pathless_kind kind, enum selinux_label_source source,
	struct selinux_label_ref *label, u32 sid,
	const struct selinux_label_view *view,
	const struct selinux_pathless_expect *expects, size_t expect_count,
	gfp_t gfp)
{
	struct selinux_pathless_projection *projection;
	struct selinux_label_resolution resolved;
	const struct selinux_label_domain *deepest;
	const struct selinux_label_domain *previous = NULL;
	size_t alloc_size, seals_size;
	bool kernel_global;
	size_t i;
	int rc;

	if (check_mul_overflow(expect_count, sizeof(projection->seals[0]),
			       &seals_size) ||
	    check_add_overflow(sizeof(*projection), seals_size, &alloc_size))
		return ERR_PTR(-EOVERFLOW);
	if (!selinux_pathless_kind_valid(kind) ||
	    !selinux_pathless_source_valid(source) || !label || !sid || !view ||
	    !view->origin_domain || !expects || !expect_count)
		return ERR_PTR(-EINVAL);
	if (expect_count > SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1)
		return ERR_PTR(-E2BIG);

	kernel_global = label->domain->flags &
			SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL;
	if (kernel_global &&
	    (source != SELINUX_LABEL_SOURCE_KERNEL_INITIAL ||
	     sid > SECINITSID_NUM))
		return ERR_PTR(-EINVAL);
	if (!kernel_global && label->domain != view->origin_domain)
		return ERR_PTR(-EINVAL);
	deepest = view->origin_domain;
	if (view->outer_domain &&
	    view->outer_domain->depth > deepest->depth)
		deepest = view->outer_domain;
	if (deepest->depth != expect_count - 1 ||
	    expects[expect_count - 1].domain != deepest)
		return ERR_PTR(-EINVAL);

	rc = selinux_pathless_projection_validate_label(label, sid, view,
							 &resolved);
	if (rc)
		return ERR_PTR(rc);
	if (resolved.max_depth != expect_count - 1)
		return ERR_PTR(-EINVAL);

	for (i = 0; i < expect_count; i++) {
		const struct selinux_pathless_expect *expect = &expects[i];

		if (!expect->domain || expect->domain->depth != i ||
		    expect->domain->parent != previous || !expect->sid ||
		    !expect->sclass ||
		    !selinux_pathless_model_valid(expect->model) ||
		    resolved.domain_id[i] != expect->domain->id ||
		    resolved.sid[i] != expect->sid ||
		    (kernel_global && expect->sid != sid))
			return ERR_PTR(-EINVAL);
		previous = expect->domain;
	}

	projection = selinux_pathless_projection_alloc_validated(
		kind, source, label, sid, view, alloc_size, gfp);
	if (IS_ERR(projection))
		return projection;
	for (i = 0; i < expect_count; i++) {
		struct selinux_global_sid_handle *seal_handle;

		if (unlikely(selinux_pathless_kunit_should_fail(
			SELINUX_PATHLESS_KUNIT_FAULT_SEAL_ACQUIRE, i + 1)))
			seal_handle = ERR_PTR(-ENOMEM);
		else
			seal_handle = selinux_pathless_sid_handle_get(
				expects[i].sid, NULL);
		if (IS_ERR(seal_handle)) {
			rc = PTR_ERR(seal_handle);
			goto out_projection;
		}
		projection->seals[i].domain_id = expects[i].domain->id;
		projection->seals[i].sid_handle = seal_handle;
		projection->seals[i].sid = expects[i].sid;
		projection->seals[i].sclass = expects[i].sclass;
		projection->seals[i].model = expects[i].model;
		if (expects[i].model == SELINUX_PATHLESS_MODEL_LEGACY &&
		    !projection->legacy_sclass)
			projection->legacy_sclass = expects[i].sclass;
		projection->seal_count++;
	}
	/*
	 * Preserve the exact class/model associated with the canonical label.
	 * This is required when a later operation asks a descendant policy to
	 * derive a new immutable seal; kind alone cannot distinguish IPC classes.
	 */
	i = kernel_global ? view->origin_domain->depth : label->domain->depth;
	if (i >= projection->seal_count) {
		rc = -EINVAL;
		goto out_projection;
	}
	projection->canonical_depth = i;
	projection->canonical_sclass = projection->seals[i].sclass;
	projection->canonical_model = projection->seals[i].model;
	if (!projection->legacy_sclass && kind == SELINUX_PATHLESS_KIND_MEMFD)
		projection->legacy_sclass = SECCLASS_FILE;
	return projection;

out_projection:
	/* No caller or RCU reader can observe a constructor rollback. */
	selinux_pathless_projection_release(projection);
	return ERR_PTR(rc);
}

struct selinux_pathless_projection *
selinux_pathless_projection_get(struct selinux_pathless_projection *projection)
{
	if (projection)
		refcount_inc(&projection->refs);
	return projection;
}

int selinux_pathless_policy_expect(
	const struct selinux_pathless_projection *projection,
	const struct selinux_policy_snapshot *snapshot,
	const struct selinux_label_domain *domain, u32 mapped_sid,
	struct selinux_pathless_expect *expect)
{
	const struct selinux_pathless_seal *seal;

	if (!projection || !snapshot || !domain || !mapped_sid || !expect)
		return -EINVAL;
	memset(expect, 0, sizeof(*expect));
	expect->domain = domain;
	expect->sid = mapped_sid;
	if (domain->depth < projection->seal_count &&
	    projection->seals[domain->depth].domain_id == domain->id) {
		seal = &projection->seals[domain->depth];
		if (seal->sid != mapped_sid ||
		    global_sid_handle_sid(seal->sid_handle) != seal->sid)
			return -ESTALE;
		expect->sclass = seal->sclass;
		expect->model = seal->model;
		return 0;
	}

	/*
	 * Kind never substitutes for policy metadata: the canonical tuple was
	 * captured explicitly at construction.  memfd_class is the sole policy
	 * capability which changes the tuple for these object families.
	 */
	if (!projection->canonical_sclass ||
	    !selinux_pathless_model_valid(projection->canonical_model))
		return -EOPNOTSUPP;
	if (projection->kind == SELINUX_PATHLESS_KIND_MEMFD &&
	    !selinux_policycap_memfd_class(snapshot)) {
		if (!projection->legacy_sclass)
			return -EOPNOTSUPP;
		expect->sclass = projection->legacy_sclass;
		expect->model = SELINUX_PATHLESS_MODEL_LEGACY;
	} else {
		/*
		 * A legacy-only origin does not describe the modern transition or
		 * context-copy tuple.  A heterogeneous descendant must fail closed
		 * until that metadata is explicitly present.
		 */
		if (projection->kind == SELINUX_PATHLESS_KIND_MEMFD &&
		    projection->canonical_model == SELINUX_PATHLESS_MODEL_LEGACY)
			return -EOPNOTSUPP;
		expect->sclass = projection->canonical_sclass;
		expect->model = projection->canonical_model;
	}
	return 0;
}

/*
 * Resolve a published identity into an operation-local policy line.  The
 * projection remains immutable.  No view/projection/resource is allocated:
 * source-to-LCA uses the source branch's sealed reverse maps and LCA-to-leaf
 * uses the observer branch's sealed forward maps.  This makes sibling and
 * cousin transfer linear in total ancestry depth without quota churn.
 */
int selinux_pathless_projection_resolve_cred_chain(
	const struct selinux_pathless_projection *projection,
	const struct cred *const *cred,
	const struct selinux_policy_snapshot *snapshots, u16 count,
	struct selinux_pathless_chain_resolution *resolved)
{
	const struct selinux_label_domain *leaf_domain;
	u16 i;
	int rc;

	if (!projection || !cred || !snapshots || !resolved || !count ||
	    count > SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1)
		return -EINVAL;
	leaf_domain = selinux_cred(cred[0])->state->label_domain;
	if (!leaf_domain || leaf_domain->depth + 1 != count)
		return -EXDEV;
	memset(resolved, 0, sizeof(*resolved));
	for (i = 0; i < count; i++) {
		const struct cred_security_struct *crsec = selinux_cred(cred[i]);
		const struct cred_security_struct *parent =
			i + 1 < count ? selinux_cred(cred[i + 1]) : NULL;

		if (!crsec->state || !crsec->state->label_domain ||
		    crsec->state->label_domain->depth != count - i - 1 ||
		    (parent && (crsec->parent_cred != cred[i + 1] ||
				crsec->state->parent != parent->state ||
				crsec->state->label_domain->parent !=
					parent->state->label_domain)) ||
		    (!parent && (crsec->parent_cred || crsec->state->parent ||
				 crsec->state->label_domain->parent)))
			return -EXDEV;
	}
	/* Common case: the published seals already are this exact actor chain. */
	for (i = 0; i < count; i++) {
		const struct selinux_label_domain *domain =
			selinux_cred(cred[i])->state->label_domain;
		struct selinux_pathless_resolution exact;

		rc = selinux_pathless_projection_resolve_sealed(
			projection, domain, &exact);
		if (rc)
			break;
		if (domain->depth && domain->depth <= projection->view->map_count &&
		    projection->view->maps[domain->depth - 1])
			exact.map_generation =
				projection->view->maps[domain->depth - 1]->generation;
		resolved->level[domain->depth] = exact;
	}
	if (i == count) {
		resolved->count = count;
		return 0;
	}
	memset(resolved, 0, sizeof(*resolved));
	rc = selinux_label_view_resolve_operation(
		projection->view, projection->label, projection->sid, leaf_domain,
		&resolved->labels);
	if (rc)
		return rc;
	for (i = 0; i < count; i++) {
		const struct selinux_label_domain *domain =
			selinux_cred(cred[i])->state->label_domain;
		struct selinux_pathless_expect expect;
		u16 depth = domain->depth;
		u32 sid = resolved->labels.labels.sid[depth];

		if (depth >= count ||
		    resolved->labels.labels.domain_id[depth] != domain->id ||
		    (depth && domain->parent->id !=
			     resolved->labels.labels.domain_id[depth - 1])) {
			rc = -EXDEV;
			goto out;
		}
		if (!sid) {
			rc = -EOPNOTSUPP;
			goto out;
		}
		rc = selinux_pathless_policy_expect(
			projection, &snapshots[i], domain, sid,
			&expect);
		if (rc)
			goto out;
		resolved->level[depth].sid = sid;
		resolved->level[depth].sclass = expect.sclass;
		resolved->level[depth].model = expect.model;
		resolved->level[depth].map_generation =
			resolved->labels.map_generation[depth];
	}
	resolved->count = count;
	rc = 0;
out:
	if (rc)
		selinux_label_operation_resolution_put(&resolved->labels);
	return rc;
}

void selinux_pathless_chain_resolution_put(
	struct selinux_pathless_chain_resolution *resolved)
{
	if (!resolved)
		return;
	selinux_label_operation_resolution_put(&resolved->labels);
	resolved->count = 0;
}

static void selinux_pathless_projection_free(struct rcu_head *rcu)
{
	struct selinux_pathless_projection *projection =
		container_of(rcu, struct selinux_pathless_projection, rcu);
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	struct completion *done = READ_ONCE(projection->free_done_kunit);
#endif

	selinux_pathless_projection_release(projection);
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (done)
		complete(done);
#endif
}

void
selinux_pathless_projection_put(struct selinux_pathless_projection *projection)
{
	if (projection && refcount_dec_and_test(&projection->refs))
		call_rcu(&projection->rcu, selinux_pathless_projection_free);
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
void selinux_pathless_projection_kunit_put_and_wait(
	struct selinux_pathless_projection *projection)
{
	DECLARE_COMPLETION_ONSTACK(done);

	if (!projection)
		return;
	/* This test-only primitive is valid only for the final owner. */
	if (WARN_ON(refcount_read(&projection->refs) != 1)) {
		selinux_pathless_projection_put(projection);
		return;
	}
	WRITE_ONCE(projection->free_done_kunit, &done);
	selinux_pathless_projection_put(projection);
	wait_for_completion(&done);
}
#endif

int
selinux_pathless_projection_resolve(const struct selinux_pathless_projection *projection,
				    const struct selinux_label_domain *policy_domain,
				    u32 *resolved_sid)
{
	if (!projection || !policy_domain || !resolved_sid)
		return -EINVAL;
	if (global_sid_handle_sid(projection->sid_handle) != projection->sid)
		return -EOPNOTSUPP;

	return selinux_label_view_resolve(projection->view, policy_domain,
					 projection->label, projection->sid,
					 resolved_sid);
}

int selinux_pathless_projection_resolve_sealed(
	const struct selinux_pathless_projection *projection,
	const struct selinux_label_domain *policy_domain,
	struct selinux_pathless_resolution *resolution)
{
	const struct selinux_pathless_seal *seal;
	u16 depth;

	if (!projection || !policy_domain || !resolution)
		return -EINVAL;
	depth = policy_domain->depth;
	if (depth >= projection->seal_count)
		return -EOPNOTSUPP;
	seal = &projection->seals[depth];
	if (seal->domain_id != policy_domain->id || !seal->sid ||
	    global_sid_handle_sid(seal->sid_handle) != seal->sid ||
	    !seal->sclass || !selinux_pathless_model_valid(seal->model))
		return -EOPNOTSUPP;

	resolution->sid = seal->sid;
	resolution->sclass = seal->sclass;
	resolution->model = seal->model;
	return 0;
}
