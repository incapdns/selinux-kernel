// SPDX-License-Identifier: GPL-2.0-only
/*
 * Immutable SELinux label views selected by VFS mounts.
 */

#include <linux/err.h>
#include <linux/limits.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
#include <linux/mutex.h>
#include <linux/sched.h>
#endif

#include "label_view.h"
#include "security.h"
#include "resource.h"
#ifdef CONFIG_SECURITY_SELINUX_NS
#include "global_sidtab.h"
#endif

static atomic64_t selinux_label_view_id = ATOMIC64_INIT(0);

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
struct selinux_label_view_kunit_fault_state {
	struct task_struct *owner;
	enum selinux_label_view_kunit_fault point;
	unsigned int occurrence;
	bool active;
};

static DEFINE_MUTEX(selinux_label_view_kunit_fault_lock);
static struct selinux_label_view_kunit_fault_state
	selinux_label_view_kunit_fault;

int selinux_label_view_kunit_fault_arm(
	enum selinux_label_view_kunit_fault point, unsigned int occurrence)
{
	if (point <= SELINUX_LABEL_VIEW_KUNIT_FAULT_NONE ||
	    point >= SELINUX_LABEL_VIEW_KUNIT_FAULT_MAX || !occurrence)
		return -EINVAL;

	mutex_lock(&selinux_label_view_kunit_fault_lock);
	WRITE_ONCE(selinux_label_view_kunit_fault.owner, current);
	WRITE_ONCE(selinux_label_view_kunit_fault.point, point);
	WRITE_ONCE(selinux_label_view_kunit_fault.occurrence, occurrence);
	/* Publish the selector before exposing this task-scoped fault. */
	smp_store_release(&selinux_label_view_kunit_fault.active, true);
	return 0;
}

void selinux_label_view_kunit_fault_disarm(void)
{
	if (WARN_ON_ONCE(READ_ONCE(selinux_label_view_kunit_fault.owner) != current))
		return;
	WRITE_ONCE(selinux_label_view_kunit_fault.active, false);
	WRITE_ONCE(selinux_label_view_kunit_fault.owner, NULL);
	WRITE_ONCE(selinux_label_view_kunit_fault.point,
		   SELINUX_LABEL_VIEW_KUNIT_FAULT_NONE);
	WRITE_ONCE(selinux_label_view_kunit_fault.occurrence, 0);
	mutex_unlock(&selinux_label_view_kunit_fault_lock);
}

static bool selinux_label_view_kunit_should_fail(
	enum selinux_label_view_kunit_fault point, unsigned int occurrence)
{
	/* Pairs with arm's release before reading the fault selector. */
	if (!smp_load_acquire(&selinux_label_view_kunit_fault.active) ||
	    READ_ONCE(selinux_label_view_kunit_fault.owner) != current ||
	    READ_ONCE(selinux_label_view_kunit_fault.point) != point ||
	    READ_ONCE(selinux_label_view_kunit_fault.occurrence) != occurrence)
		return false;

	WRITE_ONCE(selinux_label_view_kunit_fault.active, false);
	return true;
}
#else
static inline bool selinux_label_view_kunit_should_fail(
	unsigned int point, unsigned int occurrence)
{
	(void)point;
	(void)occurrence;
	return false;
}
#endif

static u64 selinux_label_view_next_id(void)
{
	s64 old = atomic64_read(&selinux_label_view_id);

	for (;;) {
		/* Never wrap into an ID which could alias a live or cached view. */
		if (unlikely(old == S64_MAX))
			return 0;
		if (atomic64_try_cmpxchg(&selinux_label_view_id, &old, old + 1))
			return old + 1;
	}
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static bool selinux_label_domain_is_ancestor(const struct selinux_label_domain *ancestor,
					     const struct selinux_label_domain *domain)
{
	while (domain && domain->depth > ancestor->depth)
		domain = domain->parent;
	return domain == ancestor;
}
#endif

static void selinux_label_view_free(struct rcu_head *rcu)
{
	struct selinux_label_view *view =
		container_of(rcu, struct selinux_label_view, rcu);
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	struct completion *done = READ_ONCE(view->free_done_kunit);
#endif
#ifdef CONFIG_SECURITY_SELINUX_NS
	int i;
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
	for (i = 0; i < view->map_count; i++)
		selinux_label_map_put(view->maps[i]);
#endif
	selinux_label_domain_put(view->origin_domain);
	selinux_label_domain_put(view->outer_domain);
	put_user_ns(view->owner_userns);
	selinux_resource_release(view->resources, SELINUX_RESOURCE_VIEW, 1,
				 view->charged_bytes);
	selinux_resource_account_put(view->resources);
	kfree(view);
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (done)
		complete(done);
#endif
}

const struct selinux_label_view *
selinux_label_view_get(const struct selinux_label_view *view)
{
	if (WARN_ON_ONCE(!view))
		return NULL;

	refcount_inc((refcount_t *)&view->refs);
	return view;
}

void selinux_label_view_put(const struct selinux_label_view *view)
{
	if (!view)
		return;

	if (refcount_dec_and_test((refcount_t *)&view->refs))
		call_rcu((struct rcu_head *)&view->rcu, selinux_label_view_free);
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
void selinux_label_view_kunit_put_and_wait(
	const struct selinux_label_view *view)
{
	struct selinux_label_view *mutable_view =
		(struct selinux_label_view *)view;
	DECLARE_COMPLETION_ONSTACK(done);

	if (!view)
		return;
	/* This test-only primitive is valid only for the final owner. */
	if (WARN_ON(refcount_read(&view->refs) != 1)) {
		selinux_label_view_put(view);
		return;
	}
	WRITE_ONCE(mutable_view->free_done_kunit, &done);
	selinux_label_view_put(view);
	wait_for_completion(&done);
}
#endif

const struct selinux_label_view *
selinux_identity_view_alloc_gfp(struct user_namespace *owner_userns,
				struct selinux_label_domain *origin_domain,
				struct selinux_label_domain *outer_domain,
				gfp_t gfp)
{
	struct selinux_label_view *view;
	struct selinux_resource_account *resources;
	size_t bytes;
	u64 id;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_label_domain *deepest, *cursor;
	unsigned int acquired = 0;
	int rc = -EOPNOTSUPP;
	int i;
#endif

	if (!owner_userns || !outer_domain)
		return ERR_PTR(-EINVAL);

#ifdef CONFIG_SECURITY_SELINUX_NS
	deepest = outer_domain;
	if (origin_domain && origin_domain->depth > outer_domain->depth)
		deepest = origin_domain;
	bytes = struct_size(view, maps, deepest->depth);
#else
	bytes = sizeof(*view);
#endif
	resources = selinux_resource_account_get_owner(owner_userns);
	if (IS_ERR(resources))
		return ERR_CAST(resources);
	if (unlikely(selinux_label_view_kunit_should_fail(
		SELINUX_LABEL_VIEW_KUNIT_FAULT_RESERVE, 1)) ||
	    selinux_resource_reserve(resources, SELINUX_RESOURCE_VIEW, 1,
				     bytes)) {
		selinux_resource_account_put(resources);
		return ERR_PTR(-EDQUOT);
	}
	if (unlikely(selinux_label_view_kunit_should_fail(
		SELINUX_LABEL_VIEW_KUNIT_FAULT_ALLOC, 1)))
		view = NULL;
	else
		view = kzalloc(bytes, gfp);
	if (!view) {
		selinux_resource_release(resources, SELINUX_RESOURCE_VIEW, 1,
					 bytes);
		selinux_resource_account_put(resources);
		return ERR_PTR(-ENOMEM);
	}

	id = selinux_label_view_next_id();
	if (unlikely(!id)) {
		kfree(view);
		selinux_resource_release(resources, SELINUX_RESOURCE_VIEW, 1,
					 bytes);
		selinux_resource_account_put(resources);
		return ERR_PTR(-EOVERFLOW);
	}

	refcount_set(&view->refs, 1);
	view->id = id;
	view->generation = 1;
	if (origin_domain == outer_domain)
		view->flags = SELINUX_LABEL_VIEW_IDENTITY;
	if (!origin_domain)
		view->flags |= SELINUX_LABEL_VIEW_ORIGIN_UNRESOLVED;
	view->owner_userns = get_user_ns(owner_userns);
	view->resources = resources;
	view->charged_bytes = bytes;
	view->origin_domain = selinux_label_domain_get(origin_domain);
	view->outer_domain = selinux_label_domain_get(outer_domain);

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!origin_domain)
		return view;
	/* Views are defined only between domains in one ancestry chain. */
	if (!selinux_label_domain_is_ancestor(origin_domain, outer_domain) &&
	    !selinux_label_domain_is_ancestor(outer_domain, origin_domain))
		goto err_view;

	view->map_count = deepest->depth;
	for (cursor = deepest; cursor->parent; cursor = cursor->parent) {
		struct selinux_label_map *map =
			selinux_label_domain_get_map(cursor);

		/* Pairs with seal's release before snapshotting this map. */
		if (!map || !smp_load_acquire(&map->sealed) ||
		    map->child_domain_id != cursor->id ||
		    map->parent != cursor->parent) {
			selinux_label_map_put(map);
			goto err_view;
		}
		view->maps[cursor->depth - 1] = map;
		acquired++;
		if (unlikely(selinux_label_view_kunit_should_fail(
			SELINUX_LABEL_VIEW_KUNIT_FAULT_CHAIN_ACQUIRE,
			acquired))) {
			rc = -ENOMEM;
			goto err_view;
		}
	}
#endif
	return view;

#ifdef CONFIG_SECURITY_SELINUX_NS
err_view:
	for (i = 0; i < view->map_count; i++)
		selinux_label_map_put(view->maps[i]);
	selinux_label_domain_put(view->origin_domain);
	selinux_label_domain_put(view->outer_domain);
	put_user_ns(view->owner_userns);
	selinux_resource_release(view->resources, SELINUX_RESOURCE_VIEW, 1,
				 view->charged_bytes);
	selinux_resource_account_put(view->resources);
	kfree(view);
	return ERR_PTR(rc);
#endif
}

const struct selinux_label_view *
selinux_identity_view_alloc(struct user_namespace *owner_userns,
			    struct selinux_label_domain *origin_domain,
			    struct selinux_label_domain *outer_domain)
{
	return selinux_identity_view_alloc_gfp(owner_userns, origin_domain,
					       outer_domain, GFP_KERNEL);
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_label_view_step(const struct selinux_label_view *view,
				   struct selinux_label_ref **current_label,
				   u32 *sid,
				   enum selinux_label_map_direction direction)
{
	const struct selinux_label_domain *domain = (*current_label)->domain;
	struct selinux_label_ref *next_label;
	struct selinux_label_map *map;
	int rc;

	if (direction == SELINUX_LABEL_MAP_CHILD_TO_PARENT) {
		if (!domain->depth)
			return -EINVAL;
		map = view->maps[domain->depth - 1];
	} else {
		if (domain->depth >= view->map_count)
			return -EINVAL;
		map = view->maps[domain->depth];
	}
	if (!map)
		return -EOPNOTSUPP;
	rc = selinux_label_map_resolve(map, direction, *current_label, *sid,
				       sid, &next_label);
	if (rc)
		return rc;
	if ((direction == SELINUX_LABEL_MAP_CHILD_TO_PARENT &&
	     (map->child_domain_id != domain->id ||
	      next_label->domain != domain->parent ||
	      map->parent != next_label->domain)) ||
	    (direction == SELINUX_LABEL_MAP_PARENT_TO_CHILD &&
	     (map->parent != domain || next_label->domain->parent != domain ||
	      map->child_domain_id != next_label->domain->id))) {
		selinux_label_ref_put(next_label);
		return -EIO;
	}
	selinux_label_ref_put(*current_label);
	*current_label = next_label;
	return 0;
}

int selinux_label_view_resolve_chain(const struct selinux_label_view *view,
				     const struct selinux_label_ref *source,
				     u32 source_sid,
				     struct selinux_label_resolution *resolution)
{
	struct selinux_label_ref *canonical, *current_label, *down_label = NULL;
	const struct selinux_label_domain *deepest, *domain, *target_domain;
	u32 sid;
	int rc = 0;

	if (!view || !source || !resolution || !view->outer_domain)
		return -EINVAL;
	deepest = view->outer_domain;
	if (view->origin_domain &&
	    view->origin_domain->depth > view->outer_domain->depth)
		deepest = view->origin_domain;
	if (deepest->depth > SELINUX_LABEL_RESOLUTION_MAX_DEPTH)
		return -EOPNOTSUPP;
	if (deepest->depth > view->map_count)
		return -EOPNOTSUPP;
	/* An exact handle lookup must precede every identity fast path. */
	canonical = global_sid_to_label_ref(source_sid);
	if (IS_ERR(canonical))
		return PTR_ERR(canonical);
	if (canonical != source) {
		selinux_label_ref_put(canonical);
		return -EINVAL;
	}
	memset(resolution, 0, sizeof(*resolution));
	resolution->max_depth = deepest->depth;
	for (domain = deepest; domain; domain = domain->parent)
		resolution->domain_id[domain->depth] = domain->id;
	if ((source->domain->flags & SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) &&
	    source_sid <= SECINITSID_NUM) {
		int depth;

		for (depth = 0; depth <= resolution->max_depth; depth++)
			resolution->sid[depth] = source_sid;
		selinux_label_ref_put(canonical);
		return 0;
	}
	if (!view->origin_domain) {
		selinux_label_ref_put(canonical);
		return -EINVAL;
	}
	if (source->domain == view->origin_domain)
		target_domain = view->outer_domain;
	else if (source->domain == view->outer_domain)
		target_domain = view->origin_domain;
	else {
		selinux_label_ref_put(canonical);
		return -EINVAL;
	}
	if (!selinux_label_domain_is_ancestor(source->domain,
					      target_domain) &&
	    !selinux_label_domain_is_ancestor(target_domain,
					      source->domain)) {
		selinux_label_ref_put(canonical);
		return -EOPNOTSUPP;
	}
	if (view->origin_domain->depth > view->map_count) {
		selinux_label_ref_put(canonical);
		return -EOPNOTSUPP;
	}

	current_label = canonical;
	sid = source_sid;
	if (source->domain->depth <= resolution->max_depth)
		resolution->sid[source->domain->depth] = sid;
	if (selinux_label_domain_is_ancestor(source->domain,
					     target_domain) &&
	    source->domain != target_domain)
		down_label = selinux_label_ref_get(canonical);

	while (!rc && current_label->domain->parent) {
		rc = selinux_label_view_step(view, &current_label, &sid,
					     SELINUX_LABEL_MAP_CHILD_TO_PARENT);
		if (!rc && current_label->domain->depth <= resolution->max_depth)
			resolution->sid[current_label->domain->depth] = sid;
	}
	selinux_label_ref_put(current_label);
	if (rc)
		goto out_down;

	current_label = down_label;
	down_label = NULL;
	sid = source_sid;
	while (!rc && current_label &&
	       current_label->domain != target_domain) {
		rc = selinux_label_view_step(view, &current_label, &sid,
					     SELINUX_LABEL_MAP_PARENT_TO_CHILD);
		if (!rc)
			resolution->sid[current_label->domain->depth] = sid;
	}
	selinux_label_ref_put(current_label);
	return rc;

out_down:
	selinux_label_ref_put(down_label);
	return rc;
}

int selinux_label_view_resolve(const struct selinux_label_view *view,
			       const struct selinux_label_domain *policy_domain,
			       const struct selinux_label_ref *source,
			       u32 source_sid, u32 *resolved_sid)
{
	struct selinux_label_resolution resolution;
	int rc;

	if (!policy_domain || !resolved_sid)
		return -EINVAL;
	rc = selinux_label_view_resolve_chain(view, source, source_sid,
					      &resolution);
	if (rc)
		return rc;
	if (policy_domain->depth > resolution.max_depth ||
	    resolution.domain_id[policy_domain->depth] != policy_domain->id ||
	    !resolution.sid[policy_domain->depth])
		return -EOPNOTSUPP;
	*resolved_sid = resolution.sid[policy_domain->depth];
	return 0;
}
#endif
