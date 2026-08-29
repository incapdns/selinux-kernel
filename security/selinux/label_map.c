// SPDX-License-Identifier: GPL-2.0-only
/* Parent-owned immutable label maps for SELinux namespace boundaries. */

#include <linux/err.h>
#include <linux/hash.h>
#include <linux/limits.h>
#include <linux/slab.h>
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
#include <linux/mutex.h>
#include <linux/sched.h>
#endif

#include "global_sidtab.h"
#include "label_map.h"
#include "resource.h"

static atomic64_t selinux_label_map_id = ATOMIC64_INIT(0);

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
struct selinux_label_map_kunit_fault_state {
	struct task_struct *owner;
	enum selinux_label_map_kunit_fault point;
	unsigned int occurrence;
	bool active;
};

static DEFINE_MUTEX(selinux_label_map_kunit_fault_lock);
static struct selinux_label_map_kunit_fault_state
	selinux_label_map_kunit_fault;

int selinux_label_map_kunit_fault_arm(
	enum selinux_label_map_kunit_fault point, unsigned int occurrence)
{
	if (point <= SELINUX_LABEL_MAP_KUNIT_FAULT_NONE ||
	    point >= SELINUX_LABEL_MAP_KUNIT_FAULT_MAX || !occurrence)
		return -EINVAL;

	mutex_lock(&selinux_label_map_kunit_fault_lock);
	WRITE_ONCE(selinux_label_map_kunit_fault.owner, current);
	WRITE_ONCE(selinux_label_map_kunit_fault.point, point);
	WRITE_ONCE(selinux_label_map_kunit_fault.occurrence, occurrence);
	/* Publish the selector before exposing this task-scoped fault. */
	smp_store_release(&selinux_label_map_kunit_fault.active, true);
	return 0;
}

void selinux_label_map_kunit_fault_disarm(void)
{
	if (WARN_ON_ONCE(READ_ONCE(selinux_label_map_kunit_fault.owner) != current))
		return;
	WRITE_ONCE(selinux_label_map_kunit_fault.active, false);
	WRITE_ONCE(selinux_label_map_kunit_fault.owner, NULL);
	WRITE_ONCE(selinux_label_map_kunit_fault.point,
		   SELINUX_LABEL_MAP_KUNIT_FAULT_NONE);
	WRITE_ONCE(selinux_label_map_kunit_fault.occurrence, 0);
	mutex_unlock(&selinux_label_map_kunit_fault_lock);
}

static bool selinux_label_map_kunit_should_fail(
	enum selinux_label_map_kunit_fault point, unsigned int occurrence)
{
	/* Pairs with arm's release before reading the fault selector. */
	if (!smp_load_acquire(&selinux_label_map_kunit_fault.active) ||
	    READ_ONCE(selinux_label_map_kunit_fault.owner) != current ||
	    READ_ONCE(selinux_label_map_kunit_fault.point) != point ||
	    READ_ONCE(selinux_label_map_kunit_fault.occurrence) != occurrence)
		return false;

	WRITE_ONCE(selinux_label_map_kunit_fault.active, false);
	return true;
}
#else
static inline bool selinux_label_map_kunit_should_fail(
	unsigned int point, unsigned int occurrence)
{
	(void)point;
	(void)occurrence;
	return false;
}
#endif

struct selinux_label_map_key {
	const struct selinux_label_ref *source;
	u32 source_sid;
};

static u32 selinux_label_map_key_hash(const void *data, u32 len, u32 seed)
{
	const struct selinux_label_map_key *key = data;

	return hash_64(key->source->id ^ ((u64)key->source_sid << 32) ^ seed,
		       32);
}

static u32 selinux_label_map_obj_hash(const void *data, u32 len, u32 seed)
{
	const struct selinux_label_map_entry *entry = data;
	const struct selinux_label_map_key key = {
		.source = entry->source,
		.source_sid = entry->source_sid,
	};

	return selinux_label_map_key_hash(&key, len, seed);
}

static int selinux_label_map_obj_cmp(struct rhashtable_compare_arg *arg,
				     const void *obj)
{
	const struct selinux_label_map_key *key = arg->key;
	const struct selinux_label_map_entry *entry = obj;

	return entry->source != key->source ||
	       entry->source_sid != key->source_sid;
}

static const struct rhashtable_params selinux_label_map_ht_params = {
	.head_offset = offsetof(struct selinux_label_map_entry, node),
	.hashfn = selinux_label_map_key_hash,
	.obj_hashfn = selinux_label_map_obj_hash,
	.obj_cmpfn = selinux_label_map_obj_cmp,
	.automatic_shrinking = true,
};

static bool
selinux_label_map_direction_valid(enum selinux_label_map_direction direction)
{
	return (unsigned int)direction < SELINUX_LABEL_MAP_DIRECTIONS;
}

static u64 selinux_label_map_next_id(void)
{
	s64 old = atomic64_read(&selinux_label_map_id);

	for (;;) {
		if (unlikely(old == S64_MAX))
			return 0;
		if (atomic64_try_cmpxchg(&selinux_label_map_id, &old, old + 1))
			return old + 1;
	}
}

static void selinux_label_map_entry_free(void *ptr, void *arg)
{
	struct selinux_label_map_entry *entry = ptr;

	global_sid_handle_put(entry->target_handle);
	global_sid_handle_put(entry->source_handle);
	selinux_label_ref_put(entry->target);
	selinux_label_ref_put(entry->source);
	selinux_resource_release(entry->resources, SELINUX_RESOURCE_MAP_ENTRY, 1,
				 sizeof(*entry));
	kfree(entry);
}

static void selinux_label_map_free_work(struct work_struct *work)
{
	struct selinux_label_map *map =
		container_of(work, struct selinux_label_map, free_work);
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	struct completion *done = READ_ONCE(map->free_done_kunit);
#endif
	int i;

	for (i = 0; i < SELINUX_LABEL_MAP_DIRECTIONS; i++)
		rhashtable_free_and_destroy(&map->direction[i].entries,
					    selinux_label_map_entry_free, NULL);
	selinux_label_domain_put(map->parent);
	selinux_resource_release(map->resources, SELINUX_RESOURCE_MAP, 1,
				 sizeof(*map));
	selinux_resource_account_put(map->resources);
	kfree(map);
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (done)
		complete(done);
#endif
}

static void selinux_label_map_free_rcu(struct rcu_head *rcu)
{
	struct selinux_label_map *map =
		container_of(rcu, struct selinux_label_map, rcu);

	schedule_work(&map->free_work);
}

struct selinux_label_map *
selinux_label_map_alloc(struct selinux_label_domain *parent,
			struct selinux_label_domain *child)
{
	struct selinux_label_map *map;
	u64 id;
	int i, rc;

	if (!parent || !child || child->parent != parent)
		return ERR_PTR(-EINVAL);

	id = selinux_label_map_next_id();
	if (!id)
		return ERR_PTR(-EOVERFLOW);
	rc = selinux_resource_reserve(parent->resources, SELINUX_RESOURCE_MAP, 1,
				      sizeof(*map));
	if (rc)
		return ERR_PTR(rc);
	map = kzalloc_obj(*map);
	if (!map) {
		rc = -ENOMEM;
		goto err_charge;
	}

	refcount_set(&map->refs, 1);
	INIT_WORK(&map->free_work, selinux_label_map_free_work);
	mutex_init(&map->build_lock);
	map->id = id;
	map->parent = selinux_label_domain_get(parent);
	map->resources = selinux_resource_account_get(parent->resources);
	map->child_domain_id = child->id;
	for (i = 0; i < SELINUX_LABEL_MAP_DIRECTIONS; i++) {
		if (unlikely(selinux_label_map_kunit_should_fail(
			SELINUX_LABEL_MAP_KUNIT_FAULT_TABLE_INIT, i + 1))) {
			rc = -ENOMEM;
			goto err_tables;
		}
		rc = rhashtable_init(&map->direction[i].entries,
				     &selinux_label_map_ht_params);
		if (rc)
			goto err_tables;
	}
	return map;

err_tables:
	while (i--)
		rhashtable_destroy(&map->direction[i].entries);
	selinux_label_domain_put(map->parent);
	selinux_resource_account_put(map->resources);
	kfree(map);
err_charge:
	selinux_resource_release(parent->resources, SELINUX_RESOURCE_MAP, 1,
				 sizeof(*map));
	return ERR_PTR(rc);
}

struct selinux_label_map *selinux_label_map_get(struct selinux_label_map *map)
{
	if (map)
		refcount_inc(&map->refs);
	return map;
}

void selinux_label_map_put(struct selinux_label_map *map)
{
	if (map && refcount_dec_and_test(&map->refs))
		call_rcu(&map->rcu, selinux_label_map_free_rcu);
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
void selinux_label_map_kunit_put_and_wait(struct selinux_label_map *map)
{
	DECLARE_COMPLETION_ONSTACK(done);

	if (!map)
		return;
	/* This test-only primitive is valid only for the final owner. */
	if (WARN_ON(refcount_read(&map->refs) != 1)) {
		selinux_label_map_put(map);
		return;
	}
	WRITE_ONCE(map->free_done_kunit, &done);
	selinux_label_map_put(map);
	wait_for_completion(&done);
}

int selinux_label_map_kunit_unpublish(struct selinux_label_domain *child,
				      struct selinux_label_map *map)
{
	struct selinux_label_map *published;

	if (!child || !map)
		return -EINVAL;

	mutex_lock(&child->map_lock);
	published = rcu_dereference_protected(child->boundary_map,
					     lockdep_is_held(&child->map_lock));
	if (published != map) {
		mutex_unlock(&child->map_lock);
		return -ENOENT;
	}
	rcu_assign_pointer(child->boundary_map, NULL);
	mutex_unlock(&child->map_lock);

	/* Drain readers before releasing the boundary's published ownership. */
	synchronize_rcu();
	selinux_label_map_put(map);
	return 0;
}
#endif

static bool selinux_label_map_domains_valid(const struct selinux_label_map *map,
					    enum selinux_label_map_direction direction,
					    const struct selinux_label_ref *source,
					    const struct selinux_label_ref *target)
{
	if (direction == SELINUX_LABEL_MAP_PARENT_TO_CHILD)
		return source->domain == map->parent &&
		       target->domain->id == map->child_domain_id;
	if (direction == SELINUX_LABEL_MAP_CHILD_TO_PARENT)
		return source->domain->id == map->child_domain_id &&
		       target->domain == map->parent;
	return false;
}

static int
selinux_label_map_add_refs(struct selinux_label_map *map,
			   enum selinux_label_map_direction direction,
			   struct selinux_global_sid_handle *source_handle,
			   struct selinux_global_sid_handle *target_handle)
{
	struct selinux_label_map_entry *entry;
	struct selinux_label_map_table *table;
	struct selinux_label_map_key key;
	struct selinux_label_ref *source = NULL, *target = NULL;
	struct selinux_global_sid_handle *entry_source = NULL;
	struct selinux_global_sid_handle *entry_target = NULL;
	u32 source_sid, target_sid;
	int rc;

	if (!map || !source_handle || !target_handle ||
	    !selinux_label_map_direction_valid(direction)) {
		rc = -EINVAL;
		goto out;
	}
	entry_source = global_sid_handle_dup(source_handle);
	if (IS_ERR(entry_source)) {
		rc = PTR_ERR(entry_source);
		entry_source = NULL;
		goto out;
	}
	entry_target = global_sid_handle_dup(target_handle);
	if (IS_ERR(entry_target)) {
		rc = PTR_ERR(entry_target);
		entry_target = NULL;
		goto out;
	}
	source_sid = global_sid_handle_sid(entry_source);
	target_sid = global_sid_handle_sid(entry_target);
	if (!source_sid || !target_sid) {
		rc = -ESTALE;
		goto out;
	}
	source = global_sid_handle_label_get(entry_source);
	target = global_sid_handle_label_get(entry_target);
	if (!source || !target) {
		rc = -ESTALE;
		goto out;
	}
	if (!selinux_label_map_domains_valid(map, direction, source, target)) {
		rc = -EINVAL;
		goto out;
	}

	if (unlikely(selinux_label_map_kunit_should_fail(
		SELINUX_LABEL_MAP_KUNIT_FAULT_ENTRY_RESERVE, 1)))
		rc = -EDQUOT;
	else
		rc = selinux_resource_reserve(map->resources,
					      SELINUX_RESOURCE_MAP_ENTRY, 1,
					      sizeof(*entry));
	if (rc)
		goto out;
	if (unlikely(selinux_label_map_kunit_should_fail(
		SELINUX_LABEL_MAP_KUNIT_FAULT_ENTRY_ALLOC, 1)))
		entry = NULL;
	else
		entry = kzalloc_obj(*entry);
	if (!entry) {
		rc = -ENOMEM;
		selinux_resource_release(map->resources,
					 SELINUX_RESOURCE_MAP_ENTRY, 1,
					 sizeof(*entry));
		goto out;
	}
	entry->source = source;
	entry->source_handle = entry_source;
	entry->source_sid = source_sid;
	entry->target = target;
	entry->target_handle = entry_target;
	entry->resources = map->resources;
	source = NULL;
	target = NULL;
	entry_source = NULL;
	entry_target = NULL;
	table = &map->direction[direction];
	key.source = entry->source;
	key.source_sid = entry->source_sid;

	mutex_lock(&map->build_lock);
	if (map->sealed) {
		rc = -EROFS;
		goto out_unlock;
	}
	if (table->count >= CONFIG_SECURITY_SELINUX_LABELS_PER_DOMAIN) {
		rc = -EDQUOT;
		goto out_unlock;
	}
	if (unlikely(selinux_label_map_kunit_should_fail(
		SELINUX_LABEL_MAP_KUNIT_FAULT_ENTRY_INSERT, 1)))
		rc = -ENOMEM;
	else
		rc = rhashtable_lookup_insert_key(&table->entries, &key,
						  &entry->node,
						  selinux_label_map_ht_params);
	if (!rc)
		table->count++;

out_unlock:
	mutex_unlock(&map->build_lock);
	if (rc)
		selinux_label_map_entry_free(entry, NULL);
out:
	global_sid_handle_put(entry_target);
	global_sid_handle_put(entry_source);
	selinux_label_ref_put(target);
	selinux_label_ref_put(source);
	return rc;
}

int selinux_label_map_add(struct selinux_label_map *map,
			  enum selinux_label_map_direction direction,
			  struct selinux_global_sid_handle *source_handle,
			  struct selinux_global_sid_handle *target_handle)
{
	return selinux_label_map_add_refs(map, direction, source_handle,
					 target_handle);
}

int selinux_label_map_seal(struct selinux_label_map *map,
			   const struct selinux_label_domain *actor)
{
	int rc = 0;

	if (!map || actor != map->parent)
		return -EPERM;
	mutex_lock(&map->build_lock);
	if (map->sealed)
		rc = -EALREADY;
	else
		/* Publish all completed entries before exposing the sealed map. */
		smp_store_release(&map->sealed, true);
	mutex_unlock(&map->build_lock);
	return rc;
}

bool selinux_label_map_complete(struct selinux_label_map *map)
{
	bool complete;

	if (!map)
		return false;
	mutex_lock(&map->build_lock);
	complete = map->direction[SELINUX_LABEL_MAP_PARENT_TO_CHILD].count &&
		   map->direction[SELINUX_LABEL_MAP_CHILD_TO_PARENT].count;
	mutex_unlock(&map->build_lock);
	return complete;
}

int selinux_label_domain_publish_map(struct selinux_label_domain *child,
				     struct selinux_label_map *map,
				     const struct selinux_label_domain *actor)
{
	struct selinux_label_map *old;
	u64 generation, old_generation;
	bool sealed;
	int rc = 0;

	if (!child || !map)
		return -EPERM;
	/* Pairs with seal's release so the published map is fully initialized. */
	sealed = smp_load_acquire(&map->sealed);
	if (map->child_domain_id != child->id || actor != child->parent ||
	    actor != map->parent || !sealed)
		return -EPERM;

	mutex_lock(&child->map_lock);
	old = rcu_dereference_protected(child->boundary_map,
					lockdep_is_held(&child->map_lock));
	if (old == map) {
		rc = -EALREADY;
		goto out_unlock;
	}
	/* A published immutable snapshot may never be recycled at a boundary. */
	if (READ_ONCE(map->generation)) {
		rc = -ESTALE;
		goto out_unlock;
	}
	if (old) {
		old_generation = READ_ONCE(old->generation);
		if (unlikely(!old_generation)) {
			rc = -EIO;
			goto out_unlock;
		}
		if (unlikely(old_generation == U64_MAX)) {
			/* Wrap could validate stale view/cache generations. */
			rc = -EOVERFLOW;
			goto out_unlock;
		}
		generation = old_generation + 1;
	} else {
		generation = 1;
	}
	WRITE_ONCE(map->generation, generation);
	rcu_assign_pointer(child->boundary_map, selinux_label_map_get(map));

out_unlock:
	mutex_unlock(&child->map_lock);
	if (!rc)
		selinux_label_map_put(old);
	return rc;
}

struct selinux_label_map *
selinux_label_domain_get_map(const struct selinux_label_domain *child)
{
	struct selinux_label_map *map;

	if (!child)
		return NULL;
	rcu_read_lock();
	map = rcu_dereference(child->boundary_map);
	if (map && !refcount_inc_not_zero(&map->refs))
		map = NULL;
	rcu_read_unlock();
	return map;
}

int selinux_label_map_resolve(struct selinux_label_map *map,
			      enum selinux_label_map_direction direction,
			      const struct selinux_label_ref *source,
			      u32 source_sid,
			      u32 *target_sid,
			      struct selinux_label_ref **target)
{
	const struct selinux_label_map_entry *entry;
	const struct selinux_label_map_key key = {
		.source = (struct selinux_label_ref *)source,
		.source_sid = source_sid,
	};
	struct selinux_label_ref *resolved = NULL;
	bool sealed;
	int rc = -ENOENT;

	if (target)
		*target = NULL;
	if (!map || !source || !source_sid || !target_sid ||
	    !selinux_label_map_direction_valid(direction))
		return -EOPNOTSUPP;
	/* Pairs with seal's release before lockless entry lookup. */
	sealed = smp_load_acquire(&map->sealed);
	if (!sealed)
		return -EOPNOTSUPP;

	rcu_read_lock();
	entry = rhashtable_lookup(&map->direction[direction].entries, &key,
				  selinux_label_map_ht_params);
	if (entry &&
	    global_sid_handle_sid(entry->source_handle) == entry->source_sid &&
	    global_sid_handle_sid(entry->target_handle) &&
	    refcount_inc_not_zero(&entry->target->refs)) {
		resolved = entry->target;
		*target_sid = global_sid_handle_sid(entry->target_handle);
		rc = 0;
	} else if (entry) {
		/* A map entry owns a strong label reference until map teardown. */
		rc = -EIO;
	}
	rcu_read_unlock();
	if (target)
		*target = resolved;
	else
		selinux_label_ref_put(resolved);
	return rc;
}
