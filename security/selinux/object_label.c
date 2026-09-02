// SPDX-License-Identifier: GPL-2.0-only
/* Policy-local labels keyed by stable SELinux object identities. */

#include <linux/err.h>
#include <linux/cred.h>
#include <linux/rcupdate.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "object_label.h"
#include "namespace.h"
#include "resource.h"
#include "security.h"

struct selinux_object_label_table {
	struct rhashtable labels;
	struct selinux_resource_account *resources;
	bool dying;
};

struct selinux_object_label_entry {
	u64 object_id;
	struct rhash_head node;
	struct list_head object_node;
	struct selinux_object_label_table *table;
	struct selinux_resource_account *resources;
	struct selinux_object_label_value value;
	struct rcu_head rcu;
};

static atomic64_t selinux_object_identity_id = ATOMIC64_INIT(0);
static DEFINE_SPINLOCK(selinux_object_labels_lock);

static const struct rhashtable_params selinux_object_label_ht_params = {
	.key_len = sizeof_field(struct selinux_object_label_entry, object_id),
	.key_offset = offsetof(struct selinux_object_label_entry, object_id),
	.head_offset = offsetof(struct selinux_object_label_entry, node),
	.automatic_shrinking = true,
};

static u64 selinux_object_identity_next_id(void)
{
	s64 old = atomic64_read(&selinux_object_identity_id);

	for (;;) {
		if (unlikely(old == S64_MAX))
			return 0;
		if (atomic64_try_cmpxchg(&selinux_object_identity_id, &old,
					 old + 1))
			return old + 1;
	}
}

static void selinux_object_label_entry_free(struct rcu_head *rcu)
{
	struct selinux_object_label_entry *entry = container_of(
		rcu, struct selinux_object_label_entry, rcu);

	selinux_resource_release(entry->resources,
				 SELINUX_RESOURCE_OBJECT_LABEL, 1,
				 sizeof(*entry));
	selinux_resource_account_put(entry->resources);
	kfree(entry);
}

static void selinux_object_label_entry_retire(
	struct selinux_object_label_entry *entry)
{
	call_rcu(&entry->rcu, selinux_object_label_entry_free);
}

int selinux_object_label_table_init(struct selinux_state *state)
{
	struct selinux_object_label_table *table;
	struct selinux_resource_account *resources;
	int rc;

	if (!state || !state->resources || state->object_labels)
		return -EINVAL;
	resources = selinux_resource_account_get(state->resources);
	if (!resources)
		return -EOPNOTSUPP;
	rc = selinux_resource_reserve(
		resources, SELINUX_RESOURCE_OBJECT_LABEL_TABLE, 1,
		sizeof(*table));
	if (rc)
		goto err_resources;
	table = kzalloc_obj(*table, GFP_KERNEL_ACCOUNT);
	if (!table) {
		rc = -ENOMEM;
		goto err_charge;
	}
	table->resources = resources;
	rc = rhashtable_init(&table->labels,
			     &selinux_object_label_ht_params);
	if (rc)
		goto err_table;
	state->object_labels = table;
	return 0;

err_table:
	kfree(table);
err_charge:
	selinux_resource_release(resources,
				 SELINUX_RESOURCE_OBJECT_LABEL_TABLE, 1,
				 sizeof(*table));
err_resources:
	selinux_resource_account_put(resources);
	return rc;
}

void selinux_object_label_table_destroy(struct selinux_state *state)
{
	struct selinux_object_label_table *table;
	struct selinux_object_label_entry *entry;
	struct rhashtable_iter iter;
	unsigned long flags;

	if (!state)
		return;
	table = state->object_labels;
	if (!table)
		return;

	spin_lock_irqsave(&selinux_object_labels_lock, flags);
	table->dying = true;
	WRITE_ONCE(state->object_labels, NULL);
	spin_unlock_irqrestore(&selinux_object_labels_lock, flags);

	rhashtable_walk_enter(&table->labels, &iter);
	rhashtable_walk_start(&iter);
	for (;;) {
		entry = rhashtable_walk_next(&iter);
		if (IS_ERR(entry)) {
			if (PTR_ERR(entry) == -EAGAIN)
				continue;
			break;
		}
		if (!entry)
			break;
		spin_lock_irqsave(&selinux_object_labels_lock, flags);
		if (rhashtable_remove_fast(&table->labels, &entry->node,
					   selinux_object_label_ht_params)) {
			spin_unlock_irqrestore(&selinux_object_labels_lock,
					       flags);
			continue;
		}
		list_del_init(&entry->object_node);
		spin_unlock_irqrestore(&selinux_object_labels_lock, flags);
		selinux_object_label_entry_retire(entry);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	synchronize_rcu();
	rhashtable_destroy(&table->labels);
	selinux_resource_release(table->resources,
				 SELINUX_RESOURCE_OBJECT_LABEL_TABLE, 1,
				 sizeof(*table));
	selinux_resource_account_put(table->resources);
	kfree(table);
}

static void selinux_object_identity_free(struct rcu_head *rcu)
{
	struct selinux_object_identity *object = container_of(
		rcu, struct selinux_object_identity, rcu);

	selinux_resource_release(object->resources,
				 SELINUX_RESOURCE_OBJECT_IDENTITY, 1,
				 sizeof(*object));
	selinux_resource_account_put(object->resources);
	kfree(object);
}

struct selinux_object_identity *
selinux_object_identity_alloc(struct selinux_state *owner, gfp_t gfp)
{
	struct selinux_object_identity *object;
	struct selinux_resource_account *resources;
	u64 id;
	int rc;

	if (!owner || !owner->resources)
		return ERR_PTR(-EINVAL);
	resources = selinux_resource_account_get(owner->resources);
	if (!resources)
		return ERR_PTR(-EOPNOTSUPP);
	rc = selinux_resource_reserve(
		resources, SELINUX_RESOURCE_OBJECT_IDENTITY, 1,
		sizeof(*object));
	if (rc)
		goto err_resources;
	object = kzalloc_obj(*object, gfp);
	if (!object) {
		rc = -ENOMEM;
		goto err_charge;
	}
	id = selinux_object_identity_next_id();
	if (!id) {
		kfree(object);
		rc = -EOVERFLOW;
		goto err_charge;
	}
	refcount_set(&object->refs, 1);
	object->id = id;
	atomic64_set(&object->generation, 2);
	INIT_LIST_HEAD(&object->entries);
	object->resources = resources;
	return object;

err_charge:
	selinux_resource_release(resources,
				 SELINUX_RESOURCE_OBJECT_IDENTITY, 1,
				 sizeof(*object));
err_resources:
	selinux_resource_account_put(resources);
	return ERR_PTR(rc);
}

struct selinux_object_identity *
selinux_object_identity_alloc_from_cred(const struct cred *cred, u16 sclass,
					 enum selinux_label_source source,
					 gfp_t gfp)
{
	const struct cred *level_cred = cred;
	struct selinux_object_identity *object;
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *state;
	u16 count = 0;
	int rc;

	if (!cred || !sclass)
		return ERR_PTR(-EINVAL);
	state = cred_selinux_state(cred);
	object = selinux_object_identity_alloc(state, gfp);
	if (IS_ERR(object))
		return object;

	while (state) {
		const struct cred_security_struct *security;

		if (!level_cred || count >= ARRAY_SIZE(states)) {
			rc = -ESTALE;
			goto err_object;
		}
		security = selinux_cred(level_cred);
		if (security->state != state) {
			rc = -ESTALE;
			goto err_object;
		}
		states[count] = state;
		values[count] = (struct selinux_object_label_value) {
			.sid = security->sid,
			.sclass = sclass,
			.source = source,
		};
		count++;
		level_cred = security->parent_cred;
		state = state->parent;
	}
	if (level_cred) {
		rc = -ESTALE;
		goto err_object;
	}
	rc = selinux_object_labels_set_chain(
		object,
		states,
		values,
		count,
		gfp);
	if (rc)
		goto err_object;
	return object;

err_object:
	selinux_object_identity_put(object);
	return ERR_PTR(rc);
}

struct selinux_object_identity *
selinux_object_identity_alloc_initial(struct selinux_state *leaf, u32 sid,
				      u16 sclass,
				      enum selinux_label_source source,
				      gfp_t gfp)
{
	struct selinux_object_identity *object;
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *state;
	u16 count = 0;
	int rc;

	if (!leaf || !sid || !sclass)
		return ERR_PTR(-EINVAL);
	object = selinux_object_identity_alloc(leaf, gfp);
	if (IS_ERR(object))
		return object;

	for (state = leaf; state; state = state->parent) {
		if (count >= ARRAY_SIZE(states)) {
			rc = -E2BIG;
			goto err_object;
		}
		states[count] = state;
		values[count] = (struct selinux_object_label_value) {
			.sid = sid,
			.sclass = sclass,
			.source = source,
		};
		count++;
	}
	rc = selinux_object_labels_set_chain(
		object,
		states,
		values,
		count,
		gfp);
	if (rc)
		goto err_object;
	return object;

err_object:
	selinux_object_identity_put(object);
	return ERR_PTR(rc);
}

struct selinux_object_identity *
selinux_object_identity_clone_for_state(
	const struct selinux_object_identity *source,
	struct selinux_state *leaf,
	gfp_t gfp)
{
	struct selinux_object_identity *object;
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *state;
	u16 count = 0;
	int rc;

	if (!source || !leaf)
		return ERR_PTR(-EINVAL);
	object = selinux_object_identity_alloc(leaf, gfp);
	if (IS_ERR(object))
		return object;

	for (state = leaf; state; state = state->parent) {
		if (count >= ARRAY_SIZE(states)) {
			rc = -E2BIG;
			goto err_object;
		}
		states[count] = state;
		rc = selinux_object_label_get(state, source, &values[count]);
		if (rc) {
			if (rc == -ENOENT)
				rc = -ESTALE;
			goto err_object;
		}
		count++;
	}
	rc = selinux_object_labels_set_chain(
		object,
		states,
		values,
		count,
		gfp);
	if (rc)
		goto err_object;
	return object;

err_object:
	selinux_object_identity_put(object);
	return ERR_PTR(rc);
}

int selinux_object_label_copy_for_state_chain(
	struct selinux_object_identity *destination,
	const struct selinux_object_identity *source,
	struct selinux_state *leaf,
	u16 fallback_sclass,
	gfp_t gfp)
{
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *state;
	u16 count = 0;

	if (!destination || !source || !leaf || !fallback_sclass)
		return -EINVAL;
	for (state = leaf; state; state = state->parent) {
		int rc;

		if (count >= ARRAY_SIZE(states))
			return -E2BIG;
		states[count] = state;
		rc = selinux_object_label_get(state, source, &values[count]);
		if (rc == -ENOENT) {
			values[count] = (struct selinux_object_label_value) {
				.sid = SECINITSID_UNLABELED,
				.sclass = fallback_sclass,
				.source = SELINUX_LABEL_SOURCE_UNSPECIFIED,
			};
		} else if (rc) {
			return rc;
		}
		count++;
	}
	return selinux_object_labels_set_chain(
		destination,
		states,
		values,
		count,
		gfp);
}

struct selinux_object_identity *
selinux_object_identity_get(struct selinux_object_identity *object)
{
	if (object)
		refcount_inc(&object->refs);
	return object;
}

void selinux_object_identity_put(struct selinux_object_identity *object)
{
	struct selinux_object_label_entry *entry, *next;
	unsigned long flags;

	if (!object || !refcount_dec_and_test(&object->refs))
		return;
	spin_lock_irqsave(&selinux_object_labels_lock, flags);
	list_for_each_entry_safe(entry, next, &object->entries, object_node) {
		if (!entry->table->dying)
			WARN_ON_ONCE(rhashtable_remove_fast(
				&entry->table->labels, &entry->node,
				selinux_object_label_ht_params));
		list_del_init(&entry->object_node);
		selinux_object_label_entry_retire(entry);
	}
	spin_unlock_irqrestore(&selinux_object_labels_lock, flags);
	call_rcu(&object->rcu, selinux_object_identity_free);
}

u64 selinux_object_identity_generation(
	const struct selinux_object_identity *object)
{
	s64 generation;

	if (!object)
		return 0;
	generation = atomic64_read_acquire(&object->generation);
	return generation > 0 && !(generation & 1) ? generation : 0;
}

static void selinux_object_label_entry_discard(
	struct selinux_object_label_entry *entry)
{
	selinux_resource_release(entry->resources,
				 SELINUX_RESOURCE_OBJECT_LABEL, 1,
				 sizeof(*entry));
	selinux_resource_account_put(entry->resources);
	kfree(entry);
}

struct selinux_object_label_transaction_entry {
	struct selinux_object_label_entry *new;
	struct selinux_object_label_entry *old;
	bool published;
	bool replaced;
};

struct selinux_object_label_transaction_object {
	struct selinux_object_identity *object;
	s64 generation;
	u64 expected_generation;
};

static bool selinux_object_label_update_is_duplicate(
	const struct selinux_object_label_update *updates,
	u16 index)
{
	u16 previous;

	for (previous = 0; previous < index; previous++)
		if (updates[previous].state == updates[index].state &&
		    updates[previous].object == updates[index].object)
			return true;
	return false;
}

static int selinux_object_label_transaction_object_add(
	struct selinux_object_label_transaction_object *objects,
	u16 *object_count,
	struct selinux_object_identity *object,
	u64 expected_generation)
{
	u16 index;

	for (index = 0; index < *object_count; index++) {
		if (objects[index].object != object)
			continue;
		if (expected_generation &&
		    objects[index].expected_generation &&
		    expected_generation != objects[index].expected_generation)
			return -EINVAL;
		if (expected_generation)
			objects[index].expected_generation = expected_generation;
		return 0;
	}
	objects[*object_count].object = object;
	objects[*object_count].expected_generation = expected_generation;
	(*object_count)++;
	return 0;
}

int selinux_object_labels_update_transaction_guarded(
	const struct selinux_object_label_update *updates,
	u16 count,
	const struct selinux_object_generation_guard *guards,
	u16 guard_count,
	gfp_t gfp)
{
	struct selinux_object_label_transaction_entry *entries;
	struct selinux_object_label_transaction_object *objects;
	unsigned long flags;
	u16 object_count = 0;
	u16 index;
	int rc = 0;

	if (!updates || !count || (guard_count && !guards))
		return -EINVAL;
	for (index = 0; index < guard_count; index++)
		if (!guards[index].object || !guards[index].generation)
			return -EINVAL;
	entries = kcalloc(count, sizeof(*entries), gfp);
	if (!entries)
		return -ENOMEM;
	objects = kcalloc(count, sizeof(*objects), gfp);
	if (!objects) {
		kfree(entries);
		return -ENOMEM;
	}

	for (index = 0; index < count; index++) {
		struct selinux_object_label_table *table;
		struct selinux_object_label_entry *entry;

		if (!updates[index].state || !updates[index].object ||
		    !updates[index].value.sid ||
		    selinux_object_label_update_is_duplicate(updates, index)) {
			rc = -EINVAL;
			goto out_discard;
		}
		table = READ_ONCE(updates[index].state->object_labels);
		if (!table) {
			rc = -ESHUTDOWN;
			goto out_discard;
		}
		rc = selinux_resource_reserve(
			table->resources,
			SELINUX_RESOURCE_OBJECT_LABEL,
			1,
			sizeof(*entry));
		if (rc)
			goto out_discard;
		entry = kzalloc_obj(*entry, gfp);
		if (!entry) {
			selinux_resource_release(
				table->resources,
				SELINUX_RESOURCE_OBJECT_LABEL,
				1,
				sizeof(*entry));
			rc = -ENOMEM;
			goto out_discard;
		}
		entry->object_id = updates[index].object->id;
		entry->table = table;
		entry->resources =
			selinux_resource_account_get(table->resources);
		entry->value = updates[index].value;
		INIT_LIST_HEAD(&entry->object_node);
		entries[index].new = entry;
		rc = selinux_object_label_transaction_object_add(
			objects,
			&object_count,
			updates[index].object,
			updates[index].expected_generation);
		if (rc)
			goto out_discard;
	}

	spin_lock_irqsave(&selinux_object_labels_lock, flags);
	for (index = 0; index < count; index++) {
		if (entries[index].new->table->dying ||
		    READ_ONCE(updates[index].state->object_labels) !=
			entries[index].new->table) {
			rc = -ESHUTDOWN;
			goto out_unlock;
		}
	}
	for (index = 0; index < guard_count; index++) {
		s64 generation = atomic64_read(
			&guards[index].object->generation);

		if (generation != guards[index].generation) {
			rc = -ESTALE;
			goto out_unlock;
		}
	}
	for (index = 0; index < object_count; index++) {
		s64 generation = atomic64_read(
			&objects[index].object->generation);

		if (generation <= 0 || generation & 1) {
			rc = -ESTALE;
			goto out_unlock;
		}
		if (objects[index].expected_generation &&
		    generation != objects[index].expected_generation) {
			rc = -ESTALE;
			goto out_unlock;
		}
		if (generation >= S64_MAX - 1) {
			rc = -EOVERFLOW;
			goto out_unlock;
		}
		objects[index].generation = generation;
	}
	for (index = 0; index < object_count; index++)
		atomic64_inc(&objects[index].object->generation);

	for (index = 0; index < count; index++) {
		struct selinux_object_label_entry *entry = entries[index].new;
		struct selinux_object_label_entry *old;

		old = rhashtable_lookup_fast(
			&entry->table->labels,
			&entry->object_id,
			selinux_object_label_ht_params);
		entries[index].old = old;
		if (old) {
			rc = rhashtable_replace_fast(
				&entry->table->labels,
				&old->node,
				&entry->node,
				selinux_object_label_ht_params);
			if (rc)
				goto out_rollback;
			list_replace(&old->object_node, &entry->object_node);
			entries[index].replaced = true;
		} else {
			rc = rhashtable_insert_fast(
				&entry->table->labels,
				&entry->node,
				selinux_object_label_ht_params);
			if (rc)
				goto out_rollback;
			list_add_tail(
				&entry->object_node,
				&updates[index].object->entries);
		}
		entries[index].published = true;
	}

	for (index = 0; index < object_count; index++)
		atomic64_inc(&objects[index].object->generation);
	smp_mb__after_atomic();
	spin_unlock_irqrestore(&selinux_object_labels_lock, flags);

	for (index = 0; index < count; index++)
		if (entries[index].old)
			selinux_object_label_entry_retire(entries[index].old);
	kfree(objects);
	kfree(entries);
	return 0;

out_rollback:
	while (index-- > 0) {
		struct selinux_object_label_transaction_entry *transaction =
			&entries[index];

		if (!transaction->published)
			continue;
		if (transaction->replaced) {
			WARN_ON_ONCE(rhashtable_replace_fast(
				&transaction->new->table->labels,
				&transaction->new->node,
				&transaction->old->node,
				selinux_object_label_ht_params));
			list_replace(
				&transaction->new->object_node,
				&transaction->old->object_node);
		} else {
			WARN_ON_ONCE(rhashtable_remove_fast(
				&transaction->new->table->labels,
				&transaction->new->node,
				selinux_object_label_ht_params));
			list_del_init(&transaction->new->object_node);
		}
	}
	for (index = 0; index < object_count; index++)
		atomic64_set(
			&objects[index].object->generation,
			objects[index].generation);
out_unlock:
	spin_unlock_irqrestore(&selinux_object_labels_lock, flags);
out_discard:
	for (index = 0; index < count; index++) {
		if (!entries[index].new)
			continue;
		if (entries[index].published)
			selinux_object_label_entry_retire(entries[index].new);
		else
			selinux_object_label_entry_discard(entries[index].new);
	}
	kfree(objects);
	kfree(entries);
	return rc;
}

int selinux_object_labels_update_transaction(
	const struct selinux_object_label_update *updates,
	u16 count,
	gfp_t gfp)
{
	return selinux_object_labels_update_transaction_guarded(
		updates,
		count,
		NULL,
		0,
		gfp);
}

int selinux_object_labels_set_chain(
	struct selinux_object_identity *object,
	struct selinux_state *const *states,
	const struct selinux_object_label_value *values,
	u16 count,
	gfp_t gfp)
{
	struct selinux_object_label_update *updates;
	u16 index;
	int rc;

	if (!object || !states || !values || !count ||
	    count > SELINUX_NS_MAX_DEPTH + 1)
		return -EINVAL;
	updates = kcalloc(count, sizeof(*updates), gfp);
	if (!updates)
		return -ENOMEM;
	for (index = 0; index < count; index++)
		updates[index] = (struct selinux_object_label_update) {
			.state = states[index],
			.object = object,
			.value = values[index],
		};
	rc = selinux_object_labels_update_transaction(updates, count, gfp);
	kfree(updates);
	return rc;
}

int selinux_object_label_set(struct selinux_state *state,
			     struct selinux_object_identity *object,
			     const struct selinux_object_label_value *value,
			     gfp_t gfp)
{
	return selinux_object_labels_set_chain(
		object,
		&state,
		value,
		1,
		gfp);
}

int selinux_object_label_get(
	const struct selinux_state *state,
	const struct selinux_object_identity *object,
	struct selinux_object_label_value *value)
{
	struct selinux_object_label_table *table;
	struct selinux_object_label_entry *entry;

	if (!state || !object || !value)
		return -EINVAL;
	table = READ_ONCE(state->object_labels);
	if (!table)
		return -ESHUTDOWN;
	rcu_read_lock();
	entry = rhashtable_lookup(&table->labels, &object->id,
				  selinux_object_label_ht_params);
	if (entry)
		*value = entry->value;
	rcu_read_unlock();
	return entry ? 0 : -ENOENT;
}

int selinux_object_label_snapshot(
	const struct selinux_state *state,
	const struct selinux_object_identity *object,
	struct selinux_object_label_value *value,
	u64 *generation)
{
	unsigned int retry;

	if (!state || !object || !value)
		return -EINVAL;
	for (retry = 0; retry < 4; retry++) {
		u64 before = selinux_object_identity_generation(object);
		int rc;

		if (!before)
			continue;
		rc = selinux_object_label_get(state, object, value);
		if (rc)
			return rc;
		if (before != selinux_object_identity_generation(object))
			continue;
		if (generation)
			*generation = before;
		return 0;
	}
	return -ESTALE;
}

void selinux_object_label_get_or_unlabeled(
	const struct selinux_state *state,
	const struct selinux_object_identity *object, u16 sclass,
	struct selinux_object_label_value *value)
{
	if (!selinux_object_label_get(state, object, value))
		return;
	*value = (struct selinux_object_label_value) {
		.sid = SECINITSID_UNLABELED,
		.sclass = sclass,
		.source = SELINUX_LABEL_SOURCE_UNSPECIFIED,
	};
}

void selinux_object_label_get_or_initial(
	const struct selinux_state *state,
	const struct selinux_object_identity *object,
	u32 initial_sid,
	u16 sclass,
	enum selinux_label_source source,
	struct selinux_object_label_value *value)
{
	if (!selinux_object_label_get(state, object, value))
		return;
	*value = (struct selinux_object_label_value) {
		.sid = initial_sid,
		.sclass = sclass,
		.source = source,
	};
}
