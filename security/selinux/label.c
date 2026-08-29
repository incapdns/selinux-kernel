// SPDX-License-Identifier: GPL-2.0-only
/* Stable provenance domains for SELinux labels. */

#include <linux/err.h>
#include <linux/jhash.h>
#include <linux/limits.h>
#include <linux/rcupdate.h>
#include <linux/rhashtable.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/user_namespace.h>
#include <linux/wait.h>

#include "label.h"
#include "resource.h"
#ifdef CONFIG_SECURITY_SELINUX_NS
#include "label_map.h"
#endif

static atomic64_t selinux_label_domain_id = ATOMIC64_INIT(0);
static atomic64_t selinux_label_ref_id = ATOMIC64_INIT(0);
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
static atomic_t selinux_label_domain_kunit_pending = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(selinux_label_domain_kunit_waitq);
#endif

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
static atomic_t selinux_label_kunit_fault =
	ATOMIC_INIT(SELINUX_LABEL_KUNIT_FAULT_NONE);
static struct selinux_label_domain *selinux_label_kunit_fault_domain;

static bool selinux_label_kunit_fault_take(
	struct selinux_label_domain *domain, enum selinux_label_kunit_fault fault)
{
	if (READ_ONCE(selinux_label_kunit_fault_domain) != domain)
		return false;
	return atomic_cmpxchg(&selinux_label_kunit_fault, fault,
			      SELINUX_LABEL_KUNIT_FAULT_NONE) == fault;
}

void selinux_label_kunit_fail_next(struct selinux_label_domain *domain,
				   enum selinux_label_kunit_fault fault)
{
	if (WARN_ON_ONCE((unsigned int)fault >=
			 SELINUX_LABEL_KUNIT_FAULT_MAX))
		fault = SELINUX_LABEL_KUNIT_FAULT_NONE;
	WRITE_ONCE(selinux_label_kunit_fault_domain, domain);
	atomic_set(&selinux_label_kunit_fault, fault);
}
#endif

struct selinux_label_key {
	const char *context;
	u32 context_len;
};

static u32 selinux_label_key_hash(const void *data, u32 len, u32 seed)
{
	const struct selinux_label_key *key = data;

	return jhash(key->context, key->context_len, seed);
}

static u32 selinux_label_obj_hash(const void *data, u32 len, u32 seed)
{
	const struct selinux_label_ref *label = data;

	return jhash(label->context, label->context_len - 1, seed);
}

static int selinux_label_obj_cmp(struct rhashtable_compare_arg *arg,
				 const void *obj)
{
	const struct selinux_label_key *key = arg->key;
	const struct selinux_label_ref *label = obj;

	if (label->context_len != key->context_len + 1)
		return 1;
	return memcmp(label->context, key->context, key->context_len);
}

static const struct rhashtable_params selinux_label_ht_params = {
	.head_offset = offsetof(struct selinux_label_ref, node),
	.hashfn = selinux_label_key_hash,
	.obj_hashfn = selinux_label_obj_hash,
	.obj_cmpfn = selinux_label_obj_cmp,
	.automatic_shrinking = true,
};

static int selinux_label_resource_reserve(
	struct selinux_label_domain *domain, size_t bytes)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (selinux_label_kunit_fault_take(
		    domain, SELINUX_LABEL_KUNIT_FAULT_RESERVE))
		return -EDQUOT;
#endif
	return selinux_resource_reserve(domain->resources,
					SELINUX_RESOURCE_LABEL, 1, bytes);
}

static struct selinux_label_ref *selinux_label_candidate_alloc(
	struct selinux_label_domain *domain, size_t bytes, gfp_t gfp)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (selinux_label_kunit_fault_take(domain,
					   SELINUX_LABEL_KUNIT_FAULT_ALLOC))
		return NULL;
#else
	(void)domain;
#endif
	return kzalloc(bytes, gfp);
}

static struct selinux_label_ref *selinux_label_candidate_insert(
	struct selinux_label_domain *domain, const struct selinux_label_key *key,
	struct selinux_label_ref *candidate)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (selinux_label_kunit_fault_take(
		    domain, SELINUX_LABEL_KUNIT_FAULT_HASH_INSERT))
		return ERR_PTR(-ENOMEM);
#endif
	return rhashtable_lookup_get_insert_key(
		&domain->labels, key, &candidate->node, selinux_label_ht_params);
}

static u64 selinux_label_domain_next_id(void)
{
	s64 old = atomic64_read(&selinux_label_domain_id);

	for (;;) {
		/* ID reuse would turn stale cache entries into valid provenance. */
		if (unlikely(old == S64_MAX))
			return 0;
		if (atomic64_try_cmpxchg(&selinux_label_domain_id, &old, old + 1))
			return old + 1;
	}
}

static u64 selinux_label_ref_next_id(void)
{
	s64 old = atomic64_read(&selinux_label_ref_id);

	for (;;) {
		if (unlikely(old == S64_MAX))
			return 0;
		if (atomic64_try_cmpxchg(&selinux_label_ref_id, &old, old + 1))
			return old + 1;
	}
}

static void selinux_label_domain_free_work(struct work_struct *work)
{
	struct selinux_label_domain *domain =
		container_of(work, struct selinux_label_domain, free_work);
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_label_map *map;
#endif

	WARN_ON(atomic_read(&domain->label_count));
	WARN_ON(atomic_long_read(&domain->label_bytes));
#ifdef CONFIG_SECURITY_SELINUX_NS
	map = rcu_dereference_protected(domain->boundary_map, 1);
	selinux_label_map_put(map);
#endif
	rhashtable_destroy(&domain->labels);
	selinux_label_domain_put(domain->parent);
	put_user_ns(domain->owner_userns);
	selinux_resource_release(domain->resources, SELINUX_RESOURCE_DOMAIN, 1,
				 sizeof(*domain));
	selinux_resource_account_put(domain->resources);
	kfree(domain);
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (atomic_dec_and_test(&selinux_label_domain_kunit_pending))
		wake_up_all(&selinux_label_domain_kunit_waitq);
#endif
}

static void selinux_label_domain_free_rcu(struct rcu_head *rcu)
{
	struct selinux_label_domain *domain =
		container_of(rcu, struct selinux_label_domain, rcu);

	schedule_work(&domain->free_work);
}

struct selinux_label_domain *
selinux_label_domain_alloc(struct user_namespace *owner_userns,
			   struct selinux_label_domain *parent, u32 flags)
{
	struct selinux_label_domain *domain;
	struct selinux_resource_account *resources;
	u64 id;
	int rc;

	if (!owner_userns)
		return ERR_PTR(-EINVAL);
	if (flags & ~SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL)
		return ERR_PTR(-EINVAL);
	if ((flags & SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) && parent)
		return ERR_PTR(-EINVAL);

	resources = selinux_resource_account_get_owner(owner_userns);
	if (IS_ERR(resources))
		return ERR_CAST(resources);
	rc = selinux_resource_reserve(resources, SELINUX_RESOURCE_DOMAIN, 1,
				      sizeof(*domain));
	if (rc) {
		selinux_resource_account_put(resources);
		return ERR_PTR(rc);
	}

	domain = kzalloc_obj(*domain);
	if (!domain)
		goto err_charge;

	id = selinux_label_domain_next_id();
	if (unlikely(!id)) {
		kfree(domain);
		rc = -EOVERFLOW;
		goto err_charge;
	}

	refcount_set(&domain->refs, 1);
	INIT_WORK(&domain->free_work, selinux_label_domain_free_work);
	domain->id = id;
	domain->generation = 1;
	domain->flags = flags;
	if (parent) {
		if (parent->depth == U16_MAX) {
			kfree(domain);
			rc = -EOVERFLOW;
			goto err_charge;
		}
		domain->depth = parent->depth + 1;
	}
	domain->owner_userns = get_user_ns(owner_userns);
	domain->resources = resources;
	domain->parent = selinux_label_domain_get(parent);
#ifdef CONFIG_SECURITY_SELINUX_NS
	mutex_init(&domain->map_lock);
#endif
	atomic_set(&domain->label_count, 0);
	atomic_long_set(&domain->label_bytes, 0);
	rc = rhashtable_init(&domain->labels, &selinux_label_ht_params);
	if (rc) {
		selinux_label_domain_put(domain->parent);
		put_user_ns(domain->owner_userns);
		kfree(domain);
		goto err_charge;
	}
	return domain;

err_charge:
	selinux_resource_release(resources, SELINUX_RESOURCE_DOMAIN, 1,
				 sizeof(*domain));
	selinux_resource_account_put(resources);
	return ERR_PTR(rc ?: -ENOMEM);
}

struct selinux_label_domain *
selinux_label_domain_get(struct selinux_label_domain *domain)
{
	if (domain)
		refcount_inc(&domain->refs);
	return domain;
}

void selinux_label_domain_put(struct selinux_label_domain *domain)
{
	if (domain && refcount_dec_and_test(&domain->refs)) {
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
		atomic_inc(&selinux_label_domain_kunit_pending);
#endif
		call_rcu(&domain->rcu, selinux_label_domain_free_rcu);
	}
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
void selinux_label_domain_kunit_drain(void)
{
	/*
	 * RCU callbacks queued before this call may perform the last domain put
	 * and enqueue another RCU callback plus free work.  The pending counter is
	 * incremented synchronously at that last put, so waiting for zero after
	 * the barrier covers the complete domain RCU -> workqueue chain without
	 * flushing unrelated workqueues.
	 */
	rcu_barrier();
	wait_event(selinux_label_domain_kunit_waitq,
		   atomic_read(&selinux_label_domain_kunit_pending) == 0);
}
#endif

static int selinux_label_charge(struct selinux_label_domain *domain,
				long bytes)
{
	long used = atomic_long_read(&domain->label_bytes);

	if (atomic_inc_return(&domain->label_count) >
	    CONFIG_SECURITY_SELINUX_LABELS_PER_DOMAIN) {
		atomic_dec(&domain->label_count);
		return -EDQUOT;
	}

	for (;;) {
		if (bytes > CONFIG_SECURITY_SELINUX_LABEL_BYTES_PER_DOMAIN - used) {
			atomic_dec(&domain->label_count);
			return -EDQUOT;
		}
		if (atomic_long_try_cmpxchg(&domain->label_bytes, &used,
					    used + bytes))
			return 0;
	}
}

static void selinux_label_uncharge(struct selinux_label_domain *domain,
				   long bytes)
{
	atomic_long_sub(bytes, &domain->label_bytes);
	atomic_dec(&domain->label_count);
}

static void selinux_label_ref_free(struct rcu_head *rcu)
{
	struct selinux_label_ref *label =
		container_of(rcu, struct selinux_label_ref, rcu);

	kfree(label);
}

struct selinux_label_ref *
selinux_label_ref_intern(struct selinux_label_domain *domain,
			 const char *context, u32 context_len, gfp_t gfp)
{
	struct selinux_label_ref *candidate, *existing;
	struct selinux_label_key key;
	size_t string_len, bytes;
	u32 canonical_len;
	u64 id;
	int rc;

	if (!domain || !context || !context_len)
		return ERR_PTR(-EINVAL);

	string_len = strnlen(context, context_len);
	if (string_len < context_len && string_len != context_len - 1)
		return ERR_PTR(-EINVAL);
	if (string_len == U32_MAX)
		return ERR_PTR(-EOVERFLOW);
	canonical_len = string_len + 1;
	bytes = struct_size(candidate, context, canonical_len);
	if (bytes > LONG_MAX)
		return ERR_PTR(-EOVERFLOW);

retry:
	key.context = context;
	key.context_len = string_len;
	rcu_read_lock();
	existing = rhashtable_lookup(&domain->labels, &key,
				     selinux_label_ht_params);
	if (existing && refcount_inc_not_zero(&existing->refs)) {
		rcu_read_unlock();
		return existing;
	}
	rcu_read_unlock();

	rc = selinux_label_charge(domain, bytes);
	if (rc)
		return ERR_PTR(rc);
	rc = selinux_label_resource_reserve(domain, bytes);
	if (rc) {
		selinux_label_uncharge(domain, bytes);
		return ERR_PTR(rc);
	}
	candidate = selinux_label_candidate_alloc(domain, bytes, gfp);
	if (!candidate) {
		selinux_resource_release(domain->resources,
					 SELINUX_RESOURCE_LABEL, 1, bytes);
		selinux_label_uncharge(domain, bytes);
		return ERR_PTR(-ENOMEM);
	}
	id = selinux_label_ref_next_id();
	if (unlikely(!id)) {
		kfree(candidate);
		selinux_resource_release(domain->resources,
					 SELINUX_RESOURCE_LABEL, 1, bytes);
		selinux_label_uncharge(domain, bytes);
		return ERR_PTR(-EOVERFLOW);
	}

	refcount_set(&candidate->refs, 1);
	candidate->id = id;
	candidate->generation = 1;
	candidate->domain = selinux_label_domain_get(domain);
	candidate->context_len = canonical_len;
	memcpy(candidate->context, context, string_len);
	candidate->context[string_len] = '\0';
	key.context = candidate->context;
	key.context_len = candidate->context_len - 1;

	rcu_read_lock();
	existing = selinux_label_candidate_insert(domain, &key, candidate);
	if (existing && !IS_ERR(existing) &&
	    !refcount_inc_not_zero(&existing->refs)) {
		rcu_read_unlock();
		selinux_label_domain_put(candidate->domain);
		kfree(candidate);
		selinux_resource_release(domain->resources,
					 SELINUX_RESOURCE_LABEL, 1, bytes);
		selinux_label_uncharge(domain, bytes);
		if (gfpflags_allow_blocking(gfp))
			cond_resched();
		else
			cpu_relax();
		goto retry;
	}
	rcu_read_unlock();
	if (IS_ERR(existing)) {
		rc = PTR_ERR(existing);
		selinux_label_domain_put(candidate->domain);
		kfree(candidate);
		selinux_resource_release(domain->resources,
					 SELINUX_RESOURCE_LABEL, 1, bytes);
		selinux_label_uncharge(domain, bytes);
		return ERR_PTR(rc);
	}
	if (existing) {
		selinux_label_domain_put(candidate->domain);
		kfree(candidate);
		selinux_resource_release(domain->resources,
					 SELINUX_RESOURCE_LABEL, 1, bytes);
		selinux_label_uncharge(domain, bytes);
		return existing;
	}

	return candidate;
}

struct selinux_label_ref *
selinux_label_ref_get(struct selinux_label_ref *label)
{
	if (label)
		refcount_inc(&label->refs);
	return label;
}

struct selinux_label_ref *
selinux_label_ref_get_rcu(struct selinux_label_ref __rcu * const *labelp)
{
	struct selinux_label_ref *label;

	rcu_read_lock();
	label = rcu_dereference(*labelp);
	if (label && !refcount_inc_not_zero(&label->refs))
		label = NULL;
	rcu_read_unlock();
	return label;
}

void selinux_label_ref_put(struct selinux_label_ref *label)
{
	struct selinux_label_domain *domain;
	long bytes;
	int rc;

	if (!label || !refcount_dec_and_test(&label->refs))
		return;

	domain = label->domain;
	bytes = struct_size(label, context, label->context_len);
	rc = rhashtable_remove_fast(&domain->labels, &label->node,
				    selinux_label_ht_params);
	if (unlikely(rc && rc != -ENOENT)) {
		/*
		 * Removal did not prove absence.  Keep a permanent quarantine
		 * reference so a surviving table link can never become a UAF or
		 * make interning spin forever on an unacquirable zero-ref object.
		 */
		refcount_set(&label->refs, 1);
		WARN_ON_ONCE(rc);
		return;
	}
	/* -ENOENT guarantees the object is absent from every table. */
	WARN_ON_ONCE(rc);
	selinux_label_uncharge(domain, bytes);
	selinux_resource_release(domain->resources, SELINUX_RESOURCE_LABEL, 1,
				 bytes);
	call_rcu(&label->rcu, selinux_label_ref_free);
	selinux_label_domain_put(domain);
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
bool selinux_label_kunit_context_published(
	struct selinux_label_domain *domain, const char *context, u32 context_len)
{
	struct selinux_label_key key;
	struct selinux_label_ref *label;
	size_t string_len;

	if (!domain || !context || !context_len)
		return false;
	string_len = strnlen(context, context_len);
	if (string_len < context_len && string_len != context_len - 1)
		return false;
	key.context = context;
	key.context_len = string_len;
	rcu_read_lock();
	label = rhashtable_lookup(&domain->labels, &key,
				  selinux_label_ht_params);
	rcu_read_unlock();
	return label != NULL;
}
#endif
