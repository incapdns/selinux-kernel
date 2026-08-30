// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/xarray.h>
#include <linux/user_namespace.h>
#include <net/netlabel.h>

#include "global_sidtab.h"
#include "label.h"
#include "label_view.h"
#include "objsec.h"
#include "pathless.h"
#include "resource.h"
#include "sidtab.h"
#include "selinux_ss.h"
#include "audit.h"

struct selinux_global_sid_tombstone {
	u32 sid;
	struct selinux_global_sid_handle __rcu *payload;
};

/*
 * The handle is the reclaimable payload.  Numeric lookup retains only the
 * separately allocated tombstone, so a dead SID can never be rebound while
 * its context, canonical label, domain and translation cache are released.
 */
struct selinux_global_sid_handle {
	refcount_t refs;
	struct selinux_global_sid_tombstone *tombstone;
	struct selinux_label_ref *label;
	struct selinux_resource_account *resources;
	size_t charged_bytes;
	u32 hash;
	u32 local_sid;
	/* Bootstrap SIDs are permanent ABI identities, not migration baselines. */
	bool immortal;
	bool baseline_pinned;
	struct hlist_node reverse_node;
#if CONFIG_SECURITY_SELINUX_SS_SID_CACHE_SIZE > 0
	struct sidtab_ss_sid_cache ss_sid_cache;
#endif
	struct rcu_head rcu;
};

#if CONFIG_SECURITY_SELINUX_SS_SID_CACHE_SIZE > 0
static bool global_sid_cache_matches(
	const struct sidtab_ss_sid_cache_entry *cached, u64 domain_id,
	const struct selinux_policy_snapshot *snapshot)
{
	return cached && cached->domain_id == domain_id &&
	       cached->policy_cookie == snapshot->policy_cookie &&
	       cached->policycaps == snapshot->policycaps &&
	       cached->chain_epoch == snapshot->chain_epoch &&
	       cached->seqno == snapshot->seqno &&
	       cached->initialized == snapshot->initialized &&
	       cached->active == snapshot->active;
}
#endif

static DEFINE_XARRAY_FLAGS(global_sid_by_id, XA_FLAGS_LOCK_IRQ);
static DEFINE_HASHTABLE(global_sid_by_context,
			CONFIG_SECURITY_SELINUX_SIDTAB_HASH_BITS);
static DEFINE_SPINLOCK(global_sid_lock);
static atomic_t global_sid_next = ATOMIC_INIT(SECINITSID_NUM);
static struct selinux_label_domain *kernel_label_domain;

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
/*
 * Faults are one-shot and task-scoped so unrelated producers cannot consume a
 * KUnit injection.  The fixed-size state and each operation remain O(1).
 */
static DEFINE_SPINLOCK(global_sid_fault_lock);
static enum selinux_kunit_global_sid_fault global_sid_fault_armed;
static struct task_struct *global_sid_fault_owner;
static u32 global_sid_fault_sid;

static bool global_sid_fault_should_fail(
	enum selinux_kunit_global_sid_fault fault, u32 sid)
{
	unsigned long flags;
	bool fail = false;

	spin_lock_irqsave(&global_sid_fault_lock, flags);
	if (global_sid_fault_armed == fault &&
	    global_sid_fault_owner == current) {
		global_sid_fault_armed = SELINUX_KUNIT_GLOBAL_SID_FAULT_NONE;
		global_sid_fault_owner = NULL;
		global_sid_fault_sid = sid;
		fail = true;
	}
	spin_unlock_irqrestore(&global_sid_fault_lock, flags);
	return fail;
}

int selinux_kunit_global_sid_fault_arm(
	enum selinux_kunit_global_sid_fault fault)
{
	unsigned long flags;
	int rc = 0;

	if (fault <= SELINUX_KUNIT_GLOBAL_SID_FAULT_NONE ||
	    fault >= SELINUX_KUNIT_GLOBAL_SID_FAULT_COUNT)
		return -EINVAL;

	spin_lock_irqsave(&global_sid_fault_lock, flags);
	if (global_sid_fault_armed != SELINUX_KUNIT_GLOBAL_SID_FAULT_NONE) {
		rc = -EBUSY;
	} else {
		global_sid_fault_sid = 0;
		global_sid_fault_owner = current;
		global_sid_fault_armed = fault;
	}
	spin_unlock_irqrestore(&global_sid_fault_lock, flags);
	return rc;
}

void selinux_kunit_global_sid_fault_reset(void)
{
	unsigned long flags;

	spin_lock_irqsave(&global_sid_fault_lock, flags);
	global_sid_fault_armed = SELINUX_KUNIT_GLOBAL_SID_FAULT_NONE;
	global_sid_fault_owner = NULL;
	global_sid_fault_sid = 0;
	spin_unlock_irqrestore(&global_sid_fault_lock, flags);
}

u32 selinux_kunit_global_sid_fault_last_sid(void)
{
	unsigned long flags;
	u32 sid;

	spin_lock_irqsave(&global_sid_fault_lock, flags);
	sid = global_sid_fault_sid;
	spin_unlock_irqrestore(&global_sid_fault_lock, flags);
	return sid;
}
#else
static bool global_sid_fault_should_fail(int fault, u32 sid)
{
	(void)fault;
	(void)sid;
	return false;
}
#endif

static u32 global_sid_context_hash(const struct selinux_label_ref *label,
				   u32 local_sid)
{
	u32 hash = jhash(label->context, label->context_len - 1, 0);

	return hash ^ hash_64(label->domain->id, 32) ^ hash_32(local_sid, 32);
}

static bool global_sid_context_equal(
	const struct selinux_global_sid_handle *handle,
	const struct selinux_label_ref *label, u32 local_sid)
{
	return handle->local_sid == local_sid &&
	       handle->label->domain == label->domain &&
	       handle->label->context_len == label->context_len &&
	       !memcmp(handle->label->context, label->context,
		       label->context_len);
}

static struct selinux_global_sid_handle *
global_sid_reverse_get(struct selinux_label_ref *label, u32 local_sid, u32 hash)
{
	struct selinux_global_sid_handle *handle;

	rcu_read_lock();
	hash_for_each_possible_rcu(global_sid_by_context, handle, reverse_node,
				   hash) {
		if (handle->hash == hash &&
		    global_sid_context_equal(handle, label, local_sid) &&
		    refcount_inc_not_zero(&handle->refs)) {
			rcu_read_unlock();
			return handle;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static int global_sid_next_id(u32 *sid)
{
	int old = atomic_read(&global_sid_next);

	for (;;) {
		/* This is an issued-ID cap: tombstone churn cannot bypass it. */
		if (old < 0 || old >= CONFIG_SECURITY_SELINUX_RESOURCE_OBJECTS_GLOBAL ||
		    old == INT_MAX)
			return -EDQUOT;
		if (atomic_try_cmpxchg(&global_sid_next, &old, old + 1)) {
			*sid = old + 1;
			return 0;
		}
	}
}

static void global_sid_payload_free_rcu(struct rcu_head *rcu)
{
	struct selinux_global_sid_handle *handle =
		container_of(rcu, struct selinux_global_sid_handle, rcu);
#if CONFIG_SECURITY_SELINUX_SS_SID_CACHE_SIZE > 0
	struct sidtab_ss_sid_cache_entry *cached;
	int i;

	for (i = 0; i < ARRAY_SIZE(handle->ss_sid_cache.slots); i++) {
		cached = rcu_access_pointer(handle->ss_sid_cache.slots[i]);
		kfree(cached);
	}
#endif
	selinux_label_ref_put(handle->label);
	selinux_resource_release(handle->resources,
				 SELINUX_RESOURCE_GLOBAL_SID, 1,
				 handle->charged_bytes);
	selinux_resource_account_put(handle->resources);
	kfree(handle);
}

void global_sid_handle_put(struct selinux_global_sid_handle *handle)
{
	unsigned long flags;

	if (!handle || !refcount_dec_and_test(&handle->refs))
		return;

	spin_lock_irqsave(&global_sid_lock, flags);
	if (!hlist_unhashed(&handle->reverse_node))
		hash_del_rcu(&handle->reverse_node);
	rcu_assign_pointer(handle->tombstone->payload, NULL);
	spin_unlock_irqrestore(&global_sid_lock, flags);
	call_rcu(&handle->rcu, global_sid_payload_free_rcu);
}

struct selinux_global_sid_handle *global_sid_handle_get(u32 sid)
{
	struct selinux_global_sid_tombstone *tombstone;
	struct selinux_global_sid_handle *handle = NULL;

	rcu_read_lock();
	tombstone = xa_load(&global_sid_by_id, sid);
	if (tombstone) {
		handle = rcu_dereference(tombstone->payload);
		if (handle && !refcount_inc_not_zero(&handle->refs))
			handle = NULL;
	}
	rcu_read_unlock();
	return handle ? handle : ERR_PTR(tombstone ? -ESTALE : -EINVAL);
}

struct selinux_global_sid_handle *
global_sid_handle_dup(struct selinux_global_sid_handle *handle)
{
	if (!handle || !refcount_inc_not_zero(&handle->refs))
		return ERR_PTR(-ESTALE);
	return handle;
}

static struct selinux_global_sid_handle *
global_existing_sid_handle(u32 sid, u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	if (!out_sid)
		return ERR_PTR(-EINVAL);
	if (!sid) {
		*out_sid = SECSID_NULL;
		return NULL;
	}
	handle = global_sid_handle_get(sid);
	if (!IS_ERR(handle))
		*out_sid = sid;
	return handle;
}

u32 global_sid_handle_sid(const struct selinux_global_sid_handle *handle)
{
	return handle ? handle->tombstone->sid : SECSID_NULL;
}

struct selinux_label_ref *
global_sid_handle_label_get(const struct selinux_global_sid_handle *handle)
{
	/* The caller's strong handle reference keeps label stable. */
	return handle ? selinux_label_ref_get(handle->label) : NULL;
}

static void global_sid_discard_unpublished(
	struct selinux_global_sid_handle *handle)
{
	/* No RCU reader can own an unpublished candidate. */
	selinux_label_ref_put(handle->label);
	selinux_resource_release(handle->resources,
				 SELINUX_RESOURCE_GLOBAL_SID, 1,
				 handle->charged_bytes);
	selinux_resource_account_put(handle->resources);
	selinux_resource_release_global(1, sizeof(*handle->tombstone));
	kfree(handle->tombstone);
	kfree(handle);
}

static struct selinux_global_sid_handle *
global_sid_payload_alloc(struct selinux_label_ref *label, u32 sid,
			 u32 local_sid, gfp_t gfp)
{
	struct selinux_global_sid_handle *handle;
	struct selinux_global_sid_tombstone *tombstone;
	struct selinux_resource_account *resources;
	size_t bytes;
	int rc;

	bytes = size_add(sizeof(*handle), label->context_len);
	if (bytes == SIZE_MAX)
		return ERR_PTR(-EOVERFLOW);
	resources = selinux_resource_account_get(label->domain->resources);
	if (!resources)
		return ERR_PTR(-EINVAL);
	if (global_sid_fault_should_fail(
		    SELINUX_KUNIT_GLOBAL_SID_FAULT_OWNER_RESERVE, sid)) {
		selinux_resource_account_put(resources);
		return ERR_PTR(-EDQUOT);
	}
	rc = selinux_resource_reserve(resources, SELINUX_RESOURCE_GLOBAL_SID,
				      1, bytes);
	if (rc) {
		selinux_resource_account_put(resources);
		return ERR_PTR(rc);
	}
	/* The permanent tombstone remains globally charged after payload death. */
	if (global_sid_fault_should_fail(
		    SELINUX_KUNIT_GLOBAL_SID_FAULT_TOMBSTONE_RESERVE, sid))
		rc = -EDQUOT;
	else
		rc = selinux_resource_reserve_global(1, sizeof(*tombstone));
	if (rc)
		goto err_charge;
	if (global_sid_fault_should_fail(
		    SELINUX_KUNIT_GLOBAL_SID_FAULT_HANDLE_ALLOC, sid)) {
		rc = -ENOMEM;
		goto err_tombstone_charge;
	}
	handle = kzalloc_obj(*handle, gfp);
	if (!handle) {
		rc = -ENOMEM;
		goto err_tombstone_charge;
	}
	if (global_sid_fault_should_fail(
		    SELINUX_KUNIT_GLOBAL_SID_FAULT_TOMBSTONE_ALLOC, sid)) {
		rc = -ENOMEM;
		goto err_handle;
	}
	tombstone = kzalloc_obj(*tombstone, gfp);
	if (!tombstone) {
		rc = -ENOMEM;
		goto err_handle;
	}

	refcount_set(&handle->refs, 1); /* explicit migration baseline */
	handle->baseline_pinned = true;
	handle->tombstone = tombstone;
	handle->label = label;
	handle->resources = resources;
	handle->charged_bytes = bytes;
	handle->local_sid = local_sid;
	handle->hash = global_sid_context_hash(label, local_sid);
	INIT_HLIST_NODE(&handle->reverse_node);
	tombstone->sid = sid;
	RCU_INIT_POINTER(tombstone->payload, handle);
	return handle;

err_handle:
	kfree(handle);
err_tombstone_charge:
	selinux_resource_release_global(1, sizeof(*tombstone));
err_charge:
	selinux_resource_release(resources, SELINUX_RESOURCE_GLOBAL_SID, 1,
				 bytes);
	selinux_resource_account_put(resources);
	return ERR_PTR(rc);
}

int global_sidtab_init(void)
{
	struct selinux_global_sid_handle *handle;
	struct selinux_label_ref *label;
	unsigned long flags;
	int rc, sid;

	kernel_label_domain = selinux_label_domain_alloc(&init_user_ns, NULL,
							 SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL);
	if (IS_ERR(kernel_label_domain))
		return PTR_ERR(kernel_label_domain);

	for (sid = 1; sid <= SECINITSID_NUM; sid++) {
		const char *str = security_get_initial_sid_context(sid);

		if (!str)
			continue;
		/*
		 * Before the policy is loaded, translate
		 * SECINITSID_INIT to "kernel", because systemd and
		 * libselinux < 2.6 take a getcon_raw() result that is
		 * both non-null and not "kernel" to mean that a policy
		 * is already loaded.
		 */
		if (sid == SECINITSID_INIT)
			str = "kernel";
		label = selinux_label_ref_intern(kernel_label_domain, str,
					 strlen(str) + 1, GFP_KERNEL);
		if (IS_ERR(label)) {
			rc = PTR_ERR(label);
			goto err_domain;
		}
		handle = global_sid_payload_alloc(label, sid, sid, GFP_KERNEL);
		if (IS_ERR(handle)) {
			rc = PTR_ERR(handle);
			selinux_label_ref_put(label);
			goto err_domain;
		}
		/* This reference is permanent and is not a migration baseline. */
		handle->immortal = true;
		handle->baseline_pinned = false;
		rc = xa_err(xa_store_irq(&global_sid_by_id, sid,
					 handle->tombstone, GFP_KERNEL));
		if (rc) {
			global_sid_discard_unpublished(handle);
			goto err_domain;
		}
		spin_lock_irqsave(&global_sid_lock, flags);
		/* Preserve each fixed initial SID even when contexts are aliases. */
		{
			struct selinux_global_sid_handle *alias;
			bool indexed = false;

			hash_for_each_possible(global_sid_by_context, alias,
					       reverse_node, handle->hash) {
				if (alias->hash == handle->hash &&
				    global_sid_context_equal(alias, label, sid)) {
					indexed = true;
					break;
				}
			}
			if (!indexed)
				hash_add_rcu(global_sid_by_context,
					     &handle->reverse_node, handle->hash);
		}
		spin_unlock_irqrestore(&global_sid_lock, flags);
	}

	return 0;

err_domain:
	/* Initialization failure is fatal; published bootstrap entries persist. */
	selinux_label_domain_put(kernel_label_domain);
	kernel_label_domain = NULL;
	return rc;
}

static int global_sid_to_context(u32 sid, const char **scontext, u32 *scontext_len)
{
	struct selinux_global_sid_tombstone *tombstone;
	struct selinux_global_sid_handle *handle;

	/* Returned storage is payload-owned and remains borrowed under RCU. */
	if (scontext)
		RCU_LOCKDEP_WARN(!rcu_read_lock_held(),
				 "global SID context returned without caller RCU");
	rcu_read_lock();
	tombstone = xa_load(&global_sid_by_id, sid);
	handle = tombstone ? rcu_dereference(tombstone->payload) : NULL;
	if (!handle) {
		rcu_read_unlock();
		if (scontext)
			*scontext = NULL;
		*scontext_len = 0;
		return tombstone ? -ESTALE : -EINVAL;
	}
	*scontext_len = handle->label->context_len;
	if (scontext)
		*scontext = handle->label->context;

	rcu_read_unlock();
	return 0;
}

struct selinux_label_ref *global_sid_to_label_ref(u32 sid)
{
	struct selinux_label_ref *label;
	struct selinux_global_sid_handle *handle;
	struct selinux_global_sid_tombstone *tombstone;

	rcu_read_lock();
	tombstone = xa_load(&global_sid_by_id, sid);
	handle = tombstone ? rcu_dereference(tombstone->payload) : NULL;
	if (!handle)
		label = ERR_PTR(tombstone ? -ESTALE : -EINVAL);
	else
		label = selinux_label_ref_get(handle->label);
	rcu_read_unlock();
	return label;
}

static bool global_sid_is_kernel_initial(u32 sid)
{
	struct selinux_global_sid_tombstone *tombstone;
	struct selinux_global_sid_handle *handle;
	bool initial;

	if (!sid || sid > SECINITSID_NUM)
		return false;
	rcu_read_lock();
	tombstone = xa_load(&global_sid_by_id, sid);
	handle = tombstone ? rcu_dereference(tombstone->payload) : NULL;
	initial = handle && handle->label->domain &&
		  (handle->label->domain->flags &
		   SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL);
	rcu_read_unlock();
	return initial;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
u32 selinux_kunit_global_sid_entry_sid(u32 sid)
{
	struct selinux_global_sid_tombstone *tombstone;
	struct selinux_global_sid_handle *handle;
	u32 entry_sid = 0;

	rcu_read_lock();
	tombstone = xa_load(&global_sid_by_id, sid);
	handle = tombstone ? rcu_dereference(tombstone->payload) : NULL;
	if (handle)
		entry_sid = tombstone->sid;
	rcu_read_unlock();
	return entry_sid;
}
#endif

struct selinux_global_sid_handle *
global_context_to_handle(struct selinux_state *state, const char *scontext,
			 u32 scontext_len, u32 local_sid, u32 *out_sid,
			 gfp_t gfp)
{
	struct selinux_global_sid_handle *candidate, *existing;
	struct selinux_label_ref *label;
	unsigned long flags, xa_flags;
	u32 hash, sid;
	int rc;

	if (!scontext || !scontext_len || !out_sid)
		return ERR_PTR(-EINVAL);

	if (!state || !state->label_domain)
		return ERR_PTR(-EINVAL);
	label = selinux_label_ref_intern(state->label_domain, scontext,
					 scontext_len, gfp);
	if (IS_ERR(label))
		return ERR_CAST(label);
	hash = global_sid_context_hash(label, local_sid);
	existing = global_sid_reverse_get(label, local_sid, hash);
	if (existing) {
		*out_sid = global_sid_handle_sid(existing);
		selinux_label_ref_put(label);
		return existing;
	}

	rc = global_sid_next_id(&sid);
	if (rc)
		goto out_label;
	candidate = global_sid_payload_alloc(label, sid, local_sid, gfp);
	if (IS_ERR(candidate)) {
		rc = PTR_ERR(candidate);
		goto out_label;
	}
	/*
	 * Establish the producer's reference before publication.  This is what
	 * removes the future numeric-return -> handle-get reclamation window.
	 */
	refcount_inc(&candidate->refs);

	spin_lock_irqsave(&global_sid_lock, flags);
	hash_for_each_possible(global_sid_by_context, existing, reverse_node,
			       hash) {
		if (existing->hash == hash &&
		    global_sid_context_equal(existing, label, local_sid) &&
		    refcount_inc_not_zero(&existing->refs))
			goto found_locked;
	}
	/*
	 * global_sid_lock is also acquired from RCU callbacks.  Keep the nested
	 * XArray acquisition IRQ-safe without using xa_store_irq(): that helper
	 * would unconditionally re-enable IRQs before global_sid_lock is dropped.
	 */
	if (global_sid_fault_should_fail(
		    SELINUX_KUNIT_GLOBAL_SID_FAULT_XA_STORE, sid)) {
		rc = -ENOMEM;
	} else {
		xa_lock_irqsave(&global_sid_by_id, xa_flags);
		rc = xa_err(__xa_store(&global_sid_by_id, sid,
				       candidate->tombstone, GFP_ATOMIC));
		xa_unlock_irqrestore(&global_sid_by_id, xa_flags);
	}
	if (rc)
		goto fail_locked;
	hash_add_rcu(global_sid_by_context, &candidate->reverse_node, hash);
	spin_unlock_irqrestore(&global_sid_lock, flags);
	*out_sid = sid;
	return candidate;

found_locked:
	spin_unlock_irqrestore(&global_sid_lock, flags);
	*out_sid = global_sid_handle_sid(existing);
	/* Drop the unpublished candidate's pre-established producer reference. */
	refcount_dec(&candidate->refs);
	global_sid_discard_unpublished(candidate);
	return existing;
fail_locked:
	spin_unlock_irqrestore(&global_sid_lock, flags);
	refcount_dec(&candidate->refs);
	global_sid_discard_unpublished(candidate);
	return ERR_PTR(rc);
out_label:
	selinux_label_ref_put(label);
	return ERR_PTR(rc);
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
static int global_context_to_sid(struct selinux_state *state,
				 const char *scontext, u32 scontext_len,
				 u32 local_sid, u32 *out_sid, gfp_t gfp)
{
	struct selinux_global_sid_handle *handle;

	handle = global_context_to_handle(state, scontext, scontext_len,
					  local_sid, out_sid, gfp);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

int selinux_kunit_global_context_to_sid(struct selinux_state *state,
					const char *context, u32 *sid)
{
	if (!state || !context || !sid)
		return -EINVAL;

	return global_context_to_sid(state, context, strlen(context) + 1, 0, sid,
				     GFP_KERNEL);
}

struct selinux_global_sid_handle *
selinux_kunit_global_context_to_handle(struct selinux_state *state,
				       const char *context, u32 *sid)
{
	if (!state || !context || !sid)
		return ERR_PTR(-EINVAL);
	return global_context_to_handle(state, context, strlen(context) + 1, 0,
					sid, GFP_KERNEL);
}

struct selinux_global_sid_handle *
selinux_kunit_global_context_to_handle_local(struct selinux_state *state,
					     const char *context, u32 local_sid,
					     u32 *sid)
{
	if (!state || !context || !local_sid ||
	    local_sid > SECINITSID_NUM || !sid)
		return ERR_PTR(-EINVAL);
	return global_context_to_handle(state, context, strlen(context) + 1,
					local_sid, sid, GFP_KERNEL);
}

int selinux_kunit_global_sid_drop_baseline(u32 sid)
{
	struct selinux_global_sid_handle *handle;
	unsigned long flags;
	bool drop = false;

	handle = global_sid_handle_get(sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	spin_lock_irqsave(&global_sid_lock, flags);
	if (handle->immortal) {
		spin_unlock_irqrestore(&global_sid_lock, flags);
		global_sid_handle_put(handle);
		return -EPERM;
	}
	if (handle->baseline_pinned) {
		handle->baseline_pinned = false;
		drop = true;
	}
	spin_unlock_irqrestore(&global_sid_lock, flags);
	if (drop)
		global_sid_handle_put(handle); /* baseline */
	global_sid_handle_put(handle); /* lookup */
	return drop ? 0 : -EALREADY;
}

bool selinux_kunit_global_sid_live(u32 sid)
{
	struct selinux_global_sid_handle *handle = global_sid_handle_get(sid);

	if (IS_ERR(handle))
		return false;
	global_sid_handle_put(handle);
	return true;
}

bool selinux_kunit_global_sid_cache_matches(
	const struct sidtab_ss_sid_cache_entry *cached, u64 domain_id,
	const struct selinux_policy_snapshot *snapshot)
{
#if CONFIG_SECURITY_SELINUX_SS_SID_CACHE_SIZE > 0
	return cached && snapshot &&
	       global_sid_cache_matches(cached, domain_id, snapshot);
#else
	return false;
#endif
}
#endif

static int map_global_sid_to_ss(struct selinux_state *state, u32 sid,
				u32 *ss_sid, gfp_t gfp)
{
	struct selinux_global_sid_handle *handle;
	struct selinux_policy_snapshot snapshot;
	u64 domain_id;
	int rc = 0;
#if CONFIG_SECURITY_SELINUX_SS_SID_CACHE_SIZE > 0
	struct sidtab_ss_sid_cache_entry *cached, *new_cached, *old_cached;
	struct sidtab_ss_sid_cache *cache;
	unsigned long flags;
	int i;
#endif

	handle = global_sid_handle_get(sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
retry:
	rc = selinux_policy_snapshot_read(state, &snapshot);
	if (rc)
		goto out;
	domain_id = state->label_domain->id;
	/* Only assertions explicitly created as kernel-global are universal. */
	if (sid <= SECINITSID_NUM && handle->label->domain &&
	    (handle->label->domain->flags &
	     SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL)) {
		*ss_sid = sid;
		goto out;
	}
	/* Cross-domain translation requires an explicit sealed boundary map. */
	if (!handle->label->domain ||
	    handle->label->domain != state->label_domain) {
		rc = -EOPNOTSUPP;
		goto out;
	}
#if CONFIG_SECURITY_SELINUX_SS_SID_CACHE_SIZE > 0
	rcu_read_lock();
	cache = &handle->ss_sid_cache;
	for (i = 0; snapshot.chain_epoch && i < ARRAY_SIZE(cache->slots); i++) {
		cached = rcu_dereference(cache->slots[i]);
		if (global_sid_cache_matches(cached, domain_id, &snapshot) &&
		    cached->ss_sid) {
			*ss_sid = cached->ss_sid;
			rcu_read_unlock();
			goto out;
		}
	}
	rcu_read_unlock();
#endif
	rc = selinux_ss_context_to_sid_force(state, handle->label->context,
					     handle->label->context_len,
					     ss_sid, gfp);
	if (rc)
		goto out;
	if (!selinux_policy_snapshot_valid(state, &snapshot))
		goto retry;
#if CONFIG_SECURITY_SELINUX_SS_SID_CACHE_SIZE > 0
	if (!snapshot.chain_epoch)
		goto out;
	new_cached = kmalloc_obj(*new_cached, gfp);
	if (!new_cached)
		goto out;
	new_cached->domain_id = domain_id;
	new_cached->policy_cookie = snapshot.policy_cookie;
	new_cached->policycaps = snapshot.policycaps;
	new_cached->chain_epoch = snapshot.chain_epoch;
	new_cached->seqno = snapshot.seqno;
	new_cached->initialized = snapshot.initialized;
	new_cached->active = snapshot.active;
	new_cached->ss_sid = *ss_sid;

	spin_lock_irqsave(&global_sid_lock, flags);
	if (rcu_access_pointer(handle->tombstone->payload) != handle ||
	    handle->label->domain != state->label_domain ||
	    !selinux_policy_snapshot_valid(state, &snapshot)) {
		spin_unlock_irqrestore(&global_sid_lock, flags);
		kfree(new_cached);
		if (handle->label->domain != state->label_domain) {
			rc = -EOPNOTSUPP;
			goto out;
		}
		goto retry;
	}
	cache = &handle->ss_sid_cache;
	for (i = 0; i < ARRAY_SIZE(cache->slots); i++) {
		cached = rcu_dereference_protected(cache->slots[i], 1);
		if (global_sid_cache_matches(cached, domain_id, &snapshot)) {
			spin_unlock_irqrestore(&global_sid_lock, flags);
			kfree(new_cached);
			goto out;
		}
	}
	i = cache->next++ % ARRAY_SIZE(cache->slots);
	old_cached = rcu_dereference_protected(cache->slots[i], 1);
	rcu_assign_pointer(cache->slots[i], new_cached);
	spin_unlock_irqrestore(&global_sid_lock, flags);
	if (old_cached)
		kfree_rcu(old_cached, rcu);
#endif
out:
	global_sid_handle_put(handle);
	return rc;
}

void global_sidtab_invalidate_state(struct selinux_state *state)
{
	/* Cache entries are weak generation cookies and age out lazily. */
}

struct selinux_global_sid_handle *
map_ss_sid_to_global_handle(struct selinux_state *state, u32 ss_sid,
			    u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;
	const char *scontext;
	u32 scontext_len;
	int rc;

	if (!state || !out_sid)
		return ERR_PTR(-EINVAL);

	rcu_read_lock();
	rc = selinux_ss_sid_to_context_force(state, ss_sid, &scontext,
					     &scontext_len);
	if (rc)
		handle = ERR_PTR(rc);
	else
		handle = global_context_to_handle(
			state, scontext, scontext_len,
			ss_sid <= SECINITSID_NUM ? ss_sid : 0, out_sid,
			GFP_ATOMIC);
	rcu_read_unlock();
	return handle;
}

int security_sid_to_context(struct selinux_state *state, u32 sid,
			    const char **scontext, u32 *scontext_len)
{
	// initial SID contexts have to be obtained from the policy, if initialized
	if (global_sid_is_kernel_initial(sid) && selinux_initialized(state))
		return selinux_ss_sid_to_context(state, sid, scontext, scontext_len);

	return global_sid_to_context(sid, scontext, scontext_len);
}

int security_sid_to_context_valid(struct selinux_state *state, u32 sid,
			    const char **scontext, u32 *scontext_len)
{
	int rc;
	u32 ss_sid;

	// Valid SID contexts have to be obtained from the policy, if initialized
	if (selinux_initialized(state)) {
		rc = map_global_sid_to_ss(state, sid, &ss_sid, GFP_ATOMIC);
		if (rc)
			return rc;
		return selinux_ss_sid_to_context(state, ss_sid, scontext,
						 scontext_len);
	}

	return global_sid_to_context(sid, scontext, scontext_len);
}

int security_sid_to_context_force(struct selinux_state *state, u32 sid,
				  const char **scontext, u32 *scontext_len)
{
	// initial SID contexts have to be obtained from the policy, if initialized
	if (global_sid_is_kernel_initial(sid) && selinux_initialized(state))
		return selinux_ss_sid_to_context_force(state, sid, scontext, scontext_len);

	return global_sid_to_context(sid, scontext, scontext_len);
}

int security_sid_to_context_inval(struct selinux_state *state, u32 sid,
				  const char **scontext, u32 *scontext_len)
{
	int rc;
	u32 ss_sid;

	// TODO Cache invalid bit in global SID table so we do not need
	// to lookup in the per-policy one each time.
	if (selinux_initialized(state)) {
		rc = map_global_sid_to_ss(state, sid, &ss_sid, GFP_ATOMIC);
		if (rc)
			return rc;
		return selinux_ss_sid_to_context_inval(state, ss_sid, scontext,
						       scontext_len);
	}
	return global_sid_to_context(sid, scontext, scontext_len);
}

struct selinux_global_sid_handle *
security_context_to_global_handle(struct selinux_state *state,
				  const char *scontext, u32 scontext_len,
				  u32 *out_sid, gfp_t gfp)
{
	struct selinux_global_sid_handle *handle;
	int rc;
	u32 ss_sid = 0;
	const char *ctx = NULL;

	if (!state || !scontext || !scontext_len || !out_sid)
		return ERR_PTR(-EINVAL);
	if (!selinux_initialized(state)) {
		rc = selinux_ss_context_to_sid(state, scontext, scontext_len,
					       &ss_sid, gfp);
		if (rc)
			return ERR_PTR(rc);
		return global_existing_sid_handle(ss_sid, out_sid);
	}

	/*
	 * Validate and canonicalize the context against the policy.
	 */
	rc = selinux_ss_context_to_sid(state, scontext, scontext_len,
				&ss_sid, gfp);
	if (rc)
		return ERR_PTR(rc);

	rcu_read_lock();
	rc = selinux_ss_sid_to_context(state, ss_sid, &ctx,
				&scontext_len);
	if (rc)
		goto err_unlock;

	scontext = kmemdup(ctx, scontext_len, GFP_ATOMIC);
	if (!scontext) {
		rc = -ENOMEM;
		goto err_unlock;
	}
	rcu_read_unlock();

	handle = global_context_to_handle(
		state, scontext, scontext_len,
		ss_sid && ss_sid <= SECINITSID_NUM ? ss_sid : 0, out_sid, gfp);
	kfree(scontext);
	return handle;
err_unlock:
	rcu_read_unlock();
	return ERR_PTR(rc);
}

int security_context_to_sid(struct selinux_state *state, const char *scontext,
			    u32 scontext_len, u32 *out_sid, gfp_t gfp)
{
	struct selinux_global_sid_handle *handle;

	handle = security_context_to_global_handle(state, scontext,
						   scontext_len, out_sid, gfp);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

int security_context_str_to_sid(struct selinux_state *state,
				const char *scontext, u32 *out_sid, gfp_t gfp)
{
	size_t scontext_len = strlen(scontext) + 1;

	return security_context_to_sid(state, scontext, scontext_len, out_sid,
				       gfp);
}

struct selinux_global_sid_handle *
security_context_to_sid_default_handle(struct selinux_state *state,
				       const char *scontext, u32 scontext_len,
				       u32 *out_sid, u32 def_sid, gfp_t gfp)
{
	struct selinux_global_sid_handle *handle;
	int rc;
	u32 ss_sid = 0;
	const char *ctx = NULL;
	bool alloc = false;

	if (!state || !scontext || !scontext_len || !out_sid)
		return ERR_PTR(-EINVAL);

	/*
	 * If initialized, validate and canonicalize the context against
	 * the policy.
	 */
	if (selinux_initialized(state)) {
		rc = selinux_ss_context_to_sid_default(state, scontext,
						       scontext_len, &ss_sid,
						       def_sid, gfp);
		if (rc)
			return ERR_PTR(rc);

		rcu_read_lock();
		rc = selinux_ss_sid_to_context(state, ss_sid, &ctx,
					       &scontext_len);
		if (rc)
			goto err_unlock;
		scontext = kmemdup(ctx, scontext_len, GFP_ATOMIC);
		if (!scontext) {
			rc = -ENOMEM;
			goto err_unlock;
		}
		alloc = true;
		rcu_read_unlock();
	}

	handle = global_context_to_handle(
		state, scontext, scontext_len,
		ss_sid && ss_sid <= SECINITSID_NUM ? ss_sid : 0, out_sid, gfp);

	if (alloc)
		kfree(scontext);
	return handle;
err_unlock:
	rcu_read_unlock();
	return ERR_PTR(rc);
}

int security_context_to_sid_default(struct selinux_state *state,
				    const char *scontext, u32 scontext_len,
				    u32 *out_sid, u32 def_sid, gfp_t gfp)
{
	struct selinux_global_sid_handle *handle;

	handle = security_context_to_sid_default_handle(
		state, scontext, scontext_len, out_sid, def_sid, gfp);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

struct selinux_global_sid_handle *
security_context_to_sid_force_handle(struct selinux_state *state,
				     const char *scontext, u32 scontext_len,
				     u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;
	int rc;
	u32 ss_sid = 0;
	const char *ctx = NULL;
	bool alloc = false;

	if (!state || !scontext || !scontext_len || !out_sid)
		return ERR_PTR(-EINVAL);

	/*
	 * If initialized, validate and canonicalize the context against
	 * the policy.
	 */
	if (selinux_initialized(state)) {
		rc = selinux_ss_context_to_sid_force(state, scontext,
						     scontext_len, &ss_sid,
						     GFP_KERNEL);
		if (rc)
			return ERR_PTR(rc);

		rcu_read_lock();
		rc = selinux_ss_sid_to_context_force(state, ss_sid, &ctx,
						     &scontext_len);
		if (rc)
			goto err_unlock;
		scontext = kmemdup(ctx, scontext_len, GFP_ATOMIC);
		if (!scontext) {
			rc = -ENOMEM;
			goto err_unlock;
		}
		alloc = true;
		rcu_read_unlock();
	}

	handle = global_context_to_handle(
		state, scontext, scontext_len,
		ss_sid && ss_sid <= SECINITSID_NUM ? ss_sid : 0, out_sid,
		GFP_KERNEL);

	if (alloc)
		kfree(scontext);
	return handle;
err_unlock:
	rcu_read_unlock();
	return ERR_PTR(rc);
}

int security_context_to_sid_force(struct selinux_state *state,
				  const char *scontext, u32 scontext_len,
				  u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_context_to_sid_force_handle(state, scontext,
						      scontext_len, out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

void security_compute_av(struct selinux_state *state, u32 ssid, u32 tsid,
			 u16 tclass, struct av_decision *avd,
			 struct extended_perms *xperms)
{
	u32 ss_ssid, ss_tsid;
	int rc;

	if (!selinux_initialized(state))
		goto allow;

	rc = map_global_sid_to_ss(state, ssid, &ss_ssid, GFP_ATOMIC);
	if (rc)
		goto deny;
	rc = map_global_sid_to_ss(state, tsid, &ss_tsid, GFP_ATOMIC);
	if (rc)
		goto deny;
	selinux_ss_compute_av(state, ss_ssid, ss_tsid, tclass, avd, xperms);
	return;
allow:
	avd->allowed = ~0U;
	goto out;
deny:
	avd->allowed = 0;
out:
	avd->auditallow = 0;
	avd->auditdeny = ~0U;
	avd->seqno = 0;
	avd->flags = 0;
	xperms->len = 0;
}

void security_compute_xperms_decision(struct selinux_state *state, u32 ssid,
				      u32 tsid, u16 tclass, u8 driver,
				      u8 base_perm,
				      struct extended_perms_decision *xpermd)
{
	u32 ss_ssid, ss_tsid;
	int rc;

	if (!selinux_initialized(state))
		goto allow;

	rc = map_global_sid_to_ss(state, ssid, &ss_ssid, GFP_ATOMIC);
	if (rc)
		goto deny;
	rc = map_global_sid_to_ss(state, tsid, &ss_tsid, GFP_ATOMIC);
	if (rc)
		goto deny;
	selinux_ss_compute_xperms_decision(state, ss_ssid, ss_tsid, tclass,
					   driver, base_perm, xpermd);
	return;
allow:
	memset(xpermd->allowed->p, 0xff, sizeof(xpermd->allowed->p));
	goto out;
deny:
	memset(xpermd->allowed->p, 0, sizeof(xpermd->allowed->p));
out:
	xpermd->driver = driver;
	xpermd->used = 0;
	memset(xpermd->auditallow->p, 0, sizeof(xpermd->auditallow->p));
	memset(xpermd->dontaudit->p, 0, sizeof(xpermd->dontaudit->p));
}

struct selinux_global_sid_handle *
security_transition_sid_handle(struct selinux_state *state, u32 ssid,
			       u32 tsid, u16 tclass,
			       const struct qstr *qstr, u32 *out_sid)
{
	u32 ss_ssid, ss_tsid, ss_outsid;
	int rc;

	if (!selinux_initialized(state)) {
		switch (tclass) {
		case SECCLASS_PROCESS:
			return global_existing_sid_handle(ssid, out_sid);
		default:
			return global_existing_sid_handle(tsid, out_sid);
		}
	}

	rc = map_global_sid_to_ss(state, ssid, &ss_ssid, GFP_ATOMIC);
	if (rc)
		return ERR_PTR(rc);
	rc = map_global_sid_to_ss(state, tsid, &ss_tsid, GFP_ATOMIC);
	if (rc)
		return ERR_PTR(rc);
	rc = selinux_ss_transition_sid(state, ss_ssid, ss_tsid, tclass, qstr,
				       &ss_outsid);
	if (rc)
		return ERR_PTR(rc);

	return map_ss_sid_to_global_handle(state, ss_outsid, out_sid);
}

int security_transition_sid(struct selinux_state *state, u32 ssid, u32 tsid,
			    u16 tclass, const struct qstr *qstr, u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_transition_sid_handle(state, ssid, tsid, tclass,
						qstr, out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

struct selinux_global_sid_handle *
security_port_sid_handle(struct selinux_state *state, u8 protocol, u16 port,
			 u32 *out_sid)
{
	u32 ss_outsid;
	int rc;

	if (!selinux_initialized(state))
		return global_existing_sid_handle(SECINITSID_PORT, out_sid);

	rc = selinux_ss_port_sid(state, protocol, port, &ss_outsid);
	if (rc)
		return ERR_PTR(rc);

	return map_ss_sid_to_global_handle(state, ss_outsid, out_sid);
}

int security_port_sid(struct selinux_state *state, u8 protocol, u16 port,
		      u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_port_sid_handle(state, protocol, port, out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

struct selinux_global_sid_handle *
security_ib_pkey_sid_handle(struct selinux_state *state, u64 subnet_prefix,
			   u16 pkey_num, u32 *out_sid)
{
	u32 ss_outsid;
	int rc;

	if (!selinux_initialized(state))
		return global_existing_sid_handle(SECINITSID_UNLABELED, out_sid);

	rc = selinux_ss_ib_pkey_sid(state, subnet_prefix, pkey_num, &ss_outsid);
	if (rc)
		return ERR_PTR(rc);

	return map_ss_sid_to_global_handle(state, ss_outsid, out_sid);
}

int security_ib_pkey_sid(struct selinux_state *state, u64 subnet_prefix,
			 u16 pkey_num, u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_ib_pkey_sid_handle(state, subnet_prefix, pkey_num,
						     out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

struct selinux_global_sid_handle *
security_ib_endport_sid_handle(struct selinux_state *state,
			      const char *dev_name, u8 port_num,
			      u32 *out_sid)
{
	u32 ss_outsid;
	int rc;

	if (!selinux_initialized(state))
		return global_existing_sid_handle(SECINITSID_UNLABELED, out_sid);

	rc = selinux_ss_ib_endport_sid(state, dev_name, port_num, &ss_outsid);
	if (rc)
		return ERR_PTR(rc);

	return map_ss_sid_to_global_handle(state, ss_outsid, out_sid);
}

int security_ib_endport_sid(struct selinux_state *state, const char *dev_name,
			    u8 port_num, u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_ib_endport_sid_handle(state, dev_name, port_num,
						out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

struct selinux_global_sid_handle *
security_netif_sid_handle(struct selinux_state *state, const char *name,
			  u32 *out_sid)
{
	u32 ss_outsid;
	int rc;

	if (!selinux_initialized(state))
		return global_existing_sid_handle(SECINITSID_NETIF, out_sid);

	rc = selinux_ss_netif_sid(state, name, &ss_outsid);
	if (rc)
		return ERR_PTR(rc);

	return map_ss_sid_to_global_handle(state, ss_outsid, out_sid);
}

int security_netif_sid(struct selinux_state *state, const char *name,
		       u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_netif_sid_handle(state, name, out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

struct selinux_global_sid_handle *
security_node_sid_handle(struct selinux_state *state, u16 domain,
			 const void *addr, u32 addrlen, u32 *out_sid)
{
	u32 ss_outsid;
	int rc;

	if (!selinux_initialized(state))
		return global_existing_sid_handle(SECINITSID_NODE, out_sid);

	rc = selinux_ss_node_sid(state, domain, addr, addrlen, &ss_outsid);
	if (rc)
		return ERR_PTR(rc);

	return map_ss_sid_to_global_handle(state, ss_outsid, out_sid);
}

int security_node_sid(struct selinux_state *state, u16 domain, const void *addr,
		      u32 addrlen, u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_node_sid_handle(state, domain, addr, addrlen, out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

int security_validate_transition(struct selinux_state *state, u32 oldsid,
				 u32 newsid, u32 tasksid, u16 tclass)
{
	u32 ss_oldsid, ss_newsid, ss_tasksid;
	int rc;

	if (!selinux_initialized(state))
		return 0;

	rc = map_global_sid_to_ss(state, oldsid, &ss_oldsid, GFP_ATOMIC);
	if (rc)
		return -EINVAL;
	rc = map_global_sid_to_ss(state, newsid, &ss_newsid, GFP_ATOMIC);
	if (rc)
		return -EINVAL;
	rc = map_global_sid_to_ss(state, tasksid, &ss_tasksid, GFP_ATOMIC);
	if (rc)
		return -EINVAL;
	return selinux_ss_validate_transition(state, ss_oldsid, ss_newsid,
					      ss_tasksid, tclass);
}

/*
 * Return structural and snapshot failures as errno.  A completed constraint
 * evaluation returns zero and records both permissive and enforcing denials.
 */
int security_validate_transition_snapshot_noaudit(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, u32 oldsid, u32 newsid,
	u32 tasksid, u16 tclass,
	enum selinux_validatetrans_decision *decision)
{
	u32 ss_oldsid, ss_newsid, ss_tasksid;
	int rc;

	if (WARN_ON_ONCE(!state || !snapshot || !decision))
		return -EINVAL;
	*decision = SELINUX_VALIDATETRANS_ALLOWED;
	if (!selinux_policy_snapshot_valid(state, snapshot))
		return -ESTALE;
	if (!snapshot->initialized)
		return selinux_policy_snapshot_valid(state, snapshot) ? 0 : -ESTALE;

	rc = map_global_sid_to_ss(state, oldsid, &ss_oldsid, GFP_ATOMIC);
	if (!selinux_policy_snapshot_valid(state, snapshot))
		return -ESTALE;
	if (rc)
		return rc;
	rc = map_global_sid_to_ss(state, newsid, &ss_newsid, GFP_ATOMIC);
	if (!selinux_policy_snapshot_valid(state, snapshot))
		return -ESTALE;
	if (rc)
		return rc;
	rc = map_global_sid_to_ss(state, tasksid, &ss_tasksid, GFP_ATOMIC);
	if (!selinux_policy_snapshot_valid(state, snapshot))
		return -ESTALE;
	if (rc)
		return rc;

	rc = selinux_ss_validate_transition_snapshot_noaudit(
		state, snapshot, ss_oldsid, ss_newsid, ss_tasksid, tclass,
		decision);
	if (!selinux_policy_snapshot_valid(state, snapshot)) {
		*decision = SELINUX_VALIDATETRANS_ALLOWED;
		return -ESTALE;
	}
	return rc;
}

int security_bounded_transition(struct selinux_state *state, u32 oldsid,
				u32 newsid)
{
	u32 ss_oldsid, ss_newsid;
	int rc;

	if (!selinux_initialized(state))
		return 0;

	rc = map_global_sid_to_ss(state, oldsid, &ss_oldsid, GFP_ATOMIC);
	if (rc)
		return -EINVAL;
	rc = map_global_sid_to_ss(state, newsid, &ss_newsid, GFP_ATOMIC);
	if (rc)
		return -EINVAL;
	return selinux_ss_bounded_transition(state, ss_oldsid, ss_newsid);
}

struct selinux_global_sid_handle *
security_sid_mls_copy_handle(struct selinux_state *state, u32 sid,
			     u32 mls_sid, u32 *out_sid)
{
	u32 ss_sid, ss_mlssid, ss_outsid;
	int rc;

	if (!selinux_initialized(state))
		return global_existing_sid_handle(sid, out_sid);

	rc = map_global_sid_to_ss(state, sid, &ss_sid, GFP_ATOMIC);
	if (rc)
		return ERR_PTR(rc);
	rc = map_global_sid_to_ss(state, mls_sid, &ss_mlssid, GFP_ATOMIC);
	if (rc)
		return ERR_PTR(rc);

	rc = selinux_ss_sid_mls_copy(state, ss_sid, ss_mlssid, &ss_outsid);
	if (rc)
		return ERR_PTR(rc);

	return map_ss_sid_to_global_handle(state, ss_outsid, out_sid);
}

int security_sid_mls_copy(struct selinux_state *state, u32 sid, u32 mls_sid,
			  u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_sid_mls_copy_handle(state, sid, mls_sid, out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

struct selinux_global_sid_handle *
security_net_peersid_resolve_handle(struct selinux_state *state, u32 nlbl_sid,
				   u32 nlbl_type, u32 xfrm_sid,
				   u32 *out_sid)
{
	u32 ss_nlblsid, ss_xfrmsid, ss_outsid;
	int rc;

	if (!selinux_initialized(state)) {
		if (xfrm_sid == SECSID_NULL)
			return global_existing_sid_handle(nlbl_sid, out_sid);
		if (nlbl_sid == SECSID_NULL ||
		    nlbl_type == NETLBL_NLTYPE_UNLABELED)
			return global_existing_sid_handle(xfrm_sid, out_sid);
		return global_existing_sid_handle(SECSID_NULL, out_sid);
	}

	ss_nlblsid = SECSID_NULL;
	if (nlbl_sid != SECSID_NULL) {
		rc = map_global_sid_to_ss(state, nlbl_sid, &ss_nlblsid,
					  GFP_ATOMIC);
		if (rc)
			return ERR_PTR(rc);
	}

	ss_xfrmsid = SECSID_NULL;
	if (xfrm_sid != SECSID_NULL) {
		rc = map_global_sid_to_ss(state, xfrm_sid, &ss_xfrmsid,
					  GFP_ATOMIC);
		if (rc)
			return ERR_PTR(rc);
	}

	rc = selinux_ss_net_peersid_resolve(state, ss_nlblsid, nlbl_type,
					    ss_xfrmsid, &ss_outsid);
	if (rc)
		return ERR_PTR(rc);

	if (ss_outsid == SECSID_NULL)
		return global_existing_sid_handle(SECSID_NULL, out_sid);

	return map_ss_sid_to_global_handle(state, ss_outsid, out_sid);
}

int security_net_peersid_resolve(struct selinux_state *state, u32 nlbl_sid,
				 u32 nlbl_type, u32 xfrm_sid, u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_net_peersid_resolve_handle(
		state, nlbl_sid, nlbl_type, xfrm_sid, out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

struct selinux_global_sid_handle *
security_fs_use_handle(struct selinux_state *state, const char *fstype,
		       unsigned short *behavior, u32 *out_sid)
{
	int rc;
	u32 ss_sid;

	if (!selinux_initialized(state)) {
		*behavior = SECURITY_FS_USE_NONE;
		return global_existing_sid_handle(SECINITSID_UNLABELED, out_sid);
	}

	rc = selinux_ss_fs_use(state, fstype, behavior, &ss_sid);
	if (rc)
		return ERR_PTR(rc);

	return map_ss_sid_to_global_handle(state, ss_sid, out_sid);
}

int security_fs_use(struct selinux_state *state, const char *fstype,
		    unsigned short *behavior, u32 *sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_fs_use_handle(state, fstype, behavior, sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

struct selinux_global_sid_handle *
security_genfs_sid_handle(struct selinux_state *state, const char *fstype,
			  const char *path, u16 sclass, u32 *out_sid)
{
	int rc;
	u32 ss_outsid;

	if (!selinux_initialized(state))
		return global_existing_sid_handle(SECINITSID_UNLABELED, out_sid);

	rc = selinux_ss_genfs_sid(state, fstype, path, sclass, &ss_outsid);
	if (rc)
		return ERR_PTR(rc);

	return map_ss_sid_to_global_handle(state, ss_outsid, out_sid);
}

int security_genfs_sid(struct selinux_state *state, const char *fstype,
		       const char *path, u16 sclass, u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_genfs_sid_handle(state, fstype, path, sclass,
						out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

struct selinux_global_sid_handle *
selinux_policy_genfs_sid_handle(struct selinux_state *state,
			       struct selinux_policy *policy,
			       const char *fstype, const char *path,
			       u16 sclass, u32 *out_sid)
{
	const char *scontext;
	u32 scontext_len;
	int rc;
	u32 ss_outsid;

	rc = selinux_ss_policy_genfs_sid(policy, fstype, path, sclass, &ss_outsid);
	if (rc)
		return ERR_PTR(rc);
	rc = selinux_ss_policy_sid_to_context(policy, ss_outsid, &scontext,
					      &scontext_len);
	if (rc)
		return ERR_PTR(rc);

	/*
	 * @policy is not published yet, therefore its local SID must never be
	 * resolved through state->policy.  Intern its borrowed context directly
	 * in the explicit state's domain.  SID lookup and interning add O(1)
	 * indexing work beyond the existing genfs lookup (plus bounded context
	 * hashing), and the initial-SID discriminator preserves exact ABI IDs.
	 */
	return global_context_to_handle(
		state, scontext, scontext_len,
		ss_outsid <= SECINITSID_NUM ? ss_outsid : 0, out_sid, GFP_KERNEL);
}

int selinux_policy_genfs_sid(struct selinux_state *state,
			     struct selinux_policy *policy,
			     const char *fstype, const char *path,
			     u16 sclass, u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = selinux_policy_genfs_sid_handle(state, policy, fstype, path,
						sclass, out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

static int selinux_audit_rule_ref_sid_uncached(
	const struct lsm_prop_ref *ref, const struct selinux_state *owner, u32 *sid)
{
	const struct selinux_prop_ref_security *rsec;

	if (!ref || !owner || !owner->label_domain || !sid)
		return -EINVAL;
	rsec = selinux_prop_ref(ref);
	if (!rsec->sid || ref->prop.selinux.secid != rsec->sid)
		return -ESTALE;

	switch (rsec->kind) {
	case SELINUX_PROP_REF_CRED: {
		const struct cred *cred = rsec->cred;

		while (cred) {
			const struct cred_security_struct *crsec =
				selinux_cred(cred);

			if (crsec->state == owner) {
				if (!crsec->sid || !crsec->sid_handle ||
				    global_sid_handle_sid(crsec->sid_handle) !=
					    crsec->sid)
					return -ESTALE;
				*sid = crsec->sid;
				return 0;
			}
			cred = crsec->parent_cred;
		}
		return -EOPNOTSUPP;
	}
	case SELINUX_PROP_REF_HANDLE:
		if (!rsec->handle ||
		    global_sid_handle_sid(rsec->handle) != rsec->sid)
			return -ESTALE;
		*sid = rsec->sid;
		return 0;
	case SELINUX_PROP_REF_PATHLESS: {
		struct selinux_pathless_resolution resolved;
		int rc;

		if (!rsec->projection)
			return -ESTALE;
		rc = selinux_pathless_projection_resolve_sealed(
			rsec->projection, owner->label_domain, &resolved);
		if (rc)
			return rc;
		*sid = resolved.sid;
		return 0;
	}
	case SELINUX_PROP_REF_NUMERIC:
		*sid = rsec->sid;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int selinux_audit_rule_ref_sid(const struct lsm_prop_ref *ref,
				      const struct selinux_state *owner,
				      u32 *sid)
{
	struct selinux_prop_ref_security *rsec;
	unsigned long cached_owner, owner_key = (unsigned long)owner;
	int rc;

	if (!ref || !owner || !sid || owner_key <= 1)
		return -EINVAL;
	rsec = selinux_prop_ref(ref);
	/* Pairs with the release publication after SID/status initialization. */
	cached_owner = smp_load_acquire(&rsec->audit_owner);
	if (cached_owner > 1) {
		if (cached_owner != owner_key)
			return -ESTALE;
		rc = READ_ONCE(rsec->audit_owner_status);
		if (rc)
			return rc;
		*sid = READ_ONCE(rsec->audit_owner_sid);
		return *sid ? 0 : -ESTALE;
	}
	if (cached_owner == 1 ||
	    cmpxchg(&rsec->audit_owner, 0UL, 1UL) != 0)
		return -EAGAIN;

	rc = selinux_audit_rule_ref_sid_uncached(ref, owner, sid);
	WRITE_ONCE(rsec->audit_owner_sid, rc ? 0 : *sid);
	WRITE_ONCE(rsec->audit_owner_status, rc);
	/* Publish both the projected SID and a deterministic failure atomically. */
	smp_store_release(&rsec->audit_owner, owner_key);
	return rc;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
int selinux_kunit_audit_rule_ref_sid(const struct lsm_prop_ref *ref,
				      const struct selinux_state *owner,
				      u32 *sid)
{
	return selinux_audit_rule_ref_sid(ref, owner, sid);
}
#endif

int selinux_audit_rule_match(const struct lsm_prop_ref *ref,
			     const struct lsm_prop *prop, u32 field, u32 op,
			     void *vrule)
{
	int rc;
	struct lsm_prop local_prop;
	struct selinux_state *state = selinux_audit_rule_state(vrule);
	u32 sid;

	if (!state)
		return -ENOENT;
	if (!selinux_initialized(state))
		return 0;

	if (ref) {
		rc = selinux_audit_rule_ref_sid(ref, state, &sid);
	} else if (!prop || !prop->selinux.secid) {
		rc = -EINVAL;
	} else {
		sid = prop->selinux.secid;
		rc = 0;
	}
	if (rc)
		return rc;
	rc = map_global_sid_to_ss(state, sid,
				  &local_prop.selinux.secid, GFP_ATOMIC);
	if (rc)
		return rc;
	return selinux_ss_audit_rule_match(&local_prop, field, op, vrule);
}

#ifdef CONFIG_NETLABEL
#define SELINUX_NETLBL_CACHE_MAGIC 0x53454c4e4c424c31ULL
#define SELINUX_NETLBL_CACHE_VERSION 3

struct selinux_netlbl_cache_data {
	u64 magic;
	u64 label_id;
	u64 label_generation;
	u64 domain_id;
	u64 domain_generation;
	u32 version;
	u32 sid;
	u32 raw_flags;
	u32 netlabel_type;
	u32 mls_level;
	u32 wire_secid;
	struct netlbl_lsm_catmap *mls_categories;
	struct selinux_label_ref *label;
	struct selinux_global_sid_handle *handle;
};

static int security_netlbl_cache_validate_live_carrier(
	const struct selinux_netlbl_cache_data *cache,
	const struct netlbl_lsm_secattr *secattr)
{
	struct selinux_global_sid_handle *carrier;
	u32 carrier_sid;
	int rc = 0;

	/* CACHE-only replays intentionally carry their raw data in @cache. */
	if ((cache->raw_flags & NETLBL_SECATTR_SECID) &&
	    (secattr->flags & NETLBL_SECATTR_SECID) &&
	    secattr->attr.secid != cache->wire_secid)
		return -ESTALE;
	if (!(secattr->flags & NETLBL_SECATTR_PROP_REF))
		return 0;
	if (!(secattr->flags & NETLBL_SECATTR_SECID) || !secattr->prop_ref ||
	    !(cache->raw_flags & NETLBL_SECATTR_SECID))
		return -ESTALE;

	carrier = selinux_prop_ref_handle_get(secattr->prop_ref, &carrier_sid);
	if (IS_ERR(carrier))
		return PTR_ERR(carrier);
	if (carrier_sid != secattr->attr.secid ||
	    carrier_sid != cache->wire_secid || carrier != cache->handle)
		rc = -ESTALE;
	global_sid_handle_put(carrier);
	return rc;
}

static struct netlbl_lsm_catmap *
security_netlbl_catmap_dup(const struct netlbl_lsm_catmap *src, gfp_t gfp)
{
	struct netlbl_lsm_catmap *head = NULL;
	struct netlbl_lsm_catmap **next = &head;

	for (; src; src = src->next) {
		struct netlbl_lsm_catmap *node = netlbl_catmap_alloc(gfp);

		if (!node) {
			netlbl_catmap_free(head);
			return NULL;
		}
		*node = *src;
		node->next = NULL;
		*next = node;
		next = &node->next;
	}
	return head;
}

static void security_netlbl_cache_free(const void *data)
{
	const struct selinux_netlbl_cache_data *cache = data;

	if (!cache)
		return;
	netlbl_catmap_free(cache->mls_categories);
	selinux_label_ref_put(cache->label);
	global_sid_handle_put(cache->handle);
	kfree(cache);
}

static struct selinux_global_sid_handle *
security_netlbl_cache_read_handle(struct selinux_state *state,
				  const struct selinux_label_view *view,
				  struct netlbl_lsm_secattr *secattr,
				  u32 *sid)
{
	const struct selinux_netlbl_cache_data *cache;
	struct selinux_global_sid_handle *handle;
	struct selinux_label_ref *canonical;
	struct netlbl_lsm_secattr raw;
	u32 ss_sid;
	int rc = -ESTALE;

	if (!secattr->cache || !secattr->cache->data)
		return ERR_PTR(-ESTALE);
	cache = secattr->cache->data;
	if (cache->magic != SELINUX_NETLBL_CACHE_MAGIC ||
	    cache->version != SELINUX_NETLBL_CACHE_VERSION || !cache->sid ||
	    !cache->label || !cache->handle ||
	    global_sid_handle_sid(cache->handle) != cache->sid ||
	    secattr->type != cache->netlabel_type ||
	    !(cache->raw_flags & (NETLBL_SECATTR_MLS_LVL |
				   NETLBL_SECATTR_MLS_CAT |
				   NETLBL_SECATTR_SECID)) ||
	    ((cache->raw_flags & NETLBL_SECATTR_SECID) &&
	     ((cache->raw_flags & (NETLBL_SECATTR_MLS_LVL |
				    NETLBL_SECATTR_MLS_CAT)) ||
	      cache->wire_secid != cache->sid)) ||
	    ((cache->raw_flags & NETLBL_SECATTR_MLS_CAT) &&
	     (!(cache->raw_flags & NETLBL_SECATTR_MLS_LVL) ||
	      !cache->mls_categories)))
		return ERR_PTR(-ESTALE);

	/* The cache's strong handle is the authority for this numeric SID. */
	canonical = global_sid_handle_label_get(cache->handle);
	if (!canonical)
		return ERR_PTR(-ESTALE);
	if (canonical == cache->label && canonical->id == cache->label_id &&
	    canonical->generation == cache->label_generation &&
	    canonical->domain->id == cache->domain_id &&
	    canonical->domain->generation == cache->domain_generation) {
		rc = 0;
	}
	selinux_label_ref_put(canonical);
	if (rc)
		return ERR_PTR(rc);
	rc = security_netlbl_cache_validate_live_carrier(cache, secattr);
	if (rc)
		return ERR_PTR(rc);

	if (cache->raw_flags & NETLBL_SECATTR_SECID) {
		if (view) {
			rc = selinux_label_view_resolve(
				view, state->label_domain, cache->label,
				cache->wire_secid, sid);
			if (rc)
				return ERR_PTR(rc);
			if (*sid == cache->sid)
				return global_sid_handle_dup(cache->handle);
			/* The immutable view pins this exact mapped target. */
			handle = global_sid_handle_get(*sid);
			if (IS_ERR(handle) ||
			    global_sid_handle_sid(handle) != *sid) {
				if (!IS_ERR(handle))
					global_sid_handle_put(handle);
				return ERR_PTR(-ESTALE);
			}
			return handle;
		}
		if (!(cache->label->domain->flags &
		      SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) &&
		    cache->label->domain != state->label_domain)
			return ERR_PTR(-EOPNOTSUPP);
		*sid = cache->wire_secid;
		return global_sid_handle_dup(cache->handle);
	}

	netlbl_secattr_init(&raw);
	raw.flags = cache->raw_flags & (NETLBL_SECATTR_MLS_LVL |
					 NETLBL_SECATTR_MLS_CAT);
	raw.type = cache->netlabel_type;
	raw.attr.mls.lvl = cache->mls_level;
	raw.attr.mls.cat = cache->mls_categories;
	rc = selinux_ss_netlbl_secattr_to_sid(state, &raw, &ss_sid);
	if (rc)
		return ERR_PTR(rc);
	if (ss_sid == SECSID_NULL) {
		*sid = SECSID_NULL;
		return NULL;
	}
	return map_ss_sid_to_global_handle(state, ss_sid, sid);
}

/* Consume @handle only after the cache has been published successfully. */
static int security_netlbl_cache_add_handle(
	struct netlbl_lsm_secattr *secattr,
	struct selinux_global_sid_handle *handle, u32 sid)
{
	struct selinux_netlbl_cache_data *data;
	struct netlbl_lsm_cache *cache;
	struct selinux_label_ref *label;
	u32 raw_flags;

	if (!handle || IS_ERR(handle) || !sid ||
	    global_sid_handle_sid(handle) != sid)
		return -EINVAL;
	if ((secattr->flags & NETLBL_SECATTR_CACHE) || secattr->cache)
		return -EEXIST;
	label = global_sid_handle_label_get(handle);
	if (!label)
		return -ESTALE;
	raw_flags = secattr->flags & (NETLBL_SECATTR_MLS_LVL |
				      NETLBL_SECATTR_MLS_CAT |
				      NETLBL_SECATTR_SECID);
	if (!raw_flags ||
	    ((raw_flags & NETLBL_SECATTR_SECID) &&
	     (raw_flags & (NETLBL_SECATTR_MLS_LVL | NETLBL_SECATTR_MLS_CAT))) ||
	    ((raw_flags & NETLBL_SECATTR_MLS_CAT) &&
	     (!(raw_flags & NETLBL_SECATTR_MLS_LVL) ||
	      !secattr->attr.mls.cat))) {
		selinux_label_ref_put(label);
		return -EINVAL;
	}

	data = kzalloc_obj(*data, GFP_ATOMIC);
	if (!data)
		goto err_label;
	if (raw_flags & NETLBL_SECATTR_MLS_CAT) {
		data->mls_categories = security_netlbl_catmap_dup(
			secattr->attr.mls.cat, GFP_ATOMIC);
		if (!data->mls_categories)
			goto err_data;
	}
	cache = netlbl_secattr_cache_alloc(GFP_ATOMIC);
	if (!cache)
		goto err_categories;

	data->magic = SELINUX_NETLBL_CACHE_MAGIC;
	data->version = SELINUX_NETLBL_CACHE_VERSION;
	data->sid = sid;
	data->raw_flags = raw_flags;
	data->netlabel_type = secattr->type;
	data->mls_level = secattr->attr.mls.lvl;
	data->wire_secid = secattr->attr.secid;
	data->label = label;
	data->handle = handle;
	data->label_id = label->id;
	data->label_generation = label->generation;
	data->domain_id = label->domain->id;
	data->domain_generation = label->domain->generation;
	cache->free = security_netlbl_cache_free;
	cache->data = data;
	secattr->cache = cache;
	secattr->flags |= NETLBL_SECATTR_CACHE;
	return 0;

err_categories:
	netlbl_catmap_free(data->mls_categories);
err_data:
	kfree(data);
err_label:
	selinux_label_ref_put(label);
	return -ENOMEM;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
static int __maybe_unused
security_netlbl_cache_add(struct netlbl_lsm_secattr *secattr, u32 sid)
{
	struct selinux_global_sid_handle *handle;
	int rc;

	handle = global_sid_handle_get(sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	rc = security_netlbl_cache_add_handle(secattr, handle, sid);
	if (rc)
		global_sid_handle_put(handle);
	return rc;
}
#endif

static struct selinux_global_sid_handle *
security_netlbl_ss_sid_to_global_handle(struct selinux_state *state,
					struct netlbl_lsm_secattr *secattr,
					u32 ss_sid, u32 *sid)
{
	struct selinux_global_sid_handle *cache_handle, *handle;
	int rc;

	if (ss_sid == SECSID_NULL) {
		*sid = SECSID_NULL;
		return NULL;
	}

	handle = map_ss_sid_to_global_handle(state, ss_sid, sid);
	if (IS_ERR(handle))
		return handle;
	cache_handle = global_sid_handle_dup(handle);
	if (!IS_ERR(cache_handle)) {
		rc = security_netlbl_cache_add_handle(secattr, cache_handle, *sid);
		if (rc)
			global_sid_handle_put(cache_handle);
	}
	return handle;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
int selinux_kunit_netlbl_cache_add(struct netlbl_lsm_secattr *secattr,
				   u32 sid)
{
	struct selinux_global_sid_handle *handle;
	int rc;

	handle = global_sid_handle_get(sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	rc = security_netlbl_cache_add_handle(secattr, handle, sid);
	if (rc)
		global_sid_handle_put(handle);
	return rc;
}

int selinux_kunit_netlbl_cache_corrupt(struct netlbl_lsm_secattr *secattr,
				       enum selinux_kunit_netlbl_cache_corruption corruption)
{
	struct selinux_netlbl_cache_data *cache;

	if (!secattr || !(secattr->flags & NETLBL_SECATTR_CACHE) ||
	    !secattr->cache || !secattr->cache->data)
		return -ENOENT;
	cache = secattr->cache->data;
	switch (corruption) {
	case SELINUX_KUNIT_NETLBL_CORRUPT_MAGIC:
		cache->magic ^= 1;
		break;
	case SELINUX_KUNIT_NETLBL_CORRUPT_VERSION:
		cache->version++;
		break;
	case SELINUX_KUNIT_NETLBL_CORRUPT_SID:
		cache->sid = U32_MAX;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int selinux_kunit_netlbl_ss_sid_to_global(struct selinux_state *state,
					  struct netlbl_lsm_secattr *secattr,
					  u32 ss_sid, u32 *sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_netlbl_ss_sid_to_global_handle(state, secattr, ss_sid,
							 sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}
#endif

struct selinux_global_sid_handle *
security_netlbl_secattr_to_sid_view_handle(
	struct selinux_state *state, const struct selinux_label_view *view,
	struct netlbl_lsm_secattr *secattr, u32 *out_sid)
{
	struct selinux_global_sid_handle *cache_handle, *handle;
	int rc;
	u32 ss_outsid;

	if (!selinux_initialized(state)) {
		*out_sid = SECSID_NULL;
		return NULL;
	}

	/* NetLabel protocol caches contain canonical global identities. */
	if (secattr->flags & NETLBL_SECATTR_CACHE)
		return security_netlbl_cache_read_handle(state, view, secattr,
							  out_sid);

	/* The secattr secid must name an extant canonical global identity. */
	if (secattr->flags & NETLBL_SECATTR_SECID) {
		struct selinux_label_ref *label;
		u32 carrier_sid;

		if (secattr->attr.secid == SECSID_NULL)
			return ERR_PTR(-ESTALE);
		if (secattr->flags & NETLBL_SECATTR_PROP_REF) {
			if (!secattr->prop_ref)
				return ERR_PTR(-ESTALE);
			handle = selinux_prop_ref_handle_get(secattr->prop_ref,
						     &carrier_sid);
			if (!IS_ERR(handle) && carrier_sid != secattr->attr.secid) {
				global_sid_handle_put(handle);
				handle = ERR_PTR(-ESTALE);
			}
		} else {
			handle = global_sid_handle_get(secattr->attr.secid);
		}
		if (IS_ERR(handle))
			return handle;
		label = global_sid_handle_label_get(handle);
		if (!label) {
			global_sid_handle_put(handle);
			return ERR_PTR(-ESTALE);
		}
		if (view)
			rc = selinux_label_view_resolve(
				view, state->label_domain, label,
				secattr->attr.secid, out_sid);
		else if (!(label->domain->flags &
			   SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) &&
			 label->domain != state->label_domain)
			rc = -EOPNOTSUPP;
		else {
			*out_sid = secattr->attr.secid;
			rc = 0;
		}
		selinux_label_ref_put(label);
		if (rc) {
			global_sid_handle_put(handle);
			return ERR_PTR(rc);
		}
		if ((secattr->flags & NETLBL_SECATTR_CACHEABLE) &&
		    !(secattr->flags & NETLBL_SECATTR_CACHE)) {
			cache_handle = global_sid_handle_dup(handle);
			if (!IS_ERR(cache_handle)) {
				rc = security_netlbl_cache_add_handle(
					secattr, cache_handle, secattr->attr.secid);
				if (rc)
					global_sid_handle_put(cache_handle);
			}
		}
		if (*out_sid == secattr->attr.secid)
			return handle;
		cache_handle = global_sid_handle_get(*out_sid);
		global_sid_handle_put(handle);
		if (IS_ERR(cache_handle) ||
		    global_sid_handle_sid(cache_handle) != *out_sid) {
			if (!IS_ERR(cache_handle))
				global_sid_handle_put(cache_handle);
			return ERR_PTR(-ESTALE);
		}
		return cache_handle;
	}

	rc = selinux_ss_netlbl_secattr_to_sid(state, secattr, &ss_outsid);
	if (rc)
		return ERR_PTR(rc);

	return security_netlbl_ss_sid_to_global_handle(state, secattr, ss_outsid,
						      out_sid);
}

int security_netlbl_secattr_to_sid_view(
	struct selinux_state *state, const struct selinux_label_view *view,
	struct netlbl_lsm_secattr *secattr, u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_netlbl_secattr_to_sid_view_handle(
		state, view, secattr, out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

int security_netlbl_secattr_to_sid(struct selinux_state *state,
				   struct netlbl_lsm_secattr *secattr,
				   u32 *out_sid)
{
	struct selinux_global_sid_handle *handle;

	handle = security_netlbl_secattr_to_sid_view_handle(
		state, NULL, secattr, out_sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	global_sid_handle_put(handle);
	return 0;
}

int security_netlbl_sid_to_secattr(struct selinux_state *state, u32 sid,
				   struct netlbl_lsm_secattr *secattr)
{
	int rc;
	u32 ss_sid;

	if (!selinux_initialized(state))
		return 0;

	rc = map_global_sid_to_ss(state, sid, &ss_sid, GFP_ATOMIC);
	if (rc)
		return rc;
	rc = selinux_ss_netlbl_sid_to_secattr(state, ss_sid, secattr);
	if (rc)
		return rc;

	// The secattr secid is a global SID.
	secattr->attr.secid = sid;
	secattr->flags |= NETLBL_SECATTR_SECID;
	return 0;
}
#endif
