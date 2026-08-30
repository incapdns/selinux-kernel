// SPDX-License-Identifier: GPL-2.0-only
/* Aggregate SELinux resource ownership and hard limits. */

#include <linux/err.h>
#include <linux/hash.h>
#include <linux/jiffies.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/user_namespace.h>

#include "resource.h"

struct selinux_resource_account {
	refcount_t refs;
	struct user_namespace *owner;
	struct rhash_head node;
	atomic64_t objects[SELINUX_RESOURCE_KINDS];
	atomic64_t bytes[SELINUX_RESOURCE_KINDS];
	atomic64_t total_objects;
	atomic64_t total_bytes;
#ifdef CONFIG_SECURITY_SELINUX_NS
	atomic64_t namespaces;
#endif
	spinlock_t audit_lock;
	u64 audit_tokens;
	unsigned long audit_refill;
	struct rcu_head rcu;
};

static struct rhashtable selinux_resource_accounts;
static DEFINE_MUTEX(selinux_resource_accounts_mutex);
static bool selinux_resource_accounts_ready;
static atomic64_t selinux_resource_global_objects = ATOMIC64_INIT(0);
static atomic64_t selinux_resource_global_bytes = ATOMIC64_INIT(0);
#ifdef CONFIG_SECURITY_SELINUX_NS
static atomic64_t selinux_namespace_global_count = ATOMIC64_INIT(0);
#endif
static DEFINE_SPINLOCK(selinux_audit_host_lock);
static DEFINE_SPINLOCK(selinux_audit_child_lock);
static u64 selinux_audit_host_tokens =
	CONFIG_SECURITY_SELINUX_AUDIT_HOST_TOKENS_RESERVED;
static u64 selinux_audit_child_tokens =
	CONFIG_SECURITY_SELINUX_AUDIT_CHILD_TOKENS_GLOBAL;
static unsigned long selinux_audit_host_refill = INITIAL_JIFFIES;
static unsigned long selinux_audit_child_refill = INITIAL_JIFFIES;

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
static atomic_t selinux_resource_account_kunit_fault =
	ATOMIC_INIT(SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_NONE);
static struct user_namespace *selinux_resource_account_kunit_fault_owner;
static atomic_t selinux_resource_reserve_kunit_fault =
	ATOMIC_INIT(SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_NONE);
static struct selinux_resource_account *
	selinux_resource_reserve_kunit_fault_account;

static bool selinux_resource_account_kunit_fault_take(
	struct user_namespace *owner,
	enum selinux_resource_account_kunit_fault fault)
{
	if (READ_ONCE(selinux_resource_account_kunit_fault_owner) != owner)
		return false;
	return atomic_cmpxchg(&selinux_resource_account_kunit_fault, fault,
			      SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_NONE) == fault;
}

static bool selinux_resource_reserve_kunit_fault_take(
	struct selinux_resource_account *account,
	enum selinux_resource_reserve_kunit_fault fault)
{
	if (READ_ONCE(selinux_resource_reserve_kunit_fault_account) != account)
		return false;
	return atomic_cmpxchg(&selinux_resource_reserve_kunit_fault, fault,
			      SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_NONE) == fault;
}

void selinux_resource_account_kunit_fail_next(
	struct user_namespace *owner,
	enum selinux_resource_account_kunit_fault fault)
{
	if (WARN_ON_ONCE((unsigned int)fault >=
			 SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_MAX))
		fault = SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_NONE;
	WRITE_ONCE(selinux_resource_account_kunit_fault_owner, owner);
	atomic_set(&selinux_resource_account_kunit_fault, fault);
}

void selinux_resource_reserve_kunit_fail_next(
	struct selinux_resource_account *account,
	enum selinux_resource_reserve_kunit_fault fault)
{
	if (WARN_ON_ONCE((unsigned int)fault >=
			 SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_MAX))
		fault = SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_NONE;
	WRITE_ONCE(selinux_resource_reserve_kunit_fault_account, account);
	atomic_set(&selinux_resource_reserve_kunit_fault, fault);
}
#endif

static u32 selinux_resource_key_hash(const void *data, u32 len, u32 seed)
{
	const struct user_namespace *const *owner = data;

	return hash_ptr(*owner, 32) ^ seed;
}

static u32 selinux_resource_obj_hash(const void *data, u32 len, u32 seed)
{
	const struct selinux_resource_account *account = data;

	return hash_ptr(account->owner, 32) ^ seed;
}

static int selinux_resource_obj_cmp(struct rhashtable_compare_arg *arg,
				    const void *obj)
{
	const struct user_namespace *const *owner = arg->key;
	const struct selinux_resource_account *account = obj;

	return account->owner != *owner;
}

static const struct rhashtable_params selinux_resource_ht_params = {
	.head_offset = offsetof(struct selinux_resource_account, node),
	.hashfn = selinux_resource_key_hash,
	.obj_hashfn = selinux_resource_obj_hash,
	.obj_cmpfn = selinux_resource_obj_cmp,
	.automatic_shrinking = true,
};

static struct selinux_resource_account *selinux_resource_account_alloc(
	struct user_namespace *owner)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (selinux_resource_account_kunit_fault_take(
		    owner, SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_ALLOC))
		return NULL;
#else
	(void)owner;
#endif
	return kzalloc_obj(struct selinux_resource_account);
}

static struct selinux_resource_account *selinux_resource_account_insert(
	struct user_namespace *owner,
	struct selinux_resource_account *candidate)
{
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (selinux_resource_account_kunit_fault_take(
		    owner, SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_HASH_INSERT))
		return ERR_PTR(-ENOMEM);
#endif
	return rhashtable_lookup_get_insert_key(
		&selinux_resource_accounts, &owner, &candidate->node,
		selinux_resource_ht_params);
}

static int selinux_resource_accounts_init(void)
{
	int rc = 0;

	mutex_lock(&selinux_resource_accounts_mutex);
	if (!selinux_resource_accounts_ready) {
		rc = rhashtable_init(&selinux_resource_accounts,
				     &selinux_resource_ht_params);
		if (!rc)
			selinux_resource_accounts_ready = true;
	}
	mutex_unlock(&selinux_resource_accounts_mutex);
	return rc;
}

static bool selinux_resource_add_bounded(atomic64_t *counter, u64 amount,
					 u64 limit)
{
	s64 old = atomic64_read(counter);

	limit = min_t(u64, limit, S64_MAX);
	if (amount > limit)
		return false;
	for (;;) {
		if (old < 0 || (u64)old > limit ||
		    amount > limit - (u64)old)
			return false;
		if (atomic64_try_cmpxchg(counter, &old, old + amount))
			return true;
	}
}

static bool selinux_resource_sub_checked(atomic64_t *counter, u64 amount)
{
	s64 old = atomic64_read(counter);

	if (amount > S64_MAX)
		return false;
	for (;;) {
		if (old < 0 || (u64)old < amount)
			return false;
		if (atomic64_try_cmpxchg(counter, &old, old - amount))
			return true;
	}
}

struct selinux_resource_account *
selinux_resource_account_get_owner(struct user_namespace *owner)
{
	struct selinux_resource_account *account, *candidate;
	int rc;

	if (!owner)
		return ERR_PTR(-EINVAL);
	rc = selinux_resource_accounts_init();
	if (rc)
		return ERR_PTR(rc);

retry:
	rcu_read_lock();
	account = rhashtable_lookup(&selinux_resource_accounts, &owner,
				    selinux_resource_ht_params);
	if (account && refcount_inc_not_zero(&account->refs)) {
		rcu_read_unlock();
		return account;
	}
	rcu_read_unlock();

	candidate = selinux_resource_account_alloc(owner);
	if (!candidate)
		return ERR_PTR(-ENOMEM);
	refcount_set(&candidate->refs, 1);
	candidate->owner = get_user_ns(owner);
	spin_lock_init(&candidate->audit_lock);
	candidate->audit_tokens =
		CONFIG_SECURITY_SELINUX_AUDIT_TOKENS_PER_USERNS;
	candidate->audit_refill = jiffies;

	rcu_read_lock();
	account = selinux_resource_account_insert(owner, candidate);
	if (account && !IS_ERR(account) &&
	    !refcount_inc_not_zero(&account->refs)) {
		rcu_read_unlock();
		put_user_ns(candidate->owner);
		kfree(candidate);
		cond_resched();
		goto retry;
	}
	rcu_read_unlock();
	if (IS_ERR(account)) {
		rc = PTR_ERR(account);
		put_user_ns(candidate->owner);
		kfree(candidate);
		return ERR_PTR(rc);
	}
	if (account) {
		put_user_ns(candidate->owner);
		kfree(candidate);
		return account;
	}
	return candidate;
}

struct selinux_resource_account *
selinux_resource_account_get(struct selinux_resource_account *account)
{
	if (account)
		refcount_inc(&account->refs);
	return account;
}

static void selinux_resource_account_free(struct rcu_head *rcu)
{
	struct selinux_resource_account *account =
		container_of(rcu, struct selinux_resource_account, rcu);

	put_user_ns(account->owner);
	kfree(account);
}

void selinux_resource_account_put(struct selinux_resource_account *account)
{
	int rc;

	if (!account || !refcount_dec_and_test(&account->refs))
		return;
	if (WARN_ON_ONCE(atomic64_read(&account->total_objects) ||
			 atomic64_read(&account->total_bytes)
#ifdef CONFIG_SECURITY_SELINUX_NS
			 || atomic64_read(&account->namespaces)
#endif
			 )) {
		/* Quarantine an inconsistent account instead of losing its charges. */
		refcount_set(&account->refs, 1);
		return;
	}
	rc = rhashtable_remove_fast(&selinux_resource_accounts, &account->node,
				    selinux_resource_ht_params);
	if (unlikely(rc && rc != -ENOENT)) {
		refcount_set(&account->refs, 1);
		WARN_ON_ONCE(rc);
		return;
	}
	WARN_ON_ONCE(rc);
	call_rcu(&account->rcu, selinux_resource_account_free);
}

int selinux_resource_reserve(struct selinux_resource_account *account,
			     enum selinux_resource_kind kind, u64 objects,
			     u64 bytes)
{
	if (!account || kind >= SELINUX_RESOURCE_KINDS || (!objects && !bytes))
		return -EINVAL;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (selinux_resource_reserve_kunit_fault_take(
		    account, SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_GLOBAL_OBJECTS))
		return -EDQUOT;
#endif
	if (!selinux_resource_add_bounded(&selinux_resource_global_objects,
					 objects,
					 CONFIG_SECURITY_SELINUX_RESOURCE_OBJECTS_GLOBAL))
		return -EDQUOT;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (selinux_resource_reserve_kunit_fault_take(
		    account, SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_GLOBAL_BYTES))
		goto err_global_objects;
#endif
	if (!selinux_resource_add_bounded(&selinux_resource_global_bytes, bytes,
					 CONFIG_SECURITY_SELINUX_RESOURCE_BYTES_GLOBAL))
		goto err_global_objects;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (selinux_resource_reserve_kunit_fault_take(
		    account, SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_OWNER_OBJECTS))
		goto err_global_bytes;
#endif
	if (!selinux_resource_add_bounded(&account->total_objects, objects,
					 CONFIG_SECURITY_SELINUX_RESOURCE_OBJECTS_PER_USERNS))
		goto err_global_bytes;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (selinux_resource_reserve_kunit_fault_take(
		    account, SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_OWNER_BYTES))
		goto err_owner_objects;
#endif
	if (!selinux_resource_add_bounded(&account->total_bytes, bytes,
					 CONFIG_SECURITY_SELINUX_RESOURCE_BYTES_PER_USERNS))
		goto err_owner_objects;

	atomic64_add(objects, &account->objects[kind]);
	atomic64_add(bytes, &account->bytes[kind]);
	return 0;

err_owner_objects:
	WARN_ON_ONCE(!selinux_resource_sub_checked(&account->total_objects,
						 objects));
err_global_bytes:
	WARN_ON_ONCE(!selinux_resource_sub_checked(
		&selinux_resource_global_bytes, bytes));
err_global_objects:
	WARN_ON_ONCE(!selinux_resource_sub_checked(
		&selinux_resource_global_objects, objects));
	return -EDQUOT;
}

int selinux_resource_reserve_global(u64 objects, u64 bytes)
{
	if (!objects && !bytes)
		return -EINVAL;
	if (!selinux_resource_add_bounded(&selinux_resource_global_objects,
					 objects,
					 CONFIG_SECURITY_SELINUX_RESOURCE_OBJECTS_GLOBAL))
		return -EDQUOT;
	if (!selinux_resource_add_bounded(&selinux_resource_global_bytes, bytes,
					 CONFIG_SECURITY_SELINUX_RESOURCE_BYTES_GLOBAL)) {
		WARN_ON_ONCE(!selinux_resource_sub_checked(
			&selinux_resource_global_objects, objects));
		return -EDQUOT;
	}
	return 0;
}

void selinux_resource_release_global(u64 objects, u64 bytes)
{
	WARN_ON_ONCE(!selinux_resource_sub_checked(
		&selinux_resource_global_bytes, bytes));
	WARN_ON_ONCE(!selinux_resource_sub_checked(
		&selinux_resource_global_objects, objects));
}

void selinux_resource_release(struct selinux_resource_account *account,
			      enum selinux_resource_kind kind, u64 objects,
			      u64 bytes)
{
	if (WARN_ON_ONCE(!account || kind >= SELINUX_RESOURCE_KINDS))
		return;
	WARN_ON_ONCE(!selinux_resource_sub_checked(&account->bytes[kind], bytes));
	WARN_ON_ONCE(!selinux_resource_sub_checked(&account->objects[kind],
						 objects));
	WARN_ON_ONCE(!selinux_resource_sub_checked(&account->total_bytes, bytes));
	WARN_ON_ONCE(!selinux_resource_sub_checked(&account->total_objects,
						 objects));
	WARN_ON_ONCE(!selinux_resource_sub_checked(
		&selinux_resource_global_bytes, bytes));
	WARN_ON_ONCE(!selinux_resource_sub_checked(
		&selinux_resource_global_objects, objects));
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int __selinux_namespace_reserve(
	struct selinux_resource_account *account, u64 bytes, u64 owner_limit,
	u64 global_limit)
{
	int rc;

	if (!account || !bytes || !owner_limit || !global_limit)
		return -EINVAL;
	if (!selinux_resource_add_bounded(&selinux_namespace_global_count, 1,
					 global_limit))
		return -EDQUOT;
	if (!selinux_resource_add_bounded(&account->namespaces, 1,
					 owner_limit)) {
		WARN_ON_ONCE(!selinux_resource_sub_checked(
			&selinux_namespace_global_count, 1));
		return -EDQUOT;
	}
	rc = selinux_resource_reserve(account, SELINUX_RESOURCE_NAMESPACE, 1,
				      bytes);
	if (rc) {
		WARN_ON_ONCE(!selinux_resource_sub_checked(&account->namespaces, 1));
		WARN_ON_ONCE(!selinux_resource_sub_checked(
			&selinux_namespace_global_count, 1));
	}
	return rc;
}

int selinux_namespace_reserve(struct selinux_resource_account *account,
			      u64 bytes, u64 global_limit)
{
	return __selinux_namespace_reserve(
		account, bytes, CONFIG_SECURITY_SELINUX_MAXNS_PER_USERNS,
		global_limit);
}

void selinux_namespace_release(struct selinux_resource_account *account,
			       u64 bytes)
{
	if (WARN_ON_ONCE(!account || !bytes))
		return;
	selinux_resource_release(account, SELINUX_RESOURCE_NAMESPACE, 1, bytes);
	WARN_ON_ONCE(!selinux_resource_sub_checked(&account->namespaces, 1));
	WARN_ON_ONCE(!selinux_resource_sub_checked(
		&selinux_namespace_global_count, 1));
}
#endif

static u64 selinux_audit_refill_amount(u64 periods, u64 maximum)
{
	u64 refill_periods = DIV_ROUND_UP_ULL(
		maximum, CONFIG_SECURITY_SELINUX_AUDIT_REFILL_PER_SECOND);

	if (periods >= refill_periods)
		return maximum;
	return periods * CONFIG_SECURITY_SELINUX_AUDIT_REFILL_PER_SECOND;
}

static bool selinux_audit_token_take(spinlock_t *lock, u64 *tokens,
				     unsigned long *last, u64 maximum)
{
	unsigned long now = jiffies;
	unsigned long elapsed;
	unsigned long flags;
	u64 periods, refill;
	bool success = false;

	spin_lock_irqsave(lock, flags);
	elapsed = now - *last;
	periods = elapsed / HZ;
	if (periods) {
		refill = selinux_audit_refill_amount(periods, maximum);
		*tokens = min_t(u64, maximum, *tokens + refill);
		*last += periods * HZ;
	}
	if (*tokens) {
		(*tokens)--;
		success = true;
	}
	spin_unlock_irqrestore(lock, flags);
	return success;
}

static void selinux_audit_token_refund(spinlock_t *lock, u64 *tokens,
				       u64 maximum)
{
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	if (*tokens < maximum)
		(*tokens)++;
	spin_unlock_irqrestore(lock, flags);
}

static int selinux_audit_reserve_channel(
	struct selinux_resource_account *account, bool host,
	u64 payload_bytes,
	struct selinux_audit_reservation *reservation)
{
	spinlock_t *global_lock;
	unsigned long *global_refill;
	u64 *global_tokens, global_max;
	int rc;

	if (!account || !reservation || reservation->account ||
	    payload_bytes > U64_MAX - SELINUX_AUDIT_RECORD_OVERHEAD)
		return -EINVAL;
	payload_bytes += SELINUX_AUDIT_RECORD_OVERHEAD;
	if (!selinux_audit_token_take(&account->audit_lock,
				      &account->audit_tokens,
				      &account->audit_refill,
				      CONFIG_SECURITY_SELINUX_AUDIT_TOKENS_PER_USERNS))
		return -EDQUOT;
	if (host) {
		global_lock = &selinux_audit_host_lock;
		global_tokens = &selinux_audit_host_tokens;
		global_refill = &selinux_audit_host_refill;
		global_max = CONFIG_SECURITY_SELINUX_AUDIT_HOST_TOKENS_RESERVED;
	} else {
		global_lock = &selinux_audit_child_lock;
		global_tokens = &selinux_audit_child_tokens;
		global_refill = &selinux_audit_child_refill;
		global_max = CONFIG_SECURITY_SELINUX_AUDIT_CHILD_TOKENS_GLOBAL;
	}
	if (!selinux_audit_token_take(global_lock, global_tokens, global_refill,
				      global_max)) {
		selinux_audit_token_refund(&account->audit_lock,
					   &account->audit_tokens,
					   CONFIG_SECURITY_SELINUX_AUDIT_TOKENS_PER_USERNS);
		return -EDQUOT;
	}
	rc = selinux_resource_reserve(account, SELINUX_RESOURCE_AUDIT, 1,
				      payload_bytes);
	if (rc) {
		selinux_audit_token_refund(global_lock, global_tokens, global_max);
		selinux_audit_token_refund(&account->audit_lock,
					   &account->audit_tokens,
					   CONFIG_SECURITY_SELINUX_AUDIT_TOKENS_PER_USERNS);
		return rc;
	}
	reservation->account = selinux_resource_account_get(account);
	reservation->bytes = payload_bytes;
	return 0;
}

int selinux_audit_reserve(struct selinux_resource_account *account,
			  u64 payload_bytes,
			  struct selinux_audit_reservation *reservation)
{
	return selinux_audit_reserve_channel(account,
					     account && account->owner == &init_user_ns,
					     payload_bytes,
					     reservation);
}

void selinux_audit_release(struct selinux_audit_reservation *reservation)
{
	struct selinux_resource_account *account;
	u64 bytes;

	if (!reservation || !reservation->account)
		return;
	account = reservation->account;
	bytes = reservation->bytes;
	reservation->account = NULL;
	reservation->bytes = 0;
	selinux_resource_release(account, SELINUX_RESOURCE_AUDIT, 1, bytes);
	selinux_resource_account_put(account);
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
bool selinux_kunit_resource_account_published(struct user_namespace *owner)
{
	struct selinux_resource_account *account;

	if (!owner || !READ_ONCE(selinux_resource_accounts_ready))
		return false;
	rcu_read_lock();
	account = rhashtable_lookup(&selinux_resource_accounts, &owner,
				    selinux_resource_ht_params);
	rcu_read_unlock();
	return account != NULL;
}

u32 selinux_kunit_resource_account_refs(
	struct selinux_resource_account *account)
{
	return account ? refcount_read(&account->refs) : 0;
}

u64 selinux_kunit_resource_total_objects(
	struct selinux_resource_account *account)
{
	return account ? atomic64_read(&account->total_objects) : 0;
}

u64 selinux_kunit_resource_total_bytes(
	struct selinux_resource_account *account)
{
	return account ? atomic64_read(&account->total_bytes) : 0;
}

u64 selinux_kunit_resource_objects(struct selinux_resource_account *account,
				   enum selinux_resource_kind kind)
{
	return account && kind < SELINUX_RESOURCE_KINDS ?
		atomic64_read(&account->objects[kind]) : 0;
}

u64 selinux_kunit_resource_bytes(struct selinux_resource_account *account,
				 enum selinux_resource_kind kind)
{
	return account && kind < SELINUX_RESOURCE_KINDS ?
		atomic64_read(&account->bytes[kind]) : 0;
}

u64 selinux_kunit_resource_global_objects(void)
{
	return atomic64_read(&selinux_resource_global_objects);
}

u64 selinux_kunit_resource_global_bytes(void)
{
	return atomic64_read(&selinux_resource_global_bytes);
}

u64 selinux_kunit_namespace_owner_count(
	struct selinux_resource_account *account)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	return account ? atomic64_read(&account->namespaces) : 0;
#else
	return 0;
#endif
}

u64 selinux_kunit_namespace_global_count(void)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	return atomic64_read(&selinux_namespace_global_count);
#else
	return 0;
#endif
}

int selinux_kunit_namespace_reserve(
	struct selinux_resource_account *account, u64 bytes, u64 owner_limit,
	u64 global_limit)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	return __selinux_namespace_reserve(account, bytes, owner_limit,
					   global_limit);
#else
	return -EOPNOTSUPP;
#endif
}

void selinux_kunit_audit_buckets_reset(void)
{
	unsigned long flags;

	spin_lock_irqsave(&selinux_audit_host_lock, flags);
	selinux_audit_host_tokens =
		CONFIG_SECURITY_SELINUX_AUDIT_HOST_TOKENS_RESERVED;
	selinux_audit_host_refill = jiffies;
	spin_unlock_irqrestore(&selinux_audit_host_lock, flags);
	spin_lock_irqsave(&selinux_audit_child_lock, flags);
	selinux_audit_child_tokens =
		CONFIG_SECURITY_SELINUX_AUDIT_CHILD_TOKENS_GLOBAL;
	selinux_audit_child_refill = jiffies;
	spin_unlock_irqrestore(&selinux_audit_child_lock, flags);
}

int selinux_kunit_audit_reserve_channel(
	struct selinux_resource_account *account, bool host, u64 payload_bytes,
	struct selinux_audit_reservation *reservation)
{
	return selinux_audit_reserve_channel(account, host, payload_bytes,
					     reservation);
}

u64 selinux_kunit_audit_host_tokens(void)
{
	return READ_ONCE(selinux_audit_host_tokens);
}

u64 selinux_kunit_audit_child_tokens(void)
{
	return READ_ONCE(selinux_audit_child_tokens);
}

u64 selinux_kunit_audit_refill_amount(u64 periods, u64 maximum)
{
	return selinux_audit_refill_amount(periods, maximum);
}

void selinux_kunit_audit_child_tokens_set(u64 tokens)
{
	unsigned long flags;

	spin_lock_irqsave(&selinux_audit_child_lock, flags);
	selinux_audit_child_tokens = min_t(u64, tokens,
					 CONFIG_SECURITY_SELINUX_AUDIT_CHILD_TOKENS_GLOBAL);
	selinux_audit_child_refill = jiffies;
	spin_unlock_irqrestore(&selinux_audit_child_lock, flags);
}

void selinux_kunit_audit_host_tokens_set(u64 tokens)
{
	unsigned long flags;

	spin_lock_irqsave(&selinux_audit_host_lock, flags);
	selinux_audit_host_tokens = min_t(
		u64, tokens, CONFIG_SECURITY_SELINUX_AUDIT_HOST_TOKENS_RESERVED);
	selinux_audit_host_refill = jiffies;
	spin_unlock_irqrestore(&selinux_audit_host_lock, flags);
}
#endif
