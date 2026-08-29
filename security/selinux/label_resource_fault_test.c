// SPDX-License-Identifier: GPL-2.0-only
/* Deterministic rollback tests for labels and resource accounts. */

#include <kunit/test.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/string.h>
#include <linux/user_namespace.h>

#include "include/label.h"
#include "include/resource.h"

struct selinux_label_fault_snapshot {
	int count;
	long bytes;
	u32 domain_refs;
	u32 account_refs;
	u64 owner_objects;
	u64 owner_bytes;
	u64 total_objects;
	u64 total_bytes;
	u64 global_objects;
	u64 global_bytes;
};

static void selinux_label_fault_snapshot(
	struct selinux_label_domain *domain,
	struct selinux_label_fault_snapshot *snapshot)
{
	struct selinux_resource_account *account = domain->resources;

	snapshot->count = atomic_read(&domain->label_count);
	snapshot->bytes = atomic_long_read(&domain->label_bytes);
	snapshot->domain_refs = refcount_read(&domain->refs);
	snapshot->account_refs = selinux_kunit_resource_account_refs(account);
	snapshot->owner_objects = selinux_kunit_resource_objects(
		account, SELINUX_RESOURCE_LABEL);
	snapshot->owner_bytes = selinux_kunit_resource_bytes(
		account, SELINUX_RESOURCE_LABEL);
	snapshot->total_objects =
		selinux_kunit_resource_total_objects(account);
	snapshot->total_bytes = selinux_kunit_resource_total_bytes(account);
	snapshot->global_objects = selinux_kunit_resource_global_objects();
	snapshot->global_bytes = selinux_kunit_resource_global_bytes();
}

static void selinux_label_fault_expect_snapshot(
	struct kunit *test, struct selinux_label_domain *domain,
	const struct selinux_label_fault_snapshot *snapshot)
{
	struct selinux_resource_account *account = domain->resources;

	KUNIT_EXPECT_EQ(test, atomic_read(&domain->label_count), snapshot->count);
	KUNIT_EXPECT_EQ(test, atomic_long_read(&domain->label_bytes),
			snapshot->bytes);
	KUNIT_EXPECT_EQ(test, refcount_read(&domain->refs),
			snapshot->domain_refs);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_account_refs(account),
			snapshot->account_refs);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_objects(
		account, SELINUX_RESOURCE_LABEL), snapshot->owner_objects);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_bytes(
		account, SELINUX_RESOURCE_LABEL), snapshot->owner_bytes);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_total_objects(account),
			snapshot->total_objects);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_total_bytes(account),
			snapshot->total_bytes);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_objects(),
			snapshot->global_objects);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_bytes(),
			snapshot->global_bytes);
}

static void selinux_label_fault_run(
	struct kunit *test, enum selinux_label_kunit_fault fault,
	const char *context, int error)
{
	struct selinux_label_fault_snapshot before;
	struct selinux_label_domain *domain;
	struct selinux_label_ref *label;
	size_t context_len = strlen(context) + 1;
	u64 bytes = sizeof(*label) + context_len;

	domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, domain);
	selinux_label_domain_kunit_drain();
	selinux_label_fault_snapshot(domain, &before);

	selinux_label_kunit_fail_next(domain, fault);
	label = selinux_label_ref_intern(domain, context, context_len,
					 GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(label));
	if (!IS_ERR(label)) {
		selinux_label_ref_put(label);
		goto out;
	}
	KUNIT_EXPECT_EQ(test, PTR_ERR(label), (long)error);
	KUNIT_EXPECT_FALSE(test, selinux_label_kunit_context_published(
				 domain, context, context_len));
	selinux_label_fault_expect_snapshot(test, domain, &before);

	/* Consuming the one-shot must make an immediate retry publishable. */
	label = selinux_label_ref_intern(domain, context, context_len,
					 GFP_KERNEL);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, label);
	if (IS_ERR_OR_NULL(label))
		goto out;
	KUNIT_EXPECT_TRUE(test, selinux_label_kunit_context_published(
				domain, context, context_len));
	KUNIT_EXPECT_EQ(test, atomic_read(&domain->label_count),
			before.count + 1);
	KUNIT_EXPECT_EQ(test, atomic_long_read(&domain->label_bytes),
			before.bytes + (long)bytes);
	KUNIT_EXPECT_EQ(test, refcount_read(&domain->refs),
			before.domain_refs + 1);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_objects(
		domain->resources, SELINUX_RESOURCE_LABEL),
		before.owner_objects + 1);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_bytes(
		domain->resources, SELINUX_RESOURCE_LABEL),
		before.owner_bytes + bytes);

	selinux_label_ref_put(label);
	KUNIT_EXPECT_FALSE(test, selinux_label_kunit_context_published(
				 domain, context, context_len));
	selinux_label_fault_expect_snapshot(test, domain, &before);

out:
	selinux_label_kunit_fail_next(NULL, SELINUX_LABEL_KUNIT_FAULT_NONE);
	selinux_label_domain_put(domain);
}

static void selinux_label_reserve_fault_test(struct kunit *test)
{
	selinux_label_fault_run(test, SELINUX_LABEL_KUNIT_FAULT_RESERVE,
		"u:object_r:label_reserve_fault_kunit_t:s0", -EDQUOT);
}

static void selinux_label_alloc_fault_test(struct kunit *test)
{
	selinux_label_fault_run(test, SELINUX_LABEL_KUNIT_FAULT_ALLOC,
		"u:object_r:label_alloc_fault_kunit_t:s0", -ENOMEM);
}

static void selinux_label_hash_insert_fault_test(struct kunit *test)
{
	selinux_label_fault_run(test, SELINUX_LABEL_KUNIT_FAULT_HASH_INSERT,
		"u:object_r:label_hash_fault_kunit_t:s0", -ENOMEM);
}

static void selinux_resource_test_owner_init(struct user_namespace *owner)
{
	memset(owner, 0, sizeof(*owner));
	refcount_set(&owner->ns.__ns_ref, 1);
}

static void selinux_resource_account_fault_run(
	struct kunit *test, enum selinux_resource_account_kunit_fault fault)
{
	struct selinux_resource_account *account;
	struct user_namespace owner;

	selinux_resource_test_owner_init(&owner);
	KUNIT_ASSERT_FALSE(test,
			   selinux_kunit_resource_account_published(&owner));
	selinux_resource_account_kunit_fail_next(&owner, fault);
	account = selinux_resource_account_get_owner(&owner);
	KUNIT_EXPECT_TRUE(test, IS_ERR(account));
	if (!IS_ERR(account)) {
		selinux_resource_account_put(account);
		rcu_barrier();
		goto out;
	}
	KUNIT_EXPECT_EQ(test, PTR_ERR(account), (long)-ENOMEM);
	KUNIT_EXPECT_FALSE(test,
			   selinux_kunit_resource_account_published(&owner));
	KUNIT_EXPECT_EQ(test, refcount_read(&owner.ns.__ns_ref), 1);

	/* No stale candidate may obstruct the successful retry. */
	account = selinux_resource_account_get_owner(&owner);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, account);
	if (IS_ERR_OR_NULL(account))
		goto out;
	KUNIT_EXPECT_TRUE(test,
			  selinux_kunit_resource_account_published(&owner));
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_account_refs(account),
			(u32)1);
	KUNIT_EXPECT_EQ(test, refcount_read(&owner.ns.__ns_ref), 2);
	selinux_resource_account_put(account);
	selinux_label_domain_kunit_drain();
	KUNIT_EXPECT_FALSE(test,
			   selinux_kunit_resource_account_published(&owner));
	KUNIT_EXPECT_EQ(test, refcount_read(&owner.ns.__ns_ref), 1);

out:
	selinux_resource_account_kunit_fail_next(
		NULL, SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_NONE);
}

static void selinux_resource_account_alloc_fault_test(struct kunit *test)
{
	selinux_resource_account_fault_run(
		test, SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_ALLOC);
}

static void selinux_resource_account_hash_fault_test(struct kunit *test)
{
	selinux_resource_account_fault_run(
		test, SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_HASH_INSERT);
}

struct selinux_resource_fault_snapshot {
	u32 refs;
	u64 objects;
	u64 bytes;
	u64 total_objects;
	u64 total_bytes;
	u64 global_objects;
	u64 global_bytes;
};

static void selinux_resource_fault_snapshot(
	struct selinux_resource_account *account,
	struct selinux_resource_fault_snapshot *snapshot)
{
	snapshot->refs = selinux_kunit_resource_account_refs(account);
	snapshot->objects = selinux_kunit_resource_objects(
		account, SELINUX_RESOURCE_LABEL);
	snapshot->bytes = selinux_kunit_resource_bytes(
		account, SELINUX_RESOURCE_LABEL);
	snapshot->total_objects =
		selinux_kunit_resource_total_objects(account);
	snapshot->total_bytes = selinux_kunit_resource_total_bytes(account);
	snapshot->global_objects = selinux_kunit_resource_global_objects();
	snapshot->global_bytes = selinux_kunit_resource_global_bytes();
}

static void selinux_resource_fault_expect_snapshot(
	struct kunit *test, struct selinux_resource_account *account,
	const struct selinux_resource_fault_snapshot *snapshot)
{
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_account_refs(account),
			snapshot->refs);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_objects(
		account, SELINUX_RESOURCE_LABEL), snapshot->objects);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_bytes(
		account, SELINUX_RESOURCE_LABEL), snapshot->bytes);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_total_objects(account),
			snapshot->total_objects);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_total_bytes(account),
			snapshot->total_bytes);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_objects(),
			snapshot->global_objects);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_bytes(),
			snapshot->global_bytes);
}

static void selinux_resource_reserve_fault_run(
	struct kunit *test, enum selinux_resource_reserve_kunit_fault fault)
{
	struct selinux_resource_fault_snapshot before;
	struct selinux_resource_account *account;
	struct user_namespace owner;
	const u64 objects = 2;
	const u64 bytes = 37;
	int rc;

	selinux_resource_test_owner_init(&owner);
	account = selinux_resource_account_get_owner(&owner);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, account);
	selinux_label_domain_kunit_drain();
	selinux_resource_fault_snapshot(account, &before);
	selinux_resource_reserve_kunit_fail_next(account, fault);
	rc = selinux_resource_reserve(account, SELINUX_RESOURCE_LABEL,
				      objects, bytes);
	KUNIT_EXPECT_EQ(test, rc, -EDQUOT);
	if (!rc) {
		selinux_resource_release(account, SELINUX_RESOURCE_LABEL,
					 objects, bytes);
		goto out_account;
	}
	if (rc != -EDQUOT)
		goto out_account;
	selinux_resource_fault_expect_snapshot(test, account, &before);

	/* The fault is one-shot; the exact same reservation must now succeed. */
	rc = selinux_resource_reserve(account, SELINUX_RESOURCE_LABEL,
				      objects, bytes);
	KUNIT_EXPECT_EQ(test, rc, 0);
	if (!rc) {
		KUNIT_EXPECT_EQ(test, selinux_kunit_resource_account_refs(account),
				before.refs);
		KUNIT_EXPECT_EQ(test, selinux_kunit_resource_objects(
			account, SELINUX_RESOURCE_LABEL), before.objects + objects);
		KUNIT_EXPECT_EQ(test, selinux_kunit_resource_bytes(
			account, SELINUX_RESOURCE_LABEL), before.bytes + bytes);
		KUNIT_EXPECT_EQ(test, selinux_kunit_resource_total_objects(account),
				before.total_objects + objects);
		KUNIT_EXPECT_EQ(test, selinux_kunit_resource_total_bytes(account),
				before.total_bytes + bytes);
		KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_objects(),
				before.global_objects + objects);
		KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_bytes(),
				before.global_bytes + bytes);
		selinux_resource_release(account, SELINUX_RESOURCE_LABEL,
					 objects, bytes);
	}
out_account:
	selinux_resource_fault_expect_snapshot(test, account, &before);
	selinux_resource_reserve_kunit_fail_next(
		NULL, SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_NONE);
	selinux_resource_account_put(account);
	rcu_barrier();
	KUNIT_EXPECT_FALSE(test,
			   selinux_kunit_resource_account_published(&owner));
	KUNIT_EXPECT_EQ(test, refcount_read(&owner.ns.__ns_ref), 1);
}

static void selinux_resource_global_bytes_fault_test(struct kunit *test)
{
	selinux_resource_reserve_fault_run(
		test, SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_GLOBAL_BYTES);
}

static void selinux_resource_global_objects_fault_test(struct kunit *test)
{
	selinux_resource_reserve_fault_run(
		test, SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_GLOBAL_OBJECTS);
}

static void selinux_resource_owner_objects_fault_test(struct kunit *test)
{
	selinux_resource_reserve_fault_run(
		test, SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_OWNER_OBJECTS);
}

static void selinux_resource_owner_bytes_fault_test(struct kunit *test)
{
	selinux_resource_reserve_fault_run(
		test, SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_OWNER_BYTES);
}

static int selinux_label_resource_fault_test_init(struct kunit *test)
{
	(void)test;
	selinux_label_kunit_fail_next(NULL, SELINUX_LABEL_KUNIT_FAULT_NONE);
	selinux_resource_account_kunit_fail_next(
		NULL, SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_NONE);
	selinux_resource_reserve_kunit_fail_next(
		NULL, SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_NONE);
	return 0;
}

static void selinux_label_resource_fault_test_exit(struct kunit *test)
{
	(void)test;
	selinux_label_kunit_fail_next(NULL, SELINUX_LABEL_KUNIT_FAULT_NONE);
	selinux_resource_account_kunit_fail_next(
		NULL, SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_NONE);
	selinux_resource_reserve_kunit_fail_next(
		NULL, SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_NONE);
}

static struct kunit_case selinux_label_resource_fault_test_cases[] = {
	KUNIT_CASE(selinux_label_reserve_fault_test),
	KUNIT_CASE(selinux_label_alloc_fault_test),
	KUNIT_CASE(selinux_label_hash_insert_fault_test),
	KUNIT_CASE(selinux_resource_account_alloc_fault_test),
	KUNIT_CASE(selinux_resource_account_hash_fault_test),
	KUNIT_CASE(selinux_resource_global_objects_fault_test),
	KUNIT_CASE(selinux_resource_global_bytes_fault_test),
	KUNIT_CASE(selinux_resource_owner_objects_fault_test),
	KUNIT_CASE(selinux_resource_owner_bytes_fault_test),
	{}
};

static struct kunit_suite selinux_label_resource_fault_test_suite = {
	.name = "selinux-label-resource-fault",
	.init = selinux_label_resource_fault_test_init,
	.exit = selinux_label_resource_fault_test_exit,
	.test_cases = selinux_label_resource_fault_test_cases,
};

kunit_test_suite(selinux_label_resource_fault_test_suite);

MODULE_DESCRIPTION("KUnit tests for SELinux label and resource rollback");
MODULE_LICENSE("GPL");
