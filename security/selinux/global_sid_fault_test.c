// SPDX-License-Identifier: GPL-2.0-only
/* Deterministic rollback tests for global SID publication failures. */

#include <kunit/test.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/string.h>
#include <linux/user_namespace.h>

#include "include/global_sidtab.h"
#include "include/label.h"
#include "include/resource.h"
#include "include/security.h"

struct global_sid_fault_case {
	enum selinux_kunit_global_sid_fault fault;
	const char *context;
	int error;
};

static const struct global_sid_fault_case global_sid_fault_cases[] = {
	{
		.fault = SELINUX_KUNIT_GLOBAL_SID_FAULT_OWNER_RESERVE,
		.context = "u:r:global_sid_owner_reserve_fault_kunit_t:s0",
		.error = -EDQUOT,
	},
	{
		.fault = SELINUX_KUNIT_GLOBAL_SID_FAULT_TOMBSTONE_RESERVE,
		.context = "u:r:global_sid_tombstone_reserve_fault_kunit_t:s0",
		.error = -EDQUOT,
	},
	{
		.fault = SELINUX_KUNIT_GLOBAL_SID_FAULT_HANDLE_ALLOC,
		.context = "u:r:global_sid_handle_alloc_fault_kunit_t:s0",
		.error = -ENOMEM,
	},
	{
		.fault = SELINUX_KUNIT_GLOBAL_SID_FAULT_TOMBSTONE_ALLOC,
		.context = "u:r:global_sid_tombstone_alloc_fault_kunit_t:s0",
		.error = -ENOMEM,
	},
	{
		.fault = SELINUX_KUNIT_GLOBAL_SID_FAULT_XA_STORE,
		.context = "u:r:global_sid_xa_store_fault_kunit_t:s0",
		.error = -ENOMEM,
	},
};

static void global_sid_fault_state_init(struct selinux_state *state,
					struct selinux_label_domain *domain)
{
	memset(state, 0, sizeof(*state));
	INIT_LIST_HEAD(&state->children);
	INIT_LIST_HEAD(&state->sibling);
	atomic64_set(&state->chain_epoch, 1);
	state->label_domain = domain;
}

static u64 sid_fault_owner_objects(struct selinux_label_domain *domain)
{
	return selinux_kunit_resource_objects(domain->resources,
					       SELINUX_RESOURCE_GLOBAL_SID);
}

static u64 sid_fault_owner_bytes(struct selinux_label_domain *domain)
{
	return selinux_kunit_resource_bytes(domain->resources,
					     SELINUX_RESOURCE_GLOBAL_SID);
}

static struct selinux_global_sid_handle *
sid_fault_create(struct selinux_state *state, const char *context, u32 *sid)
{
	return selinux_kunit_global_context_to_handle(state, context, sid);
}

static void sid_fault_cleanup(struct selinux_global_sid_handle *handle,
			      u32 sid)
{
	if (IS_ERR_OR_NULL(handle))
		return;
	if (sid > SECINITSID_NUM && selinux_kunit_global_sid_live(sid))
		selinux_kunit_global_sid_drop_baseline(sid);
	global_sid_handle_put(handle);
	selinux_label_domain_kunit_drain();
}

static void sid_fault_run(struct kunit *test, struct selinux_state *state,
			  struct selinux_label_domain *domain,
			  const struct global_sid_fault_case *fault_case)
{
	struct selinux_global_sid_handle *handle = NULL, *lookup;
	struct selinux_label_ref *label;
	u64 owner_objects, owner_bytes, global_objects, global_bytes;
	u32 failed_sid, sid = U32_MAX;
	int label_refs, rc;

	label = selinux_label_ref_intern(domain, fault_case->context,
					 strlen(fault_case->context) + 1,
					 GFP_KERNEL);
	if (IS_ERR(label)) {
		KUNIT_FAIL(test, "label setup failed for fault %u: %ld",
			   (unsigned int)fault_case->fault, PTR_ERR(label));
		return;
	}

	/* Exclude earlier tests' deferred payload releases from this baseline. */
	selinux_label_domain_kunit_drain();
	owner_objects = sid_fault_owner_objects(domain);
	owner_bytes = sid_fault_owner_bytes(domain);
	global_objects = selinux_kunit_resource_global_objects();
	global_bytes = selinux_kunit_resource_global_bytes();
	label_refs = refcount_read(&label->refs);

	selinux_kunit_global_sid_fault_reset();
	rc = selinux_kunit_global_sid_fault_arm(fault_case->fault);
	if (rc) {
		KUNIT_FAIL(test, "fault %u arm failed: %d",
			   (unsigned int)fault_case->fault, rc);
		goto out_label;
	}
	handle = sid_fault_create(state, fault_case->context, &sid);
	KUNIT_EXPECT_TRUE_MSG(test, IS_ERR(handle),
			      "fault %u unexpectedly published SID %u",
			      (unsigned int)fault_case->fault, sid);
	if (!IS_ERR(handle))
		goto out_handle;
	KUNIT_EXPECT_EQ_MSG(test, PTR_ERR(handle), (long)fault_case->error,
			    "fault %u returned the wrong errno",
			    (unsigned int)fault_case->fault);
	handle = NULL;
	KUNIT_EXPECT_EQ(test, sid, (u32)U32_MAX);

	failed_sid = selinux_kunit_global_sid_fault_last_sid();
	KUNIT_EXPECT_GT(test, failed_sid, (u32)SECINITSID_NUM);
	KUNIT_EXPECT_EQ(test, selinux_kunit_global_sid_entry_sid(failed_sid),
			(u32)0);
	lookup = global_sid_handle_get(failed_sid);
	KUNIT_EXPECT_TRUE_MSG(test, IS_ERR(lookup),
			      "fault %u left SID %u published",
			      (unsigned int)fault_case->fault, failed_sid);
	if (IS_ERR(lookup))
		KUNIT_EXPECT_EQ(test, PTR_ERR(lookup), (long)-EINVAL);
	else
		sid_fault_cleanup(lookup, failed_sid);

	KUNIT_EXPECT_EQ(test, sid_fault_owner_objects(domain), owner_objects);
	KUNIT_EXPECT_EQ(test, sid_fault_owner_bytes(domain), owner_bytes);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_objects(),
			global_objects);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_bytes(),
			global_bytes);
	KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), label_refs);

	/* A consumed one-shot must permit the immediately following attempt. */
	sid = U32_MAX;
	handle = sid_fault_create(state, fault_case->context, &sid);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, handle);
	if (IS_ERR_OR_NULL(handle))
		goto out_label;
	KUNIT_EXPECT_GT(test, sid, failed_sid);
	KUNIT_EXPECT_EQ(test, global_sid_handle_sid(handle), sid);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(sid));
	KUNIT_EXPECT_EQ(test, sid_fault_owner_objects(domain),
			owner_objects + 1);
	KUNIT_EXPECT_GT(test, sid_fault_owner_bytes(domain), owner_bytes);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_objects(),
			global_objects + 2);
	KUNIT_EXPECT_GT(test, selinux_kunit_resource_global_bytes(),
			global_bytes);
	KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), label_refs + 1);

out_handle:
	sid_fault_cleanup(handle, sid);
	KUNIT_EXPECT_EQ(test, sid_fault_owner_objects(domain), owner_objects);
	KUNIT_EXPECT_EQ(test, sid_fault_owner_bytes(domain), owner_bytes);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_objects(),
			global_objects + 1);
	KUNIT_EXPECT_GT(test, selinux_kunit_resource_global_bytes(),
			global_bytes);
	KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), label_refs);
out_label:
	selinux_kunit_global_sid_fault_reset();
	selinux_label_ref_put(label);
}

static void selinux_global_sid_fault_rollback_test(struct kunit *test)
{
	struct selinux_label_domain *domain;
	struct selinux_state state;
	size_t i;

	domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, domain);
	global_sid_fault_state_init(&state, domain);
	for (i = 0; i < ARRAY_SIZE(global_sid_fault_cases); i++)
		sid_fault_run(test, &state, domain,
			      &global_sid_fault_cases[i]);
	selinux_kunit_global_sid_fault_reset();
	selinux_label_domain_put(domain);
}

static struct kunit_case selinux_global_sid_fault_test_cases[] = {
	KUNIT_CASE(selinux_global_sid_fault_rollback_test),
	{}
};

static struct kunit_suite selinux_global_sid_fault_test_suite = {
	.name = "selinux-global-sid-fault",
	.test_cases = selinux_global_sid_fault_test_cases,
};

kunit_test_suite(selinux_global_sid_fault_test_suite);

MODULE_LICENSE("GPL");
