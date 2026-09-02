// SPDX-License-Identifier: GPL-2.0-only
/* Structural KUnit tests for policy-local SELinux object labels. */

#include <kunit/test.h>
#include <linux/cred.h>
#include <linux/err.h>

#include "flask.h"
#include "object_label.h"
#include "resource.h"
#include "security.h"

struct selinux_local_label_fixture {
	struct selinux_state *parent;
	struct selinux_state *child;
	struct selinux_object_identity *object;
};

static int selinux_local_label_test_init(struct kunit *test)
{
	struct selinux_local_label_fixture *fixture;

	fixture = kunit_kzalloc(test, sizeof(*fixture), GFP_KERNEL);
	if (!fixture)
		return -ENOMEM;
	fixture->parent = get_selinux_state(current_selinux_state);
	fixture->child = selinux_state_create_dormant(current_cred());
	if (IS_ERR(fixture->child)) {
		int rc = PTR_ERR(fixture->child);

		fixture->child = NULL;
		put_selinux_state(fixture->parent);
		fixture->parent = NULL;
		return rc;
	}
	fixture->object = selinux_object_identity_alloc(
		fixture->child,
		GFP_KERNEL_ACCOUNT);
	if (IS_ERR(fixture->object)) {
		int rc = PTR_ERR(fixture->object);

		fixture->object = NULL;
		put_selinux_state(fixture->child);
		put_selinux_state(fixture->parent);
		fixture->child = NULL;
		fixture->parent = NULL;
		return rc;
	}
	test->priv = fixture;
	return 0;
}

static void selinux_local_label_test_exit(struct kunit *test)
{
	struct selinux_local_label_fixture *fixture = test->priv;

	selinux_object_identity_put(fixture->object);
	put_selinux_state(fixture->child);
	put_selinux_state(fixture->parent);
}

static struct selinux_object_label_value test_label(u32 sid)
{
	return (struct selinux_object_label_value) {
		.sid = sid,
		.sclass = SECCLASS_FILE,
		.source = SELINUX_LABEL_SOURCE_SECURITY_CONTEXT,
	};
}

static void test_object_put(void *data)
{
	selinux_object_identity_put(data);
}

static void selinux_policy_local_labels_are_independent(struct kunit *test)
{
	struct selinux_local_label_fixture *fixture = test->priv;
	struct selinux_object_label_value parent = test_label(101);
	struct selinux_object_label_value child = test_label(202);
	struct selinux_object_label_value observed = {};

	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_set(fixture->parent, fixture->object,
						  &parent, GFP_KERNEL),
			 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_set(fixture->child, fixture->object,
						  &child, GFP_KERNEL),
			 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_get(fixture->parent, fixture->object,
						  &observed),
			 0);
	KUNIT_EXPECT_EQ(test, observed.sid, parent.sid);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_get(fixture->child, fixture->object,
						  &observed),
			 0);
	KUNIT_EXPECT_EQ(test, observed.sid, child.sid);

	child.sid = 303;
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_set(fixture->child, fixture->object,
						  &child, GFP_KERNEL),
			 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_get(fixture->parent, fixture->object,
						  &observed),
			 0);
	KUNIT_EXPECT_EQ(test, observed.sid, parent.sid);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_get(fixture->child, fixture->object,
						  &observed),
			 0);
	KUNIT_EXPECT_EQ(test, observed.sid, child.sid);
}

static void selinux_missing_policy_label_is_local_unlabeled(struct kunit *test)
{
	struct selinux_local_label_fixture *fixture = test->priv;
	struct selinux_object_label_value parent = test_label(404);
	struct selinux_object_label_value observed = {};

	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_set(fixture->parent, fixture->object,
						  &parent, GFP_KERNEL),
			 0);
	KUNIT_EXPECT_EQ(test,
			 selinux_object_label_get(fixture->child, fixture->object,
						  &observed),
			 -ENOENT);
	selinux_object_label_get_or_unlabeled(fixture->child, fixture->object,
					       SECCLASS_FILE, &observed);
	KUNIT_EXPECT_EQ(test, observed.sid, (u32)SECINITSID_UNLABELED);
	KUNIT_EXPECT_EQ(test, observed.sclass, (u16)SECCLASS_FILE);
}

static void selinux_guarded_updates_are_atomic(struct kunit *test)
{
	struct selinux_local_label_fixture *fixture = test->priv;
	struct selinux_object_identity *second;
	struct selinux_object_label_value first_before = test_label(501);
	struct selinux_object_label_value second_before = test_label(502);
	struct selinux_object_label_value first_after = test_label(601);
	struct selinux_object_label_value second_after = test_label(602);
	struct selinux_object_label_value observed = {};
	struct selinux_object_label_update updates[2];
	struct selinux_object_generation_guard guards[2];
	u64 first_generation, second_generation;

	second = selinux_object_identity_alloc(fixture->child,
					       GFP_KERNEL_ACCOUNT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, second);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, test_object_put,
						       second), 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_set(fixture->child, fixture->object,
						  &first_before, GFP_KERNEL),
			 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_set(fixture->child, second,
						  &second_before, GFP_KERNEL),
			 0);
	first_generation = selinux_object_identity_generation(fixture->object);
	second_generation = selinux_object_identity_generation(second);
	updates[0] = (struct selinux_object_label_update) {
		.state = fixture->child,
		.object = fixture->object,
		.value = first_after,
		.expected_generation = first_generation,
	};
	updates[1] = (struct selinux_object_label_update) {
		.state = fixture->child,
		.object = second,
		.value = second_after,
		.expected_generation = second_generation,
	};
	guards[0] = (struct selinux_object_generation_guard) {
		.object = fixture->object,
		.generation = first_generation,
	};
	guards[1] = (struct selinux_object_generation_guard) {
		.object = second,
		.generation = second_generation,
	};
	KUNIT_ASSERT_EQ(test,
			 selinux_object_labels_update_transaction_guarded(
				 updates, ARRAY_SIZE(updates), guards,
				 ARRAY_SIZE(guards), GFP_KERNEL),
			 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_get(fixture->child, fixture->object,
						  &observed),
			 0);
	KUNIT_EXPECT_EQ(test, observed.sid, first_after.sid);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_get(fixture->child, second, &observed),
			 0);
	KUNIT_EXPECT_EQ(test, observed.sid, second_after.sid);

	KUNIT_EXPECT_EQ(test,
			 selinux_object_labels_update_transaction_guarded(
				 updates, ARRAY_SIZE(updates), guards,
				 ARRAY_SIZE(guards), GFP_KERNEL),
			 -ESTALE);
}

static void selinux_clone_copies_each_policy_label(struct kunit *test)
{
	struct selinux_local_label_fixture *fixture = test->priv;
	struct selinux_object_identity *clone;
	struct selinux_object_label_value parent = test_label(701);
	struct selinux_object_label_value child = test_label(702);
	struct selinux_object_label_value observed = {};

	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_set(fixture->parent, fixture->object,
						  &parent, GFP_KERNEL),
			 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_set(fixture->child, fixture->object,
						  &child, GFP_KERNEL),
			 0);
	clone = selinux_object_identity_clone_for_state(fixture->object,
							fixture->child,
							GFP_KERNEL_ACCOUNT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, clone);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, test_object_put,
						       clone), 0);
	KUNIT_EXPECT_NE(test, clone->id, fixture->object->id);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_get(fixture->parent, clone, &observed),
			 0);
	KUNIT_EXPECT_EQ(test, observed.sid, parent.sid);
	KUNIT_ASSERT_EQ(test,
			 selinux_object_label_get(fixture->child, clone, &observed),
			 0);
	KUNIT_EXPECT_EQ(test, observed.sid, child.sid);
}

static void selinux_initial_state_is_not_child_quota_limited(
	struct kunit *test)
{
	struct selinux_local_label_fixture *fixture = test->priv;
	struct selinux_resource_account *resources =
		fixture->parent->resources;
	u64 global_objects = selinux_kunit_resource_global_objects();
	u64 global_bytes = selinux_kunit_resource_global_bytes();
	u64 owner_objects = selinux_kunit_resource_total_objects(resources);
	u64 owner_bytes = selinux_kunit_resource_total_bytes(resources);
	u64 objects = CONFIG_SECURITY_SELINUX_RESOURCE_OBJECTS_PER_USERNS + 1ULL;
	u64 bytes = 4096;

	KUNIT_ASSERT_EQ(test,
			 selinux_resource_reserve(
				 resources,
				 SELINUX_RESOURCE_OBJECT_IDENTITY,
				 objects,
				 bytes),
			 0);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_resource_total_objects(resources),
			owner_objects + objects);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_resource_total_bytes(resources),
			owner_bytes + bytes);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_resource_global_objects(),
			global_objects);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_resource_global_bytes(),
			global_bytes);

	selinux_resource_release(
		resources,
		SELINUX_RESOURCE_OBJECT_IDENTITY,
		objects,
		bytes);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_resource_total_objects(resources),
			owner_objects);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_resource_total_bytes(resources),
			owner_bytes);
}

static struct kunit_case selinux_local_label_test_cases[] = {
	KUNIT_CASE(selinux_policy_local_labels_are_independent),
	KUNIT_CASE(selinux_missing_policy_label_is_local_unlabeled),
	KUNIT_CASE(selinux_guarded_updates_are_atomic),
	KUNIT_CASE(selinux_clone_copies_each_policy_label),
	KUNIT_CASE(selinux_initial_state_is_not_child_quota_limited),
	{},
};

static struct kunit_suite selinux_local_label_test_suite = {
	.name = "selinux-local-label",
	.init = selinux_local_label_test_init,
	.exit = selinux_local_label_test_exit,
	.test_cases = selinux_local_label_test_cases,
};

kunit_test_suite(selinux_local_label_test_suite);

MODULE_LICENSE("GPL");
