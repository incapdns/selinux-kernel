// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/static_stub.h>
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/security.h>

#include "kernfs-internal.h"

struct kernfs_root_test_ctx {
	int alloc_error;
	int node_error;
	unsigned int alloc_calls;
	unsigned int node_calls;
	unsigned int sb_calls;
	struct super_block *last_sb;
	const void *expected_root_security;
	struct completion free_done;
};

static struct kernfs_root_test_ctx *kernfs_root_test_current(void)
{
	struct kunit *test = kunit_get_current_test();

	return test->priv;
}

static int kernfs_root_test_alloc(void **root_security)
{
	struct kernfs_root_test_ctx *ctx = kernfs_root_test_current();

	ctx->alloc_calls++;
	if (ctx->alloc_error)
		return ctx->alloc_error;
	*root_security = ctx;
	return 0;
}

static int kernfs_root_test_node(struct kernfs_node *parent,
				 struct kernfs_node *kn,
				 const void *root_security)
{
	struct kunit *test = kunit_get_current_test();
	struct kernfs_root_test_ctx *ctx = test->priv;

	KUNIT_EXPECT_NOT_NULL(test, parent);
	KUNIT_EXPECT_NOT_NULL(test, kn);
	KUNIT_EXPECT_PTR_EQ(test, root_security, ctx->expected_root_security);
	ctx->node_calls++;
	return ctx->node_error;
}

static int kernfs_root_test_to_sb(struct super_block *sb,
				  const void *root_security)
{
	struct kunit *test = kunit_get_current_test();
	struct kernfs_root_test_ctx *ctx = test->priv;

	KUNIT_EXPECT_PTR_EQ(test, root_security, ctx->expected_root_security);
	ctx->last_sb = sb;
	ctx->sb_calls++;
	return 0;
}

KUNIT_DEFINE_ACTION_WRAPPER(kernfs_root_test_destroy, kernfs_destroy_root,
			    struct kernfs_root *);

static void kernfs_root_test_init_stubs(struct kunit *test)
{
	struct kernfs_root_test_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;
	init_completion(&ctx->free_done);
	kunit_activate_static_stub(test, security_kernfs_init_security,
				   kernfs_root_test_node);
	kunit_activate_static_stub(test, security_kernfs_root_to_sb,
				   kernfs_root_test_to_sb);
}

static void kernfs_root_test_free_done(void *data)
{
	complete(data);
}

static unsigned int kernfs_root_test_id_count(struct kernfs_root *root)
{
	struct kernfs_node *kn;
	unsigned long id, tmp;
	unsigned int count = 0;

	idr_for_each_entry_ul(&root->ino_idr, kn, tmp, id)
		count++;
	return count;
}

static void kernfs_root_security_final_ref_test(struct kunit *test)
{
	struct kernfs_root_test_ctx *ctx;
	struct kernfs_root *root;
	struct kernfs_node *kn;
	bool pending;

	kernfs_root_test_init_stubs(test);
	ctx = test->priv;
	root = kernfs_create_root(NULL, KERNFS_ROOT_CREATE_DEACTIVATED, NULL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(root));
	ctx->expected_root_security = root->security;
	root->security_free_done = kernfs_root_test_free_done;
	root->security_free_done_data = &ctx->free_done;

	kn = root->kn;
	kernfs_get(kn);
	kernfs_destroy_root(root);
	KUNIT_EXPECT_FALSE(test, completion_done(&ctx->free_done));
	rcu_read_lock();
	kernfs_put(kn);
	pending = !completion_done(&ctx->free_done);
	rcu_read_unlock();
	KUNIT_EXPECT_TRUE(test, pending);
	rcu_barrier();
	KUNIT_EXPECT_TRUE(test, completion_done(&ctx->free_done));
}

static void kernfs_root_security_alloc_failure_test(struct kunit *test)
{
	struct kernfs_root_test_ctx *ctx;
	struct kernfs_root *root;

	kernfs_root_test_init_stubs(test);
	ctx = test->priv;
	ctx->alloc_error = -EACCES;
	kunit_activate_static_stub(test, security_kernfs_root_alloc,
				   kernfs_root_test_alloc);
	root = kernfs_create_root(NULL, KERNFS_ROOT_CREATE_DEACTIVATED, NULL);
	KUNIT_ASSERT_TRUE(test, IS_ERR(root));
	KUNIT_EXPECT_EQ(test, PTR_ERR(root), -EACCES);
	KUNIT_EXPECT_EQ(test, ctx->alloc_calls, 1U);
}

static void kernfs_root_security_node_rollback_test(struct kunit *test)
{
	struct kernfs_root_test_ctx *ctx;
	struct kernfs_root *root;
	struct kernfs_node *child;
	int rc;

	kernfs_root_test_init_stubs(test);
	ctx = test->priv;
	root = kernfs_create_root(NULL, KERNFS_ROOT_CREATE_DEACTIVATED, NULL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(root));
	ctx->expected_root_security = root->security;
	rc = kunit_add_action_or_reset(test, kernfs_root_test_destroy, root);
	KUNIT_ASSERT_EQ(test, rc, 0);

	child = kernfs_create_dir(root->kn, "accepted", 0500, NULL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(child));
	KUNIT_EXPECT_EQ(test, ctx->node_calls, 1U);
	kernfs_remove(child);
	KUNIT_EXPECT_EQ(test, kernfs_root_test_id_count(root), 1U);

	ctx->node_error = -EACCES;
	child = kernfs_create_dir(root->kn, "rejected", 0500, NULL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(child));
	KUNIT_EXPECT_EQ(test, ctx->node_calls, 2U);
	KUNIT_EXPECT_EQ(test, kernfs_root_test_id_count(root), 1U);
}

static void kernfs_root_security_sb_argument_test(struct kunit *test)
{
	struct kernfs_root_test_ctx *ctx;
	struct kernfs_root *root;
	struct super_block *sb;
	int rc;

	kernfs_root_test_init_stubs(test);
	ctx = test->priv;
	sb = kunit_kzalloc(test, sizeof(*sb), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, sb);
	root = kernfs_create_root(NULL, KERNFS_ROOT_CREATE_DEACTIVATED, NULL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(root));
	ctx->expected_root_security = root->security;
	rc = kunit_add_action_or_reset(test, kernfs_root_test_destroy, root);
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = security_kernfs_root_to_sb(sb, root->security);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, ctx->sb_calls, 1U);
	KUNIT_EXPECT_PTR_EQ(test, ctx->last_sb, sb);
}

static struct kunit_case kernfs_root_security_test_cases[] = {
	KUNIT_CASE(kernfs_root_security_final_ref_test),
	KUNIT_CASE(kernfs_root_security_alloc_failure_test),
	KUNIT_CASE(kernfs_root_security_node_rollback_test),
	KUNIT_CASE(kernfs_root_security_sb_argument_test),
	{}
};

static struct kunit_suite kernfs_root_security_test_suite = {
	.name = "kernfs-root-security",
	.test_cases = kernfs_root_security_test_cases,
};

kunit_test_suite(kernfs_root_security_test_suite);

MODULE_LICENSE("GPL");
