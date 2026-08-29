// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/static_stub.h>
#include <kunit/test.h>
#include <linux/err.h>
#include <linux/kernfs.h>
#include <linux/module.h>
#include <linux/xattr.h>

#include "include/label.h"
#include "include/objsec.h"
#include "include/security.h"

static void *selinux_kernfs_test_root_blob(struct kunit *test)
{
	size_t size = selinux_blob_sizes.lbs_kernfs_root +
		      sizeof(struct kernfs_root_security_struct);

	return kunit_kzalloc(test, size, GFP_KERNEL);
}

static struct super_block *selinux_kernfs_test_sb(struct kunit *test)
{
	struct superblock_security_struct *sbsec;
	struct super_block *sb;
	size_t size;

	sb = kunit_kzalloc(test, sizeof(*sb), GFP_KERNEL);
	if (!sb)
		return NULL;
	size = selinux_blob_sizes.lbs_superblock + sizeof(*sbsec);
	sb->s_security = kunit_kzalloc(test, size, GFP_KERNEL);
	if (!sb->s_security)
		return NULL;
	sbsec = selinux_superblock(sb);
	mutex_init(&sbsec->lock);
	return sb;
}

KUNIT_DEFINE_ACTION_WRAPPER(selinux_kernfs_test_destroy_root,
			    kernfs_destroy_root, struct kernfs_root *);
KUNIT_DEFINE_ACTION_WRAPPER(selinux_kernfs_test_free_root_blob,
			    selinux_kunit_kernfs_root_free, void *);
KUNIT_DEFINE_ACTION_WRAPPER(selinux_kernfs_test_free_sb,
			    selinux_kunit_kernfs_sb_free,
			    struct super_block *);

static void selinux_kernfs_strong_anchor_test(struct kunit *test)
{
	struct kernfs_root_security_struct *rootsec;
	struct selinux_label_domain *domain;
	struct selinux_state *state;
	void *blob;
	int domain_refs, rc, state_refs;

	state = current_selinux_state;
	domain = state->label_domain;
	state_refs = refcount_read(&state->count);
	domain_refs = refcount_read(&domain->refs);
	blob = selinux_kernfs_test_root_blob(test);
	KUNIT_ASSERT_NOT_NULL(test, blob);

	rc = selinux_kunit_kernfs_root_alloc(blob);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = kunit_add_action_or_reset(test,
				       selinux_kernfs_test_free_root_blob, blob);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rootsec = selinux_kernfs_root_security(blob);
	KUNIT_EXPECT_PTR_EQ(test, rootsec->anchor_state, state);
	KUNIT_EXPECT_PTR_EQ(test, rootsec->anchor_domain, domain);
	KUNIT_EXPECT_EQ(test, refcount_read(&state->count), state_refs + 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&domain->refs), domain_refs + 1);

	kunit_remove_action(test, selinux_kernfs_test_free_root_blob, blob);
	selinux_kunit_kernfs_root_free(blob);
	KUNIT_EXPECT_EQ(test, refcount_read(&state->count), state_refs);
	KUNIT_EXPECT_EQ(test, refcount_read(&domain->refs), domain_refs);
}

static void selinux_kernfs_foreign_anchor_and_mismatch_test(struct kunit *test)
{
	struct kernfs_root_security_struct *rootsec, *mismatch;
	struct superblock_security_struct *sbsec1, *sbsec2;
	struct selinux_label_domain *domain, *other_domain;
	struct selinux_state *state, *other_state;
	struct super_block *sb1, *sb2;
	void *blob, *mismatch_blob;
	int rc;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	domain = kunit_kzalloc(test, sizeof(*domain), GFP_KERNEL);
	other_state = kunit_kzalloc(test, sizeof(*other_state), GFP_KERNEL);
	other_domain = kunit_kzalloc(test, sizeof(*other_domain), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	KUNIT_ASSERT_NOT_NULL(test, other_state);
	KUNIT_ASSERT_NOT_NULL(test, other_domain);
	refcount_set(&state->count, 2);
	refcount_set(&domain->refs, 2);
	WRITE_ONCE(state->active, true);
	state->depth = 1;
	domain->depth = 1;
	state->label_domain = domain;
	blob = selinux_kernfs_test_root_blob(test);
	mismatch_blob = selinux_kernfs_test_root_blob(test);
	KUNIT_ASSERT_NOT_NULL(test, blob);
	KUNIT_ASSERT_NOT_NULL(test, mismatch_blob);
	rootsec = selinux_kernfs_root_security(blob);
	mismatch = selinux_kernfs_root_security(mismatch_blob);
	rootsec->anchor_state = state;
	rootsec->anchor_domain = domain;

	sb1 = selinux_kernfs_test_sb(test);
	sb2 = selinux_kernfs_test_sb(test);
	KUNIT_ASSERT_NOT_NULL(test, sb1);
	KUNIT_ASSERT_NOT_NULL(test, sb2);
	rc = selinux_kunit_kernfs_root_to_sb(sb1, blob);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = kunit_add_action_or_reset(test, selinux_kernfs_test_free_sb, sb1);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = selinux_kunit_kernfs_root_to_sb(sb2, blob);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = kunit_add_action_or_reset(test, selinux_kernfs_test_free_sb, sb2);
	KUNIT_ASSERT_EQ(test, rc, 0);
	sbsec1 = selinux_superblock(sb1);
	sbsec2 = selinux_superblock(sb2);
	KUNIT_EXPECT_PTR_EQ(test, sbsec1->anchor_state, state);
	KUNIT_EXPECT_PTR_EQ(test, sbsec2->anchor_state, state);
	KUNIT_EXPECT_EQ(test, refcount_read(&state->count), 4);
	KUNIT_EXPECT_EQ(test, refcount_read(&domain->refs), 4);

	refcount_set(&other_state->count, 2);
	refcount_set(&other_domain->refs, 2);
	WRITE_ONCE(other_state->active, true);
	other_state->depth = 1;
	other_domain->depth = 1;
	other_state->label_domain = other_domain;
	mismatch->anchor_state = other_state;
	mismatch->anchor_domain = other_domain;
	rc = selinux_kunit_kernfs_root_to_sb(sb1, mismatch_blob);
	KUNIT_EXPECT_EQ(test, rc, -EXDEV);

	mismatch->anchor_state = state;
	mismatch->anchor_domain = other_domain;
	rc = selinux_kunit_kernfs_root_to_sb(sb1, mismatch_blob);
	KUNIT_EXPECT_EQ(test, rc, -EACCES);

	kunit_remove_action(test, selinux_kernfs_test_free_sb, sb2);
	selinux_kunit_kernfs_sb_free(sb2);
	kunit_remove_action(test, selinux_kernfs_test_free_sb, sb1);
	selinux_kunit_kernfs_sb_free(sb1);
	KUNIT_EXPECT_EQ(test, refcount_read(&state->count), 2);
	KUNIT_EXPECT_EQ(test, refcount_read(&domain->refs), 2);
}

static void selinux_kernfs_unrelated_actor_test(struct kunit *test)
{
	struct kernfs_root_security_struct *rootsec;
	struct selinux_label_domain domain = {};
	struct selinux_state state = {};
	void *blob;
	int rc;

	WRITE_ONCE(state.active, true);
	state.label_domain = &domain;
	blob = selinux_kernfs_test_root_blob(test);
	KUNIT_ASSERT_NOT_NULL(test, blob);
	rootsec = selinux_kernfs_root_security(blob);
	rootsec->anchor_state = &state;
	rootsec->anchor_domain = &domain;
	rc = selinux_kunit_kernfs_init_security(NULL, NULL, blob);
	KUNIT_EXPECT_EQ(test, rc, -EXDEV);
}

struct selinux_kernfs_stale_ctx {
	unsigned int calls;
};

static int
selinux_kernfs_stale_snapshot(struct selinux_state *state,
			      struct selinux_policy_snapshot *snapshot)
{
	struct kunit *test = kunit_get_current_test();
	struct selinux_kernfs_stale_ctx *ctx = test->priv;

	ctx->calls++;
	return -ESTALE;
}

static void selinux_kernfs_stale_retry_test(struct kunit *test)
{
	struct selinux_kernfs_stale_ctx *ctx;
	struct kernfs_node *child, *parent, *published, *root_kn;
	struct kernfs_root *root;
	static const char label[] = "stale";
	int rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	test->priv = ctx;
	root = kernfs_create_root(NULL, KERNFS_ROOT_CREATE_DEACTIVATED, NULL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(root));
	rc = kunit_add_action_or_reset(test, selinux_kernfs_test_destroy_root,
				       root);
	KUNIT_ASSERT_EQ(test, rc, 0);
	root_kn = kernfs_root_to_node(root);
	parent = kernfs_create_dir(root_kn, "parent", 0500, NULL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(parent));
	rc = kernfs_xattr_set(parent, XATTR_NAME_SELINUX, label, sizeof(label),
			      XATTR_CREATE);
	KUNIT_ASSERT_EQ(test, rc, 0);
	kunit_activate_static_stub(test, selinux_kunit_kernfs_snapshot_read,
				   selinux_kernfs_stale_snapshot);
	child = kernfs_create_dir(parent, "child", 0500, NULL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(child));
	KUNIT_EXPECT_EQ(test, ctx->calls, SELINUX_KERNFS_POLICY_RETRIES);
	published = kernfs_find_and_get(parent, "child");
	KUNIT_EXPECT_NULL(test, published);
	kernfs_put(published);
}

static struct kunit_case selinux_kernfs_test_cases[] = {
	KUNIT_CASE(selinux_kernfs_strong_anchor_test),
	KUNIT_CASE(selinux_kernfs_foreign_anchor_and_mismatch_test),
	KUNIT_CASE(selinux_kernfs_unrelated_actor_test),
	KUNIT_CASE(selinux_kernfs_stale_retry_test),
	{}
};

static struct kunit_suite selinux_kernfs_test_suite = {
	.name = "selinux-kernfs-anchor",
	.test_cases = selinux_kernfs_test_cases,
};

kunit_test_suite(selinux_kernfs_test_suite);

MODULE_LICENSE("GPL");
