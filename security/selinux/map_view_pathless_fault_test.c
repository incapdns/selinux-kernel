// SPDX-License-Identifier: GPL-2.0-only
/* Deterministic constructor rollback tests for SELinux label provenance. */

#include <kunit/test.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/user_namespace.h>

#include "include/global_sidtab.h"
#include "include/label.h"
#include "include/label_map.h"
#include "include/label_view.h"
#include "include/pathless.h"
#include "include/resource.h"
#include "include/security.h"

struct selinux_fault_accounting {
	u64 objects;
	u64 bytes;
};

static struct selinux_fault_accounting
selinux_fault_accounting_read(struct selinux_resource_account *resources,
			      enum selinux_resource_kind kind)
{
	return (struct selinux_fault_accounting) {
		.objects = selinux_kunit_resource_objects(resources, kind),
		.bytes = selinux_kunit_resource_bytes(resources, kind),
	};
}

static void selinux_fault_accounting_expect(
	struct kunit *test, struct selinux_resource_account *resources,
	enum selinux_resource_kind kind,
	const struct selinux_fault_accounting *baseline)
{
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_objects(resources, kind),
			baseline->objects);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_bytes(resources, kind),
			baseline->bytes);
}

KUNIT_DEFINE_ACTION_WRAPPER(selinux_fault_domain_put,
			    selinux_label_domain_put,
			    struct selinux_label_domain *);

static struct selinux_label_domain *
selinux_fault_domain_alloc(struct kunit *test,
			   struct selinux_label_domain *parent)
{
	struct selinux_label_domain *domain;
	int rc;

	domain = selinux_label_domain_alloc(&init_user_ns, parent, 0);
	if (IS_ERR(domain)) {
		KUNIT_FAIL(test, "domain allocation failed: %ld", PTR_ERR(domain));
		return NULL;
	}
	rc = kunit_add_action_or_reset(test, selinux_fault_domain_put, domain);
	if (rc) {
		KUNIT_FAIL(test, "domain cleanup registration failed: %d", rc);
		return NULL;
	}
	return domain;
}

static void selinux_fault_state_init(struct selinux_state *state,
			     struct selinux_label_domain *domain)
{
	memset(state, 0, sizeof(*state));
	INIT_LIST_HEAD(&state->children);
	INIT_LIST_HEAD(&state->sibling);
	atomic64_set(&state->chain_epoch, 1);
	state->label_domain = domain;
}

static bool selinux_fault_expect_error(struct kunit *test, const void *ptr,
			       int expected, const char *what)
{
	if (!IS_ERR(ptr)) {
		KUNIT_FAIL(test, "%s unexpectedly succeeded", what);
		return false;
	}
	KUNIT_EXPECT_EQ_MSG(test, PTR_ERR(ptr), (long)expected,
			    "%s returned the wrong errno", what);
	return true;
}

static bool selinux_fault_map_arm(struct kunit *test,
			  enum selinux_label_map_kunit_fault point,
			  unsigned int occurrence)
{
	int rc = selinux_label_map_kunit_fault_arm(point, occurrence);

	if (rc)
		KUNIT_FAIL(test, "map fault arm failed: %d", rc);
	return rc == 0;
}

static bool selinux_fault_view_arm(struct kunit *test,
			   enum selinux_label_view_kunit_fault point,
			   unsigned int occurrence)
{
	int rc = selinux_label_view_kunit_fault_arm(point, occurrence);

	if (rc)
		KUNIT_FAIL(test, "view fault arm failed: %d", rc);
	return rc == 0;
}

static bool selinux_fault_pathless_arm(
	struct kunit *test, enum selinux_pathless_kunit_fault point,
	unsigned int occurrence)
{
	int rc = selinux_pathless_kunit_fault_arm(point, occurrence);

	if (rc)
		KUNIT_FAIL(test, "pathless fault arm failed: %d", rc);
	return rc == 0;
}

static void selinux_label_map_constructor_fault_test(struct kunit *test)
{
	struct selinux_fault_accounting baseline;
	struct selinux_label_domain *parent, *child;
	struct selinux_label_map *failed, *map, *published;
	int parent_refs;

	parent = selinux_fault_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, parent);
	child = selinux_fault_domain_alloc(test, parent);
	KUNIT_ASSERT_NOT_NULL(test, child);
	baseline = selinux_fault_accounting_read(parent->resources,
					 SELINUX_RESOURCE_MAP);
	parent_refs = refcount_read(&parent->refs);

	/* The second table failure must destroy the already initialized first. */
	if (!selinux_fault_map_arm(test,
		SELINUX_LABEL_MAP_KUNIT_FAULT_TABLE_INIT, 2))
		return;
	failed = selinux_label_map_alloc(parent, child);
	if (!selinux_fault_expect_error(test, failed, -ENOMEM,
					"second rhashtable init")) {
		selinux_label_map_kunit_fault_disarm();
		if (!IS_ERR(failed))
			selinux_label_map_kunit_put_and_wait(failed);
		return;
	}
	selinux_fault_accounting_expect(test, parent->resources,
					SELINUX_RESOURCE_MAP, &baseline);
	KUNIT_EXPECT_EQ(test, refcount_read(&parent->refs), parent_refs);
	published = selinux_label_domain_get_map(child);
	KUNIT_EXPECT_PTR_EQ(test, published, NULL);
	selinux_label_map_put(published);

	/* Retry before disarming proves that the matching fault was one-shot. */
	map = selinux_label_map_alloc(parent, child);
	selinux_label_map_kunit_fault_disarm();
	if (IS_ERR(map)) {
		KUNIT_FAIL(test, "map retry failed: %ld", PTR_ERR(map));
		return;
	}
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_objects(
		parent->resources, SELINUX_RESOURCE_MAP), baseline.objects + 1);
	selinux_label_map_kunit_put_and_wait(map);
	selinux_fault_accounting_expect(test, parent->resources,
					SELINUX_RESOURCE_MAP, &baseline);
	KUNIT_EXPECT_EQ(test, refcount_read(&parent->refs), parent_refs);
}

static void selinux_label_map_entry_fault_test(struct kunit *test)
{
	static const struct {
		enum selinux_label_map_kunit_fault point;
		int error;
	} cases[] = {
		{ SELINUX_LABEL_MAP_KUNIT_FAULT_ENTRY_RESERVE, -EDQUOT },
		{ SELINUX_LABEL_MAP_KUNIT_FAULT_ENTRY_ALLOC, -ENOMEM },
		{ SELINUX_LABEL_MAP_KUNIT_FAULT_ENTRY_INSERT, -ENOMEM },
	};
	static const char source_context[] =
		"u:object_r:kunit_map_fault_source_t:s0";
	static const char target_context[] =
		"u:object_r:kunit_map_fault_target_t:s0";
	struct selinux_global_sid_handle *source_handle, *target_handle;
	struct selinux_fault_accounting baseline;
	struct selinux_label_ref *source_label, *target_label;
	struct selinux_label_domain *parent, *child;
	struct selinux_state parent_state, child_state;
	struct selinux_label_map *map;
	u32 source_sid, target_sid;
	int source_refs, target_refs;
	int retry_rc, rc;
	size_t i;

	parent = selinux_fault_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, parent);
	child = selinux_fault_domain_alloc(test, parent);
	KUNIT_ASSERT_NOT_NULL(test, child);
	selinux_fault_state_init(&parent_state, parent);
	selinux_fault_state_init(&child_state, child);
	source_handle = selinux_kunit_global_context_to_handle(
		&parent_state, source_context, &source_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, source_handle);
	target_handle = selinux_kunit_global_context_to_handle(
		&child_state, target_context, &target_sid);
	if (IS_ERR(target_handle)) {
		selinux_kunit_global_sid_drop_baseline(source_sid);
		global_sid_handle_put(source_handle);
		rcu_barrier();
		KUNIT_FAIL(test, "target handle allocation failed: %ld",
			   PTR_ERR(target_handle));
		return;
	}
	KUNIT_EXPECT_NE(test, source_sid, (u32)0);
	KUNIT_EXPECT_NE(test, target_sid, (u32)0);
	source_label = global_sid_handle_label_get(source_handle);
	target_label = global_sid_handle_label_get(target_handle);
	if (!source_label || !target_label) {
		selinux_kunit_global_sid_drop_baseline(target_sid);
		selinux_kunit_global_sid_drop_baseline(source_sid);
		selinux_label_ref_put(target_label);
		selinux_label_ref_put(source_label);
		global_sid_handle_put(target_handle);
		global_sid_handle_put(source_handle);
		rcu_barrier();
		KUNIT_FAIL(test, "canonical label acquisition failed");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		map = selinux_label_map_alloc(parent, child);
		if (IS_ERR(map)) {
			KUNIT_FAIL(test, "map allocation failed: %ld", PTR_ERR(map));
			goto out;
		}
		baseline = selinux_fault_accounting_read(
			parent->resources, SELINUX_RESOURCE_MAP_ENTRY);
		source_refs = refcount_read(&source_label->refs);
		target_refs = refcount_read(&target_label->refs);
		if (!selinux_fault_map_arm(test, cases[i].point, 1)) {
			selinux_label_map_kunit_put_and_wait(map);
			goto out;
		}
		rc = selinux_label_map_add(
			map, SELINUX_LABEL_MAP_PARENT_TO_CHILD,
			source_handle, target_handle);
		KUNIT_EXPECT_EQ(test, rc, cases[i].error);
		KUNIT_EXPECT_EQ(test,
			map->direction[SELINUX_LABEL_MAP_PARENT_TO_CHILD].count,
			(u32)0);
		selinux_fault_accounting_expect(
			test, parent->resources, SELINUX_RESOURCE_MAP_ENTRY,
			&baseline);
		KUNIT_EXPECT_EQ(test, refcount_read(&source_label->refs),
				source_refs);
		KUNIT_EXPECT_EQ(test, refcount_read(&target_label->refs),
				target_refs);

		/* Retry while still armed: the exact occurrence cannot fire twice. */
		retry_rc = selinux_label_map_add(
			map, SELINUX_LABEL_MAP_PARENT_TO_CHILD,
			source_handle, target_handle);
		selinux_label_map_kunit_fault_disarm();
		if (retry_rc) {
			KUNIT_FAIL(test, "map retry failed: %d", retry_rc);
			selinux_label_map_kunit_put_and_wait(map);
			goto out;
		}
		KUNIT_EXPECT_EQ(test,
			map->direction[SELINUX_LABEL_MAP_PARENT_TO_CHILD].count,
			(u32)1);
		selinux_label_map_kunit_put_and_wait(map);
		selinux_fault_accounting_expect(
			test, parent->resources, SELINUX_RESOURCE_MAP_ENTRY,
			&baseline);
		KUNIT_EXPECT_EQ(test, refcount_read(&source_label->refs),
				source_refs);
		KUNIT_EXPECT_EQ(test, refcount_read(&target_label->refs),
				target_refs);
	}

out:
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(target_sid), 0);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(source_sid), 0);
	selinux_label_ref_put(target_label);
	selinux_label_ref_put(source_label);
	global_sid_handle_put(target_handle);
	global_sid_handle_put(source_handle);
	rcu_barrier();
}

struct selinux_fault_chain {
	struct selinux_label_domain *root;
	struct selinux_label_domain *child;
	struct selinux_label_domain *leaf;
	struct selinux_label_map *root_map;
	struct selinux_label_map *leaf_map;
};

static bool selinux_fault_chain_init(struct kunit *test,
			     struct selinux_fault_chain *chain)
{
	int rc;

	memset(chain, 0, sizeof(*chain));
	chain->root = selinux_fault_domain_alloc(test, NULL);
	if (!chain->root)
		return false;
	chain->child = selinux_fault_domain_alloc(test, chain->root);
	if (!chain->child)
		return false;
	chain->leaf = selinux_fault_domain_alloc(test, chain->child);
	if (!chain->leaf)
		return false;

	chain->root_map = selinux_label_map_alloc(chain->root, chain->child);
	if (IS_ERR(chain->root_map)) {
		KUNIT_FAIL(test, "root map allocation failed: %ld",
			   PTR_ERR(chain->root_map));
		chain->root_map = NULL;
		return false;
	}
	chain->leaf_map = selinux_label_map_alloc(chain->child, chain->leaf);
	if (IS_ERR(chain->leaf_map)) {
		KUNIT_FAIL(test, "leaf map allocation failed: %ld",
			   PTR_ERR(chain->leaf_map));
		chain->leaf_map = NULL;
		return false;
	}
	rc = selinux_label_map_seal(chain->root_map, chain->root);
	if (!rc)
		rc = selinux_label_domain_publish_map(
			chain->child, chain->root_map, chain->root);
	if (!rc)
		rc = selinux_label_map_seal(chain->leaf_map, chain->child);
	if (!rc)
		rc = selinux_label_domain_publish_map(
			chain->leaf, chain->leaf_map, chain->child);
	if (rc) {
		KUNIT_FAIL(test, "map chain publication failed: %d", rc);
		return false;
	}
	return true;
}

static void selinux_fault_chain_destroy(struct selinux_fault_chain *chain)
{
	if (chain->leaf_map) {
		selinux_label_map_kunit_unpublish(chain->leaf, chain->leaf_map);
		selinux_label_map_kunit_put_and_wait(chain->leaf_map);
		chain->leaf_map = NULL;
	}
	if (chain->root_map) {
		selinux_label_map_kunit_unpublish(chain->child, chain->root_map);
		selinux_label_map_kunit_put_and_wait(chain->root_map);
		chain->root_map = NULL;
	}
}

static void selinux_label_view_fault_test(struct kunit *test)
{
	static const struct {
		enum selinux_label_view_kunit_fault point;
		int error;
	} cases[] = {
		{ SELINUX_LABEL_VIEW_KUNIT_FAULT_RESERVE, -EDQUOT },
		{ SELINUX_LABEL_VIEW_KUNIT_FAULT_ALLOC, -ENOMEM },
	};
	struct selinux_fault_accounting baseline;
	const struct selinux_label_view *failed, *view;
	struct selinux_label_domain *root;
	int root_refs;
	size_t i;

	root = selinux_fault_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	baseline = selinux_fault_accounting_read(root->resources,
					 SELINUX_RESOURCE_VIEW);
	root_refs = refcount_read(&root->refs);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		if (!selinux_fault_view_arm(test, cases[i].point, 1))
			return;
		failed = selinux_identity_view_alloc(&init_user_ns, root, root);
		if (!selinux_fault_expect_error(test, failed, cases[i].error,
						"identity view allocation")) {
			selinux_label_view_kunit_fault_disarm();
			if (!IS_ERR(failed))
				selinux_label_view_kunit_put_and_wait(failed);
			return;
		}
		selinux_fault_accounting_expect(test, root->resources,
						SELINUX_RESOURCE_VIEW, &baseline);
		KUNIT_EXPECT_EQ(test, refcount_read(&root->refs), root_refs);

		view = selinux_identity_view_alloc(&init_user_ns, root, root);
		selinux_label_view_kunit_fault_disarm();
		if (IS_ERR(view)) {
			KUNIT_FAIL(test, "identity view retry failed: %ld",
				   PTR_ERR(view));
			return;
		}
		selinux_label_view_kunit_put_and_wait(view);
		selinux_fault_accounting_expect(test, root->resources,
						SELINUX_RESOURCE_VIEW, &baseline);
		KUNIT_EXPECT_EQ(test, refcount_read(&root->refs), root_refs);
	}
}

static void selinux_label_view_partial_chain_fault_test(struct kunit *test)
{
	struct selinux_fault_accounting baseline;
	struct selinux_fault_chain chain;
	const struct selinux_label_view *failed, *view;
	int root_refs, leaf_refs, root_map_refs, leaf_map_refs;

	if (!selinux_fault_chain_init(test, &chain)) {
		selinux_fault_chain_destroy(&chain);
		return;
	}
	baseline = selinux_fault_accounting_read(chain.root->resources,
					 SELINUX_RESOURCE_VIEW);
	root_refs = refcount_read(&chain.root->refs);
	leaf_refs = refcount_read(&chain.leaf->refs);
	root_map_refs = refcount_read(&chain.root_map->refs);
	leaf_map_refs = refcount_read(&chain.leaf_map->refs);

	/* Fail after retaining the deepest map, before a view can escape. */
	if (!selinux_fault_view_arm(
		test, SELINUX_LABEL_VIEW_KUNIT_FAULT_CHAIN_ACQUIRE, 1)) {
		selinux_fault_chain_destroy(&chain);
		return;
	}
	failed = selinux_identity_view_alloc(
		&init_user_ns, chain.leaf, chain.root);
	if (!selinux_fault_expect_error(test, failed, -ENOMEM,
					"partial view chain acquisition")) {
		selinux_label_view_kunit_fault_disarm();
		if (!IS_ERR(failed))
			selinux_label_view_kunit_put_and_wait(failed);
		selinux_fault_chain_destroy(&chain);
		return;
	}
	selinux_fault_accounting_expect(test, chain.root->resources,
					SELINUX_RESOURCE_VIEW, &baseline);
	KUNIT_EXPECT_EQ(test, refcount_read(&chain.root->refs), root_refs);
	KUNIT_EXPECT_EQ(test, refcount_read(&chain.leaf->refs), leaf_refs);
	KUNIT_EXPECT_EQ(test, refcount_read(&chain.root_map->refs),
			root_map_refs);
	KUNIT_EXPECT_EQ(test, refcount_read(&chain.leaf_map->refs),
			leaf_map_refs);

	view = selinux_identity_view_alloc(&init_user_ns, chain.leaf, chain.root);
	selinux_label_view_kunit_fault_disarm();
	if (IS_ERR(view)) {
		KUNIT_FAIL(test, "partial-chain view retry failed: %ld",
			   PTR_ERR(view));
		selinux_fault_chain_destroy(&chain);
		return;
	}
	KUNIT_EXPECT_EQ(test, view->map_count, (u16)2);
	KUNIT_EXPECT_EQ(test, refcount_read(&chain.root_map->refs),
			root_map_refs + 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&chain.leaf_map->refs),
			leaf_map_refs + 1);
	selinux_label_view_kunit_put_and_wait(view);
	selinux_fault_accounting_expect(test, chain.root->resources,
					SELINUX_RESOURCE_VIEW, &baseline);
	KUNIT_EXPECT_EQ(test, refcount_read(&chain.root_map->refs),
			root_map_refs);
	KUNIT_EXPECT_EQ(test, refcount_read(&chain.leaf_map->refs),
			leaf_map_refs);
	selinux_fault_chain_destroy(&chain);
}

static struct selinux_pathless_projection *
selinux_fault_projection_alloc(struct selinux_label_ref *label,
			       const struct selinux_label_view *view,
			       const struct selinux_pathless_expect *expects)
{
	return selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_ANON_INODE,
		SELINUX_LABEL_SOURCE_KERNEL_INITIAL, label,
		SECINITSID_KERNEL, view, expects, 3, GFP_KERNEL);
}

static void selinux_pathless_projection_fault_test(struct kunit *test)
{
	static const struct {
		enum selinux_pathless_kunit_fault point;
		int error;
	} cases[] = {
		{ SELINUX_PATHLESS_KUNIT_FAULT_RESERVE, -EDQUOT },
		{ SELINUX_PATHLESS_KUNIT_FAULT_ALLOC, -ENOMEM },
	};
	struct selinux_pathless_expect expects[3];
	struct selinux_pathless_projection *failed, *projection;
	struct selinux_fault_accounting baseline;
	struct selinux_fault_chain chain;
	struct selinux_label_ref *label;
	const struct selinux_label_view *view;
	int label_refs, view_refs;
	unsigned int k;
	size_t i;

	if (!selinux_fault_chain_init(test, &chain)) {
		selinux_fault_chain_destroy(&chain);
		return;
	}
	view = selinux_identity_view_alloc(&init_user_ns, chain.leaf, chain.root);
	if (IS_ERR(view)) {
		KUNIT_FAIL(test, "pathless view allocation failed: %ld",
			   PTR_ERR(view));
		selinux_fault_chain_destroy(&chain);
		return;
	}
	label = global_sid_to_label_ref(SECINITSID_KERNEL);
	if (IS_ERR(label)) {
		KUNIT_FAIL(test, "initial SID lookup failed: %ld", PTR_ERR(label));
		selinux_label_view_kunit_put_and_wait(view);
		selinux_fault_chain_destroy(&chain);
		return;
	}
	expects[0] = (struct selinux_pathless_expect) {
		.domain = chain.root,
		.sid = SECINITSID_KERNEL,
		.sclass = 41,
		.model = SELINUX_PATHLESS_MODEL_LEGACY,
	};
	expects[1] = (struct selinux_pathless_expect) {
		.domain = chain.child,
		.sid = SECINITSID_KERNEL,
		.sclass = 42,
		.model = SELINUX_PATHLESS_MODEL_TRANSITION,
	};
	expects[2] = (struct selinux_pathless_expect) {
		.domain = chain.leaf,
		.sid = SECINITSID_KERNEL,
		.sclass = 43,
		.model = SELINUX_PATHLESS_MODEL_CONTEXT_COPY,
	};
	baseline = selinux_fault_accounting_read(
		view->resources, SELINUX_RESOURCE_PROJECTION);
	label_refs = refcount_read(&label->refs);
	view_refs = refcount_read(&view->refs);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		if (!selinux_fault_pathless_arm(test, cases[i].point, 1))
			goto out;
		failed = selinux_fault_projection_alloc(label, view, expects);
		if (!selinux_fault_expect_error(test, failed, cases[i].error,
						"projection allocation")) {
			selinux_pathless_kunit_fault_disarm();
			if (!IS_ERR(failed))
				selinux_pathless_projection_kunit_put_and_wait(
					failed);
			goto out;
		}
		selinux_fault_accounting_expect(
			test, view->resources, SELINUX_RESOURCE_PROJECTION,
			&baseline);
		KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), label_refs);
		KUNIT_EXPECT_EQ(test, refcount_read(&view->refs), view_refs);
		projection = selinux_fault_projection_alloc(label, view, expects);
		selinux_pathless_kunit_fault_disarm();
		if (IS_ERR(projection)) {
			KUNIT_FAIL(test, "projection retry failed: %ld",
				   PTR_ERR(projection));
			goto out;
		}
		selinux_pathless_projection_kunit_put_and_wait(projection);
		selinux_fault_accounting_expect(
			test, view->resources, SELINUX_RESOURCE_PROJECTION,
			&baseline);
		KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), label_refs);
		KUNIT_EXPECT_EQ(test, refcount_read(&view->refs), view_refs);
	}

	/* Exercise rollback before the first, middle, and final seal handle. */
	for (k = 1; k <= ARRAY_SIZE(expects); k++) {
		if (!selinux_fault_pathless_arm(
			test, SELINUX_PATHLESS_KUNIT_FAULT_SEAL_ACQUIRE, k))
			goto out;
		failed = selinux_fault_projection_alloc(label, view, expects);
		if (!selinux_fault_expect_error(test, failed, -ENOMEM,
						"k-th seal acquisition")) {
			selinux_pathless_kunit_fault_disarm();
			if (!IS_ERR(failed))
				selinux_pathless_projection_kunit_put_and_wait(
					failed);
			goto out;
		}
		selinux_fault_accounting_expect(
			test, view->resources, SELINUX_RESOURCE_PROJECTION,
			&baseline);
		KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), label_refs);
		KUNIT_EXPECT_EQ(test, refcount_read(&view->refs), view_refs);
		projection = selinux_fault_projection_alloc(label, view, expects);
		selinux_pathless_kunit_fault_disarm();
		if (IS_ERR(projection)) {
			KUNIT_FAIL(test, "projection retry failed: %ld",
				   PTR_ERR(projection));
			goto out;
		}
		selinux_pathless_projection_kunit_put_and_wait(projection);
		selinux_fault_accounting_expect(
			test, view->resources, SELINUX_RESOURCE_PROJECTION,
			&baseline);
		KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), label_refs);
		KUNIT_EXPECT_EQ(test, refcount_read(&view->refs), view_refs);
	}

out:
	selinux_label_ref_put(label);
	selinux_label_view_kunit_put_and_wait(view);
	selinux_fault_chain_destroy(&chain);
}

static struct kunit_case selinux_map_view_pathless_fault_cases[] = {
	KUNIT_CASE(selinux_label_map_constructor_fault_test),
	KUNIT_CASE(selinux_label_map_entry_fault_test),
	KUNIT_CASE(selinux_label_view_fault_test),
	KUNIT_CASE(selinux_label_view_partial_chain_fault_test),
	KUNIT_CASE(selinux_pathless_projection_fault_test),
	{}
};

static struct kunit_suite selinux_map_view_pathless_fault_suite = {
	.name = "selinux-map-view-pathless-fault",
	.test_cases = selinux_map_view_pathless_fault_cases,
};

kunit_test_suite(selinux_map_view_pathless_fault_suite);

MODULE_DESCRIPTION("KUnit tests for SELinux map/view/pathless rollback");
MODULE_LICENSE("GPL");
