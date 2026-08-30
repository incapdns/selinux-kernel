// SPDX-License-Identifier: GPL-2.0-only
/* Focused regression tests for SELinux namespace cache isolation. */

#include <kunit/test.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/in.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/sched/mm.h>
#include <linux/security.h>
#include <linux/selinux_net.h>
#include <linux/string.h>
#include <linux/user_namespace.h>
#include <net/netlabel.h>
#include <net/xfrm.h>

#include "include/ibpkey.h"
#include "include/avc.h"
#include "include/audit.h"
#include "include/label.h"
#include "include/label_map.h"
#include "include/label_view.h"
#include "include/global_sidtab.h"
#include "include/netlabel.h"
#include "include/net_assertion.h"
#include "include/netns.h"
#include "include/netport.h"
#include "include/objsec.h"
#include "include/pathless.h"
#include "include/resource.h"
#include "include/security.h"
#include "include/selinux_ss.h"
#include "include/sidtab.h"
#include "ss/services.h"

#if IS_BUILTIN(CONFIG_CACHEFILES)
extern int cachefiles_kunit_apply_secctx_ref(struct lsm_prop_ref *ref,
					    u32 diagnostic_secid,
					    struct lsm_prop *applied_prop);
#endif

static struct selinux_label_domain *
selinux_test_domain_alloc(struct kunit *test,
			  struct selinux_label_domain *parent);

static void selinux_test_state_init(struct selinux_state *state, u64 epoch)
{
	memset(state, 0, sizeof(*state));
	INIT_LIST_HEAD(&state->children);
	INIT_LIST_HEAD(&state->sibling);
	atomic64_set(&state->chain_epoch, epoch);
	atomic_set(&state->chain_updates, 0);
}

static void selinux_chain_epoch_subtree_test(struct kunit *test)
{
	struct selinux_state root, child, sibling, grandchild;

	selinux_test_state_init(&root, 1);
	selinux_test_state_init(&child, 1);
	selinux_test_state_init(&sibling, 1);
	selinux_test_state_init(&grandchild, 1);
	list_add_tail(&child.sibling, &root.children);
	list_add_tail(&sibling.sibling, &root.children);
	list_add_tail(&grandchild.sibling, &child.children);

	selinux_chain_epoch_bump(&root);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&root), (u64)2);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&child), (u64)2);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&sibling), (u64)2);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&grandchild), (u64)2);

	selinux_chain_epoch_bump(&child);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&root), (u64)2);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&child), (u64)3);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&sibling), (u64)2);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&grandchild), (u64)3);
}

static void selinux_chain_epoch_saturation_test(struct kunit *test)
{
	struct selinux_state state, child;

	selinux_test_state_init(&state, S64_MAX - 1);
	selinux_test_state_init(&child, 1);
	list_add_tail(&child.sibling, &state.children);
	selinux_chain_epoch_bump(&state);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&state), (u64)S64_MAX);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&child), (u64)2);

	selinux_chain_epoch_bump(&state);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&state), (u64)0);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&child), (u64)3);

	/* A saturated ancestor remains disabled but descendants still advance. */
	selinux_chain_epoch_bump(&state);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&state), (u64)0);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&child), (u64)4);
}

static void selinux_chain_update_nested_test(struct kunit *test)
{
	struct selinux_state root, child, sibling, grandchild;

	selinux_test_state_init(&root, 1);
	selinux_test_state_init(&child, 1);
	selinux_test_state_init(&sibling, 1);
	selinux_test_state_init(&grandchild, 1);
	list_add_tail(&child.sibling, &root.children);
	list_add_tail(&sibling.sibling, &root.children);
	list_add_tail(&grandchild.sibling, &child.children);

	KUNIT_ASSERT_EQ(test, selinux_chain_update_begin(&root), 0);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&root), (u64)0);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&child), (u64)0);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&sibling), (u64)0);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&grandchild), (u64)0);

	/* A child publication may overlap its parent's publication. */
	KUNIT_ASSERT_EQ(test, selinux_chain_update_begin(&child), 0);
	selinux_chain_update_end(&root);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&root), (u64)3);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&sibling), (u64)3);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&child), (u64)0);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&grandchild), (u64)0);

	selinux_chain_update_end(&child);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&child), (u64)5);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&grandchild), (u64)5);
	KUNIT_EXPECT_FALSE(test, selinux_chain_update_active(&root));
	KUNIT_EXPECT_FALSE(test, selinux_chain_update_active(&child));
}

static void selinux_chain_update_saturation_test(struct kunit *test)
{
	struct selinux_state state;

	selinux_test_state_init(&state, S64_MAX - 1);
	KUNIT_ASSERT_EQ(test, selinux_chain_update_begin(&state), 0);
	KUNIT_EXPECT_TRUE(test, selinux_chain_update_active(&state));
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&state), (u64)0);
	selinux_chain_update_end(&state);
	KUNIT_EXPECT_FALSE(test, selinux_chain_update_active(&state));
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&state), (u64)0);

	/* The update counter itself also saturates permanently fail closed. */
	selinux_test_state_init(&state, 1);
	atomic_set(&state.chain_updates, INT_MAX - 1);
	KUNIT_ASSERT_EQ(test, selinux_chain_update_begin(&state), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&state.chain_updates), INT_MAX);
	selinux_chain_update_end(&state);
	KUNIT_EXPECT_EQ(test, atomic_read(&state.chain_updates), INT_MAX);
	KUNIT_EXPECT_EQ(test, selinux_chain_epoch_read(&state), (u64)0);
}

static void selinux_xfrm_resolution_chain_collection_test(struct kunit *test)
{
	struct selinux_label_resolution source = {}, target = {};
	struct selinux_label_domain *root_domain, *child_domain;
	struct selinux_state root, child;
	u16 root_depth, child_depth, count = 0;
	int rc;

	root_domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, root_domain);
	child_domain = selinux_label_domain_alloc(&init_user_ns, root_domain, 0);
	if (IS_ERR(child_domain)) {
		selinux_label_domain_put(root_domain);
		KUNIT_FAIL(test, "child domain allocation failed: %ld",
			   PTR_ERR(child_domain));
		return;
	}
	selinux_test_state_init(&root, 1);
	selinux_test_state_init(&child, 1);
	root.label_domain = root_domain;
	child.label_domain = child_domain;
	child.parent = &root;
	root_depth = root_domain->depth;
	child_depth = child_domain->depth;
	source.max_depth = child_depth;
	target.max_depth = child_depth;
	source.domain_id[root_depth] = root_domain->id;
	target.domain_id[root_depth] = root_domain->id;
	source.sid[root_depth] = 11;
	target.sid[root_depth] = 12;
	source.domain_id[child_depth] = child_domain->id;
	target.domain_id[child_depth] = child_domain->id;
	source.sid[child_depth] = 21;
	target.sid[child_depth] = 22;
	rc = selinux_kunit_resolution_levels(&child, &source, &target, &count);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, count, (u16)2);
	target.sid[root_depth] = 0;
	rc = selinux_kunit_resolution_levels(&child, &source, &target, &count);
	KUNIT_EXPECT_EQ(test, rc, -EXDEV);
	selinux_label_domain_put(child_domain);
	selinux_label_domain_put(root_domain);
}

static void selinux_xfrm_flow_origin_type_test(struct kunit *test)
{
	char socket_owner, request_owner, skb_owner;
	const struct sock *sk = (const struct sock *)&socket_owner;
	const struct request_sock *req =
		(const struct request_sock *)&request_owner;
	const struct sk_buff *skb = (const struct sk_buff *)&skb_owner;
	struct xfrm_flow_origin origin;

	origin = xfrm_flow_origin_none();
	KUNIT_EXPECT_EQ(test, origin.kind, XFRM_FLOW_ORIGIN_NONE);

	origin = xfrm_flow_origin_sock(sk);
	KUNIT_EXPECT_EQ(test, origin.kind, XFRM_FLOW_ORIGIN_SOCK);
	KUNIT_EXPECT_PTR_EQ(test, origin.sk, sk);
	KUNIT_EXPECT_NE(test, origin.kind, XFRM_FLOW_ORIGIN_REQUEST);

	origin = xfrm_flow_origin_request(req);
	KUNIT_EXPECT_EQ(test, origin.kind, XFRM_FLOW_ORIGIN_REQUEST);
	KUNIT_EXPECT_PTR_EQ(test, origin.req, req);
	KUNIT_EXPECT_NE(test, origin.kind, XFRM_FLOW_ORIGIN_SKB);

	origin = xfrm_flow_origin_skb(skb);
	KUNIT_EXPECT_EQ(test, origin.kind, XFRM_FLOW_ORIGIN_SKB);
	KUNIT_EXPECT_PTR_EQ(test, origin.skb, skb);
	KUNIT_EXPECT_NE(test, origin.kind, XFRM_FLOW_ORIGIN_SOCK);

	KUNIT_EXPECT_EQ(test, xfrm_flow_origin_sock(NULL).kind,
			XFRM_FLOW_ORIGIN_NONE);
	KUNIT_EXPECT_EQ(test, xfrm_flow_origin_request(NULL).kind,
			XFRM_FLOW_ORIGIN_NONE);
	KUNIT_EXPECT_EQ(test, xfrm_flow_origin_skb(NULL).kind,
			XFRM_FLOW_ORIGIN_NONE);
}

static void selinux_policy_snapshot_test(struct kunit *test)
{
	struct selinux_policy_snapshot snapshot;
	struct selinux_policy_snapshot cache_key;
	struct selinux_policy *first, *second;
	struct selinux_state *state;

	first = kunit_kzalloc(test, sizeof(*first), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, first);
	second = kunit_kzalloc(test, sizeof(*second), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, second);
	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);
	first->policycaps = 1UL << POLICYDB_CAP_OPENPERM;
	first->latest_granting = 7;
	second->policycaps = 1UL << POLICYDB_CAP_NETPEER;
	second->latest_granting = 8;

	selinux_test_state_init(state, 1);
	rcu_assign_pointer(state->policy, first);
	KUNIT_ASSERT_EQ(test,
			 selinux_policy_snapshot_read(state, &snapshot), 0);
	KUNIT_EXPECT_PTR_EQ(test, snapshot.policy_cookie, first);
	KUNIT_EXPECT_EQ(test, snapshot.seqno, (u32)7);
	KUNIT_EXPECT_TRUE(test, selinux_policy_snapshot_has_cap(
				      &snapshot, POLICYDB_CAP_OPENPERM));
	KUNIT_EXPECT_FALSE(test, selinux_policy_snapshot_has_cap(
				       &snapshot, POLICYDB_CAP_NETPEER));
	KUNIT_EXPECT_TRUE(test,
			  selinux_policy_snapshot_valid(state, &snapshot));
	KUNIT_EXPECT_FALSE(test, snapshot.initialized);
	cache_key = snapshot;
	selinux_mark_initialized(state);
	KUNIT_EXPECT_FALSE(test,
			   selinux_policy_snapshot_valid(state, &cache_key));
	KUNIT_ASSERT_EQ(test,
			 selinux_policy_snapshot_read(state, &snapshot), 0);
	KUNIT_EXPECT_TRUE(test, snapshot.initialized);
	KUNIT_EXPECT_FALSE(test,
			   selinux_policy_snapshot_equal(&snapshot, &cache_key));

	KUNIT_ASSERT_EQ(test, selinux_chain_update_begin(state), 0);
	KUNIT_EXPECT_EQ(test,
			selinux_policy_snapshot_read(state, &cache_key),
			-EAGAIN);
	KUNIT_EXPECT_FALSE(test,
			   selinux_policy_snapshot_valid(state, &snapshot));
	rcu_assign_pointer(state->policy, second);
	selinux_chain_update_end(state);
	KUNIT_EXPECT_FALSE(test,
			   selinux_policy_snapshot_valid(state, &snapshot));
	KUNIT_ASSERT_EQ(test,
			 selinux_policy_snapshot_read(state, &snapshot), 0);
	KUNIT_EXPECT_PTR_EQ(test, snapshot.policy_cookie, second);
	KUNIT_EXPECT_FALSE(test, selinux_policy_snapshot_has_cap(
				       &snapshot, POLICYDB_CAP_OPENPERM));
	KUNIT_EXPECT_TRUE(test, selinux_policy_snapshot_has_cap(
				      &snapshot, POLICYDB_CAP_NETPEER));
	cache_key = snapshot;
	KUNIT_EXPECT_TRUE(test,
			  selinux_policy_snapshot_equal(&snapshot, &cache_key));
	cache_key.policycaps ^= 1UL;
	KUNIT_EXPECT_FALSE(test,
			   selinux_policy_snapshot_equal(&snapshot, &cache_key));
	cache_key = snapshot;
	cache_key.seqno++;
	KUNIT_EXPECT_FALSE(test,
			   selinux_policy_snapshot_equal(&snapshot, &cache_key));
	cache_key = snapshot;
	cache_key.chain_epoch++;
	KUNIT_EXPECT_FALSE(test,
			   selinux_policy_snapshot_equal(&snapshot, &cache_key));
	cache_key = snapshot;
	cache_key.policy_cookie = first;
	KUNIT_EXPECT_FALSE(test,
			   selinux_policy_snapshot_equal(&snapshot, &cache_key));

	atomic64_set(&state->chain_epoch, 0);
	KUNIT_EXPECT_EQ(test,
			selinux_policy_snapshot_read(state, &snapshot),
			-EOVERFLOW);
	RCU_INIT_POINTER(state->policy, NULL);
}

#if CONFIG_SECURITY_SELINUX_SS_SID_CACHE_SIZE > 0
static void selinux_global_sid_cache_active_key_test(struct kunit *test)
{
	struct selinux_policy_snapshot snapshot = {
		.policy_cookie = (void *)0x1234,
		.policycaps = 7,
		.chain_epoch = 9,
		.seqno = 11,
		.initialized = true,
		.active = false,
	};
	struct sidtab_ss_sid_cache_entry cached = {
		.domain_id = 13,
		.policy_cookie = snapshot.policy_cookie,
		.policycaps = snapshot.policycaps,
		.chain_epoch = snapshot.chain_epoch,
		.seqno = snapshot.seqno,
		.ss_sid = 17,
		.initialized = snapshot.initialized,
		.active = snapshot.active,
	};

	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_cache_matches(
				  &cached, cached.domain_id, &snapshot));
	/* Dormant and active states must never share a cached translation. */
	snapshot.active = true;
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_cache_matches(
				   &cached, cached.domain_id, &snapshot));
}
#endif

static void selinux_test_sidtab_destroy(void *data)
{
	sidtab_destroy(data);
}

static void selinux_test_audit_rule_free(void *data)
{
	selinux_audit_rule_free(data);
}

static void selinux_audit_rule_provenance_test(struct kunit *test)
{
	struct selinux_policy *replacement, *policy;
	struct context context = {
		.user = 1,
		.role = 2,
		.type = 3,
		.str = "selinuxns_audit_test",
		.len = sizeof("selinuxns_audit_test"),
	};
	struct lsm_prop prop = {};
	struct selinux_state *owner;
	struct selinux_avc *init_avc, *other_avc;
	struct sidtab *table;
	void *rule;
	bool init_avc_owner, init_owner, other_avc_owner, other_owner;
	int rc;

	replacement = kunit_kzalloc(test, sizeof(*replacement), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, replacement);
	policy = kunit_kzalloc(test, sizeof(*policy), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, policy);
	owner = kunit_kzalloc(test, sizeof(*owner), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, owner);
	replacement->latest_granting = 8;
	policy->latest_granting = 7;
	table = kunit_kzalloc(test, sizeof(*table), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, table);
	KUNIT_ASSERT_EQ(test, sidtab_init(table), 0);
	rc = kunit_add_action_or_reset(test, selinux_test_sidtab_destroy, table);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = sidtab_set_initial(table, SECINITSID_KERNEL, &context);
	if (rc) {
		KUNIT_FAIL(test, "audit test SID insertion failed: %d", rc);
		return;
	}

	selinux_test_state_init(owner, 11);
	refcount_set(&owner->count, 1);
	policy->sidtab = table;
	replacement->sidtab = table;
	rcu_assign_pointer(owner->policy, policy);
	/* Match the release publication used when a policy makes state live. */
	smp_store_release(&owner->initialized, true);

	init_owner = selinux_kunit_audit_rule_state_is_owner(init_selinux_state);
	other_owner = selinux_kunit_audit_rule_state_is_owner(owner);
	init_avc = init_selinux_state->avc;
	other_avc = (struct selinux_avc *)owner;
	init_avc_owner = selinux_kunit_audit_rule_avc_is_owner(init_avc);
	other_avc_owner = selinux_kunit_audit_rule_avc_is_owner(other_avc);
	KUNIT_EXPECT_TRUE(test, init_owner);
	KUNIT_EXPECT_FALSE(test, other_owner);
	KUNIT_EXPECT_TRUE(test, init_avc_owner);
	KUNIT_EXPECT_FALSE(test, other_avc_owner);
	rule = selinux_kunit_audit_rule_alloc(owner, 1, 2, 3);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, rule);
	rc = kunit_add_action_or_reset(test, selinux_test_audit_rule_free, rule);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, refcount_read(&owner->count), 2);
	KUNIT_EXPECT_PTR_EQ(test, selinux_audit_rule_state(rule), owner);

	prop.selinux.secid = SECINITSID_KERNEL;
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_audit_rule_match(&prop, AUDIT_SUBJ_TYPE,
						       SELINUX_KUNIT_AUDIT_EQUAL,
						       rule),
			1);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_audit_rule_match(&prop, AUDIT_SUBJ_TYPE,
						       SELINUX_KUNIT_AUDIT_NOT_EQUAL,
						       rule),
			0);

	/* A different immutable policy identity makes the rule stale. */
	rcu_assign_pointer(owner->policy, replacement);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_audit_rule_match(&prop, AUDIT_SUBJ_TYPE,
						       SELINUX_KUNIT_AUDIT_EQUAL,
						       rule),
			-ESTALE);

	kunit_release_action(test, selinux_test_audit_rule_free, rule);
	KUNIT_EXPECT_EQ(test, refcount_read(&owner->count), 1);
	RCU_INIT_POINTER(owner->policy, NULL);
	kunit_release_action(test, selinux_test_sidtab_destroy, table);
}

static struct cred *
selinux_test_audit_cred(struct kunit *test, struct selinux_state *state,
			const struct cred *parent, u32 sid,
			struct selinux_global_sid_handle *handle)
{
	struct cred_security_struct *crsec;
	struct cred *cred;
	void *security;

	cred = kunit_kzalloc(test, sizeof(*cred), GFP_KERNEL);
	if (!cred)
		return NULL;
	security = kunit_kzalloc(test, selinux_blob_sizes.lbs_cred +
				       sizeof(*crsec), GFP_KERNEL);
	if (!security)
		return NULL;
	cred->security = security;
	crsec = selinux_cred(cred);
	crsec->state = state;
	crsec->parent_cred = parent;
	crsec->sid = sid;
	crsec->sid_handle = handle;
	return cred;
}

static struct lsm_prop_ref *
selinux_test_audit_cred_ref(struct kunit *test, const struct cred *cred,
			    u32 sid)
{
	struct selinux_prop_ref_security *rsec;
	struct lsm_prop_ref *ref;

	ref = kunit_kzalloc(test,
		struct_size(ref, security, selinux_blob_sizes.lbs_prop_ref +
			    sizeof(*rsec)), GFP_KERNEL);
	if (!ref)
		return NULL;
	ref->prop.selinux.secid = sid;
	rsec = selinux_prop_ref(ref);
	rsec->sid = sid;
	rsec->kind = SELINUX_PROP_REF_CRED;
	rsec->cred = cred;
	return ref;
}

static void selinux_cred_pair_linear_merge_test(struct kunit *test)
{
	struct selinux_label_domain *child_domain, *sibling_domain;
	struct selinux_state child, sibling;
	struct selinux_state *states[3] = {};
	struct cred *root_cred, *child_cred, *sibling_cred;
	u32 ssids[3] = {}, tsids[3] = {};
	u16 count = 0;
	int rc;

	selinux_test_state_init(&child, 1);
	selinux_test_state_init(&sibling, 1);
	child_domain = selinux_test_domain_alloc(
		test, init_selinux_state->label_domain);
	KUNIT_ASSERT_NOT_NULL(test, child_domain);
	sibling_domain = selinux_test_domain_alloc(
		test, init_selinux_state->label_domain);
	KUNIT_ASSERT_NOT_NULL(test, sibling_domain);
	child.parent = init_selinux_state;
	child.label_domain = child_domain;
	child.depth = child_domain->depth;
	sibling.parent = init_selinux_state;
	sibling.label_domain = sibling_domain;
	sibling.depth = sibling_domain->depth;
	root_cred = selinux_test_audit_cred(
		test, init_selinux_state, NULL, SECINITSID_KERNEL, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root_cred);
	child_cred = selinux_test_audit_cred(
		test, &child, root_cred, 101, NULL);
	KUNIT_ASSERT_NOT_NULL(test, child_cred);
	sibling_cred = selinux_test_audit_cred(
		test, &sibling, root_cred, 202, NULL);
	KUNIT_ASSERT_NOT_NULL(test, sibling_cred);

	/* ptrace_traceme: child policy first, then the previously skipped host. */
	rc = selinux_kunit_cred_pair_levels(
		child_cred, root_cred, child_cred, states, ssids, tsids,
		ARRAY_SIZE(states), &count);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, count, (u16)2);
	KUNIT_EXPECT_PTR_EQ(test, states[0], &child);
	KUNIT_EXPECT_EQ(test, ssids[0], (u32)SECINITSID_UNLABELED);
	KUNIT_EXPECT_EQ(test, tsids[0], (u32)101);
	KUNIT_EXPECT_PTR_EQ(test, states[1], init_selinux_state);
	KUNIT_EXPECT_EQ(test, ssids[1], (u32)SECINITSID_KERNEL);
	KUNIT_EXPECT_EQ(test, tsids[1], (u32)SECINITSID_KERNEL);

	/* Equal-depth siblings stay isolated, while their common host still runs. */
	memset(states, 0, sizeof(states));
	memset(ssids, 0, sizeof(ssids));
	memset(tsids, 0, sizeof(tsids));
	count = 0;
	rc = selinux_kunit_cred_pair_levels(
		sibling_cred, sibling_cred, child_cred, states, ssids, tsids,
		ARRAY_SIZE(states), &count);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, count, (u16)2);
	KUNIT_EXPECT_PTR_EQ(test, states[0], &sibling);
	KUNIT_EXPECT_EQ(test, ssids[0], (u32)202);
	KUNIT_EXPECT_EQ(test, tsids[0], (u32)SECINITSID_UNLABELED);
	KUNIT_EXPECT_PTR_EQ(test, states[1], init_selinux_state);
	KUNIT_EXPECT_EQ(test, ssids[1], (u32)SECINITSID_KERNEL);
	KUNIT_EXPECT_EQ(test, tsids[1], (u32)SECINITSID_KERNEL);

	/* Two distinct states cannot claim the same label-domain identity. */
	sibling.label_domain = child_domain;
	count = 0;
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_cred_pair_levels(
				child_cred, sibling_cred, child_cred, states, ssids,
				tsids, ARRAY_SIZE(states), &count),
			-EXDEV);
	sibling.label_domain = sibling_domain;

	/* Binder impersonation compares the full chain, not colliding local SIDs. */
	selinux_cred(sibling_cred)->sid = selinux_cred(child_cred)->sid;
	KUNIT_EXPECT_FALSE(test,
			  cred_sid_chain_equal(child_cred, sibling_cred));
	KUNIT_EXPECT_TRUE(test, cred_sid_chain_equal(child_cred, child_cred));

	/* A truncated or forged ancestry is rejected instead of silently skipped. */
	child.parent = NULL;
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_cred_pair_levels(
				child_cred, root_cred, child_cred, states, ssids,
				tsids, ARRAY_SIZE(states), &count),
			-EXDEV);
}

static void selinux_audit_rule_carrier_projection_test(struct kunit *test)
{
	static const char child_context[] =
		"u:r:selinuxns_audit_child_subject_t:s0";
	struct selinux_global_sid_handle *child_handle, *owner_handle;
	struct selinux_label_domain *child_domain;
	struct lsm_prop_ref *ref, *unprojectable;
	struct selinux_state child;
	struct cred *child_cred, *owner_cred;
	u32 child_sid, sid = SECSID_NULL;

	selinux_test_state_init(&child, 1);
	child_domain = selinux_test_domain_alloc(
		test, init_selinux_state->label_domain);
	KUNIT_ASSERT_NOT_NULL(test, child_domain);
	child.parent = init_selinux_state;
	child.label_domain = child_domain;
	owner_handle = global_sid_handle_get(SECINITSID_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, owner_handle);
	child_handle = selinux_kunit_global_context_to_handle(
		&child, child_context, &child_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, child_handle);
	owner_cred = selinux_test_audit_cred(
		test, init_selinux_state, NULL, SECINITSID_KERNEL, owner_handle);
	KUNIT_ASSERT_NOT_NULL(test, owner_cred);
	child_cred = selinux_test_audit_cred(
		test, &child, owner_cred, child_sid, child_handle);
	KUNIT_ASSERT_NOT_NULL(test, child_cred);
	ref = selinux_test_audit_cred_ref(test, child_cred,
					  child_sid);
	KUNIT_ASSERT_NOT_NULL(test, ref);

	/* A child subject is projected to the immutable global rule owner. */
	KUNIT_ASSERT_EQ(test,
			 selinux_kunit_audit_rule_ref_sid(
				 ref, init_selinux_state, &sid),
			 0);
	KUNIT_EXPECT_EQ(test, sid, (u32)SECINITSID_KERNEL);
	/* The second rule consumes the memo and does not walk parent_cred. */
	selinux_cred(child_cred)->parent_cred = NULL;
	sid = SECSID_NULL;
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_audit_rule_ref_sid(
				ref, init_selinux_state, &sid),
			0);
	KUNIT_EXPECT_EQ(test, sid, (u32)SECINITSID_KERNEL);

	unprojectable = selinux_test_audit_cred_ref(
		test, child_cred, child_sid);
	KUNIT_ASSERT_NOT_NULL(test, unprojectable);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_audit_rule_ref_sid(
				unprojectable, init_selinux_state, &sid),
			-EOPNOTSUPP);
	/* A deterministic projection errno is cached for every later rule. */
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_audit_rule_ref_sid(
				unprojectable, init_selinux_state, &sid),
			-EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test,
			security_audit_rule_match_ref(NULL, -ESTALE,
				AUDIT_SUBJ_TYPE, Audit_equal, NULL),
			-ESTALE);

	KUNIT_EXPECT_EQ(test, selinux_kunit_global_sid_drop_baseline(child_sid), 0);
	global_sid_handle_put(child_handle);
	global_sid_handle_put(owner_handle);
}

static void selinux_audit_rule_filter_failure_test(struct kunit *test)
{
	/* Projection errors always fail open for logging, including NEVER. */
	KUNIT_EXPECT_EQ(test,
			audit_kunit_lsm_filter_result(
				-EOPNOTSUPP, AUDIT_NEVER, AUDIT_FILTER_USER),
			1);
	KUNIT_EXPECT_EQ(test,
			audit_kunit_lsm_filter_result(
				1, AUDIT_NEVER, AUDIT_FILTER_USER),
			0);
	KUNIT_EXPECT_EQ(test,
			audit_kunit_lsm_filter_result(
				1, AUDIT_ALWAYS, AUDIT_FILTER_USER),
			1);
}

static void selinux_file_permission_cache_test(struct kunit *test)
{
	struct file_security_struct fsec = {
		.sid = 101,
		.isid = 202,
		.chain_epoch = 303,
	};
	char opener_storage, other_storage;
	const struct cred *opener = (const struct cred *)&opener_storage;
	const struct cred *other = (const struct cred *)&other_storage;
	bool valid;

	valid = selinux_file_permission_cache_valid(&fsec, opener, opener,
						    101, 202, 303);
	KUNIT_EXPECT_TRUE(test, valid);
	valid = selinux_file_permission_cache_valid(&fsec, other, opener,
						    101, 202, 303);
	KUNIT_EXPECT_FALSE(test, valid);
	valid = selinux_file_permission_cache_valid(&fsec, opener, opener,
						    102, 202, 303);
	KUNIT_EXPECT_FALSE(test, valid);
	valid = selinux_file_permission_cache_valid(&fsec, opener, opener,
						    101, 203, 303);
	KUNIT_EXPECT_FALSE(test, valid);
	valid = selinux_file_permission_cache_valid(&fsec, opener, opener,
						    101, 202, 304);
	KUNIT_EXPECT_FALSE(test, valid);
	fsec.chain_epoch = 0;
	valid = selinux_file_permission_cache_valid(&fsec, opener, opener,
						    101, 202, 0);
	KUNIT_EXPECT_FALSE(test, valid);
}

static void selinux_sidtab_cache_bounds_test(struct kunit *test)
{
	struct selinux_state victim, survivor;
	struct selinux_label_domain *victim_domain, *survivor_domain;
	struct sidtab_entry entry = {};
	struct sidtab_ss_sid_cache *cache = &entry.ss_sid_cache;
	struct sidtab_ss_sid_cache_entry *cached;

	if (ARRAY_SIZE(cache->slots) < 2) {
		kunit_skip(test, "requires at least two secondary SID cache slots");
		return;
	}
	victim_domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, victim_domain);
	survivor_domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, survivor_domain);
	victim.label_domain = victim_domain;
	survivor.label_domain = survivor_domain;

	cached = kzalloc_obj(*cached);
	KUNIT_ASSERT_NOT_NULL(test, cached);
	cached->domain_id = victim_domain->id;
	cached->chain_epoch = 1;
	cached->ss_sid = 11;
	RCU_INIT_POINTER(cache->slots[0], cached);
	cached = kzalloc_obj(*cached);
	KUNIT_ASSERT_NOT_NULL(test, cached);
	cached->domain_id = survivor_domain->id;
	cached->chain_epoch = 1;
	cached->ss_sid = 22;
	RCU_INIT_POINTER(cache->slots[1], cached);

	selinux_kunit_sidtab_invalidate_state_entry(&entry, &victim);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(cache->slots[0]), NULL);
	cached = rcu_access_pointer(cache->slots[1]);
	KUNIT_ASSERT_NOT_NULL(test, cached);
	KUNIT_EXPECT_EQ(test, cached->domain_id, survivor_domain->id);
	KUNIT_EXPECT_EQ(test, cached->ss_sid, (u32)22);

	selinux_kunit_sidtab_invalidate_state_entry(&entry, &survivor);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(cache->slots[1]), NULL);
	rcu_barrier();
	selinux_label_domain_put(survivor_domain);
	selinux_label_domain_put(victim_domain);
}

static void selinux_sidtab_cache_all_matches_test(struct kunit *test)
{
	struct selinux_state victim, survivor;
	struct selinux_label_domain *victim_domain, *survivor_domain;
	struct sidtab_entry entry = {};
	struct sidtab_ss_sid_cache *cache = &entry.ss_sid_cache;
	struct sidtab_ss_sid_cache_entry *cached;

	if (ARRAY_SIZE(cache->slots) < 3) {
		kunit_skip(test, "requires at least three secondary SID cache slots");
		return;
	}
	victim_domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, victim_domain);
	survivor_domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, survivor_domain);
	victim.label_domain = victim_domain;
	survivor.label_domain = survivor_domain;

	cached = kzalloc_obj(*cached);
	KUNIT_ASSERT_NOT_NULL(test, cached);
	cached->domain_id = victim_domain->id;
	cached->ss_sid = 11;
	RCU_INIT_POINTER(cache->slots[0], cached);
	cached = kzalloc_obj(*cached);
	KUNIT_ASSERT_NOT_NULL(test, cached);
	cached->domain_id = survivor_domain->id;
	cached->ss_sid = 22;
	RCU_INIT_POINTER(cache->slots[1], cached);
	cached = kzalloc_obj(*cached);
	KUNIT_ASSERT_NOT_NULL(test, cached);
	cached->domain_id = victim_domain->id;
	cached->ss_sid = 33;
	RCU_INIT_POINTER(cache->slots[2], cached);

	selinux_kunit_sidtab_invalidate_state_entry(&entry, &victim);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(cache->slots[0]), NULL);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(cache->slots[2]), NULL);
	cached = rcu_access_pointer(cache->slots[1]);
	KUNIT_ASSERT_NOT_NULL(test, cached);
	KUNIT_EXPECT_EQ(test, cached->domain_id, survivor_domain->id);

	selinux_kunit_sidtab_invalidate_state_entry(&entry, &survivor);
	rcu_barrier();
	selinux_label_domain_put(survivor_domain);
	selinux_label_domain_put(victim_domain);
}

static void selinux_sidtab_domain_identity_test(struct kunit *test)
{
	struct selinux_label_domain *first_domain, *second_domain;
	struct selinux_state first = {}, second = {};
	struct sidtab_entry *first_entry, *second_entry;
	struct context context = {
		.str = "u:r:same_t:s0",
		.len = sizeof("u:r:same_t:s0"),
	};
	struct sidtab *table;
	u32 first_sid, repeat_sid, second_sid;
	int rc;

	table = kunit_kzalloc(test, sizeof(*table), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, table);

	first_domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	if (IS_ERR(first_domain)) {
		KUNIT_FAIL(test, "failed to allocate first label domain");
		return;
	}
	second_domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	if (IS_ERR(second_domain)) {
		selinux_label_domain_put(first_domain);
		KUNIT_FAIL(test, "failed to allocate second label domain");
		return;
	}
	first.label_domain = first_domain;
	second.label_domain = second_domain;

	rc = sidtab_init(table);
	if (rc) {
		KUNIT_FAIL(test, "sidtab_init failed: %d", rc);
		goto out_domains;
	}
	rc = sidtab_context_ss_to_sid(table, &context, &first, &first_sid);
	if (rc) {
		KUNIT_FAIL(test, "first domain insert failed: %d", rc);
		goto out_sidtab;
	}
	rc = sidtab_context_ss_to_sid(table, &context, &first, &repeat_sid);
	if (rc) {
		KUNIT_FAIL(test, "repeat domain lookup failed: %d", rc);
		goto out_sidtab;
	}
	rc = sidtab_context_ss_to_sid(table, &context, &second, &second_sid);
	if (rc) {
		KUNIT_FAIL(test, "second domain insert failed: %d", rc);
		goto out_sidtab;
	}

	KUNIT_EXPECT_EQ(test, repeat_sid, first_sid);
	KUNIT_EXPECT_NE(test, second_sid, first_sid);
	first_entry = sidtab_search_entry_force(table, first_sid);
	second_entry = sidtab_search_entry_force(table, second_sid);
	KUNIT_EXPECT_NOT_NULL(test, first_entry);
	KUNIT_EXPECT_NOT_NULL(test, second_entry);
	if (first_entry)
		KUNIT_EXPECT_PTR_EQ(test, first_entry->origin_domain,
				    first_domain);
	if (second_entry)
		KUNIT_EXPECT_PTR_EQ(test, second_entry->origin_domain,
				    second_domain);
	if (first_entry && second_entry) {
		KUNIT_EXPECT_NOT_NULL(test, first_entry->label_ref);
		KUNIT_EXPECT_NOT_NULL(test, second_entry->label_ref);
		KUNIT_EXPECT_PTR_NE(test, first_entry->label_ref,
				    second_entry->label_ref);
	}

out_sidtab:
	sidtab_destroy(table);
out_domains:
	selinux_label_domain_put(second_domain);
	selinux_label_domain_put(first_domain);
}

KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_label_domain_put,
			    selinux_label_domain_put,
			    struct selinux_label_domain *);
KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_label_ref_put,
			    selinux_label_ref_put,
			    struct selinux_label_ref *);
KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_label_map_put,
			    selinux_label_map_kunit_put_and_wait,
			    struct selinux_label_map *);
KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_net_assertion_put,
			    selinux_net_assertion_put,
			    struct selinux_net_assertion *);
KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_net_provenance_put,
			    selinux_net_provenance_put,
			    struct selinux_net_provenance *);
KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_pathless_projection_put,
			    selinux_pathless_projection_kunit_put_and_wait,
			    struct selinux_pathless_projection *);

static void selinux_test_label_view_put(void *view)
{
	selinux_label_view_kunit_put_and_wait(view);
}

static void selinux_test_label_operation_put(void *data)
{
	selinux_label_operation_resolution_put(data);
}

static struct selinux_label_domain *
selinux_test_domain_alloc(struct kunit *test,
			  struct selinux_label_domain *parent)
{
	struct selinux_label_domain *domain;
	int rc;

	domain = selinux_label_domain_alloc(&init_user_ns, parent, 0);
	if (IS_ERR(domain)) {
		KUNIT_FAIL(test, "label domain allocation failed: %ld",
			   PTR_ERR(domain));
		return NULL;
	}
	rc = kunit_add_action_or_reset(test, selinux_test_label_domain_put,
				       domain);
	if (rc) {
		KUNIT_FAIL(test, "label domain cleanup registration failed: %d",
			   rc);
		return NULL;
	}
	return domain;
}

struct selinux_test_staged_genfs_cleanup {
	struct selinux_global_sid_handle *handle;
	u32 sid;
	bool baseline_dropped;
};

static void selinux_test_staged_genfs_handle_put(void *data)
{
	struct selinux_test_staged_genfs_cleanup *cleanup = data;

	if (!cleanup->baseline_dropped)
		selinux_kunit_global_sid_drop_baseline(cleanup->sid);
	global_sid_handle_put(cleanup->handle);
	rcu_barrier();
}

static void selinux_staged_policy_genfs_provenance_test(struct kunit *test)
{
	static const char old_context_string[] = "old_u:old_r:old_t:s0";
	static const char staged_context_string[] =
		"staged_u:staged_r:staged_t:s0";
	struct context old_context = {
		.str = old_context_string,
		.len = sizeof(old_context_string),
	};
	struct context staged_context = {
		.str = staged_context_string,
		.len = sizeof(staged_context_string),
	};
	struct selinux_test_staged_genfs_cleanup *cleanup;
	struct selinux_global_sid_handle *handle, *stale;
	struct selinux_label_domain *domain;
	struct selinux_label_ref *label;
	struct selinux_policy *old_policy, *staged_policy;
	struct selinux_state *state;
	struct sidtab *old_sidtab, *staged_sidtab;
	struct ocontext staged_ocontext = {
		.u.name = "/booleans/staged",
	};
	struct genfs staged_genfs = {
		.fstype = "selinuxfs",
		.head = &staged_ocontext,
	};
	u32 old_local_sid, staged_local_sid, global_sid;
	int rc;

	old_policy = kunit_kzalloc(test, sizeof(*old_policy), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_policy);
	staged_policy = kunit_kzalloc(test, sizeof(*staged_policy), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, staged_policy);
	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);
	old_sidtab = kunit_kzalloc(test, sizeof(*old_sidtab), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_sidtab);
	staged_sidtab = kunit_kzalloc(test, sizeof(*staged_sidtab), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, staged_sidtab);

	KUNIT_ASSERT_EQ(test, sidtab_init(old_sidtab), 0);
	rc = kunit_add_action_or_reset(test, selinux_test_sidtab_destroy,
				       old_sidtab);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, sidtab_init(staged_sidtab), 0);
	rc = kunit_add_action_or_reset(test, selinux_test_sidtab_destroy,
				       staged_sidtab);
	KUNIT_ASSERT_EQ(test, rc, 0);

	old_policy->sidtab = old_sidtab;
	staged_policy->sidtab = staged_sidtab;
	staged_policy->policydb.genfs = &staged_genfs;
	staged_ocontext.context[0] = staged_context;

	/* Both private tables deliberately assign the same policy-local SID. */
	KUNIT_ASSERT_EQ(test,
			 sidtab_context_to_sid(old_sidtab, &old_context,
					       &old_local_sid),
			 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_ss_policy_genfs_sid(staged_policy, "selinuxfs",
						       "/booleans/staged",
						       SECCLASS_FILE,
						       &staged_local_sid),
			 0);
	KUNIT_ASSERT_EQ(test, staged_local_sid, old_local_sid);

	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	selinux_test_state_init(state, 1);
	state->label_domain = domain;
	rcu_assign_pointer(state->policy, old_policy);
	smp_store_release(&state->initialized, true);

	handle = selinux_policy_genfs_sid_handle(
		state, staged_policy, "selinuxfs", "/booleans/staged",
		SECCLASS_FILE, &global_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, handle);
	cleanup = kunit_kzalloc(test, sizeof(*cleanup), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cleanup);
	cleanup->handle = handle;
	cleanup->sid = global_sid;
	rc = kunit_add_action_or_reset(test,
				       selinux_test_staged_genfs_handle_put,
				       cleanup);
	KUNIT_ASSERT_EQ(test, rc, 0);

	label = global_sid_handle_label_get(handle);
	KUNIT_ASSERT_NOT_NULL(test, label);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put, label);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_PTR_EQ(test, label->domain, domain);
	KUNIT_EXPECT_STREQ(test, label->context, staged_context_string);
	KUNIT_EXPECT_NE(test, strcmp(label->context, old_context_string), 0);

	rc = selinux_kunit_global_sid_drop_baseline(global_sid);
	KUNIT_ASSERT_EQ(test, rc, 0);
	cleanup->baseline_dropped = true;
	kunit_release_action(test, selinux_test_staged_genfs_handle_put,
			     cleanup);
	stale = global_sid_handle_get(global_sid);
	KUNIT_ASSERT_TRUE(test, IS_ERR(stale));
	KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);
	RCU_INIT_POINTER(state->policy, NULL);
}

static struct selinux_label_map *
selinux_test_label_map_alloc(struct kunit *test,
			     struct selinux_label_domain *parent,
			     struct selinux_label_domain *child)
{
	struct selinux_label_map *map;
	int rc;

	map = selinux_label_map_alloc(parent, child);
	if (IS_ERR(map)) {
		KUNIT_FAIL(test, "label map allocation failed: %ld", PTR_ERR(map));
		return NULL;
	}
	rc = kunit_add_action_or_reset(test, selinux_test_label_map_put, map);
	if (rc) {
		KUNIT_FAIL(test, "label map cleanup registration failed: %d", rc);
		return NULL;
	}
	return map;
}

struct selinux_test_published_map {
	struct selinux_label_domain *child;
	struct selinux_label_map *map;
};

static void selinux_test_label_map_unpublish(void *data)
{
	struct selinux_test_published_map *published = data;
	int rc;

	rc = selinux_label_map_kunit_unpublish(published->child,
					      published->map);
	WARN_ON_ONCE(rc && rc != -ENOENT);
}

static int
selinux_test_label_domain_publish_map(struct kunit *test,
				      struct selinux_label_domain *child,
				      struct selinux_label_map *map,
				      const struct selinux_label_domain *actor)
{
	struct selinux_test_published_map *published;
	int rc;

	rc = selinux_label_domain_publish_map(child, map, actor);
	if (rc)
		return rc;
	published = kunit_kzalloc(test, sizeof(*published), GFP_KERNEL);
	if (!published) {
		selinux_label_map_kunit_unpublish(child, map);
		return -ENOMEM;
	}
	published->child = child;
	published->map = map;
	return kunit_add_action_or_reset(test, selinux_test_label_map_unpublish,
					 published);
}

static struct selinux_label_ref *
selinux_test_global_label(struct kunit *test, struct selinux_state *state,
			  struct selinux_label_domain *domain,
			  const char *context, u32 *sid)
{
	struct selinux_label_ref *label;
	int rc;

	selinux_test_state_init(state, 1);
	state->label_domain = domain;
	rc = selinux_kunit_global_context_to_sid(state, context, sid);
	if (rc) {
		KUNIT_FAIL(test, "global label insertion failed: %d", rc);
		return NULL;
	}
	label = global_sid_to_label_ref(*sid);
	if (IS_ERR(label)) {
		KUNIT_FAIL(test, "global label lookup failed: %ld",
			   PTR_ERR(label));
		return NULL;
	}
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put, label);
	if (rc) {
		KUNIT_FAIL(test, "global label cleanup registration failed: %d",
			   rc);
		return NULL;
	}
	return label;
}

static struct selinux_net_provenance *
selinux_test_net_provenance_alloc(
	struct kunit *test, struct selinux_state *state,
	const struct selinux_label_view *view, struct selinux_label_ref *label,
	u32 sid, u16 semantic_class,
	enum selinux_net_assertion_source source)
{
	struct selinux_net_provenance *provenance;
	struct selinux_net_assertion *assertion;
	struct selinux_global_sid_handle *sid_handle;
	int rc;

	sid_handle = global_sid_handle_get(sid);
	if (IS_ERR(sid_handle)) {
		KUNIT_FAIL(test, "network SID handle acquisition failed: %ld",
			   PTR_ERR(sid_handle));
		return NULL;
	}
	assertion = selinux_net_assertion_alloc_handle(
		sid_handle, semantic_class, source, 0, GFP_KERNEL);
	global_sid_handle_put(sid_handle);
	if (IS_ERR(assertion)) {
		KUNIT_FAIL(test, "network assertion allocation failed: %ld",
			   PTR_ERR(assertion));
		return NULL;
	}
	rc = kunit_add_action_or_reset(test, selinux_test_net_assertion_put,
				       assertion);
	if (rc) {
		KUNIT_FAIL(test,
			   "network assertion cleanup registration failed: %d", rc);
		return NULL;
	}
	provenance = selinux_net_provenance_alloc(state, view, assertion,
						  GFP_KERNEL);
	if (IS_ERR(provenance)) {
		KUNIT_FAIL(test, "network provenance allocation failed: %ld",
			   PTR_ERR(provenance));
		return NULL;
	}
	rc = kunit_add_action_or_reset(test, selinux_test_net_provenance_put,
				       provenance);
	if (rc) {
		KUNIT_FAIL(test,
			   "network provenance cleanup registration failed: %d", rc);
		return NULL;
	}
	return provenance;
}

static int selinux_test_label_map_add(
	struct selinux_label_map *map,
	enum selinux_label_map_direction direction,
	struct selinux_label_ref *source, u32 source_sid,
	struct selinux_label_ref *target, u32 target_sid)
{
	struct selinux_global_sid_handle *source_handle, *target_handle;
	struct selinux_label_ref *canonical_source, *canonical_target;
	int rc;

	source_handle = global_sid_handle_get(source_sid);
	if (IS_ERR(source_handle))
		return PTR_ERR(source_handle);
	target_handle = global_sid_handle_get(target_sid);
	if (IS_ERR(target_handle)) {
		rc = PTR_ERR(target_handle);
		goto out_source;
	}
	canonical_source = global_sid_handle_label_get(source_handle);
	canonical_target = global_sid_handle_label_get(target_handle);
	if (canonical_source != source || canonical_target != target)
		rc = -EINVAL;
	else
		rc = selinux_label_map_add(map, direction, source_handle,
					   target_handle);
	selinux_label_ref_put(canonical_target);
	selinux_label_ref_put(canonical_source);
	global_sid_handle_put(target_handle);
out_source:
	global_sid_handle_put(source_handle);
	return rc;
}

static int
selinux_test_map_pair(struct selinux_label_map *map,
		      struct selinux_label_ref *parent, u32 parent_sid,
		      struct selinux_label_ref *child, u32 child_sid)
{
	int rc;

	rc = selinux_test_label_map_add(map,
					SELINUX_LABEL_MAP_PARENT_TO_CHILD,
					parent, parent_sid, child, child_sid);
	if (rc)
		return rc;
	return selinux_test_label_map_add(map,
					  SELINUX_LABEL_MAP_CHILD_TO_PARENT,
					  child, child_sid, parent, parent_sid);
}

static void selinux_label_ref_identity_test(struct kunit *test)
{
	static const char context[] = "u:object_r:same_t:s0";
	static const char invalid[] = { 'a', '\0', 'b' };
	struct selinux_label_domain *first_domain, *second_domain;
	struct selinux_label_ref *first, *repeat, *without_nul, *second, *bad;
	int rc;

	first_domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first_domain);
	rc = kunit_add_action_or_reset(test, selinux_test_label_domain_put,
				       first_domain);
	KUNIT_ASSERT_EQ(test, rc, 0);
	second_domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, second_domain);
	rc = kunit_add_action_or_reset(test, selinux_test_label_domain_put,
				       second_domain);
	KUNIT_ASSERT_EQ(test, rc, 0);

	first = selinux_label_ref_intern(first_domain, context, sizeof(context),
					 GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put, first);
	KUNIT_ASSERT_EQ(test, rc, 0);
	repeat = selinux_label_ref_intern(first_domain, context, sizeof(context),
					  GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, repeat);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put, repeat);
	KUNIT_ASSERT_EQ(test, rc, 0);
	without_nul = selinux_label_ref_intern(first_domain, context,
					       sizeof(context) - 1,
					       GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, without_nul);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put,
				       without_nul);
	KUNIT_ASSERT_EQ(test, rc, 0);
	second = selinux_label_ref_intern(second_domain, context, sizeof(context),
					  GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, second);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put, second);
	KUNIT_ASSERT_EQ(test, rc, 0);

	KUNIT_EXPECT_PTR_EQ(test, repeat, first);
	KUNIT_EXPECT_PTR_EQ(test, without_nul, first);
	KUNIT_EXPECT_PTR_NE(test, second, first);
	KUNIT_EXPECT_NE(test, second->id, first->id);
	KUNIT_EXPECT_PTR_EQ(test, first->domain, first_domain);
	KUNIT_EXPECT_PTR_EQ(test, second->domain, second_domain);
	bad = selinux_label_ref_intern(first_domain, invalid, sizeof(invalid),
				       GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(bad));
}

static void selinux_label_map_parent_ownership_test(struct kunit *test)
{
	struct selinux_label_domain *parent, *child, *other_child, *outsider;
	struct selinux_label_map *map;
	int rc;

	parent = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, parent);
	child = selinux_test_domain_alloc(test, parent);
	KUNIT_ASSERT_NOT_NULL(test, child);
	other_child = selinux_test_domain_alloc(test, parent);
	KUNIT_ASSERT_NOT_NULL(test, other_child);
	outsider = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, outsider);
	map = selinux_test_label_map_alloc(test, parent, child);
	KUNIT_ASSERT_NOT_NULL(test, map);

	KUNIT_EXPECT_EQ(test, selinux_label_map_seal(map, child), -EPERM);
	KUNIT_EXPECT_EQ(test, selinux_label_map_seal(map, outsider), -EPERM);
	rc = selinux_test_label_domain_publish_map(test, child, map, parent);
	KUNIT_EXPECT_EQ(test, rc, -EPERM);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, parent), 0);
	rc = selinux_test_label_domain_publish_map(test, child, map, child);
	KUNIT_EXPECT_EQ(test, rc, -EPERM);
	rc = selinux_test_label_domain_publish_map(test, child, map, outsider);
	KUNIT_EXPECT_EQ(test, rc, -EPERM);
	rc = selinux_test_label_domain_publish_map(test, other_child, map,
					    parent);
	KUNIT_EXPECT_EQ(test, rc, -EPERM);
	rc = selinux_test_label_domain_publish_map(test, child, map, parent);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, refcount_read(&map->refs), 2);
	KUNIT_ASSERT_EQ(test, selinux_label_map_kunit_unpublish(child, map), 0);
	KUNIT_EXPECT_EQ(test, refcount_read(&map->refs), 1);
}

static void selinux_label_map_directions_and_seal_test(struct kunit *test)
{
	struct selinux_label_domain *parent, *child;
	struct selinux_label_ref *parent_source, *parent_target;
	struct selinux_label_ref *child_source, *child_target;
	struct selinux_label_ref *resolved_target = NULL;
	struct selinux_state parent_source_state, parent_target_state;
	struct selinux_state child_source_state, child_target_state;
	struct selinux_label_map *map;
	int target_refs;
	u32 parent_source_sid, parent_target_sid;
	u32 child_source_sid, child_target_sid;
	u32 sid = 0;
	int rc;

	parent = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, parent);
	child = selinux_test_domain_alloc(test, parent);
	KUNIT_ASSERT_NOT_NULL(test, child);
	map = selinux_test_label_map_alloc(test, parent, child);
	KUNIT_ASSERT_NOT_NULL(test, map);
	parent_source = selinux_test_global_label(
		test, &parent_source_state, parent,
		"u:object_r:parent_source_t:s0", &parent_source_sid);
	KUNIT_ASSERT_NOT_NULL(test, parent_source);
	parent_target = selinux_test_global_label(
		test, &parent_target_state, parent,
		"u:object_r:parent_target_t:s0", &parent_target_sid);
	KUNIT_ASSERT_NOT_NULL(test, parent_target);
	child_source = selinux_test_global_label(
		test, &child_source_state, child,
		"u:object_r:child_source_t:s0", &child_source_sid);
	KUNIT_ASSERT_NOT_NULL(test, child_source);
	child_target = selinux_test_global_label(
		test, &child_target_state, child,
		"u:object_r:child_target_t:s0", &child_target_sid);
	KUNIT_ASSERT_NOT_NULL(test, child_target);

	rc = selinux_test_label_map_add(map,
					SELINUX_LABEL_MAP_PARENT_TO_CHILD,
					parent_source, parent_source_sid,
					child_target, child_target_sid);
	KUNIT_EXPECT_EQ(test, rc, 0);
	rc = selinux_test_label_map_add(map,
					SELINUX_LABEL_MAP_CHILD_TO_PARENT,
					child_source, child_source_sid,
					parent_target, parent_target_sid);
	KUNIT_EXPECT_EQ(test, rc, 0);
	/* Each source owns its key handle; sharing one target remains valid. */
	rc = selinux_test_label_map_add(map,
					SELINUX_LABEL_MAP_PARENT_TO_CHILD,
					parent_target, parent_target_sid,
					child_target, child_target_sid);
	KUNIT_EXPECT_EQ(test, rc, 0);
	rc = selinux_test_label_map_add(map,
					SELINUX_LABEL_MAP_PARENT_TO_CHILD,
					parent_source, parent_source_sid,
					child_source, child_source_sid);
	KUNIT_EXPECT_EQ(test, rc, -EEXIST);
	rc = selinux_test_label_map_add(map,
					SELINUX_LABEL_MAP_PARENT_TO_CHILD,
					child_source, child_source_sid,
					parent_target, parent_target_sid);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
	rc = selinux_test_label_map_add(map,
					(enum selinux_label_map_direction)-1,
					parent_source, parent_source_sid,
					child_target, child_target_sid);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
	rc = selinux_label_map_resolve(map,
				       SELINUX_LABEL_MAP_PARENT_TO_CHILD,
				       parent_source, parent_source_sid, &sid, NULL);
	KUNIT_EXPECT_EQ(test, rc, -EOPNOTSUPP);
	rc = selinux_label_map_resolve(map,
				       (enum selinux_label_map_direction)-1,
				       parent_source, parent_source_sid, &sid, NULL);
	KUNIT_EXPECT_EQ(test, rc, -EOPNOTSUPP);

	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, parent), 0);
	target_refs = refcount_read(&child_target->refs);
	rc = selinux_label_map_resolve(map,
				       SELINUX_LABEL_MAP_PARENT_TO_CHILD,
				       parent_source, parent_source_sid, &sid,
				       &resolved_target);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, sid, child_target_sid);
	KUNIT_EXPECT_PTR_EQ(test, resolved_target, child_target);
	KUNIT_EXPECT_EQ(test, refcount_read(&child_target->refs),
			(target_refs + 1));
	selinux_label_ref_put(resolved_target);
	KUNIT_EXPECT_EQ(test, refcount_read(&child_target->refs), target_refs);
	rc = selinux_label_map_resolve(map,
				       SELINUX_LABEL_MAP_PARENT_TO_CHILD,
				       parent_target, parent_target_sid, &sid, NULL);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, sid, child_target_sid);
	rc = selinux_label_map_resolve(map,
				       SELINUX_LABEL_MAP_CHILD_TO_PARENT,
				       parent_source, parent_source_sid, &sid, NULL);
	KUNIT_EXPECT_EQ(test, rc, -ENOENT);
	rc = selinux_label_map_resolve(map,
				       SELINUX_LABEL_MAP_CHILD_TO_PARENT,
				       child_source, child_source_sid, &sid, NULL);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, sid, parent_target_sid);
	rc = selinux_label_map_resolve(map,
				       SELINUX_LABEL_MAP_PARENT_TO_CHILD,
				       child_source, child_source_sid, &sid, NULL);
	KUNIT_EXPECT_EQ(test, rc, -ENOENT);
	rc = selinux_test_label_map_add(map,
					SELINUX_LABEL_MAP_PARENT_TO_CHILD,
					parent_target, parent_target_sid,
					child_source, child_source_sid);
	KUNIT_EXPECT_EQ(test, rc, -EROFS);
	KUNIT_EXPECT_EQ(test, selinux_label_map_seal(map, parent), -EALREADY);
}

static void selinux_label_map_handle_lifetime_test(struct kunit *test)
{
	static const char first_context[] =
		"u:object_r:kunit_map_first_target_t:s0";
	static const char second_context[] =
		"u:object_r:kunit_map_second_target_t:s0";
	struct selinux_global_sid_handle *kernel, *init, *first, *second;
	struct selinux_label_ref *kernel_label, *init_label, *resolved = NULL;
	struct selinux_label_domain *child;
	struct selinux_state child_state;
	struct selinux_label_map *map;
	u32 first_sid, second_sid, sid;
	int rc;

	kernel = global_sid_handle_get(SECINITSID_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, kernel);
	init = global_sid_handle_get(SECINITSID_INIT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, init);
	kernel_label = global_sid_handle_label_get(kernel);
	KUNIT_ASSERT_NOT_NULL(test, kernel_label);
	init_label = global_sid_handle_label_get(init);
	KUNIT_ASSERT_NOT_NULL(test, init_label);
	/* Exact initial SIDs deliberately share one canonical context label. */
	KUNIT_ASSERT_PTR_EQ(test, kernel_label, init_label);

	child = selinux_test_domain_alloc(test, kernel_label->domain);
	KUNIT_ASSERT_NOT_NULL(test, child);
	map = selinux_test_label_map_alloc(test, kernel_label->domain, child);
	KUNIT_ASSERT_NOT_NULL(test, map);
	selinux_test_state_init(&child_state, 1);
	child_state.label_domain = child;
	first = selinux_kunit_global_context_to_handle(
		&child_state, first_context, &first_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first);
	second = selinux_kunit_global_context_to_handle(
		&child_state, second_context, &second_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, second);

	KUNIT_ASSERT_EQ(test,
		selinux_label_map_add(map, SELINUX_LABEL_MAP_PARENT_TO_CHILD,
				      kernel, first), 0);
	KUNIT_ASSERT_EQ(test,
		selinux_label_map_add(map, SELINUX_LABEL_MAP_PARENT_TO_CHILD,
				      init, second), 0);
	KUNIT_ASSERT_EQ(test, selinux_kunit_global_sid_drop_baseline(first_sid),
			0);
	KUNIT_ASSERT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(second_sid), 0);
	global_sid_handle_put(first);
	global_sid_handle_put(second);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(first_sid));
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(second_sid));
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, kernel_label->domain),
			0);

	rc = selinux_label_map_resolve(
		map, SELINUX_LABEL_MAP_PARENT_TO_CHILD, kernel_label,
		SECINITSID_KERNEL, &sid, &resolved);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, sid, first_sid);
	selinux_label_ref_put(resolved);
	resolved = NULL;
	rc = selinux_label_map_resolve(
		map, SELINUX_LABEL_MAP_PARENT_TO_CHILD, init_label,
		SECINITSID_INIT, &sid, &resolved);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, sid, second_sid);
	selinux_label_ref_put(resolved);

	/* The target payloads die only after the map drops its strong handles. */
	kunit_release_action(test, selinux_test_label_map_put, map);
	rcu_barrier();
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(first_sid));
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(second_sid));
	selinux_label_ref_put(init_label);
	selinux_label_ref_put(kernel_label);
	global_sid_handle_put(init);
	global_sid_handle_put(kernel);
}

static void selinux_label_map_source_handle_lifetime_test(struct kunit *test)
{
	static const char source_context[] =
		"u:object_r:kunit_map_source_lifetime_t:s0";
	static const char target_context[] =
		"u:object_r:kunit_map_target_lifetime_t:s0";
	struct selinux_global_sid_handle *source_handle, *target_handle, *stale;
	struct selinux_label_ref *source_label, *target_label;
	struct selinux_label_domain *parent, *child;
	struct selinux_state parent_state, child_state;
	struct selinux_label_map *map;
	u32 source_sid, target_sid, resolved_sid;
	int source_drop, target_drop;
	int rc;

	parent = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, parent);
	child = selinux_test_domain_alloc(test, parent);
	KUNIT_ASSERT_NOT_NULL(test, child);
	map = selinux_test_label_map_alloc(test, parent, child);
	KUNIT_ASSERT_NOT_NULL(test, map);
	selinux_test_state_init(&parent_state, 1);
	parent_state.label_domain = parent;
	selinux_test_state_init(&child_state, 1);
	child_state.label_domain = child;
	source_handle = selinux_kunit_global_context_to_handle(
		&parent_state, source_context, &source_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, source_handle);
	target_handle = selinux_kunit_global_context_to_handle(
		&child_state, target_context, &target_sid);
	if (IS_ERR(target_handle)) {
		global_sid_handle_put(source_handle);
		KUNIT_FAIL(test, "target handle allocation failed: %ld",
			   PTR_ERR(target_handle));
		return;
	}
	source_label = global_sid_handle_label_get(source_handle);
	target_label = global_sid_handle_label_get(target_handle);
	if (!source_label || !target_label) {
		selinux_label_ref_put(target_label);
		selinux_label_ref_put(source_label);
		global_sid_handle_put(target_handle);
		global_sid_handle_put(source_handle);
		KUNIT_FAIL(test, "canonical label acquisition failed");
		return;
	}
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put,
				       source_label);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put,
				       target_label);
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = selinux_label_map_add(map, SELINUX_LABEL_MAP_PARENT_TO_CHILD,
				   source_handle, target_handle);
	if (rc) {
		global_sid_handle_put(target_handle);
		global_sid_handle_put(source_handle);
		KUNIT_FAIL(test, "map insertion failed: %d", rc);
		return;
	}
	source_drop = selinux_kunit_global_sid_drop_baseline(source_sid);
	target_drop = selinux_kunit_global_sid_drop_baseline(target_sid);
	global_sid_handle_put(target_handle);
	global_sid_handle_put(source_handle);
	KUNIT_ASSERT_EQ(test, source_drop, 0);
	KUNIT_ASSERT_EQ(test, target_drop, 0);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(source_sid));
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(target_sid));
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, parent), 0);
	rc = selinux_label_map_resolve(
		map, SELINUX_LABEL_MAP_PARENT_TO_CHILD, source_label, source_sid,
		&resolved_sid, NULL);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, resolved_sid, target_sid);

	/* Map teardown drops both independently owned entry handles. */
	kunit_release_action(test, selinux_test_label_map_put, map);
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(source_sid));
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(target_sid));
	stale = global_sid_handle_get(source_sid);
	KUNIT_ASSERT_TRUE(test, IS_ERR(stale));
	KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);
}

static void selinux_label_view_missing_map_test(struct kunit *test)
{
	struct selinux_label_domain *parent, *child;
	const struct selinux_label_view *view;

	parent = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, parent);
	child = selinux_test_domain_alloc(test, parent);
	KUNIT_ASSERT_NOT_NULL(test, child);

	view = selinux_identity_view_alloc(&init_user_ns, child, parent);
	KUNIT_EXPECT_TRUE(test, IS_ERR(view));
	if (IS_ERR(view))
		KUNIT_EXPECT_EQ(test, PTR_ERR(view), -EOPNOTSUPP);
}

static void selinux_label_view_sibling_domains_test(struct kunit *test)
{
	struct selinux_label_domain *parent, *first, *second;
	const struct selinux_label_view *view;

	parent = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, parent);
	first = selinux_test_domain_alloc(test, parent);
	KUNIT_ASSERT_NOT_NULL(test, first);
	second = selinux_test_domain_alloc(test, parent);
	KUNIT_ASSERT_NOT_NULL(test, second);

	view = selinux_identity_view_alloc(&init_user_ns, first, second);
	KUNIT_EXPECT_TRUE(test, IS_ERR(view));
	if (IS_ERR(view))
		KUNIT_EXPECT_EQ(test, PTR_ERR(view), -EOPNOTSUPP);
}

static void selinux_label_view_publish_snapshot_test(struct kunit *test)
{
	struct selinux_label_domain *parent, *child;
	struct selinux_label_map *first, *second, *overflow, *published;
	const struct selinux_label_view *first_view, *second_view, *down_view;
	int rc;

	parent = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, parent);
	child = selinux_test_domain_alloc(test, parent);
	KUNIT_ASSERT_NOT_NULL(test, child);
	first = selinux_test_label_map_alloc(test, parent, child);
	KUNIT_ASSERT_NOT_NULL(test, first);
	KUNIT_EXPECT_EQ(test, first->generation, (u64)0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(first, parent), 0);
	KUNIT_ASSERT_EQ(test,
			selinux_test_label_domain_publish_map(test, child, first,
						      parent), 0);
	KUNIT_EXPECT_EQ(test, first->generation, (u64)1);
	KUNIT_EXPECT_EQ(test,
			selinux_test_label_domain_publish_map(test, child, first,
						      parent),
			-EALREADY);

	first_view = selinux_identity_view_alloc(&init_user_ns, child, parent);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)first_view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, first_view->map_count, (u16)1);
	KUNIT_EXPECT_PTR_EQ(test, first_view->maps[0], first);

	second = selinux_test_label_map_alloc(test, parent, child);
	KUNIT_ASSERT_NOT_NULL(test, second);
	KUNIT_EXPECT_EQ(test, second->generation, (u64)0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(second, parent), 0);
	KUNIT_ASSERT_EQ(test,
			selinux_test_label_domain_publish_map(test, child, second,
						      parent), 0);
	KUNIT_EXPECT_EQ(test, second->generation, (u64)2);
	published = selinux_label_domain_get_map(child);
	KUNIT_ASSERT_NOT_NULL(test, published);
	KUNIT_EXPECT_PTR_EQ(test, published, second);
	selinux_label_map_put(published);

	/* Publication replacement must not reinterpret an existing view. */
	KUNIT_EXPECT_PTR_EQ(test, first_view->maps[0], first);
	KUNIT_EXPECT_EQ(test, first_view->maps[0]->generation, (u64)1);
	/* The fixture drops the view before the map's final-owner action. */
	KUNIT_EXPECT_EQ(test, refcount_read(&first->refs), 2);

	second_view = selinux_identity_view_alloc(&init_user_ns, child, parent);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, second_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)second_view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, second_view->map_count, (u16)1);
	KUNIT_EXPECT_PTR_EQ(test, second_view->maps[0], second);

	/* The same sealed snapshot is valid in the descendant direction too. */
	down_view = selinux_identity_view_alloc(&init_user_ns, parent, child);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, down_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)down_view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, down_view->map_count, (u16)1);
	KUNIT_EXPECT_PTR_EQ(test, down_view->maps[0], second);

	/* Generation exhaustion is permanent and fails closed at the boundary. */
	WRITE_ONCE(second->generation, U64_MAX);
	overflow = selinux_test_label_map_alloc(test, parent, child);
	KUNIT_ASSERT_NOT_NULL(test, overflow);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(overflow, parent), 0);
	KUNIT_EXPECT_EQ(test,
			selinux_test_label_domain_publish_map(test, child, overflow,
						      parent),
			-EOVERFLOW);
	KUNIT_EXPECT_EQ(test, overflow->generation, (u64)0);
	published = selinux_label_domain_get_map(child);
	KUNIT_ASSERT_NOT_NULL(test, published);
	KUNIT_EXPECT_PTR_EQ(test, published, second);
	selinux_label_map_put(published);
}

static void selinux_label_view_global_initial_sid_test(struct kunit *test)
{
	struct selinux_label_domain *domain;
	struct selinux_label_ref *label;
	const struct selinux_label_view *view;
	u32 resolved = 0;
	int rc;

	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	view = selinux_identity_view_alloc(&init_user_ns, domain, domain);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	label = global_sid_to_label_ref(SECINITSID_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, label);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put, label);
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = selinux_label_view_resolve(view, domain, label,
					SECINITSID_KERNEL, &resolved);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, resolved, (u32)SECINITSID_KERNEL);
}

static void selinux_label_view_full_chain_test(struct kunit *test)
{
	static const char * const contexts[] = {
		"u:object_r:kunit_root_t:s0",
		"u:object_r:kunit_child_t:s0",
		"u:object_r:kunit_grandchild_t:s0",
		"u:object_r:kunit_leaf_t:s0",
	};
	struct selinux_label_domain *domain[ARRAY_SIZE(contexts)];
	struct selinux_label_map *map[ARRAY_SIZE(contexts) - 1];
	struct selinux_label_ref *label[ARRAY_SIZE(contexts)];
	struct selinux_state *state;
	const struct selinux_label_view *up_view, *down_view;
	struct selinux_label_resolution resolution;
	u32 sid[ARRAY_SIZE(contexts)], resolved;
	int i, rc;

	state = kunit_kcalloc(test, ARRAY_SIZE(contexts), sizeof(*state),
			      GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);
	domain[0] = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain[0]);
	for (i = 1; i < ARRAY_SIZE(contexts); i++) {
		domain[i] = selinux_test_domain_alloc(test, domain[i - 1]);
		KUNIT_ASSERT_NOT_NULL(test, domain[i]);
	}
	for (i = 0; i < ARRAY_SIZE(contexts); i++) {
		label[i] = selinux_test_global_label(test, &state[i], domain[i],
						     contexts[i], &sid[i]);
		KUNIT_ASSERT_NOT_NULL(test, label[i]);
	}
	for (i = 0; i < ARRAY_SIZE(map); i++) {
		map[i] = selinux_test_label_map_alloc(test, domain[i],
						      domain[i + 1]);
		KUNIT_ASSERT_NOT_NULL(test, map[i]);
		KUNIT_ASSERT_EQ(test,
				selinux_test_map_pair(map[i], label[i], sid[i],
						      label[i + 1], sid[i + 1]),
				0);
		KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map[i], domain[i]),
				0);
		rc = selinux_test_label_domain_publish_map(test, domain[i + 1],
						   map[i], domain[i]);
		KUNIT_ASSERT_EQ(test, rc, 0);
	}

	/* A leaf-origin view bounded by the root still resolves both endpoints. */
	up_view = selinux_identity_view_alloc(&init_user_ns, domain[3],
					      domain[0]);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, up_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)up_view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = selinux_label_view_resolve_chain(up_view, label[3], sid[3],
					      &resolution);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, resolution.max_depth, (u16)3);
	for (i = 0; i < ARRAY_SIZE(contexts); i++) {
		KUNIT_EXPECT_EQ(test, resolution.domain_id[i], domain[i]->id);
		KUNIT_EXPECT_EQ(test, resolution.sid[i], sid[i]);
		resolved = 0;
		KUNIT_EXPECT_EQ(test,
				selinux_label_view_resolve(up_view, domain[i], label[3],
							   sid[3], &resolved),
				0);
		KUNIT_EXPECT_EQ(test, resolved, sid[i]);
	}
	/* The same sealed view is bidirectional for its two endpoints. */
	rc = selinux_label_view_resolve_chain(up_view, label[0], sid[0],
					      &resolution);
	KUNIT_ASSERT_EQ(test, rc, 0);
	for (i = 0; i < ARRAY_SIZE(contexts); i++) {
		KUNIT_EXPECT_EQ(test, resolution.domain_id[i], domain[i]->id);
		KUNIT_EXPECT_EQ(test, resolution.sid[i], sid[i]);
	}

	/* A root-origin view resolves the same vector while walking downward. */
	down_view = selinux_identity_view_alloc(&init_user_ns, domain[0],
						domain[3]);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, down_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)down_view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = selinux_label_view_resolve_chain(down_view, label[0], sid[0],
					      &resolution);
	KUNIT_ASSERT_EQ(test, rc, 0);
	for (i = 0; i < ARRAY_SIZE(contexts); i++) {
		KUNIT_EXPECT_EQ(test, resolution.domain_id[i], domain[i]->id);
		KUNIT_EXPECT_EQ(test, resolution.sid[i], sid[i]);
	}
}

static void selinux_inode_xattr_observer_view_test(struct kunit *test)
{
	struct selinux_label_domain *root, *child;
	struct selinux_label_ref *root_label, *child_label;
	struct selinux_label_map *map;
	struct selinux_state root_state, child_state;
	const struct selinux_label_view *view;
	u32 root_sid, child_sid, rendered;
	int rc;

	root = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	child = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, child);
	root_label = selinux_test_global_label(
		test, &root_state, root, "u:object_r:kunit_host_xattr_t:s0",
		&root_sid);
	KUNIT_ASSERT_NOT_NULL(test, root_label);
	child_label = selinux_test_global_label(
		test, &child_state, child, "u:object_r:kunit_guest_xattr_t:s0",
		&child_sid);
	KUNIT_ASSERT_NOT_NULL(test, child_label);
	map = selinux_test_label_map_alloc(test, root, child);
	KUNIT_ASSERT_NOT_NULL(test, map);
	KUNIT_ASSERT_EQ(test,
			selinux_test_map_pair(map, root_label, root_sid,
					      child_label, child_sid),
			0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, root), 0);
	KUNIT_ASSERT_EQ(test,
			selinux_test_label_domain_publish_map(test, child, map,
						      root), 0);
	view = selinux_identity_view_alloc(&init_user_ns, root, child);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, view);
	KUNIT_ASSERT_EQ(test,
			kunit_add_action_or_reset(
				test, selinux_test_label_view_put, (void *)view),
			0);

	rendered = 0;
	rc = selinux_kunit_inode_xattr_sid_for_view(
		view, true, child, root_label, root_sid, &rendered);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, rendered, child_sid);
	rendered = 0;
	rc = selinux_kunit_inode_xattr_sid_for_view(
		view, true, root, root_label, root_sid, &rendered);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, rendered, root_sid);

	/* A path-aware call never treats a missing mount view as identity. */
	rc = selinux_kunit_inode_xattr_sid_for_view(
		NULL, true, child, root_label, root_sid, &rendered);
	KUNIT_EXPECT_EQ(test, rc, -EACCES);

	/* A legacy caller may use only an identity intrinsic to its observer. */
	rendered = 0;
	rc = selinux_kunit_inode_xattr_sid_for_view(
		NULL, false, root, root_label, root_sid, &rendered);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, rendered, root_sid);
	rc = selinux_kunit_inode_xattr_sid_for_view(
		NULL, false, child, root_label, root_sid, &rendered);
	KUNIT_EXPECT_EQ(test, rc, -EXDEV);
	rendered = 0;
	rc = selinux_kunit_inode_xattr_sid_for_view(
		NULL, false, child, child_label, child_sid, &rendered);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, rendered, child_sid);

	/* Numeric handles cannot be paired with a different canonical label. */
	rc = selinux_kunit_inode_xattr_sid_for_view(
		NULL, false, root, child_label, root_sid, &rendered);
	KUNIT_EXPECT_EQ(test, rc, -EIO);
}

static void selinux_pathless_domain_origin_test(struct kunit *test)
{
	struct selinux_pathless_projection *projection, *wrong;
	struct selinux_label_domain *root, *child;
	struct selinux_label_ref *root_label, *child_label;
	struct selinux_state root_state, child_state;
	struct selinux_label_map *map;
	const struct selinux_label_view *view;
	u32 root_sid, child_sid;
	int rc;

	root = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	child = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, child);
	root_label = selinux_test_global_label(test, &root_state, root,
					      "u:object_r:kunit_pathless_root_t:s0",
					      &root_sid);
	KUNIT_ASSERT_NOT_NULL(test, root_label);
	child_label = selinux_test_global_label(test, &child_state, child,
					       "u:object_r:kunit_pathless_child_t:s0",
					       &child_sid);
	KUNIT_ASSERT_NOT_NULL(test, child_label);
	map = selinux_test_label_map_alloc(test, root, child);
	KUNIT_ASSERT_NOT_NULL(test, map);
	KUNIT_ASSERT_EQ(test,
			 selinux_test_map_pair(map, root_label, root_sid,
					       child_label, child_sid),
			 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, root), 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_test_label_domain_publish_map(test, child, map,
						       root), 0);
	view = selinux_identity_view_alloc(&init_user_ns, root, child);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)view);
	KUNIT_ASSERT_EQ(test, rc, 0);

	projection = selinux_pathless_projection_alloc(
		SELINUX_PATHLESS_KIND_ANON_INODE, SELINUX_LABEL_SOURCE_TASK,
		root_label, root_sid, view, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, projection);
	rc = kunit_add_action_or_reset(test,
				       selinux_test_pathless_projection_put,
				       projection);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_PTR_EQ(test, projection->label->domain,
			    view->origin_domain);
	KUNIT_EXPECT_PTR_EQ(test, projection->view, view);
	KUNIT_EXPECT_EQ(test, projection->kind,
			(u8)SELINUX_PATHLESS_KIND_ANON_INODE);
	KUNIT_EXPECT_EQ(test, projection->source,
			(u8)SELINUX_LABEL_SOURCE_TASK);

	/* The opposite endpoint cannot masquerade as this view's origin. */
	wrong = selinux_pathless_projection_alloc(
		SELINUX_PATHLESS_KIND_ANON_INODE, SELINUX_LABEL_SOURCE_TASK,
		child_label, child_sid, view, GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(wrong));
	if (IS_ERR(wrong))
		KUNIT_EXPECT_EQ(test, PTR_ERR(wrong), -EINVAL);
}

static void selinux_pathless_missing_map_test(struct kunit *test)
{
	struct selinux_pathless_projection *projection;
	struct selinux_label_domain *root, *child;
	struct selinux_label_ref *root_label;
	struct selinux_state root_state;
	struct selinux_label_view *view;
	u32 root_sid;

	root = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	child = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, child);
	root_label = selinux_test_global_label(test, &root_state, root,
					      "u:object_r:kunit_pathless_missing_t:s0",
					      &root_sid);
	KUNIT_ASSERT_NOT_NULL(test, root_label);
	view = kunit_kzalloc(test, struct_size(view, maps, 1), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, view);
	view->origin_domain = root;
	view->outer_domain = child;
	view->map_count = 1;

	/* A malformed snapshot with an absent boundary map must fail closed. */
	projection = selinux_pathless_projection_alloc(
		SELINUX_PATHLESS_KIND_MEMFD, SELINUX_LABEL_SOURCE_TRANSITION,
		root_label, root_sid, view, GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(projection));
	if (IS_ERR(projection))
		KUNIT_EXPECT_EQ(test, PTR_ERR(projection), -EOPNOTSUPP);
}

static void selinux_pathless_bidirectional_sealed_test(struct kunit *test)
{
	struct selinux_pathless_projection *down, *up;
	struct selinux_label_domain *root, *child;
	struct selinux_label_ref *root_label, *child_label;
	struct selinux_state root_state, child_state;
	struct selinux_label_map *map;
	const struct selinux_label_view *down_view, *up_view;
	u32 root_sid, child_sid, resolved = 0;
	int rc;

	root = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	child = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, child);
	root_label = selinux_test_global_label(test, &root_state, root,
					      "u:object_r:kunit_pathless_bidir_root_t:s0",
					      &root_sid);
	KUNIT_ASSERT_NOT_NULL(test, root_label);
	child_label = selinux_test_global_label(test, &child_state, child,
					       "u:object_r:kunit_pathless_bidir_child_t:s0",
					       &child_sid);
	KUNIT_ASSERT_NOT_NULL(test, child_label);
	map = selinux_test_label_map_alloc(test, root, child);
	KUNIT_ASSERT_NOT_NULL(test, map);
	KUNIT_ASSERT_EQ(test,
			 selinux_test_map_pair(map, root_label, root_sid,
					       child_label, child_sid),
			 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, root), 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_test_label_domain_publish_map(test, child, map,
						       root), 0);
	down_view = selinux_identity_view_alloc(&init_user_ns, root, child);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, down_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)down_view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	up_view = selinux_identity_view_alloc(&init_user_ns, child, root);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, up_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)up_view);
	KUNIT_ASSERT_EQ(test, rc, 0);

	down = selinux_pathless_projection_alloc(
		SELINUX_PATHLESS_KIND_MEMFD, SELINUX_LABEL_SOURCE_TRANSITION,
		root_label, root_sid, down_view, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, down);
	rc = kunit_add_action_or_reset(test,
				       selinux_test_pathless_projection_put, down);
	KUNIT_ASSERT_EQ(test, rc, 0);
	up = selinux_pathless_projection_alloc(
		SELINUX_PATHLESS_KIND_BPF, SELINUX_LABEL_SOURCE_TASK,
		child_label, child_sid, up_view, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, up);
	rc = kunit_add_action_or_reset(test,
				       selinux_test_pathless_projection_put, up);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_NE(test, down->id, (u64)0);
	KUNIT_EXPECT_NE(test, up->id, (u64)0);
	KUNIT_EXPECT_NE(test, down->id, up->id);

	KUNIT_EXPECT_EQ(test,
			selinux_pathless_projection_resolve(down, child,
							     &resolved),
			0);
	KUNIT_EXPECT_EQ(test, resolved, child_sid);
	resolved = 0;
	KUNIT_EXPECT_EQ(test,
			selinux_pathless_projection_resolve(up, root, &resolved),
			0);
	KUNIT_EXPECT_EQ(test, resolved, root_sid);
}

static void selinux_pathless_projection_seals_test(struct kunit *test)
{
	struct selinux_pathless_projection *projection, *second;
	struct selinux_pathless_resolution resolved;
	struct selinux_pathless_expect expects[2];
	struct selinux_label_domain *root, *child, *sibling;
	struct selinux_label_ref *root_label, *child_label;
	struct selinux_state root_state, child_state;
	struct selinux_label_map *map;
	const struct selinux_label_view *view;
	u32 root_sid, child_sid;
	int rc;

	root = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	child = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, child);
	sibling = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, sibling);
	root_label = selinux_test_global_label(
		test, &root_state, root,
		"u:object_r:kunit_pathless_sealed_root_t:s0", &root_sid);
	KUNIT_ASSERT_NOT_NULL(test, root_label);
	child_label = selinux_test_global_label(
		test, &child_state, child,
		"u:object_r:kunit_pathless_sealed_child_t:s0", &child_sid);
	KUNIT_ASSERT_NOT_NULL(test, child_label);
	map = selinux_test_label_map_alloc(test, root, child);
	KUNIT_ASSERT_NOT_NULL(test, map);
	KUNIT_ASSERT_EQ(test,
			 selinux_test_map_pair(map, root_label, root_sid,
					       child_label, child_sid),
			 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, root), 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_test_label_domain_publish_map(test, child, map,
						       root), 0);
	view = selinux_identity_view_alloc(&init_user_ns, child, root);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)view);
	KUNIT_ASSERT_EQ(test, rc, 0);

	expects[0] = (struct selinux_pathless_expect) {
		.domain = root,
		.sid = root_sid,
		.sclass = 41,
		.model = SELINUX_PATHLESS_MODEL_LEGACY,
	};
	expects[1] = (struct selinux_pathless_expect) {
		.domain = child,
		.sid = child_sid,
		.sclass = 42,
		.model = SELINUX_PATHLESS_MODEL_TRANSITION,
	};
	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_MEMFD, SELINUX_LABEL_SOURCE_TRANSITION,
		child_label, child_sid, view, expects, ARRAY_SIZE(expects),
		GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, projection);
	rc = kunit_add_action_or_reset(test,
				       selinux_test_pathless_projection_put,
				       projection);
	KUNIT_ASSERT_EQ(test, rc, 0);

	KUNIT_EXPECT_LE(test, sizeof(struct selinux_pathless_seal), (size_t)32);
	KUNIT_EXPECT_EQ(test, projection->seal_count, (u16)2);
	KUNIT_ASSERT_NOT_NULL(test, projection->sid_handle);
	KUNIT_EXPECT_EQ(test, global_sid_handle_sid(projection->sid_handle),
			child_sid);
	KUNIT_ASSERT_NOT_NULL(test, projection->seals[0].sid_handle);
	KUNIT_EXPECT_EQ(test,
			global_sid_handle_sid(projection->seals[0].sid_handle),
			root_sid);
	KUNIT_EXPECT_EQ(test, projection->seals[0].domain_id, root->id);
	KUNIT_EXPECT_EQ(test, projection->seals[0].sid, root_sid);
	KUNIT_EXPECT_EQ(test, projection->seals[0].sclass, (u16)41);
	KUNIT_EXPECT_EQ(test, projection->seals[0].model,
			(u8)SELINUX_PATHLESS_MODEL_LEGACY);
	KUNIT_EXPECT_EQ(test, projection->seals[0].reserved, (u8)0);
	KUNIT_EXPECT_EQ(test, projection->seals[1].domain_id, child->id);
	KUNIT_EXPECT_EQ(test, projection->seals[1].sid, child_sid);

	memset(&resolved, 0, sizeof(resolved));
	KUNIT_ASSERT_EQ(test,
			 selinux_pathless_projection_resolve_sealed(
				 projection, root, &resolved),
			 0);
	KUNIT_EXPECT_EQ(test, resolved.sid, root_sid);
	KUNIT_EXPECT_EQ(test, resolved.sclass, (u16)41);
	KUNIT_EXPECT_EQ(test, resolved.model,
			(u8)SELINUX_PATHLESS_MODEL_LEGACY);
	memset(&resolved, 0, sizeof(resolved));
	KUNIT_ASSERT_EQ(test,
			 selinux_pathless_projection_resolve_sealed(
				 projection, child, &resolved),
			 0);
	KUNIT_EXPECT_EQ(test, resolved.sid, child_sid);
	KUNIT_EXPECT_EQ(test, resolved.sclass, (u16)42);
	KUNIT_EXPECT_EQ(test, resolved.model,
			(u8)SELINUX_PATHLESS_MODEL_TRANSITION);

	/* Same depth is insufficient: the durable domain identity must match. */
	KUNIT_EXPECT_EQ(test,
			selinux_pathless_projection_resolve_sealed(
				projection, sibling, &resolved),
			-EOPNOTSUPP);

	second = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_MEMFD, SELINUX_LABEL_SOURCE_TRANSITION,
		child_label, child_sid, view, expects, ARRAY_SIZE(expects),
		GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, second);
	rc = kunit_add_action_or_reset(test,
				       selinux_test_pathless_projection_put, second);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_GT(test, second->id, projection->id);
}

static void selinux_pathless_projection_seal_validation_test(struct kunit *test)
{
	struct selinux_pathless_projection *projection;
	struct selinux_pathless_resolution resolved;
	struct selinux_pathless_expect expects[2];
	struct selinux_label_domain *root, *child;
	struct selinux_label_ref *root_label, *child_label, *kernel_label;
	struct selinux_state root_state, child_state;
	struct selinux_label_map *map;
	const struct selinux_label_view *down_view, *up_view;
	u32 root_sid, child_sid;
	int rc;

	root = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	child = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, child);
	root_label = selinux_test_global_label(
		test, &root_state, root,
		"u:object_r:kunit_pathless_validate_root_t:s0", &root_sid);
	KUNIT_ASSERT_NOT_NULL(test, root_label);
	child_label = selinux_test_global_label(
		test, &child_state, child,
		"u:object_r:kunit_pathless_validate_child_t:s0", &child_sid);
	KUNIT_ASSERT_NOT_NULL(test, child_label);
	map = selinux_test_label_map_alloc(test, root, child);
	KUNIT_ASSERT_NOT_NULL(test, map);
	KUNIT_ASSERT_EQ(test,
			 selinux_test_map_pair(map, root_label, root_sid,
					       child_label, child_sid),
			 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, root), 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_test_label_domain_publish_map(test, child, map,
						       root), 0);
	up_view = selinux_identity_view_alloc(&init_user_ns, child, root);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, up_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)up_view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	down_view = selinux_identity_view_alloc(&init_user_ns, root, child);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, down_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)down_view);
	KUNIT_ASSERT_EQ(test, rc, 0);

	expects[0] = (struct selinux_pathless_expect) {
		.domain = root,
		.sid = root_sid,
		.sclass = 51,
		.model = SELINUX_PATHLESS_MODEL_LEGACY,
	};
	expects[1] = (struct selinux_pathless_expect) {
		.domain = child,
		.sid = child_sid,
		.sclass = 52,
		.model = SELINUX_PATHLESS_MODEL_CONTEXT_COPY,
	};

	/* The resolved SID vector is part of construction, not a hint. */
	expects[0].sid++;
	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_ANON_INODE,
		SELINUX_LABEL_SOURCE_SECURITY_CONTEXT, child_label, child_sid,
		up_view, expects, ARRAY_SIZE(expects), GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(projection));
	if (IS_ERR(projection))
		KUNIT_EXPECT_EQ(test, PTR_ERR(projection), -EINVAL);
	expects[0].sid = root_sid;

	/* Every depth must be present and carry a valid immutable model. */
	expects[1].model = SELINUX_PATHLESS_MODEL_INVALID;
	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_ANON_INODE,
		SELINUX_LABEL_SOURCE_SECURITY_CONTEXT, child_label, child_sid,
		up_view, expects, ARRAY_SIZE(expects), GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(projection));
	if (IS_ERR(projection))
		KUNIT_EXPECT_EQ(test, PTR_ERR(projection), -EINVAL);
	expects[1].model = SELINUX_PATHLESS_MODEL_CONTEXT_COPY;
	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_ANON_INODE,
		SELINUX_LABEL_SOURCE_SECURITY_CONTEXT, child_label, child_sid,
		up_view, &expects[1], 1, GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(projection));
	if (IS_ERR(projection))
		KUNIT_EXPECT_EQ(test, PTR_ERR(projection), -EINVAL);

	/* Preserve an ancestor canonical identity across a descendant view. */
	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_ANON_INODE, SELINUX_LABEL_SOURCE_TRANSITION,
		root_label, root_sid, down_view, expects, ARRAY_SIZE(expects),
		GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, projection);
	KUNIT_EXPECT_PTR_EQ(test, projection->label, root_label);
	KUNIT_EXPECT_PTR_EQ(test, projection->label->domain, root);
	KUNIT_ASSERT_EQ(test,
			 selinux_pathless_projection_resolve_sealed(
				 projection, root, &resolved),
			 0);
	KUNIT_EXPECT_EQ(test, resolved.sid, root_sid);
	KUNIT_ASSERT_EQ(test,
			 selinux_pathless_projection_resolve_sealed(
				 projection, child, &resolved),
			 0);
	KUNIT_EXPECT_EQ(test, resolved.sid, child_sid);
	selinux_pathless_projection_kunit_put_and_wait(projection);

	/* No flexible-array arithmetic may wrap before validation. */
	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_ANON_INODE, SELINUX_LABEL_SOURCE_TRANSITION,
		child_label, child_sid, up_view, expects, SIZE_MAX, GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(projection));
	if (IS_ERR(projection))
		KUNIT_EXPECT_EQ(test, PTR_ERR(projection), -EOVERFLOW);
	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_ANON_INODE, SELINUX_LABEL_SOURCE_TRANSITION,
		child_label, child_sid, up_view, expects,
		SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 2, GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(projection));
	if (IS_ERR(projection))
		KUNIT_EXPECT_EQ(test, PTR_ERR(projection), -E2BIG);

	kernel_label = global_sid_to_label_ref(SECINITSID_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, kernel_label);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put,
				       kernel_label);
	KUNIT_ASSERT_EQ(test, rc, 0);
	expects[0].sid = SECINITSID_KERNEL;
	expects[1].sid = SECINITSID_KERNEL;
	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_ANON_INODE,
		SELINUX_LABEL_SOURCE_KERNEL_INITIAL, kernel_label,
		SECINITSID_KERNEL, up_view, expects, ARRAY_SIZE(expects),
		GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, projection);
	rc = kunit_add_action_or_reset(test,
				       selinux_test_pathless_projection_put,
				       projection);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test,
			selinux_pathless_projection_resolve_sealed(
				projection, root, &resolved),
			0);
	KUNIT_EXPECT_EQ(test, resolved.sid, (u32)SECINITSID_KERNEL);
	KUNIT_EXPECT_EQ(test,
			selinux_pathless_projection_resolve_sealed(
				projection, child, &resolved),
			0);
	KUNIT_EXPECT_EQ(test, resolved.sid, (u32)SECINITSID_KERNEL);

	/* A global initial identity cannot authorize a non-bootstrap source. */
	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_ANON_INODE, SELINUX_LABEL_SOURCE_TASK,
		kernel_label, SECINITSID_KERNEL, up_view, expects,
		ARRAY_SIZE(expects), GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(projection));
	if (IS_ERR(projection))
		KUNIT_EXPECT_EQ(test, PTR_ERR(projection), -EINVAL);
}

static void selinux_pathless_persistent_object_kinds_test(struct kunit *test)
{
	struct selinux_pathless_projection *projection;
	struct selinux_pathless_expect expect;
	struct selinux_label_domain *domain;
	struct selinux_label_ref *label;
	struct selinux_state state;
	const struct selinux_label_view *view;
	u32 sid;
	int kind, rc;

	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	label = selinux_test_global_label(
		test, &state, domain,
		"u:object_r:kunit_persistent_object_t:s0", &sid);
	KUNIT_ASSERT_NOT_NULL(test, label);
	view = selinux_identity_view_alloc(&init_user_ns, domain, domain);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)view);
	KUNIT_ASSERT_EQ(test, rc, 0);

	expect = (struct selinux_pathless_expect) {
		.domain = domain,
		.sid = sid,
		.sclass = 73,
		.model = SELINUX_PATHLESS_MODEL_LEGACY,
	};
	for (kind = SELINUX_PATHLESS_KIND_KEY;
	     kind <= SELINUX_PATHLESS_KIND_INFINIBAND; kind++) {
		projection = selinux_pathless_projection_alloc_sealed(
			kind, SELINUX_LABEL_SOURCE_TASK, label, sid, view,
			&expect, 1, GFP_KERNEL);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, projection);
		KUNIT_EXPECT_EQ(test, projection->kind, (u8)kind);
		KUNIT_EXPECT_EQ(test, projection->seal_count, (u16)1);
		selinux_pathless_projection_kunit_put_and_wait(projection);
	}
	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_MAX, SELINUX_LABEL_SOURCE_TASK, label, sid,
		view, &expect, 1, GFP_KERNEL);
	KUNIT_EXPECT_TRUE(test, IS_ERR(projection));
	if (IS_ERR(projection))
		KUNIT_EXPECT_EQ(test, PTR_ERR(projection), -EINVAL);
}

static void selinux_pathless_initial_sid_refcount_test(struct kunit *test)
{
	struct selinux_pathless_projection *projection;
	struct selinux_label_domain *domain;
	struct selinux_label_ref *label;
	const struct selinux_label_view *view;
	int label_refs, view_refs;
	u32 resolved = 0;
	int rc;

	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	view = selinux_identity_view_alloc(&init_user_ns, domain, domain);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	label = global_sid_to_label_ref(SECINITSID_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, label);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put, label);
	KUNIT_ASSERT_EQ(test, rc, 0);
	label_refs = refcount_read(&label->refs);
	view_refs = refcount_read(&view->refs);

	projection = selinux_pathless_projection_alloc(
		SELINUX_PATHLESS_KIND_ANON_INODE,
		SELINUX_LABEL_SOURCE_KERNEL_INITIAL, label, SECINITSID_KERNEL,
		view, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, projection);
	rc = kunit_add_action_or_reset(test,
				       selinux_test_pathless_projection_put,
				       projection);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, projection->sid, (u32)SECINITSID_KERNEL);
	KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), label_refs + 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&view->refs), view_refs + 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&projection->refs), 1);
	KUNIT_EXPECT_PTR_EQ(test,
			    selinux_pathless_projection_get(projection), projection);
	KUNIT_EXPECT_EQ(test, refcount_read(&projection->refs), 2);
	selinux_pathless_projection_put(projection);
	KUNIT_EXPECT_EQ(test, refcount_read(&projection->refs), 1);
	KUNIT_EXPECT_EQ(test,
			selinux_pathless_projection_resolve(projection, domain,
							     &resolved),
			0);
	KUNIT_EXPECT_EQ(test, resolved, (u32)SECINITSID_KERNEL);
}

static void selinux_pathless_projection_sid_lifetime_test(struct kunit *test)
{
	static const char context[] =
		"u:object_r:kunit_pathless_sid_lifetime_t:s0";
	struct selinux_global_sid_handle *stale;
	struct selinux_pathless_projection *projection;
	struct selinux_pathless_resolution resolution;
	struct selinux_pathless_expect expect;
	struct selinux_label_domain *domain;
	struct selinux_label_ref *label;
	struct selinux_state state;
	const struct selinux_label_view *view;
	u32 sid;
	int rc;

	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	label = selinux_test_global_label(test, &state, domain, context, &sid);
	KUNIT_ASSERT_NOT_NULL(test, label);
	view = selinux_identity_view_alloc(&init_user_ns, domain, domain);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	expect = (struct selinux_pathless_expect) {
		.domain = domain,
		.sid = sid,
		.sclass = 74,
		.model = SELINUX_PATHLESS_MODEL_LEGACY,
	};
	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_MEMFD, SELINUX_LABEL_SOURCE_TRANSITION,
		label, sid, view, &expect, 1, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, projection);
	rc = kunit_add_action_or_reset(test,
				       selinux_test_pathless_projection_put,
				       projection);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_NOT_NULL(test, projection->sid_handle);
	KUNIT_ASSERT_NOT_NULL(test, projection->seals[0].sid_handle);
	/* Equal payload addresses still represent two independently owned refs. */
	KUNIT_EXPECT_PTR_EQ(test, projection->sid_handle,
			    projection->seals[0].sid_handle);
	KUNIT_EXPECT_EQ(test, global_sid_handle_sid(projection->sid_handle),
			sid);
	KUNIT_EXPECT_EQ(test,
			global_sid_handle_sid(projection->seals[0].sid_handle),
			sid);

	KUNIT_ASSERT_EQ(test, selinux_kunit_global_sid_drop_baseline(sid), 0);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(sid));
	KUNIT_EXPECT_EQ(test,
			selinux_pathless_projection_resolve_sealed(
				projection, domain, &resolution),
			0);
	KUNIT_EXPECT_EQ(test, resolution.sid, sid);

	/* Both durable references are dropped with the projection payload. */
	kunit_release_action(test, selinux_test_pathless_projection_put,
			     projection);
	rcu_barrier();
	rcu_barrier();
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(sid));
	stale = global_sid_handle_get(sid);
	KUNIT_ASSERT_TRUE(test, IS_ERR(stale));
	KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);
}

static void selinux_label_view_chain_fail_closed_test(struct kunit *test)
{
	struct selinux_label_domain *root, *child, *sibling;
	struct selinux_label_map *map;
	struct selinux_label_ref *root_label, *child_label, *sibling_label;
	struct selinux_state root_state, child_state, sibling_state;
	const struct selinux_label_view *view;
	struct selinux_label_resolution resolution;
	u32 root_sid, child_sid, sibling_sid, resolved = 0;
	int rc;

	root = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	child = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, child);
	sibling = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, sibling);
	root_label = selinux_test_global_label(test, &root_state, root,
					       "u:object_r:kunit_fc_root_t:s0",
					       &root_sid);
	KUNIT_ASSERT_NOT_NULL(test, root_label);
	child_label = selinux_test_global_label(test, &child_state, child,
						"u:object_r:kunit_fc_child_t:s0",
						&child_sid);
	KUNIT_ASSERT_NOT_NULL(test, child_label);
	sibling_label = selinux_test_global_label(test, &sibling_state, sibling,
						  "u:object_r:kunit_fc_sibling_t:s0",
						  &sibling_sid);
	KUNIT_ASSERT_NOT_NULL(test, sibling_label);
	map = selinux_test_label_map_alloc(test, root, child);
	KUNIT_ASSERT_NOT_NULL(test, map);
	KUNIT_ASSERT_EQ(test, selinux_test_map_pair(map, root_label, root_sid,
						    child_label, child_sid), 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, root), 0);
	rc = selinux_test_label_domain_publish_map(test, child, map, root);
	KUNIT_ASSERT_EQ(test, rc, 0);
	view = selinux_identity_view_alloc(&init_user_ns, root, child);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)view);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* An exact SID/label mismatch must fail before an identity shortcut. */
	rc = selinux_label_view_resolve_chain(view, root_label, child_sid,
					      &resolution);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
	/* A policy outside the captured ancestry chain must never be consulted. */
	rc = selinux_label_view_resolve(view, sibling, root_label, root_sid,
					&resolved);
	KUNIT_EXPECT_EQ(test, rc, -EOPNOTSUPP);
	/* A label from the sibling provenance domain is not valid in this view. */
	rc = selinux_label_view_resolve_chain(view, sibling_label, sibling_sid,
					      &resolution);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void selinux_label_view_stale_snapshot_resolution_test(struct kunit *test)
{
	struct selinux_label_domain *root, *child;
	struct selinux_label_map *first, *second;
	struct selinux_label_ref *root_label, *first_child, *second_child;
	struct selinux_state root_state, first_state, second_state;
	const struct selinux_label_view *first_view, *second_view;
	u32 root_sid, first_sid, second_sid, resolved;
	int rc;

	root = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	child = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, child);
	root_label = selinux_test_global_label(test, &root_state, root,
					       "u:object_r:kunit_snap_root_t:s0",
					       &root_sid);
	KUNIT_ASSERT_NOT_NULL(test, root_label);
	first_child = selinux_test_global_label(test, &first_state, child,
						"u:object_r:kunit_snap_first_t:s0",
						&first_sid);
	KUNIT_ASSERT_NOT_NULL(test, first_child);
	second_child = selinux_test_global_label(test, &second_state, child,
						 "u:object_r:kunit_snap_second_t:s0",
						 &second_sid);
	KUNIT_ASSERT_NOT_NULL(test, second_child);

	first = selinux_test_label_map_alloc(test, root, child);
	KUNIT_ASSERT_NOT_NULL(test, first);
	rc = selinux_test_map_pair(first, root_label, root_sid, first_child,
				   first_sid);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(first, root), 0);
	rc = selinux_test_label_domain_publish_map(test, child, first, root);
	KUNIT_ASSERT_EQ(test, rc, 0);
	first_view = selinux_identity_view_alloc(&init_user_ns, root, child);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)first_view);
	KUNIT_ASSERT_EQ(test, rc, 0);

	second = selinux_test_label_map_alloc(test, root, child);
	KUNIT_ASSERT_NOT_NULL(test, second);
	rc = selinux_test_map_pair(second, root_label, root_sid, second_child,
				   second_sid);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(second, root), 0);
	rc = selinux_test_label_domain_publish_map(test, child, second, root);
	KUNIT_ASSERT_EQ(test, rc, 0);
	second_view = selinux_identity_view_alloc(&init_user_ns, root, child);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, second_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)second_view);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* A published replacement cannot reinterpret the old immutable view. */
	resolved = 0;
	rc = selinux_label_view_resolve(first_view, child, root_label, root_sid,
					&resolved);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, resolved, first_sid);
	resolved = 0;
	rc = selinux_label_view_resolve(second_view, child, root_label, root_sid,
					&resolved);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, resolved, second_sid);
}

static void selinux_label_operation_sibling_snapshot_test(struct kunit *test)
{
	struct selinux_label_domain *root, *source_domain, *target_domain;
	struct selinux_label_domain *missing_domain;
	struct selinux_label_map *source_map, *first_target, *second_target;
	struct selinux_label_ref *root_label, *source_label;
	struct selinux_label_ref *first_label, *second_label;
	struct selinux_state root_state, source_state, first_state, second_state;
	const struct selinux_label_view *source_view;
	struct selinux_label_operation_resolution *first, *second, *failed;
	u32 root_sid, source_sid, first_sid, second_sid;
	int refs, rc;

	root = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	source_domain = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, source_domain);
	target_domain = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, target_domain);
	missing_domain = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, missing_domain);
	first = kunit_kzalloc(test, sizeof(*first), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, first);
	second = kunit_kzalloc(test, sizeof(*second), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, second);
	failed = kunit_kzalloc(test, sizeof(*failed), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, failed);
	root_label = selinux_test_global_label(
		test, &root_state, root, "u:object_r:kunit_op_root_t:s0",
		&root_sid);
	KUNIT_ASSERT_NOT_NULL(test, root_label);
	source_label = selinux_test_global_label(
		test, &source_state, source_domain,
		"u:object_r:kunit_op_source_t:s0", &source_sid);
	KUNIT_ASSERT_NOT_NULL(test, source_label);
	first_label = selinux_test_global_label(
		test, &first_state, target_domain,
		"u:object_r:kunit_op_first_t:s0", &first_sid);
	KUNIT_ASSERT_NOT_NULL(test, first_label);
	second_label = selinux_test_global_label(
		test, &second_state, target_domain,
		"u:object_r:kunit_op_second_t:s0", &second_sid);
	KUNIT_ASSERT_NOT_NULL(test, second_label);

	source_map = selinux_test_label_map_alloc(test, root, source_domain);
	KUNIT_ASSERT_NOT_NULL(test, source_map);
	KUNIT_ASSERT_EQ(test, selinux_test_map_pair(
		source_map, root_label, root_sid, source_label, source_sid), 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(source_map, root), 0);
	KUNIT_ASSERT_EQ(test, selinux_test_label_domain_publish_map(
		test, source_domain, source_map, root), 0);
	source_view = selinux_identity_view_alloc(
		&init_user_ns, root, source_domain);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, source_view);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(
		test, selinux_test_label_view_put, (void *)source_view), 0);

	first_target = selinux_test_label_map_alloc(test, root, target_domain);
	KUNIT_ASSERT_NOT_NULL(test, first_target);
	KUNIT_ASSERT_EQ(test, selinux_test_map_pair(
		first_target, root_label, root_sid, first_label, first_sid), 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(first_target, root), 0);
	KUNIT_ASSERT_EQ(test, selinux_test_label_domain_publish_map(
		test, target_domain, first_target, root), 0);

	rc = selinux_label_view_resolve_operation(
		source_view, source_label, source_sid, target_domain, first);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(
		test, selinux_test_label_operation_put, first), 0);
	KUNIT_EXPECT_EQ(test, first->labels.sid[0], root_sid);
	KUNIT_EXPECT_EQ(test, first->labels.sid[1], first_sid);
	KUNIT_EXPECT_PTR_EQ(test, first->source_maps[0], source_map);
	KUNIT_EXPECT_PTR_EQ(test, first->target_maps[0], first_target);

	second_target = selinux_test_label_map_alloc(test, root, target_domain);
	KUNIT_ASSERT_NOT_NULL(test, second_target);
	KUNIT_ASSERT_EQ(test, selinux_test_map_pair(
		second_target, root_label, root_sid, second_label, second_sid), 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(second_target, root), 0);
	KUNIT_ASSERT_EQ(test, selinux_test_label_domain_publish_map(
		test, target_domain, second_target, root), 0);
	rc = selinux_label_view_resolve_operation(
		source_view, source_label, source_sid, target_domain, second);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(
		test, selinux_test_label_operation_put, second), 0);
	KUNIT_EXPECT_EQ(test, first->labels.sid[1], first_sid);
	KUNIT_EXPECT_EQ(test, second->labels.sid[1], second_sid);
	KUNIT_EXPECT_NE(test, first->map_generation[1],
			second->map_generation[1]);

	refs = refcount_read(&source_map->refs);
	rc = selinux_label_view_resolve_operation(
		source_view, source_label, source_sid, missing_domain, failed);
	KUNIT_EXPECT_EQ(test, rc, -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, refcount_read(&source_map->refs), refs);
	selinux_label_operation_resolution_put(failed);
}

static void selinux_label_operation_cousin_lca_test(struct kunit *test)
{
	struct selinux_label_domain *root, *common, *source_domain, *target_domain;
	struct selinux_label_map *common_map, *source_map, *target_map;
	struct selinux_label_ref *root_label, *common_label;
	struct selinux_label_ref *source_label, *target_label;
	struct selinux_state root_state, common_state, source_state, target_state;
	struct selinux_label_operation_resolution *operation;
	const struct selinux_label_view *source_view;
	u32 root_sid, common_sid, source_sid, target_sid;
	int rc;

	root = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	common = selinux_test_domain_alloc(test, root);
	KUNIT_ASSERT_NOT_NULL(test, common);
	source_domain = selinux_test_domain_alloc(test, common);
	KUNIT_ASSERT_NOT_NULL(test, source_domain);
	target_domain = selinux_test_domain_alloc(test, common);
	KUNIT_ASSERT_NOT_NULL(test, target_domain);
	operation = kunit_kzalloc(test, sizeof(*operation), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, operation);
	root_label = selinux_test_global_label(
		test, &root_state, root, "u:object_r:kunit_lca_root_t:s0",
		&root_sid);
	KUNIT_ASSERT_NOT_NULL(test, root_label);
	common_label = selinux_test_global_label(
		test, &common_state, common, "u:object_r:kunit_lca_common_t:s0",
		&common_sid);
	KUNIT_ASSERT_NOT_NULL(test, common_label);
	source_label = selinux_test_global_label(
		test, &source_state, source_domain,
		"u:object_r:kunit_lca_source_t:s0", &source_sid);
	KUNIT_ASSERT_NOT_NULL(test, source_label);
	target_label = selinux_test_global_label(
		test, &target_state, target_domain,
		"u:object_r:kunit_lca_target_t:s0", &target_sid);
	KUNIT_ASSERT_NOT_NULL(test, target_label);

	common_map = selinux_test_label_map_alloc(test, root, common);
	KUNIT_ASSERT_NOT_NULL(test, common_map);
	KUNIT_ASSERT_EQ(test, selinux_test_map_pair(
		common_map, root_label, root_sid, common_label, common_sid), 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(common_map, root), 0);
	KUNIT_ASSERT_EQ(test, selinux_test_label_domain_publish_map(
		test, common, common_map, root), 0);
	source_map = selinux_test_label_map_alloc(test, common, source_domain);
	KUNIT_ASSERT_NOT_NULL(test, source_map);
	KUNIT_ASSERT_EQ(test, selinux_test_map_pair(
		source_map, common_label, common_sid, source_label, source_sid), 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(source_map, common), 0);
	KUNIT_ASSERT_EQ(test, selinux_test_label_domain_publish_map(
		test, source_domain, source_map, common), 0);
	target_map = selinux_test_label_map_alloc(test, common, target_domain);
	KUNIT_ASSERT_NOT_NULL(test, target_map);
	KUNIT_ASSERT_EQ(test, selinux_test_map_pair(
		target_map, common_label, common_sid, target_label, target_sid), 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(target_map, common), 0);
	KUNIT_ASSERT_EQ(test, selinux_test_label_domain_publish_map(
		test, target_domain, target_map, common), 0);

	source_view = selinux_identity_view_alloc(
		&init_user_ns, root, source_domain);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, source_view);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(
		test, selinux_test_label_view_put, (void *)source_view), 0);
	rc = selinux_label_view_resolve_operation(
		source_view, source_label, source_sid, target_domain, operation);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(
		test, selinux_test_label_operation_put, operation), 0);
	KUNIT_EXPECT_EQ(test, operation->labels.sid[0], root_sid);
	KUNIT_EXPECT_EQ(test, operation->labels.sid[1], common_sid);
	KUNIT_EXPECT_EQ(test, operation->labels.sid[2], target_sid);
	KUNIT_EXPECT_PTR_EQ(test, operation->source_maps[1], source_map);
	KUNIT_EXPECT_PTR_EQ(test, operation->target_maps[1], target_map);
}

static void selinux_secmark_carrier_match_test(struct kunit *test)
{
	struct selinux_net_provenance *correct = NULL, *wrong_class = NULL;
	struct selinux_net_provenance *wrong_source = NULL;
	struct selinux_label_domain *domain;
	struct selinux_label_ref *label;
	const struct selinux_label_view *view;
	struct selinux_state *state;
	const u32 sid = SECINITSID_KERNEL;
	int rc;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);
	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	/* Assertions require the exact canonical label for their SID handle. */
	label = global_sid_to_label_ref(sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, label);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put, label);
	KUNIT_ASSERT_EQ(test, rc, 0);
	view = selinux_identity_view_alloc(&init_user_ns, domain, domain);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	selinux_test_state_init(state, 1);
	refcount_set(&state->count, 1);
	state->label_domain = domain;

	correct = selinux_test_net_provenance_alloc(
		test, state, view, label, sid, SECCLASS_PACKET,
		SELINUX_NET_ASSERTION_SOURCE_SECMARK);
	if (!correct)
		goto out;
	wrong_class = selinux_test_net_provenance_alloc(
		test, state, view, label, sid, SECCLASS_SOCKET,
		SELINUX_NET_ASSERTION_SOURCE_SECMARK);
	if (!wrong_class)
		goto out;
	wrong_source = selinux_test_net_provenance_alloc(
		test, state, view, label, sid, SECCLASS_PACKET,
		SELINUX_NET_ASSERTION_SOURCE_SOCKET);
	if (!wrong_source)
		goto out;

	KUNIT_EXPECT_TRUE(test,
			  selinux_secmark_provenance_matches(correct, sid));
	KUNIT_EXPECT_FALSE(test,
			   selinux_secmark_provenance_matches(correct, sid + 1));
	KUNIT_EXPECT_FALSE(test,
			   selinux_secmark_provenance_matches(wrong_class, sid));
	KUNIT_EXPECT_FALSE(test,
			   selinux_secmark_provenance_matches(wrong_source, sid));

	/* A non-zero bare mark, or a carrier left behind after clearing, fails. */
	KUNIT_EXPECT_FALSE(test,
			   selinux_secmark_provenance_matches(NULL, sid));
	KUNIT_EXPECT_FALSE(test,
			   selinux_secmark_provenance_matches(correct, 0));
	KUNIT_EXPECT_TRUE(test,
			  selinux_secmark_provenance_matches(NULL, 0));

out:
	if (wrong_source)
		kunit_release_action(test, selinux_test_net_provenance_put,
				     wrong_source);
	if (wrong_class)
		kunit_release_action(test, selinux_test_net_provenance_put,
				     wrong_class);
	if (correct)
		kunit_release_action(test, selinux_test_net_provenance_put,
				     correct);
	/* The provenance callback is the last user of the stack-independent state. */
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, refcount_read(&state->count), 1);
}

static void selinux_secmark_carrier_sealed_view_test(struct kunit *test)
{
	struct selinux_net_provenance *up = NULL, *down = NULL;
	struct selinux_netns_security netsec = {};
	struct selinux_label_domain *parent, *child;
	struct selinux_label_ref *parent_label, *child_label;
	const struct selinux_label_view *up_view, *down_view;
	struct selinux_state *parent_state, *child_state;
	struct user_namespace *other_userns;
	struct selinux_label_map *map;
	u32 parent_sid, child_sid, resolved;
	int rc;

	parent_state = kunit_kzalloc(test, sizeof(*parent_state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, parent_state);
	child_state = kunit_kzalloc(test, sizeof(*child_state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_state);
	other_userns = kunit_kzalloc(test, sizeof(*other_userns), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, other_userns);
	parent = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, parent);
	child = selinux_test_domain_alloc(test, parent);
	KUNIT_ASSERT_NOT_NULL(test, child);
	parent_label = selinux_test_global_label(
		test, parent_state, parent,
		"u:object_r:kunit_secmark_parent_t:s0", &parent_sid);
	KUNIT_ASSERT_NOT_NULL(test, parent_label);
	child_label = selinux_test_global_label(
		test, child_state, child,
		"u:object_r:kunit_secmark_child_t:s0", &child_sid);
	KUNIT_ASSERT_NOT_NULL(test, child_label);
	refcount_set(&parent_state->count, 1);
	refcount_set(&child_state->count, 1);

	map = selinux_test_label_map_alloc(test, parent, child);
	KUNIT_ASSERT_NOT_NULL(test, map);
	KUNIT_ASSERT_EQ(test,
			 selinux_test_map_pair(map, parent_label, parent_sid,
					       child_label, child_sid),
			 0);
	KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, parent), 0);
	KUNIT_ASSERT_EQ(test,
			 selinux_test_label_domain_publish_map(test, child, map,
						       parent), 0);

	up_view = selinux_identity_view_alloc(&init_user_ns, child, parent);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, up_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)up_view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	down_view = selinux_identity_view_alloc(&init_user_ns, parent, child);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, down_view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)down_view);
	KUNIT_ASSERT_EQ(test, rc, 0);

	up = selinux_test_net_provenance_alloc(
		test, child_state, up_view, child_label, child_sid,
		SECCLASS_PACKET, SELINUX_NET_ASSERTION_SOURCE_SECMARK);
	if (!up)
		goto out;
	down = selinux_test_net_provenance_alloc(
		test, parent_state, down_view, parent_label, parent_sid,
		SECCLASS_PACKET, SELINUX_NET_ASSERTION_SOURCE_SECMARK);
	if (!down)
		goto out;

	KUNIT_EXPECT_TRUE(test,
			  selinux_secmark_provenance_matches(up, child_sid));
	resolved = 0;
	rc = selinux_label_view_resolve(up->view, parent, up->subject->label,
					up->subject->sid, &resolved);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, resolved, parent_sid);
	/* A numerically equal host SID must never replace the mapped identity. */
	KUNIT_ASSERT_NE(test, parent_sid, child_sid);
	KUNIT_EXPECT_NE(test, resolved, child_sid);

	netsec.state = child_state;
	netsec.view = up_view;
	KUNIT_EXPECT_TRUE(test, selinux_kunit_secmark_netns_view_valid(
				     &netsec, &init_user_ns));
	netsec.state = parent_state;
	KUNIT_EXPECT_FALSE(test, selinux_kunit_secmark_netns_view_valid(
				      &netsec, &init_user_ns));
	netsec.state = child_state;
	KUNIT_EXPECT_FALSE(test, selinux_kunit_secmark_netns_view_valid(
				      &netsec, other_userns));

	KUNIT_EXPECT_TRUE(test,
			  selinux_secmark_provenance_matches(down, parent_sid));
	resolved = 0;
	rc = selinux_label_view_resolve(down->view, child,
					down->subject->label, down->subject->sid,
					&resolved);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, resolved, child_sid);

out:
	if (down)
		kunit_release_action(test, selinux_test_net_provenance_put, down);
	if (up)
		kunit_release_action(test, selinux_test_net_provenance_put, up);
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, refcount_read(&parent_state->count), 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&child_state->count), 1);
}

static void selinux_net_carrier_lifetime_test(struct kunit *test)
{
	struct selinux_net_provenance __rcu *published;
	struct selinux_net_provenance *provenance, *held;
	struct selinux_net_assertion *assertion;
	struct selinux_global_sid_handle *sid_handle;
	struct selinux_label_domain *domain;
	struct selinux_label_ref *label;
	const struct selinux_label_view *view;
	struct lsm_secmark carrier = {};
	struct selinux_state *state;
	u32 sid;
	int label_refs, rc;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);
	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	label = selinux_test_global_label(
		test, state, domain, "u:object_r:kunit_carrier_refs_t:s0", &sid);
	KUNIT_ASSERT_NOT_NULL(test, label);
	view = selinux_identity_view_alloc(&init_user_ns, domain, domain);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, view);
	rc = kunit_add_action_or_reset(test, selinux_test_label_view_put,
				       (void *)view);
	KUNIT_ASSERT_EQ(test, rc, 0);
	selinux_test_state_init(state, 1);
	refcount_set(&state->count, 1);
	state->label_domain = domain;
	label_refs = refcount_read(&label->refs);

	sid_handle = global_sid_handle_get(sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sid_handle);
	assertion = selinux_net_assertion_alloc_handle(
		sid_handle, SECCLASS_PACKET,
		SELINUX_NET_ASSERTION_SOURCE_SECMARK, 0, GFP_KERNEL);
	global_sid_handle_put(sid_handle);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, assertion);
	rc = kunit_add_action_or_reset(test, selinux_test_net_assertion_put,
				       assertion);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_NOT_NULL(test, assertion->sid_handle);
	KUNIT_EXPECT_EQ(test, global_sid_handle_sid(assertion->sid_handle), sid);
	KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), label_refs + 1);

	provenance = selinux_net_provenance_alloc(state, view, assertion,
						  GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, provenance);
	rc = kunit_add_action_or_reset(test, selinux_test_net_provenance_put,
				       provenance);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, refcount_read(&provenance->refs), 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&assertion->refs), 2);
	KUNIT_EXPECT_EQ(test, refcount_read(&view->refs), 2);
	KUNIT_EXPECT_EQ(test, refcount_read(&state->count), 2);

	held = selinux_net_provenance_get(provenance);
	KUNIT_EXPECT_PTR_EQ(test, held, provenance);
	KUNIT_EXPECT_EQ(test, refcount_read(&provenance->refs), 2);
	selinux_net_provenance_put(held);
	KUNIT_EXPECT_EQ(test, refcount_read(&provenance->refs), 1);

	/* Taking transfers the exact authorized reference without cloning it. */
	KUNIT_EXPECT_PTR_EQ(test, selinux_secmark_provenance_take(NULL), NULL);
	carrier.selinux.provenance = selinux_net_provenance_get(provenance);
	KUNIT_EXPECT_EQ(test, refcount_read(&provenance->refs), 2);
	held = selinux_secmark_provenance_take(&carrier);
	KUNIT_EXPECT_PTR_EQ(test, held, provenance);
	KUNIT_EXPECT_PTR_EQ(test, carrier.selinux.provenance, NULL);
	security_secmark_release(&carrier);
	KUNIT_EXPECT_EQ(test, refcount_read(&provenance->refs), 2);
	selinux_net_provenance_put(held);
	KUNIT_EXPECT_EQ(test, refcount_read(&provenance->refs), 1);

	/* Rollback consumes an untaken SELinux slot exactly once. */
	carrier.selinux.provenance = selinux_net_provenance_get(provenance);
	security_secmark_release(&carrier);
	KUNIT_EXPECT_PTR_EQ(test, carrier.selinux.provenance, NULL);
	KUNIT_EXPECT_EQ(test, refcount_read(&provenance->refs), 1);

	RCU_INIT_POINTER(published, provenance);
	held = selinux_net_provenance_get_rcu(&published);
	KUNIT_EXPECT_PTR_EQ(test, held, provenance);
	KUNIT_EXPECT_EQ(test, refcount_read(&provenance->refs), 2);
	selinux_net_provenance_put(held);
	RCU_INIT_POINTER(published, NULL);

	kunit_release_action(test, selinux_test_net_provenance_put, provenance);
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, refcount_read(&assertion->refs), 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&view->refs), 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&state->count), 1);
	kunit_release_action(test, selinux_test_net_assertion_put, assertion);
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), label_refs);
}

static void selinux_net_assertion_sid_lifetime_test(struct kunit *test)
{
	static const char context[] =
		"u:object_r:kunit_net_assertion_sid_lifetime_t:s0";
	struct selinux_global_sid_handle *producer, *stale;
	struct selinux_net_assertion *assertion, *wrong;
	struct selinux_label_domain *domain;
	struct selinux_label_ref *canonical, *label;
	struct selinux_state state;
	u32 sid;
	int rc;

	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	label = selinux_test_global_label(test, &state, domain, context, &sid);
	KUNIT_ASSERT_NOT_NULL(test, label);
	wrong = selinux_net_assertion_alloc_handle(
		NULL, SECCLASS_PACKET, SELINUX_NET_ASSERTION_SOURCE_SOCKET,
		0, GFP_KERNEL);
	KUNIT_ASSERT_TRUE(test, IS_ERR(wrong));
	KUNIT_EXPECT_EQ(test, PTR_ERR(wrong), -EINVAL);

	producer = global_sid_handle_get(sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, producer);
	wrong = selinux_net_assertion_alloc_handle(
		producer, SECCLASS_PACKET, SELINUX_NET_ASSERTION_SOURCE_INVALID,
		0, GFP_KERNEL);
	KUNIT_ASSERT_TRUE(test, IS_ERR(wrong));
	KUNIT_EXPECT_EQ(test, PTR_ERR(wrong), -EINVAL);
	assertion = selinux_net_assertion_alloc_handle(
		producer, SECCLASS_PACKET,
		SELINUX_NET_ASSERTION_SOURCE_SOCKET, 0, GFP_KERNEL);
	global_sid_handle_put(producer);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, assertion);
	rc = kunit_add_action_or_reset(test, selinux_test_net_assertion_put,
				       assertion);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_NOT_NULL(test, assertion->sid_handle);
	KUNIT_EXPECT_EQ(test, global_sid_handle_sid(assertion->sid_handle), sid);
	canonical = global_sid_handle_label_get(assertion->sid_handle);
	KUNIT_ASSERT_NOT_NULL(test, canonical);
	KUNIT_EXPECT_PTR_EQ(test, canonical, label);
	selinux_label_ref_put(canonical);

	/* Fault injection: an incoherent immutable payload cannot be retained. */
	assertion->sid = SECINITSID_KERNEL;
	KUNIT_EXPECT_PTR_EQ(test, selinux_net_assertion_get(assertion), NULL);
	assertion->sid = sid;
	assertion->label = wrong_label;
	KUNIT_EXPECT_PTR_EQ(test, selinux_net_assertion_get(assertion), NULL);
	assertion->label = label;

	KUNIT_ASSERT_EQ(test, selinux_kunit_global_sid_drop_baseline(sid), 0);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(sid));
	kunit_release_action(test, selinux_test_net_assertion_put, assertion);
	rcu_barrier();
	rcu_barrier();
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(sid));
	stale = global_sid_handle_get(sid);
	KUNIT_ASSERT_TRUE(test, IS_ERR(stale));
	KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);
}

KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_path_put, path_put, struct path *);
KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_mnt_free, security_mnt_free,
			    struct vfsmount *);
KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_mnt_topology_free,
			    security_mnt_topology_free,
			    struct security_mnt_topology *);

static void selinux_mnt_topology_transaction_test(struct kunit *test)
{
	struct security_mnt_topology *topology;
	struct vfsmount *clone, *clone_after_apply;
	struct path *root;
	int i, rc;

	root = kunit_kzalloc(test, sizeof(*root), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, root);
	rc = kern_path("/", LOOKUP_FOLLOW, root);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = kunit_add_action_or_reset(test, selinux_test_path_put, root);
	KUNIT_ASSERT_EQ(test, rc, 0);

	clone = kunit_kzalloc(test, sizeof(*clone), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, clone);
	rc = security_mnt_alloc(clone, root->mnt, NULL);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = kunit_add_action_or_reset(test, selinux_test_mnt_free, clone);
	KUNIT_ASSERT_EQ(test, rc, 0);
	topology = security_mnt_topology_alloc();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, topology);
	rc = kunit_add_action_or_reset(test, selinux_test_mnt_topology_free,
				       topology);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Commit without a matching preflight entry must fail closed. */
	KUNIT_EXPECT_EQ(test,
			security_mnt_topology_apply(topology, clone, root->mnt),
			-EACCES);
	/* Re-adding an identical pair must hit the memoized derivation. */
	rc = security_mnt_topology_add(topology, clone, root->mnt);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = security_mnt_topology_add(topology, clone, root->mnt);
	KUNIT_ASSERT_EQ(test, rc, 0);
	/* Apply is a refcount-only commit and remains infallible after preflight. */
	for (i = 0; i < 16; i++) {
		rc = security_mnt_topology_apply(topology, clone, root->mnt);
		KUNIT_ASSERT_EQ(test, rc, 0);
	}

	/* A clone made after commit retains the committed view for later moves. */
	clone_after_apply = kunit_kzalloc(test, sizeof(*clone_after_apply), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, clone_after_apply);
	rc = security_mnt_alloc(clone_after_apply, clone, NULL);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = kunit_add_action_or_reset(test, selinux_test_mnt_free,
				       clone_after_apply);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = security_mnt_topology_add(topology, clone_after_apply, root->mnt);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test,
			security_mnt_topology_apply(topology, clone_after_apply,
						    root->mnt), 0);
}

static void selinux_global_initial_sid_exactness_test(struct kunit *test)
{
	struct selinux_label_ref *kernel, *init, *gap;
	const u32 unset_sid = SECINITSID_UNLABELED + 1;
	int rc;

	kernel = global_sid_to_label_ref(SECINITSID_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, kernel);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put, kernel);
	KUNIT_ASSERT_EQ(test, rc, 0);
	init = global_sid_to_label_ref(SECINITSID_INIT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, init);
	rc = kunit_add_action_or_reset(test, selinux_test_label_ref_put, init);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Early boot deliberately gives INIT and KERNEL one canonical context. */
	KUNIT_EXPECT_PTR_EQ(test, init, kernel);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_global_sid_entry_sid(SECINITSID_KERNEL),
			(u32)SECINITSID_KERNEL);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_global_sid_entry_sid(SECINITSID_INIT),
			(u32)SECINITSID_INIT);

	/* An unset initial SID must not fall back to the unlabeled entry. */
	gap = global_sid_to_label_ref(unset_sid);
	KUNIT_EXPECT_TRUE(test, IS_ERR(gap));
	if (IS_ERR(gap))
		KUNIT_EXPECT_EQ(test, PTR_ERR(gap), -EINVAL);
}

static void selinux_test_inode_security_init(
	struct inode_security_struct *isec)
{
	memset(isec, 0, sizeof(*isec));
	spin_lock_init(&isec->lock);
	INIT_LIST_HEAD(&isec->list);
	isec->sclass = SECCLASS_FILE;
	isec->initialized = LABEL_INVALID;
}

static void selinux_test_inode_security_release(
	struct inode_security_struct *isec)
{
	struct selinux_global_sid_handle *sid_handle, *task_handle;
	struct selinux_label_ref *label;

	spin_lock(&isec->lock);
	sid_handle = isec->sid_handle;
	task_handle = isec->task_sid_handle;
	label = rcu_dereference_protected(
		isec->label_ref, lockdep_is_held(&isec->lock));
	isec->sid_handle = NULL;
	isec->task_sid_handle = NULL;
	isec->sid = SECSID_NULL;
	isec->task_sid = SECSID_NULL;
	RCU_INIT_POINTER(isec->label_ref, NULL);
	RCU_INIT_POINTER(isec->pathless, NULL);
	spin_unlock(&isec->lock);

	global_sid_handle_put(task_handle);
	global_sid_handle_put(sid_handle);
	selinux_label_ref_put(label);
}

static struct selinux_global_sid_handle *
selinux_test_inode_handle(struct kunit *test, struct selinux_state *state,
			  const char *context, u32 *sid)
{
	struct selinux_global_sid_handle *handle;

	handle = selinux_kunit_global_context_to_handle(state, context, sid);
	if (IS_ERR(handle))
		KUNIT_FAIL(test, "inode SID allocation failed for %s: %ld",
			   context, PTR_ERR(handle));
	return handle;
}

static void selinux_inode_sid_handle_lifetime_test(struct kunit *test)
{
	static const char old_context[] =
		"u:object_r:kunit_inode_old_owner_t:s0";
	static const char new_context[] =
		"u:object_r:kunit_inode_new_owner_t:s0";
	static const char task_context[] =
		"u:r:kunit_inode_pending_task_t:s0";
	struct selinux_global_sid_handle *old_handle = NULL, *new_handle = NULL;
	struct selinux_global_sid_handle *task_handle = NULL, *stale;
	struct selinux_global_sid_handle *old_producer;
	struct selinux_label_domain *domain;
	struct inode_security_struct isec;
	struct selinux_state state;
	u32 old_sid = 0, new_sid = 0, task_sid = 0;
	u16 sclass = SECCLASS_FILE;
	int rc;

	domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, domain);
	selinux_test_state_init(&state, 1);
	state.label_domain = domain;
	selinux_test_inode_security_init(&isec);

	old_handle = selinux_test_inode_handle(
		test, &state, old_context, &old_sid);
	if (IS_ERR(old_handle))
		goto out;
	new_handle = selinux_test_inode_handle(
		test, &state, new_context, &new_sid);
	if (IS_ERR(new_handle))
		goto out;
	task_handle = selinux_test_inode_handle(
		test, &state, task_context, &task_sid);
	if (IS_ERR(task_handle))
		goto out;

	/* The fixture transfers the producer's sole reference to task_sid. */
	isec.task_sid_handle = task_handle;
	isec.task_sid = task_sid;
	task_handle = NULL;
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(task_sid), 0);

	old_producer = old_handle;
	rc = selinux_inode_security_take_sid_handle(
		&isec, old_handle, &sclass, SELINUX_LABEL_SOURCE_FILESYSTEM,
		LABEL_INVALID);
	old_handle = NULL;
	KUNIT_EXPECT_EQ(test, rc, 0);
	if (rc)
		goto out;
	KUNIT_EXPECT_PTR_EQ(test, isec.sid_handle, old_producer);
	KUNIT_EXPECT_EQ(test, isec.sid, old_sid);
	KUNIT_EXPECT_EQ(test, global_sid_handle_sid(isec.sid_handle), old_sid);
	KUNIT_EXPECT_NOT_NULL(test, rcu_access_pointer(isec.label_ref));
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(old_sid), 0);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(old_sid));

	KUNIT_EXPECT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(new_sid), 0);
	rc = selinux_inode_security_take_sid_handle(
		&isec, new_handle, &sclass, SELINUX_LABEL_SOURCE_XATTR,
		LABEL_INITIALIZED);
	new_handle = NULL;
	KUNIT_EXPECT_EQ(test, rc, 0);
	if (rc)
		goto out;
	KUNIT_EXPECT_EQ(test, isec.sid, new_sid);
	KUNIT_EXPECT_EQ(test, global_sid_handle_sid(isec.sid_handle), new_sid);
	KUNIT_EXPECT_PTR_EQ(test, isec.task_sid_handle, NULL);
	KUNIT_EXPECT_EQ(test, isec.task_sid, (u32)SECSID_NULL);

	/* Payload detachment is synchronous; no system-wide RCU flush is needed. */
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(old_sid));
	stale = global_sid_handle_get(old_sid);
	KUNIT_EXPECT_TRUE(test, IS_ERR(stale));
	if (!IS_ERR(stale)) {
		global_sid_handle_put(stale);
		goto out;
	}
	KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(task_sid));
	stale = global_sid_handle_get(task_sid);
	KUNIT_EXPECT_TRUE(test, IS_ERR(stale));
	if (!IS_ERR(stale)) {
		global_sid_handle_put(stale);
		goto out;
	}
	KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(new_sid));

out:
	if (!IS_ERR_OR_NULL(task_handle))
		global_sid_handle_put(task_handle);
	if (!IS_ERR_OR_NULL(new_handle))
		global_sid_handle_put(new_handle);
	if (!IS_ERR_OR_NULL(old_handle))
		global_sid_handle_put(old_handle);
	selinux_test_inode_security_release(&isec);
	if (new_sid && selinux_kunit_global_sid_live(new_sid))
		selinux_kunit_global_sid_drop_baseline(new_sid);
	if (old_sid && selinux_kunit_global_sid_live(old_sid))
		selinux_kunit_global_sid_drop_baseline(old_sid);
	if (task_sid && selinux_kunit_global_sid_live(task_sid))
		selinux_kunit_global_sid_drop_baseline(task_sid);
	rcu_barrier();
	selinux_label_domain_put(domain);
}

static void selinux_inode_sid_handle_fail_closed_test(struct kunit *test)
{
	static const char base_context[] =
		"u:object_r:kunit_inode_stable_tuple_t:s0";
	static const char mismatch_context[] =
		"u:object_r:kunit_inode_mismatch_t:s0";
	static const char dead_context[] =
		"u:object_r:kunit_inode_dead_handle_t:s0";
	struct selinux_global_sid_handle *base = NULL, *mismatch = NULL;
	struct selinux_global_sid_handle *dead = NULL, *stale;
	struct selinux_global_sid_handle *stable_handle;
	struct selinux_label_ref *stable_label;
	struct selinux_label_domain *domain;
	struct inode_security_struct isec;
	struct selinux_state state;
	u32 base_sid = 0, mismatch_sid = 0, dead_sid = 0;
	u16 sclass = SECCLASS_FILE;
	int rc;

	domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, domain);
	selinux_test_state_init(&state, 1);
	state.label_domain = domain;
	selinux_test_inode_security_init(&isec);

	base = selinux_test_inode_handle(test, &state, base_context, &base_sid);
	if (IS_ERR(base))
		goto out;
	rc = selinux_inode_security_take_sid_handle(
		&isec, base, &sclass, SELINUX_LABEL_SOURCE_XATTR,
		LABEL_INITIALIZED);
	base = NULL;
	KUNIT_EXPECT_EQ(test, rc, 0);
	if (rc)
		goto out;
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(base_sid), 0);
	stable_handle = isec.sid_handle;
	stable_label = rcu_access_pointer(isec.label_ref);

	mismatch = selinux_test_inode_handle(
		test, &state, mismatch_context, &mismatch_sid);
	if (IS_ERR(mismatch))
		goto out;
	RCU_INIT_POINTER(isec.pathless,
			 (struct selinux_pathless_projection *)&isec);
	rc = selinux_inode_security_take_sid_handle(
		&isec, mismatch, &sclass, SELINUX_LABEL_SOURCE_XATTR,
		LABEL_INITIALIZED);
	mismatch = NULL;
	KUNIT_EXPECT_EQ(test, rc, -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, isec.sid, base_sid);
	KUNIT_EXPECT_PTR_EQ(test, isec.sid_handle, stable_handle);
	KUNIT_EXPECT_EQ(test, global_sid_handle_sid(isec.sid_handle), base_sid);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(isec.label_ref), stable_label);
	KUNIT_EXPECT_EQ(test, isec.sclass, sclass);
	KUNIT_EXPECT_EQ(test, isec.label_source,
			(u8)SELINUX_LABEL_SOURCE_XATTR);
	KUNIT_EXPECT_EQ(test, isec.initialized,
			(u8)LABEL_INITIALIZED);
	RCU_INIT_POINTER(isec.pathless, NULL);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(mismatch_sid), 0);
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(mismatch_sid));

	dead = selinux_test_inode_handle(test, &state, dead_context, &dead_sid);
	if (IS_ERR(dead))
		goto out;
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(dead_sid), 0);
	global_sid_handle_put(dead);
	dead = NULL;
	stale = global_sid_handle_get(dead_sid);
	KUNIT_EXPECT_TRUE(test, IS_ERR(stale));
	if (!IS_ERR(stale)) {
		global_sid_handle_put(stale);
		goto out;
	}
	KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);
	rc = selinux_inode_security_take_sid_handle(
		&isec, stale, &sclass, SELINUX_LABEL_SOURCE_XATTR,
		LABEL_INITIALIZED);
	KUNIT_EXPECT_EQ(test, rc, -ESTALE);
	KUNIT_EXPECT_EQ(test, isec.sid, base_sid);
	KUNIT_EXPECT_PTR_EQ(test, isec.sid_handle, stable_handle);
	KUNIT_EXPECT_EQ(test, global_sid_handle_sid(isec.sid_handle), base_sid);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(isec.label_ref), stable_label);
	KUNIT_EXPECT_EQ(test, isec.sclass, sclass);
	KUNIT_EXPECT_EQ(test, isec.label_source,
			(u8)SELINUX_LABEL_SOURCE_XATTR);
	KUNIT_EXPECT_EQ(test, isec.initialized, (u8)LABEL_INITIALIZED);

out:
	RCU_INIT_POINTER(isec.pathless, NULL);
	if (!IS_ERR_OR_NULL(dead))
		global_sid_handle_put(dead);
	if (!IS_ERR_OR_NULL(mismatch))
		global_sid_handle_put(mismatch);
	if (!IS_ERR_OR_NULL(base))
		global_sid_handle_put(base);
	selinux_test_inode_security_release(&isec);
	if (base_sid && selinux_kunit_global_sid_live(base_sid))
		selinux_kunit_global_sid_drop_baseline(base_sid);
	if (mismatch_sid && selinux_kunit_global_sid_live(mismatch_sid))
		selinux_kunit_global_sid_drop_baseline(mismatch_sid);
	if (dead_sid && selinux_kunit_global_sid_live(dead_sid))
		selinux_kunit_global_sid_drop_baseline(dead_sid);
	rcu_barrier();
	selinux_label_domain_put(domain);
}

static void selinux_global_sid_reclaim_accounting_test(struct kunit *test)
{
	static const char context[] = "u:r:global_sid_reclaim_kunit_t:s0";
	struct selinux_global_sid_handle *first, *second;
	struct selinux_label_domain *domain;
	struct selinux_state state;
	u64 objects_before, bytes_before;
	u64 global_objects_before, global_bytes_before;
	u32 first_sid, second_sid;

	domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, domain);
	selinux_test_state_init(&state, 1);
	state.label_domain = domain;
	/*
	 * Prior cases share init_user_ns accounting and may have completed their
	 * final puts while the corresponding payload RCU callbacks are pending.
	 * Drain those callbacks before taking the exact accounting baseline.
	 */
	selinux_label_domain_kunit_drain();
	objects_before = selinux_kunit_resource_objects(
		domain->resources, SELINUX_RESOURCE_GLOBAL_SID);
	bytes_before = selinux_kunit_resource_bytes(
		domain->resources, SELINUX_RESOURCE_GLOBAL_SID);
	global_objects_before = selinux_kunit_resource_global_objects();
	global_bytes_before = selinux_kunit_resource_global_bytes();

	first = selinux_kunit_global_context_to_handle(&state, context,
						      &first_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(domain->resources,
						SELINUX_RESOURCE_GLOBAL_SID),
		objects_before + 1);
	KUNIT_EXPECT_GT(test,
		selinux_kunit_resource_bytes(domain->resources,
					      SELINUX_RESOURCE_GLOBAL_SID),
		bytes_before);
	KUNIT_ASSERT_EQ(test, selinux_kunit_global_sid_drop_baseline(first_sid),
			0);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(first_sid));
	global_sid_handle_put(first);
	rcu_barrier();
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(first_sid));
	{
		struct selinux_global_sid_handle *stale_handle;
		struct selinux_label_ref *stale =
			global_sid_to_label_ref(first_sid);

		KUNIT_EXPECT_TRUE(test, IS_ERR(stale));
		if (IS_ERR(stale))
			KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);
		stale_handle = global_sid_handle_get(first_sid);
		KUNIT_EXPECT_TRUE(test, IS_ERR(stale_handle));
		if (IS_ERR(stale_handle))
			KUNIT_EXPECT_EQ(test, PTR_ERR(stale_handle), -ESTALE);
		stale_handle = global_sid_handle_get(U32_MAX);
		KUNIT_EXPECT_TRUE(test, IS_ERR(stale_handle));
		if (IS_ERR(stale_handle))
			KUNIT_EXPECT_EQ(test, PTR_ERR(stale_handle), -EINVAL);
	}
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(domain->resources,
						SELINUX_RESOURCE_GLOBAL_SID),
		objects_before);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_bytes(domain->resources,
					      SELINUX_RESOURCE_GLOBAL_SID),
		bytes_before);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_objects(),
			global_objects_before + 1);
	KUNIT_EXPECT_GT(test, selinux_kunit_resource_global_bytes(),
			global_bytes_before);

	/* A dead context gets a fresh numeric identity; tombstones never revive. */
	second = selinux_kunit_global_context_to_handle(&state, context,
						       &second_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, second);
	KUNIT_EXPECT_NE(test, second_sid, first_sid);
	KUNIT_ASSERT_EQ(test, selinux_kunit_global_sid_drop_baseline(second_sid),
			0);
	global_sid_handle_put(second);
	rcu_barrier();
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(second_sid));
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_resource_objects(domain->resources,
						SELINUX_RESOURCE_GLOBAL_SID),
		objects_before);
	KUNIT_EXPECT_EQ(test, selinux_kunit_resource_global_objects(),
			global_objects_before + 2);
	selinux_label_domain_put(domain);
}

static void selinux_global_sid_atomic_handle_test(struct kunit *test)
{
	static const char context[] = "u:r:global_sid_atomic_handle_kunit_t:s0";
	struct selinux_global_sid_handle *first, *repeat, *recreated, *stale;
	struct selinux_label_ref *canonical, *label;
	struct selinux_label_domain *domain;
	struct selinux_state state;
	u32 first_sid, repeat_sid, recreated_sid;

	/* The RCU-backed map producer exposes no caller-selected allocation mode. */
	stale = map_ss_sid_to_global_handle(NULL, SECINITSID_KERNEL,
					    &repeat_sid);
	KUNIT_ASSERT_TRUE(test, IS_ERR(stale));
	KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -EINVAL);

	domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, domain);
	selinux_test_state_init(&state, 1);
	state.label_domain = domain;

	/* The returned references are established before first publication. */
	first = selinux_kunit_global_context_to_handle(&state, context,
						     &first_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first);
	repeat = selinux_kunit_global_context_to_handle(&state, context,
						      &repeat_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, repeat);
	KUNIT_EXPECT_PTR_EQ(test, repeat, first);
	KUNIT_EXPECT_EQ(test, repeat_sid, first_sid);
	label = global_sid_handle_label_get(first);
	KUNIT_ASSERT_NOT_NULL(test, label);
	canonical = global_sid_to_label_ref(first_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, canonical);
	KUNIT_EXPECT_PTR_EQ(test, label, canonical);
	selinux_label_ref_put(canonical);
	selinux_label_ref_put(label);

	/* No numeric lookup is needed between creation and baseline removal. */
	KUNIT_ASSERT_EQ(test, selinux_kunit_global_sid_drop_baseline(first_sid),
			0);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(first_sid));
	global_sid_handle_put(first);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(first_sid));
	global_sid_handle_put(repeat);
	rcu_barrier();
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(first_sid));
	stale = global_sid_handle_get(first_sid);
	KUNIT_ASSERT_TRUE(test, IS_ERR(stale));
	KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);

	/* A dead payload cannot be rebound, even for the same canonical context. */
	recreated = selinux_kunit_global_context_to_handle(
		&state, context, &recreated_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recreated);
	KUNIT_EXPECT_NE(test, recreated_sid, first_sid);
	KUNIT_ASSERT_EQ(test,
			selinux_kunit_global_sid_drop_baseline(recreated_sid), 0);
	global_sid_handle_put(recreated);
	rcu_barrier();
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(recreated_sid));
	selinux_label_domain_put(domain);
}

static void selinux_global_sid_initial_immortal_test(struct kunit *test)
{
	struct selinux_global_sid_handle *handle;
	u32 sid = SECINITSID_KERNEL;

	handle = global_sid_handle_get(sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, handle);
	KUNIT_EXPECT_EQ(test, global_sid_handle_sid(handle), sid);
	KUNIT_EXPECT_EQ(test, selinux_kunit_global_sid_drop_baseline(sid),
			-EPERM);
	global_sid_handle_put(handle);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(sid));
}

static void selinux_global_sid_initial_alias_test(struct kunit *test)
{
	static const char context[] = "u:r:global_sid_alias_kunit_t:s0";
	struct selinux_global_sid_handle *kernel, *init, *repeat;
	struct selinux_label_domain *domain;
	struct selinux_state state;
	u32 kernel_sid, init_sid, repeat_sid;

	domain = selinux_label_domain_alloc(&init_user_ns, NULL, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, domain);
	selinux_test_state_init(&state, 1);
	state.label_domain = domain;
	kernel = selinux_kunit_global_context_to_handle_local(
		&state, context, SECINITSID_KERNEL, &kernel_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, kernel);
	init = selinux_kunit_global_context_to_handle_local(
		&state, context, SECINITSID_INIT, &init_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, init);
	repeat = selinux_kunit_global_context_to_handle_local(
		&state, context, SECINITSID_KERNEL, &repeat_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, repeat);

	KUNIT_EXPECT_NE(test, kernel_sid, init_sid);
	KUNIT_EXPECT_EQ(test, repeat_sid, kernel_sid);
	KUNIT_ASSERT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(kernel_sid), 0);
	KUNIT_ASSERT_EQ(test, selinux_kunit_global_sid_drop_baseline(init_sid),
			0);
	global_sid_handle_put(repeat);
	global_sid_handle_put(kernel);
	global_sid_handle_put(init);
	rcu_barrier();
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(kernel_sid));
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(init_sid));
	selinux_label_domain_put(domain);
}

static void selinux_net_peersid_null_sentinel_test(struct kunit *test)
{
	struct selinux_global_sid_handle *handle;
	struct selinux_state state;
	u32 peer_sid = SECSID_WILD;

	selinux_test_state_init(&state, 1);
	smp_store_release(&state.initialized, true);
	handle = security_net_peersid_resolve_handle(
		&state, SECSID_NULL, 0, SECSID_NULL, &peer_sid);
	KUNIT_EXPECT_FALSE(test, IS_ERR(handle));
	KUNIT_EXPECT_EQ(test, peer_sid, (u32)SECSID_NULL);
	global_sid_handle_put(handle);
}

static void selinux_prop_ref_scalar_metadata_lifetime_test(struct kunit *test)
{
	static const char context[] = "u:r:prop_ref_lifetime_kunit_t:s0";
	struct selinux_global_sid_handle *producer, *stale;
	struct selinux_label_domain *domain;
	struct lsm_prop_ref *ref = NULL;
	struct selinux_state state;
	const struct lsm_prop *prop;
	u32 sid, source_sid = 0;
	int rc;

	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	selinux_test_state_init(&state, 1);
	state.label_domain = domain;
	producer = selinux_kunit_global_context_to_handle(&state, context, &sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, producer);

	rc = security_secid_to_lsmprop_ref(sid, LSM_ID_SELINUX, GFP_KERNEL,
					   &ref);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_NOT_NULL(test, ref);
	prop = security_lsm_prop_ref_prop(ref);
	KUNIT_ASSERT_NOT_NULL(test, prop);
	KUNIT_EXPECT_EQ(test, security_lsm_prop_ref_provider_count(ref), 1U);
	KUNIT_EXPECT_EQ(test, security_lsm_prop_ref_lsmid(ref),
			LSM_ID_SELINUX);
	KUNIT_EXPECT_EQ(test, prop->selinux.secid, sid);
	KUNIT_EXPECT_TRUE(test,
		security_lsm_prop_ref_source_secid(ref, &source_sid));
	KUNIT_EXPECT_EQ(test, source_sid, sid);

	/* The carrier, not the producer or baseline, now owns the payload. */
	KUNIT_ASSERT_EQ(test, selinux_kunit_global_sid_drop_baseline(sid), 0);
	global_sid_handle_put(producer);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(sid));
	security_lsm_prop_ref_put(ref);
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(sid));
	stale = global_sid_handle_get(sid);
	KUNIT_ASSERT_TRUE(test, IS_ERR(stale));
	KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);
}

static void selinux_prop_ref_secctx_render_test(struct kunit *test)
{
	struct lsm_context source = {}, rendered = {};
	struct lsm_prop_ref *ref = NULL;
	struct lsm_prop prop = {};
	u32 sid = selinux_cred(current_cred())->sid;
	u32 source_sid = 0;
	int rc;

	prop.selinux.secid = sid;
	rc = security_lsmprop_to_secctx(&prop, &source, LSM_ID_SELINUX);
	KUNIT_ASSERT_GE(test, rc, 0);
	KUNIT_ASSERT_NOT_NULL(test, source.context);
	KUNIT_EXPECT_EQ(test, source.id, LSM_ID_SELINUX);

	rc = security_secctx_to_lsmprop_ref(source.context, source.len,
					    LSM_ID_SELINUX, GFP_KERNEL,
					    &ref);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_NOT_NULL(test, ref);
	KUNIT_EXPECT_EQ(test, security_lsm_prop_ref_provider_count(ref), 1U);
	KUNIT_EXPECT_EQ(test, security_lsm_prop_ref_lsmid(ref),
			LSM_ID_SELINUX);
	KUNIT_EXPECT_TRUE(test,
		security_lsm_prop_ref_source_secid(ref, &source_sid));
	KUNIT_EXPECT_EQ(test, source_sid,
			security_lsm_prop_ref_prop(ref)->selinux.secid);
	KUNIT_EXPECT_EQ(test, source_sid, sid);

	rc = security_lsm_prop_ref_to_secctx(ref, current_cred(),
					     LSM_ID_UNDEF, &rendered);
	KUNIT_ASSERT_GE(test, rc, 0);
	KUNIT_EXPECT_EQ(test, rendered.id, LSM_ID_SELINUX);
	KUNIT_EXPECT_EQ(test, rendered.len, source.len);
	KUNIT_EXPECT_MEMEQ(test, rendered.context, source.context, source.len);

	security_release_secctx(&rendered);
	security_lsm_prop_ref_put(ref);
	security_release_secctx(&source);
}

static void selinux_prop_ref_cross_domain_render_test(struct kunit *test)
{
	static const char context[] = "u:r:prop_ref_cross_domain_kunit_t:s0";
	struct selinux_global_sid_handle *producer;
	struct selinux_label_domain *domain;
	struct lsm_context rendered = {};
	struct lsm_prop_ref *ref = NULL;
	struct selinux_state state;
	u32 sid;
	int rc;

	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	selinux_test_state_init(&state, 1);
	state.label_domain = domain;
	producer = selinux_kunit_global_context_to_handle(&state, context, &sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, producer);
	KUNIT_ASSERT_EQ(test,
		security_secid_to_lsmprop_ref(sid, LSM_ID_SELINUX, GFP_KERNEL,
						 &ref),
		0);

	/* current_cred() observes the initial domain and no view was supplied. */
	rc = security_lsm_prop_ref_to_secctx(ref, current_cred(),
					     LSM_ID_SELINUX, &rendered);
	KUNIT_EXPECT_EQ(test, rc, -EOPNOTSUPP);
	KUNIT_EXPECT_PTR_EQ(test, rendered.context, NULL);
	KUNIT_EXPECT_EQ(test, rendered.len, (u32)0);
	security_lsm_prop_ref_put(ref);
	global_sid_handle_put(producer);
	KUNIT_ASSERT_EQ(test, selinux_kunit_global_sid_drop_baseline(sid), 0);
}

static void selinux_prop_ref_replace_tombstone_test(struct kunit *test)
{
	static const char first_context[] = "u:r:prop_ref_old_kunit_t:s0";
	static const char second_context[] = "u:r:prop_ref_new_kunit_t:s0";
	static const char dead_context[] = "u:r:prop_ref_stale_kunit_t:s0";
	struct selinux_global_sid_handle *first_producer, *second_producer;
	struct selinux_global_sid_handle *dead_producer;
	struct selinux_label_domain *domain;
	struct lsm_prop_ref *published = NULL, *candidate = NULL, *old;
	struct selinux_state state;
	u32 first_sid, second_sid, dead_sid;
	int rc;

	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	selinux_test_state_init(&state, 1);
	state.label_domain = domain;
	first_producer = selinux_kunit_global_context_to_handle(
		&state, first_context, &first_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first_producer);
	second_producer = selinux_kunit_global_context_to_handle(
		&state, second_context, &second_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, second_producer);
	dead_producer = selinux_kunit_global_context_to_handle(
		&state, dead_context, &dead_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, dead_producer);
	KUNIT_ASSERT_EQ(test,
		security_secid_to_lsmprop_ref(first_sid, LSM_ID_SELINUX,
						 GFP_KERNEL, &published),
		0);
	KUNIT_ASSERT_EQ(test,
		security_secid_to_lsmprop_ref(second_sid, LSM_ID_SELINUX,
						 GFP_KERNEL, &candidate),
		0);
	KUNIT_ASSERT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(first_sid), 0);
	KUNIT_ASSERT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(second_sid), 0);
	KUNIT_ASSERT_EQ(test,
		selinux_kunit_global_sid_drop_baseline(dead_sid), 0);
	global_sid_handle_put(first_producer);
	global_sid_handle_put(second_producer);
	global_sid_handle_put(dead_producer);
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(dead_sid));

	old = published;
	published = candidate;
	candidate = NULL;
	security_lsm_prop_ref_put(old);
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(first_sid));
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(second_sid));
	KUNIT_EXPECT_EQ(test,
		security_lsm_prop_ref_prop(published)->selinux.secid, second_sid);

	/* A stale candidate fails before publication and leaves the owner exact. */
	old = published;
	rc = security_secid_to_lsmprop_ref(dead_sid, LSM_ID_SELINUX,
					   GFP_KERNEL, &candidate);
	KUNIT_EXPECT_EQ(test, rc, -ESTALE);
	KUNIT_EXPECT_PTR_EQ(test, candidate, NULL);
	KUNIT_EXPECT_PTR_EQ(test, published, old);
	KUNIT_EXPECT_EQ(test,
		security_lsm_prop_ref_prop(published)->selinux.secid, second_sid);

	security_lsm_prop_ref_put(published);
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(second_sid));
}

#if IS_BUILTIN(CONFIG_CACHEFILES)
static void selinux_prop_ref_cachefiles_exact_identity_test(struct kunit *test)
{
	struct lsm_context source = {};
	struct lsm_prop_ref *ref = NULL;
	struct lsm_prop prop = {}, applied = {};
	u32 source_sid = 0;
	u32 sid = selinux_cred(current_cred())->sid;
	u32 diagnostic_sid;
	int rc;

	prop.selinux.secid = sid;
	rc = security_lsmprop_to_secctx(&prop, &source, LSM_ID_SELINUX);
	KUNIT_ASSERT_GE(test, rc, 0);
	KUNIT_ASSERT_NOT_NULL(test, source.context);
	KUNIT_ASSERT_EQ(test,
		security_secctx_to_lsmprop_ref(source.context, source.len,
						   LSM_ID_SELINUX, GFP_KERNEL,
						   &ref),
		0);
	KUNIT_ASSERT_TRUE(test,
		security_lsm_prop_ref_source_secid(ref, &source_sid));
	diagnostic_sid = source_sid == U32_MAX ? source_sid - 1 : source_sid + 1;
	KUNIT_ASSERT_NE(test, diagnostic_sid, source_sid);

	rc = cachefiles_kunit_apply_secctx_ref(ref, diagnostic_sid, &applied);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, applied.selinux.secid, source_sid);
	KUNIT_EXPECT_NE(test, applied.selinux.secid, diagnostic_sid);
	security_lsm_prop_ref_put(ref);
	security_release_secctx(&source);
}
#endif

#ifdef CONFIG_NETLABEL
static void selinux_test_netlbl_secattr_destroy(void *data)
{
	netlbl_secattr_destroy(data);
}

static struct netlbl_lsm_secattr *
selinux_test_netlbl_cache_alloc(struct kunit *test, u32 sid)
{
	struct netlbl_lsm_secattr *secattr;
	int rc;

	secattr = kunit_kzalloc(test, sizeof(*secattr), GFP_KERNEL);
	if (!secattr)
		return NULL;
	netlbl_secattr_init(secattr);
	secattr->flags = NETLBL_SECATTR_SECID;
	secattr->type = NETLBL_NLTYPE_UNLABELED;
	secattr->attr.secid = sid;
	rc = selinux_kunit_netlbl_cache_add(secattr, sid);
	if (rc) {
		KUNIT_FAIL(test, "NetLabel cache allocation failed: %d", rc);
		return NULL;
	}
	rc = kunit_add_action_or_reset(test,
				       selinux_test_netlbl_secattr_destroy,
				       secattr);
	if (rc) {
		KUNIT_FAIL(test, "NetLabel cache cleanup registration failed: %d",
			   rc);
		return NULL;
	}
	return secattr;
}

static void selinux_prop_ref_netlbl_exact_handle_test(struct kunit *test)
{
	static const char context[] = "u:r:prop_ref_netlbl_kunit_t:s0";
	struct selinux_global_sid_handle *producer, *consumer;
	struct selinux_global_sid_handle *producer_identity;
	struct selinux_label_domain *domain;
	struct netlbl_lsm_secattr secattr;
	struct lsm_prop_ref *ref = NULL;
	struct selinux_state state;
	u32 sid, resolved_sid, mismatch_sid;

	domain = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, domain);
	selinux_test_state_init(&state, 1);
	state.label_domain = domain;
	/* Match the release publication used when a policy makes state live. */
	smp_store_release(&state.initialized, true);
	producer = selinux_kunit_global_context_to_handle(&state, context, &sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, producer);
	producer_identity = producer;
	KUNIT_ASSERT_EQ(test,
		security_secid_to_lsmprop_ref(sid, LSM_ID_SELINUX, GFP_KERNEL,
						 &ref),
		0);

	netlbl_secattr_init(&secattr);
	secattr.flags = NETLBL_SECATTR_SECID | NETLBL_SECATTR_PROP_REF;
	secattr.type = NETLBL_NLTYPE_UNLABELED;
	secattr.attr.secid = sid;
	secattr.prop_ref = security_lsm_prop_ref_get(ref);
	KUNIT_ASSERT_NOT_NULL(test, secattr.prop_ref);
	KUNIT_ASSERT_EQ(test, selinux_kunit_global_sid_drop_baseline(sid), 0);
	global_sid_handle_put(producer);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(sid));

	resolved_sid = SECSID_WILD;
	consumer = security_netlbl_secattr_to_sid_view_handle(
		&state, NULL, &secattr, &resolved_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, consumer);
	KUNIT_EXPECT_PTR_EQ(test, consumer, producer_identity);
	KUNIT_EXPECT_EQ(test, resolved_sid, sid);
	KUNIT_EXPECT_EQ(test, global_sid_handle_sid(consumer), sid);
	global_sid_handle_put(consumer);
	KUNIT_ASSERT_TRUE(test, secattr.flags & NETLBL_SECATTR_CACHE);
	KUNIT_ASSERT_NOT_NULL(test, secattr.cache);

	/* A cached lookup must still reject a mirror that contradicts the carrier. */
	mismatch_sid = sid == U32_MAX ? sid - 1 : sid + 1;
	secattr.attr.secid = mismatch_sid;
	resolved_sid = SECSID_WILD;
	consumer = security_netlbl_secattr_to_sid_view_handle(
		&state, NULL, &secattr, &resolved_sid);
	KUNIT_ASSERT_TRUE(test, IS_ERR(consumer));
	KUNIT_EXPECT_EQ(test, PTR_ERR(consumer), -ESTALE);
	KUNIT_EXPECT_EQ(test, resolved_sid, (u32)SECSID_WILD);
	KUNIT_EXPECT_PTR_EQ(test, secattr.prop_ref, ref);
	KUNIT_EXPECT_EQ(test, secattr.attr.secid, mismatch_sid);

	/* Destroy consumes exactly the secattr owner; the producer owner remains. */
	netlbl_secattr_destroy(&secattr);
	KUNIT_EXPECT_TRUE(test, selinux_kunit_global_sid_live(sid));
	security_lsm_prop_ref_put(ref);
	KUNIT_EXPECT_FALSE(test, selinux_kunit_global_sid_live(sid));
}

static void selinux_netlbl_canonical_cache_test(struct kunit *test)
{
	static const char context[] = "u:object_r:netlabel_cache_test_t:s0";
	static const enum selinux_kunit_netlbl_cache_corruption corruptions[] = {
		SELINUX_KUNIT_NETLBL_CORRUPT_MAGIC,
		SELINUX_KUNIT_NETLBL_CORRUPT_VERSION,
		SELINUX_KUNIT_NETLBL_CORRUPT_SID,
	};
	struct netlbl_lsm_secattr *secattr;
	struct selinux_label_domain *origin, *other;
	struct selinux_label_ref *label;
	struct selinux_state first, second;
	u32 baseline_refs, global_sid, sid;
	int i;

	origin = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, origin);
	other = selinux_test_domain_alloc(test, NULL);
	KUNIT_ASSERT_NOT_NULL(test, other);
	label = selinux_test_global_label(test, &first, origin, context,
					  &global_sid);
	KUNIT_ASSERT_NOT_NULL(test, label);
	KUNIT_ASSERT_GT(test, global_sid, (u32)SECINITSID_NUM);
	baseline_refs = refcount_read(&label->refs);

	selinux_test_state_init(&first, 1);
	selinux_test_state_init(&second, 2);
	first.label_domain = origin;
	second.label_domain = other;
	/* Match the release publication used when a policy makes state live. */
	smp_store_release(&first.initialized, true);
	/* Publish the independent second state with the same ordering. */
	smp_store_release(&second.initialized, true);

	secattr = selinux_test_netlbl_cache_alloc(test, global_sid);
	KUNIT_ASSERT_NOT_NULL(test, secattr);
	KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), baseline_refs + 1);
	sid = SECSID_WILD;
	KUNIT_EXPECT_EQ(test,
			security_netlbl_secattr_to_sid(&first, secattr, &sid), 0);
	KUNIT_EXPECT_EQ(test, sid, global_sid);
	sid = SECSID_WILD;
	KUNIT_EXPECT_EQ(test,
			security_netlbl_secattr_to_sid(&second, secattr, &sid),
			-EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, sid, (u32)SECSID_WILD);
	kunit_release_action(test, selinux_test_netlbl_secattr_destroy, secattr);
	KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), baseline_refs);

	/* A captured source must outlive the parser-owned secattr/cache ref. */
	{
		struct selinux_global_sid_handle *source_handle;
		struct selinux_netlbl_source source;

		secattr = selinux_test_netlbl_cache_alloc(test, global_sid);
		KUNIT_ASSERT_NOT_NULL(test, secattr);
		selinux_netlbl_source_init(&source);
		source.cache = secattr->cache;
		source.type = secattr->type;
		selinux_netlbl_source_get(&source);
		kunit_release_action(test, selinux_test_netlbl_secattr_destroy,
				     secattr);
		KUNIT_EXPECT_EQ(test, refcount_read(&label->refs),
				baseline_refs + 1);
		sid = SECSID_WILD;
		source_handle = selinux_netlbl_source_sid_handle(
			&first, &source, &sid);
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, source_handle);
		if (!IS_ERR_OR_NULL(source_handle)) {
			KUNIT_EXPECT_EQ(test, sid, global_sid);
			global_sid_handle_put(source_handle);
		}
		selinux_netlbl_source_put(&source);
		KUNIT_EXPECT_PTR_EQ(test, source.cache, NULL);
		KUNIT_EXPECT_EQ(test, source.type, (u32)NETLBL_NLTYPE_NONE);
		KUNIT_EXPECT_EQ(test, refcount_read(&label->refs), baseline_refs);
	}

	for (i = 0; i < ARRAY_SIZE(corruptions); i++) {
		secattr = selinux_test_netlbl_cache_alloc(test, global_sid);
		KUNIT_ASSERT_NOT_NULL(test, secattr);
		KUNIT_ASSERT_EQ(test,
				selinux_kunit_netlbl_cache_corrupt(secattr,
								   corruptions[i]),
				0);
		sid = SECSID_WILD;
		KUNIT_EXPECT_EQ(test,
				security_netlbl_secattr_to_sid(&first, secattr,
							       &sid),
				-ESTALE);
		KUNIT_EXPECT_EQ(test, sid, (u32)SECSID_WILD);
		kunit_release_action(test, selinux_test_netlbl_secattr_destroy,
				     secattr);
		KUNIT_EXPECT_EQ(test, refcount_read(&label->refs),
				baseline_refs);
	}

	secattr = kunit_kzalloc(test, sizeof(*secattr), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, secattr);
	netlbl_secattr_init(secattr);
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_netlbl_cache_add(secattr, SECSID_NULL),
			-EINVAL);
	KUNIT_EXPECT_FALSE(test, secattr->flags & NETLBL_SECATTR_CACHE);
	KUNIT_EXPECT_PTR_EQ(test, secattr->cache, NULL);
	sid = SECSID_WILD;
	KUNIT_EXPECT_EQ(test,
			selinux_kunit_netlbl_ss_sid_to_global(&first, secattr,
							      SECSID_NULL, &sid),
			0);
	KUNIT_EXPECT_EQ(test, sid, (u32)SECSID_NULL);
	KUNIT_EXPECT_FALSE(test, secattr->flags & NETLBL_SECATTR_CACHE);
	secattr->attr.secid = SECSID_NULL;
	secattr->flags = NETLBL_SECATTR_SECID;
	sid = SECSID_WILD;
	KUNIT_EXPECT_EQ(test,
			security_netlbl_secattr_to_sid(&first, secattr, &sid),
			-ESTALE);
	KUNIT_EXPECT_EQ(test, sid, (u32)SECSID_WILD);

	/* A local SECID may cross a sealed boundary only through its view. */
	{
		static const char child_context[] =
			"u:object_r:netlabel_cache_child_t:s0";
		struct selinux_label_domain *child;
		struct selinux_label_ref *child_label;
		struct selinux_label_map *map;
		struct selinux_global_sid_handle *sid_handle;
		const struct selinux_label_view *view;
		struct selinux_state child_state;
		u32 child_sid;

		child = selinux_test_domain_alloc(test, origin);
		KUNIT_ASSERT_NOT_NULL(test, child);
		child_label = selinux_test_global_label(
			test, &child_state, child, child_context, &child_sid);
		KUNIT_ASSERT_NOT_NULL(test, child_label);
		selinux_test_state_init(&child_state, 3);
		child_state.label_domain = child;
		smp_store_release(&child_state.initialized, true);
		map = selinux_test_label_map_alloc(test, origin, child);
		KUNIT_ASSERT_NOT_NULL(test, map);
		KUNIT_ASSERT_EQ(test,
				selinux_test_map_pair(map, label, global_sid,
						      child_label, child_sid),
				0);
		KUNIT_ASSERT_EQ(test, selinux_label_map_seal(map, origin), 0);
		KUNIT_ASSERT_EQ(test,
				selinux_test_label_domain_publish_map(
					test, child, map, origin), 0);
		view = selinux_identity_view_alloc(&init_user_ns, child, origin);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, view);
		KUNIT_ASSERT_EQ(test,
				kunit_add_action_or_reset(
					test, selinux_test_label_view_put,
					(void *)view),
				0);
		secattr = selinux_test_netlbl_cache_alloc(test, global_sid);
		KUNIT_ASSERT_NOT_NULL(test, secattr);
		sid = SECSID_WILD;
		sid_handle = security_netlbl_secattr_to_sid_view_handle(
			&child_state, view, secattr, &sid);
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, sid_handle);
		if (!IS_ERR_OR_NULL(sid_handle))
			global_sid_handle_put(sid_handle);
		KUNIT_EXPECT_EQ(test, sid, child_sid);
		kunit_release_action(test, selinux_test_netlbl_secattr_destroy,
				     secattr);
	}
}
#endif

static void selinux_policy_cache_key_test(struct kunit *test)
{
	struct selinux_policy *first_policy, *second_policy;
	struct selinux_policy_snapshot stored;
	struct selinux_policy_cache_key key;
	struct selinux_policy_snapshot query;

	first_policy = kunit_kzalloc(test, sizeof(*first_policy), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, first_policy);
	second_policy = kunit_kzalloc(test, sizeof(*second_policy), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, second_policy);
	stored = (struct selinux_policy_snapshot) {
		.policy_cookie = first_policy,
		.policycaps = 1UL << POLICYDB_CAP_NETPEER,
		.chain_epoch = 23,
		.seqno = 11,
		.initialized = true,
	};
	query = stored;

	selinux_policy_cache_key_init(&key, 71, &stored);
	KUNIT_EXPECT_TRUE(test,
		selinux_policy_cache_key_matches(&key, 71, &query));
	KUNIT_EXPECT_FALSE(test,
		selinux_policy_cache_key_matches(&key, 72, &query));

	query.seqno++;
	KUNIT_EXPECT_FALSE(test,
		selinux_policy_cache_key_matches(&key, 71, &query));
	query = stored;
	query.chain_epoch++;
	KUNIT_EXPECT_FALSE(test,
		selinux_policy_cache_key_matches(&key, 71, &query));
	query = stored;
	query.policy_cookie = second_policy;
	KUNIT_EXPECT_FALSE(test,
		selinux_policy_cache_key_matches(&key, 71, &query));
}

static void selinux_netport_key_test(struct kunit *test)
{
	struct selinux_policy first_policy, second_policy;
	const struct selinux_policy_snapshot stored = {
		.policy_cookie = &first_policy,
		.policycaps = 1UL << POLICYDB_CAP_NETPEER,
		.chain_epoch = 17,
		.seqno = 9,
		.initialized = true,
	};
	struct selinux_policy_snapshot query = stored;
	const u64 first_domain = 41, second_domain = 42;

	KUNIT_EXPECT_TRUE(test, selinux_kunit_netport_key_matches(
		first_domain, &stored, IPPROTO_TCP, 443,
		first_domain, &query, IPPROTO_TCP, 443));
	KUNIT_EXPECT_FALSE(test, selinux_kunit_netport_key_matches(
		first_domain, &stored, IPPROTO_TCP, 443,
		second_domain, &query, IPPROTO_TCP, 443));
	KUNIT_EXPECT_FALSE(test, selinux_kunit_netport_key_matches(
		first_domain, &stored, IPPROTO_TCP, 443,
		first_domain, &query, IPPROTO_UDP, 443));
	KUNIT_EXPECT_FALSE(test, selinux_kunit_netport_key_matches(
		first_domain, &stored, IPPROTO_TCP, 443,
		first_domain, &query, IPPROTO_TCP, 8443));

	query = stored;
	query.seqno++;
	KUNIT_EXPECT_FALSE(test, selinux_kunit_netport_key_matches(
		first_domain, &stored, IPPROTO_TCP, 443,
		first_domain, &query, IPPROTO_TCP, 443));

	query = stored;
	query.policy_cookie = &second_policy;
	KUNIT_EXPECT_FALSE(test, selinux_kunit_netport_key_matches(
		first_domain, &stored, IPPROTO_TCP, 443,
		first_domain, &query, IPPROTO_TCP, 443));

	query = stored;
	query.chain_epoch++;
	KUNIT_EXPECT_FALSE(test, selinux_kunit_netport_key_matches(
		first_domain, &stored, IPPROTO_TCP, 443,
		first_domain, &query, IPPROTO_TCP, 443));

	query = stored;
	query.initialized = false;
	KUNIT_EXPECT_FALSE(test, selinux_kunit_netport_key_matches(
		first_domain, &stored, IPPROTO_TCP, 443,
		first_domain, &query, IPPROTO_TCP, 443));

	query = stored;
	query.policycaps ^= 1UL << POLICYDB_CAP_NETPEER;
	KUNIT_EXPECT_FALSE(test, selinux_kunit_netport_key_matches(
		first_domain, &stored, IPPROTO_TCP, 443,
		first_domain, &query, IPPROTO_TCP, 443));
}

KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_mmput, mmput, struct mm_struct *);

static void selinux_test_tracking_failure_reset(void *unused)
{
	selinuxfs_kunit_tracking_failure(false);
}

static void selinuxfs_mm_tracking_test(struct kunit *test)
{
	struct mm_struct *first, *second;
	void *first_vma, *first_split, *first_reuse, *second_vma;
	int rc;

	if (!selinuxfs_kunit_mm_tracking_ready()) {
		kunit_skip(test, "selinuxfs per-mm registry is not initialized");
		return;
	}

	first = mm_alloc();
	KUNIT_ASSERT_NOT_NULL(test, first);
	rc = kunit_add_action_or_reset(test, selinux_test_mmput, first);
	KUNIT_ASSERT_EQ(test, rc, 0);
	second = mm_alloc();
	KUNIT_ASSERT_NOT_NULL(test, second);
	rc = kunit_add_action_or_reset(test, selinux_test_mmput, second);
	KUNIT_ASSERT_EQ(test, rc, 0);

	KUNIT_EXPECT_EQ(test, selinuxfs_mm_may_change(first), 0);
	first_vma = selinuxfs_kunit_mm_track(first);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first_vma);
	rc = kunit_add_action_or_reset(test, selinuxfs_kunit_mm_untrack,
				       first_vma);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, selinuxfs_mm_may_change(first), -EBUSY);

	/* A split/mremap in the same mm must retain a distinct VMA count. */
	first_split = selinuxfs_kunit_mm_track(first);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first_split);
	rc = kunit_add_action_or_reset(test, selinuxfs_kunit_mm_untrack,
				       first_split);
	KUNIT_ASSERT_EQ(test, rc, 0);
	kunit_release_action(test, selinuxfs_kunit_mm_untrack, first_vma);
	KUNIT_EXPECT_EQ(test, selinuxfs_mm_may_change(first), -EBUSY);

	/* A forked mm gets an independent entry. */
	second_vma = selinuxfs_kunit_mm_track(second);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, second_vma);
	rc = kunit_add_action_or_reset(test, selinuxfs_kunit_mm_untrack,
				       second_vma);
	KUNIT_ASSERT_EQ(test, rc, 0);
	kunit_release_action(test, selinuxfs_kunit_mm_untrack, first_split);
	KUNIT_EXPECT_EQ(test, selinuxfs_mm_may_change(first), 0);
	KUNIT_EXPECT_EQ(test, selinuxfs_mm_may_change(second), -EBUSY);

	/* Reinsert while the removed entry may still await its RCU worker. */
	first_reuse = selinuxfs_kunit_mm_track(first);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, first_reuse);
	rc = kunit_add_action_or_reset(test, selinuxfs_kunit_mm_untrack,
				       first_reuse);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, selinuxfs_mm_may_change(first), -EBUSY);
	kunit_release_action(test, selinuxfs_kunit_mm_untrack, first_reuse);
	KUNIT_EXPECT_EQ(test, selinuxfs_mm_may_change(first), 0);

	/* A void vm_ops->open() failure must make every transition fail closed. */
	selinuxfs_kunit_tracking_failure(true);
	rc = kunit_add_action_or_reset(test,
				       selinux_test_tracking_failure_reset, NULL);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, selinuxfs_mm_may_change(first), -EIO);
	KUNIT_EXPECT_EQ(test, selinuxfs_mm_may_change(second), -EIO);
	kunit_release_action(test, selinux_test_tracking_failure_reset, NULL);

	kunit_release_action(test, selinuxfs_kunit_mm_untrack, second_vma);
	KUNIT_EXPECT_EQ(test, selinuxfs_mm_may_change(second), 0);
}

#ifdef CONFIG_SECURITY_INFINIBAND
static void selinux_ib_pkey_key_test(struct kunit *test)
{
	struct selinux_policy policy;
	const struct selinux_policy_snapshot stored = {
		.policy_cookie = &policy,
		.chain_epoch = 13,
		.seqno = 5,
		.initialized = true,
	};
	struct selinux_policy_snapshot query = stored;
	const u64 first_domain = 51, second_domain = 52;
	const u64 prefix = 0x1122334455667788ULL;
	bool match;

	match = selinux_kunit_ib_pkey_key_matches(
		first_domain, &stored, prefix, 7, first_domain, &query, prefix, 7);
	KUNIT_EXPECT_TRUE(test, match);
	match = selinux_kunit_ib_pkey_key_matches(
		first_domain, &stored, prefix, 7, second_domain, &query, prefix, 7);
	KUNIT_EXPECT_FALSE(test, match);
	match = selinux_kunit_ib_pkey_key_matches(
		first_domain, &stored, prefix, 7, first_domain, &query,
		prefix + 1, 7);
	KUNIT_EXPECT_FALSE(test, match);
	match = selinux_kunit_ib_pkey_key_matches(
		first_domain, &stored, prefix, 7, first_domain, &query, prefix, 8);
	KUNIT_EXPECT_FALSE(test, match);

	query.chain_epoch++;
	match = selinux_kunit_ib_pkey_key_matches(
		first_domain, &stored, prefix, 7, first_domain, &query, prefix, 7);
	KUNIT_EXPECT_FALSE(test, match);
}
#endif

static struct kunit_case selinux_namespaces_test_cases[] = {
	KUNIT_CASE(selinux_chain_epoch_subtree_test),
	KUNIT_CASE(selinux_chain_epoch_saturation_test),
	KUNIT_CASE(selinux_chain_update_nested_test),
	KUNIT_CASE(selinux_chain_update_saturation_test),
	KUNIT_CASE(selinux_xfrm_resolution_chain_collection_test),
	KUNIT_CASE(selinux_xfrm_flow_origin_type_test),
	KUNIT_CASE(selinux_policy_snapshot_test),
#if CONFIG_SECURITY_SELINUX_SS_SID_CACHE_SIZE > 0
	KUNIT_CASE(selinux_global_sid_cache_active_key_test),
#endif
	KUNIT_CASE(selinux_audit_rule_provenance_test),
	KUNIT_CASE(selinux_cred_pair_linear_merge_test),
	KUNIT_CASE(selinux_audit_rule_carrier_projection_test),
	KUNIT_CASE(selinux_audit_rule_filter_failure_test),
	KUNIT_CASE(selinux_file_permission_cache_test),
	KUNIT_CASE(selinux_sidtab_cache_bounds_test),
	KUNIT_CASE(selinux_sidtab_cache_all_matches_test),
	KUNIT_CASE(selinux_sidtab_domain_identity_test),
	KUNIT_CASE(selinux_staged_policy_genfs_provenance_test),
	KUNIT_CASE(selinux_label_ref_identity_test),
	KUNIT_CASE(selinux_label_map_parent_ownership_test),
	KUNIT_CASE(selinux_label_map_directions_and_seal_test),
	KUNIT_CASE(selinux_label_map_handle_lifetime_test),
	KUNIT_CASE(selinux_label_map_source_handle_lifetime_test),
	KUNIT_CASE(selinux_label_view_missing_map_test),
	KUNIT_CASE(selinux_label_view_sibling_domains_test),
	KUNIT_CASE(selinux_label_view_publish_snapshot_test),
	KUNIT_CASE(selinux_label_view_global_initial_sid_test),
	KUNIT_CASE(selinux_label_view_full_chain_test),
	KUNIT_CASE(selinux_inode_xattr_observer_view_test),
	KUNIT_CASE(selinux_pathless_domain_origin_test),
	KUNIT_CASE(selinux_pathless_missing_map_test),
	KUNIT_CASE(selinux_pathless_bidirectional_sealed_test),
	KUNIT_CASE(selinux_pathless_projection_seals_test),
	KUNIT_CASE(selinux_pathless_projection_seal_validation_test),
	KUNIT_CASE(selinux_pathless_persistent_object_kinds_test),
	KUNIT_CASE(selinux_pathless_initial_sid_refcount_test),
	KUNIT_CASE(selinux_pathless_projection_sid_lifetime_test),
	KUNIT_CASE(selinux_label_view_chain_fail_closed_test),
	KUNIT_CASE(selinux_label_view_stale_snapshot_resolution_test),
	KUNIT_CASE(selinux_label_operation_sibling_snapshot_test),
	KUNIT_CASE(selinux_label_operation_cousin_lca_test),
	KUNIT_CASE(selinux_secmark_carrier_match_test),
	KUNIT_CASE(selinux_secmark_carrier_sealed_view_test),
	KUNIT_CASE(selinux_net_carrier_lifetime_test),
	KUNIT_CASE(selinux_net_assertion_sid_lifetime_test),
	KUNIT_CASE(selinux_mnt_topology_transaction_test),
	KUNIT_CASE(selinux_global_initial_sid_exactness_test),
	KUNIT_CASE(selinux_inode_sid_handle_lifetime_test),
	KUNIT_CASE(selinux_inode_sid_handle_fail_closed_test),
	KUNIT_CASE(selinux_global_sid_reclaim_accounting_test),
	KUNIT_CASE(selinux_global_sid_atomic_handle_test),
	KUNIT_CASE(selinux_global_sid_initial_immortal_test),
	KUNIT_CASE(selinux_global_sid_initial_alias_test),
	KUNIT_CASE(selinux_net_peersid_null_sentinel_test),
	KUNIT_CASE(selinux_prop_ref_scalar_metadata_lifetime_test),
	KUNIT_CASE(selinux_prop_ref_secctx_render_test),
	KUNIT_CASE(selinux_prop_ref_cross_domain_render_test),
	KUNIT_CASE(selinux_prop_ref_replace_tombstone_test),
#if IS_BUILTIN(CONFIG_CACHEFILES)
	KUNIT_CASE(selinux_prop_ref_cachefiles_exact_identity_test),
#endif
#ifdef CONFIG_NETLABEL
	KUNIT_CASE(selinux_prop_ref_netlbl_exact_handle_test),
	KUNIT_CASE(selinux_netlbl_canonical_cache_test),
#endif
	KUNIT_CASE(selinux_policy_cache_key_test),
	KUNIT_CASE(selinux_netport_key_test),
	KUNIT_CASE(selinuxfs_mm_tracking_test),
#ifdef CONFIG_SECURITY_INFINIBAND
	KUNIT_CASE(selinux_ib_pkey_key_test),
#endif
	{}
};

static struct kunit_suite selinux_namespaces_test_suite = {
	.name = "selinux-namespaces",
	.test_cases = selinux_namespaces_test_cases,
};

kunit_test_suite(selinux_namespaces_test_suite);

MODULE_DESCRIPTION("KUnit tests for SELinux namespace cache isolation");
MODULE_LICENSE("GPL");
