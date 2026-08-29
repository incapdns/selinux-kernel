/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SELINUX_LABEL_VIEW_H_
#define _SELINUX_LABEL_VIEW_H_

#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/types.h>
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
#include <linux/completion.h>
#endif

#include "label.h"
#ifdef CONFIG_SECURITY_SELINUX_NS
#include "label_map.h"
#endif

struct user_namespace;
struct selinux_resource_account;

enum selinux_label_view_flags {
	SELINUX_LABEL_VIEW_IDENTITY = 1U << 0,
	/* The owning user namespace still needs explicit origin-state plumbing. */
	SELINUX_LABEL_VIEW_ORIGIN_UNRESOLVED = 1U << 1,
};

#define SELINUX_LABEL_RESOLUTION_MAX_DEPTH 32

struct selinux_label_resolution {
	u64 domain_id[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	u32 sid[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	u16 max_depth;
};

/*
 * A label view is immutable after publication.  Only the reference count and
 * RCU linkage are mutable lifetime metadata; identity, generation, and flags
 * participate in the meaning of every label resolved through the view.
 */
struct selinux_label_view {
	refcount_t refs;
	u64 id;
	u64 generation;
	u32 flags;
	struct user_namespace *owner_userns;
	struct selinux_resource_account *resources;
	size_t charged_bytes;
	struct selinux_label_domain *origin_domain;
	struct selinux_label_domain *outer_domain;
	u16 map_count;
	struct rcu_head rcu;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	/* External completion used only by deterministic teardown tests. */
	struct completion *free_done_kunit;
#endif
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_label_map *maps[];
#endif
};

const struct selinux_label_view *
selinux_label_view_get(const struct selinux_label_view *view);
void selinux_label_view_put(const struct selinux_label_view *view);
enum selinux_label_view_kunit_fault {
	SELINUX_LABEL_VIEW_KUNIT_FAULT_NONE,
	SELINUX_LABEL_VIEW_KUNIT_FAULT_RESERVE,
	SELINUX_LABEL_VIEW_KUNIT_FAULT_ALLOC,
	SELINUX_LABEL_VIEW_KUNIT_FAULT_CHAIN_ACQUIRE,
	SELINUX_LABEL_VIEW_KUNIT_FAULT_MAX,
};

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
void selinux_label_view_kunit_put_and_wait(
	const struct selinux_label_view *view);
/* @occurrence is one-based; an armed fault is consumed at most once. */
int selinux_label_view_kunit_fault_arm(
	enum selinux_label_view_kunit_fault point, unsigned int occurrence);
void selinux_label_view_kunit_fault_disarm(void);
#endif
const struct selinux_label_view *
selinux_identity_view_alloc(struct user_namespace *owner_userns,
			    struct selinux_label_domain *origin_domain,
			    struct selinux_label_domain *outer_domain);
const struct selinux_label_view *
selinux_identity_view_alloc_gfp(struct user_namespace *owner_userns,
				struct selinux_label_domain *origin_domain,
				struct selinux_label_domain *outer_domain,
				gfp_t gfp);
#ifdef CONFIG_SECURITY_SELINUX_NS
int selinux_label_view_resolve_chain(const struct selinux_label_view *view,
				     const struct selinux_label_ref *source,
				     u32 source_sid,
				     struct selinux_label_resolution *resolution);
int selinux_label_view_resolve(const struct selinux_label_view *view,
			       const struct selinux_label_domain *policy_domain,
			       const struct selinux_label_ref *source,
			       u32 source_sid, u32 *resolved_sid);
#endif

#endif /* _SELINUX_LABEL_VIEW_H_ */
