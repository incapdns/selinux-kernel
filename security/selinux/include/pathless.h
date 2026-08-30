/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SELINUX_PATHLESS_H_
#define _SELINUX_PATHLESS_H_

#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/types.h>
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
#include <linux/completion.h>
#endif

#include "label.h"

struct selinux_label_domain;
struct selinux_label_view;
struct selinux_global_sid_handle;
struct selinux_resource_account;
struct selinux_policy_snapshot;
struct cred;

/* The object family whose path-independent label is being projected. */
enum selinux_pathless_kind {
	SELINUX_PATHLESS_KIND_INVALID,
	SELINUX_PATHLESS_KIND_ANON_INODE,
	SELINUX_PATHLESS_KIND_MEMFD,
	SELINUX_PATHLESS_KIND_BPF,
	SELINUX_PATHLESS_KIND_KEY,
	SELINUX_PATHLESS_KIND_PERF_EVENT,
	SELINUX_PATHLESS_KIND_IPC,
	SELINUX_PATHLESS_KIND_MSG,
	SELINUX_PATHLESS_KIND_INFINIBAND,
	SELINUX_PATHLESS_KIND_NSFS,
	SELINUX_PATHLESS_KIND_MAX,
};

enum selinux_pathless_model {
	SELINUX_PATHLESS_MODEL_INVALID,
	SELINUX_PATHLESS_MODEL_LEGACY,
	SELINUX_PATHLESS_MODEL_TRANSITION,
	SELINUX_PATHLESS_MODEL_CONTEXT_COPY,
	SELINUX_PATHLESS_MODEL_MAX,
};

struct selinux_pathless_seal {
	u64 domain_id;
	struct selinux_global_sid_handle *sid_handle;
	u32 sid;
	u16 sclass;
	u8 model;
	u8 reserved;
};

struct selinux_pathless_expect {
	const struct selinux_label_domain *domain;
	u32 sid;
	u16 sclass;
	enum selinux_pathless_model model;
};

struct selinux_pathless_resolution {
	u64 map_generation;
	u32 sid;
	u16 sclass;
	u8 model;
};

struct selinux_pathless_chain_resolution {
	struct selinux_label_operation_resolution labels;
	struct selinux_pathless_resolution level[
		SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	u16 count;
};

/*
 * Immutable path-independent label provenance.  The retained view is itself
 * an immutable snapshot of every sealed map generation in the full ancestry
 * chain; a second mutable generation here would add no identity information.
 */
struct selinux_pathless_projection {
	refcount_t refs;
	u64 id;
	struct selinux_label_ref *label;
	const struct selinux_label_view *view;
	struct selinux_global_sid_handle *sid_handle;
	struct selinux_resource_account *resources;
	size_t charged_bytes;
	u32 sid;
	/* Explicit policy-local tuple at the canonical label's origin depth. */
	u16 canonical_sclass;
	u16 legacy_sclass;
	u8 kind;
	u8 source;
	u8 canonical_model;
	u8 canonical_depth;
	u16 seal_count;
	struct rcu_head rcu;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	/* External completion used only by deterministic teardown tests. */
	struct completion *free_done_kunit;
#endif
	struct selinux_pathless_seal seals[];
};

struct selinux_pathless_projection *
selinux_pathless_projection_alloc(enum selinux_pathless_kind kind,
				  enum selinux_label_source source,
				  struct selinux_label_ref *label, u32 sid,
				  const struct selinux_label_view *view,
				  gfp_t gfp);
struct selinux_pathless_projection *
selinux_pathless_projection_alloc_sealed(
	enum selinux_pathless_kind kind, enum selinux_label_source source,
	struct selinux_label_ref *label, u32 sid,
	const struct selinux_label_view *view,
	const struct selinux_pathless_expect *expects, size_t expect_count,
	gfp_t gfp);
struct selinux_pathless_projection *
selinux_pathless_projection_get(struct selinux_pathless_projection *projection);
int selinux_pathless_policy_expect(
	const struct selinux_pathless_projection *projection,
	const struct selinux_policy_snapshot *snapshot,
	const struct selinux_label_domain *domain, u32 mapped_sid,
	struct selinux_pathless_expect *expect);
int selinux_pathless_projection_resolve_cred_chain(
	const struct selinux_pathless_projection *projection,
	const struct cred *const *cred,
	const struct selinux_policy_snapshot *snapshots, u16 count,
	struct selinux_pathless_chain_resolution *resolved);
void selinux_pathless_chain_resolution_put(
	struct selinux_pathless_chain_resolution *resolved);
void
selinux_pathless_projection_put(struct selinux_pathless_projection *projection);
enum selinux_pathless_kunit_fault {
	SELINUX_PATHLESS_KUNIT_FAULT_NONE,
	SELINUX_PATHLESS_KUNIT_FAULT_RESERVE,
	SELINUX_PATHLESS_KUNIT_FAULT_ALLOC,
	SELINUX_PATHLESS_KUNIT_FAULT_SEAL_ACQUIRE,
	SELINUX_PATHLESS_KUNIT_FAULT_MAX,
};

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
void selinux_pathless_projection_kunit_put_and_wait(
	struct selinux_pathless_projection *projection);
/* @occurrence is one-based; an armed fault is consumed at most once. */
int selinux_pathless_kunit_fault_arm(
	enum selinux_pathless_kunit_fault point, unsigned int occurrence);
void selinux_pathless_kunit_fault_disarm(void);
#endif
int
selinux_pathless_projection_resolve(const struct selinux_pathless_projection *projection,
				    const struct selinux_label_domain *policy_domain,
				    u32 *resolved_sid);
int selinux_pathless_projection_resolve_sealed(
	const struct selinux_pathless_projection *projection,
	const struct selinux_label_domain *policy_domain,
	struct selinux_pathless_resolution *resolution);

#endif /* _SELINUX_PATHLESS_H_ */
