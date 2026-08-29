/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SELINUX_NET_ASSERTION_H_
#define _SELINUX_NET_ASSERTION_H_

#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/types.h>

#include "label.h"

struct selinux_global_sid_handle;
struct selinux_label_view;
struct selinux_state;

enum selinux_net_assertion_source {
	SELINUX_NET_ASSERTION_SOURCE_INVALID,
	SELINUX_NET_ASSERTION_SOURCE_SOCKET,
	SELINUX_NET_ASSERTION_SOURCE_NETLABEL,
	SELINUX_NET_ASSERTION_SOURCE_XFRM,
	SELINUX_NET_ASSERTION_SOURCE_SECMARK,
	SELINUX_NET_ASSERTION_SOURCE_TUN,
	SELINUX_NET_ASSERTION_SOURCE_KERNEL_EXPLICIT,
	SELINUX_NET_ASSERTION_SOURCE_PEER_RESOLVED,
	SELINUX_NET_ASSERTION_SOURCE_MAX,
};

/* No optional semantic flag is supported before subsystem integration. */
#define SELINUX_NET_ASSERTION_FLAGS_MASK 0U

/* Immutable after allocation, apart from lifetime metadata. */
struct selinux_net_assertion {
	refcount_t refs;
	u64 id;
	u64 generation;
	struct selinux_label_ref *label;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *sid_handle;
#endif
	u32 sid;
	u32 flags;
	u16 semantic_class;
	u8 source;
	struct rcu_head rcu;
};

struct selinux_net_assertion *
selinux_net_assertion_alloc(struct selinux_label_ref *label,
				    u32 sid,
				    u16 semantic_class,
				    enum selinux_net_assertion_source source,
				    u32 flags, gfp_t gfp);
#ifdef CONFIG_SECURITY_SELINUX_NS
/*
 * Allocate from an already-owned canonical SID handle.  The returned
 * assertion takes an independent reference; @handle remains owned by the
 * caller on success and failure.
 */
struct selinux_net_assertion *
selinux_net_assertion_alloc_handle(
	struct selinux_global_sid_handle *handle,
	u16 semantic_class, enum selinux_net_assertion_source source,
	u32 flags, gfp_t gfp);
#endif
/* Requires an already-held strong reference; use get_rcu() for RCU pointers. */
struct selinux_net_assertion *
selinux_net_assertion_get(struct selinux_net_assertion *assertion);
struct selinux_net_assertion *
selinux_net_assertion_get_rcu(struct selinux_net_assertion __rcu * const *assertionp);
void selinux_net_assertion_put(struct selinux_net_assertion *assertion);

/*
 * An immutable ownership bundle for a network object.  It keeps the policy
 * lineage, the view used to cross that lineage, and the canonical subject
 * assertion coherent across asynchronous use and object cloning.
 */
struct selinux_net_provenance {
	refcount_t refs;
	u64 id;
	u64 generation;
	struct selinux_state *state;
	const struct selinux_label_view *view;
	struct selinux_net_assertion *subject;
	struct rcu_head rcu;
};

struct selinux_net_provenance *
selinux_net_provenance_alloc(struct selinux_state *state,
			     const struct selinux_label_view *view,
			     struct selinux_net_assertion *subject, gfp_t gfp);
struct selinux_net_provenance *
selinux_net_provenance_get(struct selinux_net_provenance *provenance);
struct selinux_net_provenance *
selinux_net_provenance_get_rcu(
	struct selinux_net_provenance __rcu * const *provenancep);
void selinux_net_provenance_put(struct selinux_net_provenance *provenance);

#endif /* _SELINUX_NET_ASSERTION_H_ */
