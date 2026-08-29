/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SELINUX_LABEL_H_
#define _SELINUX_LABEL_H_

#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/rhashtable.h>
#include <linux/types.h>
#include <linux/workqueue.h>

struct user_namespace;
struct selinux_label_map;
struct selinux_resource_account;

enum selinux_label_domain_flags {
	SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL = 1U << 0,
};

/* How an object acquired a label; this does not participate in equality. */
enum selinux_label_source {
	SELINUX_LABEL_SOURCE_UNSPECIFIED,
	SELINUX_LABEL_SOURCE_KERNEL_INITIAL,
	SELINUX_LABEL_SOURCE_XATTR,
	SELINUX_LABEL_SOURCE_GENFS,
	SELINUX_LABEL_SOURCE_MOUNT_CONTEXT,
	SELINUX_LABEL_SOURCE_TASK,
	SELINUX_LABEL_SOURCE_TRANSITION,
	SELINUX_LABEL_SOURCE_FILESYSTEM,
	SELINUX_LABEL_SOURCE_SECURITY_CONTEXT,
	SELINUX_LABEL_SOURCE_SOCKET,
};

/*
 * A domain is the stable provenance identity for labels produced by one
 * SELinux policy lineage.  It deliberately does not retain the policy/state:
 * durable labels may outlive policy namespaces, while policy memory must
 * remain reclaimable.
 */
struct selinux_label_domain {
	refcount_t refs;
	u64 id;
	u64 generation;
	u32 flags;
	u16 depth;
	struct user_namespace *owner_userns;
	struct selinux_resource_account *resources;
	struct selinux_label_domain *parent;
#ifdef CONFIG_SECURITY_SELINUX_NS
	/* Serializes replacement of boundary_map. */
	struct mutex map_lock;
	struct selinux_label_map __rcu *boundary_map;
#endif
	struct rhashtable labels;
	atomic_t label_count;
	atomic_long_t label_bytes;
	struct rcu_head rcu;
	struct work_struct free_work;
};

/* Canonical context identity; assertion source and object class are separate. */
struct selinux_label_ref {
	refcount_t refs;
	u64 id;
	u64 generation;
	struct selinux_label_domain *domain;
	struct rhash_head node;
	u32 context_len;
	struct rcu_head rcu;
	char context[];
};

struct selinux_label_domain *
selinux_label_domain_alloc(struct user_namespace *owner_userns,
			   struct selinux_label_domain *parent, u32 flags);
struct selinux_label_domain *
selinux_label_domain_get(struct selinux_label_domain *domain);
void selinux_label_domain_put(struct selinux_label_domain *domain);

struct selinux_label_ref *
selinux_label_ref_intern(struct selinux_label_domain *domain,
			 const char *context, u32 context_len, gfp_t gfp);
struct selinux_label_ref *
selinux_label_ref_get(struct selinux_label_ref *label);
struct selinux_label_ref *
selinux_label_ref_get_rcu(struct selinux_label_ref __rcu * const *labelp);
void selinux_label_ref_put(struct selinux_label_ref *label);

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
void selinux_label_domain_kunit_drain(void);
enum selinux_label_kunit_fault {
	SELINUX_LABEL_KUNIT_FAULT_NONE,
	SELINUX_LABEL_KUNIT_FAULT_RESERVE,
	SELINUX_LABEL_KUNIT_FAULT_ALLOC,
	SELINUX_LABEL_KUNIT_FAULT_HASH_INSERT,
	SELINUX_LABEL_KUNIT_FAULT_MAX,
};

void selinux_label_kunit_fail_next(struct selinux_label_domain *domain,
				   enum selinux_label_kunit_fault fault);
bool selinux_label_kunit_context_published(
	struct selinux_label_domain *domain, const char *context, u32 context_len);
#endif

#endif /* _SELINUX_LABEL_H_ */
