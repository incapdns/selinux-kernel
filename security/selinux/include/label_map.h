/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SELINUX_LABEL_MAP_H_
#define _SELINUX_LABEL_MAP_H_

#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/rhashtable.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
#include <linux/completion.h>
#endif

#include "label.h"

struct selinux_global_sid_handle;

enum selinux_label_map_direction {
	SELINUX_LABEL_MAP_PARENT_TO_CHILD,
	SELINUX_LABEL_MAP_CHILD_TO_PARENT,
	SELINUX_LABEL_MAP_DIRECTIONS,
};

struct selinux_label_map_entry {
	struct rhash_head node;
	struct selinux_label_ref *source;
	struct selinux_global_sid_handle *source_handle;
	u32 source_sid;
	struct selinux_label_ref *target;
	struct selinux_global_sid_handle *target_handle;
	struct selinux_resource_account *resources;
};

struct selinux_label_map_table {
	struct rhashtable entries;
	u32 count;
};

/* Entries are mutable before sealing; publication assigns generation once. */
struct selinux_label_map {
	refcount_t refs;
	u64 id;
	/* Assigned internally on first publication; zero means unpublished. */
	u64 generation;
	struct selinux_label_domain *parent;
	struct selinux_resource_account *resources;
	/* Stable identity without a strong child reference or parent-child cycle. */
	u64 child_domain_id;
	/* Serializes construction and the one-way transition to sealed. */
	struct mutex build_lock;
	bool sealed;
	struct selinux_label_map_table direction[SELINUX_LABEL_MAP_DIRECTIONS];
	struct rcu_head rcu;
	struct work_struct free_work;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	/* External completion used only by deterministic teardown tests. */
	struct completion *free_done_kunit;
#endif
};

struct selinux_label_map *
selinux_label_map_alloc(struct selinux_label_domain *parent,
			struct selinux_label_domain *child);
struct selinux_label_map *
selinux_label_map_get(struct selinux_label_map *map);
void selinux_label_map_put(struct selinux_label_map *map);
enum selinux_label_map_kunit_fault {
	SELINUX_LABEL_MAP_KUNIT_FAULT_NONE,
	SELINUX_LABEL_MAP_KUNIT_FAULT_TABLE_INIT,
	SELINUX_LABEL_MAP_KUNIT_FAULT_ENTRY_RESERVE,
	SELINUX_LABEL_MAP_KUNIT_FAULT_ENTRY_ALLOC,
	SELINUX_LABEL_MAP_KUNIT_FAULT_ENTRY_INSERT,
	SELINUX_LABEL_MAP_KUNIT_FAULT_MAX,
};

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
void selinux_label_map_kunit_put_and_wait(struct selinux_label_map *map);
int selinux_label_map_kunit_unpublish(struct selinux_label_domain *child,
				      struct selinux_label_map *map);
/* @occurrence is one-based; an armed fault is consumed at most once. */
int selinux_label_map_kunit_fault_arm(
	enum selinux_label_map_kunit_fault point, unsigned int occurrence);
void selinux_label_map_kunit_fault_disarm(void);
#endif
int selinux_label_map_add(struct selinux_label_map *map,
			  enum selinux_label_map_direction direction,
			  struct selinux_global_sid_handle *source_handle,
			  struct selinux_global_sid_handle *target_handle);
int selinux_label_map_seal(struct selinux_label_map *map,
			   const struct selinux_label_domain *actor);
bool selinux_label_map_complete(struct selinux_label_map *map);
int selinux_label_domain_publish_map(struct selinux_label_domain *child,
				     struct selinux_label_map *map,
				     const struct selinux_label_domain *actor);
struct selinux_label_map *
selinux_label_domain_get_map(const struct selinux_label_domain *child);
int selinux_label_map_resolve(struct selinux_label_map *map,
			      enum selinux_label_map_direction direction,
			      const struct selinux_label_ref *source,
			      u32 source_sid,
			      u32 *target_sid,
			      struct selinux_label_ref **target);

#endif /* _SELINUX_LABEL_MAP_H_ */
