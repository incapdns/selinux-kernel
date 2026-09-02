/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SELINUX_OBJECT_LABEL_H_
#define _SELINUX_OBJECT_LABEL_H_

#include <linux/gfp_types.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/types.h>

struct selinux_resource_account;
struct selinux_state;
struct cred;

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
	SELINUX_LABEL_SOURCE_NETWORK,
	/* A persistent label owned by another policy is intentionally opaque. */
	SELINUX_LABEL_SOURCE_FOREIGN_PERSISTENT,
	SELINUX_LABEL_SOURCE_POLICY_BYPASS,
};

/* One policy's immutable interpretation of one kernel object. */
struct selinux_object_label_value {
	u32 sid;
	u16 sclass;
	u8 source;
	/* Valid only for SECCLASS_FILESYSTEM labels. */
	u16 filesystem_behavior;
	u16 filesystem_flags;
};

struct selinux_object_label_update {
	struct selinux_state *state;
	struct selinux_object_identity *object;
	struct selinux_object_label_value value;
	/* Zero disables compare-and-publish for this update. */
	u64 expected_generation;
};

struct selinux_object_generation_guard {
	struct selinux_object_identity *object;
	u64 generation;
};

/*
 * Stable identity shared by every policy-local label for one kernel object.
 * The entry list is modified only by object_label.c's global writer mutex.
 */
struct selinux_object_identity {
	refcount_t refs;
	u64 id;
	atomic64_t generation;
	struct list_head entries;
	struct selinux_resource_account *resources;
	struct rcu_head rcu;
};

int selinux_object_label_table_init(struct selinux_state *state);
void selinux_object_label_table_destroy(struct selinux_state *state);

struct selinux_object_identity *
selinux_object_identity_alloc(struct selinux_state *owner, gfp_t gfp);
struct selinux_object_identity *
selinux_object_identity_alloc_from_cred(const struct cred *cred, u16 sclass,
					 enum selinux_label_source source,
					 gfp_t gfp);
struct selinux_object_identity *
selinux_object_identity_alloc_initial(struct selinux_state *leaf, u32 sid,
				      u16 sclass,
				      enum selinux_label_source source,
				      gfp_t gfp);
struct selinux_object_identity *
selinux_object_identity_clone_for_state(
	const struct selinux_object_identity *source,
	struct selinux_state *leaf,
	gfp_t gfp);
int selinux_object_label_copy_for_state_chain(
	struct selinux_object_identity *destination,
	const struct selinux_object_identity *source,
	struct selinux_state *leaf,
	u16 fallback_sclass,
	gfp_t gfp);
struct selinux_object_identity *
selinux_object_identity_get(struct selinux_object_identity *object);
void selinux_object_identity_put(struct selinux_object_identity *object);
u64 selinux_object_identity_generation(
	const struct selinux_object_identity *object);

int selinux_object_label_set(struct selinux_state *state,
			     struct selinux_object_identity *object,
			     const struct selinux_object_label_value *value,
			     gfp_t gfp);
int selinux_object_labels_set_chain(
	struct selinux_object_identity *object,
	struct selinux_state *const *states,
	const struct selinux_object_label_value *values,
	u16 count,
	gfp_t gfp);
int selinux_object_labels_update_transaction(
	const struct selinux_object_label_update *updates,
	u16 count,
	gfp_t gfp);
int selinux_object_labels_update_transaction_guarded(
	const struct selinux_object_label_update *updates,
	u16 count,
	const struct selinux_object_generation_guard *guards,
	u16 guard_count,
	gfp_t gfp);
int selinux_object_label_get(
	const struct selinux_state *state,
	const struct selinux_object_identity *object,
	struct selinux_object_label_value *value);
int selinux_object_label_snapshot(
	const struct selinux_state *state,
	const struct selinux_object_identity *object,
	struct selinux_object_label_value *value,
	u64 *generation);
void selinux_object_label_get_or_unlabeled(
	const struct selinux_state *state,
	const struct selinux_object_identity *object, u16 sclass,
	struct selinux_object_label_value *value);
void selinux_object_label_get_or_initial(
	const struct selinux_state *state,
	const struct selinux_object_identity *object,
	u32 initial_sid,
	u16 sclass,
	enum selinux_label_source source,
	struct selinux_object_label_value *value);

#endif /* _SELINUX_OBJECT_LABEL_H_ */
