/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SELINUX_NAMESPACE_H_
#define _SELINUX_NAMESPACE_H_

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/mutex.h>
#include <linux/ns_common.h>
#include <linux/types.h>
#include <crypto/sha2.h>

#include "label_map.h"

struct cred;
struct file;
struct selinux_resource_account;
struct selinux_state;

/*
 * Parent-owned construction object for a two-phase SELinux namespace.  The
 * target state is not eligible for credential installation until activation.
 */
struct selinux_ns_control {
	struct ns_common ns;
	/* Serializes policy/map construction and activation. */
	struct mutex lock;
	struct selinux_state *state;
	/* Charged for the complete state/control lifetime, including dormancy. */
	struct selinux_resource_account *resources;
	u64 resource_bytes;
	struct selinux_label_map *map;
	u64 parent_chain_epoch;
	u64 child_chain_epoch;
	u64 map_entries[SELINUX_LABEL_MAP_DIRECTIONS];
	struct sha256_ctx map_digest_ctx;
	u8 map_digest[SHA256_DIGEST_SIZE];
	bool map_digest_valid;
	bool tree_published;
};

int selinux_ns_control_state_init(struct selinux_state *state, bool active);
void selinux_ns_control_state_destroy(struct selinux_state *state);

struct selinux_ns_control *selinux_ns_control_alloc(const struct cred *cred);
struct selinux_ns_control *selinux_ns_control_alloc_unassigned(
	const struct cred *cred);
int selinux_ns_control_reserve_id(struct selinux_ns_control *control,
				  u64 expected_id);
int selinux_ns_restore_parent_validate(const struct selinux_state *parent,
				       u64 expected_parent_id);
struct selinux_ns_control *
selinux_ns_control_get(struct selinux_ns_control *control);
void selinux_ns_control_put(struct selinux_ns_control *control);

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_ns_control *
selinux_ns_control_get_from_file(const struct file *file);
int selinux_ns_control_authorize_parent(
	struct selinux_ns_control *control, const struct cred *cred);
int selinux_ns_control_authorize_direct_child(
	struct selinux_ns_control *control, const struct cred *cred);
#else
static inline struct selinux_ns_control *
selinux_ns_control_get_from_file(const struct file *file)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int selinux_ns_control_authorize_direct_child(
	struct selinux_ns_control *control, const struct cred *cred)
{
	return -EOPNOTSUPP;
}

static inline int selinux_ns_control_authorize_parent(
	struct selinux_ns_control *control, const struct cred *cred)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_SECURITY_SELINUX_NS */

bool selinux_ns_control_parent(const struct selinux_ns_control *control,
			       const struct selinux_state *actor);
int selinux_ns_control_add_map(struct selinux_ns_control *control,
			       const struct selinux_state *actor,
			       enum selinux_label_map_direction direction,
			       const char *source_context, u32 source_len,
			       const char *target_context, u32 target_len);
int selinux_ns_control_activate(struct selinux_ns_control *control,
				const struct selinux_state *actor);
int selinux_ns_control_activate_restore(
	struct selinux_ns_control *control, const struct selinux_state *actor,
	u64 expected_id, u64 expected_parent_id, u64 expected_map_generation,
	u32 expected_policy_seqno, const u8 policy_digest[SHA256_DIGEST_SIZE],
	const u8 map_digest[SHA256_DIGEST_SIZE]);
int selinux_ns_control_resolve_join(struct selinux_ns_control *control,
				    const struct selinux_state *actor,
				    u32 actor_sid, u32 *target_sid);
struct selinux_state *
selinux_ns_control_state_get(struct selinux_ns_control *control);
long selinux_ns_control_ioctl(struct selinux_ns_control *control,
			      unsigned int cmd, unsigned long arg);
int selinux_ns_control_prepare_join(struct selinux_ns_control *control,
				    struct cred **prepared);
int selinux_ns_control_apply_join(struct selinux_ns_control *control,
				  const struct cred *actor,
				  struct cred *prepared);

#endif /* _SELINUX_NAMESPACE_H_ */
