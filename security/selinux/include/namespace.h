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

struct cred;
struct file;
struct selinux_resource_account;
struct selinux_state;
struct proc_ns_operations;

/* Hard bound for credential/state ancestry snapshots. */
#define SELINUX_NS_MAX_DEPTH 32U

/*
 * Parent-owned construction object for a two-phase SELinux namespace.  The
 * target state is not eligible for credential installation until activation.
 */
struct selinux_ns_control {
	struct ns_common ns;
	/* Serializes policy construction and activation. */
	struct mutex lock;
	struct selinux_state *state;
	/* Charged for the complete state/control lifetime, including dormancy. */
	struct selinux_resource_account *resources;
	u64 resource_bytes;
	bool tree_published;
};

int selinux_ns_control_state_init(struct selinux_state *state, bool active);
void selinux_ns_control_state_destroy(struct selinux_state *state);

struct selinux_ns_control *selinux_ns_control_alloc(const struct cred *cred);
struct selinux_ns_control *selinux_ns_control_alloc_unassigned(
	const struct cred *cred);
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
int selinux_ns_control_activate(struct selinux_ns_control *control,
				const struct selinux_state *actor);
struct selinux_state *
selinux_ns_control_state_get(struct selinux_ns_control *control);
long selinux_ns_control_ioctl(struct selinux_ns_control *control,
			      unsigned int cmd, unsigned long arg);
int selinux_ns_control_prepare_join(struct selinux_ns_control *control,
				    struct cred **prepared);

extern const struct proc_ns_operations selinuxns_operations;

#endif /* _SELINUX_NAMESPACE_H_ */
