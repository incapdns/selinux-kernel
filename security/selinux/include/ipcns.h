/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SELINUX_IPCNS_H_
#define _SELINUX_IPCNS_H_

#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/types.h>

struct cred;
struct ipc_namespace;
struct selinux_label_view;
struct lsm_id;

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_ipcns_anchor;

struct selinux_ipcns_security {
	spinlock_t lock;
	struct selinux_ipcns_anchor *anchor;
	struct selinux_ipcns_anchor *pending;
	u64 generation;
	u64 pending_token;
	bool initialized;
	bool initial;
	bool ever_published;
	bool reanchored;
};

struct selinux_ipcns_anchor *
selinux_ipcns_anchor_get(struct ipc_namespace *ns, const struct cred *cred);
void selinux_ipcns_anchor_put(struct selinux_ipcns_anchor *anchor);
const struct selinux_label_view *
selinux_ipcns_anchor_view(const struct selinux_ipcns_anchor *anchor);
bool selinux_ipcns_anchor_valid(struct ipc_namespace *ns,
			       const struct cred *cred,
			       const struct selinux_ipcns_anchor *anchor);
void __init selinux_ipcns_add_hooks(const struct lsm_id *lsmid);
#endif

#endif /* _SELINUX_IPCNS_H_ */
