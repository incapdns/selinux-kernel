/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Network node table
 *
 * SELinux must keep a mapping of network nodes to labels/SIDs.  This
 * mapping is maintained as part of the normal policy but a fast cache is
 * needed to reduce the lookup overhead since most of these queries happen on
 * a per-packet basis.
 *
 * Author: Paul Moore <paul@paul-moore.com>
 */

/*
 * (c) Copyright Hewlett-Packard Development Company, L.P., 2007
 */

#ifndef _SELINUX_NETNODE_H
#define _SELINUX_NETNODE_H

#include <linux/types.h>

void sel_netnode_flush(void);

struct selinux_state;
struct selinux_policy_snapshot;
struct selinux_global_sid_handle;
int sel_netnode_sid(struct selinux_state *state, const void *addr, u16 family,
		    u32 *sid);
int sel_netnode_sid_snapshot(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, const void *addr,
	u16 family, u32 *sid);
#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_global_sid_handle *
sel_netnode_sid_handle(struct selinux_state *state, const void *addr,
		      u16 family, u32 *sid);
struct selinux_global_sid_handle *
sel_netnode_sid_snapshot_handle(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, const void *addr,
	u16 family, u32 *sid);
#endif

#endif
