/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Network port table
 *
 * SELinux must keep a mapping of network ports to labels/SIDs.  This
 * mapping is maintained as part of the normal policy but a fast cache is
 * needed to reduce the lookup overhead.
 *
 * Author: Paul Moore <paul@paul-moore.com>
 */

/*
 * (c) Copyright Hewlett-Packard Development Company, L.P., 2008
 */

#ifndef _SELINUX_NETPORT_H
#define _SELINUX_NETPORT_H

#include <linux/types.h>

struct selinux_state;
struct selinux_policy_snapshot;
struct selinux_global_sid_handle;

void sel_netport_flush(void);

int sel_netport_sid(struct selinux_state *state, u8 protocol, u16 pnum,
		    u32 *sid);
int sel_netport_sid_snapshot(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, u8 protocol, u16 pnum,
	u32 *sid);
#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_global_sid_handle *
sel_netport_sid_handle(struct selinux_state *state, u8 protocol, u16 pnum,
		      u32 *sid);
struct selinux_global_sid_handle *
sel_netport_sid_snapshot_handle(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, u8 protocol, u16 pnum,
	u32 *sid);
#endif

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
bool selinux_kunit_netport_key_matches(
	u64 stored_domain_id,
	const struct selinux_policy_snapshot *stored_snapshot,
	u8 stored_protocol, u16 stored_port,
	u64 query_domain_id,
	const struct selinux_policy_snapshot *query_snapshot,
	u8 query_protocol, u16 query_port);
#endif

#endif
