/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * pkey table
 *
 * SELinux must keep a mapping of pkeys to labels/SIDs.  This
 * mapping is maintained as part of the normal policy but a fast cache is
 * needed to reduce the lookup overhead.
 */

/*
 * (c) Mellanox Technologies, 2016
 */

#ifndef _SELINUX_IB_PKEY_H
#define _SELINUX_IB_PKEY_H

#include <linux/types.h>
#include "flask.h"

struct selinux_state;
struct selinux_policy_snapshot;
struct selinux_global_sid_handle;

#ifdef CONFIG_SECURITY_INFINIBAND
void sel_ib_pkey_flush(void);
int sel_ib_pkey_sid(struct selinux_state *state, u64 subnet_prefix,
		    u16 pkey, u32 *sid);
int sel_ib_pkey_sid_snapshot(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, u64 subnet_prefix,
	u16 pkey, u32 *sid);
#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_global_sid_handle *
sel_ib_pkey_sid_handle(struct selinux_state *state, u64 subnet_prefix,
		      u16 pkey, u32 *sid);
struct selinux_global_sid_handle *
sel_ib_pkey_sid_snapshot_handle(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, u64 subnet_prefix,
	u16 pkey, u32 *sid);
#endif
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
bool selinux_kunit_ib_pkey_key_matches(
	u64 stored_domain_id,
	const struct selinux_policy_snapshot *stored_snapshot,
	u64 stored_subnet_prefix, u16 stored_pkey, u64 query_domain_id,
	const struct selinux_policy_snapshot *query_snapshot,
	u64 query_subnet_prefix, u16 query_pkey);
#endif
#else
static inline void sel_ib_pkey_flush(void)
{
	return;
}
static inline int sel_ib_pkey_sid(struct selinux_state *state,
				 u64 subnet_prefix, u16 pkey, u32 *sid)
{
	*sid = SECINITSID_UNLABELED;
	return 0;
}
#endif

#endif
