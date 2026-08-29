/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Network interface table.
 *
 * Network interfaces (devices) do not have a security field, so we
 * maintain a table associating each interface with a SID.
 *
 * Author: James Morris <jmorris@redhat.com>
 *
 * Copyright (C) 2003 Red Hat, Inc., James Morris <jmorris@redhat.com>
 * Copyright (C) 2007 Hewlett-Packard Development Company, L.P.
 *                    Paul Moore <paul@paul-moore.com>
 */

#ifndef _SELINUX_NETIF_H_
#define _SELINUX_NETIF_H_

#include <net/net_namespace.h>

void sel_netif_flush(void);

struct selinux_state;
struct selinux_policy_snapshot;
struct selinux_global_sid_handle;
int sel_netif_sid(struct selinux_state *state, struct net *ns, int ifindex,
		  u32 *sid);
int sel_netif_sid_snapshot(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, struct net *ns,
	int ifindex, u32 *sid);
#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_global_sid_handle *
sel_netif_sid_handle(struct selinux_state *state, struct net *ns, int ifindex,
		     u32 *sid);
struct selinux_global_sid_handle *
sel_netif_sid_snapshot_handle(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, struct net *ns,
	int ifindex, u32 *sid);
#endif

#endif /* _SELINUX_NETIF_H_ */
