/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_SELINUX_NET_H
#define _LINUX_SELINUX_NET_H

#include <linux/gfp_types.h>
#include <linux/types.h>

struct net;
struct lsm_secmark;
struct selinux_net_provenance;

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_net_provenance *
selinux_secmark_provenance_create(const struct net *net, u32 sid, gfp_t gfp);
struct selinux_net_provenance *
selinux_secmark_provenance_take(struct lsm_secmark *secmark);
struct selinux_net_provenance *
selinux_net_provenance_get(struct selinux_net_provenance *provenance);
struct selinux_net_provenance *
selinux_net_provenance_get_rcu(
	struct selinux_net_provenance __rcu * const *provenancep);
void selinux_net_provenance_put(
	struct selinux_net_provenance *provenance);
bool selinux_secmark_provenance_matches(
	const struct selinux_net_provenance *provenance, u32 sid);
#endif

#endif /* _LINUX_SELINUX_NET_H */
