/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SELINUX_NETNS_H_
#define _SELINUX_NETNS_H_

#include <linux/types.h>

struct net;
struct selinux_label_view;
struct selinux_state;

/* Immutable policy/view anchor for one network namespace. */
struct selinux_netns_security {
	struct selinux_state *state;
	const struct selinux_label_view *view;
	u64 id;
	u64 generation;
};

#ifdef CONFIG_NET
int selinux_netns_init(void);
const struct selinux_netns_security *selinux_netns(const struct net *net);
#else
static inline int selinux_netns_init(void)
{
	return 0;
}
#endif

#endif /* _SELINUX_NETNS_H_ */
