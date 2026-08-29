// SPDX-License-Identifier: GPL-2.0-only
/* SELinux policy and label-view anchors for network namespaces. */

#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/limits.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "label_view.h"
#include "netns.h"
#include "security.h"

static unsigned int selinux_netns_id __read_mostly;
static bool selinux_netns_registered __read_mostly;
static atomic64_t selinux_netns_sequence = ATOMIC64_INIT(0);

static u64 selinux_netns_next_id(void)
{
	s64 old = atomic64_read(&selinux_netns_sequence);

	for (;;) {
		if (unlikely(old == S64_MAX))
			return 0;
		if (atomic64_try_cmpxchg(&selinux_netns_sequence, &old, old + 1))
			return old + 1;
	}
}

const struct selinux_netns_security *selinux_netns(const struct net *net)
{
	/* net_generic() must not be used before our per-net id is allocated. */
	if (!net || !READ_ONCE(selinux_netns_registered))
		return NULL;
	return net_generic(net, selinux_netns_id);
}

static int __net_init selinux_netns_alloc(struct net *net)
{
	struct selinux_netns_security *netsec =
		net_generic(net, selinux_netns_id);
	struct selinux_state *state = current_selinux_state;
	const struct selinux_label_view *view;
	u64 id;

	if (!netsec || !state || !state->label_domain || !init_selinux_state ||
	    !init_selinux_state->label_domain || !net->user_ns)
		return -EACCES;

	id = selinux_netns_next_id();
	if (!id)
		return -EOVERFLOW;
	state = get_selinux_state(state);
	view = selinux_identity_view_alloc(net->user_ns, state->label_domain,
					   init_selinux_state->label_domain);
	if (IS_ERR(view)) {
		put_selinux_state(state);
		return PTR_ERR(view);
	}

	netsec->state = state;
	netsec->view = view;
	netsec->id = id;
	netsec->generation = id;
	return 0;
}

static void __net_exit selinux_netns_free(struct net *net)
{
	struct selinux_netns_security *netsec =
		net_generic(net, selinux_netns_id);

	if (!netsec)
		return;
	selinux_label_view_put(netsec->view);
	put_selinux_state(netsec->state);
	netsec->view = NULL;
	netsec->state = NULL;
}

static struct pernet_operations selinux_netns_ops = {
	.init = selinux_netns_alloc,
	.exit = selinux_netns_free,
	.id = &selinux_netns_id,
	.size = sizeof(struct selinux_netns_security),
};

int __init selinux_netns_init(void)
{
	int rc;

	rc = register_pernet_subsys(&selinux_netns_ops);
	if (!rc)
		WRITE_ONCE(selinux_netns_registered, true);
	return rc;
}
