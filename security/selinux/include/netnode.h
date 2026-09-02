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

struct cred;
struct selinux_object_identity;

void sel_netnode_flush(void);

int sel_netnode_object(const struct cred *cred, const void *addr, u16 family,
		       struct selinux_object_identity **object);

#endif
