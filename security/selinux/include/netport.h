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

struct cred;
struct selinux_object_identity;

void sel_netport_flush(void);

int sel_netport_object(const struct cred *cred, u8 protocol, u16 pnum,
		       struct selinux_object_identity **object);

#endif
