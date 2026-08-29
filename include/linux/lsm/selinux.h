/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Linux Security Module interface to other subsystems.
 * SELinux presents a single u32 value which is known as a secid.
 */
#ifndef __LINUX_LSM_SELINUX_H
#define __LINUX_LSM_SELINUX_H
#include <linux/types.h>

struct selinux_net_provenance;

struct lsm_prop_selinux {
#ifdef CONFIG_SECURITY_SELINUX
	u32 secid;
#endif
};

struct lsm_secmark_selinux {
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_net_provenance *provenance;
#else
	void *unused;
#endif
};

#endif /* ! __LINUX_LSM_SELINUX_H */
