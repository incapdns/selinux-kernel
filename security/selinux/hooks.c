// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Security-Enhanced Linux (SELinux) security module
 *
 *  This file contains the SELinux hook function implementations.
 *
 *  Authors:  Stephen Smalley, <stephen.smalley.work@gmail.com>
 *	      Chris Vance, <cvance@nai.com>
 *	      Wayne Salamon, <wsalamon@nai.com>
 *	      James Morris <jmorris@redhat.com>
 *
 *  Copyright (C) 2001,2002 Networks Associates Technology, Inc.
 *  Copyright (C) 2003-2008 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *					   Eric Paris <eparis@redhat.com>
 *  Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 *			    <dgoeddel@trustedcs.com>
 *  Copyright (C) 2006, 2007, 2009 Hewlett-Packard Development Company, L.P.
 *	Paul Moore <paul@paul-moore.com>
 *  Copyright (C) 2007 Hitachi Software Engineering Co., Ltd.
 *		       Yuichi Nakamura <ynakam@hitachisoft.jp>
 *  Copyright (C) 2016 Mellanox Technologies
 */

#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/kernel_read_file.h>
#include <linux/errno.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/lsm_hooks.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <net/inet_connection_sock.h>
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/rtnetlink.h>
#include <net/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sctp.h>
#include <net/sctp/structs.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <kunit/static_stub.h>
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/rhashtable.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/export.h>
#include <linux/msg.h>
#include <linux/ipc_namespace.h>
#include <linux/shm.h>
#include <uapi/linux/shm.h>
#include <linux/bpf.h>
#include <linux/kernfs.h>
#include <linux/stringhash.h>	/* for hashlen_string() */
#include <uapi/linux/mount.h>
#include <linux/fsnotify.h>
#include <linux/fanotify.h>
#include <linux/io_uring/cmd.h>
#include <uapi/linux/lsm.h>
#include <linux/memfd.h>

#include "initcalls.h"
#include "avc.h"
#include "objsec.h"
#include "netif.h"
#include "netnode.h"
#include "netport.h"
#include "ibpkey.h"
#include "ipcns.h"
#include "xfrm.h"
#include "netlabel.h"
#include "net_assertion.h"
#include "netns.h"
#include "pathless.h"
#include "audit.h"
#include "avc_ss.h"
#include "global_sidtab.h"
#include "namespace.h"

#define SELINUX_INODE_INIT_XATTRS 1

#ifdef CONFIG_SECURITY_SELINUX_NS
DEFINE_FREE(selinux_sid_handle, struct selinux_global_sid_handle *,
	    if (!IS_ERR_OR_NULL(_T)) global_sid_handle_put(_T))
#endif

/* SECMARK reference count */
static atomic_t selinux_secmark_refcount = ATOMIC_INIT(0);

#ifdef CONFIG_SECURITY_SELINUX_NS
static int sock_has_perm(struct sock *sk, u32 perms);
#endif

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
static int selinux_enforcing_boot __initdata;

static int __init enforcing_setup(char *str)
{
	unsigned long enforcing;
	if (!kstrtoul(str, 0, &enforcing))
		selinux_enforcing_boot = enforcing ? 1 : 0;
	return 1;
}
__setup("enforcing=", enforcing_setup);
#else
#define selinux_enforcing_boot 1
#endif

int selinux_enabled_boot __initdata = 1;
#ifdef CONFIG_SECURITY_SELINUX_BOOTPARAM
static int __init selinux_enabled_setup(char *str)
{
	unsigned long enabled;
	if (!kstrtoul(str, 0, &enabled))
		selinux_enabled_boot = enabled ? 1 : 0;
	return 1;
}
__setup("selinux=", selinux_enabled_setup);
#endif

static int __init checkreqprot_setup(char *str)
{
	unsigned long checkreqprot;

	if (!kstrtoul(str, 0, &checkreqprot)) {
		if (checkreqprot)
			pr_err("SELinux: checkreqprot set to 1 via kernel parameter.  This is no longer supported.\n");
	}
	return 1;
}
__setup("checkreqprot=", checkreqprot_setup);

/**
 * selinux_secmark_enabled - Check to see if SECMARK is currently enabled
 * @snapshot: immutable metadata for the policy performing the check
 *
 * Description:
 * This function checks the SECMARK reference counter to see if any SECMARK
 * targets are currently configured, if the reference counter is greater than
 * zero SECMARK is considered to be enabled.  Returns true (1) if SECMARK is
 * enabled, false (0) if SECMARK is disabled.  If the always_check_network
 * policy capability is enabled, SECMARK is always considered enabled.
 *
 */
static int selinux_secmark_enabled(const struct selinux_policy_snapshot *snapshot)
{
	return selinux_policy_snapshot_has_cap(snapshot,
					       POLICYDB_CAP_ALWAYSNETWORK) ||
	       atomic_read(&selinux_secmark_refcount);
}

/**
 * selinux_peerlbl_enabled - Check to see if peer labeling is currently enabled
 * @snapshot: immutable metadata for the policy performing the check
 *
 * Description:
 * This function checks if NetLabel or labeled IPSEC is enabled.  Returns true
 * (1) if any are enabled or false (0) if neither are enabled.  If the
 * always_check_network policy capability is enabled, peer labeling
 * is always considered enabled.
 *
 */
static int selinux_peerlbl_enabled(const struct selinux_policy_snapshot *snapshot)
{
	return selinux_policy_snapshot_has_cap(snapshot,
					       POLICYDB_CAP_ALWAYSNETWORK) ||
	       netlbl_enabled() || selinux_xfrm_enabled();
}

static int selinux_lsm_notifier_avc_callback(struct selinux_avc *avc,
					     u32 event)
{
	if (event == AVC_CALLBACK_RESET && init_selinux_state &&
	    avc == init_selinux_state->avc) {
#ifndef CONFIG_SECURITY_SELINUX_NS
		call_blocking_lsm_notifier(LSM_POLICY_CHANGE, NULL);
#endif
	}

	return 0;
}

/*
 * get the security ID of a set of credentials
 */
static inline u32 cred_sid(const struct cred *cred)
{
	const struct cred_security_struct *crsec;

	crsec = selinux_cred(cred);
	return crsec->sid;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static struct cred_security_struct unlabeled_cred_security;

static int selinux_cred_sid_slot(
	struct cred_security_struct *crsec, enum selinux_cred_sid_slot slot,
	u32 **sidp, struct selinux_global_sid_handle ***handlep)
{
	if (!crsec || !sidp || !handlep)
		return -EINVAL;
	switch (slot) {
	case SELINUX_CRED_OSID:
		*sidp = &crsec->osid;
		*handlep = &crsec->osid_handle;
		break;
	case SELINUX_CRED_SID:
		*sidp = &crsec->sid;
		*handlep = &crsec->sid_handle;
		break;
	case SELINUX_CRED_EXEC_SID:
		*sidp = &crsec->exec_sid;
		*handlep = &crsec->exec_sid_handle;
		break;
	case SELINUX_CRED_CREATE_SID:
		*sidp = &crsec->create_sid;
		*handlep = &crsec->create_sid_handle;
		break;
	case SELINUX_CRED_KEYCREATE_SID:
		*sidp = &crsec->keycreate_sid;
		*handlep = &crsec->keycreate_sid_handle;
		break;
	case SELINUX_CRED_SOCKCREATE_SID:
		*sidp = &crsec->sockcreate_sid;
		*handlep = &crsec->sockcreate_sid_handle;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int selinux_cred_sid_take_handle(
	struct cred_security_struct *crsec, enum selinux_cred_sid_slot slot,
	struct selinux_global_sid_handle *handle)
{
	struct selinux_global_sid_handle **handlep, *old;
	u32 *sidp, sid = SECSID_NULL;
	int rc;

	if (IS_ERR(handle))
		return PTR_ERR(handle);
	rc = selinux_cred_sid_slot(crsec, slot, &sidp, &handlep);
	if (rc) {
		global_sid_handle_put(handle);
		return rc;
	}
	if (handle) {
		sid = global_sid_handle_sid(handle);
		if (!sid) {
			global_sid_handle_put(handle);
			return -ESTALE;
		}
	}
	old = *handlep;
	WRITE_ONCE(*handlep, handle);
	WRITE_ONCE(*sidp, sid);
	global_sid_handle_put(old);
	return 0;
}

int selinux_cred_sid_set(struct cred_security_struct *crsec,
			 enum selinux_cred_sid_slot slot, u32 sid)
{
	struct selinux_global_sid_handle *handle = NULL;

	if (sid) {
		handle = global_sid_handle_get(sid);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
	}
	return selinux_cred_sid_take_handle(crsec, slot, handle);
}

static int selinux_cred_sid_dup_handle(
	struct cred_security_struct *crsec, enum selinux_cred_sid_slot slot,
	struct selinux_global_sid_handle *handle)
{
	if (handle) {
		handle = global_sid_handle_dup(handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
	}
	return selinux_cred_sid_take_handle(crsec, slot, handle);
}

static void selinux_cred_sid_handles_put(struct cred_security_struct *crsec)
{
	int slot;

	for (slot = 0; slot < SELINUX_CRED_SID_SLOTS; slot++)
		selinux_cred_sid_take_handle(crsec, slot, NULL);
}

static int selinux_cred_sid_handles_dup(
	struct cred_security_struct *dst,
	const struct cred_security_struct *src)
{
	int slot;

	dst->osid_handle = NULL;
	dst->sid_handle = NULL;
	dst->exec_sid_handle = NULL;
	dst->create_sid_handle = NULL;
	dst->keycreate_sid_handle = NULL;
	dst->sockcreate_sid_handle = NULL;
	for (slot = 0; slot < SELINUX_CRED_SID_SLOTS; slot++) {
		struct selinux_global_sid_handle *src_handle;
		struct selinux_global_sid_handle *handle = NULL;
		u32 src_sid;
		int rc;

		switch (slot) {
		case SELINUX_CRED_OSID:
			src_sid = src->osid;
			src_handle = src->osid_handle;
			break;
		case SELINUX_CRED_SID:
			src_sid = src->sid;
			src_handle = src->sid_handle;
			break;
		case SELINUX_CRED_EXEC_SID:
			src_sid = src->exec_sid;
			src_handle = src->exec_sid_handle;
			break;
		case SELINUX_CRED_CREATE_SID:
			src_sid = src->create_sid;
			src_handle = src->create_sid_handle;
			break;
		case SELINUX_CRED_KEYCREATE_SID:
			src_sid = src->keycreate_sid;
			src_handle = src->keycreate_sid_handle;
			break;
		case SELINUX_CRED_SOCKCREATE_SID:
			src_sid = src->sockcreate_sid;
			src_handle = src->sockcreate_sid_handle;
			break;
		default:
			return -EINVAL;
		}
		if (src_handle) {
			if (global_sid_handle_sid(src_handle) != src_sid)
				return -ESTALE;
			handle = global_sid_handle_dup(src_handle);
			if (IS_ERR(handle))
				return PTR_ERR(handle);
		} else if (src_sid) {
			/*
			 * The static fallback predates LSM blob setup and cannot carry
			 * a runtime reference.  A copied credential acquires ownership
			 * before publishing the fallback's numeric SID.
			 */
			if (src != &unlabeled_cred_security)
				return -ESTALE;
			handle = global_sid_handle_get(src_sid);
			if (IS_ERR(handle))
				return PTR_ERR(handle);
		}
		rc = selinux_cred_sid_take_handle(dst, slot, handle);
		if (rc)
			return rc;
	}
	return 0;
}
#endif

static struct cred_security_struct unlabeled_cred_security = {
	.osid = SECINITSID_UNLABELED,
	.sid = SECINITSID_UNLABELED,
};

/*
 * Caller must hold RCU read lock.
 */
static const struct cred_security_struct *task_cred_security(
	const struct task_struct *p)
{
	const struct cred_security_struct *crsec;

	crsec = selinux_cred(__task_cred(p));
	while (crsec->state != current_selinux_state && crsec->parent_cred)
		crsec = selinux_cred(crsec->parent_cred);
	if (crsec->state != current_selinux_state)
		return &unlabeled_cred_security;
	return crsec;
}

static void __ad_net_init(struct common_audit_data *ad,
			  struct lsm_network_audit *net,
			  int ifindex, struct sock *sk, u16 family)
{
	ad->type = LSM_AUDIT_DATA_NET;
	ad->u.net = net;
	net->netif = ifindex;
	net->sk = sk;
	net->family = family;
}

static void ad_net_init_from_sk(struct common_audit_data *ad,
				struct lsm_network_audit *net,
				struct sock *sk)
{
	__ad_net_init(ad, net, 0, sk, 0);
}

static void ad_net_init_from_iif(struct common_audit_data *ad,
				 struct lsm_network_audit *net,
				 int ifindex, u16 family)
{
	__ad_net_init(ad, net, ifindex, NULL, family);
}

/*
 * get the objective security ID of a task
 */
static inline u32 task_sid_obj(const struct task_struct *task)
{
	const struct cred_security_struct *crsec;
	u32 sid;

	rcu_read_lock();
	crsec = task_cred_security(task);
	sid = crsec->sid;
	rcu_read_unlock();
	return sid;
}

static int inode_doinit_with_dentry(struct inode *inode, struct dentry *opt_dentry);

/*
 * Try reloading inode security labels that have been marked as invalid.  The
 * @may_sleep parameter indicates when sleeping and thus reloading labels is
 * allowed; when set to false, returns -ECHILD when the label is
 * invalid.  The @dentry parameter should be set to a dentry of the inode.
 */
static int __inode_security_revalidate(struct inode *inode,
				       struct dentry *dentry,
				       bool may_sleep)
{
	if (!selinux_initialized(current_selinux_state))
		return 0;

	if (may_sleep)
		might_sleep();
	else
		return -ECHILD;

	/*
	 * Check to ensure that an inode's SELinux state is valid and try
	 * reloading the inode security label if necessary.  This will fail if
	 * @dentry is NULL and no dentry for this inode can be found; in that
	 * case, continue using the old label.
	 */
	inode_doinit_with_dentry(inode, dentry);
	return 0;
}

static struct inode_security_struct *inode_security_novalidate(struct inode *inode)
{
	return selinux_inode(inode);
}

static inline struct inode_security_struct *inode_security_rcu(struct inode *inode,
							       bool rcu)
{
	int rc;
	struct inode_security_struct *isec = selinux_inode(inode);

	/* check below is racy, but revalidate will recheck with lock held */
	if (data_race(likely(isec->initialized == LABEL_INITIALIZED)))
		return isec;
	rc = __inode_security_revalidate(inode, NULL, !rcu);
	if (rc)
		return ERR_PTR(rc);
	return isec;
}

/*
 * Get the security label of an inode.
 */
static inline struct inode_security_struct *inode_security(struct inode *inode)
{
	struct inode_security_struct *isec = selinux_inode(inode);

	/* check below is racy, but revalidate will recheck with lock held */
	if (data_race(likely(isec->initialized == LABEL_INITIALIZED)))
		return isec;
	__inode_security_revalidate(inode, NULL, true);
	return isec;
}

static inline struct inode_security_struct *backing_inode_security_novalidate(struct dentry *dentry)
{
	return selinux_inode(d_backing_inode(dentry));
}

/*
 * Get the security label of a dentry's backing inode.
 */
static inline struct inode_security_struct *backing_inode_security(struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);
	struct inode_security_struct *isec = selinux_inode(inode);

	/* check below is racy, but revalidate will recheck with lock held */
	if (data_race(likely(isec->initialized == LABEL_INITIALIZED)))
		return isec;
	__inode_security_revalidate(inode, dentry, true);
	return isec;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_inode_label_snapshot {
	struct selinux_global_sid_handle *sid_handle;
	struct selinux_label_ref *label;
	u32 sid;
	u16 sclass;
	u8 source;
};

static void selinux_inode_label_snapshot_put(
	struct selinux_inode_label_snapshot *snapshot)
{
	selinux_label_ref_put(snapshot->label);
	global_sid_handle_put(snapshot->sid_handle);
	memset(snapshot, 0, sizeof(*snapshot));
}

static int selinux_inode_label_snapshot_get(
	struct inode_security_struct *isec,
	struct selinux_inode_label_snapshot *snapshot)
{
	struct selinux_global_sid_handle *handle = NULL;
	struct selinux_label_ref *label = NULL;
	u32 sid;
	int rc = 0;

	memset(snapshot, 0, sizeof(*snapshot));
	spin_lock(&isec->lock);
	/*
	 * An invalid or pending tuple is retained only as revalidation input; it
	 * is never an identity that may be authorized.  Check the state under
	 * the same lock as every other tuple member so readers either observe a
	 * complete initialized identity or fail closed.
	 */
	if (isec->initialized != LABEL_INITIALIZED || !isec->sid_handle) {
		rc = -ESTALE;
		goto out_unlock;
	}
	handle = global_sid_handle_dup(isec->sid_handle);
	if (IS_ERR(handle)) {
		rc = PTR_ERR(handle);
		handle = NULL;
		goto out_unlock;
	}
	label = global_sid_handle_label_get(handle);
	sid = global_sid_handle_sid(handle);
	if (!label || !sid || sid != isec->sid || !isec->sclass ||
	    label != rcu_dereference_protected(
			     isec->label_ref, lockdep_is_held(&isec->lock))) {
		rc = -ESTALE;
		goto out_unlock;
	}
	snapshot->sid_handle = handle;
	snapshot->label = label;
	snapshot->sid = sid;
	snapshot->sclass = isec->sclass;
	snapshot->source = isec->label_source;
	handle = NULL;
	label = NULL;

out_unlock:
	spin_unlock(&isec->lock);
	selinux_label_ref_put(label);
	global_sid_handle_put(handle);
	return rc;
}

static void selinux_copy_up_carrier_free(struct work_struct *work)
{
	struct selinux_copy_up_carrier *carrier = container_of(
		work, struct selinux_copy_up_carrier, free_work);

	path_put(&carrier->src_path);
	selinux_label_view_put(carrier->dst_view);
	selinux_label_view_put(carrier->src_view);
	global_sid_handle_put(carrier->create_handle);
	global_sid_handle_put(carrier->sid_handle);
	selinux_label_ref_put(carrier->label);
	kfree(carrier);
}

static void selinux_copy_up_carrier_put(struct selinux_copy_up_carrier *carrier)
{
	if (carrier)
		schedule_work(&carrier->free_work);
}

static int inode_security_take_task_sid_handle(
	struct inode_security_struct *isec,
	struct selinux_global_sid_handle *handle)
{
	struct selinux_global_sid_handle *old;
	u32 sid = SECSID_NULL;

	if (IS_ERR(handle))
		return PTR_ERR(handle);
	if (handle) {
		sid = global_sid_handle_sid(handle);
		if (!sid) {
			global_sid_handle_put(handle);
			return -ESTALE;
		}
	}
	spin_lock(&isec->lock);
	old = isec->task_sid_handle;
	isec->task_sid_handle = handle;
	isec->task_sid = sid;
	spin_unlock(&isec->lock);
	global_sid_handle_put(old);
	return 0;
}

static int __selinux_inode_security_take_sid_handle(
	struct inode_security_struct *isec,
	struct selinux_global_sid_handle *handle, const u16 *sclass,
	enum selinux_label_source source, enum label_initialized initialized,
	bool pending_only)
{
	struct selinux_global_sid_handle *old_handle, *old_task_handle = NULL;
	struct selinux_label_ref *label, *old_label;
	u32 sid;

	if (!isec || !handle || IS_ERR(handle)) {
		if (!IS_ERR_OR_NULL(handle))
			global_sid_handle_put(handle);
		return IS_ERR(handle) ? PTR_ERR(handle) : -EINVAL;
	}
	sid = global_sid_handle_sid(handle);
	if (!sid) {
		global_sid_handle_put(handle);
		return -ESTALE;
	}
	label = global_sid_handle_label_get(handle);
	if (!label) {
		global_sid_handle_put(handle);
		return -ESTALE;
	}

	spin_lock(&isec->lock);
	if (pending_only && isec->initialized != LABEL_PENDING) {
		spin_unlock(&isec->lock);
		selinux_label_ref_put(label);
		global_sid_handle_put(handle);
		return 0;
	}
	old_label = rcu_dereference_protected(
		isec->label_ref, lockdep_is_held(&isec->lock));
	/*
	 * A published pathless projection seals label, source and class for
	 * every policy depth.  Until atomic projected relabel is implemented,
	 * permit only an idempotent re-publication of the exact leaf tuple.
	 */
	if (rcu_access_pointer(isec->pathless) &&
	    (old_label != label || isec->sid != sid ||
	     isec->label_source != source ||
	     (sclass && isec->sclass != *sclass) ||
	     isec->initialized != initialized)) {
		spin_unlock(&isec->lock);
		selinux_label_ref_put(label);
		global_sid_handle_put(handle);
		return -EOPNOTSUPP;
	}
	old_handle = isec->sid_handle;
	rcu_assign_pointer(isec->label_ref, label);
	isec->sid_handle = handle;
	isec->label_source = source;
	isec->sid = sid;
	if (sclass)
		isec->sclass = *sclass;
	isec->initialized = initialized;
	if (initialized == LABEL_INITIALIZED) {
		old_task_handle = isec->task_sid_handle;
		isec->task_sid_handle = NULL;
		isec->task_sid = SECSID_NULL;
	}
	spin_unlock(&isec->lock);

	global_sid_handle_put(old_task_handle);
	global_sid_handle_put(old_handle);
	selinux_label_ref_put(old_label);
	return 0;
}

int selinux_inode_security_take_sid_handle(
	struct inode_security_struct *isec,
	struct selinux_global_sid_handle *handle, const u16 *sclass,
	enum selinux_label_source source, enum label_initialized initialized)
{
	return __selinux_inode_security_take_sid_handle(
		isec, handle, sclass, source, initialized, false);
}

int selinux_inode_security_set_sid(
	struct inode_security_struct *isec, u32 sid, const u16 *sclass,
	enum selinux_label_source source, enum label_initialized initialized)
{
	struct selinux_global_sid_handle *handle;

	handle = global_sid_handle_get(sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	return selinux_inode_security_take_sid_handle(
		isec, handle, sclass, source, initialized);
}
#endif

static int inode_security_set_sid(struct inode_security_struct *isec, u32 sid,
				  enum selinux_label_source source,
				  enum label_initialized initialized)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_inode_security_set_sid(
		isec, sid, NULL, source, initialized);
#else
	spin_lock(&isec->lock);
	isec->sid = sid;
	isec->initialized = initialized;
	spin_unlock(&isec->lock);
	return 0;
#endif
}

static int inode_security_set_sid_class(struct inode_security_struct *isec,
					u32 sid, u16 sclass,
					enum selinux_label_source source,
					enum label_initialized initialized)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_inode_security_set_sid(
		isec, sid, &sclass, source, initialized);
#else
	spin_lock(&isec->lock);
	isec->sid = sid;
	isec->sclass = sclass;
	isec->initialized = initialized;
	spin_unlock(&isec->lock);
	return 0;
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int inode_security_validate_label_class(
	struct inode_security_struct *isec, struct selinux_label_ref *label,
	u32 sid)
{
	struct selinux_label_ref *canonical;
	int rc = 0;

	canonical = global_sid_to_label_ref(sid);
	if (IS_ERR(canonical))
		return PTR_ERR(canonical);
	if (canonical != label)
		rc = -EINVAL;
	selinux_label_ref_put(canonical);
	spin_lock(&isec->lock);
	if (!rc && rcu_access_pointer(isec->pathless))
		rc = -EOPNOTSUPP;
	spin_unlock(&isec->lock);
	return rc;
}

#endif

static void inode_free_security(struct inode *inode)
{
	struct inode_security_struct *isec = selinux_inode(inode);
	struct superblock_security_struct *sbsec;

	if (!isec)
		return;
	sbsec = selinux_superblock(inode->i_sb);
	/*
	 * As not all inode security structures are in a list, we check for
	 * empty list outside of the lock to make sure that we won't waste
	 * time taking a lock doing nothing.
	 *
	 * The list_del_init() function can be safely called more than once.
	 * It should not be possible for this function to be called with
	 * concurrent list_add(), but for better safety against future changes
	 * in the code, we use list_empty_careful() here.
	 */
	if (!list_empty_careful(&isec->list)) {
		spin_lock(&sbsec->isec_lock);
		list_del_init(&isec->list);
		spin_unlock(&sbsec->isec_lock);
	}
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (isec->copy_up) {
		selinux_label_view_put(isec->copy_up->view);
		selinux_label_ref_put(isec->copy_up->label);
		global_sid_handle_put(isec->copy_up->sid_handle);
		kfree(isec->copy_up);
		isec->copy_up = NULL;
	}
	selinux_pathless_projection_put(isec->pathless_context);
	isec->pathless_context = NULL;
	selinux_pathless_projection_put(
		rcu_dereference_protected(isec->pathless, 1));
	RCU_INIT_POINTER(isec->pathless, NULL);
	global_sid_handle_put(isec->task_sid_handle);
	isec->task_sid_handle = NULL;
	global_sid_handle_put(isec->sid_handle);
	isec->sid_handle = NULL;
	selinux_label_ref_put(rcu_dereference_protected(isec->label_ref, 1));
	RCU_INIT_POINTER(isec->label_ref, NULL);
#endif
}

enum selinux_mnt_label_index {
	SELINUX_MNT_LABEL_CONTEXT,
	SELINUX_MNT_LABEL_DEFCONTEXT,
	SELINUX_MNT_LABEL_FSCONTEXT,
	SELINUX_MNT_LABEL_ROOTCONTEXT,
	SELINUX_MNT_LABEL_COUNT,
};

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_mnt_label_opt {
	char *context;
	struct selinux_global_sid_handle *observer_handle;
	struct selinux_global_sid_handle *origin_handle;
	bool input_is_origin;
};
#endif

struct selinux_mnt_opts {
	u32 fscontext_sid;
	u32 context_sid;
	u32 rootcontext_sid;
	u32 defcontext_sid;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct cred *actor;
	struct selinux_ns_control *observer_control;
	struct selinux_state *requested_origin_state;
	struct selinux_label_domain *requested_origin_domain;
	const struct selinux_label_view *requested_observer_view;
	const struct selinux_label_view *view;
	struct selinux_policy_snapshot observer_snapshot;
	struct selinux_policy_snapshot origin_snapshot;
	struct selinux_mnt_label_opt labels[SELINUX_MNT_LABEL_COUNT];
	bool finalized;
#endif
};

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_sb_sid_set_handle(
	u32 *sidp, struct selinux_global_sid_handle **slot,
	struct selinux_global_sid_handle *source);
static int selinux_sb_sid_set_numeric(
	u32 *sidp, struct selinux_global_sid_handle **slot, u32 sid);
#endif

static int selinux_mnt_alloc_security(struct vfsmount *mnt,
				      const struct vfsmount *src_mnt,
				      struct fs_context *fc)
{
	struct mount_security_struct *msec = selinux_mount_security(mnt);
	const struct selinux_label_view *view;

	if (WARN_ON_ONCE(!msec))
		return -EIO;

	if (src_mnt) {
		const struct mount_security_struct *src_msec =
			selinux_mount_security(src_mnt);
		const struct selinux_label_view *src_view;

		/* A clone must never silently invent object provenance. */
		if (!src_msec)
			return -EACCES;
		src_view = smp_load_acquire(&src_msec->view);
		if (!src_view)
			return -EACCES;
		view = selinux_label_view_get(src_view);
	} else {
		struct selinux_state *outer_state;
#ifdef CONFIG_SECURITY_SELINUX_NS
		const struct superblock_security_struct *sbsec;
		const struct selinux_mnt_opts *opts;
#endif

		if (!fc || !fc->cred || !fc->user_ns)
			return -EINVAL;
#ifdef CONFIG_SECURITY_SELINUX_NS
		opts = fc->security;
		if (opts && opts->view) {
			if (!opts->finalized)
				return -ESTALE;
			view = selinux_label_view_get(opts->view);
			goto install;
		}
		sbsec = selinux_superblock(mnt->mnt_sb);
		if (!sbsec || !sbsec->anchor_domain)
			return -EACCES;
#endif
		outer_state = cred_selinux_state(fc->cred);
		if (!outer_state)
			return -EACCES;
#ifdef CONFIG_SECURITY_SELINUX_NS
		view = selinux_identity_view_alloc(
			outer_state->label_domain->owner_userns,
			sbsec->anchor_domain, outer_state->label_domain);
#else
		view = selinux_identity_view_alloc(
			fc->user_ns, outer_state->label_domain,
			outer_state->label_domain);
#endif
	}

	if (IS_ERR(view))
		return PTR_ERR(view);
#ifdef CONFIG_SECURITY_SELINUX_NS
install:
#endif
	WRITE_ONCE(msec->view, view);
	msec->pre_topology_view = NULL;
	msec->topology_applied = false;
	return 0;
}

static void selinux_mnt_free_security(struct vfsmount *mnt)
{
	struct mount_security_struct *msec = selinux_mount_security(mnt);

	if (!msec)
		return;
	selinux_label_view_put(READ_ONCE(msec->view));
	selinux_label_view_put(msec->pre_topology_view);
	WRITE_ONCE(msec->view, NULL);
	msec->pre_topology_view = NULL;
}

struct selinux_mnt_topology_key {
	const struct selinux_label_view *source;
	const struct selinux_label_view *target;
};

struct selinux_mnt_topology_entry {
	struct rhash_head node;
	struct selinux_mnt_topology_key key;
	const struct selinux_label_view *derived;
};

struct selinux_mnt_topology_ctx {
	struct rhashtable views;
};

static const struct rhashtable_params selinux_mnt_topology_ht_params = {
	.head_offset = offsetof(struct selinux_mnt_topology_entry, node),
	.key_offset = offsetof(struct selinux_mnt_topology_entry, key),
	.key_len = sizeof(struct selinux_mnt_topology_key),
	.automatic_shrinking = true,
};

static struct selinux_mnt_topology_ctx **
selinux_mnt_topology_slot(struct security_mnt_topology *topology)
{
	return topology->security + selinux_blob_sizes.lbs_mnt_topology;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static bool
selinux_mnt_views_share_snapshot(const struct selinux_label_view *left,
				 const struct selinux_label_view *right)
{
	u16 i, count = min(left->map_count, right->map_count);

	for (i = 0; i < count; i++) {
		if (left->maps[i] != right->maps[i])
			return false;
	}
	return true;
}
#endif

static int
selinux_mnt_topology_add(struct security_mnt_topology *topology,
			 const struct vfsmount *source,
			 const struct vfsmount *target)
{
	const struct mount_security_struct *source_sec, *target_sec;
	const struct selinux_label_view *source_view, *target_view, *derived;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_label_domain *origin_domain, *outer_domain;
	struct user_namespace *owner_userns;
#endif
	struct selinux_mnt_topology_entry *entry;
	struct selinux_mnt_topology_ctx **slot, *ctx;
	struct selinux_mnt_topology_key key;
	int rc;

	if (!topology || !source || !target)
		return -EINVAL;
	source_sec = selinux_mount_security(source);
	target_sec = selinux_mount_security(target);
	if (!source_sec || !target_sec)
		return -EACCES;
	source_view = smp_load_acquire(&source_sec->view);
	target_view = smp_load_acquire(&target_sec->view);
	if (!source_view || !target_view)
		return -EACCES;
	if ((source_view->flags | target_view->flags) &
	    SELINUX_LABEL_VIEW_ORIGIN_UNRESOLVED)
		return -EOPNOTSUPP;

	key.source = source_view;
	key.target = target_view;
	slot = selinux_mnt_topology_slot(topology);
	ctx = *slot;
	if (!ctx) {
		ctx = kzalloc_obj(*ctx, GFP_KERNEL_ACCOUNT);
		if (!ctx)
			return -ENOMEM;
		rc = rhashtable_init(&ctx->views,
				     &selinux_mnt_topology_ht_params);
		if (rc) {
			kfree(ctx);
			return rc;
		}
		*slot = ctx;
	}

	entry = rhashtable_lookup_fast(&ctx->views, &key,
				       selinux_mnt_topology_ht_params);
	if (entry)
		return 0;

	if (source_view->outer_domain == target_view->outer_domain) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		if (!selinux_mnt_views_share_snapshot(source_view, target_view))
			return -ESTALE;
#endif
		derived = selinux_label_view_get(source_view);
	} else {
#ifndef CONFIG_SECURITY_SELINUX_NS
		return -EOPNOTSUPP;
#else
		owner_userns = target_view->owner_userns;
		origin_domain = source_view->origin_domain;
		outer_domain = target_view->outer_domain;
		derived = selinux_identity_view_alloc(owner_userns, origin_domain,
						     outer_domain);
		if (IS_ERR(derived))
			return PTR_ERR(derived);
		/*
		 * A topology operation composes two already-published views.  Do
		 * not silently cross a boundary whose map was replaced after either
		 * endpoint was created; the caller can retry with fresh mounts.
		 */
		if (!selinux_mnt_views_share_snapshot(source_view, derived) ||
		    !selinux_mnt_views_share_snapshot(target_view, derived)) {
			selinux_label_view_put(derived);
			return -ESTALE;
		}
#endif
	}

	entry = kzalloc_obj(*entry, GFP_KERNEL_ACCOUNT);
	if (!entry) {
		selinux_label_view_put(derived);
		return -ENOMEM;
	}
	entry->key = key;
	entry->derived = derived;
	rc = rhashtable_insert_fast(&ctx->views, &entry->node,
				    selinux_mnt_topology_ht_params);
	if (rc) {
		selinux_label_view_put(derived);
		kfree(entry);
	}
	return rc;
}

static int
selinux_mnt_topology_apply(struct security_mnt_topology *topology,
			   struct vfsmount *mnt,
			   const struct vfsmount *target)
{
	struct mount_security_struct *mnt_sec;
	const struct mount_security_struct *target_sec;
	const struct selinux_label_view *old;
	struct selinux_mnt_topology_entry *entry;
	struct selinux_mnt_topology_ctx *ctx;
	struct selinux_mnt_topology_key key;

	if (!topology || !mnt || !target)
		return -EINVAL;
	mnt_sec = selinux_mount_security(mnt);
	target_sec = selinux_mount_security(target);
	if (!mnt_sec || !target_sec || !READ_ONCE(mnt_sec->view) ||
	    !READ_ONCE(target_sec->view))
		return -EACCES;
	ctx = *selinux_mnt_topology_slot(topology);
	if (!ctx)
		return -EACCES;
	key.source = READ_ONCE(mnt_sec->view);
	key.target = READ_ONCE(target_sec->view);
	entry = rhashtable_lookup_fast(&ctx->views, &key,
				       selinux_mnt_topology_ht_params);
	if (!entry)
		return -ESTALE;

	old = READ_ONCE(mnt_sec->view);
	if (old == entry->derived)
		return 0;
	if (mnt_sec->topology_applied)
		return -ESTALE;

	/*
	 * The VFS guarantees that topology apply targets an unpublished clone.
	 * Keep the old reference as a constant-size safety pin and publish the
	 * derived immutable view exactly once.
	 */
	mnt_sec->pre_topology_view = old;
	smp_store_release(&mnt_sec->view,
			  selinux_label_view_get(entry->derived));
	mnt_sec->topology_applied = true;
	return 0;
}

static void selinux_mnt_topology_entry_free(void *ptr, void *arg)
{
	struct selinux_mnt_topology_entry *entry = ptr;

	selinux_label_view_put(entry->derived);
	kfree(entry);
}

static void
selinux_mnt_topology_free(struct security_mnt_topology *topology)
{
	struct selinux_mnt_topology_ctx **slot =
		selinux_mnt_topology_slot(topology);
	struct selinux_mnt_topology_ctx *ctx = *slot;

	if (!ctx)
		return;
	rhashtable_free_and_destroy(&ctx->views,
				    selinux_mnt_topology_entry_free, NULL);
	kfree(ctx);
	*slot = NULL;
}

static void selinux_free_mnt_opts(void *mnt_opts)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_mnt_opts *opts = mnt_opts;
	int i;

	if (opts) {
		for (i = 0; i < SELINUX_MNT_LABEL_COUNT; i++) {
			global_sid_handle_put(opts->labels[i].origin_handle);
			global_sid_handle_put(opts->labels[i].observer_handle);
			kfree(opts->labels[i].context);
		}
		selinux_label_view_put(opts->view);
		selinux_label_view_put(opts->requested_observer_view);
		put_selinux_state(opts->requested_origin_state);
		selinux_label_domain_put(opts->requested_origin_domain);
		selinux_ns_control_put(opts->observer_control);
		if (opts->actor)
			put_cred(opts->actor);
	}
#endif
	kfree(mnt_opts);
}

enum {
	Opt_error = -1,
	Opt_context = 0,
	Opt_defcontext = 1,
	Opt_fscontext = 2,
	Opt_rootcontext = 3,
	Opt_seclabel = 4,
#ifdef CONFIG_SECURITY_SELINUX_NS
	Opt_selinuxns_fd = 5,
#endif
};

#define A(s, has_arg) {#s, sizeof(#s) - 1, Opt_##s, has_arg}
static const struct {
	const char *name;
	int len;
	int opt;
	bool has_arg;
} tokens[] = {
	A(context, true),
	A(fscontext, true),
	A(defcontext, true),
	A(rootcontext, true),
	A(seclabel, false),
};
#undef A

static int match_opt_prefix(char *s, int l, char **arg)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tokens); i++) {
		size_t len = tokens[i].len;
		if (len > l || memcmp(s, tokens[i].name, len))
			continue;
		if (tokens[i].has_arg) {
			if (len == l || s[len] != '=')
				continue;
			*arg = s + len + 1;
		} else if (len != l)
			continue;
		return tokens[i].opt;
	}
	return Opt_error;
}

#define SEL_MOUNT_FAIL_MSG "SELinux:  duplicate or incompatible mount options\n"

#define SELINUX_POLICY_OPERATION_RETRIES 3

struct selinux_policy_chain_snapshot {
	const struct cred *cred[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct selinux_policy_snapshot policy[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	u16 count;
};

#ifdef CONFIG_SECURITY_SELINUX_NS
#define SELINUX_FILE_TRANSFER_CHECKS_PER_POLICY 4
#define SELINUX_FILE_TRANSFER_MAX_CHECKS \
	(SELINUX_FILE_TRANSFER_CHECKS_PER_POLICY * \
	 (SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1))

static_assert(SELINUX_FILE_TRANSFER_MAX_CHECKS <=
	      SELINUX_AVC_TRANSACTION_MAX_CHECKS);

struct selinux_file_transfer_transaction {
	struct selinux_policy_chain_snapshot chain;
	struct selinux_avc_level levels[SELINUX_FILE_TRANSFER_MAX_CHECKS];
	struct selinux_policy_snapshot snapshots[
		SELINUX_FILE_TRANSFER_MAX_CHECKS];
	struct selinux_avc_provenance provenance[
		SELINUX_FILE_TRANSFER_CHECKS_PER_POLICY];
	struct selinux_avc_provenance level_provenance[
		SELINUX_FILE_TRANSFER_MAX_CHECKS];
	struct selinux_pathless_chain_resolution pathless_line;
	struct selinux_pathless_chain_resolution bpf_line;
	struct selinux_pathless_chain_resolution perf_line;
	struct selinux_label_operation_resolution path_line;
	struct selinux_label_operation_resolution opener_line;
	u16 count;
	u8 provenance_count;
};

struct selinux_file_operation_check {
	u32 requested;
	u16 tclass;
	u16 skip_policycap;
	u8 decision_kind;
	u8 driver;
	u8 base_perm;
	u8 xperm;
};

static int selinux_file_transfer_transaction_add(
	struct selinux_file_transfer_transaction *transaction,
	const struct selinux_avc_level *level,
	const struct selinux_policy_snapshot *snapshot)
{
	u16 next;

	if (check_add_overflow(transaction->count, (u16)1, &next) ||
	    next > ARRAY_SIZE(transaction->levels))
		return -E2BIG;
	transaction->levels[transaction->count] = *level;
	if (level->provenance) {
		transaction->level_provenance[transaction->count] =
			*level->provenance;
		transaction->levels[transaction->count].provenance =
			&transaction->level_provenance[transaction->count];
	}
	transaction->snapshots[transaction->count] = *snapshot;
	transaction->count = next;
	return 0;
}

static int selinux_file_transfer_transaction_provenance(
	struct selinux_file_transfer_transaction *transaction,
	const struct selinux_label_ref *label,
	const struct selinux_label_view *view, u8 source,
	const struct selinux_avc_provenance **provenance)
{
	struct selinux_avc_provenance *slot;

	if (!label || !view || !provenance ||
	    transaction->provenance_count >=
		SELINUX_FILE_TRANSFER_CHECKS_PER_POLICY)
		return -E2BIG;
	slot = &transaction->provenance[transaction->provenance_count++];
	*slot = (struct selinux_avc_provenance) {
		.label = label,
		.view = view,
		.source = source,
	};
	*provenance = slot;
	return 0;
}

struct selinux_label_avc_scratch {
	struct selinux_policy_chain_snapshot chain;
	struct selinux_label_operation_resolution operation;
	struct selinux_avc_level
		levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct selinux_avc_provenance
		provenance[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
};

#define SELINUX_CREATE_AVC_CHECKS 3
struct selinux_inode_create_plan {
	struct security_inode_create_plan *generic;
	struct selinux_inode_create_plan *previous;
	const struct cred *actor;
	struct task_struct *owner_task;
	struct task_security_struct *owner_tsec;
	const struct selinux_label_view *view;
	struct selinux_label_ref *dir_label;
	struct selinux_label_ref *sb_label;
	struct selinux_label_ref *anchor_label;
	struct selinux_global_sid_handle *anchor_handle;
	struct selinux_global_sid_handle *mntpoint_handle;
	struct selinux_global_sid_handle *object_handles[
		SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct selinux_label_domain *anchor_domain;
	struct selinux_state *anchor_state;
	struct dentry *dentry;
	struct inode *dir;
	struct inode *inode;
	struct super_block *sb;
	struct selinux_policy_chain_snapshot chain;
	struct selinux_label_resolution dir_resolution;
	struct selinux_label_resolution sb_resolution;
	struct selinux_label_resolution object_resolution;
	struct selinux_avc_provenance provenance[SELINUX_CREATE_AVC_CHECKS];
	struct qstr name;
	void *xattr_value;
	size_t xattr_value_len;
	u32 anchor_sid;
	u16 tclass;
	u8 source;
	bool requires_commit;
	bool requires_xattr;
	bool xattr_prepared;
	bool committed;
	bool poisoned;
};

#define SELINUX_SETXATTR_AVC_CHECKS 4

struct selinux_inode_relabel_marker {
	struct rhash_head node;
	struct rcu_head rcu;
	struct inode *inode;
	struct task_struct *owner_task;
	struct task_security_struct *owner_tsec;
	const struct selinux_label_view *view;
	struct selinux_state *anchor_state;
	struct selinux_label_domain *anchor_domain;
	u64 cookie;
};

static struct rhashtable selinux_inode_relabel_markers;
static atomic64_t selinux_inode_relabel_cookie = ATOMIC64_INIT(0);

static const struct rhashtable_params selinux_inode_relabel_marker_params = {
	.head_offset = offsetof(struct selinux_inode_relabel_marker, node),
	.key_offset = offsetof(struct selinux_inode_relabel_marker, inode),
	.key_len = sizeof(struct inode *),
	.automatic_shrinking = true,
};

struct selinux_inode_setxattr_plan {
	struct security_inode_setxattr_plan *generic;
	struct selinux_inode_setxattr_plan *previous;
	struct selinux_inode_relabel_marker *marker;
	const struct cred *actor;
	struct task_struct *owner_task;
	struct task_security_struct *owner_tsec;
	const struct selinux_label_view *view;
	struct selinux_label_ref *old_label;
	struct selinux_label_ref *new_label;
	struct selinux_label_ref *sb_label;
	struct selinux_label_ref *anchor_label;
	struct selinux_global_sid_handle *old_handle;
	struct selinux_global_sid_handle *new_handle;
	struct selinux_global_sid_handle *anchor_handle;
	struct selinux_label_domain *anchor_domain;
	struct selinux_state *anchor_state;
	struct selinux_policy_chain_snapshot chain;
	struct selinux_label_resolution old_resolution;
	struct selinux_label_resolution new_resolution;
	struct selinux_label_resolution sb_resolution;
	struct selinux_avc_provenance provenance[SELINUX_SETXATTR_AVC_CHECKS];
	struct inode *inode;
	void *xattr_value;
	size_t xattr_value_len;
	u64 relabel_cookie;
	u32 old_sid;
	u32 anchor_sid;
	u16 sclass;
	u8 old_source;
	int flags;
	int commit_rc;
	bool committed;
	bool deferred_revalidation;
	bool poisoned;
	bool forced_context;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	bool rebind_fail_kunit;
#endif
};

static bool selinux_inode_relabel_in_progress(struct inode *inode);
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
static int cred_sid_identity_has_perm(const struct cred *cred, u32 sid,
				      u16 tclass, u32 requested,
				      struct common_audit_data *ad)
{
	const struct cred_security_struct *leaf = selinux_cred(cred);
	const struct selinux_label_view *view;
	struct selinux_label_domain *origin;
	struct selinux_label_ref *label;
	int rc;

	label = global_sid_to_label_ref(sid);
	if (IS_ERR(label))
		return PTR_ERR(label);
	origin = label->domain->flags & SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL ?
		 leaf->state->label_domain : label->domain;
	view = selinux_identity_view_alloc_gfp(
		leaf->state->label_domain->owner_userns, origin,
		leaf->state->label_domain, GFP_KERNEL);
	if (IS_ERR(view)) {
		rc = PTR_ERR(view);
		goto out_label;
	}
	rc = cred_label_has_perm(cred, sid, label, view, tclass, requested, ad);
	selinux_label_view_put(view);
out_label:
	selinux_label_ref_put(label);
	return rc;
}

static bool selinux_policy_chain_snapshot_valid(
	const struct selinux_policy_chain_snapshot *chain);
static int selinux_policy_chain_snapshot_read(
	const struct cred *cred, struct selinux_policy_chain_snapshot *chain);
static int selinux_mnt_control_authorize_stable(
	struct selinux_ns_control *control, const struct cred *cred);

static int cred_sid_identity_relation_has_perm(
	const struct cred *cred, u32 ssid, u32 tsid, u16 tclass, u32 requested,
	struct common_audit_data *ad)
{
	struct selinux_sid_relation_scratch {
		struct selinux_label_resolution source;
		struct selinux_label_resolution target;
		struct selinux_avc_level
			levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	} *scratch;
	const struct cred_security_struct *leaf = selinux_cred(cred);
	const struct selinux_label_view *sview = NULL, *tview = NULL;
	struct selinux_label_ref *slabel = NULL, *tlabel = NULL;
	struct selinux_avc_provenance provenance;
	struct selinux_label_domain *origin;
	u16 count = 0;
	int rc;

	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	slabel = global_sid_to_label_ref(ssid);
	if (IS_ERR(slabel)) {
		rc = PTR_ERR(slabel);
		slabel = NULL;
		goto out;
	}
	tlabel = global_sid_to_label_ref(tsid);
	if (IS_ERR(tlabel)) {
		rc = PTR_ERR(tlabel);
		tlabel = NULL;
		goto out;
	}
	origin = slabel->domain->flags & SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL ?
		 leaf->state->label_domain : slabel->domain;
	sview = selinux_identity_view_alloc_gfp(
		leaf->state->label_domain->owner_userns, origin,
		leaf->state->label_domain, GFP_KERNEL);
	if (IS_ERR(sview)) {
		rc = PTR_ERR(sview);
		sview = NULL;
		goto out;
	}
	origin = tlabel->domain->flags & SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL ?
		 leaf->state->label_domain : tlabel->domain;
	tview = selinux_identity_view_alloc_gfp(
		leaf->state->label_domain->owner_userns, origin,
		leaf->state->label_domain, GFP_KERNEL);
	if (IS_ERR(tview)) {
		rc = PTR_ERR(tview);
		tview = NULL;
		goto out;
	}
	rc = selinux_label_view_resolve_chain(
		sview, slabel, ssid, &scratch->source);
	if (rc)
		goto out;
	rc = selinux_label_view_resolve_chain(
		tview, tlabel, tsid, &scratch->target);
	if (rc)
		goto out;
	provenance = (struct selinux_avc_provenance) {
		.label = tlabel,
		.view = tview,
		.source = SELINUX_LABEL_SOURCE_SECURITY_CONTEXT,
	};
	while (cred) {
		const struct cred_security_struct *crsec = selinux_cred(cred);
		const struct selinux_label_domain *domain =
			crsec->state->label_domain;
		u16 depth;

		if (!domain || count >= ARRAY_SIZE(scratch->levels)) {
			rc = -E2BIG;
			goto out;
		}
		depth = domain->depth;
		if (depth > scratch->source.max_depth ||
		    depth > scratch->target.max_depth ||
		    scratch->source.domain_id[depth] != domain->id ||
		    scratch->target.domain_id[depth] != domain->id ||
		    !scratch->source.sid[depth] || !scratch->target.sid[depth]) {
			rc = -EOPNOTSUPP;
			goto out;
		}
		scratch->levels[count] = (struct selinux_avc_level) {
			.state = crsec->state,
			.ssid = scratch->source.sid[depth],
			.tsid = scratch->target.sid[depth],
			.requested = requested,
			.tclass = tclass,
			.provenance = &provenance,
		};
		count++;
		cred = crsec->parent_cred;
	}
	rc = selinux_avc_levels_has_perm(scratch->levels, count, ad);
out:
	selinux_label_view_put(tview);
	selinux_label_view_put(sview);
	selinux_label_ref_put(tlabel);
	selinux_label_ref_put(slabel);
	kfree(scratch);
	return rc;
}

static noinline int cred_label_has_perm_policycap(
	const struct cred *cred, u32 tsid, const struct selinux_label_ref *label,
	const struct selinux_label_view *view, u16 tclass, u32 requested,
	u32 policycap_requested, u16 policycap, u8 source,
	struct common_audit_data *ad)
{
	struct selinux_avc_transaction_workspace *workspace;
	struct selinux_label_avc_scratch *scratch __free(kfree) = NULL;
	unsigned int retry;
	int rc = -ESTALE;

	if (!label || !view)
		return -EOPNOTSUPP;
	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1, GFP_KERNEL);
	if (!workspace)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;

		rc = selinux_policy_chain_snapshot_read(cred, &scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_label_view_resolve_operation(
			view, label, tsid,
			selinux_cred(scratch->chain.cred[0])->state->label_domain,
			&scratch->operation);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		for (i = 0; i < scratch->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(scratch->chain.cred[i]);
			const struct selinux_label_domain *domain =
				crsec->state->label_domain;
			u16 depth = domain->depth;

			if (depth > scratch->operation.labels.max_depth ||
			    scratch->operation.labels.domain_id[depth] != domain->id ||
			    !scratch->operation.labels.sid[depth]) {
				rc = -EOPNOTSUPP;
				break;
			}
			scratch->provenance[i] = (struct selinux_avc_provenance) {
				.label = label,
				.view = view,
				.map_generation =
					scratch->operation.map_generation[depth],
				.source = source,
			};
			scratch->levels[i] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = scratch->operation.labels.sid[depth],
				.requested = requested,
				.policycap_requested = policycap_requested,
				.tclass = tclass,
				.policycap = policycap,
				.provenance = &scratch->provenance[i],
			};
		}
		if (!rc)
			rc = selinux_avc_transaction_has_perm_workspace(
				scratch->levels, scratch->chain.policy,
				scratch->chain.count, ad, workspace);
		if (rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(&scratch->chain)) {
			rc = -ESTALE;
			selinux_label_operation_resolution_put(&scratch->operation);
			continue;
		}
		selinux_label_operation_resolution_put(&scratch->operation);
		break;
	}
	selinux_label_operation_resolution_put(&scratch->operation);
	selinux_avc_transaction_workspace_free(workspace);
	return rc;
}

static noinline int cred_pathless_has_perm_policycap(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection, u32 requested,
	u32 policycap_requested, u16 policycap, struct common_audit_data *ad)
{
	struct selinux_avc_transaction_workspace *workspace;
	struct {
		struct selinux_policy_chain_snapshot chain;
		struct selinux_pathless_chain_resolution line;
		struct selinux_avc_level levels[
			SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
		struct selinux_avc_provenance provenance[
			SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	} *scratch;
	unsigned int retry;
	int rc = -ESTALE;

	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1, GFP_KERNEL);
	if (!workspace) {
		kfree(scratch);
		return -ENOMEM;
	}
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;

		rc = selinux_policy_chain_snapshot_read(cred, &scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_pathless_projection_resolve_cred_chain(
			projection, scratch->chain.cred, scratch->chain.policy,
			scratch->chain.count, &scratch->line);
		if (rc)
			break;
		for (i = 0; i < scratch->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(scratch->chain.cred[i]);
			struct selinux_pathless_resolution resolved =
				scratch->line.level[
					crsec->state->label_domain->depth];

			scratch->provenance[i] = (struct selinux_avc_provenance) {
				.label = projection->label,
				.view = projection->view,
				.map_generation = resolved.map_generation,
				.source = projection->source,
			};
			scratch->levels[i] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = resolved.sid,
				.requested = requested,
				.policycap_requested = policycap_requested,
				.tclass = resolved.sclass,
				.policycap = policycap,
				.provenance = &scratch->provenance[i],
			};
		}
		rc = selinux_avc_transaction_has_perm_workspace(
			scratch->levels, scratch->chain.policy,
			scratch->chain.count, ad, workspace);
		if (rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(&scratch->chain)) {
			rc = -ESTALE;
			selinux_pathless_chain_resolution_put(&scratch->line);
			continue;
		}
		selinux_pathless_chain_resolution_put(&scratch->line);
		break;
	}
	selinux_pathless_chain_resolution_put(&scratch->line);
	selinux_avc_transaction_workspace_free(workspace);
	kfree(scratch);
	return rc;
}

static noinline int selinux_pathless_create_has_perm(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection,
	struct common_audit_data *ad)
{
	struct selinux_avc_level
		levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	struct selinux_avc_provenance provenance = {
		.label = projection->label,
		.view = projection->view,
		.source = projection->source,
	};
	u16 count = 0;

	while (cred) {
		const struct cred_security_struct *crsec = selinux_cred(cred);
		struct selinux_pathless_resolution resolved;
		int rc;

		if (count >= ARRAY_SIZE(levels))
			return -E2BIG;
		rc = selinux_pathless_projection_resolve_sealed(
			projection, crsec->state->label_domain, &resolved);
		if (rc)
			return rc;
		levels[count] = (struct selinux_avc_level) {
			.state = crsec->state,
			.ssid = crsec->sid,
			.tsid = resolved.sid,
			.requested = resolved.model ==
				SELINUX_PATHLESS_MODEL_LEGACY ? 0 : FILE__CREATE,
			.tclass = resolved.sclass,
			.provenance = &provenance,
		};
		count++;
		cred = crsec->parent_cred;
	}
	return selinux_avc_levels_has_perm(levels, count, ad);
}
#endif

static int may_context_mount_sb_relabel(u32 sid,
			struct superblock_security_struct *sbsec,
			const struct cred *cred)
{
	int rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = cred_sid_identity_has_perm(
		cred, sbsec->sid, SECCLASS_FILESYSTEM,
		FILESYSTEM__RELABELFROM, NULL);
#else
	rc = cred_tsid_has_perm(cred, sbsec->sid, SECCLASS_FILESYSTEM,
				FILESYSTEM__RELABELFROM, NULL);
#endif
	if (rc)
		return rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = cred_sid_identity_has_perm(
		cred, sid, SECCLASS_FILESYSTEM, FILESYSTEM__RELABELTO, NULL);
#else
	rc = cred_tsid_has_perm(cred, sid, SECCLASS_FILESYSTEM,
				FILESYSTEM__RELABELTO, NULL);
#endif
	return rc;
}

static int may_context_mount_inode_relabel(u32 sid,
			struct superblock_security_struct *sbsec,
			const struct cred *cred)
{
	int rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = cred_sid_identity_has_perm(
		cred, sbsec->sid, SECCLASS_FILESYSTEM,
		FILESYSTEM__RELABELFROM, NULL);
#else
	rc = cred_tsid_has_perm(cred, sbsec->sid, SECCLASS_FILESYSTEM,
				FILESYSTEM__RELABELFROM, NULL);
#endif
	if (rc)
		return rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
	/* Both object identities must be interpreted through the same chain. */
	return cred_sid_identity_relation_has_perm(
		cred, sid, sbsec->sid, SECCLASS_FILESYSTEM,
		FILESYSTEM__ASSOCIATE, NULL);
#else
	return cred_obj_has_perm(cred, sid, sbsec->sid, SECCLASS_FILESYSTEM,
				 FILESYSTEM__ASSOCIATE, NULL);
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_mnt_observer_relabel(
	struct selinux_mnt_opts *opts, enum selinux_mnt_label_index index,
	struct superblock_security_struct *sbsec, const struct cred *cred,
	bool superblock_relabel)
{
	struct selinux_ns_control *control;
	struct selinux_label_ref *old_label;
	struct selinux_state *parent, *target;
	u32 actor_sid, old_sid, new_sid;
	int first_rc, second_rc, rc;

	if (!opts || !opts->observer_control)
		return 0;
	if (!opts->finalized || !opts->view ||
	    index >= SELINUX_MNT_LABEL_COUNT ||
	    !opts->labels[index].observer_handle)
		return -ESTALE;
	control = opts->observer_control;
	parent = cred_selinux_state(cred);
	target = control->state;
	if (!parent || target->parent != parent ||
	    opts->view->origin_domain != sbsec->anchor_domain ||
	    opts->view->outer_domain != target->label_domain)
		return -EXDEV;

	mutex_lock(&parent->policy_mutex);
	mutex_lock_nested(&target->policy_mutex, SINGLE_DEPTH_NESTING);
	rc = selinux_ns_control_resolve_join(
		control, parent, selinux_cred(cred)->sid, &actor_sid);
	mutex_unlock(&target->policy_mutex);
	mutex_unlock(&parent->policy_mutex);
	if (rc)
		return rc;

	old_label = global_sid_to_label_ref(sbsec->sid);
	if (IS_ERR(old_label))
		return PTR_ERR(old_label);
	rc = selinux_label_view_resolve(opts->view, target->label_domain,
					old_label, sbsec->sid, &old_sid);
	selinux_label_ref_put(old_label);
	if (rc)
		return rc;
	new_sid = global_sid_handle_sid(opts->labels[index].observer_handle);
	if (!new_sid)
		return -ESTALE;

	first_rc = avc_has_perm(target, actor_sid, old_sid,
				SECCLASS_FILESYSTEM, FILESYSTEM__RELABELFROM,
				NULL);
	if (superblock_relabel)
		second_rc = avc_has_perm(target, actor_sid, new_sid,
					 SECCLASS_FILESYSTEM,
					 FILESYSTEM__RELABELTO, NULL);
	else
		second_rc = avc_has_perm(target, new_sid, old_sid,
					 SECCLASS_FILESYSTEM,
					 FILESYSTEM__ASSOCIATE, NULL);
	return first_rc ?: second_rc;
}

static int selinux_may_context_mount_sb_relabel(
	struct selinux_mnt_opts *opts, enum selinux_mnt_label_index index,
	u32 sid, struct superblock_security_struct *sbsec, const struct cred *cred)
{
	int observer_rc;
	int parent_rc;

	parent_rc = may_context_mount_sb_relabel(sid, sbsec, cred);
	observer_rc = selinux_mnt_observer_relabel(opts, index, sbsec, cred,
						  true);
	return parent_rc ?: observer_rc;
}

static int selinux_may_context_mount_inode_relabel(
	struct selinux_mnt_opts *opts, enum selinux_mnt_label_index index,
	u32 sid, struct superblock_security_struct *sbsec, const struct cred *cred)
{
	int observer_rc;
	int parent_rc;

	parent_rc = may_context_mount_inode_relabel(sid, sbsec, cred);
	observer_rc = selinux_mnt_observer_relabel(opts, index, sbsec, cred,
						  false);
	return parent_rc ?: observer_rc;
}
#endif /* CONFIG_SECURITY_SELINUX_NS */

static int selinux_is_genfs_special_handling(struct super_block *sb,
					      struct selinux_state *state)
{
	/* Special handling. Genfs but also in-core setxattr handler */
	return	!strcmp(sb->s_type->name, "sysfs") ||
		!strcmp(sb->s_type->name, "pstore") ||
		!strcmp(sb->s_type->name, "debugfs") ||
		!strcmp(sb->s_type->name, "tracefs") ||
		!strcmp(sb->s_type->name, "rootfs") ||
		(state && selinux_policycap_cgroupseclabel(state) &&
		 (!strcmp(sb->s_type->name, "cgroup") ||
		  !strcmp(sb->s_type->name, "cgroup2"))) ||
		(state && selinux_policycap_functionfs_seclabel(state) &&
		 !strcmp(sb->s_type->name, "functionfs"));
}

static int selinux_is_sblabel_mnt(struct super_block *sb)
{
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct selinux_state *state;

#ifdef CONFIG_SECURITY_SELINUX_NS
	state = READ_ONCE(sbsec->anchor_state);
#else
	state = current_selinux_state;
#endif

	/*
	 * IMPORTANT: Double-check logic in this function when adding a new
	 * SECURITY_FS_USE_* definition!
	 */
	BUILD_BUG_ON(SECURITY_FS_USE_MAX != 7);

	switch (sbsec->behavior) {
	case SECURITY_FS_USE_XATTR:
	case SECURITY_FS_USE_TRANS:
	case SECURITY_FS_USE_TASK:
	case SECURITY_FS_USE_NATIVE:
		return 1;

	case SECURITY_FS_USE_GENFS:
		return selinux_is_genfs_special_handling(sb, state);

	/* Never allow relabeling on context mounts */
	case SECURITY_FS_USE_MNTPOINT:
	case SECURITY_FS_USE_NONE:
	default:
		return 0;
	}
}

static int sb_check_xattr_support(struct super_block *sb)
{
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct dentry *root = sb->s_root;
	struct inode *root_inode = d_backing_inode(root);
	u32 sid;
	int rc;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *sid_handle;
#endif

	/*
	 * Make sure that the xattr handler exists and that no
	 * error other than -ENODATA is returned by getxattr on
	 * the root directory.  -ENODATA is ok, as this may be
	 * the first boot of the SELinux kernel before we have
	 * assigned xattr values to the filesystem.
	 */
	if (!(root_inode->i_opflags & IOP_XATTR)) {
		pr_warn("SELinux: (dev %s, type %s) has no xattr support\n",
			sb->s_id, sb->s_type->name);
		goto fallback;
	}

	rc = __vfs_getxattr(root, root_inode, XATTR_NAME_SELINUX, NULL, 0);
	if (rc < 0 && rc != -ENODATA) {
		if (rc == -EOPNOTSUPP) {
			pr_warn("SELinux: (dev %s, type %s) has no security xattr handler\n",
				sb->s_id, sb->s_type->name);
			goto fallback;
		} else {
			pr_warn("SELinux: (dev %s, type %s) getxattr errno %d\n",
				sb->s_id, sb->s_type->name, -rc);
			return rc;
		}
	}
	return 0;

fallback:
	/* No xattr support - try to fallback to genfs if possible. */
#ifdef CONFIG_SECURITY_SELINUX_NS
	sid_handle = security_genfs_sid_handle(
		READ_ONCE(sbsec->anchor_state), sb->s_type->name, "/",
		SECCLASS_DIR, &sid);
	rc = IS_ERR(sid_handle) ? PTR_ERR(sid_handle) : 0;
#else
	rc = security_genfs_sid(
		current_selinux_state, sb->s_type->name, "/",
		SECCLASS_DIR, &sid);
#endif
	if (rc)
		return -EOPNOTSUPP;

	pr_warn("SELinux: (dev %s, type %s) falling back to genfs\n",
		sb->s_id, sb->s_type->name);
	sbsec->behavior = SECURITY_FS_USE_GENFS;
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = selinux_sb_sid_set_handle(&sbsec->sid, &sbsec->sid_handle,
				       sid_handle);
	global_sid_handle_put(sid_handle);
	if (rc)
		return rc;
#else
	sbsec->sid = sid;
#endif
	return 0;
}

static int sb_finish_set_opts(struct super_block *sb)
{
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct dentry *root = sb->s_root;
	struct inode *root_inode = d_backing_inode(root);
	int rc = 0;

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (WARN_ON_ONCE(!READ_ONCE(sbsec->anchor_state) ||
			 !READ_ONCE(sbsec->anchor_domain)))
		return -EACCES;
#endif

	if (sbsec->behavior == SECURITY_FS_USE_XATTR) {
		rc = sb_check_xattr_support(sb);
		if (rc)
			return rc;
	}

	sbsec->flags |= SE_SBINITIALIZED;

	/* Initialize the root inode. */
	rc = inode_doinit_with_dentry(root_inode, root);

	/* Initialize any other inodes associated with the superblock, e.g.
	   inodes created prior to initial policy load or inodes created
	   during get_sb by a pseudo filesystem that directly
	   populates itself. */
	spin_lock(&sbsec->isec_lock);
	while (!list_empty(&sbsec->isec_head)) {
		struct inode_security_struct *isec =
				list_first_entry(&sbsec->isec_head,
					   struct inode_security_struct, list);
		struct inode *inode = isec->inode;
		list_del_init(&isec->list);
		spin_unlock(&sbsec->isec_lock);
		inode = igrab(inode);
		if (inode) {
			if (!IS_PRIVATE(inode))
				inode_doinit_with_dentry(inode, NULL);
			iput(inode);
		}
		spin_lock(&sbsec->isec_lock);
	}
	spin_unlock(&sbsec->isec_lock);
	return rc;
}

static int bad_option(struct superblock_security_struct *sbsec, char flag,
		      u32 old_sid, u32 new_sid)
{
	char mnt_flags = sbsec->flags & SE_MNTMASK;

	/* check if the old mount command had the same options */
	if (sbsec->flags & SE_SBINITIALIZED)
		if (!(sbsec->flags & flag) ||
		    (old_sid != new_sid))
			return 1;

	/* check if we were passed the same options twice,
	 * aka someone passed context=a,context=b
	 */
	if (!(sbsec->flags & SE_SBINITIALIZED))
		if (mnt_flags & flag)
			return 1;
	return 0;
}

static int selinux_cred_sid_for_state_checked(
	const struct cred *cred, const struct selinux_state *state, u32 *sid);

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_sb_set_anchor_locked(
	struct superblock_security_struct *sbsec, struct selinux_state *state)
{
	if (!state || !state->label_domain)
		return -EINVAL;
	if (sbsec->anchor_state)
		return sbsec->anchor_state == state &&
		       sbsec->anchor_domain == state->label_domain ? 0 : -EXDEV;

	sbsec->anchor_state = get_selinux_state(state);
	sbsec->anchor_domain = selinux_label_domain_get(state->label_domain);
	return 0;
}
#else
static int selinux_sb_set_anchor_locked(
	struct superblock_security_struct *sbsec, struct selinux_state *state)
{
	return state ? 0 : -EINVAL;
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_sb_sid_set_handle(
	u32 *sidp, struct selinux_global_sid_handle **slot,
	struct selinux_global_sid_handle *source)
{
	struct selinux_global_sid_handle *new_handle, *old_handle;
	u32 sid;

	if (!sidp || !slot || !source || IS_ERR(source))
		return -EINVAL;
	new_handle = global_sid_handle_dup(source);
	if (IS_ERR(new_handle))
		return PTR_ERR(new_handle);
	sid = global_sid_handle_sid(new_handle);
	if (!sid) {
		global_sid_handle_put(new_handle);
		return -ESTALE;
	}
	old_handle = *slot;
	*slot = new_handle;
	*sidp = sid;
	global_sid_handle_put(old_handle);
	return 0;
}

static int selinux_sb_sid_set_numeric(
	u32 *sidp, struct selinux_global_sid_handle **slot, u32 sid)
{
	struct selinux_global_sid_handle *handle, *old_handle;

	handle = global_sid_handle_get(sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	old_handle = *slot;
	*slot = handle;
	*sidp = global_sid_handle_sid(handle);
	global_sid_handle_put(old_handle);
	return 0;
}

#define SELINUX_MNT_POLICY_RETRIES 3

static bool selinux_mnt_opts_has_labels(const struct selinux_mnt_opts *opts)
{
	int i;

	if (!opts)
		return false;
	for (i = 0; i < SELINUX_MNT_LABEL_COUNT; i++)
		if (opts->labels[i].context)
			return true;
	return false;
}

static void selinux_mnt_opts_drop_resolved(struct selinux_mnt_opts *opts)
{
	int i;

	for (i = 0; i < SELINUX_MNT_LABEL_COUNT; i++) {
		global_sid_handle_put(opts->labels[i].origin_handle);
		opts->labels[i].origin_handle = NULL;
		global_sid_handle_put(opts->labels[i].observer_handle);
		opts->labels[i].observer_handle = NULL;
	}
	WARN_ON_ONCE(opts->view && !opts->finalized);
	selinux_label_view_put(opts->view);
	opts->view = NULL;
	memset(&opts->observer_snapshot, 0, sizeof(opts->observer_snapshot));
	memset(&opts->origin_snapshot, 0, sizeof(opts->origin_snapshot));
	opts->fscontext_sid = 0;
	opts->context_sid = 0;
	opts->rootcontext_sid = 0;
	opts->defcontext_sid = 0;
	opts->finalized = false;
}

static void selinux_mnt_opts_set_origin_sid(struct selinux_mnt_opts *opts,
					     int index, u32 sid)
{
	switch (index) {
	case SELINUX_MNT_LABEL_CONTEXT:
		opts->context_sid = sid;
		break;
	case SELINUX_MNT_LABEL_DEFCONTEXT:
		opts->defcontext_sid = sid;
		break;
	case SELINUX_MNT_LABEL_FSCONTEXT:
		opts->fscontext_sid = sid;
		break;
	case SELINUX_MNT_LABEL_ROOTCONTEXT:
		opts->rootcontext_sid = sid;
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

static int selinux_mnt_opts_ensure(struct fs_context *fc,
				   struct selinux_mnt_opts **out)
{
	struct selinux_mnt_opts *opts = fc->security;

	if (!opts) {
		opts = kzalloc_obj(*opts);
		if (!opts)
			return -ENOMEM;
		opts->actor = get_cred(fc->cred);
		fc->security = opts;
	} else if (!opts->actor) {
		opts->actor = get_cred(fc->cred);
	} else if (opts->actor != fc->cred) {
		return -EXDEV;
	}
	*out = opts;
	return 0;
}

static struct selinux_state *
selinux_mnt_opts_observer_state(const struct selinux_mnt_opts *opts)
{
	const struct cred *cred;
	struct selinux_state *state;

	if (opts->observer_control) {
		state = opts->observer_control->state;
		if (opts->requested_observer_view &&
		    opts->requested_observer_view->outer_domain !=
			    state->label_domain)
			return NULL;
		return state;
	}
	if (!opts->requested_observer_view)
		return cred_selinux_state(opts->actor);

	for (cred = opts->actor; cred; cred = selinux_cred(cred)->parent_cred) {
		state = cred_selinux_state(cred);
		if (state && state->label_domain ==
				     opts->requested_observer_view->outer_domain)
			return state;
	}
	return NULL;
}

static int selinux_mnt_opts_finalize_locked(
	struct superblock_security_struct *sbsec, struct selinux_mnt_opts *opts)
{
	struct selinux_global_sid_handle *observer_handles[SELINUX_MNT_LABEL_COUNT];
	struct selinux_global_sid_handle *origin_handles[SELINUX_MNT_LABEL_COUNT];
	const struct selinux_label_view *view = NULL;
	struct selinux_policy_snapshot observer_snapshot, origin_snapshot;
	struct selinux_state *observer, *origin;
	struct selinux_label_ref *label;
	u32 observer_sids[SELINUX_MNT_LABEL_COUNT];
	u32 origin_sids[SELINUX_MNT_LABEL_COUNT];
	u32 validated_sid;
	unsigned int retry;
	int i, rc;

	if (!opts || !opts->actor || !sbsec->anchor_state ||
	    !sbsec->anchor_domain)
		return -EINVAL;
	origin = sbsec->anchor_state;
	observer = selinux_mnt_opts_observer_state(opts);
	if (!observer || !selinux_state_active(observer) ||
	    !selinux_state_active(origin) || !observer->label_domain ||
	    origin->label_domain != sbsec->anchor_domain)
		return -EACCES;
	if (opts->requested_observer_view &&
	    (opts->requested_observer_view->origin_domain !=
		     sbsec->anchor_domain ||
	     opts->requested_observer_view->outer_domain !=
		     observer->label_domain))
		return -EXDEV;
	if (!selinux_initialized(observer) || !selinux_initialized(origin)) {
		if (selinux_mnt_opts_has_labels(opts) || opts->observer_control)
			return -EAGAIN;
		view = selinux_identity_view_alloc(
			observer->label_domain->owner_userns,
			sbsec->anchor_domain, observer->label_domain);
		if (IS_ERR(view))
			return PTR_ERR(view);
		if (opts->requested_observer_view &&
		    !selinux_mnt_views_share_snapshot(
			    opts->requested_observer_view, view)) {
			selinux_label_view_put(view);
			return -ESTALE;
		}
		selinux_mnt_opts_drop_resolved(opts);
		opts->view = view;
		opts->finalized = true;
		return 0;
	}

	if (opts->finalized && opts->view &&
	    opts->view->origin_domain == sbsec->anchor_domain &&
	    opts->view->outer_domain == observer->label_domain &&
	    selinux_policy_snapshot_valid(observer,
					  &opts->observer_snapshot) &&
	    selinux_policy_snapshot_valid(origin, &opts->origin_snapshot))
		return 0;

	for (retry = 0; retry < SELINUX_MNT_POLICY_RETRIES; retry++) {
		memset(observer_handles, 0, sizeof(observer_handles));
		memset(origin_handles, 0, sizeof(origin_handles));
		memset(observer_sids, 0, sizeof(observer_sids));
		memset(origin_sids, 0, sizeof(origin_sids));

		view = selinux_identity_view_alloc(
			observer->label_domain->owner_userns,
			sbsec->anchor_domain, observer->label_domain);
		if (IS_ERR(view))
			return PTR_ERR(view);
		if (opts->requested_observer_view &&
		    !selinux_mnt_views_share_snapshot(
			    opts->requested_observer_view, view)) {
			rc = -ESTALE;
			goto retry_out;
		}
		if (opts->observer_control &&
		    (!observer->depth || observer->depth > view->map_count ||
		     view->maps[observer->depth - 1] !=
			     opts->observer_control->map)) {
			rc = -ESTALE;
			goto retry_out;
		}

		rc = selinux_policy_snapshot_read(observer, &observer_snapshot);
		if (rc)
			goto retry_out;
		if (observer == origin)
			origin_snapshot = observer_snapshot;
		else {
			rc = selinux_policy_snapshot_read(origin, &origin_snapshot);
			if (rc)
				goto retry_out;
		}

		for (i = 0; i < SELINUX_MNT_LABEL_COUNT; i++) {
			if (!opts->labels[i].context)
				continue;
			if (opts->labels[i].input_is_origin) {
				origin_handles[i] =
					security_context_to_global_handle(
						origin, opts->labels[i].context,
						strlen(opts->labels[i].context) + 1,
						&origin_sids[i], GFP_KERNEL);
				if (IS_ERR(origin_handles[i])) {
					rc = PTR_ERR(origin_handles[i]);
					origin_handles[i] = NULL;
					goto retry_out;
				}
				label = global_sid_handle_label_get(origin_handles[i]);
				if (!label || IS_ERR(label)) {
					rc = label ? PTR_ERR(label) : -ESTALE;
					goto retry_out;
				}
				rc = selinux_label_view_resolve(
					view, observer->label_domain, label,
					origin_sids[i], &observer_sids[i]);
				selinux_label_ref_put(label);
				if (rc)
					goto retry_out;
				if (observer == origin &&
				    observer_sids[i] == origin_sids[i]) {
					observer_handles[i] = global_sid_handle_dup(
						origin_handles[i]);
					if (IS_ERR(observer_handles[i])) {
						rc = PTR_ERR(observer_handles[i]);
						observer_handles[i] = NULL;
						goto retry_out;
					}
					continue;
				}
				label = global_sid_to_label_ref(observer_sids[i]);
				if (IS_ERR(label)) {
					rc = PTR_ERR(label);
					goto retry_out;
				}
				observer_handles[i] =
					security_context_to_global_handle(
						observer, label->context,
						label->context_len, &validated_sid,
						GFP_KERNEL);
				selinux_label_ref_put(label);
				if (IS_ERR(observer_handles[i])) {
					rc = PTR_ERR(observer_handles[i]);
					observer_handles[i] = NULL;
					goto retry_out;
				}
				if (validated_sid != observer_sids[i]) {
					rc = -ESTALE;
					goto retry_out;
				}
				continue;
			}

			observer_handles[i] = security_context_to_global_handle(
				observer, opts->labels[i].context,
				strlen(opts->labels[i].context) + 1,
				&observer_sids[i], GFP_KERNEL);
			if (IS_ERR(observer_handles[i])) {
				rc = PTR_ERR(observer_handles[i]);
				observer_handles[i] = NULL;
				goto retry_out;
			}
			label = global_sid_handle_label_get(observer_handles[i]);
			if (!label || IS_ERR(label)) {
				rc = label ? PTR_ERR(label) : -ESTALE;
				goto retry_out;
			}
			rc = selinux_label_view_resolve(
				view, sbsec->anchor_domain, label,
				observer_sids[i], &origin_sids[i]);
			selinux_label_ref_put(label);
			if (rc)
				goto retry_out;
			if (observer == origin &&
			    origin_sids[i] == observer_sids[i]) {
				origin_handles[i] = global_sid_handle_dup(
					observer_handles[i]);
				if (IS_ERR(origin_handles[i])) {
					rc = PTR_ERR(origin_handles[i]);
					origin_handles[i] = NULL;
					goto retry_out;
				}
				continue;
			}

			label = global_sid_to_label_ref(origin_sids[i]);
			if (IS_ERR(label)) {
				rc = PTR_ERR(label);
				goto retry_out;
			}
			origin_handles[i] = security_context_to_global_handle(
				origin, label->context, label->context_len,
				&validated_sid, GFP_KERNEL);
			selinux_label_ref_put(label);
			if (IS_ERR(origin_handles[i])) {
				rc = PTR_ERR(origin_handles[i]);
				origin_handles[i] = NULL;
				goto retry_out;
			}
			if (validated_sid != origin_sids[i]) {
				rc = -ESTALE;
				goto retry_out;
			}
		}

		if (!selinux_policy_snapshot_valid(observer, &observer_snapshot) ||
		    !selinux_policy_snapshot_valid(origin, &origin_snapshot)) {
			rc = -ESTALE;
			goto retry_out;
		}

		selinux_mnt_opts_drop_resolved(opts);
		opts->view = view;
		view = NULL;
		opts->observer_snapshot = observer_snapshot;
		opts->origin_snapshot = origin_snapshot;
		for (i = 0; i < SELINUX_MNT_LABEL_COUNT; i++) {
			opts->labels[i].observer_handle = observer_handles[i];
			opts->labels[i].origin_handle = origin_handles[i];
			selinux_mnt_opts_set_origin_sid(opts, i, origin_sids[i]);
			observer_handles[i] = NULL;
			origin_handles[i] = NULL;
		}
		opts->finalized = true;
		return 0;

retry_out:
		selinux_label_view_put(view);
		view = NULL;
		for (i = 0; i < SELINUX_MNT_LABEL_COUNT; i++) {
			global_sid_handle_put(origin_handles[i]);
			global_sid_handle_put(observer_handles[i]);
		}
		if (rc != -EAGAIN && rc != -ESTALE)
			return rc;
	}
	return -ESTALE;
}

static int selinux_sb_pre_fill(struct super_block *sb, struct fs_context *fc,
			       const void *security_carrier, bool is_new)
{
	const struct kernfs_root_security_struct *rootsec = NULL;
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct selinux_mnt_opts *opts;
	struct selinux_state *origin;
	int rc;

	if (!sbsec || !fc || !fc->cred)
		return -EINVAL;
	rc = selinux_mnt_opts_ensure(fc, &opts);
	if (rc)
		return rc;
	if (opts->observer_control) {
		rc = selinux_mnt_control_authorize_stable(
			opts->observer_control, opts->actor);
		if (rc)
			return rc;
	}

	if (security_carrier) {
		rootsec = selinux_kernfs_root_security(security_carrier);
		if (!rootsec || !rootsec->anchor_state ||
		    !rootsec->anchor_domain ||
		    rootsec->anchor_state->label_domain != rootsec->anchor_domain ||
		    !selinux_state_active(rootsec->anchor_state))
			return -EACCES;
		origin = rootsec->anchor_state;
	} else if (opts->requested_origin_state) {
		if (!opts->requested_origin_domain ||
		    opts->requested_origin_state->label_domain !=
			    opts->requested_origin_domain ||
		    !selinux_state_active(opts->requested_origin_state))
			return -EACCES;
		origin = opts->requested_origin_state;
	} else {
		origin = cred_selinux_state(opts->actor);
		if (!origin || !selinux_state_active(origin))
			return -EACCES;
	}

	mutex_lock(&sbsec->lock);
	if (is_new)
		rc = selinux_sb_set_anchor_locked(sbsec, origin);
	else if (!sbsec->anchor_state || !sbsec->anchor_domain)
		rc = -EACCES;
	else if ((rootsec || opts->requested_origin_state) &&
		 (sbsec->anchor_state != origin ||
		  sbsec->anchor_domain != origin->label_domain))
		rc = -EXDEV;
	else
		rc = 0;
	if (!rc)
		rc = selinux_mnt_opts_finalize_locked(sbsec, opts);
	mutex_unlock(&sbsec->lock);
	return rc;
}
#endif /* CONFIG_SECURITY_SELINUX_NS */

/*
 * Allow filesystems with binary mount data to explicitly set mount point
 * labeling information.
 */
static int selinux_set_mnt_opts(struct super_block *sb,
				void *mnt_opts,
				unsigned long kern_flags,
				unsigned long *set_kern_flags)
{
	const struct cred *cred = current_cred();
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct dentry *root = sb->s_root;
	struct selinux_mnt_opts *opts = mnt_opts;
	struct selinux_state *state;
	struct inode_security_struct *root_isec;
	u32 fscontext_sid = 0, context_sid = 0, rootcontext_sid = 0;
	u32 defcontext_sid = 0;
	u32 actor_sid;
	int rc = 0;
#ifdef CONFIG_SECURITY_SELINUX_NS
	bool has_mnt_opts = selinux_mnt_opts_has_labels(opts);

	if (opts && opts->actor)
		cred = opts->actor;
#endif

	/*
	 * Specifying internal flags without providing a place to
	 * place the results is not allowed
	 */
	if (kern_flags && !set_kern_flags)
		return -EINVAL;

	mutex_lock(&sbsec->lock);

	state = cred_selinux_state(cred);
	if (!state) {
		rc = -EACCES;
		goto out;
	}
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (sbsec->anchor_state) {
		state = sbsec->anchor_state;
		if (opts) {
			rc = selinux_mnt_opts_finalize_locked(sbsec, opts);
			if (rc)
				goto out;
		}
		rc = selinux_cred_sid_for_state_checked(cred, state, &actor_sid);
		if (rc)
			goto out;
	} else {
		rc = selinux_sb_set_anchor_locked(sbsec, state);
		if (rc)
			goto out;
		if (opts) {
			rc = selinux_mnt_opts_finalize_locked(sbsec, opts);
			if (rc)
				goto out;
		}
		actor_sid = selinux_cred(cred)->sid;
	}
#else
	rc = selinux_sb_set_anchor_locked(sbsec, state);
	if (rc)
		goto out;
	actor_sid = selinux_cred(cred)->sid;
#endif
	if (!selinux_initialized(state)) {
		if (!opts
#ifdef CONFIG_SECURITY_SELINUX_NS
		    || !has_mnt_opts
#endif
		) {
			/* Defer initialization until selinux_complete_init,
			   after the initial policy is loaded and the security
			   server is ready to handle calls. */
			if (kern_flags & SECURITY_LSM_NATIVE_LABELS) {
				sbsec->flags |= SE_SBNATIVE;
				*set_kern_flags |= SECURITY_LSM_NATIVE_LABELS;
			}
			goto out;
		}
		rc = -EINVAL;
		pr_warn("SELinux: Unable to set superblock options "
			"before the security server is initialized\n");
		goto out;
	}

	/*
	 * Binary mount data FS will come through this function twice.  Once
	 * from an explicit call and once from the generic calls from the vfs.
	 * Since the generic VFS calls will not contain any security mount data
	 * we need to skip the double mount verification.
	 *
	 * This does open a hole in which we will not notice if the first
	 * mount using this sb set explicit options and a second mount using
	 * this sb does not set any security options.  (The first options
	 * will be used for both mounts)
	 */
	if ((sbsec->flags & SE_SBINITIALIZED) &&
	    (sb->s_type->fs_flags & FS_BINARY_MOUNTDATA) &&
	    (!opts
#ifdef CONFIG_SECURITY_SELINUX_NS
	     || !has_mnt_opts
#endif
	    ))
		goto out;

	root_isec = backing_inode_security_novalidate(root);

	/*
	 * parse the mount options, check if they are valid sids.
	 * also check if someone is trying to mount the same sb more
	 * than once with different security options.
	 */
	if (opts) {
		if (opts->fscontext_sid) {
			fscontext_sid = opts->fscontext_sid;
			if (bad_option(sbsec, FSCONTEXT_MNT, sbsec->sid,
					fscontext_sid))
				goto out_double_mount;
			sbsec->flags |= FSCONTEXT_MNT;
		}
		if (opts->context_sid) {
			context_sid = opts->context_sid;
			if (bad_option(sbsec, CONTEXT_MNT, sbsec->mntpoint_sid,
					context_sid))
				goto out_double_mount;
			sbsec->flags |= CONTEXT_MNT;
		}
		if (opts->rootcontext_sid) {
			rootcontext_sid = opts->rootcontext_sid;
			if (bad_option(sbsec, ROOTCONTEXT_MNT, root_isec->sid,
					rootcontext_sid))
				goto out_double_mount;
			sbsec->flags |= ROOTCONTEXT_MNT;
		}
		if (opts->defcontext_sid) {
			defcontext_sid = opts->defcontext_sid;
			if (bad_option(sbsec, DEFCONTEXT_MNT, sbsec->def_sid,
					defcontext_sid))
				goto out_double_mount;
			sbsec->flags |= DEFCONTEXT_MNT;
		}
	}

	if (sbsec->flags & SE_SBINITIALIZED) {
		/* previously mounted with options, but not on this attempt? */
		if ((sbsec->flags & SE_MNTMASK) &&
		    (!opts
#ifdef CONFIG_SECURITY_SELINUX_NS
		     || !has_mnt_opts
#endif
		    ))
			goto out_double_mount;
		rc = 0;
		goto out;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = selinux_sb_sid_set_numeric(&sbsec->creator_sid,
					&sbsec->creator_sid_handle, actor_sid);
	if (rc)
		goto out;
#else
	sbsec->creator_sid = actor_sid;
#endif

	if (strcmp(sb->s_type->name, "proc") == 0)
		sbsec->flags |= SE_SBPROC | SE_SBGENFS;

	if (!strcmp(sb->s_type->name, "debugfs") ||
	    !strcmp(sb->s_type->name, "tracefs") ||
	    !strcmp(sb->s_type->name, "binder") ||
	    !strcmp(sb->s_type->name, "bpf") ||
	    !strcmp(sb->s_type->name, "pstore") ||
	    !strcmp(sb->s_type->name, "securityfs") ||
	    (selinux_policycap_functionfs_seclabel(state) &&
	     !strcmp(sb->s_type->name, "functionfs")))
		sbsec->flags |= SE_SBGENFS;

	if (!strcmp(sb->s_type->name, "sysfs") ||
	    !strcmp(sb->s_type->name, "cgroup") ||
	    !strcmp(sb->s_type->name, "cgroup2"))
		sbsec->flags |= SE_SBGENFS;

	if (!sbsec->behavior) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		struct selinux_global_sid_handle *fs_handle;
#endif

		/*
		 * Determine the labeling behavior to use for this
		 * filesystem type.
		 */
#ifdef CONFIG_SECURITY_SELINUX_NS
		fs_handle = security_fs_use_handle(
			state, sb->s_type->name, &sbsec->behavior, &sbsec->sid);
		rc = IS_ERR(fs_handle) ? PTR_ERR(fs_handle) : 0;
#else
		rc = security_fs_use(state, sb->s_type->name,
				     &sbsec->behavior, &sbsec->sid);
#endif
		if (rc) {
			pr_warn("%s: security_fs_use(%s) returned %d\n",
					__func__, sb->s_type->name, rc);
			goto out;
		}
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = selinux_sb_sid_set_handle(&sbsec->sid,
					 &sbsec->sid_handle, fs_handle);
		global_sid_handle_put(fs_handle);
		if (rc)
			goto out;
#endif
	}

	/*
	 * If this is a user namespace mount and the filesystem type is not
	 * explicitly whitelisted, then no contexts are allowed on the command
	 * line.  Ignore filesystem labels unless both the SELinux state and the
	 * superblock are private to the caller's namespace.  A child SELinux
	 * namespace may safely interpret labels from its own superblocks without
	 * allowing an ordinary user namespace to inject labels into the host
	 * policy.
	 */
	if (sb->s_user_ns != &init_user_ns &&
	    strcmp(sb->s_type->name, "tmpfs") &&
	    strcmp(sb->s_type->name, "ramfs") &&
	    strcmp(sb->s_type->name, "devpts") &&
	    strcmp(sb->s_type->name, "overlay")) {
		if (context_sid || fscontext_sid || rootcontext_sid ||
		    defcontext_sid) {
			rc = -EACCES;
			goto out;
		}
		if (state == init_selinux_state ||
		    sb->s_user_ns != cred->user_ns) {
			if (sbsec->behavior == SECURITY_FS_USE_XATTR) {
				sbsec->behavior = SECURITY_FS_USE_MNTPOINT;
#ifdef CONFIG_SECURITY_SELINUX_NS
				{
					struct selinux_global_sid_handle *mnt_handle;

					mnt_handle = security_transition_sid_handle(
						state, actor_sid, actor_sid,
						SECCLASS_FILE, NULL,
						&sbsec->mntpoint_sid);
					if (IS_ERR(mnt_handle)) {
						rc = PTR_ERR(mnt_handle);
						goto out;
					}
					rc = selinux_sb_sid_set_handle(
						&sbsec->mntpoint_sid,
						&sbsec->mntpoint_sid_handle,
						mnt_handle);
					global_sid_handle_put(mnt_handle);
					if (rc)
						goto out;
				}
#else
				rc = security_transition_sid(state, actor_sid,
							     actor_sid,
						     SECCLASS_FILE, NULL,
						     &sbsec->mntpoint_sid);
				if (rc)
					goto out;
#endif
			}
			goto out_set_opts;
		}
	}

	/* sets the context of the superblock for the fs being mounted. */
	if (fscontext_sid) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = selinux_may_context_mount_sb_relabel(
			opts, SELINUX_MNT_LABEL_FSCONTEXT, fscontext_sid,
			sbsec, cred);
#else
		rc = may_context_mount_sb_relabel(fscontext_sid, sbsec, cred);
#endif
		if (rc)
			goto out;

#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = selinux_sb_sid_set_handle(
			&sbsec->sid, &sbsec->sid_handle,
			opts->labels[SELINUX_MNT_LABEL_FSCONTEXT].origin_handle);
		if (rc)
			goto out;
#else
		sbsec->sid = fscontext_sid;
#endif
	}

	/*
	 * Switch to using mount point labeling behavior.
	 * sets the label used on all file below the mountpoint, and will set
	 * the superblock context if not already set.
	 */
	if (sbsec->flags & SE_SBNATIVE) {
		/*
		 * This means we are initializing a superblock that has been
		 * mounted before the SELinux was initialized and the
		 * filesystem requested native labeling. We had already
		 * returned SECURITY_LSM_NATIVE_LABELS in *set_kern_flags
		 * in the original mount attempt, so now we just need to set
		 * the SECURITY_FS_USE_NATIVE behavior.
		 */
		sbsec->behavior = SECURITY_FS_USE_NATIVE;
	} else if (kern_flags & SECURITY_LSM_NATIVE_LABELS && !context_sid) {
		sbsec->behavior = SECURITY_FS_USE_NATIVE;
		*set_kern_flags |= SECURITY_LSM_NATIVE_LABELS;
	}

	if (context_sid) {
		if (!fscontext_sid) {
#ifdef CONFIG_SECURITY_SELINUX_NS
			rc = selinux_may_context_mount_sb_relabel(
				opts, SELINUX_MNT_LABEL_CONTEXT, context_sid,
				sbsec, cred);
#else
			rc = may_context_mount_sb_relabel(context_sid, sbsec,
							  cred);
#endif
			if (rc)
				goto out;
#ifdef CONFIG_SECURITY_SELINUX_NS
			rc = selinux_sb_sid_set_handle(
				&sbsec->sid, &sbsec->sid_handle,
				opts->labels[SELINUX_MNT_LABEL_CONTEXT].origin_handle);
			if (rc)
				goto out;
#else
			sbsec->sid = context_sid;
#endif
		} else {
#ifdef CONFIG_SECURITY_SELINUX_NS
			rc = selinux_may_context_mount_inode_relabel(
				opts, SELINUX_MNT_LABEL_CONTEXT, context_sid,
				sbsec, cred);
#else
			rc = may_context_mount_inode_relabel(context_sid, sbsec,
							     cred);
#endif
			if (rc)
				goto out;
		}
		if (!rootcontext_sid)
			rootcontext_sid = context_sid;

#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = selinux_sb_sid_set_handle(
			&sbsec->mntpoint_sid, &sbsec->mntpoint_sid_handle,
			opts->labels[SELINUX_MNT_LABEL_CONTEXT].origin_handle);
		if (rc)
			goto out;
#else
		sbsec->mntpoint_sid = context_sid;
#endif
		sbsec->behavior = SECURITY_FS_USE_MNTPOINT;
	}

	if (rootcontext_sid) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		enum selinux_mnt_label_index root_index =
			opts && opts->labels[SELINUX_MNT_LABEL_ROOTCONTEXT].context ?
			SELINUX_MNT_LABEL_ROOTCONTEXT :
			SELINUX_MNT_LABEL_CONTEXT;

		rc = selinux_may_context_mount_inode_relabel(
			opts, root_index, rootcontext_sid, sbsec, cred);
#else
		rc = may_context_mount_inode_relabel(rootcontext_sid, sbsec,
						     cred);
#endif
		if (rc)
			goto out;

		rc = inode_security_set_sid(root_isec, rootcontext_sid,
					    SELINUX_LABEL_SOURCE_MOUNT_CONTEXT,
					    LABEL_INITIALIZED);
		if (rc)
			goto out;
	}

	if (defcontext_sid) {
		if (sbsec->behavior != SECURITY_FS_USE_XATTR &&
			sbsec->behavior != SECURITY_FS_USE_NATIVE) {
			rc = -EINVAL;
			pr_warn("SELinux: defcontext option is "
			       "invalid for this filesystem type\n");
			goto out;
		}

		if (defcontext_sid != sbsec->def_sid) {
#ifdef CONFIG_SECURITY_SELINUX_NS
			rc = selinux_may_context_mount_inode_relabel(
				opts, SELINUX_MNT_LABEL_DEFCONTEXT,
				defcontext_sid, sbsec, cred);
#else
			rc = may_context_mount_inode_relabel(defcontext_sid,
							     sbsec, cred);
#endif
			if (rc)
				goto out;
		}

#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = selinux_sb_sid_set_handle(
			&sbsec->def_sid, &sbsec->def_sid_handle,
			opts->labels[SELINUX_MNT_LABEL_DEFCONTEXT].origin_handle);
		if (rc)
			goto out;
#else
		sbsec->def_sid = defcontext_sid;
#endif
	}

out_set_opts:
	rc = sb_finish_set_opts(sb);
out:
	mutex_unlock(&sbsec->lock);
	return rc;
out_double_mount:
	rc = -EINVAL;
	pr_warn("SELinux: mount invalid.  Same superblock, different "
	       "security settings for (dev %s, type %s)\n", sb->s_id,
	       sb->s_type->name);
	goto out;
}

static int selinux_cmp_sb_context(const struct super_block *oldsb,
				    const struct super_block *newsb)
{
	struct superblock_security_struct *old = selinux_superblock(oldsb);
	struct superblock_security_struct *new = selinux_superblock(newsb);
	char oldflags = old->flags & SE_MNTMASK;
	char newflags = new->flags & SE_MNTMASK;

	if (oldflags != newflags)
		goto mismatch;
	if ((oldflags & FSCONTEXT_MNT) && old->sid != new->sid)
		goto mismatch;
	if ((oldflags & CONTEXT_MNT) && old->mntpoint_sid != new->mntpoint_sid)
		goto mismatch;
	if ((oldflags & DEFCONTEXT_MNT) && old->def_sid != new->def_sid)
		goto mismatch;
	if (oldflags & ROOTCONTEXT_MNT) {
		struct inode_security_struct *oldroot = backing_inode_security(oldsb->s_root);
		struct inode_security_struct *newroot = backing_inode_security(newsb->s_root);
		if (oldroot->sid != newroot->sid)
			goto mismatch;
	}
	if (old->creator_sid != new->creator_sid)
		goto mismatch;
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (old->anchor_state != new->anchor_state ||
	    old->anchor_domain != new->anchor_domain)
		goto mismatch;
#endif
	return 0;
mismatch:
	pr_warn("SELinux: mount invalid.  Same superblock, "
			    "different security settings for (dev %s, "
			    "type %s)\n", newsb->s_id, newsb->s_type->name);
	return -EBUSY;
}

static int selinux_sb_clone_mnt_opts(const struct super_block *oldsb,
					struct super_block *newsb,
					unsigned long kern_flags,
					unsigned long *set_kern_flags)
{
	int rc = 0;
	const struct superblock_security_struct *oldsbsec =
						selinux_superblock(oldsb);
	struct superblock_security_struct *newsbsec = selinux_superblock(newsb);
	struct selinux_state *clone_state;

	int set_fscontext =	(oldsbsec->flags & FSCONTEXT_MNT);
	int set_context =	(oldsbsec->flags & CONTEXT_MNT);
	int set_rootcontext =	(oldsbsec->flags & ROOTCONTEXT_MNT);

	/*
	 * Specifying internal flags without providing a place to
	 * place the results is not allowed.
	 */
	if (kern_flags && !set_kern_flags)
		return -EINVAL;

	mutex_lock(&newsbsec->lock);

	/*
	 * if the parent was able to be mounted it clearly had no special lsm
	 * mount options.  thus we can safely deal with this superblock later
	 */
#ifdef CONFIG_SECURITY_SELINUX_NS
	clone_state = READ_ONCE(oldsbsec->anchor_state);
	if (!clone_state) {
		rc = -EACCES;
		goto out;
	}
#else
	clone_state = current_selinux_state;
#endif
	if (!selinux_initialized(clone_state)) {
		if (kern_flags & SECURITY_LSM_NATIVE_LABELS) {
			newsbsec->flags |= SE_SBNATIVE;
			*set_kern_flags |= SECURITY_LSM_NATIVE_LABELS;
		}
		goto out;
	}

	/* how can we clone if the old one wasn't set up?? */
	BUG_ON(!(oldsbsec->flags & SE_SBINITIALIZED));

	/* if fs is reusing a sb, make sure that the contexts match */
	if (newsbsec->flags & SE_SBINITIALIZED) {
		mutex_unlock(&newsbsec->lock);
		if ((kern_flags & SECURITY_LSM_NATIVE_LABELS) && !set_context)
			*set_kern_flags |= SECURITY_LSM_NATIVE_LABELS;
		return selinux_cmp_sb_context(oldsb, newsb);
	}
	rc = selinux_sb_set_anchor_locked(newsbsec, clone_state);
	if (rc)
		goto out;

	newsbsec->flags = oldsbsec->flags;

#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = selinux_sb_sid_set_handle(&newsbsec->sid, &newsbsec->sid_handle,
				       oldsbsec->sid_handle);
	if (rc)
		goto out;
	rc = selinux_sb_sid_set_handle(&newsbsec->def_sid,
				       &newsbsec->def_sid_handle,
				       oldsbsec->def_sid_handle);
	if (rc)
		goto out;
	rc = selinux_sb_sid_set_handle(&newsbsec->creator_sid,
				       &newsbsec->creator_sid_handle,
				       oldsbsec->creator_sid_handle);
	if (rc)
		goto out;
	rc = selinux_sb_sid_set_handle(&newsbsec->mntpoint_sid,
				       &newsbsec->mntpoint_sid_handle,
				       oldsbsec->mntpoint_sid_handle);
	if (rc)
		goto out;
#else
	newsbsec->sid = oldsbsec->sid;
	newsbsec->def_sid = oldsbsec->def_sid;
	newsbsec->creator_sid = oldsbsec->creator_sid;
#endif
	newsbsec->behavior = oldsbsec->behavior;

	if (newsbsec->behavior == SECURITY_FS_USE_NATIVE &&
		!(kern_flags & SECURITY_LSM_NATIVE_LABELS) && !set_context) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		struct selinux_global_sid_handle *fs_handle;

		fs_handle = security_fs_use_handle(
			clone_state, newsb->s_type->name, &newsbsec->behavior,
			&newsbsec->sid);
		rc = IS_ERR(fs_handle) ? PTR_ERR(fs_handle) : 0;
#else
		rc = security_fs_use(clone_state,
				     newsb->s_type->name,
				     &newsbsec->behavior, &newsbsec->sid);
#endif
		if (rc)
			goto out;
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = selinux_sb_sid_set_handle(&newsbsec->sid,
					 &newsbsec->sid_handle, fs_handle);
		global_sid_handle_put(fs_handle);
		if (rc)
			goto out;
#endif
	}

	if (kern_flags & SECURITY_LSM_NATIVE_LABELS && !set_context) {
		newsbsec->behavior = SECURITY_FS_USE_NATIVE;
		*set_kern_flags |= SECURITY_LSM_NATIVE_LABELS;
	}

	if (set_context) {
		u32 sid = oldsbsec->mntpoint_sid;

		if (!set_fscontext) {
#ifdef CONFIG_SECURITY_SELINUX_NS
			rc = selinux_sb_sid_set_handle(
				&newsbsec->sid, &newsbsec->sid_handle,
				oldsbsec->mntpoint_sid_handle);
			if (rc)
				goto out;
#else
			newsbsec->sid = sid;
#endif
		}
		if (!set_rootcontext) {
			struct inode_security_struct *newisec = backing_inode_security(newsb->s_root);

			rc = inode_security_set_sid(
				newisec, sid, SELINUX_LABEL_SOURCE_MOUNT_CONTEXT,
				LABEL_INITIALIZED);
			if (rc)
				goto out;
		}
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = selinux_sb_sid_set_handle(
			&newsbsec->mntpoint_sid, &newsbsec->mntpoint_sid_handle,
			oldsbsec->mntpoint_sid_handle);
		if (rc)
			goto out;
#else
		newsbsec->mntpoint_sid = sid;
#endif
	}
	if (set_rootcontext) {
		const struct inode_security_struct *oldisec = backing_inode_security(oldsb->s_root);
		struct inode_security_struct *newisec = backing_inode_security(newsb->s_root);

		rc = inode_security_set_sid(
			newisec, oldisec->sid,
			SELINUX_LABEL_SOURCE_MOUNT_CONTEXT, LABEL_INITIALIZED);
		if (rc)
			goto out;
	}

	sb_finish_set_opts(newsb);
out:
	mutex_unlock(&newsbsec->lock);
	return rc;
}

/*
 * NOTE: the caller is responsible for freeing the memory even if on error.
 */
static int selinux_add_opt(int token, const char *s, void **mnt_opts,
			   const struct cred *anchor_cred)
{
	struct selinux_mnt_opts *opts = *mnt_opts;
#ifdef CONFIG_SECURITY_SELINUX_NS
	char *context;
	int index;
#else
	struct selinux_state *state = current_selinux_state;
	u32 *dst_sid;
	int rc;
#endif

	if (token == Opt_seclabel)
		/* eaten and completely ignored */
		return 0;
	if (!s)
		return -EINVAL;

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!anchor_cred || !cred_selinux_state(anchor_cred))
		return -EACCES;
	if (!opts) {
		opts = kzalloc_obj(*opts);
		if (!opts)
			return -ENOMEM;
		opts->actor = get_cred(anchor_cred);
		*mnt_opts = opts;
	} else if (!opts->actor) {
		opts->actor = get_cred(anchor_cred);
	} else if (opts->actor != anchor_cred) {
		return -EXDEV;
	}

	switch (token) {
	case Opt_context:
		if (opts->labels[SELINUX_MNT_LABEL_CONTEXT].context ||
		    opts->labels[SELINUX_MNT_LABEL_DEFCONTEXT].context)
			goto err;
		index = SELINUX_MNT_LABEL_CONTEXT;
		break;
	case Opt_fscontext:
		if (opts->labels[SELINUX_MNT_LABEL_FSCONTEXT].context)
			goto err;
		index = SELINUX_MNT_LABEL_FSCONTEXT;
		break;
	case Opt_rootcontext:
		if (opts->labels[SELINUX_MNT_LABEL_ROOTCONTEXT].context)
			goto err;
		index = SELINUX_MNT_LABEL_ROOTCONTEXT;
		break;
	case Opt_defcontext:
		if (opts->labels[SELINUX_MNT_LABEL_CONTEXT].context ||
		    opts->labels[SELINUX_MNT_LABEL_DEFCONTEXT].context)
			goto err;
		index = SELINUX_MNT_LABEL_DEFCONTEXT;
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}
	context = kstrdup(s, GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	if (opts->finalized)
		selinux_mnt_opts_drop_resolved(opts);
	opts->labels[index].context = context;
	return 0;
#else
	if (!selinux_initialized(state)) {
		pr_warn("SELinux: Unable to set superblock options before the security server is initialized\n");
		return -EINVAL;
	}

	if (!opts) {
		opts = kzalloc_obj(*opts);
		if (!opts)
			return -ENOMEM;
		*mnt_opts = opts;
	}

	switch (token) {
	case Opt_context:
		if (opts->context_sid || opts->defcontext_sid)
			goto err;
		dst_sid = &opts->context_sid;
		break;
	case Opt_fscontext:
		if (opts->fscontext_sid)
			goto err;
		dst_sid = &opts->fscontext_sid;
		break;
	case Opt_rootcontext:
		if (opts->rootcontext_sid)
			goto err;
		dst_sid = &opts->rootcontext_sid;
		break;
	case Opt_defcontext:
		if (opts->context_sid || opts->defcontext_sid)
			goto err;
		dst_sid = &opts->defcontext_sid;
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}
	rc = security_context_str_to_sid(state, s, dst_sid,
					 GFP_KERNEL);
	if (rc)
		pr_warn("SELinux: security_context_str_to_sid (%s) failed with errno=%d\n",
			s, rc);
	return rc;
#endif

err:
	pr_warn(SEL_MOUNT_FAIL_MSG);
	return -EINVAL;
}

static int show_sid(struct seq_file *m, u32 sid)
{
	const char *context = NULL;
	u32 len;
	int rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		const struct cred_security_struct *leaf =
			selinux_cred(current_cred());
		const struct selinux_label_view *view;
		struct selinux_label_resolution resolved;
		struct selinux_label_domain *origin;
		struct selinux_label_ref *label;
		u16 depth = leaf->state->label_domain->depth;

		label = global_sid_to_label_ref(sid);
		if (IS_ERR(label))
			return PTR_ERR(label);
		origin = label->domain->flags &
				 SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL ?
			 leaf->state->label_domain : label->domain;
		view = selinux_identity_view_alloc_gfp(
			leaf->state->label_domain->owner_userns, origin,
			leaf->state->label_domain, GFP_KERNEL);
		if (IS_ERR(view)) {
			rc = PTR_ERR(view);
			goto out_label;
		}
		rc = selinux_label_view_resolve_chain(
			view, label, sid, &resolved);
		if (!rc && (depth > resolved.max_depth ||
			   resolved.domain_id[depth] !=
				   leaf->state->label_domain->id ||
			   !resolved.sid[depth]))
			rc = -EOPNOTSUPP;
		if (!rc)
			sid = resolved.sid[depth];
		selinux_label_view_put(view);
out_label:
		selinux_label_ref_put(label);
		if (rc)
			return rc;
	}
#endif
	rcu_read_lock();
	rc = security_sid_to_context(current_selinux_state, sid,
					     &context, &len);
	if (!rc) {
		bool has_comma = strchr(context, ',');

		seq_putc(m, '=');
		if (has_comma)
			seq_putc(m, '\"');
		seq_escape(m, context, "\"\n\\");
		if (has_comma)
			seq_putc(m, '\"');
	}
	rcu_read_unlock();
	return rc;
}

static int selinux_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	int rc;

	if (!(sbsec->flags & SE_SBINITIALIZED))
		return 0;

	if (!selinux_initialized(current_selinux_state))
		return 0;

	if (sbsec->flags & FSCONTEXT_MNT) {
		seq_putc(m, ',');
		seq_puts(m, FSCONTEXT_STR);
		rc = show_sid(m, sbsec->sid);
		if (rc)
			return rc;
	}
	if (sbsec->flags & CONTEXT_MNT) {
		seq_putc(m, ',');
		seq_puts(m, CONTEXT_STR);
		rc = show_sid(m, sbsec->mntpoint_sid);
		if (rc)
			return rc;
	}
	if (sbsec->flags & DEFCONTEXT_MNT) {
		seq_putc(m, ',');
		seq_puts(m, DEFCONTEXT_STR);
		rc = show_sid(m, sbsec->def_sid);
		if (rc)
			return rc;
	}
	if (sbsec->flags & ROOTCONTEXT_MNT) {
		struct dentry *root = sb->s_root;
		struct inode_security_struct *isec = backing_inode_security(root);
		seq_putc(m, ',');
		seq_puts(m, ROOTCONTEXT_STR);
		rc = show_sid(m, isec->sid);
		if (rc)
			return rc;
	}
	if (selinux_is_sblabel_mnt(sb)) {
		seq_putc(m, ',');
		seq_puts(m, SECLABEL_STR);
	}
	return 0;
}

static inline u16 inode_mode_to_security_class(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFSOCK:
		return SECCLASS_SOCK_FILE;
	case S_IFLNK:
		return SECCLASS_LNK_FILE;
	case S_IFREG:
		return SECCLASS_FILE;
	case S_IFBLK:
		return SECCLASS_BLK_FILE;
	case S_IFDIR:
		return SECCLASS_DIR;
	case S_IFCHR:
		return SECCLASS_CHR_FILE;
	case S_IFIFO:
		return SECCLASS_FIFO_FILE;

	}

	return SECCLASS_FILE;
}

static inline int default_protocol_stream(int protocol)
{
	return (protocol == IPPROTO_IP || protocol == IPPROTO_TCP ||
		protocol == IPPROTO_MPTCP);
}

static inline int default_protocol_dgram(int protocol)
{
	return (protocol == IPPROTO_IP || protocol == IPPROTO_UDP);
}

static inline u16
socket_class_for_snapshot(const struct selinux_policy_snapshot *snapshot,
			  int family, int type, int protocol)
{
	bool extsockclass =
		selinux_policy_snapshot_has_cap(snapshot,
						 POLICYDB_CAP_EXTSOCKCLASS);

	switch (family) {
	case PF_UNIX:
		switch (type) {
		case SOCK_STREAM:
		case SOCK_SEQPACKET:
			return SECCLASS_UNIX_STREAM_SOCKET;
		case SOCK_DGRAM:
		case SOCK_RAW:
			return SECCLASS_UNIX_DGRAM_SOCKET;
		}
		break;
	case PF_INET:
	case PF_INET6:
		switch (type) {
		case SOCK_STREAM:
		case SOCK_SEQPACKET:
			if (default_protocol_stream(protocol))
				return SECCLASS_TCP_SOCKET;
			else if (extsockclass && protocol == IPPROTO_SCTP)
				return SECCLASS_SCTP_SOCKET;
			else
				return SECCLASS_RAWIP_SOCKET;
		case SOCK_DGRAM:
			if (default_protocol_dgram(protocol))
				return SECCLASS_UDP_SOCKET;
			else if (extsockclass && (protocol == IPPROTO_ICMP ||
						  protocol == IPPROTO_ICMPV6))
				return SECCLASS_ICMP_SOCKET;
			else
				return SECCLASS_RAWIP_SOCKET;
		default:
			return SECCLASS_RAWIP_SOCKET;
		}
		break;
	case PF_NETLINK:
		switch (protocol) {
		case NETLINK_ROUTE:
			return SECCLASS_NETLINK_ROUTE_SOCKET;
		case NETLINK_SOCK_DIAG:
			return SECCLASS_NETLINK_TCPDIAG_SOCKET;
		case NETLINK_NFLOG:
			return SECCLASS_NETLINK_NFLOG_SOCKET;
		case NETLINK_XFRM:
			return SECCLASS_NETLINK_XFRM_SOCKET;
		case NETLINK_SELINUX:
			return SECCLASS_NETLINK_SELINUX_SOCKET;
		case NETLINK_ISCSI:
			return SECCLASS_NETLINK_ISCSI_SOCKET;
		case NETLINK_AUDIT:
			return SECCLASS_NETLINK_AUDIT_SOCKET;
		case NETLINK_FIB_LOOKUP:
			return SECCLASS_NETLINK_FIB_LOOKUP_SOCKET;
		case NETLINK_CONNECTOR:
			return SECCLASS_NETLINK_CONNECTOR_SOCKET;
		case NETLINK_NETFILTER:
			return SECCLASS_NETLINK_NETFILTER_SOCKET;
		case NETLINK_DNRTMSG:
			return SECCLASS_NETLINK_DNRT_SOCKET;
		case NETLINK_KOBJECT_UEVENT:
			return SECCLASS_NETLINK_KOBJECT_UEVENT_SOCKET;
		case NETLINK_GENERIC:
			return SECCLASS_NETLINK_GENERIC_SOCKET;
		case NETLINK_SCSITRANSPORT:
			return SECCLASS_NETLINK_SCSITRANSPORT_SOCKET;
		case NETLINK_RDMA:
			return SECCLASS_NETLINK_RDMA_SOCKET;
		case NETLINK_CRYPTO:
			return SECCLASS_NETLINK_CRYPTO_SOCKET;
		default:
			return SECCLASS_NETLINK_SOCKET;
		}
	case PF_PACKET:
		return SECCLASS_PACKET_SOCKET;
	case PF_KEY:
		return SECCLASS_KEY_SOCKET;
	case PF_APPLETALK:
		return SECCLASS_APPLETALK_SOCKET;
	}

	if (extsockclass) {
		switch (family) {
		case PF_AX25:
			return SECCLASS_AX25_SOCKET;
		case PF_IPX:
			return SECCLASS_IPX_SOCKET;
		case PF_NETROM:
			return SECCLASS_NETROM_SOCKET;
		case PF_ATMPVC:
			return SECCLASS_ATMPVC_SOCKET;
		case PF_X25:
			return SECCLASS_X25_SOCKET;
		case PF_ROSE:
			return SECCLASS_ROSE_SOCKET;
		case PF_DECnet:
			return SECCLASS_DECNET_SOCKET;
		case PF_ATMSVC:
			return SECCLASS_ATMSVC_SOCKET;
		case PF_RDS:
			return SECCLASS_RDS_SOCKET;
		case PF_IRDA:
			return SECCLASS_IRDA_SOCKET;
		case PF_PPPOX:
			return SECCLASS_PPPOX_SOCKET;
		case PF_LLC:
			return SECCLASS_LLC_SOCKET;
		case PF_CAN:
			return SECCLASS_CAN_SOCKET;
		case PF_TIPC:
			return SECCLASS_TIPC_SOCKET;
		case PF_BLUETOOTH:
			return SECCLASS_BLUETOOTH_SOCKET;
		case PF_IUCV:
			return SECCLASS_IUCV_SOCKET;
		case PF_RXRPC:
			return SECCLASS_RXRPC_SOCKET;
		case PF_ISDN:
			return SECCLASS_ISDN_SOCKET;
		case PF_PHONET:
			return SECCLASS_PHONET_SOCKET;
		case PF_IEEE802154:
			return SECCLASS_IEEE802154_SOCKET;
		case PF_CAIF:
			return SECCLASS_CAIF_SOCKET;
		case PF_ALG:
			return SECCLASS_ALG_SOCKET;
		case PF_NFC:
			return SECCLASS_NFC_SOCKET;
		case PF_VSOCK:
			return SECCLASS_VSOCK_SOCKET;
		case PF_KCM:
			return SECCLASS_KCM_SOCKET;
		case PF_QIPCRTR:
			return SECCLASS_QIPCRTR_SOCKET;
		case PF_SMC:
			return SECCLASS_SMC_SOCKET;
		case PF_XDP:
			return SECCLASS_XDP_SOCKET;
		case PF_MCTP:
			return SECCLASS_MCTP_SOCKET;
#if PF_MAX > 46
#error New address family defined, please update this function.
#endif
		}
	}

	return SECCLASS_SOCKET;
}

#ifndef CONFIG_SECURITY_SELINUX_NS
static int
socket_class_for_state(struct selinux_state *state, int family, int type,
		       int protocol, struct selinux_policy_snapshot *snapshot,
		       u16 *sclass)
{
	int rc;

	rc = selinux_policy_snapshot_read(state, snapshot);
	if (rc)
		return rc;
	*sclass = socket_class_for_snapshot(snapshot, family, type, protocol);
	return 0;
}
#endif

static bool selinux_policy_chain_snapshot_valid(
	const struct selinux_policy_chain_snapshot *chain)
{
	u16 i;

	if (!chain || !chain->count)
		return false;
	for (i = 0; i < chain->count; i++) {
		const struct cred_security_struct *crsec =
			selinux_cred(chain->cred[i]);
		const struct cred_security_struct *parent =
			i + 1 < chain->count ?
				selinux_cred(chain->cred[i + 1]) : NULL;
		struct selinux_state *state = crsec->state;

		if (!state || !state->label_domain ||
		    state->depth != state->label_domain->depth ||
		    state->depth != chain->count - i - 1 ||
		    (parent && (crsec->parent_cred != chain->cred[i + 1] ||
				state->parent != parent->state ||
				state->label_domain->parent !=
					parent->state->label_domain)) ||
		    (!parent && (crsec->parent_cred || state->parent ||
				 state->label_domain->parent)) ||
		    !selinux_policy_snapshot_valid(state, &chain->policy[i]))
			return false;
	}
	return true;
}

static int selinux_policy_chain_snapshot_read(
	const struct cred *cred, struct selinux_policy_chain_snapshot *chain)
{
	u16 count = 0;
	int rc;

	while (cred) {
		const struct cred_security_struct *crsec = selinux_cred(cred);

		if (count >= ARRAY_SIZE(chain->cred))
			return -E2BIG;
		if (!crsec->state || !crsec->state->label_domain)
			return -EXDEV;
		chain->cred[count] = cred;
		rc = selinux_policy_snapshot_read(crsec->state,
						  &chain->policy[count]);
		if (rc)
			return rc;
		count++;
		cred = crsec->parent_cred;
	}
	chain->count = count;

	return selinux_policy_chain_snapshot_valid(chain) ? 0 : -ESTALE;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_mnt_control_authorize_stable(
	struct selinux_ns_control *control, const struct cred *cred)
{
	struct selinux_mnt_auth_scratch {
		struct selinux_policy_chain_snapshot chain;
		struct selinux_policy_snapshot target;
	} *scratch __free(kfree) = NULL;
	unsigned int retry;
	int rc;

	if (!control || !cred)
		return -EINVAL;
	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_MNT_POLICY_RETRIES; retry++) {
		rc = selinux_policy_chain_snapshot_read(cred, &scratch->chain);
		if (rc) {
			if (rc != -EAGAIN && rc != -ESTALE)
				return rc;
			continue;
		}
		rc = selinux_policy_snapshot_read(control->state,
					  &scratch->target);
		if (rc) {
			if (rc != -EAGAIN && rc != -ESTALE)
				return rc;
			continue;
		}
		rc = selinux_ns_control_authorize_direct_child(control, cred);
		if (selinux_policy_chain_snapshot_valid(&scratch->chain) &&
		    selinux_policy_snapshot_valid(control->state,
					  &scratch->target))
			return rc;
	}
	return -ESTALE;
}

struct selinux_policy_state_chain_snapshot {
	struct selinux_state *state[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct selinux_policy_snapshot policy[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	u16 count;
};

static bool selinux_policy_state_chain_snapshot_valid(
	const struct selinux_policy_state_chain_snapshot *chain)
{
	u16 i;

	for (i = 0; i < chain->count; i++) {
		struct selinux_state *state = chain->state[i];

		if (!state || !state->label_domain ||
		    state->label_domain->depth != state->depth ||
		    !selinux_policy_snapshot_valid(state, &chain->policy[i]))
			return false;
		if (i + 1 < chain->count) {
			if (state->parent != chain->state[i + 1] || !state->depth ||
			    state->parent->depth != state->depth - 1 ||
			    state->label_domain->parent !=
				    state->parent->label_domain)
				return false;
		} else if (state->parent || state->depth ||
			   state->label_domain->parent) {
			return false;
		}
	}
	return chain->count != 0;
}

static int selinux_policy_state_chain_snapshot_read(
	struct selinux_state *state,
	struct selinux_policy_state_chain_snapshot *chain)
{
	u16 count = 0;
	int rc;

	while (state) {
		if (count >= ARRAY_SIZE(chain->state))
			return -E2BIG;
		chain->state[count] = state;
		rc = selinux_policy_snapshot_read(state, &chain->policy[count]);
		if (rc)
			return rc;
		count++;
		state = state->parent;
	}
	chain->count = count;
	return selinux_policy_state_chain_snapshot_valid(chain) ? 0 : -ESTALE;
}
#endif

static const struct cred *selinux_cred_for_state(
	const struct cred *cred, const struct selinux_state *state)
{
	while (cred) {
		const struct cred_security_struct *crsec = selinux_cred(cred);

		if (crsec->state == state)
			return cred;
		cred = crsec->parent_cred;
	}
	return NULL;
}

static int selinux_cred_sid_for_state_checked(const struct cred *cred,
					      const struct selinux_state *state,
					      u32 *sid)
{
	cred = selinux_cred_for_state(cred, state);
	if (cred) {
		*sid = selinux_cred(cred)->sid;
		return 0;
	}
	return -EXDEV;
}

static int selinux_genfs_get_sid(struct selinux_state *state,
				 struct dentry *dentry, u16 tclass,
				 u16 flags, u32 *sid
#ifdef CONFIG_SECURITY_SELINUX_NS
				 , struct selinux_global_sid_handle **handlep
#endif
				 )
{
	int rc;
	struct super_block *sb = dentry->d_sb;
	char *buffer, *path;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle = NULL;
#endif

	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	path = dentry_path_raw(dentry, buffer, PAGE_SIZE);
	if (IS_ERR(path))
		rc = PTR_ERR(path);
	else {
		if (flags & SE_SBPROC) {
			/* each process gets a /proc/PID/ entry. Strip off the
			 * PID part to get a valid selinux labeling.
			 * e.g. /proc/1/net/rpc/nfs -> /net/rpc/nfs */
			while (path[1] >= '0' && path[1] <= '9') {
				path[1] = '/';
					path++;
				}
			}
#ifdef CONFIG_SECURITY_SELINUX_NS
		handle = security_genfs_sid_handle(
			state, sb->s_type->name, path, tclass, sid);
		rc = IS_ERR(handle) ? PTR_ERR(handle) : 0;
		if (IS_ERR(handle))
			handle = NULL;
#else
		rc = security_genfs_sid(state, sb->s_type->name, path,
					tclass, sid);
#endif
		if (rc == -ENOENT) {
			/* No match in policy, mark as unlabeled. */
			*sid = SECINITSID_UNLABELED;
			rc = 0;
#ifdef CONFIG_SECURITY_SELINUX_NS
			handle = global_sid_handle_get(*sid);
			if (IS_ERR(handle)) {
				rc = PTR_ERR(handle);
				handle = NULL;
			}
#endif
		}
	}
	free_page((unsigned long)buffer);
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!rc) {
		global_sid_handle_put(*handlep);
		*handlep = handle;
	} else {
		global_sid_handle_put(handle);
	}
#endif
	return rc;
}

static int inode_doinit_use_xattr(struct selinux_state *state,
				  struct inode *inode,
				  struct dentry *dentry,
				  u32 def_sid, u32 *sid,
				  enum selinux_label_source *source
#ifdef CONFIG_SECURITY_SELINUX_NS
				  , struct selinux_global_sid_handle **handlep
#endif
				  )
{
#define INITCONTEXTLEN 255
	char *context;
	unsigned int len;
	int rc;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;
#endif

	len = INITCONTEXTLEN;
	context = kmalloc(len + 1, GFP_NOFS);
	if (!context)
		return -ENOMEM;

	context[len] = '\0';
	rc = __vfs_getxattr(dentry, inode, XATTR_NAME_SELINUX, context, len);
	if (rc == -ERANGE) {
		kfree(context);

		/* Need a larger buffer.  Query for the right size. */
		rc = __vfs_getxattr(dentry, inode, XATTR_NAME_SELINUX, NULL, 0);
		if (rc < 0)
			return rc;

		len = rc;
		context = kmalloc(len + 1, GFP_NOFS);
		if (!context)
			return -ENOMEM;

		context[len] = '\0';
		rc = __vfs_getxattr(dentry, inode, XATTR_NAME_SELINUX,
				    context, len);
	}
	if (rc < 0) {
		kfree(context);
		if (rc != -ENODATA) {
			pr_warn("SELinux: %s:  getxattr returned %d for dev=%s ino=%llu\n",
				__func__, -rc, inode->i_sb->s_id, inode->i_ino);
			return rc;
		}
		*sid = def_sid;
		*source = SELINUX_LABEL_SOURCE_FILESYSTEM;
		return 0;
	}

	*source = SELINUX_LABEL_SOURCE_XATTR;
#ifdef CONFIG_SECURITY_SELINUX_NS
	handle = security_context_to_sid_default_handle(
		state, context, rc, sid, def_sid, GFP_NOFS);
	rc = IS_ERR(handle) ? PTR_ERR(handle) : 0;
	if (!rc) {
		global_sid_handle_put(*handlep);
		*handlep = handle;
	}
#else
	rc = security_context_to_sid_default(state, context, rc, sid,
					     def_sid, GFP_NOFS);
#endif
	if (rc) {
		char *dev = inode->i_sb->s_id;
		u64 ino = inode->i_ino;

		if (rc == -EINVAL) {
			pr_notice_ratelimited("SELinux: inode=%llu on dev=%s was found to have an invalid context=%s.  This indicates you may need to relabel the inode or the filesystem in question.\n",
					      ino, dev, context);
		} else {
			pr_warn("SELinux: %s:  context_to_sid(%s) returned %d for dev=%s ino=%llu\n",
				__func__, context, -rc, dev, ino);
		}
	}
	kfree(context);
	return 0;
}

/* The inode's security attributes must be initialized before first use. */
static int inode_doinit_with_dentry(struct inode *inode, struct dentry *opt_dentry)
{
	struct selinux_state *state;
	struct super_block *sb = inode->i_sb;
	struct superblock_security_struct *sbsec = NULL;
	struct inode_security_struct *isec = selinux_inode(inode);
	u32 task_sid, sid = 0;
	u16 sclass;
	struct dentry *dentry;
	enum selinux_label_source source = SELINUX_LABEL_SOURCE_FILESYSTEM;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle = NULL;
	struct selinux_global_sid_handle *task_handle = NULL;
#endif
	int rc = 0;

	/* check below is racy, but we will recheck with lock held */
	if (data_race(isec->initialized == LABEL_INITIALIZED))
		return 0;

	spin_lock(&isec->lock);
	if (isec->initialized == LABEL_INITIALIZED)
		goto out_unlock;

	if (isec->sclass == SECCLASS_FILE)
		isec->sclass = inode_mode_to_security_class(inode->i_mode);

	sbsec = selinux_superblock(sb);
#ifdef CONFIG_SECURITY_SELINUX_NS
	state = READ_ONCE(sbsec->anchor_state);
#else
	state = current_selinux_state;
#endif
	if (!state || !selinux_initialized(state) ||
	    !(sbsec->flags & SE_SBINITIALIZED)) {
		/* Defer initialization until selinux_complete_init,
		   after the initial policy is loaded and the security
		   server is ready to handle calls. */
		spin_lock(&sbsec->isec_lock);
		if (list_empty(&isec->list))
			list_add(&isec->list, &sbsec->isec_head);
		spin_unlock(&sbsec->isec_lock);
		goto out_unlock;
	}

	sclass = isec->sclass;
	task_sid = isec->task_sid;
	sid = isec->sid;
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (sbsec->behavior == SECURITY_FS_USE_TASK ||
	    sbsec->behavior == SECURITY_FS_USE_TRANS) {
		if (!isec->task_sid_handle ||
		    global_sid_handle_sid(isec->task_sid_handle) != task_sid) {
			rc = -ESTALE;
			goto out_unlock;
		}
		task_handle = global_sid_handle_dup(isec->task_sid_handle);
		if (IS_ERR(task_handle)) {
			rc = PTR_ERR(task_handle);
			task_handle = NULL;
			goto out_unlock;
		}
	}
#endif
	isec->initialized = LABEL_PENDING;
	spin_unlock(&isec->lock);

	switch (sbsec->behavior) {
	/*
	 * In case of SECURITY_FS_USE_NATIVE we need to re-fetch the labels
	 * via xattr when called from delayed_superblock_init().
	 */
	case SECURITY_FS_USE_NATIVE:
	case SECURITY_FS_USE_XATTR:
		if (!(inode->i_opflags & IOP_XATTR)) {
			sid = sbsec->def_sid;
			break;
		}
		/* Need a dentry, since the xattr API requires one.
		   Life would be simpler if we could just pass the inode. */
		if (opt_dentry) {
			/* Called from d_instantiate or d_splice_alias. */
			dentry = dget(opt_dentry);
		} else {
			/*
			 * Called from selinux_complete_init, try to find a dentry.
			 * Some filesystems really want a connected one, so try
			 * that first.  We could split SECURITY_FS_USE_XATTR in
			 * two, depending upon that...
			 */
			dentry = d_find_alias(inode);
			if (!dentry)
				dentry = d_find_any_alias(inode);
		}
		if (!dentry) {
			/*
			 * this is can be hit on boot when a file is accessed
			 * before the policy is loaded.  When we load policy we
			 * may find inodes that have no dentry on the
			 * sbsec->isec_head list.  No reason to complain as these
			 * will get fixed up the next time we go through
			 * inode_doinit with a dentry, before these inodes could
			 * be used again by userspace.
			 */
			goto out_invalid;
		}

		rc = inode_doinit_use_xattr(state, inode, dentry,
					    sbsec->def_sid, &sid, &source
#ifdef CONFIG_SECURITY_SELINUX_NS
					    , &handle
#endif
					    );
		dput(dentry);
		if (rc)
			goto out;
		break;
	case SECURITY_FS_USE_TASK:
		sid = task_sid;
		source = SELINUX_LABEL_SOURCE_TASK;
#ifdef CONFIG_SECURITY_SELINUX_NS
		handle = global_sid_handle_dup(task_handle);
		if (IS_ERR(handle)) {
			rc = PTR_ERR(handle);
			handle = NULL;
			goto out;
		}
#endif
		break;
	case SECURITY_FS_USE_TRANS:
		/* Default to the fs SID. */
		sid = sbsec->sid;

		/* Try to obtain a transition SID. */
#ifdef CONFIG_SECURITY_SELINUX_NS
		handle = security_transition_sid_handle(
			state, task_sid, sid, sclass, NULL, &sid);
		if (IS_ERR(handle)) {
			rc = PTR_ERR(handle);
			handle = NULL;
		} else {
			rc = 0;
		}
#else
		rc = security_transition_sid(state, task_sid, sid, sclass,
					     NULL, &sid);
#endif
		if (rc)
			goto out;
		source = SELINUX_LABEL_SOURCE_TRANSITION;
		break;
	case SECURITY_FS_USE_MNTPOINT:
		sid = sbsec->mntpoint_sid;
		source = SELINUX_LABEL_SOURCE_MOUNT_CONTEXT;
#ifdef CONFIG_SECURITY_SELINUX_NS
		handle = global_sid_handle_dup(sbsec->mntpoint_sid_handle);
		if (IS_ERR(handle)) {
			rc = PTR_ERR(handle);
			handle = NULL;
			goto out;
		}
#endif
		break;
	default:
		/* Default to the fs superblock SID. */
		sid = sbsec->sid;

		if ((sbsec->flags & SE_SBGENFS) &&
		     (!S_ISLNK(inode->i_mode) ||
		      selinux_policycap_genfs_seclabel_symlinks(state))) {
			/* We must have a dentry to determine the label on
			 * procfs inodes */
			if (opt_dentry) {
				/* Called from d_instantiate or
				 * d_splice_alias. */
				dentry = dget(opt_dentry);
			} else {
				/* Called from selinux_complete_init, try to
				 * find a dentry.  Some filesystems really want
				 * a connected one, so try that first.
				 */
				dentry = d_find_alias(inode);
				if (!dentry)
					dentry = d_find_any_alias(inode);
			}
			/*
			 * This can be hit on boot when a file is accessed
			 * before the policy is loaded.  When we load policy we
			 * may find inodes that have no dentry on the
			 * sbsec->isec_head list.  No reason to complain as
			 * these will get fixed up the next time we go through
			 * inode_doinit() with a dentry, before these inodes
			 * could be used again by userspace.
			 */
			if (!dentry)
				goto out_invalid;
			rc = selinux_genfs_get_sid(state, dentry, sclass,
						   sbsec->flags, &sid
#ifdef CONFIG_SECURITY_SELINUX_NS
						   , &handle
#endif
						   );
			if (rc) {
				dput(dentry);
				goto out;
			}
			source = SELINUX_LABEL_SOURCE_GENFS;

			if ((inode->i_opflags & IOP_XATTR) &&
			    (!strcmp(sb->s_type->name, "sysfs") ||
			     (selinux_policycap_cgroupseclabel(state) &&
			      (!strcmp(sb->s_type->name, "cgroup") ||
			       !strcmp(sb->s_type->name, "cgroup2"))))) {
				rc = inode_doinit_use_xattr(state, inode,
							    dentry, sid, &sid,
							    &source
#ifdef CONFIG_SECURITY_SELINUX_NS
							    , &handle
#endif
							    );
				if (rc) {
					dput(dentry);
					goto out;
				}
			}
			dput(dentry);
		}
		break;
	}

out:
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!rc) {
		if (!handle)
			handle = global_sid_handle_get(sid);
		if (IS_ERR(handle)) {
			rc = PTR_ERR(handle);
			handle = NULL;
		}
	}
#endif
	if (rc) {
		spin_lock(&isec->lock);
		if (isec->initialized == LABEL_PENDING)
			isec->initialized = LABEL_INVALID;
		spin_unlock(&isec->lock);
	} else {
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = __selinux_inode_security_take_sid_handle(
			isec, handle, &sclass, source, LABEL_INITIALIZED, true);
		handle = NULL;
#else
		spin_lock(&isec->lock);
		if (isec->initialized == LABEL_PENDING) {
			isec->initialized = LABEL_INITIALIZED;
			isec->sid = sid;
		}
		spin_unlock(&isec->lock);
#endif
	}
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(handle);
	global_sid_handle_put(task_handle);
#endif
	return rc;

out_unlock:
	spin_unlock(&isec->lock);
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(handle);
	global_sid_handle_put(task_handle);
#endif
	return rc;

out_invalid:
	spin_lock(&isec->lock);
	if (isec->initialized == LABEL_PENDING)
		isec->initialized = LABEL_INVALID;
	spin_unlock(&isec->lock);
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(handle);
	global_sid_handle_put(task_handle);
#endif
	return 0;
}

/* Convert a Linux signal to an access vector. */
static inline u32 signal_to_av(int sig)
{
	u32 perm = 0;

	switch (sig) {
	case SIGCHLD:
		/* Commonly granted from child to parent. */
		perm = PROCESS__SIGCHLD;
		break;
	case SIGKILL:
		/* Cannot be caught or ignored */
		perm = PROCESS__SIGKILL;
		break;
	case SIGSTOP:
		/* Cannot be caught or ignored */
		perm = PROCESS__SIGSTOP;
		break;
	default:
		/* All other signals. */
		perm = PROCESS__SIGNAL;
		break;
	}

	return perm;
}

#if CAP_LAST_CAP > 63
#error Fix SELinux to handle capabilities > 63.
#endif

/* Check whether a task is allowed to use a capability. */
static int cred_has_capability(const struct cred *cred,
			       int cap, unsigned int opts, bool initns)
{
	struct common_audit_data ad = {};
	u16 sclass;
	u32 av = CAP_TO_MASK(cap);
	int rc;
	ad.type = LSM_AUDIT_DATA_CAP;
	ad.u.cap = cap;

	switch (CAP_TO_INDEX(cap)) {
	case 0:
		sclass = initns ? SECCLASS_CAPABILITY : SECCLASS_CAP_USERNS;
		break;
	case 1:
		sclass = initns ? SECCLASS_CAPABILITY2 : SECCLASS_CAP2_USERNS;
		break;
	default:
		pr_err("SELinux:  out of range capability %d\n", cap);
		return -EINVAL;
	}

	if (opts & CAP_OPT_NOAUDIT)
		rc = cred_self_has_perm_noaudit(cred, sclass, av);
	else
		rc = cred_self_has_perm(cred, sclass, av, &ad);

	return rc;
}

/* Check whether a task has a particular permission to an inode.
   The 'adp' parameter is optional and allows other audit
   data to be passed (e.g. the dentry). */
#ifndef CONFIG_SECURITY_SELINUX_NS
static int inode_has_perm(const struct cred *cred,
			  struct inode *inode,
			  u32 perms,
			  struct common_audit_data *adp)
{
	struct inode_security_struct *isec;

	if (unlikely(IS_PRIVATE(inode)))
		return 0;

	isec = selinux_inode(inode);

	return cred_tsid_has_perm(cred, isec->sid, isec->sclass, perms, adp);
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
static struct selinux_pathless_projection *
selinux_inode_pathless_get(struct inode_security_struct *isec)
{
	struct selinux_pathless_projection *projection;

	spin_lock(&isec->lock);
	projection = selinux_pathless_projection_get(
		rcu_dereference_protected(isec->pathless,
					  lockdep_is_held(&isec->lock)));
	spin_unlock(&isec->lock);
	return projection;
}

static int inode_has_perm_view(const struct cred *cred, struct inode *inode,
			       const struct selinux_label_view *view, u32 perms,
			       struct common_audit_data *adp)
{
	const struct cred_security_struct *crsec = selinux_cred(cred);
	struct inode_security_struct *isec;
	struct selinux_pathless_projection *projection;
	struct selinux_inode_label_snapshot snapshot;
	int rc;

	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	/*
	 * Before the initial policy load, inode labels are deliberately left on
	 * the superblock's deferred-initialization list.  Preserve the upstream
	 * policy-less bootstrap semantics for the root state rather than treating
	 * that expected LABEL_INVALID tuple as stale.  A namespaced child without
	 * a policy must never bypass its already-existing parent policy.
	 */
	if (!selinux_initialized(crsec->state))
		return selinux_cred_chain_uninitialized(cred) ? 0 : -EACCES;
	/*
	 * Do not revalidate here: file_path_has_perm() can reach this helper
	 * while holding tty->files_lock.  Sleepable path-based callers perform
	 * revalidation before entry; all other callers fail closed below when
	 * the atomic snapshot is not LABEL_INITIALIZED.
	 */
	isec = inode_security_novalidate(inode);
	projection = selinux_inode_pathless_get(isec);
	if (projection) {
		/* The published projection is the inode's authoritative identity. */
		rc = cred_pathless_has_perm(cred, projection, perms, adp);
		selinux_pathless_projection_put(projection);
		return rc;
	}
	if (!view)
		return -EOPNOTSUPP;
	rc = selinux_inode_label_snapshot_get(isec, &snapshot);
	if (rc)
		return rc;
	rc = cred_label_has_perm(cred, snapshot.sid, snapshot.label, view,
				 snapshot.sclass, perms, adp);
	selinux_inode_label_snapshot_put(&snapshot);
	return rc;
}

static const struct selinux_label_view *
selinux_mnt_label_view(const struct vfsmount *mnt)
{
	const struct mount_security_struct *msec;
	const struct selinux_label_view *view;

	if (!mnt)
		return NULL;
	msec = selinux_mount_security(mnt);
	if (!msec)
		return NULL;
	/* A mount reference pins both the current and pre-topology views. */
	view = smp_load_acquire(&msec->view);
	if (!view ||
	    (view->flags & SELINUX_LABEL_VIEW_ORIGIN_UNRESOLVED))
		return NULL;
	return view;
}
#endif

static inline int dentry_has_perm_mnt(const struct cred *cred,
				      const struct vfsmount *mnt,
				      struct dentry *dentry, u32 av)
{
	struct common_audit_data ad = {};
	struct inode *inode = d_backing_inode(dentry);
	struct inode_security_struct *isec = selinux_inode(inode);

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;
	if (data_race(unlikely(isec->initialized != LABEL_INITIALIZED)))
		__inode_security_revalidate(inode, dentry, true);
#ifdef CONFIG_SECURITY_SELINUX_NS
	return inode_has_perm_view(cred, inode, selinux_mnt_label_view(mnt), av,
				   &ad);
#else
	return inode_has_perm(cred, inode, av, &ad);
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int sid_has_perm_mnt(const struct cred *cred,
			    const struct vfsmount *mnt, u32 sid, u16 tclass,
			    u32 av, struct common_audit_data *ad)
{
	const struct selinux_label_view *view = selinux_mnt_label_view(mnt);
	struct selinux_label_ref *label;
	int rc;

	if (!view)
		return -EOPNOTSUPP;
	label = global_sid_to_label_ref(sid);
	if (IS_ERR(label))
		return PTR_ERR(label);
	rc = cred_label_has_perm(cred, sid, label, view, tclass, av, ad);
	selinux_label_ref_put(label);
	return rc;
}
#endif

/* Same as inode_has_perm, but pass explicit audit data containing
   the path to help the auditing code to more easily generate the
   pathname if needed. */
static inline int path_has_perm(const struct cred *cred,
				const struct path *path,
				u32 av)
{
	struct common_audit_data ad;
	struct inode *inode = d_backing_inode(path->dentry);
	struct inode_security_struct *isec = selinux_inode(inode);

	ad.type = LSM_AUDIT_DATA_PATH;
	ad.u.path = *path;
	/* check below is racy, but revalidate will recheck with lock held */
	if (data_race(unlikely(isec->initialized != LABEL_INITIALIZED)))
		__inode_security_revalidate(inode, path->dentry, true);
#ifdef CONFIG_SECURITY_SELINUX_NS
	return inode_has_perm_view(cred, inode,
				   selinux_mnt_label_view(path->mnt), av, &ad);
#else
	return inode_has_perm(cred, inode, av, &ad);
#endif
}

/* Same as path_has_perm, but uses the inode from the file struct. */
static inline int file_path_has_perm(const struct cred *cred,
				     struct file *file,
				     u32 av)
{
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;
#ifdef CONFIG_SECURITY_SELINUX_NS
	return inode_has_perm_view(cred, file_inode(file),
				   selinux_file(file)->view, av, &ad);
#else
	return inode_has_perm(cred, file_inode(file), av, &ad);
#endif
}

#ifdef CONFIG_BPF_SYSCALL
#ifndef CONFIG_SECURITY_SELINUX_NS
static int bpf_fd_pass(const struct file *file, const struct cred *cred);
#else
static int bpf_fd_pass_add(
	const struct file *file, const struct cred *cred,
	struct selinux_file_transfer_transaction *transaction);
#endif
static int selinux_bpf_link_access_cred(const struct cred *cred,
					struct bpf_link *link, enum bpf_cmd cmd);
static int selinux_bpf_link_access(struct bpf_link *link,
					    enum bpf_cmd cmd);
static u32 selinux_bpf_link_cmd_perm(enum bpf_cmd cmd);
static int selinux_bpf_btf_cred(const struct cred *cred,
				const struct btf *btf);
static int selinux_bpf_btf(const struct btf *btf);
#endif
#if defined(CONFIG_PERF_EVENTS) && defined(CONFIG_SECURITY_SELINUX_NS)
static int perf_fd_pass_add(
	const struct file *file, const struct cred *cred,
	struct selinux_file_transfer_transaction *transaction);
#endif
#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_file_operation_has_perm(
	const struct cred *cred, const struct file *file, const struct cred *opener,
	struct inode *inode, const struct selinux_label_view *view,
	const struct selinux_pathless_projection *pathless,
	const struct selinux_file_operation_check *check, bool include_carriers,
	struct common_audit_data *ad);
static int selinux_file_transfer_has_perm(
	const struct cred *cred, const struct file *file, const struct cred *opener,
	struct inode *inode, const struct selinux_label_view *view,
	const struct selinux_pathless_projection *pathless, u32 requested,
	struct common_audit_data *ad);
#endif

#ifndef CONFIG_SECURITY_SELINUX_NS
static int file_use_has_perm(const struct cred *cred, const struct file *file,
			     struct common_audit_data *ad)
{
	const struct cred *opener = file->f_cred;

	if (!opener)
		return -EIO;
	if (cred_sid_chain_equal(cred, opener))
		return 0;
	return cred_other_has_perm(cred, opener, SECCLASS_FD, FD__USE, ad);
}
#endif

static int __file_has_perm(const struct cred *cred, const struct file *file,
			   u32 av, bool bf_user_file)

{
	struct common_audit_data ad;
	struct inode *inode;
	const struct cred *opener;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct selinux_label_view *view;
	const struct selinux_pathless_projection *pathless;
#else
	int rc;
#endif

	if (bf_user_file) {
		struct backing_file_security_struct *bfsec;
		const struct path *path;

		if (WARN_ON(!(file->f_mode & FMODE_BACKING)))
			return -EIO;

		bfsec = selinux_backing_file(file);
		path = backing_file_user_path(file);
		opener = bfsec->cred;
		inode = d_inode(path->dentry);
#ifdef CONFIG_SECURITY_SELINUX_NS
		view = bfsec->view;
		pathless = bfsec->pathless;
#endif

		ad.type = LSM_AUDIT_DATA_PATH;
		ad.u.path = *path;
	} else {
#ifdef CONFIG_SECURITY_SELINUX_NS
		struct file_security_struct *fsec = selinux_file(file);
#endif

		opener = file->f_cred;
		inode = file_inode(file);
#ifdef CONFIG_SECURITY_SELINUX_NS
		view = fsec->view;
		pathless = fsec->pathless;
#endif

		ad.type = LSM_AUDIT_DATA_FILE;
		ad.u.file = file;
	}

	if (!opener)
		return -EIO;
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!selinux_initialized(selinux_cred(cred)->state) &&
	    selinux_cred_chain_uninitialized(cred))
		return 0;
	return selinux_file_transfer_has_perm(
		cred, file, opener, inode, view, pathless, av, &ad);
#else
	if (!cred_sid_chain_equal(cred, opener)) {
		rc = cred_other_has_perm(cred, opener, SECCLASS_FD, FD__USE, &ad);
		if (rc)
			return rc;
	}

#ifdef CONFIG_BPF_SYSCALL
	/* regardless of backing vs user file, use the underlying file here */
	rc = bpf_fd_pass(file, cred);
	if (rc)
		return rc;
#endif

	/* av is zero if only checking access to the descriptor. */
	if (av)
		return inode_has_perm(cred, inode, av, &ad);

	return 0;
#endif
}

/* Check whether a task can use an open file descriptor to
   access an inode in a given way.  Check access to the
   descriptor itself, and then use dentry_has_perm to
   check a particular permission to the file.
   Access to the descriptor is implicitly granted if it
   has the same SID as the process.  If av is zero, then
   access to the file is not checked, e.g. for cases
   where only the descriptor is affected like seek. */
static inline int file_has_perm(const struct cred *cred,
				const struct file *file, u32 av)
{
	return __file_has_perm(cred, file, av, false);
}

/*
 * Determine the label for an inode that might be unioned.
 */
#ifdef CONFIG_SECURITY_SELINUX_NS
static struct selinux_global_sid_handle *
selinux_determine_inode_label_handle(
	const struct cred_security_struct *crsec, struct inode *dir,
	const struct qstr *name, u16 tclass, u32 *_new_isid)
{
	const struct superblock_security_struct *sbsec =
		selinux_superblock(dir->i_sb);
	struct selinux_global_sid_handle *handle;
	u32 expected_sid;

	if ((sbsec->flags & SE_SBINITIALIZED) &&
	    sbsec->behavior == SECURITY_FS_USE_MNTPOINT) {
		expected_sid = sbsec->mntpoint_sid;
		handle = global_sid_handle_dup(sbsec->mntpoint_sid_handle);
	} else if (selinux_is_sblabel_mnt(dir->i_sb) &&
		   crsec->create_sid) {
		expected_sid = crsec->create_sid;
		handle = global_sid_handle_dup(crsec->create_sid_handle);
	} else {
		const struct inode_security_struct *dsec = inode_security(dir);

		return security_transition_sid_handle(
			current_selinux_state, crsec->sid, dsec->sid, tclass,
			name, _new_isid);
	}
	if (IS_ERR(handle))
		return handle;
	*_new_isid = global_sid_handle_sid(handle);
	if (!*_new_isid || *_new_isid != expected_sid) {
		global_sid_handle_put(handle);
		return ERR_PTR(-ESTALE);
	}
	return handle;
}
#endif

#ifndef CONFIG_SECURITY_SELINUX_NS
static int
selinux_determine_inode_label(const struct cred_security_struct *crsec,
				 struct inode *dir,
				 const struct qstr *name, u16 tclass,
				 u32 *_new_isid)
{
	const struct superblock_security_struct *sbsec =
						selinux_superblock(dir->i_sb);

	if ((sbsec->flags & SE_SBINITIALIZED) &&
	    (sbsec->behavior == SECURITY_FS_USE_MNTPOINT)) {
		*_new_isid = sbsec->mntpoint_sid;
	} else if (selinux_is_sblabel_mnt(dir->i_sb) &&
		   crsec->create_sid) {
		*_new_isid = crsec->create_sid;
	} else {
		const struct inode_security_struct *dsec = inode_security(dir);
		return security_transition_sid(current_selinux_state,
					       crsec->sid, dsec->sid, tclass,
					       name, _new_isid);
	}

	return 0;
}
#endif

/* Check whether a task can create a file. */
static int may_create(const struct vfsmount *mnt, struct inode *dir,
		      struct dentry *dentry,
		      u16 tclass)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct cred_security_struct *crsec =
		selinux_cred(current_cred());
	struct selinux_inode_create_plan *plan =
		selinux_task(current)->create_plan;
	const struct selinux_label_view *view = selinux_mnt_label_view(mnt);

	/* Preserve the policy-less bootstrap semantics used before first load. */
	if (!selinux_initialized(crsec->state)
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	    && !selinux_task(current)->create_plan_kunit_force
#endif
	)
		return selinux_cred_chain_uninitialized(current_cred()) ?
			0 : -EACCES;
	if (!plan || !view || plan->view != view || plan->dir != dir ||
	    plan->sb != dir->i_sb || plan->tclass != tclass ||
	    plan->name.len != dentry->d_name.len ||
	    memcmp(plan->name.name, dentry->d_name.name, plan->name.len))
		return -EOPNOTSUPP;
	return selinux_policy_chain_snapshot_valid(&plan->chain) ? 0 : -ESTALE;
#else
	const struct cred *cred = current_cred();
	const struct cred_security_struct *crsec = selinux_cred(cred);
	struct inode_security_struct *dsec;
	struct superblock_security_struct *sbsec;
	u32 newsid;
	struct common_audit_data ad;
	int rc;
	dsec = inode_security(dir);
	sbsec = selinux_superblock(dir->i_sb);

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;

	rc = cred_tsid_has_perm(cred, dsec->sid, SECCLASS_DIR,
				DIR__ADD_NAME | DIR__SEARCH, &ad);
	if (rc)
		return rc;

	rc = selinux_determine_inode_label(crsec, dir, &dentry->d_name, tclass,
					   &newsid);
	if (rc)
		return rc;

	rc = cred_tsid_has_perm(cred, newsid, tclass, FILE__CREATE, &ad);
	if (rc)
		return rc;

	return cred_obj_has_perm(cred, newsid, sbsec->sid,
				 SECCLASS_FILESYSTEM, FILESYSTEM__ASSOCIATE,
				 &ad);
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static void selinux_inode_create_plan_release(
	struct selinux_inode_create_plan *plan)
{
	u16 i;

	if (!plan)
		return;
	if (plan->actor)
		put_cred(plan->actor);
	selinux_label_view_put(plan->view);
	selinux_label_ref_put(plan->dir_label);
	selinux_label_ref_put(plan->sb_label);
	selinux_label_ref_put(plan->anchor_label);
	global_sid_handle_put(plan->anchor_handle);
	global_sid_handle_put(plan->mntpoint_handle);
	for (i = 0; i <= SELINUX_LABEL_RESOLUTION_MAX_DEPTH; i++)
		global_sid_handle_put(plan->object_handles[i]);
	selinux_label_domain_put(plan->anchor_domain);
	put_selinux_state(plan->anchor_state);
	kfree(plan->name.name);
	kfree(plan->xattr_value);
	memset(plan, 0, sizeof(*plan));
}

static int selinux_inode_create_plan_chain_valid(
	const struct selinux_inode_create_plan *plan)
{
	const struct selinux_label_domain *parent = NULL;
	u16 i;

	if (!plan->chain.count ||
	    plan->chain.count !=
		selinux_cred(plan->chain.cred[0])->state->label_domain->depth + 1)
		return -EXDEV;
	for (i = plan->chain.count; i-- > 0;) {
		const struct cred_security_struct *crsec =
			selinux_cred(plan->chain.cred[i]);
		const struct selinux_label_domain *domain =
			crsec->state->label_domain;
		u16 depth = plan->chain.count - i - 1;

		if (!domain || domain->depth != depth ||
		    crsec->state->depth != depth || domain->parent != parent)
			return -EXDEV;
		if (i + 1 < plan->chain.count &&
		    (crsec->parent_cred != plan->chain.cred[i + 1] ||
		     crsec->state->parent !=
			selinux_cred(plan->chain.cred[i + 1])->state))
			return -EXDEV;
		parent = domain;
	}
	return 0;
}

static int selinux_policy_chain_anchor_valid(
	const struct selinux_policy_chain_snapshot *chain,
	const struct selinux_state *anchor_state,
	const struct selinux_label_domain *anchor_domain)
{
	const struct cred_security_struct *crsec;
	u16 index;

	if (!chain || !anchor_state || !anchor_domain ||
	    anchor_domain->depth >= chain->count)
		return -EXDEV;
	index = chain->count - anchor_domain->depth - 1;
	crsec = selinux_cred(chain->cred[index]);
	if (crsec->state != anchor_state ||
	    crsec->state->label_domain != anchor_domain ||
	    crsec->state->depth != anchor_domain->depth ||
	    crsec->state->label_domain->id != anchor_domain->id)
		return -EXDEV;
	return 0;
}

static int selinux_inode_create_plan_owner_valid(
	const struct selinux_inode_create_plan *plan,
	const struct security_inode_create_plan *generic)
{
	if (!plan || !generic || plan->generic != generic ||
	    plan->owner_task != current ||
	    plan->owner_tsec != selinux_task(current) ||
	    plan->actor != current_cred() || !plan->view || !plan->dir ||
	    !plan->sb || plan->dir->i_sb != plan->sb || !plan->anchor_state ||
	    !plan->anchor_domain || !plan->anchor_handle ||
	    !plan->anchor_label ||
	    global_sid_handle_sid(plan->anchor_handle) != plan->anchor_sid ||
	    plan->anchor_state->label_domain != plan->anchor_domain ||
	    plan->view->origin_domain != plan->anchor_domain)
		return -EPROTO;
	return 0;
}

static int selinux_inode_create_plan_identity_valid(
	const struct selinux_inode_create_plan *plan)
{
	struct superblock_security_struct *sbsec;
	int rc = 0;

	if (selinux_inode_create_plan_owner_valid(plan, plan->generic))
		return -EPROTO;
	sbsec = selinux_superblock(plan->sb);
	mutex_lock(&sbsec->lock);
	if (sbsec->anchor_state != plan->anchor_state ||
	    sbsec->anchor_domain != plan->anchor_domain)
		rc = -ESTALE;
	mutex_unlock(&sbsec->lock);
	if (rc)
		return rc;
	if (!selinux_policy_chain_snapshot_valid(&plan->chain))
		return -ESTALE;
	return selinux_policy_chain_anchor_valid(
		&plan->chain, plan->anchor_state, plan->anchor_domain);
}

static int selinux_inode_create_plan_tuple_valid(
	const struct selinux_inode_create_plan *plan, struct inode *inode)
{
	struct inode_security_struct *isec;
	struct selinux_label_ref *label;
	int rc = 0;

	if (!inode || inode != plan->inode || inode->i_sb != plan->sb ||
	    !plan->anchor_handle ||
	    global_sid_handle_sid(plan->anchor_handle) != plan->anchor_sid)
		return -EPROTO;
	isec = selinux_inode(inode);
	spin_lock(&isec->lock);
	label = rcu_dereference_protected(
		isec->label_ref, lockdep_is_held(&isec->lock));
	if (isec->initialized != LABEL_INITIALIZED ||
	    rcu_access_pointer(isec->pathless) ||
	    isec->sid_handle != plan->anchor_handle ||
	    global_sid_handle_sid(isec->sid_handle) != plan->anchor_sid ||
	    label != plan->anchor_label || isec->sid != plan->anchor_sid ||
	    isec->sclass != plan->tclass || isec->label_source != plan->source)
		rc = -ESTALE;
	spin_unlock(&isec->lock);
	return rc;
}

static void selinux_inode_security_invalidate(struct inode *inode);

static int selinux_inode_create_plan_attempt_abort(struct inode *inode)
{
	struct selinux_inode_create_plan *plan =
		selinux_task(current)->create_plan;
	int rc, tuple_rc = 0;

	if (!plan || !plan->requires_commit)
		return 0;
	rc = selinux_inode_create_plan_owner_valid(plan, plan->generic);
	if (rc)
		return rc;
	/* A failure before this LSM prepared an inode needs no rearm. */
	if (!plan->inode && !plan->xattr_prepared && !plan->committed)
		return 0;
	if (!inode || plan->inode != inode || !plan->xattr_prepared)
		return -EPROTO;

	rc = selinux_inode_create_plan_identity_valid(plan);
	if (plan->committed)
		tuple_rc = selinux_inode_create_plan_tuple_valid(plan, inode);
	if (tuple_rc && (!rc || rc == -ESTALE))
		rc = tuple_rc;

	/*
	 * The filesystem has proved this exact inode unreachable.  Clear only
	 * per-attempt state; immutable authorization and label material remain
	 * sealed for a possible retry.
	 */
	selinux_inode_security_invalidate(inode);
	plan->inode = NULL;
	plan->xattr_prepared = false;
	plan->committed = false;
	return rc;
}

static void selinux_inode_security_invalidate(struct inode *inode)
{
	struct inode_security_struct *isec;

	if (!inode)
		return;
	isec = selinux_inode(inode);
	spin_lock(&isec->lock);
	isec->initialized = LABEL_INVALID;
	spin_unlock(&isec->lock);
}

static int selinux_inode_create_plan_inode_label(
	struct inode *inode, struct selinux_label_ref **label, u32 *sid,
	u16 *sclass, u8 *source)
{
	struct inode_security_struct *isec = selinux_inode(inode);

	spin_lock(&isec->lock);
	if (isec->initialized != LABEL_INITIALIZED
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	    && !selinux_task(current)->create_plan_kunit_force
#endif
	) {
		spin_unlock(&isec->lock);
		return -EACCES;
	}
	*label = selinux_label_ref_get(
		rcu_dereference_protected(isec->label_ref,
					  lockdep_is_held(&isec->lock)));
	*sid = isec->sid;
	*sclass = isec->sclass;
	*source = isec->label_source;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (isec->initialized != LABEL_INITIALIZED &&
	    selinux_task(current)->create_plan_kunit_force)
		*sclass = inode_mode_to_security_class(inode->i_mode);
#endif
	spin_unlock(&isec->lock);
	return *label ? 0 : -EIO;
}

static int selinux_inode_create_plan_authorize(
	struct selinux_inode_create_plan *plan, struct dentry *dentry,
	u32 mntpoint_sid, unsigned short behavior)
{
	struct selinux_avc_level *levels __free(kfree) = NULL;
	struct selinux_policy_snapshot *snapshots __free(kfree) = NULL;
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) =
		NULL;
	struct selinux_label_resolution projected;
	struct common_audit_data ad = {};
	u16 allocated_count = 0;
	unsigned int retry;
	int rc = -ESTALE;

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_AVC_TRANSACTION_MAX_CHECKS,
		GFP_KERNEL);
	if (!workspace)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 anchor_depth = plan->anchor_domain->depth;
		u16 check_count, count = 0, i;

		for (i = 0; i <= SELINUX_LABEL_RESOLUTION_MAX_DEPTH; i++) {
			global_sid_handle_put(plan->object_handles[i]);
			plan->object_handles[i] = NULL;
		}

		rc = selinux_policy_chain_snapshot_read(plan->actor,
							&plan->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = selinux_inode_create_plan_chain_valid(plan);
		if (rc)
			return rc;
		rc = selinux_policy_chain_anchor_valid(
			&plan->chain, plan->anchor_state, plan->anchor_domain);
		if (rc)
			return rc;
		check_count = plan->chain.count * SELINUX_CREATE_AVC_CHECKS;
		if (!levels) {
			levels = kcalloc(check_count, sizeof(*levels), GFP_KERNEL);
			snapshots = kcalloc(check_count, sizeof(*snapshots),
					    GFP_KERNEL);
			if (!levels || !snapshots)
				return -ENOMEM;
			allocated_count = check_count;
		} else if (allocated_count != check_count) {
			return -EXDEV;
		}

		memset(&plan->object_resolution, 0,
		       sizeof(plan->object_resolution));
		plan->object_resolution.max_depth =
			plan->dir_resolution.max_depth;
		memcpy(plan->object_resolution.domain_id,
		       plan->dir_resolution.domain_id,
		       sizeof(plan->object_resolution.domain_id));

		if (behavior == SECURITY_FS_USE_MNTPOINT) {
			plan->anchor_sid = mntpoint_sid;
			plan->anchor_handle =
				global_sid_handle_dup(plan->mntpoint_handle);
			if (IS_ERR(plan->anchor_handle)) {
				rc = PTR_ERR(plan->anchor_handle);
				plan->anchor_handle = NULL;
				return rc;
			}
			plan->anchor_label =
				global_sid_handle_label_get(plan->anchor_handle);
			if (!plan->anchor_label)
				goto retry_stale;
			if (global_sid_handle_sid(plan->anchor_handle) !=
				    plan->anchor_sid ||
			    (plan->anchor_label->domain != plan->anchor_domain &&
			     (!(plan->anchor_label->domain->flags &
				SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) ||
			      plan->anchor_sid > SECINITSID_NUM)))
				return -EXDEV;
			rc = selinux_label_view_resolve_chain(
				plan->view, plan->anchor_label, plan->anchor_sid,
				&plan->object_resolution);
			if (rc == -EAGAIN || rc == -ESTALE)
				goto retry_stale;
			if (rc)
				return rc;
			plan->source = SELINUX_LABEL_SOURCE_MOUNT_CONTEXT;
		} else {
			for (i = 0; i < plan->chain.count; i++) {
				const struct cred_security_struct *crsec =
					selinux_cred(plan->chain.cred[i]);
				struct selinux_global_sid_handle *object_handle;
				u16 depth = crsec->state->label_domain->depth;
				u32 sid;

				if (depth > plan->dir_resolution.max_depth ||
				    plan->dir_resolution.domain_id[depth] !=
					crsec->state->label_domain->id ||
				    !plan->dir_resolution.sid[depth])
					return -EOPNOTSUPP;
				if (crsec->create_sid) {
					sid = crsec->create_sid;
					object_handle = global_sid_handle_dup(
						crsec->create_sid_handle);
				} else {
					object_handle = security_transition_sid_handle(
						crsec->state, crsec->sid,
						plan->dir_resolution.sid[depth],
						plan->tclass, &plan->name, &sid);
				}
				if (IS_ERR(object_handle)) {
					rc = PTR_ERR(object_handle);
					break;
				}
				if (!sid || global_sid_handle_sid(object_handle) != sid) {
					global_sid_handle_put(object_handle);
					rc = -ESTALE;
					break;
				}
				plan->object_handles[depth] = object_handle;
				if (!selinux_policy_snapshot_valid(
					    crsec->state, &plan->chain.policy[i])) {
					rc = -ESTALE;
					break;
				}
				plan->object_resolution.sid[depth] = sid;
			}
			if (rc == -EAGAIN || rc == -ESTALE)
				goto retry_stale;
			if (rc)
				return rc;
			if (anchor_depth > plan->object_resolution.max_depth ||
			    !plan->object_resolution.sid[anchor_depth])
				return -EXDEV;
			plan->anchor_sid =
				plan->object_resolution.sid[anchor_depth];
			plan->anchor_handle = global_sid_handle_dup(
				plan->object_handles[anchor_depth]);
			if (IS_ERR(plan->anchor_handle)) {
				rc = PTR_ERR(plan->anchor_handle);
				plan->anchor_handle = NULL;
				return rc;
			}
			plan->anchor_label =
				global_sid_handle_label_get(plan->anchor_handle);
			if (!plan->anchor_label)
				goto retry_stale;
			if (plan->anchor_label->domain != plan->anchor_domain)
				return -EXDEV;
			rc = selinux_label_view_resolve_chain(
				plan->view, plan->anchor_label, plan->anchor_sid,
				&projected);
			if (rc == -EAGAIN || rc == -ESTALE)
				goto retry_stale;
			if (rc)
				return rc;
			for (i = 0; i < plan->chain.count; i++) {
				const struct cred_security_struct *crsec =
					selinux_cred(plan->chain.cred[i]);
				u16 depth = crsec->state->label_domain->depth;

				if (projected.domain_id[depth] !=
					    crsec->state->label_domain->id ||
				    projected.sid[depth] !=
					    plan->object_resolution.sid[depth])
					return -EXDEV;
			}
			plan->object_resolution = projected;
			plan->source = SELINUX_LABEL_SOURCE_TRANSITION;
		}
		plan->provenance[1] = (struct selinux_avc_provenance) {
			.label = plan->anchor_label,
			.view = plan->view,
			.source = plan->source,
		};

		for (i = 0; i < plan->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(plan->chain.cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&plan->chain.policy[i];
			u16 depth = crsec->state->label_domain->depth;

			if (depth > plan->sb_resolution.max_depth ||
			    plan->sb_resolution.domain_id[depth] !=
				    crsec->state->label_domain->id ||
			    !plan->sb_resolution.sid[depth] ||
			    !plan->object_resolution.sid[depth])
				return -EOPNOTSUPP;
			levels[count] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = plan->dir_resolution.sid[depth],
				.tclass = SECCLASS_DIR,
				.requested = DIR__ADD_NAME | DIR__SEARCH,
				.provenance = &plan->provenance[0],
			};
			snapshots[count++] = *snapshot;
			levels[count] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = plan->object_resolution.sid[depth],
				.tclass = plan->tclass,
				.requested = FILE__CREATE,
				.provenance = &plan->provenance[1],
			};
			snapshots[count++] = *snapshot;
			levels[count] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = plan->object_resolution.sid[depth],
				.tsid = plan->sb_resolution.sid[depth],
				.tclass = SECCLASS_FILESYSTEM,
				.requested = FILESYSTEM__ASSOCIATE,
				.provenance = &plan->provenance[2],
			};
			snapshots[count++] = *snapshot;
		}
		if (!selinux_policy_chain_snapshot_valid(&plan->chain))
			goto retry_stale;

		if (plan->requires_xattr) {
			const char *context;
			u32 context_len;

			rcu_read_lock();
			rc = security_sid_to_context_force(
				plan->anchor_state, plan->anchor_sid, &context,
				&context_len);
			if (!rc) {
				plan->xattr_value = kmemdup(
					context, context_len, GFP_ATOMIC);
				if (!plan->xattr_value)
					rc = -ENOMEM;
			}
			rcu_read_unlock();
			if (rc == -EAGAIN || rc == -ESTALE)
				goto retry_stale;
			if (rc)
				return rc;
			plan->xattr_value_len = context_len;
			if (!selinux_policy_chain_snapshot_valid(&plan->chain))
				goto retry_stale;
		}

		rc = selinux_avc_transaction_has_perm_workspace(
			levels, snapshots, count, &ad, workspace);
		if (rc == -ESTALE)
			goto retry_stale;
		return rc;

retry_stale:
		kfree(plan->xattr_value);
		plan->xattr_value = NULL;
		plan->xattr_value_len = 0;
		if (plan->anchor_label) {
			selinux_label_ref_put(plan->anchor_label);
			plan->anchor_label = NULL;
		}
		global_sid_handle_put(plan->anchor_handle);
		plan->anchor_handle = NULL;
		for (i = 0; i <= SELINUX_LABEL_RESOLUTION_MAX_DEPTH; i++) {
			global_sid_handle_put(plan->object_handles[i]);
			plan->object_handles[i] = NULL;
		}
	}
	return -ESTALE;
}

static int selinux_inode_create_plan_prepare(
	struct security_inode_create_plan *generic, const struct vfsmount *mnt,
	struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct selinux_inode_create_plan *plan =
		selinux_inode_create_plan_security(generic);
	struct superblock_security_struct *sbsec;
	struct task_security_struct *tsec = selinux_task(current);
	const struct cred_security_struct *crsec =
		selinux_cred(current_cred());
	const struct selinux_label_view *view;
	bool legacy_identity;
	unsigned short behavior;
	u32 dir_sid, mntpoint_sid, sb_sid;
	u16 dir_class;
	u8 dir_source;
	int rc;

	if (IS_PRIVATE(dir))
		return 0;
	/* There is no stable policy generation to seal before first load. */
	if (!selinux_initialized(crsec->state)
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	    && !tsec->create_plan_kunit_force
#endif
	)
		return selinux_cred_chain_uninitialized(current_cred()) ?
			0 : -EACCES;
	view = selinux_mnt_label_view(mnt);
	if (!view)
		return -EOPNOTSUPP;
	memset(plan, 0, sizeof(*plan));
	plan->generic = generic;
	plan->previous = tsec->create_plan;
	plan->dentry = dentry;
	plan->dir = dir;
	plan->sb = dir->i_sb;
	plan->tclass = inode_mode_to_security_class(mode);
	plan->view = selinux_label_view_get(view);
	plan->actor = get_current_cred();
	plan->owner_task = current;
	plan->owner_tsec = tsec;
	plan->name.name = kmemdup_nul(dentry->d_name.name,
				      dentry->d_name.len, GFP_KERNEL);
	if (!plan->name.name) {
		rc = -ENOMEM;
		goto out;
	}
	plan->name.len = dentry->d_name.len;
	plan->name.hash = dentry->d_name.hash;

	rc = selinux_inode_create_plan_inode_label(
		dir, &plan->dir_label, &dir_sid, &dir_class, &dir_source);
	if (rc)
		goto out;
	if (dir_class != SECCLASS_DIR) {
		rc = -ENOTDIR;
		goto out;
	}
	sbsec = selinux_superblock(dir->i_sb);
	mutex_lock(&sbsec->lock);
	if (!sbsec->anchor_state || !sbsec->anchor_domain ||
	    sbsec->anchor_state->label_domain != sbsec->anchor_domain) {
		rc = -EXDEV;
		goto out_sb;
	}
	plan->anchor_state = get_selinux_state(sbsec->anchor_state);
	plan->anchor_domain =
		selinux_label_domain_get(sbsec->anchor_domain);
	sb_sid = sbsec->sid;
	mntpoint_sid = sbsec->mntpoint_sid;
	behavior = sbsec->behavior;
	if (behavior == SECURITY_FS_USE_MNTPOINT) {
		if (!sbsec->mntpoint_sid_handle ||
		    global_sid_handle_sid(sbsec->mntpoint_sid_handle) !=
			    mntpoint_sid) {
			rc = -ESTALE;
			goto out_sb;
		}
		plan->mntpoint_handle =
			global_sid_handle_dup(sbsec->mntpoint_sid_handle);
		if (IS_ERR(plan->mntpoint_handle)) {
			rc = PTR_ERR(plan->mntpoint_handle);
			plan->mntpoint_handle = NULL;
			goto out_sb;
		}
	}
	/*
	 * Preserve the legacy single-policy host path.  It has an identity view
	 * only because every mount now carries a view; requiring the new explicit
	 * filesystem commit protocol there would reject otherwise supported host
	 * filesystems.  Any nested, mapped, or cross-domain view remains strict.
	 */
	legacy_identity = (view->flags & SELINUX_LABEL_VIEW_IDENTITY) &&
			  !view->map_count &&
			  view->origin_domain == view->outer_domain &&
			  view->origin_domain == crsec->state->label_domain &&
			  !crsec->parent_cred && !crsec->state->depth &&
			  !crsec->state->label_domain->depth &&
			  plan->anchor_state == crsec->state &&
			  plan->anchor_domain == crsec->state->label_domain;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (tsec->create_plan_kunit_force)
		legacy_identity = false;
#endif
	plan->requires_commit = selinux_is_sblabel_mnt(dir->i_sb) &&
				!legacy_identity;
	plan->requires_xattr = plan->requires_commit &&
			       behavior != SECURITY_FS_USE_GENFS;
	if (plan->requires_commit)
		generic->requirements |= SECURITY_INODE_CREATE_REQUIRE_COMMIT;
	if (plan->requires_xattr)
		generic->requirements |= SECURITY_INODE_CREATE_REQUIRE_XATTR;
	rc = 0;
out_sb:
	mutex_unlock(&sbsec->lock);
	if (rc)
		goto out;
	if (view->origin_domain != plan->anchor_domain) {
		rc = -EXDEV;
		goto out;
	}
	plan->sb_label = global_sid_to_label_ref(sb_sid);
	if (IS_ERR(plan->sb_label)) {
		rc = PTR_ERR(plan->sb_label);
		plan->sb_label = NULL;
		goto out;
	}
	rc = selinux_label_view_resolve_chain(
		view, plan->dir_label, dir_sid, &plan->dir_resolution);
	if (rc)
		goto out;
	rc = selinux_label_view_resolve_chain(
		view, plan->sb_label, sb_sid, &plan->sb_resolution);
	if (rc)
		goto out;
	plan->provenance[0] = (struct selinux_avc_provenance) {
		.label = plan->dir_label,
		.view = plan->view,
		.source = dir_source,
	};
	plan->provenance[2] = (struct selinux_avc_provenance) {
		.label = plan->sb_label,
		.view = plan->view,
		.source = SELINUX_LABEL_SOURCE_FILESYSTEM,
	};
	rc = selinux_inode_create_plan_authorize(plan, dentry, mntpoint_sid,
						 behavior);
	if (rc)
		goto out;
	plan->committed = !plan->requires_commit;
	tsec->create_plan = plan;
	return 0;
out:
	selinux_inode_create_plan_release(plan);
	return rc;
}

static int selinux_inode_create_plan_finish(
	struct security_inode_create_plan *generic, int result,
	struct inode *created_inode)
{
	struct selinux_inode_create_plan *plan =
		selinux_inode_create_plan_security(generic);
	struct task_security_struct *tsec = selinux_task(current);
	struct selinux_inode_create_plan *cursor, *next, *previous;
	int tuple_rc;

	if (!plan->generic)
		return plan->poisoned ? -EPROTO : 0;
	/* A foreign plan must never be allowed to mutate this task's stack. */
	if (selinux_inode_create_plan_owner_valid(plan, generic))
		return -EPROTO;
	if (tsec->create_plan != plan) {
		cursor = tsec->create_plan;
		while (cursor && cursor != plan) {
			next = cursor->previous;
			selinux_inode_create_plan_release(cursor);
			cursor->poisoned = true;
			cursor = next;
		}
		if (cursor == plan) {
			previous = plan->previous;
			selinux_inode_create_plan_release(plan);
			plan->poisoned = true;
			tsec->create_plan = previous;
		} else {
			tsec->create_plan = NULL;
			selinux_inode_create_plan_release(plan);
			plan->poisoned = true;
		}
		return -EPROTO;
	}
	previous = plan->previous;
	/* Authorization is linearized before the filesystem's first effect. */
	if (!result && plan->requires_commit) {
		if (!plan->committed || !created_inode ||
		    plan->inode != created_inode)
			tuple_rc = -EPROTO;
		else
			tuple_rc = selinux_inode_create_plan_tuple_valid(
				plan, created_inode);
		if (tuple_rc) {
			if (created_inode)
				selinux_inode_security_invalidate(created_inode);
			if (plan->inode && plan->inode != created_inode)
				selinux_inode_security_invalidate(plan->inode);
			result = tuple_rc;
		}
	}
	tsec->create_plan = previous;
	selinux_inode_create_plan_release(plan);
	return result;
}
#endif

#define MAY_LINK	0
#define MAY_UNLINK	1
#define MAY_RMDIR	2

/* Check whether a task can link, unlink, or rmdir a file/directory. */
static int may_link(const struct vfsmount *dir_mnt,
		    const struct vfsmount *obj_mnt, struct inode *dir,
		    struct dentry *dentry,
		    int kind)

{
	const struct cred *cred = current_cred();
#ifndef CONFIG_SECURITY_SELINUX_NS
	struct inode_security_struct *dsec, *isec;
#endif
	struct common_audit_data ad;
	u32 av;
	int rc;

#ifndef CONFIG_SECURITY_SELINUX_NS
	dsec = inode_security(dir);
	isec = backing_inode_security(dentry);
#endif

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;

	av = DIR__SEARCH;
	av |= (kind ? DIR__REMOVE_NAME : DIR__ADD_NAME);
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = inode_has_perm_view(cred, dir, selinux_mnt_label_view(dir_mnt), av,
				 &ad);
#else
	rc = cred_tsid_has_perm(cred, dsec->sid, SECCLASS_DIR, av, &ad);
#endif
	if (rc)
		return rc;

	switch (kind) {
	case MAY_LINK:
		av = FILE__LINK;
		break;
	case MAY_UNLINK:
		av = FILE__UNLINK;
		break;
	case MAY_RMDIR:
		av = DIR__RMDIR;
		break;
	default:
		pr_warn("SELinux: %s:  unrecognized kind %d\n",
			__func__, kind);
		return 0;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	return inode_has_perm_view(cred, d_backing_inode(dentry),
				   selinux_mnt_label_view(obj_mnt), av, &ad);
#else
	return cred_tsid_has_perm(cred, isec->sid, isec->sclass, av, &ad);
#endif
}

static inline int may_rename(const struct vfsmount *old_mnt,
			     struct inode *old_dir,
			     struct dentry *old_dentry,
			     const struct vfsmount *new_mnt,
			     struct inode *new_dir,
			     struct dentry *new_dentry)
{
	const struct cred *cred = current_cred();
#ifndef CONFIG_SECURITY_SELINUX_NS
	struct inode_security_struct *old_dsec, *new_dsec, *old_isec, *new_isec;
#endif
	struct common_audit_data ad;
	u32 av;
	int old_is_dir, new_is_dir;
	int rc;

#ifndef CONFIG_SECURITY_SELINUX_NS
	old_dsec = inode_security(old_dir);
	old_isec = backing_inode_security(old_dentry);
#endif
	old_is_dir = d_is_dir(old_dentry);
#ifndef CONFIG_SECURITY_SELINUX_NS
	new_dsec = inode_security(new_dir);
#endif

	ad.type = LSM_AUDIT_DATA_DENTRY;

	ad.u.dentry = old_dentry;
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = inode_has_perm_view(cred, old_dir, selinux_mnt_label_view(old_mnt),
				 DIR__REMOVE_NAME | DIR__SEARCH, &ad);
#else
	rc = cred_tsid_has_perm(cred, old_dsec->sid, SECCLASS_DIR,
				DIR__REMOVE_NAME | DIR__SEARCH, &ad);
#endif
	if (rc)
		return rc;
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = inode_has_perm_view(cred, d_backing_inode(old_dentry),
				 selinux_mnt_label_view(old_mnt), FILE__RENAME, &ad);
#else
	rc = cred_tsid_has_perm(cred, old_isec->sid, old_isec->sclass,
				FILE__RENAME, &ad);
#endif
	if (rc)
		return rc;
	if (old_is_dir && new_dir != old_dir) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = inode_has_perm_view(cred, d_backing_inode(old_dentry),
					 selinux_mnt_label_view(old_mnt),
					 DIR__REPARENT, &ad);
#else
		rc = cred_tsid_has_perm(cred, old_isec->sid, old_isec->sclass,
					DIR__REPARENT, &ad);
#endif
		if (rc)
			return rc;
	}

	ad.u.dentry = new_dentry;
	av = DIR__ADD_NAME | DIR__SEARCH;
	if (d_is_positive(new_dentry))
		av |= DIR__REMOVE_NAME;
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = inode_has_perm_view(cred, new_dir, selinux_mnt_label_view(new_mnt),
				 av, &ad);
#else
	rc = cred_tsid_has_perm(cred, new_dsec->sid, SECCLASS_DIR, av, &ad);
#endif
	if (rc)
		return rc;
	if (d_is_positive(new_dentry)) {
#ifndef CONFIG_SECURITY_SELINUX_NS
		new_isec = backing_inode_security(new_dentry);
#endif
		new_is_dir = d_is_dir(new_dentry);
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = inode_has_perm_view(cred, d_backing_inode(new_dentry),
					 selinux_mnt_label_view(new_mnt),
					 new_is_dir ? DIR__RMDIR : FILE__UNLINK,
					 &ad);
#else
		rc = cred_tsid_has_perm(cred, new_isec->sid, new_isec->sclass,
					(new_is_dir ? DIR__RMDIR : FILE__UNLINK),
					&ad);
#endif
		if (rc)
			return rc;
	}

	return 0;
}

/* Check whether a task can perform a filesystem operation. */
static int superblock_has_perm(const struct cred *cred,
					const struct super_block *sb,
					u32 perms,
					struct common_audit_data *ad)
{
	struct superblock_security_struct *sbsec;

	sbsec = selinux_superblock(sb);
#ifdef CONFIG_SECURITY_SELINUX_NS
	return cred_sid_identity_has_perm(
		cred, sbsec->sid, SECCLASS_FILESYSTEM, perms, ad);
#else
	return cred_tsid_has_perm(cred, sbsec->sid, SECCLASS_FILESYSTEM, perms,
				  ad);
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int superblock_has_perm_mnt(const struct cred *cred,
				   const struct super_block *sb,
				   const struct vfsmount *mnt, u32 perms,
				   struct common_audit_data *ad)
{
	const struct superblock_security_struct *sbsec = selinux_superblock(sb);

	if (!mnt)
		return superblock_has_perm(cred, sb, perms, ad);
	return sid_has_perm_mnt(cred, mnt, sbsec->sid, SECCLASS_FILESYSTEM,
				perms, ad);
}
#endif

/* Convert a Linux mode and permission mask to an access vector. */
static inline u32 file_mask_to_av(int mode, int mask)
{
	u32 av = 0;

	if (!S_ISDIR(mode)) {
		if (mask & MAY_EXEC)
			av |= FILE__EXECUTE;
		if (mask & MAY_READ)
			av |= FILE__READ;

		if (mask & MAY_APPEND)
			av |= FILE__APPEND;
		else if (mask & MAY_WRITE)
			av |= FILE__WRITE;

	} else {
		if (mask & MAY_EXEC)
			av |= DIR__SEARCH;
		if (mask & MAY_WRITE)
			av |= DIR__WRITE;
		if (mask & MAY_READ)
			av |= DIR__READ;
	}

	return av;
}

/* Convert a Linux file to an access vector. */
static inline u32 file_to_av(const struct file *file)
{
	u32 av = 0;

	if (file->f_mode & FMODE_READ)
		av |= FILE__READ;
	if (file->f_mode & FMODE_WRITE) {
		if (file->f_flags & O_APPEND)
			av |= FILE__APPEND;
		else
			av |= FILE__WRITE;
	}
	if (!av) {
		/*
		 * Special file opened with flags 3 for ioctl-only use.
		 */
		av = FILE__IOCTL;
	}

	return av;
}

/* Hook functions begin here. */

static int selinux_binder_set_context_mgr(const struct cred *mgr)
{
	return cred_other_has_perm(current_cred(), mgr, SECCLASS_BINDER,
				   BINDER__SET_CONTEXT_MGR, NULL);
}

static int selinux_binder_transaction(const struct cred *from,
				      const struct cred *to)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	return cred_binder_transaction_has_perm(current_cred(), from, to);
#else
	u32 mysid = current_sid();
	u32 fromsid = cred_sid(from);
	int rc;

	if (mysid != fromsid) {
		rc = cred_other_has_perm(current_cred(), from,
					 SECCLASS_BINDER,
					 BINDER__IMPERSONATE, NULL);
		if (rc)
			return rc;
	}

	return cred_other_has_perm(from, to, SECCLASS_BINDER, BINDER__CALL,
				   NULL);
#endif
}

static int selinux_binder_transfer_binder(const struct cred *from,
					  const struct cred *to)
{
	return cred_other_has_perm(from, to, SECCLASS_BINDER,
				   BINDER__TRANSFER, NULL);
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_file_transfer_cred_advance(const struct cred **cursor)
{
	const struct cred_security_struct *current_sec, *parent_sec;
	const struct cred *next;

	if (!cursor || !*cursor)
		return -EINVAL;
	current_sec = selinux_cred(*cursor);
	if (!current_sec->state || !current_sec->state->label_domain ||
	    current_sec->state->depth != current_sec->state->label_domain->depth)
		return -EXDEV;
	next = current_sec->parent_cred;
	if (!next) {
		if (current_sec->state->parent ||
		    current_sec->state->label_domain->parent ||
		    current_sec->state->depth)
			return -EXDEV;
		*cursor = NULL;
		return 0;
	}
	parent_sec = selinux_cred(next);
	if (!parent_sec->state || !parent_sec->state->label_domain ||
	    current_sec->state->parent != parent_sec->state ||
	    current_sec->state->label_domain->parent !=
		    parent_sec->state->label_domain ||
	    current_sec->state->depth != parent_sec->state->depth + 1 ||
	    current_sec->state->label_domain->depth !=
		    parent_sec->state->label_domain->depth + 1)
		return -EXDEV;
	*cursor = next;
	return 0;
}

static int selinux_file_operation_has_perm(
	const struct cred *cred, const struct file *file, const struct cred *opener,
	struct inode *inode, const struct selinux_label_view *view,
	const struct selinux_pathless_projection *pathless,
	const struct selinux_file_operation_check *check, bool include_carriers,
	struct common_audit_data *ad)
{
	struct selinux_avc_transaction_workspace *workspace;
	struct selinux_file_transfer_transaction *transaction;
	bool same_cred;
	unsigned int retry;
	int rc = -ESTALE;

	if (!cred || !file || !opener || !inode)
		return -EIO;
	/*
	 * Before the initial policy load, file and inode security blobs do not
	 * carry a resolvable label tuple yet.  Preserve the root policy-less
	 * bootstrap semantics for every operation routed through this common
	 * helper.  A policy-less child with an initialized ancestor must still
	 * enter the transaction below so that the ancestor policy is enforced.
	 */
	if (!selinux_initialized(selinux_cred(cred)->state) &&
	    selinux_cred_chain_uninitialized(cred))
		return 0;
	same_cred = cred_sid_chain_equal(cred, opener);
	transaction = kzalloc_obj(*transaction, GFP_KERNEL);
	if (!transaction)
		return -ENOMEM;
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_FILE_TRANSFER_MAX_CHECKS, GFP_KERNEL);
	if (!workspace) {
		rc = -ENOMEM;
		goto out_transaction;
	}

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		struct selinux_inode_label_snapshot snapshot = {};
		struct selinux_pathless_chain_resolution *pathless_line =
			&transaction->pathless_line;
		struct selinux_label_operation_resolution *path_line =
			&transaction->path_line;
		const struct selinux_pathless_projection *projection = pathless;
		const struct selinux_avc_provenance *provenance;
		struct selinux_label_resolution resolution;
		bool chain_valid;
		u16 i;

		transaction->count = 0;
		transaction->provenance_count = 0;
		rc = selinux_policy_chain_snapshot_read(
			cred, &transaction->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		if (projection) {
			/* fsec/bfsec must still describe the published source tuple. */
			if (view != projection->view) {
				rc = -EXDEV;
				goto release_identity;
			}
			rc = selinux_pathless_projection_resolve_cred_chain(
				projection, transaction->chain.cred,
				transaction->chain.policy, transaction->chain.count,
				pathless_line);
			if (rc)
				goto release_identity;
		}

		if (!same_cred) {
			const struct cred *lca_opener = opener;
			const struct cred_security_struct *lca_sec = NULL;
			struct selinux_label_ref *lca_label;
			u16 lca_actor_index = 0;

			while (lca_opener && !lca_sec) {
				const struct cred_security_struct *candidate =
					selinux_cred(lca_opener);

				for (i = 0; i < transaction->chain.count; i++)
					if (candidate->state->label_domain ==
					    selinux_cred(transaction->chain.cred[i])->
						    state->label_domain) {
						lca_sec = candidate;
						lca_actor_index = i;
						break;
					}
				if (!lca_sec) {
					rc = selinux_file_transfer_cred_advance(&lca_opener);
					if (rc)
						goto release_identity;
				}
			}
			if (!lca_sec) {
				rc = -EXDEV;
				goto release_identity;
			}
			lca_label = global_sid_handle_label_get(lca_sec->sid_handle);
			if (IS_ERR(lca_label)) {
				rc = PTR_ERR(lca_label);
				goto release_identity;
			}
			rc = selinux_label_view_resolve_operation(
				NULL, lca_label, lca_sec->sid,
				selinux_cred(transaction->chain.cred[0])->
					state->label_domain,
				&transaction->opener_line);
			selinux_label_ref_put(lca_label);
			if (rc)
				goto release_identity;
			for (i = lca_actor_index; i < transaction->chain.count; i++) {
				const struct cred_security_struct *source_sec =
					selinux_cred(lca_opener);
				const struct cred_security_struct *actor_sec =
					selinux_cred(transaction->chain.cred[i]);
				u16 depth = actor_sec->state->label_domain->depth;

				if (source_sec->state->label_domain !=
					    actor_sec->state->label_domain ||
				    global_sid_handle_sid(source_sec->sid_handle) !=
					    source_sec->sid) {
					rc = -EXDEV;
					goto release_identity;
				}
				transaction->opener_line.labels.sid[depth] =
					source_sec->sid;
				if (i + 1 < transaction->chain.count) {
					rc = selinux_file_transfer_cred_advance(&lca_opener);
					if (rc)
						goto release_identity;
				}
			}
			for (i = 0; i < transaction->chain.count; i++) {
				const struct cred_security_struct *crsec =
					selinux_cred(transaction->chain.cred[i]);
				u16 depth = crsec->state->label_domain->depth;
				u32 opener_sid =
					transaction->opener_line.labels.sid[depth];

				if (!opener_sid ||
				    transaction->opener_line.labels.domain_id[depth] !=
					    crsec->state->label_domain->id) {
					rc = -EOPNOTSUPP;
					break;
				}
				rc = selinux_file_transfer_transaction_add(
					transaction,
					&(struct selinux_avc_level) {
						.state = crsec->state,
						.ssid = crsec->sid,
						.tsid = opener_sid,
						.tclass = SECCLASS_FD,
						.requested = FD__USE,
					},
					&transaction->chain.policy[i]);
				if (rc)
					break;
			}
			if (rc)
				goto release_identity;
		}

		if (include_carriers) {
#ifdef CONFIG_BPF_SYSCALL
			rc = bpf_fd_pass_add(file, cred, transaction);
			if (rc)
				goto release_identity;
#endif
#ifdef CONFIG_PERF_EVENTS
			rc = perf_fd_pass_add(file, cred, transaction);
			if (rc)
				goto release_identity;
#endif
		}

		if (!check || !check->requested || unlikely(IS_PRIVATE(inode)))
			goto decide;
		if (projection) {
			rc = selinux_file_transfer_transaction_provenance(
				transaction, projection->label, projection->view,
				projection->source, &provenance);
		} else if (!view) {
			rc = -EOPNOTSUPP;
		} else {
			rc = selinux_inode_label_snapshot_get(
				inode_security_novalidate(inode), &snapshot);
			if (!rc)
				rc = selinux_label_view_resolve_operation(
					view, snapshot.label, snapshot.sid,
					selinux_cred(transaction->chain.cred[0])->
						state->label_domain,
					path_line);
			if (!rc)
				resolution = path_line->labels;
			if (!rc)
				rc = selinux_file_transfer_transaction_provenance(
					transaction, snapshot.label, view,
					snapshot.source, &provenance);
		}
		if (rc)
			goto release_identity;

		for (i = 0; i < transaction->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(transaction->chain.cred[i]);
			struct selinux_avc_provenance level_provenance = *provenance;
			u32 policy_tsid;
			u16 policy_tclass;
			u64 map_generation;

			if (projection) {
				struct selinux_pathless_resolution resolved;

				resolved = pathless_line->level[
					crsec->state->label_domain->depth];
				policy_tsid = resolved.sid;
				policy_tclass = check->tclass ?: resolved.sclass;
				map_generation = resolved.map_generation;
			} else {
				u16 depth = crsec->state->label_domain->depth;

				if (depth > resolution.max_depth ||
				    resolution.domain_id[depth] !=
					    crsec->state->label_domain->id ||
				    !resolution.sid[depth]) {
					rc = -EOPNOTSUPP;
					break;
				}
				policy_tsid = resolution.sid[depth];
				policy_tclass = check->tclass ?: snapshot.sclass;
				map_generation = path_line->map_generation[depth];
			}
			level_provenance.map_generation = map_generation;
			rc = selinux_file_transfer_transaction_add(
				transaction,
				&(struct selinux_avc_level) {
					.state = crsec->state,
					.ssid = crsec->sid,
					.tsid = policy_tsid,
					.tclass = policy_tclass,
					.requested = check->requested,
					.skip_policycap = check->skip_policycap,
					.decision_kind = check->decision_kind,
					.driver = check->driver,
					.base_perm = check->base_perm,
					.xperm = check->xperm,
					.provenance = &level_provenance,
				},
				&transaction->chain.policy[i]);
			if (rc)
				break;
		}
		if (rc)
			goto release_identity;

decide:
		if (!transaction->count) {
			rc = selinux_policy_chain_snapshot_valid(
				&transaction->chain) ? 0 : -ESTALE;
		} else {
			rc = selinux_avc_transaction_has_perm_composite_guarded_workspace(
				transaction->levels, transaction->snapshots,
				transaction->count, NULL, NULL, 0, 0, ad, workspace);
		}

release_identity:
		chain_valid = selinux_policy_chain_snapshot_valid(
			&transaction->chain);
		selinux_inode_label_snapshot_put(&snapshot);
		selinux_pathless_chain_resolution_put(pathless_line);
		selinux_label_operation_resolution_put(path_line);
		selinux_label_operation_resolution_put(&transaction->opener_line);
		selinux_pathless_chain_resolution_put(&transaction->bpf_line);
		selinux_pathless_chain_resolution_put(&transaction->perf_line);
		if (rc == -EAGAIN || rc == -ESTALE ||
		    !chain_valid) {
			rc = -ESTALE;
			continue;
		}
		break;
	}

	selinux_avc_transaction_workspace_free(workspace);
out_transaction:
	kfree(transaction);
	return rc;
}

static int selinux_file_transfer_has_perm(
	const struct cred *cred, const struct file *file, const struct cred *opener,
	struct inode *inode, const struct selinux_label_view *view,
	const struct selinux_pathless_projection *pathless, u32 requested,
	struct common_audit_data *ad)
{
	const struct selinux_file_operation_check check = {
		.requested = requested,
	};

	return selinux_file_operation_has_perm(
		cred, file, opener, inode, view, pathless, &check, true, ad);
}
#endif

static int selinux_binder_transfer_file(const struct cred *from,
					const struct cred *to,
					const struct file *file)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct file_security_struct *fsec = selinux_file(file);
#endif
	struct dentry *dentry = file->f_path.dentry;
	struct common_audit_data ad;
#ifndef CONFIG_SECURITY_SELINUX_NS
	int rc;
#endif

	ad.type = LSM_AUDIT_DATA_PATH;
	ad.u.path = file->f_path;

#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_file_transfer_has_perm(
		to, file, file->f_cred, d_backing_inode(dentry), fsec->view,
		fsec->pathless, file_to_av(file), &ad);
#else
	rc = file_use_has_perm(to, file, &ad);
	if (rc)
		return rc;

#ifdef CONFIG_BPF_SYSCALL
	rc = bpf_fd_pass(file, to);
	if (rc)
		return rc;
#endif

	if (unlikely(IS_PRIVATE(d_backing_inode(dentry))))
		return 0;
	return inode_has_perm(to, d_backing_inode(dentry), file_to_av(file),
			      &ad);
#endif
}

static int selinux_ptrace_access_check(struct task_struct *child,
				       unsigned int mode)
{
	if (mode & PTRACE_MODE_READ)
		return cred_task_has_perm(current_cred(), child,
					  SECCLASS_FILE, FILE__READ, NULL);

	return cred_task_has_perm(current_cred(), child, SECCLASS_PROCESS,
				  PROCESS__PTRACE, NULL);
}

static int selinux_ptrace_traceme(struct task_struct *parent)
{
	return task_obj_has_perm(parent, current, SECCLASS_PROCESS,
				 PROCESS__PTRACE, NULL);
}

static int selinux_capget(const struct task_struct *target, kernel_cap_t *effective,
			  kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return cred_task_has_perm(current_cred(), target, SECCLASS_PROCESS,
				  PROCESS__GETCAP, NULL);
}

static int selinux_capset(struct cred *new, const struct cred *old,
			  const kernel_cap_t *effective,
			  const kernel_cap_t *inheritable,
			  const kernel_cap_t *permitted)
{
	return cred_other_has_perm(old, new, SECCLASS_PROCESS,
				   PROCESS__SETCAP, NULL);
}

/*
 * (This comment used to live with the selinux_task_setuid hook,
 * which was removed).
 *
 * Since setuid only affects the current process, and since the SELinux
 * controls are not based on the Linux identity attributes, SELinux does not
 * need to control this operation.  However, SELinux does control the use of
 * the CAP_SETUID and CAP_SETGID capabilities using the capable hook.
 */

static int selinux_capable(const struct cred *cred, struct user_namespace *ns,
			   int cap, unsigned int opts)
{
	return cred_has_capability(cred, cap, opts, ns == &init_user_ns);
}

static int selinux_quotactl(int cmds, int type, int id, const struct super_block *sb)
{
	const struct cred *cred = current_cred();
	int rc = 0;

	if (!sb)
		return 0;

	switch (cmds) {
	case Q_SYNC:
	case Q_QUOTAON:
	case Q_QUOTAOFF:
	case Q_SETINFO:
	case Q_SETQUOTA:
	case Q_XQUOTAOFF:
	case Q_XQUOTAON:
	case Q_XSETQLIM:
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = superblock_has_perm_mnt(
			cred, sb, NULL, FILESYSTEM__QUOTAMOD, NULL);
#else
		rc = superblock_has_perm(
			cred, sb, FILESYSTEM__QUOTAMOD, NULL);
#endif
		break;
	case Q_GETFMT:
	case Q_GETINFO:
	case Q_GETQUOTA:
	case Q_XGETQUOTA:
	case Q_XGETQSTAT:
	case Q_XGETQSTATV:
	case Q_XGETNEXTQUOTA:
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = superblock_has_perm_mnt(
			cred, sb, NULL, FILESYSTEM__QUOTAGET, NULL);
#else
		rc = superblock_has_perm(
			cred, sb, FILESYSTEM__QUOTAGET, NULL);
#endif
		break;
	default:
		rc = 0;  /* let the kernel handle invalid cmds */
		break;
	}
	return rc;
}

static int selinux_quota_on(const struct vfsmount *mnt,
			    struct dentry *dentry)
{
	const struct cred *cred = current_cred();

	return dentry_has_perm_mnt(cred, mnt, dentry, FILE__QUOTAON);
}

static int selinux_syslog(int type)
{
	const struct cred *cred = current_cred();

	switch (type) {
	case SYSLOG_ACTION_READ_ALL:	/* Read last kernel messages */
	case SYSLOG_ACTION_SIZE_BUFFER:	/* Return size of the log buffer */
		return cred_tsid_has_perm(cred, SECINITSID_KERNEL,
					  SECCLASS_SYSTEM,
					  SYSTEM__SYSLOG_READ, NULL);
	case SYSLOG_ACTION_CONSOLE_OFF:	/* Disable logging to console */
	case SYSLOG_ACTION_CONSOLE_ON:	/* Enable logging to console */
	/* Set level of messages printed to console */
	case SYSLOG_ACTION_CONSOLE_LEVEL:
		return cred_tsid_has_perm(cred, SECINITSID_KERNEL,
					  SECCLASS_SYSTEM,
					  SYSTEM__SYSLOG_CONSOLE, NULL);
	}
	/* All other syslog types */
	return cred_tsid_has_perm(cred, SECINITSID_KERNEL, SECCLASS_SYSTEM,
				  SYSTEM__SYSLOG_MOD, NULL);
}

/*
 * Check permission for allocating a new virtual mapping. Returns
 * 0 if permission is granted, negative error code if not.
 *
 * Do not audit the selinux permission check, as this is applied to all
 * processes that allocate mappings.
 */
static int selinux_vm_enough_memory(struct mm_struct *mm, long pages)
{
	return cred_has_capability(current_cred(), CAP_SYS_ADMIN,
				   CAP_OPT_NOAUDIT, true);
}

/* binprm security operations */

static u32 ptrace_parent_sid(void)
{
	u32 sid = 0;
	struct task_struct *tracer;

	rcu_read_lock();
	tracer = ptrace_parent(current);
	if (tracer)
		sid = task_sid_obj(tracer);
	rcu_read_unlock();

	return sid;
}

static int check_nnp_nosuid(const struct linux_binprm *bprm,
			    const struct cred_security_struct *old_crsec,
			    const struct cred_security_struct *new_crsec,
			    const struct selinux_policy_snapshot *snapshot)
{
	struct selinux_state *state = old_crsec->state;
	int nnp = (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS);
	int nosuid = !mnt_may_suid(bprm->file->f_path.mnt);
	int rc;
	u32 av;

	if (!nnp && !nosuid)
		return 0; /* neither NNP nor nosuid */

	if (new_crsec->sid == old_crsec->sid)
		return 0; /* No change in credentials */

	/*
	 * If the policy enables the nnp_nosuid_transition policy capability,
	 * then we permit transitions under NNP or nosuid if the
	 * policy allows the corresponding permission between
	 * the old and new contexts.
	 */
	if (selinux_policycap_nnp_nosuid_transition(snapshot)) {
		av = 0;
		if (nnp)
			av |= PROCESS2__NNP_TRANSITION;
		if (nosuid)
			av |= PROCESS2__NOSUID_TRANSITION;
		/*
		 * Only check against the current SELinux namespace
		 * because only the SID in the current namespace
		 * is changed by a transition.
		 */
		rc = avc_has_perm_snapshot(state, snapshot, old_crsec->sid,
				   new_crsec->sid, SECCLASS_PROCESS2, av,
				   NULL);
		if (!rc)
			return 0;
	}

	/*
	 * We also permit NNP or nosuid transitions to bounded SIDs,
	 * i.e. SIDs that are guaranteed to only be allowed a subset
	 * of the permissions of the current SID.
	 */
	rc = security_bounded_transition(state, old_crsec->sid, new_crsec->sid);
	if (!rc)
		return 0;

	/*
	 * On failure, preserve the errno values for NNP vs nosuid.
	 * NNP:  Operation not permitted for caller.
	 * nosuid:  Permission denied to file.
	 */
	if (nnp)
		return -EPERM;
	return -EACCES;
}

struct selinux_exec_file_label {
	u32 canonical_sid;
	u32 leaf_sid;
	u16 leaf_sclass;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *sid_handle;
	struct selinux_label_ref *label;
	const struct selinux_label_view *view;
	struct selinux_pathless_projection *projection;
	struct selinux_label_operation_resolution operation;
#endif
};

static int selinux_exec_file_label_get(
	struct file *file, struct selinux_exec_file_label *target)
{
	struct inode_security_struct *isec;

	memset(target, 0, sizeof(*target));
#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		const struct file_security_struct *fsec = selinux_file(file);
		struct selinux_inode_label_snapshot snapshot;
		const struct selinux_label_domain *leaf_domain =
			selinux_cred(current_cred())->state->label_domain;
		int rc;

		target->projection = selinux_pathless_projection_get(
			fsec->pathless);
		if (target->projection) {
			target->canonical_sid = target->projection->sid;
			rc = selinux_label_view_resolve_operation(
				target->projection->view, target->projection->label,
				target->projection->sid, leaf_domain,
				&target->operation);
			if (rc)
				return rc;
			if (!leaf_domain ||
			    target->operation.labels.domain_id[leaf_domain->depth] !=
				    leaf_domain->id ||
			    !target->operation.labels.sid[leaf_domain->depth])
				return -EOPNOTSUPP;
			target->leaf_sid =
				target->operation.labels.sid[leaf_domain->depth];
			return 0;
		}

		isec = backing_inode_security(file->f_path.dentry);
		rc = selinux_inode_label_snapshot_get(isec, &snapshot);
		if (rc)
			return rc;
		target->canonical_sid = snapshot.sid;
		target->leaf_sclass = snapshot.sclass;
		target->sid_handle = snapshot.sid_handle;
		target->label = snapshot.label;
		snapshot.sid_handle = NULL;
		snapshot.label = NULL;
		selinux_inode_label_snapshot_put(&snapshot);
		target->view = selinux_label_view_get(fsec->view);
		if (!target->view)
			return -EACCES;
		rc = selinux_label_view_resolve_operation(
			target->view, target->label, target->canonical_sid, leaf_domain,
			&target->operation);
		if (rc)
			return rc;
		if (!leaf_domain ||
		    target->operation.labels.domain_id[leaf_domain->depth] !=
			    leaf_domain->id ||
		    !target->operation.labels.sid[leaf_domain->depth])
			return -EOPNOTSUPP;
		target->leaf_sid =
			target->operation.labels.sid[leaf_domain->depth];
		return 0;
	}
#else
	isec = inode_security(file_inode(file));
	target->canonical_sid = isec->sid;
	target->leaf_sid = isec->sid;
	target->leaf_sclass = isec->sclass;
	return 0;
#endif
}

static void selinux_exec_file_label_put(struct selinux_exec_file_label *target)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_pathless_projection_put(target->projection);
	selinux_label_operation_resolution_put(&target->operation);
	selinux_label_view_put(target->view);
	selinux_label_ref_put(target->label);
	global_sid_handle_put(target->sid_handle);
#endif
}

static int selinux_bprm_creds_for_exec_resolved(
	struct linux_binprm *bprm, const struct selinux_exec_file_label *target,
	const struct selinux_policy_snapshot *leaf_snapshot)
{
	const struct cred *cred = current_cred();
	const struct cred_security_struct *old_crsec;
	struct cred_security_struct *new_crsec;
	struct common_audit_data ad;
	u16 leaf_sclass = target->leaf_sclass;
	int rc;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *transition_handle;
	struct selinux_pathless_expect pathless_expect;
	u32 transition_sid;

	if (target->projection) {
		rc = selinux_pathless_policy_expect(
			target->projection, leaf_snapshot,
			selinux_cred(cred)->state->label_domain, target->leaf_sid,
			&pathless_expect);
		if (rc)
			return rc;
		leaf_sclass = pathless_expect.sclass;
	}
#endif

	/* SELinux context only depends on initial program or script and not
	 * the script interpreter */

	old_crsec = selinux_cred(cred);
	new_crsec = selinux_cred(bprm->cred);

	if (WARN_ON(leaf_sclass != SECCLASS_FILE &&
		    leaf_sclass != SECCLASS_MEMFD_FILE))
		return -EACCES;

	/* Default to the current task SID. */
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = selinux_cred_sid_dup_handle(
		new_crsec, SELINUX_CRED_SID, old_crsec->sid_handle);
	if (rc)
		return rc;
	rc = selinux_cred_sid_dup_handle(
		new_crsec, SELINUX_CRED_OSID, old_crsec->sid_handle);
	if (rc)
		return rc;
#else
	new_crsec->sid = old_crsec->sid;
	new_crsec->osid = old_crsec->sid;
#endif

	/* Reset fs, key, and sock SIDs on execve. */
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = selinux_cred_sid_set(new_crsec, SELINUX_CRED_CREATE_SID, 0);
	if (rc)
		return rc;
	rc = selinux_cred_sid_set(new_crsec, SELINUX_CRED_KEYCREATE_SID, 0);
	if (rc)
		return rc;
	rc = selinux_cred_sid_set(new_crsec, SELINUX_CRED_SOCKCREATE_SID, 0);
	if (rc)
		return rc;
#else
	new_crsec->create_sid = 0;
	new_crsec->keycreate_sid = 0;
	new_crsec->sockcreate_sid = 0;
#endif
	/*
	 * Before policy is loaded, label any task outside kernel space
	 * as SECINITSID_INIT, so that any userspace tasks surviving from
	 * early boot end up with a label different from SECINITSID_KERNEL
	 * (if the policy chooses to set SECINITSID_INIT != SECINITSID_KERNEL).
	 */
	if (!selinux_initialized(current_selinux_state)) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = selinux_cred_sid_set(
			new_crsec, SELINUX_CRED_SID, SECINITSID_INIT);
		if (rc)
			return rc;
		return selinux_cred_sid_set(
			new_crsec, SELINUX_CRED_EXEC_SID, 0);
#else
		new_crsec->sid = SECINITSID_INIT;
		/* also clear the exec_sid just in case */
		new_crsec->exec_sid = 0;
		return 0;
#endif
	}

	if (old_crsec->exec_sid) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = selinux_cred_sid_dup_handle(
			new_crsec, SELINUX_CRED_SID, old_crsec->exec_sid_handle);
		if (rc)
			return rc;
		rc = selinux_cred_sid_set(new_crsec, SELINUX_CRED_EXEC_SID, 0);
		if (rc)
			return rc;
#else
		new_crsec->sid = old_crsec->exec_sid;
		/* Reset exec SID on execve. */
		new_crsec->exec_sid = 0;
#endif

		/* Fail on NNP or nosuid if not an allowed transition. */
		rc = check_nnp_nosuid(bprm, old_crsec, new_crsec,
				      leaf_snapshot);
		if (rc)
			return rc;
	} else {
		/* Check for a default transition on this program. */
#ifdef CONFIG_SECURITY_SELINUX_NS
		transition_handle = security_transition_sid_handle(
			current_selinux_state, old_crsec->sid, target->leaf_sid,
			SECCLASS_PROCESS, NULL, &transition_sid);
		if (IS_ERR(transition_handle))
			return PTR_ERR(transition_handle);
		rc = selinux_cred_sid_take_handle(
			new_crsec, SELINUX_CRED_SID, transition_handle);
#else
		rc = security_transition_sid(current_selinux_state,
					     old_crsec->sid, target->leaf_sid,
					     SECCLASS_PROCESS, NULL,
					     &new_crsec->sid);
#endif
		if (rc)
			return rc;

		/*
		 * Fallback to old SID on NNP or nosuid if not an allowed
		 * transition.
		 */
		rc = check_nnp_nosuid(bprm, old_crsec, new_crsec,
				      leaf_snapshot);
		if (rc) {
#ifdef CONFIG_SECURITY_SELINUX_NS
			rc = selinux_cred_sid_dup_handle(
				new_crsec, SELINUX_CRED_SID,
				old_crsec->sid_handle);
			if (rc)
				return rc;
#else
			new_crsec->sid = old_crsec->sid;
#endif
		}
	}

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = bprm->file;

	if (new_crsec->sid == old_crsec->sid) {
		/*
		 * Only check against the current SELinux namespace
		 * because only the SID in the current namespace
		 * is changed by a transition.
		 */
		rc = avc_has_perm(current_selinux_state,
				  old_crsec->sid, target->leaf_sid,
				  leaf_sclass,
				  FILE__EXECUTE_NO_TRANS, &ad);
		if (rc)
			return rc;
	} else {
		/* Check permissions for the transition. */
		/*
		 * Only check against the current SELinux namespace
		 * because only the SID in the current namespace
		 * is changed by a transition.
		 */
		rc = avc_has_perm(current_selinux_state,
				  old_crsec->sid, new_crsec->sid,
				  SECCLASS_PROCESS, PROCESS__TRANSITION, &ad);
		if (rc)
			return rc;

		/*
		 * Only check against the current SELinux namespace
		 * because only the SID in the current namespace
		 * is changed by a transition.
		 */
		rc = avc_has_perm(current_selinux_state,
				  new_crsec->sid, target->leaf_sid,
				  leaf_sclass,
				  FILE__ENTRYPOINT, &ad);
		if (rc)
			return rc;

		/* Check for shared state */
		if (bprm->unsafe & LSM_UNSAFE_SHARE) {
			/*
			 * Only check against the current SELinux namespace
			 * because only the SID in the current namespace
			 * is changed by a transition.
			 */
			rc = avc_has_perm(current_selinux_state,
					  old_crsec->sid, new_crsec->sid,
					  SECCLASS_PROCESS, PROCESS__SHARE,
					  NULL);
			if (rc)
				return -EPERM;
		}

		/* Make sure that anyone attempting to ptrace over a task that
		 * changes its SID has the appropriate permit */
		if (bprm->unsafe & LSM_UNSAFE_PTRACE) {
			u32 ptsid = ptrace_parent_sid();
			if (ptsid != 0) {
				/*
				 * Only check against the current SELinux
				 * namespace because only the SID in the
				 * current namespace is changed by a
				 * transition.
				 */
				rc = avc_has_perm(current_selinux_state,
						  ptsid, new_crsec->sid,
						  SECCLASS_PROCESS,
						  PROCESS__PTRACE, NULL);
				if (rc)
					return -EPERM;
			}
		}

		/* Clear any possibly unsafe personality bits on exec: */
		bprm->per_clear |= PER_CLEAR_ON_SETID;

		/* Enable secure mode for SIDs transitions unless
		   the noatsecure permission is granted between
		   the two SIDs, i.e. ahp returns 0. */
		/*
		 * Only check against the current SELinux namespace
		 * because only the SID in the current namespace
		 * is changed by a transition.
		 */
		rc = avc_has_perm(current_selinux_state,
				  old_crsec->sid, new_crsec->sid,
				  SECCLASS_PROCESS, PROCESS__NOATSECURE,
				  NULL);
		bprm->secureexec |= !!rc;
	}

	/*
	 * If in a non-init namespace, also check the ability of the
	 * ancestors to execute without transitioning since the SID
	 * in ancestor namespaces is NOT modified.
	 */
	cred = old_crsec->parent_cred;
	if (cred) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		if (target->projection)
			rc = cred_pathless_has_perm(
				cred, target->projection, FILE__EXECUTE_NO_TRANS, &ad);
		else
			rc = cred_label_has_perm(
				cred, target->canonical_sid, target->label,
				target->view, target->leaf_sclass,
				FILE__EXECUTE_NO_TRANS, &ad);
#else
		rc = cred_tsid_has_perm(cred, target->canonical_sid,
					SECCLASS_FILE, FILE__EXECUTE_NO_TRANS, &ad);
#endif
		if (rc)
			return rc;
	}

	return 0;
}

static int selinux_bprm_creds_for_exec(struct linux_binprm *bprm)
{
	struct selinux_exec_file_label target;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct cred_security_struct *crsec =
		selinux_cred(current_cred());
	struct selinux_policy_snapshot bootstrap_snapshot = {};
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
#else
	struct selinux_policy_snapshot leaf_snapshot;
#endif
	int rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
	/* The executable inode has no stable label before the root policy load. */
	if (!selinux_initialized(crsec->state)) {
		if (!selinux_cred_chain_uninitialized(current_cred()))
			return -EACCES;
		memset(&target, 0, sizeof(target));
		target.leaf_sclass = SECCLASS_FILE;
		rc = selinux_bprm_creds_for_exec_resolved(
			bprm, &target, &bootstrap_snapshot);
		goto out;
	}
#endif
	rc = selinux_exec_file_label_get(bprm->file, &target);
	if (rc)
		goto out;
#ifdef CONFIG_SECURITY_SELINUX_NS
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain) {
		rc = -ENOMEM;
		goto out;
	}
	{
		unsigned int saved_per_clear = bprm->per_clear;
		int saved_secureexec = bprm->secureexec;
		unsigned int retry;

		for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
			rc = selinux_policy_chain_snapshot_read(current_cred(),
							 chain);
			if (rc == -EAGAIN || rc == -ESTALE)
				continue;
			if (rc)
				break;
			rc = selinux_bprm_creds_for_exec_resolved(
				bprm, &target, &chain->policy[0]);
			if (selinux_policy_chain_snapshot_valid(chain))
				break;

			/* The next attempt rebuilds every credential SID slot. */
			bprm->per_clear = saved_per_clear;
			bprm->secureexec = saved_secureexec;
			rc = -ESTALE;
		}
		if (retry == SELINUX_POLICY_OPERATION_RETRIES &&
		    (rc == -EAGAIN || rc == -ESTALE))
			rc = -ESTALE;
	}
#else
	rc = selinux_policy_snapshot_read(current_selinux_state,
					  &leaf_snapshot);
	if (!rc)
		rc = selinux_bprm_creds_for_exec_resolved(
			bprm, &target, &leaf_snapshot);
#endif
out:
	selinux_exec_file_label_put(&target);
	return rc;
}

static int match_file(const void *p, struct file *file, unsigned fd)
{
	return file_has_perm(p, file, file_to_av(file)) ? fd + 1 : 0;
}

/* Derived from fs/exec.c:flush_old_files. */
static inline void flush_unauthorized_files(const struct cred *cred,
					    struct files_struct *files)
{
	struct file *file, *devnull = NULL;
	struct tty_struct *tty;
	int drop_tty = 0;
	unsigned n;

	tty = get_current_tty();
	if (tty) {
		spin_lock(&tty->files_lock);
		if (!list_empty(&tty->tty_files)) {
			struct tty_file_private *file_priv;

			/* Revalidate access to controlling tty.
			   Use file_path_has_perm on the tty path directly
			   rather than using file_has_perm, as this particular
			   open file may belong to another process and we are
			   only interested in the inode-based check here. */
			file_priv = list_first_entry(&tty->tty_files,
						struct tty_file_private, list);
			file = file_priv->file;
			if (file_path_has_perm(cred, file, FILE__READ | FILE__WRITE))
				drop_tty = 1;
		}
		spin_unlock(&tty->files_lock);
		tty_kref_put(tty);
	}
	/* Reset controlling tty. */
	if (drop_tty)
		no_tty();

	/* Revalidate access to inherited open files. */
	n = iterate_fd(files, 0, match_file, cred);
	if (!n) /* none found? */
		return;

	devnull = dentry_open(&selinux_null, O_RDWR, cred);
	if (IS_ERR(devnull))
		devnull = NULL;
	/* replace all the matching ones with this */
	do {
		replace_fd(n - 1, devnull, 0);
	} while ((n = iterate_fd(files, n, match_file, cred)) != 0);
	if (devnull)
		fput(devnull);
}

/*
 * Prepare a process for imminent new credential changes due to exec
 */
static void selinux_bprm_committing_creds(const struct linux_binprm *bprm)
{
	struct cred_security_struct *new_crsec;
	struct rlimit *rlim, *initrlim;
	int rc, i;

	new_crsec = selinux_cred(bprm->cred);
	if (new_crsec->sid == new_crsec->osid)
		return;

	/* Close files for which the new task SID is not authorized. */
	flush_unauthorized_files(bprm->cred, current->files);

	/* Always clear parent death signal on SID transitions. */
	current->pdeath_signal = 0;

	/* Check whether the new SID can inherit resource limits from the old
	 * SID.  If not, reset all soft limits to the lower of the current
	 * task's hard limit and the init task's soft limit.
	 *
	 * Note that the setting of hard limits (even to lower them) can be
	 * controlled by the setrlimit check.  The inclusion of the init task's
	 * soft limit into the computation is to avoid resetting soft limits
	 * higher than the default soft limit for cases where the default is
	 * lower than the hard limit, e.g. RLIMIT_CORE or RLIMIT_STACK.
	 */
	/*
	 * Only check against the current SELinux namespace
	 * because only the SID in the current namespace
	 * is changed by a transition.
	 */
	rc = avc_has_perm(current_selinux_state,
			  new_crsec->osid, new_crsec->sid, SECCLASS_PROCESS,
			  PROCESS__RLIMITINH, NULL);
	if (rc) {
		/* protect against do_prlimit() */
		task_lock(current);
		for (i = 0; i < RLIM_NLIMITS; i++) {
			rlim = current->signal->rlim + i;
			initrlim = init_task.signal->rlim + i;
			rlim->rlim_cur = min(rlim->rlim_max, initrlim->rlim_cur);
		}
		task_unlock(current);
		if (IS_ENABLED(CONFIG_POSIX_TIMERS))
			update_rlimit_cpu(current, rlimit(RLIMIT_CPU));
	}
}

/*
 * Clean up the process immediately after the installation of new credentials
 * due to exec
 */
static void selinux_bprm_committed_creds(const struct linux_binprm *bprm)
{
	const struct cred_security_struct *crsec = selinux_cred(current_cred());
	u32 osid, sid;
	int rc;

	osid = crsec->osid;
	sid = crsec->sid;

	if (sid == osid)
		return;

	/* Check whether the new SID can inherit signal state from the old SID.
	 * If not, clear itimers to avoid subsequent signal generation and
	 * flush and unblock signals.
	 *
	 * This must occur _after_ the task SID has been updated so that any
	 * kill done after the flush will be checked against the new SID.
	 */
	/*
	 * Only check against the current SELinux namespace
	 * because only the SID in the current namespace
	 * is changed by a transition.
	 */
	rc = avc_has_perm(current_selinux_state,
			  osid, sid, SECCLASS_PROCESS, PROCESS__SIGINH, NULL);
	if (rc) {
		clear_itimer();

		spin_lock_irq(&unrcu_pointer(current->sighand)->siglock);
		if (!fatal_signal_pending(current)) {
			flush_sigqueue(&current->pending);
			flush_sigqueue(&current->signal->shared_pending);
			flush_signal_handlers(current, 1);
			sigemptyset(&current->blocked);
			recalc_sigpending();
		}
		spin_unlock_irq(&unrcu_pointer(current->sighand)->siglock);
	}

	/* Wake up the parent if it is waiting so that it can recheck
	 * wait permission to the new task SID. */
	read_lock(&tasklist_lock);
	__wake_up_parent(current, unrcu_pointer(current->real_parent));
	read_unlock(&tasklist_lock);
}

/* superblock security operations */

static int selinux_sb_alloc_security(struct super_block *sb)
{
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
#ifdef CONFIG_SECURITY_SELINUX_NS
	int rc;
#endif

	mutex_init(&sbsec->lock);
	INIT_LIST_HEAD(&sbsec->isec_head);
	spin_lock_init(&sbsec->isec_lock);
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = selinux_sb_sid_set_numeric(&sbsec->sid, &sbsec->sid_handle,
					SECINITSID_UNLABELED);
	if (rc)
		goto err;
	rc = selinux_sb_sid_set_numeric(&sbsec->def_sid,
					&sbsec->def_sid_handle, SECINITSID_FILE);
	if (rc)
		goto err;
	rc = selinux_sb_sid_set_numeric(&sbsec->mntpoint_sid,
					&sbsec->mntpoint_sid_handle,
					SECINITSID_UNLABELED);
	if (rc)
		goto err;
	rc = selinux_sb_sid_set_numeric(&sbsec->creator_sid,
					&sbsec->creator_sid_handle,
					SECINITSID_UNLABELED);
	if (rc)
		goto err;
#else
	sbsec->sid = SECINITSID_UNLABELED;
	sbsec->def_sid = SECINITSID_FILE;
	sbsec->mntpoint_sid = SECINITSID_UNLABELED;
	sbsec->creator_sid = SECINITSID_UNLABELED;
#endif

	return 0;

#ifdef CONFIG_SECURITY_SELINUX_NS
err:
	global_sid_handle_put(sbsec->creator_sid_handle);
	sbsec->creator_sid_handle = NULL;
	global_sid_handle_put(sbsec->mntpoint_sid_handle);
	sbsec->mntpoint_sid_handle = NULL;
	global_sid_handle_put(sbsec->def_sid_handle);
	sbsec->def_sid_handle = NULL;
	global_sid_handle_put(sbsec->sid_handle);
	sbsec->sid_handle = NULL;
	return rc;
#endif
}

static void selinux_sb_free_security(struct super_block *sb)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct superblock_security_struct *sbsec = selinux_superblock(sb);

	global_sid_handle_put(sbsec->creator_sid_handle);
	sbsec->creator_sid_handle = NULL;
	global_sid_handle_put(sbsec->mntpoint_sid_handle);
	sbsec->mntpoint_sid_handle = NULL;
	global_sid_handle_put(sbsec->def_sid_handle);
	sbsec->def_sid_handle = NULL;
	global_sid_handle_put(sbsec->sid_handle);
	sbsec->sid_handle = NULL;
	put_selinux_state(sbsec->anchor_state);
	sbsec->anchor_state = NULL;
	selinux_label_domain_put(sbsec->anchor_domain);
	sbsec->anchor_domain = NULL;
#endif
}

static inline int opt_len(const char *s)
{
	bool open_quote = false;
	int len;
	char c;

	for (len = 0; (c = s[len]) != '\0'; len++) {
		if (c == '"')
			open_quote = !open_quote;
		if (c == ',' && !open_quote)
			break;
	}
	return len;
}

static int selinux_sb_eat_lsm_opts(char *options, struct fs_context *fc)
{
	char *from = options;
	char *to = options;
	bool first = true;
	int rc;

	while (1) {
		int len = opt_len(from);
		int token;
		char *arg = NULL;

		token = match_opt_prefix(from, len, &arg);

		if (token != Opt_error) {
			char *p, *q;

			/* strip quotes */
			if (arg) {
				for (p = q = arg; p < from + len; p++) {
					char c = *p;
					if (c != '"')
						*q++ = c;
				}
				arg = kmemdup_nul(arg, q - arg, GFP_KERNEL);
				if (!arg) {
					rc = -ENOMEM;
					goto free_opt;
				}
			}
			rc = selinux_add_opt(token, arg, &fc->security, fc->cred);
			kfree(arg);
			arg = NULL;
			if (unlikely(rc)) {
				goto free_opt;
			}
		} else {
			if (!first) {	// copy with preceding comma
				from--;
				len++;
			}
			if (to != from)
				memmove(to, from, len);
			to += len;
			first = false;
		}
		if (!from[len])
			break;
		from += len + 1;
	}
	*to = '\0';
	return 0;

free_opt:
	if (fc->security) {
		selinux_free_mnt_opts(fc->security);
		fc->security = NULL;
	}
	return rc;
}

static int selinux_sb_mnt_opts_compat(struct super_block *sb, void *mnt_opts)
{
	struct selinux_mnt_opts *opts = mnt_opts;
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
#ifdef CONFIG_SECURITY_SELINUX_NS
	bool has_mnt_opts = selinux_mnt_opts_has_labels(opts);
#endif

	/*
	 * Superblock not initialized (i.e. no options) - reject if any
	 * options specified, otherwise accept.
	 */
	if (!(sbsec->flags & SE_SBINITIALIZED))
		return opts
#ifdef CONFIG_SECURITY_SELINUX_NS
			&& has_mnt_opts
#endif
			? 1 : 0;

	/*
	 * Superblock initialized and no options specified - reject if
	 * superblock has any options set, otherwise accept.
	 */
	if (!opts
#ifdef CONFIG_SECURITY_SELINUX_NS
	    || !has_mnt_opts
#endif
	)
		return (sbsec->flags & SE_MNTMASK) ? 1 : 0;

#ifdef CONFIG_SECURITY_SELINUX_NS
	/* This hook may run under sb_lock; unresolved strings cannot sleep here. */
	if (!opts->finalized || !opts->view ||
	    opts->view->origin_domain != sbsec->anchor_domain)
		return 1;
#endif

	if (opts->fscontext_sid) {
		if (bad_option(sbsec, FSCONTEXT_MNT, sbsec->sid,
			       opts->fscontext_sid))
			return 1;
	}
	if (opts->context_sid) {
		if (bad_option(sbsec, CONTEXT_MNT, sbsec->mntpoint_sid,
			       opts->context_sid))
			return 1;
	}
	if (opts->rootcontext_sid) {
		struct inode_security_struct *root_isec;

		root_isec = backing_inode_security(sb->s_root);
		if (bad_option(sbsec, ROOTCONTEXT_MNT, root_isec->sid,
			       opts->rootcontext_sid))
			return 1;
	}
	if (opts->defcontext_sid) {
		if (bad_option(sbsec, DEFCONTEXT_MNT, sbsec->def_sid,
			       opts->defcontext_sid))
			return 1;
	}
	return 0;
}

static int selinux_sb_remount(struct super_block *sb, void *mnt_opts)
{
	struct selinux_mnt_opts *opts = mnt_opts;
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
#ifdef CONFIG_SECURITY_SELINUX_NS
	int rc;
#endif

	if (!(sbsec->flags & SE_SBINITIALIZED))
		return 0;

	if (!opts)
		return 0;

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!selinux_mnt_opts_has_labels(opts))
		return 0;
	mutex_lock(&sbsec->lock);
	rc = selinux_mnt_opts_finalize_locked(sbsec, opts);
	mutex_unlock(&sbsec->lock);
	if (rc)
		return rc;
#endif

	if (opts->fscontext_sid) {
		if (bad_option(sbsec, FSCONTEXT_MNT, sbsec->sid,
			       opts->fscontext_sid))
			goto out_bad_option;
	}
	if (opts->context_sid) {
		if (bad_option(sbsec, CONTEXT_MNT, sbsec->mntpoint_sid,
			       opts->context_sid))
			goto out_bad_option;
	}
	if (opts->rootcontext_sid) {
		struct inode_security_struct *root_isec;
		root_isec = backing_inode_security(sb->s_root);
		if (bad_option(sbsec, ROOTCONTEXT_MNT, root_isec->sid,
			       opts->rootcontext_sid))
			goto out_bad_option;
	}
	if (opts->defcontext_sid) {
		if (bad_option(sbsec, DEFCONTEXT_MNT, sbsec->def_sid,
			       opts->defcontext_sid))
			goto out_bad_option;
	}
	return 0;

out_bad_option:
	pr_warn("SELinux: unable to change security options "
	       "during remount (dev %s, type=%s)\n", sb->s_id,
	       sb->s_type->name);
	return -EINVAL;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static void __free_selinux_mount_label_ref(void *data)
{
	struct selinux_label_ref *label = *(struct selinux_label_ref **)data;

	if (!IS_ERR_OR_NULL(label))
		selinux_label_ref_put(label);
}
#endif

static int selinux_sb_kern_mount(const struct super_block *sb,
				 struct fs_context *fc)
{
	const struct cred *cred = fc->cred;
	struct common_audit_data ad;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct selinux_mnt_opts *opts = fc->security;
	struct selinux_sb_mount_scratch {
		struct selinux_policy_chain_snapshot chain;
		struct selinux_policy_snapshot target_snapshot;
		struct selinux_policy_snapshot anchor_snapshot;
		struct selinux_label_resolution sb_resolution;
		struct selinux_avc_level
			levels[SELINUX_AVC_TRANSACTION_MAX_CHECKS];
		struct selinux_policy_snapshot
			snapshots[SELINUX_AVC_TRANSACTION_MAX_CHECKS];
		struct selinux_avc_provenance provenance;
	} *scratch __free(kfree) = NULL;
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) =
		NULL;
	struct selinux_label_ref *target_label
		__free(selinux_mount_label_ref) = NULL;
	struct selinux_ns_control *control;
	struct selinux_state *anchor, *parent, *target;
	unsigned int retry;
	u32 actor_sid, target_sid;
	int rc;
#endif

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = sb->s_root;
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!opts || !opts->observer_control)
		return superblock_has_perm_mnt(
			cred, sb, NULL, FILESYSTEM__MOUNT, &ad);
	if (opts->actor != cred)
		return -EXDEV;
	control = opts->observer_control;
	parent = cred_selinux_state(cred);
	target = control->state;
	anchor = READ_ONCE(sbsec->anchor_state);
	if (!parent || !target || !target->label_domain)
		return -EINVAL;
	if (!selinux_ns_control_parent(control, parent))
		return -EPERM;
	if (!selinux_state_active(target))
		return -EAGAIN;
	if (!opts->finalized || !opts->view || !anchor ||
	    !sbsec->anchor_domain ||
	    anchor->label_domain != sbsec->anchor_domain ||
	    opts->view->origin_domain != sbsec->anchor_domain ||
	    opts->view->outer_domain != target->label_domain)
		return -ESTALE;
	if (!target->depth || target->depth > opts->view->map_count ||
	    opts->view->maps[target->depth - 1] != control->map)
		return -ESTALE;
	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_AVC_TRANSACTION_MAX_CHECKS, GFP_KERNEL);
	if (!workspace)
		return -ENOMEM;
	target_label = global_sid_to_label_ref(sbsec->sid);
	if (IS_ERR(target_label))
		return PTR_ERR(target_label);
	rc = selinux_label_view_resolve_chain(
		opts->view, target_label, sbsec->sid, &scratch->sb_resolution);
	if (rc)
		return rc;
	if (target->depth > scratch->sb_resolution.max_depth ||
	    scratch->sb_resolution.domain_id[target->depth] !=
		    target->label_domain->id ||
	    !scratch->sb_resolution.sid[target->depth])
		return -EOPNOTSUPP;
	target_sid = scratch->sb_resolution.sid[target->depth];
	scratch->provenance = (struct selinux_avc_provenance) {
		.label = target_label,
		.view = opts->view,
		.source = SELINUX_LABEL_SOURCE_UNSPECIFIED,
	};

	for (retry = 0; retry < SELINUX_MNT_POLICY_RETRIES; retry++) {
		int cap_rc;
		u16 count = 0, i;

		rc = selinux_policy_chain_snapshot_read(cred, &scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = selinux_policy_snapshot_read(target,
						  &scratch->target_snapshot);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = selinux_policy_snapshot_read(anchor,
						  &scratch->anchor_snapshot);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		if (!selinux_policy_snapshot_valid(target,
						   &opts->observer_snapshot) ||
		    !selinux_policy_snapshot_valid(anchor,
						   &opts->origin_snapshot))
			continue;
		/*
		 * Preserve the complete stacked-LSM capability gate without
		 * emitting an audit before the SELinux transaction is coherent.
		 * The equivalent SELinux capability decisions are also included
		 * below so their denials participate in the host aggregate.
		 */
		cap_rc = security_capable(
			cred, target->label_domain->owner_userns, CAP_SYS_ADMIN,
			CAP_OPT_NOAUDIT);

		mutex_lock(&parent->policy_mutex);
		mutex_lock_nested(&target->policy_mutex, SINGLE_DEPTH_NESTING);
		rc = selinux_ns_control_resolve_join(
			control, parent, selinux_cred(cred)->sid, &actor_sid);
		mutex_unlock(&target->policy_mutex);
		mutex_unlock(&parent->policy_mutex);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;

		/* Guard policy-derived mount labels even if anchor is not an AVC level. */
		scratch->levels[count] = (struct selinux_avc_level) {
			.state = anchor,
			.ssid = SECINITSID_KERNEL,
			.tsid = SECINITSID_KERNEL,
			.tclass = SECCLASS_FILESYSTEM,
		};
		scratch->snapshots[count++] = scratch->anchor_snapshot;
		scratch->levels[count] = (struct selinux_avc_level) {
			.state = target,
			.ssid = actor_sid,
			.tsid = actor_sid,
			.tclass = SECCLASS_PROCESS2,
			.requested = PROCESS2__UNSHARE_SELINUXNS,
		};
		scratch->snapshots[count++] = scratch->target_snapshot;
		scratch->levels[count] = (struct selinux_avc_level) {
			.state = target,
			.ssid = actor_sid,
			.tsid = target_sid,
			.tclass = SECCLASS_FILESYSTEM,
			.requested = FILESYSTEM__MOUNT,
			.provenance = &scratch->provenance,
		};
		scratch->snapshots[count++] = scratch->target_snapshot;
		for (i = 0; i < scratch->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(scratch->chain.cred[i]);
			u16 capability_class =
				target->label_domain->owner_userns == &init_user_ns ?
					SECCLASS_CAPABILITY : SECCLASS_CAP_USERNS;
			u16 depth = crsec->state->label_domain->depth;

			if (depth > scratch->sb_resolution.max_depth ||
			    scratch->sb_resolution.domain_id[depth] !=
				    crsec->state->label_domain->id ||
			    !scratch->sb_resolution.sid[depth]) {
				rc = -EOPNOTSUPP;
				break;
			}
			scratch->levels[count] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = scratch->sb_resolution.sid[depth],
				.tclass = SECCLASS_FILESYSTEM,
				.requested = FILESYSTEM__MOUNT,
				.provenance = &scratch->provenance,
			};
			scratch->snapshots[count++] = scratch->chain.policy[i];
			scratch->levels[count] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = crsec->sid,
				.tclass = SECCLASS_PROCESS2,
				.requested = PROCESS2__UNSHARE_SELINUXNS,
			};
			scratch->snapshots[count++] = scratch->chain.policy[i];
			scratch->levels[count] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = crsec->sid,
				.tclass = capability_class,
				.requested = CAP_TO_MASK(CAP_SYS_ADMIN),
			};
			scratch->snapshots[count++] = scratch->chain.policy[i];
		}
		if (rc)
			return rc;
		if (!selinux_policy_chain_snapshot_valid(&scratch->chain) ||
		    !selinux_policy_snapshot_valid(target,
						   &scratch->target_snapshot) ||
		    !selinux_policy_snapshot_valid(anchor,
						   &scratch->anchor_snapshot))
			continue;
		rc = selinux_avc_transaction_has_perm_workspace(
			scratch->levels, scratch->snapshots, count, &ad, workspace);
		if (rc == -ESTALE || (!rc && (cap_rc == -EAGAIN ||
						 cap_rc == -ESTALE)))
			continue;
		return rc ?: cap_rc;
	}
	return -ESTALE;
#else
	return superblock_has_perm(cred, sb, FILESYSTEM__MOUNT, &ad);
#endif
}

static int selinux_sb_statfs(struct dentry *dentry,
			     const struct vfsmount *mnt)
{
	const struct cred *cred = current_cred();
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry->d_sb->s_root;
#ifdef CONFIG_SECURITY_SELINUX_NS
	return superblock_has_perm_mnt(cred, dentry->d_sb, mnt,
				       FILESYSTEM__GETATTR, &ad);
#else
	return superblock_has_perm(
		cred, dentry->d_sb, FILESYSTEM__GETATTR, &ad);
#endif
}

static int selinux_mount(const char *dev_name,
			 const struct path *path,
			 const char *type,
			 unsigned long flags,
			 void *data)
{
	const struct cred *cred = current_cred();

	if (flags & MS_REMOUNT)
#ifdef CONFIG_SECURITY_SELINUX_NS
		return superblock_has_perm_mnt(
			cred, path->dentry->d_sb, path->mnt,
			FILESYSTEM__REMOUNT, NULL);
#else
		return superblock_has_perm(
			cred, path->dentry->d_sb, FILESYSTEM__REMOUNT, NULL);
#endif
	else
		return path_has_perm(cred, path, FILE__MOUNTON);
}

static int selinux_move_mount(const struct path *from_path,
			      const struct path *to_path)
{
	const struct cred *cred = current_cred();

	return path_has_perm(cred, to_path, FILE__MOUNTON);
}

static int selinux_umount(struct vfsmount *mnt, int flags)
{
	const struct cred *cred = current_cred();

#ifdef CONFIG_SECURITY_SELINUX_NS
	return superblock_has_perm_mnt(cred, mnt->mnt_sb, mnt,
				       FILESYSTEM__UNMOUNT, NULL);
#else
	return superblock_has_perm(
		cred, mnt->mnt_sb, FILESYSTEM__UNMOUNT, NULL);
#endif
}

static int selinux_fs_context_submount(struct fs_context *fc,
				   const struct path *reference)
{
	const struct superblock_security_struct *sbsec =
		selinux_superblock(reference->dentry->d_sb);
	struct selinux_mnt_opts *opts;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;
	const struct selinux_label_view *reference_view;
	struct selinux_label_ref *label;
	struct {
		u16 flag;
		u32 sid;
		int index;
	} inherited[] = {
		{ FSCONTEXT_MNT, sbsec->sid, SELINUX_MNT_LABEL_FSCONTEXT },
		{ CONTEXT_MNT, sbsec->mntpoint_sid, SELINUX_MNT_LABEL_CONTEXT },
		{ DEFCONTEXT_MNT, sbsec->def_sid, SELINUX_MNT_LABEL_DEFCONTEXT },
	};
	size_t i;
	int rc = 0;

	if (!sbsec->anchor_state || !sbsec->anchor_domain ||
	    sbsec->anchor_state->label_domain != sbsec->anchor_domain)
		return -EACCES;

	opts = kzalloc_obj(*opts);
	if (!opts)
		return -ENOMEM;
	opts->actor = get_cred(fc->cred);
	opts->requested_origin_state = get_selinux_state(sbsec->anchor_state);
	opts->requested_origin_domain =
		selinux_label_domain_get(sbsec->anchor_domain);
	reference_view = selinux_mnt_label_view(reference->mnt);
	if (!reference_view) {
		rc = -EOPNOTSUPP;
		goto err;
	}
	opts->requested_observer_view = selinux_label_view_get(reference_view);
	if (opts->requested_observer_view->origin_domain !=
	    opts->requested_origin_domain) {
		rc = -EXDEV;
		goto err;
	}

	for (i = 0; i < ARRAY_SIZE(inherited); i++) {
		if (!(sbsec->flags & inherited[i].flag))
			continue;
		handle = global_sid_handle_get(inherited[i].sid);
		if (IS_ERR(handle)) {
			rc = PTR_ERR(handle);
			goto err;
		}
		label = global_sid_handle_label_get(handle);
		if (!label || IS_ERR(label)) {
			rc = label ? PTR_ERR(label) : -ESTALE;
			global_sid_handle_put(handle);
			goto err;
		}
		if (label->domain != sbsec->anchor_domain &&
		    !(label->domain->flags & SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL)) {
			rc = -EXDEV;
			selinux_label_ref_put(label);
			global_sid_handle_put(handle);
			goto err;
		}
		opts->labels[inherited[i].index].context = kmemdup(
			label->context, label->context_len, GFP_KERNEL);
		selinux_label_ref_put(label);
		global_sid_handle_put(handle);
		if (!opts->labels[inherited[i].index].context) {
			rc = -ENOMEM;
			goto err;
		}
		opts->labels[inherited[i].index].input_is_origin = true;
	}
	fc->security = opts;
	return 0;

err:
	selinux_free_mnt_opts(opts);
	return rc;
#else
	/* No namespace provenance exists in the compatibility configuration. */
	if (!(sbsec->flags & (FSCONTEXT_MNT|CONTEXT_MNT|DEFCONTEXT_MNT)))
		return 0;

	opts = kzalloc_obj(*opts);
	if (!opts)
		return -ENOMEM;

	if (sbsec->flags & FSCONTEXT_MNT)
		opts->fscontext_sid = sbsec->sid;
	if (sbsec->flags & CONTEXT_MNT)
		opts->context_sid = sbsec->mntpoint_sid;
	if (sbsec->flags & DEFCONTEXT_MNT)
		opts->defcontext_sid = sbsec->def_sid;
	fc->security = opts;
	return 0;
#endif
}

static int selinux_fs_context_dup(struct fs_context *fc,
				  struct fs_context *src_fc)
{
	const struct selinux_mnt_opts *src = src_fc->security;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_mnt_opts *dst;
	int i, rc = -ENOMEM;
#endif

	if (!src)
		return 0;

#ifdef CONFIG_SECURITY_SELINUX_NS
	dst = kzalloc_obj(*dst);
	if (!dst)
		return -ENOMEM;
	dst->fscontext_sid = src->fscontext_sid;
	dst->context_sid = src->context_sid;
	dst->rootcontext_sid = src->rootcontext_sid;
	dst->defcontext_sid = src->defcontext_sid;
	dst->observer_snapshot = src->observer_snapshot;
	dst->origin_snapshot = src->origin_snapshot;
	dst->finalized = src->finalized;
	dst->actor = get_cred(src->actor ? src->actor : src_fc->cred);
	dst->observer_control = selinux_ns_control_get(src->observer_control);
	dst->requested_origin_state = src->requested_origin_state ?
		get_selinux_state(src->requested_origin_state) : NULL;
	dst->requested_origin_domain = selinux_label_domain_get(
		src->requested_origin_domain);
	dst->requested_observer_view = src->requested_observer_view ?
		selinux_label_view_get(src->requested_observer_view) : NULL;
	dst->view = src->view ? selinux_label_view_get(src->view) : NULL;
	for (i = 0; i < SELINUX_MNT_LABEL_COUNT; i++) {
		dst->labels[i].input_is_origin =
			src->labels[i].input_is_origin;
		if (src->labels[i].context) {
			dst->labels[i].context = kstrdup(src->labels[i].context,
							 GFP_KERNEL);
			if (!dst->labels[i].context)
				goto err;
		}
		if (src->labels[i].observer_handle) {
			dst->labels[i].observer_handle = global_sid_handle_dup(
				src->labels[i].observer_handle);
			if (IS_ERR(dst->labels[i].observer_handle)) {
				rc = PTR_ERR(dst->labels[i].observer_handle);
				dst->labels[i].observer_handle = NULL;
				goto err;
			}
		}
		if (src->labels[i].origin_handle) {
			dst->labels[i].origin_handle = global_sid_handle_dup(
				src->labels[i].origin_handle);
			if (IS_ERR(dst->labels[i].origin_handle)) {
				rc = PTR_ERR(dst->labels[i].origin_handle);
				dst->labels[i].origin_handle = NULL;
				goto err;
			}
		}
	}
	fc->security = dst;
	return 0;

err:
	selinux_free_mnt_opts(dst);
	return rc;
#else
	fc->security = kmemdup(src, sizeof(*src), GFP_KERNEL);
	if (!fc->security)
		return -ENOMEM;
	return 0;
#endif
}

static const struct fs_parameter_spec selinux_fs_parameters[] = {
	fsparam_string(CONTEXT_STR,	Opt_context),
	fsparam_string(DEFCONTEXT_STR,	Opt_defcontext),
	fsparam_string(FSCONTEXT_STR,	Opt_fscontext),
	fsparam_string(ROOTCONTEXT_STR,	Opt_rootcontext),
	fsparam_flag  (SECLABEL_STR,	Opt_seclabel),
#ifdef CONFIG_SECURITY_SELINUX_NS
	fsparam_fd (SELINUXNS_FD_STR,	Opt_selinuxns_fd),
#endif
	{}
};

static int selinux_fs_context_parse_param(struct fs_context *fc,
					  struct fs_parameter *param)
{
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, selinux_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (opt == Opt_selinuxns_fd) {
		struct selinux_ns_control *control;
		struct selinux_mnt_opts *opts;
		int rc;

		/* fs_param_is_fd() also accepts numeric strings; forbid those. */
		if (param->type != fs_value_is_file || !param->file)
			return -EINVAL;
		if (fc->purpose == FS_CONTEXT_FOR_RECONFIGURE)
			return -EINVAL;
		control = selinux_ns_control_get_from_file(param->file);
		if (IS_ERR(control))
			return PTR_ERR(control);
		/* A dormant target may be configured now; publication waits for
		 * activation in sb_pre_fill and returns -EAGAIN until then. */
		rc = selinux_ns_control_authorize_parent(control, fc->cred);
		if (rc)
			goto out_control;
		rc = selinux_mnt_opts_ensure(fc, &opts);
		if (rc)
			goto out_control;
		if (opts->observer_control) {
			rc = -EINVAL;
			goto out_control;
		}
		if (opts->finalized)
			selinux_mnt_opts_drop_resolved(opts);
		opts->observer_control = control;
		return 0;

out_control:
		selinux_ns_control_put(control);
		return rc;
	}
#endif

	return selinux_add_opt(opt, param->string, &fc->security, fc->cred);
}

/* inode security operations */

static int selinux_inode_alloc_security(struct inode *inode)
{
	struct inode_security_struct *isec = selinux_inode(inode);
	int rc;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct cred_security_struct *crsec = selinux_cred(current_cred());
	struct selinux_global_sid_handle *task_handle;
#else
	u32 sid = current_sid();
#endif

	spin_lock_init(&isec->lock);
	INIT_LIST_HEAD(&isec->list);
	isec->inode = inode;
	isec->sclass = SECCLASS_FILE;
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!crsec->sid_handle ||
	    global_sid_handle_sid(crsec->sid_handle) != crsec->sid)
		return -ESTALE;
	task_handle = global_sid_handle_dup(crsec->sid_handle);
	if (IS_ERR(task_handle))
		return PTR_ERR(task_handle);
	rc = inode_security_take_task_sid_handle(isec, task_handle);
	if (rc)
		return rc;
#else
	isec->task_sid = sid;
#endif
	rc = inode_security_set_sid(isec, SECINITSID_UNLABELED,
				    SELINUX_LABEL_SOURCE_KERNEL_INITIAL,
				    LABEL_INVALID);
	if (rc) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		WARN_ON_ONCE(inode_security_take_task_sid_handle(isec, NULL));
#endif
		return rc;
	}

	return 0;
}

static void selinux_inode_free_security(struct inode *inode)
{
	inode_free_security(inode);
}

static int selinux_dentry_init_security(struct dentry *dentry, int mode,
					const struct qstr *name,
					const char **xattr_name,
					struct lsm_context *cp)
{
	u32 newsid;
	int rc;
	const char *ctx;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;

	handle = selinux_determine_inode_label_handle(
		selinux_cred(current_cred()), d_inode(dentry->d_parent), name,
		inode_mode_to_security_class(mode), &newsid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
#else

	rc = selinux_determine_inode_label(selinux_cred(current_cred()),
					   d_inode(dentry->d_parent), name,
					   inode_mode_to_security_class(mode),
					   &newsid);
	if (rc)
		return rc;
#endif

	if (xattr_name)
		*xattr_name = XATTR_NAME_SELINUX;

	cp->id = LSM_ID_SELINUX;
	rcu_read_lock();
	rc = security_sid_to_context(current_selinux_state, newsid,
				       &ctx, &cp->len);
	if (rc)
		goto out_unlock;

	cp->context = kmemdup(ctx, cp->len, GFP_ATOMIC);
	if (!cp->context)
		rc = -ENOMEM;

out_unlock:
	rcu_read_unlock();
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(handle);
#endif
	return rc;
}

static int selinux_dentry_create_files_as(struct dentry *dentry, int mode,
					  const struct qstr *name,
					  const struct cred *old,
					  struct cred *new)
{
	u32 newsid;
	struct cred_security_struct *crsec;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;

	handle = selinux_determine_inode_label_handle(
		selinux_cred(old), d_inode(dentry->d_parent), name,
		inode_mode_to_security_class(mode), &newsid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
#else
	int rc;

	rc = selinux_determine_inode_label(
		selinux_cred(old), d_inode(dentry->d_parent), name,
		inode_mode_to_security_class(mode), &newsid);
	if (rc)
		return rc;
#endif

	crsec = selinux_cred(new);
#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_cred_sid_take_handle(
		crsec, SELINUX_CRED_CREATE_SID, handle);
#else
	crsec->create_sid = newsid;
	return 0;
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static bool selinux_inode_create_plan_matches_init(
	const struct selinux_inode_create_plan *plan, struct inode *inode,
	struct inode *dir, const struct qstr *qstr)
{
	return plan && plan->requires_commit && !plan->committed &&
	       plan->dir == dir && plan->sb == inode->i_sb &&
	       plan->tclass == inode_mode_to_security_class(inode->i_mode) &&
	       qstr && qstr->len == plan->name.len &&
	       !memcmp(qstr->name, plan->name.name, qstr->len);
}

static int selinux_inode_init_security_plan(struct inode *inode,
					    struct inode *dir,
					    const struct qstr *qstr,
					    struct xattr *xattrs,
					    int *xattr_count)
{
	struct selinux_inode_create_plan *plan =
		selinux_task(current)->create_plan;
	struct xattr *xattr;
	int rc;

	if (!plan || !plan->requires_commit)
		return 0;
	rc = selinux_inode_create_plan_identity_valid(plan);
	if (rc)
		return rc;
	if (!selinux_inode_create_plan_matches_init(plan, inode, dir, qstr))
		return -EOPNOTSUPP;
	if (!selinux_policy_chain_snapshot_valid(&plan->chain))
		return -ESTALE;
	rc = inode_security_validate_label_class(
		selinux_inode(inode), plan->anchor_label, plan->anchor_sid);
	if (rc)
		return rc;
	if (!plan->requires_xattr) {
		plan->inode = inode;
		plan->xattr_prepared = true;
		return 0;
	}
	if (!xattrs)
		return -EOPNOTSUPP;
	xattr = lsm_get_xattr_slot(xattrs, xattr_count);
	if (!xattr)
		return -E2BIG;
	if (!plan->xattr_value || !plan->xattr_value_len)
		return -EIO;
	xattr->value = kmemdup(plan->xattr_value, plan->xattr_value_len,
				     GFP_KERNEL);
	if (!xattr->value)
		return -ENOMEM;
	xattr->value_len = plan->xattr_value_len;
	xattr->name = XATTR_SELINUX_SUFFIX;
	plan->inode = inode;
	plan->xattr_prepared = true;
	return 0;
}

static int selinux_inode_init_security_commit(struct inode *inode, int result)
{
	struct selinux_inode_create_plan *plan =
		selinux_task(current)->create_plan;
	struct selinux_global_sid_handle *handle;
	int rc;

	if (!plan || !plan->requires_commit)
		return 0;
	if (result)
		return result == -EOPNOTSUPP ? -EPROTO : 0;
	rc = selinux_inode_create_plan_owner_valid(plan, plan->generic);
	if (rc)
		return rc;
	if (!plan->xattr_prepared || plan->inode != inode || plan->committed)
		return -EPROTO;
	if (!plan->anchor_handle ||
	    global_sid_handle_sid(plan->anchor_handle) != plan->anchor_sid)
		return -ESTALE;
	handle = global_sid_handle_dup(plan->anchor_handle);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	rc = selinux_inode_security_take_sid_handle(
		selinux_inode(inode), handle, &plan->tclass, plan->source,
		LABEL_INITIALIZED);
	if (rc)
		return rc;
	plan->committed = true;
	return 0;
}
#endif

static int selinux_inode_init_security(struct inode *inode, struct inode *dir,
				       const struct qstr *qstr,
				       struct xattr *xattrs, int *xattr_count)
{
	const struct cred_security_struct *crsec = selinux_cred(current_cred());
	struct superblock_security_struct *sbsec;
	struct xattr *xattr;
	u32 newsid, clen;
	u16 newsclass;
	int rc;
	const char *context;
	char *value;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (selinux_task(current)->create_plan &&
	    selinux_task(current)->create_plan->requires_commit)
		return -EOPNOTSUPP;
#endif

	sbsec = selinux_superblock(dir->i_sb);

	if (!selinux_initialized(current_selinux_state) ||
	    !selinux_is_sblabel_mnt(dir->i_sb))
		return -EOPNOTSUPP;

	newsid = crsec->create_sid;
	newsclass = inode_mode_to_security_class(inode->i_mode);
#ifdef CONFIG_SECURITY_SELINUX_NS
	handle = selinux_determine_inode_label_handle(
		crsec, dir, qstr, newsclass, &newsid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	rc = 0;
#else
	rc = selinux_determine_inode_label(crsec, dir, qstr, newsclass, &newsid);
	if (rc)
		return rc;
#endif

	/* Possibly defer initialization to selinux_complete_init. */
	if (sbsec->flags & SE_SBINITIALIZED) {
		struct inode_security_struct *isec = selinux_inode(inode);

#ifdef CONFIG_SECURITY_SELINUX_NS
		struct selinux_global_sid_handle *inode_handle;

		inode_handle = global_sid_handle_dup(handle);
		if (IS_ERR(inode_handle)) {
			rc = PTR_ERR(inode_handle);
			goto out_handle;
		}
		rc = selinux_inode_security_take_sid_handle(
			isec, inode_handle, &newsclass,
			SELINUX_LABEL_SOURCE_TRANSITION, LABEL_INITIALIZED);
#else
		rc = inode_security_set_sid_class(
			isec, newsid, newsclass, SELINUX_LABEL_SOURCE_TRANSITION,
			LABEL_INITIALIZED);
#endif
		if (rc)
			goto out_handle;
	}

	xattr = lsm_get_xattr_slot(xattrs, xattr_count);

	rcu_read_lock();
	if (xattr) {
		rc = security_sid_to_context_force(current_selinux_state, newsid,
						   &context, &clen);
		if (rc)
			goto out_unlock;

		value = kmemdup(context, clen, GFP_ATOMIC);
		if (!(value)) {
			rc = -ENOMEM;
			goto out_unlock;
		}

		xattr->value = value;
		xattr->value_len = clen;
		xattr->name = XATTR_SELINUX_SUFFIX;
	}

out_unlock:
	rcu_read_unlock();
out_handle:
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(handle);
#endif
	return rc;
}

#ifndef CONFIG_SECURITY_SELINUX_NS
static int selinux_memfd_init_security(struct inode *inode,
				       const struct qstr *name,
				       const struct inode *context_inode)
{
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	struct common_audit_data ad;
	enum selinux_label_source source;
	u32 context_sid = 0, leaf_sid = 0;
	u16 context_sclass = 0, leaf_sclass = 0;
	unsigned int retry;
	bool leaf_enabled;

	if (context_inode) {
		struct inode_security_struct *context_isec =
			selinux_inode(context_inode);

		spin_lock(&context_isec->lock);
		if (context_isec->initialized != LABEL_INITIALIZED) {
			spin_unlock(&context_isec->lock);
			pr_err("SELinux:  context_inode is not initialized\n");
			return -EACCES;
		}
		context_sclass = context_isec->sclass;
		context_sid = context_isec->sid;
		spin_unlock(&context_isec->lock);
		source = SELINUX_LABEL_SOURCE_SECURITY_CONTEXT;
	} else {
		source = SELINUX_LABEL_SOURCE_TRANSITION;
	}

	ad.type = LSM_AUDIT_DATA_ANONINODE;
	ad.u.anonclass = name ? (const char *)name->name : "?";
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;
		int rc;

		rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		leaf_enabled = false;

		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&chain->policy[i];
			u32 inode_sid;
			u16 sclass;

			if (!selinux_policycap_memfd_class(snapshot))
				continue;
			if (context_inode) {
				sclass = context_sclass;
				inode_sid = context_sid;
			} else {
				sclass = SECCLASS_MEMFD_FILE;
				rc = security_transition_sid(crsec->state, crsec->sid,
							     crsec->sid, sclass,
							     name, &inode_sid);
				if (rc) {
					if (!selinux_policy_snapshot_valid(
						    crsec->state, snapshot)) {
						rc = -ESTALE;
						break;
					}
					return rc;
				}
			}
			rc = avc_has_perm_snapshot(crsec->state, snapshot,
						   crsec->sid, inode_sid, sclass,
						   FILE__CREATE, &ad);
			if (rc)
				break;
			if (!i) {
				leaf_enabled = true;
				leaf_sid = inode_sid;
				leaf_sclass = sclass;
			}
		}
		if (rc == -EAGAIN || rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain))
			continue;
		if (rc)
			return rc;
		if (!leaf_enabled)
			return 0;
		return inode_security_set_sid_class(
			selinux_inode(inode), leaf_sid, leaf_sclass, source,
			LABEL_INITIALIZED);
	}

	return -ESTALE;
}
#else
static int selinux_pathless_prepare_inode(
	struct inode *inode, enum selinux_pathless_kind kind,
	const struct inode *context_inode)
{
	struct inode_security_struct *isec = selinux_inode(inode);
	struct selinux_pathless_projection *context = NULL;

	if (context_inode) {
		struct inode_security_struct *context_isec =
			selinux_inode(context_inode);

		spin_lock(&context_isec->lock);
		if (context_isec->initialized == LABEL_INITIALIZED)
			context = selinux_pathless_projection_get(
				rcu_dereference_protected(
					context_isec->pathless,
					lockdep_is_held(&context_isec->lock)));
		spin_unlock(&context_isec->lock);
		/* A dentry-only inode cannot identify the mount view used for access. */
		if (!context)
			return -EXDEV;
	}

	spin_lock(&isec->lock);
	if (isec->pathless_kind != SELINUX_PATHLESS_KIND_INVALID ||
	    rcu_access_pointer(isec->pathless) || isec->pathless_context) {
		spin_unlock(&isec->lock);
		selinux_pathless_projection_put(context);
		return -EALREADY;
	}
	isec->pathless_kind = kind;
	isec->pathless_context = context;
	spin_unlock(&isec->lock);
	return 0;
}
#endif

static int selinux_inode_init_security_anon(struct inode *inode,
					    const struct qstr *name,
					    const struct inode *context_inode)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (name && name->name && !strcmp(name->name, MEMFD_ANON_NAME))
		return selinux_pathless_prepare_inode(
			inode, SELINUX_PATHLESS_KIND_MEMFD, context_inode);
	return selinux_pathless_prepare_inode(
		inode, SELINUX_PATHLESS_KIND_ANON_INODE, context_inode);
#else
	u32 sid = current_sid();
	u32 inode_sid;
	u16 sclass;
	struct common_audit_data ad;
	struct inode_security_struct *isec;
	enum selinux_label_source source;
	int rc;

	if (unlikely(!selinux_initialized(current_selinux_state)))
		return 0;

	if (name != NULL && name->name != NULL &&
	    !strcmp(name->name, MEMFD_ANON_NAME))
		return selinux_memfd_init_security(inode, name, context_inode);

	isec = selinux_inode(inode);

	/*
	 * We only get here once per ephemeral inode.  The inode has
	 * been initialized via inode_alloc_security but is otherwise
	 * untouched.
	 */

	if (context_inode) {
		struct inode_security_struct *context_isec =
			selinux_inode(context_inode);

		spin_lock(&context_isec->lock);
		if (context_isec->initialized != LABEL_INITIALIZED) {
			spin_unlock(&context_isec->lock);
			pr_err("SELinux:  context_inode is not initialized\n");
			return -EACCES;
		}

		sclass = context_isec->sclass;
		inode_sid = context_isec->sid;
		spin_unlock(&context_isec->lock);
		source = SELINUX_LABEL_SOURCE_SECURITY_CONTEXT;
	} else {
		sclass = SECCLASS_ANON_INODE;
		rc = security_transition_sid(current_selinux_state, sid, sid,
					     sclass, name, &inode_sid);
		if (rc)
			return rc;
		source = SELINUX_LABEL_SOURCE_TRANSITION;
	}

	rc = inode_security_set_sid_class(isec, inode_sid, sclass, source,
					  LABEL_INITIALIZED);
	if (rc)
		return rc;
	/*
	 * Now that we've initialized security, check whether we're
	 * allowed to actually create this type of anonymous inode.
	 */

	ad.type = LSM_AUDIT_DATA_ANONINODE;
	ad.u.anonclass = name ? (const char *)name->name : "?";

	return cred_tsid_has_perm(current_cred(), isec->sid, isec->sclass,
				  FILE__CREATE, &ad);
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_inode_init_security_nsfs(struct inode *inode,
					    struct ns_common *ns)
{
	/*
	 * nsfs dentries are stashed and can later be reopened without the path
	 * which created them.  Delay publication until struct file exists, but
	 * mark the inode now so file_set_path cannot accidentally capture the
	 * root-only internal nsfs mount view.
	 */
	if (!ns)
		return -EINVAL;
	return selinux_pathless_prepare_inode(inode,
					      SELINUX_PATHLESS_KIND_NSFS, NULL);
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_pathless_build_scratch {
	struct selinux_policy_chain_snapshot chain;
	struct selinux_pathless_expect
		expects[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct selinux_global_sid_handle
		*producer_handles[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct selinux_label_resolution legacy;
	struct selinux_pathless_chain_resolution operation_line;
};

static void selinux_pathless_producer_handles_put(
	struct selinux_pathless_build_scratch *scratch)
{
	u16 i;

	for (i = 0; i <= SELINUX_LABEL_RESOLUTION_MAX_DEPTH; i++) {
		global_sid_handle_put(scratch->producer_handles[i]);
		scratch->producer_handles[i] = NULL;
	}
}

static int selinux_pathless_chain_validate(
	struct selinux_pathless_build_scratch *scratch)
{
	const struct selinux_policy_chain_snapshot *chain = &scratch->chain;
	const struct selinux_label_domain *previous = NULL;
	u16 i;

	if (!chain->count)
		return -EINVAL;
	if (selinux_cred(chain->cred[0])->state->label_domain->depth + 1 !=
	    chain->count)
		return -EXDEV;

	for (i = chain->count; i-- > 0;) {
		const struct cred_security_struct *crsec =
			selinux_cred(chain->cred[i]);
		const struct selinux_label_domain *domain =
			crsec->state->label_domain;
		u16 depth = chain->count - i - 1;

		if (!domain || crsec->state->depth != depth ||
		    domain->depth != depth || domain->parent != previous)
			return -EXDEV;
		if (i + 1 < chain->count &&
		    (crsec->state->parent !=
			     selinux_cred(chain->cred[i + 1])->state ||
		     crsec->parent_cred != chain->cred[i + 1]))
			return -EXDEV;
		if (i + 1 == chain->count &&
		    (crsec->state->parent || crsec->parent_cred))
			return -EXDEV;
		scratch->expects[depth].domain = domain;
		previous = domain;
	}
	return 0;
}

/*
 * Materialize one immutable object identity after the caller has computed the
 * exact SID/class expected by every policy in @scratch->chain.  The leaf SID
 * remains the canonical identity; sealed parent mappings must reproduce all
 * caller-supplied expectations or allocation fails closed.
 */
static int selinux_pathless_build_sealed(
	struct selinux_pathless_build_scratch *scratch,
	enum selinux_pathless_kind kind, enum selinux_label_source source,
	u32 leaf_sid, const struct selinux_label_view *anchored_view, gfp_t gfp,
	struct selinux_pathless_projection **projectionp)
{
	const struct selinux_policy_chain_snapshot *chain = &scratch->chain;
	const struct selinux_label_view *view = NULL;
	struct selinux_label_domain *leaf_domain, *outer_domain;
	struct selinux_label_ref *label;
	struct selinux_pathless_projection *projection;
	bool kernel_global;
	int rc;

	*projectionp = NULL;
	if (!chain->count || !leaf_sid)
		return -EINVAL;
	leaf_domain = selinux_cred(chain->cred[0])->state->label_domain;
	outer_domain = selinux_cred(chain->cred[chain->count - 1])->
			       state->label_domain;
	if (!leaf_domain || !outer_domain)
		return -EXDEV;

	label = global_sid_to_label_ref(leaf_sid);
	if (IS_ERR(label))
		return PTR_ERR(label);
	kernel_global = label->domain->flags &
			SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL;
	if ((!kernel_global && label->domain != leaf_domain) ||
	    (kernel_global && leaf_sid > SECINITSID_NUM)) {
		rc = -EXDEV;
		goto out;
	}
	/*
	 * Initial SIDs belong to the immutable kernel-global label domain.  The
	 * caller describes how the SID was selected (for example, from a task or
	 * keycreate_sid), but the canonical label itself originates in the kernel
	 * bootstrap table.  Preserve that provenance so early-boot pathless
	 * objects can be sealed before a policy is loaded.
	 */
	if (kernel_global)
		source = SELINUX_LABEL_SOURCE_KERNEL_INITIAL;

	if (anchored_view) {
		if (anchored_view->origin_domain != leaf_domain ||
		    anchored_view->outer_domain != outer_domain ||
		    anchored_view->map_count != leaf_domain->depth) {
			rc = -EXDEV;
			goto out;
		}
		view = selinux_label_view_get(anchored_view);
	} else {
		view = selinux_identity_view_alloc_gfp(
			leaf_domain->owner_userns, leaf_domain, outer_domain, gfp);
		if (IS_ERR(view)) {
			rc = PTR_ERR(view);
			view = NULL;
			goto out;
		}
	}
	rc = selinux_label_view_resolve_chain(
		view, label, leaf_sid, &scratch->legacy);
	if (rc)
		goto out;
	if (scratch->legacy.max_depth != chain->count - 1) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	{
		u16 i;

		for (i = 0; i < chain->count; i++) {
			struct selinux_pathless_expect *expect =
				&scratch->expects[i];

			if (!expect->domain ||
			    scratch->legacy.domain_id[i] != expect->domain->id ||
			    !scratch->legacy.sid[i] ||
			    (expect->sid &&
			     expect->sid != scratch->legacy.sid[i])) {
				rc = -EOPNOTSUPP;
				goto out;
			}
			expect->sid = scratch->legacy.sid[i];
		}
	}
	projection = selinux_pathless_projection_alloc_sealed(
		kind, source, label, leaf_sid, view, scratch->expects,
		chain->count, gfp);
	if (IS_ERR(projection)) {
		rc = PTR_ERR(projection);
		goto out;
	}
	*projectionp = projection;
	rc = 0;
out:
	selinux_label_view_put(view);
	selinux_label_ref_put(label);
	return rc;
}

static int selinux_creator_projection_build(
	const struct cred *cred, enum selinux_pathless_kind kind, u16 sclass,
	bool use_keycreate_sid, u32 requested, struct common_audit_data *ad,
	const struct selinux_label_view *anchored_view, u32 *leaf_sidp,
	struct selinux_pathless_projection **projectionp)
{
	struct selinux_pathless_build_scratch *scratch;
	unsigned int retry;
	int rc = -ESTALE;

	*projectionp = NULL;
	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		struct selinux_pathless_projection *projection = NULL;
		bool explicit_keycreate;
		u32 leaf_sid;
		u16 i;

		memset(scratch, 0, sizeof(*scratch));
		rc = selinux_policy_chain_snapshot_read(cred, &scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_pathless_chain_validate(scratch);
		if (rc)
			break;

		explicit_keycreate = use_keycreate_sid &&
			selinux_cred(scratch->chain.cred[0])->keycreate_sid;
		leaf_sid = selinux_cred(scratch->chain.cred[0])->sid;
		if (explicit_keycreate)
			leaf_sid = selinux_cred(
				scratch->chain.cred[0])->keycreate_sid;
		for (i = 0; i < scratch->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(scratch->chain.cred[i]);
			struct selinux_pathless_expect *expect =
				&scratch->expects[crsec->state->label_domain->depth];

			expect->sclass = sclass;
			expect->model = SELINUX_PATHLESS_MODEL_LEGACY;
		}

		rc = selinux_pathless_build_sealed(
			scratch, kind,
			explicit_keycreate ?
				SELINUX_LABEL_SOURCE_SECURITY_CONTEXT :
				SELINUX_LABEL_SOURCE_TASK,
			leaf_sid, anchored_view, GFP_KERNEL, &projection);
		if (rc)
			goto next_retry;
		if (requested) {
			rc = cred_pathless_has_perm(cred, projection, requested, ad);
			if (rc)
				goto next_retry;
		}
		if (!selinux_policy_chain_snapshot_valid(&scratch->chain)) {
			rc = -ESTALE;
			goto next_retry;
		}

		*leaf_sidp = leaf_sid;
		*projectionp = projection;
		rc = 0;
		break;
next_retry:
		selinux_pathless_projection_put(projection);
		if (rc != -EAGAIN && rc != -ESTALE)
			break;
	}
	kfree(scratch);
	return rc;
}

static int selinux_pathless_capture_legacy(
	struct inode_security_struct *isec, struct selinux_label_ref **label,
	u32 *sid, u16 *sclass, enum selinux_label_source *source,
	enum label_initialized *initialized)
{
	spin_lock(&isec->lock);
	*label = selinux_label_ref_get(
		rcu_dereference_protected(isec->label_ref,
					  lockdep_is_held(&isec->lock)));
	*sid = isec->sid;
	*sclass = isec->sclass;
	*source = isec->label_source;
	*initialized = isec->initialized;
	spin_unlock(&isec->lock);

	return *label && *sid && *sclass ? 0 : -EIO;
}

static void selinux_pathless_cancel_pending(struct inode_security_struct *isec)
{
	struct selinux_pathless_projection *context;

	spin_lock(&isec->lock);
	context = isec->pathless_context;
	isec->pathless_context = NULL;
	isec->pathless_kind = SELINUX_PATHLESS_KIND_INVALID;
	spin_unlock(&isec->lock);
	selinux_pathless_projection_put(context);
}

static int selinux_pathless_publish(
	struct file *file, struct selinux_pathless_projection *projection,
	struct selinux_label_ref *legacy_label, u32 legacy_sid,
	u16 legacy_sclass, enum selinux_label_source legacy_source,
	enum label_initialized legacy_initialized,
	struct selinux_pathless_projection *context)
{
	struct inode_security_struct *isec = selinux_inode(file_inode(file));
	struct file_security_struct *fsec = selinux_file(file);
	struct selinux_pathless_projection *inode_projection, *file_projection;
	struct selinux_pathless_projection *pending_context;
	const struct selinux_label_view *file_view;
	const struct selinux_pathless_seal *leaf_seal;
	struct selinux_global_sid_handle *new_handle, *old_handle;
	struct selinux_global_sid_handle *old_task_handle;
	struct selinux_label_ref *old_label, *new_label;
	const struct selinux_label_view *old_view;
	struct selinux_pathless_resolution leaf;
	int rc;

	if (fsec->pathless)
		return -EALREADY;
	/* Relabel owns the inode tuple until its xattr/tuple commit finishes. */
	if (selinux_inode_relabel_in_progress(file_inode(file)))
		return -EBUSY;
	rc = selinux_pathless_projection_resolve_sealed(
		projection, projection->view->origin_domain, &leaf);
	if (rc)
		return rc;

	leaf_seal = &projection->seals[projection->view->origin_domain->depth];
	new_handle = global_sid_handle_dup(leaf_seal->sid_handle);
	if (IS_ERR(new_handle))
		return PTR_ERR(new_handle);
	if (global_sid_handle_sid(new_handle) != leaf.sid) {
		global_sid_handle_put(new_handle);
		return -ESTALE;
	}
	new_label = global_sid_handle_label_get(new_handle);
	if (!new_label || new_label != projection->label) {
		selinux_label_ref_put(new_label);
		global_sid_handle_put(new_handle);
		return -ESTALE;
	}
	inode_projection = selinux_pathless_projection_get(projection);
	file_projection = selinux_pathless_projection_get(projection);
	file_view = selinux_label_view_get(projection->view);

	spin_lock(&isec->lock);
	old_label = rcu_dereference_protected(
		isec->label_ref, lockdep_is_held(&isec->lock));
	if (selinux_inode_relabel_in_progress(file_inode(file)) ||
	    isec->pathless_kind != projection->kind ||
	    rcu_access_pointer(isec->pathless) || old_label != legacy_label ||
	    !isec->sid_handle ||
	    global_sid_handle_sid(isec->sid_handle) != legacy_sid ||
	    isec->sid != legacy_sid || isec->sclass != legacy_sclass ||
	    isec->label_source != legacy_source ||
	    isec->initialized != legacy_initialized ||
	    isec->pathless_context != context) {
		spin_unlock(&isec->lock);
		selinux_label_view_put(file_view);
		selinux_pathless_projection_put(file_projection);
		selinux_pathless_projection_put(inode_projection);
		selinux_label_ref_put(new_label);
		global_sid_handle_put(new_handle);
		return -ESTALE;
	}

	pending_context = isec->pathless_context;
	old_handle = isec->sid_handle;
	old_task_handle = isec->task_sid_handle;
	isec->pathless_context = NULL;
	rcu_assign_pointer(isec->label_ref, new_label);
	rcu_assign_pointer(isec->pathless, inode_projection);
	isec->sid_handle = new_handle;
	isec->sid = leaf.sid;
	isec->sclass = leaf.sclass;
	isec->label_source = projection->source;
	isec->initialized = LABEL_INITIALIZED;
	isec->task_sid_handle = NULL;
	isec->task_sid = SECSID_NULL;
	spin_unlock(&isec->lock);

	old_view = fsec->view;
	fsec->view = file_view;
	fsec->pathless = file_projection;
	selinux_label_view_put(old_view);
	global_sid_handle_put(old_task_handle);
	global_sid_handle_put(old_handle);
	selinux_label_ref_put(old_label);
	selinux_pathless_projection_put(pending_context);
	return 0;
}

static int selinux_file_init_security_anon(struct file *file)
{
	struct selinux_pathless_build_scratch *scratch;
	struct inode *inode = file_inode(file);
	struct inode_security_struct *isec = selinux_inode(inode);
	struct selinux_pathless_projection *projection = NULL, *context = NULL;
	const struct selinux_label_view *view = NULL;
	struct selinux_label_ref *legacy_label = NULL, *final_label = NULL;
	struct selinux_label_domain *leaf_domain, *outer_domain;
	struct common_audit_data ad;
	const struct qstr memfd_name = QSTR(MEMFD_ANON_NAME);
	const struct qstr *transition_name;
	enum selinux_label_source legacy_source, final_source;
	enum label_initialized legacy_initialized;
	enum selinux_pathless_kind kind;
	u32 legacy_sid;
	u16 legacy_sclass;
	unsigned int retry;
	int rc = -ESTALE;

	spin_lock(&isec->lock);
	kind = isec->pathless_kind;
	context = selinux_pathless_projection_get(isec->pathless_context);
	spin_unlock(&isec->lock);
	if (kind != SELINUX_PATHLESS_KIND_ANON_INODE &&
	    kind != SELINUX_PATHLESS_KIND_MEMFD) {
		rc = kind == SELINUX_PATHLESS_KIND_INVALID ? 0 : -EINVAL;
		goto out_context;
	}

	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch) {
		rc = -ENOMEM;
		goto out_context;
	}

	/* Materialize the filesystem's definitive legacy tuple before sealing. */
	inode_security(inode);
	rc = selinux_pathless_capture_legacy(
		isec, &legacy_label, &legacy_sid, &legacy_sclass,
		&legacy_source, &legacy_initialized);
	if (rc)
		goto out_scratch;

	transition_name = kind == SELINUX_PATHLESS_KIND_MEMFD ?
				  &memfd_name : &file->f_path.dentry->d_name;
	ad.type = LSM_AUDIT_DATA_ANONINODE;
	ad.u.anonclass = transition_name->name;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;

		selinux_pathless_producer_handles_put(scratch);
		memset(scratch, 0, sizeof(*scratch));
		rc = selinux_policy_chain_snapshot_read(file->f_cred,
						&scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_pathless_chain_validate(scratch);
		if (rc)
			break;

		/* Preserve upstream bootstrap only before the root policy exists. */
		if (!scratch->chain.policy[0].initialized) {
			if (scratch->chain.count != 1) {
				rc = -EACCES;
				break;
			}
			selinux_pathless_cancel_pending(isec);
			rc = 0;
			break;
		}
		for (i = 0; i < scratch->chain.count; i++) {
			if (!scratch->chain.policy[i].initialized) {
				rc = -EACCES;
				goto next_retry;
			}
		}

		leaf_domain = selinux_cred(scratch->chain.cred[0])->
				      state->label_domain;
		outer_domain = selinux_cred(
			scratch->chain.cred[scratch->chain.count - 1])->
				       state->label_domain;
		view = selinux_identity_view_alloc_gfp(
			leaf_domain->owner_userns, leaf_domain,
			outer_domain, GFP_KERNEL);
		if (IS_ERR(view)) {
			rc = PTR_ERR(view);
			view = NULL;
			break;
		}
		rc = selinux_label_view_resolve_chain(
			view, legacy_label, legacy_sid, &scratch->legacy);
		if (rc)
			break;

		for (i = 0; i < scratch->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(scratch->chain.cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&scratch->chain.policy[i];
			struct selinux_pathless_expect *expect =
				&scratch->expects[crsec->state->label_domain->depth];
			struct selinux_pathless_resolution copied;
			bool legacy;

			legacy = kind == SELINUX_PATHLESS_KIND_MEMFD &&
				 !selinux_policycap_memfd_class(snapshot);
			if (legacy) {
				expect->sid = scratch->legacy.sid[
					crsec->state->label_domain->depth];
				expect->sclass = legacy_sclass;
				expect->model = SELINUX_PATHLESS_MODEL_LEGACY;
				if (!expect->sid) {
					rc = -EOPNOTSUPP;
					break;
				}
				continue;
			}

			if (context) {
				rc = selinux_pathless_projection_resolve_sealed(
					context, crsec->state->label_domain,
					&copied);
				if (rc)
					break;
				expect->sid = copied.sid;
				expect->sclass = copied.sclass;
				expect->model =
					SELINUX_PATHLESS_MODEL_CONTEXT_COPY;
			} else {
				u16 depth = crsec->state->label_domain->depth;

				expect->sclass =
					kind == SELINUX_PATHLESS_KIND_MEMFD ?
					SECCLASS_MEMFD_FILE : SECCLASS_ANON_INODE;
				scratch->producer_handles[depth] =
					security_transition_sid_handle(
					crsec->state, crsec->sid, crsec->sid,
					expect->sclass, transition_name,
					&expect->sid);
				if (IS_ERR(scratch->producer_handles[depth])) {
					rc = PTR_ERR(scratch->producer_handles[depth]);
					scratch->producer_handles[depth] = NULL;
					break;
				}
				expect->model = SELINUX_PATHLESS_MODEL_TRANSITION;
			}
		}
		if (rc)
			goto next_retry;

		{
			struct selinux_pathless_expect *leaf =
				&scratch->expects[leaf_domain->depth];

			final_source = leaf->model == SELINUX_PATHLESS_MODEL_LEGACY ?
				       legacy_source :
				       leaf->model ==
					       SELINUX_PATHLESS_MODEL_CONTEXT_COPY ?
				       SELINUX_LABEL_SOURCE_SECURITY_CONTEXT :
				       SELINUX_LABEL_SOURCE_TRANSITION;
			final_label = global_sid_to_label_ref(leaf->sid);
			if (IS_ERR(final_label)) {
				rc = PTR_ERR(final_label);
				final_label = NULL;
				goto next_retry;
			}
			projection = selinux_pathless_projection_alloc_sealed(
				kind, final_source, final_label, leaf->sid, view,
				scratch->expects, scratch->chain.count,
				GFP_KERNEL);
			if (IS_ERR(projection)) {
				rc = PTR_ERR(projection);
				projection = NULL;
				goto next_retry;
			}
		}
		rc = selinux_pathless_create_has_perm(
			file->f_cred, projection, &ad);
		if (rc)
			goto next_retry;

		if (!selinux_policy_chain_snapshot_valid(&scratch->chain)) {
			rc = -ESTALE;
			goto next_retry;
		}
		rc = selinux_pathless_publish(
			file, projection, legacy_label, legacy_sid, legacy_sclass,
			legacy_source, legacy_initialized, context);
		if (!rc)
			break;

next_retry:
		if (!selinux_policy_chain_snapshot_valid(&scratch->chain))
			rc = -ESTALE;
		selinux_pathless_projection_put(projection);
		projection = NULL;
		selinux_label_ref_put(final_label);
		final_label = NULL;
		selinux_label_view_put(view);
		view = NULL;
		if (rc != -EAGAIN && rc != -ESTALE)
			break;
	}

	selinux_pathless_projection_put(projection);
	selinux_label_ref_put(final_label);
	selinux_label_view_put(view);
out_scratch:
	selinux_label_ref_put(legacy_label);
	selinux_pathless_producer_handles_put(scratch);
	kfree(scratch);
out_context:
	selinux_pathless_projection_put(context);
	return rc;
}

static int selinux_nsfs_bind_file_projection(
	struct file *file, struct selinux_pathless_projection *projection)
{
	struct file_security_struct *fsec = selinux_file(file);
	const struct selinux_label_view *old_view;

	if (!projection || projection->kind != SELINUX_PATHLESS_KIND_NSFS ||
	    fsec->pathless)
		return -EINVAL;
	old_view = fsec->view;
	fsec->view = selinux_label_view_get(projection->view);
	fsec->pathless = selinux_pathless_projection_get(projection);
	selinux_label_view_put(old_view);
	return 0;
}

/*
 * Seal the label which nsfs/genfs assigned to the inode, rather than
 * reinterpreting its numeric SID in the caller's policy.  The view spans the
 * complete credential chain and retains every parent-sealed boundary map.
 */
static int selinux_file_init_security_nsfs(struct file *file)
{
	struct selinux_pathless_build_scratch *scratch;
	struct inode *inode = file_inode(file);
	struct inode_security_struct *isec = selinux_inode(inode);
	struct selinux_pathless_projection *projection = NULL, *published;
	const struct selinux_label_view *view = NULL;
	struct selinux_label_ref *legacy_label = NULL;
	struct selinux_label_domain *leaf_domain, *root_domain, *origin_domain;
	struct selinux_label_domain *cursor;
	enum selinux_label_source legacy_source, projection_source;
	enum label_initialized legacy_initialized;
	u32 legacy_sid;
	u16 legacy_sclass;
	unsigned int retry;
	bool kernel_global;
	int rc = -ESTALE;

	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	published = selinux_inode_pathless_get(isec);

	/* Materialize nsfs's definitive genfs/task tuple before sealing it. */
	inode_security(inode);
	rc = selinux_pathless_capture_legacy(
		isec, &legacy_label, &legacy_sid, &legacy_sclass,
		&legacy_source, &legacy_initialized);
	if (rc)
		goto out_scratch;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;

		memset(scratch, 0, sizeof(*scratch));
		rc = selinux_policy_chain_snapshot_read(file->f_cred,
						&scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_pathless_chain_validate(scratch);
		if (rc)
			break;
		/*
		 * A stashed nsfs inode may have been materialized by an earlier
		 * opener, including during policy-less bootstrap.  Resolve that exact
		 * canonical projection for this operation's chain; do not reconstruct
		 * its identity from the legacy numeric SID.
		 */
		if (published) {
			struct selinux_pathless_chain_resolution *line =
				&scratch->operation_line;

			rc = selinux_pathless_projection_resolve_cred_chain(
				published, scratch->chain.cred, scratch->chain.policy,
				scratch->chain.count, line);
			selinux_pathless_chain_resolution_put(line);
			if (rc)
				goto next_retry;
			if (!selinux_policy_chain_snapshot_valid(&scratch->chain)) {
				rc = -ESTALE;
				goto next_retry;
			}
			rc = selinux_nsfs_bind_file_projection(file, published);
			if (!rc)
				break;
			goto next_retry;
		}

		leaf_domain = selinux_cred(scratch->chain.cred[0])->
				      state->label_domain;
		root_domain = selinux_cred(
			scratch->chain.cred[scratch->chain.count - 1])->
				       state->label_domain;
		kernel_global = legacy_label->domain->flags &
				SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL;

		/*
		 * A kernel initial SID has policy-independent meaning, so seal that
		 * root bootstrap tuple immediately.  Any other policy-less tuple
		 * remains pending for post-policy genfs initialization.
		 */
		if (!scratch->chain.policy[0].initialized) {
			if (scratch->chain.count != 1) {
				rc = -EACCES;
				break;
			}
			if (!kernel_global || legacy_sid > SECINITSID_NUM) {
				rc = 0;
				break;
			}
		}
		for (i = 0; scratch->chain.policy[0].initialized &&
			    i < scratch->chain.count; i++) {
			if (!scratch->chain.policy[i].initialized) {
				rc = -EACCES;
				goto next_retry;
			}
		}

		projection_source = legacy_source;
		if (kernel_global) {
			if (legacy_sid > SECINITSID_NUM) {
				rc = -EXDEV;
				goto next_retry;
			}
			origin_domain = leaf_domain;
			projection_source = SELINUX_LABEL_SOURCE_KERNEL_INITIAL;
		} else {
			for (cursor = leaf_domain; cursor; cursor = cursor->parent)
				if (cursor == legacy_label->domain)
					break;
			if (!cursor) {
				rc = -EXDEV;
				goto next_retry;
			}
			origin_domain = legacy_label->domain;
		}

		view = selinux_identity_view_alloc_gfp(
			leaf_domain->owner_userns, origin_domain,
			origin_domain == leaf_domain ? root_domain : leaf_domain,
			GFP_KERNEL);
		if (IS_ERR(view)) {
			rc = PTR_ERR(view);
			view = NULL;
			goto next_retry;
		}
		rc = selinux_label_view_resolve_chain(
			view, legacy_label, legacy_sid, &scratch->legacy);
		if (rc)
			goto next_retry;
		if (scratch->legacy.max_depth != scratch->chain.count - 1) {
			rc = -EOPNOTSUPP;
			goto next_retry;
		}
		for (i = 0; i < scratch->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(scratch->chain.cred[i]);
			u16 depth = crsec->state->label_domain->depth;
			struct selinux_pathless_expect *expect =
				&scratch->expects[depth];

			if (scratch->legacy.domain_id[depth] !=
				    crsec->state->label_domain->id ||
			    !scratch->legacy.sid[depth]) {
				rc = -EOPNOTSUPP;
				break;
			}
			expect->sid = scratch->legacy.sid[depth];
			expect->sclass = legacy_sclass;
			expect->model = SELINUX_PATHLESS_MODEL_LEGACY;
		}
		if (rc)
			goto next_retry;

		projection = selinux_pathless_projection_alloc_sealed(
			SELINUX_PATHLESS_KIND_NSFS, projection_source,
			legacy_label, legacy_sid, view, scratch->expects,
			scratch->chain.count, GFP_KERNEL);
		if (IS_ERR(projection)) {
			rc = PTR_ERR(projection);
			projection = NULL;
			goto next_retry;
		}
		if (!selinux_policy_chain_snapshot_valid(&scratch->chain)) {
			rc = -ESTALE;
			goto next_retry;
		}
		rc = selinux_pathless_publish(
			file, projection, legacy_label, legacy_sid,
			legacy_sclass, legacy_source, legacy_initialized, NULL);
		if (!rc)
			break;

next_retry:
		selinux_pathless_projection_put(projection);
		projection = NULL;
		selinux_label_view_put(view);
		view = NULL;
		if (rc == -ESTALE && !published) {
			published = selinux_inode_pathless_get(isec);
			if (published)
				continue;
		}
		if (rc != -EAGAIN && rc != -ESTALE)
			break;
	}

	selinux_pathless_projection_put(projection);
	selinux_label_view_put(view);
	selinux_label_ref_put(legacy_label);
out_scratch:
	selinux_pathless_projection_put(published);
	kfree(scratch);
	return rc;
}

static int selinux_file_kho_preserve(struct file *file)
{
	struct file_security_struct *fsec = selinux_file(file);

	/*
	 * memfd-luo-v2 carries data, position and seals only. Recreating the
	 * file would bind it to the restoring task and silently discard its
	 * canonical creator domain and sealed policy-chain identity.
	 */
	if (!fsec->pathless ||
	    fsec->pathless->kind != SELINUX_PATHLESS_KIND_MEMFD ||
	    fsec->view != fsec->pathless->view)
		return -EACCES;
	return -EOPNOTSUPP;
}
#endif

static int selinux_inode_create(const struct vfsmount *mnt, struct inode *dir,
				struct dentry *dentry, umode_t mode)
{
	return may_create(mnt, dir, dentry, SECCLASS_FILE);
}

static int selinux_inode_link(const struct vfsmount *old_mnt,
			      struct dentry *old_dentry,
			      const struct vfsmount *new_mnt, struct inode *dir,
			      struct dentry *new_dentry)
{
	return may_link(new_mnt, old_mnt, dir, old_dentry, MAY_LINK);
}

static int selinux_inode_unlink(const struct vfsmount *mnt, struct inode *dir,
				struct dentry *dentry)
{
	return may_link(mnt, mnt, dir, dentry, MAY_UNLINK);
}

static int selinux_inode_symlink(const struct vfsmount *mnt, struct inode *dir,
				 struct dentry *dentry, const char *name)
{
	return may_create(mnt, dir, dentry, SECCLASS_LNK_FILE);
}

static int selinux_inode_mkdir(const struct vfsmount *mnt, struct inode *dir,
			       struct dentry *dentry, umode_t mask)
{
	return may_create(mnt, dir, dentry, SECCLASS_DIR);
}

static int selinux_inode_rmdir(const struct vfsmount *mnt, struct inode *dir,
			       struct dentry *dentry)
{
	return may_link(mnt, mnt, dir, dentry, MAY_RMDIR);
}

static int selinux_inode_mknod(const struct vfsmount *mnt, struct inode *dir,
			       struct dentry *dentry, umode_t mode, dev_t dev)
{
	return may_create(mnt, dir, dentry,
			  inode_mode_to_security_class(mode));
}

static int selinux_inode_rename(const struct vfsmount *old_mnt,
				struct inode *old_inode,
				struct dentry *old_dentry,
				const struct vfsmount *new_mnt,
				struct inode *new_inode,
				struct dentry *new_dentry)
{
	return may_rename(old_mnt, old_inode, old_dentry, new_mnt, new_inode,
			  new_dentry);
}

static int selinux_inode_readlink(const struct vfsmount *mnt,
				  struct dentry *dentry)
{
	const struct cred *cred = current_cred();

	return dentry_has_perm_mnt(cred, mnt, dentry, FILE__READ);
}

static int selinux_inode_follow_link(const struct vfsmount *mnt,
				     struct dentry *dentry, struct inode *inode,
				     bool rcu)
{
	const struct cred *cred = current_cred();
	struct common_audit_data ad;
	struct inode_security_struct *isec;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct cred_security_struct *crsec = selinux_cred(cred);
	const struct selinux_label_view *view;
	struct selinux_inode_label_snapshot snapshot;
	int rc;

	if (!selinux_initialized(crsec->state))
		return selinux_cred_chain_uninitialized(cred) ? 0 : -EACCES;
#endif

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;
	isec = inode_security_rcu(inode, rcu);
	if (IS_ERR(isec))
		return PTR_ERR(isec);

#ifdef CONFIG_SECURITY_SELINUX_NS
	view = selinux_mnt_label_view(mnt);
	if (!view)
		return -EOPNOTSUPP;
	rc = selinux_inode_label_snapshot_get(isec, &snapshot);
	if (rc)
		return rcu && rc == -ESTALE ? -ECHILD : rc;
	rc = cred_label_has_perm(cred, snapshot.sid, snapshot.label,
				 view, snapshot.sclass, FILE__READ, &ad);
	selinux_inode_label_snapshot_put(&snapshot);
	return rc;
#else
	return cred_tsid_has_perm(cred, isec->sid, isec->sclass,
				  FILE__READ, &ad);
#endif
}

#ifndef CONFIG_SECURITY_SELINUX_NS
static noinline int audit_inode_permission(struct inode *inode,
					   u32 perms, u32 audited, u32 denied,
					   int result)
{
	struct common_audit_data ad;
	struct inode_security_struct *isec = selinux_inode(inode);

	ad.type = LSM_AUDIT_DATA_INODE;
	ad.u.inode = inode;

	return slow_avc_audit(current_selinux_state,
			    current_sid(), isec->sid, isec->sclass, perms,
			    audited, denied, result, &ad);
}

/**
 * task_avdcache_reset - Reset the task's AVD cache
 * @tsec: the task's security state
 *
 * Clear the task's AVD cache in @tsec and reset it to the current policy's
 * and task's info.
 */
static inline void task_avdcache_reset(struct task_security_struct *tsec)
{
	memset(&tsec->avdcache.dir, 0, sizeof(tsec->avdcache.dir));
	tsec->avdcache.sid = current_sid();
	tsec->avdcache.seqno = avc_policy_seqno(current_selinux_state);
	tsec->avdcache.dir_spot = TSEC_AVDC_DIR_SIZE - 1;
}

/**
 * task_avdcache_search - Search the task's AVD cache
 * @tsec: the task's security state
 * @isec: the inode to search for in the cache
 * @avdc: matching avd cache entry returned to the caller
 *
 * Search @tsec for a AVD cache entry that matches @isec and return it to the
 * caller via @avdc.  Returns 0 if a match is found, negative values otherwise.
 */
static inline int task_avdcache_search(struct task_security_struct *tsec,
				       struct inode_security_struct *isec,
				       struct avdc_entry **avdc)
{
	int orig, iter;

	if (!task_avdcache_eligible())
		return -ENOENT;

	/* focused on path walk optimization, only cache directories */
	if (isec->sclass != SECCLASS_DIR)
		return -ENOENT;

	if (unlikely(current_sid() != tsec->avdcache.sid ||
			tsec->avdcache.seqno !=
			avc_policy_seqno(current_selinux_state))) {
		task_avdcache_reset(tsec);
		return -ENOENT;
	}

	orig = iter = tsec->avdcache.dir_spot;
	do {
		if (tsec->avdcache.dir[iter].isid == isec->sid) {
			/* cache hit */
			tsec->avdcache.dir_spot = iter;
			*avdc = &tsec->avdcache.dir[iter];
			return 0;
		}
		iter = (iter - 1) & (TSEC_AVDC_DIR_SIZE - 1);
	} while (iter != orig);

	return -ENOENT;
}

/**
 * task_avdcache_update - Update the task's AVD cache
 * @tsec: the task's security state
 * @isec: the inode associated with the cache entry
 * @avd: the AVD to cache
 *
 * Update the AVD cache in @tsec with the @avd info associated
 * with @isec.
 */
static inline void task_avdcache_update(struct task_security_struct *tsec,
					struct inode_security_struct *isec,
					struct av_decision *avd)
{
	int spot;

	if (!task_avdcache_eligible())
		return;

	/* focused on path walk optimization, only cache directories */
	if (isec->sclass != SECCLASS_DIR)
		return;

	/* update cache */
	spot = (tsec->avdcache.dir_spot + 1) & (TSEC_AVDC_DIR_SIZE - 1);
	tsec->avdcache.dir_spot = spot;
	tsec->avdcache.dir[spot].isid = isec->sid;
	tsec->avdcache.dir[spot].avd = *avd;
	tsec->avdcache.permissive_neveraudit =
		(avd->flags == (AVD_FLAGS_PERMISSIVE|AVD_FLAGS_NEVERAUDIT));
}
#endif

/**
 * selinux_inode_permission - Check if the current task can access an inode
 * @mnt: mount selecting the inode's label view, or NULL for an intrinsic
 *       kernel operation
 * @inode: the inode that is being accessed
 * @requested: the accesses being requested
 *
 * Check if the current task is allowed to access @inode according to
 * @requested.  Returns 0 if allowed, negative values otherwise.
 */
static int selinux_inode_permission(const struct vfsmount *mnt,
				    struct inode *inode, int requested)
{
	int mask;
	u32 perms;
#ifndef CONFIG_SECURITY_SELINUX_NS
	u32 sid = current_sid();
	struct task_security_struct *tsec;
#endif
	struct inode_security_struct *isec;
	int rc;
#ifndef CONFIG_SECURITY_SELINUX_NS
	struct avdc_entry *avdc;
	struct av_decision avd, *avdp = &avd;
	int rc2;
	u32 audited, denied;
#else
	struct common_audit_data ad;
	const struct selinux_label_view *view = NULL;
	struct selinux_pathless_projection *projection;
	struct selinux_inode_label_snapshot snapshot;
#endif

	if (mnt) {
		const struct mount_security_struct *msec =
			selinux_mount_security(mnt);
		const struct selinux_label_view *mount_view;

		if (!msec)
			return -EACCES;
		mount_view = smp_load_acquire(&msec->view);
		if (!mount_view)
			return -EACCES;
		/*
		 * This initial integration only publishes identity views.  Never
		 * authorize a derived view as identity before per-policy label
		 * resolution is available.
		 */
		if (mount_view->flags & SELINUX_LABEL_VIEW_ORIGIN_UNRESOLVED)
			return -EOPNOTSUPP;
#ifdef CONFIG_SECURITY_SELINUX_NS
		view = mount_view;
#else
		if (!(mount_view->flags & SELINUX_LABEL_VIEW_IDENTITY))
			return -EOPNOTSUPP;
#endif
	}
	/*
	 * A NULL mount is only valid for an audited intrinsic-object operation;
	 * it must never be interpreted as an alias for a derived mount view.
	 */

	mask = requested & (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND);

	/* No policy permission to check after validating object provenance. */
	if (!mask)
		return 0;

#ifdef CONFIG_SECURITY_SELINUX_NS
	/* See inode_has_perm_view(): the root state has no inode policy yet. */
	{
		const struct cred_security_struct *crsec =
			selinux_cred(current_cred());

		if (!selinux_initialized(crsec->state))
			return selinux_cred_chain_uninitialized(current_cred()) ?
				0 : -EACCES;
	}
#endif

	isec = inode_security_rcu(inode, requested & MAY_NOT_BLOCK);
	if (IS_ERR(isec))
		return PTR_ERR(isec);
	perms = file_mask_to_av(inode->i_mode, mask);

#ifdef CONFIG_SECURITY_SELINUX_NS
	projection = selinux_inode_pathless_get(isec);
	if (projection) {
		if (requested & MAY_NOT_BLOCK) {
			rc = -ECHILD;
		} else {
			ad.type = LSM_AUDIT_DATA_INODE;
			ad.u.inode = inode;
			rc = cred_pathless_has_perm(current_cred(), projection,
						    perms, &ad);
		}
		selinux_pathless_projection_put(projection);
		return rc;
	}
#endif

#ifndef CONFIG_SECURITY_SELINUX_NS
	tsec = selinux_task(current);
	if (task_avdcache_permnoaudit(tsec, sid))
		return 0;
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (requested & MAY_NOT_BLOCK)
		return -ECHILD;
	ad.type = LSM_AUDIT_DATA_INODE;
	ad.u.inode = inode;
	rc = selinux_inode_label_snapshot_get(isec, &snapshot);
	if (rc)
		return rc;
	if (view) {
		rc = cred_label_has_perm_policycap(
			current_cred(), snapshot.sid, snapshot.label, view,
			snapshot.sclass, perms, 0, 0, snapshot.source, &ad);
	} else {
		rc = cred_tsid_has_perm(current_cred(), snapshot.sid,
					snapshot.sclass, perms, &ad);
	}
	selinux_inode_label_snapshot_put(&snapshot);
	return rc;
#else
	rc = task_avdcache_search(tsec, isec, &avdc);
	if (likely(!rc)) {
		/* Cache hit. */
		avdp = &avdc->avd;
		denied = perms & ~avdp->allowed;
		if (unlikely(denied) && enforcing_enabled(current_selinux_state) &&
		    !(avdp->flags & AVD_FLAGS_PERMISSIVE))
			rc = -EACCES;
	} else {
		/* Cache miss. */
		rc = cred_tsid_has_perm_noaudit(current_cred(), isec->sid,
						isec->sclass, perms, avdp);
		task_avdcache_update(tsec, isec, avdp);
	}

	audited = avc_audit_required(perms, avdp, rc,
				     (requested & MAY_ACCESS) ?
				     FILE__AUDIT_ACCESS : 0, &denied);
	if (likely(!audited))
		return rc;

	rc2 = audit_inode_permission(inode, perms, audited, denied, rc);
	if (rc2)
		return rc2;

	return rc;
#endif
}

static int selinux_inode_setattr(struct mnt_idmap *idmap,
				 const struct vfsmount *mnt,
				 struct dentry *dentry, struct iattr *iattr)
{
	const struct cred *cred = current_cred();
	struct inode *inode = d_backing_inode(dentry);
	unsigned int ia_valid = iattr->ia_valid;
	struct inode_security_struct *isec;
#ifndef CONFIG_SECURITY_SELINUX_NS
	struct cred_security_struct *crsec;
	struct selinux_state *state;
#endif
	struct common_audit_data ad;
	u32 av;
#ifndef CONFIG_SECURITY_SELINUX_NS
	u32 tsid, ssid, requested;
	u16 sclass;
#endif
	int rc;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct selinux_label_view *view;
	struct selinux_inode_label_snapshot snapshot;
#endif

	/* ATTR_FORCE is just used for ATTR_KILL_S[UG]ID. */
	if (ia_valid & ATTR_FORCE) {
		ia_valid &= ~(ATTR_KILL_SUID | ATTR_KILL_SGID | ATTR_MODE |
			      ATTR_FORCE);
		if (!ia_valid)
			return 0;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		const struct cred_security_struct *crsec = selinux_cred(cred);

		if (!selinux_initialized(crsec->state))
			return selinux_cred_chain_uninitialized(cred) ? 0 : -EACCES;
	}
#endif

	if (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID |
			ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_TIMES_SET))
		return dentry_has_perm_mnt(cred, mnt, dentry, FILE__SETATTR);

	/*
	 * The following is an inlined version of dentry_has_perm_mnt()->
	 * inode_has_perm()->cred_tsid_has_perm() in order to specialize
	 * the requested permissions based on the open_perms policycap
	 * value in each namespace.
	 */
	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;
	__inode_security_revalidate(inode, dentry, true);
	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	isec = selinux_inode(inode);
	av = FILE__WRITE;
#ifdef CONFIG_SECURITY_SELINUX_NS
	view = selinux_mnt_label_view(mnt);
	if (!view)
		return -EOPNOTSUPP;
	rc = selinux_inode_label_snapshot_get(isec, &snapshot);
	if (rc)
		return rc;
	rc = cred_label_has_perm_policycap(
		cred, snapshot.sid, snapshot.label, view, snapshot.sclass, av,
		inode->i_sb->s_magic != SOCKFS_MAGIC &&
			(ia_valid & ATTR_SIZE) && !(ia_valid & ATTR_FILE) ?
			FILE__OPEN : 0,
		POLICYDB_CAP_OPENPERM, snapshot.source, &ad);
	selinux_inode_label_snapshot_put(&snapshot);
	return rc;
#else
	tsid = isec->sid;
	sclass = isec->sclass;
	do {
		crsec = selinux_cred(cred);
		ssid = crsec->sid;
		state = crsec->state;
		requested = av;

		if (selinux_policycap_openperm(state) &&
		    inode->i_sb->s_magic != SOCKFS_MAGIC &&
		    (ia_valid & ATTR_SIZE) && !(ia_valid & ATTR_FILE))
			requested |= FILE__OPEN;

		rc = avc_has_perm(state, ssid, tsid, sclass, requested, &ad);
		if (rc)
			return rc;
		cred = crsec->parent_cred;
	} while (cred);

	return 0;
#endif
}

static int selinux_inode_getattr(const struct path *path)
{
#ifndef CONFIG_SECURITY_SELINUX_NS
	struct task_security_struct *tsec;

	tsec = selinux_task(current);

	if (task_avdcache_permnoaudit(tsec, current_sid()))
		return 0;
#endif

	return path_has_perm(current_cred(), path, FILE__GETATTR);
}

static bool has_cap_mac_admin(bool audit)
{
	const struct cred *cred = current_cred();
	unsigned int opts = audit ? CAP_OPT_NONE : CAP_OPT_NOAUDIT;

	if (cap_capable(cred, &init_user_ns, CAP_MAC_ADMIN, opts))
		return false;
	if (cred_has_capability(cred, CAP_MAC_ADMIN, opts, true))
		return false;
	return true;
}

/**
 * selinux_inode_xattr_skipcap - Skip the xattr capability checks?
 * @name: name of the xattr
 *
 * Returns 1 to indicate that SELinux "owns" the access control rights to xattrs
 * named @name; the LSM layer should avoid enforcing any traditional
 * capability based access controls on this xattr.  Returns 0 to indicate that
 * SELinux does not "own" the access control rights to xattrs named @name and is
 * deferring to the LSM layer for further access controls, including capability
 * based controls.
 */
static int selinux_inode_xattr_skipcap(const char *name)
{
	/* require capability check if not a selinux xattr */
	return !strcmp(name, XATTR_NAME_SELINUX);
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static void selinux_audit_setxattr_invalid_context(const void *value,
						   size_t size)
{
	struct audit_buffer *ab;
	size_t audit_size = size;

	if (value && audit_size && ((const char *)value)[audit_size - 1] == '\0')
		audit_size--;
	ab = audit_log_start(audit_context(), GFP_ATOMIC, AUDIT_SELINUX_ERR);
	if (!ab)
		return;
	audit_log_format(ab, "op=setxattr invalid_context=");
	if (value)
		audit_log_n_untrustedstring(ab, value, audit_size);
	else
		audit_log_format(ab, "(null)");
	(void)audit_log_end_status(ab);
}

static struct selinux_inode_relabel_marker *
selinux_inode_relabel_marker_lookup(struct inode *inode)
{
	return rhashtable_lookup_fast(&selinux_inode_relabel_markers, &inode,
				      selinux_inode_relabel_marker_params);
}

static bool selinux_inode_relabel_in_progress(struct inode *inode)
{
	bool in_progress;

	rcu_read_lock();
	in_progress = selinux_inode_relabel_marker_lookup(inode) != NULL;
	rcu_read_unlock();
	return in_progress;
}

static int selinux_inode_setxattr_plan_mark(
	struct selinux_inode_setxattr_plan *plan)
{
	struct selinux_inode_relabel_marker *marker;
	s64 cookie, observed;
	int rc;

	marker = kzalloc_obj(*marker, GFP_KERNEL_ACCOUNT);
	if (!marker)
		return -ENOMEM;
	for (;;) {
		observed = atomic64_read(&selinux_inode_relabel_cookie);
		if (unlikely(observed < 0 || observed == S64_MAX)) {
			kfree(marker);
			return -EOVERFLOW;
		}
		cookie = observed + 1;
		if (atomic64_cmpxchg(&selinux_inode_relabel_cookie,
				     observed, cookie) == observed)
			break;
	}
	marker->inode = plan->inode;
	marker->owner_task = plan->owner_task;
	marker->owner_tsec = plan->owner_tsec;
	marker->view = plan->view;
	marker->anchor_state = plan->anchor_state;
	marker->anchor_domain = plan->anchor_domain;
	marker->cookie = cookie;
	rc = rhashtable_insert_fast(&selinux_inode_relabel_markers,
				    &marker->node,
				    selinux_inode_relabel_marker_params);
	if (rc) {
		kfree(marker);
		return rc == -EEXIST ? -EBUSY : rc;
	}
	plan->marker = marker;
	plan->relabel_cookie = cookie;
	return 0;
}

static void selinux_inode_setxattr_plan_unmark(
	struct selinux_inode_setxattr_plan *plan)
{
	struct selinux_inode_relabel_marker *marker = plan->marker;

	if (!marker)
		return;
	if (WARN_ON_ONCE(rhashtable_remove_fast(
			&selinux_inode_relabel_markers, &marker->node,
			selinux_inode_relabel_marker_params)))
		return;
	plan->marker = NULL;
	kfree_rcu(marker, rcu);
}

static int selinux_inode_setxattr_plan_cookie_valid(
	const struct selinux_inode_setxattr_plan *plan,
	const struct security_inode_setxattr_plan *generic);

static int selinux_inode_setxattr_plan_identity_valid(
	const struct selinux_inode_setxattr_plan *plan)
{
	struct superblock_security_struct *sbsec;
	int rc;

	rc = selinux_inode_setxattr_plan_cookie_valid(plan, plan->generic);
	if (rc)
		return rc;

	sbsec = selinux_superblock(plan->inode->i_sb);
	mutex_lock(&sbsec->lock);
	if (sbsec->anchor_state != plan->anchor_state ||
	    sbsec->anchor_domain != plan->anchor_domain)
		rc = -ESTALE;
	else
		rc = 0;
	mutex_unlock(&sbsec->lock);
	if (rc)
		return rc;
	if (!selinux_policy_chain_snapshot_valid(&plan->chain))
		return -ESTALE;
	return selinux_policy_chain_anchor_valid(
		&plan->chain, plan->anchor_state, plan->anchor_domain);
}

static int selinux_inode_setxattr_plan_cookie_valid(
	const struct selinux_inode_setxattr_plan *plan,
	const struct security_inode_setxattr_plan *generic)
{
	struct selinux_inode_relabel_marker *marker;
	int rc = 0;

	if (!plan || !generic || plan->generic != generic || !plan->marker ||
	    plan->owner_task != current ||
	    plan->owner_tsec != selinux_task(current) ||
	    plan->actor != current_cred() || !plan->inode || !plan->view ||
	    !plan->anchor_state || !plan->anchor_domain ||
	    !plan->anchor_handle || !plan->anchor_label ||
	    global_sid_handle_sid(plan->anchor_handle) != plan->anchor_sid ||
	    plan->anchor_state->label_domain != plan->anchor_domain ||
	    plan->view->origin_domain != plan->anchor_domain ||
	    !plan->relabel_cookie)
		return -EPROTO;
	rcu_read_lock();
	marker = selinux_inode_relabel_marker_lookup(plan->inode);
	if (marker != plan->marker || marker->inode != plan->inode ||
	    marker->owner_task != plan->owner_task ||
	    marker->owner_tsec != plan->owner_tsec ||
	    marker->view != plan->view || marker->cookie != plan->relabel_cookie ||
	    marker->anchor_state != plan->anchor_state ||
	    marker->anchor_domain != plan->anchor_domain)
		rc = -EPROTO;
	rcu_read_unlock();
	return rc;
}

static int selinux_inode_setxattr_plan_old_tuple_valid(
	const struct selinux_inode_setxattr_plan *plan,
	struct inode_security_struct *isec)
{
	struct selinux_label_ref *label;
	int rc = 0;

	if (!isec || isec->inode != plan->inode)
		return -EPROTO;
	spin_lock(&isec->lock);
	label = rcu_dereference_protected(
		isec->label_ref, lockdep_is_held(&isec->lock));
	if (rcu_access_pointer(isec->pathless))
		rc = -EBUSY;
	else if (isec->initialized != LABEL_INITIALIZED ||
		 isec->sid_handle != plan->old_handle ||
		 global_sid_handle_sid(isec->sid_handle) != plan->old_sid ||
		 label != plan->old_label || isec->sid != plan->old_sid ||
		 isec->sclass != plan->sclass ||
		 isec->label_source != plan->old_source)
		rc = -ESTALE;
	spin_unlock(&isec->lock);
	return rc;
}

static int selinux_inode_setxattr_plan_new_tuple_valid(
	const struct selinux_inode_setxattr_plan *plan)
{
	struct inode_security_struct *isec = selinux_inode(plan->inode);
	struct selinux_label_ref *label;
	int rc = 0;

	spin_lock(&isec->lock);
	label = rcu_dereference_protected(
		isec->label_ref, lockdep_is_held(&isec->lock));
	if (isec->initialized != LABEL_INITIALIZED ||
	    rcu_access_pointer(isec->pathless) ||
	    isec->sid_handle != plan->anchor_handle ||
	    global_sid_handle_sid(isec->sid_handle) != plan->anchor_sid ||
	    label != plan->anchor_label || isec->sid != plan->anchor_sid ||
	    isec->sclass != plan->sclass ||
	    isec->label_source != SELINUX_LABEL_SOURCE_XATTR)
		rc = -ESTALE;
	spin_unlock(&isec->lock);
	return rc;
}

static void selinux_inode_setxattr_plan_release(
	struct selinux_inode_setxattr_plan *plan)
{
	if (!plan)
		return;
	selinux_inode_setxattr_plan_unmark(plan);
	if (plan->actor)
		put_cred(plan->actor);
	selinux_label_view_put(plan->view);
	selinux_label_ref_put(plan->old_label);
	selinux_label_ref_put(plan->new_label);
	selinux_label_ref_put(plan->sb_label);
	selinux_label_ref_put(plan->anchor_label);
	global_sid_handle_put(plan->old_handle);
	global_sid_handle_put(plan->new_handle);
	global_sid_handle_put(plan->anchor_handle);
	selinux_label_domain_put(plan->anchor_domain);
	put_selinux_state(plan->anchor_state);
	kfree(plan->xattr_value);
	memset(plan, 0, sizeof(*plan));
}

static int selinux_inode_setxattr_chain_valid(
	const struct selinux_inode_setxattr_plan *plan)
{
	const struct selinux_label_domain *parent = NULL;
	u16 i;

	if (!plan->chain.count ||
	    plan->chain.count !=
		selinux_cred(plan->chain.cred[0])->state->label_domain->depth + 1)
		return -EXDEV;
	for (i = plan->chain.count; i-- > 0;) {
		const struct cred_security_struct *crsec =
			selinux_cred(plan->chain.cred[i]);
		const struct selinux_label_domain *domain =
			crsec->state->label_domain;
		u16 depth = plan->chain.count - i - 1;

		if (!domain || domain->depth != depth ||
		    crsec->state->depth != depth || domain->parent != parent)
			return -EXDEV;
		if (i + 1 < plan->chain.count &&
		    (crsec->parent_cred != plan->chain.cred[i + 1] ||
		     crsec->state->parent !=
			selinux_cred(plan->chain.cred[i + 1])->state))
			return -EXDEV;
		parent = domain;
	}
	return 0;
}

static void selinux_inode_setxattr_retry_reset(
	struct selinux_inode_setxattr_plan *plan)
{
	global_sid_handle_put(plan->new_handle);
	plan->new_handle = NULL;
	global_sid_handle_put(plan->anchor_handle);
	plan->anchor_handle = NULL;
	selinux_label_ref_put(plan->new_label);
	plan->new_label = NULL;
	selinux_label_ref_put(plan->anchor_label);
	plan->anchor_label = NULL;
	kfree(plan->xattr_value);
	plan->xattr_value = NULL;
	plan->xattr_value_len = 0;
}

static int selinux_inode_setxattr_plan_authorize(
	struct selinux_inode_setxattr_plan *plan, struct dentry *dentry,
	const void *value, size_t size, u32 old_sid, u32 sb_sid)
{
	struct selinux_avc_level *levels __free(kfree) = NULL;
	struct selinux_policy_snapshot *snapshots __free(kfree) = NULL;
	struct selinux_validatetrans_level *validatetrans __free(kfree) = NULL;
	struct selinux_policy_snapshot *validatetrans_snapshots __free(kfree) =
		NULL;
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
	struct common_audit_data ad = {};
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	struct task_security_struct *tsec = selinux_task(current);
#endif
	const char *context;
	u32 context_len;
	u16 allocated_count = 0, allocated_validatetrans = 0;
	unsigned int retry;
	int rc = -ESTALE;

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		const struct cred_security_struct *leaf;
		u16 check_count, count = 0, validatetrans_count = 0;
		u16 workspace_count, i;
		u32 new_sid;
		int guard_result = 0;

		selinux_inode_setxattr_retry_reset(plan);
		plan->forced_context = false;
		rc = selinux_policy_chain_snapshot_read(plan->actor, &plan->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = selinux_inode_setxattr_chain_valid(plan);
		if (rc)
			return rc;
		rc = selinux_policy_chain_anchor_valid(
			&plan->chain, plan->anchor_state, plan->anchor_domain);
		if (rc)
			return rc;
		if (check_mul_overflow(plan->chain.count,
				       (u16)SELINUX_SETXATTR_AVC_CHECKS,
				       &check_count) ||
		    check_count > SELINUX_AVC_TRANSACTION_MAX_CHECKS ||
		    check_add_overflow(check_count, plan->chain.count,
				       &workspace_count))
			return -E2BIG;
		if (!levels) {
			levels = kcalloc(check_count, sizeof(*levels), GFP_KERNEL);
			snapshots = kcalloc(check_count, sizeof(*snapshots),
					    GFP_KERNEL);
			validatetrans = kcalloc(plan->chain.count,
						 sizeof(*validatetrans), GFP_KERNEL);
			validatetrans_snapshots = kcalloc(
				plan->chain.count, sizeof(*validatetrans_snapshots),
				GFP_KERNEL);
			workspace = selinux_avc_transaction_workspace_alloc(
				workspace_count, GFP_KERNEL);
			if (!levels || !snapshots || !validatetrans ||
			    !validatetrans_snapshots || !workspace)
				return -ENOMEM;
			allocated_count = check_count;
			allocated_validatetrans = plan->chain.count;
		} else if (allocated_count != check_count ||
			   allocated_validatetrans != plan->chain.count) {
			return -EXDEV;
		}
		leaf = selinux_cred(plan->chain.cred[0]);

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
		if (!selinux_initialized(leaf->state) &&
		    tsec->create_plan_kunit_force) {
			plan->new_handle = selinux_kunit_global_context_to_handle(
				leaf->state, value, &new_sid);
			rc = IS_ERR(plan->new_handle) ?
				PTR_ERR(plan->new_handle) : 0;
			if (IS_ERR(plan->new_handle))
				plan->new_handle = NULL;
		} else
#endif
		{
			plan->new_handle = security_context_to_global_handle(
				leaf->state, value, size, &new_sid, GFP_KERNEL);
			rc = IS_ERR(plan->new_handle) ?
				PTR_ERR(plan->new_handle) : 0;
			if (IS_ERR(plan->new_handle))
				plan->new_handle = NULL;
			if (rc && !selinux_policy_chain_snapshot_valid(&plan->chain))
				continue;
			if (rc == -EINVAL) {
				plan->forced_context = true;
				if (cap_capable(plan->actor, &init_user_ns,
						CAP_MAC_ADMIN, CAP_OPT_NOAUDIT))
					guard_result = -EINVAL;
				for (i = 0; i < plan->chain.count; i++) {
					const struct cred_security_struct *crsec =
						selinux_cred(plan->chain.cred[i]);

					levels[i] = (struct selinux_avc_level) {
						.state = crsec->state,
						.ssid = crsec->sid,
						.tsid = crsec->sid,
						.tclass = SECCLASS_CAPABILITY2,
						.requested =
							CAP_TO_MASK(CAP_MAC_ADMIN),
						.denial_errno = -EINVAL,
					};
					snapshots[i] = plan->chain.policy[i];
				}
				if (!selinux_policy_chain_snapshot_valid(&plan->chain))
					continue;
				rc = selinux_avc_transaction_has_perm_noaudit(
					levels, snapshots, plan->chain.count);
				if (rc == -ESTALE)
					continue;
				if (rc && rc != -EINVAL)
					return rc;
				if (guard_result || rc == -EINVAL) {
					rc = selinux_avc_transaction_has_perm_composite_guarded_workspace(
						levels, snapshots, plan->chain.count,
						NULL, NULL, 0, guard_result, &ad,
						workspace);
					if (rc == -ESTALE)
						continue;
					if (rc == -EINVAL)
						selinux_audit_setxattr_invalid_context(
							value, size);
					return rc;
				}
				plan->new_handle =
					security_context_to_sid_force_handle(
						leaf->state, value, size, &new_sid);
				rc = IS_ERR(plan->new_handle) ?
					PTR_ERR(plan->new_handle) : 0;
				if (IS_ERR(plan->new_handle))
					plan->new_handle = NULL;
				if (rc && !selinux_policy_chain_snapshot_valid(
						  &plan->chain))
					continue;
				count = 0;
			}
		}
		if (rc && !selinux_policy_chain_snapshot_valid(&plan->chain))
			continue;
		if (rc) {
			if (rc == -EAGAIN || rc == -ESTALE)
				continue;
			return rc;
		}
		plan->new_label =
			global_sid_handle_label_get(plan->new_handle);
		if (!plan->new_label)
			continue;
		if (!selinux_policy_snapshot_valid(leaf->state,
						   &plan->chain.policy[0]))
			continue;

		rc = selinux_label_view_resolve_chain(
			plan->view, plan->old_label, old_sid,
			&plan->old_resolution);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = selinux_label_view_resolve_chain(
			plan->view, plan->new_label, new_sid,
			&plan->new_resolution);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = selinux_label_view_resolve_chain(
			plan->view, plan->sb_label, sb_sid,
			&plan->sb_resolution);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		if (plan->anchor_domain->depth >
			    plan->new_resolution.max_depth ||
		    !plan->new_resolution.sid[plan->anchor_domain->depth])
			return -EXDEV;
		plan->anchor_sid =
			plan->new_resolution.sid[plan->anchor_domain->depth];
		plan->anchor_handle = global_sid_handle_get(plan->anchor_sid);
		if (IS_ERR(plan->anchor_handle)) {
			rc = PTR_ERR(plan->anchor_handle);
			plan->anchor_handle = NULL;
			if (rc == -EAGAIN || rc == -ESTALE)
				continue;
			return rc;
		}
		plan->anchor_label =
			global_sid_handle_label_get(plan->anchor_handle);
		if (!plan->anchor_label)
			continue;
		if (plan->anchor_label->domain != plan->anchor_domain)
			return -EXDEV;
		plan->provenance[1] = (struct selinux_avc_provenance) {
			.label = plan->anchor_label,
			.view = plan->view,
			.source = SELINUX_LABEL_SOURCE_SECURITY_CONTEXT,
		};

		for (i = 0; i < plan->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(plan->chain.cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&plan->chain.policy[i];
			u16 depth = crsec->state->label_domain->depth;

			if (plan->old_resolution.domain_id[depth] !=
				    crsec->state->label_domain->id ||
			    plan->new_resolution.domain_id[depth] !=
				    crsec->state->label_domain->id ||
			    plan->sb_resolution.domain_id[depth] !=
				    crsec->state->label_domain->id ||
			    !plan->old_resolution.sid[depth] ||
			    !plan->new_resolution.sid[depth] ||
			    !plan->sb_resolution.sid[depth])
				return -EOPNOTSUPP;
			levels[count] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = plan->old_resolution.sid[depth],
				.tclass = plan->sclass,
				.requested = FILE__RELABELFROM,
				.provenance = &plan->provenance[0],
			};
			snapshots[count++] = *snapshot;
			levels[count] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = plan->new_resolution.sid[depth],
				.tclass = plan->sclass,
				.requested = FILE__RELABELTO,
				.provenance = &plan->provenance[1],
			};
			snapshots[count++] = *snapshot;
			levels[count] = (struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = plan->new_resolution.sid[depth],
				.tsid = plan->sb_resolution.sid[depth],
				.tclass = SECCLASS_FILESYSTEM,
				.requested = FILESYSTEM__ASSOCIATE,
				.provenance = &plan->provenance[2],
			};
			snapshots[count++] = *snapshot;
			if (plan->forced_context) {
				levels[count] = (struct selinux_avc_level) {
					.state = crsec->state,
					.ssid = crsec->sid,
					.tsid = crsec->sid,
					.tclass = SECCLASS_CAPABILITY2,
					.requested = CAP_TO_MASK(CAP_MAC_ADMIN),
					.denial_errno = -EINVAL,
				};
				snapshots[count++] = *snapshot;
			}
			validatetrans[validatetrans_count] =
				(struct selinux_validatetrans_level) {
					.state = crsec->state,
					.oldsid = plan->old_resolution.sid[depth],
					.newsid = plan->new_resolution.sid[depth],
					.tasksid = crsec->sid,
					.tclass = plan->sclass,
					.provenance = &plan->provenance[1],
				};
			validatetrans_snapshots[validatetrans_count++] = *snapshot;
		}
		if (!selinux_policy_chain_snapshot_valid(&plan->chain))
			continue;

		rcu_read_lock();
		rc = security_sid_to_context_force(
			plan->anchor_state, plan->anchor_sid, &context, &context_len);
		if (!rc) {
			plan->xattr_value = kmemdup(
				context, context_len, GFP_ATOMIC);
			if (!plan->xattr_value)
				rc = -ENOMEM;
		}
		rcu_read_unlock();
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		plan->xattr_value_len = context_len;
		if (!selinux_policy_chain_snapshot_valid(&plan->chain))
			continue;
		rc = selinux_avc_transaction_has_perm_composite_guarded_workspace(
			levels, snapshots, count, validatetrans,
			validatetrans_snapshots, validatetrans_count,
			guard_result, &ad, workspace);
		if (rc == -ESTALE)
			continue;
		if (rc == -EINVAL && plan->forced_context)
			selinux_audit_setxattr_invalid_context(value, size);
		return rc;
	}
	selinux_inode_setxattr_retry_reset(plan);
	return -ESTALE;
}

static int selinux_inode_setxattr_plan_prepare(
	struct security_inode_setxattr_plan *generic, struct mnt_idmap *idmap,
	const struct vfsmount *mnt, struct dentry *dentry, const char *name,
	const void **value, size_t *size, int flags)
{
	struct selinux_inode_setxattr_plan *plan =
		selinux_inode_setxattr_plan_security(generic);
	struct task_security_struct *tsec = selinux_task(current);
	struct superblock_security_struct *sbsec;
	struct inode_security_struct *isec;
	const void *requested_value = *value;
	size_t requested_size = *size;
	u32 old_sid, sb_sid;
	u8 old_source;
	int rc;

	if (strcmp(name, XATTR_NAME_SELINUX))
		return 0;
	if (!selinux_initialized(current_selinux_state)
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	    && !tsec->create_plan_kunit_force
#endif
	)
		return selinux_cred_chain_uninitialized(current_cred()) ?
			0 : -EACCES;
	if (!mnt || !selinux_mnt_label_view(mnt))
		return -EOPNOTSUPP;
	memset(plan, 0, sizeof(*plan));
	plan->generic = generic;
	plan->previous = tsec->setxattr_plan;
	plan->actor = get_current_cred();
	plan->owner_task = current;
	plan->owner_tsec = tsec;
	plan->view = selinux_label_view_get(selinux_mnt_label_view(mnt));
	plan->inode = d_backing_inode(dentry);
	plan->flags = flags;
	if (!plan->inode || !plan->view) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	if (!selinux_is_sblabel_mnt(plan->inode->i_sb)) {
		rc = -EOPNOTSUPP;
		goto out;
	}
	if (!inode_owner_or_capable(idmap, plan->inode)) {
		rc = -EPERM;
		goto out;
	}
	sbsec = selinux_superblock(plan->inode->i_sb);
	mutex_lock(&sbsec->lock);
	if (!sbsec->anchor_state || !sbsec->anchor_domain ||
	    sbsec->anchor_state->label_domain != sbsec->anchor_domain) {
		mutex_unlock(&sbsec->lock);
		rc = -EXDEV;
		goto out;
	}
	plan->anchor_state = get_selinux_state(sbsec->anchor_state);
	plan->anchor_domain =
		selinux_label_domain_get(sbsec->anchor_domain);
	sb_sid = sbsec->sid;
	mutex_unlock(&sbsec->lock);
	if (!plan->anchor_state || !plan->anchor_domain ||
	    plan->view->origin_domain != plan->anchor_domain) {
		rc = -EXDEV;
		goto out;
	}
	rc = selinux_inode_setxattr_plan_mark(plan);
	if (rc)
		goto out;
	isec = backing_inode_security(dentry);
	spin_lock(&isec->lock);
	if (isec->initialized != LABEL_INITIALIZED ||
	    rcu_access_pointer(isec->pathless)) {
		spin_unlock(&isec->lock);
		rc = -EOPNOTSUPP;
		goto out;
	}
	plan->old_label = selinux_label_ref_get(
		rcu_dereference_protected(isec->label_ref,
					  lockdep_is_held(&isec->lock)));
	plan->old_handle = global_sid_handle_dup(isec->sid_handle);
	old_sid = isec->sid;
	plan->sclass = isec->sclass;
	old_source = isec->label_source;
	plan->old_sid = old_sid;
	plan->old_source = old_source;
	spin_unlock(&isec->lock);
	if (!plan->old_label || IS_ERR(plan->old_handle)) {
		rc = IS_ERR(plan->old_handle) ? PTR_ERR(plan->old_handle) : -EIO;
		if (IS_ERR(plan->old_handle))
			plan->old_handle = NULL;
		goto out;
	}

	plan->sb_label = global_sid_to_label_ref(sb_sid);
	if (IS_ERR(plan->sb_label)) {
		rc = PTR_ERR(plan->sb_label);
		plan->sb_label = NULL;
		goto out;
	}
	plan->provenance[0] = (struct selinux_avc_provenance) {
		.label = plan->old_label,
		.view = plan->view,
		.source = old_source,
	};
	plan->provenance[2] = (struct selinux_avc_provenance) {
		.label = plan->sb_label,
		.view = plan->view,
		.source = SELINUX_LABEL_SOURCE_FILESYSTEM,
	};
	rc = selinux_inode_setxattr_plan_authorize(
		plan, dentry, requested_value, requested_size, old_sid, sb_sid);
	if (rc)
		goto out;
	rc = selinux_inode_setxattr_plan_identity_valid(plan);
	if (rc)
		goto out;
	rc = selinux_inode_setxattr_plan_old_tuple_valid(plan, isec);
	if (rc)
		goto out;
	if (tsec->setxattr_plan != plan->previous) {
		rc = -EPROTO;
		goto out;
	}
	*value = plan->xattr_value;
	*size = plan->xattr_value_len;
	tsec->setxattr_plan = plan;
	return 0;

out:
	selinux_inode_setxattr_plan_release(plan);
	return rc;
}

static int selinux_inode_setxattr_plan_finish(
	struct security_inode_setxattr_plan *generic, int result)
{
	struct selinux_inode_setxattr_plan *plan =
		selinux_inode_setxattr_plan_security(generic);
	struct task_security_struct *tsec = selinux_task(current);
	struct selinux_inode_setxattr_plan *cursor, *next, *previous;
	int tuple_rc;

	if (!plan->generic)
		return plan->poisoned ? -EPROTO : 0;
	/* Reject a foreign/corrupted cookie before touching either task stack. */
	if (selinux_inode_setxattr_plan_cookie_valid(plan, generic))
		return -EPROTO;
	if (tsec->setxattr_plan != plan) {
		cursor = tsec->setxattr_plan;
		while (cursor && cursor != plan) {
			next = cursor->previous;
			selinux_inode_setxattr_plan_release(cursor);
			cursor->poisoned = true;
			cursor = next;
		}
		if (cursor == plan) {
			previous = plan->previous;
			selinux_inode_setxattr_plan_release(plan);
			plan->poisoned = true;
			tsec->setxattr_plan = previous;
		} else {
			tsec->setxattr_plan = NULL;
			selinux_inode_setxattr_plan_release(plan);
			plan->poisoned = true;
		}
		return -EPROTO;
	}
	previous = plan->previous;
	/* Authorization is linearized before the xattr is applied. */
	if (!result && plan->commit_rc)
		result = plan->commit_rc;
	else if (!result && !plan->committed) {
		selinux_inode_security_invalidate(plan->inode);
		result = -EPROTO;
	} else if (!result && !plan->deferred_revalidation) {
		tuple_rc = selinux_inode_setxattr_plan_new_tuple_valid(plan);
		if (tuple_rc) {
			selinux_inode_security_invalidate(plan->inode);
			result = tuple_rc;
		}
	}
	tsec->setxattr_plan = previous;
	selinux_inode_setxattr_plan_release(plan);
	return result;
}

static int selinux_inode_setxattr_plan_commit(
	struct selinux_inode_setxattr_plan *plan,
	struct inode_security_struct *isec, bool invalidate_on_error)
{
	struct selinux_global_sid_handle *handle = NULL;
	struct selinux_label_ref *label = NULL;
	int rc;

	rc = selinux_inode_setxattr_plan_cookie_valid(plan, plan->generic);
	if (rc)
		goto out_unlocked;
	if (plan->committed)
		return -EALREADY;
	rc = selinux_inode_setxattr_plan_old_tuple_valid(plan, isec);
	if (rc)
		goto out_unlocked;

	/*
	 * The permission decision and exact anchor handle were sealed before the
	 * filesystem effect.  A policy reload after that point must not turn a
	 * successful persistent xattr write into a false syscall failure.
	 */
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	if (plan->rebind_fail_kunit) {
		rc = -EIO;
		goto out;
	}
#endif
	handle = global_sid_handle_dup(plan->anchor_handle);
	if (IS_ERR(handle)) {
		rc = PTR_ERR(handle);
		handle = NULL;
		goto out;
	}
	if (global_sid_handle_sid(handle) != plan->anchor_sid ||
	    handle != plan->anchor_handle) {
		rc = -ESTALE;
		goto out;
	}
	label = global_sid_handle_label_get(handle);
	if (!label) {
		rc = -ESTALE;
		goto out;
	}
	if (label->domain != plan->anchor_domain || label != plan->anchor_label) {
		rc = -EXDEV;
		goto out;
	}
	rc = selinux_inode_security_take_sid_handle(
		isec, handle, &plan->sclass, SELINUX_LABEL_SOURCE_XATTR,
		LABEL_INITIALIZED);
	handle = NULL;
	if (!rc)
		plan->committed = true;
out:
	if (rc && invalidate_on_error) {
		spin_lock(&isec->lock);
		if (!rcu_access_pointer(isec->pathless))
			isec->initialized = LABEL_INVALID;
		spin_unlock(&isec->lock);
		/* The xattr was committed; revalidation must consume it later. */
		plan->committed = true;
		plan->deferred_revalidation = true;
		plan->commit_rc = 0;
		rc = 0;
	}
out_unlocked:
	global_sid_handle_put(handle);
	selinux_label_ref_put(label);
	return rc;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
void selinux_kunit_inode_setxattr_plan_rebind_fail(void)
{
	struct selinux_inode_setxattr_plan *plan =
		selinux_task(current)->setxattr_plan;

	if (plan)
		plan->rebind_fail_kunit = true;
}
#endif
#endif

static int selinux_inode_setxattr(struct mnt_idmap *idmap,
				  const struct vfsmount *mnt,
				  struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags)
{
	const struct cred *cred = current_cred();
	struct inode *inode = d_backing_inode(dentry);
	struct inode_security_struct *isec;
	struct superblock_security_struct *sbsec;
	struct common_audit_data ad = {};
	u32 newsid;
	int rc = 0;

	/* if not a selinux xattr, only check the ordinary setattr perm */
	if (strcmp(name, XATTR_NAME_SELINUX))
		return dentry_has_perm_mnt(current_cred(), mnt, dentry,
					    FILE__SETATTR);

	if (!selinux_initialized(current_selinux_state)
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	    && !selinux_task(current)->create_plan_kunit_force
#endif
	) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		return selinux_cred_chain_uninitialized(cred) ?
			(inode_owner_or_capable(idmap, inode) ? 0 : -EPERM) :
			-EACCES;
#else
		return inode_owner_or_capable(idmap, inode) ? 0 : -EPERM;
#endif
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		struct selinux_inode_setxattr_plan *plan =
			selinux_task(current)->setxattr_plan;
		int plan_rc;

		if (!plan || plan->inode != inode || value != plan->xattr_value ||
		    size != plan->xattr_value_len || flags != plan->flags)
			return -EOPNOTSUPP;
		plan_rc = selinux_inode_setxattr_plan_identity_valid(plan);
		if (plan_rc)
			return plan_rc;
		if (plan->view != selinux_mnt_label_view(mnt))
			return -EXDEV;
		if (!selinux_policy_chain_snapshot_valid(&plan->chain))
			return -ESTALE;
		return selinux_inode_setxattr_plan_old_tuple_valid(
			plan, selinux_inode(inode));
	}
#endif

	sbsec = selinux_superblock(inode->i_sb);
	if (!selinux_is_sblabel_mnt(inode->i_sb))
		return -EOPNOTSUPP;

	if (!inode_owner_or_capable(idmap, inode))
		return -EPERM;

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;

	isec = backing_inode_security(dentry);
#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		struct selinux_pathless_projection *projection =
			selinux_inode_pathless_get(isec);

		if (projection) {
			selinux_pathless_projection_put(projection);
			return -EOPNOTSUPP;
		}
	}
	rc = inode_has_perm_view(cred, inode, selinux_mnt_label_view(mnt),
				 FILE__RELABELFROM, &ad);
#else
	rc = cred_tsid_has_perm(cred, isec->sid, isec->sclass, FILE__RELABELFROM,
				&ad);
#endif
	if (rc)
		return rc;

	rc = security_context_to_sid(current_selinux_state, value, size, &newsid,
				     GFP_KERNEL);
	if (rc == -EINVAL) {
		if (!has_cap_mac_admin(true)) {
			struct audit_buffer *ab;
			size_t audit_size;

			/* We strip a nul only if it is at the end, otherwise the
			 * context contains a nul and we should audit that */
			if (value) {
				const char *str = value;

				if (str[size - 1] == '\0')
					audit_size = size - 1;
				else
					audit_size = size;
			} else {
				audit_size = 0;
			}
			ab = audit_log_start(audit_context(),
					     GFP_ATOMIC, AUDIT_SELINUX_ERR);
			if (!ab)
				return rc;
			audit_log_format(ab, "op=setxattr invalid_context=");
			audit_log_n_untrustedstring(ab, value, audit_size);
			(void)audit_log_end_status(ab);

			return rc;
		}
		rc = security_context_to_sid_force(current_selinux_state, value,
						   size, &newsid);
	}
	if (rc)
		return rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = sid_has_perm_mnt(cred, mnt, newsid, isec->sclass,
			       FILE__RELABELTO, &ad);
#else
	rc = cred_tsid_has_perm(cred, newsid, isec->sclass, FILE__RELABELTO, &ad);
#endif
	if (rc)
		return rc;

	rc = security_validate_transition(current_selinux_state, isec->sid, newsid,
					current_sid(), isec->sclass);
	if (rc)
		return rc;

	return cred_obj_has_perm(cred, newsid, sbsec->sid,
				 SECCLASS_FILESYSTEM,
				 FILESYSTEM__ASSOCIATE, &ad);
}

static int selinux_inode_set_acl(struct mnt_idmap *idmap,
				 const struct vfsmount *mnt,
				 struct dentry *dentry, const char *acl_name,
				 struct posix_acl *kacl)
{
	return dentry_has_perm_mnt(current_cred(), mnt, dentry, FILE__SETATTR);
}

static int selinux_inode_get_acl(struct mnt_idmap *idmap,
				 const struct vfsmount *mnt,
				 struct dentry *dentry, const char *acl_name)
{
	return dentry_has_perm_mnt(current_cred(), mnt, dentry, FILE__GETATTR);
}

static int selinux_inode_remove_acl(struct mnt_idmap *idmap,
				    const struct vfsmount *mnt,
				    struct dentry *dentry, const char *acl_name)
{
	return dentry_has_perm_mnt(current_cred(), mnt, dentry, FILE__SETATTR);
}

static void selinux_inode_post_setxattr(const struct vfsmount *mnt,
					struct dentry *dentry, const char *name,
					const void *value, size_t size, int flags)
{
	struct inode *inode = d_backing_inode(dentry);
	struct inode_security_struct *isec;
	u32 newsid;
	int rc;

	if (strcmp(name, XATTR_NAME_SELINUX)) {
		/* Not an attribute we recognize, so nothing to do. */
		return;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		struct selinux_inode_setxattr_plan *plan =
			selinux_task(current)->setxattr_plan;
		struct inode_security_struct *inode_isec = selinux_inode(inode);
		int commit_rc;

		if (!plan || !mnt ||
		    plan->view != selinux_mnt_label_view(mnt) ||
		    plan->inode != inode || value != plan->xattr_value ||
		    size != plan->xattr_value_len || flags != plan->flags ||
		    plan->committed) {
			spin_lock(&inode_isec->lock);
			if (!rcu_access_pointer(inode_isec->pathless))
				inode_isec->initialized = LABEL_INVALID;
			spin_unlock(&inode_isec->lock);
			if (plan && plan->inode == inode && !plan->committed) {
				plan->committed = true;
				plan->deferred_revalidation = true;
			}
			return;
		}
		commit_rc = selinux_inode_setxattr_plan_commit(plan, inode_isec, true);
		if (commit_rc && !plan->commit_rc) {
			spin_lock(&inode_isec->lock);
			if (!rcu_access_pointer(inode_isec->pathless))
				inode_isec->initialized = LABEL_INVALID;
			spin_unlock(&inode_isec->lock);
			plan->committed = true;
			plan->commit_rc = commit_rc;
		}
		return;
	}
#endif

	if (!selinux_initialized(current_selinux_state)) {
		/* If we haven't even been initialized, then we can't validate
		 * against a policy, so leave the label as invalid. It may
		 * resolve to a valid label on the next revalidation try if
		 * we've since initialized.
		 */
		return;
	}

	rc = security_context_to_sid_force(current_selinux_state, value, size,
					   &newsid);
	if (rc) {
		pr_err("SELinux:  unable to map context to SID"
		       "for (%s, %llu), rc=%d\n",
		       inode->i_sb->s_id, inode->i_ino, -rc);
		return;
	}

	isec = backing_inode_security(dentry);
	rc = inode_security_set_sid_class(
		isec, newsid, inode_mode_to_security_class(inode->i_mode),
		SELINUX_LABEL_SOURCE_XATTR, LABEL_INITIALIZED);
	if (rc) {
		spin_lock(&isec->lock);
#ifdef CONFIG_SECURITY_SELINUX_NS
		/*
		 * A published pathless projection is immutable.  The setxattr
		 * pre-hook rejects relabeling such an inode, but preserve the
		 * sealed tuple if a filesystem invokes the post hook without the
		 * matching pre-hook or if a future caller races publication.
		 */
		if (!rcu_access_pointer(isec->pathless))
			isec->initialized = LABEL_INVALID;
#else
		isec->initialized = LABEL_INVALID;
#endif
		spin_unlock(&isec->lock);
		pr_err("SELinux: unable to retain canonical inode label for (%s, %llu), rc=%d\n",
		       inode->i_sb->s_id, inode->i_ino, -rc);
	}
}

static int selinux_inode_getxattr(const struct vfsmount *mnt,
				  struct dentry *dentry, const char *name)
{
	const struct cred *cred = current_cred();

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (d_inode(dentry)->i_sb->s_magic == SOCKFS_MAGIC) {
		struct sock *sk = READ_ONCE(SOCKET_I(d_inode(dentry))->sk);

		return sk ? sock_has_perm(sk, SOCKET__GETATTR) : -EACCES;
	}
#endif

	return dentry_has_perm_mnt(cred, mnt, dentry, FILE__GETATTR);
}

static int selinux_inode_listxattr(const struct vfsmount *mnt,
				   struct dentry *dentry)
{
	const struct cred *cred = current_cred();

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (d_inode(dentry)->i_sb->s_magic == SOCKFS_MAGIC) {
		struct sock *sk = READ_ONCE(SOCKET_I(d_inode(dentry))->sk);

		return sk ? sock_has_perm(sk, SOCKET__GETATTR) : -EACCES;
	}
#endif

	return dentry_has_perm_mnt(cred, mnt, dentry, FILE__GETATTR);
}

static int selinux_inode_removexattr(struct mnt_idmap *idmap,
				     const struct vfsmount *mnt,
				     struct dentry *dentry, const char *name)
{
	/* if not a selinux xattr, only check the ordinary setattr perm */
	if (strcmp(name, XATTR_NAME_SELINUX))
		return dentry_has_perm_mnt(current_cred(), mnt, dentry,
					    FILE__SETATTR);

	if (!selinux_initialized(current_selinux_state)) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		return selinux_cred_chain_uninitialized(current_cred()) ?
			0 : -EACCES;
#else
		return 0;
#endif
	}

	/* No one is allowed to remove a SELinux security label.
	   You can change the label, but all data must be labeled. */
	return -EACCES;
}

static int selinux_inode_file_setattr(const struct vfsmount *mnt,
				      struct dentry *dentry,
				      struct file_kattr *fa)
{
	return dentry_has_perm_mnt(current_cred(), mnt, dentry, FILE__SETATTR);
}

static int selinux_inode_file_getattr(const struct vfsmount *mnt,
				      struct dentry *dentry,
				      struct file_kattr *fa)
{
	return dentry_has_perm_mnt(current_cred(), mnt, dentry, FILE__GETATTR);
}

static int selinux_path_notify(const struct path *path, u64 mask,
						unsigned int obj_type)
{
	int ret;
	u32 perm;

	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_PATH;
	ad.u.path = *path;

	/*
	 * Set permission needed based on the type of mark being set.
	 * Performs an additional check for sb watches.
	 */
	switch (obj_type) {
	case FSNOTIFY_OBJ_TYPE_VFSMOUNT:
		perm = FILE__WATCH_MOUNT;
		break;
	case FSNOTIFY_OBJ_TYPE_SB:
		perm = FILE__WATCH_SB;
#ifdef CONFIG_SECURITY_SELINUX_NS
		ret = superblock_has_perm_mnt(
			current_cred(), path->dentry->d_sb, path->mnt,
			FILESYSTEM__WATCH, &ad);
#else
		ret = superblock_has_perm(
			current_cred(), path->dentry->d_sb,
			FILESYSTEM__WATCH, &ad);
#endif
		if (ret)
			return ret;
		break;
	case FSNOTIFY_OBJ_TYPE_INODE:
		perm = FILE__WATCH;
		break;
	case FSNOTIFY_OBJ_TYPE_MNTNS:
		perm = FILE__WATCH_MOUNTNS;
		break;
	default:
		return -EINVAL;
	}

	/* blocking watches require the file:watch_with_perm permission */
	if (mask & (ALL_FSNOTIFY_PERM_EVENTS))
		perm |= FILE__WATCH_WITH_PERM;

	/* watches on read-like events need the file:watch_reads permission */
	if (mask & (FS_ACCESS | FS_ACCESS_PERM | FS_PRE_ACCESS |
		    FS_CLOSE_NOWRITE))
		perm |= FILE__WATCH_READS;

	return path_has_perm(current_cred(), path, perm);
}

/*
 * Copy the inode security context value to the user.
 *
 * Permission check is handled by selinux_inode_getxattr hook.
 */
#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_inode_xattr_sid_for_view(
	const struct selinux_label_view *view, bool mount_supplied,
	const struct selinux_label_domain *observer_domain,
	struct selinux_label_ref *label, u32 source_sid, u32 *observer_sid)
{
	struct selinux_label_ref *canonical;
	int rc;

	if (!observer_domain || !label || !source_sid || !observer_sid)
		return -EINVAL;

	if (mount_supplied) {
		if (!view ||
		    (view->flags & SELINUX_LABEL_VIEW_ORIGIN_UNRESOLVED))
			return -EACCES;
		rc = selinux_label_view_resolve(view, observer_domain, label,
						source_sid, observer_sid);
		/* Never let a missing boundary map expose the raw on-disk xattr. */
		return rc == -EOPNOTSUPP ? -EACCES : rc;
	}

	/*
	 * A legacy caller supplied no mount and therefore no authority to select
	 * a derived view.  Verify the exact opaque handle and allow only labels
	 * whose meaning is already intrinsic to the observer.  Global initial
	 * SIDs have deliberately universal semantics.
	 */
	canonical = global_sid_to_label_ref(source_sid);
	if (IS_ERR(canonical))
		return PTR_ERR(canonical);
	if (canonical != label)
		rc = -EIO;
	else if (((label->domain->flags &
		   SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) &&
		  source_sid <= SECINITSID_NUM) ||
		 label->domain == observer_domain) {
		*observer_sid = source_sid;
		rc = 0;
	} else {
		rc = -EXDEV;
	}
	selinux_label_ref_put(canonical);
	return rc;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
int selinux_kunit_inode_xattr_sid_for_view(
	const struct selinux_label_view *view, bool mount_supplied,
	const struct selinux_label_domain *observer_domain,
	struct selinux_label_ref *label, u32 source_sid, u32 *observer_sid)
{
	return selinux_inode_xattr_sid_for_view(
		view, mount_supplied, observer_domain, label, source_sid,
		observer_sid);
}
#endif

static int selinux_inode_pathless_getsecurity(
	const struct cred *observer_cred, struct selinux_state *observer_state,
	const struct selinux_pathless_projection *projection, void **buffer,
	bool alloc)
{
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	struct selinux_pathless_chain_resolution *line __free(kfree) = NULL;
	unsigned int retry;
	int error = -ESTALE;

	chain = kzalloc_obj(*chain, GFP_KERNEL);
	line = kzalloc_obj(*line, GFP_KERNEL);
	if (!chain || !line)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		const struct cred_security_struct *leaf;
		struct selinux_pathless_resolution resolved;
		const char *context = NULL;
		u32 size;
		bool valid;

		error = selinux_policy_chain_snapshot_read(observer_cred, chain);
		if (error == -EAGAIN || error == -ESTALE)
			continue;
		if (error)
			break;
		leaf = selinux_cred(chain->cred[0]);
		if (leaf->state != observer_state ||
		    leaf->state->label_domain->depth >= ARRAY_SIZE(line->level)) {
			error = -EXDEV;
			break;
		}
		error = selinux_pathless_projection_resolve_cred_chain(
			projection, chain->cred, chain->policy, chain->count, line);
		if (error)
			goto release_line;
		resolved = line->level[leaf->state->label_domain->depth];
		if (!resolved.sid) {
			error = -EOPNOTSUPP;
			goto release_line;
		}

		rcu_read_lock();
		if (has_cap_mac_admin(false))
			error = security_sid_to_context_force(
				observer_state, resolved.sid, &context, &size);
		else
			error = security_sid_to_context_valid(
				observer_state, resolved.sid, &context, &size);
		if (!error && alloc) {
			*buffer = kmemdup(context, size, GFP_ATOMIC);
			if (!*buffer)
				error = -ENOMEM;
		}
		rcu_read_unlock();
		if (!error)
			error = size;

release_line:
		valid = selinux_policy_chain_snapshot_valid(chain);
		selinux_pathless_chain_resolution_put(line);
		if (error == -EAGAIN || error == -ESTALE || !valid) {
			if (alloc && error >= 0) {
				kfree(*buffer);
				*buffer = NULL;
			}
			error = -ESTALE;
			continue;
		}
		break;
	}
	return error == -EOPNOTSUPP ? -EACCES : error;
}

static int selinux_socket_getsecurity(
	const struct cred *observer_cred, struct selinux_state *observer_state,
	const struct selinux_net_provenance *provenance, void **buffer, bool alloc)
{
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	struct selinux_label_operation_resolution *operation __free(kfree) = NULL;
	unsigned int retry;
	int error = -ESTALE;

	if (!provenance || !provenance->subject ||
	    !provenance->subject->label || !provenance->subject->sid_handle ||
	    !provenance->view ||
	    global_sid_handle_sid(provenance->subject->sid_handle) !=
		    provenance->subject->sid)
		return -EACCES;
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	operation = kzalloc_obj(*operation, GFP_KERNEL);
	if (!chain || !operation)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		const struct cred_security_struct *leaf;
		const char *context = NULL;
		u16 depth;
		u32 observer_sid, size;
		bool valid;

		error = selinux_policy_chain_snapshot_read(observer_cred, chain);
		if (error == -EAGAIN || error == -ESTALE)
			continue;
		if (error)
			break;
		leaf = selinux_cred(chain->cred[0]);
		if (leaf->state != observer_state) {
			error = -EXDEV;
			break;
		}
		depth = leaf->state->label_domain->depth;
		error = selinux_label_view_resolve_operation(
			provenance->view, provenance->subject->label,
			provenance->subject->sid, leaf->state->label_domain,
			operation);
		if (error)
			goto release_operation;
		if (depth > operation->labels.max_depth ||
		    operation->labels.domain_id[depth] !=
			    leaf->state->label_domain->id ||
		    !operation->labels.sid[depth]) {
			error = -EOPNOTSUPP;
			goto release_operation;
		}
		observer_sid = operation->labels.sid[depth];

		rcu_read_lock();
		if (has_cap_mac_admin(false))
			error = security_sid_to_context_force(
				observer_state, observer_sid, &context, &size);
		else
			error = security_sid_to_context_valid(
				observer_state, observer_sid, &context, &size);
		if (!error && alloc) {
			*buffer = kmemdup(context, size, GFP_ATOMIC);
			if (!*buffer)
				error = -ENOMEM;
		}
		rcu_read_unlock();
		if (!error)
			error = size;

release_operation:
		valid = selinux_policy_chain_snapshot_valid(chain);
		selinux_label_operation_resolution_put(operation);
		if (error == -EAGAIN || error == -ESTALE || !valid) {
			if (alloc && error >= 0) {
				kfree(*buffer);
				*buffer = NULL;
			}
			error = -ESTALE;
			continue;
		}
		break;
	}
	return error == -EOPNOTSUPP ? -EACCES : error;
}
#endif

static int selinux_inode_getsecurity(struct mnt_idmap *idmap,
				     const struct vfsmount *mnt,
				     struct inode *inode, const char *name, void **buffer,
				     bool alloc)
{
	const struct cred *observer_cred = current_cred();
	struct selinux_state *observer_state =
		cred_selinux_state(observer_cred);
	u32 observer_sid, size;
	int error;
	const char *context = NULL;
	struct inode_security_struct *isec;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct selinux_label_view *view = NULL;
	struct selinux_pathless_projection *projection;
	struct selinux_net_provenance *socket_provenance;
	struct selinux_inode_label_snapshot snapshot;
#endif

	/*
	 * If we're not initialized yet, then we can't validate contexts, so
	 * just let vfs_getxattr fall back to using the on-disk xattr.
	 */
	if (!observer_state || !selinux_initialized(observer_state) ||
	    strcmp(name, XATTR_SELINUX_SUFFIX))
		return -EOPNOTSUPP;

	/*
	 * If the caller has CAP_MAC_ADMIN, then get the raw context
	 * value even if it is not defined by current policy; otherwise,
	 * use the in-core value under current policy.
	 * Use the non-auditing forms of the permission checks since
	 * getxattr may be called by unprivileged processes commonly
	 * and lack of permission just means that we fall back to the
	 * in-core context value, not a denial.
	 */
	isec = inode_security(inode);
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (inode->i_sb->s_magic == SOCKFS_MAGIC) {
		struct socket *sock = SOCKET_I(inode);
		struct sock *sk = READ_ONCE(sock->sk);

		if (!sk)
			return -EACCES;
		socket_provenance = selinux_net_provenance_get_rcu(
			&selinux_sock(sk)->provenance);
		if (!socket_provenance)
			return -EACCES;
		if (READ_ONCE(selinux_sock(sk)->sid) !=
			    socket_provenance->subject->sid ||
		    READ_ONCE(selinux_sock(sk)->state) != socket_provenance->state)
			error = -ESTALE;
		else
			error = selinux_socket_getsecurity(
				observer_cred, observer_state, socket_provenance,
				buffer, alloc);
		selinux_net_provenance_put(socket_provenance);
		return error;
	}
	projection = selinux_inode_pathless_get(isec);
	if (projection) {
		error = selinux_inode_pathless_getsecurity(
			observer_cred, observer_state, projection, buffer, alloc);
		selinux_pathless_projection_put(projection);
		return error;
	}
	if (mnt)
		view = selinux_mnt_label_view(mnt);
	error = selinux_inode_label_snapshot_get(isec, &snapshot);
	if (error)
		return error;
	error = selinux_inode_xattr_sid_for_view(
		view, !!mnt, observer_state->label_domain, snapshot.label,
		snapshot.sid, &observer_sid);
	selinux_inode_label_snapshot_put(&snapshot);
	if (error)
		return error;
#else
	observer_sid = isec->sid;
#endif
	rcu_read_lock();
	if (has_cap_mac_admin(false))
		error = security_sid_to_context_force(observer_state,
						      observer_sid, &context,
						      &size);
	else
		error = security_sid_to_context_valid(observer_state, observer_sid,
						&context, &size);
	if (error)
		goto out_unlock;
	error = size;
	if (alloc) {
		*buffer = kmemdup(context, size, GFP_ATOMIC);
		if (!(*buffer))
			error = -ENOMEM;
	}

out_unlock:
	rcu_read_unlock();
	return error;
}

static int selinux_inode_setsecurity(struct inode *inode, const char *name,
				     const void *value, size_t size, int flags)
{
	struct inode_security_struct *isec = inode_security_novalidate(inode);
	u32 newsid;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle;
	u16 sclass;
#else
	int rc;
#endif

	if (strcmp(name, XATTR_SELINUX_SUFFIX))
		return -EOPNOTSUPP;

	if (!selinux_is_sblabel_mnt(inode->i_sb))
		return -EOPNOTSUPP;

	if (!value || !size)
		return -EACCES;

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (selinux_initialized(current_selinux_state)
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	    || selinux_task(current)->create_plan_kunit_force
#endif
	) {
		struct selinux_inode_setxattr_plan *plan =
			selinux_task(current)->setxattr_plan;

		/*
		 * Filesystems without an xattr handler use inode_setsecurity as
		 * both the apply and commit operation.  Consume the exact sealed
		 * value here; an ambient context-to-SID conversion would cross the
		 * mount view and could race a policy reload.
		 */
		if (!plan || plan->inode != inode || value != plan->xattr_value ||
		    size != plan->xattr_value_len || flags != plan->flags ||
		    plan->committed)
			return -EOPNOTSUPP;
		if (!selinux_policy_chain_snapshot_valid(&plan->chain))
			return -ESTALE;
		return selinux_inode_setxattr_plan_commit(plan, isec, false);
	}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
	handle = security_context_to_global_handle(
		current_selinux_state, value, size, &newsid, GFP_KERNEL);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
#else
	rc = security_context_to_sid(current_selinux_state, value, size, &newsid,
				     GFP_KERNEL);
	if (rc)
		return rc;
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
	sclass = inode_mode_to_security_class(inode->i_mode);
	return selinux_inode_security_take_sid_handle(
		isec, handle, &sclass,
		SELINUX_LABEL_SOURCE_SECURITY_CONTEXT, LABEL_INITIALIZED);
#else
	return inode_security_set_sid_class(
		isec, newsid, inode_mode_to_security_class(inode->i_mode),
		SELINUX_LABEL_SOURCE_SECURITY_CONTEXT, LABEL_INITIALIZED);
#endif
}

static int selinux_inode_listsecurity(struct inode *inode, char **buffer,
				ssize_t *remaining_size)
{
	if (!selinux_initialized(current_selinux_state))
		return 0;
	return xattr_list_one(buffer, remaining_size, XATTR_NAME_SELINUX);
}

static void selinux_inode_getlsmprop(struct inode *inode, struct lsm_prop *prop)
{
	struct inode_security_struct *isec = inode_security_novalidate(inode);

#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_inode_label_snapshot snapshot;

	if (selinux_inode_label_snapshot_get(isec, &snapshot)) {
		prop->selinux.secid = SECSID_NULL;
		return;
	}
	prop->selinux.secid = snapshot.sid;
	selinux_inode_label_snapshot_put(&snapshot);
#else
	prop->selinux.secid = isec->sid;
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
/*
 * Preserve the upstream pre-policy copy-up contract without treating an
 * uninitialized inode tuple as a policy label.  The only identity accepted
 * here is a strongly held kernel-initial SID, and every policy in the actor's
 * chain must remain uninitialized through the final publication check.
 */
static int selinux_inode_copy_up_bootstrap(
	const struct path *src, struct inode_security_struct *isec,
	const struct selinux_label_view *src_view,
	const struct selinux_label_view *dst_view, struct cred **new)
{
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	struct selinux_copy_up_carrier *carrier = NULL;
	struct selinux_global_sid_handle *cred_handle = NULL;
	struct cred_security_struct *crsec;
	struct cred *new_creds = *new;
	bool allocated_creds = false;
	u16 i;
	int rc;

	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;
	rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
	if (rc)
		return rc;
	for (i = 0; i < chain->count; i++)
		if (chain->policy[i].initialized)
			return -EACCES;
	if (src_view->origin_domain != current_selinux_state->label_domain ||
	    dst_view->origin_domain != current_selinux_state->label_domain)
		return -EXDEV;

	carrier = kzalloc_obj(*carrier, GFP_KERNEL_ACCOUNT);
	if (!carrier)
		return -ENOMEM;
	INIT_WORK(&carrier->free_work, selinux_copy_up_carrier_free);
	spin_lock(&isec->lock);
	if (!isec->sid_handle ||
	    global_sid_handle_sid(isec->sid_handle) != isec->sid) {
		rc = -ESTALE;
	} else {
		carrier->sid_handle =
			global_sid_handle_dup(isec->sid_handle);
		rc = IS_ERR(carrier->sid_handle) ?
			PTR_ERR(carrier->sid_handle) : 0;
		if (IS_ERR(carrier->sid_handle))
			carrier->sid_handle = NULL;
		carrier->sid = isec->sid;
		carrier->sclass = isec->sclass;
		carrier->source = isec->label_source;
	}
	spin_unlock(&isec->lock);
	if (rc)
		goto out;

	carrier->label =
		global_sid_handle_label_get(carrier->sid_handle);
	if (!carrier->label || !(carrier->label->domain->flags &
			SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) ||
	    carrier->sid > SECINITSID_NUM) {
		rc = -EXDEV;
		goto out;
	}
	carrier->create_handle =
		global_sid_handle_dup(carrier->sid_handle);
	if (IS_ERR(carrier->create_handle)) {
		rc = PTR_ERR(carrier->create_handle);
		carrier->create_handle = NULL;
		goto out;
	}
	carrier->src_view = selinux_label_view_get(src_view);
	carrier->dst_view = selinux_label_view_get(dst_view);
	carrier->src_path = *src;
	path_get(&carrier->src_path);
	carrier->bootstrap = true;
	if (!carrier->src_view || !carrier->dst_view) {
		rc = -ESTALE;
		goto out;
	}

	if (!new_creds) {
		new_creds = prepare_creds();
		if (!new_creds) {
			rc = -ENOMEM;
			goto out;
		}
		allocated_creds = true;
	}
	if (!selinux_policy_chain_snapshot_valid(chain)) {
		rc = -ESTALE;
		goto out;
	}
	spin_lock(&isec->lock);
	if (isec->sid_handle != carrier->sid_handle ||
	    isec->sid != carrier->sid || isec->sclass != carrier->sclass ||
	    isec->label_source != carrier->source)
		rc = -ESTALE;
	spin_unlock(&isec->lock);
	if (rc)
		goto out;
	crsec = selinux_cred(new_creds);
	if (crsec->copy_up) {
		rc = -EEXIST;
		goto out;
	}
	cred_handle = global_sid_handle_dup(carrier->create_handle);
	if (IS_ERR(cred_handle)) {
		rc = PTR_ERR(cred_handle);
		cred_handle = NULL;
		goto out;
	}
	rc = selinux_cred_sid_take_handle(crsec, SELINUX_CRED_CREATE_SID,
					  cred_handle);
	cred_handle = NULL;
	if (rc)
		goto out;
	crsec->copy_up = carrier;
	carrier = NULL;
	*new = new_creds;

out:
	if (rc && allocated_creds)
		abort_creds(new_creds);
	global_sid_handle_put(cred_handle);
	selinux_copy_up_carrier_put(carrier);
	return rc;
}
#endif

static int selinux_inode_copy_up(const struct path *src,
				 const struct vfsmount *dst_mnt,
				 struct cred **new)
{
	struct cred_security_struct *crsec;
	struct cred *new_creds = *new;
	struct inode_security_struct *isec;
#ifndef CONFIG_SECURITY_SELINUX_NS
	u32 create_sid;
#endif
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct mount_security_struct *src_sec, *dst_sec;
	const struct selinux_label_view *src_view, *dst_view, *view;
	struct selinux_copy_up_carrier *carrier = NULL;
	struct selinux_global_sid_handle *cred_handle = NULL;
	struct selinux_global_sid_handle *create_handle = NULL;
	struct selinux_inode_label_snapshot snapshot;
	u32 create_sid;
	bool allocated_creds = false;
	int rc;
#endif

	if (!src || !src->mnt || !src->dentry || !dst_mnt)
		return -EINVAL;
	isec = backing_inode_security(src->dentry);

#ifdef CONFIG_SECURITY_SELINUX_NS
	src_sec = selinux_mount_security(src->mnt);
	dst_sec = selinux_mount_security(dst_mnt);
	if (!src_sec || !dst_sec)
		return -EACCES;
	src_view = smp_load_acquire(&src_sec->view);
	dst_view = smp_load_acquire(&dst_sec->view);
	if (!src_view || !dst_view)
		return -EACCES;
	if ((src_view->flags | dst_view->flags) &
	    SELINUX_LABEL_VIEW_ORIGIN_UNRESOLVED)
		return -EOPNOTSUPP;
	if (!selinux_initialized(current_selinux_state))
		return selinux_inode_copy_up_bootstrap(
			src, isec, src_view, dst_view, new);
	/*
	 * The create SID is interpreted by the current policy.  Until label
	 * generation itself accepts an explicit destination domain, accepting a
	 * different upper origin would create a policy-local label on the wrong
	 * intrinsic layer.
	 */
	if (dst_view->origin_domain !=
	    current_selinux_state->label_domain)
		return -EOPNOTSUPP;

	rc = selinux_inode_label_snapshot_get(isec, &snapshot);
	if (rc)
		return rc;
	create_sid = snapshot.sid;
	if (!((snapshot.label->domain->flags &
	       SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) &&
	      create_sid <= SECINITSID_NUM) &&
	    snapshot.label->domain != src_view->origin_domain) {
		rc = -EINVAL;
		goto out_snapshot;
	}
	view = selinux_identity_view_alloc(dst_view->owner_userns,
					   snapshot.label->domain,
					   dst_view->outer_domain);
	if (IS_ERR(view)) {
		rc = PTR_ERR(view);
		goto out_snapshot;
	}
	if (!selinux_mnt_views_share_snapshot(src_view, view) ||
	    !selinux_mnt_views_share_snapshot(dst_view, view)) {
		rc = -ESTALE;
		goto out_view;
	}
	rc = selinux_label_view_resolve(view,
					current_selinux_state->label_domain, snapshot.label,
					create_sid, &create_sid);
	if (!rc) {
		/* The live view still pins the exact map target at this point. */
		create_handle = global_sid_handle_get(create_sid);
		if (IS_ERR(create_handle)) {
			rc = PTR_ERR(create_handle);
			create_handle = NULL;
		}
	}
out_view:
	selinux_label_view_put(view);
	if (rc)
		goto out_snapshot;

	carrier = kzalloc_obj(*carrier, GFP_KERNEL_ACCOUNT);
	if (!carrier) {
		rc = -ENOMEM;
		goto out_create;
	}
	INIT_WORK(&carrier->free_work, selinux_copy_up_carrier_free);
	carrier->src_view = selinux_label_view_get(src_view);
	carrier->dst_view = selinux_label_view_get(dst_view);
	carrier->src_path = *src;
	path_get(&carrier->src_path);
	if (!carrier->src_view || !carrier->dst_view) {
		rc = -ESTALE;
		goto out_carrier;
	}
	carrier->label = snapshot.label;
	carrier->sid_handle = snapshot.sid_handle;
	carrier->create_handle = create_handle;
	carrier->sid = snapshot.sid;
	carrier->sclass = snapshot.sclass;
	carrier->source = snapshot.source;
	snapshot.label = NULL;
	snapshot.sid_handle = NULL;
	create_handle = NULL;
#endif

	if (new_creds == NULL) {
		new_creds = prepare_creds();
		if (!new_creds) {
#ifdef CONFIG_SECURITY_SELINUX_NS
			rc = -ENOMEM;
			goto out_carrier;
#endif
			return -ENOMEM;
		}
#ifdef CONFIG_SECURITY_SELINUX_NS
		allocated_creds = true;
#endif
	}

	crsec = selinux_cred(new_creds);
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (crsec->copy_up) {
		rc = -EEXIST;
		goto out_creds;
	}
	cred_handle = global_sid_handle_dup(carrier->create_handle);
	if (IS_ERR(cred_handle)) {
		rc = PTR_ERR(cred_handle);
		cred_handle = NULL;
		goto out_creds;
	}
	rc = selinux_cred_sid_take_handle(crsec, SELINUX_CRED_CREATE_SID,
					  cred_handle);
	cred_handle = NULL;
	if (rc) {
		goto out_creds;
	}
	crsec->copy_up = carrier;
	carrier = NULL;
#else
	create_sid = isec->sid;
	crsec->create_sid = create_sid;
#endif
	*new = new_creds;
	return 0;

#ifdef CONFIG_SECURITY_SELINUX_NS
out_creds:
	global_sid_handle_put(cred_handle);
	if (allocated_creds)
		abort_creds(new_creds);
out_carrier:
	selinux_copy_up_carrier_put(carrier);
out_create:
	global_sid_handle_put(create_handle);
out_snapshot:
	selinux_inode_label_snapshot_put(&snapshot);
	return rc;
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_inode_copy_up_bootstrap_post(
	const struct path *src, struct dentry *dst,
	const struct cred *copy_up_cred,
	const struct selinux_copy_up_carrier *carrier)
{
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	struct inode_security_struct *src_isec, *dst_isec;
	u16 i;
	int rc;

	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;
	rc = selinux_policy_chain_snapshot_read(copy_up_cred, chain);
	if (rc)
		return rc;
	for (i = 0; i < chain->count; i++)
		if (chain->policy[i].initialized)
			return -EACCES;

	src_isec = backing_inode_security(src->dentry);
	dst_isec = backing_inode_security(dst);
	spin_lock(&src_isec->lock);
	if (src_isec->initialized == LABEL_INITIALIZED ||
	    src_isec->sid_handle != carrier->sid_handle ||
	    src_isec->sid != carrier->sid ||
	    src_isec->sclass != carrier->sclass ||
	    src_isec->label_source != carrier->source ||
	    rcu_dereference_protected(
		    src_isec->label_ref,
		    lockdep_is_held(&src_isec->lock)) != carrier->label)
		rc = -ESTALE;
	spin_unlock(&src_isec->lock);
	if (rc)
		return rc;

	spin_lock(&dst_isec->lock);
	if (dst_isec->initialized == LABEL_INITIALIZED ||
	    dst_isec->sid_handle != carrier->create_handle ||
	    dst_isec->sid !=
		    global_sid_handle_sid(carrier->create_handle) ||
	    dst_isec->sclass != carrier->sclass ||
	    rcu_dereference_protected(
		    dst_isec->label_ref,
		    lockdep_is_held(&dst_isec->lock)) != carrier->label)
		rc = -ESTALE;
	spin_unlock(&dst_isec->lock);
	if (rc)
		return rc;
	return selinux_policy_chain_snapshot_valid(chain) ? 0 : -ESTALE;
}
#endif

static int selinux_inode_copy_up_post(const struct path *src,
				      const struct vfsmount *dst_mnt,
				      struct dentry *dst,
				      const struct cred *copy_up_cred)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct mount_security_struct *src_sec, *dst_sec;
	const struct selinux_label_view *src_view, *dst_view;
	const struct selinux_copy_up_carrier *carrier;
	struct selinux_copy_up_assertion *assertion;
	struct inode_security_struct *src_isec, *dst_isec;
	struct selinux_inode_label_snapshot src_snapshot, dst_snapshot;
	struct selinux_label_ref *dst_label;
	int rc = 0;

	if (!src || !src->mnt || !src->dentry || !dst_mnt || !dst ||
	    !copy_up_cred)
		return -EINVAL;
	carrier = selinux_cred(copy_up_cred)->copy_up;
	if (!carrier)
		return -ESTALE;
	src_sec = selinux_mount_security(src->mnt);
	dst_sec = selinux_mount_security(dst_mnt);
	if (!src_sec || !dst_sec)
		return -EACCES;
	src_view = smp_load_acquire(&src_sec->view);
	dst_view = smp_load_acquire(&dst_sec->view);
	if (!src_view || !dst_view)
		return -EACCES;
	if ((src_view->flags | dst_view->flags) &
	    SELINUX_LABEL_VIEW_ORIGIN_UNRESOLVED)
		return -EOPNOTSUPP;
	if (src_view != carrier->src_view || dst_view != carrier->dst_view ||
	    !path_equal(src, &carrier->src_path))
		return -ESTALE;
	if (carrier->bootstrap)
		return selinux_inode_copy_up_bootstrap_post(
			src, dst, copy_up_cred, carrier);

	src_isec = backing_inode_security(src->dentry);
	dst_isec = backing_inode_security(dst);
	rc = selinux_inode_label_snapshot_get(src_isec, &src_snapshot);
	if (rc)
		return rc;
	if (src_snapshot.sid_handle != carrier->sid_handle ||
	    src_snapshot.label != carrier->label ||
	    src_snapshot.sid != carrier->sid ||
	    src_snapshot.sclass != carrier->sclass ||
	    src_snapshot.source != carrier->source) {
		rc = -ESTALE;
		goto out_src;
	}
	rc = selinux_inode_label_snapshot_get(dst_isec, &dst_snapshot);
	if (rc)
		goto out_src;
	dst_label = global_sid_handle_label_get(carrier->create_handle);
	if (!dst_label || dst_snapshot.sid_handle != carrier->create_handle ||
	    dst_snapshot.label != dst_label ||
	    dst_snapshot.sid != global_sid_handle_sid(carrier->create_handle) ||
	    dst_snapshot.sclass != carrier->sclass) {
		rc = -ESTALE;
		goto out_dst_label;
	}

	assertion = kzalloc_obj(*assertion, GFP_KERNEL_ACCOUNT);
	if (!assertion) {
		rc = -ENOMEM;
		goto out_dst_label;
	}
	assertion->label = selinux_label_ref_get(carrier->label);
	assertion->view = selinux_label_view_get(carrier->src_view);
	assertion->sid_handle = global_sid_handle_dup(carrier->sid_handle);
	assertion->sid = carrier->sid;
	assertion->source = carrier->source;
	if (!assertion->label || !assertion->view ||
	    IS_ERR(assertion->sid_handle)) {
		rc = IS_ERR(assertion->sid_handle) ?
			PTR_ERR(assertion->sid_handle) : -ESTALE;
		if (IS_ERR(assertion->sid_handle))
			assertion->sid_handle = NULL;
		selinux_label_view_put(assertion->view);
		selinux_label_ref_put(assertion->label);
		global_sid_handle_put(assertion->sid_handle);
		kfree(assertion);
		goto out_dst_label;
	}

	spin_lock(&dst_isec->lock);
	if (dst_isec->initialized != LABEL_INITIALIZED ||
	    dst_isec->sid_handle != carrier->create_handle ||
	    dst_isec->sid != dst_snapshot.sid ||
	    dst_isec->sclass != dst_snapshot.sclass ||
	    rcu_dereference_protected(dst_isec->label_ref,
				      lockdep_is_held(&dst_isec->lock)) != dst_label) {
		spin_unlock(&dst_isec->lock);
		rc = -ESTALE;
	} else if (dst_isec->copy_up) {
		spin_unlock(&dst_isec->lock);
		rc = -EEXIST;
	} else {
		dst_isec->copy_up = assertion;
		spin_unlock(&dst_isec->lock);
		assertion = NULL;
	}
	if (assertion) {
		selinux_label_view_put(assertion->view);
		selinux_label_ref_put(assertion->label);
		global_sid_handle_put(assertion->sid_handle);
		kfree(assertion);
	}
out_dst_label:
	selinux_label_ref_put(dst_label);
	selinux_inode_label_snapshot_put(&dst_snapshot);
out_src:
	selinux_inode_label_snapshot_put(&src_snapshot);
	return rc;
#else
	(void)src;
	(void)dst_mnt;
	(void)dst;
	(void)copy_up_cred;
#endif
	return 0;
}

static int selinux_inode_copy_up_xattr(const struct vfsmount *src_mnt,
				       struct dentry *dentry, const char *name)
{
	/* Filtering this well-known xattr is independent of the source view. */
	(void)src_mnt;
	/* The copy_up hook above sets the initial context on an inode, but we
	 * don't then want to overwrite it by blindly copying all the lower
	 * xattrs up.  Instead, filter out SELinux-related xattrs following
	 * policy load.
	 */
	if (selinux_initialized(current_selinux_state) &&
	    !strcmp(name, XATTR_NAME_SELINUX))
		return -ECANCELED; /* Discard */
	/*
	 * Any other attribute apart from SELINUX is not claimed, supported
	 * by selinux.
	 */
	return -EOPNOTSUPP;
}

/* kernfs node operations */

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_kernfs_root_alloc_security(void *root_security)
{
	const struct cred_security_struct *crsec = selinux_cred(current_cred());
	struct kernfs_root_security_struct *rootsec;
	struct selinux_label_domain *domain;
	struct selinux_state *state;

	rootsec = selinux_kernfs_root_security(root_security);
	state = READ_ONCE(crsec->state);
	if (!rootsec || !state || !selinux_state_active(state))
		return -EACCES;
	domain = READ_ONCE(state->label_domain);
	if (!domain || domain->depth != state->depth)
		return -EACCES;

	/* The composite blob is unpublished, so publish both strong refs once. */
	rootsec->anchor_state = get_selinux_state(state);
	rootsec->anchor_domain = selinux_label_domain_get(domain);
	return 0;
}

static void selinux_kernfs_root_free_security(void *root_security)
{
	struct kernfs_root_security_struct *rootsec;

	rootsec = selinux_kernfs_root_security(root_security);
	if (!rootsec)
		return;
	put_selinux_state(rootsec->anchor_state);
	rootsec->anchor_state = NULL;
	selinux_label_domain_put(rootsec->anchor_domain);
	rootsec->anchor_domain = NULL;
}

static int selinux_kernfs_root_to_sb(struct super_block *sb,
				     const void *root_security)
{
	const struct kernfs_root_security_struct *rootsec;
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	int rc;

	rootsec = selinux_kernfs_root_security(root_security);
	if (!rootsec || !rootsec->anchor_state || !rootsec->anchor_domain ||
	    rootsec->anchor_state->label_domain != rootsec->anchor_domain ||
	    !selinux_state_active(rootsec->anchor_state))
		return -EACCES;

	mutex_lock(&sbsec->lock);
	rc = selinux_sb_set_anchor_locked(sbsec, rootsec->anchor_state);
	mutex_unlock(&sbsec->lock);
	return rc;
}
#endif

static int selinux_kernfs_policy_snapshot_read(
	struct selinux_state *state, struct selinux_policy_snapshot *snapshot)
{
	KUNIT_STATIC_STUB_REDIRECT(selinux_kernfs_policy_snapshot_read, state,
				   snapshot);
	return selinux_policy_snapshot_read(state, snapshot);
}

static int selinux_kernfs_init_security(struct kernfs_node *kn_dir,
					struct kernfs_node *kn,
					const void *root_security)
{
	const struct cred *anchor_cred;
	const struct cred_security_struct *crsec;
	struct selinux_policy_snapshot snapshot;
	struct selinux_state *state;
	const char *context2;
	char *context, *new_context = NULL;
	const char *kn_name;
	struct qstr q;
	u32 actor_sid, parent_sid, newsid, parent_len, new_len;
	unsigned int retry;
	int rc;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct kernfs_root_security_struct *rootsec;
	struct selinux_label_ref *label;
	struct selinux_global_sid_handle *parent_handle = NULL;
	struct selinux_global_sid_handle *newsid_handle = NULL;

	rootsec = selinux_kernfs_root_security(root_security);
	if (!rootsec || !rootsec->anchor_state || !rootsec->anchor_domain ||
	    rootsec->anchor_state->label_domain != rootsec->anchor_domain ||
	    !selinux_state_active(rootsec->anchor_state))
		return -EACCES;
	state = rootsec->anchor_state;
	anchor_cred = selinux_cred_for_state(current_cred(), state);
	if (!anchor_cred)
		return -EXDEV;
#else
	state = current_selinux_state;
	anchor_cred = current_cred();
#endif
	crsec = selinux_cred(anchor_cred);
	actor_sid = crsec->sid;

	rc = kernfs_xattr_get(kn_dir, XATTR_NAME_SELINUX, NULL, 0);
	if (rc == -ENODATA)
		return 0;
	if (rc < 0)
		return rc;

	parent_len = (u32)rc;
	context = kmalloc(parent_len, GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	rc = kernfs_xattr_get(kn_dir, XATTR_NAME_SELINUX, context, parent_len);
	if (rc < 0)
		goto out;
	if (rc != parent_len) {
		rc = -EAGAIN;
		goto out;
	}

	/* kn is fresh and cannot be renamed while this hook runs. */
	kn_name = rcu_dereference_check(kn->name, true);
	q.name = kn_name;
	q.hash_len = hashlen_string(kn_dir, kn_name);

	for (retry = 0; retry < SELINUX_KERNFS_POLICY_RETRIES; retry++) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		global_sid_handle_put(newsid_handle);
		global_sid_handle_put(parent_handle);
		newsid_handle = NULL;
		parent_handle = NULL;
#endif
		rc = selinux_kernfs_policy_snapshot_read(state, &snapshot);
		if (rc) {
			if (rc == -EAGAIN || rc == -ESTALE)
				continue;
			goto out;
		}
#ifdef CONFIG_SECURITY_SELINUX_NS
		parent_handle = security_context_to_global_handle(
			state, context, parent_len, &parent_sid, GFP_KERNEL);
		rc = IS_ERR(parent_handle) ? PTR_ERR(parent_handle) : 0;
		if (IS_ERR(parent_handle))
			parent_handle = NULL;
#else
		rc = security_context_to_sid(state, context, parent_len, &parent_sid,
					     GFP_KERNEL);
#endif
		if (rc)
			goto validate;

		if (crsec->create_sid) {
			newsid = crsec->create_sid;
#ifdef CONFIG_SECURITY_SELINUX_NS
			newsid_handle = global_sid_handle_dup(crsec->create_sid_handle);
			if (IS_ERR(newsid_handle)) {
				rc = PTR_ERR(newsid_handle);
				newsid_handle = NULL;
				goto validate;
			}
#endif
		} else {
			u16 secclass = inode_mode_to_security_class(kn->mode);

#ifdef CONFIG_SECURITY_SELINUX_NS
			newsid_handle = security_transition_sid_handle(
				state, actor_sid, parent_sid, secclass, &q, &newsid);
			rc = IS_ERR(newsid_handle) ? PTR_ERR(newsid_handle) : 0;
			if (IS_ERR(newsid_handle))
				newsid_handle = NULL;
#else
			rc = security_transition_sid(state, actor_sid, parent_sid,
						     secclass, &q, &newsid);
#endif
			if (rc)
				goto validate;
		}

#ifdef CONFIG_SECURITY_SELINUX_NS
		if (!newsid_handle ||
		    global_sid_handle_sid(newsid_handle) != newsid) {
			rc = -ESTALE;
			goto validate;
		}
		if (newsid > SECINITSID_NUM) {
			label = global_sid_handle_label_get(newsid_handle);
			if (!label) {
				rc = -EACCES;
				goto validate;
			}
			if (label->domain != rootsec->anchor_domain)
				rc = -EXDEV;
			selinux_label_ref_put(label);
			if (rc)
				goto validate;
		}
#endif

		rcu_read_lock();
		rc = security_sid_to_context_force(state, newsid, &context2,
						   &new_len);
		if (!rc) {
			new_context = kmemdup(context2, new_len, GFP_ATOMIC);
			if (!new_context)
				rc = -ENOMEM;
		}
		rcu_read_unlock();

validate:
		if (!selinux_policy_snapshot_valid(state, &snapshot)) {
			kfree(new_context);
			new_context = NULL;
			continue;
		}
		if (rc)
			goto out;

		rc = kernfs_xattr_set(kn, XATTR_NAME_SELINUX, new_context, new_len,
				      XATTR_CREATE);
		goto out;
	}
	rc = -EAGAIN;

out:
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(newsid_handle);
	global_sid_handle_put(parent_handle);
#endif
	kfree(new_context);
	kfree(context);
	return rc;
}

#if defined(CONFIG_SECURITY_SELINUX_NS) && \
	defined(CONFIG_SECURITY_SELINUX_KUNIT_TEST)
int selinux_kunit_kernfs_root_alloc(void *root_security)
{
	return selinux_kernfs_root_alloc_security(root_security);
}

void selinux_kunit_kernfs_root_free(void *root_security)
{
	selinux_kernfs_root_free_security(root_security);
}

int selinux_kunit_kernfs_root_to_sb(struct super_block *sb,
				    const void *root_security)
{
	return selinux_kernfs_root_to_sb(sb, root_security);
}

void selinux_kunit_kernfs_sb_free(struct super_block *sb)
{
	selinux_sb_free_security(sb);
}

int selinux_kunit_kernfs_init_security(struct kernfs_node *parent,
				       struct kernfs_node *kn,
				       const void *root_security)
{
	return selinux_kernfs_init_security(parent, kn, root_security);
}

int (* const selinux_kunit_kernfs_snapshot_read)(
	struct selinux_state *state,
	struct selinux_policy_snapshot *snapshot) =
	selinux_kernfs_policy_snapshot_read;
#endif


/* file security operations */

static int selinux_file_bind_view(struct file *file)
{
	struct file_security_struct *fsec = selinux_file(file);
	const struct mount_security_struct *msec;
	const struct selinux_label_view *view;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_pathless_projection *projection;
	const struct selinux_label_view *old_view;

	/*
	 * Reopens through procfs and O_PATH begin with the pseudo-mount's view.
	 * Once an inode projection is published, it is the durable authority and
	 * must be captured by the new open file description before exposure.
	 */
	projection = selinux_inode_pathless_get(selinux_inode(file_inode(file)));
	if (projection) {
		if (fsec->pathless) {
			if (fsec->pathless != projection ||
			    fsec->view != projection->view) {
				selinux_pathless_projection_put(projection);
				return -ESTALE;
			}
			selinux_pathless_projection_put(projection);
			return 0;
		}
		view = selinux_label_view_get(projection->view);
		if (!view) {
			selinux_pathless_projection_put(projection);
			return -EIO;
		}
		old_view = fsec->view;
		fsec->view = view;
		fsec->pathless = projection;
		selinux_label_view_put(old_view);
		return 0;
	}
#endif

	/* The path-binding hook and file_open may both reach this helper. */
	if (fsec->view)
		return 0;
	if (!file->f_path.mnt)
		return -EACCES;

	msec = selinux_mount_security(file->f_path.mnt);
	if (!msec)
		return -EACCES;
	view = smp_load_acquire(&msec->view);
	if (!view)
		return -EACCES;
	if (view->flags & SELINUX_LABEL_VIEW_ORIGIN_UNRESOLVED)
		return -EOPNOTSUPP;
#ifndef CONFIG_SECURITY_SELINUX_NS
	if (!(view->flags & SELINUX_LABEL_VIEW_IDENTITY))
		return -EOPNOTSUPP;
#endif

	view = selinux_label_view_get(view);
	if (!view)
		return -EIO;
	fsec->view = view;
	return 0;
}

static int selinux_file_set_path(struct file *file)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct inode_security_struct *isec = selinux_inode(file_inode(file));
	enum selinux_pathless_kind kind;
	int rc;

	spin_lock(&isec->lock);
	kind = isec->pathless_kind;
	spin_unlock(&isec->lock);
	if (kind == SELINUX_PATHLESS_KIND_NSFS) {
		/*
		 * Finalize before binding the internal nsfs mount.  Otherwise a
		 * depth>0 creator would retain a root-only mount view and fail when
		 * dentry_open() resolves the inode against its policy chain.
		 */
		rc = selinux_file_init_security_nsfs(file);
		if (rc)
			return rc;
		/*
		 * The file retains the inode's immutable canonical projection.  Open
		 * and later operations resolve their current policy line locally.
		 */
		if (selinux_file(file)->pathless)
			return 0;
	}
#endif
	return selinux_file_bind_view(file);
}

static int selinux_revalidate_file_permission(struct file *file, int mask)
{
	const struct cred *cred = current_cred();
	struct inode *inode = file_inode(file);

	/* file_mask_to_av won't add FILE__WRITE if MAY_APPEND is set */
	if ((file->f_flags & O_APPEND) && (mask & MAY_WRITE))
		mask |= MAY_APPEND;

	return file_has_perm(cred, file,
			     file_mask_to_av(inode->i_mode, mask));
}

static int selinux_file_permission(struct file *file, int mask)
{
	struct inode *inode = file_inode(file);
	struct file_security_struct *fsec = selinux_file(file);
	struct inode_security_struct *isec;
	u32 sid = current_sid();
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_inode_label_snapshot snapshot;
	int rc;
#endif

	if (!mask)
		/* No permission to check.  Existence test. */
		return 0;

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		const struct cred_security_struct *crsec =
			selinux_cred(current_cred());

		if (!selinux_initialized(crsec->state))
			return selinux_cred_chain_uninitialized(current_cred()) ?
				0 : -EACCES;
	}
#endif

	isec = inode_security(inode);
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!fsec->pathless) {
		rc = selinux_inode_label_snapshot_get(isec, &snapshot);
		if (rc)
			return rc;
		rc = selinux_file_permission_cache_valid(
			fsec, current_cred(), file->f_cred, sid, snapshot.sid,
			selinux_chain_epoch_read(current_selinux_state));
		selinux_inode_label_snapshot_put(&snapshot);
		if (rc)
			/* No change since file_open check. */
			return 0;
	}
#else
	if (selinux_file_permission_cache_valid(
		    fsec, current_cred(), file->f_cred, sid, isec->sid,
		    selinux_chain_epoch_read(current_selinux_state)))
		/* No change since file_open check. */
		return 0;
#endif

	return selinux_revalidate_file_permission(file, mask);
}

static int selinux_file_alloc_security(struct file *file)
{
	struct file_security_struct *fsec = selinux_file(file);
	u32 sid = selinux_cred(file->f_cred)->sid;

	fsec->sid = sid;
	fsec->fowner_cred = NULL;

	return 0;
}

static int selinux_backing_file_alloc(struct file *backing_file,
				      const struct file *user_file)
{
	struct backing_file_security_struct *bfsec;
	const struct file_security_struct *ufsec = selinux_file(user_file);
	const struct selinux_label_view *view;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_pathless_projection *pathless;
#endif

	if (!ufsec->view || !user_file->f_cred)
		return -EACCES;
	view = selinux_label_view_get(ufsec->view);
	if (!view)
		return -EIO;
#ifdef CONFIG_SECURITY_SELINUX_NS
	pathless = selinux_pathless_projection_get(ufsec->pathless);
	if (pathless && pathless->view != view) {
		selinux_pathless_projection_put(pathless);
		selinux_label_view_put(view);
		return -ESTALE;
	}
#endif

	bfsec = selinux_backing_file(backing_file);
	bfsec->cred = get_cred(user_file->f_cred);
	bfsec->view = view;
#ifdef CONFIG_SECURITY_SELINUX_NS
	bfsec->pathless = pathless;
#endif

	return 0;
}

static void selinux_backing_file_free(struct file *backing_file)
{
	struct backing_file_security_struct *bfsec =
		selinux_backing_file(backing_file);

	put_cred(bfsec->cred);
	bfsec->cred = NULL;
#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_pathless_projection_put(bfsec->pathless);
	bfsec->pathless = NULL;
#endif
	selinux_label_view_put(bfsec->view);
	bfsec->view = NULL;
}

static void selinux_file_free_security(struct file *file)
{
	struct file_security_struct *fsec = selinux_file(file);

#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_pathless_projection_put(fsec->pathless);
	fsec->pathless = NULL;
#endif
	selinux_label_view_put(fsec->view);
	fsec->view = NULL;
	put_cred(fsec->fowner_cred);
	fsec->fowner_cred = NULL;
}

/*
 * Check whether a task has the ioctl permission and cmd
 * operation to an inode.
 */
static int ioctl_has_perm(const struct cred *cred, struct file *file,
		u32 requested, u16 cmd)
{
	struct common_audit_data ad;
	struct inode *inode = file_inode(file);
	struct lsm_ioctlop_audit ioctl;
	u8 driver = cmd >> 8;
	u8 xperm = cmd & 0xff;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct file_security_struct *fsec = selinux_file(file);
	const struct selinux_file_operation_check check = {
		.requested = requested,
		.decision_kind = SELINUX_AVC_DECISION_XPERM,
		.driver = driver,
		.base_perm = AVC_EXT_IOCTL,
		.xperm = xperm,
	};
#else
	struct inode_security_struct *isec;
	int rc;
#endif

	ad.type = LSM_AUDIT_DATA_IOCTL_OP;
	ad.u.op = &ioctl;
	ad.u.op->cmd = cmd;
	ad.u.op->path = file->f_path;

#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_file_operation_has_perm(
		cred, file, file->f_cred, inode, fsec->view, fsec->pathless,
		&check, false, &ad);
#else
	rc = file_use_has_perm(cred, file, &ad);
	if (rc || unlikely(IS_PRIVATE(inode)))
		return rc;
	isec = inode_security(inode);
	rc = cred_has_extended_perms(cred, isec->sid, isec->sclass,
				     requested, driver, AVC_EXT_IOCTL,
				     xperm, &ad);
	return rc;
#endif
}

static int ioctl_has_perm_cloexec(const struct cred *cred, struct file *file,
				  u16 cmd)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct file_security_struct *fsec = selinux_file(file);
	struct inode *inode = file_inode(file);
	const struct selinux_file_operation_check check = {
		.requested = FILE__IOCTL,
		.skip_policycap = POLICYDB_CAP_IOCTL_SKIP_CLOEXEC,
		.decision_kind = SELINUX_AVC_DECISION_XPERM,
		.driver = cmd >> 8,
		.base_perm = AVC_EXT_IOCTL,
		.xperm = cmd & 0xff,
	};
	struct common_audit_data ad;
	struct lsm_ioctlop_audit ioctl;

	ad.type = LSM_AUDIT_DATA_IOCTL_OP;
	ad.u.op = &ioctl;
	ad.u.op->cmd = cmd;
	ad.u.op->path = file->f_path;
	return selinux_file_operation_has_perm(
		cred, file, file->f_cred, inode, fsec->view, fsec->pathless,
		&check, false, &ad);
#else
	struct inode *inode = file_inode(file);
	struct inode_security_struct *isec;
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	struct common_audit_data ad;
	struct lsm_ioctlop_audit ioctl;
	unsigned int retry;
	bool same_cred;
	u8 driver = cmd >> 8;
	u8 xperm = cmd & 0xff;

	if (!file->f_cred)
		return -EIO;
	same_cred = cred_sid_chain_equal(cred, file->f_cred);
	ad.type = LSM_AUDIT_DATA_IOCTL_OP;
	ad.u.op = &ioctl;
	ad.u.op->cmd = cmd;
	ad.u.op->path = file->f_path;
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u32 tsid = 0;
		u16 sclass = 0;
		u16 i;
		int rc;
#ifdef CONFIG_SECURITY_SELINUX_NS
		struct selinux_label_resolution resolution;
		struct selinux_label_ref *label = NULL;
		const struct selinux_pathless_projection *projection =
			fsec->pathless;
#endif

		rc = selinux_policy_chain_snapshot_read(cred, chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;

		if (!IS_PRIVATE(inode)) {
			isec = inode_security(inode);
			spin_lock(&isec->lock);
			tsid = isec->sid;
			sclass = isec->sclass;
#ifdef CONFIG_SECURITY_SELINUX_NS
			if (!projection) {
				label = rcu_dereference_protected(
					isec->label_ref,
					lockdep_is_held(&isec->lock));
				label = selinux_label_ref_get(label);
			}
#endif
			spin_unlock(&isec->lock);
#ifdef CONFIG_SECURITY_SELINUX_NS
			if (projection) {
				if (fsec->view != projection->view) {
					rc = -EXDEV;
					goto out_label;
				}
			} else {
				if (!label)
					return -EIO;
				rc = selinux_label_view_resolve_chain(
					fsec->view, label, tsid, &resolution);
				if (rc)
					goto out_label;
			}
#endif
		}

		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&chain->policy[i];
			u32 policy_tsid = tsid;
			u16 policy_sclass = sclass;

			if (!same_cred) {
				u32 opener_sid;

				rc = selinux_cred_sid_for_state_checked(
					file->f_cred, crsec->state, &opener_sid);
				if (rc)
					break;

				rc = avc_has_perm_snapshot(
					crsec->state, snapshot, crsec->sid, opener_sid,
					SECCLASS_FD, FD__USE, &ad);
				if (rc)
					break;
			}
			if (selinux_policycap_ioctl_skip_cloexec(snapshot) ||
			    IS_PRIVATE(inode))
				continue;
#ifdef CONFIG_SECURITY_SELINUX_NS
			if (projection) {
				struct selinux_pathless_resolution resolved;

				rc = selinux_pathless_projection_resolve_sealed(
					projection, crsec->state->label_domain,
					&resolved);
				if (rc)
					break;
				policy_tsid = resolved.sid;
				policy_sclass = resolved.sclass;
			} else {
				u16 depth = crsec->state->label_domain->depth;

				if (depth > resolution.max_depth ||
				    resolution.domain_id[depth] !=
					    crsec->state->label_domain->id ||
				    !resolution.sid[depth]) {
					rc = -EOPNOTSUPP;
					break;
				}
				policy_tsid = resolution.sid[depth];
			}
#endif
			rc = avc_has_extended_perms_snapshot(
				crsec->state, snapshot, crsec->sid, policy_tsid,
				policy_sclass, FILE__IOCTL, driver, AVC_EXT_IOCTL,
				xperm, &ad);
			if (rc)
				break;
		}

#ifdef CONFIG_SECURITY_SELINUX_NS
out_label:
		selinux_label_ref_put(label);
#endif
		if (rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain))
			continue;
		return rc;
	}

	return -ESTALE;
#endif
}

static int selinux_file_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	const struct cred *cred = current_cred();
	int error = 0;

	switch (cmd) {
	case FIONREAD:
	case FIBMAP:
	case FIGETBSZ:
	case FS_IOC_GETFLAGS:
	case FS_IOC_GETVERSION:
		error = file_has_perm(cred, file, FILE__GETATTR);
		break;

	case FS_IOC_SETFLAGS:
	case FS_IOC_SETVERSION:
		error = file_has_perm(cred, file, FILE__SETATTR);
		break;

	/* sys_ioctl() checks */
	case FIONBIO:
	case FIOASYNC:
		error = file_has_perm(cred, file, 0);
		break;

	case KDSKBENT:
	case KDSKBSENT:
		error = cred_has_capability(cred, CAP_SYS_TTY_CONFIG,
					    CAP_OPT_NONE, true);
		break;

	case FIOCLEX:
	case FIONCLEX:
		error = ioctl_has_perm_cloexec(cred, file, (u16)cmd);
		break;

	/* default case assumes that the command will go
	 * to the file's ioctl() function.
	 */
	default:
		error = ioctl_has_perm(cred, file, FILE__IOCTL, (u16) cmd);
	}
	return error;
}

static int selinux_file_ioctl_compat(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	/*
	 * If we are in a 64-bit kernel running 32-bit userspace, we need to
	 * make sure we don't compare 32-bit flags to 64-bit flags.
	 */
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	case FS_IOC32_GETVERSION:
		cmd = FS_IOC_GETVERSION;
		break;
	case FS_IOC32_SETVERSION:
		cmd = FS_IOC_SETVERSION;
		break;
	default:
		break;
	}

	return selinux_file_ioctl(file, cmd, arg);
}

static int default_noexec __ro_after_init;

static int __file_map_prot_check(const struct file *file, unsigned long prot,
				 bool shared, bool mounter_check,
				 bool bf_user_file)
{
	struct inode *inode = NULL;
	bool prot_exec = prot & PROT_EXEC;
	bool prot_write = prot & PROT_WRITE;

	if (file) {
		if (bf_user_file)
			inode = d_inode(backing_file_user_path(file)->dentry);
		else
			inode = file_inode(file);
	}

	if (!mounter_check && default_noexec && prot_exec &&
	    (!file || IS_PRIVATE(inode) || (!shared && prot_write))) {
		int rc;
		const struct cred *cred = current_cred();

		/*
		 * We are making executable an anonymous mapping or a private
		 * file mapping that will also be writable.
		 */
		rc = cred_self_has_perm(cred, SECCLASS_PROCESS,
					PROCESS__EXECMEM, NULL);
		if (rc)
			return rc;
	}

	if (file) {
		const struct cred *cred = mounter_check ?
				file->f_cred : current_cred();
		/* "read" always possible, "write" only if shared */
		u32 av = FILE__READ;
		if (shared && prot_write)
			av |= FILE__WRITE;
		if (prot_exec)
			av |= FILE__EXECUTE;

		return __file_has_perm(cred, file, av, bf_user_file);
	}

	return 0;
}

static inline int file_map_prot_check(const struct file *file,
				      unsigned long prot, bool shared,
				      bool mounter_check)
{
	return __file_map_prot_check(file, prot, shared, mounter_check, false);
}

static int selinux_mmap_addr(unsigned long addr)
{
	int rc = 0;

	if (addr < CONFIG_LSM_MMAP_MIN_ADDR) {
		rc = cred_self_has_perm(current_cred(), SECCLASS_MEMPROTECT,
					MEMPROTECT__MMAP_ZERO, NULL);
	}

	return rc;
}

static int selinux_mmap_file_common(struct file *file, unsigned long prot,
				    bool shared, bool mounter_check)
{
	if (file) {
		int rc;
		const struct cred *cred = mounter_check ?
				file->f_cred : current_cred();

		rc = __file_has_perm(cred, file, FILE__MAP, false);
		if (rc)
			return rc;
	}

	return file_map_prot_check(file, prot, shared, mounter_check);
}

static int selinux_mmap_file(struct file *file,
			     unsigned long reqprot __always_unused,
			     unsigned long prot, unsigned long flags)
{
	return selinux_mmap_file_common(file, prot,
					(flags & MAP_TYPE) == MAP_SHARED,
					false);
}

/**
 * selinux_mmap_backing_file - Check mmap permissions on a backing file
 * @vma: memory region
 * @backing_file: stacked filesystem backing file
 * @user_file: user visible file
 *
 * This is called after selinux_mmap_file() on stacked filesystems, and it
 * is this function's responsibility to verify access to @backing_file and
 * setup the SELinux state for possible later use in the mprotect() code path.
 *
 * By the time this function is called, mmap() access to @user_file has already
 * been authorized and @vma->vm_file has been set to point to @backing_file.
 *
 * Return zero on success, negative values otherwise.
 */
static int selinux_mmap_backing_file(struct vm_area_struct *vma,
				     struct file *backing_file,
				     struct file *user_file __always_unused)
{
	unsigned long prot = 0;

	/* translate vma->vm_flags perms into PROT perms */
	if (vma->vm_flags & VM_READ)
		prot |= PROT_READ;
	if (vma->vm_flags & VM_WRITE)
		prot |= PROT_WRITE;
	if (vma->vm_flags & VM_EXEC)
		prot |= PROT_EXEC;

	return selinux_mmap_file_common(backing_file, prot,
					vma->vm_flags & VM_SHARED,
					true);
}

static int selinux_file_mprotect(struct vm_area_struct *vma,
				 unsigned long reqprot __always_unused,
				 unsigned long prot)
{
	int rc;
	const struct cred *cred = current_cred();
	const struct file *file = vma->vm_file;
	bool backing_file;
	bool shared = vma->vm_flags & VM_SHARED;

	/* check if we need to trigger the "backing files are awful" mode */
	backing_file = file && (file->f_mode & FMODE_BACKING);

	if (default_noexec &&
	    (prot & PROT_EXEC) && !(vma->vm_flags & VM_EXEC)) {
		/*
		 * We don't use the vma_is_initial_heap() helper as it has
		 * a history of problems and is currently broken on systems
		 * where there is no heap, e.g. brk == start_brk.  Before
		 * replacing the conditional below with vma_is_initial_heap(),
		 * or something similar, please ensure that the logic is the
		 * same as what we have below or you have tested every possible
		 * corner case you can think to test.
		 */
		if (vma->vm_start >= vma->vm_mm->start_brk &&
		    vma->vm_end <= vma->vm_mm->brk) {
			rc = cred_self_has_perm(cred, SECCLASS_PROCESS,
						PROCESS__EXECHEAP, NULL);
			if (rc)
				return rc;
		} else if (!file && (vma_is_initial_stack(vma) ||
			    vma_is_stack_for_current(vma))) {

			rc = cred_self_has_perm(cred, SECCLASS_PROCESS,
						PROCESS__EXECSTACK, NULL);
			if (rc)
				return rc;
		} else if (file && vma->anon_vma) {
			/*
			 * We are making executable a file mapping that has
			 * had some COW done. Since pages might have been
			 * written, check ability to execute the possibly
			 * modified content.  This typically should only
			 * occur for text relocations.
			 */
			rc = __file_has_perm(cred, file, FILE__EXECMOD,
					     backing_file);
			if (rc)
				return rc;
			if (backing_file) {
				rc = file_has_perm(file->f_cred, file,
						   FILE__EXECMOD);
				if (rc)
					return rc;
			}
		}
	}

	rc = __file_map_prot_check(file, prot, shared, false, backing_file);
	if (rc)
		return rc;
	if (backing_file) {
		rc = file_map_prot_check(file, prot, shared, true);
		if (rc)
			return rc;
	}

	return 0;
}

static int selinux_file_lock(struct file *file, unsigned int cmd)
{
	const struct cred *cred = current_cred();

	return file_has_perm(cred, file, FILE__LOCK);
}

static int selinux_file_fcntl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	const struct cred *cred = current_cred();
	int err = 0;

	switch (cmd) {
	case F_SETFL:
		if ((file->f_flags & O_APPEND) && !(arg & O_APPEND)) {
			err = file_has_perm(cred, file, FILE__WRITE);
			break;
		}
		fallthrough;
	case F_SETOWN:
	case F_SETSIG:
	case F_GETFL:
	case F_GETOWN:
	case F_GETSIG:
	case F_GETOWNER_UIDS:
		/* Just check FD__USE permission */
		err = file_has_perm(cred, file, 0);
		break;
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
	case F_OFD_GETLK:
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
#if BITS_PER_LONG == 32
	case F_GETLK64:
	case F_SETLK64:
	case F_SETLKW64:
#endif
		err = file_has_perm(cred, file, FILE__LOCK);
		break;
	}

	return err;
}

static void selinux_file_set_fowner(struct file *file)
{
	struct file_security_struct *fsec;
	const struct cred *old;

	fsec = selinux_file(file);
	/* The VFS holds file->f_owner->lock for write across this hook. */
	old = fsec->fowner_cred;
	fsec->fowner_cred = get_cred(current_cred());
	put_cred(old);
}

static int selinux_file_send_sigiotask(struct task_struct *tsk,
				       struct fown_struct *fown, int signum)
{
	struct file *file;
	u32 perm;
	struct file_security_struct *fsec;
	const struct cred *fowner_cred;

	/* struct fown_struct is never outside the context of a struct file */
	file = fown->file;

	fsec = selinux_file(file);
	/* The VFS holds fown->lock for read across this hook. */
	fowner_cred = fsec->fowner_cred;
	if (!fowner_cred)
		return -EIO;

	if (!signum)
		perm = signal_to_av(SIGIO); /* as per send_sigio_to_task */
	else
		perm = signal_to_av(signum);

	return cred_task_has_perm(fowner_cred, tsk, SECCLASS_PROCESS, perm,
				  NULL);
}

static int selinux_file_receive(struct file *file)
{
	const struct cred *cred = current_cred();

	return file_has_perm(cred, file, file_to_av(file));
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_pathless_file_open_has_perm(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection,
	const struct inode *inode, u32 av, struct common_audit_data *ad)
{
	return cred_pathless_has_perm_policycap(
		cred, projection, av,
		inode->i_sb->s_magic != SOCKFS_MAGIC ? FILE__OPEN : 0,
		POLICYDB_CAP_OPENPERM, ad);
}
#endif

static int selinux_file_open(struct file *file)
{
	struct file_security_struct *fsec = selinux_file(file);
	struct inode *inode = file_inode(file);
	struct inode_security_struct *isec = inode_security(inode);
	const struct cred *cred = file->f_cred;
#ifndef CONFIG_SECURITY_SELINUX_NS
	struct cred_security_struct *crsec;
	struct selinux_state *state;
#endif
	struct common_audit_data ad;
	u32 av;
#ifndef CONFIG_SECURITY_SELINUX_NS
	u32 tsid, ssid, requested;
	u16 sclass;
#endif
	int rc;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_inode_label_snapshot snapshot;
#endif

	rc = selinux_file_bind_view(file);
	if (rc)
		return rc;

	/*
	 * Save inode label and policy-chain generation
	 * at open-time so that selinux_file_permission
	 * can determine whether revalidation is necessary.
	 * Task label is already saved in the file security
	 * struct as its SID.
	 */
#ifndef CONFIG_SECURITY_SELINUX_NS
	fsec->isid = isec->sid;
#endif
	fsec->chain_epoch = selinux_chain_epoch_read(
		cred_selinux_state(file->f_cred));
	/*
	 * Since the inode label or policy seqno may have changed
	 * between the selinux_inode_permission check and the saving
	 * of state above, recheck that access is still permitted.
	 * Otherwise, access might never be revalidated against the
	 * new inode label or new policy.
	 * This check is not redundant - do not remove.
	 */
	/*
	 * The following is an inlined version of file_path_has_perm()->
	 * inode_has_perm()->cred_tsid_has_perm() in order to specialize
	 * the requested permissions based on the open_perms policycap
	 * value in each namespace.
	 */
	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;
	cred = file->f_cred;
	if (unlikely(IS_PRIVATE(inode))) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		fsec->isid = READ_ONCE(isec->sid);
#endif
		return 0;
	}
	av = file_to_av(file);
#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		const struct cred_security_struct *crsec = selinux_cred(cred);

		if (!selinux_initialized(crsec->state)) {
			fsec->isid = READ_ONCE(isec->sid);
			return selinux_cred_chain_uninitialized(cred) ? 0 : -EACCES;
		}
	}
	if (fsec->pathless) {
		fsec->isid = isec->sid;
		return selinux_pathless_file_open_has_perm(
			cred, fsec->pathless, inode, av, &ad);
	}
	if (!fsec->view)
		return -EOPNOTSUPP;
	rc = selinux_inode_label_snapshot_get(isec, &snapshot);
	if (rc)
		return rc;
	fsec->isid = snapshot.sid;
	rc = cred_label_has_perm_policycap(
		cred, snapshot.sid, snapshot.label, fsec->view, snapshot.sclass, av,
		inode->i_sb->s_magic != SOCKFS_MAGIC ? FILE__OPEN : 0,
		POLICYDB_CAP_OPENPERM, snapshot.source, &ad);
	selinux_inode_label_snapshot_put(&snapshot);
	return rc;
#else
	tsid = isec->sid;
	sclass = isec->sclass;
	do {
		crsec = selinux_cred(cred);
		ssid = crsec->sid;
		state = crsec->state;
		requested = av;

		if (selinux_policycap_openperm(state) &&
		    inode->i_sb->s_magic != SOCKFS_MAGIC)
			requested |= FILE__OPEN;

		rc = avc_has_perm(state, ssid, tsid, sclass, requested, &ad);
		if (rc)
			return rc;
		cred = crsec->parent_cred;
	} while (cred);

	return 0;
#endif
}

/* task security operations */

static int selinux_task_alloc(struct task_struct *task,
			      u64 clone_flags)
{
	const struct cred *cred = current_cred();
	struct task_security_struct *old_tsec = selinux_task(current);
	struct task_security_struct *new_tsec = selinux_task(task);
	int rc;

	*new_tsec = *old_tsec;
#ifdef CONFIG_SECURITY_SELINUX_NS
	/* A create transaction is synchronous and is never inherited by fork. */
	new_tsec->create_plan = NULL;
	new_tsec->setxattr_plan = NULL;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	new_tsec->create_plan_kunit_force = false;
#endif
#endif
	rc = cred_self_has_perm(cred, SECCLASS_PROCESS, PROCESS__FORK, NULL);
	return rc;
}

static void selinux_task_free(struct task_struct *task)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	WARN_ON_ONCE(selinux_task(task)->create_plan);
	WARN_ON_ONCE(selinux_task(task)->setxattr_plan);
#endif
}

/*
 * free/release any cred memory other than the blob itself
 */
static void selinux_cred_free(struct cred *cred)
{
	struct cred_security_struct *crsec = selinux_cred(cred);

#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_copy_up_carrier_put(crsec->copy_up);
	crsec->copy_up = NULL;
	selinux_cred_sid_handles_put(crsec);
#endif
	put_selinux_state(crsec->state);
	if (crsec->parent_cred)
		put_cred(crsec->parent_cred);
}

/*
 * prepare a new set of credentials for modification
 */
static int selinux_cred_prepare(struct cred *new, const struct cred *old,
				gfp_t gfp)
{
	const struct cred_security_struct *old_crsec = selinux_cred(old);
	struct cred_security_struct *crsec = selinux_cred(new);
	int rc;


	*crsec = *old_crsec;
#ifdef CONFIG_SECURITY_SELINUX_NS
	crsec->copy_up = NULL;
#endif
	crsec->state = get_selinux_state(old_crsec->state);
	if (old_crsec->parent_cred)
		crsec->parent_cred = get_cred(old_crsec->parent_cred);
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = selinux_cred_sid_handles_dup(crsec, old_crsec);
	return rc;
#else
	return 0;
#endif
}

/*
 * transfer the SELinux data to a blank set of creds
 */
static void selinux_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct cred_security_struct *old_crsec = selinux_cred(old);
	struct cred_security_struct *crsec = selinux_cred(new);

	*crsec = *old_crsec;
#ifdef CONFIG_SECURITY_SELINUX_NS
	crsec->copy_up = NULL;
#endif
	crsec->state = get_selinux_state(old_crsec->state);
	if (old_crsec->parent_cred)
		crsec->parent_cred = get_cred(old_crsec->parent_cred);
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (WARN_ON_ONCE(selinux_cred_sid_handles_dup(crsec, old_crsec)))
		selinux_cred_sid_handles_put(crsec);
#endif
}

static void selinux_cred_getsecid(const struct cred *c, u32 *secid)
{
	*secid = cred_sid(c);
}

static void selinux_cred_getlsmprop(const struct cred *c, struct lsm_prop *prop)
{
	prop->selinux.secid = cred_sid(c);
}

static int __maybe_unused selinux_kernel_act_as(struct cred *new,
							  u32 secid);
static int selinux_kernel_act_as_sid(struct cred *new, u32 secid);

static int selinux_prop_ref_publish(struct lsm_prop_ref *ref, u32 sid)
{
	struct selinux_prop_ref_security *rsec = selinux_prop_ref(ref);

	if (!sid)
		return -EOPNOTSUPP;
	rsec->sid = sid;
	ref->prop.selinux.secid = sid;
	return 0;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static const struct cred_security_struct *
selinux_prop_ref_cred_level(const struct cred *cred,
			    const struct selinux_state *state)
{
	while (cred) {
		const struct cred_security_struct *crsec = selinux_cred(cred);

		if (crsec->state == state)
			return crsec;
		cred = crsec->parent_cred;
	}
	return NULL;
}

static int selinux_prop_ref_handle_sid(
	const struct selinux_global_sid_handle *handle,
	const struct selinux_state *observer_state, u32 *sid)
{
	struct selinux_label_ref *label;
	int rc = 0;

	if (!handle || !observer_state || !observer_state->label_domain || !sid)
		return -EINVAL;
	*sid = global_sid_handle_sid(handle);
	if (!*sid)
		return -ESTALE;
	label = global_sid_handle_label_get(handle);
	if (!label)
		return -ESTALE;
	if (!(label->domain->flags & SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) &&
	    label->domain != observer_state->label_domain)
		rc = -EOPNOTSUPP;
	selinux_label_ref_put(label);
	return rc;
}

static struct selinux_global_sid_handle *
selinux_prop_ref_projection_handle(
	const struct selinux_pathless_projection *projection,
	const struct selinux_label_domain *domain, u32 *sid)
{
	const struct selinux_pathless_seal *seal;
	struct selinux_global_sid_handle *handle;
	u16 depth;

	if (!projection || !domain || !sid)
		return ERR_PTR(-EINVAL);
	depth = domain->depth;
	if (depth >= projection->seal_count)
		return ERR_PTR(-EOPNOTSUPP);
	seal = &projection->seals[depth];
	if (seal->domain_id != domain->id || !seal->sid ||
	    global_sid_handle_sid(seal->sid_handle) != seal->sid)
		return ERR_PTR(-EOPNOTSUPP);
	handle = global_sid_handle_dup(seal->sid_handle);
	if (IS_ERR(handle))
		return handle;
	*sid = seal->sid;
	return handle;
}

static int selinux_prop_ref_cred_has_perm(const struct cred *actor,
					  const struct cred *target)
{
	struct selinux_avc_level
		levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	const struct cred *target_level = target;
	u16 count = 0;

	while (actor) {
		const struct cred_security_struct *actor_sec = selinux_cred(actor);
		const struct cred_security_struct *target_sec = NULL;

		if (count >= ARRAY_SIZE(levels))
			return -E2BIG;
		while (target_level) {
			target_sec = selinux_cred(target_level);
			if (target_sec->state == actor_sec->state)
				break;
			target_level = target_sec->parent_cred;
		}
		if (!target_level || !target_sec->sid_handle ||
		    global_sid_handle_sid(target_sec->sid_handle) != target_sec->sid)
			return -EOPNOTSUPP;
		levels[count] = (struct selinux_avc_level) {
			.state = actor_sec->state,
			.ssid = actor_sec->sid,
			.tsid = target_sec->sid,
			.tclass = SECCLASS_KERNEL_SERVICE,
			.requested = KERNEL_SERVICE__USE_AS_OVERRIDE,
		};
		count++;
		actor = actor_sec->parent_cred;
		target_level = target_sec->parent_cred;
	}
	return selinux_avc_levels_has_perm(levels, count, NULL);
}

static int selinux_prop_ref_projection_has_perm(
	const struct cred *actor,
	const struct selinux_pathless_projection *projection)
{
	struct selinux_avc_level
		levels[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1] = {};
	u16 count = 0;

	while (actor) {
		const struct cred_security_struct *crsec = selinux_cred(actor);
		struct selinux_pathless_resolution resolved;
		int rc;

		if (count >= ARRAY_SIZE(levels))
			return -E2BIG;
		rc = selinux_pathless_projection_resolve_sealed(
			projection, crsec->state->label_domain, &resolved);
		if (rc)
			return rc;
		levels[count] = (struct selinux_avc_level) {
			.state = crsec->state,
			.ssid = crsec->sid,
			.tsid = resolved.sid,
			.tclass = SECCLASS_KERNEL_SERVICE,
			.requested = KERNEL_SERVICE__USE_AS_OVERRIDE,
		};
		count++;
		actor = crsec->parent_cred;
	}
	return selinux_avc_levels_has_perm(levels, count, NULL);
}
#endif

static int selinux_prop_ref_capture(struct lsm_prop_ref *ref,
				    const struct lsm_prop_ref_source *source,
				    gfp_t gfp)
{
	struct selinux_prop_ref_security *rsec = selinux_prop_ref(ref);
	u32 sid = SECSID_NULL;
	int rc;

	if (rsec->kind != SELINUX_PROP_REF_NONE)
		return -EEXIST;

#ifdef CONFIG_SECURITY_SELINUX_NS
	switch (source->kind) {
	case LSM_PROP_REF_CRED_SUBJ:
	case LSM_PROP_REF_CURRENT_SUBJ: {
		const struct cred_security_struct *crsec =
			selinux_cred(source->cred);

		if (!crsec->sid_handle ||
		    global_sid_handle_sid(crsec->sid_handle) != crsec->sid)
			return -ESTALE;
		rsec->cred = get_cred(source->cred);
		rsec->kind = SELINUX_PROP_REF_CRED;
		sid = crsec->sid;
		break;
	}
	case LSM_PROP_REF_TASK_OBJ: {
		const struct cred_security_struct *crsec;
		const struct cred *cred = get_task_cred(source->task);

		crsec = selinux_prop_ref_cred_level(cred,
						 current_selinux_state);
		if (!crsec || !crsec->sid_handle ||
		    global_sid_handle_sid(crsec->sid_handle) != crsec->sid) {
			put_cred(cred);
			return -EOPNOTSUPP;
		}
		rsec->cred = cred;
		rsec->kind = SELINUX_PROP_REF_CRED;
		sid = crsec->sid;
		break;
	}
	case LSM_PROP_REF_INODE_OBJ: {
		struct inode_security_struct *isec =
			inode_security_novalidate(source->inode);
		struct selinux_inode_label_snapshot snapshot;
		struct selinux_pathless_projection *projection;

		rc = selinux_inode_label_snapshot_get(isec, &snapshot);
		if (rc)
			return rc;
		sid = snapshot.sid;
		projection = selinux_inode_pathless_get(isec);
		if (projection) {
			if (projection->sid != sid ||
			    projection->sid_handle != snapshot.sid_handle ||
			    projection->label != snapshot.label ||
			    global_sid_handle_sid(projection->sid_handle) != sid) {
				selinux_pathless_projection_put(projection);
				selinux_inode_label_snapshot_put(&snapshot);
				return -ESTALE;
			}
			rsec->projection = projection;
			rsec->kind = SELINUX_PROP_REF_PATHLESS;
			selinux_inode_label_snapshot_put(&snapshot);
			break;
		}
		rsec->handle = snapshot.sid_handle;
		snapshot.sid_handle = NULL;
		rsec->kind = SELINUX_PROP_REF_HANDLE;
		selinux_inode_label_snapshot_put(&snapshot);
		break;
	}
	case LSM_PROP_REF_IPC_OBJ: {
		struct ipc_security_struct *isec = selinux_ipc(source->ipc);
		struct selinux_pathless_resolution resolved;
		struct selinux_pathless_projection *projection;

		projection = selinux_pathless_projection_get(
			READ_ONCE(isec->projection));
		if (!projection || projection->kind != SELINUX_PATHLESS_KIND_IPC) {
			selinux_pathless_projection_put(projection);
			return -EOPNOTSUPP;
		}
		rc = selinux_pathless_projection_resolve_sealed(
			projection, current_selinux_state->label_domain, &resolved);
		if (rc || resolved.sclass != isec->sclass) {
			selinux_pathless_projection_put(projection);
			return rc ?: -EOPNOTSUPP;
		}
		rsec->projection = projection;
		rsec->kind = SELINUX_PROP_REF_PATHLESS;
		sid = resolved.sid;
		break;
	}
	case LSM_PROP_REF_SECCTX:
		rsec->handle = security_context_to_global_handle(
			current_selinux_state, source->secctx.data,
			source->secctx.len, &sid, gfp);
		if (IS_ERR(rsec->handle)) {
			rc = PTR_ERR(rsec->handle);
			rsec->handle = NULL;
			if (source->lsmid == LSM_ID_UNDEF &&
			    (rc == -EINVAL || rc == -ENOENT))
				rc = -EOPNOTSUPP;
			return rc;
		}
		if (!rsec->handle)
			return -EOPNOTSUPP;
		rsec->kind = SELINUX_PROP_REF_HANDLE;
		break;
	case LSM_PROP_REF_SECID:
		rsec->handle = global_sid_handle_get(source->secid);
		if (IS_ERR(rsec->handle))
			return PTR_ERR(rsec->handle);
		sid = global_sid_handle_sid(rsec->handle);
		if (sid != source->secid) {
			global_sid_handle_put(rsec->handle);
			rsec->handle = NULL;
			return -ESTALE;
		}
		rsec->kind = SELINUX_PROP_REF_HANDLE;
		break;
	default:
		return -EINVAL;
	}
#else
	switch (source->kind) {
	case LSM_PROP_REF_CRED_SUBJ:
	case LSM_PROP_REF_CURRENT_SUBJ:
		sid = cred_sid(source->cred);
		break;
	case LSM_PROP_REF_TASK_OBJ:
		sid = task_sid_obj(source->task);
		break;
	case LSM_PROP_REF_INODE_OBJ:
		sid = inode_security_novalidate(source->inode)->sid;
		break;
	case LSM_PROP_REF_IPC_OBJ:
		sid = selinux_ipc(source->ipc)->sid;
		break;
	case LSM_PROP_REF_SECCTX:
		rc = security_context_to_sid(current_selinux_state,
					     source->secctx.data,
					     source->secctx.len, &sid, gfp);
		if (rc)
			return rc;
		break;
	case LSM_PROP_REF_SECID:
		sid = source->secid;
		break;
	default:
		return -EINVAL;
	}
	rsec->kind = SELINUX_PROP_REF_NUMERIC;
#endif
	rc = selinux_prop_ref_publish(ref, sid);
	if (!rc && (source->kind == LSM_PROP_REF_SECCTX ||
		    source->kind == LSM_PROP_REF_SECID))
		ref->source_secid = sid;
	if (rc) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		switch (rsec->kind) {
		case SELINUX_PROP_REF_CRED:
			put_cred(rsec->cred);
			break;
		case SELINUX_PROP_REF_HANDLE:
			global_sid_handle_put(rsec->handle);
			break;
		case SELINUX_PROP_REF_PATHLESS:
			selinux_pathless_projection_put(rsec->projection);
			break;
		default:
			break;
		}
#endif
		rsec->kind = SELINUX_PROP_REF_NONE;
		rsec->sid = SECSID_NULL;
	}
	return rc;
}

static void selinux_prop_ref_free(struct lsm_prop_ref *ref)
{
	struct selinux_prop_ref_security *rsec = selinux_prop_ref(ref);

#ifdef CONFIG_SECURITY_SELINUX_NS
	switch (rsec->kind) {
	case SELINUX_PROP_REF_CRED:
		put_cred(rsec->cred);
		break;
	case SELINUX_PROP_REF_HANDLE:
		global_sid_handle_put(rsec->handle);
		break;
	case SELINUX_PROP_REF_PATHLESS:
		selinux_pathless_projection_put(rsec->projection);
		break;
	default:
		break;
	}
#endif
	rsec->kind = SELINUX_PROP_REF_NONE;
	rsec->sid = SECSID_NULL;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_global_sid_handle *
selinux_prop_ref_handle_get(const struct lsm_prop_ref *ref, u32 *sid)
{
	const struct selinux_prop_ref_security *rsec;
	struct selinux_global_sid_handle *handle;

	if (!ref || !sid)
		return ERR_PTR(-EINVAL);
	if (ref->provider_count != 1)
		return ERR_PTR(-ENOTUNIQ);
	if (ref->source_lsmid != LSM_ID_SELINUX)
		return ERR_PTR(-EOPNOTSUPP);
	rsec = selinux_prop_ref(ref);
	if (rsec->kind != SELINUX_PROP_REF_HANDLE || !rsec->handle)
		return ERR_PTR(-EOPNOTSUPP);
	if (!rsec->sid || ref->prop.selinux.secid != rsec->sid)
		return ERR_PTR(-ESTALE);
	handle = global_sid_handle_dup(rsec->handle);
	if (IS_ERR(handle))
		return handle;
	*sid = global_sid_handle_sid(handle);
	if (*sid != rsec->sid) {
		global_sid_handle_put(handle);
		return ERR_PTR(-ESTALE);
	}
	return handle;
}
#endif

static int selinux_prop_ref_render_sid(struct selinux_state *state, u32 sid,
				       struct lsm_context *cp)
{
	const char *ctx;
	int rc;

	rcu_read_lock();
	cp->id = LSM_ID_SELINUX;
	rc = security_sid_to_context_valid(state, sid, &ctx, &cp->len);
	if (!rc)
		cp->context = kmemdup(ctx, cp->len, GFP_ATOMIC);
	rcu_read_unlock();
	if (rc)
		return rc;
	if (!cp->context)
		return -ENOMEM;
	return cp->len;
}

static int selinux_prop_ref_to_secctx(const struct lsm_prop_ref *ref,
				      const struct cred *observer,
				      struct lsm_context *cp)
{
	const struct selinux_prop_ref_security *rsec = selinux_prop_ref(ref);
	struct selinux_state *state = cred_selinux_state(observer);
	u32 sid;
#ifdef CONFIG_SECURITY_SELINUX_NS
	int rc;
#endif

	if (ref->prop.selinux.secid != rsec->sid ||
	    rsec->kind == SELINUX_PROP_REF_NONE)
		return -ESTALE;
#ifdef CONFIG_SECURITY_SELINUX_NS
	switch (rsec->kind) {
	case SELINUX_PROP_REF_CRED: {
		const struct cred_security_struct *crsec =
			selinux_prop_ref_cred_level(rsec->cred, state);

		if (!crsec || !crsec->sid_handle ||
		    global_sid_handle_sid(crsec->sid_handle) != crsec->sid)
			return -EOPNOTSUPP;
		sid = crsec->sid;
		break;
	}
	case SELINUX_PROP_REF_HANDLE:
		rc = selinux_prop_ref_handle_sid(rsec->handle, state, &sid);
		if (rc)
			return rc;
		break;
	case SELINUX_PROP_REF_PATHLESS: {
		struct selinux_pathless_resolution resolved;

		rc = selinux_pathless_projection_resolve_sealed(
			rsec->projection, state->label_domain, &resolved);
		if (rc)
			return rc;
		sid = resolved.sid;
		break;
	}
	default:
		return -EOPNOTSUPP;
	}
#else
	if (rsec->kind != SELINUX_PROP_REF_NUMERIC)
		return -EOPNOTSUPP;
	sid = rsec->sid;
#endif
	return selinux_prop_ref_render_sid(state, sid, cp);
}

static int selinux_kernel_act_as_ref(struct cred *new,
				     const struct lsm_prop_ref *ref)
{
	const struct selinux_prop_ref_security *rsec = selinux_prop_ref(ref);
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct cred_security_struct *newsec = selinux_cred(new);
	struct selinux_global_sid_handle *handle;
	u32 sid;
	int rc;
#endif

	if (ref->prop.selinux.secid != rsec->sid ||
	    rsec->kind == SELINUX_PROP_REF_NONE)
		return -ESTALE;
#ifdef CONFIG_SECURITY_SELINUX_NS
	switch (rsec->kind) {
	case SELINUX_PROP_REF_CRED: {
		const struct cred_security_struct *target =
			selinux_prop_ref_cred_level(rsec->cred, newsec->state);

		if (!target || !target->sid_handle ||
		    global_sid_handle_sid(target->sid_handle) != target->sid)
			return -EOPNOTSUPP;
		handle = global_sid_handle_dup(target->sid_handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
		sid = target->sid;
		rc = selinux_prop_ref_cred_has_perm(current_cred(), rsec->cred);
		break;
	}
	case SELINUX_PROP_REF_HANDLE:
		rc = selinux_prop_ref_handle_sid(rsec->handle, newsec->state, &sid);
		if (rc)
			return rc;
		handle = global_sid_handle_dup(rsec->handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
		rc = cred_sid_identity_has_perm(
			current_cred(), sid, SECCLASS_KERNEL_SERVICE,
			KERNEL_SERVICE__USE_AS_OVERRIDE, NULL);
		break;
	case SELINUX_PROP_REF_PATHLESS:
		handle = selinux_prop_ref_projection_handle(
			rsec->projection, newsec->state->label_domain, &sid);
		if (IS_ERR(handle))
			return PTR_ERR(handle);
		rc = selinux_prop_ref_projection_has_perm(current_cred(),
							 rsec->projection);
		break;
	default:
		return -EOPNOTSUPP;
	}
	if (rc) {
		global_sid_handle_put(handle);
		return rc;
	}
	if (global_sid_handle_sid(handle) != sid) {
		global_sid_handle_put(handle);
		return -ESTALE;
	}
	rc = selinux_cred_sid_take_handle(newsec, SELINUX_CRED_SID, handle);
	if (rc)
		return rc;
	/* Clearing a slot does not allocate and therefore cannot fail. */
	WARN_ON_ONCE(selinux_cred_sid_take_handle(
		newsec, SELINUX_CRED_CREATE_SID, NULL));
	WARN_ON_ONCE(selinux_cred_sid_take_handle(
		newsec, SELINUX_CRED_KEYCREATE_SID, NULL));
	WARN_ON_ONCE(selinux_cred_sid_take_handle(
		newsec, SELINUX_CRED_SOCKCREATE_SID, NULL));
	return 0;
#else
	return selinux_kernel_act_as_sid(new, rsec->sid);
#endif
}

/*
 * set the security data for a kernel service
 * - all the creation contexts are set to unlabelled
 */
static int selinux_kernel_act_as_sid(struct cred *new, u32 secid)
{
	struct cred_security_struct *crsec = selinux_cred(new);
	int ret;

	ret = cred_tsid_has_perm(current_cred(), secid, SECCLASS_KERNEL_SERVICE,
				 KERNEL_SERVICE__USE_AS_OVERRIDE, NULL);
	if (ret == 0) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		ret = selinux_cred_sid_set(crsec, SELINUX_CRED_SID, secid);
		if (ret)
			return ret;
		ret = selinux_cred_sid_set(crsec, SELINUX_CRED_CREATE_SID, 0);
		if (ret)
			return ret;
		ret = selinux_cred_sid_set(crsec, SELINUX_CRED_KEYCREATE_SID, 0);
		if (ret)
			return ret;
		ret = selinux_cred_sid_set(crsec, SELINUX_CRED_SOCKCREATE_SID, 0);
#else
		crsec->sid = secid;
		crsec->create_sid = 0;
		crsec->keycreate_sid = 0;
		crsec->sockcreate_sid = 0;
#endif
	}
	return ret;
}

static int __maybe_unused selinux_kernel_act_as(struct cred *new,
							  u32 secid)
{
	return selinux_kernel_act_as_sid(new, secid);
}

/*
 * set the file creation context in a security record to the same as the
 * objective context of the specified inode
 */
static int selinux_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	struct inode_security_struct *isec = inode_security(inode);
	struct cred_security_struct *crsec = selinux_cred(new);
	int ret;

#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct cred_security_struct *actor = selinux_cred(current_cred());
	const struct selinux_label_view *view;
	struct selinux_label_domain *origin;
	struct selinux_global_sid_handle *create_handle;
	struct selinux_inode_label_snapshot snapshot;
	u32 create_sid;

	ret = selinux_inode_label_snapshot_get(isec, &snapshot);
	if (ret)
		return ret;
	if (!actor->state || !actor->state->label_domain ||
	    crsec->state != actor->state) {
		ret = -EXDEV;
		goto out_snapshot;
	}
	origin = snapshot.label->domain->flags &
			 SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL ?
		 actor->state->label_domain : snapshot.label->domain;
	view = selinux_identity_view_alloc_gfp(
		actor->state->label_domain->owner_userns, origin,
		actor->state->label_domain, GFP_KERNEL);
	if (IS_ERR(view)) {
		ret = PTR_ERR(view);
		goto out_snapshot;
	}
	ret = cred_label_has_perm_policycap(
		current_cred(), snapshot.sid, snapshot.label, view,
		SECCLASS_KERNEL_SERVICE, KERNEL_SERVICE__CREATE_FILES_AS,
		0, 0, snapshot.source, NULL);
	if (ret)
		goto out_view;
	ret = selinux_label_view_resolve(
		view, crsec->state->label_domain, snapshot.label, snapshot.sid,
		&create_sid);
	if (ret)
		goto out_view;
	create_handle = global_sid_handle_get(create_sid);
	if (IS_ERR(create_handle)) {
		ret = PTR_ERR(create_handle);
		goto out_view;
	}
	ret = selinux_cred_sid_take_handle(
		crsec, SELINUX_CRED_CREATE_SID, create_handle);
out_view:
	selinux_label_view_put(view);
out_snapshot:
	selinux_inode_label_snapshot_put(&snapshot);
	return ret;
#else
	ret = cred_tsid_has_perm(current_cred(), isec->sid,
				SECCLASS_KERNEL_SERVICE,
				KERNEL_SERVICE__CREATE_FILES_AS,
				NULL);
	if (ret == 0) {
		crsec->create_sid = isec->sid;
	}
	return ret;
#endif
}

static int selinux_kernel_module_request(char *kmod_name)
{
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_KMOD;
	ad.u.kmod_name = kmod_name;

	return cred_tsid_has_perm(current_cred(), SECINITSID_KERNEL,
				  SECCLASS_SYSTEM, SYSTEM__MODULE_REQUEST, &ad);
}

static int selinux_kernel_load_from_file(struct file *file, u32 requested)
{
	struct common_audit_data ad;
	const struct cred *cred = current_cred();
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct selinux_file_operation_check check = {
		.requested = requested,
		.tclass = SECCLASS_SYSTEM,
	};
#else
	struct inode_security_struct *isec;
	int rc;
#endif

	if (file == NULL)
		return cred_self_has_perm(cred, SECCLASS_SYSTEM, requested,
					  NULL);

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;

#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct file_security_struct *fsec = selinux_file(file);

	return selinux_file_operation_has_perm(
		cred, file, file->f_cred, file_inode(file), fsec->view,
		fsec->pathless, &check, false, &ad);
#else
	rc = file_use_has_perm(cred, file, &ad);
	if (rc)
		return rc;
	isec = inode_security(file_inode(file));
	return cred_tsid_has_perm(cred, isec->sid, SECCLASS_SYSTEM, requested,
				  &ad);
#endif
}

static int selinux_kernel_read_file(struct file *file,
				    enum kernel_read_file_id id,
				    bool contents)
{
	int rc = 0;

	BUILD_BUG_ON_MSG(READING_MAX_ID > 8,
			 "New kernel_read_file_id introduced; update SELinux!");

	switch (id) {
	case READING_FIRMWARE:
		rc = selinux_kernel_load_from_file(file, SYSTEM__FIRMWARE_LOAD);
		break;
	case READING_MODULE:
	case READING_MODULE_COMPRESSED:
		rc = selinux_kernel_load_from_file(file, SYSTEM__MODULE_LOAD);
		break;
	case READING_KEXEC_IMAGE:
		rc = selinux_kernel_load_from_file(file,
						   SYSTEM__KEXEC_IMAGE_LOAD);
		break;
	case READING_KEXEC_INITRAMFS:
		rc = selinux_kernel_load_from_file(file,
						SYSTEM__KEXEC_INITRAMFS_LOAD);
		break;
	case READING_POLICY:
		rc = selinux_kernel_load_from_file(file, SYSTEM__POLICY_LOAD);
		break;
	case READING_X509_CERTIFICATE:
		rc = selinux_kernel_load_from_file(file,
						SYSTEM__X509_CERTIFICATE_LOAD);
		break;
	default:
		break;
	}

	return rc;
}

static int selinux_kernel_load_data(enum kernel_load_data_id id, bool contents)
{
	int rc = 0;

	BUILD_BUG_ON_MSG(LOADING_MAX_ID > 8,
			 "New kernel_load_data_id introduced; update SELinux!");

	switch (id) {
	case LOADING_FIRMWARE:
		rc = selinux_kernel_load_from_file(NULL, SYSTEM__FIRMWARE_LOAD);
		break;
	case LOADING_MODULE:
		rc = selinux_kernel_load_from_file(NULL, SYSTEM__MODULE_LOAD);
		break;
	case LOADING_KEXEC_IMAGE:
		rc = selinux_kernel_load_from_file(NULL,
						   SYSTEM__KEXEC_IMAGE_LOAD);
		break;
	case LOADING_KEXEC_INITRAMFS:
		rc = selinux_kernel_load_from_file(NULL,
						SYSTEM__KEXEC_INITRAMFS_LOAD);
		break;
	case LOADING_POLICY:
		rc = selinux_kernel_load_from_file(NULL,
						   SYSTEM__POLICY_LOAD);
		break;
	case LOADING_X509_CERTIFICATE:
		rc = selinux_kernel_load_from_file(NULL,
						SYSTEM__X509_CERTIFICATE_LOAD);
		break;
	default:
		break;
	}

	return rc;
}

static int selinux_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return cred_task_has_perm(current_cred(), p, SECCLASS_PROCESS,
				  PROCESS__SETPGID, NULL);
}

static int selinux_task_getpgid(struct task_struct *p)
{
	return cred_task_has_perm(current_cred(), p, SECCLASS_PROCESS,
				  PROCESS__GETPGID, NULL);
}

static int selinux_task_getsid(struct task_struct *p)
{
	return cred_task_has_perm(current_cred(), p, SECCLASS_PROCESS,
				  PROCESS__GETSESSION, NULL);
}

static void selinux_current_getlsmprop_subj(struct lsm_prop *prop)
{
	prop->selinux.secid = current_sid();
}

static void selinux_task_getlsmprop_obj(struct task_struct *p,
					struct lsm_prop *prop)
{
	prop->selinux.secid = task_sid_obj(p);
}

static int selinux_task_setnice(struct task_struct *p, int nice)
{
	return cred_task_has_perm(current_cred(), p, SECCLASS_PROCESS,
				  PROCESS__SETSCHED, NULL);
}

static int selinux_task_setioprio(struct task_struct *p, int ioprio)
{
	return cred_task_has_perm(current_cred(), p, SECCLASS_PROCESS,
				  PROCESS__SETSCHED, NULL);
}

static int selinux_task_getioprio(struct task_struct *p)
{
	return cred_task_has_perm(current_cred(), p, SECCLASS_PROCESS,
				  PROCESS__GETSCHED, NULL);
}

static int selinux_task_prlimit(const struct cred *cred, const struct cred *tcred,
				unsigned int flags)
{
	u32 av = 0;

	if (!flags)
		return 0;
	if (flags & LSM_PRLIMIT_WRITE)
		av |= PROCESS__SETRLIMIT;
	if (flags & LSM_PRLIMIT_READ)
		av |= PROCESS__GETRLIMIT;
	return cred_other_has_perm(cred, tcred, SECCLASS_PROCESS, av, NULL);
}

static int selinux_task_setrlimit(struct task_struct *p, unsigned int resource,
		struct rlimit *new_rlim)
{
	struct rlimit *old_rlim = p->signal->rlim + resource;

	/* Control the ability to change the hard limit (whether
	   lowering or raising it), so that the hard limit can
	   later be used as a safe reset point for the soft limit
	   upon context transitions.  See selinux_bprm_committing_creds. */
	if (old_rlim->rlim_max != new_rlim->rlim_max)
		return cred_task_has_perm(current_cred(), p, SECCLASS_PROCESS,
					  PROCESS__SETRLIMIT, NULL);

	return 0;
}

static int selinux_task_setscheduler(struct task_struct *p)
{
	return cred_task_has_perm(current_cred(), p, SECCLASS_PROCESS,
				  PROCESS__SETSCHED, NULL);
}

static int selinux_task_getscheduler(struct task_struct *p)
{
	return cred_task_has_perm(current_cred(), p, SECCLASS_PROCESS,
				  PROCESS__GETSCHED, NULL);
}

static int selinux_task_movememory(struct task_struct *p)
{
	return cred_task_has_perm(current_cred(), p, SECCLASS_PROCESS,
				  PROCESS__SETSCHED, NULL);
}

static int selinux_task_kill(struct task_struct *p, struct kernel_siginfo *info,
				int sig, const struct cred *cred)
{
	u32 perm;

	if (!cred)
		cred = current_cred();

	if (!sig)
		perm = PROCESS__SIGNULL; /* null signal; existence test */
	else
		perm = signal_to_av(sig);
	return cred_task_has_perm(cred, p, SECCLASS_PROCESS, perm, NULL);
}

static void selinux_task_to_inode(struct task_struct *p,
				  struct inode *inode)
{
	struct inode_security_struct *isec = selinux_inode(inode);
	u32 sid = task_sid_obj(p);

	WARN_ON_ONCE(inode_security_set_sid_class(
		isec, sid, inode_mode_to_security_class(inode->i_mode),
		SELINUX_LABEL_SOURCE_TASK, LABEL_INITIALIZED));
}

static int selinux_userns_create(const struct cred *cred)
{
	return cred_self_has_perm(current_cred(), SECCLASS_USER_NAMESPACE,
				  USER_NAMESPACE__CREATE, NULL);
}

/* Returns error only if unable to parse addresses */
static int selinux_parse_skb_ipv4(struct sk_buff *skb,
			struct common_audit_data *ad, u8 *proto)
{
	int offset, ihlen, ret = -EINVAL;
	struct iphdr _iph, *ih;

	offset = skb_network_offset(skb);
	ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph);
	if (ih == NULL)
		goto out;

	ihlen = ih->ihl * 4;
	if (ihlen < sizeof(_iph))
		goto out;

	ad->u.net->v4info.saddr = ih->saddr;
	ad->u.net->v4info.daddr = ih->daddr;
	ret = 0;

	if (proto)
		*proto = ih->protocol;

	switch (ih->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr _tcph, *th;

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		offset += ihlen;
		th = skb_header_pointer(skb, offset, sizeof(_tcph), &_tcph);
		if (th == NULL)
			break;

		ad->u.net->sport = th->source;
		ad->u.net->dport = th->dest;
		break;
	}

	case IPPROTO_UDP: {
		struct udphdr _udph, *uh;

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		offset += ihlen;
		uh = skb_header_pointer(skb, offset, sizeof(_udph), &_udph);
		if (uh == NULL)
			break;

		ad->u.net->sport = uh->source;
		ad->u.net->dport = uh->dest;
		break;
	}

#if IS_ENABLED(CONFIG_IP_SCTP)
	case IPPROTO_SCTP: {
		struct sctphdr _sctph, *sh;

		if (ntohs(ih->frag_off) & IP_OFFSET)
			break;

		offset += ihlen;
		sh = skb_header_pointer(skb, offset, sizeof(_sctph), &_sctph);
		if (sh == NULL)
			break;

		ad->u.net->sport = sh->source;
		ad->u.net->dport = sh->dest;
		break;
	}
#endif
	default:
		break;
	}
out:
	return ret;
}

#if IS_ENABLED(CONFIG_IPV6)

/* Returns error only if unable to parse addresses */
static int selinux_parse_skb_ipv6(struct sk_buff *skb,
			struct common_audit_data *ad, u8 *proto)
{
	u8 nexthdr;
	int ret = -EINVAL, offset;
	struct ipv6hdr _ipv6h, *ip6;
	__be16 frag_off;

	offset = skb_network_offset(skb);
	ip6 = skb_header_pointer(skb, offset, sizeof(_ipv6h), &_ipv6h);
	if (ip6 == NULL)
		goto out;

	ad->u.net->v6info.saddr = ip6->saddr;
	ad->u.net->v6info.daddr = ip6->daddr;
	ret = 0;

	nexthdr = ip6->nexthdr;
	offset += sizeof(_ipv6h);
	offset = ipv6_skip_exthdr(skb, offset, &nexthdr, &frag_off);
	if (offset < 0)
		goto out;

	if (proto)
		*proto = nexthdr;

	switch (nexthdr) {
	case IPPROTO_TCP: {
		struct tcphdr _tcph, *th;

		th = skb_header_pointer(skb, offset, sizeof(_tcph), &_tcph);
		if (th == NULL)
			break;

		ad->u.net->sport = th->source;
		ad->u.net->dport = th->dest;
		break;
	}

	case IPPROTO_UDP: {
		struct udphdr _udph, *uh;

		uh = skb_header_pointer(skb, offset, sizeof(_udph), &_udph);
		if (uh == NULL)
			break;

		ad->u.net->sport = uh->source;
		ad->u.net->dport = uh->dest;
		break;
	}

#if IS_ENABLED(CONFIG_IP_SCTP)
	case IPPROTO_SCTP: {
		struct sctphdr _sctph, *sh;

		sh = skb_header_pointer(skb, offset, sizeof(_sctph), &_sctph);
		if (sh == NULL)
			break;

		ad->u.net->sport = sh->source;
		ad->u.net->dport = sh->dest;
		break;
	}
#endif
	/* includes fragments */
	default:
		break;
	}
out:
	return ret;
}

#endif /* IPV6 */

static int selinux_parse_skb(struct sk_buff *skb, struct common_audit_data *ad,
			     char **_addrp, int src, u8 *proto)
{
	char *addrp;
	int ret;

	switch (ad->u.net->family) {
	case PF_INET:
		ret = selinux_parse_skb_ipv4(skb, ad, proto);
		if (ret)
			goto parse_error;
		addrp = (char *)(src ? &ad->u.net->v4info.saddr :
				       &ad->u.net->v4info.daddr);
		goto okay;

#if IS_ENABLED(CONFIG_IPV6)
	case PF_INET6:
		ret = selinux_parse_skb_ipv6(skb, ad, proto);
		if (ret)
			goto parse_error;
		addrp = (char *)(src ? &ad->u.net->v6info.saddr :
				       &ad->u.net->v6info.daddr);
		goto okay;
#endif	/* IPV6 */
	default:
		addrp = NULL;
		goto okay;
	}

parse_error:
	pr_warn(
	       "SELinux: failure in selinux_parse_skb(),"
	       " unable to parse packet\n");
	return ret;

okay:
	if (_addrp)
		*_addrp = addrp;
	return 0;
}

struct selinux_peer_sources {
	struct selinux_netlbl_source netlabel;
	struct selinux_net_provenance *xfrm;
};

static void selinux_peer_sources_init(struct selinux_peer_sources *sources)
{
	selinux_netlbl_source_init(&sources->netlabel);
	sources->xfrm = NULL;
}

static void selinux_peer_sources_put(struct selinux_peer_sources *sources)
{
	selinux_netlbl_source_put(&sources->netlabel);
	selinux_net_provenance_put(sources->xfrm);
	selinux_peer_sources_init(sources);
}

/*
 * Capture the packet's native immutable label carriers exactly once.  The
 * NetLabel cache owns a normalized copy of the wire attributes and XFRM owns
 * the canonical assertion/view pair; neither result is a policy-local SID.
 */
static int __selinux_peer_sources_capture(
	struct sk_buff *skb, u16 family, struct selinux_state *state,
	const struct selinux_label_view *view,
	struct selinux_peer_sources *sources, bool allow_egress_xfrm)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *seed_handle;
#endif
	int err;
	u32 seed_sid;

	selinux_peer_sources_init(sources);
#ifdef CONFIG_SECURITY_SELINUX_NS
	seed_handle = selinux_netlbl_skbuff_get_source_view_handle(
		skb, family, state, view, &sources->netlabel, &seed_sid);
	err = IS_ERR(seed_handle) ? PTR_ERR(seed_handle) : 0;
	if (!IS_ERR(seed_handle))
		global_sid_handle_put(seed_handle);
#else
	err = selinux_netlbl_skbuff_get_source_view(
		skb, family, state, view, &sources->netlabel, &seed_sid);
#endif
	if (unlikely(err))
		goto fail;
	if (allow_egress_xfrm)
		err = selinux_xfrm_skb_provenance_egress(skb, &sources->xfrm);
	else
		err = selinux_xfrm_skb_provenance_ingress(skb, &sources->xfrm);
	if (unlikely(err))
		goto fail;
	return 0;

fail:
	selinux_peer_sources_put(sources);
	return err;
}

static int selinux_peer_sources_capture(struct sk_buff *skb, u16 family,
					struct selinux_state *state,
					const struct selinux_label_view *view,
					struct selinux_peer_sources *sources)
{
	return __selinux_peer_sources_capture(skb, family, state, view, sources,
					      false);
}

#if defined(CONFIG_SECURITY_SELINUX_NS) && defined(CONFIG_NETFILTER)
/*
 * A SYN-ACK has no request_sock carrier at POSTROUTE.  Its only usable peer
 * assertion may therefore be the selected egress SA; unlike RX/forwarding,
 * this narrow path is allowed to consult skb_dst()->xfrm.
 */
static int selinux_peer_sources_capture_postroute(
	struct sk_buff *skb, u16 family, struct selinux_state *state,
	const struct selinux_label_view *view,
	struct selinux_peer_sources *sources)
{
	return __selinux_peer_sources_capture(skb, family, state, view, sources,
					      true);
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
static struct selinux_global_sid_handle *
selinux_peer_sources_sid_handle(
	const struct selinux_peer_sources *sources, struct selinux_state *state,
	u32 *peer_sid)
{
	struct selinux_global_sid_handle *nlbl_handle;
	struct selinux_global_sid_handle *peer_handle;
	u32 xfrm_sid = SECSID_NULL;
	u32 nlbl_sid;
	int err;

	nlbl_handle = selinux_netlbl_source_sid_handle(
		state, &sources->netlabel, &nlbl_sid);
	if (IS_ERR(nlbl_handle))
		return nlbl_handle;
	if (sources->xfrm) {
		const struct selinux_net_provenance *provenance = sources->xfrm;

		if (!provenance->subject || !provenance->subject->label ||
		    !provenance->view) {
			peer_handle = ERR_PTR(-EACCES);
			goto out_nlbl;
		}
		err = selinux_label_view_resolve(
			provenance->view, state->label_domain,
			provenance->subject->label, provenance->subject->sid,
			&xfrm_sid);
		if (err) {
			peer_handle = ERR_PTR(err);
			goto out_nlbl;
		}
	}
	peer_handle = security_net_peersid_resolve_handle(
		state, nlbl_sid, sources->netlabel.type, xfrm_sid, peer_sid);
	if (IS_ERR(peer_handle))
		pr_warn_ratelimited(
			"SELinux: unable to determine packet peer label\n");
out_nlbl:
	global_sid_handle_put(nlbl_handle);
	return peer_handle;
}
#else
static int selinux_peer_sources_resolve(
	const struct selinux_peer_sources *sources, struct selinux_state *state,
	u32 *netlabel_sid, u32 *xfrm_sid_out, u32 *peer_sid)
{
	u32 xfrm_sid = SECSID_NULL;
	u32 nlbl_sid;
	int err;

	err = selinux_netlbl_source_sid(
		state, &sources->netlabel, &nlbl_sid);
	if (unlikely(err))
		return err;
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (sources->xfrm) {
		const struct selinux_net_provenance *provenance = sources->xfrm;

		if (!provenance->subject || !provenance->subject->label ||
		    !provenance->view)
			return -EACCES;
		err = selinux_label_view_resolve(
			provenance->view, state->label_domain,
			provenance->subject->label, provenance->subject->sid,
			&xfrm_sid);
		if (unlikely(err))
			return err;
	}
#else
	if (sources->xfrm)
		xfrm_sid = sources->xfrm->subject->sid;
#endif

	if (peer_sid) {
		err = security_net_peersid_resolve(state, nlbl_sid,
						   sources->netlabel.type,
						   xfrm_sid, peer_sid);
		if (unlikely(err)) {
			pr_warn_ratelimited(
			       "SELinux: failure in selinux_peer_sources_sid(),"
			       " unable to determine packet's peer label\n");
			return err;
		}
	}
	if (netlabel_sid)
		*netlabel_sid = nlbl_sid;
	if (xfrm_sid_out)
		*xfrm_sid_out = xfrm_sid;

	return 0;
}

static int selinux_peer_sources_sid(
	const struct selinux_peer_sources *sources, struct selinux_state *state,
	u32 *sid)
{
	return selinux_peer_sources_resolve(sources, state, NULL, NULL, sid);
}

/**
 * selinux_skb_peerlbl_sid - Determine the peer label of a packet
 * @skb: the packet
 * @family: protocol family
 * @state: the SELinux state
 * @sid: the packet's peer label SID
 *
 * Capture each native labeling source and resolve it independently in
 * @state.  Callers which evaluate a policy chain should retain the source
 * bundle and call selinux_peer_sources_sid() once per policy instead.
 */
static int selinux_skb_peerlbl_sid(struct sk_buff *skb, u16 family,
				   struct selinux_state *state, u32 *sid)
{
	struct selinux_peer_sources sources;
	int err;

	err = selinux_peer_sources_capture(skb, family, state, NULL, &sources);
	if (!err)
		err = selinux_peer_sources_sid(&sources, state, sid);
	selinux_peer_sources_put(&sources);
	return err;
}
#endif

/*
 * Determine the child socket label for a connection.
 * @sk_sid: the parent socket's SID
 * @skb_sid: the packet's SID
 * @state: the SELinux state
 * @conn_sid: the resulting connection SID
 *
 * If @skb_sid is valid then the user:role:type information from @sk_sid is
 * combined with the MLS information from @skb_sid in order to create
 * @conn_sid.  If @skb_sid is not valid then @conn_sid is simply a copy
 * of @sk_sid.  Returns zero on success, negative values on failure.
 *
 */
#ifdef CONFIG_SECURITY_SELINUX_NS
static struct selinux_global_sid_handle *
selinux_conn_sid_handle(u32 sk_sid, u32 skb_sid,
			struct selinux_state *state, u32 *conn_sid)
{
	if (skb_sid != SECSID_NULL)
		return security_sid_mls_copy_handle(state, sk_sid, skb_sid,
					    conn_sid);

	*conn_sid = sk_sid;
	return global_sid_handle_get(sk_sid);
}
#else
static int selinux_conn_sid(u32 sk_sid, u32 skb_sid,
			    struct selinux_state *state, u32 *conn_sid)
{
	int err = 0;

	if (skb_sid != SECSID_NULL)
		err = security_sid_mls_copy(state, sk_sid, skb_sid, conn_sid);
	else
		*conn_sid = sk_sid;

	return err;
}
#endif

/* socket security operations */

#ifdef CONFIG_SECURITY_SELINUX_NS
static struct selinux_net_provenance *
selinux_net_provenance_create_view(
	struct selinux_state *state, const struct selinux_label_view *source_view,
	u32 sid, u16 sclass, enum selinux_net_assertion_source source, gfp_t gfp)
{
	struct selinux_net_provenance *provenance;
	struct selinux_net_assertion *assertion;
	const struct selinux_label_view *view;
	struct selinux_label_resolution resolution;
	struct selinux_label_ref *label;
	struct selinux_global_sid_handle *sid_handle;
	int rc;

	if (!state || !state->label_domain || !source_view)
		return ERR_PTR(-EINVAL);
	view = selinux_label_view_get(source_view);
	label = global_sid_to_label_ref(sid);
	if (IS_ERR(label)) {
		rc = PTR_ERR(label);
		goto out_view;
	}
	rc = selinux_label_view_resolve_chain(view, label, sid, &resolution);
	if (rc)
		goto out_label;
	sid_handle = global_sid_handle_get(sid);
	if (IS_ERR(sid_handle)) {
		rc = PTR_ERR(sid_handle);
		goto out_label;
	}
	assertion = selinux_net_assertion_alloc_handle(sid_handle, sclass,
						       source, 0, gfp);
	global_sid_handle_put(sid_handle);
	if (IS_ERR(assertion)) {
		rc = PTR_ERR(assertion);
		goto out_label;
	}
	provenance = selinux_net_provenance_alloc(state, view, assertion, gfp);
	if (IS_ERR(provenance)) {
		rc = PTR_ERR(provenance);
		goto out_assertion;
	}

	goto out_assertion;

out_assertion:
	selinux_net_assertion_put(assertion);
out_label:
	selinux_label_ref_put(label);
out_view:
	selinux_label_view_put(view);
	return rc ? ERR_PTR(rc) : provenance;
}

static struct selinux_net_provenance *
selinux_net_provenance_create(struct selinux_state *state,
			      struct user_namespace *owner_userns,
			      struct selinux_label_domain *outer_domain,
			      u32 sid, u16 sclass,
			      enum selinux_net_assertion_source source,
			      gfp_t gfp)
{
	struct selinux_net_provenance *provenance;
	const struct selinux_label_view *view;

	if (!state || !state->label_domain || !owner_userns || !outer_domain)
		return ERR_PTR(-EINVAL);
	view = selinux_identity_view_alloc_gfp(owner_userns, state->label_domain,
					       outer_domain, gfp);
	if (IS_ERR(view))
		return ERR_CAST(view);
	provenance = selinux_net_provenance_create_view(
		state, view, sid, sclass, source, gfp);
	selinux_label_view_put(view);
	return provenance;
}

static bool selinux_secmark_netns_view_valid(
	const struct selinux_netns_security *netsec,
	const struct user_namespace *owner_userns)
{
	return netsec && netsec->state && netsec->state->label_domain &&
	       netsec->view &&
	       netsec->view->origin_domain == netsec->state->label_domain &&
	       netsec->view->owner_userns == owner_userns;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
bool selinux_kunit_secmark_netns_view_valid(
	const struct selinux_netns_security *netsec,
	const struct user_namespace *owner_userns)
{
	return selinux_secmark_netns_view_valid(netsec, owner_userns);
}
#endif

struct selinux_net_provenance *
selinux_secmark_provenance_create(const struct net *net, u32 sid, gfp_t gfp)
{
	const struct selinux_netns_security *netsec;
	struct selinux_state *state = current_selinux_state;

	if (!net)
		return ERR_PTR(-EINVAL);
	netsec = selinux_netns(net);
	if (!sid || !state || !state->label_domain ||
	    !selinux_secmark_netns_view_valid(netsec, net->user_ns))
		return ERR_PTR(-EACCES);
	return selinux_net_provenance_create_view(
		state, netsec->view, sid, SECCLASS_PACKET,
		SELINUX_NET_ASSERTION_SOURCE_SECMARK, gfp);
}
EXPORT_SYMBOL_GPL(selinux_secmark_provenance_create);

static struct selinux_net_provenance *selinux_sk_provenance_create(
	struct sock *sk, u32 sid, u16 sclass,
	enum selinux_net_assertion_source source, bool allow_init_net_bootstrap,
	gfp_t gfp)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	const struct selinux_netns_security *netsec = selinux_netns(sock_net(sk));
	struct selinux_label_domain *outer_domain;
	struct user_namespace *owner_userns;

	if (!sksec->state || !sksec->state->label_domain)
		return ERR_PTR(-EACCES);
	if (netsec && netsec->state && netsec->view) {
		owner_userns = netsec->view->owner_userns;
		outer_domain = netsec->state->label_domain;
	} else if (allow_init_net_bootstrap && sock_net(sk) == &init_net &&
		   sksec->state == init_selinux_state) {
		/*
		 * Core networking creates init_net kernel sockets before the
		 * SELinux core initcall can register its per-net anchor.  Their
		 * only possible lineage is the initial SELinux/user namespace.
		 */
		owner_userns = &init_user_ns;
		outer_domain = init_selinux_state->label_domain;
	} else {
		return ERR_PTR(-EACCES);
	}
	return selinux_net_provenance_create(
		sksec->state, owner_userns, outer_domain, sid, sclass, source, gfp);
}

/* Consume @sid_handle and preserve that exact producer identity. */
static struct selinux_net_provenance *selinux_net_provenance_derive_handle(
	struct selinux_net_provenance *base,
	struct selinux_global_sid_handle *sid_handle, u16 sclass,
	enum selinux_net_assertion_source source, gfp_t gfp)
{
	struct selinux_net_provenance *provenance;
	struct selinux_net_assertion *assertion;
	struct selinux_label_resolution resolution;
	struct selinux_label_ref *label;
	u32 sid;
	int rc;

	if (IS_ERR(sid_handle))
		return ERR_CAST(sid_handle);
	if (!base || !sid_handle) {
		global_sid_handle_put(sid_handle);
		return ERR_PTR(-EINVAL);
	}
	sid = global_sid_handle_sid(sid_handle);
	label = global_sid_handle_label_get(sid_handle);
	if (!sid || !label) {
		provenance = ERR_PTR(-ESTALE);
		goto out_handle;
	}
	rc = selinux_label_view_resolve_chain(base->view, label, sid,
					      &resolution);
	if (rc) {
		provenance = ERR_PTR(rc);
		goto out_label;
	}
	assertion = selinux_net_assertion_alloc_handle(sid_handle, sclass,
						       source, 0, gfp);
	if (IS_ERR(assertion)) {
		provenance = ERR_CAST(assertion);
		goto out_label;
	}
	if (assertion->sid_handle != sid_handle) {
		selinux_net_assertion_put(assertion);
		provenance = ERR_PTR(-ESTALE);
		goto out_label;
	}
	provenance = selinux_net_provenance_alloc(base->state, base->view,
						   assertion, gfp);
	selinux_net_assertion_put(assertion);
out_label:
	selinux_label_ref_put(label);
out_handle:
	global_sid_handle_put(sid_handle);
	return provenance;
}

static void selinux_sk_provenance_free(struct sk_security_struct *sksec)
{
	struct selinux_net_provenance *provenance, *peer;

	provenance = rcu_dereference_protected(sksec->provenance, 1);
	peer = rcu_dereference_protected(sksec->peer_provenance, 1);
	RCU_INIT_POINTER(sksec->provenance, NULL);
	RCU_INIT_POINTER(sksec->peer_provenance, NULL);
	selinux_net_provenance_put(peer);
	selinux_net_provenance_put(provenance);
}

/* Publish the SID projection before the authoritative RCU pointer. */
static void selinux_sk_peer_provenance_replace(
	struct sk_security_struct *sksec,
	struct selinux_net_provenance *peer)
{
	struct selinux_net_provenance *old;
	u32 peer_sid = SECSID_NULL;

	if (peer && (!peer->subject || !peer->subject->sid_handle ||
		     global_sid_handle_sid(peer->subject->sid_handle) !=
			     peer->subject->sid)) {
		selinux_net_provenance_put(peer);
		peer = NULL;
	}
	if (peer)
		peer_sid = peer->subject->sid;
	WRITE_ONCE(sksec->peer_sid, peer_sid);
	old = rcu_replace_pointer(sksec->peer_provenance, peer, true);
	selinux_net_provenance_put(old);
}

#define SELINUX_NET_AVC_CHECKS_PER_POLICY 4
/* SCTP may validate base, old peer, XFRM, new subject, and new peer carriers. */
#define SELINUX_NET_AVC_PROVENANCE_CACHE_SIZE 5
#define SELINUX_NET_AVC_MAX_CHECKS \
	(SELINUX_NET_AVC_CHECKS_PER_POLICY * \
	 (SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1))

static_assert(SELINUX_NET_AVC_MAX_CHECKS <=
	      SELINUX_AVC_TRANSACTION_MAX_CHECKS);

struct selinux_net_avc_transaction {
	struct {
		const struct selinux_net_provenance *carrier;
		struct selinux_label_resolution resolution;
	} resolved[SELINUX_NET_AVC_PROVENANCE_CACHE_SIZE];
	struct selinux_avc_transaction_workspace *workspace;
	struct selinux_avc_level *dynamic_levels;
	struct selinux_policy_snapshot *dynamic_snapshots;
	struct selinux_global_sid_handle **dynamic_handles;
	struct selinux_label_ref **dynamic_labels;
	struct selinux_avc_provenance *dynamic_provenance;
	u16 dynamic_capacity;
	struct selinux_avc_level levels[SELINUX_NET_AVC_MAX_CHECKS];
	struct selinux_policy_snapshot snapshots[SELINUX_NET_AVC_MAX_CHECKS];
	struct selinux_global_sid_handle *handles[SELINUX_NET_AVC_MAX_CHECKS];
	struct selinux_label_ref *labels[SELINUX_NET_AVC_MAX_CHECKS];
	struct selinux_avc_provenance provenance[SELINUX_NET_AVC_MAX_CHECKS];
	u8 resolved_count;
	u16 count;
};

static u16 selinux_net_avc_transaction_capacity(
	const struct selinux_net_avc_transaction *transaction)
{
	return transaction->dynamic_capacity ?: ARRAY_SIZE(transaction->levels);
}

static struct selinux_avc_level *selinux_net_avc_transaction_levels(
	struct selinux_net_avc_transaction *transaction)
{
	return transaction->dynamic_levels ?: transaction->levels;
}

static struct selinux_policy_snapshot *selinux_net_avc_transaction_snapshots(
	struct selinux_net_avc_transaction *transaction)
{
	return transaction->dynamic_snapshots ?: transaction->snapshots;
}

static struct selinux_global_sid_handle **
selinux_net_avc_transaction_handles(
	struct selinux_net_avc_transaction *transaction)
{
	return transaction->dynamic_handles ?: transaction->handles;
}

static struct selinux_label_ref **selinux_net_avc_transaction_labels(
	struct selinux_net_avc_transaction *transaction)
{
	return transaction->dynamic_labels ?: transaction->labels;
}

static struct selinux_avc_provenance *selinux_net_avc_transaction_provenance(
	struct selinux_net_avc_transaction *transaction)
{
	return transaction->dynamic_provenance ?: transaction->provenance;
}

static void selinux_net_avc_transaction_reset(
	struct selinux_net_avc_transaction *transaction)
{
	struct selinux_global_sid_handle **handles =
		selinux_net_avc_transaction_handles(transaction);
	struct selinux_label_ref **labels =
		selinux_net_avc_transaction_labels(transaction);
	u16 i;

	for (i = 0; i < transaction->count; i++) {
		selinux_label_ref_put(labels[i]);
		global_sid_handle_put(handles[i]);
		labels[i] = NULL;
		handles[i] = NULL;
	}
	transaction->resolved_count = 0;
	transaction->count = 0;
}

/*
 * A native network-policy handle already belongs to the policy which produced
 * it.  Prove in O(1) that the policy domain is covered by the immutable view;
 * translating that same native label through every boundary would both reject
 * intermediate domains and turn a d-policy operation into Theta(d squared).
 */
static bool selinux_net_view_contains_domain(
	const struct selinux_label_view *view,
	const struct selinux_label_domain *domain)
{
	const struct selinux_label_domain *deepest;
	const struct selinux_label_map *map;
	u16 depth;

	if (!view || !view->origin_domain || !view->outer_domain || !domain)
		return false;
	deepest = view->origin_domain;
	if (view->outer_domain->depth > deepest->depth)
		deepest = view->outer_domain;
	depth = domain->depth;
	if (deepest->depth != view->map_count || depth > deepest->depth)
		return false;
	if (domain == deepest)
		return true;
	if (!view->map_count)
		return false;
	if (!depth)
		return view->maps[0] && view->maps[0]->parent == domain;
	map = view->maps[depth - 1];
	return map && map->child_domain_id == domain->id &&
	       map->parent == domain->parent;
}

/* Resolve each immutable carrier once per whole network attempt. */
static int selinux_net_avc_transaction_provenance_sid(
	struct selinux_net_avc_transaction *transaction,
	const struct selinux_net_provenance *provenance,
	const struct selinux_label_domain *domain, u32 *sid)
{
	struct selinux_label_resolution *resolution = NULL;
	struct selinux_label_ref *label;
	u8 i;
	int rc;

	if (!transaction || !provenance || !provenance->subject ||
	    !provenance->subject->label || !provenance->subject->sid_handle ||
	    !provenance->view || !domain || !sid)
		return -EOPNOTSUPP;
	if (global_sid_handle_sid(provenance->subject->sid_handle) !=
	    provenance->subject->sid)
		return -ESTALE;
	for (i = 0; i < transaction->resolved_count; i++) {
		if (transaction->resolved[i].carrier == provenance) {
			resolution = &transaction->resolved[i].resolution;
			break;
		}
	}
	if (!resolution) {
		if (transaction->resolved_count >= ARRAY_SIZE(transaction->resolved))
			return -E2BIG;
		label = global_sid_handle_label_get(provenance->subject->sid_handle);
		if (!label)
			return -ESTALE;
		if (label != provenance->subject->label) {
			selinux_label_ref_put(label);
			return -ESTALE;
		}
		selinux_label_ref_put(label);
		resolution =
			&transaction->resolved[transaction->resolved_count].resolution;
		rc = selinux_label_view_resolve_chain(
			provenance->view, provenance->subject->label,
			provenance->subject->sid, resolution);
		if (rc)
			return rc;
		transaction->resolved[transaction->resolved_count].carrier = provenance;
		transaction->resolved_count++;
	}
	if (domain->depth > resolution->max_depth ||
	    resolution->domain_id[domain->depth] != domain->id ||
	    !resolution->sid[domain->depth])
		return -EOPNOTSUPP;
	*sid = resolution->sid[domain->depth];
	return 0;
}

/* Consume @handle only after every overflow check has succeeded. */
static int selinux_net_avc_transaction_add(
	struct selinux_net_avc_transaction *transaction,
	const struct selinux_avc_level *level,
	const struct selinux_policy_snapshot *snapshot,
	struct selinux_global_sid_handle *handle)
{
	struct selinux_global_sid_handle **handles =
		selinux_net_avc_transaction_handles(transaction);
	struct selinux_policy_snapshot *snapshots =
		selinux_net_avc_transaction_snapshots(transaction);
	struct selinux_avc_level *levels =
		selinux_net_avc_transaction_levels(transaction);
	u16 next;

	if (check_add_overflow(transaction->count, (u16)1, &next) ||
	    next > selinux_net_avc_transaction_capacity(transaction)) {
		global_sid_handle_put(handle);
		return -E2BIG;
	}
	levels[transaction->count] = *level;
	snapshots[transaction->count] = *snapshot;
	handles[transaction->count] = handle;
	transaction->count = next;
	return 0;
}

static int selinux_net_avc_transaction_add_handle(
	struct selinux_net_avc_transaction *transaction,
	const struct selinux_avc_level *level,
	const struct selinux_policy_snapshot *snapshot,
	struct selinux_global_sid_handle *handle,
	const struct selinux_label_view *view, u8 source)
{
	struct selinux_avc_provenance *provenance =
		selinux_net_avc_transaction_provenance(transaction);
	struct selinux_label_ref **labels =
		selinux_net_avc_transaction_labels(transaction);
	struct selinux_label_ref *label;
	struct selinux_avc_level canonical = *level;
	u16 index = transaction->count;
	int rc;

	if (!handle || !view || !level->state || !level->state->label_domain) {
		global_sid_handle_put(handle);
		return -EOPNOTSUPP;
	}
	if (!level->tsid || global_sid_handle_sid(handle) != level->tsid) {
		global_sid_handle_put(handle);
		return -ESTALE;
	}
	label = global_sid_handle_label_get(handle);
	if (!label) {
		global_sid_handle_put(handle);
		return -ESTALE;
	}
	if (((!(label->domain->flags & SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) ||
	       level->tsid > SECINITSID_NUM) &&
	      label->domain != level->state->label_domain) ||
	    !selinux_net_view_contains_domain(view,
					      level->state->label_domain)) {
		selinux_label_ref_put(label);
		global_sid_handle_put(handle);
		return -EXDEV;
	}
	if (index >= selinux_net_avc_transaction_capacity(transaction)) {
		selinux_label_ref_put(label);
		global_sid_handle_put(handle);
		return -E2BIG;
	}
	provenance[index] = (struct selinux_avc_provenance) {
		.label = label,
		.view = view,
		.source = source,
	};
	canonical.provenance = &provenance[index];
	rc = selinux_net_avc_transaction_add(
		transaction, &canonical, snapshot, handle);
	if (rc) {
		selinux_label_ref_put(label);
		return rc;
	}
	labels[index] = label;
	return 0;
}

static int selinux_net_avc_transaction_add_provenance(
	struct selinux_net_avc_transaction *transaction,
	const struct selinux_avc_level *level,
	const struct selinux_policy_snapshot *snapshot,
	const struct selinux_net_provenance *provenance)
{
	struct selinux_avc_provenance *audit_provenance =
		selinux_net_avc_transaction_provenance(transaction);
	struct selinux_label_ref **labels =
		selinux_net_avc_transaction_labels(transaction);
	struct selinux_global_sid_handle *handle;
	struct selinux_label_ref *label;
	struct selinux_avc_level canonical = *level;
	u32 resolved_sid;
	u16 index = transaction->count;
	int rc;

	if (!provenance || !provenance->subject ||
	    !provenance->subject->label || !provenance->subject->sid_handle ||
	    !provenance->view || !level->state || !level->state->label_domain)
		return -EOPNOTSUPP;
	handle = global_sid_handle_dup(provenance->subject->sid_handle);
	if (IS_ERR_OR_NULL(handle))
		return handle ? PTR_ERR(handle) : -ESTALE;
	if (global_sid_handle_sid(handle) != provenance->subject->sid) {
		rc = -ESTALE;
		goto out_handle;
	}
	label = global_sid_handle_label_get(handle);
	if (!label) {
		rc = -ESTALE;
		goto out_handle;
	}
	if (label != provenance->subject->label) {
		rc = -ESTALE;
		goto out_label;
	}
	rc = selinux_net_avc_transaction_provenance_sid(
		transaction, provenance, level->state->label_domain, &resolved_sid);
	if (rc || resolved_sid != level->tsid) {
		rc = rc ?: -ESTALE;
		goto out_label;
	}
	if (index >= selinux_net_avc_transaction_capacity(transaction))
		goto out_too_big;
	audit_provenance[index] = (struct selinux_avc_provenance) {
		.label = label,
		.view = provenance->view,
		.source = provenance->subject->source,
	};
	canonical.provenance = &audit_provenance[index];
	rc = selinux_net_avc_transaction_add(
		transaction, &canonical, snapshot, handle);
	if (rc) {
		selinux_label_ref_put(label);
		return rc;
	}
	labels[index] = label;
	return 0;

out_too_big:
	rc = -E2BIG;
out_label:
	selinux_label_ref_put(label);
out_handle:
	global_sid_handle_put(handle);
	return rc;
}

static struct selinux_global_sid_handle *
selinux_net_avc_transaction_peer_sources_native_handle(
	struct selinux_net_avc_transaction *transaction,
	const struct selinux_peer_sources *sources, struct selinux_state *state,
	u32 *netlabel_sid, u32 *xfrm_sid_out)
{
	struct selinux_global_sid_handle *nlbl_handle;
	u32 xfrm_sid = SECSID_NULL;
	u32 nlbl_sid;
	int rc;

	if (!transaction || !sources || !state || !state->label_domain)
		return ERR_PTR(-EOPNOTSUPP);
	nlbl_handle = selinux_netlbl_source_sid_handle(
		state, &sources->netlabel, &nlbl_sid);
	if (IS_ERR(nlbl_handle))
		return nlbl_handle;
	if (sources->xfrm) {
		rc = selinux_net_avc_transaction_provenance_sid(
			transaction, sources->xfrm, state->label_domain, &xfrm_sid);
		if (rc) {
			global_sid_handle_put(nlbl_handle);
			return ERR_PTR(rc);
		}
	}
	if (netlabel_sid)
		*netlabel_sid = nlbl_sid;
	if (xfrm_sid_out)
		*xfrm_sid_out = xfrm_sid;
	return nlbl_handle;
}

static struct selinux_global_sid_handle *
selinux_net_avc_transaction_peer_sources_handle(
	struct selinux_net_avc_transaction *transaction,
	const struct selinux_peer_sources *sources, struct selinux_state *state,
	u32 *sid)
{
	struct selinux_global_sid_handle *nlbl_handle;
	struct selinux_global_sid_handle *peer_handle;
	u32 xfrm_sid, nlbl_sid;

	nlbl_handle = selinux_net_avc_transaction_peer_sources_native_handle(
		transaction, sources, state, &nlbl_sid, &xfrm_sid);
	if (IS_ERR(nlbl_handle))
		return nlbl_handle;
	peer_handle = security_net_peersid_resolve_handle(
		state, nlbl_sid, sources->netlabel.type, xfrm_sid, sid);
	global_sid_handle_put(nlbl_handle);
	return peer_handle;
}

/* Keep a policy generation in the atomic validation set when it has no ACL. */
static int selinux_net_avc_transaction_add_guard(
	struct selinux_net_avc_transaction *transaction, u16 initial_count,
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot)
{
	if (transaction->count != initial_count)
		return 0;
	return selinux_net_avc_transaction_add(
		transaction, &(struct selinux_avc_level) {
			.state = state,
		}, snapshot, NULL);
}

static int selinux_net_avc_transaction_decide(
	struct selinux_net_avc_transaction *transaction,
	struct common_audit_data *ad)
{
	if (!transaction->count)
		return 0;
	if (!transaction->workspace)
		return -ENOMEM;
	return selinux_avc_transaction_has_perm_workspace(
		selinux_net_avc_transaction_levels(transaction),
		selinux_net_avc_transaction_snapshots(transaction),
		transaction->count, ad, transaction->workspace);
}

static int selinux_net_provenance_projection_matches(
	struct selinux_net_avc_transaction *transaction,
	const struct selinux_net_provenance *candidate,
	const struct selinux_policy_state_chain_snapshot *chain,
	const u32 *expected)
{
	u16 i;

	for (i = 0; i < chain->count; i++) {
		u32 resolved;
		int rc;

		if (!candidate) {
			if (expected[i] != SECSID_NULL)
				return -EACCES;
			continue;
		}
		rc = selinux_net_avc_transaction_provenance_sid(
			transaction, candidate, chain->state[i]->label_domain,
			&resolved);
		if (rc)
			return rc;
		if (resolved != expected[i])
			return -EACCES;
	}
	return 0;
}

static int selinux_net_provenances_has_perm(
	const struct cred *cred, const struct selinux_net_provenance *source,
	const struct selinux_net_provenance *target, const struct sock *target_sk,
	u32 requested, struct common_audit_data *ad)
{
	struct {
		struct selinux_label_operation_resolution source_resolution;
		struct selinux_label_operation_resolution target_resolution;
		struct selinux_policy_chain_snapshot chain;
		struct selinux_net_avc_transaction transaction;
		struct selinux_avc_provenance audit_provenance[
			SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	} *scratch;
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
	unsigned int retry;
	int rc;

	if (!cred || !source || !target || !target_sk || !source->subject ||
	    !target->subject)
		return -EINVAL;
	scratch = kzalloc_obj(*scratch, GFP_ATOMIC);
	if (!scratch)
		return -ENOMEM;
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_NET_AVC_MAX_CHECKS, GFP_ATOMIC | __GFP_NOWARN);
	if (!workspace) {
		rc = -ENOMEM;
		goto out;
	}
	scratch->transaction.workspace = workspace;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;

		selinux_net_avc_transaction_reset(&scratch->transaction);
		selinux_label_operation_resolution_put(&scratch->source_resolution);
		selinux_label_operation_resolution_put(&scratch->target_resolution);
		rc = selinux_policy_chain_snapshot_read(cred, &scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			goto out;
		rc = selinux_label_view_resolve_operation(
			source->view, source->subject->label, source->subject->sid,
			selinux_cred(scratch->chain.cred[0])->state->label_domain,
			&scratch->source_resolution);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			goto out;
		rc = selinux_label_view_resolve_operation(
			target->view, target->subject->label, target->subject->sid,
			selinux_cred(scratch->chain.cred[0])->state->label_domain,
			&scratch->target_resolution);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			goto out;

		for (i = 0; i < scratch->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(scratch->chain.cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&scratch->chain.policy[i];
			const struct selinux_label_domain *domain =
				crsec->state->label_domain;
			u16 sclass;

			if (!domain ||
			    domain->depth > scratch->source_resolution.labels.max_depth ||
			    domain->depth > scratch->target_resolution.labels.max_depth ||
			    scratch->source_resolution.labels.domain_id[domain->depth] !=
				    domain->id ||
			    scratch->target_resolution.labels.domain_id[domain->depth] !=
				    domain->id ||
			    !scratch->source_resolution.labels.sid[domain->depth] ||
			    !scratch->target_resolution.labels.sid[domain->depth]) {
				rc = -EOPNOTSUPP;
				break;
			}
			scratch->audit_provenance[i] =
				(struct selinux_avc_provenance) {
					.label = target->subject->label,
					.view = target->view,
					.map_generation = scratch->target_resolution
						.map_generation[domain->depth],
					.source = target->subject->source,
				};
			sclass = socket_class_for_snapshot(
				snapshot, target_sk->sk_family, target_sk->sk_type,
				target_sk->sk_protocol);
			rc = selinux_net_avc_transaction_add(
				&scratch->transaction,
				&(struct selinux_avc_level) {
					.state = crsec->state,
					.ssid = scratch->source_resolution.labels
						.sid[domain->depth],
					.tsid = scratch->target_resolution.labels
						.sid[domain->depth],
					.requested = requested,
					.tclass = sclass,
					.provenance = &scratch->audit_provenance[i],
				}, snapshot, NULL);
			if (rc)
				break;
		}
		if (!rc)
			rc = selinux_net_avc_transaction_decide(
				&scratch->transaction, ad);
		if (rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(&scratch->chain)) {
			rc = -ESTALE;
			continue;
		}
		goto out;
	}

	rc = -ESTALE;
out:
	selinux_label_operation_resolution_put(&scratch->target_resolution);
	selinux_label_operation_resolution_put(&scratch->source_resolution);
	selinux_net_avc_transaction_reset(&scratch->transaction);
	kfree(scratch);
	return rc;
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_skb_secmark_sid(const struct sk_buff *skb,
				   struct selinux_state *state,
				   struct selinux_net_avc_transaction *transaction,
				   u32 *sid)
{
	const struct selinux_net_provenance *provenance =
		skb->secmark_provenance;
	u32 projected = READ_ONCE(skb->secmark);

	if (!projected) {
		if (provenance)
			return -ESTALE;
		*sid = 0;
		return 0;
	}
	if (!selinux_secmark_provenance_matches(provenance, projected) ||
	    !provenance->view || !provenance->subject ||
	    !provenance->subject->label)
		return -EOPNOTSUPP;
	return selinux_net_avc_transaction_provenance_sid(
		transaction, provenance, state->label_domain, sid);
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
static struct selinux_global_sid_handle *
socket_sockcreate_sid_handle(struct selinux_state *state,
			     const struct cred_security_struct *crsec,
			     u16 secclass, u32 *socksid)
{
	struct selinux_global_sid_handle *handle;

	if (crsec->sockcreate_sid > SECSID_NULL) {
		*socksid = crsec->sockcreate_sid;
		handle = global_sid_handle_dup(crsec->sockcreate_sid_handle);
		if (IS_ERR(handle))
			return handle;
		if (global_sid_handle_sid(handle) != *socksid) {
			global_sid_handle_put(handle);
			return ERR_PTR(-ESTALE);
		}
		return handle;
	}

	return security_transition_sid_handle(
		state, crsec->sid, crsec->sid, secclass, NULL, socksid);
}
#else
static int socket_sockcreate_sid(struct selinux_state *state,
				 const struct cred_security_struct *crsec,
				 u16 secclass, u32 *socksid)
{
	if (crsec->sockcreate_sid > SECSID_NULL) {
		*socksid = crsec->sockcreate_sid;
		return 0;
	}

	return security_transition_sid(state, crsec->sid, crsec->sid, secclass,
				       NULL, socksid);
}
#endif

static bool sock_skip_has_perm(
	const struct selinux_policy_snapshot *snapshot, u32 sid)
{
	if (sid == SECINITSID_KERNEL)
		return true;

	/*
	 * Before POLICYDB_CAP_USERSPACE_INITIAL_CONTEXT, sockets that
	 * inherited the kernel context from early boot used to be skipped
	 * here, so preserve that behavior unless the capability is set.
	 *
	 * By setting the capability the policy signals that it is ready
	 * for this quirk to be fixed. Note that sockets created by a kernel
	 * thread or a usermode helper executed without a transition will
	 * still be skipped in this check regardless of the policycap
	 * setting.
	 */
	if (!selinux_policycap_userspace_initial_context(snapshot) &&
	    sid == SECINITSID_INIT)
		return true;
	return false;
}


static int sock_has_perm(struct sock *sk, u32 perms)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct {
		struct selinux_policy_chain_snapshot chain;
#ifdef CONFIG_SECURITY_SELINUX_NS
		struct selinux_net_avc_transaction transaction;
		struct selinux_label_operation_resolution operation;
		struct selinux_avc_provenance audit_provenance[
			SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
#endif
	} *scratch __free(kfree) = NULL;
	struct selinux_policy_chain_snapshot *chain;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	unsigned int retry;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
	struct selinux_net_provenance *provenance;
	int rc;

	provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
	if (!provenance)
		return -EACCES;
	if (!provenance->view || !provenance->subject ||
	    !provenance->subject->label) {
		rc = -EACCES;
		goto out_provenance;
	}
	if (READ_ONCE(sksec->sid) != provenance->subject->sid ||
	    sksec->state != provenance->state) {
		rc = -ESTALE;
		goto out_provenance;
	}
#endif

	ad_net_init_from_sk(&ad, &net, sk);
	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = -ENOMEM;
		goto out_provenance;
#else
		return -ENOMEM;
#endif
	}
	chain = &scratch->chain;
#ifdef CONFIG_SECURITY_SELINUX_NS
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_NET_AVC_MAX_CHECKS, GFP_KERNEL);
	if (!workspace) {
		rc = -ENOMEM;
		goto out_provenance;
	}
	scratch->transaction.workspace = workspace;
#endif

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;
		int iter_rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
		selinux_net_avc_transaction_reset(&scratch->transaction);
		selinux_label_operation_resolution_put(&scratch->operation);
#endif
		iter_rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
		if (iter_rc == -EAGAIN || iter_rc == -ESTALE)
			continue;
		if (iter_rc) {
#ifdef CONFIG_SECURITY_SELINUX_NS
			rc = iter_rc;
			goto out_provenance;
#else
			return iter_rc;
#endif
		}
#ifdef CONFIG_SECURITY_SELINUX_NS
		iter_rc = selinux_label_view_resolve_operation(
			provenance->view, provenance->subject->label,
			provenance->subject->sid,
			selinux_cred(chain->cred[0])->state->label_domain,
			&scratch->operation);
		if (iter_rc == -EAGAIN || iter_rc == -ESTALE)
			continue;
		if (iter_rc) {
			rc = iter_rc;
			goto out_provenance;
		}
#endif

		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&chain->policy[i];
			u16 sclass = socket_class_for_snapshot(
				snapshot, sk->sk_family, sk->sk_type, sk->sk_protocol);
			u32 policy_sid = sksec->sid;
#ifdef CONFIG_SECURITY_SELINUX_NS
			u16 initial_count = scratch->transaction.count;
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
			if (crsec->state->depth > scratch->operation.labels.max_depth ||
			    scratch->operation.labels.domain_id[crsec->state->depth] !=
				    crsec->state->label_domain->id ||
			    !scratch->operation.labels.sid[crsec->state->depth]) {
				iter_rc = -EOPNOTSUPP;
				break;
			}
			policy_sid = scratch->operation.labels.sid[crsec->state->depth];
			scratch->audit_provenance[i] =
				(struct selinux_avc_provenance) {
					.label = provenance->subject->label,
					.view = provenance->view,
					.map_generation = scratch->operation
						.map_generation[crsec->state->depth],
					.source = provenance->subject->source,
				};
#endif
			if (sock_skip_has_perm(snapshot, policy_sid)) {
#ifdef CONFIG_SECURITY_SELINUX_NS
				iter_rc = selinux_net_avc_transaction_add_guard(
					&scratch->transaction, initial_count,
					crsec->state, snapshot);
				if (iter_rc)
					break;
#endif
				continue;
			}
#ifdef CONFIG_SECURITY_SELINUX_NS
			iter_rc = selinux_net_avc_transaction_add(
				&scratch->transaction,
				&(struct selinux_avc_level) {
					.state = crsec->state,
					.ssid = crsec->sid,
					.tsid = policy_sid,
					.requested = perms,
					.tclass = sclass,
					.provenance = &scratch->audit_provenance[i],
				}, snapshot, NULL);
#else
			iter_rc = avc_has_perm_snapshot(
				crsec->state, snapshot, crsec->sid, policy_sid,
				sclass, perms, &ad);
#endif
			if (iter_rc)
				break;
		}
#ifdef CONFIG_SECURITY_SELINUX_NS
		if (!iter_rc)
			iter_rc = selinux_net_avc_transaction_decide(
				&scratch->transaction, &ad);
		if (iter_rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain)) {
			iter_rc = -ESTALE;
			continue;
		}
#else
		if (iter_rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain))
			continue;
#endif
#ifdef CONFIG_SECURITY_SELINUX_NS
		rc = iter_rc;
		goto out_provenance;
#else
		return iter_rc;
#endif
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = -ESTALE;
out_provenance:
	if (scratch) {
		selinux_label_operation_resolution_put(&scratch->operation);
		selinux_net_avc_transaction_reset(&scratch->transaction);
	}
	selinux_net_provenance_put(provenance);
	return rc;
#else
	return -ESTALE;
#endif
}

static int selinux_socket_create(int family, int type,
				 int protocol, int kern)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	/*
	 * The actual socket label and its netns-bound view do not exist until
	 * socket_post_create.  Authorize that exact published object there.
	 */
	return 0;
#else
	const struct cred_security_struct *crsec;
	const struct cred *cred = current_cred();
	struct selinux_policy_snapshot snapshot;
	struct selinux_state *state;
	unsigned int retry;
	u32 newsid;
	u16 secclass;
	int rc = 0;

	if (kern)
		return 0;

	do {
		crsec = selinux_cred(cred);
		state = crsec->state;
		for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES;
		     retry++) {
			rc = socket_class_for_state(state, family, type, protocol,
						    &snapshot, &secclass);
			if (rc) {
				if (rc == -EAGAIN)
					continue;
				return rc;
			}
			rc = socket_sockcreate_sid(state, crsec, secclass,
						   &newsid);
			if (rc)
				return rc;
			rc = avc_has_perm_snapshot(state, &snapshot, crsec->sid,
						   newsid, secclass,
						   SOCKET__CREATE, NULL);
			if (rc != -ESTALE)
				break;
		}
		if (rc)
			return rc;

		cred = crsec->parent_cred;
	} while (cred);

	return 0;
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_socket_post_create_namespaced(struct socket *sock, int family,
						 int type, int protocol,
						 int kern)
{
	struct inode_security_struct *isec =
		inode_security_novalidate(SOCK_INODE(sock));
	struct {
		struct selinux_policy_chain_snapshot chain;
		struct selinux_net_avc_transaction transaction;
	} *scratch __free(kfree) = NULL;
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
	struct selinux_policy_chain_snapshot *chain;
	struct selinux_label_resolution resolution;
	struct selinux_net_provenance *provenance;
	struct sk_security_struct *sksec;
	unsigned int retry;

	if (!sock->sk) {
		/*
		 * sock_create_lite() publishes the socket inode before a kernel
		 * caller attaches struct sock.  Record the exact leaf class now;
		 * the late attachment path must invoke socket_post_create again to
		 * install the netns-bound provenance on the completed object.
		 */
		if (!kern)
			return -EACCES;
		scratch = kzalloc_obj(*scratch, GFP_KERNEL);
		if (!scratch)
			return -ENOMEM;
		chain = &scratch->chain;
		for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
			const struct selinux_policy_snapshot *snapshot;
			u16 sclass;
			int rc;

			rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
			if (rc == -EAGAIN || rc == -ESTALE)
				continue;
			if (rc)
				return rc;
			if (!chain->count)
				return -EACCES;
			snapshot = &chain->policy[0];
			sclass = socket_class_for_snapshot(snapshot, family, type,
						   protocol);
			if (!selinux_policy_chain_snapshot_valid(chain))
				continue;
			rc = inode_security_set_sid_class(
				isec, SECINITSID_KERNEL, sclass,
				SELINUX_LABEL_SOURCE_SOCKET, LABEL_INITIALIZED);
			if (rc)
				return rc;
			return 0;
		}
		return -ESTALE;
	}
	sksec = selinux_sock(sock->sk);
	if (rcu_access_pointer(sksec->provenance))
		return -EEXIST;
	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	chain = &scratch->chain;
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_NET_AVC_MAX_CHECKS, GFP_KERNEL);
	if (!workspace)
		return -ENOMEM;
	scratch->transaction.workspace = workspace;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		const struct cred_security_struct *leaf_crsec;
		const struct selinux_policy_snapshot *leaf_snapshot;
		struct selinux_global_sid_handle *sid_handle;
		u32 sid = SECINITSID_KERNEL;
		u16 sclass;
		u16 i;
		int rc;

		selinux_net_avc_transaction_reset(&scratch->transaction);
		rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		if (!chain->count)
			return -EACCES;
		leaf_crsec = selinux_cred(chain->cred[0]);
		leaf_snapshot = &chain->policy[0];
		if (leaf_crsec->state != sksec->state)
			return -ESTALE;
		sclass = socket_class_for_snapshot(leaf_snapshot, family, type,
						   protocol);
		if (kern)
			sid_handle = global_sid_handle_get(sid);
		else
			sid_handle = socket_sockcreate_sid_handle(
				sksec->state, leaf_crsec, sclass, &sid);
		if (IS_ERR(sid_handle))
			return PTR_ERR(sid_handle);
		provenance = selinux_sk_provenance_create(
			sock->sk, sid, sclass, SELINUX_NET_ASSERTION_SOURCE_SOCKET,
			kern, GFP_KERNEL);
		if (IS_ERR(provenance)) {
			global_sid_handle_put(sid_handle);
			return PTR_ERR(provenance);
		}
		rc = selinux_label_view_resolve_chain(
			provenance->view, provenance->subject->label,
			provenance->subject->sid, &resolution);
		if (rc)
			goto out_provenance;

		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&chain->policy[i];
			const struct selinux_label_domain *domain =
				crsec->state->label_domain;
			struct selinux_global_sid_handle *expected_handle;
			u32 expected_sid;
			u16 policy_class;

			if (!domain || domain->depth > resolution.max_depth ||
			    resolution.domain_id[domain->depth] != domain->id ||
			    !resolution.sid[domain->depth]) {
				rc = -EOPNOTSUPP;
				break;
			}
			if (kern) {
				rc = selinux_net_avc_transaction_add_guard(
					&scratch->transaction,
					scratch->transaction.count, crsec->state,
					snapshot);
				if (rc)
					break;
				continue;
			}
			policy_class = socket_class_for_snapshot(
				snapshot, family, type, protocol);
			expected_handle = socket_sockcreate_sid_handle(
				crsec->state, crsec, policy_class, &expected_sid);
			if (IS_ERR(expected_handle)) {
				rc = PTR_ERR(expected_handle);
				break;
			}
			/*
			 * A parent authorizes the exact label selected by the leaf,
			 * not an independently calculated object which is discarded.
			 */
			if (expected_sid != resolution.sid[domain->depth]) {
				global_sid_handle_put(expected_handle);
				rc = -EACCES;
				break;
			}
			rc = selinux_net_avc_transaction_add_handle(
				&scratch->transaction,
				&(struct selinux_avc_level) {
					.state = crsec->state,
					.ssid = crsec->sid,
					.tsid = expected_sid,
					.requested = SOCKET__CREATE,
					.tclass = policy_class,
				}, snapshot, expected_handle, provenance->view,
				SELINUX_LABEL_SOURCE_SOCKET);
			if (rc)
				break;
		}
		if (!rc)
			rc = selinux_net_avc_transaction_decide(
				&scratch->transaction, NULL);
		if (rc == -ESTALE) {
			selinux_net_provenance_put(provenance);
			global_sid_handle_put(sid_handle);
			continue;
		}
		if (rc)
			goto out_provenance;
		selinux_net_avc_transaction_reset(&scratch->transaction);
		if (!selinux_policy_chain_snapshot_valid(chain)) {
			selinux_net_provenance_put(provenance);
			global_sid_handle_put(sid_handle);
			continue;
		}
		rc = inode_security_set_sid_class(
			isec, sid, sclass, SELINUX_LABEL_SOURCE_SOCKET,
			LABEL_INITIALIZED);
		if (rc)
			goto out_provenance;

		WRITE_ONCE(sksec->sid, sid);
		WRITE_ONCE(sksec->sclass, sclass);
		rcu_assign_pointer(sksec->provenance, provenance);
		if (sclass == SECCLASS_SCTP_SOCKET)
			sksec->sctp_assoc_state = SCTP_ASSOC_UNSET;
		global_sid_handle_put(sid_handle);
		return selinux_netlbl_socket_post_create(sock->sk, family);

out_provenance:
		selinux_net_avc_transaction_reset(&scratch->transaction);
		selinux_net_provenance_put(provenance);
		global_sid_handle_put(sid_handle);
		return rc;
	}

	return -ESTALE;
}
#endif

static int selinux_socket_post_create(struct socket *sock, int family,
				      int type, int protocol, int kern)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_socket_post_create_namespaced(sock, family, type, protocol,
						     kern);
#else
	const struct cred_security_struct *crsec = selinux_cred(current_cred());
	struct selinux_policy_snapshot snapshot;
	struct selinux_state *state = crsec->state;
	struct inode_security_struct *isec = inode_security_novalidate(SOCK_INODE(sock));
	struct sk_security_struct *sksec;
	unsigned int retry;
	u16 sclass;
	u32 sid = SECINITSID_KERNEL;
	int err = -ESTALE;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		err = socket_class_for_state(state, family, type, protocol,
					     &snapshot, &sclass);
		if (err == -EAGAIN)
			continue;
		if (err)
			return err;
		if (!kern) {
			err = socket_sockcreate_sid(state, crsec, sclass, &sid);
			if (err)
				return err;
		}
		if (selinux_policy_snapshot_valid(state, &snapshot)) {
			err = 0;
			break;
		}
		err = -ESTALE;
	}
	if (err)
		return err;

	err = inode_security_set_sid_class(isec, sid, sclass,
					   SELINUX_LABEL_SOURCE_SOCKET,
					   LABEL_INITIALIZED);
	if (err)
		return err;

	if (sock->sk) {
		sksec = selinux_sock(sock->sk);
#ifdef CONFIG_SECURITY_SELINUX_NS
		err = selinux_sk_provenance_init(
			sock->sk, sid, sclass,
			SELINUX_NET_ASSERTION_SOURCE_SOCKET, kern, GFP_KERNEL);
		if (err)
			return err;
#else
		sksec->sclass = sclass;
		sksec->sid = sid;
#endif
		/* Allows detection of the first association on this socket */
		if (sksec->sclass == SECCLASS_SCTP_SOCKET)
			sksec->sctp_assoc_state = SCTP_ASSOC_UNSET;

		err = selinux_netlbl_socket_post_create(sock->sk, family);
	}

	return err;
#endif
}

static int selinux_socket_socketpair(struct socket *socka,
				     struct socket *sockb)
{
	struct sk_security_struct *sksec_a = selinux_sock(socka->sk);
	struct sk_security_struct *sksec_b = selinux_sock(sockb->sk);
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_net_provenance *provenance_a, *provenance_b;
	struct selinux_net_provenance *old_a, *old_b;

	provenance_a = selinux_net_provenance_get_rcu(&sksec_a->provenance);
	provenance_b = selinux_net_provenance_get_rcu(&sksec_b->provenance);
	if (!provenance_a || !provenance_b) {
		selinux_net_provenance_put(provenance_b);
		selinux_net_provenance_put(provenance_a);
		return -EACCES;
	}
	old_a = rcu_replace_pointer(sksec_a->peer_provenance,
			selinux_net_provenance_get(provenance_b), true);
	old_b = rcu_replace_pointer(sksec_b->peer_provenance,
			selinux_net_provenance_get(provenance_a), true);
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
	sksec_a->peer_sid = provenance_b->subject->sid;
	sksec_b->peer_sid = provenance_a->subject->sid;
#else
	sksec_a->peer_sid = sksec_b->sid;
	sksec_b->peer_sid = sksec_a->sid;
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_net_provenance_put(old_b);
	selinux_net_provenance_put(old_a);
	selinux_net_provenance_put(provenance_b);
	selinux_net_provenance_put(provenance_a);
#endif

	return 0;
}

/* Range of port numbers used to automatically bind.
   Need to determine whether we should perform a name_bind
   permission check between the socket and the port number. */

#ifndef CONFIG_SECURITY_SELINUX_NS
static int cred_port_has_perm(const struct cred *cred,
			      struct sock *sk, u32 socket_sid, u8 protocol,
			      u16 port, u16 tclass, u32 requested,
			      struct common_audit_data *ad)
{
	struct cred_security_struct *crsec;
	struct selinux_state *state;
	u32 port_sid;
	int rc;
	bool first = true;

	do {
		crsec = selinux_cred(cred);
		state = crsec->state;
		rc = sel_netport_sid(state, protocol, port, &port_sid);
		if (rc)
			return rc;

		rc = avc_has_perm(state, first ? socket_sid : crsec->sid,
				  port_sid, tclass, requested, ad);
		if (rc)
			return rc;

		first = false;
		cred = crsec->parent_cred;
	} while (cred);

	return 0;
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
enum selinux_socket_address_operation {
	SELINUX_SOCKET_ADDRESS_BIND,
	SELINUX_SOCKET_ADDRESS_CONNECT,
};

struct selinux_socket_address_check {
	struct sockaddr *address;
	const void *node;
	u16 family;
	u16 port;
	bool check_port;
	bool check_node;
};

static int selinux_socket_address_prepare(
	struct sock *sk, enum selinux_socket_address_operation operation,
	struct sockaddr *address, int addrlen,
	struct selinux_socket_address_check *check)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	u16 family;

	memset(check, 0, sizeof(*check));
	check->address = address;
	if (operation == SELINUX_SOCKET_ADDRESS_BIND &&
	    sk->sk_family != PF_INET && sk->sk_family != PF_INET6)
		return 0;
	if (addrlen < offsetofend(struct sockaddr, sa_family))
		return -EINVAL;
	family = address->sa_family;
	if (operation == SELINUX_SOCKET_ADDRESS_CONNECT &&
	    family == AF_UNSPEC)
		return 0;
	if (operation == SELINUX_SOCKET_ADDRESS_CONNECT &&
	    sksec->sclass != SECCLASS_TCP_SOCKET &&
	    sksec->sclass != SECCLASS_SCTP_SOCKET)
		return 0;

	switch (family) {
	case AF_UNSPEC:
	case AF_INET:
		if (addrlen < sizeof(*addr4))
			return -EINVAL;
		addr4 = (struct sockaddr_in *)address;
		if (family == AF_UNSPEC) {
			if (operation != SELINUX_SOCKET_ADDRESS_BIND)
				return 0;
			if (sk->sk_family == PF_INET6) {
				if (addrlen < SIN6_LEN_RFC2133)
					return -EINVAL;
				goto err_af;
			}
			if (addr4->sin_addr.s_addr != htonl(INADDR_ANY))
				goto err_af;
			family = AF_INET;
		}
		check->port = ntohs(addr4->sin_port);
		check->node = &addr4->sin_addr.s_addr;
		break;
	case AF_INET6:
		if (addrlen < SIN6_LEN_RFC2133)
			return -EINVAL;
		addr6 = (struct sockaddr_in6 *)address;
		check->port = ntohs(addr6->sin6_port);
		check->node = &addr6->sin6_addr.s6_addr;
		break;
	default:
		goto err_af;
	}

	check->family = family;
	if (operation == SELINUX_SOCKET_ADDRESS_BIND) {
		int low, high;

		check->check_node = true;
		if (!check->port)
			return 0;
		inet_get_local_port_range(sock_net(sk), &low, &high);
		check->check_port =
			inet_port_requires_bind_service(sock_net(sk), check->port) ||
			check->port < low || check->port > high;
	} else {
		check->check_port = true;
	}
	return 0;

err_af:
	return sk->sk_protocol == IPPROTO_SCTP ? -EINVAL : -EAFNOSUPPORT;
}

static int selinux_cred_chain_count(const struct cred *cred, u16 *count)
{
	u16 nr = 0;

	while (cred) {
		if (nr >= SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1)
			return -E2BIG;
		nr++;
		cred = selinux_cred(cred)->parent_cred;
	}
	if (!nr)
		return -EINVAL;
	*count = nr;
	return 0;
}

/*
 * Authorize the socket operation and every address-derived check as one AVC
 * transaction.  All storage is allocated before the retry loop; an attempt
 * therefore observes one policy-chain snapshot and emits one aggregate audit.
 */
static int selinux_socket_addresses_has_perm(
	struct sock *sk, enum selinux_socket_address_operation operation,
	struct selinux_socket_address_check *checks, u16 address_count,
	u32 socket_perms, bool require_extsockclass)
{
	const struct cred *cred = current_cred();
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct {
		struct selinux_policy_chain_snapshot chain;
		struct selinux_net_avc_transaction transaction;
	} *scratch __free(kfree) = NULL;
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
	struct selinux_avc_level *levels __free(kvfree) = NULL;
	struct selinux_policy_snapshot *snapshots __free(kvfree) = NULL;
	struct selinux_global_sid_handle **handles __free(kvfree) = NULL;
	struct selinux_label_ref **labels __free(kvfree) = NULL;
	struct selinux_avc_provenance *provenance_slots __free(kvfree) = NULL;
	struct selinux_net_provenance *provenance;
	struct selinux_label_resolution resolution;
	struct selinux_avc_provenance audit_provenance;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	size_t checks_per_policy, total_checks;
	u16 chain_count, capacity;
	unsigned int retry;
	int rc;

	if (!checks || !address_count)
		return -EINVAL;
	rc = selinux_cred_chain_count(cred, &chain_count);
	if (rc)
		return rc;
	checks_per_policy = 1;
	if (check_mul_overflow((size_t)address_count,
				 operation == SELINUX_SOCKET_ADDRESS_BIND ? 2UL : 1UL,
				 &total_checks) ||
	    check_add_overflow(checks_per_policy, total_checks,
			       &checks_per_policy) ||
	    check_mul_overflow((size_t)chain_count, checks_per_policy,
			       &total_checks) ||
	    total_checks > U16_MAX)
		return -E2BIG;
	capacity = total_checks;

	provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
	if (!provenance || !provenance->view || !provenance->subject ||
	    !provenance->subject->label || !provenance->subject->sid_handle) {
		rc = -EACCES;
		goto out_provenance;
	}
	if (READ_ONCE(sksec->sid) != provenance->subject->sid ||
	    sksec->state != provenance->state ||
	    global_sid_handle_sid(provenance->subject->sid_handle) !=
		    provenance->subject->sid) {
		rc = -ESTALE;
		goto out_provenance;
	}
	rc = selinux_label_view_resolve_chain(
		provenance->view, provenance->subject->label,
		provenance->subject->sid, &resolution);
	if (rc)
		goto out_provenance;

	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	levels = kvcalloc(capacity, sizeof(*levels), GFP_KERNEL);
	snapshots = kvcalloc(capacity, sizeof(*snapshots), GFP_KERNEL);
	handles = kvcalloc(capacity, sizeof(*handles), GFP_KERNEL);
	labels = kvcalloc(capacity, sizeof(*labels), GFP_KERNEL);
	provenance_slots = kvcalloc(capacity, sizeof(*provenance_slots),
				    GFP_KERNEL);
	workspace = selinux_avc_transaction_workspace_alloc(capacity,
							    GFP_KERNEL);
	if (!scratch || !levels || !snapshots || !handles || !labels ||
	    !provenance_slots || !workspace) {
		rc = -ENOMEM;
		goto out_provenance;
	}
	scratch->transaction.dynamic_levels = levels;
	scratch->transaction.dynamic_snapshots = snapshots;
	scratch->transaction.dynamic_handles = handles;
	scratch->transaction.dynamic_labels = labels;
	scratch->transaction.dynamic_provenance = provenance_slots;
	scratch->transaction.dynamic_capacity = capacity;
	scratch->transaction.workspace = workspace;
	audit_provenance = (struct selinux_avc_provenance) {
		.label = provenance->subject->label,
		.view = provenance->view,
		.source = provenance->subject->source,
	};

	ad_net_init_from_sk(&ad, &net, sk);
	/* A multi-address audit must not attribute a denial to the wrong peer. */
	if (address_count == 1 && checks[0].family) {
		ad.u.net->family = checks[0].family;
		if (operation == SELINUX_SOCKET_ADDRESS_BIND)
			ad.u.net->sport = htons(checks[0].port);
		else
			ad.u.net->dport = htons(checks[0].port);
		if (operation == SELINUX_SOCKET_ADDRESS_BIND && checks[0].node &&
		    checks[0].family == AF_INET)
			ad.u.net->v4info.saddr =
				*(const __be32 *)checks[0].node;
		else if (operation == SELINUX_SOCKET_ADDRESS_BIND &&
			 checks[0].node && checks[0].family == AF_INET6)
			ad.u.net->v6info.saddr =
				*(const struct in6_addr *)checks[0].node;
	}

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i, j;

		selinux_net_avc_transaction_reset(&scratch->transaction);
		rc = selinux_policy_chain_snapshot_read(cred, &scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			goto out_reset;
		if (scratch->chain.count != chain_count) {
			rc = -ESTALE;
			continue;
		}
		if (require_extsockclass &&
		    !selinux_policy_snapshot_has_cap(&scratch->chain.policy[0],
						 POLICYDB_CAP_EXTSOCKCLASS)) {
			rc = 0;
			goto out_reset;
		}

		for (i = 0; i < scratch->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(scratch->chain.cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&scratch->chain.policy[i];
			const struct selinux_label_domain *domain =
				crsec->state->label_domain;
			u16 initial_count = scratch->transaction.count;
			u16 sclass;
			u32 policy_sid;
			u32 address_perm;

			if (!domain || domain->depth > resolution.max_depth ||
			    resolution.domain_id[domain->depth] != domain->id ||
			    !resolution.sid[domain->depth]) {
				rc = -EOPNOTSUPP;
				break;
			}
			policy_sid = resolution.sid[domain->depth];
			sclass = socket_class_for_snapshot(
				snapshot, sk->sk_family, sk->sk_type,
				sk->sk_protocol);
			if (!sock_skip_has_perm(snapshot, policy_sid)) {
				rc = selinux_net_avc_transaction_add(
					&scratch->transaction,
					&(struct selinux_avc_level) {
						.state = crsec->state,
						.ssid = crsec->sid,
						.tsid = policy_sid,
						.requested = socket_perms,
						.tclass = sclass,
						.provenance = &audit_provenance,
					}, snapshot, NULL);
				if (rc)
					break;
			}

			if (operation == SELINUX_SOCKET_ADDRESS_BIND) {
				switch (sksec->sclass) {
				case SECCLASS_TCP_SOCKET:
					address_perm = TCP_SOCKET__NODE_BIND;
					break;
				case SECCLASS_UDP_SOCKET:
					address_perm = UDP_SOCKET__NODE_BIND;
					break;
				case SECCLASS_SCTP_SOCKET:
					address_perm = SCTP_SOCKET__NODE_BIND;
					break;
				default:
					address_perm = RAWIP_SOCKET__NODE_BIND;
					break;
				}
			} else if (sksec->sclass == SECCLASS_SCTP_SOCKET) {
				address_perm = SCTP_SOCKET__NAME_CONNECT;
			} else {
				address_perm = TCP_SOCKET__NAME_CONNECT;
			}

			for (j = 0; j < address_count; j++) {
				struct selinux_global_sid_handle *handle;
				u32 sid;

				if (checks[j].check_port) {
					handle = sel_netport_sid_snapshot_handle(
						crsec->state, snapshot,
						sk->sk_protocol, checks[j].port,
						&sid);
					if (IS_ERR(handle)) {
						rc = PTR_ERR(handle);
						break;
					}
					rc = selinux_net_avc_transaction_add_handle(
						&scratch->transaction,
						&(struct selinux_avc_level) {
							.state = crsec->state,
							.ssid = policy_sid,
							.tsid = sid,
							.requested = operation ==
								SELINUX_SOCKET_ADDRESS_BIND ?
								SOCKET__NAME_BIND :
								address_perm,
							.tclass = sclass,
						}, snapshot, handle,
						provenance->view,
						SELINUX_LABEL_SOURCE_SECURITY_CONTEXT);
					if (rc)
						break;
				}
				if (!checks[j].check_node)
					continue;
				handle = sel_netnode_sid_snapshot_handle(
					crsec->state, snapshot, checks[j].node,
					checks[j].family, &sid);
				if (IS_ERR(handle)) {
					rc = PTR_ERR(handle);
					break;
				}
				rc = selinux_net_avc_transaction_add_handle(
					&scratch->transaction,
					&(struct selinux_avc_level) {
						.state = crsec->state,
						.ssid = policy_sid,
						.tsid = sid,
						.requested = address_perm,
						.tclass = sclass,
					}, snapshot, handle, provenance->view,
					SELINUX_LABEL_SOURCE_SECURITY_CONTEXT);
				if (rc)
					break;
			}
			if (rc)
				break;
			rc = selinux_net_avc_transaction_add_guard(
				&scratch->transaction, initial_count, crsec->state,
				snapshot);
			if (rc)
				break;
		}
		if (!rc)
			rc = selinux_net_avc_transaction_decide(
				&scratch->transaction, &ad);
		if (rc == -ESTALE)
			continue;
		goto out_reset;
	}
	rc = -ESTALE;

out_reset:
	selinux_net_avc_transaction_reset(&scratch->transaction);
out_provenance:
	selinux_net_provenance_put(provenance);
	return rc;
}
#endif

static int __selinux_socket_bind(struct sock *sk, struct sockaddr *address, int addrlen)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_socket_address_check check;
	int err;

	err = selinux_socket_address_prepare(
		sk, SELINUX_SOCKET_ADDRESS_BIND, address, addrlen, &check);
	if (err)
		return err;
	return selinux_socket_addresses_has_perm(
		sk, SELINUX_SOCKET_ADDRESS_BIND, &check, 1, SOCKET__BIND, false);
#else
	const struct cred *cred = current_cred();
	struct sk_security_struct *sksec = selinux_sock(sk);
	u16 family;
	int err;

	err = sock_has_perm(sk, SOCKET__BIND);
	if (err)
		goto out;

	/* If PF_INET or PF_INET6, check name_bind permission for the port. */
	family = sk->sk_family;
	if (family == PF_INET || family == PF_INET6) {
		char *addrp;
		struct common_audit_data ad;
		struct lsm_network_audit net = {0,};
		struct sockaddr_in *addr4 = NULL;
		struct sockaddr_in6 *addr6 = NULL;
		u16 family_sa;
		unsigned short snum;
		u32 node_perm;
		u32 sid;

		/*
		 * sctp_bindx(3) calls via selinux_sctp_bind_connect()
		 * that validates multiple binding addresses. Because of this
		 * need to check address->sa_family as it is possible to have
		 * sk->sk_family = PF_INET6 with addr->sa_family = AF_INET.
		 */
		if (addrlen < offsetofend(struct sockaddr, sa_family))
			return -EINVAL;
		family_sa = address->sa_family;
		switch (family_sa) {
		case AF_UNSPEC:
		case AF_INET:
			if (addrlen < sizeof(struct sockaddr_in))
				return -EINVAL;
			addr4 = (struct sockaddr_in *)address;
			if (family_sa == AF_UNSPEC) {
				if (family == PF_INET6) {
					/* Length check from inet6_bind_sk() */
					if (addrlen < SIN6_LEN_RFC2133)
						return -EINVAL;
					/* Family check from __inet6_bind() */
					goto err_af;
				}
				/* see __inet_bind(), we only want to allow
				 * AF_UNSPEC if the address is INADDR_ANY
				 */
				if (addr4->sin_addr.s_addr != htonl(INADDR_ANY))
					goto err_af;
				family_sa = AF_INET;
			}
			snum = ntohs(addr4->sin_port);
			addrp = (char *)&addr4->sin_addr.s_addr;
			break;
		case AF_INET6:
			if (addrlen < SIN6_LEN_RFC2133)
				return -EINVAL;
			addr6 = (struct sockaddr_in6 *)address;
			snum = ntohs(addr6->sin6_port);
			addrp = (char *)&addr6->sin6_addr.s6_addr;
			break;
		default:
			goto err_af;
		}

		ad.type = LSM_AUDIT_DATA_NET;
		ad.u.net = &net;
		ad.u.net->sport = htons(snum);
		ad.u.net->family = family_sa;

		if (snum) {
			int low, high;

			inet_get_local_port_range(sock_net(sk), &low, &high);

			if (inet_port_requires_bind_service(sock_net(sk), snum) ||
			    snum < low || snum > high) {
				err = cred_port_has_perm(cred, sk, sksec->sid,
						     sk->sk_protocol, snum,
						     sksec->sclass,
						     SOCKET__NAME_BIND, &ad);
				if (err)
					goto out;
			}
		}

		switch (sksec->sclass) {
		case SECCLASS_TCP_SOCKET:
			node_perm = TCP_SOCKET__NODE_BIND;
			break;

		case SECCLASS_UDP_SOCKET:
			node_perm = UDP_SOCKET__NODE_BIND;
			break;

		case SECCLASS_SCTP_SOCKET:
			node_perm = SCTP_SOCKET__NODE_BIND;
			break;

		default:
			node_perm = RAWIP_SOCKET__NODE_BIND;
			break;
		}

		if (family_sa == AF_INET)
			ad.u.net->v4info.saddr = addr4->sin_addr.s_addr;
		else
			ad.u.net->v6info.saddr = addr6->sin6_addr;

		err = sel_netnode_sid(current_selinux_state, addrp, family_sa,
				      &sid);
		if (err)
			goto out;
		err = cred_ssid_has_perm(cred, sksec->sid, sid, sksec->sclass,
					 node_perm, &ad);
		if (err)
			goto out;
	}
out:
	return err;
err_af:
	/* Note that SCTP services expect -EINVAL, others -EAFNOSUPPORT. */
	if (sk->sk_protocol == IPPROTO_SCTP)
		return -EINVAL;
	return -EAFNOSUPPORT;
#endif
}

static int selinux_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
	return __selinux_socket_bind(sock->sk, address, addrlen);
}

/* This supports connect(2) and SCTP connect services such as sctp_connectx(3)
 * and sctp_sendmsg(3) as described in Documentation/security/SCTP.rst
 */
static int selinux_socket_connect_helper(struct sock *sk,
					 struct sockaddr *address, int addrlen)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_socket_address_check check;
	int err;

	err = selinux_socket_address_prepare(
		sk, SELINUX_SOCKET_ADDRESS_CONNECT, address, addrlen, &check);
	if (err)
		return err;
	return selinux_socket_addresses_has_perm(
		sk, SELINUX_SOCKET_ADDRESS_CONNECT, &check, 1,
		SOCKET__CONNECT, false);
#else
	const struct cred *cred = current_cred();
	struct sk_security_struct *sksec = selinux_sock(sk);
	int err;

	err = sock_has_perm(sk, SOCKET__CONNECT);
	if (err)
		return err;
	if (addrlen < offsetofend(struct sockaddr, sa_family))
		return -EINVAL;

	/* connect(AF_UNSPEC) has special handling, as it is a documented
	 * way to disconnect the socket
	 */
	if (address->sa_family == AF_UNSPEC)
		return 0;

	/*
	 * If a TCP or SCTP socket, check name_connect permission
	 * for the port.
	 */
	if (sksec->sclass == SECCLASS_TCP_SOCKET ||
	    sksec->sclass == SECCLASS_SCTP_SOCKET) {
		struct common_audit_data ad;
		struct lsm_network_audit net = {0,};
		struct sockaddr_in *addr4 = NULL;
		struct sockaddr_in6 *addr6 = NULL;
		unsigned short snum;
		u32 perm;

		/* sctp_connectx(3) calls via selinux_sctp_bind_connect()
		 * that validates multiple connect addresses. Because of this
		 * need to check address->sa_family as it is possible to have
		 * sk->sk_family = PF_INET6 with addr->sa_family = AF_INET.
		 */
		switch (address->sa_family) {
		case AF_INET:
			addr4 = (struct sockaddr_in *)address;
			if (addrlen < sizeof(struct sockaddr_in))
				return -EINVAL;
			snum = ntohs(addr4->sin_port);
			break;
		case AF_INET6:
			addr6 = (struct sockaddr_in6 *)address;
			if (addrlen < SIN6_LEN_RFC2133)
				return -EINVAL;
			snum = ntohs(addr6->sin6_port);
			break;
		default:
			/* Note that SCTP services expect -EINVAL, whereas
			 * others expect -EAFNOSUPPORT.
			 */
			if (sksec->sclass == SECCLASS_SCTP_SOCKET)
				return -EINVAL;
			else
				return -EAFNOSUPPORT;
		}

		switch (sksec->sclass) {
		case SECCLASS_TCP_SOCKET:
			perm = TCP_SOCKET__NAME_CONNECT;
			break;
		case SECCLASS_SCTP_SOCKET:
			perm = SCTP_SOCKET__NAME_CONNECT;
			break;
		}

		ad.type = LSM_AUDIT_DATA_NET;
		ad.u.net = &net;
		ad.u.net->dport = htons(snum);
		ad.u.net->family = address->sa_family;
		err = cred_port_has_perm(cred, sk, sksec->sid, sk->sk_protocol,
					 snum, sksec->sclass, perm, &ad);
		if (err)
			return err;
	}

	return 0;
#endif
}

/* Supports connect(2), see comments in selinux_socket_connect_helper() */
static int selinux_socket_connect(struct socket *sock,
				  struct sockaddr *address, int addrlen)
{
	int err;
	struct sock *sk = sock->sk;

	err = selinux_socket_connect_helper(sk, address, addrlen);
	if (err)
		return err;

	return selinux_netlbl_socket_connect(sk, address);
}

static int selinux_socket_listen(struct socket *sock, int backlog)
{
	return sock_has_perm(sock->sk, SOCKET__LISTEN);
}

static int selinux_socket_accept(struct socket *sock, struct socket *newsock)
{
	int err;
	struct inode_security_struct *isec;
	struct inode_security_struct *newisec;
	u16 sclass;
	u32 sid;

	err = sock_has_perm(sock->sk, SOCKET__ACCEPT);
	if (err)
		return err;

	isec = inode_security_novalidate(SOCK_INODE(sock));
	spin_lock(&isec->lock);
	sclass = isec->sclass;
	sid = isec->sid;
	spin_unlock(&isec->lock);

	newisec = inode_security_novalidate(SOCK_INODE(newsock));
	return inode_security_set_sid_class(newisec, sid, sclass,
					    SELINUX_LABEL_SOURCE_SOCKET,
					    LABEL_INITIALIZED);
}

static int selinux_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				  int size)
{
	int rc;
	struct sockaddr *const addr = msg->msg_name;
	const int addrlen = msg->msg_namelen;

	if (addr && (msg->msg_flags & MSG_FASTOPEN) &&
	    (sk_is_tcp(sock->sk) ||
	     (sk_is_inet(sock->sk) && sock->sk->sk_type == SOCK_STREAM &&
	      sock->sk->sk_protocol == IPPROTO_MPTCP))) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		struct selinux_socket_address_check check;

		rc = selinux_socket_address_prepare(
			sock->sk, SELINUX_SOCKET_ADDRESS_CONNECT, addr, addrlen,
			&check);
		if (rc)
			return rc;
		rc = selinux_socket_addresses_has_perm(
			sock->sk, SELINUX_SOCKET_ADDRESS_CONNECT, &check, 1,
			SOCKET__WRITE | SOCKET__CONNECT, false);
		if (rc)
			return rc;
		rc = selinux_netlbl_socket_connect(sock->sk, addr);
#else
		rc = sock_has_perm(sock->sk, SOCKET__WRITE);
		if (rc)
			return rc;
		rc = selinux_socket_connect(sock, addr, addrlen);
#endif
		if (rc)
			return rc;
	} else {
		rc = sock_has_perm(sock->sk, SOCKET__WRITE);
		if (rc)
			return rc;
	}

	return 0;
}

static int selinux_socket_recvmsg(struct socket *sock, struct msghdr *msg,
				  int size, int flags)
{
	return sock_has_perm(sock->sk, SOCKET__READ);
}

static int selinux_socket_getsockname(struct socket *sock)
{
	return sock_has_perm(sock->sk, SOCKET__GETATTR);
}

static int selinux_socket_getpeername(struct socket *sock)
{
	return sock_has_perm(sock->sk, SOCKET__GETATTR);
}

static int selinux_socket_setsockopt(struct socket *sock, int level, int optname)
{
	int err;

	err = sock_has_perm(sock->sk, SOCKET__SETOPT);
	if (err)
		return err;

	return selinux_netlbl_socket_setsockopt(sock, level, optname);
}

static int selinux_socket_getsockopt(struct socket *sock, int level,
				     int optname)
{
	return sock_has_perm(sock->sk, SOCKET__GETOPT);
}

static int selinux_socket_shutdown(struct socket *sock, int how)
{
	return sock_has_perm(sock->sk, SOCKET__SHUTDOWN);
}

static int selinux_socket_unix_stream_connect(struct sock *sock,
					      struct sock *other,
					      struct sock *newsk)
{
	const struct cred *cred = current_cred();
	struct sk_security_struct *sksec_sock = selinux_sock(sock);
	struct sk_security_struct *sksec_other = selinux_sock(other);
	struct sk_security_struct *sksec_new = selinux_sock(newsk);
	struct common_audit_data ad;
	struct lsm_network_audit net;
	int err;

	ad_net_init_from_sk(&ad, &net, other);

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		struct selinux_net_provenance *sock_provenance, *other_provenance;
		struct selinux_net_provenance *child = NULL;
		struct {
			struct selinux_policy_chain_snapshot access_chain;
			struct selinux_policy_state_chain_snapshot child_chain;
			struct selinux_net_avc_transaction transaction;
			u32 child_sid[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
			struct selinux_global_sid_handle
				*child_handle[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
		} *scratch __free(kfree) = NULL;
		struct selinux_avc_transaction_workspace *workspace
			__free(kvfree) = NULL;
		unsigned int retry;

		sock_provenance = selinux_net_provenance_get_rcu(
			&sksec_sock->provenance);
		other_provenance = selinux_net_provenance_get_rcu(
			&sksec_other->provenance);
		if (!sock_provenance || !other_provenance ||
		    !sock_provenance->subject || !sock_provenance->view ||
		    !other_provenance->subject || !other_provenance->view ||
		    sock_provenance->state != sksec_sock->state ||
		    other_provenance->state != sksec_other->state ||
		    sock_provenance->subject->sid != sksec_sock->sid ||
		    other_provenance->subject->sid != sksec_other->sid) {
			err = -EXDEV;
			goto out_unix_provenance;
		}
		scratch = kzalloc_obj(*scratch, GFP_ATOMIC);
		if (!scratch) {
			err = -ENOMEM;
			goto out_unix_provenance;
		}
		workspace = selinux_avc_transaction_workspace_alloc(
			SELINUX_NET_AVC_MAX_CHECKS, GFP_ATOMIC | __GFP_NOWARN);
		if (!workspace) {
			err = -ENOMEM;
			goto out_unix_provenance;
		}
		scratch->transaction.workspace = workspace;
		for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
			u16 i;

			for (i = 0; i < ARRAY_SIZE(scratch->child_handle); i++) {
				global_sid_handle_put(scratch->child_handle[i]);
				scratch->child_handle[i] = NULL;
			}
			selinux_net_provenance_put(child);
			child = NULL;
			selinux_net_avc_transaction_reset(&scratch->transaction);
			err = selinux_policy_chain_snapshot_read(
				cred, &scratch->access_chain);
			if (err == -EAGAIN || err == -ESTALE)
				continue;
			if (err)
				break;
			err = selinux_policy_state_chain_snapshot_read(
				other_provenance->state, &scratch->child_chain);
			if (err == -EAGAIN || err == -ESTALE)
				continue;
			if (err)
				break;
			for (i = 0; i < scratch->access_chain.count; i++) {
				const struct cred_security_struct *crsec = selinux_cred(
					scratch->access_chain.cred[i]);
				const struct selinux_policy_snapshot *snapshot =
					&scratch->access_chain.policy[i];
				struct selinux_state *policy_state = crsec->state;
				u32 client_sid, server_sid;
				u16 sclass;

				err = selinux_net_avc_transaction_provenance_sid(
					&scratch->transaction, sock_provenance,
					policy_state->label_domain, &client_sid);
				if (err)
					break;
				err = selinux_net_avc_transaction_provenance_sid(
					&scratch->transaction, other_provenance,
					policy_state->label_domain, &server_sid);
				if (err)
					break;
				sclass = socket_class_for_snapshot(
					snapshot, other->sk_family, other->sk_type,
					other->sk_protocol);
				err = selinux_net_avc_transaction_add_provenance(
					&scratch->transaction,
					&(struct selinux_avc_level) {
						.state = policy_state,
						.ssid = client_sid,
						.tsid = server_sid,
						.requested =
							UNIX_STREAM_SOCKET__CONNECTTO,
						.tclass = sclass,
					}, snapshot, other_provenance);
				if (err)
					break;
			}
			if (err)
				goto retry_unix;
			for (i = 0; i < scratch->child_chain.count; i++) {
				struct selinux_state *policy_state =
					scratch->child_chain.state[i];
				u32 client_sid, server_sid;

				err = selinux_net_avc_transaction_provenance_sid(
					&scratch->transaction, sock_provenance,
					policy_state->label_domain, &client_sid);
				if (err)
					break;
				err = selinux_net_avc_transaction_provenance_sid(
					&scratch->transaction, other_provenance,
					policy_state->label_domain, &server_sid);
				if (err)
					break;
				scratch->child_handle[i] = selinux_conn_sid_handle(
					server_sid, client_sid, policy_state,
					&scratch->child_sid[i]);
				if (IS_ERR(scratch->child_handle[i])) {
					err = PTR_ERR(scratch->child_handle[i]);
					scratch->child_handle[i] = NULL;
					break;
				}
			}
			if (err)
				goto retry_unix;
			child = selinux_net_provenance_derive_handle(
				other_provenance, scratch->child_handle[0],
				sksec_other->sclass,
				SELINUX_NET_ASSERTION_SOURCE_SOCKET, GFP_ATOMIC);
			scratch->child_handle[0] = NULL;
			if (IS_ERR(child)) {
				err = PTR_ERR(child);
				child = NULL;
				break;
			}
			err = selinux_net_provenance_projection_matches(
				&scratch->transaction, child, &scratch->child_chain,
				scratch->child_sid);
			if (!err)
				err = selinux_net_avc_transaction_decide(
					&scratch->transaction, &ad);
			if (!err &&
			    (!selinux_policy_chain_snapshot_valid(
				     &scratch->access_chain) ||
			     !selinux_policy_state_chain_snapshot_valid(
				     &scratch->child_chain)))
				err = -ESTALE;

retry_unix:
			if (err == -EAGAIN || err == -ESTALE)
				continue;
			break;
		}
		if (err)
			goto out_unix_candidate;

		selinux_sk_provenance_free(sksec_new);
		RCU_INIT_POINTER(sksec_new->provenance, child);
		RCU_INIT_POINTER(sksec_new->peer_provenance,
				 selinux_net_provenance_get(sock_provenance));
		if (sksec_new->state != child->state) {
			put_selinux_state(sksec_new->state);
			sksec_new->state = get_selinux_state(child->state);
		}
		sksec_new->sid = child->subject->sid;
		sksec_new->peer_sid = sock_provenance->subject->sid;
		selinux_sk_peer_provenance_replace(
			sksec_sock, selinux_net_provenance_get(child));
		child = NULL;
		err = 0;

out_unix_candidate:
		selinux_net_avc_transaction_reset(&scratch->transaction);
		{
			u16 i;

			for (i = 0; i < ARRAY_SIZE(scratch->child_handle); i++)
				global_sid_handle_put(scratch->child_handle[i]);
		}
		selinux_net_provenance_put(child);
out_unix_provenance:
		selinux_net_provenance_put(other_provenance);
		selinux_net_provenance_put(sock_provenance);
		return err;
	}
#else
	err = cred_ssid_has_perm(cred, sksec_sock->sid, sksec_other->sid,
				 sksec_other->sclass,
				 UNIX_STREAM_SOCKET__CONNECTTO, &ad);
	if (err)
		return err;

	/* server child socket */
	sksec_new->peer_sid = sksec_sock->sid;
	err = security_sid_mls_copy(current_selinux_state, sksec_other->sid,
				    sksec_sock->sid, &sksec_new->sid);
	if (err)
		return err;

	/* connecting socket */
	sksec_sock->peer_sid = sksec_new->sid;

	return 0;
#endif
}

static int selinux_socket_unix_may_send(struct socket *sock,
					struct socket *other)
{
	const struct cred *cred = current_cred();
	struct sk_security_struct *ssec = selinux_sock(sock->sk);
	struct sk_security_struct *osec = selinux_sock(other->sk);
	struct common_audit_data ad;
	struct lsm_network_audit net;

	ad_net_init_from_sk(&ad, &net, other->sk);

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		struct selinux_net_provenance *source_provenance;
		struct selinux_net_provenance *other_provenance;
		int rc;

		source_provenance = selinux_net_provenance_get_rcu(
			&ssec->provenance);
		other_provenance = selinux_net_provenance_get_rcu(
			&osec->provenance);
		if (!source_provenance || !other_provenance ||
		    source_provenance->subject->sid != ssec->sid ||
		    other_provenance->subject->sid != osec->sid) {
			selinux_net_provenance_put(other_provenance);
			selinux_net_provenance_put(source_provenance);
			return -EACCES;
		}
		rc = selinux_net_provenances_has_perm(
			cred, source_provenance, other_provenance, other->sk,
			SOCKET__SENDTO, &ad);
		selinux_net_provenance_put(other_provenance);
		selinux_net_provenance_put(source_provenance);
		return rc;
	}
#else
	return cred_ssid_has_perm(cred, ssec->sid, osec->sid, osec->sclass,
				  SOCKET__SENDTO, &ad);
#endif
}

#ifndef CONFIG_SECURITY_SELINUX_NS
static int
selinux_inet_sys_rcv_skb(struct selinux_state *state,
			 const struct selinux_policy_snapshot *snapshot,
			 struct net *ns, int ifindex, char *addrp, u16 family,
			 u32 peer_sid, struct common_audit_data *ad)
{
	int err;
	u32 if_sid;
	u32 node_sid;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *if_handle;
	struct selinux_global_sid_handle *node_handle;
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
	if_handle = sel_netif_sid_snapshot_handle(state, snapshot, ns, ifindex,
						    &if_sid);
	if (IS_ERR(if_handle))
		return PTR_ERR(if_handle);
#else
	err = sel_netif_sid_snapshot(state, snapshot, ns, ifindex, &if_sid);
	if (err)
		return err;
#endif
	err = avc_has_perm_snapshot(state, snapshot, peer_sid, if_sid,
				    SECCLASS_NETIF, NETIF__INGRESS, ad);
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(if_handle);
#endif
	if (err)
		return err;

#ifdef CONFIG_SECURITY_SELINUX_NS
	node_handle = sel_netnode_sid_snapshot_handle(state, snapshot, addrp,
						       family, &node_sid);
	if (IS_ERR(node_handle))
		return PTR_ERR(node_handle);
#else
	err = sel_netnode_sid_snapshot(state, snapshot, addrp, family, &node_sid);
	if (err)
		return err;
#endif
	err = avc_has_perm_snapshot(state, snapshot, peer_sid, node_sid,
				    SECCLASS_NODE, NODE__RECVFROM, ad);
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(node_handle);
#endif
	return err;
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_inet_sys_rcv_skb_add(
	struct selinux_net_avc_transaction *transaction,
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot,
	const struct selinux_label_view *view, struct net *ns, int ifindex,
	char *addrp, u16 family, u32 peer_sid)
{
	struct selinux_global_sid_handle *handle;
	struct selinux_avc_level level = {
		.state = state,
		.ssid = peer_sid,
	};
	u32 sid;
	int rc;

	handle = sel_netif_sid_snapshot_handle(state, snapshot, ns, ifindex,
					       &sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	level.tsid = sid;
	level.requested = NETIF__INGRESS;
	level.tclass = SECCLASS_NETIF;
	rc = selinux_net_avc_transaction_add_handle(
		transaction, &level, snapshot, handle, view,
		SELINUX_LABEL_SOURCE_SECURITY_CONTEXT);
	if (rc)
		return rc;

	handle = sel_netnode_sid_snapshot_handle(state, snapshot, addrp, family,
						 &sid);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	level.tsid = sid;
	level.requested = NODE__RECVFROM;
	level.tclass = SECCLASS_NODE;
	return selinux_net_avc_transaction_add_handle(
		transaction, &level, snapshot, handle, view,
		SELINUX_LABEL_SOURCE_SECURITY_CONTEXT);
}
#endif

#ifndef CONFIG_SECURITY_SELINUX_NS
static int
selinux_sock_rcv_skb_compat(struct sock *sk, struct sk_buff *skb, u16 family,
			    const struct selinux_policy_snapshot *snapshot)
{
	int err = 0;
	struct sk_security_struct *sksec = selinux_sock(sk);
	u32 sk_sid = sksec->sid;
	struct selinux_state *state = sksec->state;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	char *addrp;

	ad_net_init_from_iif(&ad, &net, skb->skb_iif, family);
	err = selinux_parse_skb(skb, &ad, &addrp, 1, NULL);
	if (err)
		return err;

	if (selinux_secmark_enabled(snapshot)) {
		err = avc_has_perm_snapshot(state, snapshot, sk_sid,
					    skb->secmark, SECCLASS_PACKET,
					    PACKET__RECV, &ad);
		if (err)
			return err;
	}

	err = selinux_netlbl_sock_rcv_skb(sksec, skb, family, &ad);
	if (err)
		return err;
	err = selinux_xfrm_sock_rcv_skb(sksec, skb, &ad);
	if (!err && !selinux_policy_snapshot_valid(state, snapshot))
		err = -ESTALE;

	return err;
}

static int
selinux_socket_sock_rcv_skb_snapshot(
	struct sock *sk, struct sk_buff *skb, u16 family,
	const struct selinux_policy_snapshot *snapshot)
{
	int err, peerlbl_active, secmark_active;
	struct sk_security_struct *sksec = selinux_sock(sk);
	u32 sk_sid = sksec->sid;
	struct selinux_state *state = sksec->state;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	char *addrp;

	/* If any sort of compatibility mode is enabled then handoff processing
	 * to the selinux_sock_rcv_skb_compat() function to deal with the
	 * special handling.  We do this in an attempt to keep this function
	 * as fast and as clean as possible. */
	if (!selinux_policy_snapshot_has_cap(snapshot, POLICYDB_CAP_NETPEER))
		return selinux_sock_rcv_skb_compat(sk, skb, family, snapshot);

	secmark_active = selinux_secmark_enabled(snapshot);
	peerlbl_active = selinux_peerlbl_enabled(snapshot);
	if (!secmark_active && !peerlbl_active)
		return selinux_policy_snapshot_valid(state, snapshot) ? 0 :
								 -ESTALE;

	ad_net_init_from_iif(&ad, &net, skb->skb_iif, family);
	err = selinux_parse_skb(skb, &ad, &addrp, 1, NULL);
	if (err)
		return err;

	if (peerlbl_active) {
		u32 peer_sid;

		err = selinux_skb_peerlbl_sid(skb, family, state, &peer_sid);
		if (err)
			return err;
		err = selinux_inet_sys_rcv_skb(state, snapshot, sock_net(sk),
					       skb->skb_iif, addrp, family,
					       peer_sid, &ad);
		if (err) {
			selinux_netlbl_err(skb, family, err, 0);
			return err;
		}
		err = avc_has_perm_snapshot(state, snapshot, sk_sid, peer_sid,
					    SECCLASS_PEER, PEER__RECV, &ad);
		if (err) {
			selinux_netlbl_err(skb, family, err, 0);
			return err;
		}
	}

	if (secmark_active) {
		err = avc_has_perm_snapshot(state, snapshot, sk_sid,
					    skb->secmark, SECCLASS_PACKET,
					    PACKET__RECV, &ad);
		if (err)
			return err;
	}

	return selinux_policy_snapshot_valid(state, snapshot) ? err : -ESTALE;
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_socket_sock_rcv_skb_policy(
	struct sock *sk, struct sk_buff *skb, u16 family,
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, u32 sk_sid,
	const struct selinux_peer_sources *sources,
	const struct selinux_label_view *view,
	struct selinux_net_avc_transaction *transaction,
	struct common_audit_data *ad, bool *netlbl_checked)
{
	u32 nlbl_sid, xfrm_sid;
	char *addrp;
	int err;

	err = selinux_parse_skb(skb, ad, &addrp, 1, NULL);
	if (err)
		return err;

	if (selinux_secmark_enabled(snapshot)) {
		u32 secmark_sid;

		err = selinux_skb_secmark_sid(skb, state, transaction,
					     &secmark_sid);
		if (err)
			return err;
		err = selinux_net_avc_transaction_add_provenance(
			transaction,
			&(struct selinux_avc_level) {
				.state = state,
				.ssid = sk_sid,
				.tsid = secmark_sid,
				.requested = PACKET__RECV,
				.tclass = SECCLASS_PACKET,
			}, snapshot, skb->secmark_provenance);
		if (err)
			return err;
	}

	if (selinux_policy_snapshot_has_cap(snapshot, POLICYDB_CAP_NETPEER)) {
		struct selinux_global_sid_handle *peer_handle;
		u32 peer_sid;

		if (!selinux_peerlbl_enabled(snapshot))
			return 0;
		peer_handle = selinux_net_avc_transaction_peer_sources_handle(
			transaction, sources, state, &peer_sid);
		if (IS_ERR(peer_handle))
			return PTR_ERR(peer_handle);
		err = selinux_inet_sys_rcv_skb_add(
			transaction, state, snapshot, view, sock_net(sk),
			skb->skb_iif, addrp, family, peer_sid);
		if (err) {
			global_sid_handle_put(peer_handle);
			goto peer_error;
		}
		err = selinux_net_avc_transaction_add_handle(
			transaction,
			&(struct selinux_avc_level) {
				.state = state,
				.ssid = sk_sid,
				.tsid = peer_sid,
				.requested = PEER__RECV,
				.tclass = SECCLASS_PEER,
			}, snapshot, peer_handle, view,
			SELINUX_NET_ASSERTION_SOURCE_PEER_RESOLVED);
		if (err)
			goto peer_error;
		return 0;
	}

	/* Legacy policies authorize the two native label sources separately. */
	{
		struct selinux_global_sid_handle *nlbl_handle;

		nlbl_handle =
			selinux_net_avc_transaction_peer_sources_native_handle(
				transaction, sources, state, &nlbl_sid, &xfrm_sid);
		if (IS_ERR(nlbl_handle))
			return PTR_ERR(nlbl_handle);
	if (netlbl_enabled()) {
		u16 sclass = socket_class_for_snapshot(
			snapshot, sk->sk_family, sk->sk_type, sk->sk_protocol);
		u32 perm;

		if (!sources->netlabel.cache)
			nlbl_sid = SECINITSID_UNLABELED;
		switch (sclass) {
		case SECCLASS_UDP_SOCKET:
			perm = UDP_SOCKET__RECVFROM;
			break;
		case SECCLASS_TCP_SOCKET:
			perm = TCP_SOCKET__RECVFROM;
			break;
		default:
			perm = RAWIP_SOCKET__RECVFROM;
			break;
		}
		if (sources->netlabel.cache) {
			struct selinux_global_sid_handle *consumed = nlbl_handle;

			nlbl_handle = NULL;
			err = selinux_net_avc_transaction_add_handle(
					transaction,
					&(struct selinux_avc_level) {
						.state = state,
						.ssid = sk_sid,
						.tsid = nlbl_sid,
						.requested = perm,
						.tclass = sclass,
					}, snapshot, consumed,
					sources->netlabel.view,
					SELINUX_NET_ASSERTION_SOURCE_NETLABEL);
		} else {
			err = selinux_net_avc_transaction_add(
				transaction,
				&(struct selinux_avc_level) {
					.state = state,
					.ssid = sk_sid,
					.tsid = nlbl_sid,
					.requested = perm,
					.tclass = sclass,
				}, snapshot, NULL);
		}
		if (err) {
			global_sid_handle_put(nlbl_handle);
			if (sources->netlabel.cache)
				*netlbl_checked = true;
			return err;
		}
		if (sources->netlabel.cache)
			*netlbl_checked = true;
	}
		global_sid_handle_put(nlbl_handle);
	}
	if (IS_ENABLED(CONFIG_SECURITY_NETWORK_XFRM)) {
		if (!sources->xfrm)
			return selinux_net_avc_transaction_add(
				transaction,
				&(struct selinux_avc_level) {
					.state = state,
					.ssid = sk_sid,
					.tsid = SECINITSID_UNLABELED,
					.requested = ASSOCIATION__RECVFROM,
					.tclass = SECCLASS_ASSOCIATION,
				}, snapshot, NULL);
		return selinux_net_avc_transaction_add_provenance(
			transaction,
			&(struct selinux_avc_level) {
				.state = state,
				.ssid = sk_sid,
				.tsid = xfrm_sid,
				.requested = ASSOCIATION__RECVFROM,
				.tclass = SECCLASS_ASSOCIATION,
			}, snapshot, sources->xfrm);
	}
	return 0;

peer_error:
	*netlbl_checked = true;
	return err;
}

static int selinux_socket_sock_rcv_skb_ns(struct sock *sk,
					   struct sk_buff *skb, u16 family)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct {
		struct selinux_policy_state_chain_snapshot chain;
		struct selinux_net_avc_transaction transaction;
	} *scratch __free(kfree) = NULL;
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
	struct selinux_policy_state_chain_snapshot *chain;
	struct selinux_label_resolution socket_resolution;
	struct selinux_net_provenance *provenance;
	struct selinux_peer_sources sources;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	const struct selinux_netns_security *netsec;
	struct selinux_state *socket_state;
	unsigned int retry;
	int err;

	provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
	socket_state = provenance ? provenance->state : NULL;
	if (!provenance || !provenance->subject || !provenance->subject->label ||
	    !provenance->view || !socket_state ||
	    socket_state != READ_ONCE(sksec->state) ||
	    provenance->subject->sid != READ_ONCE(sksec->sid)) {
		err = -EACCES;
		goto out_provenance;
	}
	err = selinux_label_view_resolve_chain(
		provenance->view, provenance->subject->label,
		provenance->subject->sid, &socket_resolution);
	if (err)
		goto out_provenance;
	netsec = selinux_netns(sock_net(sk));
	if (!netsec || netsec->state != socket_state || !netsec->view ||
	    netsec->view->origin_domain != socket_state->label_domain) {
		err = -EXDEV;
		goto out_provenance;
	}
	scratch = kzalloc_obj(*scratch, GFP_ATOMIC);
	if (!scratch) {
		err = -ENOMEM;
		goto out_provenance;
	}
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_NET_AVC_MAX_CHECKS, GFP_ATOMIC | __GFP_NOWARN);
	if (!workspace) {
		err = -ENOMEM;
		goto out_provenance;
	}
	scratch->transaction.workspace = workspace;
	chain = &scratch->chain;
	err = selinux_peer_sources_capture(skb, family, socket_state,
					   netsec->view, &sources);
	if (err)
		goto out_provenance;
	ad_net_init_from_iif(&ad, &net, skb->skb_iif, family);

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		bool netlbl_checked = false;
		u16 i;

		selinux_net_avc_transaction_reset(&scratch->transaction);
		err = selinux_policy_state_chain_snapshot_read(socket_state,
							       chain);
		if (err == -EAGAIN || err == -ESTALE)
			continue;
		if (err)
			break;
		for (i = 0, err = 0; i < chain->count; i++) {
			struct selinux_state *state = chain->state[i];
			u16 initial_count = scratch->transaction.count;
			u16 depth = state->depth;

			if (depth > socket_resolution.max_depth ||
			    socket_resolution.domain_id[depth] !=
				    state->label_domain->id ||
			    !socket_resolution.sid[depth]) {
				err = -EOPNOTSUPP;
				break;
			}
			err = selinux_socket_sock_rcv_skb_policy(
				sk, skb, family, state, &chain->policy[i],
				socket_resolution.sid[depth], &sources,
				netsec->view, &scratch->transaction, &ad,
				&netlbl_checked);
			if (err)
				break;
			err = selinux_net_avc_transaction_add_guard(
				&scratch->transaction, initial_count, state,
				&chain->policy[i]);
			if (err)
				break;
		}
		if (err)
			goto retry_or_out;
		if (READ_ONCE(sksec->state) != socket_state ||
		    READ_ONCE(sksec->sid) != provenance->subject->sid ||
		    rcu_access_pointer(sksec->provenance) != provenance) {
			err = -ESTALE;
			continue;
		}
		err = selinux_net_avc_transaction_decide(
			&scratch->transaction, &ad);
retry_or_out:
		if (err == -ESTALE)
			continue;
		if (err && netlbl_checked)
			selinux_netlbl_err(skb, family, err, 0);
		goto out_sources;
	}
	err = -ESTALE;

out_sources:
	selinux_net_avc_transaction_reset(&scratch->transaction);
	selinux_peer_sources_put(&sources);
out_provenance:
	selinux_net_provenance_put(provenance);
	return err;
}
#endif

static int selinux_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	u16 family = sk->sk_family;
#ifndef CONFIG_SECURITY_SELINUX_NS
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct selinux_policy_snapshot snapshot;
	struct selinux_state *state = sksec->state;
	unsigned int retry;
	int err;
#endif

	if (family != PF_INET && family != PF_INET6)
		return 0;

	/* Handle mapped IPv4 packets arriving via IPv6 sockets. */
	if (family == PF_INET6 && skb->protocol == htons(ETH_P_IP))
		family = PF_INET;

#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_socket_sock_rcv_skb_ns(sk, skb, family);
#else
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		err = selinux_policy_snapshot_read(state, &snapshot);
		if (err == -EAGAIN)
			continue;
		if (err)
			return err;
		err = selinux_socket_sock_rcv_skb_snapshot(sk, skb, family,
							    &snapshot);
		if (err != -ESTALE)
			return err;
	}

	return -ESTALE;
#endif
}

static int selinux_socket_getpeersec_stream(struct socket *sock,
					    sockptr_t optval, sockptr_t optlen,
					    unsigned int len)
{
	int err = 0;
	const char *scontext = NULL;
	char *scontext2;
	u32 scontext_len;
	struct sk_security_struct *sksec = selinux_sock(sock->sk);
	u32 peer_sid = SECSID_NULL;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_net_provenance *peer;

	peer = selinux_net_provenance_get_rcu(&sksec->peer_provenance);
	if (!peer)
		return -ENOPROTOOPT;
	if (READ_ONCE(sksec->peer_sid) != peer->subject->sid) {
		err = -ESTALE;
		goto out_peer;
	}
	err = selinux_label_view_resolve(
		peer->view, current_selinux_state->label_domain,
		peer->subject->label, peer->subject->sid, &peer_sid);
	if (err)
		goto out_peer;
#else

	if (sksec->sclass == SECCLASS_UNIX_STREAM_SOCKET ||
	    sksec->sclass == SECCLASS_TCP_SOCKET ||
	    sksec->sclass == SECCLASS_SCTP_SOCKET)
		peer_sid = sksec->peer_sid;
#endif
	if (peer_sid == SECSID_NULL)
		goto no_peer;

	rcu_read_lock();
	err = security_sid_to_context(current_selinux_state, peer_sid, &scontext,
				      &scontext_len);
	if (err)
		goto err_unlock;
	scontext2 = kmemdup(scontext, scontext_len, GFP_ATOMIC);
	if (!scontext2) {
		err = -ENOMEM;
		goto err_unlock;
	}
	rcu_read_unlock();
	if (scontext_len > len) {
		err = -ERANGE;
		goto out_len;
	}

	if (copy_to_sockptr(optval, scontext2, scontext_len))
		err = -EFAULT;
out_len:
	kfree(scontext2);
	if (copy_to_sockptr(optlen, &scontext_len, sizeof(scontext_len)))
		err = -EFAULT;
#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_net_provenance_put(peer);
#endif
	return err;
err_unlock:
	rcu_read_unlock();
#ifdef CONFIG_SECURITY_SELINUX_NS
out_peer:
	selinux_net_provenance_put(peer);
#endif
	return err;
no_peer:
#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_net_provenance_put(peer);
#endif
	return -ENOPROTOOPT;
}

static int selinux_socket_getpeersec_dgram(struct socket *sock,
					   struct sk_buff *skb, u32 *secid)
{
	u32 peer_secid = SECSID_NULL;
	u16 family;

	if (skb && skb->protocol == htons(ETH_P_IP))
		family = PF_INET;
	else if (skb && skb->protocol == htons(ETH_P_IPV6))
		family = PF_INET6;
	else if (sock)
		family = sock->sk->sk_family;
	else {
		*secid = SECSID_NULL;
		return -EINVAL;
	}

	if (sock && family == PF_UNIX) {
		struct inode_security_struct *isec;
		isec = inode_security_novalidate(SOCK_INODE(sock));
		peer_secid = isec->sid;
	} else if (skb) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		struct selinux_global_sid_handle *peer_handle;
		struct selinux_peer_sources sources;
		const struct selinux_label_view *view = NULL;
		int rc;

		if (sock) {
			const struct selinux_netns_security *netsec =
				selinux_netns(sock_net(sock->sk));

			if (netsec)
				view = netsec->view;
		}
		rc = selinux_peer_sources_capture(
			skb, family, current_selinux_state, view, &sources);
		if (!rc) {
			peer_handle = selinux_peer_sources_sid_handle(
				&sources, current_selinux_state, &peer_secid);
			rc = IS_ERR(peer_handle) ? PTR_ERR(peer_handle) : 0;
			if (!IS_ERR(peer_handle))
				global_sid_handle_put(peer_handle);
			selinux_peer_sources_put(&sources);
		}
		if (rc)
			return rc;
#else
		selinux_skb_peerlbl_sid(skb, family, current_selinux_state,
					&peer_secid);
#endif
	}

	*secid = peer_secid;
	if (peer_secid == SECSID_NULL)
		return -ENOPROTOOPT;
	return 0;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_peer_sid_to_secctx(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, u32 sid,
	struct lsm_context *cp)
{
	const char *context;
	char *context_copy;
	u32 context_len;
	int rc;

	rcu_read_lock();
	rc = security_sid_to_context(state, sid, &context, &context_len);
	if (rc)
		goto out_unlock;
	if (!context || !context_len) {
		rc = -EINVAL;
		goto out_unlock;
	}
	context_copy = kmemdup(context, context_len, GFP_ATOMIC);
	if (!context_copy) {
		rc = -ENOMEM;
		goto out_unlock;
	}
	rcu_read_unlock();

	if (!selinux_policy_snapshot_valid(state, snapshot)) {
		kfree(context_copy);
		return -ESTALE;
	}
	cp->context = context_copy;
	cp->len = context_len;
	cp->id = LSM_ID_SELINUX;
	return 0;

out_unlock:
	rcu_read_unlock();
	return rc;
}

/*
 * Return the packet label in the policy namespace of the receiving task.
 * The socket and its network namespace establish the only admissible view;
 * the numeric SID is rendered while it is still explicitly bound to the
 * observer's policy snapshot and is never passed through the ambient secid
 * conversion hook.
 */
static int selinux_socket_getpeersec_dgram_ctx(struct sock *observer,
						struct sk_buff *skb,
						struct lsm_context *cp)
{
	const struct cred *observer_cred = current_cred();
	const struct cred_security_struct *observer_crsec;
	const struct selinux_netns_security *netsec;
	struct selinux_net_provenance *socket_provenance;
	struct selinux_policy_snapshot snapshot;
	struct selinux_peer_sources sources;
	struct sk_security_struct *sksec;
	struct selinux_state *observer_state;
	struct selinux_state *socket_state;
	unsigned int retry;
	u32 socket_sid;
	u32 peer_sid;
	u16 family;
	int rc;

	if (!observer || !skb || !cp)
		return -EINVAL;
	if (skb->protocol == htons(ETH_P_IP))
		family = PF_INET;
	else if (skb->protocol == htons(ETH_P_IPV6))
		family = PF_INET6;
	else
		return -EAFNOSUPPORT;

	observer_crsec = selinux_cred(observer_cred);
	observer_state = observer_crsec->state;
	sksec = selinux_sock(observer);
	socket_provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
	if (!socket_provenance || !socket_provenance->state ||
	    !socket_provenance->view || !socket_provenance->subject ||
	    !socket_provenance->subject->label || !observer_state ||
	    !observer_state->label_domain) {
		rc = -EACCES;
		goto out_provenance;
	}
	socket_state = socket_provenance->state;
	socket_sid = socket_provenance->subject->sid;
	if (socket_state != READ_ONCE(sksec->state) ||
	    socket_sid != READ_ONCE(sksec->sid) ||
	    socket_provenance->subject->semantic_class !=
		    READ_ONCE(sksec->sclass) ||
	    socket_provenance->subject->source !=
		    SELINUX_NET_ASSERTION_SOURCE_SOCKET ||
	    socket_provenance->view->origin_domain !=
		    socket_state->label_domain) {
		rc = -EACCES;
		goto out_provenance;
	}

	netsec = selinux_netns(sock_net(observer));
	if (!netsec || !netsec->state || !netsec->view ||
	    netsec->state != socket_state ||
	    netsec->view->origin_domain != socket_state->label_domain ||
	    netsec->view->owner_userns !=
		    socket_provenance->view->owner_userns ||
	    netsec->view->outer_domain !=
		    socket_provenance->view->outer_domain ||
	    !selinux_mnt_views_share_snapshot(netsec->view,
					       socket_provenance->view)) {
		rc = -EXDEV;
		goto out_provenance;
	}

	/* Prove that this task's policy is part of the observer's sealed view. */
	rc = selinux_label_view_resolve(
		socket_provenance->view, observer_state->label_domain,
		socket_provenance->subject->label, socket_sid, &peer_sid);
	if (rc)
		goto out_provenance;

	/* Native packet carriers are retained once across policy retries. */
	rc = selinux_peer_sources_capture(skb, family, socket_state,
					 netsec->view, &sources);
	if (rc)
		goto out_provenance;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		struct selinux_global_sid_handle *peer_handle;
		struct lsm_context candidate = { };

		rc = selinux_policy_snapshot_read(observer_state, &snapshot);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		peer_handle = selinux_peer_sources_sid_handle(
			&sources, observer_state, &peer_sid);
		rc = IS_ERR(peer_handle) ? PTR_ERR(peer_handle) : 0;
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		if (peer_sid == SECSID_NULL) {
			global_sid_handle_put(peer_handle);
			rc = -ENOPROTOOPT;
			break;
		}
		rc = selinux_peer_sid_to_secctx(
			observer_state, &snapshot, peer_sid, &candidate);
		if (rc == -ESTALE) {
			global_sid_handle_put(peer_handle);
			continue;
		}
		if (rc) {
			global_sid_handle_put(peer_handle);
			break;
		}
		if (READ_ONCE(sksec->state) != socket_state ||
		    READ_ONCE(sksec->sid) != socket_sid ||
		    rcu_access_pointer(sksec->provenance) != socket_provenance ||
		    !selinux_policy_snapshot_valid(observer_state, &snapshot)) {
			kfree(candidate.context);
			global_sid_handle_put(peer_handle);
			rc = -ESTALE;
			continue;
		}
		*cp = candidate;
		global_sid_handle_put(peer_handle);
		rc = 0;
		goto out_sources;
	}
	if (rc == -EAGAIN || rc == -ESTALE)
		rc = -ESTALE;

out_sources:
	selinux_peer_sources_put(&sources);
out_provenance:
	selinux_net_provenance_put(socket_provenance);
	/* The hook default means "not implemented" to the LSM dispatcher. */
	return rc == -EOPNOTSUPP ? -EXDEV : rc;
}

static struct selinux_scm_security *
selinux_scm_security(const struct lsm_scm_security *scm)
{
	return (void *)scm->security + selinux_blob_sizes.lbs_scm;
}

static int selinux_unix_sock_provenance_get(
	struct sock *sk, struct socket *sock,
	struct selinux_net_provenance **provenancep)
{
	struct inode_security_struct *isec;
	struct selinux_net_provenance *provenance;
	struct selinux_label_ref *inode_label;
	struct sk_security_struct *sksec;
	enum selinux_label_source inode_source;
	enum label_initialized initialized;
	u32 inode_sid;
	u16 inode_class;
	int rc = 0;

	if (!sk || !sock || sock->sk != sk || sk->sk_family != PF_UNIX ||
	    !provenancep)
		return -EINVAL;
	*provenancep = NULL;
	sksec = selinux_sock(sk);
	provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
	if (!provenance || !provenance->state || !provenance->view ||
	    !provenance->subject || !provenance->subject->label) {
		rc = -EACCES;
		goto out;
	}

	isec = inode_security_novalidate(SOCK_INODE(sock));
	spin_lock(&isec->lock);
	inode_label = rcu_dereference_protected(
		isec->label_ref, lockdep_is_held(&isec->lock));
	inode_label = selinux_label_ref_get(inode_label);
	inode_sid = isec->sid;
	inode_class = isec->sclass;
	inode_source = isec->label_source;
	initialized = isec->initialized;
	spin_unlock(&isec->lock);

	if (!inode_label || initialized != LABEL_INITIALIZED ||
	    inode_source != SELINUX_LABEL_SOURCE_SOCKET ||
	    inode_label != provenance->subject->label ||
	    inode_sid != provenance->subject->sid ||
	    inode_class != provenance->subject->semantic_class ||
	    READ_ONCE(sksec->sid) != provenance->subject->sid ||
	    READ_ONCE(sksec->sclass) != provenance->subject->semantic_class ||
	    READ_ONCE(sksec->state) != provenance->state ||
	    provenance->subject->source !=
		    SELINUX_NET_ASSERTION_SOURCE_SOCKET ||
	    provenance->view->origin_domain !=
		    provenance->state->label_domain)
		rc = -EACCES;
	selinux_label_ref_put(inode_label);
	/* Reject a socket provenance replacement during tuple validation. */
	if (!rc && rcu_access_pointer(sksec->provenance) != provenance)
		rc = -ESTALE;
	if (rc)
		goto out;

	*provenancep = provenance;
	return 0;

out:
	selinux_net_provenance_put(provenance);
	return rc;
}

static int selinux_scm_alloc_security(struct lsm_scm_security *scm,
				      struct socket *sock, gfp_t gfp)
{
	struct selinux_scm_security *sec = selinux_scm_security(scm);
	struct selinux_net_provenance *provenance;
	int rc;

	(void)gfp;
	rc = selinux_unix_sock_provenance_get(sock->sk, sock, &provenance);
	if (rc)
		return rc;
	/* Publish the slot only after the socket/inode tuple is coherent. */
	sec->provenance = provenance;
	return 0;
}

static void selinux_scm_free_security(struct lsm_scm_security *scm)
{
	struct selinux_scm_security *sec = selinux_scm_security(scm);

	selinux_net_provenance_put(sec->provenance);
	sec->provenance = NULL;
}

static int selinux_scm_secdata_eq(const struct lsm_scm_security *left,
				  const struct lsm_scm_security *right)
{
	const struct selinux_scm_security *left_sec =
		selinux_scm_security(left);
	const struct selinux_scm_security *right_sec =
		selinux_scm_security(right);

	return left_sec->provenance &&
	       left_sec->provenance == right_sec->provenance;
}

static int selinux_scm_getsecctx(const struct lsm_scm_security *scm,
				 const struct cred *observer_cred,
				 struct sock *observer,
				 struct lsm_context *cp)
{
	const struct selinux_scm_security *sec;
	const struct cred_security_struct *observer_crsec;
	struct selinux_net_provenance *observer_provenance;
	struct selinux_policy_snapshot snapshot;
	struct selinux_net_provenance *source;
	struct socket *observer_socket;
	struct selinux_state *observer_state;
	struct sk_security_struct *observer_sksec;
	unsigned int retry;
	u32 observer_sid;
	u32 source_sid;
	int rc;

	if (!scm || !observer_cred || !observer || !cp)
		return -EACCES;
	sec = selinux_scm_security(scm);
	source = sec->provenance;
	if (!source || !source->state || !source->view || !source->subject ||
	    !source->subject->label ||
	    source->subject->source != SELINUX_NET_ASSERTION_SOURCE_SOCKET)
		return -EACCES;

	observer_socket = READ_ONCE(observer->sk_socket);
	rc = selinux_unix_sock_provenance_get(
		observer, observer_socket, &observer_provenance);
	if (rc)
		return rc;
	observer_sksec = selinux_sock(observer);
	observer_crsec = selinux_cred(observer_cred);
	observer_state = observer_crsec->state;
	if (!observer_state || !observer_state->label_domain ||
	    !selinux_mnt_views_share_snapshot(source->view,
					       observer_provenance->view)) {
		rc = -EXDEV;
		goto out_observer;
	}

	/* Prove the receiving task is represented by the socket's sealed view. */
	rc = selinux_label_view_resolve(
		observer_provenance->view, observer_state->label_domain,
		observer_provenance->subject->label,
		observer_provenance->subject->sid, &observer_sid);
	if (rc)
		goto out_observer;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		struct lsm_context candidate = { };

		rc = selinux_policy_snapshot_read(observer_state, &snapshot);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_label_view_resolve(
			source->view, observer_state->label_domain,
			source->subject->label, source->subject->sid, &source_sid);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_peer_sid_to_secctx(
			observer_state, &snapshot, source_sid, &candidate);
		if (rc == -ESTALE)
			continue;
		if (rc)
			break;
		if (READ_ONCE(observer_sksec->state) !=
			    observer_provenance->state ||
		    READ_ONCE(observer_sksec->sid) !=
			    observer_provenance->subject->sid ||
		    rcu_access_pointer(observer_sksec->provenance) !=
			    observer_provenance ||
		    !selinux_policy_snapshot_valid(observer_state, &snapshot)) {
			kfree(candidate.context);
			rc = -ESTALE;
			continue;
		}
		*cp = candidate;
		rc = 0;
		goto out_observer;
	}
	rc = -ESTALE;

out_observer:
	selinux_net_provenance_put(observer_provenance);
	/* Preserve the dispatcher default exclusively for an absent hook. */
	return rc == -EOPNOTSUPP ? -EXDEV : rc;
}
#endif

static int selinux_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	struct sk_security_struct *sksec = selinux_sock(sk);

	sksec->peer_sid = SECINITSID_UNLABELED;
	sksec->sid = SECINITSID_UNLABELED;
	sksec->sclass = SECCLASS_SOCKET;
	sksec->state = get_selinux_state(current_selinux_state);
#ifdef CONFIG_SECURITY_SELINUX_NS
	RCU_INIT_POINTER(sksec->provenance, NULL);
	RCU_INIT_POINTER(sksec->peer_provenance, NULL);
#endif
	selinux_netlbl_sk_security_reset(sksec);

	return 0;
}

static void selinux_sk_free_security(struct sock *sk)
{
	struct sk_security_struct *sksec = selinux_sock(sk);

	selinux_netlbl_sk_security_free(sksec);
#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_sk_provenance_free(sksec);
#endif
	put_selinux_state(sksec->state);
}

static void selinux_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct sk_security_struct *newsksec = selinux_sock(newsk);

	newsksec->sid = sksec->sid;
	newsksec->peer_sid = sksec->peer_sid;
	newsksec->sclass = sksec->sclass;
#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		struct selinux_net_provenance *provenance;
		struct selinux_net_provenance *peer;

		provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
		peer = selinux_net_provenance_get_rcu(&sksec->peer_provenance);
		selinux_sk_provenance_free(newsksec);
		RCU_INIT_POINTER(newsksec->provenance, provenance);
		RCU_INIT_POINTER(newsksec->peer_provenance, peer);
	}
#endif
	if (newsksec->state != sksec->state) {
		put_selinux_state(newsksec->state);
		newsksec->state = get_selinux_state(sksec->state);
	}

	selinux_netlbl_sk_security_reset(newsksec);
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static struct req_security_struct *selinux_req(const struct request_sock *req)
{
	return req->security + selinux_blob_sizes.lbs_req;
}

static struct sctp_assoc_security_struct *
selinux_sctp_assoc(const struct sctp_association *asoc)
{
	return asoc->security + selinux_blob_sizes.lbs_sctp_assoc;
}

static void selinux_sctp_assoc_sources_init(
	struct sctp_assoc_security_struct *assocsec)
{
	assocsec->peer_netlabel_cache = NULL;
	assocsec->peer_netlabel_view = NULL;
	assocsec->peer_netlabel_type = NETLBL_NLTYPE_NONE;
	assocsec->peer_xfrm = NULL;
}

/* The association socket lock serializes publication and extraction. */
static void selinux_sctp_assoc_sources_take(
	struct sctp_assoc_security_struct *assocsec,
	struct selinux_peer_sources *sources)
{
	assocsec->peer_netlabel_cache = sources->netlabel.cache;
	assocsec->peer_netlabel_view = sources->netlabel.view;
	assocsec->peer_netlabel_type = sources->netlabel.type;
	assocsec->peer_xfrm = sources->xfrm;
	selinux_peer_sources_init(sources);
}

static void selinux_sctp_assoc_sources_extract(
	struct sctp_assoc_security_struct *assocsec,
	struct selinux_peer_sources *sources)
{
	selinux_peer_sources_init(sources);
	sources->netlabel.cache = assocsec->peer_netlabel_cache;
	sources->netlabel.view = assocsec->peer_netlabel_view;
	sources->netlabel.type = assocsec->peer_netlabel_type;
	sources->xfrm = assocsec->peer_xfrm;
	selinux_sctp_assoc_sources_init(assocsec);
}

static void selinux_sctp_assoc_sources_get(
	const struct sctp_assoc_security_struct *assocsec,
	struct selinux_peer_sources *sources)
{
	selinux_peer_sources_init(sources);
	sources->netlabel.cache = assocsec->peer_netlabel_cache;
	sources->netlabel.view = assocsec->peer_netlabel_view;
	sources->netlabel.type = assocsec->peer_netlabel_type;
	sources->xfrm = assocsec->peer_xfrm;
	selinux_netlbl_source_get(&sources->netlabel);
	selinux_net_provenance_get(sources->xfrm);
}

static int selinux_req_alloc_security(struct request_sock *req,
				      const struct sock *listener, gfp_t gfp)
{
	struct req_security_struct *reqsec = selinux_req(req);
	const struct sk_security_struct *sksec;
	struct selinux_net_provenance *provenance;

	(void)gfp;
	if (!listener)
		return -EINVAL;
	sksec = selinux_sock(listener);
	provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
	if (!provenance)
		return -EACCES;
	RCU_INIT_POINTER(reqsec->provenance, provenance);
	RCU_INIT_POINTER(reqsec->peer_provenance, NULL);
	return 0;
}

static void selinux_req_free_security(struct request_sock *req)
{
	struct req_security_struct *reqsec = selinux_req(req);
	struct selinux_net_provenance *provenance, *peer;

	provenance = rcu_dereference_protected(reqsec->provenance, 1);
	peer = rcu_dereference_protected(reqsec->peer_provenance, 1);
	RCU_INIT_POINTER(reqsec->provenance, NULL);
	RCU_INIT_POINTER(reqsec->peer_provenance, NULL);
	selinux_net_provenance_put(peer);
	selinux_net_provenance_put(provenance);
}

static int selinux_req_clone_security(const struct request_sock *req,
				      struct request_sock *newreq, gfp_t gfp)
{
	const struct req_security_struct *oldsec = selinux_req(req);
	struct req_security_struct *newsec = selinux_req(newreq);
	struct selinux_net_provenance *provenance, *peer;

	(void)gfp;
	provenance = selinux_net_provenance_get_rcu(&oldsec->provenance);
	if (!provenance)
		return -EACCES;
	peer = selinux_net_provenance_get_rcu(&oldsec->peer_provenance);
	RCU_INIT_POINTER(newsec->provenance, provenance);
	RCU_INIT_POINTER(newsec->peer_provenance, peer);
	return 0;
}

static int selinux_sctp_assoc_alloc_security(struct sctp_association *asoc,
					     gfp_t gfp)
{
	struct sctp_assoc_security_struct *assocsec = selinux_sctp_assoc(asoc);
	const struct sk_security_struct *sksec;
	struct selinux_net_provenance *provenance;

	(void)gfp;
	if (!asoc->base.sk)
		return -EINVAL;
	sksec = selinux_sock(asoc->base.sk);
	provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
	if (!provenance)
		return -EACCES;
	RCU_INIT_POINTER(assocsec->provenance, provenance);
	RCU_INIT_POINTER(assocsec->peer_provenance, NULL);
	selinux_sctp_assoc_sources_init(assocsec);
	return 0;
}

static void
selinux_sctp_assoc_free_security(struct sctp_association *asoc)
{
	struct sctp_assoc_security_struct *assocsec = selinux_sctp_assoc(asoc);
	struct selinux_net_provenance *provenance, *peer;
	struct selinux_peer_sources sources;

	provenance = rcu_dereference_protected(assocsec->provenance, 1);
	peer = rcu_dereference_protected(assocsec->peer_provenance, 1);
	selinux_sctp_assoc_sources_extract(assocsec, &sources);
	RCU_INIT_POINTER(assocsec->provenance, NULL);
	RCU_INIT_POINTER(assocsec->peer_provenance, NULL);
	selinux_peer_sources_put(&sources);
	selinux_net_provenance_put(peer);
	selinux_net_provenance_put(provenance);
}
#endif

static void selinux_sk_getsecid(const struct sock *sk, u32 *secid)
{
	if (!sk)
		*secid = SECINITSID_ANY_SOCKET;
	else {
		const struct sk_security_struct *sksec = selinux_sock(sk);

		*secid = sksec->sid;
	}
}

static void selinux_sock_graft(struct sock *sk, struct socket *parent)
{
	struct inode_security_struct *isec =
		inode_security_novalidate(SOCK_INODE(parent));
	struct sk_security_struct *sksec = selinux_sock(sk);

	if (sk->sk_family == PF_INET || sk->sk_family == PF_INET6 ||
	    sk->sk_family == PF_UNIX)
		WARN_ON_ONCE(inode_security_set_sid(
			isec, sksec->sid, SELINUX_LABEL_SOURCE_SOCKET,
			LABEL_INITIALIZED));
	sksec->sclass = isec->sclass;
}

#ifndef CONFIG_SECURITY_SELINUX_NS
/* Determine the peer SID without publishing state before snapshot validation. */
static int
selinux_sctp_process_new_assoc(struct sctp_association *asoc,
	struct sk_buff *skb,
	const struct selinux_policy_snapshot *snapshot, u32 *peer_sid)
{
	struct sock *sk = asoc->base.sk;
	u16 family = sk->sk_family;
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct selinux_state *state = sksec->state;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	int err;

	/* handle mapped IPv4 packets arriving via IPv6 sockets */
	if (family == PF_INET6 && skb->protocol == htons(ETH_P_IP))
		family = PF_INET;

	if (selinux_peerlbl_enabled(snapshot)) {
		*peer_sid = SECSID_NULL;

		/* This will return peer_sid = SECSID_NULL if there are
		 * no peer labels, see security_net_peersid_resolve().
		 */
		err = selinux_skb_peerlbl_sid(skb, family, state, peer_sid);
		if (err)
			return err;

		if (*peer_sid == SECSID_NULL)
			*peer_sid = SECINITSID_UNLABELED;
	} else {
		*peer_sid = SECINITSID_UNLABELED;
	}

	if (sksec->sctp_assoc_state != SCTP_ASSOC_UNSET &&
	    sksec->peer_sid != *peer_sid) {
		/* Other association peer SIDs are checked to enforce
		 * consistency among the peer SIDs.
		 */
		ad_net_init_from_sk(&ad, &net, asoc->base.sk);
		err = avc_has_perm_snapshot(state, snapshot, sksec->peer_sid,
					    *peer_sid, sksec->sclass,
					    SCTP_SOCKET__ASSOCIATION, &ad);
		if (err)
			return err;
	}
	return selinux_policy_snapshot_valid(state, snapshot) ? 0 : -ESTALE;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_sctp_assoc_set_provenance(struct sctp_association *asoc,
					     u32 subject_sid, u32 peer_sid)
{
	struct selinux_global_sid_handle *subject_handle, *peer_handle;
	struct sctp_assoc_security_struct *assocsec = selinux_sctp_assoc(asoc);
	struct selinux_net_provenance *base, *subject, *peer;
	struct selinux_net_provenance *old_subject, *old_peer;

	base = selinux_net_provenance_get_rcu(&assocsec->provenance);
	if (!base)
		return -EACCES;
	subject_handle = global_sid_handle_get(subject_sid);
	if (IS_ERR(subject_handle)) {
		selinux_net_provenance_put(base);
		return PTR_ERR(subject_handle);
	}
	subject = selinux_net_provenance_derive_handle(
		base, subject_handle, SECCLASS_SCTP_SOCKET,
		SELINUX_NET_ASSERTION_SOURCE_SOCKET, GFP_ATOMIC);
	if (IS_ERR(subject)) {
		selinux_net_provenance_put(base);
		return PTR_ERR(subject);
	}
	peer_handle = global_sid_handle_get(peer_sid);
	if (IS_ERR(peer_handle)) {
		selinux_net_provenance_put(subject);
		selinux_net_provenance_put(base);
		return PTR_ERR(peer_handle);
	}
	peer = selinux_net_provenance_derive_handle(
		base, peer_handle, SECCLASS_PEER,
		SELINUX_NET_ASSERTION_SOURCE_PEER_RESOLVED, GFP_ATOMIC);
	if (IS_ERR(peer)) {
		selinux_net_provenance_put(subject);
		selinux_net_provenance_put(base);
		return PTR_ERR(peer);
	}
	old_subject = rcu_replace_pointer(assocsec->provenance, subject, true);
	old_peer = rcu_replace_pointer(assocsec->peer_provenance, peer, true);
	selinux_net_provenance_put(old_peer);
	selinux_net_provenance_put(old_subject);
	selinux_net_provenance_put(base);
	return 0;
}
#endif

static int selinux_sctp_commit_peer(struct sk_security_struct *sksec,
				    struct sctp_association *asoc,
				    u32 peer_sid)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct sctp_assoc_security_struct *assocsec = selinux_sctp_assoc(asoc);
	struct selinux_net_provenance *peer = NULL, *old_peer;

	peer = selinux_net_provenance_get_rcu(&assocsec->peer_provenance);
	if (!peer || peer->subject->sid != peer_sid) {
		selinux_net_provenance_put(peer);
		return -EACCES;
	}
#endif
	asoc->peer_secid = peer_sid;
	if (sksec->sctp_assoc_state == SCTP_ASSOC_UNSET) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		old_peer = rcu_replace_pointer(sksec->peer_provenance,
					       selinux_net_provenance_get(peer), true);
		selinux_net_provenance_put(old_peer);
#endif
		sksec->sctp_assoc_state = SCTP_ASSOC_SET;
		sksec->peer_sid = peer_sid;
	}
#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_net_provenance_put(peer);
#endif
	return 0;
}

/* Called whenever SCTP receives an INIT or COOKIE ECHO chunk. This
 * happens on an incoming connect(2), sctp_connectx(3) or
 * sctp_sendmsg(3) (with no association already present).
 */
static int selinux_sctp_assoc_request(struct sctp_association *asoc,
				      struct sk_buff *skb)
{
	struct sk_security_struct *sksec = selinux_sock(asoc->base.sk);
	struct selinux_policy_snapshot snapshot;
	struct selinux_state *state = sksec->state;
	unsigned int retry;
	u32 conn_sid, peer_sid;
	int err = -ESTALE;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		err = selinux_policy_snapshot_read(state, &snapshot);
		if (err == -EAGAIN)
			continue;
		if (err)
			return err;
		if (!selinux_policy_snapshot_has_cap(
			    &snapshot, POLICYDB_CAP_EXTSOCKCLASS))
			return 0;

		err = selinux_sctp_process_new_assoc(asoc, skb, &snapshot,
						     &peer_sid);
		if (err == -ESTALE)
			continue;
		if (err)
			return err;

		err = selinux_conn_sid(sksec->sid, peer_sid, state, &conn_sid);
		if (err)
			return err;
		if (!selinux_policy_snapshot_valid(state, &snapshot)) {
			err = -ESTALE;
			continue;
		}

#ifdef CONFIG_SECURITY_SELINUX_NS
		err = selinux_sctp_assoc_set_provenance(asoc, conn_sid, peer_sid);
		if (err)
			return err;
#endif
		err = selinux_sctp_commit_peer(sksec, asoc, peer_sid);
		if (err)
			return err;
		asoc->secid = conn_sid;

		/* Set any NetLabel labels including CIPSO/CALIPSO options. */
		return selinux_netlbl_sctp_assoc_request(asoc, skb, conn_sid);
	}

	return err;
}

/* Called when SCTP receives a COOKIE ACK chunk as the final
 * response to an association request (initited by us).
 */
static int selinux_sctp_assoc_established(struct sctp_association *asoc,
					  struct sk_buff *skb)
{
	struct sk_security_struct *sksec = selinux_sock(asoc->base.sk);
	struct selinux_policy_snapshot snapshot;
	struct selinux_state *state = sksec->state;
	unsigned int retry;
	u32 peer_sid;
	int err = -ESTALE;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		err = selinux_policy_snapshot_read(state, &snapshot);
		if (err == -EAGAIN)
			continue;
		if (err)
			return err;
		if (!selinux_policy_snapshot_has_cap(
			    &snapshot, POLICYDB_CAP_EXTSOCKCLASS))
			return 0;
		err = selinux_sctp_process_new_assoc(asoc, skb, &snapshot,
						     &peer_sid);
		if (err == -ESTALE)
			continue;
		if (err)
			return err;

#ifdef CONFIG_SECURITY_SELINUX_NS
		err = selinux_sctp_assoc_set_provenance(asoc, sksec->sid,
						 peer_sid);
		if (err)
			return err;
#endif
		err = selinux_sctp_commit_peer(sksec, asoc, peer_sid);
		if (err)
			return err;
		asoc->secid = sksec->sid;
		return 0;
	}

	return err;
}

#else /* CONFIG_SECURITY_SELINUX_NS */

struct selinux_sctp_assoc_candidate {
	struct selinux_peer_sources sources;
	struct selinux_net_provenance *subject;
	struct selinux_net_provenance *peer;
	u32 subject_sid;
	u32 peer_sid;
};

static void selinux_sctp_candidate_init(
	struct selinux_sctp_assoc_candidate *candidate)
{
	selinux_peer_sources_init(&candidate->sources);
	candidate->subject = NULL;
	candidate->peer = NULL;
	candidate->subject_sid = SECSID_NULL;
	candidate->peer_sid = SECSID_NULL;
}

static void selinux_sctp_candidate_put(
	struct selinux_sctp_assoc_candidate *candidate)
{
	selinux_peer_sources_put(&candidate->sources);
	selinux_net_provenance_put(candidate->peer);
	selinux_net_provenance_put(candidate->subject);
	selinux_sctp_candidate_init(candidate);
}

static void selinux_sctp_candidate_put_provenance(
	struct selinux_sctp_assoc_candidate *candidate)
{
	selinux_net_provenance_put(candidate->peer);
	selinux_net_provenance_put(candidate->subject);
	candidate->peer = NULL;
	candidate->subject = NULL;
}

/*
 * Capture once, authorize every policy in the socket's immutable state
 * lineage, and prepare all fallible objects before any association field is
 * published.  @chain is returned so the caller can revalidate immediately
 * before its first irreversible side effect.
 */
static int selinux_sctp_prepare_candidate(
	struct sctp_association *asoc, struct sk_buff *skb, bool request,
	struct selinux_sctp_assoc_candidate *candidate,
	struct selinux_policy_state_chain_snapshot *chain,
	struct selinux_net_avc_transaction *transaction, bool *active)
{
	struct sk_security_struct *sksec = selinux_sock(asoc->base.sk);
	struct selinux_net_provenance *base = NULL, *existing_peer = NULL;
	struct selinux_global_sid_handle *subject_handle = NULL;
	struct selinux_global_sid_handle *peer_handle = NULL;
	u32 peer_sid[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	u32 subject_sid[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	struct common_audit_data ad;
	struct lsm_network_audit net;
	unsigned int retry;
	u16 family = asoc->base.sk->sk_family;
	int err = -ESTALE;

	selinux_sctp_candidate_init(candidate);
	*active = false;
	if (family == PF_INET6 && skb->protocol == htons(ETH_P_IP))
		family = PF_INET;

	base = selinux_net_provenance_get_rcu(&sksec->provenance);
	if (!base || base->state != sksec->state || !base->view ||
	    !base->subject || !base->subject->label ||
	    base->subject->sid != READ_ONCE(sksec->sid)) {
		err = -EACCES;
		goto out;
	}
	err = selinux_peer_sources_capture(skb, family, sksec->state,
					   base->view, &candidate->sources);
	if (err)
		goto out;
	if (sksec->sctp_assoc_state != SCTP_ASSOC_UNSET) {
		existing_peer = selinux_net_provenance_get_rcu(
			&sksec->peer_provenance);
		if (!existing_peer || !existing_peer->subject ||
		    !existing_peer->subject->label || !existing_peer->view ||
		    existing_peer->subject->sid != READ_ONCE(sksec->peer_sid)) {
			err = -EACCES;
			goto out;
		}
	}
	ad_net_init_from_sk(&ad, &net, asoc->base.sk);

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		bool extsock_active = false;
		u16 i;

		global_sid_handle_put(peer_handle);
		global_sid_handle_put(subject_handle);
		peer_handle = NULL;
		subject_handle = NULL;
		selinux_net_avc_transaction_reset(transaction);

		err = selinux_policy_state_chain_snapshot_read(sksec->state,
							       chain);
		if (err == -EAGAIN || err == -ESTALE)
			continue;
		if (err)
			break;

		for (i = 0, err = 0; i < chain->count; i++) {
			struct selinux_global_sid_handle *level_peer
				__free(selinux_sid_handle) = NULL;
			struct selinux_global_sid_handle *level_subject
				__free(selinux_sid_handle) = NULL;
			struct selinux_state *state = chain->state[i];
			const struct selinux_policy_snapshot *snapshot =
				&chain->policy[i];
			u16 initial_count = transaction->count;
			u32 socket_sid, old_peer_sid;

			err = selinux_net_avc_transaction_provenance_sid(
				transaction, base, state->label_domain, &socket_sid);
			if (err)
				break;
			if (selinux_peerlbl_enabled(snapshot)) {
				if (!i) {
					peer_handle =
						selinux_net_avc_transaction_peer_sources_handle(
							transaction, &candidate->sources, state,
							&peer_sid[i]);
					if (IS_ERR(peer_handle)) {
						err = PTR_ERR(peer_handle);
						peer_handle = NULL;
						break;
					}
				} else {
					level_peer =
						selinux_net_avc_transaction_peer_sources_handle(
						transaction, &candidate->sources, state,
						&peer_sid[i]);
					err = IS_ERR(level_peer) ? PTR_ERR(level_peer) : 0;
					if (err)
						break;
				}
				if (peer_sid[i] == SECSID_NULL) {
					peer_sid[i] = SECINITSID_UNLABELED;
					if (!i) {
						peer_handle = global_sid_handle_get(
							peer_sid[i]);
						if (IS_ERR(peer_handle)) {
							err = PTR_ERR(peer_handle);
							peer_handle = NULL;
							break;
						}
					} else {
						level_peer = global_sid_handle_get(
							peer_sid[i]);
						if (IS_ERR(level_peer)) {
							err = PTR_ERR(level_peer);
							break;
						}
					}
				}
			} else {
				peer_sid[i] = SECINITSID_UNLABELED;
				if (!i) {
					peer_handle = global_sid_handle_get(peer_sid[i]);
					if (IS_ERR(peer_handle)) {
						err = PTR_ERR(peer_handle);
						peer_handle = NULL;
						break;
					}
				} else {
					level_peer = global_sid_handle_get(peer_sid[i]);
					if (IS_ERR(level_peer)) {
						err = PTR_ERR(level_peer);
						break;
					}
				}
			}
			if (request) {
				if (!i) {
					subject_handle = security_sid_mls_copy_handle(
						state, socket_sid, peer_sid[i],
						&subject_sid[i]);
					if (IS_ERR(subject_handle)) {
						err = PTR_ERR(subject_handle);
						subject_handle = NULL;
					}
				} else {
					if (peer_sid[i] == SECSID_NULL) {
						subject_sid[i] = socket_sid;
						level_subject =
							global_sid_handle_get(socket_sid);
					} else {
						level_subject =
							security_sid_mls_copy_handle(
								state, socket_sid,
								peer_sid[i],
								&subject_sid[i]);
					}
					err = IS_ERR(level_subject) ?
						PTR_ERR(level_subject) : 0;
				}
			} else {
				subject_sid[i] = socket_sid;
				if (!i) {
					subject_handle = global_sid_handle_dup(
						base->subject->sid_handle);
					if (IS_ERR(subject_handle)) {
						err = PTR_ERR(subject_handle);
						subject_handle = NULL;
					} else if (global_sid_handle_sid(subject_handle) !=
						   subject_sid[i]) {
						err = -ESTALE;
					}
				}
			}
			if (err)
				break;

			if (selinux_policy_snapshot_has_cap(
				    snapshot, POLICYDB_CAP_EXTSOCKCLASS)) {
				extsock_active = true;
				if (existing_peer) {
					err = selinux_net_avc_transaction_provenance_sid(
						transaction, existing_peer,
						state->label_domain, &old_peer_sid);
					if (err)
						break;
				}
				if (existing_peer && old_peer_sid != peer_sid[i]) {
					u16 sclass = socket_class_for_snapshot(
						snapshot, asoc->base.sk->sk_family,
						asoc->base.sk->sk_type,
						asoc->base.sk->sk_protocol);

					err = selinux_net_avc_transaction_add_provenance(
						transaction,
						&(struct selinux_avc_level) {
							.state = state,
							.ssid = old_peer_sid,
							.tsid = peer_sid[i],
							.requested =
								SCTP_SOCKET__ASSOCIATION,
							.tclass = sclass,
						}, snapshot, existing_peer);
					if (err)
						break;
				}
			}
			err = selinux_net_avc_transaction_add_guard(
				transaction, initial_count, state, snapshot);
			if (err)
				break;
		}
		if (!err)
			err = selinux_net_avc_transaction_decide(transaction, &ad);
		if (err == -ESTALE) {
			err = -ESTALE;
			continue;
		}
		if (err)
			break;
		if (!extsock_active) {
			err = 0;
			break;
		}

		candidate->subject = selinux_net_provenance_derive_handle(
			base, subject_handle, SECCLASS_SCTP_SOCKET,
			SELINUX_NET_ASSERTION_SOURCE_SOCKET, GFP_ATOMIC);
		subject_handle = NULL;
		if (IS_ERR(candidate->subject)) {
			err = PTR_ERR(candidate->subject);
			candidate->subject = NULL;
			break;
		}
		candidate->peer = selinux_net_provenance_derive_handle(
			base, peer_handle, SECCLASS_PEER,
			SELINUX_NET_ASSERTION_SOURCE_PEER_RESOLVED, GFP_ATOMIC);
		peer_handle = NULL;
		if (IS_ERR(candidate->peer)) {
			err = PTR_ERR(candidate->peer);
			candidate->peer = NULL;
			selinux_sctp_candidate_put_provenance(candidate);
			break;
		}

		for (i = 0, err = 0; i < chain->count; i++) {
			u32 resolved;

			err = selinux_net_avc_transaction_provenance_sid(
				transaction, candidate->subject,
				chain->state[i]->label_domain, &resolved);
			if (err || resolved != subject_sid[i]) {
				if (!err)
					err = -EACCES;
				break;
			}
			err = selinux_net_avc_transaction_provenance_sid(
				transaction, candidate->peer,
				chain->state[i]->label_domain, &resolved);
			if (err || resolved != peer_sid[i]) {
				if (!err)
					err = -EACCES;
				break;
			}
		}
		if (err == -ESTALE ||
		    !selinux_policy_state_chain_snapshot_valid(chain)) {
			selinux_sctp_candidate_put_provenance(candidate);
			err = -ESTALE;
			continue;
		}
		if (err)
			break;
		candidate->subject_sid = subject_sid[0];
		candidate->peer_sid = peer_sid[0];
		*active = true;
		break;
	}

out:
	selinux_net_avc_transaction_reset(transaction);
	global_sid_handle_put(peer_handle);
	global_sid_handle_put(subject_handle);
	selinux_net_provenance_put(existing_peer);
	selinux_net_provenance_put(base);
	if (err)
		selinux_sctp_candidate_put(candidate);
	return err;
}

/* All fallible work is complete; the socket lock makes this one tuple. */
static void selinux_sctp_commit_candidate(
	struct sk_security_struct *sksec, struct sctp_association *asoc,
	struct selinux_sctp_assoc_candidate *candidate)
{
	struct sctp_assoc_security_struct *assocsec = selinux_sctp_assoc(asoc);
	struct selinux_net_provenance *old_subject, *old_peer;
	struct selinux_peer_sources old_sources;

	selinux_sctp_assoc_sources_extract(assocsec, &old_sources);
	selinux_sctp_assoc_sources_take(assocsec, &candidate->sources);
	old_subject = rcu_replace_pointer(assocsec->provenance,
					  candidate->subject, true);
	old_peer = rcu_replace_pointer(assocsec->peer_provenance,
				       candidate->peer, true);
	candidate->subject = NULL;
	candidate->peer = NULL;

	WRITE_ONCE(asoc->secid, candidate->subject_sid);
	WRITE_ONCE(asoc->peer_secid, candidate->peer_sid);
	if (sksec->sctp_assoc_state == SCTP_ASSOC_UNSET) {
		selinux_sk_peer_provenance_replace(
			sksec, selinux_net_provenance_get(
				rcu_dereference_protected(assocsec->peer_provenance, 1)));
		WRITE_ONCE(sksec->sctp_assoc_state, SCTP_ASSOC_SET);
	}

	selinux_peer_sources_put(&old_sources);
	selinux_net_provenance_put(old_peer);
	selinux_net_provenance_put(old_subject);
}

static int selinux_sctp_assoc_request(struct sctp_association *asoc,
				      struct sk_buff *skb)
{
	struct selinux_sctp_assoc_candidate candidate;
	struct {
		struct selinux_policy_state_chain_snapshot chain;
		struct selinux_net_avc_transaction transaction;
	} *scratch __free(kfree) = NULL;
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
	struct sk_security_struct *sksec = selinux_sock(asoc->base.sk);
	bool active;
	int err;

	scratch = kzalloc_obj(*scratch, GFP_ATOMIC);
	if (!scratch)
		return -ENOMEM;
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_NET_AVC_MAX_CHECKS, GFP_ATOMIC | __GFP_NOWARN);
	if (!workspace)
		return -ENOMEM;
	scratch->transaction.workspace = workspace;
	err = selinux_sctp_prepare_candidate(asoc, skb, true, &candidate,
					     &scratch->chain,
					     &scratch->transaction, &active);
	if (err || !active)
		goto out;
	if (!selinux_policy_state_chain_snapshot_valid(&scratch->chain)) {
		err = -ESTALE;
		goto out;
	}
	/* This is the only fallible side effect and precedes publication. */
	err = selinux_netlbl_sctp_assoc_request(asoc, skb,
						 candidate.subject_sid);
	if (err)
		goto out;
	selinux_sctp_commit_candidate(sksec, asoc, &candidate);
out:
	selinux_sctp_candidate_put(&candidate);
	return err;
}

static int selinux_sctp_assoc_established(struct sctp_association *asoc,
					  struct sk_buff *skb)
{
	struct selinux_sctp_assoc_candidate candidate;
	struct {
		struct selinux_policy_state_chain_snapshot chain;
		struct selinux_net_avc_transaction transaction;
	} *scratch __free(kfree) = NULL;
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
	struct sk_security_struct *sksec = selinux_sock(asoc->base.sk);
	bool active;
	int err;

	scratch = kzalloc_obj(*scratch, GFP_ATOMIC);
	if (!scratch)
		return -ENOMEM;
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_NET_AVC_MAX_CHECKS, GFP_ATOMIC | __GFP_NOWARN);
	if (!workspace)
		return -ENOMEM;
	scratch->transaction.workspace = workspace;
	err = selinux_sctp_prepare_candidate(asoc, skb, false, &candidate,
					     &scratch->chain,
					     &scratch->transaction, &active);
	if (err || !active)
		goto out;
	if (!selinux_policy_state_chain_snapshot_valid(&scratch->chain)) {
		err = -ESTALE;
		goto out;
	}
	selinux_sctp_commit_candidate(sksec, asoc, &candidate);
out:
	selinux_sctp_candidate_put(&candidate);
	return err;
}

#endif /* CONFIG_SECURITY_SELINUX_NS */

/* Check if sctp IPv4/IPv6 addresses are valid for binding or connecting
 * based on their @optname.
 */
static int selinux_sctp_bind_connect(struct sock *sk, int optname,
				     struct sockaddr *address,
				     int addrlen)
{
	int len, err = 0, walk_size = 0;
	void *addr_buf;
	struct sockaddr *addr;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_socket_address_check *checks __free(kvfree) = NULL;
	enum selinux_socket_address_operation operation;
	u32 count = 0;
	u16 i;
	bool apply_netlabel = false;

	switch (optname) {
	case SCTP_PRIMARY_ADDR:
	case SCTP_SET_PEER_PRIMARY_ADDR:
	case SCTP_SOCKOPT_BINDX_ADD:
		operation = SELINUX_SOCKET_ADDRESS_BIND;
		break;
	case SCTP_SOCKOPT_CONNECTX:
	case SCTP_PARAM_SET_PRIMARY:
	case SCTP_PARAM_ADD_IP:
	case SCTP_SENDMSG_CONNECT:
		operation = SELINUX_SOCKET_ADDRESS_CONNECT;
		apply_netlabel = true;
		break;
	default:
		return addrlen > 0 ? -EINVAL : 0;
	}
	if (addrlen <= 0)
		return 0;

	/* Validate and count the complete packed vector before authorization. */
	addr_buf = address;
	while (walk_size < addrlen) {
		if (walk_size + sizeof(sa_family_t) > addrlen)
			return -EINVAL;
		addr = addr_buf;
		switch (addr->sa_family) {
		case AF_UNSPEC:
		case AF_INET:
			len = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			len = sizeof(struct sockaddr_in6);
			break;
		default:
			return -EINVAL;
		}
		if (walk_size + len > addrlen)
			return -EINVAL;
		if (++count > U16_MAX)
			return -E2BIG;
		addr_buf += len;
		walk_size += len;
	}
	checks = kvcalloc(count, sizeof(*checks), GFP_KERNEL);
	if (!checks)
		return -ENOMEM;
	addr_buf = address;
	for (i = 0; i < count; i++) {
		addr = addr_buf;
		len = addr->sa_family == AF_INET6 ?
			      sizeof(struct sockaddr_in6) :
			      sizeof(struct sockaddr_in);
		err = selinux_socket_address_prepare(
			sk, operation, addr, len, &checks[i]);
		if (err)
			return err;
		addr_buf += len;
	}

	err = selinux_socket_addresses_has_perm(
		sk, operation, checks, count,
		operation == SELINUX_SOCKET_ADDRESS_BIND ? SOCKET__BIND :
							 SOCKET__CONNECT,
		true);
	if (err || !apply_netlabel)
		return err;

	/* No socket/NetLabel state changes until every address is authorized. */
	for (i = 0; i < count; i++) {
		err = selinux_netlbl_socket_connect_locked(sk, checks[i].address);
		if (err)
			return err;
	}
	return 0;
#else
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct selinux_policy_snapshot snapshot;

	err = selinux_policy_snapshot_read(sksec->state, &snapshot);
	if (err)
		return err;
	if (!selinux_policy_snapshot_has_cap(&snapshot,
					     POLICYDB_CAP_EXTSOCKCLASS))
		return 0;

	/* Process one or more addresses that may be IPv4 or IPv6 */
	addr_buf = address;

	while (walk_size < addrlen) {
		if (walk_size + sizeof(sa_family_t) > addrlen)
			return -EINVAL;

		addr = addr_buf;
		switch (addr->sa_family) {
		case AF_UNSPEC:
		case AF_INET:
			len = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			len = sizeof(struct sockaddr_in6);
			break;
		default:
			return -EINVAL;
		}

		if (walk_size + len > addrlen)
			return -EINVAL;

		err = -EINVAL;
		switch (optname) {
		/* Bind checks */
		case SCTP_PRIMARY_ADDR:
		case SCTP_SET_PEER_PRIMARY_ADDR:
		case SCTP_SOCKOPT_BINDX_ADD:
			err = __selinux_socket_bind(sk, addr, len);
			break;
		/* Connect checks */
		case SCTP_SOCKOPT_CONNECTX:
		case SCTP_PARAM_SET_PRIMARY:
		case SCTP_PARAM_ADD_IP:
		case SCTP_SENDMSG_CONNECT:
			err = selinux_socket_connect_helper(sk, addr, len);
			if (err)
				return err;

			/* As selinux_sctp_bind_connect() is called by the
			 * SCTP protocol layer, the socket is already locked,
			 * therefore selinux_netlbl_socket_connect_locked()
			 * is called here. The situations handled are:
			 * sctp_connectx(3), sctp_sendmsg(3), sendmsg(2),
			 * whenever a new IP address is added or when a new
			 * primary address is selected.
			 * Note that an SCTP connect(2) call happens before
			 * the SCTP protocol layer and is handled via
			 * selinux_socket_connect().
			 */
			err = selinux_netlbl_socket_connect_locked(sk, addr);
			break;
		}

		if (err)
			return err;

		addr_buf += len;
		walk_size += len;
	}

	return 0;
#endif
}

/* Called whenever a new socket is created by accept(2) or sctp_peeloff(3). */
static void selinux_sctp_sk_clone(struct sctp_association *asoc, struct sock *sk,
				  struct sock *newsk)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct sk_security_struct *newsksec = selinux_sock(newsk);

	/* If policy does not support SECCLASS_SCTP_SOCKET then call
	 * the non-sctp clone version.
	 */
	if (sksec->sclass != SECCLASS_SCTP_SOCKET)
		return selinux_sk_clone_security(sk, newsk);

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		const struct sctp_assoc_security_struct *assocsec =
			selinux_sctp_assoc(asoc);
		struct selinux_net_provenance *provenance, *peer;
		struct selinux_peer_sources sources;
		bool sources_valid;

		provenance = selinux_net_provenance_get_rcu(
			&assocsec->provenance);
		peer = selinux_net_provenance_get_rcu(&assocsec->peer_provenance);
		/* Peeloff moves @asoc intact; pin its native evidence while the
		 * new socket receives the legacy subject/peer projections. */
		selinux_sctp_assoc_sources_get(assocsec, &sources);
		sources_valid =
			(!sources.netlabel.cache || sources.netlabel.view) &&
			(!sources.xfrm ||
			 (sources.xfrm->view && sources.xfrm->subject &&
			  sources.xfrm->subject->label));
		selinux_sk_provenance_free(newsksec);
		if (!sources_valid || !provenance || !peer ||
		    provenance->subject->sid != asoc->secid ||
		    peer->subject->sid != asoc->peer_secid) {
			selinux_net_provenance_put(peer);
			selinux_net_provenance_put(provenance);
			provenance = NULL;
			peer = NULL;
		} else if (newsksec->state != provenance->state) {
			put_selinux_state(newsksec->state);
			newsksec->state = get_selinux_state(provenance->state);
		}
		RCU_INIT_POINTER(newsksec->provenance, provenance);
		RCU_INIT_POINTER(newsksec->peer_provenance, peer);
		selinux_peer_sources_put(&sources);
	}
#endif
	newsksec->sid = asoc->secid;
	newsksec->peer_sid = asoc->peer_secid;
	newsksec->sclass = sksec->sclass;
	if (newsksec->state != sksec->state) {
		put_selinux_state(newsksec->state);
		newsksec->state = get_selinux_state(sksec->state);
	}
	selinux_netlbl_sctp_sk_clone(sk, newsk);
}

static int selinux_mptcp_add_subflow(struct sock *sk, struct sock *ssk)
{
	struct sk_security_struct *ssksec = selinux_sock(ssk);
	struct sk_security_struct *sksec = selinux_sock(sk);
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_net_provenance *provenance, *peer;

	provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
	peer = selinux_net_provenance_get_rcu(&sksec->peer_provenance);
	if (!provenance || provenance->state != sksec->state ||
	    provenance->subject->sid != sksec->sid ||
	    (peer && (peer->state != sksec->state ||
		      peer->subject->sid != sksec->peer_sid))) {
		selinux_net_provenance_put(peer);
		selinux_net_provenance_put(provenance);
		return -EACCES;
	}
	selinux_sk_provenance_free(ssksec);
	RCU_INIT_POINTER(ssksec->provenance, provenance);
	RCU_INIT_POINTER(ssksec->peer_provenance, peer);
#endif

	ssksec->sclass = sksec->sclass;
	ssksec->sid = sksec->sid;
	ssksec->peer_sid = sksec->peer_sid;
	if (ssksec->state != sksec->state) {
		put_selinux_state(ssksec->state);
		ssksec->state = get_selinux_state(sksec->state);
	}

	/* replace the existing subflow label deleting the existing one
	 * and re-recreating a new label using the updated context
	 */
	selinux_netlbl_sk_security_free(ssksec);
	return selinux_netlbl_socket_post_create(ssk, ssk->sk_family);
}

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_inet_peer_candidate {
	struct selinux_net_provenance *connection;
	struct selinux_net_provenance *peer;
	u32 connection_sid;
	u32 peer_sid;
};

static void selinux_inet_peer_candidate_put(
	struct selinux_inet_peer_candidate *candidate)
{
	selinux_net_provenance_put(candidate->peer);
	selinux_net_provenance_put(candidate->connection);
	memset(candidate, 0, sizeof(*candidate));
}

/* Resolve the packet and every derived label independently in each policy. */
static int selinux_inet_peer_candidate_prepare(
	struct selinux_net_provenance *base, struct sk_buff *skb, u16 family,
	bool derive_connection, struct selinux_inet_peer_candidate *candidate,
	struct selinux_policy_state_chain_snapshot *chain,
	struct selinux_net_avc_transaction *transaction)
{
	struct selinux_global_sid_handle *connection_handle = NULL;
	struct selinux_global_sid_handle *peer_handle = NULL;
	struct selinux_peer_sources sources;
	u32 connection_sid[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	u32 peer_sid[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	unsigned int retry;
	int rc;

	memset(candidate, 0, sizeof(*candidate));
	rc = selinux_peer_sources_capture(
		skb, family, base->state, base->view, &sources);
	if (rc)
		return rc;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;

		global_sid_handle_put(peer_handle);
		global_sid_handle_put(connection_handle);
		peer_handle = NULL;
		connection_handle = NULL;
		selinux_inet_peer_candidate_put(candidate);
		selinux_net_avc_transaction_reset(transaction);
		rc = selinux_policy_state_chain_snapshot_read(base->state, chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;

		for (i = 0; i < chain->count; i++) {
			struct selinux_global_sid_handle *level_connection
				__free(selinux_sid_handle) = NULL;
			struct selinux_global_sid_handle *level_peer
				__free(selinux_sid_handle) = NULL;
			struct selinux_state *state = chain->state[i];
			u32 base_sid;

			rc = selinux_net_avc_transaction_provenance_sid(
				transaction, base, state->label_domain, &base_sid);
			if (rc)
				break;
			if (!i) {
				peer_handle =
					selinux_net_avc_transaction_peer_sources_handle(
						transaction, &sources, state,
						&peer_sid[i]);
				if (IS_ERR(peer_handle)) {
					rc = PTR_ERR(peer_handle);
					peer_handle = NULL;
					break;
				}
			} else {
				level_peer =
					selinux_net_avc_transaction_peer_sources_handle(
					transaction, &sources, state, &peer_sid[i]);
				rc = IS_ERR(level_peer) ? PTR_ERR(level_peer) : 0;
				if (rc)
					break;
			}
			if (!derive_connection)
				continue;
			if (!i) {
				if (peer_sid[i] == SECSID_NULL) {
					connection_sid[i] = base_sid;
					connection_handle = global_sid_handle_dup(
						base->subject->sid_handle);
				} else {
					connection_handle = security_sid_mls_copy_handle(
						state, base_sid, peer_sid[i],
						&connection_sid[i]);
				}
				if (IS_ERR(connection_handle)) {
					rc = PTR_ERR(connection_handle);
					connection_handle = NULL;
					break;
				}
			} else {
				if (peer_sid[i] == SECSID_NULL) {
					connection_sid[i] = base_sid;
					level_connection = global_sid_handle_get(base_sid);
				} else {
					level_connection = security_sid_mls_copy_handle(
						state, base_sid, peer_sid[i],
						&connection_sid[i]);
				}
				rc = IS_ERR(level_connection) ?
					PTR_ERR(level_connection) : 0;
				if (rc)
					break;
			}
		}
		if (rc)
			goto retry_or_out;

		if (derive_connection) {
			candidate->connection = selinux_net_provenance_derive_handle(
				base, connection_handle,
				base->subject->semantic_class,
				SELINUX_NET_ASSERTION_SOURCE_SOCKET, GFP_ATOMIC);
			connection_handle = NULL;
			if (IS_ERR(candidate->connection)) {
				rc = PTR_ERR(candidate->connection);
				candidate->connection = NULL;
				break;
			}
		}
		if (peer_sid[0] != SECSID_NULL) {
			candidate->peer = selinux_net_provenance_derive_handle(
				base, peer_handle, SECCLASS_PEER,
				SELINUX_NET_ASSERTION_SOURCE_PEER_RESOLVED,
				GFP_ATOMIC);
			peer_handle = NULL;
			if (IS_ERR(candidate->peer)) {
				rc = PTR_ERR(candidate->peer);
				candidate->peer = NULL;
				break;
			}
		}
		rc = selinux_net_provenance_projection_matches(
			transaction, candidate->peer, chain, peer_sid);
		if (!rc && derive_connection)
			rc = selinux_net_provenance_projection_matches(
				transaction, candidate->connection, chain,
				connection_sid);
		if (!rc && !selinux_policy_state_chain_snapshot_valid(chain))
			rc = -ESTALE;
		if (!rc) {
			candidate->peer_sid = peer_sid[0];
			if (derive_connection)
				candidate->connection_sid = connection_sid[0];
			break;
		}

retry_or_out:
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		break;
	}
	if (retry == SELINUX_POLICY_OPERATION_RETRIES)
		rc = -ESTALE;

	selinux_net_avc_transaction_reset(transaction);
	global_sid_handle_put(peer_handle);
	global_sid_handle_put(connection_handle);
	selinux_peer_sources_put(&sources);
	if (rc)
		selinux_inet_peer_candidate_put(candidate);
	return rc;
}
#endif

static int selinux_inet_conn_request(const struct sock *sk, struct sk_buff *skb,
				     struct request_sock *req)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct selinux_state *state = sksec->state;
	int err;
	u16 family = req->rsk_ops->family;
	u32 connsid;
	u32 peersid;

#ifndef CONFIG_SECURITY_SELINUX_NS
	err = selinux_skb_peerlbl_sid(skb, family, state, &peersid);
	if (err)
		return err;
	err = selinux_conn_sid(sksec->sid, peersid, state, &connsid);
	if (err)
		return err;
#else
	{
		struct req_security_struct *reqsec = selinux_req(req);
		struct selinux_net_provenance *base;
		struct selinux_net_provenance *old_connection, *old_peer;
		struct selinux_inet_peer_candidate candidate;
		struct {
			struct selinux_policy_state_chain_snapshot chain;
			struct selinux_net_avc_transaction transaction;
		} *scratch __free(kfree) = NULL;

		base = selinux_net_provenance_get_rcu(&reqsec->provenance);
		if (!base || base->state != state || !base->view || !base->subject ||
		    !base->subject->sid_handle ||
		    base->subject->sid != READ_ONCE(sksec->sid)) {
			err = -EACCES;
			goto out_request_base;
		}
		scratch = kzalloc_obj(*scratch, GFP_ATOMIC);
		if (!scratch) {
			err = -ENOMEM;
			goto out_request_base;
		}
		err = selinux_inet_peer_candidate_prepare(
			base, skb, family, true, &candidate, &scratch->chain,
			&scratch->transaction);
		if (err)
			goto out_request_base;
		connsid = candidate.connection_sid;
		peersid = candidate.peer_sid;
		req->secid = connsid;
		req->peer_secid = peersid;
		if (!selinux_policy_state_chain_snapshot_valid(&scratch->chain)) {
			err = -ESTALE;
			goto out_request_candidate;
		}
		err = selinux_netlbl_inet_conn_request(req, family, state);
		if (err)
			goto out_request_candidate;
		old_connection = rcu_replace_pointer(reqsec->provenance,
						     candidate.connection, true);
		old_peer = rcu_replace_pointer(reqsec->peer_provenance,
					       candidate.peer, true);
		candidate.connection = NULL;
		candidate.peer = NULL;
		selinux_net_provenance_put(old_peer);
		selinux_net_provenance_put(old_connection);
		err = 0;
out_request_candidate:
		selinux_inet_peer_candidate_put(&candidate);
out_request_base:
		selinux_net_provenance_put(base);
		if (err)
			return err;
		return 0;
	}
#endif
	req->secid = connsid;
	req->peer_secid = peersid;

	return selinux_netlbl_inet_conn_request(req, family, state);
}

static void selinux_inet_csk_clone(struct sock *newsk,
				   const struct request_sock *req)
{
	struct sk_security_struct *newsksec = selinux_sock(newsk);
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct req_security_struct *reqsec = selinux_req(req);
	struct selinux_net_provenance *provenance, *peer;

	provenance = selinux_net_provenance_get_rcu(&reqsec->provenance);
	peer = selinux_net_provenance_get_rcu(&reqsec->peer_provenance);
	selinux_sk_provenance_free(newsksec);
	if (!provenance || provenance->subject->sid != req->secid ||
	    (req->peer_secid != SECSID_NULL &&
	     (!peer || peer->subject->sid != req->peer_secid))) {
		selinux_net_provenance_put(peer);
		selinux_net_provenance_put(provenance);
		provenance = NULL;
		peer = NULL;
	} else if (newsksec->state != provenance->state) {
		put_selinux_state(newsksec->state);
		newsksec->state = get_selinux_state(provenance->state);
	}
	RCU_INIT_POINTER(newsksec->provenance, provenance);
	RCU_INIT_POINTER(newsksec->peer_provenance, peer);
#endif

	newsksec->sid = req->secid;
	newsksec->peer_sid = req->peer_secid;
	/* NOTE: Ideally, we should also get the isec->sid for the
	   new socket in sync, but we don't have the isec available yet.
	   So we will wait until sock_graft to do it, by which
	   time it will have been created and available. */

	/* We don't need to take any sort of lock here as we are the only
	 * thread with access to newsksec */
	selinux_netlbl_inet_csk_clone(newsk, req->rsk_ops->family);
}

static void selinux_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
	u16 family = sk->sk_family;
	struct sk_security_struct *sksec = selinux_sock(sk);

	/* handle mapped IPv4 packets arriving via IPv6 sockets */
	if (family == PF_INET6 && skb->protocol == htons(ETH_P_IP))
		family = PF_INET;

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		struct selinux_net_provenance *base;
		struct selinux_inet_peer_candidate candidate;
		struct {
			struct selinux_policy_state_chain_snapshot chain;
			struct selinux_net_avc_transaction transaction;
		} *scratch __free(kfree) = NULL;
		int err;

		base = selinux_net_provenance_get_rcu(&sksec->provenance);
		if (!base || base->state != sksec->state || !base->view ||
		    !base->subject || !base->subject->sid_handle ||
		    base->subject->sid != READ_ONCE(sksec->sid))
			goto fail_closed;
		scratch = kzalloc_obj(*scratch, GFP_ATOMIC);
		if (!scratch)
			goto fail_closed;
		err = selinux_inet_peer_candidate_prepare(
			base, skb, family, false, &candidate, &scratch->chain,
			&scratch->transaction);
		if (err)
			goto fail_closed;
		if (!selinux_policy_state_chain_snapshot_valid(&scratch->chain)) {
			selinux_inet_peer_candidate_put(&candidate);
			goto fail_closed;
		}
		selinux_sk_peer_provenance_replace(sksec, candidate.peer);
		candidate.peer = NULL;
		selinux_inet_peer_candidate_put(&candidate);
		goto out_peer;

fail_closed:
		selinux_sk_peer_provenance_replace(sksec, NULL);
out_peer:
		selinux_net_provenance_put(base);
	}
#else
	selinux_skb_peerlbl_sid(skb, family, sksec->state, &sksec->peer_sid);
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_net_provenance *
selinux_secmark_provenance_take(struct lsm_secmark *secmark)
{
	struct selinux_net_provenance *provenance;

	if (!secmark)
		return NULL;
	provenance = secmark->selinux.provenance;
	secmark->selinux.provenance = NULL;
	return provenance;
}
EXPORT_SYMBOL_GPL(selinux_secmark_provenance_take);
#endif

static int selinux_secmark_relabel_packet(const struct net *net, u32 sid,
					  struct lsm_secmark *secmark)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_net_provenance *provenance;
	int rc;

	/*
	 * Parsing happens in the caller's policy, but the resulting global SID is
	 * only a handle for its canonical label; it must never be reused as another
	 * policy's local SID.  Capture the netns's exact immutable view before
	 * authorization, then let each policy in the credential chain resolve that
	 * same label.  cred_label_has_perm() snapshots and retries the whole chain
	 * and emits one fail-closed host aggregate on denial.
	 */
	if (!secmark || secmark->selinux.provenance)
		return -EINVAL;
	provenance = selinux_secmark_provenance_create(net, sid, GFP_KERNEL);
	if (IS_ERR(provenance))
		return PTR_ERR(provenance);
	if (!selinux_secmark_provenance_matches(provenance, sid)) {
		rc = -EACCES;
		goto out;
	}
	rc = cred_label_has_perm(current_cred(), sid,
				 provenance->subject->label, provenance->view,
				 SECCLASS_PACKET, PACKET__RELABELTO, NULL);
	if (!rc) {
		secmark->selinux.provenance = provenance;
		return 0;
	}
out:
	selinux_net_provenance_put(provenance);
	return rc;
#else
	(void)net;
	(void)secmark;
	return cred_tsid_has_perm(current_cred(), sid, SECCLASS_PACKET,
				  PACKET__RELABELTO, NULL);
#endif
}

static void selinux_secmark_release(struct lsm_secmark *secmark)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_net_provenance *provenance;

	if (!secmark)
		return;
	provenance = selinux_secmark_provenance_take(secmark);
	selinux_net_provenance_put(provenance);
#else
	(void)secmark;
#endif
}

static void selinux_secmark_refcount_inc(void)
{
	atomic_inc(&selinux_secmark_refcount);
}

static void selinux_secmark_refcount_dec(void)
{
	atomic_dec(&selinux_secmark_refcount);
}

static void selinux_req_classify_flow(const struct request_sock *req,
				      struct flowi_common *flic)
{
	flic->flowic_secid = req->secid;
}

static int selinux_tun_has_perm_snapshot(
	const struct selinux_label_resolution *resolution, u32 target_sid,
	u32 target_requested, u32 self_requested,
	const struct selinux_net_provenance *target)
{
	struct {
		struct selinux_policy_chain_snapshot chain;
#ifdef CONFIG_SECURITY_SELINUX_NS
		struct selinux_net_avc_transaction transaction;
#endif
	} *scratch __free(kfree) = NULL;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
#endif
	struct selinux_policy_chain_snapshot *chain;
	unsigned int retry;

#ifndef CONFIG_SECURITY_SELINUX_NS
	(void)resolution;
	(void)target;
#endif
	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	chain = &scratch->chain;
#ifdef CONFIG_SECURITY_SELINUX_NS
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_NET_AVC_MAX_CHECKS, GFP_KERNEL);
	if (!workspace)
		return -ENOMEM;
	scratch->transaction.workspace = workspace;
#endif

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;
		int rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
		selinux_net_avc_transaction_reset(&scratch->transaction);
#endif
		rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;

		for (i = 0, rc = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&chain->policy[i];
			u32 policy_tsid = target_sid;

#ifdef CONFIG_SECURITY_SELINUX_NS
			if (target_requested) {
				u16 depth = crsec->state->label_domain->depth;

				if (!resolution || depth > resolution->max_depth ||
				    resolution->domain_id[depth] !=
					    crsec->state->label_domain->id ||
				    !resolution->sid[depth]) {
					rc = -EOPNOTSUPP;
					break;
				}
				policy_tsid = resolution->sid[depth];
			}
#endif
			if (target_requested) {
#ifdef CONFIG_SECURITY_SELINUX_NS
				rc = selinux_net_avc_transaction_add_provenance(
					&scratch->transaction,
					&(struct selinux_avc_level) {
						.state = crsec->state,
						.ssid = crsec->sid,
						.tsid = policy_tsid,
						.requested = target_requested,
						.tclass = SECCLASS_TUN_SOCKET,
					}, snapshot, target);
#else
				rc = avc_has_perm_snapshot(
					crsec->state, snapshot, crsec->sid, policy_tsid,
					SECCLASS_TUN_SOCKET, target_requested, NULL);
#endif
				if (rc)
					break;
			}
			if (self_requested) {
#ifdef CONFIG_SECURITY_SELINUX_NS
				rc = selinux_net_avc_transaction_add(
					&scratch->transaction,
					&(struct selinux_avc_level) {
						.state = crsec->state,
						.ssid = crsec->sid,
						.tsid = crsec->sid,
						.requested = self_requested,
						.tclass = SECCLASS_TUN_SOCKET,
					}, snapshot, NULL);
#else
				rc = avc_has_perm_snapshot(
					crsec->state, snapshot, crsec->sid, crsec->sid,
					SECCLASS_TUN_SOCKET, self_requested, NULL);
#endif
				if (rc)
					break;
			}
		}
#ifdef CONFIG_SECURITY_SELINUX_NS
		if (!rc)
			rc = selinux_net_avc_transaction_decide(
				&scratch->transaction, NULL);
		if (rc == -ESTALE)
			continue;
#else
		if (rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain))
			continue;
#endif
#ifdef CONFIG_SECURITY_SELINUX_NS
		selinux_net_avc_transaction_reset(&scratch->transaction);
#endif
		return rc;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_net_avc_transaction_reset(&scratch->transaction);
#endif
	return -ESTALE;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static struct selinux_net_provenance *
selinux_tun_provenance_get_reanchored(struct tun_security_struct *tunsec,
					     const struct net *net)
{
	const struct selinux_netns_security *netsec = selinux_netns(net);
	struct selinux_net_provenance *provenance, *replacement, *displaced;

	ASSERT_RTNL();
	if (!netsec || !netsec->state || !netsec->state->label_domain ||
	    !netsec->view || !netsec->view->owner_userns)
		return ERR_PTR(-EACCES);

	provenance = selinux_net_provenance_get_rcu(&tunsec->provenance);
	if (!provenance || provenance->subject->sid != READ_ONCE(tunsec->sid) ||
	    provenance->subject->semantic_class != SECCLASS_TUN_SOCKET ||
	    provenance->subject->source != SELINUX_NET_ASSERTION_SOURCE_TUN) {
		selinux_net_provenance_put(provenance);
		return ERR_PTR(-EACCES);
	}
	if (provenance->view->owner_userns == netsec->view->owner_userns &&
	    provenance->view->outer_domain == netsec->state->label_domain)
		return provenance;

	/* Preserve the canonical label and change only its network view. */
	replacement = selinux_net_provenance_create(
		provenance->state, netsec->view->owner_userns,
		netsec->state->label_domain, provenance->subject->sid,
		provenance->subject->semantic_class, provenance->subject->source,
		GFP_KERNEL);
	if (IS_ERR(replacement)) {
		selinux_net_provenance_put(provenance);
		return replacement;
	}

	/* RTNL serializes every TUN blob reader and writer. */
	displaced = rcu_replace_pointer(tunsec->provenance, replacement,
					lockdep_rtnl_is_held());
	replacement = selinux_net_provenance_get(replacement);
	selinux_net_provenance_put(displaced);
	selinux_net_provenance_put(provenance);
	return replacement;
}
#endif

static int selinux_tun_dev_alloc_security(void *security,
					  const struct net *net)
{
	struct tun_security_struct *tunsec = selinux_tun_dev(security);

	tunsec->sid = current_sid();
#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		const struct selinux_netns_security *netsec = selinux_netns(net);
		struct selinux_net_provenance *provenance;

		if (!netsec || !netsec->state || !netsec->view)
			return -EACCES;
		provenance = selinux_net_provenance_create(
			current_selinux_state, netsec->view->owner_userns,
			netsec->state->label_domain, tunsec->sid,
			SECCLASS_TUN_SOCKET, SELINUX_NET_ASSERTION_SOURCE_TUN,
			GFP_KERNEL);
		if (IS_ERR(provenance))
			return PTR_ERR(provenance);
		RCU_INIT_POINTER(tunsec->provenance, provenance);
	}
#endif
	return 0;
}

static void selinux_tun_dev_free_security(void *security)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct tun_security_struct *tunsec = selinux_tun_dev(security);
	struct selinux_net_provenance *provenance;

	provenance = rcu_dereference_protected(tunsec->provenance, 1);
	RCU_INIT_POINTER(tunsec->provenance, NULL);
	selinux_net_provenance_put(provenance);
#else
	(void)security;
#endif
}

static int selinux_tun_dev_create(void)
{
	/* we aren't taking into account the "sockcreate" SID since the socket
	 * that is being created here is not a socket in the traditional sense,
	 * instead it is a private sock, accessible only to the kernel, and
	 * representing a wide range of network traffic spanning multiple
	 * connections unlike traditional sockets - check the TUN driver to
	 * get a better understanding of why this socket is special */

	return selinux_tun_has_perm_snapshot(NULL, SECSID_NULL, 0,
					     TUN_SOCKET__CREATE, NULL);
}

static int selinux_tun_dev_attach_queue(void *security, const struct net *net)
{
	struct tun_security_struct *tunsec = selinux_tun_dev(security);

	ASSERT_RTNL();
#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		struct selinux_net_provenance *provenance;
		struct selinux_label_resolution resolution;
		int rc;

		provenance = selinux_tun_provenance_get_reanchored(tunsec, net);
		if (IS_ERR(provenance))
			return PTR_ERR(provenance);
		rc = selinux_label_view_resolve_chain(
			provenance->view, provenance->subject->label,
			provenance->subject->sid, &resolution);
		if (!rc)
			rc = selinux_tun_has_perm_snapshot(
				&resolution, provenance->subject->sid,
				TUN_SOCKET__ATTACH_QUEUE, 0, provenance);
		selinux_net_provenance_put(provenance);
		return rc;
	}
#else
	(void)net;
	return selinux_tun_has_perm_snapshot(NULL, tunsec->sid,
					     TUN_SOCKET__ATTACH_QUEUE, 0, NULL);
#endif
}

static int selinux_tun_dev_attach(struct sock *sk, void *security,
				  const struct net *net)
{
	struct tun_security_struct *tunsec = selinux_tun_dev(security);
	struct sk_security_struct *sksec = selinux_sock(sk);
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_net_provenance *provenance;
	struct selinux_state *old_state = NULL;
#endif

	ASSERT_RTNL();
#ifdef CONFIG_SECURITY_SELINUX_NS
	provenance = selinux_tun_provenance_get_reanchored(tunsec, net);
	if (IS_ERR(provenance))
		return PTR_ERR(provenance);
#else
	(void)net;
#endif

	/* we don't currently perform any NetLabel based labeling here and it
	 * isn't clear that we would want to do so anyway; while we could apply
	 * labeling without the support of the TUN user the resulting labeled
	 * traffic from the other end of the connection would almost certainly
	 * cause confusion to the TUN user that had no idea network labeling
	 * protocols were being used */

	selinux_netlbl_sk_security_free(sksec);
	selinux_netlbl_sk_security_reset(sksec);
#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_sk_provenance_free(sksec);
	if (sksec->state != provenance->state) {
		old_state = sksec->state;
		WRITE_ONCE(sksec->state, get_selinux_state(provenance->state));
	}
	WRITE_ONCE(sksec->sid, provenance->subject->sid);
	WRITE_ONCE(sksec->sclass, SECCLASS_TUN_SOCKET);
	rcu_assign_pointer(sksec->provenance, provenance);
	put_selinux_state(old_state);
#else
	sksec->sid = tunsec->sid;
	sksec->sclass = SECCLASS_TUN_SOCKET;
#endif

	return 0;
}

static int selinux_tun_dev_open(void *security, const struct net *net)
{
	struct tun_security_struct *tunsec = selinux_tun_dev(security);
	int err;

	ASSERT_RTNL();
#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		struct selinux_net_provenance *old, *new, *displaced;
		struct selinux_label_resolution resolution;

		old = selinux_tun_provenance_get_reanchored(tunsec, net);
		if (IS_ERR(old))
			return PTR_ERR(old);
		err = selinux_label_view_resolve_chain(
			old->view, old->subject->label, old->subject->sid,
			&resolution);
		if (err)
			goto out_old;
		err = selinux_tun_has_perm_snapshot(
			&resolution, old->subject->sid,
			TUN_SOCKET__RELABELFROM, TUN_SOCKET__RELABELTO, old);
		if (err)
			goto out_old;
		new = selinux_net_provenance_create(
			current_selinux_state, old->view->owner_userns,
			old->view->outer_domain, current_sid(),
			SECCLASS_TUN_SOCKET, SELINUX_NET_ASSERTION_SOURCE_TUN,
			GFP_KERNEL);
		if (IS_ERR(new)) {
			err = PTR_ERR(new);
			goto out_old;
		}
		/* RTNL makes SID plus the RCU pointer one externally visible tuple. */
		WRITE_ONCE(tunsec->sid, new->subject->sid);
		displaced = rcu_replace_pointer(tunsec->provenance, new,
						lockdep_rtnl_is_held());
		selinux_net_provenance_put(displaced);
		err = 0;
out_old:
		selinux_net_provenance_put(old);
		return err;
	}
#else
	(void)net;
	err = selinux_tun_has_perm_snapshot(
		NULL, tunsec->sid, TUN_SOCKET__RELABELFROM,
		TUN_SOCKET__RELABELTO, NULL);
	if (err)
		return err;
	tunsec->sid = current_sid();

	return 0;
#endif
}

#ifdef CONFIG_NETFILTER

#ifndef CONFIG_SECURITY_SELINUX_NS
static int
selinux_ip_forward_snapshot(struct sk_buff *skb,
			    const struct nf_hook_state *state,
			    const struct selinux_policy_snapshot *snapshot)
{
	int ifindex;
	u16 family;
	char *addrp;
	u32 peer_sid;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	struct selinux_state *se_state = init_selinux_state;
	int secmark_active, peerlbl_active;
	int err;

	if (!selinux_policy_snapshot_has_cap(snapshot, POLICYDB_CAP_NETPEER))
		return selinux_policy_snapshot_valid(se_state, snapshot) ? 0 :
								 -ESTALE;

	secmark_active = selinux_secmark_enabled(snapshot);
	peerlbl_active = selinux_peerlbl_enabled(snapshot);
	if (!secmark_active && !peerlbl_active)
		return selinux_policy_snapshot_valid(se_state, snapshot) ? 0 :
								 -ESTALE;

	family = state->pf;
	if (selinux_skb_peerlbl_sid(skb, family, se_state, &peer_sid) != 0)
		return -EACCES;

	ifindex = state->in->ifindex;
	ad_net_init_from_iif(&ad, &net, ifindex, family);
	if (selinux_parse_skb(skb, &ad, &addrp, 1, NULL) != 0)
		return -EACCES;

	if (peerlbl_active) {
		err = selinux_inet_sys_rcv_skb(se_state, snapshot, state->net,
					       ifindex, addrp, family, peer_sid,
					       &ad);
		if (err) {
			selinux_netlbl_err(skb, family, err, 1);
			return err;
		}
	}

	if (secmark_active) {
		err = avc_has_perm_snapshot(se_state, snapshot, peer_sid,
					    skb->secmark, SECCLASS_PACKET,
					    PACKET__FORWARD_IN, &ad);
		if (err)
			return err;
	}

	if (!selinux_policy_snapshot_valid(se_state, snapshot))
		return -ESTALE;

	if (netlbl_enabled())
		/* we do this in the FORWARD path and not the POST_ROUTING
		 * path because we want to make sure we apply the necessary
		 * labeling before IPsec is applied so we can leverage AH
		 * protection */
		if (selinux_netlbl_skbuff_setsid(skb, family, se_state, peer_sid)
			!= 0)
			return -EACCES;

	return 0;
}

static unsigned int selinux_ip_forward(void *priv, struct sk_buff *skb,
				       const struct nf_hook_state *state)
{
	struct selinux_policy_snapshot snapshot;
	unsigned int retry;
	int err;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		err = selinux_policy_snapshot_read(init_selinux_state, &snapshot);
		if (err == -EAGAIN)
			continue;
		if (err)
			return NF_DROP;
		err = selinux_ip_forward_snapshot(skb, state, &snapshot);
		if (err != -ESTALE)
			return err ? NF_DROP : NF_ACCEPT;
	}

	return NF_DROP;
}
#else
static int selinux_ip_forward_policy(
	struct sk_buff *skb, const struct nf_hook_state *hook_state,
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot,
	const struct selinux_peer_sources *sources,
	const struct selinux_label_view *view,
	struct selinux_net_avc_transaction *transaction,
	struct common_audit_data *ad, u32 *peer_sid_out,
	struct selinux_global_sid_handle **peer_handle_out,
	bool *netlbl_checked)
{
	struct selinux_global_sid_handle *peer_handle;
	u32 peer_sid;
	char *addrp;
	int ifindex, err;
	u16 family;

	if (!selinux_policy_snapshot_has_cap(snapshot, POLICYDB_CAP_NETPEER)) {
		*peer_sid_out = SECSID_NULL;
		*peer_handle_out = NULL;
		return 0;
	}
	family = hook_state->pf;
	peer_handle = selinux_net_avc_transaction_peer_sources_handle(
		transaction, sources, state, &peer_sid);
	if (IS_ERR(peer_handle))
		return PTR_ERR(peer_handle);
	*peer_sid_out = peer_sid;
	*peer_handle_out = peer_handle;
	ifindex = hook_state->in->ifindex;
	err = selinux_parse_skb(skb, ad, &addrp, 1, NULL);
	if (err)
		return err;

	if (selinux_peerlbl_enabled(snapshot)) {
		err = selinux_inet_sys_rcv_skb_add(
			transaction, state, snapshot, view, hook_state->net,
			ifindex, addrp, family, peer_sid);
		if (err) {
			*netlbl_checked = true;
			return err;
		}
		*netlbl_checked = true;
	}
	if (selinux_secmark_enabled(snapshot)) {
		u32 secmark_sid;

		err = selinux_skb_secmark_sid(skb, state, transaction,
					     &secmark_sid);
		if (err)
			return err;
		return selinux_net_avc_transaction_add_provenance(
			transaction,
			&(struct selinux_avc_level) {
				.state = state,
				.ssid = peer_sid,
				.tsid = secmark_sid,
				.requested = PACKET__FORWARD_IN,
				.tclass = SECCLASS_PACKET,
			}, snapshot, skb->secmark_provenance);
	}
	return 0;
}

static unsigned int selinux_ip_forward(void *priv, struct sk_buff *skb,
				       const struct nf_hook_state *hook_state)
{
	const struct selinux_netns_security *netsec =
		selinux_netns(hook_state->net);
	struct {
		struct selinux_policy_state_chain_snapshot chain;
		struct selinux_net_avc_transaction transaction;
		struct selinux_global_sid_handle
			*peer_handle[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	} *scratch __free(kfree) = NULL;
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
	struct selinux_policy_state_chain_snapshot *chain;
	struct selinux_peer_sources sources;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	u32 origin_peer_sid = SECSID_NULL;
	bool origin_netpeer = false;
	unsigned int retry;
	int err;

	if (!netsec || !netsec->state || !netsec->state->label_domain ||
	    !netsec->view || netsec->view->origin_domain !=
			     netsec->state->label_domain)
		return NF_DROP;
	scratch = kzalloc_obj(*scratch, GFP_ATOMIC);
	if (!scratch)
		return NF_DROP;
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_NET_AVC_MAX_CHECKS, GFP_ATOMIC | __GFP_NOWARN);
	if (!workspace)
		return NF_DROP;
	scratch->transaction.workspace = workspace;
	chain = &scratch->chain;
	err = selinux_peer_sources_capture(skb, hook_state->pf, netsec->state,
					   netsec->view, &sources);
	if (err)
		return NF_DROP;
	ad_net_init_from_iif(&ad, &net, hook_state->in->ifindex,
			     hook_state->pf);

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		bool netlbl_checked = false;
		u16 i;

		for (i = 0; i < ARRAY_SIZE(scratch->peer_handle); i++) {
			global_sid_handle_put(scratch->peer_handle[i]);
			scratch->peer_handle[i] = NULL;
		}
		selinux_net_avc_transaction_reset(&scratch->transaction);
		err = selinux_policy_state_chain_snapshot_read(netsec->state,
							       chain);
		if (err == -EAGAIN || err == -ESTALE)
			continue;
		if (err)
			break;
		origin_netpeer = selinux_policy_snapshot_has_cap(
			&chain->policy[0], POLICYDB_CAP_NETPEER);
		for (i = 0, err = 0; i < chain->count; i++) {
			u32 peer_sid;
			u16 initial_count = scratch->transaction.count;

			err = selinux_ip_forward_policy(
				skb, hook_state, chain->state[i], &chain->policy[i],
				&sources, netsec->view, &scratch->transaction, &ad,
				&peer_sid, &scratch->peer_handle[i], &netlbl_checked);
			if (err)
				break;
			err = selinux_net_avc_transaction_add_guard(
				&scratch->transaction, initial_count, chain->state[i],
				&chain->policy[i]);
			if (err)
				break;
			if (!i)
				origin_peer_sid = peer_sid;
		}
		if (!err)
			err = selinux_net_avc_transaction_decide(
				&scratch->transaction, &ad);
		if (err == -ESTALE)
			continue;
		if (err && netlbl_checked)
			selinux_netlbl_err(skb, hook_state->pf, err, 1);
		if (!err && origin_netpeer && netlbl_enabled())
			err = selinux_netlbl_skbuff_setsid(
				skb, hook_state->pf, netsec->state,
				origin_peer_sid);
		break;
	}
	for (retry = 0; retry < ARRAY_SIZE(scratch->peer_handle); retry++)
		global_sid_handle_put(scratch->peer_handle[retry]);
	selinux_net_avc_transaction_reset(&scratch->transaction);
	selinux_peer_sources_put(&sources);
	return err ? NF_DROP : NF_ACCEPT;
}
#endif

static unsigned int selinux_ip_output(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct selinux_state *se_state;
	struct sock *sk;
	u32 sid;

	if (!netlbl_enabled())
		return NF_ACCEPT;

	/* we do this in the LOCAL_OUT path and not the POST_ROUTING path
	 * because we want to make sure we apply the necessary labeling
	 * before IPsec is applied so we can leverage AH protection */
	sk = skb_to_full_sk(skb);
	if (sk) {
		struct sk_security_struct *sksec;

		if (sk_listener(sk))
			/* if the socket is the listening state then this
			 * packet is a SYN-ACK packet which means it needs to
			 * be labeled based on the connection/request_sock and
			 * not the parent socket.  unfortunately, we can't
			 * lookup the request_sock yet as it isn't queued on
			 * the parent socket until after the SYN-ACK is sent.
			 * the "solution" is to simply pass the packet as-is
			 * as any IP option based labeling should be copied
			 * from the initial connection request (in the IP
			 * layer).  it is far from ideal, but until we get a
			 * security label in the packet itself this is the
			 * best we can do. */
			return NF_ACCEPT;

		/* standard practice, label using the parent socket */
		sksec = selinux_sock(sk);
		sid = sksec->sid;
		se_state = sksec->state;
	} else {
		sid = SECINITSID_KERNEL;
		se_state = init_selinux_state;
	}
	if (selinux_netlbl_skbuff_setsid(skb, state->pf, se_state, sid) != 0)
		return NF_DROP;

	return NF_ACCEPT;
}

#ifndef CONFIG_SECURITY_SELINUX_NS
static int
selinux_ip_postroute_compat(struct sk_buff *skb,
			    const struct nf_hook_state *state, struct sock *sk,
			    const struct selinux_policy_snapshot *snapshot)
{
	struct sk_security_struct *sksec;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	u8 proto = 0;

	if (!sk)
		return selinux_policy_snapshot_valid(init_selinux_state,
						      snapshot) ? 0 : -ESTALE;
	sksec = selinux_sock(sk);

	ad_net_init_from_iif(&ad, &net, state->out->ifindex, state->pf);
	if (selinux_parse_skb(skb, &ad, NULL, 0, &proto))
		return -EACCES;

	if (selinux_secmark_enabled(snapshot)) {
		int err = avc_has_perm_snapshot(sksec->state, snapshot,
						sksec->sid, skb->secmark,
						SECCLASS_PACKET, PACKET__SEND,
						&ad);

		if (err)
			return err;
	}

	if (selinux_xfrm_postroute_last(sksec->sid, skb, sksec->state, &ad,
					proto))
		return -EACCES;

	return selinux_policy_snapshot_valid(sksec->state, snapshot) ? 0 :
								 -ESTALE;
}

static int
selinux_ip_postroute_snapshot(struct sk_buff *skb,
			      const struct nf_hook_state *state, struct sock *sk,
			      struct selinux_state *se_state,
			      const struct selinux_policy_snapshot *snapshot)
{
	u16 family;
	u32 secmark_perm;
	u32 peer_sid;
	int ifindex;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	char *addrp;
	int secmark_active, peerlbl_active;
	int err;

	/* If any sort of compatibility mode is enabled then handoff processing
	 * to the selinux_ip_postroute_compat() function to deal with the
	 * special handling.  We do this in an attempt to keep this function
	 * as fast and as clean as possible. */
	if (!selinux_policy_snapshot_has_cap(snapshot, POLICYDB_CAP_NETPEER))
		return selinux_ip_postroute_compat(skb, state, sk, snapshot);

	secmark_active = selinux_secmark_enabled(snapshot);
	peerlbl_active = selinux_peerlbl_enabled(snapshot);
	if (!secmark_active && !peerlbl_active)
		return selinux_policy_snapshot_valid(se_state, snapshot) ? 0 :
								 -ESTALE;

#ifdef CONFIG_XFRM
	/* If skb->dst->xfrm is non-NULL then the packet is undergoing an IPsec
	 * packet transformation so allow the packet to pass without any checks
	 * since we'll have another chance to perform access control checks
	 * when the packet is on it's final way out.
	 * NOTE: there appear to be some IPv6 multicast cases where skb->dst
	 *       is NULL, in this case go ahead and apply access control.
	 * NOTE: if this is a local socket (skb->sk != NULL) that is in the
	 *       TCP listening state we cannot wait until the XFRM processing
	 *       is done as we will miss out on the SA label if we do;
	 *       unfortunately, this means more work, but it is only once per
	 *       connection. */
	if (skb_dst(skb) != NULL && skb_dst(skb)->xfrm != NULL &&
	    !(sk && sk_listener(sk)))
		return selinux_policy_snapshot_valid(se_state, snapshot) ? 0 :
								 -ESTALE;
#endif

	family = state->pf;
	if (sk == NULL) {
		/* Without an associated socket the packet is either coming
		 * from the kernel or it is being forwarded; check the packet
		 * to determine which and if the packet is being forwarded
		 * query the packet directly to determine the security label. */
		if (skb->skb_iif) {
			secmark_perm = PACKET__FORWARD_OUT;
			if (selinux_skb_peerlbl_sid(skb, family, se_state,
						    &peer_sid))
				return -EACCES;
		} else {
			secmark_perm = PACKET__SEND;
			peer_sid = SECINITSID_KERNEL;
		}
	} else if (sk_listener(sk)) {
		/* Locally generated packet but the associated socket is in the
		 * listening state which means this is a SYN-ACK packet.  In
		 * this particular case the correct security label is assigned
		 * to the connection/request_sock but unfortunately we can't
		 * query the request_sock as it isn't queued on the parent
		 * socket until after the SYN-ACK packet is sent; the only
		 * viable choice is to regenerate the label like we do in
		 * selinux_inet_conn_request().  See also selinux_ip_output()
		 * for similar problems. */
		u32 skb_sid;
		struct sk_security_struct *sksec;

		sksec = selinux_sock(sk);
		if (selinux_skb_peerlbl_sid(skb, family, se_state, &skb_sid))
			return -EACCES;
		/* At this point, if the returned skb peerlbl is SECSID_NULL
		 * and the packet has been through at least one XFRM
		 * transformation then we must be dealing with the "final"
		 * form of labeled IPsec packet; since we've already applied
		 * all of our access controls on this packet we can safely
		 * pass the packet. */
		if (skb_sid == SECSID_NULL) {
			switch (family) {
			case PF_INET:
				if (IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) {
					if (!selinux_policy_snapshot_valid(se_state,
									   snapshot))
						return -ESTALE;
					return 0;
				}
				break;
			case PF_INET6:
				if (IP6CB(skb)->flags & IP6SKB_XFRM_TRANSFORMED) {
					if (!selinux_policy_snapshot_valid(se_state,
									   snapshot))
						return -ESTALE;
					return 0;
				}
				break;
			default:
				return -EACCES;
			}
		}
		if (selinux_conn_sid(sksec->sid, skb_sid, se_state, &peer_sid))
			return -EACCES;
		secmark_perm = PACKET__SEND;
	} else {
		/* Locally generated packet, fetch the security label from the
		 * associated socket. */
		struct sk_security_struct *sksec = selinux_sock(sk);
		peer_sid = sksec->sid;
		secmark_perm = PACKET__SEND;
	}

	ifindex = state->out->ifindex;
	ad_net_init_from_iif(&ad, &net, ifindex, family);
	if (selinux_parse_skb(skb, &ad, &addrp, 0, NULL))
		return -EACCES;

	if (secmark_active) {
		err = avc_has_perm_snapshot(se_state, snapshot, peer_sid,
					    skb->secmark, SECCLASS_PACKET,
					    secmark_perm, &ad);
		if (err)
			return err;
	}

	if (peerlbl_active) {
		u32 if_sid;
		u32 node_sid;

		if (sel_netif_sid_snapshot(se_state, snapshot, state->net,
					     ifindex, &if_sid))
			return -EACCES;
		err = avc_has_perm_snapshot(se_state, snapshot, peer_sid,
					    if_sid, SECCLASS_NETIF,
					    NETIF__EGRESS, &ad);
		if (err)
			return err;

		if (sel_netnode_sid_snapshot(se_state, snapshot, addrp, family,
					       &node_sid))
			return -EACCES;
		err = avc_has_perm_snapshot(se_state, snapshot, peer_sid,
					    node_sid, SECCLASS_NODE,
					    NODE__SENDTO, &ad);
		if (err)
			return err;
	}

	return selinux_policy_snapshot_valid(se_state, snapshot) ? 0 : -ESTALE;
}

static unsigned int selinux_ip_postroute(void *priv, struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	struct selinux_policy_snapshot snapshot;
	struct selinux_state *se_state = init_selinux_state;
	struct sock *sk = skb_to_full_sk(skb);
	unsigned int retry;
	int err;

	if (sk)
		se_state = selinux_sock(sk)->state;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		err = selinux_policy_snapshot_read(se_state, &snapshot);
		if (err == -EAGAIN)
			continue;
		if (err)
			return NF_DROP;
		err = selinux_ip_postroute_snapshot(skb, state, sk, se_state,
						     &snapshot);
		if (err != -ESTALE)
			return err ? NF_DROP_ERR(-ECONNREFUSED) : NF_ACCEPT;
	}

	return NF_DROP_ERR(-ECONNREFUSED);
}
#else

enum selinux_postroute_origin {
	SELINUX_POSTROUTE_SOCKET,
	SELINUX_POSTROUTE_LISTENER,
	SELINUX_POSTROUTE_FORWARDED,
	SELINUX_POSTROUTE_KERNEL,
};

static bool selinux_ip_postroute_xfrm_transformed(const struct sk_buff *skb,
						  u16 family)
{
	switch (family) {
	case PF_INET:
		return IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED;
#if IS_ENABLED(CONFIG_IPV6)
	case PF_INET6:
		return IP6CB(skb)->flags & IP6SKB_XFRM_TRANSFORMED;
#endif
	default:
		return false;
	}
}

static int selinux_ip_postroute_resolution_sid(
	const struct selinux_label_resolution *resolution,
	const struct selinux_state *state, u32 *sid)
{
	u16 depth;

	if (!resolution || !state || !state->label_domain || !sid)
		return -EINVAL;
	depth = state->depth;
	if (depth > resolution->max_depth ||
	    resolution->domain_id[depth] != state->label_domain->id ||
	    !resolution->sid[depth])
		return -EOPNOTSUPP;
	*sid = resolution->sid[depth];
	return 0;
}

static int selinux_ip_postroute_initial_resolution(
	const struct selinux_label_view *view, u32 sid,
	struct selinux_label_resolution *resolution)
{
	struct selinux_label_ref *label;
	int err;

	label = global_sid_to_label_ref(sid);
	if (IS_ERR(label))
		return PTR_ERR(label);
	err = selinux_label_view_resolve_chain(view, label, sid, resolution);
	selinux_label_ref_put(label);
	return err;
}

/*
 * Legacy policies make an association:sendto decision only for local socket
 * traffic.  A labeled egress SA was authorized earlier by the XFRM hooks; an
 * unlabeled route must be authorized against SECINITSID_UNLABELED here.  The
 * immutable XFRM provenance is also the fail-closed proof that a labeled SA
 * really exists in a namespaced build.
 */
static int selinux_ip_postroute_compat_ns(
	struct sk_buff *skb, struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot, u32 socket_sid,
	enum selinux_postroute_origin origin,
	struct selinux_net_avc_transaction *transaction)
{
	struct selinux_net_provenance *xfrm = NULL;
	int err;

	if (origin != SELINUX_POSTROUTE_SOCKET &&
	    origin != SELINUX_POSTROUTE_LISTENER)
		return 0;

	if (selinux_secmark_enabled(snapshot)) {
		u32 secmark_sid;

		err = selinux_skb_secmark_sid(skb, state, transaction,
					     &secmark_sid);
		if (err)
			return err;
		err = selinux_net_avc_transaction_add_provenance(
			transaction, &(struct selinux_avc_level) {
				.state = state,
				.ssid = socket_sid,
				.tsid = secmark_sid,
				.tclass = SECCLASS_PACKET,
				.requested = PACKET__SEND,
			}, snapshot, skb->secmark_provenance);
		if (err)
			return err;
	}

	if (!IS_ENABLED(CONFIG_SECURITY_NETWORK_XFRM))
		return 0;

	err = selinux_xfrm_skb_provenance_egress(skb, &xfrm);
	if (err)
		return err;
	if (xfrm) {
		selinux_net_provenance_put(xfrm);
		return 0;
	}
	return selinux_net_avc_transaction_add(
		transaction, &(struct selinux_avc_level) {
			.state = state,
			.ssid = socket_sid,
			.tsid = SECINITSID_UNLABELED,
			.tclass = SECCLASS_ASSOCIATION,
			.requested = ASSOCIATION__SENDTO,
		}, snapshot, NULL);
}

static int selinux_ip_postroute_policy_ns(
	struct sk_buff *skb, const struct nf_hook_state *hook_state,
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot,
	enum selinux_postroute_origin origin,
	const struct selinux_label_resolution *subject_resolution,
	const struct selinux_peer_sources *sources, bool xfrm_pending,
	char *addrp, const struct selinux_label_view *view,
	struct selinux_net_avc_transaction *transaction,
	struct selinux_global_sid_handle **subject_handle_out)
{
	struct selinux_global_sid_handle *subject_handle = NULL;
	u32 subject_sid, socket_sid = SECSID_NULL;
	int err;

	*subject_handle_out = NULL;

	if (origin == SELINUX_POSTROUTE_SOCKET ||
	    origin == SELINUX_POSTROUTE_LISTENER) {
		err = selinux_ip_postroute_resolution_sid(subject_resolution, state,
							 &socket_sid);
		if (err)
			return err;
	}

	if (!selinux_policy_snapshot_has_cap(snapshot, POLICYDB_CAP_NETPEER))
		return selinux_ip_postroute_compat_ns(
			skb, state, snapshot, socket_sid, origin,
			transaction);

	/* A later POSTROUTE pass sees the final transform and performs checks. */
	if (xfrm_pending && origin != SELINUX_POSTROUTE_LISTENER)
		return 0;
	if (!selinux_secmark_enabled(snapshot) &&
	    !selinux_peerlbl_enabled(snapshot))
		return 0;

	switch (origin) {
	case SELINUX_POSTROUTE_SOCKET:
		subject_sid = socket_sid;
		break;
	case SELINUX_POSTROUTE_LISTENER: {
		struct selinux_global_sid_handle *peer_handle;
		u32 peer_sid;

		/*
		 * There is no request_sock pointer on the SYN-ACK skb.  Recreate
		 * its policy-local connection SID from the immutable listener and
		 * packet sources, as the non-namespaced path historically does.
		 * Once a transform consumed every peer carrier, however, accepting
		 * based on the listener alone would silently reinterpret the object;
		 * keep that unsupported case fail-closed.
		 */
		if (selinux_ip_postroute_xfrm_transformed(skb, hook_state->pf) &&
		    !sources->netlabel.cache && !sources->xfrm)
			return -EOPNOTSUPP;
		peer_handle = selinux_net_avc_transaction_peer_sources_handle(
			transaction, sources, state, &peer_sid);
		if (IS_ERR(peer_handle))
			return PTR_ERR(peer_handle);
		subject_handle = selinux_conn_sid_handle(
			socket_sid, peer_sid, state, &subject_sid);
		global_sid_handle_put(peer_handle);
		if (IS_ERR(subject_handle))
			return PTR_ERR(subject_handle);
		*subject_handle_out = subject_handle;
		break;
	}
	case SELINUX_POSTROUTE_FORWARDED:
		subject_handle = selinux_net_avc_transaction_peer_sources_handle(
			transaction, sources, state, &subject_sid);
		if (IS_ERR(subject_handle))
			return PTR_ERR(subject_handle);
		*subject_handle_out = subject_handle;
		break;
	case SELINUX_POSTROUTE_KERNEL:
		err = selinux_ip_postroute_resolution_sid(subject_resolution, state,
							 &subject_sid);
		if (err)
			return err;
		break;
	default:
		return -EINVAL;
	}

	if (selinux_secmark_enabled(snapshot)) {
		u32 perm = origin == SELINUX_POSTROUTE_FORWARDED ?
				 PACKET__FORWARD_OUT : PACKET__SEND;
		u32 secmark_sid;

		err = selinux_skb_secmark_sid(skb, state, transaction,
					     &secmark_sid);
		if (err)
			return err;
		err = selinux_net_avc_transaction_add_provenance(
			transaction, &(struct selinux_avc_level) {
				.state = state,
				.ssid = subject_sid,
				.tsid = secmark_sid,
				.tclass = SECCLASS_PACKET,
				.requested = perm,
			}, snapshot, skb->secmark_provenance);
		if (err)
			return err;
	}

	if (selinux_peerlbl_enabled(snapshot)) {
		struct selinux_global_sid_handle *if_handle;
		struct selinux_global_sid_handle *node_handle;
		u32 if_sid, node_sid;
		int ifindex = hook_state->out->ifindex;

		if_handle = sel_netif_sid_snapshot_handle(
			state, snapshot, hook_state->net, ifindex, &if_sid);
		if (IS_ERR(if_handle))
			return PTR_ERR(if_handle);
		err = selinux_net_avc_transaction_add_handle(
			transaction, &(struct selinux_avc_level) {
				.state = state,
				.ssid = subject_sid,
				.tsid = if_sid,
				.tclass = SECCLASS_NETIF,
				.requested = NETIF__EGRESS,
			}, snapshot, if_handle, view,
			SELINUX_LABEL_SOURCE_SECURITY_CONTEXT);
		if (err)
			return err;
		node_handle = sel_netnode_sid_snapshot_handle(
			state, snapshot, addrp, hook_state->pf, &node_sid);
		if (IS_ERR(node_handle))
			return PTR_ERR(node_handle);
		err = selinux_net_avc_transaction_add_handle(
			transaction, &(struct selinux_avc_level) {
				.state = state,
				.ssid = subject_sid,
				.tsid = node_sid,
				.tclass = SECCLASS_NODE,
				.requested = NODE__SENDTO,
			}, snapshot, node_handle, view,
			SELINUX_LABEL_SOURCE_SECURITY_CONTEXT);
		if (err)
			return err;
	}

	return 0;
}

static bool selinux_ip_postroute_policy_needs_parse(
	const struct selinux_policy_snapshot *snapshot,
	enum selinux_postroute_origin origin, bool xfrm_pending)
{
	if (!selinux_policy_snapshot_has_cap(snapshot, POLICYDB_CAP_NETPEER))
		return origin == SELINUX_POSTROUTE_SOCKET ||
		       origin == SELINUX_POSTROUTE_LISTENER;
	if (xfrm_pending && origin != SELINUX_POSTROUTE_LISTENER)
		return false;
	return selinux_secmark_enabled(snapshot) ||
	       selinux_peerlbl_enabled(snapshot);
}

static unsigned int selinux_ip_postroute(void *priv, struct sk_buff *skb,
					 const struct nf_hook_state *hook_state)
{
	const struct selinux_netns_security *netsec;
	struct {
		struct selinux_policy_state_chain_snapshot chain;
		struct selinux_net_avc_transaction transaction;
		struct selinux_global_sid_handle
			*subject_handle[SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1];
	} *scratch __free(kfree) = NULL;
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
	struct selinux_label_resolution subject_resolution = {};
	struct selinux_net_provenance *provenance = NULL;
	struct selinux_peer_sources sources = {};
	const struct selinux_label_view *view;
	struct selinux_state *origin_state;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	enum selinux_postroute_origin origin;
	struct sock *sk = skb_to_full_sk(skb);
	bool parsed = false;
	bool sources_captured = false;
	bool xfrm_pending = false;
	unsigned int retry;
	char *addrp = NULL;
	int err;

	(void)priv;
	if (!hook_state->out)
		return NF_DROP_ERR(-ECONNREFUSED);
	scratch = kzalloc_obj(*scratch, GFP_ATOMIC);
	if (!scratch)
		return NF_DROP_ERR(-ECONNREFUSED);
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_NET_AVC_MAX_CHECKS, GFP_ATOMIC | __GFP_NOWARN);
	if (!workspace)
		return NF_DROP_ERR(-ECONNREFUSED);
	scratch->transaction.workspace = workspace;

	if (sk) {
		struct sk_security_struct *sksec = selinux_sock(sk);

		provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
		if (!provenance || !provenance->state || !provenance->view ||
		    !provenance->subject || !provenance->subject->label ||
		    provenance->state != sksec->state ||
		    provenance->subject->sid != READ_ONCE(sksec->sid)) {
			err = -EACCES;
			goto out;
		}
		origin_state = provenance->state;
		view = provenance->view;
		err = selinux_label_view_resolve_chain(
			provenance->view, provenance->subject->label,
			provenance->subject->sid, &subject_resolution);
		if (err)
			goto out;
		origin = sk_listener(sk) ? SELINUX_POSTROUTE_LISTENER :
					   SELINUX_POSTROUTE_SOCKET;
		if (origin == SELINUX_POSTROUTE_LISTENER) {
			err = selinux_peer_sources_capture_postroute(
				skb, hook_state->pf, origin_state, provenance->view,
				&sources);
			if (err)
				goto out;
			sources_captured = true;
		}
	} else {
		netsec = selinux_netns(hook_state->net);
		if (!netsec || !netsec->state || !netsec->state->label_domain ||
		    !netsec->view || netsec->view->origin_domain !=
				     netsec->state->label_domain) {
			err = -EACCES;
			goto out;
		}
		origin_state = netsec->state;
		view = netsec->view;
		err = selinux_peer_sources_capture(skb, hook_state->pf,
					   origin_state, netsec->view, &sources);
		if (err)
			goto out;
		sources_captured = true;
		if (skb->skb_iif) {
			origin = SELINUX_POSTROUTE_FORWARDED;
		} else {
			origin = SELINUX_POSTROUTE_KERNEL;
			err = selinux_ip_postroute_initial_resolution(
				netsec->view, SECINITSID_KERNEL,
				&subject_resolution);
			if (err)
				goto out;
		}
	}

#ifdef CONFIG_XFRM
	xfrm_pending = skb_dst(skb) && skb_dst(skb)->xfrm &&
			 !(sk && sk_listener(sk));
#endif
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		bool needs_parse = false;
		u16 i;

		for (i = 0; i < ARRAY_SIZE(scratch->subject_handle); i++) {
			global_sid_handle_put(scratch->subject_handle[i]);
			scratch->subject_handle[i] = NULL;
		}
		selinux_net_avc_transaction_reset(&scratch->transaction);
		err = selinux_policy_state_chain_snapshot_read(
			origin_state, &scratch->chain);
		if (err == -EAGAIN || err == -ESTALE)
			continue;
		if (err)
			break;
		for (i = 0; i < scratch->chain.count; i++)
			needs_parse |= selinux_ip_postroute_policy_needs_parse(
				&scratch->chain.policy[i], origin, xfrm_pending);
		if (needs_parse && !parsed) {
			ad_net_init_from_iif(&ad, &net, hook_state->out->ifindex,
					     hook_state->pf);
			err = selinux_parse_skb(skb, &ad, &addrp, 0, NULL);
			if (err)
				break;
			parsed = true;
		}
		for (i = 0, err = 0; i < scratch->chain.count; i++) {
			u16 initial_count = scratch->transaction.count;

			err = selinux_ip_postroute_policy_ns(
				skb, hook_state, scratch->chain.state[i],
				&scratch->chain.policy[i],
				origin, &subject_resolution,
				sources_captured ? &sources : NULL, xfrm_pending,
				addrp, view, &scratch->transaction,
				&scratch->subject_handle[i]);
			if (err)
				break;
			err = selinux_net_avc_transaction_add_guard(
				&scratch->transaction, initial_count,
				scratch->chain.state[i],
				&scratch->chain.policy[i]);
			if (err)
				break;
		}
		if (!err)
			err = selinux_net_avc_transaction_decide(
				&scratch->transaction, parsed ? &ad : NULL);
		if (err == -ESTALE)
			continue;
		goto out;
	}
	err = -ESTALE;

out:
	for (retry = 0; scratch &&
		     retry < ARRAY_SIZE(scratch->subject_handle); retry++)
		global_sid_handle_put(scratch->subject_handle[retry]);
	selinux_net_avc_transaction_reset(&scratch->transaction);
	if (sources_captured)
		selinux_peer_sources_put(&sources);
	selinux_net_provenance_put(provenance);
	return err ? NF_DROP_ERR(-ECONNREFUSED) : NF_ACCEPT;
}
#endif
#endif	/* CONFIG_NETFILTER */

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_netlink_batch {
	struct selinux_avc_level *levels;
	struct selinux_policy_snapshot *snapshots;
	struct selinux_avc_provenance *provenance;
	struct selinux_net_provenance *carrier;
	u16 capacity;
	u16 count;
	u16 unknown_type;
	u16 unknown_sclass;
	bool unknown;
	u8 data[] __aligned(__alignof__(struct selinux_avc_level));
};

static bool selinux_netlink_batch_add_size(size_t *bytes, size_t count,
					   size_t element_size,
					   size_t alignment)
{
	size_t part;

	*bytes = ALIGN(*bytes, alignment);
	return check_mul_overflow(count, element_size, &part) ||
	       check_add_overflow(*bytes, part, bytes);
}

static struct selinux_netlink_batch *
selinux_netlink_batch_alloc(u16 capacity)
{
	struct selinux_netlink_batch *batch;
	size_t bytes = sizeof(*batch);
	u8 *cursor;

	if (!capacity)
		return NULL;
	if (selinux_netlink_batch_add_size(
		    &bytes, capacity, sizeof(struct selinux_avc_level),
		    __alignof__(struct selinux_avc_level)) ||
	    selinux_netlink_batch_add_size(
		    &bytes, capacity, sizeof(struct selinux_policy_snapshot),
		    __alignof__(struct selinux_policy_snapshot)) ||
	    selinux_netlink_batch_add_size(
		    &bytes, capacity, sizeof(struct selinux_avc_provenance),
		    __alignof__(struct selinux_avc_provenance)))
		return NULL;
	batch = kvzalloc(bytes, GFP_KERNEL);
	if (!batch)
		return NULL;
	batch->capacity = capacity;
	cursor = batch->data;
#define SELINUX_NETLINK_BATCH_SET(_member, _type)                  \
	do {                                                         \
		cursor = PTR_ALIGN(cursor, __alignof__(_type));         \
		batch->_member = (_type *)cursor;                       \
		cursor += array_size((size_t)capacity, sizeof(_type));   \
	} while (0)
	SELINUX_NETLINK_BATCH_SET(levels, struct selinux_avc_level);
	SELINUX_NETLINK_BATCH_SET(snapshots, struct selinux_policy_snapshot);
	SELINUX_NETLINK_BATCH_SET(provenance, struct selinux_avc_provenance);
#undef SELINUX_NETLINK_BATCH_SET
	return batch;
}

static int selinux_netlink_batch_add(
	struct selinux_netlink_batch *batch,
	const struct selinux_avc_level *level,
	const struct selinux_policy_snapshot *snapshot,
	const struct selinux_net_provenance *provenance,
	const struct selinux_label_resolution *resolution)
{
	struct selinux_label_ref *label;
	u16 next, index;
	int rc;

	if (!batch || !level || !snapshot || !level->state)
		return -EINVAL;
	if (check_add_overflow(batch->count, (u16)1, &next) ||
	    next > batch->capacity)
		return -EOVERFLOW;
	index = batch->count;
	if (level->decision_kind == SELINUX_AVC_DECISION_GUARD) {
		batch->levels[index] = *level;
		batch->snapshots[index] = *snapshot;
		batch->count = next;
		return 0;
	}
	if (!provenance || !provenance->subject ||
	    !provenance->subject->sid_handle || !provenance->subject->label ||
	    !provenance->view || !resolution || !level->state->label_domain)
		return -EOPNOTSUPP;
	if (global_sid_handle_sid(provenance->subject->sid_handle) !=
	    provenance->subject->sid)
		return -ESTALE;
	label = global_sid_handle_label_get(provenance->subject->sid_handle);
	if (!label)
		return -ESTALE;
	if (label != provenance->subject->label) {
		rc = -ESTALE;
		goto out_label;
	}
	if (level->state->label_domain->depth > resolution->max_depth ||
	    resolution->domain_id[level->state->label_domain->depth] !=
		    level->state->label_domain->id ||
	    resolution->sid[level->state->label_domain->depth] != level->tsid) {
		rc = -ESTALE;
		goto out_label;
	}
	batch->provenance[index] = (struct selinux_avc_provenance) {
		.label = provenance->subject->label,
		.view = provenance->view,
		.source = provenance->subject->source,
	};
	batch->levels[index] = *level;
	batch->levels[index].provenance = &batch->provenance[index];
	batch->snapshots[index] = *snapshot;
	if (!batch->carrier)
		batch->carrier = selinux_net_provenance_get(
			(struct selinux_net_provenance *)provenance);
	else if (batch->carrier != provenance) {
		rc = -ESTALE;
		goto out_label;
	}
	batch->count = next;
	rc = 0;
out_label:
	selinux_label_ref_put(label);
	return rc;
}

static void selinux_netlink_batch_reset(struct selinux_netlink_batch *batch)
{
	if (!batch)
		return;
	selinux_net_provenance_put(batch->carrier);
	batch->carrier = NULL;
	batch->count = 0;
	batch->unknown = false;
}
#endif

static int selinux_netlink_msg_has_perm(
	struct sock *sk, u16 nlmsg_type,
	const struct selinux_policy_chain_snapshot *chain
#ifdef CONFIG_SECURITY_SELINUX_NS
	, struct selinux_netlink_batch *batch,
	const struct selinux_net_provenance *provenance,
	const struct selinux_label_resolution *resolution
#endif
	)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
#ifndef CONFIG_SECURITY_SELINUX_NS
	struct common_audit_data ad;
#endif
	u8 driver = nlmsg_type >> 8;
	u8 xperm = nlmsg_type & 0xff;
	u16 i;
	int rc = 0;

#ifndef CONFIG_SECURITY_SELINUX_NS
	ad.type = LSM_AUDIT_DATA_NLMSGTYPE;
	ad.u.nlmsg_type = nlmsg_type;
#endif

	for (i = 0; i < chain->count; i++) {
		const struct cred_security_struct *crsec =
			selinux_cred(chain->cred[i]);
		const struct selinux_policy_snapshot *snapshot =
			&chain->policy[i];
		struct selinux_state *state = crsec->state;
		u16 sclass = socket_class_for_snapshot(
			snapshot, sk->sk_family, sk->sk_type, sk->sk_protocol);
		u32 policy_sid = sksec->sid;
		u32 perm;

#ifdef CONFIG_SECURITY_SELINUX_NS
		if (state->depth > resolution->max_depth ||
		    resolution->domain_id[state->depth] != state->label_domain->id ||
		    !resolution->sid[state->depth]) {
			rc = -EOPNOTSUPP;
			break;
		}
		policy_sid = resolution->sid[state->depth];
#endif
		rc = selinux_nlmsg_lookup(snapshot, sclass, nlmsg_type, &perm);
		if (!rc) {
			if (!sock_skip_has_perm(snapshot, policy_sid)) {
#ifdef CONFIG_SECURITY_SELINUX_NS
				rc = selinux_netlink_batch_add(
					batch,
					&(struct selinux_avc_level) {
						.state = state,
						.ssid = crsec->sid,
						.tsid = policy_sid,
						.tclass = sclass,
						.requested = perm,
						.decision_kind =
							selinux_policycap_netlink_xperm(
								snapshot) ?
							SELINUX_AVC_DECISION_XPERM :
							SELINUX_AVC_DECISION_AVC,
						.driver = driver,
						.base_perm = AVC_EXT_NLMSG,
						.xperm = xperm,
					}, snapshot, provenance, resolution);
#else
				if (selinux_policycap_netlink_xperm(snapshot))
					rc = avc_has_extended_perms_snapshot(
						state, snapshot, crsec->sid, policy_sid,
						sclass, perm, driver, AVC_EXT_NLMSG,
						xperm, &ad);
				else
					rc = avc_has_perm_snapshot(
						state, snapshot, crsec->sid, policy_sid,
						sclass, perm, &ad);
#endif
			} else {
#ifdef CONFIG_SECURITY_SELINUX_NS
				rc = selinux_netlink_batch_add(
					batch,
					&(struct selinux_avc_level) {
						.state = state,
						.decision_kind =
							SELINUX_AVC_DECISION_GUARD,
					}, snapshot, NULL, NULL);
#endif
			}
		} else if (rc == -EINVAL) {
			/* A missing message/permission mapping is a policy
			 * decision, so evaluate it for every state in the
			 * credential chain under that state's snapshot.
			 */
#ifdef CONFIG_SECURITY_SELINUX_NS
			if (!batch->unknown) {
				batch->unknown = true;
				batch->unknown_type = nlmsg_type;
				batch->unknown_sclass = sclass;
			}
			rc = selinux_netlink_batch_add(
				batch,
				&(struct selinux_avc_level) {
					.state = state,
					.decision_kind =
						SELINUX_AVC_DECISION_GUARD,
					.guard_result =
						enforcing_enabled(state) &&
						!security_get_allow_unknown(state) ?
						-EINVAL : 0,
				}, snapshot, NULL, NULL);
#else
			pr_warn_ratelimited(
				"SELinux: unrecognized netlink message: protocol=%u nlmsg_type=%u sclass=%s pid=%d comm=%s\n",
				(unsigned int)sk->sk_protocol,
				(unsigned int)nlmsg_type,
				secclass_map[sclass - 1].name,
				task_pid_nr(current), current->comm);
			if (enforcing_enabled(state) &&
			    !security_get_allow_unknown(state))
				break;
			rc = 0;
#endif
		} else if (rc == -ENOENT) {
			/* No userspace messaging for this policy's class. */
#ifdef CONFIG_SECURITY_SELINUX_NS
			rc = selinux_netlink_batch_add(
				batch,
				&(struct selinux_avc_level) {
					.state = state,
					.decision_kind =
						SELINUX_AVC_DECISION_GUARD,
				}, snapshot, NULL, NULL);
#else
			rc = 0;
#endif
		}
		if (rc)
			break;
	}

	return rc;
}

static int selinux_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	struct {
		struct selinux_policy_chain_snapshot chain;
	} *scratch __free(kfree) = NULL;
	struct selinux_policy_chain_snapshot *chain;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_avc_transaction_workspace *workspace __free(kvfree) = NULL;
	struct selinux_netlink_batch *batch __free(kvfree) = NULL;
	u16 message_count = 0, capacity;
#endif
	unsigned int retry;

	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	chain = &scratch->chain;

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		unsigned int data_len = skb->len;
		unsigned char *data = skb->data;

		while (data_len >= nlmsg_total_size(0)) {
			struct nlmsghdr *nlh = (struct nlmsghdr *)data;
			unsigned int msg_len;

			if (nlh->nlmsg_len < NLMSG_HDRLEN ||
			    nlh->nlmsg_len > data_len)
				break;
			if (check_add_overflow(message_count, (u16)1,
					       &message_count))
				return -EOVERFLOW;
			msg_len = NLMSG_ALIGN(nlh->nlmsg_len);
			if (msg_len >= data_len)
				break;
			data_len -= msg_len;
			data += msg_len;
		}
	}
	if (!message_count)
		return 0;
	if (check_mul_overflow(
		message_count,
		(u16)(SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1), &capacity))
		return -EOVERFLOW;
	batch = selinux_netlink_batch_alloc(capacity);
	workspace = selinux_avc_transaction_workspace_alloc(capacity,
							    GFP_KERNEL);
	if (!batch || !workspace)
		return -ENOMEM;
#endif

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		unsigned int data_len = skb->len;
		unsigned char *data = skb->data;
#ifdef CONFIG_SECURITY_SELINUX_NS
		struct sk_security_struct *sksec = selinux_sock(sk);
		struct selinux_net_provenance *provenance = NULL;
		struct selinux_label_resolution resolution;
#endif
		int rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
		selinux_netlink_batch_reset(batch);
#endif
		rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
		provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
		if (!provenance || !provenance->view || !provenance->subject ||
		    !provenance->subject->label) {
			rc = -EACCES;
			goto attempt_done;
		}
		if (READ_ONCE(sksec->sid) != provenance->subject->sid ||
		    sksec->state != provenance->state) {
			rc = -ESTALE;
			goto attempt_done;
		}
		rc = selinux_label_view_resolve_chain(
			provenance->view, provenance->subject->label,
			provenance->subject->sid, &resolution);
		if (rc)
			goto attempt_done;
#endif

		while (data_len >= nlmsg_total_size(0)) {
			struct nlmsghdr *nlh = (struct nlmsghdr *)data;
			unsigned int msg_len;

			/* NOTE: the nlmsg_len field isn't reliably set by some
			 * netlink users.  Follow netlink_rcv_skb() and stop at a
			 * message with a clearly bogus length.
			 */
			if (nlh->nlmsg_len < NLMSG_HDRLEN ||
			    nlh->nlmsg_len > data_len)
				break;

			rc = selinux_netlink_msg_has_perm(
				sk, nlh->nlmsg_type, chain
#ifdef CONFIG_SECURITY_SELINUX_NS
				, batch, provenance, &resolution
#endif
				);
			if (rc)
				break;

			/* Move to the next message after netlink padding. */
			msg_len = NLMSG_ALIGN(nlh->nlmsg_len);
			if (msg_len >= data_len)
				break;
			data_len -= msg_len;
			data += msg_len;
		}

#ifdef CONFIG_SECURITY_SELINUX_NS
attempt_done:
		selinux_net_provenance_put(provenance);
#endif
		if (rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain))
			continue;
#ifdef CONFIG_SECURITY_SELINUX_NS
		if (!rc) {
			struct common_audit_data ad = {
				.type = LSM_AUDIT_DATA_NLMSGTYPE,
			};

			rc = selinux_avc_transaction_has_perm_workspace(
				batch->levels, batch->snapshots, batch->count,
				&ad, workspace);
		}
		if (rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain))
			continue;
		if (batch->unknown)
			pr_warn_ratelimited(
				"SELinux: unrecognized netlink message: protocol=%u nlmsg_type=%u sclass=%s pid=%d comm=%s\n",
				(unsigned int)sk->sk_protocol,
				(unsigned int)batch->unknown_type,
				secclass_map[batch->unknown_sclass - 1].name,
				task_pid_nr(current), current->comm);
		selinux_netlink_batch_reset(batch);
#endif
		return rc;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_netlink_batch_reset(batch);
#endif
	return -ESTALE;
}

static int ipc_init_security(struct ipc_namespace *ns,
			     struct ipc_security_struct *isec, u16 sclass,
			     u32 requested, struct common_audit_data *ad)
{
	isec->sclass = sclass;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_ipcns_anchor *anchor;
	int rc;

	anchor = selinux_ipcns_anchor_get(ns, current_cred());
	if (IS_ERR(anchor))
		return PTR_ERR(anchor);
	rc = selinux_creator_projection_build(
		current_cred(), SELINUX_PATHLESS_KIND_IPC, sclass, false,
		requested, ad, selinux_ipcns_anchor_view(anchor), &isec->sid,
		&isec->projection);
	if (!rc && !selinux_ipcns_anchor_valid(ns, current_cred(), anchor)) {
		selinux_pathless_projection_put(isec->projection);
		isec->projection = NULL;
		rc = -ESTALE;
	}
	selinux_ipcns_anchor_put(anchor);
	return rc;
#else
	(void)ns;
	isec->sid = current_sid();
	return requested ?
		cred_tsid_has_perm(current_cred(), isec->sid, sclass,
				   requested, ad) : 0;
#endif
}

static int ipc_has_perm(struct kern_ipc_perm *ipc_perms,
			u32 perms)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;

	isec = selinux_ipc(ipc_perms);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = ipc_perms->key;

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!isec->projection ||
	    isec->projection->kind != SELINUX_PATHLESS_KIND_IPC)
		return -EACCES;
	return cred_pathless_has_perm(current_cred(), isec->projection, perms,
				      &ad);
#else
	return cred_tsid_has_perm(current_cred(), isec->sid, isec->sclass,
				  perms, &ad);
#endif
}

static int selinux_msg_msg_alloc_security(struct msg_msg *msg)
{
	struct msg_security_struct *msec;

	msec = selinux_msg_msg(msg);
	msec->sid = SECINITSID_UNLABELED;
#ifdef CONFIG_SECURITY_SELINUX_NS
	msec->projection = NULL;
#endif

	return 0;
}

static void selinux_msg_msg_free_security(struct msg_msg *msg)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct msg_security_struct *msec = selinux_msg_msg(msg);

	selinux_pathless_projection_put(msec->projection);
	msec->projection = NULL;
#endif
}

static void selinux_ipc_free_security(struct kern_ipc_perm *ipcp)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct ipc_security_struct *isec = selinux_ipc(ipcp);

	selinux_pathless_projection_put(isec->projection);
	isec->projection = NULL;
#endif
}

/* message queue security operations */
static int selinux_msg_queue_alloc_security(struct ipc_namespace *ns,
					    struct kern_ipc_perm *msq)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;

	isec = selinux_ipc(msq);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = msq->key;

	return ipc_init_security(ns, isec, SECCLASS_MSGQ, MSGQ__CREATE, &ad);
}

static int selinux_msg_queue_associate(struct kern_ipc_perm *msq, int msqflg)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;

	isec = selinux_ipc(msq);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = msq->key;

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!isec->projection ||
	    isec->projection->kind != SELINUX_PATHLESS_KIND_IPC)
		return -EACCES;
	return cred_pathless_has_perm(current_cred(), isec->projection,
				      MSGQ__ASSOCIATE, &ad);
#else
	return cred_tsid_has_perm(current_cred(), isec->sid, SECCLASS_MSGQ,
				  MSGQ__ASSOCIATE, &ad);
#endif
}

static int selinux_msg_queue_msgctl(struct kern_ipc_perm *msq, int cmd)
{
	u32 perms;

	switch (cmd) {
	case IPC_INFO:
	case MSG_INFO:
		/* No specific object, just general system-wide information. */
		return cred_tsid_has_perm(current_cred(), SECINITSID_KERNEL,
					  SECCLASS_SYSTEM, SYSTEM__IPC_INFO, NULL);
	case IPC_STAT:
	case MSG_STAT:
	case MSG_STAT_ANY:
		perms = MSGQ__GETATTR | MSGQ__ASSOCIATE;
		break;
	case IPC_SET:
		perms = MSGQ__SETATTR;
		break;
	case IPC_RMID:
		perms = MSGQ__DESTROY;
		break;
	default:
		return 0;
	}

	return ipc_has_perm(msq, perms);
}

#ifdef CONFIG_SECURITY_SELINUX_NS
/* Build a candidate using the caller's already-captured operation snapshot. */
static int selinux_msg_projection_build_snapshot(
	const struct selinux_pathless_projection *queue_projection,
	const struct selinux_pathless_chain_resolution *queue_line,
	struct selinux_pathless_build_scratch *scratch,
	struct selinux_pathless_projection **projectionp, u32 *sidp)
{
	u16 i;
	int rc;

	*projectionp = NULL;
	if (!queue_projection)
		return -EOPNOTSUPP;
	rc = selinux_pathless_chain_validate(scratch);
	if (rc)
		return rc;
	for (i = 0; i < scratch->chain.count; i++) {
		const struct cred_security_struct *crsec =
			selinux_cred(scratch->chain.cred[i]);
		struct selinux_pathless_expect *expect =
			&scratch->expects[crsec->state->label_domain->depth];
		struct selinux_pathless_resolution queue;
		u16 depth = crsec->state->label_domain->depth;

		queue = queue_line->level[depth];
		if (queue.sclass != SECCLASS_MSGQ)
			return -EOPNOTSUPP;
		expect->sclass = SECCLASS_MSG;
		expect->model = SELINUX_PATHLESS_MODEL_TRANSITION;
		scratch->producer_handles[depth] = security_transition_sid_handle(
			crsec->state, crsec->sid, queue.sid, SECCLASS_MSG, NULL,
			&expect->sid);
		if (IS_ERR(scratch->producer_handles[depth])) {
			rc = PTR_ERR(scratch->producer_handles[depth]);
			scratch->producer_handles[depth] = NULL;
			return rc;
		}
	}
	*sidp = scratch->expects[selinux_cred(scratch->chain.cred[0])->
					 state->label_domain->depth].sid;
	return selinux_pathless_build_sealed(
		scratch, SELINUX_PATHLESS_KIND_MSG,
		SELINUX_LABEL_SOURCE_TRANSITION, *sidp, NULL, GFP_ATOMIC,
		projectionp);
}

#define SELINUX_MSG_AVC_CHECKS_PER_POLICY 3
#define SELINUX_MSG_AVC_MAX_CHECKS \
	(SELINUX_MSG_AVC_CHECKS_PER_POLICY * \
	 (SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1))

static_assert(SELINUX_MSG_AVC_MAX_CHECKS <=
	      SELINUX_AVC_TRANSACTION_MAX_CHECKS);

struct selinux_msg_avc_transaction {
	struct selinux_policy_chain_snapshot chain;
	struct selinux_avc_level levels[SELINUX_MSG_AVC_MAX_CHECKS];
	struct selinux_policy_snapshot snapshots[SELINUX_MSG_AVC_MAX_CHECKS];
	struct selinux_avc_provenance queue_provenance;
	struct selinux_avc_provenance message_provenance;
	struct selinux_avc_provenance provenance[SELINUX_MSG_AVC_MAX_CHECKS];
	struct selinux_pathless_chain_resolution queue_line;
	struct selinux_pathless_chain_resolution message_line;
	u16 count;
};

static int selinux_msg_avc_transaction_add(
	struct selinux_msg_avc_transaction *transaction,
	const struct selinux_avc_level *level,
	const struct selinux_policy_snapshot *snapshot)
{
	u16 next;

	if (check_add_overflow(transaction->count, (u16)1, &next) ||
	    next > ARRAY_SIZE(transaction->levels))
		return -E2BIG;
	transaction->levels[transaction->count] = *level;
	if (level->provenance) {
		transaction->provenance[transaction->count] = *level->provenance;
		transaction->levels[transaction->count].provenance =
			&transaction->provenance[transaction->count];
	}
	transaction->snapshots[transaction->count] = *snapshot;
	transaction->count = next;
	return 0;
}

/*
 * A send/receive is one authorization event even though SELinux models it as
 * several permissions.  Capture the policy chain once and decide every part
 * against that exact generation; otherwise a concurrent reload could allow
 * different parts under mutually incompatible policies.
 */
static int selinux_msg_queue_has_perm_transaction(
	const struct cred *cred,
	const struct selinux_pathless_projection *queue_projection,
	struct msg_security_struct *msec, bool send,
	struct common_audit_data *ad)
{
	struct selinux_pathless_build_scratch *build;
	struct selinux_avc_transaction_workspace *workspace;
	struct selinux_msg_avc_transaction *transaction;
	unsigned int retry;
	int rc = -ESTALE;

	if (!queue_projection ||
	    queue_projection->kind != SELINUX_PATHLESS_KIND_IPC ||
	    !msec)
		return -EACCES;

	transaction = kzalloc_obj(*transaction, GFP_ATOMIC | __GFP_NOWARN);
	if (!transaction)
		return -ENOMEM;
	build = kzalloc_obj(*build, GFP_ATOMIC | __GFP_NOWARN);
	if (!build) {
		rc = -ENOMEM;
		goto out;
	}
	workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_MSG_AVC_MAX_CHECKS, GFP_ATOMIC | __GFP_NOWARN);
	if (!workspace) {
		rc = -ENOMEM;
		goto out_build;
	}

	transaction->queue_provenance = (struct selinux_avc_provenance) {
		.label = queue_projection->label,
		.view = queue_projection->view,
		.source = queue_projection->source,
	};
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		const struct selinux_pathless_projection *message_projection;
		struct selinux_pathless_projection *candidate = NULL;
		u32 candidate_sid = 0;
		u16 i;

		transaction->count = 0;
		selinux_pathless_producer_handles_put(build);
		memset(build, 0, sizeof(*build));
		rc = selinux_policy_chain_snapshot_read(cred, &transaction->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		build->chain = transaction->chain;
		rc = selinux_pathless_projection_resolve_cred_chain(
			queue_projection, transaction->chain.cred,
			transaction->chain.policy, transaction->chain.count,
			&transaction->queue_line);
		if (rc)
			goto retry_or_out;
		message_projection = READ_ONCE(msec->projection);
		if (!message_projection && send &&
		    READ_ONCE(msec->sid) == SECINITSID_UNLABELED) {
			rc = selinux_msg_projection_build_snapshot(
				queue_projection, &transaction->queue_line, build,
				&candidate, &candidate_sid);
			if (rc)
				goto retry_or_out;
			message_projection = candidate;
		}
		if (!message_projection ||
		    message_projection->kind != SELINUX_PATHLESS_KIND_MSG) {
			rc = -EACCES;
			goto retry_or_out;
		}
		transaction->message_provenance =
			(struct selinux_avc_provenance) {
				.label = message_projection->label,
				.view = message_projection->view,
				.source = message_projection->source,
			};
		rc = selinux_pathless_projection_resolve_cred_chain(
			message_projection, transaction->chain.cred,
			transaction->chain.policy, transaction->chain.count,
			&transaction->message_line);
		if (rc)
			goto retry_or_out;

		for (i = 0; i < transaction->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(transaction->chain.cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&transaction->chain.policy[i];
			struct selinux_pathless_resolution queue;
			struct selinux_pathless_resolution message;
			struct selinux_avc_provenance queue_provenance =
				transaction->queue_provenance;
			struct selinux_avc_provenance message_provenance =
				transaction->message_provenance;

			queue = transaction->queue_line.level[
				crsec->state->label_domain->depth];
			message = transaction->message_line.level[
				crsec->state->label_domain->depth];
			if (queue.sclass != SECCLASS_MSGQ ||
			    message.sclass != SECCLASS_MSG) {
				rc = -EOPNOTSUPP;
				break;
			}
			queue_provenance.map_generation = queue.map_generation;
			message_provenance.map_generation = message.map_generation;

			rc = selinux_msg_avc_transaction_add(
				transaction,
				&(struct selinux_avc_level) {
					.state = crsec->state,
					.ssid = crsec->sid,
					.tsid = queue.sid,
					.requested = send ? MSGQ__WRITE : MSGQ__READ,
					.tclass = SECCLASS_MSGQ,
					.provenance =
						&queue_provenance,
				}, snapshot);
			if (rc)
				break;
			rc = selinux_msg_avc_transaction_add(
				transaction,
				&(struct selinux_avc_level) {
					.state = crsec->state,
					.ssid = crsec->sid,
					.tsid = message.sid,
					.requested = send ? MSG__SEND : MSG__RECEIVE,
					.tclass = SECCLASS_MSG,
					.provenance =
						&message_provenance,
				}, snapshot);
			if (rc)
				break;
			if (!send)
				continue;
			rc = selinux_msg_avc_transaction_add(
				transaction,
				&(struct selinux_avc_level) {
					.state = crsec->state,
					.ssid = message.sid,
					.tsid = queue.sid,
					.requested = MSGQ__ENQUEUE,
					.tclass = SECCLASS_MSGQ,
					.provenance =
						&queue_provenance,
				}, snapshot);
			if (rc)
				break;
		}
		if (rc)
			goto retry_or_out;

		rc = selinux_avc_transaction_has_perm_workspace(
			transaction->levels, transaction->snapshots,
			transaction->count, ad, workspace);
		if (!rc && !selinux_policy_chain_snapshot_valid(&transaction->chain))
			rc = -ESTALE;
		if (!rc && candidate) {
			WRITE_ONCE(msec->projection, candidate);
			/* Publish canonical provenance before its numeric projection. */
			smp_store_release(&msec->sid, candidate_sid);
			candidate = NULL;
		}
retry_or_out:
		selinux_pathless_projection_put(candidate);
		selinux_pathless_chain_resolution_put(&transaction->queue_line);
		selinux_pathless_chain_resolution_put(&transaction->message_line);
		if (rc != -EAGAIN && rc != -ESTALE)
			break;
	}

	selinux_pathless_producer_handles_put(build);
	selinux_avc_transaction_workspace_free(workspace);
out_build:
	kfree(build);
out:
	kfree(transaction);
	return rc;
}
#endif

static int selinux_msg_queue_msgsnd(struct kern_ipc_perm *msq, struct msg_msg *msg, int msqflg)
{
	const struct cred *cred = current_cred();
	struct ipc_security_struct *isec;
	struct msg_security_struct *msec;
	struct common_audit_data ad;
	int rc;
#ifndef CONFIG_SECURITY_SELINUX_NS
	u32 sid = current_sid();
#endif

	isec = selinux_ipc(msq);
	msec = selinux_msg_msg(msg);

	/*
	 * First time through, need to assign label to the message
	 */
	if (msec->sid == SECINITSID_UNLABELED) {
		/*
		 * Compute new sid based on current process and
		 * message queue this message will be stored in
		 */
#ifdef CONFIG_SECURITY_SELINUX_NS
		/* The transition candidate is derived and committed by the send. */
		rc = 0;
#else
		rc = security_transition_sid(current_selinux_state, sid,
					     isec->sid, SECCLASS_MSG, NULL,
					     &msec->sid);
#endif
		if (rc)
			return rc;
	}

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = msq->key;

	/* Can this process write to the queue? */

#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = selinux_msg_queue_has_perm_transaction(
		cred, isec->projection, msec, true, &ad);
#else
	rc = cred_tsid_has_perm(cred, isec->sid, SECCLASS_MSGQ, MSGQ__WRITE,
				&ad);
	if (!rc)
		rc = cred_tsid_has_perm(cred, msec->sid, SECCLASS_MSG,
					MSG__SEND, &ad);
	if (!rc)
		rc = cred_ssid_has_perm(cred, msec->sid, isec->sid,
					SECCLASS_MSGQ, MSGQ__ENQUEUE, &ad);
#endif

	return rc;
}

static int selinux_msg_queue_msgrcv(struct kern_ipc_perm *msq, struct msg_msg *msg,
				    struct task_struct *target,
				    long type, int mode)
{
	struct ipc_security_struct *isec;
	struct msg_security_struct *msec;
	struct common_audit_data ad;
	int rc;
#ifndef CONFIG_SECURITY_SELINUX_NS
	const struct cred *cred = current_cred();
	u32 sid = task_sid_obj(target);
#endif

	isec = selinux_ipc(msq);
	msec = selinux_msg_msg(msg);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = msq->key;

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		const struct cred *target_cred = get_task_cred(target);

		rc = selinux_msg_queue_has_perm_transaction(
			target_cred, isec->projection, msec, false, &ad);
		put_cred(target_cred);
	}
#else
	rc = cred_ssid_has_perm(cred, sid, isec->sid, SECCLASS_MSGQ,
				MSGQ__READ, &ad);
	if (!rc)
		rc = cred_ssid_has_perm(cred, sid, msec->sid,
					SECCLASS_MSG, MSG__RECEIVE, &ad);
#endif
	return rc;
}

/* Shared Memory security operations */
static int selinux_shm_alloc_security(struct ipc_namespace *ns,
				      struct kern_ipc_perm *shp)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;

	isec = selinux_ipc(shp);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = shp->key;

	return ipc_init_security(ns, isec, SECCLASS_SHM, SHM__CREATE, &ad);
}

static int selinux_shm_associate(struct kern_ipc_perm *shp, int shmflg)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;

	isec = selinux_ipc(shp);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = shp->key;

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!isec->projection ||
	    isec->projection->kind != SELINUX_PATHLESS_KIND_IPC)
		return -EACCES;
	return cred_pathless_has_perm(current_cred(), isec->projection,
				      SHM__ASSOCIATE, &ad);
#else
	return cred_tsid_has_perm(current_cred(), isec->sid, SECCLASS_SHM,
				  SHM__ASSOCIATE, &ad);
#endif
}

/* Note, at this point, shp is locked down */
static int selinux_shm_shmctl(struct kern_ipc_perm *shp, int cmd)
{
	u32 perms;

	switch (cmd) {
	case IPC_INFO:
	case SHM_INFO:
		/* No specific object, just general system-wide information. */
		return cred_tsid_has_perm(current_cred(), SECINITSID_KERNEL,
					  SECCLASS_SYSTEM, SYSTEM__IPC_INFO,
					  NULL);
	case IPC_STAT:
	case SHM_STAT:
	case SHM_STAT_ANY:
		perms = SHM__GETATTR | SHM__ASSOCIATE;
		break;
	case IPC_SET:
		perms = SHM__SETATTR;
		break;
	case SHM_LOCK:
	case SHM_UNLOCK:
		perms = SHM__LOCK;
		break;
	case IPC_RMID:
		perms = SHM__DESTROY;
		break;
	default:
		return 0;
	}

	return ipc_has_perm(shp, perms);
}

static int selinux_shm_shmat(struct kern_ipc_perm *shp,
			     char __user *shmaddr, int shmflg)
{
	u32 perms;

	if (shmflg & SHM_RDONLY)
		perms = SHM__READ;
	else
		perms = SHM__READ | SHM__WRITE;

	return ipc_has_perm(shp, perms);
}

/* Semaphore security operations */
static int selinux_sem_alloc_security(struct ipc_namespace *ns,
				      struct kern_ipc_perm *sma)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;

	isec = selinux_ipc(sma);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = sma->key;

	return ipc_init_security(ns, isec, SECCLASS_SEM, SEM__CREATE, &ad);
}

static int selinux_sem_associate(struct kern_ipc_perm *sma, int semflg)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;

	isec = selinux_ipc(sma);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = sma->key;

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!isec->projection ||
	    isec->projection->kind != SELINUX_PATHLESS_KIND_IPC)
		return -EACCES;
	return cred_pathless_has_perm(current_cred(), isec->projection,
				      SEM__ASSOCIATE, &ad);
#else
	return cred_tsid_has_perm(current_cred(), isec->sid, SECCLASS_SEM,
				  SEM__ASSOCIATE, &ad);
#endif
}

/* Note, at this point, sma is locked down */
static int selinux_sem_semctl(struct kern_ipc_perm *sma, int cmd)
{
	int err;
	u32 perms;

	switch (cmd) {
	case IPC_INFO:
	case SEM_INFO:
		/* No specific object, just general system-wide information. */
		return cred_tsid_has_perm(current_cred(), SECINITSID_KERNEL,
					  SECCLASS_SYSTEM, SYSTEM__IPC_INFO,
					  NULL);
	case GETPID:
	case GETNCNT:
	case GETZCNT:
		perms = SEM__GETATTR;
		break;
	case GETVAL:
	case GETALL:
		perms = SEM__READ;
		break;
	case SETVAL:
	case SETALL:
		perms = SEM__WRITE;
		break;
	case IPC_RMID:
		perms = SEM__DESTROY;
		break;
	case IPC_SET:
		perms = SEM__SETATTR;
		break;
	case IPC_STAT:
	case SEM_STAT:
	case SEM_STAT_ANY:
		perms = SEM__GETATTR | SEM__ASSOCIATE;
		break;
	default:
		return 0;
	}

	err = ipc_has_perm(sma, perms);
	return err;
}

static int selinux_sem_semop(struct kern_ipc_perm *sma,
			     struct sembuf *sops, unsigned nsops, int alter)
{
	u32 perms;

	if (alter)
		perms = SEM__READ | SEM__WRITE;
	else
		perms = SEM__READ;

	return ipc_has_perm(sma, perms);
}

static int selinux_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	u32 av = 0;

	av = 0;
	if (flag & S_IRUGO)
		av |= IPC__UNIX_READ;
	if (flag & S_IWUGO)
		av |= IPC__UNIX_WRITE;

	if (av == 0)
		return 0;

	return ipc_has_perm(ipcp, av);
}

static void selinux_ipc_getlsmprop(struct kern_ipc_perm *ipcp,
				   struct lsm_prop *prop)
{
	struct ipc_security_struct *isec = selinux_ipc(ipcp);
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct cred_security_struct *crsec = selinux_cred(current_cred());
	struct selinux_pathless_resolution resolved;

	if (!isec->projection ||
	    isec->projection->kind != SELINUX_PATHLESS_KIND_IPC ||
	    selinux_pathless_projection_resolve_sealed(
		    isec->projection, crsec->state->label_domain, &resolved) ||
	    resolved.sclass != isec->sclass) {
		prop->selinux.secid = 0;
		return;
	}
	prop->selinux.secid = resolved.sid;
#else
	prop->selinux.secid = isec->sid;
#endif
}

static void selinux_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	if (inode)
		inode_doinit_with_dentry(inode, dentry);
}

static int selinux_lsm_getattr(unsigned int attr, struct task_struct *p,
			       char **value)
{
	const struct cred_security_struct *crsec;
	const char *ctx;
	int error;
	u32 sid;
	u32 len;

	rcu_read_lock();
	if (p != current) {
		error = cred_task_has_perm(current_cred(), p,
					   SECCLASS_PROCESS,
					   PROCESS__GETATTR, NULL);
		if (error)
			goto err_unlock;
	}
	crsec = task_cred_security(p);
	switch (attr) {
	case LSM_ATTR_CURRENT:
		sid = crsec->sid;
		break;
	case LSM_ATTR_PREV:
		sid = crsec->osid;
		break;
	case LSM_ATTR_EXEC:
		sid = crsec->exec_sid;
		break;
	case LSM_ATTR_FSCREATE:
		sid = crsec->create_sid;
		break;
	case LSM_ATTR_KEYCREATE:
		sid = crsec->keycreate_sid;
		break;
	case LSM_ATTR_SOCKCREATE:
		sid = crsec->sockcreate_sid;
		break;
#ifdef CONFIG_SECURITY_SELINUX_NS
	case LSM_ATTR_UNSHARE:
		*value = kmalloc(1, GFP_ATOMIC);
		if (!(*value)) {
			error = -ENOMEM;
			goto err_unlock;
		}
		**value = !!(crsec->state != init_selinux_state &&
			     !selinux_initialized(crsec->state));
		error = 1;
		goto err_unlock;
#endif
	default:
		error = -EOPNOTSUPP;
		goto err_unlock;
	}

	if (sid == SECSID_NULL) {
		*value = NULL;
		error = 0;
		goto err_unlock;
	}

	error = security_sid_to_context(current_selinux_state, sid, &ctx, &len);
	if (error)
		goto err_unlock;
	*value = kmemdup(ctx, len, GFP_ATOMIC);
	if (!*value)
		error = -ENOMEM;
	else
		error = len;

err_unlock:
	rcu_read_unlock();
	return error;
}

static int selinux_lsm_setattr(u64 attr, void *value, size_t size)
{
	const struct cred *cred = current_cred();
	struct selinux_state *state = current_selinux_state;
	struct cred_security_struct *crsec;
	struct cred *new;
	u32 mysid = current_sid(), sid = 0, ptsid;
	int error;
	char *str = value;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *sid_handle = NULL;
#endif

	/*
	 * Basic control over ability to set these attributes at all.
	 */
	/*
	 * Only check against the current SELinux namespace
	 * because only the SID in the current namespace
	 * is changed by this operation.
	 */
	switch (attr) {
	case LSM_ATTR_EXEC:
		error = avc_has_perm(state, mysid, mysid, SECCLASS_PROCESS,
				     PROCESS__SETEXEC, NULL);
		break;
	case LSM_ATTR_FSCREATE:
		error = avc_has_perm(state, mysid, mysid, SECCLASS_PROCESS,
				     PROCESS__SETFSCREATE, NULL);
		break;
	case LSM_ATTR_KEYCREATE:
		error = avc_has_perm(state, mysid, mysid, SECCLASS_PROCESS,
				     PROCESS__SETKEYCREATE, NULL);
		break;
	case LSM_ATTR_SOCKCREATE:
		error = avc_has_perm(state, mysid, mysid, SECCLASS_PROCESS,
				     PROCESS__SETSOCKCREATE, NULL);
		break;
	case LSM_ATTR_CURRENT:
		error = avc_has_perm(state, mysid, mysid, SECCLASS_PROCESS,
				     PROCESS__SETCURRENT, NULL);
		break;
#ifdef CONFIG_SECURITY_SELINUX_NS
	case LSM_ATTR_UNSHARE:
		/*
		 * TODO: Figure out how we want to control unsharing
		 * of the SELinux namespace. For now, require CAP_SYS_ADMIN
		 * and check SELinux unshare_selinuxns in this and all ancestor
		 * namspaces.
		 */
		if (!ns_capable(current_user_ns(), CAP_SYS_ADMIN)) {
			error = -EPERM;
			break;
		}
		error = cred_self_has_perm(cred, SECCLASS_PROCESS2,
					   PROCESS2__UNSHARE_SELINUXNS, NULL);
		break;
#endif
	default:
		error = -EOPNOTSUPP;
		break;
	}
	if (error)
		return error;

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (attr == LSM_ATTR_UNSHARE) {
		/*
		 * A resident selinuxfs policy/status PTE cannot be revoked by its
		 * fault handler.  Exclusive mm ownership closes the race with a
		 * sibling mapping a page after the VMA check.
		 */
		if (!current_is_single_threaded())
			return -EUSERS;
		error = selinuxfs_mm_may_change(current->mm);
		if (error)
			return error;
	}
#endif

	/* Obtain a SID for the context, if one was specified. */
	if (size && str[0] && str[0] != '\n') {
		if (str[size-1] == '\n') {
			str[size-1] = 0;
			size--;
		}
#ifdef CONFIG_SECURITY_SELINUX_NS
		sid_handle = security_context_to_global_handle(
			state, value, size, &sid, GFP_KERNEL);
		error = IS_ERR(sid_handle) ? PTR_ERR(sid_handle) : 0;
		if (IS_ERR(sid_handle))
			sid_handle = NULL;
#else
		error = security_context_to_sid(state, value, size,
						&sid, GFP_KERNEL);
#endif
		if (error == -EINVAL && attr == LSM_ATTR_FSCREATE) {
			if (!has_cap_mac_admin(true)) {
				struct audit_buffer *ab;
				size_t audit_size;

				/* We strip a nul only if it is at the end,
				 * otherwise the context contains a nul and
				 * we should audit that */
				if (str[size - 1] == '\0')
					audit_size = size - 1;
				else
					audit_size = size;
				ab = audit_log_start(audit_context(),
						     GFP_ATOMIC,
						     AUDIT_SELINUX_ERR);
				if (!ab)
					return error;
				audit_log_format(ab, "op=fscreate invalid_context=");
				audit_log_n_untrustedstring(ab, value,
							    audit_size);
				(void)audit_log_end_status(ab);

				return error;
			}
#ifdef CONFIG_SECURITY_SELINUX_NS
			sid_handle = security_context_to_sid_force_handle(
				state, value, size, &sid);
			error = IS_ERR(sid_handle) ? PTR_ERR(sid_handle) : 0;
			if (IS_ERR(sid_handle))
				sid_handle = NULL;
#else
			error = security_context_to_sid_force(state, value,
							      size, &sid);
#endif
		}
		if (error)
			return error;
	}

	new = prepare_creds();
	if (!new) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		global_sid_handle_put(sid_handle);
#endif
		return -ENOMEM;
	}

	/* Permission checking based on the specified context is
	   performed during the actual operation (execve,
	   open/mkdir/...), when we know the full context of the
	   operation.  See selinux_bprm_creds_for_exec for the execve
	   checks and may_create for the file creation checks. The
	   operation will then fail if the context is not permitted. */
	crsec = selinux_cred(new);
	if (attr == LSM_ATTR_EXEC) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		error = selinux_cred_sid_take_handle(
			crsec, SELINUX_CRED_EXEC_SID, sid_handle);
		sid_handle = NULL;
#else
		crsec->exec_sid = sid;
#endif
	} else if (attr == LSM_ATTR_FSCREATE) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		error = selinux_cred_sid_take_handle(
			crsec, SELINUX_CRED_CREATE_SID, sid_handle);
		sid_handle = NULL;
#else
		crsec->create_sid = sid;
#endif
	} else if (attr == LSM_ATTR_KEYCREATE) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		error = selinux_cred_sid_take_handle(
			crsec, SELINUX_CRED_KEYCREATE_SID, sid_handle);
		sid_handle = NULL;
		if (error)
			goto abort_change;
		if (sid) {
			struct selinux_pathless_projection *projection = NULL;
			u32 projected_sid = 0;

			error = selinux_creator_projection_build(
				new, SELINUX_PATHLESS_KIND_KEY, SECCLASS_KEY,
				true, KEY__CREATE, NULL, NULL, &projected_sid,
				&projection);
			selinux_pathless_projection_put(projection);
			if (error)
				goto abort_change;
			if (projected_sid != sid) {
				error = -EOPNOTSUPP;
				goto abort_change;
			}
		}
#else
		if (sid) {
			error = cred_tsid_has_perm(cred, sid, SECCLASS_KEY,
						   KEY__CREATE, NULL);
			if (error)
				goto abort_change;
		}
		crsec->keycreate_sid = sid;
#endif
	} else if (attr == LSM_ATTR_SOCKCREATE) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		error = selinux_cred_sid_take_handle(
			crsec, SELINUX_CRED_SOCKCREATE_SID, sid_handle);
		sid_handle = NULL;
#else
		crsec->sockcreate_sid = sid;
#endif
	} else if (attr == LSM_ATTR_CURRENT) {
		error = -EINVAL;
		if (sid == 0)
			goto abort_change;

		if (!current_is_single_threaded()) {
			error = security_bounded_transition(state, crsec->sid,
							    sid);
			if (error)
				goto abort_change;
		}

		/* Check permissions for the transition. */
		/*
		 * Only check against the current SELinux namespace
		 * because only the SID in the current namespace
		 * is changed by a transition.
		 */
		error = avc_has_perm(state, crsec->sid, sid, SECCLASS_PROCESS,
				     PROCESS__DYNTRANSITION, NULL);
		if (error)
			goto abort_change;

		/* Check for ptracing, and update the task SID if ok.
		   Otherwise, leave SID unchanged and fail. */
		ptsid = ptrace_parent_sid();
		if (ptsid != 0) {
			/*
			 * Only check against the current SELinux namespace
			 * because only the SID in the current namespace
			 * is changed by a transition.
			 */
			error = avc_has_perm(state, ptsid, sid,
					     SECCLASS_PROCESS,
					     PROCESS__PTRACE, NULL);
			if (error)
				goto abort_change;
		}

#ifdef CONFIG_SECURITY_SELINUX_NS
		error = selinux_cred_sid_take_handle(
			crsec, SELINUX_CRED_SID, sid_handle);
		sid_handle = NULL;
		if (error)
			goto abort_change;
#else
		crsec->sid = sid;
#endif
#ifdef CONFIG_SECURITY_SELINUX_NS
	} else if (attr == LSM_ATTR_UNSHARE) {
		error = selinux_state_create(new);
		if (error)
			goto abort_change;
#endif
	} else {
		error = -EINVAL;
		goto abort_change;
	}
	if (error)
		goto abort_change;

	commit_creds(new);
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(sid_handle);
#endif
	return size;

abort_change:
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(sid_handle);
#endif
	abort_creds(new);
	return error;
}

/**
 * selinux_getselfattr - Get SELinux current task attributes
 * @attr: the requested attribute
 * @ctx: buffer to receive the result
 * @size: buffer size (input), buffer size used (output)
 * @flags: unused
 *
 * Fill the passed user space @ctx with the details of the requested
 * attribute.
 *
 * Returns the number of attributes on success, an error code otherwise.
 * There will only ever be one attribute.
 */
static int selinux_getselfattr(unsigned int attr, struct lsm_ctx __user *ctx,
			       u32 *size, u32 flags)
{
	int rc;
	char *val = NULL;
	int val_len;

	val_len = selinux_lsm_getattr(attr, current, &val);
	if (val_len < 0)
		return val_len;
	rc = lsm_fill_user_ctx(ctx, size, val, val_len, LSM_ID_SELINUX, 0);
	kfree(val);
	return (!rc ? 1 : rc);
}

static int selinux_setselfattr(unsigned int attr, struct lsm_ctx *ctx,
			       u32 size, u32 flags)
{
	int rc;

	rc = selinux_lsm_setattr(attr, ctx->ctx, ctx->ctx_len);
	if (rc > 0)
		return 0;
	return rc;
}

static int selinux_getprocattr(struct task_struct *p,
			       const char *name, char **value)
{
	unsigned int attr = lsm_name_to_attr(name);
	int rc;

	if (attr) {
		rc = selinux_lsm_getattr(attr, p, value);
		if (rc != -EOPNOTSUPP)
			return rc;
	}

	return -EINVAL;
}

static int selinux_setprocattr(const char *name, void *value, size_t size)
{
	int attr = lsm_name_to_attr(name);

	if (attr)
		return selinux_lsm_setattr(attr, value, size);
	return -EINVAL;
}

static int selinux_ismaclabel(const char *name)
{
	return (strcmp(name, XATTR_SELINUX_SUFFIX) == 0);
}

static int selinux_secid_to_secctx(u32 secid, struct lsm_context *cp)
{
	u32 seclen;
	int ret;
	const char *ctx;

	if (cp) {
		rcu_read_lock();
		cp->id = LSM_ID_SELINUX;
		ret = security_sid_to_context(current_selinux_state, secid,
					      &ctx, &cp->len);
		if (ret < 0)
			goto err_unlock;
		cp->context = kmemdup(ctx, cp->len, GFP_ATOMIC);
		rcu_read_unlock();
		if (!cp->context)
			return -ENOMEM;
		return cp->len;
	}
	ret = security_sid_to_context(current_selinux_state, secid, NULL,
				      &seclen);
	if (ret < 0)
		return ret;
	return seclen;

err_unlock:
	rcu_read_unlock();
	return ret;
}

static int selinux_lsmprop_to_secctx(const struct lsm_prop *prop,
				     struct lsm_context *cp)
{
	return selinux_secid_to_secctx(prop->selinux.secid, cp);
}

static int selinux_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	return security_context_to_sid(current_selinux_state, secdata, seclen,
				       secid, GFP_KERNEL);
}

static void selinux_release_secctx(struct lsm_context *cp)
{
	if (cp->id == LSM_ID_SELINUX) {
		kfree(cp->context);
		cp->context = NULL;
		cp->id = LSM_ID_UNDEF;
	}
}

static void selinux_inode_invalidate_secctx(struct inode *inode)
{
	struct inode_security_struct *isec = selinux_inode(inode);

	spin_lock(&isec->lock);
#ifdef CONFIG_SECURITY_SELINUX_NS
	/* Published pathless labels have no pathname context to revalidate. */
	if (!rcu_access_pointer(isec->pathless))
		isec->initialized = LABEL_INVALID;
#else
	isec->initialized = LABEL_INVALID;
#endif
	spin_unlock(&isec->lock);
}

/*
 *	called with inode->i_mutex locked
 */
#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_inode_notifysecctx_anchored(struct inode *inode,
					       const void *ctx, u32 ctxlen)
{
	struct superblock_security_struct *sbsec = selinux_superblock(inode->i_sb);
	struct inode_security_struct *isec = selinux_inode(inode);
	struct selinux_label_domain *anchor_domain = NULL;
	struct selinux_state *anchor_state = NULL;
	struct selinux_policy_snapshot snapshot;
	u16 sclass = inode_mode_to_security_class(inode->i_mode);
	unsigned int retry;
	int rc = -ESTALE;

	if (!ctx || !ctxlen) {
		rc = -EACCES;
		goto out;
	}
	if (!selinux_is_sblabel_mnt(inode->i_sb)) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	/* This is an intrinsic filesystem assertion, not an actor relabel request. */
	mutex_lock(&sbsec->lock);
	if (!sbsec->anchor_state || !sbsec->anchor_domain ||
	    sbsec->anchor_state->label_domain != sbsec->anchor_domain ||
	    !selinux_state_active(sbsec->anchor_state)) {
		rc = -EACCES;
	} else {
		anchor_state = get_selinux_state(sbsec->anchor_state);
		anchor_domain = selinux_label_domain_get(sbsec->anchor_domain);
		rc = 0;
	}
	mutex_unlock(&sbsec->lock);
	if (rc)
		goto out;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		struct selinux_global_sid_handle *handle;
		struct selinux_label_ref *label;
		u32 sid;

		rc = selinux_policy_snapshot_read(anchor_state, &snapshot);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;

		handle = security_context_to_global_handle(
			anchor_state, ctx, ctxlen, &sid, GFP_NOFS);
		if (IS_ERR(handle)) {
			rc = PTR_ERR(handle);
			if (rc == -EAGAIN || rc == -ESTALE)
				continue;
			break;
		}
		if (!selinux_policy_snapshot_valid(anchor_state, &snapshot)) {
			global_sid_handle_put(handle);
			rc = -ESTALE;
			continue;
		}

		label = global_sid_handle_label_get(handle);
		if (!label || !sid || global_sid_handle_sid(handle) != sid) {
			rc = -ESTALE;
		} else if (label->domain != anchor_domain &&
			   !((label->domain->flags &
			      SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) &&
			     sid <= SECINITSID_NUM)) {
			rc = -EXDEV;
		} else {
			rc = 0;
		}
		selinux_label_ref_put(label);
		if (rc) {
			global_sid_handle_put(handle);
			break;
		}
		if (!selinux_policy_snapshot_valid(anchor_state, &snapshot)) {
			global_sid_handle_put(handle);
			rc = -ESTALE;
			continue;
		}

		/* Consumes @handle and publishes the complete inode label tuple. */
		rc = selinux_inode_security_take_sid_handle(
			isec, handle, &sclass, SELINUX_LABEL_SOURCE_SECURITY_CONTEXT,
			LABEL_INITIALIZED);
		if (rc) {
			if (rc == -EAGAIN || rc == -ESTALE)
				continue;
			break;
		}
		if (!selinux_policy_snapshot_valid(anchor_state, &snapshot)) {
			selinux_inode_security_invalidate(inode);
			rc = -ESTALE;
			continue;
		}
		break;
	}

out:
	if (anchor_state)
		put_selinux_state(anchor_state);
	if (anchor_domain)
		selinux_label_domain_put(anchor_domain);
	/* A rejected server label must not leave the previous tuple usable. */
	if (rc)
		selinux_inode_invalidate_secctx(inode);
	return rc;
}
#endif

static int selinux_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_inode_notifysecctx_anchored(inode, ctx, ctxlen);
#else
	int rc = selinux_inode_setsecurity(inode, XATTR_SELINUX_SUFFIX,
					   ctx, ctxlen, 0);
	/* Do not return error when suppressing label. */
	return rc == -EOPNOTSUPP ? 0 : rc;
#endif
}

/*
 *	called with inode->i_mutex locked
 */
static int selinux_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	/* This intrinsic inode hook has no path from which to obtain a mount. */
	return __vfs_setxattr_locked_mnt(&nop_mnt_idmap, NULL, dentry,
					 XATTR_NAME_SELINUX, ctx, ctxlen, 0,
					 NULL);
}

static int selinux_inode_getsecctx(struct inode *inode, struct lsm_context *cp)
{
	int len;
	len = selinux_inode_getsecurity(&nop_mnt_idmap, NULL, inode,
					XATTR_SELINUX_SUFFIX,
					(void **)&cp->context, true);
	if (len < 0)
		return len;
	cp->len = len;
	cp->id = LSM_ID_SELINUX;
	return 0;
}
#ifdef CONFIG_KEYS

static int selinux_key_alloc(struct key *k, const struct cred *cred,
			     unsigned long flags)
{
	struct key_security_struct *ksec = selinux_key(k);

#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_creator_projection_build(
		cred, SELINUX_PATHLESS_KIND_KEY, SECCLASS_KEY, true, 0, NULL,
		NULL, &ksec->sid, &ksec->projection);
#else
	const struct cred_security_struct *crsec;

	crsec = selinux_cred(cred);
	if (crsec->keycreate_sid)
		ksec->sid = crsec->keycreate_sid;
	else
		ksec->sid = crsec->sid;

	return 0;
#endif
}

static void selinux_key_free(struct key *key)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct key_security_struct *ksec;

	if (!key->security)
		return;
	ksec = selinux_key(key);
	selinux_pathless_projection_put(ksec->projection);
	ksec->projection = NULL;
#endif
}

static int selinux_key_permission(key_ref_t key_ref,
				  const struct cred *cred,
				  enum key_need_perm need_perm)
{
	struct key *key;
	struct key_security_struct *ksec;
	u32 perm;

	switch (need_perm) {
	case KEY_NEED_VIEW:
		perm = KEY__VIEW;
		break;
	case KEY_NEED_READ:
		perm = KEY__READ;
		break;
	case KEY_NEED_WRITE:
		perm = KEY__WRITE;
		break;
	case KEY_NEED_SEARCH:
		perm = KEY__SEARCH;
		break;
	case KEY_NEED_LINK:
		perm = KEY__LINK;
		break;
	case KEY_NEED_SETATTR:
		perm = KEY__SETATTR;
		break;
	case KEY_NEED_UNLINK:
	case KEY_SYSADMIN_OVERRIDE:
	case KEY_AUTHTOKEN_OVERRIDE:
	case KEY_DEFER_PERM_CHECK:
		return 0;
	default:
		WARN_ON(1);
		return -EPERM;

	}

	key = key_ref_to_ptr(key_ref);
	ksec = selinux_key(key);

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!ksec->projection ||
	    ksec->projection->kind != SELINUX_PATHLESS_KIND_KEY)
		return -EACCES;
	return cred_pathless_has_perm(cred, ksec->projection, perm, NULL);
#else
	return cred_tsid_has_perm(cred, ksec->sid, SECCLASS_KEY, perm, NULL);
#endif
}

static int selinux_key_getsecurity(struct key *key, char **_buffer)
{
	struct key_security_struct *ksec = selinux_key(key);
	const char *context = NULL;
	unsigned len;
	int rc;
	u32 sid = ksec->sid;

#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		const struct cred_security_struct *crsec =
			selinux_cred(current_cred());
		struct selinux_pathless_resolution resolved;

		if (!ksec->projection ||
		    ksec->projection->kind != SELINUX_PATHLESS_KIND_KEY)
			return -EACCES;
		rc = selinux_pathless_projection_resolve_sealed(
			ksec->projection, crsec->state->label_domain, &resolved);
		if (rc)
			return rc;
		if (resolved.sclass != SECCLASS_KEY)
			return -EOPNOTSUPP;
		sid = resolved.sid;
	}
#endif

	rcu_read_lock();
	rc = security_sid_to_context(current_selinux_state, sid,
				     &context, &len);
	if (rc) {
		rcu_read_unlock();
		return rc;
	}
	*_buffer = kmemdup(context, len, GFP_ATOMIC);
	rcu_read_unlock();
	if (!(*_buffer))
		return -ENOMEM;
	return len;
}

#ifdef CONFIG_KEY_NOTIFICATIONS
static int selinux_watch_key(struct key *key)
{
	struct key_security_struct *ksec = selinux_key(key);

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!ksec->projection ||
	    ksec->projection->kind != SELINUX_PATHLESS_KIND_KEY)
		return -EACCES;
	return cred_pathless_has_perm(current_cred(), ksec->projection,
				      KEY__VIEW, NULL);
#else
	return cred_tsid_has_perm(current_cred(), ksec->sid, SECCLASS_KEY,
				  KEY__VIEW, NULL);
#endif
}
#endif
#endif

#ifdef CONFIG_SECURITY_INFINIBAND
#ifndef CONFIG_SECURITY_SELINUX_NS
static int selinux_state_pkey_has_perm(struct selinux_state *state, u32 ssid,
				       u64 subnet_prefix, u16 pkey_val,
				       struct common_audit_data *ad)
{
	struct selinux_policy_chain_snapshot *chain __free(kfree) =
		kzalloc_obj(*chain, GFP_ATOMIC);
	unsigned int retry;

	if (!chain)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		struct selinux_state *policy_state = state;
		u32 policy_ssid = ssid;
		u16 i;
		int rc = 0;

		rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&chain->policy[i];
			u32 pkey_sid;

			if (!policy_state || crsec->state != policy_state) {
				rc = -EXDEV;
				break;
			}
			rc = sel_ib_pkey_sid_snapshot(
				policy_state, snapshot, subnet_prefix, pkey_val,
				&pkey_sid);
			if (rc)
				break;
			rc = avc_has_perm_snapshot(
				policy_state, snapshot, policy_ssid, pkey_sid,
				SECCLASS_INFINIBAND_PKEY,
				INFINIBAND_PKEY__ACCESS, ad);
			if (rc)
				break;
			policy_ssid = policy_state->creator_sid;
			policy_state = policy_state->parent;
		}
		if (!rc && policy_state)
			rc = -EXDEV;
		if (rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain))
			continue;
		return rc;
	}
	return -ESTALE;
}
#endif

static int selinux_ib_pkey_access(void *ib_sec, u64 subnet_prefix, u16 pkey_val)
{
	struct common_audit_data ad;
	struct ib_security_struct *sec = selinux_ib(ib_sec);
	struct lsm_ibpkey_audit ibpkey;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct selinux_pathless_projection *projection;
	const struct cred *cred;
	struct selinux_net_avc_transaction *transaction __free(kfree) = NULL;
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
#endif

	ad.type = LSM_AUDIT_DATA_IBPKEY;
	ibpkey.subnet_prefix = subnet_prefix;
	ibpkey.pkey = pkey_val;
	ad.u.ibpkey = &ibpkey;
#ifdef CONFIG_SECURITY_SELINUX_NS
	cred = READ_ONCE(sec->cred);
	projection = READ_ONCE(sec->projection);
	if (!cred || !projection ||
	    projection->kind != SELINUX_PATHLESS_KIND_INFINIBAND)
		return -EACCES;
	chain = kzalloc_obj(*chain, GFP_ATOMIC);
	transaction = kzalloc_obj(*transaction, GFP_ATOMIC | __GFP_NOWARN);
	if (!chain || !transaction)
		return -ENOMEM;
	transaction->workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_NET_AVC_MAX_CHECKS, GFP_ATOMIC | __GFP_NOWARN);
	if (!transaction->workspace)
		return -ENOMEM;
	{
		unsigned int retry;
		int result = -ESTALE;

		for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
			u16 i;
			int rc;

			selinux_net_avc_transaction_reset(transaction);
			rc = selinux_policy_chain_snapshot_read(cred, chain);
			if (rc == -EAGAIN || rc == -ESTALE)
				continue;
			if (rc) {
				result = rc;
				break;
			}
			for (i = 0; i < chain->count; i++) {
				const struct cred_security_struct *crsec =
					selinux_cred(chain->cred[i]);
				struct selinux_global_sid_handle *pkey_handle;
				struct selinux_pathless_resolution resolved;
				u32 pkey_sid;

				rc = selinux_pathless_projection_resolve_sealed(
					projection,
					crsec->state->label_domain, &resolved);
				if (rc)
					break;
				if (resolved.sclass != SECCLASS_PROCESS) {
					rc = -EOPNOTSUPP;
					break;
				}
				pkey_handle = sel_ib_pkey_sid_snapshot_handle(
					crsec->state, &chain->policy[i], subnet_prefix,
					pkey_val, &pkey_sid);
				if (IS_ERR(pkey_handle)) {
					rc = PTR_ERR(pkey_handle);
					break;
				}
				rc = selinux_net_avc_transaction_add_handle(
					transaction,
					&(struct selinux_avc_level) {
						.state = crsec->state,
						.ssid = resolved.sid,
						.tsid = pkey_sid,
						.tclass = SECCLASS_INFINIBAND_PKEY,
						.requested = INFINIBAND_PKEY__ACCESS,
					}, &chain->policy[i], pkey_handle,
					projection->view, projection->source);
				if (rc)
					break;
			}
			if (!rc)
				rc = selinux_net_avc_transaction_decide(transaction, &ad);
			if (rc == -ESTALE ||
			    !selinux_policy_chain_snapshot_valid(chain))
				continue;
			result = rc;
			break;
		}
		selinux_net_avc_transaction_reset(transaction);
		selinux_avc_transaction_workspace_free(transaction->workspace);
		return result;
	}
#else
	return selinux_state_pkey_has_perm(current_selinux_state, sec->sid,
					   subnet_prefix, pkey_val, &ad);
#endif
}

static int selinux_ib_endport_manage_subnet(void *ib_sec, const char *dev_name,
					    u8 port_num)
{
	struct common_audit_data ad;
	int err;
	u32 sid = 0;
	struct ib_security_struct *sec = selinux_ib(ib_sec);
	struct lsm_ibendport_audit ibendport;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct selinux_pathless_projection *projection;
	const struct cred *cred;
	struct selinux_net_avc_transaction *transaction __free(kfree) = NULL;
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
#endif

	ad.type = LSM_AUDIT_DATA_IBENDPORT;
	ibendport.dev_name = dev_name;
	ibendport.port = port_num;
	ad.u.ibendport = &ibendport;
#ifdef CONFIG_SECURITY_SELINUX_NS
	cred = READ_ONCE(sec->cred);
	projection = READ_ONCE(sec->projection);
	if (!cred || !projection ||
	    projection->kind != SELINUX_PATHLESS_KIND_INFINIBAND)
		return -EACCES;
	chain = kzalloc_obj(*chain, GFP_ATOMIC);
	transaction = kzalloc_obj(*transaction, GFP_ATOMIC | __GFP_NOWARN);
	if (!chain || !transaction)
		return -ENOMEM;
	transaction->workspace = selinux_avc_transaction_workspace_alloc(
		SELINUX_NET_AVC_MAX_CHECKS, GFP_ATOMIC | __GFP_NOWARN);
	if (!transaction->workspace)
		return -ENOMEM;
	{
		unsigned int retry;
		int result = -ESTALE;

		for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
			u16 i;

			selinux_net_avc_transaction_reset(transaction);
			err = selinux_policy_chain_snapshot_read(cred, chain);
			if (err == -EAGAIN || err == -ESTALE)
				continue;
			if (err) {
				result = err;
				break;
			}
			for (i = 0; i < chain->count; i++) {
				const struct cred_security_struct *crsec =
					selinux_cred(chain->cred[i]);
				struct selinux_global_sid_handle *endport_handle;
				struct selinux_pathless_resolution resolved;

				err = selinux_pathless_projection_resolve_sealed(
					projection,
					crsec->state->label_domain, &resolved);
				if (err)
					break;
				if (resolved.sclass != SECCLASS_PROCESS) {
					err = -EOPNOTSUPP;
					break;
				}
				endport_handle = security_ib_endport_sid_handle(
					crsec->state, dev_name, port_num, &sid);
				if (IS_ERR(endport_handle)) {
					err = PTR_ERR(endport_handle);
					break;
				}
				err = selinux_net_avc_transaction_add_handle(
					transaction,
					&(struct selinux_avc_level) {
						.state = crsec->state,
						.ssid = resolved.sid,
						.tsid = sid,
						.tclass = SECCLASS_INFINIBAND_ENDPORT,
						.requested =
							INFINIBAND_ENDPORT__MANAGE_SUBNET,
					}, &chain->policy[i], endport_handle,
					projection->view, projection->source);
				if (err)
					break;
			}
			if (!err)
				err = selinux_net_avc_transaction_decide(transaction, &ad);
			if (err == -ESTALE ||
			    !selinux_policy_chain_snapshot_valid(chain))
				continue;
			result = err;
			break;
		}
		selinux_net_avc_transaction_reset(transaction);
		selinux_avc_transaction_workspace_free(transaction->workspace);
		return result;
	}
#else
	err = security_ib_endport_sid(current_selinux_state, dev_name, port_num,
				      &sid);
	if (err)
		return err;
	return selinux_state_has_perm(current_selinux_state,
				      sec->sid, sid,
				      SECCLASS_INFINIBAND_ENDPORT,
				      INFINIBAND_ENDPORT__MANAGE_SUBNET, &ad);
#endif
}

static int selinux_ib_alloc_security(void *ib_sec)
{
	struct ib_security_struct *sec = selinux_ib(ib_sec);

#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct cred *cred = get_cred(current_cred());
	int rc;

	/* The concrete IB operation selects the target class dynamically. */
	rc = selinux_creator_projection_build(
		cred, SELINUX_PATHLESS_KIND_INFINIBAND,
		SECCLASS_PROCESS, false, 0, NULL, NULL, &sec->sid,
		&sec->projection);
	if (rc) {
		put_cred(cred);
		return rc;
	}
	WRITE_ONCE(sec->cred, cred);
	return 0;
#else
	sec->sid = current_sid();
	return 0;
#endif
}

static int selinux_ib_policy_scopes(void *ib_sec, u64 *scope_ids, u16 capacity)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct ib_security_struct *sec = selinux_ib(ib_sec);
	const struct cred *cred = READ_ONCE(sec->cred);
	u16 count = 0;

	while (cred) {
		const struct cred_security_struct *crsec = selinux_cred(cred);

		if (count == capacity || !crsec->state ||
		    !crsec->state->label_domain)
			return -E2BIG;
		scope_ids[count++] = crsec->state->label_domain->id;
		cred = crsec->parent_cred;
	}
	return count;
#else
	return 0;
#endif
}

static void selinux_ib_free_security(void *ib_sec)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct ib_security_struct *sec = selinux_ib(ib_sec);
	struct selinux_pathless_projection *projection;
	const struct cred *cred;

	projection = xchg(&sec->projection, NULL);
	cred = xchg(&sec->cred, NULL);
	selinux_pathless_projection_put(projection);
	put_cred(cred);
#endif
}
#endif

#ifdef CONFIG_BPF_SYSCALL
static int selinux_bpf(int cmd, union bpf_attr *attr,
		       unsigned int size, bool kernel)
{
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	unsigned int retry;
	bool object_cap_only = false;
	u32 requested;

	switch (cmd) {
	case BPF_MAP_CREATE:
		requested = BPF__MAP_CREATE;
		break;
	case BPF_PROG_LOAD:
		requested = BPF__PROG_LOAD;
		break;
	case BPF_MAP_GET_NEXT_ID:
		requested = BPF__MAP_ENUMERATE;
		object_cap_only = true;
		break;
	case BPF_PROG_GET_NEXT_ID:
		requested = BPF__PROG_ENUMERATE;
		object_cap_only = true;
		break;
	case BPF_PROG_QUERY:
	case BPF_TASK_FD_QUERY:
		requested = BPF__PROG_ENUMERATE;
		object_cap_only = true;
		break;
	case BPF_LINK_GET_NEXT_ID:
		requested = BPF__LINK_ENUMERATE;
		object_cap_only = true;
		break;
	case BPF_BTF_GET_NEXT_ID:
		requested = BPF__BTF_ENUMERATE;
		object_cap_only = true;
		break;
	default:
		return 0;
	}
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;
		int rc;

		rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;

		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			const struct selinux_policy_snapshot *snapshot =
				&chain->policy[i];

			if (object_cap_only &&
			    !selinux_policycap_bpf_object_perms(snapshot))
				continue;

			/* A policy that opted into token-specific hooks skips only
			 * its own legacy check; every ancestor still chooses and
			 * enforces its model independently.
			 */
			if (!object_cap_only &&
			    selinux_policycap_bpf_token_perms(snapshot))
				continue;
			rc = avc_has_perm_snapshot(
				crsec->state, snapshot, crsec->sid, crsec->sid,
				SECCLASS_BPF, requested, NULL);
			if (rc)
				break;
		}
		if (rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain))
			continue;
		return rc;
	}

	return -ESTALE;
}

static u32 bpf_map_fmode_to_av(fmode_t fmode)
{
	u32 av = 0;

	if (fmode & FMODE_READ)
		av |= BPF__MAP_READ;
	if (fmode & FMODE_WRITE)
		av |= BPF__MAP_WRITE;
	return av;
}

static u32 selinux_bpf_prog_map_av(const struct bpf_map *map)
{
	if (map->map_flags & BPF_F_RDONLY_PROG)
		return BPF__MAP_READ;
	if (map->map_flags & BPF_F_WRONLY_PROG)
		return BPF__MAP_WRITE;
	return BPF__MAP_READ | BPF__MAP_WRITE;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
/*
 * BPF objects have no stable pathname.  Retain the canonical source label and
 * one immutable view from its real provenance domain through the current
 * credential chain.  The seals contain the exact BPF SID seen independently
 * by every policy; no lossy child-to-parent round trip is required.
 */
static int selinux_bpf_projection_build(
	struct selinux_pathless_build_scratch *scratch, u32 source_sid,
	bool require_cred_match,
	struct selinux_pathless_projection **projectionp)
{
	const struct selinux_policy_chain_snapshot *chain = &scratch->chain;
	struct selinux_label_ref *source_label = NULL;
	const struct selinux_label_view *source_view = NULL;
	struct selinux_label_domain *leaf_domain, *outer_domain;
	struct selinux_pathless_projection *projection;
	enum selinux_label_source source;
	bool kernel_global;
	u16 i;
	int rc;

	*projectionp = NULL;
	if (!chain->count || !source_sid)
		return -EINVAL;

	leaf_domain = selinux_cred(chain->cred[0])->state->label_domain;
	outer_domain = selinux_cred(chain->cred[chain->count - 1])->
			       state->label_domain;
	if (!leaf_domain || !outer_domain)
		return -EXDEV;

	source_label = global_sid_to_label_ref(source_sid);
	if (IS_ERR(source_label))
		return PTR_ERR(source_label);
	kernel_global = source_label->domain->flags &
			SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL;
	if (kernel_global && source_sid > SECINITSID_NUM) {
		rc = -EINVAL;
		goto out;
	}
	source = kernel_global ? SELINUX_LABEL_SOURCE_KERNEL_INITIAL :
				 SELINUX_LABEL_SOURCE_TASK;

	/* Kernel-initial labels are universal; otherwise origin is provenance. */
	source_view = selinux_identity_view_alloc_gfp(
		leaf_domain->owner_userns,
		kernel_global ? leaf_domain : source_label->domain,
		(kernel_global || source_label->domain == leaf_domain) ?
			outer_domain : leaf_domain,
		GFP_KERNEL);
	if (IS_ERR(source_view)) {
		rc = PTR_ERR(source_view);
		source_view = NULL;
		goto out;
	}

	rc = selinux_label_view_resolve_chain(
		source_view, source_label, source_sid, &scratch->legacy);
	if (rc)
		goto out;

	for (i = 0; i < chain->count; i++) {
		const struct cred_security_struct *crsec =
			selinux_cred(chain->cred[i]);
		struct selinux_label_domain *domain = crsec->state->label_domain;
		struct selinux_pathless_expect *expect;
		u16 depth;

		if (!domain) {
			rc = -EXDEV;
			goto out;
		}
		depth = domain->depth;
		if (depth >= chain->count ||
		    scratch->legacy.domain_id[depth] != domain->id ||
		    !scratch->legacy.sid[depth]) {
			rc = -EOPNOTSUPP;
			goto out;
		}
		if (require_cred_match &&
		    scratch->legacy.sid[depth] != crsec->sid) {
			rc = -EACCES;
			goto out;
		}
		expect = &scratch->expects[depth];
		expect->domain = domain;
		expect->sid = scratch->legacy.sid[depth];
		expect->sclass = SECCLASS_BPF;
		expect->model = SELINUX_PATHLESS_MODEL_LEGACY;
	}

	projection = selinux_pathless_projection_alloc_sealed(
		SELINUX_PATHLESS_KIND_BPF, source, source_label, source_sid,
		source_view, scratch->expects, chain->count, GFP_KERNEL);
	if (IS_ERR(projection)) {
		rc = PTR_ERR(projection);
		goto out;
	}
	*projectionp = projection;
	rc = 0;

out:
	selinux_label_view_put(source_view);
	selinux_label_ref_put(source_label);
	return rc;
}

static int selinux_bpf_projection_resolve(
	const struct selinux_pathless_projection *projection,
	const struct selinux_label_domain *domain, u32 *sid)
{
	struct selinux_pathless_resolution resolved;
	int rc;

	if (!projection)
		return -EACCES;
	rc = selinux_pathless_projection_resolve_sealed(
		projection, domain, &resolved);
	if (rc)
		return rc;
	if (resolved.sclass != SECCLASS_BPF ||
	    resolved.model != SELINUX_PATHLESS_MODEL_LEGACY)
		return -EOPNOTSUPP;
	*sid = resolved.sid;
	return 0;
}

static int selinux_bpf_projection_has_perm(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection, u16 tclass,
	u32 requested)
{
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	struct selinux_pathless_chain_resolution *line __free(kfree) = NULL;
	unsigned int retry;

	if (!projection || !tclass)
		return -EACCES;
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	line = kzalloc_obj(*line, GFP_KERNEL);
	if (!chain || !line)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;
		int rc;

		selinux_pathless_chain_resolution_put(line);
		rc = selinux_policy_chain_snapshot_read(cred, chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		rc = selinux_pathless_projection_resolve_cred_chain(
			projection, chain->cred, chain->policy, chain->count, line);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			struct selinux_pathless_resolution resolved =
				line->level[crsec->state->label_domain->depth];

			if (!resolved.sid || resolved.sclass != SECCLASS_BPF ||
			    resolved.model != SELINUX_PATHLESS_MODEL_LEGACY) {
				rc = -EOPNOTSUPP;
				break;
			}
			rc = avc_has_perm_snapshot(
				crsec->state, &chain->policy[i], crsec->sid,
				resolved.sid,
				tclass, requested, NULL);
			if (rc)
				break;
		}
		if (rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain))
			continue;
		selinux_pathless_chain_resolution_put(line);
		return rc;
	}
	selinux_pathless_chain_resolution_put(line);
	return -ESTALE;
}

static int selinux_bpf_create_has_perm(
	const struct selinux_policy_chain_snapshot *chain,
	const struct selinux_pathless_projection *object,
	const struct selinux_pathless_projection *leaf_grantor, u32 requested)
{
	u16 i;
	int rc = 0;

	if (!object)
		return -EACCES;
	for (i = 0; i < chain->count; i++) {
		const struct cred_security_struct *crsec =
			selinux_cred(chain->cred[i]);
		u32 ssid = crsec->sid, tsid;

		rc = selinux_bpf_projection_resolve(
			object, crsec->state->label_domain, &tsid);
		if (rc)
			break;
		/* Preserve upstream token semantics only in the leaf policy. */
		if (leaf_grantor && i == 0) {
			rc = selinux_bpf_projection_resolve(
				leaf_grantor, crsec->state->label_domain, &ssid);
			if (rc)
				break;
		}
		rc = avc_has_perm_snapshot(
			crsec->state, &chain->policy[i], ssid, tsid,
			SECCLASS_BPF, requested, NULL);
		if (rc)
			break;
	}
	return rc;
}

static int selinux_bpf_chain_target_has_perm(
	const struct selinux_policy_chain_snapshot *chain,
	const struct selinux_pathless_projection *target, u16 tclass,
	u32 requested)
{
	u16 i;
	int rc = 0;

	if (!target || !tclass)
		return -EACCES;
	for (i = 0; i < chain->count; i++) {
		const struct cred_security_struct *crsec =
			selinux_cred(chain->cred[i]);
		u32 tsid;

		rc = selinux_bpf_projection_resolve(
			target, crsec->state->label_domain, &tsid);
		if (rc)
			break;
		rc = avc_has_perm_snapshot(
			crsec->state, &chain->policy[i], crsec->sid, tsid,
			tclass, requested, NULL);
		if (rc)
			break;
	}
	return rc;
}

#endif /* CONFIG_SECURITY_SELINUX_NS */

/* This function will check the file pass through unix socket or binder to see
 * if it is a bpf related object. And apply corresponding checks on the bpf
 * object based on the type. The bpf maps and programs, not like other files and
 * socket, are using a shared anonymous inode inside the kernel as their inode.
 * So checking that inode cannot identify if the process have privilege to
 * access the bpf object and that's why we have to add this additional check in
 * selinux_file_receive and selinux_binder_transfer_files.
 */
#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_file_transfer_bpf_add(
	struct selinux_file_transfer_transaction *transaction,
	const struct selinux_pathless_projection *projection, u32 requested,
	bool object_cap_only)
{
	const struct selinux_avc_provenance *provenance;
	struct selinux_pathless_chain_resolution *line =
		&transaction->bpf_line;
	u16 i;
	int rc;

	if (!projection || projection->kind != SELINUX_PATHLESS_KIND_BPF ||
	    !requested)
		return -EACCES;
	rc = selinux_pathless_projection_resolve_cred_chain(
		projection, transaction->chain.cred, transaction->chain.policy,
		transaction->chain.count, line);
	if (rc)
		return rc;
	rc = selinux_file_transfer_transaction_provenance(
		transaction, projection->label, projection->view,
		projection->source, &provenance);
	if (rc)
		goto out;
	for (i = 0; i < transaction->chain.count; i++) {
		const struct cred_security_struct *crsec =
			selinux_cred(transaction->chain.cred[i]);
		struct selinux_pathless_resolution resolved =
			line->level[crsec->state->label_domain->depth];
		struct selinux_avc_provenance level_provenance = *provenance;

		if (object_cap_only &&
		    !selinux_policycap_bpf_object_perms(
			    &transaction->chain.policy[i]))
			continue;
		if (resolved.sclass != SECCLASS_BPF) {
			rc = -EOPNOTSUPP;
			goto out;
		}
		level_provenance.map_generation = resolved.map_generation;
		rc = selinux_file_transfer_transaction_add(
			transaction,
			&(struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = resolved.sid,
				.tclass = SECCLASS_BPF,
				.requested = requested,
				.provenance = &level_provenance,
			}, &transaction->chain.policy[i]);
		if (rc)
			goto out;
	}
	rc = 0;
out:
	return rc;
}

static int bpf_fd_pass_add(
	const struct file *file, const struct cred *cred,
	struct selinux_file_transfer_transaction *transaction)
{
	const struct selinux_pathless_projection *projection;

	if (!transaction->chain.count || transaction->chain.cred[0] != cred)
		return -EXDEV;
	if (file->f_op == &bpf_map_fops) {
		projection = READ_ONCE(selinux_bpf_map_security(
			file->private_data)->object);
		return selinux_file_transfer_bpf_add(
			transaction, projection, bpf_map_fmode_to_av(file->f_mode),
			false);
	}
	if (file->f_op == &bpf_prog_fops) {
		projection = READ_ONCE(selinux_bpf_prog_security(
			file->private_data)->object);
		return selinux_file_transfer_bpf_add(
			transaction, projection, BPF__PROG_RUN, false);
	}
	if (file->f_op == &bpf_link_fops || file->f_op == &bpf_link_fops_poll) {
		projection = READ_ONCE(selinux_bpf_link_security(
			file->private_data)->object);
		return selinux_file_transfer_bpf_add(
			transaction, projection,
			selinux_bpf_link_cmd_perm(BPF_OBJ_GET), true);
	}
	if (file->f_op == &btf_fops) {
		projection = READ_ONCE(selinux_bpf_btf_security(
			file->private_data)->object);
		return selinux_file_transfer_bpf_add(
			transaction, projection, BPF__BTF_READ, true);
	}
	if (file->f_op == &bpf_token_fops) {
		const struct bpf_security_struct *bpfsec =
			selinux_bpf_token_security(file->private_data);
		const struct selinux_pathless_projection *object =
			READ_ONCE(bpfsec->object);
		const struct selinux_pathless_projection *grantor =
			READ_ONCE(bpfsec->grantor);
		const struct selinux_avc_provenance *object_provenance;
		const struct selinux_avc_provenance *grantor_provenance;
		u32 object_requested = READ_ONCE(bpfsec->perms);
		u32 grantor_requested = 0;
		u16 i;
		int rc;

		if (!object || object->kind != SELINUX_PATHLESS_KIND_BPF ||
		    !grantor || grantor->kind != SELINUX_PATHLESS_KIND_BPF ||
		    object_requested & ~(BPF__MAP_CREATE | BPF__PROG_LOAD |
				 BPF__BTF_LOAD))
			return -EACCES;
		if (object_requested & BPF__MAP_CREATE)
			grantor_requested |= BPF__MAP_CREATE_AS;
		if (object_requested & BPF__PROG_LOAD)
			grantor_requested |= BPF__PROG_LOAD_AS;
		rc = selinux_file_transfer_transaction_provenance(
			transaction, object->label, object->view, object->source,
			&object_provenance);
		if (rc)
			return rc;
		rc = selinux_file_transfer_transaction_provenance(
			transaction, grantor->label, grantor->view, grantor->source,
			&grantor_provenance);
		if (rc)
			return rc;
		for (i = 0; i < transaction->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(transaction->chain.cred[i]);
			u32 policy_requested = object_requested;
			u32 object_sid, grantor_sid;

			if (!selinux_policycap_bpf_object_perms(
				    &transaction->chain.policy[i]))
				policy_requested &= ~BPF__BTF_LOAD;
			rc = selinux_bpf_projection_resolve(
				object, crsec->state->label_domain, &object_sid);
			if (rc)
				return rc;
			rc = selinux_bpf_projection_resolve(
				grantor, crsec->state->label_domain, &grantor_sid);
			if (rc)
				return rc;
			if (policy_requested) {
				rc = selinux_file_transfer_transaction_add(
					transaction,
					&(struct selinux_avc_level) {
						.state = crsec->state,
						.ssid = crsec->sid,
						.tsid = object_sid,
						.tclass = SECCLASS_BPF,
						.requested = policy_requested,
						.provenance = object_provenance,
					}, &transaction->chain.policy[i]);
				if (rc)
					return rc;
			}
			if (grantor_requested) {
				rc = selinux_file_transfer_transaction_add(
					transaction,
					&(struct selinux_avc_level) {
						.state = crsec->state,
						.ssid = crsec->sid,
						.tsid = grantor_sid,
						.tclass = SECCLASS_BPF,
						.requested = grantor_requested,
						.provenance = grantor_provenance,
					}, &transaction->chain.policy[i]);
				if (rc)
					return rc;
			}
		}
	}
	return 0;
}
#endif

#ifndef CONFIG_SECURITY_SELINUX_NS
static int __maybe_unused bpf_fd_pass(const struct file *file,
				      const struct cred *cred)
{
	struct bpf_security_struct *bpfsec;
	struct bpf_prog *prog;
	struct bpf_map *map;
	int ret;

	if (file->f_op == &bpf_map_fops) {
		map = file->private_data;
		bpfsec = selinux_bpf_map_security(map);
#ifdef CONFIG_SECURITY_SELINUX_NS
		ret = selinux_bpf_projection_has_perm(
			cred, READ_ONCE(bpfsec->object), SECCLASS_BPF,
			bpf_map_fmode_to_av(file->f_mode));
#else
		ret = cred_tsid_has_perm(cred, bpfsec->sid, SECCLASS_BPF,
					 bpf_map_fmode_to_av(file->f_mode), NULL);
#endif
		if (ret)
			return ret;
	} else if (file->f_op == &bpf_prog_fops) {
		prog = file->private_data;
		bpfsec = selinux_bpf_prog_security(prog);
#ifdef CONFIG_SECURITY_SELINUX_NS
		ret = selinux_bpf_projection_has_perm(
			cred, READ_ONCE(bpfsec->object), SECCLASS_BPF,
			BPF__PROG_RUN);
#else
		ret = cred_tsid_has_perm(cred, bpfsec->sid, SECCLASS_BPF,
					 BPF__PROG_RUN, NULL);
#endif
		if (ret)
			return ret;
	} else if (file->f_op == &bpf_link_fops ||
		   file->f_op == &bpf_link_fops_poll) {
		ret = selinux_bpf_link_access_cred(
			cred, file->private_data, BPF_OBJ_GET);
		if (ret)
			return ret;
	} else if (file->f_op == &btf_fops) {
		ret = selinux_bpf_btf_cred(cred, file->private_data);
		if (ret)
			return ret;
#ifdef CONFIG_SECURITY_SELINUX_NS
	} else if (file->f_op == &bpf_token_fops) {
		ret = selinux_bpf_token_fd_pass(cred, file->private_data);
		if (ret)
			return ret;
#endif
	}
	return 0;
}
#endif

static int selinux_bpf_map(struct bpf_map *map, fmode_t fmode)
{
	struct bpf_security_struct *bpfsec;

	bpfsec = selinux_bpf_map_security(map);
#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_bpf_projection_has_perm(
		current_cred(), READ_ONCE(bpfsec->object), SECCLASS_BPF,
		bpf_map_fmode_to_av(fmode));
#else
	return cred_tsid_has_perm(current_cred(), bpfsec->sid, SECCLASS_BPF,
				  bpf_map_fmode_to_av(fmode), NULL);
#endif
}

static int selinux_bpf_map_relation(struct bpf_map *outer,
				    const struct bpf_map *inner,
				    const struct bpf_prog *prog)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct selinux_pathless_projection *outer_object = READ_ONCE(
		selinux_bpf_map_security(outer)->object);
	const struct selinux_pathless_projection *target_object;
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	u32 target_perm;
	unsigned int retry;

	if (!!inner == !!prog || !outer_object)
		return -EINVAL;
	if (inner) {
		target_object = READ_ONCE(selinux_bpf_map_security(
			(struct bpf_map *)inner)->object);
		target_perm = BPF__MAP_READ;
	} else {
		target_object = READ_ONCE(selinux_bpf_prog_security(
			(struct bpf_prog *)prog)->object);
		target_perm = BPF__PROG_RUN;
	}
	if (!target_object)
		return -EACCES;
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;
		int rc = 0;

		rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			u32 tsid;

			rc = selinux_bpf_projection_resolve(
				outer_object, crsec->state->label_domain, &tsid);
			if (rc)
				break;
			rc = avc_has_perm_snapshot(
				crsec->state, &chain->policy[i], crsec->sid, tsid,
				SECCLASS_BPF, BPF__MAP_WRITE, NULL);
			if (rc)
				break;
			rc = selinux_bpf_projection_resolve(
				target_object, crsec->state->label_domain, &tsid);
			if (rc)
				break;
			rc = avc_has_perm_snapshot(
				crsec->state, &chain->policy[i], crsec->sid, tsid,
				SECCLASS_BPF, target_perm, NULL);
			if (rc)
				break;
		}
		if (rc == -ESTALE || !selinux_policy_chain_snapshot_valid(chain))
			continue;
		return rc;
	}
	return -ESTALE;
#else
	int rc;

	if (!!inner == !!prog)
		return -EINVAL;
	rc = cred_tsid_has_perm(current_cred(),
				selinux_bpf_map_security(outer)->sid,
				SECCLASS_BPF, BPF__MAP_WRITE, NULL);
	if (rc)
		return rc;
	if (inner)
		return cred_tsid_has_perm(
			current_cred(),
			selinux_bpf_map_security((struct bpf_map *)inner)->sid,
			SECCLASS_BPF, BPF__MAP_READ, NULL);
	return cred_tsid_has_perm(
		current_cred(),
		selinux_bpf_prog_security((struct bpf_prog *)prog)->sid,
		SECCLASS_BPF, BPF__PROG_RUN, NULL);
#endif
}

static int selinux_bpf_prog(struct bpf_prog *prog)
{
	struct bpf_security_struct *bpfsec;

	bpfsec = selinux_bpf_prog_security(prog);
#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_bpf_projection_has_perm(
		current_cred(), READ_ONCE(bpfsec->object), SECCLASS_BPF,
		BPF__PROG_RUN);
#else
	return cred_tsid_has_perm(current_cred(), bpfsec->sid, SECCLASS_BPF,
				  BPF__PROG_RUN, NULL);
#endif
}

static int selinux_bpf_prog_map_relation(struct bpf_prog *prog,
					 const struct bpf_map *map)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct selinux_pathless_projection *prog_object = READ_ONCE(
		selinux_bpf_prog_security(prog)->object);
	const struct selinux_pathless_projection *map_object = READ_ONCE(
		selinux_bpf_map_security((struct bpf_map *)map)->object);
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	unsigned int retry;

	if (!prog_object || !map_object)
		return -EACCES;
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;
		int rc;

		rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			u32 tsid;

			rc = selinux_bpf_projection_resolve(
				prog_object, crsec->state->label_domain, &tsid);
			if (rc)
				break;
			rc = avc_has_perm_snapshot(
				crsec->state, &chain->policy[i], crsec->sid, tsid,
				SECCLASS_BPF, BPF__PROG_RUN, NULL);
			if (rc)
				break;
			rc = selinux_bpf_projection_resolve(
				map_object, crsec->state->label_domain, &tsid);
			if (rc)
				break;
			rc = avc_has_perm_snapshot(
				crsec->state, &chain->policy[i], crsec->sid, tsid,
				SECCLASS_BPF, BPF__MAP_READ, NULL);
			if (rc)
				break;
		}
		if (rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain))
			continue;
		return rc;
	}
	return -ESTALE;
#else
	int rc;

	rc = selinux_bpf_prog(prog);
	if (rc)
		return rc;
	return cred_tsid_has_perm(
		current_cred(),
		selinux_bpf_map_security((struct bpf_map *)map)->sid,
		SECCLASS_BPF, BPF__MAP_READ, NULL);
#endif
}

#ifndef CONFIG_SECURITY_SELINUX_NS
static u32 selinux_bpffs_creator_sid(u32 fd)
{
	struct path path;
	struct super_block *sb;
	struct superblock_security_struct *sbsec;

	CLASS(fd, f)(fd);

	if (fd_empty(f))
		return SECSID_NULL;

	path = fd_file(f)->f_path;
	sb = path.dentry->d_sb;
	sbsec = selinux_superblock(sb);

	return sbsec->creator_sid;
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_bpf_object_create_namespaced(
	struct bpf_security_struct *bpfsec, struct bpf_token *token,
	u32 requested, const struct btf *related_btf,
	const struct bpf_map *related_map, fmode_t related_map_mode)
{
	struct selinux_pathless_build_scratch *scratch;
	struct selinux_pathless_projection *object = NULL;
	const struct selinux_pathless_projection *grantor = NULL;
	unsigned int retry;
	u32 sid = current_sid();
	int rc = -ESTALE;

	if (READ_ONCE(bpfsec->object) || READ_ONCE(bpfsec->grantor))
		return -EEXIST;
	if (token) {
		struct bpf_security_struct *toksec =
			selinux_bpf_token_security(token);

		if (!READ_ONCE(toksec->object))
			return -EACCES;
		grantor = READ_ONCE(toksec->grantor);
		if (!grantor)
			return -EACCES;
	}

	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		memset(scratch, 0, sizeof(*scratch));
		rc = selinux_policy_chain_snapshot_read(current_cred(),
						 &scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_pathless_chain_validate(scratch);
		if (rc)
			break;
		rc = selinux_bpf_projection_build(scratch, sid, true, &object);
		if (rc)
			goto next_retry;
		rc = selinux_bpf_create_has_perm(
			&scratch->chain, object, grantor, requested);
		if (rc)
			goto next_retry;
		if (related_btf || related_map) {
			u16 i;

			for (i = 0; i < scratch->chain.count; i++) {
				const struct cred_security_struct *crsec =
					selinux_cred(scratch->chain.cred[i]);
				const struct selinux_pathless_projection *projection;
				u32 tsid;

				if (related_map) {
					projection = READ_ONCE(selinux_bpf_map_security(
						(struct bpf_map *)related_map)->object);
					rc = selinux_bpf_projection_resolve(
						projection, crsec->state->label_domain,
						&tsid);
					if (rc)
						break;
					rc = avc_has_perm_snapshot(
						crsec->state, &scratch->chain.policy[i],
						crsec->sid, tsid, SECCLASS_BPF,
						bpf_map_fmode_to_av(related_map_mode),
						NULL);
					if (rc)
						break;
				}
				if (!selinux_policycap_bpf_object_perms(
					    &scratch->chain.policy[i]))
					continue;
				if (related_btf) {
					projection = READ_ONCE(selinux_bpf_btf_security(
						(struct btf *)related_btf)->object);
					rc = selinux_bpf_projection_resolve(
						projection, crsec->state->label_domain,
						&tsid);
					if (rc)
						break;
					rc = avc_has_perm_snapshot(
						crsec->state, &scratch->chain.policy[i],
						crsec->sid, tsid, SECCLASS_BPF,
						BPF__BTF_READ, NULL);
					if (rc)
						break;
				}
				if (related_map && related_map->btf &&
				    related_map->btf != related_btf) {
					projection = READ_ONCE(selinux_bpf_btf_security(
						related_map->btf)->object);
					rc = selinux_bpf_projection_resolve(
						projection, crsec->state->label_domain,
						&tsid);
					if (rc)
						break;
					rc = avc_has_perm_snapshot(
						crsec->state, &scratch->chain.policy[i],
						crsec->sid, tsid, SECCLASS_BPF,
						BPF__BTF_READ, NULL);
					if (rc)
						break;
				}
			}
			if (rc)
				goto next_retry;
		}
		if (!selinux_policy_chain_snapshot_valid(&scratch->chain)) {
			rc = -ESTALE;
			goto next_retry;
		}
		if (READ_ONCE(bpfsec->object) || READ_ONCE(bpfsec->grantor)) {
			rc = -EEXIST;
			goto next_retry;
		}

		bpfsec->sid = sid;
		if (grantor)
			WRITE_ONCE(bpfsec->grantor,
				   selinux_pathless_projection_get(
					   (struct selinux_pathless_projection *)grantor));
		WRITE_ONCE(bpfsec->object, object);
		object = NULL;
		rc = 0;
		break;

next_retry:
		selinux_pathless_projection_put(object);
		object = NULL;
		if (rc != -EAGAIN && rc != -ESTALE)
			break;
	}
	selinux_pathless_projection_put(object);
	kfree(scratch);
	return rc;
}
#endif

static int selinux_bpf_map_create(struct bpf_map *map, union bpf_attr *attr,
				  struct bpf_token *token, bool kernel)
{
	struct bpf_security_struct *bpfsec;
#ifndef CONFIG_SECURITY_SELINUX_NS
	u32 ssid;
#endif

	bpfsec = selinux_bpf_map_security(map);
#ifdef CONFIG_SECURITY_SELINUX_NS
	(void)kernel;
	if (map->inner_map_meta) {
		CLASS(fd, f)(attr->inner_map_fd);
		struct bpf_map *inner_map = __bpf_map_get(f);

		if (IS_ERR(inner_map))
			return PTR_ERR(inner_map);
		return selinux_bpf_object_create_namespaced(
			bpfsec, token, BPF__MAP_CREATE, map->btf, inner_map,
			fd_file(f)->f_mode);
	}
	return selinux_bpf_object_create_namespaced(
		bpfsec, token, BPF__MAP_CREATE, map->btf, NULL, 0);
#else
	bpfsec->sid = current_sid();

	if (!token)
		ssid = bpfsec->sid;
	else
		ssid = selinux_bpffs_creator_sid(attr->map_token_fd);
	bpfsec->grantor_sid = ssid;

	{
		int rc = cred_ssid_has_perm(current_cred(), ssid, bpfsec->sid,
					    SECCLASS_BPF, BPF__MAP_CREATE,
					    NULL);
		struct bpf_map *inner_map = NULL;

		if (!rc && map->inner_map_meta) {
			CLASS(fd, f)(attr->inner_map_fd);

			inner_map = __bpf_map_get(f);
			if (IS_ERR(inner_map))
				return PTR_ERR(inner_map);
			rc = selinux_bpf_map(inner_map, fd_file(f)->f_mode);
			if (!rc && inner_map->btf &&
			    selinux_policycap_enabled(
				    current_selinux_state,
				    POLICYDB_CAP_BPF_OBJECT_PERMS))
				rc = selinux_bpf_btf_cred(current_cred(),
							 inner_map->btf);
		}

		if (!rc && map->btf &&
		    selinux_policycap_enabled(current_selinux_state,
					      POLICYDB_CAP_BPF_OBJECT_PERMS))
			rc = selinux_bpf_btf_cred(current_cred(), map->btf);
		return rc;
	}
#endif
}

static int selinux_bpf_prog_load(struct bpf_prog *prog, union bpf_attr *attr,
				 struct bpf_token *token, bool kernel)
{
	struct bpf_security_struct *bpfsec;
#ifndef CONFIG_SECURITY_SELINUX_NS
	u32 ssid;
#endif

	bpfsec = selinux_bpf_prog_security(prog);
#ifdef CONFIG_SECURITY_SELINUX_NS
	(void)attr;
	(void)kernel;
	return selinux_bpf_object_create_namespaced(
		bpfsec, token, BPF__PROG_LOAD, NULL, NULL, 0);
#else
	bpfsec->sid = current_sid();

	if (!token)
		ssid = bpfsec->sid;
	else
		ssid = selinux_bpffs_creator_sid(attr->prog_token_fd);
	bpfsec->grantor_sid = ssid;

	return cred_ssid_has_perm(current_cred(), ssid, bpfsec->sid,
				SECCLASS_BPF, BPF__PROG_LOAD,
				NULL);
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_bpf_prog_commit(struct bpf_prog *prog)
{
	struct bpf_security_struct *bpfsec = selinux_bpf_prog_security(prog);
	const struct selinux_pathless_projection *prog_object =
		READ_ONCE(bpfsec->object);
	const struct selinux_pathless_projection *grantor =
		READ_ONCE(bpfsec->grantor);
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	unsigned int retry;

	if (!prog_object)
		return -EACCES;
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;
		int rc = 0;

		rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			u32 ssid = crsec->sid, tsid;
			u32 j;

			if (grantor && i == 0) {
				rc = selinux_bpf_projection_resolve(
					grantor, crsec->state->label_domain, &ssid);
				if (rc)
					break;
			}

			rc = selinux_bpf_projection_resolve(
				prog_object, crsec->state->label_domain, &tsid);
			if (rc)
				break;
			rc = avc_has_perm_snapshot(
				crsec->state, &chain->policy[i], ssid, tsid,
				SECCLASS_BPF, BPF__PROG_LOAD, NULL);
			if (rc)
				break;

			if (prog->aux->dst_prog) {
				const struct selinux_pathless_projection *projection =
					READ_ONCE(selinux_bpf_prog_security(
						prog->aux->dst_prog)->object);

				rc = selinux_bpf_projection_resolve(
					projection, crsec->state->label_domain, &tsid);
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &chain->policy[i], crsec->sid,
					tsid, SECCLASS_BPF, BPF__PROG_RUN, NULL);
				if (rc)
					break;
			}
			for (j = 0; j < prog->aux->used_map_cnt; j++) {
				struct bpf_map *map = prog->aux->used_maps[j];
				const struct selinux_pathless_projection *projection =
					READ_ONCE(selinux_bpf_map_security(map)->object);

				rc = selinux_bpf_projection_resolve(
					projection, crsec->state->label_domain, &tsid);
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &chain->policy[i], crsec->sid,
					tsid, SECCLASS_BPF,
					selinux_bpf_prog_map_av(map), NULL);
				if (rc)
					break;
			}
			if (rc)
				break;
			if (!selinux_policycap_bpf_object_perms(&chain->policy[i]))
				continue;

			if (prog->aux->btf) {
				const struct selinux_pathless_projection *projection =
					READ_ONCE(selinux_bpf_btf_security(
						prog->aux->btf)->object);

				rc = selinux_bpf_projection_resolve(
					projection, crsec->state->label_domain, &tsid);
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &chain->policy[i], crsec->sid,
					tsid, SECCLASS_BPF, BPF__BTF_READ, NULL);
				if (rc)
					break;
			}
			if (prog->aux->attach_btf) {
				const struct selinux_pathless_projection *projection =
					READ_ONCE(selinux_bpf_btf_security(
						prog->aux->attach_btf)->object);

				rc = selinux_bpf_projection_resolve(
					projection, crsec->state->label_domain, &tsid);
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &chain->policy[i], crsec->sid,
					tsid, SECCLASS_BPF, BPF__BTF_READ, NULL);
				if (rc)
					break;
			}
			for (j = 0; j < prog->aux->used_btf_cnt; j++) {
				struct btf *btf = prog->aux->used_btfs[j].btf;
				const struct selinux_pathless_projection *projection =
					READ_ONCE(selinux_bpf_btf_security(btf)->object);

				rc = selinux_bpf_projection_resolve(
					projection, crsec->state->label_domain, &tsid);
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &chain->policy[i], crsec->sid,
					tsid, SECCLASS_BPF, BPF__BTF_READ, NULL);
				if (rc)
					break;
			}
			if (rc)
				break;
		}
		if (rc == -ESTALE || !selinux_policy_chain_snapshot_valid(chain))
			continue;
		return rc;
	}
	return -ESTALE;
}
#else
static int selinux_bpf_prog_commit(struct bpf_prog *prog)
{
	u32 i;
	int rc;

	rc = cred_ssid_has_perm(
		current_cred(), selinux_bpf_prog_security(prog)->grantor_sid,
		selinux_bpf_prog_security(prog)->sid, SECCLASS_BPF,
		BPF__PROG_LOAD, NULL);
	if (rc)
		return rc;
	if (prog->aux->dst_prog) {
		rc = selinux_bpf_prog(prog->aux->dst_prog);
		if (rc)
			return rc;
	}
	for (i = 0; i < prog->aux->used_map_cnt; i++) {
		struct bpf_map *map = prog->aux->used_maps[i];

		rc = cred_tsid_has_perm(
			current_cred(), selinux_bpf_map_security(map)->sid,
			SECCLASS_BPF, selinux_bpf_prog_map_av(map), NULL);
		if (rc)
			return rc;
	}
	if (!selinux_policycap_enabled(current_selinux_state,
				       POLICYDB_CAP_BPF_OBJECT_PERMS))
		return 0;
	if (prog->aux->btf) {
		rc = selinux_bpf_btf_cred(current_cred(), prog->aux->btf);
		if (rc)
			return rc;
	}
	if (prog->aux->attach_btf) {
		rc = selinux_bpf_btf_cred(current_cred(),
					 prog->aux->attach_btf);
		if (rc)
			return rc;
	}
	for (i = 0; i < prog->aux->used_btf_cnt; i++) {
		rc = selinux_bpf_btf_cred(current_cred(),
					 prog->aux->used_btfs[i].btf);
		if (rc)
			return rc;
	}
	return 0;
}
#endif

#define bpf_token_cmd(T, C) \
	((T)->allowed_cmds & (1ULL << (C)))

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_bpf_token_create_namespaced(
	struct bpf_token *token, const struct path *path)
{
	struct bpf_security_struct *bpfsec = selinux_bpf_token_security(token);
	struct selinux_pathless_build_scratch *scratch;
	struct selinux_pathless_projection *object = NULL, *grantor = NULL;
	struct superblock_security_struct *sbsec;
	unsigned int retry;
	u32 creator_sid, perms, sid = current_sid();
	int rc = -ESTALE;

	if (!path || !path->mnt || !path->dentry)
		return -EINVAL;
	sbsec = selinux_superblock(path->dentry->d_sb);
	if (!sbsec)
		return -EACCES;
	creator_sid = READ_ONCE(sbsec->creator_sid);
	if (!creator_sid)
		return -EACCES;
	if (READ_ONCE(bpfsec->object) || READ_ONCE(bpfsec->grantor))
		return -EEXIST;

	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		memset(scratch, 0, sizeof(*scratch));
		perms = 0;
		rc = selinux_policy_chain_snapshot_read(current_cred(),
						 &scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_pathless_chain_validate(scratch);
		if (rc)
			break;
		rc = selinux_bpf_projection_build(scratch, sid, true, &object);
		if (rc)
			goto next_retry;
		rc = selinux_bpf_projection_build(
			scratch, creator_sid, false, &grantor);
		if (rc)
			goto next_retry;

		if (bpf_token_cmd(token, BPF_MAP_CREATE)) {
			rc = selinux_bpf_chain_target_has_perm(
				&scratch->chain, grantor, SECCLASS_BPF,
				BPF__MAP_CREATE_AS);
			if (rc)
				goto next_retry;
			perms |= BPF__MAP_CREATE;
		}
		if (bpf_token_cmd(token, BPF_PROG_LOAD)) {
			rc = selinux_bpf_chain_target_has_perm(
				&scratch->chain, grantor, SECCLASS_BPF,
				BPF__PROG_LOAD_AS);
			if (rc)
				goto next_retry;
			perms |= BPF__PROG_LOAD;
		}
		/* The BTF load hook performs the grantor check at object creation. */
		if (bpf_token_cmd(token, BPF_BTF_LOAD))
			perms |= BPF__BTF_LOAD;

		if (READ_ONCE(sbsec->creator_sid) != creator_sid ||
		    !selinux_policy_chain_snapshot_valid(&scratch->chain)) {
			rc = -ESTALE;
			goto next_retry;
		}
		if (READ_ONCE(bpfsec->object) || READ_ONCE(bpfsec->grantor)) {
			rc = -EEXIST;
			goto next_retry;
		}

		bpfsec->sid = sid;
		bpfsec->grantor_sid = creator_sid;
		bpfsec->perms = perms;
		WRITE_ONCE(bpfsec->object, object);
		WRITE_ONCE(bpfsec->grantor, grantor);
		object = NULL;
		grantor = NULL;
		rc = 0;
		break;

next_retry:
		selinux_pathless_projection_put(grantor);
		grantor = NULL;
		selinux_pathless_projection_put(object);
		object = NULL;
		if (rc != -EAGAIN && rc != -ESTALE)
			break;
	}
	selinux_pathless_projection_put(grantor);
	selinux_pathless_projection_put(object);
	kfree(scratch);
	return rc;
}
#endif

static int selinux_bpf_token_create(struct bpf_token *token,
				    union bpf_attr *attr,
				    const struct path *path)
{
#ifndef CONFIG_SECURITY_SELINUX_NS
	struct bpf_security_struct *bpfsec;
	u32 sid = selinux_bpffs_creator_sid(attr->token_create.bpffs_fd);
	int err;

	bpfsec = selinux_bpf_token_security(token);
#else
	(void)attr;
	return selinux_bpf_token_create_namespaced(token, path);
#endif
#ifndef CONFIG_SECURITY_SELINUX_NS
	bpfsec->sid = current_sid();
	bpfsec->grantor_sid = sid;

	bpfsec->perms = 0;
	/**
	 * 'token->allowed_cmds' is a bit mask of allowed commands
	 * Convert the BPF command enum to a bitmask representing its position
	 * in the allowed_cmds bitmap.
	 */
	if (bpf_token_cmd(token, BPF_MAP_CREATE)) {
		err = cred_ssid_has_perm(current_cred(), bpfsec->sid, sid,
					SECCLASS_BPF, BPF__MAP_CREATE_AS,
					NULL);
		if (err)
			return err;
		bpfsec->perms |= BPF__MAP_CREATE;
	}
	if (bpf_token_cmd(token, BPF_PROG_LOAD)) {
		err = cred_ssid_has_perm(current_cred(), bpfsec->sid, sid,
					SECCLASS_BPF, BPF__PROG_LOAD_AS, NULL);
		if (err)
			return err;
		bpfsec->perms |= BPF__PROG_LOAD;
	}
	if (bpf_token_cmd(token, BPF_BTF_LOAD))
		bpfsec->perms |= BPF__BTF_LOAD;

	return 0;
#endif
}

static int selinux_bpf_token_cmd(const struct bpf_token *token,
				 enum bpf_cmd cmd)
{
	struct bpf_security_struct *bpfsec;

	bpfsec = selinux_bpf_token_security((struct bpf_token *)token);
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!READ_ONCE(bpfsec->object) || !READ_ONCE(bpfsec->grantor))
		return -EACCES;
#endif
	switch (cmd) {
	case BPF_MAP_CREATE:
		if (!(bpfsec->perms & BPF__MAP_CREATE))
			return -EACCES;
		break;
	case BPF_PROG_LOAD:
		if (!(bpfsec->perms & BPF__PROG_LOAD))
			return -EACCES;
		break;
	case BPF_BTF_LOAD:
		if (!(bpfsec->perms & BPF__BTF_LOAD))
			return -EACCES;
		break;
	default:
		break;
	}

	return 0;
}

static int selinux_bpf_token_capable(const struct bpf_token *token, int cap)
{
	u16 sclass;
	struct bpf_security_struct *bpfsec =
		selinux_bpf_token_security((struct bpf_token *)token);
	bool initns = (token->userns == &init_user_ns);
	u32 av = CAP_TO_MASK(cap);

	switch (CAP_TO_INDEX(cap)) {
	case 0:
		sclass = initns ? SECCLASS_CAPABILITY : SECCLASS_CAP_USERNS;
		break;
	case 1:
		sclass = initns ? SECCLASS_CAPABILITY2 : SECCLASS_CAP2_USERNS;
		break;
	default:
		pr_err("SELinux:  out of range capability %d\n", cap);
		return -EINVAL;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_bpf_projection_has_perm(
		current_cred(), READ_ONCE(bpfsec->grantor), sclass, av);
#else
	return cred_tsid_has_perm(current_cred(), bpfsec->grantor_sid, sclass,
				av, NULL);
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static void selinux_bpf_security_release(struct bpf_security_struct *bpfsec);
#endif

static u32 selinux_bpf_link_cmd_perm(enum bpf_cmd cmd)
{
	switch (cmd) {
	case BPF_OBJ_GET:
	case BPF_OBJ_GET_INFO_BY_FD:
	case BPF_TASK_FD_QUERY:
	case BPF_LINK_GET_FD_BY_ID:
		return BPF__LINK_READ;
	case BPF_OBJ_PIN:
		return BPF__LINK_PIN;
	case BPF_LINK_DETACH:
		return BPF__LINK_DETACH;
	case BPF_LINK_UPDATE:
		return BPF__LINK_UPDATE;
	default:
		return 0;
	}
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_bpf_link_create(struct bpf_link *link,
				   const struct bpf_prog *related_prog,
				   const struct bpf_map *related_map)
{
	struct bpf_security_struct *bpfsec = selinux_bpf_link_security(link);
	struct selinux_pathless_build_scratch *scratch;
	struct selinux_pathless_projection *object = NULL;
	const struct selinux_pathless_projection *prog_object = NULL;
	const struct selinux_pathless_projection *related_prog_object = NULL;
	const struct selinux_pathless_projection *related_map_object = NULL;
	unsigned int retry;
	u32 sid = current_sid();
	int rc = -ESTALE;

	if (READ_ONCE(bpfsec->object))
		return -EEXIST;
	if (link->prog)
		prog_object = READ_ONCE(
			selinux_bpf_prog_security(link->prog)->object);
	if (link->prog && !prog_object)
		return -EACCES;
	if (related_prog)
		related_prog_object = READ_ONCE(selinux_bpf_prog_security(
			(struct bpf_prog *)related_prog)->object);
	if (related_map)
		related_map_object = READ_ONCE(selinux_bpf_map_security(
			(struct bpf_map *)related_map)->object);
	if ((related_prog && !related_prog_object) ||
	    (related_map && !related_map_object))
		return -EACCES;
	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;

		memset(scratch, 0, sizeof(*scratch));
		rc = selinux_policy_chain_snapshot_read(current_cred(),
						 &scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_pathless_chain_validate(scratch);
		if (rc)
			break;
		rc = selinux_bpf_projection_build(scratch, sid, true, &object);
		if (rc)
			goto next_retry;

		for (i = 0; i < scratch->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(scratch->chain.cred[i]);
			u32 tsid;

			if (selinux_policycap_bpf_object_perms(
				    &scratch->chain.policy[i])) {
				rc = selinux_bpf_projection_resolve(
					object, crsec->state->label_domain, &tsid);
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &scratch->chain.policy[i],
					crsec->sid, tsid, SECCLASS_BPF,
					BPF__LINK_CREATE, NULL);
				if (rc)
					break;
			}
			if (prog_object) {
				rc = selinux_bpf_projection_resolve(
					prog_object, crsec->state->label_domain, &tsid);
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &scratch->chain.policy[i],
					crsec->sid, tsid, SECCLASS_BPF,
					BPF__PROG_RUN, NULL);
				if (rc)
					break;
			}
			if (related_prog_object) {
				rc = selinux_bpf_projection_resolve(
					related_prog_object,
					crsec->state->label_domain, &tsid);
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &scratch->chain.policy[i],
					crsec->sid, tsid, SECCLASS_BPF,
					BPF__PROG_RUN, NULL);
				if (rc)
					break;
			}
			if (related_map_object) {
				rc = selinux_bpf_projection_resolve(
					related_map_object,
					crsec->state->label_domain, &tsid);
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &scratch->chain.policy[i],
					crsec->sid, tsid, SECCLASS_BPF,
					BPF__MAP_READ, NULL);
				if (rc)
					break;
			}
		}
		if (rc)
			goto next_retry;
		if (!selinux_policy_chain_snapshot_valid(&scratch->chain)) {
			rc = -ESTALE;
			goto next_retry;
		}
		bpfsec->sid = sid;
		WRITE_ONCE(bpfsec->object, object);
		object = NULL;
		rc = 0;
		break;

next_retry:
		selinux_pathless_projection_put(object);
		object = NULL;
		if (rc != -EAGAIN && rc != -ESTALE)
			break;
	}
	selinux_pathless_projection_put(object);
	kfree(scratch);
	return rc;
}

static int selinux_bpf_link_access_cred(const struct cred *cred,
					struct bpf_link *link, enum bpf_cmd cmd)
{
	struct bpf_security_struct *bpfsec = selinux_bpf_link_security(link);
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	u32 requested = selinux_bpf_link_cmd_perm(cmd);
	unsigned int retry;

	if (!requested || !READ_ONCE(bpfsec->object))
		return -EOPNOTSUPP;
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;
		int rc = 0;

		rc = selinux_policy_chain_snapshot_read(cred, chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			u32 tsid;

			if (!selinux_policycap_bpf_object_perms(&chain->policy[i]))
				continue;
			rc = selinux_bpf_projection_resolve(
				READ_ONCE(bpfsec->object),
				crsec->state->label_domain, &tsid);
			if (rc)
				break;
			rc = avc_has_perm_snapshot(
				crsec->state, &chain->policy[i], crsec->sid, tsid,
				SECCLASS_BPF, requested, NULL);
			if (rc)
				break;
		}
		if (rc == -ESTALE || !selinux_policy_chain_snapshot_valid(chain))
			continue;
		return rc;
	}
	return -ESTALE;
}

static int selinux_bpf_link_access(struct bpf_link *link,
					    enum bpf_cmd cmd)
{
	return selinux_bpf_link_access_cred(current_cred(), link, cmd);
}

static int selinux_bpf_link_update(struct bpf_link *link,
				   const struct bpf_prog *new_prog,
				   const struct bpf_prog *old_prog,
				   const struct bpf_map *new_map,
				   const struct bpf_map *old_map)
{
	const struct selinux_pathless_projection *link_object = READ_ONCE(
		selinux_bpf_link_security(link)->object);
	const struct selinux_pathless_projection *new_object = NULL;
	const struct selinux_pathless_projection *old_object = NULL;
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	u32 object_perm;
	unsigned int retry;

	if (!link_object)
		return -EACCES;
	if (new_prog) {
		new_object = READ_ONCE(selinux_bpf_prog_security(
			(struct bpf_prog *)new_prog)->object);
		object_perm = BPF__PROG_RUN;
	} else if (new_map) {
		new_object = READ_ONCE(selinux_bpf_map_security(
			(struct bpf_map *)new_map)->object);
		object_perm = BPF__MAP_READ;
	} else {
		return -EINVAL;
	}
	if (old_prog)
		old_object = READ_ONCE(selinux_bpf_prog_security(
			(struct bpf_prog *)old_prog)->object);
	else if (old_map)
		old_object = READ_ONCE(selinux_bpf_map_security(
			(struct bpf_map *)old_map)->object);
	if (!new_object || ((old_prog || old_map) && !old_object))
		return -EACCES;
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;

	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;
		int rc = 0;

		rc = selinux_policy_chain_snapshot_read(current_cred(), chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			u32 tsid;

			if (selinux_policycap_bpf_object_perms(&chain->policy[i])) {
				rc = selinux_bpf_projection_resolve(
					link_object, crsec->state->label_domain, &tsid);
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &chain->policy[i], crsec->sid,
					tsid, SECCLASS_BPF, BPF__LINK_UPDATE, NULL);
				if (rc)
					break;
			}
			rc = selinux_bpf_projection_resolve(
				new_object, crsec->state->label_domain, &tsid);
			if (rc)
				break;
			rc = avc_has_perm_snapshot(
				crsec->state, &chain->policy[i], crsec->sid, tsid,
				SECCLASS_BPF, object_perm, NULL);
			if (rc)
				break;
			if (old_object) {
				rc = selinux_bpf_projection_resolve(
					old_object, crsec->state->label_domain, &tsid);
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &chain->policy[i], crsec->sid,
					tsid, SECCLASS_BPF, object_perm, NULL);
				if (rc)
					break;
			}
		}
		if (rc == -ESTALE || !selinux_policy_chain_snapshot_valid(chain))
			continue;
		return rc;
	}
	return -ESTALE;
}

static void selinux_bpf_link_free(struct bpf_link *link)
{
	if (!link->security)
		return;
	selinux_bpf_security_release(selinux_bpf_link_security(link));
}

static int selinux_bpf_btf_load(struct btf *btf,
				const union bpf_attr *attr,
				struct bpf_token *token,
				enum bpf_btf_origin origin)
{
	struct bpf_security_struct *bpfsec = selinux_bpf_btf_security(btf);
	struct selinux_pathless_build_scratch *scratch;
	struct selinux_pathless_projection *object = NULL;
	const struct selinux_pathless_projection *grantor = NULL;
	bool kernel_origin = origin != BPF_BTF_ORIGIN_USER;
	unsigned int retry;
	u32 sid = kernel_origin ? SECINITSID_KERNEL : current_sid();
	int rc = -ESTALE;

	(void)attr;
	if (token) {
		struct bpf_security_struct *toksec =
			selinux_bpf_token_security(token);

		grantor = READ_ONCE(toksec->grantor);
		if (!grantor)
			return -EACCES;
	}
	scratch = kzalloc_obj(*scratch, GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;

		memset(scratch, 0, sizeof(*scratch));
		rc = selinux_policy_chain_snapshot_read(current_cred(),
						 &scratch->chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			break;
		rc = selinux_pathless_chain_validate(scratch);
		if (rc)
			break;
		rc = selinux_bpf_projection_build(
			scratch, sid, !kernel_origin, &object);
		if (rc)
			goto next_retry;
		for (i = 0; i < scratch->chain.count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(scratch->chain.cred[i]);
			u32 ssid = crsec->sid, tsid;

			if (!selinux_policycap_bpf_object_perms(
				    &scratch->chain.policy[i]))
				continue;
			if (grantor && i == 0) {
				rc = selinux_bpf_projection_resolve(
					grantor, crsec->state->label_domain, &ssid);
				if (rc)
					break;
			}
			rc = selinux_bpf_projection_resolve(
				object, crsec->state->label_domain, &tsid);
			if (rc)
				break;
			rc = avc_has_perm_snapshot(
				crsec->state, &scratch->chain.policy[i], ssid, tsid,
				SECCLASS_BPF, BPF__BTF_LOAD, NULL);
			if (rc)
				break;
		}
		if (rc)
			goto next_retry;
		if (!selinux_policy_chain_snapshot_valid(&scratch->chain)) {
			rc = -ESTALE;
			goto next_retry;
		}
		bpfsec->sid = sid;
		WRITE_ONCE(bpfsec->object, object);
		object = NULL;
		rc = 0;
		break;
next_retry:
		selinux_pathless_projection_put(object);
		object = NULL;
		if (rc != -EAGAIN && rc != -ESTALE)
			break;
	}
	selinux_pathless_projection_put(object);
	kfree(scratch);
	return rc;
}

static int selinux_bpf_btf_cred(const struct cred *cred,
				const struct btf *btf)
{
	struct bpf_security_struct *bpfsec =
		selinux_bpf_btf_security((struct btf *)btf);
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	unsigned int retry;

	if (!READ_ONCE(bpfsec->object))
		return -EACCES;
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i;
		int rc = 0;

		rc = selinux_policy_chain_snapshot_read(cred, chain);
		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		for (i = 0; i < chain->count; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);
			u32 tsid;

			if (!selinux_policycap_bpf_object_perms(&chain->policy[i]))
				continue;
			rc = selinux_bpf_projection_resolve(
				READ_ONCE(bpfsec->object),
				crsec->state->label_domain, &tsid);
			if (rc)
				break;
			rc = avc_has_perm_snapshot(
				crsec->state, &chain->policy[i], crsec->sid, tsid,
				SECCLASS_BPF, BPF__BTF_READ, NULL);
			if (rc)
				break;
		}
		if (rc == -ESTALE || !selinux_policy_chain_snapshot_valid(chain))
			continue;
		return rc;
	}
	return -ESTALE;
}

static int selinux_bpf_btf(const struct btf *btf)
{
	return selinux_bpf_btf_cred(current_cred(), btf);
}

static void selinux_bpf_btf_free(struct btf *btf)
{
	if (!btf_security(btf))
		return;
	selinux_bpf_security_release(selinux_bpf_btf_security(btf));
}
#else
static int selinux_bpf_link_create(struct bpf_link *link,
				   const struct bpf_prog *related_prog,
				   const struct bpf_map *related_map)
{
	struct bpf_security_struct *bpfsec = selinux_bpf_link_security(link);
	int rc = 0;

	bpfsec->sid = current_sid();
	if (selinux_policycap_enabled(current_selinux_state,
				     POLICYDB_CAP_BPF_OBJECT_PERMS))
		rc = cred_tsid_has_perm(current_cred(), bpfsec->sid,
					SECCLASS_BPF, BPF__LINK_CREATE, NULL);
	if (!rc && link->prog)
		rc = selinux_bpf_prog(link->prog);
	if (!rc && related_prog)
		rc = selinux_bpf_prog((struct bpf_prog *)related_prog);
	if (!rc && related_map)
		rc = cred_tsid_has_perm(
			current_cred(),
			selinux_bpf_map_security((struct bpf_map *)related_map)->sid,
			SECCLASS_BPF, BPF__MAP_READ, NULL);
	return rc;
}

static int selinux_bpf_link_access_cred(const struct cred *cred,
					struct bpf_link *link, enum bpf_cmd cmd)
{
	u32 requested = selinux_bpf_link_cmd_perm(cmd);

	if (!requested)
		return -EOPNOTSUPP;
	if (!selinux_policycap_enabled(current_selinux_state,
				      POLICYDB_CAP_BPF_OBJECT_PERMS))
		return 0;
	return cred_tsid_has_perm(cred,
				selinux_bpf_link_security(link)->sid,
				SECCLASS_BPF, requested, NULL);
}

static int selinux_bpf_link_access(struct bpf_link *link,
					    enum bpf_cmd cmd)
{
	return selinux_bpf_link_access_cred(current_cred(), link, cmd);
}

static int selinux_bpf_link_update(struct bpf_link *link,
				   const struct bpf_prog *new_prog,
				   const struct bpf_prog *old_prog,
				   const struct bpf_map *new_map,
				   const struct bpf_map *old_map)
{
	int rc;

	rc = selinux_bpf_link_access_cred(current_cred(), link,
					  BPF_LINK_UPDATE);
	if (rc)
		return rc;
	if (new_prog) {
		rc = cred_tsid_has_perm(
			current_cred(),
			selinux_bpf_prog_security((struct bpf_prog *)new_prog)->sid,
			SECCLASS_BPF, BPF__PROG_RUN, NULL);
		if (!rc && old_prog)
			rc = cred_tsid_has_perm(
				current_cred(),
				selinux_bpf_prog_security(
					(struct bpf_prog *)old_prog)->sid,
				SECCLASS_BPF, BPF__PROG_RUN, NULL);
	} else if (new_map) {
		rc = cred_tsid_has_perm(
			current_cred(),
			selinux_bpf_map_security((struct bpf_map *)new_map)->sid,
			SECCLASS_BPF, BPF__MAP_READ, NULL);
		if (!rc && old_map)
			rc = cred_tsid_has_perm(
				current_cred(),
				selinux_bpf_map_security(
					(struct bpf_map *)old_map)->sid,
				SECCLASS_BPF, BPF__MAP_READ, NULL);
	} else {
		rc = -EINVAL;
	}
	return rc;
}

static void selinux_bpf_link_free(struct bpf_link *link)
{
}

static int selinux_bpf_btf_load(struct btf *btf,
				const union bpf_attr *attr,
				struct bpf_token *token,
				enum bpf_btf_origin origin)
{
	struct bpf_security_struct *bpfsec = selinux_bpf_btf_security(btf);
	u32 ssid;

	(void)attr;
	bpfsec->sid = origin == BPF_BTF_ORIGIN_USER ? current_sid() :
			SECINITSID_KERNEL;
	if (!selinux_policycap_enabled(current_selinux_state,
				      POLICYDB_CAP_BPF_OBJECT_PERMS))
		return 0;
	ssid = token ? selinux_bpf_token_security(token)->grantor_sid :
			current_sid();
	return cred_ssid_has_perm(current_cred(), ssid, bpfsec->sid,
				 SECCLASS_BPF, BPF__BTF_LOAD, NULL);
}

static int selinux_bpf_btf_cred(const struct cred *cred,
				const struct btf *btf)
{
	if (!selinux_policycap_enabled(current_selinux_state,
				      POLICYDB_CAP_BPF_OBJECT_PERMS))
		return 0;
	return cred_tsid_has_perm(
		cred,
		selinux_bpf_btf_security((struct btf *)btf)->sid,
		SECCLASS_BPF, BPF__BTF_READ, NULL);
}

static int selinux_bpf_btf(const struct btf *btf)
{
	return selinux_bpf_btf_cred(current_cred(), btf);
}

static void selinux_bpf_btf_free(struct btf *btf)
{
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
static void selinux_bpf_security_release(struct bpf_security_struct *bpfsec)
{
	struct selinux_pathless_projection *object, *grantor;

	object = xchg(&bpfsec->object, NULL);
	grantor = xchg(&bpfsec->grantor, NULL);
	selinux_pathless_projection_put(grantor);
	selinux_pathless_projection_put(object);
}

static void selinux_bpf_map_free(struct bpf_map *map)
{
	/* security_bpf_map_free() can be reached twice on a hook error. */
	if (!map->security)
		return;
	selinux_bpf_security_release(selinux_bpf_map_security(map));
}

static void selinux_bpf_prog_free(struct bpf_prog *prog)
{
	if (!prog->aux->security)
		return;
	selinux_bpf_security_release(selinux_bpf_prog_security(prog));
}

static void selinux_bpf_token_free(struct bpf_token *token)
{
	if (!token->security)
		return;
	selinux_bpf_security_release(selinux_bpf_token_security(token));
}
#endif
#endif

#ifdef CONFIG_PERF_EVENTS
#ifdef CONFIG_SECURITY_SELINUX_NS
static int perf_fd_pass_add(
	const struct file *file, const struct cred *cred,
	struct selinux_file_transfer_transaction *transaction)
{
	const struct perf_event *event = perf_get_event((struct file *)file);
	const struct selinux_avc_provenance *provenance;
	struct selinux_pathless_chain_resolution *line =
		&transaction->perf_line;
	struct perf_event_security_struct *perfsec;
	u32 requested = 0;
	u16 i;
	int rc;

	if (IS_ERR(event))
		return 0;
	if (!transaction->chain.count || transaction->chain.cred[0] != cred)
		return -EXDEV;
	perfsec = selinux_perf_event(event->security);
	if (!perfsec->projection ||
	    perfsec->projection->kind != SELINUX_PATHLESS_KIND_PERF_EVENT)
		return -EACCES;
	if (file->f_mode & FMODE_READ)
		requested |= PERF_EVENT__READ;
	if (file->f_mode & FMODE_WRITE)
		requested |= PERF_EVENT__WRITE;
	if (!requested)
		return 0;
	rc = selinux_pathless_projection_resolve_cred_chain(
		perfsec->projection, transaction->chain.cred,
		transaction->chain.policy, transaction->chain.count, line);
	if (rc)
		return rc;
	rc = selinux_file_transfer_transaction_provenance(
		transaction, perfsec->projection->label, perfsec->projection->view,
		perfsec->projection->source, &provenance);
	if (rc)
		goto out;
	for (i = 0; i < transaction->chain.count; i++) {
		const struct cred_security_struct *crsec =
			selinux_cred(transaction->chain.cred[i]);
		struct selinux_pathless_resolution resolved;
		struct selinux_avc_provenance level_provenance = *provenance;

		resolved = line->level[crsec->state->label_domain->depth];
		if (resolved.sclass != SECCLASS_PERF_EVENT)
			goto unsupported;
		level_provenance.map_generation = resolved.map_generation;
		rc = selinux_file_transfer_transaction_add(
			transaction,
			&(struct selinux_avc_level) {
				.state = crsec->state,
				.ssid = crsec->sid,
				.tsid = resolved.sid,
				.tclass = SECCLASS_PERF_EVENT,
				.requested = requested,
				.provenance = &level_provenance,
			}, &transaction->chain.policy[i]);
		if (rc)
			goto out;
	}
	rc = 0;
	goto out;
unsupported:
	rc = -EOPNOTSUPP;
out:
	return rc;
}

#endif

static int selinux_perf_event_open(int type)
{
	u32 requested;

	if (type == PERF_SECURITY_OPEN)
		requested = PERF_EVENT__OPEN;
	else if (type == PERF_SECURITY_CPU)
		requested = PERF_EVENT__CPU;
	else if (type == PERF_SECURITY_KERNEL)
		requested = PERF_EVENT__KERNEL;
	else if (type == PERF_SECURITY_TRACEPOINT)
		requested = PERF_EVENT__TRACEPOINT;
	else
		return -EINVAL;

	return cred_self_has_perm(current_cred(), SECCLASS_PERF_EVENT,
				  requested, NULL);
}

static int selinux_perf_event_alloc(struct perf_event *event)
{
	struct perf_event_security_struct *perfsec;

	perfsec = selinux_perf_event(event->security);
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (event->parent) {
		struct perf_event_security_struct *parentsec =
			selinux_perf_event(event->parent->security);
		struct selinux_pathless_projection *projection;
		const struct cred *cred = current_cred();

		projection = selinux_pathless_projection_get(
			parentsec->projection);
		if (!projection)
			return -EACCES;
		while (cred) {
			const struct cred_security_struct *crsec =
				selinux_cred(cred);
			struct selinux_pathless_resolution resolved;
			int rc;

			rc = selinux_pathless_projection_resolve_sealed(
				projection, crsec->state->label_domain, &resolved);
			if (rc || resolved.sclass != SECCLASS_PERF_EVENT) {
				selinux_pathless_projection_put(projection);
				return rc ? rc : -EOPNOTSUPP;
			}
			cred = crsec->parent_cred;
		}
		perfsec->sid = parentsec->sid;
		perfsec->projection = projection;
		return 0;
	}
	return selinux_creator_projection_build(
		current_cred(), SELINUX_PATHLESS_KIND_PERF_EVENT,
		SECCLASS_PERF_EVENT, false, 0, NULL, NULL, &perfsec->sid,
		&perfsec->projection);
#else
	perfsec->sid = current_sid();

	return 0;
#endif
}

static void selinux_perf_event_free(struct perf_event *event)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct perf_event_security_struct *perfsec;

	if (!event->security)
		return;
	perfsec = selinux_perf_event(event->security);
	selinux_pathless_projection_put(perfsec->projection);
	perfsec->projection = NULL;
#endif
}

static int selinux_perf_event_read(struct perf_event *event)
{
	struct perf_event_security_struct *perfsec =
		selinux_perf_event(event->security);

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!perfsec->projection ||
	    perfsec->projection->kind != SELINUX_PATHLESS_KIND_PERF_EVENT)
		return -EACCES;
	return cred_pathless_has_perm(current_cred(), perfsec->projection,
				      PERF_EVENT__READ, NULL);
#else
	return cred_tsid_has_perm(current_cred(), perfsec->sid,
				  SECCLASS_PERF_EVENT, PERF_EVENT__READ, NULL);
#endif
}

static int selinux_perf_event_write(struct perf_event *event)
{
	struct perf_event_security_struct *perfsec =
		selinux_perf_event(event->security);

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!perfsec->projection ||
	    perfsec->projection->kind != SELINUX_PATHLESS_KIND_PERF_EVENT)
		return -EACCES;
	return cred_pathless_has_perm(current_cred(), perfsec->projection,
				      PERF_EVENT__WRITE, NULL);
#else
	return cred_tsid_has_perm(current_cred(), perfsec->sid,
				  SECCLASS_PERF_EVENT, PERF_EVENT__WRITE, NULL);
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static u32 selinux_perf_relation_requested(unsigned int access)
{
	u32 requested = 0;

	if (access & PERF_SECURITY_RELATION_READ)
		requested |= PERF_EVENT__READ;
	if (access & PERF_SECURITY_RELATION_WRITE)
		requested |= PERF_EVENT__WRITE;
	return requested;
}

static int selinux_perf_relation_decide(
	const struct perf_event_relation_security_struct *relation,
	u64 *epochp)
{
	struct selinux_policy_chain_snapshot *chain __free(kfree) = NULL;
	unsigned int retry;

	if (!relation->cred || !relation->component_count ||
	    relation->component_count > SELINUX_PERF_RELATION_MAX_COMPONENTS)
		return -EACCES;
	chain = kzalloc_obj(*chain, GFP_KERNEL);
	if (!chain)
		return -ENOMEM;
	for (retry = 0; retry < SELINUX_POLICY_OPERATION_RETRIES; retry++) {
		u16 i, j;
		int rc = selinux_policy_chain_snapshot_read(relation->cred, chain);

		if (rc == -EAGAIN || rc == -ESTALE)
			continue;
		if (rc)
			return rc;
		for (i = 0; i < chain->count && !rc; i++) {
			const struct cred_security_struct *crsec =
				selinux_cred(chain->cred[i]);

			for (j = 0; j < relation->component_count; j++) {
				const struct perf_event_relation_component *component =
					&relation->component[j];
				u32 tsid;

				if (!component->projection || !component->requested ||
				    !component->sclass) {
					rc = -EACCES;
					break;
				}
				if (component->sclass == SECCLASS_BPF) {
#ifdef CONFIG_BPF_SYSCALL
					rc = selinux_bpf_projection_resolve(
						component->projection,
						crsec->state->label_domain, &tsid);
#else
					rc = -EOPNOTSUPP;
#endif
				} else {
					struct selinux_pathless_resolution resolved;

					rc = selinux_pathless_projection_resolve_sealed(
						component->projection,
						crsec->state->label_domain, &resolved);
					if (!rc && resolved.sclass != component->sclass)
						rc = -EOPNOTSUPP;
					tsid = resolved.sid;
				}
				if (rc)
					break;
				rc = avc_has_perm_snapshot(
					crsec->state, &chain->policy[i], crsec->sid,
					tsid, component->sclass,
					component->requested, NULL);
				if (rc)
					break;
			}
		}
		if (rc == -EAGAIN || rc == -ESTALE ||
		    !selinux_policy_chain_snapshot_valid(chain))
			continue;
		if (rc)
			return rc;
		if (!chain->count || !chain->policy[0].chain_epoch)
			return -ESTALE;
		*epochp = chain->policy[0].chain_epoch;
		return rc;
	}
	return -ESTALE;
}

static int selinux_perf_relation_add(
	struct perf_event_relation_security_struct *relation,
	struct selinux_pathless_projection *projection, u16 sclass, u32 requested)
{
	struct perf_event_relation_component *component;

	if (!projection || !sclass || !requested)
		return -EACCES;
	if (relation->component_count >= SELINUX_PERF_RELATION_MAX_COMPONENTS)
		return -E2BIG;
	component = &relation->component[relation->component_count];
	component->projection = selinux_pathless_projection_get(projection);
	if (!component->projection)
		return -EACCES;
	component->sclass = sclass;
	component->requested = requested;
	relation->component_count++;
	return 0;
}
#endif

static int selinux_perf_event_relation(struct perf_event *event,
				       unsigned int access,
				       struct perf_event *related_event,
				       unsigned int related_access,
				       const struct bpf_prog *prog,
				       const struct bpf_map *map,
				       fmode_t map_fmode,
				       struct perf_event_relation *carrier)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct perf_event_security_struct *perfsec =
		selinux_perf_event(event->security);
	struct perf_event_relation_security_struct *relation;
	u32 requested;
	u64 epoch = 0;
	int rc;

	if (!access || access & ~(PERF_SECURITY_RELATION_READ |
				 PERF_SECURITY_RELATION_WRITE))
		return -EINVAL;
	if (!perfsec->projection ||
	    perfsec->projection->kind != SELINUX_PATHLESS_KIND_PERF_EVENT)
		return -EACCES;
	requested = selinux_perf_relation_requested(access);
	if (!carrier)
		return cred_pathless_has_perm(
			current_cred(), perfsec->projection, requested, NULL);

	relation = selinux_perf_relation(carrier);
	if (relation->cred || relation->component_count)
		return -EEXIST;
	relation->cred = get_cred(current_cred());
	rc = selinux_perf_relation_add(relation, perfsec->projection,
				       SECCLASS_PERF_EVENT, requested);
	if (rc)
		return rc;
	if (related_event) {
		struct perf_event_security_struct *related =
			selinux_perf_event(related_event->security);

		if (!related_access ||
		    related_access & ~(PERF_SECURITY_RELATION_READ |
				       PERF_SECURITY_RELATION_WRITE))
			return -EINVAL;
		rc = selinux_perf_relation_add(
			relation, related->projection, SECCLASS_PERF_EVENT,
			selinux_perf_relation_requested(related_access));
		if (rc)
			return rc;
	}
#ifdef CONFIG_BPF_SYSCALL
	if (prog) {
		struct bpf_security_struct *bpfsec = selinux_bpf_prog_security(
			(struct bpf_prog *)prog);

		rc = selinux_perf_relation_add(
			relation, READ_ONCE(bpfsec->object), SECCLASS_BPF,
			BPF__PROG_RUN);
		if (rc)
			return rc;
	}
	if (map) {
		struct bpf_security_struct *bpfsec = selinux_bpf_map_security(
			(struct bpf_map *)map);
		u32 map_requested = bpf_map_fmode_to_av(map_fmode);

		if (!map_requested)
			return -EINVAL;
		rc = selinux_perf_relation_add(
			relation, READ_ONCE(bpfsec->object), SECCLASS_BPF,
			map_requested);
		if (rc)
			return rc;
	}
#else
	if (prog || map || map_fmode)
		return -EOPNOTSUPP;
#endif
	rc = selinux_perf_relation_decide(relation, &epoch);
	if (rc)
		return rc;
	WRITE_ONCE(relation->result, 0);
	/* Publish the initialized identity/result before its valid epoch. */
	smp_store_release(&relation->chain_epoch, epoch);
	return 0;
#else
	(void)event;
	(void)access;
	(void)related_event;
	(void)related_access;
	(void)prog;
	(void)map;
	(void)map_fmode;
	(void)carrier;
	return 0;
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static void selinux_perf_event_relation_free(
	struct perf_event_relation *carrier)
{
	struct perf_event_relation_security_struct *relation =
		selinux_perf_relation(carrier);
	const struct cred *cred;
	u8 i;

	for (i = 0; i < relation->component_count; i++) {
		struct selinux_pathless_projection *projection =
			xchg(&relation->component[i].projection, NULL);

		selinux_pathless_projection_put(projection);
	}
	relation->component_count = 0;
	cred = xchg(&relation->cred, NULL);
	/* Make the carrier invalid before releasing its owned identity. */
	smp_store_release(&relation->chain_epoch, 0);
	put_cred(cred);
}

static int selinux_perf_event_relation_valid(
	const struct perf_event_relation *carrier)
{
	const struct perf_event_relation_security_struct *relation =
		selinux_perf_relation(carrier);
	struct selinux_state *state;
	/* Pair with create/revalidation publication of identity and result. */
	u64 epoch = smp_load_acquire(&relation->chain_epoch);

	if (!epoch || !relation->cred || !relation->component_count ||
	    relation->component_count > SELINUX_PERF_RELATION_MAX_COMPONENTS)
		return -EACCES;
	state = cred_selinux_state(relation->cred);
	if (!state)
		return -EACCES;
	if (epoch != selinux_chain_epoch_read(state))
		return -ESTALE;
	return READ_ONCE(relation->result);
}

static int selinux_perf_event_relation_revalidate(
	struct perf_event_relation *carrier)
{
	struct perf_event_relation_security_struct *relation =
		selinux_perf_relation(carrier);
	u64 epoch = 0;
	int rc;

	rc = selinux_perf_relation_decide(relation, &epoch);
	if (!epoch)
		/* Keep the stale epoch so the next use retries asynchronously. */
		return rc;
	WRITE_ONCE(relation->result, rc);
	/* Publish the decision before the epoch which accepts that decision. */
	smp_store_release(&relation->chain_epoch, epoch);
	return rc;
}
#endif
#endif

#ifdef CONFIG_IO_URING
/**
 * selinux_uring_override_creds - check the requested cred override
 * @new: the target creds
 *
 * Check to see if the current task is allowed to override it's credentials
 * to service an io_uring operation.
 */
static int selinux_uring_override_creds(const struct cred *new)
{
	return cred_other_has_perm(current_cred(), new, SECCLASS_IO_URING,
				   IO_URING__OVERRIDE_CREDS, NULL);
}

/**
 * selinux_uring_sqpoll - check if a io_uring polling thread can be created
 *
 * Check to see if the current task is allowed to create a new io_uring
 * kernel polling thread.
 */
static int selinux_uring_sqpoll(void)
{
	return cred_self_has_perm(current_cred(), SECCLASS_IO_URING,
				  IO_URING__SQPOLL, NULL);
}

/**
 * selinux_uring_cmd - check if IORING_OP_URING_CMD is allowed
 * @ioucmd: the io_uring command structure
 *
 * Check to see if the current domain is allowed to execute an
 * IORING_OP_URING_CMD against the device/file specified in @ioucmd.
 *
 */
static int selinux_uring_cmd(struct io_uring_cmd *ioucmd)
{
	struct file *file = ioucmd->file;
	struct inode *inode = file_inode(file);
	struct common_audit_data ad;
#ifdef CONFIG_SECURITY_SELINUX_NS
	const struct file_security_struct *fsec = selinux_file(file);
	const struct selinux_file_operation_check check = {
		.requested = IO_URING__CMD,
		.tclass = SECCLASS_IO_URING,
	};
#else
	struct inode_security_struct *isec = selinux_inode(inode);
	int rc;
#endif

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;
#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_file_operation_has_perm(
		current_cred(), file, file->f_cred, inode, fsec->view,
		fsec->pathless, &check, false, &ad);
#else
	rc = file_use_has_perm(current_cred(), file, &ad);
	if (rc)
		return rc;
	return cred_tsid_has_perm(current_cred(), isec->sid,
				  SECCLASS_IO_URING, IO_URING__CMD, &ad);
#endif
}

/**
 * selinux_uring_allowed - check if io_uring_setup() can be called
 *
 * Check to see if the current task is allowed to call io_uring_setup().
 */
static int selinux_uring_allowed(void)
{
	return cred_self_has_perm(current_cred(), SECCLASS_IO_URING,
				  IO_URING__ALLOWED, NULL);
}
#endif /* CONFIG_IO_URING */

static const struct lsm_id selinux_lsmid = {
	.name = "selinux",
	.id = LSM_ID_SELINUX,
};

struct lsm_blob_sizes selinux_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct cred_security_struct),
	.lbs_task = sizeof(struct task_security_struct),
	.lbs_file = sizeof(struct file_security_struct),
	.lbs_backing_file = sizeof(struct backing_file_security_struct),
	.lbs_mnt = sizeof(struct mount_security_struct),
	.lbs_mnt_topology = sizeof(struct selinux_mnt_topology_ctx *),
	.lbs_prop_ref = sizeof(struct selinux_prop_ref_security),
#ifdef CONFIG_SECURITY_SELINUX_NS
	.lbs_inode_create_plan = sizeof(struct selinux_inode_create_plan),
	.lbs_inode_setxattr_plan = sizeof(struct selinux_inode_setxattr_plan),
	.lbs_kernfs_root = sizeof(struct kernfs_root_security_struct),
#endif
	.lbs_inode = sizeof(struct inode_security_struct),
	.lbs_ipc = sizeof(struct ipc_security_struct),
#if defined(CONFIG_SECURITY_SELINUX_NS) && \
	(defined(CONFIG_SYSVIPC) || defined(CONFIG_POSIX_MQUEUE))
	.lbs_ipc_namespace = sizeof(struct selinux_ipcns_security),
#endif
	.lbs_key = sizeof(struct key_security_struct),
	.lbs_msg_msg = sizeof(struct msg_security_struct),
#ifdef CONFIG_PERF_EVENTS
	.lbs_perf_event = sizeof(struct perf_event_security_struct),
#ifdef CONFIG_SECURITY_SELINUX_NS
	.lbs_perf_event_relation =
		sizeof(struct perf_event_relation_security_struct),
#endif
#endif
	.lbs_sock = sizeof(struct sk_security_struct),
#ifdef CONFIG_SECURITY_SELINUX_NS
	.lbs_req = sizeof(struct req_security_struct),
	.lbs_scm = sizeof(struct selinux_scm_security),
	.lbs_sctp_assoc = sizeof(struct sctp_assoc_security_struct),
#endif
	.lbs_superblock = sizeof(struct superblock_security_struct),
	.lbs_xattr_count = SELINUX_INODE_INIT_XATTRS,
	.lbs_tun_dev = sizeof(struct tun_security_struct),
	.lbs_ib = sizeof(struct ib_security_struct),
	.lbs_bpf_map = sizeof(struct bpf_security_struct),
	.lbs_bpf_prog = sizeof(struct bpf_security_struct),
	.lbs_bpf_link = sizeof(struct bpf_security_struct),
	.lbs_bpf_btf = sizeof(struct bpf_security_struct),
	.lbs_bpf_token = sizeof(struct bpf_security_struct),
};

/*
 * IMPORTANT NOTE: When adding new hooks, please be careful to keep this order:
 * 1. any hooks that don't belong to (2.) or (3.) below,
 * 2. hooks that both access structures allocated by other hooks, and allocate
 *    structures that can be later accessed by other hooks (mostly "cloning"
 *    hooks),
 * 3. hooks that only allocate structures that can be later accessed by other
 *    hooks ("allocating" hooks).
 *
 * Please follow block comment delimiters in the list to keep this order.
 */
static struct security_hook_list selinux_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(binder_set_context_mgr, selinux_binder_set_context_mgr),
	LSM_HOOK_INIT(binder_transaction, selinux_binder_transaction),
	LSM_HOOK_INIT(binder_transfer_binder, selinux_binder_transfer_binder),
	LSM_HOOK_INIT(binder_transfer_file, selinux_binder_transfer_file),

	LSM_HOOK_INIT(ptrace_access_check, selinux_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, selinux_ptrace_traceme),
	LSM_HOOK_INIT(capget, selinux_capget),
	LSM_HOOK_INIT(capset, selinux_capset),
	LSM_HOOK_INIT(capable, selinux_capable),
	LSM_HOOK_INIT(quotactl, selinux_quotactl),
	LSM_HOOK_INIT(quota_on, selinux_quota_on),
	LSM_HOOK_INIT(syslog, selinux_syslog),
	LSM_HOOK_INIT(vm_enough_memory, selinux_vm_enough_memory),

	LSM_HOOK_INIT(netlink_send, selinux_netlink_send),

	LSM_HOOK_INIT(bprm_creds_for_exec, selinux_bprm_creds_for_exec),
	LSM_HOOK_INIT(bprm_committing_creds, selinux_bprm_committing_creds),
	LSM_HOOK_INIT(bprm_committed_creds, selinux_bprm_committed_creds),
	LSM_HOOK_INIT(mnt_alloc_security, selinux_mnt_alloc_security),
	LSM_HOOK_INIT(mnt_free_security, selinux_mnt_free_security),
	LSM_HOOK_INIT(mnt_topology_add, selinux_mnt_topology_add),
	LSM_HOOK_INIT(mnt_topology_apply, selinux_mnt_topology_apply),
	LSM_HOOK_INIT(mnt_topology_free, selinux_mnt_topology_free),

	LSM_HOOK_INIT(sb_free_mnt_opts, selinux_free_mnt_opts),
	LSM_HOOK_INIT(sb_free_security, selinux_sb_free_security),
#ifdef CONFIG_SECURITY_SELINUX_NS
	LSM_HOOK_INIT(sb_pre_fill, selinux_sb_pre_fill),
#endif
	LSM_HOOK_INIT(sb_mnt_opts_compat, selinux_sb_mnt_opts_compat),
	LSM_HOOK_INIT(sb_remount, selinux_sb_remount),
	LSM_HOOK_INIT(sb_kern_mount, selinux_sb_kern_mount),
	LSM_HOOK_INIT(sb_show_options, selinux_sb_show_options),
	LSM_HOOK_INIT(sb_statfs, selinux_sb_statfs),
	LSM_HOOK_INIT(sb_mount, selinux_mount),
	LSM_HOOK_INIT(sb_umount, selinux_umount),
	LSM_HOOK_INIT(sb_set_mnt_opts, selinux_set_mnt_opts),
	LSM_HOOK_INIT(sb_clone_mnt_opts, selinux_sb_clone_mnt_opts),

	LSM_HOOK_INIT(move_mount, selinux_move_mount),

	LSM_HOOK_INIT(dentry_init_security, selinux_dentry_init_security),
	LSM_HOOK_INIT(dentry_create_files_as, selinux_dentry_create_files_as),

	LSM_HOOK_INIT(inode_free_security, selinux_inode_free_security),
#ifdef CONFIG_SECURITY_SELINUX_NS
	LSM_HOOK_INIT(inode_create_plan_prepare,
		      selinux_inode_create_plan_prepare),
	LSM_HOOK_INIT(inode_create_plan_attempt_abort,
		      selinux_inode_create_plan_attempt_abort),
	LSM_HOOK_INIT(inode_create_plan_finish,
		      selinux_inode_create_plan_finish),
	LSM_HOOK_INIT(inode_setxattr_plan_prepare,
		      selinux_inode_setxattr_plan_prepare),
	LSM_HOOK_INIT(inode_setxattr_plan_finish,
		      selinux_inode_setxattr_plan_finish),
	LSM_HOOK_INIT(inode_init_security_plan,
		      selinux_inode_init_security_plan),
	LSM_HOOK_INIT(inode_init_security_commit,
		      selinux_inode_init_security_commit),
#endif
	LSM_HOOK_INIT(inode_init_security, selinux_inode_init_security),
	LSM_HOOK_INIT(inode_init_security_anon, selinux_inode_init_security_anon),
#ifdef CONFIG_SECURITY_SELINUX_NS
	LSM_HOOK_INIT(inode_init_security_nsfs,
		      selinux_inode_init_security_nsfs),
#endif
	LSM_HOOK_INIT(inode_create, selinux_inode_create),
	LSM_HOOK_INIT(inode_link, selinux_inode_link),
	LSM_HOOK_INIT(inode_unlink, selinux_inode_unlink),
	LSM_HOOK_INIT(inode_symlink, selinux_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir, selinux_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir, selinux_inode_rmdir),
	LSM_HOOK_INIT(inode_mknod, selinux_inode_mknod),
	LSM_HOOK_INIT(inode_rename, selinux_inode_rename),
	LSM_HOOK_INIT(inode_readlink, selinux_inode_readlink),
	LSM_HOOK_INIT(inode_follow_link, selinux_inode_follow_link),
	LSM_HOOK_INIT(inode_permission, selinux_inode_permission),
	LSM_HOOK_INIT(inode_setattr, selinux_inode_setattr),
	LSM_HOOK_INIT(inode_getattr, selinux_inode_getattr),
	LSM_HOOK_INIT(inode_xattr_skipcap, selinux_inode_xattr_skipcap),
	LSM_HOOK_INIT(inode_setxattr, selinux_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr, selinux_inode_post_setxattr),
	LSM_HOOK_INIT(inode_getxattr, selinux_inode_getxattr),
	LSM_HOOK_INIT(inode_listxattr, selinux_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr, selinux_inode_removexattr),
	LSM_HOOK_INIT(inode_file_getattr, selinux_inode_file_getattr),
	LSM_HOOK_INIT(inode_file_setattr, selinux_inode_file_setattr),
	LSM_HOOK_INIT(inode_set_acl, selinux_inode_set_acl),
	LSM_HOOK_INIT(inode_get_acl, selinux_inode_get_acl),
	LSM_HOOK_INIT(inode_remove_acl, selinux_inode_remove_acl),
	LSM_HOOK_INIT(inode_getsecurity, selinux_inode_getsecurity),
	LSM_HOOK_INIT(inode_setsecurity, selinux_inode_setsecurity),
	LSM_HOOK_INIT(inode_listsecurity, selinux_inode_listsecurity),
	LSM_HOOK_INIT(inode_getlsmprop, selinux_inode_getlsmprop),
	LSM_HOOK_INIT(inode_copy_up, selinux_inode_copy_up),
	LSM_HOOK_INIT(inode_copy_up_post, selinux_inode_copy_up_post),
	LSM_HOOK_INIT(inode_copy_up_xattr, selinux_inode_copy_up_xattr),
	LSM_HOOK_INIT(path_notify, selinux_path_notify),

#ifdef CONFIG_SECURITY_SELINUX_NS
	LSM_HOOK_INIT(kernfs_root_alloc_security,
		      selinux_kernfs_root_alloc_security),
	LSM_HOOK_INIT(kernfs_root_free_security,
		      selinux_kernfs_root_free_security),
	LSM_HOOK_INIT(kernfs_root_to_sb, selinux_kernfs_root_to_sb),
#endif
	LSM_HOOK_INIT(kernfs_init_security, selinux_kernfs_init_security),

	LSM_HOOK_INIT(file_permission, selinux_file_permission),
	LSM_HOOK_INIT(file_alloc_security, selinux_file_alloc_security),
	LSM_HOOK_INIT(file_set_path, selinux_file_set_path),
#ifdef CONFIG_SECURITY_SELINUX_NS
	LSM_HOOK_INIT(file_init_security_anon,
		      selinux_file_init_security_anon),
	LSM_HOOK_INIT(file_kho_preserve, selinux_file_kho_preserve),
#endif
	LSM_HOOK_INIT(backing_file_alloc, selinux_backing_file_alloc),
	LSM_HOOK_INIT(backing_file_free, selinux_backing_file_free),
	LSM_HOOK_INIT(file_free_security, selinux_file_free_security),
	LSM_HOOK_INIT(file_ioctl, selinux_file_ioctl),
	LSM_HOOK_INIT(file_ioctl_compat, selinux_file_ioctl_compat),
	LSM_HOOK_INIT(mmap_file, selinux_mmap_file),
	LSM_HOOK_INIT(mmap_backing_file, selinux_mmap_backing_file),
	LSM_HOOK_INIT(mmap_addr, selinux_mmap_addr),
	LSM_HOOK_INIT(file_mprotect, selinux_file_mprotect),
	LSM_HOOK_INIT(file_lock, selinux_file_lock),
	LSM_HOOK_INIT(file_fcntl, selinux_file_fcntl),
	LSM_HOOK_INIT(file_set_fowner, selinux_file_set_fowner),
	LSM_HOOK_INIT(file_send_sigiotask, selinux_file_send_sigiotask),
	LSM_HOOK_INIT(file_receive, selinux_file_receive),

	LSM_HOOK_INIT(file_open, selinux_file_open),

	LSM_HOOK_INIT(task_alloc, selinux_task_alloc),
	LSM_HOOK_INIT(task_free, selinux_task_free),
	LSM_HOOK_INIT(cred_free, selinux_cred_free),
	LSM_HOOK_INIT(cred_prepare, selinux_cred_prepare),
	LSM_HOOK_INIT(cred_transfer, selinux_cred_transfer),
	LSM_HOOK_INIT(cred_getsecid, selinux_cred_getsecid),
	LSM_HOOK_INIT(cred_getlsmprop, selinux_cred_getlsmprop),
	LSM_HOOK_INIT(prop_ref_capture, selinux_prop_ref_capture),
	LSM_HOOK_INIT(prop_ref_free, selinux_prop_ref_free),
	LSM_HOOK_INIT(prop_ref_to_secctx, selinux_prop_ref_to_secctx),
	LSM_HOOK_INIT(kernel_act_as_ref, selinux_kernel_act_as_ref),
	LSM_HOOK_INIT(kernel_create_files_as, selinux_kernel_create_files_as),
	LSM_HOOK_INIT(kernel_module_request, selinux_kernel_module_request),
	LSM_HOOK_INIT(kernel_load_data, selinux_kernel_load_data),
	LSM_HOOK_INIT(kernel_read_file, selinux_kernel_read_file),
	LSM_HOOK_INIT(task_setpgid, selinux_task_setpgid),
	LSM_HOOK_INIT(task_getpgid, selinux_task_getpgid),
	LSM_HOOK_INIT(task_getsid, selinux_task_getsid),
	LSM_HOOK_INIT(current_getlsmprop_subj, selinux_current_getlsmprop_subj),
	LSM_HOOK_INIT(task_getlsmprop_obj, selinux_task_getlsmprop_obj),
	LSM_HOOK_INIT(task_setnice, selinux_task_setnice),
	LSM_HOOK_INIT(task_setioprio, selinux_task_setioprio),
	LSM_HOOK_INIT(task_getioprio, selinux_task_getioprio),
	LSM_HOOK_INIT(task_prlimit, selinux_task_prlimit),
	LSM_HOOK_INIT(task_setrlimit, selinux_task_setrlimit),
	LSM_HOOK_INIT(task_setscheduler, selinux_task_setscheduler),
	LSM_HOOK_INIT(task_getscheduler, selinux_task_getscheduler),
	LSM_HOOK_INIT(task_movememory, selinux_task_movememory),
	LSM_HOOK_INIT(task_kill, selinux_task_kill),
	LSM_HOOK_INIT(task_to_inode, selinux_task_to_inode),
	LSM_HOOK_INIT(userns_create, selinux_userns_create),

	LSM_HOOK_INIT(ipc_permission, selinux_ipc_permission),
	LSM_HOOK_INIT(ipc_getlsmprop, selinux_ipc_getlsmprop),
	LSM_HOOK_INIT(msg_msg_free_security, selinux_msg_msg_free_security),

	LSM_HOOK_INIT(msg_queue_free_security, selinux_ipc_free_security),
	LSM_HOOK_INIT(msg_queue_associate, selinux_msg_queue_associate),
	LSM_HOOK_INIT(msg_queue_msgctl, selinux_msg_queue_msgctl),
	LSM_HOOK_INIT(msg_queue_msgsnd, selinux_msg_queue_msgsnd),
	LSM_HOOK_INIT(msg_queue_msgrcv, selinux_msg_queue_msgrcv),

	LSM_HOOK_INIT(shm_free_security, selinux_ipc_free_security),
	LSM_HOOK_INIT(shm_associate, selinux_shm_associate),
	LSM_HOOK_INIT(shm_shmctl, selinux_shm_shmctl),
	LSM_HOOK_INIT(shm_shmat, selinux_shm_shmat),

	LSM_HOOK_INIT(sem_free_security, selinux_ipc_free_security),
	LSM_HOOK_INIT(sem_associate, selinux_sem_associate),
	LSM_HOOK_INIT(sem_semctl, selinux_sem_semctl),
	LSM_HOOK_INIT(sem_semop, selinux_sem_semop),

	LSM_HOOK_INIT(d_instantiate, selinux_d_instantiate),

	LSM_HOOK_INIT(getselfattr, selinux_getselfattr),
	LSM_HOOK_INIT(setselfattr, selinux_setselfattr),
	LSM_HOOK_INIT(getprocattr, selinux_getprocattr),
	LSM_HOOK_INIT(setprocattr, selinux_setprocattr),

	LSM_HOOK_INIT(ismaclabel, selinux_ismaclabel),
	LSM_HOOK_INIT(secctx_to_secid, selinux_secctx_to_secid),
	LSM_HOOK_INIT(release_secctx, selinux_release_secctx),
	LSM_HOOK_INIT(inode_invalidate_secctx, selinux_inode_invalidate_secctx),
	LSM_HOOK_INIT(inode_notifysecctx, selinux_inode_notifysecctx),
	LSM_HOOK_INIT(inode_setsecctx, selinux_inode_setsecctx),

	LSM_HOOK_INIT(unix_stream_connect, selinux_socket_unix_stream_connect),
	LSM_HOOK_INIT(unix_may_send, selinux_socket_unix_may_send),

	LSM_HOOK_INIT(socket_create, selinux_socket_create),
	LSM_HOOK_INIT(socket_post_create, selinux_socket_post_create),
	LSM_HOOK_INIT(socket_socketpair, selinux_socket_socketpair),
	LSM_HOOK_INIT(socket_bind, selinux_socket_bind),
	LSM_HOOK_INIT(socket_connect, selinux_socket_connect),
	LSM_HOOK_INIT(socket_listen, selinux_socket_listen),
	LSM_HOOK_INIT(socket_accept, selinux_socket_accept),
	LSM_HOOK_INIT(socket_sendmsg, selinux_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg, selinux_socket_recvmsg),
	LSM_HOOK_INIT(socket_getsockname, selinux_socket_getsockname),
	LSM_HOOK_INIT(socket_getpeername, selinux_socket_getpeername),
	LSM_HOOK_INIT(socket_getsockopt, selinux_socket_getsockopt),
	LSM_HOOK_INIT(socket_setsockopt, selinux_socket_setsockopt),
	LSM_HOOK_INIT(socket_shutdown, selinux_socket_shutdown),
	LSM_HOOK_INIT(socket_sock_rcv_skb, selinux_socket_sock_rcv_skb),
	LSM_HOOK_INIT(socket_getpeersec_stream,
			selinux_socket_getpeersec_stream),
	LSM_HOOK_INIT(socket_getpeersec_dgram, selinux_socket_getpeersec_dgram),
#ifdef CONFIG_SECURITY_SELINUX_NS
	LSM_HOOK_INIT(socket_getpeersec_dgram_ctx,
		      selinux_socket_getpeersec_dgram_ctx),
	LSM_HOOK_INIT(scm_alloc_security, selinux_scm_alloc_security),
	LSM_HOOK_INIT(scm_free_security, selinux_scm_free_security),
	LSM_HOOK_INIT(scm_secdata_eq, selinux_scm_secdata_eq),
	LSM_HOOK_INIT(scm_getsecctx, selinux_scm_getsecctx),
#endif
	LSM_HOOK_INIT(sk_free_security, selinux_sk_free_security),
	LSM_HOOK_INIT(sk_clone_security, selinux_sk_clone_security),
#ifdef CONFIG_SECURITY_SELINUX_NS
	LSM_HOOK_INIT(req_alloc_security, selinux_req_alloc_security),
	LSM_HOOK_INIT(req_free_security, selinux_req_free_security),
	LSM_HOOK_INIT(req_clone_security, selinux_req_clone_security),
	LSM_HOOK_INIT(sctp_assoc_alloc_security,
		      selinux_sctp_assoc_alloc_security),
	LSM_HOOK_INIT(sctp_assoc_free_security,
		      selinux_sctp_assoc_free_security),
#endif
	LSM_HOOK_INIT(sk_getsecid, selinux_sk_getsecid),
	LSM_HOOK_INIT(sock_graft, selinux_sock_graft),
	LSM_HOOK_INIT(sctp_assoc_request, selinux_sctp_assoc_request),
	LSM_HOOK_INIT(sctp_sk_clone, selinux_sctp_sk_clone),
	LSM_HOOK_INIT(sctp_bind_connect, selinux_sctp_bind_connect),
	LSM_HOOK_INIT(sctp_assoc_established, selinux_sctp_assoc_established),
	LSM_HOOK_INIT(mptcp_add_subflow, selinux_mptcp_add_subflow),
	LSM_HOOK_INIT(inet_conn_request, selinux_inet_conn_request),
	LSM_HOOK_INIT(inet_csk_clone, selinux_inet_csk_clone),
	LSM_HOOK_INIT(inet_conn_established, selinux_inet_conn_established),
	LSM_HOOK_INIT(secmark_relabel_packet, selinux_secmark_relabel_packet),
	LSM_HOOK_INIT(secmark_release, selinux_secmark_release),
	LSM_HOOK_INIT(secmark_refcount_inc, selinux_secmark_refcount_inc),
	LSM_HOOK_INIT(secmark_refcount_dec, selinux_secmark_refcount_dec),
	LSM_HOOK_INIT(req_classify_flow, selinux_req_classify_flow),
	LSM_HOOK_INIT(tun_dev_create, selinux_tun_dev_create),
	LSM_HOOK_INIT(tun_dev_free_security, selinux_tun_dev_free_security),
	LSM_HOOK_INIT(tun_dev_attach_queue, selinux_tun_dev_attach_queue),
	LSM_HOOK_INIT(tun_dev_attach, selinux_tun_dev_attach),
	LSM_HOOK_INIT(tun_dev_open, selinux_tun_dev_open),
#ifdef CONFIG_SECURITY_INFINIBAND
	LSM_HOOK_INIT(ib_pkey_access, selinux_ib_pkey_access),
	LSM_HOOK_INIT(ib_endport_manage_subnet,
		      selinux_ib_endport_manage_subnet),
	LSM_HOOK_INIT(ib_policy_scopes, selinux_ib_policy_scopes),
	LSM_HOOK_INIT(ib_free_security, selinux_ib_free_security),
#endif
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	LSM_HOOK_INIT(xfrm_policy_free_security, selinux_xfrm_policy_free),
	LSM_HOOK_INIT(xfrm_policy_delete_security, selinux_xfrm_policy_delete),
	LSM_HOOK_INIT(xfrm_state_free_security, selinux_xfrm_state_free),
	LSM_HOOK_INIT(xfrm_state_delete_security, selinux_xfrm_state_delete),
	LSM_HOOK_INIT(xfrm_policy_lookup, selinux_xfrm_policy_lookup),
	LSM_HOOK_INIT(xfrm_state_pol_flow_match,
			selinux_xfrm_state_pol_flow_match),
	LSM_HOOK_INIT(xfrm_decode_session, selinux_xfrm_decode_session),
#endif

#ifdef CONFIG_KEYS
	LSM_HOOK_INIT(key_permission, selinux_key_permission),
	LSM_HOOK_INIT(key_getsecurity, selinux_key_getsecurity),
	LSM_HOOK_INIT(key_free, selinux_key_free),
#ifdef CONFIG_KEY_NOTIFICATIONS
	LSM_HOOK_INIT(watch_key, selinux_watch_key),
#endif
#endif

#ifdef CONFIG_AUDIT
	LSM_HOOK_INIT(audit_rule_known, selinux_audit_rule_known),
	LSM_HOOK_INIT(audit_rule_match, selinux_audit_rule_match),
	LSM_HOOK_INIT(audit_rule_free, selinux_audit_rule_free),
#endif

#ifdef CONFIG_BPF_SYSCALL
	LSM_HOOK_INIT(bpf, selinux_bpf),
	LSM_HOOK_INIT(bpf_map, selinux_bpf_map),
	LSM_HOOK_INIT(bpf_map_relation, selinux_bpf_map_relation),
	LSM_HOOK_INIT(bpf_prog, selinux_bpf_prog),
	LSM_HOOK_INIT(bpf_prog_map_relation, selinux_bpf_prog_map_relation),
#ifdef CONFIG_SECURITY_SELINUX_NS
	LSM_HOOK_INIT(bpf_map_free, selinux_bpf_map_free),
	LSM_HOOK_INIT(bpf_prog_free, selinux_bpf_prog_free),
	LSM_HOOK_INIT(bpf_token_free, selinux_bpf_token_free),
#endif
#endif

#ifdef CONFIG_PERF_EVENTS
	LSM_HOOK_INIT(perf_event_open, selinux_perf_event_open),
	LSM_HOOK_INIT(perf_event_read, selinux_perf_event_read),
	LSM_HOOK_INIT(perf_event_write, selinux_perf_event_write),
	LSM_HOOK_INIT(perf_event_relation, selinux_perf_event_relation),
#ifdef CONFIG_SECURITY_SELINUX_NS
	LSM_HOOK_INIT(perf_event_relation_free,
		      selinux_perf_event_relation_free),
	LSM_HOOK_INIT(perf_event_relation_valid,
		      selinux_perf_event_relation_valid),
	LSM_HOOK_INIT(perf_event_relation_revalidate,
		      selinux_perf_event_relation_revalidate),
#endif
	LSM_HOOK_INIT(perf_event_free, selinux_perf_event_free),
#endif

#ifdef CONFIG_IO_URING
	LSM_HOOK_INIT(uring_override_creds, selinux_uring_override_creds),
	LSM_HOOK_INIT(uring_sqpoll, selinux_uring_sqpoll),
	LSM_HOOK_INIT(uring_cmd, selinux_uring_cmd),
	LSM_HOOK_INIT(uring_allowed, selinux_uring_allowed),
#endif

	/*
	 * PUT "CLONING" (ACCESSING + ALLOCATING) HOOKS HERE
	 */
	LSM_HOOK_INIT(fs_context_submount, selinux_fs_context_submount),
	LSM_HOOK_INIT(fs_context_dup, selinux_fs_context_dup),
	LSM_HOOK_INIT(fs_context_parse_param, selinux_fs_context_parse_param),
	LSM_HOOK_INIT(sb_eat_lsm_opts, selinux_sb_eat_lsm_opts),
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	LSM_HOOK_INIT(xfrm_policy_clone_security, selinux_xfrm_policy_clone),
#endif

	/*
	 * PUT "ALLOCATING" HOOKS HERE
	 */
	LSM_HOOK_INIT(msg_msg_alloc_security, selinux_msg_msg_alloc_security),
	LSM_HOOK_INIT(msg_queue_alloc_security,
		      selinux_msg_queue_alloc_security),
	LSM_HOOK_INIT(shm_alloc_security, selinux_shm_alloc_security),
	LSM_HOOK_INIT(sb_alloc_security, selinux_sb_alloc_security),
	LSM_HOOK_INIT(inode_alloc_security, selinux_inode_alloc_security),
	LSM_HOOK_INIT(sem_alloc_security, selinux_sem_alloc_security),
	LSM_HOOK_INIT(secid_to_secctx, selinux_secid_to_secctx),
	LSM_HOOK_INIT(lsmprop_to_secctx, selinux_lsmprop_to_secctx),
	LSM_HOOK_INIT(inode_getsecctx, selinux_inode_getsecctx),
	LSM_HOOK_INIT(sk_alloc_security, selinux_sk_alloc_security),
	LSM_HOOK_INIT(tun_dev_alloc_security, selinux_tun_dev_alloc_security),
#ifdef CONFIG_SECURITY_INFINIBAND
	LSM_HOOK_INIT(ib_alloc_security, selinux_ib_alloc_security),
#endif
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	LSM_HOOK_INIT(xfrm_policy_alloc_security, selinux_xfrm_policy_alloc),
	LSM_HOOK_INIT(xfrm_state_alloc, selinux_xfrm_state_alloc),
	LSM_HOOK_INIT(xfrm_state_alloc_acquire,
		      selinux_xfrm_state_alloc_acquire),
#endif
#ifdef CONFIG_KEYS
	LSM_HOOK_INIT(key_alloc, selinux_key_alloc),
#endif
#ifdef CONFIG_AUDIT
	LSM_HOOK_INIT(audit_rule_init, selinux_audit_rule_init),
#endif
#ifdef CONFIG_BPF_SYSCALL
	LSM_HOOK_INIT(bpf_map_create, selinux_bpf_map_create),
	LSM_HOOK_INIT(bpf_prog_load, selinux_bpf_prog_load),
	LSM_HOOK_INIT(bpf_prog_commit, selinux_bpf_prog_commit),
	LSM_HOOK_INIT(bpf_link_create, selinux_bpf_link_create),
	LSM_HOOK_INIT(bpf_link_free, selinux_bpf_link_free),
	LSM_HOOK_INIT(bpf_link_access, selinux_bpf_link_access),
	LSM_HOOK_INIT(bpf_link_update, selinux_bpf_link_update),
	LSM_HOOK_INIT(bpf_btf, selinux_bpf_btf),
	LSM_HOOK_INIT(bpf_btf_load, selinux_bpf_btf_load),
	LSM_HOOK_INIT(bpf_btf_free, selinux_bpf_btf_free),
	LSM_HOOK_INIT(bpf_token_create, selinux_bpf_token_create),
	LSM_HOOK_INIT(bpf_token_cmd, selinux_bpf_token_cmd),
	LSM_HOOK_INIT(bpf_token_capable, selinux_bpf_token_capable),
#endif
#ifdef CONFIG_PERF_EVENTS
	LSM_HOOK_INIT(perf_event_alloc, selinux_perf_event_alloc),
#endif
};

static void selinux_state_free(struct work_struct *work);

#ifdef CONFIG_SECURITY_SELINUX_NS
unsigned int selinux_maxns = CONFIG_SECURITY_SELINUX_MAXNS;
unsigned int selinux_maxnsdepth = CONFIG_SECURITY_SELINUX_MAXNSDEPTH;
#endif

static atomic_t selinux_nsnum = ATOMIC_INIT(0);
static DEFINE_MUTEX(selinux_state_tree_mutex);

#ifdef CONFIG_SECURITY_SELINUX_NS
static int selinux_state_creator_sid_take_handle(
	struct selinux_state *state, struct selinux_global_sid_handle *handle)
{
	struct selinux_global_sid_handle *old;
	u32 sid;

	if (!state || !handle || IS_ERR(handle)) {
		if (!IS_ERR_OR_NULL(handle))
			global_sid_handle_put(handle);
		return IS_ERR(handle) ? PTR_ERR(handle) : -EINVAL;
	}
	sid = global_sid_handle_sid(handle);
	if (!sid) {
		global_sid_handle_put(handle);
		return -ESTALE;
	}
	old = state->creator_sid_handle;
	WRITE_ONCE(state->creator_sid_handle, handle);
	WRITE_ONCE(state->creator_sid, sid);
	global_sid_handle_put(old);
	return 0;
}
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
int selinux_state_set_maxns(unsigned int value)
{
	int rc = 0;

	if (!value || value > SELINUX_MAX_NAMESPACES_LIMIT)
		return -EINVAL;
	mutex_lock(&selinux_state_tree_mutex);
	if (value < atomic_read(&selinux_nsnum))
		rc = -EBUSY;
	else
		WRITE_ONCE(selinux_maxns, value);
	mutex_unlock(&selinux_state_tree_mutex);
	return rc;
}

int selinux_state_set_maxnsdepth(unsigned int value)
{
	if (value > SELINUX_LABEL_RESOLUTION_MAX_DEPTH)
		return -EINVAL;
	mutex_lock(&selinux_state_tree_mutex);
	WRITE_ONCE(selinux_maxnsdepth, value);
	mutex_unlock(&selinux_state_tree_mutex);
	return 0;
}
#endif

u64 selinux_chain_epoch_read(const struct selinux_state *state)
{
	u64 epoch;

	/*
	 * A publication is bracketed by two epoch changes.  Returning the
	 * fail-closed sentinel while it is in progress prevents a reader from
	 * combining the new generation with the old policy (or vice versa).
	 */
	if (unlikely(atomic_read_acquire(&state->chain_updates)))
		return 0;
	epoch = atomic64_read(&state->chain_epoch);
	/* Order the epoch sample before the second publication-marker sample. */
	smp_rmb();
	if (unlikely(atomic_read(&state->chain_updates)))
		return 0;
	return epoch;
}

bool selinux_chain_update_active(const struct selinux_state *state)
{
	return atomic_read_acquire(&state->chain_updates) != 0;
}

static void selinux_chain_epoch_advance_one(struct selinux_state *state)
{
	s64 epoch = atomic64_read(&state->chain_epoch);

	/*
	 * Zero is a permanent fail-closed sentinel.  Saturating before signed
	 * wrap prevents an old file cache entry from becoming valid again after
	 * an epoch ABA.  The tree mutex serializes every writer; readers use an
	 * atomic snapshot and reject the sentinel.
	 */
	if (epoch > 0 && epoch < S64_MAX)
		atomic64_inc(&state->chain_epoch);
	else
		atomic64_set(&state->chain_epoch, 0);
}

static void selinux_chain_epoch_bump_locked(struct selinux_state *state)
{
	struct selinux_state *child;

	selinux_chain_epoch_advance_one(state);

	list_for_each_entry(child, &state->children, sibling)
		selinux_chain_epoch_bump_locked(child);
}

static void selinux_chain_update_begin_locked(struct selinux_state *state)
{
	struct selinux_state *child;

	/* Overflow is a permanent fail-closed state, like epoch saturation. */
	if (atomic_read(&state->chain_updates) != INT_MAX)
		atomic_inc_return(&state->chain_updates);
	selinux_chain_epoch_advance_one(state);
	list_for_each_entry(child, &state->children, sibling)
		selinux_chain_update_begin_locked(child);
}

static void selinux_chain_update_release_one(struct selinux_state *state)
{
	int updates = atomic_read(&state->chain_updates);

	/* A saturated update counter must never wrap back to reusable. */
	if (updates == INT_MAX)
		return;
	if (WARN_ON_ONCE(updates <= 0))
		atomic_set_release(&state->chain_updates, 0);
	else
		atomic_dec_return_release(&state->chain_updates);
}

static void selinux_chain_update_end_locked(struct selinux_state *state)
{
	struct selinux_state *child;

	selinux_chain_epoch_advance_one(state);
	selinux_chain_update_release_one(state);
	list_for_each_entry(child, &state->children, sibling)
		selinux_chain_update_end_locked(child);
}

void selinux_chain_epoch_bump(struct selinux_state *state)
{
	mutex_lock(&selinux_state_tree_mutex);
	selinux_chain_epoch_bump_locked(state);
	mutex_unlock(&selinux_state_tree_mutex);
}

int selinux_chain_update_begin(struct selinux_state *state)
{
	mutex_lock(&selinux_state_tree_mutex);
	selinux_chain_update_begin_locked(state);
	mutex_unlock(&selinux_state_tree_mutex);
	return 0;
}

/*
 * Blocking policy-change notifiers are a preparation barrier, not part of
 * the publication itself.  In particular, they may sleep.  Keeping them out
 * of the chain_updates interval is required because authorization also runs
 * from non-sleepable contexts and therefore cannot wait for a notifier.
 */
int selinux_chain_update_prepare(struct selinux_state *state)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (state->label_domain) {
		struct lsm_policy_change change = {
			.scoped = true,
			.scope_id = state->label_domain->id,
		};
		int rc;

		rc = notifier_to_errno(call_blocking_lsm_notifier(
			LSM_POLICY_CHANGE_PRE, &change));
		if (rc)
			call_blocking_lsm_notifier(LSM_POLICY_CHANGE_ABORT, &change);
		return rc;
	}
#endif
	return 0;
}

void selinux_chain_update_end(struct selinux_state *state)
{
	mutex_lock(&selinux_state_tree_mutex);
	selinux_chain_update_end_locked(state);
	mutex_unlock(&selinux_state_tree_mutex);
}

void selinux_chain_update_abort(struct selinux_state *state)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (state->label_domain) {
		struct lsm_policy_change change = {
			.scoped = true,
			.scope_id = state->label_domain->id,
		};

		call_blocking_lsm_notifier(LSM_POLICY_CHANGE_ABORT, &change);
	}
#endif
}

void selinux_chain_update_complete(struct selinux_state *state)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (state->label_domain) {
		struct lsm_policy_change change = {
			.scoped = true,
			.scope_id = state->label_domain->id,
		};

		call_blocking_lsm_notifier(LSM_POLICY_CHANGE, &change);
	}
#endif
}

static struct selinux_state *selinux_state_alloc(const struct cred *cred,
						 bool active)
{
	const struct cred_security_struct *crsec = selinux_cred(cred);
	struct selinux_state *parent = crsec->state;
#ifndef CONFIG_SECURITY_SELINUX_NS
	u32 creator_sid = crsec->sid;
#endif
	struct selinux_state *newstate = NULL;
	int rc;
#ifdef CONFIG_SECURITY_SELINUX_NS
	bool ns_counted = false;
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
	mutex_lock(&selinux_state_tree_mutex);
	if (atomic_read(&selinux_nsnum) >= READ_ONCE(selinux_maxns)) {
		rc = -ENOSPC;
		mutex_unlock(&selinux_state_tree_mutex);
		goto err;
	}
	if (parent && parent->depth >= READ_ONCE(selinux_maxnsdepth)) {
		rc = -ENOSPC;
		mutex_unlock(&selinux_state_tree_mutex);
		goto err;
	}
	atomic_inc(&selinux_nsnum);
	ns_counted = true;
	mutex_unlock(&selinux_state_tree_mutex);
#endif
	newstate = kzalloc(sizeof(*newstate), GFP_KERNEL);
	if (!newstate) {
		rc = -ENOMEM;
		goto err;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!crsec->sid_handle ||
	    global_sid_handle_sid(crsec->sid_handle) != crsec->sid) {
		rc = -ESTALE;
		goto err;
	}
	rc = selinux_state_creator_sid_take_handle(
		newstate, global_sid_handle_dup(crsec->sid_handle));
	if (rc)
		goto err;
#else
	newstate->creator_sid = creator_sid;
#endif
	WRITE_ONCE(newstate->active, active);
	INIT_LIST_HEAD(&newstate->children);
	INIT_LIST_HEAD(&newstate->sibling);
	atomic64_set(&newstate->chain_epoch, 1);
	atomic_set(&newstate->chain_updates, 0);
	newstate->label_domain = selinux_label_domain_alloc(
		cred->user_ns, parent ? parent->label_domain : NULL, 0);
	if (IS_ERR(newstate->label_domain)) {
		rc = PTR_ERR(newstate->label_domain);
		newstate->label_domain = NULL;
		goto err;
	}

	refcount_set(&newstate->count, 1);
	INIT_WORK(&newstate->work, selinux_state_free);

	mutex_init(&newstate->status_lock);
	mutex_init(&newstate->policy_mutex);
	atomic64_set(&newstate->policy_snapshot_bytes, 0);
	if (parent) {
		/* A dormant state can outlive the creating credential. */
		newstate->parent = get_selinux_state(parent);
		newstate->depth = parent->depth + 1;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = selinux_ns_control_state_init(newstate, active);
	if (rc)
		goto err;
#endif

	rc = selinux_avc_create(newstate->label_domain->resources,
				&newstate->avc);
	if (rc)
		goto err;

	if (parent) {
		mutex_lock(&selinux_state_tree_mutex);
		/*
		 * Join publications already active in an ancestor.  Their matching
		 * end traversal will visit this newly linked state and release the
		 * inherited count.
		 */
		atomic_set(&newstate->chain_updates,
			   atomic_read(&parent->chain_updates));
		list_add_tail(&newstate->sibling, &parent->children);
		mutex_unlock(&selinux_state_tree_mutex);
	}

	return newstate;

err:
	if (newstate) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		selinux_ns_control_state_destroy(newstate);
#endif
		if (newstate->avc)
			selinux_avc_free(newstate->avc);
		put_selinux_state(newstate->parent);
		selinux_label_domain_put(newstate->label_domain);
#ifdef CONFIG_SECURITY_SELINUX_NS
		global_sid_handle_put(newstate->creator_sid_handle);
#endif
	}
	kfree(newstate);
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (ns_counted) {
		mutex_lock(&selinux_state_tree_mutex);
		atomic_dec(&selinux_nsnum);
		mutex_unlock(&selinux_state_tree_mutex);
	}
#endif
	return ERR_PTR(rc);
}

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_state *selinux_state_create_dormant(const struct cred *cred)
{
	return selinux_state_alloc(cred, false);
}
#endif

int selinux_state_create(const struct cred *cred)
{
	struct cred_security_struct *crsec = selinux_cred(cred);
	struct selinux_state *parent = crsec->state;
	struct selinux_state *newstate;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *init_osid = NULL;
	struct selinux_global_sid_handle *init_sid = NULL;
	int rc;
#endif

	newstate = selinux_state_alloc(cred, true);
	if (IS_ERR(newstate))
		return PTR_ERR(newstate);

#ifdef CONFIG_SECURITY_SELINUX_NS
	/* Acquire every fallible replacement before publishing the new state. */
	if (parent) {
		init_osid = global_sid_handle_get(SECINITSID_INIT);
		if (IS_ERR(init_osid)) {
			rc = PTR_ERR(init_osid);
			init_osid = NULL;
			goto err_state;
		}
		init_sid = global_sid_handle_get(SECINITSID_INIT);
		if (IS_ERR(init_sid)) {
			rc = PTR_ERR(init_sid);
			init_sid = NULL;
			goto err_state;
		}
	}
#endif

	/* The prepared credential transfers from its parent to the new state. */
	crsec->state = newstate;
	put_selinux_state(parent);

	/* Reset the SIDs for the new namespace. */
	if (parent) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		WARN_ON_ONCE(selinux_cred_sid_take_handle(
			crsec, SELINUX_CRED_OSID, init_osid));
		init_osid = NULL;
		WARN_ON_ONCE(selinux_cred_sid_take_handle(
			crsec, SELINUX_CRED_SID, init_sid));
		init_sid = NULL;
#else
		crsec->osid = crsec->sid = SECINITSID_INIT;
#endif
	}
#ifdef CONFIG_SECURITY_SELINUX_NS
	WARN_ON_ONCE(selinux_cred_sid_take_handle(
		crsec, SELINUX_CRED_EXEC_SID, NULL));
	WARN_ON_ONCE(selinux_cred_sid_take_handle(
		crsec, SELINUX_CRED_CREATE_SID, NULL));
	WARN_ON_ONCE(selinux_cred_sid_take_handle(
		crsec, SELINUX_CRED_KEYCREATE_SID, NULL));
	WARN_ON_ONCE(selinux_cred_sid_take_handle(
		crsec, SELINUX_CRED_SOCKCREATE_SID, NULL));
#else
	crsec->exec_sid = crsec->create_sid = crsec->keycreate_sid =
		crsec->sockcreate_sid = SECSID_NULL;
#endif

	/*
	 * Save the credential in the parent namespace
	 * for later use in checks in that namespace.
	 */
	if (parent) {
		put_cred(crsec->parent_cred);
		crsec->parent_cred = get_current_cred();
	}
	return 0;

#ifdef CONFIG_SECURITY_SELINUX_NS
err_state:
	global_sid_handle_put(init_sid);
	global_sid_handle_put(init_osid);
	put_selinux_state(newstate);
	return rc;
#endif
}

static void selinux_state_free(struct work_struct *work)
{
	struct selinux_state *parent, *state =
		container_of(work, struct selinux_state, work);

	do {
		parent = state->parent;
		mutex_lock(&selinux_state_tree_mutex);
		WARN_ON(!list_empty(&state->children));
		if (parent)
			list_del_init(&state->sibling);
		atomic_dec(&selinux_nsnum);
		mutex_unlock(&selinux_state_tree_mutex);
		global_sidtab_invalidate_state(state);
		WARN_ON(atomic64_read(&state->policy_snapshot_bytes));
		if (state->status_page)
			__free_page(state->status_page);
		selinux_state_policy_free(state);
		selinux_avc_free(state->avc);
#ifdef CONFIG_SECURITY_SELINUX_NS
		selinux_ns_control_state_destroy(state);
#endif
		selinux_label_domain_put(state->label_domain);
#ifdef CONFIG_SECURITY_SELINUX_NS
		global_sid_handle_put(state->creator_sid_handle);
#endif
		kfree(state);
		state = parent;
	} while (state && refcount_dec_and_test(&state->count));
}

void __put_selinux_state(struct selinux_state *state)
{
	schedule_work(&state->work);
}

struct selinux_state *init_selinux_state;

static __init int selinux_init(void)
{
	vma_flags_t data_default_flags = VMA_DATA_DEFAULT_FLAGS;
	const struct cred *cred = unrcu_pointer(current->real_cred);
	struct cred_security_struct *crsec = selinux_cred(cred);

	pr_info("SELinux:  Initializing.\n");
	if (global_sidtab_init())
		panic("SELinux: Could not create global SID table\n");
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (rhashtable_init(&selinux_inode_relabel_markers,
			    &selinux_inode_relabel_marker_params))
		panic("SELinux: Could not create inode relabel marker table\n");
#endif

	/*
	 * Initialize the first cred with the kernel SID and
	 * NULL state since selinux_state_create() expects
	 * these two fields to be set. The rest is handled by
	 * selinux_state_create(), which will update the state
	 * field to refer to the new state and set the parent
	 * pointer to the old state value (NULL).
	 */
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (selinux_cred_sid_set(
		    crsec, SELINUX_CRED_OSID, SECINITSID_KERNEL) ||
	    selinux_cred_sid_set(
		    crsec, SELINUX_CRED_SID, SECINITSID_KERNEL))
		panic("SELinux: Could not retain initial credential SIDs\n");
#else
	crsec->osid = crsec->sid = SECINITSID_KERNEL;
#endif
	crsec->state = NULL;
	if (selinux_state_create(cred))
		panic("SELinux: Could not create initial namespace\n");

	/*
	 * Save a reference to the initial SELinux namespace
	 * for use in various other functions.
	 */
	init_selinux_state = get_selinux_state(crsec->state);

	enforcing_set(init_selinux_state, selinux_enforcing_boot);

	/* Inform the audit system that secctx is used */
	audit_cfg_lsm(&selinux_lsmid,
		      AUDIT_CFG_LSM_SECCTX_SUBJECT |
		      AUDIT_CFG_LSM_SECCTX_OBJECT);

	default_noexec = !vma_flags_test(&data_default_flags, VMA_EXEC_BIT);
	if (!default_noexec)
		pr_notice("SELinux:  virtual memory is executable by default\n");

	avc_init();

	avtab_cache_init();

	ebitmap_cache_init();

	hashtab_cache_init();

	security_add_hooks(selinux_hooks, ARRAY_SIZE(selinux_hooks),
			   &selinux_lsmid);
#if defined(CONFIG_SECURITY_SELINUX_NS) && \
	(defined(CONFIG_SYSVIPC) || defined(CONFIG_POSIX_MQUEUE))
	selinux_ipcns_add_hooks(&selinux_lsmid);
#endif

	if (avc_add_callback(selinux_lsm_notifier_avc_callback, AVC_CALLBACK_RESET))
		panic("SELinux: Unable to register AVC LSM notifier callback\n");

	if (avc_add_callback(selinux_audit_rule_avc_callback,
			     AVC_CALLBACK_RESET))
		panic("SELinux: Unable to register AVC audit callback\n");

	if (selinux_enforcing_boot)
		pr_debug("SELinux:  Starting in enforcing mode\n");
	else
		pr_debug("SELinux:  Starting in permissive mode\n");

	fs_validate_description("selinux", selinux_fs_parameters);

	return 0;
}

static void delayed_superblock_init(struct super_block *sb, void *unused)
{
	selinux_set_mnt_opts(sb, NULL, 0, NULL);
}

void selinux_complete_init(void)
{
	pr_debug("SELinux:  Completing initialization.\n");

	/* Set up any superblocks initialized prior to the policy load. */
	pr_debug("SELinux:  Setting up existing superblocks.\n");
	iterate_supers(delayed_superblock_init, NULL);
}

/* SELinux requires early initialization in order to label
   all processes and objects when they are created. */
DEFINE_LSM(selinux) = {
	.id = &selinux_lsmid,
	.flags = LSM_FLAG_LEGACY_MAJOR | LSM_FLAG_EXCLUSIVE,
	.enabled = &selinux_enabled_boot,
	.blobs = &selinux_blob_sizes,
	.init = selinux_init,
	.initcall_core = selinux_initcall_core,
	.initcall_device = selinux_initcall,
};

#if defined(CONFIG_NETFILTER)
static const struct nf_hook_ops selinux_nf_ops[] = {
	{
		.hook =		selinux_ip_postroute,
		.pf =		NFPROTO_IPV4,
		.hooknum =	NF_INET_POST_ROUTING,
		.priority =	NF_IP_PRI_SELINUX_LAST,
	},
	{
		.hook =		selinux_ip_forward,
		.pf =		NFPROTO_IPV4,
		.hooknum =	NF_INET_FORWARD,
		.priority =	NF_IP_PRI_SELINUX_FIRST,
	},
	{
		.hook =		selinux_ip_output,
		.pf =		NFPROTO_IPV4,
		.hooknum =	NF_INET_LOCAL_OUT,
		.priority =	NF_IP_PRI_SELINUX_FIRST,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook =		selinux_ip_postroute,
		.pf =		NFPROTO_IPV6,
		.hooknum =	NF_INET_POST_ROUTING,
		.priority =	NF_IP6_PRI_SELINUX_LAST,
	},
	{
		.hook =		selinux_ip_forward,
		.pf =		NFPROTO_IPV6,
		.hooknum =	NF_INET_FORWARD,
		.priority =	NF_IP6_PRI_SELINUX_FIRST,
	},
	{
		.hook =		selinux_ip_output,
		.pf =		NFPROTO_IPV6,
		.hooknum =	NF_INET_LOCAL_OUT,
		.priority =	NF_IP6_PRI_SELINUX_FIRST,
	},
#endif	/* IPV6 */
};

static int __net_init selinux_nf_register(struct net *net)
{
	return nf_register_net_hooks(net, selinux_nf_ops,
				     ARRAY_SIZE(selinux_nf_ops));
}

static void __net_exit selinux_nf_unregister(struct net *net)
{
	nf_unregister_net_hooks(net, selinux_nf_ops,
				ARRAY_SIZE(selinux_nf_ops));
}

static struct pernet_operations selinux_net_ops = {
	.init = selinux_nf_register,
	.exit = selinux_nf_unregister,
};

int __init selinux_nf_ip_init(void)
{
	int err;

	if (!selinux_enabled_boot)
		return 0;

	pr_debug("SELinux:  Registering netfilter hooks\n");

	err = register_pernet_subsys(&selinux_net_ops);
	if (err)
		panic("SELinux: register_pernet_subsys: error %d\n", err);

	return 0;
}
#endif /* CONFIG_NETFILTER */
