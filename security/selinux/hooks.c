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
#include <net/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sctp.h>
#include <net/sctp/structs.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/export.h>
#include <linux/msg.h>
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
#include "xfrm.h"
#include "netlabel.h"
#include "audit.h"
#include "avc_ss.h"
#include "chain.h"
#include "namespace.h"
#include "object_label.h"

#define SELINUX_INODE_INIT_XATTRS 1

/* SECMARK reference count */
static atomic_t selinux_secmark_refcount = ATOMIC_INIT(0);

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
 *
 * Description:
 * This function checks the SECMARK reference counter to see if any SECMARK
 * targets are currently configured, if the reference counter is greater than
 * zero SECMARK is considered to be enabled.  Returns true (1) if SECMARK is
 * enabled, false (0) if SECMARK is disabled.  If the always_check_network
 * policy capability is enabled, SECMARK is always considered enabled.
 *
 */
static int selinux_secmark_enabled(const struct cred *cred)
{
	return (selinux_chain_any_policycap(
			cred, POLICYDB_CAP_ALWAYSNETWORK) ||
		atomic_read(&selinux_secmark_refcount));
}

/**
 * selinux_peerlbl_enabled - Check to see if peer labeling is currently enabled
 *
 * Description:
 * This function checks if NetLabel or labeled IPSEC is enabled.  Returns true
 * (1) if any are enabled or false (0) if neither are enabled.  If the
 * always_check_network policy capability is enabled, peer labeling
 * is always considered enabled.
 *
 */
static int selinux_peerlbl_enabled(const struct cred *cred)
{
	return (selinux_chain_any_policycap(
			cred, POLICYDB_CAP_ALWAYSNETWORK) ||
		netlbl_enabled() || selinux_xfrm_enabled());
}

static int selinux_netcache_avc_callback(u32 event)
{
	if (event == AVC_CALLBACK_RESET) {
		sel_netif_flush();
		sel_netnode_flush();
		sel_netport_flush();
		synchronize_net();
	}
	return 0;
}

static int selinux_lsm_notifier_avc_callback(u32 event)
{
	if (event == AVC_CALLBACK_RESET) {
		sel_ib_pkey_flush();
		call_blocking_lsm_notifier(LSM_POLICY_CHANGE, NULL);
	}

	return 0;
}

/*
 * initialise the security for the init task
 */
static void cred_init_security(void)
{
	struct cred_security_struct *crsec;

	/* NOTE: the lsm framework zeros out the buffer on allocation */

	crsec = selinux_cred(unrcu_pointer(current->real_cred));
	crsec->osid = crsec->sid = SECINITSID_KERNEL;
	crsec->state = get_selinux_state(init_selinux_state);
	crsec->parent_cred = NULL;
}

/*
 * get the security ID of a set of credentials
 */
static inline u32 cred_sid_disabled(const struct cred *cred)
{
	const struct cred_security_struct *crsec;

	crsec = selinux_cred(cred);
	return crsec->sid;
}

static int selinux_object_init_initial(
	struct selinux_object_identity **slot,
	struct selinux_state *leaf,
	u32 sid,
	u16 sclass,
	enum selinux_label_source source,
	gfp_t gfp)
{
	struct selinux_object_identity *object;

	if (WARN_ON_ONCE(*slot))
		return -EALREADY;
	object = selinux_object_identity_alloc_initial(
		leaf, sid, sclass, source, gfp);
	if (IS_ERR(object))
		return PTR_ERR(object);
	*slot = object;
	return 0;
}

static int selinux_object_init_from_cred(
	struct selinux_object_identity **slot,
	const struct cred *cred,
	u16 sclass,
	enum selinux_label_source source,
	gfp_t gfp)
{
	struct selinux_object_identity *object;

	if (WARN_ON_ONCE(*slot))
		return -EALREADY;
	object = selinux_object_identity_alloc_from_cred(
		cred, sclass, source, gfp);
	if (IS_ERR(object))
		return PTR_ERR(object);
	*slot = object;
	return 0;
}

static void selinux_object_clear(struct selinux_object_identity **slot)
{
	struct selinux_object_identity *object = xchg(slot, NULL);

	selinux_object_identity_put(object);
}

static int selinux_object_set_initial_chain(
	struct selinux_object_identity *object,
	struct selinux_state *leaf,
	u32 sid,
	u16 sclass,
	enum selinux_label_source source,
	gfp_t gfp)
{
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *state;
	u16 count = 0;

	if (!object || !leaf || !sid || !sclass)
		return -EINVAL;
	for (state = leaf; state; state = state->parent) {
		if (count >= ARRAY_SIZE(states))
			return -E2BIG;
		states[count] = state;
		values[count] = (struct selinux_object_label_value) {
			.sid = sid,
			.sclass = sclass,
			.source = source,
		};
		count++;
	}
	return selinux_object_labels_set_chain(
		object, states, values, count, gfp);
}

static int selinux_anon_object_transition_from_cred(
	const struct cred *cred,
	struct selinux_object_identity *destination,
	const struct qstr *name,
	bool memfd,
	gfp_t gfp)
{
	const struct cred *level_cred = cred;
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *state;
	u16 count = 0;

	if (!cred || !destination)
		return -EINVAL;
	state = cred_selinux_state(cred);
	while (state) {
		const struct cred_security_struct *security;
		struct selinux_object_label_value *value;
		int rc;

		if (!level_cred || count >= ARRAY_SIZE(states))
			return -ESTALE;
		security = selinux_cred(level_cred);
		if (security->state != state)
			return -ESTALE;
		states[count] = state;
		value = &values[count];
		if (memfd && !selinux_policycap_memfd_class(state)) {
			/*
			 * Policies without memfd_class retain ordinary file
			 * semantics.  Leave that policy-local label unresolved so
			 * normal inode initialization can derive the tmpfs label on
			 * first use; only policies advertising memfd_class
			 * participate in the specialized creation check below.
			 */
			value->sid = SECINITSID_UNLABELED;
			value->sclass = SECCLASS_FILE;
			value->source = SELINUX_LABEL_SOURCE_UNSPECIFIED;
			goto next;
		}
		value->sclass = memfd ?
			SECCLASS_MEMFD_FILE : SECCLASS_ANON_INODE;
		rc = security_transition_sid(
			state,
			security->sid,
			security->sid,
			value->sclass,
			name,
			&value->sid);
		if (rc)
			return rc;
		value->source = SELINUX_LABEL_SOURCE_TRANSITION;
next:
		count++;
		level_cred = security->parent_cred;
		state = state->parent;
	}
	if (level_cred)
		return -ESTALE;
	return selinux_object_labels_set_chain(
		destination, states, values, count, gfp);
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

static int inode_doinit_with_dentry(
	const struct cred *cred,
	struct inode *inode,
	struct dentry *opt_dentry);

static bool selinux_inode_labels_ready(
	const struct cred *cred,
	const struct inode_security_struct *isec)
{
	const struct cred *level_cred = cred;
	struct selinux_state *state;
	u64 generation;
	u16 depth = 0;

	if (!cred || !isec || !isec->object)
		return false;
	generation = selinux_object_identity_generation(isec->object);
	if (!generation)
		return false;
	state = cred_selinux_state(cred);
	while (state) {
		const struct cred_security_struct *security;
		struct selinux_object_label_value value;

		if (!level_cred || depth++ > SELINUX_NS_MAX_DEPTH)
			return false;
		security = selinux_cred(level_cred);
		if (security->state != state)
			return false;
		if (selinux_initialized(state)) {
			if (selinux_object_label_get(state, isec->object, &value) ||
			    value.source == SELINUX_LABEL_SOURCE_UNSPECIFIED)
				return false;
		}
		level_cred = security->parent_cred;
		state = state->parent;
	}
	return !level_cred &&
	       generation == selinux_object_identity_generation(isec->object);
}

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
	struct inode_security_struct *isec = selinux_inode(inode);

	if (selinux_inode_labels_ready(current_cred(), isec))
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
	inode_doinit_with_dentry(current_cred(), inode, dentry);
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

	if (likely(selinux_inode_labels_ready(current_cred(), isec)))
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

	if (likely(selinux_inode_labels_ready(current_cred(), isec)))
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

	if (likely(selinux_inode_labels_ready(current_cred(), isec)))
		return isec;
	__inode_security_revalidate(inode, dentry, true);
	return isec;
}

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
}

struct selinux_mnt_opts {
	struct selinux_state *state;
	u32 fscontext_sid;
	u32 context_sid;
	u32 rootcontext_sid;
	u32 defcontext_sid;
};

static void selinux_free_mnt_opts(void *mnt_opts)
{
	struct selinux_mnt_opts *opts = mnt_opts;

	if (!opts)
		return;
	put_selinux_state(opts->state);
	kfree(opts);
}

enum {
	Opt_error = -1,
	Opt_context = 0,
	Opt_defcontext = 1,
	Opt_fscontext = 2,
	Opt_rootcontext = 3,
	Opt_seclabel = 4,
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

struct selinux_superblock_labels {
	struct selinux_object_label_value filesystem;
	struct selinux_object_label_value default_inode;
	struct selinux_object_label_value mountpoint;
	struct selinux_object_label_value creator;
};

static int selinux_superblock_labels_get(
	const struct selinux_state *state,
	const struct superblock_security_struct *sbsec,
	struct selinux_superblock_labels *labels)
{
	struct selinux_object_identity *objects[4];
	u64 generations[ARRAY_SIZE(objects)];
	unsigned int retry;
	unsigned int index;

	if (!state || !sbsec || !labels || !sbsec->object ||
	    !sbsec->default_object || !sbsec->mountpoint_object ||
	    !sbsec->creator_object)
		return -EUCLEAN;
	objects[0] = sbsec->object;
	objects[1] = sbsec->default_object;
	objects[2] = sbsec->mountpoint_object;
	objects[3] = sbsec->creator_object;

	for (retry = 0; retry < 4; retry++) {
		for (index = 0; index < ARRAY_SIZE(objects); index++) {
			generations[index] =
				selinux_object_identity_generation(objects[index]);
			if (!generations[index])
				break;
		}
		if (index != ARRAY_SIZE(objects))
			continue;
		selinux_object_label_get_or_initial(
			state, objects[0], SECINITSID_UNLABELED,
			SECCLASS_FILESYSTEM,
			SELINUX_LABEL_SOURCE_FILESYSTEM,
			&labels->filesystem);
		selinux_object_label_get_or_initial(
			state, objects[1], SECINITSID_FILE,
			SECCLASS_FILE,
			SELINUX_LABEL_SOURCE_FILESYSTEM,
			&labels->default_inode);
		selinux_object_label_get_or_initial(
			state, objects[2], SECINITSID_UNLABELED,
			SECCLASS_FILE,
			SELINUX_LABEL_SOURCE_MOUNT_CONTEXT,
			&labels->mountpoint);
		selinux_object_label_get_or_initial(
			state, objects[3], SECINITSID_UNLABELED,
			SECCLASS_FILESYSTEM,
			SELINUX_LABEL_SOURCE_TASK,
			&labels->creator);
		for (index = 0; index < ARRAY_SIZE(objects); index++)
			if (generations[index] !=
			    selinux_object_identity_generation(objects[index]))
				break;
		if (index == ARRAY_SIZE(objects))
			return 0;
	}
	return -ESTALE;
}

static int may_context_mount_sb_relabel(
	struct selinux_state *state,
	u32 old_sid,
	u32 new_sid,
	const struct cred *cred)
{
	const struct cred_security_struct *crsec = selinux_cred(cred);
	int rc;

	if (!state || crsec->state != state)
		return -ESTALE;
	rc = avc_has_perm_disabled(
		state,
		crsec->sid,
		old_sid,
		SECCLASS_FILESYSTEM,
		FILESYSTEM__RELABELFROM,
		NULL);
	if (rc)
		return rc;

	return avc_has_perm_disabled(
		state,
		crsec->sid,
		new_sid,
		SECCLASS_FILESYSTEM,
		FILESYSTEM__RELABELTO,
		NULL);
}

static int may_context_mount_inode_relabel(
	struct selinux_state *state,
	u32 filesystem_sid,
	u32 inode_sid,
	const struct cred *cred)
{
	const struct cred_security_struct *crsec = selinux_cred(cred);
	int rc;

	if (!state || crsec->state != state)
		return -ESTALE;
	rc = avc_has_perm_disabled(
		state,
		crsec->sid,
		filesystem_sid,
		SECCLASS_FILESYSTEM,
		FILESYSTEM__RELABELFROM,
		NULL);
	if (rc)
		return rc;

	return avc_has_perm_disabled(
		state,
		inode_sid,
		filesystem_sid,
		SECCLASS_FILESYSTEM,
		FILESYSTEM__ASSOCIATE,
		NULL);
}

static int selinux_is_genfs_special_handling(
	const struct selinux_state *state,
	struct super_block *sb)
{
	/* Special handling. Genfs but also in-core setxattr handler */
	return	!strcmp(sb->s_type->name, "sysfs") ||
		!strcmp(sb->s_type->name, "pstore") ||
		!strcmp(sb->s_type->name, "debugfs") ||
		!strcmp(sb->s_type->name, "tracefs") ||
		!strcmp(sb->s_type->name, "rootfs") ||
		(selinux_policycap_cgroupseclabel(state) &&
		 (!strcmp(sb->s_type->name, "cgroup") ||
		  !strcmp(sb->s_type->name, "cgroup2"))) ||
		(selinux_policycap_functionfs_seclabel(state) &&
		 !strcmp(sb->s_type->name, "functionfs"));
}

static int selinux_is_sblabel_mnt(
	const struct selinux_state *state,
	struct super_block *sb,
	const struct selinux_object_label_value *filesystem)
{
	/*
	 * IMPORTANT: Double-check logic in this function when adding a new
	 * SECURITY_FS_USE_* definition!
	 */
	BUILD_BUG_ON(SECURITY_FS_USE_MAX != 7);

	switch (filesystem->filesystem_behavior) {
	case SECURITY_FS_USE_XATTR:
	case SECURITY_FS_USE_TRANS:
	case SECURITY_FS_USE_TASK:
	case SECURITY_FS_USE_NATIVE:
		return 1;

	case SECURITY_FS_USE_GENFS:
		return selinux_is_genfs_special_handling(state, sb);

	/* Never allow relabeling on context mounts */
	case SECURITY_FS_USE_MNTPOINT:
	case SECURITY_FS_USE_NONE:
	default:
		return 0;
	}
}

static int sb_check_xattr_support(
	struct selinux_state *state,
	struct super_block *sb,
	struct selinux_object_label_value *filesystem)
{
	struct dentry *root = sb->s_root;
	struct inode *root_inode = d_backing_inode(root);
	u32 sid;
	int rc;

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
	rc = security_genfs_sid(
		state,
		sb->s_type->name,
		"/",
		SECCLASS_DIR,
		&sid);
	if (rc)
		return -EOPNOTSUPP;

	pr_warn("SELinux: (dev %s, type %s) falling back to genfs\n",
		sb->s_id, sb->s_type->name);
	filesystem->filesystem_behavior = SECURITY_FS_USE_GENFS;
	filesystem->sid = sid;
	return 0;
}

static int selinux_superblock_initialize_inodes(struct super_block *sb)
{
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct dentry *root = sb->s_root;
	struct inode *root_inode = d_backing_inode(root);
	int rc;

	/* Initialize the root inode. */
	rc = inode_doinit_with_dentry(current_cred(), root_inode, root);

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
				inode_doinit_with_dentry(current_cred(), inode, NULL);
			iput(inode);
		}
		spin_lock(&sbsec->isec_lock);
	}
	spin_unlock(&sbsec->isec_lock);
	return rc;
}

static int bad_option(u16 filesystem_flags, char flag,
		      u32 old_sid, u32 new_sid)
{
	u16 mount_flags = filesystem_flags & SE_MNTMASK;

	/* check if the old mount command had the same options */
	if (filesystem_flags & SE_SBINITIALIZED)
		if (!(filesystem_flags & flag) ||
		    (old_sid != new_sid))
			return 1;

	/* check if we were passed the same options twice,
	 * aka someone passed context=a,context=b
	 */
	if (!(filesystem_flags & SE_SBINITIALIZED))
		if (mount_flags & flag)
			return 1;
	return 0;
}

struct selinux_mount_state_plan {
	struct selinux_state *state;
	const struct cred *cred;
	struct selinux_superblock_labels labels;
	struct selinux_object_label_value root;
	bool dirty;
	bool root_dirty;
};

static bool selinux_userns_mount_uses_contexts(struct super_block *sb)
{
	return sb->s_user_ns == &init_user_ns ||
	       !strcmp(sb->s_type->name, "tmpfs") ||
	       !strcmp(sb->s_type->name, "ramfs") ||
	       !strcmp(sb->s_type->name, "devpts") ||
	       !strcmp(sb->s_type->name, "overlay");
}

static int selinux_mount_plan_publish(
	struct superblock_security_struct *sbsec,
	struct inode_security_struct *root_isec,
	struct selinux_mount_state_plan *plans,
	u16 count)
{
	struct selinux_object_label_update *updates;
	u16 update_count = 0;
	u16 index;
	int rc;

	updates = kcalloc(count * 5, sizeof(*updates), GFP_KERNEL_ACCOUNT);
	if (!updates)
		return -ENOMEM;
	for (index = 0; index < count; index++) {
		struct selinux_mount_state_plan *plan = &plans[index];

		if (!plan->dirty)
			continue;
		updates[update_count++] = (struct selinux_object_label_update) {
			.state = plan->state,
			.object = sbsec->object,
			.value = plan->labels.filesystem,
		};
		updates[update_count++] = (struct selinux_object_label_update) {
			.state = plan->state,
			.object = sbsec->default_object,
			.value = plan->labels.default_inode,
		};
		updates[update_count++] = (struct selinux_object_label_update) {
			.state = plan->state,
			.object = sbsec->mountpoint_object,
			.value = plan->labels.mountpoint,
		};
		updates[update_count++] = (struct selinux_object_label_update) {
			.state = plan->state,
			.object = sbsec->creator_object,
			.value = plan->labels.creator,
		};
		if (plan->root_dirty)
			updates[update_count++] =
				(struct selinux_object_label_update) {
					.state = plan->state,
					.object = root_isec->object,
					.value = plan->root,
				};
	}
	if (!update_count) {
		kfree(updates);
		return 0;
	}
	rc = selinux_object_labels_update_transaction(
		updates,
		update_count,
		GFP_KERNEL_ACCOUNT);
	kfree(updates);
	return rc;
}

/*
 * Allow filesystems with binary mount data to explicitly set mount point
 * labeling information.  Every policy state computes its own labels first;
 * publication is one multi-object transaction.
 */
static int selinux_set_mnt_opts_for_cred(
	struct super_block *sb,
	void *mnt_opts,
	unsigned long kern_flags,
	unsigned long *set_kern_flags,
	const struct cred *cred,
	bool initialize_deferred_inodes)
{
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct inode_security_struct *root_isec;
	struct selinux_mount_state_plan *plans;
	struct selinux_mnt_opts *opts = mnt_opts;
	const struct cred *level_cred = cred;
	struct selinux_state *state = cred_selinux_state(level_cred);
	u16 count = 0;
	u16 index;
	int rc = 0;
	bool initialize_inodes = false;

	if (kern_flags && !set_kern_flags)
		return -EINVAL;
	if (!sb->s_root)
		return -EAGAIN;
	root_isec = backing_inode_security_novalidate(sb->s_root);
	if (!root_isec || !root_isec->object)
		return -EUCLEAN;
	if (opts && opts->state != state)
		return -EXDEV;

	plans = kcalloc(
		SELINUX_NS_MAX_DEPTH + 1,
		sizeof(*plans),
		GFP_KERNEL_ACCOUNT);
	if (!plans)
		return -ENOMEM;

	mutex_lock(&sbsec->lock);
	while (state) {
		const struct cred_security_struct *security;
		struct selinux_mount_state_plan *plan;

		if (!level_cred || count >= SELINUX_NS_MAX_DEPTH + 1) {
			rc = -ESTALE;
			goto out;
		}
		security = selinux_cred(level_cred);
		if (security->state != state) {
			rc = -ESTALE;
			goto out;
		}
		plan = &plans[count++];
		plan->state = state;
		plan->cred = level_cred;
		rc = selinux_superblock_labels_get(
			state,
			sbsec,
			&plan->labels);
		if (rc)
			goto out;
		selinux_object_label_get_or_initial(
			state,
			root_isec->object,
			SECINITSID_UNLABELED,
			root_isec->sclass,
			SELINUX_LABEL_SOURCE_UNSPECIFIED,
			&plan->root);
		level_cred = security->parent_cred;
		state = state->parent;
	}
	if (level_cred) {
		rc = -ESTALE;
		goto out;
	}

	for (index = 0; index < count; index++) {
		struct selinux_mount_state_plan *plan = &plans[index];
		const struct cred_security_struct *security =
			selinux_cred(plan->cred);
		struct selinux_object_label_value *filesystem =
			&plan->labels.filesystem;
		u16 *flags = &filesystem->filesystem_flags;
		bool leaf = index == 0;
		u32 fscontext_sid = leaf && opts ? opts->fscontext_sid : 0;
		u32 context_sid = leaf && opts ? opts->context_sid : 0;
		u32 rootcontext_sid =
			leaf && opts ? opts->rootcontext_sid : 0;
		u32 defcontext_sid = leaf && opts ? opts->defcontext_sid : 0;

		if ((*flags & SE_SBINITIALIZED) &&
		    (sb->s_type->fs_flags & FS_BINARY_MOUNTDATA) &&
		    leaf && !opts)
			continue;

		if (leaf && opts) {
			if (fscontext_sid &&
			    bad_option(*flags, FSCONTEXT_MNT,
				       filesystem->sid, fscontext_sid))
				goto double_mount;
			if (context_sid &&
			    bad_option(*flags, CONTEXT_MNT,
				       plan->labels.mountpoint.sid,
				       context_sid))
				goto double_mount;
			if (rootcontext_sid &&
			    bad_option(*flags, ROOTCONTEXT_MNT,
				       plan->root.sid, rootcontext_sid))
				goto double_mount;
			if (defcontext_sid &&
			    bad_option(*flags, DEFCONTEXT_MNT,
				       plan->labels.default_inode.sid,
				       defcontext_sid))
				goto double_mount;
		}

		if (*flags & SE_SBINITIALIZED) {
			if (leaf && !opts && (*flags & SE_MNTMASK))
				goto double_mount;
			continue;
		}

		if (!selinux_initialized(plan->state)) {
			if (leaf && opts) {
				rc = -EINVAL;
				pr_warn("SELinux: Unable to set superblock options before the security server is initialized\n");
				goto out;
			}
			if (kern_flags & SECURITY_LSM_NATIVE_LABELS) {
				*flags |= SE_SBNATIVE;
				plan->dirty = true;
				if (leaf)
					*set_kern_flags |=
						SECURITY_LSM_NATIVE_LABELS;
			}
			continue;
		}

		plan->labels.creator = (struct selinux_object_label_value) {
			.sid = security->sid,
			.sclass = SECCLASS_FILESYSTEM,
			.source = SELINUX_LABEL_SOURCE_TASK,
		};
		plan->dirty = true;

		if (!strcmp(sb->s_type->name, "proc"))
			*flags |= SE_SBPROC | SE_SBGENFS;
		if (!strcmp(sb->s_type->name, "debugfs") ||
		    !strcmp(sb->s_type->name, "tracefs") ||
		    !strcmp(sb->s_type->name, "binder") ||
		    !strcmp(sb->s_type->name, "bpf") ||
		    !strcmp(sb->s_type->name, "pstore") ||
		    !strcmp(sb->s_type->name, "securityfs") ||
		    (selinux_policycap_functionfs_seclabel(plan->state) &&
		     !strcmp(sb->s_type->name, "functionfs")))
			*flags |= SE_SBGENFS;
		if (!strcmp(sb->s_type->name, "sysfs") ||
		    !strcmp(sb->s_type->name, "cgroup") ||
		    !strcmp(sb->s_type->name, "cgroup2"))
			*flags |= SE_SBGENFS | SE_SBGENFS_XATTR;

		if (!filesystem->filesystem_behavior) {
			rc = security_fs_use(
				plan->state,
				sb,
				&filesystem->filesystem_behavior,
				&filesystem->sid);
			if (rc) {
				pr_warn("%s: security_fs_use(%s) returned %d\n",
					__func__, sb->s_type->name, rc);
				goto out;
			}
		}

		if (!selinux_userns_mount_uses_contexts(sb)) {
			if (leaf && (context_sid || fscontext_sid ||
				     rootcontext_sid || defcontext_sid)) {
				rc = -EACCES;
				goto out;
			}
			if (filesystem->filesystem_behavior ==
			    SECURITY_FS_USE_XATTR) {
				filesystem->filesystem_behavior =
					SECURITY_FS_USE_MNTPOINT;
				rc = security_transition_sid(
					plan->state,
					security->sid,
					security->sid,
					SECCLASS_FILE,
					NULL,
					&plan->labels.mountpoint.sid);
				if (rc)
					goto out;
			}
			goto finish_plan;
		}

		if (fscontext_sid) {
			rc = may_context_mount_sb_relabel(
				plan->state,
				filesystem->sid,
				fscontext_sid,
				plan->cred);
			if (rc)
				goto out;
			filesystem->sid = fscontext_sid;
			filesystem->source =
				SELINUX_LABEL_SOURCE_MOUNT_CONTEXT;
			*flags |= FSCONTEXT_MNT;
		}

		if (*flags & SE_SBNATIVE) {
			filesystem->filesystem_behavior =
				SECURITY_FS_USE_NATIVE;
		} else if ((kern_flags & SECURITY_LSM_NATIVE_LABELS) &&
			   !context_sid) {
			filesystem->filesystem_behavior =
				SECURITY_FS_USE_NATIVE;
			if (leaf)
				*set_kern_flags |= SECURITY_LSM_NATIVE_LABELS;
		}

		if (context_sid) {
			if (!fscontext_sid)
				rc = may_context_mount_sb_relabel(
					plan->state,
					filesystem->sid,
					context_sid,
					plan->cred);
			else
				rc = may_context_mount_inode_relabel(
					plan->state,
					filesystem->sid,
					context_sid,
					plan->cred);
			if (rc)
				goto out;
			if (!fscontext_sid)
				filesystem->sid = context_sid;
			plan->labels.mountpoint.sid = context_sid;
			plan->labels.mountpoint.source =
				SELINUX_LABEL_SOURCE_MOUNT_CONTEXT;
			filesystem->filesystem_behavior =
				SECURITY_FS_USE_MNTPOINT;
			*flags |= CONTEXT_MNT;
			if (!rootcontext_sid)
				rootcontext_sid = context_sid;
		}

		if (rootcontext_sid) {
			rc = may_context_mount_inode_relabel(
				plan->state,
				filesystem->sid,
				rootcontext_sid,
				plan->cred);
			if (rc)
				goto out;
			plan->root.sid = rootcontext_sid;
			plan->root.sclass = root_isec->sclass;
			plan->root.source =
				SELINUX_LABEL_SOURCE_MOUNT_CONTEXT;
			plan->root_dirty = true;
			*flags |= ROOTCONTEXT_MNT;
		}

		if (defcontext_sid) {
			if (filesystem->filesystem_behavior !=
				    SECURITY_FS_USE_XATTR &&
			    filesystem->filesystem_behavior !=
				    SECURITY_FS_USE_NATIVE) {
				rc = -EINVAL;
				pr_warn("SELinux: defcontext option is invalid for this filesystem type\n");
				goto out;
			}
			if (defcontext_sid !=
			    plan->labels.default_inode.sid) {
				rc = may_context_mount_inode_relabel(
					plan->state,
					filesystem->sid,
					defcontext_sid,
					plan->cred);
				if (rc)
					goto out;
			}
			plan->labels.default_inode.sid = defcontext_sid;
			plan->labels.default_inode.source =
				SELINUX_LABEL_SOURCE_MOUNT_CONTEXT;
			*flags |= DEFCONTEXT_MNT;
		}

finish_plan:
		if (filesystem->filesystem_behavior == SECURITY_FS_USE_XATTR) {
			rc = sb_check_xattr_support(
				plan->state,
				sb,
				filesystem);
			if (rc)
				goto out;
		}
		*flags |= SE_SBINITIALIZED;
		if (selinux_is_sblabel_mnt(
			    plan->state, sb, filesystem))
			*flags |= SBLABEL_MNT;
		else
			*flags &= ~SBLABEL_MNT;
		initialize_inodes = true;
	}

	rc = selinux_mount_plan_publish(sbsec, root_isec, plans, count);
	goto out;

double_mount:
	rc = -EINVAL;
	pr_warn("SELinux: mount invalid. Same superblock, different security settings for (dev %s, type %s)\n",
		sb->s_id, sb->s_type->name);
out:
	mutex_unlock(&sbsec->lock);
	kfree(plans);
	if (!rc && initialize_inodes && initialize_deferred_inodes)
		rc = selinux_superblock_initialize_inodes(sb);
	return rc;
}

static int selinux_cmp_sb_context(const struct super_block *oldsb,
				  const struct super_block *newsb)
{
	const struct superblock_security_struct *old =
		selinux_superblock(oldsb);
	const struct superblock_security_struct *new =
		selinux_superblock(newsb);
	const struct inode_security_struct *oldroot =
		backing_inode_security_novalidate(oldsb->s_root);
	const struct inode_security_struct *newroot =
		backing_inode_security_novalidate(newsb->s_root);
	struct selinux_state *state = current_selinux_state;
	u16 depth = 0;

	if (!oldroot || !oldroot->object || !newroot || !newroot->object)
		return -EUCLEAN;
	while (state) {
		struct selinux_superblock_labels old_labels;
		struct selinux_superblock_labels new_labels;
		u16 old_flags;
		u16 new_flags;
		int rc;

		if (depth++ > SELINUX_NS_MAX_DEPTH)
			return -E2BIG;
		rc = selinux_superblock_labels_get(state, old, &old_labels);
		if (rc)
			return rc;
		rc = selinux_superblock_labels_get(state, new, &new_labels);
		if (rc)
			return rc;
		old_flags = old_labels.filesystem.filesystem_flags &
			SE_MNTMASK;
		new_flags = new_labels.filesystem.filesystem_flags &
			SE_MNTMASK;
		if (old_flags != new_flags)
			goto mismatch;
		if ((old_flags & FSCONTEXT_MNT) &&
		    old_labels.filesystem.sid != new_labels.filesystem.sid)
			goto mismatch;
		if ((old_flags & CONTEXT_MNT) &&
		    old_labels.mountpoint.sid != new_labels.mountpoint.sid)
			goto mismatch;
		if ((old_flags & DEFCONTEXT_MNT) &&
		    old_labels.default_inode.sid !=
			new_labels.default_inode.sid)
			goto mismatch;
		if (old_flags & ROOTCONTEXT_MNT) {
			struct selinux_object_label_value old_root_label;
			struct selinux_object_label_value new_root_label;

			selinux_object_label_get_or_unlabeled(
				state,
				oldroot->object,
				oldroot->sclass,
				&old_root_label);
			selinux_object_label_get_or_unlabeled(
				state,
				newroot->object,
				newroot->sclass,
				&new_root_label);
			if (old_root_label.sid != new_root_label.sid)
				goto mismatch;
		}
		if (old_labels.creator.sid != new_labels.creator.sid)
			goto mismatch;
		state = state->parent;
	}
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
	const struct superblock_security_struct *oldsbsec =
		selinux_superblock(oldsb);
	struct superblock_security_struct *newsbsec = selinux_superblock(newsb);
	struct inode_security_struct *oldroot =
		backing_inode_security_novalidate(oldsb->s_root);
	struct inode_security_struct *newroot =
		backing_inode_security_novalidate(newsb->s_root);
	struct selinux_mount_state_plan *plans;
	struct selinux_state *state = current_selinux_state;
	u16 count = 0;
	int rc = 0;
	bool initialize_inodes = false;

	if (kern_flags && !set_kern_flags)
		return -EINVAL;
	if (!oldroot || !oldroot->object || !newroot || !newroot->object)
		return -EUCLEAN;
	plans = kcalloc(
		SELINUX_NS_MAX_DEPTH + 1,
		sizeof(*plans),
		GFP_KERNEL_ACCOUNT);
	if (!plans)
		return -ENOMEM;

	mutex_lock(&newsbsec->lock);
	while (state) {
		struct selinux_mount_state_plan *plan;
		struct selinux_superblock_labels new_labels;
		struct selinux_object_label_value old_root_label;
		u16 flags;

		if (count >= SELINUX_NS_MAX_DEPTH + 1) {
			rc = -E2BIG;
			goto out;
		}
		plan = &plans[count++];
		plan->state = state;
		rc = selinux_superblock_labels_get(
			state,
			oldsbsec,
			&plan->labels);
		if (rc)
			goto out;
		rc = selinux_superblock_labels_get(
			state,
			newsbsec,
			&new_labels);
		if (rc)
			goto out;
		flags = plan->labels.filesystem.filesystem_flags;
		if (selinux_initialized(state) &&
		    !(flags & SE_SBINITIALIZED)) {
			rc = -EUCLEAN;
			goto out;
		}
		if (new_labels.filesystem.filesystem_flags &
		    SE_SBINITIALIZED) {
			mutex_unlock(&newsbsec->lock);
			kfree(plans);
			if ((kern_flags & SECURITY_LSM_NATIVE_LABELS) &&
			    !(flags & CONTEXT_MNT))
				*set_kern_flags |= SECURITY_LSM_NATIVE_LABELS;
			return selinux_cmp_sb_context(oldsb, newsb);
		}

		if (!selinux_initialized(state)) {
			if (kern_flags & SECURITY_LSM_NATIVE_LABELS) {
				plan->labels.filesystem.filesystem_flags |=
					SE_SBNATIVE;
				if (state == current_selinux_state)
					*set_kern_flags |=
						SECURITY_LSM_NATIVE_LABELS;
			}
			plan->dirty = true;
			state = state->parent;
			continue;
		}

		if (plan->labels.filesystem.filesystem_behavior ==
			    SECURITY_FS_USE_NATIVE &&
		    !(kern_flags & SECURITY_LSM_NATIVE_LABELS) &&
		    !(flags & CONTEXT_MNT)) {
			rc = security_fs_use(
				state,
				newsb,
				&plan->labels.filesystem.filesystem_behavior,
				&plan->labels.filesystem.sid);
			if (rc)
				goto out;
		}
		if ((kern_flags & SECURITY_LSM_NATIVE_LABELS) &&
		    !(flags & CONTEXT_MNT)) {
			plan->labels.filesystem.filesystem_behavior =
				SECURITY_FS_USE_NATIVE;
			if (state == current_selinux_state)
				*set_kern_flags |= SECURITY_LSM_NATIVE_LABELS;
		}

		selinux_object_label_get_or_unlabeled(
			state,
			oldroot->object,
			oldroot->sclass,
			&old_root_label);
		plan->root = old_root_label;
		if (flags & CONTEXT_MNT) {
			u32 sid = plan->labels.mountpoint.sid;

			if (!(flags & FSCONTEXT_MNT))
				plan->labels.filesystem.sid = sid;
			if (!(flags & ROOTCONTEXT_MNT)) {
				plan->root.sid = sid;
				plan->root.source =
					SELINUX_LABEL_SOURCE_MOUNT_CONTEXT;
			}
			plan->root_dirty = true;
		}
		if (flags & ROOTCONTEXT_MNT)
			plan->root_dirty = true;
		plan->dirty = true;
		state = state->parent;
	}

	rc = selinux_mount_plan_publish(newsbsec, newroot, plans, count);
	if (rc)
		goto out;
	put_selinux_state(newsbsec->persistent_label_owner);
	newsbsec->persistent_label_owner = get_selinux_state(
		oldsbsec->persistent_label_owner);
	initialize_inodes = true;
out:
	mutex_unlock(&newsbsec->lock);
	kfree(plans);
	if (!rc && initialize_inodes)
		rc = selinux_superblock_initialize_inodes(newsb);
	return rc;
}

static int selinux_set_mnt_opts(struct super_block *sb,
				void *mnt_opts,
				unsigned long kern_flags,
				unsigned long *set_kern_flags)
{
	return selinux_set_mnt_opts_for_cred(
		sb,
		mnt_opts,
		kern_flags,
		set_kern_flags,
		current_cred(),
		true);
}

/*
 * NOTE: the caller is responsible for freeing the memory even if on error.
 */
static int selinux_add_opt(int token, const char *s, void **mnt_opts)
{
	struct selinux_mnt_opts *opts = *mnt_opts;
	u32 *dst_sid;
	int rc;

	if (token == Opt_seclabel)
		/* eaten and completely ignored */
		return 0;
	if (!s)
		return -EINVAL;

	if (!selinux_initialized(current_selinux_state)) {
		pr_warn("SELinux: Unable to set superblock options before the security server is initialized\n");
		return -EINVAL;
	}

	if (!opts) {
		opts = kzalloc_obj(*opts);
		if (!opts)
			return -ENOMEM;
		opts->state = get_selinux_state(current_selinux_state);
		*mnt_opts = opts;
	}
	if (opts->state != current_selinux_state)
		return -EXDEV;

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
	rc = security_context_str_to_sid(opts->state, s, dst_sid, GFP_KERNEL);
	if (rc)
		pr_warn("SELinux: security_context_str_to_sid (%s) failed with errno=%d\n",
			s, rc);
	return rc;

err:
	pr_warn(SEL_MOUNT_FAIL_MSG);
	return -EINVAL;
}

static int show_sid(
	struct selinux_state *state,
	struct seq_file *m,
	u32 sid)
{
	char *context = NULL;
	u32 len;
	int rc;

	rc = security_sid_to_context(state, sid, &context, &len);
	if (!rc) {
		bool has_comma = strchr(context, ',');

		seq_putc(m, '=');
		if (has_comma)
			seq_putc(m, '\"');
		seq_escape(m, context, "\"\n\\");
		if (has_comma)
			seq_putc(m, '\"');
	}
	kfree(context);
	return rc;
}

static int selinux_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct selinux_superblock_labels labels;
	struct selinux_state *state = current_selinux_state;
	u16 flags;
	int rc;

	rc = selinux_superblock_labels_get(state, sbsec, &labels);
	if (rc)
		return rc;
	flags = labels.filesystem.filesystem_flags;
	if (!(flags & SE_SBINITIALIZED))
		return 0;

	if (!selinux_initialized(state))
		return 0;

	if (flags & FSCONTEXT_MNT) {
		seq_putc(m, ',');
		seq_puts(m, FSCONTEXT_STR);
		rc = show_sid(state, m, labels.filesystem.sid);
		if (rc)
			return rc;
	}
	if (flags & CONTEXT_MNT) {
		seq_putc(m, ',');
		seq_puts(m, CONTEXT_STR);
		rc = show_sid(state, m, labels.mountpoint.sid);
		if (rc)
			return rc;
	}
	if (flags & DEFCONTEXT_MNT) {
		seq_putc(m, ',');
		seq_puts(m, DEFCONTEXT_STR);
		rc = show_sid(state, m, labels.default_inode.sid);
		if (rc)
			return rc;
	}
	if (flags & ROOTCONTEXT_MNT) {
		struct dentry *root = sb->s_root;
		struct inode_security_struct *isec = backing_inode_security(root);
		struct selinux_object_label_value root_label;

		if (!isec || !isec->object)
			return -EUCLEAN;
		selinux_object_label_get_or_unlabeled(
			state,
			isec->object,
			isec->sclass,
			&root_label);
		seq_putc(m, ',');
		seq_puts(m, ROOTCONTEXT_STR);
		rc = show_sid(state, m, root_label.sid);
		if (rc)
			return rc;
	}
	if (flags & SBLABEL_MNT) {
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

static inline u16 socket_type_to_security_class(
	const struct selinux_state *state,
	int family,
	int type,
	int protocol)
{
	bool extsockclass = selinux_policycap_extsockclass(state);

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

static int selinux_genfs_get_sid(struct selinux_state *state,
				 struct dentry *dentry,
				 u16 tclass,
				 u16 flags,
				 u32 *sid)
{
	int rc;
	struct super_block *sb = dentry->d_sb;
	char *buffer, *path;

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
		rc = security_genfs_sid(state, sb->s_type->name,
					path, tclass, sid);
		if (rc == -ENOENT) {
			/* No match in policy, mark as unlabeled. */
			*sid = SECINITSID_UNLABELED;
			rc = 0;
		}
	}
	free_page((unsigned long)buffer);
	return rc;
}

static int inode_doinit_use_xattr(
	struct selinux_state *state,
	struct inode *inode,
	struct dentry *dentry,
	u32 def_sid,
	u32 *sid,
	u8 *source)
{
#define INITCONTEXTLEN 255
	char *context;
	unsigned int len;
	int rc;

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

	rc = security_context_to_sid_default(state, context, rc, sid,
					     def_sid, GFP_NOFS);
	if (!rc)
		*source = SELINUX_LABEL_SOURCE_XATTR;
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

#define SELINUX_INODE_INIT_RETRIES 4U

struct selinux_inode_state_plan {
	struct selinux_state *state;
	struct selinux_superblock_labels superblock;
	struct selinux_object_label_value value;
	bool update;
};

static void selinux_inode_defer_initialization(
	struct superblock_security_struct *sbsec,
	struct inode_security_struct *isec)
{
	spin_lock(&sbsec->isec_lock);
	if (list_empty(&isec->list))
		list_add_tail(&isec->list, &sbsec->isec_head);
	spin_unlock(&sbsec->isec_lock);
}

static struct dentry *selinux_inode_find_dentry(
	struct inode *inode,
	struct dentry *opt_dentry)
{
	struct dentry *dentry;

	if (opt_dentry)
		return dget(opt_dentry);
	dentry = d_find_alias(inode);
	if (!dentry)
		dentry = d_find_any_alias(inode);
	return dentry;
}

static bool selinux_superblock_generations_read(
	const struct superblock_security_struct *sbsec,
	u64 generations[4])
{
	struct selinux_object_identity *objects[] = {
		sbsec->object,
		sbsec->default_object,
		sbsec->mountpoint_object,
		sbsec->creator_object,
	};
	unsigned int index;

	for (index = 0; index < ARRAY_SIZE(objects); index++) {
		generations[index] =
			selinux_object_identity_generation(objects[index]);
		if (!generations[index])
			return false;
	}
	return true;
}

static bool selinux_superblock_generations_match(
	const struct superblock_security_struct *sbsec,
	const u64 generations[4])
{
	u64 observed[4];
	unsigned int index;

	if (!selinux_superblock_generations_read(sbsec, observed))
		return false;
	for (index = 0; index < ARRAY_SIZE(observed); index++)
		if (observed[index] != generations[index])
			return false;
	return true;
}

static struct selinux_state *selinux_persistent_label_owner_get(
	struct superblock_security_struct *sbsec)
{
	struct selinux_state *owner;

	mutex_lock(&sbsec->lock);
	owner = get_selinux_state(sbsec->persistent_label_owner);
	mutex_unlock(&sbsec->lock);
	return owner;
}

static int selinux_superblock_ensure_ancestry(
	const struct cred *cred,
	struct super_block *sb)
{
	const struct cred *level_cred = cred;
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct selinux_state *state = cred_selinux_state(level_cred);

	while (state) {
		const struct cred_security_struct *security;
		struct selinux_superblock_labels labels;
		int rc;

		if (!level_cred)
			return -ESTALE;
		security = selinux_cred(level_cred);
		if (security->state != state)
			return -ESTALE;
		if (selinux_initialized(state)) {
			rc = selinux_superblock_labels_get(
				state,
				sbsec,
				&labels);
			if (rc)
				return rc;
			if (!(labels.filesystem.filesystem_flags &
			      SE_SBINITIALIZED)) {
				/*
				 * Filesystems may instantiate their root inode while
				 * ->get_tree() is still constructing the superblock.  At
				 * that point sb->s_root has not been published and mount
				 * labeling must remain deferred until
				 * security_sb_set_mnt_opts().
				 */
				if (!READ_ONCE(sb->s_root))
					return 0;
				return selinux_set_mnt_opts_for_cred(
					sb,
					NULL,
					0,
					NULL,
					cred,
					false);
			}
		}
		level_cred = security->parent_cred;
		state = state->parent;
	}

	return level_cred ? -ESTALE : 0;
}

/* Initialize every policy-local label required by the current ancestry. */
static int inode_doinit_with_dentry(
	const struct cred *cred,
	struct inode *inode,
	struct dentry *opt_dentry)
{
	struct superblock_security_struct *sbsec =
		selinux_superblock(inode->i_sb);
	struct inode_security_struct *isec = selinux_inode(inode);
	struct selinux_inode_state_plan *plans;
	struct selinux_object_label_update *updates;
	u16 sclass = READ_ONCE(isec->sclass);
	unsigned int retry;
	int rc = 0;

	if (selinux_inode_labels_ready(cred, isec))
		return 0;
	rc = selinux_superblock_ensure_ancestry(cred, inode->i_sb);
	if (rc)
		return rc;
	if (sclass == SECCLASS_FILE) {
		sclass = inode_mode_to_security_class(inode->i_mode);
		WRITE_ONCE(isec->sclass, sclass);
	}
	plans = kcalloc(
		SELINUX_NS_MAX_DEPTH + 1,
		sizeof(*plans),
		GFP_NOFS);
	if (!plans)
		return -ENOMEM;
	updates = kcalloc(
		SELINUX_NS_MAX_DEPTH + 1,
		sizeof(*updates),
		GFP_NOFS);
	if (!updates) {
		kfree(plans);
		return -ENOMEM;
	}

	for (retry = 0; retry < SELINUX_INODE_INIT_RETRIES; retry++) {
		const struct cred *level_cred = cred;
		struct selinux_state *state = cred_selinux_state(level_cred);
		struct selinux_state *persistent_owner;
		struct dentry *dentry = NULL;
		struct selinux_object_generation_guard guards[4];
		u64 sb_generations[4];
		u64 inode_generation;
		u16 count = 0;
		u16 update_count = 0;
		u16 index;
		bool defer = false;

		memset(
			plans,
			0,
			(SELINUX_NS_MAX_DEPTH + 1) * sizeof(*plans));
		inode_generation =
			selinux_object_identity_generation(isec->object);
		if (!inode_generation)
			continue;
		mutex_lock(&sbsec->lock);
		persistent_owner = get_selinux_state(
			sbsec->persistent_label_owner);
		if (!selinux_superblock_generations_read(
		    sbsec, sb_generations)) {
			mutex_unlock(&sbsec->lock);
			put_selinux_state(persistent_owner);
			continue;
		}
		mutex_unlock(&sbsec->lock);

		while (state) {
			const struct cred_security_struct *security;
			struct selinux_inode_state_plan *plan;
			int label_rc;

			if (!level_cred ||
			    count >= SELINUX_NS_MAX_DEPTH + 1) {
				rc = -ESTALE;
				goto out_iteration;
			}
			security = selinux_cred(level_cred);
			if (security->state != state) {
				rc = -ESTALE;
				goto out_iteration;
			}
			plan = &plans[count++];
			plan->state = state;
			if (!selinux_initialized(state))
				goto next_state;
			rc = selinux_superblock_labels_get(
				state,
				sbsec,
				&plan->superblock);
			if (rc)
				goto out_iteration;
			if (!(plan->superblock.filesystem.filesystem_flags &
			      SE_SBINITIALIZED)) {
				defer = true;
				goto next_state;
			}
			label_rc = selinux_object_label_get(
				state,
				isec->object,
				&plan->value);
			if (!label_rc &&
			    plan->value.source !=
				SELINUX_LABEL_SOURCE_UNSPECIFIED)
				goto next_state;
			if (label_rc && label_rc != -ENOENT) {
				rc = label_rc;
				goto out_iteration;
			}
			plan->update = true;
next_state:
			level_cred = security->parent_cred;
			state = state->parent;
		}
		if (level_cred) {
			rc = -ESTALE;
			goto out_iteration;
		}
		if (defer) {
			selinux_inode_defer_initialization(sbsec, isec);
			rc = 0;
			goto out_iteration;
		}

		for (index = 0; index < count; index++) {
			struct selinux_inode_state_plan *plan = &plans[index];
			struct selinux_object_label_value creator;
			u16 behavior;
			u16 flags;

			if (!plan->update)
				continue;
			behavior =
				plan->superblock.filesystem.filesystem_behavior;
			flags = plan->superblock.filesystem.filesystem_flags;
			plan->value = (struct selinux_object_label_value) {
				.sid = plan->superblock.filesystem.sid,
				.sclass = sclass,
				.source = SELINUX_LABEL_SOURCE_FILESYSTEM,
			};

			switch (behavior) {
			case SECURITY_FS_USE_NATIVE:
			case SECURITY_FS_USE_XATTR:
				if (!(inode->i_opflags & IOP_XATTR)) {
					plan->value =
						plan->superblock.default_inode;
					plan->value.sclass = sclass;
					break;
				}
				if (!dentry)
					dentry = selinux_inode_find_dentry(
						inode, opt_dentry);
				if (!dentry) {
					rc = 0;
					goto out_iteration;
				}
				rc = inode_doinit_use_xattr(
					plan->state,
					inode,
					dentry,
					plan->superblock.default_inode.sid,
					&plan->value.sid,
					&plan->value.source);
				if (rc)
					goto out_iteration;
				break;
			case SECURITY_FS_USE_TASK:
				selinux_object_label_get_or_unlabeled(
					plan->state,
					isec->creator_object,
					sclass,
					&plan->value);
				plan->value.sclass = sclass;
				plan->value.source =
					SELINUX_LABEL_SOURCE_TASK;
				break;
			case SECURITY_FS_USE_TRANS:
				selinux_object_label_get_or_unlabeled(
					plan->state,
					isec->creator_object,
					sclass,
					&creator);
				rc = security_transition_sid(
					plan->state,
					creator.sid,
					plan->superblock.filesystem.sid,
					sclass,
					NULL,
					&plan->value.sid);
				if (rc)
					goto out_iteration;
				plan->value.source =
					SELINUX_LABEL_SOURCE_TRANSITION;
				break;
			case SECURITY_FS_USE_MNTPOINT:
				plan->value = plan->superblock.mountpoint;
				plan->value.sclass = sclass;
				plan->value.source =
					SELINUX_LABEL_SOURCE_MOUNT_CONTEXT;
				break;
			default:
				if (!(flags & SE_SBGENFS) ||
				    (S_ISLNK(inode->i_mode) &&
				     !selinux_policycap_genfs_seclabel_symlinks(
					plan->state)))
					break;
				if (!dentry)
					dentry = selinux_inode_find_dentry(
						inode, opt_dentry);
				if (!dentry) {
					rc = 0;
					goto out_iteration;
				}
				rc = selinux_genfs_get_sid(
					plan->state,
					dentry,
					sclass,
					flags,
					&plan->value.sid);
				if (rc)
					goto out_iteration;
				plan->value.source =
					SELINUX_LABEL_SOURCE_GENFS;
				if ((flags & SE_SBGENFS_XATTR) &&
				    (inode->i_opflags & IOP_XATTR)) {
					rc = inode_doinit_use_xattr(
						plan->state,
						inode,
						dentry,
						plan->value.sid,
						&plan->value.sid,
						&plan->value.source);
					if (rc)
						goto out_iteration;
				}
				break;
			}

			updates[update_count++] =
				(struct selinux_object_label_update) {
					.state = plan->state,
					.object = isec->object,
					.value = plan->value,
					.expected_generation =
						inode_generation,
				};
		}

		if (!update_count) {
			rc = 0;
			goto out_iteration;
		}
		guards[0] = (struct selinux_object_generation_guard) {
			.object = sbsec->object,
			.generation = sb_generations[0],
		};
		guards[1] = (struct selinux_object_generation_guard) {
			.object = sbsec->default_object,
			.generation = sb_generations[1],
		};
		guards[2] = (struct selinux_object_generation_guard) {
			.object = sbsec->mountpoint_object,
			.generation = sb_generations[2],
		};
		guards[3] = (struct selinux_object_generation_guard) {
			.object = sbsec->creator_object,
			.generation = sb_generations[3],
		};
		mutex_lock(&sbsec->lock);
		if (sbsec->persistent_label_owner != persistent_owner ||
		    !selinux_superblock_generations_match(
			sbsec, sb_generations)) {
			rc = -ESTALE;
			mutex_unlock(&sbsec->lock);
			goto out_iteration;
		}
		rc = selinux_object_labels_update_transaction_guarded(
			updates,
			update_count,
			guards,
			ARRAY_SIZE(guards),
			GFP_NOFS);
		mutex_unlock(&sbsec->lock);
		if (!rc) {
			spin_lock(&sbsec->isec_lock);
			list_del_init(&isec->list);
			spin_unlock(&sbsec->isec_lock);
		}

out_iteration:
		if (dentry)
			dput(dentry);
		put_selinux_state(persistent_owner);
		if (rc != -ESTALE)
			break;
	}

	kfree(updates);
	kfree(plans);
	return rc;
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
	struct common_audit_data ad;
	u16 sclass;
	u32 av = CAP_TO_MASK(cap);

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
		return selinux_chain_has_self_perm_noaudit(cred, sclass, av);
	return selinux_chain_has_self_perm(cred, sclass, av, &ad);
}

/* Check whether a task has a particular permission to an inode.
   The 'adp' parameter is optional and allows other audit
   data to be passed (e.g. the dentry). */
static int inode_has_perm(const struct cred *cred,
			  struct inode *inode,
			  u32 perms,
			  struct common_audit_data *adp)
{
	struct inode_security_struct *isec;

	if (unlikely(IS_PRIVATE(inode)))
		return 0;

	isec = selinux_inode(inode);
	if (unlikely(!isec || !isec->object))
		return -EUCLEAN;

	return selinux_chain_has_perm(
		cred, isec->object, isec->sclass, perms, adp);
}

static int inode_has_perm_with_policycap(
	const struct cred *cred,
	struct inode *inode,
	u32 perms,
	u32 policycap_perms,
	unsigned int policycap,
	struct common_audit_data *adp)
{
	struct inode_security_struct *isec;

	if (unlikely(IS_PRIVATE(inode)))
		return 0;

	isec = selinux_inode(inode);
	if (unlikely(!isec || !isec->object))
		return -EUCLEAN;

	return selinux_chain_has_perm_with_policycap(
		cred,
		isec->object,
		isec->sclass,
		perms,
		policycap_perms,
		policycap,
		adp);
}

/* Same as inode_has_perm, but pass explicit audit data containing
   the dentry to help the auditing code to more easily generate the
   pathname if needed. */
static inline int dentry_has_perm(const struct cred *cred,
				  struct dentry *dentry,
				  u32 av)
{
	struct common_audit_data ad;
	struct inode *inode = d_backing_inode(dentry);
	struct inode_security_struct *isec = selinux_inode(inode);

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;
	/* check below is racy, but revalidate will recheck with lock held */
	if (unlikely(!selinux_inode_labels_ready(cred, isec)))
		inode_doinit_with_dentry(cred, inode, dentry);
	return inode_has_perm(cred, inode, av, &ad);
}

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
	if (unlikely(!selinux_inode_labels_ready(cred, isec)))
		inode_doinit_with_dentry(cred, inode, path->dentry);
	return inode_has_perm(cred, inode, av, &ad);
}

/* Same as path_has_perm, but uses the inode from the file struct. */
static inline int file_path_has_perm(const struct cred *cred,
				     struct file *file,
				     u32 av)
{
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;
	return inode_has_perm(cred, file_inode(file), av, &ad);
}

#ifdef CONFIG_BPF_SYSCALL
static int bpf_fd_pass(const struct cred *cred, const struct file *file);
#endif

static int __file_has_perm(const struct cred *cred, const struct file *file,
			   u32 av, bool bf_user_file)

{
	struct common_audit_data ad;
	const struct cred *opener_cred;
	struct inode *inode;
	int rc;

	if (bf_user_file) {
		struct backing_file_security_struct *bfsec;
		const struct path *path;

		if (WARN_ON(!(file->f_mode & FMODE_BACKING)))
			return -EIO;

		bfsec = selinux_backing_file(file);
		path = backing_file_user_path(file);
		opener_cred = bfsec->opener_cred;
		inode = d_inode(path->dentry);

		ad.type = LSM_AUDIT_DATA_PATH;
		ad.u.path = *path;
	} else {
		struct file_security_struct *fsec = selinux_file(file);

		opener_cred = fsec->opener_cred;
		inode = file_inode(file);

		ad.type = LSM_AUDIT_DATA_FILE;
		ad.u.file = file;
	}

	if (unlikely(!opener_cred))
		return -EUCLEAN;
	rc = selinux_chain_has_cred_perm(
		cred, opener_cred, SECCLASS_FD, FD__USE, &ad);
	if (rc)
		return rc;

#ifdef CONFIG_BPF_SYSCALL
	/* regardless of backing vs user file, use the underlying file here */
	rc = bpf_fd_pass(cred, file);
	if (rc)
		return rc;
#endif

	/* av is zero if only checking access to the descriptor. */
	if (av)
		return inode_has_perm(cred, inode, av, &ad);

	return 0;
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

static int selinux_determine_inode_labels(
	const struct cred *cred,
	struct inode *dir,
	const struct qstr *name,
	u16 tclass,
	struct selinux_object_identity *destination)
{
	struct superblock_security_struct *sbsec =
		selinux_superblock(dir->i_sb);
	struct inode_security_struct *dsec = selinux_inode(dir);
	struct selinux_object_label_update *updates;
	unsigned int retry;
	int rc = -ESTALE;

	if (!destination || !dsec->object || !sbsec->object)
		return -EUCLEAN;
	if (!selinux_inode_labels_ready(cred, dsec))
		inode_doinit_with_dentry(cred, dir, NULL);
	if (!selinux_inode_labels_ready(cred, dsec))
		return -ESTALE;
	updates = kcalloc(
		SELINUX_NS_MAX_DEPTH + 1,
		sizeof(*updates),
		GFP_NOFS);
	if (!updates)
		return -ENOMEM;

	for (retry = 0; retry < 4; retry++) {
		const struct cred *level_cred = cred;
		struct selinux_state *state = cred_selinux_state(cred);
		struct selinux_object_generation_guard guards[5];
		u64 sb_generations[4];
		u64 destination_generation;
		u64 directory_generation;
		u64 epoch;
		u16 count = 0;

		destination_generation =
			selinux_object_identity_generation(destination);
		directory_generation =
			selinux_object_identity_generation(dsec->object);
		epoch = selinux_chain_epoch_read(state);
		if (!destination_generation || !directory_generation || !epoch ||
		    !selinux_superblock_generations_read(
			sbsec, sb_generations))
			continue;

		while (state) {
			const struct cred_security_struct *security;
			struct selinux_superblock_labels superblock;
			struct selinux_object_label_value directory_label;
			struct selinux_object_label_value value = {};

			if (!level_cred ||
			    count >= SELINUX_NS_MAX_DEPTH + 1) {
				rc = -ESTALE;
				break;
			}
			security = selinux_cred(level_cred);
			if (security->state != state) {
				rc = -ESTALE;
				break;
			}
			rc = selinux_superblock_labels_get(
				state,
				sbsec,
				&superblock);
			if (rc)
				break;

			if ((superblock.filesystem.filesystem_flags &
			     SE_SBINITIALIZED) &&
			    superblock.filesystem.filesystem_behavior ==
				SECURITY_FS_USE_MNTPOINT) {
				value = superblock.mountpoint;
				value.sclass = tclass;
				value.source =
					SELINUX_LABEL_SOURCE_MOUNT_CONTEXT;
			} else if ((superblock.filesystem.filesystem_flags &
				    SBLABEL_MNT) &&
				   security->create_sid) {
				value = (struct selinux_object_label_value) {
					.sid = security->create_sid,
					.sclass = tclass,
					.source = SELINUX_LABEL_SOURCE_TASK,
				};
			} else {
				selinux_object_label_get_or_unlabeled(
					state,
					dsec->object,
					SECCLASS_DIR,
					&directory_label);
				value.sclass = tclass;
				value.source =
					SELINUX_LABEL_SOURCE_TRANSITION;
				rc = security_transition_sid(
					state,
					security->sid,
					directory_label.sid,
					tclass,
					name,
					&value.sid);
				if (rc)
					break;
			}
			updates[count++] =
				(struct selinux_object_label_update) {
					.state = state,
					.object = destination,
					.value = value,
					.expected_generation =
						destination_generation,
				};
			level_cred = security->parent_cred;
			state = state->parent;
		}
		if (rc || state || level_cred) {
			if (!rc)
				rc = -ESTALE;
			if (rc != -ESTALE)
				break;
			continue;
		}
		if (epoch != selinux_chain_epoch_read(
		    cred_selinux_state(cred))) {
			rc = -ESTALE;
			continue;
		}

		guards[0] = (struct selinux_object_generation_guard) {
			.object = sbsec->object,
			.generation = sb_generations[0],
		};
		guards[1] = (struct selinux_object_generation_guard) {
			.object = sbsec->default_object,
			.generation = sb_generations[1],
		};
		guards[2] = (struct selinux_object_generation_guard) {
			.object = sbsec->mountpoint_object,
			.generation = sb_generations[2],
		};
		guards[3] = (struct selinux_object_generation_guard) {
			.object = sbsec->creator_object,
			.generation = sb_generations[3],
		};
		guards[4] = (struct selinux_object_generation_guard) {
			.object = dsec->object,
			.generation = directory_generation,
		};
		mutex_lock(&sbsec->lock);
		if (!selinux_superblock_generations_match(
		    sbsec, sb_generations)) {
			rc = -ESTALE;
		} else {
			rc = selinux_object_labels_update_transaction_guarded(
				updates,
				count,
				guards,
				ARRAY_SIZE(guards),
				GFP_NOFS);
		}
		mutex_unlock(&sbsec->lock);
		if (rc != -ESTALE)
			break;
	}
	kfree(updates);
	return rc;
}

/* Check whether a task can create a file. */
static int may_create(struct inode *dir,
		      struct dentry *dentry,
		      u16 tclass)
{
	const struct cred *cred = current_cred();
	struct inode_security_struct *dsec;
	struct superblock_security_struct *sbsec;
	struct selinux_object_identity *prospective;
	struct common_audit_data ad;
	int rc;

	dsec = inode_security(dir);
	sbsec = selinux_superblock(dir->i_sb);

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;

	rc = inode_has_perm(
		cred,
		dir,
		DIR__ADD_NAME | DIR__SEARCH,
		&ad);
	if (rc)
		return rc;

	prospective = selinux_object_identity_alloc(
		cred_selinux_state(cred),
		GFP_KERNEL_ACCOUNT);
	if (IS_ERR(prospective))
		return PTR_ERR(prospective);
	rc = selinux_determine_inode_labels(
		cred,
		dir,
		&dentry->d_name,
		tclass,
		prospective);
	if (rc)
		goto out;

	rc = selinux_chain_has_perm(
		cred,
		prospective,
		tclass,
		FILE__CREATE,
		&ad);
	if (rc)
		goto out;

	rc = selinux_chain_has_object_perm(
		cred,
		prospective,
		sbsec->object,
		SECCLASS_FILESYSTEM,
		FILESYSTEM__ASSOCIATE,
		&ad);
out:
	selinux_object_identity_put(prospective);
	return rc;
}

#define MAY_LINK	0
#define MAY_UNLINK	1
#define MAY_RMDIR	2

/* Check whether a task can link, unlink, or rmdir a file/directory. */
static int may_link(struct inode *dir,
		    struct dentry *dentry,
		    int kind)

{
	struct inode_security_struct *dsec, *isec;
	struct common_audit_data ad;
	u32 av;
	int rc;

	dsec = inode_security(dir);
	isec = backing_inode_security(dentry);

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;

	av = DIR__SEARCH;
	av |= (kind ? DIR__REMOVE_NAME : DIR__ADD_NAME);
	rc = inode_has_perm(current_cred(), dir, av, &ad);
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

	rc = inode_has_perm(current_cred(), d_inode(dentry), av, &ad);
	return rc;
}

static inline int may_rename(struct inode *old_dir,
			     struct dentry *old_dentry,
			     struct inode *new_dir,
			     struct dentry *new_dentry)
{
	struct inode_security_struct *old_dsec, *new_dsec, *old_isec, *new_isec;
	struct common_audit_data ad;
	u32 av;
	int old_is_dir, new_is_dir;
	int rc;

	old_dsec = inode_security(old_dir);
	old_isec = backing_inode_security(old_dentry);
	old_is_dir = d_is_dir(old_dentry);
	new_dsec = inode_security(new_dir);

	ad.type = LSM_AUDIT_DATA_DENTRY;

	ad.u.dentry = old_dentry;
	rc = inode_has_perm(
		current_cred(),
		old_dir,
		DIR__REMOVE_NAME | DIR__SEARCH,
		&ad);
	if (rc)
		return rc;
	rc = inode_has_perm(
		current_cred(),
		d_inode(old_dentry),
		FILE__RENAME,
		&ad);
	if (rc)
		return rc;
	if (old_is_dir && new_dir != old_dir) {
		rc = inode_has_perm(
			current_cred(),
			d_inode(old_dentry),
			DIR__REPARENT,
			&ad);
		if (rc)
			return rc;
	}

	ad.u.dentry = new_dentry;
	av = DIR__ADD_NAME | DIR__SEARCH;
	if (d_is_positive(new_dentry))
		av |= DIR__REMOVE_NAME;
	rc = inode_has_perm(current_cred(), new_dir, av, &ad);
	if (rc)
		return rc;
	if (d_is_positive(new_dentry)) {
		new_isec = backing_inode_security(new_dentry);
		new_is_dir = d_is_dir(new_dentry);
		rc = inode_has_perm(
			current_cred(),
			d_inode(new_dentry),
			new_is_dir ? DIR__RMDIR : FILE__UNLINK,
			&ad);
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
	if (unlikely(!sbsec || !sbsec->object))
		return -EUCLEAN;
	return selinux_chain_has_perm(
		cred, sbsec->object, SECCLASS_FILESYSTEM, perms, ad);
}

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

static int file_path_has_open_perm(
	const struct cred *cred,
	struct file *file)
{
	struct inode *inode = file_inode(file);
	struct common_audit_data ad;
	u32 open_perm = inode->i_sb->s_magic == SOCKFS_MAGIC ?
		0 : FILE__OPEN;

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;
	return inode_has_perm_with_policycap(
		cred,
		inode,
		file_to_av(file),
		open_perm,
		POLICYDB_CAP_OPENPERM,
		&ad);
}

/* Hook functions begin here. */

static int selinux_binder_set_context_mgr(const struct cred *mgr)
{
	return selinux_chain_has_cred_perm(
		current_cred(), mgr, SECCLASS_BINDER,
		BINDER__SET_CONTEXT_MGR, NULL);
}

static int selinux_binder_transaction(const struct cred *from,
				      const struct cred *to)
{
	int rc;

	if (current_cred() != from) {
		rc = selinux_chain_has_cred_perm(
			current_cred(), from, SECCLASS_BINDER,
			BINDER__IMPERSONATE, NULL);
		if (rc)
			return rc;
	}

	return selinux_chain_has_cred_perm(
		from, to, SECCLASS_BINDER, BINDER__CALL, NULL);
}

static int selinux_binder_transfer_binder(const struct cred *from,
					  const struct cred *to)
{
	return selinux_chain_has_cred_perm(
		from, to, SECCLASS_BINDER, BINDER__TRANSFER, NULL);
}

static int selinux_binder_transfer_file(const struct cred *from,
					const struct cred *to,
					const struct file *file)
{
	int rc;

#ifdef CONFIG_BPF_SYSCALL
	rc = bpf_fd_pass(to, file);
	if (rc)
		return rc;
#endif

	return __file_has_perm(to, file, file_to_av(file), false);
}

static int selinux_ptrace_access_check(struct task_struct *child,
				       unsigned int mode)
{
	const struct cred *target = get_task_cred(child);
	int rc;

	if (mode & PTRACE_MODE_READ)
		rc = selinux_chain_has_cred_perm(
			current_cred(), target, SECCLASS_FILE, FILE__READ, NULL);
	else
		rc = selinux_chain_has_cred_perm(
			current_cred(), target, SECCLASS_PROCESS,
			PROCESS__PTRACE, NULL);
	put_cred(target);
	return rc;
}

static int selinux_ptrace_traceme(struct task_struct *parent)
{
	const struct cred *source = get_task_cred(parent);
	int rc = selinux_chain_has_cred_perm(
		source, current_cred(), SECCLASS_PROCESS, PROCESS__PTRACE, NULL);

	put_cred(source);
	return rc;
}

static int selinux_capget(const struct task_struct *target, kernel_cap_t *effective,
			  kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	const struct cred *target_cred = get_task_cred(target);
	int rc = selinux_chain_has_cred_perm(
		current_cred(), target_cred,
		SECCLASS_PROCESS, PROCESS__GETCAP, NULL);

	put_cred(target_cred);
	return rc;
}

static int selinux_capset(struct cred *new, const struct cred *old,
			  const kernel_cap_t *effective,
			  const kernel_cap_t *inheritable,
			  const kernel_cap_t *permitted)
{
	return selinux_chain_has_cred_perm(
		old, new, SECCLASS_PROCESS, PROCESS__SETCAP, NULL);
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
		rc = superblock_has_perm(cred, sb, FILESYSTEM__QUOTAMOD, NULL);
		break;
	case Q_GETFMT:
	case Q_GETINFO:
	case Q_GETQUOTA:
	case Q_XGETQUOTA:
	case Q_XGETQSTAT:
	case Q_XGETQSTATV:
	case Q_XGETNEXTQUOTA:
		rc = superblock_has_perm(cred, sb, FILESYSTEM__QUOTAGET, NULL);
		break;
	default:
		rc = 0;  /* let the kernel handle invalid cmds */
		break;
	}
	return rc;
}

static int selinux_quota_on(struct dentry *dentry)
{
	const struct cred *cred = current_cred();

	return dentry_has_perm(cred, dentry, FILE__QUOTAON);
}

static int selinux_syslog(int type)
{
	switch (type) {
	case SYSLOG_ACTION_READ_ALL:	/* Read last kernel messages */
	case SYSLOG_ACTION_SIZE_BUFFER:	/* Return size of the log buffer */
		return selinux_chain_has_initial_perm(
			current_cred(), SECINITSID_KERNEL,
			SECCLASS_SYSTEM, SYSTEM__SYSLOG_READ, NULL);
	case SYSLOG_ACTION_CONSOLE_OFF:	/* Disable logging to console */
	case SYSLOG_ACTION_CONSOLE_ON:	/* Enable logging to console */
	/* Set level of messages printed to console */
	case SYSLOG_ACTION_CONSOLE_LEVEL:
		return selinux_chain_has_initial_perm(
			current_cred(), SECINITSID_KERNEL,
			SECCLASS_SYSTEM, SYSTEM__SYSLOG_CONSOLE, NULL);
	}
	/* All other syslog types */
	return selinux_chain_has_initial_perm(
		current_cred(), SECINITSID_KERNEL,
		SECCLASS_SYSTEM, SYSTEM__SYSLOG_MOD, NULL);
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

static u32 ptrace_parent_sid(struct selinux_state *state)
{
	const struct cred *cred;
	const struct cred *level_cred;
	struct task_struct *tracer;
	u32 sid = SECINITSID_UNLABELED;

	rcu_read_lock();
	tracer = ptrace_parent(current);
	if (tracer)
		get_task_struct(tracer);
	rcu_read_unlock();
	if (!tracer)
		return 0;
	cred = get_task_cred(tracer);
	level_cred = selinux_chain_cred_for_state(cred, state);
	if (level_cred)
		sid = selinux_cred(level_cred)->sid;
	put_cred(cred);
	put_task_struct(tracer);
	return sid;
}

static int check_nnp_nosuid(
	struct selinux_state *state,
	const struct linux_binprm *bprm,
	u32 old_sid,
	u32 new_sid)
{
	int nnp = (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS);
	int nosuid = !mnt_may_suid(bprm->file->f_path.mnt);
	int rc;
	u32 av;

	if (!nnp && !nosuid)
		return 0; /* neither NNP nor nosuid */

	if (new_sid == old_sid)
		return 0; /* No change in credentials */

	/*
	 * If the policy enables the nnp_nosuid_transition policy capability,
	 * then we permit transitions under NNP or nosuid if the
	 * policy allows the corresponding permission between
	 * the old and new contexts.
	 */
	if (selinux_policycap_nnp_nosuid_transition(state)) {
		av = 0;
		if (nnp)
			av |= PROCESS2__NNP_TRANSITION;
		if (nosuid)
			av |= PROCESS2__NOSUID_TRANSITION;
		rc = avc_has_perm_disabled(
			state,
			old_sid,
			new_sid,
			SECCLASS_PROCESS2,
			av,
			NULL);
		if (!rc)
			return 0;
	}

	/*
	 * We also permit NNP or nosuid transitions to bounded SIDs,
	 * i.e. SIDs that are guaranteed to only be allowed a subset
	 * of the permissions of the current SID.
	 */
	rc = security_bounded_transition(state, old_sid, new_sid);
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

struct selinux_exec_level {
	struct selinux_state *state;
	const struct cred *old_cred;
	u32 old_sid;
	u32 new_sid;
};

static int selinux_exec_install_cred_chain(
	struct linux_binprm *bprm,
	const struct selinux_exec_level *levels,
	u16 count)
{
	struct cred *new_creds[SELINUX_NS_MAX_DEPTH + 1] = {};
	u16 index;
	int rc = 0;

	if (!count)
		return -EINVAL;
	new_creds[0] = bprm->cred;
	for (index = 1; index < count; index++) {
		new_creds[index] = prepare_creds_from(levels[index].old_cred);
		if (!new_creds[index]) {
			rc = -ENOMEM;
			goto out_abort;
		}
	}
	for (index = 0; index < count; index++) {
		struct cred_security_struct *security =
			selinux_cred(new_creds[index]);

		if (security->state != levels[index].state) {
			rc = -ESTALE;
			goto out_abort;
		}
	}
	for (index = 0; index < count; index++) {
		struct cred_security_struct *security =
			selinux_cred(new_creds[index]);

		security->osid = levels[index].old_sid;
		security->sid = levels[index].new_sid;
		security->exec_sid = SECSID_NULL;
		security->create_sid = SECSID_NULL;
		security->keycreate_sid = SECSID_NULL;
		security->sockcreate_sid = SECSID_NULL;
	}
	for (index = 0; index < count; index++) {
		struct cred_security_struct *security =
			selinux_cred(new_creds[index]);
		const struct cred *parent =
			index + 1 < count ? new_creds[index + 1] : NULL;

		put_cred(security->parent_cred);
		security->parent_cred = get_cred(parent);
	}
	for (index = 1; index < count; index++)
		put_cred(new_creds[index]);
	return 0;

out_abort:
	for (index = 1; index < count; index++)
		if (new_creds[index])
			abort_creds(new_creds[index]);
	return rc;
}

static int selinux_bprm_creds_for_exec(struct linux_binprm *bprm)
{
	struct selinux_exec_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	const struct cred *level_cred = current_cred();
	struct selinux_state *state = current_selinux_state;
	struct inode_security_struct *isec;
	struct common_audit_data ad;
	struct inode *inode = file_inode(bprm->file);
	u64 epoch;
	u16 count = 0;
	bool clear_personality = false;
	bool secureexec = false;
	int rc;

	/* SELinux context only depends on initial program or script and not
	 * the script interpreter */

	isec = inode_security(inode);

	if (WARN_ON(isec->sclass != SECCLASS_FILE &&
		    isec->sclass != SECCLASS_MEMFD_FILE))
		return -EACCES;

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = bprm->file;
	epoch = selinux_chain_epoch_read(state);
	if (!epoch)
		return -ESTALE;
	while (state) {
		const struct cred_security_struct *old_security;
		struct selinux_object_label_value executable;
		struct selinux_exec_level *level;
		bool explicit_transition;

		if (!level_cred || count >= ARRAY_SIZE(levels))
			return -ESTALE;
		old_security = selinux_cred(level_cred);
		if (old_security->state != state)
			return -ESTALE;
		level = &levels[count++];
		level->state = state;
		level->old_cred = level_cred;
		level->old_sid = old_security->sid;
		level->new_sid = old_security->sid;

		if (!selinux_initialized(state)) {
			level->new_sid = SECINITSID_INIT;
			goto next_level;
		}
		selinux_object_label_get_or_unlabeled(
			state,
			isec->object,
			isec->sclass,
			&executable);
		explicit_transition = old_security->exec_sid != SECSID_NULL;
		if (explicit_transition) {
			level->new_sid = old_security->exec_sid;
		} else {
			rc = security_transition_sid(
				state,
				old_security->sid,
				executable.sid,
				SECCLASS_PROCESS,
				NULL,
				&level->new_sid);
			if (rc)
				return rc;
		}
		rc = check_nnp_nosuid(
			state,
			bprm,
			old_security->sid,
			level->new_sid);
		if (rc) {
			if (explicit_transition)
				return rc;
			level->new_sid = old_security->sid;
		}

		if (level->new_sid == old_security->sid) {
			rc = avc_has_perm_disabled(
				state,
				old_security->sid,
				executable.sid,
				isec->sclass,
				FILE__EXECUTE_NO_TRANS,
				&ad);
			if (rc)
				return rc;
			goto next_level;
		}
		rc = avc_has_perm_disabled(
			state,
			old_security->sid,
			level->new_sid,
			SECCLASS_PROCESS,
			PROCESS__TRANSITION,
			&ad);
		if (rc)
			return rc;
		rc = avc_has_perm_disabled(
			state,
			level->new_sid,
			executable.sid,
			isec->sclass,
			FILE__ENTRYPOINT,
			&ad);
		if (rc)
			return rc;
		if (bprm->unsafe & LSM_UNSAFE_SHARE) {
			rc = avc_has_perm_disabled(
				state,
				old_security->sid,
				level->new_sid,
				SECCLASS_PROCESS,
				PROCESS__SHARE,
				NULL);
			if (rc)
				return -EPERM;
		}
		if (bprm->unsafe & LSM_UNSAFE_PTRACE) {
			u32 tracer_sid = ptrace_parent_sid(state);

			if (tracer_sid) {
				rc = avc_has_perm_disabled(
					state,
					tracer_sid,
					level->new_sid,
					SECCLASS_PROCESS,
					PROCESS__PTRACE,
					NULL);
				if (rc)
					return -EPERM;
			}
		}
		clear_personality = true;
		rc = avc_has_perm_disabled(
			state,
			old_security->sid,
			level->new_sid,
			SECCLASS_PROCESS,
			PROCESS__NOATSECURE,
			NULL);
		secureexec |= !!rc;
next_level:
		level_cred = old_security->parent_cred;
		state = state->parent;
	}
	if (level_cred ||
	    epoch != selinux_chain_epoch_read(current_selinux_state))
		return -ESTALE;
	rc = selinux_exec_install_cred_chain(bprm, levels, count);
	if (rc)
		return rc;
	if (clear_personality)
		bprm->per_clear |= PER_CLEAR_ON_SETID;
	bprm->secureexec |= secureexec;
	return 0;
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

static bool selinux_cred_chain_transitioned(const struct cred *cred)
{
	const struct cred *level_cred = cred;
	struct selinux_state *state = cred_selinux_state(cred);
	u16 depth = 0;

	while (state) {
		const struct cred_security_struct *security;

		if (!level_cred || depth++ > SELINUX_NS_MAX_DEPTH)
			return true;
		security = selinux_cred(level_cred);
		if (security->state != state)
			return true;
		if (security->sid != security->osid)
			return true;
		level_cred = security->parent_cred;
		state = state->parent;
	}
	return level_cred != NULL;
}

static int selinux_cred_chain_transition_perm(
	const struct cred *cred,
	u32 permission)
{
	const struct cred *level_cred = cred;
	struct selinux_state *state = cred_selinux_state(cred);
	u64 epoch = selinux_chain_epoch_read(state);
	u16 depth = 0;

	if (!epoch)
		return -ESTALE;
	while (state) {
		const struct cred_security_struct *security;
		int rc;

		if (!level_cred || depth++ > SELINUX_NS_MAX_DEPTH)
			return -ESTALE;
		security = selinux_cred(level_cred);
		if (security->state != state)
			return -ESTALE;
		if (security->sid != security->osid) {
			rc = avc_has_perm_disabled(
				state,
				security->osid,
				security->sid,
				SECCLASS_PROCESS,
				permission,
				NULL);
			if (rc)
				return rc;
		}
		level_cred = security->parent_cred;
		state = state->parent;
	}
	if (level_cred ||
	    epoch != selinux_chain_epoch_read(cred_selinux_state(cred)))
		return -ESTALE;
	return 0;
}

/*
 * Prepare a process for imminent new credential changes due to exec
 */
static void selinux_bprm_committing_creds(const struct linux_binprm *bprm)
{
	struct rlimit *rlim, *initrlim;
	int rc, i;

	if (!selinux_cred_chain_transitioned(bprm->cred))
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
	rc = selinux_cred_chain_transition_perm(
		bprm->cred,
		PROCESS__RLIMITINH);
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
	int rc;

	if (!selinux_cred_chain_transitioned(current_cred()))
		return;

	/* Check whether the new SID can inherit signal state from the old SID.
	 * If not, clear itimers to avoid subsequent signal generation and
	 * flush and unblock signals.
	 *
	 * This must occur _after_ the task SID has been updated so that any
	 * kill done after the flush will be checked against the new SID.
	 */
	rc = selinux_cred_chain_transition_perm(
		current_cred(),
		PROCESS__SIGINH);
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
	int rc;

	mutex_init(&sbsec->lock);
	INIT_LIST_HEAD(&sbsec->isec_head);
	spin_lock_init(&sbsec->isec_lock);
	rc = selinux_object_init_initial(
		&sbsec->object,
		current_selinux_state,
		SECINITSID_UNLABELED,
		SECCLASS_FILESYSTEM,
		SELINUX_LABEL_SOURCE_FILESYSTEM,
		GFP_KERNEL);
	if (rc)
		return rc;
	rc = selinux_object_init_initial(
		&sbsec->default_object,
		current_selinux_state,
		SECINITSID_FILE,
		SECCLASS_FILE,
		SELINUX_LABEL_SOURCE_FILESYSTEM,
		GFP_KERNEL);
	if (rc)
		goto err_object;
	rc = selinux_object_init_initial(
		&sbsec->mountpoint_object,
		current_selinux_state,
		SECINITSID_UNLABELED,
		SECCLASS_FILE,
		SELINUX_LABEL_SOURCE_MOUNT_CONTEXT,
		GFP_KERNEL);
	if (rc)
		goto err_default;
	rc = selinux_object_init_from_cred(
		&sbsec->creator_object,
		current_cred(),
		SECCLASS_FILESYSTEM,
		SELINUX_LABEL_SOURCE_TASK,
		GFP_KERNEL);
	if (rc)
		goto err_mountpoint;
	sbsec->persistent_label_owner =
		get_selinux_state(current_selinux_state);

	return 0;

err_mountpoint:
	selinux_object_clear(&sbsec->mountpoint_object);
err_default:
	selinux_object_clear(&sbsec->default_object);
err_object:
	selinux_object_clear(&sbsec->object);
	return rc;
}

static void selinux_sb_free_security(struct super_block *sb)
{
	struct superblock_security_struct *sbsec = selinux_superblock(sb);

	selinux_object_clear(&sbsec->object);
	selinux_object_clear(&sbsec->default_object);
	selinux_object_clear(&sbsec->mountpoint_object);
	selinux_object_clear(&sbsec->creator_object);
	put_selinux_state(sbsec->persistent_label_owner);
	sbsec->persistent_label_owner = NULL;
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

static int selinux_sb_eat_lsm_opts(char *options, void **mnt_opts)
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
			rc = selinux_add_opt(token, arg, mnt_opts);
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
	if (*mnt_opts) {
		selinux_free_mnt_opts(*mnt_opts);
		*mnt_opts = NULL;
	}
	return rc;
}

static int selinux_sb_mnt_opts_compat(struct super_block *sb, void *mnt_opts)
{
	struct selinux_mnt_opts *opts = mnt_opts;
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct inode_security_struct *root_isec =
		backing_inode_security_novalidate(sb->s_root);
	struct selinux_object_label_value root_label;
	struct selinux_superblock_labels labels;
	struct selinux_state *state = current_selinux_state;
	u16 flags;
	int rc;

	if (opts && opts->state != state)
		return 1;
	rc = selinux_superblock_labels_get(state, sbsec, &labels);
	if (rc)
		return rc;
	if (!root_isec || !root_isec->object)
		return -EUCLEAN;
	selinux_object_label_get_or_unlabeled(
		state,
		root_isec->object,
		root_isec->sclass,
		&root_label);
	flags = labels.filesystem.filesystem_flags;

	/*
	 * Superblock not initialized (i.e. no options) - reject if any
	 * options specified, otherwise accept.
	 */
	if (!(flags & SE_SBINITIALIZED))
		return opts ? 1 : 0;

	/*
	 * Superblock initialized and no options specified - reject if
	 * superblock has any options set, otherwise accept.
	 */
	if (!opts)
		return (flags & SE_MNTMASK) ? 1 : 0;

	if (opts->fscontext_sid) {
		if (bad_option(flags, FSCONTEXT_MNT, labels.filesystem.sid,
			       opts->fscontext_sid))
			return 1;
	}
	if (opts->context_sid) {
		if (bad_option(flags, CONTEXT_MNT, labels.mountpoint.sid,
			       opts->context_sid))
			return 1;
	}
	if (opts->rootcontext_sid) {
		if (bad_option(flags, ROOTCONTEXT_MNT, root_label.sid,
			       opts->rootcontext_sid))
			return 1;
	}
	if (opts->defcontext_sid) {
		if (bad_option(flags, DEFCONTEXT_MNT,
			       labels.default_inode.sid,
			       opts->defcontext_sid))
			return 1;
	}
	return 0;
}

static int selinux_sb_remount(struct super_block *sb, void *mnt_opts)
{
	struct selinux_mnt_opts *opts = mnt_opts;
	struct superblock_security_struct *sbsec = selinux_superblock(sb);
	struct inode_security_struct *root_isec =
		backing_inode_security_novalidate(sb->s_root);
	struct selinux_object_label_value root_label;
	struct selinux_superblock_labels labels;
	struct selinux_state *state = current_selinux_state;
	u16 flags;
	int rc;

	if (opts && opts->state != state)
		goto out_bad_option;
	rc = selinux_superblock_labels_get(state, sbsec, &labels);
	if (rc)
		return rc;
	if (!root_isec || !root_isec->object)
		return -EUCLEAN;
	selinux_object_label_get_or_unlabeled(
		state,
		root_isec->object,
		root_isec->sclass,
		&root_label);
	flags = labels.filesystem.filesystem_flags;

	if (!(flags & SE_SBINITIALIZED))
		return 0;

	if (!opts)
		return 0;

	if (opts->fscontext_sid) {
		if (bad_option(flags, FSCONTEXT_MNT, labels.filesystem.sid,
			       opts->fscontext_sid))
			goto out_bad_option;
	}
	if (opts->context_sid) {
		if (bad_option(flags, CONTEXT_MNT, labels.mountpoint.sid,
			       opts->context_sid))
			goto out_bad_option;
	}
	if (opts->rootcontext_sid) {
		if (bad_option(flags, ROOTCONTEXT_MNT, root_label.sid,
			       opts->rootcontext_sid))
			goto out_bad_option;
	}
	if (opts->defcontext_sid) {
		if (bad_option(flags, DEFCONTEXT_MNT,
			       labels.default_inode.sid,
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

static int selinux_sb_kern_mount(const struct super_block *sb)
{
	const struct cred *cred = current_cred();
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = sb->s_root;
	return superblock_has_perm(cred, sb, FILESYSTEM__MOUNT, &ad);
}

static int selinux_sb_statfs(struct dentry *dentry)
{
	const struct cred *cred = current_cred();
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry->d_sb->s_root;
	return superblock_has_perm(cred, dentry->d_sb, FILESYSTEM__GETATTR, &ad);
}

static int selinux_mount(const char *dev_name,
			 const struct path *path,
			 const char *type,
			 unsigned long flags,
			 void *data)
{
	const struct cred *cred = current_cred();

	if (flags & MS_REMOUNT)
		return superblock_has_perm(cred, path->dentry->d_sb,
					   FILESYSTEM__REMOUNT, NULL);
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

	return superblock_has_perm(cred, mnt->mnt_sb,
				   FILESYSTEM__UNMOUNT, NULL);
}

static int selinux_fs_context_submount(struct fs_context *fc,
				      struct super_block *reference)
{
	const struct superblock_security_struct *sbsec =
		selinux_superblock(reference);
	struct selinux_superblock_labels labels;
	struct selinux_state *state = current_selinux_state;
	struct selinux_mnt_opts *opts;
	u16 flags;
	int rc;

	rc = selinux_superblock_labels_get(state, sbsec, &labels);
	if (rc)
		return rc;
	flags = labels.filesystem.filesystem_flags;

	/*
	 * Ensure that fc->security remains NULL when no options are set
	 * as expected by selinux_set_mnt_opts().
	 */
	if (!(flags & (FSCONTEXT_MNT | CONTEXT_MNT | DEFCONTEXT_MNT)))
		return 0;

	opts = kzalloc_obj(*opts);
	if (!opts)
		return -ENOMEM;

	opts->state = get_selinux_state(state);
	if (flags & FSCONTEXT_MNT)
		opts->fscontext_sid = labels.filesystem.sid;
	if (flags & CONTEXT_MNT)
		opts->context_sid = labels.mountpoint.sid;
	if (flags & DEFCONTEXT_MNT)
		opts->defcontext_sid = labels.default_inode.sid;
	fc->security = opts;
	return 0;
}

static int selinux_fs_context_dup(struct fs_context *fc,
				  struct fs_context *src_fc)
{
	const struct selinux_mnt_opts *src = src_fc->security;

	if (!src)
		return 0;

	fc->security = kmemdup(src, sizeof(*src), GFP_KERNEL);
	if (!fc->security)
		return -ENOMEM;
	((struct selinux_mnt_opts *)fc->security)->state =
		get_selinux_state(src->state);
	return 0;
}

static const struct fs_parameter_spec selinux_fs_parameters[] = {
	fsparam_string(CONTEXT_STR,	Opt_context),
	fsparam_string(DEFCONTEXT_STR,	Opt_defcontext),
	fsparam_string(FSCONTEXT_STR,	Opt_fscontext),
	fsparam_string(ROOTCONTEXT_STR,	Opt_rootcontext),
	fsparam_flag  (SECLABEL_STR,	Opt_seclabel),
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

	return selinux_add_opt(opt, param->string, &fc->security);
}

/* inode security operations */

static int selinux_inode_persistent_context(
	const struct cred *cred,
	struct superblock_security_struct *sbsec,
	struct selinux_object_identity *object,
	char **context,
	u32 *length)
{
	struct selinux_object_label_value value;
	struct selinux_state *owner;
	int rc;

	owner = selinux_persistent_label_owner_get(sbsec);
	if (!owner)
		return -EUCLEAN;
	if (!selinux_chain_cred_for_state(cred, owner)) {
		rc = -EXDEV;
		goto out;
	}
	rc = selinux_object_label_snapshot(
		owner,
		object,
		&value,
		NULL);
	if (rc)
		goto out;
	rc = security_sid_to_context_force(
		owner,
		value.sid,
		context,
		length);
out:
	put_selinux_state(owner);
	return rc;
}

static int selinux_inode_alloc_security(struct inode *inode)
{
	struct inode_security_struct *isec = selinux_inode(inode);
	int rc;

	spin_lock_init(&isec->lock);
	INIT_LIST_HEAD(&isec->list);
	isec->inode = inode;
	isec->sclass = SECCLASS_FILE;
	rc = selinux_object_init_initial(
		&isec->object,
		current_selinux_state,
		SECINITSID_UNLABELED,
		SECCLASS_FILE,
		SELINUX_LABEL_SOURCE_UNSPECIFIED,
		GFP_KERNEL_ACCOUNT);
	if (rc)
		return rc;
	rc = selinux_object_init_from_cred(
		&isec->creator_object,
		current_cred(),
		SECCLASS_FILE,
		SELINUX_LABEL_SOURCE_TASK,
		GFP_KERNEL_ACCOUNT);
	if (rc) {
		selinux_object_clear(&isec->object);
		return rc;
	}

	return 0;
}

static void selinux_inode_free_security(struct inode *inode)
{
	struct inode_security_struct *isec = selinux_inode(inode);

	inode_free_security(inode);
	if (isec) {
		selinux_object_clear(&isec->object);
		selinux_object_clear(&isec->creator_object);
	}
}

static int selinux_dentry_init_security(struct dentry *dentry, int mode,
					const struct qstr *name,
					const char **xattr_name,
					struct lsm_context *cp)
{
	struct superblock_security_struct *sbsec =
		selinux_superblock(dentry->d_sb);
	struct selinux_object_identity *object;
	int rc;

	object = selinux_object_identity_alloc(
		current_selinux_state,
		GFP_KERNEL_ACCOUNT);
	if (IS_ERR(object))
		return PTR_ERR(object);
	rc = selinux_determine_inode_labels(
		current_cred(),
		d_inode(dentry->d_parent),
		name,
		inode_mode_to_security_class(mode),
		object);
	if (rc)
		goto out;

	if (xattr_name)
		*xattr_name = XATTR_NAME_SELINUX;

	cp->id = LSM_ID_SELINUX;
	rc = selinux_inode_persistent_context(
		current_cred(),
		sbsec,
		object,
		&cp->context,
		&cp->len);
out:
	if (rc)
		cp->id = LSM_ID_UNDEF;
	selinux_object_identity_put(object);
	return rc;
}

static int selinux_dentry_create_files_as(struct dentry *dentry, int mode,
					  const struct qstr *name,
					  const struct cred *old,
					  struct cred *new)
{
	struct selinux_object_label_value label;
	struct selinux_object_identity *object;
	int rc;
	struct cred_security_struct *crsec;

	object = selinux_object_identity_alloc(
		cred_selinux_state(old),
		GFP_KERNEL_ACCOUNT);
	if (IS_ERR(object))
		return PTR_ERR(object);
	rc = selinux_determine_inode_labels(
		old,
		d_inode(dentry->d_parent),
		name,
		inode_mode_to_security_class(mode),
		object);
	if (rc)
		goto out;

	crsec = selinux_cred(new);
	rc = selinux_object_label_snapshot(
		crsec->state,
		object,
		&label,
		NULL);
	if (!rc)
		crsec->create_sid = label.sid;
out:
	selinux_object_identity_put(object);
	return rc;
}

static int selinux_inode_init_security(struct inode *inode, struct inode *dir,
				       const struct qstr *qstr,
				       struct xattr *xattrs, int *xattr_count)
{
	struct superblock_security_struct *sbsec;
	struct selinux_superblock_labels labels;
	struct inode_security_struct *isec;
	struct xattr *xattr;
	u32 clen;
	u16 newsclass;
	int rc;
	char *context;

	sbsec = selinux_superblock(dir->i_sb);

	if (!selinux_initialized(current_selinux_state))
		return -EOPNOTSUPP;
	rc = selinux_superblock_labels_get(
		current_selinux_state,
		sbsec,
		&labels);
	if (rc)
		return rc;
	if (!(labels.filesystem.filesystem_flags & SBLABEL_MNT))
		return -EOPNOTSUPP;

	newsclass = inode_mode_to_security_class(inode->i_mode);
	isec = selinux_inode(inode);
	rc = selinux_determine_inode_labels(
		current_cred(),
		dir,
		qstr,
		newsclass,
		isec->object);
	if (rc)
		return rc;
	WRITE_ONCE(isec->sclass, newsclass);

	xattr = lsm_get_xattr_slot(xattrs, xattr_count);
	if (xattr) {
		rc = selinux_inode_persistent_context(
			current_cred(),
			sbsec,
			isec->object,
			&context,
			&clen);
		if (rc)
			return rc;
		xattr->value = context;
		xattr->value_len = clen;
		xattr->name = XATTR_SELINUX_SUFFIX;
	}

	return 0;
}

static int selinux_inode_init_security_anon(struct inode *inode,
					    const struct qstr *name,
					    const struct inode *context_inode)
{
	struct common_audit_data ad;
	struct inode_security_struct *isec;
	struct selinux_object_label_value leaf_label;
	int rc;
	bool is_memfd = false;

	if (unlikely(!selinux_initialized(current_selinux_state)))
		return 0;

	if (name != NULL && name->name != NULL &&
	    !strcmp(name->name, MEMFD_ANON_NAME))
		is_memfd = true;

	isec = selinux_inode(inode);

	/*
	 * We only get here once per ephemeral inode.  The inode has
	 * been initialized via inode_alloc_security but is otherwise
	 * untouched.
	 */

	if (context_inode) {
		struct inode_security_struct *context_isec =
			selinux_inode(context_inode);

		if (!selinux_inode_labels_ready(
		    current_cred(), context_isec))
			inode_doinit_with_dentry(
				current_cred(),
				(struct inode *)context_inode,
				NULL);
		if (!selinux_inode_labels_ready(
		    current_cred(), context_isec)) {
			pr_err("SELinux:  context_inode is not initialized\n");
			return -EACCES;
		}
		rc = selinux_object_label_copy_for_state_chain(
			isec->object,
			context_isec->object,
			current_selinux_state,
			context_isec->sclass,
			GFP_KERNEL_ACCOUNT);
		if (rc)
			return rc;
	} else {
		rc = selinux_anon_object_transition_from_cred(
			current_cred(),
			isec->object,
			name,
			is_memfd,
			GFP_KERNEL_ACCOUNT);
		if (rc)
			return rc;
	}
	rc = selinux_object_label_get(
		current_selinux_state, isec->object, &leaf_label);
	if (rc)
		return rc;
	isec->sclass = leaf_label.source == SELINUX_LABEL_SOURCE_UNSPECIFIED ?
		SECCLASS_FILE : leaf_label.sclass;
	/*
	 * Now that we've initialized security, check whether we're
	 * allowed to actually create this type of anonymous inode.
	 */

	ad.type = LSM_AUDIT_DATA_ANONINODE;
	ad.u.anonclass = name ? (const char *)name->name : "?";

	if (is_memfd)
		return selinux_chain_has_perm_if_policycap(
			current_cred(),
			isec->object,
			SECCLASS_MEMFD_FILE,
			FILE__CREATE,
			POLICYDB_CAP_MEMFD_CLASS,
			&ad);
	return selinux_chain_has_perm(
		current_cred(), isec->object, isec->sclass,
		FILE__CREATE, &ad);
}

static int selinux_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return may_create(dir, dentry, SECCLASS_FILE);
}

static int selinux_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	return may_link(dir, old_dentry, MAY_LINK);
}

static int selinux_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return may_link(dir, dentry, MAY_UNLINK);
}

static int selinux_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
	return may_create(dir, dentry, SECCLASS_LNK_FILE);
}

static int selinux_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
	return may_create(dir, dentry, SECCLASS_DIR);
}

static int selinux_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return may_link(dir, dentry, MAY_RMDIR);
}

static int selinux_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	return may_create(dir, dentry, inode_mode_to_security_class(mode));
}

static int selinux_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
				struct inode *new_inode, struct dentry *new_dentry)
{
	return may_rename(old_inode, old_dentry, new_inode, new_dentry);
}

static int selinux_inode_readlink(struct dentry *dentry)
{
	const struct cred *cred = current_cred();

	return dentry_has_perm(cred, dentry, FILE__READ);
}

static int selinux_inode_follow_link(struct dentry *dentry, struct inode *inode,
				     bool rcu)
{
	struct common_audit_data ad;
	struct inode_security_struct *isec;

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;
	isec = inode_security_rcu(inode, rcu);
	if (IS_ERR(isec))
		return PTR_ERR(isec);

	return selinux_chain_has_perm(
		current_cred(), isec->object, isec->sclass, FILE__READ, &ad);
}

/**
 * selinux_inode_permission - Check if the current task can access an inode
 * @inode: the inode that is being accessed
 * @requested: the accesses being requested
 *
 * Check if the current task is allowed to access @inode according to
 * @requested.  Returns 0 if allowed, negative values otherwise.
 */
static int selinux_inode_permission(struct inode *inode, int requested)
{
	struct task_security_struct *tsec = selinux_task(current);
	const struct cred *cred = current_cred();
	struct selinux_task_chain_cache_entry *entry;
	struct selinux_object_identity *object;
	u64 object_generation;
	u64 chain_epoch;
	bool cacheable;
	unsigned int index;
	int mask;
	int rc;
	u32 perms;
	struct inode_security_struct *isec;
	struct common_audit_data ad;

	mask = requested & (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND);

	/* No permission to check.  Existence test. */
	if (!mask)
		return 0;

	isec = inode_security_rcu(inode, requested & MAY_NOT_BLOCK);
	if (IS_ERR(isec))
		return PTR_ERR(isec);
	object = isec->object;
	if (unlikely(!object))
		return -EUCLEAN;
	perms = file_mask_to_av(inode->i_mode, mask);
	ad.type = LSM_AUDIT_DATA_INODE;
	ad.u.inode = inode;

	if (isec->sclass == SECCLASS_DIR) {
		object_generation =
			selinux_object_identity_generation(object);
		chain_epoch = selinux_chain_epoch_read(
			cred_selinux_state(cred));
		if (object_generation && chain_epoch) {
			for (index = 0;
			     index < SELINUX_TASK_CHAIN_CACHE_SIZE;
			     index++) {
				entry = &tsec->entries[index];
				if (entry->cred != cred ||
				    entry->object_id != object->id ||
				    entry->object_generation != object_generation ||
				    entry->chain_epoch != chain_epoch ||
				    entry->tclass != isec->sclass ||
				    (perms & ~entry->permissions))
					continue;
				if (object_generation ==
					    selinux_object_identity_generation(object) &&
				    chain_epoch == selinux_chain_epoch_read(
					    cred_selinux_state(cred)))
					return 0;
			}
		}
	}

	rc = selinux_chain_has_perm_auditdeny_cacheable(
		cred,
		object,
		isec->sclass,
		perms,
		(requested & MAY_ACCESS) ? FILE__AUDIT_ACCESS : 0,
		&ad,
		&cacheable,
		&object_generation,
		&chain_epoch);
	if (rc || !cacheable || isec->sclass != SECCLASS_DIR)
		return rc;

	for (index = 0; index < SELINUX_TASK_CHAIN_CACHE_SIZE; index++) {
		entry = &tsec->entries[index];
		if (entry->cred == cred &&
		    entry->object_id == object->id &&
		    entry->object_generation == object_generation &&
		    entry->chain_epoch == chain_epoch &&
		    entry->tclass == isec->sclass) {
			entry->permissions |= perms;
			return 0;
		}
	}

	entry = &tsec->entries[tsec->next];
	tsec->next = (tsec->next + 1) &
		(SELINUX_TASK_CHAIN_CACHE_SIZE - 1);
	put_cred(entry->cred);
	*entry = (struct selinux_task_chain_cache_entry) {
		.cred = get_cred(cred),
		.object_id = object->id,
		.object_generation = object_generation,
		.chain_epoch = chain_epoch,
		.permissions = perms,
		.tclass = isec->sclass,
	};
	return 0;
}

static int selinux_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
				 struct iattr *iattr)
{
	const struct cred *cred = current_cred();
	struct inode *inode = d_backing_inode(dentry);
	unsigned int ia_valid = iattr->ia_valid;
	u32 av = FILE__WRITE;

	/* ATTR_FORCE is just used for ATTR_KILL_S[UG]ID. */
	if (ia_valid & ATTR_FORCE) {
		ia_valid &= ~(ATTR_KILL_SUID | ATTR_KILL_SGID | ATTR_MODE |
			      ATTR_FORCE);
		if (!ia_valid)
			return 0;
	}

	if (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID |
			ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_TIMES_SET))
		return dentry_has_perm(cred, dentry, FILE__SETATTR);

	if ((ia_valid & ATTR_SIZE) && !(ia_valid & ATTR_FILE)) {
		struct common_audit_data ad;
		struct inode_security_struct *isec = selinux_inode(inode);
		u32 open_perm = inode->i_sb->s_magic == SOCKFS_MAGIC ?
			0 : FILE__OPEN;

		ad.type = LSM_AUDIT_DATA_DENTRY;
		ad.u.dentry = dentry;
		if (unlikely(!selinux_inode_labels_ready(cred, isec)))
			inode_doinit_with_dentry(cred, inode, dentry);
		return inode_has_perm_with_policycap(
			cred,
			inode,
			av,
			open_perm,
			POLICYDB_CAP_OPENPERM,
			&ad);
	}

	return dentry_has_perm(cred, dentry, av);
}

static int selinux_inode_getattr(const struct path *path)
{
	return path_has_perm(current_cred(), path, FILE__GETATTR);
}

static bool has_cap_mac_admin(bool audit)
{
	const struct cred *cred = current_cred();
	struct selinux_state *state = current_selinux_state;
	unsigned int opts = audit ? CAP_OPT_NONE : CAP_OPT_NOAUDIT;

	if (cap_capable(cred, state->owner_userns, CAP_MAC_ADMIN, opts))
		return false;
	if (cred_has_capability(
		    cred,
		    CAP_MAC_ADMIN,
		    opts,
		    state->owner_userns == &init_user_ns))
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

static int selinux_inode_relabel(
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const void *value,
	size_t size,
	int flags,
	bool local_override)
{
	struct inode *inode = d_backing_inode(dentry);
	struct inode_security_struct *isec;
	struct superblock_security_struct *sbsec;
	struct selinux_superblock_labels superblock;
	struct selinux_object_label_value
		labels[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_object_identity *target;
	struct selinux_state *owner;
	struct common_audit_data ad;
	const struct cred *level_cred = current_cred();
	struct selinux_state *leaf = current_selinux_state;
	struct selinux_state *state = leaf;
	u16 count = 0;
	int rc = 0;

	sbsec = selinux_superblock(inode->i_sb);
	owner = selinux_persistent_label_owner_get(sbsec);
	if (!owner)
		return -EUCLEAN;
	if (local_override == (owner == leaf)) {
		rc = 0;
		goto out_owner;
	}
	rc = selinux_superblock_labels_get(leaf, sbsec, &superblock);
	if (rc)
		goto out_owner;
	if (!(superblock.filesystem.filesystem_flags & SBLABEL_MNT)) {
		rc = -EOPNOTSUPP;
		goto out_owner;
	}

	if (!inode_owner_or_capable(idmap, inode)) {
		rc = -EPERM;
		goto out_owner;
	}
	if (!value || !size) {
		rc = -EACCES;
		goto out_owner;
	}
	if (local_override && (flags & XATTR_CREATE)) {
		rc = -EEXIST;
		goto out_owner;
	}

	ad.type = LSM_AUDIT_DATA_DENTRY;
	ad.u.dentry = dentry;

	isec = backing_inode_security(dentry);
	target = selinux_object_identity_alloc(leaf, GFP_KERNEL_ACCOUNT);
	if (IS_ERR(target)) {
		rc = PTR_ERR(target);
		goto out_owner;
	}
	while (state) {
		const struct cred_security_struct *security;

		if (!level_cred || count >= ARRAY_SIZE(states)) {
			rc = -ESTALE;
			goto out_target;
		}
		security = selinux_cred(level_cred);
		if (security->state != state) {
			rc = -ESTALE;
			goto out_target;
		}
		states[count] = state;
		selinux_object_label_get_or_unlabeled(
			state,
			isec->object,
			isec->sclass,
			&labels[count]);
		labels[count].sclass = isec->sclass;
		labels[count].source = SELINUX_LABEL_SOURCE_SECURITY_CONTEXT;
		count++;
		level_cred = security->parent_cred;
		state = state->parent;
	}
	if (level_cred) {
		rc = -ESTALE;
		goto out_target;
	}

	rc = security_context_to_sid(
		leaf,
		value,
		size,
		&labels[0].sid,
		GFP_KERNEL);
	if (rc == -EINVAL) {
		if (!has_cap_mac_admin(true)) {
			struct audit_buffer *ab;
			size_t audit_size;

			/* Strip a trailing NUL only for the audit record. */
			if (value) {
				const char *str = value;

				if (str[size - 1] == '\0')
					audit_size = size - 1;
				else
					audit_size = size;
			} else {
				audit_size = 0;
			}
			ab = audit_log_start(
				audit_context(),
				GFP_ATOMIC,
				AUDIT_SELINUX_ERR);
			if (!ab)
				goto out_target;
			audit_log_format(
				ab, "op=setxattr invalid_context=");
			audit_log_n_untrustedstring(ab, value, audit_size);
			audit_log_end(ab);
			goto out_target;
		}
		rc = security_context_to_sid_force(
			leaf,
			value,
			size,
			&labels[0].sid);
	}
	if (rc)
		goto out_target;
	rc = selinux_object_labels_set_chain(
		target,
		states,
		labels,
		count,
		GFP_KERNEL_ACCOUNT);
	if (rc)
		goto out_target;

	/*
	 * A relabel changes exactly one policy-local identity. Ancestor labels
	 * remain immutable and their policies still authorize every later use of
	 * the object, so requiring ancestor relabelfrom/relabelto here would test
	 * permissions for identities which are not being changed.
	 */
	rc = selinux_state_has_perm_for_cred(
		leaf,
		current_cred(),
		isec->object,
		isec->sclass,
		FILE__RELABELFROM,
		&ad);
	if (rc)
		goto out_target;
	rc = selinux_state_has_perm_for_cred(
		leaf,
		current_cred(),
		target,
		isec->sclass,
		FILE__RELABELTO,
		&ad);
	if (rc)
		goto out_target;

	{
		const struct cred_security_struct *security =
			selinux_cred(current_cred());
		struct selinux_object_label_value old_label;

		if (security->state != leaf) {
			rc = -ESTALE;
			goto out_target;
		}
		selinux_object_label_get_or_unlabeled(
			leaf,
			isec->object,
			isec->sclass,
			&old_label);
		rc = security_validate_transition(
			leaf,
			old_label.sid,
			labels[0].sid,
			security->sid,
			isec->sclass);
		if (rc)
			goto out_target;
	}

	rc = selinux_state_has_object_perm(
		leaf,
		current_cred(),
		target,
		sbsec->object,
		SECCLASS_FILESYSTEM,
		FILESYSTEM__ASSOCIATE,
		&ad);
	if (!rc && local_override) {
		rc = selinux_object_label_set(
			leaf,
			isec->object,
			&labels[0],
			GFP_KERNEL_ACCOUNT);
		if (!rc)
			rc = 1;
	}
out_target:
	selinux_object_identity_put(target);
out_owner:
	put_selinux_state(owner);
	return rc;
}

static int selinux_inode_setxattr(struct mnt_idmap *idmap,
				  struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags)
{
	struct inode *inode = d_backing_inode(dentry);

	/* if not a selinux xattr, only check the ordinary setattr perm */
	if (strcmp(name, XATTR_NAME_SELINUX))
		return dentry_has_perm(current_cred(), dentry, FILE__SETATTR);

	if (!selinux_initialized(current_selinux_state))
		return inode_owner_or_capable(idmap, inode) ? 0 : -EPERM;

	return selinux_inode_relabel(
		idmap,
		dentry,
		value,
		size,
		flags,
		false);
}

static int selinux_inode_setxattr_override(
	struct mnt_idmap *idmap,
	struct dentry *dentry,
	const char *name,
	const void *value,
	size_t size,
	int flags)
{
	if (strcmp(name, XATTR_NAME_SELINUX) ||
	    !selinux_initialized(current_selinux_state))
		return 0;

	return selinux_inode_relabel(
		idmap,
		dentry,
		value,
		size,
		flags,
		true);
}

static int selinux_inode_set_acl(struct mnt_idmap *idmap,
				 struct dentry *dentry, const char *acl_name,
				 struct posix_acl *kacl)
{
	return dentry_has_perm(current_cred(), dentry, FILE__SETATTR);
}

static int selinux_inode_get_acl(struct mnt_idmap *idmap,
				 struct dentry *dentry, const char *acl_name)
{
	return dentry_has_perm(current_cred(), dentry, FILE__GETATTR);
}

static int selinux_inode_remove_acl(struct mnt_idmap *idmap,
				    struct dentry *dentry, const char *acl_name)
{
	return dentry_has_perm(current_cred(), dentry, FILE__SETATTR);
}

static int selinux_inode_publish_persistent_context(
	struct inode *inode,
	const void *context,
	size_t size,
	bool force)
{
	struct superblock_security_struct *sbsec =
		selinux_superblock(inode->i_sb);
	struct inode_security_struct *isec = selinux_inode(inode);
	struct selinux_object_label_value value;
	struct selinux_state *owner;
	int rc;

	owner = selinux_persistent_label_owner_get(sbsec);
	if (!owner)
		return -EUCLEAN;
	if (!selinux_initialized(owner)) {
		put_selinux_state(owner);
		return 0;
	}
	if (force)
		rc = security_context_to_sid_force(
			owner, context, size, &value.sid);
	else
		rc = security_context_to_sid(
			owner, context, size, &value.sid, GFP_KERNEL);
	if (rc)
		goto out;
	value.sclass = inode_mode_to_security_class(inode->i_mode);
	value.source = SELINUX_LABEL_SOURCE_XATTR;
	rc = selinux_object_label_set(
		owner,
		isec->object,
		&value,
		GFP_KERNEL_ACCOUNT);
	if (!rc)
		WRITE_ONCE(isec->sclass, value.sclass);
out:
	put_selinux_state(owner);
	return rc;
}

static void selinux_inode_post_setxattr(struct dentry *dentry, const char *name,
					const void *value, size_t size,
					int flags)
{
	struct inode *inode = d_backing_inode(dentry);
	int rc;

	if (strcmp(name, XATTR_NAME_SELINUX)) {
		/* Not an attribute we recognize, so nothing to do. */
		return;
	}

	rc = selinux_inode_publish_persistent_context(
		inode, value, size, true);
	if (rc) {
		pr_err("SELinux:  unable to map context to SID"
		       "for (%s, %llu), rc=%d\n",
		       inode->i_sb->s_id, inode->i_ino, -rc);
		return;
	}
}

static int selinux_inode_getxattr(struct dentry *dentry, const char *name)
{
	const struct cred *cred = current_cred();

	return dentry_has_perm(cred, dentry, FILE__GETATTR);
}

static int selinux_inode_listxattr(struct dentry *dentry)
{
	const struct cred *cred = current_cred();

	return dentry_has_perm(cred, dentry, FILE__GETATTR);
}

static int selinux_inode_removexattr(struct mnt_idmap *idmap,
				     struct dentry *dentry, const char *name)
{
	/* if not a selinux xattr, only check the ordinary setattr perm */
	if (strcmp(name, XATTR_NAME_SELINUX))
		return dentry_has_perm(current_cred(), dentry, FILE__SETATTR);

	if (!selinux_initialized(current_selinux_state))
		return 0;

	/* No one is allowed to remove a SELinux security label.
	   You can change the label, but all data must be labeled. */
	return -EACCES;
}

static int selinux_inode_file_setattr(struct dentry *dentry,
				      struct file_kattr *fa)
{
	return dentry_has_perm(current_cred(), dentry, FILE__SETATTR);
}

static int selinux_inode_file_getattr(struct dentry *dentry,
				      struct file_kattr *fa)
{
	return dentry_has_perm(current_cred(), dentry, FILE__GETATTR);
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
		ret = superblock_has_perm(current_cred(), path->dentry->d_sb,
						FILESYSTEM__WATCH, &ad);
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
static int selinux_inode_getsecurity(struct mnt_idmap *idmap,
				     struct inode *inode, const char *name,
				     void **buffer, bool alloc)
{
	u32 size;
	int error;
	char *context = NULL;
	struct inode_security_struct *isec;
	struct selinux_object_label_value label;
	struct selinux_state *state = current_selinux_state;

	/*
	 * If we're not initialized yet, then we can't validate contexts, so
	 * just let vfs_getxattr fall back to using the on-disk xattr.
	 */
	if (!selinux_initialized(state) ||
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
	error = selinux_object_label_snapshot(
		state,
		isec->object,
		&label,
		NULL);
	if (error)
		return error;
	if (has_cap_mac_admin(false))
		error = security_sid_to_context_force(state, label.sid, &context,
							      &size);
	else
		error = security_sid_to_context(state, label.sid,
						&context, &size);
	if (error)
		return error;
	error = size;
	if (alloc) {
		*buffer = context;
		goto out_nofree;
	}
	kfree(context);
out_nofree:
	return error;
}

static int selinux_inode_setsecurity(struct inode *inode, const char *name,
				     const void *value, size_t size, int flags)
{
	struct superblock_security_struct *sbsec;
	struct selinux_superblock_labels labels;
	struct selinux_state *owner;
	int rc;

	if (strcmp(name, XATTR_SELINUX_SUFFIX))
		return -EOPNOTSUPP;

	sbsec = selinux_superblock(inode->i_sb);
	owner = selinux_persistent_label_owner_get(sbsec);
	if (!owner)
		return -EUCLEAN;
	rc = selinux_superblock_labels_get(owner, sbsec, &labels);
	if (rc)
		goto out;
	if (!(labels.filesystem.filesystem_flags & SBLABEL_MNT)) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	if (!value || !size) {
		rc = -EACCES;
		goto out;
	}

	rc = selinux_inode_publish_persistent_context(
		inode, value, size, false);
out:
	put_selinux_state(owner);
	return rc;
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
	struct selinux_object_label_value label;

	if (selinux_object_label_get(
	    current_selinux_state, isec->object, &label))
		prop->selinux.secid = SECINITSID_UNLABELED;
	else
		prop->selinux.secid = label.sid;
}

static int selinux_inode_copy_up(struct dentry *src, struct cred **new)
{
	struct lsm_prop prop;
	struct cred_security_struct *crsec;
	struct cred *new_creds = *new;

	if (new_creds == NULL) {
		new_creds = prepare_creds();
		if (!new_creds)
			return -ENOMEM;
	}

	crsec = selinux_cred(new_creds);
	/* Get label from overlay inode and set it in create_sid */
	selinux_inode_getlsmprop(d_inode(src), &prop);
	crsec->create_sid = prop.selinux.secid;
	*new = new_creds;
	return 0;
}

static int selinux_inode_copy_up_xattr(struct dentry *dentry, const char *name)
{
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

static int selinux_kernfs_init_security(struct kernfs_node *kn_dir,
					struct kernfs_node *kn)
{
	const struct cred *cred = current_cred();
	struct kernfs_security_struct *ksec = selinux_kernfs(kn);
	struct kernfs_security_struct *parent_ksec;
	struct selinux_object_label_update *updates = NULL;
	struct selinux_state *owner;
	struct selinux_object_identity *object;
	struct selinux_object_generation_guard guards[2];
	struct selinux_object_label_value parent_owner_label;
	const char *kn_name;
	struct qstr q;
	char *context = NULL;
	u32 parent_sid;
	u32 owner_newsid = SECSID_NULL;
	u32 context_len;
	u16 child_class = inode_mode_to_security_class(kn->mode);
	u16 parent_class;
	unsigned int retry;
	int rc;

	if (!kn_dir) {
		ksec->persistent_label_owner = get_selinux_state(
			current_selinux_state);
		return selinux_object_init_initial(
			&ksec->object,
			current_selinux_state,
			SECINITSID_UNLABELED,
			child_class,
			SELINUX_LABEL_SOURCE_UNSPECIFIED,
			GFP_KERNEL_ACCOUNT);
	}

	if (!kn_dir->security)
		return -EUCLEAN;
	parent_ksec = selinux_kernfs(kn_dir);
	if (!parent_ksec->object || !parent_ksec->persistent_label_owner)
		return -EUCLEAN;
	owner = parent_ksec->persistent_label_owner;
	ksec->persistent_label_owner = get_selinux_state(owner);

	rc = kernfs_xattr_get(kn_dir, XATTR_NAME_SELINUX, NULL, 0);
	if (rc == -ENODATA)
		return selinux_object_init_initial(
			&ksec->object,
			cred_selinux_state(cred),
			SECINITSID_UNLABELED,
			child_class,
			SELINUX_LABEL_SOURCE_UNSPECIFIED,
			GFP_KERNEL_ACCOUNT);
	if (rc < 0)
		return rc;
	context_len = rc;
	if (!context_len)
		return -EUCLEAN;

	context = kmalloc(context_len, GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	rc = kernfs_xattr_get(
		kn_dir, XATTR_NAME_SELINUX, context, context_len);
	if (rc < 0)
		goto out;
	if (rc != context_len) {
		rc = -ESTALE;
		goto out;
	}
	rc = security_context_to_sid(
		owner, context, context_len, &parent_sid, GFP_KERNEL);
	if (rc)
		goto out;

	object = selinux_object_identity_alloc(owner, GFP_KERNEL_ACCOUNT);
	if (IS_ERR(object)) {
		rc = PTR_ERR(object);
		goto out;
	}
	ksec->object = object;
	updates = kcalloc(
		SELINUX_NS_MAX_DEPTH + 2,
		sizeof(*updates),
		GFP_KERNEL_ACCOUNT);
	if (!updates) {
		rc = -ENOMEM;
		goto out;
	}

	parent_class = inode_mode_to_security_class(kn_dir->mode);
	parent_owner_label = (struct selinux_object_label_value) {
		.sid = parent_sid,
		.sclass = parent_class,
		.source = SELINUX_LABEL_SOURCE_SECURITY_CONTEXT,
	};
	kn_name = rcu_dereference_check(kn->name, true);
	q.name = kn_name;
	q.hash_len = hashlen_string(kn_dir, kn_name);

	rc = -ESTALE;
	for (retry = 0; retry < 4; retry++) {
		const struct cred *level_cred = cred;
		struct selinux_state *state = cred_selinux_state(cred);
		u64 child_generation =
			selinux_object_identity_generation(ksec->object);
		u64 parent_generation =
			selinux_object_identity_generation(parent_ksec->object);
		u64 epoch = selinux_chain_epoch_read(state);
		u16 count = 0;
		bool owner_seen = false;

		if (!child_generation || !parent_generation || !epoch)
			continue;
		while (state) {
			const struct cred_security_struct *security;
			struct selinux_object_label_value parent_label;
			struct selinux_object_label_value child_label = {
				.sclass = child_class,
				.source = SELINUX_LABEL_SOURCE_TRANSITION,
			};

			if (!level_cred || count >= SELINUX_NS_MAX_DEPTH + 1) {
				rc = -ESTALE;
				break;
			}
			security = selinux_cred(level_cred);
			if (security->state != state) {
				rc = -ESTALE;
				break;
			}
			selinux_object_label_get_or_unlabeled(
				state,
				parent_ksec->object,
				parent_class,
				&parent_label);
			if (state == owner) {
				parent_label = parent_owner_label;
				owner_seen = true;
			}
			if (security->create_sid) {
				child_label.sid = security->create_sid;
				child_label.source = SELINUX_LABEL_SOURCE_TASK;
				rc = 0;
			} else {
				rc = security_transition_sid(
					state,
					security->sid,
					parent_label.sid,
					child_class,
					&q,
					&child_label.sid);
			}
			if (rc)
				break;
			if (state == owner)
				owner_newsid = child_label.sid;
			updates[count++] =
				(struct selinux_object_label_update) {
					.state = state,
					.object = ksec->object,
					.value = child_label,
					.expected_generation = child_generation,
				};
			level_cred = security->parent_cred;
			state = state->parent;
		}
		if (rc || state || level_cred || !owner_seen) {
			if (!rc)
				rc = owner_seen ? -ESTALE : -EXDEV;
			if (rc != -ESTALE)
				break;
			continue;
		}
		updates[count++] = (struct selinux_object_label_update) {
			.state = owner,
			.object = parent_ksec->object,
			.value = parent_owner_label,
			.expected_generation = parent_generation,
		};
		guards[0] = (struct selinux_object_generation_guard) {
			.object = ksec->object,
			.generation = child_generation,
		};
		guards[1] = (struct selinux_object_generation_guard) {
			.object = parent_ksec->object,
			.generation = parent_generation,
		};
		if (epoch != selinux_chain_epoch_read(
		    cred_selinux_state(cred))) {
			rc = -ESTALE;
			continue;
		}
		rc = selinux_object_labels_update_transaction_guarded(
			updates,
			count,
			guards,
			ARRAY_SIZE(guards),
			GFP_KERNEL_ACCOUNT);
		if (rc != -ESTALE)
			break;
	}
	if (rc)
		goto out;

	kfree(context);
	context = NULL;
	rc = security_sid_to_context_force(
		owner, owner_newsid, &context, &context_len);
	if (rc)
		goto out;
	rc = kernfs_xattr_set(
		kn, XATTR_NAME_SELINUX, context, context_len, XATTR_CREATE);
out:
	kfree(updates);
	kfree(context);
	return rc;
}

static void selinux_kernfs_free_security(struct kernfs_node *kn)
{
	struct kernfs_security_struct *ksec = selinux_kernfs(kn);

	selinux_object_clear(&ksec->object);
	put_selinux_state(ksec->persistent_label_owner);
	ksec->persistent_label_owner = NULL;
}


/* file security operations */

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
	struct inode_security_struct *isec = selinux_inode(inode);
	struct file_security_struct *fsec = selinux_file(file);
	u64 generation;
	u64 epoch;

	if (!mask)
		/* No permission to check.  Existence test. */
		return 0;

	if (unlikely(!isec || !isec->object))
		return -EUCLEAN;
	generation = selinux_object_identity_generation(isec->object);
	epoch = selinux_chain_epoch_read(current_selinux_state);
	if (current_cred() == fsec->opener_cred && generation && epoch &&
	    fsec->object_generation == generation &&
	    fsec->chain_epoch == epoch)
		/* No change since file_open check. */
		return 0;

	return selinux_revalidate_file_permission(file, mask);
}

static int selinux_file_alloc_security(struct file *file)
{
	struct file_security_struct *fsec = selinux_file(file);

	fsec->opener_cred = get_current_cred();
	RCU_INIT_POINTER(
		fsec->fowner_cred, get_cred(fsec->opener_cred));

	return 0;
}

static void selinux_file_free_security(struct file *file)
{
	struct file_security_struct *fsec = selinux_file(file);
	const struct cred *fowner;

	put_cred(fsec->opener_cred);
	fsec->opener_cred = NULL;
	fowner = rcu_dereference_protected(fsec->fowner_cred, 1);
	RCU_INIT_POINTER(fsec->fowner_cred, NULL);
	put_cred(fowner);
}

static int selinux_backing_file_alloc(struct file *backing_file,
				      const struct file *user_file)
{
	struct backing_file_security_struct *bfsec;
	struct inode_security_struct *isec;

	bfsec = selinux_backing_file(backing_file);
	isec = selinux_inode(file_inode(user_file));
	if (unlikely(!isec || !isec->object))
		return -EUCLEAN;
	bfsec->object = selinux_object_identity_get(isec->object);
	bfsec->opener_cred = get_cred(selinux_file(user_file)->opener_cred);
	if (!bfsec->object || !bfsec->opener_cred)
		return -EUCLEAN;

	return 0;
}

static void selinux_backing_file_free(struct file *backing_file)
{
	struct backing_file_security_struct *bfsec =
		selinux_backing_file(backing_file);

	selinux_object_clear(&bfsec->object);
	put_cred(bfsec->opener_cred);
	bfsec->opener_cred = NULL;
}

/*
 * Check whether a task has the ioctl permission and cmd
 * operation to an inode.
 */
static int ioctl_has_perm(
	const struct cred *cred,
	struct file *file,
	u32 requested,
	u16 cmd,
	bool skip_cloexec_policycap)
{
	struct common_audit_data ad;
	struct file_security_struct *fsec = selinux_file(file);
	struct inode *inode = file_inode(file);
	struct inode_security_struct *isec;
	struct lsm_ioctlop_audit ioctl;
	int rc;
	u8 driver = cmd >> 8;
	u8 xperm = cmd & 0xff;

	ad.type = LSM_AUDIT_DATA_IOCTL_OP;
	ad.u.op = &ioctl;
	ad.u.op->cmd = cmd;
	ad.u.op->path = file->f_path;

	rc = selinux_chain_has_cred_perm(
		cred, fsec->opener_cred, SECCLASS_FD, FD__USE, &ad);
	if (rc)
		goto out;

	if (unlikely(IS_PRIVATE(inode)))
		return 0;

	isec = inode_security(inode);
	if (skip_cloexec_policycap)
		rc = selinux_chain_has_extended_perm_unless_policycap(
			cred,
			isec->object,
			isec->sclass,
			requested,
			driver,
			AVC_EXT_IOCTL,
			xperm,
			POLICYDB_CAP_IOCTL_SKIP_CLOEXEC,
			&ad);
	else
		rc = selinux_chain_has_extended_perm(
			cred,
			isec->object,
			isec->sclass,
			requested,
			driver,
			AVC_EXT_IOCTL,
			xperm,
			&ad);
out:
	return rc;
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
		error = ioctl_has_perm(
			cred, file, FILE__IOCTL, (u16)cmd, true);
		break;

	/* default case assumes that the command will go
	 * to the file's ioctl() function.
	 */
	default:
		error = ioctl_has_perm(
			cred, file, FILE__IOCTL, (u16)cmd, false);
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

		/*
		 * We are making executable an anonymous mapping or a private
		 * file mapping that will also be writable.
		 */
		rc = selinux_chain_has_self_perm(
			current_cred(), SECCLASS_PROCESS, PROCESS__EXECMEM, NULL);
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
		rc = selinux_chain_has_self_perm(
			current_cred(), SECCLASS_MEMPROTECT,
			MEMPROTECT__MMAP_ZERO, NULL);
	}

	return rc;
}

static int selinux_mmap_file_common(struct file *file, unsigned long prot,
				    bool shared, bool mounter_check)
{
	if (file) {
		int rc;
		struct common_audit_data ad;
		const struct cred *cred = mounter_check ?
				file->f_cred : current_cred();

		ad.type = LSM_AUDIT_DATA_FILE;
		ad.u.file = file;
		rc = inode_has_perm(cred, file_inode(file), FILE__MAP, &ad);
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
			rc = selinux_chain_has_self_perm(
				cred, SECCLASS_PROCESS, PROCESS__EXECHEAP, NULL);
			if (rc)
				return rc;
		} else if (!file && (vma_is_initial_stack(vma) ||
			    vma_is_stack_for_current(vma))) {
			rc = selinux_chain_has_self_perm(
				cred, SECCLASS_PROCESS, PROCESS__EXECSTACK, NULL);
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
	old = rcu_replace_pointer(
		fsec->fowner_cred, get_current_cred(), 1);
	put_cred(old);
}

static int selinux_file_send_sigiotask(struct task_struct *tsk,
				       struct fown_struct *fown, int signum)
{
	struct file *file;
	u32 perm;
	struct file_security_struct *fsec;
	const struct cred *owner;
	const struct cred *target;
	int rc;

	/* struct fown_struct is never outside the context of a struct file */
	file = fown->file;

	fsec = selinux_file(file);

	if (!signum)
		perm = signal_to_av(SIGIO); /* as per send_sigio_to_task */
	else
		perm = signal_to_av(signum);

	rcu_read_lock();
	do {
		owner = rcu_dereference(fsec->fowner_cred);
	} while (owner && !get_cred_rcu(owner));
	rcu_read_unlock();
	target = get_task_cred(tsk);
	if (!owner) {
		put_cred(target);
		return -EUCLEAN;
	}
	rc = selinux_chain_has_cred_perm(
		owner, target, SECCLASS_PROCESS, perm, NULL);
	put_cred(owner);
	put_cred(target);
	return rc;
}

static int selinux_file_receive(struct file *file)
{
	const struct cred *cred = current_cred();

	return file_has_perm(cred, file, file_to_av(file));
}

static int selinux_file_open(struct file *file)
{
	struct file_security_struct *fsec;
	struct inode_security_struct *isec;
	unsigned int retry;

	fsec = selinux_file(file);
	isec = inode_security(file_inode(file));
	/*
	 * Save inode label and policy sequence number
	 * at open-time so that selinux_file_permission
	 * can determine whether revalidation is necessary.
	 * Task label is already saved in the file security
	 * struct as its SID.
	 */
	for (retry = 0; retry < 4; retry++) {
		u64 generation =
			selinux_object_identity_generation(isec->object);
		u64 epoch = selinux_chain_epoch_read(
			cred_selinux_state(file->f_cred));
		int rc;

		if (!generation || !epoch)
			continue;
		rc = file_path_has_open_perm(file->f_cred, file);
		if (rc)
			return rc;
		if (generation !=
			    selinux_object_identity_generation(isec->object) ||
		    epoch != selinux_chain_epoch_read(
				     cred_selinux_state(file->f_cred)))
			continue;
		fsec->object_generation = generation;
		fsec->chain_epoch = epoch;
		return 0;
	}
	return -ESTALE;
}

/* task security operations */

static void selinux_install_cred_from_ancestor(
	struct task_struct *task,
	const struct cred *ancestor)
{
	const struct cred_security_struct *source = selinux_cred(ancestor);
	struct cred_security_struct *target = selinux_cred(task->cred);

	put_selinux_state(target->state);
	put_cred(target->parent_cred);
	*target = *source;
	target->state = get_selinux_state(source->state);
	target->parent_cred = get_cred(source->parent_cred);
}

static void selinux_install_direct_child_state(
	struct task_struct *task,
	struct selinux_state *state)
{
	struct cred_security_struct *security = selinux_cred(task->cred);

	put_selinux_state(security->state);
	put_cred(security->parent_cred);
	security->state = get_selinux_state(state);
	security->parent_cred = get_current_cred();
	security->osid = SECINITSID_INIT;
	security->sid = SECINITSID_INIT;
	security->exec_sid = SECSID_NULL;
	security->create_sid = SECSID_NULL;
	security->keycreate_sid = SECSID_NULL;
	security->sockcreate_sid = SECSID_NULL;
}

static void selinux_task_setns_cred_for_children(const struct cred *cred)
{
	struct task_security_struct *security = selinux_task(current);
	struct selinux_state *replacement = NULL;
	struct selinux_state *old;

	if (cred_selinux_state(cred) != current_selinux_state)
		replacement = get_selinux_state(cred_selinux_state(cred));
	old = xchg(&security->state_for_children, replacement);
	put_selinux_state(old);
}

static int selinux_task_alloc(struct task_struct *task,
			      u64 clone_flags)
{
	const struct task_security_struct *parent = selinux_task(current);
	struct selinux_state *selected = parent->state_for_children;
	const struct cred *ancestor;
	int rc;

	memset(selinux_task(task), 0, sizeof(struct task_security_struct));
	rc = selinux_chain_has_self_perm(
		current_cred(), SECCLASS_PROCESS, PROCESS__FORK, NULL);
	if (rc || !selected)
		return rc;
	if (clone_flags & CLONE_THREAD)
		return -EINVAL;
	if (selected->parent == current_selinux_state) {
		rc = selinux_state_has_initial_perm(
			selected,
			SECINITSID_INIT,
			SECINITSID_INIT,
			SECCLASS_PROCESS2,
			PROCESS2__UNSHARE_SELINUXNS,
			NULL);
		if (rc)
			return rc;
		selinux_install_direct_child_state(task, selected);
		return 0;
	}
	ancestor = selinux_chain_cred_for_state(current_cred(), selected);
	if (!ancestor)
		return -ESTALE;
	selinux_install_cred_from_ancestor(task, ancestor);
	return 0;
}

static void selinux_task_free(struct task_struct *task)
{
	struct task_security_struct *tsec = selinux_task(task);
	unsigned int index;

	for (index = 0; index < SELINUX_TASK_CHAIN_CACHE_SIZE; index++) {
		put_cred(tsec->entries[index].cred);
		tsec->entries[index].cred = NULL;
	}
	put_selinux_state(tsec->state_for_children);
	tsec->state_for_children = NULL;
}

/*
 * prepare a new set of credentials for modification
 */
static int selinux_cred_prepare(struct cred *new, const struct cred *old,
				gfp_t gfp)
{
	const struct cred_security_struct *old_crsec = selinux_cred(old);
	struct cred_security_struct *crsec = selinux_cred(new);

	*crsec = *old_crsec;
	crsec->state = get_selinux_state(old_crsec->state);
	crsec->parent_cred = get_cred(old_crsec->parent_cred);
	return 0;
}

static void selinux_cred_free(struct cred *cred)
{
	struct cred_security_struct *crsec = selinux_cred(cred);

	put_selinux_state(crsec->state);
	put_cred(crsec->parent_cred);
	crsec->state = NULL;
	crsec->parent_cred = NULL;
}

/*
 * transfer the SELinux data to a blank set of creds
 */
static void selinux_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct cred_security_struct *old_crsec = selinux_cred(old);
	struct cred_security_struct *crsec = selinux_cred(new);

	*crsec = *old_crsec;
	crsec->state = get_selinux_state(old_crsec->state);
	crsec->parent_cred = get_cred(old_crsec->parent_cred);
}

static void selinux_cred_getsecid(const struct cred *c, u32 *secid)
{
	*secid = selinux_cred(c)->sid;
}

static void selinux_cred_getlsmprop(const struct cred *c, struct lsm_prop *prop)
{
	prop->selinux.secid = selinux_cred(c)->sid;
}

struct selinux_local_sid_permission {
	struct selinux_state *leaf;
	u32 target_sid;
	u32 requested;
	u16 tclass;
};

static int selinux_resolve_local_sid_permission(
	struct selinux_state *state,
	const struct cred *level_cred,
	void *data,
	struct selinux_chain_permission *permission)
{
	const struct selinux_local_sid_permission *request = data;

	permission->tsid = state == request->leaf ?
		request->target_sid : selinux_cred(level_cred)->sid;
	permission->requested = request->requested;
	permission->tclass = request->tclass;
	permission->decided = true;
	return 0;
}

/*
 * set the security data for a kernel service
 * - all the creation contexts are set to unlabelled
 */
static int selinux_kernel_act_as(struct cred *new, u32 secid)
{
	struct cred_security_struct *crsec = selinux_cred(new);
	struct selinux_local_sid_permission request = {
		.leaf = current_selinux_state,
		.target_sid = secid,
		.requested = KERNEL_SERVICE__USE_AS_OVERRIDE,
		.tclass = SECCLASS_KERNEL_SERVICE,
	};
	int ret;

	ret = selinux_chain_has_custom_perm(
		current_cred(), NULL, NULL,
		selinux_resolve_local_sid_permission, &request, NULL);
	if (ret == 0) {
		crsec->sid = secid;
		crsec->create_sid = 0;
		crsec->keycreate_sid = 0;
		crsec->sockcreate_sid = 0;
	}
	return ret;
}

/*
 * set the file creation context in a security record to the same as the
 * objective context of the specified inode
 */
static int selinux_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	struct inode_security_struct *isec = inode_security(inode);
	struct cred_security_struct *crsec = selinux_cred(new);
	struct selinux_object_label_value label;
	int ret;

	ret = selinux_chain_has_perm(
		current_cred(), isec->object, SECCLASS_KERNEL_SERVICE,
		KERNEL_SERVICE__CREATE_FILES_AS, NULL);

	if (!ret) {
		ret = selinux_object_label_get(
			crsec->state, isec->object, &label);
		if (!ret)
			crsec->create_sid = label.sid;
	}
	return ret;
}

static int selinux_kernel_module_request(char *kmod_name)
{
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_KMOD;
	ad.u.kmod_name = kmod_name;

	return selinux_chain_has_initial_perm(
		current_cred(), SECINITSID_KERNEL,
		SECCLASS_SYSTEM, SYSTEM__MODULE_REQUEST, &ad);
}

static int selinux_kernel_load_from_file(struct file *file, u32 requested)
{
	struct common_audit_data ad;
	struct inode_security_struct *isec;
	int rc;

	if (file == NULL)
		return selinux_chain_has_self_perm(
			current_cred(), SECCLASS_SYSTEM, requested, NULL);

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;

	rc = file_has_perm(current_cred(), file, 0);
	if (rc)
		return rc;

	isec = inode_security(file_inode(file));
	return selinux_chain_has_perm(
		current_cred(), isec->object, SECCLASS_SYSTEM, requested, &ad);
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

static int selinux_task_has_perm(struct task_struct *task, u32 permission)
{
	const struct cred *target = get_task_cred(task);
	int rc = selinux_chain_has_cred_perm(
		current_cred(), target, SECCLASS_PROCESS, permission, NULL);

	put_cred(target);
	return rc;
}

static int selinux_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return selinux_task_has_perm(p, PROCESS__SETPGID);
}

static int selinux_task_getpgid(struct task_struct *p)
{
	return selinux_task_has_perm(p, PROCESS__GETPGID);
}

static int selinux_task_getsid(struct task_struct *p)
{
	return selinux_task_has_perm(p, PROCESS__GETSESSION);
}

static void selinux_current_getlsmprop_subj(struct lsm_prop *prop)
{
	prop->selinux.secid = selinux_cred(current_cred())->sid;
}

static void selinux_task_getlsmprop_obj(struct task_struct *p,
					struct lsm_prop *prop)
{
	const struct cred *target = get_task_cred(p);
	const struct cred *level = selinux_chain_cred_for_state(
		target, current_selinux_state);

	prop->selinux.secid = level ?
		selinux_cred(level)->sid : SECINITSID_UNLABELED;
	put_cred(target);
}

static int selinux_task_setnice(struct task_struct *p, int nice)
{
	return selinux_task_has_perm(p, PROCESS__SETSCHED);
}

static int selinux_task_setioprio(struct task_struct *p, int ioprio)
{
	return selinux_task_has_perm(p, PROCESS__SETSCHED);
}

static int selinux_task_getioprio(struct task_struct *p)
{
	return selinux_task_has_perm(p, PROCESS__GETSCHED);
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
	return selinux_chain_has_cred_perm(
		cred, tcred, SECCLASS_PROCESS, av, NULL);
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
		return selinux_task_has_perm(p, PROCESS__SETRLIMIT);

	return 0;
}

static int selinux_task_setscheduler(struct task_struct *p)
{
	return selinux_task_has_perm(p, PROCESS__SETSCHED);
}

static int selinux_task_getscheduler(struct task_struct *p)
{
	return selinux_task_has_perm(p, PROCESS__GETSCHED);
}

static int selinux_task_movememory(struct task_struct *p)
{
	return selinux_task_has_perm(p, PROCESS__SETSCHED);
}

static int selinux_task_kill(struct task_struct *p, struct kernel_siginfo *info,
				int sig, const struct cred *cred)
{
	u32 perm;
	const struct cred *source = cred ?: current_cred();
	const struct cred *target = get_task_cred(p);
	int rc;

	if (!sig)
		perm = PROCESS__SIGNULL; /* null signal; existence test */
	else
		perm = signal_to_av(sig);
	rc = selinux_chain_has_cred_perm(
		source, target, SECCLASS_PROCESS, perm, NULL);
	put_cred(target);
	return rc;
}

static void selinux_task_to_inode(struct task_struct *p,
				  struct inode *inode)
{
	struct inode_security_struct *isec = selinux_inode(inode);
	struct selinux_object_identity *task_object;
	const struct cred *task_cred = get_task_cred(p);
	int rc;

	task_object = selinux_object_identity_alloc_from_cred(
		task_cred,
		inode_mode_to_security_class(inode->i_mode),
		SELINUX_LABEL_SOURCE_TASK,
		GFP_KERNEL_ACCOUNT);
	if (IS_ERR(task_object)) {
		put_cred(task_cred);
		return;
	}
	rc = selinux_object_label_copy_for_state_chain(
		isec->object,
		task_object,
		cred_selinux_state(task_cred),
		inode_mode_to_security_class(inode->i_mode),
		GFP_KERNEL_ACCOUNT);
	selinux_object_identity_put(task_object);
	put_cred(task_cred);
	if (rc)
		return;

	isec->sclass = inode_mode_to_security_class(inode->i_mode);
}

static int selinux_userns_create(const struct cred *cred)
{
	return selinux_chain_has_self_perm(
		cred, SECCLASS_USER_NAMESPACE, USER_NAMESPACE__CREATE, NULL);
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

/**
 * selinux_skb_peerlbl_sid - Determine the peer label of a packet
 * @skb: the packet
 * @family: protocol family
 * @sid: the packet's peer label SID
 *
 * Description:
 * Check the various different forms of network peer labeling and determine
 * the peer label/SID for the packet; most of the magic actually occurs in
 * the security server function security_net_peersid_cmp().  The function
 * returns zero if the value in @sid is valid (although it may be SECSID_NULL)
 * or -EACCES if @sid is invalid due to inconsistencies with the different
 * peer labels.
 *
 */
static int selinux_skb_peerlbl_sid(
	struct selinux_state *state,
	struct sk_buff *skb,
	u16 family,
	u32 *sid)
{
	int err;
	u32 xfrm_sid;
	u32 nlbl_sid;
	u32 nlbl_type;

	err = selinux_xfrm_skb_sid(state, skb, &xfrm_sid);
	if (unlikely(err))
		return -EACCES;
	err = selinux_netlbl_skbuff_getsid(
		state, skb, family, &nlbl_type, &nlbl_sid);
	if (unlikely(err))
		return -EACCES;

	err = security_net_peersid_resolve(
		state, nlbl_sid, nlbl_type, xfrm_sid, sid);
	if (unlikely(err)) {
		pr_warn(
		       "SELinux: failure in selinux_skb_peerlbl_sid(),"
		       " unable to determine packet's peer label\n");
		return -EACCES;
	}

	return 0;
}

static int selinux_skb_peer_object(
	const struct cred *cred,
	struct sk_buff *skb,
	u16 family,
	struct selinux_object_identity **result)
{
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	const struct cred *level_cred = cred;
	struct selinux_object_identity *object;
	struct selinux_state *state;
	u16 count = 0;
	int rc;

	if (!cred || !result)
		return -EINVAL;
	*result = NULL;
	state = cred_selinux_state(cred);
	object = selinux_object_identity_alloc(state, GFP_ATOMIC);
	if (IS_ERR(object))
		return PTR_ERR(object);

	while (state) {
		const struct cred_security_struct *security;

		if (!level_cred || count >= ARRAY_SIZE(states)) {
			rc = -ESTALE;
			goto out;
		}
		security = selinux_cred(level_cred);
		if (security->state != state) {
			rc = -ESTALE;
			goto out;
		}
		states[count] = state;
		rc = selinux_skb_peerlbl_sid(
			state, skb, family, &values[count].sid);
		if (rc)
			goto out;
		values[count].sclass = SECCLASS_PEER;
		if (values[count].sid == SECSID_NULL) {
			values[count].sid = SECINITSID_UNLABELED;
			values[count].source = SELINUX_LABEL_SOURCE_UNSPECIFIED;
		} else {
			values[count].source = SELINUX_LABEL_SOURCE_NETWORK;
		}
		count++;
		level_cred = security->parent_cred;
		state = state->parent;
	}
	if (level_cred) {
		rc = -ESTALE;
		goto out;
	}
	rc = selinux_object_labels_set_chain(
		object, states, values, count, GFP_ATOMIC);
	if (rc)
		goto out;
	*result = object;
	return 0;
out:
	selinux_object_identity_put(object);
	return rc;
}

static int selinux_root_sid_object(
	const struct cred *cred,
	u32 root_sid,
	u16 sclass,
	struct selinux_object_identity **result)
{
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	const struct cred *level_cred = cred;
	struct selinux_object_identity *object;
	struct selinux_state *state;
	char *context = NULL;
	u32 context_len = 0;
	u16 count = 0;
	int rc;

	if (!cred || !sclass || !result)
		return -EINVAL;
	*result = NULL;
	if (root_sid == SECSID_NULL)
		root_sid = SECINITSID_UNLABELED;
	rc = security_sid_to_context(
		init_selinux_state, root_sid, &context, &context_len);
	if (rc)
		return rc;
	state = cred_selinux_state(cred);
	object = selinux_object_identity_alloc(state, GFP_ATOMIC);
	if (IS_ERR(object)) {
		kfree(context);
		return PTR_ERR(object);
	}
	while (state) {
		const struct cred_security_struct *security;

		if (!level_cred || count >= ARRAY_SIZE(states)) {
			rc = -ESTALE;
			goto out;
		}
		security = selinux_cred(level_cred);
		if (security->state != state) {
			rc = -ESTALE;
			goto out;
		}
		states[count] = state;
		if (state == init_selinux_state) {
			values[count].sid = root_sid;
		} else {
			rc = security_context_to_sid(
				state,
				context,
				context_len,
				&values[count].sid,
				GFP_ATOMIC);
			if (rc)
				goto out;
		}
		values[count].sclass = sclass;
		values[count].source = SELINUX_LABEL_SOURCE_NETWORK;
		count++;
		level_cred = security->parent_cred;
		state = state->parent;
	}
	if (level_cred) {
		rc = -ESTALE;
		goto out;
	}
	rc = selinux_object_labels_set_chain(
		object, states, values, count, GFP_ATOMIC);
	if (rc)
		goto out;
	*result = object;
	kfree(context);
	return 0;
out:
	selinux_object_identity_put(object);
	kfree(context);
	return rc;
}

static const struct skb_security_struct *selinux_skb_provenance(
	const struct sk_buff *skb)
{
	const struct skb_security_struct *security = selinux_skb(skb);

	if (!security || !security->object || !security->creator_cred)
		return NULL;
	return security;
}

static int selinux_skb_provenance_set(
	struct sk_buff *skb,
	const struct cred *cred,
	struct selinux_object_identity *object)
{
	struct skb_security_struct *security;
	int rc;

	if (!cred || !object)
		return -EINVAL;
	security = selinux_skb(skb);
	if (security) {
		if (!security->object && !security->creator_cred)
			goto initialize;
		return security->object && security->creator_cred ? 0 : -ESTALE;
	}
	rc = security_skb_provenance_alloc(skb, GFP_ATOMIC);
	if (rc)
		return rc;
	security = selinux_skb(skb);
	if (!security)
		return -EOPNOTSUPP;

initialize:
	security->object = selinux_object_identity_get(object);
	if (!security->object)
		return -ESTALE;
	security->creator_cred = get_cred(cred);
	return 0;
}

static void selinux_skb_free_security(void *blob)
{
	struct skb_security_struct *security = selinux_skb_blob(blob);

	selinux_object_identity_put(security->object);
	if (security->creator_cred)
		put_cred(security->creator_cred);
	security->object = NULL;
	security->creator_cred = NULL;
}

/**
 * selinux_conn_sid - Determine the child socket label for a connection
 * @sk_sid: the parent socket's SID
 * @skb_sid: the packet's SID
 * @conn_sid: the resulting connection SID
 *
 * If @skb_sid is valid then the user:role:type information from @sk_sid is
 * combined with the MLS information from @skb_sid in order to create
 * @conn_sid.  If @skb_sid is not valid then @conn_sid is simply a copy
 * of @sk_sid.  Returns zero on success, negative values on failure.
 *
 */
static int selinux_conn_sid(
	struct selinux_state *state,
	u32 sk_sid,
	u32 skb_sid,
	u32 *conn_sid)
{
	int err = 0;

	if (skb_sid != SECSID_NULL)
		err = security_sid_mls_copy(
			state, sk_sid, skb_sid, conn_sid);
	else
		*conn_sid = sk_sid;

	return err;
}

/* socket security operations */

static int socket_sockcreate_labels(
	const struct cred *cred,
	struct selinux_object_identity *object,
	int family,
	int type,
	int protocol)
{
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	const struct cred *level_cred = cred;
	struct selinux_state *state = cred_selinux_state(cred);
	u16 count = 0;

	while (state) {
		const struct cred_security_struct *security;
		u16 secclass;
		int rc;

		if (!level_cred || count >= ARRAY_SIZE(states))
			return -ESTALE;
		security = selinux_cred(level_cred);
		if (security->state != state)
			return -ESTALE;
		secclass = socket_type_to_security_class(
			state, family, type, protocol);
		states[count] = state;
		values[count].sclass = secclass;
		values[count].source = SELINUX_LABEL_SOURCE_TRANSITION;
		if (security->sockcreate_sid) {
			values[count].sid = security->sockcreate_sid;
		} else {
			rc = security_transition_sid(
				state,
				security->sid,
				security->sid,
				secclass,
				NULL,
				&values[count].sid);
			if (rc)
				return rc;
		}
		count++;
		level_cred = security->parent_cred;
		state = state->parent;
	}
	if (level_cred)
		return -ESTALE;
	return selinux_object_labels_set_chain(
		object,
		states,
		values,
		count,
		GFP_KERNEL_ACCOUNT);
}

static bool sock_skip_has_perm(
	const struct selinux_state *state,
	u32 sid)
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
	if (!selinux_policycap_userspace_initial_context(state) &&
	    sid == SECINITSID_INIT)
		return true;
	return false;
}

struct selinux_sock_permission_request {
	struct sock *sk;
	struct sk_security_struct *security;
	u32 requested;
};

struct selinux_sock_object_permission_request {
	struct sock *sk;
	struct sk_security_struct *security;
	const struct selinux_object_identity *target;
	u32 requested;
	bool tcp_or_sctp_only;
};

static int selinux_resolve_sock_permission(
	struct selinux_state *state,
	const struct cred *level_cred,
	void *data,
	struct selinux_chain_permission *permission)
{
	const struct selinux_sock_permission_request *request = data;
	struct selinux_object_label_value label;
	u16 fallback_class = socket_type_to_security_class(
		state,
		request->sk->sk_family,
		request->sk->sk_type,
		request->sk->sk_protocol);

	selinux_object_label_get_or_unlabeled(
		state,
		request->security->object,
		fallback_class,
		&label);
	permission->tsid = label.sid;
	permission->requested = request->requested;
	permission->tclass = label.sclass ? label.sclass : fallback_class;
	permission->decided =
		label.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS &&
		!sock_skip_has_perm(state, label.sid);
	return 0;
}

static int selinux_resolve_sock_object_permission(
	struct selinux_state *state,
	const struct cred *level_cred,
	void *data,
	struct selinux_chain_permission *permission)
{
	const struct selinux_sock_object_permission_request *request = data;
	struct selinux_object_label_value socket_label;
	struct selinux_object_label_value target_label;
	u16 fallback_class = socket_type_to_security_class(
		state,
		request->sk->sk_family,
		request->sk->sk_type,
		request->sk->sk_protocol);

	selinux_object_label_get_or_unlabeled(
		state,
		request->security->object,
		fallback_class,
		&socket_label);
	selinux_object_label_get_or_unlabeled(
		state,
		request->target,
		SECCLASS_NULL,
		&target_label);
	permission->ssid = socket_label.sid;
	permission->tsid = target_label.sid;
	permission->requested = request->requested;
	permission->tclass = socket_label.sclass ?
		socket_label.sclass : fallback_class;
	if (request->tcp_or_sctp_only &&
	    permission->tclass != SECCLASS_TCP_SOCKET &&
	    permission->tclass != SECCLASS_SCTP_SOCKET) {
		permission->requested = 0;
		permission->decided = false;
		return 0;
	}
	permission->decided =
		socket_label.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS &&
		target_label.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS;
	return 0;
}

static int selinux_sock_object_has_perm(
	const struct cred *cred,
	struct sock *sk,
	const struct selinux_object_identity *target,
	u32 requested,
	bool tcp_or_sctp_only,
	struct common_audit_data *auditdata)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct selinux_sock_object_permission_request request = {
		.sk = sk,
		.security = sksec,
		.target = target,
		.requested = requested,
		.tcp_or_sctp_only = tcp_or_sctp_only,
	};

	return selinux_chain_has_custom_perm(
		cred,
		sksec->object,
		target,
		selinux_resolve_sock_object_permission,
		&request,
		auditdata);
}

static int sock_has_perm(struct sock *sk, u32 perms)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct selinux_sock_permission_request request = {
		.sk = sk,
		.security = sksec,
		.requested = perms,
	};
	struct common_audit_data ad;
	struct lsm_network_audit net;

	ad_net_init_from_sk(&ad, &net, sk);
	return selinux_chain_has_custom_perm(
		current_cred(),
		NULL,
		sksec->object,
		selinux_resolve_sock_permission,
		&request,
		&ad);
}

static int selinux_socket_create(int family, int type,
				 int protocol, int kern)
{
	struct selinux_object_identity *object;
	u16 secclass;
	int rc;

	if (kern)
		return 0;

	secclass = socket_type_to_security_class(
		current_selinux_state, family, type, protocol);
	object = selinux_object_identity_alloc(
		current_selinux_state,
		GFP_KERNEL_ACCOUNT);
	if (IS_ERR(object))
		return PTR_ERR(object);
	rc = socket_sockcreate_labels(
		current_cred(), object, family, type, protocol);
	if (!rc)
		rc = selinux_chain_has_perm(
			current_cred(),
			object,
			secclass,
			SOCKET__CREATE,
			NULL);
	selinux_object_identity_put(object);
	return rc;
}

static int selinux_socket_post_create(struct socket *sock, int family,
				      int type, int protocol, int kern)
{
	struct inode_security_struct *isec =
		inode_security_novalidate(SOCK_INODE(sock));
	struct sk_security_struct *sksec;
	u16 sclass = socket_type_to_security_class(
		current_selinux_state, family, type, protocol);
	int err = 0;

	if (kern)
		err = selinux_object_set_initial_chain(
			isec->object,
			current_selinux_state,
			SECINITSID_KERNEL,
			sclass,
			SELINUX_LABEL_SOURCE_KERNEL_INITIAL,
			GFP_KERNEL_ACCOUNT);
	else
		err = socket_sockcreate_labels(
			current_cred(), isec->object, family, type, protocol);
	if (err)
		return err;

	WRITE_ONCE(isec->sclass, sclass);

	if (sock->sk) {
		sksec = selinux_sock(sock->sk);
		if (!sksec->object)
			return -EUCLEAN;
		err = selinux_object_label_copy_for_state_chain(
			sksec->object,
			isec->object,
			current_selinux_state,
			sclass,
			GFP_KERNEL_ACCOUNT);
		if (err)
			return err;
		/* Allows detection of the first association on this socket */
		if (protocol == IPPROTO_SCTP)
			sksec->sctp_assoc_state = SCTP_ASSOC_UNSET;

		err = selinux_netlbl_socket_post_create(sock->sk, family);
	}

	return err;
}

static int selinux_socket_socketpair(struct socket *socka,
				     struct socket *sockb)
{
	struct sk_security_struct *sksec_a = selinux_sock(socka->sk);
	struct sk_security_struct *sksec_b = selinux_sock(sockb->sk);

	selinux_object_clear(&sksec_a->peer_object);
	sksec_a->peer_object =
		selinux_object_identity_get(sksec_b->object);
	selinux_object_clear(&sksec_b->peer_object);
	sksec_b->peer_object =
		selinux_object_identity_get(sksec_a->object);

	return 0;
}

/* Range of port numbers used to automatically bind.
   Need to determine whether we should perform a name_bind
   permission check between the socket and the port number. */

static int __selinux_socket_bind(struct sock *sk, struct sockaddr *address, int addrlen)
{
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
		struct selinux_object_identity *network_object;
		u16 family_sa;
		unsigned short snum;
		u32 node_perm;

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
				err = sel_netport_object(
					current_cred(), sk->sk_protocol, snum,
					&network_object);
				if (err)
					goto out;
				err = selinux_sock_object_has_perm(
					current_cred(), sk, network_object,
					SOCKET__NAME_BIND, false, &ad);
				selinux_object_identity_put(network_object);
				if (err)
					goto out;
			}
		}

		/* node_bind occupies the same AV bit in every socket class. */
		node_perm = TCP_SOCKET__NODE_BIND;

		err = sel_netnode_object(
			current_cred(), addrp, family_sa, &network_object);
		if (err)
			goto out;

		if (family_sa == AF_INET)
			ad.u.net->v4info.saddr = addr4->sin_addr.s_addr;
		else
			ad.u.net->v6info.saddr = addr6->sin6_addr;

		err = selinux_sock_object_has_perm(
			current_cred(), sk, network_object, node_perm, false, &ad);
		selinux_object_identity_put(network_object);
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
	if ((sk->sk_family == PF_INET || sk->sk_family == PF_INET6) &&
	    (sk->sk_type == SOCK_STREAM || sk->sk_type == SOCK_SEQPACKET) &&
	    (default_protocol_stream(sk->sk_protocol) ||
	     sk->sk_protocol == IPPROTO_SCTP)) {
		struct common_audit_data ad;
		struct lsm_network_audit net = {0,};
		struct sockaddr_in *addr4 = NULL;
		struct sockaddr_in6 *addr6 = NULL;
		struct selinux_object_identity *port_object;
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
			if (sk->sk_protocol == IPPROTO_SCTP)
				return -EINVAL;
			else
				return -EAFNOSUPPORT;
		}

		err = sel_netport_object(
			current_cred(), sk->sk_protocol, snum, &port_object);
		if (err)
			return err;

		/* name_connect occupies the same AV bit in TCP and SCTP. */
		perm = TCP_SOCKET__NAME_CONNECT;

		ad.type = LSM_AUDIT_DATA_NET;
		ad.u.net = &net;
		ad.u.net->dport = htons(snum);
		ad.u.net->family = address->sa_family;
		err = selinux_sock_object_has_perm(
			current_cred(), sk, port_object, perm, true, &ad);
		selinux_object_identity_put(port_object);
		if (err)
			return err;
	}

	return 0;
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

	err = sock_has_perm(sock->sk, SOCKET__ACCEPT);
	if (err)
		return err;

	isec = inode_security_novalidate(SOCK_INODE(sock));
	sclass = READ_ONCE(isec->sclass);

	newisec = inode_security_novalidate(SOCK_INODE(newsock));
	err = selinux_object_label_copy_for_state_chain(
		newisec->object,
		isec->object,
		current_selinux_state,
		sclass,
		GFP_KERNEL_ACCOUNT);
	if (!err)
		WRITE_ONCE(newisec->sclass, sclass);
	return err;
}

static int selinux_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				  int size)
{
	int rc;
	struct sockaddr *const addr = msg->msg_name;
	const int addrlen = msg->msg_namelen;

	rc = sock_has_perm(sock->sk, SOCKET__WRITE);
	if (rc)
		return rc;

	if (addr && (msg->msg_flags & MSG_FASTOPEN) &&
	    (sk_is_tcp(sock->sk) ||
	     (sk_is_inet(sock->sk) && sock->sk->sk_type == SOCK_STREAM &&
	      sock->sk->sk_protocol == IPPROTO_MPTCP))) {
		rc = selinux_socket_connect(sock, addr, addrlen);
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

static int selinux_unix_stream_connect_labels(
	const struct cred *cred,
	struct sk_security_struct *client,
	struct sk_security_struct *server,
	struct sk_security_struct *accepted)
{
	struct selinux_object_label_update *updates;
	unsigned int retry;
	int rc = -ESTALE;

	updates = kcalloc(
		SELINUX_NS_MAX_DEPTH + 1,
		sizeof(*updates),
		GFP_KERNEL_ACCOUNT);
	if (!updates)
		return -ENOMEM;

	for (retry = 0; retry < 4; retry++) {
		const struct cred *level_cred = cred;
		struct selinux_state *state = cred_selinux_state(cred);
		struct selinux_object_generation_guard guards[3];
		u64 client_generation =
			selinux_object_identity_generation(client->object);
		u64 server_generation =
			selinux_object_identity_generation(server->object);
		u64 accepted_generation =
			selinux_object_identity_generation(accepted->object);
		u64 epoch = selinux_chain_epoch_read(state);
		u16 count = 0;

		if (!client_generation || !server_generation ||
		    !accepted_generation || !epoch)
			continue;
		rc = 0;
		while (state) {
			const struct cred_security_struct *security;
			struct selinux_object_label_value client_label;
			struct selinux_object_label_value server_label;
			struct selinux_object_label_value accepted_label;

			if (!level_cred || count >= SELINUX_NS_MAX_DEPTH + 1) {
				rc = -ESTALE;
				break;
			}
			security = selinux_cred(level_cred);
			if (security->state != state) {
				rc = -ESTALE;
				break;
			}
			selinux_object_label_get_or_unlabeled(
				state, client->object,
				SECCLASS_UNIX_STREAM_SOCKET, &client_label);
			selinux_object_label_get_or_unlabeled(
				state, server->object,
				SECCLASS_UNIX_STREAM_SOCKET, &server_label);
			accepted_label = server_label;
			rc = security_sid_mls_copy(
				state,
				server_label.sid,
				client_label.sid,
				&accepted_label.sid);
			if (rc)
				break;
			accepted_label.sclass = SECCLASS_UNIX_STREAM_SOCKET;
			accepted_label.source =
				SELINUX_LABEL_SOURCE_TRANSITION;
			updates[count++] =
				(struct selinux_object_label_update) {
					.state = state,
					.object = accepted->object,
					.value = accepted_label,
					.expected_generation =
						accepted_generation,
				};
			level_cred = security->parent_cred;
			state = state->parent;
		}
		if (rc || state || level_cred) {
			if (!rc)
				rc = -ESTALE;
			if (rc != -ESTALE)
				break;
			continue;
		}
		guards[0] = (struct selinux_object_generation_guard) {
			.object = client->object,
			.generation = client_generation,
		};
		guards[1] = (struct selinux_object_generation_guard) {
			.object = server->object,
			.generation = server_generation,
		};
		guards[2] = (struct selinux_object_generation_guard) {
			.object = accepted->object,
			.generation = accepted_generation,
		};
		if (epoch != selinux_chain_epoch_read(
		    cred_selinux_state(cred))) {
			rc = -ESTALE;
			continue;
		}
		rc = selinux_object_labels_update_transaction_guarded(
			updates,
			count,
			guards,
			ARRAY_SIZE(guards),
			GFP_KERNEL_ACCOUNT);
		if (rc != -ESTALE)
			break;
	}
	if (!rc) {
		selinux_object_clear(&accepted->peer_object);
		accepted->peer_object =
			selinux_object_identity_get(client->object);
		selinux_object_clear(&client->peer_object);
		client->peer_object =
			selinux_object_identity_get(accepted->object);
	}
	kfree(updates);
	return rc;
}

static int selinux_socket_unix_stream_connect(struct sock *sock,
					      struct sock *other,
					      struct sock *newsk)
{
	struct sk_security_struct *sksec_sock = selinux_sock(sock);
	struct sk_security_struct *sksec_other = selinux_sock(other);
	struct sk_security_struct *sksec_new = selinux_sock(newsk);
	struct common_audit_data ad;
	struct lsm_network_audit net;
	int err;

	ad_net_init_from_sk(&ad, &net, other);

	err = selinux_chain_has_object_perm(
		current_cred(),
		sksec_sock->object,
		sksec_other->object,
		SECCLASS_UNIX_STREAM_SOCKET,
		UNIX_STREAM_SOCKET__CONNECTTO,
		&ad);
	if (err)
		return err;

	return selinux_unix_stream_connect_labels(
		current_cred(), sksec_sock, sksec_other, sksec_new);
}

static int selinux_socket_unix_may_send(struct socket *sock,
					struct socket *other)
{
	struct sk_security_struct *ssec = selinux_sock(sock->sk);
	struct sk_security_struct *osec = selinux_sock(other->sk);
	struct common_audit_data ad;
	struct lsm_network_audit net;

	ad_net_init_from_sk(&ad, &net, other->sk);

	return selinux_chain_has_object_perm(
		current_cred(),
		ssec->object,
		osec->object,
		SECCLASS_UNIX_DGRAM_SOCKET,
		SOCKET__SENDTO,
		&ad);
}

static int selinux_inet_sys_rcv_skb(
	const struct cred *cred,
	struct net *ns,
	int ifindex,
	char *addrp,
	u16 family,
	struct selinux_object_identity *peer,
	struct common_audit_data *ad)
{
	struct selinux_object_identity *interface = NULL;
	struct selinux_object_identity *node = NULL;
	int err;

	err = sel_netif_object(cred, ns, ifindex, &interface);
	if (err)
		return err;
	err = selinux_chain_has_object_perm_with_policycap(
		cred,
		peer,
		interface,
		SECCLASS_NETIF,
		NETIF__INGRESS,
		POLICYDB_CAP_NETPEER,
		ad);
	selinux_object_identity_put(interface);
	if (err)
		return err;

	err = sel_netnode_object(cred, addrp, family, &node);
	if (err)
		return err;
	err = selinux_chain_has_object_perm_with_policycap(
		cred,
		peer,
		node,
		SECCLASS_NODE,
		NODE__RECVFROM,
		POLICYDB_CAP_NETPEER,
		ad);
	selinux_object_identity_put(node);
	return err;
}

static int selinux_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	const struct cred *creator = sksec->creator_cred;
	struct selinux_object_identity *peer = NULL;
	struct selinux_object_identity *secmark = NULL;
	u16 family = sk->sk_family;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	char *addrp;
	int err;

	if (family != PF_INET && family != PF_INET6)
		return 0;
	if (!creator)
		return -ESTALE;

	/* Handle mapped IPv4 packets arriving via IPv6 sockets */
	if (family == PF_INET6 && skb->protocol == htons(ETH_P_IP))
		family = PF_INET;

	if (!selinux_secmark_enabled(creator) &&
	    !selinux_peerlbl_enabled(creator))
		return 0;

	ad_net_init_from_iif(&ad, &net, skb->skb_iif, family);
	err = selinux_parse_skb(skb, &ad, &addrp, 1, NULL);
	if (err)
		return err;

	if (selinux_peerlbl_enabled(creator)) {
		err = selinux_skb_peer_object(creator, skb, family, &peer);
		if (err)
			return err;
		err = selinux_inet_sys_rcv_skb(
			creator,
			sock_net(sk),
			skb->skb_iif,
			addrp,
			family,
			peer,
			&ad);
		if (err) {
			selinux_netlbl_err(skb, family, err, 0);
			goto out;
		}
		err = selinux_chain_has_object_perm_with_policycap(
			creator,
			sksec->object,
			peer,
			SECCLASS_PEER,
			PEER__RECV,
			POLICYDB_CAP_NETPEER,
			&ad);
		if (err) {
			selinux_netlbl_err(skb, family, err, 0);
			goto out;
		}
	}

	if (selinux_secmark_enabled(creator)) {
		err = selinux_root_sid_object(
			creator, skb->secmark, SECCLASS_PACKET, &secmark);
		if (err)
			goto out;
		err = selinux_chain_has_object_perm(
			creator,
			sksec->object,
			secmark,
			SECCLASS_PACKET,
			PACKET__RECV,
			&ad);
		if (err)
			goto out;
	}

	err = selinux_netlbl_sock_rcv_skb(sksec, skb, family, &ad);
	if (!err)
		err = selinux_xfrm_sock_rcv_skb(sksec, skb, &ad);
out:
	selinux_object_identity_put(secmark);
	selinux_object_identity_put(peer);
	return err;
}

static int selinux_socket_getpeersec_stream(struct socket *sock,
					    sockptr_t optval, sockptr_t optlen,
					    unsigned int len)
{
	struct selinux_state *state = current_selinux_state;
	struct selinux_object_label_value peer_label;
	struct selinux_object_label_value socket_label;
	struct sk_security_struct *sksec = selinux_sock(sock->sk);
	int err = 0;
	char *scontext = NULL;
	u32 scontext_len;

	if (selinux_object_label_get(state, sksec->object, &socket_label) ||
	    selinux_object_label_get(state, sksec->peer_object, &peer_label))
		return -ENOPROTOOPT;
	if (socket_label.sclass != SECCLASS_UNIX_STREAM_SOCKET &&
	    socket_label.sclass != SECCLASS_TCP_SOCKET &&
	    socket_label.sclass != SECCLASS_SCTP_SOCKET)
		return -ENOPROTOOPT;
	if (peer_label.sid == SECSID_NULL ||
	    peer_label.source == SELINUX_LABEL_SOURCE_UNSPECIFIED)
		return -ENOPROTOOPT;

	err = security_sid_to_context(
		state, peer_label.sid, &scontext, &scontext_len);
	if (err)
		return err;
	if (scontext_len > len) {
		err = -ERANGE;
		goto out_len;
	}

	if (copy_to_sockptr(optval, scontext, scontext_len))
		err = -EFAULT;
out_len:
	if (copy_to_sockptr(optlen, &scontext_len, sizeof(scontext_len)))
		err = -EFAULT;
	kfree(scontext);
	return err;
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
		struct selinux_object_label_value label;

		isec = inode_security_novalidate(SOCK_INODE(sock));
		if (!selinux_object_label_get(
		    current_selinux_state, isec->object, &label))
			peer_secid = label.sid;
	} else if (skb)
		selinux_skb_peerlbl_sid(
			current_selinux_state, skb, family, &peer_secid);

	*secid = peer_secid;
	if (peer_secid == SECSID_NULL)
		return -ENOPROTOOPT;
	return 0;
}

static int selinux_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	u16 sclass = socket_type_to_security_class(
		current_selinux_state,
		family,
		sk->sk_type,
		sk->sk_protocol);
	int rc;

	rc = selinux_object_init_initial(
		&sksec->object,
		current_selinux_state,
		SECINITSID_UNLABELED,
		sclass,
		SELINUX_LABEL_SOURCE_UNSPECIFIED,
		priority);
	if (rc)
		return rc;
	rc = selinux_object_init_initial(
		&sksec->peer_object,
		current_selinux_state,
		SECINITSID_UNLABELED,
		sclass,
		SELINUX_LABEL_SOURCE_UNSPECIFIED,
		priority);
	if (rc) {
		selinux_object_clear(&sksec->object);
		return rc;
	}
	sksec->creator_cred = get_current_cred();
	selinux_netlbl_sk_security_reset(sksec);

	return 0;
}

static void selinux_sk_free_security(struct sock *sk)
{
	struct sk_security_struct *sksec = selinux_sock(sk);

	selinux_netlbl_sk_security_free(sksec);
	selinux_object_clear(&sksec->object);
	selinux_object_clear(&sksec->peer_object);
	put_cred(sksec->creator_cred);
	sksec->creator_cred = NULL;
}

static void selinux_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct sk_security_struct *newsksec = selinux_sock(newsk);
	const struct cred *creator = sksec->creator_cred;
	struct selinux_state *leaf;
	u16 sclass;

	if (!creator)
		return;
	leaf = cred_selinux_state(creator);
	sclass = socket_type_to_security_class(
		leaf, sk->sk_family, sk->sk_type, sk->sk_protocol);

	if (selinux_object_label_copy_for_state_chain(
	    newsksec->object,
	    sksec->object,
	    leaf,
	    sclass,
	    GFP_ATOMIC))
		return;
	if (selinux_object_label_copy_for_state_chain(
	    newsksec->peer_object,
	    sksec->peer_object,
	    leaf,
	    sclass,
	    GFP_ATOMIC))
		return;
	put_cred(newsksec->creator_cred);
	newsksec->creator_cred = get_cred(creator);

	selinux_netlbl_sk_security_reset(newsksec);
}

static void selinux_sk_getsecid(const struct sock *sk, u32 *secid)
{
	if (!sk)
		*secid = SECINITSID_ANY_SOCKET;
	else {
		const struct sk_security_struct *sksec = selinux_sock(sk);
		struct selinux_object_label_value label;

		if (selinux_object_label_get(
		    current_selinux_state, sksec->object, &label))
			*secid = SECINITSID_UNLABELED;
		else
			*secid = label.sid;
	}
}

static void selinux_sock_graft(struct sock *sk, struct socket *parent)
{
	struct inode_security_struct *isec =
		inode_security_novalidate(SOCK_INODE(parent));
	struct sk_security_struct *sksec = selinux_sock(sk);
	u16 sclass = socket_type_to_security_class(
		current_selinux_state,
		sk->sk_family,
		sk->sk_type,
		sk->sk_protocol);
	int rc;

	if (sk->sk_family == PF_INET || sk->sk_family == PF_INET6 ||
	    sk->sk_family == PF_UNIX) {
		rc = selinux_object_label_copy_for_state_chain(
			isec->object,
			sksec->object,
			current_selinux_state,
			sclass,
			GFP_ATOMIC);
		if (rc)
			return;
	}
}

struct sctp_security_struct *selinux_sctp(
	const struct sctp_association *association)
{
	return association->security + selinux_blob_sizes.lbs_sctp_assoc;
}

static int selinux_sctp_security_init(struct sctp_association *association)
{
	struct sctp_security_struct *security = selinux_sctp(association);
	struct sk_security_struct *socket_security =
		selinux_sock(association->base.sk);
	const struct cred *creator = socket_security->creator_cred;
	struct selinux_state *leaf;
	int rc;

	if (security->creator_cred)
		return 0;
	if (!creator)
		return -ESTALE;
	leaf = cred_selinux_state(creator);
	security->object = selinux_object_identity_alloc_initial(
		leaf,
		SECINITSID_UNLABELED,
		SECCLASS_SCTP_SOCKET,
		SELINUX_LABEL_SOURCE_UNSPECIFIED,
		GFP_ATOMIC);
	if (IS_ERR(security->object)) {
		rc = PTR_ERR(security->object);
		security->object = NULL;
		return rc;
	}
	security->peer_object = selinux_object_identity_alloc_initial(
		leaf,
		SECINITSID_UNLABELED,
		SECCLASS_PEER,
		SELINUX_LABEL_SOURCE_UNSPECIFIED,
		GFP_ATOMIC);
	if (IS_ERR(security->peer_object)) {
		rc = PTR_ERR(security->peer_object);
		security->peer_object = NULL;
		selinux_object_clear(&security->object);
		return rc;
	}
	rc = selinux_object_label_copy_for_state_chain(
		security->object,
		socket_security->object,
		leaf,
		SECCLASS_SCTP_SOCKET,
		GFP_ATOMIC);
	if (rc) {
		selinux_object_clear(&security->peer_object);
		selinux_object_clear(&security->object);
		return rc;
	}
	security->creator_cred = get_cred(creator);
	return 0;
}

static void selinux_sctp_assoc_free_security(
	struct sctp_association *association)
{
	struct sctp_security_struct *security = selinux_sctp(association);

	selinux_object_clear(&security->peer_object);
	selinux_object_clear(&security->object);
	put_cred(security->creator_cred);
	security->creator_cred = NULL;
}

static int selinux_connection_labels(
	const struct cred *creator,
	struct selinux_object_identity *destination,
	struct selinux_object_identity *socket,
	struct selinux_object_identity *peer)
{
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	const struct cred *level_cred = creator;
	struct selinux_state *state = cred_selinux_state(level_cred);
	u16 count = 0;

	while (state) {
		const struct cred_security_struct *cred_security;
		struct selinux_object_label_value socket_label;
		struct selinux_object_label_value peer_label;
		int rc;

		if (!level_cred || count >= ARRAY_SIZE(states))
			return -ESTALE;
		cred_security = selinux_cred(level_cred);
		if (cred_security->state != state)
			return -ESTALE;
		states[count] = state;
		selinux_object_label_get_or_unlabeled(
			state,
			socket,
			SECCLASS_SCTP_SOCKET,
			&socket_label);
		selinux_object_label_get_or_unlabeled(
			state,
			peer,
			SECCLASS_PEER,
			&peer_label);
		values[count] = socket_label;
		if (selinux_policycap_extsockclass(state)) {
			rc = selinux_conn_sid(
				state,
				socket_label.sid,
				peer_label.sid,
				&values[count].sid);
			if (rc)
				return rc;
			values[count].source = SELINUX_LABEL_SOURCE_NETWORK;
		}
		count++;
		level_cred = cred_security->parent_cred;
		state = state->parent;
	}
	if (level_cred)
		return -ESTALE;
	return selinux_object_labels_set_chain(
		destination, states, values, count, GFP_ATOMIC);
}

/*
 * Determines peer_secid for the asoc and updates socket's peer label
 * if it's the first association on the socket.
 */
static int selinux_sctp_process_new_assoc(struct sctp_association *asoc,
					  struct sk_buff *skb)
{
	struct sock *sk = asoc->base.sk;
	u16 family = sk->sk_family;
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct sctp_security_struct *asocsec = selinux_sctp(asoc);
	struct selinux_object_identity *packet_peer = NULL;
	const struct cred *creator;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	int err;

	/* handle mapped IPv4 packets arriving via IPv6 sockets */
	if (family == PF_INET6 && skb->protocol == htons(ETH_P_IP))
		family = PF_INET;

	err = selinux_sctp_security_init(asoc);
	if (err)
		return err;
	creator = asocsec->creator_cred;
	err = selinux_skb_peer_object(creator, skb, family, &packet_peer);
	if (err)
		return err;
	err = selinux_object_label_copy_for_state_chain(
		asocsec->peer_object,
		packet_peer,
		cred_selinux_state(creator),
		SECCLASS_PEER,
		GFP_ATOMIC);
	selinux_object_identity_put(packet_peer);
	if (err)
		return err;

	if (sksec->sctp_assoc_state == SCTP_ASSOC_UNSET) {
		sksec->sctp_assoc_state = SCTP_ASSOC_SET;

		/* Here as first association on socket. As the peer SID
		 * was allowed by peer recv (and the netif/node checks),
		 * then it is approved by policy and used as the primary
		 * peer SID for getpeercon(3).
		 */
		err = selinux_object_label_copy_for_state_chain(
			sksec->peer_object,
			asocsec->peer_object,
			cred_selinux_state(creator),
			SECCLASS_PEER,
			GFP_ATOMIC);
		if (err)
			return err;
	} else {
		/* Other association peer SIDs are checked to enforce
		 * consistency among the peer SIDs.
		 */
		ad_net_init_from_sk(&ad, &net, asoc->base.sk);
		err = selinux_chain_has_object_perm_with_policycap(
			creator,
			sksec->peer_object,
			asocsec->peer_object,
			SECCLASS_SCTP_SOCKET,
			SCTP_SOCKET__ASSOCIATION,
			POLICYDB_CAP_EXTSOCKCLASS,
			&ad);
		if (err)
			return err;
	}
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
	struct sctp_security_struct *asocsec = selinux_sctp(asoc);
	int err;

	err = selinux_sctp_process_new_assoc(asoc, skb);
	if (err)
		return err;

	/* Compute the MLS component for the connection and store
	 * the information in asoc. This will be used by SCTP TCP type
	 * sockets and peeled off connections as they cause a new
	 * socket to be generated. selinux_sctp_sk_clone() will then
	 * plug this into the new socket.
	 */
	err = selinux_connection_labels(
		asocsec->creator_cred,
		asocsec->object,
		sksec->object,
		asocsec->peer_object);
	if (err)
		return err;

	/* Set any NetLabel labels including CIPSO/CALIPSO options. */
	return selinux_netlbl_sctp_assoc_request(asoc, skb);
}

/* Called when SCTP receives a COOKIE ACK chunk as the final
 * response to an association request (initited by us).
 */
static int selinux_sctp_assoc_established(struct sctp_association *asoc,
					  struct sk_buff *skb)
{
	struct sk_security_struct *sksec = selinux_sock(asoc->base.sk);
	struct sctp_security_struct *asocsec = selinux_sctp(asoc);
	int err;

	/* Inherit secid from the parent socket - this will be picked up
	 * by selinux_sctp_sk_clone() if the association gets peeled off
	 * into a new socket.
	 */
	err = selinux_sctp_process_new_assoc(asoc, skb);
	if (err)
		return err;
	return selinux_object_label_copy_for_state_chain(
		asocsec->object,
		sksec->object,
		cred_selinux_state(asocsec->creator_cred),
		SECCLASS_SCTP_SOCKET,
		GFP_ATOMIC);
}

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
}

/* Called whenever a new socket is created by accept(2) or sctp_peeloff(3). */
static void selinux_sctp_sk_clone(struct sctp_association *asoc, struct sock *sk,
				  struct sock *newsk)
{
	struct sctp_security_struct *asocsec = selinux_sctp(asoc);
	struct sk_security_struct *newsksec = selinux_sock(newsk);
	const struct cred *creator;
	int rc;

	if (selinux_sctp_security_init(asoc))
		return;
	creator = asocsec->creator_cred;
	rc = selinux_object_label_copy_for_state_chain(
		newsksec->object,
		asocsec->object,
		cred_selinux_state(creator),
		SECCLASS_SCTP_SOCKET,
		GFP_ATOMIC);
	if (rc)
		return;
	rc = selinux_object_label_copy_for_state_chain(
		newsksec->peer_object,
		asocsec->peer_object,
		cred_selinux_state(creator),
		SECCLASS_PEER,
		GFP_ATOMIC);
	if (rc)
		return;
	put_cred(newsksec->creator_cred);
	newsksec->creator_cred = get_cred(creator);
	selinux_netlbl_sctp_sk_clone(sk, newsk);
}

static int selinux_mptcp_add_subflow(struct sock *sk, struct sock *ssk)
{
	struct sk_security_struct *ssksec = selinux_sock(ssk);
	struct sk_security_struct *sksec = selinux_sock(sk);
	const struct cred *creator = sksec->creator_cred;
	int rc;

	if (!creator)
		return -ESTALE;
	rc = selinux_object_label_copy_for_state_chain(
		ssksec->object,
		sksec->object,
		cred_selinux_state(creator),
		SECCLASS_TCP_SOCKET,
		GFP_ATOMIC);
	if (rc)
		return rc;
	put_cred(ssksec->creator_cred);
	ssksec->creator_cred = get_cred(creator);

	/* replace the existing subflow label deleting the existing one
	 * and re-recreating a new label using the updated context
	 */
	selinux_netlbl_sk_security_free(ssksec);
	return selinux_netlbl_socket_post_create(ssk, ssk->sk_family);
}

struct request_sock_security_struct *selinux_request_sock(
	const struct request_sock *request)
{
	return request->security + selinux_blob_sizes.lbs_request_sock;
}

static int selinux_request_sock_security_init(
	struct request_sock *request,
	const struct sock *socket)
{
	struct request_sock_security_struct *security =
		selinux_request_sock(request);
	const struct sk_security_struct *socket_security =
		selinux_sock(socket);
	const struct cred *creator = socket_security->creator_cred;
	struct selinux_state *leaf;
	int rc;

	if (security->creator_cred)
		return 0;
	if (!creator)
		return -ESTALE;
	leaf = cred_selinux_state(creator);
	security->object = selinux_object_identity_alloc_initial(
		leaf,
		SECINITSID_UNLABELED,
		SECCLASS_TCP_SOCKET,
		SELINUX_LABEL_SOURCE_UNSPECIFIED,
		GFP_ATOMIC);
	if (IS_ERR(security->object)) {
		rc = PTR_ERR(security->object);
		security->object = NULL;
		return rc;
	}
	security->peer_object = selinux_object_identity_alloc_initial(
		leaf,
		SECINITSID_UNLABELED,
		SECCLASS_PEER,
		SELINUX_LABEL_SOURCE_UNSPECIFIED,
		GFP_ATOMIC);
	if (IS_ERR(security->peer_object)) {
		rc = PTR_ERR(security->peer_object);
		security->peer_object = NULL;
		selinux_object_clear(&security->object);
		return rc;
	}
	rc = selinux_object_label_copy_for_state_chain(
		security->object,
		socket_security->object,
		leaf,
		SECCLASS_TCP_SOCKET,
		GFP_ATOMIC);
	if (rc) {
		selinux_object_clear(&security->peer_object);
		selinux_object_clear(&security->object);
		return rc;
	}
	security->creator_cred = get_cred(creator);
	return 0;
}

static int selinux_request_sock_clone_security(
	const struct request_sock *old,
	struct request_sock *new)
{
	const struct request_sock_security_struct *old_security =
		selinux_request_sock(old);
	struct request_sock_security_struct *new_security =
		selinux_request_sock(new);
	const struct cred *creator = old_security->creator_cred;
	struct selinux_state *leaf;
	int rc;

	if (!creator)
		return 0;
	leaf = cred_selinux_state(creator);
	new_security->object = selinux_object_identity_clone_for_state(
		old_security->object, leaf, GFP_ATOMIC);
	if (IS_ERR(new_security->object)) {
		rc = PTR_ERR(new_security->object);
		new_security->object = NULL;
		return rc;
	}
	new_security->peer_object = selinux_object_identity_clone_for_state(
		old_security->peer_object, leaf, GFP_ATOMIC);
	if (IS_ERR(new_security->peer_object)) {
		rc = PTR_ERR(new_security->peer_object);
		new_security->peer_object = NULL;
		selinux_object_clear(&new_security->object);
		return rc;
	}
	new_security->creator_cred = get_cred(creator);
	return 0;
}

static void selinux_request_sock_free_security(
	struct request_sock *request)
{
	struct request_sock_security_struct *security =
		selinux_request_sock(request);

	selinux_object_clear(&security->peer_object);
	selinux_object_clear(&security->object);
	put_cred(security->creator_cred);
	security->creator_cred = NULL;
}

static int selinux_inet_conn_request(const struct sock *sk, struct sk_buff *skb,
				     struct request_sock *req)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct request_sock_security_struct *reqsec =
		selinux_request_sock(req);
	struct selinux_object_identity *packet_peer = NULL;
	const struct cred *creator = sksec->creator_cred;
	int err;
	u16 family = req->rsk_ops->family;

	err = selinux_request_sock_security_init(req, sk);
	if (err)
		return err;
	err = selinux_skb_peer_object(creator, skb, family, &packet_peer);
	if (err)
		return err;
	err = selinux_object_label_copy_for_state_chain(
		reqsec->peer_object,
		packet_peer,
		cred_selinux_state(creator),
		SECCLASS_PEER,
		GFP_ATOMIC);
	selinux_object_identity_put(packet_peer);
	if (err)
		return err;
	err = selinux_connection_labels(
		creator,
		reqsec->object,
		sksec->object,
		reqsec->peer_object);
	if (err)
		return err;

	return selinux_netlbl_inet_conn_request(req, family);
}

static void selinux_inet_csk_clone(struct sock *newsk,
				   const struct request_sock *req)
{
	struct sk_security_struct *newsksec = selinux_sock(newsk);
	const struct request_sock_security_struct *reqsec =
		selinux_request_sock(req);
	const struct cred *creator = reqsec->creator_cred;

	if (!creator)
		return;
	if (selinux_object_label_copy_for_state_chain(
	    newsksec->object,
	    reqsec->object,
	    cred_selinux_state(creator),
	    SECCLASS_TCP_SOCKET,
	    GFP_ATOMIC))
		return;
	if (selinux_object_label_copy_for_state_chain(
	    newsksec->peer_object,
	    reqsec->peer_object,
	    cred_selinux_state(creator),
	    SECCLASS_PEER,
	    GFP_ATOMIC))
		return;
	put_cred(newsksec->creator_cred);
	newsksec->creator_cred = get_cred(creator);
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
	struct selinux_object_identity *packet_peer = NULL;
	const struct cred *creator = sksec->creator_cred;

	/* handle mapped IPv4 packets arriving via IPv6 sockets */
	if (family == PF_INET6 && skb->protocol == htons(ETH_P_IP))
		family = PF_INET;

	if (!creator ||
	    selinux_skb_peer_object(creator, skb, family, &packet_peer))
		return;
	selinux_object_label_copy_for_state_chain(
		sksec->peer_object,
		packet_peer,
		cred_selinux_state(creator),
		SECCLASS_PEER,
		GFP_ATOMIC);
	selinux_object_identity_put(packet_peer);
}

static int selinux_secmark_relabel_packet(u32 sid)
{
	return selinux_chain_has_initial_perm(
		current_cred(),
		sid,
		SECCLASS_PACKET,
		PACKET__RELABELTO,
		NULL);
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
	const struct request_sock_security_struct *security =
		selinux_request_sock(req);
	struct selinux_object_label_value root_label;

	selinux_object_label_get_or_unlabeled(
		init_selinux_state,
		security->object,
		SECCLASS_TCP_SOCKET,
		&root_label);
	flic->flowic_secid = root_label.sid;
}

static int selinux_tun_dev_alloc_security(void *security)
{
	struct tun_security_struct *tunsec = selinux_tun_dev(security);

	return selinux_object_init_from_cred(
		&tunsec->object,
		current_cred(),
		SECCLASS_TUN_SOCKET,
		SELINUX_LABEL_SOURCE_TASK,
		GFP_KERNEL_ACCOUNT);
}

static void selinux_tun_dev_free_security(void *security)
{
	struct tun_security_struct *tunsec = selinux_tun_dev(security);

	selinux_object_clear(&tunsec->object);
}

static int selinux_tun_dev_create(void)
{
	/* we aren't taking into account the "sockcreate" SID since the socket
	 * that is being created here is not a socket in the traditional sense,
	 * instead it is a private sock, accessible only to the kernel, and
	 * representing a wide range of network traffic spanning multiple
	 * connections unlike traditional sockets - check the TUN driver to
	 * get a better understanding of why this socket is special */

	return selinux_chain_has_self_perm(
		current_cred(),
		SECCLASS_TUN_SOCKET,
		TUN_SOCKET__CREATE,
		NULL);
}

static int selinux_tun_dev_attach_queue(void *security)
{
	struct tun_security_struct *tunsec = selinux_tun_dev(security);

	return selinux_chain_has_perm(
		current_cred(),
		tunsec->object,
		SECCLASS_TUN_SOCKET,
		TUN_SOCKET__ATTACH_QUEUE,
		NULL);
}

static int selinux_tun_dev_attach(struct sock *sk, void *security)
{
	struct tun_security_struct *tunsec = selinux_tun_dev(security);
	struct sk_security_struct *sksec = selinux_sock(sk);

	/* we don't currently perform any NetLabel based labeling here and it
	 * isn't clear that we would want to do so anyway; while we could apply
	 * labeling without the support of the TUN user the resulting labeled
	 * traffic from the other end of the connection would almost certainly
	 * cause confusion to the TUN user that had no idea network labeling
	 * protocols were being used */

	return selinux_object_label_copy_for_state_chain(
		sksec->object,
		tunsec->object,
		cred_selinux_state(current_cred()),
		SECCLASS_TUN_SOCKET,
		GFP_ATOMIC);
}

static int selinux_tun_dev_open(void *security)
{
	struct tun_security_struct *tunsec = selinux_tun_dev(security);
	struct selinux_object_identity *replacement;
	struct selinux_object_identity *old;
	int err;

	err = selinux_chain_has_perm(
		current_cred(),
		tunsec->object,
		SECCLASS_TUN_SOCKET,
		TUN_SOCKET__RELABELFROM,
		NULL);
	if (err)
		return err;
	err = selinux_chain_has_self_perm(
		current_cred(),
		SECCLASS_TUN_SOCKET,
		TUN_SOCKET__RELABELTO,
		NULL);
	if (err)
		return err;
	replacement = selinux_object_identity_alloc_from_cred(
		current_cred(),
		SECCLASS_TUN_SOCKET,
		SELINUX_LABEL_SOURCE_TASK,
		GFP_KERNEL_ACCOUNT);
	if (IS_ERR(replacement))
		return PTR_ERR(replacement);
	old = xchg(&tunsec->object, replacement);
	selinux_object_identity_put(old);

	return 0;
}

#ifdef CONFIG_NETFILTER

static unsigned int selinux_ip_forward(void *priv, struct sk_buff *skb,
				       const struct nf_hook_state *state)
{
	const struct skb_security_struct *skbsec;
	const struct cred *cred;
	struct selinux_object_identity *peer = NULL;
	struct selinux_object_identity *secmark = NULL;
	struct selinux_object_label_value root_label;
	int ifindex;
	u16 family;
	char *addrp;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	unsigned int verdict = NF_DROP;
	int err;

	family = state->pf;
	skbsec = selinux_skb_provenance(skb);
	if (skbsec) {
		cred = get_cred(skbsec->creator_cred);
		peer = selinux_object_identity_get(skbsec->object);
		if (!peer)
			goto out;
	} else {
		cred = get_task_cred(&init_task);
		err = selinux_skb_peer_object(cred, skb, family, &peer);
		if (err)
			goto out;
		err = selinux_skb_provenance_set(skb, cred, peer);
		if (err)
			goto out;
	}

	ifindex = state->in->ifindex;
	ad_net_init_from_iif(&ad, &net, ifindex, family);
	if (selinux_parse_skb(skb, &ad, &addrp, 1, NULL) != 0)
		goto out;

	if (selinux_peerlbl_enabled(cred)) {
		err = selinux_inet_sys_rcv_skb(
			cred,
			state->net,
			ifindex,
			addrp,
			family,
			peer,
			&ad);
		if (err) {
			selinux_netlbl_err(skb, family, err, 1);
			goto out;
		}
	}

	if (selinux_secmark_enabled(cred)) {
		err = selinux_root_sid_object(
			cred, skb->secmark, SECCLASS_PACKET, &secmark);
		if (err)
			goto out;
		err = selinux_chain_has_object_perm(
			cred,
			peer,
			secmark,
			SECCLASS_PACKET,
			PACKET__FORWARD_IN,
			&ad);
		if (err)
			goto out;
	}

	if (netlbl_enabled()) {
		/* we do this in the FORWARD path and not the POST_ROUTING
		 * path because we want to make sure we apply the necessary
		 * labeling before IPsec is applied so we can leverage AH
		 * protection */
		selinux_object_label_get_or_unlabeled(
			init_selinux_state,
			peer,
			SECCLASS_PEER,
			&root_label);
		if (selinux_netlbl_skbuff_setsid(
		    init_selinux_state,
		    skb,
		    family,
		    root_label.sid) != 0)
			goto out;
	}

	verdict = NF_ACCEPT;
out:
	selinux_object_identity_put(secmark);
	selinux_object_identity_put(peer);
	put_cred(cred);
	return verdict;
}

static unsigned int selinux_ip_output(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct sock *sk;
	struct sk_security_struct *sksec;
	struct selinux_object_label_value label;
	u32 sid;
	int err;

	/* we do this in the LOCAL_OUT path and not the POST_ROUTING path
	 * because we want to make sure we apply the necessary labeling
	 * before IPsec is applied so we can leverage AH protection */
	sk = skb_to_full_sk(skb);
	if (sk) {
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
		err = selinux_skb_provenance_set(
			skb, sksec->creator_cred, sksec->object);
		if (err)
			return NF_DROP;
		if (!netlbl_enabled())
			return NF_ACCEPT;
		selinux_object_label_get_or_unlabeled(
			init_selinux_state,
			sksec->object,
			SECCLASS_SOCKET,
			&label);
		sid = label.sid;
	} else {
		if (!netlbl_enabled())
			return NF_ACCEPT;
		sid = SECINITSID_KERNEL;
	}
	if (selinux_netlbl_skbuff_setsid(
	    init_selinux_state, skb, state->pf, sid) != 0)
		return NF_DROP;

	return NF_ACCEPT;
}


static unsigned int selinux_ip_postroute(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	const struct skb_security_struct *skbsec;
	struct selinux_object_identity *interface = NULL;
	struct selinux_object_identity *node = NULL;
	struct selinux_object_identity *packet_peer = NULL;
	struct selinux_object_identity *peer = NULL;
	struct selinux_object_identity *secmark = NULL;
	struct sk_security_struct *sksec = NULL;
	const struct cred *cred;
	bool release_cred = false;
	u16 family;
	u32 secmark_perm;
	int ifindex;
	struct sock *sk;
	struct common_audit_data ad;
	struct lsm_network_audit net;
	char *addrp;
	u8 proto = 0;
	unsigned int verdict = NF_DROP_ERR(-ECONNREFUSED);
	int err;

	sk = skb_to_full_sk(skb);
	if (sk) {
		sksec = selinux_sock(sk);
		cred = sksec->creator_cred;
		if (!cred)
			return NF_DROP_ERR(-ECONNREFUSED);
	} else {
		skbsec = selinux_skb_provenance(skb);
		if (skbsec) {
			cred = skbsec->creator_cred;
			peer = selinux_object_identity_get(skbsec->object);
			if (!peer)
				return NF_DROP_ERR(-ECONNREFUSED);
		} else {
			cred = get_task_cred(&init_task);
			release_cred = true;
		}
	}
	if (!selinux_secmark_enabled(cred) &&
	    !selinux_peerlbl_enabled(cred)) {
		verdict = NF_ACCEPT;
		goto out;
	}

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
	    !(sk && sk_listener(sk))) {
		verdict = NF_ACCEPT;
		goto out;
	}
#endif

	family = state->pf;
	if (sk == NULL) {
		/* Without an associated socket the packet is either coming
		 * from the kernel or it is being forwarded; check the packet
		 * to determine which and if the packet is being forwarded
		 * query the packet directly to determine the security label. */
		if (skb->skb_iif) {
			secmark_perm = PACKET__FORWARD_OUT;
			if (!peer) {
				err = selinux_skb_peer_object(
					cred, skb, family, &peer);
				if (err)
					goto out;
			}
		} else {
			secmark_perm = PACKET__SEND;
			if (!peer) {
				err = selinux_root_sid_object(
					cred,
					SECINITSID_KERNEL,
					SECCLASS_PACKET,
					&peer);
				if (err)
					goto out;
			}
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
		struct selinux_object_label_value root_label;

		err = selinux_skb_peer_object(
			cred, skb, family, &packet_peer);
		if (err)
			goto out;
		/* At this point, if the returned skb peerlbl is SECSID_NULL
		 * and the packet has been through at least one XFRM
		 * transformation then we must be dealing with the "final"
		 * form of labeled IPsec packet; since we've already applied
		 * all of our access controls on this packet we can safely
		 * pass the packet. */
		selinux_object_label_get_or_unlabeled(
			init_selinux_state,
			packet_peer,
			SECCLASS_PEER,
			&root_label);
		if (root_label.source == SELINUX_LABEL_SOURCE_UNSPECIFIED) {
			switch (family) {
			case PF_INET:
				if (IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) {
					verdict = NF_ACCEPT;
					goto out;
				}
				break;
			case PF_INET6:
				if (IP6CB(skb)->flags & IP6SKB_XFRM_TRANSFORMED) {
					verdict = NF_ACCEPT;
					goto out;
				}
				break;
			default:
				goto out;
			}
		}
		peer = selinux_object_identity_alloc(
			cred_selinux_state(cred), GFP_ATOMIC);
		if (IS_ERR(peer)) {
			peer = NULL;
			goto out;
		}
		err = selinux_connection_labels(
			cred,
			peer,
			sksec->object,
			packet_peer);
		if (err)
			goto out;
		secmark_perm = PACKET__SEND;
	} else {
		/* Locally generated packet, fetch the security label from the
		 * associated socket. */
		peer = selinux_object_identity_get(sksec->object);
		secmark_perm = PACKET__SEND;
	}
	err = selinux_skb_provenance_set(skb, cred, peer);
	if (err)
		goto out;

	ifindex = state->out->ifindex;
	ad_net_init_from_iif(&ad, &net, ifindex, family);
	if (selinux_parse_skb(skb, &ad, &addrp, 0, &proto))
		goto out;

	if (selinux_secmark_enabled(cred)) {
		err = selinux_root_sid_object(
			cred, skb->secmark, SECCLASS_PACKET, &secmark);
		if (err)
			goto out;
		err = selinux_chain_has_object_perm(
			cred,
			peer,
			secmark,
			SECCLASS_PACKET,
			secmark_perm,
			&ad);
		if (err)
			goto out;
	}

	if (selinux_peerlbl_enabled(cred)) {
		err = sel_netif_object(
			cred, state->net, ifindex, &interface);
		if (err)
			goto out;
		err = selinux_chain_has_object_perm_with_policycap(
			cred,
			peer,
			interface,
			SECCLASS_NETIF,
			NETIF__EGRESS,
			POLICYDB_CAP_NETPEER,
			&ad);
		if (err)
			goto out;
		err = sel_netnode_object(cred, addrp, family, &node);
		if (err)
			goto out;
		err = selinux_chain_has_object_perm_with_policycap(
			cred,
			peer,
			node,
			SECCLASS_NODE,
			NODE__SENDTO,
			POLICYDB_CAP_NETPEER,
			&ad);
		if (err)
			goto out;
	}

	if (sksec && selinux_xfrm_postroute_last(sksec, skb, &ad, proto))
		goto out;
	verdict = NF_ACCEPT;
out:
	selinux_object_identity_put(node);
	selinux_object_identity_put(interface);
	selinux_object_identity_put(secmark);
	selinux_object_identity_put(peer);
	selinux_object_identity_put(packet_peer);
	if (release_cred)
		put_cred(cred);
	return verdict;
}
#endif	/* CONFIG_NETFILTER */

struct selinux_netlink_permission_request {
	struct sock *sk;
	struct sk_security_struct *security;
	u16 nlmsg_type;
};

static int selinux_resolve_netlink_permission(
	struct selinux_state *state,
	const struct cred *level_cred,
	void *data,
	struct selinux_chain_permission *permission)
{
	const struct selinux_netlink_permission_request *request = data;
	struct selinux_object_label_value socket_label;
	u16 fallback_class = socket_type_to_security_class(
		state,
		request->sk->sk_family,
		request->sk->sk_type,
		request->sk->sk_protocol);
	u32 requested;
	int rc;

	selinux_object_label_get_or_unlabeled(
		state,
		request->security->object,
		fallback_class,
		&socket_label);
	permission->tsid = socket_label.sid;
	permission->tclass = socket_label.sclass ?
		socket_label.sclass : fallback_class;
	permission->decided = false;
	permission->requested = 0;

	if (socket_label.source == SELINUX_LABEL_SOURCE_POLICY_BYPASS ||
	    sock_skip_has_perm(state, socket_label.sid))
		return 0;

	rc = selinux_nlmsg_lookup(
		state,
		permission->tclass,
		request->nlmsg_type,
		&requested);
	if (rc == -ENOENT)
		return 0;
	if (rc == -EINVAL) {
		pr_warn_ratelimited(
			"SELinux: unrecognized netlink message: protocol=%hu nlmsg_type=%hu sclass=%s pid=%d comm=%s\n",
			request->sk->sk_protocol,
			request->nlmsg_type,
			secclass_map[permission->tclass - 1].name,
			task_pid_nr(current),
			current->comm);
		if (enforcing_enabled(state) &&
		    !security_get_allow_unknown(state))
			return rc;
		return 0;
	}
	if (rc)
		return rc;

	permission->requested = requested;
	permission->decided = true;
	if (selinux_policycap_netlink_xperm(state)) {
		permission->extended = true;
		permission->xperm_driver = request->nlmsg_type >> 8;
		permission->xperm_base = AVC_EXT_NLMSG;
		permission->xperm_value = request->nlmsg_type & 0xff;
	}
	return 0;
}

static int nlmsg_sock_has_perm(
	struct sock *sk,
	u16 nlmsg_type,
	struct common_audit_data *auditdata)
{
	struct sk_security_struct *sksec = selinux_sock(sk);
	struct selinux_netlink_permission_request request = {
		.sk = sk,
		.security = sksec,
		.nlmsg_type = nlmsg_type,
	};

	return selinux_chain_has_custom_perm(
		current_cred(),
		NULL,
		sksec->object,
		selinux_resolve_netlink_permission,
		&request,
		auditdata);
}

static int selinux_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	int rc = 0;
	unsigned int msg_len;
	unsigned int data_len = skb->len;
	unsigned char *data = skb->data;
	struct nlmsghdr *nlh;
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_NLMSGTYPE;

	while (data_len >= nlmsg_total_size(0)) {
		nlh = (struct nlmsghdr *)data;

		/* NOTE: the nlmsg_len field isn't reliably set by some netlink
		 *       users which means we can't reject skb's with bogus
		 *       length fields; our solution is to follow what
		 *       netlink_rcv_skb() does and simply skip processing at
		 *       messages with length fields that are clearly junk
		 */
		if (nlh->nlmsg_len < NLMSG_HDRLEN || nlh->nlmsg_len > data_len)
			return 0;

		ad.u.nlmsg_type = nlh->nlmsg_type;
		rc = nlmsg_sock_has_perm(sk, nlh->nlmsg_type, &ad);
		if (rc)
			return rc;

		/* move to the next message after applying netlink padding */
		msg_len = NLMSG_ALIGN(nlh->nlmsg_len);
		if (msg_len >= data_len)
			return 0;
		data_len -= msg_len;
		data += msg_len;
	}

	return rc;
}

static int ipc_init_security(struct ipc_security_struct *isec, u16 sclass)
{
	isec->sclass = sclass;
	return selinux_object_init_from_cred(
		&isec->object,
		current_cred(),
		sclass,
		SELINUX_LABEL_SOURCE_TASK,
		GFP_KERNEL_ACCOUNT);
}

static void ipc_free_security(struct kern_ipc_perm *ipc)
{
	struct ipc_security_struct *isec = selinux_ipc(ipc);

	selinux_object_clear(&isec->object);
}

static int ipc_has_perm(struct kern_ipc_perm *ipc_perms,
			u32 perms)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;

	isec = selinux_ipc(ipc_perms);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = ipc_perms->key;

	return selinux_chain_has_perm(
		current_cred(), isec->object, isec->sclass, perms, &ad);
}

static int selinux_msg_msg_alloc_security(struct msg_msg *msg)
{
	struct msg_security_struct *msec;

	msec = selinux_msg_msg(msg);
	return selinux_object_init_initial(
		&msec->object,
		current_selinux_state,
		SECINITSID_UNLABELED,
		SECCLASS_MSG,
		SELINUX_LABEL_SOURCE_UNSPECIFIED,
		GFP_KERNEL_ACCOUNT);
}

static void selinux_msg_msg_free_security(struct msg_msg *msg)
{
	struct msg_security_struct *msec = selinux_msg_msg(msg);

	selinux_object_clear(&msec->object);
}

/* message queue security operations */
static int selinux_msg_queue_alloc_security(struct kern_ipc_perm *msq)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;
	int rc;

	isec = selinux_ipc(msq);
	rc = ipc_init_security(isec, SECCLASS_MSGQ);
	if (rc)
		return rc;

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = msq->key;

	return selinux_chain_has_perm(
		current_cred(), isec->object,
		SECCLASS_MSGQ, MSGQ__CREATE, &ad);
}

static void selinux_msg_queue_free_security(struct kern_ipc_perm *msq)
{
	ipc_free_security(msq);
}

static int selinux_msg_queue_associate(struct kern_ipc_perm *msq, int msqflg)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;

	isec = selinux_ipc(msq);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = msq->key;

	return selinux_chain_has_perm(
		current_cred(), isec->object,
		SECCLASS_MSGQ, MSGQ__ASSOCIATE, &ad);
}

static int selinux_msg_queue_msgctl(struct kern_ipc_perm *msq, int cmd)
{
	u32 perms;

	switch (cmd) {
	case IPC_INFO:
	case MSG_INFO:
		/* No specific object, just general system-wide information. */
		return selinux_chain_has_initial_perm(
			current_cred(), SECINITSID_KERNEL,
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

static int selinux_msg_label_for_queue(
	const struct cred *cred,
	struct selinux_object_identity *message,
	struct selinux_object_identity *queue)
{
	struct selinux_object_label_update *updates;
	unsigned int retry;
	int rc = -ESTALE;

	updates = kcalloc(
		SELINUX_NS_MAX_DEPTH + 1,
		sizeof(*updates),
		GFP_KERNEL_ACCOUNT);
	if (!updates)
		return -ENOMEM;

	for (retry = 0; retry < 4; retry++) {
		const struct cred *level_cred = cred;
		struct selinux_state *state = cred_selinux_state(cred);
		struct selinux_object_generation_guard guards[2];
		u64 message_generation =
			selinux_object_identity_generation(message);
		u64 queue_generation =
			selinux_object_identity_generation(queue);
		u64 epoch = selinux_chain_epoch_read(state);
		u16 count = 0;
		u16 depth = 0;

		if (!message_generation || !queue_generation || !epoch)
			continue;
		rc = 0;
		while (state) {
			const struct cred_security_struct *security;
			struct selinux_object_label_value message_label;
			struct selinux_object_label_value queue_label;

			if (!level_cred ||
			    depth++ >= SELINUX_NS_MAX_DEPTH + 1) {
				rc = -ESTALE;
				break;
			}
			security = selinux_cred(level_cred);
			if (security->state != state) {
				rc = -ESTALE;
				break;
			}
			selinux_object_label_get_or_unlabeled(
				state, message, SECCLASS_MSG, &message_label);
			if (message_label.source ==
			    SELINUX_LABEL_SOURCE_UNSPECIFIED) {
				selinux_object_label_get_or_unlabeled(
					state, queue, SECCLASS_MSGQ, &queue_label);
				rc = security_transition_sid(
					state,
					security->sid,
					queue_label.sid,
					SECCLASS_MSG,
					NULL,
					&message_label.sid);
				if (rc)
					break;
				message_label.sclass = SECCLASS_MSG;
				message_label.source =
					SELINUX_LABEL_SOURCE_TRANSITION;
				updates[count++] =
					(struct selinux_object_label_update) {
						.state = state,
						.object = message,
						.value = message_label,
						.expected_generation =
							message_generation,
					};
			}
			level_cred = security->parent_cred;
			state = state->parent;
		}
		if (rc || state || level_cred) {
			if (!rc)
				rc = -ESTALE;
			if (rc != -ESTALE)
				break;
			continue;
		}
		if (!count) {
			rc = 0;
			break;
		}
		guards[0] = (struct selinux_object_generation_guard) {
			.object = message,
			.generation = message_generation,
		};
		guards[1] = (struct selinux_object_generation_guard) {
			.object = queue,
			.generation = queue_generation,
		};
		if (epoch != selinux_chain_epoch_read(
		    cred_selinux_state(cred))) {
			rc = -ESTALE;
			continue;
		}
		rc = selinux_object_labels_update_transaction_guarded(
			updates,
			count,
			guards,
			ARRAY_SIZE(guards),
			GFP_KERNEL_ACCOUNT);
		if (rc != -ESTALE)
			break;
	}
	kfree(updates);
	return rc;
}

static int selinux_msg_queue_msgsnd(struct kern_ipc_perm *msq, struct msg_msg *msg, int msqflg)
{
	struct ipc_security_struct *isec;
	struct msg_security_struct *msec;
	struct common_audit_data ad;
	int rc;

	isec = selinux_ipc(msq);
	msec = selinux_msg_msg(msg);

	rc = selinux_msg_label_for_queue(
		current_cred(), msec->object, isec->object);
	if (rc)
		return rc;

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = msq->key;

	/* Can this process write to the queue? */
	rc = selinux_chain_has_perm(
		current_cred(), isec->object,
		SECCLASS_MSGQ, MSGQ__WRITE, &ad);
	if (!rc)
		/* Can this process send the message */
		rc = selinux_chain_has_perm(
			current_cred(), msec->object,
			SECCLASS_MSG, MSG__SEND, &ad);
	if (!rc)
		/* Can the message be put in the queue? */
		rc = selinux_chain_has_object_perm(
			current_cred(), msec->object, isec->object,
			SECCLASS_MSGQ, MSGQ__ENQUEUE, &ad);

	return rc;
}

static int selinux_msg_queue_msgrcv(struct kern_ipc_perm *msq, struct msg_msg *msg,
				    struct task_struct *target,
				    long type, int mode)
{
	struct ipc_security_struct *isec;
	struct msg_security_struct *msec;
	struct common_audit_data ad;
	const struct cred *target_cred;
	int rc;

	isec = selinux_ipc(msq);
	msec = selinux_msg_msg(msg);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = msq->key;

	target_cred = get_task_cred(target);
	rc = selinux_chain_has_perm(
		target_cred, isec->object,
		SECCLASS_MSGQ, MSGQ__READ, &ad);
	if (!rc)
		rc = selinux_chain_has_perm(
			target_cred, msec->object,
			SECCLASS_MSG, MSG__RECEIVE, &ad);
	put_cred(target_cred);
	return rc;
}

/* Shared Memory security operations */
static int selinux_shm_alloc_security(struct kern_ipc_perm *shp)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;
	int rc;

	isec = selinux_ipc(shp);
	rc = ipc_init_security(isec, SECCLASS_SHM);
	if (rc)
		return rc;

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = shp->key;

	return selinux_chain_has_perm(
		current_cred(), isec->object,
		SECCLASS_SHM, SHM__CREATE, &ad);
}

static void selinux_shm_free_security(struct kern_ipc_perm *shp)
{
	ipc_free_security(shp);
}

static int selinux_shm_associate(struct kern_ipc_perm *shp, int shmflg)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;

	isec = selinux_ipc(shp);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = shp->key;

	return selinux_chain_has_perm(
		current_cred(), isec->object,
		SECCLASS_SHM, SHM__ASSOCIATE, &ad);
}

/* Note, at this point, shp is locked down */
static int selinux_shm_shmctl(struct kern_ipc_perm *shp, int cmd)
{
	u32 perms;

	switch (cmd) {
	case IPC_INFO:
	case SHM_INFO:
		/* No specific object, just general system-wide information. */
		return selinux_chain_has_initial_perm(
			current_cred(), SECINITSID_KERNEL,
			SECCLASS_SYSTEM, SYSTEM__IPC_INFO, NULL);
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
static int selinux_sem_alloc_security(struct kern_ipc_perm *sma)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;
	int rc;

	isec = selinux_ipc(sma);
	rc = ipc_init_security(isec, SECCLASS_SEM);
	if (rc)
		return rc;

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = sma->key;

	return selinux_chain_has_perm(
		current_cred(), isec->object,
		SECCLASS_SEM, SEM__CREATE, &ad);
}

static void selinux_sem_free_security(struct kern_ipc_perm *sma)
{
	ipc_free_security(sma);
}

static int selinux_sem_associate(struct kern_ipc_perm *sma, int semflg)
{
	struct ipc_security_struct *isec;
	struct common_audit_data ad;

	isec = selinux_ipc(sma);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = sma->key;

	return selinux_chain_has_perm(
		current_cred(), isec->object,
		SECCLASS_SEM, SEM__ASSOCIATE, &ad);
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
		return selinux_chain_has_initial_perm(
			current_cred(), SECINITSID_KERNEL,
			SECCLASS_SYSTEM, SYSTEM__IPC_INFO, NULL);
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
	struct selinux_object_label_value label;

	if (selinux_object_label_get(
	    current_selinux_state, isec->object, &label))
		prop->selinux.secid = SECINITSID_UNLABELED;
	else
		prop->selinux.secid = label.sid;
}

static void selinux_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	struct kernfs_node *kn;

	if (!inode)
		return;

	kn = kernfs_node_from_dentry(dentry);
	if (kn && kn->security) {
		struct kernfs_security_struct *ksec = selinux_kernfs(kn);
		struct inode_security_struct *isec = selinux_inode(inode);
		struct selinux_object_identity *old;
		struct selinux_object_identity *replacement;

		if (ksec->object && isec) {
			replacement = selinux_object_identity_get(ksec->object);
			spin_lock(&isec->lock);
			old = isec->object;
			isec->object = replacement;
			spin_unlock(&isec->lock);
			selinux_object_identity_put(old);
		}
	}
	inode_doinit_with_dentry(current_cred(), inode, dentry);
}

static int selinux_lsm_getattr(unsigned int attr, struct task_struct *p,
			       char **value)
{
	const struct cred *target_cred;
	const struct cred *level_cred;
	const struct cred_security_struct *crsec = NULL;
	struct selinux_state *state = current_selinux_state;
	int error;
	u32 sid;
	u32 len;

	target_cred = get_task_cred(p);
	if (p != current) {
		error = selinux_chain_has_cred_perm(
			current_cred(),
			target_cred,
			SECCLASS_PROCESS,
			PROCESS__GETATTR,
			NULL);
		if (error)
			goto out_put;
	}

	level_cred = selinux_chain_cred_for_state(target_cred, state);
	if (level_cred)
		crsec = selinux_cred(level_cred);

	switch (attr) {
	case LSM_ATTR_CURRENT:
		sid = crsec ? crsec->sid : SECINITSID_UNLABELED;
		break;
	case LSM_ATTR_PREV:
		sid = crsec ? crsec->osid : SECINITSID_UNLABELED;
		break;
	case LSM_ATTR_EXEC:
		sid = crsec ? crsec->exec_sid : SECSID_NULL;
		break;
	case LSM_ATTR_FSCREATE:
		sid = crsec ? crsec->create_sid : SECSID_NULL;
		break;
	case LSM_ATTR_KEYCREATE:
		sid = crsec ? crsec->keycreate_sid : SECSID_NULL;
		break;
	case LSM_ATTR_SOCKCREATE:
		sid = crsec ? crsec->sockcreate_sid : SECSID_NULL;
		break;
	default:
		error = -EOPNOTSUPP;
		goto out_put;
	}
	put_cred(target_cred);

	if (sid == SECSID_NULL) {
		*value = NULL;
		return 0;
	}

	error = security_sid_to_context(state, sid, value, &len);
	if (error)
		return error;
	return len;

out_put:
	put_cred(target_cred);
	return error;
}

static int selinux_lsm_setattr(u64 attr, void *value, size_t size)
{
	struct cred_security_struct *crsec;
	struct selinux_state *state = current_selinux_state;
	struct cred *new;
	u32 mysid = selinux_cred(current_cred())->sid;
	u32 sid = SECSID_NULL;
	u32 ptsid;
	int error;
	char *str = value;

	/*
	 * Basic control over ability to set these attributes at all.
	 */
	switch (attr) {
	case LSM_ATTR_EXEC:
		error = selinux_chain_has_self_perm(
			current_cred(), SECCLASS_PROCESS,
			PROCESS__SETEXEC, NULL);
		break;
	case LSM_ATTR_FSCREATE:
		error = selinux_chain_has_self_perm(
			current_cred(), SECCLASS_PROCESS,
			PROCESS__SETFSCREATE, NULL);
		break;
	case LSM_ATTR_KEYCREATE:
		error = selinux_chain_has_self_perm(
			current_cred(), SECCLASS_PROCESS,
			PROCESS__SETKEYCREATE, NULL);
		break;
	case LSM_ATTR_SOCKCREATE:
		error = selinux_chain_has_self_perm(
			current_cred(), SECCLASS_PROCESS,
			PROCESS__SETSOCKCREATE, NULL);
		break;
	case LSM_ATTR_CURRENT:
		error = selinux_chain_has_self_perm(
			current_cred(), SECCLASS_PROCESS,
			PROCESS__SETCURRENT, NULL);
		break;
	default:
		error = -EOPNOTSUPP;
		break;
	}
	if (error)
		return error;

	/* Obtain a SID for the context, if one was specified. */
	if (size && str[0] && str[0] != '\n') {
		if (str[size-1] == '\n') {
			str[size-1] = 0;
			size--;
		}
		error = security_context_to_sid(
			state, value, size, &sid, GFP_KERNEL);
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
				audit_log_end(ab);

				return error;
			}
			error = security_context_to_sid_force(
				state, value, size, &sid);
		}
		if (error)
			return error;
	}

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	/* Permission checking based on the specified context is
	   performed during the actual operation (execve,
	   open/mkdir/...), when we know the full context of the
	   operation.  See selinux_bprm_creds_for_exec for the execve
	   checks and may_create for the file creation checks. The
	   operation will then fail if the context is not permitted. */
	crsec = selinux_cred(new);
	if (attr == LSM_ATTR_EXEC) {
		crsec->exec_sid = sid;
	} else if (attr == LSM_ATTR_FSCREATE) {
		crsec->create_sid = sid;
	} else if (attr == LSM_ATTR_KEYCREATE) {
		if (sid) {
			error = avc_has_perm_disabled(
				state, mysid, sid,
				SECCLASS_KEY, KEY__CREATE, NULL);
			if (error)
				goto abort_change;
		}
		crsec->keycreate_sid = sid;
	} else if (attr == LSM_ATTR_SOCKCREATE) {
		crsec->sockcreate_sid = sid;
	} else if (attr == LSM_ATTR_CURRENT) {
		error = -EINVAL;
		if (sid == 0)
			goto abort_change;

		if (!current_is_single_threaded()) {
			error = security_bounded_transition(
				state, crsec->sid, sid);
			if (error)
				goto abort_change;
		}

		/* Check permissions for the transition. */
		error = avc_has_perm_disabled(
			state, crsec->sid, sid, SECCLASS_PROCESS,
			PROCESS__DYNTRANSITION, NULL);
		if (error)
			goto abort_change;

		/* Check for ptracing, and update the task SID if ok.
		   Otherwise, leave SID unchanged and fail. */
		ptsid = ptrace_parent_sid(state);
		if (ptsid != 0) {
			error = avc_has_perm_disabled(
				state, ptsid, sid, SECCLASS_PROCESS,
				PROCESS__PTRACE, NULL);
			if (error)
				goto abort_change;
		}

		crsec->sid = sid;
	} else {
		error = -EINVAL;
		goto abort_change;
	}

	commit_creds(new);
	return size;

abort_change:
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
	struct selinux_state *state = current_selinux_state;
	u32 seclen;
	int ret;

	if (cp) {
		cp->id = LSM_ID_SELINUX;
		ret = security_sid_to_context(
			state, secid, &cp->context, &cp->len);
		if (ret < 0)
			return ret;
		return cp->len;
	}
	ret = security_sid_to_context(state, secid, NULL, &seclen);
	if (ret < 0)
		return ret;
	return seclen;
}

static int selinux_lsmprop_to_secctx(struct lsm_prop *prop,
				     struct lsm_context *cp)
{
	return selinux_secid_to_secctx(prop->selinux.secid, cp);
}

static int selinux_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	return security_context_to_sid(
		current_selinux_state,
		secdata,
		seclen,
		secid,
		GFP_KERNEL);
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
	struct superblock_security_struct *sbsec =
		selinux_superblock(inode->i_sb);
	struct inode_security_struct *isec = selinux_inode(inode);
	struct selinux_object_label_value value = {
		.sid = SECINITSID_UNLABELED,
		.sclass = inode_mode_to_security_class(inode->i_mode),
		.source = SELINUX_LABEL_SOURCE_UNSPECIFIED,
	};
	struct selinux_state *owner =
		selinux_persistent_label_owner_get(sbsec);

	if (!owner)
		return;
	if (selinux_object_label_set(
	    owner, isec->object, &value, GFP_KERNEL_ACCOUNT))
		pr_warn_ratelimited(
			"SELinux: unable to invalidate inode label for dev=%s ino=%llu\n",
			inode->i_sb->s_id,
			inode->i_ino);
	put_selinux_state(owner);
}

/*
 *	called with inode->i_mutex locked
 */
static int selinux_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	int rc = selinux_inode_setsecurity(inode, XATTR_SELINUX_SUFFIX,
					   ctx, ctxlen, 0);
	/* Do not return error when suppressing label (SBLABEL_MNT not set). */
	return rc == -EOPNOTSUPP ? 0 : rc;
}

/*
 *	called with inode->i_mutex locked
 */
static int selinux_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return __vfs_setxattr_locked(&nop_mnt_idmap, dentry, XATTR_NAME_SELINUX,
				     ctx, ctxlen, 0, NULL);
}

static int selinux_inode_getsecctx(struct inode *inode, struct lsm_context *cp)
{
	int len;
	len = selinux_inode_getsecurity(&nop_mnt_idmap, inode,
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
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	const struct cred *level_cred = cred;
	struct selinux_state *state = cred_selinux_state(cred);
	u16 count = 0;
	int rc;

	ksec->object = selinux_object_identity_alloc(state, GFP_KERNEL_ACCOUNT);
	if (IS_ERR(ksec->object)) {
		rc = PTR_ERR(ksec->object);
		ksec->object = NULL;
		return rc;
	}
	while (state) {
		const struct cred_security_struct *security;

		if (!level_cred || count >= ARRAY_SIZE(states)) {
			rc = -ESTALE;
			goto err_object;
		}
		security = selinux_cred(level_cred);
		if (security->state != state) {
			rc = -ESTALE;
			goto err_object;
		}
		states[count] = state;
		values[count] = (struct selinux_object_label_value) {
			.sid = security->keycreate_sid ?: security->sid,
			.sclass = SECCLASS_KEY,
			.source = SELINUX_LABEL_SOURCE_TASK,
		};
		count++;
		level_cred = security->parent_cred;
		state = state->parent;
	}
	if (level_cred) {
		rc = -ESTALE;
		goto err_object;
	}
	rc = selinux_object_labels_set_chain(
		ksec->object, states, values, count, GFP_KERNEL_ACCOUNT);
	if (!rc)
		return 0;
err_object:
	selinux_object_clear(&ksec->object);
	return rc;
}

static void selinux_key_free(struct key *key)
{
	struct key_security_struct *ksec = selinux_key(key);

	selinux_object_clear(&ksec->object);
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

	return selinux_chain_has_perm(
		cred, ksec->object, SECCLASS_KEY, perm, NULL);
}

static int selinux_key_getsecurity(struct key *key, char **_buffer)
{
	struct key_security_struct *ksec = selinux_key(key);
	char *context = NULL;
	unsigned len;
	struct selinux_object_label_value label;
	int rc;

	rc = selinux_object_label_get(
		current_selinux_state, ksec->object, &label);
	if (rc)
		return rc;
	rc = security_sid_to_context(
		current_selinux_state, label.sid, &context, &len);
	if (!rc)
		rc = len;
	*_buffer = context;
	return rc;
}

#ifdef CONFIG_KEY_NOTIFICATIONS
static int selinux_watch_key(struct key *key)
{
	struct key_security_struct *ksec = selinux_key(key);

	return selinux_chain_has_perm(
		current_cred(), ksec->object, SECCLASS_KEY, KEY__VIEW, NULL);
}
#endif
#endif

#ifdef CONFIG_SECURITY_INFINIBAND
static int selinux_ib_pkey_access(void *ib_sec, u64 subnet_prefix, u16 pkey_val)
{
	struct ib_security_struct *security = selinux_ib(ib_sec);
	struct selinux_object_identity *pkey = NULL;
	struct common_audit_data ad;
	struct lsm_ibpkey_audit ibpkey;
	int rc;

	if (!security->creator_cred || !security->object)
		return -ESTALE;
	rc = sel_ib_pkey_object(
		security->creator_cred,
		subnet_prefix,
		pkey_val,
		&pkey);
	if (rc)
		return rc;

	ad.type = LSM_AUDIT_DATA_IBPKEY;
	ibpkey.subnet_prefix = subnet_prefix;
	ibpkey.pkey = pkey_val;
	ad.u.ibpkey = &ibpkey;
	rc = selinux_chain_has_object_perm(
		security->creator_cred,
		security->object,
		pkey,
		SECCLASS_INFINIBAND_PKEY,
		INFINIBAND_PKEY__ACCESS,
		&ad);
	selinux_object_identity_put(pkey);
	return rc;
}

struct selinux_ib_endport_request {
	const struct selinux_object_identity *source;
	const char *device_name;
	u8 port_number;
};

static int selinux_ib_endport_permission_resolver(
	struct selinux_state *state,
	const struct cred *level_cred,
	void *data,
	struct selinux_chain_permission *permission)
{
	struct selinux_ib_endport_request *request = data;
	struct selinux_object_label_value source_label;
	int rc;

	selinux_object_label_get_or_unlabeled(
		state,
		request->source,
		SECCLASS_INFINIBAND_ENDPORT,
		&source_label);
	rc = security_ib_endport_sid(
		state,
		request->device_name,
		request->port_number,
		&permission->tsid);
	if (rc)
		return rc;
	permission->ssid = source_label.sid;
	permission->tclass = SECCLASS_INFINIBAND_ENDPORT;
	permission->requested = INFINIBAND_ENDPORT__MANAGE_SUBNET;
	permission->decided =
		source_label.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS;
	return 0;
}

static int selinux_ib_endport_manage_subnet(void *ib_sec, const char *dev_name,
					    u8 port_num)
{
	struct ib_security_struct *security = selinux_ib(ib_sec);
	struct selinux_ib_endport_request request;
	struct common_audit_data ad;
	struct lsm_ibendport_audit ibendport;

	if (!security->creator_cred || !security->object)
		return -ESTALE;

	ad.type = LSM_AUDIT_DATA_IBENDPORT;
	ibendport.dev_name = dev_name;
	ibendport.port = port_num;
	ad.u.ibendport = &ibendport;
	request = (struct selinux_ib_endport_request) {
		.source = security->object,
		.device_name = dev_name,
		.port_number = port_num,
	};
	return selinux_chain_has_custom_perm(
		security->creator_cred,
		security->object,
		NULL,
		selinux_ib_endport_permission_resolver,
		&request,
		&ad);
}

static int selinux_ib_alloc_security(void *ib_sec)
{
	struct ib_security_struct *sec = selinux_ib(ib_sec);
	int rc;

	rc = selinux_object_init_from_cred(
		&sec->object,
		current_cred(),
		SECCLASS_INFINIBAND_ENDPORT,
		SELINUX_LABEL_SOURCE_TASK,
		GFP_KERNEL_ACCOUNT);
	if (rc)
		return rc;
	sec->creator_cred = get_current_cred();
	return 0;
}

static void selinux_ib_free_security(void *ib_sec)
{
	struct ib_security_struct *security = selinux_ib(ib_sec);

	selinux_object_clear(&security->object);
	put_cred(security->creator_cred);
	security->creator_cred = NULL;
}
#endif

#ifdef CONFIG_BPF_SYSCALL
static int selinux_bpf(int cmd, union bpf_attr *attr,
		       unsigned int size, bool kernel)
{
	u32 permission;

	switch (cmd) {
	case BPF_MAP_CREATE:
		permission = BPF__MAP_CREATE;
		break;
	case BPF_PROG_LOAD:
		permission = BPF__PROG_LOAD;
		break;
	default:
		return 0;
	}
	return selinux_chain_has_self_perm_unless_policycap(
		current_cred(),
		POLICYDB_CAP_BPF_TOKEN_PERMS,
		SECCLASS_BPF,
		permission,
		NULL);
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

/* This function will check the file pass through unix socket or binder to see
 * if it is a bpf related object. And apply corresponding checks on the bpf
 * object based on the type. The bpf maps and programs, not like other files and
 * socket, are using a shared anonymous inode inside the kernel as their inode.
 * So checking that inode cannot identify if the process have privilege to
 * access the bpf object and that's why we have to add this additional check in
 * selinux_file_receive and selinux_binder_transfer_files.
 */
static int bpf_fd_pass(const struct cred *cred, const struct file *file)
{
	struct bpf_security_struct *bpfsec;
	struct bpf_prog *prog;
	struct bpf_map *map;

	if (file->f_op == &bpf_map_fops) {
		map = file->private_data;
		bpfsec = selinux_bpf_map_security(map);
		if (unlikely(!bpfsec->object))
			return -EUCLEAN;
		return selinux_chain_has_perm(
			cred,
			bpfsec->object,
			SECCLASS_BPF,
			bpf_map_fmode_to_av(file->f_mode),
			NULL);
	} else if (file->f_op == &bpf_prog_fops) {
		prog = file->private_data;
		bpfsec = selinux_bpf_prog_security(prog);
		if (unlikely(!bpfsec->object))
			return -EUCLEAN;
		return selinux_chain_has_perm(
			cred,
			bpfsec->object,
			SECCLASS_BPF,
			BPF__PROG_RUN,
			NULL);
	}
	return 0;
}

static int selinux_bpf_map(struct bpf_map *map, fmode_t fmode)
{
	struct bpf_security_struct *bpfsec;

	bpfsec = selinux_bpf_map_security(map);
	if (unlikely(!bpfsec->object))
		return -EUCLEAN;
	return selinux_chain_has_perm(
		current_cred(),
		bpfsec->object,
		SECCLASS_BPF,
		bpf_map_fmode_to_av(fmode),
		NULL);
}

static int selinux_bpf_prog(struct bpf_prog *prog)
{
	struct bpf_security_struct *bpfsec;

	bpfsec = selinux_bpf_prog_security(prog);
	if (unlikely(!bpfsec->object))
		return -EUCLEAN;
	return selinux_chain_has_perm(
		current_cred(),
		bpfsec->object,
		SECCLASS_BPF,
		BPF__PROG_RUN,
		NULL);
}

static struct selinux_object_identity *
selinux_bpffs_creator_object(const struct path *path)
{
	struct superblock_security_struct *sbsec;
	struct selinux_object_identity *object;

	if (!path || !path->dentry)
		return ERR_PTR(-EINVAL);
	sbsec = selinux_superblock(path->dentry->d_sb);
	object = selinux_object_identity_get(sbsec->creator_object);
	return object ?: ERR_PTR(-EUCLEAN);
}

static int selinux_bpf_map_create(struct bpf_map *map, union bpf_attr *attr,
				  struct bpf_token *token, bool kernel)
{
	struct bpf_security_struct *bpfsec;
	struct bpf_security_struct *tokensec;
	int rc;

	bpfsec = selinux_bpf_map_security(map);
	rc = selinux_object_init_from_cred(
		&bpfsec->object,
		current_cred(),
		SECCLASS_BPF,
		SELINUX_LABEL_SOURCE_TASK,
		GFP_KERNEL);
	if (rc)
		return rc;

	if (!token) {
		return selinux_chain_has_perm(
			current_cred(),
			bpfsec->object,
			SECCLASS_BPF,
			BPF__MAP_CREATE,
			NULL);
	}
	tokensec = selinux_bpf_token_security(token);
	if (unlikely(!tokensec->grantor_object))
		return -EUCLEAN;
	return selinux_chain_has_object_perm(
		current_cred(),
		tokensec->grantor_object,
		bpfsec->object,
		SECCLASS_BPF,
		BPF__MAP_CREATE,
		NULL);
}

static void selinux_bpf_map_free(struct bpf_map *map)
{
	struct bpf_security_struct *bpfsec =
		selinux_bpf_map_security(map);

	selinux_object_clear(&bpfsec->object);
	selinux_object_clear(&bpfsec->grantor_object);
}

static int selinux_bpf_prog_load(struct bpf_prog *prog, union bpf_attr *attr,
				 struct bpf_token *token, bool kernel)
{
	struct bpf_security_struct *bpfsec;
	struct bpf_security_struct *tokensec;
	int rc;

	bpfsec = selinux_bpf_prog_security(prog);
	rc = selinux_object_init_from_cred(
		&bpfsec->object,
		current_cred(),
		SECCLASS_BPF,
		SELINUX_LABEL_SOURCE_TASK,
		GFP_KERNEL);
	if (rc)
		return rc;

	if (!token) {
		return selinux_chain_has_perm(
			current_cred(),
			bpfsec->object,
			SECCLASS_BPF,
			BPF__PROG_LOAD,
			NULL);
	}
	tokensec = selinux_bpf_token_security(token);
	if (unlikely(!tokensec->grantor_object))
		return -EUCLEAN;
	return selinux_chain_has_object_perm(
		current_cred(),
		tokensec->grantor_object,
		bpfsec->object,
		SECCLASS_BPF,
		BPF__PROG_LOAD,
		NULL);
}

static void selinux_bpf_prog_free(struct bpf_prog *prog)
{
	struct bpf_security_struct *bpfsec =
		selinux_bpf_prog_security(prog);

	selinux_object_clear(&bpfsec->object);
	selinux_object_clear(&bpfsec->grantor_object);
}

#define bpf_token_cmd(T, C) \
	((T)->allowed_cmds & (1ULL << (C)))

static int selinux_bpf_token_create(struct bpf_token *token,
				    union bpf_attr *attr,
				    const struct path *path)
{
	struct bpf_security_struct *bpfsec;
	int err;

	bpfsec = selinux_bpf_token_security(token);
	err = selinux_object_init_from_cred(
		&bpfsec->object,
		current_cred(),
		SECCLASS_BPF,
		SELINUX_LABEL_SOURCE_TASK,
		GFP_KERNEL);
	if (err)
		return err;
	bpfsec->grantor_object = selinux_bpffs_creator_object(path);
	if (IS_ERR(bpfsec->grantor_object)) {
		err = PTR_ERR(bpfsec->grantor_object);
		bpfsec->grantor_object = NULL;
		return err;
	}
	bpfsec->perms = 0;
	/**
	 * 'token->allowed_cmds' is a bit mask of allowed commands
	 * Convert the BPF command enum to a bitmask representing its position
	 * in the allowed_cmds bitmap.
	 */
	if (bpf_token_cmd(token, BPF_MAP_CREATE)) {
		err = selinux_chain_has_object_perm(
			current_cred(),
			bpfsec->object,
			bpfsec->grantor_object,
			SECCLASS_BPF,
			BPF__MAP_CREATE_AS,
			NULL);
		if (err)
			return err;
		bpfsec->perms |= BPF__MAP_CREATE;
	}
	if (bpf_token_cmd(token, BPF_PROG_LOAD)) {
		err = selinux_chain_has_object_perm(
			current_cred(),
			bpfsec->object,
			bpfsec->grantor_object,
			SECCLASS_BPF,
			BPF__PROG_LOAD_AS,
			NULL);
		if (err)
			return err;
		bpfsec->perms |= BPF__PROG_LOAD;
	}

	return 0;
}

static void selinux_bpf_token_free(struct bpf_token *token)
{
	struct bpf_security_struct *bpfsec =
		selinux_bpf_token_security(token);

	selinux_object_clear(&bpfsec->object);
	selinux_object_clear(&bpfsec->grantor_object);
}

static int selinux_bpf_token_cmd(const struct bpf_token *token,
				 enum bpf_cmd cmd)
{
	struct bpf_security_struct *bpfsec;

	bpfsec = selinux_bpf_token_security((struct bpf_token *)token);
	switch (cmd) {
	case BPF_MAP_CREATE:
		if (!(bpfsec->perms & BPF__MAP_CREATE))
			return -EACCES;
		break;
	case BPF_PROG_LOAD:
		if (!(bpfsec->perms & BPF__PROG_LOAD))
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

	if (unlikely(!bpfsec->grantor_object))
		return -EUCLEAN;
	return selinux_chain_has_perm(
		current_cred(), bpfsec->grantor_object, sclass, av, NULL);
}
#endif

#ifdef CONFIG_PERF_EVENTS
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

	return selinux_chain_has_self_perm(
		current_cred(), SECCLASS_PERF_EVENT, requested, NULL);
}

static int selinux_perf_event_alloc(struct perf_event *event)
{
	struct perf_event_security_struct *perfsec;

	perfsec = selinux_perf_event(event->security);
	return selinux_object_init_from_cred(
		&perfsec->object,
		current_cred(),
		SECCLASS_PERF_EVENT,
		SELINUX_LABEL_SOURCE_TASK,
		GFP_KERNEL_ACCOUNT);
}

static void selinux_perf_event_free(struct perf_event *event)
{
	struct perf_event_security_struct *perfsec =
		selinux_perf_event(event->security);

	selinux_object_clear(&perfsec->object);
}

static int selinux_perf_event_read(struct perf_event *event)
{
	struct perf_event_security_struct *perfsec =
		selinux_perf_event(event->security);

	return selinux_chain_has_perm(
		current_cred(), perfsec->object,
		SECCLASS_PERF_EVENT, PERF_EVENT__READ, NULL);
}

static int selinux_perf_event_write(struct perf_event *event)
{
	struct perf_event_security_struct *perfsec =
		selinux_perf_event(event->security);

	return selinux_chain_has_perm(
		current_cred(), perfsec->object,
		SECCLASS_PERF_EVENT, PERF_EVENT__WRITE, NULL);
}
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
	return selinux_chain_has_cred_perm(
		current_cred(), new, SECCLASS_IO_URING,
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
	return selinux_chain_has_self_perm(
		current_cred(), SECCLASS_IO_URING, IO_URING__SQPOLL, NULL);
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
	struct inode_security_struct *isec = selinux_inode(inode);
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;

	return selinux_chain_has_perm(
		current_cred(), isec->object,
		SECCLASS_IO_URING, IO_URING__CMD, &ad);
}

/**
 * selinux_uring_allowed - check if io_uring_setup() can be called
 *
 * Check to see if the current task is allowed to call io_uring_setup().
 */
static int selinux_uring_allowed(void)
{
	return selinux_chain_has_self_perm(
		current_cred(), SECCLASS_IO_URING, IO_URING__ALLOWED, NULL);
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
	.lbs_inode = sizeof(struct inode_security_struct),
	.lbs_kernfs_node = sizeof(struct kernfs_security_struct),
	.lbs_ipc = sizeof(struct ipc_security_struct),
	.lbs_key = sizeof(struct key_security_struct),
	.lbs_msg_msg = sizeof(struct msg_security_struct),
#ifdef CONFIG_PERF_EVENTS
	.lbs_perf_event = sizeof(struct perf_event_security_struct),
#endif
	.lbs_sock = sizeof(struct sk_security_struct),
	.lbs_superblock = sizeof(struct superblock_security_struct),
	.lbs_xattr_count = SELINUX_INODE_INIT_XATTRS,
	.lbs_tun_dev = sizeof(struct tun_security_struct),
	.lbs_sctp_assoc = sizeof(struct sctp_security_struct),
	.lbs_request_sock = sizeof(struct request_sock_security_struct),
	.lbs_skb = sizeof(struct skb_security_struct),
	.lbs_ib = sizeof(struct ib_security_struct),
	.lbs_bpf_map = sizeof(struct bpf_security_struct),
	.lbs_bpf_prog = sizeof(struct bpf_security_struct),
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

	LSM_HOOK_INIT(sb_free_mnt_opts, selinux_free_mnt_opts),
	LSM_HOOK_INIT(sb_free_security, selinux_sb_free_security),
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
	LSM_HOOK_INIT(inode_init_security, selinux_inode_init_security),
	LSM_HOOK_INIT(inode_init_security_anon, selinux_inode_init_security_anon),
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
	LSM_HOOK_INIT(inode_setxattr_override,
		      selinux_inode_setxattr_override),
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
	LSM_HOOK_INIT(inode_copy_up_xattr, selinux_inode_copy_up_xattr),
	LSM_HOOK_INIT(path_notify, selinux_path_notify),

	LSM_HOOK_INIT(kernfs_init_security, selinux_kernfs_init_security),
	LSM_HOOK_INIT(kernfs_free_security, selinux_kernfs_free_security),

	LSM_HOOK_INIT(file_permission, selinux_file_permission),
	LSM_HOOK_INIT(file_alloc_security, selinux_file_alloc_security),
	LSM_HOOK_INIT(file_free_security, selinux_file_free_security),
	LSM_HOOK_INIT(backing_file_alloc, selinux_backing_file_alloc),
	LSM_HOOK_INIT(backing_file_free, selinux_backing_file_free),
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
	LSM_HOOK_INIT(task_setns_cred_for_children,
		      selinux_task_setns_cred_for_children),
	LSM_HOOK_INIT(cred_prepare, selinux_cred_prepare),
	LSM_HOOK_INIT(cred_free, selinux_cred_free),
	LSM_HOOK_INIT(cred_transfer, selinux_cred_transfer),
	LSM_HOOK_INIT(cred_getsecid, selinux_cred_getsecid),
	LSM_HOOK_INIT(cred_getlsmprop, selinux_cred_getlsmprop),
	LSM_HOOK_INIT(kernel_act_as, selinux_kernel_act_as),
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
	LSM_HOOK_INIT(msg_queue_free_security,
		      selinux_msg_queue_free_security),
	LSM_HOOK_INIT(shm_free_security, selinux_shm_free_security),
	LSM_HOOK_INIT(sem_free_security, selinux_sem_free_security),

	LSM_HOOK_INIT(msg_queue_associate, selinux_msg_queue_associate),
	LSM_HOOK_INIT(msg_queue_msgctl, selinux_msg_queue_msgctl),
	LSM_HOOK_INIT(msg_queue_msgsnd, selinux_msg_queue_msgsnd),
	LSM_HOOK_INIT(msg_queue_msgrcv, selinux_msg_queue_msgrcv),

	LSM_HOOK_INIT(shm_associate, selinux_shm_associate),
	LSM_HOOK_INIT(shm_shmctl, selinux_shm_shmctl),
	LSM_HOOK_INIT(shm_shmat, selinux_shm_shmat),

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
	LSM_HOOK_INIT(skb_free_security, selinux_skb_free_security),
	LSM_HOOK_INIT(sk_free_security, selinux_sk_free_security),
	LSM_HOOK_INIT(sk_clone_security, selinux_sk_clone_security),
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
	LSM_HOOK_INIT(secmark_refcount_inc, selinux_secmark_refcount_inc),
	LSM_HOOK_INIT(secmark_refcount_dec, selinux_secmark_refcount_dec),
	LSM_HOOK_INIT(req_classify_flow, selinux_req_classify_flow),
	LSM_HOOK_INIT(request_sock_clone_security,
		      selinux_request_sock_clone_security),
	LSM_HOOK_INIT(request_sock_free_security,
		      selinux_request_sock_free_security),
	LSM_HOOK_INIT(tun_dev_create, selinux_tun_dev_create),
	LSM_HOOK_INIT(tun_dev_free_security, selinux_tun_dev_free_security),
	LSM_HOOK_INIT(tun_dev_attach_queue, selinux_tun_dev_attach_queue),
	LSM_HOOK_INIT(tun_dev_attach, selinux_tun_dev_attach),
	LSM_HOOK_INIT(tun_dev_open, selinux_tun_dev_open),
	LSM_HOOK_INIT(sctp_assoc_free_security,
		      selinux_sctp_assoc_free_security),
#ifdef CONFIG_SECURITY_INFINIBAND
	LSM_HOOK_INIT(ib_pkey_access, selinux_ib_pkey_access),
	LSM_HOOK_INIT(ib_endport_manage_subnet,
		      selinux_ib_endport_manage_subnet),
#endif
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	LSM_HOOK_INIT(xfrm_policy_free_security, selinux_xfrm_policy_free),
	LSM_HOOK_INIT(xfrm_policy_delete_security, selinux_xfrm_policy_delete),
	LSM_HOOK_INIT(xfrm_state_free_security, selinux_xfrm_state_free),
	LSM_HOOK_INIT(xfrm_state_delete_security, selinux_xfrm_state_delete),
	LSM_HOOK_INIT(xfrm_policy_lookup, selinux_xfrm_policy_lookup),
	LSM_HOOK_INIT(xfrm_sec_ctx_match, selinux_xfrm_sec_ctx_match),
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
	LSM_HOOK_INIT(bpf_prog, selinux_bpf_prog),
#endif

#ifdef CONFIG_PERF_EVENTS
	LSM_HOOK_INIT(perf_event_open, selinux_perf_event_open),
	LSM_HOOK_INIT(perf_event_read, selinux_perf_event_read),
	LSM_HOOK_INIT(perf_event_write, selinux_perf_event_write),
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
	LSM_HOOK_INIT(ib_free_security, selinux_ib_free_security),
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
	LSM_HOOK_INIT(bpf_map_free, selinux_bpf_map_free),
	LSM_HOOK_INIT(bpf_prog_load, selinux_bpf_prog_load),
	LSM_HOOK_INIT(bpf_prog_free, selinux_bpf_prog_free),
	LSM_HOOK_INIT(bpf_token_create, selinux_bpf_token_create),
	LSM_HOOK_INIT(bpf_token_free, selinux_bpf_token_free),
	LSM_HOOK_INIT(bpf_token_cmd, selinux_bpf_token_cmd),
	LSM_HOOK_INIT(bpf_token_capable, selinux_bpf_token_capable),
#endif
#ifdef CONFIG_PERF_EVENTS
	LSM_HOOK_INIT(perf_event_alloc, selinux_perf_event_alloc),
#endif
};

static __init int selinux_init(void)
{
	vma_flags_t data_default_flags = VMA_DATA_DEFAULT_FLAGS;
	int rc;

	pr_info("SELinux:  Initializing.\n");

	rc = selinux_state_init_initial(current_cred(), selinux_enforcing_boot);
	if (rc)
		panic("SELinux: unable to initialize initial policy state: %d\n",
		      rc);

	/* Set the security state for the initial task. */
	cred_init_security();

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

	if (avc_add_callback(selinux_netcache_avc_callback, AVC_CALLBACK_RESET))
		panic("SELinux: Unable to register AVC netcache callback\n");

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

static void delayed_superblock_init(struct super_block *sb, void *data)
{
	struct selinux_state *state = data;
	int rc;

	if (WARN_ON_ONCE(current_selinux_state != state))
		return;
	rc = selinux_set_mnt_opts(sb, NULL, 0, NULL);
	if (rc)
		pr_warn_ratelimited(
			"SELinux: policy state %llu could not initialize superblock %s: %d\n",
			state->id, sb->s_id, rc);
}

void selinux_complete_init(struct selinux_state *state)
{
	const struct cred *old_cred = NULL;
	struct cred *prepared = NULL;
	struct cred_security_struct *security;

	if (WARN_ON_ONCE(!state))
		return;
	pr_debug("SELinux:  Completing initialization.\n");
	if (current_selinux_state != state) {
		if (WARN_ON_ONCE(state->parent != current_selinux_state))
			return;
		prepared = prepare_creds();
		if (!prepared) {
			pr_warn("SELinux: unable to prepare policy-state initialization credentials\n");
			return;
		}
		security = selinux_cred(prepared);
		put_selinux_state(security->state);
		put_cred(security->parent_cred);
		security->state = get_selinux_state(state);
		security->parent_cred = get_current_cred();
		security->osid = SECINITSID_INIT;
		security->sid = SECINITSID_INIT;
		security->exec_sid = SECSID_NULL;
		security->create_sid = SECSID_NULL;
		security->keycreate_sid = SECSID_NULL;
		security->sockcreate_sid = SECSID_NULL;
		old_cred = override_creds(prepared);
	}

	/* Set up any superblocks initialized prior to the policy load. */
	pr_debug("SELinux:  Setting up existing superblocks.\n");
	iterate_supers(delayed_superblock_init, state);
	if (prepared)
		put_cred(revert_creds(old_cred));
}

/* SELinux requires early initialization in order to label
   all processes and objects when they are created. */
DEFINE_LSM(selinux) = {
	.id = &selinux_lsmid,
	.flags = LSM_FLAG_LEGACY_MAJOR | LSM_FLAG_EXCLUSIVE,
	.enabled = &selinux_enabled_boot,
	.blobs = &selinux_blob_sizes,
	.init = selinux_init,
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
