/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  Security-Enhanced Linux (SELinux) security module
 *
 *  This file contains the SELinux security data structures for kernel objects.
 *
 *  Author(s):  Stephen Smalley, <stephen.smalley.work@gmail.com>
 *		Chris Vance, <cvance@nai.com>
 *		Wayne Salamon, <wsalamon@nai.com>
 *		James Morris <jmorris@redhat.com>
 *
 *  Copyright (C) 2001,2002 Networks Associates Technology, Inc.
 *  Copyright (C) 2003 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *  Copyright (C) 2016 Mellanox Technologies
 */

#ifndef _SELINUX_OBJSEC_H_
#define _SELINUX_OBJSEC_H_

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/in.h>
#include <linux/spinlock.h>
#include <linux/lsm_hooks.h>
#include <linux/msg.h>
#include <net/net_namespace.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include "flask.h"
#include "avc.h"
#include "label_view.h"
#include "security.h"

struct selinux_net_assertion;
struct selinux_net_provenance;
struct selinux_pathless_projection;
struct selinux_inode_create_plan;
struct selinux_inode_setxattr_plan;
struct selinux_global_sid_handle;
struct netlbl_lsm_cache;

enum selinux_prop_ref_kind {
	SELINUX_PROP_REF_NONE,
	SELINUX_PROP_REF_NUMERIC,
#ifdef CONFIG_SECURITY_SELINUX_NS
	SELINUX_PROP_REF_CRED,
	SELINUX_PROP_REF_HANDLE,
	SELINUX_PROP_REF_PATHLESS,
#endif
};

/* Immutable ownership behind the compatibility secid in struct lsm_prop. */
struct selinux_prop_ref_security {
	u32 sid;
	u8 kind;
#ifdef CONFIG_SECURITY_SELINUX_NS
	/*
	 * Monotonic audit-only memo.  Zero is unclaimed, one is a transient
	 * builder, and every other value is the immutable rule-owner pointer.
	 * The identity fields below remain immutable for the carrier lifetime.
	 */
	unsigned long audit_owner;
	u32 audit_owner_sid;
	int audit_owner_status;
	union {
		const struct cred *cred;
		struct selinux_global_sid_handle *handle;
		struct selinux_pathless_projection *projection;
	};
#endif
};

struct avdc_entry {
	u32 isid; /* inode SID */
	struct av_decision avd; /* av decision */
};

struct task_security_struct {
#define TSEC_AVDC_DIR_SIZE (1 << 2)
	struct {
		u32 sid; /* current SID for cached entries */
		u32 seqno; /* AVC sequence number */
		unsigned int dir_spot; /* dir cache index to check first */
		struct avdc_entry dir[TSEC_AVDC_DIR_SIZE]; /* dir entries */
		bool permissive_neveraudit; /* permissive and neveraudit */
	} avdcache;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_inode_create_plan *create_plan;
	struct selinux_inode_setxattr_plan *setxattr_plan;
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
	bool create_plan_kunit_force;
#endif
#endif
} __randomize_layout;

static inline bool task_avdcache_eligible(void)
{
	/*
	 * A chained credential is checked against multiple policies, each with
	 * its own sequence number and enforcing state.  The per-task cache only
	 * records the current policy, so it cannot safely represent that result.
	 */
	return !selinux_cred(current_cred())->parent_cred;
}

static inline bool task_avdcache_permnoaudit(struct task_security_struct *tsec,
					     u32 sid)
{
	return (task_avdcache_eligible() &&
		tsec->avdcache.permissive_neveraudit &&
		sid == tsec->avdcache.sid &&
		tsec->avdcache.seqno ==
			avc_policy_seqno(current_selinux_state));
}

enum label_initialized {
	LABEL_INVALID, /* invalid or not initialized */
	LABEL_INITIALIZED, /* initialized */
	LABEL_PENDING
};

struct inode_security_struct {
	struct inode *inode; /* back pointer to inode object */
	struct list_head list; /* list of inode_security_struct */
	u32 task_sid; /* SID of creating task */
	u32 sid; /* SID of this object */
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *task_sid_handle;
	struct selinux_global_sid_handle *sid_handle;
	struct selinux_copy_up_assertion *copy_up;
	struct selinux_label_ref __rcu *label_ref;
	struct selinux_pathless_projection __rcu *pathless;
	struct selinux_pathless_projection *pathless_context;
	u8 label_source;
	u8 pathless_kind;
#endif
	u16 sclass; /* security class of this object */
	unsigned char initialized; /* initialization flag */
	spinlock_t lock;
};

#ifdef CONFIG_SECURITY_SELINUX_NS
/* Consume @handle and atomically publish the complete canonical inode tuple. */
int selinux_inode_security_take_sid_handle(
	struct inode_security_struct *isec,
	struct selinux_global_sid_handle *handle, const u16 *sclass,
	enum selinux_label_source source,
	enum label_initialized initialized);
int selinux_inode_security_set_sid(
	struct inode_security_struct *isec, u32 sid, const u16 *sclass,
	enum selinux_label_source source,
	enum label_initialized initialized);
#endif

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_copy_up_assertion {
	struct selinux_label_ref *label;
	const struct selinux_label_view *view;
	/* Strong owner; @sid is only its compatibility projection. */
	struct selinux_global_sid_handle *sid_handle;
	u32 sid;
	u8 source;
};
#endif

struct mount_security_struct {
	const struct selinux_label_view *view;
	/*
	 * Topology derivation is permitted exactly once, before the mount is
	 * published.  Retaining the pre-derived view until mnt_free keeps a
	 * speculative reader memory-safe without charging every permission
	 * check for a reference-count operation.
	 */
	const struct selinux_label_view *pre_topology_view;
	bool topology_applied;
};

struct file_security_struct {
	u32 sid; /* SID of open file description */
	u32 isid; /* SID of inode at the time of file open */
	u64 chain_epoch; /* Policy-chain generation at file open */
	const struct cred *cred; /* cred for file owner (for SIGIO) */
	const struct selinux_label_view *view; /* view selected by f_path */
#ifdef CONFIG_SECURITY_SELINUX_NS
	/* Strong creator-origin identity for operations which no longer carry a path. */
	struct selinux_pathless_projection *pathless;
#endif
};

static inline bool selinux_file_permission_cache_valid(
	const struct file_security_struct *fsec, const struct cred *actor,
	const struct cred *opener, u32 actor_sid, u32 inode_sid, u64 chain_epoch)
{
	return chain_epoch != 0 && actor == opener && actor_sid == fsec->sid &&
	       inode_sid == fsec->isid && chain_epoch == fsec->chain_epoch;
}

struct backing_file_security_struct {
	const struct cred *cred; /* credentials that opened the user file */
	const struct selinux_label_view *view; /* user-visible file view */
};

struct superblock_security_struct {
	u32 sid; /* SID of file system superblock */
	u32 def_sid; /* default SID for labeling */
	u32 mntpoint_sid; /* SECURITY_FS_USE_MNTPOINT context for files */
	u32 creator_sid; /* SID of privileged process */
	unsigned short behavior; /* labeling behavior */
	unsigned short flags; /* which mount options were specified */
#ifdef CONFIG_SECURITY_SELINUX_NS
	/* Immutable owner of the filesystem's intrinsic label representation. */
	struct selinux_state *anchor_state;
	struct selinux_label_domain *anchor_domain;
	/* Strong owners for the compatibility SID fields above. */
	struct selinux_global_sid_handle *sid_handle;
	struct selinux_global_sid_handle *def_sid_handle;
	struct selinux_global_sid_handle *mntpoint_sid_handle;
	struct selinux_global_sid_handle *creator_sid_handle;
#endif
	struct mutex lock;
	struct list_head isec_head;
	spinlock_t isec_lock;
};

#define SELINUX_KERNFS_POLICY_RETRIES 3

#ifdef CONFIG_SECURITY_SELINUX_NS
struct kernfs_root_security_struct {
	/* Immutable intrinsic-label provenance for the entire hierarchy. */
	struct selinux_state *anchor_state;
	struct selinux_label_domain *anchor_domain;
};
#endif

struct msg_security_struct {
	u32 sid; /* SID of message */
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_pathless_projection *projection;
#endif
};

struct ipc_security_struct {
	u16 sclass; /* security class of this object */
	u32 sid; /* SID of IPC resource */
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_pathless_projection *projection;
#endif
};

/*
 * Stable identity for policy-derived optimization caches.  Cache entries must
 * not retain a selinux_state merely to guard against pointer reuse: label
 * domain IDs never repeat, and the immutable snapshot rejects policy reloads
 * and ancestor-chain changes.  policy_cookie is identity-only and is never
 * dereferenced by cache users.
 */
struct selinux_policy_cache_key {
	u64 domain_id;
	struct selinux_policy_snapshot snapshot;
};

static inline void selinux_policy_cache_key_init(
	struct selinux_policy_cache_key *key, u64 domain_id,
	const struct selinux_policy_snapshot *snapshot)
{
	key->domain_id = domain_id;
	key->snapshot = *snapshot;
}

static inline bool selinux_policy_cache_key_matches(
	const struct selinux_policy_cache_key *key, u64 domain_id,
	const struct selinux_policy_snapshot *snapshot)
{
	return key->domain_id == domain_id &&
	       selinux_policy_snapshot_equal(&key->snapshot, snapshot);
}

struct netif_security_struct {
	const struct net *ns; /* network namespace */
	int ifindex; /* device index */
	u32 sid; /* SID for this interface */
	struct selinux_policy_cache_key policy;
};

struct netnode_security_struct {
	union {
		__be32 ipv4; /* IPv4 node address */
		struct in6_addr ipv6; /* IPv6 node address */
	} addr;
	u32 sid; /* SID for this node */
	u16 family; /* address family */
	struct selinux_policy_cache_key policy;
};

struct netport_security_struct {
	u32 sid; /* SID for this node */
	u16 port; /* port number */
	u8 protocol; /* transport protocol */
	struct selinux_policy_cache_key policy;
};

struct sk_security_struct {
#ifdef CONFIG_NETLABEL
	enum { /* NetLabel state */
	       NLBL_UNSET = 0,
	       NLBL_REQUIRE,
	       NLBL_LABELED,
	       NLBL_REQSKB,
	       NLBL_CONNLABELED,
	} nlbl_state;
	struct netlbl_lsm_secattr *nlbl_secattr; /* NetLabel sec attributes */
#endif
	u32 sid; /* SID of this object */
	u32 peer_sid; /* peer SID; NS=y projection of peer_provenance */
	u16 sclass; /* sock security class */
	enum { /* SCTP association state */
	       SCTP_ASSOC_UNSET = 0,
	       SCTP_ASSOC_SET,
	} sctp_assoc_state;
	struct selinux_state *state; /* SELinux state */
#ifdef CONFIG_SECURITY_SELINUX_NS
	/* Immutable subject ownership; SID/state above are legacy projections. */
	struct selinux_net_provenance __rcu *provenance;
	struct selinux_net_provenance __rcu *peer_provenance;
#endif
};

#ifdef CONFIG_SECURITY_SELINUX_NS
struct req_security_struct {
	struct selinux_net_provenance __rcu *provenance;
	struct selinux_net_provenance __rcu *peer_provenance;
};

struct sctp_assoc_security_struct {
	struct selinux_net_provenance __rcu *provenance;
	struct selinux_net_provenance __rcu *peer_provenance;
	/* Native peer evidence; protected by the association socket lock. */
	struct netlbl_lsm_cache *peer_netlabel_cache;
	const struct selinux_label_view *peer_netlabel_view;
	struct selinux_net_provenance *peer_xfrm;
	u32 peer_netlabel_type;
};

struct selinux_scm_security {
	struct selinux_net_provenance *provenance;
};
#endif

struct tun_security_struct {
	u32 sid; /* SID for the tun device sockets */
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_net_provenance __rcu *provenance;
#endif
};

struct key_security_struct {
	u32 sid; /* SID of key */
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_pathless_projection *projection;
#endif
};

struct ib_security_struct {
	u32 sid; /* SID of the queue pair or MAD agent */
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_pathless_projection *projection;
#endif
};

struct pkey_security_struct {
	u64 subnet_prefix; /* Port subnet prefix */
	u16 pkey; /* PKey number */
	u32 sid; /* SID of pkey */
	struct selinux_policy_cache_key policy;
};

struct bpf_security_struct {
	u32 sid; /* SID of bpf obj creator */
	u32 perms; /* permissions for allowed bpf token commands */
	u32 grantor_sid; /* SID of token grantor */
#ifdef CONFIG_SECURITY_SELINUX_NS
	/* Immutable canonical identities, published before the BPF object. */
	struct selinux_pathless_projection *object;
	struct selinux_pathless_projection *grantor;
#endif
};

struct perf_event_security_struct {
	u32 sid; /* SID of perf_event obj creator */
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_pathless_projection *projection;
#endif
};

extern struct lsm_blob_sizes selinux_blob_sizes;

static inline struct task_security_struct *
selinux_task(const struct task_struct *task)
{
	return task->security + selinux_blob_sizes.lbs_task;
}

static inline struct selinux_prop_ref_security *
selinux_prop_ref(const struct lsm_prop_ref *ref)
{
	return (void *)ref->security + selinux_blob_sizes.lbs_prop_ref;
}

#if defined(CONFIG_SECURITY_SELINUX_NS) && \
	defined(CONFIG_SECURITY_SELINUX_KUNIT_TEST)
static inline void selinux_kunit_inode_create_plan_force(bool force)
{
	selinux_task(current)->create_plan_kunit_force = force;
}

void selinux_kunit_inode_setxattr_plan_rebind_fail(void);
#endif

static inline struct file_security_struct *selinux_file(const struct file *file)
{
	return file->f_security + selinux_blob_sizes.lbs_file;
}

static inline struct mount_security_struct *
selinux_mount_security(const struct vfsmount *mnt)
{
	if (unlikely(!mnt || !mnt->mnt_security))
		return NULL;
	return mnt->mnt_security + selinux_blob_sizes.lbs_mnt;
}

static inline void *
selinux_inode_create_plan_security(struct security_inode_create_plan *plan)
{
	return plan->security + selinux_blob_sizes.lbs_inode_create_plan;
}

static inline void *selinux_inode_setxattr_plan_security(
	struct security_inode_setxattr_plan *plan)
{
	return plan->security + selinux_blob_sizes.lbs_inode_setxattr_plan;
}

static inline struct backing_file_security_struct *
selinux_backing_file(const struct file *backing_file)
{
	void *blob = backing_file_security(backing_file);
	return blob + selinux_blob_sizes.lbs_backing_file;
}

static inline struct inode_security_struct *
selinux_inode(const struct inode *inode)
{
	if (unlikely(!inode->i_security))
		return NULL;
	return inode->i_security + selinux_blob_sizes.lbs_inode;
}

static inline struct msg_security_struct *
selinux_msg_msg(const struct msg_msg *msg_msg)
{
	return msg_msg->security + selinux_blob_sizes.lbs_msg_msg;
}

static inline struct ipc_security_struct *
selinux_ipc(const struct kern_ipc_perm *ipc)
{
	return ipc->security + selinux_blob_sizes.lbs_ipc;
}

static inline struct superblock_security_struct *
selinux_superblock(const struct super_block *superblock)
{
	return superblock->s_security + selinux_blob_sizes.lbs_superblock;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static inline struct kernfs_root_security_struct *
selinux_kernfs_root_security(const void *security)
{
	if (unlikely(!security))
		return NULL;
	return (void *)security + selinux_blob_sizes.lbs_kernfs_root;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
int selinux_kunit_kernfs_root_alloc(void *root_security);
void selinux_kunit_kernfs_root_free(void *root_security);
int selinux_kunit_kernfs_root_to_sb(struct super_block *sb,
				    const void *root_security);
void selinux_kunit_kernfs_sb_free(struct super_block *sb);
int selinux_kunit_kernfs_init_security(struct kernfs_node *parent,
				       struct kernfs_node *kn,
				       const void *root_security);
extern int (* const selinux_kunit_kernfs_snapshot_read)(
	struct selinux_state *state,
	struct selinux_policy_snapshot *snapshot);
#endif
#endif

#ifdef CONFIG_KEYS
static inline struct key_security_struct *selinux_key(const struct key *key)
{
	return key->security + selinux_blob_sizes.lbs_key;
}
#endif /* CONFIG_KEYS */

static inline struct sk_security_struct *selinux_sock(const struct sock *sock)
{
	return sock->sk_security + selinux_blob_sizes.lbs_sock;
}

static inline struct tun_security_struct *selinux_tun_dev(void *security)
{
	return security + selinux_blob_sizes.lbs_tun_dev;
}

static inline struct ib_security_struct *selinux_ib(void *ib_sec)
{
	return ib_sec + selinux_blob_sizes.lbs_ib;
}

static inline struct perf_event_security_struct *
selinux_perf_event(void *perf_event)
{
	return perf_event + selinux_blob_sizes.lbs_perf_event;
}

#ifdef CONFIG_BPF_SYSCALL
static inline struct bpf_security_struct *
selinux_bpf_map_security(struct bpf_map *map)
{
	return map->security + selinux_blob_sizes.lbs_bpf_map;
}

static inline struct bpf_security_struct *
selinux_bpf_prog_security(struct bpf_prog *prog)
{
	return prog->aux->security + selinux_blob_sizes.lbs_bpf_prog;
}

static inline struct bpf_security_struct *
selinux_bpf_link_security(struct bpf_link *link)
{
	return link->security + selinux_blob_sizes.lbs_bpf_link;
}

static inline struct bpf_security_struct *
selinux_bpf_btf_security(struct btf *btf)
{
	return btf_security(btf) + selinux_blob_sizes.lbs_bpf_btf;
}

static inline struct bpf_security_struct *
selinux_bpf_token_security(struct bpf_token *token)
{
	return token->security + selinux_blob_sizes.lbs_bpf_token;
}
#endif /* CONFIG_BPF_SYSCALL */
#endif /* _SELINUX_OBJSEC_H_ */
