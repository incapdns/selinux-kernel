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
#include <linux/kernfs.h>
#include <linux/spinlock.h>
#include <linux/lsm_hooks.h>
#include <linux/msg.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <linux/bpf.h>
#include "flask.h"
#include "avc.h"

struct selinux_object_identity;
struct selinux_state;
struct request_sock;
struct sctp_association;

#define SELINUX_TASK_CHAIN_CACHE_SIZE (1U << 2)

struct selinux_task_chain_cache_entry {
	const struct cred *cred;
	u64 object_id;
	u64 object_generation;
	u64 chain_epoch;
	u32 permissions;
	u16 tclass;
};

struct task_security_struct {
	struct selinux_task_chain_cache_entry
		entries[SELINUX_TASK_CHAIN_CACHE_SIZE];
	struct selinux_state *state_for_children;
	unsigned int next;
};

struct inode_security_struct {
	struct selinux_object_identity *object;
	struct selinux_object_identity *creator_object;
	struct inode *inode; /* back pointer to inode object */
	struct list_head list; /* list of inode_security_struct */
	u16 sclass; /* security class of this object */
	spinlock_t lock;
};

struct kernfs_security_struct {
	struct selinux_object_identity *object;
	struct selinux_state *persistent_label_owner;
};

struct file_security_struct {
	const struct cred *opener_cred;
	const struct cred __rcu *fowner_cred;
	u64 object_generation;
	u64 chain_epoch;
};

struct backing_file_security_struct {
	struct selinux_object_identity *object;
	const struct cred *opener_cred;
};

struct superblock_security_struct {
	struct selinux_object_identity *object;
	struct selinux_object_identity *default_object;
	struct selinux_object_identity *mountpoint_object;
	struct selinux_object_identity *creator_object;
	struct selinux_state *persistent_label_owner;
	struct mutex lock;
	struct list_head isec_head;
	spinlock_t isec_lock;
};

struct msg_security_struct {
	struct selinux_object_identity *object;
};

struct ipc_security_struct {
	struct selinux_object_identity *object;
	u16 sclass; /* security class of this object */
};

struct netif_security_struct {
	struct selinux_object_identity *object;
	const struct net *ns; /* network namespace */
	int ifindex; /* device index */
};

struct netnode_security_struct {
	struct selinux_object_identity *object;
	union {
		__be32 ipv4; /* IPv4 node address */
		struct in6_addr ipv6; /* IPv6 node address */
	} addr;
	u16 family; /* address family */
};

struct netport_security_struct {
	struct selinux_object_identity *object;
	u16 port; /* port number */
	u8 protocol; /* transport protocol */
};

struct sk_security_struct {
	struct selinux_object_identity *object;
	struct selinux_object_identity *peer_object;
	const struct cred *creator_cred;
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
	enum { /* SCTP association state */
	       SCTP_ASSOC_UNSET = 0,
	       SCTP_ASSOC_SET,
	} sctp_assoc_state;
};

struct tun_security_struct {
	struct selinux_object_identity *object;
};

struct sctp_security_struct {
	struct selinux_object_identity *object;
	struct selinux_object_identity *peer_object;
	const struct cred *creator_cred;
};

struct request_sock_security_struct {
	struct selinux_object_identity *object;
	struct selinux_object_identity *peer_object;
	const struct cred *creator_cred;
};

struct skb_security_struct {
	struct selinux_object_identity *object;
	const struct cred *creator_cred;
};

struct request_sock_security_struct *selinux_request_sock(
	const struct request_sock *request);
struct sctp_security_struct *selinux_sctp(
	const struct sctp_association *association);

struct key_security_struct {
	struct selinux_object_identity *object;
};

struct ib_security_struct {
	struct selinux_object_identity *object;
	const struct cred *creator_cred;
};

struct pkey_security_struct {
	struct selinux_object_identity *object;
	u64 subnet_prefix; /* Port subnet prefix */
	u16 pkey; /* PKey number */
};

struct bpf_security_struct {
	struct selinux_object_identity *object;
	struct selinux_object_identity *grantor_object;
	u32 perms; /* permissions for allowed bpf token commands */
};

struct perf_event_security_struct {
	struct selinux_object_identity *object;
};

static inline struct task_security_struct *
selinux_task(const struct task_struct *task)
{
	return task->security + selinux_blob_sizes.lbs_task;
}

static inline struct file_security_struct *selinux_file(const struct file *file)
{
	return file->f_security + selinux_blob_sizes.lbs_file;
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

static inline struct kernfs_security_struct *
selinux_kernfs(const struct kernfs_node *kn)
{
	return kn->security + selinux_blob_sizes.lbs_kernfs_node;
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

static inline struct skb_security_struct *selinux_skb(
	const struct sk_buff *skb)
{
	if (!skb->lsm_provenance)
		return NULL;
	return skb->lsm_provenance + selinux_blob_sizes.lbs_skb;
}

static inline struct skb_security_struct *selinux_skb_blob(void *security)
{
	return security + selinux_blob_sizes.lbs_skb;
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
selinux_bpf_token_security(struct bpf_token *token)
{
	return token->security + selinux_blob_sizes.lbs_bpf_token;
}
#endif /* CONFIG_BPF_SYSCALL */
#endif /* _SELINUX_OBJSEC_H_ */
