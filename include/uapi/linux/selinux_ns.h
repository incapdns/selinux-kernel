/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SELINUX_NS_H
#define _UAPI_LINUX_SELINUX_NS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define SELINUX_NS_IOC_MAGIC 0xf8

struct selinux_ns_policy {
	__aligned_u64 data;
	__u32 size;
	__u32 flags;
};

#define SELINUX_NS_INFO_INITIALIZED (1U << 0)
#define SELINUX_NS_INFO_ACTIVE      (1U << 1)
#define SELINUX_NS_DIGEST_SIZE 32U

struct selinux_ns_info {
	__u64 id;
	__u64 parent_id;
	__u32 depth;
	__u32 flags;
};

struct selinux_ns_metadata {
	__u32 size;
	__u32 flags;
	__u64 id;
	__u64 parent_id;
	__u64 domain_id;
	__u64 parent_domain_id;
	__u32 depth;
	__u32 policy_seqno;
	__u8 policy_digest[SELINUX_NS_DIGEST_SIZE];
};

/* Issued on /sys/fs/selinux/ns_create; returns a new close-on-exec FD. */
#define SELINUX_NS_IOC_CREATE _IO(SELINUX_NS_IOC_MAGIC, 0x00)

/* Issued on the returned namespace-control FD. */
#define SELINUX_NS_IOC_LOAD_POLICY \
	_IOW(SELINUX_NS_IOC_MAGIC, 0x01, struct selinux_ns_policy)
#define SELINUX_NS_IOC_ACTIVATE _IO(SELINUX_NS_IOC_MAGIC, 0x03)
#define SELINUX_NS_IOC_JOIN _IO(SELINUX_NS_IOC_MAGIC, 0x04)
#define SELINUX_NS_IOC_GET_INFO \
	_IOR(SELINUX_NS_IOC_MAGIC, 0x05, struct selinux_ns_info)
#define SELINUX_NS_IOC_GET_METADATA \
	_IOR(SELINUX_NS_IOC_MAGIC, 0x06, struct selinux_ns_metadata)
#endif /* _UAPI_LINUX_SELINUX_NS_H */
