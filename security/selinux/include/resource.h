/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SELINUX_RESOURCE_H_
#define _SELINUX_RESOURCE_H_

#include <linux/refcount.h>
#include <linux/types.h>

struct selinux_resource_account;
struct user_namespace;

struct selinux_audit_reservation {
	struct selinux_resource_account *account;
	u64 bytes;
};

#define SELINUX_AUDIT_RECORD_OVERHEAD 512U

enum selinux_resource_kind {
	SELINUX_RESOURCE_NAMESPACE,
	SELINUX_RESOURCE_DOMAIN,
	SELINUX_RESOURCE_LABEL,
	SELINUX_RESOURCE_GLOBAL_SID,
	SELINUX_RESOURCE_MAP,
	SELINUX_RESOURCE_MAP_ENTRY,
	SELINUX_RESOURCE_VIEW,
	SELINUX_RESOURCE_PROJECTION,
	SELINUX_RESOURCE_POLICY,
	SELINUX_RESOURCE_AVC,
	SELINUX_RESOURCE_AUDIT,
	SELINUX_RESOURCE_IPC_ANCHOR,
	SELINUX_RESOURCE_KINDS,
};

struct selinux_resource_account *
selinux_resource_account_get_owner(struct user_namespace *owner);
struct selinux_resource_account *
selinux_resource_account_get(struct selinux_resource_account *account);
void selinux_resource_account_put(struct selinux_resource_account *account);

int selinux_resource_reserve(struct selinux_resource_account *account,
			     enum selinux_resource_kind kind, u64 objects,
			     u64 bytes);
void selinux_resource_release(struct selinux_resource_account *account,
			      enum selinux_resource_kind kind, u64 objects,
			      u64 bytes);
int selinux_resource_reserve_global(u64 objects, u64 bytes);
void selinux_resource_release_global(u64 objects, u64 bytes);
#ifdef CONFIG_SECURITY_SELINUX_NS
int selinux_namespace_reserve(struct selinux_resource_account *account,
			      u64 bytes, u64 global_limit);
void selinux_namespace_release(struct selinux_resource_account *account,
			       u64 bytes);
#endif
int selinux_audit_reserve(struct selinux_resource_account *account,
			  u64 payload_bytes,
			  struct selinux_audit_reservation *reservation);
void selinux_audit_release(struct selinux_audit_reservation *reservation);

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
enum selinux_resource_account_kunit_fault {
	SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_NONE,
	SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_ALLOC,
	SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_HASH_INSERT,
	SELINUX_RESOURCE_ACCOUNT_KUNIT_FAULT_MAX,
};

enum selinux_resource_reserve_kunit_fault {
	SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_NONE,
	SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_GLOBAL_OBJECTS,
	SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_GLOBAL_BYTES,
	SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_OWNER_OBJECTS,
	SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_OWNER_BYTES,
	SELINUX_RESOURCE_RESERVE_KUNIT_FAULT_MAX,
};

void selinux_resource_account_kunit_fail_next(
	struct user_namespace *owner,
	enum selinux_resource_account_kunit_fault fault);
void selinux_resource_reserve_kunit_fail_next(
	struct selinux_resource_account *account,
	enum selinux_resource_reserve_kunit_fault fault);
bool selinux_kunit_resource_account_published(struct user_namespace *owner);
u32 selinux_kunit_resource_account_refs(
	struct selinux_resource_account *account);
u64 selinux_kunit_resource_total_objects(
	struct selinux_resource_account *account);
u64 selinux_kunit_resource_total_bytes(
	struct selinux_resource_account *account);
u64 selinux_kunit_resource_objects(struct selinux_resource_account *account,
				   enum selinux_resource_kind kind);
u64 selinux_kunit_resource_bytes(struct selinux_resource_account *account,
				 enum selinux_resource_kind kind);
u64 selinux_kunit_resource_global_objects(void);
u64 selinux_kunit_resource_global_bytes(void);
u64 selinux_kunit_namespace_owner_count(
	struct selinux_resource_account *account);
u64 selinux_kunit_namespace_global_count(void);
int selinux_kunit_namespace_reserve(
	struct selinux_resource_account *account, u64 bytes, u64 owner_limit,
	u64 global_limit);
void selinux_kunit_audit_buckets_reset(void);
int selinux_kunit_audit_reserve_channel(
	struct selinux_resource_account *account, bool host, u64 payload_bytes,
	struct selinux_audit_reservation *reservation);
u64 selinux_kunit_audit_host_tokens(void);
u64 selinux_kunit_audit_child_tokens(void);
u64 selinux_kunit_audit_refill_amount(u64 periods, u64 maximum);
void selinux_kunit_audit_child_tokens_set(u64 tokens);
#endif

#endif /* _SELINUX_RESOURCE_H_ */
