/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A global security identifier table (sidtab) is a lookup table
 * of security context strings indexed by SID value.
 */

#ifndef _GLOBAL_SIDTAB_H_
#define _GLOBAL_SIDTAB_H_

#include <linux/types.h>

struct selinux_state;
struct selinux_policy;
struct selinux_label_view;
struct selinux_global_sid_handle;
struct netlbl_lsm_secattr;
struct lsm_prop_ref;
struct qstr;

#ifdef CONFIG_SECURITY_SELINUX_NS
extern int global_sidtab_init(void);

struct selinux_label_ref;
struct selinux_label_ref *global_sid_to_label_ref(u32 sid);

/*
 * Strong global-SID handles own the canonical label and keep the numeric SID
 * live.  A successful get/dup/producer call for a non-NULL SID returns one
 * reference which must be released with global_sid_handle_put().  Producers
 * may return NULL only when their successful result is SECSID_NULL.
 */
struct selinux_global_sid_handle *global_sid_handle_get(u32 sid);
struct selinux_global_sid_handle *
global_sid_handle_dup(struct selinux_global_sid_handle *handle);
void global_sid_handle_put(struct selinux_global_sid_handle *handle);
u32 global_sid_handle_sid(const struct selinux_global_sid_handle *handle);
struct selinux_global_sid_handle *
selinux_prop_ref_handle_get(const struct lsm_prop_ref *ref, u32 *sid);
/* Requires an owned handle; the returned label needs selinux_label_ref_put(). */
struct selinux_label_ref *
global_sid_handle_label_get(const struct selinux_global_sid_handle *handle);
struct selinux_global_sid_handle *
global_context_to_handle(struct selinux_state *state, const char *scontext,
			 u32 scontext_len, u32 local_sid, u32 *out_sid,
			 gfp_t gfp);
/* Validate/canonicalize in @state and return the producer's strong handle. */
struct selinux_global_sid_handle *
security_context_to_global_handle(struct selinux_state *state,
				  const char *scontext, u32 scontext_len,
				  u32 *out_sid, gfp_t gfp);
/*
 * Resolve a map source exactly.  A source may be an uninterpreted label read
 * from a filesystem whose policy is not understood by @state; map targets
 * remain strictly validated by security_context_to_global_handle().
 */
struct selinux_global_sid_handle *
security_context_to_global_map_source_handle(struct selinux_state *state,
					     const char *scontext,
					     u32 scontext_len,
					     u32 *out_sid);
struct selinux_global_sid_handle *
security_context_to_sid_default_handle(struct selinux_state *state,
				       const char *scontext, u32 scontext_len,
				       u32 *out_sid, u32 def_sid, gfp_t gfp);
struct selinux_global_sid_handle *
security_context_to_sid_force_handle(struct selinux_state *state,
				     const char *scontext, u32 scontext_len,
				     u32 *out_sid);
struct selinux_global_sid_handle *
security_transition_sid_handle(struct selinux_state *state, u32 ssid,
			       u32 tsid, u16 tclass,
			       const struct qstr *qstr, u32 *out_sid);
struct selinux_global_sid_handle *
security_port_sid_handle(struct selinux_state *state, u8 protocol, u16 port,
			 u32 *out_sid);
struct selinux_global_sid_handle *
security_ib_pkey_sid_handle(struct selinux_state *state, u64 subnet_prefix,
			   u16 pkey_num, u32 *out_sid);
struct selinux_global_sid_handle *
security_ib_endport_sid_handle(struct selinux_state *state,
			      const char *dev_name, u8 port_num,
			      u32 *out_sid);
struct selinux_global_sid_handle *
security_netif_sid_handle(struct selinux_state *state, const char *name,
			  u32 *out_sid);
struct selinux_global_sid_handle *
security_node_sid_handle(struct selinux_state *state, u16 domain,
			 const void *addr, u32 addrlen, u32 *out_sid);
struct selinux_global_sid_handle *
security_sid_mls_copy_handle(struct selinux_state *state, u32 sid,
			     u32 mls_sid, u32 *out_sid);
struct selinux_global_sid_handle *
security_net_peersid_resolve_handle(struct selinux_state *state, u32 nlbl_sid,
				   u32 nlbl_type, u32 xfrm_sid,
				   u32 *out_sid);
struct selinux_global_sid_handle *
security_fs_use_handle(struct selinux_state *state, const char *fstype,
		       unsigned short *behavior, u32 *out_sid);
struct selinux_global_sid_handle *
security_genfs_sid_handle(struct selinux_state *state, const char *fstype,
			  const char *path, u16 sclass, u32 *out_sid);
struct selinux_global_sid_handle *
selinux_policy_genfs_sid_handle(struct selinux_state *state,
			       struct selinux_policy *policy,
			       const char *fstype, const char *path,
			       u16 sclass, u32 *out_sid);
#ifdef CONFIG_NETLABEL
struct selinux_global_sid_handle *
security_netlbl_secattr_to_sid_view_handle(
	struct selinux_state *state, const struct selinux_label_view *view,
	struct netlbl_lsm_secattr *secattr, u32 *out_sid);
#endif
/* The policy context is retained under RCU; allocation is always GFP_ATOMIC. */
struct selinux_global_sid_handle *
map_ss_sid_to_global_handle(struct selinux_state *state, u32 ss_sid,
			    u32 *out_sid);
void global_sidtab_invalidate_state(struct selinux_state *state);
enum selinux_kunit_global_sid_fault {
	SELINUX_KUNIT_GLOBAL_SID_FAULT_NONE,
	SELINUX_KUNIT_GLOBAL_SID_FAULT_OWNER_RESERVE,
	SELINUX_KUNIT_GLOBAL_SID_FAULT_TOMBSTONE_RESERVE,
	SELINUX_KUNIT_GLOBAL_SID_FAULT_HANDLE_ALLOC,
	SELINUX_KUNIT_GLOBAL_SID_FAULT_TOMBSTONE_ALLOC,
	SELINUX_KUNIT_GLOBAL_SID_FAULT_XA_STORE,
	SELINUX_KUNIT_GLOBAL_SID_FAULT_COUNT,
};

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
int selinux_kunit_global_sid_fault_arm(
	enum selinux_kunit_global_sid_fault fault);
void selinux_kunit_global_sid_fault_reset(void);
u32 selinux_kunit_global_sid_fault_last_sid(void);
u32 selinux_kunit_global_sid_entry_sid(u32 sid);
int selinux_kunit_global_context_to_sid(struct selinux_state *state,
					const char *context, u32 *sid);
struct selinux_global_sid_handle *
selinux_kunit_global_context_to_handle(struct selinux_state *state,
				       const char *context, u32 *sid);
struct selinux_global_sid_handle *
selinux_kunit_global_context_to_handle_local(struct selinux_state *state,
					     const char *context, u32 local_sid,
					     u32 *sid);
int selinux_kunit_global_sid_drop_baseline(u32 sid);
bool selinux_kunit_global_sid_live(u32 sid);
struct sidtab_ss_sid_cache_entry;
struct selinux_policy_snapshot;
bool selinux_kunit_global_sid_cache_matches(
	const struct sidtab_ss_sid_cache_entry *cached, u64 domain_id,
	const struct selinux_policy_snapshot *snapshot);
int selinux_kunit_audit_rule_ref_sid(const struct lsm_prop_ref *ref,
				      const struct selinux_state *owner,
				      u32 *sid);
#ifdef CONFIG_NETLABEL
enum selinux_kunit_netlbl_cache_corruption {
	SELINUX_KUNIT_NETLBL_CORRUPT_MAGIC,
	SELINUX_KUNIT_NETLBL_CORRUPT_VERSION,
	SELINUX_KUNIT_NETLBL_CORRUPT_SID,
};

int selinux_kunit_netlbl_cache_add(struct netlbl_lsm_secattr *secattr,
				   u32 sid);
int selinux_kunit_netlbl_cache_corrupt(struct netlbl_lsm_secattr *secattr,
				       enum selinux_kunit_netlbl_cache_corruption corruption);
int selinux_kunit_netlbl_ss_sid_to_global(struct selinux_state *state,
					  struct netlbl_lsm_secattr *secattr,
					  u32 ss_sid, u32 *sid);
#endif
#endif
#else
static inline int global_sidtab_init(void)
{
	return 0;
}

static inline void global_sidtab_invalidate_state(struct selinux_state *state)
{
}
#endif /* CONFIG_SECURITY_SELINUX_NS */

#endif /* _GLOBAL_SIDTAB_H_ */
