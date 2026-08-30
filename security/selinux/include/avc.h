/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Access vector cache interface for object managers.
 *
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 */

#ifndef _SELINUX_AVC_H_
#define _SELINUX_AVC_H_

#include <linux/stddef.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/audit.h>
#include <linux/lsm_audit.h>
#include <linux/in6.h>
#include "flask.h"
#include "av_permissions.h"
#include "label_view.h"
#include "security.h"

/*
 * An entry in the AVC.
 */
struct avc_entry;

struct task_struct;
struct inode;
struct sock;
struct sk_buff;

/*
 * AVC statistics
 */
struct avc_cache_stats {
	unsigned int lookups;
	unsigned int misses;
	unsigned int allocations;
	unsigned int reclaims;
	unsigned int frees;
};

/*
 * We only need this data after we have decided to send an audit message.
 */
struct selinux_audit_data {
	u32 ssid;
	u32 tsid;
	u16 tclass;
	u32 requested;
	u32 audited;
	u32 denied;
	int result;
	struct selinux_state *state;
} __randomize_layout;

/*
 * AVC operations
 */

void __init avc_init(void);

static inline u32 avc_audit_required(u32 requested,
				     const struct av_decision *avd,
				     int result, u32 auditdeny, u32 *deniedp)
{
	u32 denied, audited;

	if (avd->flags & AVD_FLAGS_NEVERAUDIT)
		return 0;

	denied = requested & ~avd->allowed;
	if (unlikely(denied)) {
		audited = denied & avd->auditdeny;
		/*
		 * auditdeny is TRICKY!  Setting a bit in
		 * this field means that ANY denials should NOT be audited if
		 * the policy contains an explicit dontaudit rule for that
		 * permission.  Take notice that this is unrelated to the
		 * actual permissions that were denied.  As an example lets
		 * assume:
		 *
		 * denied == READ
		 * avd.auditdeny & ACCESS == 0 (not set means explicit rule)
		 * auditdeny & ACCESS == 1
		 *
		 * We will NOT audit the denial even though the denied
		 * permission was READ and the auditdeny checks were for
		 * ACCESS
		 */
		if (auditdeny && !(auditdeny & avd->auditdeny))
			audited = 0;
	} else if (result)
		audited = denied = requested;
	else
		audited = requested & avd->auditallow;
	*deniedp = denied;
	return audited;
}

int slow_avc_audit(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
		   u32 requested, u32 audited, u32 denied, int result,
		   struct common_audit_data *a);

/**
 * avc_audit - Audit the granting or denial of permissions.
 * @state: SELinux state
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions
 * @avd: access vector decisions
 * @result: result from avc_has_perm_noaudit
 * @a:  auxiliary audit data
 *
 * Audit the granting or denial of permissions in accordance
 * with the policy.  This function is typically called by
 * avc_has_perm() after a permission check, but can also be
 * called directly by callers who use avc_has_perm_noaudit()
 * in order to separate the permission check from the auditing.
 * For example, this separation is useful when the permission check must
 * be performed under a lock, to allow the lock to be released
 * before calling the auditing code.
 */
static inline int avc_audit(struct selinux_state *state, u32 ssid, u32 tsid,
			    u16 tclass, u32 requested,
			    const struct av_decision *avd,
			    int result, struct common_audit_data *a)
{
	u32 audited, denied;
	audited = avc_audit_required(requested, avd, result, 0, &denied);
	if (likely(!audited))
		return 0;
	return slow_avc_audit(state, ssid, tsid, tclass, requested, audited,
			      denied, result, a);
}

#define AVC_STRICT	   1 /* Ignore permissive mode. */
#define AVC_EXTENDED_PERMS 2 /* update extended permissions */
int avc_has_perm_noaudit(struct selinux_state *state, u32 ssid, u32 tsid,
			 u16 tclass, u32 requested, unsigned int flags,
			 struct av_decision *avd);

int avc_has_perm(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
		 u32 requested, struct common_audit_data *auditdata);
int avc_has_perm_snapshot(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot,
	u32 ssid, u32 tsid, u16 tclass, u32 requested,
	struct common_audit_data *auditdata);

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_label_ref;
struct selinux_label_view;

struct selinux_avc_provenance {
	const struct selinux_label_ref *label;
	const struct selinux_label_view *view;
	/* Target-branch boundary used by composed operation-local resolution. */
	u64 map_generation;
	u8 source;
};

enum selinux_avc_decision_kind {
	SELINUX_AVC_DECISION_AVC,
	SELINUX_AVC_DECISION_XPERM,
	SELINUX_AVC_DECISION_GUARD,
};

struct selinux_avc_level {
	struct selinux_state *state;
	u32 ssid;
	u32 tsid;
	u32 requested;
	u32 policycap_requested;
	/* Optional exact errno for an enforcing denial in a composed operation. */
	int denial_errno;
	u16 tclass;
	u16 policycap;
	u16 skip_policycap;
	/* Per-snapshot decision ABI; zero keeps the ordinary AVC ABI. */
	u8 decision_kind;
	u8 driver;
	u8 base_perm;
	u8 xperm;
	/* Exact typed result for a guard decision (zero means allow). */
	int guard_result;
	const struct selinux_avc_provenance *provenance;
};

struct selinux_validatetrans_level {
	struct selinux_state *state;
	u32 oldsid;
	u32 newsid;
	u32 tasksid;
	u16 tclass;
	const struct selinux_avc_provenance *provenance;
};

/*
 * Network authorization can combine four checks per policy (packet, ingress,
 * node and peer).  This also covers the smaller mount transactions.  Keep the
 * vectors statically bounded even though their scratch is allocated off-stack.
 */
#define SELINUX_AVC_TRANSACTION_MAX_CHECKS \
	(4 * (SELINUX_LABEL_RESOLUTION_MAX_DEPTH + 1))

struct selinux_avc_transaction_workspace;

struct selinux_avc_transaction_workspace *
selinux_avc_transaction_workspace_alloc(u16 capacity, gfp_t gfp);
void selinux_avc_transaction_workspace_free(
	struct selinux_avc_transaction_workspace *workspace);

int selinux_avc_levels_has_perm(struct selinux_avc_level *levels, u16 count,
				struct common_audit_data *ad);
int selinux_avc_transaction_has_perm_workspace(
	const struct selinux_avc_level *levels,
	const struct selinux_policy_snapshot *snapshots, u16 count,
	struct common_audit_data *ad,
	struct selinux_avc_transaction_workspace *workspace);
int selinux_avc_transaction_has_perm_composite_guarded_workspace(
	const struct selinux_avc_level *levels,
	const struct selinux_policy_snapshot *snapshots, u16 count,
	const struct selinux_validatetrans_level *validatetrans,
	const struct selinux_policy_snapshot *validatetrans_snapshots,
	u16 validatetrans_count, int guard_result,
	struct common_audit_data *ad,
	struct selinux_avc_transaction_workspace *workspace);
int selinux_avc_transaction_has_perm_noaudit(
	const struct selinux_avc_level *levels,
	const struct selinux_policy_snapshot *snapshots, u16 count);
int selinux_avc_levels_has_extended_perm(
	struct selinux_avc_level *levels, u16 count, u8 driver, u8 base_perm,
	u8 xperm, struct common_audit_data *ad);
#endif

#define AVC_EXT_IOCTL	(1 << 0) /* Cache entry for an ioctl extended permission */
#define AVC_EXT_NLMSG	(1 << 1) /* Cache entry for an nlmsg extended permission */
int avc_has_extended_perms(struct selinux_state *state, u32 ssid, u32 tsid,
			   u16 tclass, u32 requested, u8 driver, u8 base_perm,
			   u8 perm, struct common_audit_data *ad);
int avc_has_extended_perms_snapshot(
	struct selinux_state *state,
	const struct selinux_policy_snapshot *snapshot,
	u32 ssid, u32 tsid, u16 tclass, u32 requested,
	u8 driver, u8 base_perm, u8 perm, struct common_audit_data *ad);

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
struct selinux_kunit_xperm_result {
	u16 evaluations[3];
	u16 attempts;
	u16 ordinary_audits;
	u16 aggregate_calls;
	u16 aggregate_denials;
	u16 ordinary_evaluations;
	u16 xperm_evaluations;
	u16 workspace_allocations;
	u8 aggregate_decision_kind;
	u8 aggregate_driver;
	u8 aggregate_base_perm;
	u8 aggregate_xperm;
};

#define SELINUX_KUNIT_MOUNT_TRANSACTION_CHECKS 9
struct selinux_kunit_mount_transaction_result {
	u16 evaluations[SELINUX_KUNIT_MOUNT_TRANSACTION_CHECKS];
	u16 attempts;
	u16 ordinary_audits;
	u16 aggregate_calls;
	u16 aggregate_denials;
};

#define SELINUX_KUNIT_COMPOSITE_AVC_CHECKS 6
#define SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS 2
enum selinux_kunit_composite_allocation_stage {
	SELINUX_KUNIT_COMPOSITE_ALLOC_NONE,
	SELINUX_KUNIT_COMPOSITE_ALLOC_AVC_WORK,
	SELINUX_KUNIT_COMPOSITE_ALLOC_VALIDATETRANS_WORK,
	SELINUX_KUNIT_COMPOSITE_ALLOC_AGGREGATE,
};

struct selinux_kunit_composite_transaction_result {
	u16 avc_evaluations[SELINUX_KUNIT_COMPOSITE_AVC_CHECKS];
	u16 validatetrans_evaluations[SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS];
	u16 attempts;
	u16 ordinary_audits;
	u16 aggregate_calls;
	u16 aggregate_denials;
	u16 aggregate_avc_denials;
	u16 aggregate_validatetrans_denials;
	u16 aggregate_permissive_validatetrans_denials;
	u32 aggregate_validatetrans_oldsids[
		SELINUX_KUNIT_COMPOSITE_VALIDATETRANS_CHECKS];
	u32 first_validatetrans_oldsid;
	u32 first_validatetrans_newsid;
	u32 first_validatetrans_tasksid;
	u16 first_validatetrans_tclass;
};

int selinux_kunit_avc_host_aggregate(bool child_dontaudit, int emit_rc,
				     u16 *denial_count, u64 *namespace_id);
u32 selinux_kunit_avc_effective_requested(
	unsigned long policycaps, u32 requested, u32 policycap_requested,
	u16 policycap, u16 skip_policycap);
int selinux_kunit_avc_xperm_vector(
	const unsigned long policycaps[3], int deny_level, int stale_level,
	int aggregate_rc, struct selinux_kunit_xperm_result *result);
int selinux_kunit_avc_perm_vector(
	int deny_level, int stale_level, int aggregate_rc,
	struct selinux_kunit_xperm_result *result);
int selinux_kunit_avc_mixed_transaction(
	bool ordinary_denied, bool xperm_denied, int guard_result,
	int stale_level, struct selinux_kunit_xperm_result *result);
int selinux_kunit_avc_noaudit_precheck(
	int deny_level, int stale_level, int denial_errno,
	struct selinux_kunit_xperm_result *result);
int selinux_kunit_avc_mount_transaction(
	u16 denial_mask, int stale_level, bool stale_every_attempt,
	int aggregate_rc, struct selinux_kunit_mount_transaction_result *result);
int selinux_kunit_avc_validatetrans_transaction(
	u16 avc_denial_mask, u8 validatetrans_enforcing_mask,
	u8 validatetrans_permissive_mask, int stale_validatetrans_level,
	u8 allocation_fail_stage, int aggregate_rc,
	struct selinux_kunit_composite_transaction_result *result);
#endif

int cred_task_has_perm(const struct cred *cred, const struct task_struct *p,
		       u16 tclass, u32 requested, struct common_audit_data *ad);

int cred_has_extended_perms(const struct cred *cred, u32 tsid, u16 tclass,
			    u32 requested, u8 driver, u8 base_perm, u8 xperm,
			    struct common_audit_data *ad);

int cred_self_has_perm(const struct cred *cred, u16 tclass, u32 requested,
		       struct common_audit_data *ad);

int cred_self_has_perm_noaudit(const struct cred *cred, u16 tclass,
			       u32 requested);

int cred_tsid_has_perm(const struct cred *cred, u32 tsid, u16 tclass,
		       u32 requested, struct common_audit_data *ad);

int cred_tsid_has_perm_noaudit(const struct cred *cred, u32 tsid, u16 tclass,
			       u32 requested, struct av_decision *avd);

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinux_label_resolution;
struct selinux_label_ref;
struct selinux_label_view;
struct selinux_pathless_projection;
int cred_label_has_perm(const struct cred *cred, u32 tsid,
			struct selinux_label_ref *label,
			const struct selinux_label_view *view, u16 tclass,
			u32 requested, struct common_audit_data *ad);
int cred_label_has_perm_noaudit(const struct cred *cred, u32 tsid,
				struct selinux_label_ref *label,
				const struct selinux_label_view *view, u16 tclass,
				u32 requested, struct av_decision *avd);
int cred_label_has_extended_perms(const struct cred *cred, u32 tsid,
				  struct selinux_label_ref *label,
				  const struct selinux_label_view *view,
				  u16 tclass, u32 requested, u8 driver,
				  u8 base_perm, u8 xperm,
				  struct common_audit_data *ad);
int cred_pathless_has_perm(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection, u32 requested,
	struct common_audit_data *ad);
int cred_pathless_has_perm_class(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection, u16 tclass,
	u32 requested, struct common_audit_data *ad);
int cred_pathless_relation_has_perm(
	const struct cred *cred,
	const struct selinux_pathless_projection *source,
	const struct selinux_pathless_projection *target, u16 source_tclass,
	u16 tclass,
	u32 requested, struct common_audit_data *ad);
int cred_pathless_has_perm_noaudit(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection, u32 requested,
	struct av_decision *avd);
int cred_pathless_has_extended_perms(
	const struct cred *cred,
	const struct selinux_pathless_projection *projection, u32 requested,
	u8 driver, u8 base_perm, u8 xperm, struct common_audit_data *ad);
int selinux_state_resolutions_has_perm(
	struct selinux_state *state,
	const struct selinux_label_resolution *source,
	const struct selinux_label_resolution *target, u16 tclass, u32 requested,
	const struct selinux_label_ref *canonical_target,
	const struct selinux_label_view *view, u8 assertion_source,
	struct common_audit_data *ad);
#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
int selinux_kunit_resolution_levels(
	struct selinux_state *state,
	const struct selinux_label_resolution *source,
	const struct selinux_label_resolution *target, u16 *count);
#endif
#endif

int cred_obj_has_perm(const struct cred *cred, u32 ssid, u32 tsid, u16 tclass,
		      u32 requested, struct common_audit_data *ad);

int cred_ssid_has_perm(const struct cred *cred, u32 ssid, u32 tsid, u16 tclass,
		       u32 requested, struct common_audit_data *ad);

int cred_other_has_perm(const struct cred *cred, const struct cred *other,
			u16 tclass, u32 requested,
			struct common_audit_data *ad);
bool cred_sid_chain_equal(const struct cred *left, const struct cred *right);
#ifdef CONFIG_SECURITY_SELINUX_NS
int cred_binder_transaction_has_perm(const struct cred *actor,
				     const struct cred *from,
				     const struct cred *to);
#endif

int task_obj_has_perm(const struct task_struct *s, const struct task_struct *t,
		      u16 tclass, u32 requested, struct common_audit_data *ad);

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
int selinux_kunit_cred_pair_levels(
	const struct cred *policy_cred, const struct cred *subject,
	const struct cred *target, struct selinux_state **states, u32 *ssids,
	u32 *tsids, u16 capacity, u16 *countp);
#endif

int selinux_state_has_perm(struct selinux_state *state, u32 ssid, u32 tsid,
			   u16 tclass, u32 requested,
			   struct common_audit_data *ad);

u32 avc_policy_seqno(struct selinux_state *state);

#define AVC_CALLBACK_GRANT		1
#define AVC_CALLBACK_TRY_REVOKE		2
#define AVC_CALLBACK_REVOKE		4
#define AVC_CALLBACK_RESET		8
#define AVC_CALLBACK_AUDITALLOW_ENABLE	16
#define AVC_CALLBACK_AUDITALLOW_DISABLE 32
#define AVC_CALLBACK_AUDITDENY_ENABLE	64
#define AVC_CALLBACK_AUDITDENY_DISABLE	128
#define AVC_CALLBACK_ADD_XPERMS		256

struct selinux_avc;
typedef int (*selinux_avc_callback_t)(struct selinux_avc *avc, u32 event);

int avc_add_callback(selinux_avc_callback_t callback, u32 events);

/* Exported to selinuxfs */
int avc_get_hash_stats(struct selinux_avc *avc, char *page);
unsigned int avc_get_cache_threshold(struct selinux_avc *avc);
int avc_set_cache_threshold(struct selinux_avc *avc,
			    unsigned int cache_threshold);

#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
DECLARE_PER_CPU(struct avc_cache_stats, avc_cache_stats);
#endif

#endif /* _SELINUX_AVC_H_ */
