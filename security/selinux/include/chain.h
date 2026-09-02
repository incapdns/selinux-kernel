/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SELINUX_CHAIN_H_
#define _SELINUX_CHAIN_H_

#include <linux/types.h>

struct common_audit_data;
struct cred;
struct selinux_object_identity;
struct selinux_state;

struct selinux_chain_permission {
	u32 ssid;
	u32 tsid;
	u32 requested;
	u32 auditdeny;
	u16 tclass;
	bool decided;
	bool extended;
	u8 xperm_driver;
	u8 xperm_base;
	u8 xperm_value;
};

typedef int (*selinux_chain_permission_resolver)(
	struct selinux_state *state,
	const struct cred *level_cred,
	void *data,
	struct selinux_chain_permission *permission);

const struct cred *selinux_chain_cred_for_state(
	const struct cred *cred,
	const struct selinux_state *state);

int selinux_chain_has_custom_perm(
	const struct cred *cred,
	const struct selinux_object_identity *source,
	const struct selinux_object_identity *target,
	selinux_chain_permission_resolver resolver,
	void *data,
	struct common_audit_data *auditdata);

int selinux_chain_has_perm(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata);

int selinux_chain_has_perm_with_policycap(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	u32 policycap_requested,
	unsigned int policycap,
	struct common_audit_data *auditdata);

int selinux_chain_has_perm_unless_policycap(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	unsigned int policycap,
	struct common_audit_data *auditdata);

int selinux_chain_has_perm_if_policycap(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	unsigned int policycap,
	struct common_audit_data *auditdata);

int selinux_chain_has_perm_auditdeny(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	u32 auditdeny,
	struct common_audit_data *auditdata);

int selinux_chain_has_perm_auditdeny_cacheable(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	u32 auditdeny,
	struct common_audit_data *auditdata,
	bool *cacheable,
	u64 *object_generation,
	u64 *chain_epoch);

int selinux_chain_has_extended_perm(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	u8 driver,
	u8 base_perm,
	u8 xperm,
	struct common_audit_data *auditdata);

int selinux_chain_has_extended_perm_unless_policycap(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	u8 driver,
	u8 base_perm,
	u8 xperm,
	unsigned int policycap,
	struct common_audit_data *auditdata);

int selinux_chain_has_object_perm(
	const struct cred *cred,
	const struct selinux_object_identity *source,
	const struct selinux_object_identity *target,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata);

int selinux_chain_has_object_perm_with_policycap(
	const struct cred *cred,
	const struct selinux_object_identity *source,
	const struct selinux_object_identity *target,
	u16 tclass,
	u32 requested,
	unsigned int policycap,
	struct common_audit_data *auditdata);

int selinux_chain_has_initial_perm(
	const struct cred *cred,
	u32 target_sid,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata);

int selinux_chain_has_self_perm(
	const struct cred *cred,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata);

int selinux_chain_has_self_perm_noaudit(
	const struct cred *cred,
	u16 tclass,
	u32 requested);

int selinux_chain_has_self_perm_unless_policycap(
	const struct cred *cred,
	unsigned int policycap,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata);

int selinux_chain_has_cred_perm(
	const struct cred *cred,
	const struct cred *target,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata);

int selinux_state_has_initial_perm(
	struct selinux_state *state,
	u32 source_sid,
	u32 target_sid,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata);

int selinux_state_has_perm_for_cred(
	struct selinux_state *state,
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata);

int selinux_state_has_object_perm(
	struct selinux_state *state,
	const struct cred *cred,
	const struct selinux_object_identity *source,
	const struct selinux_object_identity *target,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata);

bool selinux_chain_any_policycap(
	const struct cred *cred,
	unsigned int policycap);

#endif /* _SELINUX_CHAIN_H_ */
