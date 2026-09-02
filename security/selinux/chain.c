// SPDX-License-Identifier: GPL-2.0-only
/* Atomic authorization across one SELinux policy-state ancestry. */

#include <linux/errno.h>
#include <linux/string.h>

#include "avc.h"
#include "chain.h"
#include "namespace.h"
#include "object_label.h"
#include "security.h"

#define SELINUX_CHAIN_RETRIES 4U
#define SELINUX_CHAIN_XPERM_PRESENT BIT(31)
#define SELINUX_CHAIN_XPERM_DRIVER_SHIFT 16
#define SELINUX_CHAIN_XPERM_BASE_SHIFT 8

struct selinux_chain_level {
	struct selinux_state *state;
	u32 ssid;
	u32 tsid;
	u32 requested;
	u32 auditdeny;
	u32 xperm_spec;
	u32 seqno;
	u16 tclass;
	int result;
	bool decided;
	bool positively_granted;
};

static int selinux_chain_decide_and_audit(
	struct selinux_chain_level *levels,
	u16 count,
	struct common_audit_data *auditdata,
	const struct selinux_object_identity *source,
	u64 source_generation,
	const struct selinux_object_identity *target,
	u64 target_generation,
	bool audit);

static int selinux_chain_decide_and_audit_cacheable(
	struct selinux_chain_level *levels,
	u16 count,
	struct common_audit_data *auditdata,
	const struct selinux_object_identity *source,
	u64 source_generation,
	const struct selinux_object_identity *target,
	u64 target_generation,
	bool audit,
	bool *cacheable,
	u64 *validated_epoch);

const struct cred *selinux_chain_cred_for_state(
	const struct cred *cred,
	const struct selinux_state *state)
{
	const struct cred *level_cred = cred;
	unsigned int depth = 0;

	while (level_cred && depth++ <= SELINUX_NS_MAX_DEPTH) {
		const struct cred_security_struct *security =
			selinux_cred(level_cred);

		if (security->state == state)
			return level_cred;
		level_cred = security->parent_cred;
	}
	return NULL;
}

static int selinux_chain_collect(
	const struct cred *cred,
	struct selinux_chain_level *levels,
	u16 *count)
{
	const struct cred *level_cred = cred;
	struct selinux_state *state;
	u16 index = 0;

	if (!cred || !levels || !count)
		return -EINVAL;

	state = cred_selinux_state(cred);
	while (state) {
		const struct cred_security_struct *security;

		if (!level_cred || index >= SELINUX_NS_MAX_DEPTH + 1)
			return -E2BIG;
		security = selinux_cred(level_cred);
		if (security->state != state)
			return -ESTALE;

		levels[index].state = state;
		levels[index].ssid = security->sid;
		index++;
		level_cred = security->parent_cred;
		state = state->parent;
	}

	if (!index || level_cred)
		return -ESTALE;
	*count = index;
	return 0;
}

int selinux_chain_has_custom_perm(
	const struct cred *cred,
	const struct selinux_object_identity *source,
	const struct selinux_object_identity *target,
	selinux_chain_permission_resolver resolver,
	void *data,
	struct common_audit_data *auditdata)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	unsigned int retry;

	if (!cred || !resolver)
		return -EINVAL;
	for (retry = 0; retry < SELINUX_CHAIN_RETRIES; retry++) {
		const struct cred *level_cred = cred;
		u64 source_generation = source ?
			selinux_object_identity_generation(source) : 0;
		u64 target_generation = target ?
			selinux_object_identity_generation(target) : 0;
		u16 count;
		u16 index;
		int rc;

		if ((source && !source_generation) ||
		    (target && !target_generation))
			continue;
		memset(levels, 0, sizeof(levels));
		rc = selinux_chain_collect(cred, levels, &count);
		if (rc)
			return rc;
		for (index = 0; index < count; index++) {
			struct selinux_chain_permission permission = {
				.ssid = levels[index].ssid,
			};

			rc = resolver(
				levels[index].state,
				level_cred,
				data,
				&permission);
			if (rc == -ESTALE)
				break;
			if (rc)
				return rc;
			if (!permission.tclass ||
			    (permission.decided && !permission.requested))
				return -EINVAL;
			levels[index].ssid = permission.ssid;
			levels[index].tsid = permission.tsid;
			levels[index].requested = permission.requested;
			levels[index].auditdeny = permission.auditdeny;
			if (permission.extended)
				levels[index].xperm_spec =
					SELINUX_CHAIN_XPERM_PRESENT |
					((u32)permission.xperm_driver <<
					 SELINUX_CHAIN_XPERM_DRIVER_SHIFT) |
					((u32)permission.xperm_base <<
					 SELINUX_CHAIN_XPERM_BASE_SHIFT) |
					permission.xperm_value;
			levels[index].tclass = permission.tclass;
			levels[index].decided = permission.decided;
			level_cred = selinux_cred(level_cred)->parent_cred;
		}
		if (index != count)
			continue;
		if ((source && source_generation !=
			       selinux_object_identity_generation(source)) ||
		    (target && target_generation !=
			       selinux_object_identity_generation(target)))
			continue;
		rc = selinux_chain_decide_and_audit(
			levels,
			count,
			auditdata,
			source,
			source_generation,
			target,
			target_generation,
			true);
		if (rc != -ESTALE)
			return rc;
	}
	return -ESTALE;
}

static int selinux_chain_decide_and_audit(
	struct selinux_chain_level *levels,
	u16 count,
	struct common_audit_data *auditdata,
	const struct selinux_object_identity *source,
	u64 source_generation,
	const struct selinux_object_identity *target,
	u64 target_generation,
	bool audit)
{
	return selinux_chain_decide_and_audit_cacheable(
		levels,
		count,
		auditdata,
		source,
		source_generation,
		target,
		target_generation,
		audit,
		NULL,
		NULL);
}

static int selinux_chain_decide_and_audit_cacheable(
	struct selinux_chain_level *levels,
	u16 count,
	struct common_audit_data *auditdata,
	const struct selinux_object_identity *source,
	u64 source_generation,
	const struct selinux_object_identity *target,
	u64 target_generation,
	bool audit,
	bool *cacheable,
	u64 *validated_epoch)
{
	struct selinux_state *leaf = levels[0].state;
	unsigned int retry;

	if (cacheable)
		*cacheable = false;
	if (validated_epoch)
		*validated_epoch = 0;

	for (retry = 0; retry < SELINUX_CHAIN_RETRIES; retry++) {
		u64 epoch = selinux_chain_epoch_read(leaf);
		bool audit_required = false;
		int result = 0;
		u16 index;

		if (!epoch || (source && !source_generation) ||
		    (target && !target_generation))
			continue;

		for (index = 0; index < count; index++) {
			struct av_decision decision;

			if (!levels[index].decided) {
				levels[index].seqno =
					avc_policy_seqno(levels[index].state);
				levels[index].result = 0;
				levels[index].positively_granted = true;
				continue;
			}
			if (levels[index].xperm_spec &
			    SELINUX_CHAIN_XPERM_PRESENT) {
				levels[index].positively_granted = false;
				levels[index].result =
					avc_has_extended_perms_noaudit_disabled(
						levels[index].state,
						levels[index].ssid,
						levels[index].tsid,
						levels[index].tclass,
						levels[index].requested,
						levels[index].xperm_spec >>
							SELINUX_CHAIN_XPERM_DRIVER_SHIFT,
						levels[index].xperm_spec >>
							SELINUX_CHAIN_XPERM_BASE_SHIFT,
						levels[index].xperm_spec,
						&levels[index].seqno);
			} else {
				levels[index].result = avc_has_perm_noaudit_disabled(
					levels[index].state,
					levels[index].ssid,
					levels[index].tsid,
					levels[index].tclass,
					levels[index].requested,
					0,
					&decision);
				levels[index].seqno = decision.seqno;
				levels[index].positively_granted =
					!(levels[index].requested &
					  ~decision.allowed);
			}
			if (levels[index].result && !result)
				result = levels[index].result;
			if (levels[index].result &&
			    levels[index].result != -EACCES)
				break;
		}
		if (index != count)
			return result;

		for (index = 0; index < count; index++)
			if (levels[index].seqno !=
			    avc_policy_seqno(levels[index].state))
				break;
		if (index != count || epoch != selinux_chain_epoch_read(leaf) ||
		    (source && source_generation !=
			       selinux_object_identity_generation(source)) ||
		    (target && target_generation !=
			       selinux_object_identity_generation(target)))
			continue;

		if (!audit)
			return result;
		for (index = count; index-- > 0;) {
			if (!levels[index].decided)
				continue;

			if (levels[index].xperm_spec &
			    SELINUX_CHAIN_XPERM_PRESENT) {
				int extended_rc = avc_has_extended_perms_disabled(
					levels[index].state,
					levels[index].ssid,
					levels[index].tsid,
					levels[index].tclass,
					levels[index].requested,
					levels[index].xperm_spec >>
						SELINUX_CHAIN_XPERM_DRIVER_SHIFT,
					levels[index].xperm_spec >>
						SELINUX_CHAIN_XPERM_BASE_SHIFT,
					levels[index].xperm_spec,
					auditdata);

				if (extended_rc != levels[index].result)
					return -ESTALE;
				audit_required = true;
				continue;
			}
			{
				struct av_decision decision;
				u32 denied;
				u32 audited;
				int audit_rc;
				int decision_rc;

				decision_rc = avc_has_perm_noaudit_disabled(
					levels[index].state,
					levels[index].ssid,
					levels[index].tsid,
					levels[index].tclass,
					levels[index].requested,
					0,
					&decision);
				if (decision_rc != levels[index].result ||
				    decision.seqno != levels[index].seqno)
					return -ESTALE;
				audited = avc_audit_required(
					levels[index].requested,
					&decision,
					decision_rc,
					levels[index].auditdeny,
					&denied);
				if (!audited)
					continue;
				audit_required = true;
				audit_rc = slow_avc_audit(
					levels[index].state,
					levels[index].ssid,
					levels[index].tsid,
					levels[index].tclass,
					levels[index].requested,
					audited,
					denied,
					decision_rc,
					auditdata);
				if (audit_rc)
					return audit_rc;
			}
		}
		if (!result && !audit_required && cacheable) {
			for (index = 0; index < count; index++)
				if (!levels[index].positively_granted)
					break;
			*cacheable = index == count;
		}
		if (validated_epoch)
			*validated_epoch = epoch;
		return result;
	}
	return -ESTALE;
}

int selinux_chain_has_perm_auditdeny_cacheable(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	u32 auditdeny,
	struct common_audit_data *auditdata,
	bool *cacheable,
	u64 *object_generation,
	u64 *chain_epoch)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	u16 count;
	unsigned int retry;

	if (!object || !tclass || !requested)
		return -EINVAL;
	if (cacheable)
		*cacheable = false;
	if (object_generation)
		*object_generation = 0;
	if (chain_epoch)
		*chain_epoch = 0;
	for (retry = 0; retry < SELINUX_CHAIN_RETRIES; retry++) {
		u64 generation = selinux_object_identity_generation(object);
		u16 index;
		int rc;

		if (!generation)
			continue;
		memset(levels, 0, sizeof(levels));
		rc = selinux_chain_collect(cred, levels, &count);
		if (rc)
			return rc;
		for (index = 0; index < count; index++) {
			struct selinux_object_label_value label;

			selinux_object_label_get_or_unlabeled(
				levels[index].state,
				object,
				tclass,
				&label);
			levels[index].tsid = label.sid;
			levels[index].tclass = label.sclass ?
				label.sclass : tclass;
			levels[index].requested = requested;
			levels[index].auditdeny = auditdeny;
			levels[index].decided =
				label.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS;
		}
		if (generation != selinux_object_identity_generation(object))
			continue;
		rc = selinux_chain_decide_and_audit_cacheable(
			levels, count, auditdata,
			NULL, 0, object, generation, true,
			cacheable, chain_epoch);
		if (rc != -ESTALE) {
			if (object_generation)
				*object_generation = generation;
			return rc;
		}
	}
	return -ESTALE;
}

int selinux_chain_has_perm_auditdeny(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	u32 auditdeny,
	struct common_audit_data *auditdata)
{
	return selinux_chain_has_perm_auditdeny_cacheable(
		cred,
		object,
		tclass,
		requested,
		auditdeny,
		auditdata,
		NULL,
		NULL,
		NULL);
}

int selinux_chain_has_perm(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata)
{
	return selinux_chain_has_perm_auditdeny(
		cred, object, tclass, requested, 0, auditdata);
}

int selinux_chain_has_perm_with_policycap(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	u32 policycap_requested,
	unsigned int policycap,
	struct common_audit_data *auditdata)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	unsigned int retry;

	if (!object || !tclass || !requested ||
	    policycap >= __POLICYDB_CAP_MAX)
		return -EINVAL;

	for (retry = 0; retry < SELINUX_CHAIN_RETRIES; retry++) {
		u64 generation = selinux_object_identity_generation(object);
		u16 count;
		u16 index;
		int rc;

		if (!generation)
			continue;
		memset(levels, 0, sizeof(levels));
		rc = selinux_chain_collect(cred, levels, &count);
		if (rc)
			return rc;
		for (index = 0; index < count; index++) {
			struct selinux_object_label_value label;

			selinux_object_label_get_or_unlabeled(
				levels[index].state,
				object,
				tclass,
				&label);
			levels[index].tsid = label.sid;
			levels[index].tclass = label.sclass ?
				label.sclass : tclass;
			levels[index].requested = requested;
			if (READ_ONCE(
			    levels[index].state->policycap[policycap]))
				levels[index].requested |= policycap_requested;
			levels[index].decided =
				label.source !=
				SELINUX_LABEL_SOURCE_POLICY_BYPASS;
		}
		if (generation != selinux_object_identity_generation(object))
			continue;
		rc = selinux_chain_decide_and_audit(
			levels, count, auditdata,
			NULL, 0, object, generation, true);
		if (rc != -ESTALE)
			return rc;
	}
	return -ESTALE;
}

int selinux_chain_has_perm_unless_policycap(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	unsigned int policycap,
	struct common_audit_data *auditdata)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	unsigned int retry;

	if (!object || !tclass || !requested ||
	    policycap >= __POLICYDB_CAP_MAX)
		return -EINVAL;

	for (retry = 0; retry < SELINUX_CHAIN_RETRIES; retry++) {
		u64 generation = selinux_object_identity_generation(object);
		u16 count;
		u16 index;
		int rc;

		if (!generation)
			continue;
		memset(levels, 0, sizeof(levels));
		rc = selinux_chain_collect(cred, levels, &count);
		if (rc)
			return rc;
		for (index = 0; index < count; index++) {
			struct selinux_object_label_value label;

			selinux_object_label_get_or_unlabeled(
				levels[index].state,
				object,
				tclass,
				&label);
			levels[index].tsid = label.sid;
			levels[index].tclass = label.sclass ?
				label.sclass : tclass;
			levels[index].requested = requested;
			levels[index].decided =
				!READ_ONCE(levels[index].state->policycap[
					policycap]) &&
				label.source !=
				SELINUX_LABEL_SOURCE_POLICY_BYPASS;
		}
		if (generation != selinux_object_identity_generation(object))
			continue;
		rc = selinux_chain_decide_and_audit(
			levels, count, auditdata,
			NULL, 0, object, generation, true);
		if (rc != -ESTALE)
			return rc;
	}
	return -ESTALE;
}

int selinux_chain_has_perm_if_policycap(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	unsigned int policycap,
	struct common_audit_data *auditdata)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	unsigned int retry;

	if (!object || !tclass || !requested ||
	    policycap >= __POLICYDB_CAP_MAX)
		return -EINVAL;

	for (retry = 0; retry < SELINUX_CHAIN_RETRIES; retry++) {
		u64 generation = selinux_object_identity_generation(object);
		u16 count;
		u16 index;
		int rc;

		if (!generation)
			continue;
		memset(levels, 0, sizeof(levels));
		rc = selinux_chain_collect(cred, levels, &count);
		if (rc)
			return rc;
		for (index = 0; index < count; index++) {
			struct selinux_object_label_value label;

			selinux_object_label_get_or_unlabeled(
				levels[index].state,
				object,
				tclass,
				&label);
			levels[index].tsid = label.sid;
			levels[index].tclass = label.sclass ?
				label.sclass : tclass;
			levels[index].requested = requested;
			levels[index].decided =
				READ_ONCE(levels[index].state->policycap[
					policycap]) &&
				label.source !=
					SELINUX_LABEL_SOURCE_POLICY_BYPASS;
		}
		if (generation != selinux_object_identity_generation(object))
			continue;
		rc = selinux_chain_decide_and_audit(
			levels, count, auditdata,
			NULL, 0, object, generation, true);
		if (rc != -ESTALE)
			return rc;
	}
	return -ESTALE;
}

static int selinux_chain_has_extended_perm_internal(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	u8 driver,
	u8 base_perm,
	u8 xperm,
	int skip_policycap,
	struct common_audit_data *auditdata)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	u16 count;
	u16 index;
	u64 generation;
	int rc;

	if (!object || !tclass || !requested ||
	    skip_policycap >= __POLICYDB_CAP_MAX)
		return -EINVAL;
	generation = selinux_object_identity_generation(object);
	if (!generation)
		return -ESTALE;
	rc = selinux_chain_collect(cred, levels, &count);
	if (rc)
		return rc;
	for (index = 0; index < count; index++) {
		struct selinux_object_label_value label;

		selinux_object_label_get_or_unlabeled(
			levels[index].state, object, tclass, &label);
		levels[index].tsid = label.sid;
		levels[index].tclass = label.sclass ? label.sclass : tclass;
		levels[index].requested = requested;
		levels[index].xperm_spec = SELINUX_CHAIN_XPERM_PRESENT |
			((u32)driver << SELINUX_CHAIN_XPERM_DRIVER_SHIFT) |
			((u32)base_perm << SELINUX_CHAIN_XPERM_BASE_SHIFT) |
			xperm;
		levels[index].decided =
			(skip_policycap < 0 ||
			 !READ_ONCE(levels[index].state->policycap[
				skip_policycap])) &&
			label.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS;
	}
	if (generation != selinux_object_identity_generation(object))
		return -ESTALE;
	return selinux_chain_decide_and_audit(
		levels, count, auditdata, NULL, 0, object, generation, true);
}

int selinux_chain_has_extended_perm(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	u8 driver,
	u8 base_perm,
	u8 xperm,
	struct common_audit_data *auditdata)
{
	return selinux_chain_has_extended_perm_internal(
		cred, object, tclass, requested,
		driver, base_perm, xperm, -1, auditdata);
}

int selinux_chain_has_extended_perm_unless_policycap(
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	u8 driver,
	u8 base_perm,
	u8 xperm,
	unsigned int policycap,
	struct common_audit_data *auditdata)
{
	return selinux_chain_has_extended_perm_internal(
		cred, object, tclass, requested,
		driver, base_perm, xperm, policycap, auditdata);
}

static int selinux_chain_has_object_perm_internal(
	const struct cred *cred,
	const struct selinux_object_identity *source,
	const struct selinux_object_identity *target,
	u16 tclass,
	u32 requested,
	int required_policycap,
	struct common_audit_data *auditdata)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	unsigned int retry;

	if (!cred || !source || !target || !tclass || !requested)
		return -EINVAL;
	if (required_policycap >= __POLICYDB_CAP_MAX)
		return -EINVAL;
	for (retry = 0; retry < SELINUX_CHAIN_RETRIES; retry++) {
		u64 source_generation =
			selinux_object_identity_generation(source);
		u64 target_generation =
			selinux_object_identity_generation(target);
		u16 count;
		u16 index;
		int rc;

		if (!source_generation || !target_generation)
			continue;
		memset(levels, 0, sizeof(levels));
		rc = selinux_chain_collect(cred, levels, &count);
		if (rc)
			return rc;
		for (index = 0; index < count; index++) {
			struct selinux_object_label_value source_label;
			struct selinux_object_label_value target_label;

			selinux_object_label_get_or_unlabeled(
				levels[index].state,
				source,
				tclass,
				&source_label);
			selinux_object_label_get_or_unlabeled(
				levels[index].state,
				target,
				tclass,
				&target_label);
			levels[index].ssid = source_label.sid;
			levels[index].tsid = target_label.sid;
			levels[index].tclass = tclass;
			levels[index].requested = requested;
			levels[index].decided =
				(required_policycap < 0 ||
				 READ_ONCE(levels[index].state->policycap[
					required_policycap])) &&
				source_label.source !=
					SELINUX_LABEL_SOURCE_POLICY_BYPASS &&
				target_label.source !=
					SELINUX_LABEL_SOURCE_POLICY_BYPASS;
		}
		if (source_generation !=
			    selinux_object_identity_generation(source) ||
		    target_generation !=
			    selinux_object_identity_generation(target))
			continue;
		rc = selinux_chain_decide_and_audit(
			levels,
			count,
			auditdata,
			source,
			source_generation,
			target,
			target_generation,
			true);
		if (rc != -ESTALE)
			return rc;
	}
	return -ESTALE;
}

int selinux_chain_has_object_perm(
	const struct cred *cred,
	const struct selinux_object_identity *source,
	const struct selinux_object_identity *target,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata)
{
	return selinux_chain_has_object_perm_internal(
		cred,
		source,
		target,
		tclass,
		requested,
		-1,
		auditdata);
}

int selinux_chain_has_object_perm_with_policycap(
	const struct cred *cred,
	const struct selinux_object_identity *source,
	const struct selinux_object_identity *target,
	u16 tclass,
	u32 requested,
	unsigned int policycap,
	struct common_audit_data *auditdata)
{
	return selinux_chain_has_object_perm_internal(
		cred,
		source,
		target,
		tclass,
		requested,
		policycap,
		auditdata);
}

int selinux_chain_has_initial_perm(
	const struct cred *cred,
	u32 target_sid,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	u16 count;
	u16 index;
	int rc;

	rc = selinux_chain_collect(cred, levels, &count);
	if (rc)
		return rc;
	for (index = 0; index < count; index++)
		levels[index].tsid = target_sid;
	for (index = 0; index < count; index++) {
		levels[index].tclass = tclass;
		levels[index].requested = requested;
		levels[index].decided = true;
	}
	return selinux_chain_decide_and_audit(
		levels, count, auditdata, NULL, 0, NULL, 0, true);
}

int selinux_chain_has_self_perm(
	const struct cred *cred,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	u16 count;
	u16 index;
	int rc;

	rc = selinux_chain_collect(cred, levels, &count);
	if (rc)
		return rc;
	for (index = 0; index < count; index++)
		levels[index].tsid = levels[index].ssid;
	for (index = 0; index < count; index++) {
		levels[index].tclass = tclass;
		levels[index].requested = requested;
		levels[index].decided = true;
	}
	return selinux_chain_decide_and_audit(
		levels, count, auditdata, NULL, 0, NULL, 0, true);
}

int selinux_chain_has_self_perm_noaudit(
	const struct cred *cred,
	u16 tclass,
	u32 requested)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	u16 count;
	u16 index;
	int rc;

	rc = selinux_chain_collect(cred, levels, &count);
	if (rc)
		return rc;
	for (index = 0; index < count; index++) {
		levels[index].tsid = levels[index].ssid;
		levels[index].tclass = tclass;
		levels[index].requested = requested;
		levels[index].decided = true;
	}
	return selinux_chain_decide_and_audit(
		levels, count, NULL, NULL, 0, NULL, 0, false);
}

int selinux_chain_has_self_perm_unless_policycap(
	const struct cred *cred,
	unsigned int policycap,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	u16 count;
	u16 index;
	int rc;

	if (policycap >= __POLICYDB_CAP_MAX)
		return -EINVAL;
	rc = selinux_chain_collect(cred, levels, &count);
	if (rc)
		return rc;
	for (index = 0; index < count; index++) {
		levels[index].tsid = levels[index].ssid;
		levels[index].tclass = tclass;
		levels[index].requested = requested;
		levels[index].decided =
			!READ_ONCE(levels[index].state->policycap[policycap]);
	}
	return selinux_chain_decide_and_audit(
		levels, count, auditdata, NULL, 0, NULL, 0, true);
}

static u32 selinux_cred_sid_for_state(
	const struct cred *cred,
	const struct selinux_state *state)
{
	const struct cred *level_cred = selinux_chain_cred_for_state(
		cred,
		state);

	return level_cred ?
		selinux_cred(level_cred)->sid : SECINITSID_UNLABELED;
}

int selinux_chain_has_cred_perm(
	const struct cred *cred,
	const struct cred *target,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata)
{
	struct selinux_chain_level levels[SELINUX_NS_MAX_DEPTH + 1] = {};
	u16 count;
	u16 index;
	int rc;

	if (!target || !tclass || !requested)
		return -EINVAL;
	rc = selinux_chain_collect(cred, levels, &count);
	if (rc)
		return rc;
	for (index = 0; index < count; index++) {
		levels[index].tsid = selinux_cred_sid_for_state(
			target, levels[index].state);
		levels[index].tclass = tclass;
		levels[index].requested = requested;
		/*
		 * A same-domain operation is not implicitly authorized.  The
		 * policy still has to grant the requested permission to self, just
		 * as a scalar avc_has_perm(ssid, ssid, ...) check would require.
		 */
		levels[index].decided = true;
	}
	return selinux_chain_decide_and_audit(
		levels, count, auditdata, NULL, 0, NULL, 0, true);
}

int selinux_state_has_initial_perm(
	struct selinux_state *state,
	u32 source_sid,
	u32 target_sid,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata)
{
	return avc_has_perm_disabled(
		state,
		source_sid,
		target_sid,
		tclass,
		requested,
		auditdata);
}

struct selinux_state_object_perm_data {
	struct selinux_state *state;
	const struct selinux_object_identity *object;
	u16 tclass;
	u32 requested;
};

static int selinux_state_object_perm_resolve(
	struct selinux_state *state,
	const struct cred *level_cred,
	void *data,
	struct selinux_chain_permission *permission)
{
	const struct selinux_state_object_perm_data *request = data;
	struct selinux_object_label_value label;

	permission->tclass = request->tclass;
	permission->requested = request->requested;
	permission->decided = state == request->state;
	if (!permission->decided)
		return 0;

	selinux_object_label_get_or_unlabeled(
		state,
		request->object,
		request->tclass,
		&label);
	permission->tsid = label.sid;
	permission->tclass = label.sclass ? label.sclass : request->tclass;
	permission->decided =
		label.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS;
	return 0;
}

int selinux_state_has_perm_for_cred(
	struct selinux_state *state,
	const struct cred *cred,
	const struct selinux_object_identity *object,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata)
{
	struct selinux_state_object_perm_data request = {
		.state = state,
		.object = object,
		.tclass = tclass,
		.requested = requested,
	};

	if (!state || !cred || !object || !tclass || !requested)
		return -EINVAL;
	if (!selinux_chain_cred_for_state(cred, state))
		return -EXDEV;
	return selinux_chain_has_custom_perm(
		cred,
		NULL,
		object,
		selinux_state_object_perm_resolve,
		&request,
		auditdata);
}

struct selinux_state_object_pair_perm_data {
	struct selinux_state *state;
	const struct selinux_object_identity *source;
	const struct selinux_object_identity *target;
	u16 tclass;
	u32 requested;
};

static int selinux_state_object_pair_perm_resolve(
	struct selinux_state *state,
	const struct cred *level_cred,
	void *data,
	struct selinux_chain_permission *permission)
{
	const struct selinux_state_object_pair_perm_data *request = data;
	struct selinux_object_label_value source;
	struct selinux_object_label_value target;

	permission->tclass = request->tclass;
	permission->requested = request->requested;
	permission->decided = state == request->state;
	if (!permission->decided)
		return 0;

	selinux_object_label_get_or_unlabeled(
		state,
		request->source,
		request->tclass,
		&source);
	selinux_object_label_get_or_unlabeled(
		state,
		request->target,
		request->tclass,
		&target);
	permission->ssid = source.sid;
	permission->tsid = target.sid;
	permission->decided =
		source.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS &&
		target.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS;
	return 0;
}

int selinux_state_has_object_perm(
	struct selinux_state *state,
	const struct cred *cred,
	const struct selinux_object_identity *source,
	const struct selinux_object_identity *target,
	u16 tclass,
	u32 requested,
	struct common_audit_data *auditdata)
{
	struct selinux_state_object_pair_perm_data request = {
		.state = state,
		.source = source,
		.target = target,
		.tclass = tclass,
		.requested = requested,
	};

	if (!state || !cred || !source || !target || !tclass || !requested)
		return -EINVAL;
	if (!selinux_chain_cred_for_state(cred, state))
		return -EXDEV;
	return selinux_chain_has_custom_perm(
		cred,
		source,
		target,
		selinux_state_object_pair_perm_resolve,
		&request,
		auditdata);
}

bool selinux_chain_any_policycap(
	const struct cred *cred,
	unsigned int policycap)
{
	const struct cred *level_cred = cred;
	struct selinux_state *state;
	unsigned int depth = 0;

	if (!cred || policycap >= __POLICYDB_CAP_MAX)
		return true;
	state = cred_selinux_state(cred);
	while (state) {
		const struct cred_security_struct *security;

		if (!level_cred || depth++ > SELINUX_NS_MAX_DEPTH)
			return true;
		security = selinux_cred(level_cred);
		if (security->state != state)
			return true;
		if (READ_ONCE(state->policycap[policycap]))
			return true;
		level_cred = security->parent_cred;
		state = state->parent;
	}
	return level_cred != NULL;
}
