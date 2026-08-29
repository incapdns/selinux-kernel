/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SELinux support for the Audit LSM hooks
 *
 * Author: James Morris <jmorris@redhat.com>
 *
 * Copyright (C) 2005 Red Hat, Inc., James Morris <jmorris@redhat.com>
 * Copyright (C) 2006 Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 * Copyright (C) 2006 IBM Corporation, Timothy R. Chavez <tinytim@us.ibm.com>
 */

#ifndef _SELINUX_AUDIT_H
#define _SELINUX_AUDIT_H

#include <linux/audit.h>
#include <linux/types.h>

struct selinux_state;
struct selinux_avc;
struct lsm_prop_ref;

/**
 * selinux_audit_rule_avc_callback - update the audit LSM rules on AVC events.
 * @event: the AVC event
 *
 * Update any audit LSM rules based on the AVC event specified in @event.
 * Returns 0 on success, negative values otherwise.
 */
int selinux_audit_rule_avc_callback(struct selinux_avc *avc, u32 event);

/**
 * selinux_audit_rule_init - alloc/init an selinux audit rule structure.
 * @field: the field this rule refers to
 * @op: the operator the rule uses
 * @rulestr: the text "target" of the rule
 * @rule: pointer to the new rule structure returned via this
 * @gfp: GFP flag used for kmalloc
 *
 * Returns 0 if successful, -errno if not.  On success, the rule structure
 * will be allocated internally.  The caller must free this structure with
 * selinux_audit_rule_free() after use.
 */
int selinux_audit_rule_init(u32 field, u32 op, char *rulestr, void **rule,
			    gfp_t gfp);

/**
 * selinux_audit_rule_free - free an selinux audit rule structure.
 * @rule: pointer to the audit rule to be freed
 *
 * This will free all memory associated with the given rule.
 * If @rule is NULL, no operation is performed.
 */
void selinux_audit_rule_free(void *rule);

/**
 * selinux_audit_rule_state - return the policy state retained by a rule.
 * @rule: pointer to the audit rule
 *
 * The returned state remains valid for the duration of a rule match because
 * the audit rule owns a reference until selinux_audit_rule_free().
 */
struct selinux_state *selinux_audit_rule_state(void *rule);

/**
 * selinux_audit_rule_match - determine if a context ID matches a rule.
 * @ref: immutable identity carrier, when available
 * @prop: includes the compatibility context ID to check
 * @field: the field this rule refers to
 * @op: the operator the rule uses
 * @rule: pointer to the audit rule to check against
 *
 * Returns 1 if the context id matches the rule, 0 if it does not, and
 * -errno on failure.
 */
#ifdef CONFIG_SECURITY_SELINUX_NS
int selinux_audit_rule_match(const struct lsm_prop_ref *ref,
			     const struct lsm_prop *prop, u32 field, u32 op,
			     void *rule);
#else
static inline int selinux_audit_rule_match(const struct lsm_prop_ref *ref,
					   const struct lsm_prop *prop,
					   u32 field,
					   u32 op, void *rule)
{
	(void)ref;
	return selinux_ss_audit_rule_match(prop, field, op, rule);
}
#endif

/**
 * selinux_audit_rule_known - check to see if rule contains selinux fields.
 * @rule: rule to be checked
 * Returns 1 if there are selinux fields specified in the rule, 0 otherwise.
 */
int selinux_audit_rule_known(struct audit_krule *rule);

#endif /* _SELINUX_AUDIT_H */
