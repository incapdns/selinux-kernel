/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Implementation of the security services.
 *
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 */

#ifndef _SS_SERVICES_H_
#define _SS_SERVICES_H_

#include <crypto/sha2.h>

#include "policydb.h"

struct selinux_resource_account;

/* Mapping for a single class */
struct selinux_mapping {
	u16 value; /* policy value for class */
	u16 num_perms; /* number of permissions in class */
	u32 perms[sizeof(u32) * 8]; /* policy values for permissions */
};

/* Map for all of the classes, with array size */
struct selinux_map {
	struct selinux_mapping *mapping; /* indexed by class */
	u16 size; /* array size of mapping */
};

struct selinux_policy {
	struct sidtab *sidtab;
	struct policydb policydb;
	struct selinux_map map;
	/*
	 * One conservative admission slot is charged before policy parsing.
	 * Conditional-policy clones transfer this ownership because the clone
	 * shares every non-conditional allocation with its predecessor.
	 */
	struct selinux_resource_account *resources;
	u64 resource_bytes;
	unsigned long policycaps;
	u32 latest_granting;
	u8 binary_digest[SHA256_DIGEST_SIZE];
	u8 effective_digest[SHA256_DIGEST_SIZE];
} __randomize_layout;

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
struct selinux_state;
struct selinux_avc;
enum selinux_kunit_audit_op {
	SELINUX_KUNIT_AUDIT_EQUAL,
	SELINUX_KUNIT_AUDIT_NOT_EQUAL,
};

void *selinux_kunit_audit_rule_alloc(struct selinux_state *state,
				     u32 user, u32 role, u32 type);
bool selinux_kunit_audit_rule_state_is_owner(struct selinux_state *state);
bool selinux_kunit_audit_rule_avc_is_owner(struct selinux_avc *avc);
int selinux_kunit_audit_rule_match(const struct lsm_prop *prop, u32 field,
				   u32 op, void *rule);
int selinux_kunit_policy_resource_reserve(struct selinux_state *state,
					  struct selinux_policy *policy);
void selinux_kunit_policy_resource_release(struct selinux_policy *policy);
void selinux_kunit_policy_resource_transfer(struct selinux_policy *oldpolicy,
					    struct selinux_policy *newpolicy);
void selinux_kunit_policy_effective_digest(struct selinux_policy *policy);
#endif

struct convert_context_args {
	struct selinux_state *state;
	struct policydb *oldp;
	struct policydb *newp;
};

void services_compute_xperms_drivers(struct extended_perms *xperms,
				     struct avtab_node *node);
void services_compute_xperms_decision(struct extended_perms_decision *xpermd,
				      struct avtab_node *node);

int services_convert_context(struct convert_context_args *args,
			     struct context *oldc, struct context *newc,
			     gfp_t gfp_flags);

int context_struct_to_string(struct policydb *policydb,
				    struct context *context,
				    const char **scontext,
				    u32 *scontext_len);

#endif /* _SS_SERVICES_H_ */
