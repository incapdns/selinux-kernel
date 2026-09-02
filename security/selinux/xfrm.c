// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Security-Enhanced Linux (SELinux) security module
 *
 *  This file contains the SELinux XFRM hook function implementations.
 *
 *  Authors:  Serge Hallyn <sergeh@us.ibm.com>
 *	      Trent Jaeger <jaegert@us.ibm.com>
 *
 *  Updated: Venkat Yekkirala <vyekkirala@TrustedCS.com>
 *
 *           Granular IPSec Associations for use in MLS environments.
 *
 *  Copyright (C) 2005 International Business Machines Corporation
 *  Copyright (C) 2006 Trusted Computer Solutions, Inc.
 */

/*
 * USAGE:
 * NOTES:
 *   1. Make sure to enable the following options in your kernel config:
 *	CONFIG_SECURITY=y
 *	CONFIG_SECURITY_NETWORK=y
 *	CONFIG_SECURITY_NETWORK_XFRM=y
 *	CONFIG_SECURITY_SELINUX=m/y
 * ISSUES:
 *   1. Caching packets, so they are not dropped during negotiation
 *   2. Emulating a reasonable SO_PEERSEC across machines
 *   3. Testing addition of sk_policy's with security context via setsockopt
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <linux/security.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/xfrm.h>
#include <net/xfrm.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <linux/atomic.h>
#include <linux/overflow.h>

#include "avc.h"
#include "chain.h"
#include "namespace.h"
#include "object_label.h"
#include "objsec.h"
#include "xfrm.h"

/* Labeled XFRM instance counter */
atomic_t selinux_xfrm_refcount __read_mostly = ATOMIC_INIT(0);

/*
 * xfrm_sec_ctx is a UAPI-shaped object with a flexible string at its end.
 * SELinux owns every instance attached to an XFRM policy/state, so reserve an
 * aligned private tail for the stable multi-policy identity.  The UAPI length
 * and copies continue to expose only xfrm_sec_ctx + ctx_str.
 */
struct selinux_xfrm_context_security {
	struct selinux_object_identity *object;
	const struct cred *creator_cred;
};

static int selinux_xfrm_context_allocation_size(
	u16 context_length,
	size_t *allocation_size)
{
	size_t public_size;

	if (check_add_overflow(
			sizeof(struct xfrm_sec_ctx),
			(size_t)context_length,
			&public_size))
		return -EOVERFLOW;
	public_size = ALIGN(
		public_size,
		__alignof__(struct selinux_xfrm_context_security));
	if (check_add_overflow(
			public_size,
			sizeof(struct selinux_xfrm_context_security),
			allocation_size))
		return -EOVERFLOW;
	return 0;
}

static struct selinux_xfrm_context_security *
selinux_xfrm_context_security(struct xfrm_sec_ctx *context)
{
	return (void *)context + ALIGN(
		sizeof(*context) + context->ctx_len,
		__alignof__(struct selinux_xfrm_context_security));
}

static const struct selinux_xfrm_context_security *
selinux_xfrm_context_security_const(const struct xfrm_sec_ctx *context)
{
	return (const void *)context + ALIGN(
		sizeof(*context) + context->ctx_len,
		__alignof__(struct selinux_xfrm_context_security));
}

/*
 * Returns true if the context is an LSM/SELinux context.
 */
static inline int selinux_authorizable_ctx(struct xfrm_sec_ctx *ctx)
{
	return (ctx &&
		(ctx->ctx_doi == XFRM_SC_DOI_LSM) &&
		(ctx->ctx_alg == XFRM_SC_ALG_SELINUX));
}

/*
 * Returns true if the xfrm contains a security blob for SELinux.
 */
static inline int selinux_authorizable_xfrm(struct xfrm_state *x)
{
	return selinux_authorizable_ctx(x->security);
}

static struct selinux_object_identity *selinux_xfrm_object_from_context(
	const struct cred *cred,
	const struct xfrm_sec_ctx *context,
	gfp_t gfp)
{
	struct selinux_object_label_value
		values[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_state *states[SELINUX_NS_MAX_DEPTH + 1] = {};
	struct selinux_object_identity *object;
	struct selinux_state *state;
	struct selinux_state *leaf;
	u16 count = 0;
	size_t length;
	int rc;

	if (!cred || !selinux_authorizable_ctx(
			(struct xfrm_sec_ctx *)context))
		return ERR_PTR(-EINVAL);
	leaf = cred_selinux_state(cred);
	object = selinux_object_identity_alloc(leaf, gfp);
	if (IS_ERR(object))
		return object;

	length = strnlen(context->ctx_str, context->ctx_len);
	if (length == context->ctx_len) {
		rc = -EINVAL;
		goto err_object;
	}
	for (state = leaf; state; state = state->parent) {
		u32 sid = SECINITSID_UNLABELED;

		if (count >= ARRAY_SIZE(states)) {
			rc = -E2BIG;
			goto err_object;
		}
		if (state == leaf) {
			rc = security_context_to_sid(
				state,
				context->ctx_str,
				length,
				&sid,
				gfp);
			if (rc)
				goto err_object;
		}
		states[count] = state;
		values[count] = (struct selinux_object_label_value) {
			.sid = sid,
			.sclass = SECCLASS_ASSOCIATION,
			.source = state == leaf ?
				SELINUX_LABEL_SOURCE_SECURITY_CONTEXT :
				SELINUX_LABEL_SOURCE_FOREIGN_PERSISTENT,
		};
		count++;
	}
	rc = selinux_object_labels_set_chain(
		object,
		states,
		values,
		count,
		gfp);
	if (rc)
		goto err_object;
	return object;

err_object:
	selinux_object_identity_put(object);
	return ERR_PTR(rc);
}

static struct selinux_object_identity *selinux_xfrm_unlabeled_object(
	const struct cred *cred,
	gfp_t gfp)
{
	return selinux_object_identity_alloc_initial(
		cred_selinux_state(cred),
		SECINITSID_UNLABELED,
		SECCLASS_ASSOCIATION,
		SELINUX_LABEL_SOURCE_KERNEL_INITIAL,
		gfp);
}

struct selinux_xfrm_flow_source {
	const struct cred *cred;
	const struct selinux_object_identity *object;
	struct selinux_object_identity *owned_object;
};

static void selinux_xfrm_flow_source_release(
	struct selinux_xfrm_flow_source *source)
{
	selinux_object_identity_put(source->owned_object);
	source->owned_object = NULL;
}

static int selinux_xfrm_flow_source_from_skb(
	const struct sk_buff *skb,
	struct selinux_xfrm_flow_source *source)
{
	struct sec_path *path = skb_sec_path((struct sk_buff *)skb);
	struct sock *sk;
	int index;

	if (path) {
		for (index = path->len - 1; index >= 0; index--) {
			struct xfrm_state *x = path->xvec[index];
			const struct selinux_xfrm_context_security *security;

			if (!selinux_authorizable_xfrm(x))
				continue;
			security = selinux_xfrm_context_security_const(
				x->security);
			source->cred = security->creator_cred;
			source->object = security->object;
			return 0;
		}
	}
	{
		const struct skb_security_struct *security = selinux_skb(skb);

		if (security && security->creator_cred && security->object) {
			source->cred = security->creator_cred;
			source->object = security->object;
			return 0;
		}
	}
	sk = skb_to_full_sk((struct sk_buff *)skb);
	if (sk) {
		const struct sk_security_struct *security = selinux_sock(sk);

		if (security->creator_cred && security->object) {
			source->cred = security->creator_cred;
			source->object = security->object;
			return 0;
		}
	}
	return -ENOENT;
}

static int selinux_xfrm_flow_source_get(
	const struct flowi_common *flow,
	struct selinux_xfrm_flow_source *source)
{
	memset(source, 0, sizeof(*source));
	if (!flow)
		return -EINVAL;
	if (flow->flowic_lsm_origin_cookie != FLOWI_LSM_ORIGIN_COOKIE)
		goto kernel_origin;
	if (!flow->flowic_lsm_origin)
		goto kernel_origin;

	switch (flow->flowic_lsm_origin_type) {
	case FLOWI_LSM_ORIGIN_SOCKET: {
		const struct sk_security_struct *security = selinux_sock(
			flow->flowic_lsm_origin);

		if (security && security->creator_cred && security->object) {
			source->cred = security->creator_cred;
			source->object = security->object;
			return 0;
		}
		break;
	}
	case FLOWI_LSM_ORIGIN_REQUEST_SOCK: {
		const struct request_sock_security_struct *security =
			selinux_request_sock(flow->flowic_lsm_origin);

		if (security && security->creator_cred && security->object) {
			source->cred = security->creator_cred;
			source->object = security->object;
			return 0;
		}
		break;
	}
	case FLOWI_LSM_ORIGIN_SKB:
		if (!selinux_xfrm_flow_source_from_skb(
				flow->flowic_lsm_origin,
				source))
			return 0;
		break;
	case FLOWI_LSM_ORIGIN_NONE:
	default:
		break;
	}

kernel_origin:
	/*
	 * Flows with no live kernel origin are kernel-generated and carry an
	 * explicit unlabeled association identity in the initial policy.
	 */
	source->cred = kernel_cred();
	source->owned_object = selinux_xfrm_unlabeled_object(
		source->cred,
		GFP_ATOMIC);
	if (IS_ERR(source->owned_object)) {
		int rc = PTR_ERR(source->owned_object);

		source->owned_object = NULL;
		return rc;
	}
	source->object = source->owned_object;
	return 0;
}

static bool selinux_xfrm_flow_label_matches(
	const struct selinux_xfrm_flow_source *source,
	const struct selinux_object_identity *target)
{
	const struct cred *level_cred = source->cred;
	struct selinux_state *state = cred_selinux_state(source->cred);
	unsigned int depth = 0;

	while (state) {
		struct selinux_object_label_value source_label;
		struct selinux_object_label_value target_label;

		if (!level_cred || depth++ > SELINUX_NS_MAX_DEPTH ||
		    selinux_cred(level_cred)->state != state)
			return false;
		selinux_object_label_get_or_unlabeled(
			state,
			source->object,
			SECCLASS_ASSOCIATION,
			&source_label);
		selinux_object_label_get_or_unlabeled(
			state,
			target,
			SECCLASS_ASSOCIATION,
			&target_label);
		if (source_label.sid != target_label.sid)
			return false;
		level_cred = selinux_cred(level_cred)->parent_cred;
		state = state->parent;
	}
	return !level_cred;
}

int selinux_xfrm_sec_ctx_match(
	struct xfrm_sec_ctx *first,
	struct xfrm_sec_ctx *second)
{
	const struct selinux_xfrm_context_security *first_security;
	const struct selinux_xfrm_context_security *second_security;
	const struct cred *first_cred;
	const struct cred *second_cred;
	struct selinux_state *state;
	unsigned int depth = 0;

	if (!first || !second)
		return !first && !second;
	if (!selinux_authorizable_ctx(first) ||
	    !selinux_authorizable_ctx(second) ||
	    first->ctx_doi != second->ctx_doi ||
	    first->ctx_alg != second->ctx_alg)
		return 0;
	first_security = selinux_xfrm_context_security_const(first);
	second_security = selinux_xfrm_context_security_const(second);
	first_cred = first_security->creator_cred;
	second_cred = second_security->creator_cred;
	if (!first_cred || !second_cred ||
	    cred_selinux_state(first_cred) != cred_selinux_state(second_cred))
		return 0;

	state = cred_selinux_state(first_cred);
	while (state) {
		struct selinux_object_label_value first_label;
		struct selinux_object_label_value second_label;

		if (!first_cred || !second_cred ||
		    depth++ > SELINUX_NS_MAX_DEPTH ||
		    selinux_cred(first_cred)->state != state ||
		    selinux_cred(second_cred)->state != state)
			return 0;
		selinux_object_label_get_or_unlabeled(
			state,
			first_security->object,
			SECCLASS_ASSOCIATION,
			&first_label);
		selinux_object_label_get_or_unlabeled(
			state,
			second_security->object,
			SECCLASS_ASSOCIATION,
			&second_label);
		if (first_label.sid != second_label.sid)
			return 0;
		first_cred = selinux_cred(first_cred)->parent_cred;
		second_cred = selinux_cred(second_cred)->parent_cred;
		state = state->parent;
	}
	return !first_cred && !second_cred;
}

/*
 * Allocates a xfrm_sec_state and populates it using the supplied security
 * xfrm_user_sec_ctx context.
 */
static int selinux_xfrm_alloc_user(struct xfrm_sec_ctx **ctxp,
				   struct xfrm_user_sec_ctx *uctx,
				   gfp_t gfp)
{
	const struct cred *cred = current_cred();
	struct selinux_xfrm_context_security *security = NULL;
	struct selinux_object_label_value root_label;
	size_t allocation_size;
	int rc;
	struct xfrm_sec_ctx *ctx = NULL;
	u32 str_len;

	if (ctxp == NULL || uctx == NULL ||
	    uctx->ctx_doi != XFRM_SC_DOI_LSM ||
	    uctx->ctx_alg != XFRM_SC_ALG_SELINUX)
		return -EINVAL;

	str_len = uctx->ctx_len;
	if (str_len >= PAGE_SIZE)
		return -ENOMEM;
	rc = selinux_xfrm_context_allocation_size(
		str_len + 1,
		&allocation_size);
	if (rc)
		return rc;

	ctx = kzalloc(allocation_size, gfp);
	if (!ctx)
		return -ENOMEM;

	ctx->ctx_doi = XFRM_SC_DOI_LSM;
	ctx->ctx_alg = XFRM_SC_ALG_SELINUX;
	ctx->ctx_len = str_len + 1;
	memcpy(ctx->ctx_str, &uctx[1], str_len);
	ctx->ctx_str[str_len] = '\0';
	security = selinux_xfrm_context_security(ctx);
	security->creator_cred = get_cred(cred);
	security->object = selinux_xfrm_object_from_context(cred, ctx, gfp);
	if (IS_ERR(security->object)) {
		rc = PTR_ERR(security->object);
		security->object = NULL;
		goto err;
	}
	selinux_object_label_get_or_unlabeled(
		init_selinux_state,
		security->object,
		SECCLASS_ASSOCIATION,
		&root_label);
	ctx->ctx_sid = root_label.sid;
	rc = selinux_chain_has_perm(
		cred,
		security->object,
		SECCLASS_ASSOCIATION,
		ASSOCIATION__SETCONTEXT,
		NULL);
	if (rc)
		goto err;

	*ctxp = ctx;
	atomic_inc(&selinux_xfrm_refcount);
	return 0;

err:
	if (security) {
		selinux_object_identity_put(security->object);
		put_cred(security->creator_cred);
	}
	kfree(ctx);
	return rc;
}

/*
 * Free the xfrm_sec_ctx structure.
 */
static void selinux_xfrm_free(struct xfrm_sec_ctx *ctx)
{
	struct selinux_xfrm_context_security *security;

	if (!ctx)
		return;

	security = selinux_xfrm_context_security(ctx);
	selinux_object_identity_put(security->object);
	put_cred(security->creator_cred);
	atomic_dec(&selinux_xfrm_refcount);
	kfree(ctx);
}

/*
 * Authorize the deletion of a labeled SA or policy rule.
 */
static int selinux_xfrm_delete(struct xfrm_sec_ctx *ctx)
{
	const struct selinux_xfrm_context_security *security;

	if (!ctx)
		return 0;

	security = selinux_xfrm_context_security_const(ctx);
	return selinux_chain_has_perm(
		current_cred(),
		security->object,
		SECCLASS_ASSOCIATION,
		ASSOCIATION__SETCONTEXT,
		NULL);
}

/*
 * LSM hook implementation that authorizes that a flow can use a xfrm policy
 * rule.
 */
int selinux_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx,
			      const struct flowi_common *flow)
{
	const struct selinux_xfrm_context_security *target;
	struct selinux_xfrm_flow_source source;
	int rc;

	/* All flows should be treated as polmatch'ing an otherwise applicable
	 * "non-labeled" policy. This would prevent inadvertent "leaks". */
	if (!ctx)
		return 0;

	/* Context sid is either set to label or ANY_ASSOC */
	if (!selinux_authorizable_ctx(ctx))
		return -EINVAL;

	rc = selinux_xfrm_flow_source_get(flow, &source);
	if (rc)
		return rc;
	target = selinux_xfrm_context_security_const(ctx);
	rc = selinux_chain_has_object_perm(
		source.cred,
		source.object,
		target->object,
		SECCLASS_ASSOCIATION,
		ASSOCIATION__POLMATCH,
		NULL);
	selinux_xfrm_flow_source_release(&source);
	return (rc == -EACCES ? -ESRCH : rc);
}

/*
 * LSM hook implementation that authorizes that a state matches
 * the given policy, flow combo.
 */
int selinux_xfrm_state_pol_flow_match(struct xfrm_state *x,
				      struct xfrm_policy *xp,
				      const struct flowi_common *flic)
{
	const struct selinux_xfrm_context_security *state_security;
	struct selinux_xfrm_flow_source source;
	int rc;

	if (!xp->security)
		if (x->security)
			/* unlabeled policy and labeled SA can't match */
			return 0;
		else
			/* unlabeled policy and unlabeled SA match all flows */
			return 1;
	else
		if (!x->security)
			/* unlabeled SA and labeled policy can't match */
			return 0;
		else
			if (!selinux_authorizable_xfrm(x))
				/* Not a SELinux-labeled SA */
				return 0;

	rc = selinux_xfrm_flow_source_get(flic, &source);
	if (rc)
		return 0;
	state_security = selinux_xfrm_context_security_const(x->security);
	if (!selinux_xfrm_flow_label_matches(
			&source,
			state_security->object)) {
		selinux_xfrm_flow_source_release(&source);
		return 0;
	}

	/* We don't need a separate SA Vs. policy polmatch check since the SA
	 * is now of the same label as the flow and a flow Vs. policy polmatch
	 * check had already happened in selinux_xfrm_policy_lookup() above. */
	rc = selinux_chain_has_object_perm(
		source.cred,
		source.object,
		state_security->object,
		SECCLASS_ASSOCIATION,
		ASSOCIATION__SENDTO,
		NULL);
	selinux_xfrm_flow_source_release(&source);
	return rc ? 0 : 1;
}

static int selinux_xfrm_context_sid(
	struct selinux_state *state,
	const struct xfrm_sec_ctx *context,
	u32 *sid)
{
	const struct selinux_xfrm_context_security *security;
	struct selinux_object_label_value label;

	if (!selinux_authorizable_ctx((struct xfrm_sec_ctx *)context)) {
		*sid = SECSID_NULL;
		return 0;
	}
	security = selinux_xfrm_context_security_const(context);
	selinux_object_label_get_or_unlabeled(
		state,
		security->object,
		SECCLASS_ASSOCIATION,
		&label);
	*sid = label.sid;
	return 0;
}

static int selinux_xfrm_skb_sid_egress(
	struct selinux_state *state,
	struct sk_buff *skb,
	u32 *sid)
{
	struct dst_entry *dst = skb_dst(skb);
	struct xfrm_state *x;

	if (dst == NULL) {
		*sid = SECSID_NULL;
		return 0;
	}
	x = dst->xfrm;
	if (x == NULL || !selinux_authorizable_xfrm(x)) {
		*sid = SECSID_NULL;
		return 0;
	}

	return selinux_xfrm_context_sid(state, x->security, sid);
}

static int selinux_xfrm_skb_sid_ingress(
	struct selinux_state *state,
	struct sk_buff *skb,
	u32 *sid,
	int ckall)
{
	u32 sid_session = SECSID_NULL;
	struct sec_path *sp = skb_sec_path(skb);

	if (sp) {
		int i;

		for (i = sp->len - 1; i >= 0; i--) {
			struct xfrm_state *x = sp->xvec[i];
			if (selinux_authorizable_xfrm(x)) {
				struct xfrm_sec_ctx *ctx = x->security;
				u32 context_sid;
				int rc;

				rc = selinux_xfrm_context_sid(
					state, ctx, &context_sid);
				if (rc)
					return rc;

				if (sid_session == SECSID_NULL) {
					sid_session = context_sid;
					if (!ckall)
						goto out;
				} else if (sid_session != context_sid) {
					*sid = SECSID_NULL;
					return -EINVAL;
				}
			}
		}
	}

out:
	*sid = sid_session;
	return 0;
}

/*
 * LSM hook implementation that checks and/or returns the xfrm sid for the
 * incoming packet.
 */
int selinux_xfrm_decode_session(struct sk_buff *skb, u32 *sid, int ckall)
{
	if (skb == NULL) {
		*sid = SECSID_NULL;
		return 0;
	}
	return selinux_xfrm_skb_sid_ingress(
		init_selinux_state, skb, sid, ckall);
}

int selinux_xfrm_skb_sid(
	struct selinux_state *state,
	struct sk_buff *skb,
	u32 *sid)
{
	int rc;

	rc = selinux_xfrm_skb_sid_ingress(state, skb, sid, 0);
	if (rc == 0 && *sid == SECSID_NULL)
		rc = selinux_xfrm_skb_sid_egress(state, skb, sid);

	return rc;
}

/*
 * LSM hook implementation that allocs and transfers uctx spec to xfrm_policy.
 */
int selinux_xfrm_policy_alloc(struct xfrm_sec_ctx **ctxp,
			      struct xfrm_user_sec_ctx *uctx,
			      gfp_t gfp)
{
	return selinux_xfrm_alloc_user(ctxp, uctx, gfp);
}

/*
 * LSM hook implementation that copies security data structure from old to new
 * for policy cloning.
 */
int selinux_xfrm_policy_clone(struct xfrm_sec_ctx *old_ctx,
			      struct xfrm_sec_ctx **new_ctxp)
{
	const struct selinux_xfrm_context_security *old_security;
	struct selinux_xfrm_context_security *new_security;
	struct xfrm_sec_ctx *new_ctx;
	size_t allocation_size;
	int rc;

	if (!old_ctx)
		return 0;

	rc = selinux_xfrm_context_allocation_size(
		old_ctx->ctx_len,
		&allocation_size);
	if (rc)
		return rc;
	new_ctx = kmemdup(old_ctx, allocation_size, GFP_ATOMIC);
	if (!new_ctx)
		return -ENOMEM;
	old_security = selinux_xfrm_context_security_const(old_ctx);
	new_security = selinux_xfrm_context_security(new_ctx);
	new_security->object = selinux_object_identity_get(
		old_security->object);
	if (!new_security->object) {
		kfree(new_ctx);
		return -ESTALE;
	}
	new_security->creator_cred = get_cred(old_security->creator_cred);
	atomic_inc(&selinux_xfrm_refcount);
	*new_ctxp = new_ctx;

	return 0;
}

/*
 * LSM hook implementation that frees xfrm_sec_ctx security information.
 */
void selinux_xfrm_policy_free(struct xfrm_sec_ctx *ctx)
{
	selinux_xfrm_free(ctx);
}

/*
 * LSM hook implementation that authorizes deletion of labeled policies.
 */
int selinux_xfrm_policy_delete(struct xfrm_sec_ctx *ctx)
{
	return selinux_xfrm_delete(ctx);
}

/*
 * LSM hook implementation that allocates a xfrm_sec_state, populates it using
 * the supplied security context, and assigns it to the xfrm_state.
 */
int selinux_xfrm_state_alloc(struct xfrm_state *x,
			     struct xfrm_user_sec_ctx *uctx)
{
	return selinux_xfrm_alloc_user(&x->security, uctx, GFP_KERNEL);
}

/* Build an acquire state from the flow's complete policy-local identity. */
int selinux_xfrm_state_alloc_acquire(
	struct xfrm_state *x,
	struct xfrm_sec_ctx *policy_context,
	const struct flowi_common *flow)
{
	struct selinux_xfrm_flow_source source;
	struct selinux_xfrm_context_security *security;
	struct selinux_object_label_value leaf_label;
	struct selinux_object_label_value root_label;
	struct selinux_state *leaf;
	struct xfrm_sec_ctx *context;
	char *context_string = NULL;
	size_t allocation_size;
	u32 context_length;
	int rc;

	if (!policy_context)
		return 0;
	if (!selinux_authorizable_ctx(policy_context))
		return -EINVAL;

	rc = selinux_xfrm_flow_source_get(flow, &source);
	if (rc)
		return rc;
	leaf = cred_selinux_state(source.cred);
	selinux_object_label_get_or_unlabeled(
		leaf,
		source.object,
		SECCLASS_ASSOCIATION,
		&leaf_label);
	rc = security_sid_to_context(
		leaf,
		leaf_label.sid,
		&context_string,
		&context_length);
	if (rc)
		goto out_source;
	rc = selinux_xfrm_context_allocation_size(
		context_length,
		&allocation_size);
	if (rc)
		goto out_string;
	context = kzalloc(allocation_size, GFP_ATOMIC);
	if (!context) {
		rc = -ENOMEM;
		goto out_string;
	}

	context->ctx_doi = XFRM_SC_DOI_LSM;
	context->ctx_alg = XFRM_SC_ALG_SELINUX;
	context->ctx_len = context_length;
	memcpy(context->ctx_str, context_string, context_length);
	security = selinux_xfrm_context_security(context);
	security->object = selinux_object_identity_clone_for_state(
		source.object,
		leaf,
		GFP_ATOMIC);
	if (IS_ERR(security->object)) {
		rc = PTR_ERR(security->object);
		security->object = NULL;
		kfree(context);
		goto out_string;
	}
	security->creator_cred = get_cred(source.cred);
	selinux_object_label_get_or_unlabeled(
		init_selinux_state,
		security->object,
		SECCLASS_ASSOCIATION,
		&root_label);
	context->ctx_sid = root_label.sid;
	x->security = context;
	atomic_inc(&selinux_xfrm_refcount);
	rc = 0;

out_string:
	kfree(context_string);
out_source:
	selinux_xfrm_flow_source_release(&source);
	return rc;
}

/*
 * LSM hook implementation that frees xfrm_state security information.
 */
void selinux_xfrm_state_free(struct xfrm_state *x)
{
	selinux_xfrm_free(x->security);
}

/*
 * LSM hook implementation that authorizes deletion of labeled SAs.
 */
int selinux_xfrm_state_delete(struct xfrm_state *x)
{
	return selinux_xfrm_delete(x->security);
}

/*
 * LSM hook that controls access to unlabelled packets.  If
 * a xfrm_state is authorizable (defined by macro) then it was
 * already authorized by the IPSec process.  If not, then
 * we need to check for unlabelled access since this may not have
 * gone thru the IPSec process.
 */
struct selinux_xfrm_compat_permission {
	const struct selinux_object_identity *source;
	const struct selinux_object_identity *target;
	u32 requested;
};

static int selinux_xfrm_compat_permission_resolver(
	struct selinux_state *state,
	const struct cred *level_cred,
	void *data,
	struct selinux_chain_permission *permission)
{
	struct selinux_xfrm_compat_permission *request = data;
	struct selinux_object_label_value source_label;
	struct selinux_object_label_value target_label;

	selinux_object_label_get_or_unlabeled(
		state,
		request->source,
		SECCLASS_ASSOCIATION,
		&source_label);
	selinux_object_label_get_or_unlabeled(
		state,
		request->target,
		SECCLASS_ASSOCIATION,
		&target_label);

	permission->ssid = source_label.sid;
	permission->tsid = target_label.sid;
	permission->tclass = SECCLASS_ASSOCIATION;
	permission->requested = request->requested;
	permission->decided =
		source_label.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS &&
		target_label.source != SELINUX_LABEL_SOURCE_POLICY_BYPASS &&
		!READ_ONCE(state->policycap[POLICYDB_CAP_NETPEER]);
	return 0;
}

static int selinux_xfrm_compat_has_perm(
	const struct sk_security_struct *socket_security,
	const struct selinux_object_identity *peer,
	u32 requested,
	struct common_audit_data *audit)
{
	struct selinux_xfrm_compat_permission request;

	if (!socket_security || !socket_security->creator_cred ||
	    !socket_security->object || !peer)
		return -ESTALE;
	request = (struct selinux_xfrm_compat_permission) {
		.source = socket_security->object,
		.target = peer,
		.requested = requested,
	};
	return selinux_chain_has_custom_perm(
		socket_security->creator_cred,
		socket_security->object,
		peer,
		selinux_xfrm_compat_permission_resolver,
		&request,
		audit);
}

int selinux_xfrm_sock_rcv_skb(struct sk_security_struct *sksec,
			      struct sk_buff *skb,
			      struct common_audit_data *ad)
{
	struct selinux_object_identity *unlabeled = NULL;
	const struct selinux_object_identity *peer = NULL;
	int i;
	struct sec_path *sp = skb_sec_path(skb);

	if (sp) {
		for (i = 0; i < sp->len; i++) {
			struct xfrm_state *x = sp->xvec[i];

			if (x && selinux_authorizable_xfrm(x)) {
				peer = selinux_xfrm_context_security_const(
					x->security)->object;
				break;
			}
		}
	}
	if (!peer) {
		unlabeled = selinux_xfrm_unlabeled_object(
			sksec->creator_cred,
			GFP_ATOMIC);
		if (IS_ERR(unlabeled))
			return PTR_ERR(unlabeled);
		peer = unlabeled;
	}

	/* This check even when there's no association involved is intended,
	 * according to Trent Jaeger, to make sure a process can't engage in
	 * non-IPsec communication unless explicitly allowed by policy. */
	i = selinux_xfrm_compat_has_perm(
		sksec,
		peer,
		ASSOCIATION__RECVFROM,
		ad);
	selinux_object_identity_put(unlabeled);
	return i;
}

/*
 * POSTROUTE_LAST hook's XFRM processing:
 * If we have no security association, then we need to determine
 * whether the socket is allowed to send to an unlabelled destination.
 * If we do have a authorizable security association, then it has already been
 * checked in the selinux_xfrm_state_pol_flow_match hook above.
 */
int selinux_xfrm_postroute_last(struct sk_security_struct *sksec,
				struct sk_buff *skb,
				struct common_audit_data *ad, u8 proto)
{
	struct selinux_object_identity *unlabeled;
	struct dst_entry *dst;
	int rc;

	switch (proto) {
	case IPPROTO_AH:
	case IPPROTO_ESP:
	case IPPROTO_COMP:
		/* We should have already seen this packet once before it
		 * underwent xfrm(s). No need to subject it to the unlabeled
		 * check. */
		return 0;
	default:
		break;
	}

	dst = skb_dst(skb);
	if (dst) {
		struct dst_entry *iter;

		for (iter = dst; iter != NULL; iter = xfrm_dst_child(iter)) {
			struct xfrm_state *x = iter->xfrm;

			if (x && selinux_authorizable_xfrm(x))
				return 0;
		}
	}

	/* This check even when there's no association involved is intended,
	 * according to Trent Jaeger, to make sure a process can't engage in
	 * non-IPsec communication unless explicitly allowed by policy. */
	unlabeled = selinux_xfrm_unlabeled_object(
		sksec->creator_cred,
		GFP_ATOMIC);
	if (IS_ERR(unlabeled))
		return PTR_ERR(unlabeled);
	rc = selinux_xfrm_compat_has_perm(
		sksec,
		unlabeled,
		ASSOCIATION__SENDTO,
		ad);
	selinux_object_identity_put(unlabeled);
	return rc;
}
