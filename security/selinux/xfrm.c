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

#include "avc.h"
#include "global_sidtab.h"
#include "label_view.h"
#include "net_assertion.h"
#include "objsec.h"
#include "xfrm.h"

#ifdef CONFIG_SECURITY_NETWORK_XFRM

/* Labeled XFRM instance counter */
atomic_t selinux_xfrm_refcount __read_mostly = ATOMIC_INIT(0);

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

static struct selinux_xfrm_sec_ctx *
selinux_xfrm_sec_ctx(struct xfrm_sec_ctx *ctx)
{
	return (struct selinux_xfrm_sec_ctx *)((u8 *)ctx -
		offsetof(struct selinux_xfrm_sec_ctx, ctx));
}

static struct xfrm_sec_ctx *
selinux_xfrm_public_ctx(struct selinux_xfrm_sec_ctx *sec)
{
	return (struct xfrm_sec_ctx *)sec->ctx;
}

static struct selinux_xfrm_sec_ctx *
selinux_xfrm_sec_ctx_alloc(u32 str_len, gfp_t gfp)
{
	size_t public_len = size_add(sizeof(struct xfrm_sec_ctx), str_len);

	if (public_len == SIZE_MAX)
		return NULL;
	return kmalloc_flex(struct selinux_xfrm_sec_ctx, ctx, public_len, gfp);
}

static int
selinux_xfrm_validate_provenance(const struct selinux_label_view *view,
				 const struct selinux_label_ref *label, u32 sid)
{
	if (!view || !view->origin_domain || !view->outer_domain || !label)
		return -EACCES;
#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		struct selinux_label_resolution resolution;

		return selinux_label_view_resolve_chain(view, label, sid,
							&resolution);
	}
#else
	if (view->origin_domain != label->domain ||
	    view->origin_domain != view->outer_domain)
		return -EACCES;
	return 0;
#endif
}

static struct selinux_net_assertion *
selinux_xfrm_assertion_alloc(struct selinux_state *state,
			     const struct selinux_label_view *view,
			     struct selinux_global_sid_handle *producer,
			     u32 sid,
			     const char *context, u32 context_len, gfp_t gfp)
{
	enum selinux_net_assertion_source source =
		SELINUX_NET_ASSERTION_SOURCE_XFRM;
	struct selinux_net_assertion *assertion;
	struct selinux_label_ref *label;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *handle = producer;
#endif
	int rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
	/* Numeric reacquisition cannot prove continuity with the producer. */
	if (!handle)
		return ERR_PTR(-EACCES);
	if (global_sid_handle_sid(handle) != sid) {
		return ERR_PTR(-ESTALE);
	}
	label = global_sid_handle_label_get(handle);
#else
	if (!state || !state->label_domain || !context || !context_len)
		return ERR_PTR(-EINVAL);
	label = selinux_label_ref_intern(state->label_domain, context,
					 context_len, gfp);
#endif
	if (IS_ERR(label))
		assertion = ERR_CAST(label);
	else if (!label)
		assertion = ERR_PTR(-ESTALE);
	else {
		rc = selinux_xfrm_validate_provenance(view, label, sid);
		if (rc)
			assertion = ERR_PTR(rc);
		else {
#ifdef CONFIG_SECURITY_SELINUX_NS
			assertion = selinux_net_assertion_alloc_handle(
				handle, SECCLASS_ASSOCIATION, source, 0, gfp);
#else
			assertion = selinux_net_assertion_alloc(
				label, sid, SECCLASS_ASSOCIATION, source, 0, gfp);
#endif
		}
		selinux_label_ref_put(label);
	}
	return assertion;
}

static void
selinux_xfrm_sec_ctx_set_metadata(struct selinux_xfrm_sec_ctx *sec,
				  struct selinux_state *state,
				  const struct selinux_label_view *view,
				  struct selinux_net_assertion *assertion,
				  struct selinux_net_provenance *provenance)
{
	sec->state = state;
	sec->view = view;
	sec->assertion = assertion;
	sec->provenance = provenance;
}

static bool
selinux_xfrm_assertion_sid_valid(const struct selinux_net_assertion *assertion,
				 u32 sid)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_label_ref *canonical;
	bool valid;
#endif

	if (!assertion || !assertion->label || assertion->sid != sid)
		return false;
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!assertion->sid_handle ||
	    global_sid_handle_sid(assertion->sid_handle) != sid)
		return false;
	canonical = global_sid_handle_label_get(assertion->sid_handle);
	valid = canonical == assertion->label;
	selinux_label_ref_put(canonical);
	return valid;
#else
	return true;
#endif
}

static int selinux_xfrm_ctx_metadata(struct xfrm_sec_ctx *ctx,
				     struct selinux_xfrm_sec_ctx **secp)
{
	struct selinux_xfrm_sec_ctx *sec;

	if (!selinux_authorizable_ctx(ctx) || !secp)
		return -EINVAL;
	sec = selinux_xfrm_sec_ctx(ctx);
	if (!sec->state || !sec->state->label_domain || !sec->view ||
	    !sec->view->id || !sec->view->generation ||
	    !sec->view->owner_userns || !sec->view->origin_domain ||
	    !sec->view->outer_domain ||
	    sec->view->flags & SELINUX_LABEL_VIEW_ORIGIN_UNRESOLVED ||
	    !selinux_xfrm_assertion_sid_valid(sec->assertion, ctx->ctx_sid) ||
	    !sec->provenance || sec->provenance->state != sec->state ||
	    sec->provenance->view != sec->view ||
	    sec->provenance->subject != sec->assertion ||
	    sec->assertion->semantic_class != SECCLASS_ASSOCIATION ||
	    sec->assertion->source != SELINUX_NET_ASSERTION_SOURCE_XFRM)
		return -EACCES;
	*secp = sec;
	return 0;
}

static struct selinux_label_ref *
selinux_xfrm_canonicalize_sid(struct selinux_state *state, u32 sid)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!sid)
		return ERR_PTR(-EINVAL);
	return global_sid_to_label_ref(sid);
#else
	struct selinux_label_ref *label;
	const char *context = NULL;
	u32 context_len = 0;
	int rc;

	if (!state || !state->label_domain || !sid)
		return ERR_PTR(-EINVAL);
	rcu_read_lock();
	rc = security_sid_to_context(state, sid, &context, &context_len);
	if (rc)
		label = ERR_PTR(rc);
	else if (!context || !context_len)
		label = ERR_PTR(-EINVAL);
	else
		label = selinux_label_ref_intern(state->label_domain, context,
						 context_len, GFP_ATOMIC);
	rcu_read_unlock();
	return label;
#endif
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static int
selinux_xfrm_validate_boundary(const struct selinux_label_view *view,
			       const struct selinux_label_domain *child)
{
	struct selinux_label_map *captured, *current_map;
	u16 depth = child->depth;
	int rc = -ESTALE;

	if (!depth || depth > view->map_count)
		return -ESTALE;
	captured = view->maps[depth - 1];
	if (!captured || !READ_ONCE(captured->generation))
		return -ESTALE;
	/* Pairs with smp_store_release() in selinux_label_map_seal(). */
	if (!smp_load_acquire(&captured->sealed) ||
	    captured->child_domain_id != child->id ||
	    captured->parent != child->parent)
		return -ESTALE;
	current_map = selinux_label_domain_get_map(child);
	if (current_map == captured)
		rc = 0;
	selinux_label_map_put(current_map);
	return rc;
}
#endif

static int
selinux_xfrm_view_domains(const struct selinux_xfrm_sec_ctx *sec,
			  struct selinux_label_resolution *resolution)
{
	const struct selinux_label_domain *domain;
	struct selinux_state *state;
	u16 max_depth;

	if (!sec || !resolution || !sec->state || !sec->view)
		return -EINVAL;
	state = sec->state;
	domain = state->label_domain;
	max_depth = state->depth;
	if (!domain || max_depth > SELINUX_LABEL_RESOLUTION_MAX_DEPTH ||
	    domain->depth != max_depth ||
	    sec->view->origin_domain != domain ||
	    sec->view->map_count != max_depth)
		return -EXDEV;

	memset(resolution, 0, sizeof(*resolution));
	resolution->max_depth = max_depth;
	for (;;) {
		u16 depth = state->depth;

		if (!domain || domain != state->label_domain ||
		    domain->depth != depth || depth > max_depth)
			return -EXDEV;
		resolution->domain_id[depth] = domain->id;
		if (!state->parent) {
			if (depth || domain->parent ||
			    sec->view->outer_domain != domain)
				return -EXDEV;
			break;
		}
		if (!depth || !domain->parent ||
		    state->parent->label_domain != domain->parent ||
		    state->parent->depth != depth - 1)
			return -EXDEV;
#ifdef CONFIG_SECURITY_SELINUX_NS
		if (selinux_xfrm_validate_boundary(sec->view, domain))
			return -ESTALE;
#else
		return -EOPNOTSUPP;
#endif
		state = state->parent;
		domain = domain->parent;
	}
	return 0;
}

static int
selinux_xfrm_resolve_label(const struct selinux_xfrm_sec_ctx *sec,
			   const struct selinux_label_ref *label, u32 sid,
			   struct selinux_label_resolution *resolution)
{
	struct selinux_label_ref *current_label;
	u32 current_sid = sid;
	int rc = 0;

	if (!sec || !label || !sid || !resolution ||
	    resolution->max_depth != sec->state->depth)
		return -EINVAL;
	if ((label->domain->flags & SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) &&
	    sid <= SECINITSID_NUM) {
		int depth;

		for (depth = 0; depth <= resolution->max_depth; depth++)
			resolution->sid[depth] = sid;
		return 0;
	}
	if (label->domain != sec->view->origin_domain)
		return -EXDEV;

	current_label = selinux_label_ref_get((struct selinux_label_ref *)label);
	resolution->sid[current_label->domain->depth] = current_sid;
	while (current_label->domain->parent) {
#ifdef CONFIG_SECURITY_SELINUX_NS
		enum selinux_label_map_direction direction =
			SELINUX_LABEL_MAP_CHILD_TO_PARENT;
		struct selinux_label_ref *canonical;
		struct selinux_label_ref *next;
		struct selinux_label_map *map;
		u16 depth = current_label->domain->depth;

		if (!depth || depth > sec->view->map_count) {
			rc = -ESTALE;
			break;
		}
		map = sec->view->maps[depth - 1];
		rc = selinux_label_map_resolve(map, direction, current_label,
					       current_sid, &current_sid, &next);
		if (rc)
			break;
		if (!next || next->domain != current_label->domain->parent ||
		    resolution->domain_id[next->domain->depth] !=
			    next->domain->id) {
			selinux_label_ref_put(next);
			rc = -EXDEV;
			break;
		}
		canonical = global_sid_to_label_ref(current_sid);
		if (IS_ERR(canonical)) {
			selinux_label_ref_put(next);
			rc = PTR_ERR(canonical);
			break;
		}
		if (canonical != next) {
			selinux_label_ref_put(canonical);
			selinux_label_ref_put(next);
			rc = -ESTALE;
			break;
		}
		selinux_label_ref_put(canonical);
		selinux_label_ref_put(current_label);
		current_label = next;
		resolution->sid[current_label->domain->depth] = current_sid;
#else
		rc = -EOPNOTSUPP;
		break;
#endif
	}
	if (!rc && current_label->domain != sec->view->outer_domain)
		rc = -EXDEV;
	selinux_label_ref_put(current_label);
	return rc;
}

static int
selinux_xfrm_resolve_sid(const struct selinux_xfrm_sec_ctx *sec, u32 sid,
			 const struct selinux_label_ref *expected,
			 const struct selinux_label_resolution *domains,
			 struct selinux_label_resolution *resolution,
			 struct selinux_label_ref **canonicalp)
{
	struct selinux_label_ref *canonical;
	int rc;

	canonical = selinux_xfrm_canonicalize_sid(sec->state, sid);
	if (IS_ERR(canonical))
		return PTR_ERR(canonical);
	if (expected && canonical != expected) {
		rc = -ESTALE;
		goto out;
	}
	*resolution = *domains;
	rc = selinux_xfrm_resolve_label(sec, canonical, sid, resolution);
	if (!rc && canonicalp) {
		*canonicalp = canonical;
		return 0;
	}
out:
	selinux_label_ref_put(canonical);
	return rc;
}

static int
selinux_xfrm_has_perm_chain(const struct selinux_xfrm_sec_ctx *sec,
			    const struct selinux_label_resolution *source,
			    const struct selinux_label_resolution *target,
			    u32 requested)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	return selinux_state_resolutions_has_perm(
		sec->state, source, target, SECCLASS_ASSOCIATION, requested,
		sec->assertion->label, sec->view, sec->assertion->source, NULL);
#else
	struct selinux_state *state = sec->state;
	int rc;

	do {
		u16 depth = state->depth;

		if (depth > source->max_depth || depth > target->max_depth ||
		    source->domain_id[depth] != state->label_domain->id ||
		    target->domain_id[depth] != state->label_domain->id ||
		    !source->sid[depth] || !target->sid[depth])
			return -EXDEV;
		rc = avc_has_perm(state, source->sid[depth], target->sid[depth],
				  SECCLASS_ASSOCIATION, requested, NULL);
		if (rc)
			return rc;
		state = state->parent;
	} while (state);
	return 0;
#endif
}

static bool selinux_xfrm_same_view(const struct selinux_xfrm_sec_ctx *first,
				   const struct selinux_xfrm_sec_ctx *second)
{
	const struct selinux_label_view *a = first->view;
	const struct selinux_label_view *b = second->view;
#ifdef CONFIG_SECURITY_SELINUX_NS
	int i;
#endif

	if (first->state != second->state || a->flags != b->flags ||
	    a->owner_userns != b->owner_userns ||
	    a->origin_domain != b->origin_domain ||
	    a->outer_domain != b->outer_domain || a->map_count != b->map_count)
		return false;
#ifdef CONFIG_SECURITY_SELINUX_NS
	for (i = 0; i < a->map_count; i++) {
		if (a->maps[i] != b->maps[i] || !a->maps[i] ||
		    a->maps[i]->id != b->maps[i]->id ||
		    a->maps[i]->generation != b->maps[i]->generation)
			return false;
	}
#endif
	return true;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static struct req_security_struct *
selinux_xfrm_req_security(const struct request_sock *req)
{
	if (!req || !req->security)
		return NULL;
	return req->security + selinux_blob_sizes.lbs_req;
}

static bool selinux_xfrm_provenance_matches_policy(
	const struct selinux_net_provenance *provenance,
	const struct selinux_xfrm_sec_ctx *policy)
{
	const struct selinux_label_view *a, *b;
	int i;

	if (!provenance || !provenance->state || !provenance->view ||
	    !provenance->subject || !provenance->subject->label || !policy ||
	    provenance->state != policy->state)
		return false;
	a = provenance->view;
	b = policy->view;
	if (!b || a->flags != b->flags || a->owner_userns != b->owner_userns ||
	    a->origin_domain != b->origin_domain ||
	    a->outer_domain != b->outer_domain || a->map_count != b->map_count)
		return false;
	for (i = 0; i < a->map_count; i++) {
		if (a->maps[i] != b->maps[i] || !a->maps[i] ||
		    a->maps[i]->id != b->maps[i]->id ||
		    a->maps[i]->generation != b->maps[i]->generation)
			return false;
	}
	return true;
}

static struct selinux_net_provenance *
selinux_xfrm_flow_origin_get(const struct xfrm_flow_origin *origin,
			       const struct selinux_xfrm_sec_ctx *policy,
			       u32 sid)
{
	struct selinux_net_provenance *provenance = NULL;

	if (!origin || !policy || !sid)
		return ERR_PTR(-ESTALE);
	switch (origin->kind) {
	case XFRM_FLOW_ORIGIN_SOCK: {
		const struct sk_security_struct *sksec;

		if (!origin->sk)
			return ERR_PTR(-ESTALE);
		sksec = selinux_sock(origin->sk);
		provenance = selinux_net_provenance_get_rcu(&sksec->provenance);
		if (!provenance || READ_ONCE(sksec->sid) != sid ||
		    rcu_access_pointer(sksec->provenance) != provenance)
			goto stale;
		break;
	}
	case XFRM_FLOW_ORIGIN_REQUEST: {
		const struct req_security_struct *reqsec;

		if (!origin->req || READ_ONCE(origin->req->secid) != sid)
			return ERR_PTR(-ESTALE);
		reqsec = selinux_xfrm_req_security(origin->req);
		if (!reqsec)
			return ERR_PTR(-ESTALE);
		provenance = selinux_net_provenance_get_rcu(&reqsec->provenance);
		if (!provenance ||
		    rcu_access_pointer(reqsec->provenance) != provenance)
			goto stale;
		break;
	}
	case XFRM_FLOW_ORIGIN_SKB: {
		int rc;

		if (!origin->skb)
			return ERR_PTR(-ESTALE);
		rc = selinux_xfrm_skb_provenance(
			(struct sk_buff *)origin->skb, &provenance);
		if (rc)
			return ERR_PTR(rc == -EACCES ? -ESTALE : rc);
		if (!provenance)
			return ERR_PTR(-ESTALE);
		break;
	}
	case XFRM_FLOW_ORIGIN_NONE:
	default:
		return ERR_PTR(-ESTALE);
	}

	if (!provenance->subject || provenance->subject->sid != sid ||
	    !provenance->subject->sid_handle ||
	    global_sid_handle_sid(provenance->subject->sid_handle) != sid ||
	    !selinux_xfrm_provenance_matches_policy(provenance, policy))
		goto stale;
	return provenance;

stale:
	selinux_net_provenance_put(provenance);
	return ERR_PTR(-ESTALE);
}
#endif

/*
 * Allocates a xfrm_sec_state and populates it using the supplied security
 * xfrm_user_sec_ctx context.
 */
static int selinux_xfrm_alloc_user(struct selinux_state *state,
				   const struct cred *cred,
				   struct xfrm_sec_ctx **ctxp,
				   struct xfrm_user_sec_ctx *uctx,
				   gfp_t gfp)
{
	struct selinux_label_domain *outer_domain;
	struct selinux_net_assertion *assertion = NULL;
	struct selinux_net_provenance *provenance = NULL;
	const struct selinux_label_view *view = NULL;
	struct selinux_xfrm_sec_ctx *sec = NULL;
	struct selinux_global_sid_handle *sid_handle = NULL;
	struct xfrm_sec_ctx *ctx;
	u32 str_len;
	int rc;

	if (!state || !cred || !state->label_domain || !init_selinux_state ||
	    !init_selinux_state->label_domain || !ctxp || !uctx ||
	    uctx->ctx_doi != XFRM_SC_DOI_LSM ||
	    uctx->ctx_alg != XFRM_SC_ALG_SELINUX)
		return -EINVAL;
	str_len = uctx->ctx_len;
	if (str_len >= PAGE_SIZE)
		return -ENOMEM;

	state = get_selinux_state(state);
	outer_domain = init_selinux_state->label_domain;
	view = selinux_identity_view_alloc_gfp(cred->user_ns,
					       state->label_domain, outer_domain,
					       gfp);
	if (IS_ERR(view)) {
		rc = PTR_ERR(view);
		view = NULL;
		goto err;
	}
	sec = selinux_xfrm_sec_ctx_alloc(str_len + 1, gfp);
	if (!sec) {
		rc = -ENOMEM;
		goto err;
	}
	ctx = selinux_xfrm_public_ctx(sec);

	ctx->ctx_doi = XFRM_SC_DOI_LSM;
	ctx->ctx_alg = XFRM_SC_ALG_SELINUX;
	ctx->ctx_len = str_len + 1;
	memcpy(ctx->ctx_str, &uctx[1], str_len);
	ctx->ctx_str[str_len] = '\0';
#ifdef CONFIG_SECURITY_SELINUX_NS
	sid_handle = security_context_to_global_handle(
		state, ctx->ctx_str, str_len, &ctx->ctx_sid, gfp);
	if (IS_ERR(sid_handle)) {
		rc = PTR_ERR(sid_handle);
		sid_handle = NULL;
		goto err;
	}
#else
	rc = security_context_to_sid(state, ctx->ctx_str, str_len,
				     &ctx->ctx_sid, gfp);
	if (rc)
		goto err;
#endif

	assertion = selinux_xfrm_assertion_alloc(state, view, sid_handle,
						 ctx->ctx_sid, ctx->ctx_str,
						 ctx->ctx_len, gfp);
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(sid_handle);
	sid_handle = NULL;
#endif
	if (IS_ERR(assertion)) {
		rc = PTR_ERR(assertion);
		assertion = NULL;
		goto err;
	}
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = cred_label_has_perm(cred, ctx->ctx_sid, assertion->label, view,
				 SECCLASS_ASSOCIATION,
				 ASSOCIATION__SETCONTEXT, NULL);
#else
	rc = cred_tsid_has_perm(cred, ctx->ctx_sid, SECCLASS_ASSOCIATION,
				ASSOCIATION__SETCONTEXT, NULL);
#endif
	if (rc)
		goto err;

	provenance = selinux_net_provenance_alloc(state, view, assertion, gfp);
	if (IS_ERR(provenance)) {
		rc = PTR_ERR(provenance);
		provenance = NULL;
		goto err;
	}
	selinux_xfrm_sec_ctx_set_metadata(sec, state, view, assertion, provenance);
	*ctxp = ctx;
	atomic_inc(&selinux_xfrm_refcount);
	return 0;

err:
#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(sid_handle);
#endif
	selinux_net_provenance_put(provenance);
	selinux_net_assertion_put(assertion);
	kfree(sec);
	selinux_label_view_put(view);
	put_selinux_state(state);
	return rc;
}

/*
 * Free the xfrm_sec_ctx structure.
 */
static void selinux_xfrm_free(struct xfrm_sec_ctx *ctx)
{
	struct selinux_xfrm_sec_ctx *sec;

	if (!ctx)
		return;

	sec = selinux_xfrm_sec_ctx(ctx);
	atomic_dec(&selinux_xfrm_refcount);
	selinux_net_provenance_put(sec->provenance);
	selinux_net_assertion_put(sec->assertion);
	selinux_label_view_put(sec->view);
	put_selinux_state(sec->state);
	kfree(sec);
}

/*
 * Authorize the deletion of a labeled SA or policy rule.
 */
static int selinux_xfrm_delete(struct xfrm_sec_ctx *ctx)
{
	struct selinux_xfrm_sec_ctx *sec;
	int rc;

	if (!ctx)
		return 0;
	rc = selinux_xfrm_ctx_metadata(ctx, &sec);
	if (rc)
		return rc;

#ifdef CONFIG_SECURITY_SELINUX_NS
	return cred_label_has_perm(current_cred(), ctx->ctx_sid,
				   sec->assertion->label, sec->view,
				   SECCLASS_ASSOCIATION,
				   ASSOCIATION__SETCONTEXT, NULL);
#else
	return cred_tsid_has_perm(current_cred(), ctx->ctx_sid,
				  SECCLASS_ASSOCIATION,
				  ASSOCIATION__SETCONTEXT, NULL);
#endif
}

/*
 * LSM hook implementation that authorizes that a flow can use a xfrm policy
 * rule.
 */
int selinux_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx, u32 fl_secid,
			       const struct xfrm_flow_origin *origin)
{
	struct selinux_label_resolution association, domains, flow, post;
	struct selinux_xfrm_sec_ctx *sec;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_net_provenance *flow_provenance;
#endif
	int rc;

	/* All flows should be treated as polmatch'ing an otherwise applicable
	 * "non-labeled" policy. This would prevent inadvertent "leaks". */
	if (!ctx)
		return 0;

	rc = selinux_xfrm_ctx_metadata(ctx, &sec);
	if (rc)
		return rc;
	rc = selinux_xfrm_view_domains(sec, &domains);
	if (rc)
		return rc;
#ifdef CONFIG_SECURITY_SELINUX_NS
	flow_provenance = selinux_xfrm_flow_origin_get(origin, sec, fl_secid);
	if (IS_ERR(flow_provenance))
		return PTR_ERR(flow_provenance);
	flow = domains;
	rc = selinux_xfrm_resolve_label(sec, flow_provenance->subject->label,
					fl_secid, &flow);
#else
	rc = selinux_xfrm_resolve_sid(sec, fl_secid, NULL, &domains, &flow,
				      NULL);
#endif
	if (rc)
		goto out_flow;
	rc = selinux_xfrm_resolve_sid(sec, ctx->ctx_sid,
				      sec->assertion->label, &domains,
				      &association, NULL);
	if (rc)
		goto out_flow;
	rc = selinux_xfrm_has_perm_chain(sec, &flow, &association,
					 ASSOCIATION__POLMATCH);
	if (!rc)
		rc = selinux_xfrm_view_domains(sec, &post);
	if (rc == -EACCES)
		rc = -ESRCH;

out_flow:
#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_net_provenance_put(flow_provenance);
#endif
	return rc;
}

/*
 * LSM hook implementation that authorizes that a state matches
 * the given policy, flow combo.
 */
int selinux_xfrm_state_pol_flow_match(struct xfrm_state *x,
				      struct xfrm_policy *xp,
				      const struct flowi_common *flic,
				      const struct xfrm_flow_origin *origin)
{
	struct selinux_label_resolution association, domains, flow, post;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_net_provenance *flow_provenance = NULL;
#else
	struct selinux_label_ref *flow_label = NULL;
#endif
	struct selinux_label_ref *policy_label;
	struct selinux_xfrm_sec_ctx *policy_sec, *state_sec;
	int rc;

	if (!x || !xp || !flic)
		return 0;
	if (!xp->security) {
		/* Unlabeled policy and labeled SA cannot match. */
		return x->security ? 0 : 1;
	}
	if (!x->security || !selinux_authorizable_xfrm(x))
		return 0;
	rc = selinux_xfrm_ctx_metadata(xp->security, &policy_sec);
	if (rc)
		return 0;
	rc = selinux_xfrm_ctx_metadata(x->security, &state_sec);
	if (rc || !selinux_xfrm_same_view(policy_sec, state_sec))
		return 0;

	/* POLMATCH permits a policy range, so its label need not equal the SA. */
	policy_label = selinux_xfrm_canonicalize_sid(policy_sec->state, xp->security->ctx_sid);
	if (IS_ERR(policy_label))
		return 0;
	if (policy_label != policy_sec->assertion->label) {
		selinux_label_ref_put(policy_label);
		return 0;
	}
	selinux_label_ref_put(policy_label);

	rc = selinux_xfrm_view_domains(state_sec, &domains);
	if (rc)
		return 0;
#ifdef CONFIG_SECURITY_SELINUX_NS
	flow_provenance = selinux_xfrm_flow_origin_get(
		origin, state_sec, flic->flowic_secid);
	if (IS_ERR(flow_provenance))
		return 0;
	flow = domains;
	rc = selinux_xfrm_resolve_label(
		state_sec, flow_provenance->subject->label,
		flic->flowic_secid, &flow);
#else
	rc = selinux_xfrm_resolve_sid(state_sec, flic->flowic_secid, NULL,
				      &domains, &flow, &flow_label);
#endif
	if (rc)
		goto out_label;
	rc = selinux_xfrm_resolve_sid(state_sec, x->security->ctx_sid,
				      state_sec->assertion->label, &domains,
				      &association, NULL);
	if (rc)
		goto out_label;
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (flow_provenance->subject->label != state_sec->assertion->label ||
#else
	if (flow_label != state_sec->assertion->label ||
#endif
	    flic->flowic_secid != x->security->ctx_sid) {
		rc = -EXDEV;
		goto out_label;
	}
	rc = selinux_xfrm_has_perm_chain(state_sec, &flow, &association,
					 ASSOCIATION__SENDTO);
	if (!rc)
		rc = selinux_xfrm_view_domains(state_sec, &post);

out_label:
#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_net_provenance_put(flow_provenance);
#else
	selinux_label_ref_put(flow_label);
#endif
	return rc ? 0 : 1;
}

static u32 selinux_xfrm_skb_sid_egress(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct xfrm_state *x;

	if (dst == NULL)
		return SECSID_NULL;
	x = dst->xfrm;
	if (x == NULL || !selinux_authorizable_xfrm(x))
		return SECSID_NULL;

	return x->security->ctx_sid;
}

static int selinux_xfrm_skb_sid_ingress(struct sk_buff *skb,
					u32 *sid, int ckall)
{
	u32 sid_session = SECSID_NULL;
	struct sec_path *sp = skb_sec_path(skb);

	if (sp) {
		int i;

		for (i = sp->len - 1; i >= 0; i--) {
			struct xfrm_state *x = sp->xvec[i];
			if (selinux_authorizable_xfrm(x)) {
				struct xfrm_sec_ctx *ctx = x->security;

				if (sid_session == SECSID_NULL) {
					sid_session = ctx->ctx_sid;
					if (!ckall)
						goto out;
				} else if (sid_session != ctx->ctx_sid) {
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
	return selinux_xfrm_skb_sid_ingress(skb, sid, ckall);
}

int selinux_xfrm_skb_sid(struct sk_buff *skb, u32 *sid)
{
	int rc;

	rc = selinux_xfrm_skb_sid_ingress(skb, sid, 0);
	if (rc == 0 && *sid == SECSID_NULL)
		*sid = selinux_xfrm_skb_sid_egress(skb);

	return rc;
}

/*
 * Return the immutable provenance of the packet's labeled XFRM chain.  All
 * labeled transforms must describe the same canonical assertion and view;
 * otherwise no policy-independent peer identity exists and the packet fails
 * closed.  The returned reference is strong and requires put().
 */
static int selinux_xfrm_skb_provenance_lookup(
	struct sk_buff *skb, struct selinux_net_provenance **provenancep)
{
	struct selinux_xfrm_sec_ctx *selected = NULL;
	struct sec_path *sp;
	int i, rc;

	if (!provenancep)
		return -EINVAL;
	*provenancep = NULL;
	if (!skb)
		return 0;

	sp = skb_sec_path(skb);
	if (sp) {
		for (i = sp->len - 1; i >= 0; i--) {
			struct selinux_xfrm_sec_ctx *sec;
			struct xfrm_state *x = sp->xvec[i];

			if (!x || !selinux_authorizable_xfrm(x))
				continue;
			rc = selinux_xfrm_ctx_metadata(x->security, &sec);
			if (rc)
				return rc;
			if (selected &&
			    (selected->assertion->label != sec->assertion->label ||
			     !selinux_xfrm_same_view(selected, sec)))
				return -EACCES;
			selected = sec;
		}
	}

	if (!selected)
		return 0;

	*provenancep = selinux_net_provenance_get(selected->provenance);
	return *provenancep ? 0 : -EACCES;
}

int selinux_xfrm_skb_provenance_ingress(
	struct sk_buff *skb, struct selinux_net_provenance **provenancep)
{
	return selinux_xfrm_skb_provenance_lookup(skb, provenancep);
}

/*
 * Return the immutable provenance selected for output.  POSTROUTE must inspect
 * the entire dst/XFRM chain (not skb's ingress sec_path and not only the first
 * transform), matching selinux_xfrm_postroute_last()'s definition of a labeled
 * route.  Multiple labeled transforms must agree on canonical identity.
 */
int selinux_xfrm_skb_provenance_egress(
	struct sk_buff *skb, struct selinux_net_provenance **provenancep)
{
	struct selinux_xfrm_sec_ctx *selected = NULL;
	struct dst_entry *dst, *iter;
	int rc;

	if (!provenancep)
		return -EINVAL;
	*provenancep = NULL;
	if (!skb)
		return 0;
	dst = skb_dst(skb);
	for (iter = dst; iter; iter = xfrm_dst_child(iter)) {
		struct selinux_xfrm_sec_ctx *sec;
		struct xfrm_state *x = iter->xfrm;

		if (!x || !selinux_authorizable_xfrm(x))
			continue;
		rc = selinux_xfrm_ctx_metadata(x->security, &sec);
		if (rc)
			return rc;
		if (selected &&
		    (selected->assertion->label != sec->assertion->label ||
		     !selinux_xfrm_same_view(selected, sec)))
			return -EACCES;
		selected = sec;
	}
	if (!selected)
		return 0;
	*provenancep = selinux_net_provenance_get(selected->provenance);
	return *provenancep ? 0 : -EACCES;
}

int selinux_xfrm_skb_provenance(
	struct sk_buff *skb, struct selinux_net_provenance **provenancep)
{
	int rc;

	rc = selinux_xfrm_skb_provenance_lookup(skb, provenancep);
	if (rc || *provenancep)
		return rc;
	return selinux_xfrm_skb_provenance_egress(skb, provenancep);
}

/*
 * LSM hook implementation that allocs and transfers uctx spec to xfrm_policy.
 */
int selinux_xfrm_policy_alloc(struct xfrm_sec_ctx **ctxp,
			      struct xfrm_user_sec_ctx *uctx,
			      gfp_t gfp)
{
	const struct cred *cred = current_cred();

	return selinux_xfrm_alloc_user(cred_selinux_state(cred), cred, ctxp,
				       uctx, gfp);
}

/*
 * LSM hook implementation that copies security data structure from old to new
 * for policy cloning.
 */
int selinux_xfrm_policy_clone(struct xfrm_sec_ctx *old_ctx,
			      struct xfrm_sec_ctx **new_ctxp)
{
	struct selinux_net_assertion *assertion;
	struct selinux_net_provenance *provenance;
	const struct selinux_label_view *view;
	struct selinux_xfrm_sec_ctx *old_sec, *new_sec;
	struct selinux_state *state;
	struct xfrm_sec_ctx *new_ctx;

	if (!old_ctx)
		return 0;
	if (!new_ctxp)
		return -EINVAL;
	if (selinux_xfrm_ctx_metadata(old_ctx, &old_sec))
		return -EACCES;

	new_sec = selinux_xfrm_sec_ctx_alloc(old_ctx->ctx_len, GFP_ATOMIC);
	if (!new_sec)
		return -ENOMEM;
	new_ctx = selinux_xfrm_public_ctx(new_sec);
	memcpy(new_ctx, old_ctx, sizeof(*old_ctx) + old_ctx->ctx_len);
	state = get_selinux_state(old_sec->state);
	view = selinux_label_view_get(old_sec->view);
	assertion = selinux_net_assertion_get(old_sec->assertion);
	if (!assertion) {
		selinux_label_view_put(view);
		put_selinux_state(state);
		kfree(new_sec);
		return -EACCES;
	}
	provenance = selinux_net_provenance_get(old_sec->provenance);
	if (!provenance) {
		selinux_net_assertion_put(assertion);
		selinux_label_view_put(view);
		put_selinux_state(state);
		kfree(new_sec);
		return -EACCES;
	}
	selinux_xfrm_sec_ctx_set_metadata(new_sec, state, view, assertion,
					 provenance);
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
	const struct cred *cred = current_cred();

	if (!x)
		return -EINVAL;
	return selinux_xfrm_alloc_user(cred_selinux_state(cred), cred,
				       &x->security, uctx, GFP_KERNEL);
}

/*
 * LSM hook implementation that allocates a xfrm_sec_state and populates based
 * on a secid.
 */
int selinux_xfrm_state_alloc_acquire(
	struct xfrm_state *x, struct xfrm_sec_ctx *polsec, u32 secid,
	const struct xfrm_flow_origin *origin)
{
	struct selinux_net_assertion *assertion = NULL;
	struct selinux_net_provenance *provenance = NULL;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_net_provenance *flow_provenance = NULL;
#else
	const char *ctx_str = NULL;
#endif
	const struct selinux_label_view *view = NULL;
	struct selinux_xfrm_sec_ctx *pol_sec, *sec = NULL;
	struct selinux_state *state = NULL;
	struct xfrm_sec_ctx *ctx;
	u32 str_len;
	int rc;

	if (!polsec)
		return 0;
	if (!x || secid == 0)
		return -EINVAL;
	if (selinux_xfrm_ctx_metadata(polsec, &pol_sec))
		return -EACCES;

	state = get_selinux_state(pol_sec->state);
	view = selinux_label_view_get(pol_sec->view);

#ifdef CONFIG_SECURITY_SELINUX_NS
	flow_provenance = selinux_xfrm_flow_origin_get(origin, pol_sec, secid);
	if (IS_ERR(flow_provenance)) {
		rc = PTR_ERR(flow_provenance);
		flow_provenance = NULL;
		goto out;
	}
	str_len = flow_provenance->subject->label->context_len;
	if (!str_len || str_len > U16_MAX) {
		rc = -EOVERFLOW;
		goto out;
	}
#else
	rcu_read_lock();
	rc = security_sid_to_context(state, secid, &ctx_str, &str_len);
	if (rc)
		goto out_unlock;
	if (!ctx_str || !str_len || str_len > U16_MAX) {
		rc = -EOVERFLOW;
		goto out_unlock;
	}
#endif

	sec = selinux_xfrm_sec_ctx_alloc(str_len, GFP_ATOMIC);
	if (!sec) {
		rc = -ENOMEM;
#ifdef CONFIG_SECURITY_SELINUX_NS
		goto out;
#else
		goto out_unlock;
#endif
	}
	ctx = selinux_xfrm_public_ctx(sec);
	ctx->ctx_doi = polsec->ctx_doi;
	ctx->ctx_alg = polsec->ctx_alg;
	ctx->ctx_sid = secid;
	ctx->ctx_len = str_len;
#ifdef CONFIG_SECURITY_SELINUX_NS
	memcpy(ctx->ctx_str, flow_provenance->subject->label->context, str_len);
	assertion = selinux_xfrm_assertion_alloc(
		state, view, flow_provenance->subject->sid_handle, secid,
		ctx->ctx_str, ctx->ctx_len, GFP_ATOMIC);
#else
	memcpy(ctx->ctx_str, ctx_str, str_len);
	rcu_read_unlock();
	assertion = selinux_xfrm_assertion_alloc(state, view, NULL, secid,
						 ctx->ctx_str, ctx->ctx_len,
						 GFP_ATOMIC);
#endif
	if (IS_ERR(assertion)) {
		rc = PTR_ERR(assertion);
		assertion = NULL;
		goto out;
	}
	provenance = selinux_net_provenance_alloc(state, view, assertion,
						 GFP_ATOMIC);
	if (IS_ERR(provenance)) {
		rc = PTR_ERR(provenance);
		provenance = NULL;
		goto out;
	}
	selinux_xfrm_sec_ctx_set_metadata(sec, state, view, assertion, provenance);
	x->security = ctx;
	atomic_inc(&selinux_xfrm_refcount);
#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_net_provenance_put(flow_provenance);
#endif
	return 0;

#ifndef CONFIG_SECURITY_SELINUX_NS
out_unlock:
	rcu_read_unlock();
#endif
out:
#ifdef CONFIG_SECURITY_SELINUX_NS
	selinux_net_provenance_put(flow_provenance);
#endif
	selinux_net_provenance_put(provenance);
	selinux_net_assertion_put(assertion);
	kfree(sec);
	selinux_label_view_put(view);
	put_selinux_state(state);
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
int selinux_xfrm_sock_rcv_skb(struct sk_security_struct *sksec, struct sk_buff *skb,
			      struct common_audit_data *ad)
{
	int i;
	u32 sk_sid = sksec->sid;
	struct sec_path *sp = skb_sec_path(skb);
	u32 peer_sid = SECINITSID_UNLABELED;

	if (sp) {
		for (i = 0; i < sp->len; i++) {
			struct xfrm_state *x = sp->xvec[i];

			if (x && selinux_authorizable_xfrm(x)) {
				struct xfrm_sec_ctx *ctx = x->security;
				peer_sid = ctx->ctx_sid;
				break;
			}
		}
	}

	/* This check even when there's no association involved is intended,
	 * according to Trent Jaeger, to make sure a process can't engage in
	 * non-IPsec communication unless explicitly allowed by policy. */
	return selinux_state_has_perm(sksec->state, sk_sid, peer_sid,
				      SECCLASS_ASSOCIATION,
				      ASSOCIATION__RECVFROM, ad);
}

/*
 * POSTROUTE_LAST hook's XFRM processing:
 * If we have no security association, then we need to determine
 * whether the socket is allowed to send to an unlabelled destination.
 * If we do have a authorizable security association, then it has already been
 * checked in the selinux_xfrm_state_pol_flow_match hook above.
 */
int selinux_xfrm_postroute_last(u32 sk_sid, struct sk_buff *skb,
				struct selinux_state *state,
				struct common_audit_data *ad, u8 proto)
{
	struct dst_entry *dst;

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
	return selinux_state_has_perm(state, sk_sid, SECINITSID_UNLABELED,
				      SECCLASS_ASSOCIATION,
				      ASSOCIATION__SENDTO, ad);
}

#endif /* CONFIG_SECURITY_NETWORK_XFRM */
