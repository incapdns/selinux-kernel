// SPDX-License-Identifier: GPL-2.0-only
/* Immutable provenance-bearing SELinux network label assertions. */

#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/selinux_net.h>
#include <linux/limits.h>
#include <linux/slab.h>

#include "global_sidtab.h"
#include "label_view.h"
#include "net_assertion.h"
#include "security.h"

/*
 * One non-reusable sequence supplies both object identity and generation.
 * Assertions are immutable, so a distinct generation per allocation is
 * sufficient and avoids a second counter that could be consumed partially.
 */
static atomic64_t selinux_net_assertion_sequence = ATOMIC64_INIT(0);
static atomic64_t selinux_net_provenance_sequence = ATOMIC64_INIT(0);

static u64 selinux_net_assertion_next_sequence(void)
{
	s64 old = atomic64_read(&selinux_net_assertion_sequence);

	for (;;) {
		if (unlikely(old == S64_MAX))
			return 0;
		if (atomic64_try_cmpxchg(&selinux_net_assertion_sequence, &old,
					 old + 1))
			return old + 1;
	}
}

static bool
selinux_net_assertion_source_valid(enum selinux_net_assertion_source source)
{
	return source > SELINUX_NET_ASSERTION_SOURCE_INVALID &&
	       source < SELINUX_NET_ASSERTION_SOURCE_MAX;
}

#ifdef CONFIG_SECURITY_SELINUX_NS
static struct selinux_global_sid_handle *
selinux_net_assertion_sid_handle_get(u32 sid,
				     const struct selinux_label_ref *label)
{
	struct selinux_global_sid_handle *handle;
	struct selinux_label_ref *canonical;
	int rc = 0;

	handle = global_sid_handle_get(sid);
	if (IS_ERR(handle))
		return handle;
	if (global_sid_handle_sid(handle) != sid) {
		rc = -ESTALE;
		goto out_handle;
	}
	canonical = global_sid_handle_label_get(handle);
	if (!canonical)
		rc = -ESTALE;
	else if (canonical != label)
		rc = -EINVAL;
	selinux_label_ref_put(canonical);
	if (!rc)
		return handle;

out_handle:
	global_sid_handle_put(handle);
	return ERR_PTR(rc);
}

static bool
selinux_net_assertion_consistent(const struct selinux_net_assertion *assertion)
{
	struct selinux_label_ref *canonical;
	bool consistent;

	if (!assertion || !assertion->label || !assertion->sid_handle ||
	    global_sid_handle_sid(assertion->sid_handle) != assertion->sid)
		return false;
	canonical = global_sid_handle_label_get(assertion->sid_handle);
	consistent = canonical == assertion->label;
	selinux_label_ref_put(canonical);
	return consistent;
}

struct selinux_net_assertion *
selinux_net_assertion_alloc_handle(
	struct selinux_global_sid_handle *handle,
	u16 semantic_class, enum selinux_net_assertion_source source,
	u32 flags, gfp_t gfp)
{
	struct selinux_net_assertion *assertion;
	struct selinux_global_sid_handle *owned;
	struct selinux_label_ref *label;
	u64 sequence;
	u32 sid;

	if (!handle || !selinux_net_assertion_source_valid(source) ||
	    flags & ~SELINUX_NET_ASSERTION_FLAGS_MASK)
		return ERR_PTR(-EINVAL);
	sid = global_sid_handle_sid(handle);
	if (!sid)
		return ERR_PTR(-ESTALE);
	label = global_sid_handle_label_get(handle);
	if (!label)
		return ERR_PTR(-ESTALE);
	owned = global_sid_handle_dup(handle);
	if (IS_ERR(owned)) {
		selinux_label_ref_put(label);
		return ERR_CAST(owned);
	}
	if (global_sid_handle_sid(owned) != sid) {
		global_sid_handle_put(owned);
		selinux_label_ref_put(label);
		return ERR_PTR(-ESTALE);
	}

	sequence = selinux_net_assertion_next_sequence();
	if (!sequence) {
		global_sid_handle_put(owned);
		selinux_label_ref_put(label);
		return ERR_PTR(-EOVERFLOW);
	}
	assertion = kzalloc_obj(*assertion, gfp);
	if (!assertion) {
		global_sid_handle_put(owned);
		selinux_label_ref_put(label);
		return ERR_PTR(-ENOMEM);
	}

	refcount_set(&assertion->refs, 1);
	assertion->id = sequence;
	assertion->generation = sequence;
	assertion->label = label;
	assertion->sid_handle = owned;
	assertion->sid = sid;
	assertion->semantic_class = semantic_class;
	assertion->source = source;
	assertion->flags = flags;
	return assertion;
}
#endif

struct selinux_net_assertion *
selinux_net_assertion_alloc(struct selinux_label_ref *label,
			    u32 sid,
			    u16 semantic_class,
			    enum selinux_net_assertion_source source,
			    u32 flags, gfp_t gfp)
{
	struct selinux_net_assertion *assertion;
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct selinux_global_sid_handle *sid_handle;
#endif
	u64 sequence;

	if (!label || !sid || !selinux_net_assertion_source_valid(source) ||
	    flags & ~SELINUX_NET_ASSERTION_FLAGS_MASK)
		return ERR_PTR(-EINVAL);
#ifdef CONFIG_SECURITY_SELINUX_NS
	sid_handle = selinux_net_assertion_sid_handle_get(sid, label);
	if (IS_ERR(sid_handle))
		return ERR_CAST(sid_handle);
#endif
	/* The caller supplies a live strong reference. */
	selinux_label_ref_get(label);

	sequence = selinux_net_assertion_next_sequence();
	if (!sequence) {
		selinux_label_ref_put(label);
#ifdef CONFIG_SECURITY_SELINUX_NS
		global_sid_handle_put(sid_handle);
#endif
		return ERR_PTR(-EOVERFLOW);
	}
	assertion = kzalloc_obj(*assertion, gfp);
	if (!assertion) {
		selinux_label_ref_put(label);
#ifdef CONFIG_SECURITY_SELINUX_NS
		global_sid_handle_put(sid_handle);
#endif
		return ERR_PTR(-ENOMEM);
	}

	refcount_set(&assertion->refs, 1);
	assertion->id = sequence;
	assertion->generation = sequence;
	assertion->label = label;
#ifdef CONFIG_SECURITY_SELINUX_NS
	assertion->sid_handle = sid_handle;
#endif
	assertion->sid = sid;
	assertion->semantic_class = semantic_class;
	assertion->source = source;
	assertion->flags = flags;
	return assertion;
}

struct selinux_net_assertion *
selinux_net_assertion_get(struct selinux_net_assertion *assertion)
{
	if (!assertion)
		return NULL;
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (!selinux_net_assertion_consistent(assertion))
		return NULL;
#endif
	refcount_inc(&assertion->refs);
	return assertion;
}

struct selinux_net_assertion *
selinux_net_assertion_get_rcu(struct selinux_net_assertion __rcu * const *assertionp)
{
	struct selinux_net_assertion *assertion;

	rcu_read_lock();
	assertion = rcu_dereference(*assertionp);
	if (assertion && !refcount_inc_not_zero(&assertion->refs))
		assertion = NULL;
	rcu_read_unlock();
#ifdef CONFIG_SECURITY_SELINUX_NS
	if (assertion && !selinux_net_assertion_consistent(assertion)) {
		selinux_net_assertion_put(assertion);
		assertion = NULL;
	}
#endif
	return assertion;
}

static void selinux_net_assertion_free(struct rcu_head *rcu)
{
	struct selinux_net_assertion *assertion =
		container_of(rcu, struct selinux_net_assertion, rcu);

#ifdef CONFIG_SECURITY_SELINUX_NS
	global_sid_handle_put(assertion->sid_handle);
#endif
	selinux_label_ref_put(assertion->label);
	kfree(assertion);
}

void selinux_net_assertion_put(struct selinux_net_assertion *assertion)
{
	if (assertion && refcount_dec_and_test(&assertion->refs))
		call_rcu(&assertion->rcu, selinux_net_assertion_free);
}

static u64 selinux_net_provenance_next_sequence(void)
{
	s64 old = atomic64_read(&selinux_net_provenance_sequence);

	for (;;) {
		if (unlikely(old == S64_MAX))
			return 0;
		if (atomic64_try_cmpxchg(&selinux_net_provenance_sequence, &old,
					 old + 1))
			return old + 1;
	}
}

struct selinux_net_provenance *
selinux_net_provenance_alloc(struct selinux_state *state,
			     const struct selinux_label_view *view,
			     struct selinux_net_assertion *subject, gfp_t gfp)
{
	struct selinux_net_provenance *provenance;
	u64 sequence;

	if (!state || !state->label_domain || !view || !view->origin_domain ||
	    !subject || !subject->label ||
#ifdef CONFIG_SECURITY_SELINUX_NS
	    !selinux_net_assertion_consistent(subject) ||
#endif
	    state->label_domain != view->origin_domain ||
	    (!(subject->label->domain->flags &
	       SELINUX_LABEL_DOMAIN_KERNEL_GLOBAL) &&
	     subject->label->domain != view->origin_domain))
		return ERR_PTR(-EINVAL);

	sequence = selinux_net_provenance_next_sequence();
	if (!sequence)
		return ERR_PTR(-EOVERFLOW);
	provenance = kzalloc_obj(*provenance, gfp);
	if (!provenance)
		return ERR_PTR(-ENOMEM);

	refcount_set(&provenance->refs, 1);
	provenance->id = sequence;
	provenance->generation = sequence;
	provenance->state = get_selinux_state(state);
	provenance->view = selinux_label_view_get(view);
	provenance->subject = selinux_net_assertion_get(subject);
	if (!provenance->subject) {
		selinux_label_view_put(provenance->view);
		put_selinux_state(provenance->state);
		kfree(provenance);
		return ERR_PTR(-ESTALE);
	}
	return provenance;
}

struct selinux_net_provenance *
selinux_net_provenance_get(struct selinux_net_provenance *provenance)
{
	if (provenance)
		refcount_inc(&provenance->refs);
	return provenance;
}
EXPORT_SYMBOL_GPL(selinux_net_provenance_get);

struct selinux_net_provenance *
selinux_net_provenance_get_rcu(
	struct selinux_net_provenance __rcu * const *provenancep)
{
	struct selinux_net_provenance *provenance;

	rcu_read_lock();
	provenance = rcu_dereference(*provenancep);
	if (provenance && !refcount_inc_not_zero(&provenance->refs))
		provenance = NULL;
	rcu_read_unlock();
	return provenance;
}
EXPORT_SYMBOL_GPL(selinux_net_provenance_get_rcu);

static void selinux_net_provenance_free(struct rcu_head *rcu)
{
	struct selinux_net_provenance *provenance =
		container_of(rcu, struct selinux_net_provenance, rcu);

	selinux_net_assertion_put(provenance->subject);
	selinux_label_view_put(provenance->view);
	put_selinux_state(provenance->state);
	kfree(provenance);
}

void selinux_net_provenance_put(struct selinux_net_provenance *provenance)
{
	if (provenance && refcount_dec_and_test(&provenance->refs))
		call_rcu(&provenance->rcu, selinux_net_provenance_free);
}
EXPORT_SYMBOL_GPL(selinux_net_provenance_put);

#ifdef CONFIG_SECURITY_SELINUX_NS
bool selinux_secmark_provenance_matches(
	const struct selinux_net_provenance *provenance, u32 sid)
{
	return !sid ? !provenance :
		provenance && provenance->subject &&
		selinux_net_assertion_consistent(provenance->subject) &&
		provenance->subject->sid == sid &&
		provenance->subject->semantic_class == SECCLASS_PACKET &&
		provenance->subject->source ==
			SELINUX_NET_ASSERTION_SOURCE_SECMARK;
}
EXPORT_SYMBOL_GPL(selinux_secmark_provenance_matches);
#endif
