// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */
#include <linux/lsm_hooks.h>
#include <linux/bpf_lsm.h>
#include <uapi/linux/lsm.h>

bool bpf_lsm_initialized __ro_after_init;

/*
 * BPF LSM has no stable, provider-owned label identity to retain in a
 * carrier.  A BPF program's hook return value is an authorization result,
 * not a durable security identity, so scalar or object sources cannot be
 * captured without inventing provenance.
 */
int bpf_lsm_prop_ref_capture(struct lsm_prop_ref *ref,
			     const struct lsm_prop_ref_source *source,
			     gfp_t gfp)
{
	(void)ref;
	(void)source;
	(void)gfp;
	return -EOPNOTSUPP;
}

static struct security_hook_list bpf_lsm_hooks[] __ro_after_init = {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...) \
	LSM_HOOK_INIT(NAME, bpf_lsm_##NAME),
	#include <linux/lsm_hook_defs.h>
	#undef LSM_HOOK
	LSM_HOOK_INIT(inode_free_security, bpf_inode_storage_free),
};

static const struct lsm_id bpf_lsmid = {
	.name = "bpf",
	.id = LSM_ID_BPF,
};

static int __init bpf_lsm_init(void)
{
	security_add_hooks(bpf_lsm_hooks, ARRAY_SIZE(bpf_lsm_hooks),
			   &bpf_lsmid);
	bpf_lsm_initialized = true;
	pr_info("LSM support for eBPF active\n");
	return 0;
}

struct lsm_blob_sizes bpf_lsm_blob_sizes __ro_after_init = {
	.lbs_inode = sizeof(struct bpf_storage_blob),
};

DEFINE_LSM(bpf) = {
	.id = &bpf_lsmid,
	.init = bpf_lsm_init,
	.blobs = &bpf_lsm_blob_sizes
};
