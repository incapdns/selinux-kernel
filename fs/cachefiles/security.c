// SPDX-License-Identifier: GPL-2.0-or-later
/* CacheFiles security management
 *
 * Copyright (C) 2007, 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs.h>
#include <linux/cred.h>
#include "internal.h"

/*
 * determine the security context within which we access the cache from within
 * the kernel
 */
int cachefiles_get_security_ID(struct cachefiles_cache *cache)
{
	struct cred *new;
	int ret;

	_enter("{%u}", cache->secctx_ref ? cache->secid : 0);

	new = prepare_kernel_cred(current);
	if (!new) {
		ret = -ENOMEM;
		goto error;
	}

	if (cache->secctx_ref) {
		ret = security_kernel_act_as_ref(new, cache->secctx_ref);
		if (ret < 0) {
			put_cred(new);
			pr_err("Security denies permission to nominate security context: error %d\n",
			       ret);
			goto error;
		}
	}

	cache->cache_cred = new;
	ret = 0;
error:
	_leave(" = %d", ret);
	return ret;
}

#ifdef CONFIG_KUNIT
/*
 * Exercise the real CacheFiles override path while keeping the fixture local.
 * In particular, @diagnostic_secid must never become override authority.
 */
int cachefiles_kunit_apply_secctx_ref(struct lsm_prop_ref *ref,
				     u32 diagnostic_secid,
				     struct lsm_prop *applied_prop)
{
	struct cachefiles_cache cache = {
		.secctx_ref = ref,
		.secid = diagnostic_secid,
	};
	struct lsm_prop_ref *applied_ref = NULL;
	const struct lsm_prop *prop;
	int ret;

	if (!ref || !applied_prop)
		return -EINVAL;
	lsmprop_init(applied_prop);
	ret = cachefiles_get_security_ID(&cache);
	if (ret)
		return ret;
	ret = security_cred_getlsmprop_ref(cache.cache_cred, GFP_KERNEL,
					    &applied_ref);
	if (!ret) {
		prop = security_lsm_prop_ref_prop(applied_ref);
		if (prop)
			*applied_prop = *prop;
		else
			ret = -EIO;
	}
	security_lsm_prop_ref_put(applied_ref);
	put_cred(cache.cache_cred);
	return ret;
}
#endif

/*
 * see if mkdir and create can be performed in the root directory
 */
static int cachefiles_check_cache_dir(struct cachefiles_cache *cache,
				      struct dentry *root)
{
	int ret;

	ret = security_inode_mkdir_mnt(cache->mnt, d_backing_inode(root), root,
				       0);
	if (ret < 0) {
		pr_err("Security denies permission to make dirs: error %d",
		       ret);
		return ret;
	}

	ret = security_inode_create_mnt(cache->mnt, d_backing_inode(root), root,
					0);
	if (ret < 0)
		pr_err("Security denies permission to create files: error %d",
		       ret);

	return ret;
}

/*
 * check the security details of the on-disk cache
 * - must be called with security override in force
 * - must return with a security override in force - even in the case of an
 *   error
 */
int cachefiles_determine_cache_security(struct cachefiles_cache *cache,
					struct dentry *root,
					const struct cred **_saved_cred)
{
	struct cred *new;
	int ret;

	_enter("");

	/* duplicate the cache creds for COW (the override is currently in
	 * force, so we can use prepare_creds() to do this) */
	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	cachefiles_end_secure(cache, *_saved_cred);

	/* use the cache root dir's security context as the basis with
	 * which create files */
	ret = set_create_files_as(new, d_backing_inode(root));
	if (ret < 0) {
		abort_creds(new);
		cachefiles_begin_secure(cache, _saved_cred);
		_leave(" = %d [cfa]", ret);
		return ret;
	}

	put_cred(cache->cache_cred);
	cache->cache_cred = new;

	cachefiles_begin_secure(cache, _saved_cred);
	ret = cachefiles_check_cache_dir(cache, root);

	if (ret == -EOPNOTSUPP)
		ret = 0;
	_leave(" = %d", ret);
	return ret;
}
