// SPDX-License-Identifier: GPL-2.0-only
/*
 * Module for modifying the secmark field of the skb, for use by
 * security subsystems.
 *
 * Based on the nfmark match by:
 * (C) 1999-2001 Marc Boucher <marc@mbsi.ca>
 *
 * (C) 2006,2008 Red Hat, Inc., James Morris <jmorris@redhat.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/security.h>
#include <linux/selinux_net.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_SECMARK.h>
#ifdef CONFIG_SECURITY_SELINUX_NS
#include <linux/xarray.h>
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("James Morris <jmorris@redhat.com>");
MODULE_DESCRIPTION("Xtables: packet security mark modification");
MODULE_ALIAS("ipt_SECMARK");
MODULE_ALIAS("ip6t_SECMARK");

static u8 mode;

#ifdef CONFIG_SECURITY_SELINUX_NS
/*
 * The xtables userspace ABI has no room for an internal pointer.  Rules own
 * one immutable provenance reference in this side table; packet evaluation
 * only takes a reference and never allocates.
 */
static DEFINE_XARRAY(secmark_provenance);

struct secmark_provenance_binding {
	struct rcu_head rcu;
	struct selinux_net_provenance *provenance;
};

static void secmark_provenance_binding_free_rcu(struct rcu_head *rcu)
{
	struct secmark_provenance_binding *binding =
		container_of(rcu, struct secmark_provenance_binding, rcu);

	selinux_net_provenance_put(binding->provenance);
	kfree(binding);
}

static struct selinux_net_provenance *
secmark_provenance_load(const void *key)
{
	struct secmark_provenance_binding *binding;

	binding = xa_load(&secmark_provenance, (unsigned long)key);
	return binding ? binding->provenance : NULL;
}
#endif

static unsigned int
secmark_tg(struct sk_buff *skb, const struct xt_secmark_target_info_v1 *info,
	   const void *key)
{
	u32 secmark = 0;

	switch (mode) {
	case SECMARK_MODE_SEL:
		secmark = info->secid;
		break;
	default:
		BUG();
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	rcu_read_lock();
	skb_set_secmark(skb, secmark, secmark_provenance_load(key));
	rcu_read_unlock();
#else
	skb->secmark = secmark;
#endif
	return XT_CONTINUE;
}

static int checkentry_lsm(struct xt_secmark_target_info_v1 *info,
			  const struct net *net, const void *key)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct secmark_provenance_binding *binding;
#endif
	struct lsm_prop_ref *prop_ref = NULL;
	struct lsm_secmark secmark;
	int err;

	info->secctx[SECMARK_SECCTX_MAX - 1] = '\0';
	info->secid = 0;

	err = security_secctx_to_lsmprop_ref(info->secctx, strlen(info->secctx),
					 LSM_ID_UNDEF, GFP_KERNEL, &prop_ref);
	if (err) {
		if (err == -EINVAL)
			pr_info_ratelimited("invalid security context \'%s\'\n",
					    info->secctx);
		return err;
	}
	if (security_lsm_prop_ref_provider_count(prop_ref) != 1) {
		err = -ENOTUNIQ;
		goto out_ref;
	}
	if (!security_lsm_prop_ref_source_secid(prop_ref, &info->secid)) {
		pr_info_ratelimited("invalid security context \'%s\'\n",
				    info->secctx);
		err = -EINVAL;
		goto out_ref;
	}

	if (!info->secid) {
		pr_info_ratelimited("unable to map security context \'%s\'\n",
				    info->secctx);
		err = -ENOENT;
		goto out_ref;
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	binding = kzalloc(sizeof(*binding), GFP_KERNEL);
	if (!binding) {
		err = -ENOMEM;
		goto out_ref;
	}
#endif

	err = security_secmark_relabel_packet(net, info->secid, &secmark);
	security_lsm_prop_ref_put(prop_ref);
	prop_ref = NULL;
	if (err) {
		pr_info_ratelimited("unable to obtain relabeling permission\n");
#ifdef CONFIG_SECURITY_SELINUX_NS
		kfree(binding);
		return err;
#else
		return err;
#endif
	}

#ifdef CONFIG_SECURITY_SELINUX_NS
	binding->provenance = selinux_secmark_provenance_take(&secmark);
	security_secmark_release(&secmark);
	if (!binding->provenance) {
		err = -EACCES;
		goto out_binding;
	}
	err = xa_insert(&secmark_provenance, (unsigned long)key, binding,
			GFP_KERNEL);
	if (err)
		goto out_binding;
#else
	security_secmark_release(&secmark);
#endif
	security_secmark_refcount_inc();
	return 0;

#ifdef CONFIG_SECURITY_SELINUX_NS
out_binding:
	selinux_net_provenance_put(binding->provenance);
	kfree(binding);
#endif
out_ref:
	security_lsm_prop_ref_put(prop_ref);
	return err;
}

static int
secmark_tg_check(const struct xt_tgchk_param *par,
		 struct xt_secmark_target_info_v1 *info)
{
	int err;

	if (strcmp(par->table, "mangle") != 0 &&
	    strcmp(par->table, "security") != 0) {
		pr_info_ratelimited("only valid in \'mangle\' or \'security\' table, not \'%s\'\n",
				    par->table);
		return -EINVAL;
	}

	if (mode && mode != info->mode) {
		pr_info_ratelimited("mode already set to %hu cannot mix with rules for mode %hu\n",
				    mode, info->mode);
		return -EINVAL;
	}

	switch (info->mode) {
	case SECMARK_MODE_SEL:
		break;
	default:
		pr_info_ratelimited("invalid mode: %hu\n", info->mode);
		return -EINVAL;
	}

	err = checkentry_lsm(info, par->net, par->targinfo);
	if (err)
		return err;

	if (!mode)
		mode = info->mode;
	return 0;
}

static void secmark_tg_destroy(const struct xt_tgdtor_param *par)
{
#ifdef CONFIG_SECURITY_SELINUX_NS
	struct secmark_provenance_binding *binding;

	binding = xa_erase(&secmark_provenance,
			   (unsigned long)par->targinfo);
	if (binding)
		call_rcu(&binding->rcu, secmark_provenance_binding_free_rcu);
#endif
	switch (mode) {
	case SECMARK_MODE_SEL:
		security_secmark_refcount_dec();
	}
}

static int secmark_tg_check_v0(const struct xt_tgchk_param *par)
{
	struct xt_secmark_target_info *info = par->targinfo;
	struct xt_secmark_target_info_v1 newinfo = {
		.mode	= info->mode,
	};
	int ret;

	memcpy(newinfo.secctx, info->secctx, SECMARK_SECCTX_MAX);

	ret = secmark_tg_check(par, &newinfo);
	info->secid = newinfo.secid;

	return ret;
}

static unsigned int
secmark_tg_v0(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_secmark_target_info *info = par->targinfo;
	struct xt_secmark_target_info_v1 newinfo = {
		.secid	= info->secid,
	};

	return secmark_tg(skb, &newinfo, info);
}

static int secmark_tg_check_v1(const struct xt_tgchk_param *par)
{
	return secmark_tg_check(par, par->targinfo);
}

static unsigned int
secmark_tg_v1(struct sk_buff *skb, const struct xt_action_param *par)
{
	return secmark_tg(skb, par->targinfo, par->targinfo);
}

static struct xt_target secmark_tg_reg[] __read_mostly = {
	{
		.name		= "SECMARK",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.checkentry	= secmark_tg_check_v0,
		.destroy	= secmark_tg_destroy,
		.target		= secmark_tg_v0,
		.targetsize	= sizeof(struct xt_secmark_target_info),
		.me		= THIS_MODULE,
	},
	{
		.name		= "SECMARK",
		.revision	= 1,
		.family		= NFPROTO_IPV4,
		.checkentry	= secmark_tg_check_v1,
		.destroy	= secmark_tg_destroy,
		.target		= secmark_tg_v1,
		.targetsize	= sizeof(struct xt_secmark_target_info_v1),
		.usersize	= offsetof(struct xt_secmark_target_info_v1, secid),
		.me		= THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name		= "SECMARK",
		.revision	= 0,
		.family		= NFPROTO_IPV6,
		.checkentry	= secmark_tg_check_v0,
		.destroy	= secmark_tg_destroy,
		.target		= secmark_tg_v0,
		.targetsize	= sizeof(struct xt_secmark_target_info),
		.me		= THIS_MODULE,
	},
	{
		.name		= "SECMARK",
		.revision	= 1,
		.family		= NFPROTO_IPV6,
		.checkentry	= secmark_tg_check_v1,
		.destroy	= secmark_tg_destroy,
		.target		= secmark_tg_v1,
		.targetsize	= sizeof(struct xt_secmark_target_info_v1),
		.usersize	= offsetof(struct xt_secmark_target_info_v1, secid),
		.me		= THIS_MODULE,
	},
#endif
};

static int __init secmark_tg_init(void)
{
	return xt_register_targets(secmark_tg_reg, ARRAY_SIZE(secmark_tg_reg));
}

static void __exit secmark_tg_exit(void)
{
	xt_unregister_targets(secmark_tg_reg, ARRAY_SIZE(secmark_tg_reg));
#ifdef CONFIG_SECURITY_SELINUX_NS
	/* secmark_provenance_binding_free_rcu() lives in this module. */
	rcu_barrier();
#endif
}

module_init(secmark_tg_init);
module_exit(secmark_tg_exit);
