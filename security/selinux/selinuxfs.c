// SPDX-License-Identifier: GPL-2.0-only
/* Updated: Karl MacMillan <kmacmillan@tresys.com>
 *
 *	Added conditional policy language extensions
 *
 *  Updated: Hewlett-Packard <paul@paul-moore.com>
 *
 *	Added support for the policy capability bitmap
 *
 * Copyright (C) 2007 Hewlett-Packard Development Company, L.P.
 * Copyright (C) 2003 - 2004 Tresys Technology, LLC
 * Copyright (C) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/compat.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fs_context.h>
#include <linux/hex.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/init.h>
#include <linux/ipc_namespace.h>
#include <linux/nsproxy.h>
#include <linux/string.h>
#include <linux/security.h>
#include <linux/major.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <linux/rhashtable.h>
#include <linux/sched/mm.h>
#include <linux/workqueue.h>
#include <linux/audit.h>
#include <linux/nsfs.h>
#include <linux/uaccess.h>
#include <linux/kobject.h>
#include <linux/ctype.h>
#include <linux/selinux_ns.h>

/* selinuxfs pseudo filesystem for exporting the security policy API.
   Based on the proc code and the fs/nfsd/nfsctl.c code. */

#include "initcalls.h"
#include "flask.h"
#include "avc.h"
#include "avc_ss.h"
#include "global_sidtab.h"
#include "security.h"
#include "selinux_ss.h"
#include "objsec.h"
#include "conditional.h"
#include "ima.h"
#ifdef CONFIG_SECURITY_SELINUX_NS
#include "namespace.h"
#endif

enum sel_inos {
	SEL_ROOT_INO = 2,
	SEL_LOAD,	/* load policy */
	SEL_ENFORCE,	/* get or set enforcing status */
	SEL_CONTEXT,	/* validate context */
	SEL_ACCESS,	/* compute access decision */
	SEL_CREATE,	/* compute create labeling decision */
	SEL_RELABEL,	/* compute relabeling decision */
	SEL_USER,	/* compute reachable user contexts */
	SEL_POLICYVERS,	/* return policy version for this kernel */
	SEL_COMMIT_BOOLS, /* commit new boolean values */
	SEL_MLS,	/* return if MLS policy is enabled */
	SEL_DISABLE,	/* disable SELinux until next reboot */
	SEL_MEMBER,	/* compute polyinstantiation membership decision */
	SEL_CHECKREQPROT, /* check requested protection, not kernel-applied one */
	SEL_COMPAT_NET,	/* whether to use old compat network packet controls */
	SEL_REJECT_UNKNOWN, /* export unknown reject handling to userspace */
	SEL_DENY_UNKNOWN, /* export unknown deny handling to userspace */
	SEL_STATUS,	/* export current status using mmap() */
	SEL_POLICY,	/* allow userspace to read the in kernel policy */
	SEL_VALIDATE_TRANS, /* compute validatetrans decision */
#ifdef CONFIG_SECURITY_SELINUX_NS
	SEL_MAXNS,	    /* maximum number of SELinux namespaces */
	SEL_MAXNSDEPTH,	    /* maximum depth of SELinux namespaces */
	SEL_NS_CREATE,	    /* create a dormant namespace control FD */
#endif
	SEL_POLICY_MAX_BYTES, /* maximum accepted binary policy size */
	SEL_INO_NEXT,	/* The next inode number to use */
};

struct selinux_fs_info {
	struct dentry *bool_dir;
	unsigned int bool_num;
	char **bool_pending_names;
	int *bool_pending_values;
	struct dentry *class_dir;
	unsigned long last_class_ino;
	unsigned long last_ino;
	struct selinux_state *state;
	struct super_block *sb;
	atomic64_t policy_snapshot_bytes;
};

static struct selinux_fs_info *selinux_fs_info_create(void)
{
	struct selinux_fs_info *fsi;

	fsi = kzalloc_obj(*fsi);
	if (!fsi)
		return NULL;

	fsi->last_ino = SEL_INO_NEXT - 1;
	fsi->state = get_selinux_state(current_selinux_state);
	atomic64_set(&fsi->policy_snapshot_bytes, 0);
	return fsi;
}

static void selinux_fs_info_free(struct selinux_fs_info *fsi)
{
	unsigned int i;

	if (fsi) {
		WARN_ON(atomic64_read(&fsi->policy_snapshot_bytes));
		put_selinux_state(fsi->state);
		for (i = 0; i < fsi->bool_num; i++)
			kfree(fsi->bool_pending_names[i]);
		kfree(fsi->bool_pending_names);
		kfree(fsi->bool_pending_values);
	}
	kfree(fsi);
}

#define SEL_INITCON_INO_OFFSET		0x01000000
#define SEL_BOOL_INO_OFFSET		0x02000000
#define SEL_CLASS_INO_OFFSET		0x04000000
#define SEL_POLICYCAP_INO_OFFSET	0x08000000
#define SEL_INO_MASK			0x00ffffff

#define BOOL_DIR_NAME "booleans"
#define CLASS_DIR_NAME "class"

#define TMPBUFLEN	12

/*
 * A selinuxfs file is an authority for exactly the SELinux state which owns
 * its superblock.  Recheck on every state-dependent operation: file
 * descriptors and VMAs can outlive the task which opened them and can be
 * transferred to a task in another SELinux state.
 */
static int selinuxfs_state_access(const struct file *file)
{
	const struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;

	if (unlikely(fsi->state != current_selinux_state))
		return -EPERM;
	return 0;
}

/*
 * Account retained policy snapshots.  The selinuxfs superblock is unique per
 * SELinux state, and open files/VMAs pin that superblock, so this counter has
 * the same lifetime as every charge.  Load buffers are separately serialized
 * under policy_mutex and freed before that mutex is released.
 */
static int selinuxfs_snapshot_bytes_reserve(struct selinux_fs_info *fsi,
					    size_t bytes)
{
	s64 used = atomic64_read(&fsi->policy_snapshot_bytes);

	if (bytes > CONFIG_SECURITY_SELINUX_POLICY_MAX_BYTES)
		return -EFBIG;
	for (;;) {
		if (bytes > CONFIG_SECURITY_SELINUX_POLICY_MAX_BYTES - used)
			return -EDQUOT;
		if (atomic64_try_cmpxchg(&fsi->policy_snapshot_bytes, &used,
					 used + bytes))
			return 0;
	}
}

static void selinuxfs_snapshot_bytes_release(struct selinux_fs_info *fsi,
					     size_t bytes)
{
	atomic64_sub(bytes, &fsi->policy_snapshot_bytes);
}

#ifdef CONFIG_SECURITY_SELINUX_NS
struct selinuxfs_mm_vmas {
	struct rhash_head node;
	struct mm_struct *mm;
	refcount_t refs;
	struct rcu_work free_rwork;
};

static struct rhashtable selinuxfs_mm_vmas;
static DEFINE_MUTEX(selinuxfs_mm_vmas_lock);
/* Baseline one makes overflow saturate permanently fail-closed. */
static refcount_t selinuxfs_untracked_vmas = REFCOUNT_INIT(1);
static bool selinuxfs_mm_vmas_ready;

static const struct rhashtable_params selinuxfs_mm_vmas_params = {
	.head_offset		= offsetof(struct selinuxfs_mm_vmas, node),
	.key_offset		= offsetof(struct selinuxfs_mm_vmas, mm),
	.key_len		= sizeof(struct mm_struct *),
	.automatic_shrinking	= true,
};

static int __init selinuxfs_mm_vmas_init(void)
{
	int rc;

	rc = rhashtable_init(&selinuxfs_mm_vmas,
			     &selinuxfs_mm_vmas_params);
	if (!rc)
		smp_store_release(&selinuxfs_mm_vmas_ready, true);
	return rc;
}

static struct selinuxfs_mm_vmas *selinuxfs_mm_vmas_get(struct mm_struct *mm)
{
	struct selinuxfs_mm_vmas *entry;
	int rc;

	if (unlikely(!smp_load_acquire(&selinuxfs_mm_vmas_ready)))
		return ERR_PTR(-EIO);

	mutex_lock(&selinuxfs_mm_vmas_lock);
	entry = rhashtable_lookup_fast(&selinuxfs_mm_vmas, &mm,
				       selinuxfs_mm_vmas_params);
	if (entry) {
		refcount_inc(&entry->refs);
		mutex_unlock(&selinuxfs_mm_vmas_lock);
		return entry;
	}

	entry = kzalloc_obj(*entry);
	if (!entry) {
		mutex_unlock(&selinuxfs_mm_vmas_lock);
		return ERR_PTR(-ENOMEM);
	}
	entry->mm = mm;
	refcount_set(&entry->refs, 1);
	mmgrab(mm);
	rc = rhashtable_insert_fast(&selinuxfs_mm_vmas, &entry->node,
				    selinuxfs_mm_vmas_params);
	if (rc) {
		mmdrop(mm);
		kfree(entry);
		entry = ERR_PTR(rc);
	}
	mutex_unlock(&selinuxfs_mm_vmas_lock);
	return entry;
}

static void selinuxfs_mm_vmas_free(struct work_struct *work)
{
	struct selinuxfs_mm_vmas *entry =
		container_of(to_rcu_work(work), struct selinuxfs_mm_vmas,
			     free_rwork);

	mmdrop(entry->mm);
	kfree(entry);
}

static void selinuxfs_mm_vmas_put(struct selinuxfs_mm_vmas *entry)
{
	int rc;

	mutex_lock(&selinuxfs_mm_vmas_lock);
	if (!refcount_dec_and_test(&entry->refs)) {
		mutex_unlock(&selinuxfs_mm_vmas_lock);
		return;
	}
	rc = rhashtable_remove_fast(&selinuxfs_mm_vmas, &entry->node,
				    selinuxfs_mm_vmas_params);
	if (WARN_ON_ONCE(rc)) {
		/* Keep an unremovable entry permanently fail-closed. */
		refcount_set(&entry->refs, 1);
		mutex_unlock(&selinuxfs_mm_vmas_lock);
		return;
	}
	INIT_RCU_WORK(&entry->free_rwork, selinuxfs_mm_vmas_free);
	mutex_unlock(&selinuxfs_mm_vmas_lock);
	if (WARN_ON_ONCE(!queue_rcu_work(system_dfl_wq,
					 &entry->free_rwork)))
		return;
}

static int selinuxfs_vma_track_initial(struct vm_area_struct *vma)
{
	struct selinuxfs_mm_vmas *entry = selinuxfs_mm_vmas_get(vma->vm_mm);

	if (IS_ERR(entry))
		return PTR_ERR(entry);
	vma->vm_private_data = entry;
	return 0;
}

static void selinuxfs_vma_open(struct vm_area_struct *vma)
{
	struct selinuxfs_mm_vmas *entry = selinuxfs_mm_vmas_get(vma->vm_mm);

	if (IS_ERR(entry)) {
		/* .open cannot fail; make every state transition fail closed. */
		refcount_inc(&selinuxfs_untracked_vmas);
		vma->vm_private_data = entry;
		pr_warn_ratelimited("SELinux: unable to track selinuxfs VMA\n");
		return;
	}
	vma->vm_private_data = entry;
}

static void selinuxfs_vma_close(struct vm_area_struct *vma)
{
	struct selinuxfs_mm_vmas *entry = vma->vm_private_data;

	if (WARN_ON_ONCE(!entry))
		return;
	if (IS_ERR(entry))
		WARN_ON_ONCE(!refcount_dec_not_one(&selinuxfs_untracked_vmas));
	else
		selinuxfs_mm_vmas_put(entry);
	vma->vm_private_data = NULL;
}

int selinuxfs_mm_may_change(struct mm_struct *mm)
{
	struct selinuxfs_mm_vmas *entry;
	int rc = 0;

	if (unlikely(!smp_load_acquire(&selinuxfs_mm_vmas_ready)))
		return -EIO;
	if (!mm)
		return 0;

	/* VMA callbacks take mmap_lock before the registry mutex. */
	mmap_read_lock(mm);
	mutex_lock(&selinuxfs_mm_vmas_lock);
	if (unlikely(refcount_read(&selinuxfs_untracked_vmas) != 1)) {
		rc = -EIO;
		goto out;
	}
	entry = rhashtable_lookup_fast(&selinuxfs_mm_vmas, &mm,
				       selinuxfs_mm_vmas_params);
	if (entry)
		rc = -EBUSY;
out:
	mutex_unlock(&selinuxfs_mm_vmas_lock);
	mmap_read_unlock(mm);
	return rc;
}

#ifdef CONFIG_SECURITY_SELINUX_KUNIT_TEST
bool selinuxfs_kunit_mm_tracking_ready(void)
{
	return smp_load_acquire(&selinuxfs_mm_vmas_ready);
}

void *selinuxfs_kunit_mm_track(struct mm_struct *mm)
{
	return selinuxfs_mm_vmas_get(mm);
}

void selinuxfs_kunit_mm_untrack(void *cookie)
{
	selinuxfs_mm_vmas_put(cookie);
}

void selinuxfs_kunit_tracking_failure(bool active)
{
	if (active)
		refcount_inc(&selinuxfs_untracked_vmas);
	else
		WARN_ON_ONCE(!refcount_dec_not_one(&selinuxfs_untracked_vmas));
}
#endif
#endif

static int selinuxfs_dir_open(struct inode *inode, struct file *file)
{
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;
	return dcache_dir_open(inode, file);
}

static int selinuxfs_dir_iterate(struct file *file, struct dir_context *ctx)
{
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;
	return dcache_readdir(file, ctx);
}

static loff_t selinuxfs_lseek(struct file *file, loff_t offset, int whence)
{
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;
	return generic_file_llseek(file, offset, whence);
}

static loff_t selinuxfs_dir_lseek(struct file *file, loff_t offset, int whence)
{
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;
	return dcache_dir_lseek(file, offset, whence);
}

static const struct file_operations selinuxfs_dir_operations = {
	.open		= selinuxfs_dir_open,
	.release	= dcache_dir_close,
	.llseek		= selinuxfs_dir_lseek,
	.read		= generic_read_dir,
	.iterate_shared	= selinuxfs_dir_iterate,
	.fsync		= noop_fsync,
};

static ssize_t sel_read_enforce(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d",
			   enforcing_enabled(fsi->state));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
static ssize_t sel_write_enforce(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *page = NULL;
	ssize_t length;
	int scan_value;
	bool old_value, new_value;

	length = selinuxfs_state_access(file);
	if (length)
		return length;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	length = -EINVAL;
	if (sscanf(page, "%d", &scan_value) != 1)
		goto out;

	new_value = !!scan_value;

	old_value = enforcing_enabled(state);
	if (new_value != old_value) {
		/*
		 * Only check against the current namespace because
		 * this operation only affects it and no others.
		 */
		length = avc_has_perm(current_selinux_state,
				      current_sid(), SECINITSID_SECURITY,
				      SECCLASS_SECURITY, SECURITY__SETENFORCE,
				      NULL);
		if (length)
			goto out;
		length = selinux_chain_update_prepare(state);
		if (length)
			goto out;
		length = selinux_chain_update_begin(state);
		if (WARN_ON_ONCE(length)) {
			selinux_chain_update_abort(state);
			goto out;
		}
		enforcing_set(state, new_value);
		selinux_chain_update_end(state);

		/* Audit and cache callbacks may block; publication is stable now. */
		audit_log(audit_context(), GFP_KERNEL, AUDIT_MAC_STATUS,
			"enforcing=%d old_enforcing=%d auid=%u ses=%u"
			" enabled=1 old-enabled=1 lsm=selinux res=1",
			new_value, old_value,
			from_kuid(&init_user_ns, audit_get_loginuid(current)),
			audit_get_sessionid(current));
		if (new_value)
			avc_ss_reset(state->avc, 0);
		selinux_chain_update_complete(state);
		selnl_notify_setenforce(new_value);
		selinux_status_update_setenforce(state, new_value);
#ifndef CONFIG_SECURITY_SELINUX_NS
		if (!new_value)
			call_blocking_lsm_notifier(LSM_POLICY_CHANGE, NULL);
#endif

		selinux_ima_measure_state(state);
	}
	length = count;
out:
	kfree(page);
	return length;
}
#else
#define sel_write_enforce NULL
#endif

static const struct file_operations sel_enforce_ops = {
	.read		= sel_read_enforce,
	.write		= sel_write_enforce,
	.llseek		= selinuxfs_lseek,
};

static ssize_t sel_read_handle_unknown(struct file *filp, char __user *buf,
					size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	ino_t ino = file_inode(filp)->i_ino;
	int handle_unknown;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;
	handle_unknown = (ino == SEL_REJECT_UNKNOWN) ?
		security_get_reject_unknown(state) :
		!security_get_allow_unknown(state);

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", handle_unknown);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations sel_handle_unknown_ops = {
	.read		= sel_read_handle_unknown,
	.llseek		= selinuxfs_lseek,
};

static int sel_open_handle_status(struct inode *inode, struct file *filp)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	struct page *status;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;
	status = selinux_kernel_status_page(fsi->state);

	if (!status)
		return -ENOMEM;

	filp->private_data = status;

	return 0;
}

static ssize_t sel_read_handle_status(struct file *filp, char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct page *status = filp->private_data;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;

	if (WARN_ON_ONCE(!status))
		return -EIO;

	return simple_read_from_buffer(buf, count, ppos,
				       page_address(status),
				       sizeof(struct selinux_kernel_status));
}

static vm_fault_t sel_status_fault(struct vm_fault *vmf)
{
	struct file *file = vmf->vma->vm_file;
	struct page *status = file->private_data;

	if (WARN_ON_ONCE(!status))
		return VM_FAULT_SIGBUS;
	if (selinuxfs_state_access(file))
		return VM_FAULT_SIGBUS;
	if (vmf->flags & (FAULT_FLAG_MKWRITE | FAULT_FLAG_WRITE))
		return VM_FAULT_SIGBUS;
	if (vmf->pgoff)
		return VM_FAULT_SIGBUS;

	get_page(status);
	vmf->page = status;
	return 0;
}

static const struct vm_operations_struct sel_status_vm_ops = {
#ifdef CONFIG_SECURITY_SELINUX_NS
	.open		= selinuxfs_vma_open,
	.close		= selinuxfs_vma_close,
#endif
	.fault		= sel_status_fault,
	.page_mkwrite	= sel_status_fault,
};

static int sel_mmap_handle_status(struct file *filp,
				  struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;

	/* only allows one page from the head */
	if (vma->vm_pgoff > 0 || size != PAGE_SIZE)
		return -EIO;
	/* disallow writable mapping */
	if (vma->vm_flags & VM_WRITE)
		return -EPERM;
	/* disallow mprotect() turns it into writable */
	vm_flags_clear(vma, VM_MAYWRITE);
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = selinuxfs_vma_track_initial(vma);
	if (rc)
		return rc;
#endif
	vma->vm_ops = &sel_status_vm_ops;
	return 0;
}

static const struct file_operations sel_handle_status_ops = {
	.open		= sel_open_handle_status,
	.read		= sel_read_handle_status,
	.mmap		= sel_mmap_handle_status,
	.llseek		= selinuxfs_lseek,
};

static ssize_t sel_write_disable(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	/*
	 * Setting disable is no longer supported, see
	 * https://github.com/SELinuxProject/selinux-kernel/wiki/DEPRECATE-runtime-disable
	 */
	pr_err_once("SELinux: %s (%d) wrote to disable. This is no longer supported.\n",
		    current->comm, current->pid);
	return count;
}

static const struct file_operations sel_disable_ops = {
	.write		= sel_write_disable,
	.llseek		= generic_file_llseek,
};

#ifdef CONFIG_SECURITY_SELINUX_NS
static ssize_t sel_read_maxns(struct file *filp, char __user *buf,
			     size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%u", READ_ONCE(selinux_maxns));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}


static ssize_t sel_write_maxns(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *page = NULL;
	ssize_t length;
	unsigned int new_value;

	/*
	 * Only permit setting from the init SELinux namespace, and only
	 * on the init SELinux namespace.
	 */
	if (current_selinux_state != init_selinux_state ||
	    state != init_selinux_state)
		return -EPERM;

	length = avc_has_perm(current_selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__SETMAXNS,
			      NULL);
	if (length)
		return length;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	length = kstrtouint(page, 0, &new_value);
	if (length)
		goto out;
	length = selinux_state_set_maxns(new_value);
	if (length)
		goto out;

	length = count;
out:
	kfree(page);
	return length;
}

static const struct file_operations sel_maxns_ops = {
	.read		= sel_read_maxns,
	.write		= sel_write_maxns,
	.llseek		= generic_file_llseek,
};

static ssize_t sel_read_maxnsdepth(struct file *filp, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
			   READ_ONCE(selinux_maxnsdepth));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}


static ssize_t sel_write_maxnsdepth(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)

{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *page = NULL;
	ssize_t length;
	unsigned int new_value;

	/*
	 * Only permit setting from the init SELinux namespace, and only
	 * on the init SELinux namespace.
	 */
	if (current_selinux_state != init_selinux_state ||
	    state != init_selinux_state)
		return -EPERM;

	length = avc_has_perm(current_selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__SETMAXNSDEPTH,
			      NULL);
	if (length)
		return length;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	length = kstrtouint(page, 0, &new_value);
	if (length)
		goto out;

	length = selinux_state_set_maxnsdepth(new_value);
	if (length)
		goto out;

	length = count;
out:
	kfree(page);
	return length;
}

static const struct file_operations sel_maxnsdepth_ops = {
	.read		= sel_read_maxnsdepth,
	.write		= sel_write_maxnsdepth,
	.llseek		= generic_file_llseek,
};

static int selinux_ns_parent_authority_cred(
	struct selinux_ns_control *control, const struct cred *actor)
{
	struct selinux_state *state = control->state;
	const struct cred_security_struct *actorsec;

	if (!actor)
		return -EINVAL;
	actorsec = selinux_cred(actor);
	if (!selinux_ns_control_parent(control, actorsec->state))
		return -EPERM;
	if (security_capable(actor, actor->user_ns, CAP_SYS_ADMIN,
			     CAP_OPT_NONE) ||
	    security_capable(actor, state->label_domain->owner_userns,
			     CAP_SYS_ADMIN, CAP_OPT_NONE))
		return -EPERM;
	return cred_self_has_perm(actor, SECCLASS_PROCESS2,
				  PROCESS2__UNSHARE_SELINUXNS, NULL);
}

static __maybe_unused int selinux_ns_parent_authority(
	struct selinux_ns_control *control)
{
	return selinux_ns_parent_authority_cred(control, current_cred());
}

static int selinux_ns_copy_context(u64 address, u32 len, char **context)
{
	char *copy;

	if (!address || !len || len >= PAGE_SIZE)
		return -EINVAL;
	copy = memdup_user_nul(u64_to_user_ptr(address), len);
	if (IS_ERR(copy))
		return PTR_ERR(copy);
	if (memchr(copy, '\0', len)) {
		kfree(copy);
		return -EINVAL;
	}
	*context = copy;
	return 0;
}

static long selinux_nsfd_load_policy(struct selinux_ns_control *control,
				     unsigned long arg)
{
	struct selinux_ns_policy request;
	struct selinux_load_state load_state;
	struct selinux_state *state = control->state;
	void *data;
	int rc;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.flags || !request.data || !request.size)
		return -EINVAL;
	if (request.size > CONFIG_SECURITY_SELINUX_POLICY_MAX_BYTES)
		return -EFBIG;
	rc = cred_tsid_has_perm(current_cred(), SECINITSID_SECURITY,
				SECCLASS_SECURITY, SECURITY__LOAD_POLICY, NULL);
	if (rc)
		return rc;

	mutex_lock(&control->lock);
	if (selinux_state_active(state)) {
		rc = -EBUSY;
		goto out_control;
	}
	if (selinux_initialized(state)) {
		rc = -EALREADY;
		goto out_control;
	}

	mutex_lock(&state->policy_mutex);
	data = vmalloc(request.size);
	if (!data) {
		rc = -ENOMEM;
		goto out_policy;
	}
	if (copy_from_user(data, u64_to_user_ptr(request.data), request.size)) {
		rc = -EFAULT;
		goto out_data;
	}
	rc = security_load_policy(state, data, request.size, &load_state);
	if (!rc) {
		rc = selinux_policy_commit(state, &load_state);
		if (rc) {
			selinux_policy_cancel(state, &load_state);
			goto out_data;
		}
		audit_log(audit_context(), GFP_KERNEL, AUDIT_MAC_POLICY_LOAD,
			  "auid=%u ses=%u lsm=selinux selinuxns=%llu res=1",
			  from_kuid(&init_user_ns, audit_get_loginuid(current)),
			  audit_get_sessionid(current), state->label_domain->id);
	}
out_data:
	vfree(data);
out_policy:
	mutex_unlock(&state->policy_mutex);
out_control:
	mutex_unlock(&control->lock);
	return rc;
}

static long selinux_nsfd_add_map(struct selinux_ns_control *control,
				 unsigned long arg)
{
	struct selinux_ns_map_pair request;
	char *source = NULL, *target = NULL;
	int rc;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.direction >= SELINUX_LABEL_MAP_DIRECTIONS)
		return -EINVAL;
	rc = selinux_ns_copy_context(request.source_context,
				     request.source_len, &source);
	if (rc)
		return rc;
	rc = selinux_ns_copy_context(request.target_context,
				     request.target_len, &target);
	if (rc)
		goto out;

	rc = selinux_ns_control_add_map(control, current_selinux_state,
					request.direction, source,
					request.source_len, target,
					request.target_len);
out:
	kfree(target);
	kfree(source);
	return rc;
}

static long selinux_nsfd_activate(struct selinux_ns_control *control)
{
	return selinux_ns_control_activate(control, current_selinux_state);
}

static int selinux_ns_join_cred_sids(struct cred_security_struct *newsec,
				    u32 target_sid)
{
	static const enum selinux_cred_sid_slot slots[] = {
		SELINUX_CRED_OSID,
		SELINUX_CRED_SID,
		SELINUX_CRED_EXEC_SID,
		SELINUX_CRED_CREATE_SID,
		SELINUX_CRED_KEYCREATE_SID,
		SELINUX_CRED_SOCKCREATE_SID,
	};
	struct selinux_global_sid_handle *current_handle[] = {
		newsec->osid_handle,
		newsec->sid_handle,
		newsec->exec_sid_handle,
		newsec->create_sid_handle,
		newsec->keycreate_sid_handle,
		newsec->sockcreate_sid_handle,
	};
	u32 current_sid[] = {
		newsec->osid,
		newsec->sid,
		newsec->exec_sid,
		newsec->create_sid,
		newsec->keycreate_sid,
		newsec->sockcreate_sid,
	};
	struct selinux_global_sid_handle *rollback[ARRAY_SIZE(slots)] = {};
	struct selinux_global_sid_handle *next[ARRAY_SIZE(slots)] = {};
	size_t i;
	int rc;

	if (!target_sid)
		return -EINVAL;
	/* Own a complete rollback image before changing any unpublished slot. */
	for (i = 0; i < ARRAY_SIZE(slots); i++) {
		if (!!current_handle[i] != !!current_sid[i] ||
		    (current_handle[i] &&
		     global_sid_handle_sid(current_handle[i]) != current_sid[i])) {
			rc = -ESTALE;
			goto out;
		}
		if (current_handle[i]) {
			rollback[i] = global_sid_handle_dup(current_handle[i]);
			if (IS_ERR(rollback[i])) {
				rc = PTR_ERR(rollback[i]);
				rollback[i] = NULL;
				goto out;
			}
		}
	}

	next[SELINUX_CRED_OSID] = global_sid_handle_get(target_sid);
	if (IS_ERR(next[SELINUX_CRED_OSID])) {
		rc = PTR_ERR(next[SELINUX_CRED_OSID]);
		next[SELINUX_CRED_OSID] = NULL;
		goto out;
	}
	next[SELINUX_CRED_SID] = global_sid_handle_dup(
		next[SELINUX_CRED_OSID]);
	if (IS_ERR(next[SELINUX_CRED_SID])) {
		rc = PTR_ERR(next[SELINUX_CRED_SID]);
		next[SELINUX_CRED_SID] = NULL;
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(slots); i++) {
		if (next[i]) {
			struct selinux_global_sid_handle *handle = next[i];

			next[i] = NULL;
			rc = selinux_cred_sid_take_handle(newsec, slots[i], handle);
		} else {
			rc = selinux_cred_sid_set(newsec, slots[i], SECSID_NULL);
		}
		if (rc)
			goto rollback;
	}
	rc = 0;
	goto out;

rollback:
	for (i = 0; i < ARRAY_SIZE(slots); i++) {
		struct selinux_global_sid_handle *handle = rollback[i];

		rollback[i] = NULL;
		WARN_ON_ONCE(selinux_cred_sid_take_handle(newsec, slots[i],
							 handle));
	}
out:
	for (i = 0; i < ARRAY_SIZE(slots); i++) {
		global_sid_handle_put(next[i]);
		global_sid_handle_put(rollback[i]);
	}
	return rc;
}

int selinux_ns_control_apply_join(struct selinux_ns_control *control,
				  const struct cred *actor, struct cred *new)
{
	struct cred_security_struct *newsec;
	struct selinux_state *parent, *target, *old;
	u32 target_sid, validated_sid;
	int rc;

	if (!actor || !new)
		return -EINVAL;
	if (!current_is_single_threaded())
		return -EUSERS;
	rc = selinux_ns_parent_authority_cred(control, actor);
	if (rc)
		return rc;
	rc = selinuxfs_mm_may_change(current->mm);
	if (rc)
		return rc;
	parent = selinux_cred(actor)->state;
	target = control->state;
	mutex_lock(&parent->policy_mutex);
	mutex_lock_nested(&target->policy_mutex, SINGLE_DEPTH_NESTING);
	rc = selinux_ns_control_resolve_join(
		control, parent, selinux_cred(actor)->sid,
					     &target_sid);
	if (rc)
		goto out_unlock;
	rc = avc_has_perm(target, target_sid, target_sid, SECCLASS_PROCESS2,
			  PROCESS2__UNSHARE_SELINUXNS, NULL);
	if (rc)
		goto out_unlock;

	rc = selinux_ns_control_resolve_join(
		control, parent, selinux_cred(actor)->sid,
					     &validated_sid);
	if (rc || validated_sid != target_sid) {
		if (!rc)
			rc = -ESTALE;
		goto out_unlock;
	}
	newsec = selinux_cred(new);
	rc = selinux_ns_join_cred_sids(newsec, target_sid);
	if (rc)
		goto out_unlock;
	old = newsec->state;
	newsec->state = get_selinux_state(target);
	put_selinux_state(old);
	put_cred(newsec->parent_cred);
	newsec->parent_cred = get_cred(actor);
	rc = 0;
out_unlock:
	mutex_unlock(&target->policy_mutex);
	mutex_unlock(&parent->policy_mutex);
	return rc;
}

int selinux_ns_control_prepare_join(struct selinux_ns_control *control,
				    struct cred **prepared)
{
	struct cred *new;
	int rc;

	if (!prepared)
		return -EINVAL;
	*prepared = NULL;
	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	rc = selinux_ns_control_apply_join(control, current_cred(), new);
	if (rc) {
		abort_creds(new);
		return rc;
	}
	*prepared = new;
	return 0;
}

static long selinux_nsfd_join(struct selinux_ns_control *control)
{
#if defined(CONFIG_SYSVIPC) || defined(CONFIG_POSIX_MQUEUE)
	struct ipc_namespace_security_txn txn = {};
#endif
	struct cred *prepared;
	int rc;

	rc = selinux_ns_control_prepare_join(control, &prepared);
	if (rc)
		return rc;
#if defined(CONFIG_SYSVIPC) || defined(CONFIG_POSIX_MQUEUE)
	if (current->nsproxy->ipc_ns != &init_ipc_ns) {
		rc = security_ipc_namespace_reanchor_prepare(
			&txn, current->nsproxy->ipc_ns, prepared, NULL, NULL);
		if (rc) {
			abort_creds(prepared);
			return rc;
		}
	}
	security_ipc_namespace_reanchor_commit(&txn);
#endif /* CONFIG_SYSVIPC || CONFIG_POSIX_MQUEUE */
	commit_creds(prepared);
	return rc;
}

static long selinux_nsfd_get_info(struct selinux_ns_control *control,
				  unsigned long arg)
{
	struct selinux_state *state = control->state;
	struct selinux_ns_info info = {
		.id = control->ns.ns_id,
		.parent_id = state->parent->ns_control->ns.ns_id,
		.depth = state->depth,
	};

	if (selinux_initialized(state))
		info.flags |= SELINUX_NS_INFO_INITIALIZED;
	if (smp_load_acquire(&control->map->sealed))
		info.flags |= SELINUX_NS_INFO_SEALED;
	if (selinux_state_active(state))
		info.flags |= SELINUX_NS_INFO_ACTIVE;
	return copy_to_user((void __user *)arg, &info, sizeof(info)) ? -EFAULT : 0;
}

static long selinux_nsfd_get_metadata(struct selinux_ns_control *control,
				      unsigned long arg)
{
	struct selinux_state *state = control->state;
	struct selinux_policy_snapshot snapshot;
	struct selinux_ns_metadata metadata = {
		.size = sizeof(metadata),
		.id = control->ns.ns_id,
		.parent_id = state->parent->ns_control->ns.ns_id,
		.domain_id = state->label_domain->id,
		.parent_domain_id = state->parent->label_domain->id,
		.map_id = control->map->id,
		.depth = state->depth,
	};
	int rc;

	mutex_lock(&control->lock);
	rc = selinux_policy_snapshot_read(state, &snapshot);
	if (rc)
		goto out;
	metadata.policy_seqno = snapshot.seqno;
	metadata.map_generation = READ_ONCE(control->map->generation);
	metadata.map_entries_parent_to_child =
		control->map_entries[SELINUX_LABEL_MAP_PARENT_TO_CHILD];
	metadata.map_entries_child_to_parent =
		control->map_entries[SELINUX_LABEL_MAP_CHILD_TO_PARENT];
	if (selinux_initialized(state))
		metadata.flags |= SELINUX_NS_INFO_INITIALIZED;
	if (smp_load_acquire(&control->map->sealed))
		metadata.flags |= SELINUX_NS_INFO_SEALED;
	if (selinux_state_active(state))
		metadata.flags |= SELINUX_NS_INFO_ACTIVE;
	memcpy(metadata.policy_digest, snapshot.effective_digest,
	       sizeof(metadata.policy_digest));
	if (control->map_digest_valid)
		memcpy(metadata.map_digest, control->map_digest,
		       sizeof(metadata.map_digest));
	rc = copy_to_user((void __user *)arg, &metadata, sizeof(metadata)) ?
		-EFAULT : 0;
out:
	mutex_unlock(&control->lock);
	return rc;
}

static long selinux_nsfd_activate_restore(struct selinux_ns_control *control,
					  unsigned long arg)
{
	struct selinux_ns_restore restore;

	if (copy_from_user(&restore, (void __user *)arg, sizeof(restore)))
		return -EFAULT;
	if (restore.size != sizeof(restore) || restore.flags || restore.reserved)
		return -EINVAL;
	return selinux_ns_control_activate_restore(
		control, current_selinux_state, restore.expected_id,
		restore.expected_parent_id, restore.expected_map_generation,
		restore.expected_policy_seqno, restore.policy_digest,
		restore.map_digest);
}

long selinux_ns_control_ioctl(struct selinux_ns_control *control,
			      unsigned int cmd, unsigned long arg)
{
	int rc = selinux_ns_parent_authority_cred(control, current_cred());

	if (rc)
		return rc;
	switch (cmd) {
	case SELINUX_NS_IOC_LOAD_POLICY:
		return selinux_nsfd_load_policy(control, arg);
	case SELINUX_NS_IOC_ADD_MAP:
		return selinux_nsfd_add_map(control, arg);
	case SELINUX_NS_IOC_ACTIVATE:
		return arg ? -EINVAL : selinux_nsfd_activate(control);
	case SELINUX_NS_IOC_JOIN:
		return arg ? -EINVAL : selinux_nsfd_join(control);
	case SELINUX_NS_IOC_GET_INFO:
		return selinux_nsfd_get_info(control, arg);
	case SELINUX_NS_IOC_GET_METADATA:
		return selinux_nsfd_get_metadata(control, arg);
	case SELINUX_NS_IOC_ACTIVATE_RESTORE:
		return selinux_nsfd_activate_restore(control, arg);
	default:
		return -ENOTTY;
	}
}

static long selinux_ns_create_ioctl(struct file *file, unsigned int cmd,
				    unsigned long arg)
{
	struct selinux_ns_create_restore restore;
	struct selinux_ns_control *control;
	u64 expected_id = 0;
	struct file *nsfile;
	int fd, rc;

	if (cmd != SELINUX_NS_IOC_CREATE &&
	    cmd != SELINUX_NS_IOC_CREATE_RESTORE)
		return -ENOTTY;
	rc = selinuxfs_state_access(file);
	if (rc)
		return rc;
	if (cmd == SELINUX_NS_IOC_CREATE_RESTORE ?
	    !ns_capable(&init_user_ns, CAP_SYS_ADMIN) :
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
		return -EPERM;
	rc = cred_self_has_perm(current_cred(), SECCLASS_PROCESS2,
				PROCESS2__UNSHARE_SELINUXNS, NULL);
	if (rc)
		return rc;
	if (cmd == SELINUX_NS_IOC_CREATE) {
		if (arg)
			return -EINVAL;
	} else {
		void __user *restore_user = (void __user *)arg;
		u32 usize;

		if (get_user(usize, (u32 __user *)restore_user))
			return -EFAULT;
		if (usize < SELINUX_NS_CREATE_RESTORE_SIZE_VER0 ||
		    usize > PAGE_SIZE)
			return -EINVAL;
		memset(&restore, 0, sizeof(restore));
		rc = copy_struct_from_user(&restore, sizeof(restore), restore_user,
					   usize);
		if (rc)
			return rc;
		if (restore.flags ||
		    !restore.expected_id || restore.expected_id > S64_MAX)
			return -EINVAL;
		rc = selinux_ns_restore_parent_validate(
			current_selinux_state, restore.expected_parent_id);
		if (rc)
			return rc;
		expected_id = restore.expected_id;
	}
	if (expected_id)
		control = selinux_ns_control_alloc_unassigned(current_cred());
	else
		control = selinux_ns_control_alloc(current_cred());
	if (IS_ERR(control))
		return PTR_ERR(control);
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		selinux_ns_control_put(control);
		return fd;
	}
	/* open_namespace_file() consumes control's namespace reference. */
	nsfile = open_namespace_file(&control->ns);
	if (IS_ERR(nsfile)) {
		put_unused_fd(fd);
		return PTR_ERR(nsfile);
	}
	if (expected_id) {
		rc = selinux_ns_control_reserve_id(control, expected_id);
		if (rc) {
			fput(nsfile);
			put_unused_fd(fd);
			return rc;
		}
	}
	fd_install(fd, nsfile);
	return fd;
}

static const struct file_operations selinux_ns_create_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = selinux_ns_create_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.llseek = noop_llseek,
};
#endif

static ssize_t sel_read_policyvers(struct file *filp, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%u", POLICYDB_VERSION_MAX);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations sel_policyvers_ops = {
	.read		= sel_read_policyvers,
	.llseek		= generic_file_llseek,
};

/* declaration for sel_write_load */
static int sel_make_bools(struct selinux_state *state,
			  struct selinux_policy *newpolicy,
			  struct dentry *bool_dir,
			  unsigned int *bool_num, char ***bool_pending_names,
			  int **bool_pending_values);
static int sel_make_classes(struct selinux_policy *newpolicy,
			    struct dentry *class_dir,
			    unsigned long *last_class_ino);

/* declaration for sel_make_class_dirs */
static struct dentry *sel_make_dir(struct dentry *dir, const char *name,
			unsigned long *ino);

/* declaration for sel_make_policy_nodes */
static struct dentry *sel_make_swapover_dir(struct super_block *sb,
						unsigned long *ino);

static ssize_t sel_read_mls(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d",
			   security_mls_enabled(fsi->state));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations sel_mls_ops = {
	.read		= sel_read_mls,
	.llseek		= selinuxfs_lseek,
};

struct policy_load_memory {
	size_t len;
	size_t charge;
	void *data;
	struct selinux_fs_info *fsi;
};

static int sel_open_policy(struct inode *inode, struct file *filp)
{
	struct selinux_fs_info *fsi = inode->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	struct policy_load_memory *plm = NULL;
	int rc;

	rc = selinuxfs_state_access(filp);
	if (rc)
		return rc;
	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	rc = avc_has_perm(current_selinux_state,
			  current_sid(), SECINITSID_SECURITY,
			  SECCLASS_SECURITY, SECURITY__READ_POLICY, NULL);
	if (rc)
		return rc;

	plm = kzalloc_obj(*plm);
	if (!plm)
		return -ENOMEM;
	plm->fsi = fsi;

	mutex_lock(&state->policy_mutex);
	rc = security_policy_size(state, &plm->len);
	if (rc)
		goto err;
	if (plm->len > CONFIG_SECURITY_SELINUX_POLICY_MAX_BYTES) {
		rc = -EFBIG;
		goto err;
	}
	rc = selinuxfs_snapshot_bytes_reserve(fsi, plm->len);
	if (rc)
		goto err;
	plm->charge = plm->len;
	rc = security_read_policy(state, &plm->data, &plm->len,
				  CONFIG_SECURITY_SELINUX_POLICY_MAX_BYTES);
	if (rc)
		goto err;
	if (WARN_ON(plm->len > plm->charge)) {
		rc = -EOVERFLOW;
		goto err;
	}
	selinuxfs_snapshot_bytes_release(fsi, plm->charge - plm->len);
	plm->charge = plm->len;
	mutex_unlock(&state->policy_mutex);

	filp->private_data = plm;
	return 0;
err:
	mutex_unlock(&state->policy_mutex);
	selinuxfs_snapshot_bytes_release(fsi, plm->charge);
	vfree(plm->data);
	kfree(plm);
	return rc;
}

static int sel_release_policy(struct inode *inode, struct file *filp)
{
	struct policy_load_memory *plm = filp->private_data;

	selinuxfs_snapshot_bytes_release(plm->fsi, plm->charge);
	vfree(plm->data);
	kfree(plm);

	return 0;
}

static ssize_t sel_read_policy(struct file *filp, char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct policy_load_memory *plm = filp->private_data;
	int ret = selinuxfs_state_access(filp);

	if (ret)
		return ret;

	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	ret = avc_has_perm(current_selinux_state,
			   current_sid(), SECINITSID_SECURITY,
			   SECCLASS_SECURITY, SECURITY__READ_POLICY, NULL);
	if (ret)
		return ret;

	return simple_read_from_buffer(buf, count, ppos, plm->data, plm->len);
}

static vm_fault_t sel_mmap_policy_fault(struct vm_fault *vmf)
{
	struct file *file = vmf->vma->vm_file;
	struct policy_load_memory *plm = file->private_data;
	unsigned long offset;
	struct page *page;

	if (selinuxfs_state_access(file))
		return VM_FAULT_SIGBUS;
	if (vmf->flags & (FAULT_FLAG_MKWRITE | FAULT_FLAG_WRITE))
		return VM_FAULT_SIGBUS;

	offset = vmf->pgoff << PAGE_SHIFT;
	if (offset >= roundup(plm->len, PAGE_SIZE))
		return VM_FAULT_SIGBUS;

	page = vmalloc_to_page(plm->data + offset);
	get_page(page);

	vmf->page = page;

	return 0;
}

static const struct vm_operations_struct sel_mmap_policy_ops = {
#ifdef CONFIG_SECURITY_SELINUX_NS
	.open = selinuxfs_vma_open,
	.close = selinuxfs_vma_close,
#endif
	.fault = sel_mmap_policy_fault,
	.page_mkwrite = sel_mmap_policy_fault,
};

static int sel_mmap_policy(struct file *filp, struct vm_area_struct *vma)
{
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;
	if (vma->vm_flags & VM_SHARED) {
		/* do not allow mprotect to make mapping writable */
		vm_flags_clear(vma, VM_MAYWRITE);

		if (vma->vm_flags & VM_WRITE)
			return -EACCES;
	}

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
#ifdef CONFIG_SECURITY_SELINUX_NS
	rc = selinuxfs_vma_track_initial(vma);
	if (rc)
		return rc;
#endif
	vma->vm_ops = &sel_mmap_policy_ops;

	return 0;
}

static loff_t sel_lseek_policy(struct file *filp, loff_t offset, int whence)
{
	struct policy_load_memory *plm = filp->private_data;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;
	return fixed_size_llseek(filp, offset, whence, plm->len);
}

static const struct file_operations sel_policy_ops = {
	.open		= sel_open_policy,
	.read		= sel_read_policy,
	.mmap		= sel_mmap_policy,
	.release	= sel_release_policy,
	.llseek		= sel_lseek_policy,
};

static ssize_t sel_read_policy_max_bytes(struct file *filp, char __user *buf,
					 size_t count, loff_t *ppos)
{
	char tmpbuf[32];
	ssize_t length;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;
	length = scnprintf(tmpbuf, sizeof(tmpbuf), "%u",
			   CONFIG_SECURITY_SELINUX_POLICY_MAX_BYTES);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations sel_policy_max_bytes_ops = {
	.read		= sel_read_policy_max_bytes,
	.llseek		= selinuxfs_lseek,
};

static void sel_remove_old_bool_data(unsigned int bool_num, char **bool_names,
				     int *bool_values)
{
	u32 i;

	/* bool_dir cleanup */
	for (i = 0; i < bool_num; i++)
		kfree(bool_names[i]);
	kfree(bool_names);
	kfree(bool_values);
}

static int sel_make_policy_nodes(struct selinux_fs_info *fsi,
				struct selinux_policy *newpolicy)
{
	int ret = 0;
	struct dentry *tmp_parent, *tmp_bool_dir, *tmp_class_dir;
	struct renamedata rd = {};
	unsigned int bool_num = 0;
	char **bool_names = NULL;
	int *bool_values = NULL;
	unsigned long tmp_ino = fsi->last_ino; /* Don't increment last_ino in this function */

	tmp_parent = sel_make_swapover_dir(fsi->sb, &tmp_ino);
	if (IS_ERR(tmp_parent))
		return PTR_ERR(tmp_parent);

	tmp_ino = fsi->bool_dir->d_inode->i_ino - 1; /* sel_make_dir will increment and set */
	tmp_bool_dir = sel_make_dir(tmp_parent, BOOL_DIR_NAME, &tmp_ino);
	if (IS_ERR(tmp_bool_dir)) {
		ret = PTR_ERR(tmp_bool_dir);
		goto out;
	}

	tmp_ino = fsi->class_dir->d_inode->i_ino - 1; /* sel_make_dir will increment and set */
	tmp_class_dir = sel_make_dir(tmp_parent, CLASS_DIR_NAME, &tmp_ino);
	if (IS_ERR(tmp_class_dir)) {
		ret = PTR_ERR(tmp_class_dir);
		goto out;
	}

	ret = sel_make_bools(fsi->state, newpolicy, tmp_bool_dir, &bool_num,
			     &bool_names, &bool_values);
	if (ret)
		goto out;

	ret = sel_make_classes(newpolicy, tmp_class_dir,
			       &fsi->last_class_ino);
	if (ret)
		goto out;

	rd.old_parent = tmp_parent;
	rd.new_parent = fsi->sb->s_root;

	/* booleans */
	ret = start_renaming_two_dentries(&rd, tmp_bool_dir, fsi->bool_dir);
	if (ret)
		goto out;

	d_exchange(tmp_bool_dir, fsi->bool_dir);

	swap(fsi->bool_num, bool_num);
	swap(fsi->bool_pending_names, bool_names);
	swap(fsi->bool_pending_values, bool_values);

	fsi->bool_dir = tmp_bool_dir;
	end_renaming(&rd);

	/* classes */
	ret = start_renaming_two_dentries(&rd, tmp_class_dir, fsi->class_dir);
	if (ret)
		goto out;

	d_exchange(tmp_class_dir, fsi->class_dir);
	fsi->class_dir = tmp_class_dir;

	end_renaming(&rd);

out:
	sel_remove_old_bool_data(bool_num, bool_names, bool_values);
	/* Since the other temporary dirs are children of tmp_parent
	 * this will handle all the cleanup in the case of a failure before
	 * the swapover
	 */
	simple_recursive_removal(tmp_parent, NULL);

	return ret;
}

static ssize_t sel_write_load(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)

{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_load_state load_state;
	ssize_t length;
	void *data = NULL;

	length = selinuxfs_state_access(file);
	if (length)
		return length;
	/* no partial writes */
	if (*ppos)
		return -EINVAL;
	/* no empty policies */
	if (!count)
		return -EINVAL;
	if (count > CONFIG_SECURITY_SELINUX_POLICY_MAX_BYTES) {
		pr_warn_ratelimited("SELinux: policy load size %zu exceeds limit %u\n",
				    count,
				    CONFIG_SECURITY_SELINUX_POLICY_MAX_BYTES);
		return -EFBIG;
	}
	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	length = avc_has_perm(current_selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__LOAD_POLICY, NULL);
	if (length)
		return length;
	/*
	 * Serialize before allocating.  This makes the input accounting exact:
	 * one state can stage at most one buffer, bounded by
	 * CONFIG_SECURITY_SELINUX_POLICY_MAX_BYTES.
	 */
	mutex_lock(&fsi->state->policy_mutex);
	data = vmalloc(count);
	if (!data) {
		length = -ENOMEM;
		goto out_unlock;
	}
	if (copy_from_user(data, buf, count) != 0) {
		length = -EFAULT;
		goto out_unlock;
	}

	length = security_load_policy(fsi->state, data, count, &load_state);
	if (length) {
		pr_warn_ratelimited("SELinux: failed to load policy\n");
		goto out_unlock;
	}
	fsi = file_inode(file)->i_sb->s_fs_info;
	length = sel_make_policy_nodes(fsi, load_state.policy);
	if (length) {
		pr_warn_ratelimited("SELinux: failed to initialize selinuxfs\n");
		selinux_policy_cancel(fsi->state, &load_state);
		goto out_unlock;
	}

	length = selinux_policy_commit(fsi->state, &load_state);
	if (length) {
		selinux_policy_cancel(fsi->state, &load_state);
		goto out_unlock;
	}
	length = count;
	audit_log(audit_context(), GFP_KERNEL, AUDIT_MAC_POLICY_LOAD,
		"auid=%u ses=%u lsm=selinux res=1",
		from_kuid(&init_user_ns, audit_get_loginuid(current)),
		audit_get_sessionid(current));

out_unlock:
	vfree(data);
	mutex_unlock(&fsi->state->policy_mutex);
	return length;
}

static const struct file_operations sel_load_ops = {
	.write		= sel_write_load,
	.llseek		= selinuxfs_lseek,
};

static ssize_t sel_write_context(struct file *file, char *buf, size_t size)
{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	const char *canon = NULL;
	u32 sid, len;
	ssize_t length;

	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	length = avc_has_perm(current_selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);
	if (length)
		goto out;

	length = selinux_ss_context_to_sid(state, buf, size, &sid, GFP_KERNEL);
	if (length)
		goto out;

	rcu_read_lock();
	length = selinux_ss_sid_to_context(state, sid, &canon, &len);
	if (length)
		goto out_unlock;

	length = -ERANGE;
	if (len > SIMPLE_TRANSACTION_LIMIT) {
		pr_err("SELinux: %s:  context size (%u) exceeds "
			"payload max\n", __func__, len);
		goto out_unlock;
	}

	memcpy(buf, canon, len);
	length = len;
out_unlock:
	rcu_read_unlock();
out:
	return length;
}

static ssize_t sel_read_checkreqprot(struct file *filp, char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
			   checkreqprot_get(fsi->state));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static ssize_t sel_write_checkreqprot(struct file *file, const char __user *buf,
				      size_t count, loff_t *ppos)
{
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;

	/*
	 * Setting checkreqprot is no longer supported, see
	 * https://github.com/SELinuxProject/selinux-kernel/wiki/DEPRECATE-checkreqprot
	 */
	pr_err_once("SELinux: %s (%d) wrote to checkreqprot. This is no longer supported.\n",
		    current->comm, current->pid);
	return count;
}
static const struct file_operations sel_checkreqprot_ops = {
	.read		= sel_read_checkreqprot,
	.write		= sel_write_checkreqprot,
	.llseek		= selinuxfs_lseek,
};

static ssize_t sel_write_validatetrans(struct file *file,
					const char __user *buf,
					size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *oldcon = NULL, *newcon = NULL, *taskcon = NULL;
	char *req = NULL;
	u32 osid, nsid, tsid;
	u16 tclass;
	int rc;

	rc = selinuxfs_state_access(file);
	if (rc)
		return rc;

	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	rc = avc_has_perm(current_selinux_state,
			  current_sid(), SECINITSID_SECURITY,
			  SECCLASS_SECURITY, SECURITY__VALIDATE_TRANS, NULL);
	if (rc)
		goto out;

	rc = -ENOMEM;
	if (count >= PAGE_SIZE)
		goto out;

	/* No partial writes. */
	rc = -EINVAL;
	if (*ppos != 0)
		goto out;

	req = memdup_user_nul(buf, count);
	if (IS_ERR(req)) {
		rc = PTR_ERR(req);
		req = NULL;
		goto out;
	}

	rc = -ENOMEM;
	oldcon = kzalloc(count + 1, GFP_KERNEL);
	if (!oldcon)
		goto out;

	newcon = kzalloc(count + 1, GFP_KERNEL);
	if (!newcon)
		goto out;

	taskcon = kzalloc(count + 1, GFP_KERNEL);
	if (!taskcon)
		goto out;

	rc = -EINVAL;
	if (sscanf(req, "%s %s %hu %s", oldcon, newcon, &tclass, taskcon) != 4)
		goto out;

	rc = selinux_ss_context_str_to_sid(state, oldcon, &osid, GFP_KERNEL);
	if (rc)
		goto out;

	rc = selinux_ss_context_str_to_sid(state, newcon, &nsid, GFP_KERNEL);
	if (rc)
		goto out;

	rc = selinux_ss_context_str_to_sid(state, taskcon, &tsid, GFP_KERNEL);
	if (rc)
		goto out;

	rc = selinux_ss_validate_transition_user(state, osid, nsid, tsid, tclass);
	if (!rc)
		rc = count;
out:
	kfree(req);
	kfree(oldcon);
	kfree(newcon);
	kfree(taskcon);
	return rc;
}

static const struct file_operations sel_transition_ops = {
	.write		= sel_write_validatetrans,
	.llseek		= selinuxfs_lseek,
};

/*
 * Remaining nodes use transaction based IO methods like nfsd/nfsctl.c
 */
static ssize_t sel_write_access(struct file *file, char *buf, size_t size);
static ssize_t sel_write_create(struct file *file, char *buf, size_t size);
static ssize_t sel_write_relabel(struct file *file, char *buf, size_t size);
static ssize_t sel_write_user(struct file *file, char *buf, size_t size);
static ssize_t sel_write_member(struct file *file, char *buf, size_t size);

static ssize_t (*const write_op[])(struct file *, char *, size_t) = {
	[SEL_ACCESS] = sel_write_access,
	[SEL_CREATE] = sel_write_create,
	[SEL_RELABEL] = sel_write_relabel,
	[SEL_USER] = sel_write_user,
	[SEL_MEMBER] = sel_write_member,
	[SEL_CONTEXT] = sel_write_context,
};

static ssize_t selinux_transaction_write(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
	ino_t ino = file_inode(file)->i_ino;
	char *data;
	ssize_t rv;

	rv = selinuxfs_state_access(file);
	if (rv)
		return rv;

	if (ino >= ARRAY_SIZE(write_op) || !write_op[ino])
		return -EINVAL;

	data = simple_transaction_get(file, buf, size);
	if (IS_ERR(data))
		return PTR_ERR(data);

	rv = write_op[ino](file, data, size);
	if (rv > 0) {
		simple_transaction_set(file, rv);
		rv = size;
	}
	return rv;
}

static ssize_t selinux_transaction_read(struct file *file, char __user *buf,
					size_t size, loff_t *pos)
{
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;
	return simple_transaction_read(file, buf, size, pos);
}

static const struct file_operations transaction_ops = {
	.write		= selinux_transaction_write,
	.read		= selinux_transaction_read,
	.release	= simple_transaction_release,
	.llseek		= selinuxfs_lseek,
};

/*
 * payload - write methods
 * If the method has a response, the response should be put in buf,
 * and the length returned.  Otherwise return 0 or -error.
 */

static ssize_t sel_write_access(struct file *file, char *buf, size_t size)
{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *scon = NULL, *tcon = NULL;
	u32 ssid, tsid;
	u16 tclass;
	struct av_decision avd;
	ssize_t length;

	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	length = avc_has_perm(current_selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
	if (length)
		goto out;

	length = -ENOMEM;
	scon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon)
		goto out;

	length = -ENOMEM;
	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -EINVAL;
	if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
		goto out;

	length = selinux_ss_context_str_to_sid(state, scon, &ssid, GFP_KERNEL);
	if (length)
		goto out;

	length = selinux_ss_context_str_to_sid(state, tcon, &tsid, GFP_KERNEL);
	if (length)
		goto out;

	selinux_ss_compute_av_user(state, ssid, tsid, tclass, &avd);

	length = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT,
			  "%x %x %x %x %u %x",
			  avd.allowed, 0xffffffff,
			  avd.auditallow, avd.auditdeny,
			  avd.seqno, avd.flags);
out:
	kfree(tcon);
	kfree(scon);
	return length;
}

static ssize_t sel_write_create(struct file *file, char *buf, size_t size)
{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *scon = NULL, *tcon = NULL;
	char *namebuf = NULL, *objname = NULL;
	u32 ssid, tsid, newsid;
	u16 tclass;
	ssize_t length;
	const char *newcon = NULL;
	u32 len;
	int nargs;

	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	length = avc_has_perm(current_selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__COMPUTE_CREATE,
			      NULL);
	if (length)
		goto out;

	length = -ENOMEM;
	scon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon)
		goto out;

	length = -ENOMEM;
	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -ENOMEM;
	namebuf = kzalloc(size + 1, GFP_KERNEL);
	if (!namebuf)
		goto out;

	length = -EINVAL;
	nargs = sscanf(buf, "%s %s %hu %s", scon, tcon, &tclass, namebuf);
	if (nargs < 3 || nargs > 4)
		goto out;
	if (nargs == 4) {
		/*
		 * If and when the name of new object to be queried contains
		 * either whitespace or multibyte characters, they shall be
		 * encoded based on the percentage-encoding rule.
		 * If not encoded, the sscanf logic picks up only left-half
		 * of the supplied name; split by a whitespace unexpectedly.
		 */
		char   *r, *w;
		int     c1, c2;

		r = w = namebuf;
		do {
			c1 = *r++;
			if (c1 == '+')
				c1 = ' ';
			else if (c1 == '%') {
				c1 = hex_to_bin(*r++);
				if (c1 < 0)
					goto out;
				c2 = hex_to_bin(*r++);
				if (c2 < 0)
					goto out;
				c1 = (c1 << 4) | c2;
			}
			*w++ = c1;
		} while (c1 != '\0');

		objname = namebuf;
	}

	length = selinux_ss_context_str_to_sid(state, scon, &ssid, GFP_KERNEL);
	if (length)
		goto out;

	length = selinux_ss_context_str_to_sid(state, tcon, &tsid, GFP_KERNEL);
	if (length)
		goto out;

	length = selinux_ss_transition_sid_user(state, ssid, tsid, tclass,
					      objname, &newsid);
	if (length)
		goto out;

	rcu_read_lock();
	length = selinux_ss_sid_to_context(state, newsid, &newcon, &len);
	if (length)
		goto out_unlock;

	length = -ERANGE;
	if (len > SIMPLE_TRANSACTION_LIMIT) {
		pr_err("SELinux: %s:  context size (%u) exceeds "
			"payload max\n", __func__, len);
		goto out_unlock;
	}

	memcpy(buf, newcon, len);
	length = len;
out_unlock:
	rcu_read_unlock();
out:
	kfree(namebuf);
	kfree(tcon);
	kfree(scon);
	return length;
}

static ssize_t sel_write_relabel(struct file *file, char *buf, size_t size)
{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *scon = NULL, *tcon = NULL;
	u32 ssid, tsid, newsid;
	u16 tclass;
	ssize_t length;
	const char *newcon = NULL;
	u32 len;

	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	length = avc_has_perm(current_selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__COMPUTE_RELABEL,
			      NULL);
	if (length)
		goto out;

	length = -ENOMEM;
	scon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon)
		goto out;

	length = -ENOMEM;
	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -EINVAL;
	if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
		goto out;

	length = selinux_ss_context_str_to_sid(state, scon, &ssid, GFP_KERNEL);
	if (length)
		goto out;

	length = selinux_ss_context_str_to_sid(state, tcon, &tsid, GFP_KERNEL);
	if (length)
		goto out;

	length = selinux_ss_change_sid(state, ssid, tsid, tclass, &newsid);
	if (length)
		goto out;

	rcu_read_lock();
	length = selinux_ss_sid_to_context(state, newsid, &newcon, &len);
	if (length)
		goto out_unlock;

	length = -ERANGE;
	if (len > SIMPLE_TRANSACTION_LIMIT)
		goto out_unlock;

	memcpy(buf, newcon, len);
	length = len;
out_unlock:
	rcu_read_unlock();
out:
	kfree(tcon);
	kfree(scon);
	return length;
}

static ssize_t sel_write_user(struct file *file, char *buf, size_t size)
{
	pr_err_once("SELinux: %s (%d) wrote to user. This is no longer supported.\n",
		    current->comm, current->pid);
	buf[0] = '0';
	buf[1] = 0;
	return 2;
}

static ssize_t sel_write_member(struct file *file, char *buf, size_t size)
{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *scon = NULL, *tcon = NULL;
	u32 ssid, tsid, newsid;
	u16 tclass;
	ssize_t length;
	const char *newcon = NULL;
	u32 len;

	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	length = avc_has_perm(current_selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__COMPUTE_MEMBER,
			      NULL);
	if (length)
		goto out;

	length = -ENOMEM;
	scon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon)
		goto out;

	length = -ENOMEM;
	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -EINVAL;
	if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
		goto out;

	length = selinux_ss_context_str_to_sid(state, scon, &ssid, GFP_KERNEL);
	if (length)
		goto out;

	length = selinux_ss_context_str_to_sid(state, tcon, &tsid, GFP_KERNEL);
	if (length)
		goto out;

	length = selinux_ss_member_sid(state, ssid, tsid, tclass, &newsid);
	if (length)
		goto out;

	rcu_read_lock();
	length = selinux_ss_sid_to_context(state, newsid, &newcon, &len);
	if (length)
		goto out_unlock;

	length = -ERANGE;
	if (len > SIMPLE_TRANSACTION_LIMIT) {
		pr_err("SELinux: %s:  context size (%u) exceeds "
			"payload max\n", __func__, len);
		goto out_unlock;
	}

	memcpy(buf, newcon, len);
	length = len;
out_unlock:
	rcu_read_unlock();
out:
	kfree(tcon);
	kfree(scon);
	return length;
}

static struct inode *sel_make_inode(struct super_block *sb, umode_t mode)
{
	struct inode *ret = new_inode(sb);

	if (ret) {
		ret->i_mode = mode;
		simple_inode_init_ts(ret);
	}
	return ret;
}

static struct dentry *sel_attach(struct dentry *parent, const char *name,
				 struct inode *inode)
{
	struct dentry *dentry = d_alloc_name(parent, name);
	if (unlikely(!dentry)) {
		iput(inode);
		return ERR_PTR(-ENOMEM);
	}
	d_make_persistent(dentry, inode);
	dput(dentry);
	return dentry;
}

static int sel_attach_file(struct dentry *parent, const char *name,
			   struct inode *inode)
{
	struct dentry *dentry = sel_attach(parent, name, inode);
	return PTR_ERR_OR_ZERO(dentry);
}

static ssize_t sel_read_bool(struct file *filep, char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filep)->i_sb->s_fs_info;
	char buffer[4];
	ssize_t length;
	ssize_t ret;
	int cur_enforcing;
	unsigned index = file_inode(filep)->i_ino & SEL_INO_MASK;
	const char *name = filep->f_path.dentry->d_name.name;

	ret = selinuxfs_state_access(filep);
	if (ret)
		return ret;
	mutex_lock(&fsi->state->policy_mutex);

	ret = -EINVAL;
	if (index >= fsi->bool_num || strcmp(name,
					     fsi->bool_pending_names[index]))
		goto out_unlock;

	cur_enforcing = security_get_bool_value(fsi->state, index);
	if (cur_enforcing < 0) {
		ret = cur_enforcing;
		goto out_unlock;
	}
	length = scnprintf(buffer, sizeof(buffer), "%d %d", !!cur_enforcing,
			  !!fsi->bool_pending_values[index]);
	mutex_unlock(&fsi->state->policy_mutex);
	return simple_read_from_buffer(buf, count, ppos, buffer, length);

out_unlock:
	mutex_unlock(&fsi->state->policy_mutex);
	return ret;
}

static ssize_t sel_write_bool(struct file *filep, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filep)->i_sb->s_fs_info;
	char *page = NULL;
	ssize_t length;
	int new_value;
	unsigned index = file_inode(filep)->i_ino & SEL_INO_MASK;
	const char *name = filep->f_path.dentry->d_name.name;

	length = selinuxfs_state_access(filep);
	if (length)
		return length;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	mutex_lock(&fsi->state->policy_mutex);

	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	length = avc_has_perm(current_selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__SETBOOL,
			      NULL);
	if (length)
		goto out;

	length = -EINVAL;
	if (index >= fsi->bool_num || strcmp(name,
					     fsi->bool_pending_names[index]))
		goto out;

	length = -EINVAL;
	if (sscanf(page, "%d", &new_value) != 1)
		goto out;

	if (new_value)
		new_value = 1;

	fsi->bool_pending_values[index] = new_value;
	length = count;

out:
	mutex_unlock(&fsi->state->policy_mutex);
	kfree(page);
	return length;
}

static const struct file_operations sel_bool_ops = {
	.read		= sel_read_bool,
	.write		= sel_write_bool,
	.llseek		= selinuxfs_lseek,
};

static ssize_t sel_commit_bools_write(struct file *filep,
				      const char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filep)->i_sb->s_fs_info;
	char *page = NULL;
	ssize_t length;
	int new_value;

	length = selinuxfs_state_access(filep);
	if (length)
		return length;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	mutex_lock(&fsi->state->policy_mutex);

	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	length = avc_has_perm(current_selinux_state,
			      current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__SETBOOL,
			      NULL);
	if (length)
		goto out;

	length = -EINVAL;
	if (sscanf(page, "%d", &new_value) != 1)
		goto out;

	length = 0;
	if (new_value && fsi->bool_pending_values)
		length = security_set_bools(fsi->state, fsi->bool_num,
					    fsi->bool_pending_values);

	if (!length)
		length = count;

out:
	mutex_unlock(&fsi->state->policy_mutex);
	kfree(page);
	return length;
}

static const struct file_operations sel_commit_bools_ops = {
	.write		= sel_commit_bools_write,
	.llseek		= selinuxfs_lseek,
};

static int sel_make_bools(struct selinux_state *state,
			  struct selinux_policy *newpolicy,
			  struct dentry *bool_dir,
			  unsigned int *bool_num, char ***bool_pending_names,
			  int **bool_pending_values)
{
	int ret;
	char **names, *page;
	u32 i, num;

	page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	ret = security_get_bools(newpolicy, &num, &names, bool_pending_values);
	if (ret)
		goto out;

	*bool_num = num;
	*bool_pending_names = names;

	for (i = 0; !ret && i < num; i++) {
		struct inode *inode;
		struct inode_security_struct *isec;
		ssize_t len;
		u32 sid;
#ifdef CONFIG_SECURITY_SELINUX_NS
		struct selinux_global_sid_handle *sid_handle;
		enum selinux_label_source source = SELINUX_LABEL_SOURCE_GENFS;
		u16 sclass = SECCLASS_FILE;
#endif

		len = snprintf(page, PAGE_SIZE, "/%s/%s", BOOL_DIR_NAME, names[i]);
		if (len >= PAGE_SIZE) {
			ret = -ENAMETOOLONG;
			break;
		}

		inode = sel_make_inode(bool_dir->d_sb, S_IFREG | S_IRUGO | S_IWUSR);
		if (!inode) {
			ret = -ENOMEM;
			break;
		}

		isec = selinux_inode(inode);
#ifdef CONFIG_SECURITY_SELINUX_NS
		sid_handle = selinux_policy_genfs_sid_handle(
			state, newpolicy, "selinuxfs", page, sclass, &sid);
		if (IS_ERR(sid_handle) && PTR_ERR(sid_handle) == -ENOENT) {
			pr_warn_ratelimited("SELinux: no sid found, defaulting to security isid for %s\n",
					   page);
			sid = SECINITSID_SECURITY;
			source = SELINUX_LABEL_SOURCE_KERNEL_INITIAL;
			sid_handle = global_sid_handle_get(sid);
		}
		if (IS_ERR(sid_handle)) {
			ret = PTR_ERR(sid_handle);
			iput(inode);
			break;
		}
		ret = selinux_inode_security_take_sid_handle(
			isec, sid_handle, &sclass, source, LABEL_INITIALIZED);
		if (ret) {
			iput(inode);
			break;
		}
#else
		ret = selinux_policy_genfs_sid(state, newpolicy, "selinuxfs", page,
					 SECCLASS_FILE, &sid);
		if (ret == -ENOENT) {
			pr_warn_ratelimited("SELinux: no sid found, defaulting to security isid for %s\n",
					   page);
			sid = SECINITSID_SECURITY;
			ret = 0;
		} else if (ret) {
			iput(inode);
			break;
		}

		isec->sid = sid;
		isec->initialized = LABEL_INITIALIZED;
#endif
		inode->i_fop = &sel_bool_ops;
		inode->i_ino = i|SEL_BOOL_INO_OFFSET;

		ret = sel_attach_file(bool_dir, names[i], inode);
	}
out:
	kfree(page);
	return ret;
}

static ssize_t sel_read_avc_cache_threshold(struct file *filp, char __user *buf,
					    size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
			   avc_get_cache_threshold(state->avc));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static ssize_t sel_write_avc_cache_threshold(struct file *file,
					     const char __user *buf,
					     size_t count, loff_t *ppos)

{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *page;
	ssize_t ret;
	unsigned int new_value;

	ret = selinuxfs_state_access(file);
	if (ret)
		return ret;

	/*
	 * Only check against the current namespace because
	 * this operation only affects it and no others.
	 */
	ret = avc_has_perm(current_selinux_state,
			   current_sid(), SECINITSID_SECURITY,
			   SECCLASS_SECURITY, SECURITY__SETSECPARAM,
			   NULL);
	if (ret)
		return ret;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	ret = -EINVAL;
	if (sscanf(page, "%u", &new_value) != 1)
		goto out;

	ret = avc_set_cache_threshold(state->avc, new_value);
	if (ret)
		goto out;

	ret = count;
out:
	kfree(page);
	return ret;
}

static ssize_t sel_read_avc_hash_stats(struct file *filp, char __user *buf,
				       size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *page;
	ssize_t length;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;

	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	length = avc_get_hash_stats(state->avc, page);
	if (length >= 0)
		length = simple_read_from_buffer(buf, count, ppos, page, length);
	kfree(page);

	return length;
}

static ssize_t sel_read_sidtab_hash_stats(struct file *filp, char __user *buf,
					size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
	struct selinux_state *state = fsi->state;
	char *page;
	ssize_t length;
	int rc = selinuxfs_state_access(filp);

	if (rc)
		return rc;

	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	length = security_sidtab_hash_stats(state, page);
	if (length >= 0)
		length = simple_read_from_buffer(buf, count, ppos, page,
						length);
	kfree(page);

	return length;
}

static const struct file_operations sel_sidtab_hash_stats_ops = {
	.read		= sel_read_sidtab_hash_stats,
	.llseek		= selinuxfs_lseek,
};

static const struct file_operations sel_avc_cache_threshold_ops = {
	.read		= sel_read_avc_cache_threshold,
	.write		= sel_write_avc_cache_threshold,
	.llseek		= selinuxfs_lseek,
};

static const struct file_operations sel_avc_hash_stats_ops = {
	.read		= sel_read_avc_hash_stats,
	.llseek		= selinuxfs_lseek,
};

#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
static struct avc_cache_stats *sel_avc_get_stat_idx(loff_t *idx)
{
	loff_t cpu;

	for (cpu = *idx; cpu < nr_cpu_ids; ++cpu) {
		if (!cpu_possible(cpu))
			continue;
		*idx = cpu + 1;
		return &per_cpu(avc_cache_stats, cpu);
	}
	(*idx)++;
	return NULL;
}

static void *sel_avc_stats_seq_start(struct seq_file *seq, loff_t *pos)
{
	loff_t n = *pos - 1;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	return sel_avc_get_stat_idx(&n);
}

static void *sel_avc_stats_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return sel_avc_get_stat_idx(pos);
}

static int sel_avc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct avc_cache_stats *st = v;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq,
			 "lookups hits misses allocations reclaims frees\n");
	} else {
		unsigned int lookups = st->lookups;
		unsigned int misses = st->misses;
		unsigned int hits = lookups - misses;
		seq_printf(seq, "%u %u %u %u %u %u\n", lookups,
			   hits, misses, st->allocations,
			   st->reclaims, st->frees);
	}
	return 0;
}

static void sel_avc_stats_seq_stop(struct seq_file *seq, void *v)
{ }

static const struct seq_operations sel_avc_cache_stats_seq_ops = {
	.start		= sel_avc_stats_seq_start,
	.next		= sel_avc_stats_seq_next,
	.show		= sel_avc_stats_seq_show,
	.stop		= sel_avc_stats_seq_stop,
};

static int sel_open_avc_cache_stats(struct inode *inode, struct file *file)
{
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;
	return seq_open(file, &sel_avc_cache_stats_seq_ops);
}

static ssize_t sel_read_avc_cache_stats(struct file *file, char __user *buf,
					size_t size, loff_t *ppos)
{
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;
	return seq_read(file, buf, size, ppos);
}

static loff_t sel_lseek_avc_cache_stats(struct file *file, loff_t offset,
					int whence)
{
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;
	return seq_lseek(file, offset, whence);
}

static const struct file_operations sel_avc_cache_stats_ops = {
	.open		= sel_open_avc_cache_stats,
	.read		= sel_read_avc_cache_stats,
	.llseek		= sel_lseek_avc_cache_stats,
	.release	= seq_release,
};
#endif

static int sel_make_avc_files(struct dentry *dir)
{
	struct super_block *sb = dir->d_sb;
	struct selinux_fs_info *fsi = sb->s_fs_info;
	unsigned int i;
	int err = 0;
	static const struct tree_descr files[] = {
		{ "cache_threshold",
		  &sel_avc_cache_threshold_ops, S_IRUGO|S_IWUSR },
		{ "hash_stats", &sel_avc_hash_stats_ops, S_IRUGO },
#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
		{ "cache_stats", &sel_avc_cache_stats_ops, S_IRUGO },
#endif
	};

	for (i = 0; !err && i < ARRAY_SIZE(files); i++) {
		struct inode *inode;

		inode = sel_make_inode(dir->d_sb, S_IFREG|files[i].mode);
		if (!inode)
			return -ENOMEM;

		inode->i_fop = files[i].ops;
		inode->i_ino = ++fsi->last_ino;

		err = sel_attach_file(dir, files[i].name, inode);
	}

	return err;
}

static int sel_make_ss_files(struct dentry *dir)
{
	struct super_block *sb = dir->d_sb;
	struct selinux_fs_info *fsi = sb->s_fs_info;
	unsigned int i;
	int err = 0;
	static const struct tree_descr files[] = {
		{ "sidtab_hash_stats", &sel_sidtab_hash_stats_ops, S_IRUGO },
	};

	for (i = 0; !err && i < ARRAY_SIZE(files); i++) {
		struct inode *inode;

		inode = sel_make_inode(dir->d_sb, S_IFREG|files[i].mode);
		if (!inode)
			return -ENOMEM;

		inode->i_fop = files[i].ops;
		inode->i_ino = ++fsi->last_ino;

		err = sel_attach_file(dir, files[i].name, inode);
	}

	return err;
}

static ssize_t sel_read_initcon(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	const char *con;
	char *con2;
	u32 sid, len;
	ssize_t ret;

	ret = selinuxfs_state_access(file);
	if (ret)
		return ret;
	sid = file_inode(file)->i_ino&SEL_INO_MASK;
	rcu_read_lock();
	ret = selinux_ss_sid_to_context(fsi->state, sid, &con, &len);
	if (ret)
		goto err;
	con2 = kmemdup(con, len, GFP_ATOMIC);
	if (!con2) {
		ret = -ENOMEM;
		goto err;
	}
	rcu_read_unlock();

	ret = simple_read_from_buffer(buf, count, ppos, con2, len);
	kfree(con2);
	return ret;
err:
	rcu_read_unlock();
	return ret;
}

static const struct file_operations sel_initcon_ops = {
	.read		= sel_read_initcon,
	.llseek		= selinuxfs_lseek,
};

static int sel_make_initcon_files(struct dentry *dir)
{
	unsigned int i;
	int err = 0;

	for (i = 1; !err && i <= SECINITSID_NUM; i++) {
		const char *s = security_get_initial_sid_context(i);
		struct inode *inode;

		if (!s)
			continue;

		inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
		if (!inode)
			return -ENOMEM;

		inode->i_fop = &sel_initcon_ops;
		inode->i_ino = i|SEL_INITCON_INO_OFFSET;
		err = sel_attach_file(dir, s, inode);
	}

	return err;
}

static inline unsigned long sel_class_to_ino(u16 class)
{
	return (class * (SEL_VEC_MAX + 1)) | SEL_CLASS_INO_OFFSET;
}

static inline u16 sel_ino_to_class(unsigned long ino)
{
	return (ino & SEL_INO_MASK) / (SEL_VEC_MAX + 1);
}

static inline unsigned long sel_perm_to_ino(u16 class, u32 perm)
{
	return (class * (SEL_VEC_MAX + 1) + perm) | SEL_CLASS_INO_OFFSET;
}

static inline u32 sel_ino_to_perm(unsigned long ino)
{
	return (ino & SEL_INO_MASK) % (SEL_VEC_MAX + 1);
}

static ssize_t sel_read_class(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	unsigned long ino = file_inode(file)->i_ino;
	char res[TMPBUFLEN];
	ssize_t len;
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;
	len = scnprintf(res, sizeof(res), "%d", sel_ino_to_class(ino));
	return simple_read_from_buffer(buf, count, ppos, res, len);
}

static const struct file_operations sel_class_ops = {
	.read		= sel_read_class,
	.llseek		= selinuxfs_lseek,
};

static ssize_t sel_read_perm(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	unsigned long ino = file_inode(file)->i_ino;
	char res[TMPBUFLEN];
	ssize_t len;
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;
	len = scnprintf(res, sizeof(res), "%d", sel_ino_to_perm(ino));
	return simple_read_from_buffer(buf, count, ppos, res, len);
}

static const struct file_operations sel_perm_ops = {
	.read		= sel_read_perm,
	.llseek		= selinuxfs_lseek,
};

static ssize_t sel_read_policycap(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct selinux_fs_info *fsi = file_inode(file)->i_sb->s_fs_info;
	int value;
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	unsigned long i_ino = file_inode(file)->i_ino;
	int rc = selinuxfs_state_access(file);

	if (rc)
		return rc;

	value = security_policycap_supported(fsi->state, i_ino & SEL_INO_MASK);
	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", value);

	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations sel_policycap_ops = {
	.read		= sel_read_policycap,
	.llseek		= selinuxfs_lseek,
};

static int sel_make_perm_files(struct selinux_policy *newpolicy,
			char *objclass, int classvalue,
			struct dentry *dir)
{
	u32 i, nperms;
	int rc;
	char **perms;

	rc = security_get_permissions(newpolicy, objclass, &perms, &nperms);
	if (rc)
		return rc;

	for (i = 0; !rc && i < nperms; i++) {
		struct inode *inode;

		inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
		if (!inode) {
			rc = -ENOMEM;
			break;
		}

		inode->i_fop = &sel_perm_ops;
		/* i+1 since perm values are 1-indexed */
		inode->i_ino = sel_perm_to_ino(classvalue, i + 1);

		rc = sel_attach_file(dir, perms[i], inode);
	}
	for (i = 0; i < nperms; i++)
		kfree(perms[i]);
	kfree(perms);
	return rc;
}

static int sel_make_class_dir_entries(struct selinux_policy *newpolicy,
				char *classname, int index,
				struct dentry *dir)
{
	struct super_block *sb = dir->d_sb;
	struct selinux_fs_info *fsi = sb->s_fs_info;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;
	int err;

	inode = sel_make_inode(dir->d_sb, S_IFREG|S_IRUGO);
	if (!inode)
		return -ENOMEM;

	inode->i_fop = &sel_class_ops;
	inode->i_ino = sel_class_to_ino(index);

	err = sel_attach_file(dir, "index", inode);
	if (err)
		return err;

	dentry = sel_make_dir(dir, "perms", &fsi->last_class_ino);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	return sel_make_perm_files(newpolicy, classname, index, dentry);
}

static int sel_make_classes(struct selinux_policy *newpolicy,
			    struct dentry *class_dir,
			    unsigned long *last_class_ino)
{
	u32 i, nclasses;
	int rc;
	char **classes;

	rc = security_get_classes(newpolicy, &classes, &nclasses);
	if (rc)
		return rc;

	/* +2 since classes are 1-indexed */
	*last_class_ino = sel_class_to_ino(nclasses + 2);

	for (i = 0; i < nclasses; i++) {
		struct dentry *class_name_dir;

		class_name_dir = sel_make_dir(class_dir, classes[i],
					      last_class_ino);
		if (IS_ERR(class_name_dir)) {
			rc = PTR_ERR(class_name_dir);
			goto out;
		}

		/* i+1 since class values are 1-indexed */
		rc = sel_make_class_dir_entries(newpolicy, classes[i], i + 1,
				class_name_dir);
		if (rc)
			goto out;
	}
	rc = 0;
out:
	for (i = 0; i < nclasses; i++)
		kfree(classes[i]);
	kfree(classes);
	return rc;
}

static int sel_make_policycap(struct dentry *dir)
{
	struct super_block *sb = dir->d_sb;
	unsigned int iter;
	struct inode *inode = NULL;
	int err = 0;

	for (iter = 0; !err && iter <= POLICYDB_CAP_MAX; iter++) {
		const char *name;

		if (iter < ARRAY_SIZE(selinux_policycap_names))
			name = selinux_policycap_names[iter];
		else
			name = "unknown";

		inode = sel_make_inode(sb, S_IFREG | 0444);
		if (!inode)
			return -ENOMEM;

		inode->i_fop = &sel_policycap_ops;
		inode->i_ino = iter | SEL_POLICYCAP_INO_OFFSET;
		err = sel_attach_file(dir, name, inode);
	}

	return err;
}

static struct dentry *sel_make_dir(struct dentry *dir, const char *name,
			unsigned long *ino)
{
	struct inode *inode;

	inode = sel_make_inode(dir->d_sb, S_IFDIR | S_IRUGO | S_IXUGO);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &selinuxfs_dir_operations;
	inode->i_ino = ++(*ino);
	/* directory inodes start off with i_nlink == 2 (for "." entry) */
	inc_nlink(inode);
	/* bump link count on parent directory, too */
	inc_nlink(d_inode(dir));

	return sel_attach(dir, name, inode);
}

static int reject_all(struct mnt_idmap *idmap, struct inode *inode, int mask)
{
	return -EPERM;	// no access for anyone, root or no root.
}

static const struct inode_operations swapover_dir_inode_operations = {
	.lookup		= simple_lookup,
	.permission	= reject_all,
};

static struct dentry *sel_make_swapover_dir(struct super_block *sb,
						unsigned long *ino)
{
	struct dentry *dentry;
	struct inode *inode;

	inode = sel_make_inode(sb, S_IFDIR);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	dentry = simple_start_creating(sb->s_root, ".swapover");
	if (IS_ERR(dentry)) {
		iput(inode);
		return dentry;
	}

	inode->i_op = &swapover_dir_inode_operations;
	inode->i_ino = ++(*ino);
	/* directory inodes start off with i_nlink == 2 (for "." entry) */
	inc_nlink(inode);
	d_make_persistent(dentry, inode);
	inc_nlink(sb->s_root->d_inode);
	simple_done_creating(dentry);
	return dentry;	// borrowed
}

#define NULL_FILE_NAME "null"

static int sel_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct selinux_fs_info *fsi;
	int ret;
	struct dentry *dentry;
	struct inode *inode;
	struct inode_security_struct *isec;

	static const struct tree_descr selinux_files[] = {
		[SEL_LOAD] = {"load", &sel_load_ops, S_IRUSR|S_IWUSR},
		[SEL_ENFORCE] = {"enforce", &sel_enforce_ops, S_IRUGO|S_IWUSR},
		[SEL_CONTEXT] = {"context", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_ACCESS] = {"access", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_CREATE] = {"create", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_RELABEL] = {"relabel", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_USER] = {"user", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_POLICYVERS] = {"policyvers", &sel_policyvers_ops, S_IRUGO},
		[SEL_COMMIT_BOOLS] = {"commit_pending_bools", &sel_commit_bools_ops, S_IWUSR},
		[SEL_MLS] = {"mls", &sel_mls_ops, S_IRUGO},
		[SEL_DISABLE] = {"disable", &sel_disable_ops, S_IWUSR},
		[SEL_MEMBER] = {"member", &transaction_ops, S_IRUGO|S_IWUGO},
		[SEL_CHECKREQPROT] = {"checkreqprot", &sel_checkreqprot_ops, S_IRUGO|S_IWUSR},
		[SEL_REJECT_UNKNOWN] = {"reject_unknown", &sel_handle_unknown_ops, S_IRUGO},
		[SEL_DENY_UNKNOWN] = {"deny_unknown", &sel_handle_unknown_ops, S_IRUGO},
		[SEL_STATUS] = {"status", &sel_handle_status_ops, S_IRUGO},
		[SEL_POLICY] = {"policy", &sel_policy_ops, S_IRUGO},
		[SEL_VALIDATE_TRANS] = {"validatetrans", &sel_transition_ops,
					S_IWUGO},
#ifdef CONFIG_SECURITY_SELINUX_NS
		[SEL_MAXNS] = {"maxns", &sel_maxns_ops, 0600},
		[SEL_MAXNSDEPTH] = {"maxnsdepth", &sel_maxnsdepth_ops, 0600},
		[SEL_NS_CREATE] = {"ns_create", &selinux_ns_create_ops, 0600},
#endif
		[SEL_POLICY_MAX_BYTES] = {"policy_max_bytes",
					  &sel_policy_max_bytes_ops, 0444},
		/* last one */ {"", NULL, 0}
	};

	ret = simple_fill_super(sb, SELINUX_MAGIC, selinux_files);
	if (ret)
		goto err;
	sb->s_root->d_inode->i_fop = &selinuxfs_dir_operations;

	fsi = sb->s_fs_info;
	fsi->sb = sb;
	fsi->bool_dir = sel_make_dir(sb->s_root, BOOL_DIR_NAME, &fsi->last_ino);
	if (IS_ERR(fsi->bool_dir)) {
		ret = PTR_ERR(fsi->bool_dir);
		fsi->bool_dir = NULL;
		goto err;
	}

	ret = -ENOMEM;
	inode = sel_make_inode(sb, S_IFCHR | S_IRUGO | S_IWUGO);
	if (!inode)
		goto err;

	inode->i_ino = ++fsi->last_ino;
	isec = selinux_inode(inode);
#ifdef CONFIG_SECURITY_SELINUX_NS
	{
		struct selinux_global_sid_handle *sid_handle;
		u16 sclass = SECCLASS_CHR_FILE;

		sid_handle = global_sid_handle_get(SECINITSID_DEVNULL);
		if (IS_ERR(sid_handle)) {
			ret = PTR_ERR(sid_handle);
			iput(inode);
			goto err;
		}
		if (global_sid_handle_sid(sid_handle) != SECINITSID_DEVNULL) {
			global_sid_handle_put(sid_handle);
			ret = -ESTALE;
			iput(inode);
			goto err;
		}
		ret = selinux_inode_security_take_sid_handle(
			isec, sid_handle, &sclass,
			SELINUX_LABEL_SOURCE_KERNEL_INITIAL, LABEL_INITIALIZED);
		if (ret) {
			iput(inode);
			goto err;
		}
	}
#else
	isec->sid = SECINITSID_DEVNULL;
	isec->sclass = SECCLASS_CHR_FILE;
	isec->initialized = LABEL_INITIALIZED;
#endif

	init_special_inode(inode, S_IFCHR | S_IRUGO | S_IWUGO, MKDEV(MEM_MAJOR, 3));
	ret = sel_attach_file(sb->s_root, NULL_FILE_NAME, inode);
	if (ret)
		goto err;

	dentry = sel_make_dir(sb->s_root, "avc", &fsi->last_ino);
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		goto err;
	}

	ret = sel_make_avc_files(dentry);
	if (ret)
		goto err;

	dentry = sel_make_dir(sb->s_root, "ss", &fsi->last_ino);
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		goto err;
	}

	ret = sel_make_ss_files(dentry);
	if (ret)
		goto err;

	dentry = sel_make_dir(sb->s_root, "initial_contexts", &fsi->last_ino);
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		goto err;
	}

	ret = sel_make_initcon_files(dentry);
	if (ret)
		goto err;

	fsi->class_dir = sel_make_dir(sb->s_root, CLASS_DIR_NAME, &fsi->last_ino);
	if (IS_ERR(fsi->class_dir)) {
		ret = PTR_ERR(fsi->class_dir);
		fsi->class_dir = NULL;
		goto err;
	}

	dentry = sel_make_dir(sb->s_root, "policy_capabilities", &fsi->last_ino);
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		goto err;
	}

	ret = sel_make_policycap(dentry);
	if (ret) {
		pr_err("SELinux: failed to load policy capabilities\n");
		goto err;
	}

	return 0;
err:
	pr_err("SELinux: %s:  failed while creating inodes\n",
		__func__);

	return ret;
}

static int selinuxfs_compare(struct super_block *sb, struct fs_context *fc)
{
	struct selinux_fs_info *fsi = sb->s_fs_info;

	return (current_selinux_state == fsi->state);
}

static int sel_get_tree(struct fs_context *fc)
{
	struct selinux_fs_info *fsi;
	struct super_block *sb;
	int err;

	fsi = selinux_fs_info_create();
	if (!fsi)
		return -ENOMEM;

	fc->s_fs_info = fsi;
	sb = sget_fc(fc, selinuxfs_compare, set_anon_super_fc);
	if (IS_ERR(sb))
		return PTR_ERR(sb);

	if (!sb->s_root) {
		err = sel_fill_super(sb, fc);
		if (err) {
			deactivate_locked_super(sb);
			return err;
		}
		sb->s_flags |= SB_ACTIVE;
	}

	fc->root = dget(sb->s_root);
	return 0;
}

static void sel_free_fs_context(struct fs_context *fc)
{
	selinux_fs_info_free(fc->s_fs_info);
}

static const struct fs_context_operations sel_context_ops = {
	.free		= sel_free_fs_context,
	.get_tree	= sel_get_tree,
};

static int sel_init_fs_context(struct fs_context *fc)
{
	fc->ops = &sel_context_ops;
	return 0;
}

static void sel_kill_sb(struct super_block *sb)
{
	struct selinux_fs_info *fsi = sb->s_fs_info;

	kill_anon_super(sb);
	selinux_fs_info_free(fsi);
}

static struct file_system_type sel_fs_type = {
	.name		= "selinuxfs",
	.init_fs_context = sel_init_fs_context,
	.kill_sb	= sel_kill_sb,
#ifdef CONFIG_SECURITY_SELINUX_NS
	.fs_flags	= FS_USERNS_MOUNT,
#endif
};

struct path selinux_null __ro_after_init;

int __init init_sel_fs(void)
{
	struct qstr null_name = QSTR(NULL_FILE_NAME);
	int err;

	if (!selinux_enabled_boot)
		return 0;

#ifdef CONFIG_SECURITY_SELINUX_NS
	err = selinuxfs_mm_vmas_init();
	if (err)
		return err;
#endif

	err = sysfs_create_mount_point(fs_kobj, "selinux");
	if (err)
		return err;

	err = register_filesystem(&sel_fs_type);
	if (err) {
		sysfs_remove_mount_point(fs_kobj, "selinux");
		return err;
	}

	selinux_null.mnt = kern_mount(&sel_fs_type);
	if (IS_ERR(selinux_null.mnt)) {
		pr_err("selinuxfs:  could not mount!\n");
		err = PTR_ERR(selinux_null.mnt);
		selinux_null.mnt = NULL;
		return err;
	}

	selinux_null.dentry = try_lookup_noperm(&null_name,
						  selinux_null.mnt->mnt_root);
	if (IS_ERR(selinux_null.dentry)) {
		pr_err("selinuxfs:  could not lookup null!\n");
		err = PTR_ERR(selinux_null.dentry);
		selinux_null.dentry = NULL;
		return err;
	}

	/*
	 * Try to pre-allocate the status page, so the sequence number of the
	 * initial policy load can be stored.
	 */
	(void) selinux_kernel_status_page(current_selinux_state);

	return err;
}
