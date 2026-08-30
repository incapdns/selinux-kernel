// SPDX-License-Identifier: GPL-2.0-only
/* Focused tests for sealed SELinux inode-create transactions. */

#include <kunit/test.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mount.h>
#include <linux/ramfs.h>
#include <linux/security.h>
#include <linux/xattr.h>

#include "include/avc.h"
#include "include/global_sidtab.h"
#include "include/objsec.h"
#include "include/resource.h"

KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_kern_unmount, kern_unmount,
			    struct vfsmount *);
KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_dput, dput, struct dentry *);
KUNIT_DEFINE_ACTION_WRAPPER(selinux_test_iput, iput, struct inode *);

static void selinux_test_create_plan_unforce(void *unused)
{
	selinux_kunit_inode_create_plan_force(false);
}

static void selinux_test_create_plan_force(struct kunit *test)
{
	int rc;

	selinux_kunit_inode_create_plan_force(true);
	rc = kunit_add_action_or_reset(test,
				       selinux_test_create_plan_unforce, NULL);
	KUNIT_ASSERT_EQ(test, rc, 0);
}

static struct vfsmount *selinux_test_rootfs_mount(struct kunit *test)
{
	struct vfsmount *mnt;
	struct superblock_security_struct *sbsec;
	struct inode_security_struct *isec;
	struct selinux_global_sid_handle *handle, *old_handle;
	struct selinux_label_ref *label, *old;
	u32 sid;
	int rc;

	mnt = kern_mount(&rootfs_fs_type);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, mnt);
	rc = kunit_add_action_or_reset(test, selinux_test_kern_unmount, mnt);
	KUNIT_ASSERT_EQ(test, rc, 0);
	sbsec = selinux_superblock(mnt->mnt_sb);
	rc = selinux_kunit_global_context_to_sid(
		sbsec->anchor_state, "selinux-create-plan-test", &sid);
	KUNIT_ASSERT_EQ(test, rc, 0);
	label = global_sid_to_label_ref(sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, label);
	handle = global_sid_handle_get(sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, handle);
	isec = selinux_inode(d_inode(mnt->mnt_root));
	spin_lock(&isec->lock);
	old = rcu_dereference_protected(isec->label_ref,
					lockdep_is_held(&isec->lock));
	old_handle = isec->sid_handle;
	rcu_assign_pointer(isec->label_ref, label);
	isec->sid_handle = handle;
	isec->sid = sid;
	isec->sclass = SECCLASS_DIR;
	isec->initialized = LABEL_INITIALIZED;
	spin_unlock(&isec->lock);
	global_sid_handle_put(old_handle);
	selinux_label_ref_put(old);
	mutex_lock(&sbsec->lock);
	sbsec->behavior = SECURITY_FS_USE_GENFS;
	sbsec->sid = sid;
	sbsec->def_sid = sid;
	mutex_unlock(&sbsec->lock);
	return mnt;
}

static struct dentry *selinux_test_negative_dentry(struct kunit *test,
						   struct vfsmount *mnt,
						   const char *name)
{
	struct dentry *dentry;
	int rc;

	dentry = d_alloc_name(mnt->mnt_root, name);
	KUNIT_ASSERT_NOT_NULL(test, dentry);
	rc = kunit_add_action_or_reset(test, selinux_test_dput, dentry);
	KUNIT_ASSERT_EQ(test, rc, 0);
	return dentry;
}

static void selinux_create_plan_abort_and_nesting_test(struct kunit *test)
{
	struct security_inode_create_plan *outer, *inner;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct dentry *dentry = selinux_test_negative_dentry(
		test, mnt, "selinux-create-plan-abort");
	struct inode *dir = d_inode(mnt->mnt_root);
	int rc;

	selinux_test_create_plan_force(test);
	KUNIT_ASSERT_NOT_NULL(test, mnt);
	KUNIT_ASSERT_NOT_NULL(test, dentry);
	outer = security_inode_create_plan_prepare(
		mnt, dir, dentry, S_IFREG | 0600, SECURITY_INODE_CREATE,
		SECURITY_INODE_CREATE_OP(SECURITY_INODE_CREATE));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, outer);
	KUNIT_ASSERT_NOT_NULL(test, selinux_task(current)->create_plan);

	inner = security_inode_create_plan_prepare(
		mnt, dir, dentry, S_IFREG | 0600, SECURITY_INODE_CREATE,
		SECURITY_INODE_CREATE_OP(SECURITY_INODE_CREATE));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, inner);

	rc = security_inode_create_plan_finish(inner, -ECANCELED, NULL);
	KUNIT_EXPECT_EQ(test, rc, -ECANCELED);
	KUNIT_EXPECT_NOT_NULL(test, selinux_task(current)->create_plan);
	rc = security_inode_create_plan_finish(outer, -ECANCELED, NULL);
	KUNIT_EXPECT_EQ(test, rc, -ECANCELED);
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->create_plan, NULL);
}

static void selinux_create_plan_out_of_order_test(struct kunit *test)
{
	struct security_inode_create_plan *outer, *inner;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct dentry *dentry = selinux_test_negative_dentry(
		test, mnt, "selinux-create-plan-order");
	struct inode *dir = d_inode(mnt->mnt_root);
	int rc;

	selinux_test_create_plan_force(test);
	outer = security_inode_create_plan_prepare(
		mnt, dir, dentry, S_IFREG | 0600, SECURITY_INODE_CREATE,
		SECURITY_INODE_CREATE_OP(SECURITY_INODE_CREATE));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, outer);
	inner = security_inode_create_plan_prepare(
		mnt, dir, dentry, S_IFREG | 0600, SECURITY_INODE_CREATE,
		SECURITY_INODE_CREATE_OP(SECURITY_INODE_CREATE));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, inner);
	rc = security_inode_create_plan_finish(outer, 0, NULL);
	KUNIT_EXPECT_EQ(test, rc, -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->create_plan, NULL);
	rc = security_inode_create_plan_finish(inner, 0, NULL);
	KUNIT_EXPECT_EQ(test, rc, -EPROTO);
}

static void selinux_create_plan_missing_commit_fails_closed_test(
	struct kunit *test)
{
	struct security_inode_create_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct dentry *dentry = selinux_test_negative_dentry(
		test, mnt, "selinux-create-plan-no-commit");
	struct inode *dir = d_inode(mnt->mnt_root);
	struct inode_security_struct *isec;
	struct inode *inode;
	int rc;

	selinux_test_create_plan_force(test);
	inode = new_inode(mnt->mnt_sb);
	KUNIT_ASSERT_NOT_NULL(test, inode);
	inode->i_mode = S_IFREG | 0600;
	isec = selinux_inode(inode);
	spin_lock(&isec->lock);
	isec->initialized = LABEL_INITIALIZED;
	spin_unlock(&isec->lock);
	d_add(dentry, inode);
	plan = security_inode_create_plan_prepare(
		mnt, dir, dentry, S_IFREG | 0600, SECURITY_INODE_CREATE,
		SECURITY_INODE_CREATE_OP(SECURITY_INODE_CREATE));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plan);
	rc = security_inode_create_plan_finish(plan, 0, inode);
	KUNIT_EXPECT_EQ(test, rc, -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->create_plan, NULL);
	spin_lock(&isec->lock);
	KUNIT_EXPECT_EQ(test, isec->initialized,
			(enum label_initialized)LABEL_INVALID);
	spin_unlock(&isec->lock);
}

static void selinux_create_plan_absent_stack_fails_closed_test(
	struct kunit *test)
{
	struct security_inode_create_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct dentry *dentry = selinux_test_negative_dentry(
		test, mnt, "selinux-create-plan-absent-stack");
	struct inode *dir = d_inode(mnt->mnt_root);
	int rc;

	selinux_test_create_plan_force(test);
	plan = security_inode_create_plan_prepare(
		mnt, dir, dentry, S_IFREG | 0600, SECURITY_INODE_CREATE,
		SECURITY_INODE_CREATE_OP(SECURITY_INODE_CREATE));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plan);
	selinux_task(current)->create_plan = NULL;
	rc = security_inode_create_plan_finish(plan, -ECANCELED, NULL);
	KUNIT_EXPECT_EQ(test, rc, -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->create_plan, NULL);
}

static void selinux_create_plan_mntpoint_exact_handle_test(struct kunit *test)
{
	struct security_inode_create_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct dentry *dentry = selinux_test_negative_dentry(
		test, mnt, "selinux-create-plan-mntpoint-handle");
	struct superblock_security_struct *sbsec =
		selinux_superblock(mnt->mnt_sb);
	struct selinux_global_sid_handle *wrong_handle, *old_handle;
	u32 expected_sid, wrong_sid;
	int rc;

	selinux_test_create_plan_force(test);
	rc = selinux_kunit_global_context_to_sid(
		sbsec->anchor_state, "selinux-create-mntpoint-expected",
		&expected_sid);
	KUNIT_ASSERT_EQ(test, rc, 0);
	wrong_handle = selinux_kunit_global_context_to_handle(
		sbsec->anchor_state, "selinux-create-mntpoint-wrong", &wrong_sid);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, wrong_handle);
	mutex_lock(&sbsec->lock);
	old_handle = sbsec->mntpoint_sid_handle;
	sbsec->behavior = SECURITY_FS_USE_MNTPOINT;
	sbsec->mntpoint_sid = expected_sid;
	sbsec->mntpoint_sid_handle = wrong_handle;
	mutex_unlock(&sbsec->lock);
	global_sid_handle_put(old_handle);
	KUNIT_ASSERT_NE(test, expected_sid, wrong_sid);

	plan = security_inode_create_plan_prepare(
		mnt, d_inode(mnt->mnt_root), dentry, S_IFREG | 0600,
		SECURITY_INODE_CREATE,
		SECURITY_INODE_CREATE_OP(SECURITY_INODE_CREATE));
	KUNIT_EXPECT_TRUE(test, IS_ERR(plan));
	if (IS_ERR(plan))
		KUNIT_EXPECT_EQ(test, PTR_ERR(plan), -ESTALE);
	else {
		rc = security_inode_create_plan_finish(plan, -ECANCELED, NULL);
		KUNIT_EXPECT_EQ(test, rc, -ECANCELED);
	}
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->create_plan, NULL);
}

static void selinux_create_plan_legacy_fail_closed_test(struct kunit *test)
{
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct dentry *dentry = selinux_test_negative_dentry(
		test, mnt, "selinux-create-plan-legacy");
	struct inode *dir = d_inode(mnt->mnt_root);
	int rc;

	selinux_test_create_plan_force(test);
	KUNIT_ASSERT_NOT_NULL(test, mnt);
	KUNIT_ASSERT_NOT_NULL(test, dentry);
	rc = security_inode_create_mnt(mnt, dir, dentry, S_IFREG | 0600);
	KUNIT_EXPECT_EQ(test, rc, -EOPNOTSUPP);
}

struct selinux_create_plan_stale_commit {
	struct selinux_state *state;
	unsigned int calls;
};

static int selinux_create_plan_stale_commit_xattr(
	struct inode *inode, const struct xattr *xattrs, void *fs_data)
{
	struct selinux_create_plan_stale_commit *stale = fs_data;

	stale->calls++;
	selinux_chain_epoch_bump(stale->state);
	return 0;
}

static void selinux_create_plan_stale_at_commit_test(struct kunit *test)
{
	struct security_inode_create_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct dentry *dentry = selinux_test_negative_dentry(
		test, mnt, "selinux-create-plan-stale");
	struct inode *dir = d_inode(mnt->mnt_root);
	struct superblock_security_struct *sbsec =
		selinux_superblock(mnt->mnt_sb);
	struct selinux_create_plan_stale_commit stale = {
		.state = selinux_cred(current_cred())->state,
	};
	struct inode_security_struct *isec;
	struct inode *inode;
	int rc;

	selinux_test_create_plan_force(test);
	/* Ensure initxattrs runs between the sealed plan and commit hooks. */
	mutex_lock(&sbsec->lock);
	sbsec->behavior = SECURITY_FS_USE_XATTR;
	mutex_unlock(&sbsec->lock);
	inode = new_inode(mnt->mnt_sb);
	KUNIT_ASSERT_NOT_NULL(test, inode);
	rc = kunit_add_action_or_reset(test, selinux_test_iput, inode);
	KUNIT_ASSERT_EQ(test, rc, 0);
	inode->i_mode = S_IFREG | 0600;
	isec = selinux_inode(inode);
	plan = security_inode_create_plan_prepare(
		mnt, dir, dentry, S_IFREG | 0600, SECURITY_INODE_CREATE,
		SECURITY_INODE_CREATE_OP(SECURITY_INODE_CREATE));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plan);
	rc = security_inode_init_security(
		inode, dir, &dentry->d_name,
		selinux_create_plan_stale_commit_xattr, &stale);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, stale.calls, 1U);
	rc = security_inode_create_plan_finish(plan, rc, inode);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->create_plan, NULL);
	spin_lock(&isec->lock);
	KUNIT_EXPECT_EQ(test, isec->initialized,
			(enum label_initialized)LABEL_INITIALIZED);
	spin_unlock(&isec->lock);
}

static void selinux_create_plan_attempt_rearm_test(struct kunit *test)
{
	struct security_inode_create_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct dentry *dentry = selinux_test_negative_dentry(
		test, mnt, "selinux-create-plan-rearm");
	struct inode *dir = d_inode(mnt->mnt_root);
	struct inode_security_struct *first_isec;
	struct inode *first, *second, *wrong;
	int rc;

	selinux_test_create_plan_force(test);
	first = new_inode(mnt->mnt_sb);
	second = new_inode(mnt->mnt_sb);
	wrong = new_inode(mnt->mnt_sb);
	KUNIT_ASSERT_NOT_NULL(test, first);
	KUNIT_ASSERT_NOT_NULL(test, second);
	KUNIT_ASSERT_NOT_NULL(test, wrong);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(
		test, selinux_test_iput, first), 0);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(
		test, selinux_test_iput, second), 0);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(
		test, selinux_test_iput, wrong), 0);
	first->i_mode = S_IFREG | 0600;
	second->i_mode = S_IFREG | 0600;
	wrong->i_mode = S_IFREG | 0600;
	first_isec = selinux_inode(first);

	plan = security_inode_create_plan_prepare(
		mnt, dir, dentry, S_IFREG | 0600, SECURITY_INODE_CREATE,
		SECURITY_INODE_CREATE_OP(SECURITY_INODE_CREATE));
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plan);
	rc = security_inode_init_security(
		first, dir, &dentry->d_name, NULL, NULL);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test,
		security_inode_create_plan_attempt_abort(wrong), -EPROTO);
	KUNIT_ASSERT_EQ(test,
		security_inode_create_plan_attempt_abort(first), 0);
	spin_lock(&first_isec->lock);
	KUNIT_EXPECT_EQ(test, first_isec->initialized,
			(enum label_initialized)LABEL_INVALID);
	spin_unlock(&first_isec->lock);

	rc = security_inode_init_security(
		second, dir, &dentry->d_name, NULL, NULL);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = security_inode_create_plan_finish(plan, 0, second);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->create_plan, NULL);
}

static void selinux_create_plan_vfs_commit_test(struct kunit *test)
{
	struct inode_security_struct *isec;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct dentry *dentry = selinux_test_negative_dentry(
		test, mnt, "selinux-create-plan-commit");
	struct inode *dir = d_inode(mnt->mnt_root);
	struct selinux_label_ref *label;
	int rc;

	selinux_test_create_plan_force(test);
	KUNIT_ASSERT_NOT_NULL(test, mnt);
	KUNIT_ASSERT_NOT_NULL(test, dentry);
	inode_lock_nested(dir, I_MUTEX_PARENT);
	rc = vfs_create_mnt(mnt_idmap(mnt), mnt, dentry, 0600, NULL);
	inode_unlock(dir);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_NOT_NULL(test, d_inode(dentry));
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->create_plan, NULL);

	isec = selinux_inode(d_inode(dentry));
	spin_lock(&isec->lock);
	KUNIT_EXPECT_EQ(test, isec->initialized,
			(enum label_initialized)LABEL_INITIALIZED);
	KUNIT_EXPECT_EQ(test, isec->sclass, (u16)SECCLASS_FILE);
	label = selinux_label_ref_get(
		rcu_dereference_protected(isec->label_ref,
					  lockdep_is_held(&isec->lock)));
	spin_unlock(&isec->lock);
	KUNIT_ASSERT_NOT_NULL(test, label);
	KUNIT_EXPECT_PTR_EQ(test, label->domain,
				    selinux_superblock(dir->i_sb)->anchor_domain);
	selinux_label_ref_put(label);

	inode_lock_nested(dir, I_MUTEX_PARENT);
	rc = vfs_unlink_mnt(mnt_idmap(mnt), mnt, dir, dentry, NULL);
	inode_unlock(dir);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static int selinux_create_plan_test_atomic_open(struct inode *dir,
					 struct dentry *dentry,
					 struct file *file, unsigned int flags,
					 umode_t mode)
{
	struct inode *inode;
	int rc;

	if (!(flags & O_CREAT))
		return finish_no_open(file, NULL);
	inode = ramfs_get_inode(dir->i_sb, dir, mode | S_IFREG, 0);
	if (!inode)
		return -ENOSPC;
	rc = security_inode_init_security(inode, dir, &dentry->d_name, NULL,
					  NULL);
	if (rc) {
		iput(inode);
		return rc;
	}
	d_add(dentry, inode);
	rc = finish_open(file, dentry, generic_file_open);
	if (!rc)
		file->f_mode |= FMODE_CREATED;
	return rc;
}

static const struct inode_operations selinux_create_plan_test_atomic_iops = {
	.lookup = simple_lookup,
	.atomic_open = selinux_create_plan_test_atomic_open,
	.security_create_plan_ops =
		SECURITY_INODE_CREATE_OP(SECURITY_INODE_ATOMIC_OPEN),
};

static void selinux_create_plan_atomic_open_test(struct kunit *test)
{
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct inode *dir = d_inode(mnt->mnt_root);
	struct inode_security_struct *isec;
	struct file *file;

	selinux_test_create_plan_force(test);
	dir->i_op = &selinux_create_plan_test_atomic_iops;
	file = file_open_root_mnt(mnt, "selinux-create-plan-atomic",
				  O_CREAT | O_EXCL | O_RDWR, 0600);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file);
	KUNIT_EXPECT_TRUE(test, file->f_mode & FMODE_CREATED);
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->create_plan, NULL);
	isec = selinux_inode(file_inode(file));
	spin_lock(&isec->lock);
	KUNIT_EXPECT_EQ(test, isec->initialized,
			(enum label_initialized)LABEL_INITIALIZED);
	KUNIT_EXPECT_EQ(test, isec->sclass, (u16)SECCLASS_FILE);
	spin_unlock(&isec->lock);
	fput(file);
}

static void selinux_setxattr_plan_commit_test(struct kunit *test)
{
	struct security_inode_setxattr_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct inode *inode = d_inode(mnt->mnt_root);
	struct inode_security_struct *isec = selinux_inode(inode);
	static const char requested[] = "selinux-relabel-test";
	const void *value = requested;
	size_t size = sizeof(requested);
	u32 old_sid;
	int rc;

	selinux_test_create_plan_force(test);
	spin_lock(&isec->lock);
	old_sid = isec->sid;
	spin_unlock(&isec->lock);
	plan = security_inode_setxattr_plan_prepare(
		mnt_idmap(mnt), mnt, mnt->mnt_root, XATTR_NAME_SELINUX,
		&value, &size, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plan);
	KUNIT_EXPECT_PTR_NE(test, value, (const void *)requested);
	KUNIT_EXPECT_EQ(test, size, sizeof(requested));
	KUNIT_EXPECT_MEMEQ(test, value, requested, sizeof(requested));
	rc = security_inode_setxattr_mnt(
		mnt_idmap(mnt), mnt, mnt->mnt_root, XATTR_NAME_SELINUX,
		value, size, 0);
	KUNIT_ASSERT_EQ(test, rc, 0);
	/* Simulate a reload after authorization but before the filesystem post. */
	selinux_chain_epoch_bump(selinux_cred(current_cred())->state);
	security_inode_post_setxattr(
		mnt, mnt->mnt_root, XATTR_NAME_SELINUX, value, size, 0);
	rc = security_inode_setxattr_plan_finish(plan, 0);
	KUNIT_EXPECT_EQ(test, rc, 0);
	spin_lock(&isec->lock);
	KUNIT_EXPECT_NE(test, isec->sid, old_sid);
	KUNIT_EXPECT_EQ(test, isec->initialized,
			(enum label_initialized)LABEL_INITIALIZED);
	spin_unlock(&isec->lock);
}

static void selinux_setxattr_plan_missing_commit_fails_closed_test(
	struct kunit *test)
{
	struct security_inode_setxattr_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct inode_security_struct *isec =
		selinux_inode(d_inode(mnt->mnt_root));
	static const char requested[] = "selinux-relabel-no-commit";
	const void *value = requested;
	size_t size = sizeof(requested);
	enum label_initialized initialized;
	int rc;

	selinux_test_create_plan_force(test);
	spin_lock(&isec->lock);
	initialized = isec->initialized;
	spin_unlock(&isec->lock);
	plan = security_inode_setxattr_plan_prepare(
		mnt_idmap(mnt), mnt, mnt->mnt_root, XATTR_NAME_SELINUX,
		&value, &size, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plan);
	rc = security_inode_setxattr_plan_finish(plan, 0);
	KUNIT_EXPECT_EQ(test, rc, -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->setxattr_plan, NULL);
	spin_lock(&isec->lock);
	KUNIT_EXPECT_EQ(test, isec->initialized,
			(enum label_initialized)LABEL_INVALID);
	isec->initialized = initialized;
	spin_unlock(&isec->lock);
}

static void selinux_setxattr_plan_absent_stack_fails_closed_test(
	struct kunit *test)
{
	struct security_inode_setxattr_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	static const char requested[] = "selinux-relabel-absent-stack";
	const void *value = requested;
	size_t size = sizeof(requested);
	int rc;

	selinux_test_create_plan_force(test);
	plan = security_inode_setxattr_plan_prepare(
		mnt_idmap(mnt), mnt, mnt->mnt_root, XATTR_NAME_SELINUX,
		&value, &size, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plan);
	selinux_task(current)->setxattr_plan = NULL;
	rc = security_inode_setxattr_plan_finish(plan, -ECANCELED);
	KUNIT_EXPECT_EQ(test, rc, -EPROTO);
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->setxattr_plan, NULL);
}

static void selinux_setxattr_plan_wrong_inode_test(struct kunit *test)
{
	struct security_inode_setxattr_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct dentry *wrong = selinux_test_negative_dentry(
		test, mnt, "selinux-relabel-wrong-inode");
	struct inode *inode;
	static const char requested[] = "selinux-relabel-exact-inode";
	const void *value = requested;
	size_t size = sizeof(requested);
	int rc;

	selinux_test_create_plan_force(test);
	inode = new_inode(mnt->mnt_sb);
	KUNIT_ASSERT_NOT_NULL(test, inode);
	inode->i_mode = S_IFREG | 0600;
	d_add(wrong, inode);
	plan = security_inode_setxattr_plan_prepare(
		mnt_idmap(mnt), mnt, mnt->mnt_root, XATTR_NAME_SELINUX,
		&value, &size, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plan);
	rc = security_inode_setxattr_mnt(
		mnt_idmap(mnt), mnt, wrong, XATTR_NAME_SELINUX,
		value, size, 0);
	KUNIT_EXPECT_EQ(test, rc, -EOPNOTSUPP);
	rc = security_inode_setxattr_plan_finish(plan, rc);
	KUNIT_EXPECT_EQ(test, rc, -EOPNOTSUPP);
	KUNIT_EXPECT_PTR_EQ(test, selinux_task(current)->setxattr_plan, NULL);
}

static void selinux_setxattr_plan_stale_before_apply_test(struct kunit *test)
{
	struct security_inode_setxattr_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct inode_security_struct *isec =
		selinux_inode(d_inode(mnt->mnt_root));
	static const char requested[] = "selinux-relabel-stale";
	const void *value = requested;
	size_t size = sizeof(requested);
	u32 old_sid;
	int rc;

	selinux_test_create_plan_force(test);
	spin_lock(&isec->lock);
	old_sid = isec->sid;
	spin_unlock(&isec->lock);
	plan = security_inode_setxattr_plan_prepare(
		mnt_idmap(mnt), mnt, mnt->mnt_root, XATTR_NAME_SELINUX,
		&value, &size, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plan);
	selinux_chain_epoch_bump(selinux_cred(current_cred())->state);
	rc = security_inode_setxattr_mnt(
		mnt_idmap(mnt), mnt, mnt->mnt_root, XATTR_NAME_SELINUX,
		value, size, 0);
	KUNIT_EXPECT_EQ(test, rc, -ESTALE);
	rc = security_inode_setxattr_plan_finish(plan, rc);
	KUNIT_EXPECT_EQ(test, rc, -ESTALE);
	spin_lock(&isec->lock);
	KUNIT_EXPECT_EQ(test, isec->sid, old_sid);
	spin_unlock(&isec->lock);
}

static void selinux_setxattr_plan_post_rebind_failure_test(struct kunit *test)
{
	struct security_inode_setxattr_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct inode *inode = d_inode(mnt->mnt_root);
	struct inode_security_struct *isec = selinux_inode(inode);
	static const char requested[] = "selinux-relabel-invalidated";
	const void *value = requested;
	size_t size = sizeof(requested);
	int rc;

	selinux_test_create_plan_force(test);
	plan = security_inode_setxattr_plan_prepare(
		mnt_idmap(mnt), mnt, mnt->mnt_root, XATTR_NAME_SELINUX,
		&value, &size, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plan);
	rc = security_inode_setxattr_mnt(
		mnt_idmap(mnt), mnt, mnt->mnt_root, XATTR_NAME_SELINUX,
		value, size, 0);
	KUNIT_ASSERT_EQ(test, rc, 0);
	selinux_kunit_inode_setxattr_plan_rebind_fail();
	security_inode_post_setxattr(
		mnt, mnt->mnt_root, XATTR_NAME_SELINUX, value, size, 0);
	rc = security_inode_setxattr_plan_finish(plan, 0);
	KUNIT_EXPECT_EQ(test, rc, 0);
	spin_lock(&isec->lock);
	KUNIT_EXPECT_EQ(test, isec->initialized,
			(enum label_initialized)LABEL_INVALID);
	spin_unlock(&isec->lock);
}

static void selinux_setxattr_plan_setsecurity_commit_test(struct kunit *test)
{
	struct security_inode_setxattr_plan *plan;
	struct vfsmount *mnt = selinux_test_rootfs_mount(test);
	struct inode *inode = d_inode(mnt->mnt_root);
	struct inode_security_struct *isec = selinux_inode(inode);
	static const char requested[] = "selinux-relabel-setsecurity";
	const void *value = requested;
	size_t size = sizeof(requested);
	u32 old_sid;
	int rc;

	selinux_test_create_plan_force(test);
	spin_lock(&isec->lock);
	old_sid = isec->sid;
	spin_unlock(&isec->lock);
	plan = security_inode_setxattr_plan_prepare(
		mnt_idmap(mnt), mnt, mnt->mnt_root, XATTR_NAME_SELINUX,
		&value, &size, 0);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plan);
	rc = security_inode_setxattr_mnt(
		mnt_idmap(mnt), mnt, mnt->mnt_root, XATTR_NAME_SELINUX,
		value, size, 0);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = security_inode_setsecurity(inode, XATTR_SELINUX_SUFFIX, value,
				       size, 0);
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = security_inode_setxattr_plan_finish(plan, 0);
	KUNIT_EXPECT_EQ(test, rc, 0);
	spin_lock(&isec->lock);
	KUNIT_EXPECT_NE(test, isec->sid, old_sid);
	KUNIT_EXPECT_EQ(test, isec->initialized,
			(enum label_initialized)LABEL_INITIALIZED);
	spin_unlock(&isec->lock);
}

static void selinux_filesystem_policycap_vector_test(struct kunit *test)
{
	unsigned long openperm = BIT(POLICYDB_CAP_OPENPERM);
	unsigned long skip_cloexec =
		BIT(POLICYDB_CAP_IOCTL_SKIP_CLOEXEC);

	KUNIT_EXPECT_EQ(test,
		selinux_kunit_avc_effective_requested(
			0, FILE__WRITE, FILE__OPEN, POLICYDB_CAP_OPENPERM, 0),
		FILE__WRITE);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_avc_effective_requested(
			openperm, FILE__WRITE, FILE__OPEN,
			POLICYDB_CAP_OPENPERM, 0),
		FILE__WRITE | FILE__OPEN);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_avc_effective_requested(
			skip_cloexec, FILE__IOCTL, 0, 0,
			POLICYDB_CAP_IOCTL_SKIP_CLOEXEC),
		(u32)0);
	KUNIT_EXPECT_EQ(test,
		selinux_kunit_avc_effective_requested(
			openperm, FILE__IOCTL, 0, 0,
			POLICYDB_CAP_IOCTL_SKIP_CLOEXEC),
		FILE__IOCTL);
}

static void selinux_xperm_intermediate_denial_test(struct kunit *test)
{
	const unsigned long policycaps[3] = {};
	struct selinux_kunit_xperm_result result = {};
	int rc;

	selinux_kunit_audit_buckets_reset();
	rc = selinux_kunit_avc_xperm_vector(
		policycaps, 1, -1, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, -EACCES);
	KUNIT_EXPECT_EQ(test, result.evaluations[0], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[1], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[2], (u16)1);
	KUNIT_EXPECT_EQ(test, result.attempts, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_denials, (u16)1);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
}

static void selinux_xperm_policycap_per_level_test(struct kunit *test)
{
	const unsigned long skip =
		BIT(POLICYDB_CAP_IOCTL_SKIP_CLOEXEC);
	const unsigned long policycaps[3] = { skip, 0, skip };
	struct selinux_kunit_xperm_result result = {};
	int rc;

	selinux_kunit_audit_buckets_reset();
	rc = selinux_kunit_avc_xperm_vector(
		policycaps, -1, -1, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, result.evaluations[0], (u16)0);
	KUNIT_EXPECT_EQ(test, result.evaluations[1], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[2], (u16)0);
	KUNIT_EXPECT_EQ(test, result.attempts, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)1);
}

static void selinux_xperm_audit_failure_test(struct kunit *test)
{
	const unsigned long policycaps[3] = {};
	struct selinux_kunit_xperm_result result = {};
	int rc;

	selinux_kunit_audit_buckets_reset();
	rc = selinux_kunit_avc_xperm_vector(
		policycaps, 1, -1, -ENOMEM, &result);
	KUNIT_EXPECT_EQ(test, rc, -ENOMEM);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_denials, (u16)1);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
}

static void selinux_xperm_stale_retry_test(struct kunit *test)
{
	const unsigned long policycaps[3] = {};
	struct selinux_kunit_xperm_result result = {};
	int rc;

	rc = selinux_kunit_avc_xperm_vector(
		policycaps, -1, 1, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, result.evaluations[0], (u16)2);
	KUNIT_EXPECT_EQ(test, result.evaluations[1], (u16)2);
	KUNIT_EXPECT_EQ(test, result.evaluations[2], (u16)1);
	KUNIT_EXPECT_EQ(test, result.attempts, (u16)2);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)3);
}

static void selinux_secmark_host_denial_aggregate_test(struct kunit *test)
{
	struct selinux_kunit_xperm_result result = {};
	int rc;

	rc = selinux_kunit_avc_perm_vector(1, -1, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, -EACCES);
	KUNIT_EXPECT_EQ(test, result.evaluations[0], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[1], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[2], (u16)1);
	KUNIT_EXPECT_EQ(test, result.attempts, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_denials, (u16)1);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
}

static void selinux_secmark_stale_retry_no_partial_audit_test(struct kunit *test)
{
	struct selinux_kunit_xperm_result result = {};
	int rc;

	rc = selinux_kunit_avc_perm_vector(-1, 1, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, result.evaluations[0], (u16)2);
	KUNIT_EXPECT_EQ(test, result.evaluations[1], (u16)2);
	KUNIT_EXPECT_EQ(test, result.evaluations[2], (u16)1);
	KUNIT_EXPECT_EQ(test, result.attempts, (u16)2);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)3);
}

static void selinux_mount_child_denial_keeps_host_test(struct kunit *test)
{
	struct selinux_kunit_mount_transaction_result result = {};
	u16 denial_mask = BIT(1) | BIT(6);
	int rc;

	rc = selinux_kunit_avc_mount_transaction(
		denial_mask, -1, false, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, -EACCES);
	KUNIT_EXPECT_EQ(test, result.attempts, (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[1], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[6], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[8], (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_denials, (u16)2);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
}

static void selinux_mount_stale_retries_whole_vector_test(struct kunit *test)
{
	struct selinux_kunit_mount_transaction_result result = {};
	int rc;

	rc = selinux_kunit_avc_mount_transaction(0, 4, false, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, result.attempts, (u16)2);
	KUNIT_EXPECT_EQ(test, result.evaluations[1], (u16)2);
	KUNIT_EXPECT_EQ(test, result.evaluations[4], (u16)2);
	KUNIT_EXPECT_EQ(test, result.evaluations[5], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[8], (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)8);
}

static void selinux_mount_stale_exhaustion_test(struct kunit *test)
{
	struct selinux_kunit_mount_transaction_result result = {};
	int rc;

	rc = selinux_kunit_avc_mount_transaction(0, 4, true, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, -ESTALE);
	KUNIT_EXPECT_EQ(test, result.attempts, (u16)3);
	KUNIT_EXPECT_EQ(test, result.evaluations[1], (u16)3);
	KUNIT_EXPECT_EQ(test, result.evaluations[4], (u16)3);
	KUNIT_EXPECT_EQ(test, result.evaluations[5], (u16)0);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
}

static void selinux_mount_aggregate_failure_closed_test(struct kunit *test)
{
	struct selinux_kunit_mount_transaction_result result = {};
	int rc;

	rc = selinux_kunit_avc_mount_transaction(
		BIT(1), -1, false, -ENOMEM, &result);
	KUNIT_EXPECT_EQ(test, rc, -ENOMEM);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_denials, (u16)1);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
}

static void selinux_composite_child_host_denials_test(struct kunit *test)
{
	struct selinux_kunit_composite_transaction_result result = {};
	int rc;

	selinux_kunit_audit_buckets_reset();
	rc = selinux_kunit_avc_validatetrans_transaction(
		0, BIT(0) | BIT(1), 0, -1,
		SELINUX_KUNIT_COMPOSITE_ALLOC_NONE, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, -EPERM);
	KUNIT_EXPECT_EQ(test, result.attempts, (u16)1);
	KUNIT_EXPECT_EQ(test, result.validatetrans_evaluations[0], (u16)1);
	KUNIT_EXPECT_EQ(test, result.validatetrans_evaluations[1], (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_denials, (u16)2);
	KUNIT_EXPECT_EQ(test, result.aggregate_avc_denials, (u16)0);
	KUNIT_EXPECT_EQ(test, result.aggregate_validatetrans_denials, (u16)2);
	KUNIT_EXPECT_EQ(test, result.aggregate_validatetrans_oldsids[0],
			(u32)1000);
	KUNIT_EXPECT_EQ(test, result.aggregate_validatetrans_oldsids[1],
			(u32)1001);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
}

static void selinux_composite_avc_validatetrans_test(struct kunit *test)
{
	struct selinux_kunit_composite_transaction_result result = {};
	int rc;

	selinux_kunit_audit_buckets_reset();
	rc = selinux_kunit_avc_validatetrans_transaction(
		BIT(1), BIT(0), 0, -1,
		SELINUX_KUNIT_COMPOSITE_ALLOC_NONE, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, -EACCES);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_denials, (u16)2);
	KUNIT_EXPECT_EQ(test, result.aggregate_avc_denials, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_validatetrans_denials, (u16)1);
	KUNIT_EXPECT_EQ(test, result.first_validatetrans_oldsid, (u32)1000);
	KUNIT_EXPECT_EQ(test, result.first_validatetrans_newsid, (u32)2000);
	KUNIT_EXPECT_EQ(test, result.first_validatetrans_tasksid, (u32)3000);
	KUNIT_EXPECT_EQ(test, result.first_validatetrans_tclass,
			SECCLASS_FILE);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
}

static void selinux_composite_permissive_would_deny_test(struct kunit *test)
{
	struct selinux_kunit_composite_transaction_result result = {};
	int rc;

	selinux_kunit_audit_buckets_reset();
	rc = selinux_kunit_avc_validatetrans_transaction(
		0, 0, BIT(0), -1, SELINUX_KUNIT_COMPOSITE_ALLOC_NONE, 0,
		&result);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_denials, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_validatetrans_denials, (u16)1);
	KUNIT_EXPECT_EQ(test,
			result.aggregate_permissive_validatetrans_denials,
			(u16)1);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
}

static void selinux_composite_stale_retry_no_partial_audit_test(
	struct kunit *test)
{
	struct selinux_kunit_composite_transaction_result result = {};
	int rc;
	u16 i;

	rc = selinux_kunit_avc_validatetrans_transaction(
		0, 0, 0, 0, SELINUX_KUNIT_COMPOSITE_ALLOC_NONE, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, result.attempts, (u16)2);
	for (i = 0; i < ARRAY_SIZE(result.avc_evaluations); i++)
		KUNIT_EXPECT_EQ(test, result.avc_evaluations[i], (u16)2);
	KUNIT_EXPECT_EQ(test, result.validatetrans_evaluations[0], (u16)2);
	KUNIT_EXPECT_EQ(test, result.validatetrans_evaluations[1], (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits,
			(u16)SELINUX_KUNIT_COMPOSITE_AVC_CHECKS);
}

static void selinux_composite_allocation_failure_test(struct kunit *test)
{
	struct selinux_kunit_composite_transaction_result result = {};
	int rc;

	selinux_kunit_audit_buckets_reset();
	rc = selinux_kunit_avc_validatetrans_transaction(
		0, 0, 0, -1, SELINUX_KUNIT_COMPOSITE_ALLOC_AVC_WORK, 0,
		&result);
	KUNIT_EXPECT_EQ(test, rc, -ENOMEM);
	KUNIT_EXPECT_EQ(test, result.avc_evaluations[0], (u16)0);
	KUNIT_EXPECT_EQ(test, result.validatetrans_evaluations[0], (u16)0);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);

	memset(&result, 0, sizeof(result));
	rc = selinux_kunit_avc_validatetrans_transaction(
		0, 0, 0, -1,
		SELINUX_KUNIT_COMPOSITE_ALLOC_VALIDATETRANS_WORK, 0,
		&result);
	KUNIT_EXPECT_EQ(test, rc, -ENOMEM);
	KUNIT_EXPECT_EQ(test, result.avc_evaluations[0], (u16)0);
	KUNIT_EXPECT_EQ(test, result.validatetrans_evaluations[0], (u16)0);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);

	memset(&result, 0, sizeof(result));
	rc = selinux_kunit_avc_validatetrans_transaction(
		BIT(1), BIT(0), 0, -1,
		SELINUX_KUNIT_COMPOSITE_ALLOC_AGGREGATE, 0, &result);
	KUNIT_EXPECT_EQ(test, rc, -ENOMEM);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
}

static void selinux_composite_emitter_failure_test(struct kunit *test)
{
	struct selinux_kunit_composite_transaction_result result = {};
	int rc;

	selinux_kunit_audit_buckets_reset();
	rc = selinux_kunit_avc_validatetrans_transaction(
		BIT(1), BIT(0), 0, -1,
		SELINUX_KUNIT_COMPOSITE_ALLOC_NONE, -ENOBUFS, &result);
	KUNIT_EXPECT_EQ(test, rc, -ENOBUFS);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_denials, (u16)2);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
}

static void selinux_netlink_mixed_snapshot_abi_test(struct kunit *test)
{
	struct selinux_kunit_xperm_result result = {};
	int rc;

	rc = selinux_kunit_avc_mixed_transaction(
		false, true, -EINVAL, -1, &result);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
	KUNIT_EXPECT_EQ(test, result.ordinary_evaluations, (u16)1);
	KUNIT_EXPECT_EQ(test, result.xperm_evaluations, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_denials, (u16)1);
	KUNIT_EXPECT_EQ(test, result.aggregate_decision_kind,
			SELINUX_AVC_DECISION_XPERM);
	KUNIT_EXPECT_EQ(test, result.aggregate_driver, (u8)7);
	KUNIT_EXPECT_EQ(test, result.aggregate_base_perm,
			(u8)AVC_EXT_NLMSG);
	KUNIT_EXPECT_EQ(test, result.aggregate_xperm, (u8)23);
	KUNIT_EXPECT_EQ(test, result.workspace_allocations, (u16)1);
}

static void selinux_netlink_batch_stale_no_partial_audit_test(
	struct kunit *test)
{
	struct selinux_kunit_xperm_result result = {};
	int rc;

	rc = selinux_kunit_avc_mixed_transaction(
		false, false, 0, 1, &result);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, result.evaluations[0], (u16)2);
	KUNIT_EXPECT_EQ(test, result.evaluations[1], (u16)2);
	KUNIT_EXPECT_EQ(test, result.attempts, (u16)2);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)2);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
	KUNIT_EXPECT_EQ(test, result.workspace_allocations, (u16)1);
}

static void selinux_noaudit_cap_precheck_errno_test(struct kunit *test)
{
	struct selinux_kunit_xperm_result result = {};
	int rc;

	rc = selinux_kunit_avc_noaudit_precheck(1, -1, -EINVAL, &result);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
	KUNIT_EXPECT_EQ(test, result.evaluations[0], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[1], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[2], (u16)1);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
}

static void selinux_noaudit_cap_precheck_stale_test(struct kunit *test)
{
	struct selinux_kunit_xperm_result result = {};
	int rc;

	rc = selinux_kunit_avc_noaudit_precheck(-1, 1, -EINVAL, &result);
	KUNIT_EXPECT_EQ(test, rc, -ESTALE);
	KUNIT_EXPECT_EQ(test, result.evaluations[0], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[1], (u16)1);
	KUNIT_EXPECT_EQ(test, result.evaluations[2], (u16)0);
	KUNIT_EXPECT_EQ(test, result.ordinary_audits, (u16)0);
	KUNIT_EXPECT_EQ(test, result.aggregate_calls, (u16)0);
}

static void selinux_secmark_null_carrier_api_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		security_secmark_relabel_packet(NULL, SECINITSID_UNLABELED,
						 NULL), -EINVAL);
	security_secmark_release(NULL);
}

static struct kunit_case selinux_create_plan_test_cases[] = {
	KUNIT_CASE(selinux_create_plan_abort_and_nesting_test),
	KUNIT_CASE(selinux_create_plan_out_of_order_test),
	KUNIT_CASE(selinux_create_plan_missing_commit_fails_closed_test),
	KUNIT_CASE(selinux_create_plan_absent_stack_fails_closed_test),
	KUNIT_CASE(selinux_create_plan_mntpoint_exact_handle_test),
	KUNIT_CASE(selinux_create_plan_legacy_fail_closed_test),
	KUNIT_CASE(selinux_create_plan_stale_at_commit_test),
	KUNIT_CASE(selinux_create_plan_attempt_rearm_test),
	KUNIT_CASE(selinux_create_plan_vfs_commit_test),
	KUNIT_CASE(selinux_create_plan_atomic_open_test),
	KUNIT_CASE(selinux_setxattr_plan_commit_test),
	KUNIT_CASE(selinux_setxattr_plan_missing_commit_fails_closed_test),
	KUNIT_CASE(selinux_setxattr_plan_absent_stack_fails_closed_test),
	KUNIT_CASE(selinux_setxattr_plan_wrong_inode_test),
	KUNIT_CASE(selinux_setxattr_plan_post_rebind_failure_test),
	KUNIT_CASE(selinux_setxattr_plan_stale_before_apply_test),
	KUNIT_CASE(selinux_setxattr_plan_setsecurity_commit_test),
	KUNIT_CASE(selinux_filesystem_policycap_vector_test),
	KUNIT_CASE(selinux_xperm_intermediate_denial_test),
	KUNIT_CASE(selinux_xperm_policycap_per_level_test),
	KUNIT_CASE(selinux_xperm_audit_failure_test),
	KUNIT_CASE(selinux_xperm_stale_retry_test),
	KUNIT_CASE(selinux_secmark_host_denial_aggregate_test),
	KUNIT_CASE(selinux_secmark_stale_retry_no_partial_audit_test),
	KUNIT_CASE(selinux_mount_child_denial_keeps_host_test),
	KUNIT_CASE(selinux_mount_stale_retries_whole_vector_test),
	KUNIT_CASE(selinux_mount_stale_exhaustion_test),
	KUNIT_CASE(selinux_mount_aggregate_failure_closed_test),
	KUNIT_CASE(selinux_composite_child_host_denials_test),
	KUNIT_CASE(selinux_composite_avc_validatetrans_test),
	KUNIT_CASE(selinux_composite_permissive_would_deny_test),
	KUNIT_CASE(selinux_composite_stale_retry_no_partial_audit_test),
	KUNIT_CASE(selinux_composite_allocation_failure_test),
	KUNIT_CASE(selinux_composite_emitter_failure_test),
	KUNIT_CASE(selinux_netlink_mixed_snapshot_abi_test),
	KUNIT_CASE(selinux_netlink_batch_stale_no_partial_audit_test),
	KUNIT_CASE(selinux_noaudit_cap_precheck_errno_test),
	KUNIT_CASE(selinux_noaudit_cap_precheck_stale_test),
	KUNIT_CASE(selinux_secmark_null_carrier_api_test),
	{}
};

static struct kunit_suite selinux_create_plan_test_suite = {
	.name = "selinux-create-plan",
	.test_cases = selinux_create_plan_test_cases,
};

kunit_test_suite(selinux_create_plan_test_suite);

MODULE_DESCRIPTION("KUnit tests for sealed SELinux inode-create plans");
MODULE_LICENSE("GPL");
