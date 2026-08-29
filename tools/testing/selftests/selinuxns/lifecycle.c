// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/nsfs.h>
#include <linux/selinux_ns.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../kselftest.h"

#ifndef FD_NSFS_ROOT
#define FD_NSFS_ROOT (-10003)
#endif

static int create_restore(int ctl, uint64_t id, uint64_t parent)
{
	struct selinux_ns_create_restore req = {
		.size = sizeof(req),
		.expected_id = id,
		.expected_parent_id = parent,
	};

	return ioctl(ctl, SELINUX_NS_IOC_CREATE_RESTORE, &req);
}

static int metadata(int fd, struct selinux_ns_metadata *meta)
{
	memset(meta, 0, sizeof(*meta));
	meta->size = sizeof(*meta);
	return ioctl(fd, SELINUX_NS_IOC_GET_METADATA, meta);
}

static void skip_remaining(unsigned int count, const char *why)
{
	while (count--)
		ksft_test_result_skip("%s\n", why);
}

int main(void)
{
	struct selinux_ns_metadata meta, sparse_meta, next_meta;
	struct selinux_ns_restore activation = { .size = sizeof(activation) };
	const char *active_fd_env;
	uint64_t proc_id, sparse_id;
	int ctl, nsfd, sparse = -1, next = -1, procfd, ret;

	ksft_print_header();
	ksft_set_plan(8);
	ctl = open("/sys/fs/selinux/ns_create", O_RDONLY | O_CLOEXEC);
	if (ctl < 0) {
		skip_remaining(8, "SELinux namespace control file unavailable");
		ksft_finished();
	}
	nsfd = ioctl(ctl, SELINUX_NS_IOC_CREATE);
	if (nsfd < 0) {
		skip_remaining(8, errno == EPERM || errno == EACCES ?
			       "namespace creation not permitted by host/policy" :
			       "SELinux namespace CREATE unavailable");
		close(ctl);
		ksft_finished();
	}
	if (!metadata(nsfd, &meta) && meta.id && meta.parent_id)
		ksft_test_result_pass("CREATE and GET_METADATA return identities\n");
	else
		ksft_test_result_fail("GET_METADATA failed or returned zero IDs\n");

	/* Parent mismatch must fail before reserving sparse_id. */
	sparse_id = meta.id + 1024;
	errno = 0;
	ret = create_restore(ctl, sparse_id, meta.parent_id + 1);
	if (ret < 0 && errno == ESTALE)
		ksft_test_result_pass("CREATE_RESTORE rejects parent mismatch\n");
	else if (ret < 0 && (errno == EPERM || errno == EACCES))
		ksft_test_result_skip("host-init restore authority unavailable\n");
	else
		ksft_test_result_fail("parent mismatch did not return ESTALE\n");
	if (ret >= 0)
		close(ret);

	sparse = create_restore(ctl, sparse_id, meta.parent_id);
	if (sparse >= 0 && !metadata(sparse, &sparse_meta) &&
	    sparse_meta.id == sparse_id)
		ksft_test_result_pass("sparse increasing CREATE_RESTORE succeeds\n");
	else if (sparse < 0 && (errno == EPERM || errno == EACCES))
		ksft_test_result_skip("host-init restore authority unavailable\n");
	else
		ksft_test_result_fail("sparse CREATE_RESTORE failed\n");

	if (sparse < 0) {
		ksft_test_result_skip("restore unavailable; stale/no-consumption untestable\n");
	} else {
		int stale_errno;

		errno = 0;
		ret = create_restore(ctl, sparse_id, meta.parent_id);
		stale_errno = errno;
		next = create_restore(ctl, sparse_id + 1, meta.parent_id);
		if (ret < 0 && stale_errno == ESTALE && next >= 0 &&
		    !metadata(next, &next_meta) && next_meta.id == sparse_id + 1)
			ksft_test_result_pass("stale ID fails without consuming next ID\n");
		else
			ksft_test_result_fail("stale reservation altered high-water mark\n");
	}

	activation.expected_id = meta.id + 1;
	activation.expected_parent_id = meta.parent_id;
	errno = 0;
	ret = ioctl(nsfd, SELINUX_NS_IOC_ACTIVATE_RESTORE, &activation);
	if (ret < 0 && errno == ESTALE)
		ksft_test_result_pass("ACTIVATE_RESTORE mismatch fails closed\n");
	else if (ret < 0 && (errno == EPERM || errno == EACCES || errno == ENODATA))
		ksft_test_result_skip("policy/map prerequisites prevent restore validation\n");
	else
		ksft_test_result_fail("ACTIVATE_RESTORE mismatch did not fail ESTALE\n");

	procfd = open("/proc/self/ns/selinux", O_RDONLY | O_CLOEXEC);
	if (procfd >= 0 && !ioctl(procfd, NS_GET_ID, &proc_id) && proc_id)
		ksft_test_result_pass("/proc/self/ns/selinux supports NS_GET_ID\n");
	else
		ksft_test_result_fail("SELinux proc namespace identity unavailable\n");

	if (procfd < 0) {
		ksft_test_result_skip("proc namespace FD unavailable for file handle test\n");
	} else {
		struct file_handle *fh = calloc(1, sizeof(*fh) + 128);
		int mount_id, reopened = -1;

		if (!fh)
			ksft_exit_fail_msg("allocate namespace file handle\n");
		fh->handle_bytes = 128;
		ret = name_to_handle_at(procfd, "", fh, &mount_id, AT_EMPTY_PATH);
		if (!ret && fh->handle_bytes >= sizeof(struct nsfs_file_handle) &&
		    ((struct nsfs_file_handle *)fh->f_handle)->ns_type == 0)
			reopened = open_by_handle_at(FD_NSFS_ROOT, fh, O_RDONLY);
		if (reopened >= 0)
			ksft_test_result_pass("type-zero nsfs handle reopens successfully\n");
		else if ((ret < 0 || reopened < 0) &&
			 (errno == EPERM || errno == EACCES || errno == EOPNOTSUPP ||
			  errno == EINVAL))
			ksft_test_result_skip("namespace file handles unsupported or unprivileged\n");
		else
			ksft_test_result_fail("type-zero namespace handle failed unexpectedly\n");
		if (reopened >= 0)
			close(reopened);
		free(fh);
	}

	active_fd_env = getenv("SELINUXNS_ACTIVE_FD");
	if (!active_fd_env) {
		ksft_test_result_skip("set SELINUXNS_ACTIVE_FD to an inherited active nsfd\n");
	} else {
		int active_fd = atoi(active_fd_env);

		errno = 0;
		ret = setns(active_fd, 0);
		if (!ret)
			ksft_test_result_pass("single-thread setns(fd, 0) succeeds\n");
		else if (errno == EPERM || errno == EACCES || errno == EAGAIN ||
			 errno == EXDEV)
			ksft_test_result_skip("active namespace/policy prerequisites unavailable\n");
		else
			ksft_test_result_fail("setns(fd, 0) failed unexpectedly: %s\n",
					      strerror(errno));
	}

	if (procfd >= 0)
		close(procfd);
	if (next >= 0)
		close(next);
	if (sparse >= 0)
		close(sparse);
	close(nsfd);
	close(ctl);
	ksft_finished();
}
