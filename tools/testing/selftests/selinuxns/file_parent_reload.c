// SPDX-License-Identifier: GPL-2.0-only
/*
 * Regression harness for revalidating an already-open file after an ancestor
 * SELinux policy reload.
 *
 * Runtime prerequisites:
 *
 * - execute this process in a child SELinux namespace with the child and its
 *   parent both enforcing;
 * - SELINUXNS_REVALIDATE_FILE names a non-empty file that this process can
 *   initially read;
 * - SELINUXNS_PARENT_CONTROL_SOCKET names an AF_UNIX stream socket served by
 *   a trusted parent-namespace controller;
 * - after receiving "REVOKE_READ\n", the controller reloads only the parent
 *   policy so it denies this process read access to the target, waits until
 *   the policy commit completes, then replies exactly "OK\n";
 * - the controller must leave the child's policy, task SID, inode SID, open
 *   file description, and target contents unchanged.
 *
 * The second pread() deliberately uses the same file descriptor.  A stale
 * file_permission fast path keyed only by the child policy would incorrectly
 * allow it.  Missing environment configuration is a skip, so this binary is
 * deterministic on build hosts without a nested SELinux runtime.
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "../kselftest.h"

static ssize_t pread_retry(int fd, void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = pread(fd, buf, count, 0);
	} while (ret < 0 && errno == EINTR);
	return ret;
}

static int write_all(int fd, const void *buf, size_t count)
{
	const char *cursor = buf;

	while (count) {
		ssize_t ret = write(fd, cursor, count);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!ret) {
			errno = EIO;
			return -1;
		}
		cursor += ret;
		count -= ret;
	}
	return 0;
}

static int read_reply(int fd)
{
	char reply[3];
	size_t offset = 0;

	while (offset < sizeof(reply)) {
		ssize_t ret = read(fd, reply + offset, sizeof(reply) - offset);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!ret) {
			errno = EPIPE;
			return -1;
		}
		offset += ret;
	}

	if (memcmp(reply, "OK\n", sizeof(reply))) {
		errno = EPROTO;
		return -1;
	}
	return 0;
}

int main(void)
{
	static const char command[] = "REVOKE_READ\n";
	const char *target = getenv("SELINUXNS_REVALIDATE_FILE");
	const char *control = getenv("SELINUXNS_PARENT_CONTROL_SOCKET");
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	char byte;
	int fd, sock;
	ssize_t ret;

	if (!target || !*target || !control || !*control)
		ksft_exit_skip("%s%s\n", "set SELINUXNS_REVALIDATE_FILE and ",
			       "SELINUXNS_PARENT_CONTROL_SOCKET; see prerequisites");
	ksft_print_header();
	ksft_set_plan(1);

	if (strlen(control) >= sizeof(address.sun_path))
		ksft_exit_fail_msg("controller socket path is too long\n");
	strcpy(address.sun_path, control);

	fd = open(target, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		ksft_exit_fail_perror("open target before parent policy reload");
	ret = pread_retry(fd, &byte, sizeof(byte));
	if (ret != sizeof(byte)) {
		if (ret >= 0)
			errno = ENODATA;
		ksft_exit_fail_perror("initial pread of non-empty target");
	}

	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		ksft_exit_fail_perror("create controller socket");
	if (connect(sock, (struct sockaddr *)&address,
		    offsetof(struct sockaddr_un, sun_path) + strlen(control) + 1))
		ksft_exit_fail_perror("connect to parent policy controller");
	if (write_all(sock, command, sizeof(command) - 1))
		ksft_exit_fail_perror("request parent policy reload");
	if (read_reply(sock))
		ksft_exit_fail_perror("wait for parent policy reload");
	close(sock);

	errno = 0;
	ret = pread_retry(fd, &byte, sizeof(byte));
	if (ret >= 0)
		ksft_exit_fail_msg("%s%s\n",
				   "same-FD pread unexpectedly succeeded after ",
				   "parent policy revoked read");
	if (errno != EACCES)
		ksft_exit_fail_msg("same-FD pread failed with %s, expected EACCES\n",
				   strerror(errno));

	close(fd);
	ksft_test_result_pass("same FD was revalidated after parent policy reload\n");
	ksft_finished();
}
