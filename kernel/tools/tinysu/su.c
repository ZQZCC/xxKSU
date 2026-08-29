// SPDX-License-Identifier: GPL-2.0
#include "small_rt.h"

#include <stddef.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>

#define KSU_CAPFD_IOCTL_ENTER_ROOT _IO('C', 1)
#define KSU_FDROOT_SOCKET "ksu_fdroot_v1"

union ksu_control_buffer {
	struct cmsghdr align;
	char data[CMSG_SPACE(sizeof(int))];
};

static int receive_root_capfd(void)
{
	const char socket_name[] = KSU_FDROOT_SOCKET;
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	union ksu_control_buffer control = {};
	char payload = 0xff;
	struct iovec iovec = {
		.iov_base = &payload,
		.iov_len = sizeof(payload),
	};
	struct msghdr message = {
		.msg_iov = &iovec,
		.msg_iovlen = 1,
		.msg_control = control.data,
		.msg_controllen = sizeof(control.data),
	};
	struct cmsghdr *header;
	long socket_fd;
	long received;
	int capfd;
	size_t i;

	for (i = 0; i < sizeof(socket_name) - 1; i++)
		address.sun_path[i + 1] = socket_name[i];

	socket_fd = raw_syscall(SYS_socket, AF_UNIX,
				SOCK_STREAM | SOCK_CLOEXEC, 0, NONE, NONE, NONE);
	if (socket_fd < 0)
		return -1;

	if (raw_syscall(SYS_connect, socket_fd, (long)&address,
			offsetof(struct sockaddr_un, sun_path) +
				1 + sizeof(socket_name) - 1,
			NONE, NONE, NONE) < 0)
		goto fail;

	received = raw_syscall(SYS_recvmsg, socket_fd, (long)&message,
			       MSG_CMSG_CLOEXEC, NONE, NONE, NONE);
	raw_syscall(SYS_close, socket_fd, NONE, NONE, NONE, NONE, NONE);
	if (received != 1 || payload != 0 ||
	    (message.msg_flags & MSG_CTRUNC))
		return -1;

	header = CMSG_FIRSTHDR(&message);
	if (!header || header->cmsg_level != SOL_SOCKET ||
	    header->cmsg_type != SCM_RIGHTS ||
	    header->cmsg_len < CMSG_LEN(sizeof(capfd)))
		return -1;

	capfd = *(int *)CMSG_DATA(header);
	return capfd;

fail:
	raw_syscall(SYS_close, socket_fd, NONE, NONE, NONE, NONE, NONE);
	return -1;
}

__attribute__((used))
void tinysu_main(long *stack)
{
	long argc = *stack;
	char **argv = (char **)(stack + 1);
	char **envp = argv + argc + 1;
	const char *ksud = "/data/adb/ksud";
	const char *shell = "/system/bin/sh";
	int capfd;

	argv[0] = "su";
	if (raw_syscall(SYS_getuid, NONE, NONE, NONE, NONE, NONE, NONE) != 0) {
		capfd = receive_root_capfd();
		if (capfd < 0)
			goto fail;
		if (raw_syscall(SYS_ioctl, capfd, KSU_CAPFD_IOCTL_ENTER_ROOT, 0,
				NONE, NONE, NONE) < 0)
			goto fail_capfd;
		raw_syscall(SYS_close, capfd, NONE, NONE, NONE, NONE, NONE);
	}

	raw_syscall(SYS_execve, (long)ksud, (long)argv, (long)envp,
		    NONE, NONE, NONE);
	raw_syscall(SYS_execve, (long)shell, (long)argv, (long)envp,
		    NONE, NONE, NONE);
	goto fail;

fail_capfd:
	raw_syscall(SYS_close, capfd, NONE, NONE, NONE, NONE, NONE);
fail:
	__builtin_trap();
}
