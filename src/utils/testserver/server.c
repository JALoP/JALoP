/**
 * @file server.c This file contains server functions
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2012 Tresys Technology LLC, Columbia, Maryland, USA
 *
 * This software was developed by Tresys Technology LLC
 * with U.S. Government sponsorship.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#ifndef XTS
#include <pwd.h>
#endif
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <sys/stat.h>
#include <jalop/jal_version.h>

#define LISTEN_BACKLOG 20

// the buffer size we will use when reading from a fd that we received
// from recvmsg().
#define BUF_SIZE 4096

#define VERSION_FLAG "--version"

static const char *BREAK_STRING = "BREAK";
static uint8_t LOG_MSG = 1;
static uint8_t AUDIT_MSG = 2;
static uint8_t JOURNAL_MSG = 3;
static uint8_t JOURNAL_FD_MSG = 4;

int recvmsg_helper(int fd, struct msghdr *msgh)
{
	ssize_t bytes;

	while(1) {

		bytes = recvmsg(fd, msgh, MSG_DONTWAIT);
		int myerrno = errno;

		if (bytes == -1) {
			if ((EAGAIN == myerrno) ||
					(EWOULDBLOCK == myerrno)) {
				printf("recv_helper(): no data avail\n");
				sleep(1);
			} else {
				printf("recv_helper(): got error, %s\n", strerror(myerrno));
				return -1;
			}
		} else if (bytes == 0) {
			printf("recv_helper(): 0 bytes, no more bytes available\n");
			sleep(1);
			return 0;
		} else {
			printf("recv_helper(): read %zd bytes\n", bytes);
			return bytes;
		}

	}
}


int recv_buffer(int fd, struct msghdr *msgh, int total_size)
{
	int bytes_read = 0;
	ssize_t bytes_recv = 0;

	while (bytes_read < total_size) {
		bytes_recv = recvmsg_helper(fd, msgh);
		// we should never reach this case, unless we get an error from recvmsg()
		if (bytes_recv <= 0) {
			return -1;
		}
		bytes_read += bytes_recv;
	}

	return bytes_read;

}

int recv_break(int fd, struct msghdr *msgh)
{
	int break_len = strlen(BREAK_STRING);
	char break_buffer[break_len + 1];
	int result;
	ssize_t bytes_recv;

	msgh->msg_iov->iov_base = break_buffer;
	msgh->msg_iov->iov_len = break_len;
	msgh->msg_iovlen = 1;

	bytes_recv = recv_buffer(fd, msgh, break_len);
	break_buffer[break_len] = '\0';
	if (bytes_recv != break_len) {
		printf("Could not receive break buffer.\n");
		return -2;
	}

	result = strcmp(break_buffer, BREAK_STRING);
	if (result == 0) {
		printf("BREAK string is correct.\n");
	} else {
		printf("BREAK string was %s\n", break_buffer);
	}
	return result;
}


/**
 * Handler for each connection established.
 *
 * Reads all data for connection, and prints to \p stdout.
 *
 * @param[in] fd The file descriptor to read from.
 *
 * @return -1 on error.
 *			0 on success.
 */
int handler(int fd)
{
	int recv_fd = -1;		// the fd we will receive from the journal call
	ssize_t bytes_recv;
	int retval = 0;
	int ret;

	uint16_t protocol_version;
	uint16_t message_type;
	uint64_t data_len;
	uint64_t meta_len;


	uint8_t *data_buffer = NULL;
	uint8_t *meta_buffer = NULL;

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));

	struct iovec iov[4];
	iov[0].iov_base = &protocol_version;
	iov[0].iov_len = sizeof(protocol_version);
	iov[1].iov_base = &message_type;
	iov[1].iov_len = sizeof(message_type);
	iov[2].iov_base = &data_len;
	iov[2].iov_len = sizeof(data_len);
	iov[3].iov_base = &meta_len;
	iov[3].iov_len = sizeof(meta_len);

	msgh.msg_iov = iov;
	msgh.msg_iovlen = 4;

	char msg_control_buffer[CMSG_SPACE(sizeof(recv_fd))];

	msgh.msg_control = msg_control_buffer;
	msgh.msg_controllen = sizeof(msg_control_buffer);

	size_t total_len = sizeof(protocol_version) + sizeof(message_type)
		+ sizeof(data_len) + sizeof(meta_len);

	bytes_recv = recv_buffer(fd, &msgh, total_len);
	if ((unsigned)bytes_recv != total_len) {
		printf("Could not receive connection headers.\n");
		retval = -1;
		goto out;

	}

	printf("\nprotocol_version: %u\nmessage_type: %u\ndata_len: %llu\nmeta_len: %llu\n",
		protocol_version, message_type, (long long unsigned)data_len, (long long unsigned)meta_len);

	// make sure protocol version is correct
	if (protocol_version != 1) {
		printf("Connection headers received did not equal 1.\n");
		retval = -1;
		goto out;
	}

	// make sure the message type is legal
	if (message_type != LOG_MSG && message_type != AUDIT_MSG &&
			message_type != JOURNAL_MSG && message_type != JOURNAL_FD_MSG) {
		printf("Message type is not legal.\n");
		retval = -1;
		goto out;
	}

	//struct ucred cred;
	//unsigned int len = sizeof (cred);
	//if (0 == getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&cred,&len)) {
	//	printf("handler(): pid: %d\n", cred.pid);
	//	printf("handler(): uid: %d\n", cred.uid);
	//	printf("handler(): gid: %d\n", cred.gid);
	//}
	//struct passwd * pw = getpwuid(cred.uid);
	//if (pw) {
	//	printf("handler(): name: %s\n", pw->pw_name);
	//	printf("handler(): gecos: %s\n", pw->pw_gecos);
	//}

	struct cmsghdr *cmsg;
	cmsg = CMSG_FIRSTHDR(&msgh);
	if (cmsg != NULL && cmsg->cmsg_len == CMSG_LEN(sizeof(recv_fd))) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {

			if (message_type != JOURNAL_FD_MSG) {
				printf("Receiving fd, but not JALP_JOURNAL_FD_MSG type.\n");
				retval = -1;
				goto out;
			}

			void *temp_fd = CMSG_DATA(cmsg);
			recv_fd = *((int *) temp_fd);
			if (recv_fd < 0) {
				printf("Receiving fd is less than zero: %d\n", recv_fd);
				retval = -1;
				goto out;
			}

			char tmpfile_name[] = {'T', 'e', 's', 't', 'P', 'a', 'y', 'l', 'o', 'a', 'd', '_',
				'X', 'X', 'X', 'X', 'X', 'X', '\0'};
			int new_tmpfile_fd = mkstemp(tmpfile_name);

			printf("Receiving fd: %d. Writing to \"%s\"\n", recv_fd, tmpfile_name);
			fflush(stdout);
			char buf[BUF_SIZE];
			ssize_t read_size;
			ssize_t write_size;
			struct stat file_stat;
			if (fstat(recv_fd, &file_stat) == -1) {
				printf("fstat failed\n");
				return -1;
			}
			if (file_stat.st_size <= 0) {
				printf("file size was <= 0");
			}
			printf("file size was %u\n", (unsigned int)file_stat.st_size);

			lseek(recv_fd, 0, SEEK_SET);

			read_size = read(recv_fd, buf, BUF_SIZE);
			while (read_size > 0) {
				// write to temp file
				write_size = write(new_tmpfile_fd, buf, read_size);
				if (write_size <= 0) {
					printf("Write failed!\n");
					retval = -1;
					goto out;
				}
				read_size = read(recv_fd, buf, BUF_SIZE);
			}
			close(new_tmpfile_fd);
			if(read_size < 0) {
				printf("Read of the received fd failed\n");
			}
		}
	}
	if (recv_fd < 0) {
		printf("Not receiving fd.\n");
	}

	meta_buffer = malloc(sizeof(*meta_buffer) * meta_len + 1);
	meta_buffer[meta_len] = '\0';
	int bytes_remaining = data_len;

	if (data_len > 0 && message_type != JOURNAL_FD_MSG) {
		char tmpfile_name[] = {'T', 'e', 's', 't', 'P', 'a', 'y', 'l', 'o', 'a', 'd', '_',
			'X', 'X', 'X', 'X', 'X', 'X', '\0'};
		int new_tmpfile_fd = mkstemp(tmpfile_name);
		printf("Writing Data buffer to  %s\n", tmpfile_name);
		while (bytes_remaining > 0) {
			int tmp_len = (BUF_SIZE < bytes_remaining) ? BUF_SIZE : bytes_remaining;
			data_buffer = malloc(tmp_len);
			msgh.msg_iov->iov_base = data_buffer;
			msgh.msg_iov->iov_len = tmp_len;
			msgh.msg_iovlen = 1;

			bytes_recv = recv_buffer(fd, &msgh, tmp_len);
			if (bytes_recv < 0 || bytes_recv != tmp_len) {
				printf("Could not receive data buffer.\n");
				retval = -1;
				goto out;
			}
			int write_size = write(new_tmpfile_fd, data_buffer, tmp_len);
			if (write_size <= 0 || write_size != tmp_len) {
				printf("Write failed!\n");
				retval = -1;
				goto out;
			}
			bytes_remaining -= tmp_len;
			free(data_buffer);
		}
		close(new_tmpfile_fd);
	}

	struct msghdr msgh_break;
	memset(&msgh_break, 0, sizeof(msgh_break));

	struct iovec iov_break;
	msgh_break.msg_iov = &iov_break;

	//when journal_fd is used, the first break is omitted
	if (message_type != JOURNAL_FD_MSG) {
		ret = recv_break(fd, &msgh_break);
		if (ret != 0) {
			printf("Could not receive first \"BREAK\".\n");
			retval = -1;
			goto out;
		}
	}

	if (meta_len > 0) {
		msgh.msg_iov[0].iov_base = meta_buffer;
		msgh.msg_iov[0].iov_len = meta_len;
		msgh.msg_iovlen = 1;

		bytes_recv = recv_buffer(fd, &msgh, meta_len);
		if (bytes_recv < 0 || (size_t) bytes_recv != meta_len) {
			printf("Could not receive meta buffer.\n");
			retval = -1;
			goto out;
		}
		printf("Meta buffer: %s\n", meta_buffer);
	}

	ret = recv_break(fd, &msgh_break);
	if (ret != 0) {
		printf("Could not receive second \"BREAK\".\n");
		retval = -1;
		goto out;
	}



out:
	close(fd);
	close(recv_fd);
	free(meta_buffer);

	return retval;
}

int main(int argc, char **argv)
{
	int err = 0;
	int sock = -1;
	int my_errno;

	if (argc > 2) {
		printf("usage: [path]\n");
		goto err_out;
	}

	if (argc == 2) {
		if (0 == strcmp(argv[1], VERSION_FLAG)) {
			printf("%s\n",jal_version_as_string());
			exit(0);
		}
	}

	char *sock_path;

	if (argc <= 1) {
		sock_path = "/var/run/jalop/jalop.sock";
	} else {
		sock_path = argv[1];
	}

	// unlink our socket if it already exists
	// (TODO: this might need to get changed, because we
	// don't want to unlink the actual jalop socket that
	// is being used if we are also running the real
	// server on this system.)
	err = unlink(sock_path);
	my_errno = errno;
	if (-1 == err) {
		// we care about every error execpt No Entity (it doesn't exist)
		if (my_errno != ENOENT) {
			printf("failed to unlink socket file %s: %s\n", sock_path, strerror(my_errno));
			goto err_out;
		}

	}

	// set up signal handler for sigchld to reap child proceses
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		printf("failed to create signal handler for SIGCHLD\n");
		goto err_out;
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	my_errno = errno;
	if (-1 == sock) {
		printf("failed to created socket %s: %s\n", sock_path, strerror(my_errno));
		goto err_out;
	}


	struct sockaddr_un sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sun_family = AF_UNIX;

	size_t socket_path_len = strlen(sock_path);
	if (socket_path_len >= sizeof(sock_addr.sun_path)) {
		printf("path to socket file (%s) is too long to fit in sockaddr_un.sun_path\n",
				sock_path);
		goto err_out;
	}

	strncpy(sock_addr.sun_path, sock_path, sizeof(sock_addr.sun_path) - 1);

	err = bind(sock, (struct sockaddr*) &sock_addr, sizeof(sock_addr));
	my_errno = errno;
	if (-1 == err) {
		printf("failed to bind %s: %s\n", sock_path, strerror(my_errno));
		close(sock);
		return -1;
	}

	err = listen(sock, LISTEN_BACKLOG);
	my_errno = errno;

	if (-1 == err) {
		printf("failed to listen, %s\n", strerror(my_errno));
		close(sock);
		return -1;
	}

	struct sockaddr_un peer_addr;
	unsigned int peer_addr_size = sizeof(peer_addr);
	while(1) {
		int fd = accept(sock, (struct sockaddr *) &peer_addr, &peer_addr_size);
		my_errno = errno;
		if (-1 != fd) {
			int child = fork();
			if (0 == child) { // child process
				close(sock);
				return handler(fd);
			} else { // parent
				close(fd);
			}
		} else {
			printf("Failed to accept: %s\n", strerror(errno));
		}
	}

err_out:
	close(sock);
	return -1;
}
