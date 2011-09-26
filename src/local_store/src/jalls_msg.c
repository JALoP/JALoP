/**
 * @file jalls_msg.c This file contains helper functions to deal with
 * receiving messages for the jal local store.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>

#define JALLS_STRERROR_BUF_LEN 128

int jalls_recvmsg_helper(int fd, struct msghdr *msgh, int debug)
{
	ssize_t bytes;
	int myerrno;

	while(1) {

		bytes = recvmsg(fd, msgh, 0);
		myerrno = errno;

		if (bytes == -1) {
			if ((EAGAIN == myerrno) || (EWOULDBLOCK == myerrno)) {
				if (debug) {
					fprintf(stderr, "recvmsg: no data avail\n");
				}
			} else {
				if(debug) {
					char err_string[JALLS_STRERROR_BUF_LEN];
					strerror_r(myerrno, err_string, JALLS_STRERROR_BUF_LEN);
					fprintf(stderr, "recvmsg returned error, %s\n", err_string);
				}
				return -1;
			}
		} else {
			return bytes;
		}
	}
}

