/**
 * @file jalls_record_utils.c Functions for obtained various hunks of metadata
 * for JALoP Records
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include "jal_alloc.h"
#include "jalls_record_utils.h"
#ifdef __HAVE_SELINUX
#include <selinux/selinux.h>
#endif

char *jalls_get_security_label(int socketFd)
{
#ifdef __HAVE_SELINUX
	char *peercon_str = NULL;
	security_context_t tmp_sec_con;
	int err;
	err = getpeercon(socketFd, &tmp_sec_con);
	if (0 != err) {
		return NULL;
	}
	peercon_str = jal_strdup(tmp_sec_con);
	freecon(tmp_sec_con);
	return peercon_str;
#else
    socketFd = socketFd;
	return NULL;
#endif //__HAVE_SELINUX
}

