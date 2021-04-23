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
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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
#include "jaldb_utils.h"

#ifndef XTS
#include <pwd.h>
#endif
#include <string.h>
#include <unistd.h>

#ifdef __HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#ifndef XTS
char *jalls_get_user_id_str(uid_t uid)
{
	char *ret = NULL;
	char *pwd_buf = NULL;
	int err;
	struct passwd *user_pwd_ptr;
	struct passwd user_pwd;
	long pwd_buf_size;

	memset(&user_pwd, 0, sizeof(user_pwd));
	pwd_buf_size = sysconf(_SC_GETPW_R_SIZE_MAX);
	pwd_buf = (char *)jal_calloc(1, pwd_buf_size);

	err = getpwuid_r(uid, &user_pwd, pwd_buf, pwd_buf_size, &user_pwd_ptr);
	if (err != 0) {
		goto cleanup;
	}
	if (user_pwd_ptr) {
		ret = jal_strdup(user_pwd_ptr->pw_name);
	}
cleanup:
	free(pwd_buf);
	return ret;
}
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

int jalls_create_record(enum jaldb_rec_type rec_type, struct jalls_thread_context *thread_ctx, struct jaldb_record **prec)
{
	if (!thread_ctx || !thread_ctx->ctx || !prec || *prec) {
		return -1;
	}

	char *timestamp = jaldb_gen_timestamp();
	if (!timestamp) {
		return -1;
	}

	struct jaldb_record *rec = jaldb_create_record();

	rec->type = rec_type;
#ifdef SO_PEERCRED
	rec->pid = thread_ctx->peer_pid;
	rec->have_uid = 1;
	rec->uid = thread_ctx->peer_uid;
#endif
	rec->hostname = jal_strdup(thread_ctx->ctx->hostname);
	rec->timestamp = timestamp;
#ifdef SO_PEERCRED
	rec->username = jalls_get_user_id_str(thread_ctx->peer_uid);
#endif
	rec->sec_lbl = jalls_get_security_label(thread_ctx->fd);
	uuid_copy(rec->host_uuid, thread_ctx->ctx->system_uuid);
	uuid_generate(rec->uuid);
#ifdef SO_PEERCRED
	if (rec->username == NULL) {
		jaldb_destroy_record(&rec);
		return -1;	
	}
#endif

	*prec = rec;
	return 0;
}

