/**
 * @file jalls_handle_audit.cpp This file contains functions to handle an audit
 * to the jal local store.
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

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <jalop/jal_digest.h>
#include <jalop/jal_status.h>

#include "jal_alloc.h"
#include "jaldb_context.hpp"
#include "jalls_context.h"
#include "jalls_msg.h"
#include "jalls_handle_audit.hpp"
#include "jalls_handler.h"

extern "C" int jalls_handle_audit(struct jalls_thread_context *thread_ctx, uint64_t data_len, uint64_t meta_len)
{
	if (!thread_ctx || !(thread_ctx->ctx)) {
		return -1; //should never happen.
	}

	int ret = -1;

	int debug = thread_ctx->ctx->debug;

	uint8_t *data_buf = (uint8_t *)jal_malloc(data_len);
	uint8_t *app_meta_buf = NULL;

	std::string sid = "";
	std::string source = "";
	enum jaldb_status db_err = JALDB_OK;
	//get the payload audit

	struct iovec iov[1];
	iov[0].iov_base = data_buf;
	iov[0].iov_len = data_len;

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));

	msgh.msg_iov = iov;
	msgh.msg_iovlen = 1;

	ssize_t bytes_received;

	int err;

	struct jal_digest_ctx *digest_ctx = NULL;
	uint8_t *digest = NULL;

	bytes_received = jalls_recvmsg_helper(thread_ctx->fd, &msgh, debug);
	if (bytes_received < 0) {
		if (debug) {
			fprintf(stderr, "could not receive audit data\n");
		}
		goto err_out;
	}

	// TODO: Parse the audit data if needed.

	//get first break string
	err = jalls_handle_break(thread_ctx->fd);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not receive first BREAK\n");
		}
		goto err_out;
	}

	//get the app_metadata
	if (meta_len) {
		err = jalls_handle_app_meta(&app_meta_buf, meta_len, thread_ctx->fd, debug);
		if (err < 0) {
			if (debug) {
				fprintf(stderr, "could not receive application metadata\n");
			}
			goto err_out;
		}

		// TODO: Parse the app metadata if needed
	}

	//get second break string
	err = jalls_handle_break(thread_ctx->fd);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not receive second BREAK\n");
		}
		goto err_out;
	}

	digest_ctx = jal_sha256_ctx_create();

	// TODO: switch to new forms for inserting records into the DB.
	db_err = jaldb_insert_audit_record(
			thread_ctx->db_ctx,
			source,
			NULL,
			NULL,
			NULL,
			sid);
	if (db_err != JALDB_OK) {
		if (debug) {
			fprintf(stderr, "could not insert audit record into database\n");
		}
		goto err_out;
	}

	ret = 0;

err_out:
	jal_digest_ctx_destroy(&digest_ctx);
	free(digest);
	free(data_buf);
	free(app_meta_buf);
	return ret;
}
