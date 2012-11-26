/**
 * @file jalls_handle_log.cpp This file contains functions to handle a log
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
#include "jalls_handle_log.hpp"
#include "jalls_handler.h"
#include "jalls_xml_utils.hpp"

extern "C" int jalls_handle_log(struct jalls_thread_context *thread_ctx, uint64_t data_len, uint64_t meta_len)
{
	if (!thread_ctx || !(thread_ctx->ctx)) {
		return -1; //should never happen.
	}
	struct jal_digest_ctx *digest_ctx = NULL;

	int debug = thread_ctx->ctx->debug;
	int err;
	int ret = -1;

	uint8_t *data_buf = (uint8_t *)jal_malloc(data_len);
	uint8_t *app_meta_buf = NULL;

	void *instance = NULL;

	enum jal_status jal_err;
	enum jaldb_status db_err;
	int bdb_err;
	uint8_t *digest = NULL;
	std::string source;
	std::string sid;

	//get the log
	struct iovec iov[1];
	iov[0].iov_base = data_buf;
	iov[0].iov_len = data_len;

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));

	msgh.msg_iov = iov;
	msgh.msg_iovlen = 1;

	ssize_t bytes_received;

	if (data_len > 0) {
		bytes_received = jalls_recvmsg_helper(thread_ctx->fd, &msgh, debug);
		if (bytes_received < 0) {
			if (debug) {
				fprintf(stderr, "could not receive log data\n");
			}
			goto out;
		}
	}

	//get first break string. If the log was empty, this is omitted
	err = jalls_handle_break(thread_ctx->fd);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "%s: could not receive first BREAK\n", __FILE__);
		}
		goto out;
	}

	//get the app_metadata
	if (meta_len) {
		err = jalls_handle_app_meta(&app_meta_buf, meta_len, thread_ctx->fd, debug);
		if (err < 0) {
			if (debug) {
				fprintf(stderr, "could not receive the application metadata\n");
			}
			goto out;
		}
	}

	//get second break string
	err = jalls_handle_break(thread_ctx->fd);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not receive second BREAK\n");
		}
		goto out;
	}

	//Parse and Validate the app metadata
	//TODO: parse app metadata if needed

	//digest the log data
	digest_ctx = jal_sha256_ctx_create();

	instance = digest_ctx->create();
	digest = (uint8_t *)jal_malloc(digest_ctx->len);

	jal_err = digest_ctx->init(instance);
	if(jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not init sha256 digest\n");
		}
		goto out;
	}

	jal_err = digest_ctx->update(instance, data_buf, data_len);
	if(jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not digest the log\n");
		}
		goto out;
	}
	size_t digest_length;
	digest_length = digest_ctx->len;
	jal_err = digest_ctx->final(instance, digest, &digest_length);
	if(jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not digest the log\n");
		}
		goto out;
	}

	//create system metadata
	db_err =  jaldb_insert_log_record(
			thread_ctx->db_ctx,
			source, NULL,
			NULL, data_buf,
			data_len, sid, &bdb_err);
	if (db_err != JALDB_OK) {
		goto out;
		if (debug) {
			fprintf(stderr, "failed to insert log record\n");
		}
	}

	ret = 0;

out:
	if (digest_ctx) {
		digest_ctx->destroy(instance);
		jal_digest_ctx_destroy(&digest_ctx);
	}
	free(digest);
	free(data_buf);
	free(app_meta_buf);
	return ret;
}
