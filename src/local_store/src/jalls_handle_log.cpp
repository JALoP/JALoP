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

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <jalop/jal_digest.h>
#include <jalop/jal_status.h>

#include "jal_alloc.h"

#include "jaldb_context.hpp"
#include "jaldb_record.h"
#include "jaldb_record_xml.h"
#include "jaldb_segment.h"
#include "jaldb_utils.h"

#include "jalls_context.h"
#include "jalls_msg.h"
#include "jalls_handle_log.hpp"
#include "jalls_handler.h"
#include "jalls_record_utils.h"

extern "C" int jalls_handle_log(struct jalls_thread_context *thread_ctx, uint64_t data_len, uint64_t meta_len)
{
	if (!thread_ctx || !(thread_ctx->ctx)) {
		return -1; //should never happen.
	}
	struct jal_digest_ctx *digest_ctx = NULL;
	struct jaldb_record *rec = NULL;

	int debug = thread_ctx->ctx->debug;
	int err;
	int ret = -1;

	uint8_t *data_buf = (uint8_t *)jal_malloc(data_len);
	uint8_t *app_meta_buf = NULL;

	void *instance = NULL;

	enum jaldb_status db_err;
	uint8_t *digest = NULL;

	//get the log
	struct iovec iov[1];
	iov[0].iov_base = data_buf;
	iov[0].iov_len = data_len;

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));

	msgh.msg_iov = iov;
	msgh.msg_iovlen = 1;

	ssize_t bytes_received;

	char *nonce = NULL;

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

	err = jalls_create_record(JALDB_RTYPE_LOG, thread_ctx, &rec);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "failed to create record struct\n");
		}
		goto out;
	}

	if (meta_len) {
		rec->app_meta = jaldb_create_segment();
		rec->app_meta->length = meta_len;
		rec->app_meta->payload = app_meta_buf;
		rec->app_meta->on_disk = 0;
		app_meta_buf = NULL;
	}

	if (data_len > 0) {
		rec->payload = jaldb_create_segment();
		rec->payload->length = data_len;
		rec->payload->payload = data_buf;
		rec->payload->on_disk = 0;
		data_buf = NULL;
	}

	rec->sys_meta = jaldb_create_segment();
	db_err = jaldb_record_to_system_metadata_doc(rec, thread_ctx->signing_key, NULL, NULL, (char **) &(rec->sys_meta->payload), &(rec->sys_meta->length));
	if (JALDB_OK != db_err) {
		if (debug) {
			fprintf(stderr, "Failed to generate system metadata for record\n");
		}
		goto out;
	}

	db_err = jaldb_insert_record(thread_ctx->db_ctx, rec, 1, &nonce);
	free(nonce);
	nonce = NULL;

	if (JALDB_OK != db_err) {
		if (debug) {
			fprintf(stderr, "failed to insert log record\n");
			switch (db_err) {
				case JALDB_E_REJECT:
					fprintf(stderr, "record was too large and was rejected\n");
					break;
				default:
					break;
			}
		}
		goto out;
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
	jaldb_destroy_record(&rec);
	return ret;
}
