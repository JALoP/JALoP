/**
 * @file jalls_handle_journal.cpp This file contains functions to handle a journal
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

#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>

#include "jal_alloc.h"

#include "jaldb_context.hpp"

#include "jalls_context.h"
#include "jalls_handle_journal.hpp"
#include "jalls_handler.h"
#include "jalls_msg.h"
#include "jalls_xml_utils.hpp"

#define JALLS_JOURNAL_BUF_LEN 8192

extern "C" int jalls_handle_journal(struct jalls_thread_context *thread_ctx, uint64_t data_len, uint64_t meta_len)
{

	if (!thread_ctx || !(thread_ctx->ctx)) {
		return -1; //should never happen.
	}

	int db_payload_fd = -1;
	char *db_payload_path = NULL;
	std::string path;
	std::string sid;
	std::string source;
	enum jal_status jal_err;
	enum jaldb_status db_err;

	uint8_t *app_meta_buf = NULL;
	int err;
	int ret = -1;

	int debug = thread_ctx->ctx->debug;

	uint64_t bytes_remaining;

	struct jal_digest_ctx *digest_ctx = NULL;
	uint8_t *digest = NULL;

	void *sha256_instance = NULL;
	//get a file from the db layer to write the journal data to.
	db_err = jaldb_create_journal_file(thread_ctx->db_ctx, &db_payload_path, &db_payload_fd);
	if (db_err != JALDB_OK) {
		if (debug) {
			fprintf(stderr, "could not create a file to store journal data\n");
		}
		goto err_out;
	}
	path.assign(db_payload_path);

	//get the payload, write it to the db file.
	//digests the payload as well
	char data_buf[JALLS_JOURNAL_BUF_LEN];
	memset(data_buf, 0, JALLS_JOURNAL_BUF_LEN);

	struct iovec iov[1];
	iov[0].iov_base = data_buf;
	if (data_len > JALLS_JOURNAL_BUF_LEN) {
			iov[0].iov_len = JALLS_JOURNAL_BUF_LEN;
	} else {
			iov[0].iov_len = data_len;
	}

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));

	msgh.msg_iov = iov;
	msgh.msg_iovlen = 1;

	ssize_t bytes_received;

	bytes_remaining = data_len;
	int bytes_written;

	digest_ctx = jal_sha256_ctx_create();
	sha256_instance = digest_ctx->create();
	digest = (uint8_t *)jal_malloc(digest_ctx->len);
	jal_err = digest_ctx->init(sha256_instance);
	if(jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not init sha256 digest context\n");
		}
		goto err_out;
	}

	bytes_received = jalls_recvmsg_helper(thread_ctx->fd, &msgh, debug);
	while (bytes_received > 0 && bytes_remaining >= (uint64_t)bytes_received) {
		bytes_remaining -= (uint64_t)bytes_received;
		jal_err = digest_ctx->update(sha256_instance, (uint8_t *)data_buf, bytes_received);
		if (jal_err != JAL_OK) {
			if (debug) {
				fprintf(stderr, "could not digest the journal data\n");
			}
			goto err_out;
		}
		bytes_written = write(db_payload_fd, data_buf, bytes_received);
		if (bytes_written < 0) {
			if (debug) {
				fprintf(stderr, "could not write journal to file\n");
			}
			goto err_out;
		}
		if (bytes_remaining == 0) {
				break;
		}
		iov[0].iov_len = (bytes_remaining < JALLS_JOURNAL_BUF_LEN) ? bytes_remaining : JALLS_JOURNAL_BUF_LEN;
		bytes_received = jalls_recvmsg_helper(thread_ctx->fd, &msgh, debug);
	}
	if (bytes_received < 0) {
		if (debug) {
			fprintf(stderr, "could not receive journal data\n");
		}
		goto err_out;
	}
	size_t digest_length;
	digest_length = digest_ctx->len;
	jal_err = digest_ctx->final(sha256_instance, digest, &digest_length);
	if(jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not digest the journal\n");
		}
		goto err_out;
	}

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
				fprintf(stderr, "could not receive the application metadata\n");
			}
			goto err_out;
		}
	}

	//get second break string
	err = jalls_handle_break(thread_ctx->fd);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not receive second BREAK\n");
		}
		goto err_out;
	}

	// TODO: Parse & validate the app metadata if needed.

	db_err = jaldb_insert_journal_metadata(thread_ctx->db_ctx,
			source,
			NULL,
			NULL,
			path,
			sid);

	if (db_err != JALDB_OK) {
		goto err_out;
	}

	ret = 0;

err_out:
	if (digest_ctx) {
		digest_ctx->destroy(sha256_instance);
		jal_digest_ctx_destroy(&digest_ctx);
	}
	free(digest);
	free(app_meta_buf);
	return ret;
}
