/**
 * @file jalls_handle_journal_fd.cpp This file contains functions to handle a journal
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>

#include "jal_alloc.h"

#include "jaldb_context.hpp"
#include "jaldb_segment.h"
#include "jaldb_utils.h"

#include "jalls_context.h"
#include "jalls_msg.h"
#include "jalls_handle_journal_fd.hpp"
#include "jalls_handler.h"
#include "jalls_record_utils.h"

#define JALLS_JOURNAL_BUF_LEN 8192

extern "C" int jalls_handle_journal_fd(struct jalls_thread_context *thread_ctx, uint64_t data_len, uint64_t meta_len, int journal_fd)
{
	if (!thread_ctx || !(thread_ctx->ctx)) {
		return -1; //should never happen.
	}

	struct jaldb_record *rec = NULL;
	int err;
	enum jal_status jal_err;
	enum jaldb_status db_err;
	int ret = -1;

	int debug = thread_ctx->ctx->debug;

	uint8_t *app_meta_buf = NULL;

	struct jal_digest_ctx *digest_ctx = NULL;
	uint8_t *digest = NULL;

	void *sha256_instance = NULL;

	//get the payload, write it to the db file.
	char data_buf[JALLS_JOURNAL_BUF_LEN];
	memset(data_buf, 0, JALLS_JOURNAL_BUF_LEN);

	struct iovec iov[1];
	iov[0].iov_base = data_buf;
	iov[0].iov_len = JALLS_JOURNAL_BUF_LEN;

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));

	msgh.msg_iov = iov;
	msgh.msg_iovlen = 1;

	//data_len should be the size of the file, and there should be no
	//data or first break string
	uint64_t bytes_remaining = data_len;
	size_t bytes_to_read = JALLS_JOURNAL_BUF_LEN;
	int bytes_written;
	ssize_t bytes_read = 0;

	int db_payload_fd = -1;
	char *db_payload_path = NULL;
	char *nonce = NULL;

	//get a file from the db layer to write the journal data to.
	uuid_t uuid;
	uuid_generate(uuid);
	jal_err = (enum jal_status)jaldb_create_file(thread_ctx->db_ctx->journal_root,
			&db_payload_path, &db_payload_fd, uuid, JALDB_RTYPE_JOURNAL, JALDB_DTYPE_PAYLOAD);
	if (jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not create a file to store journal data\n");
		}
		goto err_out;
	}

	//digest and write the file
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

	if ((off_t) -1 == lseek(journal_fd, 0, SEEK_SET)) {
		if (debug) {
			fprintf(stderr, "failed to reset journal file to the beginning\n");
		}
	}
	while (bytes_remaining > 0) {
		bytes_to_read = (bytes_remaining < JALLS_JOURNAL_BUF_LEN) ? bytes_remaining : JALLS_JOURNAL_BUF_LEN;
		bytes_read = read(journal_fd, data_buf, bytes_to_read);
		if (bytes_read < 0) {
			if (debug) {
				fprintf(stderr, "failed to read from file descriptor\n");
			}
			goto err_out;
		}
		jal_err = digest_ctx->update(sha256_instance, (uint8_t *)data_buf, bytes_read);
		if (jal_err != JAL_OK) {
			if (debug) {
				fprintf(stderr, "could not digest the journal data\n");
			}
			goto err_out;
		}
		bytes_written = write(db_payload_fd, data_buf, bytes_read);
		if (bytes_written < 0) {
			if (debug) {
				fprintf(stderr, "could not write journal to file");
			}
			goto err_out;
		}
		bytes_remaining -= (uint64_t)bytes_read;
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

	//get the break string at the end of the app metadata
	err = jalls_handle_break(thread_ctx->fd);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not receive BREAK\n");
		}
		goto err_out;
	}


	err = jalls_create_record(JALDB_RTYPE_JOURNAL, thread_ctx, &rec);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "failed to create record struct\n");
		}
		goto err_out;
	}

	if (meta_len) {
		rec->app_meta = jaldb_create_segment();
		rec->app_meta->length = meta_len;
		rec->app_meta->payload = app_meta_buf;
		rec->app_meta->on_disk = 0;
		app_meta_buf = NULL;
	}

	rec->payload = jaldb_create_segment();
	rec->payload->length = data_len;
	rec->payload->payload = (uint8_t*)db_payload_path;
	rec->payload->on_disk = 1;
	rec->payload->fd = db_payload_fd;
	db_payload_path = NULL;

	db_err = jaldb_insert_record(thread_ctx->db_ctx, rec, &nonce);
	if (JALDB_OK != db_err) {
		if (debug) {
			fprintf(stderr, "could not insert journal record into database\n");
			switch (db_err) {
				case JALDB_E_REJECT:
					fprintf(stderr, "record was too large and was rejected\n");
					break;
				default:
					break;
			}
		}
		goto err_out;
	}
	ret = 0;

err_out:
	free(nonce);
	nonce = NULL;
	close(journal_fd);
	free(app_meta_buf);
	if (digest_ctx) {
		digest_ctx->destroy(sha256_instance);
		jal_digest_ctx_destroy(&digest_ctx);
	}
	free(digest);
	jaldb_destroy_record(&rec);
	return ret;
}
