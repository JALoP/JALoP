/**
* @file jsub_db_layer.cpp This file provides the function calls to the DB
* Layer.
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

#include <jalop/jal_status.h>
#include <openssl/pem.h>
#include <string.h>
#include <unistd.h>

#include "jsub_db_layer.hpp"
#include "jaldb_utils.h"
#include "jaldb_record_xml.h"
#include "jal_alloc.h"
#include "jaldb_segment.h"

#define stringify( name ) # name
#define DEBUG_LOG(args...) \
	do { \
		fprintf(stdout, "(jal_subscribe) %s[%d] ", __FILE__, __LINE__); \
		fprintf(stdout, ##args); \
		fprintf(stdout, "\n"); \
	} while(0)

jaldb_context *jsub_setup_db_layer(
		const char *db_root,
		const char *schemas_root)
{
	enum jaldb_status jaldb_ret = JALDB_OK;
	jaldb_context *db_ctx = jaldb_context_create();
	if (!db_ctx) {
		goto err;
	}
	jaldb_ret = jaldb_context_init(db_ctx, db_root, schemas_root, 0);
	if (JALDB_OK == jaldb_ret){
		goto out;
	}
err:
	jaldb_context_destroy(&db_ctx);
	db_ctx = NULL;
out:
	return db_ctx;
}

void jsub_teardown_db_layer(jaldb_context **db_ctx)
{
	jaldb_context_destroy(db_ctx);
	return;
}

int jsub_insert_audit(
		jaldb_context *db_ctx,
		char *c_source,
		uint8_t *sys_meta,
		size_t sys_len,
		uint8_t *app_meta,
		size_t app_len,
		uint8_t *audit,
		size_t audit_len,
		char *nonce_in,
		int debug)
{
	int ret = JAL_E_INVAL;
	struct jaldb_record *rec;

	// Must have sys_meta and audit_doc
	if (!sys_meta || !audit || !nonce_in || !db_ctx) {
		if (debug) {
			DEBUG_LOG("sys_meta, payload, nonce or db_ctx was NULL!\n");
		}
		ret = JAL_E_INVAL_PARAM;
		goto out;
	}

	ret = jaldb_xml_to_sys_metadata((uint8_t *)sys_meta, (size_t)sys_len, &rec);

	if (ret < 0) {
		if (debug) {
			fprintf(stderr, "failed to create record struct\n");
		}
		goto out;
	}

	if (app_len) {
		rec->app_meta = jaldb_create_segment();
		rec->app_meta->length = app_len;
		rec->app_meta->payload = (uint8_t *) jal_strdup((const char*) app_meta);
		rec->app_meta->on_disk = 0;
	}

	if (audit_len > 0) {
		rec->payload = jaldb_create_segment();
		rec->payload->length = audit_len;
		rec->payload->payload = (uint8_t *) jal_strdup((const char*) audit);
		rec->payload->on_disk = 0;
	}

	ret = jaldb_insert_record_into_temp(db_ctx, rec, c_source, nonce_in);
	jaldb_destroy_record(&rec);
	if ((JALDB_OK != ret) && debug) {
		DEBUG_LOG("Failed to insert audit into temp!\n");
	}
out:

	return ret;
}

int jsub_insert_log(
		jaldb_context *db_ctx,
		char *c_source,
		uint8_t *sys_meta,
		size_t sys_len,
		uint8_t *app_meta,
		size_t app_len,
		uint8_t *log,
		size_t log_len,
		char *nonce_in,
		int debug)
{
	int ret = JALDB_E_UNKNOWN;
	struct jaldb_record *rec;

	// Only requires sys_meta
	if (!sys_meta || !db_ctx){
		if (debug) {
			DEBUG_LOG("sys_meta or db_ctx was NULL!\n");
		}
		ret = JAL_E_INVAL_PARAM;
		goto out;
	}

	ret = jaldb_xml_to_sys_metadata((uint8_t *)sys_meta, (size_t)sys_len, &rec);

	if (ret < 0) {
		if (debug) {
			fprintf(stderr, "failed to create record struct\n");
		}
		goto out;
	}

	if (app_len) {
		rec->app_meta = jaldb_create_segment();
		rec->app_meta->length = app_len;
		rec->app_meta->payload = (uint8_t *) jal_strdup((const char*) app_meta);
		rec->app_meta->on_disk = 0;
	}

	if (log_len > 0) {
		rec->payload = jaldb_create_segment();
		rec->payload->length = log_len;
		uint8_t *payload = (uint8_t *)jal_malloc(log_len);
		memcpy(payload, log, log_len);
		rec->payload->payload = payload;
		rec->payload->on_disk = 0;
	}

	ret = jaldb_insert_record_into_temp(db_ctx, rec, c_source, nonce_in);
	jaldb_destroy_record(&rec);
	if ((JALDB_OK != ret) && debug) {
		DEBUG_LOG("Failed to insert log into temp!\n");
	}
out:
	return ret;
}

int jsub_write_journal(
		jaldb_context *db_ctx,
		char **db_payload_path,
		int *db_payload_fd,
		uint8_t *buffer,
		size_t buffer_len,
		size_t processed_len,
		const char *hostname,
		const char *nonce,
		int debug)
{
	int ret = JAL_OK;
	int bytes_written;
	if (!db_payload_path || !buffer || !db_ctx){
		if (debug) {
			DEBUG_LOG("Payload, payload_path or db_ctx was NULL!\n");
		}
		ret = JAL_E_INVAL_PARAM;
		goto out;
	}
	if (!*db_payload_path && (-1 == *db_payload_fd)) {
		// Path is NULL and FileDescriptor is invalid,
		//	get a file from the db layer to write the
		//	journal data to.
		uuid_t uuid;
		uuid_generate(uuid);
		//TODO: This needs to be updated to parse the uuid from the sys metadata
		ret = jaldb_create_file(db_ctx->journal_root, db_payload_path, db_payload_fd,
				uuid, JALDB_RTYPE_JOURNAL, JALDB_DTYPE_PAYLOAD);
		if (ret != JALDB_OK) {
			if (debug) {
				DEBUG_LOG("Could not create a file to store journal data\n");
			}
			ret = JAL_E_FILE_OPEN;
			goto out;
		}
	}
	bytes_written = write(*db_payload_fd, buffer, buffer_len);
	if (0 > bytes_written) {
		if (debug) {
			DEBUG_LOG("An error occurred while writing journal data to file.\n");
			perror("write()");
		}
		ret = JAL_E_FILE_IO;
	}

	if (JAL_OK == ret) {
		ret = jsub_store_journal_resume(db_ctx, hostname, nonce, *db_payload_path, processed_len);
	}
out:
	return ret;
}

int jsub_insert_journal_metadata(
		jaldb_context *db_ctx,
		char *c_source,
		uint8_t *sys_meta,
		size_t sys_len,
		uint8_t *app_meta,
		size_t app_len,
		char *db_payload_path,
		uint64_t payload_len,
		char *nonce_in,
		int debug)
{
	int ret = JAL_E_INVAL;
	struct jaldb_record *rec;

	if (!sys_meta || !db_ctx){
		if (debug) {
			DEBUG_LOG("sys_meta, or db_ctx was NULL!\n");
		}
		ret = JAL_E_INVAL_PARAM;
		goto out;
	}

	ret = jaldb_xml_to_sys_metadata((uint8_t *)sys_meta, (size_t)sys_len, &rec);

	if (ret < 0) {
		if (debug) {
			fprintf(stderr, "failed to create record struct\n");
		}
		goto out;
	}

	if (app_len) {
		rec->app_meta = jaldb_create_segment();
		rec->app_meta->length = app_len;
		rec->app_meta->payload = (uint8_t *) jal_strdup((const char*) app_meta);
		rec->app_meta->on_disk = 0;
	}

	rec->payload = jaldb_create_segment();
	rec->payload->payload = (uint8_t*) jal_strdup(db_payload_path);
	rec->payload->length = payload_len;
	rec->payload->on_disk = 1;

	ret = jaldb_insert_record_into_temp(db_ctx, rec, c_source, nonce_in);
	jaldb_destroy_record(&rec);
	if ((JALDB_OK != ret) && debug) {
		printf("DEBUG_LOG to insert journal metadata into temp!\n");
	}
out:

	return ret;
}

int jsub_store_journal_resume(
		jaldb_context *db_ctx,
		const char *remote_host,
		const char *nonce,
		const char *path,
		uint64_t offset)
{
	return jaldb_store_journal_resume(db_ctx, remote_host, nonce,
					  path, offset);
}

int jsub_get_journal_resume(
		jaldb_context *db_ctx,
		const char *remote_host,
		char **nonce,
		char **path,
		uint64_t &offset)
{
	return jaldb_get_journal_resume(db_ctx, remote_host, nonce,
					path, offset);
}

off_t jsub_get_offset(int file_descriptor)
{
	if (-1 == file_descriptor) {
		// Not Valid
		return file_descriptor;
	}
	return lseek(file_descriptor, 0, SEEK_CUR);
}

const char* jsub_db_status_to_string(jaldb_status db_status)
{
	switch (db_status){
		case JALDB_E_INVAL:
			return "JALDB_E_INVAL";
			break;
		case JALDB_E_READ_ONLY:
			return "JALDB_E_READ_ONLY";
			break;
		case JALDB_OK:
			return "NONE";
			break;
		case JALDB_E_NOT_FOUND:
			return "JALDB_E_NOT_FOUND";
			break;
		case JALDB_E_CORRUPTED:
			return "JALDB_E_CORRUPTED";
			break;
		case JALDB_E_DB:
			return "JALDB_E_DB";
			break;
		default:
			return "UNEXPECTED_ERROR";
			break;
	}
}

void jsub_write_to_stderr_db_status(
	jaldb_status db_status,
	char *err_msg)
{
	const char *error_name = jsub_db_status_to_string(db_status);
	fprintf(stderr, "%s\t%s\n", error_name, err_msg);
}

void jsub_flush_stale_data(jaldb_context *db_ctx, const char *host, int data_classes, int debug)
{
	if (!host) {
		return;
	}
	enum jaldb_status ret = JALDB_OK;
	if (data_classes & JALN_RTYPE_JOURNAL) {
		ret = jaldb_purge_unconfirmed_records(db_ctx, host, JALDB_RTYPE_JOURNAL);
		if ((JALDB_OK != ret) && debug) {
			printf("DEBUG_LOG purging of journal records failed.\n");
		}
	}
	if (data_classes & JALN_RTYPE_AUDIT) {
		ret = jaldb_purge_unconfirmed_records(db_ctx, host, JALDB_RTYPE_AUDIT);
		if ((JALDB_OK != ret) && debug) {
			printf("DEBUG_LOG purging of audit records failed.\n");
		}
	}
	if (data_classes & JALN_RTYPE_LOG) {
		ret = jaldb_purge_unconfirmed_records(db_ctx, host, JALDB_RTYPE_LOG);
		if ((JALDB_OK != ret) && debug) {
			printf("DEBUG_LOG purging of log records failed.\n");
		}
	}
}
