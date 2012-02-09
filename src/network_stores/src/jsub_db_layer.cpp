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

#include <string.h>
#include <unistd.h>
#include <xercesc/dom/DOM.hpp>
#include <openssl/pem.h>
#include <dbxml/DbXml.hpp>
#include <jalop/jal_status.h>
#include "jsub_db_layer.hpp"
#include "jsub_parse.hpp"

XERCES_CPP_NAMESPACE_USE
using namespace DbXml;

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
	jaldb_ret = jaldb_context_init(db_ctx, db_root, schemas_root,
				       1, 0);
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
		char *sid_in,
		int debug)
{
	int ret = JAL_E_INVAL;
	DOMDocument *sys_meta_doc = NULL;
	DOMDocument *app_meta_doc = NULL;
	DOMDocument *audit_doc = NULL;
	std::string sid = sid_in;
	std::string source = c_source;
	char *schemas_root = db_ctx->schemas_root;

	// Must have sys_meta and audit_doc
	if (!sys_meta || !audit || !sid_in || !db_ctx) {
		if (debug) {
			DEBUG_LOG("sys_meta, payload, sid or db_ctx was NULL!\n");
		}
		ret = JAL_E_INVAL_PARAM;
		goto out;
	}
	ret = jsub_parse_sys_metadata(sys_meta,
				      sys_len,
				      schemas_root,
				      &sys_meta_doc,
				      debug);
	if (JAL_OK != ret) {
		goto err;
	}
	if (app_meta && (0 < app_len)) {
		ret = jsub_parse_app_metadata(app_meta,
				      app_len,
				      schemas_root,
				      &app_meta_doc,
				      debug);
		if (JAL_OK != ret) {
			goto err;
		}
	}
	ret = jsub_parse_audit(audit,
			       audit_len,
			       schemas_root,
			       &audit_doc,
			       debug);
	if (JAL_OK != ret) {
		goto err;
	}
	try {
		ret = jaldb_insert_audit_record_into_temp(
						db_ctx,
						source,
						sys_meta_doc,
						app_meta_doc,
						audit_doc,
						sid);
	} catch (XmlException &e) {
		if (e.getExceptionCode()
			== XmlException::UNIQUE_ERROR) {
			DEBUG_LOG("Audit record already exists for serial_id: %s\n",
			       sid.c_str());
			ret = JALDB_E_SID;
		}
		else {
			// re-throw e, this is a serious problem.
			throw(e);
		}
	}
	if ((JALDB_OK != ret) && debug) {
		DEBUG_LOG("Failed to insert audit into temp!\n");
	}
err:
	delete sys_meta_doc;
	delete app_meta_doc;
	delete audit_doc;
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
		char *sid_in,
		int debug)
{
	int ret = JALDB_E_UNKNOWN;
	int db_err;
	DOMDocument *sys_meta_doc = NULL;
	DOMDocument *app_meta_doc = NULL;
	std::string sid = sid_in;
	std::string source = c_source;
	char *schemas_root = db_ctx->schemas_root;
	std::string err_str;

	// Only requires sys_meta
	if (!sys_meta || !db_ctx){
		if (debug) {
			DEBUG_LOG("sys_meta or db_ctx was NULL!\n");
		}
		ret = JAL_E_INVAL_PARAM;
		goto out;
	}
	ret = jsub_parse_sys_metadata(sys_meta, sys_len, schemas_root,
				      &sys_meta_doc, debug);
	if (JAL_OK != ret) {
		goto err;
	}
	if (app_meta && 0 < app_len) {
		ret = jsub_parse_app_metadata(app_meta, app_len,
					schemas_root,
					&app_meta_doc, debug);
		if (JAL_OK != ret) {
			goto err;
		}
	}
	try {
		ret = jaldb_insert_log_record_into_temp(
						db_ctx,
						source,
						sys_meta_doc,
						app_meta_doc,
						log,
						log_len,
						sid,
						&db_err);
	} catch (XmlException &e) {
		if (e.getExceptionCode()
			== XmlException::UNIQUE_ERROR) {
			DEBUG_LOG("Log record already exists for serial_id: %s\n",
			       sid.c_str());
			ret = JALDB_E_SID;
		}
		else {
			// re-throw e, this is a serious problem.
			throw(e);
		}
	}
	if ((JALDB_OK != ret) && debug) {
		DEBUG_LOG("Failed to insert log into temp!\n");
	}
err:
	delete sys_meta_doc;
	delete app_meta_doc;
out:

	return ret;
}

int jsub_write_journal(
		jaldb_context *db_ctx,
		char **db_payload_path,
		int *db_payload_fd,
		uint8_t *payload,
		size_t payload_len,
		int debug)
{
	int ret = JAL_OK;
	int bytes_written;
	if (!db_payload_path || !payload || !db_ctx){
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
		ret = jaldb_create_journal_file(db_ctx, db_payload_path, db_payload_fd);
		if (ret != JALDB_OK) {
			if (debug) {
				DEBUG_LOG("Could not create a file to store journal data\n");
			}
			ret = JAL_E_FILE_OPEN;
			goto out;
		}
	}
	bytes_written = write(*db_payload_fd, payload, payload_len);
	if (0 > bytes_written) {
		if (debug) {
			DEBUG_LOG("An error occurred while writing journal data to file.\n");
		}
		ret = JAL_E_FILE_IO;
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
		char *sid_in,
		int debug)
{
	int ret = JAL_E_INVAL;
	DOMDocument *sys_meta_doc = NULL;
	DOMDocument *app_meta_doc = NULL;
	std::string sid = sid_in;
	std::string source = c_source;
	char *schemas_root = db_ctx->schemas_root;

	if (!sys_meta || !db_ctx){
		if (debug) {
			DEBUG_LOG("sys_meta, or db_ctx was NULL!\n");
		}
		ret = JAL_E_INVAL_PARAM;
		goto out;
	}
	ret = jsub_parse_sys_metadata(sys_meta, sys_len, schemas_root,
				      &sys_meta_doc, debug);
	if (JAL_OK != ret) {
		goto err;
	}
	if (app_meta && (0 < app_len)) {
		ret = jsub_parse_app_metadata(app_meta, app_len,
						schemas_root,
						&app_meta_doc, debug);
		if (JAL_OK != ret) {
			goto err;
		}
	}
	ret = jaldb_insert_journal_metadata_into_temp(
						db_ctx,
						source,
						sys_meta_doc,
						app_meta_doc,
						db_payload_path,
						sid);
	if ((JALDB_OK != ret) && debug) {
		printf("DEBUG_LOG to insert journal metadata into temp!\n");
	}
err:
	delete sys_meta_doc;
	delete app_meta_doc;
out:

	return ret;
}

int jsub_transfer_audit(
		jaldb_context *db_ctx,
		std::string &source,
		std::string &tmp_sid,
		std::string &perm_sid)
{
	jaldb_status ret = jaldb_xfer_audit(db_ctx, source, tmp_sid,
					    perm_sid);
	if (ret == JALDB_OK){
		return JAL_OK;
	}
	return ret;
}

int jsub_transfer_log(
		jaldb_context *db_ctx,
		std::string &source,
		std::string &tmp_sid,
		std::string &perm_sid)
{
	jaldb_status ret = jaldb_xfer_log(db_ctx, source, tmp_sid,
					  perm_sid);
	if (ret == JALDB_OK){
		return JAL_OK;
	}
	return ret;
}

int jsub_transfer_journal(
		jaldb_context *db_ctx,
		std::string &source,
		std::string &tmp_sid,
		std::string &perm_sid)
{
	jaldb_status ret = jaldb_xfer_journal(db_ctx, source, tmp_sid,
					      perm_sid);
	if (ret == JALDB_OK){
		return JAL_OK;
	}
	return ret;
}

int jsub_store_confed_sid(
		jaldb_context *db_ctx,
		const std::string &sid,
		enum jaln_record_type type,
		const std::string &source)
{
	int ret;
	int db_err_out;
	switch (type)
	{
		case JALN_RTYPE_JOURNAL:
			ret = jaldb_store_confed_journal_sid_tmp(
					db_ctx, source.c_str(),
					sid.c_str(), &db_err_out);
			break;
		case JALN_RTYPE_AUDIT:
			ret = jaldb_store_confed_audit_sid_tmp(
					db_ctx, source.c_str(),
					sid.c_str(), &db_err_out);
			break;
		case JALN_RTYPE_LOG:
			ret = jaldb_store_confed_log_sid_tmp(
					db_ctx, source.c_str(),
					sid.c_str(), &db_err_out);
			break;
		default:
			// Nothing
			ret = JAL_OK;
			break;
	}
	return ret;
}

int jsub_get_last_confed_sid(
		jaldb_context *db_ctx,
		std::string &sid,
		enum jaln_record_type type,
		const std::string &source)
{
	int ret;
	int db_err_out;
	switch (type)
	{
		case JALN_RTYPE_JOURNAL:
			ret = jaldb_get_last_confed_journal_sid_tmp(
					db_ctx, source.c_str(),
					sid, &db_err_out);
			break;
		case JALN_RTYPE_AUDIT:
			ret = jaldb_get_last_confed_audit_sid_tmp(
					db_ctx, source.c_str(),
					sid, &db_err_out);
			break;
		case JALN_RTYPE_LOG:
			ret = jaldb_get_last_confed_log_sid_tmp(
					db_ctx, source.c_str(),
					sid, &db_err_out);
			break;
		default:
			// Nothing
			ret = JAL_OK;
			break;
	}
	return ret;
}

int jsub_store_journal_resume(
		jaldb_context *db_ctx,
		const char *remote_host,
		const char *path,
		uint64_t offset)
{
	return jaldb_store_journal_resume(db_ctx, remote_host,
					  path, offset);
}

int jsub_get_journal_resume(
		jaldb_context *db_ctx,
		const char *remote_host,
		char **path,
		uint64_t &offset)
{
	return jaldb_get_journal_resume(db_ctx, remote_host,
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

char* jsub_db_status_to_string(jaldb_status db_status)
{
	std::string err_str;
	switch (db_status){
		case JALDB_E_INVAL:
			err_str = "JALDB_E_INVAL";
			break;
		case JALDB_E_READ_ONLY:
			err_str = "JALDB_E_READ_ONLY";
			break;
		case JALDB_OK:
			err_str = "NONE";
			break;
		case JALDB_E_NOT_FOUND:
			err_str = "JALDB_E_NOT_FOUND";
			break;
		case JALDB_E_CORRUPTED:
			err_str = "JALDB_E_CORRUPTED";
			break;
		case JALDB_E_DB:
			err_str = "JALDB_E_DB";
			break;
		default:
			err_str = "UNEXPECTED_ERROR";
			break;
	}
	return (char *) err_str.c_str();
}

void jsub_write_to_stderr_db_status(
	jaldb_status db_status,
	char *err_msg)
{
	char *error_name = NULL;
	error_name = jsub_db_status_to_string(db_status);
	fprintf(stderr, "%s\t%s\n", error_name, err_msg);
	free(error_name);
}

void jsub_flush_stale_data(jaldb_context *db_ctx, const char *host, int data_classes, int debug)
{
	if (!host) {
		return;
	}
	enum jaldb_status ret = JALDB_OK;
	if (data_classes & JALN_RTYPE_JOURNAL) {
		ret = jaldb_purge_unconfirmed_journal(db_ctx, host);
		if ((JALDB_OK != ret) && debug) {
			printf("DEBUG_LOG purging of journal records failed.\n");
		}
	}
	if (data_classes & JALN_RTYPE_AUDIT) {
		ret = jaldb_purge_unconfirmed_audit(db_ctx, host);
		if ((JALDB_OK != ret) && debug) {
			printf("DEBUG_LOG purging of audit records failed.\n");
		}
	}
	if (data_classes & JALN_RTYPE_LOG) {
		int db_err;
		ret = jaldb_purge_unconfirmed_log(db_ctx, host, &db_err);
		if ((JALDB_OK != ret) && debug) {
			printf("DEBUG_LOG purging of log records failed.\n");
		}
	}
}
