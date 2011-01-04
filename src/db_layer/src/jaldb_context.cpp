/**
 * @file jaldb_context.cpp This file implements the DB context management
 * functions.
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

#define __STDC_FORMAT_MACROS
#include <fcntl.h>
#include <list>
#include <string.h>
#include <sstream>
#include <sys/stat.h>
#include <inttypes.h> // For PRIu64
#include <list>
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jaldb_context.hpp"
#include "jaldb_serial_id.hpp"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"
#include "jaldb_xml_doc_storage.hpp"

XERCES_CPP_NAMESPACE_USE
using namespace std;
using namespace DbXml;

#define DEFAULT_DB_ROOT "/var/lib/jalop/db"
#define DEFAULT_SCHEMAS_ROOT "/usr/local/share/jalop-v1.0/schemas"

jaldb_context *jaldb_context_create()
{
	jaldb_context *context = (jaldb_context *)jal_calloc(1, sizeof(*context));
	return context;
}

enum jaldb_status jaldb_context_init(
	jaldb_context *ctx,
	const char *db_root,
	const char *schemas_root,
	int db_recover_flag,
	int db_rdonly_flag)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}

	// Make certain that the context is not already initialized.
	if ((ctx->manager) || (ctx->journal_root) ||
		(ctx->schemas_root)) {
		return JALDB_E_INITIALIZED;
	}

	if (!db_root) {
		db_root = DEFAULT_DB_ROOT;
	}

	if (!schemas_root) {
		schemas_root = DEFAULT_SCHEMAS_ROOT;
	}
	ctx->schemas_root = jal_strdup(schemas_root);

	if (-1 == jal_asprintf(&ctx->journal_root, "%s%s", db_root, JALDB_JOURNAL_ROOT_NAME)) {
		return JALDB_E_NO_MEM;
	}

	// set readonly flag if specified
	ctx->db_read_only = db_rdonly_flag;

	uint32_t env_flags = DB_CREATE |
		DB_INIT_LOCK |
		DB_INIT_LOG |
		DB_INIT_MPOOL |
		DB_INIT_TXN |
		DB_THREAD;
	if (db_recover_flag) {
		env_flags |= DB_RECOVER;
	}

	DB_ENV *env = NULL;
	db_env_create(&env, 0);
	int db_err = env->open(env, db_root, env_flags, 0);
	if (db_err != 0) {
		return JALDB_E_INVAL;
	}
	env->set_lk_detect(env, DB_LOCK_DEFAULT);

	XmlManager *mgr = new XmlManager(env, DBXML_ADOPT_DBENV);

	ctx->manager = mgr;
	XmlContainerConfig cfg;
	cfg.setThreaded(true);
	cfg.setTransactional(true);
	if (db_rdonly_flag) {
		cfg.setReadOnly(true);
	} else {
		cfg.setAllowCreate(true);
	}

	XmlTransaction txn = ctx->manager->createTransaction();

	XmlContainer cont = ctx->manager->openContainer(txn, JALDB_AUDIT_SYS_META_CONT_NAME, cfg);
	ctx->audit_sys_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_AUDIT_APP_META_CONT_NAME, cfg);
	ctx->audit_app_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_AUDIT_CONT_NAME, cfg);
	ctx->audit_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_JOURNAL_SYS_META_CONT_NAME, cfg);
	ctx->journal_sys_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_JOURNAL_APP_META_CONT_NAME, cfg);
	ctx->journal_app_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_LOG_SYS_META_CONT_NAME, cfg);
	ctx->log_sys_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_LOG_APP_META_CONT_NAME, cfg);
	ctx->log_app_cont = new XmlContainer(cont);

	if (!db_rdonly_flag) {
		jaldb_initialize_serial_id(txn, *ctx->journal_sys_cont, &db_err);
		jaldb_initialize_serial_id(txn, *ctx->audit_sys_cont, &db_err);
		jaldb_initialize_serial_id(txn, *ctx->log_sys_cont, &db_err);
	}
	DB_TXN *db_txn = txn.getDB_TXN();
	int db_ret = 0;

	uint32_t db_flags = DB_THREAD;
	if (db_rdonly_flag) {
		db_flags |= DB_RDONLY;
	} else {
		db_flags |= DB_CREATE;
	}

	db_ret = db_create(&ctx->journal_conf_db, env, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->journal_conf_db), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->journal_conf_db->open(ctx->journal_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_JOURNAL_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->journal_conf_db), db_ret);
		return JALDB_E_DB;
	}

	db_ret = db_create(&ctx->audit_conf_db, env, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->audit_conf_db), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->audit_conf_db->open(ctx->audit_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_AUDIT_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->audit_conf_db), db_ret);
		return JALDB_E_DB;
	}

	db_ret = db_create(&ctx->log_conf_db, env, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->log_conf_db), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->log_conf_db->open(ctx->log_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_LOG_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->log_conf_db), db_ret);
		return JALDB_E_DB;
	}

	db_ret = db_create(&ctx->log_dbp, env, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->log_dbp), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->log_dbp->open(ctx->log_dbp, db_txn,
			JALDB_LOG_DB_NAME, NULL, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->log_dbp), db_ret);
		return JALDB_E_DB;
	}
	txn.commit();

	ctx->temp_dbs = new string_to_db_map;
	ctx->temp_containers = new string_to_container_map;

	return JALDB_OK;
}

void jaldb_context_destroy(jaldb_context **ctx)
{
	if (!ctx || !(*ctx)) {
		return;
	}
	jaldb_context *ctxp = *ctx;
	if (ctxp->audit_sys_cont) {
		delete (ctxp->audit_sys_cont);
	}
	if (ctxp->audit_app_cont) {
		delete (ctxp->audit_app_cont);
	}
	if (ctxp->audit_cont) {
		delete (ctxp->audit_cont);
	}
	if (ctxp->journal_sys_cont) {
		delete (ctxp->journal_sys_cont);
	}
	if (ctxp->journal_app_cont) {
		delete (ctxp->journal_app_cont);
	}
	if (ctxp->log_sys_cont) {
		delete (ctxp->log_sys_cont);
	}
	if (ctxp->log_app_cont) {
		delete (ctxp->log_app_cont);
	}

	free(ctxp->journal_root);
	free(ctxp->schemas_root);

	if (ctxp->journal_conf_db) {
		(*ctx)->journal_conf_db->close((*ctx)->journal_conf_db, 0);
	}

	if (ctxp->audit_conf_db) {
		(*ctx)->audit_conf_db->close((*ctx)->audit_conf_db, 0);
	}

	if (ctxp->log_conf_db) {
		(*ctx)->log_conf_db->close((*ctx)->log_conf_db, 0);
	}

	ctxp->log_dbp->close((*ctx)->log_dbp, 0);

	delete ctxp->temp_containers;

	if (ctxp->temp_dbs) {
		for (string_to_db_map::iterator iter = ctxp->temp_dbs->begin();
				iter != ctxp->temp_dbs->end();
				iter++) {
			iter->second->close(iter->second, 0);
		}
		delete ctxp->temp_dbs;
	}
	delete (*ctx)->manager;


	free(*ctx);
	*ctx = NULL;
}
std::string jaldb_make_temp_db_name(const string &id, const string &suffix)
{
	stringstream o;
	o << "__" << id << "_" << suffix;
	return o.str();
}
enum jaldb_status jaldb_open_temp_container(jaldb_context *ctx, const string& db_name, XmlContainer &cont)
{
	if (!ctx || !ctx->temp_containers) {
		return JALDB_E_INVAL;
	}
	if (db_name.length() == 0) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	string_to_container_map::iterator iter = ctx->temp_containers->find(db_name);
	if (iter == ctx->temp_containers->end()) {
		XmlContainerConfig cfg;
		if (ctx->db_read_only) {
			cfg.setReadOnly(true);
		} else {
			cfg.setAllowCreate(true);
		}
		cfg.setThreaded(true);
		cfg.setTransactional(true);
		cont = ctx->manager->openContainer(db_name, cfg);
		(*ctx->temp_containers)[db_name] = cont;
	} else {
		cont = iter->second;
	}
	return JALDB_OK;
}
enum jaldb_status jaldb_open_temp_db(jaldb_context *ctx, const string& db_name, DB **db_out, int *db_err_out)
{
	if (!ctx || !ctx->temp_dbs || !ctx->manager || !db_out || *db_out || !db_err_out) {
		return JALDB_E_INVAL;
	}
	if (db_name.length() == 0) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	DB *db;
	int db_err = 0;
	uint32_t db_flags = DB_AUTO_COMMIT | DB_THREAD;
	enum jaldb_status ret = JALDB_E_DB;
	string_to_db_map::iterator iter = ctx->temp_dbs->find(db_name);
	if (iter == ctx->temp_dbs->end()) {
		DB_ENV *env = ctx->manager->getDB_ENV();
		db_err = db_create(&db, env, 0);
		if (db_err != 0) {
			db = NULL;
			goto out;
		}
		if (ctx->db_read_only) {
			db_flags |= DB_RDONLY;
		} else {
			db_flags |= DB_CREATE;
		}
		db_err = db->open(db, NULL, db_name.c_str(), NULL, DB_BTREE, db_flags, 0);
		if (db_err != 0) {
			db->close(db, 0);
			db = NULL;
			goto out;
		}
		(*ctx->temp_dbs)[db_name] = db;
	} else {
		db = iter->second;
	}
	ret = JALDB_OK;
out:
	*db_err_out = db_err;
	*db_out = db;
	return ret;
}

enum jaldb_status jaldb_xfer_audit(
	jaldb_context *ctx,
	std::string &source,
	const std::string &sid,
	std::string &next_sid)
{
	enum jaldb_status ret = JALDB_E_INVAL;
	if (!ctx || !ctx->manager || !ctx->audit_sys_cont ||
		!ctx->audit_app_cont || !ctx->audit_cont ||
		(0 == sid.length()) || (0 == source.length())) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}

	string sys_db = jaldb_make_temp_db_name(source,
			JALDB_AUDIT_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(source,
			JALDB_AUDIT_APP_META_CONT_NAME);
	string audit_db = jaldb_make_temp_db_name(source,
			JALDB_AUDIT_CONT_NAME);

	XmlContainer sys_cont;
	XmlContainer app_cont;
	XmlContainer audit_cont;
	XmlUpdateContext uc;

	ret = jaldb_open_temp_container(ctx, sys_db, sys_cont);
	if (ret != JALDB_OK) {
		goto out;
	}
	ret = jaldb_open_temp_container(ctx, app_db, app_cont);
	if (ret != JALDB_OK) {
		goto out;
	}
	ret = jaldb_open_temp_container(ctx, audit_db, audit_cont);
	if (ret != JALDB_OK) {
		goto out;
	}
	uc = ctx->manager->createUpdateContext();

	while (1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			ret = jaldb_get_next_serial_id(txn,
					uc,
					*ctx->audit_sys_cont,
					next_sid);
			if (ret != JALDB_OK) {
				txn.abort();
				break;
			}

			XmlDocument sys_doc;
			XmlDocument app_doc;
			XmlDocument audit_doc;
			XmlValue val;
			bool has_app_meta = false;
			jaldb_status ret1, ret2, ret3;

			// Retrieve from tmp db
			ret1 = jaldb_get_document(txn, &sys_cont,
				sid, &sys_doc);
			ret2 = JALDB_OK;
			if (JALDB_OK == ret1 &&
				sys_doc.getMetaData(JALDB_NS,
					JALDB_HAS_APP_META, val)){
				has_app_meta = val.equals(true);
				if (has_app_meta){
					ret2 = jaldb_get_document(txn,
						&app_cont, sid,
						&app_doc);
				}
			}
			ret3 = jaldb_get_document(txn, &audit_cont,
				sid, &audit_doc);
			if ((ret1 | ret2 | ret3) != JALDB_OK) {
				ret = JALDB_E_NOT_FOUND;
				txn.abort();
				break;
			}

			// Save to perm db
			ret1 = jaldb_save_document(
				txn, uc, *ctx->audit_sys_cont,
				sys_doc, next_sid);
			ret2 = JALDB_OK;
			if (has_app_meta){
				ret2 = jaldb_save_document(
						txn, uc,
						*ctx->audit_app_cont,
						app_doc, next_sid);
			}
			ret3 = jaldb_save_document(
					txn, uc, *ctx->audit_cont,
					audit_doc, next_sid);
			if ((ret1 | ret2 | ret3) != JALDB_OK) {
				ret = JALDB_E_SID;
				txn.abort();
				break;
			}

			// Delete from tmp db
			ret1 = jaldb_remove_document(
				txn, uc, sys_cont, sid);
			ret2 = JALDB_OK;
			if (has_app_meta){
				ret2 = jaldb_remove_document(
						txn, uc, app_cont,
						sid);
			}
			ret3 = jaldb_remove_document(
				txn, uc, audit_cont, sid);
			if ((ret1 | ret2 | ret3) != JALDB_OK) {
				ret = JALDB_E_NOT_FOUND;
				txn.abort();
				break;
			}
			txn.commit();
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() ==
				XmlException::DATABASE_ERROR &&
				e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
out:
	return ret;
}

enum jaldb_status jaldb_insert_audit_record_into_temp(
	jaldb_context *ctx,
	std::string &source,
	const DOMDocument *sys_doc,
	const DOMDocument *app_doc,
	const DOMDocument *audit_doc,
	const std::string &sid)
{
	enum jaldb_status ret = JALDB_E_INVAL;
	if ((ctx == NULL) || (sys_doc == NULL) || audit_doc == NULL) {
		return JALDB_E_INVAL;
	}
	if (source.length() == 0 || sid.length() == 0) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}

	string sys_db = jaldb_make_temp_db_name(source, JALDB_AUDIT_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(source, JALDB_AUDIT_APP_META_CONT_NAME);
	string audit_db = jaldb_make_temp_db_name(source, JALDB_AUDIT_CONT_NAME);

	XmlContainer sys_cont;
	XmlContainer app_cont;
	XmlContainer audit_cont;

	XmlUpdateContext uc;

	ret = jaldb_open_temp_container(ctx, sys_db, sys_cont);
	if (ret != JALDB_OK) {
		goto out;
	}
	ret = jaldb_open_temp_container(ctx, app_db, app_cont);
	if (ret != JALDB_OK) {
		goto out;
	}
	ret = jaldb_open_temp_container(ctx, audit_db, audit_cont);
	if (ret != JALDB_OK) {
		goto out;
	}
	uc = ctx->manager->createUpdateContext();

	while (1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			ret = jaldb_insert_audit_helper(source, txn, *ctx->manager,
					uc, sys_cont, app_cont, audit_cont,
					sys_doc, app_doc, audit_doc, sid);
			if (ret != JALDB_OK) {
				txn.abort();
			} else {
				txn.commit();
			}
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
out:
	return ret;
}
enum jaldb_status jaldb_insert_audit_helper(const string &source,
		XmlTransaction &txn,
		XmlManager &manager,
		XmlUpdateContext &uc,
		XmlContainer &sys_cont,
		XmlContainer &app_cont,
		XmlContainer &audit_cont,
		const DOMDocument *sys_doc,
		const DOMDocument *app_doc,
		const DOMDocument *audit_doc,
		const string &sid)
{
	XmlDocument sys_db_doc;
	XmlDocument app_db_doc;
	XmlDocument audit_db_doc;
	enum jaldb_status ret = JALDB_OK;
	if (sid.length() == 0) {
		return JALDB_E_INVAL;
	}
	sys_db_doc = manager.createDocument();
	if (source.length() != 0) {
		sys_db_doc.setMetaData(JALDB_NS, JALDB_SOURCE, source);
	} else {
		sys_db_doc.setMetaData(JALDB_NS, JALDB_SOURCE, std::string(JALDB_LOCALHOST));
	}
	sys_db_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, app_doc != NULL);
	ret = jaldb_put_document_as_dom(txn, uc,
			sys_cont,
			sys_db_doc,
			sid, sys_doc);
	if (ret != JALDB_OK) {
		goto out;
	}
	if (app_doc) {
		app_db_doc = manager.createDocument();
		ret = jaldb_put_document_as_dom(txn, uc,
			app_cont,
			app_db_doc,
			sid, app_doc);
		if (ret != JALDB_OK) {
			goto out;
		}
	}
	audit_db_doc = manager.createDocument();
	ret = jaldb_put_document_as_dom(txn, uc,
		audit_cont,
		audit_db_doc,
		sid, audit_doc);
	if (ret != JALDB_OK) {
		goto out;
	}
out:
	return ret;
}

enum jaldb_status jaldb_insert_audit_record(
	jaldb_context *ctx,
	std::string &source,
	const DOMDocument *sys_meta_doc,
	const DOMDocument *app_meta_doc,
	const DOMDocument *audit_doc,
	std::string &sid)
{
	if (!ctx || !sys_meta_doc || !audit_doc || !ctx->manager ||
		!ctx->audit_sys_cont || !ctx->audit_app_cont ||
		!ctx->audit_cont) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	enum jaldb_status ret = JALDB_E_UNKNOWN;
	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while (1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			ret = jaldb_get_next_serial_id(txn,
					uc,
					*ctx->audit_sys_cont,
					sid);
			if (ret != JALDB_OK) {
				txn.abort();
				break;
			}
			ret = jaldb_insert_audit_helper(source, txn, *ctx->manager,
				uc, *ctx->audit_sys_cont, *ctx->audit_app_cont,
				*ctx->audit_cont, sys_meta_doc, app_meta_doc,
				audit_doc, sid);
			if (ret != JALDB_OK) {
				txn.abort();
			} else {
				txn.commit();
			}
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return ret;
}

enum jaldb_status jaldb_insert_log_record_helper(
	const string &source,
	XmlTransaction &txn,
	XmlManager &manager,
	XmlUpdateContext &uc,
	XmlContainer &sys_cont,
	XmlContainer &app_cont,
	DB *log_db,
	const DOMDocument *sys_meta_doc,
	const DOMDocument *app_meta_doc,
	uint8_t *log_buf,
	const size_t log_len,
	const string &sid,
	int *db_err)
{
	if (!log_db || !sys_meta_doc || !db_err) {
		return JALDB_E_INVAL;
	}
	if (sid.length() == 0) {
		return JALDB_E_INVAL;
	}
	bool has_log = log_buf && (log_len > 0);
	if (!has_log && !app_meta_doc) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status ret = JALDB_OK;

	XmlDocument sys_doc;
	XmlDocument app_doc;

	sys_doc = manager.createDocument();
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_LOG, has_log);
	if (source.length() != 0) {
		sys_doc.setMetaData(JALDB_NS, JALDB_SOURCE, source);
	} else {
		sys_doc.setMetaData(JALDB_NS, JALDB_SOURCE, std::string(JALDB_LOCALHOST));
	}
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, app_meta_doc != NULL);

	ret = jaldb_put_document_as_dom(txn, uc,
			sys_cont, sys_doc, sid,
			sys_meta_doc);
	if (ret != JALDB_OK) {
		goto out;
	}

	if (app_meta_doc) {
		app_doc = manager.createDocument();
		ret = jaldb_put_document_as_dom(txn, uc,
				app_cont, app_doc, sid,
				app_meta_doc);
		if (ret != JALDB_OK) {
			goto out;
		}
	}
	if (has_log) {
		DBT key;
		DBT data;

		memset(&key, 0, sizeof(DBT));
		memset(&data, 0, sizeof(DBT));

		key.data = jal_strdup(sid.c_str());
		key.size = sid.length();

		data.data = log_buf;
		data.size = log_len;

		int db_ret = log_db->put(log_db, txn.getDB_TXN(),
				&key, &data, DB_NOOVERWRITE);
		free(key.data);
		if (db_ret != 0) {
			*db_err = db_ret;
			ret = JALDB_E_DB;
			goto out;
		}
	}
out:
	return ret;
}

enum jaldb_status jaldb_insert_log_record(
	jaldb_context *ctx,
	const string &source,
	const DOMDocument *sys_meta_doc,
	const DOMDocument *app_meta_doc,
	uint8_t *log_buf,
	const size_t log_len,
	string &sid,
	int *db_err)
{
	if (!ctx || !ctx->manager || !ctx->log_sys_cont ||
			!ctx->log_app_cont || !ctx->log_dbp|| !db_err) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	enum jaldb_status ret = JALDB_OK;
	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while(1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			ret = jaldb_get_next_serial_id(txn, uc, *ctx->log_sys_cont, sid);
			if (ret != JALDB_OK) {
				break;
			}
			ret = jaldb_insert_log_record_helper(
				source, txn, *ctx->manager, uc,
				*ctx->log_sys_cont, *ctx->log_app_cont,
				ctx->log_dbp, sys_meta_doc, app_meta_doc,
				log_buf, log_len, sid, db_err);
			if (ret != JALDB_OK) {
				txn.abort();
				if (ret == JALDB_E_DB && *db_err == DB_LOCK_DEADLOCK) {
					continue;
				}
			} else {
				txn.commit();
			}
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
				e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return ret;
}

enum jaldb_status jaldb_delete_log(
	XmlTransaction &txn,
	XmlUpdateContext &uc,
	XmlContainer &sys_cont,
	XmlContainer &app_cont,
	DB *log_db,
	const std::string &sid,
	XmlDocument *sys_doc,
	XmlDocument *app_doc,
	int *db_err_out)
{
	if (!log_db || !sys_doc || !db_err_out ||
		(0 == sid.length())){
		return JALDB_E_INVAL;
	}

	XmlValue val;
	if (!sys_doc->getMetaData(JALDB_NS,
		JALDB_HAS_APP_META, val)) {
		return JALDB_E_CORRUPTED;
	}
	bool has_app_meta = val.equals(true);
	if (!sys_doc->getMetaData(JALDB_NS,
		JALDB_HAS_LOG, val)) {
		return JALDB_E_CORRUPTED;
	}
	bool has_log = val.equals(true);
	if (!has_log && !has_app_meta) {
		return JALDB_E_CORRUPTED;
	}
	enum jaldb_status ret = JALDB_OK;

	ret = jaldb_remove_document(txn, uc, sys_cont, sid);

	if (JALDB_OK != ret){
		return ret;
	}

	if (has_app_meta){
		ret = jaldb_remove_document(txn, uc, app_cont, sid);

		if (JALDB_OK != ret){
			return ret;
		}
	}

	if (has_log){
		DBT key;
		memset(&key, 0, sizeof(DBT));
		key.data = jal_strdup(sid.c_str());
		key.size = sid.length();
		int db_ret = log_db->del(log_db, txn.getDB_TXN(),
				&key, 0);
		free(key.data);
		if (db_ret != 0) {
			*db_err_out = db_ret;
			ret = JALDB_E_DB;
		}
	}

	return ret;
}

enum jaldb_status jaldb_save_log(
	XmlTransaction &txn,
	XmlUpdateContext &uc,
	XmlContainer &sys_cont,
	XmlContainer &app_cont,
	DB *log_db,
	const std::string &sid,
	XmlDocument *sys_doc,
	XmlDocument *app_doc,
	uint8_t *log_buf,
	size_t  log_len,
	int *db_err_out)
{
	if (!log_db || !sys_doc || !db_err_out ||
		(0 == sid.length())){
		return JALDB_E_INVAL;
	}

	XmlValue val;
	if (!sys_doc->getMetaData(JALDB_NS,
		JALDB_HAS_APP_META, val)) {
		return JALDB_E_CORRUPTED;
	}
	bool has_app_meta = val.equals(true);
	if (!sys_doc->getMetaData(JALDB_NS,
		JALDB_HAS_LOG, val)) {
		return JALDB_E_CORRUPTED;
	}
	bool has_log = val.equals(true);
	if (!has_log && !has_app_meta) {
		return JALDB_E_CORRUPTED;
	}
	enum jaldb_status ret = JALDB_OK;

	// Save to perm db
	ret = jaldb_save_document(
			txn, uc, sys_cont,
			*sys_doc, sid);

	if (JALDB_OK != ret){
		return ret;
	}

	if (has_app_meta){
		ret = jaldb_save_document(
			txn, uc, app_cont,
			*app_doc, sid);

		if (JALDB_OK != ret){
			return ret;
		}
	}

	if (has_log){
		DBT key;
		DBT data;
		memset(&key, 0, sizeof(DBT));
		memset(&data, 0, sizeof(DBT));
		key.data = jal_strdup(sid.c_str());
		key.size = sid.length();
		data.data = log_buf;
		data.size = log_len;
		int db_ret = log_db->put(log_db, txn.getDB_TXN(),
				&key, &data, DB_NOOVERWRITE);
		free(key.data);
		if (db_ret != 0) {
			*db_err_out = db_ret;
			ret = JALDB_E_DB;
		}
	}

	return ret;
}

enum jaldb_status jaldb_retrieve_log(
	XmlTransaction &txn,
	XmlUpdateContext &uc,
	XmlContainer &sys_cont,
	XmlContainer &app_cont,
	DB *log_db,
	const std::string &sid,
	XmlDocument *sys_doc,
	XmlDocument *app_doc,
	uint8_t **log_buf,
	size_t *log_len,
	int *db_err_out)
{
	jaldb_status ret = JALDB_E_INVAL;
	if (!log_db || !db_err_out || !sys_doc ||
		(0 == sid.length()) || !log_buf ||
		*log_buf || !log_len){
		return ret;
	}

	try {
		ret = jaldb_get_document(txn, &sys_cont,
			sid, sys_doc);
	} catch (XmlException &e) {
		if (e.getExceptionCode() ==
			XmlException::DOCUMENT_NOT_FOUND) {
			return JALDB_E_NOT_FOUND;
		}
		// re-throw e, it will get caught by the outer
		// try/catch block.
		throw(e);
	}
	if (JALDB_OK != ret){
		return ret;
	}
	XmlValue val;
	if (!sys_doc->getMetaData(JALDB_NS,
		JALDB_HAS_APP_META, val)) {
		return JALDB_E_CORRUPTED;
	}
	bool has_app_meta = val.equals(true);
	if (!sys_doc->getMetaData(JALDB_NS,
		JALDB_HAS_LOG, val)) {
		return JALDB_E_CORRUPTED;
	}
	bool has_log = val.equals(true);
	if (!has_log && !has_app_meta) {
		return JALDB_E_CORRUPTED;
	}

	if (has_app_meta){
		try {
			ret = jaldb_get_document(txn, &app_cont,
				sid, app_doc);
		} catch (XmlException &e){
			return JALDB_E_DB;
		}
		if (JALDB_OK != ret){
			return ret;
		}
	}

	if (has_log) {
		DBT key;
		DBT data;
		memset(&key, 0, sizeof(DBT));
		memset(&data, 0, sizeof(DBT));
		key.data = jal_strdup(sid.c_str());
		key.size = strlen(sid.c_str());
		data.flags = DB_DBT_MALLOC;
		int db_ret = log_db->get(log_db, txn.getDB_TXN(),
				&key, &data, DB_READ_COMMITTED);
		free(key.data);
		if (0 != db_ret ) {
			*db_err_out = db_ret;
			return JALDB_E_DB;
		}
		*log_buf = (uint8_t*) data.data;
		*log_len = data.size;
	}

	return JALDB_OK;
}

enum jaldb_status jaldb_xfer_log(
	jaldb_context *ctx,
	std::string &source,
	const std::string &sid,
	std::string &next_sid)
{
	if (!ctx || !ctx->manager || (0 == source.length())) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only){
		return JALDB_E_READ_ONLY;
	}

	enum jaldb_status ret = JALDB_OK;
	string sys_db_name = jaldb_make_temp_db_name(source,
		JALDB_LOG_SYS_META_CONT_NAME);
	string app_db_name = jaldb_make_temp_db_name(source,
		JALDB_LOG_APP_META_CONT_NAME);
	string log_db_name = jaldb_make_temp_db_name(source,
		JALDB_LOG_DB_NAME);

	XmlContainer sys_cont;
	XmlContainer app_cont;
	XmlUpdateContext uc;
	DB *log_db = NULL;
	int db_err = 0;

	ret = jaldb_open_temp_container(ctx, sys_db_name, sys_cont);
	if (ret != JALDB_OK) {
		goto out;
	}
	ret = jaldb_open_temp_container(ctx, app_db_name, app_cont);
	if (ret != JALDB_OK) {
		goto out;
	}
	ret = jaldb_open_temp_db(ctx, log_db_name, &log_db, &db_err);
	if (ret != JALDB_OK) {
		goto out;
	}
	uc = ctx->manager->createUpdateContext();
	while(1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			ret = jaldb_get_next_serial_id(txn,
					uc,
					*ctx->log_sys_cont,
					next_sid);
			if (ret != JALDB_OK) {
				txn.abort();
				break;
			}

			uint8_t *log_buf = NULL;
			size_t log_len;
			XmlDocument sys_doc;
			XmlDocument app_doc;
			XmlDocument log_doc;
			int db_err;

			ret = jaldb_retrieve_log(txn, uc, sys_cont,
				app_cont, log_db, sid, &sys_doc,
				&app_doc, &log_buf, &log_len,
				&db_err);

			if (ret != JALDB_OK) {
				txn.abort();
				break;
			}

			ret = jaldb_save_log(txn, uc,
				*ctx->log_sys_cont,
				*ctx->log_app_cont,
				ctx->log_dbp, next_sid,
				&sys_doc, &app_doc,
				log_buf, log_len, &db_err);
			free(log_buf);
			if (ret != JALDB_OK) {
				txn.abort();
				break;
			}

			uint8_t *copy_log_buf = NULL;
			size_t copy_log_len;
			XmlDocument copy_sys_doc;
			XmlDocument copy_app_doc;
			int copy_db_err;

			ret = jaldb_retrieve_log(txn, uc, sys_cont,
				app_cont, log_db, sid, &copy_sys_doc,
				&copy_app_doc, &copy_log_buf,
				&copy_log_len, &copy_db_err);
			free(copy_log_buf);
			if (ret != JALDB_OK) {
				txn.abort();
				break;
			}

			ret = jaldb_delete_log(txn, uc,
				sys_cont,
				app_cont,
				log_db, sid,
				&copy_sys_doc, &copy_app_doc,
				&db_err);

			if (ret != JALDB_OK) {
				txn.abort();
				break;
			}
			txn.commit();
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
				e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
out:
	return ret;
}

enum jaldb_status jaldb_insert_log_record_into_temp(
	jaldb_context *ctx,
	string &source,
	const DOMDocument *sys_meta_doc,
	const DOMDocument *app_meta_doc,
	uint8_t *log_buf,
	const size_t log_len,
	const string &sid,
	int *db_err)
{
	if (!ctx || !ctx->manager) {
		return JALDB_E_INVAL;
	}
	if (source.length() == 0) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	enum jaldb_status ret = JALDB_OK;
	string sys_db_name = jaldb_make_temp_db_name(source, JALDB_LOG_SYS_META_CONT_NAME);
	string app_db_name = jaldb_make_temp_db_name(source, JALDB_LOG_APP_META_CONT_NAME);
	string log_db_name = jaldb_make_temp_db_name(source, JALDB_LOG_DB_NAME);

	XmlContainer sys_cont;
	XmlContainer app_cont;
	XmlUpdateContext uc;
	DB *log_db = NULL;

	ret = jaldb_open_temp_container(ctx, sys_db_name, sys_cont);
	if (ret != JALDB_OK) {
		goto out;
	}
	ret = jaldb_open_temp_container(ctx, app_db_name, app_cont);
	if (ret != JALDB_OK) {
		goto out;
	}
	ret = jaldb_open_temp_db(ctx, log_db_name, &log_db, db_err);
	if (ret != JALDB_OK) {
		goto out;
	}
	uc = ctx->manager->createUpdateContext();
	while(1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			ret = jaldb_insert_log_record_helper(
				source, txn, *ctx->manager, uc,
				sys_cont, app_cont, log_db,
				sys_meta_doc, app_meta_doc,
				log_buf, log_len, sid, db_err);
			if (ret != JALDB_OK) {
				txn.abort();
				if (ret == JALDB_E_DB && *db_err == DB_LOCK_DEADLOCK) {
					continue;
				}
			} else {
				txn.commit();
			}
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
				e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
out:
	return ret;
}

enum jaldb_status jaldb_create_journal_file(
	jaldb_context *ctx,
	char **path,
	int *fd)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	return jaldb_create_file(ctx->journal_root, path, fd);
}

enum jaldb_status jaldb_xfer_journal(
	jaldb_context *ctx,
	const std::string &source,
	const std::string &sid,
	std::string &next_sid)
{
	if (!ctx || !ctx->manager || !ctx->journal_sys_cont ||
		!ctx->journal_app_cont || (0 == sid.length()) ||
		(0 == source.length())) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	string sys_meta_name = jaldb_make_temp_db_name(source,
		JALDB_JOURNAL_SYS_META_CONT_NAME);
	string app_meta_name = jaldb_make_temp_db_name(source,
		JALDB_JOURNAL_APP_META_CONT_NAME);

	enum jaldb_status ret = JALDB_E_UNKNOWN;
	XmlContainer sys_cont;
	XmlContainer app_cont;
	ret = jaldb_open_temp_container(ctx, sys_meta_name, sys_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	ret = jaldb_open_temp_container(ctx, app_meta_name, app_cont);
	if (ret != JALDB_OK) {
		return ret;
	}

	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while(1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			ret = jaldb_get_next_serial_id(
					txn,
					uc,
					*ctx->journal_sys_cont,
					next_sid);
			if (ret != JALDB_OK) {
				txn.abort();
				break;
			}

			XmlDocument sys_doc;
			XmlDocument app_doc;
			XmlValue val;
			bool has_app_meta = false;
			jaldb_status ret1, ret2;

			// Retrieve from tmp db
			ret1 = jaldb_get_document(txn, &sys_cont,
				sid, &sys_doc);
			if ((JALDB_OK == ret1) &&
				sys_doc.getMetaData(JALDB_NS,
					JALDB_HAS_APP_META, val)){
				has_app_meta = val.equals(true);
			}
			ret2 = JALDB_OK;
			if (has_app_meta){
				ret2 = jaldb_get_document(txn, &app_cont,
						sid, &app_doc);
			}
			if ((ret1 | ret2) != JALDB_OK) {
				ret = JALDB_E_NOT_FOUND;
				txn.abort();
				break;
			}

			// Save to perm db
			ret1 = jaldb_save_document(
				txn, uc, *ctx->journal_sys_cont,
				sys_doc, next_sid);
			ret2 = JALDB_OK;
			if (has_app_meta){
				ret2 = jaldb_save_document(
						txn, uc,
						*ctx->journal_app_cont,
						app_doc, next_sid);
			}
			if ((ret1 | ret2) != JALDB_OK) {
				ret = JALDB_E_SID;
				txn.abort();
				break;
			}

			// Delete from tmp db
			ret1 = jaldb_remove_document(
				txn, uc, sys_cont, sid);
			ret2 = JALDB_OK;
			if (has_app_meta){
				ret2 = jaldb_remove_document(
					txn, uc, app_cont, sid);
			}
			if ((ret1 | ret2) != JALDB_OK) {
				ret = JALDB_E_NOT_FOUND;
				txn.abort();
				break;
			}
			txn.commit();
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
				e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return ret;
}

enum jaldb_status jaldb_insert_journal_metadata_helper(
	const std::string &source,
	XmlTransaction &txn,
	XmlManager &manager,
	XmlUpdateContext &uc,
	XmlContainer &sys_cont,
	XmlContainer &app_cont,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_meta_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_meta_doc,
	const std::string &path,
	const std::string &sid)
{
	if (!sys_meta_doc || path.length() == 0) {
		return JALDB_E_INVAL;
	}
	if (sid.length() == 0) {
		return JALDB_E_INVAL;
	}
	XmlDocument sys_doc;
	XmlDocument app_doc;
	enum jaldb_status ret;
	sys_doc = manager.createDocument();
	sys_doc.setMetaData(JALDB_NS, JALDB_JOURNAL_PATH, path);
	if (source.length() != 0) {
		sys_doc.setMetaData(JALDB_NS, JALDB_SOURCE, source);
	} else {
		sys_doc.setMetaData(JALDB_NS, JALDB_SOURCE, std::string(JALDB_LOCALHOST));
	}
	if (app_meta_doc) {
		sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, true);
	} else {
		sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, false);
	}
	ret = jaldb_put_document_as_dom(txn, uc,
			sys_cont, sys_doc, sid,
			sys_meta_doc);
	if (ret != JALDB_OK) {
		goto out;
	}
	if (app_meta_doc) {
		app_doc = manager.createDocument();
		ret = jaldb_put_document_as_dom(txn, uc,
				app_cont,
				app_doc, sid, app_meta_doc);
		if (ret != JALDB_OK) {
			goto out;
		}
	}
out:
	return ret;
}
enum jaldb_status jaldb_insert_journal_metadata_into_temp(
	jaldb_context *ctx,
	const std::string &source,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_meta_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_meta_doc,
	const std::string &path,
	const std::string &sid)
{
	if (!ctx || !sys_meta_doc) {
		return JALDB_E_INVAL;
	}
	if (source.length() == 0 || path.length() == 0) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	string sys_meta_name = jaldb_make_temp_db_name(source, JALDB_JOURNAL_SYS_META_CONT_NAME);
	string app_meta_name = jaldb_make_temp_db_name(source, JALDB_JOURNAL_APP_META_CONT_NAME);

	enum jaldb_status ret = JALDB_E_UNKNOWN;
	XmlContainer sys_cont;
	XmlContainer app_cont;
	ret = jaldb_open_temp_container(ctx, sys_meta_name, sys_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	ret = jaldb_open_temp_container(ctx, app_meta_name, app_cont);
	if (ret != JALDB_OK) {
		return ret;
	}

	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while(1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			ret = jaldb_insert_journal_metadata_helper(source,
					txn,
					*ctx->manager,
					uc,
					sys_cont,
					app_cont,
					sys_meta_doc,
					app_meta_doc,
					path,
					sid);
			if (ret != JALDB_OK) {
				txn.abort();
			} else {
				txn.commit();
			}
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
				e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return ret;
}

enum jaldb_status jaldb_insert_journal_metadata(
	jaldb_context *ctx,
	const std::string &source,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_meta_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_meta_doc,
	const std::string &path,
	std::string &sid)
{
	if (!ctx || !ctx->manager || !ctx->journal_sys_cont ||
			!ctx->journal_app_cont ||
			!sys_meta_doc || path.length() == 0) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	enum jaldb_status ret = JALDB_OK;
	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while(1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			ret = jaldb_get_next_serial_id(txn, uc, *ctx->journal_sys_cont, sid);
			if (ret != JALDB_OK) {
				txn.abort();
				break;
			}
			ret = jaldb_insert_journal_metadata_helper(source,
					txn,
					*ctx->manager,
					uc,
					*ctx->journal_sys_cont,
					*ctx->journal_app_cont,
					sys_meta_doc,
					app_meta_doc,
					path,
					sid);
			if (ret != JALDB_OK) {
				txn.abort();
			} else {
				txn.commit();
			}
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
				e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return ret;
}

enum jaldb_status jaldb_lookup_audit_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **audit_buf,
	size_t *audit_len)
{
	if (!ctx || !ctx->manager || !ctx->audit_sys_cont ||
			!ctx->audit_app_cont || !ctx->audit_cont ||
			!sid) {
		return JALDB_E_INVAL;
	}
	if (!sys_meta_buf || *sys_meta_buf || !sys_meta_len ||
			!app_meta_buf || *app_meta_buf || !app_meta_len ||
			!audit_buf || *audit_buf || !audit_len) {
		return JALDB_E_INVAL;
	}
	while (true) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			XmlDocument sys_doc;
			try {
				sys_doc = ctx->audit_sys_cont->getDocument(txn, sid, DB_READ_COMMITTED);
			} catch (XmlException &e) {
				if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
					txn.abort();
					return JALDB_E_NOT_FOUND;
				}
				// re-throw e, it will get caught by the outer
				// try/catch block.
				throw(e);
			}
			XmlValue val;
			if (!sys_doc.getMetaData(JALDB_NS, JALDB_HAS_APP_META, val)) {
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			XmlDocument app_doc;
			bool has_app_meta = val.equals(true);
			if (has_app_meta) {
				try {
					app_doc = ctx->audit_app_cont->getDocument(txn, sid, DB_READ_COMMITTED);
				} catch (XmlException &e) {
					if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
						txn.abort();
						return JALDB_E_CORRUPTED;
					}
					// re-throw e, it will get caught by the outer
					// try/catch block.
					throw(e);
				}
			} else {
				app_meta_buf = NULL;
				app_meta_len = 0;
			}

			XmlDocument audit_doc;
			try {
				audit_doc = ctx->audit_cont->getDocument(txn, sid, DB_READ_COMMITTED);
			} catch (XmlException &e) {
				if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
					txn.abort();
					return JALDB_E_CORRUPTED;
				}
				// re-throw e, it will get caught by the outer
				// try/catch block.
				throw e;
			}

			XmlData sys_data = sys_doc.getContent();
			*sys_meta_buf = (uint8_t*)jal_malloc(sys_data.get_size());
			*sys_meta_len = sys_data.get_size();
			memcpy(*sys_meta_buf, sys_data.get_data(), sys_data.get_size());

			if (has_app_meta) {
				XmlData app_data = app_doc.getContent();
				*app_meta_buf = (uint8_t*)jal_malloc(app_data.get_size());
				*app_meta_len = app_data.get_size();
				memcpy(*app_meta_buf, app_data.get_data(), app_data.get_size());
			}

			XmlData audit_data = audit_doc.getContent();
			*audit_buf = (uint8_t*)jal_malloc(audit_data.get_size());
			*audit_len = audit_data.get_size();
			memcpy(*audit_buf, audit_data.get_data(), audit_data.get_size());

			txn.commit();
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_mark_audit_sent_ok(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}

	return jaldb_mark_sent_ok_common(ctx, ctx->audit_sys_cont, sid, remote_host);
}

enum jaldb_status jaldb_mark_journal_sent_ok(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}

	return jaldb_mark_sent_ok_common(ctx, ctx->journal_sys_cont, sid, remote_host);
}

enum jaldb_status jaldb_mark_log_sent_ok(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}

	return jaldb_mark_sent_ok_common(ctx, ctx->log_sys_cont, sid, remote_host);
}

enum jaldb_status jaldb_mark_sent_ok_common(
	jaldb_context *ctx,
	XmlContainer *cont,
	const char *sid,
	const char *remote_host)
{
	if (!ctx || !ctx->manager || !cont || !sid || !remote_host) {
		return JALDB_E_INVAL;
	}
	string sent_key(JALDB_REMOTE_META_PREFIX);
	sent_key += remote_host;
	sent_key += JALDB_SENT_META_SUFFIX;
	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while (true) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			XmlDocument sys_doc;
			try {
				sys_doc = cont->getDocument(txn, sid, DB_RMW | DB_READ_COMMITTED);
			} catch (XmlException &e) {
				if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
					txn.abort();
					return JALDB_E_NOT_FOUND;
				}
				// re-throw e, it will get caught by the outer
				// try/catch block.
				throw(e);
			}
			sys_doc.setMetaData(JALDB_NS, sent_key, true);
			sys_doc.setMetaData(JALDB_NS, JALDB_GLOBAL_SENT_KEY, true);
			cont->updateDocument(txn, sys_doc, uc);
			txn.commit();
			return JALDB_OK;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_mark_journal_synced(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}
	return jaldb_mark_synced_common(ctx, ctx->journal_sys_cont, sid, remote_host);
}

enum jaldb_status jaldb_mark_audit_synced(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}
	return jaldb_mark_synced_common(ctx, ctx->audit_sys_cont, sid, remote_host);
}

enum jaldb_status jaldb_mark_log_synced(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}
	return jaldb_mark_synced_common(ctx, ctx->log_sys_cont, sid, remote_host);
}

enum jaldb_status jaldb_mark_synced_common(
	jaldb_context *ctx,
	XmlContainer *cont,
	const char *sid,
	const char *remote_host)
{
	if (!ctx || !ctx->manager || !cont || !sid || !remote_host) {
		return JALDB_E_INVAL;
	}
	string synced_key(JALDB_QUERY_NS JALDB_REMOTE_META_PREFIX);
	synced_key += remote_host;
	synced_key += JALDB_SYNC_META_SUFFIX;

	string synced_key_no_ns(JALDB_REMOTE_META_PREFIX);
	synced_key_no_ns += remote_host;
	synced_key_no_ns += JALDB_SYNC_META_SUFFIX;

	string sent_key(JALDB_QUERY_NS JALDB_REMOTE_META_PREFIX);
	sent_key += remote_host;
	sent_key += JALDB_SENT_META_SUFFIX;

	XmlQueryContext qctx = ctx->manager->createQueryContext();
	qctx.setDefaultCollection(cont->getName());
	qctx.setVariableValue(JALDB_SYNC_META_VAR, synced_key);
	qctx.setVariableValue(JALDB_SENT_META_VAR, sent_key);
	qctx.setVariableValue(JALDB_SYNC_POINT_VAR, sid);

	XmlUpdateContext uc = ctx->manager->createUpdateContext();

	while (true) {
		XmlTransaction txn = ctx->manager->createTransaction();
		XmlTransaction qtxn = txn.createChild(DB_READ_COMMITTED);
		try {
			XmlQueryExpression qe = ctx->manager->prepare(txn, JALDB_FIND_UNCONFED_BY_HOST_QUERY, qctx);
			XmlResults res = qe.execute(qtxn, qctx, DB_RMW | DBXML_DOCUMENT_PROJECTION | DBXML_NO_AUTO_COMMIT |
					DB_READ_COMMITTED | DBXML_LAZY_DOCS);
			XmlDocument doc;
			while(res.next(doc)) {
				doc = cont->getDocument(txn, doc.getName(),
						DBXML_LAZY_DOCS | DB_READ_COMMITTED | DB_RMW);
				doc.setMetaData(JALDB_NS, synced_key_no_ns, true);
				doc.setMetaData(JALDB_NS, JALDB_GLOBAL_SYNCED_KEY, true);
				cont->updateDocument(txn, doc, uc);
			}
			res = XmlResults();
			qtxn.commit();
			txn.commit();
			break;
		} catch (XmlException &e) {
			qtxn.abort();
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_lookup_log_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **log_buf,
	size_t *log_len,
	int *db_err_out)
{
	if (!ctx || !ctx->manager || !ctx->log_sys_cont ||
			!ctx->log_app_cont || !ctx->log_dbp ||
			!db_err_out || !sid) {
		return JALDB_E_INVAL;
	}
	if (!sys_meta_buf || *sys_meta_buf || !sys_meta_len ||
			!app_meta_buf || *app_meta_buf || !app_meta_len ||
			!log_buf || *log_buf || !log_len) {
		return JALDB_E_INVAL;
	}


	while (true) {
		*sys_meta_buf = NULL;
		*app_meta_buf = NULL;
		*log_buf = NULL;
		*sys_meta_len = 0;
		*app_meta_len = 0;
		*log_len = 0;
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			XmlDocument sys_doc;
			try {
				sys_doc = ctx->log_sys_cont->getDocument(txn, sid, DB_READ_COMMITTED);
			} catch (XmlException &e) {
				if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
					txn.abort();
					return JALDB_E_NOT_FOUND;
				}
				// re-throw e, it will get caught by the outer
				// try/catch block.
				throw(e);
			}
			XmlValue val;
			if (!sys_doc.getMetaData(JALDB_NS, JALDB_HAS_APP_META, val)) {
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			bool has_app_meta = val.equals(true);
			if (!sys_doc.getMetaData(JALDB_NS, JALDB_HAS_LOG, val)) {
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			bool has_log = val.equals(true);
			if (!has_log && !has_app_meta) {
				txn.abort();
				return JALDB_E_CORRUPTED;
			}

			XmlDocument app_doc;
			if (has_app_meta) {
				try {
					app_doc = ctx->log_app_cont->getDocument(txn, sid, DB_READ_COMMITTED);
				} catch (XmlException &e) {
					if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
						txn.abort();
						return JALDB_E_CORRUPTED;
					}
					// re-throw e, it will get caught by the outer
					// try/catch block.
					throw(e);
				}
			} else {
				app_meta_buf = NULL;
				app_meta_len = 0;
			}
			XmlData sys_data = sys_doc.getContent();
			*sys_meta_buf = (uint8_t*)jal_malloc(sys_data.get_size());
			*sys_meta_len = sys_data.get_size();
			memcpy(*sys_meta_buf, sys_data.get_data(), sys_data.get_size());

			if (has_app_meta) {
				XmlData app_data = app_doc.getContent();
				*app_meta_buf = (uint8_t*)jal_malloc(app_data.get_size());
				*app_meta_len = app_data.get_size();
				memcpy(*app_meta_buf, app_data.get_data(), app_data.get_size());
			}

			if (has_log) {
				DBT key;
				DBT data;
				memset(&key, 0, sizeof(DBT));
				memset(&data, 0, sizeof(DBT));
				key.data = jal_strdup(sid);
				key.size = strlen(sid);
				data.flags = DB_DBT_MALLOC;
				int db_ret = ctx->log_dbp->get(ctx->log_dbp, txn.getDB_TXN(),
						&key, &data, DB_READ_COMMITTED);
				free(key.data);
				if (db_ret != 0) {
					txn.abort();
					free(*sys_meta_buf);
					*sys_meta_buf = NULL;
					free(*app_meta_buf);
					*app_meta_buf = NULL;
					free(data.data);
					if (db_ret == DB_LOCK_DEADLOCK) {
						continue;
					}
					*db_err_out = db_ret;
					return JALDB_E_DB;
				}
				*log_buf = (uint8_t*) data.data;
				*log_len = data.size;
			}
			txn.commit();
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (*sys_meta_buf) {
				free(*sys_meta_buf);
			}
			*sys_meta_buf = NULL;
			if (*app_meta_buf) {
				free(*app_meta_buf);
			}
			*app_meta_buf = NULL;
			if (*log_buf) {
				free(*log_buf);
			}
			*log_buf = NULL;
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_lookup_journal_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	int *fd, size_t *journal_size)
{
	if (!ctx || !ctx->manager || !ctx->journal_sys_cont ||
			!ctx->journal_app_cont || !sid) {
		return JALDB_E_INVAL;
	}
	if (!sys_meta_buf || *sys_meta_buf || !sys_meta_len ||
			!app_meta_buf || *app_meta_buf || !app_meta_len ||
			!fd || (*fd != -1) || !journal_size) {
		return JALDB_E_INVAL;
	}
	*fd = -1;
	while (1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			XmlDocument sys_doc;
			try {
				sys_doc = ctx->journal_sys_cont->getDocument(txn, sid, DB_READ_COMMITTED);
			} catch (XmlException &e) {
				if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
					txn.abort();
					return JALDB_E_NOT_FOUND;
				}
				// re-throw e, it will get caught by the outer
				// try/catch block.
				throw(e);
			}
			XmlValue val;
			if (!sys_doc.getMetaData(JALDB_NS, JALDB_HAS_APP_META, val)) {
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			XmlDocument app_doc;
			bool has_app_meta = val.equals(true);
			if (has_app_meta) {
				try {
					app_doc = ctx->journal_app_cont->getDocument(txn, sid, DB_READ_COMMITTED);
				} catch (XmlException &e) {
					if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
						txn.abort();
						return JALDB_E_CORRUPTED;
					}
					// re-throw e, it will get caught by the outer
					// try/catch block.
					throw(e);
				}
			} else {
				app_meta_buf = NULL;
				app_meta_len = 0;
			}

			if (!sys_doc.getMetaData(JALDB_NS, JALDB_JOURNAL_PATH, val)) {
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			stringstream full_path;
			full_path << ctx->journal_root << "/";
			full_path << val.asString();

			int flags = O_RDONLY | O_LARGEFILE;
#ifdef O_CLOEXEC
			flags |= O_CLOEXEC;
#endif
			*fd = open(full_path.str().c_str(), flags);
			if (*fd == -1) {
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			struct stat stat_buf;
			memset(&stat_buf, 0, sizeof(stat_buf));
			int stat_err = fstat(*fd, &stat_buf);
			if (stat_err != 0) {
				txn.abort();
				close(*fd);
				return JALDB_E_CORRUPTED;
			}
			*journal_size = stat_buf.st_size;

			XmlData sys_data = sys_doc.getContent();
			*sys_meta_buf = (uint8_t*)jal_malloc(sys_data.get_size());
			*sys_meta_len = sys_data.get_size();
			memcpy(*sys_meta_buf, sys_data.get_data(), sys_data.get_size());

			if (has_app_meta) {
				XmlData app_data = app_doc.getContent();
				*app_meta_buf = (uint8_t*)jal_malloc(app_data.get_size());
				*app_meta_len = app_data.get_size();
				memcpy(*app_meta_buf, app_data.get_data(), app_data.get_size());
			}
			txn.commit();
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (*fd != -1) {
				close(*fd);
			}
			*fd = -1;
			if (*sys_meta_buf) {
				free(*sys_meta_buf);
			}
			*sys_meta_buf = NULL;
			if (*app_meta_buf) {
				free(*app_meta_buf);
			}
			*app_meta_buf = NULL;
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_store_confed_journal_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out)
{
	if (!ctx || !ctx->manager) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	return jaldb_store_confed_sid_helper(ctx->journal_sys_cont,
			ctx->journal_conf_db, remote_host, sid, db_err_out);
}
enum jaldb_status jaldb_store_confed_audit_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out)
{
	if (!ctx || !ctx->manager || !ctx->audit_sys_cont) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	return jaldb_store_confed_sid_helper(ctx->audit_sys_cont,
			ctx->audit_conf_db, remote_host, sid, db_err_out);
}
enum jaldb_status jaldb_store_confed_log_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out)
{
	if (!ctx || !ctx->manager) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	return jaldb_store_confed_sid_helper(ctx->log_sys_cont,
			ctx->log_conf_db, remote_host, sid, db_err_out);
}
enum jaldb_status jaldb_store_confed_sid_helper(XmlContainer *cont, DB *db,
		const char *remote_host, const char *sid, int *db_err_out)
{
	if (!cont || !sid || !db_err_out) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status ret = JALDB_E_INVAL;
	while (1) {
		XmlTransaction txn = cont->getManager().createTransaction();
		try {
			XmlDocument doc = cont->getDocument(txn,
						JALDB_SERIAL_ID_DOC_NAME,
						DB_READ_COMMITTED);
			XmlValue val;
			if (!doc.getMetaData(JALDB_NS, JALDB_SERIAL_ID_NAME, val)) {
				// something is horribly wrong, there is no serial
				// ID in the database
				txn.abort();
				ret = JALDB_E_CORRUPTED;
				break;
			}
			if (!val.isString()) {
				txn.abort();
				ret = JALDB_E_CORRUPTED;
				break;
			}
			std::string next_sid = val.asString();
			if (jaldb_sid_cmp(next_sid.c_str(), next_sid.length(),
						sid, strlen(sid)) <= 0) {
				txn.abort();
				ret = JALDB_E_SID;
				break;
			}
			ret = jaldb_store_confed_sid(db, txn.getDB_TXN(),
					remote_host, sid, db_err_out);
			if (ret != JALDB_OK) {
				txn.abort();
				if (*db_err_out == DB_LOCK_DEADLOCK) {
					continue;
				}
				break;
			}
			txn.commit();
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR) {
				if (e.getDbErrno() == DB_LOCK_DEADLOCK) {
					continue;
				}
			}
			throw e;
		}
	}
	return ret;
}

enum jaldb_status jaldb_next_journal_record(
	jaldb_context *ctx,
	const char *last_sid,
	char **next_sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	int *fd, size_t *journal_size)
{
	if (!ctx || !ctx->manager || !ctx->journal_sys_cont ||
			!ctx->journal_app_cont || !last_sid ||
			(0 == strlen(last_sid)) || !next_sid || *next_sid) {
		return JALDB_E_INVAL;
	}
	if (!sys_meta_buf || *sys_meta_buf || !sys_meta_len ||
			!app_meta_buf || *app_meta_buf || !app_meta_len ||
			!fd || (*fd != -1) || !journal_size) {
		return JALDB_E_INVAL;
	}
	*fd = -1;

	XmlQueryContext qctx = ctx->manager->createQueryContext();
	qctx.setVariableValue("last_sid", last_sid);
	qctx.setDefaultCollection(JALDB_JOURNAL_SYS_META_CONT_NAME);
	qctx.setEvaluationType(XmlQueryContext::Lazy);

	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while (1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		XmlTransaction qtxn = txn.createChild(DB_READ_COMMITTED);
		try {
			XmlQueryExpression qe = ctx->manager->prepare(txn, JALDB_NEXT_SID_QUERY , qctx);
			XmlResults res = qe.execute(qtxn, qctx, DBXML_DOCUMENT_PROJECTION | DBXML_NO_AUTO_COMMIT | DB_READ_COMMITTED | DBXML_LAZY_DOCS);
			XmlDocument sys_doc;
			if (!res.next(sys_doc)) {
				qtxn.abort();
				txn.abort();
				return JALDB_E_NOT_FOUND;
			}
			res = XmlResults();
			string sid = sys_doc.getName();

			XmlValue val;
			if (!sys_doc.getMetaData(JALDB_NS, JALDB_HAS_APP_META, val)) {
				qtxn.abort();
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			XmlDocument app_doc;
			bool has_app_meta = val.equals(true);
			if (has_app_meta) {
				try {
					app_doc = ctx->journal_app_cont->getDocument(txn, sid, DB_READ_COMMITTED);
				} catch (XmlException &e) {
					if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
						qtxn.abort();
						txn.abort();
						return JALDB_E_CORRUPTED;
					}
					// re-throw e, it will get caught by the outer
					// try/catch block.
					throw(e);
				}
			} else {
				app_meta_buf = NULL;
				app_meta_len = 0;
			}

			if (!sys_doc.getMetaData(JALDB_NS, JALDB_JOURNAL_PATH, val)) {
				qtxn.abort();
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			stringstream full_path;
			full_path << ctx->journal_root << "/";
			full_path << val.asString();

			int flags = O_RDONLY | O_LARGEFILE;
#ifdef O_CLOEXEC
			flags |= O_CLOEXEC;
#endif
			*fd = open(full_path.str().c_str(), flags);
			if (*fd == -1) {
				qtxn.abort();
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			struct stat stat_buf;
			memset(&stat_buf, 0, sizeof(stat_buf));
			int stat_err = fstat(*fd, &stat_buf);
			if (stat_err != 0) {
				qtxn.abort();
				txn.abort();
				close(*fd);
				return JALDB_E_CORRUPTED;
			}
			*journal_size = stat_buf.st_size;

			XmlData sys_data = sys_doc.getContent();
			qtxn.commit();
			*sys_meta_buf = (uint8_t*)jal_malloc(sys_data.get_size());
			*sys_meta_len = sys_data.get_size();
			memcpy(*sys_meta_buf, sys_data.get_data(), sys_data.get_size());

			if (has_app_meta) {
				XmlData app_data = app_doc.getContent();
				*app_meta_buf = (uint8_t*)jal_malloc(app_data.get_size());
				*app_meta_len = app_data.get_size();
				memcpy(*app_meta_buf, app_data.get_data(), app_data.get_size());
			}
			*next_sid = jal_strdup(sid.c_str());
			txn.commit();
			break;
		} catch (XmlException &e) {
			qtxn.abort();
			txn.abort();
			if (*fd != -1) {
				close(*fd);
			}
			*fd = -1;
			if (*sys_meta_buf) {
				free(*sys_meta_buf);
			}
			*sys_meta_buf = NULL;
			if (*app_meta_buf) {
				free(*app_meta_buf);
			}
			*app_meta_buf = NULL;
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_next_audit_record(
	jaldb_context *ctx,
	const char *last_sid,
	char **next_sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **audit_buf,
	size_t *audit_len)
{
	if (!ctx || !ctx->manager || !ctx->audit_sys_cont ||
			!ctx->audit_app_cont || !ctx->audit_cont ||
			!last_sid || (0 == strlen(last_sid)) ||
			!next_sid || *next_sid) {
		return JALDB_E_INVAL;
	}
	if (!sys_meta_buf || *sys_meta_buf || !sys_meta_len ||
			!app_meta_buf || *app_meta_buf || !app_meta_len ||
			!audit_buf || *audit_buf || !audit_len) {
		return JALDB_E_INVAL;
	}
	XmlQueryContext qctx = ctx->manager->createQueryContext();
	qctx.setVariableValue("last_sid", last_sid);
	qctx.setDefaultCollection(JALDB_AUDIT_SYS_META_CONT_NAME);
	qctx.setEvaluationType(XmlQueryContext::Lazy);

	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while (true) {
		XmlTransaction txn = ctx->manager->createTransaction();
		XmlTransaction qtxn = txn.createChild(DB_READ_COMMITTED);
		try {
			XmlQueryExpression qe = ctx->manager->prepare(txn, JALDB_NEXT_SID_QUERY , qctx);
			XmlResults res = qe.execute(qtxn, qctx, DBXML_DOCUMENT_PROJECTION | DBXML_NO_AUTO_COMMIT | DB_READ_COMMITTED | DBXML_LAZY_DOCS);
			XmlDocument sys_doc;
			if (!res.next(sys_doc)) {
				qtxn.abort();
				txn.abort();
				return JALDB_E_NOT_FOUND;
			}
			string sid = sys_doc.getName();
			res = XmlResults();

			XmlValue val;
			if (!sys_doc.getMetaData(JALDB_NS, JALDB_HAS_APP_META, val)) {
				qtxn.abort();
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			XmlDocument app_doc;
			bool has_app_meta = val.equals(true);
			if (has_app_meta) {
				try {
					app_doc = ctx->audit_app_cont->getDocument(txn, sid, DB_READ_COMMITTED);
				} catch (XmlException &e) {
					if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
						qtxn.abort();
						txn.abort();
						return JALDB_E_CORRUPTED;
					}
					// re-throw e, it will get caught by the outer
					// try/catch block.
					throw(e);
				}
			} else {
				app_meta_buf = NULL;
				app_meta_len = 0;
			}

			XmlDocument audit_doc;
			try {
				audit_doc = ctx->audit_cont->getDocument(txn, sid, DB_READ_COMMITTED);
			} catch (XmlException &e) {
				if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
					qtxn.abort();
					txn.abort();
					return JALDB_E_CORRUPTED;
				}
				// re-throw e, it will get caught by the outer
				// try/catch block.
				throw e;
			}

			XmlData sys_data = sys_doc.getContent();
			qtxn.commit();
			*sys_meta_buf = (uint8_t*)jal_malloc(sys_data.get_size());
			*sys_meta_len = sys_data.get_size();
			memcpy(*sys_meta_buf, sys_data.get_data(), sys_data.get_size());

			if (has_app_meta) {
				XmlData app_data = app_doc.getContent();
				*app_meta_buf = (uint8_t*)jal_malloc(app_data.get_size());
				*app_meta_len = app_data.get_size();
				memcpy(*app_meta_buf, app_data.get_data(), app_data.get_size());
			}

			XmlData audit_data = audit_doc.getContent();
			*audit_buf = (uint8_t*)jal_malloc(audit_data.get_size());
			*audit_len = audit_data.get_size();
			memcpy(*audit_buf, audit_data.get_data(), audit_data.get_size());

			*next_sid = jal_strdup(sid.c_str());
			txn.commit();
			break;
		} catch (XmlException &e) {
			qtxn.abort();
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_next_log_record(
	jaldb_context *ctx,
	const char *last_sid,
	char **next_sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **log_buf,
	size_t *log_len,
	int *db_err_out)
{
	if (!ctx || !ctx->manager || !ctx->log_sys_cont ||
			!ctx->log_app_cont || !ctx->log_dbp ||
			!db_err_out || !last_sid || (0 == strlen(last_sid)) ||
			!next_sid || *next_sid) {
		return JALDB_E_INVAL;
	}
	if (!sys_meta_buf || *sys_meta_buf || !sys_meta_len ||
			!app_meta_buf || *app_meta_buf || !app_meta_len ||
			!log_buf || *log_buf || !log_len) {
		return JALDB_E_INVAL;
	}

	XmlQueryContext qctx = ctx->manager->createQueryContext();
	qctx.setVariableValue("last_sid", last_sid);
	qctx.setDefaultCollection(JALDB_LOG_SYS_META_CONT_NAME);
	qctx.setEvaluationType(XmlQueryContext::Lazy);

	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while (true) {
		*sys_meta_buf = NULL;
		*app_meta_buf = NULL;
		*log_buf = NULL;
		*sys_meta_len = 0;
		*app_meta_len = 0;
		*log_len = 0;
		XmlTransaction txn = ctx->manager->createTransaction();
		XmlTransaction qtxn = txn.createChild(DB_READ_COMMITTED);
		try {
			XmlQueryExpression qe = ctx->manager->prepare(txn, JALDB_NEXT_SID_QUERY , qctx);
			XmlResults res = qe.execute(qtxn, qctx, DBXML_DOCUMENT_PROJECTION | DBXML_NO_AUTO_COMMIT | DB_READ_COMMITTED | DBXML_LAZY_DOCS);
			XmlDocument sys_doc;
			if (!res.next(sys_doc)) {
				qtxn.abort();
				txn.abort();
				return JALDB_E_NOT_FOUND;
			}
			res = XmlResults();
			string sid = sys_doc.getName();
			XmlValue val;
			if (!sys_doc.getMetaData(JALDB_NS, JALDB_HAS_APP_META, val)) {
				qtxn.abort();
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			bool has_app_meta = val.equals(true);
			if (!sys_doc.getMetaData(JALDB_NS, JALDB_HAS_LOG, val)) {
				qtxn.abort();
				txn.abort();
				return JALDB_E_CORRUPTED;
			}
			bool has_log = val.equals(true);
			if (!has_log && !has_app_meta) {
				qtxn.abort();
				txn.abort();
				return JALDB_E_CORRUPTED;
			}

			XmlDocument app_doc;
			if (has_app_meta) {
				try {
					app_doc = ctx->log_app_cont->getDocument(txn, sid, DB_READ_COMMITTED);
				} catch (XmlException &e) {
					if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
						qtxn.abort();
						txn.abort();
						return JALDB_E_CORRUPTED;
					}
					// re-throw e, it will get caught by the outer
					// try/catch block.
					throw(e);
				}
			} else {
				app_meta_buf = NULL;
				app_meta_len = 0;
			}
			XmlData sys_data = sys_doc.getContent();
			qtxn.commit();
			*sys_meta_buf = (uint8_t*)jal_malloc(sys_data.get_size());
			*sys_meta_len = sys_data.get_size();
			memcpy(*sys_meta_buf, sys_data.get_data(), sys_data.get_size());
			*next_sid = jal_strdup(sid.c_str());

			if (has_app_meta) {
				XmlData app_data = app_doc.getContent();
				*app_meta_buf = (uint8_t*)jal_malloc(app_data.get_size());
				*app_meta_len = app_data.get_size();
				memcpy(*app_meta_buf, app_data.get_data(), app_data.get_size());
			}

			if (has_log) {
				DBT key;
				DBT data;
				memset(&key, 0, sizeof(DBT));
				memset(&data, 0, sizeof(DBT));
				key.data = jal_strdup(sid.c_str());
				key.size = sid.length();
				data.flags = DB_DBT_MALLOC;
				int db_ret = ctx->log_dbp->get(ctx->log_dbp, txn.getDB_TXN(),
						&key, &data, DB_READ_COMMITTED);
				free(key.data);
				if (db_ret != 0) {
					qtxn.abort();
					txn.abort();
					free(*sys_meta_buf);
					*sys_meta_buf = NULL;
					free(*app_meta_buf);
					*app_meta_buf = NULL;
					free(data.data);
					if (db_ret == DB_LOCK_DEADLOCK) {
						continue;
					}
					*db_err_out = db_ret;
					return JALDB_E_DB;
				}
				*log_buf = (uint8_t*) data.data;
				*log_len = data.size;
			}
			txn.commit();
			break;
		} catch (XmlException &e) {
			qtxn.abort();
			txn.abort();
			if (*sys_meta_buf) {
				free(*sys_meta_buf);
			}
			*sys_meta_buf = NULL;
			if (*app_meta_buf) {
				free(*app_meta_buf);
			}
			*app_meta_buf = NULL;
			if (*log_buf) {
				free(*log_buf);
			}
			*log_buf = NULL;
			if (*next_sid) {
				free(*next_sid);
			}
			*next_sid = NULL;
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_store_confed_journal_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		const char *sid,
		int *db_err_out)
{
	jaldb_status ret;
	if (!ctx || !ctx->manager) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	string sys_db = jaldb_make_temp_db_name(remote_host,
			JALDB_JOURNAL_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	ret = jaldb_open_temp_container(ctx, sys_db, sys_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	return jaldb_store_confed_sid_tmp_helper(ctx, &sys_cont,
				remote_host, sid, db_err_out);
}

enum jaldb_status jaldb_store_confed_audit_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		const char *sid,
		int *db_err_out)
{
	jaldb_status ret;
	if (!ctx || !ctx->manager) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	string sys_db = jaldb_make_temp_db_name(remote_host,
			JALDB_AUDIT_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	ret = jaldb_open_temp_container(ctx, sys_db, sys_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	return jaldb_store_confed_sid_tmp_helper(ctx, &sys_cont,
				remote_host, sid, db_err_out);
}

enum jaldb_status jaldb_store_confed_log_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		const char *sid,
		int *db_err_out)
{
	jaldb_status ret;
	if (!ctx || !ctx->manager) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	string sys_db = jaldb_make_temp_db_name(remote_host,
			JALDB_LOG_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	ret = jaldb_open_temp_container(ctx, sys_db, sys_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	return jaldb_store_confed_sid_tmp_helper(ctx, &sys_cont,
				remote_host, sid, db_err_out);
}

enum jaldb_status jaldb_store_confed_sid_tmp_helper(
		jaldb_context *ctx,
		XmlContainer *cont,
		const char *remote_host,
		const char *sid,
		int *db_err_out)
{
	if (!cont || !sid || !db_err_out) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status ret = JALDB_E_INVAL;
	while (1) {
		XmlUpdateContext uc = ctx->manager->createUpdateContext();
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			XmlDocument doc;
			bool wasFound = true;
			try {
				doc = cont->getDocument(txn,
						JALDB_CONNECTION_METADATA_DOC_NAME,
						DB_READ_COMMITTED);
			} catch (XmlException &e){
				if (e.getExceptionCode()
					== XmlException::DOCUMENT_NOT_FOUND) {
					wasFound = false;
				}
				else {
					throw e;
				}
			}
			if (!wasFound) {
				doc = ctx->manager->createDocument();
				doc.setName(JALDB_CONNECTION_METADATA_DOC_NAME);
				cont->putDocument(txn, doc, uc);
			}
			doc.setMetaData(JALDB_NS,
					JALDB_LAST_CONFED_SID_NAME,
					sid);
			cont->updateDocument(txn, doc, uc);
			txn.commit();
			ret = JALDB_OK;
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() ==
				XmlException::UNIQUE_ERROR) {
				return JALDB_E_SID;
			}
			if (e.getExceptionCode() ==
				XmlException::DOCUMENT_NOT_FOUND) {
				return JALDB_E_NOT_FOUND;
			}
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR) {
				if (e.getDbErrno()
					== DB_LOCK_DEADLOCK) {
					continue;
				}
			}
			return JALDB_E_DB;
		}
	}
	return ret;
}

enum jaldb_status jaldb_get_last_confed_journal_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		std::string &sid,
		int *db_err_out)
{
	jaldb_status ret;
	if (!ctx || !ctx->manager) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	string sys_db = jaldb_make_temp_db_name(remote_host,
			JALDB_JOURNAL_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	ret = jaldb_open_temp_container(ctx, sys_db, sys_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	return jaldb_get_last_confed_sid_tmp_helper(ctx, &sys_cont,
				remote_host, sid, db_err_out);
}

enum jaldb_status jaldb_get_last_confed_audit_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		std::string &sid,
		int *db_err_out)
{
	jaldb_status ret;
	if (!ctx || !ctx->manager) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	string sys_db = jaldb_make_temp_db_name(remote_host,
			JALDB_AUDIT_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	ret = jaldb_open_temp_container(ctx, sys_db, sys_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	return jaldb_get_last_confed_sid_tmp_helper(ctx, &sys_cont,
				remote_host, sid, db_err_out);
}

enum jaldb_status jaldb_get_last_confed_log_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		std::string &sid,
		int *db_err_out)
{
	jaldb_status ret;
	if (!ctx || !ctx->manager) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	string sys_db = jaldb_make_temp_db_name(remote_host,
			JALDB_LOG_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	ret = jaldb_open_temp_container(ctx, sys_db, sys_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	return jaldb_get_last_confed_sid_tmp_helper(ctx, &sys_cont,
				remote_host, sid, db_err_out);
}

enum jaldb_status jaldb_get_last_confed_sid_tmp_helper(
		jaldb_context *ctx,
		XmlContainer *cont,
		const std::string &remote_host,
		std::string &sid,
		int *db_err_out)
{
	if (!cont || (0 < sid.length()) ||
		(0 == remote_host.length()) || !db_err_out) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status ret = JALDB_E_INVAL;
	while (1) {
		XmlUpdateContext uc = ctx->manager->createUpdateContext();
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			XmlDocument doc;
			doc = cont->getDocument(txn,
						JALDB_CONNECTION_METADATA_DOC_NAME,
						DB_READ_COMMITTED);
			XmlValue val;
			if (!doc.getMetaData(JALDB_NS,
				JALDB_LAST_CONFED_SID_NAME,
				val)) {
				txn.abort();
				ret = JALDB_E_NOT_FOUND;
				break;
			}
			if (!val.isString()) {
				txn.abort();
				ret = JALDB_E_CORRUPTED;
				break;
			}
			sid = val.asString();
			txn.abort();
			ret = JALDB_OK;
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() ==
				XmlException::DATABASE_ERROR) {
				if (e.getDbErrno()
					== DB_LOCK_DEADLOCK) {
					continue;
				}
			}
			if (e.getExceptionCode()
				== XmlException::DOCUMENT_NOT_FOUND) {
				return JALDB_E_NOT_FOUND;
			}
			return JALDB_E_DB;
		}
	}
	return ret;
}

enum jaldb_status jaldb_store_journal_resume(
		jaldb_context *ctx,
		const char *remote_host,
		const char *path,
		uint64_t offset)
{
	if (!ctx || !ctx->manager || !remote_host ||
		!path  || !ctx->journal_sys_cont) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	enum jaldb_status ret = JALDB_E_INVAL;
	string sys_db = jaldb_make_temp_db_name(remote_host,
			JALDB_LOG_SYS_META_CONT_NAME);
	XmlContainer cont;
	ret = jaldb_open_temp_container(ctx, sys_db, cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	char *offset_buf = (char *) jal_malloc(21);
	snprintf(offset_buf, 21, "%" PRIu64, offset);
	while (1) {
		XmlUpdateContext uc = ctx->manager->createUpdateContext();
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			XmlDocument doc;
			bool wasFound = true;
			try {
				doc = cont.getDocument(txn,
						JALDB_CONNECTION_METADATA_DOC_NAME,
						DB_READ_COMMITTED);
			} catch (XmlException &e){
				if (e.getExceptionCode()
					== XmlException::DOCUMENT_NOT_FOUND) {
					wasFound = false;
				}
				else {
					txn.abort();
					return JALDB_E_NOT_FOUND;
				}
			}
			if (!wasFound) {
				doc = ctx->manager->createDocument();
				doc.setName(JALDB_CONNECTION_METADATA_DOC_NAME);
				cont.putDocument(txn, doc, uc);
			}
			doc.setMetaData(JALDB_NS,
					JALDB_OFFSET_NAME,
					offset_buf);
			doc.setMetaData(JALDB_NS,
					JALDB_JOURNAL_PATH,
					path);
			cont.updateDocument(txn, doc, uc);
			txn.commit();
			ret = JALDB_OK;
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() ==
				XmlException::DATABASE_ERROR) {
				if (e.getDbErrno()
					== DB_LOCK_DEADLOCK) {
					continue;
				}
			}
			if (e.getExceptionCode() ==
				XmlException::UNIQUE_ERROR) {
				return JALDB_E_SID;
			}
			if (e.getExceptionCode() ==
				XmlException::DOCUMENT_NOT_FOUND) {
				return JALDB_E_NOT_FOUND;
			}
			return JALDB_E_DB;
		}
	}
	return ret;
}

enum jaldb_status jaldb_get_journal_resume(
		jaldb_context *ctx,
		const char *remote_host,
		char **path,
		uint64_t &offset)
{
	if (!ctx || !remote_host || *path ) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status ret = JALDB_E_INVAL;
	string sys_db = jaldb_make_temp_db_name(remote_host,
			JALDB_LOG_SYS_META_CONT_NAME);
	XmlContainer cont;
	ret = jaldb_open_temp_container(ctx, sys_db, cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	while (1) {
		XmlUpdateContext uc = ctx->manager->createUpdateContext();
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			XmlDocument doc;
			doc = cont.getDocument(txn,
					JALDB_CONNECTION_METADATA_DOC_NAME,
					DB_READ_COMMITTED);
			bool offset_found = true;
			bool path_found = true;
			XmlValue offset_val;
			XmlValue path_val;
			if (!doc.getMetaData(JALDB_NS,
				JALDB_OFFSET_NAME,
				offset_val)) {
				offset_found = false;
			}
			if (!doc.getMetaData(JALDB_NS,
				JALDB_JOURNAL_PATH, path_val)) {
				path_found = false;
			}
			if (!offset_found && !path_found) {
				txn.abort();
				ret = JALDB_E_NOT_FOUND;
				break;
			}
			if (!offset_found || !path_found) {
				txn.abort();
				ret = JALDB_E_CORRUPTED;
				break;
			}
			if (!offset_val.isString()) {
				txn.abort();
				ret = JALDB_E_CORRUPTED;
				break;
			}
			const char *offset_str = offset_val.asString().c_str();
			if (0 > sscanf(offset_str, "%" PRIu64, &offset)) {
				// Failed to parse offset
				ret = JALDB_E_CORRUPTED;
				break;
			}
			if (!path_val.isString()) {
				txn.abort();
				ret = JALDB_E_CORRUPTED;
				break;
			}
			*path = jal_strdup((char *) path_val.asString().c_str());
			txn.abort();
			ret = JALDB_OK;
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() ==
				XmlException::DATABASE_ERROR) {
				if (e.getDbErrno()
					== DB_LOCK_DEADLOCK) {
					continue;
				}
			}
			if (e.getExceptionCode() ==
				XmlException::UNIQUE_ERROR) {
				return JALDB_E_SID;
			}
			if (e.getExceptionCode() ==
				XmlException::DOCUMENT_NOT_FOUND) {
				return JALDB_E_NOT_FOUND;
			}
			return JALDB_E_DB;
		}
	}
	return ret;
}

enum jaldb_status jaldb_purge_unconfirmed_log(
		jaldb_context *ctx,
		const char *remote_host,
		int *db_err)
{
	if (!ctx || !remote_host || !db_err || (0 == strlen(remote_host))) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	enum jaldb_status ret = JALDB_E_INVAL;
	string sys_db = jaldb_make_temp_db_name(remote_host,
			JALDB_LOG_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(remote_host,
			JALDB_LOG_APP_META_CONT_NAME);
	string log_db_name = jaldb_make_temp_db_name(remote_host,
			JALDB_LOG_DB_NAME);
	XmlContainer sys_cont;
	XmlContainer app_cont;
	DB *log_db = NULL;

	ret = jaldb_open_temp_container(ctx, sys_db, sys_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	ret = jaldb_open_temp_container(ctx, app_db, app_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	ret = jaldb_open_temp_db(ctx, log_db_name, &log_db, db_err);
	if (ret != JALDB_OK) {
		return ret;
	}

	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while (1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			bool found_sid_doc = false;
			XmlDocument sid_doc;
			try {
				sid_doc = sys_cont.getDocument(txn, JALDB_CONNECTION_METADATA_DOC_NAME,
						DB_RMW | DBXML_LAZY_DOCS | DB_READ_COMMITTED);
				found_sid_doc = true;
			} catch (XmlException &e) {
				if (e.getExceptionCode() != XmlException::DOCUMENT_NOT_FOUND) {
					throw e;
				}
			}
			XmlResults res = sys_cont.getAllDocuments(txn, DB_RMW | DBXML_LAZY_DOCS | DB_READ_COMMITTED);
			XmlDocument doc;
			while (res.next(doc)) {
				sys_cont.deleteDocument(txn, doc, uc);
			}
			res = app_cont.getAllDocuments(txn, DB_RMW | DBXML_LAZY_DOCS | DB_READ_COMMITTED);
			while (res.next(doc)) {
				app_cont.deleteDocument(txn, doc, uc);
			}
			res = XmlResults();

			DBT key;
			DBT data;
			memset(&key, 0, sizeof(key));
			memset(&data, 0, sizeof(data));

			DBC *cursor = NULL;
			*db_err = log_db->cursor(log_db, txn.getDB_TXN(), &cursor, DB_READ_COMMITTED);
			if (0 != *db_err) {
				txn.abort();
				return JALDB_E_DB;
			}
			while(0 == (*db_err = cursor->get(cursor, &key, &data, DB_NEXT))) {
				cursor->del(cursor, 0);
			}
			if (cursor) {
				cursor->close(cursor);
			}
			if (found_sid_doc) {
				sys_cont.putDocument(txn, sid_doc, uc);
			}
			txn.commit();
			ret = JALDB_OK;
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() ==
				XmlException::DATABASE_ERROR &&
				e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return ret;
}

enum jaldb_status jaldb_purge_unconfirmed_audit(
		jaldb_context *ctx,
		const char *remote_host)
{
	if (!ctx || !remote_host || (0 == strlen(remote_host))) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	enum jaldb_status ret = JALDB_E_INVAL;
	string sys_db = jaldb_make_temp_db_name(remote_host,
			JALDB_AUDIT_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(remote_host,
			JALDB_AUDIT_APP_META_CONT_NAME);
	string audit_db = jaldb_make_temp_db_name(remote_host,
			JALDB_AUDIT_CONT_NAME);
	XmlContainer sys_cont;
	XmlContainer app_cont;
	XmlContainer audit_cont;

	ret = jaldb_open_temp_container(ctx, sys_db, sys_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	ret = jaldb_open_temp_container(ctx, app_db, app_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	ret = jaldb_open_temp_container(ctx, audit_db, audit_cont);
	if (ret != JALDB_OK) {
		return ret;
	}

	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while (1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			bool found_sid_doc = false;
			XmlDocument sid_doc;
			try {
				sid_doc = sys_cont.getDocument(txn, JALDB_CONNECTION_METADATA_DOC_NAME,
						DB_RMW | DBXML_LAZY_DOCS | DB_READ_COMMITTED);
				found_sid_doc = true;
			} catch (XmlException &e) {
				if (e.getExceptionCode() != XmlException::DOCUMENT_NOT_FOUND) {
					throw e;
				}
			}
			XmlResults res = sys_cont.getAllDocuments(txn, DB_RMW | DBXML_LAZY_DOCS | DB_READ_COMMITTED);
			XmlDocument doc;
			while (res.next(doc)) {
				sys_cont.deleteDocument(txn, doc, uc);
			}
			res = app_cont.getAllDocuments(txn, DB_RMW | DBXML_LAZY_DOCS | DB_READ_COMMITTED);
			while (res.next(doc)) {
				app_cont.deleteDocument(txn, doc, uc);
			}
			res = audit_cont.getAllDocuments(txn, DB_RMW | DBXML_LAZY_DOCS | DB_READ_COMMITTED);
			while (res.next(doc)) {
				audit_cont.deleteDocument(txn, doc, uc);
			}
			res = XmlResults();
			if (found_sid_doc) {
				sys_cont.putDocument(txn, sid_doc, uc);
			}
			txn.commit();
			ret = JALDB_OK;
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() ==
				XmlException::DATABASE_ERROR &&
				e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			throw e;
		}
	}
	return ret;
}

enum jaldb_status jaldb_purge_unconfirmed_journal(
		jaldb_context *ctx,
		const char *remote_host)
{
	if (!ctx || !remote_host || (0 == strlen(remote_host))) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	enum jaldb_status ret = JALDB_E_INVAL;
	string sys_db = jaldb_make_temp_db_name(remote_host,
			JALDB_JOURNAL_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(remote_host,
			JALDB_JOURNAL_APP_META_CONT_NAME);
	XmlContainer sys_cont;
	XmlContainer app_cont;

	ret = jaldb_open_temp_container(ctx, sys_db, sys_cont);
	if (ret != JALDB_OK) {
		return ret;
	}
	ret = jaldb_open_temp_container(ctx, app_db, app_cont);
	if (ret != JALDB_OK) {
		return ret;
	}

	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	while (1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			bool found_sid_doc = false;
			XmlDocument sid_doc;
			try {
				sid_doc = sys_cont.getDocument(txn, JALDB_CONNECTION_METADATA_DOC_NAME,
						DB_RMW | DBXML_LAZY_DOCS | DB_READ_COMMITTED);
				found_sid_doc = true;
			} catch (XmlException &e) {
				if (e.getExceptionCode() != XmlException::DOCUMENT_NOT_FOUND) {
					throw e;
				}
			}
			XmlResults res = sys_cont.getAllDocuments(txn, DB_RMW | DBXML_LAZY_DOCS | DB_READ_COMMITTED);
			XmlDocument doc;
			list<string> files_to_remove;
			while (res.next(doc)) {
				XmlValue val;
				if (doc.getMetaData(JALDB_NS, JALDB_JOURNAL_PATH, val)) {
					files_to_remove.push_back(val.asString());
				}
				sys_cont.deleteDocument(txn, doc.getName(), uc);
			}
			res = app_cont.getAllDocuments(txn, DB_RMW | DBXML_LAZY_DOCS | DB_READ_COMMITTED);
			while (res.next(doc)) {
				app_cont.deleteDocument(txn, doc, uc);
			}
			res = XmlResults();
			if (found_sid_doc) {
				sys_cont.putDocument(txn, sid_doc, uc);
			}
			txn.commit();
			for(list<string>::iterator iter = files_to_remove.begin(); iter != files_to_remove.end(); iter++) {
				string full_path = ctx->journal_root;
				full_path.append("/").append(*iter);
				unlink(full_path.c_str());
			}
			ret = JALDB_OK;
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() ==
				XmlException::DATABASE_ERROR &&
				e.getDbErrno() == DB_LOCK_DEADLOCK) {
				continue;
			}
			std::cout << e.getExceptionCode() << std::endl;
			throw e;
		}
	}
	return ret;
}

enum jaldb_status jaldb_get_journal_document_list(
	jaldb_context *ctx,
	list<string> **doc_list)
{
	if (!ctx || !doc_list || *doc_list) {
		return JALDB_E_INVAL;
	}
	return jaldb_get_document_list(
					ctx->journal_sys_cont,
					ctx->manager,
					doc_list);
}

enum jaldb_status jaldb_get_audit_document_list(
		jaldb_context *ctx,
		list<string> **doc_list)
{
	if (!ctx || !doc_list || *doc_list) {
		return JALDB_E_INVAL;
	}
	return jaldb_get_document_list(
					ctx->audit_sys_cont,
					ctx->manager,
					doc_list);
}

enum jaldb_status jaldb_get_log_document_list(
		jaldb_context *ctx,
		list<string> **doc_list)
{
	if (!ctx || !doc_list || *doc_list) {
		return JALDB_E_INVAL;
	}
	return jaldb_get_document_list(
					ctx->log_sys_cont,
					ctx->manager,
					doc_list);
}

enum jaldb_status jaldb_get_document_list(
		XmlContainer *cont,
		XmlManager *mgr,
		list<string> **doc_list)
{
	if (!cont || !mgr || !doc_list || *doc_list) {
		return JALDB_E_INVAL;
	}
	while (1) {
		*doc_list = new list<string>();
		XmlTransaction txn = mgr->createTransaction();
		try {
			XmlResults res = cont->getAllDocuments(txn, DB_RMW |
				DBXML_LAZY_DOCS | DB_READ_COMMITTED);
			XmlDocument doc;
			while (res.next(doc)) {
				(*doc_list)->push_back(doc.getName());
			}
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() ==
				XmlException::DATABASE_ERROR &&
				e.getDbErrno() == DB_LOCK_DEADLOCK) {
				delete *doc_list;
				continue;
			}
			return JALDB_E_DB;
		}
	}
	return JALDB_OK;
}
