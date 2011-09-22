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

#include <fcntl.h>
#include <string.h>
#include <sstream>
#include <sys/stat.h>
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
	int db_recover_flag)
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
	cfg.setAllowCreate(true);
	cfg.setThreaded(true);
	cfg.setTransactional(true);

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

	jaldb_initialize_serial_id(txn, *ctx->journal_sys_cont, &db_err);
	jaldb_initialize_serial_id(txn, *ctx->audit_sys_cont, &db_err);
	jaldb_initialize_serial_id(txn, *ctx->log_sys_cont, &db_err);
	DB_TXN *db_txn = txn.getDB_TXN();
	int db_ret = 0;

	db_ret = db_create(&ctx->journal_conf_db, env, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->journal_conf_db), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->journal_conf_db->open(ctx->journal_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_JOURNAL_CONF_NAME, DB_BTREE, DB_CREATE, 0);
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
			JALDB_CONF_DB, JALDB_AUDIT_CONF_NAME, DB_BTREE, DB_CREATE, 0);
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
			JALDB_CONF_DB, JALDB_LOG_CONF_NAME, DB_BTREE, DB_CREATE, 0);
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
			JALDB_LOG_DB_NAME, NULL, DB_BTREE, DB_CREATE, 0);
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
	string_to_container_map::iterator iter = ctx->temp_containers->find(db_name);
	if (iter == ctx->temp_containers->end()) {
		XmlContainerConfig cfg;
		cfg.setAllowCreate(true);
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
	DB *db;
	int db_err = 0;
	enum jaldb_status ret = JALDB_E_DB;
	string_to_db_map::iterator iter = ctx->temp_dbs->find(db_name);
	if (iter == ctx->temp_dbs->end()) {
		DB_ENV *env = ctx->manager->getDB_ENV();
		db_err = db_create(&db, env, 0);
		if (db_err != 0) {
			db = NULL;
			goto out;
		}
		db_err = db->open(db, NULL, db_name.c_str(), NULL, DB_BTREE, DB_CREATE | DB_AUTO_COMMIT | DB_THREAD, 0);
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
	return JALDB_OK;
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
	return jaldb_create_file(ctx->journal_root, path, fd);
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
					free(key.data);
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
	return jaldb_store_confed_sid_helper(ctx->journal_sys_cont,
			ctx->journal_conf_db, remote_host, sid, db_err_out);
}
enum jaldb_status jaldb_store_confed_audit_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out)
{
	if (!ctx || !ctx->manager || !ctx->audit_sys_cont) {
		return JALDB_E_INVAL;
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

