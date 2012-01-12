/**
 * @file jaldb_purge.cpp This file implements the DB purge functions.
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

#include <list>
#include <string.h>
#include <dbxml/DbXml.hpp>
#include <dbxml/XmlContainer.hpp>
#include "jal_alloc.h"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"
#include "jaldb_context.hpp"
#include "jaldb_purge.hpp"
#include "jaldb_xml_doc_storage.hpp"

XERCES_CPP_NAMESPACE_USE
using namespace std;
using namespace DbXml;

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

enum jaldb_status jaldb_get_docs_to_purge(jaldb_context *ctx,
				XmlTransaction &txn,
				XmlUpdateContext &uc,
				XmlQueryContext &qctx,
				const string query,
				list<jaldb_doc_info> &docs)
{
	if (!ctx || !txn || !uc || !qctx || (0 == query.length())) {
		return JALDB_E_INVAL;
	}

	enum jaldb_status dbret = JALDB_OK;

	while (true) {
		XmlTransaction docs_txn = txn.createChild(DB_READ_COMMITTED);
		try {
			XmlQueryExpression qe = ctx->manager->prepare(docs_txn, query, qctx);
			XmlResults res = qe.execute(docs_txn, qctx, DB_RMW |
								DBXML_DOCUMENT_PROJECTION |
								DBXML_NO_AUTO_COMMIT |
								DB_READ_COMMITTED |
								DBXML_LAZY_DOCS);

			XmlQueryContext dqctx = ctx->manager->createQueryContext();

			XmlDocument sys_doc;
			while (res.next(sys_doc)) {
				struct jaldb_doc_info doc_info;
				memset(&doc_info, 0, sizeof(struct jaldb_doc_info));

				doc_info.sid = jal_strdup(sys_doc.getName().c_str());

				while (true) {
					XmlTransaction qtxn = docs_txn.createChild(DB_READ_COMMITTED);
					try {
						XmlQueryExpression dqe = ctx->manager->prepare(JALDB_GET_UUID_QUERY, dqctx);
						XmlResults uuid_res = dqe.execute(qtxn, sys_doc, dqctx);

						XmlValue uuid_val;
						if (uuid_res.next(uuid_val)) {
							string uuid = uuid_val.asString();
							doc_info.uuid = jal_strdup(uuid.c_str());
						}

						qtxn.commit();
						break;
					} catch (XmlException &e) {
						qtxn.abort();
						if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
								e.getDbErrno() == DB_LOCK_DEADLOCK) {
							continue;
						}
						dbret = JALDB_E_INVAL;
						goto out;
					}
				}

				docs.push_back(doc_info);
			}

			docs_txn.commit();
			break;
		} catch (XmlException &e) {
			docs_txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
				docs.clear();
				continue;
			}
			dbret = JALDB_E_INVAL;
			goto out;
		}
	}

out:
	return dbret;
}

enum jaldb_status jaldb_purge_log(jaldb_context *ctx,
				XmlTransaction &txn,
				XmlUpdateContext &uc,
				XmlQueryContext &qctx,
				const string query,
				list<jaldb_doc_info> &docs,
				int del)
{
	if (!ctx || !txn || !uc || !qctx || (0 == query.length())) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status dbret = JALDB_OK;

	dbret = jaldb_get_docs_to_purge(ctx, txn, uc, qctx, query, docs);
	if (JALDB_OK != dbret) {
		goto out;
	}

	if (del) {
		for (list<jaldb_doc_info>::iterator doc = docs.begin(); doc != docs.end(); doc++) {
			while (true) {
				XmlTransaction del_txn = txn.createChild(DB_READ_COMMITTED);
				try {
					dbret = jaldb_remove_document(txn, uc,
								*(ctx->log_sys_cont),
								string(doc->sid));
					if (JALDB_OK != dbret && JALDB_E_NOT_FOUND != dbret) {
						goto out;
					}

					dbret = jaldb_remove_document(txn, uc,
								*(ctx->log_app_cont),
								string(doc->sid));
					if (JALDB_OK != dbret && JALDB_E_NOT_FOUND != dbret) {
						goto out;
					}

					del_txn.commit();
					dbret = JALDB_OK;
					break;
				} catch (XmlException &e) {
					del_txn.abort();
					if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
							e.getDbErrno() == DB_LOCK_DEADLOCK) {
						continue;
					}
					dbret = JALDB_E_INVAL;
					goto out;
				}
			}

			DBT key;
			memset(&key, 0, sizeof(DBT));
			key.data = jal_strdup(doc->sid);
			key.size = strlen(doc->sid);
			int dbrc = ctx->log_dbp->del(ctx->log_dbp, txn.getDB_TXN(), &key, 0);
			free(key.data);
			if (0 != dbrc && DB_NOTFOUND != dbrc) {
				goto out;
			}
		}
	}

out:
	return dbret;
}

enum jaldb_status jaldb_purge_audit(jaldb_context *ctx,
				XmlTransaction &txn,
				XmlUpdateContext &uc,
				XmlQueryContext &qctx,
				const string query,
				list<jaldb_doc_info> &docs,
				int del)
{
	if (!ctx || !txn || !uc || !qctx || (0 == query.length())) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status dbret = JALDB_OK;

	dbret = jaldb_get_docs_to_purge(ctx, txn, uc, qctx, query, docs);
	if (JALDB_OK != dbret) {
		goto out;
	}

	if (del) {
		for (list<jaldb_doc_info>::iterator doc = docs.begin(); doc != docs.end(); doc++) {
			while (true) {
				XmlTransaction del_txn = txn.createChild(DB_READ_COMMITTED);
				try {

					dbret = jaldb_remove_document(del_txn, uc,
								*(ctx->audit_sys_cont),
								string(doc->sid));
					if (JALDB_OK != dbret && JALDB_E_NOT_FOUND != dbret) {
						goto out;
					}

					dbret = jaldb_remove_document(del_txn, uc,
								*(ctx->audit_app_cont),
								string(doc->sid));
					if (JALDB_OK != dbret && JALDB_E_NOT_FOUND != dbret) {
						goto out;
					}

					dbret = jaldb_remove_document(del_txn, uc,
								*(ctx->audit_cont),
								string(doc->sid));
					if (JALDB_OK != dbret && JALDB_E_NOT_FOUND != dbret) {
						goto out;
					}

					del_txn.commit();
					break;
				} catch (XmlException &e) {
					del_txn.abort();
					if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
							e.getDbErrno() == DB_LOCK_DEADLOCK) {
						continue;
					}
					dbret = JALDB_E_INVAL;
					goto out;
				}
			}
		}
	}

out:
	return dbret;
}

enum jaldb_status jaldb_purge_journal(jaldb_context *ctx,
				XmlTransaction &txn,
				XmlUpdateContext &uc,
				XmlQueryContext &qctx,
				const string query,
				list<jaldb_doc_info> &docs,
				int del)
{
	if (!ctx || !txn || !uc || !qctx || (0 == query.length())) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status dbret = JALDB_OK;

	dbret = jaldb_get_docs_to_purge(ctx, txn, uc, qctx, query, docs);
	if (JALDB_OK != dbret) {
		goto out;
	}

	if (del) {
		for (list<jaldb_doc_info>::iterator doc = docs.begin(); doc != docs.end(); doc++) {
			XmlValue val;
			while (true) {
				XmlTransaction doc_txn = txn.createChild(DB_READ_COMMITTED);
				try {
					XmlDocument sys_doc = ctx->journal_sys_cont->getDocument(doc_txn,
												doc->sid,
												DB_READ_COMMITTED);
					sys_doc.getMetaData(JALDB_NS, JALDB_JOURNAL_PATH, val);

					doc_txn.commit();
					break;
				} catch (XmlException &e) {
					doc_txn.abort();
					if (e.getExceptionCode() ==
						XmlException::DATABASE_ERROR &&
						e.getDbErrno() == DB_LOCK_DEADLOCK) {
						continue;
					} else if (e.getExceptionCode() !=
						XmlException::DOCUMENT_NOT_FOUND) {
						break;
					}
				}
			}

			while (true) {
				XmlTransaction del_txn = txn.createChild(DB_READ_COMMITTED);
				try {
					dbret = jaldb_remove_document(del_txn, uc,
								*(ctx->journal_sys_cont),
								string(doc->sid));
					if (JALDB_OK != dbret && JALDB_E_NOT_FOUND != dbret) {
						goto out;
					}

					dbret = jaldb_remove_document(del_txn, uc,
								*(ctx->journal_app_cont),
								string(doc->sid));
					if (JALDB_OK != dbret && JALDB_E_NOT_FOUND != dbret) {
						goto out;
					}

					del_txn.commit();
					dbret = JALDB_OK;
					break;
				} catch (XmlException &e) {
					del_txn.abort();
					if (e.getExceptionCode() ==
						XmlException::DATABASE_ERROR &&
						e.getDbErrno() == DB_LOCK_DEADLOCK) {
						continue;
					}
				}
			}

			string journal_file(ctx->journal_root);
			string full_path = ctx->journal_root;
			full_path.append("/").append(val.asString());
			unlink(full_path.c_str());
		}
	}

out:
	return dbret;
}

enum jaldb_status jaldb_purge_log_by_sid(jaldb_context *ctx,
					const char *sid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	if (!ctx || !sid) {
		return JALDB_E_INVAL;
	}

	enum jaldb_status dbret = JALDB_OK;

	XmlQueryContext qctx = ctx->manager->createQueryContext();
	qctx.setDefaultCollection(ctx->log_sys_cont->getName());
	qctx.setVariableValue(JALDB_SID_VAR, sid);

	XmlTransaction txn = ctx->manager->createTransaction();
	XmlUpdateContext uc = ctx->manager->createUpdateContext();

	string query;
	if (force) {
		query = JALDB_FIND_ALL_BY_SID_QUERY;
	} else {
		query = JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY;
	}

	dbret = jaldb_purge_log(ctx, txn, uc, qctx, query, docs, del);
	if (JALDB_OK != dbret) {
		goto err_out;
	}

	txn.commit();
	return dbret;
err_out:
	txn.abort();
	return dbret;
}

enum jaldb_status jaldb_purge_log_by_uuid(jaldb_context *ctx,
					const char *uuid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	if (!ctx || !uuid) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status dbret = JALDB_OK;

	XmlQueryContext qctx = ctx->manager->createQueryContext();
	qctx.setDefaultCollection(ctx->log_sys_cont->getName());
	qctx.setVariableValue(JALDB_UUID_VAR, uuid);

	XmlTransaction txn = ctx->manager->createTransaction();
	XmlUpdateContext uc = ctx->manager->createUpdateContext();

	string query;
	if (force) {
		query = JALDB_FIND_ALL_BY_UUID_QUERY;
	} else {
		query = JALDB_FIND_SYNCED_AND_SENT_BY_UUID_QUERY;
	}

	dbret = jaldb_purge_log(ctx, txn, uc, qctx, query, docs, del);
	if (JALDB_OK != dbret) {
		goto err_out;
	}

	txn.commit();
	return dbret;
err_out:
	txn.abort();
	return dbret;
}

enum jaldb_status jaldb_purge_audit_by_sid(jaldb_context *ctx,
					const char *sid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	if (!ctx || !sid) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status dbret = JALDB_OK;

	XmlQueryContext qctx = ctx->manager->createQueryContext();
	qctx.setDefaultCollection(ctx->audit_sys_cont->getName());
	qctx.setVariableValue(JALDB_SID_VAR, sid);

	XmlTransaction txn = ctx->manager->createTransaction();
	XmlUpdateContext uc = ctx->manager->createUpdateContext();

	string query;
	if (force) {
		query = JALDB_FIND_ALL_BY_SID_QUERY;
	} else {
		query = JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY;
	}

	dbret = jaldb_purge_audit(ctx, txn, uc, qctx, query, docs, del);
	if (JALDB_OK != dbret) {
		goto err_out;
	}

	txn.commit();
	return dbret;
err_out:
	txn.abort();
	return dbret;
}

enum jaldb_status jaldb_purge_audit_by_uuid(jaldb_context *ctx,
					const char *uuid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	if (!ctx || !uuid) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status dbret = JALDB_OK;

	XmlQueryContext qctx = ctx->manager->createQueryContext();
	qctx.setDefaultCollection(ctx->audit_sys_cont->getName());
	qctx.setVariableValue(JALDB_UUID_VAR, uuid);

	XmlTransaction txn = ctx->manager->createTransaction();
	XmlUpdateContext uc = ctx->manager->createUpdateContext();

	string query;
	if (force) {
		query = JALDB_FIND_ALL_BY_UUID_QUERY;
	} else {
		query = JALDB_FIND_SYNCED_AND_SENT_BY_UUID_QUERY;
	}

	dbret = jaldb_purge_audit(ctx, txn, uc, qctx, query, docs, del);
	if (JALDB_OK != dbret) {
		goto err_out;
	}

	txn.commit();
	return dbret;
err_out:
	txn.abort();
	return dbret;
}

enum jaldb_status jaldb_purge_journal_by_sid(jaldb_context *ctx,
					const char *sid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	if (!ctx || !sid) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status dbret = JALDB_OK;

	XmlQueryContext qctx = ctx->manager->createQueryContext();
	qctx.setDefaultCollection(ctx->journal_sys_cont->getName());
	qctx.setVariableValue(JALDB_SID_VAR, sid);

	XmlTransaction txn = ctx->manager->createTransaction();
	XmlUpdateContext uc = ctx->manager->createUpdateContext();

	string query;
	if (force) {
		query = JALDB_FIND_ALL_BY_SID_QUERY;
	} else {
		query = JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY;
	}

	dbret = jaldb_purge_journal(ctx, txn, uc, qctx, query, docs, del);
	if (JALDB_OK != dbret) {
		goto err_out;
	}

	txn.commit();
	return dbret;
err_out:
	txn.abort();
	return dbret;
}

enum jaldb_status jaldb_purge_journal_by_uuid(jaldb_context *ctx,
					const char *uuid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	if (!ctx || !uuid) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status dbret = JALDB_OK;

	XmlQueryContext qctx = ctx->manager->createQueryContext();
	qctx.setDefaultCollection(ctx->journal_sys_cont->getName());
	qctx.setVariableValue(JALDB_UUID_VAR, uuid);

	XmlTransaction txn = ctx->manager->createTransaction();
	XmlUpdateContext uc = ctx->manager->createUpdateContext();

	string query;
	if (force) {
		query = JALDB_FIND_ALL_BY_UUID_QUERY;
	} else {
		query = JALDB_FIND_SYNCED_AND_SENT_BY_UUID_QUERY;
	}

	dbret = jaldb_purge_journal(ctx, txn, uc, qctx, query, docs, del);
	if (JALDB_OK != dbret) {
		goto err_out;
	}

	txn.commit();
	return dbret;
err_out:
	txn.abort();
	return dbret;
}
