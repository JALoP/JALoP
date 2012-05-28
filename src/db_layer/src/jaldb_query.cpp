/**
 * @file jaldb_query.cpp This file provides some query utility functions.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <stdlib.h>
#include <dbxml/DbXml.hpp>

#include "jal_asprintf_internal.h"
#include "jaldb_query.hpp"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_context.hpp"

using namespace std;
using namespace DbXml;

enum jaldb_status jaldb_query_journal_sid(jaldb_context *ctx, const char *sid, char **result) {
	if (!ctx || !sid || !result) {
		return JALDB_E_INVAL;
	}
	if (*result) {
		//should be NULL
		return JALDB_E_INVAL;
	}

	enum jaldb_status ret;
	char *xquery;
	jal_asprintf(&xquery,
			JALDB_QUERY_FORMAT,
			JALDB_JOURNAL_SYS_META_CONT_NAME,
			JALDB_SID_WHERE_CLAUSE,
			sid);

	try {
		ret = jaldb_xquery_helper(ctx, xquery, NULL, result);
	} catch (XmlException &e) {
		free(xquery);
		throw e;
	}

	free(xquery);


	return ret;

}

enum jaldb_status jaldb_query_audit_sid(jaldb_context *ctx, const char *sid, char **result) {
	if (!ctx || !sid || !result) {
		return JALDB_E_INVAL;
	}
	if (*result) {
		//should be NULL
		return JALDB_E_INVAL;
	}

	enum jaldb_status ret;
	char *xquery;
	jal_asprintf(&xquery,
			JALDB_QUERY_FORMAT,
			JALDB_AUDIT_SYS_META_CONT_NAME,
			JALDB_SID_WHERE_CLAUSE,
			sid);

	try {
		ret = jaldb_xquery_helper(ctx, xquery, NULL, result);
	} catch (XmlException &e) {
		free(xquery);
		throw e;
	}

	free(xquery);

	return ret;

}

enum jaldb_status jaldb_query_log_sid(jaldb_context *ctx, const char *sid, char **result) {
	if (!ctx || !sid || !result) {
		return JALDB_E_INVAL;
	}
	if (*result) {
		//should be NULL
		return JALDB_E_INVAL;
	}

	enum jaldb_status ret;
	char *xquery;
	jal_asprintf(&xquery,
			JALDB_QUERY_FORMAT,
			JALDB_LOG_SYS_META_CONT_NAME,
			JALDB_SID_WHERE_CLAUSE,
			sid);

	try {
		ret = jaldb_xquery_helper(ctx, xquery, NULL, result);
	} catch (XmlException &e) {
		free(xquery);
		throw e;
	}

	free(xquery);

	return ret;

}


enum jaldb_status jaldb_query_journal_uuid(jaldb_context *ctx, const char *uuid, char **result) {

	if (!ctx || !uuid || !result) {
		return JALDB_E_INVAL;
	}
	if (*result) {
		//should be NULL
		return JALDB_E_INVAL;
	}

	enum jaldb_status ret;
	char *xquery;
	jal_asprintf(&xquery,
			JALDB_QUERY_FORMAT,
			JALDB_JOURNAL_SYS_META_CONT_NAME,
			JALDB_UUID_WHERE_CLAUSE,
			uuid);

	try {
		ret = jaldb_xquery_helper(ctx, xquery, NULL, result);
	} catch (XmlException &e) {
		free(xquery);
		throw e;
	}

	free(xquery);

	return ret;

}
enum jaldb_status jaldb_query_audit_uuid(jaldb_context *ctx, const char *uuid, char **result) {

	if (!ctx || !uuid || !result) {
		return JALDB_E_INVAL;
	}
	if (*result) {
		//should be NULL
		return JALDB_E_INVAL;
	}

	enum jaldb_status ret;
	char *xquery;
	jal_asprintf(&xquery,
			JALDB_QUERY_FORMAT,
			JALDB_AUDIT_SYS_META_CONT_NAME,
			JALDB_UUID_WHERE_CLAUSE,
			uuid);

	try {
		ret = jaldb_xquery_helper(ctx, xquery, NULL, result);
	} catch (XmlException &e) {
		free(xquery);
		throw e;
	}

	free(xquery);

	return ret;

}

enum jaldb_status jaldb_query_log_uuid(jaldb_context *ctx, const char *uuid, char **result) {

	if (!ctx || !uuid || !result) {
		return JALDB_E_INVAL;
	}
	if (*result) {
		//should be NULL
		return JALDB_E_INVAL;
	}

	enum jaldb_status ret;
	char *xquery;
	jal_asprintf(&xquery,
			JALDB_QUERY_FORMAT,
			JALDB_LOG_SYS_META_CONT_NAME,
			JALDB_UUID_WHERE_CLAUSE,
			uuid);

	try {
		ret = jaldb_xquery_helper(ctx, xquery, NULL, result);
	} catch (XmlException &e) {
		free(xquery);
		throw e;
	}

	free(xquery);

	return ret;

}



enum jaldb_status jaldb_xquery_helper(jaldb_context *ctx, const char *query, const char *collection, char **result) {

	if (!ctx || !query || !result) {
		return JALDB_E_INVAL;
	}
	if (*result) {
		//should be NULL
		return JALDB_E_INVAL;
	}

	while (1) {
		XmlTransaction txn = ctx->manager->createTransaction();
		try {
			XmlQueryContext qcontext = ctx->manager->createQueryContext();
			if (collection) {
				qcontext.setDefaultCollection(collection);
			}
			XmlQueryExpression expression = ctx->manager->prepare(txn, query, qcontext);
			XmlResults results = expression.execute(txn, qcontext);
			XmlValue val;
			while (results.hasNext()) {
				results.next(val);
				if (*result) {
					char *tmp = *result;
					jal_asprintf(result, "%s\n\n%s", tmp, val.asString().c_str());
					free(tmp);
				} else {
					jal_asprintf(result, "%s", val.asString().c_str());
				}
			}
			txn.commit();
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::QUERY_EVALUATION_ERROR) {
				jal_asprintf(result, "%s", e.what());
				return JALDB_E_QUERY_EVAL;
			}
			if (e.getExceptionCode() == XmlException::DOCUMENT_NOT_FOUND) {
				return JALDB_E_NOT_FOUND;
			}

			if (e.getExceptionCode() == XmlException::DATABASE_ERROR &&
					e.getDbErrno() == DB_LOCK_DEADLOCK) {
					if (*result) {
						free(*result);
						*result = NULL;
					}
				continue;
			}
			throw e;
		}

	}
	if (*result) {
		return JALDB_OK;
	} else {
		return JALDB_E_NOT_FOUND;
	}

}

enum jaldb_status jaldb_journal_xquery(jaldb_context *ctx, const char *query, char **result) {

	if (!ctx || !query || !result) {
		return JALDB_E_INVAL;
	}
	if (*result) {
		//should be NULL
		return JALDB_E_INVAL;
	}
	char *collection;
	jal_asprintf(&collection, "dbxml:%s", JALDB_JOURNAL_SYS_META_CONT_NAME);
	jaldb_status ret = jaldb_xquery_helper(ctx, query, collection, result);
	free(collection);

	return ret;
}

enum jaldb_status jaldb_audit_xquery(jaldb_context *ctx, const char *query, char **result) {

	if (!ctx || !query || !result) {
		return JALDB_E_INVAL;
	}
	if (*result) {
		//should be NULL
		return JALDB_E_INVAL;
	}

	char *collection;
	jal_asprintf(&collection, "dbxml:%s", JALDB_AUDIT_SYS_META_CONT_NAME);
	jaldb_status ret = jaldb_xquery_helper(ctx, query, collection, result);
	free(collection);

	return ret;
}

enum jaldb_status jaldb_log_xquery(jaldb_context *ctx, const char *query, char **result) {

	if (!ctx || !query || !result) {
		return JALDB_E_INVAL;
	}
	if (*result) {
		//should be NULL
		return JALDB_E_INVAL;
	}

	char *collection;
	jal_asprintf(&collection, "dbxml:%s", JALDB_LOG_SYS_META_CONT_NAME);
	jaldb_status ret = jaldb_xquery_helper(ctx, query, collection, result);
	free(collection);

	return ret;
}
