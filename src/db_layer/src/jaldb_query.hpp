/**
 * @file jaldb_query.hpp This file provides some query utility functions.
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

#ifndef _JALDB_QUERY_HPP_
#define _JALDB_QUERY_HPP_

#include "jaldb_context.h"
#include "jaldb_status.h"


/**
 * Query a journal document by sid.
 * @param[in] ctx The jaldb_context to use.
 * @param[in] sid The serial ID of the record to query
 * @param[out] result a pointer to storea string containing the document's sid, uuid, and timestamp.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_NOT_FOUND if the record was not found.
 *  - JALDB_E_QUERY_EVAL if their the XQuery execution fails.
 */
enum jaldb_status jaldb_query_journal_sid(jaldb_context *ctx, const char *sid, char **result);

/**
 * Query an audit document by sid.
 * @param[in] ctx The jaldb_context to use.
 * @param[in] sid The serial ID of the record to query
 * @param[out] result a pointer to storea string containing the document's sid, uuid, and timestamp.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_NOT_FOUND if the record was not found.
 *  - JALDB_E_QUERY_EVAL if their the XQuery execution fails.
 */
enum jaldb_status jaldb_query_audit_sid(jaldb_context *ctx, const char *sid, char **result);

/**
 * Query a log document by sid.
 * @param[in] ctx The jaldb_context to use.
 * @param[in] sid The serial ID of the record to query
 * @param[out] result a pointer to storea string containing the document's sid, uuid, and timestamp.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_NOT_FOUND if the record was not found.
 *  - JALDB_E_QUERY_EVAL if their the XQuery execution fails.
 */
enum jaldb_status jaldb_query_log_sid(jaldb_context *ctx, const char *sid, char **result);


/**
 * Query a journal document by uuid.
 * @param[in] ctx The jaldb_context to use.
 * @param[in] uuid The uuid of the record to query
 * @param[out] result a pointer to storea string containing the document's sid, uuid, and timestamp.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_NOT_FOUND if the record was not found.
 *  - JALDB_E_QUERY_EVAL if their the XQuery execution fails.
 */
enum jaldb_status jaldb_query_journal_uuid(jaldb_context *ctx, const char *uuid, char **result);

/**
 * Query an audit document by uuid.
 * @param[in] ctx The jaldb_context to use.
 * @param[in] uuid The uuid of the record to query
 * @param[out] result a pointer to storea string containing the document's sid, uuid, and timestamp.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_NOT_FOUND if the record was not found.
 *  - JALDB_E_QUERY_EVAL if their the XQuery execution fails.
 */
enum jaldb_status jaldb_query_audit_uuid(jaldb_context *ctx, const char *uuid, char **result);

/**
 * Query a log document by uuid.
 * @param[in] ctx The jaldb_context to use.
 * @param[in] uuid The uuid of the record to query
 * @param[out] result a pointer to storea string containing the document's sid, uuid, and timestamp.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_NOT_FOUND if the record was not found.
 *  - JALDB_E_QUERY_EVAL if their the XQuery execution fails.
 */
enum jaldb_status jaldb_query_log_uuid(jaldb_context *ctx, const char *uuid, char **result);


/**
 * Execute an arbitrary XQuery on the journal container.
 * @param[in] ctx The jaldb_context to use.
 * @param[in] query A string containing the XQuery to execute.
 * @param[out] result A pointer to store a string containing the result.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_QUERY_EVAL if their the XQuery execution fails.
 */
enum jaldb_status jaldb_journal_xquery(jaldb_context *ctx, const char *query, char **result);

/**
 * Execute an arbitrary XQuery on the audit container.
 * @param[in] ctx The jaldb_context to use.
 * @param[in] query A string containing the XQuery to execute.
 * @param[out] result A pointer to store a string containing the result.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_QUERY_EVAL if their the XQuery execution fails.
 */
enum jaldb_status jaldb_audit_xquery(jaldb_context *ctx, const char *query, char **result);

/**
 * Execute an arbitrary XQuery on the log container.
 * @param[in] ctx The jaldb_context to use.
 * @param[in] query A string containing the XQuery to execute.
 * @param[out] result A pointer to store a a string containing the result.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_QUERY_EVAL if their the XQuery execution fails.
 */
enum jaldb_status jaldb_log_xquery(jaldb_context *ctx, const char *query, char **result);

/**
 * Execute an arbitrary XQuery on the database.
 * @param[in] ctx The jaldb_context to use.
 * @param[in] query A string containing the XQuery to execute.
 * @param[in] collection A string contining the uri of the collection to search. If left Null, defaults to the ctx default.
 * @param[out] result A pointer to store a string containing the result.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_QUERY_EVAL if their the XQuery execution fails.
 */
enum jaldb_status jaldb_xquery_helper(jaldb_context *ctx, const char *query, const char *collection, char **result);



#endif // _JALDB_QUERY_HPP_


