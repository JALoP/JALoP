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

#include <list>
#include <string.h>
#include "jal_alloc.h"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"
#include "jaldb_context.hpp"
#include "jaldb_purge.hpp"

using namespace std;

enum jaldb_status jaldb_purge_unconfirmed_log(
		jaldb_context *ctx,
		const char *remote_host,
		int *db_err)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_unconfirmed_audit(
		jaldb_context *ctx,
		const char *remote_host)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_unconfirmed_journal(
		jaldb_context *ctx,
		const char *remote_host)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_log_by_sid(jaldb_context *ctx,
					const char *sid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_log_by_uuid(jaldb_context *ctx,
					const char *uuid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_audit_by_sid(jaldb_context *ctx,
					const char *sid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_audit_by_uuid(jaldb_context *ctx,
					const char *uuid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_journal_by_sid(jaldb_context *ctx,
					const char *sid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_journal_by_uuid(jaldb_context *ctx,
					const char *uuid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}
