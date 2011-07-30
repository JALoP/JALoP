/**
 * @file jaldb_context.hpp This file provides the DB context structure and
 * constants for use by the DB Layer.
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

#ifndef _JALDB_CONTEXT_HPP_
#define _JALDB_CONTEXT_HPP_

#include <dbxml/DbXml.hpp>

#define AUDIT_SYS_META_CONT_NAME "audit_sys_meta.dbxml"
#define AUDIT_APP_META_CONT_NAME "audit_app_meta.dbxml"
#define AUDIT_CONT_NAME "audit.dbxml"
#define LOG_SYS_META_CONT_NAME "log_sys_meta.dbxml"
#define LOG_APP_META_CONT_NAME "log_app_meta.dbxml"
#define LOG_DB_NAME "log.db"
#define JOURNAL_SYS_META_CONT_NAME "journal_sys_meta.dbxml"
#define JOURNAL_APP_META_CONT_NAME "journal_app_meta.dbxml"
#define JOURNAL_ROOT_NAME "journal/"

using namespace DbXml;

struct jaldb_context_t {
	XmlManager *manager; //<! The manager associated with the context.
	char *audit_sys_meta_container; //<! The audit system metadata container path.
	char *audit_app_meta_container; //<! The audit application metadata container path.
	char *audit_container; //<! The audit record container path.
	char *log_sys_meta_container; //<! The log system metadata container path.
	char *log_app_meta_container; //<! The log application metadata container path.
	char *log_db; //<! The log database path.
	char *journal_sys_meta_container; //<! The journal system metadata container path.
	char *journal_app_meta_container; //<! The journal application metadata container path.
	char *journal_root; //<! The journal record root path.
};

typedef struct jaldb_context_t jaldb_context;

#endif // _JALDB_CONTEXT_HPP_
