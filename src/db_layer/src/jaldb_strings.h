/**
 * @file jaldb_strings.h This file provides defines for a number of strings
 * used in various portions of the DB Layer.
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

#ifndef _JALDB_STRINGS_H_
#define _JALDB_STRINGS_H_

#define JALDB_AUDIT_SYS_META_CONT_NAME "audit_sys_meta.dbxml"
#define JALDB_AUDIT_APP_META_CONT_NAME "audit_app_meta.dbxml"
#define JALDB_AUDIT_CONT_NAME "audit.dbxml"
#define JALDB_LOG_SYS_META_CONT_NAME "log_sys_meta.dbxml"
#define JALDB_LOG_APP_META_CONT_NAME "log_app_meta.dbxml"
#define JALDB_LOG_DB_NAME "log.db"
#define JALDB_JOURNAL_SYS_META_CONT_NAME "journal_sys_meta.dbxml"
#define JALDB_JOURNAL_APP_META_CONT_NAME "journal_app_meta.dbxml"
#define JALDB_JOURNAL_ROOT_NAME "/journal/"
#define JALDB_CONF_DB "conf.db"
#define JALDB_JOURNAL_CONF_NAME "conf_journal"
#define JALDB_AUDIT_CONF_NAME "conf_audit"
#define JALDB_LOG_CONF_NAME "conf_log"

#define JALDB_NS "jalop:localstore/metadata"
#define JALDB_SERIAL_ID_NAME "serialId"
#define JALDB_SERIAL_ID_DOC_NAME "__next_sid"
#define JALDB_JOURNAL_PATH "journalPath"
#define JALDB_SOURCE "source"
#define JALDB_LOCALHOST "localhost"
#define JALDB_HAS_APP_META "hasAppMeta"
#define JALDB_HAS_LOG "hasLog"

#endif // _JALDB_STRINGS_H_
