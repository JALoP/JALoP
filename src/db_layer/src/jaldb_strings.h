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

#ifndef _JALDB_STRINGS_H_
#define _JALDB_STRINGS_H_

#include <jalop/jal_namespaces.h>

#define JALDB_LOG_DB_NAME "log.db"
#define JALDB_JOURNAL_ROOT_NAME "/journal/"
#define JALDB_CONF_DB "conf.db"
#define JALDB_JOURNAL_CONF_NAME "conf_journal"
#define JALDB_AUDIT_CONF_NAME "conf_audit"
#define JALDB_LOG_CONF_NAME "conf_log"

#define JALDB_INITIAL_SID "0"
#define JALDB_DEFAULT_OFFSET "0"
#define JALDB_NS "jalop:localstore/metadata"
#define JALDB_SERIAL_ID_NAME "serialId"
#define JALDB_LAST_CONFED_SID_NAME "last_confed_serialId"
#define JALDB_SERIAL_ID_DOC_NAME "__next_sid"
#define JALDB_CONNECTION_METADATA_DOC_NAME "__connection_metadata"
#define JALDB_OFFSET_NAME "offsetName"
#define JALDB_JOURNAL_PATH "journalPath"
#define JALDB_SOURCE "source"
#define JALDB_LOCALHOST "localhost"
#define JALDB_HAS_APP_META "hasAppMeta"
#define JALDB_HAS_LOG "hasLog"

#define JALDB_QUERY_SID_CMP_FUNCTION \
"declare function local:sid-cmp($a as xs:string, $b as xs:string) as xs:integer {\n" \
"    if (fn:string-length($a) lt fn:string-length($b)) then -1\n" \
"    else if (fn:string-length($b) lt fn:string-length($a)) then 1\n" \
"    else (fn:compare ($a, $b))\n" \
"}; \n"

#define JALDB_NEXT_SID_QUERY_CONT_VAR "cont"
#define JALDB_NEXT_SID_QUERY \

#define JALDB_REMOTE_META_PREFIX "_.."
#define JALDB_QUERY_NS "jal:"
#define JALDB_SYNC_META_SUFFIX "..sync"
#define JALDB_SENT_META_SUFFIX "..sent"

#define JALDB_GLOBAL_SYNCED_KEY "global_synced"
#define JALDB_GLOBAL_SENT_KEY "global_sent"

#define JALDB_SYNC_POINT_VAR "sync_point"
#define JALDB_SYNC_META_VAR "sync_meta_name"
#define JALDB_SENT_META_VAR "sent_meta_name"

#define JALDB_SID_VAR "sid"
#define JALDB_UUID_VAR "uuid"

#define JALDB_QUERY_VAR_LAST_SID "last_sid"

#endif // _JALDB_STRINGS_H_
