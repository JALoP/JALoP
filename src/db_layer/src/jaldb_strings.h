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
#define JALDB_NEXT_SID_QUERY_CONT_VAR "cont"
#define JALDB_NEXT_SID_QUERY \
"declare function local:sid-cmp($a as xs:string, $b as xs:string) as xs:integer {\n" \
"    if (fn:string-length($a) lt fn:string-length($b)) then -1\n" \
"    else if (fn:string-length($b) lt fn:string-length($a)) then 1\n" \
"    else (fn:compare ($a, $b))\n" \
"}; \n" \
"let $docs := for $i in collection()\n" \
"    where local:sid-cmp($last_sid, $i/dbxml:metadata('dbxml:name')) lt 0 \n" \
"    return $i\n" \
"let $no_hidden_docs := for $d in $docs \n" \
"    where local:sid-cmp('__next_sid', $d/dbxml:metadata('dbxml:name')) ne 0 \n" \
"    return $d\n" \
"return subsequence($no_hidden_docs, 1, 1)\n" \

#define JALDB_REMOTE_META_PREFIX "_.."
#define JALDB_QUERY_NS "jal:"
#define JALDB_SYNC_META_SUFFIX "..sync"
#define JALDB_SENT_META_SUFFIX "..sent"

#define JALDB_SYNC_POINT_VAR "sync_point"
#define JALDB_SYNC_META_VAR "sync_meta_name"
#define JALDB_SENT_META_VAR "sent_meta_name"

// This query is for a 'sync' message. the idea is to find all records that
// where successfully sent to a given remote (i.e. the local side received a
// digest message and the digests matched), but have not yet received a 'sync'
// message for.
// There are ?? variables that must be set:
// sent_meta : This is the string used to mark a record as sent to a particular
//             remote.
// sync_meta : This is the string used to mark a record as 'synced' by a
//             particular remote (i.e. we received a 'sync' message for the
//             remote for this record.
// sync_point : This is the serial ID from a 'sync' message. All records up to
//              and including the one with serial ID 'sync_point' are marked
//              as synced.
#define JALDB_FIND_UNCONFED_BY_HOST_QUERY \
"declare namespace jal='" JALDB_NS "';\n" \
"declare function local:sid-cmp($a as xs:string, $b as xs:string) as xs:integer {\n" \
"    if (fn:string-length($a) lt fn:string-length($b)) then -1\n" \
"    else if (fn:string-length($b) lt fn:string-length($a)) then 1\n" \
"    else (fn:compare ($a, $b))\n" \
"}; \n" \
"for $d in collection()\n" \
"where local:sid-cmp($" JALDB_SYNC_POINT_VAR ", $d/dbxml:metadata('dbxml:name')) ge 0 and \n"\
"    $d/dbxml:metadata($" JALDB_SENT_META_VAR ") and \n" \
"    fn:not($d/dbxml:metadata($" JALDB_SYNC_META_VAR "))\n" \
"return $d\n"

#endif // _JALDB_STRINGS_H_
