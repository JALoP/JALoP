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

#include <jalop/jal_namespaces.h>

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
JALDB_QUERY_SID_CMP_FUNCTION \
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

#define JALDB_GLOBAL_SYNCED_KEY "global_synced"
#define JALDB_GLOBAL_SENT_KEY "global_sent"

#define JALDB_SYNC_POINT_VAR "sync_point"
#define JALDB_SYNC_META_VAR "sync_meta_name"
#define JALDB_SENT_META_VAR "sent_meta_name"

#define JALDB_SID_VAR "sid"
#define JALDB_UUID_VAR "uuid"

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
JALDB_QUERY_SID_CMP_FUNCTION \
"for $d in collection()\n" \
"where local:sid-cmp($" JALDB_SYNC_POINT_VAR ", $d/dbxml:metadata('dbxml:name')) ge 0 and \n"\
"    $d/dbxml:metadata($" JALDB_SENT_META_VAR ") and \n" \
"    fn:not($d/dbxml:metadata($" JALDB_SYNC_META_VAR "))\n" \
"return $d\n"

#define JALDB_QUERY_VAR_NUM_REC "num_rec"
#define JALDB_FETCH_LAST_K_RECORDS_QUERY \
"let $docs := for $i in collection()\n" \
"		where $i/dbxml:metadata('dbxml:name') != '" JALDB_SERIAL_ID_DOC_NAME "'" \
"		return $i\n" \
"let $num_docs := count($docs)\n" \
"	return subsequence($docs,$num_docs - $" JALDB_QUERY_VAR_NUM_REC " + 1)"

#define JALDB_QUERY_VAR_LAST_SID "last_sid"
#define JALDB_FOLLOW_QUERY \
JALDB_QUERY_SID_CMP_FUNCTION \
"for $i in collection()\n" \
"	where $i/dbxml:metadata('dbxml:name') != '" JALDB_SERIAL_ID_DOC_NAME "'" \
"		and local:sid-cmp($" JALDB_QUERY_VAR_LAST_SID ", $i/dbxml:metadata('dbxml:name')) < 0 \n" \
"	return $i\n"

#define JALDB_FIND_SYNCED_AND_SENT_QUERY \
"declare namespace jal='" JALDB_NS "';\n" \
"for $d in collection()\n" \
"where $d/dbxml:metadata('jal:" JALDB_GLOBAL_SYNCED_KEY "') and $d/dbxml:metadata('jal:" JALDB_GLOBAL_SENT_KEY "')\n" \
"return $d\n"

#define JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY \
"declare namespace jal='" JALDB_NS "';\n" \
"for $d in collection()\n" \
"where fn:compare($d/dbxml:metadata('dbxml:name'), $" JALDB_SID_VAR ") lt 1 and \n" \
"    $d/dbxml:metadata('jal:" JALDB_GLOBAL_SYNCED_KEY "') and $d/dbxml:metadata('jal:" JALDB_GLOBAL_SENT_KEY "')\n" \
"return $d\n"

#define JALDB_FIND_ALL_BY_SID_QUERY \
"for $d in collection()\n" \
"where fn:compare($d/dbxml:metadata('dbxml:name'), $" JALDB_SID_VAR ") lt 1 and \n" \
"    fn:not(fn:compare($d/dbxml:metadata('dbxml:name'), '" JALDB_SERIAL_ID_DOC_NAME "') eq 0) \n" \
"return $d\n"

#define JALDB_FIND_SYNCED_AND_SENT_BY_UUID_QUERY \
"declare namespace jsm='" JAL_SYS_META_NAMESPACE_URI "';\n" \
"declare namespace lsm='" JALDB_NS "';\n" \
"let $uuid_docs := for $d in collection()\n" \
"where $d/jsm:JALRecord[jsm:RecordID=$" JALDB_UUID_VAR "] and \n" \
"    $d/dbxml:metadata('lsm:" JALDB_GLOBAL_SYNCED_KEY "') and $d/dbxml:metadata('lsm:" JALDB_GLOBAL_SENT_KEY "')\n" \
"return $d\n" \
"for $d in $uuid_docs\n" \
"    for $d2 in collection()\n" \
"    where fn:compare($d/dbxml:metadata('dbxml:name'), $d2/dbxml:metadata('dbxml:name')) lt 1 and \n" \
"    $d2/dbxml:metadata('lsm:" JALDB_GLOBAL_SYNCED_KEY "') and $d2/dbxml:metadata('lsm:" JALDB_GLOBAL_SENT_KEY "')\n" \
"    return $d2\n"

#define JALDB_FIND_ALL_BY_UUID_QUERY \
"declare namespace jal='" JAL_SYS_META_NAMESPACE_URI "';\n" \
"for $d in collection()\n" \
"where $d/jal:JALRecord[jal:RecordID=$" JALDB_UUID_VAR "]\n" \
"return $d\n" \

#define JALDB_GET_UUID_QUERY \
"declare namespace jal='" JAL_SYS_META_NAMESPACE_URI "';\n" \
"/jal:JALRecord/jal:RecordID/text()\n"

#define JALDB_SID_QUERY_FORMAT \
"declare namespace jal='" JAL_SYS_META_NAMESPACE_URI "';\n"\
"let $d := doc(\"dbxml:/%s/%s\")\n"\
"let $recordId := $d/jal:JALRecord/jal:RecordID/text()\n"\
"let $timestamp := $d/jal:JALRecord/jal:Timestamp/text()\n"\
"let $sid := $d/dbxml:metadata(\"dbxml:name\")\n"\
"let $n := <n>Serial ID: {$sid}\n"\
"RecordID : {$recordId}\n"\
"Timestamp: {$timestamp}\n"\
"</n>\n"\
"return $n/text()\n"

#define JALDB_UUID_QUERY_FORMAT \
"declare namespace jal='" JAL_SYS_META_NAMESPACE_URI "';\n"\
"for $d in collection(\"dbxml:/%s\")\n"\
"where $d/jal:JALRecord/jal:RecordID/text() = \"%s\"\n"\
"return concat(\"RecordID: \", $d/jal:JALRecord/jal:RecordID, \"\n\","\
" \"Serial ID: \", $d/dbxml:metadata(\"dbxml:name\"), \"\n\", "\
" \"Timestamp: \", $d/jal:JALRecord/jal:Timestamp)\n"

#endif // _JALDB_STRINGS_H_
