/**
 * @file
 *
 * @brief This file contains strings and other defines used by
 * the network stores.
 *
 * ### LICENSE
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

#ifndef _JALNS_STRINGS_H_
#define _JALNS_STRINGS_H_
#ifdef __cplusplus
extern "C" {
#endif

#define JALNS_AUDIT "audit"
#define JALNS_DB_ROOT "db_root"
#define JALNS_DC_CONFIG "digest_challenge"
#define JALNS_SCHEMAS_ROOT "schemas_root"
#define JALNS_HOST "host"
#define JALNS_HOSTS "hosts"
#define JALNS_JOURNAL "journal"
#define JALNS_LOG "log"
#define JALNS_MODE "mode"
#define JALNS_MODE_ARCHIVE "archive"
#define JALNS_MODE_ARCHIVE_ALTERNATIVE "archival"
#define JALNS_MODE_LIVE "live"
#define JALNS_PEERS "peers"
#define JALNS_POLL_TIME "poll_time"
#define JALNS_PORT "port"
#define JALNS_PRIVATE_KEY "private_key"
#define JALNS_PUBLIC_CERT "public_cert"
#define JALNS_PUBLISHER_ID "publisher_id"
#define JALNS_RECORD_TYPES "record_types"
#define JALNS_RETRY_INTERVAL "retry_interval"
#define JALNS_CERT_DIR "cert_dir"
#define JALNS_NETWORK_TIMEOUT "network_timeout"
#define JALNS_PID_FILE "pid_file"
#define JALNS_LOG_DIR "log_dir"
#define JALNS_DIGEST_ALGORITHMS "digest_algorithms"
#define JALNS_HTTP_CLIENT_RETRY_COUNT "http_client_retry_count"
#define JALNS_HTTP_CLIENT_RETRY_DELAY "http_client_retry_delay"
#define JALNS_ALLOW_SELF_SIGNED_CERTS "allow_self_signed_certs"
#define JALNS_USE_FILTER "use_filter"
#define JALNS_FILTER_SOCKET_BASENAME "filter_socket_basename"
#define JALNS_FILTER_SOCKET "filter_socket"
#define JALNS_MARK_UNSENT "mark_unsent"
#define JALNS_ARCHIVE_MODE "archive_mode"

#ifdef __cplusplus
}
#endif
enum jaldb_mark {
	MARK_UNSYNCED_RECORDS_UNSENT = 1,
	MARK_SENT = 2,
	MARK_SYNCED = 3,
	MARK_UNSENT = 4,
	MARK_ERROR = -1,
	MARK_SUCCESS = 0
};
//sample nonce
//74c27f93-7722-4cd9-89b0-764eb631e6a8_2025-05-16T14:17:56.171210_1312388_3393181440
struct mark_request{
	enum jaldb_mark mark;
	enum jaldb_rec_type record_type;
	char nonce[128];
	enum jaldb_mark response;
};

#endif // _JALNS_STRINGS_H_
