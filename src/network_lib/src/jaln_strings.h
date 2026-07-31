/**
 * @file
 *
 * @brief This file contains various strings used by the network
 * library.
 *
 * ### LICENSE
 *
 * Copyright (C) 2018-2026 Concurrent Technologies Corporation.
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
#ifndef _JALN_STRINGS_H_
#define _JALN_STRINGS_H_
#include <jalop/jaln_network.h>

#define JALN_CRLF "\x0d\x0A"
#define JALN_VERSION "2.0.0.0"

// defines for the various MIME headers
#define JALN_HDRS_ACCEPT_CONFIGURE_DIGEST_CHALLENGE "jal-accept-configure-digest-challenge"
#define JALN_HDRS_ACCEPT_DIGEST "jal-accept-digest"
#define JALN_HDRS_ACCEPT_COMPRESSION "jal-accept-xml-compression"
#define JALN_HDRS_APP_META_LEN "jal-application-metadata-length"
#define JALN_HDRS_AUDIT_FORMAT "jal-audit-format"
#define JALN_HDRS_AUDIT_LEN "jal-audit-length"
#define JALN_HDRS_AGENT "jal-agent"
#define JALN_HDRS_CONTENT_TXFR_ENCODING "content-transfer-encoding"
#define JALN_HDRS_CONTENT_TYPE "content-type"
#define JALN_HDRS_CONTENT_LENGTH "content-length"
#define JALN_HDRS_COUNT "jal-count"
#define JALN_HDRS_RECORD_TYPE "jal-record-type"
#define JALN_HDRS_DIGEST "jal-digest"
#define JALN_HDRS_DIGEST_STATUS "jal-digest-status"
#define JALN_HDRS_DIGEST_VALUE "jal-digest-value"
#define JALN_HDRS_ERROR_MESSAGE "jal-error-message"
#define JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE "jal-configure-digest-challenge"
#define JALN_HDRS_JOURNAL_LEN "jal-journal-length"
#define JALN_HDRS_JOURNAL_OFFSET "jal-journal-offset"
#define JALN_HDRS_LOG_LEN "jal-log-length"
#define JALN_HDRS_MESSAGE "jal-message"
#define JALN_HDRS_MODE "jal-mode"
#define JALN_HDRS_PUBLISHER_ID "jal-publisher-id"
#define JALN_HDRS_ID "jal-id"
#define JALN_HDRS_SESSION_ID "jal-session-id"
#define JALN_HDRS_SYS_META_LEN "jal-system-metadata-length"
#define JALN_HDRS_UNAUTHORIZED_MODE "jal-unauthorized-mode"
#define JALN_HDRS_UNSUPPORTED_MODE "jal-unsupported-mode"
#define JALN_HDRS_UNSUPPORTED_VERSION "jal-unsupported-version"
#define JALN_HDRS_UNSUPPORTED_COMPRESSION "jal-unsupported-xml-compression"
#define JALN_HDRS_UNSUPPORTED_DIGEST "jal-unsupported-digest"
#define JALN_HDRS_VERSION "jal-version"
#define JALN_HDRS_COMPRESSION "jal-xml-compression"

#define JALN_COLON_SPACE ": "

#define JALN_MIME_PREAMBLE \
	JALN_HDRS_CONTENT_TYPE JALN_COLON_SPACE JALN_STR_CT_JALOP JALN_CRLF \
	JALN_HDRS_MESSAGE JALN_COLON_SPACE

// defines for the various message JALoP message types
#define JALN_MSG_AUDIT "audit-record"
#define JALN_MSG_CLOSE_SESSION "close-session"
#define JALN_MSG_CLOSE_SESSION_RESPONSE "close-session-response"
#define JALN_MSG_DIGEST "digest"
#define JALN_MSG_DIGEST_CHALLENGE "digest-challenge"
#define JALN_MSG_DIGEST_RESP "digest-response"
#define JALN_MSG_INIT "initialize"
#define JALN_MSG_INIT_ACK "initialize-ack"
#define JALN_MSG_INIT_NACK "initialize-nack"
#define JALN_MSG_JOURNAL "journal-record"
#define JALN_MSG_JOURNAL_RESUME "journal-resume"
#define JALN_MSG_JOURNAL_MISSING "journal-missing"
#define JALN_MSG_JOURNAL_MISSING_RESPONSE "journal-missing-response"
#define JALN_MSG_LOG "log-record"
#define JALN_MSG_PUBLISH "publish"
#define JALN_MSG_SUBSCRIBE "subscribe"
#define JALN_MSG_PUBLISH_LIVE "live"
#define JALN_MSG_PUBLISH_ARCHIVE "archival"
#define JALN_MSG_RECORD_FAILURE "record-failure"
#define JALN_MSG_SESSION_FAILURE "session-failure"
#define JALN_MSG_SUBSCRIBE_LIVE "subscribe-live"
#define JALN_MSG_SUBSCRIBE_ARCHIVE "subscribe-archival"
#define JALN_MSG_SYNC "sync"
#define JALN_MSG_SYNC_FAILURE "sync-failure"

// strings for error messages
#define JALN_ERROR_MSG_INVALID_DIGEST "JAL-Invalid-Digest"
#define JALN_ERROR_MSG_INVALID_DIGEST_STATUS "JAL-Invalid-Digest-Status"

#define JALN_DIGEST_CHALLENGE_OFF "off"
#define JALN_DIGEST_CHALLENGE_ON "on"

#define JALN_DGST_SHA256 "sha256"

#define JALN_DGST_CHAN_FORMAT_STR "digest:%d"

#define JALN_ENC_XML "none"
#define JALN_XML "xml"

#define JALN_STR_AUDIT "audit"
#define JALN_STR_BINARY "binary"
#define JALN_STR_BREAK "BREAK"
#define JALN_STR_CONFIRMED "confirmed"
#define JALN_STR_CONFIRMED_EQUALS JALN_STR_CONFIRMED "="
#define JALN_STR_CT_JALOP "application/http+jalop"
#define JALN_STR_JOURNAL "journal"
#define JALN_STR_INVALID "invalid"
#define JALN_STR_INVALID_EQUALS JALN_STR_INVALID "="
#define JALN_STR_LOG "log"
#define JALN_STR_UNKNOWN "unknown"
#define JALN_STR_UNKNOWN_EQUALS JALN_STR_UNKNOWN "="


#define JALN_JALOP_1_0_PROFILE "http://www.dod.mil/logging/jalop-1.0"

#endif // _JALN_STRINGS_H_

