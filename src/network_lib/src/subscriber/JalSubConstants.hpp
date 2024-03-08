/*
 * Copyright (C) 2023 The National Security Agency (NSA)
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
#ifndef __JAL__SUB__CONSTANTS__H__
#define __JAL__SUB__CONSTANTS__H__

#include <string>
#include <vector>
#include <microhttpd.h>

// Message Type Strings in the order given by the spec
const std::string MSG_INIT_STR = "initialize";
const std::string MSG_INIT_ACK_STR = "initialize-ack";
const std::string MSG_INIT_NACK_STR = "initialize-nack";
const std::string MSG_SESSION_FAILURE_STR = "session-failure";
const std::string MSG_LOG_STR = "log-record";
const std::string MSG_AUDIT_STR = "audit-record";
const std::string MSG_JOURNAL_STR = "journal-record";
const std::string MSG_RECORD_FAILURE_STR = "record-failure";
const std::string MSG_JOURNAL_MISSING_STR = "journal-missing";
const std::string MSG_JOURNAL_MISSING_RESP_STR = "journal-missing-response";
const std::string MSG_DIGEST_CHALLENGE_STR = "digest-challenge";
const std::string MSG_DIGEST_CHALLENGE_RESP_STR = "digest-response";
const std::string MSG_SYNC_FAILURE_STR = "sync-failure";
const std::string MSG_SYNC_STR = "sync";
const std::string MSG_CLOSE_SESSION_STR = "close-session";
const std::string MSG_CLOSE_SESSION_RESP_STR = "close-session-response";

// Record Type Strings
const std::string JAL_AUDIT_STR = "audit";
const std::string JAL_JOURNAL_STR = "journal";
const std::string JAL_LOG_STR = "log";
const std::string JAL_INVALID_RECORD_STR = "INVALID_TYPE";

// Digest status values
const std::string DIGEST_STATUS_INVALID_STR = "invalid";
const std::string DIGEST_STATUS_CONFIRMED_STR = "confirmed";
// Header Type Strings
const std::string HEADER_MESSAGE_TYPE = "JAL-Message";
const std::string HEADER_JAL_SESSION_ID_TYPE = "JAL-Session-Id";
const std::string HEADER_CONTENT_TYPE = "Content-Type";
const std::string HEADER_JAL_PUBLISHER_ID_TYPE = "JAL-Publisher-Id";
const std::string HEADER_JAL_VERSION_TYPE = "JAL-Version";
const std::string HEADER_JAL_RECORD_TYPE = "JAL-Record-Type";
const std::string HEADER_JAL_ERROR_MESSAGE_TYPE = "JAL-Error-Message";
const std::string HEADER_JAL_MODE_TYPE = "JAL-Mode";
const std::string HEADER_JAL_ID_TYPE = "JAL-Id";
const std::string HEADER_JAL_ACCEPT_DIGEST = "JAL-Accept-Digest";
const std::string HEADER_JAL_ACCEPT_CONFIGURE_DIGEST_CHALLENGE = "JAL-Accept-Configure-Digest-Challenge";
const std::string HEADER_JAL_CONFIGURE_DIGEST_CHALLENGE = "JAL-Configure-Digest-Challenge";
const std::string HEADER_JAL_SYSTEM_METADATA_LENGTH = "JAL-System-Metadata-Length";
const std::string HEADER_JAL_APPLICATION_METADATA_LENGTH = "JAL-Application-Metadata-Length";
const std::string HEADER_JAL_AUDIT_LENGTH = "JAL-Audit-Length";
const std::string HEADER_JAL_LOG_LENGTH = "JAL-Log-Length";
const std::string HEADER_JAL_JOURNAL_LENGTH = "JAL-Journal-Length";
const std::string HEADER_JAL_PRIORITY = "JAL-Priority";
const std::string HEADER_JAL_DIGEST = "JAL-Digest";
const std::string HEADER_JAL_DIGEST_VALUE = "JAL-Digest-Value";
const std::string HEADER_JAL_DIGEST_STATUS = "JAL-Digest-Status";
const std::string HEADER_JAL_JOURNAL_OFFSET = "JAL-Journal-Offset";

// Header Const Values
const std::string HEADER_CONTENT_TYPE_DEFAULT = "application/http+jalop";
const std::string HEADER_CONTENT_LENGTH = "Content-Length";

// INIT message Values
const std::vector<std::string> SUPPORTED_XML_COMPRESSIONS = {"none", "exi-1.0", "deflate"};
const std::vector<std::string> SUPPORTED_VERSIONS = {"2.0.0.0"};

const std::string DIGEST_ALGORITHM_SHA_256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const std::string DIGEST_ALGORITHM_SHA_384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const std::string DIGEST_ALGORITHM_SHA_512 = "http://www.w3.org/2001/04/xmlenc#sha512";
const std::vector<std::string> SUPPORTED_ACCEPT_DIGEST = {
	DIGEST_ALGORITHM_SHA_256,
	DIGEST_ALGORITHM_SHA_384,
	DIGEST_ALGORITHM_SHA_512};

const std::string DIGEST_CHALLENGE_ON = "on";
const std::string DIGEST_CHALLENGE_OFF = "off";
const std::vector<std::string> SUPPORTED_ACCEPT_CONFIGURE_DIGEST_CHALLENGE = {
	DIGEST_CHALLENGE_ON,
	DIGEST_CHALLENGE_OFF};

// INIT_NACK message values
const std::string JAL_UNSUPPORTED_PUBLISHER_ID = "JAL-Unsupported-Publisher-Id";
const std::string JAL_UNSUPPORTED_VERSION = "JAL-Unsupported-Version";
const std::string JAL_UNSUPPORTED_XML_COMPRESSION = "JAL-Unsupported-XML-Compression";
const std::string JAL_UNSUPPORTED_RECORD_TYPE = "JAL-Unsupported-Record-Type";
const std::string JAL_UNSUPPORTED_MODE = "JAL-Unsupported-Mode";
const std::string JAL_UNSUPPORTED_SESSION_ID = "JAL-Unsupported-Session-Id";
const std::string JAL_UNSUPPORTED_DIGEST = "JAL-Unsupported-Digest";
const std::string JAL_UNSUPPORTED_CONFIGURE_DIGEST_CHALLENGE = "JAL-Unsupported-Configure-Digest-Challenge";

// Record Failure message values
const std::string JAL_INVALID_JAL_ID = "JAL-Invalid-JAL-Id";
const std::string JAL_INVALID_SYSTEM_METADATA_LENGTH = "JAL-Invalid-System-Metadata-Length";
const std::string JAL_INVALID_APPLICATION_METADATA_LENGTH = "JAL-Invalid-Application-Metadata-Length";
const std::string JAL_INVALID_LOG_LENGTH = "JAL-Invalid-Log-Length";
const std::string JAL_INVALID_AUDIT_LENGTH = "JAL-Invalid-Audit-Length";
const std::string JAL_INVALID_JOURNAL_LENGTH = "JAL-Invalid-Joural-Length";
const std::string JAL_RECORD_FAILURE = "JAL-Record-Failure";
const std::string JAL_INVALID_DIGEST_STATUS = "JAL-Invalid-Digest-Status";
const std::string JAL_INVALID_DIGEST = "JAL-Invalid-Digest";
const std::string JAL_SYNC_FAILURE = "JAL-Sync-Failure";

// Translation of microhttpd constants
const int JAL_STATUS_OK = MHD_HTTP_OK;
const int JAL_STATUS_SERVER_ERROR = MHD_HTTP_INTERNAL_SERVER_ERROR;
const int JAL_STATUS_CONTINUE = MHD_HTTP_CONTINUE;

#endif
