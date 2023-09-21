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
#ifndef __JAL__SUB__ENUM__TYPES__H__
#define __JAL__SUB__ENUM__TYPES__H__

#include <string>

enum class ReceiveMessageType
{
	UNKNOWN_MESSAGE,
	MSG_INIT,
	MSG_LOG,
	MSG_AUDIT,
	MSG_JOURNAL,
	MSG_JOURNAL_MISSING,
	MSG_DIGEST_CHALLENGE_RESP,
	MSG_CLOSE_SESSION,
};

enum class SendMessageType
{
	MSG_INIT_ACK,
	MSG_INIT_NACK,
	MSG_SESSION_FAILURE,
	MSG_RECORD_FAILURE,
	MSG_JOURNAL_MISSING_RESP,
	MSG_DIGEST_CHALLENGE,
	MSG_SYNC_FAILURE,
	MSG_SYNC,
	MSG_CLOSE_SESSION_RESP,
};

ReceiveMessageType receiveMessageTypeFromString(std::string str);

std::string sendMessageTypeToString(SendMessageType type);

enum class ModeType
{
	LIVE,
	ARCHIVE
};

ModeType modeTypeFromHeader(std::string str);

ModeType modeTypeFromString(std::string str);

std::string modeTypeToString(ModeType mode);

enum class RecordType
{
	JAL_AUDIT,
	JAL_LOG,
	JAL_JOURNAL
};

std::string recordTypeToString(RecordType recordType);

RecordType recordTypeFromString(std::string);

enum class DigestStatus
{
	INVALID,
	CONFIRMED
};

std::string digestStatusToString(DigestStatus digestStatus);

DigestStatus digestStatusFromString(std::string);

enum class DBType
{
	BDB, // BerkeleyDB
	FS   // Filesystem
};

std::string dbTypeToString(DBType dbType);

DBType dbTypeFromString(std::string);

#endif
