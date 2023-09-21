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
#include <string>
#include <stdexcept>

#include "JalSubConstants.hpp"
#include "JalSubEnumTypes.hpp"

enum ReceiveMessageType receiveMessageTypeFromString(std::string str)
{
	// Ordered most-to-least common for a slight performance gain
	if(0 == str.compare(MSG_AUDIT_STR))
	{
		return ReceiveMessageType::MSG_AUDIT;
	}
	else if(0 == str.compare(MSG_LOG_STR))
	{
		return ReceiveMessageType::MSG_LOG;
	}
	else if(0 == str.compare(MSG_JOURNAL_STR))
	{
		return ReceiveMessageType::MSG_JOURNAL;
	}
	else if(0 == str.compare(MSG_JOURNAL_MISSING_STR))
	{
		return ReceiveMessageType::MSG_JOURNAL_MISSING;
	}
	else if(0 == str.compare(MSG_DIGEST_CHALLENGE_RESP_STR))
	{
		return ReceiveMessageType::MSG_DIGEST_CHALLENGE_RESP;
	}
	else if(0 == str.compare(MSG_INIT_STR))
	{
		return ReceiveMessageType::MSG_INIT;
	}
	else if(0 == str.compare(MSG_CLOSE_SESSION_STR))
	{
		return ReceiveMessageType::MSG_CLOSE_SESSION;
	}
	else
	{
		throw std::runtime_error("Unknown message type: " + str);
	}
}

std::string sendMessageTypeToString(enum SendMessageType type)
{
	switch(type)
	{
		case SendMessageType::MSG_INIT_ACK:
			return MSG_INIT_ACK_STR;
			break;
		case SendMessageType::MSG_INIT_NACK:
			return MSG_INIT_NACK_STR;
			break;
		case SendMessageType::MSG_SESSION_FAILURE:
			return MSG_SESSION_FAILURE_STR;
			break;
		case SendMessageType::MSG_RECORD_FAILURE:
			return MSG_RECORD_FAILURE_STR;
			break;
		case SendMessageType::MSG_JOURNAL_MISSING_RESP:
			return MSG_JOURNAL_MISSING_RESP_STR;
			break;
		case SendMessageType::MSG_DIGEST_CHALLENGE:
			return MSG_DIGEST_CHALLENGE_STR;
			break;
		case SendMessageType::MSG_SYNC_FAILURE:
			return MSG_SYNC_FAILURE_STR;
			break;
		case SendMessageType::MSG_SYNC:
			return MSG_SYNC_STR;
			break;
		case SendMessageType::MSG_CLOSE_SESSION_RESP:
			return MSG_CLOSE_SESSION_RESP_STR;
			break;
		default:
			return "";
	}
}

ModeType modeTypeFromHeader(std::string str)
{
	if(str.compare("live") == 0)
	{
		return ModeType::LIVE;
	}
	// Only "Archival" is valid when reading from a JAL Header
	else if(str.compare("archival") == 0)
	{
		return ModeType::ARCHIVE;
	}
	else
	{
		throw std::runtime_error("Invalid conversion to ModeType from header: " + str);
	}
}

ModeType modeTypeFromString(std::string str)
{
	if(str.compare("live") == 0)
	{
		return ModeType::LIVE;
	}
	else if(str.compare("archival") == 0 || str.compare("archive") == 0)
	{
		return ModeType::ARCHIVE;
	}
	else
	{
		throw std::runtime_error("Invalid conversion to ModeType from string: " + str);
	}
}

std::string modeTypeToString(ModeType mode)
{
	if(ModeType::LIVE == mode)
	{
		return "live";
	}
	else
	{
		return "archive";
	}
}

std::string recordTypeToString(RecordType recordType)
{
	if(RecordType::JAL_AUDIT == recordType)
	{
		return JAL_AUDIT_STR;
	}
	else if(RecordType::JAL_LOG == recordType)
	{
		return JAL_LOG_STR;
	}
	else
	{
		return JAL_JOURNAL_STR;
	}
}

RecordType recordTypeFromString(std::string str)
{
	if(0 == str.compare(JAL_AUDIT_STR))
	{
		return RecordType::JAL_AUDIT;
	}
	else if(0 == str.compare(JAL_LOG_STR))
	{
		return RecordType::JAL_LOG;
	}
	else if(0 == str.compare(JAL_JOURNAL_STR))
	{
		return RecordType::JAL_JOURNAL;
	}
	else
	{
		throw std::runtime_error("Invalid conversion to RecordType from string: " + str);
	}
}

std::string digestStatusToString(DigestStatus digestStatus)
{
	if(DigestStatus::CONFIRMED == digestStatus)
	{
		return DIGEST_STATUS_CONFIRMED_STR;
	}
	else
	{
		return DIGEST_STATUS_INVALID_STR;
	}
}

DigestStatus digestStatusFromString(std::string str)
{
	if(0 == str.compare(DIGEST_STATUS_CONFIRMED_STR))
	{
		return DigestStatus::CONFIRMED;
	}
	else if(0 == str.compare(DIGEST_STATUS_INVALID_STR))
	{
		return DigestStatus::INVALID;
	}
	else
	{
		throw std::runtime_error("Invalid conversion to DigestStatus from string: " + str);
	}
}

std::string dbTypeToString(DBType dbType)
{
	if(DBType::BDB == dbType)
	{
		return "bdb";
	}
	else
	{
		return "fs";
	}
}

DBType dbTypeFromString(std::string typeStr)
{
	if(0 == typeStr.compare("bdb"))
	{
		return DBType::BDB;
	}
	else if(0 == typeStr.compare("fs"))
	{
		return DBType::FS;
	}
	else
	{
		throw std::runtime_error("Invalid conversion to DBType from string: " + typeStr);
	}
}
