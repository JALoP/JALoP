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
#ifndef __JAL__SUB__RECORD__INFO__H__
#define __JAL__SUB__RECORD__INFO__H__

enum class AuditFormat
{
	JSON,
	XML
};

// TODO: Currently a Session can have only one record in progress at a time
// It may be useful to have a map of jalId to Record mappings if it is necessary
// to allow parallel record flows over the same session
// I don't believe the publisher currently supports this sort of parallelism
struct RecordInfo
{
	// The intent for the RecordInfo class is for it to be one-to-one with a received
	// record and payload, and handed off from the Message class to the Session class
	// once the corresponding record Message has been processed
	//
	// Therefore, we're going to:
	// 1 - use the default no-param constructor
	RecordInfo() = default;
	// 2 - disable the copy-constructor
	RecordInfo(const RecordInfo& other) = delete;
	// 3 - disable the assignment operator
	RecordInfo& operator=(const RecordInfo& other) = delete;
	// 4 - define the move constructor operator
	RecordInfo(RecordInfo&& other)
	{
		*this = std::move(other);
	}
	// 5 - define the move assignment operator
	RecordInfo& operator=(RecordInfo&& other)
	{
		// Guard self-assignment
		if(this == &other)
		{
			return *this;
		}

		// The only time this move constructor should be called is when
		// we're updating the Session's instance with information from
		// a newly captured Message's instance
		//
		// If the Session's instance already points to a payload file, an error
		// must have occurred or the db interface failed to remove the old temporary
		// In either case, attempt to remove the old temporary file
		if(!payloadFileName.empty())
		{
			printf("RecordInfo removing file: %s\n", payloadFileName.c_str());
			remove(payloadFileName.c_str());
			payloadFileName.clear();
		}
		sysMetadata = std::move(other.sysMetadata);
		sysMetadataLen = other.sysMetadataLen;
		other.sysMetadataLen = 0;

		appMetadata = std::move(other.appMetadata);
		appMetadataLen = other.appMetadataLen;
		other.appMetadataLen = 0;

		payload = std::move(other.payload);
		payloadLen = other.payloadLen;
		other.payloadLen = 0;
		payloadFileName = std::move(other.payloadFileName);

		jalId = std::move(other.jalId);
		digest = std::move(other.digest);
		auditFormat = other.auditFormat;

		return *this;
	}

	// Collector for received system metadata
	std::vector<uint8_t> sysMetadata;
	// expected length of system metadata from headers
	size_t sysMetadataLen = 0;

	// Collector for received application metadata
	std::vector<uint8_t> appMetadata;
	// expected length of application metadata from headers
	size_t appMetadataLen = 0;

	// Collector for received payload data
	// Only used if total length is less than bufferSize
	std::vector<uint8_t> payload;
	// If the payload data exceeds bufferSize, the name of the file the payload
	// will be written to
	std::string payloadFileName;
	// expected length of payload from headers
	size_t payloadLen = 0;

	AuditFormat auditFormat = AuditFormat::XML;
	std::string jalId;
	std::string digest;
};

#endif
