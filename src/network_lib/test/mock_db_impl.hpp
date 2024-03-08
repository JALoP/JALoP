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

#pragma once

#include <vector>
#include <stdexcept>
//#include <stdlib.h>

#include "JalSubDatabase.hpp"
#include "JalSubConfig.hpp"
#include "JalSubRecordInfo.hpp"
#include "JalSubUtils.hpp"
#include "JalSubEnumTypes.hpp"

struct StoredRecord
{
	RecordType type;
	std::vector<uint8_t> appMetadata;
	std::vector<uint8_t> sysMetadata;
	std::vector<uint8_t> payload;
};

class MockDb : public JalSubDatabase
{
	private:
	SubscriberConfig config;
	// Map of records by JalID
	std::map<std::string, StoredRecord> recordStore;
	static std::shared_ptr<MockDb> db;

	public:

	MockDb(SubscriberConfig paramConfig) : config(paramConfig)
	{
	}

	static std::shared_ptr<MockDb> getDbHandle()
	{
		return db;
	}

	bool checkForRecord(std::string jalId)
	{
		try
		{
			recordStore.at(jalId);
		}
		catch(...)
		{
			return false;
		}
		return true;
	}

	StoredRecord getStoredRecord(std::string jalId)
	{
		return recordStore[jalId];
	}

	static std::shared_ptr<JalSubDatabase> MockDbFactory(SubscriberConfig config)
	{
		if(nullptr == db)
		{
			db = std::make_shared<MockDb>(config);
		}
		return db;
	}

	bool insertAuditImpl(const RecordInfo& recordInfo) override
	{
		return insertImpl(RecordType::JAL_AUDIT, recordInfo);
	}

	bool insertLogImpl(const RecordInfo& recordInfo) override
	{
		return insertImpl(RecordType::JAL_LOG, recordInfo);
	}

	bool insertJournalImpl(const RecordInfo& recordInfo) override
	{
		return insertImpl(RecordType::JAL_JOURNAL, recordInfo);
	}

	bool insertImpl(RecordType type, const RecordInfo& recordInfo)
	{
		if(!recordInfo.payloadFileName.empty())
		{
			std::string errMsg = "MockDB does not currently support payloads offloaded to disk."
				"Ensure payload size is less than bufferSize in SubscriberConfig.";
			throw std::runtime_error(errMsg);
		}
		StoredRecord record;
		record.type = type;
		record.appMetadata = recordInfo.appMetadata;
		record.sysMetadata = recordInfo.sysMetadata;
		record.payload = recordInfo.payload;
		recordStore.insert(std::pair<std::string, StoredRecord>(recordInfo.jalId, record));
		return true;
	}
};
