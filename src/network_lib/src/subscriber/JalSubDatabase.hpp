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
#ifndef __JAL__SUB__DATABASE__H__
#define __JAL__SUB__DATABASE__H__

#include <mutex>
#include <shared_mutex>

struct RecordInfo;

// This header defines the interface any database implementation must follow
// to be used by the subscriber
class JalSubDatabase
{
	private:
	std::shared_mutex dbMutex;
	virtual bool insertAuditImpl(const RecordInfo& recordInfo) = 0;
	virtual bool insertLogImpl(const RecordInfo& recordInfo) = 0;
	virtual bool insertJournalImpl(const RecordInfo& recordInfo) = 0;

	public:
	virtual ~JalSubDatabase(){};
	bool insertAudit(const RecordInfo& recordInfo)
	{
		std::unique_lock lock(dbMutex);
		return insertAuditImpl(recordInfo);
	}
	bool insertLog(const RecordInfo& recordInfo)
	{
		std::unique_lock lock(dbMutex);
		return insertLogImpl(recordInfo);
	}
	bool insertJournal(const RecordInfo& recordInfo)
	{
		std::unique_lock lock(dbMutex);
		return insertJournalImpl(recordInfo);
	}
};

#endif
