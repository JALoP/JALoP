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
#ifndef __JAL__SUB__DUMMY__TEST__DB__H__
#define __JAL__SUB__DUMMY__TEST__DB__H__

#include "JalSubDatabase.h"
#include "JalSubRecordInfo.h"

class DummyDB : public JalSubDatabase
{
	public:
	static std::shared_ptr<JalSubDatabase> dummyDBFactory(SubscriberConfig config)
	{
		printf("dummy db factory\n");
		return std::make_shared<DummyDB>(config);
	}

	DummyDB(SubscriberConfig config)
	{
		(void)config;
	}

	bool insertAudit(const RecordInfo& recordInfo) override
	{
		(void)recordInfo;
		printf("dummydb Insert audit called\n");
		return true;
	}

	bool insertLog(const RecordInfo& recordInfo) override
	{
		(void)recordInfo;
		printf("dummydb Insert log called\n");
		return true;
	}

	bool insertJournal(const RecordInfo& recordInfo) override
	{
		(void)recordInfo;
		printf("dummydb Insert journal called\n");
		return true;
	}
};

#endif
