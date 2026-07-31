/**
 * @file
 *
 * @brief This file contains functions to test
 * the JaldbTranslator types in isolation, without going through the
 * jaldb_context functions
 *
 * ### LICENSE
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
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

// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// C++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif

extern "C" {
#include <test-dept.h>
}

#include "test_utils.h"
#define __STDC_FORMAT_MACROS
#include "jaldb_utils.h"
#include "lmdb-safe.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stdlib.h>
#include "jaldb_strings.h"
#include "jaldb_segment.h"
#include "jal_alloc.h"

#include "jaldb_record.h"
#include "jaldb_translators.h"
#include "jaldb_context.hpp"

#include <iostream>

#define OTHER_DB_ROOT "./testdb/"

constexpr int ITEMS_IN_DB = 4;
struct jaldb_record *records[ITEMS_IN_DB];
LmdbDbType* db = NULL;

static void safe_strcmp(const char* s1, const char* s2)
{
	if(NULL == s1) { assert_equals(NULL, s2); }
	else if(NULL == s2) { assert_equals(NULL, s1); }
	else { assert_equals(0, strcmp(s1, s2)); }
}

static void segment_cmp(const struct jaldb_segment* s1, const struct jaldb_segment* s2)
{
	if(NULL == s1) { assert_equals(NULL, s2); return; }
	else if(NULL == s2) { assert_equals(NULL, s1); return; /*unreachable return*/ }

	assert_equals(s1->length, s2->length);
	for(size_t i = 0; i < s1->length; i++)
	{
		assert_equals(s1->payload[i], s2->payload[i]);
	}
	assert_equals(s1->fd, s2->fd);
	assert_equals(s1->on_disk, s2->on_disk);
}

static void compare_record_contents(const struct jaldb_record* r1, const struct jaldb_record* r2)
{
	assert_not_equals(NULL, r1);
	assert_not_equals(NULL, r2);
	safe_strcmp(r1->network_nonce, r2->network_nonce);

	assert_equals(r1->pid, r2->pid);
	assert_equals(r1->uid, r2->uid);

	segment_cmp(r1->sys_meta, r2->sys_meta);
	segment_cmp(r1->app_meta, r2->app_meta);
	segment_cmp(r1->payload, r2->payload);

	safe_strcmp(r1->source, r2->source);
	safe_strcmp(r1->hostname, r2->hostname);
	safe_strcmp(r1->timestamp, r2->timestamp);
	safe_strcmp(r1->username, r2->username);
	safe_strcmp(r1->sec_lbl, r2->sec_lbl);
	assert_equals(r1->version, r2->version);
	assert_equals(r1->type, r2->type);

	//Special case for JALDB_NOT_CONFIRMED getting changed to JALDB_NOT_SENT when
	//generating c struct
	if (r1->synced == JALDB_NOT_CONFIRMED)
	{
		assert_equals(JALDB_NOT_SENT, r2->synced);
	}
	else
	{
		assert_equals(r1->synced, r2->synced);
	}
	assert_equals(r1->confirmed, r2->confirmed);
	assert_equals(r1->have_uid, r2->have_uid);
	assert_equals(0, uuid_compare(r1->host_uuid, r2->host_uuid));
	assert_equals(0, uuid_compare(r1->uuid, r2->uuid));
}

static void create_records(struct jaldb_record** recs)
{
	uint8_t segment_data[10] = {0,1,2,3,4,5,6,7,8,9};
	// Record 0
	recs[0] = jaldb_create_record();

	assert_equals(0, uuid_parse("AAAAAAAA-89AB-CDEF-0123-456789ABCDEF", recs[0]->uuid));
	char *primary_key = jaldb_gen_primary_key(recs[0]->uuid);
	assert_not_equals(NULL, primary_key);
	recs[0]->network_nonce = primary_key;
	recs[0]->pid = 1;
	recs[0]->uid = 1;

	recs[0]->sys_meta = jaldb_create_segment();
	recs[0]->sys_meta->length = 5;
	recs[0]->sys_meta->payload = (uint8_t*)jal_calloc(recs[0]->sys_meta->length,sizeof(uint8_t));
	memcpy(recs[0]->sys_meta->payload, segment_data, recs[0]->sys_meta->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[0]->sys_meta->fd = -1;
	recs[0]->sys_meta->on_disk = 0;

	recs[0]->app_meta = jaldb_create_segment();
	recs[0]->app_meta->length = 4;
	recs[0]->app_meta->payload = (uint8_t*)jal_calloc(recs[0]->app_meta->length,sizeof(uint8_t));
	memcpy(recs[0]->app_meta->payload, segment_data, recs[0]->app_meta->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[0]->app_meta->fd = -1;
	recs[0]->app_meta->on_disk = 0;

	recs[0]->payload = jaldb_create_segment();
	recs[0]->payload->length = 3;
	recs[0]->payload->payload = (uint8_t*)jal_calloc(recs[0]->payload->length,sizeof(uint8_t));
	memcpy(recs[0]->payload->payload, segment_data, recs[0]->payload->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[0]->payload->fd = -1;
	recs[0]->payload->on_disk = 0;

	recs[0]->source = strdup("source1");
	recs[0]->hostname = strdup("hostname1");
	recs[0]->timestamp = strdup("timestamp1");
	recs[0]->username = strdup("username1");
	recs[0]->sec_lbl = strdup("sec_lbl1");
	recs[0]->version = 1;
	recs[0]->type = JALDB_RTYPE_LOG;
	recs[0]->synced = JALDB_NOT_SENT;//JALDB_SENT, JALDB_SYNCED
	recs[0]->confirmed = 1;
	recs[0]->have_uid = 1;
	assert_equals(0, uuid_parse("BBBBBBBB-89AB-CDEF-0123-456789ABCDEF", recs[0]->host_uuid));

	// Record 1
	recs[1] = jaldb_create_record();

	assert_equals(0, uuid_parse("CCCCCCCC-89AB-CDEF-0123-456789ABCDEF", recs[1]->uuid));
	primary_key = jaldb_gen_primary_key(recs[1]->uuid);
	assert_not_equals(NULL, primary_key);
	recs[1]->network_nonce = primary_key;
	recs[1]->pid = 2;
	recs[1]->uid = 2;

	recs[1]->sys_meta = jaldb_create_segment();
	recs[1]->sys_meta->length = 5;
	recs[1]->sys_meta->payload = (uint8_t*)jal_calloc(recs[1]->sys_meta->length,sizeof(uint8_t));
	memcpy(recs[1]->sys_meta->payload, segment_data, recs[1]->sys_meta->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[1]->sys_meta->fd = -1;
	recs[1]->sys_meta->on_disk = 0;

	recs[1]->app_meta = jaldb_create_segment();
	recs[1]->app_meta->length = 4;
	recs[1]->app_meta->payload = (uint8_t*)jal_calloc(recs[1]->app_meta->length,sizeof(uint8_t));
	memcpy(recs[1]->app_meta->payload, segment_data, recs[1]->app_meta->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[1]->app_meta->fd = -1;
	recs[1]->app_meta->on_disk = 0;

	recs[1]->payload = jaldb_create_segment();
	recs[1]->payload->length = 3;
	recs[1]->payload->payload = (uint8_t*)jal_calloc(recs[1]->payload->length,sizeof(uint8_t));
	memcpy(recs[1]->payload->payload, segment_data, recs[1]->payload->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[1]->payload->fd = -1;
	recs[1]->payload->on_disk = 0;

	recs[1]->source = strdup("source2");
	recs[1]->hostname = strdup("hostname2");
	recs[1]->timestamp = strdup("2timestamp");
	recs[1]->username = strdup("username2");
	recs[1]->sec_lbl = strdup("sec_lbl2");
	recs[1]->version = 1;
	recs[1]->type = JALDB_RTYPE_AUDIT;
	recs[1]->synced = JALDB_SYNCED;//JALDB_NOT_SENT, JALDB_SENT, JALDB_SYNCED
	recs[1]->confirmed = 1;
	recs[1]->have_uid = 1;
	assert_equals(0, uuid_parse("DDDDDDDD-89AB-CDEF-0123-456789ABCDEF", recs[1]->host_uuid));

	// Record 2
	recs[2] = jaldb_create_record();

	assert_equals(0, uuid_parse("EEEEEEEE-89AB-CDEF-0123-456789ABCDEF", recs[2]->uuid));
	primary_key = jaldb_gen_primary_key(recs[2]->uuid);
	assert_not_equals(NULL, primary_key);
	recs[2]->network_nonce = primary_key;
	recs[2]->pid = 2;
	recs[2]->uid = 2;

	recs[2]->sys_meta = jaldb_create_segment();
	recs[2]->sys_meta->length = 5;
	recs[2]->sys_meta->payload = (uint8_t*)jal_calloc(recs[2]->sys_meta->length,sizeof(uint8_t));
	memcpy(recs[2]->sys_meta->payload, segment_data, recs[2]->sys_meta->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[2]->sys_meta->fd = -1;
	recs[2]->sys_meta->on_disk = 0;

	recs[2]->app_meta = jaldb_create_segment();
	recs[2]->app_meta->length = 4;
	recs[2]->app_meta->payload = (uint8_t*)jal_calloc(recs[2]->app_meta->length,sizeof(uint8_t));
	memcpy(recs[2]->app_meta->payload, segment_data, recs[2]->app_meta->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[2]->app_meta->fd = -1;
	recs[2]->app_meta->on_disk = 0;

	recs[2]->payload = jaldb_create_segment();
	recs[2]->payload->length = 3;
	recs[2]->payload->payload = (uint8_t*)jal_calloc(recs[2]->payload->length,sizeof(uint8_t));
	memcpy(recs[2]->payload->payload, segment_data, recs[2]->payload->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[2]->payload->fd = -1;
	recs[2]->payload->on_disk = 0;

	recs[2]->source = strdup("source2");
	recs[2]->hostname = strdup("hostname2");
	recs[2]->timestamp = strdup("timestamp3");
	recs[2]->username = strdup("username2");
	recs[2]->sec_lbl = strdup("sec_lbl2");
	recs[2]->version = 1;
	recs[2]->type = JALDB_RTYPE_AUDIT;
	recs[2]->synced = JALDB_SENT;//JALDB_NOT_SENT, JALDB_SENT, JALDB_SYNCED
	recs[2]->confirmed = 1;
	recs[2]->have_uid = 1;
	assert_equals(0, uuid_parse("FFFFFFFF-89AB-CDEF-0123-456789ABCDEF", recs[2]->host_uuid));

	// Record 3
	recs[3] = jaldb_create_record();

	assert_equals(0, uuid_parse("BAAAAAAA-89AB-CDEF-0123-456789ABCDEF", recs[3]->uuid));
	primary_key = jaldb_gen_primary_key(recs[3]->uuid);
	assert_not_equals(NULL, primary_key);
	recs[3]->network_nonce = primary_key;
	recs[3]->pid = 1;
	recs[3]->uid = 1;

	recs[3]->sys_meta = jaldb_create_segment();
	recs[3]->sys_meta->length = 5;
	recs[3]->sys_meta->payload = (uint8_t*)jal_calloc(recs[3]->sys_meta->length,sizeof(uint8_t));
	memcpy(recs[3]->sys_meta->payload, segment_data, recs[3]->sys_meta->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[3]->sys_meta->fd = -1;
	recs[3]->sys_meta->on_disk = 0;

	recs[3]->app_meta = jaldb_create_segment();
	recs[3]->app_meta->length = 4;
	recs[3]->app_meta->payload = (uint8_t*)jal_calloc(recs[3]->app_meta->length,sizeof(uint8_t));
	memcpy(recs[3]->app_meta->payload, segment_data, recs[3]->app_meta->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[3]->app_meta->fd = -1;
	recs[3]->app_meta->on_disk = 0;

	recs[3]->payload = jaldb_create_segment();
	recs[3]->payload->length = 3;
	recs[3]->payload->payload = (uint8_t*)jal_calloc(recs[3]->payload->length,sizeof(uint8_t));
	memcpy(recs[3]->payload->payload, segment_data, recs[3]->payload->length); // nosemgrep - the copy length is less than or equal to the destination buffer size
	recs[3]->payload->fd = -1;
	recs[3]->payload->on_disk = 0;

	recs[3]->source = strdup("source3");
	recs[3]->hostname = strdup("hostname3");
	recs[3]->timestamp = strdup("timestamp3");
	recs[3]->username = strdup("username3");
	recs[3]->sec_lbl = strdup("sec_lbl3");
	recs[3]->version = 1;
	recs[3]->type = JALDB_RTYPE_LOG;
	recs[3]->synced = JALDB_NOT_CONFIRMED;
	recs[3]->confirmed = 0;
	recs[3]->have_uid = 1;
	assert_equals(0, uuid_parse("CBBBBBBB-89AB-CDEF-0123-456789ABCDEF", recs[3]->host_uuid));

	// IF ADDING A NEW RECORD, OR REMOVIG A RECORD, REMEMBER TO UPDATE ITEMS_IN_DB
}

extern "C" void setup()
{
	dir_cleanup(OTHER_DB_ROOT);
	mkdir(OTHER_DB_ROOT, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	create_records(records);

	// Create multi-index DB
	db = new LmdbDbType(getMDBEnv((std::string(OTHER_DB_ROOT) + "test_jaldb_translators_db").c_str(), MDB_NOSUBDIR, 0600, 5), "records");
}

extern "C" void teardown()
{
	delete db;
	dir_cleanup(OTHER_DB_ROOT);

	for(int i = 0; i < ITEMS_IN_DB; i++) {
		jaldb_destroy_record(&records[i]);
	}
}

extern "C" void  test_insert_and_get_by_main_id()
{
	struct jaldb_record *outRecords[ITEMS_IN_DB];
	// Insert record 0
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		auto rwtxn = db->getRWTransaction();
		auto id = rwtxn.put(JaldbRecordTranslator::fromCStruct(*records[i]));
		assert_not_equals(id, 0);
		assert_equals(i+1, id);
		rwtxn.commit();

		// Get the record back out by "main" id
		auto rotxn = db->getROTransaction();
		JaldbRecordTranslator outRec;
		bool ret = rotxn.get(id, outRec);
		assert_not_equals(false, ret);

		// Get the C struct out of the record and place it in our array
		outRecords[i] = outRec.generateCStruct();
	}
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		compare_record_contents(records[i], outRecords[i]);
	}
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		jaldb_destroy_record(&outRecords[i]);
	}
}

extern "C" void  test_insert_and_get_by_network_nonce()
{
	struct jaldb_record *outRecords[ITEMS_IN_DB];
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		auto rwtxn = db->getRWTransaction();
		auto id = rwtxn.put(JaldbRecordTranslator::fromCStruct(*records[i]));
		assert_not_equals(id, 0);
		assert_equals(i+1, id);
		rwtxn.commit();

		// Get the record back out by "main" id
		auto rotxn = db->getROTransaction();
		JaldbRecordTranslator outRec;

		// We know there will only be one, so we can cheat and use the simple .get()
		id = rotxn.get<LmdbDbIndex::IDX_NETWORK_NONCE>(records[i]->network_nonce, outRec);
		assert_not_equals(id, 0);
		assert_equals(i+1, id);

		// Get the C struct out of the record and place it in our array
		outRecords[i] = outRec.generateCStruct();
	}
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		compare_record_contents(records[i], outRecords[i]);
	}
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		jaldb_destroy_record(&outRecords[i]);
	}
}

extern "C" void  test_insert_and_get_by_nonce_timestamp()
{
	struct jaldb_record *outRecords[ITEMS_IN_DB];
	// Insert record 0
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		auto rwtxn = db->getRWTransaction();
		auto cppRec = JaldbRecordTranslator::fromCStruct(*records[i]);
		std::string nonceTimestamp = cppRec.nonceTimestamp;
		auto id = rwtxn.put(cppRec);
		assert_not_equals(id, 0);
		assert_equals(i+1, id);
		rwtxn.commit();

		// Get the record back out by "main" id
		auto rotxn = db->getROTransaction();
		JaldbRecordTranslator outRec;

		// We know there will be only 1 so we can cheat and use the simple .get()
		id = rotxn.get<LmdbDbIndex::IDX_NONCE_TIMESTAMP>(nonceTimestamp, outRec);
		assert_not_equals(id, 0);
		assert_equals(i+1, id);

		// Get the C struct out of the record and place it in our array
		outRecords[i] = outRec.generateCStruct();
	}
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		compare_record_contents(records[i], outRecords[i]);
	}
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		jaldb_destroy_record(&outRecords[i]);
	}
}

extern "C" void  test_insert_and_get_by_confirmed()
{
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		auto rwtxn = db->getRWTransaction();
		auto cppRec = JaldbRecordTranslator::fromCStruct(*records[i]);
		auto id = rwtxn.put(cppRec);
		assert_not_equals(id, 0);
		assert_equals(i+1, id);
		rwtxn.commit();
	}

	// Get the record back out by "confirmed"
	// there will be 2 results
	// record 0 and record 1
	auto rotxn = db->getROTransaction();
	JaldbRecordTranslator outRec;

	int recordsFound = 0;
	// NOTE - .find(false) appears to just give us everything, instead of the ones
	// not marked as confirmed, so that's weird
	// In that case you would thing .begin() would just give us all the records in the
	// subindex, but that doesn't work either.
	for(auto iter = rotxn.find<LmdbDbIndex::IDX_SENT>(JALDB_NOT_SENT); iter != rotxn.end(); ++iter)
	{
		recordsFound++;

		// The iterator overloads -> to return a pointer to the record struct type
		// which is handy for things like iter->networkNonce
		//
		// Because it's the first two records in our array that have confirmed = 1, we should
		// just be able to compare using an incrementing index
		struct jaldb_record* cRec = iter->generateCStruct();
		assert_not_equals(NULL, cRec);

		// To ensure we're comparing against the right record, search our array for a record
		// which has the same network nonce
		int matchingRecordIdx = 0;
		for(matchingRecordIdx = 0; matchingRecordIdx < ITEMS_IN_DB; matchingRecordIdx++) {
			if(0 == strcmp(records[matchingRecordIdx]->network_nonce, iter->networkNonce.c_str())) {
				break;
			}
		}
		assert_not_equals(ITEMS_IN_DB, matchingRecordIdx);
		compare_record_contents(cRec, records[matchingRecordIdx]);
		jaldb_destroy_record(&cRec);
	}
	// Assure we got 3 results
	if(3 != recordsFound) {
		// Better error message if the following assert would fire
		fprintf(stderr, "Expected 3 records from .find, received %d\n", recordsFound);
	}
	assert_equals(3, recordsFound);
}

extern "C" void  test_insert_and_get_by_sent()
{
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		auto rwtxn = db->getRWTransaction();
		auto cppRec = JaldbRecordTranslator::fromCStruct(*records[i]);
		auto id = rwtxn.put(cppRec);
		assert_not_equals(id, 0);
		assert_equals(i+1, id);
		rwtxn.commit();
	}

	// Get the record back out only if the synced field is set to JALDB_SENT
	// there will be 1 result
	// record 2
	auto rotxn = db->getROTransaction();
	JaldbRecordTranslator outRec;

	int recordsFound = 0;
	auto range = rotxn.equal_range<LmdbDbIndex::IDX_SENT>(JALDB_SENT);
	for(auto iter = std::move(range.first); iter != range.second; ++iter)
	{
		recordsFound++;
		// Sanity check - are we actually looping over records with the synced enum set to
		// JALDB_SENT?
		assert_equals(JALDB_SENT, iter->synced);
		// The iterator overloads -> to return a pointer to the record struct type
		// which is handy for things like iter->networkNonce
		//
		// Because it's the first two records in our array that have confirmed = 1, we should
		// just be able to compare using an incrementing index
		struct jaldb_record* cRec = iter->generateCStruct();
		assert_not_equals(NULL, cRec);

		// To ensure we're comparing against the right record, search our array for a record
		// which has the same network nonce
		int matchingRecordIdx = 0;
		for(matchingRecordIdx = 0; matchingRecordIdx < ITEMS_IN_DB; matchingRecordIdx++) {
			if(0 == strcmp(records[matchingRecordIdx]->network_nonce, iter->networkNonce.c_str())) {
				break;
			}
		}
		assert_not_equals(ITEMS_IN_DB, matchingRecordIdx);
		compare_record_contents(cRec, records[matchingRecordIdx]);
		jaldb_destroy_record(&cRec);
	}
	// Assure we got 1 results
	if(1 != recordsFound) {
		// Better error message if the following assert would fire
		fprintf(stderr, "Expected 1 records from .find, received %d\n", recordsFound);
	}
	assert_equals(1, recordsFound);
}

extern "C" void  test_insert_and_get_by_uuid()
{
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		auto rwtxn = db->getRWTransaction();
		auto cppRec = JaldbRecordTranslator::fromCStruct(*records[i]);
		auto id = rwtxn.put(cppRec);
		assert_not_equals(id, 0);
		assert_equals(i+1, id);
		rwtxn.commit();
	}

	auto rotxn = db->getROTransaction();

	// Pick a specific record's uuid to look for, we'll use record[2]
	int recordsFound = 0;
	// This loop shouldn't fire more than once since our test data only has one known
	// record with the specific uuid we're using, so we can cheat and hardcode values
	// TODO: lmdb-typed is a little dumb with non-string non-numeric types
	// We have to convert the key into a string for lmdb to make use of it

	char uuidCStr[UUID_STR_LEN] = {0};
	uuid_unparse_lower(records[2]->uuid, uuidCStr);
	auto range = rotxn.equal_range<LmdbDbIndex::IDX_UUID>(std::string(uuidCStr));
	for(auto iter = std::move(range.first); iter != range.second; ++iter)
	{
		recordsFound++;
		// Sanity check - did our discovered record match the selected uuid?
		assert_equals(0, uuid_compare(iter->uuid, records[2]->uuid));

		// Get the C struct
		struct jaldb_record* cRec = iter->generateCStruct();
		assert_not_equals(NULL, cRec);

		// Compare the record against the record we expected to find
		compare_record_contents(cRec, records[2]);
		jaldb_destroy_record(&cRec);
	}
	if(1 != recordsFound) {
		// Better error message if the following assert would fire
		fprintf(stderr, "Expected 1 records from .find, received %d\n", recordsFound);
	}
	assert_equals(1, recordsFound);
}

extern "C" void  test_insert_and_get_by_timestamp()
{
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		auto rwtxn = db->getRWTransaction();
		auto cppRec = JaldbRecordTranslator::fromCStruct(*records[i]);
		auto id = rwtxn.put(cppRec);
		assert_not_equals(id, 0);
		assert_equals(i+1, id);
		rwtxn.commit();
	}

	auto rotxn = db->getROTransaction();

	// Pick a specific record's timestamp to look for, we'll use records[0]
	int recordsFound = 0;
	// This loop shouldn't fire more than once since our test data only has one known
	// record with the specific timestamp we're using, so we can cheat and hardcode values
	auto range = rotxn.equal_range<LmdbDbIndex::IDX_TIMESTAMP>(std::string(records[0]->timestamp));
	for(auto iter = std::move(range.first); iter != range.second; ++iter)
	{
		recordsFound++;
		// Sanity check - did our discovered record match the selected timestamp?
		assert_equals(0, strcmp(iter->timestamp.c_str(), records[0]->timestamp));
		// Create the C struct
		struct jaldb_record* cRec = iter->generateCStruct();
		assert_not_equals(NULL, cRec);

		// Compare with our known target record
		compare_record_contents(cRec, records[0]);
		jaldb_destroy_record(&cRec);
	}
	if(1 != recordsFound) {
		// Better error message if the following assert would fire
		fprintf(stderr, "Expected 1 records from .find, received %d\n", recordsFound);
	}
	assert_equals(1, recordsFound);
}

extern "C" void  test_modify_in_place_sent()
{
	auto rwtxn = db->getRWTransaction();
	for(int i = 0; i < ITEMS_IN_DB; i++)
	{
		auto cppRec = JaldbRecordTranslator::fromCStruct(*records[i]);
		auto id = rwtxn.put(cppRec);
		assert_not_equals(id, 0);
		assert_equals(i+1, id);
	}

	// Lets test marking the UNSENT record as SENT
	// There should be exactly 1 - record 0
	int recordsFound = 0;
	auto range = rwtxn.equal_range<LmdbDbIndex::IDX_SENT>(JALDB_NOT_SENT);
	for(auto iter = std::move(range.first); iter != range.second; ++iter)
	{
		recordsFound++;
		// Sanity check - are we actually looping over records with the synced enum set to
		// JALDB_SENT?
		assert_equals(JALDB_NOT_SENT, iter->synced);

		struct jaldb_record* cRec = iter->generateCStruct();
		assert_not_equals(NULL, cRec);

		// Ensure we got only record[0]
		compare_record_contents(cRec, records[0]);

		// In order to modify the record in place, we need the main id from the iterator
		auto id = iter.getID();

		// Modify the record in place
		// Using a lamdba here feels like overkill, but I guess it's pretty flexible
		rwtxn.modify(id, [](JaldbRecordTranslator& r) {
				r.synced = JALDB_SENT;
			});
		jaldb_destroy_record(&cRec);
	}
	rwtxn.commit();

	if(1 != recordsFound) {
		// Better error message if the following assert would fire
		fprintf(stderr, "Expected 1 records from .equal_range, received %d\n", recordsFound);
	}
	assert_equals(1, recordsFound);

	// Do it again, this time read-only, search for SENT, and expect 2
	recordsFound = 0;
	auto rotxn = db->getROTransaction();
	auto range2 = rotxn.equal_range<LmdbDbIndex::IDX_SENT>(JALDB_SENT);
	for(auto iter = std::move(range2.first); iter != range2.second; ++iter)
	{
		recordsFound++;
		// Sanity check - are we actually looping over records with the synced enum set to
		// JALDB_SENT?
		assert_equals(JALDB_SENT, iter->synced);
	}

	// Assure we got 2 results
	if(2 != recordsFound) {
		// Better error message if the following assert would fire
		fprintf(stderr, "Expected 2 records from .find, received %d\n", recordsFound);
	}
	rwtxn.commit();
	assert_equals(2, recordsFound);
}
