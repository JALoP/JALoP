#pragma once
/**
 * @file
 *
 * @brief This file implements defines the structs used to
 * wrap the C compliant jaldb_record struct (and the segment within it) in C++
 * compatible struct types for use by lmdb-typed.cpp and .h, and the boost::archive
 * library used for serialization and deserialization *
 *
 * ### LICENSE
 *
 * Copyright (C) 2025 Concurrent Technologies Corporation.
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
#include <jalop/jal_status.h>
#include <string>
#include <vector>
#include <uuid/uuid.h>
#include "lmdb-typed.h"
#include "jaldb_record.h"
#include "jaldb_segment.h"

/**
 * Wraps the jaldb_segment C struct
 */
struct JaldbSegmentTranslator {
	uint64_t length = 0;
	std::vector<uint8_t> payload;
	bool onDisk = false;

	/**
	 * Create a jaldb_segment C struct from a JaldbSegementTranslator
	 *
	 * @return An allocated jaldb_segment* which must be freed by the caller
	 */
	jaldb_segment* generateCStruct() const;

	/**
	 * Create an instnace of JaldbSegmentTranslator from a jaldb_segment C struct
	 *
	 * @param[in] s A jaldb_segment struct by reference
	 *
	 * @return A JaldbSegmentTranslator C++ struct
	 */
	static JaldbSegmentTranslator fromCStruct(const jaldb_segment& s);
};

/**
 * Wraps the jaldb_record C struct
 */
struct JaldbRecordTranslator {
	std::string networkNonce;
	std::string nonceTimestamp;
	uint64_t pid = 0;
	uint64_t uid = 0;
	JaldbSegmentTranslator sysMeta;
	JaldbSegmentTranslator appMeta;
	JaldbSegmentTranslator payload;
	std::string source;
	std::string hostname;
	std::string timestamp;
	std::string username;
	std::string securityLabel;
	int version;
	enum jaldb_rec_type  type;            //!< The type of the record
	enum jaldb_sync_stat synced;          //!< Indicates the outbound record status.
	bool                 haveUid = false;        //!< Indicates if the uid filed is valid.
	uuid_t               hostUuid;       //!< The UUID of the machine that created the record.
	uuid_t               uuid;            //!< The UUID of the record.

	/**
	 * Create a jaldb_record C struct from a JaldbRecordTranslator
	 *
	 * @return An allocated jaldb_record* which must be freed by the caller
	 */
	jaldb_record* generateCStruct() const;

	// Create a JaldbRecordTranslator given the C jaldb_record struct
	// for insertion to DB
	static JaldbRecordTranslator fromCStruct(const struct jaldb_record& r);

	/**
	 * Regnerate the networkNonce as if the current process is the producer
	 * Also updates the nonceTimestamp
	 * Uses the existing UUID
	 */
	void regenNetworkNonce();
};

struct UuidExtract {
	std::string operator()(const JaldbRecordTranslator& t) {
		// For RHEL7 compatibility
		#ifndef UUID_STR_LEN
		constexpr int  UUID_STR_LEN = 37;
		#endif
		char uuidCStr[UUID_STR_LEN] = {0};
		uuid_unparse_lower(t.uuid, uuidCStr);
		return std::string(uuidCStr);
	}
};

/**
 * Serialization instructions to boost::archive for the JaldbSegmentTranslator
 *
 * @param[in] ar The archive object for serializing
 * @param[in] g The thing being serialized
 * @param[in] version Some internal boost thing. No idea what this is for
 */
template<class Archive>
void serialize(Archive& ar, JaldbSegmentTranslator& g, const unsigned int version) {
	(void)version;
	ar & g.length;
	ar & g.payload;
	ar & g.onDisk;
}

/**
 * Serialization instructions to boost::archive for the RecordTranslator
 *
 * @param[in] ar The archive object for serializing
 * @param[in] g The thing being serialized
 * @param[in] version Some internal boost thing. No idea what this is for
 */
template<class Archive>
void serialize(Archive& ar, JaldbRecordTranslator& g, const unsigned int version) {
	(void)version;
	ar & g.networkNonce;
	ar & g.nonceTimestamp;
	ar & g.pid;
	ar & g.uid;
	ar & g.sysMeta;
	ar & g.appMeta;
	ar & g.payload;
	ar & g.source;
	ar & g.hostname;
	ar & g.timestamp;
	ar & g.username;
	ar & g.securityLabel;
	ar & g.version;
	ar & g.type;
	ar & g.synced;
	ar & g.haveUid;
	ar & g.hostUuid;
	ar & g.uuid;
}
