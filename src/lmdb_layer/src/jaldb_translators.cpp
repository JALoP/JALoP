/**
 * @file
 *
 * @brief This file provides functions to support
 * the serialization/deserialization of a jal record.
 *
 * ### LICENSE
 *
 * Copyright (C) 2025 The National Security Agency (NSA)
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
#include "jal_alloc.h"
#include "jal_ts_utils.h"
#include "jaldb_translators.h"
#include "jal_asprintf_internal.h"

jaldb_segment* JaldbSegmentTranslator::generateCStruct() const {
	jaldb_segment *ret = (jaldb_segment*)jal_calloc(1, sizeof(*ret));
	ret->length = length;
	ret->fd = -1;
	ret->on_disk = onDisk ? 1 : 0;
	ret->payload = (uint8_t*)jal_calloc(payload.size(), sizeof(uint8_t));
	memcpy(ret->payload, payload.data(), payload.size());
	return ret;
}

JaldbSegmentTranslator JaldbSegmentTranslator::fromCStruct(const jaldb_segment& s) {
	JaldbSegmentTranslator t;
	t.length = s.length;
	t.onDisk = (1 == s.on_disk);

	// If the payload is on disk, the "payload" is actually a NULL terminated string
	// containing the file path and is not the size of "length"
	// "length" is always the size of the data segment, regardless of whether
	// its on disk or in the payload field
	size_t payloadLen;
	if(1 == s.on_disk) {
		payloadLen = strlen((char*)s.payload);
	} else {
		payloadLen = s.length;
	}
	t.payload.assign(s.payload, s.payload + payloadLen);
	return t;
}

void JaldbRecordTranslator::regenNetworkNonce() {
	// network_nonce has form uuid_timestamp_pid_tid
	// This should look a lot like jaldb_gen_primary_key from
	// jaldb_utils, but we need the timestamp twice, so we're breaking it out ourselves
	// to avoid re-parsing the nonce after we've made it

	// For RHEL7 compatibility
	#ifndef UUID_STR_LEN
	constexpr int  UUID_STR_LEN = 37;
	#endif
	char uuidCStr[UUID_STR_LEN] = {0};
	uuid_unparse(uuid, uuidCStr);

	char* ts = jal_gen_timestamp_usec();
	if(NULL == ts) {
		throw std::runtime_error("Failed to generate timestamp");
	}

	pid_t new_pid = getpid();
	pthread_t new_tid = pthread_self();//portable

	char *key = NULL;
	jal_asprintf(&key, "%s_%s_%d_%u", uuidCStr, ts, new_pid, new_tid);

	networkNonce = std::string(key);
	nonceTimestamp = std::string(ts);

	free(ts);
	free(key);
}

jaldb_record* JaldbRecordTranslator::generateCStruct() const {
	jaldb_record *ret = (jaldb_record*)jal_calloc(1, sizeof(jaldb_record));
	ret->network_nonce = strdup(networkNonce.c_str());
	ret->pid = pid;
	ret->uid = uid;

	ret->sys_meta = sysMeta.generateCStruct();

	ret->app_meta = appMeta.generateCStruct();

	ret->payload = payload.generateCStruct();

	ret->source = strdup(source.c_str());
	ret->hostname = strdup(hostname.c_str());
	ret->timestamp = strdup(timestamp.c_str());
	ret->username = strdup(username.c_str());
	ret->sec_lbl = strdup(securityLabel.c_str());
	ret->version = version;
	ret->synced = synced;
	ret->type = type;
	ret->confirmed = confirmed ? 1 : 0;
	ret->have_uid = haveUid ? 1 : 0;
	uuid_copy(ret->host_uuid, hostUuid);
	uuid_copy(ret->uuid, uuid);
	return ret;
}

JaldbRecordTranslator JaldbRecordTranslator::fromCStruct(const struct jaldb_record& r) {
	JaldbRecordTranslator ret;
	// The network nonce is the "primary" key, and is required to exist
	if(!r.network_nonce) {
		std::string errMsg = "Unable to construct JaldbRecordTranslator "
			"from jaldb_record without network nonce";
		throw std::runtime_error(errMsg);
	}
	ret.networkNonce = std::string(r.network_nonce);

	// Extract nonce timestamp from network nonce
	// That's everything between the first and second _
	size_t firstUnderscoreIdx = ret.networkNonce.find('_');
	if(std::string::npos == firstUnderscoreIdx) {
		std::string errMsg = "Unable to construct JaldbRecordTranslator: "
			"Unable to extract nonce timestamp";
		throw std::runtime_error(errMsg);
	}
	size_t secondUnderscoreIdx = ret.networkNonce.find('_', firstUnderscoreIdx + 1);
	if(std::string::npos == secondUnderscoreIdx) {
		std::string errMsg = "Unable to construct JaldbRecordTranslator: "
			"Unable to extract nonce timestamp";
		throw std::runtime_error(errMsg);
	}
	size_t len = secondUnderscoreIdx - firstUnderscoreIdx - 1;
	try {
		ret.nonceTimestamp = ret.networkNonce.substr(firstUnderscoreIdx + 1, len);
	}
	catch (std::exception &e) {
		std::string errMsg = "Unable to construct JaldbRecordTranslator: "
			"Unable to extract nonce timestamp";
		throw std::runtime_error(errMsg);
	}

	ret.pid = r.pid;
	ret.uid = r.uid;
	// TODO - these should probably null check the segment pointers
	if(r.sys_meta) {ret.sysMeta = JaldbSegmentTranslator::fromCStruct(*(r.sys_meta)); }
	if(r.app_meta) {ret.appMeta = JaldbSegmentTranslator::fromCStruct(*(r.app_meta)); }
	if(r.payload) { ret.payload = JaldbSegmentTranslator::fromCStruct(*(r.payload)); }
	if(r.source) { ret.source = std::string(r.source); }
	if(r.hostname) { ret.hostname = std::string(r.hostname); }
	if(r.timestamp) { ret.timestamp = std::string(r.timestamp); }
	if(r.username) { ret.username = std::string(r.username); }
	if(r.sec_lbl) { ret.securityLabel = std::string(r.sec_lbl); }
	ret.version = r.version;
	ret.type = r.type;
	ret.synced = r.synced;
	ret.confirmed = (1 == r.confirmed);
	ret.haveUid = (1 == r.have_uid);
	uuid_copy(ret.hostUuid, r.host_uuid);
	uuid_copy(ret.uuid, r.uuid);
	return ret;
}
