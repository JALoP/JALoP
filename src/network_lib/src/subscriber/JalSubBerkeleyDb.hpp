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

#ifndef __JAL__SUB__BERKELEY__DB__DB__H__
#define __JAL__SUB__BERKELEY__DB__DB__H__

#include <vector>
#include <stdexcept>
#include <fstream>
#include <iterator>

#include "JalSubDatabase.hpp"
#include "JalSubscriber.hpp"
#include "JalSubRecordInfo.hpp"
#include "JalSubUtils.hpp"

#include "jaldb_context.h"
#include "jsub_db_layer.hpp"

class BerkeleyDb : public JalSubDatabase
{
	private:
	jaldb_context* db_ctx;
	std::string journalPayloadPath;
	std::string databasePath;

	// For Audit, Log, the payload is always inserted as a value to the db. In the cases where
	// the payload was written to disk, we will collect it into a vector first for processing
	uint8_t* payloadCollector = NULL;

	const uint8_t* getNonJournalPayload(const RecordInfo& recordInfo)
	{
		if(recordInfo.payloadLen > 0 && recordInfo.payload.empty())
		{
			try
			{
				if(payloadCollector)
				{
					delete[] payloadCollector;
				}
				payloadCollector = new uint8_t[recordInfo.payloadLen];
			}
			catch(...)
			{
				throw std::runtime_error("Failed to allocate sufficiently sized buffer for"
					" insertion of payload to BerkeleyDB");
			}
			std::ifstream f(recordInfo.payloadFileName, std::ios::binary);
			if(!f)
			{
				std::string errMsg = "Failed to open payload file: " + recordInfo.payloadFileName + 
					" for insertion to BerkeleyDB.";
				throw std::runtime_error(errMsg);
			}
			f.read((char*)payloadCollector, recordInfo.payloadLen);
			if(!f)
			{
				throw std::runtime_error("Failed to completely read payload file for insertion"
					" to BerkeleyDB");
			}
			return payloadCollector;
		}
		else
		{
			return recordInfo.payload.data();
		}
	}
	
	public:
	static std::shared_ptr<JalSubDatabase> berkeleyDbFactory(SubscriberConfig config)
	{
		return std::make_shared<BerkeleyDb>(config);
	}

	BerkeleyDb(SubscriberConfig config)
	{
		databasePath = config.databasePath;
		journalPayloadPath = config.databasePath + "/journal";
		// If the journal dir does not exist, attempt to create it
		if(!createDir(journalPayloadPath))
		{
			throw std::runtime_error("Failed to create db output directory: " + journalPayloadPath);
		}

		db_ctx = jsub_setup_db_layer(config.databasePath.c_str());
		if(!db_ctx)
		{
			throw std::runtime_error("Failed to initialize db with path: " + journalPayloadPath);
		}

		//TODO add call to jsub_flush_stale_data
	}

	~BerkeleyDb()
	{
		if(payloadCollector)
		{
			delete[] payloadCollector;
			payloadCollector = NULL;
		}
		jsub_teardown_db_layer(&db_ctx);
	}

	bool insertAuditImpl(const RecordInfo& recordInfo) override
	{
		const uint8_t* sys_meta_ptr = recordInfo.sysMetadata.data();
		const uint8_t* app_meta_ptr = recordInfo.appMetadata.data();
		const uint8_t* payload_ptr;
		try
		{
			payload_ptr = getNonJournalPayload(recordInfo);
		}
		catch(std::runtime_error& e)
		{
			fprintf(stderr, "Failed to acquire payload data for insertion with error: %s\n",
				e.what());
			return false;
		}

		if(JAL_OK != jsub_insert_audit(db_ctx,
			NULL, // Unused
			sys_meta_ptr, 
			recordInfo.sysMetadataLen,
			app_meta_ptr,
			recordInfo.appMetadataLen,
			payload_ptr,
			recordInfo.payloadLen,
			recordInfo.jalId.c_str(),
			1))
		{
			fprintf(stderr, "Failed to insert audit\n");
			return false;
		}

		// We don't actually use this returned nonce, but it must be NULL
		char* nonce_out = NULL;

		if(JALDB_OK != jaldb_mark_confirmed(
			db_ctx,
			JALDB_RTYPE_AUDIT,
			recordInfo.jalId.c_str(),
			&nonce_out))
		{
			free(nonce_out);
			fprintf(stderr, "Failed to mark audit confirmed\n");
			return false;
		}
		free(nonce_out);
		return true;
	}

	bool insertLogImpl(const RecordInfo& recordInfo) override
	{
		const uint8_t* sys_meta_ptr = recordInfo.sysMetadata.data();
		const uint8_t* app_meta_ptr = recordInfo.appMetadata.data();
		const uint8_t* payload_ptr;
		try
		{
			payload_ptr = getNonJournalPayload(recordInfo);
		}
		catch(std::runtime_error& e)
		{
			fprintf(stderr, "Failed to acquire payload data for insertion with error: %s\n",
				e.what());
			return false;
		}

		if(JAL_OK != jsub_insert_log(db_ctx,
			NULL, // Unused
			sys_meta_ptr, 
			recordInfo.sysMetadataLen,
			app_meta_ptr,
			recordInfo.appMetadataLen,
			payload_ptr,
			recordInfo.payloadLen,
			recordInfo.jalId.c_str(),
			1))
		{
			fprintf(stderr, "Failed to insert log\n");
			return false;
		}

		// We don't actually use this returned nonce, but it must be NULL
		char* nonce_out = NULL;

		if(JALDB_OK != jaldb_mark_confirmed(
			db_ctx,
			JALDB_RTYPE_LOG,
			recordInfo.jalId.c_str(),
			&nonce_out))
		{
			free(nonce_out);
			fprintf(stderr, "Failed to mark log confirmed\n");
			return false;
		}
		free(nonce_out);
		return true;
	}

	bool insertJournalImpl(const RecordInfo& recordInfo) override
	{
		// Following the pattern used by the jal local store and v1 subscriber,
		// journal payloads will be stored in a separate subdirectory and linked to
		// from the database proper.
		// The file used to store the payloads is constructed as follows:
		//
		// <outputDir>/journal/XX/journal_payload_<jalId>
		// Where XX is the first two characters of jalId
		// and <outputDir>/journal is what is already stored in journalPayloadPath
		std::string subDir = recordInfo.jalId.substr(0,2);
		std::string subDirPath = journalPayloadPath + "/" + subDir;
		if(!createDir(subDirPath))
		{
			fprintf(stderr, "Failed to create db output directory: %s\n", subDirPath.c_str());
			return false;
		}

		// To match v1, we want to always store the journal payload in a file,
		// event if falls within our in-memory buffer size contraints
		
		// Create final payload filename
		// To match the v1 subscriber, the format of the name shall be
		// journal/XX/journal_payload_<first 36 of jalId>
		// Where XX is the first two characters of jalId
		std::string filename = "journal_payload_" + recordInfo.jalId.substr(0,36);

		std::string oldPath = recordInfo.payloadFileName;
		std::string newPath = journalPayloadPath
			+ "/" + subDir
			+ "/" + filename;

		// If we have the payload in memory, dump it to the final output file
		if(!recordInfo.payload.empty())
		{
			std::ofstream fout(newPath, std::fstream::binary);
			if(!fout)
			{
				fprintf(stderr, "Failed to create payload file: %s for writing.\n", newPath.c_str());
				return false;
			}
			fout.write((const char*)recordInfo.payload.data(), recordInfo.payload.size());
			fout.close();
		}
		// If we have the payload as a file, move it to the final location
		else
		{
			// Move the in-transit file to its final location
			int renameStatus = rename(oldPath.c_str(), newPath.c_str());
			if(0 != renameStatus)
			{
				fprintf(stderr, "Failed to move temporary payload file: %s to final location %s.\n",
					oldPath.c_str(), newPath.c_str());
				return false;
			}
		}
		
		// The jsub interface assumes a base path of <db root>/journal, provide only
		// the subdir and filename
		std::string relativeFilename = subDir + "/" + filename;
		// Insert journal metadata, including link 
		const uint8_t* sys_meta_ptr = recordInfo.sysMetadata.data();
		const uint8_t* app_meta_ptr = recordInfo.appMetadata.data();
		if(JAL_OK != jsub_insert_journal_metadata(
			db_ctx,
			NULL, //Unused
			sys_meta_ptr, 
			recordInfo.sysMetadataLen,
			app_meta_ptr,
			recordInfo.appMetadataLen,
			relativeFilename.c_str(),
			recordInfo.payloadLen,
			recordInfo.jalId.c_str(),
			1))
		{
			fprintf(stderr, "Failed to insert journal\n");
			return false;
		}

		// We don't actually use this returned nonce, but it must be NULL
		char* nonce_out = NULL;

		if(JALDB_OK != jaldb_mark_confirmed(
			db_ctx,
			JALDB_RTYPE_JOURNAL,
			recordInfo.jalId.c_str(),
			&nonce_out))
		{
			free(nonce_out);
			fprintf(stderr, "Failed to mark journal confirmed\n");
			return false;
		}
		free(nonce_out);
		return true;
	}
};

#endif
