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

#ifndef __JAL__SUB__FS__DB__H__
#define __JAL__SUB__FS__DB__H__

#include <vector>
#include <stdexcept>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>

// For the PRId64 type macro from printf
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "JalSubDatabase.hpp"
#include "JalSubConfig.hpp"
#include "JalSubRecordInfo.hpp"
#include "JalSubUtils.hpp"

class FsDb : public JalSubDatabase
{
	private:
	std::string auditStoragePath;
	std::string journalStoragePath;
	std::string logStoragePath;

	uint64_t auditCounter = 0;
	uint64_t journalCounter = 0;
	uint64_t logCounter = 0;

	SubscriberConfig config;

	// Max of a 10 digit decimal number
	// Note this value does not fit in a 32-bit counter
	const uint64_t COUNTER_MAX = 9999999999;

	// A filtering function to reject any discovered directories that don't meet our
	// expected format for record storage
	static int direntFilter(const struct dirent* dp)
	{
		// Use scanf to validate format
		// using * to ignore the number itself, we only care that it matches our format
		// Valid directory names have a length of 10
		const int expectedDirNameLen = 10;
		int charsRead = 0;
		int matchedItems = sscanf(dp->d_name, "%*d%n", &charsRead);
		if(1 != matchedItems || expectedDirNameLen != charsRead)
		{
			return -1;
		}
		else
		{
			return 0;
		}
	}

	// Scan a given directory for subdirectories of the form ########## (unsigned int length 10)
	// which is a fixed-length 0-padded sequence number. Find the largest existing
	// value, and return that value plus 1 to represent the next available record number
	//
	// TODO: It would mean a potentially VERY slow startup in situations where there are many
	// records already in the databasePath, but we may want to consider scanning for a
	// discontinuity in existing records rather than just adding on the end.
	// If a rollover has occurred, starting at COUNTER_MAX + 1 doesn't actually make sense.
	uint64_t getNextRecordNum(std::string path)
	{
		// The following loosely based on the scandir(3) manpage
		struct dirent** namelist = NULL;
		int numEntries;

		// alphasort is included in the dirent.h include
		numEntries = scandir(path.c_str(), &namelist, direntFilter, alphasort);

		if(-1 == numEntries)
		{
			// This is unusual. Probably the creation of the directory failed, or there is a
			// problem with permissions. Fail out
			std::string errMsg = "ERROR: Unable to scan directory: " + path;
			throw std::runtime_error(errMsg);
		}

		uint64_t nextRecordNum = 0;
		struct stat fileStat;

		// If there were more than 0 results...
		// It's possible to fall out of this loop without finding any valid results, in which
		// case the value of 0 is correct to keep for nextRecordNum
		//
		// TODO: dirent returns an int for the number of entries, if there are ever more than
		// MAX_INT items in the directory, this will cause problems. However it's unlikely
		// that a system will support MAX_INT inodes in a single directory anyway
		for(int i = numEntries -1; i >= 0; --i)
		{
			// Because of the lexicographic sort done by alphasort, we want to select the "last"
			// entry which is a directory. Our filter elimited any results that were not ten
			// digit numbers, so we won't have to worry about things like . and .., and we know
			// a conversion to a numeric format will succeed.
			std::string candidateResult = path + "/" + namelist[i]->d_name;

			stat(candidateResult.c_str(), &fileStat);
			// Skip this one if it isn't a directory
			if(!S_ISDIR(fileStat.st_mode))
			{
				continue;
			}
			// Take the result's filename, convert to an unsigned long, and add one
			char* end = NULL;
			nextRecordNum = strtoul(namelist[i]->d_name, &end, 10) + 1;
			break;
		}

		// Free the namelist
		for(int i = 0; i < numEntries; i++)
		{
			free(namelist[i]);
		}
		free(namelist);

		return nextRecordNum;
	}

	bool writeData(
		const std::string& recordDir,
		const std::string& fileName,
		std::vector<uint8_t> data)
	{
		// If no data exists, do nothing, return success
		if(data.empty())
		{
			return true;
		}

		// Otherwise, open a new file
		std::string filePath = recordDir + "/" + fileName;
		std::ofstream dataFile(filePath, std::ofstream::binary);
		if(!dataFile)
		{
			// Always display this error
			fprintf(stderr,
				"Error: Could not create db file: %s\n", filePath.c_str());
			return false;
		}

		// Our output file is good to go, write our data
		dataFile.write((char*)data.data(), data.size());
		if(!dataFile.bad() && !dataFile.fail())
		{
			// If all of our data wrote successfully, we're done
			return true;
		}
		else
		{
			// Otherwise, something has gone wrong. Close the file, attempt to delete it, and
			// return failure
			dataFile.close();
			remove(filePath.c_str());
			return false;
		}
	}

	bool writePayload(const std::string& recordDir, const RecordInfo& recordInfo)
	{
		if(!recordInfo.payload.empty())
		{
			// If the payload is stored in a vector, write it out
			return writeData(recordDir, "payload", recordInfo.payload);
		}
		else
		{
			// Otherwise, we just move the existing payload file to a new location
			std::string oldPath = recordInfo.payloadFileName;
			std::string newPath = recordDir + "/payload";
			int renameStatus = rename(oldPath.c_str(), newPath.c_str());
			if(0 != renameStatus)
			{
				fprintf(stderr, "Failed to move temporary payload file: %s to final location %s.\n",
					oldPath.c_str(), newPath.c_str());
				return false;
			}
			else
			{
				return true;
			}
		}
	}

	bool writeToDb(const std::string& basePath, uint64_t recordNum, const RecordInfo& recordInfo)
	{
		char recordNumBuf[11];
		sprintf(recordNumBuf, "%010" PRId64, recordNum);
		std::string newRecordDir = basePath + "/" + std::string(recordNumBuf);
		// This really shouldn't happen, abort write
		if(dirExists(newRecordDir))
		{
			// Always report this error
			fprintf(stderr,
				"Error: attempting to write record : %s, but this record already exists",
				newRecordDir.c_str());
			return false;
		}

		// Create directory basePath/recordNum
		if(!createDir(newRecordDir))
		{
			// Always report this error
			fprintf(stderr,
				"Error: Failed to create record directory: %s\n", newRecordDir.c_str());
			return false;
		}

		bool writeFailed = false;
		// Write the application metadata to app_metadata.xml
		if(!writeData(newRecordDir, "app_metadata.xml", recordInfo.appMetadata))
		{
			writeFailed = true;;
		}
		// Write the system metadata to sys_metadata.xml
		// If this fails, clean up the app_metadata.xml file
		else if(!writeData(newRecordDir, "sys_metadata.xml", recordInfo.sysMetadata))
		{
			writeFailed = true;
			std::string filename = newRecordDir + "/app_metadata.xml";
			remove(filename.c_str());
		}
		// Write the payload
		// If this fails, clean up the app_metadata.xml file and sys_metadata.xml file
		else if(!writePayload(newRecordDir, recordInfo))
		{
			writeFailed = true;
			std::string filename = newRecordDir + "/app_metadata.xml";
			remove(filename.c_str());
			filename = newRecordDir + "/sys_metadata.xml";
			remove(filename.c_str());
		}

		// If there was any failure, remove the directory entirely
		if(writeFailed)
		{
			remove(newRecordDir.c_str());
			return false;
		}
		// If there was no write failure, create the confirmed file because we're about
		// to send the sync message
		else
		{
			std::string filename = newRecordDir + "/confirmed";
			// Creates an output file, immediately flushes to guarantee it gets placed on the
			// file system, and then closes that file
			std::ofstream(filename, std::ofstream::out).flush();
			return true;
		}
	}

	public:
	static std::shared_ptr<JalSubDatabase> fsDbFactory(SubscriberConfig config)
	{
		return std::make_shared<FsDb>(config);
	}

	FsDb(SubscriberConfig paramConfig) : config(paramConfig)
	{
		journalStoragePath = config.databasePath + "/journal";
		auditStoragePath = config.databasePath + "/audit";
		logStoragePath = config.databasePath + "/log";

		for(const auto& path : { journalStoragePath, auditStoragePath, logStoragePath })
		{
			// If the journal dir does not exist, attempt to create it
			if(!createDir(path))
			{
				throw std::runtime_error("Failed to create db output directory: " + path);
			}
		}

		auditCounter = getNextRecordNum(auditStoragePath);
		journalCounter = getNextRecordNum(journalStoragePath);
		logCounter = getNextRecordNum(logStoragePath);
	}

	bool insertAuditImpl(const RecordInfo& recordInfo) override
	{
		// Note - if the user hasn't done something to clear old records when this rollover
		// happens, further inserts will fail because the directories for the new inserts
		// will already exist
		if(auditCounter >= COUNTER_MAX)
		{
			auditCounter = 0;
		}
		return writeToDb(auditStoragePath, auditCounter++, recordInfo);
	}

	bool insertLogImpl(const RecordInfo& recordInfo) override
	{
		// Note - if the user hasn't done something to clear old records when this rollover
		// happens, further inserts will fail because the directories for the new inserts
		// will already exist
		if(logCounter >= COUNTER_MAX)
		{
			logCounter = 0;
		}
		return writeToDb(logStoragePath, logCounter++, recordInfo);
	}

	bool insertJournalImpl(const RecordInfo& recordInfo) override
	{
		// Note - if the user hasn't done something to clear old records when this rollover
		// happens, further inserts will fail because the directories for the new inserts
		// will already exist
		if(journalCounter >= COUNTER_MAX)
		{
			journalCounter = 0;
		}
		return writeToDb(journalStoragePath, journalCounter++, recordInfo);
	}
};

#endif
