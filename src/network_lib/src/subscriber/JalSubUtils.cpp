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
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include "JalSubUtils.hpp"
#include "JalSubEnumTypes.hpp"

bool createDir(std::string dirPath)
{
	struct stat dirStat;
	int statRc = stat(dirPath.c_str(), &dirStat);

	// If directory does not exist, create it
	if(0 != statRc && ENOENT == errno)
	{
		int mkdirRc = mkdir(dirPath.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
		if(0 != mkdirRc)
		{
			fprintf(stderr, "Failed to create directory: %s with error: %s\n",
					dirPath.c_str(), strerror(errno));
			return false;
		}
	}
	// Some other error - abort
	else if(0 != statRc)
	{
		fprintf(stderr, "Failed to stat directory: %s, with error: %s\n",
				dirPath.c_str(), strerror(errno));
		return false;
	}
	// Something at path already exists, but is not a directory
	else if(!S_ISDIR(dirStat.st_mode))
	{
		fprintf(stderr, "Failed to create directory: %s, already exists as non-directory",
				dirPath.c_str());
		return false;
	}
	return true;
}

bool dirExists(std::string dirPath)
{
	struct stat dirStat;
	int statRc = stat(dirPath.c_str(), &dirStat);
	if(0 == statRc && S_ISDIR(dirStat.st_mode))
	{
		return true;
	}
	return false;
}

void debugOutput(bool shouldPrint, FILE* fd, const char* fmt, ...)
{
	if(!shouldPrint)
	{
		return;
	}

	va_list args;
	va_start(args, fmt);
	vfprintf(fd, fmt, args);
	va_end(args);
}

std::string getPayloadFileName(
	std::string tempFilePath,
	std::string publisherId,
	ReceiveMessageType messageType,
	std::string jalId)
{
	std::string filename = tempFilePath + "/";
	filename += publisherId + "/";
	switch(messageType)
	{
		case ReceiveMessageType::MSG_LOG:
			filename += "log/";
			break;
		case ReceiveMessageType::MSG_AUDIT:
			filename += "audit/";
			break;
		case ReceiveMessageType::MSG_JOURNAL:
			filename += "journal/";
			break;
		default:
			// Unreachable
			break;
	}
	filename += jalId;
	return filename;
}
