/**
 * @file
 *
 * @brief The jaldb_tool can be used to retrieve record counts and update record status
 *
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

#include <iostream>
#include <map>
#include <jalop/jal_version.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "jaldb_context.h"
#include "jaldb_context.hpp"

#include <argp.h>
#include <vector>
#include <ctime>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <dirent.h>
#include <ftw.h>
#include <sys/stat.h>
#include <json-c/json.h>

const char *argp_program_version = "1";
const char *argp_program_bug_address = "";
static char args_doc[] = "";
static char doc[] =
"jal-record-update -- A program to update JALoP record values for testing.";
static error_t parse_opt(int key, char *arg, struct argp_state *state);
static struct argp_option options[] = {
	{"record-type", 't', "type", 0,
		"record type:[log|l],[audit|a],[journal|j],[all|z],default:log", 0},
	{"mark-record", 'm', "flag", 0,
		"mark record type [unsent | u ], [sent | s ], [synced | y ]", 0},
	{"db-home", 'h', "db_dir", 0,
		"database home directory, default: testdb", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

enum class MarkOperation
{
	NONE,
	UNSENT,
	SENT,
	SYNC,
};

enum class RecordSelection
{
	JOURNAL,
	AUDIT,
	LOG,
	ALL,
};

class JalTime{
public:
	struct tm timeStruct;
	std::string timestamp;
	std::string timestampNoDecimal;
	time_t unixSeconds = 0;
	double microSeconds = 0;
	int nanoSeconds = 0;
	double doubleSeconds = 0;
	std::string format = "%Y-%m-%dT%H:%M:%S";

	void figureWithTimestamp(){
		if (timestamp.size()>0){
			char *endptr;
			microSeconds = strtod(timestamp.substr(19, 7).c_str(), &endptr);
			//std::cout << timestamp.substr(19, 7) << " micro " << microSeconds << std::endl;
			timestampNoDecimal = timestamp.substr(0, 19);
			timeStruct.tm_isdst = 0;
			strptime(timestampNoDecimal.c_str(), format.c_str(), &timeStruct);
			unixSeconds = mktime(&timeStruct);
			doubleSeconds = unixSeconds + microSeconds;
		}
	}
	void figureWithSeconds(){
		if(unixSeconds>0){
			timeStruct.tm_isdst = 0;
			struct tm *timeStructP = gmtime(&unixSeconds);
			std::stringstream ss;
			ss << timeStructP->tm_year+1900 << "-";
			ss << std::setw(2) << std::setfill('0') << timeStructP->tm_mon+1 << "-";
			ss << std::setw(2) << std::setfill('0') << timeStructP->tm_mday << "T";
			ss << std::setw(2) << std::setfill('0') << timeStructP->tm_hour << ":";
			ss << std::setw(2) << std::setfill('0') << timeStructP->tm_min << ":";
			ss << std::setw(2) << std::setfill('0') << timeStructP->tm_sec << ".";
			ss << nanoSeconds;
			timestamp = ss.str();
		}
	}
};
struct StatContainer{
	JaldbStat stats;
	enum jaldb_rec_type type;
	bool show;

	JalTime latest;
	JalTime earliest;
	time_t diff_time = 0;
};

struct Config
{
	RecordSelection recordSelection = RecordSelection::ALL;
	MarkOperation operation = MarkOperation::NONE;
	std::string db_home = std::string("testdb");
	std::string db_type = std::string("");
} config;

jaldb_context* setup_jal(void);
enum jaldb_status update_flags(
	jaldb_context* ctx,
	MarkOperation op,
	RecordSelection rSelect);

void print_structured_data(std::vector<StatContainer> dbStats);
bool get_fs_stats(StatContainer& s);

int byte_swapped = 0;
StatContainer *currentContainer;

bool get_fs_type()
{
	struct stat stats;
	std::string db_file;
	std::string db_directory;

	if (stat(config.db_home.c_str(), &stats)!=0)
	{
		std::cout << "db_home '" << config.db_home << "' does not exist." << std::endl;
		return false;
	}
	if ((stats.st_mode & S_IFMT) != S_IFDIR)
	{
		std::cout << " db_home '" << config.db_home << "' is not a directory. " << std::endl;
		return false;
	}
	// log_records.mdb(lmdb) log_records.db(bdb) log(fs)
	db_directory = config.db_home + "/log";
	if (stat(db_directory.c_str(), &stats)==0 && (stats.st_mode & S_IFMT) == S_IFDIR)
	{
		config.db_type = "fs";
		return true;
	}
	else
	{
		db_file = config.db_home + "/log_records.mdb";
		if (stat(db_file.c_str(), &stats)==0 && (stats.st_mode & S_IFMT) == S_IFREG)
		{
			config.db_type = "lmdb";
			return true;
		}
	}
	std::cout << "db_home '" << config.db_home << "' database type cannot be determined." << std::endl;
	return false;
}

int main(int argc, char **argv)
{
	// Parse command line options and populate global Config
	if(0 != argp_parse(&argp, argc, argv, 0, 0, NULL))
	{
		std::cout << "ARGP_ERR_UNKNOWN " << ARGP_ERR_UNKNOWN << std::endl;
	}

	if (get_fs_type()==false)
	{
		return -1;
	}

	jaldb_context* ctx = NULL;
	if (config.db_type.compare("fs")!=0){
		// Create jaldb_context or exit
		ctx = setup_jal();
		if(NULL == ctx) {
			return -1;
		}
		// If an update operation has been requested, perform the update now
		if(JALDB_OK != update_flags(ctx, config.operation, config.recordSelection))
		{
			return -1;
		}
	}
	if (config.db_type.compare("fs")==0 && config.operation!=MarkOperation::NONE){
		std::cout << "Marking records for this database type is not available at this time." << std::endl;
		return -1;
	}

	// Create storage for stats to be returned from get_stats
	std::vector<StatContainer> dbStats =
	{
		{ {}, JALDB_RTYPE_JOURNAL, false, {}, {} },
		{ {}, JALDB_RTYPE_AUDIT, false, {}, {} },
		{ {}, JALDB_RTYPE_LOG, false, {}, {} },
	};
	switch(config.recordSelection)
	{
		case RecordSelection::JOURNAL:
			dbStats[0].show = true;
			break;
		case RecordSelection::AUDIT:
			dbStats[1].show = true;
			break;
		case RecordSelection::LOG:
			dbStats[2].show = true;
			break;
		case RecordSelection::ALL:
			dbStats[0].show = true;
			dbStats[1].show = true;
			dbStats[2].show = true;
			break;
	}

	for (StatContainer & statContainer : dbStats)
	{
		if(!statContainer.show) {
			continue;
		}
		if(config.db_type.compare("fs")!=0){
			enum jaldb_status status = get_stats(ctx, statContainer.stats, statContainer.type);
			if (JALDB_OK != status)
			{
				std::cout << "Failed to get db stats with error code: " << status << std::endl;
				jaldb_context_destroy(&ctx);
				return status;
			}
			statContainer.earliest.timestamp=statContainer.stats.earliest_time;
			statContainer.latest.timestamp=statContainer.stats.latest_time;
		}
		else
		{
			bool ret = get_fs_stats(statContainer);
			if(ret != true)
			{
				std::cout << "Failed to get db stats from file system." << std::endl;
				ret = -1;
			}
		}
	}
	// Finished with the context
	jaldb_context_destroy(&ctx);

	print_structured_data(dbStats);

	return 0;
}

int get_dir_count(__attribute__ ((unused))const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
	double file_mtime;
	if (tflag == FTW_D && ftwbuf->level == 1)
	{
		currentContainer->stats.confirmed_count++;
		currentContainer->stats.count++;
		currentContainer->stats.not_sent_count++;
		file_mtime = sb->st_mtime + (sb->st_mtim.tv_nsec / 1e9);
		if (file_mtime < currentContainer->earliest.doubleSeconds)
		{
			currentContainer->earliest.doubleSeconds = file_mtime;
			currentContainer->earliest.unixSeconds = sb->st_mtime;
			currentContainer->earliest.nanoSeconds = sb->st_mtim.tv_nsec;
		}
		if (file_mtime > currentContainer->latest.doubleSeconds)
		{
			currentContainer->latest.doubleSeconds = file_mtime;
			currentContainer->latest.unixSeconds = sb->st_mtime;
			currentContainer->latest.nanoSeconds = sb->st_mtim.tv_nsec;
		}
		return FTW_CONTINUE;
	}
	else
	{
		return FTW_CONTINUE;
	}
}

bool get_fs_stats(StatContainer& s)
{
	std::string log_type;
	switch (s.type)
	{
		case JALDB_RTYPE_JOURNAL:
			log_type = "journal";
			break;
		case JALDB_RTYPE_AUDIT:
			log_type = "audit";
			break;
		case JALDB_RTYPE_LOG:
			log_type = "log";
			break;
		default:
			return false;
	}
	currentContainer = &s;
	s.earliest.doubleSeconds = 9999999999999;
	s.latest.doubleSeconds = 0;
	std::string directory = config.db_home + "/" + log_type;
	nftw(directory.c_str(), get_dir_count, 20, FTW_ACTIONRETVAL);

	return true;
}

std::string getRecordType(jaldb_rec_type log_type)
{
	switch (log_type)
	{
		case JALDB_RTYPE_JOURNAL:
			return "journal";
			break;
		case JALDB_RTYPE_AUDIT:
			return "audit";
			break;
		case JALDB_RTYPE_LOG:
			return "log";
			break;
		default:
			return "unknown";
	}
}

void print_structured_data(std::vector<StatContainer> dbStats)
{
	double min_time = 9999999999;
	double max_time = 0;
	std::string latest_time_stamp;
	std::string earliest_time_stamp;
	int total_records = 0;
	struct json_object * all = json_object_new_object();
	json_object_object_add(all, "db_home", json_object_new_string(config.db_home.c_str()));
	json_object_object_add(all, "db_type", json_object_new_string(config.db_type.c_str()));
	for (StatContainer & s : dbStats)
	{
		if (!s.show)
		{
			continue;
		}
		struct json_object * result = json_object_new_object();

		if (config.db_type.compare("fs") != 0)
		{
			s.latest.figureWithTimestamp();
			s.earliest.figureWithTimestamp();
		}
		else
		{
			s.latest.figureWithSeconds();
			s.earliest.figureWithSeconds();
		}

		s.diff_time = difftime(s.latest.unixSeconds, s.earliest.unixSeconds);

		json_object_object_add(result, "count", json_object_new_int(s.stats.count));
		json_object_object_add(result, "unsent", json_object_new_int(s.stats.not_sent_count));
		json_object_object_add(result, "sent", json_object_new_int(s.stats.sent_count));
		json_object_object_add(result, "synced", json_object_new_int(s.stats.synced_count));
		json_object_object_add(result, "confirmed", json_object_new_int(s.stats.confirmed_count));
		json_object_object_add(result, "failed", json_object_new_int(s.stats.failed_count));
		json_object_object_add(result, "latest_timestamp", json_object_new_string(s.latest.timestamp.c_str()));
		json_object_object_add(result, "earliest_timestamp", json_object_new_string(s.earliest.timestamp.c_str()));

		json_object_object_add(all, getRecordType(s.type).c_str(), result);

		if (s.stats.count > 0)
		{
			total_records += s.stats.count;
			if (s.earliest.doubleSeconds < min_time)
			{
				min_time = s.earliest.doubleSeconds;
				earliest_time_stamp = s.earliest.timestamp;
			}
			if (s.latest.doubleSeconds > max_time)
			{
				max_time = s.latest.doubleSeconds;
				latest_time_stamp = s.latest.timestamp;
			}
		}
	}

	double total_time = 0;
	total_time = max_time - min_time;
	if (total_time > 0)
	{
		int hours = total_time / 3600;
		int minutes = ((int) total_time % 3600) / 60;
		double seconds = total_time - (minutes * 60) - (hours * 3600);

		std::stringstream stime;
		stime << std::setw(2) << std::setfill('0') << hours << ":";
		stime << std::setw(2) << std::setfill('0') << minutes << ":";
		if(seconds<10){
			stime << 0;
		}
		stime << std::setw(2) << std::setfill('0') << seconds;

		struct json_object * summary = json_object_new_object();

		json_object_object_add(summary, "total_records", json_object_new_int(total_records));
		json_object_object_add(summary, "latest_timestamp", json_object_new_string(latest_time_stamp.c_str()));
		json_object_object_add(summary, "earliest_timestamp", json_object_new_string(earliest_time_stamp.c_str()));
		json_object_object_add(summary, "total_time", json_object_new_string(stime.str().c_str()));

		json_object_object_add(all, "summary", summary);
	}

	std::string output = json_object_to_json_string_ext(all, JSON_C_TO_STRING_PRETTY);
	std::cout << output << std::endl;
}

// Helper to avoid repeating this logic twice in update_flags
static enum jaldb_status mark(jaldb_context* ctx, enum jaldb_sync_stat desiredState, std::string stateStringForm, enum jaldb_rec_type type, std::string typeStringForm)
{
	enum jaldb_status status;
	if (config.db_type.compare("fs")!=0)
	{
		std::cout << "Marking records of type: " << typeStringForm << " with state:  " << stateStringForm << std::endl;
		status = mark_all_records(ctx, type, desiredState);
		if(JALDB_OK != status)
		{
			std::cout << "Jaldb Status Code: " << status << " encountered while updating record of type: " << typeStringForm << " to state: " << stateStringForm << std::endl;
		}
	}
	else
	{
		std::cout << "Marking records for this database type is not available at this time." << std::endl;
		status = JALDB_E_NOT_IMPL;
	}
	return status;
}

enum jaldb_status update_flags(
	jaldb_context* ctx,
	MarkOperation op,
	RecordSelection rSelect)
{
	enum jaldb_sync_stat desiredState;
	std::string stateStringForm;
	switch(op)
	{
		case MarkOperation::UNSENT:
			desiredState = JALDB_NOT_SENT;
			stateStringForm = "UNSENT";
			break;
		case MarkOperation::SENT:
			desiredState = JALDB_SENT;
			stateStringForm = "SENT";
			break;
		case MarkOperation::SYNC:
			desiredState = JALDB_SYNCED;
			stateStringForm = "SYNC";
			break;
		default:
			return JALDB_OK;
	}

	enum jaldb_status status = JALDB_OK;
	switch(rSelect)
	{
		case RecordSelection::JOURNAL:
			status = mark(ctx, desiredState, stateStringForm, JALDB_RTYPE_JOURNAL, "journal");
			break;
		case RecordSelection::AUDIT:
			status = mark(ctx, desiredState, stateStringForm, JALDB_RTYPE_AUDIT, "audit");
			break;
		case RecordSelection::LOG:
			status = mark(ctx, desiredState, stateStringForm, JALDB_RTYPE_LOG, "log");
			break;
		case RecordSelection::ALL:
			status = mark(ctx, desiredState, stateStringForm, JALDB_RTYPE_JOURNAL, "journal");
			// A dirty hack to skip susequent calls to mark if 0 a.k.a. JALDB_OK != status
			status || (status = mark(ctx, desiredState, stateStringForm, JALDB_RTYPE_AUDIT, "audit"));
			status || (status = mark(ctx, desiredState, stateStringForm, JALDB_RTYPE_LOG, "log"));
			break;
		// Unreachable
		default:
			status = JALDB_E_INVAL;
	}
	return status;
}

jaldb_context* setup_jal()
{
	jaldb_context* ctx = jaldb_context_create();
	enum jaldb_flags db_flags;
	db_flags = JDB_NONE;

	enum jaldb_status ret = jaldb_context_init(ctx, config.db_home.c_str(), db_flags);
	if (ret != 0)
	{
		std::cout << "Failed to initialize jaldb_context with status: " << ret << std::endl;
		return NULL;
	}
	return ctx;
}

static error_t parse_opt(int key_in,
		char *arg, __attribute__ ((unused)) struct argp_state *state)
{
	switch (key_in)
	{
		// Command to update "mark" records
		case 'm':
			// Mark unsent
			if(0 == strcmp(arg, "unsent") || 0 == strcmp(arg, "u"))
			{
				config.operation = MarkOperation::UNSENT;
			}
			else if(0 == strcmp(arg, "sent") || 0 == strcmp(arg, "s"))
			{
				config.operation = MarkOperation::SENT;
			}
			else if(0 == strcmp(arg, "sync") || 0 == strcmp(arg, "y"))
			{
				config.operation = MarkOperation::SYNC;
			}
			else
			{
				argp_failure(state, 1, 0, "unknown flag type");
				argp_usage(state);
			}
			break;
		case 'h':
			config.db_home = arg;
			break;
		case 't':
			if(0 == strcmp(arg, "journal") || 0 == strcmp(arg, "j"))
			{
				config.recordSelection = RecordSelection::JOURNAL;
			}
			else if(0 == strcmp(arg, "audit") || 0 == strcmp(arg, "a"))
			{
				config.recordSelection = RecordSelection::AUDIT;
			}
			else if(0 == strcmp(arg, "log") || 0 == strcmp(arg, "l"))
			{
				config.recordSelection = RecordSelection::LOG;
			}
			else if(0 == strcmp(arg, "all") || 0 == strcmp(arg, "z"))
			{
				config.recordSelection = RecordSelection::ALL;
			}
			else
			{
				argp_failure(state, 1, 0, "unknown record type");
				argp_usage(state);
			}
			break;
		case ARGP_KEY_END:
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
