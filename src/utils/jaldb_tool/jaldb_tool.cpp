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
	{"show_times", 's', NULL, 0,
		"show timestamps, default: false", 0},
	#ifdef JALDB_TYPE_BDB
	{"run-db_recover", 'r', NULL, 0,
		"run db_recover before opening DB, default: false", 0},
	#endif
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

struct StatContainer{
	JaldbStat stats;
	enum jaldb_rec_type type;
	bool show;

	time_t latest = 0;
	time_t earliest = 0;
	time_t diff_time = 0;
};

struct Config
{
	RecordSelection recordSelection = RecordSelection::LOG;
	MarkOperation operation = MarkOperation::NONE;
	bool run_db_recover = false;
	std::string db_home = std::string("testdb");
	bool show_times = false;
} config;

jaldb_context* setup_jal(void);
enum jaldb_status update_flags(
	jaldb_context* ctx,
	MarkOperation op,
	RecordSelection rSelect);
void print_headers();
void print_row(StatContainer& s);
void print_time_headers();
void print_time_row(StatContainer& s);

int byte_swapped = 0;

int main(int argc, char **argv)
{
	// Parse command line options and populate global Config
	if(0 != argp_parse(&argp, argc, argv, 0, 0, NULL))
	{
		std::cout << "ARGP_ERR_UNKNOWN " << ARGP_ERR_UNKNOWN << std::endl;
	}

	// Create jaldb_context or exit
	jaldb_context* ctx = setup_jal();
	if(NULL == ctx) {
		return -1;
	}

	// If an update operation has been requested, perform the update now
	if(JALDB_OK != update_flags(ctx, config.operation, config.recordSelection))
	{
		return -1;
	}

	// Create storage for stats to be returned from get_stats
	std::vector<StatContainer> dbStats =
	{
		{ {}, JALDB_RTYPE_JOURNAL, false},
		{ {}, JALDB_RTYPE_AUDIT, false},
		{ {}, JALDB_RTYPE_LOG, false},
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

	print_headers();

	for (auto & statContainer : dbStats)
	{
		if(!statContainer.show) {
			continue;
		}
		enum jaldb_status status = get_stats(ctx, statContainer.stats, statContainer.type);
		if (JALDB_OK != status)
		{
			std::cout << "Failed to get db stats with error code: " << status << std::endl;
			jaldb_context_destroy(&ctx);
			return status;
		}
		print_row(statContainer);
	}

	// Finished with the context
	jaldb_context_destroy(&ctx);

	if (config.show_times)
	{
		print_time_headers();
		time_t min_time = 0;
		time_t max_time = 0;
		int counter = 0;
		for (auto & statContainer : dbStats)
		{
			if(!statContainer.show) {
				continue;
			}
			statContainer.stats.latest_time = statContainer.stats.latest_time.substr(0, 19);
			statContainer.stats.earliest_time = statContainer.stats.earliest_time.substr(0, 19);

			//2025-02-20T14:28:46.198517
			std::string format = "%Y-%m-%dT%H:%M:%S";

			struct tm latestStruct;
			latestStruct.tm_isdst = 0;
			strptime(statContainer.stats.latest_time.c_str(), format.c_str(), &latestStruct);
			struct tm earliestStruct;
			earliestStruct.tm_isdst = 0;
			strptime(statContainer.stats.earliest_time.c_str(), format.c_str(), &earliestStruct);
			statContainer.latest = mktime(&latestStruct);
			statContainer.earliest = mktime(&earliestStruct);
			statContainer.diff_time = difftime(statContainer.latest, statContainer.earliest);

			print_time_row(statContainer);

			++counter;
			if (counter == 1)
			{
				min_time = statContainer.earliest;
				max_time = statContainer.latest;
			}
			else
			{
				if (statContainer.earliest < min_time)
				{
					min_time = statContainer.earliest;
				}
				if (statContainer.latest > max_time)
				{
					max_time = statContainer.latest;
				}
			}
		}
		time_t total_time = 0;
		total_time = max_time - min_time;
		int hours = (total_time / 3600);
		int minutes = (total_time % 3600) / 60;
		int seconds = total_time % 60;
		std::cout << std::endl << "Total Time ";
		std::cout << std::setw(2) << std::setfill('0') << hours << ":";
		std::cout << std::setw(2) << std::setfill('0') << minutes << ":";
		std::cout << std::setw(2) << std::setfill('0') << seconds << std::endl << std::endl;
	}

	return 0;
}

void print_headers()
{
	std::cout << std::endl << "\tDatabase Home " << config.db_home << std::endl;
	std::cout << "-------\t-------\t-------\t-------\t-------\t-------\t-------"<< std::endl;
	std::cout << "db name\t count \t unsent\t  sent \tsynced \tconfirm\tfailed "<< std::endl;
	std::cout << "-------\t-------\t-------\t-------\t-------\t-------\t-------"<< std::endl;
}

void print_time_headers()
{
	std::cout << "-------\t-------------------\t--------------------\t----------"<< std::endl;
	std::cout << "db name\t    first_time     \t      last_time     \tdiff_time" << std::endl;
	std::cout << "-------\t-------------------\t--------------------\t---------- "<< std::endl;
}

void print_time_row(StatContainer& s){
	switch (s.type)
	{
		case JALDB_RTYPE_JOURNAL:
			std::cout << "journal\t";
			break;
		case JALDB_RTYPE_AUDIT:
			std::cout << "audit\t";
			break;
		case JALDB_RTYPE_LOG:
			std::cout << "log\t";
			break;
		case JALDB_RTYPE_UNKNOWN:
			std::cout << "unknown\t";
			break;
	}

	std::cout << s.stats.earliest_time << "\t" << s.stats.latest_time << "\t";
	int hours = (s.diff_time/3600);
	int minutes = (s.diff_time % 3600) / 60;
	int seconds = s.diff_time % 60;
	std::cout << std::setw(2) << std::setfill('0') << hours << ":";
	std::cout << std::setw(2) << std::setfill('0') << minutes << ":";
	std::cout << std::setw(2) << std::setfill('0') << seconds << std::endl;
}

void print_row(StatContainer& s)
{
	switch(s.type)
	{
		case JALDB_RTYPE_JOURNAL:
			std::cout << "journal\t";
			break;
		case JALDB_RTYPE_AUDIT:
			std::cout << "audit\t";
			break;
		case JALDB_RTYPE_LOG:
			std::cout << "log\t";
			break;
		case JALDB_RTYPE_UNKNOWN:
			std::cout << "unknown\t";
			break;
	}

	std::cout << s.stats.count << "\t";
	std::cout << s.stats.not_sent_count << "\t";
	std::cout << s.stats.sent_count << "\t";
	std::cout << s.stats.synced_count << "\t";
	std::cout << s.stats.confirmed_count << "\t";
	std::cout << s.stats.failed_count << std::endl;
}

// Helper to avoid repeating this logic twice in update_flags
static enum jaldb_status mark(jaldb_context* ctx, enum jaldb_sync_stat desiredState, std::string stateStringForm, enum jaldb_rec_type type, std::string typeStringForm)
{
	std::cout << "Marking records of type: " << typeStringForm << " with state:  " << stateStringForm << std::endl;
	enum jaldb_status status = mark_all_records(ctx, type, desiredState);
	if(JALDB_OK != status)
	{
		std::cout << "Jaldb Status Code: " << status << " encountered while updating record of type: " << typeStringForm << " to state: " << stateStringForm << std::endl;
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

	#ifdef JALDB_TYPE_BDB
	if (config.run_db_recover)
	{
		std::cout << "Setting DB_RECOVER flag." << std::endl;
		db_flags = (enum jaldb_flags)(JDB_NONE | JDB_DB_RECOVER);
	}
	else
	{
		db_flags = JDB_NONE;
	}
	#else
		db_flags = JDB_NONE;
	#endif
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
		case 's':
			config.show_times = true;
			break;
		#ifdef JALDB_TYPE_BDB
		case 'r':
			config.run_db_recover = true;
			break;
		#endif
		case ARGP_KEY_END:
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
