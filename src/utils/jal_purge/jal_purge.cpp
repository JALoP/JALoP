/**
 * @file
 *
 * @brief This file contains the source for jal_purge
 *
 * ### LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012-2014 Tresys Technology LLC, Columbia, Maryland, USA
 *
 * This software was developed by Tresys Technology LLC
 * with U.S. Government sponsorship.
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

#include <argp.h>
#include <iostream>
#include <algorithm>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string/join.hpp>
#include <fstream>
#include <map>
#include <jalop/jal_version.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "jaldb_context.hpp"
#include "jaldb_purge.hpp"
#include "jaldb_record_dbs.h"
#include "jaldb_utils.h"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_record.h"
#include "jaldb_segment.h"
#include "jaldb_config.h"

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

using namespace std;

enum purge_action {
	JAL_PURGE_KEEP,
	JAL_PURGE_DELETE,
	JAL_PURGE_FORCE,
};

const char *send_str[] = { "UNSENT", " SENT ", "SYNCED" };
const char *recv_str[] = { "UNCONF", " CONF " };
const char *action_str[] = {"Keep  ", "Delete", "Force "};
static int exiting = 0;

const int MAX_PURGE_BATCH_SIZE = 10000;

//These are the jal processes to check if running before doing a db compact operation
const std::vector<std::string> jal_process_list = {"jal-local-store", "jald", "jal_subscribe", "jal_sub_cpp"};

static struct global_args_t {
	int del;
	int force;
	int verbose;
	int detail;
	int skip_clean;
	int compact;
	int skip_process_check;
	char *compact_path;
	char *batch_size;
	char *nonce;
	list<string> uuids;
	char type;
	char *before;
	char *home;
} global_args;

static void global_args_free();

// argp
const char *argp_program_version = jal_version_as_string();
const char *argp_program_bug_address = 0;
static char args_doc[] = "[uuid(s)]";
static char doc[] =
	"jal_purge - JALoP database purge utility.";
static error_t parse_opt(int key, char *arg, struct argp_state *state);
static struct argp_option options[] = {
	{"type", 't', "T", 0,
		"Specify the type of JAL record.  'T' may be 'j', 'a', or 'l' for journal, audit, or logging, respectively. When used with the '-u' or '--uuid' options, checks the timestamp, rather than the sequence ID, for record removal.", 0},
	{"before", 'b', "B", 0,
		"Remove all records with a timestamp before or equal to B. The timestamp must be specified as an XML schema date, time, or dateTime string. The xmlschema-2 document describes these formats. Only valid if no uuids are specified.", 0},
	{"delete", 'd', NULL, 0,
		"Delete the records. The jal_purge tool does not remove records that the JALoP Network Store has not sent to at least one JALoP Network Store.", 0},
	{"force", 'f', NULL, 0,
		"When '-d' is given, force the deletion of records even when the JALoP Network Store has not sent them to at least one JALoP Network Store.  When given without '-d', this will report the records that would be deleted.", 0},
	{"compact", 'c', NULL, 0,
		"Compact the databases associated to the JAL record type (j/a/l) passed via -t and return empty pages to the filesystem.", 0},
	{"batch-size", 'e', "E", 0,
			"Specify the the number of records to purge per transaction. The default is 10000 records if not specified. The minimum value is 1 and maximum is 10000.", 0},
	{"compact-path", 's', "S", 0,
			"Specify path of where the temporary LMDB database is copied while compacting.", 0},
	{"skip-process-check", 'a', NULL, 0,
			"This skips the JALoP process running check on compact.  WARNING!! Using this setting can result in DB corruption if compact is performed against a database that is in use.", 0},
	{"home", 'h', "H", 0, "Specify the root of the JALoP database, defaults to /var/lib/jalop/db.", 0},
	{"verbose", 'v', NULL, 0, "Output the UUID for each deleted record.", 0},
	{"detail", 'x', NULL, 0, "Report detailed information about the records jal_purge is reviewing for deletion. This reports the action to be taken (Delete, Forced Delete, Keep), the inbound state (Confirmed or Unconfirmed), the outbound state (Unsent, Sent, Synced), the local insertion timestamp, and the local nonce for each record.", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

static int setup_signals();
static void sig_handler(int sig);

extern "C" enum jaldb_iter_status iter_cb(const char *nonce, struct jaldb_record *rec, void *up);

bool isNotNumber(char c)
{
    return !(isdigit(c));
}

bool isNumber(const std::string& currDirName)
{
    return find_if(currDirName.begin(), currDirName.end(), isNotNumber) == currDirName.end();
}

bool checkForRunningProcess(const std::vector<std::string> &procNames, bool &isRunning)
{
	isRunning = false;

	std::string dirPath = "/proc";
	try
	{
		if (!boost::filesystem::exists(dirPath) || !boost::filesystem::is_directory(dirPath)) {
			fprintf(stderr, "ERROR: Failed to check for running JALoP process.\n");
			return false;
		}

		//Loop through all process id dirs in /proc and check if process listed in procName vector is running
		boost::filesystem::directory_iterator end_itr;
		for (boost::filesystem::directory_iterator dir_itr(dirPath); dir_itr != end_itr; ++dir_itr)
		{
			//Only process number directories
			std::string currDirName = dir_itr->path().filename().string();

			if (boost::filesystem::is_directory(dir_itr->path()) && isNumber(currDirName))
			{
				//Read contents of comm file in process subdir and check if it is one of the process names
				//provided in the procNames vector
				std::string currCommFile = dirPath + "/" + currDirName + "/comm";
				std::ifstream commFile(currCommFile);

				if (commFile.is_open())
				{
					std::string currCommand;
					while(std::getline(commFile, currCommand))
					{
						if (std::find(procNames.begin(), procNames.end(), currCommand) != procNames.end())
						{
							isRunning = true;
							break;
						}
					}

					commFile.close();

					if (true == isRunning)
					{
						break;
					}
				}
			}
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: Failed to check for running JALoP process: %s\n", err.what());
		return false;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: Failed to check for running JALoP process - unknown error occurred\n");
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	enum jaldb_status dbret = (enum jaldb_status)-1;
	enum jaldb_rec_type type = JALDB_RTYPE_UNKNOWN;
	jaldb_context *ctx = NULL;
	int err = 0;
	enum jaldb_flags jdb_flags = JDB_LMDB_PERFORMANCE_LEVEL2;
	std::string database_option = std::string(JDB_LMDB_PERFORMANCE_LEVEL2_STR);
	int map_size = DEFAULT_LMDB_MAP_SIZE;
	jaldb_config *jdb_config = NULL;
	enum jaldb_config_status jcs = JALDB_CONFIG_OK;

	// Perform signal hookups
	if ( 0 != setup_signals()) {
		goto out;
	}

	err = argp_parse(&argp, argc, argv, 0, 0, NULL);
	if(0 != err) {
		fprintf(stderr, "ERROR: Cannot parse command line arguments.\n");
		goto out;
	}
	if ((!global_args.uuids.empty() || global_args.before) && !global_args.type) {
		fprintf(stderr, "ERROR: -t required if -b specified.\n");
		goto out;
	}

	ctx = jaldb_context_create();
	if (!ctx) {
		fprintf(stderr, "Failed to create jaldb context\n");
		goto out;
	}

	if (global_args.compact) {
		//Ensure compact path was provided
		if (NULL == global_args.compact_path)
		{
			fprintf(stdout, "Compact path (-s) is required when compacting the database (-c)\n");
			global_args_free();
			jaldb_context_destroy(&ctx);
			return -1;
		}

		ctx->db_root = new std::string(global_args.home);
		ctx->compact_path = new std::string(global_args.compact_path);
	}
	else
	{
		//If not compact, disallow compact only args
		if (NULL != global_args.compact_path)
		{
			fprintf(stdout, "ERROR: Compact path (-s) is only valid when when compacting the database (-c)\n");
			global_args_free();
			jaldb_context_destroy(&ctx);
			return -1;
		}
	}

	//Sets batch_size if specified, otherwise default to no batching (1)
	ctx->batch_size = 1;

	if (NULL != global_args.batch_size)
	{
		std::string batch_size_str(global_args.batch_size);
		long curr_batch_size = 1;
		size_t pos;
		try
		{
			curr_batch_size = std::stol(batch_size_str, &pos);
		}
		catch(const std::invalid_argument& ia)
		{
			fprintf(stderr, "ERROR: Invalid batch_size argument.\n");
			goto out;
		}
		catch(const std::out_of_range& oor)
		{
			fprintf(stderr, "ERROR: batch_size argument out of range.\n");
			goto out;
		}

		if (curr_batch_size < 1)
		{
			fprintf(stderr, "ERROR: batch_size argument must be not be less than 1.\n");
			goto out;
		}

		ctx->batch_size = curr_batch_size;
	}

	if (global_args.compact) {
		//Ensure that jalop processes are not running (if skip process check not true)
		if (1 != global_args.skip_process_check)
		{
			bool isRunning = false;
			if (!checkForRunningProcess(jal_process_list, isRunning))
			{
				//Error occurred checking for process name, and error was printed
				//in method above.
				global_args_free();
				jaldb_context_destroy(&ctx);
				return -1;
			}

			if (true == isRunning)
			{
				std::string jal_process_list_str =  boost::algorithm::join(jal_process_list, ",");
				fprintf(stdout, "ERROR: compact cannot be performed due to one or more of the following JALoP processes are running: %s \n", jal_process_list_str.c_str());
				global_args_free();
				jaldb_context_destroy(&ctx);
				return -1;
			}
		}
	}
	else
	{
		if (1 == global_args.skip_process_check)
		{
			fprintf(stdout, "ERROR: Skip process check (-a) is only valid when when compacting the database (-c)\n");
			global_args_free();
			jaldb_context_destroy(&ctx);
			return -1;
		}
	}

	//Attempts to load optional LMDB_CONFIG file in db_root
	//If present, this will override the lmdb performance level
	//and lmdb map size, otherwise default values will be used.
	jcs = get_jaldb_config(global_args.home, &jdb_config);
	if (jcs != JALDB_CONFIG_OK && jcs != JALDB_CONFIG_E_NOTFOUND) {
		global_args_free();
		jaldb_context_destroy(&ctx);
		return -1;
	}

	//Only override map size if present in config
	if (jcs != JALDB_CONFIG_E_NOTFOUND)
	{
		if (jdb_config->map_size != 0)
		{
			map_size = jdb_config->map_size;
		}

		//Only override database option if present in config
		if (NULL != jdb_config->database_option)
		{
			jdb_flags = jdb_config->jdb_flags;
			database_option = std::string(jdb_config->database_option);
		}
		free_jaldb_config(&jdb_config);
	}

	dbret = jaldb_context_init(ctx, global_args.home, jdb_flags, map_size);
	if (JALDB_OK != dbret) {
		fprintf(stderr, "Failed to initialize jaldb context\n");
		goto out;
	}

	switch (global_args.type) {
	case 'j':
		type = JALDB_RTYPE_JOURNAL;
		break;
	case 'a':
		type = JALDB_RTYPE_AUDIT;
		break;
	case 'l':
		type = JALDB_RTYPE_LOG;
		break;
	default:
		goto out;
	}

	if (global_args.detail) {
		// Output the new detailed format
		printf("\nJAL_PURGE\n");
		printf("============\n");
		printf("SETTINGS:\n");

		if (type == JALDB_RTYPE_JOURNAL ) {
			printf("Journal records\n");
		} else if (type == JALDB_RTYPE_AUDIT) {
			printf("Audit records\n");
		} else if (type == JALDB_RTYPE_LOG) {
			printf("Log records\n");
		}

		if (global_args.del) {
			printf("Delete\n");
		} else {
			printf("Preview (no deletion)\n");
		}

		if (global_args.force) {
			printf("Synced + unsynced records\n");
		} else {
			printf("Synced records only\n");
		}

		if (global_args.batch_size)
		{
			printf("Batch Size: %s\n", global_args.batch_size);
		}
		else
		{
			printf("Batch Size: %d\n", MAX_PURGE_BATCH_SIZE);
		}

		printf("Database Option: %s\n", database_option.c_str());
		printf("LMDB Map Size (GB): %d\n", map_size);

	} else {
		// Otherwise output the old format that works with the test harness
		if (global_args.del) {
			cout << "Processing the following candidate records:" << endl;
		} else {
			cout << "Would process the following candidate records:" << endl;
		}
	}

	if (!global_args.uuids.empty()) {
		struct jaldb_record *rec = NULL;
		uuid_t uuid;
		char *nonce = NULL;
		list<string>::iterator iter;
		for(iter = global_args.uuids.begin(); iter != global_args.uuids.end(); iter++) {
#ifdef sun
			char * uuid_string = jal_strdup(iter->c_str());
			if (0 != uuid_parse(uuid_string, uuid)) {
				free(uuid_string);
#else
			if (0 != uuid_parse(iter->c_str(), uuid)) {
#endif
				fprintf(stderr, "ERROR: Invalid UUID: %s \n", iter->c_str() );
				goto out;
			}
#ifdef sun
			free(uuid_string);
#endif
			dbret = jaldb_get_record_by_uuid(ctx, type, uuid, &nonce, &rec);
			if (dbret != 0) {
				fprintf(stderr,"Cannot get record for UUID: %s\n", iter->c_str());
				// Treat UUID not found as a non-error condition
				dbret = JALDB_OK;
			} else {
				/* Inbound: records should be confirmed. Outbound: records should be synced. */
				/* Force flag causes sync flag to be ignored. */

				enum purge_action record_action = JAL_PURGE_KEEP;

				if (rec->confirmed && (rec->synced == JALDB_SYNCED)) {
					record_action = JAL_PURGE_DELETE;
				} else if (rec->confirmed && (rec->synced != JALDB_SYNCED) && global_args.force) {
					record_action = JAL_PURGE_FORCE;
				} else {
					record_action = JAL_PURGE_KEEP;
				}

				// If the detail flag is set, output the new detailed format, otherwise use the old format to prevent test harness from breaking
				if (global_args.detail) {
					// Print status of all records whether to be deleted or not
					if (global_args.del) {
						printf("%s %s %s %26s %s\n", action_str[record_action], recv_str[int(rec->confirmed)], send_str[int(rec->synced)], rec->timestamp, nonce);
					}
					else {
						printf("Preview: %s %s %s %26s %s\n", action_str[record_action], recv_str[int(rec->confirmed)], send_str[int(rec->synced)], rec->timestamp, nonce);
					}
				} else {
					printf("UUID: %s ", iter->c_str());
				}

				// Remove the record.
				if (global_args.del && rec->confirmed && (global_args.force || rec->synced == JALDB_SYNCED)) {
					dbret = jaldb_remove_record(ctx, type, nonce);
					if (dbret != 0) {
						fprintf(stderr, "ERROR: Cannot remove record: %s\n", nonce);
					} else {
						printf("Deleted\n");
					}
				} else {
					printf("Kept\n");
				}

				jaldb_destroy_record(&rec);
				free(nonce);
				nonce = NULL;
			}

			if (exiting) {
				break;
			}
		}
	} else if (global_args.before) {
		if (global_args.detail) {
			printf("Records before: %s\n\n", global_args.before);
		}
		dbret = jaldb_iterate_by_timestamp_purge(ctx, type, global_args.before, iter_cb, &global_args, exiting);
		goto out;
	} else {
		fprintf(stderr, "ERROR: Purging without a before time or uuid specified is currently not supported.\n");
		dbret = (enum jaldb_status)-1;
		goto out;
		// TODO: No arguments/filter specified
	}

out:
	if (global_args.detail) {
		printf("\n");
	}

	jaldb_status rc = JALDB_OK;
	if (global_args.compact) {
		fprintf(stdout, "Running DB->compact\n");
		rc = jaldb_compact_dbs(ctx, type);

		if (JALDB_OK != rc) {
			fprintf(stderr, "ERROR: Compact failed on one or more databases.\n");
		}
	}

	free((char *)argp_program_version);
	global_args_free();
	jaldb_context_destroy(&ctx);

	if (JALDB_OK != dbret || JALDB_OK != rc) {
		return -1;
	}
}

extern "C" enum jaldb_iter_status iter_cb(const char *nonce, struct jaldb_record *rec, void *)
{

	/* Inbound: records should be confirmed. Outbound: records should be synced. */
	/* Force flag causes sync flag to be ignored. */

	enum purge_action record_action = JAL_PURGE_KEEP;
	enum jaldb_iter_status ret_val = JALDB_ITER_CONT;
	char action[8] = {0};

	if (rec->confirmed && (rec->synced == JALDB_SYNCED)) {
		record_action = JAL_PURGE_DELETE;
		ret_val = JALDB_ITER_REM;
		strcpy(action, "Deleted");
	} else if (rec->confirmed && (rec->synced != JALDB_SYNCED) && global_args.force) {
		record_action = JAL_PURGE_FORCE;
		ret_val = JALDB_ITER_REM;
		strcpy(action, "Deleted");
	} else {
		record_action = JAL_PURGE_KEEP;
		ret_val = JALDB_ITER_CONT;
		strcpy(action, "Kept");
	}
	// If the detail flag is set, output the new detailed format, otherwise use the old format to prevent test harness from breaking
	if (global_args.detail) {
		// Print status of all records whether to be deleted or not
		if (global_args.del) {
			printf("%s %s %s %26s %s\n", action_str[record_action], recv_str[int(rec->confirmed)], send_str[int(rec->synced)], rec->timestamp, nonce);
		}
		else {
			printf("Preview: %s %s %s %26s %s\n", action_str[record_action], recv_str[int(rec->confirmed)], send_str[int(rec->synced)], rec->timestamp, nonce);
		}
	} else if (0 != strcmp(action, "Deleted")) {
		printf("NONCE: %s %s\n", nonce, action);

		if (global_args.verbose) {
			char uuid[37]; // UUID are always 36 characters + the NULL terminator
			uuid_unparse(rec->uuid, uuid);
			printf("UUID: %s %s\n", uuid, action);
		}
	}


	// If delete flag was not set, force iterator to return continue
	if (!global_args.del) {
		ret_val = JALDB_ITER_CONT;
	}

	return ret_val;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
		case 't':
			if ('j' != *arg && 'a' != *arg && 'l' != *arg) {
				fprintf(stderr, "Invalid type\n");
				goto err_out;
			}
			global_args.type = *arg;
			break;
		case 'b':
			global_args.before = strdup(arg);
			break;
		case 'd':
			global_args.del = 1;
			break;
		case 'f':
			global_args.force = 1;
			break;
		case 'h':
			global_args.home = strdup(arg);
			break;
		case 's':
			global_args.compact_path = strdup(arg);
			break;
		case 'e':
			global_args.batch_size = strdup(arg);
			break;
		case 'a':
			global_args.skip_process_check = 1;
			break;
		case 'v':
			global_args.verbose = 1;
			break;
		case 'x':
			global_args.detail = 1;
			break;
		case 'c':
			global_args.compact = 1;
			break;
		case ARGP_KEY_ARG:
			global_args.uuids.push_front(string(arg));
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;

err_out:
	argp_usage(state);

	exit(-1);
}

static void global_args_free()
{
	free(global_args.before);
	free(global_args.home);
	free(global_args.compact_path);
	free(global_args.batch_size);
}

static int setup_signals()
{
        struct sigaction action_on_sig;
        action_on_sig.sa_handler = &sig_handler;
        sigemptyset(&action_on_sig.sa_mask);
        action_on_sig.sa_flags = 0;

        if (0 != sigaction(SIGABRT, &action_on_sig, NULL)) {
                fprintf(stderr, "failed to register SIGABRT.\n");
                goto err_out;
        }
        if (0 != sigaction(SIGTERM, &action_on_sig, NULL)) {
                fprintf(stderr, "failed to register SIGTERM.\n");
                goto err_out;
        }
        if (0 != sigaction(SIGINT, &action_on_sig, NULL)) {
                fprintf(stderr, "failed to register SIGINT.\n");
                goto err_out;
        }
        return 0;

err_out:
        return -1;
}

static void sig_handler(__attribute__((unused)) int sig)
{
	fprintf(stdout, "\nCaught SIGTERM - exiting...\n");
	exiting = 1;
}
