/*
 * @file jaldb_tool.cpp
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

#include <getopt.h>
#include <iostream>
#include <map>
#include <jalop/jal_version.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <db.h>
#include <jaldb_serialize_record.h>
#include <jaldb_record.h>
#include <jaldb_segment.h>
#include "jaldb_context.h"
#include "jaldb_context.hpp"
#include "jaldb_record_dbs.h"

#include <argp.h>
#include <vector>
using namespace std;

jaldb_context * ctx;

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
	{"show-confirmed", 'c', NULL, 0,
		"show confirmed count, default: testdb", 0},
	{"run-db_recover", 'r', NULL, 0,
		"run db_recover before opening DB, default: false", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

class Config
{
public:

	Config()
	{
		record_type = "log";
		run_db_recover = false;
		db_home = "testdb";
		flag = "";
		show_confirmed = false;
	}
	string record_type;
	string flag;
	bool run_db_recover;
	bool show_confirmed;
	string db_home;
};
Config config;

DB * jaldb;
DB * filedb;
DBT key, data;
DBC * jalcursor;
DBC * filecursor;
DB_ENV *env = NULL;
int counter = 0;
int ret = 0;

class DB_Stat
{
public:

	DB_Stat()
	{
		count = 0;
		not_sent_count = 0;
		sent_count = 0;
		synced_count = 0;
		confirmed_count = 0;
		failed_count = 0;
	}
	string db_name;
	string db_location;
	int count;
	int not_sent_count;
	int sent_count;
	int synced_count;
	int confirmed_count;
	int failed_count;
	enum jaldb_rec_type record_type;
};
DB_Stat journal_stat;
DB_Stat audit_stat;
DB_Stat log_stat;
vector<DB_Stat> db_stats;

void count_stats(int byte_swapped, uint8_t * data, int size, DB_Stat * stat);
void setup_jal(void);
int mark_sent(string nonce, jaldb_rec_type rt, int mark_sent);
int mark_synced(string nonce, jaldb_rec_type rt);
void destroy_jal(void);
void setup_stats();
void update_flags(unsigned int x);
void print_headers();
void print_row(unsigned int x);

int byte_swapped = 0;

int main(int argc, char **argv)
{
	int err = argp_parse(&argp, argc, argv, 0, 0, NULL);
	if (err != 0)
	{
		cout << "ARGP_ERR_UNKNOWN " << ARGP_ERR_UNKNOWN << endl;
	}
	
	memset(&key, 0, sizeof (DBT));
	memset(&data, 0, sizeof (DBT));
	setup_jal();
	setup_stats();

	print_headers();
	
	unsigned int x;
	for (x = 0; x < db_stats.size(); ++x)
	{
		if (db_stats[x].db_name.compare("log")==0){
			jaldb = ctx->log_dbs->primary_db;
		}
		else if (db_stats[x].db_name.compare("audit")==0){
			jaldb = ctx->audit_dbs->primary_db;
		}
		else if (db_stats[x].db_name.compare("journal")==0){
			jaldb = ctx->journal_dbs->primary_db;
		}
		if (jaldb==NULL)
		{
			cout << "db null: " << db_stats[x].db_name << endl;
			destroy_jal();
			exit(1);
		}
		ret = jaldb->cursor(jaldb, NULL, &jalcursor, 0);
		if (ret != 0)
		{
			cout << "Error getting cursor for " << db_stats[x].db_location
					<< " return: " << ret << endl;
			destroy_jal();
			exit(1);
		}
		ret = jaldb->get_byteswapped(jaldb, &byte_swapped);
		if (ret != 0)
		{
			cout << "Error getting byte swapped for " << db_stats[x].db_location
					<< " return: " << ret << endl;
			destroy_jal();
			exit(1);
		}
		int wret;
		if ((config.flag.size() > 0) && (config.record_type.compare("all") == 0 ||
				config.record_type.compare(db_stats[x].db_name) == 0))
		{
			update_flags(x);
		}
		
		ret = jaldb->cursor(jaldb, NULL, &jalcursor, 0);
		if(jalcursor==NULL)
		{
			cout << "jalcursor null" << endl;
		}
		if (ret != 0)
		{
			cout << "Error getting cursor for "
					<< db_stats[x].db_location << " return: " << ret << endl;
			destroy_jal();
			exit(1);
		}
		while ((wret = jalcursor->get(jalcursor, &key, &data, DB_NEXT)) == 0)
		{
			count_stats(byte_swapped, (uint8_t *) data.data,
					data.size, &db_stats[x]);
		}
		print_row(x);
	}
	
	destroy_jal();

	return 0;
}
void print_headers()
{
	cout << "-------\t-------\t-------\t-------\t-------\t";
	if(config.show_confirmed)
	{
		cout << "-------\t";
	}
	cout << "-------" << endl;
	cout << "db name\t count \t unsent\t  sent \tsynced \t";
	if(config.show_confirmed)
	{
		cout << "confirm\t";
	}
	cout << "failed " << endl;
	cout << "-------\t-------\t-------\t-------\t-------\t";
	if(config.show_confirmed)
	{
		cout << "-------\t";
	}
	cout << "-------" << endl;
}
void print_row(unsigned int x)
{
	cout << db_stats[x].db_name << "\t";
	cout << db_stats[x].count << "\t";
	cout << db_stats[x].not_sent_count << "\t";
	cout << db_stats[x].sent_count << "\t";
	cout << db_stats[x].synced_count << "\t";
	if(config.show_confirmed)
	{
		cout << db_stats[x].confirmed_count << "\t";
	}
	cout << db_stats[x].failed_count << endl;
}
void update_flags(unsigned int x)
{
	int cret;
	db_create(&filedb, NULL, 0);
	ret = filedb->open(filedb, NULL, db_stats[x].db_location.c_str(), NULL,
	DB_BTREE, DB_CREATE, 0);
	ret = filedb->cursor(filedb, NULL, &filecursor, 0);
	if (ret != 0)
	{
		cout << "Error getting cursor for " << db_stats[x].db_location
				<< " return: " << ret << endl;
		filedb->close(filedb, 0);
		exit(1);
	}

	if (config.flag.compare("unsent") == 0)
	{
		cout << "Marking flag " << config.flag << " for "
				<< db_stats[x].db_name << endl;
		while ((cret = filecursor->get(filecursor, &key, &data, DB_NEXT)) == 0)
		{
			ret = mark_sent(
					(char*) key.data, db_stats[x].record_type, 0);
			if (ret != 0)
			{
				break;
			}
		}
	}
	else if (config.flag.compare("sent") == 0)
	{
		cout << "Marking flag " << config.flag << " for "
				<< db_stats[x].db_name << endl;
		while ((cret = filecursor->get(filecursor, &key, &data, DB_NEXT)) == 0)
		{
			ret = mark_sent(
					(char*) key.data, db_stats[x].record_type, 0);
			ret = mark_sent(
					(char*) key.data, db_stats[x].record_type, 1);
			if (ret != 0)
			{
				break;
			}
		}
	}
	else if (config.flag.compare("synced") == 0)
	{
		cout << "Marking flag " << config.flag << " for "
				<< db_stats[x].db_name << endl;
		while ((cret = filecursor->get(filecursor, &key, &data, DB_NEXT)) == 0)
		{
			ret = mark_sent(
					(char*) key.data, db_stats[x].record_type, 0);
			ret = mark_sent(
					(char*) key.data, db_stats[x].record_type, 1);
			ret = mark_synced(
					(char*) key.data, db_stats[x].record_type);
			if (ret != 0)
			{
				break;
			}
		}
	}

	if (ret != 0)
	{
		cout << "Error marking flag " << config.flag << " for "
				<< db_stats[x].db_location
				<< " return: "
				<< ret << endl;
		destroy_jal();
		exit(1);
	}
}
void setup_jal()
{
	ctx = jaldb_context_create();
	enum jaldb_flags db_flags;
	if (config.run_db_recover)
	{
		cout << "Setting DB_RECOVER flag." << endl;
		db_flags = (enum jaldb_flags)(JDB_NONE | JDB_DB_RECOVER);
	}
	else
	{
		db_flags = JDB_NONE;
	}
	ret = jaldb_context_init(ctx, config.db_home.c_str(), db_flags);
	if (ret != 0)
	{
		cout << "Setup jal: " << config.db_home << " ret: " << ret << endl;
		exit(1);
	}
}

int mark_sent(string nonce, jaldb_rec_type rt, int mark_sent)
{
	return jaldb_mark_sent(ctx, rt, (const char *) nonce.c_str(), mark_sent);
}

int mark_synced(string nonce, jaldb_rec_type rt)
{
	return jaldb_mark_synced(ctx, rt, (const char *) nonce.c_str());
}

void destroy_jal()
{
	jaldb_context_destroy(&ctx);
}

void setup_stats()
{
	journal_stat.db_name = "journal";
	journal_stat.db_location = config.db_home + "/journal_records.db";
	journal_stat.record_type = JALDB_RTYPE_JOURNAL;
	audit_stat.db_name = "audit";
	audit_stat.db_location = config.db_home + "/audit_records.db";
	audit_stat.record_type = JALDB_RTYPE_AUDIT;
	log_stat.db_name = "log";
	log_stat.db_location = config.db_home + "/log_records.db";
	log_stat.record_type = JALDB_RTYPE_LOG;
	db_stats.push_back(journal_stat);
	db_stats.push_back(audit_stat);
	db_stats.push_back(log_stat);
}

void count_stats(int byte_swapped_in, uint8_t * data_in, int size, DB_Stat * stat)
{
	struct jaldb_record * record = NULL;
	int jal_ret = jaldb_deserialize_record(byte_swapped_in, data_in, size, &record);
	if (jal_ret != 0)
	{
		stat->failed_count++;
		return;
	}
	if (record->synced == JALDB_NOT_SENT)
	{
		stat->not_sent_count++;
	}
	if (record->synced == JALDB_SENT)
	{
		stat->sent_count++;
	}
	if (record->synced == JALDB_SYNCED)
	{
		stat->synced_count++;
	}
	if(record->confirmed && (int)record->confirmed == 1){
		stat->confirmed_count++;
		//cout << "confirmed: " << (int)record->confirmed << endl;
	}
	jaldb_destroy_record(&record);
	stat->count++;
	
}

static error_t parse_opt(int key_in,
		char *arg, __attribute__ ((unused)) struct argp_state *state)
{
	switch (key_in)
	{
		case 'm':
			config.flag = arg;
			if (config.flag.compare("unsent") == 0 ||
					config.flag.compare("sent") == 0 ||
					config.flag.compare("synced") == 0)
			{
				break;
			}
			if (config.flag.compare("u") == 0 ||
					config.flag.compare("s") == 0 ||
					config.flag.compare("y") == 0)
			{

				if (config.flag.compare("u") == 0)
				{
					config.flag = "unsent";
				}
				else if (config.flag.compare("s") == 0)
				{
					config.flag = "sent";
				}
				else if (config.flag.compare("y") == 0)
				{
					config.flag = "synced";
				}
				break;
			}
			argp_failure(state, 1, 0, "unknown flag type");
			argp_usage(state);
			break;
		case 'h':
			config.db_home = arg;
			break;
		case 't':
			config.record_type = arg;
			if (config.record_type.compare("journal") == 0 ||
					config.record_type.compare("audit") == 0 ||
					config.record_type.compare("log") == 0 ||
					config.record_type.compare("all") == 0)
			{
				break;
			}
			if (config.record_type.compare("j") == 0 ||
					config.record_type.compare("a") == 0 ||
					config.record_type.compare("l") == 0 ||
					config.record_type.compare("z") == 0)
			{
				if (config.record_type.compare("j") == 0)
				{
					config.record_type = "journal";
				}
				else if (config.record_type.compare("a") == 0)
				{
					config.record_type = "audit";
				}
				else if (config.record_type.compare("l") == 0)
				{
					config.record_type = "log";
				}
				else if (config.record_type.compare("z") == 0)
				{
					config.record_type = "all";
				}
				break;
			}
			argp_failure(state, 1, 0, "unknown record type");
			argp_usage(state);
			break;
		case 'r':
			config.run_db_recover = true;
			break;
		case 'c':
			config.show_confirmed = true;
			break;
		case ARGP_KEY_END:
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

