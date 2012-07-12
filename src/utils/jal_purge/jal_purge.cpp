/**
 * @file jal_purge.cpp This file contains the source for jal_purge
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <list>
#include <string>

#include <jalop/jal_version.h>
#include "jaldb_context.hpp"
#include "jaldb_purge.hpp"
#include "jaldb_status.h"
#include "jaldb_strings.h"

using namespace std;

static struct global_args_t {
	int del;
	int force;
	int verbose;
	char *sid;
	char *uuid;
	char type;
	char *before;
	char *home;
} global_args;

static void print_records_to_delete(list<jaldb_doc_info> &docs);
static void process_options(int argc, char **argv);
static void global_args_free();
static void usage();

int main(int argc, char **argv)
{
	enum jaldb_status dbret = (enum jaldb_status)-1;
	jaldb_context *ctx = NULL;
	list<jaldb_doc_info> files_to_remove;

	process_options(argc, argv);

	ctx = jaldb_context_create();
	if (!ctx) {
		fprintf(stderr, "Failed to create jaldb context\n");
		goto out;
	}

	dbret = jaldb_context_init(ctx, global_args.home, NULL, 0);
	if (JALDB_OK != dbret) {
		fprintf(stderr, "Failed to initialize jaldb context\n");
		goto out;
	}

	if (global_args.sid) {
		switch (global_args.type) {
		case 'j':
			dbret = jaldb_purge_journal_by_sid(ctx,
							global_args.sid, 
							files_to_remove,
							global_args.force,
							global_args.del);
			break;
		case 'a':
			dbret = jaldb_purge_audit_by_sid(ctx,
							global_args.sid,
							files_to_remove,
							global_args.force,
							global_args.del);
			break;
		case 'l':
			dbret = jaldb_purge_log_by_sid(ctx,
							global_args.sid,
							files_to_remove,
							global_args.force,
							global_args.del);
			break;
		default:
			break;
		}
	} else if (global_args.uuid) {
		switch (global_args.type) {
		case 'j':
			dbret = jaldb_purge_journal_by_uuid(ctx,
							global_args.uuid,
							files_to_remove,
							global_args.force,
							global_args.del);
			break;
		case 'a':
			dbret = jaldb_purge_audit_by_uuid(ctx,
							global_args.uuid,
							files_to_remove,
							global_args.force,
							global_args.del);
			break;
		case 'l':
			dbret = jaldb_purge_log_by_uuid(ctx,
							global_args.uuid,
							files_to_remove,
							global_args.force,
							global_args.del);
			break;
		default:
			break;
		}
	} else if (global_args.before) {
		cout << "Purging by timestamp currently not supported." << endl;
		dbret = (enum jaldb_status)-1;
		goto out;
		/*switch (global_args.type) {
		case 'j':
			dbret = jaldb_purge_journal_by_before(ctx,
							global_args.before,
							&files_to_remove,
							global_args.force,
							global_args.del);
			break;
		case 'a':
			dbret = jaldb_purge_audit_by_before(ctx,
							global_args.before,
							&files_to_remove,
							global_args.force,
							global_args.del);
			break;
		case 'l':
			dbret = jaldb_purge_log_by_before(ctx,
							global_args.before,
							&files_to_remove,
							global_args.force,
							global_args.del);
			break;
		default:
			break;
		}*/
	} else {
		cout << "Purging without a sid or uuid specified is currently not supported." << endl;
		dbret = (enum jaldb_status)-1;
		goto out;
		// TODO: No arguments/filter specified
	}
	print_records_to_delete(files_to_remove);

out:
	if (JALDB_OK != dbret) {
		fprintf(stderr, "Failed to purge records\n");
	}

	global_args_free();
	jaldb_context_destroy(&ctx);
	return dbret;
}

static void print_records_to_delete(list<jaldb_doc_info> &docs)
{
	if (docs.size() > 0) {
		if (global_args.del) {
			cout << "Records removed:" << endl;
		} else {
			cout << "Records to be removed:" << endl;
		}

		for (list<jaldb_doc_info>::iterator doc = docs.begin(); doc != docs.end(); doc++) {
			cout << "SID: " << doc->sid << endl;
			if (global_args.verbose) {
				cout << "UUID: " << doc->uuid << endl;
			}
			cout << endl;
		}
	}
}

static void process_options(int argc, char **argv)
{
	int opt = 0;

	static const char *opt_string = "s:u:t:b:dfvh:";
	static const struct option long_options[] = {
		{"sid", required_argument, NULL, 's'},
		{"uuid", required_argument, NULL, 'u'},
		{"type", required_argument, NULL, 't'},
		{"before", required_argument, NULL, 'b'},
		{"delete", no_argument, NULL, 'd'},
		{"force", no_argument, NULL, 'f'},
		{"verbose", no_argument, NULL, 'v'},
		{"home", required_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'n'},
		{0, 0, 0, 0}
	};

	while (EOF != (opt = getopt_long(argc, argv, opt_string, long_options, NULL))) {
		switch (opt) {
		case 's':
			if (global_args.uuid || global_args.before) {
				goto err_out;
			}
			global_args.sid = strdup(optarg);
			break;
		case 'u':
			if (global_args.sid || global_args.before) {
				goto err_out;
			}
			global_args.uuid = strdup(optarg);
			break;
		case 't':
			if ('j' != *optarg && 'a' != *optarg && 'l' != *optarg) {
				fprintf(stderr, "Invalid type\n");
				goto err_out;
			}
			global_args.type = *optarg;
			break;
		case 'b':
			if (global_args.sid || global_args.uuid) {
				goto err_out;
			}
			global_args.before = strdup(optarg);
			break;
		case 'd':
			global_args.del = 1;
			break;
		case 'f':
			global_args.force = 1;
			break;
		case 'v':
			global_args.verbose = 1;
			break;
		case 'h':
			global_args.home = strdup(optarg);
			break;
		case 'n':
			printf("%s", jal_version_as_string());
			goto version_out;
		default:
			goto err_out;
		}
	}
	if ((global_args.sid || global_args.uuid || global_args.before) && !global_args.type) {
		goto err_out;
	}

	return;
err_out:
	usage();
version_out:
	exit(0);
}

static void global_args_free()
{
	free(global_args.sid);
	free(global_args.uuid);
	free(global_args.before);
	free(global_args.home);
}

__attribute__((noreturn)) static void usage()
{
	static const char *usage =
	"Usage:\n\
	-s, --sid=S		Remove all records up to and including the\n\
				record with serial ID 'S'. '-t' must also\n\
				be specified\n\
	-u, --uuid=U		Remove all records up to and including the\n\
				record with UUID 'U'.  By default, this checks\n\
				the serial ID to determine what records came\n\
				before.  '-t' must also be specified.\n\
	-t, --type=T		Specify the type of JAL record.  'T' may be 'j',\n\
				'a', or 'l' for journal, audit, or logging, respectively.\n\
				When used with the '-u' or '--uuid' options, checks\n\
				the timestamp, rather than the sequence ID, for record\n\
				removal.\n\
	-b, --before=B		Remove all records with a timestamp before B. The\n\
				timestamp must be specified as an XML schema date,\n\
				time, or dateTime string.  The xmlschema-2 document\n\
				describes these formats.  When the time does not\n\
				include a timezone offset, it is interpreted as local\n\
				time.\n\
	-d, --delete		Delete the records.  The jal_purge tool does not remove\n\
				records that the JALoP Network Store has not sent to at\n\
				least one JALoP Network Store.\n\
	-f, --force		When '-d' is given, force the deletion of records\n\
				even when the JALoP Network Store has not sent them\n\
				to at least one JALoP Network Store.  When given\n\
				without '-d', this will report the number of records\n\
				that would be deleted.\n\
	-v, --verbose		Report more information about the records jal_purge is\n\
				prepared to delete.  This reports the sequence number\n\
				and UUID of each record.  Records are grouped by type.\n\
	-h, --home=H		Specify the root of the JALoP database,\n\
				defaults to /var/lib/jalop/db\n\
	--version		Output the version information and exit.\n\n";
	fprintf(stderr, "%s", usage);
	exit(-1);
}
