/**
 * @file jal_purge.cpp This file contains the source for jal_purge
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <getopt.h>
#include <iostream>
#include <list>
#include <jalop/jal_version.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jaldb_context.hpp"
#include "jaldb_traverse.h"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_record.h"

#include "jal_alloc.h"

using namespace std;

static struct global_args_t {
	int del;
	int force;
	int verbose;
	char *nonce;
	list<string> uuids;
	char type;
	char *before;
	char *home;
} global_args;

static void process_options(int argc, char **argv);
static void global_args_free();
static void usage();

extern "C" enum jaldb_iter_status iter_cb(const char *nonce, struct jaldb_record *rec, void *up);

int main(int argc, char **argv)
{
	enum jaldb_status dbret = (enum jaldb_status)-1;
	jaldb_context *ctx = NULL;

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

	enum jaldb_rec_type type;
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

	if (global_args.del) {
		cout << "Deleted the following records:" << endl;
	} else {
		cout << "Would delete the following records:" << endl;
	}

	if (!global_args.uuids.empty()) {
		struct jaldb_record *rec = NULL;
		uuid_t uuid;
		char *nonce = NULL;
		list<string>::iterator iter;
		for(iter = global_args.uuids.begin(); iter != global_args.uuids.end(); iter++) {
			printf("UUID: %s\n", iter->c_str());
#ifdef sun
			char * uuid_string = jal_strdup(iter->c_str());
			if (0 != uuid_parse(uuid_string, uuid)) {
				free(uuid_string);
#else
			if (0 != uuid_parse(iter->c_str(), uuid)) {
#endif
				cout << "Invalid UUID: " << iter->c_str()  << endl;
				goto out;
			}
#ifdef sun
			free(uuid_string);
#endif
			dbret = jaldb_get_record_by_uuid(ctx, type, uuid, &nonce, &rec);
			if (dbret != 0) {
				printf("Error getting record %s\n", uuid);
			}

			dbret = jaldb_remove_record(ctx, type, nonce);
			if (dbret != 0) {
				printf("Error removing record\n");
			}

			jaldb_destroy_record(&rec);
			free(nonce);
		}
	} else if (global_args.before) {
		dbret = jaldb_iterate_by_timestamp(ctx, type, global_args.before, iter_cb, &global_args);
		goto out;
	} else {
		cout << "Purging without a nonce or uuid specified is currently not supported." << endl;
		dbret = (enum jaldb_status)-1;
		goto out;
		// TODO: No arguments/filter specified
	}

out:
	if (JALDB_OK != dbret) {
		fprintf(stderr, "Failed to purge records\n");
	}

	global_args_free();
	jaldb_context_destroy(&ctx);
	return dbret;
}

extern "C" enum jaldb_iter_status iter_cb(const char *nonce, struct jaldb_record *rec, void *)
{

	if (global_args.force || rec->synced) {
		cout << "NONCE: " << nonce << endl;
		if (global_args.verbose) {
			char uuid[37]; // UUID are always 36 characters + the NULL terminator
			uuid_unparse(rec->uuid, uuid);
			cout << "UUID: " << uuid << endl;
		}
		if (global_args.del) {
			return JALDB_ITER_REM;
		}
	}
	return JALDB_ITER_CONT;

}

static void process_options(int argc, char **argv)
{
	int opt = 0;

	static const char *opt_string = "s:u:t:b:dfvh:";
	static const struct option long_options[] = {
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
		case 't':
			if ('j' != *optarg && 'a' != *optarg && 'l' != *optarg) {
				fprintf(stderr, "Invalid type\n");
				goto err_out;
			}
			global_args.type = *optarg;
			break;
		case 'b':
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

	/* Process UUIDS */
	while (optind < argc) {
		global_args.uuids.push_front(string(argv[optind++]));
	}

	if ((!global_args.uuids.empty() || global_args.before) && !global_args.type) {
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
	free(global_args.before);
	free(global_args.home);
}

__attribute__((noreturn)) static void usage()
{
	static const char *usage =
	"Usage:\n\
	-n, --nonce=N		Remove all records up to and including the\n\
				record with nonce 'N'. '-t' must also\n\
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
