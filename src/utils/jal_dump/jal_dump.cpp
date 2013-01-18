/**
 * @file jal_dump.cpp This file contains the source for jal_dump
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <libconfig.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <list>
#include <iostream>
#include <fstream>

#include <jal_alloc.h>
#include <jal_asprintf_internal.h>
#include <jalop/jal_version.h>

#include <jaldb_status.h>
#include "jal_dump.h"
#include "jaldb_context.hpp"
#include "jaldb_record.h"
#include "jaldb_segment.h"
#include "jaldb_strings.h"

#define INITIAL_ARRAY_SIZE 20
#define WRITE_MAX 2147479552

#define JOURNAL_FILE_NAME "jal_dump_journal.txt"
#define AUDIT_FILE_NAME "jal_dump_audit.txt"
#define LOG_FILE_NAME "jal_dump_log.txt"

using namespace std;

static void parse_cmdline(int argc, char **argv, char ***sid, int *num_sid, char ***uuid, int *num_uuid, char *type,
	char *data, char **path, char **home);

static void print_usage();

void print_payload(uint8_t *payload_buf, size_t payload_size);

int print_record(jaldb_context *ctx, char *sid, char data, char *path, struct jaldb_record *rec);

static void print_error(enum jaldb_status error);

int dump_records_by_sid(jaldb_context *ctx, enum jaldb_rec_type rtype, char data, char *path, char **id_arr,
	int num_id, enum jaldb_status *ret_status);

int dump_records_by_uuid(jaldb_context *ctx, enum jaldb_rec_type rtype, char data, char *path, char **uuid_arr,
	int num_uuid, enum jaldb_status *ret_status);

/**
 * Utility function to dynamically grow an array as needed.
 * If (*max_elms == elm_count) then the array is grown.
 * @param arr[in,out] The array to grow
 * @param max_elms[in,out] The original and new maximum size of the array
 * @param elm_count[in] The current number of elements in the array.
 */
static void ensure_capacity(char ***arr, int *max_elms, int elm_count);

static void print_sids(jaldb_context *ctx, char type);
static void print_list_stdout(const list<string> &p_list);
static void print_list_file(const list<string> &p_list, const char *p_file_name);

static const size_t BUF_SIZE = 8192;
static int write_sid_flag = 0;

int main(int argc, char **argv) {
	char **sid = NULL;
	char **uuid = NULL;
	char data = 0;
	char type = 0;
	char *path = NULL;
	char *home = NULL;
	int num_sid = 0;
	int num_uuid = 0;
	int counter = 0;
	int ret = 0;
	enum jaldb_rec_type rtype = JALDB_RTYPE_UNKNOWN;

	parse_cmdline(argc, argv, &sid, &num_sid, &uuid, &num_uuid, &type,
			 &data, &path, &home);

	enum jaldb_status jaldb_ret = JALDB_OK;
	jaldb_context *ctx = jaldb_context_create();

	jaldb_ret = jaldb_context_init(ctx, home, NULL, 1);

	if (jaldb_ret != JALDB_OK) {
		printf("\nContext could not be made.\n");
		print_error(jaldb_ret);
		goto err_out;
	}

	if (write_sid_flag) {
		print_sids(ctx, type);
	}
	switch(type) {
	case ('j'):
		rtype = JALDB_RTYPE_JOURNAL;
		break;
	case ('a'):
		rtype = JALDB_RTYPE_AUDIT;
		break;
	case ('l'):
		rtype = JALDB_RTYPE_LOG;
		break;
	default:
		goto err_out;
	}

	ret = dump_records_by_sid(ctx, rtype, data, path, sid, num_sid, &jaldb_ret);
	if (jaldb_ret != JALDB_OK) {
		printf("failed to retrieve record, err\n");
		print_error(jaldb_ret);
		goto err_out;
	}
	if (0 > ret) {
		printf("Error in printing\n");
		goto err_out;
	}

	ret = dump_records_by_uuid(ctx, rtype, data, path, uuid, num_uuid, &jaldb_ret);
	if (jaldb_ret != JALDB_OK) {
		printf("failed to retrieve record, err\n");
		print_error(jaldb_ret);
		goto err_out;
	}
	if (0 > ret) {
		printf("Error in printing\n");
		goto err_out;
	}

	/* deconstruct this util */
	ret = 0;
	goto out;

err_out:
	ret = -1;
	printf("You have hit error out. Closing out.\n");
out:
	for (counter = 0; counter < (num_sid); counter++) {
		free(*(sid + counter));
	}
	for (counter = 0; counter < (num_uuid); counter++) {
		free(*(uuid + counter));
	}
	free(sid);
	free(uuid);

	if (path) {
		free(path);
	}
	if (home) {
		free(home);
	}
	jaldb_context_destroy(&ctx);

	return ret;
}

int dump_records_by_sid(jaldb_context *ctx, enum jaldb_rec_type rtype, char data, char *path, char **id_arr,
			int num_id, enum jaldb_status *ret_status)
{
	int cnt = 0;
	int ret_err = 0;

	for (cnt = 0; cnt < num_id; cnt++) {
		struct jaldb_record *rec = NULL;

		if (cnt < num_id) {
			*ret_status = jaldb_get_record(ctx, rtype, *(id_arr + cnt), &rec);
		}

		if (*ret_status != JALDB_OK) {
			ret_err = -1;
			return ret_err;
		}

		ret_err = print_record(ctx, *(id_arr + cnt), data, path, rec);

		if (0 > ret_err) {
			ret_err = -2;
			return ret_err;
		}

		jaldb_destroy_record(&rec);
	}

	return ret_err;
}

int dump_records_by_uuid(jaldb_context *ctx, enum jaldb_rec_type rtype, char data, char *path, char **id_arr,
			int num_id, enum jaldb_status *ret_status)
{
	int cnt = 0;
	int ret_err = 0;
	char *sid = NULL;

	for (cnt = 0; cnt < num_id; cnt++) {
		struct jaldb_record *rec = NULL;

		if (cnt < num_id) {
			uuid_t uuid;
			if (0 != uuid_parse(*(id_arr + cnt), uuid)) {
				fprintf(stderr, "Bad UUID (ignoring): %s\n", *(id_arr + cnt));
				continue;
			} else {
				*ret_status = jaldb_get_record_by_uuid(ctx, rtype, uuid, &sid, &rec);
			}
		}

		if (*ret_status != JALDB_OK) {
			ret_err = -1;
			return ret_err;
		}

		ret_err = print_record(ctx, sid, data, path, rec);
		free(sid);
		sid = NULL;

		if (0 > ret_err) {
			ret_err = -2;
			return ret_err;
		}

		jaldb_destroy_record(&rec);
	}

	return ret_err;
}

ssize_t jal_dump_write(jaldb_context *ctx, int fd, struct jaldb_segment *s)
{
#define BUF_SIZE 4096
	uint8_t buf[BUF_SIZE];
	ssize_t ret = 0;
	size_t count = 0;

	if (!s) {
		return 0;
	}
	if (s->on_disk) {
		if (JALDB_OK != jaldb_open_segment_for_read(ctx, s)) {
			return -1;
		}
		while(1) {
			ssize_t rd = read(s->fd, buf, BUF_SIZE);
			if (-1 == rd) {
				return -1;
			} else if (0 == rd) {
				break;
			}
			ret = write(fd, buf, rd);
			if (-1 == ret) {
				return -1;
			}
			count += ret;
		}
	} else {
		ret = write(fd, s->payload, s->length);
		if (-1 == ret) {
			return -1;
		}
		count += ret;
	}
	return count;
}

int print_record(jaldb_context *ctx, char *sid, char data, char *path, struct jaldb_record *rec)
{
	ssize_t ret = 0;
	//Initialize path to write to
	int fd_sys = -1;
	int fd_app = -1;
	int fd_dat = -1;
	char *tmpstr = NULL;
	char *sysstr = NULL;
	char *appstr = NULL;
	char *datstr = NULL;

	if ('u' == data) {
		char uuid[37];
		uuid_unparse(rec->uuid, uuid);
		printf("%s:%s\n", uuid, sid);
	} else if (!path) {
		if (('a' == data || 'z' == data)) {
			if (0 > jal_dump_write(ctx, fileno(stdout), rec->app_meta)) {
				ret = -1;
				goto out;
			}
		}
		if (('s' == data || 'z' == data)) {
			printf("\nsystem metadata\n");
			if (0 > jal_dump_write(ctx, fileno(stdout), rec->sys_meta)) {
				ret = -1;
				goto out;
			}
		}
		if (('p' == data) || ('z' == data)) {
			printf("\npayload\n");
			if (0 > jal_dump_write(ctx, fileno(stdout), rec->payload)) {
				ret = -1;
				goto out;
			}
		}
	} else {
		switch (rec->type) {
		case JALDB_RTYPE_JOURNAL:
			jal_asprintf(&tmpstr, "%sjournal-%s/", path, sid);
			jal_asprintf(&datstr, "%sjournal.bin",tmpstr);
			break;
		case JALDB_RTYPE_AUDIT:
			jal_asprintf(&tmpstr, "%saudit-%s/", path, sid);
			jal_asprintf(&datstr, "%saudit.xml",tmpstr);
			break;
		case JALDB_RTYPE_LOG:
			jal_asprintf(&tmpstr, "%slog-%s/", path, sid);
			jal_asprintf(&datstr, "%slog.bin",tmpstr);
			break;
		default:
			goto out;
		}

		//Make the sub-directory
		ret = mkdir(tmpstr, S_IRWXU|S_IRGRP|S_IROTH);

		jal_asprintf(&sysstr, "%ssystem-metadata.xml", tmpstr);
		jal_asprintf(&appstr, "%sapplication-metadata.xml", tmpstr);

		fd_sys = open(sysstr, O_RDWR|O_CREAT|O_TRUNC, 0600);	// Delete existing file(O_TRUNC)?
		if (fd_sys == -1) {
			perror("Error Opening System Metadata Doc");
			ret = -1;
			goto out;
		}
		if (0 < jal_dump_write(ctx, fd_sys, rec->sys_meta)) {
			printf("Path for system data is %s.\n", sysstr);
		} else {
			ret = -1;
			goto out;
		}
		if (rec->app_meta) {
			fd_app = open(appstr, O_RDWR|O_CREAT|O_TRUNC, 0600); 	// Delete existing file(O_TRUNC)?
			if (fd_app == -1) {
				perror("Error Opening Application Metadata Doc");
				ret = -1;
				goto out;
			}
			if (0 < jal_dump_write(ctx, fd_app, rec->app_meta)) {
				printf("Path for application data is %s.\n", appstr);
			} else {
				ret = -1;
				goto out;
			}
		}
		if (rec->payload) {
			fd_dat = open(datstr, O_RDWR|O_CREAT|O_TRUNC, 0600); 	// Delete existing file(O_TRUNC)?
			if (fd_dat == -1) {
				perror("Error Opening Payload File");
				ret = -1;
				goto out;
			}
			if (0 < jal_dump_write(ctx, fd_dat, rec->payload)) {
				printf("Path for record data is %s.\n", datstr);
			} else {
				ret = -1;
				goto out;
			}
		}
	}
out:
	free(tmpstr);
	free(sysstr);
	free(appstr);
	free(datstr);
	if ((0 < fd_sys) && (-1 == close(fd_sys))) {
		perror("Error closing system metadata");
	}
	if ((0 < fd_app) && (-1 == close(fd_app))) {
		perror("Error closing system metadata");
	}
	if ((0 < fd_dat) && (-1 == close(fd_dat))) {
		perror("Error closing system metadata");
	}

	return ret;
}

static void parse_cmdline(int argc, char **argv, char ***sid, int *num_sid, char ***uuid, int *num_uuid,
				char *type, char *data, char **path, char **home)
{

	int counter = 0;
	static const char *defdir = "/var/lib/jalop/db";
	static const char *optstring = "s:u:t:d:p:h:v:w";
	static const struct option long_options[] = {
			{"type", 1, 0, 't'}, {"sid",1,0,'s'},{"uuid",1,0,'u'},
			{"data",1,0,'d'}, {"path",1,0,'p'},{"home",2,0,'h'},
			{"version",0,0,'v'},{"write", 0, 0, 'w'}, {0,0,0,0}};

	int sid_arr_sz = INITIAL_ARRAY_SIZE;
	int uuid_arr_sz = INITIAL_ARRAY_SIZE;

	if (2 == argc) {
		if ('v' == getopt_long(argc, argv, optstring, long_options, NULL)) {
			printf("%s\n", jal_version_as_string());
			exit(0);
		}
	}
	if (4 > argc) {
		goto err_usage;
	}
	*sid = (char **) malloc(sid_arr_sz * sizeof(char*));
	if (!(*sid)) {
		printf("Insufficient memory\n");
		exit(-1);
	}
	*uuid = (char **) malloc(uuid_arr_sz * sizeof(char*));
	if (!(*uuid)) {
		free(*sid);
		printf("Insufficient memory for uuid storage. Closing.\n");
		exit(-1);
	}


	int ret_opt;
	while (EOF != (ret_opt = getopt_long(argc, argv, optstring, long_options, NULL))) {
		switch (ret_opt) {
			case 's':
				ensure_capacity(sid, &sid_arr_sz, *num_sid);
				(*sid)[*num_sid] = strdup(optarg);
				(*num_sid)++;
				break;
			case 'u':
				ensure_capacity(uuid, &uuid_arr_sz, *num_uuid);
				(*uuid)[*num_uuid] = strdup(optarg);
				(*num_uuid)++;
				break;
			case 't':
				if (('j' != *optarg) && ('a' != *optarg) && ('l' != *optarg)) {
					printf("\nType invalid\n");
					goto err_usage;
				}
				*type = *optarg;
				break;
			case 'd':
				if (('a' != *optarg) && ('s' != *optarg) && ('p' != *optarg) && ('z' != *optarg) && ('u' != *optarg)) {
					*data = 's';
				} else {
					*data = *optarg;
				}
				break;
			case 'p':
				*path = strdup(optarg);
				char *new_path;
				new_path = NULL;
				if ((*path)[strlen((*path))-1] != '/') {
					jal_asprintf(&new_path, "%s/", *path);
					free(*path);
					*path = new_path;
				}
				break;
			case 'h':
				if (NULL == optarg) {
					printf("Optarg was null. Home directory defaulting to /var/lib/jalop/db\n");
					*home = strdup(defdir);
				} else {
					*home = strdup(optarg);
				}
				break;
			case 'w':
				write_sid_flag = 1;
				break;
			case 'v':
				printf("%s\n", jal_version_as_string());
				goto version_out;
				break;
			case ':':		//Missing argument
			case '?':		//Unknown option
			default:
				goto err_usage;
		}//switch
	}//while

	//check usage
	if (('j' != *type) && ('a' != *type) && ('l' != *type)) {
		goto err_usage;
	}
	if (('a' != *data) && ('s' != *data) && ('p' != *data) && ('z' != *data) && ('u' != *data)) {
		*data = 's';
	}

	if (*path && ('u' == *data)) {
		goto err_usage;
	}
	return;

err_usage:

	printf("\nError: Usage\n");
	print_usage();
	for (counter = 0; counter < (*num_sid); counter++) {
		free(*(*sid + counter));
	}
	for (counter = 0; counter < (*num_uuid); counter++) {
		free(*(*uuid + counter));
	}

	free(*sid);
	free(*uuid);
	if (path != NULL) {
		free(*path);
	}
	if ((home != NULL) && (*home != NULL)) {
		free(*home);
	}


	exit(-1);

version_out:
	for (counter = 0; counter < (*num_sid); counter++) {
		free(*(*sid + counter));
	}
	for (counter = 0; counter < (*num_uuid); counter++) {
		free(*(*uuid + counter));
	}

	free(*sid);
	free(*uuid);
	if (path != NULL) {
		free(*path);
	}
	if ((home != NULL) && (*home != NULL)) {
		free(*home);
	}

	exit(0);
}


static void print_usage()
{
	static const char *usage =
	"Usage:\n\
	-s, --sid=S	Search using the sequence ID \"s\". Specify any number of \"-s\" options to output \n\
			multiple records in the order listed.\n\
	-u, --uuid	Search using the UUID \"u\". Specify any number of \"-u\" options to output multiple\n\
			records in the order listed. \n\
	-t, --type=T	Search within the specified type. T may be: \"j\" (journal record), \"a\" (audit record),\n\
			or \"l\" (log record).\n\
	-d, --data=D	Specifies which section of the data should be dumped, options are \"a\" for application\n\
			metadata, \"s\" for system metadata, or \"p\" for the payload (raw journal, audit, or log\n\
			data), or \"u\" for just the UUID. The output will be in the form <sid>:<uuid>. \n\
			The default is to dump the system metadata. If this option is specified \n\
			multiple times, the last occurance is used. To retrieve all portions of a record,\n\
			use \"z\".\n\
	-p, --path=P	Copy the record to the provided path, \"/P/\". This will create a sub-directory with\n\
			the name <record_type>-<sid>/ where <record_type> is replaced with \"journal\", \n\
			\"audit\", or \"log\", and <sid> is replaced with the sequence ID for the record. \n\
			This directory will always contain a file named \"system-metadata.xml\", which is the\n\
			system metadata for the record. If the record contains application metadata, the\n\
			directory will also contain a file named \"application-metadata.xml\". Depending on the\n\
			type of record, this directory may contain a file named \"journal.bin\" (for journal\n\
			records), \"log.bin\" (for log records), or \"audit.xml\" for audit records. '~' expansion\n\
			will only work with --path <~path> and not with --path=<~/path>\n\
	-h, --home=H	Specify the root of the JALoP database, defaults to /var/lib/jalop/db. The entered path\n\
			must immediately follow the option. '~' expansion will only work with --home <~path>\n\
			and not with --home=<~path>\n\
	-w, --write	Signals for a list of serial IDs in the JALoP database to be written\n\
			to a file for each record type.\n\
	-v, --version	Outputs the version and exits.\n\
\n\
	Type and at least 1 sid or uuid must be specified.\n\n";

	printf("%s\n", usage);
}

void print_payload(uint8_t *payload_buf, size_t payload_size)
{
	if (!payload_buf) {
		printf("No data.");
		return;
	}
	printf("(hex): 0x");
	for (size_t i = 0; i < payload_size; i++) {
		printf("%x", payload_buf[i]);
	}
	char *str_payload = (char *) malloc(payload_size + 1);
	memcpy(str_payload, payload_buf, payload_size);
	str_payload[payload_size] = 0;
	printf("\n\n(char): %s\n", str_payload);
	free(str_payload);
}

static void print_error(enum jaldb_status error)
{
	switch (error) {

		case JALDB_E_INVAL:
			printf("JALDB_E_INVAL");
			break;
		case JALDB_E_UNKNOWN:
			printf("JALDB_E_UNKNOWN");
			break;
		case JALDB_E_DB:
			printf("JALDB_E_DB");
			break;
		case JALDB_E_ALREADY_CONFED:
			printf("JALDB_E_ALREADY_CONFED");
			break;
		case JALDB_E_NO_MEM:
			printf("JALDB_E_NO_MEM");
			break;
		case JALDB_E_UNINITIALIZED:
			printf("JALDB_E_UNINITIALIZED");
			break;
		case JALDB_E_INTERNAL_ERROR:
			printf("JALDB_E_INTERNAL_ERROR");
			break;
		case JALDB_E_INITIALIZED:
			printf("JALDB_E_INITIALIZED");
			break;
		case JALDB_E_CORRUPTED:
			printf("JALDB_E_CORRUPTED");
			break;
		case JALDB_E_SID:
			printf("JALDB_E_SID");
			break;
		case JALDB_E_NOT_FOUND:
			printf("JALDB_E_NOT_FOUND");
			break;
		case JALDB_OK:
			break;
		default:
			printf("UNKNOWN_ERROR");
			break;
	}
	printf("\n");
}

static void ensure_capacity(char ***arr, int *max_elms, int elm_count)
{
	if (*max_elms > elm_count) {
		return;
	}
	if (*max_elms < elm_count) {
		fprintf(stderr, "Error: array is too small for the indicated number of elements\n");
		exit(-1);
	}
	(*max_elms) *= 2;
	char **tmp = (char**) realloc(*arr, *max_elms * sizeof(char*));
	if (tmp) {
		*arr = tmp;
		return;
	}
	printf("Failed to alloc memory for serial IDs");
	exit(-1);
}

static void print_sids(jaldb_context *ctx, char type)
{
	enum jaldb_status db_ret = JALDB_E_UNKNOWN;

	list<string> *doc_list = NULL;
	string print_list_filename;

	printf("SERIAL_IDs:\n");
	switch (type){
		case 'j':
			db_ret = jaldb_get_journal_document_list(ctx, &doc_list);
			print_list_filename  = JOURNAL_FILE_NAME;
			break;
		case 'a':
			db_ret = jaldb_get_audit_document_list(ctx, &doc_list);
			print_list_filename = AUDIT_FILE_NAME;
			break;
		case 'l':
			db_ret = jaldb_get_log_document_list(ctx, &doc_list);
			print_list_filename  = LOG_FILE_NAME;
			break;
		default:
			printf("Unrecognized record-type: %c\n", type);
			break;
	}
	if (db_ret != JALDB_OK) {
		goto err_out;
	}
	doc_list->remove(JALDB_SERIAL_ID_DOC_NAME);
	print_list_stdout(*doc_list);
	print_list_file(*doc_list, print_list_filename.c_str());
	return;
err_out:
	printf("Failed to retrieve SIDs from the database");
}

static void print_list_stdout(const list<string> &p_list)
{
	if (0 == p_list.size()) {
		printf("\t--none--\n");
	}
	list<string>::const_iterator i;
	for(i=p_list.begin(); i != p_list.end(); ++i) {
		std::string name = (string) *i;
		printf("\t%s\n", name.c_str());
	}
}

static void print_list_file(const list<string> &p_list, const char *p_file_name)
{
	if (0 == p_list.size()) {
		printf("Write serial IDs failed! No documents were found!\n");
	}
	else {
		ofstream fout;
		fout.open(p_file_name, ios::out | ios::trunc);

		if (fout.is_open()) {
			list<string>::const_iterator i;
			for(i=p_list.begin(); i != p_list.end(); ++i) {
				std::string name = (string) *i;
				fout << name << "\n";
			}
			fout.close();
			printf("\nWrite serial IDs success! Check your directory for %s\n\n",
			p_file_name);
		}
		else {
			printf("\nWrite serial IDs failed! Unable to open file: %s\n\n",
			p_file_name);
		}
	}
}

