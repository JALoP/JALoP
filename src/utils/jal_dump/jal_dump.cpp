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
#include "jaldb_strings.h"

#define ARRAY_MULTIPLIER 20

#define JOURNAL_FILE_NAME "jal_dump_journal.txt"
#define AUDIT_FILE_NAME "jal_dump_audit.txt"
#define LOG_FILE_NAME "jal_dump_log.txt"

using namespace std;

static void parse_cmdline(int argc, char **argv, char ***sid, int *num_sid, char ***uuid, int *num_uuid, char *type,
	char *data, char **path, char **home);

static void print_usage();

void print_payload(uint8_t *payload_buf, size_t payload_size);

int print_record(char *sid, char data, char *path, char type, uint8_t *sys_meta_buf, size_t sys_meta_len,
			uint8_t *app_meta_buf, size_t app_meta_len, uint8_t *record_buf, size_t record_len);

static void print_error(enum jaldb_status error);

char ** array_increase(char ***arr);

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

	parse_cmdline(argc, argv, &sid, &num_sid, &uuid, &num_uuid, &type,
			 &data, &path, &home);

	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;

	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;

	uint8_t *record_buf = NULL;
	size_t record_len = 0;

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

	for (counter = 0; counter < (num_sid + num_uuid); counter++) {
		//grab each sid, and display
		int fd = -1; //for the journal record
		sys_meta_buf = NULL;
		app_meta_buf = NULL;
		record_buf = NULL;

		switch(type) {
			case ('j'):
				if (counter < num_sid) {
					jaldb_ret = jaldb_lookup_journal_record(
						ctx, *(sid + counter), &sys_meta_buf, &sys_meta_len,
						&app_meta_buf, &app_meta_len, &fd, &record_len);

/*				}else{
					jaldb_ret = jaldb_get_journal_record_by_uuid(
							ctx, *(uuid + counter - num_sid), &sys_meta_buf, &sys_meta_len,
							&app_meta_buf, &app_meta_len, &record_buf, &record_len);
*/				}
				if (jaldb_ret != JALDB_OK) {
					printf("jaldb_journal failed %d\n", jaldb_ret);
					print_error(jaldb_ret);
					goto err_out;
				}

				struct stat stat_buf;
				if (-1 == fstat(fd, &stat_buf)) {
					goto err_out;
				}
				record_len = stat_buf.st_size;

				record_buf = (uint8_t *) mmap64(NULL, record_len, PROT_READ, MAP_NORESERVE | MAP_PRIVATE, fd, 0);
				ret = print_record(*(sid + counter), data, path, type, sys_meta_buf, sys_meta_len,
						app_meta_buf, app_meta_len, record_buf, record_len);
				if (0 > ret) {
					printf("Error in printing\n");
					goto err_out;
				}
				munmap(record_buf, record_len);
				record_buf = NULL;
				record_len = 0;

				close(fd);

				break;
			case ('a'):
				if (counter < num_sid) {
					jaldb_ret = jaldb_lookup_audit_record(
						ctx, *(sid + counter), &sys_meta_buf, &sys_meta_len,
						&app_meta_buf, &app_meta_len, &record_buf, &record_len);
				} /* else{
					jaldb_ret = jaldb_lookup_audit_record_by_uuid(
						ctx, *(uuid + counter - num_sid), &sys_meta_buf, &sys_meta_len,
						 &app_meta_buf, &app_meta_len, &record_buf, &record_len);
				} */

				if (jaldb_ret != JALDB_OK) {
					printf("jaldb_audit_lookup failed %d\n", jaldb_ret);
					print_error(jaldb_ret);
					goto err_out;
				}
				ret = print_record(*(sid + counter), data, path, type, sys_meta_buf, sys_meta_len,
						app_meta_buf, app_meta_len, record_buf, record_len);
				if (0 > ret) {
					printf("Error in printing\n");
					goto err_out;
				}
				break;
			case ('l'):
				ret = 0;
				if (counter < num_sid) {
					jaldb_ret = jaldb_lookup_log_record(
						ctx, *(sid + counter), &sys_meta_buf, &sys_meta_len, &app_meta_buf,
						&app_meta_len, &record_buf, &record_len, &ret);
				} else {
/*					jaldb_ret = jaldb_get_log_record_by_uuid(
						ctx, *(uuid + counter - num_sid), &sys_meta_buf, &sys_meta_len,
						&app_meta_buf, &app_meta_len, &record_buf, &record_len);
*/				}
				if (ret != 0) {
					printf("\nDB Error: %i\n", ret);
				}

				if (jaldb_ret != JALDB_OK) {
					printf("jaldb_log_lookup failed %d\n", jaldb_ret);
					print_error(jaldb_ret);
					goto err_out;
				}

				ret = print_record(*(sid + counter), data, path, type, sys_meta_buf, sys_meta_len,
						app_meta_buf, app_meta_len, record_buf, record_len);
				if (0 > ret) {
					printf("Error in printing\n");
					goto err_out;
				}
				break;
			default:
				//control should never reach here
				goto err_out;
		} //switch
		free(sys_meta_buf);
		free(app_meta_buf);
		free(record_buf);
	} //for () loop

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
	if(ctx) {
		jaldb_context_destroy(&ctx);
	}

	return ret;
}

int print_record(char *sid, char data, char *path, char type, uint8_t *sys_meta_buf, size_t sys_meta_len,
			 uint8_t *app_meta_buf, size_t app_meta_len, uint8_t *record_buf, size_t record_len) {
	int ret = 0;
	//Initialize path to write to
	int fd_sys = 0;
	int fd_app = 0;
	int fd_dat = 0;
	char *tmpstr = NULL;
	char *sysstr = NULL;
	char *appstr = NULL;
	char *datstr = NULL;

	//Print to stdout if not to a file
	if (!path) {
		if (('a' == data || 'z' == data) && (0 != app_meta_len) && app_meta_buf) {
			printf("\napplication metadata\n");
			print_payload(app_meta_buf, app_meta_len);
		}
		if (('s' == data || 'z' == data) && (0 != sys_meta_len) && sys_meta_buf) {
			printf("\nsystem metadata\n");
			//(the default)
			print_payload(sys_meta_buf, sys_meta_len);
		}
		if (('j' == type) && (('p' == data) || ('z' == data))
			 && ((size_t)(100) < record_len) && (!record_buf)) {
			printf("\njournal metadata\n");
			//used to ensure that journal records don't cause unwanted actions by being too big
			print_payload(record_buf, ((size_t)100));
		}
		if ((('p' == data) || ('z' == data)) && (0 != record_len) && (record_buf)) {
			printf("\npayload\n");
			print_payload(record_buf, record_len);
		}
	}

	//Print record to file if applicable
	if (path) {
		if ('j' == type) {
			jal_asprintf(&tmpstr, "%sjournal-%s/", path, sid);
		} else if ('a' == type) {
			jal_asprintf(&tmpstr, "%saudit-%s/", path, sid);
		} else if ('l' == type) {
			jal_asprintf(&tmpstr, "%slog-%s/", path, sid);
		}

		//Make the sub-directory
		ret = mkdir(tmpstr, S_IRWXU|S_IRGRP|S_IROTH);

		jal_asprintf(&sysstr, "%ssystem-metadata.xml", tmpstr);

		if (0 != app_meta_len && NULL != app_meta_buf) {
			jal_asprintf(&appstr, "%sapplication-metadata.xml", tmpstr);
		}

		if ('j' == type) {
			jal_asprintf(&datstr, "%sjournal.bin",tmpstr);
		} else if ('a' == type) {
			jal_asprintf(&datstr, "%saudit.xml",tmpstr);
		} else if ('l' == type) {
			jal_asprintf(&datstr, "%slog.bin",tmpstr);
		}

		// Now sys_meta_data goes to sysstr ; app_meta_data to appstr ; record to datstr

		if ((0 != sys_meta_len) && (NULL != sys_meta_buf)) {
			fd_sys = open(sysstr, O_RDWR|O_CREAT|O_TRUNC, 0600);	// Delete existing file(O_TRUNC)?
		}
		if ((0 != app_meta_len) && (NULL != app_meta_buf)) {
			fd_app = open(appstr, O_RDWR|O_CREAT|O_TRUNC, 0600); 	// Delete existing file(O_TRUNC)?
		}
		if ((0 != record_len) && (NULL != record_buf)) {
			fd_dat = open(datstr, O_RDWR|O_CREAT|O_TRUNC, 0600); 	// Delete existing file(O_TRUNC)?
		}

		if (fd_sys < 0 || fd_app < 0 || fd_dat < 0) {
			printf("file open error\n");
			printf("System fd was %i, App fd was %i, Data fd was %i\n", fd_sys, fd_app, fd_dat);
			return -1;
		}

		if (fd_sys) {
			ret = write(fd_sys, sys_meta_buf, sys_meta_len);
			if (ret >= 0)
				printf("Path for system data is %s.\n", sysstr);
		}
		if (ret >= 0 && fd_app) {
			ret = write(fd_app, app_meta_buf, app_meta_len);
			if (ret >= 0)
				printf("Path for application data is %s.\n", appstr);
		}
		if (ret >= 0 && fd_dat) {
			ret = write(fd_dat, record_buf, record_len);
			if (ret >= 0)
				printf("Path for record data is %s.\n", datstr);
		}

		free(tmpstr);
		free(sysstr);
		free(appstr);
		free(datstr);
		ret = 0;
		ret |= close(fd_sys);
		ret |= close(fd_app);
		ret |= close(fd_dat);

		if (0 == ret) {
			return 0;
		} else {
			return -1;
		}
	}
	return 0;
}

static void parse_cmdline(int argc, char **argv, char ***sid, int *num_sid, char ***uuid, int *num_uuid,
				char *type, char *data, char **path, char **home) {

	int counter = 0;
	static const char *defdir = "/var/lib/jalop/db";
	static const char *optstring = "s:u:t:d:p:h:v:w";
	static const struct option long_options[] = {
			{"type", 1, 0, 't'}, {"sid",1,0,'s'},{"uuid",1,0,'u'},
			{"data",1,0,'d'}, {"path",1,0,'p'},{"home",2,0,'h'},
			{"version",0,0,'v'},{"write", 0, 0, 'w'}, {0,0,0,0}};


	if (2 == argc) {
		if ('v' == getopt_long(argc, argv, optstring, long_options, NULL)) {
			printf("%s\n", jal_version_as_string());
			exit(0);
		}
	}
	if (4 > argc) {
		goto err_usage;
	}

	*sid = (char **) malloc(ARRAY_MULTIPLIER * sizeof(char *));
	if (!(*sid)) {
		printf("Insufficient memory\n");
		exit(-1);
	}
	*uuid = (char **) malloc(ARRAY_MULTIPLIER * sizeof(char *));
	if (!(*uuid)) {
		free(*sid);
		printf("Insufficient memory for uuid storage. Closing.\n");
		exit(-1);
	}


	int ret_opt;
	while (EOF != (ret_opt = getopt_long(argc, argv, optstring, long_options, NULL))) {
		switch (ret_opt) {
			case 's':
				if (0 == ((1 + *num_sid) % ARRAY_MULTIPLIER)) {
					*sid = array_increase(sid);
				}
				*(*sid + *num_sid) = strdup(optarg);
				(*num_sid)++;
				break;
			case 'u':
				if (0 == ((1 + *num_uuid) % ARRAY_MULTIPLIER)) {
					*uuid = array_increase(uuid);
				}
				*(*uuid + *num_uuid) = strdup(optarg);
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
				if (('a' != *optarg) && ('s' != *optarg) && ('p' != *optarg) && ('z' != *optarg)) {
					*data = 's';
				} else {
					*data = *optarg;
				}
				break;
			case 'p':
				*path = strdup(optarg);
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
	if (('a' != *data) && ('s' != *data) && ('p' != *data) && ('z' != *data)) {
		*data = 's';
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
			data). The default is to dump the system metadata. If this option is specified \n\
			multiple times, the last occurance is used. To retrieve all portions of a record,\n\
			use \"z\".\n\
	-p, --path=P	Copy the record to the provided path, \"/P/\". This will create a sub-directory with\n\
			the name <record_type>-<sid>/ where <record_type> is replaced with \"journal\", \n\
			\"audit\", or \"log\", and <sid> is replaced with the sequence ID for the record. \n\
			This directory will always contain a file named \"system-metadata.xml\", which is the\n\
			system metadata for the record. If the record contains application metadata, the\n\
			directory will also contain a file named \"application-metadata.xml\". Depending on the\n\
			type of record, this directory may contain a file named \"journal.bin\" (for journal\n\
			records), \"log.bin\" (for log records), or \"audit.xml\" for audit records.\n\
	-h, --home=H	Specify the root of the JALoP database, defaults to /var/lib/jalop/db. The entered path\n\
			must immediately follow the option.\n\
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

char ** array_increase(char ***arr) {
	char **tmp = (char**) realloc(*arr, (sizeof(*arr) + (sizeof(char*) * ARRAY_MULTIPLIER)));
	if (NULL != tmp) {
		return tmp;
	} else{
		return *arr;
	}
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

