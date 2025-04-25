/**
 * @file
 *
 * @brief This file contains the source for jal_dump
 *
 * ### LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2013 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <list>
#include <iostream>
#include <fstream>
#include <sstream>

#include <jal_alloc.h>
#include <jal_fs_utils.h>
#include <jal_asprintf_internal.h>
#include <jalop/jal_version.h>

#include <jaldb_status.h>
#include "jal_dump.h"
#include "jaldb_context.hpp"
#include "jaldb_record.h"
#include "jaldb_segment.h"
#include "jaldb_strings.h"

// For RHEL7 compatibility
#ifndef UUID_STR_LEN
constexpr int UUID_STR_LEN = 37;
#endif

#define INITIAL_ARRAY_SIZE 20
#define WRITE_MAX 2147479552

#define JOURNAL_FILE_NAME "jal_dump_journal.txt"
#define AUDIT_FILE_NAME "jal_dump_audit.txt"
#define LOG_FILE_NAME "jal_dump_log.txt"

using namespace std;

// argp
const char *argp_program_version = jal_version_as_string();
const char *argp_program_bug_address = 0;
static char args_doc[] = "";
static char doc[] = "jal_dump - JALoP database dump utility.";
static error_t parse_opt(int key, char *arg, struct argp_state *state);
static struct argp_option options[] =
{
  	{"uuid", 'u', "U", 0, "REQUIRED. Search using the UUID 'U'. Specify any number of '-u' options to output multiple records in the order listed.", 0},
	{"type", 't', "T", 0, "REQUIRED. Search within the specified type. T may be: 'j' (journal record), 'a' (audit record), or 'l' (log record).", 0},
	{"data", 'd', "D", 0, "Specifies which section of the data should be dumped, options are 'a' for application metadata, 's' for system metadata, or 'p' for the payload (raw journal, audit, or log data). The default is to dump the system metadata. If this option is specified multiple times, the last occurance is used. To retrieve all portions of a record, use 'z'.", 0},
	{"path", 'p', "P", 0, "Copy the record to the provided path, '/P/'. This will create a sub-directory with the name <record_type>-<UUID>/ where <record_type> is replaced with 'journal', 'audit', or 'log', and <UUID> is replaced with the UUID for the record. This directory will always contain a file named 'system-metadata.xml', which is the system metadata for the record. If the record contains application metadata, the directory will also contain a file named 'application-metadata.xml' Depending on the type of record, this directory may contain a file named 'journal.bin' (for journal records), 'log.bin' (for log records), or 'audit.xml' for audit records. '~' expansion will only work with --path <~path> and not with --path=<~/path>", 0},
	{"home", 'h', "H", 0, "Specify the root of the JALoP database, defaults to /var/lib/jalop/db. The entered path must immediately follow the option. '~' expansion will only work with --home <~path> and not with --home=<~path>.", 0},
	{"write", 'w', NULL, 0, "Signals for a list of nonces in the JALoP database to be written to a file for each record type.", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

struct jd_config_context {
	char **uuid;
	char data;
	char type;
	char *path;
	char *home;
	int num_uuid;
	int uuid_arr_sz;
};

void print_payload(uint8_t *payload_buf, size_t payload_size);

int print_record(jaldb_context *ctx, char *uuid, char data, char *path, struct jaldb_record *rec);

static void print_error(enum jaldb_status error);

int dump_records_by_uuid(jaldb_context *ctx, enum jaldb_rec_type rtype, char data, char *path, char **uuid_arr,
	int num_uuid, enum jaldb_status *ret_status);

/**
 * Utility function to dynamically grow an array as needed.
 * If (*max_elms == elm_count) then the array is grown.
 * @param arr [in,out] The array to grow
 * @param max_elms [in,out] The original and new maximum size of the array
 * @param elm_count [in] The current number of elements in the array.
 */
static void ensure_capacity(char ***arr, int *max_elms, int elm_count);

static void print_uuids(jaldb_context *ctx, char type);
static void print_list_stdout(const list<string> &p_list);
static void print_list_file(const list<string> &p_list, const char *p_file_name);

static string get_type(enum jaldb_rec_type type);
static string get_state(enum jaldb_sync_stat state);
static string get_string_value(char * char_string);
static string get_uuid_value(uuid_t uuid);
static int jal_meta_write(int fd, struct jaldb_record *rec);

static const size_t BUF_SIZE = 8192;
static int write_uuid_flag = 0;

int main(int argc, char **argv) {
	//#884 - Turn off line buffering to prevent payload getting printed to stdout out of
	//order when redirecting output to a file.
	setvbuf(stdout, NULL, _IONBF, 0);

	int counter = 0;
	int ret = 0;
	enum jaldb_rec_type rtype = JALDB_RTYPE_UNKNOWN;

	struct jd_config_context jd_conf_ctx = {NULL, 0, 0, NULL, NULL, 0, INITIAL_ARRAY_SIZE};

	jd_conf_ctx.uuid = (char **) malloc(jd_conf_ctx.uuid_arr_sz * sizeof(char*));
	if (!(jd_conf_ctx.uuid)) {
		printf("Insufficient memory for uuid storage. Closing.\n");
		exit(-1);
	}

	int err = argp_parse(&argp, argc, argv, 0, 0, &jd_conf_ctx);
	if(0 != err) {
		fprintf(stderr, "ERROR: Cannot parse command line arguments.\n");
		return -1;
	}
	char **uuid = jd_conf_ctx.uuid;
	char data = jd_conf_ctx.data;
	char type = jd_conf_ctx.type;
	char *path = jd_conf_ctx.path;
	char *home = jd_conf_ctx.home;
	int num_uuid = jd_conf_ctx.num_uuid;

	enum jaldb_status jaldb_ret = JALDB_OK;
	jaldb_context *ctx = jaldb_context_create();

	jaldb_ret = jaldb_context_init(ctx, home, JDB_READONLY);

	if (jaldb_ret != JALDB_OK) {
		printf("\nContext could not be made.\n");
		print_error(jaldb_ret);
		goto err_out;
	}

	if (write_uuid_flag) {
		print_uuids(ctx, type);
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
	for (counter = 0; counter < (num_uuid); counter++) {
	}
	for (counter = 0; counter < (num_uuid); counter++) {
		free(*(uuid + counter));
	}
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

int dump_records_by_uuid(jaldb_context *ctx, enum jaldb_rec_type rtype, char data, char *path, char **id_arr,
			int num_id, enum jaldb_status *ret_status)
{
	int cnt = 0;
	int ret_err = 0;
	char *nonce = NULL;

	for (cnt = 0; cnt < num_id; cnt++) {
		struct jaldb_record *rec = NULL;

		if (cnt < num_id) {
			uuid_t uuid;
			if (0 != uuid_parse(*(id_arr + cnt), uuid)) {
				fprintf(stderr, "Bad UUID (ignoring): %s\n", *(id_arr + cnt));
				continue;
			} else {
				*ret_status = jaldb_get_record_by_uuid(ctx, rtype, uuid, &nonce, &rec);
			}
		}

		if (*ret_status != JALDB_OK) {
			ret_err = -1;
			return ret_err;
		}

		char uuid[37];
		uuid_unparse(rec->uuid, uuid);
		ret_err = print_record(ctx, uuid, data, path, rec);
		free(nonce);
		nonce = NULL;

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

string get_type(enum jaldb_rec_type type)
{
	switch (type)
	{
		case (JALDB_RTYPE_JOURNAL):
			return "JALDB_RTYPE_JOURNAL";
		case (JALDB_RTYPE_AUDIT):
			return "JALDB_RTYPE_AUDIT";
		case (JALDB_RTYPE_LOG):
			return "JALDB_RTYPE_LOG";
		default:
			return "JALDB_RTYPE_UNKNOWN";
	}
}

string get_state(enum jaldb_sync_stat state)
{
	switch (state)
	{
		case (JALDB_NOT_SENT):
			return "JALDB_NOT_SENT";
		case (JALDB_SENT):
			return "JALDB_SENT";
		case (JALDB_SYNCED):
			return "JALDB_SYNCED";
		default:
			return "UNKNOWN";
	}
}

string get_string_value(char * char_string){
	string value = "";
	if(char_string!=NULL){
		value = char_string;
	}
	return value;
}
string get_uuid_value(uuid_t uuid){
	char uuid_str[UUID_STR_LEN];
	uuid_unparse(uuid, uuid_str);
	return uuid_str;
}
int jal_meta_write(int fd, struct jaldb_record *rec)
{
	std::stringstream metaout;
	string confirmed = "false";
	if(rec->confirmed == 1){
		confirmed = "true";
	}
	metaout << "confirmed: " << confirmed << endl;
	metaout << "synced: " << get_state(rec->synced) << endl;
	metaout << "host_uuid: " << get_uuid_value(rec->host_uuid) << endl;
	metaout << "hostname: " << get_string_value(rec->hostname) << endl;
	metaout << "network_nonce: " << get_string_value(rec->network_nonce) << endl;
	metaout << "pid: " << rec->pid << endl;
	metaout << "uid: " << rec->uid << endl;
	metaout << "username: " << get_string_value(rec->username) << endl;
	metaout << "sec_lbl: " << get_string_value(rec->sec_lbl) << endl;
	metaout << "source: " << get_string_value(rec->source) << endl;
	metaout << "timestamp: " << get_string_value(rec->timestamp) << endl;
	metaout << "type: " << get_type(rec->type) << endl;
	metaout << "record uuid: " << get_uuid_value(rec->uuid) << endl;
	metaout << "version: " << rec->version << endl;
	int ret = write(fd, metaout.str().c_str(), metaout.str().length());
	if (-1 == ret) {
		return -1;
	}
	return ret;
}

int print_record(jaldb_context *ctx, char *uuid, char data, char *path, struct jaldb_record *rec)
{
	ssize_t ret = 0;
	//Initialize path to write to
	int fd_sys = -1;
	int fd_app = -1;
	int fd_dat = -1;
	int fd_meta = -1;
	char *tmpstr = NULL;
	char *sysstr = NULL;
	char *appstr = NULL;
	char *datstr = NULL;
	char *metastr = NULL;
	if (!path) {
		if (('m' == data || 'z' == data)) {
			printf("\nDatabase Record Metadata\n");
			printf("------------------------\n");
			if (0 > jal_meta_write(fileno(stdout), rec)) {
				ret = -1;
				goto out;
			}
		}
		if (('a' == data || 'z' == data)) {
			printf("\napplication metadata\n");
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
			jal_asprintf(&tmpstr, "%sjournal-%s/", path, uuid);
			jal_asprintf(&datstr, "%sjournal.bin",tmpstr);
			break;
		case JALDB_RTYPE_AUDIT:
			jal_asprintf(&tmpstr, "%saudit-%s/", path, uuid);
			jal_asprintf(&datstr, "%saudit.xml",tmpstr);
			break;
		case JALDB_RTYPE_LOG:
			jal_asprintf(&tmpstr, "%slog-%s/", path, uuid);
			jal_asprintf(&datstr, "%slog.bin",tmpstr);
			break;
		default:
			goto out;
		}

		//Make the sub-directory
		ret = jal_create_dirs(tmpstr);
		if (ret != JAL_OK) {
			fprintf(stderr, "Error creating directories");
			goto out;
		}

		jal_asprintf(&sysstr, "%ssystem-metadata.xml", tmpstr);
		jal_asprintf(&appstr, "%sapplication-metadata.xml", tmpstr);
		jal_asprintf(&metastr, "%sdatabase-record-metadata.txt",tmpstr);

		fd_meta = open(metastr, O_RDWR|O_CREAT|O_TRUNC, 0600); 	// Delete existing file(O_TRUNC)?
		if (fd_meta == -1) {
			perror("Error Opening Record Metadata Doc");
			ret = -1;
			goto out;
		}
		if (0 < jal_meta_write(fd_meta, rec)) {
			printf("Path for record meta data is %s.\n", metastr);
		} else {
			ret = -1;
			goto out;
		}

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
	free(metastr);
	if ((0 <= fd_sys) && (-1 == close(fd_sys))) {
		perror("Error closing system metadata");
	}
	if ((0 <= fd_app) && (-1 == close(fd_app))) {
		perror("Error closing system metadata");
	}
	if ((0 <= fd_dat) && (-1 == close(fd_dat))) {
		perror("Error closing system metadata");
	}
	if ((0 <= fd_meta) && (-1 == close(fd_meta))) {
		perror("Error closing database record metadata");
	}

	return ret;
}

static error_t parse_opt(int key_in,
		char *arg, struct argp_state *state)
{
	int counter = 0;
	struct jd_config_context * jd_conf_ctx = (struct jd_config_context *)(state->input);
	static const char *defdir = "/var/lib/jalop/db";

	switch (key_in)
	{
		case 'u':
			ensure_capacity(&(jd_conf_ctx->uuid), &(jd_conf_ctx->uuid_arr_sz), jd_conf_ctx->num_uuid);
			(jd_conf_ctx->uuid)[jd_conf_ctx->num_uuid] = strdup(arg);
			(jd_conf_ctx->num_uuid)++;
			break;
		case 't':
			if (('j' != *arg) && ('a' != *arg) && ('l' != *arg)) {
				fprintf(stderr, "\nType invalid\n");
				goto err_usage;
			}
			jd_conf_ctx->type = *arg;
			break;
		case 'd':
			if (('a' != *arg) && ('s' != *arg) && ('p' != *arg) && ('z' != *arg) && ('m' != *arg)) {
				jd_conf_ctx->data = 's';
			} else {
				jd_conf_ctx->data = *arg;
			}
			break;
		case 'p':
			jd_conf_ctx->path = strdup(arg);
			char *new_path;
			new_path = NULL;
			if ((jd_conf_ctx->path)[strlen((jd_conf_ctx->path))-1] != '/') {
				jal_asprintf(&new_path, "%s/", jd_conf_ctx->path);
				free(jd_conf_ctx->path);
				jd_conf_ctx->path = new_path;
			}
			break;
		case 'h':
			if (NULL == arg) {
				fprintf(stderr, "arg was null. Home directory defaulting to /var/lib/jalop/db\n");
				jd_conf_ctx->home = strdup(defdir);
			} else {
				jd_conf_ctx->home = strdup(arg);
			}
			break;
		case 'w':
			write_uuid_flag = 1;
			break;
		case ARGP_KEY_END:
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;

err_usage:

	printf("\nError: Usage\n");
	for (counter = 0; counter < (jd_conf_ctx->num_uuid); counter++) {
		free(*(jd_conf_ctx->uuid + counter));
	}

	free(jd_conf_ctx->uuid);
	if (jd_conf_ctx->path != NULL) {
		free(jd_conf_ctx->path);
	}
	if (jd_conf_ctx->home != NULL) {
		free(jd_conf_ctx->home);
	}
	argp_usage(state);
	exit(-1);
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
		case JALDB_E_NONCE:
			printf("JALDB_E_NONCE");
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
	printf("Failed to alloc memory for nonces");
	exit(-1);
}

static void print_uuids(jaldb_context *ctx, char type)
{
	enum jaldb_status db_ret = JALDB_E_UNKNOWN;

	list<string> *doc_list = NULL;
	string print_list_filename;

	printf("UUIDs:\n");
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
		printf("%d\n", db_ret);
		goto err_out;
	}
	doc_list->remove(JALDB_NONCE_DOC_NAME);
	print_list_stdout(*doc_list);
	print_list_file(*doc_list, print_list_filename.c_str());
	delete(doc_list);
	return;
err_out:
	printf("Failed to retrieve UUIDs from the database");
	delete(doc_list);
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
		printf("Write nonces failed! No documents were found!\n");
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
			printf("\nWrite nonces success! Check your directory for %s\n\n",
			p_file_name);
		}
		else {
			printf("\nWrite nonces failed! Unable to open file: %s\n\n",
			p_file_name);
		}
	}
}

