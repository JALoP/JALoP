/**
 * @file
 *
 * @brief This file contains jalp test functions
 *
 * ### LICENSE
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

//for getopt()
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>
#include <jalop/jalp_context.h>
#include <jalop/jalp_app_metadata.h>
#include <jalop/jalp_journal.h>
#include <jalop/jalp_audit.h>
#include <jalop/jalp_logger.h>
#include <jalop/jal_version.h>

#include "jalp_test_app_meta.h"


#define JALP_TEST_DEFEAULT_NUM_REPEAT (long) 1
#define DEFAULT_SCHEMA_DIR "/usr/share/jalop/schemas"

// argp
const char *argp_program_version = "2.0";
const char *argp_program_bug_address = 0;
static char args_doc[] = "";
static char doc[] =
	"jalp_test - JALoP database test utility.";
static error_t parse_opt(int key, char *arg, struct argp_state *state);
static struct argp_option options[] = {
	{"type", 't', "T", 0,
		"Indicates which type of data to send: 'j' (journal record), 'a' (an audit record), or 'l' (log entry), or 'f' (journal record using file descriptor passing).", 0},
	{"appmeta", 'a', "path", 0,
		"(optional) the full, or relative path to a file to use for generating the application metadata.", 0},
	{"payload", 'p', "path", 0,
		"The full or relative path to a file that should be used as the payload for this particular record.", 0},
	{"stdin", 's', NULL, 0,
		"Indicates the payload should be taken from <stdin>.", 0},
	{"socket", 'j', "path", 0,
		"The full or relative path to the JALoP socket.", 0},
	{"key", 'k', "path", 0,
		"The full or relative path to a key file to be used for signing. Must also specify '-a'.", 0},
	{"cert", 'c', "path", 0, " The full or relative path to a certificate file to be used for signing. Requires '-k'.", 0},
	{"digest", 'd', "D", 0, "Calculates and adds a digest of the payload to the application metadata. Defaults to 'sha256' if no algorithm is provided. Valid values are 'sha256', 'sha384', and 'sha512'. Must also specify '-a'.", 0},
	{"schemas", 'x', "path", 0, "The full or relative path to the JALoP Schemas.", 0},
	{"count", 'n', "num", 0, "The number of times to repeat an event. Must be a positive numeric value within the representable range.", 0},
	{"validate", 'v', NULL, 0, "Validate XML payload against a schema.", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

struct jp_config_context {
	char *app_meta_path;
	char *payload_path;
	char *key_path;
	char *cert_path;
	int stdin_payload;
	int calculate_sha;
	enum jal_digest_algorithm dgst_alg;
	int validate_xml;
	char record_type;
	char *schema_path;
	char *socket_path;
	long int repeat_cnt;
} jp_conf_ctx;

static int build_payload(int payload_fd, uint8_t ** payload_buf, size_t *payload_size);

static int build_payload_stdin(uint8_t ** payload_buf, size_t *payload_size);

void print_payload(uint8_t *payload_buf, size_t payload_size);

static void print_error(enum jal_status error);

static const size_t BUF_SIZE = 8192;

int main(int argc, char **argv)
{
	int err = 0;
	int rc = -1;
	jp_conf_ctx.app_meta_path = NULL;
	jp_conf_ctx.payload_path = NULL;
	jp_conf_ctx.key_path = NULL;
	jp_conf_ctx.cert_path = NULL;
	jp_conf_ctx.stdin_payload = 0;
	jp_conf_ctx.calculate_sha = 0;
	jp_conf_ctx.dgst_alg = JAL_DIGEST_ALGORITHM_DEFAULT;
	jp_conf_ctx.validate_xml = 0;
	jp_conf_ctx.record_type = 0;
	jp_conf_ctx.schema_path = NULL;
	jp_conf_ctx.socket_path = NULL;
	jp_conf_ctx.repeat_cnt = JALP_TEST_DEFEAULT_NUM_REPEAT;

	struct jalp_app_metadata *app_meta = NULL;
	uint8_t *payload_buf = NULL;
	size_t payload_size = 0;
	int payload_fd = 0;

	int ret;
	enum jal_status jalp_ret;

	char *hostname = NULL;
	char *appname = NULL;

	jalp_context *ctx = NULL;
	struct jal_digest_ctx *digest_ctx = NULL;

	err = argp_parse(&argp, argc, argv, 0, 0, &jp_conf_ctx);
	if(0 != err) {
		fprintf(stderr, "ERROR: Cannot parse command line arguments.\n");
		goto err_out;
	}

	int send_payload = (jp_conf_ctx.stdin_payload || (jp_conf_ctx.payload_path));

	jalp_ret = jalp_init();
	if (jalp_ret != JAL_OK) {
		goto err_out;
	}

	ret = generate_app_metadata(jp_conf_ctx.app_meta_path, &app_meta, &hostname, &appname);
	if (ret != 0) {
		goto err_out;
	}

	if (jp_conf_ctx.stdin_payload == 1) {
		payload_fd = STDIN_FILENO;
	} else if (jp_conf_ctx.payload_path) {
		payload_fd = open(jp_conf_ctx.payload_path, O_RDONLY);
	}
	if (payload_fd < 0) {
		printf("file open error\n");
		goto err_out;
	}

	ctx = jalp_context_create();
	jalp_ret = jalp_context_init(ctx, jp_conf_ctx.socket_path, hostname, appname, jp_conf_ctx.schema_path);
	if (jalp_ret != JAL_OK) {
		printf("error creating jalp context\n");
		goto err_out;
	}

	if(jp_conf_ctx.validate_xml != 0) {
		jalp_context_set_flag(ctx, JAF_VALIDATE_XML);
	}

	if (jp_conf_ctx.key_path) {
		jalp_ret = jalp_context_load_pem_rsa(ctx, jp_conf_ctx.key_path, NULL);
		if (jalp_ret != JAL_OK) {
			printf("error loading key from path: %s\n", jp_conf_ctx.key_path);
			goto err_out;
		}
	}

	if (jp_conf_ctx.cert_path) {
		jalp_ret = jalp_context_load_pem_cert(ctx, jp_conf_ctx.cert_path);
		if (jalp_ret != JAL_OK) {
			printf("error loading cert from path: %s\n", jp_conf_ctx.cert_path);
			goto err_out;
		}
	}

	if(jp_conf_ctx.calculate_sha) {
		digest_ctx = jal_digest_ctx_create(jp_conf_ctx.dgst_alg);
		jalp_ret = jalp_context_set_digest_callbacks(ctx, digest_ctx);
		if (jalp_ret != JAL_OK) {
			printf("error setting digest callbacks\n");
			goto err_out;
		}
	}

	for(long int cnt = 0; cnt < jp_conf_ctx.repeat_cnt; cnt++) {
		switch(jp_conf_ctx.record_type) {
		case ('j'):
			if (send_payload && cnt == 0) {
				ret = build_payload(payload_fd, &payload_buf, &payload_size);
			}
			if (ret != 0) {
				printf("error building payload\n");
				goto err_out;
			}
			jalp_ret = jalp_journal(ctx, app_meta, payload_buf, payload_size);
			if (jalp_ret != JAL_OK) {
				printf("jalp_journal failed %d\n", jalp_ret);
				print_error(jalp_ret);
				goto err_out;
			}
			break;
		case ('a'):
			if (send_payload && cnt == 0) {
				ret = build_payload(payload_fd, &payload_buf, &payload_size);
			}
			if (ret != 0) {
				printf("error building payload\n");
				goto err_out;
			}
			jalp_ret = jalp_audit(ctx, app_meta, payload_buf, payload_size);
			if (jalp_ret != JAL_OK) {
				printf("jalp_audit failed %d\n", jalp_ret);
				print_error(jalp_ret);
				goto err_out;
			}
			break;
		case ('l'):
			if (send_payload && cnt == 0) {
				ret = build_payload(payload_fd, &payload_buf, &payload_size);
			}
			if (ret != 0) {
				printf("error building payload\n");
				goto err_out;
			}
			jalp_ret = jalp_log(ctx, app_meta, payload_buf, payload_size);
			if (jalp_ret != JAL_OK) {
				printf("jalp_log failed %d\n", jalp_ret);
				print_error(jalp_ret);
				goto err_out;
			}
			break;
		case ('f'):
			jalp_ret = jalp_journal_fd(ctx, app_meta, payload_fd);
			if (jalp_ret != JAL_OK) {
				printf("jalp_journal_fd failed %d\n", jalp_ret);
				print_error(jalp_ret);
				goto err_out;
			}
			break;
		default:
			//control should never reach here
			goto err_out;
		}
	}

	rc = 0;

err_out:
	if(payload_buf && !jp_conf_ctx.stdin_payload) {
		munmap(payload_buf, payload_size);
	}
	jalp_app_metadata_destroy(&app_meta);
	jalp_context_destroy(&ctx);
	jal_digest_ctx_destroy(&digest_ctx);
	jalp_shutdown();
	free(hostname);
	free(jp_conf_ctx.app_meta_path);
	free(appname);
	free(jp_conf_ctx.socket_path);
	free(jp_conf_ctx.payload_path);
	free(jp_conf_ctx.schema_path);

	if(payload_fd != STDIN_FILENO) {
		close(payload_fd);
	}

	return rc;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct jp_config_context * conf_ctx = (struct jp_config_context *)(state->input);
	switch (key)
	{
		case 'a':
			conf_ctx->app_meta_path = strdup(arg);
			break;
		case 'p':
			conf_ctx->payload_path = strdup(arg);
			break;
		case 's':
			if(arg) {
				goto err_usage;
			}
			conf_ctx->stdin_payload = 1;
			break;
		case 't':
			if(arg) {
				conf_ctx->record_type = *arg;
			} else {
				goto err_usage;
			}
			break;
		case 'j':
			conf_ctx->socket_path = strdup(arg);
			break;
		case 'k':
			conf_ctx->key_path = strdup(arg);
			break;
		case 'c':
			conf_ctx->cert_path = strdup(arg);
			break;
		case 'd':
			conf_ctx->calculate_sha = 1;
			conf_ctx->dgst_alg = JAL_DIGEST_ALGORITHM_DEFAULT;

			// If the digest=ALG format is used, arg contains the value
			if (arg) {
				enum jal_status status = jal_get_digest_from_str(arg, &(conf_ctx->dgst_alg));
				if (JAL_OK != status) {
					printf("Invalid digest found: %s\n", arg);
					goto err_usage;
				}
			}
			break;
		case 'x':
			conf_ctx->schema_path = strdup(arg);
			break;
		case 'n':
			errno = 0;
			char *end_ptr = NULL;
			long int tmp_cnt = strtol(arg, &end_ptr, 10);

			if(tmp_cnt && (LONG_MAX != tmp_cnt || ERANGE != errno)
				&& '\0' == *end_ptr) {
				conf_ctx->repeat_cnt = tmp_cnt;
			} else {
				goto err_usage;
			}
			break;
		case 'v':
			if(arg) {
				goto err_usage;
			}
			conf_ctx->validate_xml = 1;
			break;
		case ARGP_KEY_FINI:
			//check sanity of usage
			if (!(conf_ctx->app_meta_path) && ((conf_ctx->key_path) || (conf_ctx->calculate_sha))) {
				printf("Error: bad usage, must specify an app metadata path to use a key or calculate a sha\n");
				goto err_usage;
			}
			if (!(conf_ctx->key_path) && (conf_ctx->cert_path)) {
				printf("Error: bad usage, must specify a key path to use a certificate\n");
				goto err_usage;
			}
			if ((conf_ctx->payload_path) && (conf_ctx->stdin_payload)) {
				printf("Error: bad usage, cannot have both stdin payload and path specified payload\n");
				goto err_usage;
			}
			if ((conf_ctx->record_type) == 0 || ((conf_ctx->record_type) != 'j' && (conf_ctx->record_type) != 'a'
				&& (conf_ctx->record_type) != 'l' && (conf_ctx->record_type) != 'f')) {
				printf("Error: bad usage, record type of \'j\', \'a\', \'l\', or \'f\' must be specified\n");
				goto err_usage;
			}
			if ((conf_ctx->record_type == 'f') && (!(conf_ctx->payload_path))) {
				printf("Error: bad usage, record type of \'f\' requires a payload path\n");
				goto err_usage;
			}
			if ((conf_ctx->record_type == 'j' || conf_ctx->record_type == 'a') && (!(conf_ctx->payload_path)) && (!(conf_ctx->stdin_payload))) {
				printf("Error: bad usage, record type of \'j\' or \'a\' requires a payload\n");
				goto err_usage;
			}
			if (conf_ctx->repeat_cnt <= 0) {
				printf("Error: bad usage, the number of times to perform an event must be a positive number.\n");
				goto err_usage;
			}
			if (!(conf_ctx->app_meta_path) && ((conf_ctx->validate_xml) || (conf_ctx->calculate_sha))) {
				printf("Error: bad usage, must specify an app metadata path to validate XML or calculate a sha\n");
				goto err_usage;
			}
			if(!(conf_ctx->schema_path)) {
				(conf_ctx->schema_path) = strdup(DEFAULT_SCHEMA_DIR);
			}
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;

err_usage:
	argp_usage(state);
	exit(-1);
}


static int build_payload(int payload_fd, uint8_t ** payload_buf, size_t *payload_size)
{
	if(payload_fd < 0 || !payload_buf || *payload_buf || !payload_size) {
	//should never happen
		return -1;
	}
	if (payload_fd == STDIN_FILENO) {
		return build_payload_stdin(payload_buf, payload_size);
	}
	struct stat file_stat;
	if (fstat(payload_fd, &file_stat) == -1) {
		printf("fstat failed\n");
		return -1;
	}
	if (file_stat.st_size <= 0) {
		printf("file size was <= 0");
	}
	void *tmp_buf = mmap(NULL, file_stat.st_size, PROT_READ, MAP_PRIVATE, payload_fd, 0);
	if (tmp_buf == (void *)-1) {
		printf("mmap failed\n");
		perror("");
		return -1;
	}
	*payload_buf = tmp_buf;
	*payload_size = file_stat.st_size;
	return 0;
}

static int build_payload_stdin(uint8_t ** payload_buf, size_t *payload_size)
{
	ssize_t bytes_read = 0;
	uint8_t *buf = malloc(BUF_SIZE);
	uint8_t *tmp = buf;
	uint8_t *tmp_last = tmp + BUF_SIZE;
	ssize_t bytes_remaining = BUF_SIZE;
	int realloc_count = 0;


	while (0 < (bytes_read = read(STDIN_FILENO, tmp, bytes_remaining))) {
		tmp += bytes_read;
		bytes_remaining -= bytes_read;
		if (tmp == tmp_last) {
			realloc_count++;
			buf = realloc(buf, (1 + realloc_count) * BUF_SIZE);
			tmp = buf + (realloc_count * BUF_SIZE);
			tmp_last = tmp + BUF_SIZE;
			bytes_remaining = BUF_SIZE;
		}
		if (tmp > tmp_last) {//should never happen
			printf("read more than possible");
			goto err_out;
		}
	}
	if(bytes_read < 0) {
		goto err_out;
	}

	*payload_buf = buf;
	*payload_size = (1 + realloc_count) * BUF_SIZE - bytes_remaining;

	return 0;

err_out:

	free(buf);
	printf("Error building payload");
	return -1;
}

void print_payload(uint8_t *payload_buf, size_t payload_size)
{
	if (!payload_buf || 0 == payload_size) {
		return;
	}
	printf("payload(hex): 0x");
	for (size_t i = 0; i < payload_size; i++) {
		printf("%x", (payload_buf[i]));
	}
	char *str_payload = malloc(payload_size + 1);
	memcpy(str_payload, payload_buf, payload_size);
	str_payload[payload_size] = 0;
	printf("payload(char): %s\n", str_payload);
	printf("\n");
	free(str_payload);
}

static void print_error(enum jal_status error)
{
	switch (error) {
		case JAL_E_XML_PARSE:
			printf("JAL_E_XML_PARSE");
			break;
		case JAL_E_XML_SCHEMA:
			printf("JAL_E_XML_SCHEMA");
			break;
		case JAL_E_XML_CONVERSION:
			printf("JAL_E_XML_CONVERSION");
			break;
		case JAL_E_NOT_CONNECTED:
			printf("JAL_E_NOT_CONNECTED");
			break;
		case JAL_E_INVAL:
			printf("JAL_E_INVAL");
			break;
		case JAL_E_INVAL_PARAM:
			printf("JAL_E_INVAL_PARAM");
			break;
		case JAL_E_INVAL_CONTENT_TYPE:
			printf("JAL_E_INVAL_CONTENT_TYPE");
			break;
		case JAL_E_INVAL_STRUCTURED_DATA:
			printf("JAL_E_INVAL_STRUCTURED_DATA");
			break;
		case JAL_E_INVAL_URI:
			printf("JAL_E_INVAL_URI");
			break;
		case JAL_E_INVAL_TRANSFORM:
			printf("JAL_E_INVAL_TRANSFORM");
			break;
		case JAL_E_INVAL_FILE_INFO:
			printf("JAL_E_INVAL_FILE_INFO");
			break;
		case JAL_E_INVAL_SYSLOG_METADATA:
			printf("JAL_E_INVAL_SYSLOG_METADATA");
			break;
		case JAL_E_INVAL_LOGGER_METADATA:
			printf("JAL_E_INVAL_LOGGER_METADATA");
			break;
		case JAL_E_INVAL_TIMESTAMP:
			printf("JAL_E_INVAL_TIMESTAMP");
			break;
		case JAL_E_INVAL_NONCE:
			printf("JAL_E_INVAL_NONCE");
			break;
		case JAL_E_NO_MEM:
			printf("JAL_E_NO_MEM");
			break;
		case JAL_E_UNINITIALIZED:
			printf("JAL_E_UNINITIALIZED");
			break;
		case JAL_E_INITIALIZED:
			printf("JAL_E_INITIALIZED");
			break;
		case JAL_E_EXISTS:
			printf("JAL_E_EXISTS");
			break;
		case JAL_E_FILE_OPEN:
			printf("JAL_E_FILE_OPEN");
			break;
		case JAL_E_READ_PRIVKEY:
			printf("JAL_E_READ_PRIVKEY");
			break;
		case JAL_E_READ_X509:
			printf("JAL_E_READ_X509");
			break;
		case JAL_E_FILE_IO:
			printf("JAL_E_FILE_IO");
			break;
		case JAL_E_INVAL_APP_METADATA:
			printf("JAL_E_INVAL_APP_METADATA");
			break;
		case JAL_E_BAD_FD:
			printf("JAL_E_BAD_FD");
			break;
		case JAL_E_PARSE:
			printf("JAL_E_PARSE");
			break;
		case JAL_E_COMM:
			printf("JAL_E_COMM");
			break;
		case JAL_OK:
			break;
	}
	printf("\n");

}

