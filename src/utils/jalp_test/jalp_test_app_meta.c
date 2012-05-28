/**
 * @file jalp_test_app_meta.c This file contains functionsa for generating app metadata
 *
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
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <jalop/jal_status.h>
#include <jalop/jalp_app_metadata.h>

#include "jalp_test_app_meta.h"

#define REQUIRED 1
#define OPTIONAL 0

static int generate_sd(config_setting_t *sd_list, struct jalp_structured_data **app_sd);

static int generate_location(config_setting_t *location, struct jalp_stack_frame **app_location);

static int generate_transforms(config_setting_t *transforms, struct jalp_transform **jalp_transforms);

static int generate_file_info(config_setting_t *file_info, struct jalp_file_info *jalp_app_file_info);

static int get_media_type(const char *media_type);

static int get_transform_type(const char *transform_type);

static int jalptest_config_lookup_string(const config_setting_t *setting,
	const char *name, char **jalp_app_sfield, int required);

static int jalptest_config_lookup_int(const config_setting_t *setting,
	const char *name, int *result, int required);


int generate_app_metadata(const char *app_meta_path, struct jalp_app_metadata **app_metadata,
	char **hostname, char **appname)
{

	if (!app_metadata || *app_metadata || !hostname || !appname
		|| *hostname || *appname) {
		//this should never happen.
		return -1;
	}

	if (!app_meta_path) {
		//this is not an error, and app_metadata should be left NULL
		return 0;
	}

	config_t app_meta_config;
	config_init(&app_meta_config);

	int ret = config_read_file(&app_meta_config, app_meta_path);
	if (ret == CONFIG_FALSE) {
		printf("parse error: \"%s\" line %d\n",
			config_error_text(&app_meta_config), config_error_line(&app_meta_config));
		return -1;
	}

	struct jalp_app_metadata *new_app_meta = NULL;
	new_app_meta = jalp_app_metadata_create();

	if (-1 == jalptest_config_lookup_string(config_root_setting(&app_meta_config), "eventID", &new_app_meta->event_id, OPTIONAL)) {
		goto err_out;
	}

	config_setting_t *syslog = NULL;
	syslog = config_lookup(&app_meta_config, "syslog");
	if (syslog) {
		new_app_meta->sys = jalp_syslog_metadata_create();
		new_app_meta->type = JALP_METADATA_SYSLOG;

		int syslog_facility = -1;
		if (-1 == jalptest_config_lookup_int(syslog, "facility", &syslog_facility, OPTIONAL)) {
			goto err_out;
		}
		if (syslog_facility > INT8_MAX || syslog_facility < INT8_MIN) {
			printf("Error: line %d: invalid value for \"facility\"\n",
				config_setting_source_line(config_setting_get_member(syslog, "facility")));
			goto err_out;
		}
		new_app_meta->sys->facility = syslog_facility;

		int syslog_severity = -1;
		if (-1 == jalptest_config_lookup_int(syslog, "severity", &syslog_severity, OPTIONAL)) {
			goto err_out;
		}
		if (syslog_severity > INT8_MAX || syslog_severity < INT8_MIN) {
			printf("Error: line %d: invalid value for \"severity\"\n",
				config_setting_source_line(config_setting_get_member(syslog, "severity")));
			goto err_out;
		}
		new_app_meta->sys->severity = syslog_severity;

		if (-1 == jalptest_config_lookup_string(syslog, "entry", &new_app_meta->sys->entry, OPTIONAL)) {
			goto err_out;
		}

		if (-1 == jalptest_config_lookup_string(syslog, "timestamp", &new_app_meta->sys->timestamp, OPTIONAL)) {
			goto err_out;
		}

		if (-1 == jalptest_config_lookup_string(syslog, "hostname", hostname, OPTIONAL)) {
			goto err_out;
		}

		if (-1 == jalptest_config_lookup_string(syslog, "appName", appname, OPTIONAL)) {
			goto err_out;
		}

		if (-1 == jalptest_config_lookup_string(syslog, "messageID", &new_app_meta->sys->message_id, OPTIONAL)) {
			goto err_out;
		}

		//Structured Data
		config_setting_t *sd_list = NULL;
		sd_list = config_lookup(&app_meta_config, "syslog.sdList");
		if (sd_list) {
			if (0 != generate_sd(sd_list, &new_app_meta->sys->sd_head)) {
				goto err_out;
			}
		}
	}

	config_setting_t *logger = NULL;
	logger = config_lookup(&app_meta_config, "logger");
	if (logger) {
		//cannot have both logger and syslog
		if (new_app_meta->sys) {
			printf("Error: line %d: specified both logger and syslog\n", config_setting_source_line(logger));
			goto err_out;
		}
		new_app_meta->log = jalp_logger_metadata_create();
		new_app_meta->type = JALP_METADATA_LOGGER;

		if (-1 == jalptest_config_lookup_string(logger, "Name", &new_app_meta->log->logger_name, OPTIONAL)) {
			goto err_out;
		}

		//Severity
		config_setting_t *logger_severity = NULL;
		logger_severity = config_setting_get_member(logger, "severity");
		if (logger_severity) {
			new_app_meta->log->severity = jalp_log_severity_create();
			if (-1 == jalptest_config_lookup_int(logger_severity, "level", &new_app_meta->log->severity->level_val, REQUIRED)) {
				goto err_out;
			}
			if (-1 == jalptest_config_lookup_string(logger_severity, "name", &new_app_meta->log->severity->level_str, OPTIONAL)) {
				goto err_out;
			}
		}

		if (-1 == jalptest_config_lookup_string(logger, "timestamp", &new_app_meta->log->timestamp, OPTIONAL)) {
			goto err_out;
		}

		if (-1 == jalptest_config_lookup_string(logger, "hostname", hostname, OPTIONAL)) {
			goto err_out;
		}

		if (-1 == jalptest_config_lookup_string(logger, "appName", appname, OPTIONAL)) {
			goto err_out;
		}

		if (-1 == jalptest_config_lookup_string(logger, "threadID", &new_app_meta->log->threadId, OPTIONAL)) {
			goto err_out;
		}

		if (-1 == jalptest_config_lookup_string(logger, "message", &new_app_meta->log->message, OPTIONAL)) {
			goto err_out;
		}

		//Location (i.e. stack)
		config_setting_t *location = NULL;
		location = config_setting_get_member(logger, "location");
		if (location) {
			if (0 != generate_location(location, &new_app_meta->log->stack)) {
				goto err_out;
			}
		}

		if (-1 == jalptest_config_lookup_string(logger, "ndc", &new_app_meta->log->nested_diagnostic_context, OPTIONAL)) {
			goto err_out;
		}

		if (-1 == jalptest_config_lookup_string(logger, "mdc", &new_app_meta->log->mapped_diagnostic_context, OPTIONAL)) {
			goto err_out;
		}

		//Structured Data
		config_setting_t *sd_list = NULL;
		sd_list = config_setting_get_member(logger, "sd");
		if (sd_list) {
			if (0 != generate_sd(sd_list, &new_app_meta->log->sd)) {
				goto err_out;
			}
		}
	}

	const char *custom = NULL;
	if (config_lookup_string(&app_meta_config, "custom", &custom)) {
		//cannot have both custom and log or sys
		if (new_app_meta->sys) {
			goto err_out;
		}
		new_app_meta->custom = strdup(custom);
		new_app_meta->type = JALP_METADATA_CUSTOM;
	}

	config_setting_t *journal = NULL;
	journal = config_lookup(&app_meta_config, "journal");
	if (journal) {
		new_app_meta->file_metadata = jalp_journal_metadata_create();
		new_app_meta->file_metadata->file_info = jalp_file_info_create();

		//file info
		config_setting_t *file_info = NULL;
		file_info = config_setting_get_member(journal, "file_info");
		if (file_info) {
			if (0 != generate_file_info(file_info, new_app_meta->file_metadata->file_info)) {
				goto err_out;
			}
		} else {
			printf("Error: line %d: missing required field \"file_info\"\n", config_setting_source_line(journal));
			goto err_out;
		}

		//transforms
		config_setting_t *transforms = NULL;
		transforms = config_setting_get_member(journal, "transforms");
		if (transforms) {
			if (0 != generate_transforms(transforms, &new_app_meta->file_metadata->transforms)) {
				goto err_out;
			}
		}
	}

	config_destroy(&app_meta_config);
	*app_metadata = new_app_meta;
	return 0;

err_out:

	jalp_app_metadata_destroy(&new_app_meta);
	config_destroy(&app_meta_config);
	return -1;
}

static int generate_sd(config_setting_t *sd_list, struct jalp_structured_data **app_sd)
{
	int count = 0;
	if (sd_list) {
		count = config_setting_length(sd_list);
	}
	struct jalp_structured_data *tmp_jalp_sd = NULL;
	for(int i = 0; i < count; i++) {
		config_setting_t *tmp_sd = config_setting_get_elem(sd_list, i);
		char *sd_id = NULL;
		/* fail if missing sd_id (required field) */
		if (-1 == jalptest_config_lookup_string(tmp_sd, "id", &sd_id, REQUIRED)) {
			goto sd_err;
		}
		tmp_jalp_sd = jalp_structured_data_append(tmp_jalp_sd, sd_id);
		free(sd_id);
		if (i == 0) {
			*app_sd = tmp_jalp_sd;
		}
		//add param list
		config_setting_t *param_list = NULL;
		param_list = config_setting_get_member(tmp_sd, "fields");
		int param_count = 0;
		if (param_list) {
			param_count = config_setting_length(param_list);
		}
		struct jalp_param *tmp_jalp_param = NULL;
		for(int j = 0; j < param_count; j++) {
			config_setting_t *tmp_param = config_setting_get_elem(param_list, j);
			char *key = NULL;
			char *value = NULL;
			/* fail if either of these required fields are missed */
			if (-1 == jalptest_config_lookup_string(tmp_param, "key", &key, REQUIRED)) {
				goto sd_err;
			}
			if (-1 == jalptest_config_lookup_string(tmp_param, "value", &value, REQUIRED)) {
				goto sd_err;
			}
			tmp_jalp_param = jalp_param_append(tmp_jalp_param, key, value);
			free(key);
			free(value);
			if (j == 0) {
				tmp_jalp_sd->param_list = tmp_jalp_param;
			}
		}
	}

	return 0;

sd_err:
	return -1;
}

static int generate_location(config_setting_t *location, struct jalp_stack_frame **app_location) {

	int count = 0;
	if (location) {
		count = config_setting_length(location);
	}
	struct jalp_stack_frame *tmp_jalp_stack = NULL;
	for(int i = 0; i < count; i++) {
		config_setting_t *stack = config_setting_get_elem(location, i);

		tmp_jalp_stack = jalp_stack_frame_append(tmp_jalp_stack);

		long long line_number = 0;
		config_setting_lookup_int64(stack, "lineNumber", &line_number);
		tmp_jalp_stack->line_number = (uint64_t)line_number;
		if (-1 == jalptest_config_lookup_string(stack, "callerName", &tmp_jalp_stack->caller_name, OPTIONAL)) {
			goto err_out;
		}
		if (-1 == jalptest_config_lookup_string(stack, "filename", &tmp_jalp_stack->file_name, OPTIONAL)) {
			goto err_out;
		}
		if (-1 == jalptest_config_lookup_string(stack, "className", &tmp_jalp_stack->class_name, OPTIONAL)) {
			goto err_out;
		}
		if (-1 == jalptest_config_lookup_string(stack, "methodName", &tmp_jalp_stack->method_name, OPTIONAL)) {
			goto err_out;
		}
		if (-1 == jalptest_config_lookup_int(stack, "depth", &tmp_jalp_stack->depth, OPTIONAL)) {
			goto err_out;
		}
			if (i == 0) {
			*app_location = tmp_jalp_stack;
		}
	}
	return 0;

err_out:
	return -1;
}

static int get_media_type(const char *media_type) {
	if (0 == strcmp(media_type, "application")) {
		return JALP_MT_APPLICATION;
	}

	if (0 == strcmp(media_type, "audio")) {
		return JALP_MT_AUDIO;
	}

	if (0 == strcmp(media_type, "example")) {
		return JALP_MT_EXAMPLE;
	}

	if (0 == strcmp(media_type, "image")) {
		return JALP_MT_IMAGE;
	}

	if (0 == strcmp(media_type, "message")) {
		return JALP_MT_MESSAGE;
	}

	if (0 == strcmp(media_type, "model")) {
		return JALP_MT_MODEL;
	}

	if (0 == strcmp(media_type, "text")) {
		return JALP_MT_TEXT;
	}

	if (0 == strcmp(media_type, "video")) {
		return JALP_MT_VIDEO;
	}
	return -1;

}

static int get_transform_type(const char *transform_type) {
	if (0 == strcmp(transform_type, "other")) {
		return JALP_TRANSFORM_OTHER;
	}

	if (0 == strcmp(transform_type, "AES-128")) {
		return JALP_TRANSFORM_AES128;
	}

	if (0 == strcmp(transform_type, "AES-192")) {
		return JALP_TRANSFORM_AES192;
	}

	if (0 == strcmp(transform_type, "AES-256")) {
		return JALP_TRANSFORM_AES256;
	}

	if (0 == strcmp(transform_type, "xor")) {
		return JALP_TRANSFORM_XOR;
	}

	if (0 == strcmp(transform_type, "deflate")) {
		return JALP_TRANSFORM_DEFLATE;
	}

	return -1;
}

static int generate_file_info(config_setting_t *file_info, struct jalp_file_info *jalp_app_file_info)
{
	if (-1 == jalptest_config_lookup_string(file_info, "filename", &jalp_app_file_info->filename, OPTIONAL)) {
		goto err_file_info;
	}
	long long original_size = 0;
	config_setting_lookup_int64(file_info, "originalSize", &original_size);
	jalp_app_file_info->original_size = (uint64_t)original_size;

	config_setting_t *content_type = NULL;
	content_type = config_setting_get_member(file_info, "contentType");
	if (content_type) {
		jalp_app_file_info->content_type = jalp_content_type_create();
		char *media_type = NULL;
		if (-1 == jalptest_config_lookup_string(content_type, "mediaType", &media_type, REQUIRED)) {
			goto err_file_info;
		}
		int enum_media_type = get_media_type(media_type);
		free(media_type);
		if (-1 == enum_media_type) {
			printf("Error: line %d: invalid value for field \"mediaType\"\n",
				config_setting_source_line(config_setting_get_member(content_type, "mediaType")));
			goto err_file_info;
		}
		jalp_app_file_info->content_type->media_type = enum_media_type;

		if (-1 == jalptest_config_lookup_string(content_type, "subType", &jalp_app_file_info->content_type->subtype, OPTIONAL)) {
			goto err_file_info;
		}
		//params
		config_setting_t *param_list = NULL;
		param_list = config_setting_get_member(content_type, "params");
		int param_count = 0;
		if (param_list) {
			param_count = config_setting_length(param_list);
		}
		struct jalp_param *tmp_jalp_param = NULL;
		for(int j = 0; j < param_count; j++) {
			config_setting_t *tmp_param = config_setting_get_elem(param_list, j);
			char *key = NULL;
			char *value = NULL;
			/* fail if either of these required fields are missed */
			if (-1 == jalptest_config_lookup_string(tmp_param, "key", &key, REQUIRED)) {
				goto err_file_info;
			}
			if (-1 == jalptest_config_lookup_string(tmp_param, "value", &value, REQUIRED)) {
				goto err_file_info;
			}
			tmp_jalp_param = jalp_param_append(tmp_jalp_param, key, value);
			free(key);
			free(value);
			if (j == 0) {
				jalp_app_file_info->content_type->params = tmp_jalp_param;
			}
		}
	}

	char *threat_level = NULL;
	if (-1 == jalptest_config_lookup_string(file_info, "threatLevel", &threat_level, OPTIONAL)) {
		goto err_file_info;
	}

	if (NULL == threat_level) {
		goto out;
	} else if (0 == strcmp("malicious", threat_level)) {
		jalp_app_file_info->threat_level = JAL_THREAT_MALICIOUS;
	} else if (0 == strcmp("safe", threat_level)) {
		jalp_app_file_info->threat_level = JAL_THREAT_SAFE;
	} else if (0 == strcmp("unknown", threat_level)) {
		jalp_app_file_info->threat_level = JAL_THREAT_UNKNOWN;
	} else if (NULL != threat_level) {
		printf("Error: line %d: invalid value for field \"threatLevel\"\n",
			config_setting_source_line(config_setting_get_member(file_info, "threatLevel")));

		goto err_file_info;
	}
	free(threat_level);

out:
	return 0;

err_file_info:

	return -1;

}

static int generate_transforms(config_setting_t *transforms, struct jalp_transform **jalp_transforms)
{
	struct jalp_transform *tmp_jalp_transform = NULL;
	int count = 0;
	if (transforms) {
		count = config_setting_length(transforms);
	}
	for (int i = 0; i < count; i++) {
		config_setting_t *tmp_transform = config_setting_get_elem(transforms, i);
		char *transform_type = NULL;
		if (-1 == jalptest_config_lookup_string(tmp_transform, "type", &transform_type, REQUIRED)) {
			goto err_transform;
		}
		int enum_transform_type = get_transform_type(transform_type);
		free(transform_type);
		char *xml = NULL;
		if (-1 == jalptest_config_lookup_string(tmp_transform, "xml", &xml, OPTIONAL)) {
			goto err_transform;
		}
		char *uri = NULL;
		if (-1 == jalptest_config_lookup_string(tmp_transform, "uri", &uri, OPTIONAL)) {
			goto err_transform;
		}
		//iv
		config_setting_t *iv = NULL;
		iv = config_setting_get_member(tmp_transform, "iv");
		uint8_t *iv_buf = NULL;
		if (iv) {
			if (4 != config_setting_length(iv)) {
				printf("Error: line %d: \"iv\" should consist of four 32 bit ints\n",
					config_setting_source_line(iv));
				goto err_transform;
			}
		iv_buf = (uint8_t *)malloc(16);
			for (int j = 0; j < 4; j++) {
				config_setting_t *tmp_iv = config_setting_get_elem(iv, j);
				int tmp_iv_data = config_setting_get_int(tmp_iv);
				uint32_t tmp_iv_be = htonl((uint32_t)tmp_iv_data);
				memcpy(iv_buf + 4 * j, &tmp_iv_be, 4);
			}
		}
		//key
		config_setting_t *key = NULL;
		key = config_setting_get_member(tmp_transform, "key");
		uint8_t *key_buf = NULL;
		int key_count = 0;
		if (key) {
			key_count = config_setting_length(key);
			key_buf = (uint8_t *)malloc(key_count * 4);
			for (int j = 0; j < key_count; j++) {
				config_setting_t *tmp_key = config_setting_get_elem(key, j);
				int tmp_key_data = config_setting_get_int(tmp_key);
				uint32_t tmp_key_be = htonl((uint32_t)tmp_key_data);
				memcpy(key_buf + 4 * j, &tmp_key_be, 4);
			}
		}
		if(enum_transform_type != JALP_TRANSFORM_OTHER && (uri)) {
			printf("Warning: line %d: specified uri is unused",
				config_setting_source_line(config_setting_get_member(tmp_transform, "uri")));
		}

		if(enum_transform_type != JALP_TRANSFORM_OTHER && (xml)) {
			printf("Warning: line %d: specified xml is unused",
				config_setting_source_line(config_setting_get_member(tmp_transform, "xml")));
		}

		switch (enum_transform_type) {
			case (JALP_TRANSFORM_OTHER):
				tmp_jalp_transform = jalp_transform_append_other(tmp_jalp_transform, uri, xml);
				if (NULL == tmp_jalp_transform) {
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
					goto err_transform;
				}
				break;
			case (JALP_TRANSFORM_AES128):
				if (key_count != 4 && key_count != 0) {
					printf("Error: line %d: key is invalid\n", config_setting_source_line(key));
					goto err_transform;
				}
				tmp_jalp_transform = jalp_transform_append_aes(tmp_jalp_transform, JALP_AES128, key_buf, iv_buf);
				if (NULL == tmp_jalp_transform) {
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
					goto err_transform;
				}
				break;
			case (JALP_TRANSFORM_AES192):
				if (key_count != 6 && key_count != 0) {
					printf("Error: line %d: key is invalid\n", config_setting_source_line(key));
					goto err_transform;
				}
				tmp_jalp_transform = jalp_transform_append_aes(tmp_jalp_transform, JALP_AES192, key_buf, iv_buf);
				if (NULL == tmp_jalp_transform) {
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
					goto err_transform;
				}
				break;
			case (JALP_TRANSFORM_AES256):
				if (key_count != 8 && key_count != 0) {
					printf("Error: line %d: key is invalid\n", config_setting_source_line(key));
					goto err_transform;
				}
				tmp_jalp_transform = jalp_transform_append_aes(tmp_jalp_transform, JALP_AES256, key_buf, iv_buf);
				if (NULL == tmp_jalp_transform) {
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
					goto err_transform;
				}
				break;
			case (JALP_TRANSFORM_DEFLATE):
				tmp_jalp_transform = jalp_transform_append_deflate(tmp_jalp_transform);
				if (NULL == tmp_jalp_transform) {
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
					goto err_transform;
				}
				break;
			case (JALP_TRANSFORM_XOR):
				tmp_jalp_transform = jalp_transform_append_xor(tmp_jalp_transform, *(uint32_t *)key_buf);
				free(key_buf);
				if (NULL == tmp_jalp_transform) {
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
					goto err_transform;
				}
				break;
			default: //should not be possible
				goto err_transform;
		}
		if (i == 0) {
			*jalp_transforms = tmp_jalp_transform;
		}
		free(xml);
		free(uri);
	}

	return 0;

err_transform:

	return -1;
}

static int jalptest_config_lookup_string(const config_setting_t *setting,
	const char *name, char **jalp_app_sfield, int required) {
	if (!setting || !name || !jalp_app_sfield || *jalp_app_sfield) {
		//should never happen
		printf("misuse of jalptest_config_lookup_string\n");
		goto err_out;
	}
	config_setting_t *member = config_setting_get_member(setting, name);
	if (!member && required) {
		printf("Error: line %d: missing required field \"%s\"\n",
			config_setting_source_line(setting), name);
		goto err_out;
	}
	if (!member) {
		goto out;
	}
	if(config_setting_type(member) != CONFIG_TYPE_STRING) {
		printf("Error: line %d: field \"%s\" should be a string\n",
			config_setting_source_line(member), name);
		goto err_out;
	}
	const char *tmp = config_setting_get_string(member);
	if (!tmp && required) {
		printf("Error: line %d: empty required field \"%s\"\n",
			config_setting_source_line(setting), name);
		goto err_out;
	}
	if (!tmp) {
		printf("Warning: line %d: empty value for field \"%s\"\n",
			config_setting_source_line(setting), name);
		goto out;
	}
	*jalp_app_sfield = strdup(tmp);
out:
	return 0;

err_out:

	return -1;
}

static int jalptest_config_lookup_int(const config_setting_t *setting,
	const char *name, int *result, int required) {
	if (!setting || !name || !result) {
		//should never happen
		printf("misuse of jalptest_config_lookup_int");
		goto err_out;
	}
	config_setting_t *member = config_setting_get_member(setting, name);
	if (!member && required) {
		printf("Error: line %d: missing required field \"%s\"",
			config_setting_source_line(setting), name);
		goto err_out;
	}
	if (!member) {
		goto out;
	}
	if(config_setting_type(member) != CONFIG_TYPE_INT) {
		printf("Error: line %d: field \"%s\" should be a 32 bit int",
			config_setting_source_line(member), name);
		goto err_out;
	}
	*result = config_setting_get_int(member);

out:
	return 0;

err_out:

	return -1;
}
