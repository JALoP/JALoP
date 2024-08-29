/**
 * @file jalp_test_app_meta.c This file contains functionsa for generating app metadata
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
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <jalop/jal_status.h>
#include <jalop/jalp_app_metadata.h>

#include "jal_config.h"
#include "jalp_test_app_meta.h"

static const int SYSLOG_FACILITY_MAX = 23;
static const int SYSLOG_SEVERITY_MAX = 7;

static int generate_sd(config_setting_t *sd_list, struct jalp_structured_data **app_sd);

static int generate_location(config_setting_t *location, struct jalp_stack_frame **app_location);

static int generate_transforms(config_setting_t *transforms, struct jalp_transform **jalp_transforms);

static int generate_file_info(config_setting_t *file_info, struct jalp_file_info *jalp_app_file_info);

static int get_media_type(const char *media_type);

static int get_transform_type(const char *transform_type);

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
	int error_seen = jal_config_init(&app_meta_config);

	if (JAL_CFG_SUCCESS != error_seen) {
		fprintf(stderr, "Error initializing config file");
		config_destroy(&app_meta_config);
		return -1;
	}

	int rc = jal_config_read_file(&app_meta_config, app_meta_path);
	if (JAL_CFG_SUCCESS != rc) {
		config_destroy(&app_meta_config);
		return -1;
	}

	config_setting_t *app_meta_root = config_root_setting(&app_meta_config);
	struct jalp_app_metadata *new_app_meta = NULL;
	new_app_meta = jalp_app_metadata_create();

	error_seen |= jal_config_lookup_string(app_meta_root, JALP_CFG_EVENT_ID, &new_app_meta->event_id, JAL_CFG_OPTIONAL);

	config_setting_t *syslog = NULL;
	error_seen |= jal_config_lookup(&app_meta_config, JALP_CFG_SYSLOG, &syslog, JAL_CFG_OPTIONAL);
	if (syslog) {
		new_app_meta->sys = jalp_syslog_metadata_create();
		new_app_meta->type = JALP_METADATA_SYSLOG;

		int syslog_facility = -1;
		error_seen |= jal_config_lookup_int(syslog, JALP_CFG_SL_FACILITY, &syslog_facility, JAL_CFG_OPTIONAL);

		// Restricted to 0-23 inclusive per schemas/applicationMetadataTypes.xsd
		// FacilityType
		if (syslog_facility > SYSLOG_FACILITY_MAX || syslog_facility < 0) {
			error_seen |= JAL_CFG_FAILURE;
			CONFIG_ERROR(syslog, JALP_CFG_SL_FACILITY, "Invalid value");
		}

		new_app_meta->sys->facility = syslog_facility;

		int syslog_severity = -1;
		error_seen |= jal_config_lookup_int(syslog, JALP_CFG_SL_SEVERITY, &syslog_severity, JAL_CFG_OPTIONAL);

		// Restricted to 0-7 inclusive per schemas/applicationMetadataTypes.xsd
		// SyslogSeverityType
		if (syslog_severity > SYSLOG_SEVERITY_MAX || syslog_severity < 0) {
			error_seen |= JAL_CFG_FAILURE;
			CONFIG_ERROR(syslog, JALP_CFG_SL_SEVERITY, "Invalid value");
		}

		new_app_meta->sys->severity = syslog_severity;

		error_seen |= jal_config_lookup_string(syslog, JALP_CFG_SL_ENTRY, &new_app_meta->sys->entry, JAL_CFG_OPTIONAL);
		error_seen |= jal_config_lookup_string(syslog, JALP_CFG_SL_TIMESTAMP, &new_app_meta->sys->timestamp, JAL_CFG_OPTIONAL);
		error_seen |= jal_config_lookup_string(syslog, JALP_CFG_SL_HOSTNAME, hostname, JAL_CFG_OPTIONAL);
		error_seen |= jal_config_lookup_string(syslog, JALP_CFG_SL_APPNAME, appname, JAL_CFG_OPTIONAL);
		error_seen |= jal_config_lookup_string(syslog, JALP_CFG_SL_MESSAGEID, &new_app_meta->sys->message_id, JAL_CFG_OPTIONAL);

		if (JAL_CFG_SUCCESS == error_seen) {
			//Structured Data
			config_setting_t *sd_list = NULL;
			error_seen |= jal_config_get_member(syslog, JALP_CFG_SL_STRUCTURED_DATA, &sd_list, JAL_CFG_OPTIONAL);
			if (sd_list) {
				if (0 != generate_sd(sd_list, &new_app_meta->sys->sd_head)) {
					error_seen |= JAL_CFG_FAILURE;
				}
			}
		}
	}

	config_setting_t *logger = NULL;
	error_seen |= jal_config_lookup(&app_meta_config, JALP_CFG_LOGGER, &logger, JAL_CFG_OPTIONAL);
	if (logger) {
		//cannot have both logger and syslog
		if (new_app_meta->sys) {
			error_seen |= JAL_CFG_FAILURE;
			printf("Error: line %d: specified both %s and %s\n", config_setting_source_line(logger), JALP_CFG_LOGGER, JALP_CFG_SYSLOG);
		}
		else {
			new_app_meta->log = jalp_logger_metadata_create();
			new_app_meta->type = JALP_METADATA_LOGGER;

			error_seen |= jal_config_lookup_string(logger, JALP_CFG_LG_NAME, &new_app_meta->log->logger_name, JAL_CFG_OPTIONAL);

			//Severity
			config_setting_t *logger_severity = NULL;
			error_seen |= jal_config_get_member(logger, JALP_CFG_LG_SEVERITY, &logger_severity, JAL_CFG_OPTIONAL);
			if (logger_severity) {
				new_app_meta->log->severity = jalp_log_severity_create();
				error_seen |= jal_config_lookup_int(logger_severity, JALP_CFG_LG_SV_LEVEL, &new_app_meta->log->severity->level_val, JAL_CFG_REQUIRED);
				error_seen |= jal_config_lookup_string(logger_severity, JALP_CFG_LG_SV_NAME, &new_app_meta->log->severity->level_str, JAL_CFG_OPTIONAL);
			}

			error_seen |= jal_config_lookup_string(logger, JALP_CFG_LG_TIMESTAMP, &new_app_meta->log->timestamp, JAL_CFG_OPTIONAL);
			error_seen |= jal_config_lookup_string(logger, JALP_CFG_LG_HOSTNAME, hostname, JAL_CFG_OPTIONAL);
			error_seen |= jal_config_lookup_string(logger, JALP_CFG_LG_APPNAME, appname, JAL_CFG_OPTIONAL);
			error_seen |= jal_config_lookup_string(logger, JALP_CFG_LG_THREADID, &new_app_meta->log->threadId, JAL_CFG_OPTIONAL);
			error_seen |= jal_config_lookup_string(logger, JALP_CFG_LG_MESSAGE, &new_app_meta->log->message, JAL_CFG_OPTIONAL);\


			//Location (i.e. stack)
			config_setting_t *location = NULL;
			error_seen |= jal_config_get_member(logger, JALP_CFG_LG_LOCATION, &location, JAL_CFG_OPTIONAL);
			if (location) {
				if (0 != generate_location(location, &new_app_meta->log->stack)) {
					error_seen |= JAL_CFG_FAILURE;
				}
			}

			error_seen |= jal_config_lookup_string(logger, JALP_CFG_LG_NESTED_DIAG_CTX, &new_app_meta->log->nested_diagnostic_context, JAL_CFG_OPTIONAL);
			error_seen |= jal_config_lookup_string(logger, JALP_CFG_LG_MAPPED_DIAG_CTX, &new_app_meta->log->mapped_diagnostic_context, JAL_CFG_OPTIONAL);

			//Structured Data
			config_setting_t *sd_list = NULL;
			error_seen |= jal_config_get_member(logger, JALP_CFG_LG_STRUCTURED_DATA, &sd_list, JAL_CFG_OPTIONAL);
			if (sd_list) {
				if (0 != generate_sd(sd_list, &new_app_meta->log->sd)) {
					error_seen |= JAL_CFG_FAILURE;
				}
			}
		}
	}

	char *custom = NULL;
	error_seen |= jal_config_lookup_string(app_meta_root, JALP_CFG_CUSTOM, &custom, JAL_CFG_OPTIONAL);
	if (custom) {
		//cannot have both custom and log or sys
		if (new_app_meta->sys) {
			error_seen |= JAL_CFG_FAILURE;
			free(custom);
		}
		else {
			new_app_meta->custom = custom;
			new_app_meta->type = JALP_METADATA_CUSTOM;
		}
	}

	config_setting_t *journal = NULL;
	error_seen |= jal_config_lookup(&app_meta_config, JALP_CFG_JOURNAL, &journal, JAL_CFG_OPTIONAL);
	if (journal) {
		new_app_meta->file_metadata = jalp_journal_metadata_create();
		new_app_meta->file_metadata->file_info = jalp_file_info_create();

		//file info
		config_setting_t *file_info = NULL;
		error_seen |= jal_config_get_member(journal, JALP_CFG_JL_FILE_INFO, &file_info, JAL_CFG_REQUIRED);
		if (file_info) {
			if (0 != generate_file_info(file_info, new_app_meta->file_metadata->file_info)) {
				error_seen |= JAL_CFG_FAILURE;
			}
		}
		else {
			error_seen |= JAL_CFG_FAILURE;
		}

		//transforms
		config_setting_t *transforms = NULL;
		error_seen |= jal_config_get_member(journal, JALP_CFG_JL_TRANSFORMS, &transforms, JAL_CFG_OPTIONAL);
		if (transforms) {
			if (0 != generate_transforms(transforms, &new_app_meta->file_metadata->transforms)) {
				error_seen |= JAL_CFG_FAILURE;
			}
		}
	}

	if (JAL_CFG_SUCCESS == error_seen) {
		config_destroy(&app_meta_config);
		*app_metadata = new_app_meta;
		return 0;
	}

	jalp_app_metadata_destroy(&new_app_meta);
	config_destroy(&app_meta_config);
	return -1;
}

static int generate_sd(config_setting_t *sd_list, struct jalp_structured_data **app_sd)
{
	int error_seen = JAL_CFG_SUCCESS;
	int count = 0;
	if (sd_list) {
		count = config_setting_length(sd_list);
	}
	struct jalp_structured_data *tmp_jalp_sd = NULL;
	for(int i = 0; i < count; i++) {
		config_setting_t *tmp_sd = NULL;
		error_seen |= jal_config_get_elem_group(sd_list, i, &tmp_sd, config_setting_name(sd_list));
		char *sd_id = NULL;
		/* fail if missing sd_id (required field) */
		error_seen |= jal_config_lookup_string(tmp_sd, JALP_CFG_SD_ID, &sd_id, JAL_CFG_REQUIRED);

		tmp_jalp_sd = jalp_structured_data_append(tmp_jalp_sd, sd_id);
		free(sd_id);
		if (i == 0) {
			*app_sd = tmp_jalp_sd;
		}
		//add param list
		config_setting_t *param_list = NULL;
		error_seen |= jal_config_get_member(tmp_sd, JALP_CFG_SD_FIELDS, &param_list, JAL_CFG_OPTIONAL);
		int param_count = 0;
		if (param_list) {
			param_count = config_setting_length(param_list);
		}
		struct jalp_param *tmp_jalp_param = NULL;
		for(int j = 0; j < param_count; j++) {
			config_setting_t *tmp_param = NULL;
			error_seen |= jal_config_get_elem_group(param_list, j, &tmp_param, JALP_CFG_SD_FIELDS);
			char *key = NULL;
			char *value = NULL;
			/* fail if either of these required fields are missed */
			error_seen |= jal_config_lookup_string(tmp_param, JALP_CFG_SD_FIELDS_KEY, &key, JAL_CFG_REQUIRED);
			error_seen |= jal_config_lookup_string(tmp_param, JALP_CFG_SD_FIELDS_VALUE, &value, JAL_CFG_REQUIRED);

			tmp_jalp_param = jalp_param_append(tmp_jalp_param, key, value);
			free(key);
			free(value);
			if (j == 0) {
				tmp_jalp_sd->param_list = tmp_jalp_param;
			}
		}
	}

	if (JAL_CFG_SUCCESS == error_seen) {
		return 0;
	}

	return -1;
}

static int generate_location(config_setting_t *location, struct jalp_stack_frame **app_location) {

	int error_seen = JAL_CFG_SUCCESS;
	int count = 0;
	if (location) {
		count = config_setting_length(location);
	}
	struct jalp_stack_frame *tmp_jalp_stack = NULL;
	for(int i = 0; i < count; i++) {
		config_setting_t *stack = NULL;
		error_seen |= jal_config_get_elem_group(location, i, &stack, JALP_CFG_LG_LOCATION);

		tmp_jalp_stack = jalp_stack_frame_append(tmp_jalp_stack);

		long long line_number = 0;
		error_seen |= jal_config_lookup_int64(stack, JALP_CFG_LOC_LINE_NUM, &line_number, JAL_CFG_OPTIONAL);
		tmp_jalp_stack->line_number = (uint64_t)line_number;
		error_seen |= jal_config_lookup_string(stack, JALP_CFG_LOC_CALLER_NAME, &tmp_jalp_stack->caller_name, JAL_CFG_OPTIONAL);
		error_seen |= jal_config_lookup_string(stack, JALP_CFG_LOC_FILENAME, &tmp_jalp_stack->file_name, JAL_CFG_OPTIONAL);
		error_seen |= jal_config_lookup_string(stack, JALP_CFG_LOC_CLASS_NAME, &tmp_jalp_stack->class_name, JAL_CFG_OPTIONAL);
		error_seen |= jal_config_lookup_string(stack, JALP_CFG_LOC_METHOD_NAME, &tmp_jalp_stack->method_name, JAL_CFG_OPTIONAL);
		error_seen |= jal_config_lookup_int(stack, JALP_CFG_LOC_DEPTH, &tmp_jalp_stack->depth, JAL_CFG_OPTIONAL);

		if (i == 0) {
			*app_location = tmp_jalp_stack;
		}
	}

	if (JAL_CFG_SUCCESS == error_seen) {
		return 0;
	}

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
	int error_seen = jal_config_lookup_string(file_info, JALP_CFG_FI_FILENAME, &jalp_app_file_info->filename, JAL_CFG_OPTIONAL);

	long long int original_size = 0;
	error_seen |= jal_config_lookup_int64(file_info, JALP_CFG_FI_ORIGINAL_SIZE, &original_size, JAL_CFG_OPTIONAL);
	// libconfig allows for signed/unsigned values, but a size < 0 is nonsensical
	if(0 > original_size) {
		error_seen |= JAL_CFG_FAILURE;
		CONFIG_ERROR(file_info, JALP_CFG_FI_ORIGINAL_SIZE, "must be a non-negative integer");
	}
	jalp_app_file_info->original_size = (uint64_t)original_size;

	config_setting_t *content_type = NULL;
	error_seen |= jal_config_get_member(file_info, JALP_CFG_FI_CONTENT_TYPE, &content_type, JAL_CFG_OPTIONAL);
	if (content_type) {
		jalp_app_file_info->content_type = jalp_content_type_create();
		char *media_type = NULL;
		error_seen |= jal_config_lookup_string(content_type, JALP_CFG_FI_MEDIA_TYPE, &media_type, JAL_CFG_REQUIRED);
		int enum_media_type = get_media_type(media_type);
		free(media_type);
		if (-1 == enum_media_type) {
			error_seen |= JAL_CFG_FAILURE;
			CONFIG_ERROR(content_type, JALP_CFG_FI_MEDIA_TYPE, "Invalid value for field");
		}
		jalp_app_file_info->content_type->media_type = enum_media_type;

		error_seen |= jal_config_lookup_string(content_type, JALP_CFG_FI_SUB_TYPE, &jalp_app_file_info->content_type->subtype, JAL_CFG_REQUIRED);

		//params
		config_setting_t *param_list = NULL;
		error_seen |= jal_config_get_member(content_type, JALP_CFG_FI_PARAMS, &param_list, JAL_CFG_OPTIONAL);
		int param_count = 0;
		if (param_list) {
			param_count = config_setting_length(param_list);
		}
		struct jalp_param *tmp_jalp_param = NULL;
		for(int j = 0; j < param_count; j++) {
			config_setting_t *tmp_param = NULL;
			error_seen |= jal_config_get_elem_group(param_list, j, &tmp_param, JALP_CFG_FI_PARAMS);
			char *key = NULL;
			char *value = NULL;
			/* fail if either of these required fields are missed */
			error_seen |= jal_config_lookup_string(tmp_param, JALP_CFG_FI_PARAMS_KEY, &key, JAL_CFG_REQUIRED);
			error_seen |= jal_config_lookup_string(tmp_param, JALP_CFG_FI_PARAMS_VALUE, &value, JAL_CFG_REQUIRED);
			tmp_jalp_param = jalp_param_append(tmp_jalp_param, key, value);
			free(key);
			free(value);
			if (j == 0) {
				jalp_app_file_info->content_type->params = tmp_jalp_param;
			}
		}
	}

	char *threat_level = NULL;
	error_seen |= jal_config_lookup_string(file_info, JALP_CFG_FI_THREAT_LEVEL, &threat_level, JAL_CFG_OPTIONAL);

	if (threat_level) {
		if (0 == strcmp("malicious", threat_level)) {
			jalp_app_file_info->threat_level = JAL_THREAT_MALICIOUS;
		}
		else if (0 == strcmp("safe", threat_level)) {
			jalp_app_file_info->threat_level = JAL_THREAT_SAFE;
		}
		else if (0 == strcmp("unknown", threat_level)) {
			jalp_app_file_info->threat_level = JAL_THREAT_UNKNOWN;
		}
		else {
			error_seen |= JAL_CFG_FAILURE;
			CONFIG_ERROR(file_info, JALP_CFG_FI_THREAT_LEVEL, "Invalid value for field");
		}
		free(threat_level);
	}

	if (JAL_CFG_SUCCESS == error_seen) {
		return 0;
	}

	return -1;
}

static int generate_transforms(config_setting_t *transforms, struct jalp_transform **jalp_transforms)
{
	struct jalp_transform *tmp_jalp_transform = NULL;
	int count = 0;
	int error_seen = JAL_CFG_SUCCESS;
	uint8_t *iv_buf = NULL;
	uint8_t *key_buf = NULL;
	char *xml = NULL;
	char *uri = NULL;
	if (transforms) {
		count = config_setting_length(transforms);
	}
	for (int i = 0; i < count; i++) {
		config_setting_t *tmp_transform = NULL;
		error_seen |= jal_config_get_elem_group(transforms, i, &tmp_transform, JALP_CFG_JL_TRANSFORMS);
		char *transform_type = NULL;
		error_seen |= jal_config_lookup_string(tmp_transform, JALP_CFG_JL_TR_TYPE, &transform_type, JAL_CFG_REQUIRED);

		if (!transform_type) {
			// If we're missing the required field, skip the rest of the checks and move on to the next transform
			continue;
		}

		int enum_transform_type = get_transform_type(transform_type);
		free(transform_type);
		error_seen |= jal_config_lookup_string(tmp_transform, JALP_CFG_JL_TR_XML, &xml, JAL_CFG_OPTIONAL);
		error_seen |= jal_config_lookup_string(tmp_transform, JALP_CFG_JL_TR_URI, &uri, JAL_CFG_OPTIONAL);
		//iv
		config_setting_t *iv = NULL;
		error_seen |= jal_config_get_member(tmp_transform, JALP_CFG_JL_TR_IV, &iv, JAL_CFG_OPTIONAL);
		if (iv) {
			if (4 != config_setting_length(iv)) {
				error_seen |= JAL_CFG_FAILURE;
				CONFIG_ERROR(iv, JALP_CFG_JL_TR_IV, "Should consist of four 32 bit ints");
			}
		iv_buf = (uint8_t *)malloc(16);
			for (int j = 0; j < 4; j++) {
				int tmp_iv_data = 0;
				error_seen |= jal_config_get_elem_int(iv, j, &tmp_iv_data, JALP_CFG_JL_TR_IV);
				uint32_t tmp_iv_be = htonl((uint32_t)tmp_iv_data);
				memcpy(iv_buf + 4 * j, &tmp_iv_be, 4);
			}
		}
		//key
		config_setting_t *key = NULL;
		error_seen |= jal_config_get_member(tmp_transform, JALP_CFG_JL_TR_KEY, &key, JAL_CFG_OPTIONAL);
		int key_count = 0;
		if (key) {
			key_count = config_setting_length(key);
			key_buf = (uint8_t *)malloc(key_count * 4);
			for (int j = 0; j < key_count; j++) {
				int tmp_key_data = 0;
				error_seen |= jal_config_get_elem_int(key, j, &tmp_key_data, JALP_CFG_JL_TR_KEY);
				uint32_t tmp_key_be = htonl((uint32_t)tmp_key_data);
				memcpy(key_buf + 4 * j, &tmp_key_be, 4);
			}
		}
		if(enum_transform_type != JALP_TRANSFORM_OTHER && (uri)) {
			CONFIG_WARNING(tmp_transform, JALP_CFG_JL_TR_URI, "Specified uri is unused");
		}

		if(enum_transform_type != JALP_TRANSFORM_OTHER && (xml)) {
			CONFIG_WARNING(tmp_transform, JALP_CFG_JL_TR_XML, "Specified xml is unused");
		}

		switch (enum_transform_type) {
			case (JALP_TRANSFORM_OTHER):
				tmp_jalp_transform = jalp_transform_append_other(tmp_jalp_transform, uri, xml);
				if (NULL == tmp_jalp_transform) {
					error_seen |= JAL_CFG_FAILURE;
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
				}
				break;
			case (JALP_TRANSFORM_AES128):
				if (key_count != 4 && key_count != 0) {
					error_seen |= JAL_CFG_FAILURE;
					printf("Error: line %d: key is invalid\n", config_setting_source_line(key));
				}
				tmp_jalp_transform = jalp_transform_append_aes(tmp_jalp_transform, JALP_AES128, key_buf, iv_buf);
				if (NULL == tmp_jalp_transform) {
					error_seen |= JAL_CFG_FAILURE;
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
				}
				break;
			case (JALP_TRANSFORM_AES192):
				if (key_count != 6 && key_count != 0) {
					error_seen |= JAL_CFG_FAILURE;
					printf("Error: line %d: key is invalid\n", config_setting_source_line(key));
				}
				tmp_jalp_transform = jalp_transform_append_aes(tmp_jalp_transform, JALP_AES192, key_buf, iv_buf);
				if (NULL == tmp_jalp_transform) {
					error_seen |= JAL_CFG_FAILURE;
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
				}
				break;
			case (JALP_TRANSFORM_AES256):
				if (key_count != 8 && key_count != 0) {
					error_seen |= JAL_CFG_FAILURE;
					printf("Error: line %d: key is invalid\n", config_setting_source_line(key));
				}
				tmp_jalp_transform = jalp_transform_append_aes(tmp_jalp_transform, JALP_AES256, key_buf, iv_buf);
				if (NULL == tmp_jalp_transform) {
					error_seen |= JAL_CFG_FAILURE;
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
				}
				break;
			case (JALP_TRANSFORM_DEFLATE):
				tmp_jalp_transform = jalp_transform_append_deflate(tmp_jalp_transform);
				if (NULL == tmp_jalp_transform) {
					error_seen |= JAL_CFG_FAILURE;
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
				}
				break;
			case (JALP_TRANSFORM_XOR):
				tmp_jalp_transform = jalp_transform_append_xor(tmp_jalp_transform, *(uint32_t *)key_buf);
				if (NULL == tmp_jalp_transform) {
					error_seen |= JAL_CFG_FAILURE;
					printf("Error: line %d: jalp error on transform\n", config_setting_source_line(tmp_transform));
				}
				break;
			default: //should not be possible
				error_seen |= JAL_CFG_FAILURE;
		}
		if (i == 0) {
			*jalp_transforms = tmp_jalp_transform;
		}
		free(xml);
		xml = NULL;
		free(uri);
		uri = NULL;
		free(iv_buf);
		iv_buf = NULL;
		free(key_buf);
		key_buf = NULL;
	}

	if (JAL_CFG_SUCCESS == error_seen) {
		return 0;
	}

	return -1;
}
