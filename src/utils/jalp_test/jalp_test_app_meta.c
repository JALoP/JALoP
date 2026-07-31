/**
 * @file
 *
 * @brief This file contains functions for generating app metadata
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
#include <libconfig.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <jalop/jal_status.h>
#include <jalop/jalp_app_metadata.h>
#include "jal_config.h"

#include "jalp_test_app_meta.h"

#define REQUIRED 1
#define OPTIONAL 0

static const int SYSLOG_FACILITY_MAX = 23;
static const int SYSLOG_SEVERITY_MAX = 7;

static int generate_sd(config_setting_t *parent, const char* name, struct jalp_structured_data **app_sd);

static int generate_location(config_setting_t *logger, struct jalp_stack_frame **app_location);

static int generate_transforms(config_setting_t *journal, struct jalp_transform **jalp_transforms);

static int generate_file_info(config_setting_t *journal, struct jalp_file_info *jalp_app_file_info);

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
	if(JAL_CFG_SUCCESS != jal_config_init(&app_meta_config)) {
		printf("Failed to initialize config object\n");
		return -1;
	}

	if(JAL_CFG_SUCCESS != jal_config_read_file(
		&app_meta_config,
		app_meta_path)) {
			// Error printed internally
			return -1;
	}

	config_setting_t* root = config_root_setting(&app_meta_config);
	if(NULL == root) {
		printf("Failed to obtain configuration root node\n");
		goto err_out;
	}

	struct jalp_app_metadata *new_app_meta = NULL;
	new_app_meta = jalp_app_metadata_create();

	if (JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		"eventID",
		&(new_app_meta->event_id),
		JAL_CFG_OPTIONAL)) {
		// Error printed internally
		goto err_out;
	}

	config_setting_t *syslog = NULL;
	if(JAL_CFG_SUCCESS != jal_config_get_member(
		root,
		"syslog",
		&syslog,
		JAL_CFG_OPTIONAL)) {
		goto err_out;
	}

	if (syslog) {
		new_app_meta->sys = jalp_syslog_metadata_create();
		new_app_meta->type = JALP_METADATA_SYSLOG;

		int syslog_facility = -1;
		// Extract the facility value
		if (JAL_CFG_SUCCESS != jal_config_lookup_int(
			syslog,
			"facility",
			&syslog_facility,
			JAL_CFG_OPTIONAL)) {
			// Error printed internally
			goto err_out;
		}
		// Restricted to 0-23 inclusive per schemas/applicationMetadataTypes.xsd
		// FacilityType
		if (syslog_facility > SYSLOG_FACILITY_MAX || syslog_facility < 0) {
			CONFIG_ERROR(syslog,
				"facility",
				"Invalid value for \"facility\", must be within range of INT8\n");
			goto err_out;
		}
		// Assigned the facililty value
		new_app_meta->sys->facility = syslog_facility;

		int syslog_severity = -1;
		// Extract the severity value
		if (JAL_CFG_SUCCESS != jal_config_lookup_int(
			syslog,
			"severity",
			&syslog_severity,
			JAL_CFG_OPTIONAL)) {
			goto err_out;
		}
		// Restricted to 0-7 inclusive per schemas/applicationMetadataTypes.xsd
		// SyslogSeverityType
		if (syslog_severity > SYSLOG_SEVERITY_MAX || syslog_severity < 0) {
			CONFIG_ERROR(syslog,
				"facility",
				"Invalid value for \"severity\", must be within range of INT8\n");
			goto err_out;
		}
		new_app_meta->sys->severity = syslog_severity;

		// Extract entry string
		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			syslog,
			"entry",
			&new_app_meta->sys->entry,
			JAL_CFG_OPTIONAL)) {
				// Error printed internally
				goto err_out;
		}

		// Extract timestamp as string
		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			syslog,
			"timestamp",
			&new_app_meta->sys->timestamp,
			JAL_CFG_OPTIONAL)) {
				// Error printed internally
				goto err_out;
		}

		// Extract hostname as string
		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			syslog,
			"hostname",
			hostname,
			JAL_CFG_OPTIONAL)) {
				// Error printed internally
				goto err_out;
		}

		// Extract appName as string
		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			syslog,
			"appName",
			appname,
			JAL_CFG_OPTIONAL)) {
				// Error printed internally
				goto err_out;
		}

		// Extract messageID as string
		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			syslog,
			"messageID",
			&new_app_meta->sys->message_id,
			JAL_CFG_OPTIONAL)) {
				// Error printed internally
				goto err_out;
		}

		if (0 != generate_sd(syslog, "sdList", &new_app_meta->sys->sd_head)) {
			goto err_out;
		}
	}

	config_setting_t *logger = NULL;
	if(JAL_CFG_SUCCESS != jal_config_get_member(
		root,
		"logger",
		&logger,
		JAL_CFG_OPTIONAL)) {
		goto err_out;
	}

	if (logger) {
		//cannot have both logger and syslog
		if (new_app_meta->sys) {
			CONFIG_ERROR(
				logger,
				"logger",
				"Specified both logger and syslog\n");
			goto err_out;
		}
		new_app_meta->log = jalp_logger_metadata_create();
		new_app_meta->type = JALP_METADATA_LOGGER;

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			logger,
			"Name",
			&new_app_meta->log->logger_name,
			OPTIONAL)) {
			goto err_out;
		}

		//Severity
		config_setting_t *logger_severity = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_member(
			logger,
			"severity",
			&logger_severity,
			JAL_CFG_OPTIONAL)) {
				goto err_out;
		}

		if (logger_severity) {
			new_app_meta->log->severity = jalp_log_severity_create();
			if (JAL_CFG_SUCCESS != jal_config_lookup_int(
				logger_severity,
				"level",
				&new_app_meta->log->severity->level_val,
				JAL_CFG_REQUIRED)) {
					goto err_out;
			}
			if (JAL_CFG_SUCCESS != jal_config_lookup_string(
				logger_severity,
				"name",
				&new_app_meta->log->severity->level_str,
				JAL_CFG_OPTIONAL)) {
					goto err_out;
			}
		}

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			logger,
			"timestamp",
			&new_app_meta->log->timestamp,
			JAL_CFG_OPTIONAL)) {
			goto err_out;
		}

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			logger,
			"hostname",
			hostname,
			JAL_CFG_OPTIONAL)) {
				goto err_out;
		}

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			logger,
			"appName",
			appname,
			JAL_CFG_OPTIONAL)) {
				goto err_out;
		}

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			logger,
			"threadID",
			&new_app_meta->log->threadId,
			JAL_CFG_OPTIONAL)) {
				goto err_out;
		}

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			logger,
			"message",
			&new_app_meta->log->message,
			JAL_CFG_OPTIONAL)) {
			goto err_out;
		}

		//Location (i.e. stack) - optional
		if (0 != generate_location(logger, &new_app_meta->log->stack)) {
			goto err_out;
		}

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			logger,
			"ndc",
			&new_app_meta->log->nested_diagnostic_context,
			JAL_CFG_OPTIONAL)) {
				goto err_out;
		}

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			logger,
			"mdc",
			&new_app_meta->log->mapped_diagnostic_context,
			JAL_CFG_OPTIONAL)) {
				goto err_out;
		}

		//Structured Data
		config_setting_t *sd_list = NULL;
		int sd_list_len = 0;
		if(JAL_CFG_SUCCESS != jal_config_lookup_list(
			logger,
			"sd",
			&sd_list,
			&sd_list_len,
			JAL_CFG_OPTIONAL)) {
			goto err_out;
		}

		if (0 != generate_sd(logger, "sd", &new_app_meta->log->sd)) {
			goto err_out;
		}
	}

	char *custom = NULL;
	// Only execute the following block if the "custom" field is present, but use the
	// JAL_CFG_OPTIONAL flag and the NULL check so jal_config_lookup_string doesn't internally
	// print any errors
	if (JAL_CFG_SUCCESS == jal_config_lookup_string(
		root,
		"custom",
		&custom,
		JAL_CFG_OPTIONAL)
		&& custom) {
		//cannot have both custom and log or sys
		if (new_app_meta->sys) {
			goto err_out;
		}
		new_app_meta->custom = strdup(custom);
		new_app_meta->type = JALP_METADATA_CUSTOM;
	}

	config_setting_t *journal = NULL;
	if(JAL_CFG_SUCCESS != jal_config_get_member(
		root,
		"journal",
		&journal,
		JAL_CFG_OPTIONAL)) {
			goto err_out;
	}

	if (journal) {
		new_app_meta->file_metadata = jalp_journal_metadata_create();
		new_app_meta->file_metadata->file_info = jalp_file_info_create();

		if (0 != generate_file_info(journal, new_app_meta->file_metadata->file_info)) {
			goto err_out;
		}

		if (0 != generate_transforms(journal, &new_app_meta->file_metadata->transforms)) {
			goto err_out;
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

static int generate_sd(
	config_setting_t *parent,
	const char* name,
	struct jalp_structured_data **app_sd) // used for error output only
{
	// Extract Sructured Data
	config_setting_t *sd_list = NULL;
	int sd_list_len = 0;
	if(JAL_CFG_SUCCESS != jal_config_lookup_list(
		parent,
		name,
		&sd_list,
		&sd_list_len,
		JAL_CFG_OPTIONAL)) {
		goto sd_err;
	}
	struct jalp_structured_data *tmp_jalp_sd = NULL;

	config_setting_t* tmp_sd = NULL;
	for(int i = 0; i < sd_list_len; i++) {
		// Extract the ith element from the sd_list, which is a group
		if (JAL_CFG_SUCCESS != jal_config_get_elem_group(
			sd_list,
			i,
			&tmp_sd,
			name)) {
				goto sd_err;
		}

		char *sd_id = NULL;
		// Extract sd_id (required)
		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			tmp_sd,
			"id",
			&sd_id,
			JAL_CFG_REQUIRED)) {
				goto sd_err;
		}

		tmp_jalp_sd = jalp_structured_data_append(tmp_jalp_sd, sd_id);
		free(sd_id);
		if (i == 0) {
			*app_sd = tmp_jalp_sd;
		}
		//add param list
		config_setting_t *param_list = NULL;
		int param_count = 0;
		if(JAL_CFG_SUCCESS != jal_config_lookup_list(
			tmp_sd,
			"fields",
			&param_list,
			&param_count,
			JAL_CFG_OPTIONAL)) {
				goto sd_err;
		}
		struct jalp_param *tmp_jalp_param = NULL;
		for(int j = 0; j < param_count; j++) {
			config_setting_t* tmp_param = NULL;
			if(JAL_CFG_SUCCESS != jal_config_get_elem_group(
				param_list,
				j,
				&tmp_param,
				"fields")) {
					goto sd_err;
			}
			char *key = NULL;
			char *value = NULL;
			/* fail if either of these required fields are missed */
			if (JAL_CFG_SUCCESS != jal_config_lookup_string(
				tmp_param,
				"key",
				&key, JAL_CFG_REQUIRED)) {
					goto sd_err;
			}
			if (JAL_CFG_SUCCESS != jal_config_lookup_string(
				tmp_param,
				"value",
				&value,
				JAL_CFG_REQUIRED)) {
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

static int generate_location(
	config_setting_t *logger,
	struct jalp_stack_frame **app_location) {

	config_setting_t *location = NULL;
	int count = 0;
	if(JAL_CFG_SUCCESS != jal_config_lookup_list(
		logger,
		"location",
		&location,
		&count,
		JAL_CFG_OPTIONAL)) {
			goto err_out;
	}

	// The location field is optional, if it's missing, return success
	if(!location) {
		return 0;
	}

	struct jalp_stack_frame *tmp_jalp_stack = NULL;
	for(int i = 0; i < count; i++) {
		config_setting_t* stack = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_elem_group(
			location,
			i,
			&stack,
			"location")) {
				goto err_out;
		}

		tmp_jalp_stack = jalp_stack_frame_append(tmp_jalp_stack);

		// If the line number isn't present, the value of 0 will signal to other parts
		// of the program to omit this field
		long long line_number = 0;
		jal_config_lookup_int64(stack,
				"lineNumber",
				&line_number,
				JAL_CFG_OPTIONAL);
		// An unlikely edge case, ensure we didn't somehow get a negative number or one outside
		// the rangeof the in64 libconfig is cable of returning
		if(0 > line_number || INT64_MAX < line_number) {
			goto err_out;
		}
		tmp_jalp_stack->line_number = (uint64_t)line_number;

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			stack,
			"callerName",
			&tmp_jalp_stack->caller_name,
			JAL_CFG_OPTIONAL)) {
				goto err_out;
		}

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			stack,
			"filename",
			&tmp_jalp_stack->file_name,
			JAL_CFG_OPTIONAL)) {
				goto err_out;
		}

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			stack,
			"className",
			&tmp_jalp_stack->class_name,
			JAL_CFG_OPTIONAL)) {
				goto err_out;
		}

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			stack,
			"methodName",
			&tmp_jalp_stack->method_name,
			JAL_CFG_OPTIONAL)) {
				goto err_out;
		}

		if (JAL_CFG_SUCCESS != jal_config_lookup_int(
			stack,
			"depth",
			&tmp_jalp_stack->depth,
			JAL_CFG_OPTIONAL)) {
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

static int generate_file_info(config_setting_t *journal, struct jalp_file_info *jalp_app_file_info)
{
	// Extract file_info
	config_setting_t *file_info = NULL;
	if(JAL_CFG_SUCCESS != jal_config_get_member(
		journal,
		"file_info",
		&file_info,
		JAL_CFG_REQUIRED)) {
			goto err_file_info;
	}

	// File info is optional, if it's not here, return success
	if(!file_info) {
		goto out;
	}

	if (JAL_CFG_SUCCESS != jal_config_lookup_string(
		file_info,
		"filename",
		&jalp_app_file_info->filename,
		JAL_CFG_OPTIONAL)) {
			goto err_file_info;
	}

	long long int original_size = 0;
	jal_config_lookup_int64(
		file_info,
		"originalSize",
		&original_size,
		JAL_CFG_OPTIONAL);

	// A file size must not be negative
	if(0 > original_size || INT64_MAX < original_size) {
		CONFIG_ERROR(file_info, "originalSize", "must be positive and within the range of int64");
		goto err_file_info;
	}
	jalp_app_file_info->original_size = (uint64_t)original_size;

	config_setting_t *content_type = NULL;
	if(JAL_CFG_SUCCESS != jal_config_get_member(
		file_info,
		"contentType",
		&content_type,
		JAL_CFG_OPTIONAL)) {
			goto err_file_info;
	}

	if (content_type) {
		jalp_app_file_info->content_type = jalp_content_type_create();

		char *media_type = NULL;
		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			content_type,
			"mediaType",
			&media_type,
			JAL_CFG_REQUIRED)) {
				goto err_file_info;
		}

		int enum_media_type = get_media_type(media_type);
		free(media_type);

		if (-1 == enum_media_type) {
			CONFIG_ERROR(content_type, "mediaType", "invalid value");
			goto err_file_info;
		}
		jalp_app_file_info->content_type->media_type = enum_media_type;

		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			content_type,
			"subType",
			&jalp_app_file_info->content_type->subtype,
			JAL_CFG_OPTIONAL)) {
			goto err_file_info;
		}
		//params
		config_setting_t *param_list = NULL;
		int param_count = 0;
		if(JAL_CFG_SUCCESS != jal_config_lookup_list(
			content_type,
			"params",
			&param_list,
			&param_count,
			JAL_CFG_OPTIONAL)) {
			goto err_file_info;
		}

		struct jalp_param *tmp_jalp_param = NULL;
		for(int j = 0; j < param_count; j++) {
			// Extract the jth parameter
			config_setting_t *tmp_param = NULL;
			if(JAL_CFG_SUCCESS != jal_config_get_elem_group(
				param_list,
				j,
				&tmp_param,
				"params")) {
					goto err_file_info;
			}

			char *key = NULL;
			char *value = NULL;
			/* fail if either of these required fields are missed */
			if (JAL_CFG_SUCCESS != jal_config_lookup_string(
				tmp_param,
				"key",
				&key,
				JAL_CFG_REQUIRED)) {
					goto err_file_info;
			}

			if (JAL_CFG_SUCCESS != jal_config_lookup_string(
				tmp_param,
				"value",
				&value,
				JAL_CFG_REQUIRED)) {
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
	if (JAL_CFG_SUCCESS != jal_config_lookup_string(
		file_info,
		"threatLevel",
		&threat_level,
		JAL_CFG_OPTIONAL)) {
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
		CONFIG_ERROR(file_info, "threatLevel", "invalid value");

		goto err_file_info;
	}
	free(threat_level);

out:
	return 0;

err_file_info:

	return -1;

}

static int generate_transforms(config_setting_t *journal, struct jalp_transform **jalp_transforms)
{
	uint8_t *iv_buf = NULL;
	uint8_t *key_buf = NULL;
	char *xml = NULL;
	char *uri = NULL;

	config_setting_t *transforms = NULL;
	int count = 0;
	if(JAL_CFG_SUCCESS != jal_config_lookup_list(
		journal,
		"transforms",
		&transforms,
		&count,
		JAL_CFG_OPTIONAL)) {
			goto err_transform;
	}

	// transforms are optional, if there are none return success
	if (!transforms) {
		return 0;
	}

	struct jalp_transform *tmp_jalp_transform = NULL;
	for (int i = 0; i < count; i++) {
		// Extract the ith transform
		config_setting_t *tmp_transform = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_elem_group(
			transforms,
			i,
			&tmp_transform,
			"transforms")) {
				goto err_transform;
		}
		// Extract type
		char *transform_type = NULL;
		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			tmp_transform,
			"type",
			&transform_type,
			JAL_CFG_REQUIRED)) {
				goto err_transform;
		}
		int enum_transform_type = get_transform_type(transform_type);
		free(transform_type);
		// Extract xml
		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			tmp_transform,
			"xml",
			&xml,
			JAL_CFG_OPTIONAL)) {
				goto err_transform;
		}
		// Extract uri
		if (JAL_CFG_SUCCESS != jal_config_lookup_string(
			tmp_transform,
			"uri",
			&uri,
			JAL_CFG_OPTIONAL)) {
				goto err_transform;
		}
		// Extract iv
		config_setting_t *iv = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_member(
			tmp_transform,
			"iv",
			&iv,
			JAL_CFG_OPTIONAL)) {
				goto err_transform;
		}

		// iv is a fixed-size group of 4 keyX items
		if (iv) {
			if (4 != config_setting_length(iv)) {
				CONFIG_ERROR(tmp_transform, "iv", "should consist of four 32 bit ints");
				goto err_transform;
			}
		iv_buf = (uint8_t *)malloc(16);
			for (int j = 0; j < 4; j++) {
				int tmp_iv_data = 0;
				// Extract the jth key
				if(JAL_CFG_SUCCESS != jal_config_get_elem_int(
					iv,
					j,
					&tmp_iv_data,
					"iv")) {
						goto err_transform;
				}
				uint32_t tmp_iv_be = htonl((uint32_t)tmp_iv_data);
				memcpy(iv_buf + 4 * j, &tmp_iv_be, 4); // nosemgrep - the copy length is less than or equal to the destination buffer size
			}
		}

		// Extract key
		config_setting_t *key = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_member(
			tmp_transform,
			"key",
			&key,
			JAL_CFG_OPTIONAL)) {
				goto err_transform;
		}

		int key_count = 0;
		if (key) {
			key_count = config_setting_length(key);
			key_buf = (uint8_t *)malloc(key_count * 4);
			for (int j = 0; j < key_count; j++) {
				// Extract the jth keyX field in key
				int tmp_key_data = 0;
				if(JAL_CFG_SUCCESS != jal_config_get_elem_int(
					key,
					j,
					&tmp_key_data,
					"key")) {
						goto err_transform;
				}
				uint32_t tmp_key_be = htonl((uint32_t)tmp_key_data);
				memcpy(key_buf + 4 * j, &tmp_key_be, 4); // nosemgrep - the copy length is less than or equal to the destination buffer size
			}
		}
		if(enum_transform_type != JALP_TRANSFORM_OTHER && (uri)) {
			CONFIG_WARNING(tmp_transform, "uri", "specified uri is unused");
		}

		if(enum_transform_type != JALP_TRANSFORM_OTHER && (xml)) {
			CONFIG_WARNING(tmp_transform, "xml", "specified xml is unused");
		}

		switch (enum_transform_type) {
			case (JALP_TRANSFORM_OTHER):
				tmp_jalp_transform = jalp_transform_append_other(tmp_jalp_transform, uri, xml);
				if (NULL == tmp_jalp_transform) {
					CONFIG_ERROR(tmp_transform, "transform", "jalp error on transform");
					goto err_transform;
				}
				break;
			case (JALP_TRANSFORM_AES128):
				if (key_count != 4 && key_count != 0) {
					CONFIG_ERROR(key, "key", "is invalid");
					goto err_transform;
				}
				tmp_jalp_transform = jalp_transform_append_aes(tmp_jalp_transform, JALP_AES128, key_buf, iv_buf);
				if (NULL == tmp_jalp_transform) {
					CONFIG_ERROR(tmp_transform, "transform", "jalp error on transform");
					goto err_transform;
				}
				break;
			case (JALP_TRANSFORM_AES192):
				if (key_count != 6 && key_count != 0) {
					CONFIG_ERROR(key, "key", "is invalid");
					goto err_transform;
				}
				tmp_jalp_transform = jalp_transform_append_aes(tmp_jalp_transform, JALP_AES192, key_buf, iv_buf);
				if (NULL == tmp_jalp_transform) {
					CONFIG_ERROR(tmp_transform, "transform", "jalp error on transform");
					goto err_transform;
				}
				break;
			case (JALP_TRANSFORM_AES256):
				if (key_count != 8 && key_count != 0) {
					CONFIG_ERROR(key, "key", "is invalid");
					goto err_transform;
				}
				tmp_jalp_transform = jalp_transform_append_aes(tmp_jalp_transform, JALP_AES256, key_buf, iv_buf);
				if (NULL == tmp_jalp_transform) {
					CONFIG_ERROR(tmp_transform, "transform", "jalp error on transform");
					goto err_transform;
				}
				break;
			case (JALP_TRANSFORM_DEFLATE):
				tmp_jalp_transform = jalp_transform_append_deflate(tmp_jalp_transform);
				if (NULL == tmp_jalp_transform) {
					CONFIG_ERROR(tmp_transform, "transform", "jalp error on transform");
					goto err_transform;
				}
				break;
			case (JALP_TRANSFORM_XOR):
				tmp_jalp_transform = jalp_transform_append_xor(tmp_jalp_transform, *(uint32_t *)key_buf);
				if (NULL == tmp_jalp_transform) {
					CONFIG_ERROR(tmp_transform, "transform", "jalp error on transform");
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
		xml = NULL;
		free(uri);
		uri = NULL;
		free(iv_buf);
		iv_buf = NULL;
		free(key_buf);
		key_buf = NULL;
	}

	return 0;

err_transform:
	free(iv_buf);
	free(key_buf);
	free(xml);
	free(uri);
	return -1;
}
