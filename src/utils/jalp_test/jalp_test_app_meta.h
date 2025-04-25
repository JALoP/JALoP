/**
 * @file
 *
 * @brief This file contains delcarations for generating
 * application metadata
 *
 * ### LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011 Tresys Technology LLC, Columbia, Maryland, USA
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

#ifndef _JAL_TEST_APP_META_H_
#define _JAL_TEST_APP_META_H_

#include <jalop/jal_status.h>
#include <jalop/jalp_app_metadata.h>

#define JALP_CFG_EVENT_ID "eventID"

#define JALP_CFG_SYSLOG "syslog"
#define JALP_CFG_SL_FACILITY "facility"
#define JALP_CFG_SL_SEVERITY "severity"
#define JALP_CFG_SL_ENTRY "entry"
#define JALP_CFG_SL_TIMESTAMP "timestamp"
#define JALP_CFG_SL_HOSTNAME "hostname"
#define JALP_CFG_SL_APPNAME "appName"
#define JALP_CFG_SL_MESSAGEID "messageID"
#define JALP_CFG_SL_STRUCTURED_DATA "sdList"

#define JALP_CFG_LOGGER "logger"
#define JALP_CFG_LG_NAME "Name"
#define JALP_CFG_LG_SEVERITY "severity"
#define JALP_CFG_LG_SV_LEVEL "level"
#define JALP_CFG_LG_SV_NAME "name"
#define JALP_CFG_LG_TIMESTAMP "timestamp"
#define JALP_CFG_LG_HOSTNAME "hostname"
#define JALP_CFG_LG_APPNAME "appName"
#define JALP_CFG_LG_THREADID "threadID"
#define JALP_CFG_LG_MESSAGE "message"
#define JALP_CFG_LG_LOCATION "location"
#define JALP_CFG_LG_NESTED_DIAG_CTX "ndc"
#define JALP_CFG_LG_MAPPED_DIAG_CTX "mdc"
#define JALP_CFG_LG_STRUCTURED_DATA "sd"

#define JALP_CFG_CUSTOM "custom"

#define JALP_CFG_JOURNAL "journal"
#define JALP_CFG_JL_FILE_INFO "file_info"
#define JALP_CFG_JL_TRANSFORMS "transforms"

#define JALP_CFG_JL_TR_TYPE "type"
#define JALP_CFG_JL_TR_XML "xml"
#define JALP_CFG_JL_TR_URI "uri"
#define JALP_CFG_JL_TR_IV "iv"
#define JALP_CFG_JL_TR_KEY "key"

#define JALP_CFG_SD_ID "id"
#define JALP_CFG_SD_FIELDS "fields"
#define JALP_CFG_SD_FIELDS_KEY "key"
#define JALP_CFG_SD_FIELDS_VALUE "value"

#define JALP_CFG_LOC_LINE_NUM "lineNumber"
#define JALP_CFG_LOC_CALLER_NAME "callerName"
#define JALP_CFG_LOC_FILENAME "filename"
#define JALP_CFG_LOC_CLASS_NAME "className"
#define JALP_CFG_LOC_METHOD_NAME "methodName"
#define JALP_CFG_LOC_DEPTH "depth"

#define JALP_CFG_FI_FILENAME "filename"
#define JALP_CFG_FI_ORIGINAL_SIZE "originalSize"
#define JALP_CFG_FI_CONTENT_TYPE "contentType"
#define JALP_CFG_FI_MEDIA_TYPE "mediaType"
#define JALP_CFG_FI_SUB_TYPE "subType"
#define JALP_CFG_FI_PARAMS "params"
#define JALP_CFG_FI_PARAMS_KEY "key"
#define JALP_CFG_FI_PARAMS_VALUE "value"
#define JALP_CFG_FI_THREAT_LEVEL "threatLevel"

#define JALP_CFG_TR_TYPE "type"

int generate_app_metadata(const char *app_meta_path, struct jalp_app_metadata **app_metadata,
	char **hostname, char **appname);

#endif //_JAL_TEST_APP_META_H_
