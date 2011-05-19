/**
 * @file jalp_app_metadata.c This file contains functions to handle the
 * application metadata document.
 *
 * @section LICENSE
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


#include <stdlib.h>
#include <jalop/jalp_app_metadata.h>
#include <jalop/jalp_journal_metadata.h>
#include <jalop/jalp_logger_metadata.h>
#include <jalop/jalp_syslog_metadata.h>
#include "jal_alloc.h"

struct jalp_app_metadata *jalp_app_metadata_create(void)
{
	struct jalp_app_metadata *metadata;

	metadata = jal_malloc(sizeof(*metadata));
	metadata->type = JALP_METADATA_NONE;
	metadata->event_id = NULL;
	metadata->custom = NULL;
	metadata->file_metadata = NULL;

	return metadata;
}

void jalp_app_metadata_destroy(struct jalp_app_metadata **app_meta)
{
	if (!app_meta || !(*app_meta)) {
		return;
	}

	free((*app_meta)->event_id);
	jalp_journal_metadata_destroy(&(*app_meta)->file_metadata);

	switch((*app_meta)->type) {
	case JALP_METADATA_SYSLOG:
		jalp_syslog_metadata_destroy(&(*app_meta)->sys);
		break;
	case JALP_METADATA_LOGGER:
		jalp_logger_metadata_destroy(&(*app_meta)->log);
		break;
	case JALP_METADATA_CUSTOM:
		free((*app_meta)->custom);
		break;
	case JALP_METADATA_NONE:
		/* don't need to free anything here */
		break;
	default:
		/* this is user error */
		break;
	}

	free(*app_meta);
	*app_meta = NULL;
}
