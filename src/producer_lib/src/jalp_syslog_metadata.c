/**
 * @file jalp_syslog_metadata.c This file contains constructors
 * and destructors for the syslog_metadata structure.
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


#include <jalop/jalp_syslog_metadata.h>
#include <jalop/jalp_structured_data.h>
#include "jal_alloc.h"


struct jalp_syslog_metadata *jalp_syslog_metadata_create(void)
{
	struct jalp_syslog_metadata *syslog_meta = NULL;
	syslog_meta = jal_calloc(1, sizeof(*syslog_meta));
	syslog_meta->facility = -1;
	syslog_meta->severity = -1;
	return syslog_meta;
}

void jalp_syslog_metadata_destroy(struct jalp_syslog_metadata **syslog_meta)
{
	if (!syslog_meta || !(*syslog_meta)) {
		return;
	}

	free((*syslog_meta)->timestamp);
	free((*syslog_meta)->message_id);
	free((*syslog_meta)->entry);
	jalp_structured_data_destroy(&(*syslog_meta)->sd_head);

	free(*syslog_meta);
	(*syslog_meta) = NULL;
}
