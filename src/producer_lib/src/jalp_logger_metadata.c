/**
 * @file jalp_logger_metadata.h This file defines structures related to
 * the jalp_logger_metadata struct.
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
#include <jalop/jalp_logger_metadata.h>
#include <jalop/jalp_structured_data.h>
#include "jal_alloc.h"

struct jalp_logger_metadata *jalp_logger_metadata_create(void) {
	struct jalp_logger_metadata *new_logger_metadata;
	new_logger_metadata = jal_calloc(1, sizeof(*new_logger_metadata));

	return new_logger_metadata;
}

void jalp_logger_metadata_destroy(struct jalp_logger_metadata **logger_meta) {
	if(!logger_meta || !(*logger_meta))
		return;
	free((*logger_meta)->logger_name);
	free((*logger_meta)->timestamp);
	free((*logger_meta)->threadId);
	free((*logger_meta)->message);
	free((*logger_meta)->nested_diagnostic_context);
	free((*logger_meta)->mapped_diagnostic_context);
	jalp_log_severity_destroy(&((*logger_meta)->severity));
	jalp_stack_frame_destroy(&((*logger_meta)->stack));
	jalp_structured_data_destroy(&((*logger_meta)->sd));
	*logger_meta = NULL;
}

