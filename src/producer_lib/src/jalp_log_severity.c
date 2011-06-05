/**
 * @file jalp_log_severity.c This file defines functions to deal with log
 * severity metadata.
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
#include "jal_alloc.h"

struct jalp_log_severity *jalp_log_severity_create(void)
{
	struct jalp_log_severity *new_severity = jal_calloc(1, sizeof(*new_severity));
	return new_severity;
}

void jalp_log_severity_destroy(struct jalp_log_severity **log_severity)
{
	if (!log_severity || !(*log_severity)) {
		return;
	}
	free((*log_severity)->level_str);
	free(*log_severity);
	*log_severity = NULL;
}
