/**
 * @file jaldb_segment.c This file contains functions related to the
 * jaldb_segment structure.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <unistd.h>

#include "jal_alloc.h"

#include "jaldb_segment.h"

struct jaldb_segment *jaldb_create_segment()
{
	struct jaldb_segment *ret = jal_calloc(1, sizeof(*ret));
	ret->fd = -1;
	return ret;
}

void jaldb_destroy_segment(struct jaldb_segment **ppsegment)
{
	if (!ppsegment || !*ppsegment) {
		return;
	}
	struct jaldb_segment *seg = *ppsegment;
	if (seg->fd >= 0) {
		close(seg->fd);
	}
	if (seg->fd >= 0) {
		close(seg->fd);
	}
	free(seg->payload);
	free(seg);
	*ppsegment = NULL;
}

