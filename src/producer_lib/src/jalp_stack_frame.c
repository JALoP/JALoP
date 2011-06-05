/**
 * @file jalp_stack_frame.c This file contains functions for creating 
 * and destroying jalp_stack_frames.
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

#include <jalop/jalp_logger_metadata.h>
#include "jal_alloc.h"
#include "jalp_stack_frame_internal.h"

struct jalp_stack_frame *jalp_stack_frame_append(struct jalp_stack_frame *prev)
{
	struct jalp_stack_frame *stack_frame = NULL;
	stack_frame = jal_calloc(1, sizeof(*stack_frame));

	if (prev) {
		stack_frame->next = prev->next;
		prev->next = stack_frame;
	}

	return stack_frame;
}

void jalp_stack_frame_destroy_one(struct jalp_stack_frame *stack_frame)
{
	free(stack_frame->caller_name);
	free(stack_frame->file_name);
	free(stack_frame->class_name);
	free(stack_frame->method_name);
	free(stack_frame);
}

void jalp_stack_frame_destroy(struct jalp_stack_frame **stack_frame)
{
	if (!stack_frame || !(*stack_frame)) {
		return;
	}

	struct jalp_stack_frame *cur = *stack_frame;

	while(cur) {
		struct jalp_stack_frame *next = cur->next;
		jalp_stack_frame_destroy_one(cur);
		cur = next;
	}

	*stack_frame = NULL;
}
