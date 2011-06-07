/**
 * @file jalp_context.c This file defines functions for jalp_context.
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
#include <unistd.h>
#include <jalop/jalp_context.h>
#include "jal_alloc.h"
#include "jalp_context_internal.h"

jalp_context *jalp_context_create(void)
{
	jalp_context *context = jal_calloc(1, sizeof(*context));
	context->socket = -1;
	return context;
}

void jalp_context_disconnect(jalp_context *ctx)
{
	if (ctx) {
		close(ctx->socket);
		ctx->socket = -1;
	}
}
