/**
 * @file jalp_error_callback.c This file contains functions to handle fatal
 * errors encountered by the Producer Library.
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
#include <jalop/jalp_error_callback.h>
#include <jalop/jal_status.h>
#include "jalp_error_callback_internal.h"

/** The default behavior for the jalp error handler is to abort */
__attribute__((noreturn)) static void jalp_default_fatal_error_callback(__attribute__((unused))int err)
{
	abort();
}

/** holds the registered callback function provided by the
 * application for handling fatal errors. */
static jalp_app_error_handler fatal_error_callback = &jalp_default_fatal_error_callback;

enum jal_status jalp_set_error_callback(jalp_app_error_handler handler)
{
	if(!handler) {
		return JAL_E_INVAL;
	}
	fatal_error_callback = handler;
	return JAL_OK;
}

__attribute__((noreturn)) void jalp_error_handler(int err)
{
	fatal_error_callback(err);
	abort();
}
