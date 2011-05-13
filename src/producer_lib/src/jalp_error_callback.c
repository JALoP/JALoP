/**
 * @file jalp_structured_data.h This file defines structures and functions to
 * deal with structured_data elements of the syslog and logger metadata.
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
#include <include/jalop/jalp_error_callback.h>

/** The default behavior for the jalp error handler is to abort */
static void jalp_abort(int err) {
	abort();
}

/** holds the registered callback function provided by the
 * application for handling fatal errors. */
static void (*fatal_error_callback)(int error) = &jalp_abort;

/**
 * Register a function to be called in case of terminating error.
 *
 * @param[in] func Application defined function to register to be
 * called to handle unrecoverable errors.
 *
 * @return 0 on success.
 */

int jalp_set_error_callback(void (*func)(int err)) {
	
	fatal_error_callback = func;
	return 0;
}

/**
 * Calls registered function to handle errors. Never returns.
 *
 * @param[in] error Error value to be passed to the error handler.
 * Default handler ignores this and aborts.
 *
 */

void jalp_error_handler(int error) {

	fatal_error_callback(error); /**calls application defined error handler */
	abort();
}
