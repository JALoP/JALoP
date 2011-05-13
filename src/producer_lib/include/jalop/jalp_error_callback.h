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


/* All out of memory errors are will be handled by memerror_handler
* Applications may override the default behavior (to simply abort)
* but must never return control to the application.
* memerror_handler will call abort if control is ever returned */


#ifndef _JALP_ERROR_CALLBACK_H_
#define _JALP_ERROR_CALLBACK_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register a function to be called in case of terminating error.
 *
 * @param[in] func Application defined function to register to be
 * called to handle unrecoverable errors.
 *
 * @return 0 on success.
 */

int jalp_set_error_callback(void (*func)(int err));


/**
 * Calls registered function to handle errors. Never returns.
 *
 * @param[in] error Error value to be passed. Default behavior
 * ignores this and aborts.
 *
 */

void jalp_error_handler(int error);

#ifdef __cplusplus
}
#endif
#endif //_JALP_ERROR_CALLBACK_H_
