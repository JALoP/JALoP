/**
 * @file jalp_error_callback_internal.h This file defines internal functions to deal with
 * fatal errors.
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


#ifndef _JALP_ERROR_CALLBACK_INTERNAL_H_
#define _JALP_ERROR_CALLBACK_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Executed if the Producer Library encounters a fatal error, such as
 * allocation failures. Calls the application-defined error handler.
 *
 * @param[in] err Error value to be passed. The default behavior is to
 * simply abort; however, if the application overrides this, err will be
 * passed to the application-defined error handler.
 *
 */
void jalp_error_handler(int err);

#ifdef __cplusplus
}
#endif

#endif //_JALP_ERROR_CALLBACK_INTERNAL_H_
