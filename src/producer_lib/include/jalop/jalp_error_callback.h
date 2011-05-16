/**
 * @file jalp_error_callback.h This file defines functions to deal with
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



#ifndef _JALP_ERROR_CALLBACK_H_
#define _JALP_ERROR_CALLBACK_H_

#include <jalop/jal_status.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Pointer to the application defined function to handle fatal errors.
 * Such functions should not attempt to return control to the application.
 */
typedef void(*jalp_app_error_handler)(int err);

/**
 * Register a function to be called in case of terminating error. Applications
 * may use this to override the default fatal error behaivor (to simply abort).
 *
 *
 * @param[in] handler Application defined function to execute if the Producer
 * Library encounters a fatal error, such as allocation failures.
 *
 * @return JAL_OK on success or JAL_E_INVAL if the function pointer is NULL.
 */
enum jal_status jalp_set_error_callback(jalp_app_error_handler handler);

#ifdef __cplusplus
}
#endif
#endif //_JALP_ERROR_CALLBACK_H_
