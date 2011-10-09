/**
 * @file jaln_connection_callbacks_internal.h This file contains function
 * declarations for internal library functions related to connection
 * creation/configuration.
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
#ifndef _JALN_CONNECTION_HANDLERS_INTERNAL_H_
#define _JALN_CONNECTION_HANDLERS_INTERNAL_H_
#include <jalop/jaln_connection_callbacks.h>

/**
 * Check that a given connection handlers structure is valid()
 * @param[in] callbacks The callbacks to check.
 * @return
 *  - 0 if the callbacks are invalid (i.e. missing a function)
 *  - 1 if the callbacks are valid.
 */
int jaln_connection_callbacks_is_valid(struct jaln_connection_callbacks *callbacks);
#endif // _JALN_CONNECTION_HANDLERS_INTERNAL_H_
