/**
 * @file jaln_subscriber_callbacks_internal.h This file declares internal functions
 * related to jaln_subscriber_callbacks
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
#ifndef _JALN_SUBSCRIBER_CALLBACKS_INTERNAL_H_
#define _JALN_SUBSCRIBER_CALLBACKS_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <jalop/jaln_subscriber_callbacks.h>
#include <stdlib.h>

/**
 * Check that the subscriber callbacks is valid.
 * @param subscriber_callbacks The structure containing all the callbacks.
 *
 * @return 1 if subscriber_callbacks is valid, 0 otherwise
 */
int jaln_subscriber_callbacks_is_valid(struct jaln_subscriber_callbacks *subscriber_callbacks);

#ifdef __cplusplus
}
#endif

#endif // _JALN_SUBSCRIBER_CALLBACKS_INTERNAL_H_
