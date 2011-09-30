/**
 * @file jaln_channel_info.h This file contains function
 * declarations for internal library functions related to a
 * jaln_channel_info structure.
 *
 * @section LICENSE
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
#ifndef _JALN_CHANNEL_INFO_H_
#define _JALN_CHANNEL_INFO_H_
#include <jalop/jaln_network.h>

/**
 * Create a jaln_channel_info object
 */
struct jaln_channel_info *jaln_channel_info_create();

/**
 * Destroy a jaln_channel_info object
 *
 * @param[in] conn The channel_info object to destroy.
 */
void jaln_channel_info_destroy(struct jaln_channel_info **chan);

#endif // _JALN_CHANNEL_INFO_H_

