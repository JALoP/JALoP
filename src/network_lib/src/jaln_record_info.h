/**
 * @file jaln_record_info.h This file contains function
 * declarations for internal library functions related to a
 * jaln_record_info structure.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
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
#ifndef _JALN_RECORD_INFO_H_
#define _JALN_RECORD_INFO_H_

#include <axl.h>
#include <jalop/jaln_network.h>

/**
 * Create a jaln_record_info object
 */
struct jaln_record_info *jaln_record_info_create();

/**
 * Destroy a jaln_record_info object
 *
 * @param[in] rec_info The record_info object to destroy.
 */
void jaln_record_info_destroy(struct jaln_record_info **rec_info);

/**
 * Check to see if a jaln_record_info structure is valid.
 *
 * @param[in] info The jaln_record_info object to check.
 *
 * @return axl_true if the record is valid, axl_false otherwise.
 */
axl_bool jaln_record_info_is_valid(struct jaln_record_info *info);

#endif // _JALN_RECORD_INFO_H_

