/**
 * @file jal_ts_utils.h This file defines general timestamp utility functions.
 *
 * Copyright (C) 2025 The National Security Agency (NSA)
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _JAL_TS_UTILS_H_
#define _JAL_TS_UTILS_H_

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a timestamp for the Current time in the XML DateTime format which includes
 * microseconds.
 *
 * @return a newly allocated string that contains the current time as an XML
 * DateTime string.
 */
char *jal_gen_timestamp_usec();

#ifdef __cplusplus
}
#endif

#endif // _JAL_TS_UTILS_H_
