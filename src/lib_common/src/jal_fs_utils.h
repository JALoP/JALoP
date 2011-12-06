/**
 * @file jal_fs_utils.h This file defines general utility functions.
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

#ifndef _JAL_FS_UTILS_H_
#define _JAL_FS_UTILS_H_

#include <jalop/jal_status.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Helper function that will create (if needed) all directories within a path.
 *
 * A '/' is used as the path separator.  The final element in the path is only
 * create as a directory if it ends with a '/'.  For example,
 * jal_create_dirs("/foo/bar"); will create the directory /foo, but not the
 * directory /foo/bar.  On the other hand, jal_create_dirs("/foo/bar/"); will
 * create both /foo and /foo/bar as needed.
 *
 * @param[in] path The path containing directories to create.
 * @return 
 *  - JAL_OK on success
 *  - JAL_E_INVAL on error
 */
enum jal_status jal_create_dirs(const char *path);

#ifdef __cplusplus
}
#endif

#endif // _JAL_FS_UTILS_H_
