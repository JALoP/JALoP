/**
 * @file jal_version.h This file defines the version number
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2013 Tresys Technology LLC, Columbia, Maryland, USA
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
#ifndef _JAL_VERSION_H_
#define _JAL_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif

/** Sets the version for JALoP */
#define JAL_VERSION 2.0

/** Sets the version for JPP (JALoP Producer Protocol) */
#define JPP_VERSION 2

/** Return a pointer to a string containing the JALoP verion */
char *jal_version_as_string();

#ifdef __cplusplus
}
#endif

#endif //_JAL_VERSION_H_
