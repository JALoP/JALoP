/**
 * @file jal_status.h This file defines return codes used by the JAL libraries.
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
#ifndef _JAL_STATUS_H_
#define _JAL_STATUS_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Enumeration for error codes returned by JALoP calls.
 */
enum jal_status {
	JAL_E_XML_PARSE = -1024,
	JAL_E_XML_SCHEMA,
	JAL_E_XML_CONVERSION,
	JAL_E_NOT_CONNECTED,
	JAL_E_INVAL,
	JAL_E_INVAL_PARAM,
	JAL_E_INVAL_STRUCTURED_DATA,
	JAL_E_NO_MEM,
	JAL_E_UNINITIALIZED,
	JAL_E_INITIALIZED,
	JAL_OK = 0,
};

#ifdef __cplusplus
}
#endif
#endif // _JAL_STATUS_H_
