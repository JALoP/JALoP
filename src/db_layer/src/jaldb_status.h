/**
 * @file jaldb_status.h This file defines return codes used by the JAL DB Layer.
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
#ifndef _JALDB_STATUS_H_
#define _JALDB_STATUS_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Enumeration for error codes returned by DB layer calls.
 */
enum jaldb_status {
	JALDB_E_INVAL = -1024,
	JALDB_E_UNKNOWN,
	JALDB_E_DB,
	JALDB_E_ALREADY_CONFED,
	JALDB_E_NO_MEM,
	JALDB_E_UNINITIALIZED,
	JALDB_E_INTERNAL_ERROR,
	JALDB_E_INITIALIZED,
	JALDB_E_CORRUPTED,
	JALDB_E_SID,
	JALDB_E_NOT_FOUND,
	JALDB_E_READ_ONLY,
	JALDB_E_QUERY_EVAL,
	JALDB_OK = 0,
};

#ifdef __cplusplus
}
#endif
#endif // _JALDB_STATUS_H_
