/**
 * @file jaln_context.h
 *
 * Public functions for creating and configuring a jaln_context.
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
#ifndef _JALN_CONTEXT_H_
#define _JALN_CONTEXT_H_
#include <axl.h>
#ifdef __cplusplus
extern "C" {
#endif

struct jaln_context_t {
	struct jaln_publisher_callbacks *pub_callbacks;
	struct jaln_subscriber_callbacks *sub_callbacks;
	struct jaln_connection_callbacks *conn_callbacks;
	axlList *dgst_algs;
	axlList *xml_encodings;
	void *user_data;
};

#endif //_JALN_CONTEXT_H_
