 /**
 * @file jsub_callbacks.hpp This file provides the function calls
 * to be executed by the network library callback handler.
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

#ifndef _JSUB_CALLBACKS_HPP_
#define _JSUB_CALLBACKS_HPP_

#include <stdlib.h>
#include <jalop/jaln_network_types.h>
#include <jalop/jaln_subscriber_callbacks.h>
#include <jalop/jaln_connection_callbacks.h>
#include <jalop/jaln_network.h>
#include "jaldb_context.h"
#include "jaldb_context.hpp"

extern volatile bool jsub_is_conn_closed;
extern volatile int jsub_debug;
extern jaldb_context *jsub_db_ctx;

enum jal_status jsub_callbacks_init(jaln_context *ctx);

#endif // _JSUB_CALLBACKS_HPP_