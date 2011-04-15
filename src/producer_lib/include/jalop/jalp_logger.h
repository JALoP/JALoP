/**
 * @file jalp_logger.h This file defines the public API that may interest a
 * 'logger' program.
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
#ifndef JALP_LOGGER_H
#define JALP_LOGGER_H
#include <stdint.h>
#include <stdlib.h>
#include <jalop/jalp_context.h>

/**
 * @defgroup logger Logger and Syslog
 * @{
 */
/*
 * Send a log message to the JALoP Local Store.
 *
 * If an application wishes to include additional data about the event, they
 * may allocate and fill in an jalp_app_metadata structure. This typically
 * entails filling out a jalp_syslog_metadata structure or jalp_logger_metadata
 * structure depending on the needs of the application. The jalp_syslog_metdata structure is
 * aimed at providing the same information typically conveyed via the syslog
 * mechanism of *nix systems.
 * The jalp_logger_metadata structure is aimed at providing extensive metadata that is
 * typically provided by frameworks such as log4j. If neither the
 * jalp_syslog_metadata or the jalp_logger_metadata provide enough flexibility, an 
 * application may assign the jalp_app_metadata::custom field to a snippet of XML.
 *
 * In the event the \p ctx was configured to generate digest values
 * (@see jalp_context_set_digest_callbacks), the ProducerLib will
 * generate an applicationMetadata document automatically.
 *
 * @param[in] ctx The context to send the data over
 * @param[in] app_meta An optional struct that the ProducerLib will convert into XML
 * for the application metadata.
 * schema.
 * @param[in] log_buffer An optional byte buffer that is the log message
 * @param[in] log_buffer_size The size of the byte buffer.
 *
 * @note It is an error to pass NULL for both \p app_meta and \p log_buffer.
 *
 * @return JAL_OK on success.
 *         JAL_XML_EINVAL if there is something wrong with the parameters
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * @note The ctx will be connected if it isn't already.
 */
enum jal_status jalp_log(jalp_context *ctx,
		struct jalp_app_meta *app_meta,
		uint8_t *log_buffer,
		size_t log_buffer_size);

/** @} */
#endif // JALP_LOGGER_H

