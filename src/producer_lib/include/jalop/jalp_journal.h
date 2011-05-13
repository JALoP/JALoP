/**
 * @file jalp_journal.h This file defines the public API that may interest a
 * a program that is sending journal records to the JALoP Local Store.
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
#ifndef _JALP_LOGGER_H_
#define _JALP_LOGGER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <jalop/jalp_context.h>

/**
 * @defgroup journal Sending Journal Data
 * Journal data is typically large, binary records that an application
 * processed in some way. For example, a virus scanner program could use JALoP
 * to quarantine infected files using the journaling facilities.
 *
 * Because the journal data is expected to be some binary file (such as a PDF,
 * MP3, tar.gz, zip, etc), applications should include a jalp_app_metadata that
 * describes the journal entry. In particular, they should fill in the
 * jalp_app_metadata::file_metadata section.
 *
 * In the event the \p ctx was configured to generate digest values
 * , the Producer Library will generate an applicationMetadata document automatically.
 * @see jalp_context_set_digest_callbacks
 */
/**
 * Send a journal entry to the JALoP Local Store.
 *
 * @param[in] ctx The context to send the data over.
 * @param[in] app_meta An optional structure that will be converted into an XML
 * document conforming to the application metadata schema.
 * @param[in] journal_buffer A byte buffer that contains the full contents of
 * a journal entry.
 * @param[in] journal_buffer_size The size (in bytes) of \p journal_buffer.
 *
 * @note It is an error to pass NULL for both \p app_metadata and \p
 * journal_buffer.
 *
 * @return JAL_OK on success.
 *         JAL_EINVAL If the parameters are incorrect.
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * @note The ctx will be connected if it isn't already.
 */
enum jal_status jalp_journal(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		uint8_t *journal_buffer,
		uint64_t journal_buffer_size);

/**
 * Send an open file descriptor to the JALoP Local Store.
 *
 * The caller must not write to the file identified by \p fd after making this
 * call, or else the JALoP Local Store may receive incorrect data. This call
 * works by sending just the file descriptor and is not available on all
 * platforms. If the underlying system doesn't support sending a
 * file descriptor over a UNIX Domain socket, this function will always return
 * JAL_E_NOT_SUPPORTED. Applications may check for this support at compile time
 * by looking for the JALP_CAN_SEND_FDS preprocessor define.
 * For example:
 * @code
 * #include<jalop/jalp_config.h>
 * #ifdef JALP_CAN_SEND_FDS
 * \/\* do something *\/
 * #endif
 * @endcode
 *
 * @param[in] ctx The context to send the record over.
 * @param[in] app_meta The optional application provided metadata.
 * @param[in] fd The file descriptor of the journal.
 * @return 
 *  - JAL_OK on success
 *  - JAL_E_NOT_SUPPORTED if the underlying system doesn't support SCM_RIGHTS on
 *  a socket
 *
 */
enum jal_status jalp_journal_fd(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		int fd);

/**
 * Open the file at \p path and send it the JALoP Local Store.
 *
 * This uses the #jalp_journal_fd internally to send a file descriptor. The
 * application should never write to the file after calling this method, but is
 * free to unlink it.
 *
 * @param[in] ctx The context to send the journal over.
 * @param[in] app_meta An optional structure that the library will convert into
 * an XML document.
 * @param[in] path The path to the file to journal.
 *
 * @note It is an error to pass NULL for both \p app_meta and \p path.
 *
 * @return 
 *  - JAL_OK if the JPL was successful at opening the file and sending the
 * descriptor to the JALoP Local Store.
 *  - JAL_E_NOT_SUPPORTED if the underlying system doesn't support SCM_RIGHTS on
 *  a socket
 *  - JAL_E_SYS some other system error occurred, for more info, the
 *  application may call jalp_errno to get the value.
 *
 */
enum jal_status jalp_journal_path(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		char *path);

/** @} */

#ifdef __cplusplus
}
#endif

#endif // _JALP_JOURNAL_H_

