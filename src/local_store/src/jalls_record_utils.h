/**
 * @file jalls_record_utils.h Function declarations for obtaining various hunks
 * of metadata.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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
#ifndef _JALLS_UID_UTILS_H_
#define _JALLS_UID_UTILS_H_

#include <sys/types.h>

#include "jaldb_record.h"
#include "jalls_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Helper utility to obtain the username for a given UID.
 *
 * @return NULL if an error occurred, a string otherwise. The caller is
 * responsible for freeing the returned string.
 */
char *jalls_get_user_id_str(uid_t uid);

#ifdef __HAVE_SELINUX
/**
 * Retrieve the platform specific security label.
 * @param[in] socketFd the file descriptor to use when obtaining the security
 * label.
 */
char *jalls_get_security_label(int socketFd);
#endif

/**
 * Helper utility to create a record.
 *
 */
int jalls_create_record(enum jaldb_rec_type rec_type,
			struct jalls_thread_context *thread_ctx,
			struct jaldb_record **prec);

#ifdef __cplusplus
}
#endif

#endif

