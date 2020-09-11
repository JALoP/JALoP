/**
 * @file jalls_context.h This file contains structs to deal with passing data
 * to local store worker threads.
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


#ifndef _JALLS_CONTEXT_H_
#define _JALLS_CONTEXT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/pem.h>
#include <sys/types.h>
#include <stdint.h>
#include <uuid/uuid.h>

#include "jaldb_context.h"

/** holds the fields to be passed to a worker thread */
struct jalls_context {
	/** Holds the debug flag, to be passed to worker threads */
	int debug;
	/* fields read from the config file. worker threads should never write
	 * to any of these fields, as other workers point to the same strings. */
	/** The full path to the private key used to add signatures to the system metadata*/
	char *private_key_file;
	/** The full path to the public cert used when adding signatures to the system metadata*/
	char *public_cert_file;
	/** The system uuid, as stored in the config file to be recorded in the system metadata*/
	uuid_t system_uuid;
	/** The hostname the JALoP Local Store should record in the system metadata */
	char *hostname;
	/** The full path to a directory that has the schemas */
	char *schemas_root;
	/** The full path to a directory to store the various database files and journal data */
	char *db_root;
	/** The full path to a UNIX Domain Socket. The JALoP Local Store will create the socket and wait for producer applications to connect to the socket. */
	char *socket;
	/** A boolean for whether to sign the system metadata for data received from the producer library. */
	int sign_sys_meta;
	/** A boolean for whether to include manifests in the system metadata for data received from the producer library. */
	int manifest_sys_meta;
	/** Thread count threshold that shall prompt accept delay. */
	int accept_delay_thread_count;
	/** Length of each accept delay increment in microseconds. */
	int accept_delay_increment;
	/** Maximum accept delay in microseconds. */
	int accept_delay_max;
};

struct jalls_thread_context { /* the worker thread should never write to or free any of the jalls_thread_context fields */
	/** the connection fd for the worker thread to revieve data */
	int fd;
	/** pointer to the context loaded from the config.*/
	struct jalls_context *ctx;
	/** pointer to the db layer context. */
	jaldb_context *db_ctx;
	/** The pid of the peer that sent the record. This will be gathered by the thread and stored in the system metadata */
	pid_t peer_pid;
	/** The uid of the peer that sent the record. This will be gathered by the thread and stored in the system metadata */
	uid_t peer_uid;
	/** The RSA private key to use when signing system metadata*/
	RSA *signing_key;
	/** The certificate used for signing the system metadata */
	X509 *signing_cert;
};


#ifdef __cplusplus
}
#endif

#endif // _JALLS_CONTEXT_H_
