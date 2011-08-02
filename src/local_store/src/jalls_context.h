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


#ifndef _JALLS_CONTEXT_H_
#define _JALLS_CONTEXT_H_


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
	char *system_uuid;
	/** The hostname the JALoP Local Store should record in the system metadata */
	char *hostname;
	/** The full path to a directory to store the various database files and journal data */
	char *db_root;
	/** The full path to a UnixUNIX Domain Socket. The JALoP Local Store will create the socket and wait for producer applications to connect to the socket. */
	char *socket;
};

#endif // _JALLS_CONTEXT_H_
