/**
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

/** \page page_jpl JALoP Producer Library (JPL)
 *
 * \section intro_sec Introduction
 *
 * The JALoP Producer Library (JPL) provides an API to send JAL data and
 * application metadata over a UNIX Domain Socket to a JALoP Local Store. The
 * JPL exposes an API that allows applications to connect to and submit JAL
 * data to a JALoP Local Store.
 *
 * The JALoP Producer Library is built on top of Apache Xerces, Santuario,
 * OpenSSL, and the BSD sockets API. The API provides helper functions for
 * generating the application metadata and adding digital signatures. The API
 * provides functions to send JAL data and metadata to the JALoP Local Store.
 *
 * The JPL implements the JAL Producer Protocol as described in the
 * "JALoPv1.0 Specification." The JPL uses its implementation of the JAL
 * Producer Protocol to send JAL data to the JALoP Local Store.
 *
 *  \section jal_protocol The JAL Producer Protocol
 *
 * JALoP has three different message types:
 *  - Journal - records that have potentially large payloads that will be
 *    passed through without modification. Examples include files that fail
 *    antivirus checks.
 *  - Audit - System events that conform to the Mitre CEE XML schema.
 *  - Log - Application events that do not conform to the CEE XML schema.
 *    These may be text or binary, and do not have a maximum size or minimum.
 *    Some examples are syslog messages, Apache log entries and messages
 *    originating from log framework like log4c++.
 *
 *  Messages may also include metadata with additional information related to
 *  the event.
 *
 *  Although no restrictions are enforced, log applications will typically use the
 *  Syslog or Logger types of the application metadata schema to provide
 *  additional data about the logging event. Or they may include a custom XML snippet
 *  if the application metadata does not provide sufficent fields.
 *  For convenience the JPL provides structures that match typical data found
 *  in syslog entries, and data available via the log4j/log4c logging
 *  frameworks.
 *
 *  For journal applications the metadata should include a JournalMetadata element from
 *  the application metadata schema. They may also wish to include a Syslog
 *  or Logger element to describe why the data is getting logged. Again, for convenience,
 *  the JPL provides structures that match the schema.
 *
 *  For audit records, there is typically no need to include additional
 *  metadata as the audit event schema itself should take care of all the
 *  relevant fields. However, an application may wish to include an application
 *  metadata document with the audit record if they would like to include a
 *  digital signature of the audit event.
 *
 *  A typical producer will probably only generate one type of message, but
 *  there is no limit.
 *
 *  The JAL Producer Protocol is one-way. A JAL producer sends a message to
 *  the local store over a UNIX domain socket and does not get a response.
 *
 *  \section devel_sec Development
 *
 *  \subsection d_step1 Step 1: Initializing a context
 *
 *  The library state related to a connection is stored in an opaque context.
 *  Therefore, the first order of business is to create a context
 *  The context should always be allocated on the heap via the jalp_context_create()
 *  function.
 *
 *  After allocating the context it must be initialized with the location of the JAL
 *  local store socket and the schema directory, if those aren't going to be the default.
 *
 *  \code
#include <jalop/jalp_context.h>
#include <jalop/jal_status.h>

int main(void)
{
	jalp_context *context;
	enum jal_status ret;

	ret = jalp_init();
	if (ret != JAL_OK)
		return -1;

	context = jalp_context_create();
	if (context == NULL)
		return -1;

	ret = jalp_context_init(context, NULL, NULL, "myappname", NULL);
	if (ret != JAL_OK)
		return -1;

	return 0;
}

 * \endcode
 *
 *  \subsection d_step2 Step 2: Loading keys and certificates
 *
 *  If your application is going to sign the JALoP data, which is recommended,
 *  it is necessary to load the RSA key and certificate and set up the digest callbacks.
 *  The JPL provides an OpenSSL-based SHA-256 digest. If this does not meet your
 *  requirements you will need to implement another, see jal_digest.h for information.
 *
 *  Assuming the key and cert are loaded correctly the library will automatically add
 *  signatures to the metadata without any additional code in the producer.
 *
 * \code
#include <jalop/jalp_context.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>

int main(void)
{
	jalp_context *context;
	enum jal_status ret;
	struct jal_digest_ctx *digest_ctx;

	ret = jalp_init();
	if (ret != JAL_OK)
		return -1;

	context = jalp_context_create();
	if (context == NULL)
		return -1;

	ret = jalp_context_init(context, NULL, NULL, "myappname", NULL);
	if (ret != JAL_OK)
		return -1;

	ret = jalp_context_load_pem_rsa(context, "/path/to/key", NULL);	
	if (ret != JAL_OK)
		return -1;

	ret = jalp_context_load_pem_cert(ctx, "/path/to/cert");
	if (ret != JAL_OK)
		return -1;

	// This is the included sha256 digest
	digest_ctx = jal_sha256_ctx_create();
	if (digest_ctx == NULL)
		return -1;

	jalp_context_set_digest_callbacks(context, digest_ctx);

	return 0;
}
 *\endcode
 *
 *  \subsection d_step3 Step 3: Build application metadata
 *
 *  The JAL protocol has application supplied metadata that is related to the
 *  journal, audit, or log data being sent. It is highly recommended that
 *  applications fill out as much of the application metadata as possible to
 *  make searching, analyzing and coalescing logs easier to do programatically.
 *
 *  \code
struct jalp_app_metadata *fill_out_metadata()
{

	struct jalp_app_metadata *new_app_meta = NULL;
	new_app_meta = jalp_app_metadata_create();
	if (new_app_meta == NULL)
		goto err;

	new_app_meta->type = JALP_METADATA_LOGGER;
	new_app_meta->log = jalp_logger_metadata_create();
	if (new_app_meta->log == NULL)
		goto err;
	new_app_meta->log->severity = jalp_log_severity_create();
	if (new_app_meta->log->severity == NULL)
		goto err;

	new_app_meta->log->severity->level_val = 999;
	new_app_meta->log->severity->level_str = strdup("DEBUG");
	if (new_app_meta->log->severity->level_str == NULL)
		goto err;

	new_app_meta->log->message = strdup("Everything is going okay right now");
	if (new_app_meta->log->message == NULL)
		goto err;

	return new_app_meta;

err:
	jalp_app_metadata_destroy(&new_app_meta);
	return NULL;
}
 *  \endcode
 *
 *  \subsection d_step5 Step 5: Send the message
 *
 *  Finally, it is time to send the log message to the JAL local store
 *
 *  \code
void send_log()
{
	struct jalp_app_metadata *app_meta;
	app_meta = fill_out_metadata();
	if (app_meta == NULL)
		return -1;

	uint8_t[128] payload = "This is the payload, it is a string here but it can be binary\n";
	// strlen works here because it is a string but do not use it if there may be binary data
	size_t payload_size = strlen(payload);

	ret = jalp_log(context, app_meta, payload, payload_size);
	if (ret != JAL_OK) {
		//something went wrong, check ret
		return -1;
	// Done, continue to next message
	jalp_app_metadata_destroy(&app_meta);
}
 *  \endcode
 *
 * Similar steps are used to send audit or journal data to the local store,
 * see jalp_audit(), jalp_journal(), and jalp_journal_fd().
 */
