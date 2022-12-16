/**
 * @file jaln_session.h This file contains function
 * declarations for internal library functions related to a jaln_session
 * structure.
 *
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
#ifndef _JALN_SESSION_H_
#define _JALN_SESSION_H_

#include <pthread.h>
#include <axl.h>
#include <curl/curl.h>
#include <jalop/jal_digest.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_network_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JALN_SESSION_DEFAULT_DGST_LIST_MAX 1

// 30 minute timeout
#define JALN_SESSION_DEFAULT_DGST_TIMEOUT_MICROS (30 * 60 * 100000)

struct jaln_sub_state_machine;
struct jaln_pub_data;

/**
 * The session context represents a connection to a peer for either sending or
 * receiving JAL records.
 */
struct jaln_session_t {
	int ref_cnt;                         //!< Reference count
	enum jaln_publish_mode mode;         //!< Whether to send messages as archive or live

	jaln_context *jaln_ctx;              //!< The context we belong to.
	struct jal_digest_ctx *dgst;         //!< A copy of the digest to use.
	axl_bool dgst_on;                    //!< Whether digest challenging is configured to be on
	CURL *curl_ctx;                      //!< The libcurl context used for sending messages via HTTP.
	struct jaln_channel_info *ch_info;   //!< Additional information about the channel
	char *id;                            //!< Session ID added to messages to associate them with this session

	axl_bool closing;                    //!< Flag that indicates this
	axl_bool errored;                    //!< Flag that indicates an error occurred within the session
	axlList *dgst_list;                  //!< A list of jaln_digest_info structures that are calculated as data is sent/received
	enum jaln_role role;                 //!< The role this context is performing (subscriber or publisher)
	int dgst_list_max;                   //!< The maximum number of digest entries to keep as a subscriber
	long dgst_timeout;                   //!< The maximum amount of time to wait before sending a 'digest' message
	struct jaln_pub_data* pub_data;      //!< Data specific to a publisher
};


/**
 * Data related to a publisher session
 */
struct jaln_pub_data {
	struct jaln_payload_feeder journal_feeder;  //!< the jaln_payload_feeder for sending a journal record.
	int64_t feeder_sz;                       //!< The size of this message.
	int msg_no;                                 //!< The message number we are replying to

	char *nonce;                            //!< The nonce of the last record sent.

	struct curl_slist *headers;                              //!< A buffer to hold the MIME headers for the current record.
	uint8_t *sys_meta;                          //!< A buffer to hold the system metadata for the current record.
	uint8_t *app_meta;                          //!< A buffer to hold the application metadata for the current record.
	uint8_t *payload;                           //!< A buffer to hold the data for the payload (if this is an audit or log record

	uint64_t headers_sz;                          //!< The size of jaln_pub_data::headers
	uint64_t sys_meta_sz;                         //!< The size of jaln_pub_data::sys_meta
	uint64_t app_meta_sz;                         //!< The size of jaln_pub_data::app_meta
	uint64_t payload_sz;                        //!< The size of jaln_pub_data::payload, or the size of the journal record.

	uint64_t headers_off;                         //!< The current offset into jaln_pub_data::headers
	uint64_t sys_meta_off;                        //!< The current offset into jaln_pub_data::sys_meta
	uint64_t app_meta_off;                        //!< The current offset into jaln_pub_data::app_meta
	uint64_t payload_off;                       //!< The current offset into jaln_pub_data::payload, or the journal record.
	uint64_t break_off;                           //!< The current offset used when writing the "BREAK" string between segments.

	axl_bool finished_headers;                  //!< Indicates the headers have been sent.
	axl_bool finished_sys_meta;                 //!< Indicates the system metadata has been sent.
	axl_bool finished_sys_meta_break;           //!< Indicates the "BREAK" following the system metadata has been sent.
	axl_bool finished_app_meta;                 //!< Indicates the application metadata has been sent.
	axl_bool finished_app_meta_break;           //!< Indicates the "BREAK" following the system metadata has been sent.
	axl_bool finished_payload;                  //!< Indicates the payload has been sent
	axl_bool finished_payload_break;            //!< Indicates the "BREAK" following the payload has been sent.

	void *dgst_inst;                            //!< An instance of a digest_ctx for a particular record.
	uint8_t *dgst;                              //!< A buffer to hold the final contents of a digest
};

/**
 * Increment the reference count on the jaln_session
 *
 * @param[in] sess The jaln_session to obtain a reference for.
 */
void jaln_session_ref(jaln_session *sess);

/**
 * Decrement the reference count on the jaln_session and possible destroy it.
 *
 * @param[in] sess The jaln_session to obtain release a reference from.
 */
void jaln_session_unref(jaln_session *sess);

/**
 * Create a jaln_session object
 */
jaln_session *jaln_session_create();

/**
 * Destroy a jaln_session object. This should only be called by
 * jaln_session_unref()
 *
 * @param[in] sess The session object to destroy.
 */
void jaln_session_destroy(jaln_session **sess);

/**
 * Create an axlList to hold jaln_session objects. For this list, jaln_session
 * objects are considered equal iff they have the same pointer value. This
 * does not perform a deep comparison of any of the internal members.
 *
 * @return an axlList
 */
axlList *jaln_session_list_create();

/**
 * Generic helper utility for the jaln_session_list_create and the axlList.
 * This function merely returns the difference between the pointer values \p a
 * and \p b.
 *
 * @return the difference between \p a and \p b.
 */
int jaln_ptrs_equal(axlPointer a, axlPointer b);

/**
 * Create the publisher data for a session
 *
 * @return a pointer to freshly created/initialized jaln_pub_data.
 */
struct jaln_pub_data *jaln_pub_data_create();

/**
 * Destroy a jaln_pub_data structure.
 *
 * @param[in,out] pub_data The jaln_pub_data to destroy
 */
void jaln_pub_data_destroy(struct jaln_pub_data **pub_data);

/**
 * Cache the calculations of a digest to be sent at a later time.
 *
 * @param[in] session The session that the digests are associated with.
 * @param[in] nonce The nonce of the record
 * @param[in] dgst_len The length of the digest (in bytes).
 *
 * @return JAL_OK on success or an error.
 */
enum jal_status jaln_session_add_to_dgst_list(jaln_session *sess,
		char *nonce,
		uint8_t *dgst_buf,
		uint64_t dgst_len);

/**
 * Flag this session as 'errored'
 *
 * @param[in] ctx The jaln_session that encountered an error;
 */
void jaln_session_set_errored_no_lock(jaln_session *sess);

void jaln_session_set_errored(jaln_session *sess);

/**
 * Set the digest timout
 * @param[in] sess The jaln_session to set the timeout of
 * @param[in] timeout The value to set the digest timeout to
 */
void jaln_session_set_dgst_timeout(jaln_session *sess, long timeout);

/**
 * Set the digest max
 * @param[in] sess The jaln_session to set the max digest entries of
 * @param[in] max The value to set the max digest entries to
 */
void jaln_session_set_dgst_max(jaln_session *sess, int max);

#ifdef __cplusplus
}
#endif
#endif // _JALN_SESSION_H_

