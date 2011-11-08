/**
 * @file jaln_session.h This file contains function
 * declarations for internal library functions related to a jaln_session
 * structure.
 *
 * @section LICENSE
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
#ifndef _JALN_SESSION_H_
#define _JALN_SESSION_H_

#include <axl.h>
#include <jalop/jal_digest.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_network_types.h>
#include <vortex.h>

#ifdef __cplusplus
extern "C" {
#endif

struct jaln_session;
struct jaln_sub_state_machine;
struct jaln_sub_data;
struct jaln_pub_data;

/**
 * The session context represents a connection to a peer for either sending or
 * receiving JAL records.
 */
struct jaln_session {
	VortexMutex lock;                    //!< Mutex to lock the structure
	int ref_cnt;                         //!< Reference count

	jaln_context *jaln_ctx;              //!< The context we belong to.
	struct jal_digest_ctx *dgst;         //!< A copy of the digest to use.
	VortexChannel *rec_chan;             //!< The channel used for sending/receiving records
	VortexChannel *dgst_chan;            //!< The channel used for sending/receiving digests and sync messages.
	int rec_chan_num;                    //!< The channel number for the \p rec_chan
	int dgst_chan_num;                   //!< The channel number for the \p dgst_chan
	struct jaln_channel_info *ch_info;   //!< Additional information about the channel

	axl_bool closing;                    //!< Flag that indicates this
	axl_bool errored;                    //!< Flag that indicates an error occurred within the session
	axlList *dgst_list;                //!< A list of jaln_digest_info structures that are calculated as data is sent/received
	enum jaln_role role;                 //!< The role this context is performing (subscriber or publisher)
	int dgst_list_max;                 //!< The maximum number of digest entries to keep as a subscriber
	long dgst_timeout;                 //!< The maximum amount of time to wait before sending a 'digest' message
	union {
		struct jaln_sub_data* sub_data;   //!< Data specific to a subscriber
		struct jaln_pub_data* pub_data;   //!< Data specific to a publisher
	};
};

/**
 * Data related to a subscriber
 */
struct jaln_sub_data {
	//! The frame handler to use for the next incoming frame.
	void (*curr_frame_handler)(struct jaln_session *session, VortexChannel *v_chan, VortexConnection *v_conn, VortexFrame *frame);
	struct jaln_sub_state_machine *sm; //!< A state machine for processing the ANS responses for a 'subscribe' message
	VortexCond dgst_list_cond;       //!< a conditional for a thread to wait on to get notified when it is time to send digest messages.
};

/**
 * Data related to a publisher session
 */
struct jaln_pub_data {
	struct jaln_payload_feeder journal_feeder;  //!< the jaln_payload_feeder for sending a journal record.
	int vortex_feeder_sz;                       //!< The size (as reported to the Vortex engine) of this message.
	int msg_no;                                 //!< The message number we are replying to

	char *serial_id;                            //!< The serial ID of the last record sent.

	char *headers;                              //!< A buffer to hold the MIME headers for the current record.
	uint8_t *sys_meta;                          //!< A buffer to hold the system metadata for the current record.
	uint8_t *app_meta;                          //!< A buffer to hold the application metadata for the current record.
	uint8_t *payload;                           //!< A buffer to hold the data for the payload (if this is an audit or log record

	size_t headers_sz;                          //!< The size of jaln_pub_data::headers
	size_t sys_meta_sz;                         //!< The size of jaln_pub_data::sys_meta
	size_t app_meta_sz;                         //!< The size of jaln_pub_data::app_meta
	uint64_t payload_sz;                        //!< The size of jaln_pub_data::payload, or the size of the journal record.

	size_t headers_off;                         //!< The current offset into jaln_pub_data::headers
	size_t sys_meta_off;                        //!< The current offset into jaln_pub_data::sys_meta
	size_t app_meta_off;                        //!< The current offset into jaln_pub_data::app_meta
	uint64_t payload_off;                       //!< The current offset into jaln_pub_data::payload, or the journal record.
	size_t break_off;                           //!< The current offset used when writing the "BREAK" string between segments.

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
void jaln_session_ref(struct jaln_session *sess);

/**
 * Decrement the reference count on the jaln_session and possible destroy it.
 *
 * @param[in] sess The jaln_session to obtain release a reference from.
 */
void jaln_session_unref(struct jaln_session *sess);

/**
 * Create a jaln_session object
 */
struct jaln_session *jaln_session_create();

/**
 * Destroy a jaln_session object. This should only be called by
 * jaln_session_unref()
 *
 * @param[in] sess The session object to destroy.
 */
void jaln_session_destroy(struct jaln_session **sess);

/**
 * Create the subscriber data for a session
 *
 * @return a pointer to freshly created/initialized jaln_sub_data.
 */
struct jaln_sub_data *jaln_sub_data_create();

/**
 * Destroy a jaln_sub_data structure.
 *
 * @param[in,out] sub_data The jaln_sub_data to destroy
 */
void jaln_sub_data_destroy(struct jaln_sub_data **sub_data);

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
 * Flag this subscriber context as 'errored'
 * @param[in] ctx The jaln_session that encountered an error;
 */
void jaln_session_set_errored_no_lock(struct jaln_session *ctx);

void jaln_session_set_errored(struct jaln_session *ctx);

/**
 * Callback that must get notified with vortex for when a channel related to a
 * particular jaln_session gets closed. If the channel closed was the 'record'
 * (main) channel, then this will try to shutdown the other channel.
 *
 * @param[in] channel The VortexChannel that was closed.
 * @param[in] user_data This is expected to be a pointer to a jaln_session.
 */
void jaln_session_notify_unclean_channel_close(VortexChannel *channel, axlPointer user_data);

/**
 * Callback function that can be used when closing a vortex channel associated
 * with a jaln_session.
 *
 * @see VortexOnClosedNotificationFull
 *
 */
void jaln_session_notify_close(
		VortexConnection *conn,
		int channel_num,
		axl_bool was_closed,
		const char *code,
		const char *msg,
		axlPointer user_data);


/**
 * Callback function that is used to respond to incoming requests to close the
 * channel.
 *
 * @see VortexOnCloseChannel
 */
axl_bool jaln_session_on_close_channel(int channel_num,
		VortexConnection *connection,
		axlPointer user_data);

#ifdef __cplusplus
}
#endif
#endif // _JALN_SESSION_H_

