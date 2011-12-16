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

#define JALN_SESSION_DEFAULT_DGST_LIST_MAX 100

// 30 minute timeout
#define JALN_SESSION_DEFAULT_DGST_TIMEOUT_MICROS (30 * 60 * 100000)

struct jaln_sub_state_machine;
struct jaln_sub_data;
struct jaln_pub_data;

/**
 * The session context represents a connection to a peer for either sending or
 * receiving JAL records.
 */
struct jaln_session_t {
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
	void (*curr_frame_handler)(jaln_session *session, VortexChannel *v_chan, VortexConnection *v_conn, VortexFrame *frame);
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
 * Create the subscriber data for a session
 *
 * @return a pointer to freshly created/initialized jaln_sub_data.
 */
struct jaln_sub_data *jaln_sub_data_create();

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
 * Cache the calculations of a digest to be sent at a later time.
 *
 * @param[in] session The session that the digests are associated with.
 * @param[in] serial_id The serial_id of the record
 * @param[in] dgst_len The length of the digest (in bytes).
 *
 * @return JAL_OK on success or an error.
 */
enum jal_status jaln_session_add_to_dgst_list(jaln_session *sess,
		char *serial_id,
		uint8_t *dgst_buf,
		size_t dgst_len);

/**
 * Flag this session as 'errored'
 *
 * @param[in] ctx The jaln_session that encountered an error;
 */
void jaln_session_set_errored_no_lock(jaln_session *sess);

void jaln_session_set_errored(jaln_session *sess);

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
 * Callback function registered with Vortex for when use when creating a
 * 'digest' channel. The initiator of the communications should register this
 * callback when creating a channel for use as a 'digest' channel.
 *
 * @param[in] channel_num the channel number, -1 if the channel wasn't created
 * @param[in] chan The vortex channel, NULL if the channel wasn't created
 * @param[in] conn The vortex connection
 * @param[in] user_data Expected to be a pointer to a jaln_session. 
 *
 * @see vortex_channel_new
 */
void jaln_session_on_dgst_channel_create(
		int channel_num,
		VortexChannel *chan,
		VortexConnection *conn,
		axlPointer user_data);

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

/**
 * Helper to associate a Vortex channel for use as a 'digest' channel for the
 * session.
 *
 * @param[in] session The session to associate with.
 * @param[in] chan The vortex channel
 * @param[in] chan_num The channel number
 *
 * @return axl_true if \p chan was associated with \p session, axl_false
 * otherwise.
 */
axl_bool jaln_session_associate_digest_channel_no_lock(jaln_session *session,
		VortexChannel *chan,
		int chan_num);

#ifdef __cplusplus
}
#endif
#endif // _JALN_SESSION_H_

