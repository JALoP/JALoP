/**
 * @file jaln_subscriber_state_machine.h This file contains the declaration for a
 * state machine used when receiving JAL records.
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

#ifndef _JALN_SUBSCRIBER_STATE_MACH_H_
#define _JALN_SUBSCRIBER_STATE_MACH_H_

#include "jaln_session.h"

/**
 * Represents a singe state in the subscriber state machine.
 */
struct jaln_sub_state {
	/** The name of this state, used for debugging */
	char *name;

	/** The frame handler for this state
	 * @param [in] session The jaln_session the frame was received on.
	 * @param [in] frame The VortexFrame
	 * @param [in] payload_offset Indicates the number of bytes consumed by
	 * previous states. For example, if State A consumes 30 bytes,
	 * but the frame contains 50 bytes of data, then the state machine
	 * transitions to State B, passing 30 as \p frame_offset.
	 * @param [in] more Set to axl_true if more frames are expected,
	 * axl_false otherwise.
	 *
	 * @return 
	 *  - axl_true if the state was successful at processing the frame.
	 *  Success is only indicated by an absence of a failure. For example,
	 *  when processing the system metadata, if the system metadata is
	 *  expected to be 100 bytes, and after processing the current frame,
	 *  there are 50 bytes of system metadata available AND \p more is
	 *  axl_true (more frames are expected to be sent), this is considered
	 *  a success. Conversely, if no more frames are expected, then this
	 *  would be an error.
	 *  - axl_false if there was an error.
	 */
	axl_bool (*frame_handler)(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);
};

/**
 * The state machine structure used while receiving frames of a
 * Journal/audit/log Record message
 */
struct jaln_sub_state_machine {
	char *expected_msg;                //<! The expected message type (journal, audit, or log records)
	char *payload_len_hdr;             //<! The expected MIME header for the size of the payload ('jal-log-lenght
	char *serial_id;                   //<! The serial ID of the record currently in process
	uint8_t *sys_meta_buf;            //<! bufer containing the system metadata
	uint64_t sys_meta_sz;              //<! the total size of the sys_meta_bufer
	size_t sys_meta_off;               //<! offset into the bufer to begin writing the next hunk of data
	uint8_t *app_meta_buf;            //<! bufer containing the system metadata
	size_t app_meta_sz;                //<! the total size of the sys_meta_bufer
	size_t app_meta_off;               //<! offset into the bufer to begin writing the next hunk of data
	uint8_t *payload_buf;             //<! bufer containing the system metadata
	size_t payload_sz;                 //<! the total size of the sys_meta_bufer
	size_t payload_off;                //<! offset into the bufer to begin writing the next hunk of data
	uint8_t *break_buf;               //<! bufer to hold the break string between data segments
	size_t break_sz;                   //<! size of the break string
	size_t break_off;                  //<! offset into the bufer to begin writing the next hunk of data
	VortexFrame *cached_frame;         //<! used to collect frames until the complete MIME headers are available.
	void *dgst_inst;                   //<! An instance of a digest_ctx for a particular record.
	uint8_t *dgst;                     //<! A buffer to hold the final contents of a digest

	struct jaln_sub_state *curr_state;                //<! The current state.
	struct jaln_sub_state *wait_for_mime;             //<! The initial state, waiting for enough data to come through to parse the MIME headers.
	struct jaln_sub_state *wait_for_sys_meta;         //<! The state that handles reading the system metadata from the frame payload.
	struct jaln_sub_state *wait_for_sys_meta_break;   //<! The state that reads the 'BREAK' marker between the system metadata and app metadata.
	struct jaln_sub_state *wait_for_app_meta;         //<! The state that handles reading the app metadata from the frame payload.
	struct jaln_sub_state *wait_for_app_meta_break;   //<! The state that reads the 'BREAK' marker between the app metadata and the record data.
	struct jaln_sub_state *wait_for_payload;          //<! The state that handles reading record data from the frame payload.
	struct jaln_sub_state *wait_for_payload_break;    //<! The state that reads the 'BREAK' marker following the record data.
	struct jaln_sub_state *record_complete;           //<! The state that finalizes a record.
	struct jaln_sub_state *error_state;;              //<! The error state.
};


/**
 *  Because it is unlikely that the full contents of a journal record can fit
 *  into memory, the JAL library must be able to handle processing the data as
 *  it is transfered over the network, rather than waiting for the complete
 *  payload to get transfered. This requires a bit of state information to be
 *  saved between successive calls to the vortex frame handler. The different
 *  components of a record message are:
 *   - MIME headers (which designate the sizes of the sys/app metadata and the
 *  record date)
 *   - System Metadata
 *   - A 'BREAK' string
 *   - Application Metada
 *   - A 'BREAK' string
 *   - Record Payload
 *   - A 'BREAK' string
 *
 *  The basic concept here is simple, when a new frame arrives on a channel,
 *  vortex will execute our top-level frame handler, which in turn calls the
 *  state machines 'current' handler. If the new frame has enough data for the
 *  particular state (i.e. if the current state was waiting for the system
 *  metadata, and the frame contained the rest of the data for the system
 *  metadata), then transition to the next state in the chain, and continue
 *  processing the frame. Eventually the stats will exhaust all the bytes in
 *  the frame, and will need to wait for the next frame.
 *
 *  If an error occurs, we transfer into the 'error state' where every frame
 *  fails.
 *
 */

/**
 * Frame handler for processing MIME headers.
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_wait_for_mime(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);

/**
 * Frame handler for processing application metadata.
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_wait_for_app_meta(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);

/**
 * Frame handler for processing system metadata.
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_wait_for_sys_meta(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);

/**
 * Frame handler for processing the audit or log record payload.
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_wait_for_payload(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);

/**
 * Frame handler for processing the 'BREAK' string following the payload.
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_wait_for_payload_break(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);

/**
 * Frame handler for processing the 'BREAK' string following the system
 * metadata
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_wait_for_sys_meta_break(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);

/**
 * Frame handler for processing the 'BREAK' string following the application
 * metadata.
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_wait_for_app_meta_break(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);

/**
 * Frame handler for processing a journal record payload.
 * This function must
 * execute user supplied callbacks for each hunk of data recieved.
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_wait_for_journal_payload(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);

/**
 * Helper function for processing the 'BREAK' strings
 * @param[in] session The jaln_session
 * @param[in] frame The frame
 * @param[in] frame_off The offset into the frame to start looking for the
 * 'BREAK' string
 * @param[in] more Indicator of whether or not more frames are expected
 * @param[in] break_valid Set to 'axl_true' if and only if enough bytes were
 * read to determine if the 'BREAK' string exists in the messsage. If only 3
 * (out of 5) bytes have been read, this will be false.
 *
 * @return
 *  - axl_true if no errors were encountered. Note that a return of true only
 *  indicates the frame was successfully processed. You must check the value of
 *  \p break_valid to determine if it is safe to transition to the next state.
 *
 *  - axl_false If the 'BREAK' string was not found, or there was not enough
 *  data in the frame and no more frames are expected.
 */
axl_bool jaln_sub_wait_for_break_common(jaln_session *session, VortexFrame *frame,
		size_t *frame_off, axl_bool more, axl_bool *break_valid);

/**
 * Simple sanity check for when all bytes have been received. This will fail if
 * there are unconsumed bytes in the frame, or there are more frames expected
 * for this message.
 */
axl_bool jaln_sub_rec_complete_sanity_check(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);

/**
 * The frame handler for finalizing a journal record
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_journal_record_complete(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);

/**
 * The frame handler for finalizing an audit record.
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_audit_record_complete(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more);

/**
 * The frame handler for finalizing an log record.
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_log_record_complete(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more);

/**
 * The frame handler for the error state. Once entered, you can never exit, all
 * new frames will fail processing.
 * @see jaln_sub_state::frame_handler
 */
axl_bool jaln_sub_state_error_state(jaln_session *session, VortexFrame *frame, size_t payload_offset, axl_bool more);

/**
 * Helper function to reset the state machine once processing for a record is
 * complete. This gets the state machine prepared to handler the next record.
 *
 * @param[in] session The session to reset.
 */
void jaln_sub_state_reset(jaln_session *session);

/**
 * Helper function to cache a frame within the state machine.
 *
 * @param[in] session The session to cache the frame on.
 */
axl_bool jaln_sub_state_append_frame(jaln_session *session, VortexFrame *frame);

/**
 * Helper function to safely copy data between 2 buffers. Note that the buffers
 * must not overlap, and calling this function with overlapping buffers is
 * undefined.
 *
 * This function copies the maximum number of bytes that is possible, that is
 * to say, if there are 10 bytes left in the source buffer, and 20 bytes
 * available to fill the destination buffer, only 10 bytes will be copied.
 * Conversely, if there are 20 bytes left in the source buffer, and 10 bytes
 * available to fill the destination buffer, only 10 bytes will be copied.
 *
 * Note that this function will fail when there are not enough bytes in the
 * source buffer to fill the destination buffer AND \p more is false.
 *
 * @param[in] dst The destination buffer.
 * @param[in] dst_sz The size of the destination buffer
 * @param[in, out] pdst_off The offset into the destination of where to copy
 * to.
 * @param[in] src The source buffer.
 * @param[in] src_sz The size of the source buffer.
 * @param[in, out] psrc_off The offset into the source of where to begin
 * copying data from.
 * @param[in] more indicates whether or not there are more source buffers
 * (frames) expected
 *
 * @return
 *  - axl_false if an error occured.
 *  - axl_true otherwise.
 */
axl_bool jaln_copy_buffer(uint8_t *dst, const size_t dst_size, size_t *pdst_off,
		const uint8_t *src, const size_t src_sz, size_t *psrc_off, axl_bool more);

/**
 * Utility to create a state machine suitable for processing journal records
 * @return A jaln_sub_state_machine for processing journal records.
 */
struct jaln_sub_state_machine *jaln_sub_state_create_journal_machine();

/**
 * Utility to create a state machine suitable for processing audit records
 * @return A jaln_sub_state_machine for processing audit records.
 */
struct jaln_sub_state_machine *jaln_sub_state_create_audit_machine();

/**
 * Utility to create a state machine suitable for processing log records
 * @return A jaln_sub_state_machine for processing log records.
 */
struct jaln_sub_state_machine *jaln_sub_state_create_log_machine();

/**
 * Clean up all resources of a jaln_sub_state_machine
 * @param[in,out] sm The jaln_sub_state_machine to destroy, this will be set to
 * NULL.
 */

void jaln_sub_state_machine_destroy(struct jaln_sub_state_machine **sm);
/**
 * Clean up resources of a jaln_sub_state
 * @param[in,out] state The jaln_sub_state to destroy, this will be set to NULL.
 */
void jaln_sub_state_destroy(struct jaln_sub_state **state);

/**
 * Common function for creating the state machines.
 *
 * This function creates and initializes a new state machine with most of the
 * states filled in. This does fill in the state for handling the payload or
 * record complete state, since these are specific to the type of record.
 *
 */
struct jaln_sub_state_machine *jaln_sub_state_machine_create_common(const char *expected_msg, const char *payload_len_hdr);

/**
 * Create a jaln_sub_state
 *
 * @return A new jaln_sub_state.
 */
struct jaln_sub_state *jaln_sub_state_create();

/**
 * Macro for transitioning to a new state.
 */
#define jaln_sub_state_transition(sm, new) \
	do { \
		/* printf("%s[%d]: transition (%s => %s)\n", __FUNCTION__, __LINE__, \
				(sm)->curr_state->name, (new)->name); \
				*/ \
		(sm)->curr_state = (new); \
	} while (0);

#endif // _JALN_SUBSCRIBER_STATE_MACH_H_
