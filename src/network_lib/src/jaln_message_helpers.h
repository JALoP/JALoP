/**
 * @file jaln_message_helpers.h This file contains function
 * declarations for internal library functions related to creating JALoP
 * messages
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
#ifndef _JALN_MESSAGE_HELPERS_H_
#define _JALN_MESSAGE_HELPERS_H_

#include <inttypes.h>
#include <jalop/jaln_network_types.h>
#include <stddef.h>
#include <vortex.h>
#include <curl/curl.h>

#include "jaln_digest_info.h"
#include "jaln_digest_resp_info.h"

struct jaln_init_ack_header_info {
	jaln_session *sess;
	axl_bool content_type_valid;
	axl_bool message_type_valid;
	axl_bool version_valid;
};

/**
 * Create a jaln_init_ack_header_info object
 */
struct jaln_init_ack_header_info *jaln_init_ack_header_info_create(jaln_session *sess);

/**
 * Destroy a jaln_init_ack_header_info object.
 *
 * @param[in] info The header info object to destroy.
 */
void jaln_init_ack_header_info_destroy(struct jaln_init_ack_header_info **info);

/**
 * Helper function to create a journal_resume_msg
 *
 * @param[in] nonce The nonce to resume
 * @param[in] offset The offset in the journal record to resume data from.
 * @param[out] msg_out This will contain the contents of the initialize message.
 * @param[out] msg_len_out The length of the initialize message
 *
 * @return JAL_E_INVAL if there is something wrong with the parameters, or
 * JAL_OK on success
 *
 */
enum jal_status jaln_create_journal_resume_msg(const char *nonce,
		uint64_t offset, char **msg_out, uint64_t *msg_out_len);

/**
 * Helper function to create a sync msg
 *
 * @param[in] nonce The nonce to sync
 * @param[out] msg The full message to send to the remote.
 * @param[out] msg_len The length of the resulting message (including the NULL
 * terminator
 */
enum jal_status jaln_create_sync_msg(const char *nonce, char **msg, uint64_t *msg_len);

/**
 * Helper function to create a 'subscribe' message
 *
 * @param[in] nonce The last nonce to send
 * @param[out] msg_out This will contain the contents of the initialize message.
 * @param[out] msg_len_out The length of the initialize message
 *
 * @return JAL_E_INVAL if there is something wrong with the parameters, or
 * JAL_OK on success
 *
 */
enum jal_status jaln_create_subscribe_msg(char **msg_out, uint64_t *msg_out_len);

/**
 * Sanity check to make sure the MIME headers for a particular frame contain
 * the correct content-type and transfer encoding.
 *
 * @param frame The vortex frame to inspect.
 *
 * @return axl_true if the content type and transfer encoding are valid,
 * axl_false otherwise.
 */
axl_bool jaln_check_content_type_and_txfr_encoding_are_valid(VortexFrame *frame);

/**
 * Verify that a header_info struct has all the required fields
 *
 * @param header_info Information from parsing initialize-ack headers
 *
 * @return JAL_OK if all headers were present or an error code
 */
enum jal_status jaln_verify_init_ack_headers(struct jaln_init_ack_header_info *header_info);

/**
 * Parse a single header on a JALoP message
 *
 * @param content The data in the header
 * @param len The length of the data
 * @param info A struct for storing info about the headers parsed
 *
 * @return JAL_OK on success, or an error code
 */
enum jal_status jaln_parse_init_ack_header(char *content, size_t len, struct jaln_init_ack_header_info *info);

/**
 * Parse a content type header
 *
 * @param content The data in the header
 * @param len The length of the data
 * @param sess The session associated with this header.  This function will update
 * it based on the header contents
 *
 * @return JAL_OK on success, or an error code
 */
enum jal_status jaln_parse_content_type_header(char *content, size_t len, jaln_session *sess);

/**
 * Parse a JAL Message header
 *
 * @param content The data in the header
 * @param len The length of the data
 * @param sess The session associated with this header.  This function will update
 * it based on the header contents
 * @param expect What message type was expected
 *
 * @return JAL_OK on success, or an error code
 */
enum jal_status jaln_parse_message_header(char *content, size_t len, jaln_session *sess, char *expect);

/**
 * Parse an xml compression header
 *
 * @param content The data in the header
 * @param len The length of the data
 * @param sess The session associated with this header.  This function will update
 * it based on the header contents
 *
 * @return JAL_OK on success, or an error code
 */
enum jal_status jaln_parse_xml_compression_header(char *content, size_t len, jaln_session *sess);

/**
 * Parse a digest header
 *
 * @param content The data in the header
 * @param len The length of the data
 * @param sess The session associated with this header.  This function will update
 * it based on the header contents
 *
 * @return JAL_OK on success, or an error code
 */
enum jal_status jaln_parse_digest_header(char *content, size_t len, jaln_session *sess);

/**
 * Parse a configure digest challenge header
 *
 * @param content The data in the header
 * @param len The length of the data
 * @param sess The session associated with this header.  This function will update
 * it based on the header contents
 *
 * @return JAL_OK on success, or an error code
 */
enum jal_status jaln_parse_configure_digest_challenge_header(char *content, size_t len, jaln_session *sess);

/**
 * Parse a session ID header
 *
 * @param content The data in the header
 * @param len The length of the data
 * @param sess The session associated with this header.  This function will update
 * it based on the header contents
 *
 * @return JAL_OK on success, or an error code
 */
enum jal_status jaln_parse_session_id(char *content, size_t len, jaln_session *sess);

/**
 * Parse a record ID header
 *
 * @param content The data in the header
 * @param len The length of the data
 * @param sess The session associated with this header.  This function will update
 * it based on the header contents
 *
 * @return JAL_OK on success, or an error code
 */
enum jal_status jaln_parse_journal_resume_id_header(char *content, size_t len, jaln_session *sess);

/**
 * Parse a record offset for Journal Resume
 *
 * @param content The data in the header
 * @param len The length of the data
 * @param sess The session associated with this header.  This function will update
 * it based on the header contents
 *
 * @return JAL_OK on success, or an error code
 */
enum jal_status jaln_parse_journal_resume_offset_header(char *content, size_t len, jaln_session *sess);

/**
 * Helper function to calculate the number of bytes needed to to convert a
 * jaln_digest_info to a string for sending as part of a digest message.
 *
 * @param[in] di the digest info object.
 * @param return the length of the resulting string, or 0 if an error occurred.
 */
uint64_t jaln_digest_info_strlen(const struct jaln_digest_info *di);

/**
 * Helper function to append a jaln_digest_info as line for a digest message.
 * This works similar to strcat, and appends the string 'dgst=nonce\r\n', i.e.
 * the digest value (as a hex string with no leading 0x) followed by the equals
 * symbol ('=') followed by the nonce, and finished with a carriage return
 * and line feed.
 * The string \p dst must contain enough space for the entire message and the
 * trailing NULL terminator.
 *
 * @param[in,out] dst The character string to append to.
 * @param[in] di The jaln_digest_info object to output.
 *
 * @return a pointer to \p dst.
 */
char *jaln_digest_info_strcat(char *dst, const struct jaln_digest_info *di);

/**
 * Create the 'digest' message.
 *
 * It is an error to try and create a digest message for an empty list.
 * It is also an error if any of the digest_info objects in the list are not
 * valid.
 *
 * @param[in] dgst_list The list of jaln_digest_info structures to send in the
 * message.
 * @param[out] msg_out The resulting message
 * @param[out] msg_len The length of the resulting message
 *
 *
 * @return
 *  - JAL_OK on success
 *  - JAL_E_INVAL on error
 */
enum jal_status jaln_create_digest_msg(axlList *dgst_list, char **msg_out, uint64_t *msg_len);

/**
 * Helper function to calculate the number of bytes needed to to convert a
 * jaln_digest_resp_info to a string for sending as part of a digest message.
 *
 * @param[in] di the digest_resp_info object.
 * @param return the length of the resulting string, or 0 if an error occurred.
 */
uint64_t jaln_digest_resp_info_strlen(const struct jaln_digest_resp_info *di);

/**
 * Helper function to append a jaln_digest_resp_info as line for a digest message.
 * This works similar to strcat, and appends the string '<status>=nonce\r\n', i.e.
 * the status (confirmed, invalid, or unknown) followed by the equals
 * symbol ('=') followed by the nonce, and finished with a carriage return
 * and line feed.
 * The string \p must contain enough space for the entire message and the
 * trailing NULL terminator.
 * @param[in,out] dst The character string to append to.
 * @param[in] di The jaln_digest_info object to output.
 */
char *jaln_digest_resp_info_strcat(char *dst, const struct jaln_digest_resp_info *di);

/** Create the 'digest-response' message.
 *
 * It is an error to try and create a digest message for an empty list.
 * It is also an error if any of the digest_info objects in the list are not
 * valid.
 *
 * @param[in] dgst_list The list of jaln_digest_resp_info structures to send in the
 * message.
 * @param[out] msg_out The resulting message
 * @param[out] msg_len The length of the resulting message
 *
 * @return
 *  - JAL_OK on success
 *  - JAL_E_INVAL on error
 */
enum jal_status jaln_create_digest_response_msg(axlList *dgst_resp_list, char **msg_out, uint64_t *msg_len);

/**
 * Helper function to increment a counter when determining the required number of
 * bytes for a message.
 *
 * @param[in,out] base On success, base will be equal to (base + inc)
 * @param[in] inc The increment to add
 * @return axl_true if the addition was performed
 * axl_false if the addition was NOT performed. The only time the addition will
 * not happen is when \p base is NULL, or *base + inc would overflow uint64_t.
 */
axl_bool jaln_safe_add_size(uint64_t *base, uint64_t inc);

/*
 * Helper function to create an 'initialize' message
 *
 * @param[in] pub_id UUID identifying the publisher.
 * @param[in] type The type of data to send over this channel.
 * @param[in] ctx JALoP network context for this channel.
 * @param[out] headers This will contain the libcurl headers for the initialize message.
 *
 * @return JAL_E_INVAL if there is something wrong with the parameters, or
 * JAL_OK on success
 *
 */
enum jal_status jaln_create_init_msg(const char *pub_id, enum jaln_publish_mode mode, enum jaln_record_type type,
		jaln_context *ctx, struct curl_slist **headers);

/**
 * Create the headers for a ANS reply to a 'subscribe' message.
 *
 * @param[in] rec_info The record info structure describing the record to be
 * sent.
 * @param[out] headers_out This will contain the full MIME headers, including
 * the pair of CR LF to designate the end of the headers.
 * @param[out] headers_len_out This will be set to the length of the headers
 * (not including the trailing '\0' character.
 */
enum jal_status jaln_create_record_ans_rpy_headers(struct jaln_record_info *rec_info, char **headers_out, uint64_t *headers_len_out);

/**
 * Create an 'initialize-nack' message.
 *
 * @param[in] err_codes A bit mask of jaln_connect_error reasons that the
 * connection cannot be established.
 * @param[out] msg_out This will contain the contents of the initialize-nack
 * message
 * @param[out] msg_len_out This will contain the length of the initialize-nack
 * message.
 *
 * @return JAL_OK on success of JAL_E_INVAL if there is something wrong with
 * the parameters.
 */
enum jal_status jaln_create_init_nack_msg(enum jaln_connect_error err_codes, char **msg_out, uint64_t *msg_len_out);

/**
 * Create an 'initialize-ack' message.
 *
 * @param[in] encoding The selected encoding
 * @param[in] digest The selected digest
 * @param[out] msg_out This will contain the contents of the initialize-ack
 * message
 * @param[out] msg_len_out This will contain the length of the initialize-ack
 * message.
 *
 * @return JAL_OK on success of JAL_E_INVAL if there is something wrong with
 * the parameters.
 */
enum jal_status jaln_create_init_ack_msg(const char *encoding, const char *digest, char **msg_out, uint64_t *msg_len_out);

#endif // _JALN_MESSAGE_HELPERS_H_
