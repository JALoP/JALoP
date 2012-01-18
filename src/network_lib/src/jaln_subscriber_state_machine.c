/**
 * @file jaln_subscriber_state_machine.c This file contains the implementation of a
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
#include <vortex_frame_factory.h>
#include "jal_alloc.h"
#include "jaln_context.h"
#include "jaln_message_helpers.h"
#include "jaln_record_info.h"
#include "jaln_strings.h"
#include "jaln_string_utils.h"
#include "jaln_subscriber_state_machine.h"

axl_bool jaln_sub_wait_for_mime(jaln_session *session, VortexFrame *frame,
		__attribute__((unused)) size_t frame_off, axl_bool more)
{
	if (!session || !session->ch_info || !session->dgst || !session->sub_data->sm || !frame) {
		goto err_out;
	}
	int copied = 0;
	if (session->sub_data->sm->cached_frame) {
		jaln_sub_state_append_frame(session, frame);
		frame = session->sub_data->sm->cached_frame;
		copied = 1;
	}
	if (!vortex_frame_mime_process(frame)) {
		if (more) {
			// haven't received the full response, so cache this
			// frame and wait for more...
			if (!copied  && !jaln_sub_state_append_frame(session, frame)) {
				goto err_out;
			}
			return axl_true;
		}
		// no more data expected for this ANS, and couldn't process the
		// MIME headers, consider it an error
		goto err_out;
	}
	if (!jaln_check_content_type_and_txfr_encoding_are_valid(frame)) {
		goto err_out;
	}
	const char *msg = VORTEX_FRAME_GET_MIME_HEADER(frame, (JALN_HDRS_MESSAGE));
	if (!msg || 0 != strcasecmp(msg, session->sub_data->sm->expected_msg)) {
		goto err_out;
	}
	const char *sid = VORTEX_FRAME_GET_MIME_HEADER(frame, (JALN_HDRS_SERIAL_ID));
	if (!sid) {
		goto err_out;
	}
	const char *app_meta_sz_str = VORTEX_FRAME_GET_MIME_HEADER(frame, (JALN_HDRS_APP_META_LEN));
	if (!app_meta_sz_str) {
		goto err_out;
	}
	const char * sys_meta_sz_str = VORTEX_FRAME_GET_MIME_HEADER(frame, (JALN_HDRS_SYS_META_LEN));
	if (!sys_meta_sz_str) {
		goto err_out;
	}
	const char *payload_sz_str = VORTEX_FRAME_GET_MIME_HEADER(frame, (session->sub_data->sm->payload_len_hdr));
	if (!payload_sz_str) {
		goto err_out;
	}

	session->sub_data->sm->serial_id = jal_strdup(sid);

	size_t sys_meta_size;
	int err = jaln_ascii_to_size_t(sys_meta_sz_str, &sys_meta_size);
	session->sub_data->sm->sys_meta_sz = sys_meta_size;

	if (!err) {
		goto err_out;
	}
	err = jaln_ascii_to_size_t(app_meta_sz_str, &session->sub_data->sm->app_meta_sz);
	if (!err) {
		goto err_out;
	}
	err = jaln_ascii_to_size_t(payload_sz_str, &session->sub_data->sm->payload_sz);
	if (!err) {
		goto err_out;
	}

	session->sub_data->sm->sys_meta_buf = jal_malloc(session->sub_data->sm->sys_meta_sz);
	session->sub_data->sm->sys_meta_off = 0;

	session->sub_data->sm->app_meta_buf = jal_malloc(session->sub_data->sm->app_meta_sz);
	session->sub_data->sm->app_meta_off = 0;

	if ((session->ch_info->type == JALN_RTYPE_LOG) ||
		(session->ch_info->type == JALN_RTYPE_AUDIT)) {
		session->sub_data->sm->payload_buf = jal_malloc(session->sub_data->sm->payload_sz);
	}
	session->sub_data->sm->payload_off = 0;

	memset(session->sub_data->sm->break_buf, 0, session->sub_data->sm->break_sz);
	session->sub_data->sm->break_off = 0;

	session->sub_data->sm->dgst_inst = session->dgst->create();
	if (session->sub_data->sm->dgst_inst == NULL) {
		goto err_out;
	}
	if (JAL_OK != session->dgst->init(session->sub_data->sm->dgst_inst)) {
		goto err_out;
	}

	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->wait_for_sys_meta);
	axl_bool ret = session->sub_data->sm->curr_state->frame_handler(session, frame, 0, more);
	vortex_frame_free(session->sub_data->sm->cached_frame);
	session->sub_data->sm->cached_frame = NULL;
	return ret;
err_out:
	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->error_state);
	return axl_false;
}

axl_bool jaln_sub_data_segment_common(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more,
		uint8_t* dst_buffer, size_t dst_size, size_t *dst_off, struct jaln_sub_state *next_state)
{
	if (!session || !session->sub_data->sm || !frame || !dst_buffer || !dst_off || !next_state) {
		goto err_out;
	}
	uint8_t *payload = (uint8_t*) vortex_frame_get_payload(frame);
	int payload_sz = vortex_frame_get_payload_size(frame);

	if (jaln_copy_buffer(dst_buffer, dst_size, dst_off,
				payload, payload_sz, &frame_off, more)) {
		if (*dst_off == dst_size) {
			jaln_sub_state_transition(session->sub_data->sm, next_state);
			return session->sub_data->sm->curr_state->frame_handler(session, frame, frame_off, more);
		} else if (*dst_off < dst_size) {
			return axl_true;
		}
		// if dst_off > dst_size something wrong, fall
		// through to error handler
	}
err_out:
	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->error_state);
	return axl_false;
}

axl_bool jaln_sub_wait_for_payload(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more)
{
	if (!session || !session->sub_data->sm) {
		return axl_false;
	}
	return jaln_sub_data_segment_common(session, frame, frame_off, more,
			session->sub_data->sm->payload_buf, session->sub_data->sm->payload_sz, &session->sub_data->sm->payload_off,
			session->sub_data->sm->wait_for_payload_break);
}

axl_bool jaln_sub_wait_for_sys_meta(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more)
{
	if (!session || !session->sub_data->sm) {
		return axl_false;
	}
	return jaln_sub_data_segment_common(session, frame, frame_off, more,
			session->sub_data->sm->sys_meta_buf, session->sub_data->sm->sys_meta_sz, &session->sub_data->sm->sys_meta_off,
			session->sub_data->sm->wait_for_sys_meta_break);
}
axl_bool jaln_sub_wait_for_app_meta(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more)
{
	if (!session || !session->sub_data->sm) {
		return axl_false;
	}
	return jaln_sub_data_segment_common(session, frame, frame_off, more,
			session->sub_data->sm->app_meta_buf, session->sub_data->sm->app_meta_sz, &session->sub_data->sm->app_meta_off,
			session->sub_data->sm->wait_for_app_meta_break);
}

axl_bool jaln_copy_buffer(uint8_t *dst, const size_t dst_sz, size_t *pdst_off,
		const uint8_t *src, const size_t src_sz, size_t *psrc_off, axl_bool more)
{
	if (!dst || !pdst_off || !src || !psrc_off) {
		return axl_false;
	}
	size_t dst_off = *pdst_off;
	size_t src_off = *psrc_off;
	dst += dst_off;
	src += src_off;

	if ((dst_sz < dst_off) ||
		(src_sz < src_off)) {
		return axl_false;
	}

	size_t dst_bytes_left = dst_sz - dst_off;
	size_t src_bytes_left = src_sz - src_off;

	int need_more_frames = src_bytes_left < dst_bytes_left;

	if (need_more_frames && !more) {
		return axl_false;
	}

	size_t bytes_to_copy = need_more_frames ? src_bytes_left : dst_bytes_left;
	memcpy(dst, src, bytes_to_copy);
	*psrc_off = src_off + bytes_to_copy;
	*pdst_off = dst_off + bytes_to_copy;
	return axl_true;
}

axl_bool jaln_sub_wait_for_journal_payload(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more)
{
	if (!session || !session->dgst || !session->sub_data->sm || !session->sub_data->sm->dgst_inst || !session->jaln_ctx ||
			!session->jaln_ctx->sub_callbacks || !frame) {
		goto err_out;
	}

	uint8_t *payload = (uint8_t*) vortex_frame_get_payload(frame);
	int payload_sz = vortex_frame_get_payload_size(frame);
	if (!payload) {
		goto err_out;
	}
	if (payload_sz < 0) {
		goto err_out;
	}
	if (frame_off > (size_t) payload_sz) {
		goto err_out;
	}
	size_t bytes_avail = payload_sz - frame_off;
	uint32_t bytes_needed = session->sub_data->sm->payload_sz  - session->sub_data->sm->payload_off;
	uint32_t bytes_to_send = bytes_avail < bytes_needed ? bytes_avail : bytes_needed;

	int more_expected = bytes_to_send < bytes_needed;
	if (more_expected && !more) {
		goto err_out;
	}

	session->jaln_ctx->sub_callbacks->on_journal(session, session->ch_info, session->sub_data->sm->serial_id,
			payload + frame_off,
			bytes_to_send,
			session->sub_data->sm->payload_off,
			more_expected,
			session->jaln_ctx->user_data);
	if (JAL_OK != session->dgst->update(session->sub_data->sm->dgst_inst, payload + frame_off, bytes_to_send)) {
		goto err_out;
	}
	session->sub_data->sm->payload_off += bytes_to_send;
	frame_off += bytes_to_send;
	if (session->sub_data->sm->payload_off == session->sub_data->sm->payload_sz) {
		return session->sub_data->sm->wait_for_payload_break->frame_handler(session, frame, frame_off, more);
	} else if (session->sub_data->sm->payload_off < session->sub_data->sm->payload_sz) {
		return axl_true;
	}
	// otherwise it's an error and fall through
err_out:
	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->error_state);
	return axl_false;
}

axl_bool jaln_sub_wait_for_break_common(jaln_session *session, VortexFrame *frame,
		size_t *frame_off, axl_bool more, axl_bool *break_valid)
{
	if (!session || !session->sub_data->sm || !frame || !frame_off || !break_valid) {
		return axl_false;
	}
	*break_valid = axl_false;
	uint8_t *payload = (uint8_t*) vortex_frame_get_payload(frame);
	int payload_sz = vortex_frame_get_payload_size(frame);
	axl_bool ret = axl_false;

	if (payload_sz < 0) {
		return axl_false;
	}

	if (jaln_copy_buffer(session->sub_data->sm->break_buf, session->sub_data->sm->break_sz, &session->sub_data->sm->break_off,
				payload, payload_sz, frame_off, more)) {
		if (session->sub_data->sm->break_off == session->sub_data->sm->break_sz) {
			if (0 ==  memcmp(session->sub_data->sm->break_buf, JALN_STR_BREAK, session->sub_data->sm->break_sz)) {
				*break_valid = axl_true;
				ret = axl_true;
			}
			session->sub_data->sm->break_off = 0;
			memset(session->sub_data->sm->break_buf, 0, session->sub_data->sm->break_sz);
		} else if (session->sub_data->sm->break_off < session->sub_data->sm->break_sz) {
			ret = axl_true;
		}
	}
	return ret;
}

axl_bool jaln_sub_state_error_state(__attribute__((unused)) jaln_session *session,
		__attribute__((unused)) VortexFrame *frame,
		__attribute__((unused)) size_t frame_off,
		__attribute__((unused)) axl_bool more)
{
	return axl_false;
}

axl_bool jaln_sub_state_append_frame(jaln_session *session, VortexFrame *frame)
{
	if (!session || !session->sub_data->sm || !frame) {
		return axl_false;
	}
	if (!session->sub_data->sm->cached_frame) {
		session->sub_data->sm->cached_frame = frame;
		vortex_frame_ref(frame);
		return axl_true;
	}
	VortexFrame *new_frame = vortex_frame_join(session->sub_data->sm->cached_frame, frame);
	if (!new_frame) {
		return axl_false;
	}
	vortex_frame_unref(session->sub_data->sm->cached_frame);
	session->sub_data->sm->cached_frame = new_frame;
	return axl_true;
}
axl_bool jaln_sub_audit_record_complete(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more)
{
	if (!session || !session->dgst || !session->jaln_ctx ||
			!session->jaln_ctx->sub_callbacks || !frame) {
		goto err_out;
	}
	// at this point, there should be no more data coming down the pipe...
	// one last sanity check.
	if (!jaln_sub_rec_complete_sanity_check(session, frame, frame_off, more)) {
		goto err_out;
	}
	size_t dgst_len = session->dgst->len;
	session->jaln_ctx->sub_callbacks->on_audit(session, session->ch_info, session->sub_data->sm->serial_id,
			session->sub_data->sm->payload_buf, session->sub_data->sm->payload_sz, session->jaln_ctx->user_data);

	if (JAL_OK != session->dgst->update(session->sub_data->sm->dgst_inst, session->sub_data->sm->payload_buf, session->sub_data->sm->payload_sz)) {
		goto err_out;;
	}

	if (JAL_OK != session->dgst->final(session->sub_data->sm->dgst_inst, session->sub_data->sm->dgst, &dgst_len)) {
		goto err_out;;
	}

	session->jaln_ctx->sub_callbacks->notify_digest(session, session->ch_info, session->ch_info->type,
			session->sub_data->sm->serial_id, session->sub_data->sm->dgst, dgst_len, session->jaln_ctx->user_data);

	jaln_session_add_to_dgst_list(session, session->sub_data->sm->serial_id, session->sub_data->sm->dgst, dgst_len);
	jaln_sub_state_reset(session);
	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->wait_for_mime);
	return axl_true;
err_out:
	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->error_state);
	return axl_false;
}

axl_bool jaln_sub_log_record_complete(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more)
{
	if (!session || !session->dgst || !session->jaln_ctx || !session->jaln_ctx->sub_callbacks || !session->sub_data->sm) {
		goto err_out;
	}
	// at this point, there should be no more data coming down the pipe...
	// one last sanity check.
	if (!jaln_sub_rec_complete_sanity_check(session, frame, frame_off, more)) {
		goto err_out;
	}
	size_t dgst_len = session->dgst->len;
	session->jaln_ctx->sub_callbacks->on_log(session, session->ch_info, session->sub_data->sm->serial_id, session->sub_data->sm->payload_buf, session->sub_data->sm->payload_sz, session->jaln_ctx->user_data);
	if (JAL_OK != session->dgst->update(session->sub_data->sm->dgst_inst, session->sub_data->sm->payload_buf, session->sub_data->sm->payload_sz)) {
		goto err_out;
	}

	if (JAL_OK != session->dgst->final(session->sub_data->sm->dgst_inst, session->sub_data->sm->dgst, &dgst_len)) {
		goto err_out;
	}

	session->jaln_ctx->sub_callbacks->notify_digest(session, session->ch_info, session->ch_info->type,
			session->sub_data->sm->serial_id, session->sub_data->sm->dgst, dgst_len, session->jaln_ctx->user_data);
	jaln_session_add_to_dgst_list(session, session->sub_data->sm->serial_id, session->sub_data->sm->dgst, dgst_len);
	jaln_sub_state_reset(session);
	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->wait_for_mime);
	return axl_true;
err_out:
	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->error_state);
	return axl_false;
}
axl_bool jaln_sub_journal_record_complete(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more)
{
	if (!session || !session->dgst || !session->jaln_ctx || !session->jaln_ctx->sub_callbacks || !session->sub_data->sm) {
		goto err_out;
	}
	if (!jaln_sub_rec_complete_sanity_check(session, frame, frame_off, more)) {
		goto err_out;
	}

	uint8_t *dgst = NULL;
	size_t dgst_len = session->dgst->len;
	session->jaln_ctx->sub_callbacks->on_journal(session, session->ch_info, session->sub_data->sm->serial_id, NULL, 0, 0, 0, session->jaln_ctx->user_data);
	if (JAL_OK != session->dgst->final(session->sub_data->sm->dgst_inst, session->sub_data->sm->dgst, &dgst_len)) {
		goto err_out;
	}
	session->jaln_ctx->sub_callbacks->notify_digest(session, session->ch_info, session->ch_info->type, session->sub_data->sm->serial_id,
			dgst, dgst_len, session->jaln_ctx->user_data);
	jaln_session_add_to_dgst_list(session, session->sub_data->sm->serial_id, session->sub_data->sm->dgst, dgst_len);
	jaln_sub_state_reset(session);
	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->wait_for_mime);
	return axl_true;
err_out:
	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->error_state);
	return axl_false;
}
axl_bool jaln_sub_rec_complete_sanity_check(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more)
{
	if (!session || !session->sub_data->sm || !frame) {
		return axl_false;
	}
	if (more) {
		return axl_false;
	}
	int payload_sz = vortex_frame_get_payload_size(frame);
	if (payload_sz < 0) {
		return axl_false;
	}
	if (frame_off != (size_t) payload_sz) {
		// failed to consume the entire frame payload...
		return axl_false;
	}
	if (session->sub_data->sm->payload_sz != session->sub_data->sm->payload_off) {
		return axl_false;
	}
	return axl_true;
}
axl_bool jaln_sub_wait_for_payload_break(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more)
{
	if (!session || !session->sub_data->sm || !frame) {
		goto err_out;
	}
	axl_bool break_valid = axl_false;
	if (jaln_sub_wait_for_break_common(session, frame, &frame_off, more, &break_valid)) {
		if (break_valid) {
			jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->record_complete);
			return session->sub_data->sm->curr_state->frame_handler(session, frame, frame_off, more);
		}
		return axl_true;
	}
err_out:
	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->error_state);
	return axl_false;
}

axl_bool jaln_sub_wait_for_app_meta_break(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more)
{
	if (!session || !session->dgst || !session->ch_info || !session->sub_data->sm || !session->sub_data->sm->dgst_inst) {
		goto err_out;
	}
	axl_bool break_valid = axl_false;
	if (jaln_sub_wait_for_break_common(session, frame, &frame_off, more, &break_valid)) {
		if (break_valid) {
			struct jaln_record_info *info = jaln_record_info_create();

			info->type = session->ch_info->type;
			info->serial_id = jal_strdup(session->sub_data->sm->serial_id);
			info->sys_meta_len = session->sub_data->sm->sys_meta_sz;
			info->app_meta_len = session->sub_data->sm->app_meta_sz;
			info->payload_len = session->sub_data->sm->payload_sz;

			session->jaln_ctx->sub_callbacks->on_record_info(session,
					session->ch_info, session->ch_info->type,
					info, NULL,
					session->sub_data->sm->sys_meta_buf, session->sub_data->sm->sys_meta_sz,
					session->sub_data->sm->app_meta_buf, session->sub_data->sm->app_meta_sz,
					session->jaln_ctx->user_data);
			jaln_record_info_destroy(&info);

			if (JAL_OK != session->dgst->update(session->sub_data->sm->dgst_inst, session->sub_data->sm->sys_meta_buf, session->sub_data->sm->sys_meta_sz)) {
				goto err_out;
			}
			if (JAL_OK != session->dgst->update(session->sub_data->sm->dgst_inst, session->sub_data->sm->app_meta_buf, session->sub_data->sm->app_meta_sz)) {
				goto err_out;
			}
			jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->wait_for_payload);
			return session->sub_data->sm->curr_state->frame_handler(session, frame, frame_off, more);
		}
		return axl_true;
	}
err_out:
	jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->error_state);
	return axl_false;
}

axl_bool jaln_sub_wait_for_sys_meta_break(jaln_session *session, VortexFrame *frame, size_t frame_off, axl_bool more)
{
	if (!session || !session->sub_data->sm || !frame) {
		goto err_out;
	}

	axl_bool break_valid = axl_false;
	if (jaln_sub_wait_for_break_common(session, frame, &frame_off, more, &break_valid)) {
		if (break_valid) {
			jaln_sub_state_transition(session->sub_data->sm, session->sub_data->sm->wait_for_app_meta);
			return session->sub_data->sm->curr_state->frame_handler(session, frame, frame_off, more);
		}
		return axl_true;
	}
err_out:
	return axl_false;
}

void jaln_sub_state_reset(jaln_session *session)
{
	if (!session || !session->sub_data->sm || !session->dgst) {
		return;
	}
	struct jaln_sub_state_machine *sm = session->sub_data->sm;
	free(sm->serial_id);
	sm->serial_id = NULL;
	free(sm->sys_meta_buf);
	sm->sys_meta_buf = NULL;
	sm->sys_meta_sz = 0;
	sm->sys_meta_off = 0;
	free(sm->app_meta_buf);
	sm->app_meta_buf = NULL;
	sm->app_meta_sz = 0;
	sm->app_meta_off = 0;
	free(sm->payload_buf);
	sm->payload_buf = NULL;
	sm->payload_sz = 0;
	sm->payload_off = 0;
	memset(sm->break_buf, 0, sm->break_sz);
	sm->break_off = 0;
	vortex_frame_free(sm->cached_frame);
	if (session->sub_data->sm->dgst_inst) {
		session->dgst->destroy(sm->dgst_inst);
	}
	free(sm->dgst);
	sm->dgst_inst = session->dgst->create();
	sm->dgst = (uint8_t*) jal_calloc(1, session->dgst->len);
}

struct jaln_sub_state_machine *jaln_sub_state_create_journal_machine()
{
	struct jaln_sub_state_machine *sm = jaln_sub_state_machine_create_common(JALN_MSG_JOURNAL, JALN_HDRS_JOURNAL_LEN);

	sm->wait_for_payload = jaln_sub_state_create();
	sm->wait_for_payload->name = jal_strdup("WaitForJournalPayload");
	sm->wait_for_payload->frame_handler = jaln_sub_wait_for_journal_payload;

	sm->record_complete = jaln_sub_state_create();
	sm->record_complete->name = jal_strdup("JournalComplete");
	sm->record_complete->frame_handler = jaln_sub_journal_record_complete;
	return sm;
}
struct jaln_sub_state_machine *jaln_sub_state_create_audit_machine()
{
	struct jaln_sub_state_machine *sm = jaln_sub_state_machine_create_common(JALN_MSG_AUDIT, JALN_HDRS_AUDIT_LEN);

	sm->wait_for_payload = jaln_sub_state_create();
	sm->wait_for_payload->name = jal_strdup("WaitForAuditPayload");
	sm->wait_for_payload->frame_handler = jaln_sub_wait_for_payload;

	sm->record_complete = jaln_sub_state_create();
	sm->record_complete->name = jal_strdup("AuditComplete");
	sm->record_complete->frame_handler = jaln_sub_audit_record_complete;
	return sm;
}
struct jaln_sub_state_machine *jaln_sub_state_create_log_machine()
{
	struct jaln_sub_state_machine *sm = jaln_sub_state_machine_create_common(JALN_MSG_LOG, JALN_HDRS_LOG_LEN);

	sm->wait_for_payload = jaln_sub_state_create();
	sm->wait_for_payload->name = jal_strdup("WaitForLogPayload");
	sm->wait_for_payload->frame_handler = jaln_sub_wait_for_payload;

	sm->record_complete = jaln_sub_state_create();
	sm->record_complete->name = jal_strdup("AuditComplete");
	sm->record_complete->frame_handler = jaln_sub_log_record_complete;
	return sm;
}
struct jaln_sub_state_machine *jaln_sub_state_machine_create_common(const char *expected_msg, const char *payload_len_hdr)
{
	if (!expected_msg || !payload_len_hdr) {
		return NULL;
	}
	struct jaln_sub_state_machine *sm = jal_calloc(1, sizeof(*sm));

	sm->break_buf = jal_calloc(strlen(JALN_STR_BREAK), sizeof(char));

	sm->expected_msg = jal_strdup(expected_msg);
	sm->payload_len_hdr = jal_strdup(payload_len_hdr);
	sm->break_sz = strlen(JALN_STR_BREAK);

	sm->wait_for_mime = jaln_sub_state_create();
	sm->wait_for_mime->name = jal_strdup("WaitForMime");
	sm->wait_for_mime->frame_handler = jaln_sub_wait_for_mime;

	sm->wait_for_sys_meta = jaln_sub_state_create();
	sm->wait_for_sys_meta->name = jal_strdup("WaitForSysMeta");
	sm->wait_for_sys_meta->frame_handler = jaln_sub_wait_for_sys_meta;

	sm->wait_for_sys_meta_break = jaln_sub_state_create();
	sm->wait_for_sys_meta_break->name = jal_strdup("WaitForSysMetaBreak");
	sm->wait_for_sys_meta_break->frame_handler = jaln_sub_wait_for_sys_meta_break;

	sm->wait_for_app_meta = jaln_sub_state_create();
	sm->wait_for_app_meta->name = jal_strdup("WaitForAppMeta");
	sm->wait_for_app_meta->frame_handler = jaln_sub_wait_for_app_meta;

	sm->wait_for_app_meta_break = jaln_sub_state_create();
	sm->wait_for_app_meta_break->name = jal_strdup("WaitForAppMetaBreak");
	sm->wait_for_app_meta_break->frame_handler = jaln_sub_wait_for_app_meta_break;

	sm->wait_for_payload_break = jaln_sub_state_create();
	sm->wait_for_payload_break->name = jal_strdup("WaitForPayloadBreak");
	sm->wait_for_payload_break->frame_handler = jaln_sub_wait_for_payload_break;

	sm->error_state = jaln_sub_state_create();
	sm->error_state->name = jal_strdup("WaitForMime");
	sm->error_state->frame_handler = jaln_sub_state_error_state;

	sm->curr_state = sm->wait_for_mime;

	return sm;
}

void jaln_sub_state_machine_destroy(struct jaln_sub_state_machine **psm)
{
	if (!psm || !*psm) {
		return;
	}

	struct jaln_sub_state_machine *sm = *psm;
	free(sm->expected_msg);
	free(sm->payload_len_hdr);
	free(sm->serial_id);
	free(sm->sys_meta_buf);
	free(sm->app_meta_buf);
	free(sm->payload_buf);
	free(sm->break_buf);
	vortex_frame_free(sm->cached_frame);

	jaln_sub_state_destroy(&sm->wait_for_mime);
	jaln_sub_state_destroy(&sm->wait_for_app_meta);
	jaln_sub_state_destroy(&sm->wait_for_app_meta_break);
	jaln_sub_state_destroy(&sm->wait_for_sys_meta);
	jaln_sub_state_destroy(&sm->wait_for_sys_meta_break);
	jaln_sub_state_destroy(&sm->wait_for_payload);
	jaln_sub_state_destroy(&sm->wait_for_payload_break);
	jaln_sub_state_destroy(&sm->record_complete);
	jaln_sub_state_destroy(&sm->error_state);

	free(*psm);
	*psm = NULL;
}

void jaln_sub_state_destroy(struct jaln_sub_state **state)
{
	if (!state || !*state) {
		return;
	}
	free((*state)->name);
	free(*state);
	*state = NULL;

}

struct jaln_sub_state *jaln_sub_state_create()
{
	return (struct jaln_sub_state*) jal_calloc(1, sizeof(struct jaln_sub_state));
}

