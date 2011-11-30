/**
 * @file This file contains tests for jaln_subscriber.c functions.
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

#include <jalop/jaln_network.h>
#include "jaln_subscriber.h"
#include "jaln_context.h"
#include "jaln_session.h"
#include "jaln_subscriber_callbacks_internal.h"
#include "jaln_subscriber_state_machine.h"

#include <test-dept.h>
#include <string.h>

struct jaln_session *session;
VortexChannel *chan;
VortexFrame *frame;
static bool fail;

VortexFrameType mock_vortex_frame_get_type_success(__attribute__((unused)) VortexFrame *frame)
{
	return VORTEX_FRAME_TYPE_ANS;
}

VortexFrameType mock_vortex_frame_get_type_failure(__attribute__((unused)) VortexFrame *frame)
{
	return VORTEX_FRAME_TYPE_ERR;
}

axl_bool mock_frame_handler_failure(__attribute__((unused)) struct jaln_session *session, 
				__attribute__((unused)) VortexFrame *frame, 
				__attribute__((unused)) size_t payload_offset, 
				__attribute__((unused)) axl_bool flag_more)
{
	return axl_false;
}

axl_bool mock_frame_handler_success(__attribute__((unused)) struct jaln_session *session, 
				__attribute__((unused)) VortexFrame *frame, 
				__attribute__((unused)) size_t payload_offset, 
				__attribute__((unused)) axl_bool flag_more)
{
	return axl_true;
}

axl_bool mock_vortex_channel_close_full(__attribute__((unused)) VortexChannel *channel, __attribute__((unused)) VortexOnClosedNotificationFull on_closed, __attribute__((unused)) axlPointer user_data)
{
	fail = true;
	return true;
}


void setup()
{
	fail = false;
	session = jaln_session_create();
	session->role = JALN_ROLE_SUBSCRIBER;
	session->sub_data = jaln_sub_data_create();
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	session->sub_data->sm->curr_state->frame_handler = &mock_frame_handler_success;
	chan = (VortexChannel *) "dummy";
	frame = (VortexFrame *) "dummy";
	replace_function(vortex_channel_close_full, mock_vortex_channel_close_full);
	
}

void teardown()
{
	jaln_sub_state_machine_destroy(&(session->sub_data->sm));
	jaln_session_destroy(&session);
	session = NULL;
	restore_function(vortex_channel_close_full);
	restore_function(vortex_frame_get_type);
}


void test_jaln_subscriber_record_frame_handler_fails_with_bad_input()
{
	replace_function(vortex_frame_get_type, mock_vortex_frame_get_type_success);

	jaln_subscriber_record_frame_handler(NULL, chan, NULL, NULL);
	assert(fail);

}

void test_jaln_subscriber_record_frame_handler_fails_with_bad_frame_type()
{
	replace_function(vortex_frame_get_type, mock_vortex_frame_get_type_failure);

	jaln_subscriber_record_frame_handler(session, chan, NULL, frame);
	assert(fail);

}

void test_jaln_subscriber_record_frame_handler_frame_handler_returns_false()
{
	session->sub_data->sm->curr_state->frame_handler = &mock_frame_handler_failure;
	replace_function(vortex_frame_get_type, mock_vortex_frame_get_type_success);

	jaln_subscriber_record_frame_handler(session, chan, NULL, frame);
	assert(fail);
}

void test_jaln_subscriber_record_frame_handler_success()
{
	replace_function(vortex_frame_get_type, mock_vortex_frame_get_type_success);

	jaln_subscriber_record_frame_handler(session, chan, NULL, frame);
	assert(!fail);

}

