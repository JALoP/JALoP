/**
 * @file jaln_listen.c This file contains function definitions
 * related to listening for a remote peer to connect over the JALoP
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
#include "jaln_listen.h"

#include "jal_alloc.h"
#include "jaln_context.h"
#include "jaln_session.h"

axl_bool jaln_listener_handle_new_digest_channel_no_lock(jaln_context *ctx,
		VortexConnection *conn,
		const char *server_name,
		int new_chan_num,
		int paired_chan_num)
{
	if (!ctx || !conn || !server_name || 0 >= new_chan_num || 0 >= paired_chan_num) {
		return axl_false;
	}
	VortexChannel *chan = vortex_connection_get_channel(conn, new_chan_num);
	vortex_channel_set_automatic_mime(chan, 2);
	vortex_channel_set_serialize(chan, axl_true);
	char * server_name_cpy = jal_strdup(server_name);
	struct jaln_session *sess = jaln_ctx_find_session_by_rec_channel_no_lock(ctx, server_name_cpy, paired_chan_num);
	free(server_name_cpy);
	if (!sess) {
		return axl_false;
	}
	vortex_mutex_lock(&sess->lock);
	axl_bool ret = jaln_session_associate_digest_channel_no_lock(sess, chan, new_chan_num);
	vortex_mutex_unlock(&sess->lock);
	return ret;
}

