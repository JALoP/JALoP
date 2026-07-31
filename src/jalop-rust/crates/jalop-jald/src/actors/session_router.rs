/***
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
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
//! This module provides the [Actor] implementation for routing records to [SessionGroup] actors
use crate::actors::session_group::SessionGroup;

use crate::actors::internal::GroupId;
use crate::messages::RecordMsg;
use async_trait::async_trait;
use jalop_actors::actor::{Actor, ActorRef, Protocol, Receiver};
use jalop_actors::system::ActorContext;
use log::{info, trace, warn};
use std::collections::HashMap;

/// The Router actor is responsible for routing record messages ([RecordMsg]) to the correct [SessionGroup]
/// by inspecting the [jalop_protocol::Token] and [jalop_sys::RecordType] to look up the destination [SessionGroup].
#[derive(Default)]
pub struct SessionRouter {
    // the routing table - maps token + record_type to a SessionGroup actor ref
    groups: HashMap<GroupId, ActorRef<SessionGroup>>,
}

impl Actor for SessionRouter {
    type Behavior = ();
}

#[derive(Debug)]
pub enum SessionRouterMsg {
    AddGroup(SessionGroup),
}

/// Errors that can occur during [SessionRouter] operation.
#[derive(Debug)]
pub enum SessionRouterError {
    /// Failed to add a [SessionGroup] to the routing table
    GroupAddFailure(GroupId),
    /// The [SessionGroup] already exists in the routing table
    DuplicateGroup(GroupId),
}

impl Protocol for SessionRouterMsg {
    type Response = Result<(), SessionRouterError>;
}

#[async_trait]
impl Receiver<SessionRouterMsg> for SessionRouter {
    async fn receive(&mut self, msg: SessionRouterMsg, ctx: &mut ActorContext<Self>) -> Result<(), SessionRouterError> {
        match msg {
            SessionRouterMsg::AddGroup(sg) => {
                let group_id = sg.group_id();
                let group_name = group_id.to_string();

                match ctx.child::<SessionGroup>(&group_name).await {
                    Some(_) => {
                        warn!("duplicate session group found");
                        Err(SessionRouterError::DuplicateGroup(group_id))
                    }
                    None => {
                        let mode = sg.mode();
                        match ctx.spawn(&group_name, sg).await {
                            Ok(group) => {
                                info!("created new session group {group_id} for {mode:?}");
                                self.groups.insert(group_id, group);
                                Ok(())
                            }
                            Err(e) => {
                                warn!("failed to add session group {group_id}, {e}");
                                Err(SessionRouterError::GroupAddFailure(group_id))
                            }
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Receiver<RecordMsg> for SessionRouter {
    async fn receive(&mut self, msg: RecordMsg, _ctx: &mut ActorContext<Self>) {
        let k = GroupId(msg.token, msg.data.rec_type);
        match self.groups.get(&k) {
            // state is guarded by protocol by the coupling of socket/jald/filter lifecycles
            // going to leave it as warn so that it is prominent in the case it could happen
            None => warn!("group {k} does not exist, dropping message {}", msg.data.nonce),
            Some(r) => {
                trace!("routing record to {r:?} ({k})");
                let _ = r.tell(msg).await;
            }
        };
    }
}
