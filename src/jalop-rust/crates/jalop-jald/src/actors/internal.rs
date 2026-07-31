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
//! This module provides actor protocols that implement internal communications between actors and
//! that is not intended to be used outside the parent module.

use crate::actors::session_worker::SessionWorker;
use jalop_actors::actor::{ActorRef, Protocol};
use jalop_protocol::messages::ResumeInfo;
use jalop_protocol::TokenId;
use jalop_sys::record_data::RecordData;
use jalop_sys::RecordType;
use std::fmt::{Debug, Display, Formatter};

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct GroupId(pub TokenId, pub RecordType);

impl Display for GroupId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}-{}", self.1, self.0))
    }
}

#[derive(Debug)]
pub enum SessionMsg {
    StartStream,
    ResumeStream(String),
    StopStream,
    SessionAcquired(ActorRef<SessionWorker>, Option<ResumeInfo>),
    SessionClosed,
}

impl Protocol for SessionMsg {
    type Response = ();
}

pub type WorkerRef = ActorRef<SessionWorker>;
pub type Nonce = String;

/// Worker to Group protocol that informs the group how to respond to the filter
//        Done == record success
//        FailRetry == record failure, mark unsent
//        FailNoRetry == record failure, do not mark unsent
//        in both cases the worker is added back to the pool
pub enum WorkResult {
    Done(WorkerRef, Nonce),
    FailRetry(WorkerRef, Nonce),
    FailNoRetry(WorkerRef, Nonce),
    Error(Nonce),
}

impl Protocol for WorkResult {
    type Response = ();
}

/// Joins multiple incoming [Protocol]s for handling by behaviors
pub enum WorkerTask {
    /// Attempt to negotiate a connection with a subscriber
    Negotiate,
    /// Publish the [RecordData] using the existing session
    PublishRecord(RecordData),
    /// Resume and publish the [RecordData] and attached [ResumeInfo]
    ResumeRecord(RecordData, ResumeInfo),
}

impl Debug for WorkerTask {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerTask::Negotiate => f.write_str("Negotiate"),
            WorkerTask::PublishRecord(rd) => f.write_fmt(format_args!("PublishRecord: {}", rd.nonce)),
            WorkerTask::ResumeRecord(..) => f.write_str("ResumeRecord"),
        }
    }
}

pub struct AttemptNegotiate;
impl Protocol for AttemptNegotiate {
    type Response = ();
}
