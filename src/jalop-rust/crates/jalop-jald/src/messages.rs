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
//! This module defines protocol messages that allow publisher-actor and actor-actor communication.
use jalop_actors::actor::Protocol;
use jalop_protocol::messages::ResumeInfo;
use jalop_protocol::{Token, TokenId};
use jalop_sys::record_data::RecordData;
use jalop_sys::RecordType;

#[derive(Debug)]
pub struct RecordMsg {
    pub token: TokenId,
    pub data: RecordData,
}

impl Protocol for RecordMsg {
    type Response = ();
}

#[derive(Debug)]
pub enum WorkerMsg {
    Publish(RecordMsg),
    Resume(RecordMsg, ResumeInfo),
}

impl Protocol for WorkerMsg {
    type Response = ();
}

pub enum ControlMsg {
    Start(Token, RecordType),
    Resume(Token, RecordType, String),
    Stop(Token, RecordType),
    RecvOk(Token, RecordType, String),
    RecvFailNoRetry(Token, RecordType, String),
    RecvFailRetry(Token, RecordType, String),
}

impl Protocol for ControlMsg {
    type Response = ();
}

#[derive(Debug)]
pub enum WorkerMgmtMsg {
    JournalMissing(String),
    CloseSession,
}

impl Protocol for WorkerMgmtMsg {
    type Response = ();
}
