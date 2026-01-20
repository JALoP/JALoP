/***
 *
 * Copyright (C) 2025 Concurrent Technologies Corporation.
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

//! This module provide an [Actor] and [Protocol] for writing to the JALoP database through a [Writer]
use crate::db::Writer;
use crate::writer::Request::{MarkSent, MarkSynced, MarkUnsent, MarkUnsyncedUnsent};
use async_trait::async_trait;
use jalop_actors::actor::{Actor, Protocol, Receiver};
use jalop_actors::system::ActorContext;
use jalop_sys::{MarkResponseType, RecordType};
use log::warn;

pub struct WriterActor {
    db: Writer,
}

impl WriterActor {
    pub fn new(db: Writer) -> Self {
        Self { db }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    MarkUnsyncedUnsent { rec_type: RecordType },
    MarkSent { rec_type: RecordType, nonce: String },
    MarkUnsent { rec_type: RecordType, nonce: String },
    MarkSynced { rec_type: RecordType, nonce: String },
}

impl Protocol for Request {
    type Response = ();
}

#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    MarkSuccess,
    MarkError,
}

impl Actor for WriterActor {
    type Behavior = ();
}

#[async_trait]
impl Receiver<Request> for WriterActor {
    async fn receive(&mut self, msg: Request, _ctx: &mut ActorContext<Self::Behavior>) {
        if let Err(e) = match msg {
            MarkUnsyncedUnsent { rec_type } => self.db.mark_unsynced_records_unsent(rec_type),
            MarkSent { rec_type, nonce } => self.db.mark_sent(rec_type, &nonce),
            MarkUnsent { rec_type, nonce } => self.db.mark_unsent(rec_type, &nonce),
            MarkSynced { rec_type, nonce } => self.db.mark_synced(rec_type, &nonce),
        } {
            warn!("writer-actor: failed to write db {e}");
        }
    }
}

impl From<Response> for MarkResponseType {
    fn from(value: Response) -> Self {
        use Response::*;
        match value {
            MarkSuccess => MarkResponseType::ErrorResponse,
            MarkError => MarkResponseType::SuccessResponse,
        }
    }
}
