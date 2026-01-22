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

//! This module provides an [Actor] implementation that maps to a JALoP subscriber [RecordType] channel.
use crate::db::Reader;
use crate::sender::{SendResp, SenderActor, SenderMsg};
use crate::time::Timestamp;
use crate::writer;
use crate::writer::WriterActor;
use async_trait::async_trait;
use jalop_actors::actor::{Actor, ActorRef, Protocol, Receiver};
use jalop_actors::system::ActorContext;
use jalop_actors::{tell_self, ActorError};
use jalop_sys::RecordType;
use log::{error, info, warn};
use std::time::Duration;

/// A subscriber of a [RecordType] in archive mode
pub struct ArchiveSubscriber {
    id: TokenId,
    rt: RecordType,
    tx: ActorRef<SenderActor>,
    db: Reader,
    writer: ActorRef<WriterActor>,
}

/// A subscriber of a [RecordType] in live mode
pub struct LiveSubscriber {
    id: TokenId,
    ts: Timestamp,
    rt: RecordType,
    tx: ActorRef<SenderActor>,
    db: Reader,
}

impl ArchiveSubscriber {
    pub fn new(
        id: TokenId,
        rt: RecordType,
        tx: ActorRef<SenderActor>,
        db: Reader,
        writer: ActorRef<WriterActor>,
    ) -> Self {
        Self { id, rt, tx, db, writer }
    }
}

impl LiveSubscriber {
    pub fn new(id: TokenId, ts: Timestamp, rt: RecordType, tx: ActorRef<SenderActor>, db: Reader) -> Self {
        Self { id, ts, rt, tx, db }
    }
}

#[async_trait]
impl Actor for ArchiveSubscriber {
    type Behavior = ();
}

impl Actor for LiveSubscriber {
    type Behavior = ();
}

#[derive(Clone)]
pub enum SubscriberMsg {
    ReadNext,
    ResumeFrom(String),
}

impl Protocol for SubscriberMsg {
    type Response = Result<(), ActorError>;
}

#[async_trait]
impl Receiver<SubscriberMsg> for LiveSubscriber {
    async fn receive(&mut self, msg: SubscriberMsg, ctx: &mut ActorContext<Self::Behavior>) -> Result<(), ActorError> {
        match msg {
            SubscriberMsg::ReadNext => {
                match self.db.get_next_chronological(self.rt, self.ts.clone()) {
                    Ok(None) => tokio::time::sleep(Duration::from_secs(1)).await,
                    Ok(Some((record, ts))) => match self.tx.ask(SenderMsg::Send(self.id, record)).await?? {
                        SendResp::Pending(mut accepted, _sent) => {
                            let _ = accepted.recv().await;
                            self.ts = ts;
                        }
                        SendResp::Success => self.ts = ts,
                        SendResp::Failure(nonce) => warn!("send of {nonce} failed"),
                    },
                    Err(e) => error!("live-subscriber: {} failed to read next: {}", self.rt, e),
                }
                tell_self!(ctx, SubscriberMsg::ReadNext);
                Ok(())
            }
            SubscriberMsg::ResumeFrom(_) => {
                warn!("resume not supported for live mode subscribers");
                Ok(())
            }
        }
    }
}

#[async_trait]
impl Receiver<SubscriberMsg> for ArchiveSubscriber {
    async fn receive(&mut self, msg: SubscriberMsg, ctx: &mut ActorContext<Self::Behavior>) -> Result<(), ActorError> {
        match msg {
            SubscriberMsg::ReadNext => {
                match self.db.get_next_unsynced_record(self.rt) {
                    Ok(None) => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        tell_self!(ctx, SubscriberMsg::ReadNext);
                    }
                    Ok(Some(record)) => {
                        let _ = self.writer.ask(self.make_sent_msg(&record.nonce)).await;
                        let send_res = self.tx.ask(SenderMsg::Send(self.id, record)).await??;
                        match send_res {
                            SendResp::Pending(mut accepted, _sent) => {
                                let _ = accepted.recv().await;
                            }
                            SendResp::Failure(nonce) => {
                                warn!("send of {nonce} failed, marking unsent");
                                let _ = self.writer.tell(self.make_unsent_msg(&nonce)).await;
                            }
                            SendResp::Success => {}
                        }
                        tell_self!(ctx, SubscriberMsg::ReadNext);
                    }
                    Err(e) => {
                        error!("archive-subscriber: {} failed to read next: {}", self.rt, e);
                        tell_self!(ctx, SubscriberMsg::ReadNext);
                    }
                }
                Ok(())
            }
            SubscriberMsg::ResumeFrom(nonce) => match self.db.get_record(self.rt, &nonce) {
                Ok(record) => {
                    info!("resumed {} reader {} at nonce {}", self.rt, self.id, nonce);
                    let send_res = self.tx.ask(SenderMsg::Send(self.id, record)).await??;
                    match send_res {
                        SendResp::Pending(mut accepted, _sent) => {
                            let _ = self.writer.ask(self.make_sent_msg(&nonce)).await;
                            let _ = accepted.recv().await;
                        }
                        SendResp::Failure(nonce) => {
                            warn!("resume of {nonce} failed, marking unsent");
                            let _ = self.writer.tell(self.make_unsent_msg(&nonce)).await;
                        }
                        SendResp::Success => {}
                    }
                    Ok(())
                }
                Err(e) => {
                    error!("archive-subscriber: {} failed to read resume record: {}", self.rt, e);
                    tell_self!(ctx, SubscriberMsg::ReadNext);
                    Ok(())
                }
            },
        }
    }
}

impl ArchiveSubscriber {
    fn make_sent_msg(&self, nonce: &str) -> writer::Request {
        writer::Request::MarkSent {
            rec_type: self.rt,
            nonce: nonce.to_string(),
        }
    }

    fn make_unsent_msg(&self, nonce: &str) -> writer::Request {
        writer::Request::MarkUnsent {
            rec_type: self.rt,
            nonce: nonce.to_string(),
        }
    }
}

/// Token
pub type TokenId = u16;

/// Unique identifier of a subscriber
/// Provides token number and indicates the filter mode
#[derive(Clone, Debug)]
pub enum Token {
    Live(TokenId),
    Archive(TokenId),
}

impl Token {
    /// Get the identifier of this token
    pub fn id(&self) -> TokenId {
        match self {
            Token::Live(id) => *id,
            Token::Archive(id) => *id,
        }
    }
}
