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

//! This module provide actors that receive [RecordData] and publish to a single output [UnixStream].
use async_trait::async_trait;
use jalop_actors::actor::{Actor, ActorRef, Protocol, Receiver};
use jalop_actors::system::ActorContext;
use jalop_actors::ActorError;
use jalop_protocol::TokenId;
use jalop_sys::record_data::{IoData, RecordData};
use jalop_sys::RecordType;
use jalop_util::queue::BackPressureQueue;
use log::{error, trace, warn};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, UnixAddr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use tokio::sync::mpsc;

/// An [Actor] that supervises the sending of [RecordData] across a single [UnixStream].
pub struct SenderActor {
    rt: RecordType,
    bpq: Arc<BackPressureQueue<TokenId>>,
    stream: Arc<UnixStream>,
}

impl SenderActor {
    /// Create a new sender supervisor for the [RecordType] using the [UnixStream].
    /// The sender will backpressure when the specified capacity is met on the socket.
    /// Capacity is measured in number of records on the socket, not in total bytes.
    pub fn new(rt: RecordType, stream: UnixStream, capacity: usize) -> Self {
        Self {
            rt,
            bpq: Arc::new(BackPressureQueue::new(capacity)),
            stream: Arc::new(stream),
        }
    }
}

/// Behavior that maps the transition of the supervisor starting to being ready.
#[derive(Default)]
pub enum SenderBehavior {
    #[default]
    Starting,
    Initialized(ActorRef<SendWorker>),
}

/// Implement [Actor] for the [SenderActor]
#[async_trait]
impl Actor for SenderActor {
    type Behavior = SenderBehavior;

    async fn pre_start(&mut self, ctx: &mut ActorContext<Self>) -> Result<(), ActorError> {
        let worker = ctx
            .spawn(
                "worker",
                SendWorker {
                    rt: self.rt,
                    bpq: self.bpq.clone(),
                    stream: self.stream.clone(),
                },
            )
            .await?;
        ctx.becomes(SenderBehavior::Initialized(worker));
        Ok(())
    }
}

/// A [Protocol] for messaging the [SenderActor] actor.
pub enum SenderMsg {
    Send(TokenId, RecordData),
    Sent(TokenId, String),
    Evict(String),
    EvictAll(TokenId),
}

/// Tx notification that a message was sent to the socket
pub type SendNotify = mpsc::Sender<SendResp>;

/// Rx notification that a message was sent to the socket
pub type SendReceipt = mpsc::Receiver<SendResp>;

/// Tx notification that a message was accepted by the sender, but not yet sent to the socket
pub type AcceptedNotify = mpsc::Sender<()>;

/// Rx notification that a message was accepted by the sender, but not yet sent to the socket
pub type AcceptedReceipt = mpsc::Receiver<()>;

/// Responses possible from the [SenderMsg] [Protocol]
pub enum SendResp {
    Pending(AcceptedReceipt, SendReceipt),
    Success,
    Failure(String),
}

/// Implement [SenderMsg] as an actor messaging [Protocol]
#[async_trait]
impl Protocol for SenderMsg {
    type Response = Result<SendResp, ActorError>;
}

/// Implement [Receiver] of the [SenderMsg] [Protocol] for the [SenderActor] actor
#[async_trait]
impl Receiver<SenderMsg> for SenderActor {
    async fn receive(&mut self, msg: SenderMsg, ctx: &mut ActorContext<Self>) -> Result<SendResp, ActorError> {
        match ctx.behavior() {
            SenderBehavior::Initialized(worker) => match msg {
                SenderMsg::Sent(token, nonce) => {
                    self.bpq.evict(&nonce).await;
                    trace!("evict {nonce} from {:?} sender queue for subscriber {token}", self.rt);
                    Ok(SendResp::Success)
                }
                SenderMsg::Send(token, rec) => {
                    let (accepted_tx, accepted_rx) = mpsc::channel(1);
                    let (sent_tx, sent_rx) = mpsc::channel(1);
                    let _ = worker.tell(WorkerMsg::new(token, rec, accepted_tx, sent_tx)).await?;
                    Ok(SendResp::Pending(accepted_rx, sent_rx))
                }
                SenderMsg::Evict(nonce) => {
                    self.bpq.evict(&nonce).await;
                    trace!("evict {nonce} from {:?} sender queue", self.rt);
                    Ok(SendResp::Success)
                }
                SenderMsg::EvictAll(id) => {
                    trace!("evict all from {:?} sender queue for subscriber {id}", self.rt);
                    self.bpq.evict_values(id).await;
                    Ok(SendResp::Success)
                }
            },
            _ => {
                warn!("invalid sender behavior state");
                ctx.stop();
                Err(ActorError::ActorStopped)
            }
        }
    }
}

/// A [Protocol] for messaging the [SendWorker] actor.
struct WorkerMsg {
    id: TokenId,
    record: RecordData,
    accepted: AcceptedNotify,
    sent: SendNotify,
}

impl WorkerMsg {
    fn new(id: u16, record: RecordData, accepted: AcceptedNotify, sent: SendNotify) -> Self {
        Self {
            id,
            record,
            accepted,
            sent,
        }
    }
}

/// Implement [Worker] as an actor messaging [Protocol]
impl Protocol for WorkerMsg {
    type Response = Result<(), ActorError>;
}

/// A child of the [SenderActor], responsible for putting bytes into the [UnixStream]
pub struct SendWorker {
    rt: RecordType,
    bpq: Arc<BackPressureQueue<TokenId>>,
    stream: Arc<UnixStream>,
}

/// Implement [Actor] for the [SendWorker]
#[async_trait]
impl Actor for SendWorker {
    type Behavior = ();
}

/// Implement [Receiver] of the [WorkerMsg] [Protocol] for the [SendWorker] actor
#[async_trait]
impl Receiver<WorkerMsg> for SendWorker {
    async fn receive(&mut self, msg: WorkerMsg, _ctx: &mut ActorContext<Self>) -> Result<(), ActorError> {
        let fd = self.stream.as_raw_fd();
        let nonce = msg.record.nonce.clone();
        self.bpq.insert(&nonce, msg.id).await.map_err(|_| ActorError::ActorStopped)?;
        trace!("added {nonce} to {:?} sender queue for subscriber {}", self.rt, msg.id);
        let _ = msg.accepted.send(()).await;
        let send = tokio::task::spawn_blocking(move || {
            let io_data: IoData = IoData::new(msg.record, msg.id);
            let iovs = io_data.vectors();
            let mut cmsgs = vec![];

            // this construct transfers ownership of the fd reference to the outer context
            let fd_array;
            if let Some(fd) = io_data.fd.as_ref() {
                fd_array = [fd.as_raw_fd()];
                cmsgs.push(ControlMessage::ScmRights(&fd_array))
            }
            sendmsg(fd, &iovs, &cmsgs, MsgFlags::empty(), None::<&UnixAddr>)
        });
        match send.await {
            Ok(Ok(n)) => {
                trace!("{:?} uds send success {n} - {nonce}", self.rt);
                let _ = msg.sent.send(SendResp::Success).await;
            }
            Ok(Err(e)) => {
                let _ = msg.sent.send(SendResp::Failure(nonce)).await;
                error!("socket-tx: {:?} uds send failed: {e:?}", self.rt)
            }
            Err(e) => {
                let _ = msg.sent.send(SendResp::Failure(nonce)).await;
                error!("socket-tx: {:?} uds send thread join failed: {e:?}", self.rt)
            }
        }
        Ok(())
    }
}
