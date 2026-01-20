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

//! This module provides the backend execution engine for [Actor]s and the [ActorSystem]
use crate::actor::{Actor, ActorRef, Protocol, Receiver};
use crate::path::ActorPath;
use crate::system::{ActorContext, ActorSystem, SystemEvent};
use crate::KillRx;
use async_trait::async_trait;
use log::{trace, warn};
use std::marker::PhantomData;
use tokio::sync::oneshot;
use tokio::sync::{broadcast, mpsc};

// internal type that provides the execution engine for a single [Actor] implementation
pub(crate) struct ActorExecutor<A: Actor> {
    path: ActorPath,
    actor: A,
    rx: MailboxRx<A>,
    parent_kill: KillRx,
}

impl<A: Actor> ActorExecutor<A> {
    pub fn new(path: ActorPath, actor: A, parent_kill: KillRx) -> (Self, ActorRef<A>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let actor_ref = ActorRef::new(path.clone(), tx);
        let executor = ActorExecutor {
            path,
            actor,
            rx,
            parent_kill,
        };
        (executor, actor_ref)
    }

    // starts the message receive loop and calls lifecycle hooks
    pub async fn start(mut self, system: ActorSystem) {
        let (self_kill, _) = broadcast::channel(1);
        let mut ctx = ActorContext {
            path: self.path.clone(),
            system: system.clone(),
            behavior: Default::default(),
            becomes: None,
            kill: self_kill.clone(),
        };

        let start_res = self.actor.pre_start(&mut ctx).await;

        if start_res.is_err() {
            println!(
                "actor {} failed to start: {:?}",
                self.path,
                start_res.as_ref().unwrap_err()
            );
        } else {
            // update behavior if it was changed and pre-start did not error
            if let Some(b) = ctx.becomes.take() {
                ctx.behavior = b;
            }
        }

        if start_res.is_ok() {
            let mut self_kill_rx = self_kill.subscribe();
            loop {
                tokio::select! {
                    Some(mut msg) = self.rx.recv() => {
                        msg.handle(&mut self.actor, &mut ctx).await;
                        // update behavior if it was changed
                        if let Some(b) = ctx.becomes.take() {
                            ctx.behavior = b;
                        }
                    }
                    Ok(_) = self_kill_rx.recv() => break,
                    Ok(_) = self.parent_kill.recv() => {
                        let _ = self_kill.send(());
                        break
                    }
                    else => break
                }
            }
            trace!("actor {} stopping", self.path);
            self.actor.post_stop(&mut ctx).await;
        }

        if let Err(e) = system.publish(SystemEvent::ActorStopped(self.path.clone())) {
            warn!("failed to remove actor {}: {e}", self.path);
        }
    }
}

// internal alias for [Envelope] transport
pub(crate) type BoxedEnvelopeHandler<A> = Box<dyn EnvelopeHandler<A>>;

// internal "mailbox" alias, implemented by a tokio mpsc channel
pub(crate) type MailboxRx<A> = mpsc::UnboundedReceiver<BoxedEnvelopeHandler<A>>;
pub(crate) type MailboxTx<A> = mpsc::UnboundedSender<BoxedEnvelopeHandler<A>>;

// internal trait that specifies handling of [Envelop]
#[async_trait]
pub(crate) trait EnvelopeHandler<A: Actor>: Send + Sync {
    async fn handle(&mut self, actor: &mut A, ctx: &mut ActorContext<A::Behavior>);
}

// internal wrapper that provides the communication interface between the public api and the executor
pub(crate) struct MessageEnvelope<P, A>
where
    P: Protocol,
    A: Receiver<P>,
{
    message: P,
    reply_to: Option<oneshot::Sender<P::Response>>,
    _marker: PhantomData<A>,
}

impl<P, A> MessageEnvelope<P, A>
where
    P: Protocol,
    A: Receiver<P>,
{
    pub fn new(msg: P, reply_to: Option<oneshot::Sender<P::Response>>) -> Self {
        MessageEnvelope {
            message: msg,
            reply_to,
            _marker: PhantomData,
        }
    }
}

// internal wrapper implementation of message handling that links the actor with its receiver and
// implements the ask behavior when the reply_to channel is provided. the executor receives these
// messages from the public interface to the actor
#[async_trait]
impl<P, A> EnvelopeHandler<A> for MessageEnvelope<P, A>
where
    P: Protocol,
    A: Receiver<P>,
{
    async fn handle(&mut self, actor: &mut A, ctx: &mut ActorContext<A::Behavior>) {
        let r = actor.receive(self.message.clone(), ctx).await;
        if let Some(reply_to) = self.reply_to.take() {
            let _ = reply_to.send(r);
        }
    }
}
