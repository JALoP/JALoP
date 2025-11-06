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

use crate::backend::{MailboxTx, MessageEnvelope};
use crate::path::ActorPath;
use crate::system::ActorContext;
use crate::ActorError;
use async_trait::async_trait;
use log::trace;
use tokio::sync::oneshot;

/// The Actor trait identifies that a type should be treated as an actor.
/// Provides optional hooks for tasks that should be run at changes to the actor lifecycle.
#[async_trait]
pub trait Actor: Send + Sync + 'static {
    /// An optional behavior that extends the context of the actor messaging handling
    /// Use unit to specify default behavior or a custom type that can define a specific behavior
    /// The [ActorContext] provides the current behavior at execution and becoming a new behavior
    type Behavior: Default + Send + Sync + 'static;

    /// Override this function to provide a custom task that executes once prior to message handling
    async fn pre_start(&mut self, _ctx: &mut ActorContext<Self::Behavior>) -> Result<(), ActorError> {
        Ok(())
    }

    /// Override this function to provide a custom task that executes once after the actor has stopped
    async fn post_stop(&mut self, _ctx: &mut ActorContext<Self::Behavior>) {}
}

/// This trait defines the protocol used to communicate with an [Actor].
/// The [Protocol] implementor is the input type, and the response type is the output.
/// The response can be a Unit which declares that there is not a response expected.
pub trait Protocol: Clone + Send + Sync + 'static {
    /// Define the response type to the message
    /// Specify unit to declare there is no response expected
    /// The ask functionality on an actor is available regardless of this type
    type Response: Send + Sync + 'static;
}

/// This trait defines handling of a [Protocol] type, allowing the message to be received by an [Actor].
/// The [ActorContext] maintains the state of the actor instance within the [ActorSystem] and
/// maintains the current behavior of the actor.
#[async_trait]
pub trait Receiver<M: Protocol>: Actor {
    /// Receive the next message from the actor mailbox along with the current context of the actor
    /// This function will return the response type declared in the message that was received
    async fn receive(&mut self, msg: M, ctx: &mut ActorContext<Self::Behavior>) -> M::Response;
}

/// The interface to a running actor that allows message based communication with the actor.
/// This type is cloneable and lightweight, intended to be shared anywhere communication with
/// the underlying [Actor] is expected.
pub struct ActorRef<A: Actor> {
    path: ActorPath,
    tx: MailboxTx<A>,
}

impl<A: Actor> ActorRef<A> {
    pub(crate) fn new(path: ActorPath, tx: MailboxTx<A>) -> Self {
        Self { path, tx }
    }

    /// The [ActorPath] of the [Actor] instance
    pub fn path(&self) -> &ActorPath {
        &self.path
    }

    /// Send a [Protocol] to the [Actor]
    /// This is a fire-and-forget request that does not wait for a response from the [Actor]
    /// Rust provides compile-time guarantee that a [Receiver] for the message type has been implemented for the [Actor]
    pub async fn tell<M>(&self, msg: M) -> Result<(), ActorError>
    where
        M: Protocol,
        A: Receiver<M>,
    {
        if self.tx.is_closed() {
            return Err(ActorError::ActorStopped);
        }

        let message = MessageEnvelope::new(msg, None);
        self.tx.send(Box::new(message)).map_err(|_| ActorError::TellFailed)
    }

    /// Ask the [Actor] for a response to a [Protocol] message.
    /// This request waits for a response from the [Actor], the response type is defined in the [Protocol] impl.
    /// Rust guarantees at compile-time that a [Receiver] for the protocol has been implemented for the [Actor].
    pub async fn ask<M>(&self, msg: M) -> Result<M::Response, ActorError>
    where
        M: Protocol,
        A: Receiver<M>,
    {
        if self.tx.is_closed() {
            return Err(ActorError::ActorStopped);
        }

        let (tx, rx) = oneshot::channel();
        let message = MessageEnvelope::new(msg, Some(tx));
        let _ = self.tx.send(Box::new(message)).map_err(|_| ActorError::AskFailed)?;
        rx.await.map_err(|_| ActorError::AskFailed)
    }

    pub async fn is_alive(&self) -> bool {
        self.tx.is_closed()
    }
}

impl<A: Actor> Clone for ActorRef<A> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            tx: self.tx.clone(),
        }
    }
}

/// [Protocol] message that causes an [Actor] to stop
/// Being delivered as a message this results in the
/// [Actor] processing all messages in the mailbox prior
/// to the sending of this message
#[derive(Clone, Debug)]
pub struct PoisonPill;

impl Protocol for PoisonPill {
    type Response = ();
}

// blanket impl so that all actors handle this message by stopping the actor
#[async_trait]
impl<T: Actor> Receiver<PoisonPill> for T {
    async fn receive(&mut self, _: PoisonPill, ctx: &mut ActorContext<Self::Behavior>) {
        trace!("actor {} poisoned", ctx.path);
        ctx.stop();
    }
}
