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
//! This module provides the [Actor] implementation responsible for negotiating connections and publishing records
use crate::actors::config::SessionWorkerConfig;
use crate::actors::internal::{AttemptNegotiate, SessionMsg, WorkResult, WorkerTask};
use crate::actors::session_group::SessionGroup;
use crate::actors::worker_behavior::WorkerBehavior;
use crate::actors::worker_error::ReactionKind;
use crate::messages::{WorkerMgmtMsg, WorkerMsg};
use async_trait::async_trait;
use jalop_actors::actor::{Actor, ActorRef, Receiver};
use jalop_actors::system::ActorContext;
use jalop_actors::ActorError;
use jalop_protocol::messages::{
    peek_message_type, CloseSessionMessageBuilder, JalopMessageType, JournalMissingMessageBuilder,
};
use jalop_protocol::Token;
use jalop_sys::RecordType;
use log::{debug, error, info, trace, warn};
use reqwest::Client;

/// The Session Worker actor is responsible for all communication with the subscriber peer.
/// Session Workers are implicitly created by a [SessionGroup] based on the application configuration.
pub struct SessionWorker {
    pub token: Token,
    pub rec_type: RecordType,
    pub client: Client,
    pub config: SessionWorkerConfig,
    pub group: ActorRef<SessionGroup>,
}

impl SessionWorker {
    pub fn new(
        client: Client,
        token: Token,
        rec_type: RecordType,
        config: SessionWorkerConfig,
        group: ActorRef<SessionGroup>,
    ) -> Self {
        Self {
            token,
            rec_type,
            client,
            config,
            group,
        }
    }

    fn is_connected(ctx: &mut ActorContext<Self>) -> bool {
        matches!(ctx.behavior(), WorkerBehavior::SessionActive(_))
    }

    async fn reconnect(&self, ctx: &mut ActorContext<Self>) {
        let _ = ctx.tell(AttemptNegotiate).await;
        ctx.becomes(WorkerBehavior::NotConnected);

        // notify the group that the session has been disconnected
        if Self::is_connected(ctx) {
            let _ = self.group.tell(SessionMsg::SessionClosed).await;
        }
    }
}

#[async_trait]
impl Actor for SessionWorker {
    type Behavior = WorkerBehavior;

    async fn pre_start(&mut self, ctx: &mut ActorContext<Self>) -> Result<(), ActorError> {
        ctx.tell(AttemptNegotiate).await?;
        Ok(())
    }

    async fn post_stop(&mut self, ctx: &mut ActorContext<Self>) {
        debug!("stopping session worker");

        // if a session was active, inform the subscriber it is closing
        if let WorkerBehavior::SessionActive(config) = ctx.behavior() {
            debug!("closing active session on worker stop - id: {:?}", config.session_id);
            match CloseSessionMessageBuilder::new(config.session_id.clone()).build() {
                Ok((headers, body)) => {
                    if let Err(e) =
                        self.client.post(self.config.endpoint.clone()).headers(headers.clone()).body(body).send().await
                    {
                        warn!("failed to send close-session request to subscriber, {e}")
                    }
                }
                Err(e) => error!("failed to build journal-missing request {e}"),
            }
        }
    }
}

#[async_trait]
impl Receiver<AttemptNegotiate> for SessionWorker {
    async fn receive(&mut self, _: AttemptNegotiate, ctx: &mut ActorContext<Self>) {
        info!("negotiating connection");
        match ctx.behavior().receive(self, WorkerTask::Negotiate, ctx).await {
            // continue with negotiate behavior -- retry after configured interval
            Ok(None) => {
                let aref = ctx.aref();
                let interval = self.config.retry_interval;
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
                    let _ = aref.tell(AttemptNegotiate).await;
                });
            }
            // change behavior
            Ok(Some(new_behavior)) => {
                trace!("becoming: {new_behavior:?}");
                ctx.becomes(new_behavior);
            }
            // react to errors that are possible while negotiating (i.e. not RecordFail)
            // we can match in two ways in this block
            // 1. match on the WorkerError when the reaction guidance is too broad
            // 2. match on the ReactionKind attached to the error, in most cases this is specific enough
            Err(e) => {
                warn!("worker behavior error while {:?}, {e}", ctx.behavior());
                // match specifically on a WorkerError type for fine-grained negotiation error handling
                // match broadly on the attached reaction kind for non-specific negotiation error handling
                match e.severity_kind() {
                    ReactionKind::Ignore => {
                        debug!("worker error [ignore] {e}");
                    }
                    ReactionKind::Reconnect => {
                        warn!("worker error: [reconnect] {e}");
                        self.reconnect(ctx).await;
                    }
                    x => {
                        warn!("worker error: [unexpected] reaction {x:?} requested for {e}")
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Receiver<WorkerMsg> for SessionWorker {
    async fn receive(&mut self, msg: WorkerMsg, ctx: &mut ActorContext<Self>) {
        let (nonce, task) = match msg {
            WorkerMsg::Publish(m) => (m.data.nonce.clone(), WorkerTask::PublishRecord(m.data)),
            WorkerMsg::Resume(m, r) => (m.data.nonce.clone(), WorkerTask::ResumeRecord(m.data, r)),
        };

        //debug!("worker received {} {} {}", msg.token, msg.data.rec_type, nonce);
        match ctx.behavior().receive(self, task, ctx).await {
            // behavior stays the same
            Ok(None) => {}
            // change behavior
            Ok(Some(new_behavior)) => {
                trace!("becoming: {new_behavior:?}");
                ctx.becomes(new_behavior);
            }
            // react to errors that are possible while publishing (i.e. all of them)
            // again we can match in two ways in this block
            // 1. match on the WorkerError when the reaction guidance is too broad
            // 2. match on the ReactionKind attached to the error, in most cases this is specific enough
            Err(e) => {
                warn!("worker behavior error while {:?}, {e}", ctx.behavior());
                // match specifically on a WorkerError type for fine-grained record publishing error handling
                match e.severity_kind() {
                    // match broadly on the attached reaction kind for non-specific record publishing handling
                    ReactionKind::Reconnect | ReactionKind::Ignore => {
                        warn!("worker error [reconnect] {e}");
                        let _ = self.group.tell(WorkResult::FailRetry(ctx.aref(), nonce)).await;
                        self.reconnect(ctx).await;
                    }
                    ReactionKind::RecordFailNoRetry => {
                        warn!("worker error [record-fail] {e}");
                        let _ = self.group.tell(WorkResult::FailNoRetry(ctx.aref(), nonce)).await;
                    }
                    ReactionKind::RecordFailRetry => {
                        warn!("worker error [record-fail-retry] {e}");
                        let _ = self.group.tell(WorkResult::FailRetry(ctx.aref(), nonce)).await;
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Receiver<WorkerMgmtMsg> for SessionWorker {
    async fn receive(&mut self, msg: WorkerMgmtMsg, ctx: &mut ActorContext<Self>) {
        debug!("worker mgmt message received {:?}", msg);
        match (msg, ctx.behavior()) {
            // close-session - tell subscriber to close the session (only when a session is established)
            (WorkerMgmtMsg::CloseSession, WorkerBehavior::SessionActive(config)) => {
                debug!(
                    "closing active session on worker mgmt request - id: {:?}",
                    config.session_id
                );
                match CloseSessionMessageBuilder::new(config.session_id.clone()).build() {
                    Ok((headers, body)) => {
                        if let Err(e) = self
                            .client
                            .post(self.config.endpoint.clone())
                            .headers(headers.clone())
                            .body(body)
                            .send()
                            .await
                        {
                            warn!("failed to send close-session request to subscriber, {e}")
                        }
                    }
                    Err(e) => error!("failed to build journal-missing request {e}"),
                }
            }
            // journal-missing - must notify the subscriber prior to sending the message
            (WorkerMgmtMsg::JournalMissing(nonce), WorkerBehavior::SessionActive(config)) => {
                match JournalMissingMessageBuilder::new(config.session_id.clone(), nonce).build() {
                    Ok((headers, body)) => {
                        match self
                            .client
                            .post(self.config.endpoint.clone())
                            .headers(headers.clone())
                            .body(body)
                            .send()
                            .await
                        {
                            Ok(response) => {
                                info!("journal-missing response received from subscriber {response:?}");
                                match peek_message_type(&response) {
                                    Ok(JalopMessageType::SessionFailure) => {
                                        warn!("received session-failure response to journal-missing, closing session");
                                        self.reconnect(ctx).await;
                                    }
                                    Ok(JalopMessageType::RecordFailure) => {
                                        warn!("record failure received in response to journal-missing")
                                    }
                                    Err(e) => warn!("error inspecting journal-missing response: {e}"),
                                    _ => {}
                                };
                            }
                            Err(e) => warn!("failed to send journal-missing request to subscriber {e}"),
                        }
                    }
                    Err(e) => error!("failed to build journal-missing request {e}"),
                }
            }
            (m, b) => warn!("worker-management unsupported message: {m:?} for current behavior: {b:?}"),
        }
    }
}
