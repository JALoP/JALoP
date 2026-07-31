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
//! This module provides the [Actor] implementation for managing subscriber session groups
use crate::actors::config::{SessionGroupConfig, SessionWorkerConfig};
use crate::actors::internal::{GroupId, SessionMsg, WorkResult};
use crate::actors::session_worker::SessionWorker;
use crate::messages::{ControlMsg, RecordMsg, WorkerMgmtMsg, WorkerMsg};
use crate::sockets::ControlSocket;
use async_trait::async_trait;
use jalop_actors::actor::{Actor, ActorRef, Receiver};
use jalop_actors::system::ActorContext;
use jalop_actors::ActorError;
use jalop_protocol::control::subscriptions::SubscriberMode;
use jalop_protocol::messages::ResumeInfo;
use jalop_protocol::Token;
use jalop_sys::RecordType;
use log::{debug, info, warn};
use reqwest::Client;
use std::collections::VecDeque;

/// The Session Group actor is responsible for managing a predetermined set of Session Worker actors, distributing
/// work as it becomes available. It is also responsible for communication with the [ControlSocket] actor, starting
/// and stopping the record stream based on the presence of active sessions in the Session Workers, and forwarding
/// the record transmission status from the workers to the [ControlSocket] to signal to the filter the success or
/// failure of a record.
#[derive(Debug)]
pub struct SessionGroup {
    token: Token,
    rec_type: RecordType,
    http_client: Client,
    config: SessionGroupConfig,
    control: ActorRef<ControlSocket>,
    work: VecDeque<RecordMsg>,
    workers: VecDeque<ActorRef<SessionWorker>>,
    streaming: bool,
    active_session_count: usize,
}

#[derive(Debug, Default)]
pub enum PublishBehavior {
    #[default]
    Publishing,
    Resuming(ActorRef<SessionWorker>, ResumeInfo),
}

impl SessionGroup {
    pub fn new(
        token: Token,
        rec_type: RecordType,
        http: Client,
        config: SessionGroupConfig,
        control: ActorRef<ControlSocket>,
    ) -> Self {
        Self {
            token,
            rec_type,
            http_client: http,
            config,
            control,
            work: VecDeque::new(),
            workers: VecDeque::new(),
            streaming: false,
            active_session_count: 0,
        }
    }

    pub fn group_id(&self) -> GroupId {
        GroupId(self.token.id(), self.rec_type)
    }

    pub fn mode(&self) -> SubscriberMode {
        self.token.mode()
    }
}

#[async_trait]
impl Actor for SessionGroup {
    type Behavior = PublishBehavior;

    async fn pre_start(&mut self, ctx: &mut ActorContext<Self>) -> Result<(), ActorError> {
        info!(
            "starting session group {} with worker count {}",
            self.rec_type, self.config.worker_count
        );
        for i in 0..self.config.worker_count {
            let worker = SessionWorker::new(
                self.http_client.clone(),
                self.token,
                self.rec_type,
                SessionWorkerConfig::from(&self.config),
                ctx.aref(),
            );
            ctx.spawn(&format!("worker-{i}"), worker).await?;
        }
        Ok(())
    }

    async fn post_stop(&mut self, _ctx: &mut ActorContext<Self>) {
        // if streaming was not previously stopped, stop it now
        // ideally it is stopped prior to this point so that all in-flight records can be processed
        if self.streaming {
            if let Err(e) = self.control.tell(ControlMsg::Stop(self.token, self.rec_type)).await {
                warn!("stop session group {} failed {e}", self.token);
            }
        }
    }
}

#[async_trait]
impl Receiver<SessionMsg> for SessionGroup {
    async fn receive(&mut self, msg: SessionMsg, ctx: &mut ActorContext<Self>) {
        match msg {
            SessionMsg::StartStream | SessionMsg::ResumeStream(_) if self.streaming => {
                debug!(
                    "session group [{}] [start/resume] ignored, already streaming",
                    self.token
                )
            }
            SessionMsg::StartStream => {
                debug!("session group [{}] [start-stream] {}", self.token, self.rec_type);
                let _ = self.control.tell(ControlMsg::Start(self.token, self.rec_type)).await;
                self.streaming = true;
            }
            SessionMsg::ResumeStream(nonce) => {
                debug!("session group [{}] [resume-stream] {}", self.token, self.rec_type);
                let _ = self.control.tell(ControlMsg::Resume(self.token, self.rec_type, nonce)).await;
                self.streaming = true;
            }
            SessionMsg::StopStream if !self.streaming => {
                debug!(
                    "session group [{}] [stop-stream] ignored, stream not connected",
                    self.token
                )
            }
            SessionMsg::StopStream => {
                debug!("session group [{}] [stop-stream] {}", self.token, self.rec_type);
                let _ = self.control.tell(ControlMsg::Stop(self.token, self.rec_type)).await;
                self.streaming = false;
            }
            SessionMsg::SessionAcquired(worker, _) if self.streaming => {
                self.active_session_count += 1;
                debug!(
                    "session group [{}] [session-acquired] already streaming {}",
                    self.token, self.rec_type
                );
                match self.work.pop_front() {
                    Some(work) => {
                        let _ = worker.tell(WorkerMsg::Publish(work)).await;
                    }
                    None => self.workers.push_back(worker),
                };
            }
            SessionMsg::SessionAcquired(worker, None) => {
                self.active_session_count += 1;
                debug!(
                    "session group [{}] [session-acquired] starting stream {}",
                    self.token, self.rec_type
                );
                let _ = self.control.tell(ControlMsg::Start(self.token, self.rec_type)).await;
                match self.work.pop_front() {
                    Some(work) => {
                        let _ = worker.tell(WorkerMsg::Publish(work)).await;
                    }
                    None => self.workers.push_back(worker),
                };
                self.streaming = true;
            }
            SessionMsg::SessionAcquired(worker, Some(resume_info)) => {
                self.active_session_count += 1;
                debug!(
                    "session group [{}] [session-acquired] resuming stream {} {}",
                    self.token, self.rec_type, resume_info.id
                );
                let _ = self.control.tell(ControlMsg::Resume(self.token, self.rec_type, resume_info.id.clone())).await;
                ctx.becomes(PublishBehavior::Resuming(worker, resume_info));
                self.streaming = true;
            }
            SessionMsg::SessionClosed if self.streaming => {
                self.active_session_count -= 1;
                debug!(
                    "session group [{}] [session-failure] reconnecting {}",
                    self.token, self.rec_type
                );

                if self.active_session_count == 0 {
                    debug!(
                        "session group [{}] [session-failure] no active sessions, stopping stream",
                        self.token
                    );
                    let _ = self.control.tell(ControlMsg::Stop(self.token, self.rec_type)).await;
                    self.streaming = false;
                }
            }
            SessionMsg::SessionClosed => {
                warn!(
                    "session-group [{}] [session-closed] already not streaming {}",
                    self.token, self.rec_type
                )
            }
        }
    }
}

#[async_trait]
impl Receiver<WorkResult> for SessionGroup {
    async fn receive(&mut self, msg: WorkResult, _ctx: &mut ActorContext<Self>) {
        // map the result of the completed work and send to the control socket
        let (w, m) = match msg {
            WorkResult::Done(w, n) => (Some(w), ControlMsg::RecvOk(self.token, self.rec_type, n)),
            WorkResult::FailNoRetry(w, n) => (Some(w), ControlMsg::RecvFailNoRetry(self.token, self.rec_type, n)),
            WorkResult::FailRetry(w, n) => (Some(w), ControlMsg::RecvFailRetry(self.token, self.rec_type, n)),
            WorkResult::Error(n) => (None, ControlMsg::RecvFailRetry(self.token, self.rec_type, n)),
        };
        let _ = self.control.tell(m).await;

        // dispatch next work for non-error failures, or add the worker to the available workers queue
        if let Some(w) = w {
            match self.work.pop_front() {
                Some(work) => {
                    let _ = w.tell(WorkerMsg::Publish(work)).await;
                }
                None => self.workers.push_back(w),
            };
        }
    }
}

#[async_trait]
impl Receiver<RecordMsg> for SessionGroup {
    async fn receive(&mut self, msg: RecordMsg, ctx: &mut ActorContext<Self>) {
        match ctx.behavior() {
            PublishBehavior::Resuming(worker, resume_info) => {
                // ensure the expected resume nonce matches the received record nonce
                if resume_info.id == msg.data.nonce {
                    let _ = worker.tell(WorkerMsg::Resume(msg, resume_info.clone())).await;
                } else {
                    // if the resume nonce does not match - infer that the journal record is missing and
                    // 1. send a journal-missing message to the worker
                    // 2. send a Publish request rather than a Resume request
                    let _ = worker.tell(WorkerMgmtMsg::JournalMissing(resume_info.id.clone())).await;
                    let _ = worker.tell(WorkerMsg::Publish(msg)).await;
                }
                ctx.becomes(PublishBehavior::Publishing);
            }
            PublishBehavior::Publishing => {
                match self.workers.pop_front() {
                    Some(worker) => {
                        info!("received record- sending to worker");
                        let _ = worker.tell(WorkerMsg::Publish(msg)).await;
                    }
                    None => {
                        info!("received record -- no workers available");
                        self.work.push_back(msg)
                    }
                };
            }
        }
    }
}
