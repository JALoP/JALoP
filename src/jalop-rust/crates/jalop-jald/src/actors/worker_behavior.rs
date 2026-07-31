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
//! This module provide the behavior implementations used by [SessionWorker] actors.
//! Behaviors are swappable logic that allows the [SessionWorker] to operate similar to a finite state machine.
use crate::actors::config::SessionConfig;
use crate::actors::internal::{AttemptNegotiate, SessionMsg, WorkResult, WorkerTask};
use crate::actors::session_worker::SessionWorker;
use crate::actors::worker_error::WorkerError;
use crate::{change_behavior, continue_behavior};
use jalop_actors::system::ActorContext;
use jalop_protocol::jnl_types::error::JalopError;
use jalop_protocol::jnl_types::jalop_types::{
    CompressionList, DigestAlgorithmList, DigestChallenge, DigestChallengeList, DigestChallengeStatus, DigestHandler,
};
use jalop_protocol::messages::{peek_message_type, JalopMessageType, ResumeInfo};
use jalop_protocol::messages::{
    DigestChallengeMessage, DigestChallengeResponseMessageBuilder, InitAckMessage, InitMessageBuilder, Payload,
    RecordFailureMessage, RecordMessageBuilder, SessionFailureMessage, SyncMessage,
};
use jalop_sys::record_data::RecordData;
use log::{debug, info, trace};
use reqwest::header::HeaderMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

/// Defines the active [SessionWorker] behavior
/// The behavior drives the session worker response to messages and encapsulates
/// the ephemeral state required to execute those responses, e.g. the [SessionConfig]
#[derive(Debug, Default)]
pub enum WorkerBehavior {
    /// Disconnected state that prepares a fresh connection configuration
    #[default]
    NotConnected,
    /// Attempting to negotiate a session with the subscriber
    Negotiating(HeaderMap),
    /// Connected with an active session
    SessionActive(SessionConfig),
}

impl WorkerBehavior {
    /// Execute the [WorkerBehavior] against a [WorkerTask] message
    /// Behavior used for the next received message can be changed by returning a different [WorkerBehavior]
    /// The [continue_behavior] and [change_behavior] helper macros can be used to signal behavior state
    pub async fn receive(
        &self,
        state: &SessionWorker,
        msg: WorkerTask,
        ctx: &ActorContext<SessionWorker>,
    ) -> Result<Option<Self>, WorkerError> {
        match (self, msg) {
            (WorkerBehavior::NotConnected, WorkerTask::Negotiate) => {
                prepare_negotiation_configuration(state, ctx).await
            }
            (WorkerBehavior::Negotiating(headers), WorkerTask::Negotiate) => {
                negotiate_connection(headers, state, ctx).await
            }
            (WorkerBehavior::SessionActive(config), WorkerTask::PublishRecord(data)) => {
                publish_record(config, data, state, ctx).await
            }
            (WorkerBehavior::SessionActive(config), WorkerTask::ResumeRecord(data, resume_info)) => {
                resume_record(config, data, resume_info, state, ctx).await
            }
            // received an unsupported message for the current behavior
            (b, m) => {
                trace!("unsupported message: {m:?} for current behavior: {b:?}");
                if let WorkerTask::PublishRecord(r) | WorkerTask::ResumeRecord(r, _) = m {
                    let _ = state.group.tell(WorkResult::FailRetry(ctx.aref(), r.nonce)).await;
                }
                continue_behavior!()
            }
        }
    }
}

type WorkerBehaviorResult = Result<Option<WorkerBehavior>, WorkerError>;

/// Initialize configuration needed during negotiation
async fn prepare_negotiation_configuration(
    state: &SessionWorker,
    ctx: &ActorContext<SessionWorker>,
) -> WorkerBehaviorResult {
    let (headers, _) = InitMessageBuilder::new(
        state.config.publisher_id,
        CompressionList::default(),
        DigestAlgorithmList {
            algorithms: state.config.digest_algorithms.clone(),
        },
        DigestChallengeList {
            challenges: state.config.digest_challenges.clone(),
        },
        state.rec_type.into(),
        state.token.mode().into(),
    )
    .build()?;
    let _ = ctx.tell(AttemptNegotiate).await;
    change_behavior!(WorkerBehavior::Negotiating(headers))
}

/// Negotiate connection behavior
async fn negotiate_connection(
    headers: &HeaderMap,
    state: &SessionWorker,
    ctx: &ActorContext<SessionWorker>,
) -> WorkerBehaviorResult {
    match state.client.post(state.config.endpoint.clone()).headers(headers.clone()).send().await {
        Ok(response) => {
            let init_ack_message: InitAckMessage = match peek_message_type(&response) {
                Ok(JalopMessageType::InitAck) => response.try_into()?,
                Ok(JalopMessageType::InitNack) => Err(WorkerError::NegotiationNack)?,
                Ok(other) => Err(JalopError::UnexpectedResponseType(other.to_string()))?,
                Err(e) => Err(e)?,
            };

            info!(
                "connected to subscriber session {} {} @ {}",
                state.token, state.rec_type, state.config.endpoint
            );

            // signal to the group that a new session has been acquired
            let _ = state.group.tell(SessionMsg::SessionAcquired(ctx.aref(), init_ack_message.resume)).await;
            change_behavior!(WorkerBehavior::SessionActive(SessionConfig {
                session_id: init_ack_message.session_id,
                digest_algorithm: init_ack_message.digest,
                digest_challenge: init_ack_message.digest_challenge,
            }))
        }
        Err(_) => continue_behavior!(),
    }
}

/// Publish record behavior
async fn publish_record(
    config: &SessionConfig,
    data: RecordData,
    state: &SessionWorker,
    ctx: &ActorContext<SessionWorker>,
) -> WorkerBehaviorResult {
    debug!("Sending {} Record with id: {}...", state.rec_type, data.nonce);

    let _ = send_record(config, data, None, state, ctx).await?;

    continue_behavior!()
}

/// Publish a resumed record behavior
async fn resume_record(
    config: &SessionConfig,
    data: RecordData,
    resume_info: ResumeInfo,
    state: &SessionWorker,
    ctx: &ActorContext<SessionWorker>,
) -> WorkerBehaviorResult {
    debug!(
        "Sending {} Resumed Record with id: {} at offset {}...",
        state.rec_type, data.nonce, resume_info.offset
    );

    let _ = send_record(config, data, Some(resume_info), state, ctx).await?;

    // the worker does not have a separate behavior for resuming,
    // it considers a resume to be publish behavior on a different control path
    continue_behavior!()
}

// Common functionality for sending, shared by publisher and resume
async fn send_record(
    config: &SessionConfig,
    data: RecordData,
    resume_info: Option<ResumeInfo>,
    state: &SessionWorker,
    ctx: &ActorContext<SessionWorker>,
) -> WorkerBehaviorResult {
    let payload = match (data.payload, data.file) {
        (None, Some(file)) => Payload::File {
            file,
            length: data.payload_len,
        },
        (Some(payload_data), None) => Payload::Memory {
            data: payload_data,
            length: data.payload_len,
        },
        _ => Err(JalopError::InvalidPayload)?,
    };
    let digest_handler = Arc::new(Mutex::new(DigestHandler::new(
        config.digest_algorithm,
        config.digest_challenge,
    )));
    let (headers, body) = RecordMessageBuilder::build(
        state.rec_type.into(),
        config.session_id.clone(),
        data.nonce.to_string(),
        data.sys_meta,
        data.app_meta,
        payload,
        None,
        // clone the arc so the streams can update the hash but we can finalize it later
        Arc::clone(&digest_handler),
        resume_info,
    )?;

    let response = state.client.post(state.config.endpoint.clone()).headers(headers).body(body).send().await?;

    // If digest challenge is not enabled, skip the step where we expect the digest challenge
    let response = if DigestChallenge::On == config.digest_challenge {
        // Wait until after the .await to finalize the digest so we know we're done sending
        let pub_digest = digest_handler.lock().unwrap_or_else(|e| e.into_inner()).finalize_reset();

        let digest_challenge: DigestChallengeMessage = match peek_message_type(&response) {
            Ok(JalopMessageType::DigestChallenge) => response.try_into()?,
            Ok(other) => Err(JalopError::UnexpectedResponseType(other.to_string()))?,
            Err(e) => Err(e)?,
        };

        debug!(
            "Received Digest Challenge: jal-id: {}, digest: {}",
            digest_challenge.jal_id, digest_challenge.digest
        );
        if pub_digest != digest_challenge.digest {
            Err(JalopError::DigestMismatch(pub_digest, digest_challenge.digest))?;
        }

        let (headers, body) = DigestChallengeResponseMessageBuilder::new(
            config.session_id.clone(),
            digest_challenge.jal_id,
            DigestChallengeStatus::Confirmed,
        )
        .build()?;

        debug!("Sending Digest Challenge Response...");
        state.client.post(state.config.endpoint.clone()).headers(headers).body(body).send().await?
    } else {
        response
    };

    match peek_message_type(&response) {
        Ok(JalopMessageType::Sync) => {
            let sync: SyncMessage = response.try_into()?;
            debug!("Received Sync: jal-id: {}", sync.jal_id);
            let _ = state.group.tell(WorkResult::Done(ctx.aref(), data.nonce)).await;
        }
        Ok(JalopMessageType::RecordFailure) => {
            let record_failure: RecordFailureMessage = response.try_into()?;
            debug!(
                "Recieved RecordFailure: jald-id {}, {:?}",
                record_failure.jal_id, record_failure.reasons
            );
            let _ = state.group.tell(WorkResult::FailNoRetry(ctx.aref(), data.nonce)).await;
        }
        Ok(JalopMessageType::SessionFailure) => {
            let session_failure: SessionFailureMessage = response.try_into()?;
            debug!(
                "Recieved SessionFailure: jald-id {}, {:?}",
                session_failure.jal_id, session_failure.reasons
            );
            let _ = state.group.tell(WorkResult::FailRetry(ctx.aref(), data.nonce)).await;
        }
        Ok(other) => Err(JalopError::UnexpectedResponseType(other.to_string()))?,
        Err(e) => Err(e)?,
    };

    continue_behavior!()
}
