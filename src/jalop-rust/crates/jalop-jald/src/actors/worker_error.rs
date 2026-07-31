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
//! This module provides an error implementation specific to [SessionWorker] actors
use jalop_protocol::jnl_types::error::JalopError;
use thiserror::Error;

/// Errors that can occur within a [SessionWorker] actor
/// This error type has a [ReactionKind] attached that indicates what type of recovery should occur
#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("Timeout while negotiating")]
    NegotiationTimeout,

    #[error("Nack while negotiating")]
    NegotiationNack,

    #[error(transparent)]
    JalopError(#[from] JalopError),

    #[error(transparent)]
    HttpError(#[from] reqwest::Error),
}

impl WorkerError {
    pub fn severity_kind(&self) -> ReactionKind {
        match self {
            Self::NegotiationTimeout => ReactionKind::Reconnect,
            Self::NegotiationNack => ReactionKind::Reconnect,
            Self::HttpError(_) => ReactionKind::Reconnect,
            Self::JalopError(t) => match t {
                // A note about ReactionKind
                // Reconnect: instructs the worker to end the current session and attempt
                // to init a new session
                // RecordFailNoRetry: abandons the attempt to send the current record
                // and leaves the record marked as "sent" so it will not be attempted
                // again until the entire session group is restarted (i.e. the filter stream
                // is stopped and started, clearing the sent status from all records).
                // RecordFailRetry: abandons the attempt to send the current record
                // but marks the record as unsent so this worker or another worker
                // may retry the record.
                // Ignore: ???
                // By default Ignore will leave the record as Sent, which is like a
                // RecordFailNoRetry, but may not inform the filter the record has
                // been processed compeltely. See todo in session_worker.rs

                // InvalidKey is an internal logic error. An outgoing message is being
                // constructed an the header value couldn't be converted to string form
                JalopError::InvalidKey => ReactionKind::Reconnect,

                // HttpError wraps errors from the reqwest library and imply a network
                // failure of some kind.
                JalopError::HttpError(_) => ReactionKind::Reconnect,

                // MissingResponseHeader implies the Subscriber generated a response
                // which is missing a required header
                JalopError::MissingResponseHeader(_) => ReactionKind::Reconnect,

                // HeaderNotAscii implies an incoming header could not be converted
                // to a string representation. This probably indicates gargabe in a header
                // value from the subscriber or a reqwest error
                JalopError::HeaderNotAscii(_) => ReactionKind::Reconnect,

                // MissingResume* The Resume headers are optional per the spec, but
                // if one is present they must both be present. These errors imply
                // we have one but not the other, which is a protocol violation
                JalopError::MissingResumeId => ReactionKind::Reconnect,
                JalopError::MissingResumeOffset => ReactionKind::Reconnect,

                // ResumeOffsetNotUnsigned implies the header value for the resume
                // offset couldn't be converted to an unsigned numberic type, which
                // is a protocol violation
                JalopError::ResumeOffsetNotUnsigned(_) => ReactionKind::Reconnect,

                // Invalid* implies that a conversion to or from string form for
                // a bounded type failed.
                JalopError::InvalidPublisherId(_) => ReactionKind::Reconnect,
                JalopError::InvalidSessionId(_) => ReactionKind::Reconnect,
                JalopError::InvalidCompression(_) => ReactionKind::Reconnect,
                JalopError::InvalidDigestAlgorithm(_) => ReactionKind::Reconnect,
                JalopError::InvalidDigestChallenge(_) => ReactionKind::Reconnect,
                JalopError::InvalidDigestChallengeStatus(_) => ReactionKind::Reconnect,
                JalopError::InvalidMessageType(_) => ReactionKind::Reconnect,

                // Invalid*Error implies that the value of the JAL-Error-Message
                // header was not a valid failure reason
                // todo; maybe consolidate these to a single error type?
                JalopError::InvalidNackError(_) => ReactionKind::Reconnect,
                JalopError::InvalidSyncFailureError(_) => ReactionKind::Reconnect,
                JalopError::InvalidSessionFailureError(_) => ReactionKind::Reconnect,
                JalopError::InvalidRecordFailureError(_) => ReactionKind::Reconnect,

                // Priority* implies that the priority value was not unsigned or
                // not numeric
                JalopError::PriorityNotUnsigned(_) => ReactionKind::Reconnect,
                JalopError::PriorityOutOfRange(_) => ReactionKind::Reconnect,

                // UnexpectMessageType implies that when attempting to construct a message
                // from a reqwest response, the JAL-Message header did not match the expected
                // message kind
                JalopError::UnexpectedMessageType(_) => ReactionKind::Reconnect,

                // InvalidJalVersion implies that the JalVersion was not a valid value
                JalopError::InvalidJalVersion(_) => ReactionKind::Reconnect,

                // UnexpectedResponseType implies that the response received was not one
                // of the valid responses that were expected. This indicates a protocol
                // violation
                JalopError::UnexpectedResponseType(_) => ReactionKind::Reconnect,

                // BadFd indicates the fd provided by the filter could not be opened
                // or read succesfully
                JalopError::BadFd => ReactionKind::RecordFailNoRetry,

                // DigestMismatch indicates that the digest calculated by the subscriber
                // and the digest calculated locally do not match
                JalopError::DigestMismatch(_, _) => ReactionKind::RecordFailNoRetry,

                // DigestMutexFailure indicates an internal logic failure when handling
                // the mutex on the digest context. This should not happen
                JalopError::DigestMutexFailure => ReactionKind::RecordFailNoRetry,

                // InvalidPayload implies the payload to be sent to the subscriber is not
                // internally consistent. This is an internal logic error
                JalopError::InvalidPayload => ReactionKind::RecordFailNoRetry,

                // Resume*Failure implies there was an error handling the resume payload
                // These are internal logic errors
                // These are marked as recordFailRetry so the record may be sent again
                // normally after the resume fails
                JalopError::ResumeSeekFailure => ReactionKind::RecordFailRetry,
                JalopError::ResumeReadFailure => ReactionKind::RecordFailRetry,
                JalopError::ResumeLockFailure => ReactionKind::RecordFailRetry,
            },
        }
    }
}

/// Defines the reaction a [WorkerError] should invoke from the interested actors
#[derive(Debug, Default)]
pub enum ReactionKind {
    /// Log and ignore the failure
    /// For expected failures like timeout during negotiation polling
    #[default]
    Ignore,
    /// Connection issue with subscriber requiring renegotiating
    /// The worker behavior should become configuring negotiation
    Reconnect,
    /// The connection is stable but the record publish failed and should not be retried
    /// Notify the inline filter via the control socket actor
    RecordFailNoRetry,
    /// The connection is stable but the record publish failed and should be retried
    /// Notify the inline filter via the control socket actor
    RecordFailRetry,
}
