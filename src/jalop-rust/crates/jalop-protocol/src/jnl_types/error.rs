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

//! This module provides JNL related error types.
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum JalopError {
    #[error("Unable to insert HttpHeader into HeaderMap")]
    InvalidKey,
    #[error("Http Status Code: {0}")]
    HttpError(u16),
    #[error("Message missing expected header: {0}")]
    MissingResponseHeader(String),
    #[error("Header {0} contains non-ascii characters")]
    HeaderNotAscii(String),
    #[error("Resume Missing Id")]
    MissingResumeId,
    #[error("Resume Missing Offset")]
    MissingResumeOffset,
    #[error("Conversion of received resume offset header {0} to u64 failed")]
    ResumeOffsetNotUnsigned(String),
    #[error("Unable to construct valid Publisher uuid from: {0}")]
    InvalidPublisherId(String),
    #[error("Unable to construct valid Session uuid from: {0}")]
    InvalidSessionId(String),
    #[error("Unable to construct valid Compression from: {0}")]
    InvalidCompression(String),
    #[error("Unable to construct valid DigestAlgorithm from: {0}")]
    InvalidDigestAlgorithm(String),
    #[error("Unable to construct valid DigestChallenge from: {0}")]
    InvalidDigestChallenge(String),
    #[error("Unable to construct valid DigestChallengeStatus from: {0}")]
    InvalidDigestChallengeStatus(String),
    #[error("Unable to construct valid Message Type from: {0}")]
    InvalidMessageType(String),
    #[error("Unable to construct valid JAL-Error-Message value from: {0}")]
    InvalidNackError(String),
    #[error("Unable to construct valid JAL-Error-Message value from: {0}")]
    InvalidSessionFailureError(String),
    #[error("Unable to construct valid JAL-Error-Message value from: {0}")]
    InvalidRecordFailureError(String),
    #[error("Unable to construct valid JAL-Error-Message value from: {0}")]
    InvalidSyncFailureError(String),
    #[error("Unable to construct valid Priority from: {0}")]
    PriorityNotUnsigned(String),
    #[error("Unable to construct valid Priority from: {0}")]
    PriorityOutOfRange(String),
    #[error("Unexpected MessageType value: {0}")]
    UnexpectedMessageType(String),
    #[error("Unable to construct valid Jalop Version from: {0}")]
    InvalidJalVersion(String),

    #[error("Unexpected Response Type: {0}")]
    UnexpectedResponseType(String),
    #[error("Failed to take ownership of payload file descriptor")]
    BadFd,
    #[error("Digest Challenge Failure: Expected: {0}, Received: {1}.")]
    DigestMismatch(String, String),
    #[error("Internal Logic Error: Unable to acquire digest mutex")]
    DigestMutexFailure,
    #[error("Failed to seek in resume payload file")]
    ResumeSeekFailure,
    #[error("Failed to read from resume payload file")]
    ResumeReadFailure,
    #[error("Failed to lock digest handler while fast-forwarding resumed payload")]
    ResumeLockFailure,

    #[error("Internal Logic Error: Payload containts illegal combination of fields")]
    InvalidPayload,
}
