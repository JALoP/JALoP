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

//! This module provides asynchronous stream of decoded messages from a single input socket.
use crate::{Token, TokenId};
use jalop_sys::RecordType;

/// A message sent from JALoP to the filter
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    /// Start a new subscriber stream
    StartStream { token: Token, rtype: RecordType },
    /// Start a new subscriber stream at the resume point
    ResumeStream {
        token: Token,
        rtype: RecordType,
        nonce: String,
    },
    /// Stop an active stream
    StopStream { token: Token, rtype: RecordType },
    /// Indicates that a record completed
    RecordSuccess {
        token: Token,
        rtype: RecordType,
        nonce: String,
    },
    /// Indicates that a record failed for a record-related reason and should not be retried
    RecordErrorNoRetry {
        token: Token,
        rtype: RecordType,
        nonce: String,
    },
    /// Indicates that a record failed for a non-record-related reason and should be retried
    RecordErrorRetry {
        token: Token,
        rtype: RecordType,
        nonce: String,
    },
    /// Indicates a record failure for disconnected subscriber
    UnsubscribedRecordError {
        id: TokenId,
        rtype: RecordType,
        nonce: String,
    },
}

impl Message {
    pub fn start(token: Token, rtype: RecordType) -> Message {
        Message::StartStream { token, rtype }
    }

    pub fn stop(token: Token, rtype: RecordType) -> Message {
        Message::StopStream { token, rtype }
    }

    pub fn resume(token: Token, rtype: RecordType, nonce: &str) -> Message {
        Message::ResumeStream {
            token,
            rtype,
            nonce: nonce.to_string(),
        }
    }

    pub fn success(token: Token, rtype: RecordType, nonce: &str) -> Message {
        Message::RecordSuccess {
            token,
            rtype,
            nonce: nonce.to_string(),
        }
    }

    pub fn error_retry(token: Token, rtype: RecordType, nonce: &str) -> Message {
        Message::RecordErrorRetry {
            token,
            rtype,
            nonce: nonce.to_string(),
        }
    }

    pub fn error_no_retry(token: Token, rtype: RecordType, nonce: &str) -> Message {
        Message::RecordErrorNoRetry {
            token,
            rtype,
            nonce: nonce.to_string(),
        }
    }

    pub fn rtype(&self) -> RecordType {
        match *self {
            Message::StartStream { rtype, .. } => rtype,
            Message::ResumeStream { rtype, .. } => rtype,
            Message::StopStream { rtype, .. } => rtype,
            Message::RecordSuccess { rtype, .. } => rtype,
            Message::RecordErrorRetry { rtype, .. } => rtype,
            Message::RecordErrorNoRetry { rtype, .. } => rtype,
            Message::UnsubscribedRecordError { rtype, .. } => rtype,
        }
    }

    pub fn token_id(&self) -> TokenId {
        match self {
            Message::StartStream { token, .. } => token.id(),
            Message::ResumeStream { token, .. } => token.id(),
            Message::StopStream { token, .. } => token.id(),
            Message::RecordSuccess { token, .. } => token.id(),
            Message::RecordErrorRetry { token, .. } => token.id(),
            Message::RecordErrorNoRetry { token, .. } => token.id(),
            Message::UnsubscribedRecordError { id, .. } => *id,
        }
    }
}
