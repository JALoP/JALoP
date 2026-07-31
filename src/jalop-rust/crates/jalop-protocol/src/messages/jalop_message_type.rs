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

//! This module provides common types for JALoP messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{CommonMessageHeader, JalopHeaderValue};
use crate::messages::jalop_messages::extract_header;
use reqwest::Response;
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

// Publisher to Subscriber
const INIT: &str = "initialize";
const LOG: &str = "log-record";
const AUDIT: &str = "audit-record";
const JOURNAL: &str = "journal-record";
const JOURNAL_MISSING: &str = "journal-missing";
const DIGEST_CHALLENGE_RESPONSE: &str = "digest-response";
const CLOSE_SESSION: &str = "close-session";

// Subscriber to Publisher
const INIT_ACK: &str = "initialize-ack";
const INIT_NACK: &str = "initialize-nack";
const SESSION_FAILURE: &str = "session-failure";
const RECORD_FAILURE: &str = "record-failure";
const JOURNAL_MISSING_RESPONSE: &str = "journal-missing-response";
const DIGEST_CHALLENGE: &str = "digest-challenge";
const SYNC_FAILURE: &str = "sync-failure";
const SYNC: &str = "sync";
const CLOSE_SESSION_RESPONSE: &str = "close-session-response";

#[derive(PartialEq)]
pub enum JalopMessageType {
    // Publisher to Subscriber
    Init,
    Log,
    Audit,
    Journal,
    JournalMissing,
    DigestChallengeResponse,
    CloseSession,
    // Subscriber to Publisher
    InitAck,
    InitNack,
    SessionFailure,
    RecordFailure,
    JournalMissingResponse,
    DigestChallenge,
    SyncFailure,
    Sync,
    CloseSessionResponse,
}

impl JalopHeaderValue for JalopMessageType {
    fn serialize_header_value(&self) -> String {
        match self {
            // Publisher to Subscriber
            JalopMessageType::Init => INIT.to_string(),
            JalopMessageType::Log => LOG.to_string(),
            JalopMessageType::Audit => AUDIT.to_string(),
            JalopMessageType::Journal => JOURNAL.to_string(),
            JalopMessageType::JournalMissing => JOURNAL_MISSING.to_string(),
            JalopMessageType::DigestChallengeResponse => DIGEST_CHALLENGE_RESPONSE.to_string(),
            JalopMessageType::CloseSession => CLOSE_SESSION.to_string(),

            // Subscriber to Publisher
            JalopMessageType::InitAck => INIT_ACK.to_string(),
            JalopMessageType::InitNack => INIT_NACK.to_string(),
            JalopMessageType::SessionFailure => SESSION_FAILURE.to_string(),
            JalopMessageType::RecordFailure => RECORD_FAILURE.to_string(),
            JalopMessageType::JournalMissingResponse => JOURNAL_MISSING_RESPONSE.to_string(),
            JalopMessageType::DigestChallenge => DIGEST_CHALLENGE.to_string(),
            JalopMessageType::SyncFailure => SYNC_FAILURE.to_string(),
            JalopMessageType::Sync => SYNC.to_string(),
            JalopMessageType::CloseSessionResponse => CLOSE_SESSION_RESPONSE.to_string(),
        }
    }
}

impl FromStr for JalopMessageType {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<JalopMessageType, JalopError> {
        match value {
            // Publisher to Subscriber
            INIT => Ok(JalopMessageType::Init),
            LOG => Ok(JalopMessageType::Log),
            AUDIT => Ok(JalopMessageType::Audit),
            JOURNAL => Ok(JalopMessageType::Journal),
            JOURNAL_MISSING => Ok(JalopMessageType::JournalMissing),
            DIGEST_CHALLENGE_RESPONSE => Ok(JalopMessageType::DigestChallengeResponse),
            CLOSE_SESSION => Ok(JalopMessageType::CloseSession),

            // Subscriber to Publisher
            INIT_ACK => Ok(JalopMessageType::InitAck),
            INIT_NACK => Ok(JalopMessageType::InitNack),
            SESSION_FAILURE => Ok(JalopMessageType::SessionFailure),
            RECORD_FAILURE => Ok(JalopMessageType::RecordFailure),
            JOURNAL_MISSING_RESPONSE => Ok(JalopMessageType::JournalMissingResponse),
            DIGEST_CHALLENGE => Ok(JalopMessageType::DigestChallenge),
            SYNC_FAILURE => Ok(JalopMessageType::SyncFailure),
            SYNC => Ok(JalopMessageType::Sync),
            CLOSE_SESSION_RESPONSE => Ok(JalopMessageType::CloseSessionResponse),
            _ => Err(JalopError::InvalidMessageType(value.to_string())),
        }
    }
}

impl Display for JalopMessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.serialize_header_value())
    }
}

pub fn peek_message_type(response: &Response) -> Result<JalopMessageType, JalopError> {
    extract_header(response.headers(), CommonMessageHeader::MessageType)?.parse::<JalopMessageType>()
}
