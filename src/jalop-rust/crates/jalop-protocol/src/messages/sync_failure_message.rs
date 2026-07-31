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

//! This module provides message definition and builder types for sync-failure messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{CommonMessageHeader, JalopHeaderName};
use crate::messages::jalop_message_type::JalopMessageType;
use crate::messages::jalop_messages::extract_header;
use reqwest::Response;
use std::fmt;
use std::str::FromStr;

const JAL_SYNC_FAILURE: &str = "JAL-Sync-Failure";

#[derive(Debug)]
pub enum SyncFailureReason {
    SyncFailure,
}

impl fmt::Display for SyncFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SyncFailureReason::SyncFailure => write!(f, "{JAL_SYNC_FAILURE}"),
        }
    }
}

#[derive(Debug)]
pub struct SyncFailureReasons {
    pub reasons: Vec<SyncFailureReason>,
}

impl FromStr for SyncFailureReason {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<SyncFailureReason, JalopError> {
        // Note: reqwest normalizes incoming headers to lowercase
        match value {
            JAL_SYNC_FAILURE => Ok(SyncFailureReason::SyncFailure),
            _ => Err(JalopError::InvalidSyncFailureError(value.to_string())),
        }
    }
}

impl FromStr for SyncFailureReasons {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<SyncFailureReasons, JalopError> {
        // The Jal-Error-Message is one or more pipe-separated values indicating why
        // the sync failed.
        // Split the string on |, and discard leading/trailing whitespace
        let mut reasons: Vec<SyncFailureReason> = Vec::new();
        for reason_str in value.split("|") {
            reasons.push(reason_str.trim().parse::<SyncFailureReason>()?);
        }
        Ok(SyncFailureReasons { reasons })
    }
}

pub enum SyncFailureMessageHeader {
    JalId,
    JalErrorMessage,
}

impl JalopHeaderName for SyncFailureMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            SyncFailureMessageHeader::JalId => "jal-id",
            SyncFailureMessageHeader::JalErrorMessage => "jal-error-message",
        }
    }
}

pub struct SyncFailureMessage {
    pub jal_id: String,
    pub reasons: SyncFailureReasons,
}

// Used by Publisher
impl TryFrom<Response> for SyncFailureMessage {
    type Error = JalopError;

    fn try_from(response: Response) -> Result<SyncFailureMessage, JalopError> {
        let message_type: JalopMessageType =
            extract_header(response.headers(), CommonMessageHeader::MessageType)?.parse()?;
        if JalopMessageType::SyncFailure != message_type {
            return Err(JalopError::UnexpectedMessageType(message_type.to_string()));
        }
        let jal_id: String = extract_header(response.headers(), SyncFailureMessageHeader::JalId)?;
        let reasons: SyncFailureReasons =
            extract_header(response.headers(), SyncFailureMessageHeader::JalErrorMessage)?.parse()?;

        Ok(SyncFailureMessage { jal_id, reasons })
    }
}
