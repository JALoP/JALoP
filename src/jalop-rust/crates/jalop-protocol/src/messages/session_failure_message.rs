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

//! This module provides message definition and builder types for session-failure messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{CommonMessageHeader, JalopHeaderName};
use crate::jnl_types::jalop_types::SessionId;
use crate::messages::jalop_message_type::JalopMessageType;
use crate::messages::jalop_messages::extract_header;
use reqwest::header::HeaderMap;
use reqwest::{Body, Response};
use std::fmt;
use std::str::FromStr;

const JAL_UNSUPPORTED_SESSION_ID: &str = "JAL-Unsupported-Session-Id";

#[derive(Debug)]
pub enum SessionFailureReason {
    UnsupportedSessionId,
}

impl fmt::Display for SessionFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SessionFailureReason::UnsupportedSessionId => write!(f, "{JAL_UNSUPPORTED_SESSION_ID}"),
        }
    }
}

impl FromStr for SessionFailureReason {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<SessionFailureReason, JalopError> {
        // Note: reqwest normalizes incoming headers to lowercase
        match value {
            JAL_UNSUPPORTED_SESSION_ID => Ok(SessionFailureReason::UnsupportedSessionId),
            _ => Err(JalopError::InvalidSessionFailureError(value.to_string())),
        }
    }
}

#[derive(Debug)]
pub struct SessionFailureReasons {
    pub reasons: Vec<SessionFailureReason>,
}

impl FromStr for SessionFailureReasons {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<SessionFailureReasons, JalopError> {
        // The Jal-Error-Message is one or more pipe-separated values indicating why
        // the session cannot be established.
        // Split the string on |, and discard leading/trailing whitespace
        let mut reasons: Vec<SessionFailureReason> = Vec::new();
        for reason_str in value.split("|") {
            reasons.push(reason_str.trim().parse::<SessionFailureReason>()?);
        }
        Ok(SessionFailureReasons { reasons })
    }
}

pub enum SessionFailureMessageHeader {
    SessionId,
    JalId,
    ErrorMessage,
}

impl JalopHeaderName for SessionFailureMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            SessionFailureMessageHeader::SessionId => "jal-session-id",
            SessionFailureMessageHeader::JalId => "jal-id",
            SessionFailureMessageHeader::ErrorMessage => "jal-error-message",
        }
    }
}

pub struct SessionFailureMessage {
    pub session_id: SessionId,
    pub jal_id: String,
    pub reasons: SessionFailureReasons,
}

impl TryFrom<Response> for SessionFailureMessage {
    type Error = JalopError;

    fn try_from(response: Response) -> Result<SessionFailureMessage, JalopError> {
        let message_type: JalopMessageType =
            extract_header(response.headers(), CommonMessageHeader::MessageType)?.parse()?;
        if JalopMessageType::SessionFailure != message_type {
            return Err(JalopError::UnexpectedMessageType(message_type.to_string()));
        }
        let session_id: SessionId =
            extract_header(response.headers(), SessionFailureMessageHeader::SessionId)?.parse()?;
        let jal_id: String = extract_header(response.headers(), SessionFailureMessageHeader::JalId)?;
        let reasons: SessionFailureReasons =
            extract_header(response.headers(), SessionFailureMessageHeader::ErrorMessage)?.parse()?;

        Ok(SessionFailureMessage {
            session_id,
            jal_id,
            reasons,
        })
    }
}

pub struct SessionFailureMessageBuilder {
    _session_id: SessionId,
    _jal_id: String,
    _reasons: SessionFailureReasons,
}

impl SessionFailureMessageBuilder {
    pub fn new(session_id: SessionId, jal_id: String, reasons: SessionFailureReasons) -> SessionFailureMessageBuilder {
        SessionFailureMessageBuilder {
            _session_id: session_id,
            _jal_id: jal_id,
            _reasons: reasons,
        }
    }

    pub fn build(self) -> Result<(HeaderMap, Body), JalopError> {
        todo!("used by subscriber");
    }
}
