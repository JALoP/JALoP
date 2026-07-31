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

//! This module provides message definition and builder types for journal-missing messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{CommonMessageHeader, CommonMessageValue, JalopHeaderName};
use crate::jnl_types::jalop_types::SessionId;
use crate::messages::jalop_message_type::JalopMessageType;
use crate::messages::jalop_messages::{add_header, extract_header};
use crate::messages::record_message::RecordMessageHeader;
use reqwest::header::HeaderMap;
use reqwest::{Body, Response};

pub enum JournalMissingMessageHeader {
    JalSessionId,
    JalId,
}

impl JalopHeaderName for JournalMissingMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            JournalMissingMessageHeader::JalSessionId => "jal-session-id",
            JournalMissingMessageHeader::JalId => "jal-id",
        }
    }
}

pub struct JournalMissingMessage {
    pub session_id: SessionId,
    pub jal_id: String,
}

// Used by publisher
impl TryFrom<Response> for JournalMissingMessage {
    type Error = JalopError;

    fn try_from(response: Response) -> Result<JournalMissingMessage, JalopError> {
        let message_type: JalopMessageType =
            extract_header(response.headers(), CommonMessageHeader::MessageType)?.parse()?;
        if JalopMessageType::JournalMissing != message_type {
            return Err(JalopError::UnexpectedMessageType(message_type.to_string()));
        }
        let session_id: SessionId =
            extract_header(response.headers(), JournalMissingMessageHeader::JalSessionId)?.parse()?;
        let jal_id = extract_header(response.headers(), JournalMissingMessageHeader::JalId)?;
        Ok(JournalMissingMessage { session_id, jal_id })
    }
}

pub struct JournalMissingMessageBuilder {
    session_id: SessionId,
    jal_id: String,
}

impl JournalMissingMessageBuilder {
    pub fn new(session_id: SessionId, jal_id: String) -> JournalMissingMessageBuilder {
        JournalMissingMessageBuilder { session_id, jal_id }
    }

    pub fn build(self) -> Result<(HeaderMap, Body), JalopError> {
        let mut headers: HeaderMap = HeaderMap::new();
        add_header(
            &mut headers,
            CommonMessageHeader::ContentType,
            CommonMessageValue::ContentType,
        )?;
        add_header(&mut headers, CommonMessageHeader::ContentLength, 0_u64)?;
        add_header(
            &mut headers,
            CommonMessageHeader::MessageType,
            JalopMessageType::JournalMissing,
        )?;
        add_header(&mut headers, RecordMessageHeader::SessionId, self.session_id)?;
        add_header(&mut headers, RecordMessageHeader::JalId, self.jal_id)?;
        Ok((headers, Body::from(String::new())))
    }
}
