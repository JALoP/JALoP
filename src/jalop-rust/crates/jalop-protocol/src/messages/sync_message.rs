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

//! This module provides message definition and builder types for sync messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{CommonMessageHeader, JalopHeaderName};
use crate::messages::jalop_message_type::JalopMessageType;
use crate::messages::jalop_messages::extract_header;
use reqwest::header::HeaderMap;
use reqwest::{Body, Response};

pub enum SyncMessageHeader {
    JalId,
}

impl JalopHeaderName for SyncMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            SyncMessageHeader::JalId => "jal-id",
        }
    }
}

pub struct SyncMessage {
    pub jal_id: String,
}

impl TryFrom<Response> for SyncMessage {
    type Error = JalopError;

    fn try_from(response: Response) -> Result<SyncMessage, JalopError> {
        let message_type: JalopMessageType =
            extract_header(response.headers(), CommonMessageHeader::MessageType)?.parse()?;
        if JalopMessageType::Sync != message_type {
            return Err(JalopError::UnexpectedMessageType(message_type.to_string()));
        }
        let jal_id: String = extract_header(response.headers(), SyncMessageHeader::JalId)?;

        Ok(SyncMessage { jal_id })
    }
}

pub struct SyncMessageBuilder {
    _jal_id: String,
}

impl SyncMessageBuilder {
    pub fn new(jal_id: String) -> SyncMessageBuilder {
        SyncMessageBuilder { _jal_id: jal_id }
    }

    pub fn build(self) -> Result<(HeaderMap, Body), JalopError> {
        todo!("used by subscriber");
    }
}
