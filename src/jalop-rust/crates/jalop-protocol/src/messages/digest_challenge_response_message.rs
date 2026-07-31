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

//! This module provides message definition and builder types for digest challenge response messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{CommonMessageHeader, CommonMessageValue, JalopHeaderName};
use crate::jnl_types::jalop_types::{DigestChallengeStatus, SessionId};
use crate::messages::jalop_message_type::JalopMessageType;
use crate::messages::jalop_messages::add_header;
use reqwest::header::HeaderMap;
use reqwest::{Body, Response};

pub enum DigestChallengeResponseMessageHeader {
    SessionId,
    JalId,
    DigestStatus,
}

impl JalopHeaderName for DigestChallengeResponseMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            DigestChallengeResponseMessageHeader::SessionId => "jal-session-id",
            DigestChallengeResponseMessageHeader::JalId => "jal-id",
            DigestChallengeResponseMessageHeader::DigestStatus => "jal-digest-status",
        }
    }
}

pub struct DigestChallengeResponseMessage {
    pub session_id: SessionId,
    pub jal_id: String,
    pub digest_challenge_status: DigestChallengeStatus,
}

impl TryFrom<Response> for DigestChallengeResponseMessage {
    type Error = JalopError;

    fn try_from(_response: Response) -> Result<DigestChallengeResponseMessage, JalopError> {
        todo!("used by subscriber");
    }
}

// Used by Publisher
pub struct DigestChallengeResponseMessageBuilder {
    session_id: SessionId,
    jal_id: String,
    digest_challenge_status: DigestChallengeStatus,
}

impl DigestChallengeResponseMessageBuilder {
    pub fn new(
        session_id: SessionId,
        jal_id: String,
        digest_challenge_status: DigestChallengeStatus,
    ) -> DigestChallengeResponseMessageBuilder {
        DigestChallengeResponseMessageBuilder {
            session_id,
            jal_id,
            digest_challenge_status,
        }
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
            JalopMessageType::DigestChallengeResponse,
        )?;

        add_header(
            &mut headers,
            DigestChallengeResponseMessageHeader::SessionId,
            self.session_id,
        )?;
        add_header(&mut headers, DigestChallengeResponseMessageHeader::JalId, self.jal_id)?;
        add_header(
            &mut headers,
            DigestChallengeResponseMessageHeader::DigestStatus,
            self.digest_challenge_status,
        )?;
        Ok((headers, Body::from(String::new())))
    }
}
