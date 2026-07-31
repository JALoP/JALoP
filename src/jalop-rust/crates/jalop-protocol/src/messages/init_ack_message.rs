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

//! This module provides message definition and builder types for session init-ack messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{CommonMessageHeader, JalopHeaderName};
use crate::jnl_types::jalop_types::{Compression, DigestAlgorithm, DigestChallenge, SessionId};
use crate::messages::jalop_message_type::JalopMessageType;
use crate::messages::jalop_messages::{extract_header, extract_optional_header};
use reqwest::header::HeaderMap;
use reqwest::{Body, Response};

#[derive(Clone, Debug)]
pub struct ResumeInfo {
    pub id: String,
    pub offset: u64,
}

pub enum InitAckMessageHeader {
    SessionId,
    XmlCompression,
    Digest,
    ConfigureDigestChallenge,
    JalId,
    JournalOffset,
}

impl JalopHeaderName for InitAckMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            InitAckMessageHeader::SessionId => "jal-session-id",
            InitAckMessageHeader::XmlCompression => "jal-xml-compression",
            InitAckMessageHeader::Digest => "jal-digest",
            InitAckMessageHeader::ConfigureDigestChallenge => "jal-configure-digest-challenge",
            InitAckMessageHeader::JalId => "jal-id",
            InitAckMessageHeader::JournalOffset => "jal-journal-offset",
        }
    }
}

pub struct InitAckMessage {
    pub session_id: SessionId,
    pub compression: Compression,
    pub digest: DigestAlgorithm,
    pub digest_challenge: DigestChallenge,
    pub resume: Option<ResumeInfo>,
}

// Used by publisher
impl TryFrom<Response> for InitAckMessage {
    type Error = JalopError;

    fn try_from(response: Response) -> Result<InitAckMessage, JalopError> {
        let message_type: JalopMessageType =
            extract_header(response.headers(), CommonMessageHeader::MessageType)?.parse()?;
        if JalopMessageType::InitAck != message_type {
            return Err(JalopError::UnexpectedMessageType(message_type.to_string()));
        }
        let session_id: SessionId = extract_header(response.headers(), InitAckMessageHeader::SessionId)?.parse()?;
        let compression: Compression =
            extract_header(response.headers(), InitAckMessageHeader::XmlCompression)?.parse()?;
        let digest: DigestAlgorithm = extract_header(response.headers(), InitAckMessageHeader::Digest)?.parse()?;
        let digest_challenge: DigestChallenge =
            extract_header(response.headers(), InitAckMessageHeader::ConfigureDigestChallenge)?.parse()?;
        let resume_id = extract_optional_header(response.headers(), InitAckMessageHeader::JalId)?;
        let resume_offset = extract_optional_header(response.headers(), InitAckMessageHeader::JournalOffset)?;
        let resume_offset = match resume_offset {
            Some(offset_str) => {
                let Ok(offset_u64) = offset_str.parse::<u64>() else {
                    return Err(JalopError::ResumeOffsetNotUnsigned(offset_str));
                };
                Some(offset_u64)
            }
            None => None,
        };

        let resume = match (resume_id, resume_offset) {
            (None, None) => None,
            (Some(id), Some(offset)) => Some(ResumeInfo { id, offset }),
            (Some(_), None) => {
                return Err(JalopError::MissingResumeOffset);
            }
            (None, Some(_)) => {
                return Err(JalopError::MissingResumeId);
            }
        };
        Ok(InitAckMessage {
            session_id,
            compression,
            digest,
            digest_challenge,
            resume,
        })
    }
}

pub struct InitAckMessageBuilder {
    _session_id: SessionId,
    _compression: Compression,
    _digest: DigestAlgorithm,
    _digest_challenge: DigestChallenge,
    _resume: Option<ResumeInfo>,
}

impl InitAckMessageBuilder {
    pub fn new(
        _session_id: SessionId,
        _compression: Compression,
        _digest: DigestAlgorithm,
        _digest_challenge: DigestChallenge,
        _resume: Option<ResumeInfo>,
    ) -> InitAckMessageBuilder {
        InitAckMessageBuilder {
            _session_id,
            _compression,
            _digest,
            _digest_challenge,
            _resume,
        }
    }

    pub fn build(self) -> Result<(HeaderMap, Body), JalopError> {
        todo!("used by subscriber");
    }
}
