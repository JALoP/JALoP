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

//! This module provides message definition and builder types for session init messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{CommonMessageHeader, CommonMessageValue, JalopHeaderName};
use crate::jnl_types::jal_version::JalVersion;
use crate::jnl_types::jalop_types::{
    CompressionList, DigestAlgorithmList, DigestChallengeList, PublisherId, RecordType, SessionMode,
};
use crate::messages::jalop_message_type::JalopMessageType;
use crate::messages::jalop_messages::add_header;
use reqwest::header::HeaderMap;
use reqwest::{Body, Response};

pub enum InitMessageHeader {
    PublisherId,
    Version,
    // jalop doesn't yet support xml compression
    _AcceptXmlCompression,
    AcceptDigest,
    AcceptConfigureDigestChallenge,
    RecordType,
    Mode,
}

impl JalopHeaderName for InitMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            InitMessageHeader::PublisherId => "jal-publisher-id",
            InitMessageHeader::Version => "jal-version",
            InitMessageHeader::_AcceptXmlCompression => "jal-accept-xml-compression",
            InitMessageHeader::AcceptDigest => "jal-accept-digest",
            InitMessageHeader::AcceptConfigureDigestChallenge => "jal-accept-configure-digest-challenge",
            InitMessageHeader::RecordType => "jal-record-type",
            InitMessageHeader::Mode => "jal-mode",
        }
    }
}

pub struct InitMessage {
    pub publisher_id: PublisherId,
    pub version: JalVersion,
    pub accepted_xml_xompressions: CompressionList,
    pub accepted_digest_algorithms: DigestAlgorithmList,
    pub accepted_digest_challenges: DigestChallengeList,
    pub record_type: RecordType,
    pub session_mode: SessionMode,
}

impl TryFrom<Response> for InitMessage {
    type Error = JalopError;

    fn try_from(_response: Response) -> Result<InitMessage, JalopError> {
        todo!("used by subscriber");
    }
}

// Used by Publisher
pub struct InitMessageBuilder {
    publisher_id: PublisherId,
    // Compression is currently not supported by JALoP
    _accepted_xml_compressions: CompressionList,
    accepted_digest_algorithms: DigestAlgorithmList,
    accepted_digest_challenges: DigestChallengeList,
    record_type: RecordType,
    session_mode: SessionMode,
}

impl InitMessageBuilder {
    pub fn new(
        publisher_id: PublisherId,
        _accepted_xml_compressions: CompressionList,
        accepted_digest_algorithms: DigestAlgorithmList,
        accepted_digest_challenges: DigestChallengeList,
        record_type: RecordType,
        session_mode: SessionMode,
    ) -> InitMessageBuilder {
        InitMessageBuilder {
            publisher_id,
            _accepted_xml_compressions,
            accepted_digest_algorithms,
            accepted_digest_challenges,
            record_type,
            session_mode,
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
        add_header(&mut headers, CommonMessageHeader::MessageType, JalopMessageType::Init)?;

        add_header(&mut headers, InitMessageHeader::PublisherId, self.publisher_id)?;
        // Compression is currently not supported by JALoP
        //add_header(&mut headers, InitMessageHeader::AcceptCompression,
        //    self.accepted_xml_compressions)?;
        add_header(&mut headers, InitMessageHeader::Version, JalVersion::V2_0_0_0)?;
        add_header(&mut headers, InitMessageHeader::RecordType, self.record_type)?;
        add_header(&mut headers, InitMessageHeader::Mode, self.session_mode)?;
        add_header(
            &mut headers,
            InitMessageHeader::AcceptConfigureDigestChallenge,
            self.accepted_digest_challenges,
        )?;
        add_header(
            &mut headers,
            InitMessageHeader::AcceptDigest,
            self.accepted_digest_algorithms,
        )?;
        Ok((headers, Body::from(String::new())))
    }
}
