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

//! This module provides message definition and builder types for session init-nack messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{CommonMessageHeader, JalopHeaderName};
use crate::messages::jalop_message_type::JalopMessageType;
use crate::messages::jalop_messages::extract_header;
use reqwest::header::HeaderMap;
use reqwest::{Body, Response};
use std::fmt;
use std::str::FromStr;

const JAL_UNSUPPORTED_PUBLISHER_ID: &str = "JAL-Unsupported-Publisher-Id";
const JAL_UNSUPPORTED_VERSION: &str = "JAL-Unsupported-Version";
const JAL_UNSUPPORTED_XML_COMPRESSION: &str = "JAL-Unsupported-XML-Compression";
const JAL_UNSUPPORTED_RECORD_TYPE: &str = "JAL-Unsupported-Record-Type";
const JAL_UNSUPPORTED_MODE: &str = "JAL-Unsupported-Mode";
const JAL_UNSUPPORTED_DIGEST: &str = "JAL-Unsupported-Digest";
const JAL_UNSUPPORTED_CONFIGURE_DIGEST_CHALLENGE: &str = "JAL-Unsupported-Configure-Digest-Challenge";

#[derive(Debug)]
pub enum InitNackReason {
    PublisherId,
    Version,
    XmlCompression,
    Digest,
    ConfigureDigestChallenge,
    RecordType,
    Mode,
}

impl fmt::Display for InitNackReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InitNackReason::PublisherId => write!(f, "{JAL_UNSUPPORTED_PUBLISHER_ID}"),
            InitNackReason::Version => write!(f, "{JAL_UNSUPPORTED_VERSION}"),
            InitNackReason::XmlCompression => write!(f, "{JAL_UNSUPPORTED_XML_COMPRESSION}"),
            InitNackReason::Digest => write!(f, "{JAL_UNSUPPORTED_DIGEST}"),
            InitNackReason::ConfigureDigestChallenge => {
                write!(f, "{JAL_UNSUPPORTED_CONFIGURE_DIGEST_CHALLENGE}")
            }
            InitNackReason::RecordType => write!(f, "{JAL_UNSUPPORTED_RECORD_TYPE}"),
            InitNackReason::Mode => write!(f, "{JAL_UNSUPPORTED_MODE}"),
        }
    }
}

impl FromStr for InitNackReason {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<InitNackReason, JalopError> {
        // Note: reqwest normalizes incoming headers to lowercase
        match value {
            JAL_UNSUPPORTED_PUBLISHER_ID => Ok(InitNackReason::PublisherId),
            JAL_UNSUPPORTED_VERSION => Ok(InitNackReason::Version),
            JAL_UNSUPPORTED_XML_COMPRESSION => Ok(InitNackReason::XmlCompression),
            JAL_UNSUPPORTED_DIGEST => Ok(InitNackReason::Digest),
            JAL_UNSUPPORTED_CONFIGURE_DIGEST_CHALLENGE => Ok(InitNackReason::ConfigureDigestChallenge),
            JAL_UNSUPPORTED_RECORD_TYPE => Ok(InitNackReason::Digest),
            JAL_UNSUPPORTED_MODE => Ok(InitNackReason::Mode),
            _ => Err(JalopError::InvalidNackError(value.to_string())),
        }
    }
}

#[derive(Debug)]
pub struct InitNackReasons {
    pub reasons: Vec<InitNackReason>,
}

impl FromStr for InitNackReasons {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<InitNackReasons, JalopError> {
        // The Jal-Error-Message is one or more pipe-separated values indicating why
        // the session cannot be established.
        // Split the string on |, and discard leading/trailing whitespace
        let mut reasons: Vec<InitNackReason> = Vec::new();
        for reason_str in value.split("|") {
            reasons.push(reason_str.trim().parse::<InitNackReason>()?);
        }
        Ok(InitNackReasons { reasons })
    }
}

pub enum InitNackMessageHeader {
    JalErrorMessage,
}

impl JalopHeaderName for InitNackMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            InitNackMessageHeader::JalErrorMessage => "jal-error-message",
        }
    }
}

pub struct InitNackMessage {
    pub reasons: InitNackReasons,
}

// Used by Publisher
impl TryFrom<Response> for InitNackMessage {
    type Error = JalopError;

    fn try_from(response: Response) -> Result<InitNackMessage, JalopError> {
        let message_type: JalopMessageType =
            extract_header(response.headers(), CommonMessageHeader::MessageType)?.parse()?;
        if JalopMessageType::InitNack != message_type {
            return Err(JalopError::UnexpectedMessageType(message_type.to_string()));
        }
        let reasons: InitNackReasons =
            extract_header(response.headers(), InitNackMessageHeader::JalErrorMessage)?.parse()?;

        Ok(InitNackMessage { reasons })
    }
}

pub struct InitNackMessageBuilder {
    _reasons: InitNackReasons,
}

impl InitNackMessageBuilder {
    pub fn new(reasons: InitNackReasons) -> InitNackMessageBuilder {
        InitNackMessageBuilder { _reasons: reasons }
    }

    pub fn build(self) -> Result<(HeaderMap, Body), JalopError> {
        todo!("used by subscriber");
    }
}
