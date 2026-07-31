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

//! This module provides message definition and builder types for record-failure messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{CommonMessageHeader, JalopHeaderName};
use crate::messages::jalop_message_type::JalopMessageType;
use crate::messages::jalop_messages::extract_header;
use reqwest::header::HeaderMap;
use reqwest::{Body, Response};
use std::fmt;
use std::str::FromStr;

// Record Failure message values
const JAL_INVALID_SYSTEM_METADATA_LENGTH: &str = "JAL-Invalid-System-Metadata-Length";
const JAL_INVALID_APPLICATION_METADATA_LENGTH: &str = "JAL-Invalid-Application-Metadata-Length";
const JAL_INVALID_JOURNAL_LENGTH: &str = "JAL-Invalid-Joural-Length";
const JAL_INVALID_AUDIT_LENGTH: &str = "JAL-Invalid-Audit-Length";
const JAL_INVALID_LOG_LENGTH: &str = "JAL-Invalid-Log-Length";
const JAL_UNSUPPORTED_RECORD_TYPE: &str = "JAL-Unsupported-Record-Type";
const JAL_INVALID_JAL_ID: &str = "JAL-Invalid-JAL-Id";
const JAL_RECORD_FAILURE: &str = "JAL-Record-Failure";
const JAL_INVALID_DIGEST: &str = "JAL-Invalid-Digest";
const JAL_INVALID_DIGEST_STATUS: &str = "JAL-Invalid-Digest-Status";
const JAL_UNSUPPORTED_AUDIT_FORMAT: &str = "JAL-Unsupported-Audit-Format";
const JAL_INVALID_LOG_RECORD: &str = "JAL-Invalid-Log-Record";
const JAL_JOURNAL_MISSING_FAILURE: &str = "JAL-Journal-Missing-Failure";

#[derive(Debug)]
pub enum RecordFailureReason {
    InvalidSystemMetadataLength,
    InvalidApplicationMetadataLength,
    InvalidJournalLength,
    InvalidAuditLength,
    InvalidLogLength,
    UnsupportedRecordType,
    InvalidJalId,
    RecordFailure,
    InvalidDigest,
    InvalidDigestStatus,
    UnsupportedAuditFormat,
    InvalidLogRecord,
    JournalMissingFailure,
}

impl fmt::Display for RecordFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecordFailureReason::InvalidSystemMetadataLength => write!(f, "{JAL_INVALID_SYSTEM_METADATA_LENGTH}"),
            RecordFailureReason::InvalidApplicationMetadataLength => {
                write!(f, "{JAL_INVALID_APPLICATION_METADATA_LENGTH}")
            }
            RecordFailureReason::InvalidJournalLength => write!(f, "{JAL_INVALID_JOURNAL_LENGTH}"),
            RecordFailureReason::InvalidAuditLength => write!(f, "{JAL_INVALID_AUDIT_LENGTH}"),
            RecordFailureReason::InvalidLogLength => write!(f, "{JAL_INVALID_LOG_LENGTH}"),
            RecordFailureReason::UnsupportedRecordType => write!(f, "{JAL_UNSUPPORTED_RECORD_TYPE}"),
            RecordFailureReason::InvalidJalId => write!(f, "{JAL_INVALID_JAL_ID}"),
            RecordFailureReason::RecordFailure => write!(f, "{JAL_RECORD_FAILURE}"),
            RecordFailureReason::InvalidDigest => write!(f, "{JAL_INVALID_DIGEST}"),
            RecordFailureReason::InvalidDigestStatus => write!(f, "{JAL_INVALID_DIGEST_STATUS}"),
            RecordFailureReason::UnsupportedAuditFormat => write!(f, "{JAL_UNSUPPORTED_AUDIT_FORMAT}"),
            RecordFailureReason::InvalidLogRecord => write!(f, "{JAL_INVALID_LOG_RECORD}"),
            RecordFailureReason::JournalMissingFailure => write!(f, "{JAL_JOURNAL_MISSING_FAILURE}"),
        }
    }
}

impl FromStr for RecordFailureReason {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<RecordFailureReason, JalopError> {
        // Note: reqwest normalizes incoming headers to lowercase
        match value {
            JAL_INVALID_SYSTEM_METADATA_LENGTH => Ok(RecordFailureReason::InvalidSystemMetadataLength),
            JAL_INVALID_APPLICATION_METADATA_LENGTH => Ok(RecordFailureReason::InvalidApplicationMetadataLength),
            JAL_INVALID_JOURNAL_LENGTH => Ok(RecordFailureReason::InvalidJournalLength),
            JAL_INVALID_AUDIT_LENGTH => Ok(RecordFailureReason::InvalidAuditLength),
            JAL_INVALID_LOG_LENGTH => Ok(RecordFailureReason::InvalidLogLength),
            JAL_UNSUPPORTED_RECORD_TYPE => Ok(RecordFailureReason::UnsupportedRecordType),
            JAL_INVALID_JAL_ID => Ok(RecordFailureReason::InvalidJalId),
            JAL_RECORD_FAILURE => Ok(RecordFailureReason::RecordFailure),
            JAL_INVALID_DIGEST => Ok(RecordFailureReason::InvalidDigest),
            JAL_INVALID_DIGEST_STATUS => Ok(RecordFailureReason::InvalidDigestStatus),
            JAL_UNSUPPORTED_AUDIT_FORMAT => Ok(RecordFailureReason::UnsupportedAuditFormat),
            JAL_INVALID_LOG_RECORD => Ok(RecordFailureReason::InvalidLogRecord),
            JAL_JOURNAL_MISSING_FAILURE => Ok(RecordFailureReason::JournalMissingFailure),
            _ => Err(JalopError::InvalidRecordFailureError(value.to_string())),
        }
    }
}

#[derive(Debug)]
pub struct RecordFailureReasons {
    pub reasons: Vec<RecordFailureReason>,
}

impl FromStr for RecordFailureReasons {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<RecordFailureReasons, JalopError> {
        // The Jal-Error-Message is one or more pipe-separated values indicating why
        // the record failed
        // Split the string on |, and discard leading/trailing whitespace
        let mut reasons: Vec<RecordFailureReason> = Vec::new();
        for reason_str in value.split("|") {
            reasons.push(reason_str.trim().parse::<RecordFailureReason>()?);
        }
        Ok(RecordFailureReasons { reasons })
    }
}

pub enum RecordFailureMessageHeader {
    JalId,
    JalErrorMessage,
}

impl JalopHeaderName for RecordFailureMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            RecordFailureMessageHeader::JalId => "jal-id",
            RecordFailureMessageHeader::JalErrorMessage => "jal-error-message",
        }
    }
}

pub struct RecordFailureMessage {
    pub jal_id: String,
    pub reasons: RecordFailureReasons,
}

// Used by publisher
impl TryFrom<Response> for RecordFailureMessage {
    type Error = JalopError;

    fn try_from(response: Response) -> Result<RecordFailureMessage, JalopError> {
        let message_type: JalopMessageType =
            extract_header(response.headers(), CommonMessageHeader::MessageType)?.parse()?;
        if JalopMessageType::RecordFailure != message_type {
            return Err(JalopError::UnexpectedMessageType(message_type.to_string()));
        }
        let jal_id: String = extract_header(response.headers(), RecordFailureMessageHeader::JalId)?;
        let reasons: RecordFailureReasons =
            extract_header(response.headers(), RecordFailureMessageHeader::JalErrorMessage)?.parse()?;
        Ok(RecordFailureMessage { jal_id, reasons })
    }
}

pub struct RecordFailureMessageBuilder {
    _jal_id: String,
    _reasons: RecordFailureReasons,
}

impl RecordFailureMessageBuilder {
    pub fn new(_jal_id: String, _reasons: RecordFailureReasons) -> RecordFailureMessageBuilder {
        RecordFailureMessageBuilder { _jal_id, _reasons }
    }

    pub fn build(self) -> Result<(HeaderMap, Body), JalopError> {
        todo!("used by subscriber");
    }
}
