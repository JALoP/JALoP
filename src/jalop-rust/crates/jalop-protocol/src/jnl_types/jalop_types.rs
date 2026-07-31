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

//! This module defines common JALoP JNL types.
use crate::control::subscriptions::SubscriberMode;
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::JalopHeaderValue;
use digest::DynDigest;
use serde::Deserialize;
use sha2::{Sha256, Sha384, Sha512};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Copy, Clone, Deserialize)]
pub struct PublisherId {
    #[serde(rename = "publisher_id")]
    id: Uuid,
}

impl JalopHeaderValue for PublisherId {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}

impl PublisherId {
    pub fn new(uuid_str: &str) -> Result<PublisherId, JalopError> {
        let Ok(id) = Uuid::parse_str(uuid_str) else {
            return Err(JalopError::InvalidPublisherId(uuid_str.to_string()));
        };
        Ok(PublisherId { id })
    }

    pub fn random() -> PublisherId {
        PublisherId { id: Uuid::new_v4() }
    }
}

impl fmt::Display for PublisherId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl Default for PublisherId {
    fn default() -> Self {
        PublisherId::random()
    }
}

const JAL_AUDIT_STR: &str = "audit";
const JAL_JOURNAL_STR: &str = "journal";
const JAL_LOG_STR: &str = "log";

pub enum RecordType {
    Audit,
    Log,
    Journal,
}

impl From<jalop_sys::RecordType> for RecordType {
    fn from(value: jalop_sys::RecordType) -> Self {
        match value {
            jalop_sys::RecordType::Journal => RecordType::Journal,
            jalop_sys::RecordType::Audit => RecordType::Audit,
            jalop_sys::RecordType::Log => RecordType::Log,
        }
    }
}

impl JalopHeaderValue for RecordType {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RecordType::Audit => write!(f, "{JAL_AUDIT_STR}"),
            RecordType::Log => write!(f, "{JAL_LOG_STR}"),
            RecordType::Journal => write!(f, "{JAL_JOURNAL_STR}"),
        }
    }
}

const MODE_ARCHIVE: &str = "archival";
const MODE_LIVE: &str = "live";

pub enum SessionMode {
    Archive,
    Live,
}

impl From<SubscriberMode> for SessionMode {
    fn from(value: SubscriberMode) -> Self {
        match value {
            SubscriberMode::Archive => SessionMode::Archive,
            SubscriberMode::Live => SessionMode::Live,
        }
    }
}

impl JalopHeaderValue for SessionMode {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for SessionMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SessionMode::Archive => write!(f, "{MODE_ARCHIVE}"),
            SessionMode::Live => write!(f, "{MODE_LIVE}"),
        }
    }
}

const DIGEST_ALGORITHM_SHA_256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const DIGEST_ALGORITHM_SHA_384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const DIGEST_ALGORITHM_SHA_512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DigestAlgorithm::Sha256 => write!(f, "{DIGEST_ALGORITHM_SHA_256}"),
            DigestAlgorithm::Sha384 => write!(f, "{DIGEST_ALGORITHM_SHA_384}"),
            DigestAlgorithm::Sha512 => write!(f, "{DIGEST_ALGORITHM_SHA_512}"),
        }
    }
}

impl FromStr for DigestAlgorithm {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<DigestAlgorithm, JalopError> {
        // Note: reqwest normalizes incoming headers to lowercase
        match value {
            DIGEST_ALGORITHM_SHA_256 => Ok(DigestAlgorithm::Sha256),
            DIGEST_ALGORITHM_SHA_384 => Ok(DigestAlgorithm::Sha384),
            DIGEST_ALGORITHM_SHA_512 => Ok(DigestAlgorithm::Sha512),
            _ => Err(JalopError::InvalidDigestAlgorithm(value.to_string())),
        }
    }
}

pub struct DigestAlgorithmList {
    pub algorithms: Vec<DigestAlgorithm>,
}

impl JalopHeaderValue for DigestAlgorithmList {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for DigestAlgorithmList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.algorithms.is_empty() {
            return write!(f, "");
        }

        let mut string_form: String = String::new();
        for alg in &self.algorithms[..self.algorithms.len() - 1] {
            string_form += &format!("{alg},");
        }
        string_form += &self.algorithms[self.algorithms.len() - 1].to_string();
        write!(f, "{string_form}")
    }
}

const DIGEST_CHALLENGE_ON: &str = "on";
const DIGEST_CHALLENGE_OFF: &str = "off";

#[derive(Copy, Clone, Default, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DigestChallenge {
    #[default]
    On,
    Off,
}

impl fmt::Display for DigestChallenge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DigestChallenge::On => write!(f, "{DIGEST_CHALLENGE_ON}"),
            DigestChallenge::Off => write!(f, "{DIGEST_CHALLENGE_OFF}"),
        }
    }
}

impl FromStr for DigestChallenge {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<DigestChallenge, JalopError> {
        // Note: reqwest normalizes incoming headers to lowercase
        match value {
            DIGEST_CHALLENGE_ON => Ok(DigestChallenge::On),
            DIGEST_CHALLENGE_OFF => Ok(DigestChallenge::Off),
            _ => Err(JalopError::InvalidDigestChallenge(value.to_string())),
        }
    }
}

pub struct DigestChallengeList {
    pub challenges: Vec<DigestChallenge>,
}

impl JalopHeaderValue for DigestChallengeList {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for DigestChallengeList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.challenges.is_empty() {
            return write!(f, "");
        }

        let mut string_form: String = String::new();
        for challenge in &self.challenges[..self.challenges.len() - 1] {
            string_form += &format!("{challenge},");
        }
        string_form += &self.challenges[self.challenges.len() - 1].to_string();
        write!(f, "{string_form}")
    }
}

pub enum AuditFormatValue {
    Json,
    Xml,
}

impl JalopHeaderValue for AuditFormatValue {
    fn serialize_header_value(&self) -> String {
        match self {
            AuditFormatValue::Json => "json".to_string(),
            AuditFormatValue::Xml => "xml".to_string(),
        }
    }
}

const COMPRESSION_NONE: &str = "none";
const COMPRESSION_EXI_1: &str = "exi-1.0";
const COMPRESSION_DEFLATE: &str = "deflate";

pub enum Compression {
    None,
    ExiV1,
    Deflate,
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Compression::None => write!(f, "{COMPRESSION_NONE}"),
            Compression::ExiV1 => write!(f, "{COMPRESSION_EXI_1}"),
            Compression::Deflate => write!(f, "{COMPRESSION_DEFLATE}"),
        }
    }
}

impl FromStr for Compression {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<Compression, JalopError> {
        // Note: reqwest normalizes incoming headers to lowercase
        match value.to_lowercase().as_str() {
            COMPRESSION_NONE => Ok(Compression::None),
            COMPRESSION_EXI_1 => Ok(Compression::ExiV1),
            COMPRESSION_DEFLATE => Ok(Compression::Deflate),
            _ => Err(JalopError::InvalidCompression(value.to_string())),
        }
    }
}

#[derive(Default)]
pub struct CompressionList {
    pub compressions: Vec<Compression>,
}

impl JalopHeaderValue for CompressionList {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for CompressionList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.compressions.is_empty() {
            return write!(f, "");
        }

        let mut string_form: String = String::new();
        for comp in &self.compressions[..self.compressions.len() - 1] {
            string_form += &format!("{comp},");
        }
        string_form += &self.compressions[self.compressions.len() - 1].to_string();
        write!(f, "{string_form}")
    }
}

#[derive(Clone, Debug)]
pub struct SessionId {
    id: Uuid,
}

impl JalopHeaderValue for SessionId {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}

impl SessionId {
    pub fn new(uuid_str: &str) -> Result<SessionId, JalopError> {
        let Ok(id) = Uuid::parse_str(uuid_str) else {
            return Err(JalopError::InvalidSessionId(uuid_str.to_string()));
        };
        Ok(SessionId { id })
    }

    pub fn random() -> SessionId {
        SessionId { id: Uuid::new_v4() }
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl FromStr for SessionId {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<SessionId, JalopError> {
        let Ok(id) = Uuid::parse_str(value) else {
            return Err(JalopError::InvalidSessionId(value.to_string()));
        };
        Ok(SessionId { id })
    }
}

pub struct Priority {
    priority: u64,
}

impl Default for Priority {
    fn default() -> Self {
        Self { priority: 1 }
    }
}

impl JalopHeaderValue for Priority {
    fn serialize_header_value(&self) -> String {
        self.priority.to_string()
    }
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.priority)
    }
}

impl FromStr for Priority {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<Priority, JalopError> {
        // Note: reqwest normalizes incoming headers to lowercase
        let priority = value.parse::<u64>().map_err(|_| JalopError::PriorityOutOfRange(value.to_string()))?;
        // As a u64, the parsed priority cannot be < 0, so we only have to check
        // for > 99 to comply with the spec
        if priority > 99 {
            Err(JalopError::PriorityOutOfRange(value.to_string()))
        } else {
            Ok(Priority { priority })
        }
    }
}

impl TryFrom<u64> for Priority {
    type Error = JalopError;

    fn try_from(value: u64) -> Result<Priority, JalopError> {
        // As a u64, the parsed priority cannot be < 0, so we only have to check
        // for > 99 to comply with the spec
        if value > 99 {
            Err(JalopError::PriorityOutOfRange(value.to_string()))
        } else {
            Ok(Priority { priority: value })
        }
    }
}

const DIGEST_STATUS_CONFIRMED_STR: &str = "confirmed";
const DIGEST_STATUS_INVALID_STR: &str = "invalid";

pub enum DigestChallengeStatus {
    Confirmed,
    Invalid,
}

impl JalopHeaderValue for DigestChallengeStatus {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for DigestChallengeStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DigestChallengeStatus::Confirmed => write!(f, "{DIGEST_STATUS_CONFIRMED_STR}"),
            DigestChallengeStatus::Invalid => write!(f, "{DIGEST_STATUS_INVALID_STR}"),
        }
    }
}

impl FromStr for DigestChallengeStatus {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<DigestChallengeStatus, JalopError> {
        // Note: reqwest normalizes incoming headers to lowercase
        match value {
            DIGEST_STATUS_CONFIRMED_STR => Ok(DigestChallengeStatus::Confirmed),
            DIGEST_STATUS_INVALID_STR => Ok(DigestChallengeStatus::Invalid),
            _ => Err(JalopError::InvalidDigestChallengeStatus(value.to_string())),
        }
    }
}

pub struct DigestHandler {
    digest: Box<dyn DynDigest + Send + Sync>,
    digest_challenge_enabled: bool,
}

impl DigestHandler {
    pub fn new(digest_algorithm: DigestAlgorithm, digest_challenge: DigestChallenge) -> DigestHandler {
        DigestHandler {
            digest: digest_algorithm.into(),
            digest_challenge_enabled: DigestChallenge::On == digest_challenge,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        if self.digest_challenge_enabled {
            self.digest.update(data)
        }
    }

    pub fn finalize_reset(&mut self) -> String {
        self.digest.finalize_reset().iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl From<DigestAlgorithm> for Box<dyn DynDigest + Send + Sync> {
    fn from(algorithm: DigestAlgorithm) -> Self {
        match algorithm {
            DigestAlgorithm::Sha256 => Box::new(Sha256::default()),
            DigestAlgorithm::Sha384 => Box::new(Sha384::default()),
            DigestAlgorithm::Sha512 => Box::new(Sha512::default()),
        }
    }
}
