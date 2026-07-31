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

//! This module provides message definition and builder types for record messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{CommonMessageHeader, CommonMessageValue, JalopHeaderName};
use crate::jnl_types::jalop_types::AuditFormatValue;
use crate::jnl_types::jalop_types::{DigestHandler, Priority, RecordType, SessionId};
use crate::messages::init_ack_message::ResumeInfo;
use crate::messages::jalop_message_type::JalopMessageType;
use crate::messages::jalop_messages::add_header;
use futures_util::stream::{StreamExt, TryStreamExt};
use reqwest::header::HeaderMap;
use reqwest::{Body, Response};
use std::io::Read;
use std::sync::{Arc, Mutex};
use tokio_util::bytes::Bytes;
use tokio_util::codec::{BytesCodec, FramedRead};

pub enum Payload {
    File { file: std::fs::File, length: usize },
    Memory { data: Vec<u8>, length: usize },
}

fn make_body(
    application_metadata: Vec<u8>,
    system_metadata: Vec<u8>,
    payload: Payload,
    resume_info: Option<ResumeInfo>,
    digest_handler: Arc<Mutex<DigestHandler>>,
) -> Result<Body, JalopError> {
    let break_bytes: Vec<u8> = vec![b'B', b'R', b'E', b'A', b'K'];
    match payload {
        Payload::Memory { data, .. } => {
            if let Ok(mut handler) = digest_handler.lock() {
                handler.update(&system_metadata);
                handler.update(&application_metadata);
                handler.update(&data);
            } else {
                return Err(JalopError::DigestMutexFailure);
            }

            let record_bytes = [
                system_metadata,
                break_bytes.clone(),
                application_metadata,
                break_bytes.clone(),
                data,
                break_bytes,
            ]
            .concat();
            let b = vec![Ok::<Bytes, std::io::Error>(Bytes::from(record_bytes))];

            Ok(Body::wrap_stream(futures_util::stream::iter(b)))
        }
        Payload::File { mut file, .. } => {
            if let Ok(mut handler) = digest_handler.lock() {
                handler.update(&system_metadata);
                handler.update(&application_metadata);
            } else {
                return Err(JalopError::DigestMutexFailure);
            }
            let record_bytes = [
                system_metadata,
                break_bytes.clone(),
                application_metadata,
                break_bytes.clone(),
            ]
            .concat();

            let stream_part_1 = vec![Ok::<Bytes, std::io::Error>(Bytes::from(record_bytes))];
            let stream_part_1 = futures_util::stream::iter(stream_part_1);

            // If resume info was provided, read and calculate the digest over the first
            // "offset" bytes without including them in the stream
            if let Some(r_info) = resume_info {
                // Read the first "offset" bytes and update the digest
                // Since this may be very large, let's do this in page-size chunks
                // of 4096 bytes
                const BUF_MAX: u64 = 4096;
                let mut bytes_read = 0;
                while bytes_read < r_info.offset {
                    let mut buf = if r_info.offset - bytes_read > BUF_MAX {
                        vec![0u8; BUF_MAX as usize]
                    } else {
                        vec![0u8; (r_info.offset - bytes_read) as usize]
                    };
                    bytes_read += buf.len() as u64;
                    if file.read_exact(&mut buf).is_err() {
                        return Err(JalopError::ResumeReadFailure);
                    };
                    if let Ok(mut handler) = digest_handler.lock() {
                        handler.update(&buf);
                    } else {
                        return Err(JalopError::ResumeLockFailure);
                    }
                }
            }

            // Make a tokio file out of the std file and turn it into a stream with FramedRead
            let stream_part_2 = FramedRead::new(tokio::fs::File::from(file), BytesCodec::new())
                .map_ok(|b| b.freeze())
                .inspect_ok(move |b| {
                    // No real way to return error/status if the lock fails
                    // just do nothing, the digest will fail to match
                    if let Ok(mut handler) = digest_handler.lock() {
                        handler.update(b);
                    }
                });

            let stream_part_3 = vec![Ok::<Bytes, std::io::Error>(Bytes::from(break_bytes))];
            let stream_part_3 = futures_util::stream::iter(stream_part_3);

            Ok(Body::wrap_stream(
                stream_part_1.chain(stream_part_2).chain(stream_part_3),
            ))
        }
    }
}

pub enum RecordMessageHeader {
    SessionId,
    JalId,
    SystemMetadataLength,
    ApplicationMetadataLength,
    LogLength,
    AuditLength,
    JournalLength,
    Priority,
    AuditFormat,
}

impl JalopHeaderName for RecordMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            RecordMessageHeader::SessionId => "jal-session-id",
            RecordMessageHeader::JalId => "jal-id",
            RecordMessageHeader::SystemMetadataLength => "jal-system-metadata-length",
            RecordMessageHeader::ApplicationMetadataLength => "jal-application-metadata-length",
            RecordMessageHeader::LogLength => "jal-log-length",
            RecordMessageHeader::AuditLength => "jal-audit-length",
            RecordMessageHeader::JournalLength => "jal-journal-length",
            RecordMessageHeader::Priority => "jal-priority",
            RecordMessageHeader::AuditFormat => "jal-audit-format",
        }
    }
}

pub struct RecordMessage {
    pub session_id: SessionId,
    pub jal_id: String,
    pub system_metadata: Vec<u8>,
    pub application_metadata: Vec<u8>,
    pub payload: Payload,
    pub priority: Priority,
}

impl TryFrom<Response> for RecordMessage {
    type Error = JalopError;

    fn try_from(_response: Response) -> Result<RecordMessage, JalopError> {
        todo!("used by subscriber");
    }
}

pub struct RecordMessageBuilder {}

impl RecordMessageBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        record_type: RecordType,
        session_id: SessionId,
        jal_id: String,
        system_metadata: Vec<u8>,
        application_metadata: Vec<u8>,
        payload: Payload,
        priority: Option<Priority>,
        digest_handler: Arc<Mutex<DigestHandler>>,
        resume_info: Option<ResumeInfo>,
    ) -> Result<(HeaderMap, Body), JalopError> {
        let mut headers: HeaderMap = HeaderMap::new();
        add_header(
            &mut headers,
            CommonMessageHeader::ContentType,
            CommonMessageValue::ContentType,
        )?;
        let length_type = match record_type {
            RecordType::Audit => {
                add_header(&mut headers, CommonMessageHeader::MessageType, JalopMessageType::Audit)?;
                add_header(&mut headers, RecordMessageHeader::AuditFormat, AuditFormatValue::Xml)?;
                RecordMessageHeader::AuditLength
            }
            RecordType::Log => {
                add_header(&mut headers, CommonMessageHeader::MessageType, JalopMessageType::Log)?;
                RecordMessageHeader::LogLength
            }
            RecordType::Journal => {
                add_header(
                    &mut headers,
                    CommonMessageHeader::MessageType,
                    JalopMessageType::Journal,
                )?;
                RecordMessageHeader::JournalLength
            }
        };
        add_header(&mut headers, RecordMessageHeader::SessionId, session_id)?;
        add_header(&mut headers, RecordMessageHeader::JalId, jal_id)?;
        add_header(
            &mut headers,
            RecordMessageHeader::SystemMetadataLength,
            system_metadata.len(),
        )?;
        add_header(
            &mut headers,
            RecordMessageHeader::ApplicationMetadataLength,
            application_metadata.len(),
        )?;
        let payload_length = match payload {
            Payload::File { length, .. } => length,
            Payload::Memory { length, .. } => length,
        };
        let payload_length = if let Some(ref r_info) = resume_info {
            payload_length - r_info.offset as usize
        } else {
            payload_length
        };
        add_header(&mut headers, length_type, payload_length)?;
        add_header(
            &mut headers,
            RecordMessageHeader::Priority,
            priority.unwrap_or_default(),
        )?;
        let content_length = system_metadata.len() + application_metadata.len() + payload_length + "BREAK".len() * 3;
        add_header(&mut headers, CommonMessageHeader::ContentLength, content_length)?;

        let body = make_body(
            application_metadata,
            system_metadata,
            payload,
            resume_info,
            digest_handler,
        )?;

        Ok((headers, body))
    }
}
