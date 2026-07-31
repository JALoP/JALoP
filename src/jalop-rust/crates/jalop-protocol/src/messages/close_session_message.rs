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

//! This module provides message definition and builder types for close-session messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::JalopHeaderName;
use crate::jnl_types::jalop_types::SessionId;
use crate::messages::jalop_messages::add_header;
use reqwest::header::HeaderMap;
use reqwest::{Body, Response};

pub enum CloseSessionMessageHeader {
    SessionId,
}

impl JalopHeaderName for CloseSessionMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            Self::SessionId => "jal-session-id",
        }
    }
}

pub struct CloseSessionMessage {
    pub session_id: SessionId,
}

impl TryFrom<Response> for CloseSessionMessage {
    type Error = JalopError;

    fn try_from(_response: Response) -> Result<Self, Self::Error> {
        todo!("used by subscriber")
    }
}

pub struct CloseSessionMessageBuilder {
    session_id: SessionId,
}

impl CloseSessionMessageBuilder {
    pub fn new(session_id: SessionId) -> Self {
        Self { session_id }
    }

    pub fn build(self) -> Result<(HeaderMap, Body), JalopError> {
        let mut headers = HeaderMap::new();
        add_header(&mut headers, CloseSessionMessageHeader::SessionId, self.session_id)?;
        Ok((headers, Body::from(String::new())))
    }
}
