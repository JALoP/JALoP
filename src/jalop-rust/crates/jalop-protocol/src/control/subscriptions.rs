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

//! This module provides asynchronous stream of decoded messages from a single input socket.
use crate::control::error::SubscriberModeError;
use crate::TokenId;
use jalop_sys::RecordType;
use serde::Deserialize;

// JALoP Subscriber mode
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SubscriberMode {
    Archive,
    Live,
}

impl TryFrom<u16> for SubscriberMode {
    type Error = SubscriberModeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SubscriberMode::Archive),
            1 => Ok(SubscriberMode::Live),
            x => Err(SubscriberModeError::InvalidFilterMode(x)),
        }
    }
}

impl From<SubscriberMode> for u16 {
    fn from(value: SubscriberMode) -> Self {
        match value {
            SubscriberMode::Archive => 0,
            SubscriberMode::Live => 1,
        }
    }
}

// Unique identifier of a subscription
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum SubKey {
    Journal(TokenId),
    Audit(TokenId),
    Log(TokenId),
}

impl SubKey {
    pub fn new(token: TokenId, rt: RecordType) -> Self {
        match rt {
            RecordType::Journal => SubKey::Journal(token),
            RecordType::Audit => SubKey::Audit(token),
            RecordType::Log => SubKey::Log(token),
        }
    }
}
