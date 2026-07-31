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
//! This module provides types that represent the subscriber peer token.
use crate::control::subscriptions::SubscriberMode;
use crate::TokenId;
use std::fmt::{Display, Formatter};

/// Unique identifier of a subscriber
/// Provides token number and indicates the filter mode
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Token {
    Live(TokenId),
    Archive(TokenId),
}

impl Token {
    pub fn make(id: TokenId, mode: SubscriberMode) -> Token {
        match mode {
            SubscriberMode::Archive => Token::Archive(id),
            SubscriberMode::Live => Token::Live(id),
        }
    }

    /// Get the identifier of this token
    pub fn id(&self) -> TokenId {
        match self {
            Token::Live(id) => *id,
            Token::Archive(id) => *id,
        }
    }

    pub fn mode(&self) -> SubscriberMode {
        match self {
            Token::Live(_) => SubscriberMode::Live,
            Token::Archive(_) => SubscriberMode::Archive,
        }
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Live(id) => f.write_fmt(format_args!("live:{id}")),
            Token::Archive(id) => f.write_fmt(format_args!("archive:{id}")),
        }
    }
}
