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

//! This module provides control socket related error types.
use jalop_sys::RecordType;
use thiserror::Error;

/// An error that can occur in the [crate::control::message::Message] decoder
#[derive(Debug, Error)]
pub enum MessageDecodeError {
    #[error("unsupported type tag: {0}")]
    InvalidTypeTag(u16),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    BadFilterMode(#[from] SubscriberModeError),
    #[error(transparent)]
    FfiError(#[from] jalop_sys::error::Error),
    #[error("nonce was not found")]
    MissingNonce,
    #[error("sub already subscribed for {0} {1}")]
    AlreadySubscribed(u16, RecordType),
    #[error("no subscription exists for {0}")]
    NotSubscribed(u16),
}

#[derive(Debug, Error)]
pub enum SubscriberModeError {
    #[error("invalid filter mode: {0}")]
    InvalidFilterMode(u16),
}
