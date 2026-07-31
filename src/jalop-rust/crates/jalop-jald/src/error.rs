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

//! This module defines errors that can occur during the publisher application initialization and execution.
use jalop_actors::ActorError;
use thiserror::Error;

/// An error that can occur in the JALoP Publisher
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    // db context related
    #[error("jalop ffi error: {0}")]
    JalopFfiError(#[from] jalop_sys::error::Error),

    // stream parse related
    #[error("stream error: {0}")]
    StreamError(&'static str),

    #[error("incomplete {0} data")]
    IncompleteStreamData(&'static str),

    #[error("invalid {0} data")]
    InvalidStreamData(&'static str),

    #[error("actor error {0}")]
    ActorSystemError(#[from] ActorError),
}
