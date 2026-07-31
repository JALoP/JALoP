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

#[allow(warnings)]
mod bindings;
pub mod context;
pub mod error;
pub mod flags;
pub mod record_data;
mod record_type;
pub mod time;
pub use record_type::*;

use crate::error::Error;
use crate::error::Error::UnexpectedFfiError;
pub use bindings::*;
use core::convert::From;
use std::ffi::CString;
use std::ptr::NonNull;

pub const MARK_REQUEST_SIZE: usize = std::mem::size_of::<mark_request>();
pub const MARK_NONCE_LENGTH: usize = 128;
pub const JALP_BREAK_STR: &str = "BREAK";
pub const JALP_BREAK_STR_LEN: usize = JALP_BREAK_STR.len();

#[derive(Debug, Clone, Copy)]
pub enum MarkRequestType {
    UnsyncedUnsent,
    Unsent,
    Sent,
    Synced,
}

#[derive(Debug, Clone, Copy)]
pub enum MarkResponseType {
    ErrorResponse,
    SuccessResponse,
}

impl TryFrom<jaldb_mark> for MarkRequestType {
    type Error = anyhow::Error;

    fn try_from(value: jaldb_mark) -> Result<Self, Self::Error> {
        use MarkRequestType::*;
        Ok(match value {
            bindings::jaldb_mark_MARK_UNSYNCED_RECORDS_UNSENT => UnsyncedUnsent,
            bindings::jaldb_mark_MARK_SENT => Sent,
            bindings::jaldb_mark_MARK_UNSENT => Unsent,
            bindings::jaldb_mark_MARK_SYNCED => Synced,
            _ => anyhow::bail!("invalid mark request type"),
        })
    }
}

impl From<MarkRequestType> for i32 {
    fn from(value: MarkRequestType) -> Self {
        use MarkRequestType::*;
        match value {
            UnsyncedUnsent => bindings::jaldb_mark_MARK_UNSYNCED_RECORDS_UNSENT,
            Sent => bindings::jaldb_mark_MARK_SENT,
            Unsent => bindings::jaldb_mark_MARK_UNSENT,
            Synced => bindings::jaldb_mark_MARK_SYNCED,
        }
    }
}

impl TryFrom<jaldb_mark> for MarkResponseType {
    type Error = anyhow::Error;

    fn try_from(value: jaldb_mark) -> Result<Self, Self::Error> {
        use MarkResponseType::*;
        Ok(match value {
            bindings::jaldb_mark_MARK_ERROR => ErrorResponse,
            bindings::jaldb_mark_MARK_SUCCESS => SuccessResponse,
            _ => anyhow::bail!("invalid mark response type"),
        })
    }
}

pub fn jald_timestamp() -> Result<String, Error> {
    match NonNull::new(unsafe { jal_gen_timestamp_usec() }) {
        None => Err(UnexpectedFfiError("timestamp pointer".to_string())),
        Some(ts) => {
            let c_str = unsafe { CString::from_raw(ts.as_ptr()) };
            c_str.into_string().map_err(|_| UnexpectedFfiError("timestamp string".to_string()))
        }
    }
}
