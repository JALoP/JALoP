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

//! This module defines common JAL version definitions.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::JalopHeaderValue;
use std::fmt;
use std::str::FromStr;

const JAL_VERSION_2_0_0_0: &str = "2.0.0.0";

pub enum JalVersion {
    V2_0_0_0,
}

impl fmt::Display for JalVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JalVersion::V2_0_0_0 => write!(f, "{JAL_VERSION_2_0_0_0}"),
        }
    }
}

impl JalopHeaderValue for JalVersion {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}

impl FromStr for JalVersion {
    type Err = JalopError;

    fn from_str(value: &str) -> Result<JalVersion, JalopError> {
        // Note: reqwest normalizes incoming headers to lowercase
        match value {
            JAL_VERSION_2_0_0_0 => Ok(JalVersion::V2_0_0_0),
            _ => Err(JalopError::InvalidJalVersion(value.to_string())),
        }
    }
}
