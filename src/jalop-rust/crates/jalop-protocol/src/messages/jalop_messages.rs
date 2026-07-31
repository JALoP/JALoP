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

//! This module provides common functions for JALoP messages.
use crate::jnl_types::error::JalopError;
use crate::jnl_types::http_types::{JalopHeaderName, JalopHeaderValue};
use reqwest::header::{HeaderMap, HeaderValue};

pub fn add_header<T, U>(headers: &mut HeaderMap, header_name: T, header_value: U) -> Result<(), JalopError>
where
    T: JalopHeaderName,
    U: JalopHeaderValue,
{
    // If the header_value is empty, simply do not add the header
    let value_string: String = header_value.serialize_header_value();
    if value_string.is_empty() {
        return Ok(());
    }
    let name_str: &str = header_name.serialize_header_name();
    let Ok(value) = HeaderValue::from_str(value_string.as_str()) else {
        return Err(JalopError::InvalidKey);
    };
    _ = headers.insert(name_str, value);
    Ok(())
}

pub fn extract_header<T>(headers: &HeaderMap, header_name: T) -> Result<String, JalopError>
where
    T: JalopHeaderName,
{
    let name_str = header_name.serialize_header_name();
    let Some(header_value) = headers.get(name_str) else {
        return Err(JalopError::MissingResponseHeader(name_str.to_string()));
    };

    let Ok(header_str) = header_value.to_str() else {
        return Err(JalopError::HeaderNotAscii(name_str.to_string()));
    };

    Ok(header_str.to_string())
}

pub fn extract_optional_header<T>(headers: &HeaderMap, header_name: T) -> Result<Option<String>, JalopError>
where
    T: JalopHeaderName,
{
    let name_str = header_name.serialize_header_name();
    let Some(header_value) = headers.get(name_str) else {
        return Ok(None);
    };

    let Ok(header_str) = header_value.to_str() else {
        return Err(JalopError::HeaderNotAscii(name_str.to_string()));
    };

    Ok(Some(header_str.to_string()))
}
