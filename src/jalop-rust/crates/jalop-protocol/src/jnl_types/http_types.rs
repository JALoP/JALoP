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
//! This module defines common JALoP HTTP related types.

pub trait JalopHeaderValue {
    fn serialize_header_value(&self) -> String;
}

pub trait JalopHeaderName {
    fn serialize_header_name(&self) -> &'static str;
}

pub enum CommonMessageHeader {
    MessageType,
    ContentType,
    ContentLength,
}

const MESSAGE_TYPE: &str = "jal-message";
const CONTENT_TYPE: &str = "content-type";
const CONTENT_LENGTH: &str = "content-length";

impl JalopHeaderName for CommonMessageHeader {
    fn serialize_header_name(&self) -> &'static str {
        match self {
            CommonMessageHeader::MessageType => MESSAGE_TYPE,
            CommonMessageHeader::ContentType => CONTENT_TYPE,
            CommonMessageHeader::ContentLength => CONTENT_LENGTH,
        }
    }
}

pub enum CommonMessageValue {
    ContentType,
}

impl JalopHeaderValue for CommonMessageValue {
    fn serialize_header_value(&self) -> String {
        match self {
            CommonMessageValue::ContentType => "application/http+jalop".to_string(),
        }
    }
}

impl JalopHeaderValue for u64 {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}

impl JalopHeaderValue for usize {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}

impl JalopHeaderValue for String {
    fn serialize_header_value(&self) -> String {
        self.clone()
    }
}

impl JalopHeaderValue for &str {
    fn serialize_header_value(&self) -> String {
        self.to_string()
    }
}
