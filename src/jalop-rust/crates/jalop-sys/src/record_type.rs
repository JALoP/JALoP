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

//! This module provides a safe interface to the JALoP record type.
use crate::bindings as ffi;
use crate::error::Error;
use crate::jaldb_rec_type;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// A JALoP record type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    Journal,
    Audit,
    Log,
}

impl RecordType {
    /// Get a vec of all [RecordType]s
    pub fn list() -> Vec<Self> {
        vec![Self::Journal, Self::Audit, Self::Log]
    }

    /// Append the record type suffix to the specified path
    pub fn socket_path(&self, base: &Path) -> anyhow::Result<PathBuf> {
        let suff = match self {
            Self::Journal => "_J",
            Self::Audit => "_A",
            Self::Log => "_L",
        };
        Ok(PathBuf::from_str(&format!("{}{suff}", base.display()))?)
    }
}

impl From<RecordType> for u16 {
    fn from(value: RecordType) -> Self {
        use RecordType::*;
        match value {
            Journal => ffi::jaldb_rec_type_JALDB_RTYPE_JOURNAL as u16,
            Audit => ffi::jaldb_rec_type_JALDB_RTYPE_AUDIT as u16,
            Log => ffi::jaldb_rec_type_JALDB_RTYPE_LOG as u16,
        }
    }
}

impl From<RecordType> for u32 {
    fn from(value: RecordType) -> Self {
        let v: u16 = value.into();
        v as u32
    }
}

impl TryFrom<u16> for RecordType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value as u32 {
            ffi::jaldb_rec_type_JALDB_RTYPE_JOURNAL => RecordType::Journal,
            ffi::jaldb_rec_type_JALDB_RTYPE_AUDIT => RecordType::Audit,
            ffi::jaldb_rec_type_JALDB_RTYPE_LOG => RecordType::Log,
            x => return Err(Error::InvalidRecordType(x)),
        })
    }
}

impl TryFrom<jaldb_rec_type> for RecordType {
    type Error = Error;
    fn try_from(value: jaldb_rec_type) -> Result<Self, Self::Error> {
        use RecordType::*;
        Ok(match value {
            ffi::jaldb_rec_type_JALDB_RTYPE_JOURNAL => Journal,
            ffi::jaldb_rec_type_JALDB_RTYPE_AUDIT => Audit,
            ffi::jaldb_rec_type_JALDB_RTYPE_LOG => Log,
            x => return Err(Error::InvalidRecordType(x)),
        })
    }
}

impl Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Journal => "journal",
            Self::Audit => "audit",
            Self::Log => "log",
        };
        f.write_str(s)
    }
}
