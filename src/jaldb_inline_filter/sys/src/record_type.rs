use crate::bindings as ffi;
use crate::error::Error;
use crate::jaldb_rec_type;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    Journal,
    Audit,
    Log,
}

impl RecordType {
    pub fn list() -> Vec<Self> {
        vec![Self::Journal, Self::Audit, Self::Log]
    }

    pub fn socket_path<P: AsRef<Path> + Display>(&self, base: P) -> anyhow::Result<PathBuf> {
        let suff = match self {
            Self::Journal => "_J",
            Self::Audit => "_A",
            Self::Log => "_L",
        };
        Ok(PathBuf::from_str(&format!("{base}{suff}"))?)
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
