use crate as jalop_sys;
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
pub enum DbFlags {
    None,
    ReadOnly,
    Perf1,
    Perf2,
    Perf3,
}

impl From<DbFlags> for jalop_sys::jaldb_flags {
    fn from(f: DbFlags) -> Self {
        use DbFlags::*;
        match f {
            None => jalop_sys::jaldb_flags_JDB_NONE,
            ReadOnly => jalop_sys::jaldb_flags_JDB_READONLY,
            Perf1 => jalop_sys::jaldb_flags_JDB_LMDB_PERFORMANCE_LEVEL1,
            Perf2 => jalop_sys::jaldb_flags_JDB_LMDB_PERFORMANCE_LEVEL2,
            Perf3 => jalop_sys::jaldb_flags_JDB_LMDB_PERFORMANCE_LEVEL3,
        }
    }
}

impl From<jalop_sys::jaldb_flags> for DbFlags {
    fn from(value: jalop_sys::jaldb_flags) -> Self {
        use DbFlags::*;
        match value {
            jalop_sys::jaldb_flags_JDB_NONE => None,
            jalop_sys::jaldb_flags_JDB_READONLY => ReadOnly,
            jalop_sys::jaldb_flags_JDB_LMDB_PERFORMANCE_LEVEL1 => Perf1,
            jalop_sys::jaldb_flags_JDB_LMDB_PERFORMANCE_LEVEL2 => Perf2,
            jalop_sys::jaldb_flags_JDB_LMDB_PERFORMANCE_LEVEL3 => Perf3,
            _=> Perf2,
        }
    }
}

impl FromStr for DbFlags {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use DbFlags::*;
        match s {
            "none" => Ok(None),
            "ro" => Ok(ReadOnly),
            "p1" => Ok(Perf1),
            "p2" => Ok(Perf2),
            "p3" => Ok(Perf3),
            x => Err(format!("invalid db flag: {x}")),
        }
    }
}
