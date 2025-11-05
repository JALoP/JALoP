use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    // db context related
    #[error("create context failed")]
    CreateContextFailed,
    #[error("init context failed {0}")]
    InitContextFailed(i32),
    #[error("db mark failed {0}")]
    MarkFailed(i32),
    #[error("record retrieval failure: {0}")]
    GetRecordError(String),
    #[error("requested record was not found: {0}")]
    RecordNotFound(String),
    #[error("invalid record type: {0}")]
    InvalidRecordType(u32),
    #[error("config load failed")]
    ConfigLoadFailed,

    // ffi related
    #[error("unexpected: {0}")]
    UnexpectedFfiError(String),
}
