use jalop_actors::ActorError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    // db context related
    #[error("jalop ffi error: {0}")]
    JalopFfiError(#[from] jalop_sys::error::Error),

    // db pool related
    #[error("db is closed")]
    ConnectionClosed,

    // stream parse related
    #[error("incomplete {0} data")]
    IncompleteStreamData(&'static str),
    #[error("invalid {0} data")]
    InvalidStreamData(&'static str),

    #[error("actor error {0}")]
    ActorSystemError(#[from] ActorError),
}
