use crate::path::ActorPath;
use thiserror::Error;
use tokio::sync::broadcast;

/// The Actor Model provides a higher level of abstraction for writing concurrent systems.
/// This implementation standardizes communication mechanisms while remaining flexible in protocol definition.
/// For general Actor Model background see many existing implementations such as Scala's Akka, Erlang, and several
/// in Rust such as the robust Actix and Kameo libraries, and smaller implementations such as ractor and tiny tokio.
///
pub mod actor;
mod backend;
pub mod macros;
pub mod path;
pub mod system;

pub(crate) type KillTx = broadcast::Sender<()>;
pub(crate) type KillRx = broadcast::Receiver<()>;

/// [Actor] and [ActorSystem] related errors
#[derive(Error, Debug, Clone, PartialEq)]
pub enum ActorError {
    /// A stopped actor was accessed
    #[error("actor is not running")]
    ActorStopped,
    /// A fire-and-forget message send failure
    #[error("actor tell failed")]
    TellFailed,
    /// A message send and response failure
    #[error("actor ask failed")]
    AskFailed,
    /// Actor does not exist at the specified path
    #[error("actor was not found at path {0}")]
    ActorNotFound(ActorPath),
    /// An attempt to create an [Actor] at an occupied [ActorPath]
    #[error("actor at path already exists: {0}")]
    ActorExists(ActorPath),
    /// An error occurred during the post-stop lifecycle hook
    #[error("failure in post-stop of actor")]
    PostStopError(ActorPath),
}
