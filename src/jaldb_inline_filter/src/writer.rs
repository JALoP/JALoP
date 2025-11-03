use crate::db::Writer;
use crate::writer::Request::{MarkSent, MarkSynced, MarkUnsent, MarkUnsyncedUnsent};
use async_trait::async_trait;
use jalop_actors::actor::{Actor, Protocol, Receiver};
use jalop_actors::system::ActorContext;
use jalop_sys::{MarkResponseType, RecordType};
use log::warn;

pub struct WriterActor {
    db: Writer,
}

impl WriterActor {
    pub fn new(db: Writer) -> Self {
        Self { db }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    MarkUnsyncedUnsent { rec_type: RecordType },
    MarkSent { rec_type: RecordType, nonce: String },
    MarkUnsent { rec_type: RecordType, nonce: String },
    MarkSynced { rec_type: RecordType, nonce: String },
}

impl Protocol for Request {
    type Response = ();
}

#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    MarkSuccess,
    MarkError,
}

impl Actor for WriterActor {
    type Behavior = ();
}

#[async_trait]
impl Receiver<Request> for WriterActor {
    async fn receive(&mut self, msg: Request, _ctx: &mut ActorContext<Self::Behavior>) {
        if let Err(e) = match msg {
            MarkUnsyncedUnsent { rec_type } => self.db.mark_unsynced_records_unsent(rec_type),
            MarkSent { rec_type, nonce } => self.db.mark_sent(rec_type, &nonce),
            MarkUnsent { rec_type, nonce } => self.db.mark_unsent(rec_type, &nonce),
            MarkSynced { rec_type, nonce } => self.db.mark_synced(rec_type, &nonce),
        } {
            warn!("writer-actor: failed to write db {e}");
        }
    }
}

impl From<Response> for MarkResponseType {
    fn from(value: Response) -> Self {
        use Response::*;
        match value {
            MarkSuccess => MarkResponseType::ErrorResponse,
            MarkError => MarkResponseType::SuccessResponse,
        }
    }
}
