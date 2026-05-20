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

//! This module provides an interface to produce accessors of the JALoP database.
//! The [Pool] acts as a producer of [Reader] and [Writer] DB accessors, and following
//! the Single writer Multiple Reader (SWMR) pattern it limits production to a single [Writer] while
//! allowing multiple [Reader] instances. There should be one [Pool] created per underlying database.
use crate::error::Error;
use crate::error::Error::*;
use crate::time::Timestamp;
use anyhow::{anyhow, Context as _};
use core::marker::PhantomData;
use core::ops::Drop;
use core::result::Result::Ok;
use core::time::Duration;
use jalop_sys;
use jalop_sys::context::Context;
use jalop_sys::record_data::RecordData;
use jalop_sys::RecordType;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use tokio::sync::watch;
use tokio::sync::Mutex;
use tokio::time::sleep;

type NotifyRx = watch::Receiver<bool>;
type NotifyTx = watch::Sender<bool>;

/// Database writer
/// Single instance per [Pool]
pub struct Writer {
    ctx: Context,
    notify: NotifyRx,
}

impl Writer {
    /// Mark all unsynced records for the [RecordType] unsent
    pub fn mark_unsynced_records_unsent(&mut self, rec_type: RecordType) -> Result<(), Error> {
        if *self.notify.borrow() {
            return Err(ConnectionClosed);
        }
        Ok(self.ctx.mark_unsynced_records_unsent(rec_type)?)
    }

    /// Mark a single record of the given [RecordType] and identified by the nonce
    pub fn mark_sent(&mut self, rec_type: RecordType, nonce: &str) -> Result<(), Error> {
        if *self.notify.borrow() {
            return Err(ConnectionClosed);
        }
        Ok(self.ctx.mark_sent(rec_type, nonce)?)
    }

    /// Mark a single record of the given [RecordType] and identified by the nonce
    pub fn mark_unsent(&mut self, rec_type: RecordType, nonce: &str) -> Result<(), Error> {
        if *self.notify.borrow() {
            return Err(ConnectionClosed);
        }
        Ok(self.ctx.mark_unsent(rec_type, nonce)?)
    }

    /// Mark a single record of the given [RecordType] and identified by the nonce
    pub fn mark_synced(&mut self, rec_type: RecordType, nonce: &str) -> Result<(), Error> {
        if *self.notify.borrow() {
            return Err(ConnectionClosed);
        }
        Ok(self.ctx.mark_synced(rec_type, nonce)?)
    }
}

/// Database Reader
/// Multiple instances per [Pool]
pub struct Reader {
    ctx: Context,
    notify: NotifyRx,
}

impl Reader {
    /// Get the [RecordData] for the record of the given [RecordType] identified by the specified nonce
    pub fn get_record(&self, rec_type: RecordType, nonce: &str) -> Result<RecordData, Error> {
        if *self.notify.borrow() {
            return Err(ConnectionClosed);
        }
        Ok(self.ctx.get_record(rec_type, nonce, &self.ctx.path())?)
    }

    /// Get the [RecordData] for the next unsynced record of the given [RecordType]
    pub fn get_next_unsynced_record(&self, rec_type: RecordType) -> Result<Option<RecordData>, Error> {
        if *self.notify.borrow() {
            return Err(ConnectionClosed);
        }
        Ok(self.ctx.get_next_unsynced_record(rec_type, &self.ctx.path())?)
    }

    /// Get the [RecordData] for the next record of the given [RecordType] starting from the specified [Timestamp] offset
    /// returns the [Timestamp] offset of the fetched record
    pub fn get_next_chronological(
        &self,
        rec_type: RecordType,
        ts: Timestamp,
    ) -> Result<Option<(RecordData, Timestamp)>, Error> {
        if *self.notify.borrow() {
            return Err(ConnectionClosed);
        }
        Ok(self
            .ctx
            .jaldb_next_chronological_record(ts.as_ref(), rec_type, &self.ctx.path())?
            .map(|(r, t)| (r, t.into())))
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.notify.mark_changed();
    }
}

/// A Single Writer Multiple Reader interface to the JALoP database
/// Produces [Readers] and a [Writer] that share the same configuration to the underlying database.
pub struct Pool {
    path: PathBuf,
    notify_tx: NotifyTx,
    notify_rx: Mutex<Option<NotifyRx>>,
    _marker: PhantomData<Rc<()>>,
}

impl Pool {
    /// create the [Pool] and the single [Writer] available from this pool.
    // creating the writer now avoids maintaining state to track whether a reader exists or not
    pub fn new<P: AsRef<Path>>(path: P) -> Result<(Self, Writer), Error> {
        let (tx, rx) = watch::channel(false);
        Ok((
            Self {
                path: path.as_ref().to_path_buf(),
                notify_tx: tx,
                notify_rx: Mutex::new(Some(rx.clone())),
                _marker: Default::default(),
            },
            Writer {
                ctx: Context::new(&path)?,
                notify: rx,
            },
        ))
    }

    /// Create a [Reader] of the database
    pub async fn reader(&self) -> Result<Reader, Error> {
        let notify_rx = self.notify_rx.lock().await;
        let notify_rx = notify_rx.as_ref().ok_or(ConnectionClosed)?;

        if *notify_rx.borrow() {
            return Err(ConnectionClosed);
        }

        Ok(Reader {
            ctx: Context::new(self.path.clone())?,
            notify: notify_rx.clone(),
        })
    }

    /// Shutdown the [Pool] and await the closing of all [Reader] and [Writer] instances.
    pub async fn shutdown(self, timeout: Duration) -> anyhow::Result<()> {
        self.notify_tx.send(true).with_context(|| "failed to send shutdown signal")?;

        // drop our rx handle
        self.notify_rx.lock().await.take();

        tokio::select! {
            _ = sleep(timeout) => {
                Err(anyhow!("Pool shutdown timeout tx: {}, rx: {}", self.notify_tx.sender_count(), self.notify_tx.receiver_count()))
            }
            _ = self.notify_tx.closed() => { Ok(()) }
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        let _ = self.notify_tx.send(true);
    }
}
