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

//! This module provides asynchronous stream of decoded messages from a single input socket.
use crate::control::codec::MessageCodec;
use crate::control::message::Message;
use futures_util::StreamExt;
use log::{info, warn};
use tokio::io::DuplexStream;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio_util::codec::Framed;

/// Stream of [Message] parsed out of a [DuplexStream]
pub struct MessageStream {
    kill: oneshot::Sender<()>,
}

impl MessageStream {
    /// Start a new [MessageStream] that parses from the [DuplexStream]
    /// Backpressure is applied to the parse by the capacity of the [Sender]
    /// The backpressure propagates back to the source populating the duplex
    pub fn start(tx: Sender<Message>, rx: DuplexStream) -> Self {
        let (kill_tx, mut kill_rx) = oneshot::channel();
        let mut wire = Framed::new(rx, MessageCodec::default());
        tokio::spawn(async move {
            info!("socket-rx: message stream started");
            loop {
                tokio::select! {
                    msg = wire.next() => match msg {
                        Some(Ok(m)) => {
                            let _ = tx.send(m).await;
                        }
                        Some(Err(e)) => {
                            warn!("socket-rx: message stream error {e:?}");
                        }
                        None => {
                            info!("socket-rx: message stream stopped, wire closed");
                            break
                        },
                    },
                    _ = &mut kill_rx => {
                        info!("socket-rx: message stream stopped, killed");
                        break
                    },
                }
            }
        });
        Self { kill: kill_tx }
    }

    /// Interrupt the stream, stopping the parser
    pub fn stop(self) -> anyhow::Result<()> {
        Ok(self.kill.send(()).map_err(|_| crate::Error::StreamError("failed to send kill signal"))?)
    }
}
