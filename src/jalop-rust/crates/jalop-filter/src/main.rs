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

//! This module provides the main entrypoint to the inline filter.
//! It sets up communication with jald, establishes connections to the database,
//! and contains the main event loop that acts upon requests from jald.
use anyhow::{bail, Context};
use clap::Parser;
use core::time::Duration;
use jalop_actors::actor::PoisonPill;
use jalop_actors::path::ActorPath;
use jalop_actors::system::ActorSystem;
use jalop_filter::config::CliOpts;
use jalop_filter::db::Pool;
use jalop_filter::receiver::{Message, MessageStream};
use jalop_filter::sender::{SenderActor, SenderMsg};
use jalop_filter::subscriber::{ArchiveSubscriber, LiveSubscriber, SubscriberMsg, Token};
use jalop_filter::writer::{Request, WriterActor};
use jalop_filter::{config, kill, receiver, seccomp, time, writer};
use jalop_sys::{RecordType, MARK_REQUEST_SIZE};
use log::{debug, info, trace, warn};
use std::os::unix::net::UnixStream;
use std::path::Path;
use tokio::io::duplex;
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::time::interval;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let opts: CliOpts = CliOpts::parse();
    let cfg = config::from_cli(&opts)?;
    debug!("global options: {cfg:#?}");

    // apply initial seccomp filter
    seccomp::apply_initial(&cfg.seccomp)?;

    if !cfg.db.path.is_dir() {
        bail!("db_home must be an existing directory")
    }

    // rx - create one filter-owned socket to receive messages from jald
    let socket_path = &cfg.control_socket.path;
    info!("control-socket: binding to {}", socket_path.display());
    let sock = UnixListener::bind(socket_path)?;
    info!("control-socket: listening at {}", socket_path.display());

    let system = ActorSystem::default();
    let (pool, writer) = Pool::new(&cfg.db.path).expect("db init fail");
    info!("Database connected {}", &cfg.db.path.display());

    // init the kill-signal broadcast channel
    let kill = kill::setup_signals()?;

    // rx - socket - parse messages from jald and push into msg channel
    // outer thread connects the socket
    // inner threads handle socket reading from socket and parsing messages
    let (connected_tx, connected_rx) = tokio::sync::oneshot::channel();
    let (msg_tx, mut msg_rx) = mpsc::channel(1024);
    tokio::spawn({
        let kill = kill.clone();
        let mut kill_rx = kill.subscribe();
        let message_buffer_size = MARK_REQUEST_SIZE * cfg.control_socket.buffer;
        async move {
            info!("socket-rx: thread started");
            tokio::select! {
                Ok((input, _)) = sock.accept() => {
                    let _ = connected_tx.send(());
                    // pump socket bytes into the duplex
                    info!("socket-rx: io buffer size: {message_buffer_size}");
                    let (buf_tx, buf_rx) = duplex(message_buffer_size);
                    tokio::spawn(receiver::pump(buf_tx, input));

                    // decode the duplex into messages
                    let msg_stream = MessageStream::start(msg_tx, buf_rx);
                    tokio::select!{
                        _ = kill_rx.recv() => {
                            info!("socket-rx: killed");
                            let _ = msg_stream.stop();
                        },
                    }
                }
                _ = kill_rx.recv() => info!("socket-rx: connect killed"),
            }
            info!("socket-rx: thread stopped");
        }
    });

    // create the writer actor
    let writer = WriterActor::new(writer);
    let writer = system.create_actor("writer", writer).await?;

    // create a tx actor for each record type
    for rtype in RecordType::list() {
        // suffix the configured path for the mode
        let socket_path = rtype.socket_path(&cfg.record_socket.path)?;

        // wait for the specified timeout and kill the filter if not connected
        wait_for_socket(&socket_path, cfg.record_socket.timeout, kill.subscribe())
            .await
            .with_context(|| format!("{}", socket_path.display()))?;

        // tx - socket - connect to a jald-owned socket to tx records
        info!("socket-tx: connecting to {}", socket_path.display());
        let stream = UnixStream::connect(&socket_path)?;
        info!("socket-tx: connected to {}", socket_path.display());

        // create the sender actor
        let sender_actor = SenderActor::new(rtype, stream, cfg.record_socket.buffer);
        system.create_actor_path(make_sender_path(rtype), sender_actor).await?;
    }

    {
        // ensure control socket has connected
        let mut kill = kill.subscribe();
        tokio::select! {
            _ = connected_rx => {}
            _ = kill.recv() => {}
        }
    };

    // apply final seccomp filter
    seccomp::apply_final(&cfg.seccomp)?;

    // handle incoming socket messages
    while let Some(incoming) = msg_rx.recv().await {
        let sender = system.get_actor(&make_sender_path(incoming.rtype())).await.unwrap();
        match incoming {
            Message::StartStream {
                token: Token::Archive(id),
                rtype,
            } => {
                let _ = writer.ask(Request::MarkUnsyncedUnsent { rec_type: rtype }).await;
                let reader = ArchiveSubscriber::new(id, rtype, sender, pool.reader().await?, writer.clone());
                let reader = system.create_actor_path(make_reader_path(id, rtype), reader).await?;
                let _ = reader.tell(SubscriberMsg::ReadNext).await;
                trace!("processed start stream for {rtype:?} archive subscriber id {id}");
            }
            Message::StartStream {
                token: Token::Live(id),
                rtype,
            } => {
                let reader = LiveSubscriber::new(id, time::now()?, rtype, sender, pool.reader().await?);
                let reader = system.create_actor_path(make_reader_path(id, rtype), reader).await?;
                let _ = reader.tell(SubscriberMsg::ReadNext).await;
                trace!("processed start stream for {rtype} live subscriber id {id}");
            }
            Message::ResumeStream {
                token: Token::Archive(id),
                rtype,
                nonce,
            } => {
                let _ = writer.ask(Request::MarkUnsyncedUnsent { rec_type: rtype }).await;
                let reader = ArchiveSubscriber::new(id, rtype, sender, pool.reader().await?, writer.clone());
                let reader = system.create_actor_path(make_reader_path(id, rtype), reader).await?;
                let _ = reader.tell(SubscriberMsg::ResumeFrom(nonce)).await;
                trace!("processed resume stream for {rtype} archive subscriber id {id}");
            }
            Message::ResumeStream {
                token: Token::Live(id),
                rtype,
                ..
            } => {
                warn!("unsupported: resume attempted by {rtype} live subscriber {id}")
            }
            Message::StopStream {
                token: Token::Archive(id),
                rtype,
            } => {
                let reader = system.get_actor::<ArchiveSubscriber>(&make_reader_path(id, rtype)).await.unwrap();
                let _ = reader.tell(PoisonPill).await;
                let _ = sender.tell(SenderMsg::EvictAll(id)).await;
                trace!("processed stop stream for {rtype} archive subscriber id {id}");
            }
            Message::StopStream {
                token: Token::Live(id),
                rtype,
            } => {
                let reader = system.get_actor::<LiveSubscriber>(&make_reader_path(id, rtype)).await.unwrap();
                let _ = reader.tell(PoisonPill).await;
                let _ = sender.tell(SenderMsg::EvictAll(id)).await;
                trace!("processed stop stream for {rtype} live subscriber id {id}");
            }
            Message::RecordSuccess {
                token: Token::Archive(id),
                rtype,
                nonce,
            } => {
                let _ = writer.tell(make_synced_msg(rtype, nonce.clone())).await;
                let _ = sender.tell(SenderMsg::Sent(id, nonce)).await;
                trace!("processed record success for {rtype} archive subscriber id {id}");
            }
            Message::RecordSuccess {
                token: Token::Live(id),
                rtype,
                nonce,
            } => {
                let _ = sender.tell(SenderMsg::Sent(id, nonce)).await;
                trace!("processed record success for {rtype} live subscriber id {id}");
            }
            Message::RecordError {
                token: Token::Archive(id),
                rtype,
                nonce,
            } => {
                warn!("error reported by jald archive subscriber {id} for {rtype} {nonce}");
                let _ = writer.ask(make_unsent_msg(rtype, nonce.clone())).await;
                let _ = sender.tell(SenderMsg::Evict(nonce)).await;
            }
            Message::RecordError {
                token: Token::Live(id),
                rtype,
                nonce,
            } => {
                warn!("error reported by jald live subscriber {id} for {rtype} {nonce}");
                let _ = sender.tell(SenderMsg::Evict(nonce)).await;
            }
            Message::UnsubscribedRecordError { id, rtype, nonce } => {
                warn!("error reported for disconnected subscriber {id} for {rtype} {nonce}");
                let _ = writer.ask(make_unsent_msg(rtype, nonce.clone())).await;
            }
        }
    }

    // gracefully shut down actors and db
    debug!("shutting down");
    system.shutdown().await;
    if let Err(e) = pool.shutdown(Duration::from_secs(3)).await {
        warn!("{e}");
    }

    info!("Done");
    Ok(())
}

// wait for the socket file to appear on disk, waiting up to the specified timeout
async fn wait_for_socket<P: AsRef<Path>>(
    path: P,
    timeout: u16,
    mut kill: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let mut attempts = 0;
    let mut check_interval = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = kill.recv() => bail!("wait for socket interrupted by kill signal"),
            _ = check_interval.tick() => {
                if path.as_ref().try_exists()? {
                    break Ok(())
                } else if attempts < timeout {
                    debug!("waiting on socket");
                    attempts += 1;
                } else {
                    bail!("socket timeout expired")
                }
            }
        }
    }
}

fn make_sender_path(rec_type: RecordType) -> ActorPath {
    format!("sender-{rec_type:?}").into()
}

fn make_reader_path(token: u16, rec_type: RecordType) -> ActorPath {
    format!("reader-{rec_type:?}-{token}").into()
}

fn make_unsent_msg(rec_type: RecordType, nonce: String) -> writer::Request {
    writer::Request::MarkUnsent { rec_type, nonce }
}

fn make_synced_msg(rec_type: RecordType, nonce: String) -> writer::Request {
    writer::Request::MarkSynced { rec_type, nonce }
}
