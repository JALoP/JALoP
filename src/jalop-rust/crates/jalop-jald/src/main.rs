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

//! This module provides the main entrypoint to the jald publisher.
//! It sets up communication with the inline filter, establishes actors for all configured peers,
//! and contains the main event loop that acts upon records received from the filter.

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use jalop_actors::system::ActorSystem;
use jalop_jald::actors::config::SessionGroupConfig;
use jalop_jald::actors::session_group::SessionGroup;
use jalop_jald::actors::session_router::{SessionRouter, SessionRouterMsg};
use jalop_jald::config::{CliOpts, JaldCfg};
use jalop_jald::sockets::ControlSocket;
use jalop_jald::{config, sockets};
use jalop_protocol::control::subscriptions::SubscriberMode;
use jalop_protocol::{Token, TokenId};
use jalop_sec::seccomp;
use jalop_sys::RecordType;
use jalop_util::kill;
use jalop_util::wait::wait_for_socket;
use log::{debug, error, info};
use reqwest::Client;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let opts: CliOpts = CliOpts::parse();
    let cfg = config::from_cli(&opts)?;
    debug!("{cfg:#?}");

    //Ensures only one archive peer is present
    if cfg.peers.iter().filter(|p| p.mode == SubscriberMode::Archive).count() > 1 {
        bail!("Peer list in configuration file has more than one archival subscribers. At most one archival subscriber is supported.");
    }

    // apply initial seccomp filter
    seccomp::apply_initial(&cfg.seccomp)?;

    let system = ActorSystem::default();

    // init the kill-signal broadcast channel
    let kill = kill::setup_signals()?;
    shutdown_on_signal(kill.subscribe(), &system);

    // control socket - the filter creates it, wait up to the specified timeout for it to become available
    wait_for_socket(&cfg.control_socket.path, cfg.control_socket.timeout, kill.subscribe())
        .await
        .with_context(|| format!("{}", cfg.control_socket.path.display()))?;

    // control socket - socket file is now present on filesystem, attempt to connect
    let stream = UnixStream::connect(&cfg.control_socket.path).await?;

    // control socket actor - assumes ownership of the control socket
    let control = system.create_actor("control", ControlSocket::new(stream)).await?;

    // session router - create with a handle to the control socket actor
    let session_router = system.create_actor("router", SessionRouter::default()).await?;

    for (id, peer) in cfg.peers.iter().enumerate() {
        let id: TokenId = id.try_into().with_context(|| format!("token id {id} too large"))?;
        for rec_type in peer.record_types.iter() {
            let client = build_client(&cfg)?;
            let endpoint = peer.endpoint_url(*rec_type);

            // create the session group for the peer config
            let group = SessionGroup::new(
                Token::make(id, peer.mode),
                *rec_type,
                client,
                SessionGroupConfig::new(
                    cfg.general.clone(),
                    peer.clone(),
                    cfg.tuning.retry_interval,
                    endpoint,
                    opts.worker_count.into(),
                ),
                control.clone(),
            );

            session_router
                .ask(SessionRouterMsg::AddGroup(group))
                .await?
                .map_err(|e| anyhow!("session group creation failed, {e:?}"))?;
            info!("session group {id} {rec_type} created")
        }
    }

    // record sockets - create and accept one connection each
    for rec_type in RecordType::list() {
        let kill = kill.clone();

        // suffix the configured path for the mode
        let socket_path = rec_type.socket_path(&cfg.record_socket.path)?;
        info!("record-socket: binding to {}", socket_path.display());
        let sock = UnixListener::bind(&socket_path)?;
        info!("record-socket: listening at {}", socket_path.display());

        tokio::spawn({
            let mut kill_rx = kill.subscribe();
            let tx = session_router.clone();
            async move {
                tokio::select! {
                    res = sock.accept() => match res {
                        Ok((stream, _)) => {
                            info!("connected {rec_type} at {}", socket_path.display());
                            sockets::create_record_stream(stream, rec_type, tx.into(), kill_rx);
                        }
                        Err(e) => {
                            error!("record socket error = {e:?}");
                            let _ = kill.send(());
                        }
                    },
                    _ = kill_rx.recv() => {},
                }
            }
        });
    }

    // apply final seccomp filter
    seccomp::apply_final(&cfg.seccomp)?;

    system.await_shutdown().await;
    debug!("shutting down");

    info!("Done");
    Ok(())
}

fn shutdown_on_signal(mut rx: broadcast::Receiver<()>, system: &ActorSystem) {
    let system = system.clone();
    tokio::spawn(async move {
        if rx.recv().await.is_ok() {
            system.terminate().await;
            debug!("shutdown actor system due to signal")
        }
    });
}

fn build_client(config: &JaldCfg) -> anyhow::Result<Client> {
    let tmp_private_key = config.tls.private_key.clone();
    let tmp_public_cert = config.tls.public_cert.clone();
    let tmp_trust_store = config.tls.trust_store.clone();

    let client_cert = fs::read(tmp_public_cert)?;
    let client_key = fs::read(tmp_private_key)?;
    let identity = reqwest::tls::Identity::from_pkcs8_pem(&client_cert, &client_key)?;

    // get a list of all certificates in the trust store dir
    let certs: Vec<PathBuf> = fs::read_dir(tmp_trust_store)?
        .filter_map(|dir| {
            let Ok(dir) = dir else {
                return None;
            };

            let Ok(file_type) = dir.file_type() else {
                return None;
            };

            if file_type.is_dir() {
                return None;
            }

            let path = dir.path();
            let extension = path.as_path().extension()?;

            let pem_ext: OsString = "pem".into();
            if extension == pem_ext {
                Some(dir.path())
            } else {
                None
            }
        })
        .collect();

    let mut client_builder = Client::builder().identity(identity).use_native_tls();

    for cert_file in certs {
        let mut buf = Vec::new();
        fs::File::open(cert_file)?.read_to_end(&mut buf)?;
        let cert = reqwest::Certificate::from_pem(&buf)?;
        client_builder = client_builder.add_root_certificate(cert);
    }

    Ok(client_builder.build()?)
}
