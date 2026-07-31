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
//! This module provides mechanisms for IO using the record and control sockets
use crate::messages::{ControlMsg, RecordMsg};
use crate::Error;
use async_trait::async_trait;
use futures_util::SinkExt;
use jalop_actors::actor::{Actor, Receiver};
use jalop_actors::system::ActorContext;
use jalop_protocol::control::codec::MessageCodec;
use jalop_protocol::control::message::Message;
use jalop_protocol::Token;
use jalop_sys::record_data::{InputHeaderSlices, InputPayloadSlices, RecordData};
use jalop_sys::RecordType;
use jalop_util::kill::KillChannel;
use log::warn;
use log::{error, info};
use nix::cmsg_space;
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
use std::fs::File;
use std::io::IoSliceMut;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::codec::Framed;

/// [Actor] responsible for transmitting control messages to the inline filter
pub struct ControlSocket {
    stream: Framed<UnixStream, MessageCodec>,
}

impl ControlSocket {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream: Framed::new(stream, MessageCodec::default()),
        }
    }
}

impl Actor for ControlSocket {
    type Behavior = ();
}

#[async_trait]
impl Receiver<ControlMsg> for ControlSocket {
    async fn receive(&mut self, msg: ControlMsg, _ctx: &mut ActorContext<Self>) {
        match msg {
            ControlMsg::Start(token, rtype) => {
                self.stream.send(Message::StartStream { token, rtype }).await.expect("send msg");
            }
            ControlMsg::Resume(token @ Token::Archive(_), rtype, nonce) => {
                self.stream.send(Message::ResumeStream { token, rtype, nonce }).await.expect("send msg");
            }
            ControlMsg::Resume(Token::Live(_), ..) => {
                warn!("resume is unsupported in live mode")
            }
            ControlMsg::Stop(token, rtype) => {
                self.stream.send(Message::StopStream { token, rtype }).await.expect("send msg");
            }
            ControlMsg::RecvOk(token, rtype, nonce) => {
                self.stream.send(Message::RecordSuccess { token, rtype, nonce }).await.expect("send msg");
            }
            ControlMsg::RecvFailNoRetry(token, rtype, nonce) => {
                self.stream.send(Message::RecordErrorNoRetry { token, rtype, nonce }).await.expect("send msg");
            }
            ControlMsg::RecvFailRetry(token, rtype, nonce) => {
                self.stream.send(Message::RecordErrorRetry { token, rtype, nonce }).await.expect("send msg");
            }
        }
    }
}

/// Create a task that reads [RecordData] from a [UnixStream] into [RecordMsg] channel
pub fn create_record_stream(
    stream: UnixStream,
    rtype: RecordType,
    tx: UnboundedSender<RecordMsg>,
    mut kill: KillChannel,
) -> Arc<AtomicBool> {
    let run = Arc::new(AtomicBool::new(true));
    tokio::task::spawn_blocking({
        let run = run.clone();
        move || {
            let mut fds = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
            let timeout: u16 = 1000; //1 second timeout
            while run.load(std::sync::atomic::Ordering::Relaxed) {
                match poll(&mut fds, PollTimeout::from(timeout)) {
                    Ok(0) => {
                        //Timeout occurred due to no record data, just continue on this case.
                        continue;
                    }
                    Ok(_) => {
                        if let Some(revents) = fds[0].revents() {
                            if revents.contains(PollFlags::POLLIN) {
                                let mut cmsg = cmsg_space!(RawFd);
                                let mut headers = InputHeaderSlices::default();
                                let cmsgs: Vec<_> = match recvmsg::<()>(
                                    stream.as_raw_fd(),
                                    &mut headers.vectors(),
                                    Some(&mut cmsg),
                                    MsgFlags::empty(),
                                ) {
                                    Ok(res) if res.bytes == 0 => continue,
                                    Ok(res) => res
                                        .cmsgs()
                                        .map_err(|_| Error::StreamError("[record-stream] collect cmsgs"))?
                                        .collect(),
                                    Err(Errno::EAGAIN) => continue,
                                    Err(e) => {
                                        error!("[record-stream] header recvmsg: {e}");
                                        return Err(Error::StreamError("[record-stream] header recvmsg"));
                                    }
                                };

                                let mut payload: InputPayloadSlices = headers.try_into().map_err(|_| {
                                    Error::StreamError("[record-stream] failed to map headers to payload")
                                })?;
                                let mut vectors = payload.vectors();
                                let mut remaining = vectors.as_mut_slice();

                                while !remaining.is_empty() {
                                    let received = loop {
                                        match recvmsg::<()>(stream.as_raw_fd(), remaining, None, MsgFlags::empty()) {
                                            Ok(msg) => break msg.bytes,
                                            Err(Errno::EINTR) => continue,
                                            Err(Errno::EAGAIN) => continue,
                                            Err(e) => {
                                                error!("[record-stream] payload recvmsg: {e}");
                                                return Err(Error::StreamError("[record-stream] payload recvmsg"));
                                            }
                                        }
                                    };

                                    if received == 0 {
                                        return Err(Error::StreamError("[record-stream] connection reset"));
                                    }

                                    // advance slice vec to end of recv data
                                    IoSliceMut::advance_slices(&mut remaining, received)
                                }

                                let mut record_data: RecordData = payload.try_into().map_err(|_| {
                                    Error::StreamError("[record-stream] failed to map payload to record data")
                                })?;
                                if let Some(ControlMessageOwned::ScmRights(fds)) = cmsgs.first() {
                                    if !fds.is_empty() {
                                        record_data.file = Some(unsafe { File::from_raw_fd(fds[0]) });
                                    }
                                }

                                let Some(token) = record_data.token else {
                                    warn!("token was not included in record data");
                                    continue;
                                };

                                let msg = RecordMsg {
                                    token,
                                    data: record_data,
                                };
                                if tx.send(msg).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        info!("Poll error: {e}");
                        break;
                    }
                }
            }

            info!("{rtype} socket closed");
            Ok(())
        }
    });
    tokio::spawn({
        let run = run.clone();
        async move {
            let _ = kill.recv().await;
            run.store(false, std::sync::atomic::Ordering::Relaxed);
        }
    });

    run
}
