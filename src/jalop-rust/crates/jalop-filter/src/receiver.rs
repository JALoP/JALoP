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
use crate::subscriber::{Token, TokenId};
use futures_util::StreamExt;
use jalop_sys::RecordType;
use log::{error, info, trace, warn};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::{
    io,
    io::{AsyncWriteExt, DuplexStream},
    net::UnixStream,
};
use tokio_util::bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Framed};
// socket receiving and parsing

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

/// Create an IO Pump that transfers bytes from the [UnixStream] to the [DuplexStream]
pub async fn pump(mut tx: DuplexStream, mut stream: UnixStream) -> anyhow::Result<u64> {
    let res = io::copy(&mut stream, &mut tx).await;
    let _ = tx.shutdown().await;
    Ok(res?)
}

#[derive(Debug, Error)]
pub enum SubscriberModeError {
    #[error("invalid filter mode: {0}")]
    InvalidFilterMode(u16),
}

// JALoP Subscriber mode
#[derive(Copy, Clone, Debug)]
enum SubscriberMode {
    Archive,
    Live,
}

impl TryFrom<u16> for SubscriberMode {
    type Error = SubscriberModeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SubscriberMode::Archive),
            1 => Ok(SubscriberMode::Live),
            x => Err(SubscriberModeError::InvalidFilterMode(x)),
        }
    }
}

// Unique identifier of a subscription
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
enum SubKey {
    Journal(TokenId),
    Audit(TokenId),
    Log(TokenId),
}

impl SubKey {
    fn from(token: TokenId, rt: RecordType) -> Self {
        match rt {
            RecordType::Journal => SubKey::Journal(token),
            RecordType::Audit => SubKey::Audit(token),
            RecordType::Log => SubKey::Log(token),
        }
    }
}

const MESSAGE_TYPE_TAG_SZ: usize = 2;
const MIN_START_SZ: usize = 8;
const MIN_STOP_SZ: usize = 4;
const MIN_REC_RES_SZ: usize = 6;

/// A message sent from JALoP to the filter
#[derive(Clone, Debug)]
pub enum Message {
    /// Start a new subscriber stream
    StartStream { token: Token, rtype: RecordType },
    /// Start a new subscriber stream at the resume point
    ResumeStream {
        token: Token,
        rtype: RecordType,
        nonce: String,
    },
    /// Stop an active stream
    StopStream { token: Token, rtype: RecordType },
    /// Indicates that a record completed
    RecordSuccess {
        token: Token,
        rtype: RecordType,
        nonce: String,
    },
    /// Indicates that a record failed
    RecordError {
        token: Token,
        rtype: RecordType,
        nonce: String,
    },
    /// Indicates a record failure for disconnected subscriber
    UnsubscribedRecordError {
        id: TokenId,
        rtype: RecordType,
        nonce: String,
    },
}

impl Message {
    pub fn rtype(&self) -> RecordType {
        match *self {
            Message::StartStream { rtype, .. } => rtype,
            Message::ResumeStream { rtype, .. } => rtype,
            Message::StopStream { rtype, .. } => rtype,
            Message::RecordSuccess { rtype, .. } => rtype,
            Message::RecordError { rtype, .. } => rtype,
            Message::UnsubscribedRecordError { rtype, .. } => rtype,
        }
    }
}

/// An error that can occur in the [Message] decoder
#[derive(Debug, Error)]
pub enum MessageDecodeError {
    #[error("unsupported type tag: {0}")]
    InvalidTypeTag(u16),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    BadFilterMode(#[from] SubscriberModeError),
    #[error(transparent)]
    FfiError(#[from] jalop_sys::error::Error),
    #[error("nonce was not found")]
    MissingNonce,
    #[error("sub already subscribed for {0} {1}")]
    AlreadySubscribed(u16, RecordType),
    #[error("no subscription exists for {0}")]
    NotSubscribed(u16),
}

// Decode a [Message] from bytes
// Maintains state of active subscribers
#[derive(Default)]
struct MessageCodec {
    subs: HashMap<SubKey, SubscriberMode>,
}

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = MessageDecodeError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < MESSAGE_TYPE_TAG_SZ {
            return Ok(None);
        }

        let mut cursor = src.as_ref();
        let tag = cursor.get_u16_ne();
        let res = match tag {
            1 => Self::decode_start_stream_msg(self, cursor),
            2 => Self::decode_stop_stream_msg(self, cursor),
            4 => Self::decode_rec_success_msg(self, cursor),
            8 => Self::decode_rec_error_msg(self, cursor),
            x => {
                src.advance(MESSAGE_TYPE_TAG_SZ); // consume the tag if it was invalid
                Err(MessageDecodeError::InvalidTypeTag(x))
            }
        };

        // handle the result of the decoding
        match res {
            Ok(None) => Ok(None),
            Ok(Some((consumed, msg))) => {
                trace!("codec: decoded message {msg:?}");
                src.advance(MESSAGE_TYPE_TAG_SZ + consumed);
                Ok(Some(msg))
            }
            Err(MessageDecodeError::MissingNonce) => {
                src.advance(MIN_REC_RES_SZ + MESSAGE_TYPE_TAG_SZ);
                Err(MessageDecodeError::MissingNonce)
            }
            Err(e) => Err(e),
        }
    }
}

type DecodeResult = Result<Option<(usize, Message)>, MessageDecodeError>;
impl MessageCodec {
    fn decode_start_stream_msg(&mut self, src: &[u8]) -> DecodeResult {
        if src.len() < MIN_START_SZ {
            return Ok(None);
        }

        let mut cursor = src;
        let token = cursor.get_u16_ne();
        let rtype = cursor.get_u16_ne();
        let mode = cursor.get_u16_ne();
        let nonce_len = cursor.get_u16_ne();

        let rtype = rtype.try_into()?;
        let token = match self.subs.entry(SubKey::from(token, rtype)) {
            Entry::Occupied(_) => return Err(MessageDecodeError::AlreadySubscribed(token, rtype)),
            Entry::Vacant(e) => {
                let mode: SubscriberMode = mode.try_into()?;
                e.insert(mode);
                match mode {
                    SubscriberMode::Archive => Token::Archive(token),
                    SubscriberMode::Live => Token::Live(token),
                }
            }
        };

        match nonce_len {
            0 => Ok(Some((MIN_START_SZ, Message::StartStream { token, rtype }))),
            sz if src.len() < MIN_START_SZ + sz as usize => Ok(None),
            sz => {
                let nonce = String::from_utf8_lossy(&cursor[..sz as usize]).to_string();
                Ok(Some((
                    MIN_START_SZ + sz as usize,
                    Message::ResumeStream { token, rtype, nonce },
                )))
            }
        }
    }

    fn decode_stop_stream_msg(&mut self, src: &[u8]) -> DecodeResult {
        if src.len() < MIN_STOP_SZ {
            return Ok(None);
        }
        let mut cursor = src;
        let token = cursor.get_u16_ne();
        let rtype = cursor.get_u16_ne();

        let rtype = rtype.try_into()?;
        let subkey = SubKey::from(token, rtype);
        let mode = self.subs.remove(&subkey).ok_or(MessageDecodeError::NotSubscribed(token))?;
        let token = match mode {
            SubscriberMode::Archive => Token::Archive(token),
            SubscriberMode::Live => Token::Live(token),
        };

        Ok(Some((MIN_STOP_SZ, Message::StopStream { token, rtype })))
    }

    fn decode_rec_success_msg(&self, src: &[u8]) -> DecodeResult {
        if src.len() < MIN_REC_RES_SZ {
            return Ok(None);
        }

        let mut cursor = src;
        let token = cursor.get_u16_ne();
        let rtype = cursor.get_u16_ne();
        let nonce_len = cursor.get_u16_ne();

        let rtype = rtype.try_into()?;
        let subkey = SubKey::from(token, rtype);
        let mode = self.subs.get(&subkey).ok_or(MessageDecodeError::NotSubscribed(token))?;
        let token = match mode {
            SubscriberMode::Archive => Token::Archive(token),
            SubscriberMode::Live => Token::Live(token),
        };

        match nonce_len {
            0 => Err(MessageDecodeError::MissingNonce),
            sz if src.len() < MIN_REC_RES_SZ + sz as usize => Ok(None),
            sz => {
                let nonce = String::from_utf8_lossy(&cursor[..sz as usize]).to_string();
                Ok(Some((
                    MIN_REC_RES_SZ + sz as usize,
                    Message::RecordSuccess { token, rtype, nonce },
                )))
            }
        }
    }

    fn decode_rec_error_msg(&self, src: &[u8]) -> DecodeResult {
        if src.len() < MIN_REC_RES_SZ {
            return Ok(None);
        }

        let mut cursor = src;
        let token = cursor.get_u16_ne();
        let rtype = cursor.get_u16_ne();
        let nonce_len = cursor.get_u16_ne();

        let rtype = rtype.try_into()?;
        let subkey = SubKey::from(token, rtype);
        let err_type: Box<dyn FnOnce(String) -> Message> = match self.subs.get(&subkey) {
            Some(mode) => {
                let token = match mode {
                    SubscriberMode::Archive => Token::Archive(token),
                    SubscriberMode::Live => Token::Live(token),
                };
                Box::new(|nonce| Message::RecordError { token, rtype, nonce })
            }
            None => Box::new(|nonce| Message::UnsubscribedRecordError {
                id: token,
                rtype,
                nonce,
            }),
        };

        match nonce_len {
            0 => Err(MessageDecodeError::MissingNonce),
            sz if src.len() < MIN_REC_RES_SZ + sz as usize => Ok(None),
            sz => {
                let nonce = String::from_utf8_lossy(&cursor[..sz as usize]).to_string();
                Ok(Some((MIN_REC_RES_SZ + sz as usize, err_type(nonce))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::receiver::{Message, MessageCodec};
    use assert_matches::assert_matches;
    use futures_util::StreamExt;
    use tokio::io::{duplex, AsyncWriteExt, DuplexStream};
    use tokio_util::bytes::BufMut;
    use tokio_util::codec::Framed;

    async fn concat_wire(bytes: &[&[u8]]) -> Framed<DuplexStream, MessageCodec> {
        make_wire(bytes.concat().as_slice()).await
    }

    async fn make_wire(bytes: &[u8]) -> Framed<DuplexStream, MessageCodec> {
        let (mut a, b) = duplex(1024);
        //Ignore bytes_written currently
        let _bytes_written = a.write(bytes).await.unwrap();
        Framed::new(b, MessageCodec::default())
    }

    fn start_bytes() -> Vec<u8> {
        start_bytes_id(42)
    }

    fn start_bytes_id(id: u16) -> Vec<u8> {
        [
            1u16.to_ne_bytes(),
            id.to_ne_bytes(),
            1u16.to_ne_bytes(),
            1u16.to_ne_bytes(),
            0u16.to_ne_bytes(),
        ]
        .concat()
        .to_vec()
    }

    fn resume_bytes(nonce: &str) -> Vec<u8> {
        let nonce_len = nonce.len() as u16;
        let mut res = [
            1u16.to_ne_bytes(),
            42u16.to_ne_bytes(),
            1u16.to_ne_bytes(),
            1u16.to_ne_bytes(),
            nonce_len.to_ne_bytes(),
        ]
        .concat()
        .to_vec();
        res.put_slice(nonce.as_bytes());
        res
    }

    const NONCE: &str = "01234567-1234567-1234567-1234567-1234567-1234567-1234567-1234567-1234567-1234567";
    fn stop_bytes() -> Vec<u8> {
        stop_bytes_id(42)
    }

    fn stop_bytes_id(id: u16) -> Vec<u8> {
        [2u16.to_ne_bytes(), id.to_ne_bytes(), 1u16.to_ne_bytes()].concat().to_vec()
    }

    fn success_bytes() -> Vec<u8> {
        success_bytes_id(42)
    }

    fn success_bytes_id(id: u16) -> Vec<u8> {
        let nonce_len = NONCE.len() as u16;
        let mut res = [
            4u16.to_ne_bytes(),
            id.to_ne_bytes(),
            1u16.to_ne_bytes(),
            nonce_len.to_ne_bytes(),
        ]
        .concat()
        .to_vec();
        res.put_slice(NONCE.as_bytes());
        res
    }

    fn error_bytes() -> Vec<u8> {
        error_bytes_id(42)
    }
    fn error_bytes_id(id: u16) -> Vec<u8> {
        let nonce_len = NONCE.len() as u16;
        let mut res = [
            8u16.to_ne_bytes(),
            id.to_ne_bytes(),
            1u16.to_ne_bytes(),
            nonce_len.to_ne_bytes(),
        ]
        .concat()
        .to_vec();
        res.put_slice(NONCE.as_bytes());
        res
    }

    #[tokio::test]
    async fn parse_start() {
        let mut wire = make_wire(&start_bytes()).await;
        let result = wire.next().await.unwrap();
        assert_matches!(result, Ok(Message::StartStream { .. }));
    }

    #[tokio::test]
    async fn parse_resume() {
        let mut wire = make_wire(&resume_bytes("123")).await;
        let result = wire.next().await.unwrap();
        assert_matches!(result, Ok(Message::ResumeStream { .. }));
    }

    #[tokio::test]
    async fn parse_stop() {
        let mut wire = concat_wire(&[&start_bytes(), &stop_bytes()]).await;
        let result = wire.next().await.unwrap();
        assert_matches!(result, Ok(Message::StartStream { .. }));
        let result = wire.next().await.unwrap();
        assert_matches!(result, Ok(Message::StopStream { .. }));
    }

    #[tokio::test]
    async fn parse_success() {
        let mut wire = concat_wire(&[&start_bytes(), &success_bytes()]).await;
        let result = wire.next().await.unwrap();
        assert_matches!(result, Ok(Message::StartStream { .. }));
        let result = wire.next().await.unwrap();
        assert_matches!(result, Ok(Message::RecordSuccess { .. }));
    }

    #[tokio::test]
    async fn parse_error() {
        let mut wire = concat_wire(&[&start_bytes(), &error_bytes()]).await;
        assert_matches!(wire.next().await.unwrap(), Ok(Message::StartStream { .. }));
        assert_matches!(wire.next().await.unwrap(), Ok(Message::RecordError { .. }));
    }

    #[tokio::test]
    async fn parse_start_stop() {
        let bytes = [start_bytes(), stop_bytes()].concat();
        let mut wire = make_wire(&bytes).await;
        let start = wire.next().await.unwrap();
        assert_matches!(start, Ok(Message::StartStream { .. }));
        let stop = wire.next().await.unwrap();
        assert_matches!(stop, Ok(Message::StopStream { .. }));
    }

    #[tokio::test]
    async fn parse_start_success_stop() {
        let bytes = [start_bytes(), success_bytes(), stop_bytes()].concat();
        let mut wire = make_wire(&bytes).await;
        let start = wire.next().await.unwrap();
        assert_matches!(start, Ok(Message::StartStream { .. }));
        let success = wire.next().await.unwrap();
        assert_matches!(success, Ok(Message::RecordSuccess { .. }));
        let stop = wire.next().await.unwrap();
        assert_matches!(stop, Ok(Message::StopStream { .. }));
    }

    #[tokio::test]
    async fn parse_start_error_stop() {
        let bytes = [start_bytes(), error_bytes(), stop_bytes()].concat();
        let mut wire = make_wire(&bytes).await;
        let start = wire.next().await.unwrap();
        assert_matches!(start, Ok(Message::StartStream { .. }));
        let err = wire.next().await.unwrap();
        assert_matches!(err, Ok(Message::RecordError { .. }));
        let stop = wire.next().await.unwrap();
        assert_matches!(stop, Ok(Message::StopStream { .. }));
    }

    #[tokio::test]
    async fn restart() {
        let bytes = [start_bytes(), stop_bytes(), start_bytes(), stop_bytes()].concat();
        let mut wire = make_wire(&bytes).await;

        let start = wire.next().await.unwrap();
        assert_matches!(start, Ok(Message::StartStream { .. }));
        let stop = wire.next().await.unwrap();
        assert_matches!(stop, Ok(Message::StopStream { .. }));

        let start = wire.next().await.unwrap();
        assert_matches!(start, Ok(Message::StartStream { .. }));
        let stop = wire.next().await.unwrap();
        assert_matches!(stop, Ok(Message::StopStream { .. }));
    }

    #[tokio::test]
    async fn stale_status() {
        let bytes = [start_bytes_id(1), stop_bytes_id(1), error_bytes_id(1)].concat();
        let mut wire = make_wire(&bytes).await;

        let start = wire.next().await.unwrap();
        assert_matches!(start, Ok(Message::StartStream { .. }));
        let stop = wire.next().await.unwrap();
        assert_matches!(stop, Ok(Message::StopStream { .. }));

        let stop = wire.next().await.unwrap();
        assert_matches!(stop, Ok(Message::UnsubscribedRecordError { id: 1, .. }));
    }
}
