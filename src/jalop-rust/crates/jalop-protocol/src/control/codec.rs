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
use crate::control::error::MessageDecodeError;
use crate::control::message::Message;
use crate::control::subscriptions::{SubKey, SubscriberMode};
use crate::Token;
use anyhow::bail;
use log::trace;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

const MESSAGE_TYPE_TAG_SZ: usize = 2;
const MIN_START_SZ: usize = 8;
const MIN_STOP_SZ: usize = 4;
const MIN_REC_RES_SZ: usize = 6;

const TAG_MSG_START: u16 = 1;
const TAG_MSG_STOP: u16 = 2;
const TAG_MSG_SUCCESS: u16 = 4;
const TAG_MSG_FAILURE_RETRY: u16 = 8;
const TAG_MSG_FAILURE_NO_RETRY: u16 = 16;

// Decode a [Message] from bytes
// Maintains state of active subscribers
#[derive(Default)]
pub struct MessageCodec {
    subs: HashMap<SubKey, SubscriberMode>,
}

impl Encoder<Message> for MessageCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let token_id = item.token_id();
        let rtype: u16 = item.rtype().into();

        match item {
            Message::StartStream { token, .. } => {
                dst.put_u16_ne(TAG_MSG_START);
                dst.put_u16_ne(token_id);
                dst.put_u16_ne(rtype);

                let mode: u16 = match token {
                    Token::Live(_) => SubscriberMode::Live.into(),
                    Token::Archive(_) => SubscriberMode::Archive.into(),
                };
                dst.put_u16_ne(mode);

                // StartStream has no nonce; len 0
                dst.put_u16_ne(0);
            }
            Message::ResumeStream { token, nonce, .. } => {
                dst.put_u16_ne(TAG_MSG_START);
                dst.put_u16_ne(token_id);
                dst.put_u16_ne(rtype);

                let mode: u16 = match token {
                    Token::Live(_) => SubscriberMode::Live.into(),
                    Token::Archive(_) => SubscriberMode::Archive.into(),
                };
                dst.put_u16_ne(mode);

                let nonce_bytes = nonce.as_bytes();
                dst.put_u16_ne(nonce_bytes.len() as u16);
                dst.put_slice(nonce_bytes);
            }
            Message::StopStream { .. } => {
                dst.put_u16_ne(TAG_MSG_STOP);
                dst.put_u16_ne(token_id);
                dst.put_u16_ne(rtype);
            }
            Message::RecordSuccess { nonce, .. } => {
                dst.put_u16_ne(TAG_MSG_SUCCESS);
                dst.put_u16_ne(token_id);
                dst.put_u16_ne(rtype);

                let nonce_bytes = nonce.as_bytes();
                dst.put_u16_ne(nonce_bytes.len() as u16);
                dst.put_slice(nonce_bytes);
            }
            Message::RecordErrorNoRetry { nonce, .. } => {
                dst.put_u16_ne(TAG_MSG_FAILURE_NO_RETRY);
                dst.put_u16_ne(token_id);
                dst.put_u16_ne(rtype);

                let nonce_bytes = nonce.as_bytes();
                dst.put_u16_ne(nonce_bytes.len() as u16);
                dst.put_slice(nonce_bytes);
            }
            Message::RecordErrorRetry { nonce, .. } => {
                dst.put_u16_ne(TAG_MSG_FAILURE_RETRY);
                dst.put_u16_ne(token_id);
                dst.put_u16_ne(rtype);

                let nonce_bytes = nonce.as_bytes();
                dst.put_u16_ne(nonce_bytes.len() as u16);
                dst.put_slice(nonce_bytes);
            }
            Message::UnsubscribedRecordError { .. } => {
                bail!("UnsubscribedRecordError is not sendable, use RecordError instead")
            }
        };

        Ok(())
    }
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
            TAG_MSG_START => Self::decode_start_stream_msg(self, cursor),
            TAG_MSG_STOP => Self::decode_stop_stream_msg(self, cursor),
            TAG_MSG_SUCCESS => Self::decode_rec_success_msg(self, cursor),
            TAG_MSG_FAILURE_NO_RETRY => Self::decode_rec_error_no_retry_msg(self, cursor),
            TAG_MSG_FAILURE_RETRY => Self::decode_rec_error_retry_msg(self, cursor),
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
        let token = match self.subs.entry(SubKey::new(token, rtype)) {
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
        let subkey = SubKey::new(token, rtype);
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
        let subkey = SubKey::new(token, rtype);
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

    fn decode_rec_error_retry_msg(&self, src: &[u8]) -> DecodeResult {
        if src.len() < MIN_REC_RES_SZ {
            return Ok(None);
        }

        let mut cursor = src;
        let token = cursor.get_u16_ne();
        let rtype = cursor.get_u16_ne();
        let nonce_len = cursor.get_u16_ne();

        let rtype = rtype.try_into()?;
        let subkey = SubKey::new(token, rtype);
        let err_type: Box<dyn FnOnce(String) -> Message> = match self.subs.get(&subkey) {
            Some(mode) => {
                let token = match mode {
                    SubscriberMode::Archive => Token::Archive(token),
                    SubscriberMode::Live => Token::Live(token),
                };
                Box::new(move |nonce| Message::RecordErrorRetry { token, rtype, nonce })
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

    fn decode_rec_error_no_retry_msg(&self, src: &[u8]) -> DecodeResult {
        if src.len() < MIN_REC_RES_SZ {
            return Ok(None);
        }

        let mut cursor = src;
        let token = cursor.get_u16_ne();
        let rtype = cursor.get_u16_ne();
        let nonce_len = cursor.get_u16_ne();

        let rtype = rtype.try_into()?;
        let subkey = SubKey::new(token, rtype);
        let err_type: Box<dyn FnOnce(String) -> Message> = match self.subs.get(&subkey) {
            Some(mode) => {
                let token = match mode {
                    SubscriberMode::Archive => Token::Archive(token),
                    SubscriberMode::Live => Token::Live(token),
                };
                Box::new(move |nonce| Message::RecordErrorNoRetry { token, rtype, nonce })
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
    use crate::control::codec::MessageCodec;
    use crate::control::message::Message;
    use crate::Token;
    use assert_matches::assert_matches;
    use futures_util::{SinkExt, StreamExt};
    use jalop_sys::RecordType;
    use tokio::io::{duplex, AsyncWriteExt, DuplexStream};
    use tokio_util::bytes::BufMut;
    use tokio_util::codec::Framed;

    async fn concat_wire(bytes: &[&[u8]]) -> Framed<DuplexStream, MessageCodec> {
        make_wire(bytes.concat().as_slice()).await
    }

    async fn make_wire(bytes: &[u8]) -> Framed<DuplexStream, MessageCodec> {
        let (mut a, b) = duplex(1024);
        let _ = a.write(bytes).await.unwrap();
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
        assert_matches!(wire.next().await.unwrap(), Ok(Message::RecordErrorRetry { .. }));
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
        assert_matches!(err, Ok(Message::RecordErrorRetry { .. }));
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

    type FramedStream = Framed<DuplexStream, MessageCodec>;

    fn make_dewire() -> (FramedStream, FramedStream) {
        let (a, b) = duplex(1024);
        let i = Framed::new(a, MessageCodec::default());
        let o = Framed::new(b, MessageCodec::default());
        (i, o)
    }

    #[tokio::test]
    async fn round_trip_token_type_check() {
        let (mut i, mut o) = make_dewire();
        let start1 = Message::start(Token::Live(1), RecordType::Journal);
        let start2 = Message::start(Token::Archive(1), RecordType::Journal);

        i.send(start1.clone()).await.unwrap();
        let m = o.next().await.unwrap().unwrap();
        assert_eq!(m, start1);
        assert_ne!(m, start2);
    }
    #[tokio::test]
    async fn round_trip_token_id_check() {
        let (mut i, mut o) = make_dewire();
        let start1 = Message::start(Token::Live(1), RecordType::Journal);
        let start2 = Message::start(Token::Live(2), RecordType::Journal);

        i.send(start1.clone()).await.unwrap();
        let m = o.next().await.unwrap().unwrap();
        assert_eq!(m, start1);
        assert_ne!(m, start2);
    }

    #[tokio::test]
    async fn round_trip_rec_check() {
        let (mut i, mut o) = make_dewire();
        let start1 = Message::start(Token::Live(1), RecordType::Journal);
        let start2 = Message::start(Token::Live(1), RecordType::Audit);

        i.send(start1.clone()).await.unwrap();
        let m = o.next().await.unwrap().unwrap();
        assert_eq!(m, start1);
        assert_ne!(m, start2);

        let (mut i, mut o) = make_dewire();
        let start1 = Message::start(Token::Live(1), RecordType::Journal);
        let start2 = Message::start(Token::Live(1), RecordType::Log);

        i.send(start1.clone()).await.unwrap();
        let m = o.next().await.unwrap().unwrap();
        assert_eq!(m, start1);
        assert_ne!(m, start2);
    }

    #[tokio::test]
    async fn round_trip_handle_unsubscribed() {
        let (mut c, mut s) = make_dewire();
        let sub = Message::start(Token::Live(1), RecordType::Journal);
        let unsub = Message::stop(Token::Live(1), RecordType::Journal);
        let suc = Message::success(Token::Live(1), RecordType::Journal, "_nonce_");
        let err = Message::error_retry(Token::Live(1), RecordType::Journal, "_nonce_");

        c.send(sub).await.unwrap();
        s.next().await.unwrap().unwrap();

        c.send(unsub).await.unwrap();
        s.next().await.unwrap().unwrap();

        c.send(err).await.unwrap();
        s.next().await.unwrap().unwrap();

        c.send(suc).await.unwrap();
        assert!(s.next().await.unwrap().is_err());
    }
}
