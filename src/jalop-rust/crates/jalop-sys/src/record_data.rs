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

//! This module provides functionality to access and serialize JALoP database records.
use crate::error::Error;
use crate::error::Error::GetRecordError;
use crate::{self as ffi, JALP_BREAK_STR};
use crate::{RecordType, JALP_BREAK_STR_LEN};
use core::ffi::CStr;
use core::{format_args, slice};
use std::fmt::Debug;
use std::fs::File;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::OwnedFd;
use std::path::Path;

/// Represent a record read from the database
#[derive(Debug)]
pub struct RecordData {
    pub rec_type: RecordType,
    pub payload: Option<Vec<u8>>,
    pub payload_len: usize,
    pub app_meta: Vec<u8>,
    pub sys_meta: Vec<u8>,
    pub nonce: String,
    pub timestamp: String,
    pub file: Option<File>,
    on_disk: bool,
    pub token: Option<u16>,
}

// A structure that assists in serializing [RecordData] to an IO vector for
// sending across a Unix Domain Socket. The mechanics of sending impose ownership
// constraints, this struct serves as an owner of the serialized data while sending.
struct Inner {
    rec_type: Vec<u8>,
    token: Vec<u8>,
    payload_len: Vec<u8>,
    app_meta_len: Vec<u8>,
    sys_meta_len: Vec<u8>,
    nonce_len: Vec<u8>,
    timestamp_len: Vec<u8>,
    payload_on_disk: Vec<u8>,
    payload: Vec<u8>,
    app_meta: Vec<u8>,
    sys_meta: Vec<u8>,
    nonce: Vec<u8>,
    timestamp: Vec<u8>,
}

impl Default for Inner {
    fn default() -> Self {
        Inner {
            rec_type: vec![0; 2],
            token: vec![0; 2],
            payload_len: vec![0; 8],
            app_meta_len: vec![0; 8],
            sys_meta_len: vec![0; 2],
            nonce_len: vec![0; 2],
            timestamp_len: vec![0; 2],
            payload_on_disk: vec![0; 2],
            payload: vec![],
            app_meta: vec![],
            sys_meta: vec![],
            nonce: vec![],
            timestamp: vec![],
        }
    }
}

/// A serialized [RecordData] that is ready to be sent across a UDS
#[derive(Default, Debug)]
pub struct IoData {
    inner: Inner,
    on_disk: bool,
    pub fd: Option<OwnedFd>,
}

impl IoData {
    pub fn new(rd: RecordData, token: u16) -> Self {
        let mut inner = Inner::default();
        let rec_type: u16 = rd.rec_type.into();
        inner.rec_type = rec_type.to_ne_bytes().to_vec();
        inner.token = token.to_ne_bytes().to_vec();
        inner.payload_len = (rd.payload_len as u64).to_ne_bytes().to_vec();

        inner.app_meta_len = (rd.app_meta.len() as u64).to_ne_bytes().to_vec();
        inner.sys_meta_len = (rd.sys_meta.len() as u16).to_ne_bytes().to_vec();
        inner.nonce_len = (rd.nonce.len() as u16).to_ne_bytes().to_vec();
        inner.timestamp_len = (rd.timestamp.len() as u16).to_ne_bytes().to_vec();
        inner.payload_on_disk = (rd.on_disk as u16).to_ne_bytes().to_vec();

        inner.payload = rd.payload.unwrap_or_default();
        inner.app_meta = rd.app_meta;
        inner.sys_meta = rd.sys_meta;
        inner.nonce = rd.nonce.as_bytes().to_vec();
        inner.timestamp = rd.timestamp.as_bytes().to_vec();

        Self {
            inner,
            on_disk: rd.on_disk,
            fd: rd.file.map(OwnedFd::from),
        }
    }

    pub fn vectors(&self) -> Vec<IoSlice<'_>> {
        let mut iov = vec![
            IoSlice::new(&self.inner.rec_type),
            IoSlice::new(&self.inner.token),
            IoSlice::new(&self.inner.payload_len),
            IoSlice::new(&self.inner.app_meta_len),
            IoSlice::new(&self.inner.sys_meta_len),
            IoSlice::new(&self.inner.nonce_len),
            IoSlice::new(&self.inner.timestamp_len),
            IoSlice::new(&self.inner.payload_on_disk),
        ];
        if !self.on_disk {
            iov.push(IoSlice::new(&self.inner.payload));
            iov.push(IoSlice::new(JALP_BREAK_STR.as_bytes()));
        }
        iov.push(IoSlice::new(&self.inner.app_meta));
        iov.push(IoSlice::new(JALP_BREAK_STR.as_bytes()));
        iov.push(IoSlice::new(&self.inner.sys_meta));
        iov.push(IoSlice::new(JALP_BREAK_STR.as_bytes()));
        iov.push(IoSlice::new(&self.inner.nonce));
        iov.push(IoSlice::new(JALP_BREAK_STR.as_bytes()));
        iov.push(IoSlice::new(&self.inner.timestamp));
        iov.push(IoSlice::new(JALP_BREAK_STR.as_bytes()));

        iov
    }
}

/// Receive record data headers
#[derive(Default)]
pub struct InputHeaderSlices {
    inner: Inner,
}

impl InputHeaderSlices {
    /// Produce a set of input headers
    pub fn vectors(&mut self) -> Vec<IoSliceMut<'_>> {
        vec![
            IoSliceMut::new(&mut self.inner.rec_type),
            IoSliceMut::new(&mut self.inner.token),
            IoSliceMut::new(&mut self.inner.payload_len),
            IoSliceMut::new(&mut self.inner.app_meta_len),
            IoSliceMut::new(&mut self.inner.sys_meta_len),
            IoSliceMut::new(&mut self.inner.nonce_len),
            IoSliceMut::new(&mut self.inner.timestamp_len),
            IoSliceMut::new(&mut self.inner.payload_on_disk),
        ]
    }

    pub fn record_type(&self) -> anyhow::Result<RecordType> {
        Ok(RecordType::try_from(u16::from_ne_bytes(
            self.inner.rec_type.as_slice().try_into()?,
        ))?)
    }

    pub fn token(&self) -> anyhow::Result<u16> {
        Ok(u16::from_ne_bytes(self.inner.token.as_slice().try_into()?))
    }

    pub fn payload_len(&self) -> anyhow::Result<u64> {
        Ok(u64::from_ne_bytes(self.inner.payload_len.as_slice().try_into()?))
    }

    pub fn app_meta_len(&self) -> anyhow::Result<u64> {
        Ok(u64::from_ne_bytes(self.inner.app_meta_len.as_slice().try_into()?))
    }

    pub fn sys_meta_len(&self) -> anyhow::Result<u16> {
        Ok(u16::from_ne_bytes(self.inner.sys_meta_len.as_slice().try_into()?))
    }

    pub fn nonce_len(&self) -> anyhow::Result<u16> {
        Ok(u16::from_ne_bytes(self.inner.nonce_len.as_slice().try_into()?))
    }

    pub fn timestamp_len(&self) -> anyhow::Result<u16> {
        Ok(u16::from_ne_bytes(self.inner.timestamp_len.as_slice().try_into()?))
    }

    pub fn payload_on_disk(&self) -> anyhow::Result<bool> {
        let f = u16::from_ne_bytes(self.inner.payload_on_disk.as_slice().try_into()?);
        Ok(f != 0)
    }
}

impl TryFrom<InputHeaderSlices> for InputPayloadSlices {
    type Error = anyhow::Error;

    fn try_from(value: InputHeaderSlices) -> Result<Self, Self::Error> {
        InputPayloadSlices::new(value)
    }
}

/// Receive record data payload
pub struct InputPayloadSlices {
    token: u16,
    on_disk: bool,
    payload_segment_length: usize,
    rtype: RecordType,
    inner: Inner,
    _break_buffer0: [u8; JALP_BREAK_STR_LEN],
    _break_buffer1: [u8; JALP_BREAK_STR_LEN],
    _break_buffer2: [u8; JALP_BREAK_STR_LEN],
    _break_buffer3: [u8; JALP_BREAK_STR_LEN],
    _break_buffer4: [u8; JALP_BREAK_STR_LEN],
}

impl InputPayloadSlices {
    fn new(headers: InputHeaderSlices) -> anyhow::Result<Self> {
        let payload = if headers.payload_on_disk()? {
            vec![]
        } else {
            vec![0; headers.payload_len()? as usize]
        };
        Ok(Self {
            token: headers.token()?,
            on_disk: headers.payload_on_disk()?,
            payload_segment_length: headers.payload_len()? as usize,
            rtype: headers.record_type()?,
            inner: Inner {
                payload,
                app_meta: vec![0; headers.app_meta_len()? as usize],
                sys_meta: vec![0; headers.sys_meta_len()? as usize],
                nonce: vec![0; headers.nonce_len()? as usize],
                timestamp: vec![0; headers.timestamp_len()? as usize],
                ..Default::default()
            },
            _break_buffer0: [0u8; JALP_BREAK_STR_LEN],
            _break_buffer1: [0u8; JALP_BREAK_STR_LEN],
            _break_buffer2: [0u8; JALP_BREAK_STR_LEN],
            _break_buffer3: [0u8; JALP_BREAK_STR_LEN],
            _break_buffer4: [0u8; JALP_BREAK_STR_LEN],
        })
    }

    pub fn vectors(&mut self) -> Vec<IoSliceMut<'_>> {
        let mut iov = vec![];
        if !self.on_disk {
            iov.push(IoSliceMut::new(&mut self.inner.payload));
            iov.push(IoSliceMut::new(&mut self._break_buffer0));
        }
        iov.push(IoSliceMut::new(&mut self.inner.app_meta));
        iov.push(IoSliceMut::new(&mut self._break_buffer1));
        iov.push(IoSliceMut::new(&mut self.inner.sys_meta));
        iov.push(IoSliceMut::new(&mut self._break_buffer2));
        iov.push(IoSliceMut::new(&mut self.inner.nonce));
        iov.push(IoSliceMut::new(&mut self._break_buffer3));
        iov.push(IoSliceMut::new(&mut self.inner.timestamp));
        iov.push(IoSliceMut::new(&mut self._break_buffer4));
        iov
    }
}

impl TryFrom<InputPayloadSlices> for RecordData {
    type Error = anyhow::Error;

    fn try_from(headers: InputPayloadSlices) -> Result<Self, Self::Error> {
        // In the on_disk case, payload is left NULL and file is updated
        // later in records.rs read_stream. payload_len is always the length
        // of the full payload segment
        let payload = if headers.on_disk {
            None
        } else {
            Some(headers.inner.payload)
        };
        Ok(RecordData {
            rec_type: headers.rtype,
            payload,
            payload_len: headers.payload_segment_length,
            app_meta: headers.inner.app_meta,
            sys_meta: headers.inner.sys_meta,
            nonce: String::from_utf8(headers.inner.nonce)?,
            timestamp: String::from_utf8(headers.inner.timestamp)?,
            file: None,
            on_disk: headers.on_disk,
            token: Some(headers.token),
        })
    }
}

/// Extract [RecordData] and free [jaldb_record] memory
pub(crate) fn handle_record(mut rec_ptr: *mut ffi::jaldb_record, db_path: &Path) -> Result<RecordData, Error> {
    let res = extract_record_fields(rec_ptr, db_path);
    unsafe { ffi::jaldb_destroy_record(&mut rec_ptr) };
    res
}

fn extract_record_fields(rec_ptr: *const ffi::jaldb_record, db_path: &Path) -> Result<RecordData, Error> {
    if rec_ptr.is_null() {
        return Err(GetRecordError("Record pointer is NULL".to_string()));
    }

    let nonce = unsafe {
        let nonce_ptr = (*rec_ptr).network_nonce;
        if nonce_ptr.is_null() {
            return Err(GetRecordError("Null network nonce pointer".to_string()));
        }
        match CStr::from_ptr(nonce_ptr).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return Err(GetRecordError("Failed to extract nonce".to_string())),
        }
    };

    let timestamp = unsafe {
        let ptr = (*rec_ptr).timestamp;
        if ptr.is_null() {
            return Err(GetRecordError("Null timestamp pointer".to_string()));
        }
        let c_str = CStr::from_ptr(ptr);
        match c_str.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return Err(GetRecordError("Failed to extract timestamp".to_string())),
        }
    };

    let rec_type = unsafe {
        match (*rec_ptr).type_ {
            ffi::jaldb_rec_type_JALDB_RTYPE_JOURNAL => RecordType::Journal,
            ffi::jaldb_rec_type_JALDB_RTYPE_AUDIT => RecordType::Audit,
            ffi::jaldb_rec_type_JALDB_RTYPE_LOG => RecordType::Log,
            _ => {
                return Err(GetRecordError("Failed to extract record type".to_string()));
            }
        }
    };

    let sys_meta_vec = {
        let sys_meta_ptr = unsafe { (*rec_ptr).sys_meta };
        if sys_meta_ptr.is_null() {
            return Err(GetRecordError("Failed to extra sys_meta segment".to_string()));
        }
        let sys_meta_segment = unsafe { *sys_meta_ptr };
        // system metadata should never be on_disk
        if 0 != sys_meta_segment.on_disk {
            return Err(GetRecordError("System metadata unexpected on disk".to_string()));
        }
        // system metadata should never have an fd
        if -1 != sys_meta_segment.fd {
            return Err(GetRecordError("System metadata unexpected fd".to_string()));
        }
        let Ok(length) = TryInto::<usize>::try_into(sys_meta_segment.length) else {
            return Err(GetRecordError("Failed to extract system metadata length".to_string()));
        };
        let mut byte_vec = Vec::<u8>::new();
        if 0 != length {
            let bytes: &[u8] = unsafe { slice::from_raw_parts(sys_meta_segment.payload, length) };
            byte_vec.extend_from_slice(bytes);
        }
        if byte_vec.len() != length {
            return Err(GetRecordError("System metadata length mismatch".to_string()));
        }
        byte_vec
    };

    let app_meta_vec = {
        let app_meta_ptr = unsafe { (*rec_ptr).app_meta };
        if app_meta_ptr.is_null() {
            return Err(GetRecordError("Failed to extra app_meta segment".to_string()));
        }
        let app_meta_segment = unsafe { *app_meta_ptr };
        // application metadata should never be on_disk
        if 0 != app_meta_segment.on_disk {
            return Err(GetRecordError("Application metadata unexpected on disk".to_string()));
        }
        // application metadata should never have an fd
        if -1 != app_meta_segment.fd {
            return Err(GetRecordError("Application metadata unexpected fd".to_string()));
        }
        let Ok(length) = TryInto::<usize>::try_into(app_meta_segment.length) else {
            return Err(GetRecordError(
                "Failed to extract application metadata length".to_string(),
            ));
        };
        let mut byte_vec = Vec::<u8>::new();
        if 0 != length {
            let bytes: &[u8] = unsafe { slice::from_raw_parts(app_meta_segment.payload, length) };
            byte_vec.extend_from_slice(bytes);
        }
        if byte_vec.len() != length {
            return Err(GetRecordError("Application metadata length mismatch".to_string()));
        }
        byte_vec
    };

    let (payload_vec, payload_len, payload_file, on_disk) = {
        let payload_ptr = unsafe { (*rec_ptr).payload };
        if payload_ptr.is_null() {
            return Err(GetRecordError("Failed to extract payload segment".to_string()));
        }

        let payload_segment = unsafe { *payload_ptr };

        // Note that this is always the length in bytes of the payload. If the payload is
        // on_disk, this will be the length of the file. If the payload is not on_disk
        // this will be the length of the payload field in bytes
        let Ok(length) = TryInto::<usize>::try_into(payload_segment.length) else {
            return Err(GetRecordError("Failed to extract payload length".to_string()));
        };

        // the fd stored in the DB will always be -1 in this context, verify this
        if -1 != payload_segment.fd {
            return Err(GetRecordError("Payload fd not initialized to -1".to_string()));
        }

        let (payload_vec, payload_fd) = if 0 != payload_segment.on_disk {
            // The payload field is a null terminated string, the path to the payload file
            let file_path_c_str = unsafe { CStr::from_ptr(payload_segment.payload as *const i8) };
            let payload_str = file_path_c_str.to_str();
            let Ok(payload_str) = payload_str else {
                return Err(GetRecordError("Failed to get payload file path".to_string()));
            };
            let mut path = db_path.to_path_buf();
            path.push("journal/");
            path.push(payload_str);
            let Ok(file) = File::open(path) else {
                return Err(GetRecordError("Failed to open payload file".to_string()));
            };
            (None, Some(file))
        } else {
            // The payload field is "length" bytes and contains the actual payload
            // which may be of 0 length
            let mut byte_vec = Vec::<u8>::new();
            if 0 != length {
                let bytes: &[u8] = unsafe { slice::from_raw_parts(payload_segment.payload, length) };
                byte_vec.extend_from_slice(bytes);
            }
            if byte_vec.len() != length {
                return Err(GetRecordError("Payload length mismatch".to_string()));
            }
            (Some(byte_vec), None)
        };
        (payload_vec, length, payload_fd, 0 != payload_segment.on_disk)
    };
    Ok(RecordData {
        sys_meta: sys_meta_vec,
        app_meta: app_meta_vec,
        payload: payload_vec,
        payload_len,
        file: payload_file,
        rec_type,
        nonce: nonce.to_string(),
        timestamp: timestamp.to_string(),
        on_disk,
        token: None,
    })
}

impl Debug for Inner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "RecordData:
            rec-type: {:?}
            peer-hostname-len: {:?}
            length of payload segment: {:?}
            app-meta-len: {:?}
            sys-meta-len: {:?}
            nonce-len: {:?}
            timestamp-len: {:?}
            nonce-len: {}
            length of headers payload: {}
            app-meta: {}
            sys-meta: {}
            timestamp: {}
            nonce (str): {}
            payload-on-disk: {:?}
            fd: {}",
            self.rec_type,
            self.token,
            self.payload_len,
            self.app_meta_len,
            self.sys_meta_len,
            self.nonce_len,
            self.timestamp_len,
            self.nonce.len(),
            self.payload.len(),
            self.app_meta.len(),
            self.sys_meta.len(),
            self.timestamp.len(),
            "???",
            self.payload_on_disk,
            "???",
        ))
    }
}
