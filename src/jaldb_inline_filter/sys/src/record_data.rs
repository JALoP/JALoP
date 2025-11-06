/***
 *
 * Copyright (C) 2025 Concurrent Technologies Corporation.
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

use crate::error::Error;
use crate::error::Error::GetRecordError;
use crate::RecordType;
use crate::{self as ffi, JALP_BREAK_STR};
use core::ffi::CStr;
use core::{format_args, slice};
use std::fmt::Debug;
use std::fs::File;
use std::io::IoSlice;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RecordData {
    pub rec_type: RecordType,
    payload: Option<Vec<u8>>,
    payload_len: usize,
    app_meta: Vec<u8>,
    sys_meta: Vec<u8>,
    pub nonce: String,
    pub timestamp: String,
    fd: Option<Arc<OwnedFd>>,
    on_disk: bool,
}

#[derive(Default)]
struct Inner {
    rec_type: Vec<u8>,
    token: Vec<u8>,
    payload_len: Vec<u8>,
    app_meta_len: Vec<u8>,
    sys_meta_len: Vec<u8>,
    nonce_len: Vec<u8>,
    timestamp_len: Vec<u8>,
    payload_on_disk: Vec<u8>,
    peer_hostname: Vec<u8>,
    payload: Vec<u8>,
    app_meta: Vec<u8>,
    sys_meta: Vec<u8>,
    nonce: Vec<u8>,
    timestamp: Vec<u8>,
}

#[derive(Debug)]
pub struct IoData {
    // iovecs borrow from inner
    inner: Inner,
    on_disk: bool,
    pub fd: Option<Arc<OwnedFd>>,
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

        inner.payload = rd.payload.unwrap_or(Vec::new());
        inner.app_meta = rd.app_meta;
        inner.sys_meta = rd.sys_meta;
        inner.nonce = rd.nonce.as_bytes().to_vec();
        inner.timestamp = rd.timestamp.as_bytes().to_vec();

        Self {
            inner,
            on_disk: rd.on_disk,
            fd: rd.fd.clone(),
        }
    }

    pub fn vectors(&self) -> Vec<IoSlice> {
        let mut iov = vec![];
        iov.push(IoSlice::new(&self.inner.rec_type));
        iov.push(IoSlice::new(&self.inner.token));
        iov.push(IoSlice::new(&self.inner.payload_len));
        iov.push(IoSlice::new(&self.inner.app_meta_len));
        iov.push(IoSlice::new(&self.inner.sys_meta_len));
        iov.push(IoSlice::new(&self.inner.nonce_len));
        iov.push(IoSlice::new(&self.inner.timestamp_len));
        iov.push(IoSlice::new(&self.inner.payload_on_disk));
        iov.push(IoSlice::new(&self.inner.peer_hostname));
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

/// Extract [RecordData] and free [jaldb_record] memory
pub(crate) fn handle_record(mut rec_ptr: *mut ffi::jaldb_record, db_path: &PathBuf) -> Result<RecordData, Error> {
    let res = extract_record_fields(rec_ptr, db_path);
    unsafe { ffi::jaldb_destroy_record(&mut rec_ptr) };
    res
}

fn extract_record_fields(rec_ptr: *const ffi::jaldb_record, db_path: &PathBuf) -> Result<RecordData, Error> {
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

    let (payload_vec, payload_len, payload_fd, on_disk) = {
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
            let mut path = db_path.clone();
            path.push("journal/");
            path.push(payload_str);
            let Ok(file) = File::open(path) else {
                return Err(GetRecordError("Failed to open payload file".to_string()));
            };
            let fd: OwnedFd = file.into();
            (None, Some(fd))
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
        fd: payload_fd.map(Arc::new),
        rec_type,
        nonce: nonce.to_string(),
        timestamp: timestamp.to_string(),
        on_disk,
    })
}

impl Debug for Inner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "RecordData:
            rec-type: {:?}
            peer-hostname-len: {:?}
            payload-len: {:?}
            app-meta-len: {:?}
            sys-meta-len: {:?}
            nonce-len: {:?}
            timestamp-len: {:?}
            nonce-len: {}
            peer-hostanme: {:?}
            payload: {}
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
            self.peer_hostname,
            self.payload.len(),
            self.app_meta.len(),
            self.sys_meta.len(),
            self.timestamp.len(),
            "todo",
            self.payload_on_disk,
            "todo",
        ))
    }
}
