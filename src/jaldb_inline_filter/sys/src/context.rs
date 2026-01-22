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

//! This module provides a safe interface to the underlying JALoP database context.
use crate as ffi;
use crate::error::Error;
use crate::error::Error::*;
use crate::flags::DbFlags;
use crate::record_data;
use crate::record_data::RecordData;
use crate::RecordType;
use core::result::Result::Ok;
use libc::free;
use std::ffi::{c_char, c_void, CStr, CString};
use std::path::Path;
use std::path::PathBuf;
use std::ptr::NonNull;

pub struct Context {
    ctx: NonNull<ffi::jaldb_context_t>,
    path: PathBuf,
}
pub const DEFAULT_LMDB_MAP_SIZE: i32 = 120;

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        match Self::create(path.as_ref().to_path_buf()) {
            Ok(ctx) => ctx.init(),
            Err(_) => Err(CreateContextFailed),
        }
    }

    fn create(path: PathBuf) -> Result<Self, Error> {
        let ctx_ptr = unsafe { ffi::jaldb_context_create() };
        match NonNull::new(ctx_ptr) {
            Some(ctx) => Ok(Self { ctx, path }),
            None => Err(CreateContextFailed),
        }
    }

    fn init(self) -> Result<Self, Error> {
        let path = self.path.to_str().ok_or(CreateContextFailed)?;
        let db_home = CString::new(path).map_err(|e| UnexpectedFfiError(format!("init-cstring {e:?}")))?;

        //Loads LMDB_CONFIG in db_root if it exists, otherwise uses default values for map size and LMDB performance level
        let mut map_size = DEFAULT_LMDB_MAP_SIZE;
        let mut db_flags = DbFlags::Perf2;
        let mut jdb_config_ptr: *mut ffi::jaldb_config = std::ptr::null_mut();

        let result = unsafe { ffi::get_jaldb_config(db_home.as_ptr(), &mut jdb_config_ptr) };
        if result != ffi::jaldb_config_status_JALDB_CONFIG_OK
            && result != ffi::jaldb_config_status_JALDB_CONFIG_E_NOTFOUND
        {
            return Err(ConfigLoadFailed);
        }

        if result == ffi::jaldb_config_status_JALDB_CONFIG_OK {
            unsafe {
                //Only override map size if present in config
                if (*jdb_config_ptr).map_size != 0 {
                    map_size = (*jdb_config_ptr).map_size;
                }

                //Only override database option if present in config
                if !(*jdb_config_ptr).database_option.is_null() {
                    db_flags = DbFlags::from((*jdb_config_ptr).jdb_flags);
                }

                //Frees dynamic memory allocated in get_jaldb_config method
                let jdb_config_ptr_ref: *mut *mut ffi::jaldb_config = &mut jdb_config_ptr;
                ffi::free_jaldb_config(jdb_config_ptr_ref);
            }
        }

        //Display active settings for performance level and map_size
        log::info!("Performance Level: {:?}", db_flags);
        log::info!("Map Size: {}", map_size);

        let ec = unsafe {
            ffi::jaldb_context_init(
                self.ctx.as_ptr(),
                db_home.as_ptr(),
                db_flags.into(),
                map_size as std::os::raw::c_int,
            )
        };
        match ec {
            ffi::jaldb_status_JALDB_OK => Ok(self),
            ec => Err(InitContextFailed(ec)),
        }
    }

    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    pub fn mark_unsynced_records_unsent(&self, rec_type: RecordType) -> Result<(), Error> {
        let ec = unsafe { ffi::jaldb_mark_unsynced_records_unsent(self.ctx.as_ptr(), rec_type.into()) };
        match ec {
            ffi::jaldb_status_JALDB_OK => Ok(()),
            ec => Err(MarkFailed(ec)),
        }
    }

    pub fn mark_sent(&self, rec_type: RecordType, nonce: &str) -> Result<(), Error> {
        let nonce = CString::new(nonce).map_err(|e| UnexpectedFfiError(format!("sent-cstring {e:?}")))?;
        let ec = unsafe { ffi::jaldb_mark_sent(self.ctx.as_ptr(), rec_type.into(), nonce.as_ptr(), 1) };
        match ec {
            ffi::jaldb_status_JALDB_OK => Ok(()),
            ec => Err(MarkFailed(ec)),
        }
    }

    pub fn mark_unsent(&self, rec_type: RecordType, nonce: &str) -> Result<(), Error> {
        let nonce = CString::new(nonce).map_err(|e| UnexpectedFfiError(format!("unsent-cstring {e:?}")))?;
        let ec = unsafe { ffi::jaldb_mark_sent(self.ctx.as_ptr(), rec_type.into(), nonce.as_ptr(), 0) };
        match ec {
            ffi::jaldb_status_JALDB_OK => Ok(()),
            ec => Err(MarkFailed(ec)),
        }
    }

    pub fn mark_synced(&self, rec_type: RecordType, nonce: &str) -> Result<(), Error> {
        let nonce = CString::new(nonce).map_err(|e| UnexpectedFfiError(format!("synced-cstring {e:?}")))?;
        let ec = unsafe { ffi::jaldb_mark_synced(self.ctx.as_ptr(), rec_type.into(), nonce.as_ptr()) };
        match ec {
            ffi::jaldb_status_JALDB_OK => Ok(()),
            ec => Err(MarkFailed(ec)),
        }
    }

    pub fn get_next_unsynced_record(
        &self,
        rec_type: RecordType,
        db_path: &PathBuf,
    ) -> Result<Option<RecordData>, Error> {
        let mut nonce_ptr: *mut c_char = std::ptr::null_mut();
        let mut rec_ptr: *mut ffi::jaldb_record = std::ptr::null_mut();
        let res = match unsafe {
            ffi::jaldb_next_unsynced_record(self.ctx.as_ptr(), rec_type.into(), &mut nonce_ptr, &mut rec_ptr)
        } {
            ffi::jaldb_status_JALDB_OK => record_data::handle_record(rec_ptr, db_path).map(|r| Some(r)),
            ffi::jaldb_status_JALDB_E_NOT_FOUND => Ok(None),
            status => {
                let err_text = format!("jaldb_next_unsynced_record failure: {}", status);
                Err(GetRecordError(err_text))
            }
        };
        unsafe {
            free(nonce_ptr as *mut c_void);
        }
        res
    }

    pub fn jaldb_next_chronological_record(
        &self,
        ts: &str,
        rec_type: RecordType,
        db_path: &PathBuf,
    ) -> Result<Option<(RecordData, String)>, Error> {
        let mut nonce_ptr: *mut c_char = std::ptr::null_mut();
        let mut rec_ptr: *mut ffi::jaldb_record = std::ptr::null_mut();
        let c_ts = CString::new(ts.as_bytes()).map_err(|_| UnexpectedFfiError("chronological-timestamp".to_owned()))?;
        let mut ts_ptr = c_ts.into_raw();
        let res = match unsafe {
            ffi::jaldb_next_chronological_record(
                self.ctx.as_ptr(),
                rec_type.into(),
                &mut nonce_ptr,
                &mut rec_ptr,
                &mut ts_ptr,
            )
        } {
            ffi::jaldb_status_JALDB_OK => {
                let ts = unsafe {
                    let c_str = CStr::from_ptr(ts_ptr)
                        .to_str()
                        .map_err(|_| UnexpectedFfiError("timestamp string".to_string()))?;
                    c_str.to_owned()
                };
                record_data::handle_record(rec_ptr, db_path).map(|r| Some((r, ts)))
            }
            ffi::jaldb_status_JALDB_E_NOT_FOUND => Ok(None),
            status => {
                let err_text = format!("jaldb_next_chronological_record failure: {}", status);
                Err(GetRecordError(err_text))
            }
        };
        unsafe {
            free(ts_ptr as *mut c_void);
            free(nonce_ptr as *mut c_void);
        };
        res
    }

    pub fn get_record(&self, rec_type: RecordType, nonce: &str, db_path: &PathBuf) -> Result<RecordData, Error> {
        let c_nonce = CString::new(nonce).map_err(|e| UnexpectedFfiError(format!("get-rec-cstring {e:?}")))?;
        let mut rec_ptr: *mut ffi::jaldb_record = std::ptr::null_mut();
        match unsafe { ffi::jaldb_get_record(self.ctx.as_ptr(), rec_type.into(), c_nonce.as_ptr(), &mut rec_ptr) } {
            ffi::jaldb_status_JALDB_OK => record_data::handle_record(rec_ptr, db_path),
            ffi::jaldb_status_JALDB_E_NOT_FOUND => Err(RecordNotFound(nonce.to_owned())),
            status => {
                let err_text = format!("jaldb_next_unsynced_record failure: {}", status);
                Err(GetRecordError(err_text))
            }
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            ffi::jaldb_context_destroy(&mut self.ctx.as_ptr());
            log::trace!("freed jaldb context");
        }
    }
}
