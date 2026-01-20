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
use crate::{jal_seccomp_enforcer_apply_final, jal_seccomp_enforcer_apply_initial};
use anyhow::bail;
use core::result::Result::Ok;
use std::ffi::{c_char, c_int, CString};
use std::ptr::NonNull;

pub struct Enforcer {
    ptr: NonNull<ffi::jal_seccomp_enforcer_t>,
    _c_strings: Vec<CString>,
}

impl Enforcer {
    pub fn new_initial(initials: Vec<String>, debug: bool) -> Result<Self, Error> {
        let mut cstrings = vec![];
        let mut cptrs = vec![];
        for s in initials {
            let cs = CString::new(s.as_str()).map_err(|_| UnexpectedFfiError("nul in string".to_owned()))?;
            cptrs.push(cs.as_ptr() as *mut c_char);
            cstrings.push(cs);
        }

        let enforcer_ptr = unsafe {
            ffi::jal_seccomp_enforcer_create_from_list(
                cptrs.as_mut_ptr(),
                cstrings.len() as c_int,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                true,
                debug,
            )
        };

        match NonNull::new(enforcer_ptr) {
            Some(ptr) => Ok(Self {
                ptr,
                _c_strings: cstrings,
            }),
            None => Err(CreateContextFailed),
        }
    }

    pub fn new_final(finals: Vec<String>, debug: bool) -> Result<Self, Error> {
        let mut cstrings = vec![];
        let mut cptrs = vec![];
        for s in finals {
            let cs = CString::new(s.as_str()).map_err(|_| UnexpectedFfiError("nul in string".to_owned()))?;
            cptrs.push(cs.as_ptr() as *mut c_char);
            cstrings.push(cs);
        }

        let enforcer_ptr = unsafe {
            ffi::jal_seccomp_enforcer_create_from_list(
                std::ptr::null_mut(),
                0,
                cptrs.as_mut_ptr(),
                cstrings.len() as c_int,
                std::ptr::null_mut(),
                0,
                true,
                debug,
            )
        };
        match NonNull::new(enforcer_ptr) {
            Some(ptr) => Ok(Self {
                ptr,
                _c_strings: cstrings,
            }),
            None => Err(CreateContextFailed),
        }
    }

    pub fn apply_initial(self) -> anyhow::Result<()> {
        match unsafe { jal_seccomp_enforcer_apply_initial(self.ptr.as_ptr()) } {
            0 => Ok(()),
            _ => bail!("initial seccomp error"),
        }
    }

    pub fn apply_final(self) -> anyhow::Result<()> {
        match unsafe { jal_seccomp_enforcer_apply_final(self.ptr.as_ptr()) } {
            0 => Ok(()),
            _ => bail!("final seccomp error"),
        }
    }
}

impl Drop for Enforcer {
    fn drop(&mut self) {
        unsafe {
            ffi::jal_seccomp_enforcer_destroy(&mut self.ptr.as_ptr());
            log::trace!("freed seccomp enforcer");
        }
    }
}
