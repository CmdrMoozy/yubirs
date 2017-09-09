// Copyright 2017 Axel Rasmussen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use error::*;
use libc::{c_char, size_t};
use piv::try_ykpiv;
use std::ffi::CString;
use std::ptr;
use yubico_piv_tool_sys as ykpiv;

const READER_BUFFER_SIZE: usize = 65536; // 64 KiB
const DEFAULT_READER: &'static str = "Yubikey";

pub struct State {
    state: *mut ykpiv::ykpiv_state,
}

impl State {
    pub fn new(verbose: bool) -> Result<State> {
        let mut state: *mut ykpiv::ykpiv_state = ptr::null_mut();
        try_ykpiv(unsafe {
            ykpiv::ykpiv_init(
                &mut state,
                match verbose {
                    false => 0,
                    true => 1,
                },
            )
        })?;
        if state.is_null() {
            bail!("Initializing ykpiv state resulted in null ptr");
        }
        Ok(State { state: state })
    }

    /// This function returns the list of valid reader strings which can be passed to State::new.
    ///
    /// Warning: this function is, generally speaking, very inefficient in terms of memory usage.
    /// Upstream's ykpiv_list_readers function is truly awful. It requires the caller to
    /// pre-allocate a buffer, and it will return an error (which is indistinguishable from a
    /// "real" error) if the caller guesses wrong and allocates a buffer that's too small. The
    /// especially frustrating thing is that the underlying API this function wraps has a
    /// mechanism which tells us exactly how long the buffer needs to be, but it wraps it in
    /// such a way that this functionality is inaccessible.
    ///
    /// So, to be safe (and not report spurious errors), this function pre-allocates a rather large
    /// buffer (64 KiB) to avoid this condition.
    pub fn list_readers(&self) -> Result<Vec<String>> {
        let mut buffer: Vec<u8> = vec![0_u8; READER_BUFFER_SIZE];
        let mut buffer_len: size_t = READER_BUFFER_SIZE as size_t;
        let result = try_ykpiv(unsafe {
            ykpiv::ykpiv_list_readers(
                self.state,
                buffer.as_mut_ptr() as *mut c_char,
                &mut buffer_len,
            )
        });
        if let Some(err) = result.as_ref().err() {
            if *err == ::piv::Error::from(ykpiv::YKPIV_PCSC_ERROR) {
                info!(
                    "Listing readers returned a PC/SC error. Usually this means pcscd is not \
                     running, or no readers are available. Try running with --verbose for more \
                     details."
                );
            }
        }
        result?;

        buffer.truncate(buffer_len);
        let ret: ::std::result::Result<Vec<String>, ::std::str::Utf8Error> = buffer
            .split(|b| *b == 0)
            .filter_map(|slice| match slice.len() {
                0 => None,
                _ => Some(::std::str::from_utf8(slice).map(|s| s.to_owned())),
            })
            .collect();

        Ok(ret?)
    }

    pub fn connect(&mut self, reader: Option<&str>) -> Result<()> {
        let reader = CString::new(reader.unwrap_or(DEFAULT_READER)).unwrap();
        Ok(try_ykpiv(
            unsafe { ykpiv::ykpiv_connect(self.state, reader.as_ptr()) },
        )?)
    }

    pub fn disconnect(&mut self) -> Result<()> {
        Ok(try_ykpiv(unsafe { ykpiv::ykpiv_disconnect(self.state) })?)
    }
}

impl Drop for State {
    fn drop(&mut self) {
        if let Err(e) = try_ykpiv(unsafe { ykpiv::ykpiv_done(self.state) }) {
            error!("Cleaning up ykpiv state failed: {}", e);
        }
    }
}
