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

pub mod state;

use std::ffi::CStr;
use std::fmt;
use yubico_piv_tool_sys as ykpiv;

#[derive(Debug)]
pub struct Error {
    code: ykpiv::ykpiv_rc,
    name: String,
    message: String,
}

impl From<ykpiv::ykpiv_rc> for Error {
    fn from(code: ykpiv::ykpiv_rc) -> Self {
        let name_ptr = unsafe { ykpiv::ykpiv_strerror_name(code) };
        let message_ptr = unsafe { ykpiv::ykpiv_strerror(code) };

        Error {
            code: code,
            name: if name_ptr.is_null() {
                String::new()
            } else {
                (unsafe { CStr::from_ptr(name_ptr) })
                    .to_str()
                    .unwrap()
                    .to_owned()
            },
            message: if message_ptr.is_null() {
                String::new()
            } else {
                (unsafe { CStr::from_ptr(message_ptr) })
                    .to_str()
                    .unwrap()
                    .to_owned()
            },
        }
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        self.code == other.code
    }
}

impl Eq for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({}): {}", self.name, self.code, self.message)
    }
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        self.message.as_str()
    }
}

pub fn try_ykpiv(code: ykpiv::ykpiv_rc) -> ::std::result::Result<(), Error> {
    match code {
        ykpiv::YKPIV_OK => Ok(()),
        _ => Err(Error::from(code)),
    }
}
