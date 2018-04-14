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

extern crate bdrck;
extern crate bincode;
extern crate chrono;
extern crate curl;
extern crate data_encoding;
#[macro_use]
extern crate error_chain;
extern crate isatty;
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate log;
extern crate openssl;
extern crate openssl_sys;
extern crate pcsc_sys;
extern crate rand;
extern crate regex;
extern crate rpassword;
extern crate serde;
#[macro_use]
extern crate serde_derive;

pub mod crypto;
pub mod error;
pub mod otp;
pub mod piv;
mod util;

#[cfg(test)]
mod tests;

/// Initializes Yubirs and any other underlying libraries. It is recommended to call this function
/// as soon as the program starts.
pub fn init() -> error::Result<()> {
    openssl::init();
    curl::init();
    Ok(())
}
