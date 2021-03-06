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

pub mod crypto;
pub mod error;
#[cfg(feature = "otp")]
pub mod otp;
#[cfg(feature = "piv")]
pub mod piv;

#[cfg(test)]
mod tests;

#[cfg(not(feature = "curl"))]
fn init_curl() -> error::Result<()> {
    Ok(())
}

#[cfg(feature = "curl")]
fn init_curl() -> error::Result<()> {
    curl::init();
    Ok(())
}

/// Initializes Yubirs and any other underlying libraries. It is recommended to call this function
/// as soon as the program starts.
pub fn init() -> error::Result<()> {
    openssl::init();
    init_curl()?;
    Ok(())
}
