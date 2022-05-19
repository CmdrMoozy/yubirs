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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Utf8Error {
    #[error("{0}")]
    String(#[from] std::string::FromUtf8Error),
    #[error("{0}")]
    Slice(#[from] std::str::Utf8Error),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("authentication failure: {0}")]
    Authentication(String),
    #[cfg(feature = "bdrck")]
    #[error("{0}")]
    Bdrck(#[from] bdrck::error::Error),
    #[cfg(feature = "bincode")]
    #[error("{0}")]
    Bincode(#[from] bincode::Error),
    /// An internal error; we tried to mutably borrow a shared resource which
    /// was already borrowed elsewhere.
    #[error("{0}")]
    BorrowMut(#[from] std::cell::BorrowMutError),
    #[error("{0}")]
    HexDecode(#[from] data_encoding::DecodeError),
    #[cfg(feature = "curl")]
    #[error("{0}")]
    Http(#[from] curl::Error),
    /// An internal unrecoverable error, usually due to some underlying library.
    #[error("internal error: {0}")]
    Internal(String),
    /// Errors akin to EINVAL.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Nul(#[from] std::ffi::NulError),
    #[cfg(feature = "chrono")]
    #[error("{0}")]
    ParseDateTime(#[from] chrono::ParseError),
    #[error("{0}")]
    ParseBool(#[from] std::str::ParseBoolError),
    #[error("{0}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[cfg(feature = "piv")]
    #[error("{0}")]
    RmpDecode(#[from] rmp_serde::decode::Error),
    #[cfg(feature = "piv")]
    #[error("{0}")]
    RmpEncode(#[from] rmp_serde::encode::Error),
    #[cfg(feature = "piv")]
    #[error("{0}")]
    SmartCard(#[from] crate::piv::scarderr::SmartCardError),
    #[error("{0}")]
    Ssl(#[from] openssl::error::ErrorStack),
    /// An awkward hack; this error exists to use String's FromStr impl, but
    /// this operation won't actually ever fail.
    #[error("{0}")]
    StringParse(#[from] std::string::ParseError),
    /// We tried to access some thread-local storage which was already
    /// destructed.
    #[error("{0}")]
    ThreadLocalAccess(#[from] std::thread::AccessError),
    /// An unknown error. Generally, this is an error reported by an underlying library, which
    /// doesn't provide us with enough information to give a clear "error type".
    #[error("unknown error: {0}")]
    Unknown(String),
    #[error("{0}")]
    Utf8(Utf8Error),
}

// This is a shim to allow us to convert from an underlying error to an Error, *via* a Utf8Error as
// an intermediate type. The compiler doesn't notice that this is possible without us providing
// this implementation explicitly.
impl<E> From<E> for Error
where
    E: Into<Utf8Error>,
{
    fn from(e: E) -> Self {
        Error::Utf8(e.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
