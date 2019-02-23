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

pub enum Utf8Error {
    String(::std::string::FromUtf8Error),
    Slice(::std::str::Utf8Error),
}

impl ::std::fmt::Debug for Utf8Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        match self {
            Utf8Error::String(e) => write!(f, "{:?}", e),
            Utf8Error::Slice(e) => write!(f, "{:?}", e),
        }
    }
}

impl ::std::fmt::Display for Utf8Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        match self {
            Utf8Error::String(e) => write!(f, "{}", e),
            Utf8Error::Slice(e) => write!(f, "{}", e),
        }
    }
}

impl ::std::error::Error for Utf8Error {
    fn description(&self) -> &str {
        match self {
            Utf8Error::String(e) => e.description(),
            Utf8Error::Slice(e) => e.description(),
        }
    }
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "{}", _0)]
    Authentication(::failure::Error),
    #[fail(display = "{}", _0)]
    Bdrck(#[cause] ::bdrck::error::Error),
    #[fail(display = "{}", _0)]
    Bincode(#[cause] ::bincode::Error),
    /// An error encountered in deciphering command-line flag values.
    #[fail(display = "{}", _0)]
    CliFlags(::failure::Error),
    #[fail(display = "{}", _0)]
    HexDecode(#[cause] ::data_encoding::DecodeError),
    #[fail(display = "{}", _0)]
    Http(#[cause] ::curl::Error),
    /// An internal unrecoverable error, usually due to some underlying library.
    #[fail(display = "{}", _0)]
    Internal(::failure::Error),
    /// Errors akin to EINVAL.
    #[fail(display = "{}", _0)]
    InvalidArgument(::failure::Error),
    #[fail(display = "{}", _0)]
    Io(#[cause] ::std::io::Error),
    #[fail(display = "{}", _0)]
    Nul(#[cause] ::std::ffi::NulError),
    #[fail(display = "{}", _0)]
    ParseDateTime(#[cause] ::chrono::ParseError),
    #[fail(display = "{}", _0)]
    ParseBool(#[cause] ::std::str::ParseBoolError),
    #[fail(display = "{}", _0)]
    ParseInt(#[cause] ::std::num::ParseIntError),
    #[fail(display = "{}", _0)]
    SmartCard(#[cause] crate::piv::scarderr::SmartCardError),
    #[fail(display = "{}", _0)]
    Ssl(#[cause] ::openssl::error::ErrorStack),
    /// An awkward hack; this error exists to use String's FromStr impl, but
    /// this operation won't actually ever fail.
    #[fail(display = "{}", _0)]
    StringParse(#[cause] ::std::string::ParseError),
    /// An error of an unknown type occurred. Generally this comes from some
    /// dependency or underlying library, in a case where it's difficult to tell
    /// exactly what kind of problem occurred.
    #[fail(display = "{}", _0)]
    Unknown(::failure::Error),
    #[fail(display = "{}", _0)]
    Utf8(#[cause] Utf8Error),
}

impl From<::bdrck::error::Error> for Error {
    fn from(e: ::bdrck::error::Error) -> Self {
        Error::Bdrck(e)
    }
}

impl From<::bincode::Error> for Error {
    fn from(e: ::bincode::Error) -> Self {
        Error::Bincode(e)
    }
}

impl From<::flaggy::ValueError> for Error {
    fn from(e: ::flaggy::ValueError) -> Self {
        Error::CliFlags(format_err!("{}", e))
    }
}

impl From<::data_encoding::DecodeError> for Error {
    fn from(e: ::data_encoding::DecodeError) -> Self {
        Error::HexDecode(e)
    }
}

impl From<::curl::Error> for Error {
    fn from(e: ::curl::Error) -> Self {
        Error::Http(e)
    }
}

impl From<::std::io::Error> for Error {
    fn from(e: ::std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<::std::ffi::NulError> for Error {
    fn from(e: ::std::ffi::NulError) -> Self {
        Error::Nul(e)
    }
}

impl From<::chrono::ParseError> for Error {
    fn from(e: ::chrono::ParseError) -> Self {
        Error::ParseDateTime(e)
    }
}

impl From<::std::str::ParseBoolError> for Error {
    fn from(e: ::std::str::ParseBoolError) -> Self {
        Error::ParseBool(e)
    }
}

impl From<::std::num::ParseIntError> for Error {
    fn from(e: ::std::num::ParseIntError) -> Self {
        Error::ParseInt(e)
    }
}

impl From<crate::piv::scarderr::SmartCardError> for Error {
    fn from(e: crate::piv::scarderr::SmartCardError) -> Self {
        Error::SmartCard(e)
    }
}

impl From<::openssl::error::ErrorStack> for Error {
    fn from(e: ::openssl::error::ErrorStack) -> Self {
        Error::Ssl(e)
    }
}

impl From<::std::string::ParseError> for Error {
    fn from(e: ::std::string::ParseError) -> Self {
        Error::StringParse(e)
    }
}

impl From<::std::string::FromUtf8Error> for Error {
    fn from(e: ::std::string::FromUtf8Error) -> Self {
        Error::Utf8(Utf8Error::String(e))
    }
}

impl From<::std::str::Utf8Error> for Error {
    fn from(e: ::std::str::Utf8Error) -> Self {
        Error::Utf8(Utf8Error::Slice(e))
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;
