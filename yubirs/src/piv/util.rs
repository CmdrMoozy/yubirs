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

use crate::error::*;
use bdrck::cli;
use std::ffi::CString;

/// A wrapper around bdrck's MaybePromptedString which stores the data as a
/// CString, for easier FFI usage.
pub struct MaybePromptedCString {
    value: CString,
    length: usize,
    was_provided: bool,
}

impl MaybePromptedCString {
    /// Construct a new string, either using the given value or prompting for one if it no value
    /// was provided using the given prompt string and optionally confirming the value a second
    /// time.
    pub fn new(provided: Option<&str>, prompt: &str, confirm: bool) -> Result<Self> {
        let string = cli::MaybePromptedString::new(
            provided,
            cli::Stream::Stdin,
            cli::Stream::Stderr,
            prompt,
            true,
            confirm,
        )?;
        let was_provided = string.was_provided();
        let string = string.into_inner();
        let length = string.len();

        Ok(MaybePromptedCString {
            value: CString::new(string)?,
            length: length,
            was_provided: was_provided,
        })
    }

    /// Returns true if this string was provided, as opposed to being retrieved from stdin.
    pub fn was_provided(&self) -> bool {
        self.was_provided
    }

    /// Return this string's bytes. It is guaranteed that the returned byte slice is a
    /// NUL-terminated C style string, so it can be coerced to a *const c_char for FFI.
    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    /// Returns the length of this string (excluding the NUL terminator).
    pub fn len(&self) -> usize {
        self.length
    }
}

pub fn get_required_as<T: Clone + Copy, R: From<T>>(data: &[T], index: usize) -> Result<R> {
    Ok(match data.get(index) {
        None => {
            return Err(Error::InvalidArgument(format!(
                "the provided slice has only {} items, expected at least {}",
                data.len(),
                index + 1
            )));
        }
        Some(item) => (*item).into(),
    })
}

pub fn get_required<T: Clone + Copy>(data: &[T], index: usize) -> Result<T> {
    get_required_as::<T, T>(data, index)
}

/// Real PC/SC hardware often responds with variable-length data. In this case,
/// the length is encoded in the response itself, and it occupies between 1 and
/// 3 bytes.
///
/// This function parses the length out of the given device response, returning
/// the input slice excluding the bytes which comprise the length itself, and
/// the parsed length. The caller should read the returned number of bytes from
/// the beginning of the returned slice to extract the value.
///
/// Note that since the given data may contain *several* "objects", the returned
/// slice may be *longer* than the returned length.
pub fn read_length<'a>(data: &'a [u8]) -> Result<(&'a [u8], usize)> {
    if get_required(data, 0)? < 0x81 {
        let length = get_required_as::<u8, usize>(data, 0)?;
        let data = &data[1..];
        if data.len() < length {
            return Err(Error::InvalidArgument(format!(
                "parsed length says there should be at least {} more bytes, but found only {}",
                length,
                data.len()
            )));
        }
        return Ok((data, length));
    } else if (get_required(data, 0)? & 0x7f) == 1 {
        let length = get_required_as::<u8, usize>(data, 1)?;
        let data = &data[2..];
        if data.len() < length {
            return Err(Error::InvalidArgument(format!(
                "parsed length says there should be at least {} more bytes, but found only {}",
                length,
                data.len()
            )));
        }
        return Ok((data, length));
    } else if (get_required(data, 0)? & 0x7f) == 2 {
        let length =
            (get_required_as::<u8, usize>(data, 1)? << 8) + get_required_as::<u8, usize>(data, 2)?;
        let data = &data[3..];
        if data.len() < length {
            return Err(Error::InvalidArgument(format!(
                "parsed length says there should be at least {} more bytes, but found only {}",
                length,
                data.len()
            )));
        }
        return Ok((data, length));
    }

    Err(Error::InvalidArgument(format!(
        "failed to parse length from the given slice"
    )))
}
