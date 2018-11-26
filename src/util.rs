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

use bdrck::cli;
use error::*;
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
        let string =
            cli::MaybePromptedString::new(provided, cli::Stream::Stderr, prompt, true, confirm)?;
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
