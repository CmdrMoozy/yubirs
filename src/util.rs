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
use rpassword;
use std::ffi::CString;

// TODO: Return an error if stderr/stdin are not TTYs.
/// This is a utility function to prompt the user for a sensitive string, e.g. a password.
fn prompt_for_string(prompt: &str, confirm: bool) -> Result<String> {
    loop {
        let string = rpassword::prompt_password_stderr(prompt)?;
        if !confirm || string == rpassword::prompt_password_stderr("Confirm: ")? {
            return Ok(string);
        }
    }
}

/// MaybePromptedString is a wrapper for getting sensitive user input (e.g. passwords). The input
/// can either be provided upon construction (e.g. via a command-line flag), or if not provided it
/// will be automatically prompted for on stdin.
pub struct MaybePromptedString {
    value: CString,
    length: usize,
    was_provided: bool,
}

impl MaybePromptedString {
    /// Construct a new string, either using the given value or prompting for one if it no value
    /// was provided using the given prompt string and optionally confirming the value a second
    /// time.
    pub fn new(provided: Option<&str>, prompt: &str, confirm: bool) -> Result<Self> {
        let prompted: Option<String> = match provided {
            None => Some(prompt_for_string(prompt, confirm)?),
            Some(_) => None,
        };
        let length: usize =
            provided.map_or_else(|| prompted.as_ref().map_or(0, |s| s.len()), |s| s.len());

        Ok(MaybePromptedString {
            value: CString::new(
                provided.map_or_else(|| prompted.as_ref().map_or("", |s| s.as_str()), |s| s),
            )?,
            length: length,
            was_provided: provided.is_some(),
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
