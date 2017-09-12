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
use libc::{c_char, c_int, c_uchar, c_ulong, size_t};
use piv::try_ykpiv;
use rpassword;
use std::ffi::{CStr, CString};
use std::fmt;
use std::ptr;
use std::str::FromStr;
use yubico_piv_tool_sys as ykpiv;

const READER_BUFFER_SIZE: usize = 65536; // 64 KiB
/// The default reader string to use. The first reader (as returned by list_readers) which contains
/// this string as a substring is the one which will be used. So, this default will result in us
/// using the first connected Yubikey we find.
pub const DEFAULT_READER: &'static str = "Yubikey";

// The version format is "%d.%d.%d", where each number is an 8-bit unsigned integer. So, we need
// three digits per number * three numbers + two .'s + one null-terminator, which gives 12 bytes.
const VERSION_BUFFER_SIZE: usize = 12;

const PIN_NAME: &'static str = "PIN";
const PIN_PROMPT: &'static str = "PIN: ";
const NEW_PIN_PROMPT: &'static str = "New PIN: ";

const PUK_NAME: &'static str = "PUK";
const PUK_PROMPT: &'static str = "PUK: ";
const NEW_PUK_PROMPT: &'static str = "New PUK: ";

const MGM_KEY_PROMPT: &'static str = "Management Key: ";
const MGM_KEY_BYTES: usize = 24;

/// This is a utility function to prompt the user for a sensitive string, probably a PIN or a PUK.
fn prompt_for_string(prompt: &str, confirm: bool) -> Result<String> {
    loop {
        let string = rpassword::prompt_password_stderr(prompt)?;
        if !confirm || string == rpassword::prompt_password_stderr("Confirm: ")? {
            return Ok(string);
        }
    }
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Version(u8, u8, u8);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

impl FromStr for Version {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let numbers: Vec<&str> = s.split('.').collect();
        if numbers.len() != 3 {
            bail!("Invalid Yubikey version string '{}'", s);
        }
        Ok(Version(
            numbers[0].parse::<u8>()?,
            numbers[1].parse::<u8>()?,
            numbers[2].parse::<u8>()?,
        ))
    }
}

struct MaybePromptedString<'a> {
    provided: Option<&'a str>,
    prompted: Option<String>,
}

impl<'a> MaybePromptedString<'a> {
    pub fn new(provided: Option<&'a str>, prompt: &str, confirm: bool) -> Result<Self> {
        let prompted: Option<String> = match provided {
            None => Some(prompt_for_string(prompt, confirm)?),
            Some(_) => None,
        };

        Ok(MaybePromptedString {
            provided: provided,
            prompted: prompted,
        })
    }

    pub fn was_provided(&self) -> bool {
        self.provided.is_some()
    }

    pub fn as_ptr(&self) -> *const c_char {
        self.provided.map_or_else(
            || {
                self.prompted
                    .as_ref()
                    .map_or_else(ptr::null, |s| s.as_ptr() as *const c_char)
            },
            |s| s.as_ptr() as *const c_char,
        )
    }

    pub fn len(&self) -> usize {
        self.provided.map_or_else(
            || self.prompted.as_ref().map_or(0, |s| s.len()),
            |s| s.len(),
        )
    }
}

fn get_management_key(mgm_key: Option<&str>) -> Result<Vec<c_uchar>> {
    let mgm_key = MaybePromptedString::new(mgm_key, MGM_KEY_PROMPT, false)?;
    let mut decoded: Vec<c_uchar> = vec![0; MGM_KEY_BYTES];
    let mut decoded_len: size_t = MGM_KEY_BYTES;
    if decoded_len != MGM_KEY_BYTES {
        bail!("Hex decoding failed: decoded length doesn't match expectations");
    }
    try_ykpiv(unsafe { ykpiv::ykpiv_hex_decode(mgm_key.as_ptr(), mgm_key.len(), decoded.as_mut_ptr(), &mut decoded_len) })?;
    Ok(decoded)
}

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
                error!(
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

    /// Connect to the PC/SC reader which matches the given reader string (or DEFAULT_READER, if
    /// one was not provided). The first reader which includes the given string as a substring will
    /// be used.
    pub fn connect(&mut self, reader: Option<&str>) -> Result<()> {
        let reader = CString::new(reader.unwrap_or(DEFAULT_READER)).unwrap();
        Ok(try_ykpiv(
            unsafe { ykpiv::ykpiv_connect(self.state, reader.as_ptr()) },
        )?)
    }

    /// Disconnect from the currently connected PC/SC reader. This is only necessary if you want to
    /// re-use this State to interact with a different reader.
    pub fn disconnect(&mut self) -> Result<()> {
        Ok(try_ykpiv(unsafe { ykpiv::ykpiv_disconnect(self.state) })?)
    }

    /// This function returns the version number the connected reader reports. Note that connect()
    /// must be called before this function, or an error will be returned.
    pub fn get_version(&self) -> Result<Version> {
        let mut buffer: Vec<c_char> = vec![0_i8; VERSION_BUFFER_SIZE];
        let result = try_ykpiv(unsafe {
            ykpiv::ykpiv_get_version(self.state, buffer.as_mut_ptr(), VERSION_BUFFER_SIZE)
        });
        if let Some(err) = result.as_ref().err() {
            if *err == ::piv::Error::from(ykpiv::YKPIV_PCSC_ERROR) {
                error!(
                    "Getting version returned a PC/SC error. Usually this means no Yubikey found."
                );
            }
        }
        result?;
        Ok(
            unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_str()?.parse()?,
        )
    }

    /// This function provides the common implementation for the various functions which can be
    /// used to change or unblock the Yubikey's PIN or PUK.
    fn change_pin_or_puk<F>(
        &mut self,
        existing_name: &str,
        existing: Option<&str>,
        new_name: &str,
        new: Option<&str>,
        existing_prompt: &str,
        new_prompt: &str,
        change_fn: F,
    ) -> Result<()>
    where
        F: Fn(*mut ykpiv::ykpiv_state, *const c_char, size_t, *const c_char, size_t, *mut c_int)
            -> ::std::result::Result<(), ::piv::Error>,
    {
        loop {
            let existing = MaybePromptedString::new(existing, existing_prompt, false)?;
            let new = MaybePromptedString::new(new, new_prompt, true)?;

            let mut tries: c_int = 0;
            let result = change_fn(
                self.state,
                existing.as_ptr(),
                existing.len(),
                new.as_ptr(),
                new.len(),
                &mut tries,
            );

            // If we changed the value successfully, stop here.
            if result.is_ok() {
                break;
            }

            if let Some(err) = result.err() {
                if err != ::piv::Error::from(ykpiv::YKPIV_WRONG_PIN) {
                    // We got some error other than the existing PIN or PUK being wrong (the same
                    // error is used for both). Return the error.
                    bail!(err);
                } else if existing.was_provided() {
                    // The given existing PIN or PUK was wrong, but it is static. Return the error
                    // without retrying.
                    bail!(err);
                } else if tries <= 0 {
                    // If we have no more tries available, return an error.
                    bail!("Changing {} failed: no more retries", new_name);
                } else {
                    // Otherwise, loop and re-prompt the user so they can try again.
                    error!(
                        "Incorrect {}, try again - {} tries remaining",
                        existing_name,
                        tries
                    );
                }
            }
        }

        Ok(())
    }

    /// This function allows the user to change the Yubikey's PIN, given that the user knows the
    /// existing PIN. The old and new PINs can be provided as function arguments. If they are not
    /// provided, this function will prompt for them on stdin.
    ///
    /// When prompting for a PIN, this function will automatically retry if PIN verification fails,
    /// until there are no more available retries. At that point, the PIN can be unblocked using
    /// the PUK.
    pub fn change_pin(&mut self, old_pin: Option<&str>, new_pin: Option<&str>) -> Result<()> {
        self.change_pin_or_puk(
            PIN_NAME,
            old_pin,
            PIN_NAME,
            new_pin,
            PIN_PROMPT,
            NEW_PIN_PROMPT,
            |state, existing, existing_len, new, new_len, tries| {
                try_ykpiv(unsafe {
                    ykpiv::ykpiv_change_pin(state, existing, existing_len, new, new_len, tries)
                })
            },
        )
    }

    /// This function allows the user to reset the Yubikey's PIN using the PUK, after the user has
    /// exhausted their allotted tries to enter the PIN correctly. The PUK and new PIN can be
    /// provided as function arguments. If they are not provided, this function will prompt for
    /// them on stdin.
    ///
    /// When prompting for a PUK, this function will automatically retry if PUK verification fails,
    /// until there are no more available retries. At that point, the Yubiey can be reset to
    /// factory defaults using the reset function.
    pub fn unblock_pin(&mut self, puk: Option<&str>, new_pin: Option<&str>) -> Result<()> {
        self.change_pin_or_puk(
            PUK_NAME,
            puk,
            PIN_NAME,
            new_pin,
            PUK_PROMPT,
            NEW_PIN_PROMPT,
            |state, existing, existing_len, new, new_len, tries| {
                try_ykpiv(unsafe {
                    ykpiv::ykpiv_unblock_pin(state, existing, existing_len, new, new_len, tries)
                })
            },
        )
    }

    /// This function allows the user to change the Yubikey's PUK, given that the user knows the
    /// existing PUK. The old and new PUKs can be provided as function arguments. If they are not
    /// provided, this function will prompt for them on stdin.
    ///
    /// When prompting for a PUK, this function will automatically retry if PUK verification fails,
    /// until there are no more available retries. At that point, the PIN and PUK can both be
    /// unblocked using the reset function.
    pub fn change_puk(&mut self, old_puk: Option<&str>, new_puk: Option<&str>) -> Result<()> {
        self.change_pin_or_puk(
            PUK_NAME,
            old_puk,
            PUK_NAME,
            new_puk,
            PUK_PROMPT,
            NEW_PUK_PROMPT,
            |state, existing, existing_len, new, new_len, tries| {
                try_ykpiv(unsafe {
                    ykpiv::ykpiv_change_puk(state, existing, existing_len, new, new_len, tries)
                })
            },
        )
    }

    /// This function resets the PIN, PUK, and management key to their factory default values, as
    /// well as delete any stored certificates and keys. The default values for the PIN and PUK are
    /// 123456 and 12345678, respectively.
    ///
    /// Note that this function will return an error unless the tries to verify the PIN and PUK
    /// have both been fully exhausted (e.g., the Yubikey is now unusable). Otherwise, the
    /// change_pin, unblock_pin, and change_puk functions should be used instead of this function.
    pub fn reset(&mut self) -> Result<()> {
        let templ: Vec<c_uchar> = vec![0, ykpiv::YKPIV_INS_RESET, 0, 0];
        let mut data: Vec<c_uchar> = vec![0; 255];
        let mut data_len: c_ulong = 0;
        let mut sw: c_int = 0;

        try_ykpiv(unsafe {
            ykpiv::ykpiv_transfer_data(
                self.state,
                templ.as_ptr(),
                ptr::null(),
                0,
                data.as_mut_ptr(),
                &mut data_len,
                &mut sw,
            )
        })?;
        if sw != ykpiv::SW_SUCCESS {
            bail!("Reset failed, probably because PIN or PUK retries are still available");
        }
        Ok(())
    }

    /// This function authenticates this state with the management key, unlocking various
    /// administrative / management functions. For details on what features require authentication,
    /// see: https://developers.yubico.com/PIV/Introduction/Admin_access.html
    pub fn authenticate(&mut self, mgm_key: Option<&str>) -> Result<()> {
        let mgm_key = get_management_key(mgm_key)?;
        try_ykpiv(unsafe { ykpiv::ykpiv_authenticate(self.state, mgm_key.as_ptr()) })?;
        Ok(())
    }
}

impl Drop for State {
    fn drop(&mut self) {
        if let Err(e) = try_ykpiv(unsafe { ykpiv::ykpiv_done(self.state) }) {
            error!("Cleaning up ykpiv state failed: {}", e);
        }
    }
}
