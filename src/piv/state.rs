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

use cert::{format_certificate, Format};
use error::*;
use libc::c_ulong;
use piv::try_ykpiv;
use piv::id::{Key, Object};
use yubico_piv_tool_sys as ykpiv;
use yubico_piv_tool_sys::Version;

const OBJECT_BUFFER_SIZE: usize = 3072;

pub struct State {
    state: ykpiv::ykpiv_state,
}

impl State {
    pub fn new(verbose: bool) -> Result<State> {
        Ok(State {
            state: ykpiv::ykpiv_state::new(verbose)?,
        })
    }

    /// This function returns the list of valid reader strings which can be passed to State::new.
    pub fn list_readers(&self) -> Result<Vec<String>> {
        Ok(self.state.list_readers()?)
    }

    /// Connect to the PC/SC reader which matches the given reader string (or DEFAULT_READER, if
    /// one was not provided). The first reader which includes the given string as a substring will
    /// be used.
    pub fn connect(&mut self, reader: Option<&str>) -> Result<()> {
        Ok(self.state.connect(reader)?)
    }

    /// Disconnect from the currently connected PC/SC reader. This is only necessary if you want to
    /// re-use this State to interact with a different reader.
    pub fn disconnect(&mut self) {
        self.state.disconnect()
    }

    /// This function returns the version number the connected reader reports. Note that connect()
    /// must be called before this function, or an error will be returned.
    pub fn get_version(&self) -> Result<Version> {
        Ok(self.state.get_version()?)
    }

    /// This function allows the user to change the Yubikey's PIN, given that the user knows the
    /// existing PIN. The old and new PINs can be provided as function arguments. If they are not
    /// provided, this function will prompt for them on stdin.
    ///
    /// When prompting for a PIN, this function will automatically retry if PIN verification fails,
    /// until there are no more available retries. At that point, the PIN can be unblocked using
    /// the PUK.
    pub fn change_pin(&mut self, old_pin: Option<&str>, new_pin: Option<&str>) -> Result<()> {
        Ok(self.state.change_pin(old_pin, new_pin)?)
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
        Ok(self.state.unblock_pin(puk, new_pin)?)
    }

    /// This function allows the user to change the Yubikey's PUK, given that the user knows the
    /// existing PUK. The old and new PUKs can be provided as function arguments. If they are not
    /// provided, this function will prompt for them on stdin.
    ///
    /// When prompting for a PUK, this function will automatically retry if PUK verification fails,
    /// until there are no more available retries. At that point, the PIN and PUK can both be
    /// unblocked using the reset function.
    pub fn change_puk(&mut self, old_puk: Option<&str>, new_puk: Option<&str>) -> Result<()> {
        Ok(self.state.change_puk(old_puk, new_puk)?)
    }

    /// This function resets the PIN, PUK, and management key to their factory default values, as
    /// well as delete any stored certificates and keys. The default values for the PIN and PUK are
    /// 123456 and 12345678, respectively.
    ///
    /// Note that this function will return an error unless the tries to verify the PIN and PUK
    /// have both been fully exhausted (e.g., the Yubikey is now unusable). Otherwise, the
    /// change_pin, unblock_pin, and change_puk functions should be used instead of this function.
    pub fn reset(&mut self) -> Result<()> {
        Ok(self.state.reset()?)
    }

    /// This function sets the number of retries available for PIN or PUK verification. This also
    /// resets the PIN and PUK back to their factory default values, 123456 and 12345678,
    /// respectively.
    ///
    /// Note that this function is slightly strange compared to the rest of the API, in that both
    /// the management key *and* the current PIN are required.
    pub fn set_retries(
        &mut self,
        mgm_key: Option<&str>,
        pin: Option<&str>,
        pin_retries: u8,
        puk_retries: u8,
    ) -> Result<()> {
        Ok(self.state.set_retries(
            mgm_key,
            pin,
            pin_retries,
            puk_retries,
        )?)
    }

    /// This function changes the management key stored on the device. This is the key used to
    /// authenticate() for administrative / management access.
    pub fn set_management_key(
        &mut self,
        old_mgm_key: Option<&str>,
        new_mgm_key: Option<&str>,
        touch: bool,
    ) -> Result<()> {
        Ok(self.state.set_management_key(
            old_mgm_key,
            new_mgm_key,
            touch,
        )?)
    }

    /// This function writes a new, randomly-generated Card Holder Unique Identifier (CHUID) to the
    /// device. Some systems (Windows) require a CHUID to be present before they will recognize the
    /// Yubikey. This data object is not present on Yubikeys by default (from the factory).
    ///
    /// Also note that, according to the Yubikey docs, the card contents are aggressively cached on
    /// Windows. In order to invalidate the cached data, e.g. after changing stored certificates,
    /// the CHUID must also be changed.
    pub fn set_chuid(&mut self, mgm_key: Option<&str>) -> Result<()> {
        Ok(self.state.set_chuid(mgm_key)?)
    }

    /// This function writes a new, randomly-generated Card Capability Container (CCC) to the
    /// device. Some systems (MacOS) require a CCC to be present before they will recognize the
    /// Yubikey. This data object is not present on Yubikeys by default (from the factory).
    pub fn set_ccc(&mut self, mgm_key: Option<&str>) -> Result<()> {
        Ok(self.state.set_ccc(mgm_key)?)
    }

    /// Read a data object from the Yubikey, returning the byte contents.
    pub fn read_object(&mut self, id: Object) -> Result<Vec<u8>> {
        let mut buffer: Vec<u8> = vec![0; OBJECT_BUFFER_SIZE];
        let mut len: c_ulong = OBJECT_BUFFER_SIZE as c_ulong;
        try_ykpiv(unsafe {
            // TODO: Pass self.state as an immutable borrow.
            ykpiv::ykpiv_fetch_object(
                &mut self.state,
                id.to_value(),
                buffer.as_mut_ptr(),
                &mut len,
            )
        })?;
        buffer.truncate(len as usize);
        Ok(buffer)
    }

    /// Write a data object to the Yubikey. This function takes ownership of the data, because
    /// upstream's API requires a mutable data buffer.
    pub fn write_object(
        &mut self,
        mgm_key: Option<&str>,
        id: Object,
        buffer: Vec<u8>,
    ) -> Result<()> {
        Ok(self.state.write_object(mgm_key, id.to_value(), buffer)?)
    }

    /// This is a convenience function to read a certificate's data object from the Yubikey, and
    /// then return it formatted in a specified way.
    pub fn read_certificate(&mut self, id: Key, format: Format) -> Result<String> {
        let data = self.read_object(id.to_object()?)?;
        format_certificate(data.as_slice(), format)
    }
}
