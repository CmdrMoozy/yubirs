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
use crate::piv::hal::PcscHal;
use crate::piv::handle::Handle;
use crate::piv::id;
use crate::piv::pkey::{Format, PublicKey};
use bdrck::crypto::key::{AbstractKey, Digest, Nonce};
use failure::format_err;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;

/// Key is an AbstractKey structure using a public/private key pair stored on a
/// PC/SC hardware device. The idea is that we can use a hardware key for
/// encryption / decryption, and thus can use it as a wrapping key in a
/// KeyStore.
pub struct Key<T: PcscHal> {
    handle: Mutex<Handle<T>>,
    pin: Option<String>,
    slot: id::Key,
    public_key: PublicKey,
    digest: Digest,
}

impl<T: PcscHal> Key<T> {
    /// Construct a new Key instance.
    ///
    /// This requires instantiating a new PIV handle, with the given reader (if
    /// any), and using the given PIN (if not specified, it will be prompted for
    /// instead) for authentication.
    ///
    /// Encryption is done using the given public key instance, and descryption
    /// is done using the private key stored in the given slot on the hardware
    /// device.
    pub fn new(
        reader: Option<&str>,
        pin: Option<&str>,
        slot: id::Key,
        public_key: PublicKey,
    ) -> Result<Self> {
        let mut handle: Handle<T> = Handle::new()?;
        handle.connect(reader)?;

        let public_key_data = public_key.format(Format::Pem)?;

        Ok(Key {
            handle: Mutex::new(handle),
            pin: pin.map(|p| p.to_owned()),
            slot: slot,
            public_key: public_key,
            digest: Digest::from_bytes(public_key_data.as_slice()),
        })
    }

    /// Construct a new Key instance.
    ///
    /// This is equivalent to `new`, except the public key is read from the
    /// given arbitary `Read` instance.
    pub fn new_from_read<R: Read>(
        reader: Option<&str>,
        pin: Option<&str>,
        slot: id::Key,
        public_key: R,
    ) -> Result<Self> {
        let public_key = PublicKey::from_pem(public_key)?;
        Self::new(reader, pin, slot, public_key)
    }

    /// Construct a new Key instance.
    ///
    /// This is equivalent to `new`, except the public key is read from a
    /// regular file.
    pub fn new_from_file<P: AsRef<Path>>(
        reader: Option<&str>,
        pin: Option<&str>,
        slot: id::Key,
        public_key: P,
    ) -> Result<Self> {
        let f = fs::File::open(public_key)?;
        Self::new_from_read(reader, pin, slot, f)
    }
}

impl<T: PcscHal> AbstractKey for Key<T> {
    fn get_digest(&self) -> Digest {
        self.digest.clone()
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: Option<Nonce>,
    ) -> ::std::result::Result<(Option<Nonce>, Vec<u8>), ::failure::Error> {
        if nonce.is_some() {
            return Err(Error::InvalidArgument(format_err!(
                "Smart card hardware key encryption does not use nonces"
            ))
            .into());
        }
        let ciphertext = {
            let handle = self.handle.lock().unwrap();
            handle.encrypt(&self.public_key, plaintext)?.1
        };
        Ok((None, ciphertext))
    }

    fn decrypt(
        &self,
        nonce: Option<&Nonce>,
        ciphertext: &[u8],
    ) -> ::std::result::Result<Vec<u8>, ::failure::Error> {
        if nonce.is_some() {
            return Err(Error::InvalidArgument(format_err!(
                "Smart card hardware key decryption does not use nonces"
            ))
            .into());
        }
        let plaintext = {
            let mut handle = self.handle.lock().unwrap();
            handle.decrypt(
                self.pin.as_ref().map(|p| p.as_str()),
                ciphertext,
                self.slot,
                self.public_key.get_algorithm()?,
            )?
        };
        Ok(plaintext)
    }
}
