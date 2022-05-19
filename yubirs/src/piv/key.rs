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
use bdrck::crypto::digest::Digest;
use bdrck::crypto::key::{AbstractKey, Nonce};
use bdrck::crypto::secret::Secret;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Mutex;

#[derive(Deserialize, Serialize)]
struct KeyMetadata {
    reader: Option<String>,
    pin: Option<String>,
    slot: id::Key,
    public_key_data: Vec<u8>,
}

/// Key is an AbstractKey structure using a public/private key pair stored on a
/// PC/SC hardware device. The idea is that we can use a hardware key for
/// encryption / decryption, and thus can use it as a wrapping key in a
/// KeyStore.
pub struct Key<T: PcscHal> {
    handle: Mutex<Handle<T>>,
    public_key: PublicKey,
    digest: Digest,
    metadata: KeyMetadata,
}

impl<T: PcscHal> Key<T> {
    fn new_impl(metadata: KeyMetadata, public_key: Option<PublicKey>) -> Result<Self> {
        let mut handle: Handle<T> = Handle::new()?;
        handle.connect(metadata.reader.as_ref().map(|r| r.as_str()))?;

        Ok(Key {
            handle: Mutex::new(handle),
            public_key: match public_key {
                Some(pk) => pk,
                None => {
                    let cur = Cursor::new(metadata.public_key_data.as_slice());
                    PublicKey::from_pem(cur)?
                }
            },
            digest: Digest::from_bytes(metadata.public_key_data.as_slice()),
            metadata: metadata,
        })
    }

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
        Self::new_impl(
            KeyMetadata {
                reader: reader.map(|r| r.to_owned()),
                pin: pin.map(|p| p.to_owned()),
                slot: slot,
                public_key_data: public_key.format(Format::Pem)?,
            },
            Some(public_key),
        )
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
    type Error = Error;

    fn get_digest(&self) -> Digest {
        self.digest.clone()
    }

    fn serialize(&self) -> std::result::Result<Secret, Self::Error> {
        // We don't actually keep any private key data in memory, so not important to keep the
        // data secret.
        let data = rmp_serde::encode::to_vec(&self.metadata)?;
        let mut s = Secret::with_len(data.len())?;
        unsafe { s.as_mut_slice() }.copy_from_slice(&data);
        Ok(s)
    }

    fn deserialize(data: Secret) -> std::result::Result<Self, Self::Error> {
        // We don't actually keep any private key data in memory, so not important to keep the
        // data secret.
        Self::new_impl(
            rmp_serde::decode::from_slice(unsafe { data.as_slice() })?,
            None,
        )
    }

    fn encrypt(
        &self,
        plaintext: &Secret,
        nonce: Option<Nonce>,
    ) -> std::result::Result<(Option<Nonce>, Vec<u8>), Self::Error> {
        if nonce.is_some() {
            return Err(Error::InvalidArgument(format!(
                "smart card hardware key encryption does not use nonces"
            ))
            .into());
        }
        let ciphertext = {
            let handle = self.handle.lock().unwrap();
            handle
                .encrypt(&self.public_key, unsafe { plaintext.as_slice() })?
                .1
        };
        Ok((None, ciphertext))
    }

    fn decrypt(
        &self,
        nonce: Option<&Nonce>,
        ciphertext: &[u8],
    ) -> std::result::Result<Secret, Self::Error> {
        if nonce.is_some() {
            return Err(Error::InvalidArgument(format!(
                "smart card hardware key decryption does not use nonces"
            ))
            .into());
        }

        Ok({
            let pt = {
                let mut handle = self.handle.lock().unwrap();
                handle.decrypt(
                    self.metadata.pin.as_ref().map(|p| p.as_str()),
                    ciphertext,
                    self.metadata.slot,
                    self.public_key.get_algorithm()?,
                )?
            };

            let mut plaintext = Secret::with_len(pt.len())?;
            unsafe { plaintext.as_mut_slice() }.copy_from_slice(pt.as_slice());
            plaintext
        })
    }
}
