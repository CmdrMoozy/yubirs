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

use crate::crypto::*;
use crate::error::*;
use crate::piv::apdu::{self, Apdu};
use crate::piv::hal::PcscHal;
use crate::piv::id::*;
use crate::piv::pkey::{PrivateKey, PublicKey, PublicKeyCertificate};
use crate::piv::scarderr::SmartCardErrorCode;
use crate::piv::sw::StatusWord;
use crate::piv::util::MaybePromptedCString;
use data_encoding;
use libc::c_int;
use log::debug;
use openssl;
use openssl_sys;
use std::fmt;
use std::path::Path;

const PIN_NAME: &'static str = "PIN";
const PIN_PROMPT: &'static str = "PIN: ";
const NEW_PIN_PROMPT: &'static str = "New PIN: ";

const PUK_NAME: &'static str = "PUK";
const PUK_PROMPT: &'static str = "PUK: ";
const NEW_PUK_PROMPT: &'static str = "New PUK: ";

const MGM_KEY_PROMPT: &'static str = "Management Key: ";
const NEW_MGM_KEY_PROMPT: &'static str = "New Management Key: ";

// TODO: This CHUID has an expiry of 2030-01-01, it should be configurable instead.
/// FASC-N containing S9999F9999F999999F0F1F0000000000300001E encoded in 4-bit BCD with 1-bit
/// parity. This can be run through
/// https://github.com/Yubico/yubico-piv-tool/blob/master/tools/fasc.pl to get bytes.
#[cfg_attr(rustfmt, rustfmt_skip)]
const CHUID_TEMPLATE: &'static [u8] = &[
    0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68,
    0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x38, 0x42, 0x10, 0xc3, 0xf5, 0x34, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x35, 0x08, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,
];
const CHUID_RANDOM_OFFSET: usize = 29;
const CHUID_RANDOM_BYTES: usize = 16;

#[cfg_attr(rustfmt, rustfmt_skip)]
const CCC_TEMPLATE: &'static [u8] = &[
    0xf0, 0x15, 0xa0, 0x00, 0x00, 0x01, 0x16, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x01, 0x21, 0xf2, 0x01, 0x21, 0xf3,
    0x00, 0xf4, 0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7, 0x00, 0xfa, 0x00, 0xfb, 0x00,
    0xfc, 0x00, 0xfd, 0x00, 0xfe, 0x00,
];
const CCC_RANDOM_OFFSET: usize = 9;
const CCC_RANDOM_BYTES: usize = 14;

enum VerificationResult {
    /// The verification was successful.
    Success,
    /// The verification failed, but can be reattempted some number of times.
    Failure(usize, Error),
    /// Verification failed, and there are no more retries available, so the failure is permanent.
    PermanentFailure(Error),
    /// The verification failed for some other reason. There may or may not be retries left for
    /// other types of failures.
    OtherFailure(Error),
}

impl VerificationResult {
    pub fn from_status(sw: StatusWord) -> VerificationResult {
        if let Err(e) = sw.error {
            if let Some(counter) = sw.counter {
                if counter == 0 {
                    VerificationResult::PermanentFailure(e)
                } else {
                    VerificationResult::Failure(counter, e)
                }
            } else {
                VerificationResult::OtherFailure(e)
            }
        } else {
            VerificationResult::Success
        }
    }
}

/// This is a generic function which implements the boilerplate needed to execute some other
/// function which requires verification of some sort. This function will prompt for a value if one
/// is not provided, using the given prompt string. The name parameter should describe what the
/// value is, for human-readable error messages in case of failure.
fn verification_loop<F>(name: &str, value: Option<&str>, prompt: &str, callback: F) -> Result<()>
where
    F: Fn(&MaybePromptedCString) -> VerificationResult,
{
    loop {
        let value = MaybePromptedCString::new(value, prompt, false)?;
        match callback(&value) {
            VerificationResult::Success => return Ok(()),
            VerificationResult::Failure(tries, err) => {
                debug!("Incorrect {}, {} tries remaining: {}", name, tries, err);
                // If we didn't prompt for a value, retrying won't help, because we'd just be
                // retrying with the same value over again. In this case, just bail now.
                match value.was_provided() {
                    false => eprintln!("Incorrect {}, try again - {} tries remaining", name, tries),
                    true => return Err(err),
                };
            }
            VerificationResult::PermanentFailure(err) => {
                debug!("Incorrect {}, 0 tries remaining: {}", name, err);
                return Err(Error::Authentication(format!(
                    "verifying {} failed: no more retries",
                    name
                )));
            }
            VerificationResult::OtherFailure(err) => return Err(err),
        }
    }
}

/// This is a generic function which implements the boilerplate needed to verify and then change
/// some value. For example, changing the Yubikey's PIN or PUK after verifying the PIN or PUK. This
/// function will prompt for both an existing and a new value if they are not provided, using the
/// given names for human-readable error messages and the prompt strings for prompting the user.
fn verification_change_loop<F>(
    existing_name: &str,
    existing: Option<&str>,
    new: Option<&str>,
    existing_prompt: &str,
    new_prompt: &str,
    callback: F,
) -> Result<()>
where
    F: Fn(&MaybePromptedCString, &MaybePromptedCString) -> VerificationResult,
{
    verification_loop(existing_name, existing, existing_prompt, |existing| {
        let new = match MaybePromptedCString::new(new.clone(), new_prompt, true) {
            Err(err) => return VerificationResult::OtherFailure(err),
            Ok(new) => new,
        };
        callback(existing, &new)
    })
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum ChangeAction {
    ChangePin,
    UnblockPin,
    ChangePuk,
}

fn build_data_object<T: PcscHal>(
    hal: &T,
    template: &'static [u8],
    random_offset: usize,
    random_bytes_len: usize,
) -> Result<Vec<u8>> {
    let mut object: Vec<u8> = Vec::with_capacity(template.len());
    object.extend_from_slice(&template[..random_offset]);

    let mut random_bytes: Vec<u8> = vec![0; random_bytes_len];
    hal.cheap_random_bytes(&mut random_bytes)?;
    object.extend(random_bytes.into_iter());

    object.extend_from_slice(&template[random_offset + random_bytes_len..]);
    Ok(object)
}

fn ykpiv_save_object<T: PcscHal>(hal: &T, id: Object, mut buffer: Vec<u8>) -> Result<()> {
    let mut data: Vec<u8> = vec![0x5c];
    if id == Object::Discovery {
        data.extend_from_slice(&[1, id.to_value() as u8]);
    } else if id.to_value() > 0xffff && id.to_value() <= 0xffffff {
        data.extend_from_slice(&[
            3,
            ((id.to_value() >> 16) & 0xff) as u8,
            ((id.to_value() >> 8) & 0xff) as u8,
            (id.to_value() & 0xff) as u8,
        ]);
    }
    data.push(0x53);
    if buffer.len() < 0x80 {
        data.push(buffer.len() as u8);
    } else if buffer.len() < 0xff {
        data.extend_from_slice(&[0x81, buffer.len() as u8]);
    } else {
        data.extend_from_slice(&[
            0x82,
            ((buffer.len() >> 8) & 0xff) as u8,
            (buffer.len() & 0xff) as u8,
        ]);
    }
    data.append(&mut buffer);

    let (sw, _) = hal.send_data(
        &[0, Instruction::PutData.to_value(), 0x3f, 0xff],
        data.as_slice(),
    )?;
    sw.error?;
    Ok(())
}

// TODO: This function can be cleaned up / code can be reused.
fn sign_decipher_impl<T: PcscHal>(
    hal: &T,
    data: &[u8],
    algorithm: Algorithm,
    key: Key,
    decipher: bool,
) -> Result<Vec<u8>> {
    if !algorithm.is_rsa() && !algorithm.is_ecc() {
        return Err(Error::InvalidArgument(format!(
            "data signing / deciphering only supports RSA or EC algorithms"
        )));
    }

    let key_len: usize = match algorithm {
        Algorithm::Rsa1024 => 128,
        Algorithm::Rsa2048 => 256,
        Algorithm::Eccp256 => 32,
        Algorithm::Eccp384 => 48,
        _ => 0,
    };

    if algorithm.is_rsa() && data.len() != key_len {
        return Err(Error::InvalidArgument(format!(
            "invalid input data; expected exactly {} bytes",
            key_len
        )));
    } else if algorithm.is_ecc() {
        if !decipher && data.len() > key_len {
            return Err(Error::InvalidArgument(format!(
                "invalid input data; expected at most {} bytes",
                key_len
            )));
        } else if decipher && data.len() != (key_len * 2) + 1 {
            return Err(Error::InvalidArgument(format!(
                "invalid input data; expected exactly {} bytes",
                (key_len * 2) + 1
            )));
        }
    }

    // TODO: It's unclear what this length really represents? Rename it.
    let len_to_send: usize = if data.len() < 0x80 {
        data.len() + 1 + 3
    } else if data.len() < 0xff {
        data.len() + 2 + 3
    } else {
        data.len() + 3 + 3
    };

    let mut data_to_send: Vec<u8> = Vec::new();
    data_to_send.push(0x7c);
    if len_to_send < 0x80 {
        data_to_send.push(len_to_send as u8);
    } else if len_to_send < 0xff {
        data_to_send.extend_from_slice(&[0x81, len_to_send as u8]);
    } else {
        data_to_send.extend_from_slice(&[
            0x82,
            ((len_to_send >> 8) & 0xff) as u8,
            (len_to_send & 0xff) as u8,
        ]);
    }
    data_to_send.extend_from_slice(&[
        0x82,
        0x00,
        if algorithm.is_ecc() && decipher {
            0x85
        } else {
            0x81
        },
    ]);
    if data.len() < 0x80 {
        data_to_send.push(data.len() as u8);
    } else if data.len() < 0xff {
        data_to_send.extend_from_slice(&[0x81, data.len() as u8]);
    } else {
        data_to_send.extend_from_slice(&[
            0x82,
            ((data.len() >> 8) & 0xff) as u8,
            (data.len() & 0xff) as u8,
        ]);
    }
    data_to_send.extend_from_slice(data);

    let (sw, recv) = hal.send_data(
        &[
            0,
            Instruction::Authenticate.to_value(),
            algorithm.to_value(),
            key.to_value(),
        ],
        &data_to_send,
    )?;
    sw.error?;

    // Skip the first 7c tag.
    match recv.get(0) {
        None => {
            return Err(Error::Internal(format!(
                "failed to parse tag from signature reply: reply too short"
            )));
        }
        Some(b) => {
            if *b != 0x7c {
                return Err(Error::Internal(format!(
                    "failed to parse tag from signature reply: got {:02x}, expected {:02x}",
                    *b, 0x7c
                )));
            }
        }
    }
    let (recv_slice, _) = crate::piv::util::read_length(&recv[1..])?;
    // Note that we *don't* skip over len bytes here. This is intentional.

    // Skip the 82 tag.
    match recv_slice.get(0) {
        None => {
            return Err(Error::Internal(format!(
                "failed to parse tag from signature reply: reply too short"
            )));
        }
        Some(b) => {
            if *b != 0x82 {
                return Err(Error::Internal(format!(
                    "failed to parse tag from signature reply: got {:02x}, expected {:02x}",
                    *b, 0x82
                )));
            }
        }
    }
    let (recv_slice, len) = crate::piv::util::read_length(&recv_slice[1..])?;

    Ok((&recv_slice[0..len]).into())
}

// TODO: Actually make use of this function. :)
#[allow(dead_code)]
fn ykpiv_sign_data<T: PcscHal>(
    hal: &T,
    data: &[u8],
    algorithm: Algorithm,
    key: Key,
) -> Result<Vec<u8>> {
    sign_decipher_impl(hal, data, algorithm, key, false)
}

fn import_private_key<T: PcscHal>(
    hal: &T,
    slot: Key,
    key: &PrivateKey,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<()> {
    let algorithm = key.get_algorithm()?;

    let elem_len: usize = match algorithm {
        Algorithm::Rsa1024 => 64,
        Algorithm::Rsa2048 => 128,
        Algorithm::Eccp256 => 32,
        Algorithm::Eccp384 => 48,
        _ => 0,
    };

    let params = key.get_components()?;

    let param_tag: u8 = match algorithm {
        Algorithm::Rsa1024 => 0x01,
        Algorithm::Rsa2048 => 0x01,
        Algorithm::Eccp256 => 0x06,
        Algorithm::Eccp384 => 0x06,
        _ => 0,
    };

    // TODO: Actually verify `params` lengths match `elem_len`.
    let mut key_data: Vec<u8> = Vec::with_capacity(1024);
    for i in 0..params.len() {
        key_data.push(param_tag + (i as u8));
        if elem_len < 0x80 {
            key_data.push(elem_len as u8);
        } else if elem_len < 0xff {
            key_data.extend_from_slice(&[0x81, elem_len as u8]);
        } else {
            key_data.extend_from_slice(&[
                0x82,
                ((elem_len >> 8) & 0xff) as u8,
                (elem_len & 0xff) as u8,
            ]);
        }
        let new_len = key_data.len() + (elem_len - params[i].len());
        key_data.resize(new_len, 0);
        key_data.extend_from_slice(params[i].as_slice());
    }

    if pin_policy != PinPolicy::Default {
        key_data.extend_from_slice(&[Tag::PinPolicy.to_value(), 0x01, pin_policy.to_value()]);
    }

    if touch_policy != TouchPolicy::Default {
        key_data.extend_from_slice(&[Tag::TouchPolicy.to_value(), 0x01, touch_policy.to_value()]);
    }

    let (sw, _) = hal.send_data(
        &[
            0,
            Instruction::ImportKey.to_value(),
            algorithm.to_value(),
            slot.to_value(),
        ],
        key_data.as_slice(),
    )?;
    sw.error
}

/// This function provides the common implementation for all of the various ways we can change the
/// PIN or PUK on a Yubikey. The way we do this using low-level PC/SC functions is identical,
/// except we send a different action value depending on the requested change type.
fn change_impl<T: PcscHal>(
    hal: &T,
    action: ChangeAction,
    existing: &MaybePromptedCString,
    new: &MaybePromptedCString,
) -> VerificationResult {
    if existing.len() > 8 {
        return VerificationResult::OtherFailure(Error::InvalidArgument(format!(
            "invalid existing {}; it exceeds 8 characters",
            match action {
                ChangeAction::ChangePin => PIN_NAME,
                ChangeAction::UnblockPin => PIN_NAME,
                ChangeAction::ChangePuk => PUK_NAME,
            }
        )));
    }
    if new.len() > 8 {
        return VerificationResult::OtherFailure(Error::InvalidArgument(format!(
            "invalid new {}; it exceeds 8 characters",
            match action {
                ChangeAction::ChangePin => PIN_NAME,
                ChangeAction::UnblockPin => PIN_NAME,
                ChangeAction::ChangePuk => PUK_NAME,
            }
        )));
    }

    let mut templ: Vec<u8> = vec![0, Instruction::ChangeReference.to_value(), 0, 0x80];
    if action == ChangeAction::UnblockPin {
        templ[1] = Instruction::ResetRetry.to_value();
    }
    if action == ChangeAction::ChangePuk {
        templ[3] = 0x81;
    }

    let mut in_data: Vec<u8> = vec![0; 16];
    for (dst, src) in in_data.iter_mut().zip(existing.as_bytes()) {
        *dst = *src;
    }
    for b in in_data
        .iter_mut()
        .skip(existing.len())
        .take(8 - existing.len())
    {
        *b = 0xff;
    }
    for (dst, src) in in_data.iter_mut().skip(8).zip(new.as_bytes()) {
        *dst = *src;
    }
    for b in in_data.iter_mut().skip(8 + new.len()).take(8 - new.len()) {
        *b = 0xff;
    }

    match hal.send_data(templ.as_slice(), in_data.as_slice()) {
        Err(e) => VerificationResult::OtherFailure(e),
        Ok((sw, _)) => VerificationResult::from_status(sw),
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Version(pub u8, pub u8, pub u8);

impl Version {
    pub fn new(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            return Err(Error::InvalidArgument(format!(
                "version data must be three bytes long."
            )));
        }
        Ok(Version(data[0], data[1], data[2]))
    }

    pub fn major(&self) -> u8 {
        self.0
    }
    pub fn minor(&self) -> u8 {
        self.1
    }
    pub fn patch(&self) -> u8 {
        self.2
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Serial(pub u32);

impl Serial {
    pub fn new(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::InvalidArgument(format!(
                "serial number data must be four bytes long."
            )));
        }
        Ok(Serial(u32::from_be_bytes([
            data[0], data[1], data[2], data[3],
        ])))
    }
}

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A Handle representing a connection to an underlying PC/SC device. This
/// struct is parameterized on a PcscHal implementation, so the underlying
/// hardware implementation can be swapped out as long as it is "compatible"
/// with the PC/SC library, in some sense.
///
/// Users of this struct must `connect` before calling most API functions.
///
/// Many API functions also require authentication. The authentication secrets
/// can either be passed in, or alternatively will be prompted for on stdin. The
/// following table denotes which functions require which kind of
/// authentication:
///
/// | Function           | MGM Key | PIN | PUK | Notes                      |
/// | ------------------ |:-------:|:---:|:---:| -------------------------- |
/// | list_readers       |         |     |     |                            |
/// | connect            |         |     |     |                            |
/// | disconnect         |         |     |     |                            |
/// | get_version        |         |     |     |                            |
/// | get_serial         |         |     |     |                            |
/// | change_pin         |         | X   |     |                            |
/// | unblock_pin        |         |     | X   |                            |
/// | change_puk         |         |     | X   |                            |
/// | reset              |         |     |     | PIN + PUK must be blocked. |
/// | set_retries        | X       | X   |     |                            |
/// | set_management_key | X       |     |     |                            |
/// | set_chuid          | X       |     |     |                            |
/// | set_ccc            | X       |     |     |                            |
/// | read_object        |         |     |     |                            |
/// | write_object       | X       |     |     |                            |
/// | generate           | X       |     |     |                            |
/// | import_key         | X       |     |     |                            |
/// | attest             |         |     |     |                            |
/// | read_certificate   |         |     |     |                            |
/// | encrypt            |         |     |     |                            |
/// | decrypt            |         | X   |     |                            |
pub struct Handle<T: PcscHal> {
    hal: T,
    authenticated_pin: bool,
    authenticated_mgm: bool,
}

impl<T: PcscHal> Handle<T> {
    pub fn new() -> Result<Self> {
        Ok(Handle {
            hal: T::new()?,
            authenticated_pin: false,
            authenticated_mgm: false,
        })
    }

    pub fn new_with_hal(hal: T) -> Self {
        Handle {
            hal: hal,
            authenticated_pin: false,
            authenticated_mgm: false,
        }
    }

    pub fn get_hal(&self) -> &T {
        &self.hal
    }

    pub fn get_hal_mut(&mut self) -> &mut T {
        &mut self.hal
    }

    fn authenticate_pin(&mut self, pin: Option<&str>) -> Result<()> {
        if self.authenticated_pin {
            return Ok(());
        }

        verification_loop(PIN_NAME, pin, PIN_PROMPT, |pin| {
            if pin.len() > 8 {
                return VerificationResult::OtherFailure(Error::InvalidArgument(format!(
                    "invalid PIN; it exceeds 8 characters"
                )));
            }

            let mut data: [u8; 8] = [0xff; 8];
            for (dst, src) in data.iter_mut().zip(pin.as_bytes()) {
                *dst = *src;
            }

            match self
                .hal
                .send_data(&[0, Instruction::Verify.to_value(), 0x00, 0x80], &data)
            {
                Err(e) => VerificationResult::OtherFailure(e),
                Ok((sw, _)) => VerificationResult::from_status(sw),
            }
        })?;
        Ok(())
    }

    fn authenticate_mgm(&mut self, mgm_key: Option<&str>) -> Result<()> {
        if self.authenticated_mgm {
            return Ok(());
        }

        let mgm_key: Vec<u8> = data_encoding::HEXLOWER_PERMISSIVE
            .decode(MaybePromptedCString::new(mgm_key, MGM_KEY_PROMPT, false)?.as_bytes())?;
        // For 3DES, we should have three key portions of 8 bytes each, for a total of 24 bytes.
        debug_assert!(mgm_key.len() == MGM_KEY_BYTES);

        // Get a challenge from the card.
        let mut data: [u8; 255] = [0; 255];
        data[0] = 0x7c;
        data[1] = 0x02;
        data[2] = 0x80;
        let apdu = Apdu::from_pieces(
            0,
            Instruction::Authenticate.to_value(),
            Algorithm::Des.to_value(),
            Key::CardManagement.to_value(),
            0x04,
            &data,
        )?;
        let (sw, response) = self.hal.send_data_impl(&apdu)?;
        sw.error?;
        let card_challenge: Vec<u8> = (&response[4..12]).into();
        debug_assert!(card_challenge.len() == 8);

        // Send a response to the card's challenge, and a challenge of our own.
        let our_challenge = decrypt_des_challenge(mgm_key.as_slice(), card_challenge.as_slice())?;
        let mut data: [u8; 255] = [0; 255];
        data[0] = 0x7c;
        data[1] = 20; // 2 + 8 + 2 + 8
        data[2] = 0x80;
        data[3] = 8;
        (&mut data[4..12]).copy_from_slice(our_challenge.as_slice());
        data[12] = 0x81;
        data[13] = 8;
        self.hal.secure_random_bytes(&mut data[14..22])?;
        let expected_card_reply: Vec<u8> = (&data[14..22]).into();
        let apdu = Apdu::from_pieces(
            0,
            Instruction::Authenticate.to_value(),
            Algorithm::Des.to_value(),
            Key::CardManagement.to_value(),
            22,
            &data,
        )?;
        let (sw, response) = self.hal.send_data_impl(&apdu)?;
        sw.error?;

        // Compare the response from the card with our expected response.
        let expected_card_reply =
            encrypt_des_challenge(mgm_key.as_slice(), expected_card_reply.as_slice())?;
        if expected_card_reply.as_slice() != &response[4..12] {
            return Err(Error::Authentication(format!(
                "management key authentication failed"
            )));
        }

        Ok(())
    }

    /// This function returns the list of valid reader strings which can be
    /// passed to State::new.
    pub fn list_readers(&self) -> Result<Vec<String>> {
        self.hal.list_readers()
    }

    /// Connect to the PC/SC reader which matches the given reader string (or
    /// DEFAULT_READER, if one was not provided). The first reader which
    /// includes the given string as a substring will be used.
    pub fn connect(&mut self, reader: Option<&str>) -> Result<()> {
        self.hal.connect(reader)
    }

    /// Disconnect from the currently connected PC/SC reader. This is only
    /// necessary if you want to re-use this State to interact with a different
    /// reader.
    pub fn disconnect(&mut self) {
        self.hal.disconnect()
    }

    /// This function returns the version number the connected reader reports.
    /// Note that connect() must be called before this function, or an error
    /// will be returned.
    pub fn get_version(&self) -> Result<Version> {
        let (sw, buffer) = self
            .hal
            .send_data(&[0, Instruction::GetVersion.to_value(), 0, 0, 0], &[])?;
        sw.error?;
        Ok(Version::new(buffer.as_slice())?)
    }

    /// This function returns the serial number of the connected reader. This
    /// is a number which uniquely identifes this device from others of the
    /// same model. Note that connect() must be called before this function, or
    /// an error will be returned.
    pub fn get_serial(&self) -> Result<Serial> {
        self.hal.begin_transaction()?;

        let version = self.get_version()?;

        let ret = if version.major() < 5 {
            // For NEO and YK4 devices, we have to get the serial number from
            // the OTP applet.

            let (sw, _) = self.hal.send_data(
                &[
                    0,
                    Instruction::SelectApplication.to_value(),
                    0x04,
                    0,
                    apdu::YK_AID.len() as u8,
                ],
                &apdu::YK_AID,
            )?;
            sw.error?;

            let (sw, serial_buffer) = self.hal.send_data(&[0, 0x01, 0x10, 0, 0], &[])?;
            sw.error?;

            let (sw, _) = self.hal.send_data(
                &[
                    0,
                    Instruction::SelectApplication.to_value(),
                    0x04,
                    0,
                    apdu::PIV_AID.len() as u8,
                ],
                &apdu::PIV_AID,
            )?;
            sw.error?;

            Ok(Serial::new(serial_buffer.as_slice())?)
        } else {
            // For YK5 and newer devices, get the serial number with the F8
            // command.

            let (sw, buffer) = self
                .hal
                .send_data(&[0, Instruction::GetSerial.to_value(), 0, 0, 0], &[])?;
            sw.error?;
            Ok(Serial::new(buffer.as_slice())?)
        };

        self.hal.end_transaction()?;
        ret
    }

    /// This function allows the user to change the Yubikey's PIN, given that
    /// the user knows the existing PIN. The old and new PINs can be provided
    /// as function arguments. If they are not provided, this function will
    /// prompt for them on stdin.
    ///
    /// When prompting for a PIN, this function will automatically retry if PIN
    /// verification fails, until there are no more available retries. At that
    /// point, the PIN can be unblocked using the PUK.
    pub fn change_pin(&mut self, old_pin: Option<&str>, new_pin: Option<&str>) -> Result<()> {
        verification_change_loop(
            PIN_NAME,
            old_pin,
            new_pin,
            PIN_PROMPT,
            NEW_PIN_PROMPT,
            |existing, new| change_impl(&self.hal, ChangeAction::ChangePin, existing, new),
        )
    }

    /// This function allows the user to reset the Yubikey's PIN using the PUK,
    /// after the user has exhausted their allotted tries to enter the PIN
    /// correctly. The PUK and new PIN can be provided as function arguments. If
    /// they are not provided, this function will prompt for them on stdin.
    ///
    /// When prompting for a PUK, this function will automatically retry if PUK
    /// verification fails, until there are no more available retries. At that
    /// point, the Yubiey can be reset to factory defaults using the reset
    /// function.
    pub fn unblock_pin(&mut self, puk: Option<&str>, new_pin: Option<&str>) -> Result<()> {
        verification_change_loop(
            PUK_NAME,
            puk,
            new_pin,
            PUK_PROMPT,
            NEW_PIN_PROMPT,
            |existing, new| change_impl(&self.hal, ChangeAction::UnblockPin, existing, new),
        )
    }

    /// This function allows the user to change the Yubikey's PUK, given that
    /// the user knows the existing PUK. The old and new PUKs can be provided
    /// as function arguments. If they are not provided, this function will
    /// prompt for them on stdin.
    ///
    /// When prompting for a PUK, this function will automatically retry if PUK
    /// verification fails, until there are no more available retries. At that
    /// point, the PIN and PUK can both be unblocked using the reset function.
    pub fn change_puk(&mut self, old_puk: Option<&str>, new_puk: Option<&str>) -> Result<()> {
        verification_change_loop(
            PUK_NAME,
            old_puk,
            new_puk,
            PUK_PROMPT,
            NEW_PUK_PROMPT,
            |existing, new| change_impl(&self.hal, ChangeAction::ChangePuk, existing, new),
        )
    }

    /// This function resets the PIN, PUK, and management key to their factory
    /// default values, as well as delete any stored certificates and keys. The
    /// default values for the PIN and PUK are 123456 and 12345678,
    /// respectively.
    ///
    /// Note that this function will return an error unless the tries to verify
    /// the PIN and PUK have both been fully exhausted (e.g., the Yubikey is now
    /// unusable). Otherwise, the change_pin, unblock_pin, and change_puk
    /// functions should be used instead of this function.
    pub fn reset(&mut self) -> Result<()> {
        let (sw, _) = self
            .hal
            .send_data(&[0, Instruction::Reset.to_value(), 0, 0], &[])?;
        sw.error?;
        Ok(())
    }

    /// This function is similar to reset, except it first ensures that all of
    /// the PIN and PUK retries have been exhausted first (by intentionally
    /// exhausting them with known-bad values).
    pub fn force_reset(&mut self) -> Result<()> {
        // Exhaust PIN verification retries.
        let mut bad_pin: &'static str = "111111";
        loop {
            match self.authenticate_pin(Some(bad_pin)) {
                Ok(_) => {
                    if bad_pin == "111111" {
                        bad_pin = "222222";
                    } else {
                        return Err(Error::Internal(format!(
                            "logic error: failed to find bad PIN for force reset"
                        )));
                    }
                }
                Err(e) => match e {
                    Error::SmartCard(ref sce) => {
                        if *sce.get_code() == SmartCardErrorCode::InvalidChv {
                            continue;
                        } else {
                            return Err(Error::Internal(format!(
                                "logic error: got unexpected failure during force reset: {}",
                                e
                            )));
                        }
                    }
                    Error::Authentication(ref ae) => {
                        if ae.to_string().contains("no more retries") {
                            break;
                        } else {
                            return Err(Error::Internal(format!(
                                "logic error: got unexpected failure during force reset: {}",
                                e
                            )));
                        }
                    }
                    _ => {
                        return Err(Error::Internal(format!(
                            "logic error: got unexpected failure during force reset: {}",
                            e
                        )));
                    }
                },
            }
        }

        // Exhaust PUK verification retries.
        let mut bad_puk: &'static str = "111111";
        loop {
            match self.change_puk(Some(bad_puk), Some("333333")) {
                Ok(_) => {
                    if bad_puk == "111111" {
                        bad_puk = "222222";
                    } else {
                        return Err(Error::Internal(format!(
                            "logic error: failed to find bad PUK for force reset"
                        )));
                    }
                }
                Err(e) => match e {
                    Error::SmartCard(ref sce) => {
                        if *sce.get_code() == SmartCardErrorCode::InvalidChv {
                            continue;
                        } else {
                            return Err(Error::Internal(format!(
                                "logic error: got unexpected failure during force reset: {}",
                                e
                            )));
                        }
                    }
                    Error::Authentication(ref ae) => {
                        if ae.to_string().contains("no more retries") {
                            break;
                        } else {
                            return Err(Error::Internal(format!(
                                "logic error: got unexpected failure during force reset: {}",
                                e
                            )));
                        }
                    }
                    _ => {
                        return Err(Error::Internal(format!(
                            "logic error: got unexpected failure during force reset: {}",
                            e
                        )));
                    }
                },
            }
        }

        // Now, reset!
        self.reset()
    }

    /// This function sets the number of retries available for PIN or PUK
    /// verification. This also resets the PIN and PUK back to their factory
    /// default values, 123456 and 12345678, respectively.
    ///
    /// Note that this function is slightly strange compared to the rest of the
    /// API, in that both the management key *and* the current PIN are required.
    pub fn set_retries(
        &mut self,
        mgm_key: Option<&str>,
        pin: Option<&str>,
        pin_retries: u8,
        puk_retries: u8,
    ) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        self.authenticate_pin(pin)?;
        let (sw, _) = self.hal.send_data(
            &[
                0,
                Instruction::SetPinRetries.to_value(),
                pin_retries,
                puk_retries,
            ],
            &[],
        )?;
        sw.error?;
        Ok(())
    }

    /// This function changes the management key stored on the device. This is
    /// the key used to authenticate() for administrative / management access.
    pub fn set_management_key(
        &mut self,
        old_mgm_key: Option<&str>,
        new_mgm_key: Option<&str>,
        touch: bool,
    ) -> Result<()> {
        self.authenticate_mgm(old_mgm_key)?;

        let new_mgm_key: Vec<u8> = data_encoding::HEXLOWER_PERMISSIVE
            .decode(MaybePromptedCString::new(new_mgm_key, NEW_MGM_KEY_PROMPT, true)?.as_bytes())?;
        if is_weak_mgm_key(new_mgm_key.as_slice())? {
            return Err(Error::InvalidArgument(format!(
                "refusing to set new management key because it contains weak DES keys"
            )));
        }

        let mut data: [u8; 255] = [0; 255];
        data[0] = Algorithm::Des.to_value();
        data[1] = Key::CardManagement.to_value();
        data[2] = MGM_KEY_BYTES as u8; // Key length
        (&mut data[3..(3 + MGM_KEY_BYTES)]).copy_from_slice(new_mgm_key.as_slice());
        // "lc" value is key length + 3 extra bytes in data.
        let apdu = Apdu::from_pieces(
            0,
            Instruction::SetManagementKey.to_value(),
            0xff,
            if touch { 0xfe } else { 0xff },
            (MGM_KEY_BYTES as u8) + 3,
            &data,
        )?;

        let (sw, _) = self.hal.send_data_impl(&apdu)?;
        sw.error?;
        Ok(())
    }

    /// This function writes a new, randomly-generated Card Holder Unique
    /// Identifier (CHUID) to the device. Some systems (Windows) require a CHUID
    /// to be present before they will recognize the Yubikey. This data object
    /// is not present on Yubikeys by default (from the factory).
    ///
    /// Also note that, according to the Yubikey docs, the card contents are
    /// aggressively cached on Windows. In order to invalidate the cached data,
    /// e.g. after changing stored certificates, the CHUID must also be changed.
    pub fn set_chuid(&mut self, mgm_key: Option<&str>) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        let object = build_data_object(
            &self.hal,
            CHUID_TEMPLATE,
            CHUID_RANDOM_OFFSET,
            CHUID_RANDOM_BYTES,
        )?;
        ykpiv_save_object(&self.hal, Object::Chuid, object)?;
        Ok(())
    }

    /// This function writes a new, randomly-generated Card Capability Container
    /// (CCC) to the device. Some systems (MacOS) require a CCC to be present
    /// before they will recognize the Yubikey. This data object is not present
    /// on Yubikeys by default (from the factory).
    pub fn set_ccc(&mut self, mgm_key: Option<&str>) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        let object =
            build_data_object(&self.hal, CCC_TEMPLATE, CCC_RANDOM_OFFSET, CCC_RANDOM_BYTES)?;
        ykpiv_save_object(&self.hal, Object::Capability, object)?;
        Ok(())
    }

    /// Read a data object from the Yubikey, returning the byte contents.
    pub fn read_object(&self, id: Object) -> Result<Vec<u8>> {
        let mut data: Vec<u8> = Vec::new();
        // TODO: Deduplicate this setup code? It appears in one other place.
        data.push(0x5c);
        if id == Object::Discovery {
            data.extend_from_slice(&[1, id.to_value() as u8]);
        } else if id.to_value() > 0xffff && id.to_value() <= 0xffffff {
            data.extend_from_slice(&[
                3,
                ((id.to_value() >> 16) & 0xff) as u8,
                ((id.to_value() >> 8) & 0xff) as u8,
                (id.to_value() & 0xff) as u8,
            ]);
        }

        let (sw, mut recv) = self.hal.send_data(
            &[0, Instruction::GetData.to_value(), 0x3f, 0xff],
            data.as_slice(),
        )?;
        sw.error?;

        // TODO: This code might be duplicated elsewhere, combine?
        recv.remove(0); // TODO: The first byte is not part of object or length?
        if recv[0] < 0x81 {
            let length = recv[0] as usize;
            recv.remove(0);
            recv.truncate(length);
        } else if (recv[0] & 0x7f) == 1 {
            let length = recv[1] as usize;
            recv.remove(0);
            recv.remove(0);
            recv.truncate(length);
        } else if (recv[0] & 0x7f) == 2 {
            let length = ((recv[1] as usize) << 8) + (recv[2] as usize);
            recv.remove(0);
            recv.remove(0);
            recv.remove(0);
            recv.truncate(length);
        } else {
            return Err(Error::Internal(format!(
                "failed to determine size of returned data object"
            )));
        }

        Ok(recv)
    }

    /// Write a data object to the Yubikey. This function takes ownership of the
    /// data, because upstream's API requires a mutable data buffer.
    pub fn write_object(
        &mut self,
        mgm_key: Option<&str>,
        id: Object,
        buffer: Vec<u8>,
    ) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        ykpiv_save_object(&self.hal, id, buffer)?;
        Ok(())
    }

    /// Generate a new private / public key pair, using the underlying
    /// hardware's generation capability. Store the private key in the given key
    /// slot, and return the public key. The specified PIN and touch policies
    /// will be enforced whenever this key is used in the future.
    pub fn generate(
        &mut self,
        mgm_key: Option<&str>,
        slot: Key,
        algorithm: Algorithm,
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
    ) -> Result<PublicKey> {
        if !(algorithm.is_rsa() || algorithm.is_ecc()) {
            return Err(Error::InvalidArgument(format!(
                "only RSA and ECC algorithms are supported by this function"
            )));
        }

        // As per https://developers.yubico.com/yubico-piv-tool/YKCS11_release_notes.html
        if algorithm == Algorithm::Eccp384 {
            return Err(Error::InvalidArgument(format!(
                "384-bit EC key generation is not supported"
            )));
        }

        if algorithm.is_rsa() {
            let version = self.get_version()?;
            if version >= Version(4, 2, 6) && version <= Version(4, 3, 4) {
                return Err(Error::InvalidArgument(format!("this device is affected by https://yubi.co/ysa201701/, so RSA key generation is disabled")));
            }
        }

        self.authenticate_mgm(mgm_key)?;

        let template: [u8; 4] = [
            0,
            Instruction::GenerateAsymmetric.to_value(),
            0,
            slot.to_value(),
        ];

        let mut data: Vec<u8> = vec![0xac, 3, Tag::Algorithm.to_value(), 1, algorithm.to_value()];
        if pin_policy != PinPolicy::Default {
            data[1] += 3;
            data.extend_from_slice(&[Tag::PinPolicy.to_value(), 1, pin_policy.to_value()]);
        }
        if touch_policy != TouchPolicy::Default {
            data[1] += 3;
            data.extend_from_slice(&[Tag::TouchPolicy.to_value(), 1, touch_policy.to_value()]);
        }

        let (sw, recv) = self.hal.send_data(&template, data.as_slice())?;
        sw.error?;

        if algorithm.is_rsa() {
            PublicKey::from_rsa_structure(recv.as_slice())
        } else if algorithm.is_ecc() {
            PublicKey::from_ec_structure(algorithm, recv.as_slice())
        } else {
            unreachable!(); // We already checked the algorithm type above.
        }
    }

    /// Import an RSA or EC private key into the given key slot. The provided
    /// input key must be a PEM-encoded private key file. The caller must
    /// indicate if the private key is encrypted or not. If the key is
    /// encrypted, and no passphrase is provided, one will be prompted for. The
    /// specified PIN and touch policies will be enforced whenever this key is
    /// used in the future.
    pub fn import_key<P: AsRef<Path>>(
        &mut self,
        mgm_key: Option<&str>,
        input: P,
        slot: Key,
        encrypted: bool,
        passphrase: Option<&str>,
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
    ) -> Result<PublicKey> {
        let key = PrivateKey::from_pem(input, encrypted, passphrase)?;

        self.authenticate_mgm(mgm_key)?;

        import_private_key(&self.hal, slot, &key, pin_policy, touch_policy)?;
        Ok(key.to_public_key()?)
    }

    /// Attest returns an X.509 certificate signed with the private key in the
    /// given slot if and only if the private key was generated on the device
    /// rather than imported. Note that this feature is only supported by some
    /// newer hardware devices. For details, see:
    /// https://developers.yubico.com/yubico-piv-tool/Attestation.html
    pub fn attest(&self, slot: Key) -> Result<PublicKeyCertificate> {
        let (sw, recv) = self.hal.send_data(
            &[0, Instruction::Attest.to_value(), slot.to_value(), 0],
            &[],
        )?;
        sw.error?;

        if *recv.get(0).unwrap_or(&0) != 0x30 {
            return Err(Error::Internal(format!(
                "failed to attest key; got invalid response from device"
            )));
        }

        Ok(PublicKeyCertificate::from_der(recv.as_slice())?)
    }

    pub fn read_certificate(&self, slot: Key) -> Result<PublicKeyCertificate> {
        // TODO: This seems to not work if the key was generated with the
        // "generate" command, I *think* because that writes a public key to the
        // card instead of a full X509 certificate. At least,
        // generate -> request-certificate also fails with upstream's code, so
        // this seems to be intended behavior. Revisit this + add tests once a
        // function to write X509 certificates is implemented + tested.
        let object = self.read_object(slot.to_object()?)?;
        if object.len() < 2 {
            return Err(Error::Internal(format!(
                "expected at least two bytes in the stored object, got {}",
                object.len()
            )));
        }

        let has_tag: bool = match object.get(0) {
            None => false,
            Some(byte) => *byte == 0x70,
        };
        if !has_tag {
            return Err(Error::Internal(format!(
                "the object stored on the device lacks the expected tag"
            )));
        }

        let (der, len) = crate::piv::util::read_length(&object[1..])?;
        Ok(PublicKeyCertificate::from_der(&der[0..len])?)
    }

    /// Encrypts the given data with the given public key. It is assumed that
    /// the matching private key is stored on the device, in which case the
    /// returned encrypted data can later be deciphered using the hardware
    /// device.
    ///
    /// Note that the given input key must be an RSA key in PEM format.
    ///
    /// Refer to `piv::pkey::PublicKey::encrypt` for more details.
    pub fn encrypt(
        &self,
        public_key: &PublicKey,
        plaintext: &[u8],
    ) -> Result<(Algorithm, Vec<u8>)> {
        let algorithm = public_key.get_algorithm()?;
        Ok((algorithm, public_key.encrypt(plaintext)?))
    }

    /// Decrypts the given ciphertext with the private key in the given key
    /// slot. The specified key must be an RSA key, and the cipertext must
    /// have been encrypted with padding as per the `encrypt` function.
    pub fn decrypt(
        &mut self,
        pin: Option<&str>,
        ciphertext: &[u8],
        slot: Key,
        algorithm: Algorithm,
    ) -> Result<Vec<u8>> {
        self.authenticate_pin(pin)?;

        let mut plaintext = sign_decipher_impl(&self.hal, ciphertext, algorithm, slot, true)?;
        let mut unpadded: Vec<u8> = vec![0; plaintext.len()];
        let len = unsafe {
            openssl_sys::RSA_padding_check_PKCS1_type_2(
                unpadded.as_mut_ptr(),
                unpadded.len() as c_int,
                plaintext.as_mut_ptr().offset(1),
                (plaintext.len() - 1) as c_int,
                match algorithm {
                    Algorithm::Rsa1024 => 1024 / 8,
                    Algorithm::Rsa2048 => 2048 / 8,
                    _ => {
                        return Err(Error::InvalidArgument(format!(
                            "unsupported algorithm {:?}",
                            algorithm
                        )));
                    }
                },
            )
        };
        if len == -1 {
            let errors = openssl::error::ErrorStack::get();
            let has_errors = errors.errors().is_empty();
            return Err(match has_errors {
                false => Error::Unknown(format!("unknown error")),
                true => errors.into(),
            });
        }
        unpadded.truncate(len as usize);
        Ok(unpadded)
    }
}

impl<T: PcscHal> Drop for Handle<T> {
    fn drop(&mut self) {
        self.disconnect();
    }
}
