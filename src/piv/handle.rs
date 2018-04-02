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

use crypto::*;
use data_encoding;
use error::*;
use openssl;
use piv::hal::{Apdu, PcscHal};
use piv::id::*;
use piv::sw::StatusWord;
use rand::{self, Rng};
use std::fmt;
use util::MaybePromptedString;

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
    F: Fn(&MaybePromptedString) -> VerificationResult,
{
    loop {
        let value = MaybePromptedString::new(value, prompt, false)?;
        match callback(&value) {
            VerificationResult::Success => return Ok(()),
            VerificationResult::Failure(tries, err) => {
                debug!("Incorrect {}, {} tries remaining: {}", name, tries, err);
                // If we didn't prompt for a value, retrying won't help, because we'd just be
                // retrying with the same value over again. In this case, just bail now.
                match value.was_provided() {
                    false => eprintln!("Incorrect {}, try again - {} tries remaining", name, tries),
                    true => bail!(err),
                };
            }
            VerificationResult::PermanentFailure(err) => {
                debug!("Incorrect {}, 0 tries remaining: {}", name, err);
                bail!("Verifying {} failed: no more retries", name);
            }
            VerificationResult::OtherFailure(err) => bail!(err),
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
    new_name: &str,
    new: Option<&str>,
    existing_prompt: &str,
    new_prompt: &str,
    callback: F,
) -> Result<()>
where
    F: Fn(&MaybePromptedString, &MaybePromptedString) -> VerificationResult,
{
    verification_loop(existing_name, existing, existing_prompt, |existing| {
        let new = match MaybePromptedString::new(new.clone(), new_prompt, true) {
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

fn build_data_object(
    template: &'static [u8],
    random_offset: usize,
    random_bytes_len: usize,
) -> Vec<u8> {
    let mut object: Vec<u8> = Vec::with_capacity(template.len());
    object.extend_from_slice(&template[..random_offset]);
    let random_bytes: Vec<u8> = rand::weak_rng().gen_iter().take(random_bytes_len).collect();
    object.extend(random_bytes.into_iter());
    object.extend_from_slice(&template[random_offset + random_bytes_len..]);
    object
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
        bail!("Data signing / deciphering only supports RSA or ECC algorithms");
    }

    let key_len: usize = match algorithm {
        Algorithm::Rsa1024 => 128,
        Algorithm::Rsa2048 => 256,
        Algorithm::Eccp256 => 32,
        Algorithm::Eccp384 => 48,
        _ => 0,
    };

    if algorithm.is_rsa() && data.len() != key_len {
        bail!("Invalid input data; expected {} bytes", key_len);
    } else if algorithm.is_ecc() {
        if !decipher && data.len() > key_len {
            bail!("Invalid input data; expected at most {} bytes", key_len);
        } else if decipher && data.len() != (key_len * 2) + 1 {
            bail!("Invalid input data; expected {} bytes", (key_len * 2) + 1);
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
        data,
    )?;
    sw.error?;

    // Skip the first 7c tag.
    if recv[0] != 0x7c {
        bail!("Failed to parse tag from signature reply");
    }
    let recv_slice = if recv[1] < 0x81 {
        let len = recv[1] as usize;
        &recv[2 + len..]
    } else if (recv[1] & 0x7f) == 1 {
        let len = recv[2] as usize;
        &recv[3 + len..]
    } else if (recv[1] & 0x7f) == 2 {
        let len = ((recv[2] as usize) << 8) + (recv[3] as usize);
        &recv[4 + len..]
    } else {
        bail!("Failed to parse tag length from signature reply");
    };

    // Skip the 82 tag.
    if recv_slice[0] != 0x82 {
        bail!("Failed to parse tag from signature reply");
    }
    let recv_slice = if recv_slice[1] < 0x81 {
        let len = recv_slice[1] as usize;
        &recv_slice[2 + len..]
    } else if (recv_slice[1] & 0x7f) == 1 {
        let len = recv_slice[2] as usize;
        &recv_slice[3 + len..]
    } else if (recv_slice[1] & 0x7f) == 2 {
        let len = ((recv_slice[2] as usize) << 8) + (recv_slice[3] as usize);
        &recv_slice[4 + len..]
    } else {
        bail!("Failed to parse tag length from signature reply");
    };

    Ok(recv_slice.into())
}

fn ykpiv_sign_data<T: PcscHal>(
    hal: &T,
    data: &[u8],
    algorithm: Algorithm,
    key: Key,
) -> Result<Vec<u8>> {
    sign_decipher_impl(hal, data, algorithm, key, false)
}

fn ykpiv_decipher_data<T: PcscHal>(
    hal: &T,
    data: &[u8],
    algorithm: Algorithm,
    key: Key,
) -> Result<Vec<u8>> {
    sign_decipher_impl(hal, data, algorithm, key, true)
}

fn ykpiv_import_private_key<T: PcscHal>(
    hal: &T,
    id: Key,
    algorithm: Algorithm,
    p: &[u8],
    q: &[u8],
    dp: &[u8],
    dq: &[u8],
    qinv: &[u8],
    ec_data: &[u8],
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Result<()> {
    if !algorithm.is_rsa() && !algorithm.is_ecc() {
        bail!("Certificate functions only support RSA or ECC algorithms");
    }

    let elem_len: usize = match algorithm {
        Algorithm::Rsa1024 => 64,
        Algorithm::Rsa2048 => 128,
        Algorithm::Eccp256 => 32,
        Algorithm::Eccp384 => 48,
        _ => 0,
    };

    let params: Vec<&[u8]> = if algorithm.is_rsa() {
        vec![p, q, dp, dq, qinv]
    } else if algorithm.is_ecc() {
        vec![ec_data]
    } else {
        vec![]
    };

    let param_tag: u8 = match algorithm {
        Algorithm::Rsa1024 => 0x01,
        Algorithm::Rsa2048 => 0x01,
        Algorithm::Eccp256 => 0x06,
        Algorithm::Eccp384 => 0x06,
        _ => 0,
    };

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
        key_data.extend_from_slice(params[i]);
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
            id.to_value(),
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
    existing: &MaybePromptedString,
    new: &MaybePromptedString,
) -> VerificationResult {
    if existing.len() > 8 {
        return VerificationResult::OtherFailure(
            format!(
                "Invalid existing {}; it exceeds 8 characters",
                match action {
                    ChangeAction::ChangePin => "PIN",
                    ChangeAction::UnblockPin => "PUK",
                    ChangeAction::ChangePuk => "PUK",
                }
            ).into(),
        );
    }
    if new.len() > 8 {
        return VerificationResult::OtherFailure(
            format!(
                "Invalid new {}; it exceeds 8 characters",
                match action {
                    ChangeAction::ChangePin => "PIN",
                    ChangeAction::UnblockPin => "PIN",
                    ChangeAction::ChangePuk => "PUK",
                }
            ).into(),
        );
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
    pub fn new(data: &[u8]) -> Result<Version> {
        if data.len() < 3 {
            bail!("Version data must be three bytes long.");
        }
        Ok(Version(data[0], data[1], data[2]))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

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
                return VerificationResult::OtherFailure(
                    "Invalid PIN; it exceeds 8 characters".into(),
                );
            }

            let mut data: [u8; 128] = [0; 128];
            for (dst, src) in data.iter_mut().zip(pin.as_bytes()) {
                *dst = *src;
            }
            for b in data.iter_mut().skip(pin.len()).take(8 - pin.len()) {
                *b = 0xff;
            }

            match self.hal
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
            .decode(MaybePromptedString::new(mgm_key, MGM_KEY_PROMPT, false)?.as_bytes())?;
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
        let (sw, response) = self.hal.send_data_impl(&apdu.raw)?;
        sw.error?;
        let card_challenge: Vec<u8> = (&response[4..13]).into();
        debug_assert!(card_challenge.len() == 8);

        // Send a response to the card's challenge, and a challenge of our own.
        let our_challenge = decrypt_des_challenge(mgm_key.as_slice(), card_challenge.as_slice())?;
        let mut data: [u8; 255] = [0; 255];
        data[0] = 0x7c;
        data[1] = 20; // 2 + 8 + 2 + 8
        data[2] = 0x80;
        data[3] = 8;
        (&mut data[4..13]).copy_from_slice(our_challenge.as_slice());
        data[12] = 0x81;
        openssl::rand::rand_bytes(&mut data[13..21])?;
        let expected_card_reply: Vec<u8> = (&data[13..21]).into();
        let apdu = Apdu::from_pieces(
            0,
            Instruction::Authenticate.to_value(),
            Algorithm::Des.to_value(),
            Key::CardManagement.to_value(),
            21,
            &[0; 255],
        )?;
        let (sw, response) = self.hal.send_data_impl(&apdu.raw)?;
        sw.error?;

        // Compare the response from the card with our expected response.
        let expected_card_reply =
            encrypt_des_challenge(mgm_key.as_slice(), expected_card_reply.as_slice())?;
        if expected_card_reply.as_slice() != &response[4..13] {
            bail!("Management key authentication failed");
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
        let (sw, buffer) = self.hal
            .send_data(&[0, Instruction::GetVersion.to_value(), 0, 0, 0], &[])?;
        sw.error?;
        Ok(Version::new(buffer.as_slice())?)
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
            PIN_NAME,
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
            PIN_NAME,
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
            PUK_NAME,
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
        let (sw, _) = self.hal
            .send_data(&[0, Instruction::Reset.to_value(), 0, 0], &[])?;
        sw.error?;
        Ok(())
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
            .decode(MaybePromptedString::new(new_mgm_key, NEW_MGM_KEY_PROMPT, true)?.as_bytes())?;
        if is_weak_mgm_key(new_mgm_key.as_slice())? {
            bail!("Refusing to set new management key because it contains weak DES keys");
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

        let (sw, _) = self.hal.send_data_impl(&apdu.raw)?;
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
        let object = build_data_object(CHUID_TEMPLATE, CHUID_RANDOM_OFFSET, CHUID_RANDOM_BYTES);
        ykpiv_save_object(&self.hal, Object::Chuid, object)?;
        Ok(())
    }

    /// This function writes a new, randomly-generated Card Capability Container
    /// (CCC) to the device. Some systems (MacOS) require a CCC to be present
    /// before they will recognize the Yubikey. This data object is not present
    /// on Yubikeys by default (from the factory).
    pub fn set_ccc(&mut self, mgm_key: Option<&str>) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        let object = build_data_object(CCC_TEMPLATE, CCC_RANDOM_OFFSET, CCC_RANDOM_BYTES);
        ykpiv_save_object(&self.hal, Object::Capability, object)?;
        Ok(())
    }

    /// Read a data object from the Yubikey, returning the byte contents.
    pub fn read_object(&self, id: Object) -> Result<Vec<u8>> {
        let mut data: Vec<u8> = Vec::new();
        // TODO: Deduplicate this if statement? It appears in one other place.
        if id == Object::Discovery {
            data.extend_from_slice(&[1, Object::Discovery.to_value() as u8]);
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

        recv.remove(0); // The first byte is not part of the object or length?
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
            bail!("Failed to determine size of returned data object");
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

    /// This is a convenience function to read a certificate's data object from
    /// the Yubikey, and then return it formatted in a specified way.
    pub fn read_certificate(&mut self, id: Key, format: Format) -> Result<String> {
        let data = self.read_object(id.to_object()?)?;
        format_certificate(data.as_slice(), format)
    }
}

impl<T: PcscHal> Drop for Handle<T> {
    fn drop(&mut self) {
        self.disconnect();
    }
}
