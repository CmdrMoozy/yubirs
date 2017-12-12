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

use crypto::{is_weak_mgm_key, MGM_KEY_BYTES};
use data_encoding;
use error::*;
use libc::{c_char, c_int, c_uchar};
use openssl;
use pcsc_sys;
use piv::DEFAULT_READER;
use piv::id::{Algorithm, PinPolicy};
use piv::nid::*;
use piv::scarderr::SmartCardError;
use rand::{self, Rng};
use std::ffi::CString;
use std::fmt;
use std::ptr;
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
const CHUID_TEMPLATE: &'static [c_uchar] = &[
    0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68,
    0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x38, 0x42, 0x10, 0xc3, 0xf5, 0x34, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x35, 0x08, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,
];
const CHUID_RANDOM_OFFSET: usize = 29;
const CHUID_RANDOM_BYTES: usize = 16;

#[cfg_attr(rustfmt, rustfmt_skip)]
const CCC_TEMPLATE: &'static [c_uchar] = &[
    0xf0, 0x15, 0xa0, 0x00, 0x00, 0x01, 0x16, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x01, 0x21, 0xf2, 0x01, 0x21, 0xf3,
    0x00, 0xf4, 0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7, 0x00, 0xfa, 0x00, 0xfb, 0x00,
    0xfc, 0x00, 0xfd, 0x00, 0xfe, 0x00,
];
const CCC_RANDOM_OFFSET: usize = 9;
const CCC_RANDOM_BYTES: usize = 14;

#[repr(C)]
#[derive(Clone, Copy)]
struct StructuredApdu {
    /// Instruction class - indicates the type of command, e.g. interindustry or
    /// proprietary.
    pub cla: c_uchar,
    /// Instruction code - indicates the specific command, e.g. "write data".
    pub ins: c_uchar,
    /// First instruction parameter for the command, e.g. offset into file at
    /// which to write the data.
    pub p1: c_uchar,
    /// Second instruction parameter for the command, e.g. offset into file at
    /// which to write the data.
    pub p2: c_uchar,
    /// Encodes the number (N_c) of bytes of command data to follow. The
    /// official specification says that this field can be variable length, but
    /// upstream specifies it statically at 1 byte.
    pub lc: c_uchar,
    /// The command data. The official specification says this can be up to
    /// 65535 bytes long, but upstream defines it as a static 255 bytes.
    pub data: [c_uchar; 255],
}

/// APDU stands for "smart card Application Protocol Data Unit". This union
/// definition is used by upstream's library to alternate between treating APDU
/// data in a structured or unstructured way.
#[repr(C)]
#[derive(Clone, Copy)]
union Apdu {
    st: StructuredApdu,
    raw: [c_uchar; 230],
}

/// The Application ID to send in an APDU when connecting to a Yubikey.
const APDU_AID: [c_uchar; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

// TODO: Remove this function, leaving only send_data.
fn send_data_impl(
    card: pcsc_sys::SCARDHANDLE,
    apdu: *const Apdu,
    recv_buffer: &mut Vec<u8>,
) -> Result<c_int> {
    let send_len: pcsc_sys::DWORD = unsafe { (*apdu).st.lc as pcsc_sys::DWORD + 5 };
    debug!(
        "> {}",
        (unsafe { &(*apdu).raw[0..(send_len as usize)] })
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    let mut recv_length = recv_buffer.len() as pcsc_sys::DWORD;
    SmartCardError::new(unsafe {
        pcsc_sys::SCardTransmit(
            card,
            &pcsc_sys::g_rgSCardT1Pci,
            (*apdu).raw.as_ptr(),
            send_len,
            ptr::null_mut(),
            recv_buffer.as_mut_ptr(),
            &mut recv_length,
        )
    })?;
    debug!(
        "< {}",
        recv_buffer
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    recv_buffer.truncate(recv_length as usize);
    Ok(if recv_buffer.len() >= 2 {
        ((recv_buffer[recv_length as usize - 2] as c_int) << 8)
            | (recv_buffer[recv_length as usize - 1] as c_int)
    } else {
        0
    })
}

fn send_data(card: pcsc_sys::SCARDHANDLE, apdu: &Apdu) -> Result<(c_int, Vec<u8>)> {
    // Upstream uses a 261-byte buffer in all cases, even though this number seems mostly made up.
    // It seems like a sane default for now.
    let mut recv: Vec<u8> = vec![0; 261];
    Ok((send_data_impl(card, apdu, &mut recv)?, recv))
}

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
    pub fn from_status(sw: c_int) -> VerificationResult {
        if sw == SW_SUCCESS {
            VerificationResult::Success
        } else if (sw >> 8) == 0x63 {
            VerificationResult::Failure(
                (sw & 0xf) as usize,
                SmartCardError::new(pcsc_sys::SCARD_E_INVALID_CHV)
                    .err()
                    .unwrap()
                    .into(),
            )
        } else if sw == SW_ERR_AUTH_BLOCKED {
            VerificationResult::PermanentFailure(
                SmartCardError::new(pcsc_sys::SCARD_W_CHV_BLOCKED)
                    .err()
                    .unwrap()
                    .into(),
            )
        } else {
            VerificationResult::OtherFailure(
                SmartCardError::new(pcsc_sys::SCARD_E_UNKNOWN_RES_MNG)
                    .err()
                    .unwrap()
                    .into(),
            )
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

fn ykpiv_transfer_data(
    card: pcsc_sys::SCARDHANDLE,
    templ: &[c_uchar],
    in_data: &[c_uchar],
) -> Result<(c_int, Vec<c_uchar>)> {
    SmartCardError::new(unsafe { pcsc_sys::SCardBeginTransaction(card) })?;

    let mut out_data: Vec<c_uchar> = Vec::new();
    let mut sw: c_int = SW_SUCCESS;

    for chunk in in_data.chunks(255) {
        let mut data: [c_uchar; 255] = [0; 255];
        for (dst, src) in data.iter_mut().zip(chunk.iter()) {
            *dst = *src;
        }
        let apdu = Apdu {
            st: StructuredApdu {
                cla: if chunk.len() == 255 {
                    0x10
                } else {
                    *templ.get(0).unwrap_or(&0)
                },
                ins: *templ.get(1).unwrap_or(&0),
                p1: *templ.get(2).unwrap_or(&0),
                p2: *templ.get(3).unwrap_or(&0),
                lc: chunk.len() as u8,
                data: data,
            },
        };

        debug!(
            "Sending chunk of {} out of {} total bytes",
            chunk.len(),
            in_data.len()
        );
        let (sw_new, mut recv) = send_data(card, &apdu)?;
        sw = sw_new;
        if sw != SW_SUCCESS && sw >> 8 != 0x61 {
            return Ok((sw, out_data));
        }
        let recv_len = recv.len() - 2;
        recv.truncate(recv_len);
        out_data.append(&mut recv);
    }

    while sw >> 8 == 0x61 {
        let apdu = Apdu {
            st: StructuredApdu {
                cla: 0,
                ins: 0xc0,
                p1: 0,
                p2: 0,
                lc: 0,
                data: [0; 255],
            },
        };

        debug!(
            "The card indicates there are {} more bytes of data to read",
            sw & 0xff
        );
        let (sw_new, mut recv) = send_data(card, &apdu)?;
        sw = sw_new;
        if sw != SW_SUCCESS && sw >> 8 != 0x61 {
            return Ok((sw, out_data));
        }
        let recv_len = recv.len() - 2;
        recv.truncate(recv_len);
        out_data.append(&mut recv);
    }

    SmartCardError::new(unsafe {
        pcsc_sys::SCardEndTransaction(card, pcsc_sys::SCARD_LEAVE_CARD)
    })?;
    Ok((sw, out_data))
}

fn build_data_object(
    template: &'static [c_uchar],
    random_offset: usize,
    random_bytes_len: usize,
) -> Vec<u8> {
    let mut object: Vec<c_uchar> = Vec::with_capacity(template.len());
    object.extend_from_slice(&template[..random_offset]);
    let random_bytes: Vec<c_uchar> = rand::weak_rng().gen_iter().take(random_bytes_len).collect();
    object.extend(random_bytes.into_iter());
    object.extend_from_slice(&template[random_offset + random_bytes_len..]);
    object
}

// TODO: This should accept a Rust-style enum instead of an int.
fn ykpiv_save_object(
    card: pcsc_sys::SCARDHANDLE,
    object_id: c_int,
    mut object: Vec<u8>,
) -> Result<()> {
    let mut data: Vec<u8> = vec![0x5c];
    if object_id == YKPIV_OBJ_DISCOVERY {
        data.extend_from_slice(&[1, YKPIV_OBJ_DISCOVERY as u8]);
    } else if object_id > 0xffff && object_id <= 0xffffff {
        data.extend_from_slice(&[
            3,
            ((object_id >> 16) & 0xff) as u8,
            ((object_id >> 8) & 0xff) as u8,
            (object_id & 0xff) as u8,
        ]);
    }
    data.push(0x53);
    if object.len() < 0x80 {
        data.push(object.len() as u8);
    } else if object.len() < 0xff {
        data.extend_from_slice(&[0x81, object.len() as u8]);
    } else {
        data.extend_from_slice(&[
            0x82,
            ((object.len() >> 8) & 0xff) as u8,
            (object.len() & 0xff) as u8,
        ]);
    }
    data.append(&mut object);

    let (sw, _) = ykpiv_transfer_data(card, &[0, YKPIV_INS_PUT_DATA, 0x3f, 0xff], data.as_slice())?;
    if sw != SW_SUCCESS {
        bail!("Failed to save data object");
    }
    Ok(())
}

// TODO: This function can be cleaned up / code can be reused.
// TODO: This function should accept Rust-style enums instead of IDs. This would let us clean up
// some assorted input validation code.
fn sign_decipher_impl(
    card: pcsc_sys::SCARDHANDLE,
    data: &[u8],
    algorithm: Algorithm,
    key_id: c_uchar,
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

    let (sw, recv) = ykpiv_transfer_data(
        card,
        &[0, YKPIV_INS_AUTHENTICATE, algorithm.to_value(), key_id],
        data,
    )?;
    if sw == SW_ERR_SECURITY_STATUS {
        bail!("Authenticating for sign / decipher failed");
    } else if sw != SW_SUCCESS {
        bail!("Authenticating for sign / decipher failed due to an unknown error");
    }

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

pub fn ykpiv_sign_data(
    card: pcsc_sys::SCARDHANDLE,
    data: &[u8],
    algorithm: Algorithm,
    key_id: c_uchar,
) -> Result<Vec<u8>> {
    sign_decipher_impl(card, data, algorithm, key_id, false)
}

pub fn ykpiv_decipher_data(
    card: pcsc_sys::SCARDHANDLE,
    data: &[u8],
    algorithm: Algorithm,
    key_id: c_uchar,
) -> Result<Vec<u8>> {
    sign_decipher_impl(card, data, algorithm, key_id, true)
}

// TODO: This function should accept Rust-style enums instead of IDs. This would let us clean up
// some assorted input validation code.
pub fn ykpiv_import_private_key(
    card: pcsc_sys::SCARDHANDLE,
    key_id: c_uchar,
    algorithm: Algorithm,
    p: &[u8],
    q: &[u8],
    dp: &[u8],
    dq: &[u8],
    qinv: &[u8],
    ec_data: &[u8],
    pin_policy: PinPolicy,
    touch_policy_id: c_uchar,
) -> Result<()> {
    if key_id == YKPIV_KEY_CARDMGM || key_id < YKPIV_KEY_RETIRED1
        || (key_id > YKPIV_KEY_RETIRED20 && key_id < YKPIV_KEY_AUTHENTICATION)
        || (key_id > YKPIV_KEY_CARDAUTH && key_id != YKPIV_KEY_ATTESTATION)
    {
        bail!("The specified key type is not supported by this function");
    }

    if touch_policy_id != YKPIV_TOUCHPOLICY_DEFAULT && touch_policy_id != YKPIV_TOUCHPOLICY_NEVER
        && touch_policy_id != YKPIV_TOUCHPOLICY_ALWAYS
        && touch_policy_id != YKPIV_TOUCHPOLICY_CACHED
    {
        bail!("Invalid touch policy");
    }

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
        key_data.extend_from_slice(&[YKPIV_PINPOLICY_TAG, 0x01, pin_policy.to_value()]);
    }

    if touch_policy_id != YKPIV_TOUCHPOLICY_DEFAULT {
        key_data.extend_from_slice(&[YKPIV_TOUCHPOLICY_TAG, 0x01, touch_policy_id]);
    }

    let (sw, _) = ykpiv_transfer_data(
        card,
        &[0, YKPIV_INS_IMPORT_KEY, algorithm.to_value(), key_id],
        key_data.as_slice(),
    )?;
    match sw {
        SW_ERR_SECURITY_STATUS => bail!("Failed to import private key due to authentication error"),
        SW_SUCCESS => Ok(()),
        _ => bail!("Failed to import private key due to unknown error"),
    }
}

/// This function provides the common implementation for all of the various ways we can change the
/// PIN or PUK on a Yubikey. The way we do this using low-level PC/SC functions is identical,
/// except we send a different action value depending on the requested change type.
fn change_impl(
    card: pcsc_sys::SCARDHANDLE,
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

    let mut templ: Vec<c_uchar> = vec![0, YKPIV_INS_CHANGE_REFERENCE, 0, 0x80];
    if action == ChangeAction::UnblockPin {
        templ[1] = YKPIV_INS_RESET_RETRY;
    }
    if action == ChangeAction::ChangePuk {
        templ[3] = 0x81;
    }

    let mut in_data: Vec<c_uchar> = vec![0; 16];
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

    let (sw, _) = match ykpiv_transfer_data(card, templ.as_slice(), in_data.as_slice()) {
        Err(e) => return VerificationResult::OtherFailure(e),
        Ok(tuple) => tuple,
    };
    VerificationResult::from_status(sw)
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Version(u8, u8, u8);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[repr(C)]
pub struct ykpiv_state {
    pub context: pcsc_sys::SCARDCONTEXT,
    pub card: pcsc_sys::SCARDHANDLE,
    pub verbose: c_int,
    authenticated_pin: bool,
    authenticated_mgm: bool,
}

impl ykpiv_state {
    // TODO: Remove verbose flag.
    pub fn new(verbose: bool) -> Result<Self> {
        let mut context: pcsc_sys::SCARDCONTEXT = pcsc_sys::SCARD_E_INVALID_HANDLE;
        SmartCardError::new(unsafe {
            pcsc_sys::SCardEstablishContext(
                pcsc_sys::SCARD_SCOPE_SYSTEM,
                ptr::null(),
                ptr::null(),
                &mut context,
            )
        })?;
        Ok(ykpiv_state {
            context: context,
            card: 0,
            verbose: match verbose {
                false => 0,
                true => 1,
            },
            authenticated_pin: false,
            authenticated_mgm: false,
        })
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

            let mut data: [c_uchar; 255] = [0; 255];
            for (dst, src) in data.iter_mut().zip(pin.as_bytes()) {
                *dst = *src;
            }
            for b in data.iter_mut().skip(pin.len()).take(8 - pin.len()) {
                *b = 0xff;
            }

            let apdu = Apdu {
                st: StructuredApdu {
                    cla: 0,
                    ins: YKPIV_INS_VERIFY,
                    p1: 0x00,
                    p2: 0x80,
                    lc: 0x80,
                    data: data,
                },
            };

            let mut buffer: Vec<c_uchar> = vec![0; 261];
            VerificationResult::from_status(match send_data_impl(self.card, &apdu, &mut buffer) {
                Err(e) => return VerificationResult::OtherFailure(e),
                Ok(sw) => sw,
            })
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
        let mut data: [c_uchar; 255] = [0; 255];
        data[0] = 0x7c;
        data[1] = 0x02;
        data[2] = 0x80;
        let apdu = Apdu {
            st: StructuredApdu {
                cla: 0,
                ins: YKPIV_INS_AUTHENTICATE,
                p1: Algorithm::Des.to_value(),
                p2: YKPIV_KEY_CARDMGM,
                lc: 0x04,
                data: data,
            },
        };
        let (sw, response) = send_data(self.card, &apdu)?;
        if sw != SW_SUCCESS {
            bail!("Failed to get management key challenge from card");
        }
        let card_challenge: Vec<u8> = (&response[4..13]).into();
        debug_assert!(card_challenge.len() == 8);

        // Send a response to the card's challenge, and a challenge of our own.
        let our_challenge = openssl::symm::encrypt(
            openssl::symm::Cipher::des_ecb(),
            mgm_key.as_slice(),
            None,
            card_challenge.as_slice(),
        )?;
        debug_assert!(our_challenge.len() == 8);
        let mut data: [c_uchar; 255] = [0; 255];
        data[0] = 0x7c;
        data[1] = 20; // 2 + 8 + 2 + 8
        data[2] = 0x80;
        data[3] = 8;
        (&mut data[4..13]).copy_from_slice(our_challenge.as_slice());
        data[12] = 0x81;
        openssl::rand::rand_bytes(&mut data[13..21])?;
        let expected_card_reply: Vec<u8> = (&data[13..21]).into();
        let apdu = Apdu {
            st: StructuredApdu {
                cla: 0,
                ins: YKPIV_INS_AUTHENTICATE,
                p1: Algorithm::Des.to_value(),
                p2: YKPIV_KEY_CARDMGM,
                lc: 21,
                data: [0; 255],
            },
        };
        let (sw, response) = send_data(self.card, &apdu)?;
        if sw != SW_SUCCESS {
            bail!("Failed to send management key challenge back to card");
        }

        // Compare the response from the card with our expected response.
        let expected_card_reply = openssl::symm::encrypt(
            openssl::symm::Cipher::des_ecb(),
            mgm_key.as_slice(),
            None,
            expected_card_reply.as_slice(),
        )?;
        if expected_card_reply.as_slice() != &response[4..13] {
            bail!("Management key authentication failed");
        }

        Ok(())
    }

    pub fn list_readers(&self) -> Result<Vec<String>> {
        let mut readers_len: pcsc_sys::DWORD = 0;
        SmartCardError::new(unsafe {
            pcsc_sys::SCardListReaders(self.context, ptr::null(), ptr::null_mut(), &mut readers_len)
        })?;

        let mut buffer: Vec<u8> = vec![0_u8; readers_len as usize];
        SmartCardError::new(unsafe {
            pcsc_sys::SCardListReaders(
                self.context,
                ptr::null(),
                buffer.as_mut_ptr() as *mut c_char,
                &mut readers_len,
            )
        })?;
        if readers_len as usize != buffer.len() {
            bail!("Failed to retrieve full reader list due to buffer size race.");
        }

        let ret: ::std::result::Result<Vec<String>, ::std::str::Utf8Error> = buffer
            .split(|b| *b == 0)
            .filter_map(|slice| match slice.len() {
                0 => None,
                _ => Some(::std::str::from_utf8(slice).map(|s| s.to_owned())),
            })
            .collect();

        Ok(ret?)
    }

    pub fn connect(&mut self, reader: Option<&str>) -> Result<()> {
        let reader = reader.unwrap_or(DEFAULT_READER);
        let readers = self.list_readers()?;
        for potential_reader in readers {
            if !potential_reader.contains(reader) {
                info!(
                    "Skipping reader '{}' since it doesn't match '{}'",
                    potential_reader,
                    reader
                );
                continue;
            }

            info!("Attempting to connect to reader '{}'", potential_reader);
            let potential_reader = CString::new(potential_reader)?;
            let mut active_protocol: pcsc_sys::DWORD = pcsc_sys::SCARD_PROTOCOL_UNDEFINED;
            SmartCardError::new(unsafe {
                pcsc_sys::SCardConnect(
                    self.context,
                    potential_reader.as_ptr(),
                    pcsc_sys::SCARD_SHARE_SHARED,
                    pcsc_sys::SCARD_PROTOCOL_T1,
                    &mut self.card,
                    &mut active_protocol,
                )
            })?;

            let mut data: [c_uchar; 255] = [0; 255];
            for (dst, src) in data.iter_mut().zip(APDU_AID.iter()) {
                *dst = *src;
            }
            let apdu = Apdu {
                st: StructuredApdu {
                    cla: 0,
                    ins: 0xa4,
                    p1: 0x04,
                    p2: 0,
                    lc: APDU_AID.len() as c_uchar,
                    data: data,
                },
            };

            let mut recv_buffer: Vec<u8> = vec![0; 255];
            let sw = send_data_impl(self.card, &apdu, &mut recv_buffer)?;
            if sw != SW_SUCCESS {
                bail!("Failed selecting application: {:x}", sw);
            }

            return Ok(());
        }

        Err(
            SmartCardError::new(pcsc_sys::SCARD_E_UNKNOWN_READER)
                .err()
                .unwrap()
                .into(),
        )
    }

    pub fn disconnect(&mut self) {
        if self.card != 0 {
            unsafe {
                pcsc_sys::SCardDisconnect(self.card, pcsc_sys::SCARD_RESET_CARD);
            }
            self.card = 0;
        }

        if unsafe { pcsc_sys::SCardIsValidContext(self.context) } == pcsc_sys::SCARD_S_SUCCESS {
            unsafe { pcsc_sys::SCardReleaseContext(self.context) };
            self.context = pcsc_sys::SCARD_E_INVALID_HANDLE;
        }
    }

    pub fn get_version(&self) -> Result<Version> {
        let apdu = Apdu {
            st: StructuredApdu {
                cla: 0,
                ins: YKPIV_INS_GET_VERSION,
                p1: 0,
                p2: 0,
                lc: 0,
                data: [0; 255],
            },
        };
        let mut buffer: Vec<u8> = vec![0; 261];

        let sw = send_data_impl(self.card, &apdu, &mut buffer)?;
        if sw != SW_SUCCESS {
            bail!("Get version instruction returned error: {:x}", sw);
        }

        Ok(Version(buffer[0], buffer[1], buffer[2]))
    }

    pub fn change_pin(&mut self, old_pin: Option<&str>, new_pin: Option<&str>) -> Result<()> {
        verification_change_loop(
            PIN_NAME,
            old_pin,
            PIN_NAME,
            new_pin,
            PIN_PROMPT,
            NEW_PIN_PROMPT,
            |existing, new| change_impl(self.card, ChangeAction::ChangePin, existing, new),
        )
    }

    pub fn unblock_pin(&mut self, puk: Option<&str>, new_pin: Option<&str>) -> Result<()> {
        verification_change_loop(
            PUK_NAME,
            puk,
            PIN_NAME,
            new_pin,
            PUK_PROMPT,
            NEW_PIN_PROMPT,
            |existing, new| change_impl(self.card, ChangeAction::UnblockPin, existing, new),
        )
    }

    pub fn change_puk(&mut self, old_puk: Option<&str>, new_puk: Option<&str>) -> Result<()> {
        verification_change_loop(
            PUK_NAME,
            old_puk,
            PUK_NAME,
            new_puk,
            PUK_PROMPT,
            NEW_PUK_PROMPT,
            |existing, new| change_impl(self.card, ChangeAction::ChangePuk, existing, new),
        )
    }

    pub fn reset(&mut self) -> Result<()> {
        let (sw, _) = ykpiv_transfer_data(self.card, &[0, YKPIV_INS_RESET, 0, 0], &[])?;
        if sw != SW_SUCCESS {
            bail!("Reset failed, probably because PIN or PUK retries are still available");
        }
        Ok(())
    }

    pub fn set_retries(
        &mut self,
        mgm_key: Option<&str>,
        pin: Option<&str>,
        pin_retries: u8,
        puk_retries: u8,
    ) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        self.authenticate_pin(pin)?;
        let (sw, _) = ykpiv_transfer_data(
            self.card,
            &[0, YKPIV_INS_SET_PIN_RETRIES, pin_retries, puk_retries],
            &[],
        )?;
        if sw != SW_SUCCESS {
            bail!("Setting PIN and PUK retries failed");
        }
        Ok(())
    }

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

        let mut data: [c_uchar; 255] = [0; 255];
        data[0] = Algorithm::Des.to_value();
        data[1] = YKPIV_KEY_CARDMGM;
        data[2] = MGM_KEY_BYTES as c_uchar; // Key length
        (&mut data[3..(3 + MGM_KEY_BYTES)]).copy_from_slice(new_mgm_key.as_slice());
        let apdu = Apdu {
            st: StructuredApdu {
                cla: 0,
                ins: YKPIV_INS_SET_MGMKEY,
                p1: 0xff,
                p2: if touch { 0xfe } else { 0xff },
                lc: (MGM_KEY_BYTES as c_uchar) + 3, // Key length + 3 extra bytes in data
                data: data,
            },
        };

        let (sw, _) = send_data(self.card, &apdu)?;
        if sw != SW_SUCCESS {
            bail!("Failed to set new card management key");
        }
        Ok(())
    }

    pub fn set_chuid(&mut self, mgm_key: Option<&str>) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        let object = build_data_object(CHUID_TEMPLATE, CHUID_RANDOM_OFFSET, CHUID_RANDOM_BYTES);
        ykpiv_save_object(self.card, YKPIV_OBJ_CHUID, object)?;
        Ok(())
    }

    pub fn set_ccc(&mut self, mgm_key: Option<&str>) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        let object = build_data_object(CCC_TEMPLATE, CCC_RANDOM_OFFSET, CCC_RANDOM_BYTES);
        ykpiv_save_object(self.card, YKPIV_OBJ_CAPABILITY, object)?;
        Ok(())
    }

    pub fn read_object(&self, object_id: c_int) -> Result<Vec<u8>> {
        let mut data: Vec<u8> = Vec::new();
        // TODO: Deduplicate this if statement? It appears in one other place.
        if object_id == YKPIV_OBJ_DISCOVERY {
            data.extend_from_slice(&[1, YKPIV_OBJ_DISCOVERY as u8]);
        } else if object_id > 0xffff && object_id <= 0xffffff {
            data.extend_from_slice(&[
                3,
                ((object_id >> 16) & 0xff) as u8,
                ((object_id >> 8) & 0xff) as u8,
                (object_id & 0xff) as u8,
            ]);
        }

        let (sw, mut recv) = ykpiv_transfer_data(
            self.card,
            &[0, YKPIV_INS_GET_DATA, 0x3f, 0xff],
            data.as_slice(),
        )?;
        if sw != SW_SUCCESS {
            bail!("Failed to read data object");
        }

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

    pub fn write_object(
        &mut self,
        mgm_key: Option<&str>,
        object_id: c_int,
        buffer: Vec<u8>,
    ) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        ykpiv_save_object(self.card, object_id, buffer)?;
        Ok(())
    }
}

impl Drop for ykpiv_state {
    fn drop(&mut self) {
        self.disconnect();
    }
}
