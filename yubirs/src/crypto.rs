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
use lazy_static::lazy_static;
use openssl;
use std::collections::HashSet;

/// The number of bytes a binary management key must contain (3DES keys are 8 bytes each, so
/// 8 * 3 = 24 bytes total).
pub const MGM_KEY_BYTES: usize = 24;

/// The number of bytes in a PIV management key challenge.
pub const DES_CHALLENGE_BYTES: usize = 8;

lazy_static! {
    // Weak DES keys, from: https://en.wikipedia.org/wiki/Weak_key#Weak_keys_in_DES.
    static ref DES_WEAK_KEYS: HashSet<[u8; 8]> = {
        let mut s = HashSet::new();
        s.insert([0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01]);
        s.insert([0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE]);
        s.insert([0xE0,0xE0,0xE0,0xE0,0xF1,0xF1,0xF1,0xF1]);
        s.insert([0x1F,0x1F,0x1F,0x1F,0x0E,0x0E,0x0E,0x0E]);
        s.insert([0x01,0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E]);
        s.insert([0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E,0x01]);
        s.insert([0x01,0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1]);
        s.insert([0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1,0x01]);
        s.insert([0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE]);
        s.insert([0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01]);
        s.insert([0x1F,0xE0,0x1F,0xE0,0x0E,0xF1,0x0E,0xF1]);
        s.insert([0xE0,0x1F,0xE0,0x1F,0xF1,0x0E,0xF1,0x0E]);
        s.insert([0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E,0xFE]);
        s.insert([0xFE,0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E]);
        s.insert([0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE]);
        s.insert([0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1]);
        s
    };
}

#[cfg_attr(rustfmt, rustfmt_skip)]
const ODD_PARITY_BYTES: [u8; 256] = [
    1,   1,   2,   2,   4,   4,   7,   7,   8,   8,   11,  11,  13,  13,  14,  14,  16,  16,  19,
    19,  21,  21,  22,  22,  25,  25,  26,  26,  28,  28,  31,  31,  32,  32,  35,  35,  37,  37,
    38,  38,  41,  41,  42,  42,  44,  44,  47,  47,  49,  49,  50,  50,  52,  52,  55,  55,  56,
    56,  59,  59,  61,  61,  62,  62,  64,  64,  67,  67,  69,  69,  70,  70,  73,  73,  74,  74,
    76,  76,  79,  79,  81,  81,  82,  82,  84,  84,  87,  87,  88,  88,  91,  91,  93,  93,  94,
    94,  97,  97,  98,  98,  100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110, 112, 112,
    115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127, 128, 128, 131, 131, 133,
    133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143, 145, 145, 146, 146, 148, 148, 151, 151,
    152, 152, 155, 155, 157, 157, 158, 158, 161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171,
    171, 173, 173, 174, 174, 176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188,
    191, 191, 193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206, 208,
    208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223, 224, 224, 227, 227,
    229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239, 241, 241, 242, 242, 244, 244, 247,
    247, 248, 248, 251, 251, 253, 253, 254, 254,
];

/// Returns true if the given managment key's 3 DES keys are "weak", and therefore shouldn't be
/// used. The given input management key should have been decoded from hex, but no parity bits
/// should have been added yet (this is done implicitly).
///
/// The given management key should be in binary, and must be MGM_KEY_BYTES in length.
pub fn is_weak_mgm_key(mgm_key: &[u8]) -> Result<bool> {
    if mgm_key.len() != MGM_KEY_BYTES {
        return Err(Error::InvalidArgument(format!(
            "invalid management key; must be {} bytes long",
            MGM_KEY_BYTES
        )));
    }
    let mgm_key: Vec<u8> = mgm_key
        .iter()
        .map(|b| ODD_PARITY_BYTES[*b as usize])
        .collect();
    for key in mgm_key.as_slice().chunks(8) {
        if DES_WEAK_KEYS.contains(key) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn decrypt_des_challenge(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != MGM_KEY_BYTES {
        return Err(Error::InvalidArgument(format!(
            "invalid management key; must be {} bytes long",
            MGM_KEY_BYTES
        )));
    }
    if ciphertext.len() != DES_CHALLENGE_BYTES {
        return Err(Error::InvalidArgument(format!(
            "invalid challenge; must be {} bytes long",
            DES_CHALLENGE_BYTES
        )));
    }

    let mut crypter = openssl::symm::Crypter::new(
        openssl::symm::Cipher::des_ede3(),
        openssl::symm::Mode::Decrypt,
        key,
        None,
    )?;
    // Upstream doesn't use any padding.
    crypter.pad(false);
    // OpenSSL requires we allocate twice as much memory, even though DES_CHALLENGE_BYTES is only
    // one DES block in length.
    let mut plaintext = vec![0; DES_CHALLENGE_BYTES * 2];
    let count = crypter.update(ciphertext, &mut plaintext)?;
    let rest = crypter.finalize(&mut plaintext[count..])?;
    debug_assert_eq!(DES_CHALLENGE_BYTES, count + rest);
    plaintext.truncate(count + rest);

    Ok(plaintext)
}

pub fn encrypt_des_challenge(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != MGM_KEY_BYTES {
        return Err(Error::InvalidArgument(format!(
            "invalid management key; must be {} bytes long",
            MGM_KEY_BYTES
        )));
    }
    if plaintext.len() != DES_CHALLENGE_BYTES {
        return Err(Error::InvalidArgument(format!(
            "invalid challenge; must be {} bytes long",
            DES_CHALLENGE_BYTES
        )));
    }

    let mut crypter = openssl::symm::Crypter::new(
        openssl::symm::Cipher::des_ede3(),
        openssl::symm::Mode::Encrypt,
        key,
        None,
    )?;
    // Upstream doesn't use any padding.
    crypter.pad(false);
    // OpenSSL requires we allocate twice as much memory, even though DES_CHALLENGE_BYTES is only
    // one DES block in length.
    let mut ciphertext = vec![0; DES_CHALLENGE_BYTES * 2];
    let count = crypter.update(plaintext, &mut ciphertext)?;
    let rest = crypter.finalize(&mut ciphertext[count..])?;
    debug_assert_eq!(DES_CHALLENGE_BYTES, count + rest);
    ciphertext.truncate(count + rest);

    Ok(ciphertext)
}
