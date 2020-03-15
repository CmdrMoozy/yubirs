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
use curl::easy::Easy;
use data_encoding;
use openssl;

/// URL-encode the given string. That is, replacing any characters which are not allowed to appear
/// in URLs with their percent-encoded versions.
pub fn url_encode(s: &str) -> String {
    let mut easy = Easy::new();
    easy.url_encode(s.as_bytes())
}

/// Generate a HMAC-SHA1 signature as accepted by the Yubico API, using the given decoded API key.
pub fn generate_signature(key: &[u8], data: String) -> Result<Vec<u8>> {
    let hmac = openssl::pkey::PKey::hmac(key)?;
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha1(), &hmac)?;
    let data = data.into_bytes();
    signer.update(data.as_slice())?;
    Ok(signer.sign_to_vec()?)
}

/// Generates a signature as per generate_signature(), and then encodes it in such a way that it
/// will be accepted by Yubico's API (base64 + percent-encoded).
pub fn generate_encoded_signature(key: &[u8], data: String) -> Result<String> {
    Ok(url_encode(
        data_encoding::BASE64
            .encode(generate_signature(key, data)?.as_slice())
            .as_str(),
    ))
}
