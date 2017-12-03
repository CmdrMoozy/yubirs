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

use base64;
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use curl::easy::Easy;

/// URL-encode the given string. That is, replacing any characters which are not allowed to appear
/// in URLs with their percent-encoded versions.
pub fn url_encode(s: &str) -> String {
    let mut easy = Easy::new();
    easy.url_encode(s.as_bytes())
}

/// Generate a HMAC-SHA1 signature as accepted by the Yubico API, using the given decoded API key.
pub fn generate_signature(key: &[u8], data: String) -> Vec<u8> {
    use crypto::mac::Mac;
    let mut hmac = Hmac::new(Sha1::new(), key);
    let data = data.into_bytes();
    hmac.input(&data[..]);
    hmac.result().code().to_vec()
}

/// Generates a signature as per generate_signature(), and then encodes it in such a way that it
/// will be accepted by Yubico's API (base64 + percent-encoded).
pub fn generate_encoded_signature(key: &[u8], data: String) -> String {
    url_encode(base64::encode_config(generate_signature(key, data).as_slice(), base64::STANDARD).as_str())
}
