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

use data_encoding;
use error::*;
use openssl::rand::rand_bytes;
use otp::Otp;
use otp::util;
use std::fmt;

/// Generate a 40 character long string with random unique data. Note that the Yubico API will only
/// accept nonces which contain the characters [a-zA-Z0-9]. If the nonce contains other characters,
/// the misleading error code MISSING_PARAMETER will be returned.
fn gen_yubico_api_nonce() -> Result<String> {
    let mut bytes: Vec<u8> = vec![0; 30];
    let mut s = String::with_capacity(40);
    while s.len() < 40 {
        let remaining: usize = 40 - s.len();
        rand_bytes(bytes.as_mut_slice())?;
        s.extend(
            data_encoding::BASE64URL_NOPAD
                .encode(bytes.as_slice())
                .chars()
                .filter(|c| *c != '-' && *c != '_')
                .take(remaining),
        )
    }
    Ok(s)
}

/// The possible values for the "success percentage" request parameter. From the validation server
/// specification, this value is: "A value of 0 to 100 indicating percentage of syncing required by
/// client, or strings 'fast' or 'secure' to use server-configured values."
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SuccessPercentage {
    Fast,
    Secure,
    Percent(u8),
}

impl fmt::Display for SuccessPercentage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                SuccessPercentage::Fast => "fast".to_owned(),
                SuccessPercentage::Secure => "secure".to_owned(),
                SuccessPercentage::Percent(p) => p.to_string(),
            }
        )
    }
}

/// This structure denotes all of the parameters which comprise a verification API request.
#[derive(Clone, Debug)]
pub struct Request {
    pub client_id: String,
    api_key: Vec<u8>,
    pub otp: Otp,
    pub timestamp: bool,
    pub nonce: String,
    pub success_percentage: Option<SuccessPercentage>,
    pub timeout: Option<u64>,
}

impl Request {
    /// Create a new request with the given parameters. More details on what the parameters mean
    /// are available in the official documentation:
    /// https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html.
    pub fn new(
        client_id: String,
        api_key: Vec<u8>,
        otp: Otp,
        timestamp: bool,
        success_percentage: Option<SuccessPercentage>,
        timeout: Option<u64>,
    ) -> Result<Request> {
        Ok(Request {
            client_id: client_id,
            api_key: api_key,
            otp: otp,
            timestamp: timestamp,
            nonce: gen_yubico_api_nonce()?,
            success_percentage: success_percentage,
            timeout: timeout,
        })
    }

    fn to_string_without_signature(&self) -> String {
        // NOTE: It is very important that we append the parameters to the string in alphabetical
        // key order. The server uses the same convention to allow us to verify the signature.
        let mut parameters: Vec<String> = vec![];
        parameters.push(format!("{}={}", "id", self.client_id));
        parameters.push(format!("{}={}", "nonce", self.nonce));
        parameters.push(format!("{}={}", "otp", self.otp));
        if let Some(sl) = self.success_percentage.as_ref() {
            parameters.push(format!("{}={}", "sl", sl));
        }
        if let Some(t) = self.timeout.as_ref() {
            parameters.push(format!("{}={}", "timeout", t));
        }
        if self.timestamp {
            parameters.push("timestamp=1".to_owned());
        }
        parameters.join("&")
    }

    /// Returns, as a base64-/percent-encoded string, the signature for this request.
    pub fn get_signature(&self) -> Result<String> {
        util::generate_encoded_signature(
            self.api_key.as_slice(),
            self.to_string_without_signature(),
        )
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "h={}&{}",
            self.get_signature()
                .ok()
                .unwrap_or("COMPUTING SIGNATURE FAILED".to_owned()),
            self.to_string_without_signature()
        )
    }
}
