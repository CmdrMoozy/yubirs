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

use crate::error::Result;
use crate::otp::request::{Request, SuccessPercentage};
use crate::otp::result::VerificationResult;
use crate::otp::Otp;
use bdrck::cli;
use curl::easy::{Easy, List};
use data_encoding;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The protocol to use to make the verification request.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Protocol {
    /// Use plain HTTP. Not recommended.
    Http,
    /// Use HTTPS, but don't verify the server's certificate. STRONGLY NOT RECOMMENDED.
    HttpsWithoutVerification,
    /// Use HTTPS. Recommended.
    Https,
}

lazy_static! {
    static ref PROTOCOL_PREFIXES: HashMap<Protocol, &'static str> = {
        let mut m = HashMap::new();
        m.insert(Protocol::Http, "http://");
        m.insert(Protocol::HttpsWithoutVerification, "https://");
        m.insert(Protocol::Https, "https://");
        m
    };
}

fn build_url(protocol: Protocol, api_server: &str, request: &Request) -> String {
    format!(
        "{}{}?{}",
        PROTOCOL_PREFIXES.get(&protocol).unwrap(),
        api_server,
        request
    )
}

/// Client is an opaque structure which manages the state and configuration used to make
/// verification requests.
pub struct Client {
    protocol: Protocol,
    api_server: String,
    client_id: String,
    api_key: Vec<u8>,
}

static DEFAULT_API_SERVER: &'static str = "api.yubico.com/wsapi/2.0/verify";

static TOUCH_YUBIKEY_PROMPT: &'static str = "Touch YubiKey: ";

impl Client {
    /// Create a new, fully-customized client. The API server should be given without a protocol on
    /// the front - for example, "api.yubico.com/wsapi/2.0/verify". If you don't have a client ID /
    /// API key pair, you can get one here: https://upgrade.yubico.com/getapikey/.
    pub fn new(
        protocol: Protocol,
        api_server: &str,
        client_id: &str,
        api_key: &str,
    ) -> Result<Client> {
        let api_key = data_encoding::BASE64.decode(api_key.as_bytes())?;
        Ok(Client {
            protocol: protocol,
            api_server: api_server.to_owned(),
            client_id: client_id.to_owned(),
            api_key: api_key,
        })
    }

    /// Create a new client using the default / recommended protocol and API server.
    pub fn default(client_id: &str, api_key: &str) -> Result<Client> {
        Client::new(Protocol::Https, DEFAULT_API_SERVER, client_id, api_key)
    }

    /// Verify the given YubiKey OTP string. If some internal error occurs, an error will be
    /// returned. Otherwise, even if the key is invalid, a VerificationResult structure will be
    /// returned. It is up to the caller to check .is_valid() to see if the OTP was accepted.
    pub fn verify(
        &self,
        otp: &str,
        timestamp: bool,
        success_percentage: Option<SuccessPercentage>,
        timeout: Option<u64>,
    ) -> Result<VerificationResult> {
        // Try parsing the OTP, to ensure it is vaguely valid.
        let otp = Otp::new(otp)?;
        let request = Request::new(
            self.client_id.clone(),
            self.api_key.clone(),
            otp,
            timestamp,
            success_percentage,
            timeout,
        )?;

        let mut headers = List::new();
        headers.append("User-Agent: github.com/CmdrMoozy/yubirs")?;

        let mut handle = Easy::new();
        if self.protocol == Protocol::HttpsWithoutVerification {
            handle.ssl_verify_peer(false)?;
        }
        handle.http_headers(headers)?;
        handle.get(true)?;
        handle.url(build_url(self.protocol, self.api_server.as_str(), &request).as_str())?;

        let mut response = Vec::new();
        {
            let mut transfer = handle.transfer();
            transfer.write_function(|data| {
                response.extend_from_slice(data);
                Ok(data.len())
            })?;
            transfer.perform()?;
        }

        Ok(VerificationResult::new(
            &self.api_key[..],
            &request.otp,
            request.nonce.as_str(),
            response,
        )?)
    }

    /// Call .verify(), with most options set to sane default values. Timestamp information will be
    /// returned, we'll use the "secure" success percentage, and we'll let the server choose a
    /// timeout value.
    pub fn verify_default(&self, otp: &str) -> Result<VerificationResult> {
        self.verify(otp, true, Some(SuccessPercentage::Secure), None)
    }

    /// Prompt for a YubiKey OTP (wait for a "touch"), and then verify it as per verify().
    pub fn verify_prompt(
        &self,
        timestamp: bool,
        success_percentage: Option<SuccessPercentage>,
        timeout: Option<u64>,
    ) -> Result<VerificationResult> {
        self.verify(
            cli::prompt_for_string(cli::Stream::Stderr, TOUCH_YUBIKEY_PROMPT, true)?.as_str(),
            timestamp,
            success_percentage,
            timeout,
        )
    }

    /// Call .verify_prompt(), with most options set to sane default values. Timestamp information
    /// will be returned, we'll use the "secure" success percentage, and we'll let the server
    /// choose a timeout value.
    pub fn verify_prompt_default(&self) -> Result<VerificationResult> {
        self.verify_prompt(true, Some(SuccessPercentage::Secure), None)
    }
}
