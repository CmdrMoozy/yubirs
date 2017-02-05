use data_encoding::base64url;
use otp::Otp;
use sodiumoxide::randombytes::randombytes;
use std::fmt;
use util;

/// Generate a 40 character long string with random unique data. Note that the Yubico API will only
/// accept nonces which contain the characters [a-zA-Z0-9]. If the nonce contains other characters,
/// the misleading error code MISSING_PARAMETER will be returned.
fn gen_yubico_api_nonce() -> String {
    let mut nonce = String::new();
    while nonce.len() < 40 {
        let s = base64url::encode(randombytes(30).as_slice());
        let s: String = s.chars().filter(|c| *c != '-' && *c != '_').collect();
        nonce.push_str(s.as_str());
    }
    nonce.truncate(40);
    nonce
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SuccessPercentage {
    Fast,
    Secure,
    Percent(u8),
}

impl fmt::Display for SuccessPercentage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "{}",
               match *self {
                   SuccessPercentage::Fast => "fast".to_owned(),
                   SuccessPercentage::Secure => "secure".to_owned(),
                   SuccessPercentage::Percent(p) => p.to_string(),
               })
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    client_id: String,
    otp: Otp,
    signature: String,
    timestamp: bool,
    nonce: String,
    success_percentage: Option<SuccessPercentage>,
    timeout: Option<u64>,
}

impl Request {
    pub fn new(client_id: String,
               api_key: &[u8],
               otp: Otp,
               timestamp: bool,
               success_percentage: Option<SuccessPercentage>,
               timeout: Option<u64>)
               -> Request {
        let mut req = Request {
            client_id: client_id,
            otp: otp,
            signature: String::new(),
            timestamp: timestamp,
            nonce: gen_yubico_api_nonce(),
            success_percentage: success_percentage,
            timeout: timeout,
        };
        let signature_data = req.to_string_without_signature();
        req.signature = util::generate_encoded_signature(api_key, signature_data);
        req
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

    pub fn get_otp(&self) -> &Otp {
        &self.otp
    }

    pub fn get_nonce(&self) -> &str {
        self.nonce.as_str()
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "h={}&{}",
               self.signature,
               self.to_string_without_signature())
    }
}
