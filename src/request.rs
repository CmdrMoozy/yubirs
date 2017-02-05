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
    pub client_id: String,
    api_key: Vec<u8>,
    pub otp: Otp,
    pub timestamp: bool,
    pub nonce: String,
    pub success_percentage: Option<SuccessPercentage>,
    pub timeout: Option<u64>,
}

impl Request {
    pub fn new(client_id: String,
               api_key: Vec<u8>,
               otp: Otp,
               timestamp: bool,
               success_percentage: Option<SuccessPercentage>,
               timeout: Option<u64>)
               -> Request {
        Request {
            client_id: client_id,
            api_key: api_key,
            otp: otp,
            timestamp: timestamp,
            nonce: gen_yubico_api_nonce(),
            success_percentage: success_percentage,
            timeout: timeout,
        }
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

    pub fn get_signature(&self) -> String {
        util::generate_encoded_signature(self.api_key.as_slice(),
                                         self.to_string_without_signature())
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "h={}&{}",
               self.get_signature(),
               self.to_string_without_signature())
    }
}
