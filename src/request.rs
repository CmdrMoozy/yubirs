use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use data_encoding::base64;
use data_encoding::base64url;
use otp::Otp;
use sodiumoxide::randombytes::randombytes;
use std::fmt;

/// Generate a 40 character long string with random unique data.
fn gen_yubico_api_nonce() -> String {
    base64url::encode(randombytes(30).as_slice())
}

/// Generate a HMAC-SHA1 signature as accepted by the Yubico API, using the given decoded API key.
fn generate_signature(key: &[u8], data: String) -> String {
    use crypto::mac::Mac;
    let mut hmac = Hmac::new(Sha1::new(), key);
    let data = data.into_bytes();
    hmac.input(&data[..]);
    let signature = hmac.result();
    let signature = base64::encode(signature.code());
    signature.replace('+', "%2B")
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
        req.signature = generate_signature(api_key, signature_data);
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
