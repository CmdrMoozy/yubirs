use curl::easy::{Easy, List};
use data_encoding::base64;
use error::Result;
use otp::Otp;
use request::{Request, SuccessPercentage};
use result::VerificationResult;
use rpassword::prompt_password_stderr;
use std::collections::HashMap;

/// The protocol to use to make the verification request.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
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

// TODO: Make 'sl' and 'timestamp' parameters configurable.
fn build_url(protocol: Protocol, api_server: &str, request: &Request) -> String {
    format!("{}{}?{}",
            PROTOCOL_PREFIXES.get(&protocol).unwrap(),
            api_server,
            request)
}

pub struct Client {
    protocol: Protocol,
    api_server: String,
    client_id: String,
    api_key: Vec<u8>,
}

static DEFAULT_API_SERVER: &'static str = "api.yubico.com/wsapi/2.0/verify";

static TOUCH_YUBIKEY_PROMPT: &'static str = "Touch YubiKey: ";

impl Client {
    pub fn new(protocol: Protocol,
               api_server: &str,
               client_id: &str,
               api_key: &str)
               -> Result<Client> {
        let api_key = try!(base64::decode(api_key.as_bytes()));
        Ok(Client {
            protocol: protocol,
            api_server: api_server.to_owned(),
            client_id: client_id.to_owned(),
            api_key: api_key,
        })
    }

    pub fn default(client_id: &str, api_key: &str) -> Result<Client> {
        Client::new(Protocol::Https, DEFAULT_API_SERVER, client_id, api_key)
    }

    pub fn verify(&self, otp: &str) -> Result<VerificationResult> {
        // Try parsing the OTP, to ensure it is vaguely valid.
        let otp = try!(Otp::new(otp));
        let request = Request::new(self.client_id.clone(),
                                   &self.api_key[..],
                                   otp,
                                   true,
                                   Some(SuccessPercentage::Secure),
                                   None);

        let mut headers = List::new();
        try!(headers.append("User-Agent: github.com/CmdrMoozy/yubirs"));

        let mut handle = Easy::new();
        if self.protocol == Protocol::HttpsWithoutVerification {
            try!(handle.ssl_verify_peer(false));
        }
        try!(handle.http_headers(headers));
        try!(handle.get(true));
        try!(handle.url(build_url(self.protocol, self.api_server.as_str(), &request).as_str()));

        let mut response = Vec::new();
        {
            let mut transfer = handle.transfer();
            try!(transfer.write_function(|data| {
                response.extend_from_slice(data);
                Ok(data.len())
            }));
            try!(transfer.perform());
        }

        Ok(try!(VerificationResult::new(request.get_otp(), request.get_nonce(), response)))
    }

    pub fn verify_prompt(&self) -> Result<VerificationResult> {
        self.verify(try!(prompt_password_stderr(TOUCH_YUBIKEY_PROMPT)).as_str())
    }
}
