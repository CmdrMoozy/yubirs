use curl::easy::{Easy, List};
use data_encoding::{base64, base64url};
use error::Result;
use otp::Otp;
use result::VerificationResult;
use rpassword::prompt_password_stderr;
use sodiumoxide::randombytes::randombytes;
use std::collections::HashMap;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum Protocol {
    Http,
    HttpsWithoutVerification,
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

/// Generate a 40 character long string with random unique data.
fn gen_yubico_api_nonce() -> String {
    base64url::encode(randombytes(30).as_slice())
}

fn build_url(protocol: Protocol,
             api_server: &str,
             client_id: &str,
             otp: &str,
             nonce: &str)
             -> String {
    format!("{}{}?id={}&otp={}&nonce={}&sl=secure&timestamp=1",
            PROTOCOL_PREFIXES.get(&protocol).unwrap(),
            api_server,
            client_id,
            otp,
            nonce)
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
        try!(Otp::new(otp));

        let nonce = gen_yubico_api_nonce();

        let mut headers = List::new();
        try!(headers.append("User-Agent: github.com/CmdrMoozy/yubirs"));

        let mut handle = Easy::new();
        try!(handle.http_headers(headers));
        try!(handle.get(true));
        try!(handle.url(build_url(self.protocol,
                                  self.api_server.as_str(),
                                  self.client_id.as_str(),
                                  otp,
                                  nonce.as_str())
            .as_str()));

        let mut response = Vec::new();
        {
            let mut transfer = handle.transfer();
            try!(transfer.write_function(|data| {
                response.extend_from_slice(data);
                Ok(data.len())
            }));
            try!(transfer.perform());
        }

        Ok(try!(VerificationResult::new(response)))
    }

    pub fn verify_prompt(&self) -> Result<VerificationResult> {
        self.verify(try!(prompt_password_stderr(TOUCH_YUBIKEY_PROMPT)).as_str())
    }
}
