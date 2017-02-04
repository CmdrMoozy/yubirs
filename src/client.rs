use data_encoding::base64;
use error::Result;

pub enum Protocol {
    Http,
    HttpsWithoutVerification,
    Https,
}

pub struct Client {
    protocol: Protocol,
    api_server: String,
    client_id: String,
    api_key: Vec<u8>,
}

static DEFAULT_API_SERVER: &'static str = "http://api.yubico.com/wsapi/2.0/verify";

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
}
