use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use curl::easy::Easy;
use data_encoding::base64;

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
    let signature = base64::encode(&generate_signature(key, data)[..]);
    url_encode(signature.as_str())
}
