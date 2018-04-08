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

use error::*;
use openssl;
use piv::id::Algorithm;
use piv::util::*;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum Format {
    Pem,
    Der,
    Ssh,
}

lazy_static! {
    static ref FORMAT_STRINGS: HashMap<Format, &'static str> = {
        let mut m = HashMap::new();
        m.insert(Format::Pem, "PEM");
        m.insert(Format::Der, "DER");
        m.insert(Format::Ssh, "SSH");
        m
    };

    static ref STRING_FORMATS: HashMap<String, Format> = {
        FORMAT_STRINGS.iter().map(|pair| (pair.1.to_uppercase(), *pair.0)).collect()
    };
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", FORMAT_STRINGS.get(self).map_or("", |s| *s))
    }
}

impl FromStr for Format {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.to_uppercase();
        Ok(match STRING_FORMATS.get(&s) {
            None => bail!("Invalid Format '{}'", s),
            Some(o) => *o,
        })
    }
}

/// A public key.
pub struct PublicKey {
    inner: openssl::pkey::PKey<openssl::pkey::Public>,
}

impl PublicKey {
    /// Construct a PublicKey from the raw RSA structure returned from the
    /// underlying hardware. The provided `data` should be the entire response
    /// from the device to a `generate` command.
    pub fn from_rsa_structure(data: &[u8]) -> Result<Self> {
        // The first 5 bytes are not part of the RSA structure.
        if data.len() < 5 {
            bail!("Invalid RSA data structure (too short)");
        }
        let data = &data[5..];

        // Parse the first BigNum out of the data.
        if get_required(data, 0)? != 0x81 {
            bail!("Failed to parse RSA data structure (invalid tag)");
        }
        let (data, len) = read_length(&data[1..])?;
        let n = openssl::bn::BigNum::from_slice(&data[0..len])?;
        let data = &data[len..];

        // Parse the second BigNum out of the data.
        if get_required(data, 0)? != 0x82 {
            bail!("Failed to parse RSA data structure (invalid tag)");
        }
        let (data, len) = read_length(&data[1..])?;
        let e = openssl::bn::BigNum::from_slice(&data[0..len])?;

        Ok(PublicKey {
            inner: openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::from_public_components(n, e)?)?,
        })
    }

    /// Construct a PublicKey from the raw EC structure returned from the
    /// underlying hardware. The provided `data` should be the entire response
    /// from the device to a `generate` command.
    pub fn from_ec_structure(algorithm: Algorithm, data: &[u8]) -> Result<Self> {
        // The first 3 bytes are not part of the EC structure.
        if data.len() < 3 {
            bail!("Invalid EC data structure (too short)");
        }
        let data = &data[3..];

        let (nid, expected_length): (openssl::nid::Nid, usize) = match algorithm {
            Algorithm::Eccp256 => (openssl::nid::Nid::X9_62_PRIME256V1, 65),
            Algorithm::Eccp384 => (openssl::nid::Nid::SECP384R1, 97),
            _ => bail!("Unsupported algorithm {:?}", algorithm),
        };

        let mut group = openssl::ec::EcGroup::from_curve_name(nid)?;
        group.set_asn1_flag(openssl::ec::Asn1Flag::NAMED_CURVE);

        if get_required(data, 0)? != 0x86 {
            bail!("Failed to parse EC data structure (invalid tag)");
        }
        let (data, len) = read_length(&data[1..])?;
        if expected_length != len {
            bail!("Failed to parse EC data structure (invalid length)");
        }
        let mut ctx = openssl::bn::BigNumContext::new()?;
        let point = openssl::ec::EcPoint::from_bytes(&group, &data[0..len], &mut ctx)?;

        Ok(PublicKey {
            inner: openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::from_public_key(
                &group,
                &point,
            )?)?,
        })
    }

    pub fn format(&self, format: Format) -> Result<Vec<u8>> {
        Ok(match format {
            Format::Pem => self.inner.public_key_to_pem()?,
            Format::Der => self.inner.public_key_to_der()?,
            Format::Ssh => bail!("SSH format is not supported for public keys"),
        })
    }
}
