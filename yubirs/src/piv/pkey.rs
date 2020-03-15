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

use crate::error::*;
use crate::piv::id::Algorithm;
use crate::piv::util::*;
use crate::util::MaybePromptedCString;
use failure::format_err;
use lazy_static::lazy_static;
use openssl;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

const MEGABYTE: usize = 1048576;
const PASSPHRASE_PROMPT: &'static str = "Passphrase: ";

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
        FORMAT_STRINGS
            .iter()
            .map(|pair| (pair.1.to_uppercase(), *pair.0))
            .collect()
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
            None => {
                return Err(Error::InvalidArgument(format_err!(
                    "Invalid Format '{}'",
                    s
                )));
            }
            Some(o) => *o,
        })
    }
}

fn get_algorithm<T: openssl::pkey::HasPublic>(
    key: &openssl::pkey::PKeyRef<T>,
) -> Result<Algorithm> {
    let id = key.id();
    let bits = key.bits();
    Ok(match id {
        openssl::pkey::Id::RSA => match bits {
            1024 => Algorithm::Rsa1024,
            2048 => Algorithm::Rsa2048,
            _ => {
                return Err(Error::InvalidArgument(format_err!(
                    "Unsupported key algorithm RSA-{}",
                    bits
                )));
            }
        },
        openssl::pkey::Id::EC => match bits {
            256 => Algorithm::Eccp256,
            384 => Algorithm::Eccp384,
            _ => {
                return Err(Error::InvalidArgument(format_err!(
                    "Unsupported key algorithm {}-bit EC",
                    bits
                )));
            }
        },
        _ => {
            return Err(Error::InvalidArgument(format_err!(
                "Unsupported key algorithm {:?}",
                id
            )));
        }
    })
}

/// A public key. Note that this structure denotes *just the key*, not the other
/// metadata which would be included in a full X.509 certificate.
pub struct PublicKey {
    inner: openssl::pkey::PKey<openssl::pkey::Public>,
}

impl PublicKey {
    pub fn from_pem<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut data: Vec<u8> = Vec::new();
        {
            let mut f = File::open(path)?;
            if f.metadata()?.len() > MEGABYTE as u64 {
                return Err(Error::InvalidArgument(format_err!(
                    "The provided input certificate exceeded 1 MiB in size"
                )));
            }
            f.read_to_end(&mut data)?;
        }

        Ok(PublicKey {
            inner: openssl::pkey::PKey::public_key_from_pem(data.as_slice())?,
        })
    }

    /// Construct a PublicKey from the raw RSA structure returned from the
    /// underlying hardware. The provided `data` should be the entire response
    /// from the device to a `generate` command.
    pub fn from_rsa_structure(data: &[u8]) -> Result<Self> {
        // The first 5 bytes are not part of the RSA structure.
        if data.len() < 5 {
            return Err(Error::InvalidArgument(format_err!(
                "Invalid RSA data structure (too short)"
            )));
        }
        let data = &data[5..];

        // Parse the first BigNum out of the data.
        if get_required(data, 0)? != 0x81 {
            return Err(Error::InvalidArgument(format_err!(
                "Failed to parse RSA data structure (invalid tag)"
            )));
        }
        let (data, len) = read_length(&data[1..])?;
        let n = openssl::bn::BigNum::from_slice(&data[0..len])?;
        let data = &data[len..];

        // Parse the second BigNum out of the data.
        if get_required(data, 0)? != 0x82 {
            return Err(Error::InvalidArgument(format_err!(
                "Failed to parse RSA data structure (invalid tag)"
            )));
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
            return Err(Error::InvalidArgument(format_err!(
                "Invalid EC data structure (too short)"
            )));
        }
        let data = &data[3..];

        let (nid, expected_length): (openssl::nid::Nid, usize) = match algorithm {
            Algorithm::Eccp256 => (openssl::nid::Nid::X9_62_PRIME256V1, 65),
            Algorithm::Eccp384 => (openssl::nid::Nid::SECP384R1, 97),
            _ => {
                return Err(Error::InvalidArgument(format_err!(
                    "Unsupported algorithm {:?}",
                    algorithm
                )));
            }
        };

        let mut group = openssl::ec::EcGroup::from_curve_name(nid)?;
        group.set_asn1_flag(openssl::ec::Asn1Flag::NAMED_CURVE);

        if get_required(data, 0)? != 0x86 {
            return Err(Error::InvalidArgument(format_err!(
                "Failed to parse EC data structure (invalid tag)"
            )));
        }
        let (data, len) = read_length(&data[1..])?;
        if expected_length != len {
            return Err(Error::InvalidArgument(format_err!(
                "Failed to parse EC data structure (invalid length)"
            )));
        }
        let mut ctx = openssl::bn::BigNumContext::new()?;
        let point = openssl::ec::EcPoint::from_bytes(&group, &data[0..len], &mut ctx)?;

        Ok(PublicKey {
            inner: openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::from_public_key(
                &group, &point,
            )?)?,
        })
    }

    pub fn get_algorithm(&self) -> Result<Algorithm> {
        get_algorithm(self.inner.as_ref())
    }

    /// This function returns the maximum number of bytes `encrypt` can encrypt
    /// using the given algorithm.
    pub fn max_encrypt_len(&self) -> Result<usize> {
        let algorithm = self.get_algorithm()?;
        // Divide key size by 8 to convert to bytes. The padding standard
        // upstream uses occupies 11 bytes at minimum.
        Ok(match algorithm {
            Algorithm::Rsa1024 => 1024 / 8,
            Algorithm::Rsa2048 => 2048 / 8,
            _ => {
                return Err(Error::InvalidArgument(format_err!(
                    "Unsupported encryption algorithm {:?}",
                    algorithm
                )));
            }
        } - 11)
    }

    /// Encrypt the given data using this RSA public key. In order to decipher
    /// the returned ciphertext, the caller must have access to the matching
    /// private key.
    ///
    /// Note that only RSA is supported, because OpenSSL likewise only (easily)
    /// supports this kind of encryption with an RSA key.
    ///
    /// Also note that this *should not* be used to encrypt large amounts of
    /// data. In fact, as per the docs
    /// (https://www.openssl.org/docs/manmaster/man3/RSA_public_encrypt.html),
    /// this function can only encrypt at most `max_encrypt_len` bytes of data.
    ///
    /// In order to use this feature to encrypt larger amounts of data, this
    /// function should be used to wrap a *key* which is then used with a more
    /// normal cipher like AES.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let algorithm = self.get_algorithm()?;
        if algorithm.is_rsa() {
            let rsa = self.inner.rsa()?;
            if plaintext.len() + 11 > rsa.size() as usize {
                return Err(Error::InvalidArgument(format_err!(
                    "Invalid input data; this function can only encrypt at most {} bytes",
                    rsa.size() - 11
                )));
            }
            let mut ciphertext = vec![0; rsa.size() as usize];
            let len =
                rsa.public_encrypt(plaintext, &mut ciphertext, openssl::rsa::Padding::PKCS1)?;
            debug_assert!(len > plaintext.len());
            ciphertext.truncate(len);
            Ok(ciphertext)
        } else {
            return Err(Error::InvalidArgument(format_err!(
                "Unsupported public key encryption algorithm {:?}",
                algorithm
            )));
        }
    }

    pub fn format(&self, format: Format) -> Result<Vec<u8>> {
        Ok(match format {
            Format::Pem => self.inner.public_key_to_pem()?,
            Format::Der => self.inner.public_key_to_der()?,
            Format::Ssh => {
                return Err(Error::InvalidArgument(format_err!(
                    "SSH format is not supported for public keys"
                )));
            }
        })
    }
}

pub struct PrivateKey {
    inner: openssl::pkey::PKey<openssl::pkey::Private>,
}

impl PrivateKey {
    pub fn from_pem<P: AsRef<Path>>(
        path: P,
        encrypted: bool,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        let mut data: Vec<u8> = Vec::new();
        {
            let mut f = File::open(path)?;
            if f.metadata()?.len() > MEGABYTE as u64 {
                return Err(Error::InvalidArgument(format_err!(
                    "The provided input certificate exceeded 1 MiB in size"
                )));
            }
            f.read_to_end(&mut data)?;
        }

        Ok(PrivateKey {
            inner: match encrypted {
                false => openssl::pkey::PKey::private_key_from_pem(data.as_slice())?,
                true => {
                    let passphrase =
                        MaybePromptedCString::new(passphrase, PASSPHRASE_PROMPT, false)?;
                    openssl::pkey::PKey::private_key_from_pem_passphrase(
                        data.as_slice(),
                        passphrase.as_bytes(),
                    )?
                }
            },
        })
    }

    pub fn get_algorithm(&self) -> Result<Algorithm> {
        get_algorithm(self.inner.as_ref())
    }

    pub fn to_public_key(&self) -> Result<PublicKey> {
        let der = self.inner.public_key_to_der()?;
        Ok(PublicKey {
            inner: openssl::pkey::PKey::public_key_from_der(der.as_slice())?,
        })
    }

    /// Return the components which make up this private key. For RSA keys, this
    /// returns the p, q, dmp1, dmq1, and iqmp values as big-endian bytes, and
    /// for EC keys this returns the single EC private key value as big-endian
    /// bytes.
    pub fn get_components(&self) -> Result<Vec<Vec<u8>>> {
        let algorithm = self.get_algorithm()?;
        Ok(if algorithm.is_rsa() {
            let rsa = self.inner.rsa()?;
            vec![
                match rsa.p() {
                    None => {
                        return Err(Error::InvalidArgument(format_err!(
                            "This RSA key has no 'p' factor"
                        )));
                    }
                    Some(p) => p.to_vec(),
                },
                match rsa.q() {
                    None => {
                        return Err(Error::InvalidArgument(format_err!(
                            "This RSA key has no 'q' factor"
                        )));
                    }
                    Some(q) => q.to_vec(),
                },
                match rsa.dmp1() {
                    None => {
                        return Err(Error::InvalidArgument(format_err!(
                            "This RSA key has no 'dmp1' CRT exponent"
                        )));
                    }
                    Some(dmp1) => dmp1.to_vec(),
                },
                match rsa.dmq1() {
                    None => {
                        return Err(Error::InvalidArgument(format_err!(
                            "This RSA key has no 'dmq1' CRT exponent"
                        )));
                    }
                    Some(dmq1) => dmq1.to_vec(),
                },
                match rsa.iqmp() {
                    None => {
                        return Err(Error::InvalidArgument(format_err!(
                            "This RSA key has no 'iqmp' CRT coefficient"
                        )));
                    }
                    Some(iqmp) => iqmp.to_vec(),
                },
            ]
        } else if algorithm.is_ecc() {
            vec![self.inner.ec_key()?.private_key().to_vec()]
        } else {
            return Err(Error::InvalidArgument(format_err!(
                "Unsupported algorithm {:?}",
                algorithm
            )));
        })
    }
}

/// An X.509 public key. This includes both the key itself, as well as the other
/// metadata which comes with a standard X.509 certificate.
pub struct PublicKeyCertificate {
    inner: openssl::x509::X509,
}

impl PublicKeyCertificate {
    /// Load the given standard DER-encoded X.509 certificate.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Ok(PublicKeyCertificate {
            inner: openssl::x509::X509::from_der(der)?,
        })
    }

    pub fn format(&self, format: Format) -> Result<Vec<u8>> {
        Ok(match format {
            Format::Pem => self.inner.to_pem()?,
            Format::Der => self.inner.to_der()?,
            Format::Ssh => {
                return Err(Error::InvalidArgument(format_err!(
                    "SSH format is not supported for public key certificates"
                )));
            }
        })
    }
}
