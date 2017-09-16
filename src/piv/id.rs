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
use libc::{c_int, c_uchar};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use yubico_piv_tool_sys as ykpiv;

/// This enumeration describes the identifiers for the various objects a YubiKey can store.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Object {
    Capability,
    Chuid,
    Authentication,
    Fingerprints,
    Security,
    Facial,
    Printed,
    Signature,
    KeyManagement,
    CardAuthentication,
    Discovery,
    KeyHistory,
    Iris,
    Retired1,
    Retired2,
    Retired3,
    Retired4,
    Retired5,
    Retired6,
    Retired7,
    Retired8,
    Retired9,
    Retired10,
    Retired11,
    Retired12,
    Retired13,
    Retired14,
    Retired15,
    Retired16,
    Retired17,
    Retired18,
    Retired19,
    Retired20,
    Attestation,
}

lazy_static! {
    static ref OBJECT_STRINGS: HashMap<Object, &'static str> = {
        let mut m = HashMap::new();
        m.insert(Object::Capability, "Capability");
        m.insert(Object::Chuid, "Chuid");
        m.insert(Object::Authentication, "Authentication");
        m.insert(Object::Fingerprints, "Fingerprints");
        m.insert(Object::Security, "Security");
        m.insert(Object::Facial, "Facial");
        m.insert(Object::Printed, "Printed");
        m.insert(Object::Signature, "Signature");
        m.insert(Object::KeyManagement, "KeyManagement");
        m.insert(Object::CardAuthentication, "CardAuthentication");
        m.insert(Object::Discovery, "Discovery");
        m.insert(Object::KeyHistory, "KeyHistory");
        m.insert(Object::Iris, "Iris");
        m.insert(Object::Retired1, "Retired1");
        m.insert(Object::Retired2, "Retired2");
        m.insert(Object::Retired3, "Retired3");
        m.insert(Object::Retired4, "Retired4");
        m.insert(Object::Retired5, "Retired5");
        m.insert(Object::Retired6, "Retired6");
        m.insert(Object::Retired7, "Retired7");
        m.insert(Object::Retired8, "Retired8");
        m.insert(Object::Retired9, "Retired9");
        m.insert(Object::Retired10, "Retired10");
        m.insert(Object::Retired11, "Retired11");
        m.insert(Object::Retired12, "Retired12");
        m.insert(Object::Retired13, "Retired13");
        m.insert(Object::Retired14, "Retired14");
        m.insert(Object::Retired15, "Retired15");
        m.insert(Object::Retired16, "Retired16");
        m.insert(Object::Retired17, "Retired17");
        m.insert(Object::Retired18, "Retired18");
        m.insert(Object::Retired19, "Retired19");
        m.insert(Object::Retired20, "Retired20");
        m.insert(Object::Attestation, "Attestation");
        m
    };

    static ref STRING_OBJECTS: HashMap<String, Object> = {
        OBJECT_STRINGS.iter().map(|pair| (pair.1.to_uppercase(), *pair.0)).collect()
    };
}

impl fmt::Display for Object {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", OBJECT_STRINGS.get(self).map_or("", |s| *s))
    }
}

impl FromStr for Object {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.to_uppercase();
        Ok(match STRING_OBJECTS.get(&s) {
            None => bail!("Invalid Object '{}'", s),
            Some(o) => *o,
        })
    }
}

impl Object {
    pub fn to_value(&self) -> c_int {
        match *self {
            Object::Capability => ykpiv::YKPIV_OBJ_CAPABILITY,
            Object::Chuid => ykpiv::YKPIV_OBJ_CHUID,
            Object::Authentication => ykpiv::YKPIV_OBJ_AUTHENTICATION,
            Object::Fingerprints => ykpiv::YKPIV_OBJ_FINGERPRINTS,
            Object::Security => ykpiv::YKPIV_OBJ_SECURITY,
            Object::Facial => ykpiv::YKPIV_OBJ_FACIAL,
            Object::Printed => ykpiv::YKPIV_OBJ_PRINTED,
            Object::Signature => ykpiv::YKPIV_OBJ_SIGNATURE,
            Object::KeyManagement => ykpiv::YKPIV_OBJ_KEY_MANAGEMENT,
            Object::CardAuthentication => ykpiv::YKPIV_OBJ_CARD_AUTH,
            Object::Discovery => ykpiv::YKPIV_OBJ_DISCOVERY,
            Object::KeyHistory => ykpiv::YKPIV_OBJ_KEY_HISTORY,
            Object::Iris => ykpiv::YKPIV_OBJ_IRIS,
            Object::Retired1 => ykpiv::YKPIV_OBJ_RETIRED1,
            Object::Retired2 => ykpiv::YKPIV_OBJ_RETIRED2,
            Object::Retired3 => ykpiv::YKPIV_OBJ_RETIRED3,
            Object::Retired4 => ykpiv::YKPIV_OBJ_RETIRED4,
            Object::Retired5 => ykpiv::YKPIV_OBJ_RETIRED5,
            Object::Retired6 => ykpiv::YKPIV_OBJ_RETIRED6,
            Object::Retired7 => ykpiv::YKPIV_OBJ_RETIRED7,
            Object::Retired8 => ykpiv::YKPIV_OBJ_RETIRED8,
            Object::Retired9 => ykpiv::YKPIV_OBJ_RETIRED9,
            Object::Retired10 => ykpiv::YKPIV_OBJ_RETIRED10,
            Object::Retired11 => ykpiv::YKPIV_OBJ_RETIRED11,
            Object::Retired12 => ykpiv::YKPIV_OBJ_RETIRED12,
            Object::Retired13 => ykpiv::YKPIV_OBJ_RETIRED13,
            Object::Retired14 => ykpiv::YKPIV_OBJ_RETIRED14,
            Object::Retired15 => ykpiv::YKPIV_OBJ_RETIRED15,
            Object::Retired16 => ykpiv::YKPIV_OBJ_RETIRED16,
            Object::Retired17 => ykpiv::YKPIV_OBJ_RETIRED17,
            Object::Retired18 => ykpiv::YKPIV_OBJ_RETIRED18,
            Object::Retired19 => ykpiv::YKPIV_OBJ_RETIRED19,
            Object::Retired20 => ykpiv::YKPIV_OBJ_RETIRED20,
            Object::Attestation => ykpiv::YKPIV_OBJ_ATTESTATION,
        }
    }
}

/// This enumeration describes the identifiers for the various slots the Yubikey has for
/// certificates.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Key {
    /// Used to authenticate the card and the cardholder. Used for things like system login. The
    /// PIN is required to perform any private key operations.
    Authentication,
    /// The card management key, used to authenticate administrative / management functionality on
    /// the Yubikey itself.
    CardManagement,
    /// Used for digital dignatures for the purpose of document signing, or signing files and
    /// executables. The PIN is required to perform any private key operations.
    Signature,
    /// Used for encryption for confidentiality, e.g. encrypting e-mails or files. The PIN is
    /// required to perform any private key operations.
    KeyManagement,
    /// Used to support additional physical access applications, such as providing physical access
    /// to buildings via PIV-enabled door locks. The PIN is NOT required to perform private key
    /// operations.
    CardAuthentication,
    Retired1,
    Retired2,
    Retired3,
    Retired4,
    Retired5,
    Retired6,
    Retired7,
    Retired8,
    Retired9,
    Retired10,
    Retired11,
    Retired12,
    Retired13,
    Retired14,
    Retired15,
    Retired16,
    Retired17,
    Retired18,
    Retired19,
    Retired20,
    /// This slot is only available on Yubikey 4.3 and newer. It is used for attestation of other
    /// keys generated on device. This slot is not cleared on reset, but can be overwritten.
    Attestation,
}

lazy_static! {
    static ref KEY_STRINGS: HashMap<Key, &'static str> = {
        let mut m = HashMap::new();
        m.insert(Key::Authentication, "Authentication");
        m.insert(Key::CardManagement, "CardManagement");
        m.insert(Key::Signature, "Signature");
        m.insert(Key::KeyManagement, "KeyManagement");
        m.insert(Key::CardAuthentication, "CardAuthentication");
        m.insert(Key::Retired1, "Retired1");
        m.insert(Key::Retired2, "Retired2");
        m.insert(Key::Retired3, "Retired3");
        m.insert(Key::Retired4, "Retired4");
        m.insert(Key::Retired5, "Retired5");
        m.insert(Key::Retired6, "Retired6");
        m.insert(Key::Retired7, "Retired7");
        m.insert(Key::Retired8, "Retired8");
        m.insert(Key::Retired9, "Retired9");
        m.insert(Key::Retired10, "Retired10");
        m.insert(Key::Retired11, "Retired11");
        m.insert(Key::Retired12, "Retired12");
        m.insert(Key::Retired13, "Retired13");
        m.insert(Key::Retired14, "Retired14");
        m.insert(Key::Retired15, "Retired15");
        m.insert(Key::Retired16, "Retired16");
        m.insert(Key::Retired17, "Retired17");
        m.insert(Key::Retired18, "Retired18");
        m.insert(Key::Retired19, "Retired19");
        m.insert(Key::Retired20, "Retired20");
        m.insert(Key::Attestation, "Attestation");
        m
    };

    static ref STRING_KEYS: HashMap<String, Key> = {
        KEY_STRINGS.iter().map(|pair| (pair.1.to_uppercase(), *pair.0)).collect()
    };
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", KEY_STRINGS.get(self).map_or("", |s| *s))
    }
}

impl FromStr for Key {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.to_uppercase();
        Ok(match STRING_KEYS.get(&s) {
            None => bail!("Invalid Key '{}'", s),
            Some(o) => *o,
        })
    }
}

impl Key {
    pub fn to_value(&self) -> c_uchar {
        match *self {
            Key::Authentication => ykpiv::YKPIV_KEY_AUTHENTICATION,
            Key::CardManagement => ykpiv::YKPIV_KEY_CARDMGM,
            Key::Signature => ykpiv::YKPIV_KEY_SIGNATURE,
            Key::KeyManagement => ykpiv::YKPIV_KEY_KEYMGM,
            Key::CardAuthentication => ykpiv::YKPIV_KEY_CARDAUTH,
            Key::Retired1 => ykpiv::YKPIV_KEY_RETIRED1,
            Key::Retired2 => ykpiv::YKPIV_KEY_RETIRED2,
            Key::Retired3 => ykpiv::YKPIV_KEY_RETIRED3,
            Key::Retired4 => ykpiv::YKPIV_KEY_RETIRED4,
            Key::Retired5 => ykpiv::YKPIV_KEY_RETIRED5,
            Key::Retired6 => ykpiv::YKPIV_KEY_RETIRED6,
            Key::Retired7 => ykpiv::YKPIV_KEY_RETIRED7,
            Key::Retired8 => ykpiv::YKPIV_KEY_RETIRED8,
            Key::Retired9 => ykpiv::YKPIV_KEY_RETIRED9,
            Key::Retired10 => ykpiv::YKPIV_KEY_RETIRED10,
            Key::Retired11 => ykpiv::YKPIV_KEY_RETIRED11,
            Key::Retired12 => ykpiv::YKPIV_KEY_RETIRED12,
            Key::Retired13 => ykpiv::YKPIV_KEY_RETIRED13,
            Key::Retired14 => ykpiv::YKPIV_KEY_RETIRED14,
            Key::Retired15 => ykpiv::YKPIV_KEY_RETIRED15,
            Key::Retired16 => ykpiv::YKPIV_KEY_RETIRED16,
            Key::Retired17 => ykpiv::YKPIV_KEY_RETIRED17,
            Key::Retired18 => ykpiv::YKPIV_KEY_RETIRED18,
            Key::Retired19 => ykpiv::YKPIV_KEY_RETIRED19,
            Key::Retired20 => ykpiv::YKPIV_KEY_RETIRED20,
            Key::Attestation => ykpiv::YKPIV_KEY_ATTESTATION,
        }
    }

    /// Each key is stored as a data object on the Yubikey. So, to retrieve a stored key, we need
    /// the Object ID associated with it (which this function returns).
    ///
    /// Note that, for some Keys, there is no associated Object. In this case, an error will be
    /// returned instead.
    pub fn to_object(&self) -> Result<Object> {
        Ok(match *self {
            Key::Authentication => Object::Authentication,
            Key::Signature => Object::Signature,
            Key::KeyManagement => Object::KeyManagement,
            Key::CardAuthentication => Object::CardAuthentication,
            Key::Retired1 => Object::Retired1,
            Key::Retired2 => Object::Retired2,
            Key::Retired3 => Object::Retired3,
            Key::Retired4 => Object::Retired4,
            Key::Retired5 => Object::Retired5,
            Key::Retired6 => Object::Retired6,
            Key::Retired7 => Object::Retired7,
            Key::Retired8 => Object::Retired8,
            Key::Retired9 => Object::Retired9,
            Key::Retired10 => Object::Retired10,
            Key::Retired11 => Object::Retired11,
            Key::Retired12 => Object::Retired12,
            Key::Retired13 => Object::Retired13,
            Key::Retired14 => Object::Retired14,
            Key::Retired15 => Object::Retired15,
            Key::Retired16 => Object::Retired16,
            Key::Retired17 => Object::Retired17,
            Key::Retired18 => Object::Retired18,
            Key::Retired19 => Object::Retired19,
            Key::Retired20 => Object::Retired20,
            Key::Attestation => Object::Attestation,
            _ => bail!("Key '{}' has no associated data object", self),
        })
    }
}
