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
use piv::nid;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Algorithm {
    Des,
    Rsa1024,
    Rsa2048,
    Eccp256,
    Eccp384,
}

lazy_static! {
    static ref ALGORITHM_STRINGS: HashMap<Algorithm, &'static str> = {
        let mut m = HashMap::new();
        m.insert(Algorithm::Des, "3DES");
        m.insert(Algorithm::Rsa1024, "RSA1024");
        m.insert(Algorithm::Rsa2048, "RSA2048");
        m.insert(Algorithm::Eccp256, "ECCP256");
        m.insert(Algorithm::Eccp384, "ECCP384");
        m
    };
    static ref STRING_ALGORITHMS: HashMap<String, Algorithm> = {
        ALGORITHM_STRINGS
            .iter()
            .map(|pair| (pair.1.to_uppercase(), *pair.0))
            .collect()
    };
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", ALGORITHM_STRINGS.get(self).map_or("", |s| *s))
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.to_uppercase();
        Ok(match STRING_ALGORITHMS.get(&s) {
            None => {
                return Err(Error::InvalidArgument(format_err!(
                    "Invalid algorithm '{}'",
                    s
                )))
            }
            Some(a) => *a,
        })
    }
}

impl Algorithm {
    pub fn to_value(&self) -> c_uchar {
        match *self {
            Algorithm::Des => nid::YKPIV_ALGO_3DES,
            Algorithm::Rsa1024 => nid::YKPIV_ALGO_RSA1024,
            Algorithm::Rsa2048 => nid::YKPIV_ALGO_RSA2048,
            Algorithm::Eccp256 => nid::YKPIV_ALGO_ECCP256,
            Algorithm::Eccp384 => nid::YKPIV_ALGO_ECCP384,
        }
    }

    pub fn is_rsa(&self) -> bool {
        match *self {
            Algorithm::Rsa1024 => true,
            Algorithm::Rsa2048 => true,
            _ => false,
        }
    }

    pub fn is_ecc(&self) -> bool {
        match *self {
            Algorithm::Eccp256 => true,
            Algorithm::Eccp384 => true,
            _ => false,
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Instruction {
    Attest,
    Authenticate,
    ChangeReference,
    GenerateAsymmetric,
    GetData,
    GetVersion,
    ImportKey,
    PutData,
    Reset,
    ResetRetry,
    SetManagementKey,
    SetPinRetries,
    Verify,
}

lazy_static! {
    static ref INSTRUCTION_STRINGS: HashMap<Instruction, &'static str> = {
        let mut m = HashMap::new();
        m.insert(Instruction::Attest, "Attest");
        m.insert(Instruction::Authenticate, "Authenticate");
        m.insert(Instruction::ChangeReference, "ChangeReference");
        m.insert(Instruction::GenerateAsymmetric, "GenerateAsymmetric");
        m.insert(Instruction::GetData, "GetData");
        m.insert(Instruction::GetVersion, "GetVersion");
        m.insert(Instruction::ImportKey, "ImportKey");
        m.insert(Instruction::PutData, "PutData");
        m.insert(Instruction::Reset, "Reset");
        m.insert(Instruction::ResetRetry, "ResetRetry");
        m.insert(Instruction::SetManagementKey, "SetManagementKey");
        m.insert(Instruction::SetPinRetries, "SetPinRetries");
        m.insert(Instruction::Verify, "Verify");
        m
    };
    static ref STRING_INSTRUCTIONS: HashMap<String, Instruction> = {
        INSTRUCTION_STRINGS
            .iter()
            .map(|pair| (pair.1.to_uppercase(), *pair.0))
            .collect()
    };
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", INSTRUCTION_STRINGS.get(self).map_or("", |s| *s))
    }
}

impl FromStr for Instruction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.to_uppercase();
        Ok(match STRING_INSTRUCTIONS.get(&s) {
            None => {
                return Err(Error::InvalidArgument(format_err!(
                    "Invalid instruction '{}'",
                    s
                )))
            }
            Some(i) => *i,
        })
    }
}

impl Instruction {
    pub fn to_value(&self) -> u8 {
        match *self {
            Instruction::Attest => nid::YKPIV_INS_ATTEST,
            Instruction::Authenticate => nid::YKPIV_INS_AUTHENTICATE,
            Instruction::ChangeReference => nid::YKPIV_INS_CHANGE_REFERENCE,
            Instruction::GenerateAsymmetric => nid::YKPIV_INS_GENERATE_ASYMMETRIC,
            Instruction::GetData => nid::YKPIV_INS_GET_DATA,
            Instruction::GetVersion => nid::YKPIV_INS_GET_VERSION,
            Instruction::ImportKey => nid::YKPIV_INS_IMPORT_KEY,
            Instruction::PutData => nid::YKPIV_INS_PUT_DATA,
            Instruction::Reset => nid::YKPIV_INS_RESET,
            Instruction::ResetRetry => nid::YKPIV_INS_RESET_RETRY,
            Instruction::SetManagementKey => nid::YKPIV_INS_SET_MGMKEY,
            Instruction::SetPinRetries => nid::YKPIV_INS_SET_PIN_RETRIES,
            Instruction::Verify => nid::YKPIV_INS_VERIFY,
        }
    }
}

/// This enumeration describes the identifiers for the various slots the Yubikey has for
/// certificates.
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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
        KEY_STRINGS
            .iter()
            .map(|pair| (pair.1.to_uppercase(), *pair.0))
            .collect()
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
            None => return Err(Error::InvalidArgument(format_err!("Invalid Key '{}'", s))),
            Some(o) => *o,
        })
    }
}

impl Key {
    pub fn to_value(&self) -> c_uchar {
        match *self {
            Key::Authentication => nid::YKPIV_KEY_AUTHENTICATION,
            Key::CardManagement => nid::YKPIV_KEY_CARDMGM,
            Key::Signature => nid::YKPIV_KEY_SIGNATURE,
            Key::KeyManagement => nid::YKPIV_KEY_KEYMGM,
            Key::CardAuthentication => nid::YKPIV_KEY_CARDAUTH,
            Key::Retired1 => nid::YKPIV_KEY_RETIRED1,
            Key::Retired2 => nid::YKPIV_KEY_RETIRED2,
            Key::Retired3 => nid::YKPIV_KEY_RETIRED3,
            Key::Retired4 => nid::YKPIV_KEY_RETIRED4,
            Key::Retired5 => nid::YKPIV_KEY_RETIRED5,
            Key::Retired6 => nid::YKPIV_KEY_RETIRED6,
            Key::Retired7 => nid::YKPIV_KEY_RETIRED7,
            Key::Retired8 => nid::YKPIV_KEY_RETIRED8,
            Key::Retired9 => nid::YKPIV_KEY_RETIRED9,
            Key::Retired10 => nid::YKPIV_KEY_RETIRED10,
            Key::Retired11 => nid::YKPIV_KEY_RETIRED11,
            Key::Retired12 => nid::YKPIV_KEY_RETIRED12,
            Key::Retired13 => nid::YKPIV_KEY_RETIRED13,
            Key::Retired14 => nid::YKPIV_KEY_RETIRED14,
            Key::Retired15 => nid::YKPIV_KEY_RETIRED15,
            Key::Retired16 => nid::YKPIV_KEY_RETIRED16,
            Key::Retired17 => nid::YKPIV_KEY_RETIRED17,
            Key::Retired18 => nid::YKPIV_KEY_RETIRED18,
            Key::Retired19 => nid::YKPIV_KEY_RETIRED19,
            Key::Retired20 => nid::YKPIV_KEY_RETIRED20,
            Key::Attestation => nid::YKPIV_KEY_ATTESTATION,
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
            _ => {
                return Err(Error::InvalidArgument(format_err!(
                    "Key '{}' has no associated data object",
                    self
                )))
            }
        })
    }
}

/// This enumeration describes the identifiers for the various objects a YubiKey can store.
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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
        OBJECT_STRINGS
            .iter()
            .map(|pair| (pair.1.to_uppercase(), *pair.0))
            .collect()
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
            None => {
                return Err(Error::InvalidArgument(format_err!(
                    "Invalid Object '{}'",
                    s
                )))
            }
            Some(o) => *o,
        })
    }
}

impl Object {
    pub fn to_value(&self) -> c_int {
        match *self {
            Object::Capability => nid::YKPIV_OBJ_CAPABILITY,
            Object::Chuid => nid::YKPIV_OBJ_CHUID,
            Object::Authentication => nid::YKPIV_OBJ_AUTHENTICATION,
            Object::Fingerprints => nid::YKPIV_OBJ_FINGERPRINTS,
            Object::Security => nid::YKPIV_OBJ_SECURITY,
            Object::Facial => nid::YKPIV_OBJ_FACIAL,
            Object::Printed => nid::YKPIV_OBJ_PRINTED,
            Object::Signature => nid::YKPIV_OBJ_SIGNATURE,
            Object::KeyManagement => nid::YKPIV_OBJ_KEY_MANAGEMENT,
            Object::CardAuthentication => nid::YKPIV_OBJ_CARD_AUTH,
            Object::Discovery => nid::YKPIV_OBJ_DISCOVERY,
            Object::KeyHistory => nid::YKPIV_OBJ_KEY_HISTORY,
            Object::Iris => nid::YKPIV_OBJ_IRIS,
            Object::Retired1 => nid::YKPIV_OBJ_RETIRED1,
            Object::Retired2 => nid::YKPIV_OBJ_RETIRED2,
            Object::Retired3 => nid::YKPIV_OBJ_RETIRED3,
            Object::Retired4 => nid::YKPIV_OBJ_RETIRED4,
            Object::Retired5 => nid::YKPIV_OBJ_RETIRED5,
            Object::Retired6 => nid::YKPIV_OBJ_RETIRED6,
            Object::Retired7 => nid::YKPIV_OBJ_RETIRED7,
            Object::Retired8 => nid::YKPIV_OBJ_RETIRED8,
            Object::Retired9 => nid::YKPIV_OBJ_RETIRED9,
            Object::Retired10 => nid::YKPIV_OBJ_RETIRED10,
            Object::Retired11 => nid::YKPIV_OBJ_RETIRED11,
            Object::Retired12 => nid::YKPIV_OBJ_RETIRED12,
            Object::Retired13 => nid::YKPIV_OBJ_RETIRED13,
            Object::Retired14 => nid::YKPIV_OBJ_RETIRED14,
            Object::Retired15 => nid::YKPIV_OBJ_RETIRED15,
            Object::Retired16 => nid::YKPIV_OBJ_RETIRED16,
            Object::Retired17 => nid::YKPIV_OBJ_RETIRED17,
            Object::Retired18 => nid::YKPIV_OBJ_RETIRED18,
            Object::Retired19 => nid::YKPIV_OBJ_RETIRED19,
            Object::Retired20 => nid::YKPIV_OBJ_RETIRED20,
            Object::Attestation => nid::YKPIV_OBJ_ATTESTATION,
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum PinPolicy {
    Default,
    Never,
    Once,
    Always,
}

lazy_static! {
    static ref PIN_POLICY_STRINGS: HashMap<PinPolicy, &'static str> = {
        let mut m = HashMap::new();
        m.insert(PinPolicy::Default, "Default");
        m.insert(PinPolicy::Never, "Never");
        m.insert(PinPolicy::Once, "Once");
        m.insert(PinPolicy::Always, "Always");
        m
    };
    static ref STRING_PIN_POLICIES: HashMap<String, PinPolicy> = {
        PIN_POLICY_STRINGS
            .iter()
            .map(|pair| (pair.1.to_uppercase(), *pair.0))
            .collect()
    };
}

impl fmt::Display for PinPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", PIN_POLICY_STRINGS.get(self).map_or("", |s| *s))
    }
}

impl FromStr for PinPolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.to_uppercase();
        Ok(match STRING_PIN_POLICIES.get(&s) {
            None => {
                return Err(Error::InvalidArgument(format_err!(
                    "Invalid PIN policy '{}'",
                    s
                )))
            }
            Some(pp) => *pp,
        })
    }
}

impl PinPolicy {
    pub fn to_value(&self) -> c_uchar {
        match *self {
            PinPolicy::Default => nid::YKPIV_PINPOLICY_DEFAULT,
            PinPolicy::Never => nid::YKPIV_PINPOLICY_NEVER,
            PinPolicy::Once => nid::YKPIV_PINPOLICY_ONCE,
            PinPolicy::Always => nid::YKPIV_PINPOLICY_ALWAYS,
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Tag {
    Algorithm,
    PinPolicy,
    TouchPolicy,
}

lazy_static! {
    static ref TAG_STRINGS: HashMap<Tag, &'static str> = {
        let mut m = HashMap::new();
        m.insert(Tag::Algorithm, "Algorithm");
        m.insert(Tag::PinPolicy, "PinPolicy");
        m.insert(Tag::TouchPolicy, "TouchPolicy");
        m
    };
    static ref STRING_TAGS: HashMap<String, Tag> = {
        TAG_STRINGS
            .iter()
            .map(|pair| (pair.1.to_uppercase(), *pair.0))
            .collect()
    };
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", TAG_STRINGS.get(self).map_or("", |s| *s))
    }
}

impl FromStr for Tag {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.to_uppercase();
        Ok(match STRING_TAGS.get(&s) {
            None => return Err(Error::InvalidArgument(format_err!("Invalid tag '{}'", s))),
            Some(t) => *t,
        })
    }
}

impl Tag {
    pub fn to_value(&self) -> u8 {
        match *self {
            Tag::Algorithm => nid::YKPIV_ALGO_TAG,
            Tag::PinPolicy => nid::YKPIV_PINPOLICY_TAG,
            Tag::TouchPolicy => nid::YKPIV_TOUCHPOLICY_TAG,
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum TouchPolicy {
    Default,
    Never,
    Always,
    Cached,
}

lazy_static! {
    static ref TOUCH_POLICY_STRINGS: HashMap<TouchPolicy, &'static str> = {
        let mut m = HashMap::new();
        m.insert(TouchPolicy::Default, "Default");
        m.insert(TouchPolicy::Never, "Never");
        m.insert(TouchPolicy::Always, "Always");
        m.insert(TouchPolicy::Cached, "Cached");
        m
    };
    static ref STRING_TOUCH_POLICIES: HashMap<String, TouchPolicy> = {
        TOUCH_POLICY_STRINGS
            .iter()
            .map(|pair| (pair.1.to_uppercase(), *pair.0))
            .collect()
    };
}

impl fmt::Display for TouchPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", TOUCH_POLICY_STRINGS.get(self).map_or("", |s| *s))
    }
}

impl FromStr for TouchPolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.to_uppercase();
        Ok(match STRING_TOUCH_POLICIES.get(&s) {
            None => {
                return Err(Error::InvalidArgument(format_err!(
                    "Invalid touch policy '{}'",
                    s
                )))
            }
            Some(tp) => *tp,
        })
    }
}

impl TouchPolicy {
    pub fn to_value(&self) -> c_uchar {
        match *self {
            TouchPolicy::Default => nid::YKPIV_TOUCHPOLICY_DEFAULT,
            TouchPolicy::Never => nid::YKPIV_TOUCHPOLICY_NEVER,
            TouchPolicy::Always => nid::YKPIV_TOUCHPOLICY_ALWAYS,
            TouchPolicy::Cached => nid::YKPIV_TOUCHPOLICY_CACHED,
        }
    }
}
