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
use libc::c_int;
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
    CardAuth,
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
        m.insert(Object::CardAuth, "CardAuth");
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
            Object::CardAuth => ykpiv::YKPIV_OBJ_CARD_AUTH,
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
