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
use piv::scarderr::SmartCardError;
use serde::de::{Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

#[derive(Debug)]
pub struct StatusWord {
    pub value: u16,
    pub error: Result<()>,
    pub bytes_remaining: Option<usize>,
    pub counter: Option<usize>,
}

impl StatusWord {
    pub fn new_from_value(value: u16) -> StatusWord {
        // This page contains a partial listing of status word values:
        // https://web.archive.org/web/20090623030155/http://cheef.ru/docs/HowTo/SW1SW2.info. It is
        // likely incomplete, but at least covers all of the cases upstream's library takes
        // advantage of. So, populate the struct according to this table.

        // Extract the number of bytes remaining, if applicable for this status.
        let bytes_remaining: Option<usize> = if value & 0xff00 == 0x9f00 {
            Some((value & 0xff) as usize)
        } else if value & 0xff00 == 0x6100 {
            Some((value & 0xff) as usize)
        } else {
            None
        };

        // Extract the counter value, if applicable for this status.
        let counter: Option<usize> = if value & 0xfff0 == 0x63c0 {
            Some((value & 0xf) as usize)
        } else if value == 0x6983 {
            Some(0)
        } else {
            None
        };

        let error: Result<()> = if bytes_remaining.is_some() {
            Ok(())
        } else if value & 0xfff0 == 0x63c0 {
            Err(SmartCardError::InvalidChv.into())
        } else if value & 0xff00 == 0x6700 {
            Err(SmartCardError::InvalidParameter.into())
        } else if value & 0xff00 == 0x6c00 {
            Err("Incorrect P3 length".into())
        } else if value & 0xff00 == 0x9200 {
            Err(SmartCardError::NoMemory.into())
        } else if value & 0xff00 == 0x9400 {
            Err("File error".into())
        } else if value & 0xff00 == 0x9800 {
            Err("Security error".into())
        } else {
            match value {
                0x6200 => Err("No information given".into()),
                0x6281 => Err("Returned data may be corrupted".into()),
                0x6282 => Err(SmartCardError::Eof.into()),
                0x6283 => Err("Invalid DF".into()),
                0x6284 => Err("Selected file is not valid; file descriptor error".into()),
                0x6300 => Err(SmartCardError::InvalidChv.into()),
                0x6381 => Err("File filled up by the last write".into()),
                0x6501 => Err("Memory failure; there have been problems in writing or reading the EEPROM; other hardware problems may also bring this error".into()),
                0x6581 => Err("Write problem / memory failure / unknown mode".into()),
                0x6700 => Err("Incorrect length or address range error".into()),
                0x6800 => Err(SmartCardError::UnsupportedFeature.into()),
                0x6881 => Err("Logical channel not supported".into()),
                0x6882 => Err("Secure messaging not supported".into()),
                0x6900 => Err("No successful transaction executed during session".into()),
                0x6981 => Err("Cannot select indicated file, command not compatible with file organization".into()),
                0x6982 => Err("Authentication failure".into()),
                0x6983 => Err(SmartCardError::ChvBlocked.into()),
                0x6984 => Err("Referenced data invalidated".into()),
                0x6985 => Err("No currently selected EF, no command to monitor / no Transaction Manager File".into()),
                0x6986 => Err("Command not allowed (no current EF)".into()),
                0x6987 => Err("Expected SM data objects missing".into()),
                0x6988 => Err("SM data objects incorrect".into()),
                0x6a00 => Err("Bytes P1 and / or P2 are incorrect".into()),
                0x6a80 => Err(SmartCardError::InvalidParameter.into()),
                0x6a81 => Err("Card is blocked or command not supported".into()),
                0x6a82 => Err(SmartCardError::FileNotFound.into()),
                0x6a83 => Err("Record not found".into()),
                0x6a84 => Err(SmartCardError::NoMemory.into()),
                0x6a85 => Err("L_C inconsistent with TLV structure".into()),
                0x6a86 => Err("Incorrect parameters P1-P2".into()),
                0x6a87 => Err("The P3 value is not consistent with the P1 and P2 values".into()),
                0x6a88 => Err("Referenced data not found".into()),
                0x6b00 => Err("Incorrect object or key slot".into()),
                0x6d00 => Err("Command not allowed; invalid instruction byte".into()),
                0x6e00 => Err("Incorrect application; invalid CLA parameter".into()),
                0x6f00 => Err("Checking error".into()),
                0x9000 => Ok(()),
                0x9100 => Err("Purse balance error: cannot perform transaction".into()),
                0x9102 => Err("Purse balance error".into()),
                _ => Err(format!("Unknown status word error code {:#x}", value).into()),
            }
        };

        StatusWord {
            value: value,
            error: error,
            bytes_remaining: bytes_remaining,
            counter: counter,
        }
    }

    pub fn new(buffer: &[u8], length: usize) -> StatusWord {
        let value: u16 = if length >= 2 {
            ((buffer[length - 2] as u16) << 8) | (buffer[length - 1] as u16)
        } else {
            0
        };
        StatusWord::new_from_value(value)
    }

    pub fn success() -> StatusWord {
        StatusWord {
            value: 0x9000,
            error: Ok(()),
            bytes_remaining: None,
            counter: None,
        }
    }
}

impl Clone for StatusWord {
    fn clone(&self) -> Self {
        StatusWord::new_from_value(self.value)
    }
}

struct StatusWordVisitor;

impl<'de> Visitor<'de> for StatusWordVisitor {
    type Value = StatusWord;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a two-byte status word")
    }

    fn visit_u16<E: ::serde::de::Error>(self, v: u16) -> ::std::result::Result<Self::Value, E> {
        Ok(StatusWord::new_from_value(v))
    }
}

impl Default for StatusWordVisitor {
    fn default() -> Self {
        StatusWordVisitor {}
    }
}

impl Serialize for StatusWord {
    fn serialize<S: Serializer>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.value)
    }
}

impl<'de> Deserialize<'de> for StatusWord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> ::std::result::Result<Self, D::Error> {
        deserializer.deserialize_u16(StatusWordVisitor::default())
    }
}
