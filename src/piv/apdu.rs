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
use std::fmt;

/// The Application ID to send in an APDU when connecting to a Yubikey.
const APDU_AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

/// APDU stands for "smart card Application Protocol Data Unit". This union
/// definition is used by upstream's library to alternate between treating APDU
/// data in a structured or unstructured way.
#[derive(Clone, Copy)]
pub struct Apdu {
    pub raw: [u8; 230],
}

impl Apdu {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 230 {
            bail!("Invalid APDU data; expected 230 bytes, got {}", bytes.len());
        }
        let mut apdu = Apdu { raw: [0; 230] };
        for (dst, src) in apdu.raw.iter_mut().zip(bytes.iter()) {
            *dst = *src;
        }
        Ok(apdu)
    }

    pub fn from_pieces(cla: u8, ins: u8, p1: u8, p2: u8, lc: u8, data: &[u8]) -> Result<Self> {
        if data.len() != 255 {
            bail!("Invalid APDU data; expected 255 bytes, got {}", data.len());
        }
        let mut apdu = Apdu { raw: [0; 230] };
        apdu.raw[0] = cla;
        apdu.raw[1] = ins;
        apdu.raw[2] = p1;
        apdu.raw[3] = p2;
        apdu.raw[4] = lc;
        for (dst, src) in apdu.raw[5..].iter_mut().zip(data.iter()) {
            *dst = *src;
        }
        Ok(apdu)
    }

    /// Construct a new Application ID APDU, which should be sent to the
    /// underlying hardware when we connect to it.
    pub fn new_aid() -> Result<Self> {
        let mut data: [u8; 255] = [0; 255];
        for (dst, src) in data.iter_mut().zip(APDU_AID.iter()) {
            *dst = *src;
        }
        Self::from_pieces(0, 0xa4, 0x04, 0, APDU_AID.len() as u8, &data)
    }

    /// Return this APDU's raw data, including the various properties which are
    /// normally broken out (e.g., this function returns more bytes than
    /// `data`).
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Instruction class - indicates the type of command, e.g. interindustry or
    /// proprietary.
    pub fn cla(&self) -> u8 {
        self.raw[0]
    }

    /// Instruction code - indicates the specific command, e.g. "write data".
    pub fn ins(&self) -> u8 {
        self.raw[1]
    }

    /// First instruction parameter for the command, e.g. offset into file at
    /// which to write the data.
    pub fn p1(&self) -> u8 {
        self.raw[2]
    }

    /// Second instruction parameter for the command, e.g. offset into file at
    /// which to write the data.
    pub fn p2(&self) -> u8 {
        self.raw[3]
    }

    /// Encodes the number (N_c) of bytes of command data to follow. The
    /// official specification says that this field can be variable length, but
    /// upstream specifies it statically at 1 byte.
    pub fn lc(&self) -> u8 {
        self.raw[4]
    }

    /// The command data. The official specification says this can be up to
    /// 65535 bytes long, but upstream defines it as a static 255 bytes.
    pub fn data(&self) -> &[u8] {
        &self.raw[5..]
    }
}

impl fmt::Debug for Apdu {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Apdu {{ cla: {:02x}, ins: {:02x}, p1: {:02x}, p2: {:02x}, lc: {:02x}, data: [{}] }}",
            self.cla(),
            self.ins(),
            self.p1(),
            self.p2(),
            self.lc(),
            self.data()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }
}
