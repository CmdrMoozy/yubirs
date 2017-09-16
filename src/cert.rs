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

pub fn format_certificate(certificate: &[u8], format: Format) -> Result<String> {
    bail!("Not implemented");
}
