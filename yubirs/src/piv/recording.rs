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
use crate::piv::apdu::Apdu;
use crate::piv::sw::StatusWord;
use bincode;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::File;
use std::path::Path;

pub type RecordedResult<T> = ::std::result::Result<T, String>;

#[derive(Debug, Deserialize, Serialize)]
pub struct RecordingEntry {
    pub sent: Vec<u8>,
    pub received: RecordedResult<(StatusWord, Vec<u8>)>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Recording(pub VecDeque<RecordingEntry>);

impl Recording {
    pub fn record(&mut self, sent: &Apdu, received: &crate::error::Result<(StatusWord, Vec<u8>)>) {
        self.0.push_back(RecordingEntry {
            sent: sent.raw_minimal().to_vec(),
            received: match received {
                &Err(ref e) => Err(e.to_string()),
                &Ok(ref tuple) => Ok(tuple.clone()),
            },
        })
    }

    pub fn flush<P: AsRef<Path>>(&self, output: P) -> Result<()> {
        Ok(bincode::serialize_into(File::create(output)?, self)?)
    }
}

impl Default for Recording {
    fn default() -> Self {
        Recording(VecDeque::new())
    }
}
