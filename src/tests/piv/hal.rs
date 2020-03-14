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
use crate::piv::hal::*;
use crate::piv::recording::{Recording, RecordingEntry};
use crate::piv::sw::StatusWord;
use crate::piv::DEFAULT_READER;
use bincode;
use failure::format_err;
use std::collections::VecDeque;
use std::sync::Mutex;

pub struct PcscTestStub {
    connected: bool,
    readers: Vec<String>,
    recordings: Mutex<VecDeque<Recording>>,
}

impl PcscTestStub {
    pub fn set_mock_readers(&mut self, readers: &[&str]) {
        self.readers = readers
            .iter()
            .map(|&r| -> String { r.to_owned() })
            .collect();
    }

    pub fn push_recording(&self, recording: &[u8]) -> Result<&Self> {
        self.recordings
            .lock()
            .unwrap()
            .push_back(bincode::deserialize(recording)?);
        Ok(self)
    }

    pub fn no_recordings(&self) -> bool {
        self.recordings.lock().unwrap().is_empty()
    }
}

impl PcscHal for PcscTestStub {
    fn new() -> Result<Self> {
        Ok(PcscTestStub {
            connected: false,
            readers: vec![DEFAULT_READER.to_owned()],
            recordings: Mutex::new(VecDeque::new()),
        })
    }

    fn secure_random_bytes(&self, buf: &mut [u8]) -> Result<()> {
        for dst in buf.iter_mut() {
            *dst = 0xff;
        }
        Ok(())
    }

    fn cheap_random_bytes(&self, buf: &mut [u8]) -> Result<()> {
        self.secure_random_bytes(buf)
    }

    fn list_readers(&self) -> Result<Vec<String>> {
        Ok(self.readers.clone())
    }

    fn connect_impl(&mut self, _reader: &str) -> Result<()> {
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) {
        self.connected = false;
    }

    fn send_data_impl(&self, apdu: &Apdu) -> Result<(StatusWord, Vec<u8>)> {
        if !self.connected {
            return Err(Error::Internal(format_err!(
                "Can't send data without first being connected"
            )));
        }

        let entry: RecordingEntry;
        let pop: bool;
        let mut recordings = self.recordings.lock().unwrap();

        {
            let recording = match recordings.front_mut() {
                None => {
                    return Err(Error::Internal(format_err!(
                        "Unexpected call to send_data_impl (no more mock recordings)"
                    )));
                }
                Some(recording) => recording,
            };
            entry = recording.0.pop_front().unwrap();
            pop = recording.0.is_empty();
        }

        if pop {
            recordings.pop_front();
        }

        // Since expected_sent is for the assertion, we really do want to unwrap().
        let expected_sent = Apdu::from_bytes(entry.sent.as_slice()).unwrap();
        assert_eq!(
            &expected_sent, apdu,
            "device expected {:?}, got {:?}",
            expected_sent, apdu
        );

        Ok(match entry.received {
            Ok(v) => v,
            Err(msg) => return Err(Error::Internal(format_err!("{}", msg))),
        })
    }

    fn begin_transaction(&self) -> Result<()> {
        if !self.connected {
            return Err(Error::Internal(format_err!(
                "Can't begin transaction without first being connected."
            )));
        }
        Ok(())
    }

    fn end_transaction(&self) -> Result<()> {
        if !self.connected {
            return Err(Error::Internal(format_err!(
                "Can't end transaction without first being connected."
            )));
        }
        Ok(())
    }
}
