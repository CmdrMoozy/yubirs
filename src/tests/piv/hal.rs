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
use piv::{DEFAULT_PIN, DEFAULT_PUK, DEFAULT_READER};
use piv::hal::*;
use piv::handle::Version;
use piv::id::Instruction;
use piv::sw::StatusWord;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

struct MockSendData {
    remaining: usize,
    callback: Box<FnMut(Apdu) -> Result<(StatusWord, Vec<u8>)>>,
}

impl MockSendData {
    /// Construct a new MockSendData which is intended to be called `calls`
    /// times, using the given actual callback function.
    pub fn new<F: 'static + FnMut(Apdu) -> Result<(StatusWord, Vec<u8>)>>(
        calls: usize,
        callback: F,
    ) -> Self {
        MockSendData {
            remaining: calls,
            callback: Box::new(callback),
        }
    }

    /// Call this MockSendData function with the given argument. This function
    /// returns the result from the mock implementation, along with a bool. If
    /// the bool is true, it means this mock should be left in place for future
    /// calls. If false, then the caller should pop this mock off, and not call
    /// it again.
    pub fn call(&mut self, apdu: Apdu) -> (Result<(StatusWord, Vec<u8>)>, bool) {
        debug_assert!(self.remaining > 0);
        let ret = (self.callback)(apdu);
        self.remaining -= 1;
        (ret, self.remaining > 0)
    }
}

pub struct PcscTestStub {
    connected: bool,
    readers: Vec<String>,
    send_data_callbacks: Mutex<VecDeque<MockSendData>>,
}

impl PcscTestStub {
    pub fn set_mock_readers(&mut self, readers: &[&str]) {
        self.readers = readers
            .iter()
            .map(|&r| -> String { r.to_owned() })
            .collect();
    }

    pub fn push_mock_send_data<F: 'static + FnMut(Apdu) -> Result<(StatusWord, Vec<u8>)>>(
        &self,
        calls: usize,
        callback: F,
    ) -> &Self {
        self.send_data_callbacks
            .lock()
            .unwrap()
            .push_back(MockSendData::new(calls, callback));
        self
    }

    pub fn push_mock_get_version(&self, calls: usize, mock_version: Version) -> &Self {
        self.push_mock_send_data(calls, move |apdu: Apdu| -> Result<(StatusWord, Vec<u8>)> {
            if apdu.cla() == 0 && apdu.ins() == Instruction::GetVersion.to_value() && apdu.p1() == 0
                && apdu.p2() == 0 && apdu.lc() == 0
            {
                Ok((
                    StatusWord::new_from_value(0x9000),
                    vec![mock_version.0, mock_version.1, mock_version.2],
                ))
            } else {
                // Return "invalid instruction byte" status word.
                Ok((StatusWord::new_from_value(0x6d00), vec![]))
            }
        })
    }

    pub fn push_mock_change(&self, instructions: &[(Instruction, u8)]) -> &Self {
        let mut instructions: VecDeque<(Instruction, u8)> = instructions.to_vec().into();

        let mut retry_counters: HashMap<(Instruction, u8), usize> = HashMap::new();
        retry_counters.insert((Instruction::ChangeReference, 0x80), 3);
        retry_counters.insert((Instruction::ChangeReference, 0x81), 3);

        let mut secrets: HashMap<(Instruction, u8), String> = HashMap::new();
        secrets.insert((Instruction::ChangeReference, 0x80), DEFAULT_PIN.to_owned());
        secrets.insert((Instruction::ChangeReference, 0x81), DEFAULT_PUK.to_owned());

        let calls = instructions.len();

        self.push_mock_send_data(calls, move |apdu: Apdu| -> Result<(StatusWord, Vec<u8>)> {
            let instruction = instructions.pop_front().unwrap();

            let retry_counter: &mut usize = retry_counters.get_mut(&instruction).unwrap();
            if *retry_counter == 0 {
                // Return "too many attempts".
                return Ok((StatusWord::new_from_value(0x6983), vec![]));
            }

            if apdu.cla() == 0 && apdu.ins() == instruction.0.to_value() && apdu.p1() == 0
                && apdu.p2() == instruction.1 && apdu.lc() == 16
            {
                let existing: Vec<u8> = apdu.data()[0..8].to_owned();
                let existing: Vec<u8> = existing.into_iter().take_while(|b| *b != 0xff).collect();
                let existing = String::from_utf8(existing).unwrap();
                if &existing != secrets.get(&instruction).unwrap() {
                    // Return "authentication failed" status word.
                    *retry_counter -= 1;
                    return Ok((StatusWord::new_from_value(0x6300), vec![]));
                }

                let new: Vec<u8> = apdu.data()[8..16].to_owned();
                let new: Vec<u8> = new.into_iter().take_while(|b| *b != 0xff).collect();
                let new = String::from_utf8(new).unwrap();
                if new.is_empty() {
                    // Return "invalid data parameters" status word.
                    return Ok((StatusWord::new_from_value(0x6a80), vec![]));
                }

                // Return "success" status word.
                secrets.insert(instruction, new);
                return Ok((StatusWord::new_from_value(0x9000), vec![]));
            } else {
                // Return "invalid instruction byte" status word.
                return Ok((StatusWord::new_from_value(0x6d00), vec![]));
            }
        })
    }
}

impl PcscHal for PcscTestStub {
    fn new() -> Result<Self> {
        Ok(PcscTestStub {
            connected: false,
            readers: vec![DEFAULT_READER.to_owned()],
            send_data_callbacks: Mutex::new(VecDeque::new()),
        })
    }

    fn list_readers(&self) -> Result<Vec<String>> {
        Ok(self.readers.clone())
    }

    fn connect(&mut self, reader: Option<&str>) -> Result<()> {
        let reader: &str = reader.unwrap_or(DEFAULT_READER);
        for r in self.readers.iter() {
            if r.contains(reader) {
                self.connected = true;
                return Ok(());
            }
        }
        bail!("No reading matching '{}' found", reader);
    }

    fn disconnect(&mut self) {
        self.connected = false;
    }

    fn send_data_impl(&self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        if !self.connected {
            bail!("Can't send data without first being connected.");
        }
        let apdu = Apdu::from_bytes(apdu)?;
        let mut callbacks = self.send_data_callbacks.lock().unwrap();
        let (ret, should_keep) = match callbacks.front_mut() {
            None => {
                bail!("Unexpected call to send_data_impl (no mock callbacks to handle this data)")
            }
            Some(mut callback) => callback.call(apdu),
        };
        if !should_keep {
            callbacks.pop_front();
        }
        ret
    }

    fn begin_transaction(&self) -> Result<()> {
        if !self.connected {
            bail!("Can't begin transaction without first being connected.");
        }
        Ok(())
    }

    fn end_transaction(&self) -> Result<()> {
        if !self.connected {
            bail!("Can't end transaction without first being connected.");
        }
        Ok(())
    }
}
