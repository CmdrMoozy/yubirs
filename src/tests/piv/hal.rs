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
use piv::DEFAULT_READER;
use piv::hal::*;
use piv::sw::StatusWord;
use std::collections::VecDeque;
use std::sync::Mutex;

pub struct PcscTestStub {
    connected: bool,
    readers: Vec<String>,
    send_data_callbacks: Mutex<VecDeque<Box<Fn(Apdu) -> Result<(StatusWord, Vec<u8>)>>>>,
}

impl PcscTestStub {
    pub fn set_mock_readers(&mut self, readers: &[&str]) {
        self.readers = readers
            .iter()
            .map(|&r| -> String { r.to_owned() })
            .collect();
    }

    pub fn push_mock_send_data<F: 'static + Fn(Apdu) -> Result<(StatusWord, Vec<u8>)>>(
        &self,
        callback: F,
    ) {
        self.send_data_callbacks
            .lock()
            .unwrap()
            .push_back(Box::new(callback));
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
        match callbacks.pop_front() {
            None => {
                bail!("Unexpected call to send_data_impl (no mock callbacks to handle this data)")
            }
            Some(callback) => callback(apdu),
        }
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
