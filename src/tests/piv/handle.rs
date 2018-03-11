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
use piv::hal::Apdu;
use piv::handle::{Handle, Version};
use piv::id::Instruction;
use piv::sw::StatusWord;
use tests::piv::hal::PcscTestStub;

fn new_test_handle() -> Handle<PcscTestStub> {
    Handle::new().unwrap()
}

#[test]
fn test_list_readers() {
    // This is a really stupid test, which essentially just verifies that
    // set_mock_readers works.
    let mut handle = new_test_handle();
    handle
        .get_hal_mut()
        .set_mock_readers(&[DEFAULT_READER, "foobar"]);

    let expected_readers = vec![DEFAULT_READER.to_owned(), "foobar".to_owned()];
    assert_eq!(expected_readers, handle.list_readers().unwrap());
}

#[test]
fn test_get_version() {
    let mut handle = new_test_handle();
    handle.get_hal_mut().set_mock_readers(&[DEFAULT_READER]);
    handle
        .get_hal()
        .push_mock_send_data(|apdu: Apdu| -> Result<(StatusWord, Vec<u8>)> {
            println!(
                "cla: {}, ins: {}, p1: {}, p2: {}, lc: {}",
                apdu.cla(),
                apdu.ins(),
                apdu.p1(),
                apdu.p2(),
                apdu.lc()
            );
            if apdu.cla() == 0 && apdu.ins() == Instruction::GetVersion.to_value() && apdu.p1() == 0
                && apdu.p2() == 0 && apdu.lc() == 0
            {
                // TODO: Get rid of the trailing two bytes, or at least make it more clear why they
                // exist. See src/piv/hal.rs "let recv_len = recv.len() - 2;".
                return Ok((
                    StatusWord::new(&[0x90, 0x00], 2),
                    vec![0x01, 0x02, 0x03, 0x00, 0x00],
                ));
            } else {
                // Return "invalid instruction byte" status word.
                return Ok((StatusWord::new(&[0x6d, 0x00], 2), vec![]));
            }
        });

    let expected_version = Version::new(&[1, 2, 3]).unwrap();
    handle.connect(None).unwrap();
    assert_eq!("1.2.3", expected_version.to_string().as_str());
    assert_eq!(expected_version, handle.get_version().unwrap());
}
