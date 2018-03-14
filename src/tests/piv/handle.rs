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
    let mut handle: Handle<PcscTestStub> = Handle::new().unwrap();
    handle.get_hal_mut().set_mock_readers(&[DEFAULT_READER]);
    handle
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
    handle
        .get_hal()
        .push_mock_send_data(|apdu: Apdu| -> Result<(StatusWord, Vec<u8>)> {
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

const MOCK_INITIAL_PIN: &'static str = "123456";

fn mock_change_pin_send_data(apdu: Apdu) -> Result<(StatusWord, Vec<u8>)> {
    if apdu.cla() == 0 && apdu.ins() == Instruction::ChangeReference.to_value() && apdu.p1() == 0
        && apdu.p2() == 0x80 && apdu.lc() == 16
    {
        let existing: Vec<u8> = apdu.data()[0..8].to_owned();
        let existing: Vec<u8> = existing.into_iter().take_while(|b| *b != 0xff).collect();
        let existing = String::from_utf8(existing).unwrap();
        if existing != MOCK_INITIAL_PIN {
            // Return "authentication failed" status word.
            return Ok((StatusWord::new(&[0x63, 0x00], 2), vec![]));
        }

        let new: Vec<u8> = apdu.data()[8..16].to_owned();
        let new: Vec<u8> = new.into_iter().take_while(|b| *b != 0xff).collect();
        let new = String::from_utf8(new).unwrap();
        if new.is_empty() {
            // Return "invalid data parameters" status word.
            return Ok((StatusWord::new(&[0x6a, 0x80], 2), vec![]));
        }

        // TODO: The empty two-byte response is weird here too; see other TODOs in this file.
        // Return "success" status word.
        return Ok((StatusWord::new(&[0x90, 0x00], 2), vec![0x00, 0x00]));
    } else {
        // Return "invalid instruction byte" status word.
        return Ok((StatusWord::new(&[0x6d, 0x00], 2), vec![]));
    }
}

#[test]
fn test_change_pin() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_mock_send_data(mock_change_pin_send_data);
    handle
        .get_hal()
        .push_mock_send_data(mock_change_pin_send_data);

    handle.connect(None).unwrap();
    // Changing with the right initial PIN should succeed.
    let res = handle.change_pin(Some(MOCK_INITIAL_PIN), Some("111111"));
    println!("{:?}", res);
    assert!(res.is_ok());
    // assert!(handle.change_pin(Some(MOCK_INITIAL_PIN), Some("111111")).is_ok());
    // Changing with the wrong initial PIN should fail.
    assert_eq!(
        "The supplied PIN is incorrect.",
        handle
            .change_pin(Some("WRONG"), Some("111111"))
            .err()
            .unwrap()
            .to_string()
    );

    handle.connect(None).unwrap();
}

#[test]
fn test_change_pin_invalid_parameters() {
    let mut handle = new_test_handle();
    // No need to add mock data, validation happens first.

    handle.connect(None).unwrap();
    assert_eq!(
        "Invalid existing PIN; it exceeds 8 characters".to_owned(),
        handle
            .change_pin(Some("123456789"), Some("123456"))
            .err()
            .unwrap()
            .to_string()
    );
    assert_eq!(
        "Invalid new PIN; it exceeds 8 characters".to_owned(),
        handle
            .change_pin(Some("123456"), Some("123456789"))
            .err()
            .unwrap()
            .to_string()
    );
}
