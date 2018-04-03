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

use piv::{DEFAULT_PIN, DEFAULT_PUK, DEFAULT_READER};
use piv::handle::{Handle, Version};
use piv::id::Instruction;
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
    let expected = Version::new(&[1, 2, 3]).unwrap();
    handle.get_hal().push_mock_get_version(1, expected);
    handle.connect(None).unwrap();
    assert_eq!("1.2.3", expected.to_string().as_str());
    assert_eq!(expected, handle.get_version().unwrap());
}

#[test]
fn test_change_pin() {
    let mut handle = new_test_handle();
    handle.get_hal().push_mock_change(&[
        (Instruction::ChangeReference, 0x80),
        (Instruction::ChangeReference, 0x80),
    ]);

    handle.connect(None).unwrap();
    // Changing with the right initial PIN should succeed.
    assert!(handle.change_pin(Some(DEFAULT_PIN), Some("111111")).is_ok());
    // Changing with the wrong initial PIN should fail.
    assert_eq!(
        "The supplied PIN/PUK is incorrect.",
        handle
            .change_pin(Some("WRONG"), Some("222222"))
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

#[test]
fn test_change_puk() {
    let mut handle = new_test_handle();
    handle.get_hal().push_mock_change(&[
        (Instruction::ChangeReference, 0x81),
        (Instruction::ChangeReference, 0x81),
    ]);

    handle.connect(None).unwrap();
    // Changing with the right initial PUK should succeed.
    assert!(handle.change_puk(Some(DEFAULT_PUK), Some("1111")).is_ok());
    // Changing with the wrong initial PUK should fail.
    assert_eq!(
        "The supplied PIN/PUK is incorrect.",
        handle
            .change_puk(Some("WRONG"), Some("2222"))
            .err()
            .unwrap()
            .to_string()
    );

    handle.connect(None).unwrap();
}

#[test]
fn test_change_puk_invalid_parameters() {
    let mut handle = new_test_handle();
    // No need to add mock data, validation happens first.

    handle.connect(None).unwrap();
    assert_eq!(
        "Invalid existing PUK; it exceeds 8 characters".to_owned(),
        handle
            .change_puk(Some("123456789"), Some("123456"))
            .err()
            .unwrap()
            .to_string()
    );
    assert_eq!(
        "Invalid new PUK; it exceeds 8 characters".to_owned(),
        handle
            .change_puk(Some("123456"), Some("123456789"))
            .err()
            .unwrap()
            .to_string()
    );
}
