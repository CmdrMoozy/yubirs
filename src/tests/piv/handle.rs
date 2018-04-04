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
use tests::piv::hal::PcscTestStub;

const CONNECT_RECORDING: &'static [u8] = include_bytes!("recordings/connect.dr");
const GET_VERSION_RECORDING: &'static [u8] = include_bytes!("recordings/get_version.dr");
const CHANGE_PIN_RECORDING: &'static [u8] = include_bytes!("recordings/change_pin.dr");
const CHANGE_PIN_WRONG_RECORDING: &'static [u8] = include_bytes!("recordings/change_pin_wrong.dr");
const UNBLOCK_PIN_RECORDING: &'static [u8] = include_bytes!("recordings/unblock_pin.dr");
const CHANGE_PUK_RECORDING: &'static [u8] = include_bytes!("recordings/change_puk.dr");
const CHANGE_PUK_WRONG_RECORDING: &'static [u8] = include_bytes!("recordings/change_puk_wrong.dr");
const RESET_RECORDING: &'static [u8] = include_bytes!("recordings/reset.dr");

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
        .push_recording(GET_VERSION_RECORDING)
        .unwrap();

    let expected = Version::new(&[1, 0, 4]).unwrap();
    handle.connect(None).unwrap();
    assert_eq!("1.0.4", expected.to_string().as_str());
    assert_eq!(expected, handle.get_version().unwrap());
}

#[test]
fn test_change_pin_success() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(CHANGE_PIN_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert!(handle.change_pin(Some(DEFAULT_PIN), Some("123")).is_ok());
}

#[test]
fn test_change_pin_wrong_pin() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(CHANGE_PIN_WRONG_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert_eq!(
        "The supplied PIN/PUK is incorrect.",
        handle
            .change_pin(Some("123"), Some("111111"))
            .err()
            .unwrap()
            .to_string()
    );
}

#[test]
fn test_change_pin_invalid_parameters() {
    let mut handle = new_test_handle();
    handle.get_hal().push_recording(CONNECT_RECORDING).unwrap();

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
fn test_unblock_pin_success() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(UNBLOCK_PIN_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert!(
        handle
            .unblock_pin(Some(DEFAULT_PUK), Some(DEFAULT_PIN))
            .is_ok()
    );
}

#[test]
fn test_change_puk_invalid_parameters() {
    let mut handle = new_test_handle();
    handle.get_hal().push_recording(CONNECT_RECORDING).unwrap();

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

#[test]
fn test_change_puk() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(CHANGE_PUK_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert!(handle.change_puk(Some(DEFAULT_PUK), Some("123")).is_ok());
}

#[test]
fn test_change_puk_wrong_puk() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(CHANGE_PUK_WRONG_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert_eq!(
        "The supplied PIN/PUK is incorrect.",
        handle
            .change_puk(Some("123"), Some("111111"))
            .err()
            .unwrap()
            .to_string()
    );
}

#[test]
fn test_reset_success() {
    let mut handle = new_test_handle();
    handle.get_hal().push_recording(RESET_RECORDING).unwrap();

    handle.connect(None).unwrap();
    assert!(handle.reset().is_ok());
}
