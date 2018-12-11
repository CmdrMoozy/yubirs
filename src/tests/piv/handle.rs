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

use bdrck::testing::temp;
use data_encoding;
use piv::handle::{Handle, Version};
use piv::id::*;
use piv::pkey::Format;
use piv::{DEFAULT_MGM_KEY, DEFAULT_PIN, DEFAULT_PUK, DEFAULT_READER};
use std::fs::File;
use std::io::Write;
use tests::piv::hal::PcscTestStub;

const CONNECT_RECORDING: &'static [u8] = include_bytes!("recordings/connect.dr");
const GET_VERSION_RECORDING: &'static [u8] = include_bytes!("recordings/get_version.dr");
const CHANGE_PIN_RECORDING: &'static [u8] = include_bytes!("recordings/change_pin.dr");
const CHANGE_PIN_WRONG_RECORDING: &'static [u8] = include_bytes!("recordings/change_pin_wrong.dr");
const UNBLOCK_PIN_RECORDING: &'static [u8] = include_bytes!("recordings/unblock_pin.dr");
const CHANGE_PUK_RECORDING: &'static [u8] = include_bytes!("recordings/change_puk.dr");
const CHANGE_PUK_WRONG_RECORDING: &'static [u8] = include_bytes!("recordings/change_puk_wrong.dr");
const RESET_RECORDING: &'static [u8] = include_bytes!("recordings/reset.dr");
const SET_RETRIES_RECORDING: &'static [u8] = include_bytes!("recordings/set_retries.dr");
const CHANGE_MGM_KEY_RECORDING: &'static [u8] = include_bytes!("recordings/change_mgm_key.dr");
const CHANGE_MGM_KEY_WRONG_RECORDING: &'static [u8] =
    include_bytes!("recordings/change_mgm_key_wrong.dr");
const SET_CHUID_RECORDING: &'static [u8] = include_bytes!("recordings/set_chuid.dr");
const SET_CCC_RECORDING: &'static [u8] = include_bytes!("recordings/set_ccc.dr");
const READ_OBJECT_CHUID_RECORDING: &'static [u8] =
    include_bytes!("recordings/read_object_chuid.dr");
const READ_OBJECT_CHUID_MISSING_RECORDING: &'static [u8] =
    include_bytes!("recordings/read_object_chuid_missing.dr");
const WRITE_OBJECT_RECORDING: &'static [u8] = include_bytes!("recordings/write_object.dr");
const GENERATE_RSA_RECORDING: &'static [u8] = include_bytes!("recordings/generate_rsa.dr");
const GENERATE_RSA_EXPECTED_PEM: &'static [u8] =
    include_bytes!("recordings/generate_rsa_expected.pem");
const GENERATE_RSA_EXPECTED_DER: &'static [u8] =
    include_bytes!("recordings/generate_rsa_expected.der");
const GENERATE_EC_RECORDING: &'static [u8] = include_bytes!("recordings/generate_ec.dr");
const GENERATE_EC_EXPECTED_PEM: &'static [u8] =
    include_bytes!("recordings/generate_ec_expected.pem");
const GENERATE_EC_EXPECTED_DER: &'static [u8] =
    include_bytes!("recordings/generate_ec_expected.der");
const IMPORT_KEY_RSA_INPUT: &'static [u8] = include_bytes!("recordings/import_key_rsa_input.pem");
const IMPORT_KEY_RSA_RECORDING: &'static [u8] = include_bytes!("recordings/import_key_rsa.dr");
const IMPORT_KEY_RSA_EXPECTED_PEM: &'static [u8] =
    include_bytes!("recordings/import_key_rsa_expected.pem");
const IMPORT_KEY_EC_INPUT: &'static [u8] = include_bytes!("recordings/import_key_ec_input.pem");
const IMPORT_KEY_EC_RECORDING: &'static [u8] = include_bytes!("recordings/import_key_ec.dr");
const IMPORT_KEY_EC_EXPECTED_PEM: &'static [u8] =
    include_bytes!("recordings/import_key_ec_expected.pem");

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
    assert!(handle.get_hal().no_recordings());
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
    assert!(handle.get_hal().no_recordings());
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
    assert!(handle.get_hal().no_recordings());
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
    assert_eq!(
        "The supplied PIN/PUK is incorrect.",
        handle
            .change_pin(Some("123"), Some("111111"))
            .err()
            .unwrap()
            .to_string()
    );
    assert_eq!(
        "Verifying PIN failed: no more retries",
        handle
            .change_pin(Some("123"), Some("111111"))
            .err()
            .unwrap()
            .to_string()
    );
    assert!(handle.get_hal().no_recordings());
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
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_unblock_pin_success() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(UNBLOCK_PIN_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert!(handle
        .unblock_pin(Some(DEFAULT_PUK), Some(DEFAULT_PIN))
        .is_ok());
    assert!(handle.get_hal().no_recordings());
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
    assert!(handle.get_hal().no_recordings());
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
    assert!(handle.get_hal().no_recordings());
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
    assert_eq!(
        "The supplied PIN/PUK is incorrect.",
        handle
            .change_puk(Some("123"), Some("111111"))
            .err()
            .unwrap()
            .to_string()
    );
    assert_eq!(
        "Verifying PUK failed: no more retries",
        handle
            .change_puk(Some("123"), Some("111111"))
            .err()
            .unwrap()
            .to_string()
    );
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_reset_success() {
    let mut handle = new_test_handle();
    handle.get_hal().push_recording(RESET_RECORDING).unwrap();

    handle.connect(None).unwrap();
    assert!(handle.reset().is_ok());
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_set_retries() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(SET_RETRIES_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert!(handle
        .set_retries(Some(DEFAULT_MGM_KEY), Some(DEFAULT_PIN), 6, 6)
        .is_ok());
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_change_mgm_key() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(CHANGE_MGM_KEY_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert!(handle
        .set_management_key(
            Some(DEFAULT_MGM_KEY),
            Some("fedcba9876543210fedcba9876543210fedcba9876543210"),
            false
        )
        .is_ok());
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_change_mgm_key_wrong_key() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(CHANGE_MGM_KEY_WRONG_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert_eq!(
        "Authentication failure",
        handle
            .set_management_key(
                Some("fedcba9876543210fedcba9876543210fedcba9876543210"),
                Some(DEFAULT_MGM_KEY),
                false
            )
            .err()
            .unwrap()
            .to_string()
    );
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_set_chuid() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(SET_CHUID_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert!(handle.set_chuid(Some(DEFAULT_MGM_KEY)).is_ok());
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_set_ccc() {
    let mut handle = new_test_handle();
    handle.get_hal().push_recording(SET_CCC_RECORDING).unwrap();

    handle.connect(None).unwrap();
    assert!(handle.set_ccc(Some(DEFAULT_MGM_KEY)).is_ok());
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_read_object_chuid() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(READ_OBJECT_CHUID_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert!(handle.read_object(Object::Chuid).is_ok());
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_read_object_chuid_missing() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(READ_OBJECT_CHUID_MISSING_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    assert_eq!(
        "The specified file does not exist in the smart card.",
        handle.read_object(Object::Chuid).err().unwrap().to_string()
    );
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_write_object() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(WRITE_OBJECT_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    let data: Vec<u8> = data_encoding::BASE64
        .decode(
            "MBnU5znac5ztOc5znYNoWCEIQhCEIThCEMP1NBD/////////////////////NQgyMDMwMDEwMT4A/gA="
                .as_bytes(),
        )
        .unwrap();
    assert!(handle
        .write_object(Some(DEFAULT_MGM_KEY), Object::Chuid, data)
        .is_ok());
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_generate_rsa() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(GENERATE_RSA_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    let public_key = handle
        .generate(
            Some(DEFAULT_MGM_KEY),
            Key::Authentication,
            Algorithm::Rsa2048,
            PinPolicy::Default,
            TouchPolicy::Default,
        )
        .unwrap();
    assert_eq!(
        GENERATE_RSA_EXPECTED_PEM,
        public_key.format(Format::Pem).unwrap().as_slice()
    );
    assert_eq!(
        GENERATE_RSA_EXPECTED_DER,
        public_key.format(Format::Der).unwrap().as_slice()
    );
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_generate_ec() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(GENERATE_EC_RECORDING)
        .unwrap();

    handle.connect(None).unwrap();
    let public_key = handle
        .generate(
            Some(DEFAULT_MGM_KEY),
            Key::Authentication,
            Algorithm::Eccp256,
            PinPolicy::Default,
            TouchPolicy::Default,
        )
        .unwrap();
    assert_eq!(
        GENERATE_EC_EXPECTED_PEM,
        public_key.format(Format::Pem).unwrap().as_slice()
    );
    assert_eq!(
        GENERATE_EC_EXPECTED_DER,
        public_key.format(Format::Der).unwrap().as_slice()
    );
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_import_key_rsa() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(IMPORT_KEY_RSA_RECORDING)
        .unwrap();

    let input_file = temp::File::new_file().unwrap();
    {
        let mut f = File::create(input_file.path()).unwrap();
        f.write_all(IMPORT_KEY_RSA_INPUT).unwrap();
        f.flush().unwrap();
    }

    handle.connect(None).unwrap();
    let public_key = handle
        .import_key(
            Some(DEFAULT_MGM_KEY),
            input_file.path(),
            Key::Authentication,
            false,
            None,
            PinPolicy::Default,
            TouchPolicy::Default,
        )
        .unwrap();
    assert_eq!(
        IMPORT_KEY_RSA_EXPECTED_PEM,
        public_key.format(Format::Pem).unwrap().as_slice()
    );
    assert!(handle.get_hal().no_recordings());
}

#[test]
fn test_import_key_ec() {
    let mut handle = new_test_handle();
    handle
        .get_hal()
        .push_recording(IMPORT_KEY_EC_RECORDING)
        .unwrap();

    let input_file = temp::File::new_file().unwrap();
    {
        let mut f = File::create(input_file.path()).unwrap();
        f.write_all(IMPORT_KEY_EC_INPUT).unwrap();
        f.flush().unwrap();
    }

    handle.connect(None).unwrap();
    let public_key = handle
        .import_key(
            Some(DEFAULT_MGM_KEY),
            input_file.path(),
            Key::Authentication,
            false,
            None,
            PinPolicy::Default,
            TouchPolicy::Default,
        )
        .unwrap();
    assert_eq!(
        IMPORT_KEY_EC_EXPECTED_PEM,
        public_key.format(Format::Pem).unwrap().as_slice()
    );
    assert!(handle.get_hal().no_recordings());
}
