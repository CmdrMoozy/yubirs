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

use crypto::*;

const TEST_MGM_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

#[test]
fn test_decrypt_des_challenge() {
    // Decryption test vectors, list of (ciphertext, expected).
    const TEST_CASES: &'static [([u8; 8], [u8; 8])] = &[
        (
            [0x99, 0x94, 0xf4, 0xc6, 0x9d, 0x40, 0xae, 0x4f],
            [0x0e, 0x0f, 0xce, 0x58, 0xc9, 0x75, 0xdb, 0x90],
        ),
        (
            [0xf5, 0xad, 0xa9, 0x23, 0xf1, 0x9a, 0x48, 0x2c],
            [0xa8, 0xc7, 0x17, 0x4a, 0x5b, 0xfe, 0xd0, 0x24],
        ),
        (
            [0x33, 0xf2, 0x90, 0x0c, 0x5a, 0xd3, 0x53, 0xa6],
            [0x71, 0xc7, 0xe8, 0x0a, 0x17, 0xbb, 0x6f, 0x78],
        ),
        (
            [0x1e, 0x91, 0x0d, 0xe9, 0x06, 0x2e, 0x41, 0xe2],
            [0x5c, 0xc1, 0x18, 0x30, 0x6d, 0xc7, 0x02, 0xe4],
        ),
        (
            [0x31, 0x2c, 0x46, 0xb2, 0xfa, 0xf4, 0x69, 0x53],
            [0xfe, 0x57, 0x24, 0x47, 0x0a, 0x87, 0xfa, 0x9c],
        ),
    ];

    for &(ciphertext, expected) in TEST_CASES {
        assert_eq!(
            &expected,
            decrypt_des_challenge(&TEST_MGM_KEY, &ciphertext)
                .unwrap()
                .as_slice()
        );
    }
}

#[test]
fn test_decrypt_des_challenge_input_validation() {
    assert!(decrypt_des_challenge(&[0; 24], &[0; 8]).is_ok());
    assert!(decrypt_des_challenge(&[0; 23], &[0; 8]).is_err());
    assert!(decrypt_des_challenge(&[0; 25], &[0; 8]).is_err());
    assert!(decrypt_des_challenge(&[0; 24], &[0; 7]).is_err());
    assert!(decrypt_des_challenge(&[0; 24], &[0; 9]).is_err());
}

#[test]
fn test_encrypt_des_challenge() {
    // Encryption test vectors, list of (plaintext, expected).
    const TEST_CASES: &'static [([u8; 8], [u8; 8])] = &[
        (
            [0x99, 0x94, 0xf4, 0xc6, 0x9d, 0x40, 0xae, 0x4f],
            [0x9e, 0x5c, 0x42, 0x97, 0xd6, 0x05, 0x82, 0xf8],
        ),
        (
            [0xf5, 0xad, 0xa9, 0x23, 0xf1, 0x9a, 0x48, 0x2c],
            [0x34, 0xff, 0x40, 0x3b, 0x5c, 0xf3, 0x9d, 0x4c],
        ),
        (
            [0x33, 0xf2, 0x90, 0x0c, 0x5a, 0xd3, 0x53, 0xa6],
            [0xba, 0x55, 0xdf, 0x4d, 0x0a, 0x53, 0x1b, 0xd9],
        ),
        (
            [0x1e, 0x91, 0x0d, 0xe9, 0x06, 0x2e, 0x41, 0xe2],
            [0x92, 0x81, 0xa9, 0x83, 0x65, 0x4e, 0xed, 0x4d],
        ),
        (
            [0x31, 0x2c, 0x46, 0xb2, 0xfa, 0xf4, 0x69, 0x53],
            [0xbf, 0x06, 0x5d, 0x6b, 0x36, 0x14, 0xd8, 0x84],
        ),
    ];

    for &(plaintext, expected) in TEST_CASES {
        assert_eq!(
            &expected,
            encrypt_des_challenge(&TEST_MGM_KEY, &plaintext)
                .unwrap()
                .as_slice()
        );
    }
}

#[test]
fn test_encrypt_des_challenge_input_validation() {
    assert!(encrypt_des_challenge(&[0; 24], &[0; 8]).is_ok());
    assert!(encrypt_des_challenge(&[0; 23], &[0; 8]).is_err());
    assert!(encrypt_des_challenge(&[0; 25], &[0; 8]).is_err());
    assert!(encrypt_des_challenge(&[0; 24], &[0; 7]).is_err());
    assert!(encrypt_des_challenge(&[0; 24], &[0; 9]).is_err());
}
