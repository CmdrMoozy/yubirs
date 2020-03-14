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

use crate::otp::util::*;
use lazy_static::lazy_static;
use std::iter::repeat;

#[cfg_attr(rustfmt, rustfmt_skip)]
#[test]
fn test_url_encode() {
    let exp: &'static str =
        "%21%2A%27%28%29%3B%3A%40%26%3D%2B%24%2C%2F%3F%23%5B%5D\
         ABCDEFGHIJKLMNOPQRSTUVWXYZ\
         abcdefghijklmnopqrstuvwxyz\
         0123456789\
         -_.~";
    let org: &'static str =
        "!*'();:@&=+$,/?#[]\
         ABCDEFGHIJKLMNOPQRSTUVWXYZ\
         abcdefghijklmnopqrstuvwxyz\
         0123456789\
         -_.~";
    assert_eq!(exp, url_encode(org).as_str());
}

struct SignatureTest {
    key: Vec<u8>,
    data: &'static str,
    expected: Vec<u8>,
    expected_encoded: &'static str,
}

lazy_static! {
    static ref SIGNATURE_TEST_CASES: Vec<SignatureTest> = vec![
        SignatureTest {
            key: repeat(0x0bu8).take(16).collect(),
            data: "Hello, world!",
            expected: vec![
                0x7f, 0xb8, 0x1c, 0x6f, 0x67, 0x26, 0xce, 0xea, 0x94, 0xd9, 0xc7, 0x21, 0xc8, 0x45,
                0xb4, 0x09, 0x47, 0xde, 0xa1, 0x0a,
            ],
            expected_encoded: "f7gcb2cmzuqU2cchyEW0CUfeoQo%3D",
        },
        SignatureTest {
            key: repeat(0xaau8).take(16).collect(),
            data: "foo bar baz",
            expected: vec![
                0xa5, 0xb2, 0x4b, 0x6f, 0x63, 0x78, 0x33, 0xdf, 0x17, 0x67, 0xe5, 0xca, 0xcc, 0x20,
                0xe4, 0x16, 0x72, 0xad, 0x24, 0x2a,
            ],
            expected_encoded: "pbJLb2N4M98XZ%2BXKzCDkFnKtJCo%3D",
        },
    ];
}

#[cfg_attr(rustfmt, rustfmt_skip)]
#[test]
fn test_signature_generation() {
    for test_case in SIGNATURE_TEST_CASES.iter() {
        let sig = generate_signature(test_case.key.as_slice(), test_case.data.to_owned()).unwrap();
        let enc = generate_encoded_signature(
            test_case.key.as_slice(), test_case.data.to_owned()).unwrap();
        assert_eq!(test_case.expected, sig);
        assert_eq!(test_case.expected_encoded, enc);
    }
}
