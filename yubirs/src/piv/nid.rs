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

use libc::c_int;

pub const YKPIV_ALGO_TAG: u8 = 0x80;
pub const YKPIV_ALGO_3DES: u8 = 0x03;
pub const YKPIV_ALGO_RSA1024: u8 = 0x06;
pub const YKPIV_ALGO_RSA2048: u8 = 0x07;
pub const YKPIV_ALGO_ECCP256: u8 = 0x11;
pub const YKPIV_ALGO_ECCP384: u8 = 0x14;

pub const YKPIV_KEY_AUTHENTICATION: u8 = 0x9a;
pub const YKPIV_KEY_CARDMGM: u8 = 0x9b;
pub const YKPIV_KEY_SIGNATURE: u8 = 0x9c;
pub const YKPIV_KEY_KEYMGM: u8 = 0x9d;
pub const YKPIV_KEY_CARDAUTH: u8 = 0x9e;
pub const YKPIV_KEY_RETIRED1: u8 = 0x82;
pub const YKPIV_KEY_RETIRED2: u8 = 0x83;
pub const YKPIV_KEY_RETIRED3: u8 = 0x84;
pub const YKPIV_KEY_RETIRED4: u8 = 0x85;
pub const YKPIV_KEY_RETIRED5: u8 = 0x86;
pub const YKPIV_KEY_RETIRED6: u8 = 0x87;
pub const YKPIV_KEY_RETIRED7: u8 = 0x88;
pub const YKPIV_KEY_RETIRED8: u8 = 0x89;
pub const YKPIV_KEY_RETIRED9: u8 = 0x8a;
pub const YKPIV_KEY_RETIRED10: u8 = 0x8b;
pub const YKPIV_KEY_RETIRED11: u8 = 0x8c;
pub const YKPIV_KEY_RETIRED12: u8 = 0x8d;
pub const YKPIV_KEY_RETIRED13: u8 = 0x8e;
pub const YKPIV_KEY_RETIRED14: u8 = 0x8f;
pub const YKPIV_KEY_RETIRED15: u8 = 0x90;
pub const YKPIV_KEY_RETIRED16: u8 = 0x91;
pub const YKPIV_KEY_RETIRED17: u8 = 0x92;
pub const YKPIV_KEY_RETIRED18: u8 = 0x93;
pub const YKPIV_KEY_RETIRED19: u8 = 0x94;
pub const YKPIV_KEY_RETIRED20: u8 = 0x95;
pub const YKPIV_KEY_ATTESTATION: u8 = 0xf9;

pub const YKPIV_OBJ_CAPABILITY: c_int = 0x5fc107;
pub const YKPIV_OBJ_CHUID: c_int = 0x5fc102;
pub const YKPIV_OBJ_AUTHENTICATION: c_int = 0x5fc105;
pub const YKPIV_OBJ_FINGERPRINTS: c_int = 0x5fc103;
pub const YKPIV_OBJ_SECURITY: c_int = 0x5fc106;
pub const YKPIV_OBJ_FACIAL: c_int = 0x5fc108;
pub const YKPIV_OBJ_PRINTED: c_int = 0x5fc109;
pub const YKPIV_OBJ_SIGNATURE: c_int = 0x5fc10a;
pub const YKPIV_OBJ_KEY_MANAGEMENT: c_int = 0x5fc10b;
pub const YKPIV_OBJ_CARD_AUTH: c_int = 0x5fc101;
pub const YKPIV_OBJ_DISCOVERY: c_int = 0x7e;
pub const YKPIV_OBJ_KEY_HISTORY: c_int = 0x5fc10c;
pub const YKPIV_OBJ_IRIS: c_int = 0x5fc121;
pub const YKPIV_OBJ_RETIRED1: c_int = 0x5fc10d;
pub const YKPIV_OBJ_RETIRED2: c_int = 0x5fc10e;
pub const YKPIV_OBJ_RETIRED3: c_int = 0x5fc10f;
pub const YKPIV_OBJ_RETIRED4: c_int = 0x5fc110;
pub const YKPIV_OBJ_RETIRED5: c_int = 0x5fc111;
pub const YKPIV_OBJ_RETIRED6: c_int = 0x5fc112;
pub const YKPIV_OBJ_RETIRED7: c_int = 0x5fc113;
pub const YKPIV_OBJ_RETIRED8: c_int = 0x5fc114;
pub const YKPIV_OBJ_RETIRED9: c_int = 0x5fc115;
pub const YKPIV_OBJ_RETIRED10: c_int = 0x5fc116;
pub const YKPIV_OBJ_RETIRED11: c_int = 0x5fc117;
pub const YKPIV_OBJ_RETIRED12: c_int = 0x5fc118;
pub const YKPIV_OBJ_RETIRED13: c_int = 0x5fc119;
pub const YKPIV_OBJ_RETIRED14: c_int = 0x5fc11a;
pub const YKPIV_OBJ_RETIRED15: c_int = 0x5fc11b;
pub const YKPIV_OBJ_RETIRED16: c_int = 0x5fc11c;
pub const YKPIV_OBJ_RETIRED17: c_int = 0x5fc11d;
pub const YKPIV_OBJ_RETIRED18: c_int = 0x5fc11e;
pub const YKPIV_OBJ_RETIRED19: c_int = 0x5fc11f;
pub const YKPIV_OBJ_RETIRED20: c_int = 0x5fc120;
pub const YKPIV_OBJ_ATTESTATION: c_int = 0x5fff01;

pub const YKPIV_INS_VERIFY: u8 = 0x20;
pub const YKPIV_INS_CHANGE_REFERENCE: u8 = 0x24;
pub const YKPIV_INS_RESET_RETRY: u8 = 0x2c;
pub const YKPIV_INS_GENERATE_ASYMMETRIC: u8 = 0x47;
pub const YKPIV_INS_AUTHENTICATE: u8 = 0x87;
pub const YKPIV_INS_GET_DATA: u8 = 0xcb;
pub const YKPIV_INS_PUT_DATA: u8 = 0xdb;

pub const YKPIV_INS_SET_MGMKEY: u8 = 0xff;
pub const YKPIV_INS_IMPORT_KEY: u8 = 0xfe;
pub const YKPIV_INS_GET_VERSION: u8 = 0xfd;
pub const YKPIV_INS_GET_SERIAL: u8 = 0xf8;
pub const YKPIV_INS_RESET: u8 = 0xfb;
pub const YKPIV_INS_SET_PIN_RETRIES: u8 = 0xfa;
pub const YKPIV_INS_ATTEST: u8 = 0xf9;
pub const YKPIV_INS_SELECT_APPLICATION: u8 = 0xa4;

pub const YKPIV_PINPOLICY_TAG: u8 = 0xaa;
pub const YKPIV_PINPOLICY_DEFAULT: u8 = 0;
pub const YKPIV_PINPOLICY_NEVER: u8 = 1;
pub const YKPIV_PINPOLICY_ONCE: u8 = 2;
pub const YKPIV_PINPOLICY_ALWAYS: u8 = 3;

pub const YKPIV_TOUCHPOLICY_TAG: u8 = 0xab;
pub const YKPIV_TOUCHPOLICY_DEFAULT: u8 = 0;
pub const YKPIV_TOUCHPOLICY_NEVER: u8 = 1;
pub const YKPIV_TOUCHPOLICY_ALWAYS: u8 = 2;
pub const YKPIV_TOUCHPOLICY_CACHED: u8 = 3;
