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

use libc::{c_int, c_uchar};

pub const YKPIV_ALGO_TAG: c_uchar = 0x80;
pub const YKPIV_ALGO_3DES: c_uchar = 0x03;
pub const YKPIV_ALGO_RSA1024: c_uchar = 0x06;
pub const YKPIV_ALGO_RSA2048: c_uchar = 0x07;
pub const YKPIV_ALGO_ECCP256: c_uchar = 0x11;
pub const YKPIV_ALGO_ECCP384: c_uchar = 0x14;

pub const YKPIV_KEY_AUTHENTICATION: c_uchar = 0x9a;
pub const YKPIV_KEY_CARDMGM: c_uchar = 0x9b;
pub const YKPIV_KEY_SIGNATURE: c_uchar = 0x9c;
pub const YKPIV_KEY_KEYMGM: c_uchar = 0x9d;
pub const YKPIV_KEY_CARDAUTH: c_uchar = 0x9e;
pub const YKPIV_KEY_RETIRED1: c_uchar = 0x82;
pub const YKPIV_KEY_RETIRED2: c_uchar = 0x83;
pub const YKPIV_KEY_RETIRED3: c_uchar = 0x84;
pub const YKPIV_KEY_RETIRED4: c_uchar = 0x85;
pub const YKPIV_KEY_RETIRED5: c_uchar = 0x86;
pub const YKPIV_KEY_RETIRED6: c_uchar = 0x87;
pub const YKPIV_KEY_RETIRED7: c_uchar = 0x88;
pub const YKPIV_KEY_RETIRED8: c_uchar = 0x89;
pub const YKPIV_KEY_RETIRED9: c_uchar = 0x8a;
pub const YKPIV_KEY_RETIRED10: c_uchar = 0x8b;
pub const YKPIV_KEY_RETIRED11: c_uchar = 0x8c;
pub const YKPIV_KEY_RETIRED12: c_uchar = 0x8d;
pub const YKPIV_KEY_RETIRED13: c_uchar = 0x8e;
pub const YKPIV_KEY_RETIRED14: c_uchar = 0x8f;
pub const YKPIV_KEY_RETIRED15: c_uchar = 0x90;
pub const YKPIV_KEY_RETIRED16: c_uchar = 0x91;
pub const YKPIV_KEY_RETIRED17: c_uchar = 0x92;
pub const YKPIV_KEY_RETIRED18: c_uchar = 0x93;
pub const YKPIV_KEY_RETIRED19: c_uchar = 0x94;
pub const YKPIV_KEY_RETIRED20: c_uchar = 0x95;
pub const YKPIV_KEY_ATTESTATION: c_uchar = 0xf9;

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

pub const YKPIV_INS_VERIFY: c_uchar = 0x20;
pub const YKPIV_INS_CHANGE_REFERENCE: c_uchar = 0x24;
pub const YKPIV_INS_RESET_RETRY: c_uchar = 0x2c;
pub const YKPIV_INS_GENERATE_ASYMMETRIC: c_uchar = 0x47;
pub const YKPIV_INS_AUTHENTICATE: c_uchar = 0x87;
pub const YKPIV_INS_GET_DATA: c_uchar = 0xcb;
pub const YKPIV_INS_PUT_DATA: c_uchar = 0xdb;

pub const SW_SUCCESS: c_int = 0x9000;
pub const SW_ERR_SECURITY_STATUS: c_int = 0x6982;
pub const SW_ERR_AUTH_BLOCKED: c_int = 0x6983;
pub const SW_ERR_INCORRECT_PARAM: c_int = 0x6a80;
pub const SW_ERR_INCORRECT_SLOT: c_int = 0x6b00;

pub const YKPIV_INS_SET_MGMKEY: c_uchar = 0xff;
pub const YKPIV_INS_IMPORT_KEY: c_uchar = 0xfe;
pub const YKPIV_INS_GET_VERSION: c_uchar = 0xfd;
pub const YKPIV_INS_RESET: c_uchar = 0xfb;
pub const YKPIV_INS_SET_PIN_RETRIES: c_uchar = 0xfa;
pub const YKPIV_INS_ATTEST: c_uchar = 0xf9;

pub const YKPIV_PINPOLICY_TAG: c_uchar = 0xaa;
pub const YKPIV_PINPOLICY_DEFAULT: c_uchar = 0;
pub const YKPIV_PINPOLICY_NEVER: c_uchar = 1;
pub const YKPIV_PINPOLICY_ONCE: c_uchar = 2;
pub const YKPIV_PINPOLICY_ALWAYS: c_uchar = 3;

pub const YKPIV_TOUCHPOLICY_TAG: c_uchar = 0xab;
pub const YKPIV_TOUCHPOLICY_DEFAULT: c_uchar = 0;
pub const YKPIV_TOUCHPOLICY_NEVER: c_uchar = 1;
pub const YKPIV_TOUCHPOLICY_ALWAYS: c_uchar = 2;
pub const YKPIV_TOUCHPOLICY_CACHED: c_uchar = 3;
