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

// TODO: Remove this.
#![allow(non_camel_case_types)]

extern crate data_encoding;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate log;
extern crate openssl;
extern crate pcsc_sys;
extern crate rand;
extern crate rpassword;

use libc::{c_char, c_int, c_uchar, size_t};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fmt;
use std::ptr;

/// The default reader string to use. The first reader (as returned by list_readers) which contains
/// this string as a substring is the one which will be used. So, this default will result in us
/// using the first connected Yubikey we find.
pub const DEFAULT_READER: &'static str = "Yubikey";

const PIN_NAME: &'static str = "PIN";
const PIN_PROMPT: &'static str = "PIN: ";
const NEW_PIN_PROMPT: &'static str = "New PIN: ";

const PUK_NAME: &'static str = "PUK";
const PUK_PROMPT: &'static str = "PUK: ";
const NEW_PUK_PROMPT: &'static str = "New PUK: ";

const MGM_KEY_PROMPT: &'static str = "Management Key: ";
const NEW_MGM_KEY_PROMPT: &'static str = "New Management Key: ";
const MGM_KEY_BYTES: usize = 24;

// TODO: This CHUID has an expiry of 2030-01-01, it should be configurable instead.
/// FASC-N containing S9999F9999F999999F0F1F0000000000300001E encoded in 4-bit BCD with 1-bit
/// parity. This can be run through
/// https://github.com/Yubico/yubico-piv-tool/blob/master/tools/fasc.pl to get bytes.
#[cfg_attr(rustfmt, rustfmt_skip)]
const CHUID_TEMPLATE: &'static [c_uchar] = &[
    0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68,
    0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x38, 0x42, 0x10, 0xc3, 0xf5, 0x34, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x35, 0x08, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,
];
const CHUID_RANDOM_OFFSET: usize = 29;
const CHUID_RANDOM_BYTES: usize = 16;

#[cfg_attr(rustfmt, rustfmt_skip)]
const CCC_TEMPLATE: &'static [c_uchar] = &[
    0xf0, 0x15, 0xa0, 0x00, 0x00, 0x01, 0x16, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x01, 0x21, 0xf2, 0x01, 0x21, 0xf3,
    0x00, 0xf4, 0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7, 0x00, 0xfa, 0x00, 0xfb, 0x00,
    0xfc, 0x00, 0xfd, 0x00, 0xfe, 0x00,
];
const CCC_RANDOM_OFFSET: usize = 9;
const CCC_RANDOM_BYTES: usize = 14;

lazy_static! {
    // Weak DES keys, from: https://en.wikipedia.org/wiki/Weak_key#Weak_keys_in_DES.
    static ref DES_WEAK_KEYS: HashSet<[u8; 8]> = {
        let mut s = HashSet::new();
        s.insert([0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01]);
        s.insert([0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE]);
        s.insert([0xE0,0xE0,0xE0,0xE0,0xF1,0xF1,0xF1,0xF1]);
        s.insert([0x1F,0x1F,0x1F,0x1F,0x0E,0x0E,0x0E,0x0E]);
        s.insert([0x01,0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E]);
        s.insert([0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E,0x01]);
        s.insert([0x01,0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1]);
        s.insert([0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1,0x01]);
        s.insert([0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE]);
        s.insert([0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01]);
        s.insert([0x1F,0xE0,0x1F,0xE0,0x0E,0xF1,0x0E,0xF1]);
        s.insert([0xE0,0x1F,0xE0,0x1F,0xF1,0x0E,0xF1,0x0E]);
        s.insert([0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E,0xFE]);
        s.insert([0xFE,0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E]);
        s.insert([0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE]);
        s.insert([0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1]);
        s
    };
}

#[cfg_attr(rustfmt, rustfmt_skip)]
const ODD_PARITY_BYTES: [u8; 256] = [
    1,   1,   2,   2,   4,   4,   7,   7,   8,   8,   11,  11,  13,  13,  14,  14,  16,  16,  19,
    19,  21,  21,  22,  22,  25,  25,  26,  26,  28,  28,  31,  31,  32,  32,  35,  35,  37,  37,
    38,  38,  41,  41,  42,  42,  44,  44,  47,  47,  49,  49,  50,  50,  52,  52,  55,  55,  56,
    56,  59,  59,  61,  61,  62,  62,  64,  64,  67,  67,  69,  69,  70,  70,  73,  73,  74,  74,
    76,  76,  79,  79,  81,  81,  82,  82,  84,  84,  87,  87,  88,  88,  91,  91,  93,  93,  94,
    94,  97,  97,  98,  98,  100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110, 112, 112,
    115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127, 128, 128, 131, 131, 133,
    133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143, 145, 145, 146, 146, 148, 148, 151, 151,
    152, 152, 155, 155, 157, 157, 158, 158, 161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171,
    171, 173, 173, 174, 174, 176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188,
    191, 191, 193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206, 208,
    208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223, 224, 224, 227, 227,
    229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239, 241, 241, 242, 242, 244, 244, 247,
    247, 248, 248, 251, 251, 253, 253, 254, 254,
];

/// Returns true if the given managment key's 3 DES keys are "weak", and therefore shouldn't be
/// used. The given input management key should have been decoded from hex, but no parity bits
/// should have been added yet (this is done implicitly).
fn is_weak_mgm_key(mgm_key: &[u8]) -> Result<bool> {
    if mgm_key.len() != MGM_KEY_BYTES {
        bail!(
            "Invalid management key; must be {} bytes long",
            MGM_KEY_BYTES
        );
    }
    let mgm_key: Vec<u8> = mgm_key
        .iter()
        .map(|b| ODD_PARITY_BYTES[*b as usize])
        .collect();
    for key in mgm_key.as_slice().chunks(8) {
        if DES_WEAK_KEYS.contains(key) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SmartCardError {
    BadSeek,
    BrokenPipe,
    CacheItemNotFound,
    CacheItemStale,
    CacheItemTooBig,
    Cancelled,
    CancelledByUser,
    CantDispose,
    CardNotAuthenticated,
    CardUnsupported,
    CertificateUnavailable,
    ChvBlocked,
    CommDataLost,
    CommError,
    DirNotFound,
    DuplicateReader,
    Eof,
    FileNotFound,
    IccCreateOrder,
    IccInstallation,
    InsufficientBuffer,
    InternalError,
    InvalidAtr,
    InvalidChv,
    InvalidHandle,
    InvalidParameter,
    InvalidTarget,
    InvalidValue,
    NoAccess,
    NoDir,
    NoFile,
    NoKeyContainer,
    NoMemory,
    NoPinCache,
    NoReadersAvailable,
    NoService,
    NoSmartCard,
    NoSuchCertificate,
    NotReady,
    NotTransacted,
    PciTooSmall,
    PinCacheExpired,
    ProtoMismatch,
    ReaderUnavailable,
    ReaderUnsupported,
    ReadOnlyCard,
    RemovedCard,
    ResetCard,
    SecurityViolation,
    ServerTooBusy,
    ServiceStopped,
    SharingViolation,
    Shutdown,
    SystemCancelled,
    Timeout,
    Unexpected,
    UnknownCard,
    UnknownError,
    UnknownReader,
    UnknownResMng,
    UnpoweredCard,
    UnresponsiveCard,
    UnsupportedCard,
    UnsupportedFeature,
    WaitedTooLong,
    WriteTooMany,
    WrongChv,
}

lazy_static! {
    static ref FROM_SCARDERR_H_MAPPING: HashMap<pcsc_sys::LONG, SmartCardError> = {
        let mut m = HashMap::new();
        m.insert(pcsc_sys::SCARD_E_BAD_SEEK, SmartCardError::BadSeek);
        m.insert(0x00000109, SmartCardError::BrokenPipe);
        m.insert(pcsc_sys::SCARD_W_CACHE_ITEM_NOT_FOUND, SmartCardError::CacheItemNotFound);
        m.insert(pcsc_sys::SCARD_W_CACHE_ITEM_STALE, SmartCardError::CacheItemStale);
        m.insert(pcsc_sys::SCARD_W_CACHE_ITEM_TOO_BIG, SmartCardError::CacheItemTooBig);
        m.insert(pcsc_sys::SCARD_E_CANCELLED, SmartCardError::Cancelled);
        m.insert(pcsc_sys::SCARD_W_CANCELLED_BY_USER, SmartCardError::CancelledByUser);
        m.insert(pcsc_sys::SCARD_E_CANT_DISPOSE, SmartCardError::CantDispose);
        m.insert(pcsc_sys::SCARD_W_CARD_NOT_AUTHENTICATED, SmartCardError::CardNotAuthenticated);
        m.insert(pcsc_sys::SCARD_E_CARD_UNSUPPORTED, SmartCardError::CardUnsupported);
        m.insert(pcsc_sys::SCARD_E_CERTIFICATE_UNAVAILABLE, SmartCardError::CertificateUnavailable);
        m.insert(pcsc_sys::SCARD_W_CHV_BLOCKED, SmartCardError::ChvBlocked);
        m.insert(pcsc_sys::SCARD_E_COMM_DATA_LOST, SmartCardError::CommDataLost);
        m.insert(pcsc_sys::SCARD_F_COMM_ERROR, SmartCardError::CommError);
        m.insert(pcsc_sys::SCARD_E_DIR_NOT_FOUND, SmartCardError::DirNotFound);
        m.insert(pcsc_sys::SCARD_E_DUPLICATE_READER, SmartCardError::DuplicateReader);
        m.insert(pcsc_sys::SCARD_W_EOF, SmartCardError::Eof);
        m.insert(pcsc_sys::SCARD_E_FILE_NOT_FOUND, SmartCardError::FileNotFound);
        m.insert(pcsc_sys::SCARD_E_ICC_CREATEORDER, SmartCardError::IccCreateOrder);
        m.insert(pcsc_sys::SCARD_E_ICC_INSTALLATION, SmartCardError::IccInstallation);
        m.insert(pcsc_sys::SCARD_E_INSUFFICIENT_BUFFER, SmartCardError::InsufficientBuffer);
        m.insert(pcsc_sys::SCARD_F_INTERNAL_ERROR, SmartCardError::InternalError);
        m.insert(pcsc_sys::SCARD_E_INVALID_ATR, SmartCardError::InvalidAtr);
        m.insert(pcsc_sys::SCARD_E_INVALID_CHV, SmartCardError::InvalidChv);
        m.insert(pcsc_sys::SCARD_E_INVALID_HANDLE, SmartCardError::InvalidHandle);
        m.insert(pcsc_sys::SCARD_E_INVALID_PARAMETER, SmartCardError::InvalidParameter);
        m.insert(pcsc_sys::SCARD_E_INVALID_TARGET, SmartCardError::InvalidTarget);
        m.insert(pcsc_sys::SCARD_E_INVALID_VALUE, SmartCardError::InvalidValue);
        m.insert(pcsc_sys::SCARD_E_NO_ACCESS, SmartCardError::NoAccess);
        m.insert(pcsc_sys::SCARD_E_NO_DIR, SmartCardError::NoDir);
        m.insert(pcsc_sys::SCARD_E_NO_FILE, SmartCardError::NoFile);
        m.insert(pcsc_sys::SCARD_E_NO_KEY_CONTAINER, SmartCardError::NoKeyContainer);
        m.insert(pcsc_sys::SCARD_E_NO_MEMORY, SmartCardError::NoMemory);
        m.insert(0x80100033, SmartCardError::NoPinCache);
        m.insert(pcsc_sys::SCARD_E_NO_READERS_AVAILABLE, SmartCardError::NoReadersAvailable);
        m.insert(pcsc_sys::SCARD_E_NO_SERVICE, SmartCardError::NoService);
        m.insert(pcsc_sys::SCARD_E_NO_SMARTCARD, SmartCardError::NoSmartCard);
        m.insert(pcsc_sys::SCARD_E_NO_SUCH_CERTIFICATE, SmartCardError::NoSuchCertificate);
        m.insert(pcsc_sys::SCARD_E_NOT_READY, SmartCardError::NotReady);
        m.insert(pcsc_sys::SCARD_E_NOT_TRANSACTED, SmartCardError::NotTransacted);
        m.insert(pcsc_sys::SCARD_E_PCI_TOO_SMALL, SmartCardError::PciTooSmall);
        m.insert(0x80100032, SmartCardError::PinCacheExpired);
        m.insert(pcsc_sys::SCARD_E_PROTO_MISMATCH, SmartCardError::ProtoMismatch);
        m.insert(pcsc_sys::SCARD_E_READER_UNAVAILABLE, SmartCardError::ReaderUnavailable);
        m.insert(pcsc_sys::SCARD_E_READER_UNSUPPORTED, SmartCardError::ReaderUnsupported);
        m.insert(0x80100034, SmartCardError::ReadOnlyCard);
        m.insert(pcsc_sys::SCARD_W_REMOVED_CARD, SmartCardError::RemovedCard);
        m.insert(pcsc_sys::SCARD_W_RESET_CARD, SmartCardError::ResetCard);
        m.insert(pcsc_sys::SCARD_W_SECURITY_VIOLATION, SmartCardError::SecurityViolation);
        m.insert(pcsc_sys::SCARD_E_SERVER_TOO_BUSY, SmartCardError::ServerTooBusy);
        m.insert(pcsc_sys::SCARD_E_SERVICE_STOPPED, SmartCardError::ServiceStopped);
        m.insert(pcsc_sys::SCARD_E_SHARING_VIOLATION, SmartCardError::SharingViolation);
        m.insert(pcsc_sys::SCARD_P_SHUTDOWN, SmartCardError::Shutdown);
        m.insert(pcsc_sys::SCARD_E_SYSTEM_CANCELLED, SmartCardError::SystemCancelled);
        m.insert(pcsc_sys::SCARD_E_TIMEOUT, SmartCardError::Timeout);
        m.insert(pcsc_sys::SCARD_E_UNEXPECTED, SmartCardError::Unexpected);
        m.insert(pcsc_sys::SCARD_E_UNKNOWN_CARD, SmartCardError::UnknownCard);
        m.insert(pcsc_sys::SCARD_F_UNKNOWN_ERROR, SmartCardError::UnknownError);
        m.insert(pcsc_sys::SCARD_E_UNKNOWN_READER, SmartCardError::UnknownReader);
        m.insert(pcsc_sys::SCARD_E_UNKNOWN_RES_MNG, SmartCardError::UnknownResMng);
        m.insert(pcsc_sys::SCARD_W_UNPOWERED_CARD, SmartCardError::UnpoweredCard);
        m.insert(pcsc_sys::SCARD_W_UNRESPONSIVE_CARD, SmartCardError::UnresponsiveCard);
        m.insert(pcsc_sys::SCARD_W_UNSUPPORTED_CARD, SmartCardError::UnsupportedCard);
        m.insert(pcsc_sys::SCARD_E_UNSUPPORTED_FEATURE, SmartCardError::UnsupportedFeature);
        m.insert(pcsc_sys::SCARD_F_WAITED_TOO_LONG, SmartCardError::WaitedTooLong);
        m.insert(pcsc_sys::SCARD_E_WRITE_TOO_MANY, SmartCardError::WriteTooMany);
        m.insert(pcsc_sys::SCARD_W_WRONG_CHV, SmartCardError::WrongChv);
        m
    };

    static ref TO_SCARDERR_H_MAPPING: HashMap<SmartCardError, pcsc_sys::LONG> =
        FROM_SCARDERR_H_MAPPING.iter().map(|pair| (*pair.1, *pair.0)).collect();
}

impl SmartCardError {
    pub fn new(code: pcsc_sys::LONG) -> std::result::Result<(), SmartCardError> {
        match code {
            pcsc_sys::SCARD_S_SUCCESS => Ok(()),
            _ => if let Some(e) = FROM_SCARDERR_H_MAPPING.get(&code) {
                Err(*e)
            } else {
                Err(SmartCardError::UnknownResMng)
            },
        }
    }

    pub fn get_code(&self) -> pcsc_sys::LONG {
        *TO_SCARDERR_H_MAPPING.get(self).unwrap()
    }
}

impl std::error::Error for SmartCardError {
    fn description(&self) -> &str {
        match *self {
            SmartCardError::BadSeek => {
                "An error occurred in setting the smart card file object pointer."
            }
            SmartCardError::BrokenPipe => concat!(
                "The client attempted a smart card operation in a remote session, such as a ",
                "client session running on a terminal server, and the operating system in use ",
                "does not support smart card redirection.",
            ),
            SmartCardError::CacheItemNotFound => {
                "The requested item could not be found in the cache."
            }
            SmartCardError::CacheItemStale => {
                "The requested cache item is too old and was deleted from the cache."
            }
            SmartCardError::CacheItemTooBig => {
                "The new cache item exceeds the maximum per-item size defined for the cache."
            }
            SmartCardError::Cancelled => "The action was canceled by an SCardCancel request.",
            SmartCardError::CancelledByUser => "The action was canceled by the user.",
            SmartCardError::CantDispose => {
                "The system could not dispose of the media in the requested manner."
            }
            SmartCardError::CardNotAuthenticated => "No PIN was presented to the smart card.",
            SmartCardError::CardUnsupported => {
                "The smart card does not meet minimal requirements for support."
            }
            SmartCardError::CertificateUnavailable => {
                "The requested certificate could not be obtained."
            }
            SmartCardError::ChvBlocked => {
                "The card can't be accessed because the max number of PIN attempts was reached."
            }
            SmartCardError::CommDataLost => {
                "A communications error with the smart card has been detected."
            }
            SmartCardError::CommError => "An internal communications error has been detected.",
            SmartCardError::DirNotFound => {
                "The specified directory does not exist in the smart card."
            }
            SmartCardError::DuplicateReader => {
                "The reader driver did not produce a unique reader name."
            }
            SmartCardError::Eof => "The end of the smart card file has been reached.",
            SmartCardError::FileNotFound => "The specified file does not exist in the smart card.",
            SmartCardError::IccCreateOrder => {
                "The requested order of object creation is not supported."
            }
            SmartCardError::IccInstallation => {
                "No primary provider can be found for the smart card."
            }
            SmartCardError::InsufficientBuffer => {
                "The data buffer for returned data is too small for the returned data."
            }
            SmartCardError::InternalError => "An internal consistency check failed.",
            SmartCardError::InvalidAtr => {
                "An ATR string obtained from the registry is not a valid ATR string."
            }
            SmartCardError::InvalidChv => "The supplied PIN is incorrect.",
            SmartCardError::InvalidHandle => "The supplied handle was not valid.",
            SmartCardError::InvalidParameter => {
                "One or more of the supplied parameters could not be properly interpreted."
            }
            SmartCardError::InvalidTarget => {
                "Registry startup information is missing or not valid."
            }
            SmartCardError::InvalidValue => {
                "One or more of the supplied parameter values could not be properly interpreted."
            }
            SmartCardError::NoAccess => "Access is denied to the file.",
            SmartCardError::NoDir => "The supplied path does not represent a smart card directory.",
            SmartCardError::NoFile => "The supplied path does not represent a smart card file.",
            SmartCardError::NoKeyContainer => {
                "The requested key container does not exist on the smart card."
            }
            SmartCardError::NoMemory => "Not enough memory available to complete this command.",
            SmartCardError::NoPinCache => "The smart card PIN cannot be cached.",
            SmartCardError::NoReadersAvailable => "No smart card reader is available.",
            SmartCardError::NoService => "The smart card resource manager is not running.",
            SmartCardError::NoSmartCard => {
                "The operation requires a smart card, but no card is currently in the device."
            }
            SmartCardError::NoSuchCertificate => "The requested certificate does not exist.",
            SmartCardError::NotReady => "The reader or card is not ready to accept commands.",
            SmartCardError::NotTransacted => {
                "An attempt was made to end a nonexistent transaction."
            }
            SmartCardError::PciTooSmall => "The PCI receive buffer was too small.",
            SmartCardError::PinCacheExpired => "The smart card PIN cache has expired.",
            SmartCardError::ProtoMismatch => {
                "The requested protocols are incompatible with the protocol currently in use."
            }
            SmartCardError::ReaderUnavailable => {
                "The specified reader is not currently available for use."
            }
            SmartCardError::ReaderUnsupported => {
                "The reader driver does not meet minimal requirements for support."
            }
            SmartCardError::ReadOnlyCard => "The smart card is read-only and cannot be written to.",
            SmartCardError::RemovedCard => {
                "The smart card has been removed, so further communication is not possible."
            }
            SmartCardError::ResetCard => "The smart card was reset.",
            SmartCardError::SecurityViolation => {
                "Access was denied because of a security violation."
            }
            SmartCardError::ServerTooBusy => {
                "The smart card resource manager is too busy to complete this operation."
            }
            SmartCardError::ServiceStopped => "The smart card resource manager has shut down.",
            SmartCardError::SharingViolation => {
                "The smart card cannot be accessed because of other outstanding connections."
            }
            SmartCardError::Shutdown => {
                "The operation has been aborted to allow the server application to exit."
            }
            SmartCardError::SystemCancelled => {
                "The action was canceled by the system, presumably to log off or shut down."
            }
            SmartCardError::Timeout => "The user-specified time-out value has expired.",
            SmartCardError::Unexpected => "An unexpected card error has occurred.",
            SmartCardError::UnknownCard => "The specified smart card name is not recognized.",
            SmartCardError::UnknownError => {
                "An internal error has been detected, but the source is unknown."
            }
            SmartCardError::UnknownReader => "The specified reader name is not recognized.",
            SmartCardError::UnknownResMng => "An unrecognized error code was returned.",
            SmartCardError::UnpoweredCard => {
                "Power removed from the smart card, so further communication isn't possible."
            }
            SmartCardError::UnresponsiveCard => "The smart card is not responding to a reset.",
            SmartCardError::UnsupportedCard => {
                "The reader can't communicate with the card, due to ATR string config conflicts."
            }
            SmartCardError::UnsupportedFeature => {
                "This smart card does not support the requested feature."
            }
            SmartCardError::WaitedTooLong => "An internal consistency timer has expired.",
            SmartCardError::WriteTooMany => {
                "An attempt was made to write more data than would fit in the target object."
            }
            SmartCardError::WrongChv => {
                "The card cannot be accessed because the wrong PIN was presented."
            }
        }
    }
}

impl fmt::Display for SmartCardError {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        use std::error::Error;
        write!(f, "{}", self.description())
    }
}

impl fmt::Debug for SmartCardError {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        write!(
            f,
            "{:#x} {}",
            TO_SCARDERR_H_MAPPING.get(self).unwrap(),
            self
        )
    }
}

error_chain! {
    foreign_links {
        Decode(data_encoding::DecodeError);
        Io(std::io::Error);
        Nul(std::ffi::NulError);
        Openssl(openssl::error::ErrorStack);
        SCard(SmartCardError);
        Utf8Slice(std::str::Utf8Error);
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct StructuredApdu {
    /// Instruction class - indicates the type of command, e.g. interindustry or
    /// proprietary.
    pub cla: c_uchar,
    /// Instruction code - indicates the specific command, e.g. "write data".
    pub ins: c_uchar,
    /// First instruction parameter for the command, e.g. offset into file at
    /// which to write the data.
    pub p1: c_uchar,
    /// Second instruction parameter for the command, e.g. offset into file at
    /// which to write the data.
    pub p2: c_uchar,
    /// Encodes the number (N_c) of bytes of command data to follow. The
    /// official specification says that this field can be variable length, but
    /// upstream specifies it statically at 1 byte.
    pub lc: c_uchar,
    /// The command data. The official specification says this can be up to
    /// 65535 bytes long, but upstream defines it as a static 255 bytes.
    pub data: [c_uchar; 255],
}

/// APDU stands for "smart card Application Protocol Data Unit". This union
/// definition is used by upstream's library to alternate between treating APDU
/// data in a structured or unstructured way.
#[repr(C)]
#[derive(Clone, Copy)]
union Apdu {
    st: StructuredApdu,
    raw: [c_uchar; 230],
}

/// The Application ID to send in an APDU when connecting to a Yubikey.
const APDU_AID: [c_uchar; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

// TODO: Remove this function, leaving only send_data.
fn send_data_impl(
    card: pcsc_sys::SCARDHANDLE,
    apdu: *const Apdu,
    recv_buffer: &mut Vec<u8>,
) -> Result<c_int> {
    let send_len: pcsc_sys::DWORD = unsafe { (*apdu).st.lc as pcsc_sys::DWORD + 5 };
    debug!(
        "> {}",
        (unsafe { &(*apdu).raw[0..(send_len as usize)] })
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    let mut recv_length = recv_buffer.len() as pcsc_sys::DWORD;
    SmartCardError::new(unsafe {
        pcsc_sys::SCardTransmit(
            card,
            &pcsc_sys::g_rgSCardT1Pci,
            (*apdu).raw.as_ptr(),
            send_len,
            ptr::null_mut(),
            recv_buffer.as_mut_ptr(),
            &mut recv_length,
        )
    })?;
    debug!(
        "< {}",
        recv_buffer
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    recv_buffer.truncate(recv_length as usize);
    Ok(if recv_buffer.len() >= 2 {
        ((recv_buffer[recv_length as usize - 2] as c_int) << 8)
            | (recv_buffer[recv_length as usize - 1] as c_int)
    } else {
        0
    })
}

fn send_data(card: pcsc_sys::SCARDHANDLE, apdu: &Apdu) -> Result<(c_int, Vec<u8>)> {
    // Upstream uses a 261-byte buffer in all cases, even though this number seems mostly made up.
    // It seems like a sane default for now.
    let mut recv: Vec<u8> = vec![0; 261];
    Ok((send_data_impl(card, apdu, &mut recv)?, recv))
}

/// This is a utility function to prompt the user for a sensitive string, probably a PIN or a PUK.
fn prompt_for_string(prompt: &str, confirm: bool) -> Result<String> {
    loop {
        let string = rpassword::prompt_password_stderr(prompt)?;
        if !confirm || string == rpassword::prompt_password_stderr("Confirm: ")? {
            return Ok(string);
        }
    }
}

struct MaybePromptedString {
    value: CString,
    length: usize,
    was_provided: bool,
}

impl MaybePromptedString {
    pub fn new(provided: Option<&str>, prompt: &str, confirm: bool) -> Result<Self> {
        let prompted: Option<String> = match provided {
            None => Some(prompt_for_string(prompt, confirm)?),
            Some(_) => None,
        };
        let length: usize =
            provided.map_or_else(|| prompted.as_ref().map_or(0, |s| s.len()), |s| s.len());

        Ok(MaybePromptedString {
            value: CString::new(
                provided.map_or_else(|| prompted.as_ref().map_or("", |s| s.as_str()), |s| s),
            )?,
            length: length,
            was_provided: provided.is_some(),
        })
    }

    pub fn was_provided(&self) -> bool {
        self.was_provided
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    pub fn len(&self) -> usize {
        self.length
    }
}

enum VerificationResult {
    /// The verification was successful.
    Success,
    /// The verification failed, but can be reattempted some number of times.
    Failure(usize, Error),
    /// Verification failed, and there are no more retries available, so the failure is permanent.
    PermanentFailure(Error),
    /// The verification failed for some other reason. There may or may not be retries left for
    /// other types of failures.
    OtherFailure(Error),
}

impl VerificationResult {
    pub fn from_status(sw: c_int) -> VerificationResult {
        if sw == SW_SUCCESS {
            VerificationResult::Success
        } else if (sw >> 8) == 0x63 {
            VerificationResult::Failure(
                (sw & 0xf) as usize,
                SmartCardError::new(pcsc_sys::SCARD_E_INVALID_CHV)
                    .err()
                    .unwrap()
                    .into(),
            )
        } else if sw == SW_ERR_AUTH_BLOCKED {
            VerificationResult::PermanentFailure(
                SmartCardError::new(pcsc_sys::SCARD_W_CHV_BLOCKED)
                    .err()
                    .unwrap()
                    .into(),
            )
        } else {
            VerificationResult::OtherFailure(
                SmartCardError::new(pcsc_sys::SCARD_E_UNKNOWN_RES_MNG)
                    .err()
                    .unwrap()
                    .into(),
            )
        }
    }
}

/// This is a generic function which implements the boilerplate needed to execute some other
/// function which requires verification of some sort. This function will prompt for a value if one
/// is not provided, using the given prompt string. The name parameter should describe what the
/// value is, for human-readable error messages in case of failure.
fn verification_loop<F>(name: &str, value: Option<&str>, prompt: &str, callback: F) -> Result<()>
where
    F: Fn(&MaybePromptedString) -> VerificationResult,
{
    loop {
        let value = MaybePromptedString::new(value, prompt, false)?;
        match callback(&value) {
            VerificationResult::Success => return Ok(()),
            VerificationResult::Failure(tries, err) => {
                debug!("Incorrect {}, {} tries remaining: {}", name, tries, err);
                // If we didn't prompt for a value, retrying won't help, because we'd just be
                // retrying with the same value over again. In this case, just bail now.
                match value.was_provided() {
                    false => eprintln!("Incorrect {}, try again - {} tries remaining", name, tries),
                    true => bail!(err),
                };
            }
            VerificationResult::PermanentFailure(err) => {
                debug!("Incorrect {}, 0 tries remaining: {}", name, err);
                bail!("Verifying {} failed: no more retries", name);
            }
            VerificationResult::OtherFailure(err) => bail!(err),
        }
    }
}

/// This is a generic function which implements the boilerplate needed to verify and then change
/// some value. For example, changing the Yubikey's PIN or PUK after verifying the PIN or PUK. This
/// function will prompt for both an existing and a new value if they are not provided, using the
/// given names for human-readable error messages and the prompt strings for prompting the user.
fn verification_change_loop<F>(
    existing_name: &str,
    existing: Option<&str>,
    new_name: &str,
    new: Option<&str>,
    existing_prompt: &str,
    new_prompt: &str,
    callback: F,
) -> Result<()>
where
    F: Fn(&MaybePromptedString, &MaybePromptedString) -> VerificationResult,
{
    verification_loop(existing_name, existing, existing_prompt, |existing| {
        let new = match MaybePromptedString::new(new.clone(), new_prompt, true) {
            Err(err) => return VerificationResult::OtherFailure(err),
            Ok(new) => new,
        };
        callback(existing, &new)
    })
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum ChangeAction {
    ChangePin,
    UnblockPin,
    ChangePuk,
}

fn ykpiv_transfer_data(
    card: pcsc_sys::SCARDHANDLE,
    templ: &[c_uchar],
    in_data: &[c_uchar],
) -> Result<(c_int, Vec<c_uchar>)> {
    SmartCardError::new(unsafe { pcsc_sys::SCardBeginTransaction(card) })?;

    let mut out_data: Vec<c_uchar> = Vec::new();
    let mut sw: c_int = SW_SUCCESS;

    for chunk in in_data.chunks(255) {
        let mut data: [c_uchar; 255] = [0; 255];
        for (dst, src) in data.iter_mut().zip(chunk.iter()) {
            *dst = *src;
        }
        let apdu = Apdu {
            st: StructuredApdu {
                cla: if chunk.len() == 255 {
                    0x10
                } else {
                    *templ.get(0).unwrap_or(&0)
                },
                ins: *templ.get(1).unwrap_or(&0),
                p1: *templ.get(2).unwrap_or(&0),
                p2: *templ.get(3).unwrap_or(&0),
                lc: chunk.len() as u8,
                data: data,
            },
        };

        debug!(
            "Sending chunk of {} out of {} total bytes",
            chunk.len(),
            in_data.len()
        );
        let (sw_new, mut recv) = send_data(card, &apdu)?;
        sw = sw_new;
        if sw != SW_SUCCESS && sw >> 8 != 0x61 {
            return Ok((sw, out_data));
        }
        let recv_len = recv.len() - 2;
        recv.truncate(recv_len);
        out_data.append(&mut recv);
    }

    while sw >> 8 == 0x61 {
        let apdu = Apdu {
            st: StructuredApdu {
                cla: 0,
                ins: 0xc0,
                p1: 0,
                p2: 0,
                lc: 0,
                data: [0; 255],
            },
        };

        debug!(
            "The card indicates there are {} more bytes of data to read",
            sw & 0xff
        );
        let (sw_new, mut recv) = send_data(card, &apdu)?;
        sw = sw_new;
        if sw != SW_SUCCESS && sw >> 8 != 0x61 {
            return Ok((sw, out_data));
        }
        let recv_len = recv.len() - 2;
        recv.truncate(recv_len);
        out_data.append(&mut recv);
    }

    SmartCardError::new(unsafe {
        pcsc_sys::SCardEndTransaction(card, pcsc_sys::SCARD_LEAVE_CARD)
    })?;
    Ok((sw, out_data))
}

fn build_data_object(
    template: &'static [c_uchar],
    random_offset: usize,
    random_bytes_len: usize,
) -> Vec<u8> {
    let mut object: Vec<c_uchar> = Vec::with_capacity(template.len());
    object.extend_from_slice(&template[..random_offset]);
    let random_bytes: Vec<c_uchar> = rand::weak_rng().gen_iter().take(random_bytes_len).collect();
    object.extend(random_bytes.into_iter());
    object.extend_from_slice(&template[random_offset + random_bytes_len..]);
    object
}

// TODO: This should accept a Rust-style enum instead of an int.
fn ykpiv_save_object(
    card: pcsc_sys::SCARDHANDLE,
    object_id: c_int,
    mut object: Vec<u8>,
) -> Result<()> {
    let mut data: Vec<u8> = vec![0x5c];
    if object_id == YKPIV_OBJ_DISCOVERY {
        data.extend_from_slice(&[1, YKPIV_OBJ_DISCOVERY as u8]);
    } else if object_id > 0xffff && object_id <= 0xffffff {
        data.extend_from_slice(&[
            3,
            ((object_id >> 16) & 0xff) as u8,
            ((object_id >> 8) & 0xff) as u8,
            (object_id & 0xff) as u8,
        ]);
    }
    data.push(0x53);
    if object.len() < 0x80 {
        data.push(object.len() as u8);
    } else if object.len() < 0xff {
        data.extend_from_slice(&[0x81, object.len() as u8]);
    } else {
        data.extend_from_slice(&[
            0x82,
            ((object.len() >> 8) & 0xff) as u8,
            (object.len() & 0xff) as u8,
        ]);
    }
    data.append(&mut object);

    let (sw, _) = ykpiv_transfer_data(card, &[0, YKPIV_INS_PUT_DATA, 0x3f, 0xff], data.as_slice())?;
    if sw != SW_SUCCESS {
        bail!("Failed to save data object");
    }
    Ok(())
}

// TODO: This function should accept Rust-style enums instead of IDs. This would let us clean up
// some assorted input validation code.
pub fn ykpiv_import_private_key(
    card: pcsc_sys::SCARDHANDLE,
    key_id: c_uchar,
    algorithm_id: c_uchar,
    p: &[u8],
    q: &[u8],
    dp: &[u8],
    dq: &[u8],
    qinv: &[u8],
    ec_data: &[u8],
    pin_policy_id: c_uchar,
    touch_policy_id: c_uchar,
) -> Result<()> {
    if key_id == YKPIV_KEY_CARDMGM || key_id < YKPIV_KEY_RETIRED1
        || (key_id > YKPIV_KEY_RETIRED20 && key_id < YKPIV_KEY_AUTHENTICATION)
        || (key_id > YKPIV_KEY_CARDAUTH && key_id != YKPIV_KEY_ATTESTATION)
    {
        bail!("The specified key type is not supported by this function");
    }

    if pin_policy_id != YKPIV_PINPOLICY_DEFAULT && pin_policy_id != YKPIV_PINPOLICY_NEVER
        && pin_policy_id != YKPIV_PINPOLICY_ONCE && pin_policy_id != YKPIV_PINPOLICY_ALWAYS
    {
        bail!("Invalid PIN policy");
    }

    if touch_policy_id != YKPIV_TOUCHPOLICY_DEFAULT && touch_policy_id != YKPIV_TOUCHPOLICY_NEVER
        && touch_policy_id != YKPIV_TOUCHPOLICY_ALWAYS
        && touch_policy_id != YKPIV_TOUCHPOLICY_CACHED
    {
        bail!("Invalid touch policy");
    }

    if algorithm_id != YKPIV_ALGO_RSA1024 && algorithm_id != YKPIV_ALGO_RSA2048
        && algorithm_id != YKPIV_ALGO_ECCP256 && algorithm_id != YKPIV_ALGO_ECCP384
    {
        bail!("Invalid cryptographic algorithm");
    }

    let elem_len: usize = match algorithm_id {
        YKPIV_ALGO_RSA1024 => 64,
        YKPIV_ALGO_RSA2048 => 128,
        YKPIV_ALGO_ECCP256 => 32,
        YKPIV_ALGO_ECCP384 => 48,
        _ => 0,
    };

    let params: Vec<&[u8]> =
        if algorithm_id == YKPIV_ALGO_RSA1024 || algorithm_id == YKPIV_ALGO_RSA2048 {
            vec![p, q, dp, dq, qinv]
        } else if algorithm_id == YKPIV_ALGO_ECCP256 || algorithm_id == YKPIV_ALGO_ECCP384 {
            vec![ec_data]
        } else {
            vec![]
        };

    let param_tag: u8 = match algorithm_id {
        YKPIV_ALGO_RSA1024 => 0x01,
        YKPIV_ALGO_RSA2048 => 0x01,
        YKPIV_ALGO_ECCP256 => 0x06,
        YKPIV_ALGO_ECCP384 => 0x06,
        _ => 0,
    };

    let mut key_data: Vec<u8> = Vec::with_capacity(1024);
    for i in 0..params.len() {
        key_data.push(param_tag + (i as u8));
        if elem_len < 0x80 {
            key_data.push(elem_len as u8);
        } else if elem_len < 0xff {
            key_data.extend_from_slice(&[0x81, elem_len as u8]);
        } else {
            key_data.extend_from_slice(&[
                0x82,
                ((elem_len >> 8) & 0xff) as u8,
                (elem_len & 0xff) as u8,
            ]);
        }
        let new_len = key_data.len() + (elem_len - params[i].len());
        key_data.resize(new_len, 0);
        key_data.extend_from_slice(params[i]);
    }

    if pin_policy_id != YKPIV_PINPOLICY_DEFAULT {
        key_data.extend_from_slice(&[YKPIV_PINPOLICY_TAG, 0x01, pin_policy_id]);
    }

    if touch_policy_id != YKPIV_TOUCHPOLICY_DEFAULT {
        key_data.extend_from_slice(&[YKPIV_TOUCHPOLICY_TAG, 0x01, touch_policy_id]);
    }

    let (sw, _) = ykpiv_transfer_data(
        card,
        &[0, YKPIV_INS_IMPORT_KEY, algorithm_id, key_id],
        key_data.as_slice(),
    )?;
    match sw {
        SW_ERR_SECURITY_STATUS => bail!("Failed to import private key due to authentication error"),
        SW_SUCCESS => Ok(()),
        _ => bail!("Failed to import private key due to unknown error"),
    }
}

/// This function provides the common implementation for all of the various ways we can change the
/// PIN or PUK on a Yubikey. The way we do this using low-level PC/SC functions is identical,
/// except we send a different action value depending on the requested change type.
fn change_impl(
    card: pcsc_sys::SCARDHANDLE,
    action: ChangeAction,
    existing: &MaybePromptedString,
    new: &MaybePromptedString,
) -> VerificationResult {
    if existing.len() > 8 {
        return VerificationResult::OtherFailure(
            format!(
                "Invalid existing {}; it exceeds 8 characters",
                match action {
                    ChangeAction::ChangePin => "PIN",
                    ChangeAction::UnblockPin => "PUK",
                    ChangeAction::ChangePuk => "PUK",
                }
            ).into(),
        );
    }
    if new.len() > 8 {
        return VerificationResult::OtherFailure(
            format!(
                "Invalid new {}; it exceeds 8 characters",
                match action {
                    ChangeAction::ChangePin => "PIN",
                    ChangeAction::UnblockPin => "PIN",
                    ChangeAction::ChangePuk => "PUK",
                }
            ).into(),
        );
    }

    let mut templ: Vec<c_uchar> = vec![0, YKPIV_INS_CHANGE_REFERENCE, 0, 0x80];
    if action == ChangeAction::UnblockPin {
        templ[1] = YKPIV_INS_RESET_RETRY;
    }
    if action == ChangeAction::ChangePuk {
        templ[3] = 0x81;
    }

    let mut in_data: Vec<c_uchar> = vec![0; 16];
    for (dst, src) in in_data.iter_mut().zip(existing.as_bytes()) {
        *dst = *src;
    }
    for b in in_data
        .iter_mut()
        .skip(existing.len())
        .take(8 - existing.len())
    {
        *b = 0xff;
    }
    for (dst, src) in in_data.iter_mut().skip(8).zip(new.as_bytes()) {
        *dst = *src;
    }
    for b in in_data.iter_mut().skip(8 + new.len()).take(8 - new.len()) {
        *b = 0xff;
    }

    let (sw, _) = match ykpiv_transfer_data(card, templ.as_slice(), in_data.as_slice()) {
        Err(e) => return VerificationResult::OtherFailure(e),
        Ok(tuple) => tuple,
    };
    VerificationResult::from_status(sw)
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Version(u8, u8, u8);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

#[repr(C)]
pub struct ykpiv_state {
    pub context: pcsc_sys::SCARDCONTEXT,
    pub card: pcsc_sys::SCARDHANDLE,
    pub verbose: c_int,
    authenticated_pin: bool,
    authenticated_mgm: bool,
}

impl ykpiv_state {
    // TODO: Remove verbose flag.
    pub fn new(verbose: bool) -> Result<Self> {
        let mut context: pcsc_sys::SCARDCONTEXT = pcsc_sys::SCARD_E_INVALID_HANDLE;
        SmartCardError::new(unsafe {
            pcsc_sys::SCardEstablishContext(
                pcsc_sys::SCARD_SCOPE_SYSTEM,
                ptr::null(),
                ptr::null(),
                &mut context,
            )
        })?;
        Ok(ykpiv_state {
            context: context,
            card: 0,
            verbose: match verbose {
                false => 0,
                true => 1,
            },
            authenticated_pin: false,
            authenticated_mgm: false,
        })
    }

    fn authenticate_pin(&mut self, pin: Option<&str>) -> Result<()> {
        if self.authenticated_pin {
            return Ok(());
        }

        verification_loop(PIN_NAME, pin, PIN_PROMPT, |pin| {
            if pin.len() > 8 {
                return VerificationResult::OtherFailure(
                    "Invalid PIN; it exceeds 8 characters".into(),
                );
            }

            let mut data: [c_uchar; 255] = [0; 255];
            for (dst, src) in data.iter_mut().zip(pin.as_bytes()) {
                *dst = *src;
            }
            for b in data.iter_mut().skip(pin.len()).take(8 - pin.len()) {
                *b = 0xff;
            }

            let apdu = Apdu {
                st: StructuredApdu {
                    cla: 0,
                    ins: YKPIV_INS_VERIFY,
                    p1: 0x00,
                    p2: 0x80,
                    lc: 0x80,
                    data: data,
                },
            };

            let mut buffer: Vec<c_uchar> = vec![0; 261];
            VerificationResult::from_status(match send_data_impl(self.card, &apdu, &mut buffer) {
                Err(e) => return VerificationResult::OtherFailure(e),
                Ok(sw) => sw,
            })
        })?;
        Ok(())
    }

    fn authenticate_mgm(&mut self, mgm_key: Option<&str>) -> Result<()> {
        if self.authenticated_mgm {
            return Ok(());
        }

        let mgm_key: Vec<u8> = data_encoding::HEXLOWER_PERMISSIVE
            .decode(MaybePromptedString::new(mgm_key, MGM_KEY_PROMPT, false)?.as_bytes())?;
        // For 3DES, we should have three key portions of 8 bytes each, for a total of 24 bytes.
        debug_assert!(mgm_key.len() == MGM_KEY_BYTES);

        // Get a challenge from the card.
        let mut data: [c_uchar; 255] = [0; 255];
        data[0] = 0x7c;
        data[1] = 0x02;
        data[2] = 0x80;
        let apdu = Apdu {
            st: StructuredApdu {
                cla: 0,
                ins: YKPIV_INS_AUTHENTICATE,
                p1: YKPIV_ALGO_3DES,
                p2: YKPIV_KEY_CARDMGM,
                lc: 0x04,
                data: data,
            },
        };
        let (sw, response) = send_data(self.card, &apdu)?;
        if sw != SW_SUCCESS {
            bail!("Failed to get management key challenge from card");
        }
        let card_challenge: Vec<u8> = (&response[4..13]).into();
        debug_assert!(card_challenge.len() == 8);

        // Send a response to the card's challenge, and a challenge of our own.
        let our_challenge = openssl::symm::encrypt(
            openssl::symm::Cipher::des_ecb(),
            mgm_key.as_slice(),
            None,
            card_challenge.as_slice(),
        )?;
        debug_assert!(our_challenge.len() == 8);
        let mut data: [c_uchar; 255] = [0; 255];
        data[0] = 0x7c;
        data[1] = 20; // 2 + 8 + 2 + 8
        data[2] = 0x80;
        data[3] = 8;
        (&mut data[4..13]).copy_from_slice(our_challenge.as_slice());
        data[12] = 0x81;
        openssl::rand::rand_bytes(&mut data[13..21])?;
        let expected_card_reply: Vec<u8> = (&data[13..21]).into();
        let apdu = Apdu {
            st: StructuredApdu {
                cla: 0,
                ins: YKPIV_INS_AUTHENTICATE,
                p1: YKPIV_ALGO_3DES,
                p2: YKPIV_KEY_CARDMGM,
                lc: 21,
                data: [0; 255],
            },
        };
        let (sw, response) = send_data(self.card, &apdu)?;
        if sw != SW_SUCCESS {
            bail!("Failed to send management key challenge back to card");
        }

        // Compare the response from the card with our expected response.
        let expected_card_reply = openssl::symm::encrypt(
            openssl::symm::Cipher::des_ecb(),
            mgm_key.as_slice(),
            None,
            expected_card_reply.as_slice(),
        )?;
        if expected_card_reply.as_slice() != &response[4..13] {
            bail!("Management key authentication failed");
        }

        Ok(())
    }

    pub fn list_readers(&self) -> Result<Vec<String>> {
        let mut readers_len: pcsc_sys::DWORD = 0;
        SmartCardError::new(unsafe {
            pcsc_sys::SCardListReaders(self.context, ptr::null(), ptr::null_mut(), &mut readers_len)
        })?;

        let mut buffer: Vec<u8> = vec![0_u8; readers_len as usize];
        SmartCardError::new(unsafe {
            pcsc_sys::SCardListReaders(
                self.context,
                ptr::null(),
                buffer.as_mut_ptr() as *mut c_char,
                &mut readers_len,
            )
        })?;
        if readers_len as usize != buffer.len() {
            bail!("Failed to retrieve full reader list due to buffer size race.");
        }

        let ret: std::result::Result<Vec<String>, std::str::Utf8Error> = buffer
            .split(|b| *b == 0)
            .filter_map(|slice| match slice.len() {
                0 => None,
                _ => Some(std::str::from_utf8(slice).map(|s| s.to_owned())),
            })
            .collect();

        Ok(ret?)
    }

    pub fn connect(&mut self, reader: Option<&str>) -> Result<()> {
        let reader = reader.unwrap_or(DEFAULT_READER);
        let readers = self.list_readers()?;
        for potential_reader in readers {
            if !potential_reader.contains(reader) {
                info!(
                    "Skipping reader '{}' since it doesn't match '{}'",
                    potential_reader,
                    reader
                );
                continue;
            }

            info!("Attempting to connect to reader '{}'", potential_reader);
            let potential_reader = CString::new(potential_reader)?;
            let mut active_protocol: pcsc_sys::DWORD = pcsc_sys::SCARD_PROTOCOL_UNDEFINED;
            SmartCardError::new(unsafe {
                pcsc_sys::SCardConnect(
                    self.context,
                    potential_reader.as_ptr(),
                    pcsc_sys::SCARD_SHARE_SHARED,
                    pcsc_sys::SCARD_PROTOCOL_T1,
                    &mut self.card,
                    &mut active_protocol,
                )
            })?;

            let mut data: [c_uchar; 255] = [0; 255];
            for (dst, src) in data.iter_mut().zip(APDU_AID.iter()) {
                *dst = *src;
            }
            let apdu = Apdu {
                st: StructuredApdu {
                    cla: 0,
                    ins: 0xa4,
                    p1: 0x04,
                    p2: 0,
                    lc: APDU_AID.len() as c_uchar,
                    data: data,
                },
            };

            let mut recv_buffer: Vec<u8> = vec![0; 255];
            let sw = send_data_impl(self.card, &apdu, &mut recv_buffer)?;
            if sw != SW_SUCCESS {
                bail!("Failed selecting application: {:x}", sw);
            }

            return Ok(());
        }

        Err(
            SmartCardError::new(pcsc_sys::SCARD_E_UNKNOWN_READER)
                .err()
                .unwrap()
                .into(),
        )
    }

    pub fn disconnect(&mut self) {
        if self.card != 0 {
            unsafe {
                pcsc_sys::SCardDisconnect(self.card, pcsc_sys::SCARD_RESET_CARD);
            }
            self.card = 0;
        }

        if unsafe { pcsc_sys::SCardIsValidContext(self.context) } == pcsc_sys::SCARD_S_SUCCESS {
            unsafe { pcsc_sys::SCardReleaseContext(self.context) };
            self.context = pcsc_sys::SCARD_E_INVALID_HANDLE;
        }
    }

    pub fn get_version(&self) -> Result<Version> {
        let apdu = Apdu {
            st: StructuredApdu {
                cla: 0,
                ins: YKPIV_INS_GET_VERSION,
                p1: 0,
                p2: 0,
                lc: 0,
                data: [0; 255],
            },
        };
        let mut buffer: Vec<u8> = vec![0; 261];

        let sw = send_data_impl(self.card, &apdu, &mut buffer)?;
        if sw != SW_SUCCESS {
            bail!("Get version instruction returned error: {:x}", sw);
        }

        Ok(Version(buffer[0], buffer[1], buffer[2]))
    }

    pub fn change_pin(&mut self, old_pin: Option<&str>, new_pin: Option<&str>) -> Result<()> {
        verification_change_loop(
            PIN_NAME,
            old_pin,
            PIN_NAME,
            new_pin,
            PIN_PROMPT,
            NEW_PIN_PROMPT,
            |existing, new| change_impl(self.card, ChangeAction::ChangePin, existing, new),
        )
    }

    pub fn unblock_pin(&mut self, puk: Option<&str>, new_pin: Option<&str>) -> Result<()> {
        verification_change_loop(
            PUK_NAME,
            puk,
            PIN_NAME,
            new_pin,
            PUK_PROMPT,
            NEW_PIN_PROMPT,
            |existing, new| change_impl(self.card, ChangeAction::UnblockPin, existing, new),
        )
    }

    pub fn change_puk(&mut self, old_puk: Option<&str>, new_puk: Option<&str>) -> Result<()> {
        verification_change_loop(
            PUK_NAME,
            old_puk,
            PUK_NAME,
            new_puk,
            PUK_PROMPT,
            NEW_PUK_PROMPT,
            |existing, new| change_impl(self.card, ChangeAction::ChangePuk, existing, new),
        )
    }

    pub fn reset(&mut self) -> Result<()> {
        let (sw, _) = ykpiv_transfer_data(self.card, &[0, YKPIV_INS_RESET, 0, 0], &[])?;
        if sw != SW_SUCCESS {
            bail!("Reset failed, probably because PIN or PUK retries are still available");
        }
        Ok(())
    }

    pub fn set_retries(
        &mut self,
        mgm_key: Option<&str>,
        pin: Option<&str>,
        pin_retries: u8,
        puk_retries: u8,
    ) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        self.authenticate_pin(pin)?;
        let (sw, _) = ykpiv_transfer_data(
            self.card,
            &[0, YKPIV_INS_SET_PIN_RETRIES, pin_retries, puk_retries],
            &[],
        )?;
        if sw != SW_SUCCESS {
            bail!("Setting PIN and PUK retries failed");
        }
        Ok(())
    }

    pub fn set_management_key(
        &mut self,
        old_mgm_key: Option<&str>,
        new_mgm_key: Option<&str>,
        touch: bool,
    ) -> Result<()> {
        self.authenticate_mgm(old_mgm_key)?;

        let new_mgm_key: Vec<u8> = data_encoding::HEXLOWER_PERMISSIVE
            .decode(MaybePromptedString::new(new_mgm_key, NEW_MGM_KEY_PROMPT, true)?.as_bytes())?;
        if is_weak_mgm_key(new_mgm_key.as_slice())? {
            bail!("Refusing to set new management key because it contains weak DES keys");
        }

        let mut data: [c_uchar; 255] = [0; 255];
        data[0] = YKPIV_ALGO_3DES;
        data[1] = YKPIV_KEY_CARDMGM;
        data[2] = MGM_KEY_BYTES as c_uchar; // Key length
        (&mut data[3..(3 + MGM_KEY_BYTES)]).copy_from_slice(new_mgm_key.as_slice());
        let apdu = Apdu {
            st: StructuredApdu {
                cla: 0,
                ins: YKPIV_INS_SET_MGMKEY,
                p1: 0xff,
                p2: if touch { 0xfe } else { 0xff },
                lc: (MGM_KEY_BYTES as c_uchar) + 3, // Key length + 3 extra bytes in data
                data: data,
            },
        };

        let (sw, _) = send_data(self.card, &apdu)?;
        if sw != SW_SUCCESS {
            bail!("Failed to set new card management key");
        }
        Ok(())
    }

    pub fn set_chuid(&mut self, mgm_key: Option<&str>) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        let object = build_data_object(CHUID_TEMPLATE, CHUID_RANDOM_OFFSET, CHUID_RANDOM_BYTES);
        ykpiv_save_object(self.card, YKPIV_OBJ_CHUID, object)?;
        Ok(())
    }

    pub fn set_ccc(&mut self, mgm_key: Option<&str>) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        let object = build_data_object(CCC_TEMPLATE, CCC_RANDOM_OFFSET, CCC_RANDOM_BYTES);
        ykpiv_save_object(self.card, YKPIV_OBJ_CAPABILITY, object)?;
        Ok(())
    }

    pub fn read_object(&self, object_id: c_int) -> Result<Vec<u8>> {
        let mut data: Vec<u8> = Vec::new();
        // TODO: Deduplicate this if statement? It appears in one other place.
        if object_id == YKPIV_OBJ_DISCOVERY {
            data.extend_from_slice(&[1, YKPIV_OBJ_DISCOVERY as u8]);
        } else if object_id > 0xffff && object_id <= 0xffffff {
            data.extend_from_slice(&[
                3,
                ((object_id >> 16) & 0xff) as u8,
                ((object_id >> 8) & 0xff) as u8,
                (object_id & 0xff) as u8,
            ]);
        }

        let (sw, mut recv) = ykpiv_transfer_data(
            self.card,
            &[0, YKPIV_INS_GET_DATA, 0x3f, 0xff],
            data.as_slice(),
        )?;
        if sw != SW_SUCCESS {
            bail!("Failed to read data object");
        }

        recv.remove(0); // The first byte is not part of the object or length.
        if recv[0] < 0x81 {
            let length = recv[0] as usize;
            recv.remove(0);
            recv.truncate(length);
        } else if (recv[0] & 0x7f) == 1 {
            let length = recv[1] as usize;
            recv.remove(0);
            recv.remove(0);
            recv.truncate(length);
        } else if (recv[0] & 0x7f) == 2 {
            let length = ((recv[1] as usize) << 8) + (recv[2] as usize);
            recv.remove(0);
            recv.remove(0);
            recv.remove(0);
            recv.truncate(length);
        } else {
            bail!("Failed to determine size of returned data object");
        }

        Ok(recv)
    }

    pub fn write_object(
        &mut self,
        mgm_key: Option<&str>,
        object_id: c_int,
        buffer: Vec<u8>,
    ) -> Result<()> {
        self.authenticate_mgm(mgm_key)?;
        ykpiv_save_object(self.card, object_id, buffer)?;
        Ok(())
    }
}

impl Drop for ykpiv_state {
    fn drop(&mut self) {
        self.disconnect();
    }
}

macro_rules! ykpiv_enum {
    (pub enum $name:ident { $($variants:tt)* }) => {
        #[cfg(target_env = "msvc")]
        pub type $name = i32;
        #[cfg(not(target_env = "msvc"))]
        pub type $name = u32;
        ykpiv_enum!(gen, $name, 0, $($variants)*);
    };
    (pub enum $name:ident: $t:ty { $($variants:tt)* }) => {
        pub type $name = $t;
        ykpiv_enum!(gen, $name, 0, $($variants)*);
    };
    (gen, $name:ident, $val:expr, $variant:ident, $($rest:tt)*) => {
        pub const $variant: $name = $val;
        ykpiv_enum!(gen, $name, $val+1, $($rest)*);
    };
    (gen, $name:ident, $val:expr, $variant:ident = $e:expr, $($rest:tt)*) => {
        pub const $variant: $name = $e;
        ykpiv_enum!(gen, $name, $e+1, $($rest)*);
    };
    (gen, $name:ident, $val:expr, ) => {}
}

ykpiv_enum! {
    pub enum ykpiv_rc: c_int {
        YKPIV_OK = 0,
        YKPIV_MEMORY_ERROR = -1,
        YKPIV_PCSC_ERROR = -2,
        YKPIV_SIZE_ERROR = -3,
        YKPIV_APPLET_ERROR = -4,
        YKPIV_AUTHENTICATION_ERROR = -5,
        YKPIV_RANDOMNESS_ERROR = -6,
        YKPIV_GENERIC_ERROR = -7,
        YKPIV_KEY_ERROR = -8,
        YKPIV_PARSE_ERROR = -9,
        YKPIV_WRONG_PIN = -10,
        YKPIV_INVALID_OBJECT = -11,
        YKPIV_ALGORITHM_ERROR = -12,
        YKPIV_PIN_LOCKED = -13,
    }
}

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

extern "C" {
    pub fn ykpiv_sign_data(
        state: *mut ykpiv_state,
        sign_in: *const c_uchar,
        in_len: size_t,
        sign_out: *mut c_uchar,
        out_len: *mut size_t,
        algorithm: c_uchar,
        key: c_uchar,
    ) -> ykpiv_rc;
    pub fn ykpiv_decipher_data(
        state: *mut ykpiv_state,
        enc_in: *const c_uchar,
        in_len: size_t,
        enc_out: *mut c_uchar,
        out_len: *mut size_t,
        algorithm: c_uchar,
        key: c_uchar,
    ) -> ykpiv_rc;
}
