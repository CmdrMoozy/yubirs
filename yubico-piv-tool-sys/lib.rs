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

#![allow(non_camel_case_types)]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate pcsc_sys;

use libc::{c_char, c_int, c_long, c_uchar, c_ulong, size_t};
use std::collections::HashMap;
use std::fmt;
use std::ptr;

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
        SCard(SmartCardError);
        Utf8Slice(std::str::Utf8Error);
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

#[repr(C)]
pub struct ykpiv_state {
    pub context: pcsc_sys::SCARDCONTEXT,
    pub card: pcsc_sys::SCARDHANDLE,
    pub verbose: c_int,
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
        })
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
}

impl Drop for ykpiv_state {
    fn drop(&mut self) {
        self.disconnect();
    }
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
    pub fn ykpiv_strerror(err: ykpiv_rc) -> *const c_char;
    pub fn ykpiv_strerror_name(err: ykpiv_rc) -> *const c_char;

    pub fn ykpiv_connect(state: *mut ykpiv_state, wanted: *const c_char) -> ykpiv_rc;
    pub fn ykpiv_transfer_data(
        state: *mut ykpiv_state,
        templ: *const c_uchar,
        in_data: *const c_uchar,
        in_len: c_long,
        out_data: *mut c_uchar,
        out_len: *mut c_ulong,
        sw: *mut c_int,
    ) -> ykpiv_rc;
    pub fn ykpiv_authenticate(state: *mut ykpiv_state, key: *const c_uchar) -> ykpiv_rc;
    pub fn ykpiv_hex_decode(
        hex_in: *const c_char,
        in_len: size_t,
        hex_out: *mut c_uchar,
        out_len: *mut size_t,
    ) -> ykpiv_rc;
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
    pub fn ykpiv_get_version(
        state: *mut ykpiv_state,
        version: *mut c_char,
        len: size_t,
    ) -> ykpiv_rc;
    pub fn ykpiv_verify(state: *mut ykpiv_state, pin: *const c_char, tries: *mut c_int)
        -> ykpiv_rc;
    pub fn ykpiv_change_pin(
        state: *mut ykpiv_state,
        current_pin: *const c_char,
        current_pin_len: size_t,
        new_pin: *const c_char,
        new_pin_len: size_t,
        tries: *mut c_int,
    ) -> ykpiv_rc;
    pub fn ykpiv_change_puk(
        state: *mut ykpiv_state,
        current_puk: *const c_char,
        current_puk_len: size_t,
        new_puk: *const c_char,
        new_puk_len: size_t,
        tries: *mut c_int,
    ) -> ykpiv_rc;
    pub fn ykpiv_unblock_pin(
        state: *mut ykpiv_state,
        puk: *const c_char,
        puk_len: size_t,
        new_pin: *const c_char,
        new_pin_len: size_t,
        tries: *mut c_int,
    ) -> ykpiv_rc;
    pub fn ykpiv_fetch_object(
        state: *mut ykpiv_state,
        object_id: c_int,
        data: *mut c_uchar,
        len: *mut c_ulong,
    ) -> ykpiv_rc;
    pub fn ykpiv_set_mgmkey2(
        state: *mut ykpiv_state,
        new_key: *const c_uchar,
        touch: c_uchar,
    ) -> ykpiv_rc;
    pub fn ykpiv_save_object(
        state: *mut ykpiv_state,
        object_id: c_int,
        indata: *mut c_uchar,
        len: size_t,
    ) -> ykpiv_rc;
    pub fn ykpiv_import_private_key(
        state: *mut ykpiv_state,
        key: c_uchar,
        algorithm: c_uchar,
        p: *const c_uchar,
        p_len: size_t,
        q: *const c_uchar,
        q_len: size_t,
        dp: *const c_uchar,
        dp_len: size_t,
        dq: *const c_uchar,
        dq_len: size_t,
        qinv: *const c_uchar,
        qinv_len: size_t,
        ec_data: *const c_uchar,
        ec_data_len: c_uchar,
        pin_policy: c_uchar,
        touch_policy: c_uchar,
    ) -> ykpiv_rc;
}

#[inline]
pub fn ykpiv_is_ec(a: c_uchar) -> bool {
    a == YKPIV_ALGO_ECCP256 || a == YKPIV_ALGO_ECCP384
}
#[inline]
pub fn ykpiv_is_rsa(a: c_uchar) -> bool {
    a == YKPIV_ALGO_RSA1024 || a == YKPIV_ALGO_RSA2048
}
