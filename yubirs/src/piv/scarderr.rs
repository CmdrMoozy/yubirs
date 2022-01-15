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

use backtrace::Backtrace;
use lazy_static::lazy_static;
use pcsc_sys;
use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SmartCardErrorCode {
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
    Other(String),
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
    static ref FROM_SCARDERR_H_MAPPING: HashMap<pcsc_sys::LONG, SmartCardErrorCode> = {
        let mut m = HashMap::new();
        m.insert(pcsc_sys::SCARD_E_BAD_SEEK, SmartCardErrorCode::BadSeek);
        m.insert(0x00000109, SmartCardErrorCode::BrokenPipe);
        m.insert(
            pcsc_sys::SCARD_W_CACHE_ITEM_NOT_FOUND,
            SmartCardErrorCode::CacheItemNotFound,
        );
        m.insert(
            pcsc_sys::SCARD_W_CACHE_ITEM_STALE,
            SmartCardErrorCode::CacheItemStale,
        );
        m.insert(
            pcsc_sys::SCARD_W_CACHE_ITEM_TOO_BIG,
            SmartCardErrorCode::CacheItemTooBig,
        );
        m.insert(pcsc_sys::SCARD_E_CANCELLED, SmartCardErrorCode::Cancelled);
        m.insert(
            pcsc_sys::SCARD_W_CANCELLED_BY_USER,
            SmartCardErrorCode::CancelledByUser,
        );
        m.insert(
            pcsc_sys::SCARD_E_CANT_DISPOSE,
            SmartCardErrorCode::CantDispose,
        );
        m.insert(
            pcsc_sys::SCARD_W_CARD_NOT_AUTHENTICATED,
            SmartCardErrorCode::CardNotAuthenticated,
        );
        m.insert(
            pcsc_sys::SCARD_E_CARD_UNSUPPORTED,
            SmartCardErrorCode::CardUnsupported,
        );
        m.insert(
            pcsc_sys::SCARD_E_CERTIFICATE_UNAVAILABLE,
            SmartCardErrorCode::CertificateUnavailable,
        );
        m.insert(
            pcsc_sys::SCARD_W_CHV_BLOCKED,
            SmartCardErrorCode::ChvBlocked,
        );
        m.insert(
            pcsc_sys::SCARD_E_COMM_DATA_LOST,
            SmartCardErrorCode::CommDataLost,
        );
        m.insert(pcsc_sys::SCARD_F_COMM_ERROR, SmartCardErrorCode::CommError);
        m.insert(
            pcsc_sys::SCARD_E_DIR_NOT_FOUND,
            SmartCardErrorCode::DirNotFound,
        );
        m.insert(
            pcsc_sys::SCARD_E_DUPLICATE_READER,
            SmartCardErrorCode::DuplicateReader,
        );
        m.insert(pcsc_sys::SCARD_W_EOF, SmartCardErrorCode::Eof);
        m.insert(
            pcsc_sys::SCARD_E_FILE_NOT_FOUND,
            SmartCardErrorCode::FileNotFound,
        );
        m.insert(
            pcsc_sys::SCARD_E_ICC_CREATEORDER,
            SmartCardErrorCode::IccCreateOrder,
        );
        m.insert(
            pcsc_sys::SCARD_E_ICC_INSTALLATION,
            SmartCardErrorCode::IccInstallation,
        );
        m.insert(
            pcsc_sys::SCARD_E_INSUFFICIENT_BUFFER,
            SmartCardErrorCode::InsufficientBuffer,
        );
        m.insert(
            pcsc_sys::SCARD_F_INTERNAL_ERROR,
            SmartCardErrorCode::InternalError,
        );
        m.insert(
            pcsc_sys::SCARD_E_INVALID_ATR,
            SmartCardErrorCode::InvalidAtr,
        );
        m.insert(
            pcsc_sys::SCARD_E_INVALID_CHV,
            SmartCardErrorCode::InvalidChv,
        );
        m.insert(
            pcsc_sys::SCARD_E_INVALID_HANDLE,
            SmartCardErrorCode::InvalidHandle,
        );
        m.insert(
            pcsc_sys::SCARD_E_INVALID_PARAMETER,
            SmartCardErrorCode::InvalidParameter,
        );
        m.insert(
            pcsc_sys::SCARD_E_INVALID_TARGET,
            SmartCardErrorCode::InvalidTarget,
        );
        m.insert(
            pcsc_sys::SCARD_E_INVALID_VALUE,
            SmartCardErrorCode::InvalidValue,
        );
        m.insert(pcsc_sys::SCARD_E_NO_ACCESS, SmartCardErrorCode::NoAccess);
        m.insert(pcsc_sys::SCARD_E_NO_DIR, SmartCardErrorCode::NoDir);
        m.insert(pcsc_sys::SCARD_E_NO_FILE, SmartCardErrorCode::NoFile);
        m.insert(
            pcsc_sys::SCARD_E_NO_KEY_CONTAINER,
            SmartCardErrorCode::NoKeyContainer,
        );
        m.insert(pcsc_sys::SCARD_E_NO_MEMORY, SmartCardErrorCode::NoMemory);
        m.insert(0x80100033, SmartCardErrorCode::NoPinCache);
        m.insert(
            pcsc_sys::SCARD_E_NO_READERS_AVAILABLE,
            SmartCardErrorCode::NoReadersAvailable,
        );
        m.insert(pcsc_sys::SCARD_E_NO_SERVICE, SmartCardErrorCode::NoService);
        m.insert(
            pcsc_sys::SCARD_E_NO_SMARTCARD,
            SmartCardErrorCode::NoSmartCard,
        );
        m.insert(
            pcsc_sys::SCARD_E_NO_SUCH_CERTIFICATE,
            SmartCardErrorCode::NoSuchCertificate,
        );
        m.insert(pcsc_sys::SCARD_E_NOT_READY, SmartCardErrorCode::NotReady);
        m.insert(
            pcsc_sys::SCARD_E_NOT_TRANSACTED,
            SmartCardErrorCode::NotTransacted,
        );
        m.insert(
            pcsc_sys::SCARD_E_PCI_TOO_SMALL,
            SmartCardErrorCode::PciTooSmall,
        );
        m.insert(0x80100032, SmartCardErrorCode::PinCacheExpired);
        m.insert(
            pcsc_sys::SCARD_E_PROTO_MISMATCH,
            SmartCardErrorCode::ProtoMismatch,
        );
        m.insert(
            pcsc_sys::SCARD_E_READER_UNAVAILABLE,
            SmartCardErrorCode::ReaderUnavailable,
        );
        m.insert(
            pcsc_sys::SCARD_E_READER_UNSUPPORTED,
            SmartCardErrorCode::ReaderUnsupported,
        );
        m.insert(0x80100034, SmartCardErrorCode::ReadOnlyCard);
        m.insert(
            pcsc_sys::SCARD_W_REMOVED_CARD,
            SmartCardErrorCode::RemovedCard,
        );
        m.insert(pcsc_sys::SCARD_W_RESET_CARD, SmartCardErrorCode::ResetCard);
        m.insert(
            pcsc_sys::SCARD_W_SECURITY_VIOLATION,
            SmartCardErrorCode::SecurityViolation,
        );
        m.insert(
            pcsc_sys::SCARD_E_SERVER_TOO_BUSY,
            SmartCardErrorCode::ServerTooBusy,
        );
        m.insert(
            pcsc_sys::SCARD_E_SERVICE_STOPPED,
            SmartCardErrorCode::ServiceStopped,
        );
        m.insert(
            pcsc_sys::SCARD_E_SHARING_VIOLATION,
            SmartCardErrorCode::SharingViolation,
        );
        m.insert(pcsc_sys::SCARD_P_SHUTDOWN, SmartCardErrorCode::Shutdown);
        m.insert(
            pcsc_sys::SCARD_E_SYSTEM_CANCELLED,
            SmartCardErrorCode::SystemCancelled,
        );
        m.insert(pcsc_sys::SCARD_E_TIMEOUT, SmartCardErrorCode::Timeout);
        m.insert(pcsc_sys::SCARD_E_UNEXPECTED, SmartCardErrorCode::Unexpected);
        m.insert(
            pcsc_sys::SCARD_E_UNKNOWN_CARD,
            SmartCardErrorCode::UnknownCard,
        );
        m.insert(
            pcsc_sys::SCARD_F_UNKNOWN_ERROR,
            SmartCardErrorCode::UnknownError,
        );
        m.insert(
            pcsc_sys::SCARD_E_UNKNOWN_READER,
            SmartCardErrorCode::UnknownReader,
        );
        m.insert(
            pcsc_sys::SCARD_E_UNKNOWN_RES_MNG,
            SmartCardErrorCode::UnknownResMng,
        );
        m.insert(
            pcsc_sys::SCARD_W_UNPOWERED_CARD,
            SmartCardErrorCode::UnpoweredCard,
        );
        m.insert(
            pcsc_sys::SCARD_W_UNRESPONSIVE_CARD,
            SmartCardErrorCode::UnresponsiveCard,
        );
        m.insert(
            pcsc_sys::SCARD_W_UNSUPPORTED_CARD,
            SmartCardErrorCode::UnsupportedCard,
        );
        m.insert(
            pcsc_sys::SCARD_E_UNSUPPORTED_FEATURE,
            SmartCardErrorCode::UnsupportedFeature,
        );
        m.insert(
            pcsc_sys::SCARD_F_WAITED_TOO_LONG,
            SmartCardErrorCode::WaitedTooLong,
        );
        m.insert(
            pcsc_sys::SCARD_E_WRITE_TOO_MANY,
            SmartCardErrorCode::WriteTooMany,
        );
        m.insert(pcsc_sys::SCARD_W_WRONG_CHV, SmartCardErrorCode::WrongChv);
        m
    };
    static ref TO_SCARDERR_H_MAPPING: HashMap<SmartCardErrorCode, pcsc_sys::LONG> =
        FROM_SCARDERR_H_MAPPING
            .iter()
            .map(|pair| (pair.1.clone(), *pair.0))
            .collect();
}

impl SmartCardErrorCode {
    pub fn new(code: pcsc_sys::LONG) -> ::std::result::Result<(), SmartCardErrorCode> {
        match code {
            pcsc_sys::SCARD_S_SUCCESS => Ok(()),
            _ => {
                if let Some(e) = FROM_SCARDERR_H_MAPPING.get(&code) {
                    Err(e.clone())
                } else {
                    Err(SmartCardErrorCode::UnknownResMng)
                }
            }
        }
    }

    pub fn new_other(s: &str) -> Self {
        SmartCardErrorCode::Other(s.to_owned())
    }

    pub fn get_code(&self) -> pcsc_sys::LONG {
        match self {
            SmartCardErrorCode::Other(_) => pcsc_sys::SCARD_F_UNKNOWN_ERROR,
            _ => *TO_SCARDERR_H_MAPPING.get(self).unwrap(),
        }
    }

    pub fn get_message(&self) -> &str {
        match self {
            SmartCardErrorCode::BadSeek => {
                "An error occurred in setting the smart card file object pointer."
            }
            SmartCardErrorCode::BrokenPipe => concat!(
                "The client attempted a smart card operation in a remote session, such as a ",
                "client session running on a terminal server, and the operating system in use ",
                "does not support smart card redirection.",
            ),
            SmartCardErrorCode::CacheItemNotFound => {
                "The requested item could not be found in the cache."
            }
            SmartCardErrorCode::CacheItemStale => {
                "The requested cache item is too old and was deleted from the cache."
            }
            SmartCardErrorCode::CacheItemTooBig => {
                "The new cache item exceeds the maximum per-item size defined for the cache."
            }
            SmartCardErrorCode::Cancelled => "The action was canceled by an SCardCancel request.",
            SmartCardErrorCode::CancelledByUser => "The action was canceled by the user.",
            SmartCardErrorCode::CantDispose => {
                "The system could not dispose of the media in the requested manner."
            }
            SmartCardErrorCode::CardNotAuthenticated => "No PIN was presented to the smart card.",
            SmartCardErrorCode::CardUnsupported => {
                "The smart card does not meet minimal requirements for support."
            }
            SmartCardErrorCode::CertificateUnavailable => {
                "The requested certificate could not be obtained."
            }
            SmartCardErrorCode::ChvBlocked => {
                "The card can't be accessed because the max number of PIN attempts was reached."
            }
            SmartCardErrorCode::CommDataLost => {
                "A communications error with the smart card has been detected."
            }
            SmartCardErrorCode::CommError => "An internal communications error has been detected.",
            SmartCardErrorCode::DirNotFound => {
                "The specified directory does not exist in the smart card."
            }
            SmartCardErrorCode::DuplicateReader => {
                "The reader driver did not produce a unique reader name."
            }
            SmartCardErrorCode::Eof => "The end of the smart card file has been reached.",
            SmartCardErrorCode::FileNotFound => {
                "The specified file does not exist in the smart card."
            }
            SmartCardErrorCode::IccCreateOrder => {
                "The requested order of object creation is not supported."
            }
            SmartCardErrorCode::IccInstallation => {
                "No primary provider can be found for the smart card."
            }
            SmartCardErrorCode::InsufficientBuffer => {
                "The data buffer for returned data is too small for the returned data."
            }
            SmartCardErrorCode::InternalError => "An internal consistency check failed.",
            SmartCardErrorCode::InvalidAtr => {
                "An ATR string obtained from the registry is not a valid ATR string."
            }
            SmartCardErrorCode::InvalidChv => "The supplied PIN/PUK is incorrect.",
            SmartCardErrorCode::InvalidHandle => "The supplied handle was not valid.",
            SmartCardErrorCode::InvalidParameter => {
                "One or more of the supplied parameters could not be properly interpreted."
            }
            SmartCardErrorCode::InvalidTarget => {
                "Registry startup information is missing or not valid."
            }
            SmartCardErrorCode::InvalidValue => {
                "One or more of the supplied parameter values could not be properly interpreted."
            }
            SmartCardErrorCode::NoAccess => "Access is denied to the file.",
            SmartCardErrorCode::NoDir => {
                "The supplied path does not represent a smart card directory."
            }
            SmartCardErrorCode::NoFile => "The supplied path does not represent a smart card file.",
            SmartCardErrorCode::NoKeyContainer => {
                "The requested key container does not exist on the smart card."
            }
            SmartCardErrorCode::NoMemory => "Not enough memory available to complete this command.",
            SmartCardErrorCode::NoPinCache => "The smart card PIN cannot be cached.",
            SmartCardErrorCode::NoReadersAvailable => "No smart card reader is available.",
            SmartCardErrorCode::NoService => "The smart card resource manager is not running.",
            SmartCardErrorCode::NoSmartCard => {
                "The operation requires a smart card, but no card is currently in the device."
            }
            SmartCardErrorCode::NoSuchCertificate => "The requested certificate does not exist.",
            SmartCardErrorCode::NotReady => "The reader or card is not ready to accept commands.",
            SmartCardErrorCode::NotTransacted => {
                "An attempt was made to end a nonexistent transaction."
            }
            SmartCardErrorCode::Other(_) => "Other / unknown smart card error.",
            SmartCardErrorCode::PciTooSmall => "The PCI receive buffer was too small.",
            SmartCardErrorCode::PinCacheExpired => "The smart card PIN cache has expired.",
            SmartCardErrorCode::ProtoMismatch => {
                "The requested protocols are incompatible with the protocol currently in use."
            }
            SmartCardErrorCode::ReaderUnavailable => {
                "The specified reader is not currently available for use."
            }
            SmartCardErrorCode::ReaderUnsupported => {
                "The reader driver does not meet minimal requirements for support."
            }
            SmartCardErrorCode::ReadOnlyCard => {
                "The smart card is read-only and cannot be written to."
            }
            SmartCardErrorCode::RemovedCard => {
                "The smart card has been removed, so further communication is not possible."
            }
            SmartCardErrorCode::ResetCard => "The smart card was reset.",
            SmartCardErrorCode::SecurityViolation => {
                "Access was denied because of a security violation."
            }
            SmartCardErrorCode::ServerTooBusy => {
                "The smart card resource manager is too busy to complete this operation."
            }
            SmartCardErrorCode::ServiceStopped => "The smart card resource manager has shut down.",
            SmartCardErrorCode::SharingViolation => {
                "The smart card cannot be accessed because of other outstanding connections."
            }
            SmartCardErrorCode::Shutdown => {
                "The operation has been aborted to allow the server application to exit."
            }
            SmartCardErrorCode::SystemCancelled => {
                "The action was canceled by the system, presumably to log off or shut down."
            }
            SmartCardErrorCode::Timeout => "The user-specified time-out value has expired.",
            SmartCardErrorCode::Unexpected => "An unexpected card error has occurred.",
            SmartCardErrorCode::UnknownCard => "The specified smart card name is not recognized.",
            SmartCardErrorCode::UnknownError => {
                "An internal error has been detected, but the source is unknown."
            }
            SmartCardErrorCode::UnknownReader => "The specified reader name is not recognized.",
            SmartCardErrorCode::UnknownResMng => "An unrecognized error code was returned.",
            SmartCardErrorCode::UnpoweredCard => {
                "Power removed from the smart card, so further communication isn't possible."
            }
            SmartCardErrorCode::UnresponsiveCard => "The smart card is not responding to a reset.",
            SmartCardErrorCode::UnsupportedCard => {
                "The reader can't communicate with the card, due to ATR string config conflicts."
            }
            SmartCardErrorCode::UnsupportedFeature => {
                "This smart card does not support the requested feature."
            }
            SmartCardErrorCode::WaitedTooLong => "An internal consistency timer has expired.",
            SmartCardErrorCode::WriteTooMany => {
                "An attempt was made to write more data than would fit in the target object."
            }
            SmartCardErrorCode::WrongChv => {
                "The card cannot be accessed because the wrong PIN was presented."
            }
        }
    }
}

impl fmt::Display for SmartCardErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                SmartCardErrorCode::Other(message) => message.as_str(),
                _ => self.get_message(),
            }
        )
    }
}

impl fmt::Debug for SmartCardErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        write!(
            f,
            "{} {}",
            TO_SCARDERR_H_MAPPING.get(self).map_or_else(
                || "<unknown error code>".to_owned(),
                |e| format!("{:#x}", e)
            ),
            self
        )
    }
}

#[derive(Debug)]
pub struct SmartCardError {
    code: SmartCardErrorCode,
    _backtrace: Backtrace,
}

impl SmartCardError {
    pub fn new(code: pcsc_sys::LONG) -> ::std::result::Result<(), SmartCardError> {
        match SmartCardErrorCode::new(code) {
            Ok(_) => Ok(()),
            Err(c) => Err(SmartCardError {
                code: c,
                _backtrace: Backtrace::new(),
            }),
        }
    }

    pub fn new_other(s: &str) -> Self {
        SmartCardError {
            code: SmartCardErrorCode::Other(s.to_owned()),
            _backtrace: Backtrace::new(),
        }
    }

    pub fn get_code(&self) -> &SmartCardErrorCode {
        &self.code
    }

    pub fn get_raw_code(&self) -> pcsc_sys::LONG {
        self.code.get_code()
    }

    pub fn get_message(&self) -> &str {
        self.code.get_message()
    }
}

impl From<SmartCardErrorCode> for SmartCardError {
    fn from(code: SmartCardErrorCode) -> Self {
        SmartCardError {
            code: code,
            _backtrace: Backtrace::new(),
        }
    }
}

impl fmt::Display for SmartCardError {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        write!(f, "{}", self.code)
    }
}

impl std::error::Error for SmartCardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
