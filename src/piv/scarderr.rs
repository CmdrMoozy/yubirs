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

use pcsc_sys;
use std::collections::HashMap;
use std::fmt;

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
    pub fn new(code: pcsc_sys::LONG) -> ::std::result::Result<(), SmartCardError> {
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

impl ::std::error::Error for SmartCardError {
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
            SmartCardError::InvalidChv => "The supplied PIN/PUK is incorrect.",
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
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        use std::error::Error;
        write!(f, "{}", self.description())
    }
}

impl fmt::Debug for SmartCardError {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        write!(
            f,
            "{:#x} {}",
            TO_SCARDERR_H_MAPPING.get(self).unwrap(),
            self
        )
    }
}
