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

use error::*;
use libc::{c_char, c_int};
use pcsc_sys;
use piv::DEFAULT_READER;
use piv::nid::*;
use piv::scarderr::SmartCardError;
use std::ffi::CString;
use std::ptr;

/// The Application ID to send in an APDU when connecting to a Yubikey.
const APDU_AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StructuredApdu {
    /// Instruction class - indicates the type of command, e.g. interindustry or
    /// proprietary.
    pub cla: u8,
    /// Instruction code - indicates the specific command, e.g. "write data".
    pub ins: u8,
    /// First instruction parameter for the command, e.g. offset into file at
    /// which to write the data.
    pub p1: u8,
    /// Second instruction parameter for the command, e.g. offset into file at
    /// which to write the data.
    pub p2: u8,
    /// Encodes the number (N_c) of bytes of command data to follow. The
    /// official specification says that this field can be variable length, but
    /// upstream specifies it statically at 1 byte.
    pub lc: u8,
    /// The command data. The official specification says this can be up to
    /// 65535 bytes long, but upstream defines it as a static 255 bytes.
    pub data: [u8; 255],
}

/// APDU stands for "smart card Application Protocol Data Unit". This union
/// definition is used by upstream's library to alternate between treating APDU
/// data in a structured or unstructured way.
#[repr(C)]
#[derive(Clone, Copy)]
pub union Apdu {
    pub st: StructuredApdu,
    pub raw: [u8; 230],
}

pub trait PcscHal {
    fn new() -> Result<Self>
    where
        Self: ::std::marker::Sized;

    fn list_readers(&self) -> Result<Vec<String>>;

    fn connect(&mut self, reader: Option<&str>) -> Result<()>;
    fn disconnect(&mut self);

    /// Send data to the underlying hardware. The given byte slice must be formatted as a smart
    /// card APDU (https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit). This
    /// function should return a status word, as well as any bytes returned by the hardware.
    fn send_data_impl(&self, apdu: &[u8]) -> Result<(c_int, Vec<u8>)>;

    fn begin_transaction(&self) -> Result<()>;
    fn end_transaction(&self) -> Result<()>;

    /// A provided, higher-level interface for sending data to the underlying hardware.
    fn send_data(&self, templ: &[u8], data: &[u8]) -> Result<(c_int, Vec<u8>)> {
        self.begin_transaction()?;

        let mut out_data: Vec<u8> = Vec::new();
        let mut sw: c_int = SW_SUCCESS;

        for chunk in data.chunks(255) {
            let mut data: [u8; 255] = [0; 255];
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
                data.len()
            );
            let (sw_new, mut recv) =
                self.send_data_impl(unsafe { &apdu.raw })?;
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
            let (sw_new, mut recv) =
                self.send_data_impl(unsafe { &apdu.raw })?;
            sw = sw_new;
            if sw != SW_SUCCESS && sw >> 8 != 0x61 {
                return Ok((sw, out_data));
            }
            let recv_len = recv.len() - 2;
            recv.truncate(recv_len);
            out_data.append(&mut recv);
        }

        self.end_transaction()?;
        Ok((sw, out_data))
    }
}

/// An implementation of PcscHal which actually talks to real hardware using the PC/SC library.
pub struct PcscHardware {
    context: pcsc_sys::SCARDCONTEXT,
    card: pcsc_sys::SCARDHANDLE,
}

impl PcscHal for PcscHardware {
    fn new() -> Result<Self> {
        let mut context: pcsc_sys::SCARDCONTEXT = pcsc_sys::SCARD_E_INVALID_HANDLE;
        SmartCardError::new(unsafe {
            pcsc_sys::SCardEstablishContext(
                pcsc_sys::SCARD_SCOPE_SYSTEM,
                ptr::null(),
                ptr::null(),
                &mut context,
            )
        })?;

        Ok(PcscHardware {
            context: context,
            card: 0,
        })
    }

    fn list_readers(&self) -> Result<Vec<String>> {
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

        let ret: ::std::result::Result<Vec<String>, ::std::str::Utf8Error> = buffer
            .split(|b| *b == 0)
            .filter_map(|slice| match slice.len() {
                0 => None,
                _ => Some(::std::str::from_utf8(slice).map(|s| s.to_owned())),
            })
            .collect();

        Ok(ret?)
    }

    fn connect(&mut self, reader: Option<&str>) -> Result<()> {
        let reader = reader.unwrap_or(DEFAULT_READER);
        let readers = self.list_readers()?;
        for potential_reader in readers {
            if !potential_reader.contains(reader) {
                info!(
                    "Skipping reader '{}' since it doesn't match '{}'",
                    potential_reader, reader
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

            let mut data: [u8; 255] = [0; 255];
            for (dst, src) in data.iter_mut().zip(APDU_AID.iter()) {
                *dst = *src;
            }
            let apdu = Apdu {
                st: StructuredApdu {
                    cla: 0,
                    ins: 0xa4,
                    p1: 0x04,
                    p2: 0,
                    lc: APDU_AID.len() as u8,
                    data: data,
                },
            };

            let (sw, _) =
                self.send_data_impl(unsafe { &apdu.raw })?;
            if sw != SW_SUCCESS {
                bail!("Failed selecting application: {:x}", sw);
            }

            return Ok(());
        }

        Err(SmartCardError::new(pcsc_sys::SCARD_E_UNKNOWN_READER)
            .err()
            .unwrap()
            .into())
    }

    fn disconnect(&mut self) {
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

    fn send_data_impl(&self, apdu: &[u8]) -> Result<(c_int, Vec<u8>)> {
        let send_len: pcsc_sys::DWORD = apdu[4] as pcsc_sys::DWORD + 5;
        debug!(
            "> {}",
            (&apdu[0..(send_len as usize)])
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        // Upstream uses a 261-byte buffer in all cases, even though this number seems mostly made
        // up. It seems like a sane default for now.
        let mut recv_buffer: Vec<u8> = vec![0; 261];
        let mut recv_length = recv_buffer.len() as pcsc_sys::DWORD;
        SmartCardError::new(unsafe {
            pcsc_sys::SCardTransmit(
                self.card,
                &pcsc_sys::g_rgSCardT1Pci,
                apdu.as_ptr(),
                send_len,
                ptr::null_mut(),
                recv_buffer.as_mut_ptr(),
                &mut recv_length,
            )
        })?;

        recv_buffer.truncate(recv_length as usize);
        debug!(
            "< {}",
            recv_buffer
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        let sw: c_int = if recv_buffer.len() >= 2 {
            ((recv_buffer[recv_length as usize - 2] as c_int) << 8)
                | (recv_buffer[recv_length as usize - 1] as c_int)
        } else {
            0
        };
        Ok((sw, recv_buffer))
    }

    fn begin_transaction(&self) -> Result<()> {
        SmartCardError::new(unsafe { pcsc_sys::SCardBeginTransaction(self.card) })?;
        Ok(())
    }

    fn end_transaction(&self) -> Result<()> {
        SmartCardError::new(unsafe {
            pcsc_sys::SCardEndTransaction(self.card, pcsc_sys::SCARD_LEAVE_CARD)
        })?;
        Ok(())
    }
}
