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
use libc::c_char;
use pcsc_sys;
use piv::DEFAULT_READER;
use piv::recording::Recording;
use piv::scarderr::SmartCardError;
use piv::sw::StatusWord;
use std::ffi::CString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;

/// The Application ID to send in an APDU when connecting to a Yubikey.
const APDU_AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

/// APDU stands for "smart card Application Protocol Data Unit". This union
/// definition is used by upstream's library to alternate between treating APDU
/// data in a structured or unstructured way.
#[derive(Clone, Copy)]
pub struct Apdu {
    pub raw: [u8; 230],
}

impl Apdu {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 230 {
            bail!("Invalid APDU data; expected 230 bytes, got {}", bytes.len());
        }
        let mut apdu = Apdu { raw: [0; 230] };
        for (dst, src) in apdu.raw.iter_mut().zip(bytes.iter()) {
            *dst = *src;
        }
        Ok(apdu)
    }

    pub fn from_pieces(cla: u8, ins: u8, p1: u8, p2: u8, lc: u8, data: &[u8]) -> Result<Self> {
        if data.len() != 255 {
            bail!("Invalid APDU data; expected 255 bytes, got {}", data.len());
        }
        let mut apdu = Apdu { raw: [0; 230] };
        apdu.raw[0] = cla;
        apdu.raw[1] = ins;
        apdu.raw[2] = p1;
        apdu.raw[3] = p2;
        apdu.raw[4] = lc;
        for (dst, src) in apdu.raw[5..].iter_mut().zip(data.iter()) {
            *dst = *src;
        }
        Ok(apdu)
    }

    /// Instruction class - indicates the type of command, e.g. interindustry or
    /// proprietary.
    pub fn cla(&self) -> u8 {
        self.raw[0]
    }

    /// Instruction code - indicates the specific command, e.g. "write data".
    pub fn ins(&self) -> u8 {
        self.raw[1]
    }

    /// First instruction parameter for the command, e.g. offset into file at
    /// which to write the data.
    pub fn p1(&self) -> u8 {
        self.raw[2]
    }

    /// Second instruction parameter for the command, e.g. offset into file at
    /// which to write the data.
    pub fn p2(&self) -> u8 {
        self.raw[3]
    }

    /// Encodes the number (N_c) of bytes of command data to follow. The
    /// official specification says that this field can be variable length, but
    /// upstream specifies it statically at 1 byte.
    pub fn lc(&self) -> u8 {
        self.raw[4]
    }

    /// The command data. The official specification says this can be up to
    /// 65535 bytes long, but upstream defines it as a static 255 bytes.
    pub fn data(&self) -> &[u8] {
        &self.raw[5..]
    }
}

impl fmt::Debug for Apdu {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Apdu {{ cla: {:02x}, ins: {:02x}, p1: {:02x}, p2: {:02x}, lc: {:02x}, data: [{}] }}",
            self.cla(),
            self.ins(),
            self.p1(),
            self.p2(),
            self.lc(),
            self.data()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }
}

pub trait PcscHal {
    /// Construct a new HAL, ready to connect to / interact with underlying
    /// hardware.
    fn new() -> Result<Self>
    where
        Self: ::std::marker::Sized;

    /// Return a list of the PC/SC readers currently available on the system.
    fn list_readers(&self) -> Result<Vec<String>>;

    /// Actually connect to the given reader using the native PC/SC library.
    /// This trait already provides the higher level `connect`, which handles
    /// selecting the right reader, and performing setup interactions with the
    /// device after connecting. This function simply wraps the real interaction
    /// with the underlying hardware.
    fn connect_impl(&mut self, reader: &str) -> Result<()>;

    /// Connect to the given reader (or the default reader, if none was
    /// specified). This must be called before e.g. data is sent or transactions
    /// are started.
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
            self.connect_impl(potential_reader.as_str())?;

            let mut data: [u8; 255] = [0; 255];
            for (dst, src) in data.iter_mut().zip(APDU_AID.iter()) {
                *dst = *src;
            }
            let apdu = Apdu::from_pieces(0, 0xa4, 0x04, 0, APDU_AID.len() as u8, &data)?;

            let (sw, _) = self.send_data_impl(&apdu.raw)?;
            sw.error?;

            return Ok(());
        }

        Err(SmartCardError::new(pcsc_sys::SCARD_E_UNKNOWN_READER)
            .err()
            .unwrap()
            .into())
    }

    /// Disconnect from the current reader, if any.
    fn disconnect(&mut self);

    /// Send data to the underlying hardware. The given byte slice must be formatted as a smart
    /// card APDU (https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit). This
    /// function should return a status word, as well as any bytes returned by the hardware.
    fn send_data_impl(&self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)>;

    /// Start a new PC/SC transaction with the underlying hardware.
    fn begin_transaction(&self) -> Result<()>;

    /// End a previously started PC/SC transaction with the underlying hardware.
    fn end_transaction(&self) -> Result<()>;

    /// A provided, higher-level interface for sending data to the underlying hardware.
    fn send_data(&self, templ: &[u8], data: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        self.begin_transaction()?;

        let mut out_data: Vec<u8> = Vec::new();
        let mut sw: StatusWord = StatusWord::success();
        // If the given data slice is empty, we still want to execute the first loop at least once,
        // sending the template by itself with no real data.
        let chunks: Vec<&[u8]> = match data.is_empty() {
            false => data.chunks(255).collect(),
            true => vec![&[]],
        };

        for chunk in chunks {
            let mut data: [u8; 255] = [0; 255];
            for (dst, src) in data.iter_mut().zip(chunk.iter()) {
                *dst = *src;
            }
            let apdu = Apdu::from_pieces(
                if chunk.len() == 255 {
                    0x10
                } else {
                    *templ.get(0).unwrap_or(&0)
                },
                *templ.get(1).unwrap_or(&0),
                *templ.get(2).unwrap_or(&0),
                *templ.get(3).unwrap_or(&0),
                chunk.len() as u8,
                &data,
            )?;

            debug!(
                "Sending chunk of {} out of {} total bytes",
                chunk.len(),
                data.len()
            );
            let (sw_new, mut recv) = self.send_data_impl(&apdu.raw)?;
            sw = sw_new;
            if sw.error.is_err() {
                return Ok((sw, out_data));
            }
            out_data.append(&mut recv);
        }

        while let Some(bytes_remaining) = sw.bytes_remaining {
            let apdu = Apdu::from_pieces(0, 0xc0, 0, 0, 0, &[0; 255])?;

            debug!(
                "The card indicates there are {} more bytes of data to read",
                bytes_remaining
            );
            let (sw_new, mut recv) = self.send_data_impl(&apdu.raw)?;
            sw = sw_new;
            if sw.error.is_err() {
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
    recording: Option<Mutex<Recording>>,
    output_recording: Option<PathBuf>,
}

impl PcscHardware {
    fn new_impl(
        recording: Option<Mutex<Recording>>,
        output_recording: Option<PathBuf>,
    ) -> Result<Self> {
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
            recording: recording,
            output_recording: output_recording,
        })
    }

    pub fn new_with_recording<P: AsRef<Path>>(output: P) -> Result<Self> {
        Self::new_impl(
            Some(Mutex::new(Recording::default())),
            Some(output.as_ref().to_path_buf()),
        )
    }

    fn send_data_impl_impl(&self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
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

        let sw = StatusWord::new(recv_buffer.as_slice(), recv_length as usize);
        recv_buffer.truncate(recv_length as usize - 2);
        Ok((sw, recv_buffer))
    }
}

impl PcscHal for PcscHardware {
    fn new() -> Result<Self> {
        Self::new_impl(None, None)
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

    fn connect_impl(&mut self, reader: &str) -> Result<()> {
        let reader = CString::new(reader)?;
        let mut active_protocol: pcsc_sys::DWORD = pcsc_sys::SCARD_PROTOCOL_UNDEFINED;
        SmartCardError::new(unsafe {
            pcsc_sys::SCardConnect(
                self.context,
                reader.as_ptr(),
                pcsc_sys::SCARD_SHARE_SHARED,
                pcsc_sys::SCARD_PROTOCOL_T1,
                &mut self.card,
                &mut active_protocol,
            )
        })?;
        Ok(())
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

    fn send_data_impl(&self, apdu: &[u8]) -> Result<(StatusWord, Vec<u8>)> {
        if let Some(recording) = self.recording.as_ref() {
            let mut lock = recording.lock().unwrap();
            let ret = self.send_data_impl_impl(apdu);
            lock.record(apdu, &ret);
            ret
        } else {
            self.send_data_impl_impl(apdu)
        }
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

impl Drop for PcscHardware {
    fn drop(&mut self) {
        if let Some(output_recording) = self.output_recording.as_ref() {
            // We want to write the recording to the given file. Note that we're
            // happy to panic if things go awry here, because this is purely a
            // debugging / testing feature anyway.
            self.recording
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .flush(output_recording)
                .unwrap();
        }
    }
}
