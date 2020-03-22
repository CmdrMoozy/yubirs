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

use crate::error::*;
use crate::piv::context::PcscHardwareContext;
use crate::piv::scarderr::{SmartCardError, SmartCardErrorCode};
use lazy_static::lazy_static;
use log::warn;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::{Arc, Mutex, Weak};

lazy_static! {
    static ref READER_REF_COUNTS: Mutex<HashMap<String, Weak<()>>> = Mutex::new(HashMap::new());
}

pub(crate) struct PcscHardwareConnection {
    reader: CString,
    card: pcsc_sys::SCARDHANDLE,
    refcount: Option<Arc<()>>,
}

impl PcscHardwareConnection {
    pub fn establish(context: &PcscHardwareContext, reader: &str) -> Result<Self> {
        let cstr_reader = CString::new(reader)?;
        // We want to acquire the lock first. Globally, we only want one connect
        // or disconnect happening at a time, so we can keep track of refcounts.
        let mut ref_counts = READER_REF_COUNTS.lock().unwrap();

        let mut card: pcsc_sys::SCARDHANDLE = 0;
        let mut active_protocol: pcsc_sys::DWORD = pcsc_sys::SCARD_PROTOCOL_UNDEFINED;

        let mut ret = SmartCardError::new(unsafe {
            pcsc_sys::SCardConnect(
                context.get(),
                cstr_reader.as_ptr(),
                pcsc_sys::SCARD_SHARE_SHARED,
                pcsc_sys::SCARD_PROTOCOL_T1,
                &mut card,
                &mut active_protocol,
            )
        });

        if ret
            .as_ref()
            .err()
            .map(|e| *e.get_code() == SmartCardErrorCode::ResetCard)
            .unwrap_or(false)
        {
            warn!("Card '{}' was unexpectedly reset; reconnecting", reader);
            ret = SmartCardError::new(unsafe {
                pcsc_sys::SCardReconnect(
                    card,
                    pcsc_sys::SCARD_SHARE_SHARED,
                    pcsc_sys::SCARD_PROTOCOL_T1,
                    pcsc_sys::SCARD_RESET_CARD,
                    &mut active_protocol,
                )
            });
        }

        ret?;

        let weak = ref_counts
            .entry(reader.to_string())
            .or_insert_with(Weak::new);
        let mut maybe_rc = weak.upgrade();
        if maybe_rc.is_none() {
            let rc = Arc::new(());
            *weak = Arc::downgrade(&rc);
            maybe_rc.replace(rc);
        }

        Ok(PcscHardwareConnection {
            reader: cstr_reader,
            card: card,
            // Call `unwrap` so we panic if there is no refcount. The logic
            // above guarantees this will never be the case.
            refcount: Some(maybe_rc.unwrap()),
        })
    }

    pub fn get(&self) -> pcsc_sys::SCARDHANDLE {
        self.card
    }
}

impl Drop for PcscHardwareConnection {
    fn drop(&mut self) {
        // Again, acquire the lock first, so we have exclusive control over the
        // refcount and connection.
        let mut ref_counts = READER_REF_COUNTS.lock().unwrap();

        // By default (if there are other connections), just leave the card, so
        // as not to interrupt others' usage of it.
        let mut disposition = pcsc_sys::SCARD_LEAVE_CARD;

        {
            let refcount = self.refcount.take().unwrap();
            // It's safe to use `strong_count`, because we hold the lock.
            if Arc::strong_count(&refcount) == 1 {
                // If we are the last connection, reset the card when we disconnect.
                // Also, remove this entry from the
                disposition = pcsc_sys::SCARD_RESET_CARD;

                // Clean up our entry in the refcount map. It's safe to unwrap() here,
                // because we know the reader is valid UTF-8 - it was a `&str` when it
                // was given to us in the first place.
                ref_counts.remove(self.reader.to_str().unwrap());
            }
        } // Drop the refcount instance.

        // Finally, disconnect.
        unsafe {
            pcsc_sys::SCardDisconnect(self.card, disposition);
        }
    }
}
