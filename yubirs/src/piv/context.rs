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
use crate::piv::scarderr::SmartCardError;
use std::cell::RefCell;
use std::ptr;
use std::rc::{Rc, Weak};

pub(crate) struct PcscHardwareContext {
    context: pcsc_sys::SCARDCONTEXT,
}

thread_local! {
    static CONTEXT_SINGLETON: RefCell<Weak<PcscHardwareContext>> = RefCell::new(Weak::new());
}

impl PcscHardwareContext {
    pub fn establish() -> Result<Rc<Self>> {
        Ok(
            CONTEXT_SINGLETON.try_with(|singleton| -> Result<Rc<PcscHardwareContext>> {
                let mut borrowed = singleton.try_borrow_mut()?;
                if let Some(context_ref) = borrowed.upgrade() {
                    return Ok(context_ref);
                }

                let mut context: pcsc_sys::SCARDCONTEXT = pcsc_sys::SCARD_E_INVALID_HANDLE;
                SmartCardError::new(unsafe {
                    pcsc_sys::SCardEstablishContext(
                        pcsc_sys::SCARD_SCOPE_SYSTEM,
                        ptr::null(),
                        ptr::null(),
                        &mut context,
                    )
                })?;

                let context_ref = Rc::new(PcscHardwareContext { context: context });
                *borrowed = Rc::downgrade(&context_ref);

                Ok(context_ref)
            })??,
        )
    }

    pub fn get(&self) -> pcsc_sys::SCARDCONTEXT {
        self.context
    }
}

impl Drop for PcscHardwareContext {
    fn drop(&mut self) {
        if unsafe { pcsc_sys::SCardIsValidContext(self.context) } == pcsc_sys::SCARD_S_SUCCESS {
            unsafe { pcsc_sys::SCardReleaseContext(self.context) };
        }
    }
}
