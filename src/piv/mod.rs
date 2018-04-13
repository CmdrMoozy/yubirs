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

pub mod apdu;
pub mod hal;
pub mod handle;
pub mod id;
mod nid;
pub mod pkey;
pub mod recording;
pub mod scarderr;
pub mod sw;
mod util;

/// The default reader string to use. The first reader (as returned by list_readers) which contains
/// this string as a substring is the one which will be used. So, this default will result in us
/// using the first connected Yubikey we find.
pub const DEFAULT_READER: &'static str = "Yubikey";

/// The default PIN code configured on YubiKeys from the factory.
pub const DEFAULT_PIN: &'static str = "123456";
/// The default PUK code configured on YubiKeys from the factory.
pub const DEFAULT_PUK: &'static str = "12345678";
/// The default 3DES management key (slot 9B) configured on YubiKeys from the factory.
pub const DEFAULT_MGM_KEY: &'static str = "010203040506070801020304050607080102030405060708";

pub use self::hal::{PcscHal, PcscHardware};
pub use self::handle::{Handle, Version};
