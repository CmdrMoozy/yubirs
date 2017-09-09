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

use piv::*;
use yubico_piv_tool_sys as ykpiv;

#[test]
fn test_try_ykpiv() {
    assert!(try_ykpiv(ykpiv::YKPIV_OK).is_ok());
    assert!(try_ykpiv(ykpiv::YKPIV_MEMORY_ERROR).is_err());
}

#[test]
fn test_ykpiv_error() {
    assert_eq!(
        "YKPIV_OK (0): Successful return",
        Error::from(ykpiv::YKPIV_OK).to_string()
    );
    assert_eq!(
        "YKPIV_MEMORY_ERROR (-1): Error allocating memory",
        Error::from(ykpiv::YKPIV_MEMORY_ERROR).to_string()
    );

    assert_eq!(Error::from(ykpiv::YKPIV_OK), Error::from(ykpiv::YKPIV_OK));
    assert_ne!(
        Error::from(ykpiv::YKPIV_OK),
        Error::from(ykpiv::YKPIV_MEMORY_ERROR)
    );
    assert_eq!(
        Error::from(ykpiv::YKPIV_MEMORY_ERROR),
        Error::from(ykpiv::YKPIV_MEMORY_ERROR)
    );
}
