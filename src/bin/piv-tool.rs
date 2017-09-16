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

extern crate base64;
extern crate bdrck_log;
extern crate bdrck_params;
extern crate isatty;
extern crate yubirs;

use bdrck_params::command::{Command, ExecutableCommand};
use bdrck_params::main_impl::main_impl_multiple_commands;
use bdrck_params::option::Option;
use std::collections::HashMap;
use yubirs::error::*;
use yubirs::piv::state::{State, DEFAULT_READER};

fn print_data(data: &[u8]) -> Result<()> {
    if isatty::stdout_isatty() {
        println!("{}", base64::encode(data));
    } else {
        use std::io::Write;
        let mut stdout = ::std::io::stdout();
        stdout.write_all(data)?;
    }
    Ok(())
}

fn list_readers(
    _: HashMap<String, String>,
    flags: HashMap<String, bool>,
    _: HashMap<String, Vec<String>>,
) -> Result<()> {
    let state = State::new(flags.get("verbose").map_or(false, |v| *v))?;
    let readers: Vec<String> = state.list_readers()?;
    for reader in readers {
        println!("{}", reader);
    }
    Ok(())
}

fn get_version(
    options: HashMap<String, String>,
    flags: HashMap<String, bool>,
    _: HashMap<String, Vec<String>>,
) -> Result<()> {
    let mut state = State::new(flags.get("verbose").map_or(false, |v| *v))?;
    state.connect(Some(options.get("reader").unwrap().as_str()))?;
    println!("{}", state.get_version()?);
    Ok(())
}

fn change_pin(
    options: HashMap<String, String>,
    flags: HashMap<String, bool>,
    _: HashMap<String, Vec<String>>,
) -> Result<()> {
    let mut state = State::new(flags.get("verbose").map_or(false, |v| *v))?;
    state.connect(Some(options.get("reader").unwrap().as_str()))?;
    state.change_pin(None, None)
}

fn unblock_pin(
    options: HashMap<String, String>,
    flags: HashMap<String, bool>,
    _: HashMap<String, Vec<String>>,
) -> Result<()> {
    let mut state = State::new(flags.get("verbose").map_or(false, |v| *v))?;
    state.connect(Some(options.get("reader").unwrap().as_str()))?;
    state.unblock_pin(None, None)
}

fn change_puk(
    options: HashMap<String, String>,
    flags: HashMap<String, bool>,
    _: HashMap<String, Vec<String>>,
) -> Result<()> {
    let mut state = State::new(flags.get("verbose").map_or(false, |v| *v))?;
    state.connect(Some(options.get("reader").unwrap().as_str()))?;
    state.change_puk(None, None)
}

fn reset(
    options: HashMap<String, String>,
    flags: HashMap<String, bool>,
    _: HashMap<String, Vec<String>>,
) -> Result<()> {
    let mut state = State::new(flags.get("verbose").map_or(false, |v| *v))?;
    state.connect(Some(options.get("reader").unwrap().as_str()))?;
    state.reset()
}

fn read_object(
    options: HashMap<String, String>,
    flags: HashMap<String, bool>,
    _: HashMap<String, Vec<String>>,
) -> Result<()> {
    let mut state = State::new(flags.get("verbose").map_or(false, |v| *v))?;
    state.connect(Some(options.get("reader").unwrap().as_str()))?;
    let data = state.read_object(options.get("object_id").unwrap().parse()?)?;
    print_data(data.as_slice())?;
    Ok(())
}

fn set_retries(
    options: HashMap<String, String>,
    flags: HashMap<String, bool>,
    _: HashMap<String, Vec<String>>,
) -> Result<()> {
    let pin_retries = options.get("pin_retries").unwrap().parse::<u8>()?;
    let puk_retries = options.get("puk_retries").unwrap().parse::<u8>()?;
    let mut state = State::new(flags.get("verbose").map_or(false, |v| *v))?;
    state.connect(Some(options.get("reader").unwrap().as_str()))?;
    state.set_retries(None, None, pin_retries, puk_retries)?;
    Ok(())
}

fn change_mgm_key(
    options: HashMap<String, String>,
    flags: HashMap<String, bool>,
    _: HashMap<String, Vec<String>>,
) -> Result<()> {
    let mut state = State::new(flags.get("verbose").map_or(false, |v| *v))?;
    state.connect(Some(options.get("reader").unwrap().as_str()))?;
    state.set_management_key(None, None)?;
    Ok(())
}

fn set_chuid(
    options: HashMap<String, String>,
    flags: HashMap<String, bool>,
    _: HashMap<String, Vec<String>>,
) -> Result<()> {
    let mut state = State::new(flags.get("verbose").map_or(false, |v| *v))?;
    state.connect(Some(options.get("reader").unwrap().as_str()))?;
    state.set_chuid(None)?;
    Ok(())
}

fn set_ccc(
    options: HashMap<String, String>,
    flags: HashMap<String, bool>,
    _: HashMap<String, Vec<String>>,
) -> Result<()> {
    let mut state = State::new(flags.get("verbose").map_or(false, |v| *v))?;
    state.connect(Some(options.get("reader").unwrap().as_str()))?;
    state.set_ccc(None)?;
    Ok(())
}

fn main() {
    bdrck_log::init_cli_logger().unwrap();
    yubirs::init().unwrap();

    main_impl_multiple_commands(vec![
        ExecutableCommand::new(
            Command::new(
                "list_readers",
                "List the available PC/SC readers",
                vec![Option::flag("verbose", "Enable verbose output", Some('v'))],
                vec![],
                false,
            ).unwrap(),
            Box::new(list_readers),
        ),
        ExecutableCommand::new(
            Command::new(
                "get_version",
                "Retrieve the version number from the Yubikey",
                vec![
                    Option::flag("verbose", "Enable verbose output", Some('v')),
                    Option::required(
                        "reader",
                        "The PC/SC reader to use. Try list_readers for possible values. The first \
                         reader with the value given here as a substring is used.",
                        Some('r'),
                        Some(DEFAULT_READER),
                    ),
                ],
                vec![],
                false,
            ).unwrap(),
            Box::new(get_version),
        ),
        ExecutableCommand::new(
            Command::new(
                "change_pin",
                "Change the Yubikey's PIN, using the existing PIN",
                vec![
                    Option::flag("verbose", "Enable verbose output", Some('v')),
                    Option::required(
                        "reader",
                        "The PC/SC reader to use. Try list_readers for possible values. The first \
                         reader with the value given here as a substring is used.",
                        Some('r'),
                        Some(DEFAULT_READER),
                    ),
                ],
                vec![],
                false,
            ).unwrap(),
            Box::new(change_pin),
        ),
        ExecutableCommand::new(
            Command::new(
                "unblock_pin",
                "Unblock the Yubikey's PIN using the PUK, after exhausting the tries allotted to \
                 enter a valid PIN",
                vec![
                    Option::flag("verbose", "Enable verbose output", Some('v')),
                    Option::required(
                        "reader",
                        "The PC/SC reader to use. Try list_readers for possible values. The first \
                         reader with the value given here as a substring is used.",
                        Some('r'),
                        Some(DEFAULT_READER),
                    ),
                ],
                vec![],
                false,
            ).unwrap(),
            Box::new(unblock_pin),
        ),
        ExecutableCommand::new(
            Command::new(
                "change_puk",
                "Change the Yubikey's PUK, using the existing PUK",
                vec![
                    Option::flag("verbose", "Enable verbose output", Some('v')),
                    Option::required(
                        "reader",
                        "The PC/SC reader to use. Try list_readers for possible values. The first \
                         reader with the value given here as a substring is used.",
                        Some('r'),
                        Some(DEFAULT_READER),
                    ),
                ],
                vec![],
                false,
            ).unwrap(),
            Box::new(change_puk),
        ),
        ExecutableCommand::new(
            Command::new(
                "reset",
                "Reset the Yubikey's PIN, PUK, and management key to unblock the PIN and PUK retry \
                 counters",
                vec![
                    Option::flag("verbose", "Enable verbose output", Some('v')),
                    Option::required(
                        "reader",
                        "The PC/SC reader to use. Try list_readers for possible values. The first \
                         reader with the value given here as a substring is used.",
                        Some('r'),
                        Some(DEFAULT_READER),
                    ),
                ],
                vec![],
                false,
            ).unwrap(),
            Box::new(reset),
        ),
        ExecutableCommand::new(
            Command::new(
                "read_object",
                "Read the contents of a data object from the Yubikey",
                vec![
                    Option::flag("verbose", "Enable verbose output", Some('v')),
                    Option::required(
                        "reader",
                        "The PC/SC reader to use. Try list_readers for possible values. The first \
                         reader with the value given here as a substring is used.",
                        Some('r'),
                        Some(DEFAULT_READER),
                    ),
                    Option::required(
                        "object_id",
                        "The human-readable object ID of the object to read.",
                        Some('o'),
                        None,
                    ),
                ],
                vec![],
                false,
            ).unwrap(),
            Box::new(read_object),
        ),
        ExecutableCommand::new(
            Command::new(
                "set_retries",
                "Set the PIN and PUK retry counters, and reset the PIN and PUK back to defaults",
                vec![
                    Option::flag("verbose", "Enable verbose output", Some('v')),
                    Option::required(
                        "reader",
                        "The PC/SC reader to use. Try list_readers for possible values. The first \
                         reader with the value given here as a substring is used.",
                        Some('r'),
                        Some(DEFAULT_READER),
                    ),
                    Option::required(
                        "pin_retries",
                        "The number of retries to allow for the PIN.",
                        None,
                        None,
                    ),
                    Option::required(
                        "puk_retries",
                        "The number of retries to allow for the PUK.",
                        None,
                        None,
                    ),
                ],
                vec![],
                false,
            ).unwrap(),
            Box::new(set_retries),
        ),
        ExecutableCommand::new(
            Command::new(
                "change_mgm_key",
                "Change the Yubikey's management key",
                vec![
                    Option::flag("verbose", "Enable verbose output", Some('v')),
                    Option::required(
                        "reader",
                        "The PC/SC reader to use. Try list_readers for possible values. The first \
                         reader with the value given here as a substring is used.",
                        Some('r'),
                        Some(DEFAULT_READER),
                    ),
                ],
                vec![],
                false,
            ).unwrap(),
            Box::new(change_mgm_key),
        ),
        ExecutableCommand::new(
            Command::new(
                "set_chuid",
                "Write a new Card Holder Unique Identifier (CHUID) to the Yubikey",
                vec![
                    Option::flag("verbose", "Enable verbose output", Some('v')),
                    Option::required(
                        "reader",
                        "The PC/SC reader to use. Try list_readers for possible values. The first \
                         reader with the value given here as a substring is used.",
                        Some('r'),
                        Some(DEFAULT_READER),
                    ),
                ],
                vec![],
                false,
            ).unwrap(),
            Box::new(set_chuid),
        ),
        ExecutableCommand::new(
            Command::new(
                "set_ccc",
                "Write a new Card Capability Container (CCC) to the Yubikey",
                vec![
                    Option::flag("verbose", "Enable verbose output", Some('v')),
                    Option::required(
                        "reader",
                        "The PC/SC reader to use. Try list_readers for possible values. The first \
                         reader with the value given here as a substring is used.",
                        Some('r'),
                        Some(DEFAULT_READER),
                    ),
                ],
                vec![],
                false,
            ).unwrap(),
            Box::new(set_ccc),
        ),
    ]);
}
