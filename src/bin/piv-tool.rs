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
extern crate bdrck;
extern crate isatty;
extern crate yubirs;

use bdrck::flags::*;
use std::fs::File;
use std::io::Read;
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

fn read_data(path: &str, is_base64: bool) -> Result<Vec<u8>> {
    Ok(match is_base64 {
        false => {
            let mut buffer: Vec<u8> = Vec::new();
            let mut f = File::open(path)?;
            f.read_to_end(&mut buffer)?;
            buffer
        }
        true => base64::decode(path)?,
    })
}

fn list_readers(values: Values) -> Result<()> {
    let mut state = State::new(values.get_boolean("verbose"));
    let readers: Vec<String> = state.list_readers()?;
    for reader in readers {
        println!("{}", reader);
    }
    Ok(())
}

fn get_version(values: Values) -> Result<()> {
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    println!("{}", state.get_version()?);
    Ok(())
}

fn change_pin(values: Values) -> Result<()> {
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    state.change_pin(None, None)
}

fn unblock_pin(values: Values) -> Result<()> {
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    state.unblock_pin(None, None)
}

fn change_puk(values: Values) -> Result<()> {
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    state.change_puk(None, None)
}

fn reset(values: Values) -> Result<()> {
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    state.reset()
}

fn set_retries(values: Values) -> Result<()> {
    let pin_retries: u8 = values.get_required_parsed("pin_retries")?;
    let puk_retries: u8 = values.get_required_parsed("puk_retries")?;
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    state.set_retries(None, None, pin_retries, puk_retries)?;
    Ok(())
}

fn change_mgm_key(values: Values) -> Result<()> {
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    state.set_management_key(None, None)?;
    Ok(())
}

fn set_chuid(values: Values) -> Result<()> {
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    state.set_chuid(None)?;
    Ok(())
}

fn set_ccc(values: Values) -> Result<()> {
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    state.set_ccc(None)?;
    Ok(())
}

fn read_object(values: Values) -> Result<()> {
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    let data = state.read_object(values.get_required_parsed("object_id")?)?;
    print_data(data.as_slice())?;
    Ok(())
}

fn write_object(values: Values) -> Result<()> {
    let data = read_data(values.get_required("input"), values.get_boolean("base64"))?;
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    state.write_object(None, values.get_required_parsed("object_id")?, data)?;
    Ok(())
}

fn read_certificate(values: Values) -> Result<()> {
    let mut state = State::new(values.get_boolean("verbose"));
    state.connect(Some(values.get_required("reader")))?;
    println!(
        "{}",
        state.read_certificate(
            values.get_required_parsed("certificate_id")?,
            values.get_required_parsed("format")?
        )?
    );
    Ok(())
}

fn main() {
    bdrck::logging::init(None);
    yubirs::init().unwrap();

    main_impl_multiple_commands(vec![
        Command::new(
            "list_readers",
            "List the available PC/SC readers",
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
            ]).unwrap(),
            Box::new(list_readers),
        ),
        Command::new(
            "get_version",
            "Retrieve the version number from the Yubikey",
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
            ]).unwrap(),
            Box::new(get_version),
        ),
        Command::new(
            "change_pin",
            "Change the Yubikey's PIN, using the existing PIN",
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
            ]).unwrap(),
            Box::new(change_pin),
        ),
        Command::new(
            "unblock_pin",
            concat!(
                "Unblock the Yubikey's PIN using the PUK, after exhausting the tries allotted to ",
                "enter a valid PIN",
            ),
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
            ]).unwrap(),
            Box::new(unblock_pin),
        ),
        Command::new(
            "change_puk",
            "Change the Yubikey's PUK, using the existing PUK",
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
            ]).unwrap(),
            Box::new(change_puk),
        ),
        Command::new(
            "reset",
            concat!(
                "Reset the Yubikey's PIN, PUK, and management key to unblock the PIN and PUK ",
                "retry counters",
            ),
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
            ]).unwrap(),
            Box::new(reset),
        ),
        Command::new(
            "set_retries",
            "Set the PIN and PUK retry counters, and reset the PIN and PUK back to defaults",
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::required(
                    "pin_retries",
                    "The number of retries to allow for the PIN.",
                    None,
                    None,
                ),
                Spec::required(
                    "puk_retries",
                    "The number of retries to allow for the PUK.",
                    None,
                    None,
                ),
            ]).unwrap(),
            Box::new(set_retries),
        ),
        Command::new(
            "change_mgm_key",
            "Change the Yubikey's management key",
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
            ]).unwrap(),
            Box::new(change_mgm_key),
        ),
        Command::new(
            "set_chuid",
            "Write a new Card Holder Unique Identifier (CHUID) to the Yubikey",
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
            ]).unwrap(),
            Box::new(set_chuid),
        ),
        Command::new(
            "set_ccc",
            "Write a new Card Capability Container (CCC) to the Yubikey",
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
            ]).unwrap(),
            Box::new(set_ccc),
        ),
        Command::new(
            "read_object",
            "Read the contents of a data object from the Yubikey",
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::required(
                    "object_id",
                    "The human-readable ID of the object to read.",
                    Some('o'),
                    None,
                ),
            ]).unwrap(),
            Box::new(read_object),
        ),
        Command::new(
            "write_object",
            "Write a data object to the Yubikey",
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::required(
                    "object_id",
                    "The human-readable ID of the object to write.",
                    Some('o'),
                    None,
                ),
                Spec::required(
                    "input",
                    "The path to an input file, or a base64-encoded string.",
                    Some('i'),
                    None,
                ),
                Spec::boolean(
                    "base64",
                    "The input is a base64-encoded string, instead of a path.",
                    None,
                ),
            ]).unwrap(),
            Box::new(write_object),
        ),
        Command::new(
            "read_certificate",
            "Read a certificate from the Yubikey",
            Specs::new(vec![
                Spec::boolean("verbose", "Enable verbose output", Some('v')),
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::required(
                    "certificate_id",
                    "The human-readable ID of the certificate to read.",
                    Some('c'),
                    None,
                ),
                Spec::required(
                    "format",
                    "The output format to use.",
                    Some('f'),
                    Some("PEM"),
                ),
            ]).unwrap(),
            Box::new(read_certificate),
        ),
    ]);
}
