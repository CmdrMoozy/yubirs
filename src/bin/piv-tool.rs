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

extern crate bdrck;
extern crate data_encoding;
#[macro_use]
extern crate error_chain;
extern crate isatty;
extern crate yubirs;

use bdrck::flags::*;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use yubirs::error::*;
use yubirs::piv::*;
use yubirs::piv::id::{PinPolicy, TouchPolicy};
use yubirs::piv::pkey::Format;

fn new_handle(values: &Values) -> Result<Handle<PcscHardware>> {
    match values.get_single("output_recording") {
        None => Handle::new(),
        Some(output_recording) => Ok(Handle::new_with_hal(PcscHardware::new_with_recording(
            output_recording,
        )?)),
    }
}

// TODO: This function's (or callers') behavior is wrong for DER output.
fn print_data(data: &[u8], text: bool) -> Result<()> {
    if isatty::stdout_isatty() {
        if text {
            println!("{}", ::std::str::from_utf8(data)?);
        } else {
            println!("{}", data_encoding::BASE64.encode(data));
        }
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
        true => data_encoding::BASE64.decode(path.as_bytes())?,
    })
}

fn list_readers(values: Values) -> Result<()> {
    let handle = new_handle(&values)?;
    let readers: Vec<String> = handle.list_readers()?;
    for reader in readers {
        println!("{}", reader);
    }
    Ok(())
}

fn get_version(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    println!("{}", handle.get_version()?);
    Ok(())
}

fn change_pin(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    handle.change_pin(None, None)
}

fn unblock_pin(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    handle.unblock_pin(None, None)
}

fn change_puk(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    handle.change_puk(None, None)
}

fn reset(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    handle.reset()
}

fn set_retries(values: Values) -> Result<()> {
    let pin_retries: u8 = values.get_required_parsed("pin_retries")?;
    let puk_retries: u8 = values.get_required_parsed("puk_retries")?;
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    handle.set_retries(None, None, pin_retries, puk_retries)?;
    Ok(())
}

fn change_mgm_key(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    handle.set_management_key(None, None, false)?;
    Ok(())
}

fn set_chuid(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    handle.set_chuid(None)?;
    Ok(())
}

fn set_ccc(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    handle.set_ccc(None)?;
    Ok(())
}

fn read_object(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    let data = handle.read_object(values.get_required_parsed("object_id")?)?;
    print_data(data.as_slice(), false)?;
    Ok(())
}

fn write_object(values: Values) -> Result<()> {
    let data = read_data(values.get_required("input"), values.get_boolean("base64"))?;
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    handle.write_object(None, values.get_required_parsed("object_id")?, data)?;
    Ok(())
}

fn generate(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    let public_key = handle.generate(
        None,
        values.get_required_parsed("slot")?,
        values.get_required_parsed("algorithm")?,
        values.get_required_parsed("pin_policy")?,
        values.get_required_parsed("touch_policy")?,
    )?;
    print_data(
        public_key
            .format(values.get_required_parsed("format")?)?
            .as_slice(),
        true,
    )?;
    Ok(())
}

fn import_key(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    let public_key = handle.import_key(
        None,
        &values.get_required_as::<PathBuf>("input_file"),
        values.get_required_parsed("slot")?,
        values.get_boolean("encrypted"),
        None,
        values.get_required_parsed("pin_policy")?,
        values.get_required_parsed("touch_policy")?,
    )?;
    print_data(
        public_key
            .format(values.get_required_parsed("format")?)?
            .as_slice(),
        true,
    )?;
    Ok(())
}

fn attest(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    let cert = handle.attest(values.get_required_parsed("slot")?)?;
    print_data(
        cert.format(values.get_required_parsed("foramt")?)?
            .as_slice(),
        true,
    )?;
    Ok(())
}

fn read_certificate(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    let public_key_cert = handle.read_certificate(values.get_required_parsed("slot")?)?;
    print_data(
        public_key_cert
            .format(values.get_required_parsed("format")?)?
            .as_slice(),
        true,
    )?;
    Ok(())
}

fn test_decrypt(values: Values) -> Result<()> {
    let mut handle = new_handle(&values)?;
    handle.connect(Some(values.get_required("reader")))?;
    let mut plaintext: Vec<u8> = vec![0; 32];
    handle.get_hal().cheap_random_bytes(&mut plaintext)?;
    let (algorithm, ciphertext) = handle.encrypt(
        &values.get_required_as::<PathBuf>("input_file"),
        plaintext.as_slice(),
    )?;
    let result_plaintext = handle.decrypt(
        None,
        &ciphertext,
        values.get_required_parsed("slot")?,
        algorithm,
    )?;
    println!(
        "Original:  {}",
        plaintext
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "Encrypted: {}",
        ciphertext
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "Decrypted: {}",
        result_plaintext
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    if plaintext != result_plaintext {
        bail!("Decryption test failed; decrypted result did not match original plaintext");
    }
    println!("Success!");
    Ok(())
}

fn main() {
    let debug: bool = cfg!(debug_assertions);
    bdrck::logging::init(
        bdrck::logging::OptionsBuilder::new()
            .set_filters(match debug {
                false => "warn".parse().unwrap(),
                true => "debug".parse().unwrap(),
            })
            .set_panic_on_output_failure(debug)
            .set_always_flush(true)
            .build()
            .unwrap(),
    );
    yubirs::init().unwrap();

    main_impl_multiple_commands(vec![
        Command::new(
            "list_readers",
            "List the available PC/SC readers",
            Specs::new(vec![
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
            ]).unwrap(),
            Box::new(list_readers),
        ),
        Command::new(
            "get_version",
            "Retrieve the version number from the Yubikey",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
            ]).unwrap(),
            Box::new(get_version),
        ),
        Command::new(
            "change_pin",
            "Change the Yubikey's PIN, using the existing PIN",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
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
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
            ]).unwrap(),
            Box::new(unblock_pin),
        ),
        Command::new(
            "change_puk",
            "Change the Yubikey's PUK, using the existing PUK",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
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
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
            ]).unwrap(),
            Box::new(reset),
        ),
        Command::new(
            "set_retries",
            "Set the PIN and PUK retry counters, and reset the PIN and PUK back to defaults",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
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
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
            ]).unwrap(),
            Box::new(change_mgm_key),
        ),
        Command::new(
            "set_chuid",
            "Write a new Card Holder Unique Identifier (CHUID) to the Yubikey",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
            ]).unwrap(),
            Box::new(set_chuid),
        ),
        Command::new(
            "set_ccc",
            "Write a new Card Capability Container (CCC) to the Yubikey",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
            ]).unwrap(),
            Box::new(set_ccc),
        ),
        Command::new(
            "read_object",
            "Read the contents of a data object from the Yubikey",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
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
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
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
            "generate",
            "Generate a private key, store it on the device, and return the public key",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
                Spec::required(
                    "slot",
                    "The key slot to write the generated key to.",
                    Some('s'),
                    None,
                ),
                Spec::required(
                    "algorithm",
                    "The algorithm to use for key generation.",
                    Some('a'),
                    None,
                ),
                Spec::required(
                    "pin_policy",
                    "The PIN verification policy to enforce on future key access.",
                    Some('p'),
                    Some(PinPolicy::Default.to_string().as_str()),
                ),
                Spec::required(
                    "touch_policy",
                    "The touch verification policy to enforce on future key access.",
                    Some('t'),
                    Some(TouchPolicy::Default.to_string().as_str()),
                ),
                Spec::required(
                    "format",
                    "The format for the public key written to stdout.",
                    Some('f'),
                    Some(Format::Pem.to_string().as_str()),
                ),
            ]).unwrap(),
            Box::new(generate),
        ),
        Command::new(
            "import_key",
            "Import an existing private key, store it on the device, and return the public key",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
                Spec::required(
                    "input_file",
                    "The input file containing the private key, in PEM format.",
                    Some('i'),
                    None,
                ),
                Spec::required(
                    "slot",
                    "The key slot to write the imported key to.",
                    Some('s'),
                    None,
                ),
                Spec::boolean(
                    "encrypted",
                    "The input key is encrypted and requires a passphrase to import.",
                    Some('e'),
                ),
                Spec::required(
                    "pin_policy",
                    "The PIN verification policy to enforce on future key access.",
                    Some('p'),
                    Some(PinPolicy::Default.to_string().as_str()),
                ),
                Spec::required(
                    "touch_policy",
                    "The touch verification policy to enforce on future key access.",
                    Some('t'),
                    Some(TouchPolicy::Default.to_string().as_str()),
                ),
                Spec::required(
                    "format",
                    "The format for the public key written to stdout.",
                    Some('f'),
                    Some(Format::Pem.to_string().as_str()),
                ),
            ]).unwrap(),
            Box::new(import_key),
        ),
        Command::new(
            "attest",
            "Attest that a given private key was generated by the hardware device",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
                Spec::required(
                    "slot",
                    "The slot which contains the private key to attest.",
                    Some('s'),
                    None,
                ),
                Spec::required(
                    "format",
                    "The format for the X.509 public key certificate written to stdout.",
                    Some('f'),
                    Some(Format::Pem.to_string().as_str()),
                ),
            ]).unwrap(),
            Box::new(attest),
        ),
        Command::new(
            "read_certificate",
            "Read a public key certificate from the device",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
                Spec::required(
                    "slot",
                    "The key slot to read the public key certificate from.",
                    Some('s'),
                    None,
                ),
                Spec::required(
                    "format",
                    "The format for the public key certificate written to stdout.",
                    Some('f'),
                    Some(Format::Pem.to_string().as_str()),
                ),
            ]).unwrap(),
            Box::new(read_certificate),
        ),
        Command::new(
            "test_decrypt",
            "Test encrypt / decrypt functionality with a keypair on the device",
            Specs::new(vec![
                Spec::required(
                    "reader",
                    concat!(
                        "The PC/SC reader to use. Try list_readers for possible values. The first ",
                        "reader with the value given here as a substring is used.",
                    ),
                    Some('r'),
                    Some(DEFAULT_READER),
                ),
                Spec::optional(
                    "output_recording",
                    "Record interactions with the hardware, and write it to this file.",
                    None,
                ),
                Spec::required(
                    "input_file",
                    "The input file containing the public key, in PEM format.",
                    Some('i'),
                    None,
                ),
                Spec::required(
                    "slot",
                    "The slot which contains the private key to use for decryption.",
                    Some('s'),
                    None,
                ),
            ]).unwrap(),
            Box::new(test_decrypt),
        ),
    ]);
}
