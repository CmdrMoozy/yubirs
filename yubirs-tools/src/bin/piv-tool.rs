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

use failure::format_err;
use flaggy::*;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use yubirs::piv::id::{Algorithm, Key, Object, PinPolicy, TouchPolicy};
use yubirs::piv::pkey::{Format, PublicKey};
use yubirs::piv::*;

struct Error(yubirs::error::Error);

impl From<yubirs::error::Error> for Error {
    fn from(e: yubirs::error::Error) -> Self {
        Error(e)
    }
}

impl From<bdrck::error::Error> for Error {
    fn from(e: bdrck::error::Error) -> Self {
        Error(e.into())
    }
}

impl From<data_encoding::DecodeError> for Error {
    fn from(e: data_encoding::DecodeError) -> Self {
        Error(e.into())
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(e: std::convert::Infallible) -> Self {
        Error(e.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.into())
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error(e.into())
    }
}

impl From<std::str::ParseBoolError> for Error {
    fn from(e: std::str::ParseBoolError) -> Self {
        Error(e.into())
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Error(e.into())
    }
}

impl From<ValueError> for Error {
    fn from(e: ValueError) -> Self {
        Error(yubirs::error::Error::CliFlags(format_err!("{}", e)))
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl failure::Fail for Error {}

type Result<T> = ::std::result::Result<T, Error>;

fn new_handle(output_recording: Option<PathBuf>) -> Result<Handle<PcscHardware>> {
    match output_recording {
        None => Ok(Handle::new()?),
        Some(output_recording) => Ok(Handle::new_with_hal(PcscHardware::new_with_recording(
            output_recording,
        )?)),
    }
}

// TODO: This function's (or callers') behavior is wrong for DER output.
fn print_data(data: &[u8], text: bool) -> Result<()> {
    if bdrck::cli::isatty(bdrck::cli::Stream::Stdout) {
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

#[command_callback]
fn list_readers(output_recording: Option<PathBuf>) -> Result<()> {
    let handle = new_handle(output_recording)?;
    let readers: Vec<String> = handle.list_readers()?;
    for reader in readers {
        println!("{}", reader);
    }
    Ok(())
}

#[command_callback]
fn get_version(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    println!("{}", handle.get_version()?);
    Ok(())
}

#[command_callback]
fn get_serial(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    println!("{}", handle.get_serial()?);
    Ok(())
}

#[command_callback]
fn change_pin(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    Ok(handle.change_pin(None, None)?)
}

#[command_callback]
fn unblock_pin(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    Ok(handle.unblock_pin(None, None)?)
}

#[command_callback]
fn change_puk(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    Ok(handle.change_puk(None, None)?)
}

#[command_callback]
fn reset(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    Ok(handle.reset()?)
}

#[command_callback]
fn force_reset(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    // This is a very destructive operation; confirm with the user first before
    // proceeding.
    if !bdrck::cli::continue_confirmation(
        bdrck::cli::Stream::Stderr,
        "This will reset all PIV device data (certificates, ...) to factory defaults. ",
    )? {
        return Ok(());
    }

    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    Ok(handle.force_reset()?)
}

#[command_callback]
fn set_retries(
    reader: String,
    output_recording: Option<PathBuf>,
    pin_retries: u8,
    puk_retries: u8,
) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    handle.set_retries(None, None, pin_retries, puk_retries)?;
    Ok(())
}

#[command_callback]
fn change_mgm_key(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    handle.set_management_key(None, None, false)?;
    Ok(())
}

#[command_callback]
fn set_chuid(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    handle.set_chuid(None)?;
    Ok(())
}

#[command_callback]
fn set_ccc(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    handle.set_ccc(None)?;
    Ok(())
}

#[command_callback]
fn read_object(reader: String, output_recording: Option<PathBuf>, object_id: Object) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    let data = handle.read_object(object_id)?;
    print_data(data.as_slice(), false)?;
    Ok(())
}

#[command_callback]
fn write_object(
    reader: String,
    output_recording: Option<PathBuf>,
    object_id: Object,
    input: String,
    base64: bool,
) -> Result<()> {
    let data = read_data(&input, base64)?;
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    handle.write_object(None, object_id, data)?;
    Ok(())
}

#[command_callback]
fn generate(
    reader: String,
    output_recording: Option<PathBuf>,
    slot: Key,
    algorithm: Algorithm,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    format: Format,
) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    let public_key = handle.generate(None, slot, algorithm, pin_policy, touch_policy)?;
    print_data(public_key.format(format)?.as_slice(), true)?;
    Ok(())
}

#[command_callback]
fn import_key(
    reader: String,
    output_recording: Option<PathBuf>,
    input_file: PathBuf,
    slot: Key,
    encrypted: bool,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    format: Format,
) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    let public_key = handle.import_key(
        None,
        &input_file,
        slot,
        encrypted,
        None,
        pin_policy,
        touch_policy,
    )?;
    print_data(public_key.format(format)?.as_slice(), true)?;
    Ok(())
}

#[command_callback]
fn attest(
    reader: String,
    output_recording: Option<PathBuf>,
    slot: Key,
    format: Format,
) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    let cert = handle.attest(slot)?;
    print_data(cert.format(format)?.as_slice(), true)?;
    Ok(())
}

#[command_callback]
fn read_certificate(
    reader: String,
    output_recording: Option<PathBuf>,
    slot: Key,
    format: Format,
) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    let public_key_cert = handle.read_certificate(slot)?;
    print_data(public_key_cert.format(format)?.as_slice(), true)?;
    Ok(())
}

#[command_callback]
fn test_decrypt(
    reader: String,
    output_recording: Option<PathBuf>,
    input_file: PathBuf,
    slot: Key,
) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    let mut plaintext: Vec<u8> = vec![0; 32];
    handle.get_hal().cheap_random_bytes(&mut plaintext)?;
    let public_key = PublicKey::from_pem_file(&input_file)?;
    let (algorithm, ciphertext) = handle.encrypt(&public_key, plaintext.as_slice())?;
    let result_plaintext = handle.decrypt(None, &ciphertext, slot, algorithm)?;
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
        return Err(yubirs::error::Error::Internal(format_err!(
            "Decryption test failed; decrypted result did not match original plaintext"
        ))
        .into());
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

    main_impl(vec![
        Command::new(
            "list_readers",
            "List the available PC/SC readers",
            Specs::new(vec![Spec::optional(
                "output_recording",
                "Record interactions with the hardware, and write it to this file.",
                None,
            )])
            .unwrap(),
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
            ])
            .unwrap(),
            Box::new(get_version),
        ),
        Command::new(
            "get_serial",
            "Retrieve the serial number from the Yubikey",
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
            ])
            .unwrap(),
            Box::new(get_serial),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
            Box::new(reset),
        ),
        Command::new(
            "force_reset",
            concat!(
                "The same as 'reset', but force it to happen by invalidating the PIN and PUK ",
                "retry counters.",
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
            ])
            .unwrap(),
            Box::new(force_reset),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
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
            ])
            .unwrap(),
            Box::new(test_decrypt),
        ),
    ]);
}
