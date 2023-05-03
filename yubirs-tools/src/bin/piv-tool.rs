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

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use tracing_subscriber::{filter::LevelFilter, prelude::*, EnvFilter};
use yubirs::piv::id::{Algorithm, Key, Object, PinPolicy, TouchPolicy};
use yubirs::piv::pkey::{Format, PublicKey};
use yubirs::piv::*;

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
    use bdrck::cli::AbstractStream;

    if bdrck::cli::Stream::Stdout.isatty() {
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

fn list_readers(output_recording: Option<PathBuf>) -> Result<()> {
    let handle = new_handle(output_recording)?;
    let readers: Vec<String> = handle.list_readers()?;
    for reader in readers {
        println!("{}", reader);
    }
    Ok(())
}

fn get_version(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    println!("{}", handle.get_version()?);
    Ok(())
}

fn get_serial(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    println!("{}", handle.get_serial()?);
    Ok(())
}

fn change_pin(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    Ok(handle.change_pin(None, None)?)
}

fn unblock_pin(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    Ok(handle.unblock_pin(None, None)?)
}

fn change_puk(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    Ok(handle.change_puk(None, None)?)
}

fn reset(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    Ok(handle.reset()?)
}

fn force_reset(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    // This is a very destructive operation; confirm with the user first before
    // proceeding.
    if !bdrck::cli::continue_confirmation(
        bdrck::cli::Stream::Stdin,
        bdrck::cli::Stream::Stderr,
        "This will reset all PIV device data (certificates, ...) to factory defaults. ",
    )? {
        return Ok(());
    }

    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    Ok(handle.force_reset()?)
}

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

fn change_mgm_key(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    handle.set_management_key(None, None, false)?;
    Ok(())
}

fn set_chuid(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    handle.set_chuid(None)?;
    Ok(())
}

fn set_ccc(reader: String, output_recording: Option<PathBuf>) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    handle.set_ccc(None)?;
    Ok(())
}

fn read_object(reader: String, output_recording: Option<PathBuf>, object_id: Object) -> Result<()> {
    let mut handle = new_handle(output_recording)?;
    handle.connect(Some(&reader))?;
    let data = handle.read_object(object_id)?;
    print_data(data.as_slice(), false)?;
    Ok(())
}

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
        return Err(yubirs::error::Error::Internal(format!(
            "decryption test failed; decrypted result did not match original plaintext"
        ))
        .into());
    }
    println!("Success!");
    Ok(())
}

#[derive(Args)]
// Arguments common to all commands.
struct CommonArgs {
    #[arg(long)]
    /// Record interactions with the hardware, and write it to this file.
    output_recording: Option<PathBuf>,
}

#[derive(Args)]
// Arguments to select which PC/SC reader to use.
struct ReaderArgs {
    #[arg(short = 'r', long, default_value_t = DEFAULT_READER.to_string())]
    /// The PC/SC reader to use. Try list_readers for possible values. The first reader with
    /// the value given here as a substring is used.
    reader: String,
}

#[derive(Args)]
struct ObjectArgs {
    #[arg(short = 'o', long)]
    /// The human-readable ID of the object to read.
    object_id: Object,
}

#[derive(Args)]
struct SlotArgs {
    #[arg(short = 's', long)]
    /// The private key slot to operate on.
    slot: Key,
}

#[derive(Args)]
struct FormatArgs {
    #[arg(short = 'f', long, default_value_t = Format::Pem)]
    /// The format for the X.509 public key certificate written to stdout.
    format: Format,
}

#[derive(Args)]
struct PolicyArgs {
    #[arg(short = 'p', long, default_value_t = PinPolicy::Default)]
    /// The PIN verification policy to enforce on future key access.
    pin_policy: PinPolicy,

    #[arg(short = 't', long, default_value_t = TouchPolicy::Default)]
    /// The touch verification policy to enforce on future key access.
    touch_policy: TouchPolicy,
}

#[derive(Subcommand)]
enum Commands {
    /// List the available PC/SC readers.
    ListReaders {
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Retrieve the version number from the Yubikey.
    GetVersion {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Retrieve the serial number from the Yubikey.
    GetSerial {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Change the Yubikey's PIN, using the existing PIN.
    ChangePin {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Unblock the Yubikey's PIN using the PUK, after exhausting the tries allotted to enter a
    /// valid PIN.
    UnblockPin {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Change the Yubikey's PUK, using the existing PUK.
    ChangePuk {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Reset the Yubikey's PIN, PUK, and management key to unblock the PIN and PUK retry counters.
    Reset {
        #[command(flatten)]
        reader: ReaderArgs,

        #[arg(short = 'f', long)]
        /// Force the reset, by automatically invalidating the PIN and PUK retry counters.
        force: bool,

        #[command(flatten)]
        common: CommonArgs,
    },

    /// Set the PIN and PUK retry counters, and reset the PIN and PUK back to defaults.
    SetRetries {
        #[command(flatten)]
        reader: ReaderArgs,

        #[arg(long)]
        /// The number of retries to allow for the PIN.
        pin_retries: u8,

        #[arg(long)]
        /// The number of retries to allow for the PUK.
        puk_retries: u8,

        #[command(flatten)]
        common: CommonArgs,
    },

    /// Change the Yubikey's management key.
    ChangeMgmtKey {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Write a new Card Holder Unique Identifier (CHUID) to the Yubikey.
    SetChuid {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Write a new Card Capability Container (CCC) to the Yubikey.
    SetCcc {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Read the contents of a data object from the Yubikey.
    ReadObject {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        object: ObjectArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Write a data object to the Yubikey.
    WriteObject {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        object: ObjectArgs,

        #[arg(short = 'i', long)]
        /// The path to an input file, or a base64-encoded data string.
        input: String,

        #[arg(long)]
        /// The input is a base64-encoded string, instead of a path.
        base64: bool,

        #[command(flatten)]
        common: CommonArgs,
    },

    /// Generate a private key, store it on the device, and return the public key.
    Generate {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        slot: SlotArgs,
        #[command(flatten)]
        format: FormatArgs,

        #[arg(short = 'a', long)]
        /// The algorithm to use for key generation.
        algorithm: Algorithm,

        #[command(flatten)]
        policy: PolicyArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Import an existing private key, store it on the device, and return the public key.
    ImportKey {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        slot: SlotArgs,
        #[command(flatten)]
        format: FormatArgs,

        #[arg(short = 'i', long)]
        /// The input file containing the private key, in PEM format.
        input_file: PathBuf,

        #[arg(short = 'e', long)]
        /// The input key is encrypted and requires a passphrase to import.
        encrypted: bool,

        #[command(flatten)]
        policy: PolicyArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Attest that a given private key was generated by the hardware device.
    Attest {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        slot: SlotArgs,
        #[command(flatten)]
        format: FormatArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Read a public key certificate from the device.
    ReadCertificate {
        #[command(flatten)]
        reader: ReaderArgs,
        #[command(flatten)]
        slot: SlotArgs,
        #[command(flatten)]
        format: FormatArgs,
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Test encrypt / decrypt functionality with a keypair on the device.
    TestDecrypt {
        #[command(flatten)]
        reader: ReaderArgs,

        #[arg(short = 'i', long)]
        /// The input file containing the public key, in PEM format.
        input_file: PathBuf,

        #[command(flatten)]
        slot: SlotArgs,
        #[command(flatten)]
        common: CommonArgs,
    },
}

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(
                    if cfg!(debug_assertions) {
                        LevelFilter::DEBUG
                    } else {
                        LevelFilter::WARN
                    }
                    .into(),
                )
                .from_env()
                .unwrap(),
        )
        .init();

    yubirs::init()?;

    match Cli::parse().command {
        Commands::ListReaders { common } => list_readers(common.output_recording),
        Commands::GetVersion { reader, common } => {
            get_version(reader.reader, common.output_recording)
        }
        Commands::GetSerial { reader, common } => {
            get_serial(reader.reader, common.output_recording)
        }
        Commands::ChangePin { reader, common } => {
            change_pin(reader.reader, common.output_recording)
        }
        Commands::UnblockPin { reader, common } => {
            unblock_pin(reader.reader, common.output_recording)
        }
        Commands::ChangePuk { reader, common } => {
            change_puk(reader.reader, common.output_recording)
        }
        Commands::Reset {
            reader,
            force,
            common,
        } => match force {
            false => reset(reader.reader, common.output_recording),
            true => force_reset(reader.reader, common.output_recording),
        },
        Commands::SetRetries {
            reader,
            pin_retries,
            puk_retries,
            common,
        } => set_retries(
            reader.reader,
            common.output_recording,
            pin_retries,
            puk_retries,
        ),
        Commands::ChangeMgmtKey { reader, common } => {
            change_mgm_key(reader.reader, common.output_recording)
        }
        Commands::SetChuid { reader, common } => set_chuid(reader.reader, common.output_recording),
        Commands::SetCcc { reader, common } => set_ccc(reader.reader, common.output_recording),
        Commands::ReadObject {
            reader,
            object,
            common,
        } => read_object(reader.reader, common.output_recording, object.object_id),
        Commands::WriteObject {
            reader,
            object,
            input,
            base64,
            common,
        } => write_object(
            reader.reader,
            common.output_recording,
            object.object_id,
            input,
            base64,
        ),
        Commands::Generate {
            reader,
            slot,
            format,
            algorithm,
            policy,
            common,
        } => generate(
            reader.reader,
            common.output_recording,
            slot.slot,
            algorithm,
            policy.pin_policy,
            policy.touch_policy,
            format.format,
        ),
        Commands::ImportKey {
            reader,
            slot,
            format,
            input_file,
            encrypted,
            policy,
            common,
        } => import_key(
            reader.reader,
            common.output_recording,
            input_file,
            slot.slot,
            encrypted,
            policy.pin_policy,
            policy.touch_policy,
            format.format,
        ),
        Commands::Attest {
            reader,
            slot,
            format,
            common,
        } => attest(
            reader.reader,
            common.output_recording,
            slot.slot,
            format.format,
        ),
        Commands::ReadCertificate {
            reader,
            slot,
            format,
            common,
        } => read_certificate(
            reader.reader,
            common.output_recording,
            slot.slot,
            format.format,
        ),
        Commands::TestDecrypt {
            reader,
            input_file,
            slot,
            common,
        } => test_decrypt(
            reader.reader,
            common.output_recording,
            input_file,
            slot.slot,
        ),
    }
}
