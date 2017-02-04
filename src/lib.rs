extern crate chrono;
extern crate curl;
extern crate data_encoding;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate rpassword;
extern crate sodiumoxide;

pub mod client;
pub mod error;
pub mod otp;
pub mod result;

#[cfg(test)]
mod tests;

/// Initializes Yubirs and any other underlying libraries. It is recommended to call this function
/// as soon as the program starts.
pub fn init() -> error::Result<()> {
    curl::init();
    if !sodiumoxide::init() {
        bail!("Initializing sodiumoxide library failed");
    }

    Ok(())
}
