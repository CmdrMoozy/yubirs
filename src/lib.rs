#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
extern crate regex;

pub mod error;
mod otp;

#[cfg(test)]
mod tests;
