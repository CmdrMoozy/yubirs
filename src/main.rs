use std::collections::HashMap;

extern crate bdrck_log;
use bdrck_log::init_cli_logger;

extern crate bdrck_params;
use bdrck_params::command::{Command, ExecutableCommand};
use bdrck_params::main_impl::main_impl_single_command;
use bdrck_params::option::Option;

extern crate yubirs;
use yubirs::client::Client;
use yubirs::error::Result;

fn verify(options: HashMap<String, String>,
          _: HashMap<String, bool>,
          _: HashMap<String, Vec<String>>)
          -> Result<()> {
    try!(yubirs::init());
    let client = try!(Client::default(options.get("client_id").unwrap().as_str(),
                                      options.get("api_key").unwrap().as_str()));
    println!("{:?}", try!(client.verify_prompt()));
    Ok(())
}

fn main() {
    init_cli_logger().unwrap();
    main_impl_single_command(
        ExecutableCommand::new(
            Command::new(
                "verify",
                "Prompt for and verify a Yubikey OTP",
                vec![
                    Option::required("client_id", "The Yubico API client ID to use", None, None),
                    Option::required("api_key", "The Yubico API key to use", None, None),
                ],
                vec![],
                false).unwrap(),
            Box::new(verify)));
}
