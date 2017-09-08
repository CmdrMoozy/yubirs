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

extern crate cmake;

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

const SUBMODULE_PATH: &'static str = "yubico-piv-tool";

macro_rules! t {
    ($e:expr) => (match $e {
        Ok(res) => res,
        Err(err) => panic!("{} failed with {}", stringify!($e), err),
    })
}

fn main() {
    if !Path::new(format!("{}/.git", SUBMODULE_PATH).as_str()).exists() {
        let _ = Command::new("git")
            .args(&["submodule", "update", "--init"])
            .status();
    }

    let mut cfg = cmake::Config::new(SUBMODULE_PATH);

    let _ = fs::remove_dir_all(env::var("OUT_DIR").unwrap());
    t!(fs::create_dir_all(env::var("OUT_DIR").unwrap()));

    // Unset DESTDIR or CMake incorrectly uses it.
    let dst = cfg.build();

    println!("cargo:rustc-link-lib=static=ykpiv");
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
}
