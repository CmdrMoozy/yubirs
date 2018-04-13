# yubirs

[![Build Status](https://travis-ci.org/CmdrMoozy/yubirs.svg?branch=master)](https://travis-ci.org/CmdrMoozy/yubirs) [![Coverage Status](https://coveralls.io/repos/github/CmdrMoozy/yubirs/badge.svg?branch=master)](https://coveralls.io/github/CmdrMoozy/yubirs?branch=master)

A library for interacting with YubiKeys in Rust.

## Using Yubikeys on Linux

Here are some helpful resources on how to use the Yubikey:

- https://wiki.archlinux.org/index.php/Yubikey
- https://developers.yubico.com/OTP/
- https://developers.yubico.com/PIV/

In particular, a few pieces of setup are necessary in order to fully use the Yubikey. OTP mode generally works without any additional setup (since we only rely on the Yubikey's USB keyboard functionality), but for PIV / smartcard features some additional setup is needed. On Arch Linux, as an example, the following packages and services are needed:

- `libu2f-host` provides udev rules for using the Yubikey as a non-root user.
- `yubikey-manager` provides some utilities for managing the Yubikey.
- `pcsclite` is a dependency of yubirs; this is the PC/SC library we use to interact with the Yubikey programmatically.
- `pcsc-tools` provides some utilities for interacting with smartcards in general.
- `ccid` provides a generic USB Chip/Smart Card Interface Devices driver.
- `libusb-compat` provides a library for userspace applications to communicate with USB devices.

```shell
sudo pacman -S libu2f-host yubikey-manager pcsclite pcsc-tools ccid libusb-compat

# For pcsclite to work, we need to start the pcscd daemon.
sudo systemctl start pcscd.service
sudo systemctl enable pcscd.service
```

To verify that everything is setup right, the following commands should both work and print out information about the Yubikey:

```shell
gpg --card-status
pcsc_scan
```

## Yubikey PIV Functionality

yubirs provides a command-line interface, piv-tool, as well as a high-level API for interacting with the Yubikey's PIV functionality. Many of the concepts used may be unfamiliar to those who don't have a lot of experience with the Yubikey. The [official upstream documentation](https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html) provides a good overview of the concepts involved.

## Development

This repository includes some extra Git configuration which makes development easier. To use this configuration, run `git config --local include.path ../.gitconfig` from the repository root. *NOTE*: including arbitrary Git configurations is a security vulnerability, so you should audit this custom configuration before including it.
