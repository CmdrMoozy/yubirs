# yubirs

[![Build Status](https://travis-ci.org/CmdrMoozy/yubirs.svg?branch=master)](https://travis-ci.org/CmdrMoozy/yubirs)

A library for interacting with YubiKeys in Rust.

## Using Yubikeys on Linux

Here are some helpful resources on how to use the Yubikey:

- https://wiki.archlinux.org/index.php/Yubikey
- https://developers.yubico.com/OTP/
- https://developers.yubico.com/PIV/

In particular, a few pieces of setup are necessary in order to fully use the Yubikey. OTP mode generally works without any additional setup (since we only rely on the Yubikey's USB keyboard functionality), but for PIV / smartcard features some additional setup is needed.

### Arch Linux

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

### Gentoo Linux

The process on Gentoo is very similar:

```shell
# Install necessary packages.
emerge -av libu2f-host yubikey-manager pcsc-lite pcsc-tools ccid libusb-compat

# Add your user to the right group to be able to access the device. Replace
# $MY_USER with your username.
gpasswd -a $MY_USER pcscd plugdev usb

# Configure hotplugging by setting rc_hotplug="pcscd" in this file:
vim /etc/rc.conf

# Start pcscd, and configure it to start on boot.
rc-update add pcscd default
/etc/init.d/pcscd start
```

### polkit

If your system is configured to use polkit (for example, if you're running KDE), then you additionally need to modify polkit's rules to allow non-root users to access PC/SC devices. In `/usr/share/polkit-1/rules.d/02-pcsc.rules`:

```
polkit.addRule(function(action, subject) {
    if (action.id == "org.debian.pcsc-lite.access_card" &&
        subject.user == "< YOUR USER HERE >") {
            return polkit.Result.YES;
    }
});

polkit.addRule(function(action, subject) {
    if (action.id == "org.debian.pcsc-lite.access_pcsc" &&
        subject.user == "< YOUR USER HERE >") {
            return polkit.Result.YES;
    }
});
```

### Testing

To verify that everything is setup right, the following commands should both work and print out information about the Yubikey:

```shell
gpg --card-status
pcsc_scan
```

## Yubikey PIV Functionality

yubirs provides a command-line interface, piv-tool, as well as a high-level API for interacting with the Yubikey's PIV functionality. Many of the concepts used may be unfamiliar to those who don't have a lot of experience with the Yubikey. The [official upstream documentation](https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html) provides a good overview of the concepts involved.

## Development

This repository includes some extra Git configuration which makes development easier. To use this configuration, run `git config --local include.path ../.gitconfig` from the repository root. *NOTE*: including arbitrary Git configurations is a security vulnerability, so you should audit this custom configuration before including it.
