use error::Result;
use regex::Regex;
use std::collections::HashMap;
use std::fmt;

lazy_static! {
    static ref DVORAK_OTP_RE: Regex = Regex::new(r"^[jxe.uidchtnbpygk]{32,48}$").unwrap();
    static ref QWERTY_OTP_RE: Regex = Regex::new(r"^[cbdefghijklnrtuv]{32,48}$").unwrap();

    static ref DVORAK_TO_QWERTY: HashMap<char, char> = {
        let mut m = HashMap::new();
		m.insert('j', 'c');
        m.insert('x', 'b');
        m.insert('e', 'd');
        m.insert('.', 'e');
        m.insert('u', 'f');
        m.insert('i', 'g');
        m.insert('d', 'h');
        m.insert('c', 'i');
		m.insert('h', 'j');
        m.insert('t', 'k');
        m.insert('n', 'l');
        m.insert('b', 'n');
        m.insert('p', 'r');
        m.insert('y', 't');
        m.insert('g', 'u');
        m.insert('k', 'v');
        m
    };
}

fn to_qwerty(otp: &str) -> Result<String> {
    let otp = otp.to_lowercase();
    if DVORAK_OTP_RE.is_match(otp.as_str()) {
        let otp: String = otp.chars().map(|c| *DVORAK_TO_QWERTY.get(&c).unwrap()).collect();
        Ok(otp)
    } else if QWERTY_OTP_RE.is_match(otp.as_str()) {
        Ok(otp.to_owned())
    } else {
        bail!("'{}' is not a valid Yubikey OTP. It is the wrong length or contains invalid \
               characters.",
              otp);
    }
}

/// Otp is a structure which represents a YubiKey OTP in a standard format, used throughout yubirs.
#[derive(Clone, Debug)]
pub struct Otp {
    pub prefix: String,
    pub ciphertext: String,
}

impl Otp {
    /// Construct a new Otp structure from the given raw OTP string. Since YubiKeys act as USB
    /// keyboard devices, the output from a "touch" is different depending on the system's keyboard
    /// layout. Either QWERTY or DVORAK versions of OTPs are accepted.
    pub fn new(otp: &str) -> Result<Otp> {
        let otp = try!(to_qwerty(otp));
        Ok(Otp {
            prefix: otp[0..(otp.len() - 32)].to_owned(),
            ciphertext: otp[(otp.len() - 32)..].to_owned(),
        })
    }
}

impl fmt::Display for Otp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", self.prefix, self.ciphertext)
    }
}
