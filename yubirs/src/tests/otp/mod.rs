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

#[cfg(test)]
mod request;
#[cfg(test)]
mod result;
#[cfg(test)]
mod util;

use crate::otp::*;

#[cfg_attr(rustfmt, rustfmt_skip)]
#[test]
fn test_otp_parsing() {
    static TEST_CASES: &'static [(&'static str, &'static str, &'static str)] = &[
        (
            "ccccccbetgjevivbklihljgtbenbfrefccveiglnjfbc",
            "ccccccbetgje",
            "vivbklihljgtbenbfrefccveiglnjfbc"
        ),
        (
            "jjjjjjx.yih.kckxtncdnhiyx.bxup.ujjk.cinbhuxj",
            "ccccccbetgje",
            "vivbklihljgtbenbfrefccveiglnjfbc"
        ),
        (
            "CCCCCCBETGJEVIVBKLIHLJGTBENBFREFCCVEIGLNJFBC",
            "ccccccbetgje",
            "vivbklihljgtbenbfrefccveiglnjfbc"
        ),
        (
            "JJJJJJX.YIH.KCKXTNCDNHIYX.BXUP.UJJK.CINBHUXJ",
            "ccccccbetgje",
            "vivbklihljgtbenbfrefccveiglnjfbc"
        ),
    ];

    for test_case in TEST_CASES {
        let otp = Otp::new(test_case.0).unwrap();
        assert_eq!(otp.prefix, test_case.1);
        assert_eq!(otp.ciphertext, test_case.2);
        assert_eq!(otp.to_string(), format!("{}{}", otp.prefix, otp.ciphertext));
    }
}

#[test]
fn test_invalid_otp_parsing() {
    assert!(Otp::new("ccccccbetgjevivbklihljg_benbfrefccveiglnjfbc").is_err());
    assert!(Otp::new("jjjjjjx.yih.kckxtncdnhiyx.bxup.uj_k.cinbhuxj").is_err());
}
