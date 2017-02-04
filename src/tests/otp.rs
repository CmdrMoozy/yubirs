use otp::*;

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
    }
}

#[test]
fn test_invalid_otp_parsing() {
    assert!(Otp::new("ccccccbetgjevivbklihljg_benbfrefccveiglnjfbc").is_err());
    assert!(Otp::new("jjjjjjx.yih.kckxtncdnhiyx.bxup.uj_k.cinbhuxj").is_err());
}
