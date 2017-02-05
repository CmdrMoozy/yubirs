use otp::Otp;
use result::*;

static TEST_API_KEY: &'static [u8] = &[0x7d, 0xdb, 0x1a, 0x7d, 0xfa, 0x9a, 0x7f, 0x8b, 0xeb, 0x73,
                                       0x6a, 0xb7, 0x71, 0xdb];
static TEST_OTP: &'static str = "vvvvvvcucrlcietctckflvnncdgckubflugerlnr";
static TEST_NONCE: &'static str = "gPjfNhJFeeHZgfC9kKifggiWmIApziQ8XA4Vye1e";

lazy_static! {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    static ref RESULT_CONSTRUCTION_TEST_CASES: Vec<(Vec<u8>, bool)> = vec![
        // Valid result.
        (vec![
            format!("otp={}", TEST_OTP),
            format!("nonce={}", TEST_NONCE),
            "h=yBTXdBJ0wMmdXxZ7aPqGU7rd0og=".to_owned(),
            "t=2017-02-05T03:16:19Z0302".to_owned(),
            "status=OK".to_owned(),
            "sl=100".to_owned(),
        ].join("\n").into_bytes(), true),

        // Invalid field name.
        (vec![
            format!("otp={}", TEST_OTP),
            format!("nonce={}", TEST_NONCE),
            "h=waUYX2BayANQT0W3lpDB3EzhFRs=".to_owned(),
            "t=2017-02-05T03:16:19Z0302".to_owned(),
            "istatus=OK".to_owned(),
            "foo=bar".to_owned(),
        ].join("\n").into_bytes(), false),

        // Missing required field.
        (vec![
            format!("otp={}", TEST_OTP),
            format!("nonce={}", TEST_NONCE),
            "h=waUYX2BayANQT0W3lpDB3EzhFRs=".to_owned(),
            "status=OK".to_owned(),
        ].join("\n").into_bytes(), false),

        // Invalid timestamp format.
        (vec![
            format!("otp={}", TEST_OTP),
            format!("nonce={}", TEST_NONCE),
            "h=waUYX2BayANQT0W3lpDB3EzhFRs=".to_owned(),
            "t=20170205T03:16:19Z0302".to_owned(),
            "status=OK".to_owned(),
        ].join("\n").into_bytes(), false),

        // OTP mismatch.
        (vec![
            "otp=foo".to_owned(),
            format!("nonce={}", TEST_NONCE),
            "h=waUYX2BayANQT0W3lpDB3EzhFRs=".to_owned(),
            "t=2017-02-05T03:16:19Z0302".to_owned(),
            "status=OK".to_owned(),
        ].join("\n").into_bytes(), false),

        // Nonce mismatch.
        (vec![
            format!("otp={}", TEST_OTP),
            "nonce=foo".to_owned(),
            "h=waUYX2BayANQT0W3lpDB3EzhFRs=".to_owned(),
            "t=2017-02-05T03:16:19Z0302".to_owned(),
            "status=OK".to_owned(),
        ].join("\n").into_bytes(), false),

        // Invalid status.
        (vec![
            format!("otp={}", TEST_OTP),
            format!("nonce={}", TEST_NONCE),
            "h=waUYX2BayANQT0W3lpDB3EzhFRs=".to_owned(),
            "t=2017-02-05T03:16:19Z0302".to_owned(),
            "status=FOOBAR".to_owned(),
        ].join("\n").into_bytes(), false),

        // Invalid success percent.
        (vec![
            format!("otp={}", TEST_OTP),
            format!("nonce={}", TEST_NONCE),
            "h=waUYX2BayANQT0W3lpDB3EzhFRs=".to_owned(),
            "t=2017-02-05T03:16:19Z0302".to_owned(),
            "status=OK".to_owned(),
            "sl=foo".to_owned(),
        ].join("\n").into_bytes(), false),

        // Signature mismatch.
        (vec![
            format!("otp={}", TEST_OTP),
            format!("nonce={}", TEST_NONCE),
            "h=waUYX2BayANQTTW3lpDB3EzhFRs=".to_owned(),
            "t=2017-02-05T03:16:19Z0302".to_owned(),
            "status=OK".to_owned(),
        ].join("\n").into_bytes(), false),
    ];
}

#[test]
fn test_result_construction() {
    for test_case in RESULT_CONSTRUCTION_TEST_CASES.iter() {
        let result = VerificationResult::new(TEST_API_KEY,
                                             &Otp::new(TEST_OTP).unwrap(),
                                             TEST_NONCE,
                                             test_case.0.clone());
        assert_eq!(test_case.1, result.is_ok());

        if let Ok(result) = result {
            assert!(result.is_valid());
            assert!(!result.is_retryable_error());
        }
    }
}
