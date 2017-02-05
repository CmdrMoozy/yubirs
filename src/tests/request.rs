use otp::Otp;
use request::*;
use regex::Regex;

#[test]
fn test_success_percentage_display() {
    static TEST_CASES: &'static [(SuccessPercentage, &'static str)] =
        &[(SuccessPercentage::Fast, "fast"),
          (SuccessPercentage::Secure, "secure"),
          (SuccessPercentage::Percent(0), "0"),
          (SuccessPercentage::Percent(100), "100"),
          (SuccessPercentage::Percent(33), "33")];

    for test_case in TEST_CASES {
        assert_eq!(test_case.1, test_case.0.to_string());
    }
}

static TEST_NONCE: &'static str = "gPjfNhJFeeHZgfC9kKifggiWmIApziQ8XA4Vye1e";

lazy_static! {
    static ref VALID_NONCE_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9]{16,40}$").unwrap();
}

#[cfg_attr(rustfmt, rustfmt_skip)]
#[test]
fn test_request_construction() {
    let mut request = Request::new(
        "87".to_owned(),
        vec![
            0x7d, 0xdb, 0x1a, 0x7d, 0xfa, 0x9a, 0x7f,
            0x8b, 0xeb, 0x73, 0x6a, 0xb7, 0x71, 0xdb
        ],
        Otp::new("vvvvvvcucrlcietctckflvnncdgckubflugerlnr").unwrap(),
        true,
        Some(SuccessPercentage::Secure),
        Some(8));
    assert!(VALID_NONCE_REGEX.is_match(request.nonce.as_str()));
    request.nonce = TEST_NONCE.to_owned();
    assert_eq!("DCzYoErmGciW6hQUR%2FTtfRq97no%3D", request.get_signature());
    assert_eq!(
        request.to_string(),
        "h=DCzYoErmGciW6hQUR%2FTtfRq97no%3D&id=87&\
         nonce=gPjfNhJFeeHZgfC9kKifggiWmIApziQ8XA4Vye1e&\
         otp=vvvvvvcucrlcietctckflvnncdgckubflugerlnr&\
         sl=secure&\
         timeout=8&\
         timestamp=1");
}
