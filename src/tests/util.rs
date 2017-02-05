use util::*;

#[cfg_attr(rustfmt, rustfmt_skip)]
#[test]
fn test_url_encode() {
    let exp: &'static str =
        "%21%2A%27%28%29%3B%3A%40%26%3D%2B%24%2C%2F%3F%23%5B%5D\
         ABCDEFGHIJKLMNOPQRSTUVWXYZ\
         abcdefghijklmnopqrstuvwxyz\
         0123456789\
         -_.~";
    let org: &'static str =
        "!*'();:@&=+$,/?#[]\
         ABCDEFGHIJKLMNOPQRSTUVWXYZ\
         abcdefghijklmnopqrstuvwxyz\
         0123456789\
         -_.~";
    assert_eq!(exp, url_encode(org).as_str());
}
