use curl::easy::Easy;

pub fn url_encode(s: &str) -> String {
    let mut easy = Easy::new();
    easy.url_encode(s.as_bytes())
}
