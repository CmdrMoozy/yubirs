error_chain! {
    foreign_links {
        Curl(::curl::Error);
        Encoding(::data_encoding::decode::Error);
        Io(::std::io::Error);
    }
}
