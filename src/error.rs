error_chain! {
    foreign_links {
        Curl(::curl::Error);
        Encoding(::data_encoding::decode::Error);
        Io(::std::io::Error);
        ParseDateTime(::chrono::ParseError);
        ParseInt(::std::num::ParseIntError);
        Utf8(::std::string::FromUtf8Error);
    }
}
