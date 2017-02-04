error_chain! {
    foreign_links {
        Encoding(::data_encoding::decode::Error);
    }
}
