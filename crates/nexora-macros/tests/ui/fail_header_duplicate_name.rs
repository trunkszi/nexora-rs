use nexora_macros::HeaderMap;

#[derive(HeaderMap)]
struct Bad {
    #[header(name = "X-Token")]
    first: String,
    #[header(name = "x-token")]
    second: String,
}

fn main() {}
