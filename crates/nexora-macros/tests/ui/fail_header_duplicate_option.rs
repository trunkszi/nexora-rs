use nexora_macros::HeaderMap;

#[derive(HeaderMap)]
struct Bad {
    #[header(required, required)]
    value: String,
}

fn main() {}
