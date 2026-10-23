use nexora_macros::HeaderMap;
#[derive(HeaderMap)]
struct Bad {
    #[header(name = "bad:name")]
    value: String,
}
fn main() {}
