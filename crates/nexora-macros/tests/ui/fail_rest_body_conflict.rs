use nexora_macros::RestRequest;
#[derive(RestRequest)]
#[rest(method = "POST", path = "/items")]
struct Bad {
    #[body]
    first: Vec<u8>,
    #[body]
    second: Vec<u8>,
}
fn main() {}
