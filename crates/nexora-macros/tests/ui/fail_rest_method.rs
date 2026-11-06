use nexora_macros::RestRequest;
#[derive(RestRequest)]
#[rest(method = "FETCH", path = "/items")]
struct Bad {}
fn main() {}
