use nexora_macros::RestRequest;
#[derive(RestRequest)]
#[rest(method = "GET", path = "/items")]
struct Bad {
    #[path_param]
    id: String,
}
fn main() {}
