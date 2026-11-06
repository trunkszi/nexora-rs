use nexora_macros::RestRequest;
#[derive(RestRequest)]
#[rest(method = "GET", path = "/items/{id}")]
struct Bad {
    #[query]
    id: String,
}
fn main() {}
