use nexora_macros::RestRequest;
#[derive(RestRequest)]
#[rest(method = "GET", path = "/items/{id}/{id}")]
struct Bad {
    #[path_param]
    id: String,
}
fn main() {}
