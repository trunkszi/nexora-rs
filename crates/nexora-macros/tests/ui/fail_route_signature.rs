use nexora_macros::http_service;
struct Service;
#[http_service]
impl Service {
    #[route(method = "GET", path = "/items")]
    fn items(&mut self) {}
}
fn main() {}
