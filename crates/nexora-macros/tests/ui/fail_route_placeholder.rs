use nexora_macros::http_service;

struct Service;

#[http_service]
impl Service {
    #[route(method = "GET", path = "/items/prefix-{id}")]
    fn items(&mut self, _: &mut RequestContext, _: Request) -> Result<Response> {
        Ok(Response::ok("items"))
    }
}

fn main() {}
