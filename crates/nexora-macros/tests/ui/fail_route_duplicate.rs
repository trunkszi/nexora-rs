use nexora_macros::http_service;

struct Service;

#[http_service]
impl Service {
    #[route(method = "GET", path = "/items/{id}")]
    fn first(&mut self, _: &mut RequestContext, _: Request) -> Result<Response> {
        Ok(Response::ok("first"))
    }

    #[route(method = "GET", path = "/items/{other}")]
    fn second(&mut self, _: &mut RequestContext, _: Request) -> Result<Response> {
        Ok(Response::ok("second"))
    }
}

fn main() {}
