//! Compile-only proof of canonical and shorthand route signatures.

extern crate self as nexora;

#[path = "support/runtime.rs"]
mod runtime;
use nexora_macros::http_service;
use nexora_proto::{Request, Response};
pub use runtime::*;

struct Service<T>(T);

#[http_service]
impl<T: Clone> Service<T> {
    #[route(method = "GET", path = "/items/{id}")]
    fn immediate(&mut self, _: &mut RequestContext, _: Request) -> Result<Response> {
        Ok(Response::ok("immediate"))
    }

    #[route(method = "POST", path = "/items")]
    fn deferred(&mut self, _: &mut RequestContext, _: Request, responder: Responder) -> Result<()> {
        responder.respond(Response::ok("deferred"))
    }

    #[get("/get")]
    #[post("/post")]
    #[put("/put")]
    #[delete("/delete")]
    #[head("/head")]
    #[options("/options")]
    #[patch("/patch")]
    #[connect("/connect")]
    #[trace("/trace")]
    fn aliases(&mut self, _: &mut RequestContext, _: Request) -> Result<Response> {
        Ok(Response::ok("aliases"))
    }
}

fn accepts_service<T: HttpService>() {}

fn main() {
    accepts_service::<Service<()>>();
}
