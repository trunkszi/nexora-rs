use std::{cell::RefCell, rc::Rc};

use nexora::{HttpService, Request, RequestContext, Responder, Response};
use nexora_macros::http_service;

struct Router;
#[http_service]
impl Router {
    #[get("/users/{user}/items/{item}")]
    fn item(&mut self, ctx: &mut RequestContext, _: Request) -> nexora::Result<Response> {
        Ok(Response::ok(format!(
            "{}/{}",
            ctx.param("user").unwrap_or("missing"),
            ctx.param("item").unwrap_or("missing")
        )))
    }
    #[get("/health")]
    fn health(&mut self, ctx: &mut RequestContext, _: Request) -> nexora::Result<Response> {
        Ok(Response::ok(
            ctx.param("user").unwrap_or("empty").to_owned(),
        ))
    }
    #[post("/health")]
    fn update(&mut self, _: &mut RequestContext, _: Request) -> nexora::Result<Response> {
        Ok(Response::ok("updated"))
    }
}
#[test]
fn router_populates_named_path_parameters() -> Result<(), Box<dyn std::error::Error>> {
    let mut router = Router;
    let mut ctx = RequestContext::default();
    for (path, expected) in [
        ("/users/alice/items/book", "alice/book"),
        ("/health", "empty"),
    ] {
        let sink = Rc::new(RefCell::new(None));
        router.call(
            &mut ctx,
            Request::get(&format!("http://host{path}"))?,
            Responder::for_test(Rc::clone(&sink), true),
        )?;
        let response = sink.borrow_mut().take().ok_or("missing response")?;
        assert_eq!(response.body.as_slice(), expected.as_bytes());
    }
    Ok(())
}

#[test]
fn method_mismatch_lists_allowed_methods() -> Result<(), Box<dyn std::error::Error>> {
    let sink = Rc::new(RefCell::new(None));
    Router.call(
        &mut RequestContext::default(),
        Request::new(
            nexora::Method::Put,
            nexora::Uri::parse("http://host/health")?,
        ),
        Responder::for_test(Rc::clone(&sink), true),
    )?;
    let response = sink.borrow_mut().take().ok_or("missing response")?;
    assert_eq!(response.status.as_u16(), 405);
    let allowed = response.headers.get("allow").ok_or("405 omitted Allow")?;
    let mut methods: Vec<_> = allowed.split(',').map(str::trim).collect();
    methods.sort_unstable();
    assert_eq!(methods, ["GET", "POST"]);
    Ok(())
}
