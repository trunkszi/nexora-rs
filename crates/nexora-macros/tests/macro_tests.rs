//! Public macro, SDK dispatch, and Sans-IO tests without kernel networking.

use nexora_macros::{HeaderMap, RestRequest, headers, http2_headers};
use nexora_proto::{HeaderMapExt, Headers, Method, ProtoError};

#[derive(Debug, PartialEq, HeaderMap)]
struct Credentials {
    #[header(name = "authorization", required)]
    token: String,
    #[header(name = "x-retries", default = "3")]
    retries: u16,
    #[header(name = "x-trace")]
    trace: Option<String>,
}

#[derive(RestRequest)]
#[rest(method = "POST", path = "/v1/orders/{id}")]
struct Order {
    #[path_param]
    id: String,
    #[query(name = "search")]
    search: String,
    #[query]
    cursor: Option<u64>,
    #[header(name = "authorization")]
    token: String,
    #[body]
    payload: Vec<u8>,
}

mod integration_tests {
    use super::*;

    #[test]
    fn header_literals_and_typed_headers_share_the_protocol_boundary() -> nexora_proto::Result<()> {
        let values = headers! { "Authorization" => "Bearer abc", "x-trace" => "span-1" };
        let typed = Credentials::from_headers(&values)?;
        assert_eq!(typed.token, "Bearer abc");
        assert_eq!(typed.retries, 3);
        assert_eq!(typed.trace.as_deref(), Some("span-1"));
        assert_eq!(typed.to_headers().get("x-retries"), Some("3"));
        assert_eq!(
            http2_headers! { ":method" => "GET", ":path" => "/v1/ping" },
            vec![
                (String::from(":method"), String::from("GET")),
                (String::from(":path"), String::from("/v1/ping"))
            ]
        );
        Ok(())
    }

    #[test]
    fn malformed_numeric_headers_and_missing_required_headers_are_distinct() {
        assert!(matches!(Credentials::from_headers(&Headers::new()),
            Err(ProtoError::MissingHeader(name)) if name == "authorization"));
        let values = headers! { "authorization" => "abc", "x-retries" => "many" };
        assert!(matches!(
            Credentials::from_headers(&values),
            Err(ProtoError::InvalidHeader(_))
        ));
    }

    #[test]
    fn empty_literal_collections_have_concrete_types() {
        let values = headers! {};
        let pairs = http2_headers! {};
        assert!(values.is_empty());
        assert!(pairs.is_empty());
    }

    mod scalar {
        #[derive(Debug, PartialEq)]
        pub struct Option<T>(pub T);
        impl<T: std::fmt::Display> std::fmt::Display for Option<T> {
            fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(out)
            }
        }
        impl<T: std::str::FromStr> std::str::FromStr for Option<T> {
            type Err = T::Err;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                value.parse().map(Self)
            }
        }
    }

    #[test]
    fn custom_option_scalar_and_qualified_optional_headers_preserve_contracts()
    -> nexora_proto::Result<()> {
        #[derive(HeaderMap)]
        struct Mapped {
            #[header(name = "x-scalar")]
            scalar: scalar::Option<u16>,
            #[header(name = "x-optional")]
            optional: core::option::Option<u16>,
            #[header(name = "x-default", default = "7")]
            defaulted: std::option::Option<u16>,
        }
        let mut source = headers! { "x-scalar" => "12" };
        let first = Mapped::from_headers(&source)?;
        assert_eq!(first.scalar, scalar::Option(12));
        assert_eq!(first.optional, None);
        assert_eq!(first.defaulted, Some(7));
        assert!(!first.to_headers().contains("x-optional"));
        source.insert("x-optional", "4");
        assert_eq!(Mapped::from_headers(&source)?.optional, Some(4));
        #[derive(RestRequest)]
        #[rest(method = "GET", path = "/query")]
        struct Query {
            #[query]
            value: scalar::Option<u16>,
        }
        assert_eq!(
            Query {
                value: scalar::Option(12)
            }
            .build_path_and_query(),
            "/query?value=12"
        );
        source.remove("x-scalar");
        assert!(
            matches!(Mapped::from_headers(&source), Err(ProtoError::MissingHeader(name)) if name == "x-scalar")
        );
        Ok(())
    }

    #[test]
    #[allow(non_upper_case_globals)]
    fn header_bindings_do_not_collide_with_const_generic_names() -> nexora_proto::Result<()> {
        #[derive(HeaderMap)]
        struct Named<
            const r#__nexora_headers: usize,
            const __nexora_value: usize,
            const r#value: usize,
        > {
            field: String,
        }
        let input = headers! { "field" => "retained" };
        let mapped = Named::<1, 2, 3>::from_headers(&input)?;
        assert_eq!(mapped.field, "retained");
        assert_eq!(mapped.to_headers(), input);
        Ok(())
    }

    #[test]
    #[allow(non_upper_case_globals)]
    fn request_bindings_do_not_collide_with_const_generic_names() -> nexora_proto::Result<()> {
        #[derive(RestRequest)]
        #[rest(method = "GET", path = "/items/{id}")]
        struct Named<
            const r#base_url: usize,
            const r#__nexora_path: usize,
            const __nexora_value: usize,
        > {
            #[path_param]
            id: u64,
        }
        let request = Named::<1, 2, 3> { id: 17 }.into_request("http://localhost")?;
        assert_eq!(request.uri.path(), "/items/17");
        Ok(())
    }

    #[test]
    fn json_body_is_serialized_and_sets_the_content_type() -> nexora_proto::Result<()> {
        #[derive(RestRequest)]
        #[rest(method = "POST", path = "/items")]
        struct Create {
            #[json_body]
            body: sonic_rs::Value,
        }
        let create = Create {
            body: sonic_rs::json!({"quantity": 7}),
        };
        let request = create.into_request("https://example.test")?;
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.body.as_ref(), br#"{"quantity":7}"#);
        Ok(())
    }
}

mod e2e_tests {
    use nexora_proto::{BytesMut, Http1ClientCodec, Http1ServerCodec};

    use super::*;

    #[test]
    fn typed_request_round_trips_through_real_http1_codecs() -> nexora_proto::Result<()> {
        let order = Order {
            id: String::from("alpha/beta"),
            search: String::from("a+b &c"),
            cursor: Some(9),
            token: String::from("Bearer abc"),
            payload: br#"{"quantity":7}"#.to_vec(),
        };
        let request = order.into_request("http://localhost:8080/")?;
        assert_eq!(request.method, Method::Post);
        assert_eq!(
            request.uri.path_and_query(),
            "/v1/orders/alpha%2Fbeta?search=a%2Bb%20%26c&cursor=9"
        );
        let mut wire = BytesMut::new();
        Http1ClientCodec::default().encode_request(&request, &mut wire)?;
        let decoded = Http1ServerCodec::default().decode_request(&mut wire)?;
        let Some((decoded, _)) = decoded else {
            panic!("complete encoded request was not decoded")
        };
        assert_eq!(decoded.body.as_ref(), br#"{"quantity":7}"#);
        assert_eq!(decoded.header("authorization"), Some("Bearer abc"));
        assert_eq!(Credentials::from_headers(&decoded.headers)?.retries, 3);
        assert!(wire.is_empty());
        Ok(())
    }
}

mod lifecycle_tests {
    use super::*;

    #[test]
    fn borrowed_builder_and_short_lived_base_url_produce_an_owned_request()
    -> nexora_proto::Result<()> {
        #[derive(RestRequest)]
        #[rest(method = "POST", path = "/items/{id}")]
        struct Borrowed<'a> {
            #[path_param]
            id: &'a str,
            #[body]
            payload: &'a [u8],
        }
        let item = String::from("abc");
        let payload = vec![7, 8, 9];
        let borrowed = Borrowed {
            id: &item,
            payload: &payload,
        };
        let request = {
            let base = String::from("http://localhost");
            borrowed.into_request(&base)?
        };
        assert_eq!(request.uri.path(), "/items/abc");
        assert_eq!(request.body.as_ref(), &[7, 8, 9]);
        Ok(())
    }

    #[test]
    fn generated_requests_own_their_bytes_after_the_builder_is_dropped() -> nexora_proto::Result<()>
    {
        let request = {
            let order = Order {
                id: String::from("7"),
                search: String::new(),
                cursor: None,
                token: String::from("original"),
                payload: vec![0, 1, 255],
            };
            order.into_request("https://example.test")?
        };
        assert_eq!(request.body.as_ref(), &[0, 1, 255]);
        assert_eq!(request.header("authorization"), Some("original"));
        Ok(())
    }

    #[test]
    fn typed_header_conversion_preserves_source_ownership_and_optional_omission()
    -> nexora_proto::Result<()> {
        let source = Credentials {
            token: String::from("abc"),
            retries: 7,
            trace: None,
        };
        let values = source.to_headers();
        assert!(!values.contains("x-trace"));
        let recovered = Credentials::from_headers(&values)?;
        assert_eq!(source, recovered);
        assert_eq!(source.token, "abc");
        Ok(())
    }
}

mod scenario_tests {
    use super::*;

    #[test]
    fn reserved_delimiters_and_utf8_cannot_inject_query_parameters() {
        let order = Order {
            id: String::from("../a?b#c"),
            search: String::from("caf\u{e9}&admin=true"),
            cursor: None,
            token: String::new(),
            payload: Vec::new(),
        };
        assert_eq!(
            order.build_path_and_query(),
            "/v1/orders/..%2Fa%3Fb%23c?search=caf%C3%A9%26admin%3Dtrue"
        );
    }

    #[test]
    fn optional_fields_can_be_removed_without_reusing_previous_values() -> nexora_proto::Result<()>
    {
        let mut order = Order {
            id: String::from("8"),
            search: String::from("ok"),
            cursor: Some(5),
            token: String::from("token"),
            payload: Vec::new(),
        };
        let first = order.into_request("http://localhost")?;
        order.cursor = None;
        let second = order.into_request("http://localhost")?;
        assert_eq!(first.uri.query(), Some("search=ok&cursor=5"));
        assert_eq!(second.uri.query(), Some("search=ok"));
        Ok(())
    }

    #[test]
    fn dynamic_header_injection_and_ambiguous_base_urls_fail_closed() {
        let mut order = Order {
            id: String::from("9"),
            search: String::new(),
            cursor: None,
            token: String::from("value\r\nx-admin: true"),
            payload: Vec::new(),
        };
        assert!(matches!(
            order.into_request("https://example.test"),
            Err(ProtoError::InvalidHeader(_))
        ));
        order.token.clear();
        for base in [
            "https://example.test?admin=true",
            "https://example.test#fragment",
        ] {
            assert!(matches!(
                order.into_request(base),
                Err(ProtoError::InvalidUri(_))
            ));
        }
    }
}

mod sdk_tests {
    use std::{cell::RefCell, rc::Rc};

    use nexora::{HttpService, RequestContext, Responder};
    use nexora_macros::http_service;
    use nexora_proto::{Request, Response, StatusCode, Uri};

    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    type ResponseSlot = Rc<RefCell<Option<Response>>>;

    fn take_response(
        sink: &ResponseSlot,
    ) -> std::result::Result<Response, Box<dyn std::error::Error>> {
        sink.borrow_mut()
            .take()
            .ok_or_else(|| std::io::Error::other("missing response").into())
    }

    #[derive(Default)]
    struct Gateway {
        pending: Option<Responder>,
        seen: Vec<String>,
    }

    #[http_service]
    impl Gateway {
        #[cfg(any())]
        #[get("/disabled")]
        fn disabled(&mut self, _: &mut RequestContext, _: Request) -> nexora::Result<Response> {
            Ok(Response::ok("unreachable"))
        }

        #[get("/disabled-attr")]
        #[cfg_attr(all(), cfg(any()), allow(dead_code))]
        fn disabled_attr(
            &mut self,
            _: &mut RequestContext,
            _: Request,
        ) -> nexora::Result<Response> {
            Ok(Response::ok("unreachable"))
        }

        #[get("/health")]
        #[get("/status")]
        fn health(&mut self, _ctx: &mut RequestContext, req: Request) -> nexora::Result<Response> {
            self.seen.push(req.path().to_owned());
            Ok(Response::ok("healthy"))
        }

        #[get("/orders/new")]
        fn new_order(
            &mut self,
            _ctx: &mut RequestContext,
            _req: Request,
        ) -> nexora::Result<Response> {
            Ok(Response::ok("new order form"))
        }

        #[get("/orders/{id}")]
        fn order(&mut self, _ctx: &mut RequestContext, req: Request) -> nexora::Result<Response> {
            self.seen.push(req.path().to_owned());
            Ok(Response::ok(req.uri.path_and_query().to_owned()))
        }

        #[post("/orders")]
        #[post("/v1/orders/{id}")]
        fn create(&mut self, _ctx: &mut RequestContext, req: Request) -> nexora::Result<Response> {
            Ok(Response::new(StatusCode::CREATED).with_body(req.body))
        }

        #[put("/orders/{id}")]
        #[patch("/orders/{id}")]
        fn update(&mut self, _ctx: &mut RequestContext, req: Request) -> nexora::Result<Response> {
            Ok(Response::ok(req.body))
        }

        #[delete("/orders/{id}")]
        fn delete(&mut self, _ctx: &mut RequestContext, _req: Request) -> nexora::Result<Response> {
            Ok(Response::new(StatusCode::NO_CONTENT))
        }

        #[get("/required")]
        fn required(
            &mut self,
            _ctx: &mut RequestContext,
            req: Request,
        ) -> nexora::Result<Response> {
            match Credentials::from_headers(&req.headers) {
                Ok(credentials) => Ok(Response::ok(credentials.token)),
                Err(ProtoError::MissingHeader(_) | ProtoError::InvalidHeader(_)) => {
                    Ok(Response::new(StatusCode::BAD_REQUEST))
                }
                Err(error) => Err(error.into()),
            }
        }

        #[get("/limited")]
        fn limited(&mut self, _ctx: &mut RequestContext, req: Request) -> nexora::Result<Response> {
            if req.body.len() > 4 {
                Ok(Response::new(StatusCode::PAYLOAD_TOO_LARGE))
            } else {
                Ok(Response::ok(req.body))
            }
        }

        #[get("/deferred")]
        fn deferred(
            &mut self,
            _ctx: &mut RequestContext,
            _req: Request,
            responder: Responder,
        ) -> nexora::Result<()> {
            self.pending = Some(responder);
            Ok(())
        }

        #[get("/drop")]
        fn abandoned(
            &mut self,
            _ctx: &mut RequestContext,
            _req: Request,
            responder: Responder,
        ) -> nexora::Result<()> {
            drop(responder);
            Ok(())
        }

        #[get("/failure")]
        fn failure(
            &mut self,
            _ctx: &mut RequestContext,
            _req: Request,
        ) -> nexora::Result<Response> {
            Err(nexora::Error::InvalidState("domain failure".to_owned()))
        }
    }

    fn request(method: Method, path: &str) -> nexora_proto::Result<Request> {
        Ok(Request::new(
            method,
            Uri::parse(&format!("http://localhost{path}"))?,
        ))
    }

    fn dispatch(
        service: &mut Gateway,
        req: Request,
    ) -> std::result::Result<Response, Box<dyn std::error::Error>> {
        let sink = Rc::new(RefCell::new(None));
        service.call(
            &mut RequestContext::default(),
            req,
            Responder::for_test(Rc::clone(&sink), true),
        )?;
        let response = take_response(&sink)?;
        assert!(sink.borrow().is_none());
        Ok(response)
    }

    fn deferred(
        service: &mut Gateway,
        open: bool,
    ) -> std::result::Result<ResponseSlot, Box<dyn std::error::Error>> {
        let sink = Rc::new(RefCell::new(None));
        service.call(
            &mut RequestContext::default(),
            request(Method::Get, "/deferred")?,
            Responder::for_test(Rc::clone(&sink), open),
        )?;
        assert!(sink.borrow().is_none());
        Ok(sink)
    }

    mod integration_tests {
        use super::*;

        #[test]
        #[allow(non_upper_case_globals)]
        fn router_bindings_do_not_collide_with_const_generic_names() -> TestResult {
            struct Named<const ctx: usize, const r#req: usize, const responder: usize>;
            #[http_service]
            impl<const ctx: usize, const r#req: usize, const responder: usize> Named<ctx, r#req, responder> {
                #[get("/generic")]
                fn handle(
                    &mut self,
                    _: &mut RequestContext,
                    _: Request,
                ) -> nexora::Result<Response> {
                    Ok(Response::ok("generic"))
                }
            }
            let sink = Rc::new(RefCell::new(None));
            Named::<1, 2, 3>.call(
                &mut RequestContext::default(),
                request(Method::Get, "/generic")?,
                Responder::for_test(Rc::clone(&sink), true),
            )?;
            assert_eq!(take_response(&sink)?.body.as_slice(), b"generic");
            assert!(sink.borrow().is_none());
            Ok(())
        }

        #[test]
        fn generated_router_implements_the_actual_sdk_trait_and_preserves_service_state()
        -> TestResult {
            let mut service = Gateway::default();
            for path in ["/health", "/status"] {
                let response = dispatch(&mut service, request(Method::Get, path)?)?;
                assert_eq!(response.status, StatusCode::OK);
                assert_eq!(response.body.as_ref(), b"healthy");
            }
            assert_eq!(service.seen, ["/health", "/status"]);
            Ok(())
        }
    }

    mod e2e_tests {
        use super::*;

        #[test]
        fn typed_builder_dispatches_through_real_sdk_and_protocol_codecs() -> TestResult {
            let order = Order {
                id: "17".to_owned(),
                search: "filled".to_owned(),
                cursor: None,
                token: "Bearer abc".to_owned(),
                payload: b"order body".to_vec(),
            };
            let built = order.into_request("http://localhost")?;
            let mut wire = nexora_proto::BytesMut::new();
            nexora_proto::Http1ClientCodec::default().encode_request(&built, &mut wire)?;
            let Some((decoded, _)) =
                nexora_proto::Http1ServerCodec::default().decode_request(&mut wire)?
            else {
                panic!("complete typed request did not decode")
            };
            assert!(wire.is_empty());
            assert_eq!(
                Credentials::from_headers(&decoded.headers)?.token,
                "Bearer abc"
            );
            let response = dispatch(&mut Gateway::default(), decoded)?;
            assert_eq!(response.status, StatusCode::CREATED);
            assert_eq!(response.body.as_ref(), b"order body");
            Ok(())
        }
    }

    mod lifecycle_tests {
        use super::*;

        #[test]
        fn deferred_response_survives_dispatch_then_sends_exactly_once() -> TestResult {
            let mut service = Gateway::default();
            let sink = deferred(&mut service, true)?;
            let Some(responder) = service.pending.take() else {
                panic!("deferred handler did not retain its responder")
            };
            assert!(!responder.is_closed());
            responder.respond(Response::ok("later"))?;
            assert_eq!(take_response(&sink)?.body.as_ref(), b"later");
            assert!(sink.borrow().is_none());
            Ok(())
        }

        #[test]
        fn dropping_retained_responder_queues_one_server_error() -> TestResult {
            let mut service = Gateway::default();
            let sink = deferred(&mut service, true)?;
            drop(service);
            assert_eq!(
                take_response(&sink)?.status,
                StatusCode::INTERNAL_SERVER_ERROR
            );
            assert!(sink.borrow().is_none());
            let response = dispatch(&mut Gateway::default(), request(Method::Get, "/drop")?)?;
            assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
            Ok(())
        }

        #[test]
        fn disconnected_deferred_response_reports_closed_without_fallback() -> TestResult {
            let mut service = Gateway::default();
            let sink = deferred(&mut service, false)?;
            let Some(responder) = service.pending.take() else {
                panic!("deferred handler did not retain its responder")
            };
            assert!(responder.is_closed());
            assert!(matches!(
                responder.respond(Response::ok("too late")),
                Err(nexora::Error::ConnectionClosed)
            ));
            assert!(sink.borrow().is_none());
            Ok(())
        }

        #[test]
        fn immediate_handler_error_is_preserved_and_drop_supplies_fallback() -> TestResult {
            let sink = Rc::new(RefCell::new(None));
            let result = Gateway::default().call(
                &mut RequestContext::default(),
                request(Method::Get, "/failure")?,
                Responder::for_test(Rc::clone(&sink), true),
            );
            assert!(
                matches!(result, Err(nexora::Error::InvalidState(reason)) if reason == "domain failure")
            );
            assert_eq!(
                take_response(&sink)?.status,
                StatusCode::INTERNAL_SERVER_ERROR
            );
            assert!(sink.borrow().is_none());
            Ok(())
        }
    }

    mod scenario_tests {
        use super::*;

        #[test]
        fn gateway_routes_cover_static_priority_dynamic_methods_and_error_statuses() -> TestResult {
            let mut service = Gateway::default();
            for (method, path, expected) in [
                (Method::Get, "/health", 200),
                (Method::Get, "/status", 200),
                (Method::Get, "/orders/new", 200),
                (Method::Get, "/orders/17", 200),
                (Method::Post, "/orders", 201),
                (Method::Put, "/orders/17", 200),
                (Method::Patch, "/orders/17", 200),
                (Method::Delete, "/orders/17", 204),
                (Method::Get, "/required", 400),
                (Method::Get, "/limited", 200),
                (Method::Post, "/health", 405),
                (Method::Get, "/unknown", 404),
                (Method::Get, "/disabled", 404),
                (Method::Get, "/disabled-attr", 404),
                (Method::Get, "/orders/17/extra", 404),
                (Method::Get, "/orders/", 404),
            ] {
                let response = dispatch(&mut service, request(method, path)?)?;
                assert_eq!(response.status.as_u16(), expected, "{method:?} {path}");
                if path == "/orders/new" {
                    assert_eq!(response.body.as_ref(), b"new order form");
                }
            }
            let authorized =
                request(Method::Get, "/required")?.with_header("authorization", "Bearer accepted");
            assert_eq!(
                dispatch(&mut service, authorized)?.body.as_ref(),
                b"Bearer accepted"
            );
            let invalid = request(Method::Get, "/required")?
                .with_header("authorization", "abc")
                .with_header("x-retries", "many");
            assert_eq!(
                dispatch(&mut service, invalid)?.status,
                StatusCode::BAD_REQUEST
            );
            let too_large = request(Method::Get, "/limited")?.with_body("12345");
            assert_eq!(
                dispatch(&mut service, too_large)?.status,
                StatusCode::PAYLOAD_TOO_LARGE
            );
            let queried = request(Method::Get, "/orders/17?cursor=9")?;
            assert_eq!(
                dispatch(&mut service, queried)?.body.as_ref(),
                b"/orders/17?cursor=9"
            );
            Ok(())
        }
    }
}

#[allow(non_upper_case_globals)]
mod websocket_compile_contract_tests {
    use nexora::{WebSocketServerSession, WebSocketUpgradeHandler};
    use nexora_macros::websocket_handler;
    use nexora_proto::WebSocketMessage;

    #[allow(dead_code, non_snake_case)]
    fn Ok() {}

    #[allow(non_upper_case_globals)]
    struct Handler<
        const r#__nexora_websocket_session: usize,
        const message: usize,
        const payload: usize,
    >;

    #[allow(non_upper_case_globals)]
    #[websocket_handler]
    impl<const r#__nexora_websocket_session: usize, const message: usize, const payload: usize>
        Handler<r#__nexora_websocket_session, message, payload>
    {
        #[cfg(any())]
        #[on_text]
        fn disabled_text(
            &mut self,
            _: &mut WebSocketServerSession,
            _: String,
        ) -> nexora::Result<()> {
            ::std::result::Result::Ok(())
        }

        #[cfg_attr(all(), cfg(any()))]
        #[on_open]
        fn disabled_open(&mut self, _: &mut WebSocketServerSession) -> nexora::Result<()> {
            ::std::result::Result::Ok(())
        }

        #[on_message]
        fn fallback(
            &mut self,
            _: &mut WebSocketServerSession,
            _: WebSocketMessage,
        ) -> nexora::Result<()> {
            ::std::result::Result::Ok(())
        }
    }

    #[test]
    fn disabled_callbacks_and_const_names_compile_against_the_sdk_trait() {
        fn require<T: WebSocketUpgradeHandler>() {}
        require::<Handler<1, 2, 3>>();
    }
}
