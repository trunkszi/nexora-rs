//! Compile-time validation and code generation for Nexora protocol interfaces.
//!
//! Generated protocol types use the `nexora_proto` crate path. Service and
//! WebSocket handler implementations additionally use the `nexora` crate path.

use proc_macro::TokenStream;

mod header_map;
mod http_service;
mod literals;
mod rest_request;
mod websocket_handler;

/// Derives typed HTTP header conversion through `nexora_proto::HeaderMapExt`.
///
/// Named struct fields accept `#[header(name = "x-name", required,
/// default = "value")]`. A field without an explicit name uses its field name
/// with underscores replaced by hyphens. Values use `ToString` and `FromStr`.
/// Non-optional fields are required unless a default is supplied. Optional
/// fields are omitted when absent; `required` makes their absence an error.
/// Invalid values and missing required headers return protocol errors.
/// Tuple structs, enums, invalid names, and duplicate header mappings produce
/// compiler diagnostics. A default is parsed through the field's `FromStr`
/// implementation when its header is absent.
///
/// # Errors
/// Invalid macro input emits a compiler diagnostic.
///
/// # Panics
/// Does not panic for malformed input.
#[proc_macro_derive(HeaderMap, attributes(header))]
pub fn derive_header_map(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    finish(header_map::expand(input))
}

/// Derives REST request construction from a named struct.
///
/// Use `#[rest(method = "GET", path = "/items/{id}")]` on the struct and
/// `#[path_param]`, `#[query]`, `#[header(name = "x-name")]`, or `#[body]` on
/// fields. Path placeholders must match path fields one-to-one. Generated
/// `into_request` returns protocol errors and `build_path_and_query` builds
/// the encoded request target. `#[json_body]` serializes a body with sonic-rs.
/// JSON fields require a direct `sonic-rs` dependency in the consuming crate.
/// Optional query, header, and body fields are omitted when absent. Raw body
/// fields implement `AsRef<[u8]>`; path, query, and header values implement
/// `Display`. Malformed declarations produce compiler diagnostics.
///
/// # Errors
/// Invalid macro input emits a compiler diagnostic.
///
/// # Panics
/// Does not panic for malformed input.
#[proc_macro_derive(
    RestRequest,
    attributes(rest, path_param, query, header, body, json_body)
)]
pub fn derive_rest_request(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    finish(rest_request::expand(input))
}

/// Generates `nexora::HttpService` routing for an inherent implementation.
///
/// Annotate handlers with `#[route(method = "GET", path = "/items/{id}")]`.
/// Handlers receive a mutable request context and an owned request, returning
/// `nexora::Result<Response>`. A deferred handler additionally receives an owned
/// `nexora::Responder` and returns `nexora::Result<()>`.
/// Verb attributes such as `#[get("/items")]` are also accepted. Unmatched paths
/// receive 404 and matched paths with another method receive 405. Handlers must
/// use `&mut self`, `&mut RequestContext`, and owned request/responder arguments.
/// Register WebSocket upgrades through `HttpServer::with_websocket_handler`.
///
/// # Errors
/// Invalid macro input emits a compiler diagnostic.
///
/// # Panics
/// Does not panic for malformed input.
#[proc_macro_attribute]
pub fn http_service(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            "http_service takes no arguments",
        )
        .to_compile_error()
        .into();
    }
    let input = syn::parse_macro_input!(input as syn::ItemImpl);
    finish(http_service::expand(input))
}

/// Generates `nexora::WebSocketUpgradeHandler` delegation for an inherent implementation.
///
/// Define callbacks named `on_open`, `on_message`, `on_close`, and `on_error`
/// using the matching trait signatures. Callback attributes also select event
/// handlers. Omitted callbacks retain the trait's default behavior.
/// Event selectors are `#[on_open]`, `#[on_message]`, `#[on_text]`,
/// `#[on_binary]`, `#[on_ping]`, `#[on_pong]`, `#[on_close]`, and `#[on_error]`.
/// Each callback receives `&mut self` and `&mut nexora::WebSocketServerSession`.
/// Text callbacks receive an owned `String`, binary/ping/pong callbacks receive
/// `nexora_proto::Bytes`, and message callbacks receive `WebSocketMessage`. Close
/// callbacks receive `Option<WebSocketCloseFrame>`; error callbacks receive `&Error`.
/// Every callback returns `nexora::Result<()>` except error callbacks, which
/// return unit. Message variants without an event callback reach `on_message`
/// when present. Close lifecycle notifications use the separate trait method.
///
/// # Errors
/// Invalid macro input emits a compiler diagnostic.
///
/// # Panics
/// Does not panic for malformed input.
#[proc_macro_attribute]
pub fn websocket_handler(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            "websocket_handler takes no arguments",
        )
        .to_compile_error()
        .into();
    }
    let input = syn::parse_macro_input!(input as syn::ItemImpl);
    finish(websocket_handler::expand(input))
}

/// Constructs `nexora_proto::Headers` from validated string literal pairs.
///
/// Syntax: `headers! { "content-type" => "application/json" }`. Header names
/// must be nonempty HTTP tokens and values cannot contain line breaks or
/// forbidden control bytes. Names are normalized by `Headers`; repeated names
/// retain all values. Empty input and a trailing comma are accepted.
///
/// # Errors
/// Invalid macro input emits a compiler diagnostic.
///
/// # Panics
/// Does not panic for malformed input.
#[proc_macro]
pub fn headers(input: TokenStream) -> TokenStream {
    finish(literals::expand(input.into(), false))
}

/// Constructs `Vec<(String, String)>` from validated HTTP/2 header literals.
///
/// Syntax: `http2_headers! { ":method" => "GET", ":path" => "/items" }`. Names must be
/// lowercase HTTP tokens, optionally beginning with a single colon. Values
/// cannot contain line breaks or forbidden control bytes. Empty input and a
/// trailing comma are accepted, and insertion order is preserved.
///
/// # Errors
/// Invalid macro input emits a compiler diagnostic.
///
/// # Panics
/// Does not panic for malformed input.
#[proc_macro]
pub fn http2_headers(input: TokenStream) -> TokenStream {
    finish(literals::expand(input.into(), true))
}

fn finish(result: syn::Result<proc_macro2::TokenStream>) -> TokenStream {
    match result {
        Ok(output) => output.into(),
        Err(error) => error.to_compile_error().into(),
    }
}
