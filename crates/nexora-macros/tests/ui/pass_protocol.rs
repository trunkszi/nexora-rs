use nexora_macros::{HeaderMap, RestRequest, headers, http2_headers};
use nexora_proto::HeaderMapExt;

#[derive(HeaderMap)]
struct Typed<T: std::fmt::Display + std::str::FromStr> {
    #[header(name = "x-count")]
    count: T,
    #[header(name = "x-optional")]
    optional: Option<u16>,
}

#[derive(RestRequest)]
#[rest(method = "PUT", path = "/items/{id}")]
struct Update<'a> {
    #[path_param]
    id: &'a str,
    #[query]
    limit: Option<usize>,
    #[header(name = "x-token")]
    token: Option<&'a str>,
    #[body]
    body: &'a [u8],
}

fn main() -> nexora_proto::Result<()> {
    let values = headers! { "x-count" => "4", };
    let _: Typed<u16> = Typed::from_headers(&values)?;
    let _ = http2_headers! { ":method" => "PUT", "content-type" => "text/plain", };
    let request = Update {
        id: "5",
        limit: None,
        token: None,
        body: b"abc",
    };
    let _ = request.into_request("https://example.test")?;
    Ok(())
}
