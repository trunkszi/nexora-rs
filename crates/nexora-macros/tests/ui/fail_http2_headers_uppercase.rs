use nexora_macros::http2_headers;
fn main() {
    let _ = http2_headers! { "Content-Type" => "text/plain" };
}
