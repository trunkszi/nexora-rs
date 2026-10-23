use nexora_macros::headers;
fn main() {
    let _ = headers! { ":method" => "GET" };
}
