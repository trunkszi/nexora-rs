use nexora_macros::headers;
fn main() {
    let _ = headers! { "bad name" => "value" };
}
