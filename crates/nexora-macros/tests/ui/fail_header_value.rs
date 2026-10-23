use nexora_macros::headers;
fn main() {
    let _ = headers! { "x-name" => "safe\r\ninjected: true" };
}
