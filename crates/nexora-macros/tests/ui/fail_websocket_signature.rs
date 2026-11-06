use nexora_macros::websocket_handler;
struct Handler;
#[websocket_handler]
impl Handler {
    fn on_message(&mut self) {}
}
fn main() {}
