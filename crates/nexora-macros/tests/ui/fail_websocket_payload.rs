use nexora_macros::websocket_handler;

struct Handler;

#[websocket_handler]
impl Handler {
    #[on_text]
    fn text(&mut self, _: &mut WebSocketServerSession, _: Bytes) -> Result<()> {
        Ok(())
    }
}

fn main() {}
