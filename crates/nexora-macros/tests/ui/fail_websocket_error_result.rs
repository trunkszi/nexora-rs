use nexora_macros::websocket_handler;

struct Handler;

#[websocket_handler]
impl Handler {
    fn on_error(&mut self, _: &mut WebSocketServerSession, _: &Error) -> Result<()> {
        Ok(())
    }
}

fn main() {}
