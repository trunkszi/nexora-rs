use nexora_macros::websocket_handler;

struct Handler;

#[websocket_handler]
impl Handler {
    #[on_open]
    fn opened(&mut self, _: &WebSocketServerSession) -> Result<()> {
        Ok(())
    }
}

fn main() {}
