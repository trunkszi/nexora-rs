use nexora_macros::websocket_handler;

struct Handler;

#[websocket_handler]
impl Handler {
    #[on_open]
    fn first(&mut self, _: &mut WebSocketServerSession) -> Result<()> {
        Ok(())
    }

    #[on_open]
    fn second(&mut self, _: &mut WebSocketServerSession) -> Result<()> {
        Ok(())
    }
}

fn main() {}
