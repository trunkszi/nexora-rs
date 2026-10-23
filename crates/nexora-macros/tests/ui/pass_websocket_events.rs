//! Compile-only proof of all event attributes and fallback message dispatch.

extern crate self as nexora;

#[path = "support/runtime.rs"]
mod runtime;
use nexora_macros::websocket_handler;
use nexora_proto::{Bytes, WebSocketCloseFrame, WebSocketMessage};
pub use runtime::*;

struct Handler;

#[websocket_handler]
impl Handler {
    #[on_open]
    fn opened(&mut self, _: &mut WebSocketServerSession) -> Result<()> {
        Ok(())
    }

    #[on_text]
    fn text(&mut self, _: &mut WebSocketServerSession, _: String) -> Result<()> {
        Ok(())
    }

    #[on_binary]
    fn binary(&mut self, _: &mut WebSocketServerSession, _: Bytes) -> Result<()> {
        Ok(())
    }

    #[on_ping]
    fn ping(&mut self, _: &mut WebSocketServerSession, _: Bytes) -> Result<()> {
        Ok(())
    }

    #[on_pong]
    fn pong(&mut self, _: &mut WebSocketServerSession, _: Bytes) -> Result<()> {
        Ok(())
    }

    #[on_message]
    fn fallback(&mut self, _: &mut WebSocketServerSession, _: WebSocketMessage) -> Result<()> {
        Ok(())
    }

    #[on_close]
    fn closed(&mut self, _: &mut WebSocketServerSession, _: Option<WebSocketCloseFrame>) -> Result<()> {
        Ok(())
    }

    #[on_error]
    fn failed(&mut self, _: &mut WebSocketServerSession, _: &Error) {}
}

fn accepts_handler<T: WebSocketUpgradeHandler>() {}

fn main() {
    accepts_handler::<Handler>();
}
