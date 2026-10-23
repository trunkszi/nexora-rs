//! Compile-only proof of the canonical WebSocket upgrade trait signatures.

extern crate self as nexora;

#[path = "support/runtime.rs"]
mod runtime;
use nexora_macros::websocket_handler;
use nexora_proto::{WebSocketCloseFrame, WebSocketMessage};
pub use runtime::*;

struct Handler<T>(T);

#[websocket_handler]
impl<T: Clone> Handler<T> {
    fn on_open(&mut self, _: &mut WebSocketServerSession) -> Result<()> {
        Ok(())
    }

    fn on_message(&mut self, _: &mut WebSocketServerSession, _: WebSocketMessage) -> Result<()> {
        Ok(())
    }

    fn on_close(&mut self, _: &mut WebSocketServerSession, _: Option<WebSocketCloseFrame>) -> Result<()> {
        Ok(())
    }

    fn on_error(&mut self, _: &mut WebSocketServerSession, _: &Error) {}
}

fn accepts_handler<T: WebSocketUpgradeHandler>() {}

fn main() {
    accepts_handler::<Handler<()>>();
}
