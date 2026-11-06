//! Single-port HTTP/1.1, HTTP/2, and WebSocket server on one proactor.
//!
//! The listener demuxes TLS (`0x16` plus a configured certificate) from
//! cleartext, then HTTP/2 prior knowledge from HTTP/1.1. WebSocket upgrades
//! keep the bytes that follow the HTTP head. Deferred replies travel through
//! [`crate::SubsystemInbox`].

mod config;
mod driver;
mod io;
mod model;
mod net;
mod proto;
mod service;

pub use config::{ServerBuilder, ServerConfig};
pub use driver::HttpServer;
pub use service::{HttpService, RequestContext, Responder};

pub(super) const KIND_ACCEPT: u64 = 1;
pub(super) const KIND_RECV: u64 = 2;
pub(super) const KIND_SEND: u64 = 3;
pub(super) const KIND_CLOSE: u64 = 4;
pub(super) const MAX_CONN: usize = 1024;
