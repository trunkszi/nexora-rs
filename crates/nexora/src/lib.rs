//! Single-threaded, completion-driven HTTP/1.1, HTTP/2, WebSocket, and TLS
//! client and server SDK.
//!
//! The caller dispatches state machines on a shared [`liburing::Proactor`]
//! ring and never spawns a thread or blocks the ring-owning thread. Client
//! callbacks, server handlers, DNS completions, and deferred replies all run
//! on that thread, and re-entrant work is staged through
//! [`inbox::SubsystemInbox`] instead of overlapping mutable borrows.

pub mod client;
pub mod dispatch;
pub mod dns;
pub mod error;
pub mod inbox;
pub mod pool;
pub mod server;
pub mod socket;
pub mod websocket_client;
pub mod websocket_server;

pub use client::{ClientBuilder, ClientConfig, HttpClient};
pub use dispatch::{CompletionRoute, CompletionRoutes};
pub use dns::{DnsCache, DnsCacheEntry, HostResolver};
pub use error::{Error, Result};
pub use inbox::{ClientContext, RequestId, SubsystemInbox, TimerId, WebSocketSessionId};
pub use liburing::{
    Completion, CompletionDispatcher, EventDrivenConfig, Proactor as UringProactor, Proactor,
    ProactorBuilder, ProactorConfig, ProactorMode, ProactorStats, SqPollConfig, SubmissionContext,
    SubsystemId,
};
pub use nexora_macros::{
    HeaderMap, RestRequest, headers, http_service, http2_headers, websocket_handler,
};
pub use nexora_proto as proto;
pub use nexora_proto::{
    AlpnProtocol, Bytes, BytesMut, HeaderField, HeaderMapExt, Headers, Http2Config, Http2ErrorCode,
    Http2Settings, Method, ProtoError, Request, Response, Scheme, StatusCode, TlsClientConfig,
    TlsServerConfig, Uri, Version, WebSocketCloseCode, WebSocketCloseFrame, WebSocketConfig,
    WebSocketFrame, WebSocketMessage, WebSocketOpcode,
};
pub use pool::{OriginKey, OriginPool, PoolConfig};
pub use server::{HttpServer, HttpService, RequestContext, Responder, ServerBuilder, ServerConfig};
pub use socket::{IoUringSocket, SocketState};
pub use websocket_client::{WebSocketClient, WebSocketSession};
pub use websocket_server::{WebSocketServerSession, WebSocketUpgradeHandler};
