//! Shared error type for the Tier-3 runtime.
//!
//! Every fallible boundary in the client, server, DNS, and socket layers
//! converts into [`Error`], so callers handle one enum while the source error
//! keeps its original diagnostic text through `thiserror`.

/// Result alias used by every fallible public function in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Failure reported at a client, server, DNS, or socket boundary.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A protocol codec rejected input or produced an invalid message.
    #[error("protocol error: {0}")]
    Proto(#[from] nexora_proto::ProtoError),
    /// The io_uring proactor rejected an operation or reported a kernel error.
    #[error("io_uring error: {0}")]
    Uring(#[from] liburing::UringError),
    /// The c-ares resolver reported a query or channel failure.
    #[error("DNS error: {0}")]
    Dns(#[from] cares::AresError),
    /// An operating-system call failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The request was cancelled before its terminal callback ran.
    #[error("request cancelled")]
    Cancelled,
    /// The operation exceeded its deadline.
    #[error("operation timed out")]
    Timeout,
    /// A request or response body exceeded the configured maximum.
    #[error("body size {size} exceeds maximum {max}")]
    BodyTooLarge {
        /// Observed body size in bytes.
        size: usize,
        /// Configured maximum in bytes.
        max: usize,
    },
    /// A host name could not be resolved.
    #[error("DNS resolution failed for host `{host}`: {reason}")]
    DnsResolutionFailed {
        /// Host name that failed to resolve.
        host: String,
        /// Diagnostic text describing the failure.
        reason: String,
    },
    /// The peer closed the connection before the exchange completed.
    #[error("connection closed by peer")]
    ConnectionClosed,
    /// The origin pool has no connection slot available.
    #[error("connection pool exhausted for origin `{origin}`")]
    PoolExhausted {
        /// Origin whose pool is exhausted.
        origin: String,
    },
    /// Redirect following exceeded the configured limit.
    #[error("redirect limit ({max}) exceeded")]
    TooManyRedirects {
        /// Configured redirect limit.
        max: usize,
    },
    /// A URI could not be parsed.
    #[error("invalid URI: {0}")]
    InvalidUri(String),
    /// A state machine was asked to make a transition it does not allow.
    #[error("invalid state: {0}")]
    InvalidState(String),
}
