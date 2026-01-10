//! Error types for contactless frontend operations.

/// Error indicating that the requested target type is not supported.
#[derive(Debug, thiserror::Error)]
#[error("unsupported target: {0}")]
pub struct UnsupportedTargetError(pub String);

impl UnsupportedTargetError {
    /// Creates a new `UnsupportedTargetError` with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl<T: Into<String>> From<T> for UnsupportedTargetError {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

/// Errors that can occur during NFC communication.
#[derive(Debug, thiserror::Error)]
pub enum CommunicationError {
    /// A protocol-level error occurred.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// A transmission error occurred.
    #[error("transmission error: {0}")]
    Transmission(String),

    /// The operation timed out.
    #[error("timeout error: {0}")]
    Timeout(String),

    /// The communication link was broken.
    #[error("broken link: {0}")]
    BrokenLink(String),
}

impl CommunicationError {
    /// Creates a protocol error.
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    /// Creates a transmission error.
    pub fn transmission(msg: impl Into<String>) -> Self {
        Self::Transmission(msg.into())
    }

    /// Creates a timeout error.
    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::Timeout(msg.into())
    }

    /// Creates a broken link error.
    pub fn broken_link(msg: impl Into<String>) -> Self {
        Self::BrokenLink(msg.into())
    }
}
