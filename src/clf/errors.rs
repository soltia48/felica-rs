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

impl From<String> for UnsupportedTargetError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for UnsupportedTargetError {
    fn from(value: &str) -> Self {
        Self(value.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_target_error_construction_and_from_conversion() {
        let from_new = UnsupportedTargetError::new("unsupported 424X");
        assert_eq!(from_new.0, "unsupported 424X");
        assert_eq!(from_new.to_string(), "unsupported target: unsupported 424X");

        let from_into: UnsupportedTargetError = "bad target".into();
        assert_eq!(from_into.0, "bad target");
    }

    #[test]
    fn communication_error_helpers_create_expected_variants() {
        match CommunicationError::protocol("p") {
            CommunicationError::Protocol(msg) => assert_eq!(msg, "p"),
            other => panic!("unexpected variant: {other:?}"),
        }
        match CommunicationError::transmission("t") {
            CommunicationError::Transmission(msg) => assert_eq!(msg, "t"),
            other => panic!("unexpected variant: {other:?}"),
        }
        match CommunicationError::timeout("to") {
            CommunicationError::Timeout(msg) => assert_eq!(msg, "to"),
            other => panic!("unexpected variant: {other:?}"),
        }
        match CommunicationError::broken_link("b") {
            CommunicationError::BrokenLink(msg) => assert_eq!(msg, "b"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn communication_error_display_messages_are_human_readable() {
        assert_eq!(
            CommunicationError::protocol("crc").to_string(),
            "protocol error: crc"
        );
        assert_eq!(
            CommunicationError::transmission("usb").to_string(),
            "transmission error: usb"
        );
        assert_eq!(
            CommunicationError::timeout("500ms").to_string(),
            "timeout error: 500ms"
        );
        assert_eq!(
            CommunicationError::broken_link("disconnected").to_string(),
            "broken link: disconnected"
        );
    }
}
