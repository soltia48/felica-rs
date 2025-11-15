#[derive(Debug, thiserror::Error)]
#[error("unsupported target: {0}")]
pub struct UnsupportedTargetError(pub String);

#[derive(Debug, thiserror::Error)]
pub enum CommunicationError {
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("transmission error: {0}")]
    Transmission(String),
    #[error("timeout error: {0}")]
    Timeout(String),
    #[error("broken link: {0}")]
    BrokenLink(String),
}

impl CommunicationError {
    pub fn protocol(msg: impl Into<String>) -> Self {
        CommunicationError::Protocol(msg.into())
    }

    pub fn transmission(msg: impl Into<String>) -> Self {
        CommunicationError::Transmission(msg.into())
    }

    pub fn timeout(msg: impl Into<String>) -> Self {
        CommunicationError::Timeout(msg.into())
    }

    pub fn broken_link(msg: impl Into<String>) -> Self {
        CommunicationError::BrokenLink(msg.into())
    }
}

impl From<&str> for UnsupportedTargetError {
    fn from(value: &str) -> Self {
        UnsupportedTargetError(value.to_string())
    }
}

impl From<String> for UnsupportedTargetError {
    fn from(value: String) -> Self {
        UnsupportedTargetError(value)
    }
}

impl From<&str> for CommunicationError {
    fn from(value: &str) -> Self {
        CommunicationError::Transmission(value.to_string())
    }
}

impl From<String> for CommunicationError {
    fn from(value: String) -> Self {
        CommunicationError::Transmission(value)
    }
}
