use crate::clf::errors::UnsupportedTargetError;
use crate::driver::errors::DriverError;
use thiserror::Error;

/// Errors produced while constructing, exchanging, or validating a FeliCa
/// Standard command.
///
/// Transport failures are preserved as [`Driver`](Self::Driver), while a card
/// that returned status flags indicating failure becomes [`Status`](Self::Status).
/// This distinction lets callers decide whether retrying an RF exchange is safe:
/// a status error means the card received and processed the command.
#[derive(Debug, Error)]
pub enum FelicaStandardError {
    /// The reader driver or its underlying transport failed.
    #[error(transparent)]
    Driver(#[from] DriverError),
    /// The requested target bitrate or modulation is unsupported or malformed.
    #[error(transparent)]
    UnsupportedTarget(#[from] UnsupportedTargetError),
    /// A caller-supplied value cannot be encoded by the command or violates a
    /// protocol limit.
    #[error("Felica parameter error: {0}")]
    InvalidParameter(String),
    /// The card returned a non-success status flag 1.
    ///
    /// `status_flag1` identifies whether the failure belongs to a list entry;
    /// `status_flag2` describes the reason. `detail` is their human-readable
    /// interpretation and should be treated as diagnostic text.
    #[error("{command} failed with status {status_flag1:02X} {status_flag2:02X}: {detail}")]
    Status {
        /// Name of the command whose response reported the error.
        command: &'static str,
        /// Raw Status Flag 1 byte from the response.
        status_flag1: u8,
        /// Raw Status Flag 2 byte from the response.
        status_flag2: u8,
        /// Human-readable interpretation of both status bytes.
        detail: String,
    },
    /// A secure command was requested without an authenticated session.
    #[error("secure command requires mutual authentication")]
    AuthenticationRequired,
    /// A challenge response did not authenticate the card, or the card rejected
    /// the reader during mutual authentication.
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),
    /// Secure-session state, encryption, MAC, or transaction-number processing
    /// failed after authentication.
    #[error("secure session error: {0}")]
    SecureSession(String),
    /// A packet was structurally inconsistent with the FeliCa protocol.
    #[error("Felica protocol error: {0}")]
    Protocol(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clf::errors::UnsupportedTargetError;
    use crate::driver::errors::DriverError;

    #[test]
    fn display_messages_cover_all_error_variants() {
        assert_eq!(
            FelicaStandardError::InvalidParameter("bad arg".into()).to_string(),
            "Felica parameter error: bad arg"
        );
        assert_eq!(
            (FelicaStandardError::Status {
                command: "Read",
                status_flag1: 0xA1,
                status_flag2: 0xB2,
                detail: "detail".into(),
            })
            .to_string(),
            "Read failed with status A1 B2: detail"
        );
        assert_eq!(
            FelicaStandardError::AuthenticationRequired.to_string(),
            "secure command requires mutual authentication"
        );
        assert_eq!(
            FelicaStandardError::AuthenticationFailed("no key".into()).to_string(),
            "authentication failed: no key"
        );
        assert_eq!(
            FelicaStandardError::SecureSession("expired".into()).to_string(),
            "secure session error: expired"
        );
        assert_eq!(
            FelicaStandardError::Protocol("framing".into()).to_string(),
            "Felica protocol error: framing"
        );
    }

    #[test]
    fn from_conversions_wrap_driver_and_unsupported_target_errors() {
        let driver_wrapped: FelicaStandardError = DriverError::other("driver fail").into();
        match driver_wrapped {
            FelicaStandardError::Driver(DriverError::Other(message)) => {
                assert_eq!(message, "driver fail");
            }
            other => panic!("expected Driver variant, got {other:?}"),
        }

        let unsupported_wrapped: FelicaStandardError =
            UnsupportedTargetError::new("unsupported 848B").into();
        match unsupported_wrapped {
            FelicaStandardError::UnsupportedTarget(err) => {
                assert_eq!(err.0, "unsupported 848B");
            }
            other => panic!("expected UnsupportedTarget variant, got {other:?}"),
        }
    }
}
