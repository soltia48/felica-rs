use crate::clf::errors::UnsupportedTargetError;
use crate::driver::errors::DriverError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FelicaStandardError {
    #[error(transparent)]
    Driver(#[from] DriverError),
    #[error(transparent)]
    UnsupportedTarget(#[from] UnsupportedTargetError),
    #[error("Felica parameter error: {0}")]
    InvalidParameter(String),
    #[error("{command} failed with status {status_flag1:02X} {status_flag2:02X}: {detail}")]
    Status {
        command: &'static str,
        status_flag1: u8,
        status_flag2: u8,
        detail: String,
    },
    #[error("secure command requires mutual authentication")]
    AuthenticationRequired,
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("secure session error: {0}")]
    SecureSession(String),
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
