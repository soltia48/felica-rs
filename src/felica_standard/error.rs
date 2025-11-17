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
