//! Driver error types for NFC reader communication.

use crate::clf::errors::{CommunicationError, UnsupportedTargetError};
use std::fmt;

/// Result type alias for driver operations.
pub type Result<T> = std::result::Result<T, DriverError>;

/// Errors that can occur during NFC driver operations.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The requested target type is not supported.
    #[error(transparent)]
    UnsupportedTarget(#[from] UnsupportedTargetError),

    /// A communication error occurred.
    #[error(transparent)]
    Communication(#[from] CommunicationError),

    /// The chipset returned an error status.
    #[error(transparent)]
    Status(#[from] StatusError),

    /// A communication fault was detected.
    #[error(transparent)]
    Fault(#[from] CommunicationFault),

    /// An I/O error occurred.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A generic error with a custom message.
    #[error("{0}")]
    Other(String),
}

impl DriverError {
    /// Creates a new `DriverError::Other` with the given message.
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}

/// Chipset status error with an error code.
#[derive(Debug, thiserror::Error, Clone, Copy)]
#[error("chipset status error {errno:#04x}")]
pub struct StatusError {
    /// The error code returned by the chipset.
    pub errno: u8,
}

impl StatusError {
    /// Creates a new `StatusError` with the given error number.
    pub const fn new(errno: u8) -> Self {
        Self { errno }
    }
}

/// Communication fault codes from the chipset.
#[derive(Debug, Clone, Copy)]
pub struct CommunicationFault {
    /// The fault code.
    pub errno: u32,
}

/// Known communication fault codes.
mod fault_codes {
    pub const NO_ERROR: u32 = 0x00000000;
    pub const PROTOCOL_ERROR: u32 = 0x00000001;
    pub const PARITY_ERROR: u32 = 0x00000002;
    pub const CRC_ERROR: u32 = 0x00000004;
    pub const COLLISION_ERROR: u32 = 0x00000008;
    pub const OVERFLOW_ERROR: u32 = 0x00000010;
    pub const TEMPERATURE_ERROR: u32 = 0x00000040;
    pub const RECEIVE_TIMEOUT_ERROR: u32 = 0x00000080;
    pub const CRYPTO1_ERROR: u32 = 0x00000100;
    pub const RFCA_ERROR: u32 = 0x00000200;
    pub const RF_OFF_ERROR: u32 = 0x00000400;
    pub const TRANSMIT_TIMEOUT_ERROR: u32 = 0x00000800;
    pub const RECEIVE_LENGTH_ERROR: u32 = 0x80000000;
}

impl CommunicationFault {
    /// Creates a new `CommunicationFault` with the given error number.
    pub const fn new(errno: u32) -> Self {
        Self { errno }
    }

    /// Parses a `CommunicationFault` from a status byte slice.
    pub fn from_status(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let errno = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Some(Self { errno })
    }

    /// Returns a human-readable description of the fault.
    pub const fn as_str(&self) -> &'static str {
        match self.errno {
            fault_codes::NO_ERROR => "NO_ERROR",
            fault_codes::PROTOCOL_ERROR => "PROTOCOL_ERROR",
            fault_codes::PARITY_ERROR => "PARITY_ERROR",
            fault_codes::CRC_ERROR => "CRC_ERROR",
            fault_codes::COLLISION_ERROR => "COLLISION_ERROR",
            fault_codes::OVERFLOW_ERROR => "OVERFLOW_ERROR",
            fault_codes::TEMPERATURE_ERROR => "TEMPERATURE_ERROR",
            fault_codes::RECEIVE_TIMEOUT_ERROR => "RECEIVE_TIMEOUT_ERROR",
            fault_codes::CRYPTO1_ERROR => "CRYPTO1_ERROR",
            fault_codes::RFCA_ERROR => "RFCA_ERROR",
            fault_codes::RF_OFF_ERROR => "RF_OFF_ERROR",
            fault_codes::TRANSMIT_TIMEOUT_ERROR => "TRANSMIT_TIMEOUT_ERROR",
            fault_codes::RECEIVE_LENGTH_ERROR => "RECEIVE_LENGTH_ERROR",
            _ => "UNKNOWN_ERROR",
        }
    }

    /// Checks if this fault matches the given label.
    pub fn matches(&self, label: &str) -> bool {
        self.as_str() == label
    }

    /// Returns true if this is a timeout error.
    pub const fn is_timeout(&self) -> bool {
        self.errno == fault_codes::RECEIVE_TIMEOUT_ERROR
    }

    /// Returns true if this is an RF off error.
    pub const fn is_rf_off(&self) -> bool {
        self.errno == fault_codes::RF_OFF_ERROR
    }
}

impl fmt::Display for CommunicationFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "chipset communication error {:#010x}: {}",
            self.errno,
            self.as_str()
        )
    }
}

impl std::error::Error for CommunicationFault {}

/// Ensures that the chipset status indicates success.
pub(crate) fn ensure_status_ok(status: Option<u8>) -> Result<()> {
    match status {
        Some(0) | None => Ok(()),
        Some(code) => Err(StatusError::new(code).into()),
    }
}

/// Converts a communication fault to an appropriate `DriverError`.
pub(crate) fn convert_fault_to_comm_error(
    fault: CommunicationFault,
    treat_rf_off_as_broken: bool,
) -> DriverError {
    if treat_rf_off_as_broken && fault.is_rf_off() {
        DriverError::Communication(CommunicationError::broken_link(fault.to_string()))
    } else if fault.is_timeout() {
        DriverError::Communication(CommunicationError::timeout(fault.to_string()))
    } else {
        DriverError::Communication(CommunicationError::transmission(fault.to_string()))
    }
}
