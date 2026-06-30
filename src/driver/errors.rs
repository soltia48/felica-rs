//! Driver error types for NFC reader communication.

use crate::clf::errors::{CommunicationError, UnsupportedTargetError};
use std::fmt;

/// Result type alias for driver operations.
pub type Result<T> = std::result::Result<T, DriverError>;

/// Errors that can occur during NFC driver operations.
///
/// The driver layer sits between the contactless-frontend primitives
/// ([`CommunicationError`], [`UnsupportedTargetError`]) and the FeliCa protocol
/// layer (`FelicaStandardError`). Hardware-level rejections reported by the
/// reader chipset are grouped under [`ChipsetError`].
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The requested target type is not supported.
    #[error(transparent)]
    UnsupportedTarget(#[from] UnsupportedTargetError),

    /// A communication error occurred.
    #[error(transparent)]
    Communication(#[from] CommunicationError),

    /// The reader chipset rejected a command (status byte or RF fault).
    #[error(transparent)]
    Chipset(#[from] ChipsetError),

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

impl From<CommunicationFault> for DriverError {
    fn from(fault: CommunicationFault) -> Self {
        DriverError::Chipset(ChipsetError::Fault(fault))
    }
}

/// A hardware-level error reported by the reader's chipset.
///
/// Both kinds originate from the chipset refusing or failing a command, but
/// they carry different payloads: a one-byte command status versus a 32-bit RF
/// communication fault bitmask (see [`CommunicationFault`]).
#[derive(Debug, thiserror::Error, Clone, Copy)]
pub enum ChipsetError {
    /// The chipset returned a non-zero status byte for a command.
    #[error("chipset status error {0:#04x}")]
    Status(u8),

    /// The chipset reported an RF communication fault.
    #[error(transparent)]
    Fault(CommunicationFault),
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
        Some(code) => Err(ChipsetError::Status(code).into()),
    }
}

impl CommunicationFault {
    /// Maps this fault to the most appropriate [`DriverError::Communication`]
    /// variant.
    ///
    /// When `treat_rf_off_as_broken` is set, an RF-off fault is reported as a
    /// broken link rather than a transmission error.
    pub fn to_driver_error(self, treat_rf_off_as_broken: bool) -> DriverError {
        if treat_rf_off_as_broken && self.is_rf_off() {
            DriverError::Communication(CommunicationError::broken_link(self.to_string()))
        } else if self.is_timeout() {
            DriverError::Communication(CommunicationError::timeout(self.to_string()))
        } else {
            DriverError::Communication(CommunicationError::transmission(self.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn communication_fault_from_status_and_properties() {
        assert!(CommunicationFault::from_status(&[0x01, 0x02, 0x03]).is_none());

        let fault = CommunicationFault::from_status(&[0x80, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(fault.errno, 0x00000080);
        assert_eq!(fault.as_str(), "RECEIVE_TIMEOUT_ERROR");
        assert!(fault.is_timeout());
        assert!(fault.matches("RECEIVE_TIMEOUT_ERROR"));
        assert!(fault.to_string().contains("RECEIVE_TIMEOUT_ERROR"));

        let unknown = CommunicationFault::new(0xDEADBEEF);
        assert_eq!(unknown.as_str(), "UNKNOWN_ERROR");
        assert!(!unknown.is_timeout());
        assert!(!unknown.is_rf_off());
    }

    #[test]
    fn ensure_status_ok_handles_success_and_error() {
        assert!(ensure_status_ok(None).is_ok());
        assert!(ensure_status_ok(Some(0)).is_ok());

        match ensure_status_ok(Some(0x7F)) {
            Err(DriverError::Chipset(ChipsetError::Status(errno))) => assert_eq!(errno, 0x7F),
            Err(other) => panic!("expected status error, got {other}"),
            Ok(_) => panic!("expected status error, got Ok"),
        }
    }

    #[test]
    fn communication_fault_to_driver_error_maps_each_branch() {
        match CommunicationFault::new(0x00000080).to_driver_error(false) {
            DriverError::Communication(CommunicationError::Timeout(message)) => {
                assert!(message.contains("RECEIVE_TIMEOUT_ERROR"));
            }
            other => panic!("expected timeout communication error, got {other}"),
        }

        match CommunicationFault::new(0x00000400).to_driver_error(true) {
            DriverError::Communication(CommunicationError::BrokenLink(message)) => {
                assert!(message.contains("RF_OFF_ERROR"));
            }
            other => panic!("expected broken-link communication error, got {other}"),
        }

        match CommunicationFault::new(0x00000400).to_driver_error(false) {
            DriverError::Communication(CommunicationError::Transmission(message)) => {
                assert!(message.contains("RF_OFF_ERROR"));
            }
            other => panic!("expected transmission communication error, got {other}"),
        }
    }
}
