use crate::clf::errors::{CommunicationError, UnsupportedTargetError};
use std::fmt;

pub type Result<T> = std::result::Result<T, DriverError>;

#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error(transparent)]
    UnsupportedTarget(#[from] UnsupportedTargetError),
    #[error(transparent)]
    Communication(#[from] CommunicationError),
    #[error(transparent)]
    Status(#[from] StatusError),
    #[error(transparent)]
    Fault(#[from] CommunicationFault),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, thiserror::Error, Clone, Copy)]
#[error("chipset status error {errno:#04x}")]
pub struct StatusError {
    pub errno: u8,
}

impl StatusError {
    pub fn new(errno: u8) -> Self {
        Self { errno }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CommunicationFault {
    pub errno: u32,
}

impl CommunicationFault {
    pub fn new(errno: u32) -> Self {
        Self { errno }
    }

    pub fn from_status(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let errno = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Some(Self { errno })
    }

    pub fn as_str(&self) -> &'static str {
        match self.errno {
            0x00000000 => "NO_ERROR",
            0x00000001 => "PROTOCOL_ERROR",
            0x00000002 => "PARITY_ERROR",
            0x00000004 => "CRC_ERROR",
            0x00000008 => "COLLISION_ERROR",
            0x00000010 => "OVERFLOW_ERROR",
            0x00000040 => "TEMPERATURE_ERROR",
            0x00000080 => "RECEIVE_TIMEOUT_ERROR",
            0x00000100 => "CRYPTO1_ERROR",
            0x00000200 => "RFCA_ERROR",
            0x00000400 => "RF_OFF_ERROR",
            0x00000800 => "TRANSMIT_TIMEOUT_ERROR",
            0x80000000 => "RECEIVE_LENGTH_ERROR",
            _ => "UNKNOWN_ERROR",
        }
    }

    pub fn matches(&self, label: &str) -> bool {
        self.as_str() == label
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

pub(crate) fn ensure_status_ok(status: Option<u8>) -> Result<()> {
    match status {
        Some(0) | None => Ok(()),
        Some(code) => Err(StatusError::new(code).into()),
    }
}

pub(crate) fn convert_fault_to_comm_error(
    fault: CommunicationFault,
    treat_rf_off_as_broken: bool,
) -> DriverError {
    if treat_rf_off_as_broken && fault.matches("RF_OFF_ERROR") {
        DriverError::Communication(CommunicationError::broken_link(fault.to_string()))
    } else if fault.matches("RECEIVE_TIMEOUT_ERROR") {
        DriverError::Communication(CommunicationError::timeout(fault.to_string()))
    } else {
        DriverError::Communication(CommunicationError::transmission(fault.to_string()))
    }
}
