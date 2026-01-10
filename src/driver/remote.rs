//! Remote NFC driver implementation.
//!
//! This module provides a driver that communicates with an NFC reader
//! over a TCP connection, allowing remote access to NFC functionality.

use crate::clf::targets::RemoteTarget;
use crate::driver::errors::{DriverError, Result};
use crate::felica_standard::{FelicaDriver, Type3TagPollingResult};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

/// Request message for the remote NFC server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteRequest {
    /// Poll for a Type 3 (FeliCa) tag.
    DetectTypeF {
        /// Bit rate (e.g., "212F" or "424F")
        brty: String,
        /// System code to poll for
        system_code: u16,
        /// Request code
        request_code: u8,
        /// Time slots
        time_slots: u8,
    },
    /// Send raw data and receive response.
    Transceive {
        /// Bit rate
        brty: String,
        /// Raw data as hex string
        data: String,
        /// Timeout in milliseconds
        timeout_ms: Option<u16>,
    },
}

/// Response message from the remote NFC server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RemoteResponse {
    /// Successful operation.
    Success {
        /// Response data
        #[serde(flatten)]
        data: RemoteResponseData,
    },
    /// Operation failed.
    Error {
        /// Error message
        message: String,
    },
}

/// Response data variants.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RemoteResponseData {
    /// Polling result.
    Poll {
        /// IDm as hex string
        idm: String,
        /// PMm as hex string
        pmm: String,
        /// Optional RD as hex string
        #[serde(skip_serializing_if = "Option::is_none")]
        rd: Option<String>,
    },
    /// Transceive result.
    Transceive {
        /// Response as hex string
        response: String,
    },
}

/// A remote NFC driver that communicates over TCP.
pub struct RemoteDriver {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl RemoteDriver {
    /// Creates a new `RemoteDriver` connected to the specified address.
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).map_err(DriverError::Io)?;
        let reader = BufReader::new(stream.try_clone().map_err(DriverError::Io)?);
        Ok(Self { stream, reader })
    }

    /// Sends a request and receives a response.
    fn send_request(&mut self, request: &RemoteRequest) -> Result<RemoteResponse> {
        let json = serde_json::to_string(request)
            .map_err(|e| DriverError::Other(format!("Failed to serialize request: {}", e)))?;

        writeln!(self.stream, "{}", json).map_err(DriverError::Io)?;
        self.stream.flush().map_err(DriverError::Io)?;

        let mut response_line = String::new();
        self.reader
            .read_line(&mut response_line)
            .map_err(DriverError::Io)?;

        serde_json::from_str(&response_line)
            .map_err(|e| DriverError::Other(format!("Failed to parse response: {}", e)))
    }

    fn hex_decode(s: &str) -> Result<Vec<u8>> {
        hex::decode(s).map_err(|e| DriverError::Other(format!("Invalid hex: {}", e)))
    }
}

impl FelicaDriver for RemoteDriver {
    fn detect_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<Type3TagPollingResult> {
        let request = RemoteRequest::DetectTypeF {
            brty: target.brty().to_string(),
            system_code,
            request_code,
            time_slots,
        };

        match self.send_request(&request)? {
            RemoteResponse::Success { data } => match data {
                RemoteResponseData::Poll { idm, pmm, rd } => {
                    let idm = Self::hex_decode(&idm)?;
                    let pmm = Self::hex_decode(&pmm)?;
                    let optional = match rd {
                        Some(rd) => Self::hex_decode(&rd)?,
                        None => Vec::new(),
                    };
                    Ok(Type3TagPollingResult { idm, pmm, optional })
                }
                _ => Err(DriverError::Other("Unexpected response type".into())),
            },
            RemoteResponse::Error { message } => Err(DriverError::Other(message)),
        }
    }

    fn transceive(
        &mut self,
        target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>> {
        let request = RemoteRequest::Transceive {
            brty: target.brty().to_string(),
            data: hex::encode(data).to_uppercase(),
            timeout_ms,
        };

        match self.send_request(&request)? {
            RemoteResponse::Success { data } => match data {
                RemoteResponseData::Transceive { response } => Self::hex_decode(&response),
                _ => Err(DriverError::Other("Unexpected response type".into())),
            },
            RemoteResponse::Error { message } => Err(DriverError::Other(message)),
        }
    }
}
