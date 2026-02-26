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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn spawn_single_request_server(
        response_line: &str,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener should have local address")
            .to_string();
        let response = response_line.to_string();
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("server should accept");
            let mut line = String::new();
            let mut reader = BufReader::new(socket.try_clone().expect("clone stream"));
            reader
                .read_line(&mut line)
                .expect("server should read request line");
            tx.send(line).expect("request line should be sent to test");
            writeln!(socket, "{}", response).expect("server should send response line");
            socket.flush().expect("server should flush");
        });
        (addr, rx, handle)
    }

    #[test]
    fn hex_decode_accepts_valid_hex_and_rejects_invalid_input() {
        let decoded = RemoteDriver::hex_decode("00a1FF").expect("valid hex should decode");
        assert_eq!(decoded, vec![0x00, 0xA1, 0xFF]);

        match RemoteDriver::hex_decode("GG") {
            Err(DriverError::Other(message)) => assert!(message.contains("Invalid hex")),
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(value) => panic!("expected decode error, got {value:?}"),
        }
    }

    #[test]
    fn remote_request_serialization_includes_tagged_type_and_fields() {
        let request = RemoteRequest::DetectTypeF {
            brty: "212F".to_string(),
            system_code: 0xFE00,
            request_code: 0x01,
            time_slots: 0x0F,
        };
        let json: Value = serde_json::to_value(request).expect("request should serialize");
        assert_eq!(json["type"], "detect_type_f");
        assert_eq!(json["brty"], "212F");
        assert_eq!(json["system_code"], 0xFE00);

        let request = RemoteRequest::Transceive {
            brty: "424F".to_string(),
            data: "AABB".to_string(),
            timeout_ms: Some(500),
        };
        let json: Value = serde_json::to_value(request).expect("request should serialize");
        assert_eq!(json["type"], "transceive");
        assert_eq!(json["data"], "AABB");
        assert_eq!(json["timeout_ms"], 500);
    }

    #[test]
    fn remote_response_deserialization_handles_each_variant() {
        let response: RemoteResponse = serde_json::from_str(
            r#"{"status":"success","idm":"0102030405060708","pmm":"1122334455667788"}"#,
        )
        .expect("poll success response should deserialize");
        match response {
            RemoteResponse::Success {
                data: RemoteResponseData::Poll { rd, .. },
            } => assert!(rd.is_none()),
            other => panic!("expected poll success response, got {other:?}"),
        }

        let response: RemoteResponse =
            serde_json::from_str(r#"{"status":"success","response":"90AB"}"#)
                .expect("transceive success response should deserialize");
        match response {
            RemoteResponse::Success {
                data: RemoteResponseData::Transceive { response },
            } => assert_eq!(response, "90AB"),
            other => panic!("expected transceive success response, got {other:?}"),
        }

        let response: RemoteResponse =
            serde_json::from_str(r#"{"status":"error","message":"failed"}"#)
                .expect("error response should deserialize");
        match response {
            RemoteResponse::Error { message } => assert_eq!(message, "failed"),
            other => panic!("expected error response, got {other:?}"),
        }
    }

    #[test]
    fn remote_response_serialization_omits_optional_rd_when_none() {
        let response = RemoteResponse::Success {
            data: RemoteResponseData::Poll {
                idm: "01".to_string(),
                pmm: "02".to_string(),
                rd: None,
            },
        };
        let json: Value = serde_json::to_value(response).expect("response should serialize");
        let object = json
            .as_object()
            .expect("serialized response should be object");
        assert!(object.contains_key("idm"));
        assert!(!object.contains_key("rd"));
    }

    #[test]
    fn detect_type_f_round_trips_request_and_decodes_poll_response() {
        let (addr, request_rx, server) = spawn_single_request_server(
            r#"{"status":"success","idm":"0102030405060708","pmm":"1122334455667788","rd":"A1B2"}"#,
        );
        let mut driver = RemoteDriver::connect(&addr).expect("driver should connect");
        let target = RemoteTarget::new("212F").expect("target should be created");

        let result = driver
            .detect_type_f(&target, 0xFE00, 0x01, 0x02)
            .expect("detect_type_f should succeed");
        assert_eq!(result.idm, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            result.pmm,
            vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
        assert_eq!(result.optional, vec![0xA1, 0xB2]);

        let raw_request = request_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("request should be captured");
        let json: Value =
            serde_json::from_str(raw_request.trim()).expect("request should be valid JSON");
        assert_eq!(json["type"], "detect_type_f");
        assert_eq!(json["brty"], "212F");
        assert_eq!(json["system_code"], 0xFE00);
        assert_eq!(json["request_code"], 0x01);
        assert_eq!(json["time_slots"], 0x02);

        server.join().expect("server thread should finish");
    }

    #[test]
    fn transceive_uses_uppercase_hex_and_decodes_response() {
        let (addr, request_rx, server) =
            spawn_single_request_server(r#"{"status":"success","response":"90AF"}"#);
        let mut driver = RemoteDriver::connect(&addr).expect("driver should connect");
        let target = RemoteTarget::new("424F").expect("target should be created");

        let response = driver
            .transceive(&target, &[0x0A, 0xBB], Some(250))
            .expect("transceive should succeed");
        assert_eq!(response, vec![0x90, 0xAF]);

        let raw_request = request_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("request should be captured");
        let json: Value =
            serde_json::from_str(raw_request.trim()).expect("request should be valid JSON");
        assert_eq!(json["type"], "transceive");
        assert_eq!(json["brty"], "424F");
        assert_eq!(json["data"], "0ABB");
        assert_eq!(json["timeout_ms"], 250);

        server.join().expect("server thread should finish");
    }

    #[test]
    fn detect_type_f_reports_parse_errors_from_invalid_json_response() {
        let (addr, _request_rx, server) = spawn_single_request_server("not-json");
        let mut driver = RemoteDriver::connect(&addr).expect("driver should connect");
        let target = RemoteTarget::new("212F").expect("target should be created");

        match driver.detect_type_f(&target, 0xFFFF, 0, 0) {
            Err(DriverError::Other(message)) => {
                assert!(message.contains("Failed to parse response"))
            }
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(value) => panic!("expected parse error, got {value:?}"),
        }

        server.join().expect("server thread should finish");
    }

    #[test]
    fn detect_type_f_rejects_success_response_with_wrong_payload_variant() {
        let (addr, _request_rx, server) =
            spawn_single_request_server(r#"{"status":"success","response":"90AF"}"#);
        let mut driver = RemoteDriver::connect(&addr).expect("driver should connect");
        let target = RemoteTarget::new("212F").expect("target should be created");

        match driver.detect_type_f(&target, 0xFFFF, 0, 0) {
            Err(DriverError::Other(message)) => assert_eq!(message, "Unexpected response type"),
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(value) => panic!("expected response-type error, got {value:?}"),
        }

        server.join().expect("server thread should finish");
    }

    #[test]
    fn transceive_rejects_success_response_with_wrong_payload_variant() {
        let (addr, _request_rx, server) = spawn_single_request_server(
            r#"{"status":"success","idm":"0102030405060708","pmm":"1122334455667788"}"#,
        );
        let mut driver = RemoteDriver::connect(&addr).expect("driver should connect");
        let target = RemoteTarget::new("212F").expect("target should be created");

        match driver.transceive(&target, &[0x00], None) {
            Err(DriverError::Other(message)) => assert_eq!(message, "Unexpected response type"),
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(value) => panic!("expected response-type error, got {value:?}"),
        }

        server.join().expect("server thread should finish");
    }
}
