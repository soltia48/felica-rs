//! NFC-F Remote Command Server
//!
//! This server allows remote execution of arbitrary NFC-F commands.
//! It listens on a TCP socket and accepts JSON-formatted commands,
//! forwarding them to the local NFC reader and returning the responses.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example remote_server -- [address:port]
//! ```
//!
//! Default address is 127.0.0.1:7878
//!
//! # Protocol
//!
//! The server accepts two types of requests:
//!
//! ## DetectTypeF (Polling)
//! ```json
//! {"type": "detect_type_f", "brty": "212F", "system_code": 65535, "request_code": 0, "time_slots": 0}
//! ```
//!
//! ## Transceive (Raw command)
//! ```json
//! {"type": "transceive", "brty": "212F", "data": "0A02...", "timeout_ms": 1000}
//! ```

use hex::{decode as hex_decode, encode as hex_encode};
use nfc_rs::{Reader, ReaderPreference, RemoteTarget, open_reader};
use nfc_rs::{RemoteRequest, RemoteResponse, RemoteResponseData};
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7878".to_string());

    let reader = open_reader(ReaderPreference::Auto)?;
    println!(
        "Reader: {} - {} ({})",
        reader.vendor_name().unwrap_or("Unknown"),
        reader.product_name().unwrap_or("Unknown"),
        reader.chipset_name()
    );

    let reader = Arc::new(Mutex::new(reader));
    let listener = TcpListener::bind(&addr)?;
    println!("NFC-F Remote Server listening on {}", addr);
    println!();
    println!("Protocol:");
    println!(
        r#"  DetectTypeF: {{"type": "detect_type_f", "brty": "212F", "system_code": 65535, "request_code": 0, "time_slots": 0}}"#
    );
    println!(
        r#"  Transceive:  {{"type": "transceive", "brty": "212F", "data": "HEX...", "timeout_ms": 1000}}"#
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let reader = Arc::clone(&reader);
                std::thread::spawn(move || {
                    if let Err(e) = handle_client(stream, reader) {
                        eprintln!("Client error: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_client(stream: TcpStream, reader: Arc<Mutex<Reader>>) -> Result<(), Box<dyn Error>> {
    let peer_addr = stream.peer_addr()?;
    println!("Client connected: {}", peer_addr);

    let mut writer = stream.try_clone()?;
    let buf_reader = BufReader::new(stream);

    for line in buf_reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<RemoteRequest>(&line) {
            Ok(request) => {
                let mut reader = reader.lock().unwrap();
                process_request(&mut reader, request)
            }
            Err(e) => RemoteResponse::Error {
                message: format!("Invalid JSON: {}", e),
            },
        };

        let response_json = serde_json::to_string(&response)?;
        writeln!(writer, "{}", response_json)?;
        writer.flush()?;
    }

    println!("Client disconnected: {}", peer_addr);
    Ok(())
}

fn process_request(reader: &mut Reader, request: RemoteRequest) -> RemoteResponse {
    match request {
        RemoteRequest::DetectTypeF {
            brty,
            system_code,
            request_code,
            time_slots,
        } => {
            let target = match RemoteTarget::new(&brty) {
                Ok(t) => t,
                Err(e) => {
                    return RemoteResponse::Error {
                        message: format!("Invalid brty: {}", e),
                    };
                }
            };

            match reader
                .driver_mut()
                .detect_type_f(&target, system_code, request_code, time_slots)
            {
                Ok(result) => {
                    let rd = if result.optional.is_empty() {
                        None
                    } else {
                        Some(hex_encode(&result.optional).to_uppercase())
                    };
                    RemoteResponse::Success {
                        data: RemoteResponseData::Poll {
                            idm: hex_encode(&result.idm).to_uppercase(),
                            pmm: hex_encode(&result.pmm).to_uppercase(),
                            rd,
                        },
                    }
                }
                Err(e) => RemoteResponse::Error {
                    message: e.to_string(),
                },
            }
        }

        RemoteRequest::Transceive {
            brty,
            data,
            timeout_ms,
        } => {
            let target = match RemoteTarget::new(&brty) {
                Ok(t) => t,
                Err(e) => {
                    return RemoteResponse::Error {
                        message: format!("Invalid brty: {}", e),
                    };
                }
            };

            let bytes = match hex_decode(&data) {
                Ok(b) => b,
                Err(e) => {
                    return RemoteResponse::Error {
                        message: format!("Invalid hex data: {}", e),
                    };
                }
            };

            match reader.driver_mut().transceive(&target, &bytes, timeout_ms) {
                Ok(response) => RemoteResponse::Success {
                    data: RemoteResponseData::Transceive {
                        response: hex_encode(response).to_uppercase(),
                    },
                },
                Err(e) => RemoteResponse::Error {
                    message: e.to_string(),
                },
            }
        }
    }
}
