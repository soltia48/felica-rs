//! Helpers shared by the secure-messaging submodules' unit tests.

use crate::felica_standard::FelicaStandardError;

pub(super) fn bytes_from_hex(input: &str) -> Vec<u8> {
    let mut cleaned = String::with_capacity(input.len());
    for ch in input.chars() {
        if !ch.is_ascii_whitespace() {
            cleaned.push(ch);
        }
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte =
            u8::from_str_radix(&cleaned[i..i + 2], 16).expect("invalid hex literal in test vector");
        out.push(byte);
    }
    out
}

pub(super) fn assert_protocol_error_contains<T>(
    result: Result<T, FelicaStandardError>,
    expected: &str,
) {
    match result {
        Err(FelicaStandardError::Protocol(message)) => {
            assert!(
                message.contains(expected),
                "unexpected protocol error message: {message}"
            );
        }
        Err(other) => panic!("expected protocol error, got {other}"),
        Ok(_) => panic!("expected protocol error, got Ok"),
    }
}

pub(super) fn assert_secure_session_error_contains<T>(
    result: Result<T, FelicaStandardError>,
    expected: &str,
) {
    match result {
        Err(FelicaStandardError::SecureSession(message)) => {
            assert!(
                message.contains(expected),
                "unexpected secure-session error message: {message}"
            );
        }
        Err(other) => panic!("expected secure-session error, got {other}"),
        Ok(_) => panic!("expected secure-session error, got Ok"),
    }
}
