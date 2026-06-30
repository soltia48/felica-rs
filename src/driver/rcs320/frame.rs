//! Frame handling for RC-S320 communication protocol.
//!
//! The RC-S320 uses a similar frame format to the PN53x family:
//!
//! ```text
//! [PREAMBLE][START][LEN][LCS][DATA...][DCS][POSTAMBLE]
//! ```
//!
//! Where:
//! - PREAMBLE: 0x00
//! - START: 0x00 0xFF
//! - LEN: Data length (1 byte)
//! - LCS: Length checksum (256 - LEN) & 0xFF
//! - DATA: Command/response data
//! - DCS: Data checksum (256 - sum(DATA)) & 0xFF
//! - POSTAMBLE: 0x00

use crate::driver::framing::{
    checksum as data_checksum, checksum_matches, has_sof, length_checksum,
};

pub use crate::driver::framing::{ACK_BYTES, SOF};

/// Frame types that can be parsed or built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameType {
    /// ACK frame indicating command was received.
    Ack,
    /// Error frame indicating a protocol error.
    Error,
    /// Data frame containing command/response payload.
    Data(Vec<u8>),
}

/// A parsed or built frame for RC-S320 communication.
#[derive(Debug, Clone)]
pub struct Frame {
    raw: Vec<u8>,
    frame_type: FrameType,
}

impl Frame {
    /// Creates a new ACK frame.
    pub fn ack() -> Self {
        Self {
            raw: ACK_BYTES.to_vec(),
            frame_type: FrameType::Ack,
        }
    }

    /// Builds a data frame with the given payload.
    pub fn build(payload: &[u8]) -> Self {
        let len = payload.len();
        assert!(len < 256, "payload too long for RC-S320 frame");

        let mut frame = Vec::with_capacity(len + 7);
        frame.extend_from_slice(&SOF);
        frame.push(len as u8);
        frame.push(length_checksum(len as u8));
        frame.extend_from_slice(payload);
        frame.push(data_checksum(payload));
        frame.push(0x00); // Postamble

        Self {
            raw: frame,
            frame_type: FrameType::Data(payload.to_vec()),
        }
    }

    /// Parses raw bytes into a frame.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if !has_sof(data) {
            return None;
        }

        let frame_type = classify_frame(data)?;

        Some(Self {
            raw: data.to_vec(),
            frame_type,
        })
    }

    /// Returns the frame type.
    pub fn frame_type(&self) -> &FrameType {
        &self.frame_type
    }

    /// Returns the payload if this is a data frame.
    pub fn payload(&self) -> Option<&[u8]> {
        match &self.frame_type {
            FrameType::Data(payload) => Some(payload.as_slice()),
            _ => None,
        }
    }

    /// Consumes the frame and returns the payload if this is a data frame.
    pub fn into_payload(self) -> Option<Vec<u8>> {
        match self.frame_type {
            FrameType::Data(payload) => Some(payload),
            _ => None,
        }
    }

    /// Returns the raw frame bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
}

fn classify_frame(data: &[u8]) -> Option<FrameType> {
    if data == ACK_BYTES {
        return Some(FrameType::Ack);
    }

    // Check for error frame (0x7F in data byte)
    if data.len() >= 6 && data.get(5) == Some(&0x7F) {
        return Some(FrameType::Error);
    }

    parse_data_frame(data)
}

fn parse_data_frame(data: &[u8]) -> Option<FrameType> {
    if data.len() < 6 {
        return None;
    }

    let len = data[3] as usize;
    let lcs = data[4];

    // Verify length checksum
    if (len as u8).wrapping_add(lcs) != 0 {
        return None;
    }

    // Check if we have enough data
    let expected_len = 5 + len + 2; // SOF(3) + LEN(1) + LCS(1) + DATA(len) + DCS(1) + POSTAMBLE(1)
    if data.len() < expected_len {
        return None;
    }

    let payload = &data[5..5 + len];
    let dcs = data[5 + len];
    let postamble = data[5 + len + 1];

    // Verify data checksum
    if !checksum_matches(payload, dcs) {
        return None;
    }

    // Verify postamble
    if postamble != 0x00 {
        return None;
    }

    Some(FrameType::Data(payload.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack_frame() {
        let frame = Frame::parse(&ACK_BYTES).unwrap();
        assert_eq!(frame.frame_type(), &FrameType::Ack);
    }

    #[test]
    fn test_build_and_parse_frame() {
        let payload = vec![0x58]; // Get firmware version command
        let frame = Frame::build(&payload);
        let parsed = Frame::parse(frame.as_bytes()).unwrap();
        let parsed_payload = parsed.payload().unwrap();
        assert_eq!(parsed_payload, &payload[..]);
    }

    #[test]
    fn test_length_checksum() {
        assert_eq!(length_checksum(1), 0xFF);
        assert_eq!(length_checksum(2), 0xFE);
        assert_eq!(length_checksum(0), 0x00);
        assert_eq!(length_checksum(255), 0x01);
    }

    #[test]
    fn test_data_checksum() {
        let data = vec![0x58];
        let checksum = data_checksum(&data);
        let sum: u16 = data.iter().map(|b| *b as u16).sum::<u16>() + checksum as u16;
        assert_eq!(sum % 256, 0);
    }
}
