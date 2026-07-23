//! Frame handling for PN53x-style communication protocol.
//!
//! The RC-S956 uses the same frame format as the NXP PN53x family:
//!
//! Normal frame format:
//! ```text
//! [PREAMBLE][START][LEN][LCS][DATA...][DCS][POSTAMBLE]
//! ```
//!
//! Extended frame format (for data > 255 bytes):
//! ```text
//! [PREAMBLE][START][0xFF][0xFF][LEN_HI][LEN_LO][LCS][DATA...][DCS][POSTAMBLE]
//! ```
//!
//! Where:
//! - PREAMBLE: 0x00
//! - START: 0x00 0xFF
//! - LEN: Data length (1 byte for normal, 2 bytes for extended)
//! - LCS: Length checksum (256 - LEN) & 0xFF
//! - DATA: Command/response data
//! - DCS: Data checksum (256 - sum(DATA)) & 0xFF
//! - POSTAMBLE: 0x00

use crate::driver::framing::{
    checksum as data_checksum, checksum_matches, has_sof, length_checksum as length_checksum_normal,
};

pub use crate::driver::framing::{ACK_BYTES, ERROR_BYTES, SOF};

/// Extended frame length marker.
const EXTENDED_LENGTH_MARKER: [u8; 2] = [0xFF, 0xFF];

/// Host to controller command identifier.
pub const HOST_TO_CONTROLLER: u8 = 0xD4;

/// Controller to host response identifier.
pub const CONTROLLER_TO_HOST: u8 = 0xD5;

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

/// A parsed or built frame for PN53x communication.
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

    /// Builds a command frame with the given command code and data.
    ///
    /// The frame includes the D4 host identifier, command code, and data payload.
    pub fn build_command(cmd_code: u8, data: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(data.len() + 2);
        payload.push(HOST_TO_CONTROLLER);
        payload.push(cmd_code);
        payload.extend_from_slice(data);
        Self::build(&payload)
    }

    /// Builds a data frame with the given payload.
    pub fn build(payload: &[u8]) -> Self {
        let len = payload.len();

        let raw = if len < 256 {
            // Normal frame format
            let mut frame = Vec::with_capacity(len + 7);
            frame.extend_from_slice(&SOF);
            frame.push(len as u8);
            frame.push(length_checksum_normal(len as u8));
            frame.extend_from_slice(payload);
            frame.push(data_checksum(payload));
            frame.push(0x00); // Postamble
            frame
        } else {
            // Extended frame format
            let len_bytes = (len as u16).to_be_bytes();
            let mut frame = Vec::with_capacity(len + 10);
            frame.extend_from_slice(&SOF);
            frame.extend_from_slice(&EXTENDED_LENGTH_MARKER);
            frame.extend_from_slice(&len_bytes);
            frame.push(data_checksum(&len_bytes));
            frame.extend_from_slice(payload);
            frame.push(data_checksum(payload));
            frame.push(0x00); // Postamble
            frame
        };

        Self {
            raw,
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
    if data == ERROR_BYTES {
        return Some(FrameType::Error);
    }

    let layout = DataFrameLayout::parse(data)?;
    parse_data_frame(layout, data)
}

fn parse_data_frame(layout: DataFrameLayout<'_>, data: &[u8]) -> Option<FrameType> {
    // Verify length checksum
    if !layout.verify_length_checksum() {
        return None;
    }

    // Get payload range
    let data_range = layout.payload_range()?;
    let payload = data.get(data_range.clone())?;

    // Verify data checksum
    let (dcs_index, postamble_index) = layout.trailer_indexes()?;
    if !checksum_matches(payload, *data.get(dcs_index)?) {
        return None;
    }

    // Verify postamble
    if data.get(postamble_index) != Some(&0x00) {
        return None;
    }

    Some(FrameType::Data(payload.to_vec()))
}

struct DataFrameLayout<'a> {
    length: usize,
    length_bytes: &'a [u8],
    lcs: u8,
    data_start: usize,
}

impl<'a> DataFrameLayout<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }

        // Check for extended frame format
        if data.get(3..5) == Some(&EXTENDED_LENGTH_MARKER) {
            if data.len() < 9 {
                return None;
            }
            let length_bytes = &data[5..7];
            let length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
            Some(Self {
                length,
                length_bytes,
                lcs: *data.get(7)?,
                data_start: 8,
            })
        } else {
            let length = *data.get(3)? as usize;
            Some(Self {
                length,
                length_bytes: &data[3..4],
                lcs: *data.get(4)?,
                data_start: 5,
            })
        }
    }

    fn verify_length_checksum(&self) -> bool {
        checksum_matches(self.length_bytes, self.lcs)
    }

    fn payload_range(&self) -> Option<std::ops::Range<usize>> {
        let end = self.data_end()?;
        Some(self.data_start..end)
    }

    fn trailer_indexes(&self) -> Option<(usize, usize)> {
        let data_end = self.data_end()?;
        let dcs_index = data_end;
        let postamble_index = data_end.checked_add(1)?;
        Some((dcs_index, postamble_index))
    }

    fn data_end(&self) -> Option<usize> {
        self.data_start.checked_add(self.length)
    }
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
    fn test_error_frame() {
        let frame = Frame::parse(&ERROR_BYTES).unwrap();
        assert_eq!(frame.frame_type(), &FrameType::Error);
    }

    #[test]
    fn test_build_command_frame() {
        let frame = Frame::build_command(0x02, &[]);
        let parsed = Frame::parse(frame.as_bytes()).unwrap();
        let payload = parsed.payload().unwrap();
        assert_eq!(payload[0], HOST_TO_CONTROLLER);
        assert_eq!(payload[1], 0x02);
    }

    #[test]
    fn test_length_checksum_normal() {
        assert_eq!(length_checksum_normal(2), 0xFE);
        assert_eq!(length_checksum_normal(0), 0x00);
        assert_eq!(length_checksum_normal(255), 0x01);
    }

    #[test]
    fn test_data_checksum() {
        let data = vec![0xD4, 0x02];
        let checksum = data_checksum(&data);
        let sum: u16 = data.iter().map(|b| *b as u16).sum::<u16>() + checksum as u16;
        assert_eq!(sum % 256, 0);
    }
}
