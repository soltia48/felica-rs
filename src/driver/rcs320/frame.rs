//! Frame dialect of the RC-S320.
//!
//! The RC-S320 speaks the [SOF-based envelope](crate::driver::framing) with a
//! single length byte — it has no extended form, so a payload never exceeds 255
//! bytes — and reports a fault as a data frame whose first payload byte is `7F`
//! rather than through the dedicated error frame the later readers use.

use crate::driver::framing::{ErrorDetection, FrameFormat, LengthEncoding};

pub use crate::driver::framing::{ACK_BYTES, FrameType, SOF};

/// The RC-S320's frame dialect.
#[derive(Debug, Clone, Copy)]
pub struct Rcs320Format;

impl FrameFormat for Rcs320Format {
    const LENGTH: LengthEncoding = LengthEncoding::Normal;
    const ERROR: ErrorDetection = ErrorDetection::StatusByte;
}

/// A parsed or built RC-S320 frame.
pub type Frame = crate::driver::framing::Frame<Rcs320Format>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_frame_is_recognised() {
        let frame = Frame::parse(&ACK_BYTES).expect("ACK frame should parse");
        assert_eq!(frame.frame_type(), &FrameType::Ack);
    }

    #[test]
    fn build_and_parse_round_trip() {
        let payload = vec![0x58]; // Get firmware version command
        let frame = Frame::build(&payload);
        let parsed = Frame::parse(frame.as_bytes()).expect("built frame should parse");
        assert_eq!(parsed.payload(), Some(payload.as_slice()));
    }

    #[test]
    fn a_status_byte_payload_is_reported_as_an_error_frame() {
        let frame = Frame::build(&[0x7F]);
        let parsed = Frame::parse(frame.as_bytes()).expect("status frame should parse");
        assert_eq!(parsed.frame_type(), &FrameType::Error);
    }
}
