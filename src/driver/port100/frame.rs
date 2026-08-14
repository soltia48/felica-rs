//! Frame dialect of the NFC Port-100.
//!
//! The Port-100 speaks the [SOF-based envelope](crate::driver::framing) and
//! always writes its length in the extended little-endian form, whatever the
//! payload size. Frames it sends back may use either form, which the shared
//! parser handles.

use crate::driver::framing::{ErrorDetection, FrameFormat, LengthEncoding};

pub use crate::driver::framing::{ACK_BYTES, FrameType, SOF as PREAMBLE};

/// The Port-100's frame dialect.
#[derive(Debug, Clone, Copy)]
pub struct Port100Format;

impl FrameFormat for Port100Format {
    const LENGTH: LengthEncoding = LengthEncoding::ExtendedLittleEndian;
    const ERROR: ErrorDetection = ErrorDetection::ErrorFrame;
}

/// A parsed or built Port-100 frame.
pub type Frame = crate::driver::framing::Frame<Port100Format>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::framing::ERROR_BYTES;

    #[test]
    fn parses_ack_and_error_frames() {
        let ack = Frame::parse(&ACK_BYTES).expect("ACK frame should parse");
        assert_eq!(ack.frame_type(), &FrameType::Ack);
        assert!(ack.payload().is_none());

        let error = Frame::parse(&ERROR_BYTES).expect("ERROR frame should parse");
        assert_eq!(error.frame_type(), &FrameType::Error);
        assert!(error.payload().is_none());
    }

    #[test]
    fn build_uses_the_extended_length_and_round_trips() {
        let payload = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        let frame = Frame::build(&payload);
        assert_eq!(frame.as_bytes()[0..3], PREAMBLE);
        assert_eq!(frame.as_bytes()[3..5], [0xFF, 0xFF]);

        let parsed = Frame::parse(frame.as_bytes()).expect("built frame should parse");
        assert_eq!(parsed.frame_type(), &FrameType::Data(payload));
    }

    #[test]
    fn parse_accepts_a_normal_frame_from_the_reader() {
        let frame = vec![0x00, 0x00, 0xFF, 0x01, 0xFF, 0xAA, 0x56, 0x00];
        let parsed = Frame::parse(&frame).expect("normal frame should parse");
        assert_eq!(parsed.payload(), Some([0xAA].as_slice()));
    }
}
