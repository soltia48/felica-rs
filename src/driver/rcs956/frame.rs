//! Frame dialect of the RC-S956, which is the NXP PN53x format.
//!
//! The RC-S956 speaks the [SOF-based envelope](crate::driver::framing) with a
//! single length byte for payloads below 256 bytes and the extended big-endian
//! form above that. Its data frames additionally carry a direction identifier as
//! their first byte.

use crate::driver::framing::{ErrorDetection, FrameFormat, LengthEncoding};

pub use crate::driver::framing::{ACK_BYTES, FrameType, SOF};

/// Host to controller command identifier.
pub const HOST_TO_CONTROLLER: u8 = 0xD4;

/// Controller to host response identifier.
pub const CONTROLLER_TO_HOST: u8 = 0xD5;

/// The RC-S956's frame dialect.
#[derive(Debug, Clone, Copy)]
pub struct Rcs956Format;

impl FrameFormat for Rcs956Format {
    const LENGTH: LengthEncoding = LengthEncoding::NormalOrExtendedBigEndian;
    const ERROR: ErrorDetection = ErrorDetection::ErrorFrame;
}

/// A parsed or built RC-S956 frame.
pub type Frame = crate::driver::framing::Frame<Rcs956Format>;

/// Builds a command frame: the host-to-controller identifier, the command
/// code, and then `data`.
pub fn build_command(cmd_code: u8, data: &[u8]) -> Frame {
    let mut payload = Vec::with_capacity(data.len() + 2);
    payload.push(HOST_TO_CONTROLLER);
    payload.push(cmd_code);
    payload.extend_from_slice(data);
    Frame::build(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::framing::ERROR_BYTES;

    #[test]
    fn parses_ack_and_error_frames() {
        assert_eq!(
            Frame::parse(&ACK_BYTES)
                .expect("ACK should parse")
                .frame_type(),
            &FrameType::Ack
        );
        assert_eq!(
            Frame::parse(&ERROR_BYTES)
                .expect("ERROR should parse")
                .frame_type(),
            &FrameType::Error
        );
    }

    #[test]
    fn build_command_prefixes_the_direction_and_command_code() {
        let frame = build_command(0x02, &[0xAA]);
        let parsed = Frame::parse(frame.as_bytes()).expect("built frame should parse");
        assert_eq!(
            parsed.payload(),
            Some([HOST_TO_CONTROLLER, 0x02, 0xAA].as_slice())
        );
    }

    #[test]
    fn payloads_switch_to_the_extended_length_above_255_bytes() {
        let short = Frame::build(&[0xAA; 255]);
        assert_eq!(short.as_bytes()[3], 255);

        let long = Frame::build(&[0xAA; 300]);
        assert_eq!(long.as_bytes()[3..5], [0xFF, 0xFF]);
        assert_eq!(long.as_bytes()[5..7], (300u16).to_be_bytes());
        assert_eq!(
            Frame::parse(long.as_bytes()).and_then(|f| f.into_payload()),
            Some(vec![0xAA; 300])
        );
    }
}
