//! Shared primitives for the Sony SOF-based frame format.
//!
//! The Port-100, RC-S320, and RC-S956 drivers all wrap payloads in the same
//! envelope:
//!
//! ```text
//! [SOF = 00 00 FF][LEN/LCS][DATA...][DCS][POSTAMBLE = 00]
//! ```
//!
//! and share an identical 2's-complement checksum algorithm. The *length
//! encoding* differs per device (RC-S320 is normal-only; Port-100 always uses a
//! little-endian extended length; RC-S956 uses a big-endian extended length for
//! payloads larger than 255 bytes), so the frame builders themselves stay in
//! each driver while these constants and checksum helpers live here as the
//! single source of truth.

/// Start-of-frame / preamble sequence (`00 00 FF`).
pub const SOF: [u8; 3] = [0x00, 0x00, 0xFF];

/// ACK frame bytes.
pub const ACK_BYTES: [u8; 6] = [0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00];

/// Error frame bytes.
pub const ERROR_BYTES: [u8; 6] = [0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00];

/// Returns the 2's-complement checksum of `bytes`: the byte value that makes
/// the running sum a multiple of 256.
pub fn checksum(bytes: &[u8]) -> u8 {
    let sum: u16 = bytes.iter().map(|b| *b as u16).sum();
    ((256 - (sum % 256)) % 256) as u8
}

/// Returns the length checksum (LCS) for a single-byte normal-frame length.
pub fn length_checksum(len: u8) -> u8 {
    checksum(&[len])
}

/// Returns `true` if `checksum_byte` is the valid 2's-complement checksum of
/// `bytes`.
pub fn checksum_matches(bytes: &[u8], checksum_byte: u8) -> bool {
    let sum: u16 = bytes.iter().map(|b| *b as u16).sum();
    (sum + checksum_byte as u16).is_multiple_of(256)
}

/// Returns `true` if `data` begins with the [`SOF`] sequence.
pub fn has_sof(data: &[u8]) -> bool {
    data.get(0..3) == Some(&SOF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_checksum_is_twos_complement() {
        assert_eq!(length_checksum(0), 0x00);
        assert_eq!(length_checksum(1), 0xFF);
        assert_eq!(length_checksum(2), 0xFE);
        assert_eq!(length_checksum(255), 0x01);
    }

    #[test]
    fn checksum_makes_running_sum_a_multiple_of_256() {
        let data = [0xD4, 0x02];
        let cs = checksum(&data);
        assert!(checksum_matches(&data, cs));
        let sum: u16 = data.iter().map(|b| *b as u16).sum::<u16>() + cs as u16;
        assert_eq!(sum % 256, 0);
    }

    #[test]
    fn checksum_matches_rejects_wrong_checksum() {
        assert!(checksum_matches(&[0x58], length_checksum(0x58)));
        assert!(!checksum_matches(&[0x58], 0x00));
    }

    #[test]
    fn has_sof_requires_three_byte_prefix() {
        assert!(has_sof(&[0x00, 0x00, 0xFF, 0x01]));
        assert!(!has_sof(&[0x00, 0x00]));
        assert!(!has_sof(&[0x12, 0x00, 0xFF]));
    }
}
