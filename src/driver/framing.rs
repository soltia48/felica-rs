//! The Sony SOF-based frame format shared by the Port-100, RC-S320 and RC-S956
//! drivers.
//!
//! Every one of them wraps payloads in the same envelope:
//!
//! ```text
//! [SOF = 00 00 FF][LEN/LCS][DATA...][DCS][POSTAMBLE = 00]
//! ```
//!
//! and shares an identical 2's-complement checksum algorithm. What differs is
//! only how the length is encoded and how the chipset reports an error, so
//! [`Frame`] is generic over a [`FrameFormat`] that names both. Each driver
//! declares its dialect once and aliases `Frame` to it, which keeps the envelope
//! itself as a single implementation.

use std::marker::PhantomData;

/// Start-of-frame / preamble sequence (`00 00 FF`).
pub const SOF: [u8; 3] = [0x00, 0x00, 0xFF];

/// ACK frame bytes.
pub const ACK_BYTES: [u8; 6] = [0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00];

/// Error frame bytes.
pub const ERROR_BYTES: [u8; 6] = [0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00];

/// Trailing byte of every frame.
const POSTAMBLE: u8 = 0x00;

/// Marker that introduces an extended length field.
const EXTENDED_LENGTH_MARKER: [u8; 2] = [0xFF, 0xFF];

/// Offset of the length field, right behind the [`SOF`].
const LENGTH_OFFSET: usize = SOF.len();

/// Offset of the payload in a normal (single length byte) frame.
const NORMAL_DATA_START: usize = LENGTH_OFFSET + 2;

/// Offset of the payload in an extended (marker plus two length bytes) frame.
const EXTENDED_DATA_START: usize = LENGTH_OFFSET + 5;

/// Largest payload a single length byte can describe.
const NORMAL_LENGTH_LIMIT: usize = 256;

/// First payload byte of an [`ErrorDetection::StatusByte`] error frame.
const STATUS_ERROR_BYTE: u8 = 0x7F;

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
    data.get(0..SOF.len()) == Some(&SOF)
}

/// How a chipset encodes the length of a frame's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthEncoding {
    /// A single length byte. Payloads of 256 bytes or more cannot be framed.
    Normal,
    /// Always the extended form: the `FF FF` marker and a little-endian `u16`.
    ExtendedLittleEndian,
    /// A single length byte below 256 bytes, and otherwise the `FF FF` marker
    /// followed by a big-endian `u16`, as the PN53x family defines it.
    NormalOrExtendedBigEndian,
}

/// How a chipset reports that it hit an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorDetection {
    /// The dedicated six-byte [`ERROR_BYTES`] frame.
    ErrorFrame,
    /// A frame whose first payload byte is `7F`. The checksums are not looked
    /// at: the chipset reports the fault this way precisely when the exchange
    /// went wrong, so the frame is classified before it is validated.
    StatusByte,
}

/// The frame dialect one chipset speaks.
///
/// Implemented by a marker type per driver, which then aliases
/// `Frame<ThatMarker>` as its own `Frame`.
pub trait FrameFormat {
    /// How this chipset encodes payload lengths.
    const LENGTH: LengthEncoding;
    /// How this chipset reports errors.
    const ERROR: ErrorDetection;
}

/// Frame types that can be parsed or built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameType {
    /// ACK frame indicating the command was received.
    Ack,
    /// Error frame indicating a protocol error.
    Error,
    /// Data frame carrying a command or response payload.
    Data(Vec<u8>),
}

/// A parsed or built frame in the dialect `F`.
#[derive(Debug, Clone)]
pub struct Frame<F: FrameFormat> {
    raw: Vec<u8>,
    frame_type: FrameType,
    format: PhantomData<F>,
}

impl<F: FrameFormat> Frame<F> {
    /// Creates a new ACK frame.
    pub fn ack() -> Self {
        Self::new(ACK_BYTES.to_vec(), FrameType::Ack)
    }

    /// Builds a data frame carrying `payload`.
    ///
    /// # Panics
    ///
    /// Panics if `payload` is too long for the format's [`LengthEncoding`],
    /// which only [`LengthEncoding::Normal`] bounds at 255 bytes.
    pub fn build(payload: &[u8]) -> Self {
        let mut raw = Vec::with_capacity(payload.len() + EXTENDED_DATA_START + 2);
        raw.extend_from_slice(&SOF);
        push_length(&mut raw, payload.len(), F::LENGTH);
        raw.extend_from_slice(payload);
        raw.push(checksum(payload));
        raw.push(POSTAMBLE);
        Self::new(raw, FrameType::Data(payload.to_vec()))
    }

    /// Parses raw bytes into a frame, or returns `None` if they do not form a
    /// valid one.
    ///
    /// `data` may hold more than one frame's worth of bytes — a transport that
    /// delivers whole packets often does — in which case only the leading frame
    /// is parsed and [`Self::as_bytes`] returns only its bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if !has_sof(data) {
            return None;
        }
        let (frame_type, frame_len) = classify::<F>(data)?;
        Some(Self::new(data[..frame_len].to_vec(), frame_type))
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

    /// Returns the frame's own bytes, excluding anything that followed it.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn new(raw: Vec<u8>, frame_type: FrameType) -> Self {
        Self {
            raw,
            frame_type,
            format: PhantomData,
        }
    }
}

/// Appends the length field for a `len` byte payload.
fn push_length(frame: &mut Vec<u8>, len: usize, encoding: LengthEncoding) {
    match encoding {
        LengthEncoding::Normal => {
            assert!(
                len < NORMAL_LENGTH_LIMIT,
                "payload of {len} bytes is too long for a normal frame"
            );
            push_normal_length(frame, len);
        }
        LengthEncoding::ExtendedLittleEndian => {
            push_extended_length(frame, (len as u16).to_le_bytes());
        }
        LengthEncoding::NormalOrExtendedBigEndian => {
            if len < NORMAL_LENGTH_LIMIT {
                push_normal_length(frame, len);
            } else {
                push_extended_length(frame, (len as u16).to_be_bytes());
            }
        }
    }
}

fn push_normal_length(frame: &mut Vec<u8>, len: usize) {
    frame.push(len as u8);
    frame.push(length_checksum(len as u8));
}

fn push_extended_length(frame: &mut Vec<u8>, len_bytes: [u8; 2]) {
    frame.extend_from_slice(&EXTENDED_LENGTH_MARKER);
    frame.extend_from_slice(&len_bytes);
    frame.push(checksum(&len_bytes));
}

/// Decides what kind of frame `data` is, having already established that it
/// starts with the [`SOF`].
/// Decides what kind of frame `data` starts with, and how many bytes it takes
/// up, having already established that it begins with the [`SOF`].
fn classify<F: FrameFormat>(data: &[u8]) -> Option<(FrameType, usize)> {
    if data == ACK_BYTES {
        return Some((FrameType::Ack, ACK_BYTES.len()));
    }
    match F::ERROR {
        ErrorDetection::ErrorFrame if data == ERROR_BYTES => {
            return Some((FrameType::Error, ERROR_BYTES.len()));
        }
        ErrorDetection::StatusByte if data.get(NORMAL_DATA_START) == Some(&STATUS_ERROR_BYTE) => {
            // The fault is reported in the payload, and the frame around it is
            // not validated, so its length is not known either.
            return Some((FrameType::Error, data.len()));
        }
        _ => {}
    }
    let layout = FrameLayout::parse(data, F::LENGTH)?;
    let payload = layout.validated_payload(data)?;
    Some((FrameType::Data(payload.to_vec()), layout.frame_len()?))
}

/// Where the parts of a data frame sit within its raw bytes.
struct FrameLayout<'a> {
    length: usize,
    length_bytes: &'a [u8],
    lcs: u8,
    data_start: usize,
}

impl<'a> FrameLayout<'a> {
    fn parse(data: &'a [u8], encoding: LengthEncoding) -> Option<Self> {
        let extended = match encoding {
            // RC-S320 frames have no extended form, so an `FF FF` here is a
            // 255 byte payload rather than a marker.
            LengthEncoding::Normal => false,
            _ => data.get(LENGTH_OFFSET..LENGTH_OFFSET + 2) == Some(&EXTENDED_LENGTH_MARKER),
        };
        if !extended {
            return Some(Self {
                length: *data.get(LENGTH_OFFSET)? as usize,
                length_bytes: data.get(LENGTH_OFFSET..LENGTH_OFFSET + 1)?,
                lcs: *data.get(LENGTH_OFFSET + 1)?,
                data_start: NORMAL_DATA_START,
            });
        }
        let length_bytes = data.get(LENGTH_OFFSET + 2..LENGTH_OFFSET + 4)?;
        let length_pair = [length_bytes[0], length_bytes[1]];
        let length = match encoding {
            LengthEncoding::ExtendedLittleEndian => u16::from_le_bytes(length_pair),
            _ => u16::from_be_bytes(length_pair),
        };
        Some(Self {
            length: length as usize,
            length_bytes,
            lcs: *data.get(LENGTH_OFFSET + 4)?,
            data_start: EXTENDED_DATA_START,
        })
    }

    /// The total number of bytes the frame occupies: everything up to and
    /// including the postamble.
    fn frame_len(&self) -> Option<usize> {
        self.data_start.checked_add(self.length)?.checked_add(2) // DCS and postamble
    }

    /// Returns the payload once the length checksum, the data checksum and the
    /// postamble have all been verified.
    fn validated_payload(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        if !checksum_matches(self.length_bytes, self.lcs) {
            return None;
        }
        let data_end = self.data_start.checked_add(self.length)?;
        let payload = data.get(self.data_start..data_end)?;
        if !checksum_matches(payload, *data.get(data_end)?) {
            return None;
        }
        if data.get(data_end.checked_add(1)?) != Some(&POSTAMBLE) {
            return None;
        }
        Some(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for the RC-S320: one length byte, faults reported in the
    /// payload.
    #[derive(Debug, Clone, Copy)]
    struct NormalStatus;
    impl FrameFormat for NormalStatus {
        const LENGTH: LengthEncoding = LengthEncoding::Normal;
        const ERROR: ErrorDetection = ErrorDetection::StatusByte;
    }

    /// Stands in for the Port-100: always an extended little-endian length.
    #[derive(Debug, Clone, Copy)]
    struct ExtendedLe;
    impl FrameFormat for ExtendedLe {
        const LENGTH: LengthEncoding = LengthEncoding::ExtendedLittleEndian;
        const ERROR: ErrorDetection = ErrorDetection::ErrorFrame;
    }

    /// Stands in for the RC-S956: normal below 256 bytes, big-endian above.
    #[derive(Debug, Clone, Copy)]
    struct NormalOrExtendedBe;
    impl FrameFormat for NormalOrExtendedBe {
        const LENGTH: LengthEncoding = LengthEncoding::NormalOrExtendedBigEndian;
        const ERROR: ErrorDetection = ErrorDetection::ErrorFrame;
    }

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

    #[test]
    fn each_encoding_round_trips_its_own_frames() {
        let payload = vec![0x10, 0x20, 0x30];

        let normal = Frame::<NormalStatus>::build(&payload);
        assert_eq!(normal.as_bytes()[3], payload.len() as u8);
        assert_eq!(
            Frame::<NormalStatus>::parse(normal.as_bytes()).and_then(|f| f.into_payload()),
            Some(payload.clone())
        );

        let extended_le = Frame::<ExtendedLe>::build(&payload);
        assert_eq!(extended_le.as_bytes()[3..5], EXTENDED_LENGTH_MARKER);
        assert_eq!(
            extended_le.as_bytes()[5..7],
            (payload.len() as u16).to_le_bytes()
        );
        assert_eq!(
            Frame::<ExtendedLe>::parse(extended_le.as_bytes()).and_then(|f| f.into_payload()),
            Some(payload.clone())
        );

        // Below 256 bytes this format stays on the normal encoding, above it
        // switches to a big-endian extended length.
        let short_be = Frame::<NormalOrExtendedBe>::build(&payload);
        assert_eq!(short_be.as_bytes()[3], payload.len() as u8);
        assert_eq!(
            Frame::<NormalOrExtendedBe>::parse(short_be.as_bytes()).and_then(|f| f.into_payload()),
            Some(payload)
        );

        let long = vec![0xAB; 300];
        let extended_be = Frame::<NormalOrExtendedBe>::build(&long);
        assert_eq!(extended_be.as_bytes()[3..5], EXTENDED_LENGTH_MARKER);
        assert_eq!(extended_be.as_bytes()[5..7], (300u16).to_be_bytes());
        assert_eq!(
            Frame::<NormalOrExtendedBe>::parse(extended_be.as_bytes())
                .and_then(|f| f.into_payload()),
            Some(long)
        );
    }

    #[test]
    fn normal_encoding_never_reads_an_extended_length() {
        // The largest payload the encoding can describe still round-trips.
        let payload = vec![0x5A; NORMAL_LENGTH_LIMIT - 1];
        let frame = Frame::<NormalStatus>::build(&payload);
        assert_eq!(frame.as_bytes()[3], 0xFF);
        assert_eq!(
            Frame::<NormalStatus>::parse(frame.as_bytes()).and_then(|f| f.into_payload()),
            Some(payload)
        );

        // An extended frame is not a frame this format can read: the `FF FF`
        // marker is taken as a length byte and its checksum, which do not match.
        let extended = Frame::<ExtendedLe>::build(&[0x01, 0x02]);
        assert!(Frame::<NormalStatus>::parse(extended.as_bytes()).is_none());
    }

    #[test]
    #[should_panic(expected = "too long for a normal frame")]
    fn normal_encoding_rejects_an_oversized_payload() {
        Frame::<NormalStatus>::build(&[0x00; NORMAL_LENGTH_LIMIT]);
    }

    #[test]
    fn ack_and_error_frames_are_classified_per_format() {
        assert_eq!(
            Frame::<ExtendedLe>::parse(&ACK_BYTES).map(|f| f.frame_type().clone()),
            Some(FrameType::Ack)
        );
        assert_eq!(
            Frame::<ExtendedLe>::parse(&ERROR_BYTES).map(|f| f.frame_type().clone()),
            Some(FrameType::Error)
        );
        assert_eq!(Frame::<ExtendedLe>::ack().frame_type(), &FrameType::Ack);

        // A status-byte format reports the fault as the first payload byte, and
        // does so without checking the frame it arrived in.
        assert_eq!(
            Frame::<NormalStatus>::parse(&[0x00, 0x00, 0xFF, 0x01, 0xFF, 0x7F, 0x00, 0x00])
                .map(|f| f.frame_type().clone()),
            Some(FrameType::Error)
        );
        // The same bytes are just a data frame to a format that does not.
        assert!(matches!(
            Frame::<NormalOrExtendedBe>::parse(&[0x00, 0x00, 0xFF, 0x01, 0xFF, 0x7F, 0x81, 0x00])
                .map(|f| f.frame_type().clone()),
            Some(FrameType::Data(_))
        ));

        let error = Frame::<ExtendedLe>::parse(&ERROR_BYTES).expect("error frame should parse");
        assert!(error.payload().is_none());
        assert!(error.into_payload().is_none());
    }

    #[test]
    fn parse_rejects_corrupt_frames() {
        let payload = vec![0x01, 0x02, 0x03];
        let good = Frame::<ExtendedLe>::build(&payload).as_bytes().to_vec();

        assert!(Frame::<ExtendedLe>::parse(&[0x12, 0x00, 0xFF, 0x00, 0x00]).is_none());
        assert!(Frame::<ExtendedLe>::parse(&good[..good.len() - 1]).is_none());

        let mut bad_lcs = good.clone();
        bad_lcs[7] ^= 0x01;
        assert!(Frame::<ExtendedLe>::parse(&bad_lcs).is_none());

        let mut bad_dcs = good.clone();
        let dcs = bad_dcs.len() - 2;
        bad_dcs[dcs] ^= 0x01;
        assert!(Frame::<ExtendedLe>::parse(&bad_dcs).is_none());

        let mut bad_postamble = good;
        let postamble = bad_postamble.len() - 1;
        bad_postamble[postamble] = 0x01;
        assert!(Frame::<ExtendedLe>::parse(&bad_postamble).is_none());

        // A format that builds extended frames still reads normal ones back, so
        // those have to be checked just as closely.
        let normal = vec![0x00, 0x00, 0xFF, 0x01, 0xFF, 0xAA, 0x56, 0x00];
        assert!(Frame::<ExtendedLe>::parse(&normal).is_some());

        let mut normal_bad_lcs = normal.clone();
        normal_bad_lcs[4] ^= 0x01;
        assert!(Frame::<ExtendedLe>::parse(&normal_bad_lcs).is_none());

        let mut normal_bad_dcs = normal;
        normal_bad_dcs[6] ^= 0x01;
        assert!(Frame::<ExtendedLe>::parse(&normal_bad_dcs).is_none());
    }

    #[test]
    fn parse_stops_at_the_end_of_the_leading_frame() {
        // A transport that delivers whole packets can hand over more than one
        // frame's worth of bytes; only the first is parsed.
        let payload = vec![0x11, 0x22];
        let frame = Frame::<ExtendedLe>::build(&payload);
        let frame_len = frame.as_bytes().len();

        let mut packet = frame.as_bytes().to_vec();
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let parsed = Frame::<ExtendedLe>::parse(&packet).expect("leading frame should parse");
        assert_eq!(parsed.as_bytes().len(), frame_len);
        assert_eq!(parsed.payload(), Some(payload.as_slice()));

        // The same holds for the fixed-size frames.
        let mut ack = ACK_BYTES.to_vec();
        ack.push(0x99);
        let parsed = Frame::<ExtendedLe>::parse(&ack);
        // An ACK is matched exactly, so trailing bytes make it a data frame
        // candidate instead — and this one is not a valid frame either.
        assert!(parsed.is_none());
    }

    #[test]
    fn zero_length_payloads_round_trip() {
        let frame = Frame::<ExtendedLe>::build(&[]);
        let parsed =
            Frame::<ExtendedLe>::parse(frame.as_bytes()).expect("empty frame should parse");
        assert_eq!(parsed.payload(), Some([].as_slice()));
    }
}
