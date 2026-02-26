use std::convert::TryInto;

pub const PREAMBLE: [u8; 3] = [0x00, 0x00, 0xFF];
pub const ACK_BYTES: [u8; 6] = [0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00];
pub const ERROR_BYTES: [u8; 6] = [0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00];
const EXTENDED_LENGTH_MARKER: [u8; 2] = [0xFF, 0xFF];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameType {
    Ack,
    Error,
    Data(Vec<u8>),
    Raw,
}

#[derive(Debug, Clone)]
pub struct Frame {
    raw: Vec<u8>,
    frame_type: FrameType,
}

impl Frame {
    pub fn build(payload: &[u8]) -> Self {
        let mut frame = Vec::with_capacity(payload.len() + 9);
        frame.extend_from_slice(&PREAMBLE);
        frame.extend_from_slice(&EXTENDED_LENGTH_MARKER);
        let len = payload.len() as u16;
        frame.extend_from_slice(&len.to_le_bytes());
        frame.push(checksum(&len.to_le_bytes()));
        let data_start = frame.len();
        frame.extend_from_slice(payload);
        frame.push(checksum(&frame[data_start..]));
        frame.push(0x00);
        Self {
            raw: frame,
            frame_type: FrameType::Data(payload.to_vec()),
        }
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if !has_preamble(data) {
            return None;
        }

        let frame_type = classify_frame(data)?;

        Some(Self {
            raw: data.to_vec(),
            frame_type,
        })
    }

    pub fn frame_type(&self) -> &FrameType {
        &self.frame_type
    }

    pub fn payload(&self) -> Option<&[u8]> {
        match &self.frame_type {
            FrameType::Data(payload) => Some(payload.as_slice()),
            _ => None,
        }
    }

    pub fn into_payload(self) -> Option<Vec<u8>> {
        match self.frame_type {
            FrameType::Data(payload) => Some(payload),
            _ => None,
        }
    }

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
    if !checksum_matches(layout.length_bytes, layout.lcs) {
        return None;
    }
    let data_range = layout.payload_range()?;
    let payload = data.get(data_range.clone())?;
    let (dcs_index, postamble_index) = layout.trailer_indexes()?;
    if !checksum_matches(payload, *data.get(dcs_index)?) {
        return None;
    }
    if data.get(postamble_index) != Some(&0x00) {
        return None;
    }
    Some(FrameType::Data(payload.to_vec()))
}

fn checksum(bytes: &[u8]) -> u8 {
    let sum: u16 = bytes.iter().map(|b| *b as u16).sum();
    ((256 - (sum % 256)) % 256) as u8
}

fn checksum_matches(bytes: &[u8], checksum: u8) -> bool {
    let sum: u16 = bytes.iter().map(|b| *b as u16).sum();
    (sum + checksum as u16).is_multiple_of(256)
}

fn has_preamble(data: &[u8]) -> bool {
    data.len() >= 5 && data.get(0..3) == Some(&PREAMBLE)
}

struct DataFrameLayout<'a> {
    length: usize,
    length_bytes: &'a [u8],
    lcs: u8,
    data_start: usize,
}

impl<'a> DataFrameLayout<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        if data.get(3..5) == Some(&EXTENDED_LENGTH_MARKER) {
            let length_bytes: [u8; 2] = data.get(5..7)?.try_into().ok()?;
            Some(Self {
                length: u16::from_le_bytes(length_bytes) as usize,
                length_bytes: &data[5..7],
                lcs: *data.get(7)?,
                data_start: 8,
            })
        } else {
            Some(Self {
                length: *data.get(3)? as usize,
                length_bytes: &data[3..4],
                lcs: *data.get(4)?,
                data_start: 5,
            })
        }
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
    fn parses_ack_and_error_frames() {
        let ack = Frame::parse(&ACK_BYTES).expect("ACK frame should parse");
        assert_eq!(ack.frame_type(), &FrameType::Ack);
        assert!(ack.payload().is_none());
        assert!(ack.clone().into_payload().is_none());

        let error = Frame::parse(&ERROR_BYTES).expect("ERROR frame should parse");
        assert_eq!(error.frame_type(), &FrameType::Error);
        assert!(error.payload().is_none());
        assert!(error.clone().into_payload().is_none());
    }

    #[test]
    fn build_and_parse_extended_data_frame_round_trip() {
        let payload = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        let frame = Frame::build(&payload);
        assert_eq!(frame.as_bytes()[0..3], PREAMBLE);
        assert_eq!(frame.as_bytes()[3..5], EXTENDED_LENGTH_MARKER);

        let parsed = Frame::parse(frame.as_bytes()).expect("built frame should parse");
        assert_eq!(parsed.frame_type(), &FrameType::Data(payload.clone()));
        assert_eq!(parsed.payload(), Some(payload.as_slice()));
        assert_eq!(parsed.clone().into_payload(), Some(payload));
    }

    #[test]
    fn parse_accepts_normal_non_extended_data_frame() {
        let payload = vec![0xAA];
        let frame = vec![0x00, 0x00, 0xFF, 0x01, 0xFF, 0xAA, 0x56, 0x00];
        let parsed = Frame::parse(&frame).expect("normal frame should parse");
        assert_eq!(parsed.frame_type(), &FrameType::Data(payload.clone()));
        assert_eq!(parsed.payload(), Some(payload.as_slice()));
    }

    #[test]
    fn build_and_parse_zero_length_payload() {
        let frame = Frame::build(&[]);
        let parsed = Frame::parse(frame.as_bytes()).expect("empty payload frame should parse");
        assert_eq!(parsed.frame_type(), &FrameType::Data(vec![]));
        assert_eq!(parsed.payload(), Some([].as_slice()));
    }

    #[test]
    fn parse_rejects_invalid_preamble() {
        let invalid = vec![0x12, 0x00, 0xFF, 0x00, 0x00];
        assert!(Frame::parse(&invalid).is_none());
    }

    #[test]
    fn parse_rejects_invalid_length_checksum() {
        let payload = vec![0x01, 0x02, 0x03];
        let mut frame = Frame::build(&payload).as_bytes().to_vec();
        frame[7] ^= 0x01; // LCS byte for extended frame
        assert!(Frame::parse(&frame).is_none());
    }

    #[test]
    fn parse_rejects_invalid_data_checksum() {
        let payload = vec![0x01, 0x02, 0x03];
        let mut frame = Frame::build(&payload).as_bytes().to_vec();
        let last_data_index = frame.len() - 2;
        frame[last_data_index] ^= 0x01; // DCS
        assert!(Frame::parse(&frame).is_none());
    }

    #[test]
    fn parse_rejects_invalid_postamble() {
        let payload = vec![0x01, 0x02, 0x03];
        let mut frame = Frame::build(&payload).as_bytes().to_vec();
        let postamble_index = frame.len() - 1;
        frame[postamble_index] = 0x01;
        assert!(Frame::parse(&frame).is_none());
    }

    #[test]
    fn parse_rejects_non_extended_frame_with_invalid_checksums() {
        let mut bad_lcs = vec![0x00, 0x00, 0xFF, 0x01, 0xFE, 0xAA, 0x56, 0x00];
        assert!(Frame::parse(&bad_lcs).is_none());

        bad_lcs = vec![0x00, 0x00, 0xFF, 0x01, 0xFF, 0xAA, 0x57, 0x00];
        assert!(Frame::parse(&bad_lcs).is_none());
    }

    #[test]
    fn parse_rejects_truncated_frame() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let frame = Frame::build(&payload);
        let truncated = &frame.as_bytes()[..frame.as_bytes().len() - 1];
        assert!(Frame::parse(truncated).is_none());
    }
}
