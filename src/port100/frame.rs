use std::convert::TryInto;

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
        let mut frame = vec![0x00, 0x00, 0xFF, 0xFF, 0xFF];
        let len = payload.len() as u16;
        frame.extend_from_slice(&len.to_le_bytes());
        let lcs = len_checksum(&len.to_le_bytes());
        frame.push(lcs);
        let data_start = frame.len();
        frame.extend_from_slice(payload);
        let dcs = data_checksum(&frame[data_start..]);
        frame.push(dcs);
        frame.push(0x00);
        Self {
            raw: frame,
            frame_type: FrameType::Data(payload.to_vec()),
        }
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 5 || &data[0..3] != [0x00, 0x00, 0xFF] {
            return None;
        }

        if data == [0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00] {
            return Some(Self {
                raw: data.to_vec(),
                frame_type: FrameType::Ack,
            });
        }

        if data == [0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00] {
            return Some(Self {
                raw: data.to_vec(),
                frame_type: FrameType::Error,
            });
        }

        if data.get(3..5) == Some(&[0xFF, 0xFF]) {
            if data.len() < 9 {
                return None;
            }
            let length = u16::from_le_bytes(data[5..7].try_into().ok()?) as usize;
            let lcs = data[7];
            if !checksum_matches(&data[5..7], lcs) {
                return None;
            }
            let data_start: usize = 8;
            let data_end = data_start.checked_add(length)?;
            if data.len() < data_end + 2 {
                return None;
            }
            let payload = data[data_start..data_end].to_vec();
            let dcs = data[data_end];
            if !checksum_matches(&payload, dcs) {
                return None;
            }
            if data[data_end + 1] != 0x00 {
                return None;
            }
            return Some(Self {
                raw: data.to_vec(),
                frame_type: FrameType::Data(payload),
            });
        }

        if data.len() < 7 {
            return None;
        }
        let len = data[3] as usize;
        let lcs = data[4];
        if !checksum_matches(&data[3..4], lcs) {
            return None;
        }
        let data_start: usize = 5;
        let data_end = data_start.checked_add(len)?;
        if data.len() < data_end + 2 {
            return None;
        }
        let payload = data[data_start..data_end].to_vec();
        let dcs = data[data_end];
        if !checksum_matches(&payload, dcs) {
            return None;
        }
        if data[data_end + 1] != 0x00 {
            return None;
        }
        Some(Self {
            raw: data.to_vec(),
            frame_type: FrameType::Data(payload),
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

fn len_checksum(len_bytes: &[u8]) -> u8 {
    let sum: u16 = len_bytes.iter().map(|b| *b as u16).sum();
    ((256 - (sum % 256)) % 256) as u8
}

fn data_checksum(data: &[u8]) -> u8 {
    let sum: u16 = data.iter().map(|b| *b as u16).sum();
    ((256 - (sum % 256)) % 256) as u8
}

fn checksum_matches(bytes: &[u8], checksum: u8) -> bool {
    let sum: u16 = bytes.iter().map(|b| *b as u16).sum();
    ((sum + checksum as u16) % 256) == 0
}
