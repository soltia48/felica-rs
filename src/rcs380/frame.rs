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
        let lcs = (256 - (frame[5] as u16 + frame[6] as u16) % 256) % 256;
        frame.push(lcs as u8);
        let data_start = frame.len();
        frame.extend_from_slice(payload);
        let checksum: u16 = frame[data_start..].iter().map(|b| *b as u16).sum();
        let dcs = (256 - (checksum % 256)) % 256;
        frame.push(dcs as u8);
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

        let mut frame_type = FrameType::Raw;
        if data == [0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00] {
            frame_type = FrameType::Ack;
        } else if data == [0x00, 0x00, 0xFF, 0xFF, 0xFF] {
            frame_type = FrameType::Error;
        } else if data.get(3..5) == Some(&[0xFF, 0xFF]) && data.len() >= 8 {
            let length = u16::from_le_bytes(data[5..7].try_into().ok()?) as usize;
            if data.len() >= 8 + length {
                let payload = data[8..8 + length].to_vec();
                frame_type = FrameType::Data(payload);
            }
        }

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
