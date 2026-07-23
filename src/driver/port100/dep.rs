use crate::clf::errors::CommunicationError;
use crate::driver::errors::{DriverError, Result};
use crate::driver::port100::device::Device;
use crate::transport::Transport;
use log::{debug, warn};

impl<T: Transport> Device<T> {
    pub(crate) fn dep_verify_frame(
        &self,
        bitrate: &str,
        data: &[u8],
        cmd_set: &[u8],
    ) -> Option<DepFrame> {
        dep_parse_frame(bitrate, data, cmd_set)
    }

    pub(crate) fn dep_send_frame(
        &mut self,
        bitrate: &str,
        payload: Option<&[u8]>,
        timeout: u16,
    ) -> Result<Option<Vec<u8>>> {
        let tx = payload.map(|data| dep_build_frame(bitrate, data));
        let response = self.chipset.target_exchange_rf(
            0,
            0xFFFF,
            false,
            &[],
            &[],
            false,
            false,
            timeout,
            tx.as_deref(),
        )?;
        if timeout == 0 {
            return Ok(None);
        }
        let payload = response.get(7..).unwrap_or(&[]);
        Ok(self
            .dep_verify_frame(bitrate, payload, &[0, 4, 6, 8, 10])
            .map(|frame| frame.payload))
    }

    pub(crate) fn dep_handle_psl(
        &mut self,
        bitrate: &str,
        data: &[u8],
    ) -> Result<Option<(String, Vec<u8>)>> {
        if data.len() < 4 {
            return Ok(None);
        }
        let dsi = (data[3] >> 3) & 0x07;
        let dri = data[3] & 0x07;
        if dsi != dri {
            return Err(DriverError::Communication(
                CommunicationError::transmission("PSL_REQ DSI != DRI is not supported"),
            ));
        }
        let psl_res = vec![0xD5, 0x05, data[2]];
        debug!("{} send PSL_RES {}", bitrate, hex::encode(&psl_res));
        self.dep_send_frame(bitrate, Some(&psl_res), 0)?;
        let new_bitrate = match dsi {
            0 => "106A",
            1 => "212F",
            2 => "424F",
            _ => bitrate,
        };
        self.chipset.set_target_rf(new_bitrate)?;
        Ok(Some((new_bitrate.to_string(), data.to_vec())))
    }

    pub(crate) fn dep_send_simple_response(
        &mut self,
        bitrate: &str,
        code: u8,
        data: &[u8],
    ) -> Result<()> {
        let payload = dep_simple_response_payload(code, data);
        debug!("{} send {}", bitrate, hex::encode(&payload));
        self.dep_send_frame(bitrate, Some(&payload), 0)?;
        Ok(())
    }
}

fn dep_parse_frame(bitrate: &str, data: &[u8], cmd_set: &[u8]) -> Option<DepFrame> {
    let offset = dep_offset(bitrate);
    if bitrate == "106A" && data.first() != Some(&0xF0) {
        dep_warn(bitrate, "received frame has invalid start byte");
        return None;
    }
    let length = data.get(offset)?;
    if *length as usize != data.len().saturating_sub(offset) {
        dep_warn(bitrate, "received frame has incorrect length byte");
        return None;
    }
    if data.get(offset + 1) != Some(&0xD4) {
        dep_warn(bitrate, "received frame command byte 1 is not D4h");
        return None;
    }
    let code = data.get(offset + 2).copied()?;
    if !cmd_set.contains(&code) {
        dep_warn(
            bitrate,
            &format!("received frame command byte 2 not in {:?}", cmd_set),
        );
        return None;
    }
    Some(DepFrame {
        code,
        payload: data[offset + 1..].to_vec(),
    })
}

fn dep_build_frame(bitrate: &str, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 2);
    if bitrate == "106A" {
        frame.push(0xF0);
    }
    frame.push((payload.len() + 1) as u8);
    frame.extend_from_slice(payload);
    frame
}

fn dep_offset(bitrate: &str) -> usize {
    usize::from(bitrate == "106A")
}

fn dep_simple_response_payload(code: u8, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0xD5, code];
    if let Some(byte) = data.get(2) {
        frame.push(*byte);
    }
    frame
}

fn dep_warn(bitrate: &str, message: &str) {
    warn!("{bitrate}: {message}");
}

pub(crate) struct DepFrame {
    #[allow(unused)]
    pub code: u8,
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dep_build_frame_and_parse_round_trip_for_106a_and_212f() {
        let payload = vec![0xD4, 0x04, 0xAA];

        let frame_106a = dep_build_frame("106A", &payload);
        assert_eq!(frame_106a, vec![0xF0, 0x04, 0xD4, 0x04, 0xAA]);
        let parsed_106a = dep_parse_frame("106A", &frame_106a, &[0x04]).expect("valid 106A frame");
        assert_eq!(parsed_106a.code, 0x04);
        assert_eq!(parsed_106a.payload, payload);

        let frame_212f = dep_build_frame("212F", &payload);
        assert_eq!(frame_212f, vec![0x04, 0xD4, 0x04, 0xAA]);
        let parsed_212f = dep_parse_frame("212F", &frame_212f, &[0x04]).expect("valid 212F frame");
        assert_eq!(parsed_212f.code, 0x04);
        assert_eq!(parsed_212f.payload, payload);
    }

    #[test]
    fn dep_parse_frame_rejects_invalid_header_length_or_command_bytes() {
        let valid = vec![0xF0, 0x04, 0xD4, 0x04, 0xAA];
        assert!(dep_parse_frame("106A", &valid, &[0x04]).is_some());

        let bad_start = vec![0x00, 0x04, 0xD4, 0x04, 0xAA];
        assert!(dep_parse_frame("106A", &bad_start, &[0x04]).is_none());

        let bad_len = vec![0xF0, 0x05, 0xD4, 0x04, 0xAA];
        assert!(dep_parse_frame("106A", &bad_len, &[0x04]).is_none());

        let bad_cmd1 = vec![0xF0, 0x04, 0xD5, 0x04, 0xAA];
        assert!(dep_parse_frame("106A", &bad_cmd1, &[0x04]).is_none());

        let bad_cmd2 = vec![0xF0, 0x04, 0xD4, 0x05, 0xAA];
        assert!(dep_parse_frame("106A", &bad_cmd2, &[0x04]).is_none());
    }

    #[test]
    fn dep_offset_and_simple_response_payload_behave_as_expected() {
        assert_eq!(dep_offset("106A"), 1);
        assert_eq!(dep_offset("212F"), 0);
        assert_eq!(dep_offset("424F"), 0);

        let with_did = dep_simple_response_payload(0x07, &[0xD4, 0x06, 0x99, 0x00]);
        assert_eq!(with_did, vec![0xD5, 0x07, 0x99]);

        let without_did = dep_simple_response_payload(0x07, &[0xD4, 0x06]);
        assert_eq!(without_did, vec![0xD5, 0x07]);
    }
}
