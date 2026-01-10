use crate::clf::errors::CommunicationError;
use crate::driver::errors::{DriverError, Result};
use crate::driver::port100::device::Device;
use crate::transport::Transport;
use log::{debug, warn};

impl<T: Transport> Device<T> {
    pub(crate) fn dep_verify_frame(
        &self,
        brty: &str,
        data: &[u8],
        cmd_set: &[u8],
    ) -> Option<DepFrame> {
        dep_parse_frame(brty, data, cmd_set)
    }

    pub(crate) fn dep_send_frame(
        &mut self,
        brty: &str,
        payload: Option<&[u8]>,
        timeout: u16,
    ) -> Result<Option<Vec<u8>>> {
        let tx = payload.map(|data| dep_build_frame(brty, data));
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
            .dep_verify_frame(brty, payload, &[0, 4, 6, 8, 10])
            .map(|frame| frame.payload))
    }

    pub(crate) fn dep_handle_psl(
        &mut self,
        brty: &str,
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
        debug!("{} send PSL_RES {}", brty, hex::encode(&psl_res));
        self.dep_send_frame(brty, Some(&psl_res), 0)?;
        let new_brty = match dsi {
            0 => "106A",
            1 => "212F",
            2 => "424F",
            _ => brty,
        };
        self.chipset.set_target_rf(new_brty)?;
        Ok(Some((new_brty.to_string(), data.to_vec())))
    }

    pub(crate) fn dep_send_simple_response(
        &mut self,
        brty: &str,
        code: u8,
        data: &[u8],
    ) -> Result<()> {
        let payload = dep_simple_response_payload(code, data);
        debug!("{} send {}", brty, hex::encode(&payload));
        self.dep_send_frame(brty, Some(&payload), 0)?;
        Ok(())
    }
}

fn dep_parse_frame(brty: &str, data: &[u8], cmd_set: &[u8]) -> Option<DepFrame> {
    let offset = dep_offset(brty);
    if brty == "106A" && data.first() != Some(&0xF0) {
        dep_warn(brty, "received frame has invalid start byte");
        return None;
    }
    let length = data.get(offset)?;
    if *length as usize != data.len().saturating_sub(offset) {
        dep_warn(brty, "received frame has incorrect length byte");
        return None;
    }
    if data.get(offset + 1) != Some(&0xD4) {
        dep_warn(brty, "received frame command byte 1 is not D4h");
        return None;
    }
    let code = data.get(offset + 2).copied()?;
    if !cmd_set.contains(&code) {
        dep_warn(
            brty,
            &format!("received frame command byte 2 not in {:?}", cmd_set),
        );
        return None;
    }
    Some(DepFrame {
        code,
        payload: data[offset + 1..].to_vec(),
    })
}

fn dep_build_frame(brty: &str, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 2);
    if brty == "106A" {
        frame.push(0xF0);
    }
    frame.push((payload.len() + 1) as u8);
    frame.extend_from_slice(payload);
    frame
}

fn dep_offset(brty: &str) -> usize {
    usize::from(brty == "106A")
}

fn dep_simple_response_payload(code: u8, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0xD5, code];
    if let Some(byte) = data.get(2) {
        frame.push(*byte);
    }
    frame
}

fn dep_warn(brty: &str, message: &str) {
    warn!("{brty}: {message}");
}

pub(crate) struct DepFrame {
    #[allow(unused)]
    pub code: u8,
    pub payload: Vec<u8>,
}
