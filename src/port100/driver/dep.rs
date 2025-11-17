use super::device::Device;
use super::errors::{DriverError, Result};
use crate::clf::errors::CommunicationError;
use crate::transport::Transport;
use log::{debug, warn};

impl<T: Transport> Device<T> {
    pub(super) fn dep_verify_frame(
        &self,
        brty: &str,
        data: &[u8],
        cmd_set: &[u8],
    ) -> Option<Vec<u8>> {
        let offset = if brty == "106A" { 1 } else { 0 };
        if brty == "106A" && data.get(0) != Some(&0xF0) {
            warn!("received frame has invalid start byte");
            return None;
        }
        let length = data.get(offset)?;
        if *length as usize != data.len() - offset {
            warn!("received frame has incorrect length byte");
            return None;
        }
        if data.get(offset + 1) != Some(&0xD4) {
            warn!("received frame command byte 1 is not D4h");
            return None;
        }
        let code = data.get(offset + 2).copied()?;
        if !cmd_set.contains(&code) {
            warn!("received frame command byte 2 not in {:?}", cmd_set);
            return None;
        }
        Some(data[offset + 1..].to_vec())
    }

    pub(super) fn dep_send_frame(
        &mut self,
        brty: &str,
        payload: Option<&[u8]>,
        timeout: u16,
    ) -> Result<Option<Vec<u8>>> {
        let tx = payload.map(|data| {
            let mut frame = Vec::new();
            if brty == "106A" {
                frame.push(0xF0);
            }
            frame.push((data.len() + 1) as u8);
            frame.extend_from_slice(data);
            frame
        });
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
        Ok(self.dep_verify_frame(brty, payload, &[0, 4, 6, 8, 10]))
    }

    pub(super) fn dep_handle_psl(
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

    pub(super) fn dep_send_simple_response(
        &mut self,
        brty: &str,
        code: u8,
        data: &[u8],
    ) -> Result<()> {
        let mut frame = vec![0xD5, code];
        if let Some(byte) = data.get(2) {
            frame.push(*byte);
        }
        debug!("{} send {}", brty, hex::encode(&frame));
        self.dep_send_frame(brty, Some(&frame), 0)?;
        Ok(())
    }
}
