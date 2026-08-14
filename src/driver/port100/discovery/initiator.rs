//! Polling for cards: the reader acts as the NFC initiator.
//!
//! Each `detect_*` method configures the RF for one technology, sends its sense
//! command and, when a card answers, activates it far enough to describe it as a
//! [`RemoteTarget`].

use super::ensure_supported_bitrate;
use crate::clf::errors::UnsupportedTargetError;
use crate::clf::targets::RemoteTarget;
use crate::driver::errors::{DriverError, Result};
use crate::driver::port100::device::Device;
use crate::felica_standard::{
    FelicaStandardCommand, FelicaStandardResponse, Type3TagPollingResult, polling_timeout_ms,
};
use crate::transport::Transport;
use log::debug;

impl<T: Transport> Device<T> {
    pub fn detect_type_a(&mut self, target: &RemoteTarget) -> Result<Option<RemoteTarget>> {
        let bitrate = target.bitrate();
        ensure_supported_bitrate(bitrate, &["106A", "212A", "424A"], "unsupported bitrate ")?;

        debug!("polling for NFC-A technology");

        self.configure_initiator_for_poll(
            bitrate,
            &[
                ("initial_guard_time", 6),
                ("add_crc", 0),
                ("check_crc", 0),
                ("check_parity", 1),
                ("last_byte_bit_count", 7),
            ],
        )?;

        let sens_req = target.data.sens_req.clone().unwrap_or_else(|| vec![0x26]);
        let Some(sens_res) = self.initiator_exchange_optional(&sens_req, 30, "SENS_REQ", false)?
        else {
            return Ok(None);
        };

        if sens_res.len() != 2 {
            return Ok(None);
        }

        debug!("received SENS_RES {}", hex::encode(&sens_res));

        if is_type1_atqa(&sens_res) {
            return self.handle_type1_activation(bitrate, sens_res);
        }

        self.chipset
            .configure_initiator(&[("last_byte_bit_count", 8), ("add_parity", 1)])?;

        match self.perform_type_a_anticollision(target)? {
            Some((sel_res, uid_value))
                if !sel_res.is_empty() && (sel_res[0] & 0b0000_0100) == 0 =>
            {
                let mut found = RemoteTarget::new(bitrate)?;
                found.data.sens_res = Some(sens_res);
                found.data.sel_res = Some(sel_res);
                found.data.sdd_res = Some(uid_value);
                Ok(Some(found))
            }
            _ => Ok(None),
        }
    }

    fn handle_type1_activation(
        &mut self,
        bitrate: &str,
        sens_res: Vec<u8>,
    ) -> Result<Option<RemoteTarget>> {
        self.chipset.configure_initiator(&[
            ("last_byte_bit_count", 8),
            ("add_crc", 2),
            ("check_crc", 2),
            ("type_1_tag_rrdd", 2),
        ])?;
        let mut found = RemoteTarget::new(bitrate)?;
        found.data.sens_res = Some(sens_res.clone());
        if sens_res[1] & 0x0F == 0b1100 {
            let rid_cmd = vec![0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            debug!("send RID_CMD {}", hex::encode(&rid_cmd));
            let Some(rid_res) = self.initiator_exchange_optional(&rid_cmd, 30, "RID_CMD", true)?
            else {
                return Ok(None);
            };
            found.data.rid_res = Some(rid_res);
        }
        Ok(Some(found))
    }

    fn perform_type_a_anticollision(
        &mut self,
        target: &RemoteTarget,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        if let Some(uid) = target.data.sel_req.clone() {
            let sel_res = self.select_known_uid(&uid)?;
            return Ok(sel_res.map(|res| (res, uid)));
        }
        self.discover_uid()
    }

    fn select_known_uid(&mut self, uid: &[u8]) -> Result<Option<Vec<u8>>> {
        let cascade_uid = cascade_uid(uid);
        self.chipset
            .configure_initiator(&[("add_crc", 1), ("check_crc", 1)])?;
        let mut sel_res = Vec::new();
        for (sel_cmd, start) in [0x93u8, 0x95, 0x97]
            .iter()
            .zip((0..cascade_uid.len()).step_by(4))
        {
            let slice_end = (start + 4).min(cascade_uid.len());
            let mut sel_req = vec![*sel_cmd, 0x70];
            sel_req.extend_from_slice(&cascade_uid[start..slice_end]);
            let bcc = sel_req[2..6.min(sel_req.len())]
                .iter()
                .fold(0, |acc, b| acc ^ b);
            sel_req.push(bcc);
            debug!("send SEL_REQ {}", hex::encode(&sel_req));
            let Some(res) = self.initiator_exchange_optional(&sel_req, 30, "SEL_REQ", true)? else {
                return Ok(None);
            };
            sel_res = res;
            debug!("received SEL_RES {}", hex::encode(&sel_res));
        }
        Ok(Some(sel_res))
    }

    fn discover_uid(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let mut sel_res = Vec::new();
        let mut uid = Vec::new();
        for sel_cmd in [0x93u8, 0x95, 0x97] {
            self.chipset
                .configure_initiator(&[("add_crc", 0), ("check_crc", 0)])?;
            let sdd_req = vec![sel_cmd, 0x20];
            debug!("send SDD_REQ {}", hex::encode(&sdd_req));
            let Some(sdd_res) = self.initiator_exchange_optional(&sdd_req, 30, "SDD_REQ", true)?
            else {
                return Ok(None);
            };
            debug!("received SDD_RES {}", hex::encode(&sdd_res));
            self.chipset
                .configure_initiator(&[("add_crc", 1), ("check_crc", 1)])?;
            let mut sel_req = vec![sel_cmd, 0x70];
            sel_req.extend_from_slice(&sdd_res);
            debug!("send SEL_REQ {}", hex::encode(&sel_req));
            let Some(res) = self.initiator_exchange_optional(&sel_req, 30, "SEL_REQ", true)? else {
                return Ok(None);
            };
            sel_res = res.clone();
            debug!("received SEL_RES {}", hex::encode(&sel_res));
            if !sel_res.is_empty() && (sel_res[0] & 0b0000_0100) != 0 {
                if sdd_res.len() >= 4 {
                    uid.extend_from_slice(&sdd_res[1..4]);
                }
            } else {
                let take = sdd_res.len().min(4);
                uid.extend_from_slice(&sdd_res[0..take]);
                break;
            }
        }
        Ok(Some((sel_res, uid)))
    }

    pub fn detect_type_b(&mut self, target: &RemoteTarget) -> Result<Option<RemoteTarget>> {
        let bitrate = target.bitrate();
        ensure_supported_bitrate(bitrate, &["106B", "212B", "424B"], "unsupported bitrate ")?;

        debug!("polling for NFC-B technology");

        self.configure_initiator_for_poll(
            bitrate,
            &[
                ("initial_guard_time", 20),
                ("add_sof", 1),
                ("check_sof", 1),
                ("add_eof", 1),
                ("check_eof", 1),
            ],
        )?;

        let sensb_req = target
            .data
            .sensb_req
            .clone()
            .unwrap_or_else(|| vec![0x05, 0x00, 0x10]);
        debug!("send SENSB_REQ {}", hex::encode(&sensb_req));

        let sensb_res =
            match self.initiator_exchange_optional(&sensb_req, 30, "SENSB_REQ", false)? {
                Some(data) => data,
                None => return Ok(None),
            };

        if sensb_res.len() >= 12 && sensb_res[0] == 0x50 {
            debug!("received SENSB_RES {}", hex::encode(&sensb_res));
            let mut found = RemoteTarget::new(bitrate)?;
            found.data.sensb_res = Some(sensb_res);
            return Ok(Some(found));
        }

        Ok(None)
    }

    pub fn detect_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<Type3TagPollingResult> {
        let bitrate = target.bitrate();
        ensure_supported_bitrate(bitrate, &["212F", "424F"], "unsupported bitrate ")?;

        debug!("polling for NFC-F technology");

        self.configure_initiator_for_poll(bitrate, &[("initial_guard_time", 24)])?;

        let command = FelicaStandardCommand::Polling {
            system_code,
            request_code,
            time_slots,
        };
        let frame = command
            .to_frame()
            .map_err(|err| DriverError::Other(format!("failed to build SENSF_REQ: {err}")))?;
        debug!("send SENSF_REQ {}", hex::encode(&frame));
        let response = self
            .chipset
            .initiator_exchange_rf(&frame, polling_timeout_ms(time_slots))?;

        match FelicaStandardResponse::from_bytes(&response) {
            Ok(FelicaStandardResponse::Polling { idm, pmm, optional }) => {
                debug!("received SENSF_RES {}", hex::encode(idm));
                Ok(Type3TagPollingResult {
                    idm: idm.to_vec(),
                    pmm: pmm.to_vec(),
                    optional,
                })
            }
            Ok(other) => {
                debug!("unexpected Felica response {:?}", other);
                Err(DriverError::Other("unexpected Felica response".into()))
            }
            Err(err) => {
                debug!("failed to parse Felica response: {}", err);
                Err(DriverError::Other("failed to parse Felica response".into()))
            }
        }
    }

    pub fn detect_dep_passive(&mut self, _target: &RemoteTarget) -> Result<Option<RemoteTarget>> {
        Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
            "device does not support active DEP detect".into(),
        )))
    }
}

fn is_type1_atqa(sens_res: &[u8]) -> bool {
    sens_res
        .first()
        .map(|byte| byte & 0x1F == 0)
        .unwrap_or(false)
}

fn cascade_uid(uid: &[u8]) -> Vec<u8> {
    let mut out = uid.to_vec();
    if out.len() > 4 {
        out.insert(0, 0x88);
    }
    if out.len() > 8 {
        out.insert(4, 0x88);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type1_atqa_and_cascade_uid_helpers_work() {
        assert!(is_type1_atqa(&[0x00, 0x44]));
        assert!(is_type1_atqa(&[0x20]));
        assert!(!is_type1_atqa(&[0x1F]));
        assert!(!is_type1_atqa(&[]));

        assert_eq!(cascade_uid(&[1, 2, 3, 4]), vec![1, 2, 3, 4]);
        assert_eq!(cascade_uid(&[1, 2, 3, 4, 5]), vec![0x88, 1, 2, 3, 4, 5]);
        assert_eq!(
            cascade_uid(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
            vec![0x88, 1, 2, 3, 0x88, 4, 5, 6, 7, 8, 9, 10]
        );
    }
}
