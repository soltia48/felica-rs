use super::device::Device;
use super::errors::{DriverError, Result};
use crate::clf::errors::UnsupportedTargetError;
use crate::clf::targets::{LocalTarget, RemoteTarget};
use crate::felica_standard::{
    FelicaStandardCommand, FelicaStandardResponse, Type3TagPollingResult,
};
use crate::transport::Transport;
use log::{debug, warn};
use std::time::{Duration, Instant};

const DEFAULT_RATS_RESPONSE: [u8; 5] = [0x05, 0x78, 0x80, 0x70, 0x02];

impl<T: Transport> Device<T> {
    pub fn detect_type_a(&mut self, target: &RemoteTarget) -> Result<Option<RemoteTarget>> {
        let brty = target.brty();
        if !matches!(brty, "106A" | "212A" | "424A") {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                format!("unsupported bitrate {}", brty),
            )));
        }

        debug!("polling for NFC-A technology");

        self.chipset.set_initiator_rf(brty, None)?;
        self.chipset.apply_initiator_defaults()?;
        self.chipset.configure_initiator(&[
            ("initial_guard_time", 6),
            ("add_crc", 0),
            ("check_crc", 0),
            ("check_parity", 1),
            ("last_byte_bit_count", 7),
        ])?;

        let sens_req = target.data.sens_req.clone().unwrap_or_else(|| vec![0x26]);

        let sens_res = match self.chipset.initiator_exchange_rf(&sens_req, 30) {
            Ok(data) => data,
            Err(DriverError::Fault(fault)) => {
                if fault.matches("RECEIVE_TIMEOUT_ERROR") {
                    return Ok(None);
                }
                debug!("{}", fault);
                return Ok(None);
            }
            Err(err) => return Err(err),
        };

        if sens_res.len() != 2 {
            return Ok(None);
        }

        debug!("received SENS_RES {}", hex::encode(&sens_res));

        if sens_res[0] & 0x1F == 0 {
            self.chipset.configure_initiator(&[
                ("last_byte_bit_count", 8),
                ("add_crc", 2),
                ("check_crc", 2),
                ("type_1_tag_rrdd", 2),
            ])?;
            let mut found = RemoteTarget::new(brty)?;
            found.data.sens_res = Some(sens_res.clone());
            if sens_res[1] & 0x0F == 0b1100 {
                let rid_cmd = vec![0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                debug!("send RID_CMD {}", hex::encode(&rid_cmd));
                match self.chipset.initiator_exchange_rf(&rid_cmd, 30) {
                    Ok(rid_res) => {
                        found.data.rid_res = Some(rid_res);
                    }
                    Err(DriverError::Fault(fault)) => {
                        debug!("{}", fault);
                        return Ok(None);
                    }
                    Err(err) => return Err(err),
                }
            }
            return Ok(Some(found));
        }

        self.chipset
            .configure_initiator(&[("last_byte_bit_count", 8), ("add_parity", 1)])?;

        let mut sel_res = Vec::new();
        let uid_value: Vec<u8>;

        if let Some(mut uid) = target.data.sel_req.clone() {
            if uid.len() > 4 {
                let mut tmp = vec![0x88];
                tmp.extend_from_slice(&uid);
                uid = tmp;
            }
            if uid.len() > 8 {
                let mut tmp = uid[0..4].to_vec();
                tmp.push(0x88);
                tmp.extend_from_slice(&uid[4..]);
                uid = tmp;
            }
            self.chipset
                .configure_initiator(&[("add_crc", 1), ("check_crc", 1)])?;
            for (sel_cmd, start) in [0x93u8, 0x95, 0x97].iter().zip((0..uid.len()).step_by(4)) {
                let slice_end = (start + 4).min(uid.len());
                let mut sel_req = vec![*sel_cmd, 0x70];
                sel_req.extend_from_slice(&uid[start..slice_end]);
                let bcc = sel_req[2..6.min(sel_req.len())]
                    .iter()
                    .fold(0, |acc, b| acc ^ b);
                sel_req.push(bcc);
                debug!("send SEL_REQ {}", hex::encode(&sel_req));
                match self.chipset.initiator_exchange_rf(&sel_req, 30) {
                    Ok(res) => {
                        sel_res = res;
                        debug!("received SEL_RES {}", hex::encode(&sel_res));
                    }
                    Err(DriverError::Fault(fault)) => {
                        debug!("{}", fault);
                        return Ok(None);
                    }
                    Err(err) => return Err(err),
                }
            }
            uid_value = target.data.sel_req.clone().unwrap_or_default();
        } else {
            let mut uid = Vec::new();
            for sel_cmd in [0x93u8, 0x95, 0x97] {
                self.chipset
                    .configure_initiator(&[("add_crc", 0), ("check_crc", 0)])?;
                let sdd_req = vec![sel_cmd, 0x20];
                debug!("send SDD_REQ {}", hex::encode(&sdd_req));
                let sdd_res = match self.chipset.initiator_exchange_rf(&sdd_req, 30) {
                    Ok(data) => data,
                    Err(DriverError::Fault(fault)) => {
                        debug!("{}", fault);
                        return Ok(None);
                    }
                    Err(err) => return Err(err),
                };
                debug!("received SDD_RES {}", hex::encode(&sdd_res));
                self.chipset
                    .configure_initiator(&[("add_crc", 1), ("check_crc", 1)])?;
                let mut sel_req = vec![sel_cmd, 0x70];
                sel_req.extend_from_slice(&sdd_res);
                debug!("send SEL_REQ {}", hex::encode(&sel_req));
                match self.chipset.initiator_exchange_rf(&sel_req, 30) {
                    Ok(res) => {
                        sel_res = res.clone();
                        debug!("received SEL_RES {}", hex::encode(&sel_res));
                    }
                    Err(DriverError::Fault(fault)) => {
                        debug!("{}", fault);
                        return Ok(None);
                    }
                    Err(err) => return Err(err),
                }
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
            uid_value = uid;
        }

        if !sel_res.is_empty() && (sel_res[0] & 0b0000_0100) == 0 {
            let mut found = RemoteTarget::new(brty)?;
            found.data.sens_res = Some(sens_res);
            found.data.sel_res = Some(sel_res);
            found.data.sdd_res = Some(uid_value);
            return Ok(Some(found));
        }

        Ok(None)
    }

    pub fn detect_type_b(&mut self, target: &RemoteTarget) -> Result<Option<RemoteTarget>> {
        let brty = target.brty();
        if !matches!(brty, "106B" | "212B" | "424B") {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                format!("unsupported bitrate {}", brty),
            )));
        }

        debug!("polling for NFC-B technology");

        self.chipset.set_initiator_rf(brty, None)?;
        self.chipset.apply_initiator_defaults()?;
        self.chipset.configure_initiator(&[
            ("initial_guard_time", 20),
            ("add_sof", 1),
            ("check_sof", 1),
            ("add_eof", 1),
            ("check_eof", 1),
        ])?;

        let sensb_req = target
            .data
            .sensb_req
            .clone()
            .unwrap_or_else(|| vec![0x05, 0x00, 0x10]);
        debug!("send SENSB_REQ {}", hex::encode(&sensb_req));

        let sensb_res = match self.chipset.initiator_exchange_rf(&sensb_req, 30) {
            Ok(data) => data,
            Err(DriverError::Fault(fault)) => {
                if fault.matches("RECEIVE_TIMEOUT_ERROR") {
                    return Ok(None);
                }
                debug!("{}", fault);
                return Ok(None);
            }
            Err(err) => return Err(err),
        };

        if sensb_res.len() >= 12 && sensb_res[0] == 0x50 {
            debug!("received SENSB_RES {}", hex::encode(&sensb_res));
            let mut found = RemoteTarget::new(brty)?;
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
        let brty = target.brty();
        if !matches!(brty, "212F" | "424F") {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                format!("unsupported bitrate {}", brty),
            )));
        }

        debug!("polling for NFC-F technology");

        self.chipset.set_initiator_rf(brty, None)?;
        self.chipset.apply_initiator_defaults()?;
        self.chipset
            .configure_initiator(&[("initial_guard_time", 24)])?;

        let timeout_ms = ((0.003625_f32 + time_slots as f32 * 0.001208_f32) * 1000.0).ceil();
        let command = FelicaStandardCommand::Polling {
            system_code,
            request_code,
            time_slots,
        };
        let frame = command.to_frame();
        debug!("send SENSF_REQ {}", hex::encode(&frame));
        let response = match self
            .chipset
            .initiator_exchange_rf(&frame, timeout_ms as u16)
        {
            Ok(data) => data,
            Err(err) => return Err(err),
        };

        match FelicaStandardResponse::from_bytes(&response) {
            Ok(FelicaStandardResponse::Polling { idm, pmm, optional }) => {
                debug!("received SENSF_RES {}", hex::encode(&idm));
                Ok(Type3TagPollingResult { idm, pmm, optional })
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

    pub fn sense_dep_passive(&mut self, _target: &RemoteTarget) -> Result<Option<RemoteTarget>> {
        Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
            "device does not support active DEP sense".into(),
        )))
    }

    pub fn listen_type_a(
        &mut self,
        target: &LocalTarget,
        timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        if target.brty_send() != "106A" {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                format!("unsupported target bitrate: {}", target.brty()),
            )));
        }
        if target.data.rid_res.is_some() {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                "listening for type 1 tag activation is not supported".into(),
            )));
        }
        let nfca_params = nfca_params_from_local(target)?;
        debug!("nfca_params {}", hex::encode(&nfca_params));

        self.chipset.set_target_rf("106A")?;
        self.chipset.apply_target_defaults()?;
        self.chipset.configure_target(&[("rf_off_error", 0)])?;

        let sel_res_byte = target
            .data
            .sel_res
            .as_ref()
            .and_then(|bytes| bytes.first())
            .copied()
            .ok_or_else(|| DriverError::Other("sel_res is required".into()))?;

        if sel_res_byte & 0x60 == 0x00 {
            return self.listen_type_a_tt2(&nfca_params, timeout);
        }
        if sel_res_byte & 0x20 == 0x20 {
            return self.listen_type_a_tt4(target, &nfca_params, timeout);
        }

        Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
            "sel_res does not indicate any tag support".into(),
        )))
    }

    pub fn listen_type_b(
        &mut self,
        target: &LocalTarget,
        _timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
            format!("{} does not support listen as Type B Target", target.brty()),
        )))
    }

    pub fn listen_type_f(
        &mut self,
        target: &LocalTarget,
        timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        if !matches!(target.brty_send(), "212F" | "424F") {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                format!("unsupported target bitrate: {}", target.brty()),
            )));
        }
        let sensf_res = ensure_sensf_res(target)?;

        self.chipset.set_target_rf(target.brty_send())?;
        self.chipset.apply_target_defaults()?;
        self.chipset.configure_target(&[("rf_off_error", 0)])?;

        self.listen_type_f_loop(target, sensf_res, timeout)
    }

    pub fn listen_dep(
        &mut self,
        target: &LocalTarget,
        timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        debug!("listen_dep for {:.3} sec", timeout);
        let nfca_params = nfca_params_from_local(target)?;
        let sensf_res = target
            .data
            .sensf_res
            .as_ref()
            .ok_or_else(|| DriverError::Other("sensf_res is required".into()))?;
        if sensf_res.len() < 19 {
            return Err(DriverError::Other(
                "sensf_res must be at least 19 bytes".into(),
            ));
        }
        let nfcf_params = sensf_res[1..19].to_vec();
        if target.data.atr_res.as_ref().map(|v| v.len()).unwrap_or(0) < 17 {
            return Err(DriverError::Other(
                "atr_res is required and must be >= 17 bytes".into(),
            ));
        }

        self.chipset.set_target_rf("106A")?;
        self.chipset.apply_target_defaults()?;
        self.chipset.configure_target(&[("rf_off_error", 0)])?;

        self.listen_dep_loop(target, nfca_params, nfcf_params, timeout)
    }

    fn listen_type_a_tt2(
        &mut self,
        nfca_params: &[u8],
        timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        let Some((mut recv_timeout, deadline)) = start_timeout_window(timeout) else {
            return Ok(None);
        };
        while recv_timeout > 0 {
            debug!("wait {} ms for Type 2 Tag activation", recv_timeout);
            match self.chipset.target_exchange_rf(
                0,
                0xFFFF,
                true,
                nfca_params,
                &[],
                false,
                false,
                recv_timeout,
                None,
            ) {
                Ok(data) => {
                    let bitrate = data.get(0).and_then(|&v| decode_target_bitrate(v));
                    let payload = data.get(7..).unwrap_or(&[]);
                    if bitrate == Some("106A")
                        && data.get(2).map(|value| value & 0x03 == 3).unwrap_or(false)
                    {
                        debug!("106A received {}", hex::encode(payload));
                        self.chipset.configure_target(&[("rf_off_error", 1)])?;
                        let mut local = self.build_local_nfca_target(nfca_params)?;
                        local.data.tt2_cmd = Some(payload.to_vec());
                        return Ok(Some(local));
                    }
                }
                Err(DriverError::Fault(fault)) => {
                    debug!("{}", fault);
                }
                Err(err) => return Err(err),
            }
            recv_timeout = remaining_timeout(deadline);
        }
        Ok(None)
    }

    fn listen_type_a_tt4(
        &mut self,
        target: &LocalTarget,
        nfca_params: &[u8],
        timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        let Some((mut recv_timeout, deadline)) = start_timeout_window(timeout) else {
            return Ok(None);
        };
        let mut transmit_data: Option<Vec<u8>> = None;
        let mut rats_cmd: Option<Vec<u8>> = None;
        let mut rats_res: Option<Vec<u8>> = None;

        while recv_timeout > 0 {
            debug!("wait {} ms for 106A TT4 command", recv_timeout);
            let payload = transmit_data.as_deref();
            let result = self.chipset.target_exchange_rf(
                0,
                0xFFFF,
                true,
                nfca_params,
                &[],
                false,
                false,
                recv_timeout,
                payload,
            );
            transmit_data = None;

            match result {
                Ok(data) => {
                    let bitrate = data.get(0).and_then(|&v| decode_target_bitrate(v));
                    let frame = data.get(7..).unwrap_or(&[]);
                    debug!(
                        "{} received {}",
                        bitrate.unwrap_or("unknown bitrate"),
                        hex::encode(frame)
                    );
                    if bitrate == Some("106A")
                        && data.get(2) == Some(&3)
                        && frame.first() == Some(&0xE0)
                    {
                        rats_cmd = Some(frame.to_vec());
                        rats_res = target
                            .data
                            .rats_res
                            .clone()
                            .or_else(|| Some(DEFAULT_RATS_RESPONSE.to_vec()));
                        if let Some(ref rsp) = rats_res {
                            debug!("send RATS_RES {}", hex::encode(rsp));
                            transmit_data = Some(rsp.clone());
                        }
                    } else if bitrate == Some("106A")
                        && !frame.is_empty()
                        && frame[0] != 0xF0
                        && rats_cmd.is_some()
                    {
                        if let (Some(cmd), Some(res)) = (rats_cmd.clone(), rats_res.clone()) {
                            if self.is_valid_tt4_command(&cmd, &res, frame) {
                                if matches!(frame.first(), Some(0xC2) | Some(0xCA)) {
                                    debug!("received S(DESELECT) {}", hex::encode(frame));
                                    transmit_data = Some(frame.to_vec());
                                    rats_cmd = None;
                                    rats_res = None;
                                } else {
                                    debug!("received TT4_CMD {}", hex::encode(frame));
                                    self.chipset.configure_target(&[("rf_off_error", 1)])?;
                                    let mut local = self.build_local_nfca_target(nfca_params)?;
                                    local.data.tt4_cmd = Some(frame.to_vec());
                                    local.data.rats_cmd = Some(cmd);
                                    local.data.rats_res = Some(res);
                                    return Ok(Some(local));
                                }
                            } else {
                                debug!("skip TT4_CMD {} (DID)", hex::encode(frame));
                            }
                        }
                    }
                }
                Err(DriverError::Fault(fault)) => {
                    debug!("{}", fault);
                    rats_cmd = None;
                    rats_res = None;
                }
                Err(err) => return Err(err),
            }

            recv_timeout = remaining_timeout(deadline);
        }

        Ok(None)
    }

    fn is_valid_tt4_command(&self, rats_cmd: &[u8], rats_res: &[u8], cmd: &[u8]) -> bool {
        if rats_cmd.len() < 2 || cmd.is_empty() {
            return false;
        }
        let did = rats_cmd[1] & 0x0F;
        let mut params = rats_res[2..].to_vec();
        let ta = if rats_res[1] & 0x10 != 0 && !params.is_empty() {
            Some(params.remove(0))
        } else {
            None
        };
        let tb = if rats_res[1] & 0x20 != 0 && !params.is_empty() {
            Some(params.remove(0))
        } else {
            None
        };
        let tc = if rats_res[1] & 0x40 != 0 && !params.is_empty() {
            Some(params.remove(0))
        } else {
            None
        };
        if let Some(value) = ta {
            debug!("TA(1) = {:08b}", value);
        }
        if let Some(value) = tb {
            debug!("TB(1) = {:08b}", value);
        }
        if let Some(value) = tc {
            debug!("TC(1) = {:08b}", value);
        }
        if !params.is_empty() {
            debug!("T({}) = {}", params.len(), hex::encode(params));
        }
        let did_supported = tc.map(|value| value & 0x02 != 0).unwrap_or(true);
        let cmd_with_did = cmd.get(0).map(|value| value & 0x08 != 0).unwrap_or(false);
        (cmd_with_did && did_supported && cmd.get(1).copied() == Some(did))
            || (did == 0 && !cmd_with_did)
    }

    fn build_local_nfca_target(&self, nfca_params: &[u8]) -> Result<LocalTarget> {
        let mut target = LocalTarget::new("106A")?;
        target.data.sens_res = Some(nfca_params[0..2].to_vec());
        let mut sdd = vec![0x08];
        sdd.extend_from_slice(&nfca_params[2..5]);
        target.data.sdd_res = Some(sdd);
        target.data.sel_res = Some(nfca_params[5..6].to_vec());
        Ok(target)
    }

    fn listen_type_f_loop(
        &mut self,
        target: &LocalTarget,
        sensf_res: Vec<u8>,
        timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        let Some((mut recv_timeout, deadline)) = start_timeout_window(timeout) else {
            return Ok(None);
        };
        let mut transmit_data: Option<Vec<u8>> = None;
        let mut sensf_req: Option<Vec<u8>> = None;

        while recv_timeout > 0 {
            if let Some(ref data) = transmit_data {
                debug!("{} send {}", target.brty(), hex::encode(data));
            }
            debug!("{} wait recv {} ms", target.brty(), recv_timeout);
            let response = self.chipset.target_exchange_rf(
                0,
                0xFFFF,
                false,
                &[],
                &[],
                false,
                false,
                recv_timeout,
                transmit_data.as_deref(),
            );
            transmit_data = None;

            let data = match response {
                Ok(value) => value,
                Err(DriverError::Fault(fault)) => {
                    debug!("{}", fault);
                    recv_timeout = remaining_timeout(deadline);
                    continue;
                }
                Err(err) => return Err(err),
            };

            let brty = data
                .get(0)
                .and_then(|&code| decode_target_bitrate(code))
                .unwrap_or("unknown bitrate");
            let frame = data.get(7..).unwrap_or(&[]);
            debug!("{} received {}", brty, hex::encode(frame));

            if frame.len() > 0 && frame.len() == frame[0] as usize {
                if let Some(ref req) = sensf_req {
                    if frame.len() >= 18 && frame.len() > 10 && frame[2..10] == sensf_res[1..9] {
                        self.chipset.configure_target(&[("rf_off_error", 1)])?;
                        let mut local = LocalTarget::new(target.brty_send())?;
                        local.data.sensf_req = Some(req.clone());
                        local.data.sensf_res = Some(sensf_res.clone());
                        local.data.tt3_cmd = Some(frame[1..].to_vec());
                        return Ok(Some(local));
                    }
                }
            }

            if data.len() == 13 && data.get(7) == Some(&6) && data.get(8) == Some(&0) {
                let req = frame.to_vec();
                if (req[1] == 0xFF || req[1] == sensf_res[17])
                    && (req[2] == 0xFF || req[2] == sensf_res[18])
                {
                    sensf_req = Some(req);
                    let mut tx = sensf_res[0..17].to_vec();
                    if frame.get(3) == Some(&1) {
                        tx.extend_from_slice(&sensf_res[17..19]);
                    } else if frame.get(3) == Some(&2) {
                        tx.push(0x00);
                        tx.push(if target.brty_send() == "424F" {
                            0x02
                        } else {
                            0x01
                        });
                    }
                    let mut full = Vec::with_capacity(tx.len() + 1);
                    full.push((tx.len() + 1) as u8);
                    full.extend_from_slice(&tx);
                    transmit_data = Some(full);
                }
            }

            recv_timeout = remaining_timeout(deadline);
        }

        Ok(None)
    }

    fn listen_dep_loop(
        &mut self,
        target: &LocalTarget,
        nfca_params: Vec<u8>,
        nfcf_params: Vec<u8>,
        timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        let Some((mut recv_timeout, deadline)) = start_timeout_window(timeout) else {
            return Ok(None);
        };
        let mut activation_frame = None;
        let mut activation_bitrate = String::from("106A");

        while recv_timeout > 0 {
            debug!("wait {} ms for activation", recv_timeout);
            match self.chipset.target_exchange_rf(
                0,
                0xFFFF,
                true,
                &nfca_params,
                &nfcf_params,
                false,
                false,
                recv_timeout,
                None,
            ) {
                Ok(data) => {
                    let brty = data.get(0).and_then(|&v| decode_target_bitrate(v));
                    debug!(
                        "{} {}",
                        brty.unwrap_or("unknown bitrate"),
                        hex::encode(&data)
                    );
                    if data.get(2).map(|value| value & 0x03 == 3).unwrap_or(false) {
                        activation_frame = Some(data.get(7..).unwrap_or(&[]).to_vec());
                        activation_bitrate = brty.unwrap_or("106A").to_string();
                        break;
                    }
                }
                Err(DriverError::Fault(fault)) => {
                    if !fault.matches("RECEIVE_TIMEOUT_ERROR") {
                        warn!("{}", fault);
                    }
                }
                Err(err) => return Err(err),
            }
            recv_timeout = remaining_timeout(deadline);
        }

        let frame = match activation_frame {
            Some(data) => data,
            None => return Ok(None),
        };

        self.chipset.configure_target(&[("rf_off_error", 1)])?;

        if activation_bitrate == "106A" && frame.len() > 1 && frame[0] != 0xF0 {
            let mut local = self.build_local_nfca_target(&nfca_params)?;
            local.data.tt2_cmd = Some(frame);
            return Ok(Some(local));
        }

        let mut data = self
            .dep_verify_frame(&activation_bitrate, &frame, &[0])
            .map(|f| f.to_vec());
        let activation_params = if activation_bitrate == "106A" {
            nfca_params.clone()
        } else {
            nfcf_params.clone()
        };
        let mut atr_req = Vec::new();

        while let Some(current) = data.clone() {
            if current.get(1) != Some(&0) {
                break;
            }
            atr_req = current.clone();
            if !(16..=64).contains(&current.len()) {
                warn!("ATR_REQ must be 16 to 64 byte");
                data = None;
                break;
            }
            let atr_res = target
                .data
                .atr_res
                .as_ref()
                .ok_or_else(|| DriverError::Other("atr_res is required".into()))?
                .clone();
            debug!(
                "{} received ATR_REQ {}",
                activation_bitrate,
                hex::encode(&atr_req)
            );
            debug!(
                "{} send ATR_RES {}",
                activation_bitrate,
                hex::encode(&atr_res)
            );
            data = self.dep_send_frame(&activation_bitrate, Some(&atr_res), 1000)?;
        }

        let mut psl_req: Option<Vec<u8>> = None;
        while let Some(current) = data.clone() {
            match current.get(1).copied() {
                Some(4) => {
                    if let Some(new_brty) = self.dep_handle_psl(&activation_bitrate, &current)? {
                        activation_bitrate = new_brty.0;
                        psl_req = Some(new_brty.1);
                    }
                }
                Some(6) => {
                    let did = atr_req.get(12).copied().filter(|value| *value > 0);
                    let recv_did = if current.get(2).map(|v| v >> 2 & 1).unwrap_or(0) != 0 {
                        current.get(3).copied()
                    } else {
                        None
                    };
                    if did == recv_did {
                        let mut local = LocalTarget::new(&activation_bitrate)?;
                        local.data.dep_req = Some(current.clone());
                        local.data.atr_req = Some(atr_req.clone());
                        if let Some(psl) = psl_req.clone() {
                            local.data.psl_req = Some(psl);
                        }
                        if activation_params == nfca_params {
                            local.data.sens_res = Some(activation_params[0..2].to_vec());
                            let mut sdd = vec![0x08];
                            sdd.extend_from_slice(&activation_params[2..5]);
                            local.data.sdd_res = Some(sdd);
                            local.data.sel_res = Some(activation_params[5..6].to_vec());
                        } else {
                            let mut sensf = vec![0x01];
                            sensf.extend_from_slice(&activation_params);
                            local.data.sensf_res = Some(sensf);
                        }
                        return Ok(Some(local));
                    }
                }
                Some(8) => {
                    self.dep_send_simple_response(&activation_bitrate, 0x09, &current)?;
                    return Ok(None);
                }
                Some(10) => {
                    self.dep_send_simple_response(&activation_bitrate, 0x0B, &current)?;
                    return Ok(None);
                }
                Some(_) => {}
                None => break,
            }
            data = self.dep_send_frame(&activation_bitrate, None, 1000)?;
        }

        Ok(None)
    }
}

fn decode_target_bitrate(value: u8) -> Option<&'static str> {
    match value.checked_sub(11) {
        Some(0) => Some("106A"),
        Some(1) => Some("212F"),
        Some(2) => Some("424F"),
        _ => None,
    }
}

fn clamp_timeout(timeout: f32) -> u16 {
    if timeout <= 0.0 {
        0
    } else {
        let ms = (timeout * 1000.0).round() as i32;
        ms.clamp(1, 0xFFFF) as u16
    }
}

fn start_timeout_window(timeout: f32) -> Option<(u16, Instant)> {
    let recv_timeout = clamp_timeout(timeout);
    if recv_timeout == 0 {
        return None;
    }
    let seconds = timeout.max(0.0);
    let deadline = Instant::now() + Duration::from_secs_f32(seconds);
    Some((recv_timeout, deadline))
}

fn remaining_timeout(deadline: Instant) -> u16 {
    if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let ms = remaining.as_millis().min(u16::MAX as u128) as u16;
        ms
    } else {
        0
    }
}

fn nfca_params_from_local(target: &LocalTarget) -> Result<Vec<u8>> {
    let sens_res = expect_exact_field(target.data.sens_res.as_ref(), "sens_res", 2)?;
    let sdd_res = expect_exact_field(target.data.sdd_res.as_ref(), "sdd_res", 4)?;
    if sdd_res[0] != 0x08 {
        return Err(DriverError::Other("sdd_res[0] must be 0x08".into()));
    }
    let sel_res = expect_exact_field(target.data.sel_res.as_ref(), "sel_res", 1)?;
    let mut params = Vec::with_capacity(6);
    params.extend_from_slice(sens_res);
    params.extend_from_slice(&sdd_res[1..4]);
    params.extend_from_slice(sel_res);
    Ok(params)
}

fn expect_exact_field<'a>(
    field: Option<&'a Vec<u8>>,
    name: &str,
    expected_len: usize,
) -> Result<&'a [u8]> {
    let value = field.ok_or_else(|| DriverError::Other(format!("{name} is required")))?;
    if value.len() != expected_len {
        return Err(DriverError::Other(format!(
            "{name} must be {expected_len} bytes"
        )));
    }
    Ok(value)
}

fn ensure_sensf_res(target: &LocalTarget) -> Result<Vec<u8>> {
    let sensf_res = target
        .data
        .sensf_res
        .as_ref()
        .ok_or_else(|| DriverError::Other("sensf_res is required".into()))?;
    if sensf_res.len() != 19 {
        return Err(DriverError::Other("sensf_res must be 19 bytes".into()));
    }
    Ok(sensf_res.clone())
}
