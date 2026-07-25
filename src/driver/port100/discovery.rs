use crate::clf::errors::UnsupportedTargetError;
use crate::clf::targets::{LocalTarget, RemoteTarget};
use crate::driver::errors::{ChipsetError, DriverError, Result};
use crate::driver::port100::device::Device;
use crate::felica_standard::{
    FelicaStandardCommand, FelicaStandardResponse, Type3TagPollingResult,
};
use crate::transport::Transport;
use log::{debug, warn};
use std::time::{Duration, Instant};

const DEFAULT_RATS_RESPONSE: [u8; 5] = [0x05, 0x78, 0x80, 0x70, 0x02];

#[derive(Debug, Clone)]
pub struct SensfRequest {
    pub system_code: u16,
    pub request_code: u8,
    pub time_slots: u8,
    pub raw: Vec<u8>,
}

impl SensfRequest {
    fn from_frame(frame: &[u8]) -> Option<Self> {
        if frame.len() < 6 || frame.get(1) != Some(&0x00) {
            return None;
        }
        Some(Self {
            system_code: u16::from_be_bytes([frame[2], frame[3]]),
            request_code: frame[4],
            time_slots: frame[5],
            raw: frame.to_vec(),
        })
    }
}

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

        let timeout_ms = ((0.003625_f32 + time_slots as f32 * 0.001208_f32) * 1000.0).ceil();
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
            .initiator_exchange_rf(&frame, timeout_ms as u16)?;

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

    pub fn listen_type_a(
        &mut self,
        target: &LocalTarget,
        timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        ensure_supported_bitrate(
            target.bitrate_send(),
            &["106A"],
            "unsupported target bitrate: ",
        )?;
        if target.data.rid_res.is_some() {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                "listening for type 1 tag activation is not supported".into(),
            )));
        }
        let nfca_params = nfca_params_from_local(target)?;
        debug!("nfca_params {}", hex::encode(&nfca_params));

        self.configure_target_for_listen("106A")?;

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
            format!(
                "{} does not support listen as Type B Target",
                target.bitrate()
            ),
        )))
    }

    /// Listen for NFC-F and respond to SENSF_REQ frames using the provided responder.
    /// The responder receives a parsed SENSF_REQ and should return the polling result
    /// (IDm/PMm/optional bytes) to use in the SENSF_RES response.
    pub fn listen_type_f<F>(
        &mut self,
        target: &LocalTarget,
        timeout: f32,
        responder: F,
    ) -> Result<Option<LocalTarget>>
    where
        F: FnMut(&SensfRequest) -> Option<Type3TagPollingResult>,
    {
        ensure_supported_bitrate(
            target.bitrate_send(),
            &["212F", "424F"],
            "unsupported target bitrate: ",
        )?;

        self.configure_target_for_listen(target.bitrate_send())?;

        self.listen_type_f_loop(target, timeout, responder)
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

        self.configure_target_for_listen("106A")?;

        self.listen_dep_loop(target, nfca_params, nfcf_params, timeout)
    }

    fn listen_type_a_tt2(
        &mut self,
        nfca_params: &[u8],
        timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        self.run_timeout_loop(timeout, |device, recv_timeout, _| {
            debug!("wait {} ms for Type 2 Tag activation", recv_timeout);
            match device.target_exchange_default(true, nfca_params, &[], recv_timeout, None) {
                Ok(data) => {
                    let exchange = ExchangeView::new(&data);
                    let bitrate = exchange.bitrate();
                    let payload = exchange.payload();
                    if matches!(bitrate, Bitrate::A106) && exchange.is_activation_frame() {
                        debug!("106A received {}", hex::encode(payload));
                        device.chipset.configure_target(&[("rf_off_error", 1)])?;
                        let mut local = device.build_local_nfca_target(nfca_params)?;
                        local.data.tt2_cmd = Some(payload.to_vec());
                        return Ok(Some(local));
                    }
                }
                Err(DriverError::Chipset(ChipsetError::Fault(fault))) => {
                    debug!("{}", fault);
                }
                Err(err) => return Err(err),
            }
            Ok(None)
        })
    }

    fn listen_type_a_tt4(
        &mut self,
        target: &LocalTarget,
        nfca_params: &[u8],
        timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        let mut session = Tt4Session::new();

        self.run_timeout_loop(timeout, |device, recv_timeout, _| {
            debug!("wait {} ms for 106A TT4 command", recv_timeout);
            let payload = session.take_response();
            let result = device.target_exchange_default(
                true,
                nfca_params,
                &[],
                recv_timeout,
                payload.as_deref(),
            );

            match result {
                Ok(data) => {
                    let exchange = ExchangeView::new(&data);
                    debug!(
                        "{} received {}",
                        exchange.bitrate().as_str(),
                        hex::encode(exchange.payload())
                    );
                    match device.handle_tt4_frame(target, nfca_params, &mut session, &exchange)? {
                        Tt4Step::QueueResponse(bytes) => session.queue_response(bytes),
                        Tt4Step::Found(local) => return Ok(Some(local)),
                        Tt4Step::Continue => {}
                    }
                }
                Err(DriverError::Chipset(ChipsetError::Fault(fault))) => {
                    debug!("{}", fault);
                    session.clear();
                }
                Err(err) => return Err(err),
            }

            Ok(None)
        })
    }

    fn handle_tt4_frame(
        &mut self,
        target: &LocalTarget,
        nfca_params: &[u8],
        session: &mut Tt4Session,
        exchange: &ExchangeView<'_>,
    ) -> Result<Tt4Step> {
        if !matches!(exchange.bitrate(), Bitrate::A106) {
            return Ok(Tt4Step::Continue);
        }

        let frame = exchange.payload();

        if exchange.is_activation_frame() && frame.first() == Some(&0xE0) {
            let rats_res = target
                .data
                .rats_res
                .clone()
                .unwrap_or_else(|| DEFAULT_RATS_RESPONSE.to_vec());
            session.start(frame.to_vec(), rats_res.clone());
            debug!("send RATS_RES {}", hex::encode(&rats_res));
            return Ok(Tt4Step::QueueResponse(rats_res));
        }

        if frame.is_empty() || frame[0] == 0xF0 || !session.has_session() {
            return Ok(Tt4Step::Continue);
        }

        let (rats_cmd, rats_res) = match session.rats() {
            Some(value) => value,
            None => return Ok(Tt4Step::Continue),
        };

        if !is_valid_tt4_command(rats_cmd, rats_res, frame) {
            debug!("skip TT4_CMD {} (DID)", hex::encode(frame));
            return Ok(Tt4Step::Continue);
        }

        if matches!(frame.first(), Some(0xC2) | Some(0xCA)) {
            debug!("received S(DESELECT) {}", hex::encode(frame));
            session.clear();
            return Ok(Tt4Step::QueueResponse(frame.to_vec()));
        }

        debug!("received TT4_CMD {}", hex::encode(frame));
        self.chipset.configure_target(&[("rf_off_error", 1)])?;
        let mut local = self.build_local_nfca_target(nfca_params)?;
        local.data.tt4_cmd = Some(frame.to_vec());
        local.data.rats_cmd = Some(rats_cmd.to_vec());
        local.data.rats_res = Some(rats_res.to_vec());
        session.clear();
        Ok(Tt4Step::Found(local))
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

    fn listen_type_f_loop<F>(
        &mut self,
        target: &LocalTarget,
        timeout: f32,
        mut responder: F,
    ) -> Result<Option<LocalTarget>>
    where
        F: FnMut(&SensfRequest) -> Option<Type3TagPollingResult>,
    {
        let mut transmit_data: Option<Vec<u8>> = None;
        let mut sensf_req: Option<SensfRequest> = None;
        let mut sensf_res: Option<Type3TagPollingResult> = None;

        self.run_timeout_loop(timeout, |device, recv_timeout, _| {
            if let Some(ref data) = transmit_data {
                debug!("{} send {}", target.bitrate(), hex::encode(data));
            }
            debug!("{} wait recv {} ms", target.bitrate(), recv_timeout);
            let response = device.target_exchange_default(
                false,
                &[],
                &[],
                recv_timeout,
                transmit_data.as_deref(),
            );
            transmit_data = None;

            let data = match response {
                Ok(value) => value,
                Err(DriverError::Chipset(ChipsetError::Fault(fault))) => {
                    debug!("{}", fault);
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };

            let exchange = ExchangeView::new(&data);
            debug!(
                "{} received {}",
                exchange.bitrate().as_str(),
                hex::encode(exchange.payload())
            );

            let frame = exchange.payload();

            if exchange.len_matches_len_byte()
                && let Some(ref req) = sensf_req
                && let Some(ref res) = sensf_res
                && frame.get(2..10) == Some(res.idm.as_slice())
            {
                device.chipset.configure_target(&[("rf_off_error", 1)])?;
                let mut local = LocalTarget::new(target.bitrate_send())?;
                local.data.sensf_req = Some(req.raw.clone());
                local.data.sensf_res = Some(build_sensf_res_payload(
                    res,
                    req.request_code,
                    target.bitrate_send(),
                ));
                local.data.tt3_cmd = Some(frame.to_vec());
                return Ok(Some(local));
            }

            if exchange.len_matches_len_byte() && frame.len() >= 10 && frame.get(1) != Some(&0x00) {
                if sensf_req.is_none() {
                    debug!(
                        "accepting TT3 command without SENSF_REQ (idm {})",
                        hex::encode(&frame[2..10])
                    );
                } else if let Some(ref res) = sensf_res
                    && frame.get(2..10) != Some(res.idm.as_slice())
                {
                    debug!(
                        "accepting TT3 command with IDm mismatch (req {}, expected {})",
                        hex::encode(&frame[2..10]),
                        hex::encode(&res.idm)
                    );
                }
                device.chipset.configure_target(&[("rf_off_error", 1)])?;
                let mut local = LocalTarget::new(target.bitrate_send())?;
                local.data.sensf_req = sensf_req.as_ref().map(|req| req.raw.clone());
                if let (Some(req), Some(res)) = (sensf_req.as_ref(), sensf_res.as_ref()) {
                    local.data.sensf_res = Some(build_sensf_res_payload(
                        res,
                        req.request_code,
                        target.bitrate_send(),
                    ));
                }
                local.data.tt3_cmd = Some(frame.to_vec());
                return Ok(Some(local));
            }

            if exchange.raw().len() == 13
                && exchange.raw().get(7) == Some(&6)
                && exchange.raw().get(8) == Some(&0)
                && let Some(req) = SensfRequest::from_frame(frame)
                && let Some(res) = responder(&req)
            {
                let tx = build_sensf_res_payload(&res, req.request_code, target.bitrate_send());
                sensf_req = Some(req);
                sensf_res = Some(res);
                let mut full = Vec::with_capacity(tx.len() + 1);
                full.push((tx.len() + 1) as u8);
                full.extend_from_slice(&tx);
                transmit_data = Some(full);
            }

            Ok(None)
        })
    }

    fn listen_dep_loop(
        &mut self,
        target: &LocalTarget,
        nfca_params: Vec<u8>,
        nfcf_params: Vec<u8>,
        timeout: f32,
    ) -> Result<Option<LocalTarget>> {
        let activation = self.await_dep_activation(timeout, &nfca_params, &nfcf_params)?;
        let (activation_bitrate, frame) = match activation {
            Some(value) => value,
            None => return Ok(None),
        };
        self.handle_dep_activation(target, activation_bitrate, frame, nfca_params, nfcf_params)
    }

    fn configure_initiator_for_poll(&mut self, bitrate: &str, params: &[(&str, u8)]) -> Result<()> {
        self.chipset.set_initiator_rf(bitrate, None)?;
        self.chipset.apply_initiator_defaults()?;
        if !params.is_empty() {
            self.chipset.configure_initiator(params)?;
        }
        Ok(())
    }

    fn configure_target_for_listen(&mut self, bitrate: &str) -> Result<()> {
        self.chipset.set_target_rf(bitrate)?;
        self.chipset.apply_target_defaults()?;
        self.chipset.configure_target(&[("rf_off_error", 0)])
    }

    fn run_timeout_loop<R, F>(&mut self, timeout: f32, mut step: F) -> Result<Option<R>>
    where
        F: FnMut(&mut Self, u16, Instant) -> Result<Option<R>>,
    {
        let Some(mut window) = TimeoutWindow::new(timeout) else {
            return Ok(None);
        };
        while window.active() {
            if let Some(outcome) = step(self, window.remaining(), window.deadline())? {
                return Ok(Some(outcome));
            }
            window.refresh();
        }
        Ok(None)
    }

    fn target_exchange_default(
        &mut self,
        mdaa: bool,
        nfca_params: &[u8],
        nfcf_params: &[u8],
        timeout: u16,
        payload: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.chipset.target_exchange_rf(
            0,
            0xFFFF,
            mdaa,
            nfca_params,
            nfcf_params,
            false,
            false,
            timeout,
            payload,
        )
    }

    fn initiator_exchange_optional(
        &mut self,
        payload: &[u8],
        timeout: u16,
        context: &str,
        log_timeouts: bool,
    ) -> Result<Option<Vec<u8>>> {
        match self.chipset.initiator_exchange_rf(payload, timeout) {
            Ok(data) => Ok(Some(data)),
            Err(DriverError::Chipset(ChipsetError::Fault(fault))) => {
                let is_timeout = fault.matches("RECEIVE_TIMEOUT_ERROR");
                if log_timeouts || !is_timeout {
                    debug!("{}: {}", context, fault);
                }
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    fn await_dep_activation(
        &mut self,
        timeout: f32,
        nfca_params: &[u8],
        nfcf_params: &[u8],
    ) -> Result<Option<(Bitrate, Vec<u8>)>> {
        let mut activation_bitrate = Bitrate::A106;
        let frame = self.run_timeout_loop(timeout, |device, recv_timeout, _| {
            debug!("wait {} ms for activation", recv_timeout);
            match device.target_exchange_default(true, nfca_params, nfcf_params, recv_timeout, None)
            {
                Ok(data) => {
                    let exchange = ExchangeView::new(&data);
                    debug!("{} {}", exchange.bitrate().as_str(), hex::encode(&data));
                    if exchange.is_activation_frame() {
                        activation_bitrate = exchange.bitrate();
                        return Ok(Some(exchange.payload().to_vec()));
                    }
                }
                Err(DriverError::Chipset(ChipsetError::Fault(fault))) => {
                    if !fault.matches("RECEIVE_TIMEOUT_ERROR") {
                        warn!("{}", fault);
                    }
                }
                Err(err) => return Err(err),
            }
            Ok(None)
        })?;
        Ok(frame.map(|data| (activation_bitrate, data)))
    }

    fn handle_dep_activation(
        &mut self,
        target: &LocalTarget,
        activation_bitrate: Bitrate,
        frame: Vec<u8>,
        nfca_params: Vec<u8>,
        nfcf_params: Vec<u8>,
    ) -> Result<Option<LocalTarget>> {
        self.chipset.configure_target(&[("rf_off_error", 1)])?;
        if matches!(activation_bitrate, Bitrate::A106) && frame.len() > 1 && frame[0] != 0xF0 {
            let mut local = self.build_local_nfca_target(&nfca_params)?;
            local.data.tt2_cmd = Some(frame);
            return Ok(Some(local));
        }

        let mut data = self
            .dep_verify_frame(activation_bitrate.as_str(), &frame, &[0])
            .map(|f| f.payload);
        let activation_params = if matches!(activation_bitrate, Bitrate::A106) {
            nfca_params.clone()
        } else {
            nfcf_params.clone()
        };
        let mut atr_req = Vec::new();

        data = self.handle_dep_atr(activation_bitrate.as_str(), target, data, &mut atr_req)?;

        self.process_dep_requests(
            activation_bitrate,
            activation_params,
            nfca_params,
            data,
            atr_req,
        )
    }

    fn handle_dep_atr(
        &mut self,
        activation_bitrate: &str,
        target: &LocalTarget,
        mut data: Option<Vec<u8>>,
        atr_req: &mut Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        while let Some(current) = data.clone() {
            if current.get(1) != Some(&0) {
                break;
            }
            *atr_req = current.clone();
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
                hex::encode(&*atr_req)
            );
            debug!(
                "{} send ATR_RES {}",
                activation_bitrate,
                hex::encode(&atr_res)
            );
            data = self.dep_send_frame(activation_bitrate, Some(&atr_res), 1000)?;
        }
        Ok(data)
    }

    #[allow(clippy::too_many_arguments)]
    fn process_dep_requests(
        &mut self,
        mut activation_bitrate: Bitrate,
        activation_params: Vec<u8>,
        nfca_params: Vec<u8>,
        mut data: Option<Vec<u8>>,
        atr_req: Vec<u8>,
    ) -> Result<Option<LocalTarget>> {
        let mut psl_req: Option<Vec<u8>> = None;
        while let Some(current) = data.clone() {
            match current.get(1).copied() {
                Some(4) => {
                    if let Some(new_bitrate) =
                        self.dep_handle_psl(activation_bitrate.as_str(), &current)?
                    {
                        activation_bitrate = Bitrate::from_str(new_bitrate.0.as_str());
                        psl_req = Some(new_bitrate.1);
                    }
                }
                Some(6) => {
                    if let Some(local) = self.build_dep_local_target(
                        activation_bitrate.as_str(),
                        &activation_params,
                        &nfca_params,
                        &current,
                        &atr_req,
                        psl_req.clone(),
                    )? {
                        return Ok(Some(local));
                    }
                }
                Some(8) => {
                    self.dep_send_simple_response(activation_bitrate.as_str(), 0x09, &current)?;
                    return Ok(None);
                }
                Some(10) => {
                    self.dep_send_simple_response(activation_bitrate.as_str(), 0x0B, &current)?;
                    return Ok(None);
                }
                Some(_) => {}
                None => break,
            }
            data = self.dep_send_frame(activation_bitrate.as_str(), None, 1000)?;
        }
        Ok(None)
    }

    fn build_dep_local_target(
        &mut self,
        activation_bitrate: &str,
        activation_params: &[u8],
        nfca_params: &[u8],
        current: &[u8],
        atr_req: &[u8],
        psl_req: Option<Vec<u8>>,
    ) -> Result<Option<LocalTarget>> {
        let did = atr_req.get(12).copied().filter(|value| *value > 0);
        let recv_did = if current.get(2).map(|v| v >> 2 & 1).unwrap_or(0) != 0 {
            current.get(3).copied()
        } else {
            None
        };
        if did != recv_did {
            return Ok(None);
        }
        let mut local = if activation_params == nfca_params {
            self.build_local_nfca_target(activation_params)?
        } else {
            let mut target = LocalTarget::new(activation_bitrate)?;
            let mut sensf = vec![0x01];
            sensf.extend_from_slice(activation_params);
            target.data.sensf_res = Some(sensf);
            target
        };
        local.data.dep_req = Some(current.to_vec());
        local.data.atr_req = Some(atr_req.to_vec());
        if let Some(psl) = psl_req {
            local.data.psl_req = Some(psl);
        }
        Ok(Some(local))
    }
}

fn ensure_supported_bitrate(bitrate: &str, allowed: &[&str], error_prefix: &str) -> Result<()> {
    if allowed.contains(&bitrate) {
        Ok(())
    } else {
        Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
            format!("{error_prefix}{bitrate}"),
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

#[allow(clippy::large_enum_variant)]
enum Tt4Step {
    Continue,
    QueueResponse(Vec<u8>),
    Found(LocalTarget),
}

#[derive(Default)]
struct Tt4Session {
    pending_response: Option<Vec<u8>>,
    rats_cmd: Option<Vec<u8>>,
    rats_res: Option<Vec<u8>>,
}

impl Tt4Session {
    fn new() -> Self {
        Self::default()
    }

    fn take_response(&mut self) -> Option<Vec<u8>> {
        self.pending_response.take()
    }

    fn queue_response(&mut self, data: Vec<u8>) {
        self.pending_response = Some(data);
    }

    fn start(&mut self, cmd: Vec<u8>, res: Vec<u8>) {
        self.rats_cmd = Some(cmd);
        self.rats_res = Some(res.clone());
        self.pending_response = Some(res);
    }

    fn rats(&self) -> Option<(&[u8], &[u8])> {
        Some((self.rats_cmd.as_deref()?, self.rats_res.as_deref()?))
    }

    fn has_session(&self) -> bool {
        self.rats().is_some()
    }

    fn clear(&mut self) {
        self.pending_response = None;
        self.rats_cmd = None;
        self.rats_res = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bitrate {
    A106,
    F212,
    F424,
    Unknown(u8),
}

impl Bitrate {
    fn as_str(&self) -> &'static str {
        match self {
            Bitrate::A106 => "106A",
            Bitrate::F212 => "212F",
            Bitrate::F424 => "424F",
            Bitrate::Unknown(_) => "unknown bitrate",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "106A" => Bitrate::A106,
            "212F" => Bitrate::F212,
            "424F" => Bitrate::F424,
            _ => Bitrate::Unknown(0),
        }
    }
}

struct ExchangeView<'a> {
    bitrate: Bitrate,
    payload: &'a [u8],
    raw: &'a [u8],
}

impl<'a> ExchangeView<'a> {
    fn new(raw: &'a [u8]) -> Self {
        let bitrate = Self::decode_bitrate(raw);
        let payload = Self::extract_payload(raw);
        Self {
            bitrate,
            payload,
            raw,
        }
    }

    fn bitrate(&self) -> Bitrate {
        self.bitrate
    }

    fn payload(&self) -> &'a [u8] {
        self.payload
    }

    fn len_matches_len_byte(&self) -> bool {
        self.payload
            .first()
            .map(|byte| self.payload.len() == *byte as usize)
            .unwrap_or(false)
    }

    fn raw(&self) -> &'a [u8] {
        self.raw
    }

    fn is_activation_frame(&self) -> bool {
        Self::is_activation_frame_raw(self.raw)
    }

    fn decode_bitrate(data: &[u8]) -> Bitrate {
        data.first()
            .copied()
            .map(Self::decode_target_bitrate)
            .unwrap_or(Bitrate::Unknown(0))
    }

    fn extract_payload(data: &[u8]) -> &[u8] {
        data.get(7..).unwrap_or(&[])
    }

    fn is_activation_frame_raw(data: &[u8]) -> bool {
        data.get(2).map(|value| value & 0x03 == 3).unwrap_or(false)
    }

    fn decode_target_bitrate(value: u8) -> Bitrate {
        match value.checked_sub(11) {
            Some(0) => Bitrate::A106,
            Some(1) => Bitrate::F212,
            Some(2) => Bitrate::F424,
            _ => Bitrate::Unknown(value),
        }
    }
}

struct TimeoutWindow {
    deadline: Instant,
    remaining_ms: u16,
}

impl TimeoutWindow {
    fn new(timeout: f32) -> Option<Self> {
        let remaining_ms = clamp_timeout(timeout);
        if remaining_ms == 0 {
            return None;
        }
        Some(Self {
            deadline: Instant::now() + Duration::from_secs_f32(timeout.max(0.0)),
            remaining_ms,
        })
    }

    fn refresh(&mut self) {
        self.remaining_ms = self
            .deadline
            .checked_duration_since(Instant::now())
            .map(|remaining| remaining.as_millis().min(u16::MAX as u128) as u16)
            .unwrap_or(0);
    }

    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn remaining(&self) -> u16 {
        self.remaining_ms
    }

    fn active(&self) -> bool {
        self.remaining_ms > 0
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

fn build_sensf_res_payload(
    res: &Type3TagPollingResult,
    request_code: u8,
    bitrate: &str,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(19);
    payload.push(0x01);
    payload.extend_from_slice(&res.idm);
    payload.extend_from_slice(&res.pmm);
    match request_code {
        0x01 => payload.extend_from_slice(&res.optional),
        0x02 => {
            payload.push(0x00);
            payload.push(if bitrate == "424F" { 0x02 } else { 0x01 });
        }
        _ => {}
    }
    payload
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

fn is_valid_tt4_command(rats_cmd: &[u8], rats_res: &[u8], cmd: &[u8]) -> bool {
    // RATS_RES is TL, T0 and then the optional TA(1)/TB(1)/TC(1) interface
    // bytes, so both the length byte and T0 must be present before T0's
    // presence bits can be read or the interface bytes sliced off. RATS_RES
    // comes from the caller's `LocalTarget`, and a short one is a rejected
    // configuration rather than a reason to abort the listen loop.
    if rats_cmd.len() < 2 || rats_res.len() < 2 || cmd.is_empty() {
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
    let cmd_with_did = cmd.first().map(|value| value & 0x08 != 0).unwrap_or(false);
    (cmd_with_did && did_supported && cmd.get(1).copied() == Some(did))
        || (did == 0 && !cmd_with_did)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_supported_bitrate_accepts_allowed_values_and_rejects_others() {
        assert!(ensure_supported_bitrate("106A", &["106A", "212F"], "unsupported ").is_ok());
        match ensure_supported_bitrate("424A", &["106A", "212F"], "unsupported ") {
            Err(DriverError::UnsupportedTarget(err)) => {
                assert_eq!(err.0, "unsupported 424A");
            }
            Err(other) => panic!("expected UnsupportedTarget error, got {other}"),
            Ok(_) => panic!("expected error for unsupported bitrate"),
        }
    }

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

    #[test]
    fn tt4_session_tracks_pending_and_rats_data() {
        let mut session = Tt4Session::new();
        assert!(!session.has_session());
        assert!(session.take_response().is_none());

        session.start(vec![0xE0, 0x50], vec![0x06, 0x77]);
        assert!(session.has_session());
        let (rats_cmd, rats_res) = session.rats().expect("RATS should be present");
        assert_eq!(rats_cmd, &[0xE0, 0x50]);
        assert_eq!(rats_res, &[0x06, 0x77]);
        assert_eq!(session.take_response(), Some(vec![0x06, 0x77]));
        assert!(session.take_response().is_none());

        session.queue_response(vec![0x90, 0x00]);
        assert_eq!(session.take_response(), Some(vec![0x90, 0x00]));
        session.clear();
        assert!(!session.has_session());
    }

    #[test]
    fn bitrate_and_exchange_view_decode_fields_consistently() {
        assert_eq!(Bitrate::from_str("106A"), Bitrate::A106);
        assert_eq!(Bitrate::from_str("212F"), Bitrate::F212);
        assert_eq!(Bitrate::from_str("424F"), Bitrate::F424);
        assert_eq!(Bitrate::from_str("999X"), Bitrate::Unknown(0));
        assert_eq!(Bitrate::A106.as_str(), "106A");
        assert_eq!(Bitrate::Unknown(99).as_str(), "unknown bitrate");

        let raw = vec![11, 0, 0x03, 0, 0, 0, 0, 3, 0xAA, 0xBB];
        let view = ExchangeView::new(&raw);
        assert_eq!(view.bitrate(), Bitrate::A106);
        assert_eq!(view.payload(), &[3, 0xAA, 0xBB]);
        assert!(view.len_matches_len_byte());
        assert!(view.is_activation_frame());
        assert_eq!(view.raw(), raw.as_slice());

        let raw_unknown = vec![0xFF, 0, 0x00, 0, 0, 0, 0, 3, 0xAA];
        let unknown = ExchangeView::new(&raw_unknown);
        assert_eq!(unknown.bitrate(), Bitrate::Unknown(0xFF));
        assert!(!unknown.is_activation_frame());
        assert!(!unknown.len_matches_len_byte());
    }

    #[test]
    fn timeout_window_and_clamp_timeout_cover_edge_cases() {
        assert_eq!(clamp_timeout(-1.0), 0);
        assert_eq!(clamp_timeout(0.0), 0);
        assert_eq!(clamp_timeout(0.0006), 1);
        assert_eq!(clamp_timeout(1.5), 1500);
        assert_eq!(clamp_timeout(100_000.0), 0xFFFF);

        assert!(TimeoutWindow::new(0.0).is_none());
        let mut window = TimeoutWindow::new(0.05).expect("positive timeout should create window");
        assert!(window.active());
        assert!(window.remaining() > 0);
        let _ = window.deadline();
        window.deadline = Instant::now();
        window.refresh();
        assert!(!window.active());
        assert_eq!(window.remaining(), 0);
    }

    #[test]
    fn build_sensf_res_payload_handles_request_code_variants() {
        let res = Type3TagPollingResult {
            idm: vec![0x01; 8],
            pmm: vec![0x02; 8],
            optional: vec![0xFE, 0x00],
        };
        let req1 = build_sensf_res_payload(&res, 0x01, "212F");
        assert_eq!(req1[0], 0x01);
        assert_eq!(&req1[1..9], &[0x01; 8]);
        assert_eq!(&req1[9..17], &[0x02; 8]);
        assert_eq!(&req1[17..], &[0xFE, 0x00]);

        let req2_212 = build_sensf_res_payload(&res, 0x02, "212F");
        assert_eq!(&req2_212[17..], &[0x00, 0x01]);
        let req2_424 = build_sensf_res_payload(&res, 0x02, "424F");
        assert_eq!(&req2_424[17..], &[0x00, 0x02]);

        let req_other = build_sensf_res_payload(&res, 0x03, "212F");
        assert_eq!(req_other.len(), 17);
    }

    #[test]
    fn nfca_params_from_local_validates_required_fields_and_lengths() {
        let mut target = LocalTarget::new("106A").expect("local target");
        target.data.sens_res = Some(vec![0x04, 0x00]);
        target.data.sdd_res = Some(vec![0x08, 0x11, 0x22, 0x33]);
        target.data.sel_res = Some(vec![0x20]);
        assert_eq!(
            nfca_params_from_local(&target).expect("params should be built"),
            vec![0x04, 0x00, 0x11, 0x22, 0x33, 0x20]
        );

        let mut missing = LocalTarget::new("106A").expect("local target");
        missing.data.sdd_res = Some(vec![0x08, 0x11, 0x22, 0x33]);
        missing.data.sel_res = Some(vec![0x20]);
        match nfca_params_from_local(&missing) {
            Err(DriverError::Other(message)) => assert_eq!(message, "sens_res is required"),
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(_) => panic!("expected error for missing sens_res"),
        }

        let mut invalid = LocalTarget::new("106A").expect("local target");
        invalid.data.sens_res = Some(vec![0x04, 0x00]);
        invalid.data.sdd_res = Some(vec![0x09, 0x11, 0x22, 0x33]);
        invalid.data.sel_res = Some(vec![0x20]);
        match nfca_params_from_local(&invalid) {
            Err(DriverError::Other(message)) => assert_eq!(message, "sdd_res[0] must be 0x08"),
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(_) => panic!("expected error for invalid sdd_res"),
        }
    }

    /// RATS_RES comes from the caller's `LocalTarget`, and `is_valid_tt4_command`
    /// reads T0's presence bits out of it. A RATS_RES shorter than TL + T0 used to
    /// panic on `rats_res[2..]` instead of being rejected.
    #[test]
    fn is_valid_tt4_command_rejects_a_short_rats_res() {
        // TL=0x05, T0=0x78 (TA/TB/TC present), then the three interface bytes.
        let rats_res = [0x05u8, 0x78, 0x80, 0x70, 0x02];
        let rats_cmd = [0xE0u8, 0x00];
        // DID 0 with a command that carries no DID is the accepted combination.
        assert!(is_valid_tt4_command(&rats_cmd, &rats_res, &[0x02]));

        for short in [&[][..], &[0x05][..]] {
            assert!(
                !is_valid_tt4_command(&rats_cmd, short, &[0x02]),
                "a {}-byte RATS_RES must be rejected, not panic",
                short.len()
            );
        }

        // The existing guards on the other two arguments still hold.
        assert!(!is_valid_tt4_command(&[0xE0], &rats_res, &[0x02]));
        assert!(!is_valid_tt4_command(&rats_cmd, &rats_res, &[]));
    }
}
