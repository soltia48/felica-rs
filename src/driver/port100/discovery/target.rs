//! Card emulation: the reader acts as the NFC target.
//!
//! Each `listen_*` method configures the RF for one technology and then answers
//! an initiator's commands from the [`LocalTarget`] the caller supplied, up to
//! the point where the exchange becomes the caller's to drive. `listen_dep`
//! carries on through the ATR, PSL and DEP request sequence that activates a
//! peer-to-peer link.

use super::{SensfRequest, ensure_supported_bitrate};
use crate::clf::errors::UnsupportedTargetError;
use crate::clf::targets::LocalTarget;
use crate::driver::errors::{ChipsetError, DriverError, Result};
use crate::driver::port100::device::Device;
use crate::felica_standard::Type3TagPollingResult;
use crate::transport::Transport;
use log::{debug, warn};

/// RATS response used when the caller's target does not carry one.
const DEFAULT_RATS_RESPONSE: [u8; 5] = [0x05, 0x78, 0x80, 0x70, 0x02];

impl<T: Transport> Device<T> {
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
