//! The ISO-DEP (ISO/IEC 14443-4) half-duplex block protocol.
//!
//! Once a Type A or Type B card has been activated, application data travels in
//! I-blocks that both sides acknowledge, retry and chain. This module owns that
//! state machine: [`Device::iso_dep_exchange`] sends one payload and returns the
//! card's answer, running the block loop, the WTX and IFS negotiations and the
//! chaining bookkeeping on the way. The block *encoding* lives in
//! [`super::super::iso14443`]; what is here is the conversation those blocks
//! make up.

use super::{Device, MAX_THROUGH_PAYLOAD, ThroughProtocol};
use crate::driver::errors::{DriverError, Result};
use crate::driver::port400::iso14443::{
    ISO_DEP_S_DESELECT, ISO_DEP_S_IFS, ISO_DEP_S_WTX, IsoDepBlockType, IsoDepIFrame, IsoDepSession,
    IsoDepState, build_iso_dep_r_block, build_iso_dep_s_block, extend_timeout,
    next_iso_dep_i_frame, parse_iso_dep_response, wtx_multiplier,
};
use crate::transport::Transport;
use hex::encode;
use log::debug;
use std::time::Duration;

impl<T: Transport> Device<T> {
    fn ensure_iso_dep_link_parameters(&mut self, session: &mut IsoDepSession) -> Result<()> {
        if !session.needs_ifs_request() {
            return Ok(());
        }
        let protocol = self.iso_dep_protocol_or_default();
        let desired_ifs = session.config().max_inf_len_pcd().min(0xFE) as u8;
        let response = self.send_s_block_ifs(session.state(), desired_ifs, protocol)?;
        let parsed = parse_iso_dep_response(session.state(), &response)?;
        match parsed.block_type {
            IsoDepBlockType::R { ack } if ack => {
                session.mark_ifs_negotiated();
                Ok(())
            }
            _ => Err(DriverError::Other(
                "unexpected response to S(IFS) request".into(),
            )),
        }
    }

    pub fn iso_dep_exchange(&mut self, payload: &[u8], chaining: bool) -> Result<Vec<u8>> {
        let mut session = self.take_iso_dep_session()?;
        self.ensure_iso_dep_link_parameters(&mut session)?;
        let protocol = self.iso_dep_protocol_or_default();
        let mut state = IsoDepExchangeState::new(&session, payload, chaining)?;
        let result = self.run_iso_dep_loop(&mut session, &mut state, protocol);
        if self.iso_dep_protocol.is_some() {
            self.iso_dep_session = Some(session);
        }
        result
    }

    fn run_iso_dep_loop(
        &mut self,
        session: &mut IsoDepSession,
        state: &mut IsoDepExchangeState,
        protocol: ThroughProtocol,
    ) -> Result<Vec<u8>> {
        loop {
            let response_bytes = state.next_response(self, protocol)?;
            let response = parse_iso_dep_response(session.state(), &response_bytes)?;
            let outcome = match response.block_type {
                IsoDepBlockType::I {
                    payload: picc_payload,
                } => self.handle_iso_dep_i_block(
                    session,
                    state,
                    response.block_number,
                    &picc_payload,
                    response.chaining,
                    protocol,
                ),
                IsoDepBlockType::R { ack } => {
                    self.handle_iso_dep_r_block(session, state, ack, response.block_number)
                }
                IsoDepBlockType::S { code, payload } => {
                    self.handle_iso_dep_s_block(session, state, code, &payload, protocol)
                }
                IsoDepBlockType::Unknown(code) => Err(DriverError::Other(format!(
                    "Unknown ISO-DEP block type {:02X}",
                    code
                ))),
            }?;

            if let IsoDepOutcome::Finished(data) = outcome {
                return Ok(data);
            }
        }
    }

    fn handle_iso_dep_i_block(
        &mut self,
        session: &mut IsoDepSession,
        state: &mut IsoDepExchangeState,
        block_number: u8,
        payload: &[u8],
        chaining: bool,
        protocol: ThroughProtocol,
    ) -> Result<IsoDepOutcome> {
        let expected = session.state().expected_picc_block();
        if block_number != expected {
            let duplicate = expected ^ 0x01;
            if block_number == duplicate {
                self.send_iso_dep_ack(state, session.state(), protocol)?;
                return Ok(IsoDepOutcome::Continue);
            }
            return Err(DriverError::Other(
                "ISO-DEP PICC block number mismatch".into(),
            ));
        }

        state.validate_picc_payload(payload)?;
        state.accumulate_payload(payload);
        session.state_mut().advance_picc_block();
        state.reset_progress();

        if chaining {
            self.send_iso_dep_ack(state, session.state(), protocol)?;
            return Ok(IsoDepOutcome::Continue);
        }
        session.state_mut().next_tx_block();
        Ok(IsoDepOutcome::Finished(state.take_aggregated()))
    }

    fn handle_iso_dep_r_block(
        &mut self,
        session: &mut IsoDepSession,
        state: &mut IsoDepExchangeState,
        ack: bool,
        block_number: u8,
    ) -> Result<IsoDepOutcome> {
        state.reset_progress();
        let expected_nr = session.state().current_tx_block() ^ 0x01;
        if block_number != expected_nr {
            return Err(DriverError::Other("ISO-DEP R-Block NR mismatch".into()));
        }
        if ack {
            session.state_mut().next_tx_block();
            if let Some(next_frame) = state.next_frame(session) {
                state.update_frame(next_frame);
                return Ok(IsoDepOutcome::Continue);
            }
            if state.last_frame_chaining() {
                return Ok(IsoDepOutcome::Finished(Vec::new()));
            }
            return Err(DriverError::Other(
                "ISO-DEP unexpected ACK without pending data".into(),
            ));
        }
        state.retry_after_nak()?;
        Ok(IsoDepOutcome::Continue)
    }

    fn handle_iso_dep_s_block(
        &mut self,
        session: &mut IsoDepSession,
        state: &mut IsoDepExchangeState,
        code: u8,
        payload: &[u8],
        protocol: ThroughProtocol,
    ) -> Result<IsoDepOutcome> {
        match code {
            ISO_DEP_S_WTX => {
                let wtxm = payload
                    .first()
                    .copied()
                    .ok_or_else(|| DriverError::Other("Invalid WTX block".into()))?;
                state.record_wtx_attempt(session.config().max_try_s_wtx)?;
                let multiplier = wtx_multiplier(wtxm);
                let timeout = state.extend_timeout(multiplier);
                let state_snapshot = *session.state();
                let next_response =
                    self.send_s_block_wtx(&state_snapshot, wtxm, protocol, timeout)?;
                state.schedule_pending(next_response);
                Ok(IsoDepOutcome::Continue)
            }
            ISO_DEP_S_IFS => {
                let new_ifs = payload
                    .first()
                    .copied()
                    .ok_or_else(|| DriverError::Other("Invalid IFS block".into()))?;
                session.config_mut().update_pcd_ifs(new_ifs);
                session.mark_ifs_negotiated();
                let state_snapshot = *session.state();
                self.send_s_block_ifs(&state_snapshot, new_ifs, protocol)?;
                Ok(IsoDepOutcome::Continue)
            }
            ISO_DEP_S_DESELECT => {
                let state_snapshot = *session.state();
                self.send_s_block_deselect(&state_snapshot, protocol)?;
                self.end_iso_dep_session();
                Err(DriverError::Other("ISO-DEP deselected by PICC".into()))
            }
            _ => Err(DriverError::Other(format!(
                "ISO-DEP S-Block {:02X} handling not implemented",
                code
            ))),
        }
    }

    fn send_iso_dep_ack(
        &mut self,
        state: &mut IsoDepExchangeState,
        iso_state: &IsoDepState,
        protocol: ThroughProtocol,
    ) -> Result<()> {
        let ack_frame = build_iso_dep_r_block(iso_state, true);
        let ack_response =
            self.iso_dep_transceive(&ack_frame, protocol, state.current_timeout())?;
        state.schedule_pending(ack_response);
        Ok(())
    }

    fn iso_dep_transceive(
        &mut self,
        frame: &[u8],
        protocol: ThroughProtocol,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let flags = protocol.iso_dep_flags();
        debug!("Port-400 ISO-DEP TX ({protocol:?}): {}", encode(frame));
        let response = self.pcsc.transceive(frame, timeout, &flags)?;
        debug!("Port-400 ISO-DEP RX ({protocol:?}): {}", encode(&response));
        Ok(response)
    }

    fn send_s_block_wtx(
        &mut self,
        state: &IsoDepState,
        wtxm: u8,
        protocol: ThroughProtocol,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let payload = [wtxm];
        let frame = build_iso_dep_s_block(state, ISO_DEP_S_WTX, true, &payload);
        self.iso_dep_transceive(&frame, protocol, timeout)
    }

    fn send_s_block_ifs(
        &mut self,
        state: &IsoDepState,
        ifs: u8,
        protocol: ThroughProtocol,
    ) -> Result<Vec<u8>> {
        let payload = [ifs];
        let frame = build_iso_dep_s_block(state, ISO_DEP_S_IFS, false, &payload);
        self.iso_dep_transceive(&frame, protocol, Duration::from_millis(10))
    }

    fn send_s_block_deselect(
        &mut self,
        state: &IsoDepState,
        protocol: ThroughProtocol,
    ) -> Result<Vec<u8>> {
        let frame = build_iso_dep_s_block(state, ISO_DEP_S_DESELECT, false, &[]);
        self.iso_dep_transceive(&frame, protocol, Duration::from_millis(10))
    }
}

enum IsoDepOutcome {
    Continue,
    Finished(Vec<u8>),
}

struct IsoDepExchangeState<'a> {
    pcd_payload: &'a [u8],
    chaining: bool,
    tx_offset: usize,
    sent_empty_frame: bool,
    pending_response: Option<Vec<u8>>,
    aggregated_response: Vec<u8>,
    current_frame: IsoDepIFrame,
    last_frame_chaining: bool,
    base_timeout: Duration,
    current_timeout: Duration,
    wtx_attempts: u8,
    nak_retries: i32,
    max_picc_inf: usize,
}

impl<'a> IsoDepExchangeState<'a> {
    fn new(session: &IsoDepSession, payload: &'a [u8], chaining: bool) -> Result<Self> {
        let mut tx_offset = 0usize;
        let mut sent_empty_frame = false;
        let current_frame = next_iso_dep_i_frame(
            session.state(),
            payload,
            &mut tx_offset,
            session.config().max_inf_len_pcd(),
            chaining,
            &mut sent_empty_frame,
        )
        .ok_or_else(|| DriverError::Other("ISO-DEP empty frame generation failed".into()))?;
        let base_timeout = session.config().fwt_duration();
        Ok(Self {
            pcd_payload: payload,
            chaining,
            tx_offset,
            sent_empty_frame,
            pending_response: None,
            aggregated_response: Vec::new(),
            last_frame_chaining: current_frame.chaining,
            current_frame,
            base_timeout,
            current_timeout: base_timeout,
            wtx_attempts: 0,
            nak_retries: session.config().max_retry_r_nak.max(1) as i32,
            max_picc_inf: session.config().max_inf_len_picc(),
        })
    }

    fn current_frame(&self) -> &[u8] {
        &self.current_frame.frame
    }

    fn next_response<T: Transport>(
        &mut self,
        device: &mut Device<T>,
        protocol: ThroughProtocol,
    ) -> Result<Vec<u8>> {
        if let Some(bytes) = self.pending_response.take() {
            return Ok(bytes);
        }
        device.iso_dep_transceive(self.current_frame(), protocol, self.current_timeout)
    }

    fn validate_picc_payload(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > self.max_picc_inf {
            return Err(DriverError::Other(
                "ISO-DEP PICC payload exceeds FSC".into(),
            ));
        }
        if self.aggregated_response.len() + payload.len() > MAX_THROUGH_PAYLOAD {
            return Err(DriverError::Other(
                "ISO-DEP response exceeds receive buffer".into(),
            ));
        }
        Ok(())
    }

    fn accumulate_payload(&mut self, payload: &[u8]) {
        self.aggregated_response.extend_from_slice(payload);
    }

    fn reset_progress(&mut self) {
        self.wtx_attempts = 0;
        self.current_timeout = self.base_timeout;
    }

    fn take_aggregated(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.aggregated_response)
    }

    fn next_frame(&mut self, session: &IsoDepSession) -> Option<IsoDepIFrame> {
        next_iso_dep_i_frame(
            session.state(),
            self.pcd_payload,
            &mut self.tx_offset,
            session.config().max_inf_len_pcd(),
            self.chaining,
            &mut self.sent_empty_frame,
        )
    }

    fn update_frame(&mut self, frame: IsoDepIFrame) {
        self.last_frame_chaining = frame.chaining;
        self.current_frame = frame;
    }

    fn last_frame_chaining(&self) -> bool {
        self.last_frame_chaining
    }

    fn retry_after_nak(&mut self) -> Result<()> {
        if self.nak_retries == 0 {
            return Err(DriverError::Other("ISO-DEP retry limit reached".into()));
        }
        self.nak_retries -= 1;
        Ok(())
    }

    fn record_wtx_attempt(&mut self, max_attempts: u8) -> Result<()> {
        self.wtx_attempts = self.wtx_attempts.saturating_add(1);
        if self.wtx_attempts > max_attempts {
            return Err(DriverError::Other("ISO-DEP WTX retry limit reached".into()));
        }
        Ok(())
    }

    fn extend_timeout(&mut self, multiplier: u8) -> Duration {
        let timeout = extend_timeout(self.base_timeout, multiplier);
        self.current_timeout = timeout;
        timeout
    }

    fn schedule_pending(&mut self, response: Vec<u8>) {
        self.pending_response = Some(response);
    }

    fn current_timeout(&self) -> Duration {
        self.current_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::port400::iso14443::IsoDepConfig;
    use crate::driver::testing::assert_driver_error_contains;

    #[test]
    fn iso_dep_exchange_state_retries_and_bounds_validation() {
        let mut config = IsoDepConfig::type_a_defaults();
        config.max_retry_r_nak = 1;
        config.max_try_s_wtx = 1;
        let session = IsoDepSession::new(config);
        let payload = [0x10, 0x20, 0x30];
        let mut state =
            IsoDepExchangeState::new(&session, &payload, false).expect("state should initialize");

        let too_large = vec![0x00; session.config().max_inf_len_picc() + 1];
        assert_driver_error_contains(state.validate_picc_payload(&too_large), "exceeds FSC");

        state.accumulate_payload(&vec![0xAA; MAX_THROUGH_PAYLOAD - 1]);
        assert_driver_error_contains(
            state.validate_picc_payload(&[0xBB, 0xCC]),
            "exceeds receive buffer",
        );

        state.retry_after_nak().expect("first retry should pass");
        assert_driver_error_contains(state.retry_after_nak(), "retry limit reached");

        state
            .record_wtx_attempt(session.config().max_try_s_wtx)
            .expect("first WTX should pass");
        assert_driver_error_contains(
            state.record_wtx_attempt(session.config().max_try_s_wtx),
            "WTX retry limit reached",
        );
    }

    #[test]
    fn iso_dep_exchange_state_timeout_extension_and_reset_progress() {
        let session = IsoDepSession::new(IsoDepConfig::type_a_defaults());
        let mut state =
            IsoDepExchangeState::new(&session, &[0x10], false).expect("state should initialize");

        let base = state.current_timeout();
        let extended = state.extend_timeout(4);
        assert!(extended >= base);
        assert_eq!(state.current_timeout(), extended);

        state.reset_progress();
        assert_eq!(state.current_timeout(), base);
    }
}
