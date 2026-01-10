use crate::clf::errors::UnsupportedTargetError;
use crate::clf::targets::RemoteTarget;
use crate::driver::errors::{DriverError, Result};
use crate::driver::port400::iso14443::{
    ISO_DEP_S_DESELECT, ISO_DEP_S_IFS, ISO_DEP_S_WTX, IsoDepBlockType, IsoDepConfig, IsoDepIFrame,
    IsoDepSession, IsoDepState, build_iso_dep_r_block, build_iso_dep_s_block, extend_timeout,
    next_iso_dep_i_frame, parse_iso_dep_response, wtx_multiplier,
};
use crate::driver::port400::pcsc::{Pcsc, TransmissionFlags, TypeBInfo};
use crate::felica_standard::{
    FelicaDriver, FelicaStandardCommand, FelicaStandardResponse, Type3TagPollingResult,
};
use crate::transport::Transport;
use crate::transport::usb::UsbTransport;
use hex::encode;
use log::{debug, warn};
use std::io::{self, ErrorKind};
use std::thread::sleep;
use std::time::Duration;

const SONY_VID: u16 = 0x054C;
const PORT400_PIDS: &[u16] = &[0x0DC8, 0x0DC9, 0x0D8F];
const MAX_THROUGH_PAYLOAD: usize = 290;
const TYPE_A_CMD_TIMEOUT_MS: u16 = 30;
const TYPE_B_CMD_TIMEOUT_MS: u16 = 30;
const PROPERTY_HARDWARE_VERSION: u8 = 1;
const PROPERTY_MODEL_ID: u8 = 2;
const PROPERTY_SERIAL_NO: u8 = 3;
const PROPERTY_GROUP_NO: u8 = 8;
const RFFE_PARAM_EEPROM: u8 = 0x01;
const RFFE_PARAM_PD_SC_DPC: u8 = 0x02;
const RFFE_PARAM_PROTOCOL_CONFIGURATION: u8 = 0x03;
const DIAG_COMMUNICATION_LINE_SIZE_MAX: usize = 500;
const DIAG_POLLING_COUNT_MIN: u8 = 1;

pub struct Device<T: Transport> {
    pcsc: Pcsc<T>,
    chipset_name: String,
    vendor_name: Option<String>,
    product_name: Option<String>,
    iso_dep_session: Option<IsoDepSession>,
    iso_dep_protocol: Option<ThroughProtocol>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ThroughProtocol {
    #[default]
    Felica,
    Iso14443TypeA,
    Iso14443TypeB,
    Iso15693,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ThroughOptions {
    pub protocol: ThroughProtocol,
    pub append_crc: Option<bool>,
    pub discard_crc: Option<bool>,
    pub insert_parity: Option<bool>,
    pub expect_parity: Option<bool>,
    pub append_protocol_prologue: Option<bool>,
    pub tx_valid_bits: Option<u8>,
}

impl ThroughProtocol {
    fn transmission_flags(self) -> TransmissionFlags {
        match self {
            ThroughProtocol::Felica => TransmissionFlags::felica(),
            ThroughProtocol::Iso14443TypeA => TransmissionFlags::iso14443_type_a(),
            ThroughProtocol::Iso14443TypeB => TransmissionFlags::iso14443_type_b(),
            ThroughProtocol::Iso15693 => TransmissionFlags::iso15693(),
        }
    }

    fn iso_dep_flags(self) -> TransmissionFlags {
        match self {
            ThroughProtocol::Iso14443TypeB => TransmissionFlags::iso14443_type_b(),
            _ => TransmissionFlags::iso14443_type_a(),
        }
    }
}

impl ThroughOptions {
    fn flags(&self) -> TransmissionFlags {
        let mut flags = self.protocol.transmission_flags();
        if let Some(value) = self.append_crc {
            flags.append_crc = value;
        }
        if let Some(value) = self.discard_crc {
            flags.discard_crc = value;
        }
        if let Some(value) = self.insert_parity {
            flags.insert_parity = value;
        }
        if let Some(value) = self.expect_parity {
            flags.expect_parity = value;
        }
        if let Some(value) = self.append_protocol_prologue {
            flags.append_protocol_prologue = value;
        }
        if let Some(bits) = self.tx_valid_bits {
            flags.tx_valid_bits = Some(bits);
        }
        flags
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TypeADetectOptions {
    pub iso_dep: Option<IsoDepConfig>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TypeBDetectOptions {
    pub iso_dep: Option<IsoDepConfig>,
    pub afi: Option<u8>,
    pub param: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct TypeACardInfo {
    pub atqa: [u8; 2],
    pub sak: u8,
    pub uid: Vec<u8>,
    pub ats: Vec<u8>,
    pub iso_dep_config: IsoDepConfig,
}

#[derive(Debug, Clone)]
pub struct TypeBCardInfo {
    pub pupi: [u8; 4],
    pub application_data: [u8; 4],
    pub protocol_info: Vec<u8>,
    pub attrib_response: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DiagnoseCommand {
    CommunicationLine(Vec<u8>),
    Rom,
    Ram,
    Polling {
        protocol: DiagnosePollingProtocol,
        count: u8,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum DiagnosePollingProtocol {
    Felica,
    Iso18092,
    Iso14443TypeA,
    Iso14443TypeB,
    Iso15693,
}

impl DiagnosePollingProtocol {
    fn code(self) -> u8 {
        match self {
            DiagnosePollingProtocol::Felica | DiagnosePollingProtocol::Iso18092 => 0x02,
            DiagnosePollingProtocol::Iso14443TypeA => 0x00,
            DiagnosePollingProtocol::Iso14443TypeB => 0x01,
            DiagnosePollingProtocol::Iso15693 => 0x03,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DiagnoseResult {
    CommunicationLine(Vec<u8>),
    Rom(u8),
    Ram(Vec<u8>),
    Polling(u8),
}

pub fn init<T: Transport>(transport: T) -> Result<Device<T>> {
    Device::new(transport)
}

pub fn open_port400_device() -> Result<Device<UsbTransport>> {
    let mut last_error: Option<io::Error> = None;
    for &pid in PORT400_PIDS {
        match UsbTransport::open(SONY_VID, pid) {
            Ok(transport) => return Device::new(transport),
            Err(err) => last_error = Some(err),
        }
    }
    Err(DriverError::Io(last_error.unwrap_or_else(|| {
        io::Error::new(ErrorKind::NotFound, "NFC Port-400 reader not found")
    })))
}

impl<T: Transport> Device<T> {
    pub fn new(transport: T) -> Result<Self> {
        let vendor_name = transport.manufacturer_name().map(|s| s.to_string());
        let product_name = transport.product_name().map(|s| s.to_string());
        let mut pcsc = Pcsc::new(transport);
        pcsc.set_receive_timeout(Duration::from_millis(1_500));
        pcsc.start_transparent_session(false)?;
        pcsc.switch_protocol_type_f(false)?;
        let firmware = pcsc
            .get_firmware_version()
            .ok()
            .and_then(|bytes| format_firmware(&bytes));
        if let Ok(Some(rate)) = pcsc.card_baudrate() {
            debug!("Port-400 target baud rate {} kbps", rate);
        }
        let chipset_name = firmware
            .map(|fw| format!("NFC Port-400 {fw}"))
            .unwrap_or_else(|| "NFC Port-400".to_string());
        Ok(Self {
            pcsc,
            chipset_name,
            vendor_name,
            product_name,
            iso_dep_session: None,
            iso_dep_protocol: None,
        })
    }

    pub fn vendor_name(&self) -> Option<&str> {
        self.vendor_name.as_deref()
    }

    pub fn product_name(&self) -> Option<&str> {
        self.product_name.as_deref()
    }

    pub fn chipset_name(&self) -> &str {
        &self.chipset_name
    }

    pub fn close(&mut self) -> Result<()> {
        let _ = self.pcsc.end_transparent_session();
        self.pcsc.close()
    }

    pub fn mute(&mut self) -> Result<()> {
        self.pcsc.turn_off_rf()
    }

    pub fn get_max_send_data_size(&self, _target: &RemoteTarget) -> usize {
        MAX_THROUGH_PAYLOAD
    }

    pub fn get_max_recv_data_size(&self, _target: &RemoteTarget) -> usize {
        MAX_THROUGH_PAYLOAD
    }

    pub fn detect_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<Type3TagPollingResult> {
        let brty = target.brty();
        if brty != "212F" && brty != "424F" {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                format!("unsupported bitrate {brty}"),
            )));
        }
        debug!("polling for NFC-F using Port-400");
        let command = FelicaStandardCommand::Polling {
            system_code,
            request_code,
            time_slots,
        };
        let frame = command.to_frame();
        let timeout_ms = ((0.003625_f32 + time_slots as f32 * 0.001208_f32) * 1000.0).ceil() as u64;
        let flags = TransmissionFlags::felica();
        let response = self
            .pcsc
            .transceive(&frame, Duration::from_millis(timeout_ms), &flags)?;
        match FelicaStandardResponse::from_bytes(&response) {
            Ok(FelicaStandardResponse::Polling { idm, pmm, optional }) => {
                Ok(Type3TagPollingResult { idm, pmm, optional })
            }
            Ok(other) => Err(DriverError::Other(format!(
                "unexpected Felica response: {other:?}"
            ))),
            Err(err) => Err(DriverError::Other(format!(
                "failed to parse Felica response: {err}"
            ))),
        }
    }

    pub fn transceive(
        &mut self,
        _target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>> {
        let timeout = duration_from_timeout(timeout_ms);
        let flags = TransmissionFlags::felica();
        self.pcsc.transceive(data, timeout, &flags)
    }

    pub fn communicate_thru(
        &mut self,
        data: &[u8],
        timeout_ms: Option<u16>,
        options: Option<ThroughOptions>,
    ) -> Result<Vec<u8>> {
        let opts = options.unwrap_or_default();
        let timeout = duration_from_timeout(timeout_ms);
        let flags = opts.flags();
        self.pcsc.transceive(data, timeout, &flags)
    }

    pub fn detect_type_a(&mut self, options: Option<TypeADetectOptions>) -> Result<Vec<u8>> {
        let opts = options.unwrap_or_default();
        if let Some(config) = opts.iso_dep {
            self.enable_type_a_iso_dep(config)?;
        } else {
            self.prepare_type_a_polling()?;
        }
        self.refresh_card_baudrate()?;
        self.pcsc.get_uid()
    }

    pub fn detect_type_b(&mut self, options: Option<TypeBDetectOptions>) -> Result<Vec<u8>> {
        let opts = options.unwrap_or_default();
        let mut config = opts.iso_dep.unwrap_or_else(IsoDepConfig::type_b_defaults);
        let info = self.prepare_type_b_link(&mut config, &opts)?;
        self.start_iso_dep_session(ThroughProtocol::Iso14443TypeB, config);
        self.refresh_card_baudrate()?;
        Ok(info.pupi.to_vec())
    }

    pub fn detect_type_a_low_level(&mut self) -> Result<TypeACardInfo> {
        self.prepare_type_a_polling()?;
        let atqa_bytes = self.send_type_a_frame(&[0x26], Some(7), false, false)?;
        if atqa_bytes.len() != 2 {
            return Err(DriverError::Other("invalid ATQA length".into()));
        }
        let atqa = [atqa_bytes[0], atqa_bytes[1]];
        let (uid, final_sak) = self.perform_type_a_anticollision()?;
        let mut config = IsoDepConfig::type_a_defaults();
        let rats_param = ((config.fsdi & 0x0F) << 4) | (config.cid & 0x0F);
        let rats_cmd = [0xE0, rats_param];
        let ats = self.send_type_a_frame(&rats_cmd, None, true, true)?;
        apply_ats_config(&mut config, &ats);
        sleep(config.sfgt_duration());
        self.send_type_a_pps(&config)?;
        Ok(TypeACardInfo {
            atqa,
            sak: final_sak,
            uid,
            ats,
            iso_dep_config: config,
        })
    }

    pub fn detect_type_b_low_level(
        &mut self,
        options: Option<TypeBDetectOptions>,
    ) -> Result<TypeBCardInfo> {
        let opts = options.unwrap_or_default();
        let mut config = opts.iso_dep.unwrap_or_else(IsoDepConfig::type_b_defaults);
        let info = self.prepare_type_b_link(&mut config, &opts)?;
        let (dri, dsi) = data_rate_symbols(&config);
        let attrib_cmd = build_type_b_attrib_command(&info, &config, dri, dsi);
        let attrib_response =
            self.send_type_b_frame(&attrib_cmd, true, true, TYPE_B_CMD_TIMEOUT_MS)?;
        if attrib_response.is_empty() {
            return Err(DriverError::Other("invalid ATTRIB response".into()));
        }
        self.apply_comm_speed(dri, dsi)?;
        sleep(config.sfgt_duration());
        Ok(TypeBCardInfo {
            pupi: info.pupi,
            application_data: info.application_data,
            protocol_info: info.protocol_info,
            attrib_response,
        })
    }

    pub fn detect_type_v(&mut self) -> Result<Vec<u8>> {
        self.pcsc.switch_protocol_iso15693()?;
        self.pcsc.get_uid()
    }

    pub fn set_detection_target(&mut self, selector: u8) -> Result<()> {
        self.pcsc.set_detection_target(selector)
    }

    pub fn set_rf_speed(
        &mut self,
        reader_to_card: u8,
        card_to_reader: u8,
        option: u8,
    ) -> Result<()> {
        self.pcsc
            .set_rf_speed(reader_to_card, card_to_reader, option)
    }

    pub fn get_rf_speed(&mut self, selector: u8) -> Result<Vec<u8>> {
        self.pcsc.get_rf_speed(selector)
    }

    pub fn set_comm_speed(&mut self, speed: u8) -> Result<()> {
        self.pcsc.set_comm_speed(speed)
    }

    pub fn set_tx_rx_flag(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.pcsc.set_tx_rx_flag(data)
    }

    pub fn set_tx_bit_framing(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.pcsc.set_tx_bit_framing(data)
    }

    pub fn iso_dep_session(&mut self) -> Option<&mut IsoDepSession> {
        self.iso_dep_session.as_mut()
    }

    pub fn start_iso_dep_session(&mut self, protocol: ThroughProtocol, config: IsoDepConfig) {
        self.iso_dep_session = Some(IsoDepSession::new(config));
        self.iso_dep_protocol = Some(protocol);
    }

    pub fn reset_iso_dep_session(&mut self) -> Result<()> {
        match self.iso_dep_session.as_mut() {
            Some(session) => {
                session.reset();
                Ok(())
            }
            None => Err(DriverError::Other("ISO-DEP session is not active".into())),
        }
    }

    pub fn end_iso_dep_session(&mut self) {
        self.iso_dep_session = None;
        self.iso_dep_protocol = None;
    }

    fn iso_dep_protocol_or_default(&self) -> ThroughProtocol {
        self.iso_dep_protocol
            .unwrap_or(ThroughProtocol::Iso14443TypeA)
    }

    fn take_iso_dep_session(&mut self) -> Result<IsoDepSession> {
        self.iso_dep_session
            .take()
            .ok_or_else(|| DriverError::Other("ISO-DEP session is not active".into()))
    }

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

    pub fn start_rffe_parameter_mode(&mut self) -> Result<()> {
        self.pcsc.start_rffe_parameter_mode()
    }

    pub fn end_rffe_parameter_mode(&mut self) -> Result<()> {
        self.pcsc.end_rffe_parameter_mode()
    }

    pub fn read_rffe_parameter(&mut self, category: u8, selector: u8) -> Result<Vec<u8>> {
        ensure_rffe_category(category)?;
        self.pcsc.read_rffe_parameter(category, selector)
    }

    pub fn write_rffe_parameter(
        &mut self,
        category: u8,
        selector: u8,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        ensure_rffe_category(category)?;
        self.pcsc.write_rffe_parameter(category, selector, data)
    }

    pub fn hardware_version(&mut self) -> Result<Vec<u8>> {
        self.pcsc.get_property(PROPERTY_HARDWARE_VERSION)
    }

    pub fn model_id(&mut self) -> Result<Vec<u8>> {
        self.pcsc.get_property(PROPERTY_MODEL_ID)
    }

    pub fn card_identifier(&mut self) -> Result<Vec<u8>> {
        self.pcsc.card_id()
    }

    pub fn card_name(&mut self) -> Result<Vec<u8>> {
        self.pcsc.card_name()
    }

    pub fn card_type(&mut self) -> Result<Vec<u8>> {
        self.pcsc.card_type()
    }

    pub fn card_type_name(&mut self) -> Result<Vec<u8>> {
        self.pcsc.card_type_name()
    }

    pub fn serial_number_bytes(&mut self) -> Result<Vec<u8>> {
        self.pcsc.get_property(PROPERTY_SERIAL_NO)
    }

    pub fn group_number(&mut self) -> Result<Vec<u8>> {
        self.pcsc.get_property(PROPERTY_GROUP_NO)
    }

    pub fn prepare_firmware_update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.pcsc.prepare_firmware_update(data)
    }

    pub fn update_firmware(&mut self, sequence: u16, data: &[u8]) -> Result<Vec<u8>> {
        self.pcsc.update_firmware(sequence, data)
    }

    pub fn reset_device(&mut self, delay_ms: u16) -> Result<Vec<u8>> {
        self.pcsc.reset_device(delay_ms)
    }

    pub fn self_diagnose(&mut self, command: DiagnoseCommand) -> Result<DiagnoseResult> {
        match command {
            DiagnoseCommand::CommunicationLine(data) => {
                if data.is_empty() || data.len() > DIAG_COMMUNICATION_LINE_SIZE_MAX {
                    return Err(DriverError::Other("diagnostic data size is invalid".into()));
                }
                let response = self.pcsc.diagnose_communication_line(&data)?;
                Ok(DiagnoseResult::CommunicationLine(response))
            }
            DiagnoseCommand::Rom => {
                let result = self.pcsc.diagnose_rom()?;
                Ok(DiagnoseResult::Rom(result))
            }
            DiagnoseCommand::Ram => {
                let result = self.pcsc.diagnose_ram()?;
                Ok(DiagnoseResult::Ram(result))
            }
            DiagnoseCommand::Polling { protocol, count } => {
                if count < DIAG_POLLING_COUNT_MIN {
                    return Err(DriverError::Other(
                        "diagnostic polling count out of range".into(),
                    ));
                }
                let code = protocol.code();
                let result = self.pcsc.diagnose_polling(code, count)?;
                Ok(DiagnoseResult::Polling(result))
            }
        }
    }

    fn enable_type_a_iso_dep(&mut self, mut config: IsoDepConfig) -> Result<()> {
        self.pcsc
            .switch_protocol_iso14443_4a(config.fsdi, config.cid, 4)?;
        if let Ok(ats) = self.pcsc.get_historical_bytes() {
            apply_ats_config(&mut config, &ats);
        }
        self.start_iso_dep_session(ThroughProtocol::Iso14443TypeA, config);
        Ok(())
    }

    fn prepare_type_a_polling(&mut self) -> Result<()> {
        self.pcsc.switch_protocol_iso14443_3a()?;
        self.end_iso_dep_session();
        Ok(())
    }

    fn refresh_card_baudrate(&mut self) -> Result<()> {
        let _ = self.pcsc.card_baudrate()?;
        Ok(())
    }

    fn apply_comm_speed(&mut self, dri: u8, dsi: u8) -> Result<()> {
        let speed_code = build_speed_code(dri, dsi);
        if speed_code != 0 {
            self.pcsc.set_comm_speed(speed_code)?;
        }
        Ok(())
    }

    fn prepare_type_b_link(
        &mut self,
        config: &mut IsoDepConfig,
        options: &TypeBDetectOptions,
    ) -> Result<TypeBInfo> {
        self.pcsc
            .switch_protocol_iso14443_4b(config.fsdi, config.cid, 4)?;
        let info = self
            .pcsc
            .request_type_b_info(options.afi.unwrap_or(0x00), options.param.unwrap_or(0x00))?;
        apply_type_b_protocol_details(config, &info.protocol_info);
        Ok(info)
    }

    fn iso_dep_transceive(
        &mut self,
        frame: &[u8],
        protocol: ThroughProtocol,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let flags = protocol.iso_dep_flags();
        self.pcsc.transceive(frame, timeout, &flags)
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

    fn send_type_a_frame(
        &mut self,
        payload: &[u8],
        tx_valid_bits: Option<u8>,
        append_crc: bool,
        discard_crc: bool,
    ) -> Result<Vec<u8>> {
        let options = ThroughOptions {
            protocol: ThroughProtocol::Iso14443TypeA,
            append_crc: Some(append_crc),
            discard_crc: Some(discard_crc),
            insert_parity: Some(true),
            expect_parity: Some(true),
            append_protocol_prologue: Some(false),
            tx_valid_bits,
        };
        self.communicate_thru(payload, Some(TYPE_A_CMD_TIMEOUT_MS), Some(options))
    }

    fn perform_type_a_anticollision(&mut self) -> Result<(Vec<u8>, u8)> {
        let mut sel_code = 0x93;
        let mut uid = Vec::new();
        loop {
            let anticollision = self.send_type_a_frame(&[sel_code, 0x20], None, false, false)?;
            let block = anticollision
                .get(..5)
                .ok_or_else(|| DriverError::Other("invalid anticollision response".into()))?;
            let (uid_block, bcc) = block.split_at(4);
            let bcc = *bcc
                .first()
                .ok_or_else(|| DriverError::Other("invalid anticollision response".into()))?;
            validate_bcc(uid_block, bcc)?;
            let sak = self.send_type_a_select(sel_code, &anticollision)?;
            append_uid_block(&mut uid, uid_block);
            if (sak & 0x04) == 0 {
                return Ok((uid, sak));
            }
            sel_code = next_cascade_code(sel_code)?;
            uid.clear();
        }
    }

    fn send_type_a_select(&mut self, sel_code: u8, anticollision: &[u8]) -> Result<u8> {
        let mut select = Vec::with_capacity(7);
        select.extend_from_slice(&[sel_code, 0x70]);
        select.extend_from_slice(&anticollision[..5]);
        let sak_resp = self.send_type_a_frame(&select, None, true, true)?;
        sak_resp
            .first()
            .copied()
            .ok_or_else(|| DriverError::Other("missing SAK".into()))
    }

    fn send_type_a_pps(&mut self, config: &IsoDepConfig) -> Result<()> {
        let (dri, dsi) = data_rate_symbols(config);
        if dri == 0 && dsi == 0 {
            return Ok(());
        }
        let ppss = 0xD0 | (config.cid & 0x0F);
        let pps0 = 0x11;
        let pps1 = ((dsi & 0x03) << 2) | (dri & 0x03);
        let frame = [ppss, pps0, pps1];
        let response = self.send_type_a_frame(&frame, None, true, true)?;
        if response.first().copied() != Some(ppss) {
            return Err(DriverError::Other("PPS response mismatch".into()));
        }
        self.apply_comm_speed(dri, dsi)
    }

    fn send_type_b_frame(
        &mut self,
        payload: &[u8],
        append_crc: bool,
        discard_crc: bool,
        timeout_ms: u16,
    ) -> Result<Vec<u8>> {
        let options = ThroughOptions {
            protocol: ThroughProtocol::Iso14443TypeB,
            append_crc: Some(append_crc),
            discard_crc: Some(discard_crc),
            insert_parity: Some(false),
            expect_parity: Some(false),
            append_protocol_prologue: Some(false),
            tx_valid_bits: None,
        };
        self.communicate_thru(payload, Some(timeout_ms), Some(options))
    }
}

fn build_type_b_attrib_command(
    info: &TypeBInfo,
    config: &IsoDepConfig,
    dri: u8,
    dsi: u8,
) -> Vec<u8> {
    let param2 = ((dsi & 0x03) << 6) | ((dri & 0x03) << 4) | (config.fsdi & 0x0F);
    let param3 = info.protocol_info.get(1).copied().unwrap_or(0x02) & 0x0F;
    let mut frame = Vec::with_capacity(9);
    frame.push(0x1D);
    frame.extend_from_slice(&info.pupi);
    frame.push(0x00);
    frame.push(param2);
    frame.push(param3);
    frame.push(config.cid & 0x0F);
    frame
}

fn ensure_rffe_category(category: u8) -> Result<()> {
    match category {
        RFFE_PARAM_EEPROM | RFFE_PARAM_PD_SC_DPC | RFFE_PARAM_PROTOCOL_CONFIGURATION => Ok(()),
        _ => Err(DriverError::Other(format!(
            "unsupported RFFE parameter category {category}"
        ))),
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

impl<T: Transport> FelicaDriver for Device<T> {
    fn detect_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<Type3TagPollingResult> {
        self.detect_type_f(target, system_code, request_code, time_slots)
    }

    fn transceive(
        &mut self,
        target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>> {
        self.transceive(target, data, timeout_ms)
    }
}

fn duration_from_timeout(timeout_ms: Option<u16>) -> Duration {
    timeout_ms
        .map(|ms| Duration::from_millis(ms as u64))
        .unwrap_or_else(|| Duration::from_millis(0))
}

fn data_rate_symbols(config: &IsoDepConfig) -> (u8, u8) {
    (config.dr.symbol().min(3), config.ds.symbol().min(3))
}

fn format_firmware(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 {
        return None;
    }
    Some(format!(
        "v{:02X}.{:02X}.{:02X}.{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    ))
}

fn apply_ats_config(config: &mut IsoDepConfig, ats: &[u8]) {
    if let Err(err) = config.apply_ats(ats) {
        warn!("failed to apply ATS parameters: {err}");
    } else {
        debug!("Port-400 ATS: {}", encode(ats));
    }
}

fn apply_type_b_protocol_details(config: &mut IsoDepConfig, info: &[u8]) {
    if let Err(err) = config.apply_type_b_protocol_info(info) {
        warn!("failed to apply Type-B protocol info: {err}");
    } else {
        debug!("Port-400 Type-B protocol info: {}", encode(info));
    }
}

fn validate_bcc(block: &[u8], bcc: u8) -> Result<()> {
    let computed_bcc = block.iter().fold(0u8, |acc, b| acc ^ b);
    if bcc == computed_bcc {
        Ok(())
    } else {
        Err(DriverError::Other("UID BCC mismatch".into()))
    }
}

fn next_cascade_code(sel_code: u8) -> Result<u8> {
    match sel_code {
        0x93 => Ok(0x95),
        0x95 => Ok(0x97),
        _ => Err(DriverError::Other(
            "unsupported Type-A cascade level".into(),
        )),
    }
}

fn append_uid_block(uid: &mut Vec<u8>, block: &[u8]) {
    if block.first() == Some(&0x88) && block.len() >= 4 {
        uid.extend_from_slice(&block[1..4]);
    } else {
        uid.extend_from_slice(block);
    }
}

fn build_speed_code(dri: u8, dsi: u8) -> u8 {
    ((dri & 0x07) << 3) | (dsi & 0x07)
}
