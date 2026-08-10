use crate::clf::errors::CommunicationError;
use crate::driver::errors::{DriverError, Result};
use crate::transport::Transport;
use log::{debug, warn};
use std::borrow::Cow;
use std::convert::{TryFrom, TryInto};
use std::io::{self, Error, ErrorKind};
use std::thread::sleep;
use std::time::{Duration, Instant};

const START_TRANSPARENT_SESSION_TAG: u8 = 0x81;
const END_TRANSPARENT_SESSION_TAG: u8 = 0x82;
const TURN_OFF_RF_TAG: u8 = 0x83;
const TURN_ON_RF_TAG: u8 = 0x84;
const TRANSMISSION_AND_RECEPTION_FLAG_TAG: u8 = 0x90;
const TRANSMISSION_BIT_FRAMING_TAG: u8 = 0x91;
const RESPONSE_BIT_FRAMING_TAG: u8 = 0x92;
const TRANSCEIVE_TAG: u8 = 0x95;
const RESPONSE_STATUS_TAG: u8 = 0x96;
const RESPONSE_DATA_TAG: u8 = 0x97;
const SWITCH_PROTOCOL_METADATA_TAG: u8 = 0x8F;
const STATUS_TLV_TAG: u8 = 0xC0;
const DEVICE_STATE_TLV_TAG: u8 = 0x80;
const EXTENDED_TAG_PREFIX: u8 = 0x5F;
const ATR_TLV_TAG: u8 = 0x51;
const FDT_TLV_TAG: u8 = 0x46;
const GET_DATA_INS: u8 = 0xCA;
const GET_FIRMWARE_VERSION_INS: u8 = 0x56;
const GET_PROPERTY_INS: u8 = 0x5F;
const GET_UID_SELECTOR: u8 = 0x00;
const GET_HISTORICAL_BYTES_SELECTOR: u8 = 0x01;
const GET_CARD_ID_SELECTOR: u8 = 0xF0;
const GET_CARD_NAME_SELECTOR: u8 = 0xF1;
const GET_CARD_BAUDRATE_SELECTOR: u8 = 0xF2;
const GET_CARD_TYPE_SELECTOR: u8 = 0xF3;
const GET_CARD_TYPE_NAME_SELECTOR: u8 = 0xF4;
const MANAGE_SESSION_INS: u8 = 0x50;
const TRANSPARENT_SESSION_CHANNEL: u8 = 0x01;
const SLOT_BUSY_ERROR: u8 = 0xE0;
const VENDOR_SPECIFIC_TAG: u8 = 0xFF;
const VENDOR_TAG_RESPONSE: u8 = 0x6D;
const DIAGNOSE_INS: u8 = 0x57;
const PREPARE_FIRMWARE_UPDATE_INS: u8 = 0x53;
const UPDATE_FIRMWARE_INS: u8 = 0x54;
const RESET_DEVICE_INS: u8 = 0x55;
const DIAG_TEST_COMMUNICATION_LINE: u8 = 0x00;
const DIAG_TEST_ROM: u8 = 0x01;
const DIAG_TEST_RAM: u8 = 0x02;
const DIAG_TEST_POLLING: u8 = 0x03;
const READ_RFFE_PARAMETER_INS: u8 = 0x61;
const WRITE_RFFE_PARAMETER_INS: u8 = 0x62;
const RFFE_PARAM_EEPROM: u8 = 0x01;
const RFFE_PARAM_PD_SC_DPC: u8 = 0x02;
const RFFE_PARAM_PROTOCOL_CONFIGURATION: u8 = 0x03;
const RFFE_PARAM_PRODUCTION_DATA: u8 = 0x01;
const RFFE_PARAM_SYSTEM_CONFIGURATION: u8 = 0x02;
const RFFE_PARAM_DPC: u8 = 0x03;

const DEFAULT_RECEIVE_TIMEOUT: Duration = Duration::from_millis(1_500);
const SLOT_BUSY_WAIT_TIME: Duration = Duration::from_millis(50);
const TIME_EXTENSION_WAIT: Duration = Duration::from_millis(20);
const RF_ON_GUARD_TIME: Duration = Duration::from_millis(21);
const RF_OFF_GUARD_TIME: Duration = Duration::from_millis(30);
const SWITCH_PROTOCOL_GUARD_TIME: Duration = Duration::from_millis(20);
const CCID_SLOT_NUMBER: u8 = 0;
const SLOT_BUSY_RETRY_COUNT: usize = 1;
const SLOT_BUSY_END_SESSION_RETRIES: usize = 4;
const SEQUENCE_ERROR_RETRY_COUNT: usize = 2;

#[derive(Clone, Copy, Debug, Default)]
pub struct TransmissionFlags {
    pub append_crc: bool,
    pub discard_crc: bool,
    pub insert_parity: bool,
    pub expect_parity: bool,
    pub append_protocol_prologue: bool,
    pub tx_valid_bits: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct TypeBInfo {
    pub pupi: [u8; 4],
    pub application_data: [u8; 4],
    pub protocol_info: Vec<u8>,
}

impl TransmissionFlags {
    pub fn felica() -> Self {
        Self {
            append_crc: true,
            discard_crc: true,
            insert_parity: false,
            expect_parity: false,
            append_protocol_prologue: false,
            tx_valid_bits: None,
        }
    }

    pub fn iso14443_type_a() -> Self {
        Self {
            append_crc: true,
            discard_crc: true,
            insert_parity: true,
            expect_parity: true,
            append_protocol_prologue: false,
            tx_valid_bits: None,
        }
    }

    pub fn iso14443_type_b() -> Self {
        Self {
            append_crc: true,
            discard_crc: true,
            insert_parity: false,
            expect_parity: false,
            append_protocol_prologue: false,
            tx_valid_bits: None,
        }
    }

    pub fn iso15693() -> Self {
        Self {
            append_crc: true,
            discard_crc: true,
            insert_parity: false,
            expect_parity: false,
            append_protocol_prologue: false,
            tx_valid_bits: None,
        }
    }
}

pub struct Pcsc<T: Transport> {
    ccid: CcidTransport<T>,
    receive_timeout: Duration,
    /// The reader keeps the transmission bit framing it was last given, so a
    /// command that shortened the frame has to be followed by an explicit reset
    /// before the next full-byte command.
    modified_bit_framing: bool,
}

impl<T: Transport> Pcsc<T> {
    pub fn new(transport: T) -> Self {
        Self {
            ccid: CcidTransport::new(transport),
            receive_timeout: DEFAULT_RECEIVE_TIMEOUT,
            modified_bit_framing: false,
        }
    }

    pub fn set_receive_timeout(&mut self, timeout: Duration) {
        self.receive_timeout = timeout;
    }

    pub fn start_transparent_session(&mut self, priority: bool) -> Result<()> {
        debug!("start transparent session (priority={priority})");
        if priority {
            // Releasing a session another process may hold is best effort: there
            // is nothing to end when no session is open.
            let _ = self.manage_session(
                &[(END_TRANSPARENT_SESSION_TAG, &[][..])],
                SLOT_BUSY_END_SESSION_RETRIES,
            );
        }
        self.manage_session(
            &[(START_TRANSPARENT_SESSION_TAG, &[][..])],
            SLOT_BUSY_RETRY_COUNT,
        )?;
        self.turn_off_rf()?;
        sleep(RF_OFF_GUARD_TIME);
        self.turn_on_rf()?;
        sleep(RF_ON_GUARD_TIME);
        self.modified_bit_framing = false;
        Ok(())
    }

    pub fn end_transparent_session(&mut self) -> Result<()> {
        debug!("end transparent session");
        // The RF field is switched off first so the card is not left powered; a
        // failure here must not keep the session open.
        if let Err(err) = self.turn_off_rf() {
            debug!("turning the RF off before ending the session failed: {err}");
        }
        self.manage_session(
            &[(END_TRANSPARENT_SESSION_TAG, &[][..])],
            SLOT_BUSY_END_SESSION_RETRIES,
        )?;
        self.modified_bit_framing = false;
        Ok(())
    }

    pub fn switch_protocol_type_f(&mut self, auto_baud: bool) -> Result<()> {
        let param = if auto_baud { 1 } else { 0 };
        self.switch_protocol(3, param, None, None)
    }

    pub fn switch_protocol_iso14443_3a(&mut self) -> Result<()> {
        self.switch_protocol(0, 3, None, None)
    }

    pub fn switch_protocol_iso14443_4a(&mut self, fsdi: u8, cid: u8, parameter: u8) -> Result<()> {
        self.switch_protocol(0, parameter, Some(fsdi), Some(cid))
    }

    pub fn switch_protocol_iso14443_4b(&mut self, fsdi: u8, cid: u8, parameter: u8) -> Result<()> {
        self.switch_protocol(1, parameter, Some(fsdi), Some(cid))
    }

    pub fn switch_protocol_iso15693(&mut self) -> Result<()> {
        self.switch_protocol(2, 3, None, None)
    }

    pub fn transceive(
        &mut self,
        payload: &[u8],
        timeout: Duration,
        flags: &TransmissionFlags,
    ) -> Result<Vec<u8>> {
        self.exchange(TRANSCEIVE_TAG, payload)
            .timeout(timeout)
            .flags(*flags)
            .execute_payload()
    }

    pub fn get_data(&mut self, selector: u8) -> Result<Vec<u8>> {
        let command = EscapeCommand::new(GET_DATA_INS, selector, 0x00);
        self.send_escape_command(command)
    }

    pub fn get_firmware_version(&mut self) -> Result<Vec<u8>> {
        let frame = [0xFF, GET_FIRMWARE_VERSION_INS, 0x00, 0x00];
        let response = self
            .ccid
            .escape(&frame, self.receive_timeout, SLOT_BUSY_RETRY_COUNT)?;
        Self::verify_status(&response)?;
        Ok(response[..response.len() - 2].to_vec())
    }

    pub fn card_baudrate(&mut self) -> Result<Option<u32>> {
        let data = self.get_data(GET_CARD_BAUDRATE_SELECTOR)?;
        let rate = data.first().and_then(|code| match code {
            1 => Some(106),
            2 => Some(212),
            3 => Some(424),
            4 => Some(848),
            _ => None,
        });
        Ok(rate)
    }

    pub fn card_id(&mut self) -> Result<Vec<u8>> {
        self.get_data(GET_CARD_ID_SELECTOR)
    }

    pub fn card_name(&mut self) -> Result<Vec<u8>> {
        self.get_data(GET_CARD_NAME_SELECTOR)
    }

    pub fn card_type(&mut self) -> Result<Vec<u8>> {
        self.get_data(GET_CARD_TYPE_SELECTOR)
    }

    pub fn card_type_name(&mut self) -> Result<Vec<u8>> {
        self.get_data(GET_CARD_TYPE_NAME_SELECTOR)
    }

    pub fn request_type_b_info(&mut self, afi: u8, param: u8) -> Result<TypeBInfo> {
        const REQB: u8 = 0x05;
        let cmd = [REQB, afi, param];
        let flags = TransmissionFlags::iso14443_type_b();
        let response = self.transceive(&cmd, Duration::from_millis(10), &flags)?;
        if response.len() < 13 || response[0] != 0x50 {
            return Err(DriverError::Other(
                "invalid or unsupported SENSB_RES response".into(),
            ));
        }
        let pupi: [u8; 4] = response[1..5]
            .try_into()
            .map_err(|_| DriverError::Other("SENSB_RES missing PUPI".into()))?;
        let application_data: [u8; 4] = response[5..9]
            .try_into()
            .map_err(|_| DriverError::Other("SENSB_RES missing application data".into()))?;
        let protocol_info = response[9..].to_vec();
        Ok(TypeBInfo {
            pupi,
            application_data,
            protocol_info,
        })
    }

    pub fn get_uid(&mut self) -> Result<Vec<u8>> {
        self.get_data(GET_UID_SELECTOR)
    }

    pub fn get_historical_bytes(&mut self) -> Result<Vec<u8>> {
        self.get_data(GET_HISTORICAL_BYTES_SELECTOR)
    }

    pub fn set_detection_target(&mut self, selector: u8) -> Result<()> {
        let data = [selector];
        let command = EscapeCommand::with_data(0x5A, 0x00, 0x00, &data);
        self.send_escape_command(command).map(|_| ())
    }

    /// Sets the RF speed the frontend uses for `protocol` (0: Type A,
    /// 1: Type B, 2: Type F), where the two speed codes are the ones reported by
    /// [`Self::card_baudrate`].
    pub fn set_rf_speed(&mut self, protocol: u8, rw_to_card: u8, card_to_rw: u8) -> Result<()> {
        let data = [protocol, rw_to_card, card_to_rw];
        let command = EscapeCommand::with_data(0x5C, 0x00, 0x00, &data);
        self.send_escape_command(command).map(|_| ())
    }

    /// Reads the RF speed currently configured for `protocol`, returning the
    /// reader-to-card code first and the card-to-reader code second.
    pub fn get_rf_speed(&mut self, protocol: u8) -> Result<Vec<u8>> {
        let data = [protocol];
        let command = EscapeCommand::with_data(0x5D, 0x00, 0x00, &data);
        self.send_escape_command(command)
    }

    pub fn set_comm_speed(&mut self, speed: u8) -> Result<()> {
        // Vendor specific parameters are nested TLVs: FF <sub tag> <len> <value>,
        // the same shape switch_protocol uses for FSDI and CID.
        let payload = [VENDOR_SPECIFIC_TAG, 0x6E, 0x03, 0x05, 0x01, speed];
        self.manage_session_raw(&payload, 0x00, SLOT_BUSY_RETRY_COUNT)?;
        Ok(())
    }

    pub fn set_tx_rx_flag(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.exchange(TRANSMISSION_AND_RECEPTION_FLAG_TAG, data)
            .execute_payload()
    }

    pub fn set_tx_bit_framing(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.exchange(TRANSMISSION_BIT_FRAMING_TAG, data)
            .execute_payload()
    }

    pub fn get_property(&mut self, selector: u8) -> Result<Vec<u8>> {
        let command = EscapeCommand::new(GET_PROPERTY_INS, selector, 0x00);
        self.send_escape_command(command)
    }

    pub fn prepare_firmware_update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut frame = Vec::with_capacity(7 + data.len());
        frame.extend_from_slice(&[
            0xFF,
            PREPARE_FIRMWARE_UPDATE_INS,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
        ]);
        frame.extend_from_slice(data);
        self.send_extended_escape(&frame)
    }

    pub fn update_firmware(&mut self, sequence: u16, data: &[u8]) -> Result<Vec<u8>> {
        let mut frame = Vec::with_capacity(7 + data.len());
        frame.extend_from_slice(&[
            0xFF,
            UPDATE_FIRMWARE_INS,
            (sequence & 0xFF) as u8,
            (sequence >> 8) as u8,
            0x00,
            0x01,
            0x00,
        ]);
        frame.extend_from_slice(data);
        self.send_extended_escape(&frame)
    }

    pub fn reset_device(&mut self, delay_ms: u16) -> Result<Vec<u8>> {
        let frame = vec![
            0xFF,
            RESET_DEVICE_INS,
            0x00,
            0x00,
            0x02,
            (delay_ms & 0xFF) as u8,
            (delay_ms >> 8) as u8,
        ];
        self.send_extended_escape(&frame)
    }

    pub fn diagnose_communication_line(&mut self, pattern: &[u8]) -> Result<Vec<u8>> {
        let total_len = pattern
            .len()
            .checked_add(1)
            .ok_or_else(|| DriverError::Other("diagnose payload too large".into()))?;
        let total_len = u16::try_from(total_len)
            .map_err(|_| DriverError::Other("diagnose payload too large".into()))?;
        let mut frame = Vec::with_capacity(pattern.len() + 11);
        frame.extend_from_slice(&[0xFF, DIAGNOSE_INS, 0x00, 0x00]);
        frame.push(0x00);
        frame.push((total_len >> 8) as u8);
        frame.push((total_len & 0xFF) as u8);
        frame.push(DIAG_TEST_COMMUNICATION_LINE);
        frame.extend_from_slice(pattern);
        frame.extend_from_slice(&[0x00, 0x00, 0x00]);
        let payload = self.send_extended_escape(&frame)?;
        if payload.len() != total_len as usize {
            return Err(DriverError::Other(
                "diagnose response length mismatch".into(),
            ));
        }
        if payload.first().copied() != Some(DIAG_TEST_COMMUNICATION_LINE) {
            return Err(DriverError::Other("diagnose test mismatch".into()));
        }
        Ok(payload[1..].to_vec())
    }

    pub fn diagnose_rom(&mut self) -> Result<u8> {
        let frame = [0xFF, DIAGNOSE_INS, 0x00, 0x00, 0x01, DIAG_TEST_ROM];
        let payload = self.send_extended_escape(&frame)?;
        if payload.len() != 2 || payload[0] != DIAG_TEST_ROM {
            return Err(DriverError::Other("diagnose ROM response invalid".into()));
        }
        Ok(payload[1])
    }

    pub fn diagnose_ram(&mut self) -> Result<Vec<u8>> {
        let frame = [0xFF, DIAGNOSE_INS, 0x00, 0x00, 0x01, DIAG_TEST_RAM];
        let payload = self.send_extended_escape(&frame)?;
        if payload.is_empty() || payload.len() > 7 {
            return Err(DriverError::Other(
                "diagnose RAM response length invalid".into(),
            ));
        }
        if payload[0] != DIAG_TEST_RAM {
            return Err(DriverError::Other("diagnose RAM response invalid".into()));
        }
        Ok(payload[1..].to_vec())
    }

    pub fn diagnose_polling(&mut self, protocol_code: u8, count: u8) -> Result<u8> {
        let frame = [
            0xFF,
            DIAGNOSE_INS,
            0x00,
            0x00,
            0x03,
            DIAG_TEST_POLLING,
            protocol_code,
            count,
        ];
        let payload = self.send_extended_escape(&frame)?;
        if payload.len() != 2 || payload[0] != DIAG_TEST_POLLING {
            return Err(DriverError::Other(
                "diagnose polling response invalid".into(),
            ));
        }
        Ok(payload[1])
    }

    pub fn start_rffe_parameter_mode(&mut self) -> Result<()> {
        self.end_transparent_session()?;
        Ok(())
    }

    pub fn end_rffe_parameter_mode(&mut self) -> Result<()> {
        self.start_transparent_session(false)
    }

    /// Reads an RFFE parameter. Only the EEPROM category carries a request
    /// payload (the address block to read); the other categories are addressed
    /// by `selector` alone.
    pub fn read_rffe_parameter(
        &mut self,
        category: u8,
        selector: u8,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let payload: &[u8] = match category {
            RFFE_PARAM_EEPROM => {
                if selector != 0 {
                    return Err(DriverError::Other(
                        "EEPROM parameters use selector 0".into(),
                    ));
                }
                data
            }
            RFFE_PARAM_PD_SC_DPC => {
                Self::ensure_pd_sc_dpc_selector(selector, false)?;
                &[]
            }
            RFFE_PARAM_PROTOCOL_CONFIGURATION => &[],
            _ => {
                return Err(DriverError::Other(format!(
                    "unsupported RFFE parameter category {category}"
                )));
            }
        };
        self.rffe_command(READ_RFFE_PARAMETER_INS, category, selector, payload)
    }

    pub fn write_rffe_parameter(
        &mut self,
        category: u8,
        selector: u8,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        match category {
            RFFE_PARAM_EEPROM => {
                if selector != 0 {
                    return Err(DriverError::Other(
                        "EEPROM parameters use selector 0".into(),
                    ));
                }
            }
            RFFE_PARAM_PD_SC_DPC => Self::ensure_pd_sc_dpc_selector(selector, true)?,
            RFFE_PARAM_PROTOCOL_CONFIGURATION => {}
            _ => {
                return Err(DriverError::Other(format!(
                    "unsupported RFFE parameter category {category}"
                )));
            }
        }
        self.rffe_command(WRITE_RFFE_PARAMETER_INS, category, selector, data)
    }

    /// Validates the selector of the PD/SC/DPC category. Production data is
    /// readable but not writable.
    fn ensure_pd_sc_dpc_selector(selector: u8, write: bool) -> Result<()> {
        let allowed = matches!(
            (selector, write),
            (RFFE_PARAM_PRODUCTION_DATA, false)
                | (RFFE_PARAM_SYSTEM_CONFIGURATION | RFFE_PARAM_DPC, _)
        );
        if allowed {
            Ok(())
        } else {
            Err(DriverError::Other(format!(
                "unsupported PD/SC/DPC parameter selector {selector}"
            )))
        }
    }

    pub fn turn_off_rf(&mut self) -> Result<()> {
        self.manage_session(&[(TURN_OFF_RF_TAG, &[][..])], SLOT_BUSY_RETRY_COUNT)?;
        Ok(())
    }

    pub fn turn_on_rf(&mut self) -> Result<()> {
        self.manage_session(&[(TURN_ON_RF_TAG, &[][..])], SLOT_BUSY_RETRY_COUNT)?;
        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        self.ccid.close().map_err(DriverError::from)
    }

    fn exchange<'a, 'b>(
        &'a mut self,
        tag: u8,
        payload: &'b [u8],
    ) -> TransparentExchange<'a, 'b, T> {
        TransparentExchange::new(self, tag, payload)
    }

    fn switch_protocol(
        &mut self,
        mode: u8,
        parameter: u8,
        fsdi: Option<u8>,
        cid: Option<u8>,
    ) -> Result<()> {
        let mut payload = Vec::new();
        if let Some(value) = fsdi {
            payload.extend_from_slice(&[0xFF, 0x6E, 0x03, 0x01, 0x01, value]);
        }
        if let Some(value) = cid {
            payload.extend_from_slice(&[0xFF, 0x6E, 0x03, 0x08, 0x01, value]);
        }
        payload.push(SWITCH_PROTOCOL_METADATA_TAG);
        payload.push(2);
        payload.push(mode);
        payload.push(parameter);
        let response = self.manage_session_raw(&payload, 0x02, SLOT_BUSY_RETRY_COUNT)?;
        Self::parse_switch_protocol_response(&response)?;
        // Switching the protocol re-initialises the framing the reader applies.
        self.modified_bit_framing = false;
        sleep(SWITCH_PROTOCOL_GUARD_TIME);
        Ok(())
    }

    fn send_escape_command(&mut self, command: EscapeCommand<'_>) -> Result<Vec<u8>> {
        let frame = command.into_bytes();
        let response = self
            .ccid
            .escape(&frame, self.receive_timeout, SLOT_BUSY_RETRY_COUNT)?;
        Self::verify_status(&response)?;
        Ok(response[..response.len() - 2].to_vec())
    }

    fn send_extended_escape(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let response = self
            .ccid
            .escape(frame, self.receive_timeout, SLOT_BUSY_RETRY_COUNT)?;
        Self::verify_status(&response)?;
        Ok(response[..response.len() - 2].to_vec())
    }

    fn rffe_command(
        &mut self,
        ins: u8,
        category: u8,
        selector: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let command = EscapeCommand::with_data(ins, category, selector, payload);
        self.send_escape_command(command)
    }

    fn manage_session(
        &mut self,
        commands: &[(u8, &[u8])],
        slot_busy_retries: usize,
    ) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        for (tag, value) in commands {
            payload.push(*tag);
            payload.push(value.len() as u8);
            payload.extend_from_slice(value);
        }
        let response = self.manage_session_raw(&payload, 0x00, slot_busy_retries)?;
        Self::parse_manage_session_response(&response)?;
        Ok(response)
    }

    /// Sends a Manage Session APDU carrying `payload` on the given P2 channel and
    /// returns the response data without the trailing status word.
    fn manage_session_raw(
        &mut self,
        payload: &[u8],
        channel: u8,
        slot_busy_retries: usize,
    ) -> Result<Vec<u8>> {
        let mut frame = vec![0xFF, MANAGE_SESSION_INS, 0x00, channel, payload.len() as u8];
        frame.extend_from_slice(payload);
        frame.push(0x00);
        let response = self
            .ccid
            .escape(&frame, self.receive_timeout, slot_busy_retries)?;
        Self::verify_status(&response)?;
        Ok(response[..response.len() - 2].to_vec())
    }

    fn transparent_exchange(
        &mut self,
        tag: u8,
        payload: &[u8],
        timeout: Duration,
        flags: Option<&TransmissionFlags>,
    ) -> Result<TransparentExchangeResult> {
        let mut fields = Vec::new();
        if let Some(flags) = flags {
            // The mask is sent even when it is zero: the reader keeps the flags of
            // the previous command, so the defaults have to be restated.
            let mask = Self::build_flag_mask(flags);
            fields.push(TRANSMISSION_AND_RECEPTION_FLAG_TAG);
            fields.push(2);
            fields.push((mask >> 8) as u8);
            fields.push((mask & 0xFF) as u8);
        }
        let tx_valid_bits = flags.and_then(|flags| flags.tx_valid_bits);
        match tx_valid_bits {
            Some(bits) => {
                if !(1..=8).contains(&bits) {
                    return Err(DriverError::Other(format!(
                        "invalid TX number of valid bits {bits}"
                    )));
                }
                // A complete byte is encoded as zero valid bits.
                let value = if bits < 8 { bits } else { 0 };
                fields.push(TRANSMISSION_BIT_FRAMING_TAG);
                fields.push(1);
                fields.push(value);
            }
            // Undo the short framing left behind by the previous command.
            None if self.modified_bit_framing => {
                fields.push(TRANSMISSION_BIT_FRAMING_TAG);
                fields.push(1);
                fields.push(0);
            }
            None => {}
        }
        self.modified_bit_framing = tx_valid_bits.is_some();
        if timeout > Duration::from_millis(0) {
            let micros = (timeout.as_millis() * 1_000).min(u32::MAX as u128) as u32;
            fields.push(EXTENDED_TAG_PREFIX);
            fields.push(FDT_TLV_TAG);
            fields.push(4);
            fields.extend_from_slice(&micros.to_le_bytes());
        }
        if !payload.is_empty() {
            Self::push_extended_tlv(&mut fields, tag, payload);
        }
        let mut frame = vec![0xFF, MANAGE_SESSION_INS, 0x00, TRANSPARENT_SESSION_CHANNEL];
        frame.push(0x00);
        frame.push(((fields.len() >> 8) & 0xFF) as u8);
        frame.push((fields.len() & 0xFF) as u8);
        frame.extend_from_slice(&fields);
        frame.extend_from_slice(&[0x00, 0x00, 0x00]);
        let response = self
            .ccid
            .escape(&frame, self.receive_timeout, SLOT_BUSY_RETRY_COUNT)?;
        Self::verify_status(&response)?;
        Self::parse_transparent_response(&response[..response.len() - 2])
    }

    fn build_flag_mask(flags: &TransmissionFlags) -> u16 {
        let mut mask = 0u16;
        if !flags.append_crc {
            mask |= 0x0001;
        }
        if !flags.discard_crc {
            mask |= 0x0002;
        }
        if !flags.insert_parity {
            mask |= 0x0004;
        }
        if !flags.expect_parity {
            mask |= 0x0008;
        }
        if !flags.append_protocol_prologue {
            mask |= 0x0010;
        }
        mask
    }

    fn push_extended_tlv(buf: &mut Vec<u8>, tag: u8, value: &[u8]) {
        buf.push(tag);
        buf.push(0x82);
        buf.push(((value.len() >> 8) & 0xFF) as u8);
        buf.push((value.len() & 0xFF) as u8);
        buf.extend_from_slice(value);
    }

    fn verify_status(data: &[u8]) -> Result<()> {
        if data.len() < 2 {
            return Err(DriverError::Other("short CCID status".into()));
        }
        let sw1 = data[data.len() - 2];
        let sw2 = data[data.len() - 1];
        if sw1 == 0x90 && sw2 == 0x00 {
            return Ok(());
        }
        Err(DriverError::Other(format!(
            "CCID status {:02X}{:02X}",
            sw1, sw2
        )))
    }

    /// Reads the single byte length that follows a TLV tag and returns the value.
    ///
    /// `idx` points at the length byte on entry and past the value on return.
    fn take_tlv_value<'a>(data: &'a [u8], idx: &mut usize, context: &str) -> Result<&'a [u8]> {
        let len_index = *idx;
        let len = *data
            .get(len_index)
            .ok_or_else(|| DriverError::Other(format!("{context}: TLV length missing")))?
            as usize;
        // The value has to stay inside the response, matching the bounds check the
        // reference library applies.
        if len_index + len >= data.len() {
            return Err(DriverError::Other(format!(
                "{context}: TLV length out of range"
            )));
        }
        let start = len_index + 1;
        *idx = start + len;
        Ok(&data[start..start + len])
    }

    /// Checks the `C0` status TLV every Manage Session response carries.
    fn take_status_tlv(data: &[u8], idx: &mut usize, context: &str) -> Result<()> {
        let value = Self::take_tlv_value(data, idx, context)?;
        if value.len() != 3 {
            return Err(DriverError::Other(format!(
                "{context}: malformed status TLV"
            )));
        }
        if value != [0x00, 0x90, 0x00] {
            return Err(Self::status_error(value));
        }
        Ok(())
    }

    /// Skips a vendor specific TLV. Returns `false` when the sub tag is unknown,
    /// in which case the rest of the response is not parsed any further.
    fn skip_vendor_tlv(data: &[u8], idx: &mut usize, context: &str) -> Result<bool> {
        let Some(&subtag) = data.get(*idx) else {
            debug!("{context}: truncated vendor TLV");
            return Ok(false);
        };
        *idx += 1;
        if subtag != VENDOR_TAG_RESPONSE {
            warn!("{context}: unexpected vendor tag {subtag:02X}");
            return Ok(false);
        }
        let value = Self::take_tlv_value(data, idx, context)?;
        if value.len() != 3 && value.len() != 6 {
            return Err(DriverError::Other(format!(
                "{context}: malformed vendor TLV"
            )));
        }
        Ok(true)
    }

    fn parse_manage_session_response(data: &[u8]) -> Result<()> {
        const CONTEXT: &str = "manageSession";
        let mut idx = 0;
        while idx + 1 < data.len() {
            let tag = data[idx];
            idx += 1;
            match tag {
                STATUS_TLV_TAG => Self::take_status_tlv(data, &mut idx, CONTEXT)?,
                DEVICE_STATE_TLV_TAG => {
                    let value = Self::take_tlv_value(data, &mut idx, CONTEXT)?;
                    if value.len() != 3 {
                        return Err(DriverError::Other(format!(
                            "{CONTEXT}: malformed device state TLV"
                        )));
                    }
                }
                VENDOR_SPECIFIC_TAG => {
                    if !Self::skip_vendor_tlv(data, &mut idx, CONTEXT)? {
                        break;
                    }
                }
                _ => {
                    warn!("{CONTEXT}: unexpected TAG {tag:02X}");
                    break;
                }
            }
        }
        Ok(())
    }

    fn parse_switch_protocol_response(data: &[u8]) -> Result<()> {
        const CONTEXT: &str = "switchProtocol";
        let mut idx = 0;
        while idx + 1 < data.len() {
            let tag = data[idx];
            idx += 1;
            match tag {
                STATUS_TLV_TAG => Self::take_status_tlv(data, &mut idx, CONTEXT)?,
                SWITCH_PROTOCOL_METADATA_TAG => {
                    let value = Self::take_tlv_value(data, &mut idx, CONTEXT)?;
                    if value.len() != 1 && value.len() != 3 {
                        return Err(DriverError::Other(format!(
                            "{CONTEXT}: malformed protocol TLV"
                        )));
                    }
                }
                EXTENDED_TAG_PREFIX => {
                    // The reader reports the card's ATR as a 5F51 TLV.
                    let subtag = data.get(idx).copied();
                    idx += 1;
                    if subtag != Some(ATR_TLV_TAG) {
                        return Err(DriverError::Other(format!("{CONTEXT}: ATR error")));
                    }
                    Self::take_tlv_value(data, &mut idx, CONTEXT)?;
                }
                VENDOR_SPECIFIC_TAG => {
                    if !Self::skip_vendor_tlv(data, &mut idx, CONTEXT)? {
                        break;
                    }
                }
                _ => {
                    warn!("{CONTEXT}: unexpected TAG {tag:02X}");
                    break;
                }
            }
        }
        Ok(())
    }

    fn parse_transparent_response(data: &[u8]) -> Result<TransparentExchangeResult> {
        const CONTEXT: &str = "transparentExchange";
        let mut idx = 0;
        let mut result = TransparentExchangeResult::default();
        while idx + 1 < data.len() {
            let tag = data[idx];
            idx += 1;
            match tag {
                STATUS_TLV_TAG => Self::take_status_tlv(data, &mut idx, CONTEXT)?,
                RESPONSE_BIT_FRAMING_TAG => {
                    let value = Self::take_tlv_value(data, &mut idx, CONTEXT)?;
                    let [bits] = value else {
                        return Err(DriverError::Other(format!(
                            "{CONTEXT}: Reception Bit Framing error"
                        )));
                    };
                    // Zero valid bits stands for a complete byte.
                    result.valid_bits = Some(if *bits == 0 { 8 } else { *bits });
                }
                RESPONSE_STATUS_TAG => {
                    let value = Self::take_tlv_value(data, &mut idx, CONTEXT)?;
                    let [status, _] = value else {
                        return Err(DriverError::Other(format!(
                            "{CONTEXT}: Response Status error"
                        )));
                    };
                    result.rf_status = Some(*status);
                }
                RESPONSE_DATA_TAG => {
                    let (len, consumed) = Self::parse_length(&data[idx..]).map_err(|_| {
                        DriverError::Other(format!("{CONTEXT}: Response Data error"))
                    })?;
                    idx += consumed;
                    if idx + len > data.len() {
                        return Err(DriverError::Other(format!(
                            "{CONTEXT}: Response Data out of range"
                        )));
                    }
                    result.payload.extend_from_slice(&data[idx..idx + len]);
                    idx += len;
                }
                VENDOR_SPECIFIC_TAG => {
                    if !Self::skip_vendor_tlv(data, &mut idx, CONTEXT)? {
                        break;
                    }
                }
                _ => {
                    warn!("{CONTEXT}: unexpected TAG {tag:02X}");
                    break;
                }
            }
        }
        Ok(result)
    }

    fn parse_length(data: &[u8]) -> Result<(usize, usize)> {
        if data.is_empty() {
            return Err(DriverError::Other("missing length field".into()));
        }
        let first = data[0];
        if first < 0x80 {
            Ok((first as usize, 1))
        } else {
            let count = match first {
                0x81 => 1,
                0x82 => 2,
                0x83 => 3,
                0x84 => 4,
                _ => {
                    return Err(DriverError::Other("unsupported TLV length encoding".into()));
                }
            };
            if data.len() < 1 + count {
                return Err(DriverError::Other("incomplete TLV length field".into()));
            }
            let mut len = 0usize;
            for &byte in &data[1..=count] {
                len = (len << 8) | byte as usize;
            }
            Ok((len, 1 + count))
        }
    }

    /// Maps the status word of a `C0` TLV onto a driver error, keeping the
    /// distinctions the reference library draws between a card that did not
    /// answer, a card that answered with an unexpected status, and a reader that
    /// is owned by another application.
    fn status_error(value: &[u8]) -> DriverError {
        let sw1 = value.get(1).copied().unwrap_or_default();
        let sw2 = value.get(2).copied().unwrap_or_default();
        let text = format!(
            "status {:02X}{:02X}{:02X}",
            value.first().copied().unwrap_or_default(),
            sw1,
            sw2
        );
        match (sw1, sw2) {
            (0x64, 0x00 | 0x01) => DriverError::Communication(CommunicationError::Timeout(
                format!("{text} (no response packet received)"),
            )),
            (0x63, 0x01) => DriverError::Communication(CommunicationError::Protocol(format!(
                "{text} (invalid status)"
            ))),
            (0x69, 0x8A) => DriverError::Other(format!("{text} (failed to get access authority)")),
            _ => DriverError::Other(text),
        }
    }
}

struct CcidTransport<T: Transport> {
    transport: T,
    sequence: u8,
    buffer: Vec<u8>,
}

impl<T: Transport> CcidTransport<T> {
    fn new(transport: T) -> Self {
        Self {
            transport,
            sequence: 0,
            buffer: Vec::new(),
        }
    }

    fn escape(
        &mut self,
        payload: &[u8],
        timeout: Duration,
        slot_busy_retries: usize,
    ) -> Result<Vec<u8>> {
        let mut remaining_retries = slot_busy_retries + 1;
        while remaining_retries > 0 {
            let start = Instant::now();
            let seq = self.next_sequence();
            let frame = self.build_escape_frame(payload, seq);
            self.transport.write(&frame)?;
            self.buffer.clear();
            let mut seq_retry = SEQUENCE_ERROR_RETRY_COUNT + 1;
            loop {
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    return Err(DriverError::Io(Error::new(
                        ErrorKind::TimedOut,
                        "CCID escape timeout",
                    )));
                }
                let header = self.read_exact(10, timeout - elapsed)?;
                let (response, status) = CcidResponse::parse(&header, seq)?;
                if status == CommandStatus::SequenceMismatch {
                    seq_retry -= 1;
                    if seq_retry == 0 {
                        return Err(DriverError::Other("CCID sequence mismatch".into()));
                    }
                    // The body of the stale response still has to be drained,
                    // otherwise it would be mistaken for the next header.
                    if response.length > 0 {
                        let elapsed = start.elapsed();
                        if elapsed >= timeout {
                            return Err(DriverError::Io(Error::new(
                                ErrorKind::TimedOut,
                                "CCID escape timeout",
                            )));
                        }
                        self.read_exact(response.length, timeout - elapsed)?;
                    }
                    continue;
                }
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    return Err(DriverError::Io(Error::new(
                        ErrorKind::TimedOut,
                        "CCID escape timeout",
                    )));
                }
                let data = if response.length > 0 {
                    self.read_exact(response.length, timeout - elapsed)?
                } else {
                    Vec::new()
                };
                match status {
                    CommandStatus::Success => {
                        if data.len() < 2 {
                            return Err(DriverError::Other("escape response too short".into()));
                        }
                        return Ok(data);
                    }
                    CommandStatus::SlotBusy => {
                        remaining_retries -= 1;
                        if remaining_retries == 0 {
                            return Err(DriverError::Other("slot busy".into()));
                        }
                        sleep(SLOT_BUSY_WAIT_TIME);
                        break;
                    }
                    CommandStatus::TimeExtension => {
                        sleep(TIME_EXTENSION_WAIT);
                    }
                    CommandStatus::Failure(code) => {
                        return Err(DriverError::Other(format!("CCID failure {code:#04x}",)));
                    }
                    CommandStatus::SequenceMismatch => unreachable!(),
                }
            }
        }
        Err(DriverError::Other("slot busy".into()))
    }

    fn read_exact(&mut self, len: usize, timeout: Duration) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(len);
        let deadline = Instant::now() + timeout;
        while result.len() < len {
            if !self.buffer.is_empty() {
                let take = (len - result.len()).min(self.buffer.len());
                result.extend(self.buffer.drain(..take));
                continue;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(DriverError::Io(Error::new(
                    ErrorKind::TimedOut,
                    "USB read timeout",
                )));
            }
            let remaining = deadline - now;
            let chunk = self.transport.read(remaining)?;
            if chunk.is_empty() {
                continue;
            }
            let take = (len - result.len()).min(chunk.len());
            result.extend_from_slice(&chunk[..take]);
            if take < chunk.len() {
                self.buffer.extend_from_slice(&chunk[take..]);
            }
        }
        Ok(result)
    }

    fn build_escape_frame(&self, payload: &[u8], seq: u8) -> Vec<u8> {
        let mut frame = Vec::with_capacity(payload.len() + 10);
        frame.push(0x6B);
        let len = payload.len() as u32;
        frame.extend_from_slice(&len.to_le_bytes());
        frame.push(CCID_SLOT_NUMBER);
        frame.push(seq);
        frame.push(0);
        frame.push(0);
        frame.push(0);
        if !payload.is_empty() {
            frame.extend_from_slice(payload);
        }
        frame
    }

    fn next_sequence(&mut self) -> u8 {
        self.sequence = self.sequence.wrapping_add(1);
        self.sequence
    }

    fn close(&mut self) -> io::Result<()> {
        self.transport.close()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandStatus {
    Success,
    Failure(u8),
    SlotBusy,
    TimeExtension,
    SequenceMismatch,
}

struct CcidResponse {
    length: usize,
}

impl CcidResponse {
    fn parse(data: &[u8], expected_seq: u8) -> Result<(Self, CommandStatus)> {
        if data.len() < 10 {
            return Err(DriverError::Other("short CCID header".into()));
        }
        let message_type = data[0];
        if message_type != 0x83 {
            return Err(DriverError::Other("invalid CCID message".into()));
        }
        let length = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if data[5] != CCID_SLOT_NUMBER {
            return Err(DriverError::Other("invalid CCID slot number".into()));
        }
        let seq = data[6];
        if seq != expected_seq {
            // The length is reported so the caller can drain the stale response.
            return Ok((Self { length }, CommandStatus::SequenceMismatch));
        }
        let status_byte = data[7];
        let error = data[8];
        let command_status = (status_byte >> 6) & 0x03;
        let status = match command_status {
            0 => CommandStatus::Success,
            1 => {
                if error == SLOT_BUSY_ERROR {
                    CommandStatus::SlotBusy
                } else {
                    CommandStatus::Failure(error)
                }
            }
            2 => CommandStatus::TimeExtension,
            _ => CommandStatus::Failure(error),
        };
        Ok((Self { length }, status))
    }
}
#[allow(dead_code)]
const FDT_MIN_MICROS: u32 = 6780; // ISO14443-4 default FDT in microseconds

struct EscapeCommand<'a> {
    ins: u8,
    p1: u8,
    p2: u8,
    data: Cow<'a, [u8]>,
}

impl<'a> EscapeCommand<'a> {
    fn new(ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            ins,
            p1,
            p2,
            data: Cow::Borrowed(&[]),
        }
    }

    fn with_data(ins: u8, p1: u8, p2: u8, data: &'a [u8]) -> Self {
        Self {
            ins,
            p1,
            p2,
            data: Cow::Borrowed(data),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        let mut frame = vec![0xFF, self.ins, self.p1, self.p2];
        if !self.data.is_empty() {
            frame.push(self.data.len() as u8);
            frame.extend_from_slice(&self.data);
        }
        frame
    }
}

#[derive(Default)]
struct TransparentExchangeResult {
    payload: Vec<u8>,
    rf_status: Option<u8>,
    valid_bits: Option<u8>,
}

struct TransparentExchange<'a, 'b, T: Transport> {
    pcsc: &'a mut Pcsc<T>,
    tag: u8,
    payload: &'b [u8],
    flags: Option<TransmissionFlags>,
    timeout: Duration,
}

impl<'a, 'b, T: Transport> TransparentExchange<'a, 'b, T> {
    fn new(pcsc: &'a mut Pcsc<T>, tag: u8, payload: &'b [u8]) -> Self {
        Self {
            pcsc,
            tag,
            payload,
            flags: None,
            timeout: Duration::from_millis(0),
        }
    }

    fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn flags(mut self, flags: TransmissionFlags) -> Self {
        self.flags = Some(flags);
        self
    }

    fn execute(self) -> Result<TransparentExchangeResult> {
        self.pcsc
            .transparent_exchange(self.tag, self.payload, self.timeout, self.flags.as_ref())
    }

    fn execute_payload(self) -> Result<Vec<u8>> {
        self.execute().map(|result| result.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct DummyTransport {
        reads: VecDeque<io::Result<Vec<u8>>>,
        writes: Vec<Vec<u8>>,
    }

    impl DummyTransport {
        fn with_reads(reads: Vec<io::Result<Vec<u8>>>) -> Self {
            Self {
                reads: reads.into(),
                writes: Vec::new(),
            }
        }
    }

    impl Transport for DummyTransport {
        fn write(&mut self, data: &[u8]) -> io::Result<()> {
            self.writes.push(data.to_vec());
            Ok(())
        }

        fn read(&mut self, _timeout: Duration) -> io::Result<Vec<u8>> {
            match self.reads.pop_front() {
                Some(chunk) => chunk,
                None => Ok(Vec::new()),
            }
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn assert_driver_error_contains<T>(result: Result<T>, expected: &str) {
        match result {
            Err(DriverError::Other(message)) => assert!(
                message.contains(expected),
                "unexpected DriverError::Other message: {message}"
            ),
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(_) => panic!("expected DriverError::Other, got Ok"),
        }
    }

    /// Wraps `data` in the CCID header a reader would answer an escape with.
    fn ccid_escape_response(seq: u8, data: &[u8]) -> Vec<u8> {
        let mut response = vec![0x83];
        response.extend_from_slice(&(data.len() as u32).to_le_bytes());
        response.extend_from_slice(&[CCID_SLOT_NUMBER, seq, 0x00, 0x00, 0x00]);
        response.extend_from_slice(data);
        response
    }

    /// A transparent exchange answering with an empty payload and status 9000.
    fn empty_transparent_response(seq: u8) -> Vec<u8> {
        ccid_escape_response(seq, &[STATUS_TLV_TAG, 0x03, 0x00, 0x90, 0x00, 0x90, 0x00])
    }

    /// Returns the transmission bit framing value of a written escape frame.
    fn written_bit_framing(frame: &[u8]) -> Option<u8> {
        frame
            .windows(3)
            .find(|window| window[0] == TRANSMISSION_BIT_FRAMING_TAG && window[1] == 0x01)
            .map(|window| window[2])
    }

    #[test]
    fn transceive_resets_the_bit_framing_after_a_short_frame() {
        let transport = DummyTransport::with_reads(vec![
            Ok(empty_transparent_response(1)),
            Ok(empty_transparent_response(2)),
            Ok(empty_transparent_response(3)),
        ]);
        let mut pcsc = Pcsc::new(transport);
        let mut flags = TransmissionFlags::iso14443_type_a();

        flags.tx_valid_bits = Some(7);
        pcsc.transceive(&[0x26], Duration::from_millis(10), &flags)
            .expect("REQA should be sent");
        flags.tx_valid_bits = None;
        pcsc.transceive(&[0x93, 0x20], Duration::from_millis(10), &flags)
            .expect("anticollision should be sent");
        pcsc.transceive(&[0x93, 0x70], Duration::from_millis(10), &flags)
            .expect("select should be sent");

        let writes = &pcsc.ccid.transport.writes;
        assert_eq!(writes.len(), 3);
        assert_eq!(written_bit_framing(&writes[0]), Some(7));
        // The short frame has to be undone explicitly ...
        assert_eq!(written_bit_framing(&writes[1]), Some(0));
        // ... but only once, since the reader now uses full bytes again.
        assert_eq!(written_bit_framing(&writes[2]), None);
    }

    #[test]
    fn transceive_always_states_the_transmission_flags() {
        let transport = DummyTransport::with_reads(vec![Ok(empty_transparent_response(1))]);
        let mut pcsc = Pcsc::new(transport);
        let all_enabled = TransmissionFlags {
            append_crc: true,
            discard_crc: true,
            insert_parity: true,
            expect_parity: true,
            append_protocol_prologue: true,
            tx_valid_bits: None,
        };
        pcsc.transceive(&[0x00], Duration::from_millis(10), &all_enabled)
            .expect("command should be sent");

        // The reader keeps the previous flags, so an all zero mask is still sent.
        let frame = &pcsc.ccid.transport.writes[0];
        assert!(
            frame
                .windows(4)
                .any(|window| window == [TRANSMISSION_AND_RECEPTION_FLAG_TAG, 0x02, 0x00, 0x00]),
            "expected a zero flag mask in {frame:02X?}"
        );
    }

    #[test]
    fn transceive_rejects_an_out_of_range_valid_bit_count() {
        let mut pcsc = Pcsc::new(DummyTransport::default());
        let mut flags = TransmissionFlags::iso14443_type_a();
        flags.tx_valid_bits = Some(0);
        assert_driver_error_contains(
            pcsc.transceive(&[0x26], Duration::from_millis(10), &flags),
            "invalid TX number of valid bits",
        );
        flags.tx_valid_bits = Some(9);
        assert_driver_error_contains(
            pcsc.transceive(&[0x26], Duration::from_millis(10), &flags),
            "invalid TX number of valid bits",
        );
    }

    #[test]
    fn set_comm_speed_nests_the_vendor_parameter() {
        let transport = DummyTransport::with_reads(vec![Ok(ccid_escape_response(
            1,
            &[STATUS_TLV_TAG, 0x03, 0x00, 0x90, 0x00, 0x90, 0x00],
        ))]);
        let mut pcsc = Pcsc::new(transport);
        pcsc.set_comm_speed(0x09).expect("speed should be set");
        assert_eq!(
            pcsc.ccid.transport.writes[0][10..],
            [
                0xFF,
                MANAGE_SESSION_INS,
                0x00,
                0x00,
                0x06,
                VENDOR_SPECIFIC_TAG,
                0x6E,
                0x03,
                0x05,
                0x01,
                0x09,
                0x00
            ]
        );
    }

    #[test]
    fn rffe_parameter_categories_and_selectors_are_validated() {
        let mut pcsc = Pcsc::new(DummyTransport::default());
        assert_driver_error_contains(
            pcsc.read_rffe_parameter(RFFE_PARAM_EEPROM, 0x01, &[0x00]),
            "EEPROM parameters use selector 0",
        );
        assert_driver_error_contains(
            pcsc.read_rffe_parameter(RFFE_PARAM_PD_SC_DPC, 0x04, &[]),
            "unsupported PD/SC/DPC parameter selector",
        );
        assert_driver_error_contains(
            pcsc.read_rffe_parameter(0x04, 0x00, &[]),
            "unsupported RFFE parameter category",
        );
        // Production data can be read but not written.
        assert!(
            Pcsc::<DummyTransport>::ensure_pd_sc_dpc_selector(RFFE_PARAM_PRODUCTION_DATA, false)
                .is_ok()
        );
        assert_driver_error_contains(
            pcsc.write_rffe_parameter(RFFE_PARAM_PD_SC_DPC, RFFE_PARAM_PRODUCTION_DATA, &[0x00]),
            "unsupported PD/SC/DPC parameter selector",
        );
    }

    #[test]
    fn build_flag_mask_reflects_disabled_bits() {
        let all_true = TransmissionFlags {
            append_crc: true,
            discard_crc: true,
            insert_parity: true,
            expect_parity: true,
            append_protocol_prologue: true,
            tx_valid_bits: None,
        };
        assert_eq!(Pcsc::<DummyTransport>::build_flag_mask(&all_true), 0x0000);
        assert_eq!(
            Pcsc::<DummyTransport>::build_flag_mask(&TransmissionFlags::felica()),
            0x001C
        );
        let all_false = TransmissionFlags {
            append_crc: false,
            discard_crc: false,
            insert_parity: false,
            expect_parity: false,
            append_protocol_prologue: false,
            tx_valid_bits: Some(7),
        };
        assert_eq!(Pcsc::<DummyTransport>::build_flag_mask(&all_false), 0x001F);
    }

    #[test]
    fn push_extended_tlv_encodes_tag_and_length() {
        let mut tlv = Vec::new();
        Pcsc::<DummyTransport>::push_extended_tlv(&mut tlv, 0x95, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(tlv, vec![0x95, 0x82, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn verify_status_accepts_success_and_rejects_errors() {
        Pcsc::<DummyTransport>::verify_status(&[0x90, 0x00]).expect("9000 status should pass");
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::verify_status(&[0x6A, 0x82]),
            "CCID status 6A82",
        );
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::verify_status(&[0x90]),
            "short CCID status",
        );
    }

    #[test]
    fn parse_length_supports_short_and_long_forms() {
        assert_eq!(
            Pcsc::<DummyTransport>::parse_length(&[0x7F]).expect("short length"),
            (0x7F, 1)
        );
        assert_eq!(
            Pcsc::<DummyTransport>::parse_length(&[0x81, 0x80]).expect("0x81 length"),
            (0x80, 2)
        );
        assert_eq!(
            Pcsc::<DummyTransport>::parse_length(&[0x82, 0x01, 0x00]).expect("0x82 length"),
            (0x0100, 3)
        );
        assert_eq!(
            Pcsc::<DummyTransport>::parse_length(&[0x84, 0x00, 0x00, 0x01, 0x00])
                .expect("0x84 length"),
            (0x0100, 5)
        );
    }

    #[test]
    fn parse_length_reports_malformed_encodings() {
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_length(&[]),
            "missing length field",
        );
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_length(&[0x85, 0x00]),
            "unsupported TLV length encoding",
        );
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_length(&[0x82, 0x01]),
            "incomplete TLV length field",
        );
    }

    #[test]
    fn parse_manage_session_response_accepts_valid_tlvs() {
        Pcsc::<DummyTransport>::parse_manage_session_response(&[
            STATUS_TLV_TAG,
            0x03,
            0x00,
            0x90,
            0x00,
        ])
        .expect("status TLV should parse");
        Pcsc::<DummyTransport>::parse_manage_session_response(&[
            VENDOR_SPECIFIC_TAG,
            VENDOR_TAG_RESPONSE,
            0x03,
            0xAA,
            0xBB,
            0xCC,
            DEVICE_STATE_TLV_TAG,
            0x03,
            0x01,
            0x02,
            0x03,
            STATUS_TLV_TAG,
            0x03,
            0x00,
            0x90,
            0x00,
        ])
        .expect("vendor + device state + status TLV should parse");
    }

    #[test]
    fn parse_manage_session_response_reports_invalid_inputs() {
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_manage_session_response(&[
                STATUS_TLV_TAG,
                0x04,
                0x00,
                0x90,
                0x00,
            ]),
            "TLV length out of range",
        );
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_manage_session_response(&[
                STATUS_TLV_TAG,
                0x03,
                0x01,
                0x90,
                0x00,
            ]),
            "status 019000",
        );
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_manage_session_response(&[
                VENDOR_SPECIFIC_TAG,
                VENDOR_TAG_RESPONSE,
                0x02,
                0xAA,
                0xBB,
            ]),
            "malformed vendor TLV",
        );
    }

    #[test]
    fn parse_manage_session_response_stops_at_unknown_tags() {
        // Both an unknown top level tag and an unknown vendor sub tag end the
        // parse without failing the command, the way NFCPortLib does.
        Pcsc::<DummyTransport>::parse_manage_session_response(&[0x01, 0x00, 0x02, 0x00])
            .expect("unknown tag should stop the parse");
        Pcsc::<DummyTransport>::parse_manage_session_response(&[VENDOR_SPECIFIC_TAG, 0x10, 0x00])
            .expect("unknown vendor tag should stop the parse");
    }

    #[test]
    fn parse_switch_protocol_response_accepts_metadata_and_atr() {
        Pcsc::<DummyTransport>::parse_switch_protocol_response(&[
            STATUS_TLV_TAG,
            0x03,
            0x00,
            0x90,
            0x00,
            SWITCH_PROTOCOL_METADATA_TAG,
            0x03,
            0x01,
            0x02,
            0x03,
            EXTENDED_TAG_PREFIX,
            ATR_TLV_TAG,
            0x02,
            0x3B,
            0x8F,
        ])
        .expect("switch protocol response should parse");
        Pcsc::<DummyTransport>::parse_switch_protocol_response(&[
            SWITCH_PROTOCOL_METADATA_TAG,
            0x01,
            0x04,
        ])
        .expect("single byte protocol TLV should parse");
    }

    #[test]
    fn parse_switch_protocol_response_reports_invalid_inputs() {
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_switch_protocol_response(&[
                SWITCH_PROTOCOL_METADATA_TAG,
                0x02,
                0x01,
                0x02,
            ]),
            "malformed protocol TLV",
        );
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_switch_protocol_response(&[
                EXTENDED_TAG_PREFIX,
                0x46,
                0x01,
                0x00,
            ]),
            "ATR error",
        );
    }

    #[test]
    fn status_error_maps_reader_status_words() {
        match Pcsc::<DummyTransport>::status_error(&[0x00, 0x64, 0x01]) {
            DriverError::Communication(CommunicationError::Timeout(message)) => {
                assert!(message.contains("006401"), "unexpected message: {message}");
            }
            other => panic!("expected a timeout error, got {other}"),
        }
        match Pcsc::<DummyTransport>::status_error(&[0x00, 0x63, 0x01]) {
            DriverError::Communication(CommunicationError::Protocol(message)) => {
                assert!(message.contains("006301"), "unexpected message: {message}");
            }
            other => panic!("expected a protocol error, got {other}"),
        }
        match Pcsc::<DummyTransport>::status_error(&[0x00, 0x69, 0x8A]) {
            DriverError::Other(message) => {
                assert!(message.contains("access authority"), "got {message}");
            }
            other => panic!("expected an access authority error, got {other}"),
        }
    }

    #[test]
    fn parse_transparent_response_parses_payload_and_metadata() {
        let parsed = Pcsc::<DummyTransport>::parse_transparent_response(&[
            0xC0,
            0x03,
            0x00,
            0x90,
            0x00,
            RESPONSE_BIT_FRAMING_TAG,
            0x01,
            0x00,
            RESPONSE_STATUS_TAG,
            0x02,
            0x5A,
            0x00,
            RESPONSE_DATA_TAG,
            0x03,
            0xAA,
            0xBB,
            0xCC,
            VENDOR_SPECIFIC_TAG,
            VENDOR_TAG_RESPONSE,
            0x03,
            0x99,
            0x88,
            0x77,
        ])
        .expect("transparent response should parse");
        assert_eq!(parsed.payload, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(parsed.rf_status, Some(0x5A));
        assert_eq!(parsed.valid_bits, Some(8));
    }

    #[test]
    fn parse_transparent_response_supports_extended_data_length() {
        let parsed = Pcsc::<DummyTransport>::parse_transparent_response(&[
            RESPONSE_DATA_TAG,
            0x82,
            0x00,
            0x02,
            0x11,
            0x22,
            0xC0,
            0x03,
            0x00,
            0x90,
            0x00,
        ])
        .expect("extended length data TLV should parse");
        assert_eq!(parsed.payload, vec![0x11, 0x22]);
    }

    #[test]
    fn parse_transparent_response_reports_invalid_inputs() {
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_transparent_response(&[
                RESPONSE_BIT_FRAMING_TAG,
                0x02,
                0x01,
                0x02,
            ]),
            "Reception Bit Framing error",
        );
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_transparent_response(&[
                RESPONSE_STATUS_TAG,
                0x01,
                0x00,
                0x00,
            ]),
            "Response Status error",
        );
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_transparent_response(&[RESPONSE_DATA_TAG, 0x03, 0xAA]),
            "Response Data",
        );
        assert_driver_error_contains(
            Pcsc::<DummyTransport>::parse_transparent_response(&[RESPONSE_DATA_TAG, 0x85, 0x00]),
            "Response Data error",
        );
    }

    #[test]
    fn parse_transparent_response_stops_at_unknown_tags() {
        let parsed = Pcsc::<DummyTransport>::parse_transparent_response(&[0x01, 0x00, 0x02, 0x00])
            .expect("unknown tag should stop the parse");
        assert!(parsed.payload.is_empty());
        let parsed =
            Pcsc::<DummyTransport>::parse_transparent_response(&[VENDOR_SPECIFIC_TAG, 0x01, 0x00])
                .expect("unknown vendor tag should stop the parse");
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn ccid_response_parse_maps_status_variants() {
        let mut header = [0u8; 10];
        header[0] = 0x83;
        header[1..5].copy_from_slice(&4u32.to_le_bytes());
        header[6] = 0x10;

        let (ok, ok_status) =
            CcidResponse::parse(&header, 0x10).expect("success header should parse");
        assert_eq!(ok.length, 4);
        assert_eq!(ok_status, CommandStatus::Success);

        header[7] = 0x40;
        header[8] = SLOT_BUSY_ERROR;
        let (_, busy_status) =
            CcidResponse::parse(&header, 0x10).expect("slot busy header should parse");
        assert_eq!(busy_status, CommandStatus::SlotBusy);

        header[7] = 0x40;
        header[8] = 0x12;
        let (_, fail_status) =
            CcidResponse::parse(&header, 0x10).expect("failure header should parse");
        assert_eq!(fail_status, CommandStatus::Failure(0x12));

        header[7] = 0x80;
        let (_, te_status) =
            CcidResponse::parse(&header, 0x10).expect("time extension header should parse");
        assert_eq!(te_status, CommandStatus::TimeExtension);

        header[6] = 0x11;
        let (seq, seq_status) =
            CcidResponse::parse(&header, 0x10).expect("seq mismatch should parse");
        // The announced body length is kept so the stale response can be drained.
        assert_eq!(seq.length, 4);
        assert_eq!(seq_status, CommandStatus::SequenceMismatch);

        header[5] = 0x01;
        assert_driver_error_contains(
            CcidResponse::parse(&header, 0x10),
            "invalid CCID slot number",
        );
    }

    #[test]
    fn ccid_response_parse_rejects_invalid_headers() {
        assert_driver_error_contains(CcidResponse::parse(&[0u8; 9], 1), "short CCID header");

        let mut header = [0u8; 10];
        header[0] = 0x6B;
        assert_driver_error_contains(CcidResponse::parse(&header, 0), "invalid CCID message");
    }

    #[test]
    fn escape_command_serializes_with_and_without_data() {
        let no_data = EscapeCommand::new(GET_DATA_INS, 0xF2, 0x00).into_bytes();
        assert_eq!(no_data, vec![0xFF, GET_DATA_INS, 0xF2, 0x00]);

        let with_data = EscapeCommand::with_data(0x5A, 0x00, 0x00, &[0x12, 0x34]).into_bytes();
        assert_eq!(with_data, vec![0xFF, 0x5A, 0x00, 0x00, 0x02, 0x12, 0x34]);
    }

    #[test]
    fn ccid_transport_build_escape_frame_and_sequence_wrap() {
        let mut ccid = CcidTransport::new(DummyTransport::default());
        let frame = ccid.build_escape_frame(&[0xAA, 0xBB], 0x05);
        assert_eq!(
            frame,
            vec![
                0x6B, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0xAA, 0xBB
            ]
        );

        ccid.sequence = 0xFF;
        assert_eq!(ccid.next_sequence(), 0x00);
        assert_eq!(ccid.next_sequence(), 0x01);
    }

    #[test]
    fn ccid_transport_read_exact_uses_buffer_and_transport_reads() {
        let transport = DummyTransport::with_reads(vec![
            Ok(vec![0x01, 0x02, 0x03]),
            Ok(vec![0x04]),
            Ok(vec![0x05, 0x06]),
        ]);
        let mut ccid = CcidTransport::new(transport);

        let first = ccid
            .read_exact(2, Duration::from_millis(10))
            .expect("first read");
        assert_eq!(first, vec![0x01, 0x02]);

        let second = ccid
            .read_exact(3, Duration::from_millis(10))
            .expect("second read");
        assert_eq!(second, vec![0x03, 0x04, 0x05]);

        let third = ccid
            .read_exact(1, Duration::from_millis(10))
            .expect("third read");
        assert_eq!(third, vec![0x06]);
    }

    #[test]
    fn ccid_transport_read_exact_times_out_with_zero_deadline() {
        let mut ccid = CcidTransport::new(DummyTransport::default());
        let result = ccid.read_exact(1, Duration::from_millis(0));
        match result {
            Err(DriverError::Io(err)) => assert_eq!(err.kind(), ErrorKind::TimedOut),
            Err(other) => panic!("expected DriverError::Io timeout, got {other}"),
            Ok(data) => panic!("expected timeout error, got {data:?}"),
        }
    }
}
