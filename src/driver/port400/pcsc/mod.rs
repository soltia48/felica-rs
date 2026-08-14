//! PC/SC command layer for the Sony NFC Port-400.
//!
//! The Port-400 is driven as a PC/SC reader: sessions, protocol switches and
//! card exchanges are all APDUs sent through the CCID escape channel. [`Pcsc`]
//! turns each of those into a method, leaving the escape framing to [`ccid`] and
//! the response parsing to [`tlv`].

mod ccid;
mod tlv;

use crate::driver::errors::{DriverError, Result};
use crate::transport::Transport;
use ccid::{CcidTransport, EscapeCommand};
use log::debug;
use std::convert::{TryFrom, TryInto};
use std::thread::sleep;
use std::time::Duration;
use tlv::{
    EXTENDED_TAG_PREFIX, SWITCH_PROTOCOL_METADATA_TAG, TransparentExchangeResult,
    VENDOR_SPECIFIC_TAG,
};

const START_TRANSPARENT_SESSION_TAG: u8 = 0x81;
const END_TRANSPARENT_SESSION_TAG: u8 = 0x82;
const TURN_OFF_RF_TAG: u8 = 0x83;
const TURN_ON_RF_TAG: u8 = 0x84;
const TRANSMISSION_AND_RECEPTION_FLAG_TAG: u8 = 0x90;
const TRANSMISSION_BIT_FRAMING_TAG: u8 = 0x91;
const TRANSCEIVE_TAG: u8 = 0x95;
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
const DIAGNOSE_INS: u8 = 0x57;
const PREPARE_FIRMWARE_UPDATE_INS: u8 = 0x53;
const UPDATE_FIRMWARE_INS: u8 = 0x54;
const RESET_DEVICE_INS: u8 = 0x55;
const DIAG_TEST_COMMUNICATION_LINE: u8 = 0x00;
const DIAG_TEST_ROM: u8 = 0x01;
const DIAG_TEST_RAM: u8 = 0x02;
const DIAG_TEST_POLLING: u8 = 0x03;
const LOAD_KEYS_INS: u8 = 0x82;
const GENERAL_AUTHENTICATE_INS: u8 = 0x86;
const READ_RFFE_PARAMETER_INS: u8 = 0x61;
const WRITE_RFFE_PARAMETER_INS: u8 = 0x62;
const RFFE_PARAM_EEPROM: u8 = 0x01;
const RFFE_PARAM_PD_SC_DPC: u8 = 0x02;
const RFFE_PARAM_PROTOCOL_CONFIGURATION: u8 = 0x03;
const RFFE_PARAM_PRODUCTION_DATA: u8 = 0x01;
const RFFE_PARAM_SYSTEM_CONFIGURATION: u8 = 0x02;
const RFFE_PARAM_DPC: u8 = 0x03;

const DEFAULT_RECEIVE_TIMEOUT: Duration = Duration::from_millis(1_500);
/// Timeout of the keep-alive exchange, which only has to reach the reader.
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_millis(100);
const RF_ON_GUARD_TIME: Duration = Duration::from_millis(21);
const RF_OFF_GUARD_TIME: Duration = Duration::from_millis(30);
const SWITCH_PROTOCOL_GUARD_TIME: Duration = Duration::from_millis(20);
/// Length of the CCID response header that precedes the payload.
const SLOT_BUSY_RETRY_COUNT: usize = 1;
const SLOT_BUSY_END_SESSION_RETRIES: usize = 4;
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
    /// Reader key slot used for MIFARE Classic authentication.
    mifare_auth_key_number: u8,
}

impl<T: Transport> Pcsc<T> {
    pub fn new(transport: T) -> Self {
        Self {
            ccid: CcidTransport::new(transport),
            receive_timeout: DEFAULT_RECEIVE_TIMEOUT,
            modified_bit_framing: false,
            mifare_auth_key_number: 0,
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
        tlv::verify_status(&response)?;
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

    /// Loads a MIFARE Classic key into the reader's key slot.
    pub fn load_keys(&mut self, key: &[u8]) -> Result<()> {
        let mut frame = vec![0xFF, LOAD_KEYS_INS, 0x00, self.mifare_auth_key_number];
        frame.push(key.len() as u8);
        frame.extend_from_slice(key);
        let response = self
            .ccid
            .escape(&frame, self.receive_timeout, SLOT_BUSY_RETRY_COUNT)?;
        tlv::verify_status(&response)
            .map_err(|err| DriverError::Other(format!("loadKeys failed: {err}")))
    }

    /// Authenticates a MIFARE Classic block with the key loaded by
    /// [`Self::load_keys`], where `key_type` is `60h` for key A or `61h` for key B.
    pub fn general_authenticate(&mut self, block_number: u8, key_type: u8) -> Result<()> {
        let frame = [
            0xFF,
            GENERAL_AUTHENTICATE_INS,
            0x00,
            0x00,
            0x05,
            0x00,
            // The block number is sent as a big endian 16 bit address.
            0x00,
            block_number,
            key_type,
            self.mifare_auth_key_number,
        ];
        let response = self
            .ccid
            .escape(&frame, self.receive_timeout, SLOT_BUSY_RETRY_COUNT)?;
        tlv::verify_status(&response)
            .map_err(|err| DriverError::Other(format!("generateAutheticate failed: {err}")))
    }

    /// Sends the command the reference library repeats while a transparent
    /// session is open so the reader does not drop it for inactivity.
    ///
    /// The response is not inspected: reaching the reader is the whole point.
    pub fn keep_alive(&mut self) -> Result<()> {
        let frame = [0xFF, GET_FIRMWARE_VERSION_INS, 0x00, 0x00, 0x00];
        self.ccid
            .escape(&frame, KEEP_ALIVE_TIMEOUT, SLOT_BUSY_RETRY_COUNT)?;
        Ok(())
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
        tlv::parse_switch_protocol_response(&response)?;
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
        tlv::verify_status(&response)?;
        Ok(response[..response.len() - 2].to_vec())
    }

    fn send_extended_escape(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let response = self
            .ccid
            .escape(frame, self.receive_timeout, SLOT_BUSY_RETRY_COUNT)?;
        tlv::verify_status(&response)?;
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
        tlv::parse_manage_session_response(&response)?;
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
        tlv::verify_status(&response)?;
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
            tlv::push_extended_tlv(&mut fields, tag, payload);
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
        tlv::verify_status(&response)?;
        tlv::parse_transparent_response(&response[..response.len() - 2])
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
    use crate::driver::testing::{DummyTransport, assert_driver_error_contains};
    use tlv::STATUS_TLV_TAG;

    /// Wraps `data` in the CCID header a reader would answer an escape with.
    fn ccid_escape_response(seq: u8, data: &[u8]) -> Vec<u8> {
        let mut response = vec![0x83];
        response.extend_from_slice(&(data.len() as u32).to_le_bytes());
        response.extend_from_slice(&[ccid::CCID_SLOT_NUMBER, seq, 0x00, 0x00, 0x00]);
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

        let writes = pcsc.ccid.transport.writes();
        assert_eq!(writes.len(), 3);
        assert_eq!(written_bit_framing(&writes.frame(0)), Some(7));
        // The short frame has to be undone explicitly ...
        assert_eq!(written_bit_framing(&writes.frame(1)), Some(0));
        // ... but only once, since the reader now uses full bytes again.
        assert_eq!(written_bit_framing(&writes.frame(2)), None);
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
        let frame = pcsc.ccid.transport.writes().frame(0);
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
            pcsc.ccid.transport.writes().frame(0)[10..],
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
}
