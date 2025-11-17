use crate::driver::errors::{DriverError, Result};
use crate::transport::Transport;
use log::debug;
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
const GET_DATA_INS: u8 = 0xCA;
const GET_FIRMWARE_VERSION_INS: u8 = 0x56;
const GET_CARD_BAUDRATE_SELECTOR: u8 = 0xF2;
const MANAGE_SESSION_INS: u8 = 0x50;
const TRANSPARENT_SESSION_CHANNEL: u8 = 0x01;
const SLOT_BUSY_ERROR: u8 = 0xE0;
const VENDOR_SPECIFIC_TAG: u8 = 0xFF;
const VENDOR_TAG_RESPONSE: u8 = 0x6D;

const DEFAULT_RECEIVE_TIMEOUT: Duration = Duration::from_millis(1_500);
const SLOT_BUSY_WAIT_TIME: Duration = Duration::from_millis(50);
const TIME_EXTENSION_WAIT: Duration = Duration::from_millis(20);
const RF_ON_GUARD_TIME: Duration = Duration::from_millis(21);
const RF_OFF_GUARD_TIME: Duration = Duration::from_millis(30);
const SWITCH_PROTOCOL_GUARD_TIME: Duration = Duration::from_millis(20);
const SLOT_BUSY_RETRY_COUNT: usize = 1;
const SLOT_BUSY_END_SESSION_RETRIES: usize = 4;
const SEQUENCE_ERROR_RETRY_COUNT: usize = 2;

pub struct TransmissionFlags {
    pub append_crc: bool,
    pub discard_crc: bool,
    pub insert_parity: bool,
    pub expect_parity: bool,
    pub append_protocol_prologue: bool,
    pub tx_valid_bits: Option<u8>,
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
}

pub struct Pcsc<T: Transport> {
    ccid: CcidTransport<T>,
    receive_timeout: Duration,
}

impl<T: Transport> Pcsc<T> {
    pub fn new(transport: T) -> Self {
        Self {
            ccid: CcidTransport::new(transport),
            receive_timeout: DEFAULT_RECEIVE_TIMEOUT,
        }
    }

    pub fn set_receive_timeout(&mut self, timeout: Duration) {
        self.receive_timeout = timeout;
    }

    pub fn start_transparent_session(&mut self, priority: bool) -> Result<()> {
        debug!("start transparent session (priority={priority})");
        if priority {
            let _ = self.manage_session(
                &[(END_TRANSPARENT_SESSION_TAG, &[][..])],
                SLOT_BUSY_END_SESSION_RETRIES,
            );
        }
        self.manage_session(
            &[(START_TRANSPARENT_SESSION_TAG, &[][..])],
            SLOT_BUSY_END_SESSION_RETRIES,
        )?;
        self.turn_off_rf()?;
        sleep(RF_OFF_GUARD_TIME);
        self.turn_on_rf()?;
        sleep(RF_ON_GUARD_TIME);
        Ok(())
    }

    pub fn end_transparent_session(&mut self) -> Result<()> {
        debug!("end transparent session");
        self.manage_session(
            &[(END_TRANSPARENT_SESSION_TAG, &[][..])],
            SLOT_BUSY_END_SESSION_RETRIES,
        )?;
        Ok(())
    }

    pub fn switch_protocol_type_f(&mut self, auto_baud: bool) -> Result<()> {
        let param = if auto_baud { 1 } else { 0 };
        self.switch_protocol(3, param)
    }

    pub fn transceive(
        &mut self,
        payload: &[u8],
        timeout: Duration,
        flags: &TransmissionFlags,
    ) -> Result<Vec<u8>> {
        self.transparent_exchange(TRANSCEIVE_TAG, payload, timeout, flags)
    }

    pub fn get_data(&mut self, selector: u8) -> Result<Vec<u8>> {
        let frame = [0xFF, GET_DATA_INS, selector, 0x00];
        let response = self
            .ccid
            .escape(&frame, self.receive_timeout, SLOT_BUSY_RETRY_COUNT)?;
        Self::verify_status(&response)?;
        Ok(response[..response.len() - 2].to_vec())
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
        let rate = data.get(0).and_then(|code| match code {
            1 => Some(106),
            2 => Some(212),
            3 => Some(424),
            4 => Some(848),
            _ => None,
        });
        Ok(rate)
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

    fn switch_protocol(&mut self, mode: u8, parameter: u8) -> Result<()> {
        let mut payload = Vec::new();
        payload.push(SWITCH_PROTOCOL_METADATA_TAG);
        payload.push(2);
        payload.push(mode);
        payload.push(parameter);
        let mut frame = vec![0xFF, MANAGE_SESSION_INS, 0x00, 0x02, payload.len() as u8];
        frame.extend_from_slice(&payload);
        frame.push(0x00);
        let response = self
            .ccid
            .escape(&frame, self.receive_timeout, SLOT_BUSY_RETRY_COUNT)?;
        Self::verify_status(&response)?;
        let tlv = &response[..response.len() - 2];
        Self::parse_status_block(tlv)?;
        sleep(SWITCH_PROTOCOL_GUARD_TIME);
        Ok(())
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
        let mut frame = vec![0xFF, MANAGE_SESSION_INS, 0x00, 0x00, payload.len() as u8];
        frame.extend_from_slice(&payload);
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
        flags: &TransmissionFlags,
    ) -> Result<Vec<u8>> {
        let mut fields = Vec::new();
        let mask = Self::build_flag_mask(flags);
        if mask != 0 {
            fields.push(TRANSMISSION_AND_RECEPTION_FLAG_TAG);
            fields.push(2);
            fields.push((mask >> 8) as u8);
            fields.push((mask & 0xFF) as u8);
        }
        if let Some(bits) = flags.tx_valid_bits {
            let value = bits.min(7);
            fields.push(TRANSMISSION_BIT_FRAMING_TAG);
            fields.push(1);
            fields.push(value);
        }
        if timeout > Duration::from_millis(0) {
            let micros = (timeout.as_millis() as u128 * 1_000).min(u32::MAX as u128) as u32;
            fields.push(0x5F);
            fields.push(0x46);
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

    fn parse_status_block(data: &[u8]) -> Result<()> {
        let mut idx = 0;
        while idx + 1 < data.len() {
            let tag = data[idx];
            idx += 1;
            match tag {
                0xC0 => {
                    if idx >= data.len() {
                        return Err(DriverError::Other("status TLV truncated".into()));
                    }
                    let len = data[idx] as usize;
                    idx += 1;
                    if idx + len > data.len() {
                        return Err(DriverError::Other("status TLV length out of range".into()));
                    }
                    let value = &data[idx..idx + len];
                    idx += len;
                    if value != [0x00, 0x90, 0x00] {
                        return Err(Self::status_error(value));
                    }
                }
                VENDOR_SPECIFIC_TAG => {
                    if idx >= data.len() {
                        return Err(DriverError::Other("vendor TLV truncated".into()));
                    }
                    let subtag = data[idx];
                    idx += 1;
                    if subtag == VENDOR_TAG_RESPONSE {
                        if idx >= data.len() {
                            return Err(DriverError::Other("vendor TLV length missing".into()));
                        }
                        let len = data[idx] as usize;
                        idx += 1;
                        if idx + len > data.len() {
                            return Err(DriverError::Other(
                                "vendor TLV length out of range".into(),
                            ));
                        }
                        idx += len;
                    } else {
                        return Err(DriverError::Other(format!(
                            "unexpected vendor tag {:02X}",
                            subtag
                        )));
                    }
                }
                _ => {
                    return Err(DriverError::Other(format!(
                        "unexpected TLV tag {:02X}",
                        tag
                    )));
                }
            }
        }
        Ok(())
    }

    fn parse_transparent_response(data: &[u8]) -> Result<Vec<u8>> {
        let mut idx = 0;
        let mut response = Vec::new();
        while idx + 1 <= data.len() {
            let tag = data[idx];
            idx += 1;
            match tag {
                0xC0 => {
                    if idx >= data.len() {
                        return Err(DriverError::Other("status TLV truncated".into()));
                    }
                    let len = data[idx] as usize;
                    idx += 1;
                    if idx + len > data.len() {
                        return Err(DriverError::Other("status TLV length out of range".into()));
                    }
                    let value = &data[idx..idx + len];
                    idx += len;
                    if value != [0x00, 0x90, 0x00] {
                        return Err(Self::status_error(value));
                    }
                }
                RESPONSE_BIT_FRAMING_TAG | RESPONSE_STATUS_TAG => {
                    if idx >= data.len() {
                        return Err(DriverError::Other("response TLV truncated".into()));
                    }
                    let len = data[idx] as usize;
                    idx += 1 + len;
                    if idx > data.len() {
                        return Err(DriverError::Other(
                            "response TLV length out of range".into(),
                        ));
                    }
                }
                RESPONSE_DATA_TAG => {
                    if idx >= data.len() {
                        return Err(DriverError::Other("data TLV truncated".into()));
                    }
                    let (len, consumed) = Self::parse_length(&data[idx..])?;
                    idx += consumed;
                    if idx + len > data.len() {
                        return Err(DriverError::Other("data TLV length out of range".into()));
                    }
                    response.extend_from_slice(&data[idx..idx + len]);
                    idx += len;
                }
                VENDOR_SPECIFIC_TAG => {
                    if idx + 1 >= data.len() {
                        return Err(DriverError::Other("vendor TLV truncated".into()));
                    }
                    let subtag = data[idx];
                    idx += 1;
                    let len = data[idx] as usize;
                    idx += 1;
                    idx += len;
                    if idx > data.len() {
                        return Err(DriverError::Other("vendor TLV length out of range".into()));
                    }
                    if subtag != VENDOR_TAG_RESPONSE {
                        return Err(DriverError::Other(format!(
                            "unexpected vendor tag {:02X}",
                            subtag
                        )));
                    }
                }
                _ => {
                    return Err(DriverError::Other(format!(
                        "unexpected TLV tag {:02X}",
                        tag
                    )));
                }
            }
        }
        Ok(response)
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

    fn status_error(value: &[u8]) -> DriverError {
        let text = format!(
            "status {:02X}{:02X}{:02X}",
            value.get(0).copied().unwrap_or_default(),
            value.get(1).copied().unwrap_or_default(),
            value.get(2).copied().unwrap_or_default()
        );
        DriverError::Other(text)
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
                    if seq_retry == 0 {
                        return Err(DriverError::Other("CCID sequence mismatch".into()));
                    }
                    seq_retry -= 1;
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
        frame.push(0);
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
        let seq = data[6];
        if seq != expected_seq {
            return Ok((Self { length: 0 }, CommandStatus::SequenceMismatch));
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
