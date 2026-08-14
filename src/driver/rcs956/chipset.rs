//! RC-S956 chipset command implementation.
//!
//! This module provides low-level communication with the RC-S956 chipset.

use crate::driver::errors::{ChipsetError, DriverError, Result};
use crate::driver::io::{self, recover_after_error, remaining_until, timeout_error};
use crate::driver::rcs956::frame::{self, CONTROLLER_TO_HOST, Frame};
use crate::transport::Transport;
use log::{debug, warn};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Maximum host command frame size for RC-S956.
pub const HOST_COMMAND_FRAME_MAX_SIZE: usize = 265;

/// Maximum number of targets for InListPassiveTarget.
#[allow(dead_code)]
pub const IN_LIST_PASSIVE_TARGET_MAX_TARGET: u8 = 1;

/// Supported bitrate types for InListPassiveTarget.
pub const IN_LIST_PASSIVE_TARGET_BRTY_RANGE: [u8; 5] = [0, 1, 2, 3, 4];

/// RC-S956 command codes.
#[allow(dead_code)]
pub mod cmd {
    pub const DIAGNOSE: u8 = 0x00;
    pub const GET_FIRMWARE_VERSION: u8 = 0x02;
    pub const GET_GENERAL_STATUS: u8 = 0x04;
    pub const READ_REGISTER: u8 = 0x06;
    pub const WRITE_REGISTER: u8 = 0x08;
    pub const READ_GPIO: u8 = 0x0C;
    pub const SET_SERIAL_BAUDRATE: u8 = 0x10;
    pub const SET_PARAMETERS: u8 = 0x12;
    pub const POWER_DOWN: u8 = 0x16;
    pub const RESET_MODE: u8 = 0x18;
    pub const CONTROL_LED: u8 = 0x1C;
    pub const RF_CONFIGURATION: u8 = 0x32;
    pub const IN_DATA_EXCHANGE: u8 = 0x40;
    pub const IN_COMMUNICATE_THRU: u8 = 0x42;
    pub const IN_DESELECT: u8 = 0x44;
    pub const IN_JUMP_FOR_PSL: u8 = 0x46;
    pub const IN_LIST_PASSIVE_TARGET: u8 = 0x4A;
    pub const IN_PSL: u8 = 0x4E;
    pub const IN_ATR: u8 = 0x50;
    pub const IN_RELEASE: u8 = 0x52;
    pub const IN_SELECT: u8 = 0x54;
    pub const IN_JUMP_FOR_DEP: u8 = 0x56;
    pub const RF_REGULATION_TEST: u8 = 0x58;
    pub const TG_GET_DEP_DATA: u8 = 0x86;
    pub const TG_GET_INITIATOR_COMMAND: u8 = 0x88;
    pub const TG_GET_TARGET_STATUS: u8 = 0x8A;
    pub const TG_INIT_TARGET: u8 = 0x8C;
    pub const TG_SET_DEP_DATA: u8 = 0x8E;
    pub const TG_RESPONSE_TO_INITIATOR: u8 = 0x90;
    pub const TG_SET_GENERAL_BYTES: u8 = 0x92;
    pub const TG_SET_META_DEP_DATA: u8 = 0x94;
    pub const COMMUNICATE_THRU_EX: u8 = 0xA0;
}

/// RC-S956 error codes.
#[allow(dead_code)]
pub mod err {
    pub const TIMEOUT: u8 = 0x01;
    pub const CRC_ERROR: u8 = 0x02;
    pub const PARITY_ERROR: u8 = 0x03;
    pub const COLLISION_BIT_ERROR: u8 = 0x04;
    pub const OVERFLOW_ERROR: u8 = 0x07;
    pub const RF_NOT_ACTIVATED: u8 = 0x0A;
    pub const PROTOCOL_ERROR: u8 = 0x0B;
    pub const ISO_DEP_OVERFLOW: u8 = 0x0C;
    pub const OVERHEATED: u8 = 0x0D;
    pub const SDD_RESPONSE_TOO_LONG: u8 = 0x10;
    pub const FORMAT_ERROR: u8 = 0x13;
    pub const AUTH_FAILED: u8 = 0x14;
    pub const UNMATCHED_BLOCK_NUMBER: u8 = 0x17;
    pub const INVALID_BCC: u8 = 0x23;
    pub const WRONG_TIME: u8 = 0x25;
    pub const POWER_DOWN_USB: u8 = 0x26;
    pub const ABNORMAL_TG_PARAM: u8 = 0x27;
    pub const RELEASE_FROM_INITIATOR: u8 = 0x29;
    pub const PUPI_MISMATCH: u8 = 0x2A;
    pub const SELECT_DESELECTED_FAIL: u8 = 0x2B;
    pub const ALREADY_DESELECTED: u8 = 0x2F;
    pub const RF_OFF_DETECTED: u8 = 0x31;
    pub const BUFFER_OVERFLOW: u8 = 0x32;
    pub const DEP_NACK_ERROR: u8 = 0x34;
    pub const DATA_EXCEEDS_LEN: u8 = 0x35;
    pub const ERROR_FRAME: u8 = 0x7F;
    pub const REGISTER_WRITE_FAILED: u8 = 0xFE;
    pub const NO_DATA: u8 = 0xFF;
}

/// CIU register addresses.
#[allow(dead_code)]
pub mod ciu {
    pub const MODE: u16 = 0x6301;
    pub const TX_MODE: u16 = 0x6302;
    pub const RX_MODE: u16 = 0x6303;
    pub const TX_CONTROL: u16 = 0x6304;
    pub const TX_AUTO: u16 = 0x6305;
    pub const TX_SEL: u16 = 0x6306;
    pub const RX_SEL: u16 = 0x6307;
    pub const RX_THRESHOLD: u16 = 0x6308;
    pub const DEMOD: u16 = 0x6309;
    pub const FEL_NFC1: u16 = 0x630A;
    pub const FEL_NFC2: u16 = 0x630B;
    pub const MIF_NFC: u16 = 0x630C;
    pub const MANUAL_RCV: u16 = 0x630D;
    pub const TYPE_B: u16 = 0x630E;
    pub const SERIAL_SPEED: u16 = 0x630F;
    pub const CRC_RESULT_MSB: u16 = 0x6311;
    pub const CRC_RESULT_LSB: u16 = 0x6312;
    pub const GS_N_OFF: u16 = 0x6313;
    pub const MOD_WIDTH: u16 = 0x6314;
    pub const TX_BIT_PHASE: u16 = 0x6315;
    pub const RF_CFG: u16 = 0x6316;
    pub const GS_N_ON: u16 = 0x6317;
    pub const CW_GS_P: u16 = 0x6318;
    pub const MOD_GS_P: u16 = 0x6319;
    pub const T_MODE: u16 = 0x631A;
    pub const T_PRESCALER: u16 = 0x631B;
    pub const T_RELOAD_HI: u16 = 0x631C;
    pub const T_RELOAD_LO: u16 = 0x631D;
    pub const T_COUNTER_HI: u16 = 0x631E;
    pub const T_COUNTER_LO: u16 = 0x631F;
    pub const TEST_SEL1: u16 = 0x6321;
    pub const TEST_SEL2: u16 = 0x6322;
    pub const TEST_PIN_EN: u16 = 0x6323;
    pub const TEST_PIN_VALUE: u16 = 0x6324;
    pub const TEST_BUS: u16 = 0x6325;
    pub const AUTO_TEST: u16 = 0x6326;
    pub const VERSION: u16 = 0x6327;
    pub const ANALOG_TEST: u16 = 0x6328;
    pub const TEST_DAC1: u16 = 0x6329;
    pub const TEST_DAC2: u16 = 0x632A;
    pub const TEST_ADC: u16 = 0x632B;
    pub const COMMAND: u16 = 0x6331;
    pub const COMM_I_EN: u16 = 0x6332;
    pub const DIV_I_EN: u16 = 0x6333;
    pub const COMM_IRQ: u16 = 0x6334;
    pub const DIV_IRQ: u16 = 0x6335;
    pub const ERROR: u16 = 0x6336;
    pub const STATUS1: u16 = 0x6337;
    pub const STATUS2: u16 = 0x6338;
    pub const FIFO_DATA: u16 = 0x6339;
    pub const FIFO_LEVEL: u16 = 0x633A;
    pub const WATER_LEVEL: u16 = 0x633B;
    pub const CONTROL: u16 = 0x633C;
    pub const BIT_FRAMING: u16 = 0x633D;
    pub const COLL: u16 = 0x633E;
}

/// RC-S956 chipset communication handler.
pub struct Chipset<T: Transport> {
    pub(crate) transport: T,
    firmware_version: (u8, u8, u8),
    read_buffer: VecDeque<u8>,
}

impl<T: Transport> Chipset<T> {
    /// ACK frame bytes.
    pub const ACK: [u8; 6] = frame::ACK_BYTES;
    #[allow(dead_code)]
    const ACK_TIMEOUT: Duration = Duration::from_millis(100);
    #[allow(dead_code)]
    const RESPONSE_TIMEOUT: Duration = Duration::from_millis(1_000);

    /// Creates a new chipset handler with the given transport.
    pub fn new(mut transport: T) -> Result<Self> {
        // Send ACK to check if we can communicate with the device
        transport.write(&Self::ACK)?;

        // Clear any garbage from the buffer
        while let Ok(data) = transport.read(Duration::from_millis(10)) {
            debug!("cleared garbage {:x?}", data);
        }

        Ok(Self {
            transport,
            firmware_version: (0, 0, 0),
            read_buffer: VecDeque::new(),
        })
    }

    /// Initializes the chipset after creation.
    /// This should be called from Device::new() after reset_mode().
    pub fn initialize(&mut self) -> Result<()> {
        // Get firmware version
        let version = self.get_firmware_version()?;
        self.firmware_version = version;
        debug!(
            "firmware version: IC={:02x} Ver={:x}.{:x}",
            version.0, version.1, version.2
        );
        Ok(())
    }

    /// Returns the firmware version (IC, version, revision).
    pub fn firmware_version(&self) -> (u8, u8, u8) {
        self.firmware_version
    }

    /// Returns the manufacturer name from the transport.
    pub fn manufacturer_name(&self) -> Option<&str> {
        self.transport.manufacturer_name()
    }

    /// Returns the product name from the transport.
    pub fn product_name(&self) -> Option<&str> {
        self.transport.product_name()
    }

    /// Closes the chipset connection.
    pub fn close(&mut self) -> Result<()> {
        self.reset_mode()?;
        self.transport.write(&Self::ACK)?;
        self.transport.close()?;
        Ok(())
    }

    // ========================================================================
    // Core command methods
    // ========================================================================

    /// Sends a command and receives the response.
    fn command(&mut self, cmd_code: u8, data: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let frame = frame::build_command(cmd_code, data);
        debug!("CMD {:02X} data={:?}", cmd_code, hex::encode(data));
        self.write_frame(&frame)?;
        self.read_command_response(cmd_code, timeout)
    }

    /// Writes a frame to the transport.
    fn write_frame(&mut self, frame: &Frame) -> Result<()> {
        debug!("TX: {:?}", hex::encode(frame.as_bytes()));
        self.with_recovery(false, |chipset| {
            chipset
                .transport
                .write(frame.as_bytes())
                .map_err(DriverError::from)
        })
    }

    /// Reads the ACK and response for a command.
    ///
    /// This follows nfcpy's logic:
    /// 1. Read a complete frame with 100ms timeout
    /// 2. If it's not ACK, log warning but use it as the response
    /// 3. If it is ACK, keep reading until we get a non-ACK frame
    fn read_command_response(&mut self, cmd_code: u8, timeout: Duration) -> Result<Vec<u8>> {
        // First read with 100ms timeout for ACK
        let mut frame_bytes = self.read_frame_from_transport(Duration::from_millis(100))?;
        debug!("RX: {:?}", hex::encode(&frame_bytes));

        // Check if it starts with SOF
        if frame_bytes.get(0..3) != Some(&frame::SOF) {
            recover_after_error(&mut self.transport, &mut self.read_buffer, &Self::ACK, true);
            return Err(DriverError::Other("invalid frame start sequence".into()));
        }

        // Check if it's ACK (nfcpy compares the whole 6-byte ACK frame)
        if frame_bytes.get(0..6) != Some(&Self::ACK) {
            // Not ACK - nfcpy logs a warning but continues with this frame
            warn!("missing ack frame");
        } else {
            // It's ACK - keep reading until we get a non-ACK frame
            let deadline = Instant::now() + timeout;
            loop {
                let remaining = remaining_until(deadline).ok_or_else(|| {
                    // Timeout - send ACK to cancel command
                    let _ = self.transport.write(&Self::ACK);
                    DriverError::Io(timeout_error())
                })?;

                frame_bytes = self.read_frame_from_transport(remaining)?;
                debug!("RX: {:?}", hex::encode(&frame_bytes));

                if frame_bytes.get(0..6) != Some(&Self::ACK) {
                    break;
                }
            }
        }

        // Parse and validate the response frame
        let frame = self.parse_response_frame(&frame_bytes)?;
        Self::extract_response_payload(frame, cmd_code)
    }

    /// Reads a complete frame from the transport (as a USB packet).
    fn read_frame_from_transport(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        // First, try to use any buffered data
        if !self.read_buffer.is_empty() {
            let bytes: Vec<u8> = self.read_buffer.drain(..).collect();
            return Ok(bytes);
        }

        // Read from transport - USB reads return complete packets
        let bytes = self.transport.read(timeout)?;
        if bytes.is_empty() {
            return Err(DriverError::Io(timeout_error()));
        }
        Ok(bytes)
    }

    /// Parses a response frame and checks that it fills the USB packet exactly.
    ///
    /// The envelope itself — the length checksum, the data checksum and the
    /// postamble — is validated by [`Frame::parse`]. What it cannot tell is that
    /// the frame accounts for every byte the reader sent: a USB read hands over
    /// a whole packet, so bytes left over past the postamble mean the reader and
    /// this driver disagree about the response rather than that a second frame
    /// arrived.
    fn parse_response_frame(&self, frame_bytes: &[u8]) -> Result<Frame> {
        let frame = Frame::parse(frame_bytes)
            .ok_or_else(|| DriverError::Other("invalid response frame".into()))?;
        let frame_len = frame.as_bytes().len();
        if frame_len != frame_bytes.len() {
            return Err(DriverError::Other(format!(
                "frame length value mismatch: the frame is {frame_len} bytes but the packet is {}",
                frame_bytes.len()
            )));
        }
        Ok(frame)
    }

    /// Extracts the response payload from a frame.
    fn extract_response_payload(frame: Frame, cmd_code: u8) -> Result<Vec<u8>> {
        let payload = frame
            .into_payload()
            .ok_or_else(|| DriverError::Other("unexpected frame type".into()))?;

        // Check for error frame
        if payload.first() == Some(&0x7F) {
            return Err(ChipsetError::Status(err::ERROR_FRAME).into());
        }

        // Verify response identifier and command code
        if payload.first() != Some(&CONTROLLER_TO_HOST) {
            return Err(DriverError::Other("invalid response identifier".into()));
        }
        if payload.get(1) != Some(&cmd_code.wrapping_add(1)) {
            return Err(DriverError::Other("unexpected response code".into()));
        }

        Ok(payload[2..].to_vec())
    }

    /// Executes an action with error recovery.
    fn with_recovery<R>(
        &mut self,
        drain_buffer: bool,
        action: impl FnOnce(&mut Self) -> Result<R>,
    ) -> Result<R> {
        let result = action(self);
        io::recover_on_error(
            result,
            &mut self.transport,
            &mut self.read_buffer,
            &Self::ACK,
            drain_buffer,
        )
    }

    // ========================================================================
    // RC-S956 specific commands
    // ========================================================================

    /// Resets the chipset state machine to Mode 0.
    pub fn reset_mode(&mut self) -> Result<()> {
        let _ = self.command(cmd::RESET_MODE, &[0x01], Duration::from_millis(100));
        self.transport.write(&Self::ACK)?;
        std::thread::sleep(Duration::from_millis(10));
        Ok(())
    }

    /// Gets the firmware version.
    pub fn get_firmware_version(&mut self) -> Result<(u8, u8, u8)> {
        let data = self.command(cmd::GET_FIRMWARE_VERSION, &[], Duration::from_millis(100))?;
        if data.len() >= 4 {
            Ok((data[0], data[1], data[2]))
        } else {
            Err(DriverError::Other(
                "firmware version response too short".into(),
            ))
        }
    }

    /// Sets the chipset parameters.
    pub fn set_parameters(&mut self, flags: u8) -> Result<()> {
        self.command(cmd::SET_PARAMETERS, &[flags], Duration::from_millis(100))?;
        Ok(())
    }

    /// Configures RF settings.
    pub fn rf_configuration(&mut self, cfg_item: u8, cfg_data: &[u8]) -> Result<()> {
        let mut data = Vec::with_capacity(cfg_data.len() + 1);
        data.push(cfg_item);
        data.extend_from_slice(cfg_data);
        self.command(cmd::RF_CONFIGURATION, &data, Duration::from_millis(100))?;
        Ok(())
    }

    /// Reads CIU registers.
    pub fn read_register(&mut self, addresses: &[u16]) -> Result<Vec<u8>> {
        assert!(addresses.len() <= 64, "max 64 registers can be read");
        let mut data = Vec::with_capacity(addresses.len() * 2);
        for addr in addresses {
            data.extend_from_slice(&addr.to_be_bytes());
        }
        self.command(cmd::READ_REGISTER, &data, Duration::from_millis(250))
    }

    /// Writes to CIU registers.
    pub fn write_register(&mut self, registers: &[(u16, u8)]) -> Result<()> {
        assert!(registers.len() <= 64, "max 64 registers can be written");
        let mut data = Vec::with_capacity(registers.len() * 3);
        for (addr, value) in registers {
            data.extend_from_slice(&addr.to_be_bytes());
            data.push(*value);
        }
        let status = self.command(cmd::WRITE_REGISTER, &data, Duration::from_millis(250))?;
        if status.iter().any(|&b| b != 0) {
            return Err(ChipsetError::Status(err::REGISTER_WRITE_FAILED).into());
        }
        Ok(())
    }

    /// Reads a single register.
    pub fn read_single_register(&mut self, address: u16) -> Result<u8> {
        let data = self.read_register(&[address])?;
        data.first()
            .copied()
            .ok_or_else(|| DriverError::Other("no register data".into()))
    }

    /// Writes a single register.
    pub fn write_single_register(&mut self, address: u16, value: u8) -> Result<()> {
        self.write_register(&[(address, value)])
    }

    /// Performs InListPassiveTarget command.
    ///
    /// Returns the target data (skipping NbTg and Tg bytes), matching nfcpy's behavior.
    /// For Type F, the returned data is the raw SENSF_RES.
    pub fn in_list_passive_target(
        &mut self,
        max_tg: u8,
        bitrate: u8,
        initiator_data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let mut data = Vec::with_capacity(initiator_data.len() + 2);
        data.push(max_tg);
        data.push(bitrate);
        data.extend_from_slice(initiator_data);

        let response = self.command(cmd::IN_LIST_PASSIVE_TARGET, &data, Duration::from_secs(1))?;
        // Response format: [NbTg][Tg][...target data...]
        // nfcpy returns data[2:] which skips both NbTg and Tg
        if response.is_empty() || response[0] == 0 {
            return Ok(None);
        }
        // A response claiming a target must carry both NbTg and Tg. The reader is
        // the one supplying this, so a short frame has to be reported rather than
        // indexed past the end.
        if response.len() < 2 {
            return Err(DriverError::Other(
                "InListPassiveTarget response reports a target but is too short".into(),
            ));
        }
        // Skip NbTg (response[0]) and Tg (response[1])
        Ok(Some(response[2..].to_vec()))
    }

    /// Performs InDataExchange command.
    pub fn in_data_exchange(&mut self, data: &[u8], timeout: Duration) -> Result<(Vec<u8>, bool)> {
        let mut cmd_data = Vec::with_capacity(data.len() + 1);
        cmd_data.push(0x01); // Target number
        cmd_data.extend_from_slice(data);

        let response = self.command(cmd::IN_DATA_EXCHANGE, &cmd_data, timeout)?;
        if response.is_empty() {
            return Err(ChipsetError::Status(err::NO_DATA).into());
        }

        let status = response[0];
        if status & 0x3F != 0 {
            return Err(ChipsetError::Status(status & 0x3F).into());
        }

        let more = (status & 0x40) != 0;
        Ok((response[1..].to_vec(), more))
    }

    /// Performs InCommunicateThru command.
    pub fn in_communicate_thru(&mut self, data: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let response = self.command(cmd::IN_COMMUNICATE_THRU, data, timeout)?;
        if response.is_empty() || response[0] != 0 {
            let errno = response.first().copied().unwrap_or(err::NO_DATA);
            return Err(ChipsetError::Status(errno).into());
        }
        Ok(response[1..].to_vec())
    }

    /// Performs InJumpForDEP command for active communication mode.
    pub fn in_jump_for_dep(
        &mut self,
        active: bool,
        br: u8,
        passive_data: &[u8],
        nfcid3: &[u8],
        gi: &[u8],
    ) -> Result<Vec<u8>> {
        let cm = if active { 1u8 } else { 0u8 };
        let nf = ((!passive_data.is_empty()) as u8)
            | (((!nfcid3.is_empty()) as u8) << 1)
            | (((!gi.is_empty()) as u8) << 2);

        let mut data = Vec::new();
        data.push(cm);
        data.push(br);
        data.push(nf);
        data.extend_from_slice(passive_data);
        data.extend_from_slice(nfcid3);
        data.extend_from_slice(gi);

        let response = self.command(cmd::IN_JUMP_FOR_DEP, &data, Duration::from_secs(3))?;
        if response.is_empty() || response[0] != 0 {
            let errno = response.first().copied().unwrap_or(err::NO_DATA);
            return Err(ChipsetError::Status(errno).into());
        }
        // A success response carries the status byte and Tg ahead of ATR_RES, so
        // anything shorter than two bytes is malformed and must not be sliced.
        if response.len() < 2 {
            return Err(DriverError::Other(
                "InJumpForDEP response is too short to contain ATR_RES".into(),
            ));
        }
        Ok(response[2..].to_vec())
    }

    /// Performs TgInitTarget command.
    pub fn tg_init_target(
        &mut self,
        mode: u8,
        mifare_params: &[u8],
        felica_params: &[u8],
        nfcid3t: &[u8],
        gt: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        assert!(mode & 0b11111101 == 0, "invalid mode");
        assert_eq!(mifare_params.len(), 6, "mifare_params must be 6 bytes");
        assert_eq!(felica_params.len(), 18, "felica_params must be 18 bytes");
        assert_eq!(nfcid3t.len(), 10, "nfcid3t must be 10 bytes");

        let mut data = Vec::with_capacity(35 + gt.len());
        data.push(mode);
        data.extend_from_slice(mifare_params);
        data.extend_from_slice(felica_params);
        data.extend_from_slice(nfcid3t);
        data.extend_from_slice(gt);

        self.command(cmd::TG_INIT_TARGET, &data, timeout)
    }

    /// Sets general bytes for target mode.
    pub fn tg_set_general_bytes(&mut self, gb: &[u8]) -> Result<()> {
        let response = self.command(cmd::TG_SET_GENERAL_BYTES, gb, Duration::from_millis(100))?;
        if response.first() != Some(&0) {
            let errno = response.first().copied().unwrap_or(err::NO_DATA);
            return Err(ChipsetError::Status(errno).into());
        }
        Ok(())
    }

    /// Gets initiator command in target mode.
    pub fn tg_get_initiator_command(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        let response = self.command(cmd::TG_GET_INITIATOR_COMMAND, &[], timeout)?;
        if response.is_empty() || response[0] != 0 {
            return Ok(None);
        }
        Ok(Some(response[1..].to_vec()))
    }

    /// Sends response to initiator in target mode.
    pub fn tg_response_to_initiator(&mut self, data: &[u8]) -> Result<()> {
        let response = self.command(cmd::TG_RESPONSE_TO_INITIATOR, data, Duration::from_secs(1))?;
        if response.first() != Some(&0) {
            let errno = response.first().copied().unwrap_or(err::NO_DATA);
            return Err(ChipsetError::Status(errno).into());
        }
        Ok(())
    }

    /// Gets target status.
    pub fn tg_get_target_status(&mut self) -> Result<(u8, u16, u16)> {
        let data = self.command(cmd::TG_GET_TARGET_STATUS, &[], Duration::from_millis(100))?;
        if data.len() < 2 {
            return Err(DriverError::Other(
                "target status response too short".into(),
            ));
        }

        let state = data[0];
        let (br_tx, br_rx) = if state == 0x01 {
            let br_tx = [106, 212, 424][(data[1] >> 4 & 7) as usize];
            let br_rx = [106, 212, 424][(data[1] & 7) as usize];
            (br_tx, br_rx)
        } else {
            (0, 0)
        };

        Ok((state, br_tx, br_rx))
    }

    /// Turns the RF field off.
    pub fn rf_field_off(&mut self) -> Result<()> {
        self.rf_configuration(0x01, &[0b00000010])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testing::{DummyTransport, assert_driver_error_contains};
    use std::collections::VecDeque;
    use std::io::ErrorKind;

    fn new_chipset(transport: DummyTransport) -> Chipset<DummyTransport> {
        Chipset {
            transport,
            firmware_version: (0, 0, 0),
            read_buffer: VecDeque::new(),
        }
    }

    #[test]
    fn extract_response_payload_validates_frame_shape_and_command_code() {
        let ok_frame = Frame::build(&[CONTROLLER_TO_HOST, 0x03, 0xAA]);
        let ok_payload =
            Chipset::<DummyTransport>::extract_response_payload(ok_frame, 0x02).expect("valid");
        assert_eq!(ok_payload, vec![0xAA]);

        assert_driver_error_contains(
            Chipset::<DummyTransport>::extract_response_payload(Frame::ack(), 0x02),
            "unexpected frame type",
        );

        match Chipset::<DummyTransport>::extract_response_payload(Frame::build(&[0x7F]), 0x02) {
            Err(DriverError::Chipset(ChipsetError::Status(errno))) => {
                assert_eq!(errno, err::ERROR_FRAME)
            }
            Err(other) => panic!("expected status error, got {other}"),
            Ok(payload) => panic!("expected status error, got payload {payload:?}"),
        }

        assert_driver_error_contains(
            Chipset::<DummyTransport>::extract_response_payload(Frame::build(&[0xD4, 0x03]), 0x02),
            "invalid response identifier",
        );
        assert_driver_error_contains(
            Chipset::<DummyTransport>::extract_response_payload(
                Frame::build(&[CONTROLLER_TO_HOST, 0x04]),
                0x02,
            ),
            "unexpected response code",
        );
    }

    #[test]
    fn parse_response_frame_accepts_valid_normal_and_extended_frames() {
        let chipset = new_chipset(DummyTransport::default());

        let normal = Frame::build(&[CONTROLLER_TO_HOST, 0x03, 0x11]);
        chipset
            .parse_response_frame(normal.as_bytes())
            .expect("normal frame should parse");

        let extended_payload = vec![0xAB; 300];
        let extended = Frame::build(&extended_payload);
        chipset
            .parse_response_frame(extended.as_bytes())
            .expect("extended frame should parse");
    }

    #[test]
    fn parse_response_frame_rejects_malformed_frames() {
        let chipset = new_chipset(DummyTransport::default());

        // Truncated before the postamble.
        assert_driver_error_contains(
            chipset.parse_response_frame(&[0x00, 0x00, 0xFF, 0x01, 0xFF, 0xD5]),
            "invalid response frame",
        );

        let mut bad_lcs = Frame::build(&[0xD5, 0x03]).as_bytes().to_vec();
        bad_lcs[4] ^= 0x01;
        assert_driver_error_contains(
            chipset.parse_response_frame(&bad_lcs),
            "invalid response frame",
        );

        let mut bad_extended_lcs = Frame::build(&vec![0xAA; 300]).as_bytes().to_vec();
        bad_extended_lcs[7] ^= 0x01;
        assert_driver_error_contains(
            chipset.parse_response_frame(&bad_extended_lcs),
            "invalid response frame",
        );
    }

    /// A frame that does not account for the whole USB packet is reported even
    /// though its own checksums are sound: the reader sent bytes this driver
    /// cannot explain.
    #[test]
    fn parse_response_frame_rejects_a_packet_with_bytes_past_the_frame() {
        let chipset = new_chipset(DummyTransport::default());

        let mut packet = Frame::build(&[CONTROLLER_TO_HOST, 0x03, 0x11])
            .as_bytes()
            .to_vec();
        let frame_len = packet.len();
        packet.extend_from_slice(&[0xAA, 0xBB]);

        assert_driver_error_contains(
            chipset.parse_response_frame(&packet),
            &format!(
                "the frame is {frame_len} bytes but the packet is {}",
                packet.len()
            ),
        );
    }

    #[test]
    fn read_frame_from_transport_prefers_buffer_and_handles_empty_reads() {
        let mut buffered = new_chipset(DummyTransport::default());
        buffered.read_buffer.extend([0x01, 0x02, 0x03]);
        let from_buffer = buffered
            .read_frame_from_transport(Duration::from_millis(10))
            .expect("buffered frame should be returned");
        assert_eq!(from_buffer, vec![0x01, 0x02, 0x03]);
        assert!(buffered.read_buffer.is_empty());

        let mut from_transport = new_chipset(DummyTransport::with_reads(vec![Ok(vec![
            0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00,
        ])]));
        let bytes = from_transport
            .read_frame_from_transport(Duration::from_millis(10))
            .expect("transport frame should be returned");
        assert_eq!(bytes, vec![0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00]);

        let mut empty = new_chipset(DummyTransport::with_reads(vec![Ok(Vec::new())]));
        match empty.read_frame_from_transport(Duration::from_millis(10)) {
            Err(DriverError::Io(err)) => assert_eq!(err.kind(), ErrorKind::TimedOut),
            Err(other) => panic!("expected timeout io error, got {other}"),
            Ok(data) => panic!("expected timeout error, got {data:?}"),
        }
    }

    /// The reader supplies these frames, so a response that claims a result but
    /// is too short to hold one has to be reported rather than sliced past the
    /// end. Both of these used to panic with "range start index 2 out of range
    /// for slice of length 1".
    #[test]
    fn short_device_responses_are_reported_instead_of_panicking() {
        use crate::driver::framing::ACK_BYTES;

        // InListPassiveTarget: NbTg = 1 with no Tg byte behind it.
        let frame = Frame::build(&[CONTROLLER_TO_HOST, cmd::IN_LIST_PASSIVE_TARGET + 1, 0x01]);
        let mut chipset = new_chipset(DummyTransport::with_reads(vec![
            Ok(ACK_BYTES.to_vec()),
            Ok(frame.as_bytes().to_vec()),
        ]));
        assert_driver_error_contains(
            chipset.in_list_passive_target(1, 1, &[]),
            "reports a target but is too short",
        );

        // NbTg = 0 still means "no target", which is not an error.
        let frame = Frame::build(&[CONTROLLER_TO_HOST, cmd::IN_LIST_PASSIVE_TARGET + 1, 0x00]);
        let mut chipset = new_chipset(DummyTransport::with_reads(vec![
            Ok(ACK_BYTES.to_vec()),
            Ok(frame.as_bytes().to_vec()),
        ]));
        assert_eq!(chipset.in_list_passive_target(1, 1, &[]).unwrap(), None);

        // InJumpForDEP: status 0 with no Tg byte behind it.
        let frame = Frame::build(&[CONTROLLER_TO_HOST, cmd::IN_JUMP_FOR_DEP + 1, 0x00]);
        let mut chipset = new_chipset(DummyTransport::with_reads(vec![
            Ok(ACK_BYTES.to_vec()),
            Ok(frame.as_bytes().to_vec()),
        ]));
        assert_driver_error_contains(
            chipset.in_jump_for_dep(true, 1, &[], &[0u8; 10], &[]),
            "too short to contain ATR_RES",
        );
    }
}
