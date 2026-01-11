//! RC-S320 chipset command implementation.
//!
//! This module provides low-level communication with the RC-S320 chipset.
//! The RC-S320 uses a proprietary protocol that differs from the PN53x-based
//! RC-S330 and later devices.

use crate::driver::errors::{DriverError, Result};
use crate::driver::rcs320::frame::{ACK_BYTES, Frame, FrameType, SOF};
use crate::transport::Transport;
use log::debug;
use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::time::{Duration, Instant};

/// Maximum data size for RC-S320 frames.
pub const MAX_DATA_SIZE: usize = 255;

/// RC-S320 command codes.
#[allow(dead_code)]
pub mod cmd {
    /// Get firmware version command.
    pub const GET_FIRMWARE_VERSION: u8 = 0x58;
    /// Firmware version response.
    pub const GET_FIRMWARE_VERSION_RES: u8 = 0x59;

    /// Self diagnosis command.
    pub const SELF_DIAGNOSIS: u8 = 0x52;
    /// Self diagnosis response.
    pub const SELF_DIAGNOSIS_RES: u8 = 0x53;

    /// Reset command.
    pub const RESET: u8 = 0x54;

    /// Send packet to card command.
    pub const SEND_PACKET: u8 = 0x5C;
    /// Send packet response.
    pub const SEND_PACKET_RES: u8 = 0x5D;

    /// Initialization command (used for various init sequences).
    pub const INIT: u8 = 0x62;
    /// Initialization response.
    pub const INIT_RES: u8 = 0x63;

    /// RF field on/off control.
    pub const RF_CONTROL: u8 = 0x5A;
    /// RF control response.
    pub const RF_CONTROL_RES: u8 = 0x5B;
}

/// RC-S320 initialization sequences (from libpafe).
pub mod init_seq {
    /// Init sequence 0: Read register 0x82
    pub const INIT0: &[u8] = &[0x62, 0x01, 0x82];

    /// Init sequence 1: Read registers 0x80, 0x81
    pub const INIT1: &[u8] = &[0x62, 0x02, 0x80, 0x81];

    /// Init sequence 2: Write registers 0x80=0xCC, 0x81=0x88
    pub const INIT2: &[u8] = &[0x62, 0x22, 0x80, 0xcc, 0x81, 0x88];

    /// Init sequence 3: Same as INIT1
    pub const INIT3: &[u8] = &[0x62, 0x02, 0x80, 0x81];

    /// Init sequence 4: Read registers 0x82, 0x87
    pub const INIT4: &[u8] = &[0x62, 0x02, 0x82, 0x87];

    /// Init sequence 5: Write register 0x25=0x58
    pub const INIT5: &[u8] = &[0x62, 0x21, 0x25, 0x58];

    /// RF on command
    pub const RF_ON: &[u8] = &[0x5a, 0x80];

    /// Reset command
    pub const RESET: &[u8] = &[0x54];
}

/// RC-S320 chipset communication handler.
pub struct Chipset<T: Transport> {
    transport: T,
    firmware_version: (u8, u8),
    read_buffer: VecDeque<u8>,
    timeout: Duration,
}

impl<T: Transport> Chipset<T> {
    const ACK: [u8; 6] = ACK_BYTES;
    const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);
    /// ACK timeout - must be long enough for card operations
    const ACK_TIMEOUT: Duration = Duration::from_millis(1000);

    /// Creates a new chipset handler with the given transport.
    pub fn new(transport: T) -> Result<Self> {
        let mut chipset = Self {
            transport,
            firmware_version: (0, 0),
            read_buffer: VecDeque::new(),
            timeout: Self::DEFAULT_TIMEOUT,
        };

        // Initialize the device
        chipset.initialize()?;

        Ok(chipset)
    }

    /// Returns the firmware version (major, minor).
    pub fn firmware_version(&self) -> (u8, u8) {
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

    /// Sets the timeout for operations.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Closes the chipset connection.
    pub fn close(&mut self) -> Result<()> {
        self.reset()?;
        self.transport.close()?;
        Ok(())
    }

    /// Initializes the RC-S320 device.
    ///
    /// This sends the initialization sequence required by the RC-S320.
    fn initialize(&mut self) -> Result<()> {
        debug!("initializing RC-S320");

        // Send initialization sequences
        self.send_init_command(init_seq::INIT0)?;
        self.send_init_command(init_seq::INIT1)?;
        self.send_init_command(init_seq::INIT2)?;
        self.send_init_command(init_seq::INIT3)?;
        self.send_init_command(init_seq::INIT4)?;
        self.send_init_command(init_seq::INIT5)?;

        // Turn on RF field
        self.send_init_command(init_seq::RF_ON)?;

        // Get firmware version
        let version = self.get_firmware_version()?;
        self.firmware_version = version;
        debug!("RC-S320 firmware version: {}.{}", version.0, version.1);

        Ok(())
    }

    /// Sends an initialization command and waits for response.
    fn send_init_command(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.packet_write(data)?;
        self.recv_response(Self::DEFAULT_TIMEOUT)
    }

    /// Resets the RC-S320 device.
    pub fn reset(&mut self) -> Result<()> {
        debug!("resetting RC-S320");
        let _ = self.send_init_command(init_seq::RESET);
        Ok(())
    }

    /// Gets the firmware version.
    pub fn get_firmware_version(&mut self) -> Result<(u8, u8)> {
        let data = &[cmd::GET_FIRMWARE_VERSION];
        self.packet_write(data)?;
        let response = self.packet_read(Self::DEFAULT_TIMEOUT)?;

        if response.first() != Some(&cmd::GET_FIRMWARE_VERSION_RES) {
            return Err(DriverError::Other(
                "invalid firmware version response".into(),
            ));
        }

        if response.len() < 3 {
            return Err(DriverError::Other(
                "firmware version response too short".into(),
            ));
        }

        // Response format: [0x59, minor, major]
        let minor = response[1];
        let major = response[2];

        Ok((major, minor))
    }

    /// Sends data to a FeliCa card.
    ///
    /// This wraps the data with the SEND_PACKET command.
    pub fn send_to_card(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_DATA_SIZE - 2 {
            return Err(DriverError::Other("data too long for send_to_card".into()));
        }

        // Command format: [0x5C, length+1, data...]
        let mut cmd = Vec::with_capacity(data.len() + 2);
        cmd.push(cmd::SEND_PACKET);
        cmd.push((data.len() + 1) as u8);
        cmd.extend_from_slice(data);

        self.packet_write(&cmd)
    }

    /// Receives data from a FeliCa card.
    pub fn recv_from_card(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let response = match self.packet_read(timeout) {
            Ok(response) => response,
            Err(e) => return Err(e),
        };

        debug!("RC-S320 card response: {:02X?}", response);

        if response.first() != Some(&cmd::SEND_PACKET_RES) {
            return Err(DriverError::Other(format!(
                "invalid card response, expected 0x5D, got: {:02X?}",
                response.first()
            )));
        }

        if response.len() < 2 {
            return Err(DriverError::Other("card response too short".into()));
        }

        // Response format: [0x5D, length, data...]
        // Per libpafe: length is the count of data bytes, data starts at offset 2
        let len = response[1] as usize;

        // Return all data after the 2-byte header
        // The actual data length is min(len, available bytes)
        let available = response.len() - 2;
        let data_len = std::cmp::min(len, available);

        Ok(response[2..2 + data_len].to_vec())
    }

    /// Performs a communicate thru operation (send and receive from card).
    pub fn communicate_thru(&mut self, data: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        self.send_to_card(data)?;
        self.recv_from_card(timeout)
    }

    // ========================================================================
    // Low-level packet I/O
    // ========================================================================

    /// Writes a packet with framing.
    fn packet_write(&mut self, data: &[u8]) -> Result<()> {
        let frame = Frame::build(data);
        debug!("RC-S320 packet write: {:02X?}", frame.as_bytes());
        self.transport.write(frame.as_bytes())?;

        // Wait for and verify ACK
        self.wait_for_ack()
    }

    /// Reads a packet with framing.
    fn packet_read(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let frame = self.recv_response(timeout)?;
        Ok(frame)
    }

    /// Waits for ACK after sending a command.
    fn wait_for_ack(&mut self) -> Result<()> {
        let deadline = Instant::now() + Self::ACK_TIMEOUT;
        let bytes = self.read_exact(Self::ACK.len(), deadline)?;

        if bytes != Self::ACK {
            // Check if it's actually a response frame (RC-S320 might skip ACK)
            if bytes.get(0..3) == Some(&SOF) {
                // Push back to buffer for later processing
                for byte in bytes.into_iter().rev() {
                    self.read_buffer.push_front(byte);
                }
                return Ok(());
            }
            return Err(DriverError::Other(format!(
                "expected ACK, got: {:02X?}",
                bytes
            )));
        }

        debug!("RC-S320 received ACK");
        Ok(())
    }

    /// Receives a response frame.
    fn recv_response(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        let frame_bytes = self.read_frame_bytes(deadline)?;

        let frame = Frame::parse(&frame_bytes)
            .ok_or_else(|| DriverError::Other("invalid response frame".into()))?;

        match frame.frame_type() {
            FrameType::Ack => {
                // Got ACK, wait for actual response
                let frame_bytes = self.read_frame_bytes(deadline)?;
                let frame = Frame::parse(&frame_bytes)
                    .ok_or_else(|| DriverError::Other("invalid response frame after ACK".into()))?;
                frame
                    .into_payload()
                    .ok_or_else(|| DriverError::Other("no payload in response".into()))
            }
            FrameType::Error => Err(DriverError::Other("error frame received".into())),
            FrameType::Data(_) => frame
                .into_payload()
                .ok_or_else(|| DriverError::Other("no payload in response".into())),
        }
    }

    /// Reads the raw bytes of a frame.
    fn read_frame_bytes(&mut self, deadline: Instant) -> Result<Vec<u8>> {
        // Read header: SOF(3) + LEN(1) + LCS(1) = 5 bytes
        let mut frame = self.read_exact(5, deadline)?;

        if frame.get(0..3) != Some(&SOF) {
            return Err(DriverError::Other("invalid frame preamble".into()));
        }

        // Check for ACK frame (LEN=0x00, LCS=0xFF)
        if frame[3] == 0x00 && frame[4] == 0xFF {
            // Read postamble
            let postamble = self.read_exact(1, deadline)?;
            frame.extend_from_slice(&postamble);
            return Ok(frame);
        }

        let len = frame[3] as usize;

        // Read remaining: DATA(len) + DCS(1) + POSTAMBLE(1) = len + 2 bytes
        let tail = self.read_exact(len + 2, deadline)?;
        frame.extend_from_slice(&tail);

        debug!("RC-S320 received frame: {:02X?}", frame);
        Ok(frame)
    }

    /// Reads exactly `len` bytes from the buffer/transport.
    fn read_exact(&mut self, len: usize, deadline: Instant) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len);

        while out.len() < len {
            self.take_from_buffer(&mut out, len);
            if out.len() == len {
                break;
            }

            let remaining =
                remaining_until(deadline).ok_or_else(|| DriverError::Io(timeout_error()))?;

            match self.transport.read(remaining) {
                Ok(chunk) => {
                    if !chunk.is_empty() {
                        self.read_buffer.extend(chunk);
                    }
                }
                Err(e) if e.kind() == ErrorKind::TimedOut => {
                    return Err(DriverError::Io(timeout_error()));
                }
                Err(e) => return Err(DriverError::Io(e)),
            }
        }

        Ok(out)
    }

    /// Takes bytes from the read buffer.
    fn take_from_buffer(&mut self, out: &mut Vec<u8>, len: usize) {
        while out.len() < len {
            if let Some(byte) = self.read_buffer.pop_front() {
                out.push(byte);
            } else {
                break;
            }
        }
    }
}

fn remaining_until(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| d.as_nanos() != 0)
}

fn timeout_error() -> io::Error {
    io::Error::new(ErrorKind::TimedOut, "timeout while waiting for data")
}
