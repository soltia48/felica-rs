//! RC-S320 chipset command implementation.
//!
//! This module provides low-level communication with the RC-S320 chipset.
//! The RC-S320 uses a proprietary protocol that differs from the PN53x-based
//! RC-S330 and later devices.

use crate::driver::errors::{DriverError, Result};
use crate::driver::io::{remaining_until, take_from_buffer, timeout_error};
use crate::driver::rcs320::frame::{ACK_BYTES, Frame, FrameType, SOF};
use crate::transport::Transport;
use log::debug;
use std::collections::VecDeque;
use std::io::ErrorKind;
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
        let response = self.packet_read(timeout)?;

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
            take_from_buffer(&mut self.read_buffer, &mut out, len);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;

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

    fn new_chipset(transport: DummyTransport) -> Chipset<DummyTransport> {
        Chipset {
            transport,
            firmware_version: (0, 0),
            read_buffer: VecDeque::new(),
            timeout: Duration::from_millis(100),
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

    #[test]
    fn read_exact_uses_buffer_and_transport_reads() {
        let transport = DummyTransport::with_reads(vec![Ok(vec![0xB0, 0xC0, 0xD0])]);
        let mut chipset = new_chipset(transport);
        chipset.read_buffer.extend([0xA0]);

        let result = chipset
            .read_exact(3, Instant::now() + Duration::from_millis(100))
            .expect("read_exact should gather bytes");
        assert_eq!(result, vec![0xA0, 0xB0, 0xC0]);
        assert_eq!(chipset.read_buffer, VecDeque::from(vec![0xD0]));
    }

    #[test]
    fn read_exact_maps_transport_timeout_to_standard_timeout_error() {
        let transport = DummyTransport::with_reads(vec![Err(io::Error::new(
            ErrorKind::TimedOut,
            "transport timeout",
        ))]);
        let mut chipset = new_chipset(transport);

        match chipset.read_exact(1, Instant::now() + Duration::from_millis(100)) {
            Err(DriverError::Io(err)) => {
                assert_eq!(err.kind(), ErrorKind::TimedOut);
                assert_eq!(err.to_string(), "timeout while waiting for data");
            }
            Err(other) => panic!("expected DriverError::Io timeout, got {other}"),
            Ok(bytes) => panic!("expected timeout error, got {bytes:?}"),
        }
    }

    #[test]
    fn read_exact_times_out_when_deadline_has_passed() {
        let mut chipset = new_chipset(DummyTransport::default());
        match chipset.read_exact(1, Instant::now()) {
            Err(DriverError::Io(err)) => assert_eq!(err.kind(), ErrorKind::TimedOut),
            Err(other) => panic!("expected timeout, got {other}"),
            Ok(bytes) => panic!("expected timeout error, got {bytes:?}"),
        }
    }

    #[test]
    fn read_frame_bytes_handles_ack_and_data_frames() {
        let payload = vec![0x59, 0x01, 0x02];
        let data_frame = Frame::build(&payload).as_bytes().to_vec();

        let transport =
            DummyTransport::with_reads(vec![Ok(ACK_BYTES.to_vec()), Ok(data_frame.clone())]);
        let mut chipset = new_chipset(transport);

        let ack = chipset
            .read_frame_bytes(Instant::now() + Duration::from_millis(100))
            .expect("ACK frame should parse");
        assert_eq!(ack, ACK_BYTES.to_vec());

        let data = chipset
            .read_frame_bytes(Instant::now() + Duration::from_millis(100))
            .expect("data frame should parse");
        assert_eq!(data, data_frame);
    }

    #[test]
    fn read_frame_bytes_rejects_invalid_preamble() {
        let transport = DummyTransport::with_reads(vec![Ok(vec![0x12, 0x00, 0xFF, 0x00, 0xFF])]);
        let mut chipset = new_chipset(transport);
        assert_driver_error_contains(
            chipset.read_frame_bytes(Instant::now() + Duration::from_millis(100)),
            "invalid frame preamble",
        );
    }

    #[test]
    fn wait_for_ack_accepts_ack_or_buffers_response_frame_bytes() {
        let mut ack_chipset = new_chipset(DummyTransport::with_reads(vec![Ok(ACK_BYTES.to_vec())]));
        ack_chipset.wait_for_ack().expect("ACK should be accepted");
        assert!(ack_chipset.read_buffer.is_empty());

        let response_frame = Frame::build(&[0x59, 0x00, 0x01]).as_bytes().to_vec();
        let first_six = response_frame[..6].to_vec();
        let mut response_chipset =
            new_chipset(DummyTransport::with_reads(vec![Ok(first_six.clone())]));
        response_chipset
            .wait_for_ack()
            .expect("response frame prefix should be buffered");
        assert_eq!(
            response_chipset
                .read_buffer
                .iter()
                .copied()
                .collect::<Vec<u8>>(),
            first_six
        );
    }

    #[test]
    fn wait_for_ack_rejects_non_ack_non_frame_data() {
        let mut chipset = new_chipset(DummyTransport::with_reads(vec![Ok(vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        ])]));
        assert_driver_error_contains(chipset.wait_for_ack(), "expected ACK");
    }

    #[test]
    fn get_firmware_version_parses_response_and_writes_command() {
        let response = Frame::build(&[cmd::GET_FIRMWARE_VERSION_RES, 0x02, 0x01])
            .as_bytes()
            .to_vec();
        let transport = DummyTransport::with_reads(vec![Ok(ACK_BYTES.to_vec()), Ok(response)]);
        let mut chipset = new_chipset(transport);

        let version = chipset
            .get_firmware_version()
            .expect("firmware version should parse");
        assert_eq!(version, (0x01, 0x02));

        let command_frame = chipset
            .transport
            .writes
            .first()
            .expect("command frame should be written");
        let payload = Frame::parse(command_frame)
            .and_then(|frame| frame.into_payload())
            .expect("command frame should have payload");
        assert_eq!(payload, vec![cmd::GET_FIRMWARE_VERSION]);
    }

    #[test]
    fn get_firmware_version_rejects_wrong_response_code() {
        let response = Frame::build(&[0x00, 0x02, 0x01]).as_bytes().to_vec();
        let transport = DummyTransport::with_reads(vec![Ok(ACK_BYTES.to_vec()), Ok(response)]);
        let mut chipset = new_chipset(transport);
        assert_driver_error_contains(
            chipset.get_firmware_version(),
            "invalid firmware version response",
        );
    }

    #[test]
    fn send_to_card_builds_send_packet_command_and_checks_size() {
        let transport = DummyTransport::with_reads(vec![Ok(ACK_BYTES.to_vec())]);
        let mut chipset = new_chipset(transport);
        chipset
            .send_to_card(&[0xDE, 0xAD])
            .expect("send_to_card should write a command");

        let written = chipset
            .transport
            .writes
            .first()
            .expect("at least one frame should be written");
        let payload = Frame::parse(written)
            .and_then(|frame| frame.into_payload())
            .expect("written frame should have payload");
        assert_eq!(payload, vec![cmd::SEND_PACKET, 0x03, 0xDE, 0xAD]);

        let mut oversized_chipset = new_chipset(DummyTransport::default());
        let oversized = vec![0x00; MAX_DATA_SIZE - 1];
        assert_driver_error_contains(
            oversized_chipset.send_to_card(&oversized),
            "data too long for send_to_card",
        );
    }

    #[test]
    fn recv_from_card_returns_payload_and_validates_response_code() {
        let valid_response = Frame::build(&[cmd::SEND_PACKET_RES, 0x02, 0xAA, 0xBB, 0xCC])
            .as_bytes()
            .to_vec();
        let transport = DummyTransport::with_reads(vec![Ok(valid_response)]);
        let mut chipset = new_chipset(transport);
        let payload = chipset
            .recv_from_card(Duration::from_millis(50))
            .expect("valid card response should parse");
        assert_eq!(payload, vec![0xAA, 0xBB]);

        let bad_code = Frame::build(&[0x01, 0x01, 0xAA]).as_bytes().to_vec();
        let transport = DummyTransport::with_reads(vec![Ok(bad_code)]);
        let mut chipset = new_chipset(transport);
        assert_driver_error_contains(
            chipset.recv_from_card(Duration::from_millis(50)),
            "invalid card response",
        );
    }

    #[test]
    fn recv_from_card_rejects_short_response() {
        let short_response = Frame::build(&[cmd::SEND_PACKET_RES]).as_bytes().to_vec();
        let transport = DummyTransport::with_reads(vec![Ok(short_response)]);
        let mut chipset = new_chipset(transport);
        assert_driver_error_contains(
            chipset.recv_from_card(Duration::from_millis(50)),
            "card response too short",
        );
    }
}
