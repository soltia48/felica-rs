//! RC-S320 device driver implementation.
//!
//! This module provides the high-level device interface for RC-S320 readers.

use crate::clf::errors::CommunicationError;
use crate::clf::targets::RemoteTarget;
use crate::driver::common::{DeviceInfo, DeviceMetadata, impl_reader_device};
use crate::driver::errors::{DriverError, Result};
use crate::driver::rcs320::chipset::Chipset;
use crate::driver::rcs320::transport::Rcs320Transport;
use crate::felica_standard::Type3TagPollingResult;
use crate::transport::Transport;
use log::debug;
use std::time::Duration;

/// FeliCa command codes.
mod felica_cmd {
    /// Polling command.
    pub const POLLING: u8 = 0x00;
    /// Polling response.
    pub const POLLING_RES: u8 = 0x01;
}

/// RC-S320 device driver.
pub struct Device<T: Transport> {
    pub(crate) chipset: Chipset<T>,
    meta: DeviceMetadata,
}

/// Initializes an RC-S320 device with the given transport.
pub fn init<T: Transport>(transport: T) -> Result<Device<T>> {
    let chipset = Chipset::new(transport)?;
    Device::new(chipset)
}

/// Opens an RC-S320 device.
pub fn open_rcs320() -> Result<Device<Rcs320Transport>> {
    let transport = Rcs320Transport::open().map_err(DriverError::Io)?;
    init(transport)
}

impl<T: Transport> Device<T> {
    /// Creates a new device with the given chipset.
    pub fn new(chipset: Chipset<T>) -> Result<Self> {
        let version = chipset.firmware_version();
        let meta = DeviceMetadata {
            vendor_name: chipset.manufacturer_name().map(|s| s.to_string()),
            product_name: chipset.product_name().map(|s| s.to_string()),
            chipset_name: format!("RCS320v{}.{}", version.0, version.1),
        };

        debug!("chipset is a {}", meta.chipset_name);

        Ok(Self { chipset, meta })
    }

    /// Returns a mutable reference to the chipset.
    pub fn chipset(&mut self) -> &mut Chipset<T> {
        &mut self.chipset
    }

    /// Closes the device.
    pub fn close(&mut self) -> Result<()> {
        self.chipset.close()
    }

    /// Returns the maximum send data size for a target.
    pub fn get_max_send_data_size(&self, _target: &RemoteTarget) -> usize {
        crate::driver::rcs320::chipset::MAX_DATA_SIZE - 4
    }

    /// Returns the maximum receive data size for a target.
    pub fn get_max_recv_data_size(&self, _target: &RemoteTarget) -> usize {
        crate::driver::rcs320::chipset::MAX_DATA_SIZE - 4
    }

    /// Detects a Type F target (NFC-F/FeliCa).
    pub fn detect_type_f(
        &mut self,
        _target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<Type3TagPollingResult> {
        debug!(
            "RC-S320 polling for FeliCa: system_code={:04X}, request_code={:02X}, time_slots={}",
            system_code, request_code, time_slots
        );

        // Build Polling command (5 bytes, no length prefix)
        // The RC-S320 hardware adds the length byte when sending to card
        // Format: [cmd, SC_hi, SC_lo, RFU, TSN]
        let sc_bytes = system_code.to_be_bytes();
        let polling_cmd = [
            felica_cmd::POLLING, // 0x00
            sc_bytes[0],         // System code high byte
            sc_bytes[1],         // System code low byte
            request_code,        // RFU (Request code)
            time_slots,          // Time slot
        ];

        let timeout = Duration::from_millis(1000);
        let response = self.chipset.communicate_thru(&polling_cmd, timeout)?;

        // Parse Polling response
        // Response format from card: [cmd, IDm(8), PMm(8), RD(optional)]
        // (no length byte in response from RC-S320)
        if response.is_empty() {
            return Err(DriverError::Communication(CommunicationError::timeout(
                "no FeliCa card found",
            )));
        }

        if response.first() != Some(&felica_cmd::POLLING_RES) {
            return Err(DriverError::Other(format!(
                "unexpected response code: {:02X}",
                response.first().unwrap_or(&0xFF)
            )));
        }

        // Response: [01, IDm(8), PMm(8), RD(optional)]
        if response.len() < 17 {
            return Err(DriverError::Other(format!(
                "polling response too short: {} bytes",
                response.len()
            )));
        }

        let idm = response[1..9].to_vec();
        let pmm = response[9..17].to_vec();

        let optional = if response.len() > 17 {
            response[17..].to_vec()
        } else {
            Vec::new()
        };

        debug!("FeliCa card found: IDm={}", hex::encode(&idm));

        Ok(Type3TagPollingResult { idm, pmm, optional })
    }

    /// Sends data and receives a response from a FeliCa card.
    pub fn transceive(
        &mut self,
        _target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>> {
        let timeout = Duration::from_millis(timeout_ms.unwrap_or(1000) as u64 + 100);

        // FelicaStandard sends data WITH a length prefix: [len, cmd, ...]
        // But RC-S320 expects data WITHOUT length prefix: [cmd, ...]
        // The RC-S320 hardware adds the length when sending to the card
        if data.is_empty() {
            return Err(DriverError::Other("empty transceive data".into()));
        }

        // Strip the length byte from the front of the data
        let card_data = if data[0] as usize == data.len() {
            // First byte is length - strip it
            &data[1..]
        } else {
            // Data doesn't have length prefix, use as-is
            data
        };

        debug!("RC-S320 transceive: sending {:02X?}", card_data);

        let response = self.chipset.communicate_thru(card_data, timeout)?;

        // RC-S320 response doesn't include length byte
        // We need to add it back for FelicaStandard compatibility
        let mut result = Vec::with_capacity(response.len() + 1);
        result.push((response.len() + 1) as u8);
        result.extend_from_slice(&response);

        debug!("RC-S320 transceive: received {:02X?}", result);

        Ok(result)
    }
}

impl<T: Transport> DeviceInfo for Device<T> {
    fn metadata(&self) -> &DeviceMetadata {
        &self.meta
    }
}

impl_reader_device!(Device);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::rcs320::frame::{ACK_BYTES, Frame};
    use crate::driver::testing::{DummyTransport, WriteLog};
    use std::io;

    fn init_read_sequence(extra_reads: Vec<io::Result<Vec<u8>>>) -> Vec<io::Result<Vec<u8>>> {
        let mut reads = Vec::new();

        // INIT0..INIT5, RF_ON: ACK + simple response frame payload [0x00].
        for _ in 0..7 {
            reads.push(Ok(ACK_BYTES.to_vec()));
            reads.push(Ok(Frame::build(&[0x00]).as_bytes().to_vec()));
        }

        // Firmware version command: ACK + response [0x59, minor, major].
        reads.push(Ok(ACK_BYTES.to_vec()));
        reads.push(Ok(Frame::build(&[0x59, 0x02, 0x01]).as_bytes().to_vec()));

        reads.extend(extra_reads);
        reads
    }

    fn build_device(extra_reads: Vec<io::Result<Vec<u8>>>) -> (Device<DummyTransport>, WriteLog) {
        let transport = DummyTransport::with_reads(init_read_sequence(extra_reads))
            .with_metadata("Sony", "RC-S320")
            .timing_out_when_exhausted();
        let writes = transport.writes();
        let chipset = Chipset::new(transport).expect("chipset should initialize");
        (
            Device::new(chipset).expect("device should be constructed"),
            writes,
        )
    }

    fn target() -> RemoteTarget {
        RemoteTarget::new("212F").expect("target should be created")
    }

    fn send_packet_response_frame(data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(data.len() + 2);
        payload.push(0x5D);
        payload.push(data.len() as u8);
        payload.extend_from_slice(data);
        Frame::build(&payload).as_bytes().to_vec()
    }

    #[test]
    fn device_metadata_and_max_sizes_are_reported() {
        let (device, _) = build_device(Vec::new());
        assert_eq!(device.vendor_name(), Some("Sony"));
        assert_eq!(device.product_name(), Some("RC-S320"));
        assert_eq!(device.chipset_name(), "RCS320v1.2");

        let target = target();
        assert_eq!(
            device.get_max_send_data_size(&target),
            crate::driver::rcs320::chipset::MAX_DATA_SIZE - 4
        );
        assert_eq!(
            device.get_max_recv_data_size(&target),
            crate::driver::rcs320::chipset::MAX_DATA_SIZE - 4
        );
    }

    #[test]
    fn transceive_rejects_empty_payload_before_touching_chipset_exchange() {
        let (mut device, writes) = build_device(Vec::new());
        let writes_before = writes.len();
        let target = target();
        match device.transceive(&target, &[], None) {
            Err(DriverError::Other(message)) => assert_eq!(message, "empty transceive data"),
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(data) => panic!("expected error, got {data:?}"),
        }
        assert_eq!(writes.len(), writes_before);
    }

    #[test]
    fn transceive_strips_length_prefix_and_readds_response_length() {
        let response_payload = vec![0x5D, 0x03, 0xAA, 0xBB, 0xCC];
        let (mut device, writes) = build_device(vec![
            Ok(ACK_BYTES.to_vec()),
            Ok(Frame::build(&response_payload).as_bytes().to_vec()),
        ]);
        let target = target();

        let result = device
            .transceive(&target, &[0x04, 0x06, 0x01, 0x02], Some(100))
            .expect("transceive should succeed");
        assert_eq!(result, vec![0x04, 0xAA, 0xBB, 0xCC]);

        let last_write = writes.last();
        let command_payload = Frame::parse(&last_write)
            .and_then(|frame| frame.into_payload())
            .expect("written frame should contain payload");
        assert_eq!(command_payload, vec![0x5C, 0x04, 0x06, 0x01, 0x02]);
    }

    #[test]
    fn detect_type_f_sends_polling_command_and_parses_response() {
        let card_response = vec![
            0x01, // Polling response command
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // IDm
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // PMm
            0xA1, 0xB2, // optional bytes
        ];
        let (mut device, writes) = build_device(vec![
            Ok(ACK_BYTES.to_vec()),
            Ok(send_packet_response_frame(&card_response)),
        ]);
        let target = target();

        let result = device
            .detect_type_f(&target, 0xFE00, 0x01, 0x02)
            .expect("detect_type_f should succeed");
        assert_eq!(result.idm, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            result.pmm,
            vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
        assert_eq!(result.optional, vec![0xA1, 0xB2]);

        let last_write = writes.last();
        let command_payload = Frame::parse(&last_write)
            .and_then(|frame| frame.into_payload())
            .expect("written frame should contain payload");
        assert_eq!(
            command_payload,
            vec![0x5C, 0x06, 0x00, 0xFE, 0x00, 0x01, 0x02]
        );
    }

    #[test]
    fn detect_type_f_maps_empty_response_to_timeout() {
        let (mut device, _) = build_device(vec![
            Ok(ACK_BYTES.to_vec()),
            Ok(send_packet_response_frame(&[])),
        ]);
        let target = target();

        match device.detect_type_f(&target, 0xFFFF, 0, 0) {
            Err(DriverError::Communication(crate::clf::errors::CommunicationError::Timeout(
                message,
            ))) => assert_eq!(message, "no FeliCa card found"),
            Err(other) => panic!("expected timeout communication error, got {other}"),
            Ok(value) => panic!("expected timeout error, got {value:?}"),
        }
    }

    #[test]
    fn detect_type_f_rejects_unexpected_response_code() {
        let (mut device, _) = build_device(vec![
            Ok(ACK_BYTES.to_vec()),
            Ok(send_packet_response_frame(&[0x7F])),
        ]);
        let target = target();

        match device.detect_type_f(&target, 0xFFFF, 0, 0) {
            Err(DriverError::Other(message)) => assert_eq!(message, "unexpected response code: 7F"),
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(value) => panic!("expected error, got {value:?}"),
        }
    }

    #[test]
    fn detect_type_f_rejects_short_polling_response() {
        let (mut device, _) = build_device(vec![
            Ok(ACK_BYTES.to_vec()),
            Ok(send_packet_response_frame(&[0x01, 0xAA])),
        ]);
        let target = target();

        match device.detect_type_f(&target, 0xFFFF, 0, 0) {
            Err(DriverError::Other(message)) => {
                assert_eq!(message, "polling response too short: 2 bytes")
            }
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(value) => panic!("expected error, got {value:?}"),
        }
    }
}
