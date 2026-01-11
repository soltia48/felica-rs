//! RC-S320 device driver implementation.
//!
//! This module provides the high-level device interface for RC-S320 readers.

use crate::clf::errors::CommunicationError;
use crate::clf::targets::RemoteTarget;
use crate::driver::errors::{DriverError, Result};
use crate::driver::rcs320::chipset::Chipset;
use crate::driver::rcs320::transport::Rcs320Transport;
use crate::felica_standard::{FelicaDriver, Type3TagPollingResult};
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
    vendor_name: Option<String>,
    product_name: Option<String>,
    chipset_name: String,
}

/// Initializes an RC-S320 device with the given transport.
pub fn init<T: Transport>(transport: T) -> Result<Device<T>> {
    let chipset = Chipset::new(transport)?;
    Device::new(chipset)
}

/// Opens an RC-S320 device.
pub fn open_rcs320_device() -> Result<Device<Rcs320Transport>> {
    let transport = Rcs320Transport::open().map_err(DriverError::Io)?;
    init(transport)
}

impl<T: Transport> Device<T> {
    /// Creates a new device with the given chipset.
    pub fn new(chipset: Chipset<T>) -> Result<Self> {
        let version = chipset.firmware_version();
        let chipset_name = format!("RCS320v{}.{}", version.0, version.1);
        let vendor_name = chipset.manufacturer_name().map(|s| s.to_string());
        let product_name = chipset.product_name().map(|s| s.to_string());

        debug!("chipset is a {}", chipset_name);

        Ok(Self {
            vendor_name,
            product_name,
            chipset,
            chipset_name,
        })
    }

    /// Returns a mutable reference to the chipset.
    pub fn chipset(&mut self) -> &mut Chipset<T> {
        &mut self.chipset
    }

    /// Returns the vendor name.
    pub fn vendor_name(&self) -> Option<&str> {
        self.vendor_name.as_deref()
    }

    /// Returns the product name.
    pub fn product_name(&self) -> Option<&str> {
        self.product_name.as_deref()
    }

    /// Returns the chipset name.
    pub fn chipset_name(&self) -> &str {
        &self.chipset_name
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
            felica_cmd::POLLING,  // 0x00
            sc_bytes[0],          // System code high byte
            sc_bytes[1],          // System code low byte
            request_code,         // RFU (Request code)
            time_slots,           // Time slot
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
