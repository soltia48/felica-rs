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

        // Build SENSF_REQ (Polling command)
        // Format: [len, cmd, SC_hi, SC_lo, RC, TSN]
        let sc_bytes = system_code.to_be_bytes();
        let sensf_req = [
            6, // Length including this byte
            felica_cmd::POLLING,
            sc_bytes[0],
            sc_bytes[1],
            request_code,
            time_slots,
        ];

        let timeout = Duration::from_millis(500);
        let response = self.chipset.communicate_thru(&sensf_req, timeout)?;

        // Parse SENSF_RES
        // Format: [len, cmd, IDm(8), PMm(8), RD(optional)]
        if response.is_empty() {
            return Err(DriverError::Communication(CommunicationError::timeout(
                "no FeliCa card found",
            )));
        }

        let len = response[0] as usize;
        if len < 18 || response.len() < len {
            return Err(DriverError::Other("SENSF_RES too short".into()));
        }

        if response.get(1) != Some(&felica_cmd::POLLING_RES) {
            return Err(DriverError::Other(format!(
                "unexpected response code: {:02X}",
                response.get(1).unwrap_or(&0xFF)
            )));
        }

        let idm = response[2..10].to_vec();
        let pmm = response[10..18].to_vec();

        let optional = if len > 18 && response.len() >= len {
            response[18..len].to_vec()
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

        // The data should already include the length byte as per FeliCa protocol
        let response = self.chipset.communicate_thru(data, timeout)?;

        // Return the response (includes length byte)
        Ok(response)
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
