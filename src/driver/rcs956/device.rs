//! RC-S956 device driver implementation.
//!
//! This module provides the high-level device interface for RC-S956 based readers.

use crate::clf::crc;
use crate::clf::errors::CommunicationError;
use crate::clf::targets::RemoteTarget;
use crate::driver::errors::{DriverError, Result};
use crate::driver::rcs956::chipset::Chipset;
use crate::felica_standard::{FelicaDriver, Type3TagPollingResult};
use crate::transport::Transport;
use crate::transport::usb::UsbTransport;
use log::debug;
use std::io::{self, ErrorKind};

/// RC-S956 device driver.
pub struct Device<T: Transport> {
    pub(crate) chipset: Chipset<T>,
    vendor_name: Option<String>,
    product_name: Option<String>,
    chipset_name: String,
}

/// Initializes an RC-S956 device with the given transport.
pub fn init<T: Transport>(transport: T) -> Result<Device<T>> {
    let chipset = Chipset::new(transport)?;
    Device::new(chipset)
}

/// Opens an RC-S956 device (RC-S330/RC-S360/RC-S370).
pub fn open_rcs956_device() -> Result<Device<UsbTransport>> {
    const SONY_VID: u16 = 0x054C;
    // RC-S330: 0x01BB, RC-S360: 0x02E1, RC-S370: 0x02E1
    const PRODUCT_IDS: [u16; 3] = [0x01BB, 0x02E1, 0x0193];

    let mut last_error: Option<io::Error> = None;
    for pid in PRODUCT_IDS {
        match UsbTransport::open(SONY_VID, pid) {
            Ok(transport) => return init(transport),
            Err(err) => last_error = Some(err),
        }
    }

    Err(DriverError::Io(last_error.unwrap_or_else(|| {
        io::Error::new(ErrorKind::NotFound, "RC-S956 reader not found")
    })))
}

impl<T: Transport> Device<T> {
    /// Creates a new device with the given chipset.
    pub fn new(mut chipset: Chipset<T>) -> Result<Self> {
        let version = chipset.firmware_version();
        let chipset_name = format!("RCS956v{:x}.{:x}", version.1, version.2);
        let vendor_name = chipset.manufacturer_name().map(|s| s.to_string());
        let product_name = chipset.product_name().map(|s| s.to_string());

        debug!("chipset is a {}", chipset_name);

        // Initialize the device
        chipset.rf_field_off()?;

        // Set timeout for PSL_RES, ATR_RES, InDataExchange/InCommunicateThru
        chipset.rf_configuration(0x02, &[0x0B, 0x0B, 0x0A])?;
        chipset.rf_configuration(0x04, &[0x00])?;
        chipset.rf_configuration(0x05, &[0x00, 0x00, 0x01])?;

        // Write RF settings for 106A
        debug!("write rf settings for 106A");
        let rf_settings = [
            0x5A, 0xF4, 0x3F, 0x11, 0x4D, 0x85, 0x61, 0x6F, 0x26, 0x62, 0x87,
        ];
        chipset.rf_configuration(0x0A, &rf_settings)?;

        // Set parameters
        chipset.set_parameters(0b00001000)?;
        chipset.reset_mode()?;

        // Set the RFCfg value for RAM-07
        chipset.write_single_register(0x0328, 0x59)?;

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
        self.mute()?;
        self.chipset.close()
    }

    /// Turns off the RF field.
    pub fn mute(&mut self) -> Result<()> {
        self.chipset.reset_mode()?;
        self.chipset.rf_field_off()
    }

    /// Returns the maximum send data size for a target.
    pub fn get_max_send_data_size(&self, _target: &RemoteTarget) -> usize {
        crate::driver::rcs956::chipset::HOST_COMMAND_FRAME_MAX_SIZE - 2
    }

    /// Returns the maximum receive data size for a target.
    pub fn get_max_recv_data_size(&self, _target: &RemoteTarget) -> usize {
        crate::driver::rcs956::chipset::HOST_COMMAND_FRAME_MAX_SIZE - 3
    }

    /// Sends data and receives a response.
    pub fn transceive(
        &mut self,
        target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>> {
        let timeout = std::time::Duration::from_millis(timeout_ms.unwrap_or(1000) as u64 + 100);

        // Handle Type 2 Tag (need CRC check since firmware reports CRC errors for ACK/NAK)
        if is_type2_target(target) {
            return self.transceive_type2(data, timeout);
        }

        // Handle Type 1 Tag
        if target.data.rid_res.is_some() {
            return self.transceive_type1(data, timeout);
        }

        // Standard communication
        self.chipset.in_communicate_thru(data, timeout)
    }

    fn transceive_type1(&mut self, data: &[u8], timeout: std::time::Duration) -> Result<Vec<u8>> {
        // Type 1 Tag commands: RALL, READ, WRITE-NE, WRITE-E, RID
        if matches!(
            data.first(),
            Some(0x00) | Some(0x01) | Some(0x1A) | Some(0x53) | Some(0x72)
        ) {
            let (response, _more) = self.chipset.in_data_exchange(data, timeout)?;
            return Ok(response);
        }

        // Other commands cannot be executed on RC-S956
        Err(DriverError::Communication(
            CommunicationError::transmission("tt1 command cannot be sent with this hardware"),
        ))
    }

    fn transceive_type2(&mut self, data: &[u8], timeout: std::time::Duration) -> Result<Vec<u8>> {
        let response = self.chipset.in_communicate_thru(data, timeout)?;

        // Check CRC for responses longer than 2 bytes
        if response.len() > 2 && !crc::check_crc_a(&response) {
            return Err(DriverError::Communication(
                CommunicationError::transmission("crc_a check error"),
            ));
        }

        // Strip CRC if present
        if response.len() > 2 {
            Ok(response[..response.len() - 2].to_vec())
        } else {
            Ok(response)
        }
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

/// Checks if the target is a Type 2 Tag.
fn is_type2_target(target: &RemoteTarget) -> bool {
    target.brty() == "106A"
        && target
            .data
            .sel_res
            .as_ref()
            .and_then(|bytes| bytes.first())
            .map(|b| b & 0x60 == 0x00)
            .unwrap_or(false)
        && target.data.rid_res.is_none()
}
