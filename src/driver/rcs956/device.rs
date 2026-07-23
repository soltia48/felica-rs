//! RC-S956 device driver implementation.
//!
//! This module provides the high-level device interface for RC-S956 based readers.

use crate::clf::crc;
use crate::clf::errors::CommunicationError;
use crate::clf::targets::RemoteTarget;
use crate::driver::common::{self, DeviceInfo, DeviceMetadata, impl_reader_device, is_type2_106a};
use crate::driver::errors::{DriverError, Result};
use crate::driver::rcs956::chipset::Chipset;
use crate::transport::Transport;
use crate::transport::usb::UsbTransport;
use hex::encode;
use log::debug;

/// RC-S956 device driver.
pub struct Device<T: Transport> {
    pub(crate) chipset: Chipset<T>,
    meta: DeviceMetadata,
}

/// Initializes an RC-S956 device with the given transport.
pub fn init<T: Transport>(transport: T) -> Result<Device<T>> {
    let chipset = Chipset::new(transport)?;
    Device::new(chipset)
}

/// Opens an RC-S956 device (RC-S330/RC-S360/RC-S370).
pub fn open_rcs956() -> Result<Device<UsbTransport>> {
    // RC-S330: 0x02E1, RC-S360/RC-S370: 0x02E1, 0x0193
    // Note: 0x01BB is RC-S320, which uses a different protocol.
    const PRODUCT_IDS: [u16; 2] = [0x02E1, 0x0193];
    common::open_usb_device(
        common::SONY_VENDOR_ID,
        &PRODUCT_IDS,
        "RC-S956 reader not found",
        init,
    )
}

impl<T: Transport> Device<T> {
    /// Creates a new device with the given chipset.
    pub fn new(mut chipset: Chipset<T>) -> Result<Self> {
        // Reset the state machine to Mode 0 first (as per nfcpy)
        chipset.reset_mode()?;

        // Initialize chipset (gets firmware version)
        chipset.initialize()?;

        let version = chipset.firmware_version();
        let meta = DeviceMetadata {
            vendor_name: chipset.manufacturer_name().map(|s| s.to_string()),
            product_name: chipset.product_name().map(|s| s.to_string()),
            chipset_name: format!("RCS956v{:x}.{:x}", version.1, version.2),
        };

        debug!("chipset is a {}", meta.chipset_name);

        // Mute (turn off RF field)
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
        // RF settings in RAM-07 are used for initial target state
        chipset.write_single_register(0x0328, 0x59)?;

        Ok(Self { chipset, meta })
    }

    /// Returns a mutable reference to the chipset.
    pub fn chipset(&mut self) -> &mut Chipset<T> {
        &mut self.chipset
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
        debug!(
            "RC-S956 transceive TX ({}): {}",
            target.bitrate(),
            encode(data)
        );
        let timeout = std::time::Duration::from_millis(timeout_ms.unwrap_or(1000) as u64 + 100);

        // Handle Type 2 Tag (need CRC check since firmware reports CRC errors for ACK/NAK)
        let response = if is_type2_target(target) {
            self.transceive_type2(data, timeout)?
        } else if target.data.rid_res.is_some() {
            // Handle Type 1 Tag
            self.transceive_type1(data, timeout)?
        } else {
            // Standard communication
            self.chipset.in_communicate_thru(data, timeout)?
        };
        debug!(
            "RC-S956 transceive RX ({}): {}",
            target.bitrate(),
            encode(&response)
        );
        Ok(response)
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

impl<T: Transport> DeviceInfo for Device<T> {
    fn metadata(&self) -> &DeviceMetadata {
        &self.meta
    }
}

impl_reader_device!(Device);

/// Checks if the target is a Type 2 Tag.
///
/// Unlike the shared [`is_type2_106a`] helper, the RC-S956 additionally
/// requires the target to not be a Type 1 Tag (no RID response).
fn is_type2_target(target: &RemoteTarget) -> bool {
    is_type2_106a(target) && target.data.rid_res.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target(
        bitrate: &str,
        sel_res: Option<Vec<u8>>,
        rid_res: Option<Vec<u8>>,
    ) -> RemoteTarget {
        let mut target = RemoteTarget::new(bitrate).expect("target should be created");
        target.data.sel_res = sel_res;
        target.data.rid_res = rid_res;
        target
    }

    #[test]
    fn is_type2_target_requires_106a_and_type2_sel_res_without_rid() {
        let type2 = make_target("106A", Some(vec![0x00]), None);
        assert!(is_type2_target(&type2));

        let type4_like = make_target("106A", Some(vec![0x20]), None);
        assert!(!is_type2_target(&type4_like));

        let wrong_bitrate = make_target("212F", Some(vec![0x00]), None);
        assert!(!is_type2_target(&wrong_bitrate));

        let no_sel = make_target("106A", None, None);
        assert!(!is_type2_target(&no_sel));

        let type1 = make_target("106A", Some(vec![0x00]), Some(vec![0x11]));
        assert!(!is_type2_target(&type1));
    }
}
