//! USB transport for RC-S320.
//!
//! The RC-S320 uses a different USB communication method than the newer readers:
//! - Send: USB control transfer (vendor request)
//! - Receive: USB interrupt transfer
//!
//! This differs from RC-S330 and later which use bulk transfers for both.

use crate::transport::Transport;
use crate::transport::usb_common::{open_usb_interface, rusb_to_io_error};
use log::debug;
use rusb::Direction;
use std::io::{self, Error, ErrorKind};
use std::time::Duration;

/// Sony USB Vendor ID.
pub const SONY_VID: u16 = 0x054C;

/// RC-S320 USB Product ID.
pub const RCS320_PID: u16 = 0x01BB;

/// Default timeout for USB operations.
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);

/// USB transport for RC-S320 using control and interrupt transfers.
pub struct Rcs320Transport {
    handle: Option<rusb::DeviceHandle<rusb::GlobalContext>>,
    interrupt_ep_in: u8,
    interface: u8,
    manufacturer: Option<String>,
    product: Option<String>,
    timeout: Duration,
}

/// Selects the first interrupt IN endpoint, returning its owning interface and
/// address. The RC-S320 receives responses over this endpoint.
fn select_interrupt_in_endpoint(config: &rusb::ConfigDescriptor) -> io::Result<(u8, u8)> {
    for interface_desc in config.interfaces() {
        for descriptor in interface_desc.descriptors() {
            for endpoint in descriptor.endpoint_descriptors() {
                if endpoint.transfer_type() == rusb::TransferType::Interrupt
                    && endpoint.direction() == Direction::In
                {
                    return Ok((descriptor.interface_number(), endpoint.address()));
                }
            }
        }
    }
    Err(Error::other("missing interrupt IN endpoint"))
}

impl Rcs320Transport {
    /// Opens an RC-S320 device.
    pub fn open() -> io::Result<Self> {
        Self::open_with_ids(SONY_VID, RCS320_PID)
    }

    /// Opens a device with the specified vendor and product IDs.
    pub fn open_with_ids(vendor_id: u16, product_id: u16) -> io::Result<Self> {
        let connection = open_usb_interface(
            vendor_id,
            product_id,
            "RC-S320 device not found",
            select_interrupt_in_endpoint,
        )?;
        let interrupt_ep_in = connection.endpoints;

        debug!(
            "opened RC-S320: interrupt_ep_in=0x{:02X}, interface={}, manufacturer={:?}, product={:?}",
            interrupt_ep_in, connection.interface, connection.manufacturer, connection.product
        );

        Ok(Self {
            handle: Some(connection.handle),
            interrupt_ep_in,
            interface: connection.interface,
            manufacturer: connection.manufacturer,
            product: connection.product,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Sets the timeout for USB operations.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Sends data using USB control transfer.
    ///
    /// The RC-S320 uses vendor-specific control transfers for sending commands.
    pub fn control_send(&mut self, data: &[u8]) -> io::Result<usize> {
        let handle = self
            .handle
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::NotConnected, "USB handle closed"))?;

        debug!("RC-S320 control send {} bytes: {:02X?}", data.len(), data);

        // USB_TYPE_VENDOR | USB_ENDPOINT_OUT = 0x40
        let request_type = rusb::request_type(
            rusb::Direction::Out,
            rusb::RequestType::Vendor,
            rusb::Recipient::Device,
        );

        let len = handle
            .write_control(request_type, 0, 0, 0, data, self.timeout)
            .map_err(rusb_to_io_error)?;

        Ok(len)
    }

    /// Receives data using USB interrupt transfer.
    pub fn interrupt_recv(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        let handle = self
            .handle
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::NotConnected, "USB handle closed"))?;

        let mut buffer = [0u8; 256];
        let len = handle
            .read_interrupt(self.interrupt_ep_in, &mut buffer, timeout)
            .map_err(rusb_to_io_error)?;

        debug!(
            "RC-S320 interrupt recv {} bytes: {:02X?}",
            len,
            &buffer[..len]
        );

        if len == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "USB interrupt read returned zero",
            ));
        }

        Ok(buffer[..len].to_vec())
    }
}

impl Transport for Rcs320Transport {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.control_send(data)?;
        Ok(())
    }

    fn read(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        self.interrupt_recv(timeout)
    }

    fn close(&mut self) -> io::Result<()> {
        if let Some(handle) = self.handle.take() {
            let _ = handle.release_interface(self.interface);
        }
        Ok(())
    }

    fn manufacturer_name(&self) -> Option<&str> {
        self.manufacturer.as_deref()
    }

    fn product_name(&self) -> Option<&str> {
        self.product.as_deref()
    }
}

impl Drop for Rcs320Transport {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_transport() -> Rcs320Transport {
        Rcs320Transport {
            handle: None,
            interrupt_ep_in: 0x81,
            interface: 0,
            manufacturer: Some("Sony".to_string()),
            product: Some("RC-S320".to_string()),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    #[test]
    fn set_timeout_and_metadata_accessors_work() {
        let mut transport = dummy_transport();
        transport.set_timeout(Duration::from_millis(250));
        assert_eq!(transport.timeout, Duration::from_millis(250));
        assert_eq!(transport.manufacturer_name(), Some("Sony"));
        assert_eq!(transport.product_name(), Some("RC-S320"));
    }

    #[test]
    fn control_send_and_interrupt_recv_fail_when_handle_is_closed() {
        let mut transport = dummy_transport();
        let send_err = transport
            .control_send(&[0x00])
            .expect_err("closed handle should fail control_send");
        assert_eq!(send_err.kind(), ErrorKind::NotConnected);

        let recv_err = transport
            .interrupt_recv(Duration::from_millis(10))
            .expect_err("closed handle should fail interrupt_recv");
        assert_eq!(recv_err.kind(), ErrorKind::NotConnected);
    }

    #[test]
    fn close_is_noop_when_handle_already_none() {
        let mut transport = dummy_transport();
        transport.close().expect("close should succeed");
        assert!(transport.handle.is_none());
    }
}
