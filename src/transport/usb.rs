use super::Transport;
use log::debug;
use rusb::Direction;
use std::io::{self, Error, ErrorKind};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(100);

pub struct UsbTransport {
    handle: Option<rusb::DeviceHandle<rusb::GlobalContext>>,
    in_ep: u8,
    out_ep: u8,
    max_packet_size: u16,
    interface: u8,
    manufacturer: Option<String>,
    product: Option<String>,
}

impl UsbTransport {
    pub fn open(vendor_id: u16, product_id: u16) -> io::Result<Self> {
        let handle = rusb::open_device_with_vid_pid(vendor_id, product_id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "USB device not found"))?;

        let device = handle.device();
        let descriptor = device.device_descriptor().map_err(rusb_to_io_error)?;
        let config = device
            .active_config_descriptor()
            .map_err(rusb_to_io_error)?;

        let mut interface_number = None;
        let mut in_ep = None;
        let mut out_ep = None;
        let mut max_packet = 0;

        'outer: for interface_desc in config.interfaces() {
            for descriptor in interface_desc.descriptors() {
                for endpoint in descriptor.endpoint_descriptors() {
                    if endpoint.transfer_type() != rusb::TransferType::Bulk {
                        continue;
                    }
                    match endpoint.direction() {
                        Direction::In if in_ep.is_none() => {
                            in_ep = Some(endpoint.address());
                            max_packet = endpoint.max_packet_size();
                        }
                        Direction::Out if out_ep.is_none() => {
                            out_ep = Some(endpoint.address());
                            if max_packet == 0 {
                                max_packet = endpoint.max_packet_size();
                            }
                        }
                        _ => {}
                    }
                }
                if in_ep.is_some() && out_ep.is_some() {
                    interface_number = Some(descriptor.interface_number());
                    break 'outer;
                }
            }
        }

        let in_ep = in_ep.ok_or_else(|| Error::other("missing bulk IN endpoint"))?;
        let out_ep = out_ep.ok_or_else(|| Error::other("missing bulk OUT endpoint"))?;
        let interface = interface_number.unwrap_or(0);

        let device_handle = handle;
        if device_handle
            .kernel_driver_active(interface)
            .unwrap_or(false)
            && let Err(err) = device_handle.detach_kernel_driver(interface)
        {
            debug!("failed to detach kernel driver: {:?}", err);
        }
        device_handle
            .claim_interface(interface)
            .map_err(rusb_to_io_error)?;

        let manufacturer = descriptor
            .manufacturer_string_index()
            .and_then(|idx| device_handle.read_string_descriptor_ascii(idx).ok());
        let product = descriptor
            .product_string_index()
            .and_then(|idx| device_handle.read_string_descriptor_ascii(idx).ok());

        Ok(Self {
            handle: Some(device_handle),
            in_ep,
            out_ep,
            max_packet_size: max_packet,
            interface,
            manufacturer,
            product,
        })
    }
}

impl Transport for UsbTransport {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let handle = self
            .handle
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::NotConnected, "USB handle closed"))?;
        debug!("USB write {} bytes to ep {:02x}", data.len(), self.out_ep);
        handle
            .write_bulk(self.out_ep, data, DEFAULT_TIMEOUT)
            .map_err(rusb_to_io_error)?;
        if self.max_packet_size > 0 && (data.len() as u16).is_multiple_of(self.max_packet_size) {
            handle
                .write_bulk(self.out_ep, &[], DEFAULT_TIMEOUT)
                .map_err(rusb_to_io_error)?;
        }
        Ok(())
    }

    fn read(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        let handle = self
            .handle
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::NotConnected, "USB handle closed"))?;
        let mut buffer = [0u8; 512];
        let len = match handle.read_bulk(self.in_ep, &mut buffer, timeout) {
            Ok(len) => {
                debug!(
                    "USB read {} bytes from ep {:02x} (timeout {:?})",
                    len, self.in_ep, timeout
                );
                len
            }
            Err(err) => {
                debug!("USB read error: {:?}", err);
                return Err(rusb_to_io_error(err));
            }
        };
        if len == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "USB bulk read returned zero",
            ));
        }
        Ok(buffer[..len].to_vec())
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

impl Drop for UsbTransport {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn rusb_to_io_error(err: rusb::Error) -> io::Error {
    match err {
        rusb::Error::Timeout => Error::new(ErrorKind::TimedOut, err),
        rusb::Error::NoDevice => Error::new(ErrorKind::NotFound, err),
        rusb::Error::Busy => Error::other(err),
        rusb::Error::Access => Error::new(ErrorKind::PermissionDenied, err),
        other => Error::other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_transport() -> UsbTransport {
        UsbTransport {
            handle: None,
            in_ep: 0x81,
            out_ep: 0x02,
            max_packet_size: 64,
            interface: 0,
            manufacturer: Some("Sony".to_string()),
            product: Some("Port-100".to_string()),
        }
    }

    #[test]
    fn rusb_to_io_error_maps_known_error_kinds() {
        assert_eq!(
            rusb_to_io_error(rusb::Error::Timeout).kind(),
            ErrorKind::TimedOut
        );
        assert_eq!(
            rusb_to_io_error(rusb::Error::NoDevice).kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            rusb_to_io_error(rusb::Error::Access).kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(rusb_to_io_error(rusb::Error::Busy).kind(), ErrorKind::Other);
        assert_eq!(
            rusb_to_io_error(rusb::Error::Interrupted).kind(),
            ErrorKind::Other
        );
    }

    #[test]
    fn metadata_accessors_and_close_with_none_handle() {
        let mut transport = dummy_transport();
        assert_eq!(transport.manufacturer_name(), Some("Sony"));
        assert_eq!(transport.product_name(), Some("Port-100"));
        transport.close().expect("close should succeed");
        assert!(transport.handle.is_none());
    }

    #[test]
    fn write_and_read_fail_with_not_connected_when_handle_is_closed() {
        let mut transport = dummy_transport();
        let write_err = transport
            .write(&[0x00])
            .expect_err("write should fail without handle");
        assert_eq!(write_err.kind(), ErrorKind::NotConnected);

        let read_err = transport
            .read(Duration::from_millis(10))
            .expect_err("read should fail without handle");
        assert_eq!(read_err.kind(), ErrorKind::NotConnected);
    }
}
