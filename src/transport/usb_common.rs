//! Shared USB connection setup for the reader transports.
//!
//! Both the bulk-transfer [`UsbTransport`](super::usb::UsbTransport) and the
//! control/interrupt [`Rcs320Transport`](crate::driver::rcs320::Rcs320Transport)
//! open their device the same way: locate it by vendor/product id, read the
//! configuration descriptor, detach any kernel driver, select the active
//! configuration, and claim the interface. Only the *endpoint selection* and the
//! read/write path genuinely differ between them.
//!
//! Keeping that setup in one place means platform quirks (such as the macOS
//! Address-state handling below) are fixed once for every reader rather than
//! being copied — and drifting — across transports.

use log::debug;
use rusb::{ConfigDescriptor, DeviceHandle, GlobalContext};
use std::io::{self, Error, ErrorKind};

/// A device that has been opened, configured, and had its interface claimed by
/// [`open_usb_interface`].
///
/// The `endpoints` field carries whatever the caller's selector extracted from
/// the configuration descriptor (e.g. bulk IN/OUT endpoints, or a single
/// interrupt IN endpoint).
pub struct UsbConnection<E> {
    /// The claimed device handle.
    pub handle: DeviceHandle<GlobalContext>,
    /// The claimed interface number.
    pub interface: u8,
    /// USB manufacturer string, if the device reports one.
    pub manufacturer: Option<String>,
    /// USB product string, if the device reports one.
    pub product: Option<String>,
    /// Endpoint information selected by the caller.
    pub endpoints: E,
}

/// Opens the USB device identified by `vendor_id`/`product_id`, prepares it for
/// I/O, and claims its interface.
///
/// The `select_endpoints` closure inspects the (first) configuration descriptor
/// and returns the interface number to claim together with any endpoint data the
/// caller needs. This is the only device-specific part of opening a reader; the
/// surrounding setup is identical for every USB transport.
pub fn open_usb_interface<E>(
    vendor_id: u16,
    product_id: u16,
    not_found_msg: &'static str,
    select_endpoints: impl FnOnce(&ConfigDescriptor) -> io::Result<(u8, E)>,
) -> io::Result<UsbConnection<E>> {
    let handle = rusb::open_device_with_vid_pid(vendor_id, product_id)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, not_found_msg))?;

    let device = handle.device();
    let descriptor = device.device_descriptor().map_err(rusb_to_io_error)?;
    // Read the configuration descriptor by index rather than
    // active_config_descriptor(): on macOS a freshly opened device with no bound
    // driver is left in the Address state (no active configuration yet), so
    // active_config_descriptor() spuriously fails with NotFound.
    let config = device.config_descriptor(0).map_err(rusb_to_io_error)?;

    let (interface, endpoints) = select_endpoints(&config)?;

    if handle.kernel_driver_active(interface).unwrap_or(false)
        && let Err(err) = handle.detach_kernel_driver(interface)
    {
        debug!("failed to detach kernel driver: {:?}", err);
    }

    // Some platforms (notably macOS) leave a freshly opened device in the Address
    // state rather than auto-selecting the sole configuration, which makes
    // claim_interface fail with NotFound until we set it explicitly.
    //
    // Only set it when the device is not already in the desired configuration.
    // Calling libusb_set_configuration() with the value that is already active is
    // not a no-op: libusb re-issues SET_CONFIGURATION, which acts as a lightweight
    // device reset (endpoint toggles/halts reset, altsetting cleared). On Linux
    // the kernel already configures the device at enumeration, so an unconditional
    // call reset the RC-S380 right before the ACK handshake and intermittently
    // corrupted it ("invalid ack frame").
    let needs_configuration = match handle.active_configuration() {
        Ok(active) => active != config.number(),
        // Could not determine the current configuration; fall back to setting it
        // (this is the macOS Address-state path).
        Err(err) => {
            debug!("failed to read active configuration: {:?}", err);
            true
        }
    };
    if needs_configuration && let Err(err) = handle.set_active_configuration(config.number()) {
        debug!("failed to set active configuration: {:?}", err);
    }

    handle
        .claim_interface(interface)
        .map_err(rusb_to_io_error)?;

    let manufacturer = descriptor
        .manufacturer_string_index()
        .and_then(|idx| handle.read_string_descriptor_ascii(idx).ok());
    let product = descriptor
        .product_string_index()
        .and_then(|idx| handle.read_string_descriptor_ascii(idx).ok());

    Ok(UsbConnection {
        handle,
        interface,
        manufacturer,
        product,
        endpoints,
    })
}

/// Maps a [`rusb::Error`] onto the closest [`io::Error`] kind.
pub fn rusb_to_io_error(err: rusb::Error) -> io::Error {
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
        assert_eq!(rusb_to_io_error(rusb::Error::Pipe).kind(), ErrorKind::Other);
    }
}
