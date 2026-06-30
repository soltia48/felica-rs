//! Shared building blocks for the reader drivers.
//!
//! Every driver exposes the same human-readable metadata (vendor, product, and
//! chipset name), opens its USB transport the same way, and implements
//! [`FelicaDriver`](crate::felica_standard::FelicaDriver) by forwarding to its
//! inherent methods. Those concerns live here so each driver only has to supply
//! what is genuinely device-specific.

use crate::clf::targets::RemoteTarget;
use crate::driver::errors::{DriverError, Result};
use crate::transport::usb::UsbTransport;
use std::io::{self, ErrorKind};

/// Sony's USB vendor id, shared by every supported reader.
pub const SONY_VENDOR_ID: u16 = 0x054C;

/// Human-readable identification reported by a reader.
#[derive(Debug, Clone, Default)]
pub struct DeviceMetadata {
    /// USB vendor / manufacturer string, if the transport reports one.
    pub vendor_name: Option<String>,
    /// USB product string, if the transport reports one.
    pub product_name: Option<String>,
    /// Chipset name, including its firmware version where available.
    pub chipset_name: String,
}

/// Metadata accessors shared by every device driver.
///
/// Implementors only need to provide [`DeviceInfo::metadata`]; the named
/// accessors are derived from it.
pub trait DeviceInfo {
    /// Returns the device's [`DeviceMetadata`].
    fn metadata(&self) -> &DeviceMetadata;

    /// Returns the USB vendor / manufacturer name, if known.
    fn vendor_name(&self) -> Option<&str> {
        self.metadata().vendor_name.as_deref()
    }

    /// Returns the USB product name, if known.
    fn product_name(&self) -> Option<&str> {
        self.metadata().product_name.as_deref()
    }

    /// Returns the chipset name (with firmware version where available).
    fn chipset_name(&self) -> &str {
        &self.metadata().chipset_name
    }
}

/// The object-safe capability set shared by every reader the [`Reader`] facade
/// can drive: FeliCa exchange ([`FelicaDriver`]), metadata ([`DeviceInfo`]),
/// orderly shutdown, and downcasting back to the concrete driver for
/// device-specific features.
///
/// [`Reader`]: crate::reader::Reader
/// [`FelicaDriver`]: crate::felica_standard::FelicaDriver
pub trait ReaderDevice:
    crate::felica_standard::FelicaDriver + DeviceInfo + std::any::Any + Send
{
    /// Releases the device and turns off the RF field.
    fn close(&mut self) -> Result<()>;

    /// Returns this device as [`std::any::Any`] so callers can downcast to the
    /// concrete driver type for device-specific functionality.
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

/// Opens the first reachable USB device among `product_ids` for `vendor_id` and
/// hands the transport to `build`.
///
/// Returns the last underlying I/O error if none of the product ids match, or a
/// `NotFound` error tagged with `not_found_msg` if the list was empty.
pub fn open_usb_device<D>(
    vendor_id: u16,
    product_ids: &[u16],
    not_found_msg: &'static str,
    build: impl Fn(UsbTransport) -> Result<D>,
) -> Result<D> {
    let mut last_error: Option<io::Error> = None;
    for &pid in product_ids {
        match UsbTransport::open(vendor_id, pid) {
            Ok(transport) => return build(transport),
            Err(err) => last_error = Some(err),
        }
    }
    Err(DriverError::Io(last_error.unwrap_or_else(|| {
        io::Error::new(ErrorKind::NotFound, not_found_msg)
    })))
}

/// Returns `true` if `target` is a Type 2 Tag: an NFC-A (`106A`) target whose
/// SEL_RES has bits 5..6 clear.
///
/// Drivers that also distinguish Type 1 Tags additionally require
/// `target.data.rid_res` to be absent.
pub fn is_type2_106a(target: &RemoteTarget) -> bool {
    target.bitrate() == "106A"
        && target
            .data
            .sel_res
            .as_ref()
            .and_then(|bytes| bytes.first())
            .map(|b| b & 0x60 == 0x00)
            .unwrap_or(false)
}

/// Implements [`FelicaDriver`](crate::felica_standard::FelicaDriver) and
/// [`ReaderDevice`] for a `Device<T: Transport>` by forwarding to the type's
/// inherent `detect_type_f`, `transceive`, and `close` methods.
macro_rules! impl_reader_device {
    ($ty:ident) => {
        impl<T: $crate::transport::Transport> $crate::felica_standard::FelicaDriver for $ty<T> {
            fn detect_type_f(
                &mut self,
                target: &$crate::clf::targets::RemoteTarget,
                system_code: u16,
                request_code: u8,
                time_slots: u8,
            ) -> $crate::driver::errors::Result<$crate::felica_standard::Type3TagPollingResult>
            {
                $ty::detect_type_f(self, target, system_code, request_code, time_slots)
            }

            fn transceive(
                &mut self,
                target: &$crate::clf::targets::RemoteTarget,
                data: &[u8],
                timeout_ms: Option<u16>,
            ) -> $crate::driver::errors::Result<Vec<u8>> {
                $ty::transceive(self, target, data, timeout_ms)
            }
        }

        impl<T: $crate::transport::Transport + Send + 'static> $crate::driver::common::ReaderDevice
            for $ty<T>
        {
            fn close(&mut self) -> $crate::driver::errors::Result<()> {
                $ty::close(self)
            }

            fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
                self
            }
        }
    };
}

pub(crate) use impl_reader_device;

#[cfg(test)]
mod tests {
    use super::*;

    fn target(bitrate: &str, sel_res: Option<Vec<u8>>) -> RemoteTarget {
        let mut target = RemoteTarget::new(bitrate).expect("target should be created");
        target.data.sel_res = sel_res;
        target
    }

    #[test]
    fn device_info_derives_accessors_from_metadata() {
        struct Dummy(DeviceMetadata);
        impl DeviceInfo for Dummy {
            fn metadata(&self) -> &DeviceMetadata {
                &self.0
            }
        }

        let dummy = Dummy(DeviceMetadata {
            vendor_name: Some("Sony".into()),
            product_name: None,
            chipset_name: "Chip v1.0".into(),
        });
        assert_eq!(dummy.vendor_name(), Some("Sony"));
        assert_eq!(dummy.product_name(), None);
        assert_eq!(dummy.chipset_name(), "Chip v1.0");
    }

    #[test]
    fn is_type2_106a_checks_bitrate_and_sel_res_bits() {
        assert!(is_type2_106a(&target("106A", Some(vec![0x00]))));
        assert!(is_type2_106a(&target("106A", Some(vec![0x1F]))));
        assert!(!is_type2_106a(&target("106A", Some(vec![0x20]))));
        assert!(!is_type2_106a(&target("212F", Some(vec![0x00]))));
        assert!(!is_type2_106a(&target("106A", None)));
    }

    #[test]
    fn open_usb_device_reports_not_found_for_empty_list() {
        let result = open_usb_device(
            SONY_VENDOR_ID,
            &[],
            "nothing here",
            |_: UsbTransport| Ok(()),
        );
        match result {
            Err(DriverError::Io(err)) => {
                assert_eq!(err.kind(), ErrorKind::NotFound);
                assert_eq!(err.to_string(), "nothing here");
            }
            other => panic!("expected NotFound io error, got {other:?}"),
        }
    }
}
