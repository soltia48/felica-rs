//! Transport layer abstractions for NFC reader communication.
//!
//! This module provides the [`Transport`] trait that abstracts the communication
//! channel between the host and the NFC reader hardware.
//!
//! Currently supported transports:
//! - [`usb`] - USB communication via the `rusb` crate
//!
//! Setup shared by every USB-based transport (opening the device, claiming the
//! interface, mapping `rusb` errors) lives in [`usb_common`].

#[cfg(feature = "usb")]
pub mod usb;
#[cfg(feature = "usb")]
pub(crate) mod usb_common;

use std::time::Duration;

/// Trait for transport layer implementations.
///
/// Implementors of this trait provide the low-level communication channel
/// to the NFC reader hardware.
pub trait Transport {
    fn write(&mut self, data: &[u8]) -> std::io::Result<()>;
    fn read(&mut self, timeout: Duration) -> std::io::Result<Vec<u8>>;
    fn close(&mut self) -> std::io::Result<()>;

    fn manufacturer_name(&self) -> Option<&str> {
        None
    }

    fn product_name(&self) -> Option<&str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct DummyTransport;

    impl Transport for DummyTransport {
        fn write(&mut self, _data: &[u8]) -> std::io::Result<()> {
            Ok(())
        }

        fn read(&mut self, _timeout: Duration) -> std::io::Result<Vec<u8>> {
            Ok(Vec::new())
        }

        fn close(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn default_metadata_methods_return_none() {
        let transport = DummyTransport;
        assert_eq!(transport.manufacturer_name(), None);
        assert_eq!(transport.product_name(), None);
    }
}
