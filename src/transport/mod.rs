//! Transport layer abstractions for NFC reader communication.
//!
//! This module provides the [`Transport`] trait that abstracts the communication
//! channel between the host and the NFC reader hardware.
//!
//! Currently supported transports:
//! - [`usb`] - USB communication via the `rusb` crate

pub mod usb;

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
