//! # nfc-rs
//!
//! A Rust library for interacting with NFC (Near Field Communication) devices,
//! with support for Sony's NFC Port-100 (RC-S380), Port-400, RC-S320, and
//! RC-S330/RC-S360/RC-S370 PaSoRi readers.
//!
//! ## Features
//!
//! - Support for NFC Port-100 (RC-S380) readers
//! - Support for NFC Port-400 readers
//! - Support for RC-S320 readers
//! - Support for RC-S956 (RC-S330/RC-S360/RC-S370) readers
//! - FeliCa Standard protocol implementation
//! - USB transport layer
//!
//! ## Quick Start
//!
//! ```no_run
//! use nfc_rs::prelude::*;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Open the first available reader
//!     let mut reader = open_reader(ReaderPreference::Auto)?;
//!
//!     println!("Reader: {} - {}",
//!         reader.vendor_name().unwrap_or("Unknown"),
//!         reader.product_name().unwrap_or("Unknown"));
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Module Structure
//!
//! - [`clf`] - Contactless Frontend utilities (CRC, errors, targets)
//! - [`driver`] - Hardware driver implementations for NFC readers
//! - [`felica_standard`] - FeliCa Standard protocol implementation
//! - [`reader`] - High-level reader abstraction
//! - [`transport`] - Transport layer abstractions (USB)
//! - [`prelude`] - Convenient re-exports of common types

pub mod clf;
pub mod driver;
pub mod felica_standard;
pub mod prelude;
pub mod reader;
pub mod transport;

// Re-export error types at crate root
pub use clf::errors::{CommunicationError, UnsupportedTargetError};

// Re-export target types at crate root
pub use clf::targets::{LocalTarget, RemoteTarget, TargetData};

// Re-export reader types at crate root
pub use reader::{Reader, ReaderPreference, open_reader};

// Re-export transport types
pub use transport::usb::UsbTransport;

// Re-export FeliCa Standard types
pub use felica_standard::{
    AuthenticatedContext, BlockListElement, FelicaDriver, FelicaStandard, FelicaStandardError,
    MutualAuthenticationResult, SearchServiceCodeResult, ServiceCode,
};

// Re-export driver modules and key types
pub use driver::port100::{self, Chipset, Device, init as init_port100, open_port100_device};
pub use driver::port400::{
    self, Device as Port400Device, init as init_port400, open_port400_device,
};
pub use driver::rcs320::{
    self as rcs320, Device as Rcs320Device, Rcs320Transport, init as init_rcs320,
    open_rcs320_device,
};
pub use driver::rcs956::{
    self as rcs956, Device as Rcs956Device, init as init_rcs956, open_rcs956_device,
};
pub use driver::remote::{self, RemoteDriver, RemoteRequest, RemoteResponse, RemoteResponseData};
