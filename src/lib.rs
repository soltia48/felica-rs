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

// ---- Errors (low-level → high-level) ----
pub use clf::errors::{CommunicationError, UnsupportedTargetError};
pub use driver::errors::{ChipsetError, CommunicationFault, DriverError};
pub use felica_standard::FelicaStandardError;

// ---- Targets ----
pub use clf::targets::{LocalTarget, RemoteTarget, TargetData};

// ---- Transport ----
pub use transport::Transport;
pub use transport::usb::UsbTransport;

// ---- Reader facade ----
pub use driver::common::{DeviceInfo, DeviceMetadata, ReaderDevice};
pub use reader::{
    Port100Device, Port400Device, Rcs320Device, Rcs956Device, Reader, ReaderPreference, open_reader,
};

// ---- Concrete driver entry points ----
// `open_X` opens the default USB reader; `init_X` builds a driver from a custom
// transport. The generic `Device<T>` / `Chipset<T>` types live under their
// `driver::*` modules for advanced use.
pub use driver::port100::{init as init_port100, open_port100};
pub use driver::port400::{init as init_port400, open_port400};
pub use driver::rcs320::{Rcs320Transport, init as init_rcs320, open_rcs320};
pub use driver::rcs956::{init as init_rcs956, open_rcs956};

// ---- Remote driver ----
pub use driver::remote::{RemoteDriver, RemoteRequest, RemoteResponse, RemoteResponseData};

// ---- FeliCa Standard protocol ----
pub use felica_standard::{
    AuthenticatedContext, BlockListElement, FelicaDriver, FelicaStandard,
    MutualAuthenticationResult, SearchServiceCodeResult, ServiceCode,
};
