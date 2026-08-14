//! NFC reader driver implementations.
//!
//! This module provides hardware drivers for supported NFC readers:
//!
//! - [`port100`] - Driver for Sony NFC Port-100 (RC-S380) readers
//! - [`port400`] - Driver for Sony NFC Port-400 readers
//! - [`rcs320`] - Driver for Sony RC-S320 readers
//! - [`rcs956`] - Driver for Sony RC-S956 (RC-S330/RC-S360/RC-S370) readers
//! - [`remote`] - Driver for remote NFC access over TCP
//!
//! All drivers implement the [`crate::felica_standard::FelicaDriver`] trait,
//! allowing them to be used interchangeably for FeliCa card operations.
//!
//! What the drivers have in common lives beside them rather than inside any one
//! of them: [`framing`] holds the SOF frame envelope the Port-100, RC-S320 and
//! RC-S956 all speak, the crate-internal `io` module the buffered reads and
//! error recovery every driver performs on its transport, and `common` the
//! metadata, USB opening and `FelicaDriver` forwarding they each need.

#[cfg(feature = "usb")]
pub(crate) mod common;
pub mod errors;
// The SOF frame envelope is shared by three drivers, and each of them
// re-exports a `Frame` aliased to it, so it has to be nameable from outside.
#[cfg(feature = "usb")]
pub mod framing;
#[cfg(feature = "usb")]
pub(crate) mod io;
#[cfg(feature = "usb")]
pub mod port100;
#[cfg(feature = "usb")]
pub mod port400;
#[cfg(feature = "usb")]
pub mod rcs320;
#[cfg(feature = "usb")]
pub mod rcs956;
// The TCP remote driver is hardware-independent (no `rusb`), so it stays
// available even when the `usb` feature is disabled.
pub mod remote;
// Only the USB drivers are exercised with these doubles; without that feature
// they would be dead code.
#[cfg(all(test, feature = "usb"))]
pub(crate) mod testing;

pub use errors::*;
