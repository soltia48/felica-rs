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

#[cfg(feature = "usb")]
pub(crate) mod common;
pub mod errors;
#[cfg(feature = "usb")]
pub(crate) mod framing;
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

pub use errors::*;
