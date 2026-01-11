//! NFC reader driver implementations.
//!
//! This module provides hardware drivers for supported NFC readers:
//!
//! - [`port100`] - Driver for Sony NFC Port-100 (RC-S380) readers
//! - [`port400`] - Driver for Sony NFC Port-400 readers
//! - [`rcs320`] - Driver for Sony RC-S320 PaSoRi readers
//! - [`rcs956`] - Driver for Sony RC-S956 (RC-S330/RC-S360/RC-S370) readers
//! - [`remote`] - Driver for remote NFC access over TCP
//!
//! All drivers implement the [`crate::felica_standard::FelicaDriver`] trait,
//! allowing them to be used interchangeably for FeliCa card operations.

pub mod errors;
pub mod port100;
pub mod port400;
pub mod rcs320;
pub mod rcs956;
pub mod remote;

pub use errors::*;
