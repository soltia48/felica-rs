//! NFC reader driver implementations.
//!
//! This module provides hardware drivers for supported NFC readers:
//!
//! - [`port100`] - Driver for Sony NFC Port-100 (RC-S380) readers
//! - [`port400`] - Driver for Sony NFC Port-400 readers
//! - [`remote`] - Driver for remote NFC access over TCP
//!
//! All drivers implement the [`crate::felica_standard::FelicaDriver`] trait,
//! allowing them to be used interchangeably for FeliCa card operations.

pub mod errors;
pub mod port100;
pub mod port400;
pub mod remote;

pub use errors::*;
