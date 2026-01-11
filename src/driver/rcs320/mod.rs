//! Driver for Sony RC-S320 PaSoRi contactless reader.
//!
//! This module provides support for the Sony RC-S320 PaSoRi reader,
//! which is an older generation USB contactless card reader.
//!
//! The RC-S320 uses a different communication protocol from the newer
//! RC-S956 based readers (RC-S330 and later). It uses USB control transfers
//! for sending commands and interrupt transfers for receiving responses.
//!
//! ## Supported Features
//!
//! - **sense_ttf**: Type F Target (FeliCa) detection at 212kbps and 424kbps
//! - **transceive**: Send/receive FeliCa commands
//!
//! ## Protocol Notes
//!
//! The RC-S320 frame format:
//! ```text
//! [PREAMBLE][START][LEN][LCS][DATA...][DCS][POSTAMBLE]
//! ```
//! Where:
//! - PREAMBLE: 0x00
//! - START: 0x00 0xFF
//! - LEN: Data length (1 byte)
//! - LCS: Length checksum (256 - LEN) & 0xFF
//! - DATA: Command/response data
//! - DCS: Data checksum (256 - sum(DATA)) & 0xFF
//! - POSTAMBLE: 0x00

mod chipset;
mod device;
mod frame;
mod transport;

pub use chipset::Chipset;
pub use device::{Device, init, open_rcs320_device};
pub use frame::{Frame, FrameType};
pub use transport::Rcs320Transport;

pub use crate::driver::errors::{CommunicationFault, DriverError, Result, StatusError};
