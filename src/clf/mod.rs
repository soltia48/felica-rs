//! Contactless Frontend (CLF) utilities.
//!
//! This module provides common utilities for NFC contactless communication:
//! - CRC calculation for NFC-A and NFC-B protocols
//! - Error types for communication and target handling
//! - Target definitions for remote and local NFC targets

pub mod crc;
pub mod errors;
pub mod targets;

pub use crc::{add_crc_a, add_crc_b, check_crc_a, check_crc_b};
