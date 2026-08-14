//! Driver for Sony RC-S956 based contactless devices.
//!
//! This module provides support for NFC readers based on the Sony RC-S956
//! chipset, including the PaSoRi RC-S330, RC-S360, and RC-S370.
//!
//! The RC-S956 has the same hardware architecture as the NXP PN53x family,
//! with a PN512 Contactless Interface Unit (CIU) coupled with an 80C51
//! microcontroller. It uses similar frame structures and commands to the
//! PN53x family, but has a stricter state machine.
//!
//! ## Supported Features
//!
//! - **sense_tta**: Type A Target detection (Type 1 Tags limited to 128 bytes)
//! - **sense_ttb**: Type B Target detection
//! - **sense_ttf**: Type F Target (FeliCa) detection
//! - **sense_dep**: DEP Target activation
//! - **listen_tta**: Type A Target emulation (DEP and Type 2 only)
//! - **listen_dep**: DEP Target mode (passive communication only)
//!
//! ## Unsupported Features
//!
//! - **listen_ttb**: Type B Target emulation
//! - **listen_ttf**: Type F Target emulation

mod chipset;
mod device;
mod discovery;
mod frame;

pub use chipset::Chipset;
pub use device::{Device, init, open_rcs956};
pub use frame::{Frame, FrameType, build_command};

pub use crate::driver::errors::{ChipsetError, CommunicationFault, DriverError, Result};
