//! FeliCa Standard protocol implementation.
//!
//! This module provides a complete implementation of the FeliCa Standard protocol
//! for communicating with FeliCa cards (Type 3 NFC tags).
//!
//! ## Key Types
//!
//! - [`FelicaStandard`] - Main interface for FeliCa card operations
//! - [`FelicaDriver`] - Trait implemented by NFC reader drivers
//! - [`ServiceCode`] - FeliCa service code representation
//! - [`BlockListElement`] - Block list element for read/write operations
//!
//! ## Example
//!
//! ```no_run
//! use nfc_rs::prelude::*;
//!
//! fn read_card(reader: &mut Reader) -> Result<(), FelicaStandardError> {
//!     // Poll for a FeliCa card with any system code
//!     let (mut felica, polling) = FelicaStandard::polling(
//!         reader.driver_mut(), "212F", 0xFFFF, 0x00, 0x00
//!     )?;
//!     
//!     println!("Found card with IDm: {:02X?}", felica.idm());
//!     Ok(())
//! }
//! ```

mod api;
mod command;
mod constants;
mod emulator;
mod error;
mod response;
mod secure;
mod type3;
mod types;

pub use api::{FelicaDriver, FelicaStandard};
pub use command::FelicaStandardCommand;
pub use emulator::{
    DirectoryEntry, EmulatedArea, EmulatedService, EmulatedSystem, EmulatorConfigError,
    FelicaStandardEmulator,
};
pub use error::FelicaStandardError;
pub use response::FelicaStandardResponse;
pub use secure::{AuthenticatedContext, Authentication2Response, generate_service_keys};
pub use type3::Type3TagPollingResult;
pub use types::{
    AreaCodeRange, BlockListElement, ChangeKeyParameters, ContainerInformation, ContainerProperty,
    GetAreaInformationResult, GetNodePropertyResult, MutualAuthenticationResult, NodeProperty,
    NodePropertyType, ReadResult, ReadWithoutEncryptionResult, RegisterIssueIdResult,
    RegisterServiceResult, RequestBlockInformationExResult, RequestCodeListResult,
    RequestServiceV2KeyVersion, RequestServiceV2Result, SearchServiceCodeResult, ServiceCode,
    SetParameterEncryptionType, SetParameterPacketType, StatusFlag1, StatusFlag2,
    status_flag_description,
};

pub(crate) use command::frame_with_length_prefix;
pub(crate) use constants::*;
