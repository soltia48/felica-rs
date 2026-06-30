//! Convenience re-exports for common types and traits.
//!
//! This module provides a convenient way to import commonly used types
//! from the nfc-rs library with a single `use` statement:
//!
//! ```
//! use nfc_rs::prelude::*;
//! ```
//!
//! ## Included Types
//!
//! - Error types: [`CommunicationError`], [`UnsupportedTargetError`], [`DriverError`], [`FelicaStandardError`]
//! - Target types: [`LocalTarget`], [`RemoteTarget`], [`TargetData`]
//! - Reader types: [`Reader`], [`ReaderPreference`], [`open_reader`]
//! - FeliCa types: [`FelicaStandard`], [`FelicaDriver`], [`ServiceCode`], [`BlockListElement`]
//! - Transport trait: [`Transport`]

// Error types
pub use crate::clf::errors::{CommunicationError, UnsupportedTargetError};
pub use crate::driver::errors::{
    ChipsetError, CommunicationFault, DriverError, Result as DriverResult,
};
pub use crate::felica_standard::FelicaStandardError;

// Target types
pub use crate::clf::targets::{LocalTarget, RemoteTarget, TargetData};

// Reader types
pub use crate::driver::common::{DeviceInfo, ReaderDevice};
pub use crate::reader::{Reader, ReaderPreference, open_reader};

// FeliCa Standard types
pub use crate::felica_standard::{
    AuthenticatedContext, BlockListElement, FelicaDriver, FelicaStandard,
    MutualAuthenticationResult, ServiceCode,
};

// Transport trait
pub use crate::transport::Transport;
