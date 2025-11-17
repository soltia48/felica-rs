mod api;
mod command;
mod error;
mod response;
mod secure;
mod type3;
mod types;

pub use api::{FelicaDriver, FelicaStandard};
pub use command::FelicaStandardCommand;
pub use error::FelicaStandardError;
pub use response::FelicaStandardResponse;
pub use secure::{AuthenticatedContext, Authentication2Response, generate_service_keys};
pub use type3::Type3TagPollingResult;
pub use types::{
    BlockListElement, ChangeKeyParameters, MutualAuthenticationResult, RequestServiceV2KeyVersion,
    SearchServiceCodeResult, ServiceCode,
};

pub(crate) use command::frame_with_length_prefix;

pub(crate) const IDM_LEN: usize = 8;
pub(crate) const MAX_SERVICE_CODES: usize = 0x20;
pub(crate) const MAX_RW_SERVICE_CODES: usize = 0x10;
pub(crate) const MAX_BLOCK_LIST_LEN: usize = 0xFF;
pub(crate) const MAX_NODE_CODES: usize = 0x20;
pub(crate) const BLOCK_SIZE: usize = 16;
pub(crate) const DES_BLOCK_SIZE: usize = 8;
pub(crate) const READ_COMMAND_CODE: u8 = 0x14;
pub(crate) const WRITE_COMMAND_CODE: u8 = 0x16;
pub(crate) const REGISTER_ISSUE_ID_COMMAND_CODE: u8 = 0x80;
pub(crate) const REGISTER_AREA_COMMAND_CODE: u8 = 0x82;
pub(crate) const REGISTER_SERVICE_COMMAND_CODE: u8 = 0x84;
pub(crate) const COMMIT_REGISTRATION_COMMAND_CODE: u8 = 0x8E;
