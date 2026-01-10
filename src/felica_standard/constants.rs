//! FeliCa Standard protocol constants.

/// Length of the IDm (Identifier) field.
pub const IDM_LEN: usize = 8;

/// Maximum number of service codes in a single request.
pub const MAX_SERVICE_CODES: usize = 0x20;

/// Maximum number of service codes for read/write operations.
pub const MAX_RW_SERVICE_CODES: usize = 0x10;

/// Maximum length of the block list.
pub const MAX_BLOCK_LIST_LEN: usize = 0xFF;

/// Maximum number of node codes in a single request.
pub const MAX_NODE_CODES: usize = 0x20;

/// Size of a single data block in bytes.
pub const BLOCK_SIZE: usize = 16;

/// DES block size in bytes.
pub const DES_BLOCK_SIZE: usize = 8;

// Command codes
/// Read Without Encryption command code.
pub const READ_COMMAND_CODE: u8 = 0x14;

/// Write Without Encryption command code.
pub const WRITE_COMMAND_CODE: u8 = 0x16;

/// Register Issue ID command code.
pub const REGISTER_ISSUE_ID_COMMAND_CODE: u8 = 0x80;

/// Register Area command code.
pub const REGISTER_AREA_COMMAND_CODE: u8 = 0x82;

/// Register Service command code.
pub const REGISTER_SERVICE_COMMAND_CODE: u8 = 0x84;

/// Change System Block command code.
pub const CHANGE_SYSTEM_BLOCK_COMMAND_CODE: u8 = 0x8E;
