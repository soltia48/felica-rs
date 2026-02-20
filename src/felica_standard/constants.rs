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

/// Maximum number of node codes in a Get Node Property request.
pub const MAX_NODE_PROPERTY_CODES: usize = 0x10;

/// Size of a single data block in bytes.
pub const BLOCK_SIZE: usize = 16;

/// DES block size in bytes.
pub const DES_BLOCK_SIZE: usize = 8;

// Standard command codes
/// Polling command code.
pub const POLLING_COMMAND_CODE: u8 = 0x00;

/// Request Service command code.
pub const REQUEST_SERVICE_COMMAND_CODE: u8 = 0x02;

/// Request Response command code.
pub const REQUEST_RESPONSE_COMMAND_CODE: u8 = 0x04;

/// Read Without Encryption command code.
pub const READ_WITHOUT_ENCRYPTION_COMMAND_CODE: u8 = 0x06;

/// Write Without Encryption command code.
pub const WRITE_WITHOUT_ENCRYPTION_COMMAND_CODE: u8 = 0x08;

/// Search Service Code command code.
pub const SEARCH_SERVICE_CODE_COMMAND_CODE: u8 = 0x0A;

/// Request System Code command code.
pub const REQUEST_SYSTEM_CODE_COMMAND_CODE: u8 = 0x0C;

/// Request Block Information command code.
pub const REQUEST_BLOCK_INFORMATION_COMMAND_CODE: u8 = 0x0E;

/// Authentication1 command code.
pub const AUTHENTICATION1_COMMAND_CODE: u8 = 0x10;

/// Authentication2 command code.
pub const AUTHENTICATION2_COMMAND_CODE: u8 = 0x12;

/// Request Code List command code.
pub const REQUEST_CODE_LIST_COMMAND_CODE: u8 = 0x1A;

/// Request Block Information Ex command code.
pub const REQUEST_BLOCK_INFORMATION_EX_COMMAND_CODE: u8 = 0x1E;

/// Set Parameter command code.
pub const SET_PARAMETER_COMMAND_CODE: u8 = 0x20;

/// Get Container Issue Information command code.
pub const GET_CONTAINER_ISSUE_INFORMATION_COMMAND_CODE: u8 = 0x22;

/// Get Area Information command code.
pub const GET_AREA_INFORMATION_COMMAND_CODE: u8 = 0x24;

/// Get Node Property command code.
pub const GET_NODE_PROPERTY_COMMAND_CODE: u8 = 0x28;

/// Get Container Property command code.
pub const GET_CONTAINER_PROPERTY_COMMAND_CODE: u8 = 0x2E;

/// Request Service V2 command code.
pub const REQUEST_SERVICE_V2_COMMAND_CODE: u8 = 0x32;

/// Get System Status command code.
pub const GET_SYSTEM_STATUS_COMMAND_CODE: u8 = 0x38;

/// Get Platform Information command code.
pub const GET_PLATFORM_INFORMATION_COMMAND_CODE: u8 = 0x3A;

/// Request Specification Version command code.
pub const REQUEST_SPECIFICATION_VERSION_COMMAND_CODE: u8 = 0x3C;

/// Reset Mode command code.
pub const RESET_MODE_COMMAND_CODE: u8 = 0x3E;

/// Authentication1 V2 command code.
pub const AUTHENTICATION1_V2_COMMAND_CODE: u8 = 0x40;

/// Authentication2 V2 command code.
pub const AUTHENTICATION2_V2_COMMAND_CODE: u8 = 0x42;

/// Get Container ID command code.
pub const GET_CONTAINER_ID_COMMAND_CODE: u8 = 0x70;

// Secure command codes
/// Read command code.
pub const READ_COMMAND_CODE: u8 = 0x14;

/// Write command code.
pub const WRITE_COMMAND_CODE: u8 = 0x16;

/// Register Issue ID command code.
pub const REGISTER_ISSUE_ID_COMMAND_CODE: u8 = 0x80;

/// Register Area command code.
pub const REGISTER_AREA_COMMAND_CODE: u8 = 0x82;

/// Register Service command code.
pub const REGISTER_SERVICE_COMMAND_CODE: u8 = 0x84;

/// Change System Block command code.
pub const CHANGE_SYSTEM_BLOCK_COMMAND_CODE: u8 = 0x8E;

// Standard response codes
/// Polling response code.
pub const POLLING_RESPONSE_CODE: u8 = 0x01;

/// Request Service response code.
pub const REQUEST_SERVICE_RESPONSE_CODE: u8 = 0x03;

/// Request Response response code.
pub const REQUEST_RESPONSE_RESPONSE_CODE: u8 = 0x05;

/// Read Without Encryption response code.
pub const READ_WITHOUT_ENCRYPTION_RESPONSE_CODE: u8 = 0x07;

/// Write Without Encryption response code.
pub const WRITE_WITHOUT_ENCRYPTION_RESPONSE_CODE: u8 = 0x09;

/// Search Service Code response code.
pub const SEARCH_SERVICE_CODE_RESPONSE_CODE: u8 = 0x0B;

/// Request System Code response code.
pub const REQUEST_SYSTEM_CODE_RESPONSE_CODE: u8 = 0x0D;

/// Request Block Information response code.
pub const REQUEST_BLOCK_INFORMATION_RESPONSE_CODE: u8 = 0x0F;

/// Authentication1 response code.
pub const AUTHENTICATION1_RESPONSE_CODE: u8 = 0x11;

/// Authentication2 response code.
pub const AUTHENTICATION2_RESPONSE_CODE: u8 = 0x13;

/// Request Code List response code.
pub const REQUEST_CODE_LIST_RESPONSE_CODE: u8 = 0x1B;

/// Request Block Information Ex response code.
pub const REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE: u8 = 0x1F;

/// Set Parameter response code.
pub const SET_PARAMETER_RESPONSE_CODE: u8 = 0x21;

/// Get Container Issue Information response code.
pub const GET_CONTAINER_ISSUE_INFORMATION_RESPONSE_CODE: u8 = 0x23;

/// Get Area Information response code.
pub const GET_AREA_INFORMATION_RESPONSE_CODE: u8 = 0x25;

/// Get Node Property response code.
pub const GET_NODE_PROPERTY_RESPONSE_CODE: u8 = 0x29;

/// Get Container Property response code.
pub const GET_CONTAINER_PROPERTY_RESPONSE_CODE: u8 = 0x2F;

/// Request Service V2 response code.
pub const REQUEST_SERVICE_V2_RESPONSE_CODE: u8 = 0x33;

/// Get System Status response code.
pub const GET_SYSTEM_STATUS_RESPONSE_CODE: u8 = 0x39;

/// Get Platform Information response code.
pub const GET_PLATFORM_INFORMATION_RESPONSE_CODE: u8 = 0x3B;

/// Request Specification Version response code.
pub const REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE: u8 = 0x3D;

/// Reset Mode response code.
pub const RESET_MODE_RESPONSE_CODE: u8 = 0x3F;

/// Authentication1 V2 response code.
pub const AUTHENTICATION1_V2_RESPONSE_CODE: u8 = 0x41;

/// Authentication2 V2 response code.
pub const AUTHENTICATION2_V2_RESPONSE_CODE: u8 = 0x43;

/// Get Container ID response code.
pub const GET_CONTAINER_ID_RESPONSE_CODE: u8 = 0x71;
