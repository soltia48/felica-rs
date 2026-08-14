//! FeliCa Standard protocol constants.

/// Length of the IDm (Identifier) field.
pub const IDM_LEN: usize = 8;

/// Maximum number of service codes in a single request.
pub const MAX_SERVICE_CODES: usize = 0x20;

/// Maximum number of service codes for read/write operations.
pub const MAX_RW_SERVICE_CODES: usize = 0x10;

/// Largest block count a command or response can state.
///
/// This is the width of the block count field, which §4.4.5 and §4.4.6 define as
/// one byte — not a limit on how many blocks a card will actually accept. The
/// manual leaves 最大同時読み出し／書き込みブロック数 to each product, and even the
/// most permissive product is bounded by what a single packet holds; see
/// [`MAX_PACKET_LEN`] and [`MAX_READ_WITHOUT_ENCRYPTION_BLOCK_COUNT`].
pub const MAX_BLOCK_COUNT: usize = 0xFF;

/// Maximum length of a FeliCa packet in bytes, counting the one-byte data
/// length (LEN) field itself.
///
/// The card user's manual (§2.2, table 2-2) defines LEN as a single byte whose
/// value is the packet data length plus one, so no packet — command or
/// response — can be longer than 255 bytes.
///
/// This bound is what actually caps a block list. §4.4.6's worked examples fall
/// straight out of it: a Write Without Encryption naming one service with
/// two-byte block list elements tops out at 13 blocks (248 bytes) and one naming
/// sixteen services with three-byte elements at 11 blocks (253 bytes), which are
/// exactly the figures the manual quotes.
pub const MAX_PACKET_LEN: usize = 0xFF;

/// Fixed part of a Read Without Encryption response: the LEN byte, the response
/// code, the IDm, both status flags and the block count (§4.4.5).
const READ_WITHOUT_ENCRYPTION_RESPONSE_OVERHEAD: usize = 1 + 1 + IDM_LEN + 1 + 1 + 1;

/// Most blocks a single Read Without Encryption can return.
///
/// §4.4.5 makes 最大同時読み出しブロック数 product-specific, but no product can
/// exceed what one response packet holds: 16 bytes per block on top of a fixed
/// 13-byte header, against the [`MAX_PACKET_LEN`] ceiling of §2.2. Unlike a
/// write, a read is limited by the *response* — the command itself stays small —
/// so the request has to be checked against this before it is sent.
pub const MAX_READ_WITHOUT_ENCRYPTION_BLOCK_COUNT: usize =
    (MAX_PACKET_LEN - READ_WITHOUT_ENCRYPTION_RESPONSE_OVERHEAD) / BLOCK_SIZE;

/// Request codes the Polling command defines (§4.4.2): `00h` requests no
/// additional data, `01h` the system code and `02h` the communication
/// performance. All other values are reserved.
pub const POLLING_REQUEST_CODES: [u8; 3] = [0x00, 0x01, 0x02];

/// Time slot values the Polling command defines (§4.4.2, table 4-6), granting
/// the card 1, 2, 4, 8 or 16 anti-collision response slots respectively.
///
/// The manual states that only these values may be sent, since the behaviour of
/// any other value is product-dependent.
pub const POLLING_TIME_SLOTS: [u8; 5] = [0x00, 0x01, 0x03, 0x07, 0x0F];

/// Maximum number of node codes in a single request.
pub const MAX_NODE_CODES: usize = 0x20;

/// Maximum number of node codes in a Get Node Property request.
pub const MAX_NODE_PROPERTY_CODES: usize = 0x10;

/// Size of a single data block in bytes.
pub const BLOCK_SIZE: usize = 16;

/// DES block size in bytes.
pub const DES_BLOCK_SIZE: usize = 8;

/// DES MAC size in bytes.
pub const DES_MAC_SIZE: usize = 8;

/// AES-128 block size in bytes.
pub const V2_AES128_BLOCK_SIZE: usize = 16;

/// AES-128 MAC size in bytes for FeliCa Standard v2 secure messaging.
pub const V2_AES128_MAC_SIZE: usize = 8;

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

/// Request Product Information command code.
pub const REQUEST_PRODUCT_INFORMATION_COMMAND_CODE: u8 = 0x3A;

/// Request Specification Version command code.
pub const REQUEST_SPECIFICATION_VERSION_COMMAND_CODE: u8 = 0x3C;

/// Reset Mode command code.
pub const RESET_MODE_COMMAND_CODE: u8 = 0x3E;

/// Authentication1 V2 command code.
pub const AUTHENTICATION1_V2_COMMAND_CODE: u8 = 0x40;

/// Authentication2 V2 command code.
pub const AUTHENTICATION2_V2_COMMAND_CODE: u8 = 0x42;

/// Read v2 command code.
pub const READ_V2_COMMAND_CODE: u8 = 0x44;

/// Write v2 command code.
pub const WRITE_V2_COMMAND_CODE: u8 = 0x46;

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

/// Request Product Information response code.
pub const REQUEST_PRODUCT_INFORMATION_RESPONSE_CODE: u8 = 0x3B;

/// Request Specification Version response code.
pub const REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE: u8 = 0x3D;

/// Reset Mode response code.
pub const RESET_MODE_RESPONSE_CODE: u8 = 0x3F;

/// Authentication1 V2 response code.
pub const AUTHENTICATION1_V2_RESPONSE_CODE: u8 = 0x41;

/// Authentication2 V2 response code.
pub const AUTHENTICATION2_V2_RESPONSE_CODE: u8 = 0x43;

/// Read v2 response code.
pub const READ_V2_RESPONSE_CODE: u8 = 0x45;

/// Write v2 response code.
pub const WRITE_V2_RESPONSE_CODE: u8 = 0x47;

/// Get Container ID response code.
pub const GET_CONTAINER_ID_RESPONSE_CODE: u8 = 0x71;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_and_response_codes_follow_expected_pairing() {
        assert_eq!(POLLING_RESPONSE_CODE, POLLING_COMMAND_CODE + 1);
        assert_eq!(
            REQUEST_SERVICE_RESPONSE_CODE,
            REQUEST_SERVICE_COMMAND_CODE + 1
        );
        assert_eq!(
            REQUEST_RESPONSE_RESPONSE_CODE,
            REQUEST_RESPONSE_COMMAND_CODE + 1
        );
        assert_eq!(
            READ_WITHOUT_ENCRYPTION_RESPONSE_CODE,
            READ_WITHOUT_ENCRYPTION_COMMAND_CODE + 1
        );
        assert_eq!(
            WRITE_WITHOUT_ENCRYPTION_RESPONSE_CODE,
            WRITE_WITHOUT_ENCRYPTION_COMMAND_CODE + 1
        );
        assert_eq!(
            REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE,
            REQUEST_BLOCK_INFORMATION_EX_COMMAND_CODE + 1
        );
        assert_eq!(RESET_MODE_RESPONSE_CODE, RESET_MODE_COMMAND_CODE + 1);
        assert_eq!(
            AUTHENTICATION1_V2_RESPONSE_CODE,
            AUTHENTICATION1_V2_COMMAND_CODE + 1
        );
        assert_eq!(
            AUTHENTICATION2_V2_RESPONSE_CODE,
            AUTHENTICATION2_V2_COMMAND_CODE + 1
        );
        assert_eq!(READ_V2_RESPONSE_CODE, READ_V2_COMMAND_CODE + 1);
        assert_eq!(WRITE_V2_RESPONSE_CODE, WRITE_V2_COMMAND_CODE + 1);
        assert_eq!(
            GET_CONTAINER_ID_RESPONSE_CODE,
            GET_CONTAINER_ID_COMMAND_CODE + 1
        );
    }

    #[test]
    // Comparing constants is the point: these pin the relationships the
    // protocol code assumes between the size limits.
    #[allow(clippy::assertions_on_constants)]
    fn size_and_limit_constants_match_protocol_expectations() {
        assert_eq!(IDM_LEN, 8);
        assert_eq!(BLOCK_SIZE, 16);
        assert_eq!(DES_BLOCK_SIZE, 8);
        assert_eq!(DES_MAC_SIZE, 8);
        assert_eq!(V2_AES128_BLOCK_SIZE, 16);
        assert_eq!(V2_AES128_MAC_SIZE, 8);
        assert!(MAX_SERVICE_CODES >= MAX_RW_SERVICE_CODES);
        assert!(MAX_BLOCK_COUNT >= MAX_SERVICE_CODES);
        assert!(MAX_NODE_CODES >= MAX_NODE_PROPERTY_CODES);
        // The LEN field is one byte holding "packet data length + 1".
        assert_eq!(MAX_PACKET_LEN, u8::MAX as usize);
    }
}
