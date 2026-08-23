use super::{
    AUTHENTICATION1_COMMAND_CODE, AUTHENTICATION1_V2_COMMAND_CODE, AUTHENTICATION2_COMMAND_CODE,
    AUTHENTICATION2_V2_COMMAND_CODE, BLOCK_SIZE, BlockListElement,
    CHANGE_SYSTEM_BLOCK_COMMAND_CODE, ContainerProperty, FelicaStandardError,
    GET_AREA_INFORMATION_COMMAND_CODE, GET_CONTAINER_ID_COMMAND_CODE,
    GET_CONTAINER_ISSUE_INFORMATION_COMMAND_CODE, GET_CONTAINER_PROPERTY_COMMAND_CODE,
    GET_NODE_PROPERTY_COMMAND_CODE, GET_SYSTEM_STATUS_COMMAND_CODE, IDM_LEN, MAX_BLOCK_COUNT,
    MAX_NODE_CODES, MAX_NODE_PROPERTY_CODES, MAX_PACKET_LEN, MAX_RW_SERVICE_CODES,
    MAX_SERVICE_CODES, NodePropertyType, POLLING_COMMAND_CODE, POLLING_REQUEST_CODES,
    POLLING_TIME_SLOTS, READ_COMMAND_CODE, READ_V2_COMMAND_CODE,
    READ_WITHOUT_ENCRYPTION_COMMAND_CODE, REGISTER_AREA_COMMAND_CODE,
    REGISTER_ISSUE_ID_COMMAND_CODE, REGISTER_SERVICE_COMMAND_CODE,
    REQUEST_BLOCK_INFORMATION_COMMAND_CODE, REQUEST_BLOCK_INFORMATION_EX_COMMAND_CODE,
    REQUEST_CODE_LIST_COMMAND_CODE, REQUEST_PRODUCT_INFORMATION_COMMAND_CODE,
    REQUEST_RESPONSE_COMMAND_CODE, REQUEST_SERVICE_COMMAND_CODE, REQUEST_SERVICE_V2_COMMAND_CODE,
    REQUEST_SPECIFICATION_VERSION_COMMAND_CODE, REQUEST_SYSTEM_CODE_COMMAND_CODE,
    RESET_MODE_COMMAND_CODE, SEARCH_SERVICE_CODE_COMMAND_CODE, SET_PARAMETER_COMMAND_CODE,
    ServiceCode, SetParameterEncryptionType, SetParameterPacketType, WRITE_COMMAND_CODE,
    WRITE_V2_COMMAND_CODE, WRITE_WITHOUT_ENCRYPTION_COMMAND_CODE,
};

/// A typed FeliCa Standard command before packet serialization.
///
/// [`to_frame`](Self::to_frame) validates protocol limits and emits the leading
/// one-byte packet length. Secure variants (`Read`, `Write`, their v2 forms, and
/// issuing commands) represent the plaintext inner payload; they require an
/// [`AuthenticatedContext`](super::AuthenticatedContext) when sent through
/// [`FelicaStandard::send_command`](super::FelicaStandard::send_command).
pub enum FelicaStandardCommand {
    /// Discovers cards and optionally requests System Code or communication data.
    Polling {
        /// Desired System Code; `FFFFh` is the wildcard used to discover any System.
        system_code: u16,
        /// Optional-data selector: `00h` none, `01h` System Code, `02h`
        /// communication performance.
        request_code: u8,
        /// Anti-collision slot value: `00h`, `01h`, `03h`, `07h`, or `0Fh`.
        time_slots: u8,
    },
    /// Checks Node existence and requests legacy key versions.
    RequestService {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Area/Service codes whose key versions are requested.
        service_codes: Vec<ServiceCode>,
    },
    /// Requests the card's current Mode.
    RequestResponse {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
    },
    /// Reads Blocks from authentication-free Services.
    ReadWithoutEncryption {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Ordered Service Code List referenced by `block_list`.
        service_codes: Vec<ServiceCode>,
        /// Blocks to read, including Service Code List indexes.
        block_list: Vec<BlockListElement>,
    },
    /// Writes Blocks to authentication-free Services.
    WriteWithoutEncryption {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Ordered Service Code List referenced by `block_list`.
        service_codes: Vec<ServiceCode>,
        /// Blocks to write, including Service Code List indexes.
        block_list: Vec<BlockListElement>,
        /// Concatenated 16-byte Block Data, one Block per list element.
        data: Vec<u8>,
    },
    /// Retrieves an Area or Service entry by System-list index.
    SearchServiceCode {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Zero-based index of the requested entry.
        service_index: u16,
    },
    /// Retrieves all System Codes registered on the card.
    RequestSystemCode {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
    },
    /// Retrieves the number of Blocks assigned to each Node.
    RequestBlockInformation {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Ordered System, Area, or Service Node Code List.
        node_codes: Vec<u16>,
    },
    /// Starts legacy DES mutual authentication.
    Authentication1 {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Ordered Area Code List contributing to the key hierarchy.
        areas: Vec<u16>,
        /// Ordered Service Code List contributing to authentication and later
        /// secure Block List addressing.
        services: Vec<u16>,
        /// Eight-byte encrypted reader challenge (`challenge 1A`).
        challenge_1a: [u8; 8],
    },
    /// Completes legacy DES mutual authentication.
    Authentication2 {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Eight-byte encrypted card challenge response (`challenge 2B`).
        challenge_2b: [u8; 8],
    },
    /// Reads authenticated Blocks through DES secure messaging.
    Read {
        /// Blocks to read; Service indexes refer to the Authentication1 Service list.
        block_list: Vec<BlockListElement>,
    },
    /// Writes authenticated Blocks through DES secure messaging.
    Write {
        /// Blocks to write; access mode `100b` denotes DES key change.
        block_list: Vec<BlockListElement>,
        /// Concatenated 16-byte Block Data or key-change packages.
        data: Vec<u8>,
    },
    /// Reads authenticated Blocks through AES-128 secure messaging.
    ReadV2 {
        /// Blocks to read; Service indexes refer to the Authentication1 v2 Node list.
        block_list: Vec<BlockListElement>,
    },
    /// Writes authenticated Blocks through AES-128 secure messaging.
    WriteV2 {
        /// Blocks to write; key-change access mode is not valid for this command.
        block_list: Vec<BlockListElement>,
        /// Concatenated 16-byte Block Data.
        data: Vec<u8>,
    },
    /// Retrieves one page of child Nodes under a parent Node.
    RequestCodeList {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Node Code whose direct children are requested.
        parent_node_code: u16,
        /// Protocol-defined start/page index.
        index: u16,
    },
    /// Retrieves assigned and free Block counts for Nodes.
    RequestBlockInformationEx {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Ordered System, Area, or Service Node Code List.
        node_codes: Vec<u16>,
    },
    /// Selects an SRM encryption format and Node Code width.
    SetParameter {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// SRM encryption-format selector.
        encryption_type: SetParameterEncryptionType,
        /// Two- or four-byte Node Code selector.
        packet_type: SetParameterPacketType,
    },
    /// Retrieves mobile-FeliCa container issue information.
    GetContainerIssueInformation {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
    },
    /// Retrieves product-dependent information for one Area.
    GetAreaInformation {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Area Node Code to query.
        node_code: u16,
    },
    /// Retrieves one property group for a list of Nodes.
    GetNodeProperty {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Property group to retrieve.
        node_property_type: NodePropertyType,
        /// Ordered Node Code List.
        node_codes: Vec<u16>,
    },
    /// Retrieves a mobile-FeliCa container property.
    GetContainerProperty {
        /// Product-defined property index.
        property: ContainerProperty,
    },
    /// Requests cryptographic-system and key-version information.
    RequestServiceV2 {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Ordered Node codes whose key versions are requested.
        service_codes: Vec<ServiceCode>,
    },
    /// Retrieves configuration state for the selected System.
    GetSystemStatus {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
    },
    /// Retrieves product-specific card information.
    RequestProductInformation {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
    },
    /// Retrieves the card OS basic and optional-feature versions.
    RequestSpecificationVersion {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
    },
    /// Returns the card to Mode 0.
    ResetMode {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
    },
    /// Starts AES-128 mutual authentication.
    Authentication1V2 {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Product-defined authentication operation parameter.
        operation_parameter: u8,
        /// Ordered Node Code List used for key derivation and Block addressing.
        nodes: Vec<u16>,
        /// Sixteen-byte encrypted reader challenge (`challenge 1A`).
        challenge_1a: [u8; 16],
    },
    /// Completes AES-128 mutual authentication.
    Authentication2V2 {
        /// IDm of the addressed card.
        idm: [u8; IDM_LEN],
        /// Sixteen-byte encrypted card challenge response (`challenge 2B`).
        challenge_2b: [u8; 16],
    },
    /// Retrieves the Container IDm from a mobile FeliCa product.
    GetContainerId,
    /// Initializes a System and registers its issue data and Area 0 package.
    RegisterIssueId {
        /// Eight-byte Issue ID (`IDi`).
        issue_id: [u8; 8],
        /// Eight-byte Issue Parameter (`PMi`).
        issue_parameter: [u8; 8],
        /// Encrypted and MAC-protected 16-byte DES issuance package.
        package: Vec<u8>,
    },
    /// Registers a new Area through DES issuing secure messaging.
    RegisterArea {
        /// Area Code to create.
        area_code: u16,
        /// Encrypted and MAC-protected 16-byte DES issuance package.
        package: Vec<u8>,
    },
    /// Registers a new Service through DES issuing secure messaging.
    RegisterService {
        /// Service Code to create.
        service_code: u16,
        /// Encrypted and MAC-protected 16-byte DES issuance package.
        package: Vec<u8>,
    },
    /// Commits the results of preceding issuing commands to the System Block.
    ChangeSystemBlock,
}

pub(crate) enum CommandEncoding {
    Plain(Vec<u8>),
    Secure { opcode: u8, payload: Vec<u8> },
}

/// Prefixes `payload` with the FeliCa data length (LEN) byte.
///
/// Per §2.2 (table 2-2) LEN is a single byte carrying "packet data length + 1",
/// so a packet may not exceed [`MAX_PACKET_LEN`] bytes. Over-long payloads are
/// rejected rather than silently truncated: a wrapped-around LEN byte would put
/// a frame on the air that every card answers with silence, because the received
/// data length no longer matches the command's expected length.
pub(crate) fn frame_with_length_prefix(payload: &[u8]) -> Result<Vec<u8>, FelicaStandardError> {
    let frame_len = payload.len() + 1;
    if frame_len > MAX_PACKET_LEN {
        return Err(FelicaStandardError::Protocol(format!(
            "FeliCa packet would be {frame_len} bytes, but the one-byte data length field \
             caps a packet at {MAX_PACKET_LEN} bytes"
        )));
    }
    let mut frame = Vec::with_capacity(frame_len);
    frame.push(frame_len as u8);
    frame.extend_from_slice(payload);
    Ok(frame)
}

mod parse;
mod serialize;

pub(crate) use parse::{is_register_command, is_secure_command_code};

#[cfg(test)]
mod tests;
