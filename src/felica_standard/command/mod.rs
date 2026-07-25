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

pub enum FelicaStandardCommand {
    Polling {
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    },
    RequestService {
        idm: [u8; IDM_LEN],
        service_codes: Vec<ServiceCode>,
    },
    RequestResponse {
        idm: [u8; IDM_LEN],
    },
    ReadWithoutEncryption {
        idm: [u8; IDM_LEN],
        service_codes: Vec<ServiceCode>,
        block_list: Vec<BlockListElement>,
    },
    WriteWithoutEncryption {
        idm: [u8; IDM_LEN],
        service_codes: Vec<ServiceCode>,
        block_list: Vec<BlockListElement>,
        data: Vec<u8>,
    },
    SearchServiceCode {
        idm: [u8; IDM_LEN],
        service_index: u16,
    },
    RequestSystemCode {
        idm: [u8; IDM_LEN],
    },
    RequestBlockInformation {
        idm: [u8; IDM_LEN],
        node_codes: Vec<u16>,
    },
    Authentication1 {
        idm: [u8; IDM_LEN],
        areas: Vec<u16>,
        services: Vec<u16>,
        challenge_1a: [u8; 8],
    },
    Authentication2 {
        idm: [u8; IDM_LEN],
        challenge_2b: [u8; 8],
    },
    Read {
        block_list: Vec<BlockListElement>,
    },
    Write {
        block_list: Vec<BlockListElement>,
        data: Vec<u8>,
    },
    ReadV2 {
        block_list: Vec<BlockListElement>,
    },
    WriteV2 {
        block_list: Vec<BlockListElement>,
        data: Vec<u8>,
    },
    RequestCodeList {
        idm: [u8; IDM_LEN],
        parent_node_code: u16,
        index: u16,
    },
    RequestBlockInformationEx {
        idm: [u8; IDM_LEN],
        node_codes: Vec<u16>,
    },
    SetParameter {
        idm: [u8; IDM_LEN],
        encryption_type: SetParameterEncryptionType,
        packet_type: SetParameterPacketType,
    },
    GetContainerIssueInformation {
        idm: [u8; IDM_LEN],
    },
    GetAreaInformation {
        idm: [u8; IDM_LEN],
        node_code: u16,
    },
    GetNodeProperty {
        idm: [u8; IDM_LEN],
        node_property_type: NodePropertyType,
        node_codes: Vec<u16>,
    },
    GetContainerProperty {
        property: ContainerProperty,
    },
    RequestServiceV2 {
        idm: [u8; IDM_LEN],
        service_codes: Vec<ServiceCode>,
    },
    GetSystemStatus {
        idm: [u8; IDM_LEN],
    },
    RequestProductInformation {
        idm: [u8; IDM_LEN],
    },
    RequestSpecificationVersion {
        idm: [u8; IDM_LEN],
    },
    ResetMode {
        idm: [u8; IDM_LEN],
    },
    Authentication1V2 {
        idm: [u8; IDM_LEN],
        operation_parameter: u8,
        nodes: Vec<u16>,
        challenge_1a: [u8; 16],
    },
    Authentication2V2 {
        idm: [u8; IDM_LEN],
        challenge_2b: [u8; 16],
    },
    GetContainerId,
    RegisterIssueId {
        issue_id: [u8; 8],
        issue_parameter: [u8; 8],
        package: Vec<u8>,
    },
    RegisterArea {
        area_code: u16,
        package: Vec<u8>,
    },
    RegisterService {
        service_code: u16,
        package: Vec<u8>,
    },
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
