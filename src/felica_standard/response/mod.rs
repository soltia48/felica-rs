use super::{
    AUTHENTICATION1_RESPONSE_CODE, AUTHENTICATION1_V2_RESPONSE_CODE, AUTHENTICATION2_RESPONSE_CODE,
    AUTHENTICATION2_V2_RESPONSE_CODE, AreaCodeRange, Authentication2Response,
    Authentication2V2Response, BLOCK_SIZE, CHANGE_SYSTEM_BLOCK_COMMAND_CODE, ContainerInformation,
    FelicaStandardError, GET_AREA_INFORMATION_RESPONSE_CODE, GET_CONTAINER_ID_RESPONSE_CODE,
    GET_CONTAINER_ISSUE_INFORMATION_RESPONSE_CODE, GET_CONTAINER_PROPERTY_RESPONSE_CODE,
    GET_NODE_PROPERTY_RESPONSE_CODE, GET_SYSTEM_STATUS_RESPONSE_CODE, GetAreaInformationResult,
    GetNodePropertyResult, GetSystemStatusResult, IDM_LEN, MAX_BLOCK_COUNT, MAX_NODE_CODES,
    MAX_NODE_PROPERTY_CODES, MAX_SERVICE_CODES, NodeProperty, OptionVersion, POLLING_RESPONSE_CODE,
    READ_COMMAND_CODE, READ_V2_COMMAND_CODE, READ_WITHOUT_ENCRYPTION_RESPONSE_CODE,
    REGISTER_AREA_COMMAND_CODE, REGISTER_ISSUE_ID_COMMAND_CODE, REGISTER_SERVICE_COMMAND_CODE,
    REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE, REQUEST_BLOCK_INFORMATION_RESPONSE_CODE,
    REQUEST_CODE_LIST_RESPONSE_CODE, REQUEST_PRODUCT_INFORMATION_RESPONSE_CODE,
    REQUEST_RESPONSE_RESPONSE_CODE, REQUEST_SERVICE_RESPONSE_CODE,
    REQUEST_SERVICE_V2_RESPONSE_CODE, REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE,
    REQUEST_SYSTEM_CODE_RESPONSE_CODE, RESET_MODE_RESPONSE_CODE, ReadResult,
    ReadWithoutEncryptionResult, RegisterIssueIdResult, RegisterServiceResult,
    RequestBlockInformationExResult, RequestCodeListResult, RequestServiceV2KeyVersion,
    RequestServiceV2Result, SEARCH_SERVICE_CODE_RESPONSE_CODE, SET_PARAMETER_RESPONSE_CODE,
    SearchServiceCodeResult, ServiceCode, SpecificationVersion, WRITE_COMMAND_CODE,
    WRITE_V2_COMMAND_CODE, WRITE_WITHOUT_ENCRYPTION_RESPONSE_CODE, frame_with_length_prefix,
};
use crate::driver::errors::{DriverError, Result as DriverResult};

type Idm = [u8; IDM_LEN];
type Pmm = [u8; 8];

#[derive(Debug)]
pub enum FelicaStandardResponse {
    Polling {
        idm: Idm,
        pmm: Pmm,
        optional: Vec<u8>,
    },
    RequestService {
        idm: Idm,
        key_versions: Vec<u16>,
    },
    RequestResponse {
        idm: Idm,
        mode: u8,
    },
    ReadWithoutEncryption {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<ReadWithoutEncryptionResult>,
    },
    WriteWithoutEncryption {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
    },
    SearchServiceCode {
        idm: Idm,
        result: Option<SearchServiceCodeResult>,
    },
    RequestSystemCode {
        idm: Idm,
        system_codes: Vec<u16>,
    },
    RequestBlockInformation {
        idm: Idm,
        block_counts: Vec<u16>,
    },
    Authentication1 {
        idm: Idm,
        challenge_1b: [u8; 8],
        challenge_2a: [u8; 8],
    },
    Authentication2(Authentication2Response),
    RequestCodeList {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RequestCodeListResult>,
    },
    RequestBlockInformationEx {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RequestBlockInformationExResult>,
    },
    SetParameter {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
    },
    GetContainerIssueInformation {
        idm: Idm,
        container_information: ContainerInformation,
    },
    GetAreaInformation {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<GetAreaInformationResult>,
    },
    GetNodeProperty {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<GetNodePropertyResult>,
    },
    GetContainerProperty {
        data: Vec<u8>,
    },
    RequestServiceV2 {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RequestServiceV2Result>,
    },
    GetSystemStatus {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: GetSystemStatusResult,
    },
    RequestProductInformation {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<Vec<u8>>,
    },
    RequestSpecificationVersion {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        specification_version: Option<SpecificationVersion>,
    },
    ResetMode {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
    },
    Authentication1V2 {
        idm: Idm,
        challenge_1b: [u8; 16],
        challenge_2a: [u8; 16],
        challenge_3c: [u8; 4],
    },
    Authentication2V2(Authentication2V2Response),
    GetContainerId {
        container_idm: Idm,
    },
    Read {
        status_flag1: u8,
        status_flag2: u8,
        result: Option<ReadResult>,
    },
    Write {
        status_flag1: u8,
        status_flag2: u8,
    },
    ReadV2 {
        status_flag1: u8,
        status_flag2: u8,
        result: Option<ReadResult>,
    },
    WriteV2 {
        status_flag1: u8,
        status_flag2: u8,
    },
    RegisterIssueId {
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RegisterIssueIdResult>,
    },
    RegisterArea {
        status_flag1: u8,
        status_flag2: u8,
    },
    RegisterService {
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RegisterServiceResult>,
    },
    ChangeSystemBlock {
        status_flag1: u8,
        status_flag2: u8,
    },
    Unknown,
}

mod parse;
mod serialize;

#[cfg(test)]
mod tests;
