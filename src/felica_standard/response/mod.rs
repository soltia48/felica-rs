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
/// A parsed FeliCa Standard response.
///
/// Status-bearing variants keep both raw status bytes. Their `result` is
/// present only when the packet contains the success-only fields. High-level
/// [`FelicaStandard`](super::FelicaStandard) methods turn non-success status
/// flag 1 values into [`FelicaStandardError`](super::FelicaStandardError).
pub enum FelicaStandardResponse {
    /// Response to Polling.
    Polling {
        /// Manufacture ID (`IDm`) of the responding card.
        idm: Idm,
        /// Manufacture Parameter (`PMm`), including response-time parameters.
        pmm: Pmm,
        /// Request-data field selected by the Polling request code.
        optional: Vec<u8>,
    },
    /// Legacy key versions returned by Request Service.
    RequestService {
        /// Echoed IDm.
        idm: Idm,
        /// One key version per requested Node, in request order.
        key_versions: Vec<u16>,
    },
    /// Current card Mode returned by Request Response.
    RequestResponse {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Mode byte.
        mode: u8,
    },
    /// Block data returned by Read Without Encryption.
    ReadWithoutEncryption {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
        /// Block data, present only in a successful response.
        result: Option<ReadWithoutEncryptionResult>,
    },
    /// Completion status returned by Write Without Encryption.
    WriteWithoutEncryption {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
    },
    /// Area or Service entry returned by Search Service Code.
    SearchServiceCode {
        /// Echoed IDm.
        idm: Idm,
        /// Requested entry, or `None` for the end-of-list marker.
        result: Option<SearchServiceCodeResult>,
    },
    /// System Codes returned by Request System Code.
    RequestSystemCode {
        /// Echoed IDm.
        idm: Idm,
        /// Registered System Codes in card-defined order.
        system_codes: Vec<u16>,
    },
    /// Assigned Block counts returned by Request Block Information.
    RequestBlockInformation {
        /// Echoed IDm.
        idm: Idm,
        /// One assigned Block count per requested Node.
        block_counts: Vec<u16>,
    },
    /// Card challenges returned by legacy DES Authentication1.
    Authentication1 {
        /// Echoed IDm.
        idm: Idm,
        /// Encrypted reflection of the reader challenge (`challenge 1B`).
        challenge_1b: [u8; 8],
        /// Encrypted card challenge (`challenge 2A`).
        challenge_2a: [u8; 8],
    },
    /// Encrypted legacy DES Authentication2 response.
    Authentication2(Authentication2Response),
    /// One page returned by Request Code List.
    RequestCodeList {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
        /// Child Areas and Services, present only on success.
        result: Option<RequestCodeListResult>,
    },
    /// Assigned/free Block counts returned by Request Block Information Ex.
    RequestBlockInformationEx {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
        /// Count vectors, present only on success.
        result: Option<RequestBlockInformationExResult>,
    },
    /// Completion status returned by Set Parameter.
    SetParameter {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
    },
    /// Mobile-FeliCa issue information returned by Get Container Issue Information.
    GetContainerIssueInformation {
        /// Echoed IDm.
        idm: Idm,
        /// Fixed-size container information fields.
        container_information: ContainerInformation,
    },
    /// Product-dependent Area information returned by Get Area Information.
    GetAreaInformation {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
        /// Area information, present only on success.
        result: Option<GetAreaInformationResult>,
    },
    /// Node properties returned by Get Node Property.
    GetNodeProperty {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
        /// Property list, present only on success.
        result: Option<GetNodePropertyResult>,
    },
    /// Raw property bytes returned by Get Container Property.
    GetContainerProperty {
        /// Product-dependent property value.
        data: Vec<u8>,
    },
    /// Cryptographic-system and key-version data returned by Request Service v2.
    RequestServiceV2 {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
        /// Cryptographic identifier and versions, present only on success.
        result: Option<RequestServiceV2Result>,
    },
    /// Selected-System configuration returned by Get System Status.
    GetSystemStatus {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
        /// Product-defined status flag and data.
        result: GetSystemStatusResult,
    },
    /// Product data returned by Request Product Information.
    RequestProductInformation {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
        /// Product-defined information, present only on success.
        result: Option<Vec<u8>>,
    },
    /// OS versions returned by Request Specification Version.
    RequestSpecificationVersion {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
        /// Basic and option versions, present only on success.
        specification_version: Option<SpecificationVersion>,
    },
    /// Completion status returned by Reset Mode.
    ResetMode {
        /// Echoed IDm.
        idm: Idm,
        /// Raw Status Flag 1.
        status_flag1: u8,
        /// Raw Status Flag 2.
        status_flag2: u8,
    },
    /// Card challenges returned by AES-128 Authentication1 v2.
    Authentication1V2 {
        /// Echoed IDm.
        idm: Idm,
        /// Encrypted reflection of the reader challenge (`challenge 1B`).
        challenge_1b: [u8; 16],
        /// Encrypted card challenge (`challenge 2A`).
        challenge_2a: [u8; 16],
        /// Four-byte AES challenge parameter (`challenge 3C`).
        challenge_3c: [u8; 4],
    },
    /// Encrypted AES-128 Authentication2 v2 response.
    Authentication2V2(Authentication2V2Response),
    /// Container identifier returned by Get Container ID.
    GetContainerId {
        /// Eight-byte Container IDm.
        container_idm: Idm,
    },
    /// Decrypted Block data returned by DES Read.
    Read {
        /// Raw Status Flag 1 from the secure inner response.
        status_flag1: u8,
        /// Raw Status Flag 2 from the secure inner response.
        status_flag2: u8,
        /// Block data, present only on success.
        result: Option<ReadResult>,
    },
    /// Completion status returned by DES Write.
    Write {
        /// Raw Status Flag 1 from the secure inner response.
        status_flag1: u8,
        /// Raw Status Flag 2 from the secure inner response.
        status_flag2: u8,
    },
    /// Decrypted Block data returned by AES Read v2.
    ReadV2 {
        /// Raw Status Flag 1 from the secure inner response.
        status_flag1: u8,
        /// Raw Status Flag 2 from the secure inner response.
        status_flag2: u8,
        /// Block data, present only on success.
        result: Option<ReadResult>,
    },
    /// Completion status returned by AES Write v2.
    WriteV2 {
        /// Raw Status Flag 1 from the secure inner response.
        status_flag1: u8,
        /// Raw Status Flag 2 from the secure inner response.
        status_flag2: u8,
    },
    /// Result returned by Register Issue ID.
    RegisterIssueId {
        /// Raw Status Flag 1 from the secure inner response.
        status_flag1: u8,
        /// Raw Status Flag 2 from the secure inner response.
        status_flag2: u8,
        /// Remaining Block count, present only on success.
        result: Option<RegisterIssueIdResult>,
    },
    /// Completion status returned by Register Area.
    RegisterArea {
        /// Raw Status Flag 1 from the secure inner response.
        status_flag1: u8,
        /// Raw Status Flag 2 from the secure inner response.
        status_flag2: u8,
    },
    /// Result returned by Register Service.
    RegisterService {
        /// Raw Status Flag 1 from the secure inner response.
        status_flag1: u8,
        /// Raw Status Flag 2 from the secure inner response.
        status_flag2: u8,
        /// Remaining Block count, present only on success.
        result: Option<RegisterServiceResult>,
    },
    /// Completion status returned by Change System Block.
    ChangeSystemBlock {
        /// Raw Status Flag 1 from the secure inner response.
        status_flag1: u8,
        /// Raw Status Flag 2 from the secure inner response.
        status_flag2: u8,
    },
    /// A response code that this crate does not currently decode.
    Unknown,
}

mod parse;
mod serialize;

#[cfg(test)]
mod tests;
