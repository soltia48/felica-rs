use super::{
    AUTHENTICATION1_RESPONSE_CODE, AUTHENTICATION1_V2_RESPONSE_CODE, AUTHENTICATION2_RESPONSE_CODE,
    AUTHENTICATION2_V2_RESPONSE_CODE, AreaCodeRange, Authentication2Response,
    Authentication2V2Response, BLOCK_SIZE, CHANGE_SYSTEM_BLOCK_COMMAND_CODE, ContainerInformation,
    FelicaStandardError, GET_AREA_INFORMATION_RESPONSE_CODE, GET_CONTAINER_ID_RESPONSE_CODE,
    GET_CONTAINER_ISSUE_INFORMATION_RESPONSE_CODE, GET_CONTAINER_PROPERTY_RESPONSE_CODE,
    GET_NODE_PROPERTY_RESPONSE_CODE, GET_PLATFORM_INFORMATION_RESPONSE_CODE,
    GET_SYSTEM_STATUS_RESPONSE_CODE, GetAreaInformationResult, GetNodePropertyResult,
    GetSystemStatusResult, IDM_LEN, MAX_BLOCK_LIST_LEN, MAX_NODE_CODES, MAX_NODE_PROPERTY_CODES,
    MAX_SERVICE_CODES, NodeProperty, OptionVersion, POLLING_RESPONSE_CODE, READ_COMMAND_CODE,
    READ_WITHOUT_ENCRYPTION_RESPONSE_CODE, REGISTER_AREA_COMMAND_CODE,
    REGISTER_ISSUE_ID_COMMAND_CODE, REGISTER_SERVICE_COMMAND_CODE,
    REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE, REQUEST_BLOCK_INFORMATION_RESPONSE_CODE,
    REQUEST_CODE_LIST_RESPONSE_CODE, REQUEST_RESPONSE_RESPONSE_CODE, REQUEST_SERVICE_RESPONSE_CODE,
    REQUEST_SERVICE_V2_RESPONSE_CODE, REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE,
    REQUEST_SYSTEM_CODE_RESPONSE_CODE, RESET_MODE_RESPONSE_CODE, ReadResult,
    ReadWithoutEncryptionResult, RegisterIssueIdResult, RegisterServiceResult,
    RequestBlockInformationExResult, RequestCodeListResult, RequestServiceV2KeyVersion,
    RequestServiceV2Result, SEARCH_SERVICE_CODE_RESPONSE_CODE, SET_PARAMETER_RESPONSE_CODE,
    SearchServiceCodeResult, ServiceCode, SpecificationVersion, WRITE_COMMAND_CODE,
    WRITE_WITHOUT_ENCRYPTION_RESPONSE_CODE, frame_with_length_prefix,
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
    GetPlatformInformation {
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

impl FelicaStandardResponse {
    pub fn from_bytes(data: &[u8]) -> DriverResult<FelicaStandardResponse> {
        Self::ensure_response_len(data, 2, "short Felica response")?;
        let expected_len = data[0] as usize;
        if expected_len != data.len() {
            return Err(DriverError::Other(
                "length byte does not match response length".into(),
            ));
        }
        let code = data[1];
        if code == AUTHENTICATION2_RESPONSE_CODE {
            return Self::parse_authentication2(data);
        }
        if code == GET_CONTAINER_PROPERTY_RESPONSE_CODE {
            return Self::parse_get_container_property(data);
        }
        if code == AUTHENTICATION2_V2_RESPONSE_CODE {
            return Self::parse_authentication2_v2(data);
        }
        Self::ensure_response_len(data, 10, "short Felica response")?;
        let (idm, _rest) = parse_idm(&data[2..])?;
        match code {
            POLLING_RESPONSE_CODE => Self::parse_polling(idm, data),
            REQUEST_SERVICE_RESPONSE_CODE => Self::parse_request_service(idm, data),
            REQUEST_RESPONSE_RESPONSE_CODE => Self::parse_request_response(idm, data),
            READ_WITHOUT_ENCRYPTION_RESPONSE_CODE => Self::parse_read_without_encryption(idm, data),
            WRITE_WITHOUT_ENCRYPTION_RESPONSE_CODE => {
                Self::parse_write_without_encryption(idm, data)
            }
            SEARCH_SERVICE_CODE_RESPONSE_CODE => Self::parse_search_service_code(idm, data),
            REQUEST_SYSTEM_CODE_RESPONSE_CODE => Self::parse_request_systemcode(idm, data),
            REQUEST_BLOCK_INFORMATION_RESPONSE_CODE => {
                Self::parse_request_block_information(idm, data)
            }
            AUTHENTICATION1_RESPONSE_CODE => Self::parse_authentication1(idm, data),
            REQUEST_CODE_LIST_RESPONSE_CODE => Self::parse_request_code_list(idm, data),
            REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE => {
                Self::parse_request_block_information_ex(idm, data)
            }
            SET_PARAMETER_RESPONSE_CODE => Self::parse_set_parameter(idm, data),
            GET_CONTAINER_ISSUE_INFORMATION_RESPONSE_CODE => {
                Self::parse_get_container_issue_information(idm, data)
            }
            GET_AREA_INFORMATION_RESPONSE_CODE => Self::parse_get_area_information(idm, data),
            GET_NODE_PROPERTY_RESPONSE_CODE => Self::parse_get_node_property(idm, data),
            REQUEST_SERVICE_V2_RESPONSE_CODE => Self::parse_request_service_v2(idm, data),
            GET_SYSTEM_STATUS_RESPONSE_CODE => Self::parse_get_system_status(idm, data),
            GET_PLATFORM_INFORMATION_RESPONSE_CODE => {
                Self::parse_get_platform_information(idm, data)
            }
            REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE => {
                Self::parse_request_specification_version(idm, data)
            }
            RESET_MODE_RESPONSE_CODE => Self::parse_reset_mode(idm, data),
            AUTHENTICATION1_V2_RESPONSE_CODE => Self::parse_authentication1_v2(idm, data),
            GET_CONTAINER_ID_RESPONSE_CODE => Self::parse_get_container_id(idm, data),
            _ => Ok(FelicaStandardResponse::Unknown),
        }
    }

    pub(crate) fn from_secure_bytes(
        command_code: u8,
        data: &[u8],
    ) -> DriverResult<FelicaStandardResponse> {
        match command_code {
            READ_COMMAND_CODE => Self::parse_secure_read(data),
            WRITE_COMMAND_CODE => Self::parse_secure_write(data),
            REGISTER_ISSUE_ID_COMMAND_CODE => Self::parse_register_issue_id(data),
            REGISTER_AREA_COMMAND_CODE => Self::parse_register_area(data),
            REGISTER_SERVICE_COMMAND_CODE => Self::parse_register_service(data),
            CHANGE_SYSTEM_BLOCK_COMMAND_CODE => Self::parse_change_system_block(data),
            _ => Err(DriverError::Other(
                "unsupported secure Felica command response".into(),
            )),
        }
    }

    fn parse_authentication2(data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 10, "short authentication2 response payload")?;
        Ok(FelicaStandardResponse::Authentication2(
            Authentication2Response {
                encrypted_payload: data[2..].to_vec(),
            },
        ))
    }

    fn parse_authentication2_v2(data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 10, "short authentication2 v2 response payload")?;
        Ok(FelicaStandardResponse::Authentication2V2(
            Authentication2V2Response {
                encrypted_payload: data[2..].to_vec(),
            },
        ))
    }

    fn parse_polling(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 18, "short polling response")?;
        let (pmm, _rest) = parse_pmm(&data[10..])?;
        Ok(FelicaStandardResponse::Polling {
            idm,
            pmm,
            optional: data.get(18..).unwrap_or(&[]).to_vec(),
        })
    }

    fn parse_request_service(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 11, "short request service response")?;
        let node_count = data[10] as usize;
        if node_count == 0 || node_count > MAX_SERVICE_CODES {
            return Err(DriverError::Other(
                "request service node count must be between 1 and 32".into(),
            ));
        }
        let expected_len = 11 + node_count * 2;
        Self::ensure_response_len(data, expected_len, "short request service key version list")?;
        let mut key_versions = Vec::with_capacity(node_count);
        for chunk in data[11..11 + node_count * 2].chunks_exact(2) {
            key_versions.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        Ok(FelicaStandardResponse::RequestService { idm, key_versions })
    }

    fn parse_request_service_v2(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short request service v2 response header")?;
        let status_flag1 = data[10];
        let status_flag2 = data[11];
        let mut result = None;

        if status_flag1 == 0 {
            Self::ensure_response_len(
                data,
                14,
                "short request service v2 crypto identifier response",
            )?;
            let parsed_crypto_id = data[12];
            let node_count = data[13] as usize;
            if node_count == 0 || node_count > MAX_SERVICE_CODES {
                return Err(DriverError::Other(
                    "request service v2 node count must be between 1 and 32".into(),
                ));
            }
            let payload = &data[14..];
            let mut parsed_versions = Vec::with_capacity(node_count);
            if matches!(parsed_crypto_id, 0x41 | 0x43) {
                let expected = node_count * 4;
                if payload.len() < expected {
                    return Err(DriverError::Other(
                        "request service v2 dual key version list truncated".into(),
                    ));
                }
                for i in 0..node_count {
                    let aes_offset = i * 2;
                    let des_offset = node_count * 2 + aes_offset;
                    let aes = u16::from_le_bytes([payload[aes_offset], payload[aes_offset + 1]]);
                    let des = u16::from_le_bytes([payload[des_offset], payload[des_offset + 1]]);
                    parsed_versions.push(RequestServiceV2KeyVersion::Dual { aes, des });
                }
            } else {
                let expected = node_count * 2;
                if payload.len() < expected {
                    return Err(DriverError::Other(
                        "request service v2 key version list truncated".into(),
                    ));
                }
                for chunk in payload[..expected].chunks_exact(2) {
                    parsed_versions.push(RequestServiceV2KeyVersion::Single(u16::from_le_bytes([
                        chunk[0], chunk[1],
                    ])));
                }
            }
            result = Some(RequestServiceV2Result {
                crypto_id: parsed_crypto_id,
                key_versions: parsed_versions,
            });
        }

        Ok(FelicaStandardResponse::RequestServiceV2 {
            idm,
            status_flag1,
            status_flag2,
            result,
        })
    }

    fn parse_request_response(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 11, "short request response payload")?;
        Ok(FelicaStandardResponse::RequestResponse {
            idm,
            mode: data[10],
        })
    }

    fn parse_read_without_encryption(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short read without encryption response")?;
        let sf1 = data[10];
        let sf2 = data[11];
        if sf1 != 0 {
            return Ok(FelicaStandardResponse::ReadWithoutEncryption {
                idm,
                status_flag1: sf1,
                status_flag2: sf2,
                result: None,
            });
        }
        let block_count = data[12] as usize;
        if block_count == 0 || block_count > MAX_BLOCK_LIST_LEN {
            return Err(DriverError::Other(
                "read without encryption block count must be between 1 and 255".into(),
            ));
        }
        let expected_len = 13 + block_count * BLOCK_SIZE;
        Self::ensure_response_len(
            data,
            expected_len,
            "short read without encryption block data",
        )?;
        let blocks = collect_blocks(&data[13..13 + block_count * BLOCK_SIZE], block_count);
        Ok(FelicaStandardResponse::ReadWithoutEncryption {
            idm,
            status_flag1: sf1,
            status_flag2: sf2,
            result: Some(ReadWithoutEncryptionResult { blocks }),
        })
    }

    fn parse_write_without_encryption(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short write without encryption response")?;
        let sf1 = data[10];
        let sf2 = data[11];
        Ok(FelicaStandardResponse::WriteWithoutEncryption {
            idm,
            status_flag1: sf1,
            status_flag2: sf2,
        })
    }

    fn parse_search_service_code(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short search service code response")?;
        let payload = &data[10..];
        let result = if payload == [0xFF, 0xFF] {
            None
        } else if payload.len() == 2 {
            Some(SearchServiceCodeResult::Service(ServiceCode::new(
                u16::from_le_bytes([payload[0], payload[1]]),
            )))
        } else if payload.len() == 4 {
            Some(SearchServiceCodeResult::Area {
                area_code: u16::from_le_bytes([payload[0], payload[1]]),
                end_service_code: u16::from_le_bytes([payload[2], payload[3]]),
            })
        } else {
            return Err(DriverError::Other(
                "search service code response must contain 2 or 4 bytes".into(),
            ));
        };
        Ok(FelicaStandardResponse::SearchServiceCode { idm, result })
    }

    fn parse_request_systemcode(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short request system code response")?;
        let count = data[10] as usize;
        if count == 0 {
            return Err(DriverError::Other(
                "request system code response count must be at least 1".into(),
            ));
        }
        let expected_len = 11 + count * 2;
        Self::ensure_response_len(
            data,
            expected_len,
            "short request system code response list",
        )?;
        let mut system_codes = Vec::with_capacity(count);
        for chunk in data[11..11 + count * 2].chunks_exact(2) {
            system_codes.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        Ok(FelicaStandardResponse::RequestSystemCode { idm, system_codes })
    }

    fn parse_request_block_information(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short request block information response")?;
        let count = data[10] as usize;
        if count == 0 {
            return Err(DriverError::Other(
                "request block information count must be at least 1".into(),
            ));
        }
        let expected_len = 11 + count * 2;
        Self::ensure_response_len(data, expected_len, "short request block information list")?;
        let mut block_counts = Vec::with_capacity(count);
        for chunk in data[11..11 + count * 2].chunks_exact(2) {
            block_counts.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        Ok(FelicaStandardResponse::RequestBlockInformation { idm, block_counts })
    }

    fn parse_request_block_information_ex(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short request block information ex response")?;
        let status_flag1 = data[10];
        let status_flag2 = data[11];
        if status_flag1 != 0 {
            return Ok(FelicaStandardResponse::RequestBlockInformationEx {
                idm,
                status_flag1,
                status_flag2,
                result: None,
            });
        }

        Self::ensure_response_len(
            data,
            13,
            "short request block information ex success response",
        )?;
        let count = data[12] as usize;
        if count == 0 || count > MAX_NODE_CODES {
            return Err(DriverError::Other(
                "request block information ex count must be between 1 and 32".into(),
            ));
        }

        let expected_len = 13 + count * 4;
        Self::ensure_response_len(
            data,
            expected_len,
            "short request block information ex count list",
        )?;
        let mut assigned_block_counts = Vec::with_capacity(count);
        let mut free_block_counts = Vec::with_capacity(count);
        for chunk in data[13..13 + count * 4].chunks_exact(4) {
            assigned_block_counts.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            free_block_counts.push(u16::from_le_bytes([chunk[2], chunk[3]]));
        }

        Ok(FelicaStandardResponse::RequestBlockInformationEx {
            idm,
            status_flag1,
            status_flag2,
            result: Some(RequestBlockInformationExResult {
                assigned_block_counts,
                free_block_counts,
            }),
        })
    }

    fn parse_request_code_list(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short request code list response")?;
        let status_flag1 = data[10];
        let status_flag2 = data[11];
        if status_flag1 != 0 {
            return Ok(FelicaStandardResponse::RequestCodeList {
                idm,
                status_flag1,
                status_flag2,
                result: None,
            });
        }

        Self::ensure_response_len(data, 15, "short request code list success response")?;
        let continue_flag = data[12] != 0;

        let area_count = data[13] as usize;
        let mut offset = 14usize;
        let area_payload_len = area_count.checked_mul(4).ok_or_else(|| {
            DriverError::Other("request code list area payload length overflow".into())
        })?;
        Self::ensure_response_len(
            data,
            offset + area_payload_len + 1,
            "short request code list area payload",
        )?;

        let mut areas = Vec::with_capacity(area_count);
        for chunk in data[offset..offset + area_payload_len].chunks_exact(4) {
            areas.push(AreaCodeRange {
                area_code: u16::from_le_bytes([chunk[0], chunk[1]]),
                end_service_code: u16::from_le_bytes([chunk[2], chunk[3]]),
            });
        }
        offset += area_payload_len;

        let service_count = data[offset] as usize;
        offset += 1;
        let service_payload_len = service_count.checked_mul(2).ok_or_else(|| {
            DriverError::Other("request code list service payload length overflow".into())
        })?;
        Self::ensure_response_len(
            data,
            offset + service_payload_len,
            "short request code list service payload",
        )?;

        let mut services = Vec::with_capacity(service_count);
        for chunk in data[offset..offset + service_payload_len].chunks_exact(2) {
            services.push(ServiceCode::new(u16::from_le_bytes([chunk[0], chunk[1]])));
        }

        Ok(FelicaStandardResponse::RequestCodeList {
            idm,
            status_flag1,
            status_flag2,
            result: Some(RequestCodeListResult {
                continue_flag,
                areas,
                services,
            }),
        })
    }

    fn parse_set_parameter(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short set parameter response")?;
        Ok(FelicaStandardResponse::SetParameter {
            idm,
            status_flag1: data[10],
            status_flag2: data[11],
        })
    }

    fn parse_get_container_issue_information(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 26, "short get container issue information response")?;
        let mut format_version_carrier_information = [0u8; 5];
        format_version_carrier_information.copy_from_slice(&data[10..15]);
        let mut mobile_phone_model_information = [0u8; 11];
        mobile_phone_model_information.copy_from_slice(&data[15..26]);
        Ok(FelicaStandardResponse::GetContainerIssueInformation {
            idm,
            container_information: ContainerInformation {
                format_version_carrier_information,
                mobile_phone_model_information,
            },
        })
    }

    fn parse_get_container_property(data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 3, "short get container property response")?;
        let payload = data[2..].to_vec();
        if payload.is_empty() {
            return Err(DriverError::Other(
                "get container property response data must contain at least one byte".into(),
            ));
        }
        Ok(FelicaStandardResponse::GetContainerProperty { data: payload })
    }

    fn parse_get_container_id(container_idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 10, "short get container id response")?;
        Ok(FelicaStandardResponse::GetContainerId { container_idm })
    }

    fn parse_get_area_information(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short get area information response")?;
        let status_flag1 = data[10];
        let status_flag2 = data[11];
        if status_flag1 != 0 {
            return Ok(FelicaStandardResponse::GetAreaInformation {
                idm,
                status_flag1,
                status_flag2,
                result: None,
            });
        }
        Self::ensure_response_len(data, 16, "short get area information success response")?;
        Ok(FelicaStandardResponse::GetAreaInformation {
            idm,
            status_flag1,
            status_flag2,
            result: Some(GetAreaInformationResult {
                node_code: u16::from_le_bytes([data[12], data[13]]),
                data: [data[14], data[15]],
            }),
        })
    }

    fn parse_get_node_property(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short get node property response")?;
        let status_flag1 = data[10];
        let status_flag2 = data[11];
        if status_flag1 != 0 {
            return Ok(FelicaStandardResponse::GetNodeProperty {
                idm,
                status_flag1,
                status_flag2,
                result: None,
            });
        }

        Self::ensure_response_len(data, 13, "short get node property success response")?;
        let node_count = data[12] as usize;
        if node_count == 0 || node_count > MAX_NODE_PROPERTY_CODES {
            return Err(DriverError::Other(
                "get node property node count must be between 1 and 16".into(),
            ));
        }

        let payload = &data[13..];
        let value_limited_len = node_count.checked_mul(10).ok_or_else(|| {
            DriverError::Other("get node property value-limited payload length overflow".into())
        })?;
        let mac_communication_len = node_count;

        let node_properties = if payload.len() == value_limited_len {
            let mut properties = Vec::with_capacity(node_count);
            for chunk in payload.chunks_exact(10) {
                properties.push(NodeProperty::ValueLimitedPurseService {
                    enabled: chunk[0] == 0x01,
                    upper_limit: i32::from_le_bytes([chunk[1], chunk[2], chunk[3], chunk[4]]),
                    lower_limit: i32::from_le_bytes([chunk[5], chunk[6], chunk[7], chunk[8]]),
                    generation_number: chunk[9],
                });
            }
            properties
        } else if payload.len() == mac_communication_len {
            payload
                .iter()
                .map(|value| NodeProperty::MacCommunication {
                    enabled: *value == 0x01,
                })
                .collect()
        } else {
            return Err(DriverError::Other(
                "get node property payload length does not match known node property format".into(),
            ));
        };

        Ok(FelicaStandardResponse::GetNodeProperty {
            idm,
            status_flag1,
            status_flag2,
            result: Some(GetNodePropertyResult { node_properties }),
        })
    }

    fn parse_get_system_status(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 14, "short get system status response")?;
        let status_flag1 = data[10];
        let status_flag2 = data[11];
        let flag = data[12];
        let data_len = data[13] as usize;
        Self::ensure_response_len(
            data,
            14 + data_len,
            "short get system status response payload",
        )?;
        Ok(FelicaStandardResponse::GetSystemStatus {
            idm,
            status_flag1,
            status_flag2,
            result: GetSystemStatusResult {
                flag,
                data: data[14..14 + data_len].to_vec(),
            },
        })
    }

    fn parse_get_platform_information(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short get platform information response")?;
        let status_flag1 = data[10];
        let status_flag2 = data[11];
        if status_flag1 != 0 {
            return Ok(FelicaStandardResponse::GetPlatformInformation {
                idm,
                status_flag1,
                status_flag2,
                result: None,
            });
        }

        Self::ensure_response_len(data, 13, "short get platform information success response")?;
        let data_len = data[12] as usize;
        Self::ensure_response_len(
            data,
            13 + data_len,
            "short get platform information response payload",
        )?;
        Ok(FelicaStandardResponse::GetPlatformInformation {
            idm,
            status_flag1,
            status_flag2,
            result: Some(data[13..13 + data_len].to_vec()),
        })
    }

    fn parse_request_specification_version(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short request specification version response")?;
        let status_flag1 = data[10];
        let status_flag2 = data[11];
        let specification_version = if status_flag1 == 0 && data.len() > 12 {
            Some(parse_specification_version_data(&data[12..])?)
        } else {
            None
        };
        Ok(FelicaStandardResponse::RequestSpecificationVersion {
            idm,
            status_flag1,
            status_flag2,
            specification_version,
        })
    }

    fn parse_reset_mode(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short reset mode response")?;
        Ok(FelicaStandardResponse::ResetMode {
            idm,
            status_flag1: data[10],
            status_flag2: data[11],
        })
    }

    fn parse_authentication1(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 26, "short authentication1 response")?;
        let mut challenge_1b = [0u8; 8];
        challenge_1b.copy_from_slice(&data[10..18]);
        let mut challenge_2a = [0u8; 8];
        challenge_2a.copy_from_slice(&data[18..26]);
        Ok(FelicaStandardResponse::Authentication1 {
            idm,
            challenge_1b,
            challenge_2a,
        })
    }

    fn parse_secure_read(data: &[u8]) -> DriverResult<Self> {
        if data.len() < 3 {
            return Err(DriverError::Other(
                "encrypted read response shorter than status flags".into(),
            ));
        }
        let sf1 = data[0];
        let sf2 = data[1];
        if sf1 != 0 {
            return Ok(FelicaStandardResponse::Read {
                status_flag1: sf1,
                status_flag2: sf2,
                result: None,
            });
        }
        let block_count = data[2] as usize;
        if block_count == 0 || block_count > MAX_BLOCK_LIST_LEN {
            return Err(DriverError::Other(
                "encrypted read response block count must be between 1 and 255".into(),
            ));
        }
        let expected_len = 3 + block_count * BLOCK_SIZE;
        if data.len() < expected_len {
            return Err(DriverError::Other(
                "encrypted read response truncated before block data".into(),
            ));
        }
        let blocks = collect_blocks(&data[3..3 + block_count * BLOCK_SIZE], block_count);
        Ok(FelicaStandardResponse::Read {
            status_flag1: sf1,
            status_flag2: sf2,
            result: Some(ReadResult { blocks }),
        })
    }

    fn parse_secure_write(data: &[u8]) -> DriverResult<Self> {
        if data.len() < 2 {
            return Err(DriverError::Other(
                "encrypted write response shorter than status flags".into(),
            ));
        }
        Ok(FelicaStandardResponse::Write {
            status_flag1: data[0],
            status_flag2: data[1],
        })
    }

    fn parse_register_issue_id(data: &[u8]) -> DriverResult<Self> {
        if data.len() < 2 {
            return Err(DriverError::Other(
                "register issue id response shorter than status flags".into(),
            ));
        }
        let status_flag1 = data[0];
        let status_flag2 = data[1];
        let result = if status_flag1 == 0 {
            if data.len() < 4 {
                return Err(DriverError::Other(
                    "register issue id response missing remaining block count".into(),
                ));
            }
            Some(RegisterIssueIdResult {
                remaining_blocks: u16::from_le_bytes([data[2], data[3]]),
            })
        } else {
            None
        };
        Ok(FelicaStandardResponse::RegisterIssueId {
            status_flag1,
            status_flag2,
            result,
        })
    }

    fn parse_register_area(data: &[u8]) -> DriverResult<Self> {
        if data.len() < 2 {
            return Err(DriverError::Other(
                "register area response shorter than status flags".into(),
            ));
        }
        Ok(FelicaStandardResponse::RegisterArea {
            status_flag1: data[0],
            status_flag2: data[1],
        })
    }

    fn parse_register_service(data: &[u8]) -> DriverResult<Self> {
        if data.len() < 2 {
            return Err(DriverError::Other(
                "register service response shorter than status flags".into(),
            ));
        }
        let status_flag1 = data[0];
        let status_flag2 = data[1];
        let result = if status_flag1 == 0 {
            if data.len() < 4 {
                return Err(DriverError::Other(
                    "register service response missing remaining block count".into(),
                ));
            }
            Some(RegisterServiceResult {
                remaining_blocks: u16::from_le_bytes([data[2], data[3]]),
            })
        } else {
            None
        };
        Ok(FelicaStandardResponse::RegisterService {
            status_flag1,
            status_flag2,
            result,
        })
    }

    fn parse_change_system_block(data: &[u8]) -> DriverResult<Self> {
        if data.len() < 2 {
            return Err(DriverError::Other(
                "commit registration response shorter than status flags".into(),
            ));
        }
        Ok(FelicaStandardResponse::ChangeSystemBlock {
            status_flag1: data[0],
            status_flag2: data[1],
        })
    }

    fn parse_authentication1_v2(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 46, "short authentication1 v2 response")?;
        let mut challenge_1b = [0u8; 16];
        challenge_1b.copy_from_slice(&data[10..26]);
        let mut challenge_2a = [0u8; 16];
        challenge_2a.copy_from_slice(&data[26..42]);
        let mut challenge_3c = [0u8; 4];
        challenge_3c.copy_from_slice(&data[42..46]);
        Ok(FelicaStandardResponse::Authentication1V2 {
            idm,
            challenge_1b,
            challenge_2a,
            challenge_3c,
        })
    }

    fn ensure_response_len(data: &[u8], required: usize, message: &str) -> DriverResult<()> {
        if data.len() < required {
            Err(DriverError::Other(message.into()))
        } else {
            Ok(())
        }
    }

    pub fn to_payload(&self) -> Result<Vec<u8>, FelicaStandardError> {
        match self {
            FelicaStandardResponse::Polling { idm, pmm, optional } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 8 + optional.len());
                payload.push(POLLING_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.extend_from_slice(pmm);
                payload.extend_from_slice(optional);
                Ok(payload)
            }
            FelicaStandardResponse::RequestService { idm, key_versions } => {
                if key_versions.is_empty() || key_versions.len() > MAX_SERVICE_CODES {
                    return Err(FelicaStandardError::Protocol(
                        "request service key version count out of range".into(),
                    ));
                }
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 1 + key_versions.len() * 2);
                payload.push(REQUEST_SERVICE_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(key_versions.len() as u8);
                for version in key_versions {
                    payload.extend_from_slice(&version.to_le_bytes());
                }
                Ok(payload)
            }
            FelicaStandardResponse::RequestResponse { idm, mode } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 1);
                payload.push(REQUEST_RESPONSE_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*mode);
                Ok(payload)
            }
            FelicaStandardResponse::ReadWithoutEncryption {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                let block_len = result.as_ref().map(|value| value.blocks.len()).unwrap_or(0);
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 3 + block_len * BLOCK_SIZE);
                payload.push(READ_WITHOUT_ENCRYPTION_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "read without encryption result is missing on success".into(),
                        )
                    })?;
                    let blocks = &result.blocks;
                    if blocks.is_empty() || blocks.len() > MAX_BLOCK_LIST_LEN {
                        return Err(FelicaStandardError::Protocol(
                            "read without encryption block count out of range".into(),
                        ));
                    }
                    payload.push(blocks.len() as u8);
                    for block in blocks {
                        payload.extend_from_slice(block);
                    }
                } else if result.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "read without encryption result must be omitted on error".into(),
                    ));
                }
                Ok(payload)
            }
            FelicaStandardResponse::WriteWithoutEncryption {
                idm,
                status_flag1,
                status_flag2,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                payload.push(WRITE_WITHOUT_ENCRYPTION_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                Ok(payload)
            }
            FelicaStandardResponse::SearchServiceCode { idm, result } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 4);
                payload.push(SEARCH_SERVICE_CODE_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                match result {
                    None => payload.extend_from_slice(&[0xFF, 0xFF]),
                    Some(SearchServiceCodeResult::Service(code)) => {
                        payload.extend_from_slice(&code.raw().to_le_bytes());
                    }
                    Some(SearchServiceCodeResult::Area {
                        area_code,
                        end_service_code,
                    }) => {
                        payload.extend_from_slice(&area_code.to_le_bytes());
                        payload.extend_from_slice(&end_service_code.to_le_bytes());
                    }
                }
                Ok(payload)
            }
            FelicaStandardResponse::RequestSystemCode { idm, system_codes } => {
                if system_codes.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "request system code must include at least one entry".into(),
                    ));
                }
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 1 + system_codes.len() * 2);
                payload.push(REQUEST_SYSTEM_CODE_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(system_codes.len() as u8);
                for code in system_codes {
                    payload.extend_from_slice(&code.to_be_bytes());
                }
                Ok(payload)
            }
            FelicaStandardResponse::RequestBlockInformation { idm, block_counts } => {
                if block_counts.is_empty() || block_counts.len() > MAX_NODE_CODES {
                    return Err(FelicaStandardError::Protocol(
                        "request block information count out of range".into(),
                    ));
                }
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 1 + block_counts.len() * 2);
                payload.push(REQUEST_BLOCK_INFORMATION_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(block_counts.len() as u8);
                for count in block_counts {
                    payload.extend_from_slice(&count.to_le_bytes());
                }
                Ok(payload)
            }
            FelicaStandardResponse::Authentication1 {
                idm,
                challenge_1b,
                challenge_2a,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 16);
                payload.push(AUTHENTICATION1_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.extend_from_slice(challenge_1b);
                payload.extend_from_slice(challenge_2a);
                Ok(payload)
            }
            FelicaStandardResponse::Authentication2(auth) => {
                let mut payload = Vec::with_capacity(1 + auth.encrypted_payload.len());
                payload.push(AUTHENTICATION2_RESPONSE_CODE);
                payload.extend_from_slice(&auth.encrypted_payload);
                Ok(payload)
            }
            FelicaStandardResponse::RequestCodeList {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "request code list result is missing on success".into(),
                        )
                    })?;
                    if result.areas.len() > u8::MAX as usize {
                        return Err(FelicaStandardError::Protocol(
                            "request code list area count out of range".into(),
                        ));
                    }
                    if result.services.len() > u8::MAX as usize {
                        return Err(FelicaStandardError::Protocol(
                            "request code list service count out of range".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(
                        1 + IDM_LEN
                            + 2
                            + 1
                            + 1
                            + result.areas.len() * 4
                            + 1
                            + result.services.len() * 2,
                    );
                    payload.push(REQUEST_CODE_LIST_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    payload.push(if result.continue_flag { 0x01 } else { 0x00 });
                    payload.push(result.areas.len() as u8);
                    for area in &result.areas {
                        payload.extend_from_slice(&area.area_code.to_le_bytes());
                        payload.extend_from_slice(&area.end_service_code.to_le_bytes());
                    }
                    payload.push(result.services.len() as u8);
                    for service in &result.services {
                        payload.extend_from_slice(&service.raw().to_le_bytes());
                    }
                    Ok(payload)
                } else {
                    if result.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "request code list result must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(REQUEST_CODE_LIST_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::RequestBlockInformationEx {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "request block information ex result is missing on success".into(),
                        )
                    })?;
                    if result.assigned_block_counts.is_empty()
                        || result.assigned_block_counts.len() > MAX_NODE_CODES
                    {
                        return Err(FelicaStandardError::Protocol(
                            "request block information ex count out of range".into(),
                        ));
                    }
                    if result.assigned_block_counts.len() != result.free_block_counts.len() {
                        return Err(FelicaStandardError::Protocol(
                            "request block information ex assigned/free length mismatch".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(
                        1 + IDM_LEN + 2 + 1 + result.assigned_block_counts.len() * 4,
                    );
                    payload.push(REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    payload.push(result.assigned_block_counts.len() as u8);
                    for (assigned, free) in result
                        .assigned_block_counts
                        .iter()
                        .zip(result.free_block_counts.iter())
                    {
                        payload.extend_from_slice(&assigned.to_le_bytes());
                        payload.extend_from_slice(&free.to_le_bytes());
                    }
                    Ok(payload)
                } else {
                    if result.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "request block information ex result must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::SetParameter {
                idm,
                status_flag1,
                status_flag2,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                payload.push(SET_PARAMETER_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                Ok(payload)
            }
            FelicaStandardResponse::GetContainerIssueInformation {
                idm,
                container_information,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 16);
                payload.push(GET_CONTAINER_ISSUE_INFORMATION_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload
                    .extend_from_slice(&container_information.format_version_carrier_information);
                payload.extend_from_slice(&container_information.mobile_phone_model_information);
                Ok(payload)
            }
            FelicaStandardResponse::GetAreaInformation {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "get area information result is missing on success".into(),
                        )
                    })?;
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2 + 4);
                    payload.push(GET_AREA_INFORMATION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    payload.extend_from_slice(&result.node_code.to_le_bytes());
                    payload.extend_from_slice(&result.data);
                    Ok(payload)
                } else {
                    if result.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "get area information result must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(GET_AREA_INFORMATION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::GetNodeProperty {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "get node property result is missing on success".into(),
                        )
                    })?;
                    if result.node_properties.is_empty()
                        || result.node_properties.len() > MAX_NODE_PROPERTY_CODES
                    {
                        return Err(FelicaStandardError::Protocol(
                            "get node property count out of range".into(),
                        ));
                    }
                    let property_type = result.node_properties[0].property_type();
                    if result
                        .node_properties
                        .iter()
                        .any(|property| property.property_type() != property_type)
                    {
                        return Err(FelicaStandardError::Protocol(
                            "get node property response cannot mix property types".into(),
                        ));
                    }
                    let property_payload_len = result
                        .node_properties
                        .iter()
                        .map(|property| (*property).size_bytes())
                        .sum::<usize>();
                    let mut payload =
                        Vec::with_capacity(1 + IDM_LEN + 2 + 1 + property_payload_len);
                    payload.push(GET_NODE_PROPERTY_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    payload.push(result.node_properties.len() as u8);
                    for property in &result.node_properties {
                        payload.extend_from_slice(&(*property).to_bytes());
                    }
                    Ok(payload)
                } else {
                    if result.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "get node property result must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(GET_NODE_PROPERTY_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::GetContainerProperty { data } => {
                if data.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "get container property response data must contain at least one byte"
                            .into(),
                    ));
                }
                let mut payload = Vec::with_capacity(1 + data.len());
                payload.push(GET_CONTAINER_PROPERTY_RESPONSE_CODE);
                payload.extend_from_slice(data);
                Ok(payload)
            }
            FelicaStandardResponse::RequestServiceV2 {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                let kv_len = result
                    .as_ref()
                    .map(|value| value.key_versions.len())
                    .unwrap_or(0);
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 4 + kv_len * 4);
                payload.push(REQUEST_SERVICE_V2_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "request service v2 result is missing on success".into(),
                        )
                    })?;
                    let crypto_id = result.crypto_id;
                    let key_versions = &result.key_versions;
                    if key_versions.is_empty() || key_versions.len() > MAX_SERVICE_CODES {
                        return Err(FelicaStandardError::Protocol(
                            "request service v2 key version count out of range".into(),
                        ));
                    }
                    payload.push(crypto_id);
                    payload.push(key_versions.len() as u8);
                    if matches!(crypto_id, 0x41 | 0x43) {
                        let mut secondary_versions = Vec::with_capacity(key_versions.len());
                        for version in key_versions {
                            let secondary = version.secondary_raw().ok_or_else(|| {
                                FelicaStandardError::Protocol(
                                    "request service v2 dual crypto requires dual key versions"
                                        .into(),
                                )
                            })?;
                            payload.extend_from_slice(&version.primary_raw().to_le_bytes());
                            secondary_versions.push(secondary);
                        }
                        for secondary in secondary_versions {
                            payload.extend_from_slice(&secondary.to_le_bytes());
                        }
                    } else {
                        for version in key_versions {
                            if version.secondary_raw().is_some() {
                                return Err(FelicaStandardError::Protocol(
                                    "request service v2 single crypto requires single key versions"
                                        .into(),
                                ));
                            }
                            payload.extend_from_slice(&version.primary_raw().to_le_bytes());
                        }
                    }
                } else if result.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "request service v2 result must be omitted on error".into(),
                    ));
                }
                Ok(payload)
            }
            FelicaStandardResponse::GetSystemStatus {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if result.data.len() > u8::MAX as usize {
                    return Err(FelicaStandardError::Protocol(
                        "get system status response data length out of range".into(),
                    ));
                }
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 2 + 1 + 1 + result.data.len());
                payload.push(GET_SYSTEM_STATUS_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                payload.push(result.flag);
                payload.push(result.data.len() as u8);
                payload.extend_from_slice(&result.data);
                Ok(payload)
            }
            FelicaStandardResponse::GetPlatformInformation {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "get platform information result is missing on success".into(),
                        )
                    })?;
                    if result.len() > u8::MAX as usize {
                        return Err(FelicaStandardError::Protocol(
                            "get platform information response data length out of range".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2 + 1 + result.len());
                    payload.push(GET_PLATFORM_INFORMATION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    payload.push(result.len() as u8);
                    payload.extend_from_slice(result);
                    Ok(payload)
                } else {
                    if result.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "get platform information result must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(GET_PLATFORM_INFORMATION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::RequestSpecificationVersion {
                idm,
                status_flag1,
                status_flag2,
                specification_version,
            } => {
                if *status_flag1 == 0 {
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2 + 16);
                    payload.push(REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    if let Some(specification_version) = specification_version {
                        if specification_version.format_version != 0x00 {
                            return Err(FelicaStandardError::Protocol(
                                "request specification version format version must be 0x00".into(),
                            ));
                        }
                        if specification_version.option_versions.len() > u8::MAX as usize {
                            return Err(FelicaStandardError::Protocol(
                                "request specification version option count out of range".into(),
                            ));
                        }
                        payload.extend_from_slice(&specification_version.to_bytes());
                    }
                    Ok(payload)
                } else {
                    if specification_version.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "request specification version payload must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::ResetMode {
                idm,
                status_flag1,
                status_flag2,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                payload.push(RESET_MODE_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                Ok(payload)
            }
            FelicaStandardResponse::Authentication1V2 {
                idm,
                challenge_1b,
                challenge_2a,
                challenge_3c,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 36);
                payload.push(AUTHENTICATION1_V2_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.extend_from_slice(challenge_1b);
                payload.extend_from_slice(challenge_2a);
                payload.extend_from_slice(challenge_3c);
                Ok(payload)
            }
            FelicaStandardResponse::Authentication2V2(auth) => {
                let mut payload = Vec::with_capacity(1 + auth.encrypted_payload.len());
                payload.push(AUTHENTICATION2_V2_RESPONSE_CODE);
                payload.extend_from_slice(&auth.encrypted_payload);
                Ok(payload)
            }
            FelicaStandardResponse::GetContainerId { container_idm } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN);
                payload.push(GET_CONTAINER_ID_RESPONSE_CODE);
                payload.extend_from_slice(container_idm);
                Ok(payload)
            }
            FelicaStandardResponse::Read { .. }
            | FelicaStandardResponse::Write { .. }
            | FelicaStandardResponse::RegisterIssueId { .. }
            | FelicaStandardResponse::RegisterArea { .. }
            | FelicaStandardResponse::RegisterService { .. }
            | FelicaStandardResponse::ChangeSystemBlock { .. } => self.to_secure_payload(),
            FelicaStandardResponse::Unknown => Err(FelicaStandardError::Protocol(
                "cannot encode unknown response".into(),
            )),
        }
    }

    pub fn to_frame(&self) -> Result<Vec<u8>, FelicaStandardError> {
        match self {
            FelicaStandardResponse::Read { .. }
            | FelicaStandardResponse::Write { .. }
            | FelicaStandardResponse::RegisterIssueId { .. }
            | FelicaStandardResponse::RegisterArea { .. }
            | FelicaStandardResponse::RegisterService { .. }
            | FelicaStandardResponse::ChangeSystemBlock { .. } => Err(
                FelicaStandardError::Protocol("secure response requires encryption".into()),
            ),
            _ => {
                let payload = self.to_payload()?;
                Ok(frame_with_length_prefix(&payload))
            }
        }
    }

    pub fn to_secure_payload(&self) -> Result<Vec<u8>, FelicaStandardError> {
        match self {
            FelicaStandardResponse::Read {
                status_flag1,
                status_flag2,
                result,
            } => {
                let block_len = result.as_ref().map(|value| value.blocks.len()).unwrap_or(0);
                let mut payload = Vec::with_capacity(2 + 1 + block_len * BLOCK_SIZE);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "secure read result is missing on success".into(),
                        )
                    })?;
                    let blocks = &result.blocks;
                    if blocks.is_empty() || blocks.len() > MAX_BLOCK_LIST_LEN {
                        return Err(FelicaStandardError::Protocol(
                            "secure read block count out of range".into(),
                        ));
                    }
                    payload.push(blocks.len() as u8);
                    for block in blocks {
                        payload.extend_from_slice(block);
                    }
                } else if result.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "secure read result must be omitted on error".into(),
                    ));
                }
                Ok(payload)
            }
            FelicaStandardResponse::Write {
                status_flag1,
                status_flag2,
            } => Ok(vec![*status_flag1, *status_flag2]),
            FelicaStandardResponse::RegisterIssueId {
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload = Vec::with_capacity(4);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "register issue id result is missing on success".into(),
                        )
                    })?;
                    payload.extend_from_slice(&result.remaining_blocks.to_le_bytes());
                } else if result.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "register issue id result must be omitted on error".into(),
                    ));
                }
                Ok(payload)
            }
            FelicaStandardResponse::RegisterArea {
                status_flag1,
                status_flag2,
            } => Ok(vec![*status_flag1, *status_flag2]),
            FelicaStandardResponse::RegisterService {
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload = Vec::with_capacity(4);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "register service result is missing on success".into(),
                        )
                    })?;
                    payload.extend_from_slice(&result.remaining_blocks.to_le_bytes());
                } else if result.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "register service result must be omitted on error".into(),
                    ));
                }
                Ok(payload)
            }
            FelicaStandardResponse::ChangeSystemBlock {
                status_flag1,
                status_flag2,
            } => Ok(vec![*status_flag1, *status_flag2]),
            _ => Err(FelicaStandardError::Protocol(
                "plain response cannot be encoded as secure payload".into(),
            )),
        }
    }
}

fn parse_fixed<'a, const N: usize>(
    data: &'a [u8],
    label: &str,
) -> DriverResult<([u8; N], &'a [u8])> {
    if data.len() < N {
        return Err(DriverError::Other(format!("{label} payload too short")));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&data[..N]);
    Ok((out, &data[N..]))
}

fn parse_specification_version_data(data: &[u8]) -> DriverResult<SpecificationVersion> {
    if data.len() < 4 {
        return Err(DriverError::Other(
            "request specification version payload too short".into(),
        ));
    }
    let format_version = data[0];
    if format_version != 0x00 {
        return Err(DriverError::Other(
            "request specification version format version must be 0x00".into(),
        ));
    }
    let basic_version = OptionVersion::from_le_bytes([data[1], data[2]]);
    let option_count = data[3] as usize;
    let option_bytes_len = option_count.checked_mul(2).ok_or_else(|| {
        DriverError::Other("request specification version option bytes length overflow".into())
    })?;
    if data.len() < 4 + option_bytes_len {
        return Err(DriverError::Other(
            "request specification version option list truncated".into(),
        ));
    }
    let mut option_versions = Vec::with_capacity(option_count);
    let option_bytes = &data[4..4 + option_bytes_len];
    for chunk in option_bytes.chunks_exact(2) {
        option_versions.push(OptionVersion::from_le_bytes([chunk[0], chunk[1]]));
    }
    Ok(SpecificationVersion {
        format_version,
        basic_version,
        option_versions,
    })
}

fn parse_idm(data: &[u8]) -> DriverResult<(Idm, &[u8])> {
    parse_fixed::<IDM_LEN>(data, "IDm")
}

fn parse_pmm(data: &[u8]) -> DriverResult<(Pmm, &[u8])> {
    parse_fixed::<8>(data, "PMm")
}

fn collect_blocks(data: &[u8], block_count: usize) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::with_capacity(block_count);
    for chunk in data[..block_count * BLOCK_SIZE].chunks_exact(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        blocks.push(block);
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_idm() -> [u8; IDM_LEN] {
        [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
    }

    fn assert_protocol_error_contains<T>(result: Result<T, FelicaStandardError>, expected: &str) {
        match result {
            Err(FelicaStandardError::Protocol(message)) => {
                assert!(
                    message.contains(expected),
                    "unexpected protocol error message: {message}"
                );
            }
            Err(other) => panic!("expected FelicaStandardError::Protocol, got {other}"),
            Ok(_) => panic!("expected FelicaStandardError::Protocol, got Ok"),
        }
    }

    fn assert_driver_error_contains(result: DriverResult<FelicaStandardResponse>, expected: &str) {
        match result {
            Err(DriverError::Other(message)) => {
                assert!(
                    message.contains(expected),
                    "unexpected driver error message: {message}"
                );
            }
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(_) => panic!("expected DriverError::Other, got Ok"),
        }
    }

    #[test]
    fn from_bytes_parses_polling_with_optional_bytes() {
        let idm = sample_idm();
        let pmm = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let optional = vec![0xAA, 0xBB];

        let mut payload = vec![POLLING_RESPONSE_CODE];
        payload.extend_from_slice(&idm);
        payload.extend_from_slice(&pmm);
        payload.extend_from_slice(&optional);
        let frame = frame_with_length_prefix(&payload);

        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::Polling {
                idm: parsed_idm,
                pmm: parsed_pmm,
                optional: parsed_optional,
            } => {
                assert_eq!(parsed_idm, idm);
                assert_eq!(parsed_pmm, pmm);
                assert_eq!(parsed_optional, optional);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn from_bytes_parses_request_service_v2_dual_keys() {
        let idm = sample_idm();
        let mut payload = vec![REQUEST_SERVICE_V2_RESPONSE_CODE];
        payload.extend_from_slice(&idm);
        payload.extend_from_slice(&[0x00, 0x00, 0x41, 0x02]);
        payload.extend_from_slice(&0x1111u16.to_le_bytes());
        payload.extend_from_slice(&0x2222u16.to_le_bytes());
        payload.extend_from_slice(&0x3333u16.to_le_bytes());
        payload.extend_from_slice(&0x4444u16.to_le_bytes());
        let frame = frame_with_length_prefix(&payload);

        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestServiceV2 {
                idm: parsed_idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(parsed_idm, idm);
                assert_eq!(status_flag1, 0);
                assert_eq!(status_flag2, 0);
                let parsed_result = result.expect("missing request service v2 result");
                assert_eq!(parsed_result.crypto_id, 0x41);
                assert_eq!(
                    parsed_result.key_versions,
                    vec![
                        RequestServiceV2KeyVersion::Dual {
                            aes: 0x1111,
                            des: 0x3333
                        },
                        RequestServiceV2KeyVersion::Dual {
                            aes: 0x2222,
                            des: 0x4444
                        },
                    ]
                );
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn from_bytes_rejects_truncated_request_service_v2_dual_keys() {
        let idm = sample_idm();
        let mut payload = vec![REQUEST_SERVICE_V2_RESPONSE_CODE];
        payload.extend_from_slice(&idm);
        payload.extend_from_slice(&[0x00, 0x00, 0x41, 0x02]);
        payload.extend_from_slice(&0x1111u16.to_le_bytes());
        payload.extend_from_slice(&0x2222u16.to_le_bytes());
        payload.extend_from_slice(&0x3333u16.to_le_bytes());
        let frame = frame_with_length_prefix(&payload);

        assert_driver_error_contains(
            FelicaStandardResponse::from_bytes(&frame),
            "dual key version list truncated",
        );
    }

    #[test]
    fn from_bytes_parses_get_node_property_mac_payload() {
        let idm = sample_idm();
        let mut payload = vec![GET_NODE_PROPERTY_RESPONSE_CODE];
        payload.extend_from_slice(&idm);
        payload.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x00]);
        let frame = frame_with_length_prefix(&payload);

        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetNodeProperty {
                idm: parsed_idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(parsed_idm, idm);
                assert_eq!(status_flag1, 0);
                assert_eq!(status_flag2, 0);
                let parsed_result = result.expect("missing node property result");
                assert_eq!(
                    parsed_result.node_properties,
                    vec![
                        NodeProperty::MacCommunication { enabled: true },
                        NodeProperty::MacCommunication { enabled: false },
                    ]
                );
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn from_bytes_rejects_unknown_get_node_property_payload_length() {
        let idm = sample_idm();
        let mut payload = vec![GET_NODE_PROPERTY_RESPONSE_CODE];
        payload.extend_from_slice(&idm);
        payload.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x00, 0x01]);
        let frame = frame_with_length_prefix(&payload);

        assert_driver_error_contains(
            FelicaStandardResponse::from_bytes(&frame),
            "payload length does not match known node property format",
        );
    }

    #[test]
    fn from_bytes_parses_authentication2_v2_variant() {
        let encrypted_payload = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97];
        let mut payload = vec![AUTHENTICATION2_V2_RESPONSE_CODE];
        payload.extend_from_slice(&encrypted_payload);
        let frame = frame_with_length_prefix(&payload);

        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::Authentication2V2(auth) => {
                assert_eq!(auth.encrypted_payload, encrypted_payload);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn from_secure_bytes_parses_secure_read_success() {
        let mut block = [0u8; BLOCK_SIZE];
        for (index, byte) in block.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut data = vec![0x00, 0x00, 0x01];
        data.extend_from_slice(&block);

        let parsed = FelicaStandardResponse::from_secure_bytes(READ_COMMAND_CODE, &data).unwrap();
        match parsed {
            FelicaStandardResponse::Read {
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(status_flag1, 0);
                assert_eq!(status_flag2, 0);
                let parsed_result = result.expect("missing secure read result");
                assert_eq!(parsed_result.blocks.len(), 1);
                assert_eq!(parsed_result.blocks[0], block);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn from_secure_bytes_rejects_register_issue_id_without_remaining_blocks() {
        assert_driver_error_contains(
            FelicaStandardResponse::from_secure_bytes(
                REGISTER_ISSUE_ID_COMMAND_CODE,
                &[0x00, 0x00],
            ),
            "missing remaining block count",
        );
    }

    #[test]
    fn from_secure_bytes_rejects_unsupported_command_code() {
        assert_driver_error_contains(
            FelicaStandardResponse::from_secure_bytes(0x99, &[]),
            "unsupported secure Felica command response",
        );
    }

    #[test]
    fn to_payload_rejects_request_service_with_empty_key_versions() {
        let response = FelicaStandardResponse::RequestService {
            idm: sample_idm(),
            key_versions: Vec::new(),
        };

        assert_protocol_error_contains(response.to_payload(), "key version count out of range");
    }

    #[test]
    fn to_payload_rejects_success_read_without_encryption_without_result() {
        let response = FelicaStandardResponse::ReadWithoutEncryption {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: None,
        };

        assert_protocol_error_contains(response.to_payload(), "result is missing on success");
    }

    #[test]
    fn to_payload_rejects_error_read_without_encryption_with_result() {
        let response = FelicaStandardResponse::ReadWithoutEncryption {
            idm: sample_idm(),
            status_flag1: 0xA5,
            status_flag2: 0x00,
            result: Some(ReadWithoutEncryptionResult {
                blocks: vec![[0x00; BLOCK_SIZE]],
            }),
        };

        assert_protocol_error_contains(response.to_payload(), "result must be omitted on error");
    }

    #[test]
    fn to_payload_rejects_request_service_v2_mismatched_crypto_and_key_version_shape() {
        let dual_crypto_single_keys = FelicaStandardResponse::RequestServiceV2 {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(RequestServiceV2Result {
                crypto_id: 0x41,
                key_versions: vec![
                    RequestServiceV2KeyVersion::Single(0x1111),
                    RequestServiceV2KeyVersion::Single(0x2222),
                ],
            }),
        };
        assert_protocol_error_contains(
            dual_crypto_single_keys.to_payload(),
            "dual crypto requires dual key versions",
        );

        let single_crypto_dual_keys = FelicaStandardResponse::RequestServiceV2 {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(RequestServiceV2Result {
                crypto_id: 0x40,
                key_versions: vec![RequestServiceV2KeyVersion::Dual {
                    aes: 0x3333,
                    des: 0x4444,
                }],
            }),
        };
        assert_protocol_error_contains(
            single_crypto_dual_keys.to_payload(),
            "single crypto requires single key versions",
        );
    }

    #[test]
    fn secure_read_to_secure_payload_round_trip() {
        let mut block = [0u8; BLOCK_SIZE];
        for (index, byte) in block.iter_mut().enumerate() {
            *byte = (index as u8) ^ 0x5A;
        }
        let response = FelicaStandardResponse::Read {
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(ReadResult {
                blocks: vec![block],
            }),
        };

        let secure_payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(READ_COMMAND_CODE, &secure_payload).unwrap();
        match parsed {
            FelicaStandardResponse::Read {
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                let parsed_result = result.expect("missing secure read result");
                assert_eq!(parsed_result.blocks, vec![block]);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn to_frame_rejects_secure_response_variants() {
        let response = FelicaStandardResponse::Write {
            status_flag1: 0x00,
            status_flag2: 0x00,
        };

        assert_protocol_error_contains(response.to_frame(), "secure response requires encryption");
    }

    #[test]
    fn to_secure_payload_rejects_plain_response_variants() {
        let response = FelicaStandardResponse::RequestResponse {
            idm: sample_idm(),
            mode: 0x07,
        };

        assert_protocol_error_contains(
            response.to_secure_payload(),
            "plain response cannot be encoded as secure payload",
        );
    }

    #[test]
    fn request_code_list_to_frame_round_trip() {
        let expected_result = RequestCodeListResult {
            continue_flag: true,
            areas: vec![AreaCodeRange::new(0x1000, 0x10FF)],
            services: vec![ServiceCode::new(0x090F), ServiceCode::new(0x1208)],
        };
        let response = FelicaStandardResponse::RequestCodeList {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(expected_result.clone()),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestCodeList {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(result, Some(expected_result));
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn request_block_information_ex_to_frame_round_trip() {
        let expected_result = RequestBlockInformationExResult {
            assigned_block_counts: vec![0x0010, 0x0200],
            free_block_counts: vec![0x0002, 0x0011],
        };
        let response = FelicaStandardResponse::RequestBlockInformationEx {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(expected_result.clone()),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestBlockInformationEx {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(result, Some(expected_result));
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn request_specification_version_to_frame_round_trip() {
        let expected_spec = SpecificationVersion {
            format_version: 0x00,
            basic_version: OptionVersion::new(0x01, 0x02, 0x03),
            option_versions: vec![
                OptionVersion::new(0x04, 0x05, 0x06),
                OptionVersion::new(0x07, 0x08, 0x09),
            ],
        };
        let response = FelicaStandardResponse::RequestSpecificationVersion {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            specification_version: Some(expected_spec.clone()),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestSpecificationVersion {
                idm,
                status_flag1,
                status_flag2,
                specification_version,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(specification_version, Some(expected_spec));
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn get_platform_information_to_frame_round_trip() {
        let expected_platform_info = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let response = FelicaStandardResponse::GetPlatformInformation {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(expected_platform_info.clone()),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetPlatformInformation {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(result, Some(expected_platform_info));
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn get_container_property_to_frame_round_trip() {
        let expected_data = vec![0xAA, 0xBB, 0xCC];
        let response = FelicaStandardResponse::GetContainerProperty {
            data: expected_data.clone(),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetContainerProperty { data } => {
                assert_eq!(data, expected_data);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn authentication2_v2_to_frame_round_trip() {
        let expected_payload = vec![0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97];
        let response = FelicaStandardResponse::Authentication2V2(Authentication2V2Response {
            encrypted_payload: expected_payload.clone(),
        });

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::Authentication2V2(auth) => {
                assert_eq!(auth.encrypted_payload, expected_payload);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn secure_register_issue_id_round_trip() {
        let response = FelicaStandardResponse::RegisterIssueId {
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(RegisterIssueIdResult {
                remaining_blocks: 0x3412,
            }),
        };

        let payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(REGISTER_ISSUE_ID_COMMAND_CODE, &payload)
                .unwrap();
        match parsed {
            FelicaStandardResponse::RegisterIssueId {
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(
                    result,
                    Some(RegisterIssueIdResult {
                        remaining_blocks: 0x3412
                    })
                );
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn secure_register_service_round_trip() {
        let response = FelicaStandardResponse::RegisterService {
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(RegisterServiceResult {
                remaining_blocks: 0x00AA,
            }),
        };

        let payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(REGISTER_SERVICE_COMMAND_CODE, &payload)
                .unwrap();
        match parsed {
            FelicaStandardResponse::RegisterService {
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(
                    result,
                    Some(RegisterServiceResult {
                        remaining_blocks: 0x00AA
                    })
                );
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn to_payload_rejects_unknown_response_variant() {
        assert_protocol_error_contains(
            FelicaStandardResponse::Unknown.to_payload(),
            "cannot encode unknown response",
        );
    }

    #[test]
    fn get_system_status_to_frame_round_trip() {
        let expected_result = GetSystemStatusResult {
            flag: 0xA5,
            data: vec![0x10, 0x20, 0x30],
        };
        let response = FelicaStandardResponse::GetSystemStatus {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: expected_result.clone(),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetSystemStatus {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(result, expected_result);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn get_area_information_to_frame_round_trip() {
        let expected_result = GetAreaInformationResult {
            node_code: 0x2201,
            data: [0x7E, 0x01],
        };
        let response = FelicaStandardResponse::GetAreaInformation {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(expected_result),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetAreaInformation {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(result, Some(expected_result));
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn authentication1_v2_to_frame_round_trip() {
        let challenge_1b = [0x11; 16];
        let challenge_2a = [0x22; 16];
        let challenge_3c = [0x33; 4];
        let response = FelicaStandardResponse::Authentication1V2 {
            idm: sample_idm(),
            challenge_1b,
            challenge_2a,
            challenge_3c,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::Authentication1V2 {
                idm,
                challenge_1b: parsed_1b,
                challenge_2a: parsed_2a,
                challenge_3c: parsed_3c,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(parsed_1b, challenge_1b);
                assert_eq!(parsed_2a, challenge_2a);
                assert_eq!(parsed_3c, challenge_3c);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn get_container_id_to_frame_round_trip() {
        let container_idm = [0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6, 0x97, 0x88];
        let response = FelicaStandardResponse::GetContainerId { container_idm };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetContainerId {
                container_idm: parsed_idm,
            } => {
                assert_eq!(parsed_idm, container_idm);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn secure_write_round_trip() {
        let response = FelicaStandardResponse::Write {
            status_flag1: 0x12,
            status_flag2: 0x34,
        };

        let payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(WRITE_COMMAND_CODE, &payload).unwrap();
        match parsed {
            FelicaStandardResponse::Write {
                status_flag1,
                status_flag2,
            } => {
                assert_eq!(status_flag1, 0x12);
                assert_eq!(status_flag2, 0x34);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn secure_register_area_round_trip() {
        let response = FelicaStandardResponse::RegisterArea {
            status_flag1: 0x00,
            status_flag2: 0x7F,
        };

        let payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(REGISTER_AREA_COMMAND_CODE, &payload)
                .unwrap();
        match parsed {
            FelicaStandardResponse::RegisterArea {
                status_flag1,
                status_flag2,
            } => {
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x7F);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn secure_change_system_block_round_trip() {
        let response = FelicaStandardResponse::ChangeSystemBlock {
            status_flag1: 0xAB,
            status_flag2: 0xCD,
        };

        let payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(CHANGE_SYSTEM_BLOCK_COMMAND_CODE, &payload)
                .unwrap();
        match parsed {
            FelicaStandardResponse::ChangeSystemBlock {
                status_flag1,
                status_flag2,
            } => {
                assert_eq!(status_flag1, 0xAB);
                assert_eq!(status_flag2, 0xCD);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn to_secure_payload_rejects_secure_read_without_result_on_success() {
        let response = FelicaStandardResponse::Read {
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: None,
        };

        assert_protocol_error_contains(
            response.to_secure_payload(),
            "secure read result is missing on success",
        );
    }

    #[test]
    fn to_payload_rejects_empty_container_property_data() {
        let response = FelicaStandardResponse::GetContainerProperty { data: Vec::new() };
        assert_protocol_error_contains(
            response.to_payload(),
            "response data must contain at least one byte",
        );
    }

    #[test]
    fn to_payload_rejects_mixed_get_node_property_types() {
        let response = FelicaStandardResponse::GetNodeProperty {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(GetNodePropertyResult {
                node_properties: vec![
                    NodeProperty::MacCommunication { enabled: true },
                    NodeProperty::ValueLimitedPurseService {
                        enabled: true,
                        upper_limit: 100,
                        lower_limit: -100,
                        generation_number: 1,
                    },
                ],
            }),
        };

        assert_protocol_error_contains(response.to_payload(), "cannot mix property types");
    }

    #[test]
    fn request_response_to_frame_round_trip() {
        let response = FelicaStandardResponse::RequestResponse {
            idm: sample_idm(),
            mode: 0x07,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestResponse { idm, mode } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(mode, 0x07);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn request_system_code_to_frame_round_trip() {
        let expected_codes = vec![0x0003, 0x12FC];
        let response = FelicaStandardResponse::RequestSystemCode {
            idm: sample_idm(),
            system_codes: expected_codes.clone(),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestSystemCode { idm, system_codes } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(system_codes, expected_codes);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn request_block_information_to_frame_round_trip() {
        let expected_counts = vec![0x0011, 0x0202, 0x3300];
        let response = FelicaStandardResponse::RequestBlockInformation {
            idm: sample_idm(),
            block_counts: expected_counts.clone(),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestBlockInformation { idm, block_counts } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(block_counts, expected_counts);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn set_parameter_to_frame_round_trip() {
        let response = FelicaStandardResponse::SetParameter {
            idm: sample_idm(),
            status_flag1: 0xA1,
            status_flag2: 0xB2,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::SetParameter {
                idm,
                status_flag1,
                status_flag2,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0xA1);
                assert_eq!(status_flag2, 0xB2);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn reset_mode_to_frame_round_trip() {
        let response = FelicaStandardResponse::ResetMode {
            idm: sample_idm(),
            status_flag1: 0x11,
            status_flag2: 0x22,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::ResetMode {
                idm,
                status_flag1,
                status_flag2,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x11);
                assert_eq!(status_flag2, 0x22);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn get_container_issue_information_to_frame_round_trip() {
        let expected = ContainerInformation::new(
            [0x01, 0x02, 0x03, 0x04, 0x05],
            [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
            ],
        );
        let response = FelicaStandardResponse::GetContainerIssueInformation {
            idm: sample_idm(),
            container_information: expected,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetContainerIssueInformation {
                idm,
                container_information,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(container_information, expected);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn search_service_code_area_to_frame_round_trip() {
        let response = FelicaStandardResponse::SearchServiceCode {
            idm: sample_idm(),
            result: Some(SearchServiceCodeResult::Area {
                area_code: 0x1000,
                end_service_code: 0x10FF,
            }),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::SearchServiceCode { idm, result } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(
                    result,
                    Some(SearchServiceCodeResult::Area {
                        area_code: 0x1000,
                        end_service_code: 0x10FF
                    })
                );
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn search_service_code_none_to_frame_round_trip() {
        let response = FelicaStandardResponse::SearchServiceCode {
            idm: sample_idm(),
            result: None,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::SearchServiceCode { idm, result } => {
                assert_eq!(idm, sample_idm());
                assert!(result.is_none());
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn authentication1_to_frame_round_trip() {
        let response = FelicaStandardResponse::Authentication1 {
            idm: sample_idm(),
            challenge_1b: [0xAA; 8],
            challenge_2a: [0x55; 8],
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::Authentication1 {
                idm,
                challenge_1b,
                challenge_2a,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(challenge_1b, [0xAA; 8]);
                assert_eq!(challenge_2a, [0x55; 8]);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn to_payload_rejects_request_system_code_without_entries() {
        let response = FelicaStandardResponse::RequestSystemCode {
            idm: sample_idm(),
            system_codes: Vec::new(),
        };
        assert_protocol_error_contains(response.to_payload(), "must include at least one entry");
    }

    #[test]
    fn to_payload_rejects_request_block_information_ex_length_mismatch() {
        let response = FelicaStandardResponse::RequestBlockInformationEx {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(RequestBlockInformationExResult {
                assigned_block_counts: vec![0x0001, 0x0002],
                free_block_counts: vec![0x0003],
            }),
        };
        assert_protocol_error_contains(response.to_payload(), "assigned/free length mismatch");
    }

    #[test]
    fn to_payload_rejects_get_platform_information_missing_result_on_success() {
        let response = FelicaStandardResponse::GetPlatformInformation {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: None,
        };
        assert_protocol_error_contains(response.to_payload(), "result is missing on success");
    }

    #[test]
    fn to_payload_rejects_request_specification_version_non_zero_format() {
        let response = FelicaStandardResponse::RequestSpecificationVersion {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            specification_version: Some(SpecificationVersion {
                format_version: 0x01,
                basic_version: OptionVersion::new(0x01, 0x02, 0x03),
                option_versions: vec![],
            }),
        };
        assert_protocol_error_contains(response.to_payload(), "format version must be 0x00");
    }
}
