use super::{
    AreaCodeRange, Authentication2Response, BLOCK_SIZE, CHANGE_SYSTEM_BLOCK_COMMAND_CODE,
    ContainerInformation, FelicaStandardError, GetAreaInformationResult, GetNodePropertyResult,
    GetSystemStatusResult, IDM_LEN, MAX_BLOCK_LIST_LEN, MAX_NODE_CODES, MAX_NODE_PROPERTY_CODES,
    MAX_SERVICE_CODES, NodeProperty, READ_COMMAND_CODE, REGISTER_AREA_COMMAND_CODE,
    REGISTER_ISSUE_ID_COMMAND_CODE, REGISTER_SERVICE_COMMAND_CODE, ReadResult,
    ReadWithoutEncryptionResult, RegisterIssueIdResult, RegisterServiceResult,
    RequestBlockInformationExResult, RequestCodeListResult, RequestServiceV2KeyVersion,
    RequestServiceV2Result, SearchServiceCodeResult, ServiceCode, WRITE_COMMAND_CODE,
    frame_with_length_prefix,
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
    RequestBlockInformationEx {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RequestBlockInformationExResult>,
    },
    RequestCodeList {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RequestCodeListResult>,
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
    GetContainerProperty {
        data: Vec<u8>,
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
    GetSystemStatus {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: GetSystemStatusResult,
    },
    Authentication1 {
        idm: Idm,
        challenge_1b: [u8; 8],
        challenge_2a: [u8; 8],
    },
    Authentication2(Authentication2Response),
    Read {
        status_flag1: u8,
        status_flag2: u8,
        result: Option<ReadResult>,
    },
    Write {
        status_flag1: u8,
        status_flag2: u8,
    },
    RequestServiceV2 {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RequestServiceV2Result>,
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
        if code == 0x13 {
            return Self::parse_authentication2(data);
        }
        if code == 0x2F {
            return Self::parse_get_container_property(data);
        }
        Self::ensure_response_len(data, 10, "short Felica response")?;
        let (idm, _rest) = parse_idm(&data[2..])?;
        match code {
            0x01 => Self::parse_polling(idm, data),
            0x03 => Self::parse_request_service(idm, data),
            0x33 => Self::parse_request_service_v2(idm, data),
            0x05 => Self::parse_request_response(idm, data),
            0x07 => Self::parse_read_without_encryption(idm, data),
            0x09 => Self::parse_write_without_encryption(idm, data),
            0x0B => Self::parse_search_service_code(idm, data),
            0x0D => Self::parse_request_systemcode(idm, data),
            0x0F => Self::parse_request_block_information(idm, data),
            0x1F => Self::parse_request_block_information_ex(idm, data),
            0x1B => Self::parse_request_code_list(idm, data),
            0x21 => Self::parse_set_parameter(idm, data),
            0x23 => Self::parse_get_container_issue_information(idm, data),
            0x25 => Self::parse_get_area_information(idm, data),
            0x29 => Self::parse_get_node_property(idm, data),
            0x39 => Self::parse_get_system_status(idm, data),
            0x11 => Self::parse_authentication1(idm, data),
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
                payload.push(0x01);
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
                payload.push(0x03);
                payload.extend_from_slice(idm);
                payload.push(key_versions.len() as u8);
                for version in key_versions {
                    payload.extend_from_slice(&version.to_le_bytes());
                }
                Ok(payload)
            }
            FelicaStandardResponse::RequestResponse { idm, mode } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 1);
                payload.push(0x05);
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
                payload.push(0x07);
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
                payload.push(0x09);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                Ok(payload)
            }
            FelicaStandardResponse::SearchServiceCode { idm, result } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 4);
                payload.push(0x0B);
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
                payload.push(0x0D);
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
                payload.push(0x0F);
                payload.extend_from_slice(idm);
                payload.push(block_counts.len() as u8);
                for count in block_counts {
                    payload.extend_from_slice(&count.to_le_bytes());
                }
                Ok(payload)
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
                    payload.push(0x1F);
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
                    payload.push(0x1F);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
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
                    payload.push(0x1B);
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
                    payload.push(0x1B);
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
                payload.push(0x21);
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
                payload.push(0x23);
                payload.extend_from_slice(idm);
                payload
                    .extend_from_slice(&container_information.format_version_carrier_information);
                payload.extend_from_slice(&container_information.mobile_phone_model_information);
                Ok(payload)
            }
            FelicaStandardResponse::GetContainerProperty { data } => {
                if data.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "get container property response data must contain at least one byte"
                            .into(),
                    ));
                }
                let mut payload = Vec::with_capacity(1 + data.len());
                payload.push(0x2F);
                payload.extend_from_slice(data);
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
                    payload.push(0x25);
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
                    payload.push(0x25);
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
                    payload.push(0x29);
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
                    payload.push(0x29);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
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
                payload.push(0x39);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                payload.push(result.flag);
                payload.push(result.data.len() as u8);
                payload.extend_from_slice(&result.data);
                Ok(payload)
            }
            FelicaStandardResponse::Authentication1 {
                idm,
                challenge_1b,
                challenge_2a,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 16);
                payload.push(0x11);
                payload.extend_from_slice(idm);
                payload.extend_from_slice(challenge_1b);
                payload.extend_from_slice(challenge_2a);
                Ok(payload)
            }
            FelicaStandardResponse::Authentication2(auth) => {
                let mut payload = Vec::with_capacity(1 + auth.encrypted_payload.len());
                payload.push(0x13);
                payload.extend_from_slice(&auth.encrypted_payload);
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
                payload.push(0x33);
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
