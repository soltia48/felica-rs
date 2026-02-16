use super::{
    AreaCodeRange, Authentication2Response, BLOCK_SIZE, CHANGE_SYSTEM_BLOCK_COMMAND_CODE,
    FelicaStandardError, IDM_LEN, MAX_BLOCK_LIST_LEN, MAX_NODE_CODES, MAX_SERVICE_CODES,
    READ_COMMAND_CODE, REGISTER_AREA_COMMAND_CODE, REGISTER_ISSUE_ID_COMMAND_CODE,
    REGISTER_SERVICE_COMMAND_CODE, RequestServiceV2KeyVersion, SearchServiceCodeResult,
    ServiceCode, WRITE_COMMAND_CODE, frame_with_length_prefix,
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
        blocks: Option<Vec<[u8; BLOCK_SIZE]>>,
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
    RequestCodeList {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        continue_flag: bool,
        areas: Vec<AreaCodeRange>,
        services: Vec<ServiceCode>,
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
        blocks: Option<Vec<[u8; BLOCK_SIZE]>>,
    },
    Write {
        status_flag1: u8,
        status_flag2: u8,
    },
    RequestServiceV2 {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        crypto_id: Option<u8>,
        key_versions: Option<Vec<RequestServiceV2KeyVersion>>,
    },
    RegisterIssueId {
        status_flag1: u8,
        status_flag2: u8,
        remaining_blocks: Option<u16>,
    },
    RegisterArea {
        status_flag1: u8,
        status_flag2: u8,
    },
    RegisterService {
        status_flag1: u8,
        status_flag2: u8,
        remaining_blocks: Option<u16>,
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
            0x1B => Self::parse_request_code_list(idm, data),
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
        let mut crypto_id = None;
        let mut key_versions = None;

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
            crypto_id = Some(parsed_crypto_id);
            key_versions = Some(parsed_versions);
        }

        Ok(FelicaStandardResponse::RequestServiceV2 {
            idm,
            status_flag1,
            status_flag2,
            crypto_id,
            key_versions,
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
                blocks: None,
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
            blocks: Some(blocks),
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

    fn parse_request_code_list(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 15, "short request code list response")?;
        let status_flag1 = data[10];
        let status_flag2 = data[11];
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
            continue_flag,
            areas,
            services,
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
                blocks: None,
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
            blocks: Some(blocks),
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
        let remaining_blocks = if status_flag1 == 0 {
            if data.len() < 4 {
                return Err(DriverError::Other(
                    "register issue id response missing remaining block count".into(),
                ));
            }
            Some(u16::from_le_bytes([data[2], data[3]]))
        } else {
            None
        };
        Ok(FelicaStandardResponse::RegisterIssueId {
            status_flag1,
            status_flag2,
            remaining_blocks,
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
        let remaining_blocks = if status_flag1 == 0 {
            if data.len() < 4 {
                return Err(DriverError::Other(
                    "register service response missing remaining block count".into(),
                ));
            }
            Some(u16::from_le_bytes([data[2], data[3]]))
        } else {
            None
        };
        Ok(FelicaStandardResponse::RegisterService {
            status_flag1,
            status_flag2,
            remaining_blocks,
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
                blocks,
            } => {
                let block_len = blocks.as_ref().map(|values| values.len()).unwrap_or(0);
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 3 + block_len * BLOCK_SIZE);
                payload.push(0x07);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let blocks = blocks.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "read without encryption missing block data".into(),
                        )
                    })?;
                    if blocks.is_empty() || blocks.len() > MAX_BLOCK_LIST_LEN {
                        return Err(FelicaStandardError::Protocol(
                            "read without encryption block count out of range".into(),
                        ));
                    }
                    payload.push(blocks.len() as u8);
                    for block in blocks {
                        payload.extend_from_slice(block);
                    }
                } else if blocks.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "read without encryption blocks must be omitted on error".into(),
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
            FelicaStandardResponse::RequestCodeList {
                idm,
                status_flag1,
                status_flag2,
                continue_flag,
                areas,
                services,
            } => {
                if areas.len() > u8::MAX as usize {
                    return Err(FelicaStandardError::Protocol(
                        "request code list area count out of range".into(),
                    ));
                }
                if services.len() > u8::MAX as usize {
                    return Err(FelicaStandardError::Protocol(
                        "request code list service count out of range".into(),
                    ));
                }
                let mut payload = Vec::with_capacity(
                    1 + IDM_LEN + 2 + 1 + 1 + areas.len() * 4 + 1 + services.len() * 2,
                );
                payload.push(0x1B);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                payload.push(if *continue_flag { 0x01 } else { 0x00 });
                payload.push(areas.len() as u8);
                for area in areas {
                    payload.extend_from_slice(&area.area_code.to_le_bytes());
                    payload.extend_from_slice(&area.end_service_code.to_le_bytes());
                }
                payload.push(services.len() as u8);
                for service in services {
                    payload.extend_from_slice(&service.raw().to_le_bytes());
                }
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
                crypto_id,
                key_versions,
            } => {
                let kv_len = key_versions
                    .as_ref()
                    .map(|versions| versions.len())
                    .unwrap_or(0);
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 4 + kv_len * 4);
                payload.push(0x33);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let crypto_id = *crypto_id.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "request service v2 missing crypto identifier".into(),
                        )
                    })?;
                    let key_versions = key_versions.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "request service v2 missing key version list".into(),
                        )
                    })?;
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
                } else if crypto_id.is_some() || key_versions.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "request service v2 key versions must be omitted on error".into(),
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
                blocks,
            } => {
                let block_len = blocks.as_ref().map(|values| values.len()).unwrap_or(0);
                let mut payload = Vec::with_capacity(2 + 1 + block_len * BLOCK_SIZE);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let blocks = blocks.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol("secure read missing block data".into())
                    })?;
                    if blocks.is_empty() || blocks.len() > MAX_BLOCK_LIST_LEN {
                        return Err(FelicaStandardError::Protocol(
                            "secure read block count out of range".into(),
                        ));
                    }
                    payload.push(blocks.len() as u8);
                    for block in blocks {
                        payload.extend_from_slice(block);
                    }
                } else if blocks.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "secure read blocks must be omitted on error".into(),
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
                remaining_blocks,
            } => {
                let mut payload = Vec::with_capacity(4);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let remaining_blocks = remaining_blocks.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "register issue id missing remaining block count".into(),
                        )
                    })?;
                    payload.extend_from_slice(&remaining_blocks.to_le_bytes());
                } else if remaining_blocks.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "register issue id remaining blocks must be omitted on error".into(),
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
                remaining_blocks,
            } => {
                let mut payload = Vec::with_capacity(4);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let remaining_blocks = remaining_blocks.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "register service missing remaining block count".into(),
                        )
                    })?;
                    payload.extend_from_slice(&remaining_blocks.to_le_bytes());
                } else if remaining_blocks.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "register service remaining blocks must be omitted on error".into(),
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
