use super::{
    Authentication2Response, BLOCK_SIZE, CHANGE_SYSTEM_BLOCK_COMMAND_CODE, MAX_BLOCK_LIST_LEN,
    MAX_SERVICE_CODES, READ_COMMAND_CODE, REGISTER_AREA_COMMAND_CODE,
    REGISTER_ISSUE_ID_COMMAND_CODE, REGISTER_SERVICE_COMMAND_CODE, RequestServiceV2KeyVersion,
    SearchServiceCodeResult, ServiceCode, WRITE_COMMAND_CODE,
};
use crate::driver::errors::{DriverError, Result as DriverResult};

#[derive(Debug)]
pub enum FelicaStandardResponse {
    Polling {
        idm: Vec<u8>,
        pmm: Vec<u8>,
        optional: Vec<u8>,
    },
    RequestService {
        idm: Vec<u8>,
        key_versions: Vec<u16>,
    },
    RequestResponse {
        idm: Vec<u8>,
        mode: u8,
    },
    ReadWithoutEncryption {
        idm: Vec<u8>,
        status_flag1: u8,
        status_flag2: u8,
        blocks: Vec<[u8; BLOCK_SIZE]>,
    },
    WriteWithoutEncryption {
        idm: Vec<u8>,
        status_flag1: u8,
        status_flag2: u8,
    },
    SearchServiceCode {
        idm: Vec<u8>,
        result: Option<SearchServiceCodeResult>,
    },
    RequestSystemCode {
        idm: Vec<u8>,
        system_codes: Vec<u16>,
    },
    RequestBlockInformation {
        idm: Vec<u8>,
        block_counts: Vec<u16>,
    },
    Authentication1 {
        idm: Vec<u8>,
        challenge_1b: [u8; 8],
        challenge_2a: [u8; 8],
    },
    Authentication2(Authentication2Response),
    Read {
        status_flag1: u8,
        status_flag2: u8,
        blocks: Vec<[u8; BLOCK_SIZE]>,
    },
    Write {
        status_flag1: u8,
        status_flag2: u8,
    },
    RequestServiceV2 {
        idm: Vec<u8>,
        status_flag1: u8,
        status_flag2: u8,
        crypto_id: u8,
        key_versions: Vec<RequestServiceV2KeyVersion>,
    },
    RegisterIssueId {
        status_flag1: u8,
        status_flag2: u8,
        remaining_blocks: u16,
    },
    RegisterArea {
        status_flag1: u8,
        status_flag2: u8,
    },
    RegisterService {
        status_flag1: u8,
        status_flag2: u8,
        remaining_blocks: u16,
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
        let code = data[1];
        if code == 0x13 {
            return Self::parse_authentication2(data);
        }
        Self::ensure_response_len(data, 10, "short Felica response")?;
        let idm = data[2..10].to_vec();
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

    fn parse_polling(idm: Vec<u8>, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 18, "short polling response")?;
        let pmm = data[10..18].to_vec();
        Ok(FelicaStandardResponse::Polling {
            idm,
            pmm,
            optional: data.get(18..).unwrap_or(&[]).to_vec(),
        })
    }

    fn parse_request_service(idm: Vec<u8>, data: &[u8]) -> DriverResult<Self> {
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

    fn parse_request_service_v2(idm: Vec<u8>, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short request service v2 response header")?;
        let status_flag1 = data[10];
        let status_flag2 = data[11];
        let mut crypto_id = 0u8;
        let mut key_versions = Vec::new();

        if status_flag1 == 0 {
            Self::ensure_response_len(
                data,
                14,
                "short request service v2 crypto identifier response",
            )?;
            crypto_id = data[12];
            let node_count = data[13] as usize;
            if node_count == 0 || node_count > MAX_SERVICE_CODES {
                return Err(DriverError::Other(
                    "request service v2 node count must be between 1 and 32".into(),
                ));
            }
            let payload = &data[14..];
            if matches!(crypto_id, 0x41 | 0x43) {
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
                    key_versions.push(RequestServiceV2KeyVersion::Dual { aes, des });
                }
            } else {
                let expected = node_count * 2;
                if payload.len() < expected {
                    return Err(DriverError::Other(
                        "request service v2 key version list truncated".into(),
                    ));
                }
                for chunk in payload[..expected].chunks_exact(2) {
                    key_versions.push(RequestServiceV2KeyVersion::Single(u16::from_le_bytes([
                        chunk[0], chunk[1],
                    ])));
                }
            }
        }

        Ok(FelicaStandardResponse::RequestServiceV2 {
            idm,
            status_flag1,
            status_flag2,
            crypto_id,
            key_versions,
        })
    }

    fn parse_request_response(idm: Vec<u8>, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 11, "short request response payload")?;
        Ok(FelicaStandardResponse::RequestResponse {
            idm,
            mode: data[10],
        })
    }

    fn parse_read_without_encryption(idm: Vec<u8>, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short read without encryption response")?;
        let sf1 = data[10];
        let sf2 = data[11];
        if sf1 != 0 || sf2 != 0 {
            return Ok(FelicaStandardResponse::ReadWithoutEncryption {
                idm,
                status_flag1: sf1,
                status_flag2: sf2,
                blocks: Vec::new(),
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
        let mut blocks = Vec::with_capacity(block_count);
        for chunk in data[13..13 + block_count * BLOCK_SIZE].chunks_exact(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(chunk);
            blocks.push(block);
        }
        Ok(FelicaStandardResponse::ReadWithoutEncryption {
            idm,
            status_flag1: sf1,
            status_flag2: sf2,
            blocks,
        })
    }

    fn parse_write_without_encryption(idm: Vec<u8>, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short write without encryption response")?;
        let sf1 = data[10];
        let sf2 = data[11];
        Ok(FelicaStandardResponse::WriteWithoutEncryption {
            idm,
            status_flag1: sf1,
            status_flag2: sf2,
        })
    }

    fn parse_search_service_code(idm: Vec<u8>, data: &[u8]) -> DriverResult<Self> {
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
                end_service_index: u16::from_le_bytes([payload[2], payload[3]]),
            })
        } else {
            return Err(DriverError::Other(
                "search service code response must contain 2 or 4 bytes".into(),
            ));
        };
        Ok(FelicaStandardResponse::SearchServiceCode { idm, result })
    }

    fn parse_request_systemcode(idm: Vec<u8>, data: &[u8]) -> DriverResult<Self> {
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

    fn parse_request_block_information(idm: Vec<u8>, data: &[u8]) -> DriverResult<Self> {
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

    fn parse_authentication1(idm: Vec<u8>, data: &[u8]) -> DriverResult<Self> {
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
        if sf1 != 0 || sf2 != 0 {
            return Ok(FelicaStandardResponse::Read {
                status_flag1: sf1,
                status_flag2: sf2,
                blocks: Vec::new(),
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
        let mut blocks = Vec::with_capacity(block_count);
        for chunk in data[3..3 + block_count * BLOCK_SIZE].chunks_exact(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(chunk);
            blocks.push(block);
        }
        Ok(FelicaStandardResponse::Read {
            status_flag1: sf1,
            status_flag2: sf2,
            blocks,
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
        if data.len() < 4 {
            return Err(DriverError::Other(
                "register issue id response shorter than status flags".into(),
            ));
        }
        Ok(FelicaStandardResponse::RegisterIssueId {
            status_flag1: data[0],
            status_flag2: data[1],
            remaining_blocks: u16::from_le_bytes([data[2], data[3]]),
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
        if data.len() < 4 {
            return Err(DriverError::Other(
                "register service response shorter than status flags".into(),
            ));
        }
        Ok(FelicaStandardResponse::RegisterService {
            status_flag1: data[0],
            status_flag2: data[1],
            remaining_blocks: u16::from_le_bytes([data[2], data[3]]),
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
}
