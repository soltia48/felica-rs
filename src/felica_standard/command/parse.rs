use super::*;
use std::ops::RangeInclusive;

impl FelicaStandardCommand {
    pub fn parse_frame(frame: &[u8]) -> Result<Self, FelicaStandardError> {
        if frame.is_empty() {
            return Err(FelicaStandardError::Protocol("empty Felica frame".into()));
        }
        let expected_len = frame[0] as usize;
        if expected_len != frame.len() {
            return Err(FelicaStandardError::Protocol(
                "length byte does not match frame length".into(),
            ));
        }
        Self::parse_payload(&frame[1..])
    }

    pub fn parse_payload(payload: &[u8]) -> Result<Self, FelicaStandardError> {
        let (&command, body) = payload
            .split_first()
            .ok_or_else(|| FelicaStandardError::Protocol("empty command payload".into()))?;

        match command {
            POLLING_COMMAND_CODE => Self::parse_polling(body),
            REQUEST_SERVICE_COMMAND_CODE => Self::parse_request_service(body),
            REQUEST_RESPONSE_COMMAND_CODE => Self::parse_request_response(body),
            READ_WITHOUT_ENCRYPTION_COMMAND_CODE => Self::parse_read_without_encryption(body),
            WRITE_WITHOUT_ENCRYPTION_COMMAND_CODE => Self::parse_write_without_encryption(body),
            SEARCH_SERVICE_CODE_COMMAND_CODE => Self::parse_search_service_code(body),
            REQUEST_SYSTEM_CODE_COMMAND_CODE => Self::parse_request_system_code(body),
            REQUEST_BLOCK_INFORMATION_COMMAND_CODE => Self::parse_request_block_information(body),
            AUTHENTICATION1_COMMAND_CODE => Self::parse_authentication1(body),
            AUTHENTICATION2_COMMAND_CODE => Self::parse_authentication2(body),
            REQUEST_CODE_LIST_COMMAND_CODE => Self::parse_request_code_list(body),
            REQUEST_BLOCK_INFORMATION_EX_COMMAND_CODE => {
                Self::parse_request_block_information_ex(body)
            }
            SET_PARAMETER_COMMAND_CODE => Self::parse_set_parameter(body),
            GET_CONTAINER_ISSUE_INFORMATION_COMMAND_CODE => {
                Self::parse_get_container_issue_information(body)
            }
            GET_AREA_INFORMATION_COMMAND_CODE => Self::parse_get_area_information(body),
            GET_NODE_PROPERTY_COMMAND_CODE => Self::parse_get_node_property(body),
            GET_CONTAINER_PROPERTY_COMMAND_CODE => Self::parse_get_container_property(body),
            REQUEST_SERVICE_V2_COMMAND_CODE => Self::parse_request_service_v2(body),
            GET_SYSTEM_STATUS_COMMAND_CODE => Self::parse_get_system_status(body),
            REQUEST_PRODUCT_INFORMATION_COMMAND_CODE => {
                Self::parse_request_product_information(body)
            }
            REQUEST_SPECIFICATION_VERSION_COMMAND_CODE => {
                Self::parse_request_specification_version(body)
            }
            RESET_MODE_COMMAND_CODE => Self::parse_reset_mode(body),
            GET_CONTAINER_ID_COMMAND_CODE => Self::parse_get_container_id(body),
            // A secure command travels encrypted inside a session, so its
            // payload is not readable here; see [`Self::parse_secure_payload`].
            code if is_secure_command_code(code) => Err(FelicaStandardError::Protocol(
                "secure command payload requires decryption".into(),
            )),
            _ => Err(FelicaStandardError::Protocol(format!(
                "unsupported command code: 0x{command:02X}"
            ))),
        }
    }

    fn parse_polling(body: &[u8]) -> Result<Self, FelicaStandardError> {
        if body.len() < 4 {
            return Err(FelicaStandardError::Protocol(
                "polling payload too short".into(),
            ));
        }
        Ok(FelicaStandardCommand::Polling {
            system_code: u16::from_be_bytes([body[0], body[1]]),
            request_code: body[2],
            time_slots: body[3],
        })
    }

    fn parse_request_service(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        let (service_codes, _consumed) =
            take_service_code_list(rest, MAX_SERVICE_CODES, "request service")?;
        Ok(FelicaStandardCommand::RequestService { idm, service_codes })
    }

    fn parse_request_response(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        if !rest.is_empty() {
            return Err(FelicaStandardError::Protocol(
                "request response payload has trailing bytes".into(),
            ));
        }
        Ok(FelicaStandardCommand::RequestResponse { idm })
    }

    fn parse_read_without_encryption(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        let (service_codes, rest) =
            take_service_code_list(rest, MAX_RW_SERVICE_CODES, "read without encryption")?;
        let (block_count, rest) = take_count(
            rest,
            1..=MAX_BLOCK_COUNT,
            "read without encryption",
            "block",
        )?;
        let (block_list, _rest) = take_block_list(rest, block_count)?;
        Ok(FelicaStandardCommand::ReadWithoutEncryption {
            idm,
            service_codes,
            block_list,
        })
    }

    fn parse_write_without_encryption(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        let (service_codes, rest) =
            take_service_code_list(rest, MAX_RW_SERVICE_CODES, "write without encryption")?;
        let (block_count, rest) = take_count(
            rest,
            1..=MAX_BLOCK_COUNT,
            "write without encryption",
            "block",
        )?;
        let (block_list, rest) = take_block_list(rest, block_count)?;
        let expected_len = block_count.checked_mul(BLOCK_SIZE).ok_or_else(|| {
            FelicaStandardError::Protocol("write without encryption data length overflow".into())
        })?;
        let data = rest
            .get(..expected_len)
            .ok_or_else(|| {
                FelicaStandardError::Protocol("write without encryption data truncated".into())
            })?
            .to_vec();
        Ok(FelicaStandardCommand::WriteWithoutEncryption {
            idm,
            service_codes,
            block_list,
            data,
        })
    }

    fn parse_search_service_code(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        if rest.len() < 2 {
            return Err(FelicaStandardError::Protocol(
                "search service code payload too short".into(),
            ));
        }
        Ok(FelicaStandardCommand::SearchServiceCode {
            idm,
            service_index: u16::from_le_bytes([rest[0], rest[1]]),
        })
    }

    fn parse_request_system_code(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        if !rest.is_empty() {
            return Err(FelicaStandardError::Protocol(
                "request system code payload has trailing bytes".into(),
            ));
        }
        Ok(FelicaStandardCommand::RequestSystemCode { idm })
    }

    fn parse_request_block_information(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        let (node_codes, _rest) = take_u16_list(
            rest,
            1..=MAX_NODE_CODES,
            "request block information",
            "node",
        )?;
        Ok(FelicaStandardCommand::RequestBlockInformation { idm, node_codes })
    }

    fn parse_authentication1(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        let mut cursor = 0usize;
        let area_count = *rest.get(cursor).ok_or_else(|| {
            FelicaStandardError::Protocol("authentication1 missing area count".into())
        })? as usize;
        cursor += 1;
        if area_count > MAX_SERVICE_CODES {
            return Err(FelicaStandardError::Protocol(
                "authentication1 area count out of range".into(),
            ));
        }
        let areas = parse_u16_list_le(&rest[cursor..], area_count)?;
        cursor += area_count * 2;
        let service_count = *rest.get(cursor).ok_or_else(|| {
            FelicaStandardError::Protocol("authentication1 missing service count".into())
        })? as usize;
        cursor += 1;
        if service_count > MAX_SERVICE_CODES {
            return Err(FelicaStandardError::Protocol(
                "authentication1 service count out of range".into(),
            ));
        }
        let services = parse_u16_list_le(&rest[cursor..], service_count)?;
        cursor += service_count * 2;
        let challenge_1a = rest.get(cursor..cursor + 8).ok_or_else(|| {
            FelicaStandardError::Protocol("authentication1 missing challenge1a".into())
        })?;
        let mut challenge_bytes = [0u8; 8];
        challenge_bytes.copy_from_slice(challenge_1a);
        Ok(FelicaStandardCommand::Authentication1 {
            idm,
            areas,
            services,
            challenge_1a: challenge_bytes,
        })
    }

    fn parse_authentication2(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        let challenge_2b = rest.get(..8).ok_or_else(|| {
            FelicaStandardError::Protocol("authentication2 missing challenge2b".into())
        })?;
        let mut challenge_bytes = [0u8; 8];
        challenge_bytes.copy_from_slice(challenge_2b);
        Ok(FelicaStandardCommand::Authentication2 {
            idm,
            challenge_2b: challenge_bytes,
        })
    }

    fn parse_request_code_list(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        if rest.len() < 4 {
            return Err(FelicaStandardError::Protocol(
                "request code list payload too short".into(),
            ));
        }
        if rest.len() > 4 {
            return Err(FelicaStandardError::Protocol(
                "request code list payload has trailing bytes".into(),
            ));
        }
        Ok(FelicaStandardCommand::RequestCodeList {
            idm,
            parent_node_code: u16::from_le_bytes([rest[0], rest[1]]),
            index: u16::from_le_bytes([rest[2], rest[3]]),
        })
    }

    fn parse_request_block_information_ex(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        let (node_codes, _rest) = take_u16_list(
            rest,
            1..=MAX_NODE_CODES,
            "request block information ex",
            "node",
        )?;
        Ok(FelicaStandardCommand::RequestBlockInformationEx { idm, node_codes })
    }

    fn parse_set_parameter(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        if rest.len() < 8 {
            return Err(FelicaStandardError::Protocol(
                "set parameter payload too short".into(),
            ));
        }
        if rest.len() > 8 {
            return Err(FelicaStandardError::Protocol(
                "set parameter payload has trailing bytes".into(),
            ));
        }
        if rest[..4].iter().any(|value| *value != 0x00) {
            return Err(FelicaStandardError::Protocol(
                "set parameter reserved bytes D0-D3 must be 0x00".into(),
            ));
        }
        if rest[6..8].iter().any(|value| *value != 0x00) {
            return Err(FelicaStandardError::Protocol(
                "set parameter reserved bytes D6-D7 must be 0x00".into(),
            ));
        }
        let encryption_type = SetParameterEncryptionType::from_byte(rest[4]).ok_or_else(|| {
            FelicaStandardError::Protocol("set parameter encryption type out of range".into())
        })?;
        let packet_type = SetParameterPacketType::from_byte(rest[5]).ok_or_else(|| {
            FelicaStandardError::Protocol("set parameter packet type out of range".into())
        })?;

        Ok(FelicaStandardCommand::SetParameter {
            idm,
            encryption_type,
            packet_type,
        })
    }

    fn parse_get_container_issue_information(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        if rest.len() < 2 {
            return Err(FelicaStandardError::Protocol(
                "get container issue information payload too short".into(),
            ));
        }
        if rest.len() > 2 {
            return Err(FelicaStandardError::Protocol(
                "get container issue information payload has trailing bytes".into(),
            ));
        }
        if rest.iter().any(|value| *value != 0x00) {
            return Err(FelicaStandardError::Protocol(
                "get container issue information reserved bytes must be 0x00".into(),
            ));
        }
        Ok(FelicaStandardCommand::GetContainerIssueInformation { idm })
    }

    fn parse_get_area_information(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        if rest.len() < 2 {
            return Err(FelicaStandardError::Protocol(
                "get area information payload too short".into(),
            ));
        }
        if rest.len() > 2 {
            return Err(FelicaStandardError::Protocol(
                "get area information payload has trailing bytes".into(),
            ));
        }
        Ok(FelicaStandardCommand::GetAreaInformation {
            idm,
            node_code: u16::from_le_bytes([rest[0], rest[1]]),
        })
    }

    fn parse_get_node_property(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        let (&type_byte, rest) = rest.split_first().ok_or_else(|| {
            FelicaStandardError::Protocol("get node property payload too short".into())
        })?;
        let node_property_type = NodePropertyType::from_byte(type_byte).ok_or_else(|| {
            FelicaStandardError::Protocol("get node property type out of range".into())
        })?;
        let (node_codes, _rest) = take_u16_list(
            rest,
            1..=MAX_NODE_PROPERTY_CODES,
            "get node property",
            "node",
        )?;
        Ok(FelicaStandardCommand::GetNodeProperty {
            idm,
            node_property_type,
            node_codes,
        })
    }

    fn parse_get_container_property(body: &[u8]) -> Result<Self, FelicaStandardError> {
        if body.len() < 2 {
            return Err(FelicaStandardError::Protocol(
                "get container property payload too short".into(),
            ));
        }
        if body.len() > 2 {
            return Err(FelicaStandardError::Protocol(
                "get container property payload has trailing bytes".into(),
            ));
        }
        let index = u16::from_le_bytes([body[0], body[1]]);
        Ok(FelicaStandardCommand::GetContainerProperty {
            property: ContainerProperty::from_index(index),
        })
    }

    fn parse_request_service_v2(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        let (service_codes, _consumed) =
            take_service_code_list(rest, MAX_SERVICE_CODES, "request service v2")?;
        Ok(FelicaStandardCommand::RequestServiceV2 { idm, service_codes })
    }

    fn parse_get_system_status(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        if rest.len() < 2 {
            return Err(FelicaStandardError::Protocol(
                "get system status payload too short".into(),
            ));
        }
        if rest.len() > 2 {
            return Err(FelicaStandardError::Protocol(
                "get system status payload has trailing bytes".into(),
            ));
        }
        if rest.iter().any(|value| *value != 0x00) {
            return Err(FelicaStandardError::Protocol(
                "get system status reserved bytes must be 0x00".into(),
            ));
        }
        Ok(FelicaStandardCommand::GetSystemStatus { idm })
    }

    fn parse_request_product_information(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        if !rest.is_empty() {
            return Err(FelicaStandardError::Protocol(
                "request product information payload has trailing bytes".into(),
            ));
        }
        Ok(FelicaStandardCommand::RequestProductInformation { idm })
    }

    fn parse_request_specification_version(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        if rest.len() < 2 {
            return Err(FelicaStandardError::Protocol(
                "request specification version payload too short".into(),
            ));
        }
        if rest.len() > 2 {
            return Err(FelicaStandardError::Protocol(
                "request specification version payload has trailing bytes".into(),
            ));
        }
        if rest.iter().any(|value| *value != 0x00) {
            return Err(FelicaStandardError::Protocol(
                "request specification version reserved bytes must be 0x00".into(),
            ));
        }
        Ok(FelicaStandardCommand::RequestSpecificationVersion { idm })
    }

    fn parse_reset_mode(body: &[u8]) -> Result<Self, FelicaStandardError> {
        let (idm, rest) = parse_idm(body)?;
        if rest.len() < 2 {
            return Err(FelicaStandardError::Protocol(
                "reset mode payload too short".into(),
            ));
        }
        if rest.len() > 2 {
            return Err(FelicaStandardError::Protocol(
                "reset mode payload has trailing bytes".into(),
            ));
        }
        if rest.iter().any(|value| *value != 0x00) {
            return Err(FelicaStandardError::Protocol(
                "reset mode reserved bytes must be 0x00".into(),
            ));
        }
        Ok(FelicaStandardCommand::ResetMode { idm })
    }

    fn parse_get_container_id(body: &[u8]) -> Result<Self, FelicaStandardError> {
        if body.len() < 2 {
            return Err(FelicaStandardError::Protocol(
                "get container id payload too short".into(),
            ));
        }
        if body.len() > 2 {
            return Err(FelicaStandardError::Protocol(
                "get container id payload has trailing bytes".into(),
            ));
        }
        Ok(FelicaStandardCommand::GetContainerId)
    }

    pub(crate) fn parse_secure_payload(
        command_code: u8,
        payload: &[u8],
    ) -> Result<Self, FelicaStandardError> {
        match command_code {
            READ_COMMAND_CODE | READ_V2_COMMAND_CODE => {
                let (block_count, payload) =
                    take_count(payload, 1..=MAX_BLOCK_COUNT, "secure read", "block")?;
                let (block_list, _rest) = take_block_list(payload, block_count)?;
                if command_code == READ_V2_COMMAND_CODE {
                    Ok(FelicaStandardCommand::ReadV2 { block_list })
                } else {
                    Ok(FelicaStandardCommand::Read { block_list })
                }
            }
            WRITE_COMMAND_CODE | WRITE_V2_COMMAND_CODE => {
                let (block_count, payload) =
                    take_count(payload, 1..=MAX_BLOCK_COUNT, "secure write", "block")?;
                let (block_list, payload) = take_block_list(payload, block_count)?;
                let expected_len = block_count.checked_mul(BLOCK_SIZE).ok_or_else(|| {
                    FelicaStandardError::Protocol("secure write data length overflow".into())
                })?;
                let data = payload
                    .get(..expected_len)
                    .ok_or_else(|| {
                        FelicaStandardError::Protocol("secure write data truncated".into())
                    })?
                    .to_vec();
                if command_code == WRITE_V2_COMMAND_CODE {
                    Ok(FelicaStandardCommand::WriteV2 { block_list, data })
                } else {
                    Ok(FelicaStandardCommand::Write { block_list, data })
                }
            }
            REGISTER_ISSUE_ID_COMMAND_CODE => {
                if payload.len() < 16 {
                    return Err(FelicaStandardError::Protocol(
                        "register issue id payload too short".into(),
                    ));
                }
                let mut issue_id = [0u8; 8];
                let mut issue_parameter = [0u8; 8];
                issue_id.copy_from_slice(&payload[..8]);
                issue_parameter.copy_from_slice(&payload[8..16]);
                Ok(FelicaStandardCommand::RegisterIssueId {
                    issue_id,
                    issue_parameter,
                    package: payload[16..].to_vec(),
                })
            }
            REGISTER_AREA_COMMAND_CODE => {
                if payload.len() < 2 {
                    return Err(FelicaStandardError::Protocol(
                        "register area payload too short".into(),
                    ));
                }
                Ok(FelicaStandardCommand::RegisterArea {
                    area_code: u16::from_le_bytes([payload[0], payload[1]]),
                    package: payload[2..].to_vec(),
                })
            }
            REGISTER_SERVICE_COMMAND_CODE => {
                if payload.len() < 2 {
                    return Err(FelicaStandardError::Protocol(
                        "register service payload too short".into(),
                    ));
                }
                Ok(FelicaStandardCommand::RegisterService {
                    service_code: u16::from_le_bytes([payload[0], payload[1]]),
                    package: payload[2..].to_vec(),
                })
            }
            CHANGE_SYSTEM_BLOCK_COMMAND_CODE => {
                if !payload.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "change system block payload must be empty".into(),
                    ));
                }
                Ok(FelicaStandardCommand::ChangeSystemBlock)
            }
            _ => Err(FelicaStandardError::Protocol(format!(
                "unsupported secure command code: 0x{command_code:02X}"
            ))),
        }
    }
}

fn parse_idm(data: &[u8]) -> Result<([u8; IDM_LEN], &[u8]), FelicaStandardError> {
    if data.len() < IDM_LEN {
        return Err(FelicaStandardError::Protocol("missing idm".into()));
    }
    let mut idm = [0u8; IDM_LEN];
    idm.copy_from_slice(&data[..IDM_LEN]);
    Ok((idm, &data[IDM_LEN..]))
}

/// Takes the one-byte count that introduces a list, with the bytes behind it.
///
/// `allowed` is the number of entries the protocol permits — most lists must
/// carry at least one, but a few may be empty. `label` names the command and
/// `noun` what it counts, so a rejection reads `"read without encryption block
/// count out of range"`.
fn take_count<'a>(
    data: &'a [u8],
    allowed: RangeInclusive<usize>,
    label: &str,
    noun: &str,
) -> Result<(usize, &'a [u8]), FelicaStandardError> {
    let (&count, rest) = data
        .split_first()
        .ok_or_else(|| FelicaStandardError::Protocol(format!("{label} {noun} count is missing")))?;
    let count = count as usize;
    if !allowed.contains(&count) {
        return Err(FelicaStandardError::Protocol(format!(
            "{label} {noun} count out of range"
        )));
    }
    Ok((count, rest))
}

/// Takes a list of little-endian `u16` values introduced by a one-byte count,
/// with the bytes behind it.
fn take_u16_list<'a>(
    data: &'a [u8],
    allowed: RangeInclusive<usize>,
    label: &str,
    noun: &str,
) -> Result<(Vec<u16>, &'a [u8]), FelicaStandardError> {
    let (count, rest) = take_count(data, allowed, label, noun)?;
    let values = parse_u16_list_le(rest, count)?;
    Ok((values, &rest[count * 2..]))
}

/// Takes a list of service codes introduced by a one-byte count, with the bytes
/// behind it.
fn take_service_code_list<'a>(
    data: &'a [u8],
    max: usize,
    label: &str,
) -> Result<(Vec<ServiceCode>, &'a [u8]), FelicaStandardError> {
    let (values, rest) = take_u16_list(data, 1..=max, label, "service")?;
    Ok((values.into_iter().map(ServiceCode::new).collect(), rest))
}

fn parse_u16_list_le(data: &[u8], count: usize) -> Result<Vec<u16>, FelicaStandardError> {
    let expected = count
        .checked_mul(2)
        .ok_or_else(|| FelicaStandardError::Protocol("u16 list length overflow".into()))?;
    if data.len() < expected {
        return Err(FelicaStandardError::Protocol("u16 list truncated".into()));
    }
    let mut out = Vec::with_capacity(count);
    for chunk in data[..expected].chunks_exact(2) {
        out.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    Ok(out)
}

/// Takes `count` block list elements, with the bytes behind them.
///
/// Elements are two or three bytes wide depending on their header bit, so the
/// caller cannot work out where they end without parsing them.
fn take_block_list(
    data: &[u8],
    count: usize,
) -> Result<(Vec<BlockListElement>, &[u8]), FelicaStandardError> {
    let mut blocks = Vec::with_capacity(count);
    let mut offset = 0usize;
    for _ in 0..count {
        let header = *data
            .get(offset)
            .ok_or_else(|| FelicaStandardError::Protocol("block list truncated".into()))?;
        offset += 1;
        let access_mode = (header >> 4) & 0x07;
        let service_code_list_index = header & 0x0F;
        let block_number_or_key_version = if header & 0x80 != 0 {
            let value = *data.get(offset).ok_or_else(|| {
                FelicaStandardError::Protocol("block list missing short block number".into())
            })? as u16;
            offset += 1;
            value
        } else {
            let bytes = data.get(offset..offset + 2).ok_or_else(|| {
                FelicaStandardError::Protocol("block list missing long block number".into())
            })?;
            offset += 2;
            u16::from_le_bytes([bytes[0], bytes[1]])
        };
        blocks.push(BlockListElement {
            block_number_or_key_version,
            service_code_list_index,
            access_mode,
        });
    }
    Ok((blocks, &data[offset..]))
}

pub(crate) fn is_secure_command_code(command_code: u8) -> bool {
    matches!(
        command_code,
        READ_COMMAND_CODE
            | WRITE_COMMAND_CODE
            | READ_V2_COMMAND_CODE
            | WRITE_V2_COMMAND_CODE
            | REGISTER_ISSUE_ID_COMMAND_CODE
            | REGISTER_AREA_COMMAND_CODE
            | REGISTER_SERVICE_COMMAND_CODE
            | CHANGE_SYSTEM_BLOCK_COMMAND_CODE
    )
}

pub(crate) fn is_register_command(command_code: u8) -> bool {
    matches!(
        command_code,
        REGISTER_ISSUE_ID_COMMAND_CODE
            | REGISTER_AREA_COMMAND_CODE
            | REGISTER_SERVICE_COMMAND_CODE
            | CHANGE_SYSTEM_BLOCK_COMMAND_CODE
    )
}
