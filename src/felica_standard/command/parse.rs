use super::*;

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
            POLLING_COMMAND_CODE => {
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
            REQUEST_SERVICE_COMMAND_CODE => {
                let (idm, rest) = parse_idm(body)?;
                let (service_codes, _consumed) =
                    parse_service_code_list(rest, MAX_SERVICE_CODES, "request service")?;
                Ok(FelicaStandardCommand::RequestService { idm, service_codes })
            }
            REQUEST_RESPONSE_COMMAND_CODE => {
                let (idm, rest) = parse_idm(body)?;
                if !rest.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "request response payload has trailing bytes".into(),
                    ));
                }
                Ok(FelicaStandardCommand::RequestResponse { idm })
            }
            READ_WITHOUT_ENCRYPTION_COMMAND_CODE => {
                let (idm, rest) = parse_idm(body)?;
                let (service_codes, rest) =
                    parse_service_code_list(rest, MAX_RW_SERVICE_CODES, "read without encryption")?;
                if rest.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "read without encryption missing block count".into(),
                    ));
                }
                let block_count = rest[0] as usize;
                if block_count == 0 || block_count > MAX_BLOCK_LIST_LEN {
                    return Err(FelicaStandardError::Protocol(
                        "read without encryption block count out of range".into(),
                    ));
                }
                let (block_list, _consumed) = parse_block_list(&rest[1..], block_count)?;
                Ok(FelicaStandardCommand::ReadWithoutEncryption {
                    idm,
                    service_codes,
                    block_list,
                })
            }
            WRITE_WITHOUT_ENCRYPTION_COMMAND_CODE => {
                let (idm, rest) = parse_idm(body)?;
                let (service_codes, rest) = parse_service_code_list(
                    rest,
                    MAX_RW_SERVICE_CODES,
                    "write without encryption",
                )?;
                if rest.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "write without encryption missing block count".into(),
                    ));
                }
                let block_count = rest[0] as usize;
                if block_count == 0 || block_count > MAX_BLOCK_LIST_LEN {
                    return Err(FelicaStandardError::Protocol(
                        "write without encryption block count out of range".into(),
                    ));
                }
                let (block_list, consumed) = parse_block_list(&rest[1..], block_count)?;
                let data_offset = 1 + consumed;
                let expected_len = block_count.checked_mul(BLOCK_SIZE).ok_or_else(|| {
                    FelicaStandardError::Protocol(
                        "write without encryption data length overflow".into(),
                    )
                })?;
                let data = rest
                    .get(data_offset..data_offset + expected_len)
                    .ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "write without encryption data truncated".into(),
                        )
                    })?
                    .to_vec();
                Ok(FelicaStandardCommand::WriteWithoutEncryption {
                    idm,
                    service_codes,
                    block_list,
                    data,
                })
            }
            SEARCH_SERVICE_CODE_COMMAND_CODE => {
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
            REQUEST_SYSTEM_CODE_COMMAND_CODE => {
                let (idm, rest) = parse_idm(body)?;
                if !rest.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "request system code payload has trailing bytes".into(),
                    ));
                }
                Ok(FelicaStandardCommand::RequestSystemCode { idm })
            }
            REQUEST_BLOCK_INFORMATION_COMMAND_CODE => {
                let (idm, rest) = parse_idm(body)?;
                if rest.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "request block information payload too short".into(),
                    ));
                }
                let count = rest[0] as usize;
                if count == 0 || count > MAX_NODE_CODES {
                    return Err(FelicaStandardError::Protocol(
                        "request block information count out of range".into(),
                    ));
                }
                let values = parse_u16_list_le(&rest[1..], count)?;
                Ok(FelicaStandardCommand::RequestBlockInformation {
                    idm,
                    node_codes: values,
                })
            }
            AUTHENTICATION1_COMMAND_CODE => {
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
            AUTHENTICATION2_COMMAND_CODE => {
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
            READ_COMMAND_CODE
            | WRITE_COMMAND_CODE
            | READ_V2_COMMAND_CODE
            | WRITE_V2_COMMAND_CODE
            | REGISTER_ISSUE_ID_COMMAND_CODE
            | REGISTER_AREA_COMMAND_CODE
            | REGISTER_SERVICE_COMMAND_CODE
            | CHANGE_SYSTEM_BLOCK_COMMAND_CODE => Err(FelicaStandardError::Protocol(
                "secure command payload requires decryption".into(),
            )),
            REQUEST_CODE_LIST_COMMAND_CODE => {
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
            REQUEST_BLOCK_INFORMATION_EX_COMMAND_CODE => {
                let (idm, rest) = parse_idm(body)?;
                if rest.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "request block information ex payload too short".into(),
                    ));
                }
                let count = rest[0] as usize;
                if count == 0 || count > MAX_NODE_CODES {
                    return Err(FelicaStandardError::Protocol(
                        "request block information ex count out of range".into(),
                    ));
                }
                let values = parse_u16_list_le(&rest[1..], count)?;
                Ok(FelicaStandardCommand::RequestBlockInformationEx {
                    idm,
                    node_codes: values,
                })
            }
            SET_PARAMETER_COMMAND_CODE => {
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
                let encryption_type =
                    SetParameterEncryptionType::from_byte(rest[4]).ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "set parameter encryption type out of range".into(),
                        )
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
            GET_CONTAINER_ISSUE_INFORMATION_COMMAND_CODE => {
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
            GET_AREA_INFORMATION_COMMAND_CODE => {
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
            GET_NODE_PROPERTY_COMMAND_CODE => {
                let (idm, rest) = parse_idm(body)?;
                if rest.len() < 2 {
                    return Err(FelicaStandardError::Protocol(
                        "get node property payload too short".into(),
                    ));
                }
                let node_property_type = NodePropertyType::from_byte(rest[0]).ok_or_else(|| {
                    FelicaStandardError::Protocol("get node property type out of range".into())
                })?;
                let count = rest[1] as usize;
                if count == 0 || count > MAX_NODE_PROPERTY_CODES {
                    return Err(FelicaStandardError::Protocol(
                        "get node property count out of range".into(),
                    ));
                }
                let node_codes = parse_u16_list_le(&rest[2..], count)?;
                Ok(FelicaStandardCommand::GetNodeProperty {
                    idm,
                    node_property_type,
                    node_codes,
                })
            }
            GET_CONTAINER_PROPERTY_COMMAND_CODE => {
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
            REQUEST_SERVICE_V2_COMMAND_CODE => {
                let (idm, rest) = parse_idm(body)?;
                let (service_codes, _consumed) =
                    parse_service_code_list(rest, MAX_SERVICE_CODES, "request service v2")?;
                Ok(FelicaStandardCommand::RequestServiceV2 { idm, service_codes })
            }
            GET_SYSTEM_STATUS_COMMAND_CODE => {
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
            REQUEST_PRODUCT_INFORMATION_COMMAND_CODE => {
                let (idm, rest) = parse_idm(body)?;
                if !rest.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "request product information payload has trailing bytes".into(),
                    ));
                }
                Ok(FelicaStandardCommand::RequestProductInformation { idm })
            }
            REQUEST_SPECIFICATION_VERSION_COMMAND_CODE => {
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
            RESET_MODE_COMMAND_CODE => {
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
            GET_CONTAINER_ID_COMMAND_CODE => {
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
            _ => Err(FelicaStandardError::Protocol(format!(
                "unsupported command code: 0x{command:02X}"
            ))),
        }
    }

    pub(crate) fn parse_secure_payload(
        command_code: u8,
        payload: &[u8],
    ) -> Result<Self, FelicaStandardError> {
        match command_code {
            READ_COMMAND_CODE | READ_V2_COMMAND_CODE => {
                if payload.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "secure read payload too short".into(),
                    ));
                }
                let block_count = payload[0] as usize;
                if block_count == 0 || block_count > MAX_BLOCK_LIST_LEN {
                    return Err(FelicaStandardError::Protocol(
                        "secure read block count out of range".into(),
                    ));
                }
                let (block_list, _consumed) = parse_block_list(&payload[1..], block_count)?;
                if command_code == READ_V2_COMMAND_CODE {
                    Ok(FelicaStandardCommand::ReadV2 { block_list })
                } else {
                    Ok(FelicaStandardCommand::Read { block_list })
                }
            }
            WRITE_COMMAND_CODE | WRITE_V2_COMMAND_CODE => {
                if payload.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "secure write payload too short".into(),
                    ));
                }
                let block_count = payload[0] as usize;
                if block_count == 0 || block_count > MAX_BLOCK_LIST_LEN {
                    return Err(FelicaStandardError::Protocol(
                        "secure write block count out of range".into(),
                    ));
                }
                let (block_list, consumed) = parse_block_list(&payload[1..], block_count)?;
                let data_offset = 1 + consumed;
                let expected_len = block_count.checked_mul(BLOCK_SIZE).ok_or_else(|| {
                    FelicaStandardError::Protocol("secure write data length overflow".into())
                })?;
                let data = payload
                    .get(data_offset..data_offset + expected_len)
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

fn parse_service_code_list<'a>(
    data: &'a [u8],
    max: usize,
    label: &str,
) -> Result<(Vec<ServiceCode>, &'a [u8]), FelicaStandardError> {
    if data.is_empty() {
        return Err(FelicaStandardError::Protocol(format!(
            "{label} payload too short"
        )));
    }
    let count = data[0] as usize;
    if count == 0 || count > max {
        return Err(FelicaStandardError::Protocol(format!(
            "{label} service count out of range"
        )));
    }
    let list = parse_u16_list_le(&data[1..], count)?;
    let mut codes = Vec::with_capacity(count);
    for value in list {
        codes.push(ServiceCode::new(value));
    }
    Ok((codes, &data[1 + count * 2..]))
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

fn parse_block_list(
    data: &[u8],
    count: usize,
) -> Result<(Vec<BlockListElement>, usize), FelicaStandardError> {
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
    Ok((blocks, offset))
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
