use super::{
    BLOCK_SIZE, BlockListElement, CHANGE_SYSTEM_BLOCK_COMMAND_CODE, FelicaStandardError, IDM_LEN,
    MAX_BLOCK_LIST_LEN, MAX_NODE_CODES, MAX_RW_SERVICE_CODES, MAX_SERVICE_CODES, READ_COMMAND_CODE,
    REGISTER_AREA_COMMAND_CODE, REGISTER_ISSUE_ID_COMMAND_CODE, REGISTER_SERVICE_COMMAND_CODE,
    ServiceCode, SetParameterEncryptionType, SetParameterPacketType, WRITE_COMMAND_CODE,
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
    RequestBlockInformationEx {
        idm: [u8; IDM_LEN],
        node_codes: Vec<u16>,
    },
    RequestCodeList {
        idm: [u8; IDM_LEN],
        parent_node_code: u16,
        index: u16,
    },
    SetParameter {
        idm: [u8; IDM_LEN],
        encryption_type: SetParameterEncryptionType,
        packet_type: SetParameterPacketType,
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
    RequestServiceV2 {
        idm: [u8; IDM_LEN],
        service_codes: Vec<ServiceCode>,
    },
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

struct PayloadWriter {
    buf: Vec<u8>,
}

impl PayloadWriter {
    fn new(opcode: u8) -> Self {
        Self { buf: vec![opcode] }
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    fn idm(&mut self, idm: &[u8; IDM_LEN]) {
        self.buf.extend_from_slice(idm);
    }

    fn push_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    fn extend_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn extend_u16_le(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn extend_u16_be(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    fn extend_u16_list_le(&mut self, values: &[u16]) {
        for &value in values {
            self.extend_u16_le(value);
        }
    }

    fn extend_service_codes(&mut self, service_codes: &[ServiceCode]) {
        for &code in service_codes {
            self.buf.extend_from_slice(&code.to_le_bytes());
        }
    }

    fn extend_block_list(&mut self, block_list: &[BlockListElement]) {
        for block in block_list {
            self.buf.extend(block.pack());
        }
    }

    fn finish_frame(self) -> Vec<u8> {
        frame_with_length_prefix(&self.buf)
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

fn append_service_codes(payload: &mut PayloadWriter, service_codes: &[ServiceCode]) {
    payload.push_u8(service_codes.len() as u8);
    payload.extend_service_codes(service_codes);
}

fn append_block_list(payload: &mut PayloadWriter, block_list: &[BlockListElement]) {
    payload.push_u8(block_list.len() as u8);
    payload.extend_block_list(block_list);
}

pub(crate) enum CommandEncoding {
    Plain(Vec<u8>),
    Secure { opcode: u8, payload: Vec<u8> },
}

pub(crate) fn frame_with_length_prefix(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 1);
    frame.push((payload.len() + 1) as u8);
    frame.extend_from_slice(payload);
    frame
}

impl FelicaStandardCommand {
    pub fn to_frame(&self) -> Vec<u8> {
        match self.encoding() {
            CommandEncoding::Plain(frame) => frame,
            CommandEncoding::Secure { .. } => {
                panic!("secure commands cannot be converted to a frame")
            }
        }
    }

    pub(crate) fn encoding(&self) -> CommandEncoding {
        match self {
            FelicaStandardCommand::Polling {
                system_code,
                request_code,
                time_slots,
            } => {
                let mut payload = PayloadWriter::new(0x00);
                payload.extend_u16_be(*system_code);
                payload.push_u8(*request_code);
                payload.push_u8(*time_slots);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::RequestService { idm, service_codes } => {
                debug_assert!(
                    !service_codes.is_empty() && service_codes.len() <= MAX_SERVICE_CODES
                );
                let mut payload = PayloadWriter::new(0x02);
                payload.idm(idm);
                append_service_codes(&mut payload, service_codes);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::RequestServiceV2 { idm, service_codes } => {
                debug_assert!(
                    !service_codes.is_empty() && service_codes.len() <= MAX_SERVICE_CODES
                );
                let mut payload = PayloadWriter::new(0x32);
                payload.idm(idm);
                append_service_codes(&mut payload, service_codes);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::RequestResponse { idm } => {
                let mut payload = PayloadWriter::new(0x04);
                payload.idm(idm);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::ReadWithoutEncryption {
                idm,
                service_codes,
                block_list,
            } => {
                debug_assert!(
                    !service_codes.is_empty() && service_codes.len() <= MAX_RW_SERVICE_CODES
                );
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_LIST_LEN);
                let mut payload = PayloadWriter::new(0x06);
                payload.idm(idm);
                append_service_codes(&mut payload, service_codes);
                append_block_list(&mut payload, block_list);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::WriteWithoutEncryption {
                idm,
                service_codes,
                block_list,
                data,
            } => {
                debug_assert!(
                    !service_codes.is_empty() && service_codes.len() <= MAX_RW_SERVICE_CODES
                );
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_LIST_LEN);
                debug_assert_eq!(data.len(), block_list.len() * BLOCK_SIZE);
                let mut payload = PayloadWriter::new(0x08);
                payload.idm(idm);
                append_service_codes(&mut payload, service_codes);
                append_block_list(&mut payload, block_list);
                payload.extend_bytes(data);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::SearchServiceCode { idm, service_index } => {
                let mut payload = PayloadWriter::new(0x0A);
                payload.idm(idm);
                payload.extend_u16_le(*service_index);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::RequestSystemCode { idm } => {
                let mut payload = PayloadWriter::new(0x0C);
                payload.idm(idm);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::RequestBlockInformation { idm, node_codes } => {
                debug_assert!(!node_codes.is_empty() && node_codes.len() <= MAX_NODE_CODES);
                let mut payload = PayloadWriter::new(0x0E);
                payload.idm(idm);
                payload.push_u8(node_codes.len() as u8);
                payload.extend_u16_list_le(node_codes);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::RequestBlockInformationEx { idm, node_codes } => {
                debug_assert!(!node_codes.is_empty() && node_codes.len() <= MAX_NODE_CODES);
                let mut payload = PayloadWriter::new(0x1E);
                payload.idm(idm);
                payload.push_u8(node_codes.len() as u8);
                payload.extend_u16_list_le(node_codes);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::RequestCodeList {
                idm,
                parent_node_code,
                index,
            } => {
                let mut payload = PayloadWriter::new(0x1A);
                payload.idm(idm);
                payload.extend_u16_le(*parent_node_code);
                payload.extend_u16_le(*index);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::SetParameter {
                idm,
                encryption_type,
                packet_type,
            } => {
                let mut payload = PayloadWriter::new(0x20);
                payload.idm(idm);
                payload.extend_bytes(&[0x00; 4]);
                payload.push_u8(encryption_type.to_byte());
                payload.push_u8(packet_type.to_byte());
                payload.extend_bytes(&[0x00; 2]);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::Authentication1 {
                idm,
                areas,
                services,
                challenge_1a,
            } => {
                let mut payload = PayloadWriter::new(0x10);
                payload.idm(idm);
                payload.push_u8(areas.len() as u8);
                payload.extend_u16_list_le(areas);
                payload.push_u8(services.len() as u8);
                payload.extend_u16_list_le(services);
                payload.extend_bytes(challenge_1a);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::Authentication2 { idm, challenge_2b } => {
                let mut payload = PayloadWriter::new(0x12);
                payload.idm(idm);
                payload.extend_bytes(challenge_2b);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::Read { block_list } => {
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_LIST_LEN);
                let mut payload = PayloadWriter::with_capacity(1 + block_list.len() * 3);
                append_block_list(&mut payload, block_list);
                CommandEncoding::Secure {
                    opcode: READ_COMMAND_CODE,
                    payload: payload.finish(),
                }
            }
            FelicaStandardCommand::Write { block_list, data } => {
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_LIST_LEN);
                debug_assert_eq!(data.len(), block_list.len() * BLOCK_SIZE);
                let mut payload =
                    PayloadWriter::with_capacity(1 + block_list.len() * 3 + data.len());
                append_block_list(&mut payload, block_list);
                payload.extend_bytes(data);
                CommandEncoding::Secure {
                    opcode: WRITE_COMMAND_CODE,
                    payload: payload.finish(),
                }
            }
            FelicaStandardCommand::RegisterIssueId {
                issue_id,
                issue_parameter,
                package,
            } => {
                let mut payload = PayloadWriter::with_capacity(16 + package.len());
                payload.extend_bytes(issue_id);
                payload.extend_bytes(issue_parameter);
                payload.extend_bytes(package);
                CommandEncoding::Secure {
                    opcode: REGISTER_ISSUE_ID_COMMAND_CODE,
                    payload: payload.finish(),
                }
            }
            FelicaStandardCommand::RegisterArea { area_code, package } => {
                let mut payload = PayloadWriter::with_capacity(2 + package.len());
                payload.extend_u16_le(*area_code);
                payload.extend_bytes(package);
                CommandEncoding::Secure {
                    opcode: REGISTER_AREA_COMMAND_CODE,
                    payload: payload.finish(),
                }
            }
            FelicaStandardCommand::RegisterService {
                service_code,
                package,
            } => {
                let mut payload = PayloadWriter::with_capacity(2 + package.len());
                payload.extend_u16_le(*service_code);
                payload.extend_bytes(package);
                CommandEncoding::Secure {
                    opcode: REGISTER_SERVICE_COMMAND_CODE,
                    payload: payload.finish(),
                }
            }
            FelicaStandardCommand::ChangeSystemBlock => CommandEncoding::Secure {
                opcode: CHANGE_SYSTEM_BLOCK_COMMAND_CODE,
                payload: Vec::new(),
            },
        }
    }

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
            0x00 => {
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
            0x02 => {
                let (idm, rest) = parse_idm(body)?;
                let (service_codes, _consumed) =
                    parse_service_code_list(rest, MAX_SERVICE_CODES, "request service")?;
                Ok(FelicaStandardCommand::RequestService { idm, service_codes })
            }
            0x32 => {
                let (idm, rest) = parse_idm(body)?;
                let (service_codes, _consumed) =
                    parse_service_code_list(rest, MAX_SERVICE_CODES, "request service v2")?;
                Ok(FelicaStandardCommand::RequestServiceV2 { idm, service_codes })
            }
            0x04 => {
                let (idm, rest) = parse_idm(body)?;
                if !rest.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "request response payload has trailing bytes".into(),
                    ));
                }
                Ok(FelicaStandardCommand::RequestResponse { idm })
            }
            0x06 => {
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
            0x08 => {
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
            0x0A => {
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
            0x0C => {
                let (idm, rest) = parse_idm(body)?;
                if !rest.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "request system code payload has trailing bytes".into(),
                    ));
                }
                Ok(FelicaStandardCommand::RequestSystemCode { idm })
            }
            0x0E => {
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
            0x1E => {
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
            0x1A => {
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
            0x20 => {
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
            0x10 => {
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
            0x12 => {
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
            0x14 | 0x16 | 0x80 | 0x82 | 0x84 | 0x8E => Err(FelicaStandardError::Protocol(
                "secure command payload requires decryption".into(),
            )),
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
            READ_COMMAND_CODE => {
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
                Ok(FelicaStandardCommand::Read { block_list })
            }
            WRITE_COMMAND_CODE => {
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
                Ok(FelicaStandardCommand::Write { block_list, data })
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
