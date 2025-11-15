use super::{
    BLOCK_SIZE, BlockListElement, COMMIT_REGISTRATION_COMMAND_CODE, IDM_LEN, MAX_BLOCK_LIST_LEN,
    MAX_NODE_CODES, MAX_RW_SERVICE_CODES, MAX_SERVICE_CODES, READ_COMMAND_CODE,
    REGISTER_AREA_COMMAND_CODE, REGISTER_ISSUE_ID_COMMAND_CODE, REGISTER_SERVICE_COMMAND_CODE,
    ServiceCode, WRITE_COMMAND_CODE,
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
    CommitRegistration,
}

struct PayloadBuilder {
    buf: Vec<u8>,
}

impl PayloadBuilder {
    fn new(opcode: u8) -> Self {
        Self { buf: vec![opcode] }
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
    pub(crate) fn to_frame(&self) -> Vec<u8> {
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
                let mut payload = PayloadBuilder::new(0x00);
                payload.extend_u16_be(*system_code);
                payload.push_u8(*request_code);
                payload.push_u8(*time_slots);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::RequestService { idm, service_codes } => {
                debug_assert!(
                    !service_codes.is_empty() && service_codes.len() <= MAX_SERVICE_CODES
                );
                let mut payload = PayloadBuilder::new(0x02);
                payload.idm(idm);
                payload.push_u8(service_codes.len() as u8);
                payload.extend_service_codes(service_codes);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::RequestServiceV2 { idm, service_codes } => {
                debug_assert!(
                    !service_codes.is_empty() && service_codes.len() <= MAX_SERVICE_CODES
                );
                let mut payload = PayloadBuilder::new(0x32);
                payload.idm(idm);
                payload.push_u8(service_codes.len() as u8);
                payload.extend_service_codes(service_codes);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::RequestResponse { idm } => {
                let mut payload = PayloadBuilder::new(0x04);
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
                let mut payload = PayloadBuilder::new(0x06);
                payload.idm(idm);
                payload.push_u8(service_codes.len() as u8);
                payload.extend_service_codes(service_codes);
                payload.push_u8(block_list.len() as u8);
                payload.extend_block_list(block_list);
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
                let mut payload = PayloadBuilder::new(0x08);
                payload.idm(idm);
                payload.push_u8(service_codes.len() as u8);
                payload.extend_service_codes(service_codes);
                payload.push_u8(block_list.len() as u8);
                payload.extend_block_list(block_list);
                payload.extend_bytes(data);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::SearchServiceCode { idm, service_index } => {
                let mut payload = PayloadBuilder::new(0x0A);
                payload.idm(idm);
                payload.extend_u16_le(*service_index);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::RequestBlockInformation { idm, node_codes } => {
                debug_assert!(!node_codes.is_empty() && node_codes.len() <= MAX_NODE_CODES);
                let mut payload = PayloadBuilder::new(0x0E);
                payload.idm(idm);
                payload.push_u8(node_codes.len() as u8);
                payload.extend_u16_list_le(node_codes);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::Authentication1 {
                idm,
                areas,
                services,
                challenge_1a,
            } => {
                let mut payload = PayloadBuilder::new(0x10);
                payload.idm(idm);
                payload.push_u8(areas.len() as u8);
                payload.extend_u16_list_le(areas);
                payload.push_u8(services.len() as u8);
                payload.extend_u16_list_le(services);
                payload.extend_bytes(challenge_1a);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::Authentication2 { idm, challenge_2b } => {
                let mut payload = PayloadBuilder::new(0x12);
                payload.idm(idm);
                payload.extend_bytes(challenge_2b);
                CommandEncoding::Plain(payload.finish_frame())
            }
            FelicaStandardCommand::Read { block_list } => {
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_LIST_LEN);
                let mut payload = Vec::with_capacity(1 + block_list.len() * 3);
                payload.push(block_list.len() as u8);
                for block in block_list {
                    payload.extend(block.pack());
                }
                CommandEncoding::Secure {
                    opcode: READ_COMMAND_CODE,
                    payload,
                }
            }
            FelicaStandardCommand::Write { block_list, data } => {
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_LIST_LEN);
                debug_assert_eq!(data.len(), block_list.len() * BLOCK_SIZE);
                let mut payload = Vec::with_capacity(1 + block_list.len() * 3 + data.len());
                payload.push(block_list.len() as u8);
                for block in block_list {
                    payload.extend(block.pack());
                }
                payload.extend_from_slice(data);
                CommandEncoding::Secure {
                    opcode: WRITE_COMMAND_CODE,
                    payload,
                }
            }
            FelicaStandardCommand::RegisterIssueId {
                issue_id,
                issue_parameter,
                package,
            } => {
                let mut payload = Vec::with_capacity(16 + package.len());
                payload.extend_from_slice(issue_id);
                payload.extend_from_slice(issue_parameter);
                payload.extend_from_slice(package);
                CommandEncoding::Secure {
                    opcode: REGISTER_ISSUE_ID_COMMAND_CODE,
                    payload,
                }
            }
            FelicaStandardCommand::RegisterArea { area_code, package } => {
                let mut payload = Vec::with_capacity(2 + package.len());
                payload.extend_from_slice(&area_code.to_le_bytes());
                payload.extend_from_slice(package);
                CommandEncoding::Secure {
                    opcode: REGISTER_AREA_COMMAND_CODE,
                    payload,
                }
            }
            FelicaStandardCommand::RegisterService {
                service_code,
                package,
            } => {
                let mut payload = Vec::with_capacity(2 + package.len());
                payload.extend_from_slice(&service_code.to_le_bytes());
                payload.extend_from_slice(package);
                CommandEncoding::Secure {
                    opcode: REGISTER_SERVICE_COMMAND_CODE,
                    payload,
                }
            }
            FelicaStandardCommand::CommitRegistration => CommandEncoding::Secure {
                opcode: COMMIT_REGISTRATION_COMMAND_CODE,
                payload: Vec::new(),
            },
        }
    }
}
