use super::{
    AUTHENTICATION1_COMMAND_CODE, AUTHENTICATION1_V2_COMMAND_CODE, AUTHENTICATION2_COMMAND_CODE,
    AUTHENTICATION2_V2_COMMAND_CODE, BLOCK_SIZE, BlockListElement,
    CHANGE_SYSTEM_BLOCK_COMMAND_CODE, ContainerProperty, FelicaStandardError,
    GET_AREA_INFORMATION_COMMAND_CODE, GET_CONTAINER_ID_COMMAND_CODE,
    GET_CONTAINER_ISSUE_INFORMATION_COMMAND_CODE, GET_CONTAINER_PROPERTY_COMMAND_CODE,
    GET_NODE_PROPERTY_COMMAND_CODE, GET_SYSTEM_STATUS_COMMAND_CODE, IDM_LEN, MAX_BLOCK_LIST_LEN,
    MAX_NODE_CODES, MAX_NODE_PROPERTY_CODES, MAX_RW_SERVICE_CODES, MAX_SERVICE_CODES,
    NodePropertyType, POLLING_COMMAND_CODE, READ_COMMAND_CODE, READ_V2_COMMAND_CODE,
    READ_WITHOUT_ENCRYPTION_COMMAND_CODE, REGISTER_AREA_COMMAND_CODE,
    REGISTER_ISSUE_ID_COMMAND_CODE, REGISTER_SERVICE_COMMAND_CODE,
    REQUEST_BLOCK_INFORMATION_COMMAND_CODE, REQUEST_BLOCK_INFORMATION_EX_COMMAND_CODE,
    REQUEST_CODE_LIST_COMMAND_CODE, REQUEST_PRODUCT_INFORMATION_COMMAND_CODE,
    REQUEST_RESPONSE_COMMAND_CODE, REQUEST_SERVICE_COMMAND_CODE, REQUEST_SERVICE_V2_COMMAND_CODE,
    REQUEST_SPECIFICATION_VERSION_COMMAND_CODE, REQUEST_SYSTEM_CODE_COMMAND_CODE,
    RESET_MODE_COMMAND_CODE, SEARCH_SERVICE_CODE_COMMAND_CODE, SET_PARAMETER_COMMAND_CODE,
    ServiceCode, SetParameterEncryptionType, SetParameterPacketType, WRITE_COMMAND_CODE,
    WRITE_V2_COMMAND_CODE, WRITE_WITHOUT_ENCRYPTION_COMMAND_CODE,
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
    ReadV2 {
        block_list: Vec<BlockListElement>,
    },
    WriteV2 {
        block_list: Vec<BlockListElement>,
        data: Vec<u8>,
    },
    RequestCodeList {
        idm: [u8; IDM_LEN],
        parent_node_code: u16,
        index: u16,
    },
    RequestBlockInformationEx {
        idm: [u8; IDM_LEN],
        node_codes: Vec<u16>,
    },
    SetParameter {
        idm: [u8; IDM_LEN],
        encryption_type: SetParameterEncryptionType,
        packet_type: SetParameterPacketType,
    },
    GetContainerIssueInformation {
        idm: [u8; IDM_LEN],
    },
    GetAreaInformation {
        idm: [u8; IDM_LEN],
        node_code: u16,
    },
    GetNodeProperty {
        idm: [u8; IDM_LEN],
        node_property_type: NodePropertyType,
        node_codes: Vec<u16>,
    },
    GetContainerProperty {
        property: ContainerProperty,
    },
    RequestServiceV2 {
        idm: [u8; IDM_LEN],
        service_codes: Vec<ServiceCode>,
    },
    GetSystemStatus {
        idm: [u8; IDM_LEN],
    },
    RequestProductInformation {
        idm: [u8; IDM_LEN],
    },
    RequestSpecificationVersion {
        idm: [u8; IDM_LEN],
    },
    ResetMode {
        idm: [u8; IDM_LEN],
    },
    Authentication1V2 {
        idm: [u8; IDM_LEN],
        operation_parameter: u8,
        nodes: Vec<u16>,
        challenge_1a: [u8; 16],
    },
    Authentication2V2 {
        idm: [u8; IDM_LEN],
        challenge_2b: [u8; 16],
    },
    GetContainerId,
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

mod parse;
mod serialize;

pub(crate) use parse::{is_register_command, is_secure_command_code};

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_idm() -> [u8; IDM_LEN] {
        [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
    }

    fn assert_protocol_error_contains(
        result: Result<FelicaStandardCommand, FelicaStandardError>,
        expected: &str,
    ) {
        match result {
            Err(FelicaStandardError::Protocol(message)) => {
                assert!(
                    message.contains(expected),
                    "unexpected protocol message: {message}"
                );
            }
            Err(other) => panic!("expected protocol error, got {other}"),
            Ok(_) => panic!("expected protocol error, got Ok"),
        }
    }

    #[test]
    fn request_service_frame_round_trip() {
        let idm = sample_idm();
        let service_codes = vec![ServiceCode::new(0x090F), ServiceCode::new(0x1234)];
        let command = FelicaStandardCommand::RequestService {
            idm,
            service_codes: service_codes.clone(),
        };

        let frame = command.to_frame();
        assert_eq!(frame[0] as usize, frame.len());

        let parsed = FelicaStandardCommand::parse_frame(&frame).unwrap();
        match parsed {
            FelicaStandardCommand::RequestService {
                idm: parsed_idm,
                service_codes: parsed_service_codes,
            } => {
                assert_eq!(parsed_idm, idm);
                assert_eq!(parsed_service_codes, service_codes);
            }
            _ => panic!("unexpected parsed command variant"),
        }
    }

    #[test]
    fn read_without_encryption_round_trip_with_mixed_block_encodings() {
        let idm = sample_idm();
        let service_codes = vec![ServiceCode::new(0x1008)];
        let block_list = vec![
            BlockListElement::new(0x002A, 0x01, 0x02),
            BlockListElement::new(0x0123, 0x03, 0x04),
        ];
        let command = FelicaStandardCommand::ReadWithoutEncryption {
            idm,
            service_codes: service_codes.clone(),
            block_list: block_list.clone(),
        };

        let frame = command.to_frame();
        let parsed = FelicaStandardCommand::parse_frame(&frame).unwrap();
        match parsed {
            FelicaStandardCommand::ReadWithoutEncryption {
                idm: parsed_idm,
                service_codes: parsed_service_codes,
                block_list: parsed_block_list,
            } => {
                assert_eq!(parsed_idm, idm);
                assert_eq!(parsed_service_codes, service_codes);
                assert_eq!(parsed_block_list, block_list);
            }
            _ => panic!("unexpected parsed command variant"),
        }
    }

    #[test]
    fn parse_frame_rejects_length_mismatch() {
        assert_protocol_error_contains(
            FelicaStandardCommand::parse_frame(&[0x04, REQUEST_RESPONSE_COMMAND_CODE, 0x00]),
            "length byte does not match frame length",
        );
    }

    #[test]
    fn parse_payload_rejects_non_zero_reserved_set_parameter_bytes() {
        let mut payload = vec![SET_PARAMETER_COMMAND_CODE];
        payload.extend_from_slice(&sample_idm());
        payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        assert_protocol_error_contains(
            FelicaStandardCommand::parse_payload(&payload),
            "reserved bytes D0-D3 must be 0x00",
        );
    }

    #[test]
    fn secure_write_encoding_round_trip() {
        let block_list = vec![BlockListElement::new(0x0003, 0x01, 0x00)];
        let data = vec![0xAB; BLOCK_SIZE];
        let command = FelicaStandardCommand::Write {
            block_list: block_list.clone(),
            data: data.clone(),
        };

        let (opcode, payload) = match command.encoding() {
            CommandEncoding::Secure { opcode, payload } => (opcode, payload),
            CommandEncoding::Plain(_) => panic!("expected secure encoding"),
        };
        assert_eq!(opcode, WRITE_COMMAND_CODE);

        let parsed = FelicaStandardCommand::parse_secure_payload(opcode, &payload).unwrap();
        match parsed {
            FelicaStandardCommand::Write {
                block_list: parsed_block_list,
                data: parsed_data,
            } => {
                assert_eq!(parsed_block_list, block_list);
                assert_eq!(parsed_data, data);
            }
            _ => panic!("unexpected parsed secure command variant"),
        }
    }

    #[test]
    fn secure_write_v2_encoding_round_trip() {
        let block_list = vec![BlockListElement::new(0x0003, 0x01, 0x00)];
        let data = vec![0xAB; BLOCK_SIZE];
        let command = FelicaStandardCommand::WriteV2 {
            block_list: block_list.clone(),
            data: data.clone(),
        };

        let (opcode, payload) = match command.encoding() {
            CommandEncoding::Secure { opcode, payload } => (opcode, payload),
            CommandEncoding::Plain(_) => panic!("expected secure encoding"),
        };
        assert_eq!(opcode, WRITE_V2_COMMAND_CODE);

        let parsed = FelicaStandardCommand::parse_secure_payload(opcode, &payload).unwrap();
        match parsed {
            FelicaStandardCommand::WriteV2 {
                block_list: parsed_block_list,
                data: parsed_data,
            } => {
                assert_eq!(parsed_block_list, block_list);
                assert_eq!(parsed_data, data);
            }
            _ => panic!("unexpected parsed secure command variant"),
        }
    }

    #[test]
    fn parse_secure_payload_rejects_non_empty_change_system_block_payload() {
        assert_protocol_error_contains(
            FelicaStandardCommand::parse_secure_payload(CHANGE_SYSTEM_BLOCK_COMMAND_CODE, &[0x01]),
            "payload must be empty",
        );
    }

    #[test]
    fn parse_frame_rejects_empty_frame() {
        assert_protocol_error_contains(
            FelicaStandardCommand::parse_frame(&[]),
            "empty Felica frame",
        );
    }

    #[test]
    fn parse_payload_rejects_empty_payload() {
        assert_protocol_error_contains(
            FelicaStandardCommand::parse_payload(&[]),
            "empty command payload",
        );
    }

    #[test]
    fn parse_payload_rejects_secure_command_without_decryption() {
        assert_protocol_error_contains(
            FelicaStandardCommand::parse_payload(&[READ_COMMAND_CODE]),
            "requires decryption",
        );
    }

    #[test]
    fn parse_payload_rejects_request_response_trailing_bytes() {
        let mut payload = vec![REQUEST_RESPONSE_COMMAND_CODE];
        payload.extend_from_slice(&sample_idm());
        payload.push(0x00);

        assert_protocol_error_contains(
            FelicaStandardCommand::parse_payload(&payload),
            "payload has trailing bytes",
        );
    }

    #[test]
    fn parse_payload_rejects_write_without_encryption_truncated_data() {
        let mut payload = vec![WRITE_WITHOUT_ENCRYPTION_COMMAND_CODE];
        payload.extend_from_slice(&sample_idm());
        payload.push(0x01);
        payload.extend_from_slice(&ServiceCode::new(0x090F).to_le_bytes());
        payload.push(0x01);
        payload.extend_from_slice(&BlockListElement::new(0x0002, 0x00, 0x00).pack());
        payload.extend_from_slice(&[0xAB; BLOCK_SIZE - 1]);

        assert_protocol_error_contains(
            FelicaStandardCommand::parse_payload(&payload),
            "data truncated",
        );
    }

    #[test]
    fn parse_payload_rejects_non_zero_reserved_set_parameter_d6_d7() {
        let mut payload = vec![SET_PARAMETER_COMMAND_CODE];
        payload.extend_from_slice(&sample_idm());
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);

        assert_protocol_error_contains(
            FelicaStandardCommand::parse_payload(&payload),
            "reserved bytes D6-D7 must be 0x00",
        );
    }

    #[test]
    fn parse_payload_rejects_request_product_information_trailing_bytes() {
        let mut payload = vec![REQUEST_PRODUCT_INFORMATION_COMMAND_CODE];
        payload.extend_from_slice(&sample_idm());
        payload.push(0x00);

        assert_protocol_error_contains(
            FelicaStandardCommand::parse_payload(&payload),
            "payload has trailing bytes",
        );
    }

    #[test]
    fn parse_secure_payload_rejects_secure_read_block_count_zero() {
        assert_protocol_error_contains(
            FelicaStandardCommand::parse_secure_payload(READ_COMMAND_CODE, &[0x00]),
            "block count out of range",
        );
    }

    #[test]
    fn parse_secure_payload_rejects_secure_write_truncated_data() {
        let mut payload = vec![0x01];
        payload.extend_from_slice(&BlockListElement::new(0x0001, 0x00, 0x00).pack());
        payload.extend_from_slice(&[0xCD; BLOCK_SIZE - 1]);

        assert_protocol_error_contains(
            FelicaStandardCommand::parse_secure_payload(WRITE_COMMAND_CODE, &payload),
            "data truncated",
        );
    }

    #[test]
    fn parse_secure_payload_rejects_unsupported_secure_command_code() {
        assert_protocol_error_contains(
            FelicaStandardCommand::parse_secure_payload(0x99, &[]),
            "unsupported secure command code",
        );
    }
}
