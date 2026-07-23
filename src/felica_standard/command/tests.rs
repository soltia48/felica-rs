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
