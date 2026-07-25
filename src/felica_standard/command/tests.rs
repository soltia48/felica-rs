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

    let frame = command.to_frame().unwrap();
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

    let frame = command.to_frame().unwrap();
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

    let (opcode, payload) = match command.encoding().unwrap() {
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

    let (opcode, payload) = match command.encoding().unwrap() {
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

/// §2.2: LEN is a single byte holding "packet data length + 1", so a packet
/// tops out at 255 bytes. A 16-block Write Without Encryption needs 302 and
/// must be refused rather than emitted with a wrapped-around LEN byte, which
/// every card answers with silence.
#[test]
fn to_frame_rejects_a_packet_longer_than_the_len_byte_can_describe() {
    let block_list: Vec<BlockListElement> = (0..16)
        .map(|block| BlockListElement::new(block, 0x00, 0x00))
        .collect();
    let command = FelicaStandardCommand::WriteWithoutEncryption {
        idm: sample_idm(),
        service_codes: vec![ServiceCode::new(0x0009)],
        block_list,
        data: vec![0x00; 16 * BLOCK_SIZE],
    };

    match command.to_frame() {
        Err(FelicaStandardError::Protocol(message)) => {
            assert!(
                message.contains("302 bytes") && message.contains("255 bytes"),
                "unexpected protocol message: {message}"
            );
        }
        Err(other) => panic!("expected protocol error, got {other}"),
        Ok(frame) => panic!("expected an error, got a {}-byte frame", frame.len()),
    }
}

/// §4.4.6's worked examples of 最大同時書き込みブロック数 are exactly what the
/// 255-byte packet limit allows, which is how a caller can tell whether a block
/// list is too long without knowing the product:
///
/// - one service, two-byte block list elements -> 13 blocks (248 bytes)
/// - sixteen services, three-byte elements     -> 11 blocks (253 bytes)
#[test]
fn write_block_count_limit_matches_the_worked_examples_of_section_4_4_6() {
    fn build(service_count: usize, block_count: usize, three_byte: bool) -> Option<usize> {
        // A block number below 256 packs into two bytes; 0x0100 forces three.
        let base = if three_byte { 0x0100u16 } else { 0x0000 };
        let block_list: Vec<BlockListElement> = (0..block_count)
            .map(|index| BlockListElement::new(base + index as u16, 0x00, 0x00))
            .collect();
        let service_codes = (0..service_count)
            .map(|index| ServiceCode::new((index as u16) << 6 | 0x0009))
            .collect();
        FelicaStandardCommand::WriteWithoutEncryption {
            idm: sample_idm(),
            service_codes,
            block_list,
            data: vec![0x00; block_count * BLOCK_SIZE],
        }
        .to_frame()
        .ok()
        .map(|frame| frame.len())
    }

    assert_eq!(build(1, 13, false), Some(248), "13 blocks is the maximum");
    assert_eq!(build(1, 14, false), None, "14 blocks does not fit");

    assert_eq!(build(16, 11, true), Some(253), "11 blocks is the maximum");
    assert_eq!(build(16, 12, true), None, "12 blocks does not fit");
}

/// A frame at the limit must still carry a LEN byte that matches its length and
/// parse back cleanly.
#[test]
fn to_frame_accepts_the_longest_packet_the_len_byte_can_describe() {
    let fitting: Vec<BlockListElement> = (0..13)
        .map(|block| BlockListElement::new(block, 0x00, 0x00))
        .collect();
    let frame = FelicaStandardCommand::WriteWithoutEncryption {
        idm: sample_idm(),
        service_codes: vec![ServiceCode::new(0x0009)],
        block_list: fitting,
        data: vec![0x00; 13 * BLOCK_SIZE],
    }
    .to_frame()
    .expect("a 248-byte frame fits in the LEN byte");
    assert_eq!(frame.len(), 248);
    assert_eq!(frame[0] as usize, frame.len());
    assert!(FelicaStandardCommand::parse_frame(&frame).is_ok());
}

#[test]
fn to_frame_reports_secure_commands_as_an_error_instead_of_panicking() {
    let command = FelicaStandardCommand::Read {
        block_list: vec![BlockListElement::new(0x0000, 0x00, 0x00)],
    };
    match command.to_frame() {
        Err(FelicaStandardError::Protocol(message)) => {
            assert!(
                message.contains("secure commands must be encrypted"),
                "unexpected protocol message: {message}"
            );
        }
        other => panic!("expected a protocol error, got {other:?}"),
    }
}
