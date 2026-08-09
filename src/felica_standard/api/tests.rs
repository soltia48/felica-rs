use super::*;
use crate::driver::errors::DriverError;
use crate::felica_standard::secure::{
    build_secure_response_frame_des, build_secure_response_frame_v2_aes128,
    generate_registration_package_des,
};
use crate::felica_standard::{
    MAX_PACKET_LEN, READ_COMMAND_CODE, ReadWithoutEncryptionResult, WRITE_COMMAND_CODE,
};
use std::collections::VecDeque;

struct MockDriver {
    detect_result: Option<DriverResult<Type3TagPollingResult>>,
    transceive_responses: VecDeque<DriverResult<Vec<u8>>>,
}

impl MockDriver {
    fn with_polling_result(polling_result: Type3TagPollingResult) -> Self {
        Self {
            detect_result: Some(Ok(polling_result)),
            transceive_responses: VecDeque::new(),
        }
    }

    fn with_detect_error(message: &str) -> Self {
        Self {
            detect_result: Some(Err(DriverError::other(message))),
            transceive_responses: VecDeque::new(),
        }
    }

    fn queue_response(&mut self, response: Vec<u8>) {
        self.transceive_responses.push_back(Ok(response));
    }
}

impl FelicaDriver for MockDriver {
    fn detect_type_f(
        &mut self,
        _target: &RemoteTarget,
        _system_code: u16,
        _request_code: u8,
        _time_slots: u8,
    ) -> DriverResult<Type3TagPollingResult> {
        self.detect_result
            .take()
            .unwrap_or_else(|| Err(DriverError::other("detect_type_f not configured")))
    }

    fn transceive(
        &mut self,
        _target: &RemoteTarget,
        _data: &[u8],
        _timeout_ms: Option<u16>,
    ) -> DriverResult<Vec<u8>> {
        self.transceive_responses
            .pop_front()
            .unwrap_or_else(|| Err(DriverError::other("transceive not configured")))
    }
}

fn sample_idm() -> [u8; 8] {
    [1, 2, 3, 4, 5, 6, 7, 8]
}

fn sample_polling_result() -> Type3TagPollingResult {
    Type3TagPollingResult {
        idm: sample_idm().to_vec(),
        pmm: vec![0; 8],
        optional: vec![],
    }
}

fn assert_invalid_parameter_contains<T>(result: Result<T, FelicaStandardError>, expected: &str) {
    match result {
        Err(FelicaStandardError::InvalidParameter(message)) => {
            assert!(
                message.contains(expected),
                "unexpected invalid-parameter message: {message}"
            );
        }
        Err(other) => panic!("expected InvalidParameter error, got {other}"),
        Ok(_) => panic!("expected InvalidParameter error, got Ok"),
    }
}

fn assert_protocol_error_contains<T>(result: Result<T, FelicaStandardError>, expected: &str) {
    match result {
        Err(FelicaStandardError::Protocol(message)) => {
            assert!(
                message.contains(expected),
                "unexpected protocol message: {message}"
            );
        }
        Err(other) => panic!("expected Protocol error, got {other}"),
        Ok(_) => panic!("expected Protocol error, got Ok"),
    }
}

#[test]
fn helper_len_and_index_validation() {
    assert!(ensure_len_in_range("x", 1, 1, 2).is_ok());
    assert!(ensure_len_in_range("x", 2, 1, 2).is_ok());
    assert_invalid_parameter_contains(ensure_len_in_range("x", 0, 1, 2), "between 1 and 2");

    let block_list = vec![BlockListElement::new(0x0001, 1, 0)];
    assert_invalid_parameter_contains(
        validate_block_list_indices(&block_list, 1),
        "out-of-range service index",
    );
}

#[test]
fn helper_data_length_and_registration_package_validation() {
    assert!(ensure_block_data_length(2, 32).is_ok());
    assert_invalid_parameter_contains(
        ensure_block_data_length(2, 31),
        "data length must equal 16 * block_list length",
    );

    assert_invalid_parameter_contains(
        generate_registration_package_des(&[0x00; 10], &[0x11; DES_BLOCK_SIZE]),
        "multiple of 8 bytes",
    );

    let package = generate_registration_package_des(&[0xAB; 16], &[0x11; DES_BLOCK_SIZE]).unwrap();
    assert_eq!(package.len(), 24);
}

#[test]
fn polling_propagates_driver_error() {
    let mut driver = MockDriver::with_detect_error("detect failed");
    let result = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00);
    match result {
        Err(FelicaStandardError::Driver(DriverError::Other(message))) => {
            assert!(message.contains("detect failed"));
        }
        Err(other) => panic!("expected driver error, got {other}"),
        Ok(_) => panic!("expected polling to fail"),
    }
}

/// A driver that records every bitrate `detect_type_f` is polled at and only
/// activates a card for the bitrates it was told to support.
struct BitrateMockDriver {
    supported: Vec<&'static str>,
    attempts: Vec<String>,
}

impl BitrateMockDriver {
    fn new(supported: Vec<&'static str>) -> Self {
        Self {
            supported,
            attempts: Vec::new(),
        }
    }
}

impl FelicaDriver for BitrateMockDriver {
    fn detect_type_f(
        &mut self,
        target: &RemoteTarget,
        _system_code: u16,
        _request_code: u8,
        _time_slots: u8,
    ) -> DriverResult<Type3TagPollingResult> {
        let bitrate = target.bitrate().to_string();
        self.attempts.push(bitrate.clone());
        if self.supported.iter().any(|&b| b == bitrate) {
            Ok(sample_polling_result())
        } else {
            Err(DriverError::other(format!("no card at {bitrate}")))
        }
    }

    fn transceive(
        &mut self,
        _target: &RemoteTarget,
        _data: &[u8],
        _timeout_ms: Option<u16>,
    ) -> DriverResult<Vec<u8>> {
        Err(DriverError::other("transceive not configured"))
    }
}

#[test]
fn order_felica_bitrates_prefers_424f_and_dedups() {
    assert_eq!(
        order_felica_bitrates(&["212F", "424F"]),
        vec!["424F", "212F"]
    );
    assert_eq!(
        order_felica_bitrates(&["424F", "212F"]),
        vec!["424F", "212F"]
    );
    assert_eq!(order_felica_bitrates(&["212F"]), vec!["212F"]);
    assert_eq!(order_felica_bitrates(&["424F"]), vec!["424F"]);
    assert_eq!(
        order_felica_bitrates(&["212F", "424F", "212F"]),
        vec!["424F", "212F"]
    );
    // Unrecognized bitrates keep their relative order after the FeliCa rates.
    assert_eq!(
        order_felica_bitrates(&["106A", "424F"]),
        vec!["424F", "106A"]
    );
}

#[test]
fn polling_multi_prefers_424f_when_card_supports_it() {
    let mut driver = BitrateMockDriver::new(vec!["424F", "212F"]);
    {
        let (felica, _) =
            FelicaStandard::polling_multi(&mut driver, &["212F", "424F"], 0xFFFF, 0x00, 0x00)
                .expect("polling should succeed at 424F");
        // The retained bitrate must be the one that activated the card.
        assert_eq!(felica.bitrate(), "424F");
    }
    // 424F succeeds first, so 212F is never attempted.
    assert_eq!(driver.attempts, vec!["424F".to_string()]);
}

#[test]
fn polling_multi_falls_back_to_212f_when_424f_unsupported() {
    let mut driver = BitrateMockDriver::new(vec!["212F"]);
    {
        let (felica, _) =
            FelicaStandard::polling_multi(&mut driver, &["212F", "424F"], 0xFFFF, 0x00, 0x00)
                .expect("polling should fall back to 212F");
        assert_eq!(felica.bitrate(), "212F");
    }
    // 424F is tried first, then the 212F fallback.
    assert_eq!(
        driver.attempts,
        vec!["424F".to_string(), "212F".to_string()]
    );
}

#[test]
fn polling_multi_rejects_empty_bitrates() {
    let mut driver = BitrateMockDriver::new(vec![]);
    let result = FelicaStandard::polling_multi(&mut driver, &[], 0xFFFF, 0x00, 0x00).map(|_| ());
    assert_invalid_parameter_contains(result, "at least one bitrate");
}

#[test]
fn polling_multi_returns_last_error_when_no_card_responds() {
    let mut driver = BitrateMockDriver::new(vec![]);
    match FelicaStandard::polling_multi(&mut driver, &["424F", "212F"], 0xFFFF, 0x00, 0x00) {
        Err(FelicaStandardError::Driver(DriverError::Other(message))) => {
            // The last attempt (212F) surfaces its error.
            assert!(
                message.contains("212F"),
                "expected the 212F error to surface, got {message}"
            );
        }
        Err(other) => panic!("expected driver error, got {other}"),
        Ok(_) => panic!("expected polling to fail"),
    }
    assert_eq!(
        driver.attempts,
        vec!["424F".to_string(), "212F".to_string()]
    );
}

#[test]
fn request_service_rejects_empty_service_codes() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");

    assert_invalid_parameter_contains(felica.request_service(&[]), "service_codes");
}

#[test]
fn request_response_reports_unexpected_response_variant() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let unexpected_frame = FelicaStandardResponse::RequestService {
        idm: sample_idm(),
        key_versions: vec![0x1234],
    }
    .to_frame()
    .unwrap();
    driver.queue_response(unexpected_frame);

    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");

    assert_protocol_error_contains(
        felica.request_response(),
        "unexpected response for Request Response command",
    );
}

#[test]
fn read_without_encryption_maps_status_error() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let frame = FelicaStandardResponse::ReadWithoutEncryption {
        idm: sample_idm(),
        status_flag1: 0xA5,
        status_flag2: 0x01,
        result: None,
    }
    .to_frame()
    .unwrap();
    driver.queue_response(frame);

    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    let result = felica.read_without_encryption(
        &[ServiceCode::new(0x090F)],
        &[BlockListElement::new(0x0001, 0, 0)],
    );

    match result {
        Err(FelicaStandardError::Status {
            command,
            status_flag1,
            status_flag2,
            ..
        }) => {
            assert_eq!(command, "Read Without Encryption");
            assert_eq!(status_flag1, 0xA5);
            assert_eq!(status_flag2, 0x01);
        }
        Err(other) => panic!("expected status error, got {other}"),
        Ok(_) => panic!("expected read_without_encryption to fail"),
    }
}

#[test]
fn secure_read_round_trip_with_mock_driver() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let tx_id = [1, 2, 3, 4, 5, 6];
    let tx_key = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    let block = [0xAB; BLOCK_SIZE];

    let secure_payload = FelicaStandardResponse::Read {
        status_flag1: 0x00,
        status_flag2: 0x00,
        result: Some(super::super::types::ReadResult {
            blocks: vec![block],
        }),
    }
    .to_secure_payload()
    .unwrap();

    let response_frame = build_secure_response_frame_des(
        super::super::constants::READ_COMMAND_CODE + 1,
        3,
        &tx_id,
        &tx_key,
        &secure_payload,
    )
    .expect("secure response frame build should succeed");
    driver.queue_response(response_frame);

    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    felica.authenticated_context = Some(AuthenticatedContext::new(
        1,
        tx_id,
        SecureSessionCredentials::Des(tx_key),
    ));

    let blocks = felica
        .read(&[BlockListElement::new(0x0001, 0, 0)])
        .expect("secure read should succeed");
    assert_eq!(blocks, vec![block]);
    assert_eq!(
        felica.authenticated_context().unwrap().transaction_number(),
        3
    );
    assert_eq!(
        felica.authenticated_scheme(),
        Some(SecureSessionScheme::Des)
    );
}

#[test]
fn secure_read_round_trip_with_mock_driver_v2() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let tx_id = [1, 2, 3, 4, 5, 6];
    let encryption_key = [0x21u8; 16];
    let mac_key = [0x31u8; 16];
    let challenge_3c = [0x00u8; 4];
    let block = [0xCD; BLOCK_SIZE];

    let secure_payload = FelicaStandardResponse::Read {
        status_flag1: 0x00,
        status_flag2: 0x00,
        result: Some(super::super::types::ReadResult {
            blocks: vec![block],
        }),
    }
    .to_secure_payload()
    .unwrap();

    let response_frame = build_secure_response_frame_v2_aes128(
        super::super::constants::READ_V2_COMMAND_CODE + 1,
        3,
        &tx_id,
        &challenge_3c,
        &encryption_key,
        &mac_key,
        &secure_payload,
    )
    .expect("secure response frame build should succeed");
    driver.queue_response(response_frame);

    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    felica.set_authenticated_context(AuthenticatedContext::new(
        1,
        tx_id,
        SecureSessionCredentials::Aes128 {
            encryption_key,
            mac_key,
            challenge_3c,
        },
    ));

    let blocks = felica
        .read_v2(&[BlockListElement::new(0x0001, 0, 0)])
        .expect("secure read v2 should succeed");
    assert_eq!(blocks, vec![block]);
    assert_eq!(
        felica.authenticated_context().unwrap().transaction_number(),
        3
    );
    assert_eq!(
        felica.authenticated_scheme(),
        Some(SecureSessionScheme::Aes128)
    );
}

#[test]
fn secure_read_rejects_bad_response_length_field() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let bad_frame = vec![
        0x05,
        super::super::constants::READ_COMMAND_CODE + 1,
        0xAA,
        0xBB,
    ];
    driver.queue_response(bad_frame);

    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    felica.authenticated_context = Some(AuthenticatedContext::new(
        1,
        [1, 2, 3, 4, 5, 6],
        SecureSessionCredentials::Des([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]),
    ));

    assert_protocol_error_contains(
        felica.read(&[BlockListElement::new(0x0001, 0, 0)]),
        "length field does not match payload",
    );
}

#[test]
fn authentication1_v2_parses_v2_response() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let frame = FelicaStandardResponse::Authentication1V2 {
        idm: sample_idm(),
        challenge_1b: [0x11; 16],
        challenge_2a: [0x22; 16],
        challenge_3c: [0x33; 4],
    }
    .to_frame()
    .unwrap();
    driver.queue_response(frame);

    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    let nodes = [0x0100u16, 0x0101u16];
    let challenge_1a = [0x44; 16];

    let result = felica
        .authentication1_v2(0x00, &nodes, &challenge_1a)
        .expect("authentication1_v2 should succeed");
    assert_eq!(result.0, [0x11; 16]);
    assert_eq!(result.1, [0x22; 16]);
    assert_eq!(result.2, [0x33; 4]);
}

#[test]
fn authentication2_v2_reports_scheme() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let frame = FelicaStandardResponse::Authentication2V2(Authentication2V2Response {
        encrypted_payload: vec![0xAA; 8],
    })
    .to_frame()
    .unwrap();
    driver.queue_response(frame);

    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    let challenge_2b = [0x55; 16];

    let response = felica
        .authentication2_v2(&challenge_2b)
        .expect("authentication2_v2 should succeed");
    assert_eq!(response.scheme(), SecureSessionScheme::Aes128);
}

#[test]
fn mutual_authentication_v2_requires_nodes() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");

    assert_invalid_parameter_contains(
        felica.mutual_authentication_v2(0x00, &[], &[0u8; 16], &[0u8; 16]),
        "requires at least one node code",
    );
}

#[test]
fn change_keys_rejects_aes128_session() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    felica.set_authenticated_context(AuthenticatedContext::new(
        1,
        [1, 2, 3, 4, 5, 6],
        SecureSessionCredentials::Aes128 {
            encryption_key: [0x11; 16],
            mac_key: [0x22; 16],
            challenge_3c: [0x00; 4],
        },
    ));

    let params = [ChangeKeyParameters::new(
        0x1008, [0x01; 8], [0x02; 8], [0x03; 8], 0x0100,
    )];
    assert_invalid_parameter_contains(felica.change_keys(&params), "only supported for Write");
}

/// A key change names its node by position in the list the session was opened
/// against, so a node that list does not contain has no position to use. Sending
/// it anyway would rewrite the key of whichever node does sit at the position,
/// which is why this is rejected before anything reaches the card.
#[test]
fn change_keys_rejects_a_node_outside_the_authenticated_node_list() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    felica.set_authenticated_context(
        AuthenticatedContext::new(
            1,
            [1, 2, 3, 4, 5, 6],
            SecureSessionCredentials::Des([0x10; 8]),
        )
        .with_nodes(vec![0x0048, 0xFFFF]),
    );

    let params = [ChangeKeyParameters::new(
        0x1008, [0x01; 8], [0x02; 8], [0x03; 8], 0x0100,
    )];
    assert_invalid_parameter_contains(
        felica.change_keys(&params),
        "is not in the authenticated node list",
    );
}

/// The system node is addressable like any other: naming it among the session's
/// services is what makes its key changeable.
#[test]
fn change_keys_targets_a_node_of_the_authenticated_session() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let tx_id = [1, 2, 3, 4, 5, 6];
    let tx_key = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];

    let secure_payload = FelicaStandardResponse::Write {
        status_flag1: 0x00,
        status_flag2: 0x00,
    }
    .to_secure_payload()
    .unwrap();
    let response_frame = build_secure_response_frame_des(
        WRITE_COMMAND_CODE + 1,
        3,
        &tx_id,
        &tx_key,
        &secure_payload,
    )
    .expect("secure response frame build should succeed");
    driver.queue_response(response_frame);

    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    felica.set_authenticated_context(
        AuthenticatedContext::new(1, tx_id, SecureSessionCredentials::Des(tx_key))
            .with_nodes(vec![0x0048, 0xFFFF]),
    );

    let context = felica.authenticated_context().unwrap();
    assert_eq!(context.nodes(), &[0x0048, 0xFFFF]);
    assert_eq!(context.node_index(0xFFFF), Some(1));

    let params = [ChangeKeyParameters::new(
        0xFFFF, [0x01; 8], [0x02; 8], [0x03; 8], 0x0003,
    )];
    felica
        .change_keys(&params)
        .expect("changing the system key of a listed node should succeed");
}

#[test]
fn send_command_rejects_when_idm_length_is_not_8() {
    let mut driver = MockDriver::with_polling_result(Type3TagPollingResult {
        idm: vec![1, 2, 3, 4, 5, 6, 7],
        pmm: vec![0; 8],
        optional: vec![],
    });
    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");

    assert_invalid_parameter_contains(felica.request_response(), "IDm must be 8 bytes long");
}

/// §4.4.2 defines request codes 00h-02h and time slot values 00h/01h/03h/07h/0Fh,
/// and states that any other time slot value behaves differently from product to
/// product. Neither may be put on the air.
#[test]
fn polling_rejects_undefined_request_codes_and_time_slot_values() {
    for request_code in [0x03u8, 0x10, 0xFF] {
        let mut driver = MockDriver::with_polling_result(sample_polling_result());
        assert_invalid_parameter_contains(
            FelicaStandard::polling(&mut driver, "212F", 0xFFFF, request_code, 0x00),
            "is reserved",
        );
    }

    for time_slots in [0x02u8, 0x05, 0x08, 0x10, 0xFF] {
        let mut driver = MockDriver::with_polling_result(sample_polling_result());
        assert_invalid_parameter_contains(
            FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, time_slots),
            "is not defined",
        );
    }
}

#[test]
fn polling_accepts_every_defined_request_code_and_time_slot_value() {
    for request_code in [0x00u8, 0x01, 0x02] {
        let mut driver = MockDriver::with_polling_result(sample_polling_result());
        assert!(FelicaStandard::polling(&mut driver, "212F", 0xFFFF, request_code, 0x00).is_ok());
    }

    for time_slots in [0x00u8, 0x01, 0x03, 0x07, 0x0F] {
        let mut driver = MockDriver::with_polling_result(sample_polling_result());
        assert!(FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, time_slots).is_ok());
    }
}

/// §4.5.2 (table 4-11): status flag 2 = 71h is a warning raised *after* the write
/// has happened, and some products pair it with status flag 1 = 00h. Such a
/// response reports a completed write and must not surface as an error.
#[test]
fn write_without_encryption_accepts_the_memory_rewrite_count_warning() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    driver.queue_response(
        FelicaStandardResponse::WriteWithoutEncryption {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x71,
        }
        .to_frame()
        .unwrap(),
    );

    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    let block_list = [BlockListElement::new(0x0000, 0x00, 0x00)];
    felica
        .write_without_encryption(
            &[ServiceCode::new(0x0009)],
            &block_list,
            &[0xAA; BLOCK_SIZE],
        )
        .expect("a normal-completion status flag 1 means the write was performed");
}

/// A non-zero status flag 1 still fails, warning byte or not.
#[test]
fn write_without_encryption_still_fails_on_a_non_zero_status_flag1() {
    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    driver.queue_response(
        FelicaStandardResponse::WriteWithoutEncryption {
            idm: sample_idm(),
            status_flag1: 0xFF,
            status_flag2: 0x71,
        }
        .to_frame()
        .unwrap(),
    );

    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    let block_list = [BlockListElement::new(0x0000, 0x00, 0x00)];
    match felica.write_without_encryption(
        &[ServiceCode::new(0x0009)],
        &block_list,
        &[0xAA; BLOCK_SIZE],
    ) {
        Err(FelicaStandardError::Status {
            status_flag1,
            status_flag2,
            ..
        }) => {
            assert_eq!(status_flag1, 0xFF);
            assert_eq!(status_flag2, 0x71);
        }
        other => panic!("expected a status error, got {other:?}"),
    }
}

/// §4.4.5 leaves 最大同時読み出しブロック数 to the product, but the *response* is
/// what bounds a read: 16 bytes per block on a 13-byte header against the
/// 255-byte packet limit of §2.2 allows 15 blocks at most. The command itself
/// stays small, so this cannot be caught when the frame is built.
#[test]
fn read_without_encryption_rejects_more_blocks_than_a_response_can_carry() {
    let block_list: Vec<BlockListElement> = (0..16)
        .map(|block| BlockListElement::new(block, 0x00, 0x00))
        .collect();

    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    assert_invalid_parameter_contains(
        felica.read_without_encryption(&[ServiceCode::new(0x0009)], &block_list),
        "must contain between 1 and 15 entries",
    );

    // 15 blocks is accepted, and the response it implies is exactly 253 bytes.
    let blocks: Vec<[u8; BLOCK_SIZE]> = (0..15).map(|index| [index as u8; BLOCK_SIZE]).collect();
    let frame = FelicaStandardResponse::ReadWithoutEncryption {
        idm: sample_idm(),
        status_flag1: 0x00,
        status_flag2: 0x00,
        result: Some(ReadWithoutEncryptionResult {
            blocks: blocks.clone(),
        }),
    }
    .to_frame()
    .expect("a 15-block response fits in one packet");
    assert_eq!(frame.len(), 253);

    let mut driver = MockDriver::with_polling_result(sample_polling_result());
    driver.queue_response(frame);
    let (mut felica, _) = FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
        .expect("polling should succeed");
    let read = felica
        .read_without_encryption(&[ServiceCode::new(0x0009)], &block_list[..15])
        .expect("15 blocks is within the response limit");
    assert_eq!(read, blocks);
}

/// The block count a secure command can carry is fixed by the 255-byte packet
/// limit of §2.2 acting on the secure-messaging framing, measured here by
/// building real frames rather than by restating the arithmetic.
///
/// Reads are bounded by their *response* and writes by their *command*:
///
/// | command  | read (response-bound) | write (command-bound, 2/3-byte elements) |
/// |----------|----------------------:|-----------------------------------------:|
/// | Read/Write     (DES)    | 14 | 12 / 12 |
/// | Read/Write v2  (AES)    | 15 | 13 / 12 |
///
/// The DES scheme loses a block to its PKCS#7 padding; the v2 scheme is an OFB
/// stream and needs none.
#[test]
fn secure_block_count_limits_follow_the_secure_messaging_framing() {
    fn block_list_payload(blocks: usize, three_byte: bool) -> Vec<u8> {
        // Block numbers below 256 pack into two bytes; 0x0100 upward force three.
        let base = if three_byte { 0x0100u16 } else { 0x0000 };
        let mut payload = vec![blocks as u8];
        for index in 0..blocks {
            payload.extend(BlockListElement::new(base + index as u16, 0, 0).pack());
        }
        payload
    }

    fn credentials(des: bool) -> SecureSessionCredentials {
        if des {
            SecureSessionCredentials::Des([0x11; 8])
        } else {
            SecureSessionCredentials::Aes128 {
                encryption_key: [0x22; 16],
                mac_key: [0x33; 16],
                challenge_3c: [0x44; 4],
            }
        }
    }

    /// On-air length of the command frame the client would send.
    fn command_frame_len(des: bool, code: u8, command_payload: &[u8]) -> Option<usize> {
        let mut context = AuthenticatedContext::new(0, [1, 2, 3, 4, 5, 6], credentials(des));
        let captured = SecureCommandContext::capture(&mut context).ok()?;
        let payload = captured.build_secure_payload(command_payload);
        let encrypted = captured.encrypt_command(code, payload).ok()?;
        let mut framed = vec![code];
        framed.extend_from_slice(&encrypted);
        frame_with_length_prefix(&framed).ok().map(|f| f.len())
    }

    /// On-air length of the response frame the card would have to send back.
    fn read_response_frame_len(des: bool, code: u8, blocks: usize) -> Option<usize> {
        let mut payload = vec![0x00, 0x00, blocks as u8];
        payload.extend(vec![0u8; blocks * BLOCK_SIZE]);
        if des {
            build_secure_response_frame_des(code, 1, &[1, 2, 3, 4, 5, 6], &[0x11; 8], &payload)
                .map(|frame| frame.len())
        } else {
            build_secure_response_frame_v2_aes128(
                code,
                1,
                &[1, 2, 3, 4, 5, 6],
                &[0x44; 4],
                &[0x22; 16],
                &[0x33; 16],
                &payload,
            )
            .map(|frame| frame.len())
        }
    }

    /// Largest block count for which `frame_len` still yields a legal packet.
    fn largest_fitting(mut frame_len: impl FnMut(usize) -> Option<usize>) -> usize {
        let mut blocks = 0;
        while matches!(frame_len(blocks + 1), Some(len) if len <= MAX_PACKET_LEN) {
            blocks += 1;
        }
        blocks
    }

    // Reads: the response is what runs out of room, and the constants the client
    // checks against must be exactly that measured limit.
    assert_eq!(
        largest_fitting(|blocks| read_response_frame_len(true, READ_COMMAND_CODE + 1, blocks)),
        14,
    );
    assert_eq!(MAX_SECURE_READ_BLOCK_COUNT, 14);
    assert_eq!(
        largest_fitting(|blocks| read_response_frame_len(false, READ_V2_RESPONSE_CODE, blocks)),
        15,
    );
    assert_eq!(MAX_SECURE_READ_V2_BLOCK_COUNT, 15);

    // A read command is nowhere near the limit at those counts, which is why the
    // frame builder alone cannot catch an over-long read.
    for (des, code, limit) in [
        (true, READ_COMMAND_CODE, MAX_SECURE_READ_BLOCK_COUNT),
        (false, READ_V2_COMMAND_CODE, MAX_SECURE_READ_V2_BLOCK_COUNT),
    ] {
        for three_byte in [false, true] {
            assert!(
                largest_fitting(|blocks| command_frame_len(
                    des,
                    code,
                    &block_list_payload(blocks, three_byte)
                )) > limit,
                "the command side must not be the binding constraint for a read"
            );
        }
    }

    // Writes: the command is what runs out of room, and the limit depends on the
    // block list element width, so it cannot be a single constant.
    fn write_command_limit(des: bool, code: u8, three_byte: bool) -> usize {
        largest_fitting(|blocks| {
            let mut payload = block_list_payload(blocks, three_byte);
            payload.extend(vec![0u8; blocks * BLOCK_SIZE]);
            command_frame_len(des, code, &payload)
        })
    }
    assert_eq!(write_command_limit(true, WRITE_COMMAND_CODE, false), 12);
    assert_eq!(write_command_limit(true, WRITE_COMMAND_CODE, true), 12);
    assert_eq!(write_command_limit(false, WRITE_V2_COMMAND_CODE, false), 13);
    assert_eq!(write_command_limit(false, WRITE_V2_COMMAND_CODE, true), 12);
}
