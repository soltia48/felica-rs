use super::*;
use crate::driver::errors::DriverError;
use crate::felica_standard::secure::{
    build_secure_response_frame_des, build_secure_response_frame_v2_aes128,
    generate_registration_package_des,
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
        [0x01; 8], [0x02; 8], [0x03; 8], 0x0100,
    )];
    assert_invalid_parameter_contains(felica.change_keys(&params), "only supported for Write");
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
