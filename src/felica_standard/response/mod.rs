use super::{
    AUTHENTICATION1_RESPONSE_CODE, AUTHENTICATION1_V2_RESPONSE_CODE, AUTHENTICATION2_RESPONSE_CODE,
    AUTHENTICATION2_V2_RESPONSE_CODE, AreaCodeRange, Authentication2Response,
    Authentication2V2Response, BLOCK_SIZE, CHANGE_SYSTEM_BLOCK_COMMAND_CODE, ContainerInformation,
    FelicaStandardError, GET_AREA_INFORMATION_RESPONSE_CODE, GET_CONTAINER_ID_RESPONSE_CODE,
    GET_CONTAINER_ISSUE_INFORMATION_RESPONSE_CODE, GET_CONTAINER_PROPERTY_RESPONSE_CODE,
    GET_NODE_PROPERTY_RESPONSE_CODE, GET_SYSTEM_STATUS_RESPONSE_CODE, GetAreaInformationResult,
    GetNodePropertyResult, GetSystemStatusResult, IDM_LEN, MAX_BLOCK_LIST_LEN, MAX_NODE_CODES,
    MAX_NODE_PROPERTY_CODES, MAX_SERVICE_CODES, NodeProperty, OptionVersion, POLLING_RESPONSE_CODE,
    READ_COMMAND_CODE, READ_V2_COMMAND_CODE, READ_WITHOUT_ENCRYPTION_RESPONSE_CODE,
    REGISTER_AREA_COMMAND_CODE, REGISTER_ISSUE_ID_COMMAND_CODE, REGISTER_SERVICE_COMMAND_CODE,
    REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE, REQUEST_BLOCK_INFORMATION_RESPONSE_CODE,
    REQUEST_CODE_LIST_RESPONSE_CODE, REQUEST_PRODUCT_INFORMATION_RESPONSE_CODE,
    REQUEST_RESPONSE_RESPONSE_CODE, REQUEST_SERVICE_RESPONSE_CODE,
    REQUEST_SERVICE_V2_RESPONSE_CODE, REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE,
    REQUEST_SYSTEM_CODE_RESPONSE_CODE, RESET_MODE_RESPONSE_CODE, ReadResult,
    ReadWithoutEncryptionResult, RegisterIssueIdResult, RegisterServiceResult,
    RequestBlockInformationExResult, RequestCodeListResult, RequestServiceV2KeyVersion,
    RequestServiceV2Result, SEARCH_SERVICE_CODE_RESPONSE_CODE, SET_PARAMETER_RESPONSE_CODE,
    SearchServiceCodeResult, ServiceCode, SpecificationVersion, WRITE_COMMAND_CODE,
    WRITE_V2_COMMAND_CODE, WRITE_WITHOUT_ENCRYPTION_RESPONSE_CODE, frame_with_length_prefix,
};
use crate::driver::errors::{DriverError, Result as DriverResult};

type Idm = [u8; IDM_LEN];
type Pmm = [u8; 8];

#[derive(Debug)]
pub enum FelicaStandardResponse {
    Polling {
        idm: Idm,
        pmm: Pmm,
        optional: Vec<u8>,
    },
    RequestService {
        idm: Idm,
        key_versions: Vec<u16>,
    },
    RequestResponse {
        idm: Idm,
        mode: u8,
    },
    ReadWithoutEncryption {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<ReadWithoutEncryptionResult>,
    },
    WriteWithoutEncryption {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
    },
    SearchServiceCode {
        idm: Idm,
        result: Option<SearchServiceCodeResult>,
    },
    RequestSystemCode {
        idm: Idm,
        system_codes: Vec<u16>,
    },
    RequestBlockInformation {
        idm: Idm,
        block_counts: Vec<u16>,
    },
    Authentication1 {
        idm: Idm,
        challenge_1b: [u8; 8],
        challenge_2a: [u8; 8],
    },
    Authentication2(Authentication2Response),
    RequestCodeList {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RequestCodeListResult>,
    },
    RequestBlockInformationEx {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RequestBlockInformationExResult>,
    },
    SetParameter {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
    },
    GetContainerIssueInformation {
        idm: Idm,
        container_information: ContainerInformation,
    },
    GetAreaInformation {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<GetAreaInformationResult>,
    },
    GetNodeProperty {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<GetNodePropertyResult>,
    },
    GetContainerProperty {
        data: Vec<u8>,
    },
    RequestServiceV2 {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RequestServiceV2Result>,
    },
    GetSystemStatus {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: GetSystemStatusResult,
    },
    RequestProductInformation {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        result: Option<Vec<u8>>,
    },
    RequestSpecificationVersion {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
        specification_version: Option<SpecificationVersion>,
    },
    ResetMode {
        idm: Idm,
        status_flag1: u8,
        status_flag2: u8,
    },
    Authentication1V2 {
        idm: Idm,
        challenge_1b: [u8; 16],
        challenge_2a: [u8; 16],
        challenge_3c: [u8; 4],
    },
    Authentication2V2(Authentication2V2Response),
    GetContainerId {
        container_idm: Idm,
    },
    Read {
        status_flag1: u8,
        status_flag2: u8,
        result: Option<ReadResult>,
    },
    Write {
        status_flag1: u8,
        status_flag2: u8,
    },
    ReadV2 {
        status_flag1: u8,
        status_flag2: u8,
        result: Option<ReadResult>,
    },
    WriteV2 {
        status_flag1: u8,
        status_flag2: u8,
    },
    RegisterIssueId {
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RegisterIssueIdResult>,
    },
    RegisterArea {
        status_flag1: u8,
        status_flag2: u8,
    },
    RegisterService {
        status_flag1: u8,
        status_flag2: u8,
        result: Option<RegisterServiceResult>,
    },
    ChangeSystemBlock {
        status_flag1: u8,
        status_flag2: u8,
    },
    Unknown,
}

mod parse;
mod serialize;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_idm() -> [u8; IDM_LEN] {
        [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
    }

    fn assert_protocol_error_contains<T>(result: Result<T, FelicaStandardError>, expected: &str) {
        match result {
            Err(FelicaStandardError::Protocol(message)) => {
                assert!(
                    message.contains(expected),
                    "unexpected protocol error message: {message}"
                );
            }
            Err(other) => panic!("expected FelicaStandardError::Protocol, got {other}"),
            Ok(_) => panic!("expected FelicaStandardError::Protocol, got Ok"),
        }
    }

    fn assert_driver_error_contains(result: DriverResult<FelicaStandardResponse>, expected: &str) {
        match result {
            Err(DriverError::Other(message)) => {
                assert!(
                    message.contains(expected),
                    "unexpected driver error message: {message}"
                );
            }
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(_) => panic!("expected DriverError::Other, got Ok"),
        }
    }

    #[test]
    fn from_bytes_parses_polling_with_optional_bytes() {
        let idm = sample_idm();
        let pmm = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let optional = vec![0xAA, 0xBB];

        let mut payload = vec![POLLING_RESPONSE_CODE];
        payload.extend_from_slice(&idm);
        payload.extend_from_slice(&pmm);
        payload.extend_from_slice(&optional);
        let frame = frame_with_length_prefix(&payload);

        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::Polling {
                idm: parsed_idm,
                pmm: parsed_pmm,
                optional: parsed_optional,
            } => {
                assert_eq!(parsed_idm, idm);
                assert_eq!(parsed_pmm, pmm);
                assert_eq!(parsed_optional, optional);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn from_bytes_parses_request_service_v2_dual_keys() {
        let idm = sample_idm();
        let mut payload = vec![REQUEST_SERVICE_V2_RESPONSE_CODE];
        payload.extend_from_slice(&idm);
        payload.extend_from_slice(&[0x00, 0x00, 0x41, 0x02]);
        payload.extend_from_slice(&0x1111u16.to_le_bytes());
        payload.extend_from_slice(&0x2222u16.to_le_bytes());
        payload.extend_from_slice(&0x3333u16.to_le_bytes());
        payload.extend_from_slice(&0x4444u16.to_le_bytes());
        let frame = frame_with_length_prefix(&payload);

        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestServiceV2 {
                idm: parsed_idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(parsed_idm, idm);
                assert_eq!(status_flag1, 0);
                assert_eq!(status_flag2, 0);
                let parsed_result = result.expect("missing request service v2 result");
                assert_eq!(parsed_result.crypto_id, 0x41);
                assert_eq!(
                    parsed_result.key_versions,
                    vec![
                        RequestServiceV2KeyVersion::Dual {
                            aes: 0x1111,
                            des: 0x3333
                        },
                        RequestServiceV2KeyVersion::Dual {
                            aes: 0x2222,
                            des: 0x4444
                        },
                    ]
                );
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn from_bytes_rejects_truncated_request_service_v2_dual_keys() {
        let idm = sample_idm();
        let mut payload = vec![REQUEST_SERVICE_V2_RESPONSE_CODE];
        payload.extend_from_slice(&idm);
        payload.extend_from_slice(&[0x00, 0x00, 0x41, 0x02]);
        payload.extend_from_slice(&0x1111u16.to_le_bytes());
        payload.extend_from_slice(&0x2222u16.to_le_bytes());
        payload.extend_from_slice(&0x3333u16.to_le_bytes());
        let frame = frame_with_length_prefix(&payload);

        assert_driver_error_contains(
            FelicaStandardResponse::from_bytes(&frame),
            "dual key version list truncated",
        );
    }

    #[test]
    fn from_bytes_parses_get_node_property_mac_payload() {
        let idm = sample_idm();
        let mut payload = vec![GET_NODE_PROPERTY_RESPONSE_CODE];
        payload.extend_from_slice(&idm);
        payload.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x00]);
        let frame = frame_with_length_prefix(&payload);

        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetNodeProperty {
                idm: parsed_idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(parsed_idm, idm);
                assert_eq!(status_flag1, 0);
                assert_eq!(status_flag2, 0);
                let parsed_result = result.expect("missing node property result");
                assert_eq!(
                    parsed_result.node_properties,
                    vec![
                        NodeProperty::MacCommunication { enabled: true },
                        NodeProperty::MacCommunication { enabled: false },
                    ]
                );
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn from_bytes_rejects_unknown_get_node_property_payload_length() {
        let idm = sample_idm();
        let mut payload = vec![GET_NODE_PROPERTY_RESPONSE_CODE];
        payload.extend_from_slice(&idm);
        payload.extend_from_slice(&[0x00, 0x00, 0x02, 0x01, 0x00, 0x01]);
        let frame = frame_with_length_prefix(&payload);

        assert_driver_error_contains(
            FelicaStandardResponse::from_bytes(&frame),
            "payload length does not match known node property format",
        );
    }

    #[test]
    fn from_bytes_parses_authentication2_v2_variant() {
        let encrypted_payload = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97];
        let mut payload = vec![AUTHENTICATION2_V2_RESPONSE_CODE];
        payload.extend_from_slice(&encrypted_payload);
        let frame = frame_with_length_prefix(&payload);

        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::Authentication2V2(auth) => {
                assert_eq!(auth.encrypted_payload, encrypted_payload);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn from_secure_bytes_parses_secure_read_success() {
        let mut block = [0u8; BLOCK_SIZE];
        for (index, byte) in block.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut data = vec![0x00, 0x00, 0x01];
        data.extend_from_slice(&block);

        let parsed = FelicaStandardResponse::from_secure_bytes(READ_COMMAND_CODE, &data).unwrap();
        match parsed {
            FelicaStandardResponse::Read {
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(status_flag1, 0);
                assert_eq!(status_flag2, 0);
                let parsed_result = result.expect("missing secure read result");
                assert_eq!(parsed_result.blocks.len(), 1);
                assert_eq!(parsed_result.blocks[0], block);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn from_secure_bytes_parses_secure_read_v2_success() {
        let mut block = [0u8; BLOCK_SIZE];
        for (index, byte) in block.iter_mut().enumerate() {
            *byte = (index as u8) ^ 0xA5;
        }
        let mut data = vec![0x00, 0x00, 0x01];
        data.extend_from_slice(&block);

        let parsed =
            FelicaStandardResponse::from_secure_bytes(READ_V2_COMMAND_CODE, &data).unwrap();
        match parsed {
            FelicaStandardResponse::ReadV2 {
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(status_flag1, 0);
                assert_eq!(status_flag2, 0);
                let parsed_result = result.expect("missing secure read result");
                assert_eq!(parsed_result.blocks.len(), 1);
                assert_eq!(parsed_result.blocks[0], block);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn from_secure_bytes_rejects_register_issue_id_without_remaining_blocks() {
        assert_driver_error_contains(
            FelicaStandardResponse::from_secure_bytes(
                REGISTER_ISSUE_ID_COMMAND_CODE,
                &[0x00, 0x00],
            ),
            "missing remaining block count",
        );
    }

    #[test]
    fn from_secure_bytes_rejects_unsupported_command_code() {
        assert_driver_error_contains(
            FelicaStandardResponse::from_secure_bytes(0x99, &[]),
            "unsupported secure Felica command response",
        );
    }

    #[test]
    fn to_payload_rejects_request_service_with_empty_key_versions() {
        let response = FelicaStandardResponse::RequestService {
            idm: sample_idm(),
            key_versions: Vec::new(),
        };

        assert_protocol_error_contains(response.to_payload(), "key version count out of range");
    }

    #[test]
    fn to_payload_rejects_success_read_without_encryption_without_result() {
        let response = FelicaStandardResponse::ReadWithoutEncryption {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: None,
        };

        assert_protocol_error_contains(response.to_payload(), "result is missing on success");
    }

    #[test]
    fn to_payload_rejects_error_read_without_encryption_with_result() {
        let response = FelicaStandardResponse::ReadWithoutEncryption {
            idm: sample_idm(),
            status_flag1: 0xA5,
            status_flag2: 0x00,
            result: Some(ReadWithoutEncryptionResult {
                blocks: vec![[0x00; BLOCK_SIZE]],
            }),
        };

        assert_protocol_error_contains(response.to_payload(), "result must be omitted on error");
    }

    #[test]
    fn to_payload_rejects_request_service_v2_mismatched_crypto_and_key_version_shape() {
        let dual_crypto_single_keys = FelicaStandardResponse::RequestServiceV2 {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(RequestServiceV2Result {
                crypto_id: 0x41,
                key_versions: vec![
                    RequestServiceV2KeyVersion::Single(0x1111),
                    RequestServiceV2KeyVersion::Single(0x2222),
                ],
            }),
        };
        assert_protocol_error_contains(
            dual_crypto_single_keys.to_payload(),
            "dual crypto requires dual key versions",
        );

        let single_crypto_dual_keys = FelicaStandardResponse::RequestServiceV2 {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(RequestServiceV2Result {
                crypto_id: 0x40,
                key_versions: vec![RequestServiceV2KeyVersion::Dual {
                    aes: 0x3333,
                    des: 0x4444,
                }],
            }),
        };
        assert_protocol_error_contains(
            single_crypto_dual_keys.to_payload(),
            "single crypto requires single key versions",
        );
    }

    #[test]
    fn secure_read_to_secure_payload_round_trip() {
        let mut block = [0u8; BLOCK_SIZE];
        for (index, byte) in block.iter_mut().enumerate() {
            *byte = (index as u8) ^ 0x5A;
        }
        let response = FelicaStandardResponse::Read {
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(ReadResult {
                blocks: vec![block],
            }),
        };

        let secure_payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(READ_COMMAND_CODE, &secure_payload).unwrap();
        match parsed {
            FelicaStandardResponse::Read {
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                let parsed_result = result.expect("missing secure read result");
                assert_eq!(parsed_result.blocks, vec![block]);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn to_frame_rejects_secure_response_variants() {
        let response = FelicaStandardResponse::Write {
            status_flag1: 0x00,
            status_flag2: 0x00,
        };

        assert_protocol_error_contains(response.to_frame(), "secure response requires encryption");
    }

    #[test]
    fn to_secure_payload_rejects_plain_response_variants() {
        let response = FelicaStandardResponse::RequestResponse {
            idm: sample_idm(),
            mode: 0x07,
        };

        assert_protocol_error_contains(
            response.to_secure_payload(),
            "plain response cannot be encoded as secure payload",
        );
    }

    #[test]
    fn request_code_list_to_frame_round_trip() {
        let expected_result = RequestCodeListResult {
            continue_flag: true,
            areas: vec![AreaCodeRange::new(0x1000, 0x10FF)],
            services: vec![ServiceCode::new(0x090F), ServiceCode::new(0x1208)],
        };
        let response = FelicaStandardResponse::RequestCodeList {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(expected_result.clone()),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestCodeList {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(result, Some(expected_result));
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn request_block_information_ex_to_frame_round_trip() {
        let expected_result = RequestBlockInformationExResult {
            assigned_block_counts: vec![0x0010, 0x0200],
            free_block_counts: vec![0x0002, 0x0011],
        };
        let response = FelicaStandardResponse::RequestBlockInformationEx {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(expected_result.clone()),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestBlockInformationEx {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(result, Some(expected_result));
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn request_specification_version_to_frame_round_trip() {
        let expected_spec = SpecificationVersion {
            format_version: 0x00,
            basic_version: OptionVersion::new(0x01, 0x02, 0x03),
            option_versions: vec![
                OptionVersion::new(0x04, 0x05, 0x06),
                OptionVersion::new(0x07, 0x08, 0x09),
            ],
        };
        let response = FelicaStandardResponse::RequestSpecificationVersion {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            specification_version: Some(expected_spec.clone()),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestSpecificationVersion {
                idm,
                status_flag1,
                status_flag2,
                specification_version,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(specification_version, Some(expected_spec));
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn request_product_information_to_frame_round_trip() {
        let expected_platform_info = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let response = FelicaStandardResponse::RequestProductInformation {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(expected_platform_info.clone()),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestProductInformation {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(result, Some(expected_platform_info));
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn get_container_property_to_frame_round_trip() {
        let expected_data = vec![0xAA, 0xBB, 0xCC];
        let response = FelicaStandardResponse::GetContainerProperty {
            data: expected_data.clone(),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetContainerProperty { data } => {
                assert_eq!(data, expected_data);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn authentication2_v2_to_frame_round_trip() {
        let expected_payload = vec![0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97];
        let response = FelicaStandardResponse::Authentication2V2(Authentication2V2Response {
            encrypted_payload: expected_payload.clone(),
        });

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::Authentication2V2(auth) => {
                assert_eq!(auth.encrypted_payload, expected_payload);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn secure_register_issue_id_round_trip() {
        let response = FelicaStandardResponse::RegisterIssueId {
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(RegisterIssueIdResult {
                remaining_blocks: 0x3412,
            }),
        };

        let payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(REGISTER_ISSUE_ID_COMMAND_CODE, &payload)
                .unwrap();
        match parsed {
            FelicaStandardResponse::RegisterIssueId {
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(
                    result,
                    Some(RegisterIssueIdResult {
                        remaining_blocks: 0x3412
                    })
                );
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn secure_register_service_round_trip() {
        let response = FelicaStandardResponse::RegisterService {
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(RegisterServiceResult {
                remaining_blocks: 0x00AA,
            }),
        };

        let payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(REGISTER_SERVICE_COMMAND_CODE, &payload)
                .unwrap();
        match parsed {
            FelicaStandardResponse::RegisterService {
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(
                    result,
                    Some(RegisterServiceResult {
                        remaining_blocks: 0x00AA
                    })
                );
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn to_payload_rejects_unknown_response_variant() {
        assert_protocol_error_contains(
            FelicaStandardResponse::Unknown.to_payload(),
            "cannot encode unknown response",
        );
    }

    #[test]
    fn get_system_status_to_frame_round_trip() {
        let expected_result = GetSystemStatusResult {
            flag: 0xA5,
            data: vec![0x10, 0x20, 0x30],
        };
        let response = FelicaStandardResponse::GetSystemStatus {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: expected_result.clone(),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetSystemStatus {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(result, expected_result);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn get_area_information_to_frame_round_trip() {
        let expected_result = GetAreaInformationResult {
            node_code: 0x2201,
            data: [0x7E, 0x01],
        };
        let response = FelicaStandardResponse::GetAreaInformation {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(expected_result),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetAreaInformation {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x00);
                assert_eq!(result, Some(expected_result));
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn authentication1_v2_to_frame_round_trip() {
        let challenge_1b = [0x11; 16];
        let challenge_2a = [0x22; 16];
        let challenge_3c = [0x33; 4];
        let response = FelicaStandardResponse::Authentication1V2 {
            idm: sample_idm(),
            challenge_1b,
            challenge_2a,
            challenge_3c,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::Authentication1V2 {
                idm,
                challenge_1b: parsed_1b,
                challenge_2a: parsed_2a,
                challenge_3c: parsed_3c,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(parsed_1b, challenge_1b);
                assert_eq!(parsed_2a, challenge_2a);
                assert_eq!(parsed_3c, challenge_3c);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn get_container_id_to_frame_round_trip() {
        let container_idm = [0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6, 0x97, 0x88];
        let response = FelicaStandardResponse::GetContainerId { container_idm };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetContainerId {
                container_idm: parsed_idm,
            } => {
                assert_eq!(parsed_idm, container_idm);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn secure_write_round_trip() {
        let response = FelicaStandardResponse::Write {
            status_flag1: 0x12,
            status_flag2: 0x34,
        };

        let payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(WRITE_COMMAND_CODE, &payload).unwrap();
        match parsed {
            FelicaStandardResponse::Write {
                status_flag1,
                status_flag2,
            } => {
                assert_eq!(status_flag1, 0x12);
                assert_eq!(status_flag2, 0x34);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn secure_write_v2_round_trip() {
        let response = FelicaStandardResponse::WriteV2 {
            status_flag1: 0x56,
            status_flag2: 0x78,
        };

        let payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(WRITE_V2_COMMAND_CODE, &payload).unwrap();
        match parsed {
            FelicaStandardResponse::WriteV2 {
                status_flag1,
                status_flag2,
            } => {
                assert_eq!(status_flag1, 0x56);
                assert_eq!(status_flag2, 0x78);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn secure_register_area_round_trip() {
        let response = FelicaStandardResponse::RegisterArea {
            status_flag1: 0x00,
            status_flag2: 0x7F,
        };

        let payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(REGISTER_AREA_COMMAND_CODE, &payload)
                .unwrap();
        match parsed {
            FelicaStandardResponse::RegisterArea {
                status_flag1,
                status_flag2,
            } => {
                assert_eq!(status_flag1, 0x00);
                assert_eq!(status_flag2, 0x7F);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn secure_change_system_block_round_trip() {
        let response = FelicaStandardResponse::ChangeSystemBlock {
            status_flag1: 0xAB,
            status_flag2: 0xCD,
        };

        let payload = response.to_secure_payload().unwrap();
        let parsed =
            FelicaStandardResponse::from_secure_bytes(CHANGE_SYSTEM_BLOCK_COMMAND_CODE, &payload)
                .unwrap();
        match parsed {
            FelicaStandardResponse::ChangeSystemBlock {
                status_flag1,
                status_flag2,
            } => {
                assert_eq!(status_flag1, 0xAB);
                assert_eq!(status_flag2, 0xCD);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn to_secure_payload_rejects_secure_read_without_result_on_success() {
        let response = FelicaStandardResponse::Read {
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: None,
        };

        assert_protocol_error_contains(
            response.to_secure_payload(),
            "secure read result is missing on success",
        );
    }

    #[test]
    fn to_payload_rejects_empty_container_property_data() {
        let response = FelicaStandardResponse::GetContainerProperty { data: Vec::new() };
        assert_protocol_error_contains(
            response.to_payload(),
            "response data must contain at least one byte",
        );
    }

    #[test]
    fn to_payload_rejects_mixed_get_node_property_types() {
        let response = FelicaStandardResponse::GetNodeProperty {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(GetNodePropertyResult {
                node_properties: vec![
                    NodeProperty::MacCommunication { enabled: true },
                    NodeProperty::ValueLimitedPurseService {
                        enabled: true,
                        upper_limit: 100,
                        lower_limit: -100,
                        generation_number: 1,
                    },
                ],
            }),
        };

        assert_protocol_error_contains(response.to_payload(), "cannot mix property types");
    }

    #[test]
    fn request_response_to_frame_round_trip() {
        let response = FelicaStandardResponse::RequestResponse {
            idm: sample_idm(),
            mode: 0x07,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestResponse { idm, mode } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(mode, 0x07);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn request_system_code_to_frame_round_trip() {
        let expected_codes = vec![0x0003, 0x12FC];
        let response = FelicaStandardResponse::RequestSystemCode {
            idm: sample_idm(),
            system_codes: expected_codes.clone(),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestSystemCode { idm, system_codes } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(system_codes, expected_codes);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn request_block_information_to_frame_round_trip() {
        let expected_counts = vec![0x0011, 0x0202, 0x3300];
        let response = FelicaStandardResponse::RequestBlockInformation {
            idm: sample_idm(),
            block_counts: expected_counts.clone(),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::RequestBlockInformation { idm, block_counts } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(block_counts, expected_counts);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn set_parameter_to_frame_round_trip() {
        let response = FelicaStandardResponse::SetParameter {
            idm: sample_idm(),
            status_flag1: 0xA1,
            status_flag2: 0xB2,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::SetParameter {
                idm,
                status_flag1,
                status_flag2,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0xA1);
                assert_eq!(status_flag2, 0xB2);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn reset_mode_to_frame_round_trip() {
        let response = FelicaStandardResponse::ResetMode {
            idm: sample_idm(),
            status_flag1: 0x11,
            status_flag2: 0x22,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::ResetMode {
                idm,
                status_flag1,
                status_flag2,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(status_flag1, 0x11);
                assert_eq!(status_flag2, 0x22);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn get_container_issue_information_to_frame_round_trip() {
        let expected = ContainerInformation::new(
            [0x01, 0x02, 0x03, 0x04, 0x05],
            [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
            ],
        );
        let response = FelicaStandardResponse::GetContainerIssueInformation {
            idm: sample_idm(),
            container_information: expected,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::GetContainerIssueInformation {
                idm,
                container_information,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(container_information, expected);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn search_service_code_area_to_frame_round_trip() {
        let response = FelicaStandardResponse::SearchServiceCode {
            idm: sample_idm(),
            result: Some(SearchServiceCodeResult::Area {
                area_code: 0x1000,
                end_service_code: 0x10FF,
            }),
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::SearchServiceCode { idm, result } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(
                    result,
                    Some(SearchServiceCodeResult::Area {
                        area_code: 0x1000,
                        end_service_code: 0x10FF
                    })
                );
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn search_service_code_none_to_frame_round_trip() {
        let response = FelicaStandardResponse::SearchServiceCode {
            idm: sample_idm(),
            result: None,
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::SearchServiceCode { idm, result } => {
                assert_eq!(idm, sample_idm());
                assert!(result.is_none());
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn authentication1_to_frame_round_trip() {
        let response = FelicaStandardResponse::Authentication1 {
            idm: sample_idm(),
            challenge_1b: [0xAA; 8],
            challenge_2a: [0x55; 8],
        };

        let frame = response.to_frame().unwrap();
        let parsed = FelicaStandardResponse::from_bytes(&frame).unwrap();
        match parsed {
            FelicaStandardResponse::Authentication1 {
                idm,
                challenge_1b,
                challenge_2a,
            } => {
                assert_eq!(idm, sample_idm());
                assert_eq!(challenge_1b, [0xAA; 8]);
                assert_eq!(challenge_2a, [0x55; 8]);
            }
            _ => panic!("unexpected parsed response variant"),
        }
    }

    #[test]
    fn to_payload_rejects_request_system_code_without_entries() {
        let response = FelicaStandardResponse::RequestSystemCode {
            idm: sample_idm(),
            system_codes: Vec::new(),
        };
        assert_protocol_error_contains(response.to_payload(), "must include at least one entry");
    }

    #[test]
    fn to_payload_rejects_request_block_information_ex_length_mismatch() {
        let response = FelicaStandardResponse::RequestBlockInformationEx {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: Some(RequestBlockInformationExResult {
                assigned_block_counts: vec![0x0001, 0x0002],
                free_block_counts: vec![0x0003],
            }),
        };
        assert_protocol_error_contains(response.to_payload(), "assigned/free length mismatch");
    }

    #[test]
    fn to_payload_rejects_request_product_information_missing_result_on_success() {
        let response = FelicaStandardResponse::RequestProductInformation {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            result: None,
        };
        assert_protocol_error_contains(response.to_payload(), "result is missing on success");
    }

    #[test]
    fn to_payload_rejects_request_specification_version_non_zero_format() {
        let response = FelicaStandardResponse::RequestSpecificationVersion {
            idm: sample_idm(),
            status_flag1: 0x00,
            status_flag2: 0x00,
            specification_version: Some(SpecificationVersion {
                format_version: 0x01,
                basic_version: OptionVersion::new(0x01, 0x02, 0x03),
                option_versions: vec![],
            }),
        };
        assert_protocol_error_contains(response.to_payload(), "format version must be 0x00");
    }
}
