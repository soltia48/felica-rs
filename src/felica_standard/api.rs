use super::command::{CommandEncoding, FelicaStandardCommand};
use super::error::FelicaStandardError;
use super::response::FelicaStandardResponse;
use super::secure::{
    AuthenticatedContext, Authentication2Response, Authentication2V2Response,
    AuthenticationContext, AuthenticationContextV2Aes128, DecryptedSecureResponse,
    SecureCommandContext, SecureSessionCredentials, SecureSessionScheme,
    generate_registration_package_des,
};
use super::types::{
    BlockListElement, ChangeKeyParameters, ContainerInformation, ContainerProperty,
    GetAreaInformationResult, GetNodePropertyResult, GetSystemStatusResult,
    MutualAuthenticationResult, NodePropertyType, RequestBlockInformationExResult,
    RequestCodeListResult, RequestServiceV2KeyVersion, SearchServiceCodeResult, ServiceCode,
    SetParameterEncryptionType, SetParameterPacketType, SpecificationVersion,
    status_flag_description,
};
use super::{
    BLOCK_SIZE, DES_BLOCK_SIZE, IDM_LEN, MAX_BLOCK_LIST_LEN, MAX_NODE_CODES,
    MAX_NODE_PROPERTY_CODES, MAX_RW_SERVICE_CODES, MAX_SERVICE_CODES, READ_V2_COMMAND_CODE,
    READ_V2_RESPONSE_CODE, WRITE_V2_COMMAND_CODE, WRITE_V2_RESPONSE_CODE, frame_with_length_prefix,
};
use crate::RemoteTarget;
use crate::driver::errors::Result as DriverResult;
use crate::felica_standard::Type3TagPollingResult;
use rand::{RngCore, rngs::OsRng};
use std::convert::TryInto;

pub trait FelicaDriver {
    fn detect_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> DriverResult<Type3TagPollingResult>;

    fn transceive(
        &mut self,
        target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> DriverResult<Vec<u8>>;
}

pub struct FelicaStandard<'a, D: FelicaDriver + ?Sized> {
    device: &'a mut D,
    target: RemoteTarget,
    polling_result: Type3TagPollingResult,
    authenticated_context: Option<AuthenticatedContext>,
}

impl<'a, D: FelicaDriver + ?Sized> FelicaStandard<'a, D> {
    pub fn idm(&self) -> &[u8] {
        &self.polling_result.idm
    }

    pub fn pmm(&self) -> &[u8] {
        &self.polling_result.pmm
    }

    fn idm_bytes(&self) -> Result<[u8; IDM_LEN], FelicaStandardError> {
        self.idm()
            .try_into()
            .map_err(|_| FelicaStandardError::InvalidParameter("IDm must be 8 bytes long".into()))
    }

    fn status_error(command: &'static str, sf1: u8, sf2: u8) -> FelicaStandardError {
        FelicaStandardError::Status {
            command,
            status_flag1: sf1,
            status_flag2: sf2,
            detail: status_flag_description(sf1, sf2),
        }
    }

    pub fn polling(
        device: &'a mut D,
        brty: &str,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<(Self, Type3TagPollingResult), FelicaStandardError> {
        let target = RemoteTarget::new(brty)?;
        let polling_result =
            device.detect_type_f(&target, system_code, request_code, time_slots)?;
        Ok((
            Self {
                device,
                target,
                polling_result: polling_result.clone(),
                authenticated_context: None,
            },
            polling_result,
        ))
    }

    pub fn send_command(
        &mut self,
        command: FelicaStandardCommand,
        timeout_ms: u16,
    ) -> Result<FelicaStandardResponse, FelicaStandardError> {
        match command.encoding() {
            CommandEncoding::Plain(frame) => {
                let response_bytes =
                    self.device
                        .transceive(&self.target, &frame, Some(timeout_ms))?;
                Ok(FelicaStandardResponse::from_bytes(&response_bytes)?)
            }
            CommandEncoding::Secure { opcode, payload } => {
                let decrypted = self.encrypted_command_exchange(opcode, &payload, timeout_ms)?;
                Ok(FelicaStandardResponse::from_secure_bytes(
                    opcode, &decrypted,
                )?)
            }
        }
    }

    fn execute_command(
        &mut self,
        _command_name: &'static str,
        command: FelicaStandardCommand,
        timeout_ms: u16,
    ) -> Result<FelicaStandardResponse, FelicaStandardError> {
        self.send_command(command, timeout_ms)
    }

    pub fn request_service(
        &mut self,
        service_codes: &[ServiceCode],
    ) -> Result<Vec<u16>, FelicaStandardError> {
        ensure_len_in_range("service_codes", service_codes.len(), 1, MAX_SERVICE_CODES)?;

        let idm = self.idm_bytes()?;

        let timeout_ms = self
            .polling_result
            .request_service_timeout_ms(service_codes.len());

        let response = self.execute_command(
            "Request Service",
            FelicaStandardCommand::RequestService {
                idm,
                service_codes: service_codes.to_vec(),
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RequestService { key_versions, .. } => Ok(key_versions),
            _ => Err(unexpected_response("Request Service")),
        }
    }

    pub fn request_response(&mut self) -> Result<u8, FelicaStandardError> {
        let idm = self.idm_bytes()?;

        let timeout_ms = self.polling_result.request_response_timeout_ms();

        let response = self.execute_command(
            "Request Response",
            FelicaStandardCommand::RequestResponse { idm },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RequestResponse { mode, .. } => Ok(mode),
            _ => Err(unexpected_response("Request Response")),
        }
    }

    pub fn read_without_encryption(
        &mut self,
        service_codes: &[ServiceCode],
        block_list: &[BlockListElement],
    ) -> Result<Vec<[u8; BLOCK_SIZE]>, FelicaStandardError> {
        ensure_len_in_range(
            "service_codes",
            service_codes.len(),
            1,
            MAX_RW_SERVICE_CODES,
        )?;
        ensure_len_in_range("block_list", block_list.len(), 1, MAX_BLOCK_LIST_LEN)?;
        validate_block_list_indices(block_list, service_codes.len())?;

        let idm = self.idm_bytes()?;
        let timeout_ms = self
            .polling_result
            .read_without_encryption_timeout_ms(block_list.len());

        let response = self.execute_command(
            "Read Without Encryption",
            FelicaStandardCommand::ReadWithoutEncryption {
                idm,
                service_codes: service_codes.to_vec(),
                block_list: block_list.to_vec(),
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::ReadWithoutEncryption {
                status_flag1,
                status_flag2,
                result,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Read Without Encryption",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    let result = result.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "Read Without Encryption missing result payload".into(),
                        )
                    })?;
                    Ok(result.blocks)
                }
            }
            _ => Err(unexpected_response("Read Without Encryption")),
        }
    }

    pub fn write_without_encryption(
        &mut self,
        service_codes: &[ServiceCode],
        block_list: &[BlockListElement],
        data: &[u8],
    ) -> Result<(), FelicaStandardError> {
        ensure_len_in_range(
            "service_codes",
            service_codes.len(),
            1,
            MAX_RW_SERVICE_CODES,
        )?;
        ensure_len_in_range("block_list", block_list.len(), 1, MAX_BLOCK_LIST_LEN)?;
        validate_block_list_indices(block_list, service_codes.len())?;
        ensure_block_data_length(block_list.len(), data.len())?;

        let idm = self.idm_bytes()?;
        let timeout_ms = self
            .polling_result
            .write_without_encryption_timeout_ms(block_list.len());

        let response = self.execute_command(
            "Write Without Encryption",
            FelicaStandardCommand::WriteWithoutEncryption {
                idm,
                service_codes: service_codes.to_vec(),
                block_list: block_list.to_vec(),
                data: data.to_vec(),
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::WriteWithoutEncryption {
                status_flag1,
                status_flag2,
                ..
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error(
                        "Write Without Encryption",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    Ok(())
                }
            }
            _ => Err(unexpected_response("Write Without Encryption")),
        }
    }

    pub fn search_service_code(
        &mut self,
        service_index: u16,
    ) -> Result<Option<SearchServiceCodeResult>, FelicaStandardError> {
        let idm = self.idm_bytes()?;
        let timeout_ms = self.polling_result.search_service_code_timeout_ms();

        let response = self.execute_command(
            "Search Service Code",
            FelicaStandardCommand::SearchServiceCode { idm, service_index },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::SearchServiceCode { result, .. } => Ok(result),
            _ => Err(unexpected_response("Search Service Code")),
        }
    }

    pub fn request_system_code(&mut self) -> Result<Vec<u16>, FelicaStandardError> {
        let idm = self.idm_bytes()?;
        let timeout_ms = self.polling_result.request_system_code_timeout_ms();

        let response = self.execute_command(
            "Request System Code",
            FelicaStandardCommand::RequestSystemCode { idm },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RequestSystemCode { system_codes, .. } => Ok(system_codes),
            _ => Err(unexpected_response("Request System Code")),
        }
    }

    pub fn request_block_information(
        &mut self,
        node_codes: &[u16],
    ) -> Result<Vec<u16>, FelicaStandardError> {
        ensure_len_in_range("node_codes", node_codes.len(), 1, MAX_NODE_CODES)?;

        let idm = self.idm_bytes()?;
        let timeout_ms = self
            .polling_result
            .request_block_information_timeout_ms(node_codes.len());

        let response = self.execute_command(
            "Request Block Information",
            FelicaStandardCommand::RequestBlockInformation {
                idm,
                node_codes: node_codes.to_vec(),
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RequestBlockInformation { block_counts, .. } => {
                Ok(block_counts)
            }
            _ => Err(unexpected_response("Request Block Information")),
        }
    }

    pub fn request_block_information_ex(
        &mut self,
        node_codes: &[u16],
    ) -> Result<RequestBlockInformationExResult, FelicaStandardError> {
        ensure_len_in_range("node_codes", node_codes.len(), 1, MAX_NODE_CODES)?;

        let idm = self.idm_bytes()?;
        let timeout_ms = self
            .polling_result
            .request_block_information_ex_timeout_ms(node_codes.len());

        let response = self.execute_command(
            "Request Block Information Ex",
            FelicaStandardCommand::RequestBlockInformationEx {
                idm,
                node_codes: node_codes.to_vec(),
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RequestBlockInformationEx {
                status_flag1,
                status_flag2,
                result,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Request Block Information Ex",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    let result = result.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "Request Block Information Ex missing result payload".into(),
                        )
                    })?;
                    if result.assigned_block_counts.len() != node_codes.len()
                        || result.free_block_counts.len() != node_codes.len()
                    {
                        Err(FelicaStandardError::Protocol(
                            "Request Block Information Ex count list length mismatch".into(),
                        ))
                    } else {
                        Ok(result)
                    }
                }
            }
            _ => Err(unexpected_response("Request Block Information Ex")),
        }
    }

    pub fn request_code_list(
        &mut self,
        parent_node_code: u16,
        index: u16,
    ) -> Result<RequestCodeListResult, FelicaStandardError> {
        let idm = self.idm_bytes()?;
        let timeout_ms = self.polling_result.request_code_list_timeout_ms();

        let response = self.execute_command(
            "Request Code List",
            FelicaStandardCommand::RequestCodeList {
                idm,
                parent_node_code,
                index,
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RequestCodeList {
                status_flag1,
                status_flag2,
                result,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Request Code List",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    result.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "Request Code List missing result payload".into(),
                        )
                    })
                }
            }
            _ => Err(unexpected_response("Request Code List")),
        }
    }

    pub fn set_parameter(
        &mut self,
        encryption_type: SetParameterEncryptionType,
        packet_type: SetParameterPacketType,
    ) -> Result<(), FelicaStandardError> {
        let idm = self.idm_bytes()?;
        let timeout_ms = self.polling_result.set_parameter_timeout_ms();

        let response = self.execute_command(
            "Set Parameter",
            FelicaStandardCommand::SetParameter {
                idm,
                encryption_type,
                packet_type,
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::SetParameter {
                status_flag1,
                status_flag2,
                ..
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error(
                        "Set Parameter",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    Ok(())
                }
            }
            _ => Err(unexpected_response("Set Parameter")),
        }
    }

    pub fn get_container_issue_information(
        &mut self,
    ) -> Result<ContainerInformation, FelicaStandardError> {
        let idm = self.idm_bytes()?;
        let timeout_ms = self
            .polling_result
            .get_container_issue_information_timeout_ms();

        let response = self.execute_command(
            "Get Container Issue Information",
            FelicaStandardCommand::GetContainerIssueInformation { idm },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::GetContainerIssueInformation {
                container_information,
                ..
            } => Ok(container_information),
            _ => Err(unexpected_response("Get Container Issue Information")),
        }
    }

    pub fn get_container_property(
        &mut self,
        property: ContainerProperty,
    ) -> Result<Vec<u8>, FelicaStandardError> {
        let timeout_ms = self.polling_result.get_container_property_timeout_ms();

        let response = self.execute_command(
            "Get Container Property",
            FelicaStandardCommand::GetContainerProperty { property },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::GetContainerProperty { data } => Ok(data),
            _ => Err(unexpected_response("Get Container Property")),
        }
    }

    pub fn get_container_id(&mut self) -> Result<[u8; IDM_LEN], FelicaStandardError> {
        let timeout_ms = self.polling_result.get_container_id_timeout_ms();

        let response = self.execute_command(
            "Get Container ID",
            FelicaStandardCommand::GetContainerId,
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::GetContainerId { container_idm } => Ok(container_idm),
            _ => Err(unexpected_response("Get Container ID")),
        }
    }

    pub fn get_system_status(&mut self) -> Result<GetSystemStatusResult, FelicaStandardError> {
        let idm = self.idm_bytes()?;
        let timeout_ms = self.polling_result.get_system_status_timeout_ms();

        let response = self.execute_command(
            "Get System Status",
            FelicaStandardCommand::GetSystemStatus { idm },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::GetSystemStatus {
                status_flag1,
                status_flag2,
                result,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Get System Status",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    Ok(result)
                }
            }
            _ => Err(unexpected_response("Get System Status")),
        }
    }

    pub fn get_platform_information(&mut self) -> Result<Vec<u8>, FelicaStandardError> {
        let idm = self.idm_bytes()?;
        let timeout_ms = self.polling_result.get_platform_information_timeout_ms();

        let response = self.execute_command(
            "Get Platform Information",
            FelicaStandardCommand::GetPlatformInformation { idm },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::GetPlatformInformation {
                status_flag1,
                status_flag2,
                result,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Get Platform Information",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    result.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "Get Platform Information missing result payload".into(),
                        )
                    })
                }
            }
            _ => Err(unexpected_response("Get Platform Information")),
        }
    }

    pub fn request_specification_version(
        &mut self,
    ) -> Result<Option<SpecificationVersion>, FelicaStandardError> {
        let idm = self.idm_bytes()?;
        let timeout_ms = self
            .polling_result
            .request_specification_version_timeout_ms();

        let response = self.execute_command(
            "Request Specification Version",
            FelicaStandardCommand::RequestSpecificationVersion { idm },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RequestSpecificationVersion {
                status_flag1,
                status_flag2,
                specification_version,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Request Specification Version",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    Ok(specification_version)
                }
            }
            _ => Err(unexpected_response("Request Specification Version")),
        }
    }

    pub fn reset_mode(&mut self) -> Result<(), FelicaStandardError> {
        let idm = self.idm_bytes()?;
        let timeout_ms = self.polling_result.reset_mode_timeout_ms();

        let response = self.execute_command(
            "Reset Mode",
            FelicaStandardCommand::ResetMode { idm },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::ResetMode {
                status_flag1,
                status_flag2,
                ..
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error("Reset Mode", status_flag1, status_flag2))
                } else {
                    Ok(())
                }
            }
            _ => Err(unexpected_response("Reset Mode")),
        }
    }

    pub fn get_area_information(
        &mut self,
        node_code: u16,
    ) -> Result<GetAreaInformationResult, FelicaStandardError> {
        let idm = self.idm_bytes()?;
        let timeout_ms = self.polling_result.get_area_information_timeout_ms();

        let response = self.execute_command(
            "Get Area Information",
            FelicaStandardCommand::GetAreaInformation { idm, node_code },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::GetAreaInformation {
                status_flag1,
                status_flag2,
                result,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Get Area Information",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    result.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "Get Area Information missing result payload".into(),
                        )
                    })
                }
            }
            _ => Err(unexpected_response("Get Area Information")),
        }
    }

    pub fn get_node_property(
        &mut self,
        node_property_type: NodePropertyType,
        node_codes: &[u16],
    ) -> Result<GetNodePropertyResult, FelicaStandardError> {
        ensure_len_in_range("node_codes", node_codes.len(), 1, MAX_NODE_PROPERTY_CODES)?;

        let idm = self.idm_bytes()?;
        let timeout_ms = self
            .polling_result
            .get_node_property_timeout_ms(node_codes.len());

        let response = self.execute_command(
            "Get Node Property",
            FelicaStandardCommand::GetNodeProperty {
                idm,
                node_property_type,
                node_codes: node_codes.to_vec(),
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::GetNodeProperty {
                status_flag1,
                status_flag2,
                result,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Get Node Property",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    let result = result.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "Get Node Property missing result payload".into(),
                        )
                    })?;
                    if result.node_properties.len() != node_codes.len() {
                        return Err(FelicaStandardError::Protocol(
                            "Get Node Property property count mismatch".into(),
                        ));
                    }
                    if result
                        .node_properties
                        .iter()
                        .any(|property| property.property_type() != node_property_type)
                    {
                        return Err(FelicaStandardError::Protocol(
                            "Get Node Property returned unexpected property type".into(),
                        ));
                    }
                    Ok(result)
                }
            }
            _ => Err(unexpected_response("Get Node Property")),
        }
    }

    pub fn authentication1(
        &mut self,
        areas: &[u16],
        services: &[ServiceCode],
        challenge_1a: &[u8; 8],
    ) -> Result<([u8; 8], [u8; 8]), FelicaStandardError> {
        let idm = self.idm_bytes()?;
        if areas.len() > MAX_SERVICE_CODES {
            return Err(FelicaStandardError::InvalidParameter(
                "too many areas for authentication1".into(),
            ));
        }
        if services.len() > MAX_SERVICE_CODES {
            return Err(FelicaStandardError::InvalidParameter(
                "too many services for authentication1".into(),
            ));
        }
        let node_count = areas.len() + services.len();
        let timeout_ms = self.polling_result.authentication1_timeout_ms(node_count);
        let response = self.execute_command(
            "Authentication1",
            FelicaStandardCommand::Authentication1 {
                idm,
                areas: areas.to_vec(),
                services: services.iter().map(|s| s.raw()).collect(),
                challenge_1a: *challenge_1a,
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::Authentication1 {
                challenge_1b,
                challenge_2a,
                ..
            } => Ok((challenge_1b, challenge_2a)),
            _ => Err(unexpected_response("Authentication1")),
        }
    }

    pub fn authentication2(
        &mut self,
        challenge_2b: &[u8; 8],
    ) -> Result<Authentication2Response, FelicaStandardError> {
        let idm = self.idm_bytes()?;

        let timeout_ms = self.polling_result.authentication2_timeout_ms();
        let response = self.execute_command(
            "Authentication2",
            FelicaStandardCommand::Authentication2 {
                idm,
                challenge_2b: *challenge_2b,
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::Authentication2(payload) => Ok(payload),
            _ => Err(unexpected_response("Authentication2")),
        }
    }

    pub fn mutual_authentication(
        &mut self,
        areas: &[u16],
        services: &[ServiceCode],
        group_service_key: &[u8; 8],
        user_service_key: &[u8; 8],
    ) -> Result<MutualAuthenticationResult, FelicaStandardError> {
        if areas.is_empty() && services.is_empty() {
            return Err(FelicaStandardError::InvalidParameter(
                "mutual authentication requires at least one area or service code".into(),
            ));
        }
        let idm = self.idm_bytes()?;
        let mut random_1 = [0u8; 8];
        OsRng.fill_bytes(&mut random_1);

        let context = AuthenticationContext::new(&idm, group_service_key, user_service_key);

        let challenge_1a = context.encrypt_challenge1a(&random_1);
        let (challenge_1b, challenge_2a) = self.authentication1(areas, services, &challenge_1a)?;
        if !context.verify_challenge1b(&random_1, &challenge_1b) {
            return Err(FelicaStandardError::AuthenticationFailed(
                "Authentication1 verification failed".into(),
            ));
        }

        let random_2 = context.decrypt_challenge2a(&challenge_2a);
        let challenge_2b = context.encrypt_challenge2b(&random_2);
        let auth2_response = self.authentication2(&challenge_2b)?;
        let payload = auth2_response.decrypt_payload(&random_2)?;
        if payload.len() < 24 {
            return Err(FelicaStandardError::Protocol(
                "Authentication2 response payload too short".into(),
            ));
        }
        let transaction_number = u16::from_le_bytes([payload[0], payload[1]]);
        let mut transaction_id = [0u8; 6];
        transaction_id.copy_from_slice(&payload[2..8]);
        let mut expected_id = [0u8; 6];
        expected_id.copy_from_slice(&random_1[2..8]);
        if transaction_id != expected_id {
            return Err(FelicaStandardError::AuthenticationFailed(
                "Authentication2 transaction ID mismatch".into(),
            ));
        }
        let mut issue_id = [0u8; 8];
        issue_id.copy_from_slice(&payload[8..16]);
        let mut issue_parameter = [0u8; 8];
        issue_parameter.copy_from_slice(&payload[16..24]);

        let context = AuthenticatedContext::new(
            transaction_number,
            transaction_id,
            SecureSessionCredentials::Des(random_2),
        );
        self.authenticated_context = Some(context);

        Ok(MutualAuthenticationResult {
            issue_id,
            issue_parameter,
        })
    }

    pub fn authenticated_context(&self) -> Option<&AuthenticatedContext> {
        self.authenticated_context.as_ref()
    }

    pub fn set_authenticated_context(&mut self, context: AuthenticatedContext) {
        self.authenticated_context = Some(context);
    }

    pub fn clear_authenticated_context(&mut self) {
        self.authenticated_context = None;
    }

    pub fn authenticated_scheme(&self) -> Option<SecureSessionScheme> {
        self.authenticated_context.as_ref().map(|ctx| ctx.scheme())
    }

    fn secure_context_mut(&mut self) -> Result<&mut AuthenticatedContext, FelicaStandardError> {
        self.authenticated_context
            .as_mut()
            .ok_or(FelicaStandardError::AuthenticationRequired)
    }

    fn encrypted_command_exchange(
        &mut self,
        command_code: u8,
        command_payload: &[u8],
        timeout_ms: u16,
    ) -> Result<Vec<u8>, FelicaStandardError> {
        let command_context = {
            let session = self.secure_context_mut()?;
            SecureCommandContext::capture(session)?
        };
        let payload = command_context.build_secure_payload(command_payload);
        let encrypted = command_context.encrypt_command(command_code, payload)?;
        let encrypted_response =
            self.send_encrypted_command(command_code, &encrypted, timeout_ms)?;
        let decrypted_response = command_context.decrypt_response(
            expected_secure_response_code(command_code),
            &encrypted_response,
        )?;
        self.process_encrypted_response(decrypted_response)
    }

    fn send_encrypted_command(
        &mut self,
        command_code: u8,
        encrypted_payload: &[u8],
        timeout_ms: u16,
    ) -> Result<Vec<u8>, FelicaStandardError> {
        let mut payload = Vec::with_capacity(1 + encrypted_payload.len());
        payload.push(command_code);
        payload.extend_from_slice(encrypted_payload);
        let frame = frame_with_length_prefix(&payload);
        let response = self
            .device
            .transceive(&self.target, &frame, Some(timeout_ms))?;
        if response.len() < 2 {
            return Err(FelicaStandardError::Protocol(
                "secure response too short".into(),
            ));
        }
        if response[0] as usize != response.len() {
            return Err(FelicaStandardError::Protocol(
                "secure response length field does not match payload".into(),
            ));
        }
        if response[1] != expected_secure_response_code(command_code) {
            return Err(FelicaStandardError::Protocol(
                "secure response command code mismatch".into(),
            ));
        }
        Ok(response[2..].to_vec())
    }

    fn process_encrypted_response(
        &mut self,
        decrypted_response: DecryptedSecureResponse,
    ) -> Result<Vec<u8>, FelicaStandardError> {
        let context = self.secure_context_mut()?;
        if decrypted_response.transaction_number <= context.transaction_number() {
            return Err(FelicaStandardError::SecureSession(
                "secure response transaction number did not advance".into(),
            ));
        }
        context.set_transaction_number(decrypted_response.transaction_number);
        Ok(decrypted_response.payload)
    }

    pub fn read(
        &mut self,
        block_list: &[BlockListElement],
    ) -> Result<Vec<[u8; BLOCK_SIZE]>, FelicaStandardError> {
        ensure_len_in_range("block_list", block_list.len(), 1, MAX_BLOCK_LIST_LEN)?;

        let timeout_ms = self.polling_result.read_timeout_ms(block_list.len());
        let read_command = FelicaStandardCommand::Read {
            block_list: block_list.to_vec(),
        };

        let response = self.execute_command("Read", read_command, timeout_ms)?;

        match response {
            FelicaStandardResponse::Read {
                status_flag1,
                status_flag2,
                result,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error("Read", status_flag1, status_flag2))
                } else {
                    let result = result.ok_or_else(|| {
                        FelicaStandardError::Protocol("Read missing result payload".into())
                    })?;
                    let blocks = result.blocks;
                    if blocks.len() != block_list.len() {
                        Err(FelicaStandardError::Protocol(
                            "encrypted read response block count mismatch".into(),
                        ))
                    } else {
                        Ok(blocks)
                    }
                }
            }
            _ => Err(unexpected_response("Read")),
        }
    }

    pub fn read_v2(
        &mut self,
        block_list: &[BlockListElement],
    ) -> Result<Vec<[u8; BLOCK_SIZE]>, FelicaStandardError> {
        ensure_len_in_range("block_list", block_list.len(), 1, MAX_BLOCK_LIST_LEN)?;

        let timeout_ms = self.polling_result.read_timeout_ms(block_list.len());
        let response = self.execute_command(
            "Read v2",
            FelicaStandardCommand::ReadV2 {
                block_list: block_list.to_vec(),
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::ReadV2 {
                status_flag1,
                status_flag2,
                result,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error("Read v2", status_flag1, status_flag2))
                } else {
                    let result = result.ok_or_else(|| {
                        FelicaStandardError::Protocol("Read v2 missing result payload".into())
                    })?;
                    let blocks = result.blocks;
                    if blocks.len() != block_list.len() {
                        Err(FelicaStandardError::Protocol(
                            "encrypted read v2 response block count mismatch".into(),
                        ))
                    } else {
                        Ok(blocks)
                    }
                }
            }
            _ => Err(unexpected_response("Read v2")),
        }
    }

    pub fn write(
        &mut self,
        block_list: &[BlockListElement],
        data: &[u8],
    ) -> Result<(), FelicaStandardError> {
        ensure_len_in_range("block_list", block_list.len(), 1, MAX_BLOCK_LIST_LEN)?;
        ensure_block_data_length(block_list.len(), data.len())?;

        let timeout_ms = self.polling_result.write_timeout_ms(block_list.len());
        let write_command = FelicaStandardCommand::Write {
            block_list: block_list.to_vec(),
            data: data.to_vec(),
        };

        let response = self.execute_command("Write", write_command, timeout_ms)?;

        match response {
            FelicaStandardResponse::Write {
                status_flag1,
                status_flag2,
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error("Write", status_flag1, status_flag2))
                } else {
                    Ok(())
                }
            }
            _ => Err(unexpected_response("Write")),
        }
    }

    pub fn write_v2(
        &mut self,
        block_list: &[BlockListElement],
        data: &[u8],
    ) -> Result<(), FelicaStandardError> {
        ensure_len_in_range("block_list", block_list.len(), 1, MAX_BLOCK_LIST_LEN)?;
        ensure_block_data_length(block_list.len(), data.len())?;

        let timeout_ms = self.polling_result.write_timeout_ms(block_list.len());
        let response = self.execute_command(
            "Write v2",
            FelicaStandardCommand::WriteV2 {
                block_list: block_list.to_vec(),
                data: data.to_vec(),
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::WriteV2 {
                status_flag1,
                status_flag2,
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error("Write v2", status_flag1, status_flag2))
                } else {
                    Ok(())
                }
            }
            _ => Err(unexpected_response("Write v2")),
        }
    }

    pub fn change_keys(
        &mut self,
        change_key_params: &[ChangeKeyParameters],
    ) -> Result<(), FelicaStandardError> {
        if change_key_params.is_empty() {
            return Err(FelicaStandardError::InvalidParameter(
                "change_keys requires at least one entry".into(),
            ));
        }
        if self.authenticated_scheme() == Some(SecureSessionScheme::Aes128) {
            return Err(FelicaStandardError::InvalidParameter(
                "change_keys is only supported for Write (DES)".into(),
            ));
        }

        let mut block_list = Vec::with_capacity(change_key_params.len());
        for params in change_key_params {
            let block_number = params.block_descriptor_block_number();
            block_list.push(BlockListElement::new(block_number, 0, 4));
        }

        let mut data = Vec::with_capacity(change_key_params.len() * BLOCK_SIZE);
        for params in change_key_params {
            data.extend_from_slice(&params.payload());
        }

        self.write(&block_list, &data)
    }

    pub fn request_service_v2(
        &mut self,
        service_codes: &[ServiceCode],
    ) -> Result<Vec<RequestServiceV2KeyVersion>, FelicaStandardError> {
        ensure_len_in_range("service_codes", service_codes.len(), 1, MAX_SERVICE_CODES)?;

        let idm = self.idm_bytes()?;
        let timeout_ms = self
            .polling_result
            .request_service_timeout_ms(service_codes.len());

        let response = self.execute_command(
            "Request Service v2",
            FelicaStandardCommand::RequestServiceV2 {
                idm,
                service_codes: service_codes.to_vec(),
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RequestServiceV2 {
                status_flag1,
                status_flag2,
                result,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Request Service v2",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    let result = result.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "Request Service v2 missing result payload".into(),
                        )
                    })?;
                    let key_versions = result.key_versions;
                    if key_versions.len() != service_codes.len() {
                        Err(FelicaStandardError::Protocol(
                            "Request Service v2 key version count mismatch".into(),
                        ))
                    } else {
                        Ok(key_versions)
                    }
                }
            }
            _ => Err(unexpected_response("Request Service V2")),
        }
    }

    pub fn authentication1_v2(
        &mut self,
        operation_parameter: u8,
        nodes: &[u16],
        challenge_1a: &[u8; 16],
    ) -> Result<([u8; 16], [u8; 16], [u8; 4]), FelicaStandardError> {
        let idm = self.idm_bytes()?;
        if nodes.len() > MAX_SERVICE_CODES {
            return Err(FelicaStandardError::InvalidParameter(
                "too many nodes for authentication1 v2".into(),
            ));
        }
        let timeout_ms = self.polling_result.authentication1_timeout_ms(nodes.len());
        let response = self.execute_command(
            "Authentication1 v2",
            FelicaStandardCommand::Authentication1V2 {
                idm,
                operation_parameter,
                nodes: nodes.to_vec(),
                challenge_1a: *challenge_1a,
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::Authentication1V2 {
                challenge_1b,
                challenge_2a,
                challenge_3c,
                ..
            } => Ok((challenge_1b, challenge_2a, challenge_3c)),
            _ => Err(unexpected_response("Authentication1 v2")),
        }
    }

    pub fn authentication2_v2(
        &mut self,
        challenge_2b: &[u8; 16],
    ) -> Result<Authentication2V2Response, FelicaStandardError> {
        let idm = self.idm_bytes()?;

        let timeout_ms = self.polling_result.authentication2_timeout_ms();
        let response = self.execute_command(
            "Authentication2 v2",
            FelicaStandardCommand::Authentication2V2 {
                idm,
                challenge_2b: *challenge_2b,
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::Authentication2V2(payload) => Ok(payload),
            _ => Err(unexpected_response("Authentication2 v2")),
        }
    }

    pub fn mutual_authentication_v2(
        &mut self,
        operation_parameter: u8,
        nodes: &[u16],
        group_key: &[u8; 16],
        individual_key: &[u8; 16],
    ) -> Result<MutualAuthenticationResult, FelicaStandardError> {
        if nodes.is_empty() {
            return Err(FelicaStandardError::InvalidParameter(
                "mutual authentication v2 requires at least one node code".into(),
            ));
        }

        let idm = self.idm_bytes()?;
        let mut random_1 = [0u8; 16];
        OsRng.fill_bytes(&mut random_1);

        let context = AuthenticationContextV2Aes128::new(&idm, group_key, individual_key);
        let challenge_1a = context.encrypt_challenge1a(&random_1);
        let (challenge_1b, challenge_2a, challenge_3c) =
            self.authentication1_v2(operation_parameter, nodes, &challenge_1a)?;
        if !context.verify_challenge1b(&random_1, &challenge_1b, &challenge_3c) {
            return Err(FelicaStandardError::AuthenticationFailed(
                "Authentication1 v2 verification failed".into(),
            ));
        }

        let random_2 = context.decrypt_challenge2a(&challenge_2a, &challenge_3c);
        let challenge_2b = context.encrypt_challenge2b(&random_2);
        let auth2_response = self.authentication2_v2(&challenge_2b)?;

        let mut transaction_id = [0u8; 6];
        transaction_id.copy_from_slice(&random_1[2..8]);
        let (encryption_key, mac_key) = context.derive_secure_session_keys(&random_2);

        let (transaction_number, payload) = auth2_response.decrypt_payload(
            &transaction_id,
            &challenge_3c,
            &encryption_key,
            &mac_key,
        )?;
        if payload.len() < 16 {
            return Err(FelicaStandardError::Protocol(
                "Authentication2 v2 response payload too short".into(),
            ));
        }

        let mut issue_id = [0u8; 8];
        issue_id.copy_from_slice(&payload[0..8]);
        let mut issue_parameter = [0u8; 8];
        issue_parameter.copy_from_slice(&payload[8..16]);

        let authenticated = AuthenticatedContext::new(
            transaction_number,
            transaction_id,
            SecureSessionCredentials::Aes128 {
                encryption_key,
                mac_key,
                challenge_3c,
            },
        );
        self.authenticated_context = Some(authenticated);

        Ok(MutualAuthenticationResult {
            issue_id,
            issue_parameter,
        })
    }

    pub fn register_issue_id(
        &mut self,
        system_code: u16,
        area0_key_version: u16,
        area0_key: &[u8; DES_BLOCK_SIZE],
        issue_id: &[u8; DES_BLOCK_SIZE],
        issue_parameter: &[u8; DES_BLOCK_SIZE],
        package_key: &[u8; DES_BLOCK_SIZE],
    ) -> Result<u16, FelicaStandardError> {
        let mut package_plain = Vec::with_capacity(16);
        package_plain.extend_from_slice(&system_code.to_be_bytes());
        package_plain.extend_from_slice(&area0_key_version.to_le_bytes());
        package_plain.extend_from_slice(area0_key);
        package_plain.extend_from_slice(&[0u8; 4]);

        let package = generate_registration_package_des(&package_plain, package_key)?;

        let timeout_ms = self.polling_result.registration_timeout_ms();
        let response = self.execute_command(
            "Register Issue ID",
            FelicaStandardCommand::RegisterIssueId {
                issue_id: *issue_id,
                issue_parameter: *issue_parameter,
                package,
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RegisterIssueId {
                status_flag1,
                status_flag2,
                result,
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Register Issue ID",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    let result = result.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "Register Issue ID missing result payload".into(),
                        )
                    })?;
                    Ok(result.remaining_blocks)
                }
            }
            _ => Err(unexpected_response("Register Issue ID")),
        }
    }

    pub fn register_area(
        &mut self,
        area_code: u16,
        service_code_range: (u16, u16),
        size: u16,
        key_version: u16,
        area_key: &[u8; DES_BLOCK_SIZE],
        package_key: &[u8; DES_BLOCK_SIZE],
    ) -> Result<(), FelicaStandardError> {
        let (service_code_begin, service_code_end) = service_code_range;
        if area_code != service_code_begin {
            return Err(FelicaStandardError::InvalidParameter(
                "area_code must match service_code_range start".into(),
            ));
        }

        let mut package_plain = Vec::with_capacity(2 * 4 + DES_BLOCK_SIZE);
        package_plain.extend_from_slice(&service_code_begin.to_le_bytes());
        package_plain.extend_from_slice(&service_code_end.to_le_bytes());
        package_plain.extend_from_slice(&size.to_le_bytes());
        package_plain.extend_from_slice(&key_version.to_le_bytes());
        package_plain.extend_from_slice(area_key);

        let package = generate_registration_package_des(&package_plain, package_key)?;

        let timeout_ms = self.polling_result.registration_timeout_ms();
        let response = self.execute_command(
            "Register Area",
            FelicaStandardCommand::RegisterArea { area_code, package },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RegisterArea {
                status_flag1,
                status_flag2,
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error(
                        "Register Area",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    Ok(())
                }
            }
            _ => Err(unexpected_response("Register Area")),
        }
    }

    pub fn register_service(
        &mut self,
        service_code: u16,
        size: u16,
        key_version: u16,
        service_key: &[u8; DES_BLOCK_SIZE],
        package_key: &[u8; DES_BLOCK_SIZE],
    ) -> Result<u16, FelicaStandardError> {
        let mut package_plain = Vec::with_capacity(16);
        package_plain.extend_from_slice(&service_code.to_le_bytes());
        package_plain.extend_from_slice(&[0u8; 2]);
        package_plain.extend_from_slice(&size.to_le_bytes());
        package_plain.extend_from_slice(&key_version.to_le_bytes());
        package_plain.extend_from_slice(service_key);

        let package = generate_registration_package_des(&package_plain, package_key)?;

        let timeout_ms = self.polling_result.registration_timeout_ms();
        let response = self.execute_command(
            "Register Service",
            FelicaStandardCommand::RegisterService {
                service_code,
                package,
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RegisterService {
                status_flag1,
                status_flag2,
                result,
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Register Service",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    let result = result.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "Register Service missing result payload".into(),
                        )
                    })?;
                    Ok(result.remaining_blocks)
                }
            }
            _ => Err(unexpected_response("Register Service")),
        }
    }

    pub fn change_system_block(&mut self) -> Result<(), FelicaStandardError> {
        let timeout_ms = self.polling_result.registration_timeout_ms();
        let response = self.execute_command(
            "Change System Block",
            FelicaStandardCommand::ChangeSystemBlock,
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::ChangeSystemBlock {
                status_flag1,
                status_flag2,
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error(
                        "Change System Block",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    Ok(())
                }
            }
            _ => Err(unexpected_response("Change System Block")),
        }
    }
}

fn ensure_len_in_range(
    name: &str,
    len: usize,
    min: usize,
    max: usize,
) -> Result<(), FelicaStandardError> {
    if (min..=max).contains(&len) {
        Ok(())
    } else {
        Err(FelicaStandardError::InvalidParameter(format!(
            "{name} must contain between {min} and {max} entries"
        )))
    }
}

fn validate_block_list_indices(
    block_list: &[BlockListElement],
    service_codes_len: usize,
) -> Result<(), FelicaStandardError> {
    if block_list
        .iter()
        .any(|block| block.service_code_list_index as usize >= service_codes_len)
    {
        Err(FelicaStandardError::InvalidParameter(
            "block_list references out-of-range service index".into(),
        ))
    } else {
        Ok(())
    }
}

fn ensure_block_data_length(
    block_count: usize,
    data_len: usize,
) -> Result<(), FelicaStandardError> {
    let expected = block_count * BLOCK_SIZE;
    if data_len == expected {
        Ok(())
    } else {
        Err(FelicaStandardError::InvalidParameter(
            "data length must equal 16 * block_list length".into(),
        ))
    }
}

fn expected_secure_response_code(command_code: u8) -> u8 {
    match command_code {
        READ_V2_COMMAND_CODE => READ_V2_RESPONSE_CODE,
        WRITE_V2_COMMAND_CODE => WRITE_V2_RESPONSE_CODE,
        _ => command_code.wrapping_add(1),
    }
}

fn unexpected_response(command: &'static str) -> FelicaStandardError {
    FelicaStandardError::Protocol(format!("unexpected response for {command} command"))
}

#[cfg(test)]
mod tests {
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

    fn assert_invalid_parameter_contains<T>(
        result: Result<T, FelicaStandardError>,
        expected: &str,
    ) {
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

        let package =
            generate_registration_package_des(&[0xAB; 16], &[0x11; DES_BLOCK_SIZE]).unwrap();
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
}
