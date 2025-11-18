use super::command::{CommandEncoding, FelicaStandardCommand};
use super::error::FelicaStandardError;
use super::response::FelicaStandardResponse;
use super::secure::{
    AuthenticatedContext, Authentication2Response, AuthenticationContext, SecureCommandContext,
    SecureResponse, encrypt_des_cbc_zero_iv,
};
use super::types::{
    BlockListElement, ChangeKeyParameters, MutualAuthenticationResult, RequestServiceV2KeyVersion,
    SearchServiceCodeResult, ServiceCode,
};
use super::{
    BLOCK_SIZE, DES_BLOCK_SIZE, IDM_LEN, MAX_BLOCK_LIST_LEN, MAX_NODE_CODES, MAX_RW_SERVICE_CODES,
    MAX_SERVICE_CODES, frame_with_length_prefix,
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
            detail: status_flag_description_text(sf1, sf2),
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
            "request service",
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
            "request response",
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
            "read without encryption",
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
                blocks,
                ..
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error(
                        "read without encryption",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    Ok(blocks)
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
            "write without encryption",
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
                        "write without encryption",
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
            "search service code",
            FelicaStandardCommand::SearchServiceCode { idm, service_index },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::SearchServiceCode { result, .. } => Ok(result),
            _ => Err(unexpected_response("Search Service Code")),
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
            "request block information",
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
            "authentication1",
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
            "authentication2",
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

        let challenge_1a = context.encrypt_challenge1(&random_1);
        let (challenge_1b, challenge_2a) = self.authentication1(areas, services, &challenge_1a)?;
        if !context.verify_challenge1(&random_1, &challenge_1b) {
            return Err(FelicaStandardError::AuthenticationFailed(
                "authentication1 verification failed".into(),
            ));
        }

        let random_2 = context.decrypt_challenge2(&challenge_2a);
        let challenge_2b = context.encrypt_challenge2(&random_2);
        let auth2_response = self.authentication2(&challenge_2b)?;
        let payload = auth2_response.decrypt_payload(&random_2)?;
        if payload.len() < 24 {
            return Err(FelicaStandardError::Protocol(
                "authentication2 response payload too short".into(),
            ));
        }
        let transaction_number = u16::from_le_bytes([payload[0], payload[1]]);
        let mut transaction_id = [0u8; 6];
        transaction_id.copy_from_slice(&payload[2..8]);
        let mut expected_id = [0u8; 6];
        expected_id.copy_from_slice(&random_1[2..8]);
        if transaction_id != expected_id {
            return Err(FelicaStandardError::AuthenticationFailed(
                "authentication2 transaction ID mismatch".into(),
            ));
        }
        let mut issue_id = [0u8; 8];
        issue_id.copy_from_slice(&payload[8..16]);
        let mut issue_parameter = [0u8; 8];
        issue_parameter.copy_from_slice(&payload[16..24]);

        let context = AuthenticatedContext::new(transaction_number, transaction_id, random_2);
        self.authenticated_context = Some(context);

        Ok(MutualAuthenticationResult {
            issue_id,
            issue_parameter,
        })
    }

    pub fn authenticated_context(&self) -> Option<&AuthenticatedContext> {
        self.authenticated_context.as_ref()
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
        let payload = command_context.build_payload(command_payload);
        let encrypted = command_context.encrypt_request(command_code, payload)?;
        let encrypted_response =
            self.send_encrypted_command(command_code, &encrypted, timeout_ms)?;
        let decrypted_response = command_context.decrypt_response(&encrypted_response)?;
        self.process_encrypted_response(command_code, &decrypted_response)
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
        if response[1] != command_code + 1 {
            return Err(FelicaStandardError::Protocol(
                "secure response command code mismatch".into(),
            ));
        }
        Ok(response[2..].to_vec())
    }

    fn process_encrypted_response(
        &mut self,
        command_code: u8,
        decrypted_response: &[u8],
    ) -> Result<Vec<u8>, FelicaStandardError> {
        let SecureResponse { header, payload } =
            SecureResponse::parse(decrypted_response, command_code + 1)?;
        {
            let context = self.secure_context_mut()?;
            header.apply(context)?;
        }
        Ok(payload.to_vec())
    }

    pub fn read(
        &mut self,
        block_list: &[BlockListElement],
    ) -> Result<Vec<[u8; BLOCK_SIZE]>, FelicaStandardError> {
        ensure_len_in_range("block_list", block_list.len(), 1, MAX_BLOCK_LIST_LEN)?;

        let timeout_ms = self
            .polling_result
            .read_without_encryption_timeout_ms(block_list.len());

        let response = self.execute_command(
            "read",
            FelicaStandardCommand::Read {
                block_list: block_list.to_vec(),
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::Read {
                status_flag1,
                status_flag2,
                blocks,
                ..
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error("read", status_flag1, status_flag2))
                } else if blocks.len() != block_list.len() {
                    Err(FelicaStandardError::Protocol(
                        "encrypted read response block count mismatch".into(),
                    ))
                } else {
                    Ok(blocks)
                }
            }
            _ => Err(unexpected_response("Read")),
        }
    }

    pub fn write(
        &mut self,
        block_list: &[BlockListElement],
        data: &[u8],
    ) -> Result<(), FelicaStandardError> {
        ensure_len_in_range("block_list", block_list.len(), 1, MAX_BLOCK_LIST_LEN)?;
        ensure_block_data_length(block_list.len(), data.len())?;

        let timeout_ms = self
            .polling_result
            .write_without_encryption_timeout_ms(block_list.len());

        let response = self.execute_command(
            "write",
            FelicaStandardCommand::Write {
                block_list: block_list.to_vec(),
                data: data.to_vec(),
            },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::Write {
                status_flag1,
                status_flag2,
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error("write", status_flag1, status_flag2))
                } else {
                    Ok(())
                }
            }
            _ => Err(unexpected_response("Write")),
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
            "request service v2",
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
                key_versions,
                ..
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error(
                        "request service v2",
                        status_flag1,
                        status_flag2,
                    ))
                } else if key_versions.len() != service_codes.len() {
                    Err(FelicaStandardError::Protocol(
                        "request service v2 key version count mismatch".into(),
                    ))
                } else {
                    Ok(key_versions)
                }
            }
            _ => Err(unexpected_response("Request Service V2")),
        }
    }

    pub fn register_issue_id(
        &mut self,
        system_code: u16,
        key_version: u16,
        area0_key: &[u8; DES_BLOCK_SIZE],
        issue_id: &[u8; DES_BLOCK_SIZE],
        issue_parameter: &[u8; DES_BLOCK_SIZE],
        package_key: &[u8; DES_BLOCK_SIZE],
    ) -> Result<u16, FelicaStandardError> {
        let mut package_plain = Vec::with_capacity(16);
        package_plain.extend_from_slice(&system_code.to_be_bytes());
        package_plain.extend_from_slice(&key_version.to_le_bytes());
        package_plain.extend_from_slice(area0_key);
        package_plain.extend_from_slice(&[0u8; 4]);

        let package = generate_registration_package(&package_plain, package_key)?;

        let timeout_ms = self.polling_result.registration_timeout_ms();
        let response = self.execute_command(
            "register issue id",
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
                remaining_blocks,
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error(
                        "register issue id",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    Ok(remaining_blocks)
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

        let package = generate_registration_package(&package_plain, package_key)?;

        let timeout_ms = self.polling_result.registration_timeout_ms();
        let response = self.execute_command(
            "register area",
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
                        "register area",
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

        let package = generate_registration_package(&package_plain, package_key)?;

        let timeout_ms = self.polling_result.registration_timeout_ms();
        let response = self.execute_command(
            "register service",
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
                remaining_blocks,
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error(
                        "register service",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    Ok(remaining_blocks)
                }
            }
            _ => Err(unexpected_response("Register Service")),
        }
    }

    pub fn commit_registration(&mut self) -> Result<(), FelicaStandardError> {
        let timeout_ms = self.polling_result.registration_timeout_ms();
        let response = self.execute_command(
            "commit registration",
            FelicaStandardCommand::CommitRegistration,
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::CommitRegistration {
                status_flag1,
                status_flag2,
            } => {
                if status_flag1 != 0 || status_flag2 != 0 {
                    Err(Self::status_error(
                        "commit registration",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    Ok(())
                }
            }
            _ => Err(unexpected_response("Commit Registration")),
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

fn generate_registration_package(
    package_plain: &[u8],
    package_key: &[u8; DES_BLOCK_SIZE],
) -> Result<Vec<u8>, FelicaStandardError> {
    if package_plain.is_empty() || package_plain.len() % DES_BLOCK_SIZE != 0 {
        return Err(FelicaStandardError::InvalidParameter(
            "registration package must be multiple of 8 bytes".into(),
        ));
    }

    let mut mac_key = [0u8; DES_BLOCK_SIZE];
    for (dst, src) in mac_key.iter_mut().zip(package_key.iter()) {
        *dst = *src ^ 0xFF;
    }

    let encrypted_plain =
        encrypt_des_cbc_zero_iv(package_plain, &mac_key).map_err(FelicaStandardError::Protocol)?;
    if encrypted_plain.len() < DES_BLOCK_SIZE {
        return Err(FelicaStandardError::Protocol(
            "registration package MAC calculation failed".into(),
        ));
    }

    let mac = &encrypted_plain[encrypted_plain.len() - DES_BLOCK_SIZE..];
    let mut package_with_mac = Vec::with_capacity(package_plain.len() + DES_BLOCK_SIZE);
    package_with_mac.extend_from_slice(package_plain);
    package_with_mac.extend_from_slice(mac);

    encrypt_des_cbc_zero_iv(&package_with_mac, package_key).map_err(FelicaStandardError::Protocol)
}

fn unexpected_response(command: &'static str) -> FelicaStandardError {
    FelicaStandardError::Protocol(format!("unexpected response for {command} command"))
}

fn status_flag_description_text(sf1: u8, sf2: u8) -> String {
    let sf1_desc = match sf1 {
        0x00 => "normal completion".to_string(),
        0xFF => "error not associated with a specific list entry".to_string(),
        other => format!("error at list index {}", other),
    };
    let sf2_desc = match sf2 {
        0x00 => "no additional error detail",
        0x01 => "purse decrement would underflow or cashback overflow",
        0x02 => "cashback amount exceeds stored purse value",
        0x03 => "limit purse write outside allowed range",
        0x70 => "memory error",
        0x71 => "memory write count exceeded",
        0xA1 => "service/node count out of range",
        0xA2 => "block count out of range",
        0xA3 => "service list index out of range",
        0xA4 => "area or service attribute mismatch",
        0xA5 => "access denied or parameters do not satisfy constraints",
        0xA6 => "referenced service/area/node does not exist",
        0xA7 => "invalid access mode",
        0xA8 => "block number exceeds service size",
        0xA9 => "issuing command write failure",
        0xAA => "key change failed",
        0xAB => "package parity or MAC invalid",
        0xAC => "invalid parameters",
        0xAD => "service already exists",
        0xAE => "system code invalid",
        0xAF => "cyclic service simultaneous writes exceed service blocks",
        0xC0 => "package identifier invalid",
        0xC1 => "package parameter mismatch",
        0xC2 => "issuing command disabled",
        0xC3 => "node attribute mismatch",
        _ => "unknown status flag 2",
    };
    format!("SF1: {sf1_desc}; SF2: {sf2_desc}")
}
