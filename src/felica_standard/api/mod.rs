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
        bitrate: &str,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<(Self, Type3TagPollingResult), FelicaStandardError> {
        let target = RemoteTarget::new(bitrate)?;
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

mod basic;
mod secure_ops;

#[cfg(test)]
mod tests;
