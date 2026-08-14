use super::*;
use crate::felica_standard::payload::{
    PayloadWriter, ensure_count_in_range, ensure_fits_in_count, ensure_omitted_on_error,
    for_success,
};

/// What a response calls the bytes behind its status flags, for the errors
/// [`for_success`] raises.
const RESULT: &str = "result";

impl FelicaStandardResponse {
    pub fn to_payload(&self) -> Result<Vec<u8>, FelicaStandardError> {
        match self {
            FelicaStandardResponse::Polling { idm, pmm, optional } => {
                let mut payload = PayloadWriter::response(POLLING_RESPONSE_CODE, idm);
                payload.extend_bytes(pmm);
                payload.extend_bytes(optional);
                Ok(payload.finish())
            }
            FelicaStandardResponse::RequestService { idm, key_versions } => {
                ensure_count_in_range(
                    "request service key version count",
                    key_versions.len(),
                    MAX_SERVICE_CODES,
                )?;
                let mut payload = PayloadWriter::response(REQUEST_SERVICE_RESPONSE_CODE, idm);
                payload.extend_counted_u16_le(key_versions);
                Ok(payload.finish())
            }
            FelicaStandardResponse::RequestResponse { idm, mode } => {
                let mut payload = PayloadWriter::response(REQUEST_RESPONSE_RESPONSE_CODE, idm);
                payload.push_u8(*mode);
                Ok(payload.finish())
            }
            FelicaStandardResponse::ReadWithoutEncryption {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload =
                    PayloadWriter::response(READ_WITHOUT_ENCRYPTION_RESPONSE_CODE, idm);
                payload.status_flags(*status_flag1, *status_flag2);
                if let Some(result) = for_success(
                    "read without encryption",
                    RESULT,
                    *status_flag1,
                    result.as_ref(),
                )? {
                    ensure_count_in_range(
                        "read without encryption block count",
                        result.blocks.len(),
                        MAX_BLOCK_COUNT,
                    )?;
                    payload.push_count(result.blocks.len());
                    for block in &result.blocks {
                        payload.extend_bytes(block);
                    }
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::WriteWithoutEncryption {
                idm,
                status_flag1,
                status_flag2,
            } => Ok(Self::status_only(
                WRITE_WITHOUT_ENCRYPTION_RESPONSE_CODE,
                idm,
                *status_flag1,
                *status_flag2,
            )),
            FelicaStandardResponse::SearchServiceCode { idm, result } => {
                let mut payload = PayloadWriter::response(SEARCH_SERVICE_CODE_RESPONSE_CODE, idm);
                match result {
                    // No node with that index: the card answers with FFFFh.
                    None => payload.extend_bytes(&[0xFF, 0xFF]),
                    Some(SearchServiceCodeResult::Service(code)) => {
                        payload.extend_u16_le(code.raw());
                    }
                    Some(SearchServiceCodeResult::Area {
                        area_code,
                        end_service_code,
                    }) => {
                        payload.extend_u16_le(*area_code);
                        payload.extend_u16_le(*end_service_code);
                    }
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::RequestSystemCode { idm, system_codes } => {
                if system_codes.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "request system code must include at least one entry".into(),
                    ));
                }
                let mut payload = PayloadWriter::response(REQUEST_SYSTEM_CODE_RESPONSE_CODE, idm);
                payload.extend_counted_u16_be(system_codes);
                Ok(payload.finish())
            }
            FelicaStandardResponse::RequestBlockInformation { idm, block_counts } => {
                ensure_count_in_range(
                    "request block information count",
                    block_counts.len(),
                    MAX_NODE_CODES,
                )?;
                let mut payload =
                    PayloadWriter::response(REQUEST_BLOCK_INFORMATION_RESPONSE_CODE, idm);
                payload.extend_counted_u16_le(block_counts);
                Ok(payload.finish())
            }
            FelicaStandardResponse::Authentication1 {
                idm,
                challenge_1b,
                challenge_2a,
            } => {
                let mut payload = PayloadWriter::response(AUTHENTICATION1_RESPONSE_CODE, idm);
                payload.extend_bytes(challenge_1b);
                payload.extend_bytes(challenge_2a);
                Ok(payload.finish())
            }
            FelicaStandardResponse::Authentication2(auth) => {
                let mut payload = PayloadWriter::new(AUTHENTICATION2_RESPONSE_CODE);
                payload.extend_bytes(&auth.encrypted_payload);
                Ok(payload.finish())
            }
            FelicaStandardResponse::RequestCodeList {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload = PayloadWriter::response(REQUEST_CODE_LIST_RESPONSE_CODE, idm);
                payload.status_flags(*status_flag1, *status_flag2);
                if let Some(result) =
                    for_success("request code list", RESULT, *status_flag1, result.as_ref())?
                {
                    ensure_fits_in_count("request code list area count", result.areas.len())?;
                    ensure_fits_in_count("request code list service count", result.services.len())?;
                    payload.push_flag(result.continue_flag);
                    payload.push_count(result.areas.len());
                    for area in &result.areas {
                        payload.extend_u16_le(area.area_code);
                        payload.extend_u16_le(area.end_service_code);
                    }
                    payload.push_count(result.services.len());
                    for service in &result.services {
                        payload.extend_u16_le(service.raw());
                    }
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::RequestBlockInformationEx {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload =
                    PayloadWriter::response(REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE, idm);
                payload.status_flags(*status_flag1, *status_flag2);
                if let Some(result) = for_success(
                    "request block information ex",
                    RESULT,
                    *status_flag1,
                    result.as_ref(),
                )? {
                    ensure_count_in_range(
                        "request block information ex count",
                        result.assigned_block_counts.len(),
                        MAX_NODE_CODES,
                    )?;
                    if result.assigned_block_counts.len() != result.free_block_counts.len() {
                        return Err(FelicaStandardError::Protocol(
                            "request block information ex assigned/free length mismatch".into(),
                        ));
                    }
                    payload.push_count(result.assigned_block_counts.len());
                    for (assigned, free) in result
                        .assigned_block_counts
                        .iter()
                        .zip(result.free_block_counts.iter())
                    {
                        payload.extend_u16_le(*assigned);
                        payload.extend_u16_le(*free);
                    }
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::SetParameter {
                idm,
                status_flag1,
                status_flag2,
            } => Ok(Self::status_only(
                SET_PARAMETER_RESPONSE_CODE,
                idm,
                *status_flag1,
                *status_flag2,
            )),
            FelicaStandardResponse::GetContainerIssueInformation {
                idm,
                container_information,
            } => {
                let mut payload =
                    PayloadWriter::response(GET_CONTAINER_ISSUE_INFORMATION_RESPONSE_CODE, idm);
                payload.extend_bytes(&container_information.format_version_carrier_information);
                payload.extend_bytes(&container_information.mobile_phone_model_information);
                Ok(payload.finish())
            }
            FelicaStandardResponse::GetAreaInformation {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload = PayloadWriter::response(GET_AREA_INFORMATION_RESPONSE_CODE, idm);
                payload.status_flags(*status_flag1, *status_flag2);
                if let Some(result) = for_success(
                    "get area information",
                    RESULT,
                    *status_flag1,
                    result.as_ref(),
                )? {
                    payload.extend_u16_le(result.node_code);
                    payload.extend_bytes(&result.data);
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::GetNodeProperty {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload = PayloadWriter::response(GET_NODE_PROPERTY_RESPONSE_CODE, idm);
                payload.status_flags(*status_flag1, *status_flag2);
                if let Some(result) =
                    for_success("get node property", RESULT, *status_flag1, result.as_ref())?
                {
                    ensure_count_in_range(
                        "get node property count",
                        result.node_properties.len(),
                        MAX_NODE_PROPERTY_CODES,
                    )?;
                    // The one property type byte of the response covers every
                    // entry, so a mixed list has no encoding.
                    let property_type = result.node_properties[0].property_type();
                    if result
                        .node_properties
                        .iter()
                        .any(|property| property.property_type() != property_type)
                    {
                        return Err(FelicaStandardError::Protocol(
                            "get node property response cannot mix property types".into(),
                        ));
                    }
                    payload.push_count(result.node_properties.len());
                    for property in &result.node_properties {
                        payload.extend_bytes(&(*property).to_bytes());
                    }
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::GetContainerProperty { data } => {
                if data.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "get container property response data must contain at least one byte"
                            .into(),
                    ));
                }
                let mut payload = PayloadWriter::new(GET_CONTAINER_PROPERTY_RESPONSE_CODE);
                payload.extend_bytes(data);
                Ok(payload.finish())
            }
            FelicaStandardResponse::RequestServiceV2 {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload = PayloadWriter::response(REQUEST_SERVICE_V2_RESPONSE_CODE, idm);
                payload.status_flags(*status_flag1, *status_flag2);
                if let Some(result) =
                    for_success("request service v2", RESULT, *status_flag1, result.as_ref())?
                {
                    Self::write_service_v2_key_versions(&mut payload, result)?;
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::GetSystemStatus {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                ensure_fits_in_count("get system status response data length", result.data.len())?;
                let mut payload = PayloadWriter::response(GET_SYSTEM_STATUS_RESPONSE_CODE, idm);
                payload.status_flags(*status_flag1, *status_flag2);
                payload.push_u8(result.flag);
                payload.push_count(result.data.len());
                payload.extend_bytes(&result.data);
                Ok(payload.finish())
            }
            FelicaStandardResponse::RequestProductInformation {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload =
                    PayloadWriter::response(REQUEST_PRODUCT_INFORMATION_RESPONSE_CODE, idm);
                payload.status_flags(*status_flag1, *status_flag2);
                if let Some(result) = for_success(
                    "request product information",
                    RESULT,
                    *status_flag1,
                    result.as_ref(),
                )? {
                    ensure_fits_in_count(
                        "request product information response data length",
                        result.len(),
                    )?;
                    payload.push_count(result.len());
                    payload.extend_bytes(result);
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::RequestSpecificationVersion {
                idm,
                status_flag1,
                status_flag2,
                specification_version,
            } => {
                // Unlike the other flagged responses this one may report success
                // and still carry nothing, so only the error half is required.
                ensure_omitted_on_error(
                    "request specification version",
                    "payload",
                    *status_flag1,
                    specification_version.is_some(),
                )?;
                let mut payload =
                    PayloadWriter::response(REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE, idm);
                payload.status_flags(*status_flag1, *status_flag2);
                if let Some(version) = specification_version
                    .as_ref()
                    .filter(|_| *status_flag1 == 0)
                {
                    if version.format_version != 0x00 {
                        return Err(FelicaStandardError::Protocol(
                            "request specification version format version must be 0x00".into(),
                        ));
                    }
                    ensure_fits_in_count(
                        "request specification version option count",
                        version.option_versions.len(),
                    )?;
                    payload.extend_bytes(&version.to_bytes());
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::ResetMode {
                idm,
                status_flag1,
                status_flag2,
            } => Ok(Self::status_only(
                RESET_MODE_RESPONSE_CODE,
                idm,
                *status_flag1,
                *status_flag2,
            )),
            FelicaStandardResponse::Authentication1V2 {
                idm,
                challenge_1b,
                challenge_2a,
                challenge_3c,
            } => {
                let mut payload = PayloadWriter::response(AUTHENTICATION1_V2_RESPONSE_CODE, idm);
                payload.extend_bytes(challenge_1b);
                payload.extend_bytes(challenge_2a);
                payload.extend_bytes(challenge_3c);
                Ok(payload.finish())
            }
            FelicaStandardResponse::Authentication2V2(auth) => {
                let mut payload = PayloadWriter::new(AUTHENTICATION2_V2_RESPONSE_CODE);
                payload.extend_bytes(&auth.encrypted_payload);
                Ok(payload.finish())
            }
            FelicaStandardResponse::GetContainerId { container_idm } => {
                Ok(PayloadWriter::response(GET_CONTAINER_ID_RESPONSE_CODE, container_idm).finish())
            }
            FelicaStandardResponse::Read { .. }
            | FelicaStandardResponse::Write { .. }
            | FelicaStandardResponse::ReadV2 { .. }
            | FelicaStandardResponse::WriteV2 { .. }
            | FelicaStandardResponse::RegisterIssueId { .. }
            | FelicaStandardResponse::RegisterArea { .. }
            | FelicaStandardResponse::RegisterService { .. }
            | FelicaStandardResponse::ChangeSystemBlock { .. } => self.to_secure_payload(),
            FelicaStandardResponse::Unknown => Err(FelicaStandardError::Protocol(
                "cannot encode unknown response".into(),
            )),
        }
    }

    pub fn to_frame(&self) -> Result<Vec<u8>, FelicaStandardError> {
        match self {
            FelicaStandardResponse::Read { .. }
            | FelicaStandardResponse::Write { .. }
            | FelicaStandardResponse::ReadV2 { .. }
            | FelicaStandardResponse::WriteV2 { .. }
            | FelicaStandardResponse::RegisterIssueId { .. }
            | FelicaStandardResponse::RegisterArea { .. }
            | FelicaStandardResponse::RegisterService { .. }
            | FelicaStandardResponse::ChangeSystemBlock { .. } => Err(
                FelicaStandardError::Protocol("secure response requires encryption".into()),
            ),
            _ => {
                let payload = self.to_payload()?;
                frame_with_length_prefix(&payload)
            }
        }
    }

    pub fn to_secure_payload(&self) -> Result<Vec<u8>, FelicaStandardError> {
        match self {
            FelicaStandardResponse::Read {
                status_flag1,
                status_flag2,
                result,
            }
            | FelicaStandardResponse::ReadV2 {
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload = Self::secure_status_only(*status_flag1, *status_flag2);
                if let Some(result) =
                    for_success("secure read", RESULT, *status_flag1, result.as_ref())?
                {
                    ensure_count_in_range(
                        "secure read block count",
                        result.blocks.len(),
                        MAX_BLOCK_COUNT,
                    )?;
                    payload.push_count(result.blocks.len());
                    for block in &result.blocks {
                        payload.extend_bytes(block);
                    }
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::RegisterIssueId {
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload = Self::secure_status_only(*status_flag1, *status_flag2);
                if let Some(result) =
                    for_success("register issue id", RESULT, *status_flag1, result.as_ref())?
                {
                    payload.extend_u16_le(result.remaining_blocks);
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::RegisterService {
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload = Self::secure_status_only(*status_flag1, *status_flag2);
                if let Some(result) =
                    for_success("register service", RESULT, *status_flag1, result.as_ref())?
                {
                    payload.extend_u16_le(result.remaining_blocks);
                }
                Ok(payload.finish())
            }
            FelicaStandardResponse::Write {
                status_flag1,
                status_flag2,
            }
            | FelicaStandardResponse::WriteV2 {
                status_flag1,
                status_flag2,
            }
            | FelicaStandardResponse::RegisterArea {
                status_flag1,
                status_flag2,
            }
            | FelicaStandardResponse::ChangeSystemBlock {
                status_flag1,
                status_flag2,
            } => Ok(vec![*status_flag1, *status_flag2]),
            _ => Err(FelicaStandardError::Protocol(
                "plain response cannot be encoded as secure payload".into(),
            )),
        }
    }

    /// Encodes a response that carries nothing beyond its status flags.
    fn status_only(code: u8, idm: &Idm, status_flag1: u8, status_flag2: u8) -> Vec<u8> {
        let mut payload = PayloadWriter::response(code, idm);
        payload.status_flags(status_flag1, status_flag2);
        payload.finish()
    }

    /// Starts a secure response, which is addressed by its session rather than
    /// by an IDm and so begins at the status flags.
    fn secure_status_only(status_flag1: u8, status_flag2: u8) -> PayloadWriter {
        let mut payload = PayloadWriter::with_capacity(4);
        payload.status_flags(status_flag1, status_flag2);
        payload
    }

    /// Writes the crypto identifier and key version list of a Request Service
    /// V2 response.
    ///
    /// Crypto identifiers `41h` and `43h` mean the card holds both an AES and a
    /// DES key per node, and sends the two versions as separate runs rather than
    /// interleaved: every AES version first, then every DES version.
    fn write_service_v2_key_versions(
        payload: &mut PayloadWriter,
        result: &RequestServiceV2Result,
    ) -> Result<(), FelicaStandardError> {
        let key_versions = &result.key_versions;
        ensure_count_in_range(
            "request service v2 key version count",
            key_versions.len(),
            MAX_SERVICE_CODES,
        )?;
        payload.push_u8(result.crypto_id);
        payload.push_count(key_versions.len());

        if !matches!(result.crypto_id, 0x41 | 0x43) {
            for version in key_versions {
                if version.secondary_raw().is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "request service v2 single crypto requires single key versions".into(),
                    ));
                }
                payload.extend_u16_le(version.primary_raw());
            }
            return Ok(());
        }

        let mut secondary_versions = Vec::with_capacity(key_versions.len());
        for version in key_versions {
            let secondary = version.secondary_raw().ok_or_else(|| {
                FelicaStandardError::Protocol(
                    "request service v2 dual crypto requires dual key versions".into(),
                )
            })?;
            payload.extend_u16_le(version.primary_raw());
            secondary_versions.push(secondary);
        }
        payload.extend_u16_list_le(&secondary_versions);
        Ok(())
    }
}
