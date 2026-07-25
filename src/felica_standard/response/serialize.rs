use super::*;

impl FelicaStandardResponse {
    pub fn to_payload(&self) -> Result<Vec<u8>, FelicaStandardError> {
        match self {
            FelicaStandardResponse::Polling { idm, pmm, optional } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 8 + optional.len());
                payload.push(POLLING_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.extend_from_slice(pmm);
                payload.extend_from_slice(optional);
                Ok(payload)
            }
            FelicaStandardResponse::RequestService { idm, key_versions } => {
                if key_versions.is_empty() || key_versions.len() > MAX_SERVICE_CODES {
                    return Err(FelicaStandardError::Protocol(
                        "request service key version count out of range".into(),
                    ));
                }
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 1 + key_versions.len() * 2);
                payload.push(REQUEST_SERVICE_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(key_versions.len() as u8);
                for version in key_versions {
                    payload.extend_from_slice(&version.to_le_bytes());
                }
                Ok(payload)
            }
            FelicaStandardResponse::RequestResponse { idm, mode } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 1);
                payload.push(REQUEST_RESPONSE_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*mode);
                Ok(payload)
            }
            FelicaStandardResponse::ReadWithoutEncryption {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                let block_len = result.as_ref().map(|value| value.blocks.len()).unwrap_or(0);
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 3 + block_len * BLOCK_SIZE);
                payload.push(READ_WITHOUT_ENCRYPTION_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "read without encryption result is missing on success".into(),
                        )
                    })?;
                    let blocks = &result.blocks;
                    if blocks.is_empty() || blocks.len() > MAX_BLOCK_COUNT {
                        return Err(FelicaStandardError::Protocol(
                            "read without encryption block count out of range".into(),
                        ));
                    }
                    payload.push(blocks.len() as u8);
                    for block in blocks {
                        payload.extend_from_slice(block);
                    }
                } else if result.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "read without encryption result must be omitted on error".into(),
                    ));
                }
                Ok(payload)
            }
            FelicaStandardResponse::WriteWithoutEncryption {
                idm,
                status_flag1,
                status_flag2,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                payload.push(WRITE_WITHOUT_ENCRYPTION_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                Ok(payload)
            }
            FelicaStandardResponse::SearchServiceCode { idm, result } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 4);
                payload.push(SEARCH_SERVICE_CODE_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                match result {
                    None => payload.extend_from_slice(&[0xFF, 0xFF]),
                    Some(SearchServiceCodeResult::Service(code)) => {
                        payload.extend_from_slice(&code.raw().to_le_bytes());
                    }
                    Some(SearchServiceCodeResult::Area {
                        area_code,
                        end_service_code,
                    }) => {
                        payload.extend_from_slice(&area_code.to_le_bytes());
                        payload.extend_from_slice(&end_service_code.to_le_bytes());
                    }
                }
                Ok(payload)
            }
            FelicaStandardResponse::RequestSystemCode { idm, system_codes } => {
                if system_codes.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "request system code must include at least one entry".into(),
                    ));
                }
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 1 + system_codes.len() * 2);
                payload.push(REQUEST_SYSTEM_CODE_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(system_codes.len() as u8);
                for code in system_codes {
                    payload.extend_from_slice(&code.to_be_bytes());
                }
                Ok(payload)
            }
            FelicaStandardResponse::RequestBlockInformation { idm, block_counts } => {
                if block_counts.is_empty() || block_counts.len() > MAX_NODE_CODES {
                    return Err(FelicaStandardError::Protocol(
                        "request block information count out of range".into(),
                    ));
                }
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 1 + block_counts.len() * 2);
                payload.push(REQUEST_BLOCK_INFORMATION_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(block_counts.len() as u8);
                for count in block_counts {
                    payload.extend_from_slice(&count.to_le_bytes());
                }
                Ok(payload)
            }
            FelicaStandardResponse::Authentication1 {
                idm,
                challenge_1b,
                challenge_2a,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 16);
                payload.push(AUTHENTICATION1_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.extend_from_slice(challenge_1b);
                payload.extend_from_slice(challenge_2a);
                Ok(payload)
            }
            FelicaStandardResponse::Authentication2(auth) => {
                let mut payload = Vec::with_capacity(1 + auth.encrypted_payload.len());
                payload.push(AUTHENTICATION2_RESPONSE_CODE);
                payload.extend_from_slice(&auth.encrypted_payload);
                Ok(payload)
            }
            FelicaStandardResponse::RequestCodeList {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "request code list result is missing on success".into(),
                        )
                    })?;
                    if result.areas.len() > u8::MAX as usize {
                        return Err(FelicaStandardError::Protocol(
                            "request code list area count out of range".into(),
                        ));
                    }
                    if result.services.len() > u8::MAX as usize {
                        return Err(FelicaStandardError::Protocol(
                            "request code list service count out of range".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(
                        1 + IDM_LEN
                            + 2
                            + 1
                            + 1
                            + result.areas.len() * 4
                            + 1
                            + result.services.len() * 2,
                    );
                    payload.push(REQUEST_CODE_LIST_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    payload.push(if result.continue_flag { 0x01 } else { 0x00 });
                    payload.push(result.areas.len() as u8);
                    for area in &result.areas {
                        payload.extend_from_slice(&area.area_code.to_le_bytes());
                        payload.extend_from_slice(&area.end_service_code.to_le_bytes());
                    }
                    payload.push(result.services.len() as u8);
                    for service in &result.services {
                        payload.extend_from_slice(&service.raw().to_le_bytes());
                    }
                    Ok(payload)
                } else {
                    if result.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "request code list result must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(REQUEST_CODE_LIST_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::RequestBlockInformationEx {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "request block information ex result is missing on success".into(),
                        )
                    })?;
                    if result.assigned_block_counts.is_empty()
                        || result.assigned_block_counts.len() > MAX_NODE_CODES
                    {
                        return Err(FelicaStandardError::Protocol(
                            "request block information ex count out of range".into(),
                        ));
                    }
                    if result.assigned_block_counts.len() != result.free_block_counts.len() {
                        return Err(FelicaStandardError::Protocol(
                            "request block information ex assigned/free length mismatch".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(
                        1 + IDM_LEN + 2 + 1 + result.assigned_block_counts.len() * 4,
                    );
                    payload.push(REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    payload.push(result.assigned_block_counts.len() as u8);
                    for (assigned, free) in result
                        .assigned_block_counts
                        .iter()
                        .zip(result.free_block_counts.iter())
                    {
                        payload.extend_from_slice(&assigned.to_le_bytes());
                        payload.extend_from_slice(&free.to_le_bytes());
                    }
                    Ok(payload)
                } else {
                    if result.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "request block information ex result must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::SetParameter {
                idm,
                status_flag1,
                status_flag2,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                payload.push(SET_PARAMETER_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                Ok(payload)
            }
            FelicaStandardResponse::GetContainerIssueInformation {
                idm,
                container_information,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 16);
                payload.push(GET_CONTAINER_ISSUE_INFORMATION_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload
                    .extend_from_slice(&container_information.format_version_carrier_information);
                payload.extend_from_slice(&container_information.mobile_phone_model_information);
                Ok(payload)
            }
            FelicaStandardResponse::GetAreaInformation {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "get area information result is missing on success".into(),
                        )
                    })?;
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2 + 4);
                    payload.push(GET_AREA_INFORMATION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    payload.extend_from_slice(&result.node_code.to_le_bytes());
                    payload.extend_from_slice(&result.data);
                    Ok(payload)
                } else {
                    if result.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "get area information result must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(GET_AREA_INFORMATION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::GetNodeProperty {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "get node property result is missing on success".into(),
                        )
                    })?;
                    if result.node_properties.is_empty()
                        || result.node_properties.len() > MAX_NODE_PROPERTY_CODES
                    {
                        return Err(FelicaStandardError::Protocol(
                            "get node property count out of range".into(),
                        ));
                    }
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
                    let property_payload_len = result
                        .node_properties
                        .iter()
                        .map(|property| (*property).size_bytes())
                        .sum::<usize>();
                    let mut payload =
                        Vec::with_capacity(1 + IDM_LEN + 2 + 1 + property_payload_len);
                    payload.push(GET_NODE_PROPERTY_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    payload.push(result.node_properties.len() as u8);
                    for property in &result.node_properties {
                        payload.extend_from_slice(&(*property).to_bytes());
                    }
                    Ok(payload)
                } else {
                    if result.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "get node property result must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(GET_NODE_PROPERTY_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::GetContainerProperty { data } => {
                if data.is_empty() {
                    return Err(FelicaStandardError::Protocol(
                        "get container property response data must contain at least one byte"
                            .into(),
                    ));
                }
                let mut payload = Vec::with_capacity(1 + data.len());
                payload.push(GET_CONTAINER_PROPERTY_RESPONSE_CODE);
                payload.extend_from_slice(data);
                Ok(payload)
            }
            FelicaStandardResponse::RequestServiceV2 {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                let kv_len = result
                    .as_ref()
                    .map(|value| value.key_versions.len())
                    .unwrap_or(0);
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 4 + kv_len * 4);
                payload.push(REQUEST_SERVICE_V2_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "request service v2 result is missing on success".into(),
                        )
                    })?;
                    let crypto_id = result.crypto_id;
                    let key_versions = &result.key_versions;
                    if key_versions.is_empty() || key_versions.len() > MAX_SERVICE_CODES {
                        return Err(FelicaStandardError::Protocol(
                            "request service v2 key version count out of range".into(),
                        ));
                    }
                    payload.push(crypto_id);
                    payload.push(key_versions.len() as u8);
                    if matches!(crypto_id, 0x41 | 0x43) {
                        let mut secondary_versions = Vec::with_capacity(key_versions.len());
                        for version in key_versions {
                            let secondary = version.secondary_raw().ok_or_else(|| {
                                FelicaStandardError::Protocol(
                                    "request service v2 dual crypto requires dual key versions"
                                        .into(),
                                )
                            })?;
                            payload.extend_from_slice(&version.primary_raw().to_le_bytes());
                            secondary_versions.push(secondary);
                        }
                        for secondary in secondary_versions {
                            payload.extend_from_slice(&secondary.to_le_bytes());
                        }
                    } else {
                        for version in key_versions {
                            if version.secondary_raw().is_some() {
                                return Err(FelicaStandardError::Protocol(
                                    "request service v2 single crypto requires single key versions"
                                        .into(),
                                ));
                            }
                            payload.extend_from_slice(&version.primary_raw().to_le_bytes());
                        }
                    }
                } else if result.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "request service v2 result must be omitted on error".into(),
                    ));
                }
                Ok(payload)
            }
            FelicaStandardResponse::GetSystemStatus {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if result.data.len() > u8::MAX as usize {
                    return Err(FelicaStandardError::Protocol(
                        "get system status response data length out of range".into(),
                    ));
                }
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 2 + 1 + 1 + result.data.len());
                payload.push(GET_SYSTEM_STATUS_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                payload.push(result.flag);
                payload.push(result.data.len() as u8);
                payload.extend_from_slice(&result.data);
                Ok(payload)
            }
            FelicaStandardResponse::RequestProductInformation {
                idm,
                status_flag1,
                status_flag2,
                result,
            } => {
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "request product information result is missing on success".into(),
                        )
                    })?;
                    if result.len() > u8::MAX as usize {
                        return Err(FelicaStandardError::Protocol(
                            "request product information response data length out of range".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2 + 1 + result.len());
                    payload.push(REQUEST_PRODUCT_INFORMATION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    payload.push(result.len() as u8);
                    payload.extend_from_slice(result);
                    Ok(payload)
                } else {
                    if result.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "request product information result must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(REQUEST_PRODUCT_INFORMATION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::RequestSpecificationVersion {
                idm,
                status_flag1,
                status_flag2,
                specification_version,
            } => {
                if *status_flag1 == 0 {
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2 + 16);
                    payload.push(REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    if let Some(specification_version) = specification_version {
                        if specification_version.format_version != 0x00 {
                            return Err(FelicaStandardError::Protocol(
                                "request specification version format version must be 0x00".into(),
                            ));
                        }
                        if specification_version.option_versions.len() > u8::MAX as usize {
                            return Err(FelicaStandardError::Protocol(
                                "request specification version option count out of range".into(),
                            ));
                        }
                        payload.extend_from_slice(&specification_version.to_bytes());
                    }
                    Ok(payload)
                } else {
                    if specification_version.is_some() {
                        return Err(FelicaStandardError::Protocol(
                            "request specification version payload must be omitted on error".into(),
                        ));
                    }
                    let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                    payload.push(REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE);
                    payload.extend_from_slice(idm);
                    payload.push(*status_flag1);
                    payload.push(*status_flag2);
                    Ok(payload)
                }
            }
            FelicaStandardResponse::ResetMode {
                idm,
                status_flag1,
                status_flag2,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 2);
                payload.push(RESET_MODE_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                Ok(payload)
            }
            FelicaStandardResponse::Authentication1V2 {
                idm,
                challenge_1b,
                challenge_2a,
                challenge_3c,
            } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN + 36);
                payload.push(AUTHENTICATION1_V2_RESPONSE_CODE);
                payload.extend_from_slice(idm);
                payload.extend_from_slice(challenge_1b);
                payload.extend_from_slice(challenge_2a);
                payload.extend_from_slice(challenge_3c);
                Ok(payload)
            }
            FelicaStandardResponse::Authentication2V2(auth) => {
                let mut payload = Vec::with_capacity(1 + auth.encrypted_payload.len());
                payload.push(AUTHENTICATION2_V2_RESPONSE_CODE);
                payload.extend_from_slice(&auth.encrypted_payload);
                Ok(payload)
            }
            FelicaStandardResponse::GetContainerId { container_idm } => {
                let mut payload = Vec::with_capacity(1 + IDM_LEN);
                payload.push(GET_CONTAINER_ID_RESPONSE_CODE);
                payload.extend_from_slice(container_idm);
                Ok(payload)
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
                let block_len = result.as_ref().map(|value| value.blocks.len()).unwrap_or(0);
                let mut payload = Vec::with_capacity(2 + 1 + block_len * BLOCK_SIZE);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "secure read result is missing on success".into(),
                        )
                    })?;
                    let blocks = &result.blocks;
                    if blocks.is_empty() || blocks.len() > MAX_BLOCK_COUNT {
                        return Err(FelicaStandardError::Protocol(
                            "secure read block count out of range".into(),
                        ));
                    }
                    payload.push(blocks.len() as u8);
                    for block in blocks {
                        payload.extend_from_slice(block);
                    }
                } else if result.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "secure read result must be omitted on error".into(),
                    ));
                }
                Ok(payload)
            }
            FelicaStandardResponse::Write {
                status_flag1,
                status_flag2,
            }
            | FelicaStandardResponse::WriteV2 {
                status_flag1,
                status_flag2,
            } => Ok(vec![*status_flag1, *status_flag2]),
            FelicaStandardResponse::RegisterIssueId {
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload = Vec::with_capacity(4);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "register issue id result is missing on success".into(),
                        )
                    })?;
                    payload.extend_from_slice(&result.remaining_blocks.to_le_bytes());
                } else if result.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "register issue id result must be omitted on error".into(),
                    ));
                }
                Ok(payload)
            }
            FelicaStandardResponse::RegisterArea {
                status_flag1,
                status_flag2,
            } => Ok(vec![*status_flag1, *status_flag2]),
            FelicaStandardResponse::RegisterService {
                status_flag1,
                status_flag2,
                result,
            } => {
                let mut payload = Vec::with_capacity(4);
                payload.push(*status_flag1);
                payload.push(*status_flag2);
                if *status_flag1 == 0 {
                    let result = result.as_ref().ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "register service result is missing on success".into(),
                        )
                    })?;
                    payload.extend_from_slice(&result.remaining_blocks.to_le_bytes());
                } else if result.is_some() {
                    return Err(FelicaStandardError::Protocol(
                        "register service result must be omitted on error".into(),
                    ));
                }
                Ok(payload)
            }
            FelicaStandardResponse::ChangeSystemBlock {
                status_flag1,
                status_flag2,
            } => Ok(vec![*status_flag1, *status_flag2]),
            _ => Err(FelicaStandardError::Protocol(
                "plain response cannot be encoded as secure payload".into(),
            )),
        }
    }
}
