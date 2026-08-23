use super::*;

/// Offset of the IDm in an addressed response, behind the length byte and the
/// response code.
const IDM_OFFSET: usize = 2;
/// First byte behind the IDm: where a response's own fields begin, and where
/// the responses that report an outcome put status flag 1.
const PAYLOAD_OFFSET: usize = IDM_OFFSET + IDM_LEN;

impl FelicaStandardResponse {
    /// Parses a complete length-prefixed response received from a card.
    ///
    /// Packet length, fixed-size fields, item counts, status-dependent fields,
    /// and response-code-specific structure are validated. Unknown response
    /// codes are represented by [`FelicaStandardResponse::Unknown`]. Secure
    /// inner responses must first be decrypted by an authenticated session.
    pub fn from_bytes(data: &[u8]) -> DriverResult<FelicaStandardResponse> {
        Self::ensure_response_len(data, 2, "short Felica response")?;
        let expected_len = data[0] as usize;
        if expected_len != data.len() {
            return Err(DriverError::Other(
                "length byte does not match response length".into(),
            ));
        }
        let code = data[1];
        if code == AUTHENTICATION2_RESPONSE_CODE {
            return Self::parse_authentication2(data);
        }
        if code == GET_CONTAINER_PROPERTY_RESPONSE_CODE {
            return Self::parse_get_container_property(data);
        }
        if code == AUTHENTICATION2_V2_RESPONSE_CODE {
            return Self::parse_authentication2_v2(data);
        }
        Self::ensure_response_len(data, PAYLOAD_OFFSET, "short Felica response")?;
        let (idm, _rest) = parse_idm(&data[IDM_OFFSET..])?;
        match code {
            POLLING_RESPONSE_CODE => Self::parse_polling(idm, data),
            REQUEST_SERVICE_RESPONSE_CODE => Self::parse_request_service(idm, data),
            REQUEST_RESPONSE_RESPONSE_CODE => Self::parse_request_response(idm, data),
            READ_WITHOUT_ENCRYPTION_RESPONSE_CODE => Self::parse_read_without_encryption(idm, data),
            WRITE_WITHOUT_ENCRYPTION_RESPONSE_CODE => {
                Self::parse_write_without_encryption(idm, data)
            }
            SEARCH_SERVICE_CODE_RESPONSE_CODE => Self::parse_search_service_code(idm, data),
            REQUEST_SYSTEM_CODE_RESPONSE_CODE => Self::parse_request_systemcode(idm, data),
            REQUEST_BLOCK_INFORMATION_RESPONSE_CODE => {
                Self::parse_request_block_information(idm, data)
            }
            AUTHENTICATION1_RESPONSE_CODE => Self::parse_authentication1(idm, data),
            REQUEST_CODE_LIST_RESPONSE_CODE => Self::parse_request_code_list(idm, data),
            REQUEST_BLOCK_INFORMATION_EX_RESPONSE_CODE => {
                Self::parse_request_block_information_ex(idm, data)
            }
            SET_PARAMETER_RESPONSE_CODE => Self::parse_set_parameter(idm, data),
            GET_CONTAINER_ISSUE_INFORMATION_RESPONSE_CODE => {
                Self::parse_get_container_issue_information(idm, data)
            }
            GET_AREA_INFORMATION_RESPONSE_CODE => Self::parse_get_area_information(idm, data),
            GET_NODE_PROPERTY_RESPONSE_CODE => Self::parse_get_node_property(idm, data),
            REQUEST_SERVICE_V2_RESPONSE_CODE => Self::parse_request_service_v2(idm, data),
            GET_SYSTEM_STATUS_RESPONSE_CODE => Self::parse_get_system_status(idm, data),
            REQUEST_PRODUCT_INFORMATION_RESPONSE_CODE => {
                Self::parse_request_product_information(idm, data)
            }
            REQUEST_SPECIFICATION_VERSION_RESPONSE_CODE => {
                Self::parse_request_specification_version(idm, data)
            }
            RESET_MODE_RESPONSE_CODE => Self::parse_reset_mode(idm, data),
            AUTHENTICATION1_V2_RESPONSE_CODE => Self::parse_authentication1_v2(idm, data),
            GET_CONTAINER_ID_RESPONSE_CODE => Self::parse_get_container_id(idm, data),
            _ => Ok(FelicaStandardResponse::Unknown),
        }
    }

    pub(crate) fn from_secure_bytes(
        command_code: u8,
        data: &[u8],
    ) -> DriverResult<FelicaStandardResponse> {
        match command_code {
            READ_COMMAND_CODE => Self::parse_secure_read(data, false),
            READ_V2_COMMAND_CODE => Self::parse_secure_read(data, true),
            WRITE_COMMAND_CODE => Self::parse_secure_write(data, false),
            WRITE_V2_COMMAND_CODE => Self::parse_secure_write(data, true),
            REGISTER_ISSUE_ID_COMMAND_CODE => Self::parse_register_issue_id(data),
            REGISTER_AREA_COMMAND_CODE => Self::parse_register_area(data),
            REGISTER_SERVICE_COMMAND_CODE => Self::parse_register_service(data),
            CHANGE_SYSTEM_BLOCK_COMMAND_CODE => Self::parse_change_system_block(data),
            _ => Err(DriverError::Other(
                "unsupported secure Felica command response".into(),
            )),
        }
    }

    fn parse_authentication2(data: &[u8]) -> DriverResult<Self> {
        Self::ensure_exact_response_len(
            data,
            34,
            "authentication2 response must contain exactly 32 encrypted bytes",
        )?;
        Ok(FelicaStandardResponse::Authentication2(
            Authentication2Response {
                encrypted_payload: data[IDM_OFFSET..].to_vec(),
            },
        ))
    }

    fn parse_authentication2_v2(data: &[u8]) -> DriverResult<Self> {
        Self::ensure_exact_response_len(
            data,
            28,
            "authentication2 v2 response must contain a transaction number, 16 encrypted bytes and an 8-byte MAC",
        )?;
        Ok(FelicaStandardResponse::Authentication2V2(
            Authentication2V2Response {
                encrypted_payload: data[IDM_OFFSET..].to_vec(),
            },
        ))
    }

    fn parse_polling(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 18, "short polling response")?;
        if !matches!(data.len(), 18 | 20) {
            return Err(DriverError::Other(
                "polling response optional data must contain 0 or 2 bytes".into(),
            ));
        }
        let (pmm, _rest) = parse_pmm(&data[10..])?;
        Ok(FelicaStandardResponse::Polling {
            idm,
            pmm,
            optional: data.get(18..).unwrap_or(&[]).to_vec(),
        })
    }

    fn parse_request_service(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 11, "short request service response")?;
        let node_count = data[10] as usize;
        if node_count == 0 || node_count > MAX_SERVICE_CODES {
            return Err(DriverError::Other(
                "request service node count must be between 1 and 32".into(),
            ));
        }
        let expected_len = 11 + node_count * 2;
        Self::ensure_exact_response_len(
            data,
            expected_len,
            "request service response length does not match node count",
        )?;
        let mut key_versions = Vec::with_capacity(node_count);
        for chunk in data[11..11 + node_count * 2].as_chunks::<2>().0 {
            key_versions.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        Ok(FelicaStandardResponse::RequestService { idm, key_versions })
    }

    fn parse_request_service_v2(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        let (status_flag1, status_flag2) =
            Self::status_flags(data, "short request service v2 response header")?;
        let mut result = None;

        if status_flag1 == 0 {
            Self::ensure_response_len(
                data,
                14,
                "short request service v2 crypto identifier response",
            )?;
            let parsed_crypto_id = data[12];
            if !matches!(parsed_crypto_id, 0x4F | 0x41 | 0x43) {
                return Err(DriverError::Other(
                    "request service v2 crypto identifier must be 0x4F, 0x41 or 0x43".into(),
                ));
            }
            let node_count = data[13] as usize;
            if node_count == 0 || node_count > MAX_SERVICE_CODES {
                return Err(DriverError::Other(
                    "request service v2 node count must be between 1 and 32".into(),
                ));
            }
            let payload = &data[14..];
            let mut parsed_versions = Vec::with_capacity(node_count);
            if matches!(parsed_crypto_id, 0x41 | 0x43) {
                let expected = node_count * 4;
                Self::ensure_exact_response_len(
                    data,
                    14 + expected,
                    "request service v2 response length does not match dual key version count",
                )?;
                for i in 0..node_count {
                    let aes_offset = i * 2;
                    let des_offset = node_count * 2 + aes_offset;
                    let aes = u16::from_le_bytes([payload[aes_offset], payload[aes_offset + 1]]);
                    let des = u16::from_le_bytes([payload[des_offset], payload[des_offset + 1]]);
                    parsed_versions.push(RequestServiceV2KeyVersion::Dual { aes, des });
                }
            } else {
                let expected = node_count * 2;
                Self::ensure_exact_response_len(
                    data,
                    14 + expected,
                    "request service v2 response length does not match key version count",
                )?;
                for chunk in payload[..expected].as_chunks::<2>().0 {
                    parsed_versions.push(RequestServiceV2KeyVersion::Single(u16::from_le_bytes([
                        chunk[0], chunk[1],
                    ])));
                }
            }
            result = Some(RequestServiceV2Result {
                crypto_id: parsed_crypto_id,
                key_versions: parsed_versions,
            });
        } else {
            Self::ensure_exact_response_len(
                data,
                12,
                "request service v2 error response must contain only status flags",
            )?;
        }

        Ok(FelicaStandardResponse::RequestServiceV2 {
            idm,
            status_flag1,
            status_flag2,
            result,
        })
    }

    fn parse_request_response(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_exact_response_len(
            data,
            11,
            "request response must contain exactly one mode byte",
        )?;
        Ok(FelicaStandardResponse::RequestResponse {
            idm,
            mode: data[10],
        })
    }

    fn parse_read_without_encryption(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        let (sf1, sf2) = Self::status_flags(data, "short read without encryption response")?;
        if sf1 != 0 {
            Self::ensure_exact_response_len(
                data,
                12,
                "read without encryption error response must contain only status flags",
            )?;
            return Ok(FelicaStandardResponse::ReadWithoutEncryption {
                idm,
                status_flag1: sf1,
                status_flag2: sf2,
                result: None,
            });
        }
        Self::ensure_response_len(data, 13, "short read without encryption success response")?;
        let block_count = data[12] as usize;
        if block_count == 0 || block_count > MAX_BLOCK_COUNT {
            return Err(DriverError::Other(
                "read without encryption block count must be between 1 and 255".into(),
            ));
        }
        let expected_len = 13 + block_count * BLOCK_SIZE;
        Self::ensure_exact_response_len(
            data,
            expected_len,
            "read without encryption response length does not match block count",
        )?;
        let blocks = collect_blocks(&data[13..13 + block_count * BLOCK_SIZE], block_count);
        Ok(FelicaStandardResponse::ReadWithoutEncryption {
            idm,
            status_flag1: sf1,
            status_flag2: sf2,
            result: Some(ReadWithoutEncryptionResult { blocks }),
        })
    }

    fn parse_write_without_encryption(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        let (sf1, sf2) = Self::status_flags(data, "short write without encryption response")?;
        Self::ensure_exact_response_len(
            data,
            12,
            "write without encryption response must contain only status flags",
        )?;
        Ok(FelicaStandardResponse::WriteWithoutEncryption {
            idm,
            status_flag1: sf1,
            status_flag2: sf2,
        })
    }

    fn parse_search_service_code(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short search service code response")?;
        let payload = &data[10..];
        let result = if payload == [0xFF, 0xFF] {
            None
        } else if payload.len() == 2 {
            Some(SearchServiceCodeResult::Service(ServiceCode::new(
                u16::from_le_bytes([payload[0], payload[1]]),
            )))
        } else if payload.len() == 4 {
            Some(SearchServiceCodeResult::Area {
                area_code: u16::from_le_bytes([payload[0], payload[1]]),
                end_service_code: u16::from_le_bytes([payload[2], payload[3]]),
            })
        } else {
            return Err(DriverError::Other(
                "search service code response must contain 2 or 4 bytes".into(),
            ));
        };
        Ok(FelicaStandardResponse::SearchServiceCode { idm, result })
    }

    fn parse_request_systemcode(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short request system code response")?;
        let count = data[10] as usize;
        if count == 0 {
            return Err(DriverError::Other(
                "request system code response count must be at least 1".into(),
            ));
        }
        let expected_len = 11 + count * 2;
        Self::ensure_exact_response_len(
            data,
            expected_len,
            "request system code response length does not match count",
        )?;
        let mut system_codes = Vec::with_capacity(count);
        for chunk in data[11..11 + count * 2].as_chunks::<2>().0 {
            system_codes.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        Ok(FelicaStandardResponse::RequestSystemCode { idm, system_codes })
    }

    fn parse_request_block_information(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 12, "short request block information response")?;
        let count = data[10] as usize;
        if count == 0 {
            return Err(DriverError::Other(
                "request block information count must be at least 1".into(),
            ));
        }
        let expected_len = 11 + count * 2;
        Self::ensure_exact_response_len(
            data,
            expected_len,
            "request block information response length does not match count",
        )?;
        let mut block_counts = Vec::with_capacity(count);
        for chunk in data[11..11 + count * 2].as_chunks::<2>().0 {
            block_counts.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        Ok(FelicaStandardResponse::RequestBlockInformation { idm, block_counts })
    }

    fn parse_request_block_information_ex(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        let (status_flag1, status_flag2) =
            Self::status_flags(data, "short request block information ex response")?;
        if status_flag1 != 0 {
            Self::ensure_exact_response_len(
                data,
                12,
                "request block information ex error response must contain only status flags",
            )?;
            return Ok(FelicaStandardResponse::RequestBlockInformationEx {
                idm,
                status_flag1,
                status_flag2,
                result: None,
            });
        }

        Self::ensure_response_len(
            data,
            13,
            "short request block information ex success response",
        )?;
        let count = data[12] as usize;
        if count == 0 || count > MAX_NODE_CODES {
            return Err(DriverError::Other(
                "request block information ex count must be between 1 and 32".into(),
            ));
        }

        let expected_len = 13 + count * 4;
        Self::ensure_exact_response_len(
            data,
            expected_len,
            "request block information ex response length does not match count",
        )?;
        let mut assigned_block_counts = Vec::with_capacity(count);
        let mut free_block_counts = Vec::with_capacity(count);
        for chunk in data[13..13 + count * 4].as_chunks::<4>().0 {
            assigned_block_counts.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            free_block_counts.push(u16::from_le_bytes([chunk[2], chunk[3]]));
        }

        Ok(FelicaStandardResponse::RequestBlockInformationEx {
            idm,
            status_flag1,
            status_flag2,
            result: Some(RequestBlockInformationExResult {
                assigned_block_counts,
                free_block_counts,
            }),
        })
    }

    fn parse_request_code_list(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        let (status_flag1, status_flag2) =
            Self::status_flags(data, "short request code list response")?;
        if status_flag1 != 0 {
            Self::ensure_exact_response_len(
                data,
                12,
                "request code list error response must contain only status flags",
            )?;
            return Ok(FelicaStandardResponse::RequestCodeList {
                idm,
                status_flag1,
                status_flag2,
                result: None,
            });
        }

        Self::ensure_response_len(data, 15, "short request code list success response")?;
        let continue_flag = data[12] != 0;

        let area_count = data[13] as usize;
        let mut offset = 14usize;
        let area_payload_len = area_count.checked_mul(4).ok_or_else(|| {
            DriverError::Other("request code list area payload length overflow".into())
        })?;
        Self::ensure_response_len(
            data,
            offset + area_payload_len + 1,
            "short request code list area payload",
        )?;

        let mut areas = Vec::with_capacity(area_count);
        for chunk in data[offset..offset + area_payload_len].as_chunks::<4>().0 {
            areas.push(AreaCodeRange {
                area_code: u16::from_le_bytes([chunk[0], chunk[1]]),
                end_service_code: u16::from_le_bytes([chunk[2], chunk[3]]),
            });
        }
        offset += area_payload_len;

        let service_count = data[offset] as usize;
        offset += 1;
        let service_payload_len = service_count.checked_mul(2).ok_or_else(|| {
            DriverError::Other("request code list service payload length overflow".into())
        })?;
        Self::ensure_response_len(
            data,
            offset + service_payload_len,
            "short request code list service payload",
        )?;
        Self::ensure_exact_response_len(
            data,
            offset + service_payload_len,
            "request code list response length does not match its counts",
        )?;

        let mut services = Vec::with_capacity(service_count);
        for chunk in data[offset..offset + service_payload_len]
            .as_chunks::<2>()
            .0
        {
            services.push(ServiceCode::new(u16::from_le_bytes([chunk[0], chunk[1]])));
        }

        Ok(FelicaStandardResponse::RequestCodeList {
            idm,
            status_flag1,
            status_flag2,
            result: Some(RequestCodeListResult {
                continue_flag,
                areas,
                services,
            }),
        })
    }

    fn parse_set_parameter(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        let (status_flag1, status_flag2) =
            Self::status_flags(data, "short set parameter response")?;
        Self::ensure_exact_response_len(
            data,
            12,
            "set parameter response must contain only status flags",
        )?;
        Ok(FelicaStandardResponse::SetParameter {
            idm,
            status_flag1,
            status_flag2,
        })
    }

    fn parse_get_container_issue_information(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_exact_response_len(
            data,
            26,
            "get container issue information response must contain exactly 16 data bytes",
        )?;
        let mut format_version_carrier_information = [0u8; 5];
        format_version_carrier_information.copy_from_slice(&data[10..15]);
        let mut mobile_phone_model_information = [0u8; 11];
        mobile_phone_model_information.copy_from_slice(&data[15..26]);
        Ok(FelicaStandardResponse::GetContainerIssueInformation {
            idm,
            container_information: ContainerInformation {
                format_version_carrier_information,
                mobile_phone_model_information,
            },
        })
    }

    fn parse_get_container_property(data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 3, "short get container property response")?;
        let payload = data[IDM_OFFSET..].to_vec();
        if payload.is_empty() {
            return Err(DriverError::Other(
                "get container property response data must contain at least one byte".into(),
            ));
        }
        Ok(FelicaStandardResponse::GetContainerProperty { data: payload })
    }

    fn parse_get_container_id(container_idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_exact_response_len(
            data,
            PAYLOAD_OFFSET,
            "get container id response must contain exactly one IDm",
        )?;
        Ok(FelicaStandardResponse::GetContainerId { container_idm })
    }

    fn parse_get_area_information(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        let (status_flag1, status_flag2) =
            Self::status_flags(data, "short get area information response")?;
        if status_flag1 != 0 {
            Self::ensure_exact_response_len(
                data,
                12,
                "get area information error response must contain only status flags",
            )?;
            return Ok(FelicaStandardResponse::GetAreaInformation {
                idm,
                status_flag1,
                status_flag2,
                result: None,
            });
        }
        Self::ensure_exact_response_len(
            data,
            16,
            "get area information success response must contain exactly four result bytes",
        )?;
        Ok(FelicaStandardResponse::GetAreaInformation {
            idm,
            status_flag1,
            status_flag2,
            result: Some(GetAreaInformationResult {
                node_code: u16::from_le_bytes([data[12], data[13]]),
                data: [data[14], data[15]],
            }),
        })
    }

    fn parse_get_node_property(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        let (status_flag1, status_flag2) =
            Self::status_flags(data, "short get node property response")?;
        if status_flag1 != 0 {
            Self::ensure_exact_response_len(
                data,
                12,
                "get node property error response must contain only status flags",
            )?;
            return Ok(FelicaStandardResponse::GetNodeProperty {
                idm,
                status_flag1,
                status_flag2,
                result: None,
            });
        }

        Self::ensure_response_len(data, 13, "short get node property success response")?;
        let node_count = data[12] as usize;
        if node_count == 0 || node_count > MAX_NODE_PROPERTY_CODES {
            return Err(DriverError::Other(
                "get node property node count must be between 1 and 16".into(),
            ));
        }

        let payload = &data[13..];
        let value_limited_len = node_count.checked_mul(10).ok_or_else(|| {
            DriverError::Other("get node property value-limited payload length overflow".into())
        })?;
        let mac_communication_len = node_count;

        let node_properties = if payload.len() == value_limited_len {
            let mut properties = Vec::with_capacity(node_count);
            for chunk in payload.as_chunks::<10>().0 {
                properties.push(NodeProperty::ValueLimitedPurseService {
                    enabled: chunk[0] == 0x01,
                    upper_limit: i32::from_le_bytes([chunk[1], chunk[2], chunk[3], chunk[4]]),
                    lower_limit: i32::from_le_bytes([chunk[5], chunk[6], chunk[7], chunk[8]]),
                    generation_number: chunk[9],
                });
            }
            properties
        } else if payload.len() == mac_communication_len {
            payload
                .iter()
                .map(|value| NodeProperty::MacCommunication {
                    enabled: *value == 0x01,
                })
                .collect()
        } else {
            return Err(DriverError::Other(
                "get node property payload length does not match known node property format".into(),
            ));
        };

        Ok(FelicaStandardResponse::GetNodeProperty {
            idm,
            status_flag1,
            status_flag2,
            result: Some(GetNodePropertyResult { node_properties }),
        })
    }

    fn parse_get_system_status(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_response_len(data, 14, "short get system status response")?;
        let status_flag1 = data[PAYLOAD_OFFSET];
        let status_flag2 = data[PAYLOAD_OFFSET + 1];
        let flag = data[12];
        let data_len = data[13] as usize;
        Self::ensure_exact_response_len(
            data,
            14 + data_len,
            "get system status response length does not match data length",
        )?;
        Ok(FelicaStandardResponse::GetSystemStatus {
            idm,
            status_flag1,
            status_flag2,
            result: GetSystemStatusResult {
                flag,
                data: data[14..14 + data_len].to_vec(),
            },
        })
    }

    fn parse_request_product_information(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        let (status_flag1, status_flag2) =
            Self::status_flags(data, "short request product information response")?;
        if status_flag1 != 0 {
            Self::ensure_exact_response_len(
                data,
                12,
                "request product information error response must contain only status flags",
            )?;
            return Ok(FelicaStandardResponse::RequestProductInformation {
                idm,
                status_flag1,
                status_flag2,
                result: None,
            });
        }

        Self::ensure_response_len(
            data,
            13,
            "short request product information success response",
        )?;
        let data_len = data[12] as usize;
        Self::ensure_exact_response_len(
            data,
            13 + data_len,
            "request product information response length does not match data length",
        )?;
        Ok(FelicaStandardResponse::RequestProductInformation {
            idm,
            status_flag1,
            status_flag2,
            result: Some(data[13..13 + data_len].to_vec()),
        })
    }

    fn parse_request_specification_version(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        let (status_flag1, status_flag2) =
            Self::status_flags(data, "short request specification version response")?;
        let specification_version = if status_flag1 == 0 {
            Some(parse_specification_version_data(&data[12..])?)
        } else {
            Self::ensure_exact_response_len(
                data,
                12,
                "request specification version error response must contain only status flags",
            )?;
            None
        };
        Ok(FelicaStandardResponse::RequestSpecificationVersion {
            idm,
            status_flag1,
            status_flag2,
            specification_version,
        })
    }

    fn parse_reset_mode(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        let (status_flag1, status_flag2) = Self::status_flags(data, "short reset mode response")?;
        Self::ensure_exact_response_len(
            data,
            12,
            "reset mode response must contain only status flags",
        )?;
        Ok(FelicaStandardResponse::ResetMode {
            idm,
            status_flag1,
            status_flag2,
        })
    }

    fn parse_authentication1(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_exact_response_len(
            data,
            26,
            "authentication1 response must contain exactly two 8-byte challenges",
        )?;
        let mut challenge_1b = [0u8; 8];
        challenge_1b.copy_from_slice(&data[10..18]);
        let mut challenge_2a = [0u8; 8];
        challenge_2a.copy_from_slice(&data[18..26]);
        Ok(FelicaStandardResponse::Authentication1 {
            idm,
            challenge_1b,
            challenge_2a,
        })
    }

    fn parse_secure_read(data: &[u8], read_v2: bool) -> DriverResult<Self> {
        if data.len() < 2 {
            return Err(DriverError::Other(
                "encrypted read response shorter than status flags".into(),
            ));
        }
        let sf1 = data[0];
        let sf2 = data[1];
        if sf1 != 0 {
            return Ok(if read_v2 {
                FelicaStandardResponse::ReadV2 {
                    status_flag1: sf1,
                    status_flag2: sf2,
                    result: None,
                }
            } else {
                FelicaStandardResponse::Read {
                    status_flag1: sf1,
                    status_flag2: sf2,
                    result: None,
                }
            });
        }
        if data.len() < 3 {
            return Err(DriverError::Other(
                "successful encrypted read response missing block count".into(),
            ));
        }
        let block_count = data[2] as usize;
        if block_count == 0 || block_count > MAX_BLOCK_COUNT {
            return Err(DriverError::Other(
                "encrypted read response block count must be between 1 and 255".into(),
            ));
        }
        let expected_len = 3 + block_count * BLOCK_SIZE;
        if data.len() < expected_len {
            return Err(DriverError::Other(
                "encrypted read response truncated before block data".into(),
            ));
        }
        let blocks = collect_blocks(&data[3..3 + block_count * BLOCK_SIZE], block_count);
        Ok(if read_v2 {
            FelicaStandardResponse::ReadV2 {
                status_flag1: sf1,
                status_flag2: sf2,
                result: Some(ReadResult { blocks }),
            }
        } else {
            FelicaStandardResponse::Read {
                status_flag1: sf1,
                status_flag2: sf2,
                result: Some(ReadResult { blocks }),
            }
        })
    }

    fn parse_secure_write(data: &[u8], write_v2: bool) -> DriverResult<Self> {
        if data.len() < 2 {
            return Err(DriverError::Other(
                "encrypted write response shorter than status flags".into(),
            ));
        }
        Ok(if write_v2 {
            FelicaStandardResponse::WriteV2 {
                status_flag1: data[0],
                status_flag2: data[1],
            }
        } else {
            FelicaStandardResponse::Write {
                status_flag1: data[0],
                status_flag2: data[1],
            }
        })
    }

    fn parse_register_issue_id(data: &[u8]) -> DriverResult<Self> {
        if data.len() < 2 {
            return Err(DriverError::Other(
                "register issue id response shorter than status flags".into(),
            ));
        }
        let status_flag1 = data[0];
        let status_flag2 = data[1];
        let result = if status_flag1 == 0 {
            if data.len() < 4 {
                return Err(DriverError::Other(
                    "register issue id response missing remaining block count".into(),
                ));
            }
            Some(RegisterIssueIdResult {
                remaining_blocks: u16::from_le_bytes([data[2], data[3]]),
            })
        } else {
            None
        };
        Ok(FelicaStandardResponse::RegisterIssueId {
            status_flag1,
            status_flag2,
            result,
        })
    }

    fn parse_register_area(data: &[u8]) -> DriverResult<Self> {
        if data.len() < 2 {
            return Err(DriverError::Other(
                "register area response shorter than status flags".into(),
            ));
        }
        Ok(FelicaStandardResponse::RegisterArea {
            status_flag1: data[0],
            status_flag2: data[1],
        })
    }

    fn parse_register_service(data: &[u8]) -> DriverResult<Self> {
        if data.len() < 2 {
            return Err(DriverError::Other(
                "register service response shorter than status flags".into(),
            ));
        }
        let status_flag1 = data[0];
        let status_flag2 = data[1];
        let result = if status_flag1 == 0 {
            if data.len() < 4 {
                return Err(DriverError::Other(
                    "register service response missing remaining block count".into(),
                ));
            }
            Some(RegisterServiceResult {
                remaining_blocks: u16::from_le_bytes([data[2], data[3]]),
            })
        } else {
            None
        };
        Ok(FelicaStandardResponse::RegisterService {
            status_flag1,
            status_flag2,
            result,
        })
    }

    fn parse_change_system_block(data: &[u8]) -> DriverResult<Self> {
        if data.len() < 2 {
            return Err(DriverError::Other(
                "commit registration response shorter than status flags".into(),
            ));
        }
        Ok(FelicaStandardResponse::ChangeSystemBlock {
            status_flag1: data[0],
            status_flag2: data[1],
        })
    }

    fn parse_authentication1_v2(idm: Idm, data: &[u8]) -> DriverResult<Self> {
        Self::ensure_exact_response_len(
            data,
            46,
            "authentication1 v2 response must contain exactly two 16-byte challenges and challenge3c",
        )?;
        let mut challenge_1b = [0u8; 16];
        challenge_1b.copy_from_slice(&data[10..26]);
        let mut challenge_2a = [0u8; 16];
        challenge_2a.copy_from_slice(&data[26..42]);
        let mut challenge_3c = [0u8; 4];
        challenge_3c.copy_from_slice(&data[42..46]);
        Ok(FelicaStandardResponse::Authentication1V2 {
            idm,
            challenge_1b,
            challenge_2a,
            challenge_3c,
        })
    }

    /// Reads the two status flags an addressed response reports its outcome
    /// with, having checked that the response is long enough to hold them.
    fn status_flags(data: &[u8], message: &str) -> DriverResult<(u8, u8)> {
        Self::ensure_response_len(data, PAYLOAD_OFFSET + 2, message)?;
        Ok((data[PAYLOAD_OFFSET], data[PAYLOAD_OFFSET + 1]))
    }

    fn ensure_response_len(data: &[u8], required: usize, message: &str) -> DriverResult<()> {
        if data.len() < required {
            Err(DriverError::Other(message.into()))
        } else {
            Ok(())
        }
    }

    fn ensure_exact_response_len(data: &[u8], expected: usize, message: &str) -> DriverResult<()> {
        if data.len() == expected {
            Ok(())
        } else {
            Err(DriverError::Other(message.into()))
        }
    }
}

fn parse_fixed<'a, const N: usize>(
    data: &'a [u8],
    label: &str,
) -> DriverResult<([u8; N], &'a [u8])> {
    if data.len() < N {
        return Err(DriverError::Other(format!("{label} payload too short")));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&data[..N]);
    Ok((out, &data[N..]))
}

fn parse_specification_version_data(data: &[u8]) -> DriverResult<SpecificationVersion> {
    if data.len() < 4 {
        return Err(DriverError::Other(
            "request specification version payload too short".into(),
        ));
    }
    let format_version = data[0];
    if format_version != 0x00 {
        return Err(DriverError::Other(
            "request specification version format version must be 0x00".into(),
        ));
    }
    let basic_version = OptionVersion::from_le_bytes([data[1], data[2]]).ok_or_else(|| {
        DriverError::Other(
            "request specification version basic version is not valid packed BCD".into(),
        )
    })?;
    let option_count = data[3] as usize;
    let option_bytes_len = option_count.checked_mul(2).ok_or_else(|| {
        DriverError::Other("request specification version option bytes length overflow".into())
    })?;
    if data.len() != 4 + option_bytes_len {
        return Err(DriverError::Other(
            "request specification version payload length does not match option count".into(),
        ));
    }
    let mut option_versions = Vec::with_capacity(option_count);
    let option_bytes = &data[4..4 + option_bytes_len];
    for chunk in option_bytes.as_chunks::<2>().0 {
        option_versions.push(
            OptionVersion::from_le_bytes([chunk[0], chunk[1]]).ok_or_else(|| {
                DriverError::Other(
                    "request specification version option is not valid packed BCD".into(),
                )
            })?,
        );
    }
    Ok(SpecificationVersion {
        format_version,
        basic_version,
        option_versions,
    })
}

fn parse_idm(data: &[u8]) -> DriverResult<(Idm, &[u8])> {
    parse_fixed::<IDM_LEN>(data, "IDm")
}

fn parse_pmm(data: &[u8]) -> DriverResult<(Pmm, &[u8])> {
    parse_fixed::<8>(data, "PMm")
}

fn collect_blocks(data: &[u8], block_count: usize) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::with_capacity(block_count);
    for chunk in data[..block_count * BLOCK_SIZE].as_chunks::<BLOCK_SIZE>().0 {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(chunk);
        blocks.push(block);
    }
    blocks
}
