use super::*;

impl<'a, D: FelicaDriver + ?Sized> FelicaStandard<'a, D> {
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

    pub fn request_product_information(&mut self) -> Result<Vec<u8>, FelicaStandardError> {
        let idm = self.idm_bytes()?;
        let timeout_ms = self.polling_result.request_product_information_timeout_ms();

        let response = self.execute_command(
            "Request Product Information",
            FelicaStandardCommand::RequestProductInformation { idm },
            timeout_ms,
        )?;

        match response {
            FelicaStandardResponse::RequestProductInformation {
                status_flag1,
                status_flag2,
                result,
                ..
            } => {
                if status_flag1 != 0 {
                    Err(Self::status_error(
                        "Request Product Information",
                        status_flag1,
                        status_flag2,
                    ))
                } else {
                    result.ok_or_else(|| {
                        FelicaStandardError::Protocol(
                            "Request Product Information missing result payload".into(),
                        )
                    })
                }
            }
            _ => Err(unexpected_response("Request Product Information")),
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
}
