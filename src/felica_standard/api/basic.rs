use super::*;

impl<'a, D: FelicaDriver + ?Sized> FelicaStandard<'a, D> {
    /// Checks whether Nodes exist and returns their two-byte key versions.
    ///
    /// The result contains one entry per requested code, in request order;
    /// `FFFFh` is the card's no-such-node marker. This original command is
    /// intended for DES-capable cards; use
    /// [`request_service_v2`](Self::request_service_v2) when the card exposes
    /// AES/DES cryptographic-system information.
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
            FelicaStandardResponse::RequestService { key_versions, .. } => {
                if key_versions.len() != service_codes.len() {
                    return Err(FelicaStandardError::Protocol(
                        "Request Service key version count mismatch".into(),
                    ));
                }
                Ok(key_versions)
            }
            _ => Err(unexpected_response("Request Service")),
        }
    }

    /// Returns the card's current mode byte.
    ///
    /// Cards start in Mode 0, enter Mode 1 after Authentication1, and enter
    /// Mode 2 after Authentication2 completes mutual authentication. Issuing
    /// commands can move a supported card to Mode 3.
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

    /// Reads 16-byte Blocks from authentication-free Services.
    ///
    /// Each Block List Element selects a Service by its zero-based position in
    /// `service_codes`; returned Blocks preserve Block List order. The command
    /// does not encrypt its payload despite its name and must only address
    /// Services whose attribute permits access without authentication.
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
        // A read is bounded by its response rather than its command: the request
        // stays small however many blocks it asks for, so an over-long one would
        // go out on the air and simply never be answerable.
        ensure_len_in_range(
            "block_list",
            block_list.len(),
            1,
            MAX_READ_WITHOUT_ENCRYPTION_BLOCK_COUNT,
        )?;
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
                let result = Self::require_result(
                    "Read Without Encryption",
                    status_flag1,
                    status_flag2,
                    result,
                )?;
                if result.blocks.len() != block_list.len() {
                    return Err(FelicaStandardError::Protocol(
                        "Read Without Encryption response block count mismatch".into(),
                    ));
                }
                Ok(result.blocks)
            }
            _ => Err(unexpected_response("Read Without Encryption")),
        }
    }

    /// Writes 16-byte Blocks to authentication-free Services.
    ///
    /// `data` is the concatenation of exactly one 16-byte Block for every Block
    /// List Element. Access mode `001b` requests purse cashback; ordinary writes
    /// use `000b`.
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
        ensure_len_in_range("block_list", block_list.len(), 1, MAX_BLOCK_COUNT)?;
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
                Self::check_status_flags("Write Without Encryption", status_flag1, status_flag2)?;
                Ok(())
            }
            _ => Err(unexpected_response("Write Without Encryption")),
        }
    }

    /// Returns the Area or Service entry at a zero-based system-list index.
    ///
    /// `None` is the protocol's end-of-list marker. Repeated calls beginning at
    /// index zero can therefore enumerate the selected System's node structure.
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

    /// Returns every System Code registered on the currently selected card.
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

    /// Returns the assigned Block count of each requested Node.
    ///
    /// Counts retain the order of `node_codes`. A Node may be a System, Area, or
    /// Service supported by the card product.
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
                if block_counts.len() != node_codes.len() {
                    return Err(FelicaStandardError::Protocol(
                        "Request Block Information block count list length mismatch".into(),
                    ));
                }
                Ok(block_counts)
            }
            _ => Err(unexpected_response("Request Block Information")),
        }
    }

    /// Returns assigned and free Block counts for each requested Node.
    ///
    /// Both vectors retain `node_codes` order and have the same length on a
    /// valid response.
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
                let result = Self::require_result(
                    "Request Block Information Ex",
                    status_flag1,
                    status_flag2,
                    result,
                )?;
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
            _ => Err(unexpected_response("Request Block Information Ex")),
        }
    }

    /// Returns one page of child Area and Service codes under `parent_node_code`.
    ///
    /// `index` is the page/start position defined by the command. Inspect
    /// [`RequestCodeListResult::continue_flag`] to determine whether another
    /// request is necessary.
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
            } => Self::require_result("Request Code List", status_flag1, status_flag2, result),
            _ => Err(unexpected_response("Request Code List")),
        }
    }

    /// Selects the card's SRM encryption format and Node Code width.
    ///
    /// This optional command changes communication parameters for later
    /// commands; support and permitted transitions are product-dependent.
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
                Self::check_status_flags("Set Parameter", status_flag1, status_flag2)?;
                Ok(())
            }
            _ => Err(unexpected_response("Set Parameter")),
        }
    }

    /// Returns mobile-FeliCa container format/carrier and handset-model data.
    ///
    /// This optional command is only implemented by applicable mobile FeliCa
    /// products.
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

    /// Returns the raw value of a product-dependent mobile-FeliCa property.
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

    /// Returns the eight-byte Container IDm from a mobile FeliCa product.
    ///
    /// Unlike most commands, Get Container ID is not addressed by the currently
    /// selected card IDm.
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

    /// Returns product-defined configuration state for the selected System.
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
                Self::check_status_flags("Get System Status", status_flag1, status_flag2)?;
                Ok(result)
            }
            _ => Err(unexpected_response("Get System Status")),
        }
    }

    /// Returns the card's product-information bytes.
    ///
    /// The field layout is product-dependent and is therefore kept raw.
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
            } => Self::require_result(
                "Request Product Information",
                status_flag1,
                status_flag2,
                result,
            ),
            _ => Err(unexpected_response("Request Product Information")),
        }
    }

    /// Returns the basic and optional-feature versions implemented by the card.
    ///
    /// A successful response always contains the version payload. The return
    /// type remains optional for API compatibility, but a conforming parsed
    /// success is therefore always `Some`.
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
                Self::check_status_flags(
                    "Request Specification Version",
                    status_flag1,
                    status_flag2,
                )?;
                Ok(specification_version)
            }
            _ => Err(unexpected_response("Request Specification Version")),
        }
    }

    /// Returns the card to Mode 0.
    ///
    /// Any previously authenticated context no longer describes the card's
    /// state; call [`clear_authenticated_context`](Self::clear_authenticated_context)
    /// before starting another secure exchange.
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
                Self::check_status_flags("Reset Mode", status_flag1, status_flag2)?;
                Ok(())
            }
            _ => Err(unexpected_response("Reset Mode")),
        }
    }

    /// Returns the product-dependent two-byte information field for an Area.
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
            } => Self::require_result("Get Area Information", status_flag1, status_flag2, result),
            _ => Err(unexpected_response("Get Area Information")),
        }
    }

    /// Returns one property value for each requested Node, in request order.
    ///
    /// Supported property groups are the limited-purse configuration and the
    /// communication-with-MAC enable flag. This command is optional and only
    /// available on applicable AES or AES/DES products.
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
                let result =
                    Self::require_result("Get Node Property", status_flag1, status_flag2, result)?;
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
            _ => Err(unexpected_response("Get Node Property")),
        }
    }
}
