use super::*;
use crate::felica_standard::keys::{DerivedAuthKeys, ResolvedNodeKeys};
use zeroize::Zeroize;

/// Challenges returned by a v2 (AES-128) Authentication1 exchange:
/// `(challenge_1b, challenge_2a, challenge_3c)`.
type Authentication1V2Challenges = ([u8; 16], [u8; 16], [u8; 4]);

impl<'a, D: FelicaDriver + ?Sized> FelicaStandard<'a, D> {
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
        let mut random_1: [u8; 8] = rand::random();

        let context = AuthenticationContext::new(&idm, group_service_key, user_service_key);

        let mut challenge_1a = context.encrypt_challenge1a(&random_1);
        let (challenge_1b, challenge_2a) = self.authentication1(areas, services, &challenge_1a)?;
        if !context.verify_challenge1b(&random_1, &challenge_1b) {
            return Err(FelicaStandardError::AuthenticationFailed(
                "Authentication1 verification failed".into(),
            ));
        }

        let mut random_2 = context.decrypt_challenge2a(&challenge_2a);
        let mut challenge_2b = context.encrypt_challenge2b(&random_2);
        let auth2_response = self.authentication2(&challenge_2b)?;
        let mut payload = auth2_response.decrypt_payload(&random_2)?;
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

        // `random_2` now lives in the session context, which clears it on drop.
        // `random_1` and the challenges derived from it are ours, and the payload
        // holds the decrypted Authentication2 response.
        random_1.zeroize();
        random_2.zeroize();
        challenge_1a.zeroize();
        challenge_2b.zeroize();
        payload.zeroize();

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

    /// Encrypt an arbitrary command (`command_code` + `command_payload`) under the
    /// active secure session, transceive it, and return the decrypted response
    /// payload.
    ///
    /// This is the low-level primitive behind the typed secure commands (`read`,
    /// `write`, ...). It is exposed for callers that need to drive arbitrary
    /// secure commands over a relayed [`FelicaDriver`] — for example a remote
    /// crypto oracle that holds the keys while a separate client owns the reader.
    /// Requires a prior [`mutual_authentication`](Self::mutual_authentication).
    pub fn secure_transceive(
        &mut self,
        command_code: u8,
        command_payload: &[u8],
        timeout_ms: u16,
    ) -> Result<Vec<u8>, FelicaStandardError> {
        self.encrypted_command_exchange(command_code, command_payload, timeout_ms)
    }

    pub(super) fn encrypted_command_exchange(
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
        let frame = frame_with_length_prefix(&payload)?;
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
        // Like Read Without Encryption, a secure read is bounded by its response
        // rather than its command; the DES scheme's padding costs it one block
        // against Read v2.
        ensure_len_in_range(
            "block_list",
            block_list.len(),
            1,
            MAX_SECURE_READ_BLOCK_COUNT,
        )?;

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
        ensure_len_in_range(
            "block_list",
            block_list.len(),
            1,
            MAX_SECURE_READ_V2_BLOCK_COUNT,
        )?;

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
        // A write's true ceiling depends on whether its block list elements are
        // two or three bytes wide, so there is no single count to check here; the
        // 255-byte packet limit is enforced exactly when the frame is built.
        ensure_len_in_range("block_list", block_list.len(), 1, MAX_BLOCK_COUNT)?;
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
                Self::check_status_flags("Write", status_flag1, status_flag2)?;
                Ok(())
            }
            _ => Err(unexpected_response("Write")),
        }
    }

    pub fn write_v2(
        &mut self,
        block_list: &[BlockListElement],
        data: &[u8],
    ) -> Result<(), FelicaStandardError> {
        // A write's true ceiling depends on whether its block list elements are
        // two or three bytes wide, so there is no single count to check here; the
        // 255-byte packet limit is enforced exactly when the frame is built.
        ensure_len_in_range("block_list", block_list.len(), 1, MAX_BLOCK_COUNT)?;
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
                Self::check_status_flags("Write v2", status_flag1, status_flag2)?;
                Ok(())
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
    ) -> Result<Authentication1V2Challenges, FelicaStandardError> {
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
        let mut random_1: [u8; 16] = rand::random();

        let context = AuthenticationContextV2Aes128::new(&idm, group_key, individual_key);
        let mut challenge_1a = context.encrypt_challenge1a(&random_1);
        let (challenge_1b, challenge_2a, challenge_3c) =
            self.authentication1_v2(operation_parameter, nodes, &challenge_1a)?;
        if !context.verify_challenge1b(&random_1, &challenge_1b, &challenge_3c) {
            return Err(FelicaStandardError::AuthenticationFailed(
                "Authentication1 v2 verification failed".into(),
            ));
        }

        let mut random_2 = context.decrypt_challenge2a(&challenge_2a, &challenge_3c);
        let mut challenge_2b = context.encrypt_challenge2b(&random_2);
        let auth2_response = self.authentication2_v2(&challenge_2b)?;

        let mut transaction_id = [0u8; 6];
        transaction_id.copy_from_slice(&random_1[2..8]);
        let (mut encryption_key, mut mac_key) = context.derive_secure_session_keys(&random_2);

        let (transaction_number, mut payload) = auth2_response.decrypt_payload(
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

        // The derived session keys now live in the session context, which clears
        // them on drop; these are the copies this exchange made.
        random_1.zeroize();
        random_2.zeroize();
        challenge_1a.zeroize();
        challenge_2b.zeroize();
        encryption_key.zeroize();
        mac_key.zeroize();
        payload.zeroize();

        Ok(MutualAuthenticationResult {
            issue_id,
            issue_parameter,
        })
    }

    /// Derive the authentication keys for the target node(s) from a
    /// [`ResolvedNodeKeys`] and run the matching mutual authentication (DES or
    /// AES-128) in one step.
    ///
    /// `area_path`/`services` name the nodes to access; `individual_key` sets the
    /// AES-128 individual key manually (see
    /// [`ResolvedNodeKeys::derive_auth_keys`]) and must be `None` for DES nodes.
    ///
    /// [`ResolvedNodeKeys`]: crate::felica_standard::ResolvedNodeKeys
    /// [`ResolvedNodeKeys::derive_auth_keys`]: crate::felica_standard::ResolvedNodeKeys::derive_auth_keys
    pub fn authenticate_node(
        &mut self,
        keys: &ResolvedNodeKeys,
        area_path: &[u16],
        services: &[ServiceCode],
        individual_key: Option<[u8; 16]>,
    ) -> Result<MutualAuthenticationResult, FelicaStandardError> {
        let derived = keys
            .derive_auth_keys(area_path, services, individual_key)
            .map_err(|err| FelicaStandardError::InvalidParameter(err.to_string()))?;
        // Borrow rather than destructure: `DerivedAuthKeys` zeroizes on drop, so
        // moving its keys out would leave copies that are never cleared.
        match &derived {
            DerivedAuthKeys::Des {
                areas,
                services,
                group_service_key,
                user_service_key,
            } => self.mutual_authentication(areas, services, group_service_key, user_service_key),
            DerivedAuthKeys::Aes128 {
                nodes,
                group_key,
                individual_key,
            } => self.mutual_authentication_v2(0x00, nodes, group_key, individual_key),
        }
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
                Self::check_status_flags("Register Area", status_flag1, status_flag2)?;
                Ok(())
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
                Self::check_status_flags("Change System Block", status_flag1, status_flag2)?;
                Ok(())
            }
            _ => Err(unexpected_response("Change System Block")),
        }
    }
}
