use super::*;

struct PayloadWriter {
    buf: Vec<u8>,
}

impl PayloadWriter {
    fn new(opcode: u8) -> Self {
        Self { buf: vec![opcode] }
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    fn idm(&mut self, idm: &[u8; IDM_LEN]) {
        self.buf.extend_from_slice(idm);
    }

    fn push_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    fn extend_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn extend_u16_le(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn extend_u16_be(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    fn extend_u16_list_le(&mut self, values: &[u16]) {
        for &value in values {
            self.extend_u16_le(value);
        }
    }

    fn extend_service_codes(&mut self, service_codes: &[ServiceCode]) {
        for &code in service_codes {
            self.buf.extend_from_slice(&code.to_le_bytes());
        }
    }

    fn extend_block_list(&mut self, block_list: &[BlockListElement]) {
        for block in block_list {
            self.buf.extend(block.pack());
        }
    }

    fn finish_frame(self) -> Result<Vec<u8>, FelicaStandardError> {
        frame_with_length_prefix(&self.buf)
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

fn append_service_codes(payload: &mut PayloadWriter, service_codes: &[ServiceCode]) {
    payload.push_u8(service_codes.len() as u8);
    payload.extend_service_codes(service_codes);
}

fn append_block_list(payload: &mut PayloadWriter, block_list: &[BlockListElement]) {
    payload.push_u8(block_list.len() as u8);
    payload.extend_block_list(block_list);
}

impl FelicaStandardCommand {
    /// Encodes this command as a wire frame (LEN byte + packet data).
    ///
    /// # Errors
    ///
    /// Returns [`FelicaStandardError::Protocol`] if the command is a secure
    /// (encrypted) one, which must be wrapped by a secure session rather than
    /// framed directly, or if the resulting packet would exceed the
    /// 255-byte limit imposed by the
    /// one-byte data length field.
    pub fn to_frame(&self) -> Result<Vec<u8>, FelicaStandardError> {
        match self.encoding()? {
            CommandEncoding::Plain(frame) => Ok(frame),
            CommandEncoding::Secure { .. } => Err(FelicaStandardError::Protocol(
                "secure commands must be encrypted by a secure session, not framed directly".into(),
            )),
        }
    }

    pub(crate) fn encoding(&self) -> Result<CommandEncoding, FelicaStandardError> {
        match self {
            FelicaStandardCommand::Polling {
                system_code,
                request_code,
                time_slots,
            } => {
                // §4.4.2 reserves every request code outside 00h-02h, and states
                // that a time slot value other than the five defined ones behaves
                // differently from product to product. Neither is safe to put on
                // the air, so reject them here — this is the choke point every
                // caller passes through, including drivers that build the command
                // themselves rather than going via `FelicaStandard::polling`.
                if !POLLING_REQUEST_CODES.contains(request_code) {
                    return Err(FelicaStandardError::Protocol(format!(
                        "polling request code {request_code:#04X} is reserved"
                    )));
                }
                if !POLLING_TIME_SLOTS.contains(time_slots) {
                    return Err(FelicaStandardError::Protocol(format!(
                        "polling time slot value {time_slots:#04X} is not defined; \
                         use 0x00, 0x01, 0x03, 0x07 or 0x0F"
                    )));
                }
                let mut payload = PayloadWriter::new(POLLING_COMMAND_CODE);
                payload.extend_u16_be(*system_code);
                payload.push_u8(*request_code);
                payload.push_u8(*time_slots);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::RequestService { idm, service_codes } => {
                debug_assert!(
                    !service_codes.is_empty() && service_codes.len() <= MAX_SERVICE_CODES
                );
                let mut payload = PayloadWriter::new(REQUEST_SERVICE_COMMAND_CODE);
                payload.idm(idm);
                append_service_codes(&mut payload, service_codes);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::RequestResponse { idm } => {
                let mut payload = PayloadWriter::new(REQUEST_RESPONSE_COMMAND_CODE);
                payload.idm(idm);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::ReadWithoutEncryption {
                idm,
                service_codes,
                block_list,
            } => {
                debug_assert!(
                    !service_codes.is_empty() && service_codes.len() <= MAX_RW_SERVICE_CODES
                );
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_COUNT);
                let mut payload = PayloadWriter::new(READ_WITHOUT_ENCRYPTION_COMMAND_CODE);
                payload.idm(idm);
                append_service_codes(&mut payload, service_codes);
                append_block_list(&mut payload, block_list);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::WriteWithoutEncryption {
                idm,
                service_codes,
                block_list,
                data,
            } => {
                debug_assert!(
                    !service_codes.is_empty() && service_codes.len() <= MAX_RW_SERVICE_CODES
                );
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_COUNT);
                debug_assert_eq!(data.len(), block_list.len() * BLOCK_SIZE);
                let mut payload = PayloadWriter::new(WRITE_WITHOUT_ENCRYPTION_COMMAND_CODE);
                payload.idm(idm);
                append_service_codes(&mut payload, service_codes);
                append_block_list(&mut payload, block_list);
                payload.extend_bytes(data);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::SearchServiceCode { idm, service_index } => {
                let mut payload = PayloadWriter::new(SEARCH_SERVICE_CODE_COMMAND_CODE);
                payload.idm(idm);
                payload.extend_u16_le(*service_index);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::RequestSystemCode { idm } => {
                let mut payload = PayloadWriter::new(REQUEST_SYSTEM_CODE_COMMAND_CODE);
                payload.idm(idm);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::RequestBlockInformation { idm, node_codes } => {
                debug_assert!(!node_codes.is_empty() && node_codes.len() <= MAX_NODE_CODES);
                let mut payload = PayloadWriter::new(REQUEST_BLOCK_INFORMATION_COMMAND_CODE);
                payload.idm(idm);
                payload.push_u8(node_codes.len() as u8);
                payload.extend_u16_list_le(node_codes);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::Authentication1 {
                idm,
                areas,
                services,
                challenge_1a,
            } => {
                let mut payload = PayloadWriter::new(AUTHENTICATION1_COMMAND_CODE);
                payload.idm(idm);
                payload.push_u8(areas.len() as u8);
                payload.extend_u16_list_le(areas);
                payload.push_u8(services.len() as u8);
                payload.extend_u16_list_le(services);
                payload.extend_bytes(challenge_1a);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::Authentication2 { idm, challenge_2b } => {
                let mut payload = PayloadWriter::new(AUTHENTICATION2_COMMAND_CODE);
                payload.idm(idm);
                payload.extend_bytes(challenge_2b);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::Read { block_list } => {
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_COUNT);
                let mut payload = PayloadWriter::with_capacity(1 + block_list.len() * 3);
                append_block_list(&mut payload, block_list);
                Ok(CommandEncoding::Secure {
                    opcode: READ_COMMAND_CODE,
                    payload: payload.finish(),
                })
            }
            FelicaStandardCommand::Write { block_list, data } => {
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_COUNT);
                debug_assert_eq!(data.len(), block_list.len() * BLOCK_SIZE);
                let mut payload =
                    PayloadWriter::with_capacity(1 + block_list.len() * 3 + data.len());
                append_block_list(&mut payload, block_list);
                payload.extend_bytes(data);
                Ok(CommandEncoding::Secure {
                    opcode: WRITE_COMMAND_CODE,
                    payload: payload.finish(),
                })
            }
            FelicaStandardCommand::ReadV2 { block_list } => {
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_COUNT);
                let mut payload = PayloadWriter::with_capacity(1 + block_list.len() * 3);
                append_block_list(&mut payload, block_list);
                Ok(CommandEncoding::Secure {
                    opcode: READ_V2_COMMAND_CODE,
                    payload: payload.finish(),
                })
            }
            FelicaStandardCommand::WriteV2 { block_list, data } => {
                debug_assert!(!block_list.is_empty() && block_list.len() <= MAX_BLOCK_COUNT);
                debug_assert_eq!(data.len(), block_list.len() * BLOCK_SIZE);
                let mut payload =
                    PayloadWriter::with_capacity(1 + block_list.len() * 3 + data.len());
                append_block_list(&mut payload, block_list);
                payload.extend_bytes(data);
                Ok(CommandEncoding::Secure {
                    opcode: WRITE_V2_COMMAND_CODE,
                    payload: payload.finish(),
                })
            }
            FelicaStandardCommand::RequestCodeList {
                idm,
                parent_node_code,
                index,
            } => {
                let mut payload = PayloadWriter::new(REQUEST_CODE_LIST_COMMAND_CODE);
                payload.idm(idm);
                payload.extend_u16_le(*parent_node_code);
                payload.extend_u16_le(*index);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::RequestBlockInformationEx { idm, node_codes } => {
                debug_assert!(!node_codes.is_empty() && node_codes.len() <= MAX_NODE_CODES);
                let mut payload = PayloadWriter::new(REQUEST_BLOCK_INFORMATION_EX_COMMAND_CODE);
                payload.idm(idm);
                payload.push_u8(node_codes.len() as u8);
                payload.extend_u16_list_le(node_codes);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::SetParameter {
                idm,
                encryption_type,
                packet_type,
            } => {
                let mut payload = PayloadWriter::new(SET_PARAMETER_COMMAND_CODE);
                payload.idm(idm);
                payload.extend_bytes(&[0x00; 4]);
                payload.push_u8(encryption_type.to_byte());
                payload.push_u8(packet_type.to_byte());
                payload.extend_bytes(&[0x00; 2]);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::GetContainerIssueInformation { idm } => {
                let mut payload = PayloadWriter::new(GET_CONTAINER_ISSUE_INFORMATION_COMMAND_CODE);
                payload.idm(idm);
                payload.extend_bytes(&[0x00; 2]);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::GetAreaInformation { idm, node_code } => {
                let mut payload = PayloadWriter::new(GET_AREA_INFORMATION_COMMAND_CODE);
                payload.idm(idm);
                payload.extend_u16_le(*node_code);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::GetNodeProperty {
                idm,
                node_property_type,
                node_codes,
            } => {
                debug_assert!(
                    !node_codes.is_empty() && node_codes.len() <= MAX_NODE_PROPERTY_CODES
                );
                let mut payload = PayloadWriter::new(GET_NODE_PROPERTY_COMMAND_CODE);
                payload.idm(idm);
                payload.push_u8(node_property_type.to_byte());
                payload.push_u8(node_codes.len() as u8);
                payload.extend_u16_list_le(node_codes);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::GetContainerProperty { property } => {
                let mut payload = PayloadWriter::new(GET_CONTAINER_PROPERTY_COMMAND_CODE);
                payload.extend_u16_le(property.to_index());
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::RequestServiceV2 { idm, service_codes } => {
                debug_assert!(
                    !service_codes.is_empty() && service_codes.len() <= MAX_SERVICE_CODES
                );
                let mut payload = PayloadWriter::new(REQUEST_SERVICE_V2_COMMAND_CODE);
                payload.idm(idm);
                append_service_codes(&mut payload, service_codes);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::GetSystemStatus { idm } => {
                let mut payload = PayloadWriter::new(GET_SYSTEM_STATUS_COMMAND_CODE);
                payload.idm(idm);
                payload.extend_bytes(&[0x00; 2]);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::RequestProductInformation { idm } => {
                let mut payload = PayloadWriter::new(REQUEST_PRODUCT_INFORMATION_COMMAND_CODE);
                payload.idm(idm);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::RequestSpecificationVersion { idm } => {
                let mut payload = PayloadWriter::new(REQUEST_SPECIFICATION_VERSION_COMMAND_CODE);
                payload.idm(idm);
                payload.extend_bytes(&[0x00; 2]);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::ResetMode { idm } => {
                let mut payload = PayloadWriter::new(RESET_MODE_COMMAND_CODE);
                payload.idm(idm);
                payload.extend_bytes(&[0x00; 2]);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::Authentication1V2 {
                idm,
                operation_parameter,
                nodes,
                challenge_1a,
            } => {
                let mut payload = PayloadWriter::new(AUTHENTICATION1_V2_COMMAND_CODE);
                payload.idm(idm);
                payload.push_u8(*operation_parameter);
                payload.push_u8(nodes.len() as u8);
                payload.extend_u16_list_le(nodes);
                payload.extend_bytes(challenge_1a);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::Authentication2V2 { idm, challenge_2b } => {
                let mut payload = PayloadWriter::new(AUTHENTICATION2_V2_COMMAND_CODE);
                payload.idm(idm);
                payload.extend_bytes(challenge_2b);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::GetContainerId => {
                let mut payload = PayloadWriter::new(GET_CONTAINER_ID_COMMAND_CODE);
                payload.extend_bytes(&[0x00; 2]);
                Ok(CommandEncoding::Plain(payload.finish_frame()?))
            }
            FelicaStandardCommand::RegisterIssueId {
                issue_id,
                issue_parameter,
                package,
            } => {
                let mut payload = PayloadWriter::with_capacity(16 + package.len());
                payload.extend_bytes(issue_id);
                payload.extend_bytes(issue_parameter);
                payload.extend_bytes(package);
                Ok(CommandEncoding::Secure {
                    opcode: REGISTER_ISSUE_ID_COMMAND_CODE,
                    payload: payload.finish(),
                })
            }
            FelicaStandardCommand::RegisterArea { area_code, package } => {
                let mut payload = PayloadWriter::with_capacity(2 + package.len());
                payload.extend_u16_le(*area_code);
                payload.extend_bytes(package);
                Ok(CommandEncoding::Secure {
                    opcode: REGISTER_AREA_COMMAND_CODE,
                    payload: payload.finish(),
                })
            }
            FelicaStandardCommand::RegisterService {
                service_code,
                package,
            } => {
                let mut payload = PayloadWriter::with_capacity(2 + package.len());
                payload.extend_u16_le(*service_code);
                payload.extend_bytes(package);
                Ok(CommandEncoding::Secure {
                    opcode: REGISTER_SERVICE_COMMAND_CODE,
                    payload: payload.finish(),
                })
            }
            FelicaStandardCommand::ChangeSystemBlock => Ok(CommandEncoding::Secure {
                opcode: CHANGE_SYSTEM_BLOCK_COMMAND_CODE,
                payload: Vec::new(),
            }),
        }
    }
}
