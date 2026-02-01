use super::command::{is_register_command, is_secure_command_code};
use super::secure::{
    AuthenticationContext, build_authentication2_payload, build_secure_response_frame,
    check_packet_mac, decrypt_des_cbc_zero_iv, encrypt_authentication2_payload,
    generate_service_keys, strip_secure_padding,
};
use super::{
    Authentication2Response, BLOCK_SIZE, BlockListElement, DES_BLOCK_SIZE, FelicaStandardCommand,
    FelicaStandardResponse, SearchServiceCodeResult, ServiceCode, Type3TagPollingResult,
    frame_with_length_prefix,
};
use rand::{RngCore, rngs::OsRng};
use std::cell::{Ref, RefCell, RefMut};
use std::collections::BTreeMap;
use std::rc::Rc;

const ROOT_AREA_CODE: u16 = 0x0000;
const ROOT_END_SERVICE_CODE: u16 = 0xFFFE;
const STATUS_UNSUPPORTED_SF1: u8 = 0xFF;
const STATUS_UNSUPPORTED_SF2: u8 = 0xC2;
type SharedBlocks = Rc<RefCell<Vec<[u8; BLOCK_SIZE]>>>;

#[derive(Debug, thiserror::Error)]
pub enum EmulatorConfigError {
    #[error("area code 0x{area_code:04X} exceeds end service code 0x{end_service_code:04X}")]
    InvalidAreaRange {
        area_code: u16,
        end_service_code: u16,
    },
    #[error("area code 0x0000 must have end service code 0xFFFE (got 0x{end_service_code:04X})")]
    InvalidRootAreaRange { end_service_code: u16 },
    #[error(
        "service code 0x{service_code:04X} is outside area range 0x{area_code:04X}..=0x{end_service_code:04X}"
    )]
    ServiceOutOfRange {
        area_code: u16,
        end_service_code: u16,
        service_code: u16,
    },
    #[error(
        "child area 0x{child_area_code:04X}..=0x{child_end_service_code:04X} is outside area range 0x{area_code:04X}..=0x{end_service_code:04X}"
    )]
    AreaOutOfRange {
        area_code: u16,
        end_service_code: u16,
        child_area_code: u16,
        child_end_service_code: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SystemMode {
    Mode0,
    Mode1,
    Mode2,
    Mode3,
}

impl SystemMode {
    fn code(self) -> u8 {
        match self {
            SystemMode::Mode0 => 0x00,
            SystemMode::Mode1 => 0x01,
            SystemMode::Mode2 => 0x02,
            SystemMode::Mode3 => 0x03,
        }
    }
}

pub struct FelicaStandardEmulator {
    systems: Vec<EmulatedSystem>,
    active_system: Option<u16>,
}

impl FelicaStandardEmulator {
    pub fn new() -> Self {
        Self {
            systems: Vec::new(),
            active_system: None,
        }
    }

    pub fn add_system(&mut self, system: EmulatedSystem) -> &mut Self {
        let system_code = system.system_code;
        self.systems.push(system);
        if self.active_system.is_none() {
            self.active_system = Some(system_code);
        }
        self
    }

    pub fn set_active_system(&mut self, system_code: u16) -> bool {
        match self
            .systems
            .iter_mut()
            .find(|system| system.system_code == system_code)
        {
            Some(system) => {
                system.reset_mode();
                self.active_system = Some(system_code);
                true
            }
            None => false,
        }
    }

    pub fn active_system_code(&self) -> Option<u16> {
        self.resolve_active_system_code()
    }

    pub fn system_codes(&self) -> Vec<u16> {
        self.systems
            .iter()
            .map(|system| system.system_code)
            .collect()
    }

    /// Build the SENSF_RES payload (without the length byte) for the active system.
    /// Uses request code 0x01 (system code request).
    pub fn sensf_res(&self) -> Option<Vec<u8>> {
        let system_code = self.resolve_active_system_code()?;
        self.sensf_res_for(system_code)
    }

    /// Build a length-prefixed SENSF_RES frame for the active system.
    pub fn sensf_res_frame(&self) -> Option<Vec<u8>> {
        let system_code = self.resolve_active_system_code()?;
        self.sensf_res_frame_for(system_code)
    }

    /// Build the SENSF_RES payload (without the length byte) for a given system code.
    /// Uses request code 0x01 (system code request).
    pub fn sensf_res_for(&self, system_code: u16) -> Option<Vec<u8>> {
        self.polling_payload_for(system_code, 0x01)
    }

    /// Build the SENSF_RES payload (without the length byte) for a given request code.
    pub fn polling_payload_for(&self, system_code: u16, request_code: u8) -> Option<Vec<u8>> {
        let system = self
            .systems
            .iter()
            .find(|system| system.system_code == system_code)?;
        let optional = polling_optional(system.system_code, request_code);
        FelicaStandardResponse::Polling {
            idm: system.idm,
            pmm: system.pmm,
            optional,
        }
        .to_payload()
        .ok()
    }

    /// Build the polling result for a given request code.
    pub fn polling_result_for(
        &self,
        system_code: u16,
        request_code: u8,
    ) -> Option<Type3TagPollingResult> {
        let system = self
            .systems
            .iter()
            .find(|system| system.system_code == system_code)?;
        let optional = polling_optional(system.system_code, request_code);
        Some(Type3TagPollingResult {
            idm: system.idm.to_vec(),
            pmm: system.pmm.to_vec(),
            optional,
        })
    }

    /// Build the SENSF_RES payload (without the length byte) for a polling request.
    /// This selects a matching system and updates the active system.
    pub fn polling_response(
        &mut self,
        request_system_code: u16,
        request_code: u8,
    ) -> Option<Type3TagPollingResult> {
        let system_code = self.resolve_polling_system_code(request_system_code)?;
        self.set_active_system(system_code);
        self.polling_result_for(system_code, request_code)
    }

    fn resolve_polling_system_code(&self, request_system_code: u16) -> Option<u16> {
        if request_system_code == 0xFFFF {
            return self.systems.first().map(|system| system.system_code);
        }
        if let Some(active) = self.active_system {
            if self.systems.iter().any(|system| {
                system.system_code == active && matches_system_code(request_system_code, active)
            }) {
                return Some(active);
            }
        }
        self.systems
            .iter()
            .find(|system| matches_system_code(request_system_code, system.system_code))
            .map(|system| system.system_code)
    }

    /// Build a length-prefixed SENSF_RES frame for a given system code.
    pub fn sensf_res_frame_for(&self, system_code: u16) -> Option<Vec<u8>> {
        let payload = self.sensf_res_for(system_code)?;
        Some(frame_with_length_prefix(&payload))
    }

    /// Handle a length-prefixed FeliCa frame (length byte + payload).
    pub fn handle_frame(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < 2 {
            return None;
        }
        let expected_len = frame[0] as usize;
        if expected_len != frame.len() {
            return None;
        }
        let command_code = frame[1];
        let payload = &frame[2..];
        if is_secure_command_code(command_code) {
            return self.handle_secure_frame(command_code, payload);
        }
        let command = FelicaStandardCommand::parse_frame(frame).ok()?;
        self.handle_command(command)
    }

    pub fn handle_command(&mut self, command: FelicaStandardCommand) -> Option<Vec<u8>> {
        match command {
            FelicaStandardCommand::Polling {
                system_code,
                request_code,
                ..
            } => {
                let index = self.system_index_for_polling(system_code)?;
                let system = self.systems.get(index)?;
                let optional = polling_optional(system.system_code, request_code);
                encode_response_frame(FelicaStandardResponse::Polling {
                    idm: system.idm,
                    pmm: system.pmm,
                    optional,
                })
            }
            FelicaStandardCommand::RequestResponse { idm } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get(index)?;
                encode_response_frame(FelicaStandardResponse::RequestResponse {
                    idm,
                    mode: system.mode.code(),
                })
            }
            FelicaStandardCommand::RequestSystemCode { idm } => {
                self.system_index_for_idm(&idm)?;
                let codes = self.system_codes();
                if codes.is_empty() {
                    None
                } else {
                    encode_response_frame(FelicaStandardResponse::RequestSystemCode {
                        idm,
                        system_codes: codes,
                    })
                }
            }
            FelicaStandardCommand::SearchServiceCode { idm, service_index } => {
                let index = self.system_index_for_idm(&idm)?;
                let directory = self.systems.get(index)?.directory();
                let entry = directory.get(service_index as usize);
                let result = match entry {
                    Some(DirectoryEntry::Service(code)) => {
                        Some(SearchServiceCodeResult::Service(*code))
                    }
                    Some(DirectoryEntry::Area {
                        area_code,
                        end_service_code,
                    }) => Some(SearchServiceCodeResult::Area {
                        area_code: *area_code,
                        end_service_index: *end_service_code,
                    }),
                    None => None,
                };
                encode_response_frame(FelicaStandardResponse::SearchServiceCode { idm, result })
            }
            FelicaStandardCommand::RequestService { idm, service_codes } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get(index)?;
                let key_versions = service_codes
                    .iter()
                    .map(|code| system.node_key_version(*code))
                    .collect::<Vec<_>>();
                encode_response_frame(FelicaStandardResponse::RequestService { idm, key_versions })
            }
            FelicaStandardCommand::ReadWithoutEncryption {
                idm,
                service_codes,
                block_list,
            } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get(index)?;
                Self::handle_read(idm, system, &service_codes, &block_list)
            }
            FelicaStandardCommand::WriteWithoutEncryption {
                idm,
                service_codes,
                block_list,
                data,
            } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get_mut(index)?;
                Self::handle_write(idm, system, &service_codes, &block_list, &data)
            }
            FelicaStandardCommand::RequestBlockInformation { idm, node_codes } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get(index)?;
                let counts = node_codes
                    .iter()
                    .map(|code| system.block_count_for_node(*code))
                    .collect::<Vec<_>>();
                encode_response_frame(FelicaStandardResponse::RequestBlockInformation {
                    idm,
                    block_counts: counts,
                })
            }
            FelicaStandardCommand::Authentication1 {
                idm,
                areas,
                services,
                challenge_1a,
            } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get_mut(index)?;
                system.handle_authentication1(idm, &areas, &services, challenge_1a)
            }
            FelicaStandardCommand::Authentication2 { idm, challenge_2b } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get_mut(index)?;
                system.handle_authentication2(idm, challenge_2b)
            }
            _ => None,
        }
    }

    fn handle_read(
        idm: [u8; 8],
        system: &EmulatedSystem,
        service_codes: &[ServiceCode],
        block_list: &[BlockListElement],
    ) -> Option<Vec<u8>> {
        let mut blocks = Vec::with_capacity(block_list.len());
        for (index, block) in block_list.iter().enumerate() {
            let (service_code, block_number) =
                match system.validate_block(service_codes, index, block, AccessType::Read) {
                    Ok(value) => value,
                    Err((sf1, sf2)) => {
                        return encode_response_frame(
                            FelicaStandardResponse::ReadWithoutEncryption {
                                idm,
                                status_flag1: sf1,
                                status_flag2: sf2,
                                blocks: None,
                            },
                        );
                    }
                };
            let service = system.find_service(service_code).unwrap();
            let block_data = {
                let shared = service.blocks.borrow();
                shared[block_number]
            };
            blocks.push(block_data);
        }
        encode_response_frame(FelicaStandardResponse::ReadWithoutEncryption {
            idm,
            status_flag1: 0x00,
            status_flag2: 0x00,
            blocks: Some(blocks),
        })
    }

    fn handle_write(
        idm: [u8; 8],
        system: &mut EmulatedSystem,
        service_codes: &[ServiceCode],
        block_list: &[BlockListElement],
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let expected_len = block_list.len().saturating_mul(BLOCK_SIZE);
        if data.len() < expected_len {
            return encode_response_frame(FelicaStandardResponse::WriteWithoutEncryption {
                idm,
                status_flag1: 0xFF,
                status_flag2: 0xAC,
            });
        }
        let mut updates = Vec::with_capacity(block_list.len());
        for (index, block) in block_list.iter().enumerate() {
            let (service_code, block_number) =
                match system.validate_block(service_codes, index, block, AccessType::Write) {
                    Ok(value) => value,
                    Err((sf1, sf2)) => {
                        return encode_response_frame(
                            FelicaStandardResponse::WriteWithoutEncryption {
                                idm,
                                status_flag1: sf1,
                                status_flag2: sf2,
                            },
                        );
                    }
                };
            let offset = index * BLOCK_SIZE;
            let mut block_data = [0u8; BLOCK_SIZE];
            block_data.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
            updates.push((service_code, block_number, block_data));
        }

        let mut shared_blocks: BTreeMap<u16, SharedBlocks> = BTreeMap::new();
        for (service_code, block_number, block_data) in updates {
            let service_number = service_code.number();
            let shared = if let Some(shared) = shared_blocks.get(&service_number) {
                shared.clone()
            } else {
                let Some(service) = system.find_service(service_code) else {
                    return encode_response_frame(FelicaStandardResponse::WriteWithoutEncryption {
                        idm,
                        status_flag1: 0xFF,
                        status_flag2: 0xA6,
                    });
                };
                let shared = service.blocks.clone();
                shared_blocks.insert(service_number, shared.clone());
                shared
            };
            let mut blocks = shared.borrow_mut();
            if let Some(slot) = blocks.get_mut(block_number) {
                *slot = block_data;
            }
        }

        encode_response_frame(FelicaStandardResponse::WriteWithoutEncryption {
            idm,
            status_flag1: 0x00,
            status_flag2: 0x00,
        })
    }

    fn resolve_active_system_code(&self) -> Option<u16> {
        if let Some(code) = self.active_system {
            if self.systems.iter().any(|system| system.system_code == code) {
                return Some(code);
            }
        }
        self.systems.first().map(|system| system.system_code)
    }

    fn system_index_for_idm(&mut self, idm: &[u8; 8]) -> Option<usize> {
        let index = self.systems.iter().position(|system| &system.idm == idm)?;
        let system_code = self.systems[index].system_code;
        if self.active_system != Some(system_code) {
            self.systems[index].reset_mode();
            self.active_system = Some(system_code);
        }
        Some(index)
    }

    fn system_index_for_polling(&mut self, system_code: u16) -> Option<usize> {
        let index = self
            .systems
            .iter()
            .position(|system| matches_system_code(system_code, system.system_code))?;
        let resolved = self.systems[index].system_code;
        self.systems[index].reset_mode();
        self.active_system = Some(resolved);
        Some(index)
    }

    fn handle_secure_frame(
        &mut self,
        command_code: u8,
        encrypted_payload: &[u8],
    ) -> Option<Vec<u8>> {
        let system_code = self.resolve_active_system_code()?;
        let index = self
            .systems
            .iter()
            .position(|system| system.system_code == system_code)?;
        let system = self.systems.get_mut(index)?;
        system.handle_secure_frame(command_code, encrypted_payload)
    }
}

pub struct EmulatedSystem {
    system_code: u16,
    idm: [u8; 8],
    pmm: [u8; 8],
    root_area: EmulatedArea,
    mode: SystemMode,
    system_key_version: u16,
    system_key: [u8; 8],
    idi: [u8; 8],
    pmi: [u8; 8],
    pending_auth: Option<PendingAuthentication>,
    secure_session: Option<SecureSession>,
}

impl EmulatedSystem {
    pub fn new(system_code: u16, idm: [u8; 8], pmm: [u8; 8]) -> Result<Self, EmulatorConfigError> {
        let root_area = EmulatedArea::new(ROOT_AREA_CODE, ROOT_END_SERVICE_CODE)?;
        Ok(Self {
            system_code,
            idm,
            pmm,
            root_area,
            mode: SystemMode::Mode0,
            system_key_version: 0x0000,
            system_key: [0x00; 8],
            idi: [0x00; 8],
            pmi: [0x00; 8],
            pending_auth: None,
            secure_session: None,
        })
    }

    pub fn system_code(&self) -> u16 {
        self.system_code
    }

    pub fn system_key_version(&self) -> u16 {
        self.system_key_version
    }

    pub fn system_key(&self) -> &[u8; 8] {
        &self.system_key
    }

    pub fn idm(&self) -> &[u8; 8] {
        &self.idm
    }

    pub fn pmm(&self) -> &[u8; 8] {
        &self.pmm
    }

    pub fn root_area(&self) -> &EmulatedArea {
        &self.root_area
    }

    pub fn root_area_mut(&mut self) -> &mut EmulatedArea {
        &mut self.root_area
    }

    pub fn set_system_key_version(&mut self, version: u16) -> &mut Self {
        self.system_key_version = version;
        self
    }

    pub fn set_system_key(&mut self, system_key: [u8; 8]) -> &mut Self {
        self.system_key = system_key;
        self
    }

    pub fn set_idi_pmi(&mut self, idi: [u8; 8], pmi: [u8; 8]) -> &mut Self {
        self.idi = idi;
        self.pmi = pmi;
        self
    }

    pub fn set_issue_information(
        &mut self,
        issue_id: [u8; 8],
        issue_parameter: [u8; 8],
    ) -> &mut Self {
        self.set_idi_pmi(issue_id, issue_parameter)
    }

    pub fn add_service(
        &mut self,
        service: EmulatedService,
    ) -> Result<&mut Self, EmulatorConfigError> {
        self.root_area.add_service(service)?;
        self.sync_overlapping_services();
        Ok(self)
    }

    pub fn add_area(&mut self, area: EmulatedArea) -> Result<&mut Self, EmulatorConfigError> {
        self.root_area.add_area(area)?;
        self.sync_overlapping_services();
        Ok(self)
    }

    pub fn directory(&self) -> Vec<DirectoryEntry> {
        let mut entries = Vec::new();
        self.root_area.append_directory_entries(&mut entries);
        entries
    }

    fn find_service(&self, service_code: ServiceCode) -> Option<&EmulatedService> {
        self.root_area.find_service(service_code)
    }

    fn find_area(&self, area_code: u16) -> Option<&EmulatedArea> {
        self.root_area.find_area(area_code)
    }

    fn node_key_version(&self, node_code: ServiceCode) -> u16 {
        if node_code.raw() == 0xFFFF {
            return self.system_key_version;
        }
        if let Some(service) = self.find_service(node_code) {
            if service.service_code.requires_key() {
                return service.key_version;
            }
            return 0xFFFF;
        }
        if let Some(area) = self.find_area(node_code.raw()) {
            return area.key_version;
        }
        0xFFFF
    }

    fn handle_authentication1(
        &mut self,
        idm: [u8; 8],
        areas: &[u16],
        services: &[u16],
        challenge_1a: [u8; 8],
    ) -> Option<Vec<u8>> {
        let system_key = self.system_key;
        let mut area_keys = Vec::new();
        let mut service_keys = Vec::new();
        for area_code in areas {
            let area = self.find_area(*area_code)?;
            area_keys.push(*area.key());
        }
        let mut service_codes = Vec::new();
        for area_code in areas {
            let area = self.find_area(*area_code)?;
            area.append_service_codes(&mut service_codes);
        }
        for &raw in services {
            let code = ServiceCode::new(raw);
            let service = self.find_service(code)?;
            if code.requires_key() {
                service_keys.push(*service.key());
            }
            service_codes.push(code);
        }

        let (group_key, user_key) = generate_service_keys(&system_key, &area_keys, &service_keys);
        let context = AuthenticationContext::new(&idm, &group_key, &user_key);
        let random_1 = context.decrypt_challenge1a(&challenge_1a);
        let mut random_2 = [0u8; 8];
        OsRng.fill_bytes(&mut random_2);
        let challenge_1b = context.encrypt_challenge1b(&random_1);
        let challenge_2a = context.encrypt_challenge2a(&random_2);

        self.pending_auth = Some(PendingAuthentication {
            context,
            random_1,
            random_2,
            service_codes,
        });
        self.secure_session = None;
        self.mode = SystemMode::Mode1;

        encode_response_frame(FelicaStandardResponse::Authentication1 {
            idm,
            challenge_1b,
            challenge_2a,
        })
    }

    fn handle_authentication2(&mut self, _idm: [u8; 8], challenge_2b: [u8; 8]) -> Option<Vec<u8>> {
        let pending = self.pending_auth.take()?;
        let expected = pending.context.encrypt_challenge2b(&pending.random_2);
        if expected != challenge_2b {
            return None;
        }

        let mut transaction_id = [0u8; 6];
        transaction_id.copy_from_slice(&pending.random_1[2..8]);
        let transaction_number = 0u16;
        let payload = build_authentication2_payload(
            transaction_number,
            &transaction_id,
            &self.idi,
            &self.pmi,
        );
        let encrypted_payload = encrypt_authentication2_payload(&payload, &pending.random_2)?;

        self.secure_session = Some(SecureSession {
            transaction_number,
            transaction_id,
            transaction_key: pending.random_2,
            service_codes: pending.service_codes,
        });
        self.mode = SystemMode::Mode2;

        encode_response_frame(FelicaStandardResponse::Authentication2(
            Authentication2Response { encrypted_payload },
        ))
    }

    fn validate_block(
        &self,
        service_codes: &[ServiceCode],
        index: usize,
        block: &BlockListElement,
        access: AccessType,
    ) -> Result<(ServiceCode, usize), (u8, u8)> {
        if block.access_mode != 0 {
            return Err((list_error_index(index), 0xA7));
        }

        let service_index = block.service_code_list_index as usize;
        let Some(service_code) = service_codes.get(service_index).copied() else {
            return Err((list_error_index(index), 0xA3));
        };
        let Some(service) = self.find_service(service_code) else {
            return Err((list_error_index(index), 0xA5));
        };
        if service_code.requires_key() {
            return Err((list_error_index(index), 0xA5));
        }
        if matches!(access, AccessType::Write) && !service_allows_write(service_code) {
            return Err((list_error_index(index), 0xA5));
        }

        let block_number = block.block_number_or_key_version as usize;
        let block_count = service.blocks.borrow().len();
        if block_number >= block_count {
            return Err((list_error_index(index), 0xA8));
        }

        Ok((service_code, block_number))
    }

    fn validate_secure_block(
        &self,
        service_codes: &[ServiceCode],
        index: usize,
        block: &BlockListElement,
        access: AccessType,
    ) -> Result<(ServiceCode, usize), (u8, u8)> {
        if block.access_mode != 0 {
            return Err((list_error_index(index), 0xA7));
        }

        let service_index = block.service_code_list_index as usize;
        let Some(service_code) = service_codes.get(service_index).copied() else {
            return Err((list_error_index(index), 0xA3));
        };
        let Some(service) = self.find_service(service_code) else {
            return Err((list_error_index(index), 0xA5));
        };
        if matches!(access, AccessType::Write) && !service_allows_write(service_code) {
            return Err((list_error_index(index), 0xA5));
        }

        let block_number = block.block_number_or_key_version as usize;
        let block_count = service.blocks.borrow().len();
        if block_number >= block_count {
            return Err((list_error_index(index), 0xA8));
        }

        Ok((service_code, block_number))
    }

    fn block_count_for_node(&self, node_code: u16) -> u16 {
        let service_code = ServiceCode::new(node_code);
        if let Some(service) = self.find_service(service_code) {
            let block_count = service.blocks.borrow().len();
            return block_count.min(u16::MAX as usize) as u16;
        }
        if let Some(area) = self.find_area(node_code) {
            return area.total_block_count().min(u16::MAX as usize) as u16;
        }
        0
    }

    fn reset_mode(&mut self) {
        self.mode = SystemMode::Mode0;
        self.pending_auth = None;
        self.secure_session = None;
    }

    fn sync_overlapping_services(&mut self) {
        let mut registry = BTreeMap::new();
        self.root_area.sync_overlapping_services(&mut registry);
    }

    fn handle_secure_frame(
        &mut self,
        command_code: u8,
        encrypted_payload: &[u8],
    ) -> Option<Vec<u8>> {
        let (transaction_key, transaction_id, service_codes, last_transaction_number) = {
            let session = self.secure_session.as_ref()?;
            (
                session.transaction_key,
                session.transaction_id,
                session.service_codes.clone(),
                session.transaction_number,
            )
        };
        let decrypted = decrypt_des_cbc_zero_iv(encrypted_payload, &transaction_key).ok()?;
        if !check_packet_mac(&decrypted, command_code) {
            return None;
        }
        if decrypted.len() < DES_BLOCK_SIZE {
            return None;
        }
        let (payload, _mac) = decrypted.split_at(decrypted.len() - DES_BLOCK_SIZE);
        if payload.len() < 8 {
            return None;
        }
        let transaction_number = u16::from_le_bytes([payload[0], payload[1]]);
        let mut payload_transaction_id = [0u8; 6];
        payload_transaction_id.copy_from_slice(&payload[2..8]);
        if payload_transaction_id != transaction_id {
            return None;
        }
        if transaction_number <= last_transaction_number {
            return None;
        }
        let response_transaction_number = transaction_number.checked_add(1)?;

        let mut command_payload = payload[8..].to_vec();
        strip_secure_padding(&mut command_payload);
        let command =
            FelicaStandardCommand::parse_secure_payload(command_code, &command_payload).ok()?;

        let response = match command {
            FelicaStandardCommand::Read { block_list } => {
                self.handle_secure_read(&service_codes, &block_list)
            }
            FelicaStandardCommand::Write { block_list, data } => {
                self.handle_secure_write(&service_codes, &block_list, &data)
            }
            FelicaStandardCommand::RegisterIssueId { .. } => {
                FelicaStandardResponse::RegisterIssueId {
                    status_flag1: STATUS_UNSUPPORTED_SF1,
                    status_flag2: STATUS_UNSUPPORTED_SF2,
                    remaining_blocks: None,
                }
            }
            FelicaStandardCommand::RegisterArea { .. } => FelicaStandardResponse::RegisterArea {
                status_flag1: STATUS_UNSUPPORTED_SF1,
                status_flag2: STATUS_UNSUPPORTED_SF2,
            },
            FelicaStandardCommand::RegisterService { .. } => {
                FelicaStandardResponse::RegisterService {
                    status_flag1: STATUS_UNSUPPORTED_SF1,
                    status_flag2: STATUS_UNSUPPORTED_SF2,
                    remaining_blocks: None,
                }
            }
            FelicaStandardCommand::ChangeSystemBlock => FelicaStandardResponse::ChangeSystemBlock {
                status_flag1: STATUS_UNSUPPORTED_SF1,
                status_flag2: STATUS_UNSUPPORTED_SF2,
            },
            _ => return None,
        };
        let response_payload = response.to_secure_payload().ok()?;

        let response_code = command_code.wrapping_add(1);
        let frame = build_secure_response_frame(
            response_code,
            response_transaction_number,
            &transaction_id,
            &transaction_key,
            &response_payload,
        )?;
        if is_register_command(command_code) {
            if response_payload.first() == Some(&0x00) {
                self.mode = SystemMode::Mode3;
            }
        }
        if let Some(session) = self.secure_session.as_mut() {
            session.transaction_number = response_transaction_number;
        }
        Some(frame)
    }

    fn handle_secure_read(
        &self,
        service_codes: &[ServiceCode],
        block_list: &[BlockListElement],
    ) -> FelicaStandardResponse {
        let mut blocks = Vec::with_capacity(block_list.len());
        for (index, block) in block_list.iter().enumerate() {
            let (service_code, block_number) =
                match self.validate_secure_block(service_codes, index, block, AccessType::Read) {
                    Ok(value) => value,
                    Err((sf1, sf2)) => {
                        return FelicaStandardResponse::Read {
                            status_flag1: sf1,
                            status_flag2: sf2,
                            blocks: None,
                        };
                    }
                };
            let service = self.find_service(service_code).unwrap();
            let block_data = {
                let shared = service.blocks.borrow();
                shared[block_number]
            };
            blocks.push(block_data);
        }
        FelicaStandardResponse::Read {
            status_flag1: 0x00,
            status_flag2: 0x00,
            blocks: Some(blocks),
        }
    }

    fn handle_secure_write(
        &mut self,
        service_codes: &[ServiceCode],
        block_list: &[BlockListElement],
        data: &[u8],
    ) -> FelicaStandardResponse {
        let expected_len = block_list.len().saturating_mul(BLOCK_SIZE);
        if data.len() < expected_len {
            return FelicaStandardResponse::Write {
                status_flag1: 0xFF,
                status_flag2: 0xAC,
            };
        }
        let mut updates = Vec::with_capacity(block_list.len());
        for (index, block) in block_list.iter().enumerate() {
            let (service_code, block_number) =
                match self.validate_secure_block(service_codes, index, block, AccessType::Write) {
                    Ok(value) => value,
                    Err((sf1, sf2)) => {
                        return FelicaStandardResponse::Write {
                            status_flag1: sf1,
                            status_flag2: sf2,
                        };
                    }
                };
            let offset = index * BLOCK_SIZE;
            let mut block_data = [0u8; BLOCK_SIZE];
            block_data.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
            updates.push((service_code, block_number, block_data));
        }

        let mut shared_blocks: BTreeMap<u16, SharedBlocks> = BTreeMap::new();
        for (service_code, block_number, block_data) in updates {
            let service_number = service_code.number();
            let shared = if let Some(shared) = shared_blocks.get(&service_number) {
                shared.clone()
            } else {
                let Some(service) = self.find_service(service_code) else {
                    return FelicaStandardResponse::Write {
                        status_flag1: 0xFF,
                        status_flag2: 0xA6,
                    };
                };
                let shared = service.blocks.clone();
                shared_blocks.insert(service_number, shared.clone());
                shared
            };
            let mut blocks = shared.borrow_mut();
            if let Some(slot) = blocks.get_mut(block_number) {
                *slot = block_data;
            }
        }

        FelicaStandardResponse::Write {
            status_flag1: 0x00,
            status_flag2: 0x00,
        }
    }
}

pub struct EmulatedArea {
    area_code: u16,
    key_version: u16,
    key: [u8; 8],
    end_service_code: u16,
    children: Vec<AreaChild>,
}

impl EmulatedArea {
    pub fn new(area_code: u16, end_service_code: u16) -> Result<Self, EmulatorConfigError> {
        validate_area_range(area_code, end_service_code)?;
        Ok(Self {
            area_code,
            key_version: 0x0000,
            key: [0x00; 8],
            end_service_code,
            children: Vec::new(),
        })
    }

    pub fn with_key_version(
        area_code: u16,
        end_service_code: u16,
        key_version: u16,
    ) -> Result<Self, EmulatorConfigError> {
        validate_area_range(area_code, end_service_code)?;
        Ok(Self {
            area_code,
            key_version,
            key: [0x00; 8],
            end_service_code,
            children: Vec::new(),
        })
    }

    pub fn with_end_service_code(
        area_code: u16,
        end_service_code: u16,
    ) -> Result<Self, EmulatorConfigError> {
        Self::new(area_code, end_service_code)
    }

    pub fn area_code(&self) -> u16 {
        self.area_code
    }

    pub fn end_service_code(&self) -> u16 {
        self.end_service_code
    }

    pub fn key_version(&self) -> u16 {
        self.key_version
    }

    pub fn key(&self) -> &[u8; 8] {
        &self.key
    }

    pub fn set_key(&mut self, key: [u8; 8]) -> &mut Self {
        self.key = key;
        self
    }

    pub fn add_service(
        &mut self,
        service: EmulatedService,
    ) -> Result<&mut Self, EmulatorConfigError> {
        self.validate_child_service(&service)?;
        self.children.push(AreaChild::Service(service));
        Ok(self)
    }

    pub fn add_area(&mut self, area: EmulatedArea) -> Result<&mut Self, EmulatorConfigError> {
        self.validate_child_area(&area)?;
        self.children.push(AreaChild::Area(area));
        Ok(self)
    }

    fn validate_child_service(&self, service: &EmulatedService) -> Result<(), EmulatorConfigError> {
        let code = service.service_code.raw();
        if code < self.area_code || code > self.end_service_code {
            return Err(EmulatorConfigError::ServiceOutOfRange {
                area_code: self.area_code,
                end_service_code: self.end_service_code,
                service_code: code,
            });
        }
        Ok(())
    }

    fn validate_child_area(&self, area: &EmulatedArea) -> Result<(), EmulatorConfigError> {
        if area.area_code < self.area_code || area.end_service_code > self.end_service_code {
            return Err(EmulatorConfigError::AreaOutOfRange {
                area_code: self.area_code,
                end_service_code: self.end_service_code,
                child_area_code: area.area_code,
                child_end_service_code: area.end_service_code,
            });
        }
        Ok(())
    }

    fn append_directory_entries(&self, entries: &mut Vec<DirectoryEntry>) {
        let end_service_code = self.end_service_code();
        entries.push(DirectoryEntry::Area {
            area_code: self.area_code,
            end_service_code,
        });

        for child in &self.children {
            match child {
                AreaChild::Area(area) => area.append_directory_entries(entries),
                AreaChild::Service(service) => {
                    entries.push(DirectoryEntry::Service(service.service_code));
                }
            }
        }
    }

    fn append_service_codes(&self, codes: &mut Vec<ServiceCode>) {
        for child in &self.children {
            match child {
                AreaChild::Area(area) => area.append_service_codes(codes),
                AreaChild::Service(service) => codes.push(service.service_code),
            }
        }
    }

    fn find_service(&self, service_code: ServiceCode) -> Option<&EmulatedService> {
        for child in &self.children {
            match child {
                AreaChild::Area(area) => {
                    if let Some(service) = area.find_service(service_code) {
                        return Some(service);
                    }
                }
                AreaChild::Service(service) => {
                    if service.service_code == service_code {
                        return Some(service);
                    }
                }
            }
        }
        None
    }

    fn find_area(&self, area_code: u16) -> Option<&EmulatedArea> {
        if self.area_code == area_code {
            return Some(self);
        }
        for child in &self.children {
            if let AreaChild::Area(area) = child {
                if let Some(found) = area.find_area(area_code) {
                    return Some(found);
                }
            }
        }
        None
    }

    fn total_block_count(&self) -> usize {
        let mut total = 0usize;
        for child in &self.children {
            match child {
                AreaChild::Area(area) => {
                    total = total.saturating_add(area.total_block_count());
                }
                AreaChild::Service(service) => {
                    let block_count = service.blocks.borrow().len();
                    total = total.saturating_add(block_count);
                }
            }
        }
        total
    }

    fn sync_overlapping_services(&mut self, registry: &mut BTreeMap<u16, SharedBlocks>) {
        for child in &mut self.children {
            match child {
                AreaChild::Area(area) => area.sync_overlapping_services(registry),
                AreaChild::Service(service) => {
                    let number = service.service_code.number();
                    if let Some(shared) = registry.get(&number) {
                        service.blocks = shared.clone();
                    } else {
                        registry.insert(number, service.blocks.clone());
                    }
                }
            }
        }
    }
}

pub struct EmulatedService {
    service_code: ServiceCode,
    key_version: u16,
    key: [u8; 8],
    blocks: SharedBlocks,
}

impl EmulatedService {
    pub fn new(service_code: ServiceCode, block_count: usize) -> Self {
        let key_version = if service_code.requires_key() {
            0x0000
        } else {
            0xFFFF
        };
        Self::with_key_version(service_code, key_version, block_count)
    }

    pub fn with_key_version(
        service_code: ServiceCode,
        key_version: u16,
        block_count: usize,
    ) -> Self {
        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            blocks.push([0x00; BLOCK_SIZE]);
        }
        Self {
            service_code,
            key_version,
            key: [0x00; 8],
            blocks: Rc::new(RefCell::new(blocks)),
        }
    }

    pub fn with_blocks(
        service_code: ServiceCode,
        key_version: u16,
        blocks: Vec<[u8; BLOCK_SIZE]>,
    ) -> Self {
        Self {
            service_code,
            key_version,
            key: [0x00; 8],
            blocks: Rc::new(RefCell::new(blocks)),
        }
    }

    pub fn service_code(&self) -> ServiceCode {
        self.service_code
    }

    pub fn key_version(&self) -> u16 {
        self.key_version
    }

    pub fn key(&self) -> &[u8; 8] {
        &self.key
    }

    pub fn set_key(&mut self, key: [u8; 8]) -> &mut Self {
        self.key = key;
        self
    }

    pub fn blocks(&self) -> Ref<'_, [[u8; BLOCK_SIZE]]> {
        Ref::map(self.blocks.borrow(), |blocks| blocks.as_slice())
    }

    pub fn blocks_mut(&self) -> RefMut<'_, [[u8; BLOCK_SIZE]]> {
        RefMut::map(self.blocks.borrow_mut(), |blocks| blocks.as_mut_slice())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DirectoryEntry {
    Service(ServiceCode),
    Area {
        area_code: u16,
        end_service_code: u16,
    },
}

enum AreaChild {
    Area(EmulatedArea),
    Service(EmulatedService),
}

struct PendingAuthentication {
    context: AuthenticationContext,
    random_1: [u8; 8],
    random_2: [u8; 8],
    service_codes: Vec<ServiceCode>,
}

struct SecureSession {
    transaction_number: u16,
    transaction_id: [u8; 6],
    transaction_key: [u8; 8],
    service_codes: Vec<ServiceCode>,
}

enum AccessType {
    Read,
    Write,
}

fn encode_response_frame(response: FelicaStandardResponse) -> Option<Vec<u8>> {
    response.to_frame().ok()
}

fn list_error_index(index: usize) -> u8 {
    let value = index.saturating_add(1);
    if value > u8::MAX as usize {
        u8::MAX
    } else {
        value as u8
    }
}

fn service_allows_write(service_code: ServiceCode) -> bool {
    match service_code.attributes() {
        0b001010 | 0b001011 | 0b001110 | 0b001111 | 0b010110 | 0b010111 => false,
        _ => true,
    }
}

fn validate_area_range(area_code: u16, end_service_code: u16) -> Result<(), EmulatorConfigError> {
    if area_code == ROOT_AREA_CODE && end_service_code != ROOT_END_SERVICE_CODE {
        return Err(EmulatorConfigError::InvalidRootAreaRange { end_service_code });
    }
    if area_code > end_service_code {
        Err(EmulatorConfigError::InvalidAreaRange {
            area_code,
            end_service_code,
        })
    } else {
        Ok(())
    }
}

fn matches_system_code(request: u16, system_code: u16) -> bool {
    let req_hi = (request >> 8) as u8;
    let req_lo = request as u8;
    let sys_hi = (system_code >> 8) as u8;
    let sys_lo = system_code as u8;
    (req_hi == 0xFF || req_hi == sys_hi) && (req_lo == 0xFF || req_lo == sys_lo)
}

fn polling_optional(system_code: u16, request_code: u8) -> Vec<u8> {
    match request_code {
        0x01 => system_code.to_be_bytes().to_vec(),
        0x02 => vec![0x00, 0x00],
        _ => Vec::new(),
    }
}
