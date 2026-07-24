//! In-memory FeliCa Standard card emulator.
//!
//! [`FelicaStandardEmulator`] is the device-level entry point: it owns a set of
//! [`EmulatedSystem`]s, resolves polling/selection across them, and dispatches
//! decoded commands. The per-system protocol logic (reads/writes,
//! authentication, secure messaging) lives in [`system`], and the configurable
//! card structure (areas, services, block data) lives in [`structure`].

mod structure;
mod system;

use super::command::is_secure_command_code;
use super::{
    BLOCK_SIZE, BlockListElement, FelicaStandardCommand, FelicaStandardResponse,
    ReadWithoutEncryptionResult, SearchServiceCodeResult, ServiceCode, Type3TagPollingResult,
    frame_with_length_prefix,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use system::AccessType;

pub use structure::{DirectoryEntry, EmulatedArea, EmulatedService, EmulatorConfigError};
pub use system::EmulatedSystem;

type SharedBlocks = Rc<RefCell<Vec<[u8; BLOCK_SIZE]>>>;

pub struct FelicaStandardEmulator {
    systems: Vec<EmulatedSystem>,
    active_system: Option<u16>,
}

impl Default for FelicaStandardEmulator {
    fn default() -> Self {
        Self::new()
    }
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
        if let Some(active) = self.active_system
            && self.systems.iter().any(|system| {
                system.system_code == active && matches_system_code(request_system_code, active)
            })
        {
            return Some(active);
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
                    mode: system.mode_code(),
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
                        end_service_code: *end_service_code,
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
            FelicaStandardCommand::ResetMode { idm } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get_mut(index)?;
                system.reset_mode();
                encode_response_frame(FelicaStandardResponse::ResetMode {
                    idm,
                    status_flag1: 0x00,
                    status_flag2: 0x00,
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
                                result: None,
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
            result: Some(ReadWithoutEncryptionResult { blocks }),
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
        if let Some(code) = self.active_system
            && self.systems.iter().any(|system| system.system_code == code)
        {
            return Some(code);
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

fn encode_response_frame(response: FelicaStandardResponse) -> Option<Vec<u8>> {
    response.to_frame().ok()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clf::targets::RemoteTarget;
    use crate::driver::errors::{DriverError, Result as DriverResult};
    use crate::felica_standard::secure::generate_service_keys_des;
    use crate::felica_standard::{BlockListElement, EmulatedArea, FelicaDriver, FelicaStandard};

    /// Drives a `FelicaStandard` client straight against an emulated card.
    struct EmulatorDriver<'a> {
        emulator: &'a mut FelicaStandardEmulator,
        idm: [u8; 8],
        pmm: [u8; 8],
    }

    impl FelicaDriver for EmulatorDriver<'_> {
        fn detect_type_f(
            &mut self,
            _target: &RemoteTarget,
            _system_code: u16,
            _request_code: u8,
            _time_slots: u8,
        ) -> DriverResult<Type3TagPollingResult> {
            Ok(Type3TagPollingResult {
                idm: self.idm.to_vec(),
                pmm: self.pmm.to_vec(),
                optional: Vec::new(),
            })
        }

        fn transceive(
            &mut self,
            _target: &RemoteTarget,
            data: &[u8],
            _timeout_ms: Option<u16>,
        ) -> DriverResult<Vec<u8>> {
            self.emulator
                .handle_frame(data)
                .ok_or_else(|| DriverError::other("card rejected frame"))
        }
    }

    /// Authenticating an area must not widen data access: a secure session can
    /// touch only the services named in the service code list, never the other
    /// services that happen to live under the authenticated area.
    #[test]
    fn authenticating_an_area_does_not_grant_access_to_its_other_services() {
        const IDM: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        const PMM: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
        const SYSTEM_KEY: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        const AREA_KEY: [u8; 8] = [0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB, 0xED, 0x0F];
        const AUTHENTICATED_KEY: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        const OTHER_KEY: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];
        // Two "random read/write with key" services sharing one area.
        const AUTHENTICATED_SERVICE: u16 = 0x0048;
        const OTHER_SERVICE: u16 = 0x0088;
        const AUTHENTICATED_BLOCK: [u8; BLOCK_SIZE] = [0xAA; BLOCK_SIZE];
        const OTHER_BLOCK: [u8; BLOCK_SIZE] = [0xBB; BLOCK_SIZE];

        let mut system = EmulatedSystem::new(0x0003, IDM, PMM).expect("system");
        system.set_system_key(SYSTEM_KEY);
        let mut area = EmulatedArea::new(0x0040, 0x00FF).expect("area");
        area.set_key(AREA_KEY);
        let mut authenticated = EmulatedService::with_blocks(
            ServiceCode::new(AUTHENTICATED_SERVICE),
            0x0000,
            vec![AUTHENTICATED_BLOCK],
        );
        authenticated.set_key(AUTHENTICATED_KEY);
        area.add_service(authenticated)
            .expect("authenticated service");
        let mut other = EmulatedService::with_blocks(
            ServiceCode::new(OTHER_SERVICE),
            0x0000,
            vec![OTHER_BLOCK],
        );
        other.set_key(OTHER_KEY);
        area.add_service(other).expect("other service");
        system.add_area(area).expect("area fits");

        let mut emulator = FelicaStandardEmulator::new();
        emulator.add_system(system);

        let mut driver = EmulatorDriver {
            emulator: &mut emulator,
            idm: IDM,
            pmm: PMM,
        };
        let (mut felica, _polling) =
            FelicaStandard::polling(&mut driver, "212F", 0x0003, 0x00, 0x00).expect("polling");

        // Authenticate the area, but name only one of its two services.
        let (group_key, user_key) =
            generate_service_keys_des(&SYSTEM_KEY, &[AREA_KEY], &[AUTHENTICATED_KEY]);
        felica
            .mutual_authentication(
                &[0x0040],
                &[ServiceCode::new(AUTHENTICATED_SERVICE)],
                &group_key,
                &user_key,
            )
            .expect("mutual authentication should succeed");

        // Index 0 is the one authenticated service.
        let blocks = felica
            .read(&[BlockListElement::new(0, 0, 0)])
            .expect("reading the authenticated service should succeed");
        assert_eq!(blocks[0], AUTHENTICATED_BLOCK);

        // The other service in the same area was never named, so there is no
        // second entry in the service code list to address it with.
        assert!(
            felica.read(&[BlockListElement::new(0, 1, 0)]).is_err(),
            "an unnamed service under the authenticated area must not be reachable"
        );
    }

    #[test]
    fn system_code_matching_and_polling_optional() {
        assert!(matches_system_code(0x12AB, 0x12AB));
        assert!(matches_system_code(0x12FF, 0x12AB));
        assert!(matches_system_code(0xFFAB, 0x12AB));
        assert!(matches_system_code(0xFFFF, 0x12AB));
        assert!(!matches_system_code(0x34AB, 0x12AB));

        assert_eq!(polling_optional(0xFE00, 0x01), vec![0xFE, 0x00]);
        assert_eq!(polling_optional(0xFE00, 0x02), vec![0x00, 0x00]);
        assert!(polling_optional(0xFE00, 0x03).is_empty());
    }

    #[test]
    fn emulator_tracks_active_system_and_polling_result() {
        let mut emulator = FelicaStandardEmulator::new();
        assert_eq!(emulator.active_system_code(), None);
        assert!(emulator.system_codes().is_empty());

        let system_a = EmulatedSystem::new(0x12AB, [1; 8], [2; 8]).expect("system A");
        let system_b = EmulatedSystem::new(0x34CD, [3; 8], [4; 8]).expect("system B");
        emulator.add_system(system_a).add_system(system_b);

        assert_eq!(emulator.system_codes(), vec![0x12AB, 0x34CD]);
        assert_eq!(emulator.active_system_code(), Some(0x12AB));
        assert!(!emulator.set_active_system(0x9999));
        assert!(emulator.set_active_system(0x34CD));
        assert_eq!(emulator.active_system_code(), Some(0x34CD));

        let poll = emulator
            .polling_response(0x34FF, 0x01)
            .expect("polling response should resolve wildcard");
        assert_eq!(poll.idm, vec![3; 8]);
        assert_eq!(poll.pmm, vec![4; 8]);
        assert_eq!(poll.optional, vec![0x34, 0xCD]);
        assert_eq!(emulator.active_system_code(), Some(0x34CD));
    }

    #[test]
    fn handle_frame_rejects_invalid_length_prefix() {
        let mut emulator = FelicaStandardEmulator::new();
        let frame = [0x03, 0x00, 0xFF, 0xFF]; // length says 3 but actual length is 4
        assert!(emulator.handle_frame(&frame).is_none());
        assert!(emulator.handle_frame(&[0x01]).is_none());
    }
}
