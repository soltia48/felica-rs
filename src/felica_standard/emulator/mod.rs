//! In-memory FeliCa Standard card emulator.
//!
//! [`FelicaStandardEmulator`] is the device-level entry point: it owns a set of
//! [`EmulatedSystem`]s, resolves polling/selection across them, and dispatches
//! decoded commands. The per-system protocol logic (reads/writes,
//! authentication, secure messaging) lives in [`system`], and the configurable
//! card structure (areas, services, block data) lives in [`structure`].

mod blocks;
mod structure;
mod system;

use super::command::is_secure_command_code;
use super::{
    BLOCK_SIZE, BlockListElement, FelicaStandardCommand, FelicaStandardResponse,
    ReadWithoutEncryptionResult, SearchServiceCodeResult, ServiceCode, Type3TagPollingResult,
    frame_with_length_prefix,
};
use std::cell::RefCell;
use std::rc::Rc;
use system::ModeRequirement;

pub use structure::{
    DirectoryEntry, EmulatedArea, EmulatedService, EmulatorConfigError, LimitPurseProperty,
};
pub use system::{CommunicationPerformance, EmulatedSystem};

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

    /// Models the card leaving the reader's field: every system returns to Mode0
    /// and any authentication in progress is discarded.
    ///
    /// §4.3: "電源供給が絶たれた場合は、モードは維持されず、再電源供給時に Mode0 と
    /// なります". A host driving this emulator should call it whenever the RF field
    /// drops, because a system left in Mode1 or above stops answering Polling
    /// commands addressed to it and would otherwise never become reachable again.
    pub fn power_off(&mut self) -> &mut Self {
        for system in &mut self.systems {
            system.reset_mode();
        }
        self.active_system = self.systems.first().map(|system| system.system_code);
        self
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
        let optional = polling_optional(system, request_code);
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
        let optional = polling_optional(system, request_code);
        Some(Type3TagPollingResult {
            idm: system.idm.to_vec(),
            pmm: system.pmm.to_vec(),
            optional,
        })
    }

    /// Build the SENSF_RES payload (without the length byte) for a polling request.
    ///
    /// This resolves the addressed system exactly as [`handle_command`] does,
    /// applying §4.4.2's system-0-first matching and §4.3's rule that a card
    /// outside Mode0 ignores a Polling aimed at the system it is already talking
    /// to. `None` means the card would not answer.
    ///
    /// [`handle_command`]: Self::handle_command
    pub fn polling_response(
        &mut self,
        request_system_code: u16,
        request_code: u8,
    ) -> Option<Type3TagPollingResult> {
        let index = self.system_index_for_polling(request_system_code)?;
        let system = self.systems.get(index)?;
        Some(Type3TagPollingResult {
            idm: system.idm.to_vec(),
            pmm: system.pmm.to_vec(),
            optional: polling_optional(system, request_code),
        })
    }

    /// Build a length-prefixed SENSF_RES frame for a given system code.
    pub fn sensf_res_frame_for(&self, system_code: u16) -> Option<Vec<u8>> {
        let payload = self.sensf_res_for(system_code)?;
        frame_with_length_prefix(&payload).ok()
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
                let optional = polling_optional(system, request_code);
                encode_response_frame(FelicaStandardResponse::Polling {
                    idm: system.idm,
                    pmm: system.pmm,
                    optional,
                })
            }
            FelicaStandardCommand::RequestResponse { idm } => {
                let index = self.system_index_for_idm(&idm, ModeRequirement::AnyMode)?;
                let system = self.systems.get(index)?;
                encode_response_frame(FelicaStandardResponse::RequestResponse {
                    idm,
                    mode: system.mode_code(),
                })
            }
            FelicaStandardCommand::RequestSystemCode { idm } => {
                self.system_index_for_idm(&idm, ModeRequirement::AnyMode)?;
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
                let index = self.system_index_for_idm(&idm, ModeRequirement::AnyMode)?;
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
                let index = self.system_index_for_idm(&idm, ModeRequirement::AnyMode)?;
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
                // Table 4-1 lists Read Without Encryption for Mode0 only.
                let index = self.system_index_for_idm(&idm, ModeRequirement::Unauthenticated)?;
                let system = self.systems.get(index)?;
                Self::handle_read(idm, system, &service_codes, &block_list)
            }
            FelicaStandardCommand::WriteWithoutEncryption {
                idm,
                service_codes,
                block_list,
                data,
            } => {
                // Table 4-1 lists Write Without Encryption for Mode0 only.
                let index = self.system_index_for_idm(&idm, ModeRequirement::Unauthenticated)?;
                let system = self.systems.get_mut(index)?;
                Self::handle_write(idm, system, &service_codes, &block_list, &data)
            }
            FelicaStandardCommand::RequestBlockInformation { idm, node_codes } => {
                let index = self.system_index_for_idm(&idm, ModeRequirement::AnyMode)?;
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
                let index = self.system_index_for_idm(&idm, ModeRequirement::AnyMode)?;
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
                // Table 4-1: Authentication1 runs in any mode and lands in Mode1.
                let index = self.system_index_for_idm(&idm, ModeRequirement::AnyMode)?;
                let system = self.systems.get_mut(index)?;
                system.handle_authentication1(idm, &areas, &services, challenge_1a)
            }
            FelicaStandardCommand::Authentication2 { idm, challenge_2b } => {
                // Table 4-1 lists Authentication2 for Mode1 (1->2) and Mode2 (2->2).
                let index =
                    self.system_index_for_idm(&idm, ModeRequirement::AuthenticationStarted)?;
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
            // §4.4.5: Read Without Encryption reaches only services whose
            // attribute is "認証不要".
            let (service_code, block_number) =
                match system.validate_read_block(service_codes, index, block, true) {
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
        let (status_flag1, status_flag2) =
            match system.apply_block_writes(service_codes, block_list, data, true) {
                Ok(()) => (0x00, 0x00),
                Err(flags) => flags,
            };
        encode_response_frame(FelicaStandardResponse::WriteWithoutEncryption {
            idm,
            status_flag1,
            status_flag2,
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

    /// Resolves the system a command's IDm addresses, applying system switching
    /// and the mode restrictions of §4.3.
    ///
    /// A command carrying another system's IDm switches to that system (§3.2.4),
    /// which drops it to Mode0. `requirement` is then checked against the mode the
    /// addressed system is actually in; `None` means the card stays silent, which
    /// is how table 4-1's "－" behaves.
    fn system_index_for_idm(
        &mut self,
        idm: &[u8; 8],
        requirement: ModeRequirement,
    ) -> Option<usize> {
        let index = self.systems.iter().position(|system| &system.idm == idm)?;
        let system_code = self.systems[index].system_code;
        if self.active_system != Some(system_code) {
            self.systems[index].reset_mode();
            self.active_system = Some(system_code);
        }
        if !self.systems[index].mode_permits(requirement) {
            return None;
        }
        Some(index)
    }

    /// Resolves the system a Polling command addresses, applying §4.3's rule that
    /// only a Polling aimed at another system may be answered outside Mode0.
    fn system_index_for_polling(&mut self, request_system_code: u16) -> Option<usize> {
        let index = self.polling_target_index(request_system_code)?;
        let resolved = self.systems[index].system_code;

        if self.active_system == Some(resolved) {
            // "Mode0 以外へ遷移すると、Polling コマンドを受け付けなくなります。これは、
            // IDm をすでに取得したカードが Polling コマンドに返答しないことで、カードか
            // らの返答の衝突を軽減させるためです" (§4.3). Table 4-1 accordingly lists
            // Polling addressed to the current system for Mode0 alone, and a
            // rejected Polling leaves the mode untouched.
            if !self.systems[index].mode_permits(ModeRequirement::Unauthenticated) {
                return None;
            }
        } else {
            // A Polling naming a different system of the same card is system
            // switching, which §3.2.4 permits in any mode and which lands the
            // newly selected system in Mode0.
            self.systems[index].reset_mode();
        }

        self.active_system = Some(resolved);
        Some(index)
    }

    /// Finds the system whose system code matches, comparing from system 0 upward.
    ///
    /// §4.4.2: "カードのシステムが分割されていた場合は、まずシステム 0 に対してシステム
    /// コードの比較が行われ、順次、システム 1 以降のシステムに対して比較が行われます。
    /// したがって、システムコードの両バイトにワイルドカードを指定（FFFFh）した場合は常に
    /// システム 0 が応答します". The order is fixed by the card layout, so the system
    /// currently being talked to gets no precedence.
    fn polling_target_index(&self, request_system_code: u16) -> Option<usize> {
        self.systems
            .iter()
            .position(|system| matches_system_code(request_system_code, system.system_code))
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

/// Builds the Polling response's request data for a request code (§4.4.2, table 4-7).
///
/// A request code the card does not answer contributes nothing, which table 4-7
/// says is handled exactly as request code `00h`.
fn polling_optional(system: &EmulatedSystem, request_code: u8) -> Vec<u8> {
    match request_code {
        0x01 => system.system_code.to_be_bytes().to_vec(),
        0x02 => system
            .communication_performance()
            .to_request_data()
            .to_vec(),
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

        let mut system = EmulatedSystem::new(0xFE00, [1; 8], [2; 8]).expect("system");
        assert_eq!(polling_optional(&system, 0x01), vec![0xFE, 0x00]);
        // Table 4-8: D0 is fixed at 00h; in D1, b0 is 212 kbps and b1 is 424 kbps.
        // The default reports both, since a card that answers a Polling command at
        // all can communicate.
        assert_eq!(polling_optional(&system, 0x02), vec![0x00, 0b0000_0011]);
        // Table 4-7: a request code the product does not support returns no request
        // data, exactly as 00h does.
        assert!(polling_optional(&system, 0x00).is_empty());
        assert!(polling_optional(&system, 0x03).is_empty());

        system.set_communication_performance(CommunicationPerformance {
            supports_212_kbps: true,
            supports_424_kbps: false,
            supports_automatic_bitrate_detection: true,
        });
        assert_eq!(polling_optional(&system, 0x02), vec![0x00, 0b1000_0001]);
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

    /// Builds a one-system card: an auth-free random service, an auth-free cyclic
    /// service and an auth-free purse (cashback/decrement) service under area
    /// 0x1000.
    fn card() -> FelicaStandardEmulator {
        let mut system = EmulatedSystem::new(0x1234, [0x11; 8], [0x22; 8]).expect("system");
        let mut area = EmulatedArea::new(0x1000, 0x1FFF).expect("area");
        // 0x1049: random read/write, authentication not required.
        area.add_service(EmulatedService::new(ServiceCode::new(0x1049), 2))
            .expect("random service");
        // 0x108D: cyclic read/write, authentication not required.
        area.add_service(EmulatedService::new(ServiceCode::new(0x108D), 3))
            .expect("cyclic service");
        // 0x10D3: purse cashback/decrement, authentication not required.
        area.add_service(EmulatedService::with_blocks(
            ServiceCode::new(0x10D3),
            0xFFFF,
            vec![purse_block(1_000, 0, [0x00; 4])],
        ))
        .expect("purse service");
        // 0x1008: random read/write, authentication required.
        area.add_service(EmulatedService::new(ServiceCode::new(0x1008), 1))
            .expect("auth-required service");
        system.add_area(area).expect("area fits");

        let mut emulator = FelicaStandardEmulator::new();
        emulator.add_system(system);
        emulator
    }

    fn purse_block(purse: u32, cashback: u32, execution_id: [u8; 4]) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        block[0..4].copy_from_slice(&purse.to_le_bytes());
        block[4..8].copy_from_slice(&cashback.to_le_bytes());
        block[12..16].copy_from_slice(&execution_id);
        block
    }

    fn read(emulator: &mut FelicaStandardEmulator, service: u16, block: u16) -> Option<Vec<u8>> {
        emulator.handle_command(FelicaStandardCommand::ReadWithoutEncryption {
            idm: [0x11; 8],
            service_codes: vec![ServiceCode::new(service)],
            block_list: vec![BlockListElement::new(block, 0, 0)],
        })
    }

    /// Returns (status flag 1, status flag 2) from a Write Without Encryption.
    fn write(
        emulator: &mut FelicaStandardEmulator,
        service: u16,
        elements: &[BlockListElement],
        data: &[u8],
    ) -> (u8, u8) {
        let frame = emulator
            .handle_command(FelicaStandardCommand::WriteWithoutEncryption {
                idm: [0x11; 8],
                service_codes: vec![ServiceCode::new(service)],
                block_list: elements.to_vec(),
                data: data.to_vec(),
            })
            .expect("the card answers a Write Without Encryption in Mode0");
        (frame[10], frame[11])
    }

    fn authenticate_to_mode1(emulator: &mut FelicaStandardEmulator) {
        emulator
            .handle_command(FelicaStandardCommand::Authentication1 {
                idm: [0x11; 8],
                areas: vec![0x1000],
                services: vec![0x1008],
                challenge_1a: [0u8; 8],
            })
            .expect("Authentication1 is accepted in Mode0");
    }

    fn current_mode(emulator: &mut FelicaStandardEmulator) -> u8 {
        let frame = emulator
            .handle_command(FelicaStandardCommand::RequestResponse { idm: [0x11; 8] })
            .expect("Request Response runs in every mode");
        frame[10]
    }

    /// Table 4-1 lists Read/Write Without Encryption and a Polling addressed to
    /// the current system for Mode0 alone; in any other mode the card stays silent
    /// and keeps its mode.
    #[test]
    fn commands_restricted_to_mode0_draw_no_response_in_mode1() {
        let mut emulator = card();
        authenticate_to_mode1(&mut emulator);
        assert_eq!(current_mode(&mut emulator), 0x01);

        assert!(
            read(&mut emulator, 0x1049, 0).is_none(),
            "Read Without Encryption is not executable in Mode1"
        );
        assert!(
            emulator
                .handle_command(FelicaStandardCommand::WriteWithoutEncryption {
                    idm: [0x11; 8],
                    service_codes: vec![ServiceCode::new(0x1049)],
                    block_list: vec![BlockListElement::new(0, 0, 0)],
                    data: vec![0xAA; BLOCK_SIZE],
                })
                .is_none(),
            "Write Without Encryption is not executable in Mode1"
        );
        assert!(
            emulator
                .handle_command(FelicaStandardCommand::Polling {
                    system_code: 0x1234,
                    request_code: 0x00,
                    time_slots: 0x00,
                })
                .is_none(),
            "a Polling addressed to the current system is not executable in Mode1"
        );

        // A rejected command leaves the mode alone, and the commands table 4-1
        // lists for every mode still work.
        assert_eq!(current_mode(&mut emulator), 0x01);
        assert!(
            emulator
                .handle_command(FelicaStandardCommand::RequestSystemCode { idm: [0x11; 8] })
                .is_some(),
            "Request System Code runs in every mode"
        );

        // Reset Mode returns to Mode0, where the Mode0 commands work again.
        emulator
            .handle_command(FelicaStandardCommand::ResetMode { idm: [0x11; 8] })
            .expect("Reset Mode runs in every mode");
        assert_eq!(current_mode(&mut emulator), 0x00);
        assert!(read(&mut emulator, 0x1049, 0).is_some());
    }

    /// §3.2.4: a Polling naming another system of the same card switches to it,
    /// which is allowed in any mode and lands in Mode0.
    #[test]
    fn polling_another_system_switches_and_resets_the_mode() {
        let mut emulator = card();
        let second = EmulatedSystem::new(0x5678, [0x33; 8], [0x44; 8]).expect("second system");
        emulator.add_system(second);

        authenticate_to_mode1(&mut emulator);
        assert_eq!(current_mode(&mut emulator), 0x01);

        // Polling the sleeping system is answered even though system 0x1234 is in
        // Mode1, and the newly selected system starts in Mode0.
        let frame = emulator
            .handle_command(FelicaStandardCommand::Polling {
                system_code: 0x5678,
                request_code: 0x01,
                time_slots: 0x00,
            })
            .expect("a Polling addressed to a sleeping system is answered in any mode");
        assert_eq!(&frame[2..10], &[0x33; 8], "the second system answered");
        assert_eq!(emulator.active_system_code(), Some(0x5678));

        // §4.4.2: matching runs from system 0 upward, so a fully wildcarded
        // Polling always brings back system 0 even while another one is selected.
        let frame = emulator
            .handle_command(FelicaStandardCommand::Polling {
                system_code: 0xFFFF,
                request_code: 0x00,
                time_slots: 0x00,
            })
            .expect("0xFFFF always matches system 0");
        assert_eq!(&frame[2..10], &[0x11; 8]);
        assert_eq!(emulator.active_system_code(), Some(0x1234));
    }

    /// §4.4.2: comparison starts at system 0, so a half-wildcarded system code that
    /// matches two systems selects the lower-numbered one regardless of which is
    /// currently selected. `polling_response` must agree with `handle_command`.
    #[test]
    fn wildcard_polling_matches_from_system_zero_in_both_entry_points() {
        let mut emulator = FelicaStandardEmulator::new();
        emulator.add_system(EmulatedSystem::new(0x12AB, [1; 8], [2; 8]).expect("system 0"));
        emulator.add_system(EmulatedSystem::new(0x12CD, [3; 8], [4; 8]).expect("system 1"));

        // Select system 1, then poll with a code that matches both.
        assert!(emulator.set_active_system(0x12CD));
        let poll = emulator
            .polling_response(0x12FF, 0x01)
            .expect("the low byte wildcard matches both systems");
        assert_eq!(poll.idm, vec![1; 8], "system 0 answers first");
        assert_eq!(poll.optional, vec![0x12, 0xAB]);

        assert!(emulator.set_active_system(0x12CD));
        let frame = emulator
            .handle_command(FelicaStandardCommand::Polling {
                system_code: 0x12FF,
                request_code: 0x00,
                time_slots: 0x00,
            })
            .expect("handle_command resolves the same system");
        assert_eq!(&frame[2..10], &[1; 8]);
    }

    /// §4.4.5/§4.4.6 with table 4-12: a service code list entry naming the system
    /// or an area is A4h (service type invalid), a service code that simply is not
    /// registered is A6h, and an out-of-range service list index is A3h.
    #[test]
    fn block_list_errors_report_the_status_flag_2_of_table_4_12() {
        let mut emulator = card();

        let cases = [
            // The system node is not a service.
            (0xFFFFu16, 0xA4u8),
            // 0x1000 is the area code of the area holding these services.
            (0x1000, 0xA4),
            // 0x1F49 is a well-formed service code that is not registered.
            (0x1F49, 0xA6),
        ];
        for (service_code, expected_sf2) in cases {
            let frame = emulator
                .handle_command(FelicaStandardCommand::ReadWithoutEncryption {
                    idm: [0x11; 8],
                    service_codes: vec![ServiceCode::new(service_code)],
                    block_list: vec![BlockListElement::new(0, 0, 0)],
                })
                .expect("the card answers with a status");
            assert_eq!(frame[10], 0x01, "error at the first list entry");
            assert_eq!(
                frame[11], expected_sf2,
                "service code {service_code:#06X} should report {expected_sf2:#04X}"
            );
        }

        // Service list index 1 with only one service in the list -> A3h.
        let frame = emulator
            .handle_command(FelicaStandardCommand::ReadWithoutEncryption {
                idm: [0x11; 8],
                service_codes: vec![ServiceCode::new(0x1049)],
                block_list: vec![BlockListElement::new(0, 1, 0)],
            })
            .expect("the card answers with a status");
        assert_eq!((frame[10], frame[11]), (0x01, 0xA3));

        // A block number past the service's block count -> A8h.
        let frame = emulator
            .handle_command(FelicaStandardCommand::ReadWithoutEncryption {
                idm: [0x11; 8],
                service_codes: vec![ServiceCode::new(0x1049)],
                block_list: vec![BlockListElement::new(2, 0, 0)],
            })
            .expect("the card answers with a status");
        assert_eq!((frame[10], frame[11]), (0x01, 0xA8));

        // An authentication-required service is out of reach for the plain read -> A5h.
        let frame = read(&mut emulator, 0x1008, 0).expect("the card answers with a status");
        assert_eq!((frame[10], frame[11]), (0x01, 0xA5));

        // §4.4.5 permits access mode 000b only on a read -> A7h.
        let frame = emulator
            .handle_command(FelicaStandardCommand::ReadWithoutEncryption {
                idm: [0x11; 8],
                service_codes: vec![ServiceCode::new(0x1049)],
                block_list: vec![BlockListElement::new(0, 0, 1)],
            })
            .expect("the card answers with a status");
        assert_eq!((frame[10], frame[11]), (0x01, 0xA7));
    }

    /// §4.4.6: access mode 001b is legal on a write, provided the service offers
    /// the cashback function.
    #[test]
    fn cashback_access_mode_is_accepted_only_on_a_cashback_service() {
        let mut emulator = card();

        // Deduct 400 from the purse so there is something to give back.
        let element = BlockListElement::new(0, 0, 0);
        assert_eq!(
            write(
                &mut emulator,
                0x10D3,
                &[element],
                &purse_block(400, 0, [0x01; 4])
            ),
            (0x00, 0x00)
        );
        let frame = read(&mut emulator, 0x10D3, 0).expect("read back");
        assert_eq!(&frame[13..17], &600u32.to_le_bytes(), "purse decremented");
        assert_eq!(&frame[17..21], &400u32.to_le_bytes(), "cashback recorded");

        // Access mode 001b gives 250 of it back.
        let cashback = BlockListElement::new(0, 0, 1);
        assert_eq!(
            write(
                &mut emulator,
                0x10D3,
                &[cashback],
                &purse_block(250, 0, [0x02; 4])
            ),
            (0x00, 0x00),
            "access mode 001b is accepted on a purse cashback service"
        );
        let frame = read(&mut emulator, 0x10D3, 0).expect("read back");
        assert_eq!(&frame[13..17], &850u32.to_le_bytes());
        assert_eq!(&frame[17..21], &0u32.to_le_bytes(), "cashback data cleared");

        // The same access mode on a random service is A5h, not A7h: the mode is a
        // legal write mode, the service just does not offer cashback.
        assert_eq!(
            write(&mut emulator, 0x1049, &[cashback], &[0xAA; BLOCK_SIZE]),
            (0x01, 0xA5)
        );
    }

    /// §3.4.3: a cyclic write always lands on the newest slot, must address block
    /// number 0, and rotates the ring.
    #[test]
    fn cyclic_service_writes_rotate_the_ring() {
        let mut emulator = card();
        let newest = BlockListElement::new(0, 0, 0);

        for value in [0xA1u8, 0xA2, 0xA3, 0xA4] {
            assert_eq!(
                write(&mut emulator, 0x108D, &[newest], &[value; BLOCK_SIZE]),
                (0x00, 0x00)
            );
        }

        // Generations 0..2 are the last three entries, newest first; 0xA1 has been
        // pushed off the end of the three-block ring.
        for (block, expected) in [(0u16, 0xA4u8), (1, 0xA3), (2, 0xA2)] {
            let frame = read(&mut emulator, 0x108D, block).expect("read back");
            assert_eq!(frame[13], expected, "generation {block}");
        }

        // "書き込み時は、常にブロック番号に 0 を指定する必要があります".
        assert_eq!(
            write(
                &mut emulator,
                0x108D,
                &[BlockListElement::new(1, 0, 0)],
                &[0xB0; BLOCK_SIZE]
            ),
            (0x01, 0xA5)
        );

        // Writing the same newest generation again is recognised as a repeat and
        // completes without appending (§3.4.3).
        assert_eq!(
            write(&mut emulator, 0x108D, &[newest], &[0xA4; BLOCK_SIZE]),
            (0x00, 0x00)
        );
        let frame = read(&mut emulator, 0x108D, 1).expect("read back");
        assert_eq!(frame[13], 0xA3, "the ring did not rotate");

        // Table 4-12: more simultaneous writes than the ring holds is AFh.
        let mut data = Vec::new();
        for value in [0xC1u8, 0xC2, 0xC3, 0xC4] {
            data.extend_from_slice(&[value; BLOCK_SIZE]);
        }
        assert_eq!(
            write(&mut emulator, 0x108D, &[newest; 4], &data),
            (0x01, 0xAF)
        );
    }

    /// §3.4.4: a re-sent purse write that repeats the execution ID completes
    /// normally without deducting again.
    #[test]
    fn a_resent_purse_write_does_not_deduct_twice() {
        let mut emulator = card();
        let element = BlockListElement::new(0, 0, 0);
        let command = purse_block(150, 0, [0x0A; 4]);

        assert_eq!(write(&mut emulator, 0x10D3, &[element], &command), (0, 0));
        let frame = read(&mut emulator, 0x10D3, 0).expect("read back");
        assert_eq!(&frame[13..17], &850u32.to_le_bytes());

        // The retry carries the same execution ID.
        assert_eq!(write(&mut emulator, 0x10D3, &[element], &command), (0, 0));
        let frame = read(&mut emulator, 0x10D3, 0).expect("read back");
        assert_eq!(
            &frame[13..17],
            &850u32.to_le_bytes(),
            "the balance did not move a second time"
        );
    }

    /// §3.6.1: a command's writes are applied completely or not at all, so a block
    /// list whose later element fails must leave the earlier blocks untouched.
    #[test]
    fn a_failing_element_rolls_back_the_whole_command() {
        let mut emulator = card();
        let data = [[0xAA; BLOCK_SIZE], [0xBB; BLOCK_SIZE]].concat();

        // The second element addresses a block past the end of the service.
        let (sf1, sf2) = write(
            &mut emulator,
            0x1049,
            &[
                BlockListElement::new(0, 0, 0),
                BlockListElement::new(9, 0, 0),
            ],
            &data,
        );
        assert_eq!((sf1, sf2), (0x02, 0xA8), "the second element failed");

        let frame = read(&mut emulator, 0x1049, 0).expect("read back");
        assert_eq!(
            &frame[13..29],
            &[0x00; BLOCK_SIZE],
            "the first element must not have been written"
        );
    }

    /// §3.4.4.1: a limit purse confines the purse value to its limits and reports a
    /// breach as 03h.
    #[test]
    fn a_limit_purse_service_enforces_its_limits() {
        let mut system = EmulatedSystem::new(0x1234, [0x11; 8], [0x22; 8]).expect("system");
        let mut area = EmulatedArea::new(0x1000, 0x1FFF).expect("area");
        let mut purse = EmulatedService::with_blocks(
            ServiceCode::new(0x10D3),
            0xFFFF,
            vec![purse_block(500, 0, [0x00; 4])],
        );
        purse.set_limit_purse(LimitPurseProperty {
            upper_limit: 1_000,
            lower_limit: 100,
            generation_number: 1,
        });
        area.add_service(purse).expect("limit purse service");
        system.add_area(area).expect("area fits");
        let mut emulator = FelicaStandardEmulator::new();
        emulator.add_system(system);

        let element = BlockListElement::new(0, 0, 0);
        // Down to the lower limit is fine.
        assert_eq!(
            write(
                &mut emulator,
                0x10D3,
                &[element],
                &purse_block(400, 0, [0x01; 4])
            ),
            (0x00, 0x00)
        );
        // One more would breach it.
        assert_eq!(
            write(
                &mut emulator,
                0x10D3,
                &[element],
                &purse_block(1, 0, [0x02; 4])
            ),
            (0x01, 0x03)
        );
    }

    /// §4.3: modes do not survive power loss, so a card that left the field is
    /// reachable again from Mode0.
    #[test]
    fn power_off_returns_every_system_to_mode0() {
        let mut emulator = card();
        authenticate_to_mode1(&mut emulator);
        assert_eq!(current_mode(&mut emulator), 0x01);
        assert!(
            emulator
                .handle_command(FelicaStandardCommand::Polling {
                    system_code: 0x1234,
                    request_code: 0x00,
                    time_slots: 0x00,
                })
                .is_none(),
            "a card above Mode0 ignores Polling addressed to it"
        );

        emulator.power_off();

        assert_eq!(current_mode(&mut emulator), 0x00);
        assert!(
            emulator
                .handle_command(FelicaStandardCommand::Polling {
                    system_code: 0x1234,
                    request_code: 0x00,
                    time_slots: 0x00,
                })
                .is_some(),
            "after power loss the card answers Polling again"
        );
    }
}
