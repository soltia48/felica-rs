//! One emulated FeliCa system: its identity, keys, mode state, and the command
//! handling that reads/writes the [`super::structure`] tree, runs DES mutual
//! authentication, and processes secure-messaging frames.

use super::SharedBlocks;
use super::blocks::{CyclicWrite, PurseOperation, apply_cyclic_write, apply_purse_write};
use super::encode_response_frame;
use super::structure::{
    DirectoryEntry, EmulatedArea, EmulatedService, EmulatorConfigError, LimitPurseProperty,
    ROOT_AREA_CODE, ROOT_END_SERVICE_CODE,
};
use crate::felica_standard::command::is_register_command;
use crate::felica_standard::secure::{
    AuthenticationContext, build_authentication2_payload, build_secure_response_frame_des,
    check_packet_mac_des, ct_eq, decrypt_des_cbc_zero_iv, encrypt_authentication2_payload,
    generate_service_keys_des,
};
use crate::felica_standard::{
    Authentication2Response, BLOCK_SIZE, BlockListElement, DES_BLOCK_SIZE, FelicaStandardCommand,
    FelicaStandardResponse, ReadResult, ServiceAttribute, ServiceCode, ServiceKind,
};
use std::collections::BTreeMap;

const STATUS_UNSUPPORTED_SF1: u8 = 0xFF;
const STATUS_UNSUPPORTED_SF2: u8 = 0xC2;

const SYSTEM_NODE_CODE: u16 = 0xFFFF;

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

/// Which modes §4.3 (table 4-1) lets a command run in.
///
/// A command sent in a mode it is not listed for draws no response at all and
/// leaves the mode untouched — the table's "－" — rather than an error status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ModeRequirement {
    /// Runs in every mode and leaves it unchanged: Request Service, Request
    /// Response, Search Service Code, Request System Code.
    AnyMode,
    /// Runs only in Mode0: Read Without Encryption, Write Without Encryption,
    /// and Polling addressed to the system currently communicating.
    Unauthenticated,
    /// Runs in Mode1 and Mode2: Authentication2.
    AuthenticationStarted,
    /// Runs only in Mode2: Read, Write.
    Authenticated,
    /// Runs in Mode2 and Mode3: the issuing commands, which move the card to
    /// Mode3 and may then be repeated there.
    Issuing,
}

/// The communication performance a card reports for Polling request code `02h`
/// (§4.4.2, table 4-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommunicationPerformance {
    /// b0 of D1: able to communicate at 212 kbps.
    pub supports_212_kbps: bool,
    /// b1 of D1: able to communicate at 424 kbps.
    pub supports_424_kbps: bool,
    /// b7 of D1: supports automatic bitrate detection.
    pub supports_automatic_bitrate_detection: bool,
}

impl Default for CommunicationPerformance {
    fn default() -> Self {
        // FeliCa defines exactly two data rates (§2.1, table 2-1) and both are
        // what a reader polls at, so a card that answers at all supports 212 kbps
        // at minimum. Reporting neither — as an all-zero response does — would
        // contradict the response itself.
        Self {
            supports_212_kbps: true,
            supports_424_kbps: true,
            supports_automatic_bitrate_detection: false,
        }
    }
}

impl CommunicationPerformance {
    /// Encodes the two request data bytes of table 4-8, D0 first.
    ///
    /// D0 is fixed at `00h`, and in D1 the 848 kbps and 1.6 Mbps bits plus b6-b4
    /// are reserved and stay zero.
    pub(super) fn to_request_data(self) -> [u8; 2] {
        let mut d1 = 0u8;
        if self.supports_212_kbps {
            d1 |= 0b0000_0001;
        }
        if self.supports_424_kbps {
            d1 |= 0b0000_0010;
        }
        if self.supports_automatic_bitrate_detection {
            d1 |= 0b1000_0000;
        }
        [0x00, d1]
    }
}

pub struct EmulatedSystem {
    pub(super) system_code: u16,
    pub(super) idm: [u8; 8],
    pub(super) pmm: [u8; 8],
    root_area: EmulatedArea,
    mode: SystemMode,
    system_key_version: u16,
    system_key: [u8; 8],
    idi: [u8; 8],
    pmi: [u8; 8],
    communication_performance: CommunicationPerformance,
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
            communication_performance: CommunicationPerformance::default(),
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
        self.sync_overlapping_services()?;
        Ok(self)
    }

    pub fn add_area(&mut self, area: EmulatedArea) -> Result<&mut Self, EmulatorConfigError> {
        self.root_area.add_area(area)?;
        self.sync_overlapping_services()?;
        Ok(self)
    }

    pub fn directory(&self) -> Vec<DirectoryEntry> {
        let mut entries = Vec::new();
        self.root_area.append_directory_entries(&mut entries);
        entries
    }

    /// What this system reports for Polling request code `02h` (§4.4.2, table 4-8).
    pub fn communication_performance(&self) -> CommunicationPerformance {
        self.communication_performance
    }

    pub fn set_communication_performance(
        &mut self,
        performance: CommunicationPerformance,
    ) -> &mut Self {
        self.communication_performance = performance;
        self
    }

    pub(super) fn mode_code(&self) -> u8 {
        self.mode.code()
    }

    /// Whether §4.3 (table 4-1) lets a command with this mode requirement run in
    /// the system's current mode.
    pub(super) fn mode_permits(&self, requirement: ModeRequirement) -> bool {
        match requirement {
            ModeRequirement::AnyMode => true,
            ModeRequirement::Unauthenticated => self.mode == SystemMode::Mode0,
            ModeRequirement::AuthenticationStarted => {
                matches!(self.mode, SystemMode::Mode1 | SystemMode::Mode2)
            }
            ModeRequirement::Authenticated => self.mode == SystemMode::Mode2,
            ModeRequirement::Issuing => {
                matches!(self.mode, SystemMode::Mode2 | SystemMode::Mode3)
            }
        }
    }

    pub(super) fn find_service(&self, service_code: ServiceCode) -> Option<&EmulatedService> {
        self.root_area.find_service(service_code)
    }

    fn find_area(&self, area_code: u16) -> Option<&EmulatedArea> {
        self.root_area.find_area(area_code)
    }

    pub(super) fn node_key_version(&self, node_code: ServiceCode) -> u16 {
        if node_code.raw() == 0xFFFF {
            return self.system_key_version;
        }
        if let Some(service) = self.find_service(node_code) {
            if service.service_code().requires_key() {
                return service.key_version();
            }
            return 0xFFFF;
        }
        if let Some(area) = self.find_area(node_code.raw()) {
            return area.key_version();
        }
        0xFFFF
    }

    fn area_list_well_formed(&self, areas: &[u16]) -> bool {
        let Some(&first) = areas.first() else {
            return false;
        };
        if first == SYSTEM_NODE_CODE || self.find_area(first).is_none() {
            return false;
        }
        areas
            .iter()
            .all(|&code| code == SYSTEM_NODE_CODE || self.find_area(code).is_some())
    }

    fn service_list_well_formed(services: &[u16]) -> bool {
        let mut has_auth_required = false;
        let mut seen_auth_free = false;
        for &raw in services {
            // The system code (0xFFFF) may appear in the service code list; it is an
            // authentication-required node even though its low bit reads as key-free.
            if raw == SYSTEM_NODE_CODE || ServiceCode::new(raw).requires_key() {
                if seen_auth_free {
                    return false;
                }
                has_auth_required = true;
            } else {
                seen_auth_free = true;
            }
        }
        has_auth_required
    }

    pub(super) fn handle_authentication1(
        &mut self,
        idm: [u8; 8],
        areas: &[u16],
        services: &[u16],
        challenge_1a: [u8; 8],
    ) -> Option<Vec<u8>> {
        if !self.area_list_well_formed(areas) || !Self::service_list_well_formed(services) {
            return None;
        }

        let system_key = self.system_key;
        let mut area_keys = Vec::with_capacity(areas.len());
        let mut service_keys = Vec::new();
        let mut service_codes = Vec::new();
        for &area_code in areas {
            if area_code == SYSTEM_NODE_CODE {
                area_keys.push(system_key);
                continue;
            }
            // An area node only takes part in the key derivation; it does not
            // widen data access. The session may touch exactly the services named
            // in the service code list.
            let area = self.find_area(area_code)?;
            area_keys.push(*area.key());
        }
        for &raw in services {
            let code = ServiceCode::new(raw);
            if raw == SYSTEM_NODE_CODE {
                service_keys.push(system_key);
                service_codes.push(code);
                continue;
            }
            let service = self.find_service(code)?;
            if code.requires_key() {
                service_keys.push(*service.key());
            }
            service_codes.push(code);
        }

        let (group_key, user_key) =
            generate_service_keys_des(&system_key, &area_keys, &service_keys);
        let context = AuthenticationContext::new(&idm, &group_key, &user_key);
        let random_1 = context.decrypt_challenge1a(&challenge_1a);
        let random_2: [u8; 8] = rand::random();
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

    pub(super) fn handle_authentication2(
        &mut self,
        _idm: [u8; 8],
        challenge_2b: [u8; 8],
    ) -> Option<Vec<u8>> {
        // Table 4-1 lists Authentication2 for Mode1 (1->2) and Mode2 (2->2), so
        // the authentication context outlives the first Authentication2 and a
        // repeat in Mode2 simply re-establishes the session.
        let pending = self.pending_auth.as_ref()?;
        // `challenge_2b` is the reader's proof it knows the key; compare the
        // expected value in constant time so a wrong guess leaks no timing.
        let expected = pending.context.encrypt_challenge2b(&pending.random_2);
        if !ct_eq(&expected, &challenge_2b) {
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
            service_codes: pending.service_codes.clone(),
        });
        self.mode = SystemMode::Mode2;

        encode_response_frame(FelicaStandardResponse::Authentication2(
            Authentication2Response { encrypted_payload },
        ))
    }

    /// Checks one block list element against the success requirements of §4.4.5
    /// (read) and §4.4.6 (write), reporting the (status flag 1, status flag 2)
    /// pair the card would return.
    ///
    /// `require_auth_free` distinguishes Read/Write Without Encryption, which may
    /// only reach services whose attribute is "認証不要", from the encrypted
    /// Read/Write, which §4.2 allows on both kinds of service.
    fn validate_block_element(
        &self,
        service_codes: &[ServiceCode],
        index: usize,
        block: &BlockListElement,
        access: AccessType,
        require_auth_free: bool,
    ) -> Result<ValidatedBlock, (u8, u8)> {
        let position = list_error_index(index);

        // "「サービスコードリスト順番」の値がサービス数を超えていないこと" -> A3h.
        let service_index = block.service_code_list_index as usize;
        let Some(service_code) = service_codes.get(service_index).copied() else {
            return Err((position, 0xA3));
        };

        // §4.4.5 permits access mode 000b only; §4.4.6 additionally permits 001b
        // for a cashback write. Anything else is A7h (ブロックリスト不正:
        // アクセスモード).
        let access_mode_allowed = match access {
            AccessType::Read => block.access_mode == 0b000,
            AccessType::Write => matches!(block.access_mode, 0b000 | 0b001),
        };
        if !access_mode_allowed {
            return Err((position, 0xA7));
        }

        // "サービスコードリストで指定するアクセス先がエリアもしくはシステムではないこと".
        // A4h is サービスタイプ不正, which table 4-12 defines as a wrong area *or*
        // service attribute — and an area code carries an area attribute, which is
        // never a valid service attribute, so this one test covers both.
        if service_code.raw() == SYSTEM_NODE_CODE {
            return Err((position, 0xA4));
        }
        let Some(attribute) = service_code.attribute() else {
            return Err((position, 0xA4));
        };

        // "サービスコードリストで指定するサービスがシステム内に存在すること" -> A6h.
        let Some(service) = self.find_service(service_code) else {
            return Err((position, 0xA6));
        };

        // "サービスコードリストで指定するサービスのサービス属性が認証不要であること".
        if require_auth_free && service_code.requires_key() {
            return Err((position, 0xA5));
        }

        if matches!(access, AccessType::Write) {
            // "サービス属性がリードオンリーではないこと".
            if !attribute.allows_write() {
                return Err((position, 0xA5));
            }
            // "アクセスモードに 001b が指定された場合、指定されたサービスのサービス属性
            // が、パースサービスのキャッシュバック／デクリメントアクセスであること".
            if block.access_mode == 0b001 && !attribute.allows_cashback() {
                return Err((position, 0xA5));
            }
        } else if block.access_mode != 0b000 {
            return Err((position, 0xA7));
        }

        // "ブロック番号が、指定したサービスに設定されたブロック数の範囲内であること" -> A8h.
        let block_number = block.block_number_or_key_version as usize;
        let block_count = service.blocks.borrow().len();
        if block_number >= block_count {
            return Err((position, 0xA8));
        }

        Ok(ValidatedBlock {
            position,
            service_code,
            attribute,
            block_number,
            access_mode: block.access_mode,
            limit_purse: service.limit_purse(),
        })
    }

    pub(super) fn validate_read_block(
        &self,
        service_codes: &[ServiceCode],
        index: usize,
        block: &BlockListElement,
        require_auth_free: bool,
    ) -> Result<(ServiceCode, usize), (u8, u8)> {
        let validated = self.validate_block_element(
            service_codes,
            index,
            block,
            AccessType::Read,
            require_auth_free,
        )?;
        Ok((validated.service_code, validated.block_number))
    }

    /// Applies a whole block list of writes, honouring the per-kind semantics of
    /// §3.4.2 (random), §3.4.3 (cyclic) and §3.4.4 (purse).
    ///
    /// Every element is validated and every new block computed before anything is
    /// stored, which is what gives §3.6.1's guarantee that a command's writes are
    /// applied "完全に行われる" or not at all.
    pub(super) fn apply_block_writes(
        &self,
        service_codes: &[ServiceCode],
        block_list: &[BlockListElement],
        data: &[u8],
        require_auth_free: bool,
    ) -> Result<(), (u8, u8)> {
        let mut planned = Vec::with_capacity(block_list.len());
        for (index, element) in block_list.iter().enumerate() {
            let validated = self.validate_block_element(
                service_codes,
                index,
                element,
                AccessType::Write,
                require_auth_free,
            )?;
            let offset = index * BLOCK_SIZE;
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
            planned.push((validated, block));
        }

        // Overlapping services share one block store (§3.4.6), so stage the work
        // per store, keyed by the service number they overlap on.
        let mut staged: BTreeMap<u16, (SharedBlocks, Vec<[u8; BLOCK_SIZE]>)> = BTreeMap::new();
        for (validated, _) in &planned {
            let number = validated.service_code.number();
            if staged.contains_key(&number) {
                continue;
            }
            let service = self
                .find_service(validated.service_code)
                .expect("the service was resolved during validation");
            let snapshot = service.blocks.borrow().clone();
            staged.insert(number, (service.blocks.clone(), snapshot));
        }

        let mut cursor = 0usize;
        while cursor < planned.len() {
            // §3.4.3 treats blocks written consecutively to the same cyclic
            // service as one data unit, so runs have to be found before applying
            // anything.
            let number = planned[cursor].0.service_code.number();
            let mut end = cursor + 1;
            while end < planned.len() && planned[end].0.service_code.number() == number {
                end += 1;
            }
            let run = &planned[cursor..end];
            let (_, blocks) = staged
                .get_mut(&number)
                .expect("every planned service was staged");

            match run[0].0.attribute.kind() {
                ServiceKind::Random => {
                    for (validated, block) in run {
                        blocks[validated.block_number] = *block;
                    }
                }
                ServiceKind::Cyclic => {
                    // "書き込み時は、常にブロック番号に 0 を指定する必要があります".
                    if let Some((validated, _)) = run
                        .iter()
                        .find(|(validated, _)| validated.block_number != 0)
                    {
                        return Err((validated.position, 0xA5));
                    }
                    let command_blocks: Vec<[u8; BLOCK_SIZE]> =
                        run.iter().map(|(_, block)| *block).collect();
                    match apply_cyclic_write(blocks, &command_blocks) {
                        Ok(CyclicWrite::Updated(updated)) => *blocks = updated,
                        Ok(CyclicWrite::Unchanged) => {}
                        Err(sf2) => return Err((run[0].0.position, sf2)),
                    }
                }
                ServiceKind::Purse => {
                    for (validated, command) in run {
                        let operation =
                            PurseOperation::resolve(validated.attribute, validated.access_mode)
                                .map_err(|sf2| (validated.position, sf2))?;
                        let stored = blocks[validated.block_number];
                        match apply_purse_write(&stored, command, operation, validated.limit_purse)
                        {
                            Ok(Some(updated)) => blocks[validated.block_number] = updated,
                            // §3.4.4: a repeated execution ID completes normally
                            // without updating the block.
                            Ok(None) => {}
                            Err(sf2) => return Err((validated.position, sf2)),
                        }
                    }
                }
            }
            cursor = end;
        }

        for (shared, blocks) in staged.into_values() {
            *shared.borrow_mut() = blocks;
        }
        Ok(())
    }

    pub(super) fn block_count_for_node(&self, node_code: u16) -> u16 {
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

    pub(super) fn reset_mode(&mut self) {
        self.mode = SystemMode::Mode0;
        self.pending_auth = None;
        self.secure_session = None;
    }

    fn sync_overlapping_services(&mut self) -> Result<(), EmulatorConfigError> {
        let mut registry = BTreeMap::new();
        self.root_area.sync_overlapping_services(&mut registry)
    }

    pub(super) fn handle_secure_frame(
        &mut self,
        command_code: u8,
        encrypted_payload: &[u8],
    ) -> Option<Vec<u8>> {
        // Table 4-1: Read and Write run in Mode2 only, while the issuing commands
        // run in Mode2 (moving the card to Mode3) and again in Mode3. A secure
        // frame sent in any other mode draws no response.
        let requirement = if is_register_command(command_code) {
            ModeRequirement::Issuing
        } else {
            ModeRequirement::Authenticated
        };
        if !self.mode_permits(requirement) {
            return None;
        }

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
        if !check_packet_mac_des(&decrypted, command_code) {
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

        let command_payload = payload[8..].to_vec();
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
                    result: None,
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
                    result: None,
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
        let frame = build_secure_response_frame_des(
            response_code,
            response_transaction_number,
            &transaction_id,
            &transaction_key,
            &response_payload,
        )?;
        if is_register_command(command_code) && response_payload.first() == Some(&0x00) {
            self.mode = SystemMode::Mode3;
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
            // §4.2: the encrypted Read reaches services of either attribute.
            let (service_code, block_number) =
                match self.validate_read_block(service_codes, index, block, false) {
                    Ok(value) => value,
                    Err((sf1, sf2)) => {
                        return FelicaStandardResponse::Read {
                            status_flag1: sf1,
                            status_flag2: sf2,
                            result: None,
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
            result: Some(ReadResult { blocks }),
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
        match self.apply_block_writes(service_codes, block_list, data, false) {
            Ok(()) => FelicaStandardResponse::Write {
                status_flag1: 0x00,
                status_flag2: 0x00,
            },
            Err((sf1, sf2)) => FelicaStandardResponse::Write {
                status_flag1: sf1,
                status_flag2: sf2,
            },
        }
    }
}

/// A block list element that has passed the §4.4.5/§4.4.6 success requirements.
struct ValidatedBlock {
    /// Value to report in status flag 1 if this element later fails.
    position: u8,
    service_code: ServiceCode,
    attribute: ServiceAttribute,
    block_number: usize,
    access_mode: u8,
    limit_purse: Option<LimitPurseProperty>,
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

pub(super) enum AccessType {
    Read,
    Write,
}

fn list_error_index(index: usize) -> u8 {
    let value = index.saturating_add(1);
    if value > u8::MAX as usize {
        u8::MAX
    } else {
        value as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_mode_codes_and_list_error_index() {
        assert_eq!(SystemMode::Mode0.code(), 0x00);
        assert_eq!(SystemMode::Mode1.code(), 0x01);
        assert_eq!(SystemMode::Mode2.code(), 0x02);
        assert_eq!(SystemMode::Mode3.code(), 0x03);

        assert_eq!(list_error_index(0), 1);
        assert_eq!(list_error_index(200), 201);
        assert_eq!(list_error_index(usize::MAX), u8::MAX);
    }

    const AUTH_SERVICE: u16 = 0x1008; // even -> authentication-required
    const NO_AUTH_SERVICE: u16 = 0x1049; // odd -> authentication-free
    const IDM: [u8; 8] = [0x11; 8];
    const CHALLENGE: [u8; 8] = [0u8; 8];

    /// A system with the root area, a child area `0x1000`, and one auth-required
    /// plus one auth-free service under that child.
    fn auth1_test_system() -> EmulatedSystem {
        let mut system = EmulatedSystem::new(0x1234, IDM, [0x22; 8]).expect("system");
        system.set_system_key([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        system.root_area_mut().set_key([0x10; 8]);

        let mut area = EmulatedArea::new(0x1000, 0x1FFF).expect("area");
        area.set_key([0x20; 8]);
        let mut auth_service = EmulatedService::new(ServiceCode::new(AUTH_SERVICE), 1);
        auth_service.set_key([0x30; 8]);
        area.add_service(auth_service).expect("auth service");
        area.add_service(EmulatedService::new(ServiceCode::new(NO_AUTH_SERVICE), 1))
            .expect("no-auth service");
        system.add_area(area).expect("add area");
        system
    }

    #[test]
    fn authentication1_accepts_well_formed_node_list() {
        let mut system = auth1_test_system();
        // Area + one authentication-required service.
        assert!(
            system
                .handle_authentication1(IDM, &[0x1000], &[AUTH_SERVICE], CHALLENGE)
                .is_some()
        );
        // Authentication-free service after the authentication-required one.
        assert!(
            system
                .handle_authentication1(IDM, &[0x1000], &[AUTH_SERVICE, NO_AUTH_SERVICE], CHALLENGE)
                .is_some()
        );
        // The system code is allowed in a non-first area-list position.
        assert!(
            system
                .handle_authentication1(IDM, &[0x1000, 0xFFFF], &[AUTH_SERVICE], CHALLENGE)
                .is_some()
        );
    }

    #[test]
    fn authentication1_accepts_system_code_in_service_list() {
        let mut system = auth1_test_system();
        // The system code alone is an authentication-required node in the service list.
        assert!(
            system
                .handle_authentication1(IDM, &[0x1000], &[0xFFFF], CHALLENGE)
                .is_some()
        );
        // System code among services, with an auth-free service last.
        assert!(
            system
                .handle_authentication1(
                    IDM,
                    &[0x1000],
                    &[AUTH_SERVICE, 0xFFFF, NO_AUTH_SERVICE],
                    CHALLENGE,
                )
                .is_some()
        );
        // An auth-free service before the system code still violates the order rule.
        assert!(
            system
                .handle_authentication1(IDM, &[0x1000], &[NO_AUTH_SERVICE, 0xFFFF], CHALLENGE)
                .is_none()
        );
    }

    #[test]
    fn system_service_node_adds_a_system_key_layer() {
        let mut system = auth1_test_system();
        let challenge = [0xA5u8; 8];
        let frame = system
            .handle_authentication1(IDM, &[0x1000], &[0xFFFF], challenge)
            .expect("Authentication1 with the system node as service must be accepted");

        // Response frame: [len][code][idm(8)][challenge_1b(8)][challenge_2a(8)].
        let mut actual_c1b = [0u8; 8];
        actual_c1b.copy_from_slice(&frame[10..18]);

        // On real hardware, listing 0xFFFF in the service list adds an E_system
        // layer, so USK = E_system(GSK) != GSK (NOT area authentication).
        let system_key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let area_key = [0x20u8; 8];
        let (group_key, user_key) =
            generate_service_keys_des(&system_key, &[area_key], &[system_key]);
        assert_ne!(
            group_key, user_key,
            "the system node must add a user-key layer"
        );

        let context = AuthenticationContext::new(&IDM, &group_key, &user_key);
        let random_1 = context.decrypt_challenge1a(&challenge);
        let expected_c1b = context.encrypt_challenge1b(&random_1);
        assert_eq!(
            actual_c1b, expected_c1b,
            "services=[0xFFFF] must derive USK = E_system(GSK)"
        );
    }

    #[test]
    fn authentication1_rejects_service_list_without_auth_required_node() {
        let mut system = auth1_test_system();
        // Empty service list — the Kg=Ks-for-free shortcut — draws no response.
        assert!(
            system
                .handle_authentication1(IDM, &[0x1000], &[], CHALLENGE)
                .is_none()
        );
        // Only an authentication-free service — still no authentication-required node.
        assert!(
            system
                .handle_authentication1(IDM, &[0x1000], &[NO_AUTH_SERVICE], CHALLENGE)
                .is_none()
        );
    }

    #[test]
    fn authentication1_rejects_auth_free_service_before_auth_required() {
        let mut system = auth1_test_system();
        assert!(
            system
                .handle_authentication1(IDM, &[0x1000], &[NO_AUTH_SERVICE, AUTH_SERVICE], CHALLENGE)
                .is_none()
        );
    }

    #[test]
    fn authentication1_rejects_malformed_area_list() {
        let mut system = auth1_test_system();
        // Empty area list.
        assert!(
            system
                .handle_authentication1(IDM, &[], &[AUTH_SERVICE], CHALLENGE)
                .is_none()
        );
        // First entry is the system code, not an area code.
        assert!(
            system
                .handle_authentication1(IDM, &[0xFFFF, 0x1000], &[AUTH_SERVICE], CHALLENGE)
                .is_none()
        );
        // First entry is not a real area.
        assert!(
            system
                .handle_authentication1(IDM, &[0x9999], &[AUTH_SERVICE], CHALLENGE)
                .is_none()
        );
    }
}
