use super::{
    BLOCK_SIZE, BlockListElement, FelicaStandardCommand, ServiceCode, frame_with_length_prefix,
};
use std::collections::BTreeMap;

const ROOT_AREA_CODE: u16 = 0x0000;
const ROOT_END_SERVICE_CODE: u16 = 0xFFFE;

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
#[allow(dead_code)]
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

    pub fn sensf_res(&self) -> Option<Vec<u8>> {
        let system_code = self.resolve_active_system_code()?;
        self.sensf_res_for(system_code)
    }

    pub fn sensf_res_for(&self, system_code: u16) -> Option<Vec<u8>> {
        let system = self
            .systems
            .iter()
            .find(|system| system.system_code == system_code)?;
        Some(build_sensf_res(system.idm, system.pmm, system_code))
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
                Some(build_polling_response(system, request_code))
            }
            FelicaStandardCommand::RequestResponse { idm } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get(index)?;
                Some(build_request_response(&idm, system.mode.code()))
            }
            FelicaStandardCommand::RequestSystemCode { idm } => {
                self.system_index_for_idm(&idm)?;
                let codes = self.system_codes();
                if codes.is_empty() {
                    None
                } else {
                    Some(build_request_system_code(&idm, &codes))
                }
            }
            FelicaStandardCommand::SearchServiceCode { idm, service_index } => {
                let index = self.system_index_for_idm(&idm)?;
                let directory = self.systems.get(index)?.directory();
                let entry = directory.get(service_index as usize);
                let result = match entry {
                    Some(DirectoryEntry::Service(code)) => Some(SearchResult::Service(*code)),
                    Some(DirectoryEntry::Area {
                        area_code,
                        end_service_code,
                    }) => Some(SearchResult::Area {
                        area_code: *area_code,
                        end_service_code: *end_service_code,
                    }),
                    None => None,
                };
                Some(build_search_service_code(&idm, result))
            }
            FelicaStandardCommand::RequestService { idm, service_codes } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get(index)?;
                let key_versions = service_codes
                    .iter()
                    .map(|code| system.node_key_version(*code))
                    .collect::<Vec<_>>();
                Some(build_request_service(&idm, &key_versions))
            }
            FelicaStandardCommand::ReadWithoutEncryption {
                idm,
                service_codes,
                block_list,
            } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get(index)?;
                Some(Self::handle_read(idm, system, &service_codes, &block_list))
            }
            FelicaStandardCommand::WriteWithoutEncryption {
                idm,
                service_codes,
                block_list,
                data,
            } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get_mut(index)?;
                Some(Self::handle_write(
                    idm,
                    system,
                    &service_codes,
                    &block_list,
                    &data,
                ))
            }
            FelicaStandardCommand::RequestBlockInformation { idm, node_codes } => {
                let index = self.system_index_for_idm(&idm)?;
                let system = self.systems.get(index)?;
                let counts = node_codes
                    .iter()
                    .map(|code| system.block_count_for_node(*code))
                    .collect::<Vec<_>>();
                Some(build_request_block_information(&idm, &counts))
            }
            _ => None,
        }
    }

    fn handle_read(
        idm: [u8; 8],
        system: &EmulatedSystem,
        service_codes: &[ServiceCode],
        block_list: &[BlockListElement],
    ) -> Vec<u8> {
        let mut blocks = Vec::with_capacity(block_list.len());
        for (index, block) in block_list.iter().enumerate() {
            let (service_code, block_number) =
                match system.validate_block(service_codes, index, block, AccessType::Read) {
                    Ok(value) => value,
                    Err((sf1, sf2)) => return build_read_without_encryption(&idm, sf1, sf2, &[]),
                };
            let service = system.find_service(service_code).unwrap();
            blocks.push(service.blocks[block_number]);
        }
        build_read_without_encryption(&idm, 0x00, 0x00, &blocks)
    }

    fn handle_write(
        idm: [u8; 8],
        system: &mut EmulatedSystem,
        service_codes: &[ServiceCode],
        block_list: &[BlockListElement],
        data: &[u8],
    ) -> Vec<u8> {
        let expected_len = block_list.len().saturating_mul(BLOCK_SIZE);
        if data.len() < expected_len {
            return build_write_without_encryption(&idm, 0xFF, 0xAC);
        }
        let mut updates = Vec::with_capacity(block_list.len());
        for (index, block) in block_list.iter().enumerate() {
            let (service_code, block_number) =
                match system.validate_block(service_codes, index, block, AccessType::Write) {
                    Ok(value) => value,
                    Err((sf1, sf2)) => return build_write_without_encryption(&idm, sf1, sf2),
                };
            let offset = index * BLOCK_SIZE;
            let mut block_data = [0u8; BLOCK_SIZE];
            block_data.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
            updates.push((service_code, block_number, block_data));
        }

        let mut shared_blocks = BTreeMap::new();
        for (service_code, block_number, block_data) in updates {
            let service_number = service_code.number();
            if !shared_blocks.contains_key(&service_number) {
                let Some(service) = system.find_service(service_code) else {
                    return build_write_without_encryption(&idm, 0xFF, 0xA6);
                };
                shared_blocks.insert(service_number, service.blocks.clone());
            }
            if let Some(blocks) = shared_blocks.get_mut(&service_number) {
                if let Some(slot) = blocks.get_mut(block_number) {
                    *slot = block_data;
                }
            }
        }

        for (service_number, blocks) in shared_blocks {
            system.sync_blocks_by_number(service_number, &blocks);
        }

        build_write_without_encryption(&idm, 0x00, 0x00)
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
}

pub struct EmulatedSystem {
    system_code: u16,
    idm: [u8; 8],
    pmm: [u8; 8],
    root_area: EmulatedArea,
    mode: SystemMode,
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
        })
    }

    pub fn system_code(&self) -> u16 {
        self.system_code
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
        if let Some(service) = self.find_service(node_code) {
            return service.key_version;
        }
        if let Some(area) = self.find_area(node_code.raw()) {
            return area.key_version;
        }
        0xFFFF
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
        if block_number >= service.blocks.len() {
            return Err((list_error_index(index), 0xA8));
        }

        Ok((service_code, block_number))
    }

    fn block_count_for_node(&self, node_code: u16) -> u16 {
        let service_code = ServiceCode::new(node_code);
        if let Some(service) = self.find_service(service_code) {
            return service.blocks.len().min(u16::MAX as usize) as u16;
        }
        if let Some(area) = self.find_area(node_code) {
            return area.total_block_count().min(u16::MAX as usize) as u16;
        }
        0
    }

    fn reset_mode(&mut self) {
        self.mode = SystemMode::Mode0;
    }

    fn sync_overlapping_services(&mut self) {
        let mut registry = BTreeMap::new();
        self.root_area.sync_overlapping_services(&mut registry);
    }

    fn sync_blocks_by_number(&mut self, service_number: u16, blocks: &[[u8; BLOCK_SIZE]]) {
        self.root_area.sync_blocks_by_number(service_number, blocks);
    }
}

pub struct EmulatedArea {
    area_code: u16,
    key_version: u16,
    end_service_code: u16,
    children: Vec<AreaChild>,
}

impl EmulatedArea {
    pub fn new(area_code: u16, end_service_code: u16) -> Result<Self, EmulatorConfigError> {
        validate_area_range(area_code, end_service_code)?;
        Ok(Self {
            area_code,
            key_version: 0x0000,
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
                    total = total.saturating_add(service.blocks.len());
                }
            }
        }
        total
    }

    fn sync_overlapping_services(&mut self, registry: &mut BTreeMap<u16, Vec<[u8; BLOCK_SIZE]>>) {
        for child in &mut self.children {
            match child {
                AreaChild::Area(area) => area.sync_overlapping_services(registry),
                AreaChild::Service(service) => {
                    let number = service.service_code.number();
                    if let Some(shared) = registry.get(&number) {
                        if service.blocks.len() == shared.len() {
                            service.blocks.clone_from_slice(shared);
                        } else {
                            service.blocks = shared.clone();
                        }
                    } else {
                        registry.insert(number, service.blocks.clone());
                    }
                }
            }
        }
    }

    fn sync_blocks_by_number(&mut self, service_number: u16, blocks: &[[u8; BLOCK_SIZE]]) {
        for child in &mut self.children {
            match child {
                AreaChild::Area(area) => area.sync_blocks_by_number(service_number, blocks),
                AreaChild::Service(service) => {
                    if service.service_code.number() == service_number {
                        if service.blocks.len() == blocks.len() {
                            service.blocks.clone_from_slice(blocks);
                        } else {
                            service.blocks = blocks.to_vec();
                        }
                    }
                }
            }
        }
    }
}

pub struct EmulatedService {
    service_code: ServiceCode,
    key_version: u16,
    blocks: Vec<[u8; BLOCK_SIZE]>,
}

impl EmulatedService {
    pub fn new(service_code: ServiceCode, block_count: usize) -> Self {
        Self::with_key_version(service_code, 0x0000, block_count)
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
            blocks,
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
            blocks,
        }
    }

    pub fn service_code(&self) -> ServiceCode {
        self.service_code
    }

    pub fn key_version(&self) -> u16 {
        self.key_version
    }

    pub fn blocks(&self) -> &[[u8; BLOCK_SIZE]] {
        &self.blocks
    }

    pub fn blocks_mut(&mut self) -> &mut [[u8; BLOCK_SIZE]] {
        &mut self.blocks
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

enum SearchResult {
    Service(ServiceCode),
    Area {
        area_code: u16,
        end_service_code: u16,
    },
}

enum AccessType {
    Read,
    Write,
}

fn build_sensf_res(idm: [u8; 8], pmm: [u8; 8], system_code: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    out.push(0x01);
    out.extend_from_slice(&idm);
    out.extend_from_slice(&pmm);
    out.extend_from_slice(&system_code.to_be_bytes());
    out
}

fn build_request_response(idm: &[u8; 8], mode: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(10);
    payload.push(0x05);
    payload.extend_from_slice(idm);
    payload.push(mode);
    frame_with_length_prefix(&payload)
}

fn build_polling_response(system: &EmulatedSystem, request_code: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(19);
    payload.push(0x01);
    payload.extend_from_slice(&system.idm);
    payload.extend_from_slice(&system.pmm);
    match request_code {
        0x01 => payload.extend_from_slice(&system.system_code.to_be_bytes()),
        0x02 => payload.extend_from_slice(&[0x00, 0x00]),
        _ => {}
    }
    frame_with_length_prefix(&payload)
}

fn build_request_system_code(idm: &[u8; 8], system_codes: &[u16]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(11 + system_codes.len() * 2);
    payload.push(0x0D);
    payload.extend_from_slice(idm);
    payload.push(system_codes.len().min(u8::MAX as usize) as u8);
    for code in system_codes {
        payload.extend_from_slice(&code.to_be_bytes());
    }
    frame_with_length_prefix(&payload)
}

fn build_search_service_code(idm: &[u8; 8], result: Option<SearchResult>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(14);
    payload.push(0x0B);
    payload.extend_from_slice(idm);
    match result {
        Some(SearchResult::Service(code)) => payload.extend_from_slice(&code.raw().to_le_bytes()),
        Some(SearchResult::Area {
            area_code,
            end_service_code,
        }) => {
            payload.extend_from_slice(&area_code.to_le_bytes());
            payload.extend_from_slice(&end_service_code.to_le_bytes());
        }
        None => payload.extend_from_slice(&0xFFFFu16.to_le_bytes()),
    }
    frame_with_length_prefix(&payload)
}

fn build_request_service(idm: &[u8; 8], key_versions: &[u16]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(11 + key_versions.len() * 2);
    payload.push(0x03);
    payload.extend_from_slice(idm);
    payload.push(key_versions.len().min(u8::MAX as usize) as u8);
    for key_version in key_versions {
        payload.extend_from_slice(&key_version.to_le_bytes());
    }
    frame_with_length_prefix(&payload)
}

fn build_read_without_encryption(
    idm: &[u8; 8],
    sf1: u8,
    sf2: u8,
    blocks: &[[u8; BLOCK_SIZE]],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(13 + blocks.len() * BLOCK_SIZE);
    payload.push(0x07);
    payload.extend_from_slice(idm);
    payload.push(sf1);
    payload.push(sf2);
    if sf1 == 0 && sf2 == 0 {
        payload.push(blocks.len().min(u8::MAX as usize) as u8);
        for block in blocks {
            payload.extend_from_slice(block);
        }
    }
    frame_with_length_prefix(&payload)
}

fn build_write_without_encryption(idm: &[u8; 8], sf1: u8, sf2: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(11);
    payload.push(0x09);
    payload.extend_from_slice(idm);
    payload.push(sf1);
    payload.push(sf2);
    frame_with_length_prefix(&payload)
}

fn build_request_block_information(idm: &[u8; 8], block_counts: &[u16]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(11 + block_counts.len() * 2);
    payload.push(0x0F);
    payload.extend_from_slice(idm);
    payload.push(block_counts.len().min(u8::MAX as usize) as u8);
    for count in block_counts {
        payload.extend_from_slice(&count.to_le_bytes());
    }
    frame_with_length_prefix(&payload)
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
