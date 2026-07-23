//! The stored structure of an emulated FeliCa card: the area/service tree that
//! holds block data, plus the configuration-time validation that keeps node
//! code ranges well formed.
//!
//! These types are the user-facing builder surface ([`EmulatedArea`],
//! [`EmulatedService`]); the per-system command handling that walks this tree
//! lives in [`super::system`].

use super::SharedBlocks;
use crate::felica_standard::{BLOCK_SIZE, ServiceCode};
use std::cell::{Ref, RefCell, RefMut};
use std::collections::BTreeMap;
use std::rc::Rc;

pub(super) const ROOT_AREA_CODE: u16 = 0x0000;
pub(super) const ROOT_END_SERVICE_CODE: u16 = 0xFFFE;

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

    pub(super) fn append_directory_entries(&self, entries: &mut Vec<DirectoryEntry>) {
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

    pub(super) fn append_service_codes(&self, codes: &mut Vec<ServiceCode>) {
        for child in &self.children {
            match child {
                AreaChild::Area(area) => area.append_service_codes(codes),
                AreaChild::Service(service) => codes.push(service.service_code),
            }
        }
    }

    pub(super) fn find_service(&self, service_code: ServiceCode) -> Option<&EmulatedService> {
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

    pub(super) fn find_area(&self, area_code: u16) -> Option<&EmulatedArea> {
        if self.area_code == area_code {
            return Some(self);
        }
        for child in &self.children {
            if let AreaChild::Area(area) = child
                && let Some(found) = area.find_area(area_code)
            {
                return Some(found);
            }
        }
        None
    }

    pub(super) fn total_block_count(&self) -> usize {
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

    pub(super) fn sync_overlapping_services(&mut self, registry: &mut BTreeMap<u16, SharedBlocks>) {
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
    pub(super) blocks: SharedBlocks,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_area_range_rules() {
        match validate_area_range(ROOT_AREA_CODE, 0xFFFD) {
            Err(EmulatorConfigError::InvalidRootAreaRange { end_service_code }) => {
                assert_eq!(end_service_code, 0xFFFD);
            }
            other => panic!("expected InvalidRootAreaRange, got {other:?}"),
        }

        match validate_area_range(0x2000, 0x1000) {
            Err(EmulatorConfigError::InvalidAreaRange {
                area_code,
                end_service_code,
            }) => {
                assert_eq!(area_code, 0x2000);
                assert_eq!(end_service_code, 0x1000);
            }
            other => panic!("expected InvalidAreaRange, got {other:?}"),
        }

        assert!(validate_area_range(0x1000, 0x1000).is_ok());
    }

    #[test]
    fn emulated_service_default_key_version_depends_on_service_attributes() {
        let with_key = EmulatedService::new(ServiceCode::new((0x10 << 6) | 0b001010), 2);
        assert_eq!(with_key.key_version(), 0x0000);
        assert_eq!(with_key.blocks().len(), 2);

        let without_key = EmulatedService::new(ServiceCode::new((0x10 << 6) | 0b001011), 1);
        assert_eq!(without_key.key_version(), 0xFFFF);
        assert_eq!(without_key.blocks().len(), 1);
    }

    #[test]
    fn emulated_area_rejects_children_outside_range() {
        let mut root = EmulatedArea::new(ROOT_AREA_CODE, ROOT_END_SERVICE_CODE).expect("root area");

        let out_of_range_service = EmulatedService::new(ServiceCode::new(0xFFFF), 1);
        match root.add_service(out_of_range_service) {
            Err(EmulatorConfigError::ServiceOutOfRange {
                area_code,
                end_service_code,
                service_code,
            }) => {
                assert_eq!(area_code, ROOT_AREA_CODE);
                assert_eq!(end_service_code, ROOT_END_SERVICE_CODE);
                assert_eq!(service_code, 0xFFFF);
            }
            _ => panic!("expected ServiceOutOfRange"),
        }

        let child = EmulatedArea::new(0x0100, 0xFFFF).expect("child area");
        match root.add_area(child) {
            Err(EmulatorConfigError::AreaOutOfRange {
                area_code,
                end_service_code,
                child_area_code,
                child_end_service_code,
            }) => {
                assert_eq!(area_code, ROOT_AREA_CODE);
                assert_eq!(end_service_code, ROOT_END_SERVICE_CODE);
                assert_eq!(child_area_code, 0x0100);
                assert_eq!(child_end_service_code, 0xFFFF);
            }
            _ => panic!("expected AreaOutOfRange"),
        }
    }
}
