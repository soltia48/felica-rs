//! The stored structure of an emulated FeliCa card: the area/service tree that
//! holds block data, plus the configuration-time validation that keeps node
//! code ranges well formed.
//!
//! These types are the user-facing builder surface ([`EmulatedArea`],
//! [`EmulatedService`]); the per-system command handling that walks this tree
//! lives in [`super::system`].

use super::SharedBlocks;
use crate::felica_standard::{BLOCK_SIZE, ServiceCode, ServiceKind};
use std::cell::{Ref, RefCell, RefMut};
use std::collections::BTreeMap;
use std::rc::Rc;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(super) const ROOT_AREA_CODE: u16 = 0x0000;
pub(super) const ROOT_END_SERVICE_CODE: u16 = 0xFFFE;

/// Highest node code the file system can address (§3.5: "エリアコードおよびサービス
/// コードには、0000h～FFFEh が利用可能です"). `FFFFh` is reserved for the system node.
const MAX_NODE_CODE: u16 = 0xFFFE;

/// Area attribute meaning "child areas may be created below this area"
/// (§3.3.1, table 3-1).
const AREA_ATTRIBUTE_CHILD_AREAS_ALLOWED: u8 = 0b000000;

/// Area attribute meaning "no child area may be created below this area"
/// (§3.3.1, table 3-1).
const AREA_ATTRIBUTE_CHILD_AREAS_FORBIDDEN: u8 = 0b000001;

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
        "node code 0x{node_code:04X} is outside the usable range 0x0000..=0xFFFE; 0xFFFF denotes the system"
    )]
    NodeCodeOutOfRange { node_code: u16 },
    #[error(
        "area code 0x{area_code:04X} has attribute {attribute:06b}, but an area attribute must be 000000b (child areas allowed) or 000001b (child areas forbidden)"
    )]
    InvalidAreaAttribute { area_code: u16, attribute: u8 },
    #[error(
        "area 0x{area_code:04X} has attribute 000001b, so no child area may be created below it"
    )]
    ChildAreaForbidden { area_code: u16 },
    #[error(
        "service code 0x{service_code:04X} has attribute {attribute:06b}, which is not a service attribute defined by table 3-2"
    )]
    UndefinedServiceAttribute { service_code: u16, attribute: u8 },
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
    #[error(
        "service 0x{service_code:04X} would overlap service number 0x{service_number:03X}, which is a {existing_kind:?} service, but it is a {added_kind:?} service; random, cyclic and purse services cannot be mixed in an overlap"
    )]
    OverlapKindMismatch {
        service_code: u16,
        service_number: u16,
        existing_kind: ServiceKind,
        added_kind: ServiceKind,
    },
}

/// Clears its area key on drop; the children clear their own keys through their
/// own `Drop` impls.
#[derive(ZeroizeOnDrop)]
pub struct EmulatedArea {
    #[zeroize(skip)]
    area_code: u16,
    #[zeroize(skip)]
    key_version: u16,
    key: [u8; 8],
    #[zeroize(skip)]
    end_service_code: u16,
    #[zeroize(skip)]
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

    /// The six-bit area attribute, i.e. the low bits of the area code
    /// (§3.3.1, figure 3-7).
    pub fn attribute(&self) -> u8 {
        (self.area_code & 0x3F) as u8
    }

    /// Whether child areas may be created below this area (§3.3.1, table 3-1).
    pub fn allows_child_areas(&self) -> bool {
        self.attribute() == AREA_ATTRIBUTE_CHILD_AREAS_ALLOWED
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
        // Overwrite rather than replace, so the previous key does not survive.
        self.key.zeroize();
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
        validate_node_code(code)?;
        // A service whose attribute is not in table 3-2 has no defined kind or
        // access rules, so nothing downstream could handle it correctly.
        if service.service_code.attribute().is_none() {
            return Err(EmulatorConfigError::UndefinedServiceAttribute {
                service_code: code,
                attribute: service.service_code.attributes(),
            });
        }
        // §3.5: an area owns the node code range starting at its area code and
        // ending at its end service code; a service belongs to the area whose
        // range contains its service code.
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
        // §3.3.1, table 3-1: attribute 000001b marks an area below which no
        // further area may be created.
        if !self.allows_child_areas() {
            return Err(EmulatorConfigError::ChildAreaForbidden {
                area_code: self.area_code,
            });
        }
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

    /// Links up the overlap services of §3.4.6: services that share a service
    /// number within one system manage the same blocks under different access
    /// rules, so they must share one block store.
    ///
    /// §3.4.6 forbids mixing random, cyclic and purse services in an overlap —
    /// each kind interprets its blocks differently — and that is rejected here.
    /// Where block counts differ the overlap target's count wins, which is what
    /// an AES card does: "ブロック数が異なる場合、強制的にオーバーラップ先サービス
    /// のブロック数に修正してサービスを登録します".
    pub(super) fn sync_overlapping_services(
        &mut self,
        registry: &mut BTreeMap<u16, OverlapGroup>,
    ) -> Result<(), EmulatorConfigError> {
        for child in &mut self.children {
            match child {
                AreaChild::Area(area) => area.sync_overlapping_services(registry)?,
                AreaChild::Service(service) => {
                    let number = service.service_code.number();
                    // Attributes are validated on insertion, so a registered
                    // service always has a defined kind.
                    let kind = service
                        .service_code
                        .kind()
                        .expect("service attributes are validated when the service is added");
                    match registry.get(&number) {
                        Some(group) => {
                            if group.kind != kind {
                                return Err(EmulatorConfigError::OverlapKindMismatch {
                                    service_code: service.service_code.raw(),
                                    service_number: number,
                                    existing_kind: group.kind,
                                    added_kind: kind,
                                });
                            }
                            service.blocks = group.blocks.clone();
                        }
                        None => {
                            registry.insert(
                                number,
                                OverlapGroup {
                                    kind,
                                    blocks: service.blocks.clone(),
                                },
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// The blocks shared by every service that overlaps one service number, plus the
/// service kind they must all agree on (§3.4.6).
pub(super) struct OverlapGroup {
    pub(super) kind: ServiceKind,
    pub(super) blocks: SharedBlocks,
}

/// The upper/lower limits and generation number a limit purse service carries as
/// its service property (§3.4.4.1, table 3-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitPurseProperty {
    /// Highest purse value a write may leave in the block. Defaults to
    /// `7FFFFFFFh` per table 3-8.
    pub upper_limit: i32,
    /// Lowest purse value a write may leave in the block. Defaults to `0`.
    pub lower_limit: i32,
    /// Generation of the limits; a limit update may only raise it (§3.4.4.1).
    pub generation_number: u8,
}

impl Default for LimitPurseProperty {
    fn default() -> Self {
        // Table 3-8: 上限値 7FFFFFFFh, 下限値 00000000h, 世代番号 00h.
        Self {
            upper_limit: i32::MAX,
            lower_limit: 0,
            generation_number: 0,
        }
    }
}

/// Clears its service key on drop.
#[derive(ZeroizeOnDrop)]
pub struct EmulatedService {
    #[zeroize(skip)]
    service_code: ServiceCode,
    #[zeroize(skip)]
    key_version: u16,
    key: [u8; 8],
    #[zeroize(skip)]
    limit_purse: Option<LimitPurseProperty>,
    #[zeroize(skip)]
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
            limit_purse: None,
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
            limit_purse: None,
            blocks: Rc::new(RefCell::new(blocks)),
        }
    }

    pub fn service_code(&self) -> ServiceCode {
        self.service_code
    }

    /// Turns this purse service into a limit purse service (§3.4.4.1), whose
    /// purse data is treated as a two's-complement value bounded by
    /// `upper_limit` and `lower_limit`.
    ///
    /// Enabling it on a service that is not a purse service has no effect on
    /// block access, since the limits only constrain purse arithmetic.
    pub fn set_limit_purse(&mut self, property: LimitPurseProperty) -> &mut Self {
        self.limit_purse = Some(property);
        self
    }

    /// The limit purse service property, or `None` if the limit purse service
    /// flag is disabled for this service.
    pub fn limit_purse(&self) -> Option<LimitPurseProperty> {
        self.limit_purse
    }

    pub fn key_version(&self) -> u16 {
        self.key_version
    }

    pub fn key(&self) -> &[u8; 8] {
        &self.key
    }

    pub fn set_key(&mut self, key: [u8; 8]) -> &mut Self {
        // Overwrite rather than replace, so the previous key does not survive.
        self.key.zeroize();
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

/// Rejects a node code the file system cannot address (§3.5).
fn validate_node_code(node_code: u16) -> Result<(), EmulatorConfigError> {
    if node_code > MAX_NODE_CODE {
        return Err(EmulatorConfigError::NodeCodeOutOfRange { node_code });
    }
    Ok(())
}

fn validate_area_range(area_code: u16, end_service_code: u16) -> Result<(), EmulatorConfigError> {
    validate_node_code(area_code)?;
    validate_node_code(end_service_code)?;
    // §3.3.2: area 0 is the root of the hierarchy and always spans the whole
    // usable node code range.
    if area_code == ROOT_AREA_CODE && end_service_code != ROOT_END_SERVICE_CODE {
        return Err(EmulatorConfigError::InvalidRootAreaRange { end_service_code });
    }
    // §3.3.1, table 3-1: only two area attributes exist. Any other value in the
    // low six bits of the area code is undefined, and taking it as an area code
    // would also break the "child areas allowed" test below.
    let attribute = (area_code & 0x3F) as u8;
    if attribute != AREA_ATTRIBUTE_CHILD_AREAS_ALLOWED
        && attribute != AREA_ATTRIBUTE_CHILD_AREAS_FORBIDDEN
    {
        return Err(EmulatorConfigError::InvalidAreaAttribute {
            area_code,
            attribute,
        });
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
        let mut child = EmulatedArea::new(0x1000, 0x1FFF).expect("child area");

        // 0x2008 is a valid service code, but it falls outside 0x1000..=0x1FFF.
        match child
            .add_service(EmulatedService::new(ServiceCode::new(0x2008), 1))
            .map(|_| ())
        {
            Err(EmulatorConfigError::ServiceOutOfRange {
                area_code,
                end_service_code,
                service_code,
            }) => {
                assert_eq!(area_code, 0x1000);
                assert_eq!(end_service_code, 0x1FFF);
                assert_eq!(service_code, 0x2008);
            }
            other => panic!("expected ServiceOutOfRange, got {other:?}"),
        }

        let grandchild = EmulatedArea::new(0x0100, 0xFFFE).expect("grandchild area");
        match child.add_area(grandchild).map(|_| ()) {
            Err(EmulatorConfigError::AreaOutOfRange {
                area_code,
                end_service_code,
                child_area_code,
                child_end_service_code,
            }) => {
                assert_eq!(area_code, 0x1000);
                assert_eq!(end_service_code, 0x1FFF);
                assert_eq!(child_area_code, 0x0100);
                assert_eq!(child_end_service_code, 0xFFFE);
            }
            other => panic!("expected AreaOutOfRange, got {other:?}"),
        }

        root.add_area(child)
            .expect("0x1000..=0x1FFF fits in area 0");
    }

    /// §3.5: only 0000h-FFFEh are usable node codes, because FFFFh denotes the
    /// system itself (§3.2.2).
    #[test]
    fn node_codes_are_limited_to_the_usable_range() {
        match EmulatedArea::new(0xFFFF, 0xFFFF).map(|_| ()) {
            Err(EmulatorConfigError::NodeCodeOutOfRange { node_code }) => {
                assert_eq!(node_code, 0xFFFF);
            }
            other => panic!("expected NodeCodeOutOfRange, got {other:?}"),
        }
        match EmulatedArea::new(0x1000, 0xFFFF).map(|_| ()) {
            Err(EmulatorConfigError::NodeCodeOutOfRange { node_code }) => {
                assert_eq!(node_code, 0xFFFF);
            }
            other => panic!("expected NodeCodeOutOfRange, got {other:?}"),
        }

        let mut root = EmulatedArea::new(ROOT_AREA_CODE, ROOT_END_SERVICE_CODE).expect("root area");
        match root
            .add_service(EmulatedService::new(ServiceCode::new(0xFFFF), 1))
            .map(|_| ())
        {
            Err(EmulatorConfigError::NodeCodeOutOfRange { node_code }) => {
                assert_eq!(node_code, 0xFFFF);
            }
            other => panic!("expected NodeCodeOutOfRange, got {other:?}"),
        }
    }

    /// §3.3.1, table 3-1: an area attribute is 000000b or 000001b, nothing else.
    #[test]
    fn area_attributes_are_limited_to_the_two_defined_values() {
        assert!(EmulatedArea::new(0x1000, 0x1FFF).is_ok(), "000000b");
        assert!(EmulatedArea::new(0x1001, 0x1FFF).is_ok(), "000001b");

        for attribute in [0b000010u16, 0b000011, 0b001000, 0b111111] {
            let area_code = 0x1000 | attribute;
            match EmulatedArea::new(area_code, 0x1FFF).map(|_| ()) {
                Err(EmulatorConfigError::InvalidAreaAttribute {
                    area_code: reported,
                    attribute: reported_attribute,
                }) => {
                    assert_eq!(reported, area_code);
                    assert_eq!(u16::from(reported_attribute), attribute);
                }
                other => {
                    panic!("expected InvalidAreaAttribute for {area_code:#06X}, got {other:?}")
                }
            }
        }
    }

    /// Attribute 000001b means "child area creation not possible", so an area
    /// carrying it may hold services but no further area.
    #[test]
    fn an_area_marked_child_area_forbidden_rejects_child_areas() {
        let mut leaf = EmulatedArea::new(0x1001, 0x1FFF).expect("leaf area");
        assert!(!leaf.allows_child_areas());
        assert_eq!(leaf.attribute(), 0b000001);

        // Services are still fine.
        leaf.add_service(EmulatedService::new(ServiceCode::new(0x1008), 1))
            .expect("a leaf area still holds services");

        match leaf
            .add_area(EmulatedArea::new(0x1100, 0x1FFF).expect("child"))
            .map(|_| ())
        {
            Err(EmulatorConfigError::ChildAreaForbidden { area_code }) => {
                assert_eq!(area_code, 0x1001);
            }
            other => panic!("expected ChildAreaForbidden, got {other:?}"),
        }

        let mut branch = EmulatedArea::new(0x2000, 0x2FFF).expect("branch area");
        assert!(branch.allows_child_areas());
        branch
            .add_area(EmulatedArea::new(0x2100, 0x2FFF).expect("child"))
            .expect("attribute 000000b permits child areas");
    }

    /// An attribute outside table 3-2 has no defined kind or access rules.
    #[test]
    fn services_with_an_undefined_attribute_are_rejected() {
        let mut area = EmulatedArea::new(0x1000, 0x1FFF).expect("area");
        match area
            .add_service(EmulatedService::new(ServiceCode::new(0x1000 | 0b011000), 1))
            .map(|_| ())
        {
            Err(EmulatorConfigError::UndefinedServiceAttribute {
                service_code,
                attribute,
            }) => {
                assert_eq!(service_code, 0x1000 | 0b011000);
                assert_eq!(attribute, 0b011000);
            }
            other => panic!("expected UndefinedServiceAttribute, got {other:?}"),
        }
    }

    /// §3.4.6: services sharing a service number overlap onto one set of blocks,
    /// but "ランダム／サイクリック／パースサービスを混用させてオーバーラップさせること
    /// はできません" — each kind reads its blocks differently, so a mixed overlap
    /// has no meaning.
    #[test]
    fn overlapping_services_must_agree_on_the_service_kind() {
        use crate::felica_standard::EmulatedSystem;

        // Service number 0x040: random read/write (0x1000) and random read-only
        // without key (0x100B) overlap legitimately.
        let mut system = EmulatedSystem::new(0x0003, [1; 8], [2; 8]).expect("system");
        let mut area = EmulatedArea::new(0x1000, 0x1FFF).expect("area");
        area.add_service(EmulatedService::new(ServiceCode::new(0x1008), 3))
            .expect("random read/write");
        area.add_service(EmulatedService::new(ServiceCode::new(0x100B), 3))
            .expect("random read-only");
        system
            .add_area(area)
            .expect("a same-kind overlap is allowed");

        // The two now share one block store.
        system
            .root_area()
            .find_service(ServiceCode::new(0x100B))
            .expect("service exists")
            .blocks_mut()[0] = [0xAB; BLOCK_SIZE];
        assert_eq!(
            system
                .root_area()
                .find_service(ServiceCode::new(0x1008))
                .expect("service exists")
                .blocks()[0],
            [0xAB; BLOCK_SIZE],
            "an overlap shares block data"
        );

        // A purse service on the same service number does not.
        let mut system = EmulatedSystem::new(0x0003, [1; 8], [2; 8]).expect("system");
        let mut area = EmulatedArea::new(0x1000, 0x1FFF).expect("area");
        area.add_service(EmulatedService::new(ServiceCode::new(0x1008), 3))
            .expect("random read/write");
        // 0x1010 is service number 0x040 with the purse-direct attribute.
        area.add_service(EmulatedService::new(ServiceCode::new(0x1010), 3))
            .expect("purse direct");
        match system.add_area(area).map(|_| ()) {
            Err(EmulatorConfigError::OverlapKindMismatch {
                service_number,
                existing_kind,
                added_kind,
                ..
            }) => {
                assert_eq!(service_number, 0x040);
                assert_eq!(existing_kind, ServiceKind::Random);
                assert_eq!(added_kind, ServiceKind::Purse);
            }
            other => panic!("expected OverlapKindMismatch, got {other:?}"),
        }
    }
}
