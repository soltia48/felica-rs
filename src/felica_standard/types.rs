use super::BLOCK_SIZE;
use super::secure::encrypt_des_block;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceCode(pub u16);

impl ServiceCode {
    pub fn new(raw: u16) -> Self {
        ServiceCode(raw)
    }

    pub fn raw(&self) -> u16 {
        self.0
    }

    pub fn number(&self) -> u16 {
        self.0 >> 6
    }

    pub fn attributes(&self) -> u8 {
        (self.0 & 0x3F) as u8
    }

    pub fn attributes_description(&self) -> Option<&'static str> {
        match self.attributes() {
            0b001000 => Some("Random read/write with key"),
            0b001001 => Some("Random read/write without key"),
            0b001010 => Some("Random read-only with key"),
            0b001011 => Some("Random read-only without key"),
            0b001100 => Some("Cyclic read/write with key"),
            0b001101 => Some("Cyclic read/write without key"),
            0b001110 => Some("Cyclic read-only with key"),
            0b001111 => Some("Cyclic read-only without key"),
            0b010000 => Some("Purse direct with key"),
            0b010001 => Some("Purse direct without key"),
            0b010010 => Some("Purse cashback with key"),
            0b010011 => Some("Purse cashback without key"),
            0b010100 => Some("Purse decrement with key"),
            0b010101 => Some("Purse decrement without key"),
            0b010110 => Some("Purse read-only with key"),
            0b010111 => Some("Purse read-only without key"),
            _ => None,
        }
    }

    pub fn requires_key(&self) -> bool {
        self.0 & 0x0001 == 0
    }

    pub(crate) fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusFlag1 {
    NormalCompletion,
    ErrorNotAssociatedWithList,
    ErrorAtListIndex(u8),
}

impl StatusFlag1 {
    pub fn from_byte(value: u8) -> Self {
        match value {
            0x00 => StatusFlag1::NormalCompletion,
            0xFF => StatusFlag1::ErrorNotAssociatedWithList,
            other => StatusFlag1::ErrorAtListIndex(other),
        }
    }

    pub fn description(&self) -> String {
        match self {
            StatusFlag1::NormalCompletion => "normal completion".to_string(),
            StatusFlag1::ErrorNotAssociatedWithList => {
                "error not associated with a specific list entry".to_string()
            }
            StatusFlag1::ErrorAtListIndex(index) => format!("error at list index {}", index),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusFlag2 {
    NormalCompletion,
    PurseDecrementUnderflowOrCashbackOverflow,
    CashbackExceedsStoredValue,
    LimitPurseOutOfRange,
    MemoryError,
    MemoryWriteCountExceeded,
    ServiceOrNodeCountOutOfRange,
    BlockCountOutOfRange,
    ServiceListIndexOutOfRange,
    AreaOrServiceAttributeMismatch,
    AccessDeniedOrParameterMismatch,
    ReferencedNodeDoesNotExist,
    InvalidAccessMode,
    BlockNumberOutOfRange,
    IssuingWriteFailure,
    KeyChangeFailed,
    PackageParityOrMacInvalid,
    InvalidParameters,
    ServiceAlreadyExists,
    InvalidSystemCode,
    CyclicServiceWriteOverflow,
    PackageIdentifierInvalid,
    PackageParameterMismatch,
    IssuingCommandDisabled,
    NodeAttributeMismatch,
    Unknown(u8),
}

impl StatusFlag2 {
    pub fn from_byte(value: u8) -> Self {
        match value {
            0x00 => StatusFlag2::NormalCompletion,
            0x01 => StatusFlag2::PurseDecrementUnderflowOrCashbackOverflow,
            0x02 => StatusFlag2::CashbackExceedsStoredValue,
            0x03 => StatusFlag2::LimitPurseOutOfRange,
            0x70 => StatusFlag2::MemoryError,
            0x71 => StatusFlag2::MemoryWriteCountExceeded,
            0xA1 => StatusFlag2::ServiceOrNodeCountOutOfRange,
            0xA2 => StatusFlag2::BlockCountOutOfRange,
            0xA3 => StatusFlag2::ServiceListIndexOutOfRange,
            0xA4 => StatusFlag2::AreaOrServiceAttributeMismatch,
            0xA5 => StatusFlag2::AccessDeniedOrParameterMismatch,
            0xA6 => StatusFlag2::ReferencedNodeDoesNotExist,
            0xA7 => StatusFlag2::InvalidAccessMode,
            0xA8 => StatusFlag2::BlockNumberOutOfRange,
            0xA9 => StatusFlag2::IssuingWriteFailure,
            0xAA => StatusFlag2::KeyChangeFailed,
            0xAB => StatusFlag2::PackageParityOrMacInvalid,
            0xAC => StatusFlag2::InvalidParameters,
            0xAD => StatusFlag2::ServiceAlreadyExists,
            0xAE => StatusFlag2::InvalidSystemCode,
            0xAF => StatusFlag2::CyclicServiceWriteOverflow,
            0xC0 => StatusFlag2::PackageIdentifierInvalid,
            0xC1 => StatusFlag2::PackageParameterMismatch,
            0xC2 => StatusFlag2::IssuingCommandDisabled,
            0xC3 => StatusFlag2::NodeAttributeMismatch,
            other => StatusFlag2::Unknown(other),
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            StatusFlag2::NormalCompletion => "no additional error detail",
            StatusFlag2::PurseDecrementUnderflowOrCashbackOverflow => {
                "purse decrement would underflow or cashback overflow"
            }
            StatusFlag2::CashbackExceedsStoredValue => "cashback amount exceeds stored purse value",
            StatusFlag2::LimitPurseOutOfRange => "limit purse write outside allowed range",
            StatusFlag2::MemoryError => "memory error",
            StatusFlag2::MemoryWriteCountExceeded => "memory write count exceeded",
            StatusFlag2::ServiceOrNodeCountOutOfRange => "service/node count out of range",
            StatusFlag2::BlockCountOutOfRange => "block count out of range",
            StatusFlag2::ServiceListIndexOutOfRange => "service list index out of range",
            StatusFlag2::AreaOrServiceAttributeMismatch => "area or service attribute mismatch",
            StatusFlag2::AccessDeniedOrParameterMismatch => {
                "access denied or parameters do not satisfy constraints"
            }
            StatusFlag2::ReferencedNodeDoesNotExist => {
                "referenced service/area/node does not exist"
            }
            StatusFlag2::InvalidAccessMode => "invalid access mode",
            StatusFlag2::BlockNumberOutOfRange => "block number exceeds service size",
            StatusFlag2::IssuingWriteFailure => "issuing command write failure",
            StatusFlag2::KeyChangeFailed => "key change failed",
            StatusFlag2::PackageParityOrMacInvalid => "package parity or MAC invalid",
            StatusFlag2::InvalidParameters => "invalid parameters",
            StatusFlag2::ServiceAlreadyExists => "service already exists",
            StatusFlag2::InvalidSystemCode => "system code invalid",
            StatusFlag2::CyclicServiceWriteOverflow => {
                "cyclic service simultaneous writes exceed service blocks"
            }
            StatusFlag2::PackageIdentifierInvalid => "package identifier invalid",
            StatusFlag2::PackageParameterMismatch => "package parameter mismatch",
            StatusFlag2::IssuingCommandDisabled => "issuing command disabled",
            StatusFlag2::NodeAttributeMismatch => "node attribute mismatch",
            StatusFlag2::Unknown(_) => "unknown status flag 2",
        }
    }
}

pub fn status_flag_description(sf1: u8, sf2: u8) -> String {
    let sf1_desc = StatusFlag1::from_byte(sf1).description();
    let sf2_desc = StatusFlag2::from_byte(sf2).description();
    format!("SF1: {sf1_desc}; SF2: {sf2_desc}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockListElement {
    pub block_number_or_key_version: u16,
    pub service_code_list_index: u8,
    pub access_mode: u8,
}

impl BlockListElement {
    pub fn new(
        block_number_or_key_version: u16,
        service_code_list_index: u8,
        access_mode: u8,
    ) -> Self {
        Self {
            block_number_or_key_version,
            service_code_list_index,
            access_mode,
        }
    }

    pub(crate) fn pack(&self) -> Vec<u8> {
        let mut descriptor = Vec::new();
        if self.block_number_or_key_version < 256 {
            let header =
                0x80 | ((self.access_mode & 0x07) << 4) | (self.service_code_list_index & 0x0F);
            descriptor.push(header);
            descriptor.push(self.block_number_or_key_version as u8);
        } else {
            let header = ((self.access_mode & 0x07) << 4) | (self.service_code_list_index & 0x0F);
            descriptor.push(header);
            descriptor.extend_from_slice(&self.block_number_or_key_version.to_le_bytes());
        }
        descriptor
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchServiceCodeResult {
    Service(ServiceCode),
    Area {
        area_code: u16,
        end_service_code: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AreaCodeRange {
    pub area_code: u16,
    pub end_service_code: u16,
}

impl AreaCodeRange {
    pub fn new(area_code: u16, end_service_code: u16) -> Self {
        Self {
            area_code,
            end_service_code,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainerInformation {
    pub format_version_carrier_information: [u8; 5],
    pub mobile_phone_model_information: [u8; 11],
}

impl ContainerInformation {
    pub fn new(
        format_version_carrier_information: [u8; 5],
        mobile_phone_model_information: [u8; 11],
    ) -> Self {
        Self {
            format_version_carrier_information,
            mobile_phone_model_information,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerProperty {
    Property1,
    Property2,
    Unknown(u16),
}

impl ContainerProperty {
    pub fn index(self) -> u16 {
        match self {
            ContainerProperty::Property1 => 0x0000,
            ContainerProperty::Property2 => 0x0001,
            ContainerProperty::Unknown(index) => index,
        }
    }

    pub(crate) fn to_index(self) -> u16 {
        self.index()
    }

    pub(crate) fn from_index(index: u16) -> Self {
        match index {
            0x0000 => ContainerProperty::Property1,
            0x0001 => ContainerProperty::Property2,
            _ => ContainerProperty::Unknown(index),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodePropertyType {
    ValueLimitedPurseService,
    MacCommunication,
}

impl NodePropertyType {
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            NodePropertyType::ValueLimitedPurseService => 0x00,
            NodePropertyType::MacCommunication => 0x01,
        }
    }

    pub(crate) fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(NodePropertyType::ValueLimitedPurseService),
            0x01 => Some(NodePropertyType::MacCommunication),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeProperty {
    ValueLimitedPurseService {
        enabled: bool,
        upper_limit: i32,
        lower_limit: i32,
        generation_number: u8,
    },
    MacCommunication {
        enabled: bool,
    },
}

impl NodeProperty {
    pub fn property_type(&self) -> NodePropertyType {
        match self {
            NodeProperty::ValueLimitedPurseService { .. } => {
                NodePropertyType::ValueLimitedPurseService
            }
            NodeProperty::MacCommunication { .. } => NodePropertyType::MacCommunication,
        }
    }

    pub(crate) fn size_bytes(self) -> usize {
        match self {
            NodeProperty::ValueLimitedPurseService { .. } => 10,
            NodeProperty::MacCommunication { .. } => 1,
        }
    }

    pub(crate) fn to_bytes(self) -> Vec<u8> {
        match self {
            NodeProperty::ValueLimitedPurseService {
                enabled,
                upper_limit,
                lower_limit,
                generation_number,
            } => {
                let mut bytes = Vec::with_capacity(10);
                bytes.push(if enabled { 0x01 } else { 0x00 });
                bytes.extend_from_slice(&upper_limit.to_le_bytes());
                bytes.extend_from_slice(&lower_limit.to_le_bytes());
                bytes.push(generation_number);
                bytes
            }
            NodeProperty::MacCommunication { enabled } => {
                vec![if enabled { 0x01 } else { 0x00 }]
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetParameterEncryptionType {
    SrmType1,
    SrmType2,
}

impl SetParameterEncryptionType {
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            SetParameterEncryptionType::SrmType1 => 0x00,
            SetParameterEncryptionType::SrmType2 => 0x01,
        }
    }

    pub(crate) fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(SetParameterEncryptionType::SrmType1),
            0x01 => Some(SetParameterEncryptionType::SrmType2),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetParameterPacketType {
    NodeCodeSize2,
    NodeCodeSize4,
}

impl SetParameterPacketType {
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            SetParameterPacketType::NodeCodeSize2 => 0x00,
            SetParameterPacketType::NodeCodeSize4 => 0x01,
        }
    }

    pub(crate) fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(SetParameterPacketType::NodeCodeSize2),
            0x01 => Some(SetParameterPacketType::NodeCodeSize4),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestCodeListResult {
    pub continue_flag: bool,
    pub areas: Vec<AreaCodeRange>,
    pub services: Vec<ServiceCode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestBlockInformationExResult {
    pub assigned_block_counts: Vec<u16>,
    pub free_block_counts: Vec<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetAreaInformationResult {
    pub node_code: u16,
    pub data: [u8; 2],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetNodePropertyResult {
    pub node_properties: Vec<NodeProperty>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetSystemStatusResult {
    pub flag: u8,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl OptionVersion {
    pub fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major: major & 0x0F,
            minor: minor & 0x0F,
            patch: patch & 0x0F,
        }
    }

    pub(crate) fn from_le_bytes(bytes: [u8; 2]) -> Self {
        Self {
            major: bytes[1] & 0x0F,
            minor: (bytes[0] >> 4) & 0x0F,
            patch: bytes[0] & 0x0F,
        }
    }

    pub(crate) fn to_le_bytes(self) -> [u8; 2] {
        [
            ((self.minor & 0x0F) << 4) | (self.patch & 0x0F),
            0x80 | (self.major & 0x0F),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecificationVersion {
    pub format_version: u8,
    pub basic_version: OptionVersion,
    pub option_versions: Vec<OptionVersion>,
}

impl SpecificationVersion {
    pub fn des_option_version(&self) -> Option<OptionVersion> {
        self.option_versions.first().copied()
    }

    pub fn special_option_version(&self) -> Option<OptionVersion> {
        self.option_versions.get(1).copied()
    }

    pub fn extended_overlap_option_version(&self) -> Option<OptionVersion> {
        self.option_versions.get(2).copied()
    }

    pub fn value_limited_purse_service_option_version(&self) -> Option<OptionVersion> {
        self.option_versions.get(3).copied()
    }

    pub fn communication_with_mac_option_version(&self) -> Option<OptionVersion> {
        self.option_versions.get(4).copied()
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.option_versions.len() * 2);
        bytes.push(self.format_version);
        bytes.extend_from_slice(&self.basic_version.to_le_bytes());
        bytes.push(self.option_versions.len() as u8);
        for version in &self.option_versions {
            bytes.extend_from_slice(&version.to_le_bytes());
        }
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadWithoutEncryptionResult {
    pub blocks: Vec<[u8; BLOCK_SIZE]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadResult {
    pub blocks: Vec<[u8; BLOCK_SIZE]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestServiceV2Result {
    pub crypto_id: u8,
    pub key_versions: Vec<RequestServiceV2KeyVersion>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterIssueIdResult {
    pub remaining_blocks: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterServiceResult {
    pub remaining_blocks: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutualAuthenticationResult {
    pub issue_id: [u8; 8],
    pub issue_parameter: [u8; 8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeKeyParameters {
    pub parent_key: [u8; 8],
    pub new_key: [u8; 8],
    pub old_key: [u8; 8],
    pub new_key_version: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestServiceV2KeyVersion {
    Single(u16),
    Dual { aes: u16, des: u16 },
}

impl RequestServiceV2KeyVersion {
    const NO_KEY_VERSION: u16 = 0xFFFF;

    pub fn single(value: u16) -> Self {
        RequestServiceV2KeyVersion::Single(value)
    }

    pub fn dual(aes: u16, des: u16) -> Self {
        RequestServiceV2KeyVersion::Dual { aes, des }
    }

    pub fn primary(&self) -> Option<u16> {
        match self {
            RequestServiceV2KeyVersion::Single(value) => Self::normalize_key_version(*value),
            RequestServiceV2KeyVersion::Dual { aes, .. } => Self::normalize_key_version(*aes),
        }
    }

    pub fn secondary(&self) -> Option<u16> {
        match self {
            RequestServiceV2KeyVersion::Single(_) => None,
            RequestServiceV2KeyVersion::Dual { des, .. } => Self::normalize_key_version(*des),
        }
    }

    pub(crate) fn primary_raw(&self) -> u16 {
        match self {
            RequestServiceV2KeyVersion::Single(value) => *value,
            RequestServiceV2KeyVersion::Dual { aes, .. } => *aes,
        }
    }

    pub(crate) fn secondary_raw(&self) -> Option<u16> {
        match self {
            RequestServiceV2KeyVersion::Single(_) => None,
            RequestServiceV2KeyVersion::Dual { des, .. } => Some(*des),
        }
    }

    fn normalize_key_version(value: u16) -> Option<u16> {
        if value == Self::NO_KEY_VERSION {
            None
        } else {
            Some(value)
        }
    }
}

impl ChangeKeyParameters {
    pub fn new(
        parent_key: [u8; 8],
        new_key: [u8; 8],
        old_key: [u8; 8],
        new_key_version: u16,
    ) -> Self {
        Self {
            parent_key,
            new_key,
            old_key,
            new_key_version,
        }
    }

    pub fn new_key_version(&self) -> u16 {
        self.new_key_version
    }

    pub(crate) fn block_descriptor_block_number(&self) -> u16 {
        self.new_key_version
    }

    pub(crate) fn payload(&self) -> [u8; 16] {
        let mut version_block = [0u8; 8];
        version_block[6..].copy_from_slice(&self.new_key_version.to_le_bytes());

        let mut parameter1 = encrypt_des_block(&version_block, &self.new_key);
        parameter1 = encrypt_des_block(&parameter1, &self.old_key);
        parameter1 = encrypt_des_block(&parameter1, &self.parent_key);

        let mut parameter2 = encrypt_des_block(&self.new_key, &self.old_key);
        parameter2 = encrypt_des_block(&parameter2, &self.parent_key);

        let mut payload = [0u8; 16];
        payload[..8].copy_from_slice(&parameter1);
        payload[8..].copy_from_slice(&parameter2);
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_code_accessors_descriptions_and_key_requirement() {
        let code = ServiceCode::new((0x123 << 6) | 0b001010);
        assert_eq!(code.raw(), (0x123 << 6) | 0b001010);
        assert_eq!(code.number(), 0x123);
        assert_eq!(code.attributes(), 0b001010);
        assert_eq!(
            code.attributes_description(),
            Some("Random read-only with key")
        );
        assert!(code.requires_key());
        assert_eq!(code.to_le_bytes(), code.raw().to_le_bytes());

        let no_key = ServiceCode::new((0x001 << 6) | 0b001001);
        assert!(!no_key.requires_key());
        assert_eq!(
            no_key.attributes_description(),
            Some("Random read/write without key")
        );
    }

    #[test]
    fn status_flags_map_from_byte_and_descriptions() {
        assert_eq!(StatusFlag1::from_byte(0x00), StatusFlag1::NormalCompletion);
        assert_eq!(
            StatusFlag1::from_byte(0xFF),
            StatusFlag1::ErrorNotAssociatedWithList
        );
        assert_eq!(
            StatusFlag1::from_byte(0x12),
            StatusFlag1::ErrorAtListIndex(0x12)
        );
        assert_eq!(
            StatusFlag1::from_byte(0x05).description(),
            "error at list index 5"
        );

        assert_eq!(
            StatusFlag2::from_byte(0xA2),
            StatusFlag2::BlockCountOutOfRange
        );
        assert_eq!(StatusFlag2::from_byte(0xFE), StatusFlag2::Unknown(0xFE));
        assert_eq!(
            StatusFlag2::from_byte(0xAB).description(),
            "package parity or MAC invalid"
        );
    }

    #[test]
    fn status_flag_description_formats_both_flags() {
        let text = status_flag_description(0x02, 0xA8);
        assert!(text.contains("SF1: error at list index 2"));
        assert!(text.contains("SF2: block number exceeds service size"));
    }

    #[test]
    fn block_list_element_pack_short_and_extended_forms() {
        let short = BlockListElement::new(0x12, 0x0A, 0x05).pack();
        assert_eq!(short, vec![0xDA, 0x12]);

        let extended = BlockListElement::new(0x1234, 0x03, 0x02).pack();
        assert_eq!(extended, vec![0x23, 0x34, 0x12]);
    }

    #[test]
    fn container_property_and_node_property_type_round_trip() {
        assert_eq!(ContainerProperty::Property1.index(), 0x0000);
        assert_eq!(ContainerProperty::Property2.to_index(), 0x0001);
        assert_eq!(
            ContainerProperty::from_index(0x2222),
            ContainerProperty::Unknown(0x2222)
        );
        assert_eq!(ContainerProperty::Unknown(0xABCD).index(), 0xABCD);

        assert_eq!(
            NodePropertyType::from_byte(NodePropertyType::ValueLimitedPurseService.to_byte()),
            Some(NodePropertyType::ValueLimitedPurseService)
        );
        assert_eq!(
            NodePropertyType::from_byte(NodePropertyType::MacCommunication.to_byte()),
            Some(NodePropertyType::MacCommunication)
        );
        assert_eq!(NodePropertyType::from_byte(0xFF), None);
    }

    #[test]
    fn node_property_sizes_and_serialization_are_consistent() {
        let purse = NodeProperty::ValueLimitedPurseService {
            enabled: true,
            upper_limit: 1_000,
            lower_limit: -500,
            generation_number: 7,
        };
        assert_eq!(
            purse.property_type(),
            NodePropertyType::ValueLimitedPurseService
        );
        assert_eq!(purse.size_bytes(), 10);
        let purse_bytes = purse.to_bytes();
        assert_eq!(purse_bytes.len(), 10);
        assert_eq!(purse_bytes[0], 0x01);
        assert_eq!(&purse_bytes[1..5], &1_000i32.to_le_bytes());
        assert_eq!(&purse_bytes[5..9], &(-500i32).to_le_bytes());
        assert_eq!(purse_bytes[9], 7);

        let mac = NodeProperty::MacCommunication { enabled: false };
        assert_eq!(mac.property_type(), NodePropertyType::MacCommunication);
        assert_eq!(mac.size_bytes(), 1);
        assert_eq!(mac.to_bytes(), vec![0x00]);
    }

    #[test]
    fn set_parameter_enums_round_trip() {
        assert_eq!(
            SetParameterEncryptionType::from_byte(SetParameterEncryptionType::SrmType1.to_byte()),
            Some(SetParameterEncryptionType::SrmType1)
        );
        assert_eq!(
            SetParameterEncryptionType::from_byte(SetParameterEncryptionType::SrmType2.to_byte()),
            Some(SetParameterEncryptionType::SrmType2)
        );
        assert_eq!(SetParameterEncryptionType::from_byte(0xFF), None);

        assert_eq!(
            SetParameterPacketType::from_byte(SetParameterPacketType::NodeCodeSize2.to_byte()),
            Some(SetParameterPacketType::NodeCodeSize2)
        );
        assert_eq!(
            SetParameterPacketType::from_byte(SetParameterPacketType::NodeCodeSize4.to_byte()),
            Some(SetParameterPacketType::NodeCodeSize4)
        );
        assert_eq!(SetParameterPacketType::from_byte(0xFF), None);
    }

    #[test]
    fn option_version_and_specification_version_serialization() {
        let version = OptionVersion::new(0x12, 0x34, 0x56);
        assert_eq!(version.major, 0x02);
        assert_eq!(version.minor, 0x04);
        assert_eq!(version.patch, 0x06);
        assert_eq!(version.to_le_bytes(), [0x46, 0x82]);
        assert_eq!(
            OptionVersion::from_le_bytes(version.to_le_bytes()),
            OptionVersion::new(0x02, 0x04, 0x06)
        );

        let spec = SpecificationVersion {
            format_version: 1,
            basic_version: OptionVersion::new(1, 2, 3),
            option_versions: vec![
                OptionVersion::new(4, 5, 6),
                OptionVersion::new(7, 8, 9),
                OptionVersion::new(10, 11, 12),
                OptionVersion::new(13, 14, 15),
                OptionVersion::new(1, 1, 1),
            ],
        };
        assert_eq!(spec.des_option_version(), Some(OptionVersion::new(4, 5, 6)));
        assert_eq!(
            spec.special_option_version(),
            Some(OptionVersion::new(7, 8, 9))
        );
        assert_eq!(
            spec.extended_overlap_option_version(),
            Some(OptionVersion::new(10, 11, 12))
        );
        assert_eq!(
            spec.value_limited_purse_service_option_version(),
            Some(OptionVersion::new(13, 14, 15))
        );
        assert_eq!(
            spec.communication_with_mac_option_version(),
            Some(OptionVersion::new(1, 1, 1))
        );
        let serialized = spec.to_bytes();
        assert_eq!(serialized.len(), 14);
        assert_eq!(serialized[0], 1);
        assert_eq!(serialized[1..3], [0x23, 0x81]);
        assert_eq!(serialized[3], 5);
    }

    #[test]
    fn request_service_v2_key_version_accessors_normalize_no_key_value() {
        let single = RequestServiceV2KeyVersion::single(0x1234);
        assert_eq!(single.primary(), Some(0x1234));
        assert_eq!(single.secondary(), None);
        assert_eq!(single.primary_raw(), 0x1234);
        assert_eq!(single.secondary_raw(), None);

        let single_none = RequestServiceV2KeyVersion::single(0xFFFF);
        assert_eq!(single_none.primary(), None);
        assert_eq!(single_none.secondary(), None);

        let dual = RequestServiceV2KeyVersion::dual(0x1000, 0xFFFF);
        assert_eq!(dual.primary(), Some(0x1000));
        assert_eq!(dual.secondary(), None);
        assert_eq!(dual.primary_raw(), 0x1000);
        assert_eq!(dual.secondary_raw(), Some(0xFFFF));
    }

    #[test]
    fn change_key_parameters_accessors_and_payload_shape() {
        let params = ChangeKeyParameters::new([1; 8], [2; 8], [3; 8], 0x1234);
        assert_eq!(params.new_key_version(), 0x1234);
        assert_eq!(params.block_descriptor_block_number(), 0x1234);

        let payload_a = params.payload();
        assert_eq!(payload_a.len(), 16);

        let payload_b = ChangeKeyParameters::new([1; 8], [2; 8], [3; 8], 0x1235).payload();
        assert_ne!(payload_a, payload_b);
    }
}
