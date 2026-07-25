use super::BLOCK_SIZE;
use super::secure::encrypt_des_block;

/// The three kinds of service §3.4 defines, each with its own block access rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceKind {
    /// §3.4.2 — any block number may be read or written.
    Random,
    /// §3.4.3 — a log ring: reads pick a generation, writes always land on the
    /// oldest block and must address block number 0.
    Cyclic,
    /// §3.4.4 — a stored value with automatic decrement/cashback arithmetic.
    Purse,
}

/// A service attribute from §3.4.1 (table 3-2), with the authentication bit
/// (b0) factored out into [`ServiceCode::requires_key`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceAttribute {
    /// `0010 00b` / `0010 01b` — random service, read/write access.
    RandomReadWrite,
    /// `0010 10b` / `0010 11b` — random service, read-only access.
    RandomReadOnly,
    /// `0011 00b` / `0011 01b` — cyclic service, read/write access.
    CyclicReadWrite,
    /// `0011 10b` / `0011 11b` — cyclic service, read-only access.
    CyclicReadOnly,
    /// `0100 00b` / `0100 01b` — purse service, direct access. No arithmetic:
    /// the purse value is written as given (table 3-6).
    PurseDirect,
    /// `0100 10b` / `0100 11b` — purse service, cashback **and** decrement
    /// access (table 3-6).
    PurseCashback,
    /// `0101 00b` / `0101 01b` — purse service, decrement access only.
    PurseDecrement,
    /// `0101 10b` / `0101 11b` — purse service, read-only access.
    PurseReadOnly,
}

impl ServiceAttribute {
    /// Decodes the six-bit service attribute, ignoring its authentication bit.
    ///
    /// Returns `None` for the values table 3-2 leaves undefined.
    pub fn from_attribute_bits(attribute: u8) -> Option<Self> {
        // b0 is the authentication requirement, so the kind and access mode live
        // in b5-b1 and every attribute pairs an "auth required" value with the
        // "auth not required" value one greater.
        match (attribute & 0x3F) >> 1 {
            0b00100 => Some(ServiceAttribute::RandomReadWrite),
            0b00101 => Some(ServiceAttribute::RandomReadOnly),
            0b00110 => Some(ServiceAttribute::CyclicReadWrite),
            0b00111 => Some(ServiceAttribute::CyclicReadOnly),
            0b01000 => Some(ServiceAttribute::PurseDirect),
            0b01001 => Some(ServiceAttribute::PurseCashback),
            0b01010 => Some(ServiceAttribute::PurseDecrement),
            0b01011 => Some(ServiceAttribute::PurseReadOnly),
            _ => None,
        }
    }

    /// Which of the three §3.4 service kinds this attribute belongs to.
    pub fn kind(self) -> ServiceKind {
        match self {
            ServiceAttribute::RandomReadWrite | ServiceAttribute::RandomReadOnly => {
                ServiceKind::Random
            }
            ServiceAttribute::CyclicReadWrite | ServiceAttribute::CyclicReadOnly => {
                ServiceKind::Cyclic
            }
            ServiceAttribute::PurseDirect
            | ServiceAttribute::PurseCashback
            | ServiceAttribute::PurseDecrement
            | ServiceAttribute::PurseReadOnly => ServiceKind::Purse,
        }
    }

    /// Whether blocks of this service may be written at all (tables 3-3, 3-4, 3-6).
    pub fn allows_write(self) -> bool {
        !matches!(
            self,
            ServiceAttribute::RandomReadOnly
                | ServiceAttribute::CyclicReadOnly
                | ServiceAttribute::PurseReadOnly
        )
    }

    /// Whether the purse decrement function applies on write (table 3-6).
    pub fn allows_decrement(self) -> bool {
        matches!(
            self,
            ServiceAttribute::PurseCashback | ServiceAttribute::PurseDecrement
        )
    }

    /// Whether the purse cashback function applies, i.e. whether block list
    /// access mode `001b` is accepted (table 3-6, §4.4.6).
    pub fn allows_cashback(self) -> bool {
        matches!(self, ServiceAttribute::PurseCashback)
    }

    fn label(self) -> &'static str {
        match self {
            ServiceAttribute::RandomReadWrite => "Random read/write",
            ServiceAttribute::RandomReadOnly => "Random read-only",
            ServiceAttribute::CyclicReadWrite => "Cyclic read/write",
            ServiceAttribute::CyclicReadOnly => "Cyclic read-only",
            ServiceAttribute::PurseDirect => "Purse direct",
            ServiceAttribute::PurseCashback => "Purse cashback/decrement",
            ServiceAttribute::PurseDecrement => "Purse decrement",
            ServiceAttribute::PurseReadOnly => "Purse read-only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceCode(pub u16);

impl ServiceCode {
    pub fn new(raw: u16) -> Self {
        ServiceCode(raw)
    }

    pub fn raw(&self) -> u16 {
        self.0
    }

    /// The service number: the upper 10 bits of the service code (§3.4.1, figure 3-9).
    pub fn number(&self) -> u16 {
        self.0 >> 6
    }

    /// The raw six-bit service attribute (§3.4.1, figure 3-9).
    pub fn attributes(&self) -> u8 {
        (self.0 & 0x3F) as u8
    }

    /// The decoded service attribute, or `None` if the six attribute bits are
    /// not one of the values table 3-2 defines.
    pub fn attribute(&self) -> Option<ServiceAttribute> {
        ServiceAttribute::from_attribute_bits(self.attributes())
    }

    /// Which of the three §3.4 service kinds this service is, or `None` for an
    /// attribute table 3-2 does not define.
    pub fn kind(&self) -> Option<ServiceKind> {
        self.attribute().map(ServiceAttribute::kind)
    }

    pub fn attributes_description(&self) -> Option<String> {
        let suffix = if self.requires_key() {
            "with key"
        } else {
            "without key"
        };
        Some(format!("{} {suffix}", self.attribute()?.label()))
    }

    /// Whether accessing this service requires prior mutual authentication.
    ///
    /// The authentication requirement is the low bit of the service attribute:
    /// table 3-2 pairs every "認証必要" value with the "認証不要" value one
    /// greater, so an even attribute requires a key.
    pub fn requires_key(&self) -> bool {
        self.0 & 0x0001 == 0
    }

    pub(crate) fn to_le_bytes(self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
}

/// Status flag 1 (§4.5.1): whether the card completed the command, and if not,
/// which service-code-list or block-list entry failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusFlag1 {
    /// `00h` — the card processed the command normally.
    NormalCompletion,
    /// `FFh` — the command carried no list, or the error does not belong to a
    /// particular list entry.
    ErrorNotAssociatedWithList,
    /// `XXh` — the error belongs to a list entry. The byte is kept raw because
    /// §4.5.1 defines **two** product-dependent encodings for it and the
    /// response carries no indication of which one a card uses; see
    /// [`ordinal_position`](Self::ordinal_position) and
    /// [`bitmap_positions`](Self::bitmap_positions).
    ErrorAtListPosition(u8),
}

impl StatusFlag1 {
    pub fn from_byte(value: u8) -> Self {
        match value {
            0x00 => StatusFlag1::NormalCompletion,
            0xFF => StatusFlag1::ErrorNotAssociatedWithList,
            other => StatusFlag1::ErrorAtListPosition(other),
        }
    }

    /// The raw error byte, for [`ErrorAtListPosition`](Self::ErrorAtListPosition).
    pub fn error_byte(&self) -> Option<u8> {
        match self {
            StatusFlag1::ErrorAtListPosition(value) => Some(*value),
            _ => None,
        }
    }

    /// Reads the error byte under §4.5.1's "エラー箇所を順番で示す" encoding, where
    /// the byte *is* the 1-based position in the list — an error on the 10th
    /// block list entry is reported as `0Ah`.
    pub fn ordinal_position(&self) -> Option<u8> {
        self.error_byte()
    }

    /// Reads the error byte under §4.5.1's "エラー箇所をビットデータで示す" encoding,
    /// returning every 1-based list position a set bit can denote.
    ///
    /// In that encoding bit *n* (for `n` in 0..=6) means the *(n+1)*-th **or**
    /// *(n+9)*-th entry, and bit 7 means the 8th entry; the encoding cannot tell
    /// the two candidates of a bit apart, so both are returned. An error on the
    /// 10th entry is reported as `02h`, which yields positions 2 and 10.
    pub fn bitmap_positions(&self) -> Vec<u8> {
        let Some(value) = self.error_byte() else {
            return Vec::new();
        };
        let mut positions = Vec::new();
        for bit in 0..8u8 {
            if value & (1 << bit) == 0 {
                continue;
            }
            positions.push(bit + 1);
            if bit <= 6 {
                positions.push(bit + 9);
            }
        }
        positions.sort_unstable();
        positions
    }

    pub fn description(&self) -> String {
        match self {
            StatusFlag1::NormalCompletion => "normal completion".to_string(),
            StatusFlag1::ErrorNotAssociatedWithList => {
                "error not associated with a specific list entry".to_string()
            }
            // Both readings are surfaced because the card does not say which
            // encoding it used, and §4.5.2 warns that these flags are for
            // debugging rather than operational error handling.
            StatusFlag1::ErrorAtListPosition(value) => {
                let bitmap = self
                    .bitmap_positions()
                    .iter()
                    .map(|position| position.to_string())
                    .collect::<Vec<_>>()
                    .join("/");
                format!(
                    "error at list position {value} (ordinal encoding) or {bitmap} (bit encoding)"
                )
            }
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

    pub fn random_id_option_version(&self) -> Option<OptionVersion> {
        self.option_versions.get(5).copied()
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
            code.attributes_description().as_deref(),
            Some("Random read-only with key")
        );
        assert!(code.requires_key());
        assert_eq!(code.to_le_bytes(), code.raw().to_le_bytes());

        let no_key = ServiceCode::new((0x001 << 6) | 0b001001);
        assert!(!no_key.requires_key());
        assert_eq!(
            no_key.attributes_description().as_deref(),
            Some("Random read/write without key")
        );
    }

    /// Every attribute in table 3-2, checked against the kind and the access
    /// rules tables 3-3, 3-4 and 3-6 assign it.
    #[test]
    fn service_attribute_table_3_2_is_decoded_completely() {
        use ServiceAttribute::*;
        let expected = [
            (0b001000u8, RandomReadWrite, ServiceKind::Random, true),
            (0b001001, RandomReadWrite, ServiceKind::Random, false),
            (0b001010, RandomReadOnly, ServiceKind::Random, true),
            (0b001011, RandomReadOnly, ServiceKind::Random, false),
            (0b001100, CyclicReadWrite, ServiceKind::Cyclic, true),
            (0b001101, CyclicReadWrite, ServiceKind::Cyclic, false),
            (0b001110, CyclicReadOnly, ServiceKind::Cyclic, true),
            (0b001111, CyclicReadOnly, ServiceKind::Cyclic, false),
            (0b010000, PurseDirect, ServiceKind::Purse, true),
            (0b010001, PurseDirect, ServiceKind::Purse, false),
            (0b010010, PurseCashback, ServiceKind::Purse, true),
            (0b010011, PurseCashback, ServiceKind::Purse, false),
            (0b010100, PurseDecrement, ServiceKind::Purse, true),
            (0b010101, PurseDecrement, ServiceKind::Purse, false),
            (0b010110, PurseReadOnly, ServiceKind::Purse, true),
            (0b010111, PurseReadOnly, ServiceKind::Purse, false),
        ];
        for (bits, attribute, kind, requires_key) in expected {
            let code = ServiceCode::new((0x123 << 6) | u16::from(bits));
            assert_eq!(code.attribute(), Some(attribute), "attribute {bits:06b}");
            assert_eq!(code.kind(), Some(kind), "kind {bits:06b}");
            assert_eq!(code.requires_key(), requires_key, "key {bits:06b}");
            assert!(code.attributes_description().is_some());
        }

        // Read-only attributes are the only ones that forbid writing.
        assert!(RandomReadWrite.allows_write());
        assert!(CyclicReadWrite.allows_write());
        assert!(PurseDirect.allows_write());
        assert!(PurseCashback.allows_write());
        assert!(PurseDecrement.allows_write());
        assert!(!RandomReadOnly.allows_write());
        assert!(!CyclicReadOnly.allows_write());
        assert!(!PurseReadOnly.allows_write());

        // Table 3-6: cashback belongs to the cashback/decrement attribute alone,
        // and direct access performs no arithmetic at all.
        assert!(PurseCashback.allows_cashback());
        assert!(!PurseDecrement.allows_cashback());
        assert!(PurseCashback.allows_decrement());
        assert!(PurseDecrement.allows_decrement());
        assert!(!PurseDirect.allows_decrement());
        assert!(!PurseDirect.allows_cashback());

        // Values outside table 3-2 have no meaning.
        for undefined in [0b000000u8, 0b000111, 0b011000, 0b100000, 0b111111] {
            let code = ServiceCode::new((0x123 << 6) | u16::from(undefined));
            assert_eq!(code.attribute(), None, "attribute {undefined:06b}");
            assert_eq!(code.kind(), None);
            assert_eq!(code.attributes_description(), None);
        }
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
            StatusFlag1::ErrorAtListPosition(0x12)
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

    /// §4.5.1 defines two product-dependent encodings for the error position and
    /// gives the same worked example for both: an error on the 10th list entry is
    /// `0Ah` ordinally and `02h` as a bitmap. Neither can be ruled out from the
    /// response alone, so both readings must be reported.
    #[test]
    fn status_flag1_reports_both_encodings_of_the_error_position() {
        let ordinal_tenth = StatusFlag1::from_byte(0x0A);
        assert_eq!(ordinal_tenth.error_byte(), Some(0x0A));
        assert_eq!(ordinal_tenth.ordinal_position(), Some(10));
        // 0Ah = bits 1 and 3 -> 2nd/10th and 4th/12th.
        assert_eq!(ordinal_tenth.bitmap_positions(), vec![2, 4, 10, 12]);

        let bitmap_tenth = StatusFlag1::from_byte(0x02);
        assert_eq!(bitmap_tenth.ordinal_position(), Some(2));
        assert!(bitmap_tenth.bitmap_positions().contains(&10));

        // Bit 7 denotes the 8th entry only; it has no second candidate.
        assert_eq!(StatusFlag1::from_byte(0x80).bitmap_positions(), vec![8]);

        // Positions only exist for the error case.
        assert_eq!(StatusFlag1::NormalCompletion.error_byte(), None);
        assert!(
            StatusFlag1::ErrorNotAssociatedWithList
                .bitmap_positions()
                .is_empty()
        );
    }

    #[test]
    fn status_flag_description_formats_both_flags() {
        let text = status_flag_description(0x02, 0xA8);
        assert!(
            text.contains("SF1: error at list position 2 (ordinal encoding)"),
            "unexpected description: {text}"
        );
        assert!(text.contains("2/10 (bit encoding)"), "unexpected: {text}");
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
                OptionVersion::new(2, 2, 2),
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
        assert_eq!(
            spec.random_id_option_version(),
            Some(OptionVersion::new(2, 2, 2))
        );
        let serialized = spec.to_bytes();
        assert_eq!(serialized.len(), 16);
        assert_eq!(serialized[0], 1);
        assert_eq!(serialized[1..3], [0x23, 0x81]);
        assert_eq!(serialized[3], 6);
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
