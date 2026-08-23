use super::BLOCK_SIZE;
use super::redact::Redacted;
use super::secure::encrypt_des_block;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// A 16-bit Service Code: ten service-number bits followed by six attribute bits.
///
/// Service codes are serialized little-endian in command packets. The raw tuple
/// field is public for compatibility; [`new`](Self::new) and [`raw`](Self::raw)
/// make intent clearer at API boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceCode(
    /// The unencoded 16-bit Service Code value in host byte order.
    pub u16,
);

impl ServiceCode {
    /// Wraps a raw 16-bit Service Code.
    pub fn new(raw: u16) -> Self {
        ServiceCode(raw)
    }

    /// Returns the complete 16-bit Service Code.
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

    /// Returns a concise description of the service kind, permissions, and
    /// authentication requirement.
    ///
    /// Returns `None` when the attribute bits are not assigned by the service
    /// attribute table.
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

    /// Whether a node named in a service code list is an authentication-free
    /// Service, which holds a key of its own but folds none into the
    /// authentication key chain.
    ///
    /// This is deliberately narrower than `!requires_key()`. A service code list
    /// may name areas and the system node as well as services, and the low bit
    /// alone misclassifies both: `FFFFh` and an area whose attribute is
    /// `000001b` each carry a key the chain does apply, yet read as odd. Neither
    /// decodes to a table 3-2 service attribute, so requiring [`attribute`] to
    /// decode first is what separates them from a genuine key-free service.
    ///
    /// [`attribute`]: Self::attribute
    pub fn is_key_free_service(&self) -> bool {
        self.attribute().is_some() && !self.requires_key()
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
    /// Decodes the raw Status Flag 1 byte without discarding an error position.
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

    /// Returns a diagnostic description of the completion state and, where
    /// applicable, both permitted interpretations of the error-position byte.
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

/// Status flag 2 (§4.5.2): the reason a command failed, or a product-dependent
/// warning accompanying normal completion.
///
/// Status flag 1 determines command success. In particular, `71h` can be paired
/// with normal completion after a write has already occurred, so callers must
/// not decide success from this flag alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusFlag2 {
    /// `00h` — no additional error detail.
    NormalCompletion,
    /// `01h` — decrement would underflow, or cashback would overflow.
    PurseDecrementUnderflowOrCashbackOverflow,
    /// `02h` — cashback exceeds the currently stored purse value.
    CashbackExceedsStoredValue,
    /// `03h` — a limited-purse write lies outside its configured range.
    LimitPurseOutOfRange,
    /// `70h` — card memory error.
    MemoryError,
    /// `71h` — the product-defined memory rewrite count was exceeded.
    MemoryWriteCountExceeded,
    /// `A1h` — the command's Service or Node count is outside its allowed range.
    ServiceOrNodeCountOutOfRange,
    /// `A2h` — the requested Block count is outside the product-defined range.
    BlockCountOutOfRange,
    /// `A3h` — a Block List Element refers past the Service Code List.
    ServiceListIndexOutOfRange,
    /// `A4h` — an Area Code or Service Code has an invalid attribute.
    AreaOrServiceAttributeMismatch,
    /// `A5h` — access is not permitted or a command success condition is unmet.
    AccessDeniedOrParameterMismatch,
    /// `A6h` — a Block List or Node Code List refers to a missing node.
    ReferencedNodeDoesNotExist,
    /// `A7h` — a Block List Element uses an invalid access mode.
    InvalidAccessMode,
    /// `A8h` — a block number exceeds the blocks allocated to its Service.
    BlockNumberOutOfRange,
    /// `A9h` — writing during an issuing command failed.
    IssuingWriteFailure,
    /// `AAh` — a DES key-change operation failed.
    KeyChangeFailed,
    /// `ABh` — an issuing package has invalid parity or MAC data.
    PackageParityOrMacInvalid,
    /// `ACh` — an issuing command contains an invalid parameter.
    InvalidParameters,
    /// `ADh` — the Service being registered already exists.
    ServiceAlreadyExists,
    /// `AEh` — an issuing command contains an invalid System Code.
    InvalidSystemCode,
    /// `AFh` — one operation writes more cyclic blocks than the Service owns.
    CyclicServiceWriteOverflow,
    /// `C0h` — an issuing package has an invalid package identifier.
    PackageIdentifierInvalid,
    /// `C1h` — parameters inside and outside an issuing package disagree.
    PackageParameterMismatch,
    /// `C2h` — issuing commands are disabled on the card.
    IssuingCommandDisabled,
    /// `C3h` — a command specifies a node with the wrong node attribute.
    NodeAttributeMismatch,
    /// A value not assigned by the documented Status Flag 2 table.
    Unknown(u8),
}

impl StatusFlag2 {
    /// Decodes a raw Status Flag 2 byte, retaining unassigned values as
    /// [`Unknown`](Self::Unknown).
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

    /// Returns a concise diagnostic description of this status reason.
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

/// Decodes and formats a pair of raw FeliCa status flags.
///
/// The result is intended for logs and error messages. For programmatic
/// inspection use [`StatusFlag1::from_byte`] and [`StatusFlag2::from_byte`].
pub fn status_flag_description(sf1: u8, sf2: u8) -> String {
    let sf1_desc = StatusFlag1::from_byte(sf1).description();
    let sf2_desc = StatusFlag2::from_byte(sf2).description();
    format!("SF1: {sf1_desc}; SF2: {sf2_desc}")
}

/// Identifies one Service and Block in a read or write command (§4.2.1).
///
/// Values below `0x0100` serialize in the compact two-byte form; larger block
/// numbers use the three-byte form. Both encodings reserve four bits for the
/// zero-based Service Code List position and three bits for the access mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockListElement {
    /// Block number, or the new key version when `access_mode == 0b100`.
    pub block_number_or_key_version: u16,
    /// Zero-based position in the command's Service Code List, in `0..=15`.
    pub service_code_list_index: u8,
    /// Three-bit access mode: `000b` normal, `001b` purse cashback, or `100b`
    /// DES key change.
    pub access_mode: u8,
}

impl BlockListElement {
    /// Creates a Block List Element.
    ///
    /// Construction performs no validation. Serialization masks
    /// `service_code_list_index` to four bits and `access_mode` to three bits;
    /// callers should use only the access modes defined above.
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

/// One entry returned by Search Service Code (§4.4.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchServiceCodeResult {
    /// A Service Code at the requested index.
    Service(ServiceCode),
    /// An Area Code together with the last Service Code covered by that Area.
    Area {
        /// The Area Code, including its Area Attribute bits.
        area_code: u16,
        /// The inclusive upper bound of the Area's Service Code range.
        end_service_code: u16,
    },
}

/// An Area Code and the inclusive end of the code range managed by the Area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AreaCodeRange {
    /// The Area Code, including Area Attribute bits.
    pub area_code: u16,
    /// The inclusive last Service Code belonging to the Area.
    pub end_service_code: u16,
}

impl AreaCodeRange {
    /// Creates an Area range from its first and last encoded node values.
    pub fn new(area_code: u16, end_service_code: u16) -> Self {
        Self {
            area_code,
            end_service_code,
        }
    }
}

/// The 16-byte container issue information returned by mobile FeliCa products.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainerInformation {
    /// Five bytes containing format-version and carrier information.
    pub format_version_carrier_information: [u8; 5],
    /// Eleven bytes containing product-specific mobile-phone model information.
    pub mobile_phone_model_information: [u8; 11],
}

impl ContainerInformation {
    /// Creates container information from its two on-wire fields.
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

/// Property index for the product-dependent Get Container Property command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerProperty {
    /// Property index `0000h`.
    Property1,
    /// Property index `0001h`.
    Property2,
    /// An index not given a symbolic name by this crate.
    Unknown(u16),
}

impl ContainerProperty {
    /// Returns the 16-bit property index placed in the command.
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

/// Property group requested by Get Node Property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodePropertyType {
    /// Limited-purse enable flag, upper/lower limits, and generation count.
    ValueLimitedPurseService,
    /// Communication-with-MAC enable flag.
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

/// A decoded property value returned for one Node.
///
/// Entries retain the order of the Node Code List supplied to Get Node
/// Property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeProperty {
    /// Limited-purse configuration for a purse Service.
    ValueLimitedPurseService {
        /// Whether the limited-purse feature is enabled.
        enabled: bool,
        /// Signed upper bound accepted for the stored purse value.
        upper_limit: i32,
        /// Signed lower bound accepted for the stored purse value.
        lower_limit: i32,
        /// Product-defined limited-purse generation number.
        generation_number: u8,
    },
    /// Communication-with-MAC configuration for a Service.
    MacCommunication {
        /// Whether communication with MAC is enabled.
        enabled: bool,
    },
}

impl NodeProperty {
    /// Returns the property group represented by this value.
    pub fn property_type(&self) -> NodePropertyType {
        match self {
            NodeProperty::ValueLimitedPurseService { .. } => {
                NodePropertyType::ValueLimitedPurseService
            }
            NodeProperty::MacCommunication { .. } => NodePropertyType::MacCommunication,
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

/// SRM encryption-format selector used by Set Parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetParameterEncryptionType {
    /// SRM type 1 (`00h`).
    SrmType1,
    /// SRM type 2 (`01h`).
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

/// Node-code width selected by Set Parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetParameterPacketType {
    /// Two-byte Node Codes (`00h`).
    NodeCodeSize2,
    /// Four-byte Node Codes (`01h`).
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

/// One page of child Areas and Services returned by Request Code List.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestCodeListResult {
    /// Whether another request with a later index is needed to continue the list.
    pub continue_flag: bool,
    /// Area entries contained in this response page.
    pub areas: Vec<AreaCodeRange>,
    /// Service entries contained in this response page.
    pub services: Vec<ServiceCode>,
}

/// Assigned and free Block counts returned by Request Block Information Ex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestBlockInformationExResult {
    /// Assigned Block count for each requested Node, in request order.
    pub assigned_block_counts: Vec<u16>,
    /// Free Block count for each requested Node, in request order.
    pub free_block_counts: Vec<u16>,
}

/// Product-dependent two-byte information returned for an Area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetAreaInformationResult {
    /// Echoed Node Code identifying the requested Area.
    pub node_code: u16,
    /// Raw two-byte Area information field.
    pub data: [u8; 2],
}

/// Property values returned by Get Node Property.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetNodePropertyResult {
    /// One decoded property for each requested Node, in request order.
    pub node_properties: Vec<NodeProperty>,
}

/// System configuration state returned by Get System Status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetSystemStatusResult {
    /// Product-defined system-status flag.
    pub flag: u8,
    /// Product-defined status data following the flag.
    pub data: Vec<u8>,
}

/// A packed FeliCa specification version with three BCD digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionVersion {
    /// Major-version BCD digit (`0..=9` on the wire).
    pub major: u8,
    /// Minor-version BCD digit (`0..=9` on the wire).
    pub minor: u8,
    /// Patch-version BCD digit (`0..=9` on the wire).
    pub patch: u8,
}

impl OptionVersion {
    /// Creates a version, retaining only the low four bits of each component.
    ///
    /// Components `0Ah..=0Fh` are not valid BCD and are rejected when a
    /// response is serialized.
    pub fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major: major & 0x0F,
            minor: minor & 0x0F,
            patch: patch & 0x0F,
        }
    }

    pub(crate) fn from_le_bytes(bytes: [u8; 2]) -> Option<Self> {
        let version = Self {
            major: bytes[1] & 0x0F,
            minor: (bytes[0] >> 4) & 0x0F,
            patch: bytes[0] & 0x0F,
        };
        if bytes[1] & 0xF0 == 0x80 && version.is_valid_bcd() {
            Some(version)
        } else {
            None
        }
    }

    pub(crate) fn is_valid_bcd(self) -> bool {
        self.major <= 9 && self.minor <= 9 && self.patch <= 9
    }

    pub(crate) fn to_le_bytes(self) -> [u8; 2] {
        [
            ((self.minor & 0x0F) << 4) | (self.patch & 0x0F),
            0x80 | (self.major & 0x0F),
        ]
    }
}

/// Card OS basic and optional-feature versions returned by Request
/// Specification Version (§4.4.16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecificationVersion {
    /// Layout version for the fields that follow; version 2.31 defines `00h`.
    pub format_version: u8,
    /// Version of the basic FeliCa command set.
    pub basic_version: OptionVersion,
    /// Optional-feature versions in the specification-defined order.
    pub option_versions: Vec<OptionVersion>,
}

impl SpecificationVersion {
    /// Returns option-list entry 0, the DES option version.
    pub fn des_option_version(&self) -> Option<OptionVersion> {
        self.option_versions.first().copied()
    }

    /// Returns option-list entry 1, the special-option version.
    pub fn special_option_version(&self) -> Option<OptionVersion> {
        self.option_versions.get(1).copied()
    }

    /// Returns option-list entry 2, the extended-overlap option version.
    pub fn extended_overlap_option_version(&self) -> Option<OptionVersion> {
        self.option_versions.get(2).copied()
    }

    /// Returns option-list entry 3, the limited-purse option version.
    pub fn value_limited_purse_service_option_version(&self) -> Option<OptionVersion> {
        self.option_versions.get(3).copied()
    }

    /// Returns option-list entry 4, the communication-with-MAC option version.
    pub fn communication_with_mac_option_version(&self) -> Option<OptionVersion> {
        self.option_versions.get(4).copied()
    }

    /// Returns option-list entry 5, the random-ID option version.
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

/// Block data returned by Read Without Encryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadWithoutEncryptionResult {
    /// Sixteen-byte blocks in the same order as the request's Block List.
    pub blocks: Vec<[u8; BLOCK_SIZE]>,
}

/// Block data returned by an authenticated Read or Read v2 command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadResult {
    /// Sixteen-byte blocks in the same order as the request's Block List.
    pub blocks: Vec<[u8; BLOCK_SIZE]>,
}

/// Cryptographic capability and key versions returned by Request Service v2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestServiceV2Result {
    /// Raw Cryptographic System Identifier reported by the card.
    pub crypto_id: u8,
    /// Key-version entry for each requested Node, in request order.
    pub key_versions: Vec<RequestServiceV2KeyVersion>,
}

/// Issuance result returned after registering Issue ID data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterIssueIdResult {
    /// Number of unallocated Blocks remaining in the System after registration.
    pub remaining_blocks: u16,
}

/// Issuance result returned after registering a Service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterServiceResult {
    /// Number of unallocated Blocks remaining in the containing Area.
    pub remaining_blocks: u16,
}

/// Public issue data returned when mutual authentication completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutualAuthenticationResult {
    /// Eight-byte Issue ID (`IDi`).
    pub issue_id: [u8; 8],
    /// Eight-byte Issue Parameter (`PMi`).
    pub issue_parameter: [u8; 8],
}

/// Not `Copy`: see [`SecureSessionCredentials`] — an implicit copy would escape
/// [`Drop`] and never be cleared.
///
/// [`SecureSessionCredentials`]: super::SecureSessionCredentials
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ChangeKeyParameters {
    /// Node code of the key being changed. `0xFFFF` denotes the system key.
    pub node: u16,
    /// Key of the node's parent in the DES key hierarchy.
    ///
    /// For a service key this is the key of the Area containing the Service;
    /// for an Area key it is the key of the parent Area. The System has no
    /// parent Area, so changing the system key uses the old system key itself
    /// as the parent key (`parent_key == old_key`).
    pub parent_key: [u8; 8],
    /// New key to install for `node`.
    pub new_key: [u8; 8],
    /// Existing key currently assigned to `node`.
    pub old_key: [u8; 8],
    /// Key version to assign to the new key.
    pub new_key_version: u16,
}

/// Key-version representation selected by the card's Cryptographic System
/// Identifier in a Request Service v2 response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestServiceV2KeyVersion {
    /// One key version (AES-only or DES-only card).
    Single(u16),
    /// Separate versions for an AES/DES card.
    Dual {
        /// AES key version.
        aes: u16,
        /// DES key version.
        des: u16,
    },
}

impl RequestServiceV2KeyVersion {
    const NO_KEY_VERSION: u16 = 0xFFFF;

    /// Creates a single-version entry.
    pub fn single(value: u16) -> Self {
        RequestServiceV2KeyVersion::Single(value)
    }

    /// Creates an AES/DES dual-version entry.
    pub fn dual(aes: u16, des: u16) -> Self {
        RequestServiceV2KeyVersion::Dual { aes, des }
    }

    /// Returns the single version, or the AES version of a dual entry.
    ///
    /// The protocol sentinel `FFFFh`, meaning that no usable key version is
    /// present, is normalized to `None`.
    pub fn primary(&self) -> Option<u16> {
        match self {
            RequestServiceV2KeyVersion::Single(value) => Self::normalize_key_version(*value),
            RequestServiceV2KeyVersion::Dual { aes, .. } => Self::normalize_key_version(*aes),
        }
    }

    /// Returns the DES version of a dual entry.
    ///
    /// Returns `None` for a single entry and for the `FFFFh` no-key sentinel.
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

// The three keys are secret; the version identifies which key is being installed
// and is sent to the card in the clear.
impl fmt::Debug for ChangeKeyParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangeKeyParameters")
            .field("node", &format_args!("{:#06X}", self.node))
            .field("parent_key", &Redacted(self.parent_key.len()))
            .field("new_key", &Redacted(self.new_key.len()))
            .field("old_key", &Redacted(self.old_key.len()))
            .field("new_key_version", &self.new_key_version)
            .finish()
    }
}

impl ChangeKeyParameters {
    /// Creates the parameters for one DES key change.
    ///
    /// The caller supplies the parent key according to the node hierarchy. In
    /// particular, when `node` is the system (`0xFFFF`), `parent_key` must be
    /// the same key as `old_key` because the System has no parent Area.
    pub fn new(
        node: u16,
        parent_key: [u8; 8],
        new_key: [u8; 8],
        old_key: [u8; 8],
        new_key_version: u16,
    ) -> Self {
        Self {
            node,
            parent_key,
            new_key,
            old_key,
            new_key_version,
        }
    }

    /// Returns the Node Code whose key will be changed.
    pub fn node(&self) -> u16 {
        self.node
    }

    /// Returns the version assigned to the new key.
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

    /// Only a code that decodes to a table 3-2 service attribute *and* reads as
    /// authentication free folds no key into the authentication chain. The low
    /// bit alone would misclassify the other nodes a service code list may name:
    /// the system node and an area whose attribute is `000001b` both read as
    /// odd, and both contribute their key.
    #[test]
    fn key_free_classification_covers_every_node_a_service_list_may_name() {
        // Table 3-2 pairs each attribute with the key-free value one greater.
        for bits in [
            0b001000u16,
            0b001010,
            0b001100,
            0b001110,
            0b010000,
            0b010010,
            0b010100,
            0b010110,
        ] {
            let with_key = ServiceCode::new((0x123 << 6) | bits);
            let without_key = ServiceCode::new((0x123 << 6) | bits | 1);
            assert!(!with_key.is_key_free_service(), "{bits:06b} with key");
            assert!(without_key.is_key_free_service(), "{bits:06b} without key");
        }

        // The nodes a service code list may name that are not services at all:
        // the system node, and an area under either attribute it may carry
        // (`000000b`, so bare, and `000001b`). None decodes to a service
        // attribute, and every one contributes its key.
        for raw in [0xFFFFu16, 0x123 << 6, (0x123 << 6) | 0b000001] {
            let code = ServiceCode::new(raw);
            assert!(code.attribute().is_none(), "{raw:04X} is not a service");
            assert!(!code.is_key_free_service(), "{raw:04X} contributes");
        }

        // Two of those three read as odd, which is the trap `requires_key` alone
        // falls into and `is_key_free_service` exists to avoid.
        assert!(!ServiceCode::new(0xFFFF).requires_key());
        assert!(!ServiceCode::new((0x123 << 6) | 0b000001).requires_key());
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
        let purse_bytes = purse.to_bytes();
        assert_eq!(purse_bytes.len(), 10);
        assert_eq!(purse_bytes[0], 0x01);
        assert_eq!(&purse_bytes[1..5], &1_000i32.to_le_bytes());
        assert_eq!(&purse_bytes[5..9], &(-500i32).to_le_bytes());
        assert_eq!(purse_bytes[9], 7);

        let mac = NodeProperty::MacCommunication { enabled: false };
        assert_eq!(mac.property_type(), NodePropertyType::MacCommunication);
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
            Some(OptionVersion::new(0x02, 0x04, 0x06))
        );
        assert_eq!(OptionVersion::from_le_bytes([0x1A, 0x82]), None);
        assert_eq!(OptionVersion::from_le_bytes([0x12, 0x02]), None);

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
        let params = ChangeKeyParameters::new(0x1008, [1; 8], [2; 8], [3; 8], 0x1234);
        assert_eq!(params.node(), 0x1008);
        assert_eq!(params.new_key_version(), 0x1234);
        assert_eq!(params.block_descriptor_block_number(), 0x1234);

        let payload_a = params.payload();
        assert_eq!(payload_a.len(), 16);

        let payload_b = ChangeKeyParameters::new(0x1008, [1; 8], [2; 8], [3; 8], 0x1235).payload();
        assert_ne!(payload_a, payload_b);
    }

    /// The three keys in a key-change request must not print.
    #[test]
    fn change_key_parameters_debug_redacts_the_keys() {
        let params = ChangeKeyParameters::new(0x1008, [0xDE; 8], [0xAD; 8], [0xBE; 8], 0x1234);
        let text = format!("{params:?}");
        assert_eq!(text.matches("<8 bytes redacted>").count(), 3);
        assert!(!text.contains("222"), "leaked a key byte: {text}");
        assert!(!text.contains("173"), "leaked a key byte: {text}");
        // The key version is sent to the card in the clear.
        assert!(text.contains("new_key_version: 4660"), "unexpected: {text}");
    }
}
