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

    pub(crate) fn to_le_bytes(&self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
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
        end_service_index: u16,
    },
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
    pub fn single(value: u16) -> Self {
        RequestServiceV2KeyVersion::Single(value)
    }

    pub fn dual(aes: u16, des: u16) -> Self {
        RequestServiceV2KeyVersion::Dual { aes, des }
    }

    pub fn primary(&self) -> u16 {
        match self {
            RequestServiceV2KeyVersion::Single(value) => *value,
            RequestServiceV2KeyVersion::Dual { aes, .. } => *aes,
        }
    }

    pub fn secondary(&self) -> Option<u16> {
        match self {
            RequestServiceV2KeyVersion::Single(_) => None,
            RequestServiceV2KeyVersion::Dual { des, .. } => Some(*des),
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
