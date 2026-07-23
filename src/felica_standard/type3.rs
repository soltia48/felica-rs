#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Type3TagPollingResult {
    pub idm: Vec<u8>,
    pub pmm: Vec<u8>,
    pub optional: Vec<u8>,
}

impl Type3TagPollingResult {
    const MIN_TIMEOUT_SECONDS: f32 = 0.0020000003;

    /// Compute the Request Service command timeout using the Request Service PMm byte.
    pub fn request_service_timeout_ms(&self, service_count: usize) -> u16 {
        self.scaled_timeout_with_units(
            PmmSlot::REQUEST_SERVICE,
            service_count,
            UnitClamp::between(1, 32),
        )
    }

    /// Compute the Request Response command timeout using the Request Response PMm byte.
    pub fn request_response_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::REQUEST_RESPONSE)
    }

    /// Compute the Read Without Encryption command timeout using the Read Without Encryption PMm byte.
    pub fn read_without_encryption_timeout_ms(&self, block_count: usize) -> u16 {
        self.scaled_timeout_with_units(
            PmmSlot::READ_WITHOUT_ENCRYPTION,
            block_count,
            UnitClamp::at_least(1),
        )
    }

    /// Compute the Write Without Encryption command timeout using the Write Without Encryption PMm byte.
    pub fn write_without_encryption_timeout_ms(&self, block_count: usize) -> u16 {
        self.scaled_timeout_with_units(
            PmmSlot::WRITE_WITHOUT_ENCRYPTION,
            block_count,
            UnitClamp::at_least(1),
        )
    }

    /// Compute the Search Service Code command timeout using the Search Service Code PMm byte.
    pub fn search_service_code_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::SEARCH_SERVICE_CODE)
    }

    /// Compute the Request System Code command timeout using the Request System Code PMm byte.
    pub fn request_system_code_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::REQUEST_SYSTEM_CODE)
    }

    /// Compute the Request Block Information command timeout using the Request Block Information PMm byte.
    pub fn request_block_information_timeout_ms(&self, node_count: usize) -> u16 {
        self.scaled_timeout_with_units(
            PmmSlot::REQUEST_BLOCK_INFORMATION,
            node_count,
            UnitClamp::unbounded(),
        )
    }

    /// Compute the Request Block Information Ex command timeout using the Request Block Information PMm byte.
    pub fn request_block_information_ex_timeout_ms(&self, node_count: usize) -> u16 {
        self.request_block_information_timeout_ms(node_count)
    }

    /// Compute the Request Code List command timeout using the Request Service PMm byte.
    pub fn request_code_list_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::REQUEST_CODE_LIST)
    }

    /// Compute the Set Parameter command timeout using the Other PMm byte.
    pub fn set_parameter_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::OTHER)
    }

    /// Compute the Get Container Issue Information command timeout using the Other PMm byte.
    pub fn get_container_issue_information_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::OTHER)
    }

    /// Compute the Get Container Property command timeout using the Other PMm byte.
    pub fn get_container_property_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::OTHER)
    }

    /// Compute the Get Container ID command timeout using the Other PMm byte.
    pub fn get_container_id_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::OTHER)
    }

    /// Compute the Get System Status command timeout using the fixed response PMm byte.
    pub fn get_system_status_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::GET_SYSTEM_STATUS)
    }

    /// Compute the Request Product Information command timeout using the Other PMm byte.
    pub fn request_product_information_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::OTHER)
    }

    /// Compute the Request Specification Version command timeout using the fixed response PMm byte.
    pub fn request_specification_version_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::REQUEST_SPECIFICATION_VERSION)
    }

    /// Compute the Reset Mode command timeout using the fixed response PMm byte.
    pub fn reset_mode_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::RESET_MODE)
    }

    /// Compute the Get Area Information command timeout using the fixed response PMm byte.
    pub fn get_area_information_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::GET_AREA_INFORMATION)
    }

    /// Compute the Get Node Property command timeout using the variable response PMm byte.
    pub fn get_node_property_timeout_ms(&self, node_count: usize) -> u16 {
        self.scaled_timeout_with_units(
            PmmSlot::GET_NODE_PROPERTY,
            node_count,
            UnitClamp::between(1, 16),
        )
    }

    /// Compute the Authentication1 command timeout using the Authentication1 PMm byte.
    pub fn authentication1_timeout_ms(&self, node_count: usize) -> u16 {
        self.scaled_timeout_with_units(PmmSlot::AUTHENTICATION1, node_count, UnitClamp::at_least(1))
    }

    /// Compute the Authentication2 command timeout using the Authentication2 PMm byte.
    pub fn authentication2_timeout_ms(&self) -> u16 {
        self.base_timeout(PmmSlot::AUTHENTICATION2)
    }

    /// Compute the Read command timeout using the Read PMm byte.
    pub fn read_timeout_ms(&self, block_count: usize) -> u16 {
        self.scaled_timeout_with_units(PmmSlot::READ, block_count, UnitClamp::at_least(1))
    }

    /// Compute the Write command timeout using the Write PMm byte.
    pub fn write_timeout_ms(&self, block_count: usize) -> u16 {
        self.scaled_timeout_with_units(PmmSlot::WRITE, block_count, UnitClamp::at_least(1))
    }

    /// Compute the Issuing/Registration command timeout using the Registration PMm byte.
    /// Sony specifies a minimum of 2 ms for these operations (a floor that we apply to all commands).
    pub fn registration_timeout_ms(&self) -> u16 {
        let timeout_seconds = self.timeout_seconds(PmmSlot::REGISTRATION, |p| p.a + 1.0);
        Self::seconds_to_timeout_ms(timeout_seconds)
    }

    fn base_timeout(&self, slot: PmmSlot) -> u16 {
        self.compute_timeout(slot, |p| p.a + 1.0)
    }

    fn scaled_timeout(&self, slot: PmmSlot, units: f32) -> u16 {
        self.compute_timeout(slot, |p| ((p.b + 1.0) * units) + p.a + 1.0)
    }

    fn scaled_timeout_with_units(&self, slot: PmmSlot, units: usize, clamp: UnitClamp) -> u16 {
        self.scaled_timeout(slot, clamp.clamp(units))
    }

    fn compute_timeout<F>(&self, slot: PmmSlot, term_fn: F) -> u16
    where
        F: Fn(&TimingParameters) -> f32,
    {
        let timeout_seconds = self.timeout_seconds(slot, term_fn);
        Self::seconds_to_timeout_ms(timeout_seconds)
    }

    fn timeout_seconds<F>(&self, slot: PmmSlot, term_fn: F) -> f32
    where
        F: Fn(&TimingParameters) -> f32,
    {
        let params = self.timing_parameters(slot);
        302e-6_f32 * term_fn(&params) * 4f32.powi(params.e)
    }

    fn seconds_to_timeout_ms(seconds: f32) -> u16 {
        (seconds.max(Self::MIN_TIMEOUT_SECONDS) * 1000.0)
            .ceil()
            .clamp(0.0, u16::MAX as f32) as u16
    }

    fn timing_parameters(&self, slot: PmmSlot) -> TimingParameters {
        let byte = self.pmm.get(slot.index()).copied().unwrap_or(0);
        byte.into()
    }
}

#[derive(Clone, Copy)]
struct TimingParameters {
    a: f32,
    b: f32,
    e: i32,
}

impl From<u8> for TimingParameters {
    fn from(byte: u8) -> Self {
        Self {
            a: (byte & 0x07) as f32,
            b: ((byte >> 3) & 0x07) as f32,
            e: (byte >> 6) as i32,
        }
    }
}

#[derive(Clone, Copy)]
struct PmmSlot(usize);

impl PmmSlot {
    const fn new(index: usize) -> Self {
        Self(index)
    }

    const REQUEST_SERVICE: Self = Self::new(2);
    const REQUEST_CODE_LIST: Self = Self::new(2);
    const GET_NODE_PROPERTY: Self = Self::new(2);
    const REQUEST_RESPONSE: Self = Self::new(3);
    const SEARCH_SERVICE_CODE: Self = Self::new(3);
    const REQUEST_SYSTEM_CODE: Self = Self::new(3);
    const GET_SYSTEM_STATUS: Self = Self::new(3);
    const REQUEST_SPECIFICATION_VERSION: Self = Self::new(3);
    const RESET_MODE: Self = Self::new(3);
    const GET_AREA_INFORMATION: Self = Self::new(3);
    const REQUEST_BLOCK_INFORMATION: Self = Self::new(2);
    const AUTHENTICATION1: Self = Self::new(4);
    const AUTHENTICATION2: Self = Self::new(4);
    const READ_WITHOUT_ENCRYPTION: Self = Self::new(5);
    const WRITE_WITHOUT_ENCRYPTION: Self = Self::new(6);
    const READ: Self = Self::new(5);
    const WRITE: Self = Self::new(6);
    const OTHER: Self = Self::new(7);
    const REGISTRATION: Self = Self::new(7);

    fn index(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy)]
struct UnitClamp {
    min: usize,
    max: Option<usize>,
}

impl UnitClamp {
    const fn new(min: usize, max: Option<usize>) -> Self {
        Self { min, max }
    }

    const fn between(min: usize, max: usize) -> Self {
        Self::new(min, Some(max))
    }

    const fn at_least(min: usize) -> Self {
        Self::new(min, None)
    }

    const fn unbounded() -> Self {
        Self::new(0, None)
    }

    fn clamp(self, units: usize) -> f32 {
        let clamped = units.max(self.min);
        let clamped = match self.max {
            Some(max) => clamped.min(max),
            None => clamped,
        };
        clamped as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn polling_result_with_pmm(pmm: Vec<u8>) -> Type3TagPollingResult {
        Type3TagPollingResult {
            idm: vec![0; 8],
            pmm,
            optional: Vec::new(),
        }
    }

    #[test]
    fn timeout_uses_minimum_floor_when_parameters_are_small_or_missing() {
        let empty = polling_result_with_pmm(Vec::new());
        assert_eq!(empty.request_response_timeout_ms(), 3);
        assert_eq!(empty.read_without_encryption_timeout_ms(1), 3);

        let zeros = polling_result_with_pmm(vec![0; 8]);
        assert_eq!(zeros.request_response_timeout_ms(), 3);
        assert_eq!(zeros.request_service_timeout_ms(1), 3);
    }

    #[test]
    fn service_and_node_count_clamps_are_applied() {
        // slot 2 byte: a=1, b=2, e=1
        let mut pmm = vec![0; 8];
        pmm[2] = 0x51;
        let result = polling_result_with_pmm(pmm);

        assert_eq!(
            result.request_service_timeout_ms(0),
            result.request_service_timeout_ms(1)
        );
        assert_eq!(
            result.request_service_timeout_ms(32),
            result.request_service_timeout_ms(100)
        );
        assert_eq!(
            result.get_node_property_timeout_ms(16),
            result.get_node_property_timeout_ms(100)
        );
        assert_eq!(
            result.authentication1_timeout_ms(0),
            result.authentication1_timeout_ms(1)
        );
    }

    #[test]
    fn methods_sharing_same_pmm_slot_return_equal_base_timeouts() {
        let mut pmm = vec![0; 8];
        // slot 3 byte: a=3, b=0, e=2
        pmm[3] = 0x83;
        // slot 7 byte: a=2, b=1, e=1
        pmm[7] = 0x4A;
        let result = polling_result_with_pmm(pmm);

        let slot3 = result.request_response_timeout_ms();
        assert_eq!(slot3, result.search_service_code_timeout_ms());
        assert_eq!(slot3, result.request_system_code_timeout_ms());
        assert_eq!(slot3, result.get_system_status_timeout_ms());
        assert_eq!(slot3, result.request_specification_version_timeout_ms());
        assert_eq!(slot3, result.reset_mode_timeout_ms());
        assert_eq!(slot3, result.get_area_information_timeout_ms());

        let slot7 = result.set_parameter_timeout_ms();
        assert_eq!(slot7, result.get_container_issue_information_timeout_ms());
        assert_eq!(slot7, result.get_container_property_timeout_ms());
        assert_eq!(slot7, result.get_container_id_timeout_ms());
        assert_eq!(slot7, result.request_product_information_timeout_ms());
    }

    #[test]
    fn request_block_information_ex_delegates_to_base_method() {
        let mut pmm = vec![0; 8];
        pmm[2] = 0x51;
        let result = polling_result_with_pmm(pmm);
        assert_eq!(
            result.request_block_information_timeout_ms(5),
            result.request_block_information_ex_timeout_ms(5)
        );
    }

    #[test]
    fn timing_parameter_and_unit_clamp_helpers_behave_as_expected() {
        let params = TimingParameters::from(0b11_101_010);
        assert_eq!(params.a, 0b010 as f32);
        assert_eq!(params.b, 0b101 as f32);
        assert_eq!(params.e, 0b11);

        assert_eq!(UnitClamp::between(1, 4).clamp(0), 1.0);
        assert_eq!(UnitClamp::between(1, 4).clamp(10), 4.0);
        assert_eq!(UnitClamp::at_least(3).clamp(1), 3.0);
        assert_eq!(UnitClamp::unbounded().clamp(0), 0.0);
    }
}
