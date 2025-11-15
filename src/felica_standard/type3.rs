#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Type3TagPollingResult {
    pub idm: Vec<u8>,
    pub pmm: Vec<u8>,
    pub optional: Vec<u8>,
}

impl Type3TagPollingResult {
    /// Compute the Request Service command timeout defined by PMm[2].
    pub fn request_service_timeout_ms(&self, service_count: usize) -> u16 {
        let services = service_count.max(1).min(32) as f32;
        self.scaled_timeout(2, services)
    }

    /// Compute the Request Response command timeout defined by PMm[3].
    pub fn request_response_timeout_ms(&self) -> u16 {
        self.base_timeout(3)
    }

    /// Compute the Read Without Encryption command timeout defined by PMm[5].
    pub fn read_without_encryption_timeout_ms(&self, block_count: usize) -> u16 {
        let blocks = block_count.max(1) as f32;
        self.scaled_timeout(5, blocks)
    }

    /// Compute the Write Without Encryption command timeout defined by PMm[6].
    pub fn write_without_encryption_timeout_ms(&self, block_count: usize) -> u16 {
        let blocks = block_count.max(1) as f32;
        self.scaled_timeout(6, blocks)
    }

    /// Compute the Search Service Code command timeout defined by PMm[3].
    pub fn search_service_code_timeout_ms(&self) -> u16 {
        self.base_timeout(3)
    }

    /// Compute the Request Block Information command timeout defined by PMm[3].
    pub fn request_block_information_timeout_ms(&self, node_count: usize) -> u16 {
        let nodes = node_count as f32;
        self.scaled_timeout(2, nodes)
    }

    /// Compute the Authentication1 command timeout defined by PMm[3].
    pub fn authentication1_timeout_ms(&self, node_count: usize) -> u16 {
        let nodes = node_count.max(1) as f32;
        self.scaled_timeout(4, nodes)
    }

    /// Compute the Authentication2 command timeout defined by PMm[4].
    pub fn authentication2_timeout_ms(&self) -> u16 {
        self.base_timeout(4)
    }

    /// Compute the Issuing/Registration command timeout defined by PMm[7].
    /// Unlike other commands, Sony specifies a minimum of 2 ms for these operations.
    pub fn registration_timeout_ms(&self) -> u16 {
        let params = self.timing_parameters(7);
        let timeout_seconds = 302e-6_f32 * (params.a + 1.0) * 4f32.powi(params.e);
        let timeout_seconds = timeout_seconds.max(0.002);
        (timeout_seconds * 1000.0)
            .ceil()
            .clamp(0.0, u16::MAX as f32) as u16
    }

    fn base_timeout(&self, pmm_index: usize) -> u16 {
        self.compute_timeout(pmm_index, |p| p.a + 1.0)
    }

    fn scaled_timeout(&self, pmm_index: usize, units: f32) -> u16 {
        self.compute_timeout(pmm_index, |p| ((p.b + 1.0) * units) + p.a + 1.0)
    }

    fn compute_timeout<F>(&self, pmm_index: usize, term_fn: F) -> u16
    where
        F: Fn(&TimingParameters) -> f32,
    {
        let params = self.timing_parameters(pmm_index);
        let timeout_seconds = 302e-6_f32 * term_fn(&params) * 4f32.powi(params.e);
        (timeout_seconds * 1000.0)
            .ceil()
            .clamp(0.0, u16::MAX as f32) as u16
    }

    fn timing_parameters(&self, index: usize) -> TimingParameters {
        let byte = self.pmm.get(index).copied().unwrap_or(0);
        TimingParameters {
            a: (byte & 0x07) as f32,
            b: ((byte >> 3) & 0x07) as f32,
            e: (byte >> 6) as i32,
        }
    }
}

struct TimingParameters {
    a: f32,
    b: f32,
    e: i32,
}
