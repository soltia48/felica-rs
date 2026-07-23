use crate::clf::errors::UnsupportedTargetError;

/// Validates a bitrate string (e.g., "106A", "212F").
fn validate_bitrate(part: &str) -> bool {
    if part.len() < 2 {
        return false;
    }
    let (digits, suffix) = part.split_at(part.len() - 1);
    digits.chars().all(|c| c.is_ascii_digit()) && suffix.chars().all(|c| c.is_ascii_uppercase())
}

/// Parses a bitrate specification which may contain send/receive rates separated by '/'.
fn parse_bitrate(value: &str) -> Result<(String, String), UnsupportedTargetError> {
    let mut parts = value.splitn(2, '/');
    let send = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| UnsupportedTargetError("missing bitrate".into()))?;
    if !validate_bitrate(send) {
        return Err(UnsupportedTargetError(format!("invalid bitrate: {}", send)));
    }
    let recv = match parts.next() {
        Some(recv) if !validate_bitrate(recv) => {
            return Err(UnsupportedTargetError(format!(
                "invalid receive bitrate: {}",
                recv
            )));
        }
        Some(recv) => recv.to_string(),
        None => send.to_string(),
    };
    Ok((send.to_string(), recv))
}

/// NFC target data fields for various protocols.
#[derive(Debug, Clone, Default)]
pub struct TargetData {
    pub sens_req: Option<Vec<u8>>,
    pub sens_res: Option<Vec<u8>>,
    pub sel_req: Option<Vec<u8>>,
    pub sel_res: Option<Vec<u8>>,
    pub sdd_res: Option<Vec<u8>>,
    pub rid_res: Option<Vec<u8>>,
    pub sensb_req: Option<Vec<u8>>,
    pub sensb_res: Option<Vec<u8>>,
    pub sensf_req: Option<Vec<u8>>,
    /// SENSF_RES payload (length byte excluded). Used by listen_dep and DEP activation helpers.
    pub sensf_res: Option<Vec<u8>>,
    pub rats_res: Option<Vec<u8>>,
    pub rats_cmd: Option<Vec<u8>>,
    pub psl_req: Option<Vec<u8>>,
    pub atr_req: Option<Vec<u8>>,
    pub atr_res: Option<Vec<u8>>,
    pub tt2_cmd: Option<Vec<u8>>,
    /// Type 3 (NFC-F) command frame including the length byte.
    pub tt3_cmd: Option<Vec<u8>>,
    pub tt4_cmd: Option<Vec<u8>>,
    pub dep_req: Option<Vec<u8>>,
    pub mf_halted: bool,
    pub arae: bool,
}

#[derive(Debug, Clone)]
pub struct RemoteTarget {
    bitrate_send: String,
    bitrate_recv: String,
    pub data: TargetData,
}

impl RemoteTarget {
    pub fn new(bitrate: impl Into<String>) -> Result<Self, UnsupportedTargetError> {
        let bitrate = bitrate.into();
        let (bitrate_send, bitrate_recv) = parse_bitrate(&bitrate)?;
        Ok(Self {
            bitrate_send,
            bitrate_recv,
            data: TargetData::default(),
        })
    }

    pub fn bitrate(&self) -> &str {
        &self.bitrate_send
    }

    pub fn bitrate_send(&self) -> &str {
        &self.bitrate_send
    }

    pub fn bitrate_recv(&self) -> &str {
        &self.bitrate_recv
    }

    pub fn fields(&self) -> &TargetData {
        &self.data
    }

    pub fn fields_mut(&mut self) -> &mut TargetData {
        &mut self.data
    }
}

#[derive(Debug, Clone)]
pub struct LocalTarget {
    bitrate_send: String,
    bitrate_recv: String,
    pub data: TargetData,
}

impl LocalTarget {
    pub fn new(bitrate: impl Into<String>) -> Result<Self, UnsupportedTargetError> {
        let bitrate = bitrate.into();
        if !validate_bitrate(&bitrate) {
            return Err(UnsupportedTargetError(format!(
                "invalid bitrate: {}",
                bitrate
            )));
        }
        Ok(Self {
            bitrate_send: bitrate.clone(),
            bitrate_recv: bitrate,
            data: TargetData::default(),
        })
    }

    pub fn bitrate(&self) -> String {
        if self.bitrate_send == self.bitrate_recv {
            self.bitrate_send.clone()
        } else {
            format!("{}/{}", self.bitrate_send, self.bitrate_recv)
        }
    }

    pub fn bitrate_send(&self) -> &str {
        &self.bitrate_send
    }

    pub fn bitrate_recv(&self) -> &str {
        &self.bitrate_recv
    }

    pub fn set_bitrate(
        &mut self,
        bitrate: impl Into<String>,
    ) -> Result<(), UnsupportedTargetError> {
        let bitrate = bitrate.into();
        if !validate_bitrate(&bitrate) {
            return Err(UnsupportedTargetError(format!(
                "invalid bitrate: {}",
                bitrate
            )));
        }
        self.bitrate_send = bitrate.clone();
        self.bitrate_recv = bitrate;
        Ok(())
    }

    pub fn fields(&self) -> &TargetData {
        &self.data
    }

    pub fn fields_mut(&mut self) -> &mut TargetData {
        &mut self.data
    }
}

impl TargetData {
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_bitrate_accepts_numeric_uppercase_suffix_and_rejects_invalid_forms() {
        assert!(validate_bitrate("106A"));
        assert!(validate_bitrate("424F"));
        assert!(!validate_bitrate(""));
        assert!(!validate_bitrate("A"));
        assert!(!validate_bitrate("106a"));
        assert!(!validate_bitrate("10AF")); // non-digit in numeric portion
    }

    #[test]
    fn parse_bitrate_supports_single_and_split_send_receive_values() {
        let (send, recv) = parse_bitrate("106A").expect("single bitrate should parse");
        assert_eq!(send, "106A");
        assert_eq!(recv, "106A");

        let (send, recv) = parse_bitrate("212F/424F").expect("split bitrate should parse");
        assert_eq!(send, "212F");
        assert_eq!(recv, "424F");
    }

    #[test]
    fn parse_bitrate_rejects_missing_or_invalid_values() {
        let err = parse_bitrate("").expect_err("empty bitrate should fail");
        assert_eq!(err.0, "missing bitrate");

        let err = parse_bitrate("abc").expect_err("invalid send bitrate should fail");
        assert_eq!(err.0, "invalid bitrate: abc");

        let err = parse_bitrate("106A/42f").expect_err("invalid receive bitrate should fail");
        assert_eq!(err.0, "invalid receive bitrate: 42f");
    }

    #[test]
    fn remote_target_parses_bitrate_and_exposes_mutable_fields() {
        let mut target = RemoteTarget::new("212F/424F").expect("remote target should be created");
        assert_eq!(target.bitrate(), "212F");
        assert_eq!(target.bitrate_send(), "212F");
        assert_eq!(target.bitrate_recv(), "424F");
        assert!(target.fields().sensf_req.is_none());

        target.fields_mut().sensf_req = Some(vec![0x00, 0xFF]);
        assert_eq!(target.fields().sensf_req, Some(vec![0x00, 0xFF]));
    }

    #[test]
    fn local_target_validates_and_updates_bitrate() {
        let mut target = LocalTarget::new("106A").expect("local target should be created");
        assert_eq!(target.bitrate(), "106A");
        assert_eq!(target.bitrate_send(), "106A");
        assert_eq!(target.bitrate_recv(), "106A");

        target
            .set_bitrate("424F")
            .expect("set_bitrate should succeed");
        assert_eq!(target.bitrate(), "424F");

        let err = target
            .set_bitrate("42f")
            .expect_err("invalid bitrate should fail");
        assert_eq!(err.0, "invalid bitrate: 42f");
    }

    #[test]
    fn target_data_reset_restores_default_values() {
        let mut data = TargetData {
            sens_req: Some(vec![0x01]),
            dep_req: Some(vec![0xAA]),
            mf_halted: true,
            arae: true,
            ..TargetData::default()
        };
        data.reset();
        assert!(data.sens_req.is_none());
        assert!(data.dep_req.is_none());
        assert!(!data.mf_halted);
        assert!(!data.arae);
    }
}
