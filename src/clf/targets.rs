//! The NFC targets a reader talks to, and the ones it presents as.
//!
//! A target is a bitrate pair plus the protocol fields the activation exchanged.
//! [`RemoteTarget`] describes a card the reader found, [`LocalTarget`] a card the
//! reader emulates; they differ only in how their bitrate is set, so the parsing
//! and validation of one live in the private `BitratePair`.

use crate::clf::errors::UnsupportedTargetError;

/// The send and receive bitrates of a target.
///
/// A bitrate is a decimal speed followed by an uppercase technology letter, such
/// as `106A` or `212F`. A target that sends and receives at different speeds
/// writes them as `send/recv`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BitratePair {
    send: String,
    recv: String,
}

impl BitratePair {
    /// Parses a `send` or `send/recv` specification.
    fn parse(value: &str) -> Result<Self, UnsupportedTargetError> {
        let mut parts = value.splitn(2, '/');
        let send = parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or_else(|| UnsupportedTargetError("missing bitrate".into()))?;
        Self::ensure_valid(send, "invalid bitrate")?;
        let recv = match parts.next() {
            Some(recv) => {
                Self::ensure_valid(recv, "invalid receive bitrate")?;
                recv.to_string()
            }
            None => send.to_string(),
        };
        Ok(Self {
            send: send.to_string(),
            recv,
        })
    }

    /// Parses one bitrate, used in both directions.
    fn single(value: &str) -> Result<Self, UnsupportedTargetError> {
        Self::ensure_valid(value, "invalid bitrate")?;
        Ok(Self {
            send: value.to_string(),
            recv: value.to_string(),
        })
    }

    /// The combined form: one bitrate when both directions match, `send/recv`
    /// otherwise.
    fn combined(&self) -> String {
        if self.send == self.recv {
            self.send.clone()
        } else {
            format!("{}/{}", self.send, self.recv)
        }
    }

    fn ensure_valid(value: &str, message: &str) -> Result<(), UnsupportedTargetError> {
        if is_valid_bitrate(value) {
            Ok(())
        } else {
            Err(UnsupportedTargetError(format!("{message}: {value}")))
        }
    }
}

/// Returns `true` if `value` is a decimal speed followed by an uppercase
/// technology letter, such as `106A` or `212F`.
fn is_valid_bitrate(value: &str) -> bool {
    if value.len() < 2 {
        return false;
    }
    let (digits, suffix) = value.split_at(value.len() - 1);
    digits.chars().all(|c| c.is_ascii_digit()) && suffix.chars().all(|c| c.is_ascii_uppercase())
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
    bitrate: BitratePair,
    pub data: TargetData,
}

impl RemoteTarget {
    /// Creates a target for a `send` or `send/recv` bitrate specification.
    pub fn new(bitrate: impl Into<String>) -> Result<Self, UnsupportedTargetError> {
        Ok(Self {
            bitrate: BitratePair::parse(&bitrate.into())?,
            data: TargetData::default(),
        })
    }

    /// The bitrate the reader sends at, which is what identifies the
    /// technology a discovered card was found with.
    pub fn bitrate(&self) -> &str {
        &self.bitrate.send
    }

    pub fn bitrate_send(&self) -> &str {
        &self.bitrate.send
    }

    pub fn bitrate_recv(&self) -> &str {
        &self.bitrate.recv
    }
}

#[derive(Debug, Clone)]
pub struct LocalTarget {
    bitrate: BitratePair,
    pub data: TargetData,
}

impl LocalTarget {
    /// Creates a target that sends and receives at `bitrate`.
    pub fn new(bitrate: impl Into<String>) -> Result<Self, UnsupportedTargetError> {
        Ok(Self {
            bitrate: BitratePair::single(&bitrate.into())?,
            data: TargetData::default(),
        })
    }

    /// The bitrate in its combined form: one value while both directions match,
    /// and `send/recv` once a speed negotiation has split them.
    pub fn bitrate(&self) -> String {
        self.bitrate.combined()
    }

    pub fn bitrate_send(&self) -> &str {
        &self.bitrate.send
    }

    pub fn bitrate_recv(&self) -> &str {
        &self.bitrate.recv
    }

    /// Sets both directions to `bitrate`.
    pub fn set_bitrate(
        &mut self,
        bitrate: impl Into<String>,
    ) -> Result<(), UnsupportedTargetError> {
        self.bitrate = BitratePair::single(&bitrate.into())?;
        Ok(())
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
    fn is_valid_bitrate_accepts_numeric_uppercase_suffix_and_rejects_invalid_forms() {
        assert!(is_valid_bitrate("106A"));
        assert!(is_valid_bitrate("424F"));
        assert!(!is_valid_bitrate(""));
        assert!(!is_valid_bitrate("A"));
        assert!(!is_valid_bitrate("106a"));
        assert!(!is_valid_bitrate("10AF")); // non-digit in numeric portion
    }

    #[test]
    fn bitrate_pair_supports_single_and_split_send_receive_values() {
        let single = BitratePair::parse("106A").expect("single bitrate should parse");
        assert_eq!(single.send, "106A");
        assert_eq!(single.recv, "106A");
        assert_eq!(single.combined(), "106A");

        let split = BitratePair::parse("212F/424F").expect("split bitrate should parse");
        assert_eq!(split.send, "212F");
        assert_eq!(split.recv, "424F");
        assert_eq!(split.combined(), "212F/424F");
    }

    #[test]
    fn bitrate_pair_rejects_missing_or_invalid_values() {
        let err = BitratePair::parse("").expect_err("empty bitrate should fail");
        assert_eq!(err.0, "missing bitrate");

        let err = BitratePair::parse("abc").expect_err("invalid send bitrate should fail");
        assert_eq!(err.0, "invalid bitrate: abc");

        let err = BitratePair::parse("106A/42f").expect_err("invalid receive bitrate should fail");
        assert_eq!(err.0, "invalid receive bitrate: 42f");

        // A single bitrate has no split form to accept.
        let err = BitratePair::single("212F/424F").expect_err("split value should fail");
        assert_eq!(err.0, "invalid bitrate: 212F/424F");
    }

    #[test]
    fn remote_target_parses_bitrate_and_exposes_mutable_fields() {
        let mut target = RemoteTarget::new("212F/424F").expect("remote target should be created");
        assert_eq!(target.bitrate(), "212F");
        assert_eq!(target.bitrate_send(), "212F");
        assert_eq!(target.bitrate_recv(), "424F");
        assert!(target.data.sensf_req.is_none());

        target.data.sensf_req = Some(vec![0x00, 0xFF]);
        assert_eq!(target.data.sensf_req, Some(vec![0x00, 0xFF]));
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
