use crate::clf::errors::UnsupportedTargetError;

fn validate_brty(part: &str) -> bool {
    if part.len() < 2 {
        return false;
    }
    let (digits, suffix) = part.split_at(part.len() - 1);
    digits.chars().all(|c| c.is_ascii_digit()) && suffix.chars().all(|c| c.is_ascii_uppercase())
}

fn parse_brty(value: &str) -> Result<(String, String), UnsupportedTargetError> {
    let mut parts = value.splitn(2, '/');
    let send = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| UnsupportedTargetError("missing bitrate".into()))?;
    if !validate_brty(send) {
        return Err(UnsupportedTargetError(format!("invalid bitrate: {}", send)));
    }
    if let Some(recv) = parts.next() {
        if !validate_brty(recv) {
            return Err(UnsupportedTargetError(format!(
                "invalid receive bitrate: {}",
                recv
            )));
        }
        Ok((send.to_string(), recv.to_string()))
    } else {
        Ok((send.to_string(), send.to_string()))
    }
}

fn default_target() -> TargetData {
    TargetData {
        sens_req: None,
        sens_res: None,
        sel_req: None,
        sel_res: None,
        sdd_res: None,
        rid_res: None,
        sensb_req: None,
        sensb_res: None,
        sensf_req: None,
        sensf_res: None,
        rats_res: None,
        rats_cmd: None,
        psl_req: None,
        atr_req: None,
        atr_res: None,
        tt2_cmd: None,
        tt3_cmd: None,
        tt4_cmd: None,
        dep_req: None,
        mf_halted: false,
        arae: false,
    }
}

#[derive(Debug, Clone)]
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
    pub sensf_res: Option<Vec<u8>>,
    pub rats_res: Option<Vec<u8>>,
    pub rats_cmd: Option<Vec<u8>>,
    pub psl_req: Option<Vec<u8>>,
    pub atr_req: Option<Vec<u8>>,
    pub atr_res: Option<Vec<u8>>,
    pub tt2_cmd: Option<Vec<u8>>,
    pub tt3_cmd: Option<Vec<u8>>,
    pub tt4_cmd: Option<Vec<u8>>,
    pub dep_req: Option<Vec<u8>>,
    pub mf_halted: bool,
    pub arae: bool,
}

impl Default for TargetData {
    fn default() -> Self {
        default_target()
    }
}

#[derive(Debug, Clone)]
pub struct RemoteTarget {
    brty_send: String,
    brty_recv: String,
    pub data: TargetData,
}

impl RemoteTarget {
    pub fn new(brty: impl Into<String>) -> Result<Self, UnsupportedTargetError> {
        let brty = brty.into();
        let (brty_send, brty_recv) = parse_brty(&brty)?;
        Ok(Self {
            brty_send,
            brty_recv,
            data: default_target(),
        })
    }

    pub fn brty(&self) -> &str {
        &self.brty_send
    }

    pub fn brty_send(&self) -> &str {
        &self.brty_send
    }

    pub fn brty_recv(&self) -> &str {
        &self.brty_recv
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
    brty_send: String,
    brty_recv: String,
    pub data: TargetData,
}

impl LocalTarget {
    pub fn new(brty: impl Into<String>) -> Result<Self, UnsupportedTargetError> {
        let brty = brty.into();
        if !validate_brty(&brty) {
            return Err(UnsupportedTargetError(format!("invalid bitrate: {}", brty)));
        }
        Ok(Self {
            brty_send: brty.clone(),
            brty_recv: brty,
            data: default_target(),
        })
    }

    pub fn brty(&self) -> String {
        if self.brty_send == self.brty_recv {
            self.brty_send.clone()
        } else {
            format!("{}/{}", self.brty_send, self.brty_recv)
        }
    }

    pub fn brty_send(&self) -> &str {
        &self.brty_send
    }

    pub fn brty_recv(&self) -> &str {
        &self.brty_recv
    }

    pub fn set_brty(&mut self, brty: impl Into<String>) -> Result<(), UnsupportedTargetError> {
        let brty = brty.into();
        if !validate_brty(&brty) {
            return Err(UnsupportedTargetError(format!("invalid bitrate: {}", brty)));
        }
        self.brty_send = brty.clone();
        self.brty_recv = brty;
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
        *self = default_target();
    }
}
