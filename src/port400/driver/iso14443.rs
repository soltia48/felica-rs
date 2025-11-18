use crate::driver::errors::{DriverError, Result};
use std::time::Duration;

const FWT_BASE_MICROS: u32 = 302; // approx (256 * 16 / fc)
const SFGT_BASE_MICROS: u32 = 256; // approx (256 / fc)
const ISO_DEP_MAX_FSCI: u8 = 8;
const ISO_DEP_MAX_FSDI: u8 = 8;
const ISO_DEP_MAX_FWI: u8 = 14;
const ISO_DEP_MAX_SFGI: u8 = 14;
const ISO_DEP_FRAME_SIZE_TABLE: [usize; 9] = [16, 24, 32, 40, 48, 64, 96, 128, 256];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsoDepDataRate {
    Kbps106,
    Kbps212,
    Kbps424,
    Kbps848,
}

impl IsoDepDataRate {
    pub fn symbol(&self) -> u8 {
        match self {
            IsoDepDataRate::Kbps106 => 0,
            IsoDepDataRate::Kbps212 => 1,
            IsoDepDataRate::Kbps424 => 2,
            IsoDepDataRate::Kbps848 => 3,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IsoDepConfig {
    pub fsdi: u8,
    pub fsci: u8,
    pub cid: u8,
    pub use_cid: bool,
    pub use_nad: bool,
    pub nad: u8,
    pub sfgi: u8,
    pub fwi: u8,
    pub dr: IsoDepDataRate,
    pub ds: IsoDepDataRate,
    pub same_d: bool,
    pub max_retry_i: u8,
    pub max_retry_r_ack: u8,
    pub max_retry_r_nak: u8,
    pub max_try_s_wtx: u8,
    pub fwt_extra: Duration,
}

impl IsoDepConfig {
    pub fn type_a_defaults() -> Self {
        Self {
            fsdi: 8,
            fsci: 2,
            cid: 0x02,
            use_cid: true,
            use_nad: false,
            nad: 0x00,
            sfgi: 0,
            fwi: 4,
            dr: IsoDepDataRate::Kbps106,
            ds: IsoDepDataRate::Kbps106,
            same_d: true,
            max_retry_i: 2,
            max_retry_r_ack: 2,
            max_retry_r_nak: 2,
            max_try_s_wtx: 5,
            fwt_extra: Duration::from_millis(0),
        }
    }

    pub fn type_b_defaults() -> Self {
        Self {
            sfgi: 0,
            fwi: 4,
            ..Self::type_a_defaults()
        }
    }

    pub fn fwt_duration(&self) -> Duration {
        let micro = fwt_microseconds(self.fwi) + self.fwt_extra.as_micros() as u32;
        Duration::from_micros(u64::from(micro))
    }

    pub fn sfgt_duration(&self) -> Duration {
        Duration::from_micros(u64::from(sfgt_microseconds(self.sfgi)))
    }

    pub fn fsc(&self) -> usize {
        ISO_DEP_FRAME_SIZE_TABLE[self.fsci.min(ISO_DEP_MAX_FSCI) as usize]
    }

    pub fn fsd(&self) -> usize {
        ISO_DEP_FRAME_SIZE_TABLE[self.fsdi.min(ISO_DEP_MAX_FSDI) as usize]
    }

    pub fn max_inf_len_picc(&self) -> usize {
        self.fsc()
            .saturating_sub(block_header_len(self.use_cid, self.use_nad))
    }

    pub fn max_inf_len_pcd(&self) -> usize {
        self.fsd()
            .saturating_sub(block_header_len(self.use_cid, self.use_nad))
    }

    pub fn update_pcd_ifs(&mut self, ifs: u8) {
        let clamped = ifs.max(16).min(255);
        self.fsdi = bytes_to_fdsi(clamped as usize);
    }

    pub fn apply_ats(&mut self, ats: &[u8]) -> Result<()> {
        if ats.len() < 2 {
            return Err(DriverError::Other("ATS is too short".into()));
        }
        let tl = ats[0] as usize;
        if tl == 0 || tl > ats.len() {
            return Err(DriverError::Other("ATS length mismatch".into()));
        }
        let mut offset = 1;
        if offset >= tl {
            return Err(DriverError::Other("ATS missing T0".into()));
        }
        let t0 = ats[offset];
        offset += 1;
        self.fsci = (t0 & 0x0F).min(ISO_DEP_MAX_FSCI);
        if (t0 & 0x10) != 0 {
            let ta = *ats
                .get(offset)
                .ok_or_else(|| DriverError::Other("ATS missing TA".into()))?;
            offset += 1;
            if (ta & 0x08) == 0 {
                self.dr = decode_data_rate(ta & 0x07);
                self.ds = decode_data_rate((ta >> 4) & 0x07);
                self.same_d = (ta & 0x80) != 0;
            }
        }
        if (t0 & 0x20) != 0 {
            let tb = *ats
                .get(offset)
                .ok_or_else(|| DriverError::Other("ATS missing TB".into()))?;
            offset += 1;
            let sfgi = tb & 0x0F;
            let fwi = (tb >> 4) & 0x0F;
            self.sfgi = sfgi.min(ISO_DEP_MAX_SFGI);
            self.fwi = fwi.min(ISO_DEP_MAX_FWI);
        }
        if (t0 & 0x40) != 0 {
            let tc = *ats
                .get(offset)
                .ok_or_else(|| DriverError::Other("ATS missing TC".into()))?;
            if (tc & 0x02) == 0 {
                self.use_cid = false;
            }
            if (tc & 0x01) == 0 {
                self.use_nad = false;
            }
        }
        Ok(())
    }

    pub fn apply_type_b_protocol_info(&mut self, info: &[u8]) -> Result<()> {
        if info.len() < 3 {
            return Err(DriverError::Other(
                "ISO-DEP Protocol Info must be at least 3 bytes".into(),
            ));
        }
        self.fsci = ((info[1] >> 4) & 0x0F).min(ISO_DEP_MAX_FSCI);
        if (info[0] & 0x08) == 0 {
            self.dr = decode_data_rate(info[0] & 0x07);
            self.ds = decode_data_rate((info[0] >> 4) & 0x07);
            self.same_d = (info[0] & 0x80) != 0;
        }
        if (info[2] & 0x01) == 0 {
            self.use_cid = false;
        }
        if (info[2] & 0x02) == 0 {
            self.use_nad = false;
        }
        self.fwi = ((info[2] >> 4) & 0x0F).min(ISO_DEP_MAX_FWI);
        if let Some(extra) = info.get(3) {
            self.sfgi = ((extra >> 4) & 0x0F).min(ISO_DEP_MAX_SFGI);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IsoDepState {
    tx_block_number: u8,
    picc_block_number: u8,
    use_cid: bool,
    cid: u8,
    use_nad: bool,
    nad: u8,
    chaining: bool,
}

impl IsoDepState {
    pub fn new(cid: Option<u8>, nad: Option<u8>) -> Self {
        Self {
            tx_block_number: 0,
            picc_block_number: 0,
            use_cid: cid.is_some(),
            cid: cid.unwrap_or(0),
            use_nad: nad.is_some(),
            nad: nad.unwrap_or(0),
            chaining: false,
        }
    }

    pub fn next_tx_block(&mut self) -> u8 {
        self.tx_block_number ^= 1;
        self.tx_block_number
    }

    pub fn current_tx_block(&self) -> u8 {
        self.tx_block_number
    }

    pub fn expected_picc_block(&self) -> u8 {
        self.picc_block_number
    }

    pub fn advance_picc_block(&mut self) -> u8 {
        self.picc_block_number ^= 1;
        self.picc_block_number
    }

    pub fn set_chaining(&mut self, chaining: bool) {
        self.chaining = chaining;
    }

    pub fn chaining(&self) -> bool {
        self.chaining
    }

    pub fn cid(&self) -> Option<u8> {
        if self.use_cid { Some(self.cid) } else { None }
    }

    pub fn nad(&self) -> Option<u8> {
        if self.use_nad { Some(self.nad) } else { None }
    }
}

#[derive(Clone, Debug)]
pub struct IsoDepSession {
    config: IsoDepConfig,
    state: IsoDepState,
    ifs_negotiated: bool,
    retry_i_counter: u8,
    retry_r_ack_counter: u8,
    retry_r_nak_counter: u8,
}

impl IsoDepSession {
    pub fn new(config: IsoDepConfig) -> Self {
        let cid = if config.use_cid {
            Some(config.cid)
        } else {
            None
        };
        let nad = if config.use_nad {
            Some(config.nad)
        } else {
            None
        };
        let state = IsoDepState::new(cid, nad);
        Self {
            config,
            state,
            ifs_negotiated: false,
            retry_i_counter: 0,
            retry_r_ack_counter: 0,
            retry_r_nak_counter: 0,
        }
    }

    pub fn config(&self) -> &IsoDepConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut IsoDepConfig {
        &mut self.config
    }

    pub fn state(&self) -> &IsoDepState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut IsoDepState {
        &mut self.state
    }

    pub fn reset(&mut self) {
        let cid = self.state.cid();
        let nad = self.state.nad();
        self.state = IsoDepState::new(cid, nad);
        self.ifs_negotiated = false;
        self.retry_i_counter = 0;
        self.retry_r_ack_counter = 0;
        self.retry_r_nak_counter = 0;
    }

    pub fn needs_ifs_request(&self) -> bool {
        self.config.max_inf_len_pcd() > 32 && !self.ifs_negotiated
    }

    pub fn mark_ifs_negotiated(&mut self) {
        self.ifs_negotiated = true;
    }

    pub fn reset_retry_counters(&mut self) {
        self.retry_i_counter = 0;
        self.retry_r_ack_counter = 0;
        self.retry_r_nak_counter = 0;
    }

    pub fn increment_retry_i(&mut self) -> bool {
        self.retry_i_counter = self.retry_i_counter.saturating_add(1);
        self.retry_i_counter <= self.config.max_retry_i
    }

    pub fn increment_retry_r_ack(&mut self) -> bool {
        self.retry_r_ack_counter = self.retry_r_ack_counter.saturating_add(1);
        self.retry_r_ack_counter <= self.config.max_retry_r_ack
    }

    pub fn increment_retry_r_nak(&mut self) -> bool {
        self.retry_r_nak_counter = self.retry_r_nak_counter.saturating_add(1);
        self.retry_r_nak_counter <= self.config.max_retry_r_nak
    }
}

fn fwt_microseconds(fwi: u8) -> u32 {
    let shift = fwi.min(14);
    FWT_BASE_MICROS.saturating_mul(1 << shift)
}

fn sfgt_microseconds(sfgi: u8) -> u32 {
    let shift = sfgi.min(8);
    SFGT_BASE_MICROS.saturating_mul(1 << shift)
}

fn decode_data_rate(value: u8) -> IsoDepDataRate {
    match value & 0x03 {
        0 => IsoDepDataRate::Kbps106,
        1 => IsoDepDataRate::Kbps212,
        2 => IsoDepDataRate::Kbps424,
        3 => IsoDepDataRate::Kbps848,
        _ => IsoDepDataRate::Kbps106,
    }
}

fn block_header_len(use_cid: bool, use_nad: bool) -> usize {
    let mut len = 1;
    if use_cid {
        len += 1;
    }
    if use_nad {
        len += 1;
    }
    len
}

fn bytes_to_fdsi(value: usize) -> u8 {
    for (idx, size) in ISO_DEP_FRAME_SIZE_TABLE.iter().enumerate() {
        if *size >= value {
            return idx as u8;
        }
    }
    ISO_DEP_MAX_FSDI
}
