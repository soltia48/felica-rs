//! ISO/IEC 14443-3 activation of Type A and Type B cards.
//!
//! [`Device::detect_type_a_low_level`] and [`Device::detect_type_b_low_level`]
//! drive the activation the reader would otherwise perform on its own: the sense
//! command, the anticollision loop, the select, and the rate negotiation that
//! settles the link before ISO-DEP takes over. Doing it a frame at a time is what
//! makes the card's ATQA, SAK, UID and ATS visible to the caller.

use super::{
    Device, TYPE_A_CMD_TIMEOUT_MS, TYPE_B_CMD_TIMEOUT_MS, ThroughOptions, ThroughProtocol,
    TypeACardInfo, TypeBCardInfo, TypeBDetectOptions, apply_ats_config, data_rate_symbols,
};
use crate::driver::errors::{DriverError, Result};
use crate::driver::port400::iso14443::IsoDepConfig;
use crate::driver::port400::pcsc::TypeBInfo;
use crate::transport::Transport;
use std::thread::sleep;

impl<T: Transport> Device<T> {
    pub fn detect_type_a_low_level(&mut self) -> Result<TypeACardInfo> {
        self.prepare_type_a_polling()?;
        let atqa_bytes = self.send_type_a_frame(&[0x26], Some(7), false, false)?;
        if atqa_bytes.len() != 2 {
            return Err(DriverError::Other("invalid ATQA length".into()));
        }
        let atqa = [atqa_bytes[0], atqa_bytes[1]];
        let (uid, final_sak) = self.perform_type_a_anticollision()?;
        let mut config = IsoDepConfig::type_a_defaults();
        let rats_param = ((config.fsdi & 0x0F) << 4) | (config.cid & 0x0F);
        let rats_cmd = [0xE0, rats_param];
        let ats = self.send_type_a_frame(&rats_cmd, None, true, true)?;
        apply_ats_config(&mut config, &ats);
        sleep(config.sfgt_duration());
        self.send_type_a_pps(&config)?;
        Ok(TypeACardInfo {
            atqa,
            sak: final_sak,
            uid,
            ats,
            iso_dep_config: config,
        })
    }

    pub fn detect_type_b_low_level(
        &mut self,
        options: Option<TypeBDetectOptions>,
    ) -> Result<TypeBCardInfo> {
        let opts = options.unwrap_or_default();
        let mut config = opts.iso_dep.unwrap_or_else(IsoDepConfig::type_b_defaults);
        let info = self.prepare_type_b_link(&mut config, &opts)?;
        let (dri, dsi) = data_rate_symbols(&config);
        let attrib_cmd = build_type_b_attrib_command(&info, &config, dri, dsi);
        let attrib_response =
            self.send_type_b_frame(&attrib_cmd, true, true, TYPE_B_CMD_TIMEOUT_MS)?;
        if attrib_response.is_empty() {
            return Err(DriverError::Other("invalid ATTRIB response".into()));
        }
        self.apply_comm_speed(dri, dsi)?;
        sleep(config.sfgt_duration());
        Ok(TypeBCardInfo {
            pupi: info.pupi,
            application_data: info.application_data,
            protocol_info: info.protocol_info,
            attrib_response,
        })
    }

    fn send_type_a_frame(
        &mut self,
        payload: &[u8],
        tx_valid_bits: Option<u8>,
        append_crc: bool,
        discard_crc: bool,
    ) -> Result<Vec<u8>> {
        let options = ThroughOptions {
            protocol: ThroughProtocol::Iso14443TypeA,
            append_crc: Some(append_crc),
            discard_crc: Some(discard_crc),
            insert_parity: Some(true),
            expect_parity: Some(true),
            append_protocol_prologue: Some(false),
            tx_valid_bits,
        };
        self.communicate_thru(payload, Some(TYPE_A_CMD_TIMEOUT_MS), Some(options))
    }

    fn perform_type_a_anticollision(&mut self) -> Result<(Vec<u8>, u8)> {
        let mut sel_code = 0x93;
        let mut uid = Vec::new();
        loop {
            let anticollision = self.send_type_a_frame(&[sel_code, 0x20], None, false, false)?;
            let block = anticollision
                .get(..5)
                .ok_or_else(|| DriverError::Other("invalid anticollision response".into()))?;
            let (uid_block, bcc) = block.split_at(4);
            let bcc = *bcc
                .first()
                .ok_or_else(|| DriverError::Other("invalid anticollision response".into()))?;
            validate_bcc(uid_block, bcc)?;
            let sak = self.send_type_a_select(sel_code, &anticollision)?;
            append_uid_block(&mut uid, uid_block);
            if (sak & 0x04) == 0 {
                return Ok((uid, sak));
            }
            sel_code = next_cascade_code(sel_code)?;
            uid.clear();
        }
    }

    fn send_type_a_select(&mut self, sel_code: u8, anticollision: &[u8]) -> Result<u8> {
        let mut select = Vec::with_capacity(7);
        select.extend_from_slice(&[sel_code, 0x70]);
        select.extend_from_slice(&anticollision[..5]);
        let sak_resp = self.send_type_a_frame(&select, None, true, true)?;
        sak_resp
            .first()
            .copied()
            .ok_or_else(|| DriverError::Other("missing SAK".into()))
    }

    fn send_type_a_pps(&mut self, config: &IsoDepConfig) -> Result<()> {
        let (dri, dsi) = data_rate_symbols(config);
        if dri == 0 && dsi == 0 {
            return Ok(());
        }
        let ppss = 0xD0 | (config.cid & 0x0F);
        let pps0 = 0x11;
        let pps1 = ((dsi & 0x03) << 2) | (dri & 0x03);
        let frame = [ppss, pps0, pps1];
        let response = self.send_type_a_frame(&frame, None, true, true)?;
        if response.first().copied() != Some(ppss) {
            return Err(DriverError::Other("PPS response mismatch".into()));
        }
        self.apply_comm_speed(dri, dsi)
    }

    fn send_type_b_frame(
        &mut self,
        payload: &[u8],
        append_crc: bool,
        discard_crc: bool,
        timeout_ms: u16,
    ) -> Result<Vec<u8>> {
        let options = ThroughOptions {
            protocol: ThroughProtocol::Iso14443TypeB,
            append_crc: Some(append_crc),
            discard_crc: Some(discard_crc),
            insert_parity: Some(false),
            expect_parity: Some(false),
            append_protocol_prologue: Some(false),
            tx_valid_bits: None,
        };
        self.communicate_thru(payload, Some(timeout_ms), Some(options))
    }
}

fn build_type_b_attrib_command(
    info: &TypeBInfo,
    config: &IsoDepConfig,
    dri: u8,
    dsi: u8,
) -> Vec<u8> {
    let param2 = ((dsi & 0x03) << 6) | ((dri & 0x03) << 4) | (config.fsdi & 0x0F);
    let param3 = info.protocol_info.get(1).copied().unwrap_or(0x02) & 0x0F;
    let mut frame = Vec::with_capacity(9);
    frame.push(0x1D);
    frame.extend_from_slice(&info.pupi);
    frame.push(0x00);
    frame.push(param2);
    frame.push(param3);
    frame.push(config.cid & 0x0F);
    frame
}

fn validate_bcc(block: &[u8], bcc: u8) -> Result<()> {
    let computed_bcc = block.iter().fold(0u8, |acc, b| acc ^ b);
    if bcc == computed_bcc {
        Ok(())
    } else {
        Err(DriverError::Other("UID BCC mismatch".into()))
    }
}

fn next_cascade_code(sel_code: u8) -> Result<u8> {
    match sel_code {
        0x93 => Ok(0x95),
        0x95 => Ok(0x97),
        _ => Err(DriverError::Other(
            "unsupported Type-A cascade level".into(),
        )),
    }
}

fn append_uid_block(uid: &mut Vec<u8>, block: &[u8]) {
    if block.first() == Some(&0x88) && block.len() >= 4 {
        uid.extend_from_slice(&block[1..4]);
    } else {
        uid.extend_from_slice(block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testing::assert_driver_error_contains;

    #[test]
    fn build_type_b_attrib_command_packs_parameters() {
        let info = TypeBInfo {
            pupi: [0x11, 0x22, 0x33, 0x44],
            application_data: [0; 4],
            protocol_info: vec![0x00, 0xF2],
        };
        let mut config = IsoDepConfig::type_b_defaults();
        config.fsdi = 0x1A;
        config.cid = 0x2F;
        let frame = build_type_b_attrib_command(&info, &config, 0x03, 0x02);
        assert_eq!(
            frame,
            vec![0x1D, 0x11, 0x22, 0x33, 0x44, 0x00, 0xBA, 0x02, 0x0F]
        );
    }

    #[test]
    fn build_type_b_attrib_command_uses_default_param3_when_info_is_short() {
        let info = TypeBInfo {
            pupi: [1, 2, 3, 4],
            application_data: [0; 4],
            protocol_info: vec![0xA0],
        };
        let config = IsoDepConfig::type_b_defaults();
        let frame = build_type_b_attrib_command(&info, &config, 1, 1);
        assert_eq!(frame, vec![0x1D, 1, 2, 3, 4, 0x00, 0x58, 0x02, 0x02]);
    }

    #[test]
    fn validate_bcc_checks_xor_of_uid_block() {
        let block = [0x04, 0x25, 0x85, 0x93];
        let bcc = block.iter().fold(0u8, |acc, b| acc ^ b);
        assert!(validate_bcc(&block, bcc).is_ok());
        assert_driver_error_contains(validate_bcc(&block, bcc ^ 0x01), "UID BCC mismatch");
    }

    #[test]
    fn next_cascade_code_maps_known_levels_and_rejects_invalid_level() {
        assert_eq!(next_cascade_code(0x93).expect("cascade level 1"), 0x95);
        assert_eq!(next_cascade_code(0x95).expect("cascade level 2"), 0x97);
        assert_driver_error_contains(next_cascade_code(0x97), "unsupported Type-A cascade level");
    }

    #[test]
    fn append_uid_block_strips_ct_prefix_only_for_complete_blocks() {
        let mut uid = vec![0xAA];
        append_uid_block(&mut uid, &[0x88, 0x11, 0x22, 0x33, 0x44]);
        assert_eq!(uid, vec![0xAA, 0x11, 0x22, 0x33]);

        let mut normal = Vec::new();
        append_uid_block(&mut normal, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(normal, vec![0x01, 0x02, 0x03, 0x04]);

        let mut short_ct = Vec::new();
        append_uid_block(&mut short_ct, &[0x88, 0x99]);
        assert_eq!(short_ct, vec![0x88, 0x99]);
    }
}
