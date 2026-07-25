//! Target discovery for RC-S956 devices.
//!
//! This module implements target detection for NFC-A, NFC-B, and NFC-F targets.

use crate::clf::errors::UnsupportedTargetError;
use crate::clf::targets::RemoteTarget;
use crate::driver::errors::{ChipsetError, DriverError, Result};
use crate::driver::rcs956::chipset::{IN_LIST_PASSIVE_TARGET_BRTY_RANGE, ciu, err};
use crate::driver::rcs956::device::Device;
use crate::felica_standard::Type3TagPollingResult;
use crate::transport::Transport;
use log::{debug, warn};
use std::time::Duration;

/// How long to keep the RF field up before sending the first Polling command.
///
/// A card needs up to 20 ms from entering the field to being able to receive a
/// command, and the FeliCa card user's manual (§2.4.1) recommends holding the
/// field for at least 20.4 ms — 20 ms of start-up plus margin for the field's
/// own rise time — before polling. Polling earlier is allowed but only if the
/// caller retries, so a driver that polls once must wait out the full time.
const CARD_STARTUP_TIME: Duration = Duration::from_micros(20_400);

impl<T: Transport> Device<T> {
    /// Detects a Type A target (NFC-A).
    pub fn detect_type_a(&mut self, target: &RemoteTarget) -> Result<Option<RemoteTarget>> {
        let bitrate = bitrate_code(target.bitrate())?;
        if !IN_LIST_PASSIVE_TARGET_BRTY_RANGE.contains(&bitrate) {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                format!("unsupported bitrate {}", target.bitrate()),
            )));
        }

        debug!("polling for NFC-A target at {}", target.bitrate());

        // Prepare UID for anticollision if provided
        let mut uid = target.data.sel_req.clone().unwrap_or_default();
        if uid.len() > 4 {
            uid.insert(0, 0x88);
        }
        if uid.len() > 8 {
            uid.insert(4, 0x88);
        }

        // Perform InListPassiveTarget
        let response = self.chipset.in_list_passive_target(1, bitrate, &uid)?;
        let Some(data) = response else {
            // Check if we received SENS_RES but no SDD_RES (Type 1 Tag)
            if let Ok(fifo_data) = self.chipset.read_single_register(ciu::FIFO_DATA)
                && fifo_data == 0x26
            {
                // No SENS_RES, no tag present
                return Ok(None);
            }

            debug!("sens_res but no sdd_res, try as type 1 tag");
            return self.try_type1_detection();
        };

        // Parse the response
        if data.len() < 4 {
            return Ok(None);
        }

        let sens_res = vec![data[1], data[0]]; // Response is in reverse order
        let sel_res = vec![data[2]];
        let sdd_res = data[4..].to_vec();

        // Disable CRC check for Type 2 Tag
        if sel_res[0] & 0x60 == 0x00 {
            debug!("disable crc check for type 2 tag");
            let rx_mode = self.chipset.read_single_register(ciu::RX_MODE)?;
            self.chipset
                .write_single_register(ciu::RX_MODE, rx_mode & 0x7F)?;
        }

        let mut found = RemoteTarget::new(target.bitrate())?;
        found.data.sens_res = Some(sens_res);
        found.data.sel_res = Some(sel_res);
        found.data.sdd_res = Some(sdd_res);

        Ok(Some(found))
    }

    fn try_type1_detection(&mut self) -> Result<Option<RemoteTarget>> {
        // Check if Type 1 Tag detection is supported
        if !IN_LIST_PASSIVE_TARGET_BRTY_RANGE.contains(&4) {
            warn!("The RC-S956 can not read Type 1 Tags");
            return Ok(None);
        }

        let response = self.chipset.in_list_passive_target(1, 4, &[])?;
        let Some(data) = response else {
            return Ok(None);
        };

        // Send RID command
        let rid_cmd = [0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let timeout = std::time::Duration::from_millis(100);
        match self.chipset.in_data_exchange(&rid_cmd, timeout) {
            Ok((rid_res, _)) => {
                let mut found = RemoteTarget::new("106A")?;
                found.data.sens_res = Some(vec![data[1], data[0]]);
                found.data.rid_res = Some(rid_res);
                Ok(Some(found))
            }
            Err(DriverError::Chipset(ChipsetError::Status(errno))) => {
                debug!("RID command failed with error {:02x}", errno);
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Detects a Type B target (NFC-B).
    pub fn detect_type_b(&mut self, target: &RemoteTarget) -> Result<Option<RemoteTarget>> {
        let bitrate = match target.bitrate() {
            "106B" => 3,
            "212B" => 6,
            "424B" => 7,
            "848B" => 8,
            other => {
                return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                    format!("unsupported bitrate {}", other),
                )));
            }
        };

        if !IN_LIST_PASSIVE_TARGET_BRTY_RANGE.contains(&bitrate) {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                format!("unsupported bitrate {}", target.bitrate()),
            )));
        }

        debug!("polling for NFC-B target at {}", target.bitrate());

        let afi = target
            .data
            .sensb_req
            .as_ref()
            .and_then(|d| d.first())
            .copied()
            .unwrap_or(0x00);

        let response = self.chipset.in_list_passive_target(1, bitrate, &[afi])?;
        let Some(data) = response else {
            return Ok(None);
        };

        // Check if this is an ISO-DEP capable tag
        if data.len() < 11 || data[10] & 0b00001001 != 0b00000001 {
            return Ok(None);
        }

        // The firmware has activated the tag with ATTRIB. We need to deselect
        // and wake it up again to allow proper activation.
        let timeout = std::time::Duration::from_millis(500);
        let deselect_cmd = [0xC2];
        let _ = self.chipset.in_communicate_thru(&deselect_cmd, timeout);

        let wupb_cmd = [0x05, afi, 0x08];
        match self.chipset.in_communicate_thru(&wupb_cmd, timeout) {
            Ok(sensb_res) => {
                let mut found = RemoteTarget::new(target.bitrate())?;
                found.data.sensb_res = Some(sensb_res);
                Ok(Some(found))
            }
            Err(e) => {
                debug!("WUPB failed: {:?}", e);
                Ok(None)
            }
        }
    }

    /// Detects a Type F target (NFC-F/FeliCa).
    pub fn detect_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<Type3TagPollingResult> {
        let bitrate = match target.bitrate() {
            "212F" => 1,
            "424F" => 2,
            other => {
                return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                    format!("unsupported bitrate {}", other),
                )));
            }
        };

        if !IN_LIST_PASSIVE_TARGET_BRTY_RANGE.contains(&bitrate) {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                format!("unsupported bitrate {}", target.bitrate()),
            )));
        }

        debug!("polling for NFC-F target at {}", target.bitrate());

        // Check if RF field is already on, if not activate it and wait out the
        // card's start-up time before polling.
        let tx_control = self.chipset.read_single_register(ciu::TX_CONTROL)?;
        if tx_control & 0b00000011 == 0 {
            self.chipset.rf_configuration(0x01, &[0x01])?;
            std::thread::sleep(CARD_STARTUP_TIME);
        }

        // Build SENSF_REQ
        let sensf_req = build_sensf_req(system_code, request_code, time_slots);
        let response = self
            .chipset
            .in_list_passive_target(1, bitrate, &sensf_req)?;

        let Some(data) = response else {
            return Err(DriverError::Communication(
                crate::clf::errors::CommunicationError::timeout("no type F target found"),
            ));
        };

        // Parse SENSF_RES
        // Format: [Length][ResponseCode][IDm(8)][PMm(8)][RD(0-2)]
        // Minimum length is 18 bytes (length byte indicates total size including itself)
        if data.len() < 18 {
            return Err(DriverError::Other("SENSF_RES too short".into()));
        }

        // Skip length byte [0] and response code [1]
        let idm = data[2..10].to_vec();
        let pmm = data[10..18].to_vec();

        let optional = if data.len() > 18 {
            data[18..].to_vec()
        } else {
            Vec::new()
        };

        debug!("received SENSF_RES IDm={}", hex::encode(&idm));

        Ok(Type3TagPollingResult { idm, pmm, optional })
    }

    /// Detects a DEP target in active communication mode.
    pub fn detect_dep(&mut self, target: &RemoteTarget) -> Result<Option<RemoteTarget>> {
        let atr_req = target
            .data
            .atr_req
            .as_ref()
            .ok_or_else(|| DriverError::Other("atr_req is required".into()))?;

        if atr_req.len() < 16 || atr_req.len() > 64 {
            return Err(DriverError::Other("atr_req must be 16 to 64 bytes".into()));
        }

        let br = match target.bitrate() {
            "106A" => 0,
            "212F" => 1,
            "424F" => 2,
            other => {
                return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                    format!("unsupported bitrate for DEP: {}", other),
                )));
            }
        };

        // Set timeout for ATR_RES
        self.chipset.rf_configuration(0x02, &[0x0B, 0x0B, 0x0A])?;

        let nfcid3 = &atr_req[2..12];
        let gi = if atr_req.len() > 16 {
            &atr_req[16..]
        } else {
            &[]
        };

        match self.chipset.in_jump_for_dep(true, br, &[], nfcid3, gi) {
            Ok(response) => {
                let mut atr_res = vec![0xD5, 0x01];
                atr_res.extend_from_slice(&response);

                // Unset detect-sync bit for 106A
                self.chipset.write_single_register(ciu::MODE, 0b00111011)?;

                debug!(
                    "running DEP in {} kbps active mode",
                    match br {
                        0 => 106,
                        1 => 212,
                        2 => 424,
                        _ => 0,
                    }
                );

                let mut found = RemoteTarget::new(target.bitrate())?;
                found.data.atr_res = Some(atr_res);
                found.data.atr_req = Some(atr_req.clone());

                Ok(Some(found))
            }
            Err(DriverError::Chipset(ChipsetError::Status(errno)))
                if errno == err::TIMEOUT || errno == err::RF_NOT_ACTIVATED =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

/// Converts a bitrate string to the PN53x bitrate code.
fn bitrate_code(bitrate: &str) -> Result<u8> {
    match bitrate {
        "106A" => Ok(0),
        "212F" => Ok(1),
        "424F" => Ok(2),
        "106B" => Ok(3),
        other => Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
            format!("unsupported bitrate {}", other),
        ))),
    }
}

/// Builds a SENSF_REQ initiator data for InListPassiveTarget.
///
/// The format follows nfcpy: [CMD][SC_HI][SC_LO][RC][TS]
/// where CMD=0x00 is the Polling command code.
fn build_sensf_req(system_code: u16, request_code: u8, time_slots: u8) -> Vec<u8> {
    let sc_bytes = system_code.to_be_bytes();
    // First byte 0x00 is the Polling command code (SENSF_REQ command)
    vec![0x00, sc_bytes[0], sc_bytes[1], request_code, time_slots]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitrate_code_maps_supported_values() {
        assert_eq!(bitrate_code("106A").expect("106A should map"), 0);
        assert_eq!(bitrate_code("212F").expect("212F should map"), 1);
        assert_eq!(bitrate_code("424F").expect("424F should map"), 2);
        assert_eq!(bitrate_code("106B").expect("106B should map"), 3);
    }

    #[test]
    fn bitrate_code_rejects_unsupported_values() {
        match bitrate_code("848B") {
            Err(DriverError::UnsupportedTarget(err)) => {
                assert_eq!(err.0, "unsupported bitrate 848B");
            }
            Err(other) => panic!("expected UnsupportedTarget error, got {other}"),
            Ok(code) => panic!("expected error, got code {code}"),
        }
    }

    #[test]
    fn build_sensf_req_uses_big_endian_system_code_order() {
        let request = build_sensf_req(0xFE00, 0x01, 0x0F);
        assert_eq!(request, vec![0x00, 0xFE, 0x00, 0x01, 0x0F]);
    }
}
