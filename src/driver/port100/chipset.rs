use crate::driver::errors::{
    ChipsetError, CommunicationFault, DriverError, Result, ensure_status_ok,
};
use crate::driver::io::{recover_after_error, remaining_until, take_from_buffer, timeout_error};
use crate::driver::port100::frame::{self, Frame, FrameType};
use crate::transport::Transport;
use log::debug;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

const IN_SET_PROTOCOL_DEFAULTS: [u8; 38] = [
    0x00, 0x18, 0x01, 0x01, 0x02, 0x01, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x08,
    0x08, 0x00, 0x09, 0x00, 0x0A, 0x00, 0x0B, 0x00, 0x0C, 0x00, 0x0E, 0x04, 0x0F, 0x00, 0x10, 0x00,
    0x11, 0x00, 0x12, 0x00, 0x13, 0x06,
];

const TG_SET_PROTOCOL_DEFAULTS: [u8; 6] = [0x00, 0x01, 0x01, 0x01, 0x02, 0x07];

/// Receive setting the reference library applies to the FeliCa RF configuration:
/// register `1A`, mask `C0`, value `40`, which improves noise resistance.
const RF_NOISE_RESISTANT_IMPROVEMENT: [u8; 3] = [0x1A, 0xC0, 0x40];
/// Most register settings the reader accepts in one RCT block.
const IN_SET_RCT_SETTING_NUM_MAX: usize = 16;
/// Length of the LT-Info block that unlocks the RCT commands.
const LT_INFO_LEN: usize = 16;
/// Initiator protocol keys the reader defines, `00h` through `13h`.
const INITIATOR_PROTOCOL_KEYS: usize = 0x14;

/// Readers whose LT-Info the reference library knows.
///
/// Each row is the two identifying bytes of the property block, the two bytes of
/// the PD data version, and then the reader's 16 byte LT-Info.
const LT_INFO_TABLE: [[u8; 4 + LT_INFO_LEN]; 4] = [
    [
        0, 0, 1, 1, 139, 91, 9, 236, 122, 221, 197, 129, 0, 151, 75, 95, 164, 118, 161, 213,
    ],
    [
        0, 1, 1, 0, 213, 159, 243, 133, 168, 199, 47, 105, 44, 65, 173, 1, 230, 180, 145, 103,
    ],
    [
        0, 6, 1, 0, 106, 206, 150, 130, 181, 221, 246, 214, 152, 205, 55, 232, 219, 31, 152, 186,
    ],
    [
        0, 8, 1, 0, 71, 212, 66, 85, 79, 225, 65, 241, 115, 21, 127, 202, 181, 114, 86, 210,
    ],
];

pub struct Chipset<T: Transport> {
    pub(crate) transport: T,
    firmware_version: (u8, u8),
    read_buffer: VecDeque<u8>,
    /// Bitrates the initiator RF was last configured for, send then receive.
    initiator_bitrate: Option<(String, String)>,
    /// Whether the FeliCa receive tuning has been attempted for this session.
    noise_resistance_attempted: bool,
    /// Initiator protocol values the reader is known to hold, indexed by key, so
    /// a setting that is already in place is not written again.
    initiator_protocol: [Option<u8>; INITIATOR_PROTOCOL_KEYS],
}

impl<T: Transport> Chipset<T> {
    pub const ACK: [u8; 6] = frame::ACK_BYTES;
    const ACK_TIMEOUT: Duration = Duration::from_millis(1_000);
    const RESPONSE_TIMEOUT: Duration = Duration::from_millis(1_500);

    pub fn new(mut transport: T) -> Result<Self> {
        transport.write(&Self::ACK)?;
        while let Ok(data) = transport.read(Duration::from_millis(10)) {
            debug!("cleared garbage {:x?}", data);
        }

        let mut chipset = Self {
            transport,
            firmware_version: (0, 0),
            read_buffer: VecDeque::new(),
            initiator_bitrate: None,
            noise_resistance_attempted: false,
            initiator_protocol: [None; INITIATOR_PROTOCOL_KEYS],
        };
        match chipset.set_command_type(1) {
            Ok(()) => {}
            Err(DriverError::Chipset(ChipsetError::Status(_))) => {
                chipset.set_command_type(0)?;
            }
            Err(err) => return Err(err),
        }
        let version = chipset.get_firmware_version(Some(0x60))?;
        chipset.firmware_version = (version[0], version[1]);
        chipset.get_pd_data_version()?;
        chipset.switch_rf(false)?;
        Ok(chipset)
    }

    pub fn close(&mut self) -> Result<()> {
        self.switch_rf(false)?;
        self.transport.write(&Self::ACK)?;
        self.transport.close()?;
        Ok(())
    }

    pub fn firmware_version(&self) -> (u8, u8) {
        self.firmware_version
    }

    pub fn manufacturer_name(&self) -> Option<&str> {
        self.transport.manufacturer_name()
    }

    pub fn product_name(&self) -> Option<&str> {
        self.transport.product_name()
    }

    fn send_command(&mut self, code: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let frame = Frame::build(&Self::build_command_payload(code, payload));
        self.write_frame(&frame)?;
        self.read_command_response(code)
    }

    pub fn set_command_type(&mut self, value: u8) -> Result<()> {
        let rsp = self.send_command(0x2A, &[value])?;
        ensure_status_ok(rsp.first().copied())?;
        self.forget_initiator_settings();
        Ok(())
    }

    pub fn get_firmware_version(&mut self, option: Option<u8>) -> Result<Vec<u8>> {
        let args = option.into_iter().collect::<Vec<_>>();
        self.send_command(0x20, &args)
    }

    pub fn get_pd_data_version(&mut self) -> Result<Vec<u8>> {
        self.send_command(0x22, &[])
    }

    pub fn reset_device(&mut self, startup_delay: u16) -> Result<()> {
        let delay_bytes = startup_delay.to_le_bytes();
        self.send_command(0x12, &delay_bytes)?;
        self.transport.write(&Self::ACK)?;
        let delay_ms = startup_delay as u64 + 500;
        std::thread::sleep(Duration::from_millis(delay_ms));
        self.forget_initiator_settings();
        Ok(())
    }

    pub fn get_command_type(&mut self) -> Result<u64> {
        let data = self.send_command(0x28, &[])?;
        if data.len() >= 8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[0..8]);
            Ok(u64::from_be_bytes(buf))
        } else {
            Err(DriverError::Other("short command type response".into()))
        }
    }

    pub fn switch_rf(&mut self, on: bool) -> Result<()> {
        let rsp = self.send_command(0x06, &[if on { 1 } else { 0 }])?;
        ensure_status_ok(rsp.first().copied())?;
        self.forget_initiator_settings();
        Ok(())
    }

    pub fn apply_initiator_defaults(&mut self) -> Result<()> {
        let defaults: Vec<(u8, u8)> = IN_SET_PROTOCOL_DEFAULTS
            .chunks_exact(2)
            .map(|pair| (pair[0], pair[1]))
            .collect();
        self.write_initiator_protocol(&defaults)
    }

    pub fn configure_initiator(&mut self, params: &[(&str, u8)]) -> Result<()> {
        let mut entries = Vec::with_capacity(params.len());
        for (name, value) in params {
            let key = initiator_param_index(name).ok_or_else(|| {
                DriverError::Other(format!("invalid initiator protocol key {name}"))
            })?;
            entries.push((key, *value));
        }
        self.write_initiator_protocol(&entries)
    }

    /// Writes the initiator protocol keys whose value the reader does not hold
    /// yet, and nothing at all when every one of them is already in place.
    fn write_initiator_protocol(&mut self, entries: &[(u8, u8)]) -> Result<()> {
        let mut payload = Vec::with_capacity(entries.len() * 2);
        for &(key, value) in entries {
            if self.initiator_protocol.get(key as usize).copied().flatten() == Some(value) {
                continue;
            }
            payload.push(key);
            payload.push(value);
        }
        if payload.is_empty() {
            return Ok(());
        }
        let rsp = self.send_command(0x02, &payload)?;
        ensure_status_ok(rsp.first().copied())?;
        for pair in payload.chunks_exact(2) {
            if let Some(slot) = self.initiator_protocol.get_mut(pair[0] as usize) {
                *slot = Some(pair[1]);
            }
        }
        Ok(())
    }

    /// Drops what is known about the initiator configuration, so the next
    /// exchange establishes it again.
    fn forget_initiator_settings(&mut self) {
        self.initiator_bitrate = None;
        self.initiator_protocol = [None; INITIATOR_PROTOCOL_KEYS];
    }

    pub fn apply_target_defaults(&mut self) -> Result<()> {
        self.tg_set_protocol(Some(&TG_SET_PROTOCOL_DEFAULTS), &[])
    }

    pub fn configure_target(&mut self, params: &[(&str, u8)]) -> Result<()> {
        self.tg_set_protocol(None, params)
    }

    fn tg_set_protocol(&mut self, data: Option<&[u8]>, params: &[(&str, u8)]) -> Result<()> {
        self.configure_protocol(0x42, data, params, target_param_index, "target key")
    }

    pub fn set_initiator_rf(
        &mut self,
        bitrate_send: &str,
        bitrate_recv: Option<&str>,
    ) -> Result<()> {
        fn settings(bitrate: &str) -> Option<(u8, u8, u8, u8)> {
            match bitrate {
                "212F" => Some((1, 1, 15, 1)),
                "424F" => Some((1, 2, 15, 2)),
                "106A" => Some((2, 3, 15, 3)),
                "212A" => Some((4, 4, 15, 4)),
                "424A" => Some((5, 5, 15, 5)),
                "106B" => Some((3, 7, 15, 7)),
                "212B" => Some((3, 8, 15, 8)),
                "424B" => Some((3, 9, 15, 9)),
                _ => None,
            }
        }

        let recv = bitrate_recv.unwrap_or(bitrate_send);
        if self.initiator_bitrate() == Some((bitrate_send, recv)) {
            // The RF already runs at these speeds, and nothing since has reset it.
            return Ok(());
        }
        let send_cfg = settings(bitrate_send)
            .ok_or_else(|| DriverError::Other(format!("unsupported bitrate {}", bitrate_send)))?;
        let recv_cfg = settings(recv)
            .ok_or_else(|| DriverError::Other(format!("unsupported bitrate {}", recv)))?;

        let params = vec![send_cfg.0, send_cfg.1, recv_cfg.2, recv_cfg.3];
        let rsp = self.send_command(0x00, &params)?;
        ensure_status_ok(rsp.first().copied())?;
        // Changing the RF re-initialises the protocol settings that go with it.
        self.forget_initiator_settings();
        self.initiator_bitrate = Some((bitrate_send.to_string(), recv.to_string()));
        // The reference library tunes the receive registers whenever it sets the
        // FeliCa RF speed; the setting is a register write that sticks, so one
        // attempt per session is enough.
        if bitrate_send.ends_with('F') {
            self.apply_felica_noise_resistance();
        }
        Ok(())
    }

    /// Bitrates the initiator RF is configured for, send first, or `None` before
    /// any RF configuration.
    ///
    /// The Port-100 has no query for the speed a card was activated at: the host
    /// drives the RF itself, so this is the speed every exchange runs at.
    pub fn initiator_bitrate(&self) -> Option<(&str, &str)> {
        self.initiator_bitrate
            .as_ref()
            .map(|(send, recv)| (send.as_str(), recv.as_str()))
    }

    /// Applies the reference library's FeliCa receive tuning, ignoring failures.
    ///
    /// A reader whose LT-Info is not in [`LT_INFO_TABLE`] cannot be tuned, and
    /// the reference library treats that and every transport failure here as
    /// non-fatal, so this reports problems to the log and returns.
    fn apply_felica_noise_resistance(&mut self) {
        if self.noise_resistance_attempted {
            return;
        }
        self.noise_resistance_attempted = true;
        if let Err(err) = self.tune_felica_receive_settings() {
            debug!("skipping the FeliCa receive tuning: {err}");
        }
    }

    fn tune_felica_receive_settings(&mut self) -> Result<()> {
        let lt_info = self.lt_info()?;
        let (send_setting, mut receive_setting) = self.in_get_rct(&lt_info)?;
        if !update_rct_setting(&mut receive_setting, RF_NOISE_RESISTANT_IMPROVEMENT) {
            debug!("FeliCa receive tuning already in place");
            return Ok(());
        }
        self.in_set_rct(&lt_info, &send_setting, &receive_setting)
    }

    /// Looks up the LT-Info that unlocks the RCT commands for this reader.
    fn lt_info(&mut self) -> Result<[u8; LT_INFO_LEN]> {
        let property = self.get_property()?;
        let model = property
            .get(14..16)
            .ok_or_else(|| DriverError::Other("property block is too short".into()))?;
        let version = self.get_pd_data_version()?;
        // The reference library reads the version bytes back to front.
        let version = match version[..] {
            [low, high, ..] => [high, low],
            _ => return Err(DriverError::Other("PD data version is too short".into())),
        };
        LT_INFO_TABLE
            .iter()
            .find(|entry| entry[..2] == *model && entry[2..4] == version)
            .and_then(|entry| entry[4..].try_into().ok())
            .ok_or_else(|| DriverError::Other("LT-Info unsupported reader/writer".into()))
    }

    pub fn get_property(&mut self) -> Result<Vec<u8>> {
        self.send_command(0x24, &[])
    }

    /// Reads the reader's send and receive register settings.
    fn in_get_rct(&mut self, lt_info: &[u8; LT_INFO_LEN]) -> Result<(Vec<u8>, Vec<u8>)> {
        let rsp = self.send_command(0x32, lt_info)?;
        ensure_status_ok(rsp.first().copied())?;
        let body = &rsp[1..];
        let send = take_rct_block(body, 0)?;
        let receive = take_rct_block(body, 1 + send.len())?;
        Ok((send, receive))
    }

    /// Writes both register setting blocks back.
    fn in_set_rct(
        &mut self,
        lt_info: &[u8; LT_INFO_LEN],
        send_setting: &[u8],
        receive_setting: &[u8],
    ) -> Result<()> {
        let mut payload =
            Vec::with_capacity(lt_info.len() + send_setting.len() + receive_setting.len() + 2);
        payload.extend_from_slice(lt_info);
        payload.push((send_setting.len() / 3) as u8);
        payload.extend_from_slice(send_setting);
        payload.push((receive_setting.len() / 3) as u8);
        payload.extend_from_slice(receive_setting);
        let rsp = self.send_command(0x30, &payload)?;
        ensure_status_ok(rsp.first().copied())
    }

    pub fn initiator_exchange_rf(&mut self, data: &[u8], timeout: u16) -> Result<Vec<u8>> {
        let timeout_units = if timeout > 0 {
            (((timeout as u32) + 1) * 10).min(0xFFFF) as u16
        } else {
            0
        };
        let mut payload = timeout_units.to_le_bytes().to_vec();
        payload.extend_from_slice(data);
        let rsp = self.send_command(0x04, &payload)?;
        if rsp.len() >= 4 && rsp[0..4] != [0, 0, 0, 0] {
            let fault = CommunicationFault::from_status(&rsp[0..4])
                .unwrap_or_else(|| CommunicationFault::new(0));
            return Err(DriverError::Chipset(ChipsetError::Fault(fault)));
        }
        Ok(rsp.get(5..).map(|d| d.to_vec()).unwrap_or_default())
    }

    pub fn set_target_rf(&mut self, comm_type: &str) -> Result<()> {
        let params = match comm_type {
            "106A" => Some((8, 11)),
            "212F" => Some((8, 12)),
            "424F" => Some((8, 13)),
            "212A" => Some((8, 14)),
            "424A" => Some((8, 15)),
            _ => None,
        }
        .ok_or_else(|| DriverError::Other(format!("unsupported comm type {}", comm_type)))?;
        let rsp = self.send_command(0x40, &[params.0, params.1])?;
        ensure_status_ok(rsp.first().copied())?;
        // Switching the reader into target mode drops the initiator setup.
        self.forget_initiator_settings();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn target_exchange_rf(
        &mut self,
        guard_time: u16,
        send_timeout: u16,
        mdaa: bool,
        nfca_params: &[u8],
        nfcf_params: &[u8],
        mf_halted: bool,
        arae: bool,
        recv_timeout: u16,
        transmit_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&guard_time.to_le_bytes());
        payload.extend_from_slice(&send_timeout.to_le_bytes());
        payload.push(mdaa as u8);

        let mut nfca_buf = [0u8; 6];
        nfca_buf[..nfca_params.len().min(6)]
            .copy_from_slice(&nfca_params[..nfca_params.len().min(6)]);
        payload.extend_from_slice(&nfca_buf);

        let mut nfcf_buf = [0u8; 18];
        nfcf_buf[..nfcf_params.len().min(18)]
            .copy_from_slice(&nfcf_params[..nfcf_params.len().min(18)]);
        payload.extend_from_slice(&nfcf_buf);

        payload.push(mf_halted as u8);
        payload.push(arae as u8);
        payload.extend_from_slice(&recv_timeout.to_le_bytes());

        if let Some(data) = transmit_data {
            payload.extend_from_slice(data);
        }

        let rsp = self.send_command(0x48, &payload)?;
        if rsp.len() >= 7
            && rsp[3..7] != [0, 0, 0, 0]
            && let Some(fault) = CommunicationFault::from_status(&rsp[3..7])
        {
            return Err(DriverError::Chipset(ChipsetError::Fault(fault)));
        }
        Ok(rsp)
    }

    fn configure_protocol<F>(
        &mut self,
        command: u8,
        data: Option<&[u8]>,
        params: &[(&str, u8)],
        lookup: F,
        key_kind: &str,
    ) -> Result<()>
    where
        F: Fn(&str) -> Option<u8>,
    {
        let mut payload = Vec::new();
        if let Some(bytes) = data {
            payload.extend_from_slice(bytes);
        }
        if !params.is_empty() {
            payload.reserve(params.len() * 2);
            for (name, value) in params {
                let index = lookup(name)
                    .ok_or_else(|| DriverError::Other(format!("invalid {key_kind} {}", name)))?;
                payload.push(index);
                payload.push(*value);
            }
        }
        if payload.is_empty() {
            return Ok(());
        }
        let rsp = self.send_command(command, &payload)?;
        ensure_status_ok(rsp.first().copied())
    }

    fn read_ack_frame(&mut self) -> Result<()> {
        let deadline = Instant::now() + Self::ACK_TIMEOUT;
        let bytes = self.read_exact(Self::ACK.len(), deadline)?;
        let frame =
            Frame::parse(&bytes).ok_or_else(|| DriverError::Other("invalid ack frame".into()))?;
        if frame.frame_type() != &FrameType::Ack {
            return Err(DriverError::Other("unexpected frame type".into()));
        }
        Ok(())
    }

    fn read_response_frame(&mut self) -> Result<Frame> {
        let deadline = Instant::now() + Self::RESPONSE_TIMEOUT;
        let bytes = self.read_frame_bytes(deadline)?;
        Frame::parse(&bytes).ok_or_else(|| DriverError::Other("invalid response frame".into()))
    }

    fn read_frame_bytes(&mut self, deadline: Instant) -> Result<Vec<u8>> {
        let mut frame = self.read_exact(5, deadline)?;
        if frame.get(0..3) != Some(&frame::PREAMBLE) {
            return Err(DriverError::Other("invalid frame preamble".into()));
        }

        let len = if frame[3] == 0xFF && frame[4] == 0xFF {
            let extended = self.read_exact(3, deadline)?;
            frame.extend_from_slice(&extended);
            u16::from_le_bytes([extended[0], extended[1]]) as usize
        } else {
            frame[3] as usize
        };

        let remaining = len
            .checked_add(2)
            .ok_or_else(|| DriverError::Other("frame length overflow".into()))?;
        let tail = self.read_exact(remaining, deadline)?;
        frame.extend_from_slice(&tail);
        Ok(frame)
    }

    fn read_exact(&mut self, len: usize, deadline: Instant) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            take_from_buffer(&mut self.read_buffer, &mut out, len);
            if out.len() == len {
                break;
            }
            let remaining =
                remaining_until(deadline).ok_or_else(|| DriverError::Io(timeout_error()))?;
            let chunk = self.transport.read(remaining)?;
            if !chunk.is_empty() {
                self.read_buffer.extend(chunk);
            }
        }
        Ok(out)
    }

    fn read_command_response(&mut self, code: u8) -> Result<Vec<u8>> {
        self.with_recovery(false, |chipset| chipset.read_ack_frame())?;
        let response = self.with_recovery(true, |chipset| chipset.read_response_frame())?;
        Self::extract_response_payload(response, code)
    }

    fn write_frame(&mut self, frame: &Frame) -> Result<()> {
        self.with_recovery(false, |chipset| {
            chipset
                .transport
                .write(frame.as_bytes())
                .map_err(DriverError::from)
        })
    }

    fn extract_response_payload(frame: Frame, code: u8) -> Result<Vec<u8>> {
        let payload = frame
            .into_payload()
            .ok_or_else(|| DriverError::Other("unexpected frame type".into()))?;
        if payload.first() == Some(&0xD7) && payload.get(1) == Some(&code.wrapping_add(1)) {
            Ok(payload[2..].to_vec())
        } else {
            Err(DriverError::Other("unexpected response".into()))
        }
    }

    fn build_command_payload(code: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(payload.len() + 2);
        data.push(0xD6);
        data.push(code);
        data.extend_from_slice(payload);
        data
    }

    fn with_recovery<R>(
        &mut self,
        drain_buffer: bool,
        action: impl FnOnce(&mut Self) -> Result<R>,
    ) -> Result<R> {
        match action(self) {
            Ok(value) => Ok(value),
            Err(err) => {
                recover_after_error(
                    &mut self.transport,
                    &mut self.read_buffer,
                    &Self::ACK,
                    drain_buffer,
                );
                Err(err)
            }
        }
    }
}

/// Reads one length-prefixed block of three-byte register settings.
///
/// `body` is the RCT payload and `offset` points at the block's count byte.
fn take_rct_block(body: &[u8], offset: usize) -> Result<Vec<u8>> {
    let count = *body
        .get(offset)
        .ok_or_else(|| DriverError::Other("RCT block count is missing".into()))?
        as usize;
    let start = offset + 1;
    let end = start + count * 3;
    body.get(start..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| DriverError::Other("RCT block is truncated".into()))
}

/// Merges one three-byte register setting into `settings`, returning whether the
/// block has to be written back.
///
/// A setting already carrying the wanted value needs no write; a register not
/// listed yet is appended as long as there is room for it.
fn update_rct_setting(settings: &mut Vec<u8>, entry: [u8; 3]) -> bool {
    for existing in settings.chunks_exact_mut(3) {
        if existing[0] != entry[0] || existing[1] != entry[1] {
            continue;
        }
        if existing[2] == entry[2] {
            return false;
        }
        existing[2] = entry[2];
        return true;
    }
    if settings.len() / 3 >= IN_SET_RCT_SETTING_NUM_MAX {
        return false;
    }
    settings.extend_from_slice(&entry);
    true
}

fn initiator_param_index(name: &str) -> Option<u8> {
    match name {
        "initial_guard_time" => Some(0),
        "add_crc" => Some(1),
        "check_crc" => Some(2),
        "multi_card" => Some(3),
        "add_parity" => Some(4),
        "check_parity" => Some(5),
        "bitwise_anticoll" => Some(6),
        "last_byte_bit_count" => Some(7),
        "mifare_crypto" => Some(8),
        "add_sof" => Some(9),
        "check_sof" => Some(10),
        "add_eof" => Some(11),
        "check_eof" => Some(12),
        "rfu" => Some(13),
        "deaf_time" => Some(14),
        "continuous_receive_mode" => Some(15),
        "min_len_for_crm" => Some(16),
        "type_1_tag_rrdd" => Some(17),
        "rfca" => Some(18),
        "guard_time" => Some(19),
        _ => None,
    }
}

fn target_param_index(name: &str) -> Option<u8> {
    match name {
        "send_timeout_time_unit" => Some(0),
        "rf_off_error" => Some(1),
        "continuous_receive_mode" => Some(2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Transport;
    use std::io::{self, ErrorKind};

    #[derive(Default)]
    struct DummyTransport {
        reads: VecDeque<io::Result<Vec<u8>>>,
        writes: Vec<Vec<u8>>,
        closed: bool,
    }

    impl DummyTransport {
        fn with_reads(reads: Vec<io::Result<Vec<u8>>>) -> Self {
            Self {
                reads: reads.into_iter().collect(),
                ..Self::default()
            }
        }
    }

    impl Transport for DummyTransport {
        fn write(&mut self, data: &[u8]) -> io::Result<()> {
            self.writes.push(data.to_vec());
            Ok(())
        }

        fn read(&mut self, _timeout: Duration) -> io::Result<Vec<u8>> {
            self.reads
                .pop_front()
                .unwrap_or_else(|| Err(io::Error::new(ErrorKind::TimedOut, "no queued read")))
        }

        fn close(&mut self) -> io::Result<()> {
            self.closed = true;
            Ok(())
        }
    }

    fn new_chipset(transport: DummyTransport) -> Chipset<DummyTransport> {
        Chipset {
            transport,
            firmware_version: (0, 0),
            read_buffer: VecDeque::new(),
            initiator_bitrate: None,
            noise_resistance_attempted: false,
            initiator_protocol: [None; INITIATOR_PROTOCOL_KEYS],
        }
    }

    /// Queues a bare success response for one command, as the reader sends it.
    fn ok_response(code: u8) -> Vec<u8> {
        Frame::build(&[0xD7, code + 1, 0x00]).as_bytes().to_vec()
    }

    /// Command payloads of every frame the chipset wrote.
    fn written_payloads(chipset: &Chipset<DummyTransport>) -> Vec<Vec<u8>> {
        chipset
            .transport
            .writes
            .iter()
            .filter_map(|bytes| Frame::parse(bytes).and_then(Frame::into_payload))
            .collect()
    }

    /// Queues an ACK followed by `count` command responses for `code`.
    fn queue_command_responses(code: u8, count: usize) -> Vec<io::Result<Vec<u8>>> {
        let mut reads = Vec::with_capacity(count * 2);
        for _ in 0..count {
            reads.push(Ok(frame::ACK_BYTES.to_vec()));
            reads.push(Ok(ok_response(code)));
        }
        reads
    }

    #[test]
    fn write_initiator_protocol_sends_only_what_changed() {
        let mut chipset = new_chipset(DummyTransport::with_reads(queue_command_responses(0x02, 2)));

        chipset
            .configure_initiator(&[("add_crc", 1), ("check_crc", 1)])
            .expect("first write should reach the reader");
        // Repeating the same values needs no command at all.
        chipset
            .configure_initiator(&[("add_crc", 1), ("check_crc", 1)])
            .expect("repeat should be skipped");
        // Only the key that actually changes is sent.
        chipset
            .configure_initiator(&[("add_crc", 1), ("check_crc", 0)])
            .expect("changed key should be written");

        let payloads = written_payloads(&chipset);
        assert_eq!(payloads.len(), 2, "expected two commands, got {payloads:?}");
        // Both keys are new, so both are written.
        assert_eq!(payloads[0], vec![0xD6, 0x02, 0x01, 0x01, 0x02, 0x01]);
        // Only check_crc changed, so add_crc is left out.
        assert_eq!(payloads[1], vec![0xD6, 0x02, 0x02, 0x00]);
    }

    #[test]
    fn set_initiator_rf_skips_a_repeated_bitrate_and_resets_the_protocol_cache() {
        // Type A and Type B avoid the FeliCa receive tuning, which would send
        // commands of its own.
        let mut reads = queue_command_responses(0x00, 1);
        reads.extend(queue_command_responses(0x02, 1));
        reads.extend(queue_command_responses(0x00, 1));
        reads.extend(queue_command_responses(0x02, 1));
        let mut chipset = new_chipset(DummyTransport::with_reads(reads));

        chipset
            .set_initiator_rf("106A", None)
            .expect("first RF setup should reach the reader");
        chipset
            .configure_initiator(&[("add_crc", 1)])
            .expect("protocol write should reach the reader");
        chipset
            .set_initiator_rf("106A", None)
            .expect("repeated RF setup should be skipped");
        assert_eq!(chipset.initiator_bitrate(), Some(("106A", "106A")));
        assert_eq!(chipset.transport.writes.len(), 2);

        // A different bitrate is written, and invalidates the protocol cache so
        // the settings that go with it are established again.
        chipset
            .set_initiator_rf("106B", None)
            .expect("new bitrate should reach the reader");
        chipset
            .configure_initiator(&[("add_crc", 1)])
            .expect("protocol write should be repeated after the RF change");
        assert_eq!(chipset.transport.writes.len(), 4);
    }

    #[test]
    fn update_rct_setting_replaces_appends_and_reports_no_change() {
        // A register already carrying the value needs no write.
        let mut settings = vec![0x1A, 0xC0, 0x40];
        assert!(!update_rct_setting(&mut settings, [0x1A, 0xC0, 0x40]));
        assert_eq!(settings, vec![0x1A, 0xC0, 0x40]);

        // A register listed with another value is replaced in place.
        let mut settings = vec![0x01, 0x02, 0x03, 0x1A, 0xC0, 0x00];
        assert!(update_rct_setting(&mut settings, [0x1A, 0xC0, 0x40]));
        assert_eq!(settings, vec![0x01, 0x02, 0x03, 0x1A, 0xC0, 0x40]);

        // A register not listed yet is appended.
        let mut settings = vec![0x01, 0x02, 0x03];
        assert!(update_rct_setting(&mut settings, [0x1A, 0xC0, 0x40]));
        assert_eq!(settings, vec![0x01, 0x02, 0x03, 0x1A, 0xC0, 0x40]);

        // A full block cannot take another register.
        let mut settings = vec![0u8; IN_SET_RCT_SETTING_NUM_MAX * 3];
        assert!(!update_rct_setting(&mut settings, [0x1A, 0xC0, 0x40]));
        assert_eq!(settings.len(), IN_SET_RCT_SETTING_NUM_MAX * 3);
    }

    #[test]
    fn take_rct_block_reads_length_prefixed_settings() {
        let body = [
            0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x1A, 0xC0, 0x40,
        ];
        let send = take_rct_block(&body, 0).expect("send block should parse");
        assert_eq!(send, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let receive = take_rct_block(&body, 1 + send.len()).expect("receive block should parse");
        assert_eq!(receive, vec![0x1A, 0xC0, 0x40]);

        assert!(take_rct_block(&body, body.len()).is_err());
        assert!(take_rct_block(&[0x05, 0x00], 0).is_err());
    }

    #[test]
    fn lt_info_table_rows_are_well_formed() {
        // Every row is two property bytes, two version bytes and a 16 byte key.
        for entry in LT_INFO_TABLE {
            assert_eq!(entry.len(), 4 + LT_INFO_LEN);
        }
    }

    #[test]
    fn build_command_payload_adds_prefix_and_code() {
        let payload = Chipset::<DummyTransport>::build_command_payload(0x20, &[0xAA, 0xBB]);
        assert_eq!(payload, vec![0xD6, 0x20, 0xAA, 0xBB]);
    }

    #[test]
    fn extract_response_payload_validates_frame_type_and_response_code() {
        let frame = Frame::build(&[0xD7, 0x21, 0x10, 0x20]);
        let payload = Chipset::<DummyTransport>::extract_response_payload(frame, 0x20).unwrap();
        assert_eq!(payload, vec![0x10, 0x20]);

        let wrong_code = Frame::build(&[0xD7, 0x22, 0x10, 0x20]);
        match Chipset::<DummyTransport>::extract_response_payload(wrong_code, 0x20) {
            Err(DriverError::Other(message)) => assert!(message.contains("unexpected response")),
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(_) => panic!("expected error for wrong response code"),
        }

        let ack_frame = Frame::parse(&frame::ACK_BYTES).expect("ACK frame should parse");
        match Chipset::<DummyTransport>::extract_response_payload(ack_frame, 0x20) {
            Err(DriverError::Other(message)) => assert!(message.contains("unexpected frame type")),
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(_) => panic!("expected error for ACK frame"),
        }
    }

    #[test]
    fn protocol_param_index_helpers_map_known_keys() {
        assert_eq!(initiator_param_index("guard_time"), Some(19));
        assert_eq!(initiator_param_index("unknown"), None);
        assert_eq!(target_param_index("rf_off_error"), Some(1));
        assert_eq!(target_param_index("unknown"), None);
    }

    #[test]
    fn read_exact_uses_buffer_and_transport_reads() {
        let transport = DummyTransport::with_reads(vec![Ok(vec![1, 2]), Ok(vec![3, 4, 5])]);
        let mut chipset = new_chipset(transport);
        let deadline = Instant::now() + Duration::from_millis(50);

        let out = chipset
            .read_exact(4, deadline)
            .expect("read_exact should succeed");
        assert_eq!(out, vec![1, 2, 3, 4]);
        assert_eq!(chipset.read_buffer, VecDeque::from(vec![5]));
    }

    #[test]
    fn read_exact_times_out_when_deadline_already_elapsed() {
        let mut chipset = new_chipset(DummyTransport::default());
        let deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("checked_sub should return Some");
        match chipset.read_exact(1, deadline) {
            Err(DriverError::Io(err)) => assert_eq!(err.kind(), ErrorKind::TimedOut),
            Err(other) => panic!("expected timeout io error, got {other}"),
            Ok(_) => panic!("expected read_exact timeout"),
        }
    }

    #[test]
    fn read_frame_bytes_handles_extended_and_rejects_bad_preamble() {
        let payload = vec![0xD7, 0x21, 0xAA, 0xBB];
        let frame_bytes = Frame::build(&payload).as_bytes().to_vec();
        let mut chipset = new_chipset(DummyTransport::default());
        chipset.read_buffer = frame_bytes.iter().copied().collect();
        let deadline = Instant::now() + Duration::from_millis(20);
        let parsed = chipset
            .read_frame_bytes(deadline)
            .expect("extended frame should parse");
        assert_eq!(parsed, frame_bytes);

        let mut bad = new_chipset(DummyTransport::default());
        bad.read_buffer = VecDeque::from(vec![0x12, 0x00, 0xFF, 0x01, 0xFF]);
        let deadline = Instant::now() + Duration::from_millis(20);
        match bad.read_frame_bytes(deadline) {
            Err(DriverError::Other(message)) => assert!(message.contains("invalid frame preamble")),
            Err(other) => panic!("expected DriverError::Other, got {other}"),
            Ok(_) => panic!("expected preamble validation failure"),
        }
    }
}
