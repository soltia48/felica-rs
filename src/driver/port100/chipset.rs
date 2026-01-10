use crate::driver::errors::{CommunicationFault, DriverError, Result, ensure_status_ok};
use crate::driver::port100::frame::{self, Frame, FrameType};
use crate::transport::Transport;
use log::{debug, warn};
use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::time::{Duration, Instant};

const IN_SET_PROTOCOL_DEFAULTS: [u8; 38] = [
    0x00, 0x18, 0x01, 0x01, 0x02, 0x01, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x08,
    0x08, 0x00, 0x09, 0x00, 0x0A, 0x00, 0x0B, 0x00, 0x0C, 0x00, 0x0E, 0x04, 0x0F, 0x00, 0x10, 0x00,
    0x11, 0x00, 0x12, 0x00, 0x13, 0x06,
];

const TG_SET_PROTOCOL_DEFAULTS: [u8; 6] = [0x00, 0x01, 0x01, 0x01, 0x02, 0x07];

pub struct Chipset<T: Transport> {
    pub(crate) transport: T,
    firmware_version: (u8, u8),
    read_buffer: VecDeque<u8>,
}

impl<T: Transport> Chipset<T> {
    pub const ACK: [u8; 6] = frame::ACK_BYTES;
    const ACK_TIMEOUT: Duration = Duration::from_millis(1_000);
    const RESPONSE_TIMEOUT: Duration = Duration::from_millis(1_500);
    const BUFFER_CLEAR_TIMEOUT: Duration = Duration::from_millis(50);

    pub fn new(mut transport: T) -> Result<Self> {
        transport.write(&Self::ACK)?;
        while let Ok(data) = transport.read(Duration::from_millis(10)) {
            debug!("cleared garbage {:x?}", data);
        }

        let mut chipset = Self {
            transport,
            firmware_version: (0, 0),
            read_buffer: VecDeque::new(),
        };
        match chipset.set_command_type(1) {
            Ok(()) => {}
            Err(DriverError::Status(_)) => {
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
        ensure_status_ok(rsp.first().copied())
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
        ensure_status_ok(rsp.first().copied())
    }

    pub fn apply_initiator_defaults(&mut self) -> Result<()> {
        self.in_set_protocol(Some(&IN_SET_PROTOCOL_DEFAULTS), &[])
    }

    pub fn configure_initiator(&mut self, params: &[(&str, u8)]) -> Result<()> {
        self.in_set_protocol(None, params)
    }

    fn in_set_protocol(&mut self, data: Option<&[u8]>, params: &[(&str, u8)]) -> Result<()> {
        self.configure_protocol(
            0x02,
            data,
            params,
            initiator_param_index,
            "initiator protocol key",
        )
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

    pub fn set_initiator_rf(&mut self, brty_send: &str, brty_recv: Option<&str>) -> Result<()> {
        fn settings(brty: &str) -> Option<(u8, u8, u8, u8)> {
            match brty {
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

        let recv = brty_recv.unwrap_or(brty_send);
        let send_cfg = settings(brty_send)
            .ok_or_else(|| DriverError::Other(format!("unsupported bitrate {}", brty_send)))?;
        let recv_cfg = settings(recv)
            .ok_or_else(|| DriverError::Other(format!("unsupported bitrate {}", recv)))?;

        let params = vec![send_cfg.0, send_cfg.1, recv_cfg.2, recv_cfg.3];
        let rsp = self.send_command(0x00, &params)?;
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
            return Err(DriverError::Fault(fault));
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
        ensure_status_ok(rsp.first().copied())
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
            return Err(DriverError::Fault(fault));
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
            self.take_from_buffer(&mut out, len);
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

    fn recover_after_error(&mut self, drain_buffer: bool) {
        if let Err(err) = self.transport.write(&Self::ACK) {
            warn!("failed to send recovery ACK: {}", err);
        }
        if drain_buffer {
            self.drain_input(Self::BUFFER_CLEAR_TIMEOUT);
        }
        self.read_buffer.clear();
    }

    fn drain_input(&mut self, timeout: Duration) {
        self.read_buffer.clear();
        let deadline = Instant::now() + timeout;
        loop {
            let Some(remaining) = remaining_until(deadline) else {
                break;
            };
            match self.transport.read(remaining) {
                Ok(bytes) => {
                    if bytes.is_empty() {
                        break;
                    }
                }
                Err(err) => {
                    if err.kind() == ErrorKind::TimedOut {
                        break;
                    }
                }
            }
        }
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

    fn take_from_buffer(&mut self, out: &mut Vec<u8>, len: usize) {
        while out.len() < len {
            if let Some(byte) = self.read_buffer.pop_front() {
                out.push(byte);
            } else {
                break;
            }
        }
    }

    fn with_recovery<R>(
        &mut self,
        drain_buffer: bool,
        action: impl FnOnce(&mut Self) -> Result<R>,
    ) -> Result<R> {
        match action(self) {
            Ok(value) => Ok(value),
            Err(err) => {
                self.recover_after_error(drain_buffer);
                Err(err)
            }
        }
    }
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

fn remaining_until(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| d.as_nanos() != 0)
}

fn timeout_error() -> io::Error {
    io::Error::new(ErrorKind::TimedOut, "timeout while waiting for data")
}
