use super::pcsc::{Pcsc, TransmissionFlags};
use crate::clf::errors::UnsupportedTargetError;
use crate::clf::targets::RemoteTarget;
use crate::driver::errors::{DriverError, Result};
use crate::felica_standard::{
    FelicaDriver, FelicaStandardCommand, FelicaStandardResponse, Type3TagPollingResult,
};
use crate::transport::Transport;
use crate::transport::usb::UsbTransport;
use log::debug;
use std::io::{self, ErrorKind};
use std::time::Duration;

const SONY_VID: u16 = 0x054C;
const PORT400_PIDS: &[u16] = &[0x0DC8, 0x0DC9, 0x0D8F];
const MAX_THROUGH_PAYLOAD: usize = 290;

pub struct Device<T: Transport> {
    pcsc: Pcsc<T>,
    chipset_name: String,
    vendor_name: Option<String>,
    product_name: Option<String>,
}

pub fn init<T: Transport>(transport: T) -> Result<Device<T>> {
    Device::new(transport)
}

pub fn open_port400_device() -> Result<Device<UsbTransport>> {
    let mut last_error: Option<io::Error> = None;
    for &pid in PORT400_PIDS {
        match UsbTransport::open(SONY_VID, pid) {
            Ok(transport) => return Device::new(transport),
            Err(err) => last_error = Some(err),
        }
    }
    Err(DriverError::Io(last_error.unwrap_or_else(|| {
        io::Error::new(ErrorKind::NotFound, "NFC Port-400 reader not found")
    })))
}

impl<T: Transport> Device<T> {
    pub fn new(transport: T) -> Result<Self> {
        let vendor_name = transport.manufacturer_name().map(|s| s.to_string());
        let product_name = transport.product_name().map(|s| s.to_string());
        let mut pcsc = Pcsc::new(transport);
        pcsc.set_receive_timeout(Duration::from_millis(1_500));
        pcsc.start_transparent_session(false)?;
        pcsc.switch_protocol_type_f(false)?;
        let firmware = pcsc
            .get_firmware_version()
            .ok()
            .and_then(|bytes| format_firmware(&bytes));
        if let Ok(Some(rate)) = pcsc.card_baudrate() {
            debug!("Port-400 target baud rate {} kbps", rate);
        }
        let chipset_name = firmware
            .map(|fw| format!("NFC Port-400 {fw}"))
            .unwrap_or_else(|| "NFC Port-400".to_string());
        Ok(Self {
            pcsc,
            chipset_name,
            vendor_name,
            product_name,
        })
    }

    pub fn vendor_name(&self) -> Option<&str> {
        self.vendor_name.as_deref()
    }

    pub fn product_name(&self) -> Option<&str> {
        self.product_name.as_deref()
    }

    pub fn chipset_name(&self) -> &str {
        &self.chipset_name
    }

    pub fn close(&mut self) -> Result<()> {
        let _ = self.pcsc.end_transparent_session();
        self.pcsc.close()
    }

    pub fn mute(&mut self) -> Result<()> {
        self.pcsc.turn_off_rf()
    }

    pub fn get_max_send_data_size(&self, _target: &RemoteTarget) -> usize {
        MAX_THROUGH_PAYLOAD
    }

    pub fn get_max_recv_data_size(&self, _target: &RemoteTarget) -> usize {
        MAX_THROUGH_PAYLOAD
    }

    pub fn sense_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<Type3TagPollingResult> {
        let brty = target.brty();
        if brty != "212F" && brty != "424F" {
            return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                format!("unsupported bitrate {brty}"),
            )));
        }
        debug!("polling for NFC-F using Port-400");
        let command = FelicaStandardCommand::Polling {
            system_code,
            request_code,
            time_slots,
        };
        let frame = command.to_frame();
        let timeout_ms = ((0.003625_f32 + time_slots as f32 * 0.001208_f32) * 1000.0).ceil() as u64;
        let flags = TransmissionFlags::felica();
        let response = self
            .pcsc
            .transceive(&frame, Duration::from_millis(timeout_ms), &flags)?;
        match FelicaStandardResponse::from_bytes(&response) {
            Ok(FelicaStandardResponse::Polling { idm, pmm, optional }) => {
                Ok(Type3TagPollingResult { idm, pmm, optional })
            }
            Ok(other) => Err(DriverError::Other(format!(
                "unexpected Felica response: {other:?}"
            ))),
            Err(err) => Err(DriverError::Other(format!(
                "failed to parse Felica response: {err}"
            ))),
        }
    }

    pub fn send_command_receive_response(
        &mut self,
        _target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>> {
        let timeout = timeout_ms
            .map(|ms| Duration::from_millis(ms as u64))
            .unwrap_or_else(|| Duration::from_millis(0));
        let flags = TransmissionFlags::felica();
        self.pcsc.transceive(data, timeout, &flags)
    }
}

impl<T: Transport> FelicaDriver for Device<T> {
    fn sense_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<Type3TagPollingResult> {
        self.sense_type_f(target, system_code, request_code, time_slots)
    }

    fn send_command_receive_response(
        &mut self,
        target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>> {
        self.send_command_receive_response(target, data, timeout_ms)
    }
}

fn format_firmware(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 {
        return None;
    }
    Some(format!(
        "v{:02X}.{:02X}.{:02X}.{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    ))
}
