use super::chipset::Chipset;
use super::errors::{DriverError, Result, convert_fault_to_comm_error};
use crate::clf::crc;
use crate::clf::errors::CommunicationError;
use crate::clf::targets::RemoteTarget;
use crate::felica_standard::{FelicaDriver, Type3TagPollingResult};
use crate::transport::Transport;
use crate::transport::usb::UsbTransport;
use smallvec::SmallVec;
use std::io::{self, ErrorKind};

pub struct Device<T: Transport> {
    pub(super) chipset: Chipset<T>,
    vendor_name: Option<String>,
    product_name: Option<String>,
    chipset_name: String,
}

pub fn init<T: Transport>(transport: T) -> Result<Device<T>> {
    let chipset = Chipset::new(transport)?;
    Device::new(chipset)
}

pub fn open_port100_device() -> Result<Device<UsbTransport>> {
    const SONY_VID: u16 = 0x054C;
    const PRODUCT_IDS: [u16; 2] = [0x06C1, 0x06C3];

    let mut last_error: Option<io::Error> = None;
    for pid in PRODUCT_IDS {
        match UsbTransport::open(SONY_VID, pid) {
            Ok(transport) => return init(transport),
            Err(err) => last_error = Some(err),
        }
    }

    Err(DriverError::Io(last_error.unwrap_or_else(|| {
        io::Error::new(ErrorKind::NotFound, "RC-S380 reader not found")
    })))
}

impl<T: Transport> Device<T> {
    pub fn new(chipset: Chipset<T>) -> Result<Self> {
        let version = chipset.firmware_version();
        let chipset_name = format!("NFC Port-100 v{:x}.{:02x}", version.1, version.0);
        let vendor_name = chipset.manufacturer_name().map(|s| s.to_string());
        let product_name = chipset.product_name().map(|s| s.to_string());
        Ok(Self {
            vendor_name,
            product_name,
            chipset,
            chipset_name,
        })
    }

    pub fn chipset(&mut self) -> &mut Chipset<T> {
        &mut self.chipset
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
        self.chipset.close()
    }

    pub fn mute(&mut self) -> Result<()> {
        self.chipset.switch_rf(false)
    }

    pub fn get_max_send_data_size(&self, _target: &RemoteTarget) -> usize {
        290
    }

    pub fn get_max_recv_data_size(&self, _target: &RemoteTarget) -> usize {
        290
    }

    pub fn transceive(
        &mut self,
        target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>> {
        let timeout_ms = timeout_ms.unwrap_or(0);
        let profile = self.prepare_initiator_exchange(target)?;
        self.perform_initiator_exchange(data, timeout_ms, &profile)
    }

    pub fn send_response_receive_command(
        &mut self,
        data: &[u8],
        timeout_ms: u16,
    ) -> Result<Option<Vec<u8>>> {
        let result = self.chipset.target_exchange_rf(
            500,
            0xFFFF,
            false,
            &[],
            &[],
            false,
            false,
            timeout_ms,
            Some(data),
        );
        match result {
            Ok(payload) => {
                if payload.len() > 7 {
                    Ok(Some(payload[7..].to_vec()))
                } else {
                    Ok(None)
                }
            }
            Err(DriverError::Fault(fault)) => Err(convert_fault_to_comm_error(fault, true)),
            Err(err) => Err(err),
        }
    }

    fn prepare_initiator_exchange(
        &mut self,
        target: &RemoteTarget,
    ) -> Result<InitiatorExchangeProfile> {
        self.chipset
            .set_initiator_rf(target.brty_send(), Some(target.brty_recv()))?;
        self.chipset.apply_initiator_defaults()?;
        let profile = InitiatorExchangeProfile::for_target(target);
        profile.apply_to(&mut self.chipset)?;
        Ok(profile)
    }

    fn perform_initiator_exchange(
        &mut self,
        data: &[u8],
        timeout: u16,
        profile: &InitiatorExchangeProfile,
    ) -> Result<Vec<u8>> {
        if profile.strip_crc() {
            self.transceive_type2_with_crc(data, timeout)
        } else {
            self.exchange_as_initiator(data, timeout)
        }
    }

    fn exchange_as_initiator(&mut self, data: &[u8], timeout: u16) -> Result<Vec<u8>> {
        match self.chipset.initiator_exchange_rf(data, timeout) {
            Ok(response) => Ok(response),
            Err(DriverError::Fault(fault)) => Err(convert_fault_to_comm_error(fault, false)),
            Err(err) => Err(err),
        }
    }

    fn transceive_type2_with_crc(&mut self, data: &[u8], timeout: u16) -> Result<Vec<u8>> {
        let mut response = self.exchange_as_initiator(data, timeout)?;
        if response.len() > 2 && !crc::check_crc_a(&response) {
            return Err(DriverError::Communication(
                CommunicationError::transmission("crc_a check error"),
            ));
        }
        if response.len() > 2 {
            response.truncate(response.len() - 2);
        }
        Ok(response)
    }
}

impl<T: Transport> FelicaDriver for Device<T> {
    fn detect_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<Type3TagPollingResult> {
        self.detect_type_f(target, system_code, request_code, time_slots)
    }

    fn transceive(
        &mut self,
        target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>> {
        self.transceive(target, data, timeout_ms)
    }
}

type ProtocolParamList = SmallVec<[(&'static str, u8); 8]>;

struct InitiatorExchangeProfile {
    params: ProtocolParamList,
    strip_crc_a: bool,
}

impl InitiatorExchangeProfile {
    fn for_target(target: &RemoteTarget) -> Self {
        let mut params = initiator_params_for_brty(target.brty_send());
        let strip_crc_a = is_type2_target(target);
        if strip_crc_a {
            params.push(("check_crc", 0));
        }
        Self {
            params,
            strip_crc_a,
        }
    }

    fn params(&self) -> &[(&'static str, u8)] {
        &self.params
    }

    fn strip_crc(&self) -> bool {
        self.strip_crc_a
    }

    fn apply_to<TTransport: Transport>(&self, chipset: &mut Chipset<TTransport>) -> Result<()> {
        if self.params.is_empty() {
            Ok(())
        } else {
            chipset.configure_initiator(self.params())
        }
    }
}

fn initiator_params_for_brty(brty: &str) -> ProtocolParamList {
    let mut params = ProtocolParamList::new();
    if brty.ends_with('A') {
        params.push(("add_parity", 1));
        params.push(("check_parity", 1));
    }
    if brty.ends_with('B') {
        params.push(("initial_guard_time", 20));
        params.push(("add_sof", 1));
        params.push(("check_sof", 1));
        params.push(("add_eof", 1));
        params.push(("check_eof", 1));
    }
    params
}

fn is_type2_target(target: &RemoteTarget) -> bool {
    target.brty() == "106A"
        && target
            .data
            .sel_res
            .as_ref()
            .and_then(|bytes| bytes.first())
            .map(|b| b & 0x60 == 0x00)
            .unwrap_or(false)
}
