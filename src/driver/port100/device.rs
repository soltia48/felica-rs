use crate::clf::crc;
use crate::clf::errors::CommunicationError;
use crate::clf::targets::RemoteTarget;
use crate::driver::common::{self, DeviceInfo, DeviceMetadata, impl_reader_device, is_type2_106a};
use crate::driver::errors::{ChipsetError, DriverError, Result};
use crate::driver::port100::chipset::Chipset;
use crate::transport::Transport;
use crate::transport::usb::UsbTransport;
use hex::encode;
use log::debug;
use smallvec::SmallVec;

pub struct Device<T: Transport> {
    pub(crate) chipset: Chipset<T>,
    meta: DeviceMetadata,
}

pub fn init<T: Transport>(transport: T) -> Result<Device<T>> {
    let chipset = Chipset::new(transport)?;
    Device::new(chipset)
}

pub fn open_port100() -> Result<Device<UsbTransport>> {
    const PRODUCT_IDS: [u16; 2] = [0x06C1, 0x06C3];
    common::open_usb_device(
        common::SONY_VENDOR_ID,
        &PRODUCT_IDS,
        "RC-S380 reader not found",
        init,
    )
}

impl<T: Transport> Device<T> {
    pub fn new(chipset: Chipset<T>) -> Result<Self> {
        let version = chipset.firmware_version();
        let meta = DeviceMetadata {
            vendor_name: chipset.manufacturer_name().map(|s| s.to_string()),
            product_name: chipset.product_name().map(|s| s.to_string()),
            chipset_name: format!("NFC Port-100 v{:x}.{:02x}", version.1, version.0),
        };
        Ok(Self { chipset, meta })
    }

    pub fn chipset(&mut self) -> &mut Chipset<T> {
        &mut self.chipset
    }

    pub fn close(&mut self) -> Result<()> {
        self.chipset.close()
    }

    pub fn mute(&mut self) -> Result<()> {
        self.chipset.switch_rf(false)
    }

    /// Bitrates the reader's RF is configured for, send first, or `None` before
    /// the first detection.
    ///
    /// Unlike the Port-400, the Port-100 has no query for the speed a card was
    /// activated at: the host sets the RF itself and the card either answers at
    /// that speed or is not found, so this is the speed of the current link.
    pub fn initiator_bitrate(&self) -> Option<(&str, &str)> {
        self.chipset.initiator_bitrate()
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
        debug!(
            "Port-100 transceive TX ({}): {}",
            target.bitrate(),
            encode(data)
        );
        let timeout_ms = timeout_ms.unwrap_or(0);
        let profile = self.prepare_initiator_exchange(target)?;
        let response = self.perform_initiator_exchange(data, timeout_ms, &profile)?;
        debug!(
            "Port-100 transceive RX ({}): {}",
            target.bitrate(),
            encode(&response)
        );
        Ok(response)
    }

    pub fn send_response_receive_command(
        &mut self,
        data: &[u8],
        timeout_ms: u16,
    ) -> Result<Option<Vec<u8>>> {
        debug!("Port-100 target TX: {}", encode(data));
        let payload = Self::map_fault(
            self.chipset.target_exchange_rf(
                500,
                0xFFFF,
                false,
                &[],
                &[],
                false,
                false,
                timeout_ms,
                Some(data),
            ),
            true,
        )?;
        let response = payload.get(7..).map(|bytes| bytes.to_vec());
        if let Some(bytes) = response.as_ref() {
            debug!("Port-100 target RX: {}", encode(bytes));
        }
        Ok(response)
    }

    fn prepare_initiator_exchange(
        &mut self,
        target: &RemoteTarget,
    ) -> Result<InitiatorExchangeProfile> {
        self.chipset
            .set_initiator_rf(target.bitrate_send(), Some(target.bitrate_recv()))?;
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
        Self::map_fault(self.chipset.initiator_exchange_rf(data, timeout), false)
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

impl<T: Transport> DeviceInfo for Device<T> {
    fn metadata(&self) -> &DeviceMetadata {
        &self.meta
    }
}

impl_reader_device!(Device);

type ProtocolParamList = SmallVec<[(&'static str, u8); 8]>;

struct InitiatorExchangeProfile {
    params: ProtocolParamList,
    strip_crc_a: bool,
}

impl InitiatorExchangeProfile {
    fn for_target(target: &RemoteTarget) -> Self {
        let mut params = initiator_params_for_bitrate(target.bitrate_send());
        let strip_crc_a = is_type2_106a(target);
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

fn initiator_params_for_bitrate(bitrate: &str) -> ProtocolParamList {
    let mut params = ProtocolParamList::new();
    if bitrate.ends_with('A') {
        params.push(("add_parity", 1));
        params.push(("check_parity", 1));
    }
    if bitrate.ends_with('B') {
        params.push(("initial_guard_time", 20));
        params.push(("add_sof", 1));
        params.push(("check_sof", 1));
        params.push(("add_eof", 1));
        params.push(("check_eof", 1));
    }
    params
}

impl<T: Transport> Device<T> {
    fn map_fault<U>(
        result: std::result::Result<U, DriverError>,
        treat_rf_off_as_broken: bool,
    ) -> Result<U> {
        result.map_err(|error| match error {
            DriverError::Chipset(ChipsetError::Fault(fault)) => {
                fault.to_driver_error(treat_rf_off_as_broken)
            }
            other => other,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::errors::CommunicationFault;
    use std::time::Duration;

    struct DummyTransport;

    impl Transport for DummyTransport {
        fn write(&mut self, _data: &[u8]) -> std::io::Result<()> {
            Ok(())
        }

        fn read(&mut self, _timeout: Duration) -> std::io::Result<Vec<u8>> {
            Ok(Vec::new())
        }

        fn close(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn make_target(bitrate: &str, sel_res: Option<Vec<u8>>) -> RemoteTarget {
        let mut target = RemoteTarget::new(bitrate).expect("target should be created");
        target.data.sel_res = sel_res;
        target
    }

    #[test]
    fn initiator_params_for_bitrate_matches_expected_protocol_defaults() {
        assert_eq!(
            initiator_params_for_bitrate("106A").as_slice(),
            &[("add_parity", 1), ("check_parity", 1)]
        );
        assert_eq!(
            initiator_params_for_bitrate("106B").as_slice(),
            &[
                ("initial_guard_time", 20),
                ("add_sof", 1),
                ("check_sof", 1),
                ("add_eof", 1),
                ("check_eof", 1),
            ]
        );
        assert!(initiator_params_for_bitrate("424F").is_empty());
    }

    #[test]
    fn initiator_exchange_profile_enables_crc_stripping_for_type2_target() {
        let type2 = make_target("106A", Some(vec![0x00]));
        let profile = InitiatorExchangeProfile::for_target(&type2);
        assert!(profile.strip_crc());
        assert!(profile.params().contains(&("add_parity", 1)));
        assert!(profile.params().contains(&("check_parity", 1)));
        assert!(profile.params().contains(&("check_crc", 0)));

        let non_type2 = make_target("106A", Some(vec![0x20]));
        let profile = InitiatorExchangeProfile::for_target(&non_type2);
        assert!(!profile.strip_crc());
        assert!(!profile.params().contains(&("check_crc", 0)));
    }

    #[test]
    fn map_fault_converts_faults_and_preserves_non_fault_errors() {
        let ok: Result<u8> = Device::<DummyTransport>::map_fault(Ok(7), false);
        assert_eq!(ok.expect("ok should pass through"), 7);

        match Device::<DummyTransport>::map_fault::<()>(
            Err(DriverError::Chipset(ChipsetError::Fault(
                CommunicationFault::new(0x00000080),
            ))),
            false,
        ) {
            Err(DriverError::Communication(CommunicationError::Timeout(message))) => {
                assert!(message.contains("RECEIVE_TIMEOUT_ERROR"));
            }
            other => panic!("expected timeout communication error, got {other:?}"),
        }

        match Device::<DummyTransport>::map_fault::<()>(
            Err(DriverError::Chipset(ChipsetError::Fault(
                CommunicationFault::new(0x00000400),
            ))),
            true,
        ) {
            Err(DriverError::Communication(CommunicationError::BrokenLink(message))) => {
                assert!(message.contains("RF_OFF_ERROR"));
            }
            other => panic!("expected broken-link communication error, got {other:?}"),
        }

        match Device::<DummyTransport>::map_fault::<()>(
            Err(DriverError::Chipset(ChipsetError::Fault(
                CommunicationFault::new(0x00000400),
            ))),
            false,
        ) {
            Err(DriverError::Communication(CommunicationError::Transmission(message))) => {
                assert!(message.contains("RF_OFF_ERROR"));
            }
            other => panic!("expected transmission communication error, got {other:?}"),
        }

        match Device::<DummyTransport>::map_fault::<()>(Err(DriverError::other("x")), false) {
            Err(DriverError::Other(message)) => assert_eq!(message, "x"),
            other => panic!("expected DriverError::Other, got {other:?}"),
        }
    }
}
