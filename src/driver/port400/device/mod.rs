mod activation;
mod iso_dep;

use crate::clf::errors::UnsupportedTargetError;
use crate::clf::targets::RemoteTarget;
use crate::driver::common::{self, DeviceInfo, DeviceMetadata, impl_reader_device};
use crate::driver::errors::{DriverError, Result};
use crate::driver::port400::iso14443::{IsoDepConfig, IsoDepSession};
use crate::driver::port400::pcsc::{Pcsc, TransmissionFlags, TypeBInfo};
use crate::felica_standard::{
    FelicaStandardCommand, FelicaStandardResponse, Type3TagPollingResult, polling_timeout_ms,
};
use crate::transport::Transport;
use crate::transport::usb::UsbTransport;
use hex::encode;
use log::{debug, warn};
use std::time::Duration;

const PORT400_PIDS: &[u16] = &[0x0DC8, 0x0DC9, 0x0D8F];
const MAX_THROUGH_PAYLOAD: usize = 290;
const DEFAULT_THROUGH_TIMEOUT_MS: u16 = 400;
const TYPE_A_CMD_TIMEOUT_MS: u16 = 30;
const TYPE_B_CMD_TIMEOUT_MS: u16 = 30;
/// Offsets into the Get Firmware Version response that report whether the
/// reader booted into firmware update mode.
const FW_VER_UPDATE_STATE: std::ops::Range<usize> = 14..16;
const PROPERTY_HARDWARE_VERSION: u8 = 1;
const PROPERTY_MODEL_ID: u8 = 2;
const PROPERTY_SERIAL_NO: u8 = 3;
const PROPERTY_GROUP_NO: u8 = 8;
const RFFE_PARAM_EEPROM: u8 = 0x01;
const RFFE_PARAM_PD_SC_DPC: u8 = 0x02;
const RFFE_PARAM_PROTOCOL_CONFIGURATION: u8 = 0x03;
const DIAG_COMMUNICATION_LINE_SIZE_MAX: usize = 500;
const DIAG_POLLING_COUNT_MIN: u8 = 1;
/// Polling request codes (SENSF_REQ RC).
const FELICA_POLLING_OPTION_NONE: u8 = 0;
const FELICA_POLLING_OPTION_REQ_BAUDRATE: u8 = 2;
/// Protocol slots the reader keeps a frontend RF speed for: Type A, Type B and
/// Type F, in that order.
const RF_SPEED_PROTOCOLS: usize = 3;
/// Protocol slot of the Type-F frontend.
const RF_SPEED_PROTOCOL_TYPE_F: u8 = 2;
/// RF speed code for 424 kbps, in the same encoding Get Data reports for the
/// activated card.
const RF_SPEED_CODE_424K: u8 = 3;
/// Speeds the reference library pins each protocol to while it runs without
/// automatic baud rate selection: 106 kbps for Type A and Type B, 212 kbps for
/// Type F.
const RF_SPEED_FIXED_VALUE: [[u8; 2]; RF_SPEED_PROTOCOLS] = [[1, 1], [1, 1], [2, 2]];
/// Byte of the group number property that reports where the reader is fitted.
const GROUP_NO_DEVICE_TYPE_OFFSET: usize = 4;
/// Interval at which the reference library repeats its keep-alive command while
/// a session is open; see [`Device::keep_alive`].
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(2);
/// MIFARE Classic key length.
pub const MIFARE_KEY_LEN: usize = 6;
const MIFARE_KEY_TYPE_A: u8 = 0x60;
const MIFARE_KEY_TYPE_B: u8 = 0x61;

pub struct Device<T: Transport> {
    pcsc: Pcsc<T>,
    meta: DeviceMetadata,
    iso_dep_session: Option<IsoDepSession>,
    iso_dep_protocol: Option<ThroughProtocol>,
    /// Whether the reader is running the firmware update boot loader.
    update_mode: bool,
    /// Whether a transparent session is currently open.
    session_open: bool,
    /// Per protocol RF speed found in the reader before the driver changed it,
    /// so [`Device::close`] can put it back.
    original_rf_speed: [Option<[u8; 2]>; RF_SPEED_PROTOCOLS],
    /// Speed code the Type-F frontend is known to be set to in both directions,
    /// so a detection does not rewrite a setting that already fits.
    type_f_rf_speed: Option<u8>,
    /// Where the reader reports it is fitted.
    device_type: DeviceType,
    /// Serial number string the reader reports.
    serial_number: Option<String>,
    /// Firmware version the reader reports.
    firmware_version: Option<String>,
}

/// Where a reader is fitted, as its group number property reports it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeviceType {
    /// Built into a host machine.
    Internal,
    /// Attached externally.
    External,
    /// The reader did not report a value this driver knows.
    #[default]
    Unknown,
}

/// Which of a MIFARE Classic sector's two keys to authenticate with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MifareKeyType {
    A,
    B,
}

impl MifareKeyType {
    fn code(self) -> u8 {
        match self {
            MifareKeyType::A => MIFARE_KEY_TYPE_A,
            MifareKeyType::B => MIFARE_KEY_TYPE_B,
        }
    }
}

/// Parameters of a MIFARE Classic authentication.
#[derive(Clone, Debug)]
pub struct MifareAuthentication {
    pub key: [u8; MIFARE_KEY_LEN],
    pub key_type: MifareKeyType,
    pub block_number: u8,
    /// UID of the card to authenticate against. The Port-400 uses the card it
    /// activated rather than this value, but the reference library requires
    /// callers to supply it and other readers do transmit it.
    pub uid: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ThroughProtocol {
    #[default]
    Felica,
    Iso14443TypeA,
    Iso14443TypeB,
    Iso15693,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ThroughOptions {
    pub protocol: ThroughProtocol,
    pub append_crc: Option<bool>,
    pub discard_crc: Option<bool>,
    pub insert_parity: Option<bool>,
    pub expect_parity: Option<bool>,
    pub append_protocol_prologue: Option<bool>,
    pub tx_valid_bits: Option<u8>,
}

impl ThroughProtocol {
    fn transmission_flags(self) -> TransmissionFlags {
        match self {
            ThroughProtocol::Felica => TransmissionFlags::felica(),
            ThroughProtocol::Iso14443TypeA => TransmissionFlags::iso14443_type_a(),
            ThroughProtocol::Iso14443TypeB => TransmissionFlags::iso14443_type_b(),
            ThroughProtocol::Iso15693 => TransmissionFlags::iso15693(),
        }
    }

    fn iso_dep_flags(self) -> TransmissionFlags {
        match self {
            ThroughProtocol::Iso14443TypeB => TransmissionFlags::iso14443_type_b(),
            _ => TransmissionFlags::iso14443_type_a(),
        }
    }
}

impl ThroughOptions {
    fn flags(&self) -> TransmissionFlags {
        let mut flags = self.protocol.transmission_flags();
        if let Some(value) = self.append_crc {
            flags.append_crc = value;
        }
        if let Some(value) = self.discard_crc {
            flags.discard_crc = value;
        }
        if let Some(value) = self.insert_parity {
            flags.insert_parity = value;
        }
        if let Some(value) = self.expect_parity {
            flags.expect_parity = value;
        }
        if let Some(value) = self.append_protocol_prologue {
            flags.append_protocol_prologue = value;
        }
        if let Some(bits) = self.tx_valid_bits {
            flags.tx_valid_bits = Some(bits);
        }
        flags
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TypeADetectOptions {
    pub iso_dep: Option<IsoDepConfig>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TypeBDetectOptions {
    pub iso_dep: Option<IsoDepConfig>,
    pub afi: Option<u8>,
    pub param: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct TypeACardInfo {
    pub atqa: [u8; 2],
    pub sak: u8,
    pub uid: Vec<u8>,
    pub ats: Vec<u8>,
    pub iso_dep_config: IsoDepConfig,
}

#[derive(Debug, Clone)]
pub struct TypeBCardInfo {
    pub pupi: [u8; 4],
    pub application_data: [u8; 4],
    pub protocol_info: Vec<u8>,
    pub attrib_response: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DiagnoseCommand {
    CommunicationLine(Vec<u8>),
    Rom,
    Ram,
    Polling {
        protocol: DiagnosePollingProtocol,
        count: u8,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum DiagnosePollingProtocol {
    Felica,
    Iso18092,
    Iso14443TypeA,
    Iso14443TypeB,
    Iso15693,
}

impl DiagnosePollingProtocol {
    fn code(self) -> u8 {
        match self {
            DiagnosePollingProtocol::Felica | DiagnosePollingProtocol::Iso18092 => 0x02,
            DiagnosePollingProtocol::Iso14443TypeA => 0x00,
            DiagnosePollingProtocol::Iso14443TypeB => 0x01,
            DiagnosePollingProtocol::Iso15693 => 0x03,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DiagnoseResult {
    CommunicationLine(Vec<u8>),
    Rom(u8),
    Ram(Vec<u8>),
    Polling(u8),
}

pub fn init<T: Transport>(transport: T) -> Result<Device<T>> {
    Device::new(transport)
}

pub fn open_port400() -> Result<Device<UsbTransport>> {
    common::open_usb_device(
        common::SONY_VENDOR_ID,
        PORT400_PIDS,
        "NFC Port-400 reader not found",
        Device::new,
    )
}

impl<T: Transport> Device<T> {
    pub fn new(transport: T) -> Result<Self> {
        let vendor_name = transport.manufacturer_name().map(|s| s.to_string());
        let product_name = transport.product_name().map(|s| s.to_string());
        let mut pcsc = Pcsc::new(transport);
        pcsc.set_receive_timeout(Duration::from_millis(1_500));
        // The firmware version is read before any session is opened: a reader
        // running the boot loader answers this command but nothing else.
        let version = pcsc.get_firmware_version()?;
        let update_mode = !is_firmware_update_state_normal(&version);
        let chipset_name = format_firmware(&version)
            .map(|fw| format!("NFC Port-400 {fw}"))
            .unwrap_or_else(|| "NFC Port-400".to_string());
        let mut session_open = false;
        let mut device_type = DeviceType::Unknown;
        let mut serial_number = None;
        if update_mode {
            warn!("Port-400 is in firmware update mode; card operations are unavailable");
        } else {
            // Taking priority ends a session another process left open, which is
            // what makes a reader whose last user exited uncleanly usable again.
            pcsc.start_transparent_session(true)?;
            session_open = true;
            pcsc.switch_protocol_type_f(false)?;
            device_type = pcsc
                .get_property(PROPERTY_GROUP_NO)
                .map(|group| device_type_from_group_number(&group))
                .unwrap_or_default();
            serial_number = pcsc
                .get_property(PROPERTY_SERIAL_NO)
                .ok()
                .map(|bytes| bytes.iter().map(|&byte| byte as char).collect::<String>());
            if let Ok(Some(rate)) = pcsc.card_baudrate() {
                debug!("Port-400 target baud rate {} kbps", rate);
            }
        }
        Ok(Self {
            pcsc,
            meta: DeviceMetadata {
                vendor_name,
                product_name,
                chipset_name,
            },
            iso_dep_session: None,
            iso_dep_protocol: None,
            update_mode,
            session_open,
            original_rf_speed: [None; RF_SPEED_PROTOCOLS],
            type_f_rf_speed: None,
            device_type,
            serial_number,
            firmware_version: format_firmware(&version),
        })
    }

    /// Where the reader reports it is fitted, from its group number property.
    pub fn device_type(&self) -> DeviceType {
        self.device_type
    }

    /// Serial number string the reader reported when it was opened.
    pub fn serial_number(&self) -> Option<&str> {
        self.serial_number.as_deref()
    }

    /// Firmware version the reader reported when it was opened.
    pub fn firmware_version(&self) -> Option<&str> {
        self.firmware_version.as_deref()
    }

    /// Whether the reader booted into firmware update mode, in which case only
    /// [`Self::prepare_firmware_update`], [`Self::update_firmware`] and
    /// [`Self::reset_device`] can be used.
    pub fn is_update_mode(&self) -> bool {
        self.update_mode
    }

    pub fn close(&mut self) -> Result<()> {
        self.release_reader();
        self.pcsc.close()
    }

    /// Turns the RF field on or off, as the reference library's `switchRF` does.
    pub fn switch_rf(&mut self, on: bool) -> Result<()> {
        if on {
            self.pcsc.turn_on_rf()
        } else {
            self.pcsc.turn_off_rf()
        }
    }

    /// Sends the command that keeps an idle transparent session from being
    /// dropped by the reader.
    ///
    /// The reference library runs this on a timer every
    /// [`KEEP_ALIVE_INTERVAL`] for as long as a session is open. This driver
    /// owns no thread of its own, so an application that keeps a session idle
    /// for that long has to call this itself.
    pub fn keep_alive(&mut self) -> Result<()> {
        self.pcsc.keep_alive()
    }

    /// Authenticates a MIFARE Classic block, as the reference library's
    /// `typea_mifareAuth` does.
    ///
    /// The card has to be activated as ISO 14443-3 Type A first (see
    /// [`Self::detect_type_a`] without an ISO-DEP configuration).
    pub fn mifare_authenticate(&mut self, auth: &MifareAuthentication) -> Result<()> {
        if auth.uid.is_empty() {
            return Err(DriverError::Other(
                "MIFARE authentication requires the card's UID".into(),
            ));
        }
        self.pcsc.load_keys(&auth.key)?;
        self.pcsc
            .general_authenticate(auth.block_number, auth.key_type.code())
    }

    pub fn mute(&mut self) -> Result<()> {
        self.pcsc.turn_off_rf()
    }

    /// Bitrate in kbps the reader reports for the currently activated card, as
    /// the reference library's `targetCardBaudRate` does.
    ///
    /// `None` means the reader answered with a speed code it does not define.
    pub fn card_baudrate(&mut self) -> Result<Option<u32>> {
        self.pcsc.card_baudrate()
    }

    pub fn get_max_send_data_size(&self, _target: &RemoteTarget) -> usize {
        MAX_THROUGH_PAYLOAD
    }

    pub fn get_max_recv_data_size(&self, _target: &RemoteTarget) -> usize {
        MAX_THROUGH_PAYLOAD
    }

    pub fn detect_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<Type3TagPollingResult> {
        let bitrate = target.bitrate();
        let auto_baud = match bitrate {
            "212F" => false,
            "424F" => true,
            _ => {
                return Err(DriverError::UnsupportedTarget(UnsupportedTargetError(
                    format!("unsupported bitrate {bitrate}"),
                )));
            }
        };
        // The frontend has to be allowed to run at 424 kbps before the auto baud
        // rate switch can negotiate it. Changing it cycles the session, so it has
        // to happen before the card is activated.
        if auto_baud {
            self.ensure_type_f_rf_speed(RF_SPEED_CODE_424K)?;
        }
        // Every Type-F detection starts from the fixed-speed protocol, so that a
        // previous detection left on auto baud rate does not carry over.
        self.set_type_f_auto_baud(false)?;
        // Raising the speed is a negotiation: the reader can only switch up if the
        // card was asked for its supported bitrates, which is what request code
        // REQ_BAUDRATE does. Polling with request code NONE and then asking for a
        // higher speed leaves the link at 212 kbps.
        let request_code = if auto_baud && request_code == FELICA_POLLING_OPTION_NONE {
            FELICA_POLLING_OPTION_REQ_BAUDRATE
        } else {
            request_code
        };
        debug!("polling for NFC-F using Port-400 at {bitrate}");
        let command = FelicaStandardCommand::Polling {
            system_code,
            request_code,
            time_slots,
        };
        let frame = command
            .to_frame()
            .map_err(|err| DriverError::Other(format!("failed to build SENSF_REQ: {err}")))?;
        let flags = TransmissionFlags::felica();
        let timeout = Duration::from_millis(polling_timeout_ms(time_slots) as u64);
        let response = self.pcsc.transceive(&frame, timeout, &flags)?;
        match FelicaStandardResponse::from_bytes(&response) {
            Ok(FelicaStandardResponse::Polling { idm, pmm, optional }) => {
                if auto_baud {
                    self.set_type_f_auto_baud(true)?;
                }
                if let Ok(Some(rate)) = self.pcsc.card_baudrate() {
                    debug!("Port-400 Type-F card baud rate {rate} kbps");
                    if auto_baud && rate < 424 {
                        warn!(
                            "requested {bitrate} but the Type-F link settled at {rate} kbps; \
                             treat the link as {rate} kbps rather than as {bitrate}"
                        );
                    }
                }
                Ok(Type3TagPollingResult {
                    idm: idm.to_vec(),
                    pmm: pmm.to_vec(),
                    optional,
                })
            }
            Ok(other) => Err(DriverError::Other(format!(
                "unexpected Felica response: {other:?}"
            ))),
            Err(err) => Err(DriverError::Other(format!(
                "failed to parse Felica response: {err}"
            ))),
        }
    }

    pub fn transceive(
        &mut self,
        _target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>> {
        let timeout = through_timeout(timeout_ms);
        ensure_through_command(data)?;
        let flags = TransmissionFlags::felica();
        debug!("Port-400 transceive TX (FeliCa): {}", encode(data));
        let response = self.pcsc.transceive(data, timeout, &flags)?;
        debug!("Port-400 transceive RX (FeliCa): {}", encode(&response));
        Ok(response)
    }

    pub fn communicate_thru(
        &mut self,
        data: &[u8],
        timeout_ms: Option<u16>,
        options: Option<ThroughOptions>,
    ) -> Result<Vec<u8>> {
        let opts = options.unwrap_or_default();
        let timeout = through_timeout(timeout_ms);
        ensure_through_command(data)?;
        let flags = opts.flags();
        debug!(
            "Port-400 through TX ({:?}): {}",
            opts.protocol,
            encode(data)
        );
        let response = self.pcsc.transceive(data, timeout, &flags)?;
        debug!(
            "Port-400 through RX ({:?}): {}",
            opts.protocol,
            encode(&response)
        );
        Ok(response)
    }

    pub fn detect_type_a(&mut self, options: Option<TypeADetectOptions>) -> Result<Vec<u8>> {
        let opts = options.unwrap_or_default();
        if let Some(config) = opts.iso_dep {
            self.enable_type_a_iso_dep(config)?;
        } else {
            self.prepare_type_a_polling()?;
        }
        self.refresh_card_baudrate()?;
        self.pcsc.get_uid()
    }

    pub fn detect_type_b(&mut self, options: Option<TypeBDetectOptions>) -> Result<Vec<u8>> {
        let opts = options.unwrap_or_default();
        let mut config = opts.iso_dep.unwrap_or_else(IsoDepConfig::type_b_defaults);
        let info = self.prepare_type_b_link(&mut config, &opts)?;
        self.start_iso_dep_session(ThroughProtocol::Iso14443TypeB, config);
        self.refresh_card_baudrate()?;
        Ok(info.pupi.to_vec())
    }

    pub fn detect_type_v(&mut self) -> Result<Vec<u8>> {
        self.pcsc.switch_protocol_iso15693()?;
        self.pcsc.get_uid()
    }

    pub fn set_detection_target(&mut self, selector: u8) -> Result<()> {
        self.pcsc.set_detection_target(selector)
    }

    /// Sets the RF speed used for `protocol` (0: Type A, 1: Type B, 2: Type F).
    ///
    /// The setting persists in the reader across sessions.
    pub fn set_rf_speed(&mut self, protocol: u8, rw_to_card: u8, card_to_rw: u8) -> Result<()> {
        self.without_transparent_session(|pcsc| {
            pcsc.set_rf_speed(protocol, rw_to_card, card_to_rw)
        })?;
        if protocol == RF_SPEED_PROTOCOL_TYPE_F {
            self.type_f_rf_speed = (rw_to_card == card_to_rw).then_some(rw_to_card);
        }
        Ok(())
    }

    /// Reads the RF speed configured for `protocol`, reader-to-card code first.
    pub fn get_rf_speed(&mut self, protocol: u8) -> Result<Vec<u8>> {
        self.without_transparent_session(|pcsc| pcsc.get_rf_speed(protocol))
    }

    /// Pins every protocol's frontend to a fixed RF speed, as the reference
    /// library does for a session that does not use automatic baud rate
    /// selection.
    ///
    /// The speed in place beforehand is remembered and put back by
    /// [`Self::reset_rf_speed`], which [`Self::close`] also calls. A protocol
    /// whose speed cannot be read or written is left alone.
    pub fn set_fixed_rf_speed(&mut self) {
        for (protocol, fixed) in RF_SPEED_FIXED_VALUE.iter().enumerate() {
            if let Err(err) = self.pin_rf_speed(protocol as u8, fixed[0], fixed[1]) {
                warn!("get/set RFSpeed failed for protocol {protocol}: {err}");
                self.original_rf_speed[protocol] = None;
            }
        }
    }

    /// Restores every RF speed [`Self::set_fixed_rf_speed`] changed.
    pub fn reset_rf_speed(&mut self) {
        for protocol in 0..RF_SPEED_PROTOCOLS {
            let Some([rw_to_card, card_to_rw]) = self.original_rf_speed[protocol].take() else {
                continue;
            };
            if let Err(err) = self.set_rf_speed(protocol as u8, rw_to_card, card_to_rw) {
                warn!("setRFSpeed failed for protocol {protocol}: {err}");
            }
        }
    }

    /// Records the current RF speed of `protocol` and writes the new one.
    fn pin_rf_speed(&mut self, protocol: u8, rw_to_card: u8, card_to_rw: u8) -> Result<()> {
        let slot = protocol as usize;
        if self.original_rf_speed[slot].is_none() {
            let current = self.get_rf_speed(protocol)?;
            let [before_rw, before_cr, ..] = current[..] else {
                return Err(DriverError::Other(
                    "reader reported a malformed RF speed".into(),
                ));
            };
            self.original_rf_speed[slot] = Some([before_rw, before_cr]);
        }
        self.set_rf_speed(protocol, rw_to_card, card_to_rw)
    }

    /// Runs `f` with the transparent session suspended.
    ///
    /// The reader rejects the RF speed commands with `6985` (conditions of use
    /// not satisfied) while a transparent session is open, which is why the
    /// reference library reads and writes them in `open()` before the session is
    /// started and in `close()` after it ended. Re-opening the session power
    /// cycles the RF field, so a card that was activated has to be polled again.
    fn without_transparent_session<R>(
        &mut self,
        f: impl FnOnce(&mut Pcsc<T>) -> Result<R>,
    ) -> Result<R> {
        if !self.session_open {
            return f(&mut self.pcsc);
        }
        self.pcsc.end_transparent_session()?;
        self.session_open = false;
        let result = f(&mut self.pcsc);
        self.pcsc.start_transparent_session(false)?;
        self.session_open = true;
        self.pcsc.switch_protocol_type_f(false)?;
        self.end_iso_dep_session();
        result
    }

    pub fn set_comm_speed(&mut self, speed: u8) -> Result<()> {
        self.pcsc.set_comm_speed(speed)
    }

    pub fn set_tx_rx_flag(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.pcsc.set_tx_rx_flag(data)
    }

    pub fn set_tx_bit_framing(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.pcsc.set_tx_bit_framing(data)
    }

    pub fn iso_dep_session(&mut self) -> Option<&mut IsoDepSession> {
        self.iso_dep_session.as_mut()
    }

    pub fn start_iso_dep_session(&mut self, protocol: ThroughProtocol, config: IsoDepConfig) {
        self.iso_dep_session = Some(IsoDepSession::new(config));
        self.iso_dep_protocol = Some(protocol);
    }

    pub fn reset_iso_dep_session(&mut self) -> Result<()> {
        match self.iso_dep_session.as_mut() {
            Some(session) => {
                session.reset();
                Ok(())
            }
            None => Err(DriverError::Other("ISO-DEP session is not active".into())),
        }
    }

    pub fn end_iso_dep_session(&mut self) {
        self.iso_dep_session = None;
        self.iso_dep_protocol = None;
    }

    fn iso_dep_protocol_or_default(&self) -> ThroughProtocol {
        self.iso_dep_protocol
            .unwrap_or(ThroughProtocol::Iso14443TypeA)
    }

    fn take_iso_dep_session(&mut self) -> Result<IsoDepSession> {
        self.iso_dep_session
            .take()
            .ok_or_else(|| DriverError::Other("ISO-DEP session is not active".into()))
    }

    pub fn start_rffe_parameter_mode(&mut self) -> Result<()> {
        self.pcsc.start_rffe_parameter_mode()?;
        self.session_open = false;
        Ok(())
    }

    pub fn end_rffe_parameter_mode(&mut self) -> Result<()> {
        self.pcsc.end_rffe_parameter_mode()?;
        self.session_open = true;
        Ok(())
    }

    /// Ends the transparent session and undoes the RF speeds this driver changed.
    ///
    /// Both live in the reader rather than in this process, so they have to be
    /// given back whether the caller closes the device or just drops it.
    fn release_reader(&mut self) {
        if self.session_open {
            let _ = self.pcsc.end_transparent_session();
            self.session_open = false;
        }
        self.reset_rf_speed();
    }

    pub fn read_rffe_parameter(
        &mut self,
        category: u8,
        selector: u8,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        ensure_rffe_category(category)?;
        self.pcsc.read_rffe_parameter(category, selector, data)
    }

    pub fn write_rffe_parameter(
        &mut self,
        category: u8,
        selector: u8,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        ensure_rffe_category(category)?;
        self.pcsc.write_rffe_parameter(category, selector, data)
    }

    pub fn hardware_version(&mut self) -> Result<Vec<u8>> {
        self.pcsc.get_property(PROPERTY_HARDWARE_VERSION)
    }

    pub fn model_id(&mut self) -> Result<Vec<u8>> {
        self.pcsc.get_property(PROPERTY_MODEL_ID)
    }

    pub fn card_identifier(&mut self) -> Result<Vec<u8>> {
        self.pcsc.card_id()
    }

    pub fn card_name(&mut self) -> Result<Vec<u8>> {
        self.pcsc.card_name()
    }

    pub fn card_type(&mut self) -> Result<Vec<u8>> {
        self.pcsc.card_type()
    }

    pub fn card_type_name(&mut self) -> Result<Vec<u8>> {
        self.pcsc.card_type_name()
    }

    pub fn serial_number_bytes(&mut self) -> Result<Vec<u8>> {
        self.pcsc.get_property(PROPERTY_SERIAL_NO)
    }

    pub fn group_number(&mut self) -> Result<Vec<u8>> {
        self.pcsc.get_property(PROPERTY_GROUP_NO)
    }

    /// Prepares a firmware update, returning the status the reader reports.
    pub fn prepare_firmware_update(&mut self, data: &[u8]) -> Result<u8> {
        let response = self.pcsc.prepare_firmware_update(data)?;
        response
            .first()
            .copied()
            .ok_or_else(|| DriverError::Other("prepareUpdateFirmware returned no status".into()))
    }

    /// Sends one firmware packet, returning the packet number the reader expects
    /// next.
    pub fn update_firmware(&mut self, sequence: u16, data: &[u8]) -> Result<u16> {
        let response = self.pcsc.update_firmware(sequence, data)?;
        let [low, high, ..] = response[..] else {
            return Err(DriverError::Other(
                "updateFirmware returned no packet number".into(),
            ));
        };
        Ok(u16::from_le_bytes([low, high]))
    }

    /// Resets the reader after `delay_ms`.
    ///
    /// A reader in firmware update mode resets without answering, so the error
    /// that follows is ignored there, as the reference library does.
    pub fn reset_device(&mut self, delay_ms: u16) -> Result<Vec<u8>> {
        match self.pcsc.reset_device(delay_ms) {
            Ok(response) => Ok(response),
            Err(err) if self.update_mode => {
                debug!("resetDevice reported {err} while in update mode; ignoring it");
                Ok(Vec::new())
            }
            Err(err) => Err(err),
        }
    }

    pub fn self_diagnose(&mut self, command: DiagnoseCommand) -> Result<DiagnoseResult> {
        match command {
            DiagnoseCommand::CommunicationLine(data) => {
                if data.is_empty() || data.len() > DIAG_COMMUNICATION_LINE_SIZE_MAX {
                    return Err(DriverError::Other("diagnostic data size is invalid".into()));
                }
                let response = self.pcsc.diagnose_communication_line(&data)?;
                Ok(DiagnoseResult::CommunicationLine(response))
            }
            DiagnoseCommand::Rom => {
                let result = self.pcsc.diagnose_rom()?;
                Ok(DiagnoseResult::Rom(result))
            }
            DiagnoseCommand::Ram => {
                let result = self.pcsc.diagnose_ram()?;
                Ok(DiagnoseResult::Ram(result))
            }
            DiagnoseCommand::Polling { protocol, count } => {
                if count < DIAG_POLLING_COUNT_MIN {
                    return Err(DriverError::Other(
                        "diagnostic polling count out of range".into(),
                    ));
                }
                let code = protocol.code();
                let result = self.pcsc.diagnose_polling(code, count)?;
                Ok(DiagnoseResult::Polling(result))
            }
        }
    }

    fn enable_type_a_iso_dep(&mut self, mut config: IsoDepConfig) -> Result<()> {
        self.pcsc
            .switch_protocol_iso14443_4a(config.fsdi, config.cid, 4)?;
        if let Ok(ats) = self.pcsc.get_historical_bytes() {
            apply_ats_config(&mut config, &ats);
        }
        self.start_iso_dep_session(ThroughProtocol::Iso14443TypeA, config);
        Ok(())
    }

    fn prepare_type_a_polling(&mut self) -> Result<()> {
        self.pcsc.switch_protocol_iso14443_3a()?;
        self.end_iso_dep_session();
        Ok(())
    }

    /// Lets the Type-F frontend run at `speed_code` in both directions.
    ///
    /// The reader negotiates no faster than the RF speed its frontend is set to,
    /// so a frontend sitting at its 212 kbps default keeps the auto baud rate
    /// switch at 212 kbps however much the card advertises. The setting outlives
    /// the session, so the value found beforehand is remembered and put back by
    /// [`Self::close`], the same save and restore the reference library performs
    /// around a fixed-speed session.
    fn ensure_type_f_rf_speed(&mut self, speed_code: u8) -> Result<()> {
        if self.type_f_rf_speed == Some(speed_code) {
            return Ok(());
        }
        let slot = RF_SPEED_PROTOCOL_TYPE_F as usize;
        if self.original_rf_speed[slot].is_none() {
            let current = self.get_rf_speed(RF_SPEED_PROTOCOL_TYPE_F)?;
            let [rw_to_card, card_to_rw, ..] = current[..] else {
                return Err(DriverError::Other(
                    "reader reported a malformed Type-F RF speed".into(),
                ));
            };
            // A frontend that already allows the speed needs no write, and leaves
            // close() nothing to restore.
            if rw_to_card == speed_code && card_to_rw == speed_code {
                self.type_f_rf_speed = Some(speed_code);
                return Ok(());
            }
            debug!(
                "raising the Type-F RF speed from {rw_to_card},{card_to_rw} to {speed_code} \
                 so the link can negotiate 424 kbps"
            );
            self.original_rf_speed[slot] = Some([rw_to_card, card_to_rw]);
        }
        self.set_rf_speed(RF_SPEED_PROTOCOL_TYPE_F, speed_code, speed_code)
    }

    /// Switches the Type-F protocol between fixed speed and auto baud rate.
    ///
    /// The command is sent even when the reader is already in the wanted mode:
    /// switching the protocol re-activates the card, and the reference library
    /// relies on that fresh activation before every polling.
    fn set_type_f_auto_baud(&mut self, auto_baud: bool) -> Result<()> {
        self.pcsc.switch_protocol_type_f(auto_baud)
    }

    fn refresh_card_baudrate(&mut self) -> Result<()> {
        let _ = self.card_baudrate()?;
        Ok(())
    }

    fn apply_comm_speed(&mut self, dri: u8, dsi: u8) -> Result<()> {
        let speed_code = build_speed_code(dri, dsi);
        if speed_code != 0 {
            self.pcsc.set_comm_speed(speed_code)?;
        }
        Ok(())
    }

    fn prepare_type_b_link(
        &mut self,
        config: &mut IsoDepConfig,
        options: &TypeBDetectOptions,
    ) -> Result<TypeBInfo> {
        self.pcsc
            .switch_protocol_iso14443_4b(config.fsdi, config.cid, 4)?;
        let info = self
            .pcsc
            .request_type_b_info(options.afi.unwrap_or(0x00), options.param.unwrap_or(0x00))?;
        apply_type_b_protocol_details(config, &info.protocol_info);
        Ok(info)
    }
}

fn ensure_rffe_category(category: u8) -> Result<()> {
    match category {
        RFFE_PARAM_EEPROM | RFFE_PARAM_PD_SC_DPC | RFFE_PARAM_PROTOCOL_CONFIGURATION => Ok(()),
        _ => Err(DriverError::Other(format!(
            "unsupported RFFE parameter category {category}"
        ))),
    }
}

impl<T: Transport> Drop for Device<T> {
    /// Releases the reader for callers that drop the device without closing it.
    ///
    /// The transparent session belongs to the reader and outlives the process, so
    /// leaving it open locks the next run out with an access authority error.
    fn drop(&mut self) {
        self.release_reader();
    }
}

impl<T: Transport> DeviceInfo for Device<T> {
    fn metadata(&self) -> &DeviceMetadata {
        &self.meta
    }
}

impl_reader_device!(Device);

/// Frame waiting time of a through command.
///
/// The caller's value is used as it stands: the FeliCa layer works each command's
/// timeout out from the card's PMm, and raising it to a floor would throw that
/// away. Only a caller that supplies none falls back to a fixed default.
fn through_timeout(timeout_ms: Option<u16>) -> Duration {
    Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_THROUGH_TIMEOUT_MS) as u64)
}

fn ensure_through_command(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Err(DriverError::Other("through command is empty".into()));
    }
    if data.len() > MAX_THROUGH_PAYLOAD {
        return Err(DriverError::Other(format!(
            "through command is {} bytes, the maximum is {MAX_THROUGH_PAYLOAD}",
            data.len()
        )));
    }
    Ok(())
}

/// Reads where the reader is fitted out of its group number property.
fn device_type_from_group_number(group: &[u8]) -> DeviceType {
    match group.get(GROUP_NO_DEVICE_TYPE_OFFSET) {
        Some(1) => DeviceType::Internal,
        Some(2) => DeviceType::External,
        _ => {
            debug!("Port-400 did not report a device type");
            DeviceType::Unknown
        }
    }
}

/// A reader running its regular firmware reports `FF FF` as the update state.
fn is_firmware_update_state_normal(version: &[u8]) -> bool {
    version
        .get(FW_VER_UPDATE_STATE)
        .is_some_and(|state| state == [0xFF, 0xFF])
}

fn data_rate_symbols(config: &IsoDepConfig) -> (u8, u8) {
    (config.dr.symbol().min(3), config.ds.symbol().min(3))
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

fn apply_ats_config(config: &mut IsoDepConfig, ats: &[u8]) {
    if let Err(err) = config.apply_ats(ats) {
        warn!("failed to apply ATS parameters: {err}");
    } else {
        debug!("Port-400 ATS: {}", encode(ats));
    }
}

fn apply_type_b_protocol_details(config: &mut IsoDepConfig, info: &[u8]) {
    if let Err(err) = config.apply_type_b_protocol_info(info) {
        warn!("failed to apply Type-B protocol info: {err}");
    } else {
        debug!("Port-400 Type-B protocol info: {}", encode(info));
    }
}

fn build_speed_code(dri: u8, dsi: u8) -> u8 {
    ((dri & 0x07) << 3) | (dsi & 0x07)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::port400::iso14443::IsoDepDataRate;
    use crate::driver::testing::assert_driver_error_contains;
    use std::time::Duration;

    #[test]
    fn through_protocol_flag_defaults_match_protocol() {
        let type_a = ThroughProtocol::Iso14443TypeA.transmission_flags();
        assert!(type_a.insert_parity);
        assert!(type_a.expect_parity);

        let type_b = ThroughProtocol::Iso14443TypeB.transmission_flags();
        assert!(!type_b.insert_parity);
        assert!(!type_b.expect_parity);
    }

    #[test]
    fn through_protocol_iso_dep_flags_default_to_type_a_except_type_b() {
        let felica = ThroughProtocol::Felica.iso_dep_flags();
        let type_a = ThroughProtocol::Iso14443TypeA.iso_dep_flags();
        let type_b = ThroughProtocol::Iso14443TypeB.iso_dep_flags();
        assert_eq!(felica.insert_parity, type_a.insert_parity);
        assert_eq!(felica.expect_parity, type_a.expect_parity);
        assert!(!type_b.insert_parity);
        assert!(!type_b.expect_parity);
    }

    #[test]
    fn through_options_flags_override_protocol_defaults() {
        let options = ThroughOptions {
            protocol: ThroughProtocol::Iso14443TypeA,
            append_crc: Some(false),
            discard_crc: Some(false),
            insert_parity: Some(false),
            expect_parity: Some(false),
            append_protocol_prologue: Some(true),
            tx_valid_bits: Some(7),
        };
        let flags = options.flags();
        assert!(!flags.append_crc);
        assert!(!flags.discard_crc);
        assert!(!flags.insert_parity);
        assert!(!flags.expect_parity);
        assert!(flags.append_protocol_prologue);
        assert_eq!(flags.tx_valid_bits, Some(7));
    }
    #[test]
    fn ensure_rffe_category_accepts_known_categories_and_rejects_unknown() {
        assert!(ensure_rffe_category(RFFE_PARAM_EEPROM).is_ok());
        assert!(ensure_rffe_category(RFFE_PARAM_PD_SC_DPC).is_ok());
        assert!(ensure_rffe_category(RFFE_PARAM_PROTOCOL_CONFIGURATION).is_ok());
        assert_driver_error_contains(
            ensure_rffe_category(0xFF),
            "unsupported RFFE parameter category",
        );
    }

    #[test]
    fn through_timeout_keeps_the_caller_value_and_defaults_when_absent() {
        assert_eq!(
            through_timeout(None),
            Duration::from_millis(DEFAULT_THROUGH_TIMEOUT_MS as u64)
        );
        // A computed timeout is passed through untouched, however short.
        assert_eq!(through_timeout(Some(2)), Duration::from_millis(2));
        assert_eq!(through_timeout(Some(1_000)), Duration::from_millis(1_000));
    }

    #[test]
    fn ensure_through_command_checks_the_command_size() {
        assert!(ensure_through_command(&[0x06, 0x00]).is_ok());
        assert!(ensure_through_command(&vec![0x00; MAX_THROUGH_PAYLOAD]).is_ok());
        assert_driver_error_contains(ensure_through_command(&[]), "through command is empty");
        assert_driver_error_contains(
            ensure_through_command(&vec![0x00; MAX_THROUGH_PAYLOAD + 1]),
            "the maximum is",
        );
    }

    #[test]
    fn is_firmware_update_state_normal_requires_the_update_state_bytes() {
        let mut version = vec![0x00; 18];
        version[14] = 0xFF;
        version[15] = 0xFF;
        assert!(is_firmware_update_state_normal(&version));
        version[15] = 0x00;
        assert!(!is_firmware_update_state_normal(&version));
        assert!(!is_firmware_update_state_normal(&[0xFF; 4]));
    }

    #[test]
    fn data_rate_symbols_clamps_to_two_bits() {
        let mut config = IsoDepConfig::type_a_defaults();
        config.dr = IsoDepDataRate::Kbps848;
        config.ds = IsoDepDataRate::Kbps424;
        assert_eq!(data_rate_symbols(&config), (3, 2));
    }

    #[test]
    fn format_firmware_requires_four_bytes_and_formats_hex() {
        assert_eq!(format_firmware(&[0x01, 0x02, 0x03]), None);
        assert_eq!(
            format_firmware(&[0x01, 0x02, 0xAB, 0xCD]),
            Some("v01.02.AB.CD".to_string())
        );
    }

    #[test]
    fn apply_ats_config_updates_on_valid_input_and_ignores_invalid_input() {
        let mut valid = IsoDepConfig::type_a_defaults();
        valid.fsci = 1;
        apply_ats_config(&mut valid, &[0x02, 0x08]);
        assert_eq!(valid.fsci, 8);

        let mut invalid = IsoDepConfig::type_a_defaults();
        invalid.fsci = 3;
        apply_ats_config(&mut invalid, &[0x01]);
        assert_eq!(invalid.fsci, 3);
    }

    #[test]
    fn apply_type_b_protocol_details_updates_on_valid_input_and_ignores_invalid_input() {
        let mut valid = IsoDepConfig::type_b_defaults();
        apply_type_b_protocol_details(&mut valid, &[0xA1, 0xF0, 0x00, 0xB0]);
        assert_eq!(valid.fsci, 8);
        assert_eq!(valid.dr, IsoDepDataRate::Kbps212);
        assert_eq!(valid.ds, IsoDepDataRate::Kbps424);
        assert!(!valid.use_cid);
        assert!(!valid.use_nad);
        assert_eq!(valid.sfgi, 11);

        let mut invalid = IsoDepConfig::type_b_defaults();
        invalid.fsci = 5;
        apply_type_b_protocol_details(&mut invalid, &[0x00, 0x00]);
        assert_eq!(invalid.fsci, 5);
    }

    #[test]
    fn build_speed_code_masks_upper_bits() {
        assert_eq!(build_speed_code(0x03, 0x05), 0x1D);
        assert_eq!(build_speed_code(0xFF, 0xAA), 0x3A);
    }

    #[test]
    fn diagnose_polling_protocol_code_matches_expected_values() {
        assert_eq!(DiagnosePollingProtocol::Felica.code(), 0x02);
        assert_eq!(DiagnosePollingProtocol::Iso18092.code(), 0x02);
        assert_eq!(DiagnosePollingProtocol::Iso14443TypeA.code(), 0x00);
        assert_eq!(DiagnosePollingProtocol::Iso14443TypeB.code(), 0x01);
        assert_eq!(DiagnosePollingProtocol::Iso15693.code(), 0x03);
    }

    #[test]
    fn device_type_from_group_number_reads_the_fifth_byte() {
        assert_eq!(
            device_type_from_group_number(&[0, 0, 0, 0, 1]),
            DeviceType::Internal
        );
        assert_eq!(
            device_type_from_group_number(&[0, 0, 0, 0, 2]),
            DeviceType::External
        );
        assert_eq!(
            device_type_from_group_number(&[0, 0, 0, 0, 9]),
            DeviceType::Unknown
        );
        // A property too short to hold the byte reports Unknown rather than panicking.
        assert_eq!(device_type_from_group_number(&[0, 0]), DeviceType::Unknown);
    }

    #[test]
    fn mifare_key_type_maps_to_the_reader_codes() {
        assert_eq!(MifareKeyType::A.code(), 0x60);
        assert_eq!(MifareKeyType::B.code(), 0x61);
    }
}
