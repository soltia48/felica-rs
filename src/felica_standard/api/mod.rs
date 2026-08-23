use super::command::{CommandEncoding, FelicaStandardCommand};
use super::error::FelicaStandardError;
use super::response::FelicaStandardResponse;
use super::secure::{
    AuthenticatedContext, Authentication2Response, Authentication2V2Response,
    AuthenticationContext, AuthenticationContextV2Aes128, DecryptedSecureResponse,
    MAX_SECURE_READ_BLOCK_COUNT, MAX_SECURE_READ_V2_BLOCK_COUNT, SecureCommandContext,
    SecureSessionCredentials, SecureSessionScheme, generate_registration_package_des,
};
use super::types::{
    BlockListElement, ChangeKeyParameters, ContainerInformation, ContainerProperty,
    GetAreaInformationResult, GetNodePropertyResult, GetSystemStatusResult,
    MutualAuthenticationResult, NodePropertyType, RequestBlockInformationExResult,
    RequestCodeListResult, RequestServiceV2KeyVersion, SearchServiceCodeResult, ServiceCode,
    SetParameterEncryptionType, SetParameterPacketType, SpecificationVersion, StatusFlag2,
    status_flag_description,
};
use super::{
    BLOCK_SIZE, DES_BLOCK_SIZE, IDM_LEN, MAX_BLOCK_COUNT, MAX_NODE_CODES, MAX_NODE_PROPERTY_CODES,
    MAX_READ_WITHOUT_ENCRYPTION_BLOCK_COUNT, MAX_RW_SERVICE_CODES, MAX_SERVICE_CODES,
    POLLING_REQUEST_CODES, POLLING_TIME_SLOTS, READ_V2_COMMAND_CODE, READ_V2_RESPONSE_CODE,
    WRITE_V2_COMMAND_CODE, WRITE_V2_RESPONSE_CODE, frame_with_length_prefix,
};
use crate::RemoteTarget;
use crate::driver::errors::Result as DriverResult;
use crate::felica_standard::Type3TagPollingResult;
use std::convert::TryInto;

/// Minimal reader interface required by the FeliCa Standard protocol layer.
///
/// Hardware drivers implement card discovery and raw packet exchange; packet
/// construction, parsing, timeouts, authentication, and secure messaging are
/// handled by [`FelicaStandard`]. A relay or test double can implement this
/// trait without depending on USB support.
pub trait FelicaDriver {
    /// Polls for an NFC-F target and returns its IDm, PMm, and optional request
    /// data.
    fn detect_type_f(
        &mut self,
        target: &RemoteTarget,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> DriverResult<Type3TagPollingResult>;

    /// Sends one length-prefixed FeliCa command packet to an activated target
    /// and returns its length-prefixed response packet.
    fn transceive(
        &mut self,
        target: &RemoteTarget,
        data: &[u8],
        timeout_ms: Option<u16>,
    ) -> DriverResult<Vec<u8>>;
}

/// Stateful high-level interface to one polled FeliCa Standard card.
///
/// The value borrows the reader driver for its lifetime and retains the target
/// bitrate, polling result, and optional authenticated-session state. Create it
/// with [`polling`](Self::polling) or [`polling_multi`](Self::polling_multi).
pub struct FelicaStandard<'a, D: FelicaDriver + ?Sized> {
    device: &'a mut D,
    target: RemoteTarget,
    polling_result: Type3TagPollingResult,
    authenticated_context: Option<AuthenticatedContext>,
}

impl<'a, D: FelicaDriver + ?Sized> FelicaStandard<'a, D> {
    /// Returns the eight-byte Manufacture ID (`IDm`) selected by Polling.
    pub fn idm(&self) -> &[u8] {
        &self.polling_result.idm
    }

    /// Returns the eight-byte Manufacture Parameter (`PMm`).
    ///
    /// PMm bytes 2 through 7 encode the card's maximum response times and are
    /// used automatically for subsequent command timeouts.
    pub fn pmm(&self) -> &[u8] {
        &self.polling_result.pmm
    }

    /// Returns the bitrate (e.g. `"212F"` or `"424F"`) at which the card was
    /// activated and at which every subsequent command is exchanged.
    pub fn bitrate(&self) -> &str {
        self.target.bitrate()
    }

    fn idm_bytes(&self) -> Result<[u8; IDM_LEN], FelicaStandardError> {
        self.idm()
            .try_into()
            .map_err(|_| FelicaStandardError::InvalidParameter("IDm must be 8 bytes long".into()))
    }

    fn status_error(command: &'static str, sf1: u8, sf2: u8) -> FelicaStandardError {
        FelicaStandardError::Status {
            command,
            status_flag1: sf1,
            status_flag2: sf2,
            detail: status_flag_description(sf1, sf2),
        }
    }

    /// Decides success or failure from a response's status flags.
    ///
    /// §4.5.1 normally makes status flag 1 authoritative: `00h` means that the
    /// card processed the command normally. The one documented exception is
    /// §4.5.2 table 4-11's `SF2 = 71h` (memory rewrite count exceeded), a warning
    /// raised *after* the write has been performed. Products may pair it with
    /// either `SF1 = 00h` or `SF1 = FFh`; both combinations are therefore
    /// accepted so a caller is not invited to repeat a completed write.
    ///
    /// A non-zero flag 2 alongside a normal-completion flag 1 is logged so the
    /// warning is not silently dropped.
    fn check_status_flags(
        command: &'static str,
        sf1: u8,
        sf2: u8,
    ) -> Result<(), FelicaStandardError> {
        if sf2 == 0x71 && matches!(sf1, 0x00 | 0xFF) {
            log::warn!(
                "{command} completed with memory rewrite count warning 71: {}",
                StatusFlag2::from_byte(sf2).description()
            );
            return Ok(());
        }
        if sf1 != 0x00 {
            return Err(Self::status_error(command, sf1, sf2));
        }
        if sf2 != 0x00 {
            log::warn!(
                "{command} completed normally but reported status flag 2 {sf2:02X}: {}",
                StatusFlag2::from_byte(sf2).description()
            );
        }
        Ok(())
    }

    /// Checks a response's status flags and hands back the payload the card
    /// sends behind them.
    ///
    /// §4.5.1 pairs the two: a card that completed the command normally sends
    /// its result. A normal completion with nothing behind it is therefore a
    /// protocol violation rather than an empty answer, and is reported as one.
    fn require_result<R>(
        command: &'static str,
        sf1: u8,
        sf2: u8,
        result: Option<R>,
    ) -> Result<R, FelicaStandardError> {
        Self::check_status_flags(command, sf1, sf2)?;
        result.ok_or_else(|| {
            FelicaStandardError::Protocol(format!("{command} missing result payload"))
        })
    }

    /// Polls for a FeliCa (Type 3 / NFC-F) card at a single `bitrate`
    /// (`"212F"` or `"424F"`).
    ///
    /// This is a convenience wrapper over [`polling_multi`](Self::polling_multi)
    /// for callers that only accept one communication speed.
    pub fn polling(
        device: &'a mut D,
        bitrate: &str,
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<(Self, Type3TagPollingResult), FelicaStandardError> {
        Self::polling_multi(device, &[bitrate], system_code, request_code, time_slots)
    }

    /// Polls for a FeliCa (Type 3 / NFC-F) card, trying each requested bitrate
    /// in turn until a card responds.
    ///
    /// FeliCa communicates at either 212 kbps (`"212F"`) or 424 kbps (`"424F"`).
    /// When both are requested the faster 424F rate is attempted first, so a
    /// card that supports 424F is polled at that speed while a card that does
    /// not support 424F is still reached through the 212F fallback. Any other
    /// requested bitrates are tried afterwards in the order given; duplicates
    /// are ignored. The bitrate that actually activated the card is retained and
    /// reused for every subsequent command.
    ///
    /// `request_code` selects the optional request data (`00h` none, `01h` system
    /// code, `02h` communication performance) and `time_slots` the maximum number
    /// of anti-collision response slots (`00h`, `01h`, `03h`, `07h` or `0Fh` for
    /// 1, 2, 4, 8 or 16 slots). Both are restricted to those values; see
    /// [`Polling`](FelicaStandardCommand::Polling).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidParameter`](FelicaStandardError::InvalidParameter) if
    /// `bitrates` is empty or `request_code`/`time_slots` is not a defined value,
    /// propagates an
    /// [`UnsupportedTarget`](FelicaStandardError::UnsupportedTarget) error for a
    /// malformed bitrate string, or returns the last driver error if no card
    /// responded at any requested bitrate.
    pub fn polling_multi(
        device: &'a mut D,
        bitrates: &[&str],
        system_code: u16,
        request_code: u8,
        time_slots: u8,
    ) -> Result<(Self, Type3TagPollingResult), FelicaStandardError> {
        validate_polling_parameters(request_code, time_slots)?;
        let ordered = order_felica_bitrates(bitrates);
        if ordered.is_empty() {
            return Err(FelicaStandardError::InvalidParameter(
                "polling requires at least one bitrate".into(),
            ));
        }

        let mut last_error: Option<FelicaStandardError> = None;
        for bitrate in ordered {
            let target = RemoteTarget::new(bitrate)?;
            match device.detect_type_f(&target, system_code, request_code, time_slots) {
                Ok(polling_result) => {
                    return Ok((
                        Self {
                            device,
                            target,
                            polling_result: polling_result.clone(),
                            authenticated_context: None,
                        },
                        polling_result,
                    ));
                }
                Err(err) => last_error = Some(err.into()),
            }
        }

        Err(last_error.expect("a bitrate was attempted, so an error was recorded"))
    }

    /// Sends one command and parses the card's response, decrypting it first for
    /// secure commands.
    ///
    /// `timeout_ms` should come from the maximum response time the card
    /// advertises in its PMm; [`Type3TagPollingResult`] derives it per command
    /// (§2.3.4, table 2-5).
    ///
    /// # Guard time
    ///
    /// §2.4.2 defines two guard times around each exchange: a card waits at least
    /// ~198 µs after receiving a command before answering, and a reader should
    /// wait at least ~501 µs after a response before starting the next command's
    /// preamble. Both are enforced by the reader's own RF layer — the drivers
    /// configure it at activation time — rather than by this method, which cannot
    /// see when the frame actually left the antenna. A [`FelicaDriver`] that
    /// reaches the card over something other than a FeliCa reader (a relay, say)
    /// is responsible for preserving those gaps itself.
    pub fn send_command(
        &mut self,
        command: FelicaStandardCommand,
        timeout_ms: u16,
    ) -> Result<FelicaStandardResponse, FelicaStandardError> {
        match command.encoding()? {
            CommandEncoding::Plain(frame) => {
                let response_bytes =
                    self.device
                        .transceive(&self.target, &frame, Some(timeout_ms))?;
                Ok(FelicaStandardResponse::from_bytes(&response_bytes)?)
            }
            CommandEncoding::Secure { opcode, payload } => {
                let decrypted = self.encrypted_command_exchange(opcode, &payload, timeout_ms)?;
                Ok(FelicaStandardResponse::from_secure_bytes(
                    opcode, &decrypted,
                )?)
            }
        }
    }

    fn execute_command(
        &mut self,
        _command_name: &'static str,
        command: FelicaStandardCommand,
        timeout_ms: u16,
    ) -> Result<FelicaStandardResponse, FelicaStandardError> {
        self.send_command(command, timeout_ms)
    }
}

/// Orders the requested FeliCa bitrates from most to least preferred — 424F
/// before 212F — while removing duplicates and preserving the caller's order
/// among entries of equal preference.
fn order_felica_bitrates<'b>(bitrates: &[&'b str]) -> Vec<&'b str> {
    let mut ordered: Vec<&'b str> = Vec::with_capacity(bitrates.len());
    for &bitrate in bitrates {
        if !ordered.contains(&bitrate) {
            ordered.push(bitrate);
        }
    }
    // `sort_by_key` is stable, so equally-ranked bitrates keep their input order.
    ordered.sort_by_key(|bitrate| felica_bitrate_preference(bitrate));
    ordered
}

/// Preference rank for a FeliCa bitrate; a lower value is polled first. 424F
/// outranks 212F so the faster rate wins whenever both are requested.
fn felica_bitrate_preference(bitrate: &str) -> u8 {
    match bitrate {
        "424F" => 0,
        "212F" => 1,
        _ => 2,
    }
}

/// Rejects Polling request codes and time slot counts that §4.4.2 does not define.
///
/// Request codes other than `00h`/`01h`/`02h` are reserved, and the specification
/// is explicit that only the five listed time slot values may be sent: "タイム
/// スロット値は、規定値（00h、01h、03h、07h、0Fh）のみ指定してください。規定値以外
/// の値を設定した場合、製品によって動作が異なる場合があります" (§4.4.2, table 4-6).
/// A reserved value therefore has no portable meaning, and the response timeout a
/// driver derives from the slot count would not match the card's actual response
/// window either.
fn validate_polling_parameters(
    request_code: u8,
    time_slots: u8,
) -> Result<(), FelicaStandardError> {
    if !POLLING_REQUEST_CODES.contains(&request_code) {
        return Err(FelicaStandardError::InvalidParameter(format!(
            "polling request code {request_code:#04X} is reserved; use 0x00 (no request), \
             0x01 (system code) or 0x02 (communication performance)"
        )));
    }
    if !POLLING_TIME_SLOTS.contains(&time_slots) {
        return Err(FelicaStandardError::InvalidParameter(format!(
            "polling time slot value {time_slots:#04X} is not defined; use 0x00, 0x01, 0x03, \
             0x07 or 0x0F for 1, 2, 4, 8 or 16 slots"
        )));
    }
    Ok(())
}

fn ensure_len_in_range(
    name: &str,
    len: usize,
    min: usize,
    max: usize,
) -> Result<(), FelicaStandardError> {
    if (min..=max).contains(&len) {
        Ok(())
    } else {
        Err(FelicaStandardError::InvalidParameter(format!(
            "{name} must contain between {min} and {max} entries"
        )))
    }
}

fn validate_block_list_indices(
    block_list: &[BlockListElement],
    service_codes_len: usize,
) -> Result<(), FelicaStandardError> {
    if block_list
        .iter()
        .any(|block| block.service_code_list_index as usize >= service_codes_len)
    {
        Err(FelicaStandardError::InvalidParameter(
            "block_list references out-of-range service index".into(),
        ))
    } else {
        Ok(())
    }
}

fn ensure_block_data_length(
    block_count: usize,
    data_len: usize,
) -> Result<(), FelicaStandardError> {
    let expected = block_count * BLOCK_SIZE;
    if data_len == expected {
        Ok(())
    } else {
        Err(FelicaStandardError::InvalidParameter(
            "data length must equal 16 * block_list length".into(),
        ))
    }
}

fn expected_secure_response_code(command_code: u8) -> u8 {
    match command_code {
        READ_V2_COMMAND_CODE => READ_V2_RESPONSE_CODE,
        WRITE_V2_COMMAND_CODE => WRITE_V2_RESPONSE_CODE,
        _ => command_code.wrapping_add(1),
    }
}

fn unexpected_response(command: &'static str) -> FelicaStandardError {
    FelicaStandardError::Protocol(format!("unexpected response for {command} command"))
}

mod basic;
mod secure_ops;

#[cfg(test)]
mod tests;
