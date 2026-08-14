//! TLV parsing for the Port-400's PC/SC responses.
//!
//! Every response the reader sends back — Manage Session, Switch Protocol and
//! the transparent exchange — is a sequence of tag/length/value fields sharing
//! one status TLV and one vendor TLV encoding. The parsers for all three, and
//! the primitives they are built from, live here so the command layer in
//! [`super`] deals only in commands.

use crate::clf::errors::CommunicationError;
use crate::driver::errors::{DriverError, Result};
use log::{debug, warn};

/// Status TLV every response carries.
pub(super) const STATUS_TLV_TAG: u8 = 0xC0;
/// Device state TLV of a Manage Session response.
const DEVICE_STATE_TLV_TAG: u8 = 0x80;
/// Protocol metadata TLV of a Switch Protocol response.
pub(super) const SWITCH_PROTOCOL_METADATA_TAG: u8 = 0x8F;
/// Prefix of a two-byte extended tag.
pub(super) const EXTENDED_TAG_PREFIX: u8 = 0x5F;
/// Second byte of the extended tag carrying the card's ATR.
const ATR_TLV_TAG: u8 = 0x51;
/// Reception bit framing TLV of a transparent exchange response.
const RESPONSE_BIT_FRAMING_TAG: u8 = 0x92;
/// RF status TLV of a transparent exchange response.
const RESPONSE_STATUS_TAG: u8 = 0x96;
/// Payload TLV of a transparent exchange response.
const RESPONSE_DATA_TAG: u8 = 0x97;
/// Vendor specific tag, which introduces a nested sub tag.
pub(super) const VENDOR_SPECIFIC_TAG: u8 = 0xFF;
/// Sub tag of a vendor specific response TLV.
const VENDOR_TAG_RESPONSE: u8 = 0x6D;

/// What a transparent exchange answered with.
#[derive(Default)]
pub(super) struct TransparentExchangeResult {
    pub(super) payload: Vec<u8>,
    pub(super) rf_status: Option<u8>,
    pub(super) valid_bits: Option<u8>,
}

pub(super) fn push_extended_tlv(buf: &mut Vec<u8>, tag: u8, value: &[u8]) {
    buf.push(tag);
    buf.push(0x82);
    buf.push(((value.len() >> 8) & 0xFF) as u8);
    buf.push((value.len() & 0xFF) as u8);
    buf.extend_from_slice(value);
}

pub(super) fn verify_status(data: &[u8]) -> Result<()> {
    if data.len() < 2 {
        return Err(DriverError::Other("short CCID status".into()));
    }
    let sw1 = data[data.len() - 2];
    let sw2 = data[data.len() - 1];
    if sw1 == 0x90 && sw2 == 0x00 {
        return Ok(());
    }
    Err(DriverError::Other(format!(
        "CCID status {:02X}{:02X}",
        sw1, sw2
    )))
}

/// Reads the single byte length that follows a TLV tag and returns the value.
///
/// `idx` points at the length byte on entry and past the value on return.
pub(super) fn take_tlv_value<'a>(
    data: &'a [u8],
    idx: &mut usize,
    context: &str,
) -> Result<&'a [u8]> {
    let len_index = *idx;
    let len = *data
        .get(len_index)
        .ok_or_else(|| DriverError::Other(format!("{context}: TLV length missing")))?
        as usize;
    // The value has to stay inside the response, matching the bounds check the
    // reference library applies.
    if len_index + len >= data.len() {
        return Err(DriverError::Other(format!(
            "{context}: TLV length out of range"
        )));
    }
    let start = len_index + 1;
    *idx = start + len;
    Ok(&data[start..start + len])
}

/// Checks the `C0` status TLV every Manage Session response carries.
pub(super) fn take_status_tlv(data: &[u8], idx: &mut usize, context: &str) -> Result<()> {
    let value = take_tlv_value(data, idx, context)?;
    if value.len() != 3 {
        return Err(DriverError::Other(format!(
            "{context}: malformed status TLV"
        )));
    }
    if value != [0x00, 0x90, 0x00] {
        return Err(status_error(value));
    }
    Ok(())
}

/// Skips a vendor specific TLV. Returns `false` when the sub tag is unknown,
/// in which case the rest of the response is not parsed any further.
pub(super) fn skip_vendor_tlv(data: &[u8], idx: &mut usize, context: &str) -> Result<bool> {
    let Some(&subtag) = data.get(*idx) else {
        debug!("{context}: truncated vendor TLV");
        return Ok(false);
    };
    *idx += 1;
    if subtag != VENDOR_TAG_RESPONSE {
        warn!("{context}: unexpected vendor tag {subtag:02X}");
        return Ok(false);
    }
    let value = take_tlv_value(data, idx, context)?;
    if value.len() != 3 && value.len() != 6 {
        return Err(DriverError::Other(format!(
            "{context}: malformed vendor TLV"
        )));
    }
    Ok(true)
}

pub(super) fn parse_manage_session_response(data: &[u8]) -> Result<()> {
    const CONTEXT: &str = "manageSession";
    let mut idx = 0;
    while idx + 1 < data.len() {
        let tag = data[idx];
        idx += 1;
        match tag {
            STATUS_TLV_TAG => take_status_tlv(data, &mut idx, CONTEXT)?,
            DEVICE_STATE_TLV_TAG => {
                let value = take_tlv_value(data, &mut idx, CONTEXT)?;
                if value.len() != 3 {
                    return Err(DriverError::Other(format!(
                        "{CONTEXT}: malformed device state TLV"
                    )));
                }
            }
            VENDOR_SPECIFIC_TAG => {
                if !skip_vendor_tlv(data, &mut idx, CONTEXT)? {
                    break;
                }
            }
            _ => {
                warn!("{CONTEXT}: unexpected TAG {tag:02X}");
                break;
            }
        }
    }
    Ok(())
}

pub(super) fn parse_switch_protocol_response(data: &[u8]) -> Result<()> {
    const CONTEXT: &str = "switchProtocol";
    let mut idx = 0;
    while idx + 1 < data.len() {
        let tag = data[idx];
        idx += 1;
        match tag {
            STATUS_TLV_TAG => take_status_tlv(data, &mut idx, CONTEXT)?,
            SWITCH_PROTOCOL_METADATA_TAG => {
                let value = take_tlv_value(data, &mut idx, CONTEXT)?;
                if value.len() != 1 && value.len() != 3 {
                    return Err(DriverError::Other(format!(
                        "{CONTEXT}: malformed protocol TLV"
                    )));
                }
            }
            EXTENDED_TAG_PREFIX => {
                // The reader reports the card's ATR as a 5F51 TLV.
                let subtag = data.get(idx).copied();
                idx += 1;
                if subtag != Some(ATR_TLV_TAG) {
                    return Err(DriverError::Other(format!("{CONTEXT}: ATR error")));
                }
                take_tlv_value(data, &mut idx, CONTEXT)?;
            }
            VENDOR_SPECIFIC_TAG => {
                if !skip_vendor_tlv(data, &mut idx, CONTEXT)? {
                    break;
                }
            }
            _ => {
                warn!("{CONTEXT}: unexpected TAG {tag:02X}");
                break;
            }
        }
    }
    Ok(())
}

pub(super) fn parse_transparent_response(data: &[u8]) -> Result<TransparentExchangeResult> {
    const CONTEXT: &str = "transparentExchange";
    let mut idx = 0;
    let mut result = TransparentExchangeResult::default();
    while idx + 1 < data.len() {
        let tag = data[idx];
        idx += 1;
        match tag {
            STATUS_TLV_TAG => take_status_tlv(data, &mut idx, CONTEXT)?,
            RESPONSE_BIT_FRAMING_TAG => {
                let value = take_tlv_value(data, &mut idx, CONTEXT)?;
                let [bits] = value else {
                    return Err(DriverError::Other(format!(
                        "{CONTEXT}: Reception Bit Framing error"
                    )));
                };
                // Zero valid bits stands for a complete byte.
                result.valid_bits = Some(if *bits == 0 { 8 } else { *bits });
            }
            RESPONSE_STATUS_TAG => {
                let value = take_tlv_value(data, &mut idx, CONTEXT)?;
                let [status, _] = value else {
                    return Err(DriverError::Other(format!(
                        "{CONTEXT}: Response Status error"
                    )));
                };
                result.rf_status = Some(*status);
            }
            RESPONSE_DATA_TAG => {
                let (len, consumed) = parse_length(&data[idx..])
                    .map_err(|_| DriverError::Other(format!("{CONTEXT}: Response Data error")))?;
                idx += consumed;
                if idx + len > data.len() {
                    return Err(DriverError::Other(format!(
                        "{CONTEXT}: Response Data out of range"
                    )));
                }
                result.payload.extend_from_slice(&data[idx..idx + len]);
                idx += len;
            }
            VENDOR_SPECIFIC_TAG => {
                if !skip_vendor_tlv(data, &mut idx, CONTEXT)? {
                    break;
                }
            }
            _ => {
                warn!("{CONTEXT}: unexpected TAG {tag:02X}");
                break;
            }
        }
    }
    Ok(result)
}

pub(super) fn parse_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(DriverError::Other("missing length field".into()));
    }
    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let count = match first {
            0x81 => 1,
            0x82 => 2,
            0x83 => 3,
            0x84 => 4,
            _ => {
                return Err(DriverError::Other("unsupported TLV length encoding".into()));
            }
        };
        if data.len() < 1 + count {
            return Err(DriverError::Other("incomplete TLV length field".into()));
        }
        let mut len = 0usize;
        for &byte in &data[1..=count] {
            len = (len << 8) | byte as usize;
        }
        Ok((len, 1 + count))
    }
}

/// Maps the status word of a `C0` TLV onto a driver error, keeping the
/// distinctions the reference library draws between a card that did not
/// answer, a card that answered with an unexpected status, and a reader that
/// is owned by another application.
pub(super) fn status_error(value: &[u8]) -> DriverError {
    let sw1 = value.get(1).copied().unwrap_or_default();
    let sw2 = value.get(2).copied().unwrap_or_default();
    let text = format!(
        "status {:02X}{:02X}{:02X}",
        value.first().copied().unwrap_or_default(),
        sw1,
        sw2
    );
    match (sw1, sw2) {
        (0x64, 0x00 | 0x01) => DriverError::Communication(CommunicationError::Timeout(format!(
            "{text} (no response packet received)"
        ))),
        (0x63, 0x01) => DriverError::Communication(CommunicationError::Protocol(format!(
            "{text} (invalid status)"
        ))),
        (0x69, 0x8A) => DriverError::Other(format!("{text} (failed to get access authority)")),
        _ => DriverError::Other(text),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testing::assert_driver_error_contains;

    #[test]
    fn push_extended_tlv_encodes_tag_and_length() {
        let mut tlv = Vec::new();
        push_extended_tlv(&mut tlv, 0x95, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(tlv, vec![0x95, 0x82, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn verify_status_accepts_success_and_rejects_errors() {
        verify_status(&[0x90, 0x00]).expect("9000 status should pass");
        assert_driver_error_contains(verify_status(&[0x6A, 0x82]), "CCID status 6A82");
        assert_driver_error_contains(verify_status(&[0x90]), "short CCID status");
    }

    #[test]
    fn parse_length_supports_short_and_long_forms() {
        assert_eq!(parse_length(&[0x7F]).expect("short length"), (0x7F, 1));
        assert_eq!(parse_length(&[0x81, 0x80]).expect("0x81 length"), (0x80, 2));
        assert_eq!(
            parse_length(&[0x82, 0x01, 0x00]).expect("0x82 length"),
            (0x0100, 3)
        );
        assert_eq!(
            parse_length(&[0x84, 0x00, 0x00, 0x01, 0x00]).expect("0x84 length"),
            (0x0100, 5)
        );
    }

    #[test]
    fn parse_length_reports_malformed_encodings() {
        assert_driver_error_contains(parse_length(&[]), "missing length field");
        assert_driver_error_contains(
            parse_length(&[0x85, 0x00]),
            "unsupported TLV length encoding",
        );
        assert_driver_error_contains(parse_length(&[0x82, 0x01]), "incomplete TLV length field");
    }

    #[test]
    fn parse_manage_session_response_accepts_valid_tlvs() {
        parse_manage_session_response(&[STATUS_TLV_TAG, 0x03, 0x00, 0x90, 0x00])
            .expect("status TLV should parse");
        parse_manage_session_response(&[
            VENDOR_SPECIFIC_TAG,
            VENDOR_TAG_RESPONSE,
            0x03,
            0xAA,
            0xBB,
            0xCC,
            DEVICE_STATE_TLV_TAG,
            0x03,
            0x01,
            0x02,
            0x03,
            STATUS_TLV_TAG,
            0x03,
            0x00,
            0x90,
            0x00,
        ])
        .expect("vendor + device state + status TLV should parse");
    }

    #[test]
    fn parse_manage_session_response_reports_invalid_inputs() {
        assert_driver_error_contains(
            parse_manage_session_response(&[STATUS_TLV_TAG, 0x04, 0x00, 0x90, 0x00]),
            "TLV length out of range",
        );
        assert_driver_error_contains(
            parse_manage_session_response(&[STATUS_TLV_TAG, 0x03, 0x01, 0x90, 0x00]),
            "status 019000",
        );
        assert_driver_error_contains(
            parse_manage_session_response(&[
                VENDOR_SPECIFIC_TAG,
                VENDOR_TAG_RESPONSE,
                0x02,
                0xAA,
                0xBB,
            ]),
            "malformed vendor TLV",
        );
    }

    #[test]
    fn parse_manage_session_response_stops_at_unknown_tags() {
        // Both an unknown top level tag and an unknown vendor sub tag end the
        // parse without failing the command, the way NFCPortLib does.
        parse_manage_session_response(&[0x01, 0x00, 0x02, 0x00])
            .expect("unknown tag should stop the parse");
        parse_manage_session_response(&[VENDOR_SPECIFIC_TAG, 0x10, 0x00])
            .expect("unknown vendor tag should stop the parse");
    }

    #[test]
    fn parse_switch_protocol_response_accepts_metadata_and_atr() {
        parse_switch_protocol_response(&[
            STATUS_TLV_TAG,
            0x03,
            0x00,
            0x90,
            0x00,
            SWITCH_PROTOCOL_METADATA_TAG,
            0x03,
            0x01,
            0x02,
            0x03,
            EXTENDED_TAG_PREFIX,
            ATR_TLV_TAG,
            0x02,
            0x3B,
            0x8F,
        ])
        .expect("switch protocol response should parse");
        parse_switch_protocol_response(&[SWITCH_PROTOCOL_METADATA_TAG, 0x01, 0x04])
            .expect("single byte protocol TLV should parse");
    }

    #[test]
    fn parse_switch_protocol_response_reports_invalid_inputs() {
        assert_driver_error_contains(
            parse_switch_protocol_response(&[SWITCH_PROTOCOL_METADATA_TAG, 0x02, 0x01, 0x02]),
            "malformed protocol TLV",
        );
        assert_driver_error_contains(
            parse_switch_protocol_response(&[EXTENDED_TAG_PREFIX, 0x46, 0x01, 0x00]),
            "ATR error",
        );
    }

    #[test]
    fn status_error_maps_reader_status_words() {
        match status_error(&[0x00, 0x64, 0x01]) {
            DriverError::Communication(CommunicationError::Timeout(message)) => {
                assert!(message.contains("006401"), "unexpected message: {message}");
            }
            other => panic!("expected a timeout error, got {other}"),
        }
        match status_error(&[0x00, 0x63, 0x01]) {
            DriverError::Communication(CommunicationError::Protocol(message)) => {
                assert!(message.contains("006301"), "unexpected message: {message}");
            }
            other => panic!("expected a protocol error, got {other}"),
        }
        match status_error(&[0x00, 0x69, 0x8A]) {
            DriverError::Other(message) => {
                assert!(message.contains("access authority"), "got {message}");
            }
            other => panic!("expected an access authority error, got {other}"),
        }
    }

    #[test]
    fn parse_transparent_response_parses_payload_and_metadata() {
        let parsed = parse_transparent_response(&[
            0xC0,
            0x03,
            0x00,
            0x90,
            0x00,
            RESPONSE_BIT_FRAMING_TAG,
            0x01,
            0x00,
            RESPONSE_STATUS_TAG,
            0x02,
            0x5A,
            0x00,
            RESPONSE_DATA_TAG,
            0x03,
            0xAA,
            0xBB,
            0xCC,
            VENDOR_SPECIFIC_TAG,
            VENDOR_TAG_RESPONSE,
            0x03,
            0x99,
            0x88,
            0x77,
        ])
        .expect("transparent response should parse");
        assert_eq!(parsed.payload, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(parsed.rf_status, Some(0x5A));
        assert_eq!(parsed.valid_bits, Some(8));
    }

    #[test]
    fn parse_transparent_response_supports_extended_data_length() {
        let parsed = parse_transparent_response(&[
            RESPONSE_DATA_TAG,
            0x82,
            0x00,
            0x02,
            0x11,
            0x22,
            0xC0,
            0x03,
            0x00,
            0x90,
            0x00,
        ])
        .expect("extended length data TLV should parse");
        assert_eq!(parsed.payload, vec![0x11, 0x22]);
    }

    #[test]
    fn parse_transparent_response_reports_invalid_inputs() {
        assert_driver_error_contains(
            parse_transparent_response(&[RESPONSE_BIT_FRAMING_TAG, 0x02, 0x01, 0x02]),
            "Reception Bit Framing error",
        );
        assert_driver_error_contains(
            parse_transparent_response(&[RESPONSE_STATUS_TAG, 0x01, 0x00, 0x00]),
            "Response Status error",
        );
        assert_driver_error_contains(
            parse_transparent_response(&[RESPONSE_DATA_TAG, 0x03, 0xAA]),
            "Response Data",
        );
        assert_driver_error_contains(
            parse_transparent_response(&[RESPONSE_DATA_TAG, 0x85, 0x00]),
            "Response Data error",
        );
    }

    #[test]
    fn parse_transparent_response_stops_at_unknown_tags() {
        let parsed = parse_transparent_response(&[0x01, 0x00, 0x02, 0x00])
            .expect("unknown tag should stop the parse");
        assert!(parsed.payload.is_empty());
        let parsed = parse_transparent_response(&[VENDOR_SPECIFIC_TAG, 0x01, 0x00])
            .expect("unknown vendor tag should stop the parse");
        assert!(parsed.payload.is_empty());
    }
}
