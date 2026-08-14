//! Building the byte payload of a FeliCa command or response.
//!
//! Both directions share one shape: an opcode, usually the IDm, and then the
//! command's own fields, with multi-byte values little-endian and lists
//! introduced by a one-byte count. [`PayloadWriter`] spells that out once so the
//! encoders read as the packet layouts they implement rather than as index
//! arithmetic.
//!
//! Responses additionally share an invariant from §4.5: the payload behind the
//! status flags exists exactly when status flag 1 reports success. [`for_success`]
//! and [`ensure_omitted_on_error`] enforce it in one place.

use super::{
    BlockListElement, FelicaStandardError, IDM_LEN, ServiceCode, frame_with_length_prefix,
};

/// Bytes a response header occupies: the response code and the IDm.
const RESPONSE_HEADER_LEN: usize = 1 + IDM_LEN;

/// Accumulates the bytes of one command or response payload.
pub(super) struct PayloadWriter {
    buf: Vec<u8>,
}

impl PayloadWriter {
    /// Starts a payload with `opcode` as its first byte.
    pub(super) fn new(opcode: u8) -> Self {
        Self { buf: vec![opcode] }
    }

    /// Starts a payload with room for `capacity` bytes and no opcode, for the
    /// secure responses that carry only status flags.
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Starts an addressed response: its response code followed by the IDm.
    pub(super) fn response(code: u8, idm: &[u8; IDM_LEN]) -> Self {
        let mut writer = Self {
            buf: Vec::with_capacity(RESPONSE_HEADER_LEN),
        };
        writer.push_u8(code);
        writer.idm(idm);
        writer
    }

    /// Appends the IDm.
    pub(super) fn idm(&mut self, idm: &[u8; IDM_LEN]) {
        self.buf.extend_from_slice(idm);
    }

    /// Appends the two status flag bytes a response reports its outcome with.
    pub(super) fn status_flags(&mut self, status_flag1: u8, status_flag2: u8) {
        self.push_u8(status_flag1);
        self.push_u8(status_flag2);
    }

    pub(super) fn push_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    /// Appends a boolean as the `01h` / `00h` the protocol encodes flags with.
    pub(super) fn push_flag(&mut self, value: bool) {
        self.push_u8(u8::from(value));
    }

    /// Appends the length of `values` as a one-byte count.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds 255. Every caller bounds its list against the
    /// protocol maximum first, all of which are far below that.
    pub(super) fn push_count(&mut self, len: usize) {
        let count = u8::try_from(len).expect("list length is bounded well below 255");
        self.push_u8(count);
    }

    pub(super) fn extend_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub(super) fn extend_u16_le(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn extend_u16_be(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn extend_u16_list_le(&mut self, values: &[u16]) {
        for &value in values {
            self.extend_u16_le(value);
        }
    }

    /// Appends a one-byte count followed by the values, little-endian.
    pub(super) fn extend_counted_u16_le(&mut self, values: &[u16]) {
        self.push_count(values.len());
        self.extend_u16_list_le(values);
    }

    /// Appends a one-byte count followed by the values, big-endian, which is
    /// how system codes travel.
    pub(super) fn extend_counted_u16_be(&mut self, values: &[u16]) {
        self.push_count(values.len());
        for &value in values {
            self.extend_u16_be(value);
        }
    }

    pub(super) fn extend_service_codes(&mut self, service_codes: &[ServiceCode]) {
        for &code in service_codes {
            self.buf.extend_from_slice(&code.to_le_bytes());
        }
    }

    /// Appends a one-byte count followed by the service codes.
    pub(super) fn extend_counted_service_codes(&mut self, service_codes: &[ServiceCode]) {
        self.push_count(service_codes.len());
        self.extend_service_codes(service_codes);
    }

    pub(super) fn extend_block_list(&mut self, block_list: &[BlockListElement]) {
        for block in block_list {
            self.buf.extend(block.pack());
        }
    }

    /// Appends a one-byte count followed by the block list elements.
    pub(super) fn extend_counted_block_list(&mut self, block_list: &[BlockListElement]) {
        self.push_count(block_list.len());
        self.extend_block_list(block_list);
    }

    /// Wraps the payload in the one-byte length prefix that makes it a frame.
    pub(super) fn finish_frame(self) -> Result<Vec<u8>, FelicaStandardError> {
        frame_with_length_prefix(&self.buf)
    }

    /// Returns the payload bytes.
    pub(super) fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Returns the payload to encode behind a response's status flags.
///
/// §4.5.1 pairs the two: a card that completed the command normally sends its
/// result, and one that did not sends nothing behind the flags. Encoding a
/// response that breaks the pairing would put a packet on the air no reader
/// could make sense of, so both halves are rejected here. `what` names the
/// response in the error, and `noun` is what the response calls its payload.
pub(super) fn for_success<'a, R>(
    what: &str,
    noun: &str,
    status_flag1: u8,
    result: Option<&'a R>,
) -> Result<Option<&'a R>, FelicaStandardError> {
    ensure_omitted_on_error(what, noun, status_flag1, result.is_some())?;
    if status_flag1 != 0 {
        return Ok(None);
    }
    let result = result.ok_or_else(|| {
        FelicaStandardError::Protocol(format!("{what} {noun} is missing on success"))
    })?;
    Ok(Some(result))
}

/// Rejects a list whose length falls outside the 1 to `max` entries the
/// protocol allows for it. `what` names the list *and* what is being counted,
/// e.g. `"request service key version count"`.
pub(super) fn ensure_count_in_range(
    what: &str,
    len: usize,
    max: usize,
) -> Result<(), FelicaStandardError> {
    if len == 0 || len > max {
        return Err(FelicaStandardError::Protocol(format!(
            "{what} out of range"
        )));
    }
    Ok(())
}

/// Rejects a list too long for the one-byte count that introduces it.
pub(super) fn ensure_fits_in_count(what: &str, len: usize) -> Result<(), FelicaStandardError> {
    if len > u8::MAX as usize {
        return Err(FelicaStandardError::Protocol(format!(
            "{what} out of range"
        )));
    }
    Ok(())
}

/// Rejects a payload carried by a response that reports a failure.
///
/// Use this directly for the responses whose payload is optional even on
/// success; [`for_success`] additionally requires one to be there.
pub(super) fn ensure_omitted_on_error(
    what: &str,
    noun: &str,
    status_flag1: u8,
    has_result: bool,
) -> Result<(), FelicaStandardError> {
    if status_flag1 != 0 && has_result {
        return Err(FelicaStandardError::Protocol(format!(
            "{what} {noun} must be omitted on error"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_writes_the_code_idm_and_status_flags() {
        let mut writer = PayloadWriter::response(0x07, &[0xAA; IDM_LEN]);
        writer.status_flags(0x00, 0x00);
        writer.extend_counted_u16_le(&[0x0102, 0x0304]);
        assert_eq!(
            writer.finish(),
            vec![
                0x07, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x02, 0x02, 0x01,
                0x04, 0x03
            ]
        );
    }

    #[test]
    fn counted_lists_use_big_endian_for_system_codes() {
        let mut writer = PayloadWriter::new(0x0D);
        writer.extend_counted_u16_be(&[0x0003]);
        writer.push_flag(true);
        writer.push_flag(false);
        assert_eq!(writer.finish(), vec![0x0D, 0x01, 0x00, 0x03, 0x01, 0x00]);
    }

    #[test]
    fn for_success_pairs_the_payload_with_the_status_flag() {
        let value = 42u8;
        assert_eq!(
            for_success("x", "result", 0x00, Some(&value)).expect("success with a result"),
            Some(&value)
        );
        assert_eq!(
            for_success::<u8>("x", "result", 0xFF, None).expect("error without a result"),
            None
        );

        let missing = for_success::<u8>("x", "result", 0x00, None)
            .expect_err("success without a result should fail");
        assert!(
            missing
                .to_string()
                .contains("x result is missing on success")
        );

        let extra = for_success("x", "result", 0xFF, Some(&value))
            .expect_err("error with a result should fail");
        assert!(
            extra
                .to_string()
                .contains("x result must be omitted on error")
        );
    }

    #[test]
    fn ensure_omitted_on_error_only_rejects_a_payload_behind_a_failure() {
        assert!(ensure_omitted_on_error("x", "payload", 0x00, true).is_ok());
        assert!(ensure_omitted_on_error("x", "payload", 0x00, false).is_ok());
        assert!(ensure_omitted_on_error("x", "payload", 0xFF, false).is_ok());
        assert!(ensure_omitted_on_error("x", "payload", 0xFF, true).is_err());
    }
}
