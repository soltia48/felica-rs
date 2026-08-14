//! The CCID escape framing the Port-400 is driven through.
//!
//! The reader is a CCID device, so every PC/SC command travels inside an escape
//! frame: a ten byte header, the APDU, and a status the reader answers with.
//! This module owns that envelope — building frames, matching sequence numbers,
//! and retrying the busy and time-extension answers — so the command layer in
//! [`super`] never sees it.

use crate::driver::errors::{DriverError, Result};
use crate::driver::io as buffered_io;
use crate::transport::Transport;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::io;
use std::thread::sleep;
use std::time::{Duration, Instant};

/// CCID slot the reader answers on.
pub(super) const CCID_SLOT_NUMBER: u8 = 0;
/// Length of the CCID response header that precedes the payload.
const CCID_HEADER_LEN: usize = 10;
/// Error byte the reader reports while its slot is busy.
const SLOT_BUSY_ERROR: u8 = 0xE0;
/// How long to wait before retrying a busy slot.
const SLOT_BUSY_WAIT_TIME: Duration = Duration::from_millis(50);
/// How long to wait when the reader asks for more time.
const TIME_EXTENSION_WAIT: Duration = Duration::from_millis(20);
/// How many times a sequence number mismatch is retried before giving up.
const SEQUENCE_ERROR_RETRY_COUNT: usize = 2;

pub(super) struct CcidTransport<T: Transport> {
    pub(super) transport: T,
    sequence: u8,
    buffer: VecDeque<u8>,
}

impl<T: Transport> CcidTransport<T> {
    pub(super) fn new(transport: T) -> Self {
        Self {
            transport,
            sequence: 0,
            buffer: VecDeque::new(),
        }
    }

    pub(super) fn escape(
        &mut self,
        payload: &[u8],
        timeout: Duration,
        slot_busy_retries: usize,
    ) -> Result<Vec<u8>> {
        let mut remaining_retries = slot_busy_retries + 1;
        while remaining_retries > 0 {
            // Every read below shares one deadline, so a reader that answers
            // slowly cannot stretch the exchange past the caller's timeout.
            let deadline = Instant::now() + timeout;
            let seq = self.next_sequence();
            let frame = self.build_escape_frame(payload, seq);
            self.transport.write(&frame)?;
            self.buffer.clear();
            let mut seq_retry = SEQUENCE_ERROR_RETRY_COUNT + 1;
            loop {
                let header = self.read_exact(CCID_HEADER_LEN, deadline)?;
                let (response, status) = CcidResponse::parse(&header, seq)?;
                if status == CommandStatus::SequenceMismatch {
                    seq_retry -= 1;
                    if seq_retry == 0 {
                        return Err(DriverError::Other("CCID sequence mismatch".into()));
                    }
                    // The body of the stale response still has to be drained,
                    // otherwise it would be mistaken for the next header.
                    if response.length > 0 {
                        self.read_exact(response.length, deadline)?;
                    }
                    continue;
                }
                let data = if response.length > 0 {
                    self.read_exact(response.length, deadline)?
                } else {
                    Vec::new()
                };
                match status {
                    CommandStatus::Success => {
                        if data.len() < 2 {
                            return Err(DriverError::Other("escape response too short".into()));
                        }
                        return Ok(data);
                    }
                    CommandStatus::SlotBusy => {
                        remaining_retries -= 1;
                        if remaining_retries == 0 {
                            return Err(DriverError::Other("slot busy".into()));
                        }
                        sleep(SLOT_BUSY_WAIT_TIME);
                        break;
                    }
                    CommandStatus::TimeExtension => {
                        sleep(TIME_EXTENSION_WAIT);
                    }
                    CommandStatus::Failure(code) => {
                        return Err(DriverError::Other(format!("CCID failure {code:#04x}",)));
                    }
                    CommandStatus::SequenceMismatch => unreachable!(),
                }
            }
        }
        Err(DriverError::Other("slot busy".into()))
    }

    pub(super) fn read_exact(&mut self, len: usize, deadline: Instant) -> Result<Vec<u8>> {
        buffered_io::read_exact(&mut self.transport, &mut self.buffer, len, deadline)
    }

    pub(super) fn build_escape_frame(&self, payload: &[u8], seq: u8) -> Vec<u8> {
        let mut frame = Vec::with_capacity(payload.len() + 10);
        frame.push(0x6B);
        let len = payload.len() as u32;
        frame.extend_from_slice(&len.to_le_bytes());
        frame.push(CCID_SLOT_NUMBER);
        frame.push(seq);
        frame.push(0);
        frame.push(0);
        frame.push(0);
        if !payload.is_empty() {
            frame.extend_from_slice(payload);
        }
        frame
    }

    pub(super) fn next_sequence(&mut self) -> u8 {
        self.sequence = self.sequence.wrapping_add(1);
        self.sequence
    }

    pub(super) fn close(&mut self) -> io::Result<()> {
        self.transport.close()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CommandStatus {
    Success,
    Failure(u8),
    SlotBusy,
    TimeExtension,
    SequenceMismatch,
}

pub(super) struct CcidResponse {
    length: usize,
}

impl CcidResponse {
    pub(super) fn parse(data: &[u8], expected_seq: u8) -> Result<(Self, CommandStatus)> {
        if data.len() < CCID_HEADER_LEN {
            return Err(DriverError::Other("short CCID header".into()));
        }
        let message_type = data[0];
        if message_type != 0x83 {
            return Err(DriverError::Other("invalid CCID message".into()));
        }
        let length = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if data[5] != CCID_SLOT_NUMBER {
            return Err(DriverError::Other("invalid CCID slot number".into()));
        }
        let seq = data[6];
        if seq != expected_seq {
            // The length is reported so the caller can drain the stale response.
            return Ok((Self { length }, CommandStatus::SequenceMismatch));
        }
        let status_byte = data[7];
        let error = data[8];
        let command_status = (status_byte >> 6) & 0x03;
        let status = match command_status {
            0 => CommandStatus::Success,
            1 => {
                if error == SLOT_BUSY_ERROR {
                    CommandStatus::SlotBusy
                } else {
                    CommandStatus::Failure(error)
                }
            }
            2 => CommandStatus::TimeExtension,
            _ => CommandStatus::Failure(error),
        };
        Ok((Self { length }, status))
    }
}
#[allow(dead_code)]
const FDT_MIN_MICROS: u32 = 6780; // ISO14443-4 default FDT in microseconds

pub(super) struct EscapeCommand<'a> {
    ins: u8,
    p1: u8,
    p2: u8,
    data: Cow<'a, [u8]>,
}

impl<'a> EscapeCommand<'a> {
    pub(super) fn new(ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            ins,
            p1,
            p2,
            data: Cow::Borrowed(&[]),
        }
    }

    pub(super) fn with_data(ins: u8, p1: u8, p2: u8, data: &'a [u8]) -> Self {
        Self {
            ins,
            p1,
            p2,
            data: Cow::Borrowed(data),
        }
    }

    pub(super) fn into_bytes(self) -> Vec<u8> {
        let mut frame = vec![0xFF, self.ins, self.p1, self.p2];
        if !self.data.is_empty() {
            frame.push(self.data.len() as u8);
            frame.extend_from_slice(&self.data);
        }
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::testing::{DummyTransport, assert_driver_error_contains};
    use std::io::ErrorKind;

    /// Get Data, a command with no data field.
    const GET_DATA_INS: u8 = 0xCA;

    #[test]
    fn ccid_response_parse_maps_status_variants() {
        let mut header = [0u8; 10];
        header[0] = 0x83;
        header[1..5].copy_from_slice(&4u32.to_le_bytes());
        header[6] = 0x10;

        let (ok, ok_status) =
            CcidResponse::parse(&header, 0x10).expect("success header should parse");
        assert_eq!(ok.length, 4);
        assert_eq!(ok_status, CommandStatus::Success);

        header[7] = 0x40;
        header[8] = SLOT_BUSY_ERROR;
        let (_, busy_status) =
            CcidResponse::parse(&header, 0x10).expect("slot busy header should parse");
        assert_eq!(busy_status, CommandStatus::SlotBusy);

        header[7] = 0x40;
        header[8] = 0x12;
        let (_, fail_status) =
            CcidResponse::parse(&header, 0x10).expect("failure header should parse");
        assert_eq!(fail_status, CommandStatus::Failure(0x12));

        header[7] = 0x80;
        let (_, te_status) =
            CcidResponse::parse(&header, 0x10).expect("time extension header should parse");
        assert_eq!(te_status, CommandStatus::TimeExtension);

        header[6] = 0x11;
        let (seq, seq_status) =
            CcidResponse::parse(&header, 0x10).expect("seq mismatch should parse");
        // The announced body length is kept so the stale response can be drained.
        assert_eq!(seq.length, 4);
        assert_eq!(seq_status, CommandStatus::SequenceMismatch);

        header[5] = 0x01;
        assert_driver_error_contains(
            CcidResponse::parse(&header, 0x10),
            "invalid CCID slot number",
        );
    }

    #[test]
    fn ccid_response_parse_rejects_invalid_headers() {
        assert_driver_error_contains(CcidResponse::parse(&[0u8; 9], 1), "short CCID header");

        let mut header = [0u8; 10];
        header[0] = 0x6B;
        assert_driver_error_contains(CcidResponse::parse(&header, 0), "invalid CCID message");
    }

    #[test]
    fn escape_command_serializes_with_and_without_data() {
        let no_data = EscapeCommand::new(GET_DATA_INS, 0xF2, 0x00).into_bytes();
        assert_eq!(no_data, vec![0xFF, GET_DATA_INS, 0xF2, 0x00]);

        let with_data = EscapeCommand::with_data(0x5A, 0x00, 0x00, &[0x12, 0x34]).into_bytes();
        assert_eq!(with_data, vec![0xFF, 0x5A, 0x00, 0x00, 0x02, 0x12, 0x34]);
    }

    #[test]
    fn ccid_transport_build_escape_frame_and_sequence_wrap() {
        let mut ccid = CcidTransport::new(DummyTransport::default());
        let frame = ccid.build_escape_frame(&[0xAA, 0xBB], 0x05);
        assert_eq!(
            frame,
            vec![
                0x6B, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0xAA, 0xBB
            ]
        );

        ccid.sequence = 0xFF;
        assert_eq!(ccid.next_sequence(), 0x00);
        assert_eq!(ccid.next_sequence(), 0x01);
    }

    #[test]
    fn ccid_transport_read_exact_uses_buffer_and_transport_reads() {
        let transport = DummyTransport::with_reads(vec![
            Ok(vec![0x01, 0x02, 0x03]),
            Ok(vec![0x04]),
            Ok(vec![0x05, 0x06]),
        ]);
        let mut ccid = CcidTransport::new(transport);

        let first = ccid
            .read_exact(2, Instant::now() + Duration::from_millis(10))
            .expect("first read");
        assert_eq!(first, vec![0x01, 0x02]);

        let second = ccid
            .read_exact(3, Instant::now() + Duration::from_millis(10))
            .expect("second read");
        assert_eq!(second, vec![0x03, 0x04, 0x05]);

        let third = ccid
            .read_exact(1, Instant::now() + Duration::from_millis(10))
            .expect("third read");
        assert_eq!(third, vec![0x06]);
    }

    #[test]
    fn ccid_transport_read_exact_times_out_at_the_deadline() {
        let mut ccid = CcidTransport::new(DummyTransport::default());
        let result = ccid.read_exact(1, Instant::now());
        match result {
            Err(DriverError::Io(err)) => assert_eq!(err.kind(), ErrorKind::TimedOut),
            Err(other) => panic!("expected DriverError::Io timeout, got {other}"),
            Ok(data) => panic!("expected timeout error, got {data:?}"),
        }
    }
}
